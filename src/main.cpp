#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "net/socket.hpp"
#include "protocol/reader.hpp"
#include "protocol/responses.hpp"
#include "protocol/writer.hpp"
#include "resolver/local_override.hpp"
#include "resolver/upstream.hpp"
#include "types/message.hpp"
#include "utils/logger.hpp"

namespace {

// Oye baselines set kar rahe haan, code nu pad ke muskaan aayegi. (Setting stage for fun yet serious DNS antics.)
constexpr int kDnsPort = 2053;

// Oye upstream resolver, command line to badal sakde. (Upstream resolver, swappable from the command line.)
dns::UpstreamConfig g_upstream;

// Oye forward declaration, makeARecord nu pehlan hi bula lo. (Forward declaration to keep compiler chill.)
dns::DnsRecord makeARecord(const std::string& name, const std::string& ip, uint32_t ttl = 60);

// Oye synthetic answer, jad forwarder nakhre kare ta apne app serve karange. (Synthetic answer when forwarder throws tantrums.)
std::vector<uint8_t> buildSyntheticAnswer(const dns::DnsPacket& query, const std::string& ip = "8.8.8.8") {
    dns::DnsPacket resp;
    resp.header = query.header;
    resp.header.qr = true;
    resp.header.aa = false;
    resp.header.tc = false;
    resp.header.rd = query.header.rd;
    resp.header.ra = false;
    resp.header.rcode = dns::rcodeFor(query.header.opcode, dns::Rcode::kNoError);
    resp.questions = query.questions;
    resp.header.qdCount = static_cast<uint16_t>(resp.questions.size());

    // Oye sare questions da jawab dena, koi chhadna nahi. (Answer all questions, leave none behind.)
    for (const auto& q : query.questions) {
        if (q.qtype == 1 && q.qclass == 1) {
            resp.answers.push_back(makeARecord(q.qname, ip, 60));
        }
    }
    resp.header.anCount = static_cast<uint16_t>(resp.answers.size());
    resp.header.nsCount = static_cast<uint16_t>(resp.authorities.size());
    resp.header.arCount = static_cast<uint16_t>(resp.additionals.size());
    return dns::buildPacket(resp);
}

// Oye quick helper to craft A record for friendly testing. (Helper to craft a friendly A record.)
dns::DnsRecord makeARecord(const std::string& name, const std::string& ip, uint32_t ttl) {
    dns::DnsRecord r;
    r.name = name;
    r.type = 1;      // A
    r.rclass = 1;    // IN
    r.ttl = ttl;
    r.rdata.resize(4);
    inet_pton(AF_INET, ip.c_str(), r.rdata.data());
    return r;
}

} // namespace

int main(int argc, char* argv[]) {
    // Oye command-line arguments, resolver nu pakad rahe. (Parsing command-line args to grab resolver.)
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--resolver" && i + 1 < argc) {
            std::string resolverAddr = argv[i + 1];
            auto colonPos = resolverAddr.find(':');
            if (colonPos != std::string::npos) {
                g_upstream.host = resolverAddr.substr(0, colonPos);
                g_upstream.port = std::stoi(resolverAddr.substr(colonPos + 1));
            } else {
                g_upstream.host = resolverAddr;
                g_upstream.port = 53;
            }
            ++i;
        }
    }

    // Oye server socket te dhyaan, bina isde kahani hi adhuri. (Server socket is the hero of this story.)
    const int serverSocket = dns::bindServerSocket(kDnsPort);
    if (serverSocket < 0) {
        return 1;
    }

    // Oye infinite loop, DNS seva 24x7. (Service loop, dhaba open 24x7.)
    while (true) {
        const std::optional<dns::Datagram> request = dns::receiveDatagram(serverSocket);
        if (!request) {
            continue;
        }

        std::optional<std::vector<uint8_t>> response;
        try {
            const dns::DnsPacket packet = dns::parsePacket(request->bytes);
            dns::logPacketSummary(packet);

            if (packet.header.opcode != 0) {
                response = dns::buildHeaderOnlyReply(packet);
            } else if (packet.header.rd == 0) {
                response = dns::buildHeaderOnlyReply(packet);
            } else if (auto local = dns::tryLocalAnswer(packet)) {
                response = local;
            } else if (packet.header.qdCount > 1) {
                // Oye multiple questions, apni factory khol rahe. (Multiple questions, running our own factory.)
                response = buildSyntheticAnswer(packet);
            } else {
                response = dns::forwardToUpstream(g_upstream, request->bytes.data(), request->bytes.size());
                if (!response) {
                    // Oye upstream busy, asi khud answer de rahe. (Upstream ghosted, we self-serve.)
                    response = buildSyntheticAnswer(packet);
                }
            }
        } catch (const std::exception& ex) {
            dns::logError(std::string{"Parsing error: "} + ex.what());
            try {
                dns::DnsPacket fallbackPacket;
                std::size_t offset = 0;
                fallbackPacket.header = dns::parseHeader(request->bytes, offset);
                response = dns::buildServFail(fallbackPacket);
            } catch (...) {
                response = std::nullopt;
            }
        }

        if (response && !response->empty()) {
            dns::sendDatagram(serverSocket, *response, request->from, request->fromLength);
        }
    }

    close(serverSocket);
    return 0;
}
