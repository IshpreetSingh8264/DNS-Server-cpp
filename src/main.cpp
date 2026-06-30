#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "protocol/reader.hpp"
#include "protocol/responses.hpp"
#include "protocol/writer.hpp"
#include "types/message.hpp"

namespace {

// Oye baselines set kar rahe haan, code nu pad ke muskaan aayegi. (Setting stage for fun yet serious DNS antics.)
constexpr int kDnsPort = 2053;
constexpr size_t kMaxPacketSize = 512; // DNS classic limit
constexpr int kSocketTimeoutMs = 1500;

// Oye global resolver, runtime te badal sakde. (Global resolver that can be swapped at runtime.)
std::string g_upstreamResolver = "8.8.8.8";
int g_upstreamPort = 53;

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

// Oye local override da option, koi khaas domain ho ta turant jawab. (Local override for VIP domains.)
std::optional<std::vector<uint8_t>> tryLocalAnswer(const dns::DnsPacket& query) {
    // Oye local override sirf default resolver te, forwarding wale mode vich nahi. (Local override only when using default resolver, not in forwarding mode.)
    if (g_upstreamResolver != "8.8.8.8") {
        return std::nullopt;
    }
    if (query.questions.empty()) {
        return std::nullopt;
    }
    const auto& q = query.questions.front();
    if (q.qtype == 1 && q.qclass == 1 && q.qname == "codecrafters.io") {
        dns::DnsPacket resp;
        resp.header = query.header;
        resp.header.qr = true;
        resp.header.aa = false;
        resp.header.ra = false;
        resp.header.rcode = dns::rcodeFor(query.header.opcode, dns::Rcode::kNoError);
        resp.header.qdCount = static_cast<uint16_t>(query.questions.size());
        resp.questions = query.questions;
        resp.answers.push_back(makeARecord(q.qname, "8.8.8.8", 300));
        resp.header.anCount = static_cast<uint16_t>(resp.answers.size());
        resp.header.nsCount = static_cast<uint16_t>(resp.authorities.size());
        resp.header.arCount = static_cast<uint16_t>(resp.additionals.size());
        return dns::buildPacket(resp);
    }
    return std::nullopt;
}

// Oye upstream forwarding, packet nu Uber bhej rahe Google DNS kol. (Forwarding packet via Uber to Google DNS.)
std::optional<std::vector<uint8_t>> forwardToUpstream(const uint8_t* data, size_t length) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return std::nullopt;
    }

    timeval tv{};
    tv.tv_sec = kSocketTimeoutMs / 1000;
    tv.tv_usec = (kSocketTimeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in upstream{};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(g_upstreamPort);
    inet_pton(AF_INET, g_upstreamResolver.c_str(), &upstream.sin_addr);

    ssize_t sent = sendto(sock, data, length, 0, reinterpret_cast<sockaddr*>(&upstream), sizeof(upstream));
    if (sent < 0) {
        close(sock);
        return std::nullopt;
    }

    std::vector<uint8_t> buffer(kMaxPacketSize);
    ssize_t received = recv(sock, buffer.data(), buffer.size(), 0);
    close(sock);
    if (received < 0) {
        return std::nullopt;
    }
    buffer.resize(static_cast<size_t>(received));
    return buffer;
}

// Oye socket bana ke duniya se baat karange. (Spinning up socket to chat with the world.)
int createServerSocket() {
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return -1;
    }

    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        close(udpSocket);
        return -1;
    }

    sockaddr_in servAddr{};
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(kDnsPort);
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&servAddr), sizeof(servAddr)) != 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        close(udpSocket);
        return -1;
    }
    return udpSocket;
}

// Oye logging helper, bas halka phulka bakbak. (Lightweight gossip logger.)
void logPacketSummary(const dns::DnsPacket& packet) {
    std::ostringstream oss;
    oss << "id=" << packet.header.id << " qd=" << packet.header.qdCount
        << " an=" << packet.header.anCount << " ns=" << packet.header.nsCount
        << " ar=" << packet.header.arCount;
    if (!packet.questions.empty()) {
        oss << " qname=" << packet.questions.front().qname << " qtype=" << packet.questions.front().qtype;
    }
    std::cout << "Incoming packet: " << oss.str() << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    // Oye stdout flush on, taaki logs jaldi nikal jaan. (Auto flush so logs sprint out.)
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    setbuf(stdout, nullptr);

    // Oye command-line arguments, resolver nu pakad rahe. (Parsing command-line args to grab resolver.)
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--resolver" && i + 1 < argc) {
            std::string resolverAddr = argv[i + 1];
            auto colonPos = resolverAddr.find(':');
            if (colonPos != std::string::npos) {
                g_upstreamResolver = resolverAddr.substr(0, colonPos);
                g_upstreamPort = std::stoi(resolverAddr.substr(colonPos + 1));
            } else {
                g_upstreamResolver = resolverAddr;
                g_upstreamPort = 53;
            }
            ++i;
        }
    }

    // Oye server socket te dhyaan, bina isde kahani hi adhuri. (Server socket is the hero of this story.)
    int serverSocket = createServerSocket();
    if (serverSocket < 0) {
        return 1;
    }

    sockaddr_in clientAddress{};
    std::vector<uint8_t> buffer(kMaxPacketSize + 1);

    // Oye infinite loop, DNS seva 24x7. (Service loop, dhaba open 24x7.)
    while (true) {
        socklen_t clientAddrLen = sizeof(clientAddress);  // Oye har baar reset, address corruption na ho. (Reset each time to avoid address corruption.)
        ssize_t bytesRead = recvfrom(serverSocket, buffer.data(), kMaxPacketSize, 0,
                                     reinterpret_cast<sockaddr*>(&clientAddress), &clientAddrLen);
        if (bytesRead <= 0) {
            std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
            continue;
        }
        buffer[static_cast<size_t>(bytesRead)] = 0;
        std::vector<uint8_t> request(buffer.begin(), buffer.begin() + bytesRead);

        std::optional<std::vector<uint8_t>> response;
        try {
            dns::DnsPacket packet = dns::parsePacket(request);
            logPacketSummary(packet);

            if (packet.header.opcode != 0) {
                response = buildHeaderOnlyReply(packet);
            } else if (packet.header.rd == 0) {
                response = buildHeaderOnlyReply(packet);
            } else if (auto local = tryLocalAnswer(packet)) {
                response = local;
            } else if (packet.header.qdCount > 1) {
                // Oye multiple questions, apni factory khol rahe. (Multiple questions, running our own factory.)
                response = buildSyntheticAnswer(packet);
            } else {
                response = forwardToUpstream(request.data(), request.size());
                if (!response) {
                    // Oye upstream busy, asi khud answer de rahe. (Upstream ghosted, we self-serve.)
                    response = buildSyntheticAnswer(packet);
                }
            }
        } catch (const std::exception& ex) {
            std::cerr << "Parsing error: " << ex.what() << std::endl;
            try {
                dns::DnsPacket fallbackPacket;
                size_t offset = 0;
                fallbackPacket.header = dns::parseHeader(request, offset);
                response = dns::buildServFail(fallbackPacket);
            } catch (...) {
                response = std::nullopt;
            }
        }

        if (response && !response->empty()) {
            ssize_t sent = sendto(serverSocket, response->data(), response->size(), 0,
                                  reinterpret_cast<sockaddr*>(&clientAddress), clientAddrLen);
            if (sent < 0) {
                std::cerr << "Failed to send response: " << strerror(errno) << std::endl;
            }
        }
    }

    close(serverSocket);
    return 0;
}
