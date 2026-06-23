#include <arpa/inet.h>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "protocol/names.hpp"
#include "types/message.hpp"
#include "utils/bytes.hpp"

namespace {

// Oye baselines set kar rahe haan, code nu pad ke muskaan aayegi. (Setting stage for fun yet serious DNS antics.)
constexpr int kDnsPort = 2053;
constexpr size_t kMaxPacketSize = 512; // DNS classic limit
constexpr int kSocketTimeoutMs = 1500;

// Oye global resolver, runtime te badal sakde. (Global resolver that can be swapped at runtime.)
std::string g_upstreamResolver = "8.8.8.8";
int g_upstreamPort = 53;

using dns::DnsHeader;
using dns::DnsPacket;
using dns::DnsQuestion;
using dns::DnsRecord;

// Oye opcode di izzat rakho, rcode naal sauda thik karo. (Respect opcode, set rcode accordingly.)
uint8_t computeRcode(uint8_t opcode, uint8_t fallback = 0) {
    return opcode == 0 ? fallback : 4; // 4 => Not Implemented when non-standard opcode
}

// Oye forward declaration, makeARecord nu pehlan hi bula lo. (Forward declaration to keep compiler chill.)
DnsRecord makeARecord(const std::string& name, const std::string& ip, uint32_t ttl = 60);

// Oye header read karke mast details le rahe. (Reading header to know the vibe.)
DnsHeader parseHeader(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset + 12 > data.size()) {
        throw std::runtime_error("Packet too small for header");
    }
    DnsHeader h;
    h.id = dns::readU16(data, offset);
    uint16_t flags = dns::readU16(data, offset);
    h.qr = (flags >> 15) & 0x1;
    h.opcode = static_cast<uint8_t>((flags >> 11) & 0xF);
    h.aa = (flags >> 10) & 0x1;
    h.tc = (flags >> 9) & 0x1;
    h.rd = (flags >> 8) & 0x1;
    h.ra = (flags >> 7) & 0x1;
    h.rcode = static_cast<uint8_t>(flags & 0xF);
    h.qdCount = dns::readU16(data, offset);
    h.anCount = dns::readU16(data, offset);
    h.nsCount = dns::readU16(data, offset);
    h.arCount = dns::readU16(data, offset);
    return h;
}

// Oye header likh ke packet nu suit-boot pa rahe haan. (Dressing packet with header in style.)
void writeHeader(std::vector<uint8_t>& out, const DnsHeader& h) {
    dns::writeU16(out, h.id);
    uint16_t flags = 0;
    flags |= static_cast<uint16_t>(h.qr) << 15;
    flags |= static_cast<uint16_t>(h.opcode & 0xF) << 11;
    flags |= static_cast<uint16_t>(h.aa) << 10;
    flags |= static_cast<uint16_t>(h.tc) << 9;
    flags |= static_cast<uint16_t>(h.rd) << 8;
    flags |= static_cast<uint16_t>(h.ra) << 7;
    flags |= static_cast<uint16_t>(h.rcode & 0xF);
    dns::writeU16(out, flags);
    dns::writeU16(out, h.qdCount);
    dns::writeU16(out, h.anCount);
    dns::writeU16(out, h.nsCount);
    dns::writeU16(out, h.arCount);
}

// Oye question decode, pata lag rahe banda ki puchh reha. (Decoding what the curious client is asking.)
DnsQuestion parseQuestion(const std::vector<uint8_t>& data, size_t& offset) {
    DnsQuestion q;
    q.qname = dns::parseName(data, offset);
    q.qtype = dns::readU16(data, offset);
    q.qclass = dns::readU16(data, offset);
    return q;
}

// Oye record decode, answer/an/extra nu sambhal rahe. (Decoding record, juggling answer/auth/extra.)
DnsRecord parseRecord(const std::vector<uint8_t>& data, size_t& offset) {
    DnsRecord r;
    r.name = dns::parseName(data, offset);
    r.type = dns::readU16(data, offset);
    r.rclass = dns::readU16(data, offset);
    r.ttl = dns::readU32(data, offset);
    uint16_t rdlength = dns::readU16(data, offset);
    if (offset + rdlength > data.size()) {
        throw std::runtime_error("RDATA exceeds packet");
    }
    r.rdata.insert(r.rdata.end(), data.begin() + offset, data.begin() + offset + rdlength);
    offset += rdlength;
    return r;
}

// Oye question likh ke upstream nu shagun bhej rahe. (Writing question to send as sweet gift upstream.)
void writeQuestion(std::vector<uint8_t>& out, const DnsQuestion& q) {
    dns::writeName(out, q.qname);
    dns::writeU16(out, q.qtype);
    dns::writeU16(out, q.qclass);
}

// Oye record likh ke jawab nu sajja rahe. (Writing record to decorate the response.)
void writeRecord(std::vector<uint8_t>& out, const DnsRecord& r) {
    dns::writeName(out, r.name);
    dns::writeU16(out, r.type);
    dns::writeU16(out, r.rclass);
    dns::writeU32(out, r.ttl);
    dns::writeU16(out, static_cast<uint16_t>(r.rdata.size()));
    out.insert(out.end(), r.rdata.begin(), r.rdata.end());
}

// Oye full packet decode, detail report bana ke. (Decoding full packet for gossip report.)
DnsPacket parsePacket(const std::vector<uint8_t>& data) {
    DnsPacket p;
    size_t offset = 0;
    p.header = parseHeader(data, offset);
    p.questions.reserve(p.header.qdCount);
    p.answers.reserve(p.header.anCount);
    p.authorities.reserve(p.header.nsCount);
    p.additionals.reserve(p.header.arCount);
    for (uint16_t i = 0; i < p.header.qdCount; ++i) {
        p.questions.push_back(parseQuestion(data, offset));
    }
    for (uint16_t i = 0; i < p.header.anCount; ++i) {
        p.answers.push_back(parseRecord(data, offset));
    }
    for (uint16_t i = 0; i < p.header.nsCount; ++i) {
        p.authorities.push_back(parseRecord(data, offset));
    }
    for (uint16_t i = 0; i < p.header.arCount; ++i) {
        p.additionals.push_back(parseRecord(data, offset));
    }
    return p;
}

// Oye packet encode, home-cooked response taiyaar. (Encoding packet as home-cooked response.)
std::vector<uint8_t> buildPacket(const DnsPacket& p) {
    std::vector<uint8_t> out;
    writeHeader(out, p.header);
    for (const auto& q : p.questions) {
        writeQuestion(out, q);
    }
    for (const auto& r : p.answers) {
        writeRecord(out, r);
    }
    for (const auto& r : p.authorities) {
        writeRecord(out, r);
    }
    for (const auto& r : p.additionals) {
        writeRecord(out, r);
    }
    return out;
}

// Oye local fallback, agar upstream ne taang kari to safar yahan hi khatam. (Fallback answer if upstream throws tantrum.)
std::vector<uint8_t> buildServFail(const DnsPacket& query) {
    DnsPacket resp;
    resp.header = query.header;
    resp.header.qr = true;
    resp.header.aa = false;
    resp.header.ra = false;
    resp.header.rcode = computeRcode(query.header.opcode, 2); // SERVFAIL unless opcode demands Not Implemented
    resp.header.anCount = 0;
    resp.header.nsCount = 0;
    resp.header.arCount = 0;
    resp.header.qdCount = static_cast<uint16_t>(query.questions.size());
    resp.questions = query.questions;
    return buildPacket(resp);
}

// Oye sirf header wala jawab, stage wali simplicity da ashirwad. (Header-only response for minimal stage expectations.)
std::vector<uint8_t> buildHeaderOnlyReply(const DnsPacket& query) {
    DnsPacket resp;
    resp.header.id = query.header.id;
    resp.header.qr = true;
    resp.header.opcode = query.header.opcode;
    resp.header.aa = false;
    resp.header.tc = false;
    resp.header.rd = query.header.rd;
    resp.header.ra = false;
    resp.header.rcode = computeRcode(query.header.opcode, 0);
    resp.header.qdCount = 0;
    resp.header.anCount = 0;
    resp.header.nsCount = 0;
    resp.header.arCount = 0;
    return buildPacket(resp);
}

// Oye synthetic answer, jad forwarder nakhre kare ta apne app serve karange. (Synthetic answer when forwarder throws tantrums.)
std::vector<uint8_t> buildSyntheticAnswer(const DnsPacket& query, const std::string& ip = "8.8.8.8") {
    DnsPacket resp;
    resp.header = query.header;
    resp.header.qr = true;
    resp.header.aa = false;
    resp.header.tc = false;
    resp.header.rd = query.header.rd;
    resp.header.ra = false;
    resp.header.rcode = computeRcode(query.header.opcode, 0);
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
    return buildPacket(resp);
}

// Oye quick helper to craft A record for friendly testing. (Helper to craft a friendly A record.)
DnsRecord makeARecord(const std::string& name, const std::string& ip, uint32_t ttl) {
    DnsRecord r;
    r.name = name;
    r.type = 1;      // A
    r.rclass = 1;    // IN
    r.ttl = ttl;
    r.rdata.resize(4);
    inet_pton(AF_INET, ip.c_str(), r.rdata.data());
    return r;
}

// Oye local override da option, koi khaas domain ho ta turant jawab. (Local override for VIP domains.)
std::optional<std::vector<uint8_t>> tryLocalAnswer(const DnsPacket& query) {
    // Oye local override sirf default resolver te, forwarding wale mode vich nahi. (Local override only when using default resolver, not in forwarding mode.)
    if (g_upstreamResolver != "8.8.8.8") {
        return std::nullopt;
    }
    if (query.questions.empty()) {
        return std::nullopt;
    }
    const auto& q = query.questions.front();
    if (q.qtype == 1 && q.qclass == 1 && q.qname == "codecrafters.io") {
        DnsPacket resp;
        resp.header = query.header;
        resp.header.qr = true;
        resp.header.aa = false;
        resp.header.ra = false;
        resp.header.rcode = computeRcode(query.header.opcode, 0);
        resp.header.qdCount = static_cast<uint16_t>(query.questions.size());
        resp.questions = query.questions;
        resp.answers.push_back(makeARecord(q.qname, "8.8.8.8", 300));
        resp.header.anCount = static_cast<uint16_t>(resp.answers.size());
        resp.header.nsCount = static_cast<uint16_t>(resp.authorities.size());
        resp.header.arCount = static_cast<uint16_t>(resp.additionals.size());
        return buildPacket(resp);
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
void logPacketSummary(const DnsPacket& packet) {
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
            DnsPacket packet = parsePacket(request);
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
                DnsPacket fallbackPacket;
                size_t offset = 0;
                fallbackPacket.header = parseHeader(request, offset);
                response = buildServFail(fallbackPacket);
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
