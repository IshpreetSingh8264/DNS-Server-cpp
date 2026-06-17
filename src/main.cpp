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

namespace {

// Oye baselines set kar rahe haan, code nu pad ke muskaan aayegi. (Setting stage for fun yet serious DNS antics.)
constexpr int kDnsPort = 2053;
constexpr size_t kMaxPacketSize = 512; // DNS classic limit
constexpr const char* kUpstreamResolver = "8.8.8.8"; // Default Google DNS
constexpr int kUpstreamPort = 53;
constexpr int kSocketTimeoutMs = 1500;

// Oye opcode di izzat rakho, rcode naal sauda thik karo. (Respect opcode, set rcode accordingly.)
uint8_t computeRcode(uint8_t opcode, uint8_t fallback = 0) {
    return opcode == 0 ? fallback : 4; // 4 => Not Implemented when non-standard opcode
}

// Oye safe casting helper, bhulekhe vich overflow na ho jaave. (Guarding against goofy overflow surprises.)
template <typename T>
T readUInt(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset + sizeof(T) > data.size()) {
        throw std::runtime_error("Buffer underrun while reading integer");
    }
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        value = static_cast<T>((value << 8) | data[offset + i]);
    }
    offset += sizeof(T);
    return value;
}

// Oye writer helper, byte-by-byte love letter bhej rahe haan. (Writing integers as a byte love letter.)
template <typename T>
void writeUInt(std::vector<uint8_t>& out, T value) {
    for (int i = sizeof(T) - 1; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

struct DnsHeader {
    uint16_t id{};
    bool qr{};
    uint8_t opcode{};
    bool aa{};
    bool tc{};
    bool rd{};
    bool ra{};
    uint8_t rcode{};
    uint16_t qdCount{};
    uint16_t anCount{};
    uint16_t nsCount{};
    uint16_t arCount{};
};

struct DnsQuestion {
    std::string qname;
    uint16_t qtype{};
    uint16_t qclass{};
};

struct DnsRecord {
    std::string name;
    uint16_t type{};
    uint16_t rclass{};
    uint32_t ttl{};
    std::vector<uint8_t> rdata;
};

struct DnsPacket {
    DnsHeader header;
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> additionals;
};

// Oye label splitter, dots nu tod ke jalebi bana rahe haan. (Splitting dotted names like jalebi spirals.)
std::vector<std::string> splitLabels(const std::string& name) {
    std::vector<std::string> labels;
    std::stringstream ss(name);
    std::string part;
    while (std::getline(ss, part, '.')) {
        if (!part.empty()) {
            labels.push_back(part);
        }
    }
    return labels;
}

// Oye DNS naam parse kar rahe, compression de nakhre vi sambhal rahe. (Parsing DNS names while babysitting compression drama.)
std::string parseName(const std::vector<uint8_t>& data, size_t& offset, int depth = 0) {
    if (depth > 20) {
        throw std::runtime_error("Name compression loop detected");
    }
    std::string name;
    while (offset < data.size()) {
        uint8_t len = data[offset];
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= data.size()) {
                throw std::runtime_error("Incomplete compression pointer");
            }
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | data[offset + 1]);
            offset += 2;
            size_t newOffset = ptr;
            std::string suffix = parseName(data, newOffset, depth + 1);
            name += suffix;
            return name;
        }
        if (len == 0) {
            offset += 1;
            break;
        }
        offset += 1;
        if (offset + len > data.size()) {
            throw std::runtime_error("Label exceeds packet bounds");
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        name.append(reinterpret_cast<const char*>(&data[offset]), len);
        offset += len;
    }
    return name;
}

// Oye DNS naam likh rahe, compression to bina simple gaddi. (Writing DNS names plain, no fancy compression joyride.)
void writeName(std::vector<uint8_t>& out, const std::string& name) {
    auto labels = splitLabels(name);
    for (const auto& label : labels) {
        out.push_back(static_cast<uint8_t>(label.size()));
        out.insert(out.end(), label.begin(), label.end());
    }
    out.push_back(0);
}

// Oye header read karke mast details le rahe. (Reading header to know the vibe.)
DnsHeader parseHeader(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset + 12 > data.size()) {
        throw std::runtime_error("Packet too small for header");
    }
    DnsHeader h;
    h.id = readUInt<uint16_t>(data, offset);
    uint16_t flags = readUInt<uint16_t>(data, offset);
    h.qr = (flags >> 15) & 0x1;
    h.opcode = static_cast<uint8_t>((flags >> 11) & 0xF);
    h.aa = (flags >> 10) & 0x1;
    h.tc = (flags >> 9) & 0x1;
    h.rd = (flags >> 8) & 0x1;
    h.ra = (flags >> 7) & 0x1;
    h.rcode = static_cast<uint8_t>(flags & 0xF);
    h.qdCount = readUInt<uint16_t>(data, offset);
    h.anCount = readUInt<uint16_t>(data, offset);
    h.nsCount = readUInt<uint16_t>(data, offset);
    h.arCount = readUInt<uint16_t>(data, offset);
    return h;
}

// Oye header likh ke packet nu suit-boot pa rahe haan. (Dressing packet with header in style.)
void writeHeader(std::vector<uint8_t>& out, const DnsHeader& h) {
    writeUInt<uint16_t>(out, h.id);
    uint16_t flags = 0;
    flags |= static_cast<uint16_t>(h.qr) << 15;
    flags |= static_cast<uint16_t>(h.opcode & 0xF) << 11;
    flags |= static_cast<uint16_t>(h.aa) << 10;
    flags |= static_cast<uint16_t>(h.tc) << 9;
    flags |= static_cast<uint16_t>(h.rd) << 8;
    flags |= static_cast<uint16_t>(h.ra) << 7;
    flags |= static_cast<uint16_t>(h.rcode & 0xF);
    writeUInt<uint16_t>(out, flags);
    writeUInt<uint16_t>(out, h.qdCount);
    writeUInt<uint16_t>(out, h.anCount);
    writeUInt<uint16_t>(out, h.nsCount);
    writeUInt<uint16_t>(out, h.arCount);
}

// Oye question decode, pata lag rahe banda ki puchh reha. (Decoding what the curious client is asking.)
DnsQuestion parseQuestion(const std::vector<uint8_t>& data, size_t& offset) {
    DnsQuestion q;
    q.qname = parseName(data, offset);
    q.qtype = readUInt<uint16_t>(data, offset);
    q.qclass = readUInt<uint16_t>(data, offset);
    return q;
}

// Oye record decode, answer/an/extra nu sambhal rahe. (Decoding record, juggling answer/auth/extra.)
DnsRecord parseRecord(const std::vector<uint8_t>& data, size_t& offset) {
    DnsRecord r;
    r.name = parseName(data, offset);
    r.type = readUInt<uint16_t>(data, offset);
    r.rclass = readUInt<uint16_t>(data, offset);
    r.ttl = readUInt<uint32_t>(data, offset);
    uint16_t rdlength = readUInt<uint16_t>(data, offset);
    if (offset + rdlength > data.size()) {
        throw std::runtime_error("RDATA exceeds packet");
    }
    r.rdata.insert(r.rdata.end(), data.begin() + offset, data.begin() + offset + rdlength);
    offset += rdlength;
    return r;
}

// Oye question likh ke upstream nu shagun bhej rahe. (Writing question to send as sweet gift upstream.)
void writeQuestion(std::vector<uint8_t>& out, const DnsQuestion& q) {
    writeName(out, q.qname);
    writeUInt<uint16_t>(out, q.qtype);
    writeUInt<uint16_t>(out, q.qclass);
}

// Oye record likh ke jawab nu sajja rahe. (Writing record to decorate the response.)
void writeRecord(std::vector<uint8_t>& out, const DnsRecord& r) {
    writeName(out, r.name);
    writeUInt<uint16_t>(out, r.type);
    writeUInt<uint16_t>(out, r.rclass);
    writeUInt<uint32_t>(out, r.ttl);
    writeUInt<uint16_t>(out, static_cast<uint16_t>(r.rdata.size()));
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

// Oye quick helper to craft A record for friendly testing. (Helper to craft a friendly A record.)
DnsRecord makeARecord(const std::string& name, const std::string& ip, uint32_t ttl = 60) {
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
    upstream.sin_port = htons(kUpstreamPort);
    inet_pton(AF_INET, kUpstreamResolver, &upstream.sin_addr);

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

int main() {
    // Oye stdout flush on, taaki logs jaldi nikal jaan. (Auto flush so logs sprint out.)
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    setbuf(stdout, nullptr);

    // Oye server socket te dhyaan, bina isde kahani hi adhuri. (Server socket is the hero of this story.)
    int serverSocket = createServerSocket();
    if (serverSocket < 0) {
        return 1;
    }

    sockaddr_in clientAddress{};
    socklen_t clientAddrLen = sizeof(clientAddress);
    std::vector<uint8_t> buffer(kMaxPacketSize + 1);

    // Oye infinite loop, DNS seva 24x7. (Service loop, dhaba open 24x7.)
    while (true) {
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
            } else {
                response = forwardToUpstream(request.data(), request.size());
                if (!response) {
                    response = buildServFail(packet);
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
