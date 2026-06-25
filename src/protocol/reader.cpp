#include "protocol/reader.hpp"

#include <stdexcept>

#include "protocol/names.hpp"
#include "types/message.hpp"
#include "utils/bytes.hpp"

namespace dns {

// Oye header read karke mast details le rahe. (Reading header to know the vibe.)
DnsHeader parseHeader(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    if (offset + kHeaderSize > data.size()) {
        throw std::runtime_error("Packet too small for header");
    }
    DnsHeader header;
    header.id = readU16(data, offset);
    const std::uint16_t flags = readU16(data, offset);
    header.qr = (flags >> 15) & 0x1;
    header.opcode = static_cast<std::uint8_t>((flags >> 11) & 0xF);
    header.aa = (flags >> 10) & 0x1;
    header.tc = (flags >> 9) & 0x1;
    header.rd = (flags >> 8) & 0x1;
    header.ra = (flags >> 7) & 0x1;
    header.rcode = static_cast<std::uint8_t>(flags & 0xF);
    header.qdCount = readU16(data, offset);
    header.anCount = readU16(data, offset);
    header.nsCount = readU16(data, offset);
    header.arCount = readU16(data, offset);
    return header;
}

// Oye question decode, pata lag rahe banda ki puchh reha. (Decoding what the curious client is asking.)
DnsQuestion parseQuestion(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    DnsQuestion question;
    question.qname = parseName(data, offset);
    question.qtype = readU16(data, offset);
    question.qclass = readU16(data, offset);
    return question;
}

// Oye record decode, answer/an/extra nu sambhal rahe. (Decoding record, juggling answer/auth/extra.)
DnsRecord parseRecord(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    DnsRecord record;
    record.name = parseName(data, offset);
    record.type = readU16(data, offset);
    record.rclass = readU16(data, offset);
    record.ttl = readU32(data, offset);
    const std::uint16_t rdlength = readU16(data, offset);
    if (offset + rdlength > data.size()) {
        throw std::runtime_error("RDATA exceeds packet");
    }
    record.rdata.insert(record.rdata.end(), data.begin() + offset, data.begin() + offset + rdlength);
    offset += rdlength;
    return record;
}

// Oye full packet decode, detail report bana ke. (Decoding full packet for gossip report.)
// Header counts drive the loops, so a lying count surfaces as a bounds throw rather
// than a half-read packet.
DnsPacket parsePacket(const std::vector<std::uint8_t>& data) {
    DnsPacket packet;
    std::size_t offset = 0;
    packet.header = parseHeader(data, offset);
    packet.questions.reserve(packet.header.qdCount);
    packet.answers.reserve(packet.header.anCount);
    packet.authorities.reserve(packet.header.nsCount);
    packet.additionals.reserve(packet.header.arCount);
    for (std::uint16_t i = 0; i < packet.header.qdCount; ++i) {
        packet.questions.push_back(parseQuestion(data, offset));
    }
    for (std::uint16_t i = 0; i < packet.header.anCount; ++i) {
        packet.answers.push_back(parseRecord(data, offset));
    }
    for (std::uint16_t i = 0; i < packet.header.nsCount; ++i) {
        packet.authorities.push_back(parseRecord(data, offset));
    }
    for (std::uint16_t i = 0; i < packet.header.arCount; ++i) {
        packet.additionals.push_back(parseRecord(data, offset));
    }
    return packet;
}

}  // namespace dns
