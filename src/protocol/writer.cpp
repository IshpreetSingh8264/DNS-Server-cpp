#include "protocol/writer.hpp"

#include "protocol/names.hpp"
#include "types/message.hpp"
#include "utils/bytes.hpp"

namespace dns {

// Oye header likh ke packet nu suit-boot pa rahe haan. (Dressing packet with header in style.)
void writeHeader(std::vector<std::uint8_t>& out, const DnsHeader& header) {
    writeU16(out, header.id);
    std::uint16_t flags = 0;
    flags |= static_cast<std::uint16_t>(header.qr) << 15;
    flags |= static_cast<std::uint16_t>(header.opcode & 0xF) << 11;
    flags |= static_cast<std::uint16_t>(header.aa) << 10;
    flags |= static_cast<std::uint16_t>(header.tc) << 9;
    flags |= static_cast<std::uint16_t>(header.rd) << 8;
    flags |= static_cast<std::uint16_t>(header.ra) << 7;
    flags |= static_cast<std::uint16_t>(header.rcode & 0xF);
    writeU16(out, flags);
    writeU16(out, header.qdCount);
    writeU16(out, header.anCount);
    writeU16(out, header.nsCount);
    writeU16(out, header.arCount);
}

// Oye question likh ke upstream nu shagun bhej rahe. (Writing question to send as sweet gift upstream.)
void writeQuestion(std::vector<std::uint8_t>& out, const DnsQuestion& question) {
    writeName(out, question.qname);
    writeU16(out, question.qtype);
    writeU16(out, question.qclass);
}

// Oye record likh ke jawab nu sajja rahe. (Writing record to decorate the response.)
void writeRecord(std::vector<std::uint8_t>& out, const DnsRecord& record) {
    writeName(out, record.name);
    writeU16(out, record.type);
    writeU16(out, record.rclass);
    writeU32(out, record.ttl);
    writeU16(out, static_cast<std::uint16_t>(record.rdata.size()));
    out.insert(out.end(), record.rdata.begin(), record.rdata.end());
}

// Oye packet encode, home-cooked response taiyaar. (Encoding packet as home-cooked response.)
std::vector<std::uint8_t> buildPacket(const DnsPacket& packet) {
    std::vector<std::uint8_t> out;
    writeHeader(out, packet.header);
    for (const DnsQuestion& question : packet.questions) {
        writeQuestion(out, question);
    }
    for (const DnsRecord& record : packet.answers) {
        writeRecord(out, record);
    }
    for (const DnsRecord& record : packet.authorities) {
        writeRecord(out, record);
    }
    for (const DnsRecord& record : packet.additionals) {
        writeRecord(out, record);
    }
    return out;
}

}  // namespace dns
