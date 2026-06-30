#include "utils/logger.hpp"

#include <iostream>
#include <sstream>

namespace dns {
namespace {

// Oye har line nu turant flush hona chahida, warna debug runner nu late dikhna. (Flush
// every line; otherwise the debug runner sees the log late, or not at all.)
void writeLine(std::string_view message) {
    std::cerr << message << '\n';
    std::cerr.flush();
}

}  // namespace

void logInfo(std::string_view message) {
    writeLine(message);
}

void logError(std::string_view message) {
    writeLine(message);
}

void logPacketSummary(const DnsPacket& packet) {
    std::ostringstream oss;
    oss << "Incoming packet: id=" << packet.header.id << " qr=" << packet.header.qr
        << " opcode=" << toString(static_cast<Opcode>(packet.header.opcode))
        << " rd=" << packet.header.rd << " rcode=" << toString(static_cast<Rcode>(packet.header.rcode))
        << " qd=" << packet.header.qdCount << " an=" << packet.header.anCount
        << " ns=" << packet.header.nsCount << " ar=" << packet.header.arCount;
    for (const DnsQuestion& question : packet.questions) {
        oss << "\n  question: " << question.qname << " "
            << toString(static_cast<RecordType>(question.qtype)) << ' '
            << toString(static_cast<RecordClass>(question.qclass));
    }
    writeLine(oss.str());
}

}  // namespace dns
