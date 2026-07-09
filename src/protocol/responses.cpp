#include "protocol/responses.hpp"

#include <algorithm>

#include "protocol/writer.hpp"
#include "types/message.hpp"

namespace dns {
namespace {

// Oye EDNS0 bina ke UDP te band da maan. (The UDP limit for a client that speaks no EDNS0.)
constexpr std::size_t kClassicUdpPayloadSize = 512;

}  // namespace

// Oye opcode di izzat rakho, rcode naal sauda thik karo. (Respect opcode, set rcode accordingly.)
std::uint8_t rcodeFor(std::uint8_t opcode, Rcode fallback) {
    // 4 => Not Implemented when non-standard opcode
    return opcode == 0 ? static_cast<std::uint8_t>(fallback)
                       : static_cast<std::uint8_t>(Rcode::kNotImplemented);
}

// Oye sirf header wala jawab, stage wali simplicity da ashirwad. (Header-only response
// for minimal stage expectations.) "Header-only" means no answer records, not "no
// question": the question section is echoed so the client can match the response to
// what it asked, and that costs 12 bytes plus the question either way.
std::vector<std::uint8_t> buildHeaderOnlyReply(const DnsPacket& query) {
    DnsPacket resp;
    resp.header.id = query.header.id;
    resp.header.qr = true;
    resp.header.opcode = query.header.opcode;
    resp.header.aa = false;
    resp.header.tc = false;
    resp.header.rd = query.header.rd;
    resp.header.ra = false;
    resp.header.rcode = rcodeFor(query.header.opcode, Rcode::kNoError);
    resp.questions = query.questions;
    resp.syncCounts();
    return buildPacket(resp);
}

// Oye local fallback, agar upstream ne taang kari to safar yahan hi khatam. (Fallback answer if upstream throws tantrum.)
std::vector<std::uint8_t> buildServFail(const DnsPacket& query) {
    DnsPacket resp;
    resp.header = query.header;
    resp.header.qr = true;
    resp.header.aa = false;
    resp.header.ra = false;
    resp.header.rcode = rcodeFor(query.header.opcode, Rcode::kServerFailure);
    resp.questions = query.questions;
    resp.syncCounts();
    return buildPacket(resp);
}

// Oye EDNS0 te 512. Client ne jo size bataya hai, oh hi maanna; par 512 to chhadna
// nahi (RFC 6891). (EDNS0 or 512. Believe the size the client advertised, but never
// go below 512 - RFC 6891.)
std::size_t maxResponseSize(const DnsPacket& query) {
    for (const DnsRecord& record : query.additionals) {
        if (record.type == static_cast<std::uint16_t>(RecordType::kOpt)) {
            // The OPT record's class field is the advertised UDP payload size, not a
            // class at all. That is the whole point of the record.
            return std::max<std::size_t>(record.rclass, kClassicUdpPayloadSize);
        }
    }
    return kClassicUdpPayloadSize;
}

// Oye jawaab kata de diya, par TC bit laga ke ta client nu pata lage. (Cut the answer
// short, but say so with the TC bit so the client knows.)
std::vector<std::uint8_t> buildTruncatedReply(const DnsPacket& query) {
    DnsPacket resp;
    resp.header = query.header;
    resp.header.qr = true;
    resp.header.aa = false;
    resp.header.tc = true;
    resp.header.rd = query.header.rd;
    resp.header.ra = true;
    resp.header.rcode = rcodeFor(query.header.opcode, Rcode::kNoError);
    resp.questions = query.questions;
    resp.syncCounts();
    return buildPacket(resp);
}

}  // namespace dns
