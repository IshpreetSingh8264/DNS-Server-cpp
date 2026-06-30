#include "protocol/responses.hpp"

#include "protocol/writer.hpp"
#include "types/message.hpp"

namespace dns {

// Oye opcode di izzat rakho, rcode naal sauda thik karo. (Respect opcode, set rcode accordingly.)
std::uint8_t rcodeFor(std::uint8_t opcode, Rcode fallback) {
    // 4 => Not Implemented when non-standard opcode
    return opcode == 0 ? static_cast<std::uint8_t>(fallback)
                       : static_cast<std::uint8_t>(Rcode::kNotImplemented);
}

// Oye sirf header wala jawab, stage wali simplicity da ashirwad. (Header-only response for minimal stage expectations.)
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
    resp.header.qdCount = 0;
    resp.header.anCount = 0;
    resp.header.nsCount = 0;
    resp.header.arCount = 0;
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
    resp.header.anCount = 0;
    resp.header.nsCount = 0;
    resp.header.arCount = 0;
    resp.header.qdCount = static_cast<std::uint16_t>(query.questions.size());
    resp.questions = query.questions;
    return buildPacket(resp);
}

}  // namespace dns
