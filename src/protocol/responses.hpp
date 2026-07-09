#pragma once

// Oye locally banawan jawaab, jinhon de koi upstream zaroorat nahi. (Locally built
// responses, the ones that never need an upstream.)

#include <cstddef>
#include <cstdint>
#include <vector>

#include "types/message.hpp"

namespace dns {

// Oye opcode di izzat rakho, rcode naal sauda thik karo. (Respect the opcode, settle
// the rcode accordingly.) A non-QUERY opcode is always NOTIMP, whatever the caller
// asked for.
std::uint8_t rcodeFor(std::uint8_t opcode, Rcode fallback);

// Oye sirf header wala jawab, stage wali simplicity da ashirwad. (Header-only response
// for minimal stage expectations. Used for non-QUERY opcodes and for queries with
// recursion desired cleared.)
std::vector<std::uint8_t> buildHeaderOnlyReply(const DnsPacket& query);

// Oye local fallback, agar upstream ne taang kari to safar yahan hi khatam. (When the
// upstream goes missing, the trip ends here: an error, not a guess.)
std::vector<std::uint8_t> buildServFail(const DnsPacket& query);

// Oye client kitna bada jawab sammhal sakda hai. (How big a response the client is
// willing to accept over plain UDP.) An EDNS0 OPT record carries the size the client
// advertised, in the record's class field. With no OPT record the classic 512-byte
// limit applies, and RFC 6891 says a smaller advertised size is still honoured as 512.
std::size_t maxResponseSize(const DnsPacket& query);

// Oye upstream da jawaab client nu nahi samaatda. RFC 2181 section 9: thoda sa answer
// chhadke bhejne to koi bhal nahi, kyunki client samajh nahi payega ki kuch reh gaya.
// Sirf question section bhejo te TC bit lagao, ta client baad vich puchh sake.
// (The upstream's answer is too big for the client. Per RFC 2181 section 9, sending a
// partial answer is worse than none, because the client cannot tell that records are
// missing. Send the question section with TC set so the client knows to retry.)
std::vector<std::uint8_t> buildTruncatedReply(const DnsPacket& query);

}  // namespace dns
