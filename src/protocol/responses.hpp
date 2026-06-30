#pragma once

// Oye locally banawan jawaab, jinhon de koi upstream zaroorat nahi. (Locally built
// responses, the ones that never need an upstream.)

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

}  // namespace dns
