#pragma once

// Oye packet to bytes da encode taraf. (The encode side: packet to bytes.)

#include <cstdint>
#include <vector>

#include "types/message.hpp"

namespace dns {

// Oye header likh ke packet nu suit-boot pa rahe haan. (Dressing packet with header in style.)
void writeHeader(std::vector<std::uint8_t>& out, const DnsHeader& header);

void writeQuestion(std::vector<std::uint8_t>& out, const DnsQuestion& question);

void writeRecord(std::vector<std::uint8_t>& out, const DnsRecord& record);

// Oye packet encode, home-cooked response taiyaar. (Encoding packet as home-cooked response.)
// Names are written uncompressed, so the output is always a few bytes per name larger
// than the compressed form.
std::vector<std::uint8_t> buildPacket(const DnsPacket& packet);

}  // namespace dns
