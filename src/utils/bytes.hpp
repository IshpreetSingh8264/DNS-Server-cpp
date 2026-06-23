#pragma once

// Oye big-endian byte helpers, domain dyanu shavam. (Big-endian byte helpers, no
// domain knowledge whatsoever.)

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dns {

// Oye paddedha buffer vich se nuhe, chhuna ta ghabra de. (Read out of the byte buffer;
// throw rather than flail if the buffer is too short.)
std::uint16_t readU16(const std::vector<std::uint8_t>& data, std::size_t& offset);
std::uint32_t readU32(const std::vector<std::uint8_t>& data, std::size_t& offset);

void writeU16(std::vector<std::uint8_t>& out, std::uint16_t value);
void writeU32(std::vector<std::uint8_t>& out, std::uint32_t value);

}  // namespace dns
