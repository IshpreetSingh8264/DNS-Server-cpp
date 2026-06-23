#include "utils/bytes.hpp"

#include <stdexcept>

namespace dns {

// Oye guard pehlan, phir byte lawa. (Guard first, then byte lawa.)
std::uint16_t readU16(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    if (offset + 2 > data.size()) {
        throw std::runtime_error("Buffer underrun while reading integer");
    }
    const std::uint16_t value = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[offset]) << 8) | data[offset + 1]);
    offset += 2;
    return value;
}

std::uint32_t readU32(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("Buffer underrun while reading integer");
    }
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        value = (value << 8) | data[offset + i];
    }
    offset += 4;
    return value;
}

// Oye bade endian vich likhna, ta har reader nu samajh aa jaaye. (Write big-endian so
// every reader understands it.)
void writeU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void writeU32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

}  // namespace dns
