#pragma once

// Oye DNS naam de encode/decode, compression samet. (Encoding and decoding DNS
// names, compression pointers included.)

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dns {

// Dots nu tod ke labels bana dena. (Chop a dotted name into labels.)
std::vector<std::string> splitLabels(const std::string& name);

// Wire theek thi naam padho, `offset` te compression pointer de pichhe aa ke khada hona.
// (Read a name off the wire starting at `offset`; a compression pointer leaves `offset`
// just past the two pointer bytes. Throws on a pointer loop or a truncated label.)
std::string parseName(const std::vector<std::uint8_t>& data, std::size_t& offset);

// Naam likhna, bina compression de seedha label label. (Write a name as plain labels,
// no compression. Every well-known name fits comfortably under 255 bytes this way.)
void writeName(std::vector<std::uint8_t>& out, const std::string& name);

}  // namespace dns
