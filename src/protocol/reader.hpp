#pragma once

// Oye bytes to packet da decode taraf. (The decode side: bytes to packet.)

#include <cstddef>
#include <cstdint>
#include <vector>

#include "types/message.hpp"

namespace dns {

// Oye 12 byte da header padho, `offset` te 12 tod ke khada hona. (Read the 12-byte
// header; `offset` is left 12 bytes further along. Throws if the datagram is shorter.)
DnsHeader parseHeader(const std::vector<std::uint8_t>& data, std::size_t& offset);

DnsQuestion parseQuestion(const std::vector<std::uint8_t>& data, std::size_t& offset);

DnsRecord parseRecord(const std::vector<std::uint8_t>& data, std::size_t& offset);

// Oye poora packet decode, chaaron section nu samajh ke. (Decode a whole packet:
// header, questions, answers, authorities, additionals.)
DnsPacket parsePacket(const std::vector<std::uint8_t>& data);

}  // namespace dns
