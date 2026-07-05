#pragma once

// Oye apna chhota sa local zone. (Our little local zone.) This is a real zone file
// with real, deliberately chosen data - not a fallback. It answers the one name the
// CodeCrafters stages require, and returns nullopt for everything else so the query
// goes upstream.

#include <cstdint>
#include <optional>
#include <vector>

#include "types/message.hpp"

namespace dns {

// Ek A record, tedaan hamesha 8.8.8.8 te 300 second di TTL. (One A record, always
// 8.8.8.8 with a 300-second TTL.)
inline constexpr char kLocalZoneAddress[] = "8.8.8.8";
inline constexpr std::uint32_t kLocalZoneTtl = 300;

// std::nullopt matlab "mera ilaqa nahi, upstream te bhejo" - jawaab nahi.
// (nullopt means "not my zone, send it upstream" - never a synthesized answer.)
std::optional<std::vector<std::uint8_t>> tryLocalAnswer(const DnsPacket& query);

}  // namespace dns
