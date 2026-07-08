#pragma once

// Oye query te jawaab da faisla. (The decision for a query and its response.) This is
// the only place that knows the *order* of the strategies: local zone first, then
// upstream, then an error. Add a strategy here, not in main.

#include <cstdint>
#include <optional>
#include <vector>

#include "resolver/upstream.hpp"

namespace dns {

// Ek poora request datagram lao aur jawaab bytes de. std::nullopt matlab client nu
// kuch nahi bhejna (response hi nahi bana paaya).
// (Take one request datagram and return the response bytes. nullopt means send the
// client nothing at all - we could not even build an error response.)
std::optional<std::vector<std::uint8_t>> handleQuery(const std::vector<std::uint8_t>& request,
                                                     const UpstreamConfig& upstream);

}  // namespace dns
