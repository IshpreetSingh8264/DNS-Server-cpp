#pragma once

// Oye upstream te bhejna. (Forwarding upstream.) This is the ONLY way a non-local
// answer ever reaches a client: whatever comes back is relayed byte for byte, so the
// client gets what the upstream really said, compression included.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns {

// Oye upstream da address, command line to aaunda hai. (The upstream address, handed
// in from the command line.) Passed by value rather than kept in a global, so two
// configurations can never race.
struct UpstreamConfig {
    std::string host{"8.8.8.8"};
    std::uint16_t port{53};
};

// Oye packet bhejo te jawaab wait karo. std::nullopt matlab upstream tak pohanch
// nahi paye (socket error ya 1.5 second da timeout) - jawaab nahi, error.
// (Send the datagram and wait for the reply. nullopt means the upstream was
// unreachable: a socket error or the timeout. It is never an empty answer.)
std::optional<std::vector<std::uint8_t>> forwardToUpstream(const UpstreamConfig& upstream,
                                                            const std::uint8_t* data,
                                                            std::size_t length);

}  // namespace dns
