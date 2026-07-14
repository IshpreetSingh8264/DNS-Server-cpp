#pragma once

// Oye ik packet vich sau questions. (Several questions in one packet.)

#include <cstdint>
#include <optional>
#include <vector>

#include "resolver/upstream.hpp"
#include "types/message.hpp"

namespace dns {

// A multi-question datagram is a legal query, but a single upstream query is not
// guaranteed to come back answered: a resolver may reply to the first question only,
// or reject the packet outright, and then a straight relay hands the client an empty
// answer section. So ask the upstream once per question and merge the replies.
//
// Every record in the result came from the upstream. This function never invents an
// answer, and if the upstream cannot be reached at all it returns nullopt so the
// caller can return SERVFAIL rather than paper over it.
std::optional<std::vector<std::uint8_t>> forwardMultiQuestion(const DnsPacket& query,
                                                              const UpstreamConfig& upstream);

}  // namespace dns
