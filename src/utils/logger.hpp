#pragma once

// Oye saara log ek jagah, te sirf stderr te. (All logging, one place, and only ever on
// stderr.) stdout belongs to the process' data output, not to diagnostics: a DNS
// server that chats on stdout corrupts anything reading that stream.

#include <string>
#include <string_view>

#include "types/message.hpp"

namespace dns {

void logInfo(std::string_view message);
void logError(std::string_view message);

// Oye logging helper, bas halka phulka bakbak. (Lightweight gossip logger.)
void logPacketSummary(const DnsPacket& packet);

}  // namespace dns
