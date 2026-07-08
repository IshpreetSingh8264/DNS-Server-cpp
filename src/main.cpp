// DNS server entry point. Oye file sirf wiring kardi hai: arguments, socket, aur
// ghoom-ta serve loop. Koi domain logic nahi - wo resolver/handler de andar hai.
// (This file only wires things up: arguments, socket, and the serving loop. No domain
// logic - that lives in resolver/handler.)

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "net/socket.hpp"
#include "resolver/handler.hpp"
#include "resolver/upstream.hpp"
#include "utils/logger.hpp"

namespace {

// Oye baselines set kar rahe haan, code nu pad ke muskaan aayegi. (Setting stage for fun yet serious DNS antics.)
constexpr std::uint16_t kDnsPort = 2053;

// Oye port number padho, galat ho te kuch nahi. (Read a port number; if it is not one,
// hand back nothing.)
std::optional<std::uint16_t> parsePort(std::string_view text) {
    std::uint32_t value = 0;
    const char* const begin = text.data();
    const char* const end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{} || result.ptr != end || value > 0xFFFF) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

// Oye `--resolver <ip>` ya `--resolver <ip>:<port>`. (Accepts "--resolver <ip>" or
// "--resolver <ip>:<port>".) A bad address is reported and ignored rather than
// silently leaving the server pointed at 0.0.0.0.
void applyResolverArg(std::string_view address, dns::UpstreamConfig& upstream) {
    const std::size_t colon = address.find(':');
    if (colon == std::string_view::npos) {
        upstream.host = address;
        upstream.port = 53;
        return;
    }
    const std::optional<std::uint16_t> port = parsePort(address.substr(colon + 1));
    if (!port) {
        dns::logError("Ignoring --resolver " + std::string(address) + ": port is not a number 0-65535");
        return;
    }
    upstream.host = address.substr(0, colon);
    upstream.port = *port;
}

}  // namespace

int main(int argc, char* argv[]) {
    dns::UpstreamConfig upstream;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--resolver" && i + 1 < argc) {
            applyResolverArg(argv[++i], upstream);
        }
    }

    dns::logInfo("DNS server listening on 0.0.0.0:" + std::to_string(kDnsPort) + ", upstream " +
                 upstream.host + ":" + std::to_string(upstream.port));

    const int serverSocket = dns::bindServerSocket(kDnsPort);
    if (serverSocket < 0) {
        return 1;
    }

    // Oye infinite loop, DNS seva 24x7. (Service loop, dhaba open 24x7.)
    for (;;) {
        const std::optional<dns::Datagram> request = dns::receiveDatagram(serverSocket);
        if (!request) {
            continue;
        }
        const std::optional<std::vector<std::uint8_t>> response =
            dns::handleQuery(request->bytes, upstream);
        if (response && !response->empty()) {
            dns::sendDatagram(serverSocket, *response, request->from, request->fromLength);
        }
    }

    close(serverSocket);
    return 0;
}
