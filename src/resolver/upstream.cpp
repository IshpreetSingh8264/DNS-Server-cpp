#include "resolver/upstream.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "net/socket.hpp"
#include "utils/logger.hpp"

namespace dns {
namespace {

// Oye forwarder di time-out. (The forwarder's timeout.)
constexpr int kUpstreamTimeoutMs = 1500;

}  // namespace

// Oye upstream forwarding, packet nu Uber bhej rahe Google DNS kol. (Forwarding packet via Uber to Google DNS.)
std::optional<std::vector<std::uint8_t>> forwardToUpstream(const UpstreamConfig& upstream,
                                                            const std::uint8_t* data,
                                                            std::size_t length) {
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        logError(std::string{"Upstream socket creation failed: "} + strerror(errno));
        return std::nullopt;
    }

    timeval tv{};
    tv.tv_sec = kUpstreamTimeoutMs / 1000;
    tv.tv_usec = (kUpstreamTimeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(upstream.port);
    if (inet_pton(AF_INET, upstream.host.c_str(), &server.sin_addr) != 1) {
        logError("Upstream host is not a valid IPv4 address: " + upstream.host);
        close(sock);
        return std::nullopt;
    }

    // Oye connect() zaroori hai, warna kernel kisi de bhi datagram nu jawaab samajh
    // lavan ge. Aaj kal koi ukhaad pakad ke 8.8.8.8 nu jawaab bhej de, oh seedha
    // client tak pohanch janda - te assi usnu "jawaab" maan ke bhej dende haan.
    // (connect() is not optional. Without it the kernel hands us a reply from any
    // source, and whatever random datagram arrives while we wait gets relayed to a
    // real client as if the upstream had said it. Connecting pins the peer, so only
    // the resolver's own datagram is accepted.)
    if (connect(sock, reinterpret_cast<sockaddr*>(&server), sizeof(server)) != 0) {
        logError(std::string{"Could not connect to upstream: "} + strerror(errno));
        close(sock);
        return std::nullopt;
    }

    const ssize_t sent = send(sock, data, length, 0);
    if (sent < 0) {
        logError(std::string{"Upstream send failed: "} + strerror(errno));
        close(sock);
        return std::nullopt;
    }

    // Oye poora datagram room, 512 nahi. A 512-byte buffer here silently chopped the
    // tail off any large reply (a big answer section, a chunk of additional records)
    // and the client got a corrupt packet with no indication anything was missing.
    // (Full datagram room, not 512. A 512-byte buffer silently chopped the tail off
    // any large reply and the client got a corrupt packet with nothing indicating
    // data was missing. The caller, not this module, decides what fits.)
    std::vector<std::uint8_t> buffer(kMaxDatagramSize);
    const ssize_t received = recv(sock, buffer.data(), buffer.size(), 0);
    close(sock);
    if (received < 0) {
        // Timeout or ICMP-unreachable; the caller turns this into SERVFAIL.
        return std::nullopt;
    }
    buffer.resize(static_cast<std::size_t>(received));
    return buffer;
}

}  // namespace dns
