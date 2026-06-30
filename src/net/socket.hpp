#pragma once

// Oye UDP theek karan de kaam, ek jagah. (All UDP plumbing, one place.) This is the
// only layer that knows about file descriptors, sockaddr, and errno.

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace dns {

// Oye sab to bada UDP datagram jo assi padhna chahunde haan, 65507 bytes. (The largest
// UDP datagram we will ever read, 65507 bytes.) A 512-byte cap here would throw away
// half of any EDNS0 query before the parser ever sees it.
inline constexpr std::size_t kMaxDatagramSize = 65507;

// Oye UDP theek karan da ek khatra: raw bytes + kithon aaya. (One received UDP
// datagram: the raw bytes plus where it came from.)
struct Datagram {
    std::vector<std::uint8_t> bytes;
    sockaddr_in from{};
    socklen_t fromLength{};
};

// Oye server da socket bana ke 0.0.0.0 te port te baith jao. -1 matlab haar gaye.
// (Create and bind the server socket to 0.0.0.0:<port>. Returns -1 on failure.)
int bindServerSocket(std::uint16_t port);

// Ek datagram padho. A error te -1, warna bytes kitne aaye. (Read one datagram.
// Returns -1 on error, otherwise the number of bytes read.)
std::optional<Datagram> receiveDatagram(int socketFd);

bool sendDatagram(int socketFd, const std::vector<std::uint8_t>& bytes, const sockaddr_in& to,
                  socklen_t toLength);

}  // namespace dns
