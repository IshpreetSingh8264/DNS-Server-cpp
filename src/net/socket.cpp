#include "net/socket.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include "utils/logger.hpp"

namespace dns {

// Oye socket bana ke duniya se baat karange. (Spinning up socket to chat with the world.)
int bindServerSocket(std::uint16_t port) {
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        logError(std::string{"Socket creation failed: "} + strerror(errno));
        return -1;
    }

    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        logError(std::string{"SO_REUSEPORT failed: "} + strerror(errno));
        close(udpSocket);
        return -1;
    }

    sockaddr_in servAddr{};
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&servAddr), sizeof(servAddr)) != 0) {
        logError(std::string{"Bind failed: "} + strerror(errno));
        close(udpSocket);
        return -1;
    }
    return udpSocket;
}

// Oye ek packet pakadna. clientAddrLen har dafa reset hona zaroori hai, warna pichle
// client da address ghisat janda hai. (Grab one packet. fromLength must be reset every
// time or the previous client's address leaks into this one.)
std::optional<Datagram> receiveDatagram(int socketFd) {
    Datagram datagram;
    datagram.bytes.resize(kMaxDatagramSize);
    datagram.fromLength = sizeof(sockaddr_in);
    const ssize_t received =
        recvfrom(socketFd, datagram.bytes.data(), datagram.bytes.size(), 0,
                 reinterpret_cast<sockaddr*>(&datagram.from), &datagram.fromLength);
    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            logError(std::string{"Error receiving data: "} + strerror(errno));
        }
        return std::nullopt;
    }
    datagram.bytes.resize(static_cast<std::size_t>(received));
    return datagram;
}

bool sendDatagram(int socketFd, const std::vector<std::uint8_t>& bytes, const sockaddr_in& to,
                  socklen_t toLength) {
    const ssize_t sent = sendto(socketFd, bytes.data(), bytes.size(), 0,
                                reinterpret_cast<const sockaddr*>(&to), toLength);
    if (sent < 0) {
        logError(std::string{"Failed to send response: "} + strerror(errno));
        return false;
    }
    return true;
}

}  // namespace dns
