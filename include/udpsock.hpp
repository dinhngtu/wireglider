#pragma once

#include <variant>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <tdutil/fildes.hpp>

namespace wgss {

class UdpServer {
public:
    UdpServer(sockaddr_in sin) : _sin(sin) {
        _sock = tdutil::FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));
        _sock.check();

        if (bind(_sock, reinterpret_cast<sockaddr *>(&sin), sizeof(sin)) < 0)
            throw std::system_error(errno, std::system_category(), "bind");
    }

    UdpServer(sockaddr_in6 sin6) : _sin(sin6) {
        _sock = tdutil::FileDescriptor(socket(AF_INET6, SOCK_DGRAM, 0));
        _sock.check();

        if (bind(_sock, reinterpret_cast<sockaddr *>(&sin6), sizeof(sin6)) < 0)
            throw std::system_error(errno, std::system_category(), "bind");
    }

    constexpr tdutil::FileDescriptor &fd() {
        return _sock;
    }

private:
    tdutil::FileDescriptor _sock;
    std::variant<sockaddr_in, sockaddr_in6> _sin;
};

} // namespace wgss
