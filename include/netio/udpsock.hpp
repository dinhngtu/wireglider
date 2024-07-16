#pragma once

#include <variant>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <tdutil/fildes.hpp>

namespace wireglider {

class UdpServer {
public:
    UdpServer() {
        _sock = tdutil::FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));
        _sock.check();
    }

    UdpServer(tdutil::FileDescriptor &&sock) : _sock(std::move(sock)) {
    }

    UdpServer(sockaddr_in sin, bool offload, bool nonblock) {
        _sock = tdutil::FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));
        _sock.check();

        int rup = 1;
        if (setsockopt(_sock, SOL_SOCKET, SO_REUSEPORT, &rup, sizeof(rup)) < 0)
            throw std::system_error(errno, std::system_category(), "setsockopt(SO_REUSEPORT)");

        if (offload)
            set_offloads();

        if (bind(_sock, reinterpret_cast<sockaddr *>(&sin), sizeof(sin)) < 0)
            throw std::system_error(errno, std::system_category(), "bind");

        if (nonblock)
            _sock.set_nonblock(true);
    }

    UdpServer(sockaddr_in6 sin6, bool offload, bool nonblock) {
        _sock = tdutil::FileDescriptor(socket(AF_INET6, SOCK_DGRAM, 0));
        _sock.check();

        int rup = 1;
        if (setsockopt(_sock, SOL_SOCKET, SO_REUSEPORT, &rup, sizeof(rup)) < 0)
            throw std::system_error(errno, std::system_category(), "setsockopt(SO_REUSEPORT)");

        if (offload)
            set_offloads();

        if (bind(_sock, reinterpret_cast<sockaddr *>(&sin6), sizeof(sin6)) < 0)
            throw std::system_error(errno, std::system_category(), "bind");

        if (nonblock)
            _sock.set_nonblock(true);
    }

    constexpr tdutil::FileDescriptor &fd() {
        return _sock;
    }

private:
    void set_offloads() {
        int gro = 1;
        if (setsockopt(_sock, SOL_UDP, UDP_GRO, &gro, sizeof(gro)) < 0)
            throw std::system_error(errno, std::system_category(), "setsockopt(UDP_GRO)");

        int tos = 1;
        if (setsockopt(_sock, SOL_IP, IP_RECVTOS, &tos, sizeof(tos)) < 0)
            throw std::system_error(errno, std::system_category(), "setsockopt(IP_RECVTOS)");
    }

private:
    tdutil::FileDescriptor _sock;
};

} // namespace wireglider
