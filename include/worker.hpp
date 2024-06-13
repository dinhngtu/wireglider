#pragma once

#include <cstring>
#include <memory>
#include <vector>
#include <mutex>
#include <tuple>
#include <variant>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <tdutil/epollman.hpp>
#include <wireguard_ffi.h>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <xxhash.h>

#include "tun.hpp"
#include "udpsock.hpp"
#include "rundown.hpp"

namespace std {

template <>
struct hash<sockaddr_in> {
    size_t operator()(const sockaddr_in &a) const noexcept {
        return XXH3_64bits(&a, offsetof(sockaddr_in, sin_zero));
    }
};

template <>
struct hash<sockaddr_in6> {
    size_t operator()(const sockaddr_in6 &a) const noexcept {
        return XXH3_64bits(&a, sizeof(a));
    }
};

} // namespace std

static inline bool operator==(const sockaddr_in &a, const sockaddr_in &b) noexcept {
    return !memcmp(&a, &b, offsetof(sockaddr_in, sin_zero));
}

static inline auto operator<=>(const sockaddr_in &a, const sockaddr_in &b) noexcept {
    return memcmp(&a, &b, offsetof(sockaddr_in, sin_zero));
}

static inline bool operator==(const sockaddr_in6 &a, const sockaddr_in6 &b) noexcept {
    return !memcmp(&a, &b, sizeof(a));
}

static inline auto operator<=>(const sockaddr_in6 &a, const sockaddr_in6 &b) noexcept {
    return memcmp(&a, &b, sizeof(a));
}

namespace wgss {

using ClientAddress = std::variant<sockaddr_in, sockaddr_in6>;

struct Client : public CdsHashtableNode<ClientAddress, Client> {
    uint32_t index;
    std::mutex mutex;
    // protected by mutex:
    wireguard_tunnel *tunnel;
};

struct WorkerArg {
    Tun *tun;
    UdpServer *server;
    bool tun_is_v6;
    bool srv_is_v6;
    CdsHashtable<ClientAddress, Client> *clients;
};

class Worker {
public:
    Worker(const WorkerArg &arg);

    void run();

private:
    void do_tun(epoll_event *ev);
    virtio_net_hdr do_tun_read(std::vector<std::vector<uint8_t>> &out, epoll_event *ev);
    void do_server_write(const virtio_net_hdr &vnethdr, std::vector<std::vector<uint8_t>> &out);

    void do_server(epoll_event *ev);

    size_t calc_overhead() {
        size_t ret = sizeof(udphdr) + 32;
        ret += _arg.srv_is_v6 ? sizeof(ip6_hdr) : sizeof(iphdr);
        return ret;
    }

private:
    WorkerArg _arg;
    tdutil::EpollManager<> _poll;
    size_t _overhead;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wgss
