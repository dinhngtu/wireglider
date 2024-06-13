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
#include <xxhash.h>

#include "tun.hpp"
#include "udpsock.hpp"
#include "rundown.hpp"
#include "maple_tree.hpp"

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

using ClientEndpoint = std::variant<sockaddr_in, sockaddr_in6>;

using IpRange = std::variant<std::pair<in_addr, unsigned int>, std::pair<in6_addr, unsigned int>>;

struct Client : public CdsHashtableNode<ClientEndpoint, Client> {
    // readonly
    uint32_t index;
    ClientEndpoint ep;

    std::mutex mutex;
    // protected by mutex:
    wireguard_tunnel *tunnel;
    std::vector<IpRange> allowed_ips;
};

struct WorkerArg {
    Tun *tun;
    UdpServer *server;
    bool tun_is_v6;
    bool srv_is_v6;
    CdsHashtable<ClientEndpoint, Client> *clients;
    maple_tree *allowed_ips;
};

class Worker {
public:
    Worker(const WorkerArg &arg);

    void run();

    static size_t calc_overhead(bool srv_is_v6) {
        size_t ret = sizeof(udphdr) + 32;
        ret += srv_is_v6 ? sizeof(ip6_hdr) : sizeof(iphdr);
        return ret;
    }

private:
    void do_tun(epoll_event *ev);
    // returns (size of each segment, number of segments)
    std::pair<size_t, size_t> do_tun_read(virtio_net_hdr &vnethdr, std::vector<uint8_t> &tunpkts, epoll_event *ev);
    std::pair<size_t, ClientEndpoint> do_crypt_encap(
        std::vector<uint8_t> &crypted,
        const virtio_net_hdr &vnethdr,
        const std::vector<uint8_t> &tunpkts,
        size_t segment_size,
        size_t nr_segments);

    void do_server(epoll_event *ev);

private:
    WorkerArg _arg;
    std::vector<uint8_t> _recvbuf;
    tdutil::EpollManager<> _poll;
    size_t _overhead;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wgss
