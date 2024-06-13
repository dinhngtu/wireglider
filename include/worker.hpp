#pragma once

#include <cstring>
#include <algorithm>
#include <memory>
#include <vector>
#include <mutex>
#include <tuple>
#include <variant>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <xxhash.h>
#include <boost/intrusive/list.hpp>
#include <tdutil/epollman.hpp>

extern "C" {
#include <wireguard_ffi.h>
}

#include "tun.hpp"
#include "udpsock.hpp"
#include "rundown.hpp"
#include "maple_tree.hpp"

namespace wgss {
using ClientEndpoint = std::variant<sockaddr_in, sockaddr_in6>;
}

namespace std {
template <>
struct hash<wgss::ClientEndpoint> {
    constexpr size_t operator()(const wgss::ClientEndpoint &a) const noexcept {
        if (auto sin = std::get_if<sockaddr_in>(&a))
            return XXH3_64bits(sin, offsetof(sockaddr_in, sin_zero));
        else if (auto sin6 = std::get_if<sockaddr_in6>(&a))
            return XXH3_64bits(sin6, sizeof(a));
        else
            return 0;
    }
};
} // namespace std

static inline bool operator==(const sockaddr_in &a, const sockaddr_in &b) noexcept {
    return !memcmp(&a, &b, offsetof(sockaddr_in, sin_zero));
}

static inline auto operator<=>(const sockaddr_in &a, const sockaddr_in &b) noexcept {
    return memcmp(&a, &b, offsetof(sockaddr_in, sin_zero)) <=> 0;
}

static inline bool operator==(const sockaddr_in6 &a, const sockaddr_in6 &b) noexcept {
    return !memcmp(&a, &b, sizeof(a));
}

static inline auto operator<=>(const sockaddr_in6 &a, const sockaddr_in6 &b) noexcept {
    return memcmp(&a, &b, sizeof(a)) <=> 0;
}

static inline bool operator==(const wgss::ClientEndpoint &a, const wgss::ClientEndpoint &b) noexcept {
    if (a.index() != b.index())
        return 0;
    if (auto sina = std::get_if<sockaddr_in>(&a)) {
        auto sinb = std::get_if<sockaddr_in>(&b);
        return *sina == *sinb;
    } else if (auto sin6a = std::get_if<sockaddr_in6>(&a)) {
        auto sin6b = std::get_if<sockaddr_in6>(&a);
        return *sin6a == *sin6b;
    } else {
        return 0;
    }
}

static inline std::strong_ordering operator<=>(const wgss::ClientEndpoint &a, const wgss::ClientEndpoint &b) noexcept {
    if (a.index() != b.index()) {
        return a.index() <=> b.index();
    } else if (auto sina = std::get_if<sockaddr_in>(&a)) {
        auto sinb = std::get_if<sockaddr_in>(&b);
        return *sina <=> *sinb;
    } else if (auto sin6a = std::get_if<sockaddr_in6>(&a)) {
        auto sin6b = std::get_if<sockaddr_in6>(&a);
        return *sin6a <=> *sin6b;
    } else {
        return a.index() <=> b.index();
    }
}

// I swear that all of the crap above compiles down to fairly efficient code...

namespace wgss {

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

struct ServerSend : public boost::intrusive::list_base_hook<> {
    ServerSend() {
    }
    explicit ServerSend(std::span<uint8_t> data, size_t _segment_size, ClientEndpoint _ep)
        : ep(_ep), buf(data.begin(), data.end()), segment_size(_segment_size) {
    }
    ClientEndpoint ep;
    std::vector<uint8_t> buf;
    size_t segment_size;
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
    std::optional<PacketBatch> do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr);
    PacketBatch do_tun_gso_split(PacketBatch &pb, std::vector<uint8_t> &outbuf, const virtio_net_hdr &vnethdr);
    std::optional<std::pair<PacketBatch, ClientEndpoint>> do_tun_encap(PacketBatch &pb, std::vector<uint8_t> &outbuf);
    // returns -errno
    int do_server_send(std::span<uint8_t> data, size_t segment_size, ClientEndpoint ep, bool queue_again);

    void do_server(epoll_event *ev);
    std::optional<std::pair<PacketBatch, ClientEndpoint>> do_server_recv(epoll_event *ev, std::vector<uint8_t> &outbuf);
    std::optional<PacketBatch> do_server_decap(PacketBatch pb, ClientEndpoint ep, std::vector<uint8_t> &outbuf);

    static constexpr bool is_eagain(int e = errno) {
        return e == EAGAIN || e == EWOULDBLOCK;
    }

    void tun_disable(uint32_t events) {
        auto newevents = _poll_tun & ~events;
        if (newevents != _poll_tun)
            _poll.set_events(_arg.tun->fd(), newevents);
    }

    void tun_enable(uint32_t events) {
        auto newevents = _poll_tun | events;
        if (newevents != _poll_tun)
            _poll.set_events(_arg.tun->fd(), newevents);
    }

    void server_disable(uint32_t events) {
        auto newevents = _poll_server & ~events;
        if (newevents != _poll_server)
            _poll.set_events(_arg.server->fd(), newevents);
    }

    void server_enable(uint32_t events) {
        auto newevents = _poll_server | events;
        if (newevents != _poll_server)
            _poll.set_events(_arg.server->fd(), newevents);
    }

private:
    tdutil::EpollManager<> _poll;
    uint32_t _poll_tun = 0;
    uint32_t _poll_server = 0;
    WorkerArg _arg;
    size_t _overhead;
    std::vector<uint8_t> _recvbuf;
    // do_tun
    std::vector<uint8_t> _tunpkts, _crypted;
    boost::intrusive::list<ServerSend, boost::intrusive::constant_time_size<true>> _serversend;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wgss
