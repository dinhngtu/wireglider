#pragma once

#include <cstring>
#include <algorithm>
#include <memory>
#include <vector>
#include <mutex>
#include <tuple>
#include <variant>
#include <map>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <xxhash.h>
#include <boost/container/flat_map.hpp>
#include <boost/intrusive/list.hpp>
#include <wireguard_ffi.h>
#include <tdutil/epollman.hpp>

#include "tun.hpp"
#include "udpsock.hpp"
#include "rundown.hpp"
#include "maple_tree.hpp"

#if 1 // region ClientEndpoint

namespace wgss::worker_impl {

using ClientEndpoint = std::variant<sockaddr_in, sockaddr_in6>;

static inline bool operator==(const ClientEndpoint &a, const ClientEndpoint &b) noexcept {
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

static inline std::strong_ordering operator<=>(const ClientEndpoint &a, const ClientEndpoint &b) noexcept {
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

} // namespace wgss::worker_impl

namespace std {
template <>
struct hash<wgss::worker_impl::ClientEndpoint> {
    constexpr size_t operator()(const wgss::worker_impl::ClientEndpoint &a) const noexcept {
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

#endif // endregion

namespace wgss {

namespace worker_impl {

using IpRange = std::variant<std::pair<in_addr, unsigned int>, std::pair<in6_addr, unsigned int>>;

struct Client : public CdsHashtableNode<ClientEndpoint, Client> {
    // readonly
    uint32_t index;
    ClientEndpoint ep;

    std::mutex mutex;
    // protected by mutex:
    wireguard_tunnel_raw *tunnel;
    std::vector<IpRange> allowed_ips;
};

// encap

struct PacketBatch {
    std::span<uint8_t> prefix;
    std::span<uint8_t> data;
    size_t segment_size;
    constexpr size_t nr_segments() {
        return tdutil::round_up(data.size(), segment_size) / segment_size;
    }
};

struct ServerSendBatch : public boost::intrusive::list_base_hook<> {
    ServerSendBatch() {
    }
    explicit ServerSendBatch(std::span<uint8_t> data, size_t _segment_size, ClientEndpoint _ep)
        : ep(_ep), buf(data.begin(), data.end()), segment_size(_segment_size) {
    }
    ClientEndpoint ep;
    std::vector<uint8_t> buf;
    size_t segment_size;

    struct deleter {
        void operator()(ServerSendBatch *self) {
            delete self;
        }
    };
};

using ServerSendList = boost::intrusive::list<worker_impl::ServerSendBatch, boost::intrusive::constant_time_size<true>>;

// decap

struct OwnedPacketBatch {
    explicit OwnedPacketBatch(size_t cap) {
        buf.reserve(cap);
    }
    void append(std::span<uint8_t> data) {
        buf.insert(buf.end(), data.begin(), data.end());
        count++;
    }
    void extend(OwnedPacketBatch &other) {
        buf.insert(buf.end(), other.buf.begin(), other.buf.end());
        count += other.count;
        other.buf.clear();
        other.count = 0;
    }
    std::vector<uint8_t> buf;
    size_t count = 0;
};

/*
struct OwnedPacketBatch : public boost::intrusive::list_base_hook<> {
    explicit OwnedPacketBatch(size_t cap) {
        buf.reserve(cap);
    }
    std::vector<uint8_t> buf;

    struct deleter {
        void operator()(OwnedPacketBatch *self) {
            delete self;
        }
    };
};

using DecapBatch = boost::unordered_map<uint16_t, boost::intrusive::list<OwnedPacketBatch>>;

void push_packet(DecapBatch &batch, std::span<uint8_t> buf) {
    auto it = &batch[buf.size()];
    auto slice = it->empty() ? nullptr : &it->back();
    if (!slice || slice->buf.capacity() - slice->buf.size() < buf.size()) {
        slice = new OwnedPacketBatch(std::min(65536uz, buf.size() * 16));
        it->push_back(*slice);
    }
    std::copy(buf.begin(), buf.end(), std::back_inserter(slice->buf));
}
 */

template <typename AddressType>
struct FlowKey {
    // network order
    AddressType srcip;
    // network order
    AddressType dstip;
    // native order
    uint16_t srcport;
    // native order
    uint16_t dstport;
    uint16_t datalen;

    // native order
    uint16_t ipid;
    // native order
    uint32_t tcpseq;

    bool matches(const FlowKey &other) const {
        return !memcmp(this, &other, offsetof(FlowKey, ipid));
    }

    bool is_consecutive_with(const FlowKey &other, size_t count, size_t size = 0) const {
        return this->matches(other) && this->ipid + count == other.ipid && this->tcpseq + size == other.tcpseq;
    }
};

template <typename AddressType>
static inline bool operator==(const FlowKey<AddressType> &a, const FlowKey<AddressType> &b) noexcept {
    return !memcmp(&a, &b, sizeof(a));
}

template <typename AddressType>
static inline auto operator<=>(const FlowKey<AddressType> &a, const FlowKey<AddressType> &b) noexcept {
    auto prefix = memcmp(&a, &b, offsetof(FlowKey<AddressType>, ipid));
    if (prefix > 0)
        return std::strong_ordering::greater;
    else if (prefix < 0)
        return std::strong_ordering::less;
    else
        return std::tie(a.ipid, a.tcpseq) <=> std::tie(b.ipid, b.tcpseq);
}

template <typename AddressType>
using FlowMap = boost::container::flat_map<FlowKey<AddressType>, OwnedPacketBatch, std::greater<FlowKey<AddressType>>>;
using IP4Flow = FlowMap<in_addr>;
using IP6Flow = FlowMap<in6_addr>;

struct GROBatch {
    enum Outcome {
        GRO_ADDED,
        GRO_NOADD,
        GRO_DROP,
    };

    IP4Flow tcp4;
    IP6Flow tcp6;
    IP4Flow udp4;
    IP6Flow udp6;

    Outcome push_packet_v4(std::span<uint8_t> ippkt);
};

} // namespace worker_impl

struct WorkerArg {
    int id;
    Tun *tun;
    UdpServer *server;
    bool tun_is_v6;
    bool srv_is_v6;
    CdsHashtable<worker_impl::ClientEndpoint, worker_impl::Client> *clients;
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
    std::optional<worker_impl::PacketBatch> do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr);
    worker_impl::PacketBatch do_tun_gso_split(
        worker_impl::PacketBatch &pb,
        std::vector<uint8_t> &outbuf,
        const virtio_net_hdr &vnethdr);
    std::optional<std::pair<worker_impl::PacketBatch, worker_impl::ClientEndpoint>> do_tun_encap(
        worker_impl::PacketBatch &pb,
        std::vector<uint8_t> &outbuf);
    // returns -errno
    int do_server_send(std::span<uint8_t> data, size_t segment_size, worker_impl::ClientEndpoint ep, bool queue_again);

    void do_server(epoll_event *ev);
    std::optional<std::pair<worker_impl::PacketBatch, worker_impl::ClientEndpoint>> do_server_recv(
        epoll_event *ev,
        std::vector<uint8_t> &outbuf);
    std::optional<GROBatch> do_server_decap(worker_impl::PacketBatch pb, worker_impl::ClientEndpoint ep);

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
    // fits at least 64 KB
    std::vector<uint8_t> _recvbuf;
    std::vector<uint8_t> _pktbuf, _sendbuf;
    worker_impl::ServerSendList _serversend;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wgss
