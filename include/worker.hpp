#pragma once

#include <variant>
#include <mutex>
#include <vector>
#include <deque>
#include <wireguard_ffi.h>
#include <tdutil/epollman.hpp>

#include "tun.hpp"
#include "udpsock.hpp"
#include "rundown.hpp"
#include "maple_tree.hpp"
#include "worker/encap.hpp"
#include "worker/decap.hpp"

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
    std::optional<DecapBatch> do_server_decap(
        worker_impl::PacketBatch pb,
        worker_impl::ClientEndpoint ep,
        std::vector<uint8_t> &scratch);
    void tunnel_flush(
        [[maybe_unused]] RundownGuard &rcu,
        [[maybe_unused]] std::lock_guard<std::mutex> &lock,
        wireguard_tunnel_raw *tunnel,
        std::vector<uint8_t> &scratch);

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
    std::deque<std::vector<uint8_t>> _serversend2;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wgss
