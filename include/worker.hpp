#pragma once

#include <mutex>
#include <vector>
#include <deque>
#include <wireguard_ffi.h>
#include <tdutil/epollman.hpp>

#include "wireglider.hpp"
#include "result.hpp"
#include "client.hpp"
#include "tun.hpp"
#include "udpsock.hpp"
#include "maple_tree.hpp"
#include "endpoint.hpp"
#include "worker/offload.hpp"
#include "worker/flowkey.hpp"
#include "worker/send.hpp"
#include "worker/write.hpp"

namespace wireglider {

struct WorkerArg {
    unsigned int id;
    Tun *tun;
    UdpServer *server;
    ClientTable *clients;
    EndpointTable *client_eps;
    maple_tree *allowed_ips;
};

class Worker {
public:
    Worker(const WorkerArg &arg);

    void run();

    static constexpr size_t calc_overhead() {
        size_t ret = sizeof(udphdr) + 32 + sizeof(ip6_hdr);
        return ret;
    }

private:
    void do_tun(epoll_event *ev);
    // returns (size of each segment, number of segments)
    outcome::result<std::span<uint8_t>> do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr);
    std::optional<std::pair<worker_impl::PacketBatch, ClientEndpoint>> do_tun_encap(
        worker_impl::PacketBatch &pb,
        std::vector<uint8_t> &outbuf);

    void do_server_send();
    void server_send_batch(worker_impl::ServerSendBatch *batch, std::span<uint8_t> data, bool queue_on_eagain);
    // use when batch is a non-owning batch that contains no data
    void server_send_batch(worker_impl::ServerSendBatch *batch, std::span<uint8_t> data) {
        server_send_batch(batch, data, true);
    }
    void server_send_batch(worker_impl::ServerSendBatch *batch) {
        server_send_batch(batch, batch->buf, false);
    }
    outcome::result<void> server_send_list(worker_impl::ServerSendList *list);
    outcome::result<void> do_server_send_step(worker_impl::ServerSendBase *send);

    void do_server(epoll_event *ev);
    std::optional<std::pair<worker_impl::PacketBatch, ClientEndpoint>> do_server_recv(
        epoll_event *ev,
        std::vector<uint8_t> &outbuf);
    std::optional<worker_impl::DecapBatch> do_server_decap(
        worker_impl::PacketBatch pb,
        ClientEndpoint ep,
        std::vector<uint8_t> &scratch);

    void do_tun_write();
    outcome::result<void> do_tun_write_batch(worker_impl::DecapBatch &batch);

    void tun_disable(uint32_t events) {
        auto newevents = _poll_tun & ~events;
        if (newevents != _poll_tun) {
            _poll.set_events(_arg.tun->fd(), newevents);
            _poll_tun = newevents;
        }
    }

    void tun_enable(uint32_t events) {
        auto newevents = _poll_tun | events;
        if (newevents != _poll_tun) {
            _poll.set_events(_arg.tun->fd(), newevents);
            _poll_tun = newevents;
        }
    }

    void server_disable(uint32_t events) {
        auto newevents = _poll_server & ~events;
        if (newevents != _poll_server) {
            _poll.set_events(_arg.server->fd(), newevents);
            _poll_server = newevents;
        }
    }

    void server_enable(uint32_t events) {
        auto newevents = _poll_server | events;
        if (newevents != _poll_server) {
            _poll.set_events(_arg.server->fd(), newevents);
            _poll_server = newevents;
        }
    }

private:
    tdutil::FileDescriptor _sigfd;
    tdutil::EpollManager<> _poll;
    uint32_t _poll_tun = 0;
    uint32_t _poll_server = 0;
    WorkerArg _arg;
    size_t _overhead;
    // fits at least 64 KB
    std::vector<uint8_t> _recvbuf;
    std::vector<uint8_t> _pktbuf, _sendbuf;
    worker_impl::ServerSendQueue _serversend;
    worker_impl::TunWriteQueue _tunwrite;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wireglider
