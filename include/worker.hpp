#pragma once

#include <vector>
#include <deque>
#include <optional>
#include <tdutil/epollman.hpp>

#include "result.hpp"
#include "tun.hpp"
#include "udpsock.hpp"
#include "endpoint.hpp"
#include "worker/arg.hpp"
#include "worker/decap.hpp"
#include "worker/offload.hpp"
#include "worker/flowkey_own.hpp"
#include "worker/flowkey_ref.hpp"
#include "worker/send.hpp"
#include "worker/write.hpp"
#include "dbgprint.hpp"

namespace wireglider {

class Worker {
public:
    Worker(const WorkerArg &arg);

    void run();

    static constexpr size_t calc_max_overhead_conservative() {
        return sizeof(udphdr) + sizeof(proto::DataHeader) + proto::PaddingMultiple +
               crypto_aead_chacha20poly1305_IETF_ABYTES;
    }

private:
    void do_tun(epoll_event *ev);
    // returns (size of each segment, number of segments)
    outcome::result<std::span<uint8_t>> do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr);
    std::optional<std::pair<worker_impl::PacketBatch, ClientEndpoint>> do_tun_encap(
        worker_impl::PacketBatch &pb,
        std::vector<uint8_t> &outbuf,
        std::vector<uint8_t> &unrelbuf,
        std::vector<iovec> &unreliov);

    void do_server_send();
    // returns remaining iovecs if EAGAIN
    std::optional<std::span<const iovec>> server_send_reflist(std::span<iovec> pkts, ClientEndpoint ep);

    void do_server(epoll_event *ev);
    int do_server_recv([[maybe_unused]] epoll_event *ev, worker_impl::DecapRecvBatch &drb);
    std::optional<worker_impl::DecapBatch> do_server_decap(
        worker_impl::PacketBatch pb,
        ClientEndpoint ep,
        std::vector<uint8_t> &scratch);
    // memory must live for the duration of the DecapRefBatch
    std::optional<worker_impl::DecapRefBatch> do_server_decap_ref(
        worker_impl::PacketBatch pb,
        ClientEndpoint ep,
        std::vector<uint8_t> &memory);

    void do_tun_write();
    void do_tun_requeue_batch(worker_impl::DecapBatch &batch);
    void do_tun_requeue_batch(worker_impl::DecapRefBatch &batch);

    void do_poll_reset();

    void tun_disable(uint32_t events) {
        auto newevents = _poll_tun & ~events;
        if (newevents != _poll_tun) {
            DBG_PRINT("tun_disable {}\n", events);
            _poll.set_events(_arg.tun->fd(), newevents);
            _poll_tun = newevents;
        }
    }

    void tun_enable(uint32_t events) {
        auto newevents = _poll_tun | events;
        if (newevents != _poll_tun) {
            DBG_PRINT("tun_enable {}\n", events);
            _poll.set_events(_arg.tun->fd(), newevents);
            _poll_tun = newevents;
        }
    }

    void server_disable(uint32_t events) {
        auto newevents = _poll_server & ~events;
        if (newevents != _poll_server) {
            DBG_PRINT("server_disable {}\n", events);
            _poll.set_events(_arg.server->fd(), newevents);
            _poll_server = newevents;
        }
    }

    void server_enable(uint32_t events) {
        auto newevents = _poll_server | events;
        if (newevents != _poll_server) {
            DBG_PRINT("server_enable {}\n", events);
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
    // persistent send queues
    worker_impl::ServerSendQueue _serversend;
    worker_impl::TunWriteQueue _tunwrite;
    std::deque<std::vector<uint8_t>> _tununrel;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wireglider
