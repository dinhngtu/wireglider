#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
#include <deque>
#include <sys/uio.h>
#include <sys/socket.h>
#include <boost/intrusive/list.hpp>

#include "result.hpp"
#include "endpoint.hpp"

namespace wireglider::worker_impl {

// TODO: explore mi_heap_destroy_stl_allocator or boost::pool as alternative allocators for send queues
// TODO: explore buffer ring-based arena allocators for our need which is FIFO allocations
// (multiple arena allocators in a circular ring)

struct ServerSendBase : public boost::intrusive::list_base_hook<> {
    virtual ~ServerSendBase() {
    }

    virtual outcome::result<void> send(int fd) = 0;

    struct deleter {
        void operator()(ServerSendBase *self) {
            delete self;
        }
    };
};

struct ServerSendBatch : public ServerSendBase {
    explicit ServerSendBatch(std::span<uint8_t> data, size_t _segment_size, ClientEndpoint _ep, uint8_t _ecn)
        : ep(_ep), buf(data.begin(), data.end()), segment_size(_segment_size), max_send(65535 - 65535 % segment_size),
          ecn(_ecn) {
    }
    explicit ServerSendBatch(size_t _segment_size, ClientEndpoint _ep, uint8_t _ecn)
        : ep(_ep), segment_size(_segment_size), max_send(65535 - 65535 % segment_size), ecn(_ecn) {
    }
    virtual ~ServerSendBatch() {
    }

    outcome::result<void> send(int fd, std::span<uint8_t> data);
    outcome::result<void> send(int fd) override {
        return send(fd, buf);
    }

    ClientEndpoint ep;
    std::vector<uint8_t> buf;
    size_t segment_size;
    size_t max_send;
    size_t pos = 0;
    uint8_t ecn;
};

struct ServerSendList : public ServerSendBase {
    using packet_list = std::deque<std::vector<uint8_t>>;
    explicit ServerSendList(ClientEndpoint _ep) : ep(_ep) {
    }
    explicit ServerSendList(packet_list &&pkts, ClientEndpoint _ep);
    virtual ~ServerSendList() {
    }

    outcome::result<void> send(int fd) override;

    void push_back(iovec pkt);
    void finalize();

    packet_list packets;
    ClientEndpoint ep;
    std::vector<iovec> iovecs;
    std::vector<mmsghdr> mh;
    size_t pos = 0;
    bool finalized = false;
};

// separate endpoint per packet, for timer use
struct ServerSendMultilist : public ServerSendBase {
    using packet_list = std::deque<std::vector<uint8_t>>;
    virtual ~ServerSendMultilist() {
    }

    outcome::result<void> send(int fd) override;

    void push_back(iovec pkt, ClientEndpoint _ep);
    void finalize();

    packet_list packets;
    std::vector<ClientEndpoint> eps;
    std::vector<iovec> iovecs;
    std::vector<mmsghdr> mh;
    size_t pos = 0;
    bool finalized = false;
};

using ServerSendQueue = boost::intrusive::list<worker_impl::ServerSendBase, boost::intrusive::constant_time_size<true>>;

} // namespace wireglider::worker_impl
