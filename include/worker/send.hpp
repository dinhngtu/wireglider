#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
#include <deque>
#include <sys/uio.h>
#include <sys/socket.h>
#include <boost/intrusive/list.hpp>

#include "endpoint.hpp"

namespace wireglider::worker_impl {

struct ServerSendBase : public boost::intrusive::list_base_hook<> {
    virtual ~ServerSendBase() {
    }

    struct deleter {
        void operator()(ServerSendBase *self) {
            delete self;
        }
    };
};

struct ServerSendBatch : public ServerSendBase {
    ServerSendBatch() {
    }
    explicit ServerSendBatch(std::span<uint8_t> data, size_t _segment_size, ClientEndpoint _ep)
        : ep(_ep), buf(data.begin(), data.end()), segment_size(_segment_size) {
    }
    virtual ~ServerSendBatch() {
    }

    ClientEndpoint ep;
    std::vector<uint8_t> buf;
    size_t segment_size;
    uint8_t ecn;
};

struct ServerSendList : public ServerSendBase {
    using packet_list = std::deque<std::vector<uint8_t>>;
    explicit ServerSendList(ClientEndpoint _ep) : ep(_ep) {
    }
    explicit ServerSendList(packet_list &&pkts, ClientEndpoint _ep);
    virtual ~ServerSendList() {
    }
    void push_back(iovec pkt);
    void finalize();
    packet_list packets;
    ClientEndpoint ep;
    std::vector<iovec> iovecs;
    std::vector<mmsghdr> mh;
    size_t pos = 0;
};

using ServerSendQueue = boost::intrusive::list<worker_impl::ServerSendBase, boost::intrusive::constant_time_size<true>>;

} // namespace wireglider::worker_impl
