#pragma once

#include <vector>
#include <span>
#include <deque>
#include <boost/intrusive/list.hpp>
#include <tdutil/util.hpp>

#include "worker/endpoint.hpp"

namespace wgss::worker_impl {

struct PacketBatch {
    std::span<uint8_t> prefix;
    std::span<uint8_t> data;
    size_t segment_size;
    constexpr size_t nr_segments() {
        return tdutil::round_up(data.size(), segment_size) / segment_size;
    }
};

struct ServerSendTag {
    using BaseHook = boost::intrusive::list_base_hook<boost::intrusive::tag<ServerSendTag>>;
};

struct ServerSendBase : public ServerSendTag::BaseHook {
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
};

struct ServerSendList : public ServerSendBase {
    using packet_list = std::deque<std::vector<uint8_t>>;
    explicit ServerSendList(packet_list &&pkts, ClientEndpoint _ep);
    virtual ~ServerSendList() {
    }
    ClientEndpoint ep;
    packet_list packets;
    std::vector<iovec> iovecs;
    std::vector<mmsghdr> mh;
    size_t pos;
};

using ServerSendQueue = boost::intrusive::list<worker_impl::ServerSendBase, boost::intrusive::constant_time_size<true>>;

} // namespace wgss::worker_impl
