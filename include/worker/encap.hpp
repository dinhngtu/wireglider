#pragma once

#include <vector>
#include <span>
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

} // namespace wgss::worker_impl
