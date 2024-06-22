#pragma once

#include <iterator>
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
    bool isv6;
    constexpr size_t nr_segments() {
        return tdutil::round_up(data.size(), segment_size) / segment_size;
    }

    class PacketBatchIterator {
    public:
        using difference_type = ssize_t;
        using value_type = std::span<const uint8_t>;

        constexpr PacketBatchIterator() {
        }
        constexpr explicit PacketBatchIterator(
            size_t segment_size,
            std::span<uint8_t>::iterator first,
            std::span<uint8_t>::iterator last)
            : _segment_size(segment_size), _span(first, last) {
        }
        constexpr explicit PacketBatchIterator(
            size_t segment_size,
            std::span<const uint8_t>::iterator first,
            std::span<const uint8_t>::iterator last)
            : _segment_size(segment_size), _span(first, last) {
        }
        constexpr PacketBatchIterator(const PacketBatchIterator &) = default;
        constexpr PacketBatchIterator &operator=(const PacketBatchIterator &) = default;
        constexpr PacketBatchIterator(PacketBatchIterator &&) = default;
        constexpr PacketBatchIterator &operator=(PacketBatchIterator &&) = default;
        ~PacketBatchIterator() = default;

        PacketBatchIterator &operator++() {
            assert(!_span.empty());
            _span = _span.subspan(std::min(_span.size(), _segment_size));
            return *this;
        }
        PacketBatchIterator operator++(int) {
            PacketBatchIterator old = *this;
            ++*this;
            return old;
        }

        constexpr std::span<const uint8_t> operator*() const {
            return _span.subspan(0, std::min(_span.size(), _segment_size));
        }

        friend bool operator==(const PacketBatchIterator &a, const PacketBatchIterator &b) {
            return a._segment_size == b._segment_size &&
                   ((a._span.empty() && b._span.empty()) ||
                    (a._span.begin() == b._span.begin() && a._span.end() == b._span.end()));
        }

    private:
        size_t _segment_size = 0;
        std::span<const uint8_t> _span{};
    };

    static_assert(std::forward_iterator<PacketBatchIterator>);
    using iterator = PacketBatchIterator;
};

constexpr PacketBatch::iterator begin(PacketBatch &pb) {
    return PacketBatch::iterator(pb.segment_size, pb.data.begin(), pb.data.end());
}

constexpr PacketBatch::iterator end(PacketBatch &pb) {
    return PacketBatch::iterator(pb.segment_size, pb.data.end(), pb.data.end());
}

constexpr PacketBatch::iterator begin(const PacketBatch &pb) {
    return PacketBatch::iterator(pb.segment_size, pb.data.begin(), pb.data.end());
}

constexpr PacketBatch::iterator end(const PacketBatch &pb) {
    return PacketBatch::iterator(pb.segment_size, pb.data.end(), pb.data.end());
}

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
};

struct ServerSendList : public ServerSendBase {
    using packet_list = std::deque<std::vector<uint8_t>>;
    explicit ServerSendList(packet_list &&pkts, ClientEndpoint _ep);
    virtual ~ServerSendList() {
    }
    packet_list packets;
    ClientEndpoint ep;
    std::vector<iovec> iovecs;
    std::vector<mmsghdr> mh;
    size_t pos;
};

using ServerSendQueue = boost::intrusive::list<worker_impl::ServerSendBase, boost::intrusive::constant_time_size<true>>;

} // namespace wgss::worker_impl
