#pragma once

#include <vector>
#include <span>
#include <deque>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <boost/container/flat_map.hpp>

namespace wgss::worker_impl {

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
    bool is_appendable(size_t size) const {
        return count + 1 < 64 && buf.size() + size < 65536;
    }
    bool is_mergeable(const OwnedPacketBatch &other) const {
        return count + other.count < 64 && buf.size() + other.buf.size() < 65536;
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
    uint16_t segment_size;

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

struct DecapBatch {
    enum Outcome {
        GRO_ADDED,
        GRO_NOADD,
        GRO_DROP,
    };

    IP4Flow tcp4;
    IP6Flow tcp6;
    IP4Flow udp4;
    IP6Flow udp6;
    // packets that are not aggregated
    std::deque<std::vector<uint8_t>> unrel;

    // packets that must be returned to the client for protocol reason
    std::deque<std::vector<uint8_t>> retpkt;

    Outcome push_packet_v4(std::span<uint8_t> ippkt);
};

} // namespace wgss::worker_impl
