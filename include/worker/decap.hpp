#pragma once

#include <vector>
#include <span>
#include <deque>
#include <type_traits>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <boost/container/flat_map.hpp>

namespace wgss::worker_impl {

struct OwnedPacketBatch {
    explicit OwnedPacketBatch() {
    }
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

template <typename AddressType>
struct FlowKey {
    using address_type = AddressType;

    // network order
    AddressType srcip;
    // network order
    AddressType dstip;
    // native order
    uint16_t srcport;
    // native order
    uint16_t dstport;
    uint32_t segment_size;
    // native order
    uint32_t tcpack;

    // variable part
    // native order
    uint32_t tcpseq;

    bool matches(const FlowKey &other) const {
        static_assert(std::has_unique_object_representations_v<FlowKey>);
        return !memcmp(this, &other, offsetof(FlowKey, tcpseq));
    }

    bool is_consecutive_with(const FlowKey &other, [[maybe_unused]] size_t count, size_t size = 0) const {
        return this->matches(other) && this->tcpack == other.tcpack && this->tcpseq + size == other.tcpseq;
    }
};

template <typename AddressType>
static inline bool operator==(const FlowKey<AddressType> &a, const FlowKey<AddressType> &b) noexcept {
    static_assert(std::has_unique_object_representations_v<FlowKey<AddressType>>);
    return !memcmp(&a, &b, sizeof(a));
}

template <typename AddressType>
static inline auto operator<=>(const FlowKey<AddressType> &a, const FlowKey<AddressType> &b) noexcept {
    static_assert(std::has_unique_object_representations_v<FlowKey<AddressType>>);
    auto prefix = memcmp(&a, &b, offsetof(FlowKey<AddressType>, tcpseq));
    if (prefix > 0)
        return std::strong_ordering::greater;
    else if (prefix < 0)
        return std::strong_ordering::less;
    else
        return std::tie(a.tcpseq, a.tcpseq) <=> std::tie(b.tcpseq, b.tcpseq);
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

    // packets that must be returned to the client for protocol reasons
    std::deque<std::vector<uint8_t>> retpkt;

    Outcome push_packet_v4(std::span<uint8_t> ippkt);
    Outcome push_packet_v6(std::span<uint8_t> ippkt);
};

} // namespace wgss::worker_impl
