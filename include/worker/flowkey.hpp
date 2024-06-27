#pragma once

#include <cassert>
#include <bitset>
#include <vector>
#include <span>
#include <deque>
#include <type_traits>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "virtio_net.hpp"
#include <boost/endian.hpp>
#include <boost/container/flat_map.hpp>

namespace wgss::worker_impl {

struct PacketFlags {
    using type = std::bitset<3>;
    virtio_net_hdr vnethdr;
    type storage;
    constexpr bool isv6() const {
        return storage[0];
    }
    type::reference isv6() {
        return storage[0];
    }
    constexpr bool istcp() const {
        return storage[1];
    }
    type::reference istcp() {
        return storage[1];
    }
    constexpr bool ispsh() const {
        return storage[2];
    }
    type::reference ispsh() {
        return storage[2];
    }
};

struct OwnedPacketBatch {
    explicit OwnedPacketBatch() {
    }
    explicit OwnedPacketBatch(std::span<const uint8_t> hdr, size_t cap, const PacketFlags &_flags)
        : hdrbuf(hdr.begin(), hdr.end()), flags(_flags) {
        buf.reserve(cap);
    }
    void append(std::span<const uint8_t> data) {
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
    struct ip *ip4hdr() {
        assert(!flags.isv6());
        return reinterpret_cast<struct ip *>(hdrbuf.data());
    }
    struct ip6_hdr *ip6hdr() {
        assert(flags.isv6());
        return reinterpret_cast<struct ip6_hdr *>(hdrbuf.data());
    }
    struct tcphdr *tcphdr() {
        assert(flags.istcp());
        auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
        return reinterpret_cast<struct tcphdr *>(&hdrbuf[iphsize]);
    }
    struct udphdr *udphdr() {
        assert(!flags.istcp());
        auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
        return reinterpret_cast<struct udphdr *>(&hdrbuf[iphsize]);
    }
    std::vector<uint8_t> hdrbuf;
    std::vector<uint8_t> buf;
    size_t count = 0;
    PacketFlags flags;
};

template <typename AddressType>
struct FlowKey {
    using address_type = AddressType;

    AddressType srcip;
    AddressType dstip;
    // all below are native order unless otherwise specified
    uint16_t srcport;
    uint16_t dstport;
    uint16_t segment_size;
    uint8_t tos;
    uint8_t ttl;
    uint32_t tcpack;

    // variable part
    uint32_t seq;

    // TODO: reordering to tcpack-tos-ttl-segment_size breaks our tests
    // need to see what's happening and why we needed to reorder in the first place
    // normally we only depend on ordering of `seq` so the reordering shouldn't have broken anything...

    static constexpr size_t variable_offset = offsetof(FlowKey, seq);

    bool matches(const FlowKey &other) const {
        static_assert(std::has_unique_object_representations_v<FlowKey>);
        return !memcmp(this, &other, variable_offset);
    }

    bool is_consecutive_with(const FlowKey &other, [[maybe_unused]] size_t count, size_t size) const {
        return this->matches(other) && this->seq + size == other.seq;
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
    auto prefix = memcmp(&a, &b, FlowKey<AddressType>::variable_offset);
    if (prefix > 0)
        return std::strong_ordering::greater;
    else if (prefix < 0)
        return std::strong_ordering::less;
    else
        return a.seq <=> b.seq;
}

template <typename AddressType>
using FlowMap = boost::container::flat_map<FlowKey<AddressType>, OwnedPacketBatch, std::greater<FlowKey<AddressType>>>;
using IP4Flow = FlowMap<in_addr>;
using IP6Flow = FlowMap<in6_addr>;

struct DecapBatch {
    enum Outcome {
        GRO_ADD,
        GRO_NOADD,
        GRO_DROP,
    };

    IP4Flow tcp4;
    IP4Flow udp4;
    IP6Flow tcp6;
    IP6Flow udp6;
    // packets that are not aggregated
    std::deque<std::vector<uint8_t>> unrel;

    // packets that must be returned to the client for protocol reasons
    std::deque<std::vector<uint8_t>> retpkt;

    Outcome push_packet_v4(std::span<const uint8_t> ippkt);
    Outcome push_packet_v6(std::span<const uint8_t> ippkt);
    Outcome push_packet(std::span<const uint8_t> ippkt);
    void aggregate_udp();
};

} // namespace wgss::worker_impl
