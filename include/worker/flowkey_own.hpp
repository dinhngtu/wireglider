#pragma once

#include "worker/flowkey.hpp"

namespace wireglider::worker_impl {

// TODO: investigate arenas for OPBs to reduce allocator pressure
struct PacketRefBatch;
struct OwnedPacketBatch {
    OwnedPacketBatch() {
    }
    explicit OwnedPacketBatch(const PacketRefBatch &prb);
    explicit OwnedPacketBatch(std::span<const uint8_t> hdr, size_t cap, const PacketFlags &_flags)
        : hdrbuf(hdr.begin(), hdr.end()), flags(_flags) {
        buf.reserve(cap);
    }
    OwnedPacketBatch(const OwnedPacketBatch &) = default;
    OwnedPacketBatch &operator=(const OwnedPacketBatch &) = default;
    OwnedPacketBatch(OwnedPacketBatch &&other) noexcept {
        hdrbuf = std::move(other.hdrbuf);
        buf = std::move(other.buf);
        count = std::exchange(other.count, 0);
        flags = other.flags;
    }
    OwnedPacketBatch &operator=(OwnedPacketBatch &&other) noexcept {
        if (this != &other) {
            hdrbuf = std::move(other.hdrbuf);
            buf = std::move(other.buf);
            count = std::exchange(other.count, 0);
            flags = other.flags;
        }
        return *this;
    }
    ~OwnedPacketBatch() = default;

    // for compatibility with PacketRefBatch
    constexpr OwnedPacketBatch *operator->() {
        return this;
    }
    constexpr OwnedPacketBatch &operator*() {
        return *this;
    }

    size_t size_bytes() const {
        return buf.size();
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
        return tdutil::start_lifetime_as<struct ip>(hdrbuf.data());
    }
    struct ip6_hdr *ip6hdr() {
        assert(flags.isv6());
        return tdutil::start_lifetime_as<struct ip6_hdr>(hdrbuf.data());
    }
    struct tcphdr *tcphdr() {
        assert(flags.istcp());
        auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
        return tdutil::start_lifetime_as<struct tcphdr>(&hdrbuf[iphsize]);
    }
    struct udphdr *udphdr() {
        assert(!flags.istcp());
        auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
        return tdutil::start_lifetime_as<struct udphdr>(&hdrbuf[iphsize]);
    }
    std::vector<uint8_t> hdrbuf;
    std::vector<uint8_t> buf;
    size_t count = 0;
    PacketFlags flags;
};

template <typename AddressType>
using OwnFlowMap =
    boost::container::flat_map<FlowKey<AddressType>, OwnedPacketBatch, std::greater<FlowKey<AddressType>>>;
using IP4Flow = OwnFlowMap<in_addr>;
using IP6Flow = OwnFlowMap<in6_addr>;

struct DecapBatch {
    [[deprecated("must specify has_uso")]] DecapBatch() : has_uso(true) {
    }
    explicit DecapBatch(bool _has_uso) : has_uso(_has_uso) {
    }

    IP4Flow tcp4;
    IP4Flow udp4;
    IP6Flow tcp6;
    IP6Flow udp6;
    // packets that are not aggregated
    std::deque<std::vector<uint8_t>> unrel;

    // packets that must be returned to the client for protocol reasons
    std::deque<std::vector<uint8_t>> retpkt;

    // unique udp flow number
    uint32_t udpid = 0;
    bool has_uso;

    DecapOutcome push_packet_v4(std::span<const uint8_t> ippkt, uint8_t ecn_outer);
    DecapOutcome push_packet_v6(std::span<const uint8_t> ippkt, uint8_t ecn_outer);
    DecapOutcome push_packet(std::span<const uint8_t> ippkt, uint8_t ecn_outer);
    void aggregate_udp();
};

} // namespace wireglider::worker_impl
