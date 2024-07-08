#pragma once

#include <cstdint>
#include <vector>
#include <functional>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <tins/tins.h>

#include "worker/flowkey.hpp"

template <typename IPType>
static std::vector<uint8_t> make_tcp(
    typename IPType::address_type ipsrc,
    uint16_t sport,
    typename IPType::address_type ipdst,
    uint16_t dport,
    Tins::small_uint<12UL> flags,
    uint32_t segment_size,
    uint32_t seq,
    std::function<void(IPType &, Tins::TCP &)> mutate = {}) {
    IPType ip(ipdst, ipsrc);
    if constexpr (std::same_as<IPType, Tins::IP>)
        ip.ttl(64);
    else if constexpr (std::same_as<IPType, Tins::IPv6>)
        ip.hop_limit(64);
    Tins::TCP tcp(dport, sport);
    tcp.flags(flags);
    tcp.seq(seq);
    std::vector<uint8_t> payload(segment_size);
    Tins::RawPDU raw(payload);
    if (mutate)
        mutate(ip, tcp);
    auto pkt = ip / tcp / raw;
    return pkt.serialize();
}

template <typename IPType>
static std::vector<uint8_t> make_udp(
    typename IPType::address_type ipsrc,
    uint16_t sport,
    typename IPType::address_type ipdst,
    uint16_t dport,
    uint32_t segment_size,
    std::function<void(IPType &, Tins::UDP &)> mutate = {}) {
    IPType ip(ipdst, ipsrc);
    if constexpr (std::same_as<IPType, Tins::IP>)
        ip.ttl(64);
    else if constexpr (std::same_as<IPType, Tins::IPv6>)
        ip.hop_limit(64);
    Tins::UDP udp(dport, sport);
    std::vector<uint8_t> payload(segment_size);
    Tins::RawPDU raw(payload);
    if (mutate)
        mutate(ip, udp);
    auto pkt = ip / udp / raw;
    return pkt.serialize();
}

static inline in_addr to_addr(Tins::IPv4Address a) {
    return in_addr{a};
}

static inline in6_addr to_addr(Tins::IPv6Address a) {
    in6_addr ret;
    a.copy(ret.s6_addr);
    return ret;
}

static inline wireglider::worker_impl::FlowKey<in_addr> make_fk(
    Tins::IPv4Address ipsrc,
    Tins::IPv4Address ipdst,
    uint32_t seq = 0,
    uint16_t segment_size = 100) {
    return wireglider::worker_impl::FlowKey<in_addr>{
        .srcip = to_addr(ipsrc),
        .dstip = to_addr(ipdst),
        .srcport = 1,
        .dstport = 1,
        .tcpack = 0,
        .tos = 0,
        .ttl = 64,
        .segment_size = segment_size,
        .seq = seq,
    };
}

static inline wireglider::worker_impl::FlowKey<in6_addr> make_fk(
    Tins::IPv6Address ipsrc,
    Tins::IPv6Address ipdst,
    uint32_t seq = 0,
    uint16_t segment_size = 100) {
    return wireglider::worker_impl::FlowKey<in6_addr>{
        .srcip = to_addr(ipsrc),
        .dstip = to_addr(ipdst),
        .srcport = 1,
        .dstport = 1,
        .tcpack = 0,
        .tos = 0,
        .ttl = 64,
        .segment_size = segment_size,
        .seq = seq,
    };
}
