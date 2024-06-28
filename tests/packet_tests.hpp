#pragma once

#include <cstdint>
#include <vector>
#include <functional>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <tins/tins.h>

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