#pragma once

#include <cstdint>
#include <vector>
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
    uint32_t seq) {
    IPType ip(ipdst, ipsrc);
    Tins::TCP tcp(dport, sport);
    tcp.flags(flags);
    tcp.seq(seq);
    std::vector<uint8_t> payload(segment_size);
    Tins::RawPDU raw(payload);
    auto pkt = ip / tcp / raw;
    return pkt.serialize();
}

template <typename IPType>
static std::vector<uint8_t> make_udp(
    typename IPType::address_type ipsrc,
    uint16_t sport,
    typename IPType::address_type ipdst,
    uint16_t dport,
    uint32_t segment_size) {
    IPType ip(ipdst, ipsrc);
    Tins::UDP udp(dport, sport);
    std::vector<uint8_t> payload(segment_size);
    Tins::RawPDU raw(payload);
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
