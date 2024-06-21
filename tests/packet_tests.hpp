#pragma once

#include <cstdlib>
#include <memory>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "virtio_net.hpp"
#include <boost/endian.hpp>

#include "checksum.hpp"

constexpr in_addr_t makeip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return boost::endian::native_to_big((in_addr_t)((a << 24) | (b << 16) | (c << 8) | d));
}

struct [[gnu::packed]] tcp4packet {
    struct ip ip;
    struct tcphdr tcp;
    std::span<uint8_t> to_span() {
        return std::span<uint8_t>(reinterpret_cast<uint8_t *>(this), boost::endian::big_to_native(ip.ip_len));
    }
    std::span<uint8_t> data() {
        return to_span().subspan(sizeof(*this));
    }
};
static_assert(sizeof(tcp4packet) == 40);

std::unique_ptr<tcp4packet, decltype(&free)> make_tcp4(
    size_t datasize,
    in_addr_t srcip,
    in_addr_t dstip,
    uint16_t sport,
    uint16_t dport,
    uint32_t seq,
    uint8_t flags) {
    auto sz = static_cast<uint16_t>(sizeof(tcp4packet) + datasize);
    auto p = static_cast<tcp4packet *>(calloc(1, sz));
    if (!p)
        throw std::bad_alloc();

    p->ip.ip_v = 4;
    p->ip.ip_hl = 5;
    p->ip.ip_len = boost::endian::native_to_big(sz);
    p->ip.ip_ttl = 64;
    p->ip.ip_p = IPPROTO_TCP;
    p->ip.ip_src.s_addr = srcip;
    p->ip.ip_dst.s_addr = dstip;

    p->tcp.th_sport = boost::endian::native_to_big(sport);
    p->tcp.th_dport = boost::endian::native_to_big(dport);
    p->tcp.th_seq = boost::endian::native_to_big(seq);
    p->tcp.th_ack = boost::endian::native_to_big(1);
    p->tcp.th_off = sizeof(struct ip) / 4;
    p->tcp.th_flags = flags;
    p->tcp.th_win = boost::endian::native_to_big(uint16_t(3000));

    p->ip.ip_sum = boost::endian::native_to_big(wgss::checksum(p->to_span().subspan(0, sizeof(struct ip)), 0));
    auto sum = wgss::pseudo_header_checksum(
        IPPROTO_TCP,
        std::span<const uint8_t, 4>(reinterpret_cast<uint8_t *>(&p->ip.ip_src.s_addr), 4),
        std::span<const uint8_t, 4>(reinterpret_cast<uint8_t *>(&p->ip.ip_dst.s_addr), 4),
        sz);
    sum = wgss::checksum_impl::checksum_nofold(std::span<const uint8_t>(p->data()), sum);
    p->tcp.th_sum = boost::endian::native_to_big(fastcsum::fold_complement_checksum64(sum));

    return {p, &free};
}

struct [[gnu::packed]] udp4packet {
    struct ip ip;
    struct udphdr udp;
    std::span<uint8_t> to_span() {
        return std::span<uint8_t>(reinterpret_cast<uint8_t *>(this), boost::endian::big_to_native(ip.ip_len));
    }
    std::span<uint8_t> data() {
        return to_span().subspan(sizeof(*this));
    }
};
static_assert(sizeof(udp4packet) == 28);

std::unique_ptr<udp4packet, decltype(&free)> make_udp4(
    size_t datasize,
    in_addr_t srcip,
    in_addr_t dstip,
    uint16_t sport,
    uint16_t dport) {
    auto sz = static_cast<uint16_t>(sizeof(udp4packet) + datasize);
    auto p = static_cast<udp4packet *>(calloc(1, sz));
    if (!p)
        throw std::bad_alloc();

    p->ip.ip_v = 4;
    p->ip.ip_hl = 5;
    p->ip.ip_len = boost::endian::native_to_big(sz);
    p->ip.ip_ttl = 64;
    p->ip.ip_p = IPPROTO_UDP;
    p->ip.ip_src.s_addr = srcip;
    p->ip.ip_dst.s_addr = dstip;

    p->udp.source = boost::endian::native_to_big(sport);
    p->udp.dest = boost::endian::native_to_big(dport);
    p->udp.len = boost::endian::native_to_big(static_cast<uint16_t>(sizeof(udphdr) + datasize));

    p->ip.ip_sum = boost::endian::native_to_big(wgss::checksum(p->to_span().subspan(0, sizeof(struct ip)), 0));
    auto sum = wgss::pseudo_header_checksum(
        IPPROTO_UDP,
        std::span<const uint8_t, 4>(reinterpret_cast<uint8_t *>(&p->ip.ip_src.s_addr), 4),
        std::span<const uint8_t, 4>(reinterpret_cast<uint8_t *>(&p->ip.ip_dst.s_addr), 4),
        sz);
    sum = wgss::checksum_impl::checksum_nofold(std::span<const uint8_t>(p->data()), sum);
    p->udp.check = boost::endian::native_to_big(fastcsum::fold_complement_checksum64(sum));

    return {p, &free};
}
