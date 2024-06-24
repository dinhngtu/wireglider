#include <array>
#include <vector>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <catch2/catch_test_macros.hpp>
#include <tins/tins.h>

#include "worker.hpp"

using namespace wgss;
using namespace Tins;

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
    TCP tcp(dport, sport);
    tcp.flags(flags);
    tcp.seq(seq);
    std::vector<uint8_t> payload(segment_size);
    RawPDU raw(payload);
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
    UDP udp(dport, sport);
    std::vector<uint8_t> payload(segment_size);
    RawPDU raw(payload);
    auto pkt = ip / udp / raw;
    return pkt.serialize();
}

static inline in_addr to_addr(IPv4Address a) {
    return in_addr{a};
}

static inline in6_addr to_addr(IPv6Address a) {
    in6_addr ret;
    a.copy(ret.s6_addr);
    return ret;
}

static const IPv4Address ip4a("192.0.2.1"), ip4b("192.0.2.2"), ip4c("192.0.2.3");
static const IPv6Address ip6a("2001:db8::1"), ip6b("2001:db8::2"), ip6c("2001:db8::3");

TEST_CASE("do_tun_gso_split") {
    std::vector<uint8_t> vec(131072);

    SECTION("tcp4") {
        auto pkt_bytes = make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK | TCP::PSH, 200, 1);
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
            .hdr_len = 40,
            .gso_size = 100,
            .csum_start = 20,
            .csum_offset = offsetof(struct tcphdr, th_sum),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 140);
        REQUIRE(pb.data.size() == 2 * 140);
    }

    SECTION("tcp6") {
        auto pkt_bytes = make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK | TCP::PSH, 200, 1);
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
            .hdr_len = 60,
            .gso_size = 100,
            .csum_start = 40,
            .csum_offset = offsetof(struct tcphdr, th_sum),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 160);
        REQUIRE(pb.data.size() == 2 * 160);
    }

    SECTION("udp4") {
        auto pkt_bytes = make_udp<IP>(ip4a, 1, ip4b, 1, 200);
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
            .hdr_len = 28,
            .gso_size = 100,
            .csum_start = 20,
            .csum_offset = offsetof(struct udphdr, check),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 128);
        REQUIRE(pb.data.size() == 2 * 128);
    }

    SECTION("udp6") {
        auto pkt_bytes = make_udp<IPv6>(ip6a, 1, ip6b, 1, 200);
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
            .hdr_len = 48,
            .gso_size = 100,
            .csum_start = 40,
            .csum_offset = offsetof(struct udphdr, check),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 148);
        REQUIRE(pb.data.size() == 2 * 148);
    }
}

void push_one(worker_impl::DecapBatch &batch, std::vector<uint8_t> pkt) {
    auto res = batch.push_packet(std::span<const uint8_t>(pkt));
    REQUIRE(res == worker_impl::DecapBatch::Outcome::GRO_ADDED);
}

TEST_CASE("DecapBatch") {
    worker_impl::DecapBatch batch;

    SECTION("multiple protocols and flows") {
        push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));     // tcp4 flow 1
        push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));                  // udp4 flow 1
        push_one(batch, make_udp<IP>(ip4a, 1, ip4c, 1, 100));                  // udp4 flow 2
        push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101));   // tcp4 flow 1
        push_one(batch, make_tcp<IP>(ip4a, 1, ip4c, 1, TCP::ACK, 100, 201));   // tcp4 flow 2
        push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 1));   // tcp6 flow 1
        push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 101)); // tcp6 flow 1
        push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6c, 1, TCP::ACK, 100, 201)); // tcp6 flow 2
        push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));                  // udp4 flow 1
        push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100));                // udp6 flow 1
        push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100));                // udp6 flow 1

        REQUIRE(batch.tcp4.size() == 2);
        {
            worker_impl::FlowKey<in_addr> fk{
                to_addr(ip4a),
                to_addr(ip4b),
                1,
                1,
                100,
                0,
                1,
            };
            auto it = batch.tcp4.lower_bound(fk);
            REQUIRE(it != batch.tcp4.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->first.tcpseq == 1);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);

            it--;
            REQUIRE(it != batch.tcp4.end());
            REQUIRE(it->first.dstip == to_addr(ip4c));
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->first.tcpseq == 201);
            REQUIRE(it->second.buf.size() == 100);
            REQUIRE(it->second.count == 1);
        }

        REQUIRE(batch.udp4.size() == 2);
        {
            worker_impl::FlowKey<in_addr> fk{
                to_addr(ip4a),
                to_addr(ip4b),
                1,
                1,
                100,
                0,
                0,
            };
            auto it = batch.udp4.lower_bound(fk);
            REQUIRE(it != batch.udp4.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);

            it--;
            REQUIRE(it != batch.udp4.end());
            REQUIRE(it->first.dstip == to_addr(ip4c));
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->second.buf.size() == 100);
            REQUIRE(it->second.count == 1);
        }

        REQUIRE(batch.tcp6.size() == 2);
        {
            worker_impl::FlowKey<in6_addr> fk{
                to_addr(ip6a),
                to_addr(ip6b),
                1,
                1,
                100,
                0,
                1,
            };
            auto it = batch.tcp6.lower_bound(fk);
            REQUIRE(it != batch.tcp6.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->first.tcpseq == 1);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);

            it--;
            REQUIRE(it != batch.tcp6.end());
            REQUIRE(it->first.dstip == to_addr(ip6c));
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->first.tcpseq == 201);
            REQUIRE(it->second.buf.size() == 100);
            REQUIRE(it->second.count == 1);
        }

        REQUIRE(batch.udp6.size() == 1);
        {
            worker_impl::FlowKey<in6_addr> fk{
                to_addr(ip6a),
                to_addr(ip6b),
                1,
                1,
                100,
                0,
                0,
            };
            auto it = batch.udp6.lower_bound(fk);
            REQUIRE(it != batch.udp6.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);
        }
    }

    SECTION("PSH interleaved") {
        push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));                // v4 flow 1
        push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK | TCP::PSH, 100, 101));   // v4 flow 1
        push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 201));              // v4 flow 1
        push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 301));              // v4 flow 1
        push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 1));              // v6 flow 1
        push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK | TCP::PSH, 100, 101)); // v6 flow 1
        push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 201));            // v6 flow 1
        push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 301));            // v6 flow 1

        REQUIRE(batch.tcp4.size() == 2);
        {
            worker_impl::FlowKey<in_addr> fk{
                to_addr(ip4a),
                to_addr(ip4b),
                1,
                1,
                100,
                0,
                1,
            };
            auto it = batch.tcp4.lower_bound(fk);
            REQUIRE(it != batch.tcp4.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);
        }
        {
            worker_impl::FlowKey<in_addr> fk{
                to_addr(ip4a),
                to_addr(ip4b),
                1,
                1,
                100,
                0,
                201,
            };
            auto it = batch.tcp4.lower_bound(fk);
            REQUIRE(it != batch.tcp4.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);
        }

        REQUIRE(batch.tcp6.size() == 2);
        {
            worker_impl::FlowKey<in6_addr> fk{
                to_addr(ip6a),
                to_addr(ip6b),
                1,
                1,
                100,
                0,
                1,
            };
            auto it = batch.tcp6.lower_bound(fk);
            REQUIRE(it != batch.tcp6.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);
        }
        {
            worker_impl::FlowKey<in6_addr> fk{
                to_addr(ip6a),
                to_addr(ip6b),
                1,
                1,
                100,
                0,
                201,
            };
            auto it = batch.tcp6.lower_bound(fk);
            REQUIRE(it != batch.tcp6.end());
            REQUIRE(it->first.segment_size == 100);
            REQUIRE(it->second.buf.size() == 200);
            REQUIRE(it->second.count == 2);
        }
    }
}
