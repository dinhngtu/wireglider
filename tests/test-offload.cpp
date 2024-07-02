#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "virtio_net.hpp"
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <tins/tins.h>
#include <tdutil/util.hpp>

#include "worker/offload.hpp"
#include "packet_tests.hpp"
#include "netutil.hpp"

using namespace wireglider;
using namespace Tins;

static const IPv4Address ip4a("192.0.2.1"), ip4b("192.0.2.2"), ip4c("192.0.2.3");
static const IPv6Address ip6a("2001:db8::1"), ip6b("2001:db8::2"), ip6c("2001:db8::3");

TEST_CASE("do_tun_gso_split tcp4") {
    auto pkt_bytes = make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK | TCP::PSH, 200, 1);
    // 0 as a marker for pkt_bytes.size()
    __virtio16 hdrlen = GENERATE(40, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 20,
        .csum_offset = offsetof(tcphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 140);
    REQUIRE(pb.data.size() == 2 * 140);
}

TEST_CASE("do_tun_gso_split tcp6") {
    auto pkt_bytes = make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK | TCP::PSH, 200, 1);
    __virtio16 hdrlen = GENERATE(60, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 40,
        .csum_offset = offsetof(tcphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 160);
    REQUIRE(pb.data.size() == 2 * 160);
}

TEST_CASE("do_tun_gso_split udp4") {
    auto pkt_bytes = make_udp<IP>(ip4a, 1, ip4b, 1, 200);
    __virtio16 hdrlen = GENERATE(28, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 20,
        .csum_offset = offsetof(struct udphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 128);
    REQUIRE(pb.data.size() == 2 * 128);
}

TEST_CASE("do_tun_gso_split udp6") {
    auto pkt_bytes = make_udp<IPv6>(ip6a, 1, ip6b, 1, 200);
    __virtio16 hdrlen = GENERATE(48, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 40,
        .csum_offset = offsetof(struct udphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 148);
    REQUIRE(pb.data.size() == 2 * 148);
}

// TODO: ECN tests
