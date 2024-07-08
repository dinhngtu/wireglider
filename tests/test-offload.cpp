#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "virtio_net.hpp"
#include <boost/endian.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <tins/tins.h>
#include <tdutil/util.hpp>

#include "worker/offload.hpp"
#include "packet_tests.hpp"
#include "netutil.hpp"

using namespace wireglider;
using namespace boost::endian;
using namespace Tins;

static const IPv4Address ip4a("192.0.2.1"), ip4b("192.0.2.2"), ip4c("192.0.2.3");
static const IPv6Address ip6a("2001:db8::1"), ip6b("2001:db8::2"), ip6c("2001:db8::3");

TEST_CASE("do_tun_gso_split tcp4") {
    auto pkt_bytes = make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK | TCP::PSH, 200, 9999);
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
    {
        auto pkt1 = Tins::IP(&pb.data[0], 140);
        auto &tcp = pkt1.rfind_pdu<TCP>();
        REQUIRE(tcp.seq() == 9999);
        auto oldcsum = tcp.checksum();
        tcp.serialize();
        REQUIRE(big_to_native(oldcsum) == tcp.checksum());
    }
    {
        auto pkt2 = Tins::IP(&pb.data[140], 140);
        auto &tcp = pkt2.rfind_pdu<TCP>();
        REQUIRE(tcp.seq() == 9999 + 100);
        auto oldcsum = tcp.checksum();
        tcp.serialize();
        REQUIRE(big_to_native(oldcsum) == tcp.checksum());
    }
}

TEST_CASE("do_tun_gso_split tcp4 unrel") {
    auto pkt_bytes = make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK | TCP::PSH | TCP::FIN, 100, 9999);
    // 0 as a marker for pkt_bytes.size()
    __virtio16 hdrlen = GENERATE(40, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = VIRTIO_NET_HDR_GSO_NONE,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 20,
        .csum_offset = offsetof(tcphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 140);
    REQUIRE(pb.data.size() == 140);
    {
        auto pkt1 = Tins::IP(&pb.data[0], 140);
        auto &tcp = pkt1.rfind_pdu<TCP>();
        REQUIRE(tcp.seq() == 9999);
        auto oldcsum = tcp.checksum();
        tcp.serialize();
        REQUIRE(big_to_native(oldcsum) == tcp.checksum());
    }
}

TEST_CASE("do_tun_gso_split tcp6") {
    auto pkt_bytes = make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK | TCP::PSH, 200, 9999);
    __virtio16 hdrlen = GENERATE(60, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = VIRTIO_NET_HDR_GSO_TCPV6,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 40,
        .csum_offset = offsetof(tcphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 160);
    REQUIRE(pb.data.size() == 2 * 160);
    {
        auto pkt1 = Tins::IPv6(&pb.data[0], 160);
        auto &tcp = pkt1.rfind_pdu<TCP>();
        REQUIRE(tcp.seq() == 9999);
        auto oldcsum = tcp.checksum();
        tcp.serialize();
        REQUIRE(big_to_native(oldcsum) == tcp.checksum());
    }
    {
        auto pkt2 = Tins::IPv6(&pb.data[160], 160);
        auto &tcp = pkt2.rfind_pdu<TCP>();
        REQUIRE(tcp.seq() == 9999 + 100);
        auto oldcsum = tcp.checksum();
        tcp.serialize();
        REQUIRE(big_to_native(oldcsum) == tcp.checksum());
    }
}

TEST_CASE("do_tun_gso_split tcp6 unrel") {
    auto pkt_bytes = make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK | TCP::PSH | TCP::FIN, 100, 9999);
    __virtio16 hdrlen = GENERATE(60, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = VIRTIO_NET_HDR_GSO_NONE,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 40,
        .csum_offset = offsetof(tcphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 160);
    REQUIRE(pb.data.size() == 160);
    {
        auto pkt1 = Tins::IPv6(&pb.data[0], 160);
        auto &tcp = pkt1.rfind_pdu<TCP>();
        REQUIRE(tcp.seq() == 9999);
        auto oldcsum = tcp.checksum();
        tcp.serialize();
        REQUIRE(big_to_native(oldcsum) == tcp.checksum());
    }
}

TEST_CASE("do_tun_gso_split udp4") {
    auto pkt_bytes = make_udp<IP>(ip4a, 1, ip4b, 1, 200);
    __virtio16 hdrlen = GENERATE(28, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = WIREGLIDER_VIRTIO_NET_HDR_GSO_UDP_L4,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 20,
        .csum_offset = offsetof(udphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 128);
    REQUIRE(pb.data.size() == 2 * 128);
    {
        auto pkt1 = Tins::IP(&pb.data[0], 128);
        auto &udp = pkt1.rfind_pdu<UDP>();
        auto oldcsum = udp.checksum();
        udp.serialize();
        REQUIRE(big_to_native(oldcsum) == udp.checksum());
    }
    {
        auto pkt2 = Tins::IP(&pb.data[128], 128);
        auto &udp = pkt2.rfind_pdu<UDP>();
        auto oldcsum = udp.checksum();
        udp.serialize();
        REQUIRE(big_to_native(oldcsum) == udp.checksum());
    }
}

TEST_CASE("do_tun_gso_split udp6") {
    auto pkt_bytes = make_udp<IPv6>(ip6a, 1, ip6b, 1, 200);
    __virtio16 hdrlen = GENERATE(48, 0);
    virtio_net_hdr vnethdr{
        .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
        .gso_type = WIREGLIDER_VIRTIO_NET_HDR_GSO_UDP_L4,
        .hdr_len = hdrlen ? hdrlen : static_cast<__virtio16>(pkt_bytes.size()),
        .gso_size = 100,
        .csum_start = 40,
        .csum_offset = offsetof(udphdr, check),
    };
    std::vector<uint8_t> vec(131072);
    auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
    REQUIRE(pb.segment_size == 148);
    REQUIRE(pb.data.size() == 2 * 148);
    {
        auto pkt1 = Tins::IPv6(&pb.data[0], 148);
        REQUIRE(pkt1.find_pdu<UDP>());
        auto &udp = pkt1.rfind_pdu<UDP>();
        auto oldcsum = udp.checksum();
        udp.serialize();
        REQUIRE(big_to_native(oldcsum) == udp.checksum());
    }
    {
        auto pkt2 = Tins::IPv6(&pb.data[148], 148);
        REQUIRE(pkt2.find_pdu<UDP>());
        auto &udp = pkt2.rfind_pdu<UDP>();
        auto oldcsum = udp.checksum();
        udp.serialize();
        REQUIRE(big_to_native(oldcsum) == udp.checksum());
    }
}

// TODO: ECN tests
