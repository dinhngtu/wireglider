#include <catch2/catch_test_macros.hpp>

#include "worker/flowkey.hpp"
#include "packet_tests.hpp"
#include "netutil.hpp"

using namespace wgss;
using namespace Tins;
using enum wgss::worker_impl::DecapBatch::Outcome;

static const IPv4Address ip4a("192.0.2.1"), ip4b("192.0.2.2"), ip4c("192.0.2.3");
static const IPv6Address ip6a("2001:db8::1"), ip6b("2001:db8::2"), ip6c("2001:db8::3");

static void push_one(
    worker_impl::DecapBatch &batch,
    std::vector<uint8_t> pkt,
    worker_impl::DecapBatch::Outcome outcome = GRO_ADD,
    uint8_t ecn_outer = 0) {
    auto res = batch.push_packet(std::span<const uint8_t>(pkt), ecn_outer);
    REQUIRE(res == outcome);
}

template <typename FlowIteratorType, typename AddressType>
static void check_flow(
    FlowIteratorType it,
    AddressType src,
    AddressType dst,
    uint32_t seq,
    size_t count,
    uint16_t segment_size = 100) {
    REQUIRE(it->first.srcip == to_addr(src));
    REQUIRE(it->first.dstip == to_addr(dst));
    REQUIRE(it->first.segment_size == segment_size);
    REQUIRE(it->first.seq == seq);
    REQUIRE(it->second.count == count);
    REQUIRE(it->second.buf.size() == count * segment_size);
}

// for use when the two flows are otherwise equivalent
template <typename FlowIteratorType, typename AddressType>
static void check_flow_udp(
    FlowIteratorType it,
    AddressType src,
    AddressType dst,
    size_t count,
    uint16_t segment_size = 100) {
    REQUIRE(it->first.srcip == to_addr(src));
    REQUIRE(it->first.dstip == to_addr(dst));
    REQUIRE(it->first.segment_size == segment_size);
    REQUIRE(it->second.count == count);
    REQUIRE(it->second.buf.size() == count * segment_size);
}

template <typename IPType, typename L4Type>
static std::vector<uint8_t> flip_l4_csum(std::vector<uint8_t> pkt) {
    auto l4hdr = reinterpret_cast<L4Type *>(&pkt[sizeof(IPType)]);
    l4hdr->check = ~l4hdr->check;
    return pkt;
}

static inline wgss::worker_impl::FlowKey<in_addr> make_fk(
    Tins::IPv4Address ipsrc,
    Tins::IPv4Address ipdst,
    uint32_t seq = 0,
    uint16_t segment_size = 100) {
    return {
        to_addr(ipsrc),
        to_addr(ipdst),
        1,
        1,
        segment_size,
        0,
        64,
        0,
        seq,
    };
}

static inline wgss::worker_impl::FlowKey<in6_addr> make_fk(
    Tins::IPv6Address ipsrc,
    Tins::IPv6Address ipdst,
    uint32_t seq = 0,
    uint16_t segment_size = 100) {
    return {
        to_addr(ipsrc),
        to_addr(ipdst),
        1,
        1,
        segment_size,
        0,
        64,
        0,
        seq,
    };
}

TEST_CASE("DecapBatch multiple protocols and flows") {
    worker_impl::DecapBatch batch;

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
        auto fk = make_fk(ip4a, ip4b, 1);
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, ip4a, ip4b, 1, 2);

        REQUIRE(it != batch.tcp4.begin());
        it--;
        check_flow(it, ip4a, ip4c, 201, 1);
    }

    REQUIRE(batch.udp4.size() == 2);
    {
        {
            auto fk = make_fk(ip4a, ip4b, UINT32_MAX);
            auto it = batch.udp4.upper_bound(fk);
            REQUIRE(it != batch.udp4.end());
            check_flow_udp(it, ip4a, ip4b, 2);
        }
        {
            auto fk = make_fk(ip4a, ip4c, UINT32_MAX);
            auto it = batch.udp4.upper_bound(fk);
            REQUIRE(it != batch.udp4.end());
            check_flow_udp(it, ip4a, ip4c, 1);
        }
    }

    REQUIRE(batch.tcp6.size() == 2);
    {
        auto fk = make_fk(ip6a, ip6b, 1);
        auto it = batch.tcp6.lower_bound(fk);
        REQUIRE(it != batch.tcp6.end());
        check_flow(it, ip6a, ip6b, 1, 2);

        REQUIRE(it != batch.tcp6.begin());
        it--;
        check_flow(it, ip6a, ip6c, 201, 1);
    }

    REQUIRE(batch.udp6.size() == 1);
    {
        auto fk = make_fk(ip6a, ip6b, UINT32_MAX);
        auto it = batch.udp6.upper_bound(fk);
        REQUIRE(it != batch.udp6.end());
        check_flow_udp(it, ip6a, ip6b, 2);
    }
}

TEST_CASE("DecapBatch PSH interleaved") {
    worker_impl::DecapBatch batch;

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
        auto fk = make_fk(ip4a, ip4b, 1);
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, ip4a, ip4b, 1, 2);
    }
    {
        auto fk = make_fk(ip4a, ip4b, 201);
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, ip4a, ip4b, 201, 2);
    }

    REQUIRE(batch.tcp6.size() == 2);
    {
        auto fk = make_fk(ip6a, ip6b, 1);
        auto it = batch.tcp6.lower_bound(fk);
        REQUIRE(it != batch.tcp6.end());
        check_flow(it, ip6a, ip6b, 1, 2);
    }
    {
        auto fk = make_fk(ip6a, ip6b, 201);
        auto it = batch.tcp6.lower_bound(fk);
        REQUIRE(it != batch.tcp6.end());
        check_flow(it, ip6a, ip6b, 201, 2);
    }
}

TEST_CASE("DecapBatch coalesceItemInvalidCSum") {
    worker_impl::DecapBatch batch;

    push_one(
        batch,
        flip_l4_csum<struct ip, tcphdr>(make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1)),
        GRO_NOADD);                                                      // v4 flow 1 seq 1 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101)); // v4 flow 1 seq 101 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 201)); // v4 flow 1 seq 201 len 100
    push_one(batch, flip_l4_csum<struct ip, udphdr>(make_udp<IP>(ip4a, 1, ip4b, 1, 100)), GRO_NOADD);
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));

    REQUIRE(batch.tcp4.size() == 1);
    {
        auto fk = make_fk(ip4a, ip4b, UINT32_MAX);
        auto it = batch.tcp4.upper_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, ip4a, ip4b, 101, 2);
    }

    REQUIRE(batch.udp4.size() == 1);
    {
        auto fk = make_fk(ip4a, ip4b, UINT32_MAX);
        auto it = batch.udp4.upper_bound(fk);
        REQUIRE(it != batch.udp4.end());
        check_flow_udp(it, ip4a, ip4b, 2);
    }

    REQUIRE(batch.unrel.size() == 2);
}

TEST_CASE("DecapBatch out of order") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101)); // v4 flow 1 seq 101 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));   // v4 flow 1 seq 1 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 201)); // v4 flow 1 seq 201 len 100

    REQUIRE(batch.tcp4.size() == 1);
    {
        auto fk = make_fk(ip4a, ip4b, 1);
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, ip4a, ip4b, 1, 3);
    }
}

TEST_CASE("DecapBatch out of order 2") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 201));
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101));

    REQUIRE(batch.tcp4.size() == 1);
    {
        auto fk = make_fk(ip4a, ip4b, 1);
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, ip4a, ip4b, 1, 3);
    }
}

TEST_CASE("DecapBatch unequal TTL") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101, [](IP &ip, TCP &tcp) { ip.ttl(65); }));
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100, [](IP &ip, UDP &udp) { ip.ttl(65); }));

    REQUIRE(batch.tcp4.size() == 2);
    {
        {
            auto fk = make_fk(ip4a, ip4b, 1);
            auto it = batch.tcp4.lower_bound(fk);
            REQUIRE(it != batch.tcp4.end());
            check_flow(it, ip4a, ip4b, 1, 1);
        }
        {
            auto fk = make_fk(ip4a, ip4b, 101);
            fk.ttl = 65;
            auto it = batch.tcp4.lower_bound(fk);
            REQUIRE(it != batch.tcp4.end());
            check_flow(it, ip4a, ip4b, 101, 1);
        }
    }

    REQUIRE(batch.udp4.size() == 2);
    {
        {
            auto fk = make_fk(ip4a, ip4b, UINT32_MAX);
            auto it = batch.udp4.upper_bound(fk);
            REQUIRE(it != batch.udp4.end());
            check_flow_udp(it, ip4a, ip4b, 1);
        }
        {
            auto fk = make_fk(ip4a, ip4b, UINT32_MAX);
            fk.ttl = 65;
            auto it = batch.udp4.upper_bound(fk);
            REQUIRE(it != batch.udp4.end());
            check_flow_udp(it, ip4a, ip4b, 1);
        }
    }
}

TEST_CASE("DecapBatch unequal ToS") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101, [](IP &ip, TCP &tcp) { ip.tos(1); }));
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100, [](IP &ip, UDP &udp) { ip.tos(1); }));

    REQUIRE(batch.tcp4.size() == 2);
    {
        {
            auto fk = make_fk(ip4a, ip4b, 1);
            auto it = batch.tcp4.lower_bound(fk);
            REQUIRE(it != batch.tcp4.end());
            check_flow(it, ip4a, ip4b, 1, 1);
        }
        {
            auto fk = make_fk(ip4a, ip4b, 101);
            fk.tos = 1;
            auto it = batch.tcp4.lower_bound(fk);
            REQUIRE(it != batch.tcp4.end());
            check_flow(it, ip4a, ip4b, 101, 1);
        }
    }

    REQUIRE(batch.udp4.size() == 2);
    {
        {
            auto fk = make_fk(ip4a, ip4b, UINT32_MAX);
            auto it = batch.udp4.upper_bound(fk);
            REQUIRE(it != batch.udp4.end());
            check_flow_udp(it, ip4a, ip4b, 1);
        }
        {
            auto fk = make_fk(ip4a, ip4b, UINT32_MAX);
            fk.tos = 1;
            auto it = batch.udp4.upper_bound(fk);
            REQUIRE(it != batch.udp4.end());
            check_flow_udp(it, ip4a, ip4b, 1);
        }
    }
}

TEST_CASE("DecapBatch unequal flags more fragments set") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));
    push_one(
        batch,
        make_tcp<IP>(
            ip4a,
            1,
            ip4b,
            1,
            TCP::ACK,
            100,
            101,
            [](IP &ip, TCP &tcp) { ip.flags(static_cast<IP::Flags>(ip.flags() | IP::MORE_FRAGMENTS)); }),
        GRO_NOADD);
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));
    push_one(
        batch,
        make_udp<IP>(
            ip4a,
            1,
            ip4b,
            1,
            100,
            [](IP &ip, UDP &udp) { ip.flags(static_cast<IP::Flags>(ip.flags() | IP::MORE_FRAGMENTS)); }),
        GRO_NOADD);
}

TEST_CASE("DecapBatch unequal flags DF set") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));
    push_one(
        batch,
        make_tcp<IP>(
            ip4a,
            1,
            ip4b,
            1,
            TCP::ACK,
            100,
            101,
            [](IP &ip, TCP &tcp) { ip.flags(static_cast<IP::Flags>(ip.flags() | IP::DONT_FRAGMENT)); }),
        GRO_NOADD);
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));
    push_one(
        batch,
        make_udp<IP>(
            ip4a,
            1,
            ip4b,
            1,
            100,
            [](IP &ip, UDP &udp) { ip.flags(static_cast<IP::Flags>(ip.flags() | IP::DONT_FRAGMENT)); }),
        GRO_NOADD);
}

TEST_CASE("DecapBatch ipv6 unequal hop limit") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 1));
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 101, [](IPv6 &ip, TCP &tcp) { ip.hop_limit(65); }));
    push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100));
    push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100, [](IPv6 &ip, UDP &udp) { ip.hop_limit(65); }));

    REQUIRE(batch.tcp6.size() == 2);
    {
        {
            auto fk = make_fk(ip6a, ip6b, 1);
            auto it = batch.tcp6.lower_bound(fk);
            REQUIRE(it != batch.tcp6.end());
            check_flow(it, ip6a, ip6b, 1, 1);
        }
        {
            auto fk = make_fk(ip6a, ip6b, 101);
            fk.ttl = 65;
            auto it = batch.tcp6.lower_bound(fk);
            REQUIRE(it != batch.tcp6.end());
            check_flow(it, ip6a, ip6b, 101, 1);
        }
    }

    REQUIRE(batch.udp6.size() == 2);
    {
        {
            auto fk = make_fk(ip6a, ip6b, UINT32_MAX);
            auto it = batch.udp6.upper_bound(fk);
            REQUIRE(it != batch.udp6.end());
            check_flow_udp(it, ip6a, ip6b, 1);
        }
        {
            auto fk = make_fk(ip6a, ip6b, UINT32_MAX);
            fk.ttl = 65;
            auto it = batch.udp6.upper_bound(fk);
            REQUIRE(it != batch.udp6.end());
            check_flow_udp(it, ip6a, ip6b, 1);
        }
    }
}

TEST_CASE("DecapBatch ipv6 unequal traffic class") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 1));
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 101, [](IPv6 &ip, TCP &tcp) {
                 ip.traffic_class(1);
             }));
    push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100));
    push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100, [](IPv6 &ip, UDP &udp) { ip.traffic_class(1); }));

    REQUIRE(batch.tcp6.size() == 2);
    {
        {
            auto fk = make_fk(ip6a, ip6b, 1);
            auto it = batch.tcp6.lower_bound(fk);
            REQUIRE(it != batch.tcp6.end());
            check_flow(it, ip6a, ip6b, 1, 1);
        }
        {
            auto fk = make_fk(ip6a, ip6b, 101);
            fk.tos = 1;
            auto it = batch.tcp6.lower_bound(fk);
            REQUIRE(it != batch.tcp6.end());
            check_flow(it, ip6a, ip6b, 101, 1);
        }
    }

    REQUIRE(batch.udp6.size() == 2);
    {
        {
            auto fk = make_fk(ip6a, ip6b, UINT32_MAX);
            auto it = batch.udp6.upper_bound(fk);
            REQUIRE(it != batch.udp6.end());
            check_flow_udp(it, ip6a, ip6b, 1);
        }
        {
            auto fk = make_fk(ip6a, ip6b, UINT32_MAX);
            fk.tos = 1;
            auto it = batch.udp6.upper_bound(fk);
            REQUIRE(it != batch.udp6.end());
            check_flow_udp(it, ip6a, ip6b, 1);
        }
    }
}

TEST_CASE("DecapBatch invalid packets") {
    auto tcp4 = make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1);
    auto udp4 = make_udp<IP>(ip4a, 1, ip4b, 1, 100);
    auto tcp6 = make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 1);
    auto udp6 = make_udp<IPv6>(ip6a, 1, ip6b, 1, 100);

    worker_impl::DecapBatch batch;

    SECTION("tcp4 too short") {
        std::vector<uint8_t> pkt(&tcp4[0], &tcp4[40]);
        push_one(batch, pkt, GRO_NOADD);
    }
    SECTION("udp4 too short") {
        std::vector<uint8_t> pkt(&udp4[0], &udp4[28]);
        push_one(batch, pkt, GRO_NOADD);
    }
    SECTION("tcp6 too short") {
        std::vector<uint8_t> pkt(&tcp6[0], &tcp6[60]);
        push_one(batch, pkt, GRO_NOADD);
    }
    SECTION("udp6 too short") {
        std::vector<uint8_t> pkt(&udp6[0], &udp6[48]);
        push_one(batch, pkt, GRO_NOADD);
    }
    SECTION("invalid IP version") {
        std::vector<uint8_t> pkt(1, 0);
        push_one(batch, pkt, GRO_NOADD);
    }
    SECTION("invalid IP header len") {
        std::vector<uint8_t> pkt(tcp4);
        reinterpret_cast<struct ip *>(pkt.data())->ip_hl = 6;
        push_one(batch, pkt, GRO_NOADD);
    }
    SECTION("ip4 invalid protocol") {
        std::vector<uint8_t> pkt(tcp4);
        reinterpret_cast<struct ip *>(pkt.data())->ip_p = IPPROTO_GRE;
        push_one(batch, pkt, GRO_NOADD);
    }
    SECTION("ip6 invalid protocol") {
        std::vector<uint8_t> pkt(tcp6);
        reinterpret_cast<ip6_hdr *>(pkt.data())->ip6_nxt = IPPROTO_GRE;
        push_one(batch, pkt, GRO_NOADD);
    }
}
