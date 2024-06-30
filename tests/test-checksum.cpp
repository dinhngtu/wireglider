#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <tins/tins.h>

#include "checksum.hpp"
#include "checksum_tests.hpp"

using namespace Tins;

TEST_CASE("checksum") {
    auto size = GENERATE(Catch::Generators::range(1, 1501));
    auto pkt = create_packet(size);
    auto csum = wgss::checksum(pkt, 0);
    auto ref1 = checksum_ref1(pkt.data(), pkt.size());
    auto ref2 = checksum_ref2(reinterpret_cast<uint16_t *>(pkt.data()), pkt.size());
    REQUIRE(ref1 == ref2);
    REQUIRE(csum == ref1);
}

TEST_CASE("checksum_carry") {
    auto size = GENERATE(Catch::Generators::range(1, 64));
    auto pkt = create_packet_carry(size);
    auto csum = wgss::checksum(pkt, 0);
    auto ref1 = checksum_ref1(pkt.data(), pkt.size());
    auto ref2 = checksum_ref2(reinterpret_cast<uint16_t *>(pkt.data()), pkt.size());
    REQUIRE(ref1 == ref2);
    REQUIRE(csum == ref1);
}

template <size_t O, size_t N>
static inline void csum_test_sized(std::span<uint8_t> b) {
    std::span<const uint8_t, N> pkt = b.subspan<O, N>();
    auto csum = fastcsum::fold_complement_checksum64(wgss::checksum_impl::checksum_nofold(pkt, 0));
    auto ref1 = checksum_ref1(pkt.data(), pkt.size());
    auto ref2 = checksum_ref2(reinterpret_cast<const uint16_t *>(pkt.data()), pkt.size());
    REQUIRE(ref1 == ref2);
    REQUIRE(csum == ref1);
}

TEST_CASE("checksum_sizes") {
    auto pkt = create_packet(16);
    csum_test_sized<0, 1>(pkt);
    csum_test_sized<0, 2>(pkt);
    csum_test_sized<0, 4>(pkt);
    csum_test_sized<0, 8>(pkt);
    csum_test_sized<0, 16>(pkt);
}

TEST_CASE("checksum_sizes_carry") {
    auto pkt = create_packet_carry(16);
    csum_test_sized<15, 1>(pkt);
    csum_test_sized<14, 2>(pkt);
    csum_test_sized<12, 4>(pkt);
    csum_test_sized<8, 8>(pkt);
    csum_test_sized<0, 16>(pkt);
}

template <bool isv6, bool istcp>
void csum_test_l4() {
    using ip_type = std::conditional_t<isv6, IPv6, IP>;
    using l4_type = std::conditional_t<istcp, TCP, UDP>;
    ip_type ip;
    if constexpr (isv6)
        ip = ip_type("2001:db8::2", "2001:db8::1");
    else
        ip = ip_type("192.0.2.2", "192.0.2.1");
    l4_type l4(1, 1);
    RawPDU payload(create_packet(100));
    auto pkt = ip / l4 / payload;
    auto pkt_bytes = pkt.serialize();
    REQUIRE(wgss::calc_l4_checksum(pkt_bytes, isv6, istcp, ip.header_size()) == 0);
}

TEST_CASE("l4 checksum") {
    SECTION("ipv4 tcp") {
        csum_test_l4<false, true>();
    }
    SECTION("ipv4 udp") {
        csum_test_l4<false, false>();
    }
    SECTION("ipv6 tcp") {
        csum_test_l4<true, true>();
    }
    SECTION("ipv6 udp") {
        csum_test_l4<true, false>();
    }
}
