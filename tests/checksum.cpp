#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include "checksum_tests.hpp"

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
    auto csum = fastcsum::fold_complement_checksum(wgss::checksum_impl::checksum_nofold(pkt, 0));
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
