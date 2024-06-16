#include <cstddef>
#include <climits>
#include <vector>
#include <random>
#include <boost/endian.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include "checksum.hpp"

// https://github.com/snabbco/snabb/blob/b7f6934caa241ac1d1b1be10d5d9f3db5d335f13/src/arch/checksum.dasl#L117
static uint16_t checksum_ref1(const uint8_t *data, size_t size) {
    uint64_t csum = 0;
    size_t i = size;
    while (i > 1) {
        auto word = *reinterpret_cast<const uint16_t *>(data + (size - i));
        csum += word;
        i -= 2;
    }
    if (i == 1)
        csum += data[size - 1];
    while (1) {
        auto carry = csum >> 16;
        if (!carry)
            break;
        csum = (csum & 0xffff) + carry;
    }
    return ~csum & 0xffff;
}

// https://stackoverflow.com/a/8845286/8642889
static uint16_t checksum_ref2(const uint16_t *buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }
    if (size)
        cksum += *(const uint8_t *)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (uint16_t)(~cksum);
}

static std::vector<uint8_t> create_packet(size_t size) {
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t> rnd;
    std::vector<uint8_t> vec(size);
    for (auto &b : vec)
        b = rnd();
    return vec;
}

static std::vector<uint8_t> create_packet_carry(size_t size) {
    std::vector<uint8_t> vec(size, 0xff);
    vec[size - 1] = 1;
    return vec;
}

TEST_CASE("checksum") {
    auto size = GENERATE(Catch::Generators::range(44, 1501));
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
