#include <catch2/catch_test_macros.hpp>

#include "endian.hpp"

using namespace wireglider;
using namespace boost::endian;

TEST_CASE("large from small") {
    uint64_t dest;
    uint16_t src = 1;
    SECTION("assign_big_from_native") {
        assign_big_from_native(dest, src);
        REQUIRE(dest == native_to_big(uint64_t(src)));
    }
    SECTION("assign_little_from_native") {
        assign_little_from_native(dest, src);
        REQUIRE(dest == native_to_little(uint64_t(src)));
    }
    SECTION("sanity") {
        big_ref(dest) = little_ref(src);
        REQUIRE(dest == uint64_t(1) << 56);
        native_ref(dest) = native_ref(src);
        REQUIRE(dest == 1);
    }
    SECTION("ref") {
        big_ref(dest) = native_ref(src);
        REQUIRE(dest == native_to_big(uint64_t(src)));
        little_ref(dest) = native_ref(src);
        REQUIRE(dest == native_to_little(uint64_t(src)));
        native_ref(dest) = big_ref(src);
        REQUIRE(dest == big_to_native(uint64_t(src)));
        native_ref(dest) = little_ref(src);
        REQUIRE(dest == little_to_native(uint64_t(src)));
        big_ref(dest) = little_ref(src);
        REQUIRE(dest == endian_reverse(uint64_t(src)));
        little_ref(dest) = big_ref(src);
        REQUIRE(dest == endian_reverse(uint64_t(src)));
    }
}

TEST_CASE("small from large") {
    uint16_t dest;
    uint64_t src = 1;
    SECTION("assign_big_from_native") {
        assign_big_from_native(dest, src);
        REQUIRE(dest == native_to_big(uint16_t(src)));
    }
    SECTION("assign_little_from_native") {
        assign_little_from_native(dest, src);
        REQUIRE(dest == native_to_little(uint16_t(src)));
    }
    SECTION("sanity") {
        big_ref(dest) = little_ref(src);
        REQUIRE(dest == 0x100);
        native_ref(dest) = native_ref(src);
        REQUIRE(dest == 1);
    }
    SECTION("ref") {
        big_ref(dest) = native_ref(src);
        REQUIRE(dest == native_to_big(uint16_t(src)));
        little_ref(dest) = native_ref(src);
        REQUIRE(dest == native_to_little(uint16_t(src)));
        native_ref(dest) = big_ref(src);
        REQUIRE(dest == big_to_native(uint16_t(src)));
        native_ref(dest) = little_ref(src);
        REQUIRE(dest == little_to_native(uint16_t(src)));
        big_ref(dest) = little_ref(src);
        REQUIRE(dest == endian_reverse(uint16_t(src)));
        little_ref(dest) = big_ref(src);
        REQUIRE(dest == endian_reverse(uint16_t(src)));
    }
}

TEST_CASE("large from const small") {
    uint64_t dest;
    const uint16_t src = 1;
    big_ref(dest) = native_ref(src);
    REQUIRE(dest == native_to_big(uint64_t(src)));
    little_ref(dest) = native_ref(src);
    REQUIRE(dest == native_to_little(uint64_t(src)));
    native_ref(dest) = big_ref(src);
    REQUIRE(dest == big_to_native(uint64_t(src)));
    native_ref(dest) = little_ref(src);
    REQUIRE(dest == little_to_native(uint64_t(src)));
    big_ref(dest) = little_ref(src);
    REQUIRE(dest == endian_reverse(uint64_t(src)));
    little_ref(dest) = big_ref(src);
    REQUIRE(dest == endian_reverse(uint64_t(src)));
}

TEST_CASE("small from const large") {
    uint16_t dest;
    const uint64_t src = 1;
    big_ref(dest) = native_ref(src);
    REQUIRE(dest == native_to_big(uint16_t(src)));
    little_ref(dest) = native_ref(src);
    REQUIRE(dest == native_to_little(uint16_t(src)));
    native_ref(dest) = big_ref(src);
    REQUIRE(dest == big_to_native(uint16_t(src)));
    native_ref(dest) = little_ref(src);
    REQUIRE(dest == little_to_native(uint16_t(src)));
    big_ref(dest) = little_ref(src);
    REQUIRE(dest == endian_reverse(uint16_t(src)));
    little_ref(dest) = big_ref(src);
    REQUIRE(dest == endian_reverse(uint16_t(src)));
}

TEST_CASE("large from rvalue small") {
    uint64_t dest;
    big_ref(dest) = native_ref(uint16_t(1));
    REQUIRE(dest == native_to_big(uint64_t(1)));
    little_ref(dest) = native_ref(uint16_t(1));
    REQUIRE(dest == native_to_little(uint64_t(1)));
    native_ref(dest) = big_ref(uint16_t(1));
    REQUIRE(dest == big_to_native(uint64_t(1)));
    native_ref(dest) = little_ref(uint16_t(1));
    REQUIRE(dest == little_to_native(uint64_t(1)));
    big_ref(dest) = little_ref(uint16_t(1));
    REQUIRE(dest == endian_reverse(uint64_t(1)));
    little_ref(dest) = big_ref(uint16_t(1));
    REQUIRE(dest == endian_reverse(uint64_t(1)));
}

TEST_CASE("small from rvalue large") {
    uint16_t dest;
    big_ref(dest) = native_ref(uint64_t(1));
    REQUIRE(dest == native_to_big(uint16_t(1)));
    little_ref(dest) = native_ref(uint64_t(1));
    REQUIRE(dest == native_to_little(uint16_t(1)));
    native_ref(dest) = big_ref(uint64_t(1));
    REQUIRE(dest == big_to_native(uint16_t(1)));
    native_ref(dest) = little_ref(uint64_t(1));
    REQUIRE(dest == little_to_native(uint16_t(1)));
    big_ref(dest) = little_ref(uint64_t(1));
    REQUIRE(dest == endian_reverse(uint16_t(1)));
    little_ref(dest) = big_ref(uint64_t(1));
    REQUIRE(dest == endian_reverse(uint16_t(1)));
}
