#pragma once

#include <cstdint>
#include <climits>
#include <cstring>
#include <endian.h>
#include <vector>
#include <random>

// https://github.com/snabbco/snabb/blob/b7f6934caa241ac1d1b1be10d5d9f3db5d335f13/src/arch/checksum.dasl#L117
static uint16_t checksum_ref1(const uint8_t *data, size_t size) {
    uint64_t csum = 0;
    size_t i = size;
    while (i > 1) {
        uint16_t word;
        memcpy(&word, data + (size - i), sizeof(word));
        csum += word;
        i -= 2;
    }
    if (i == 1) {
        // RFC 1071 erratum 3133 https://www.rfc-editor.org/errata/eid3133
        uint16_t last = data[size - 1];
        if (__BYTE_ORDER == __BIG_ENDIAN)
            last <<= 8;
        csum += last;
    }
    while (1) {
        auto carry = csum >> 16;
        if (!carry)
            break;
        csum = (csum & 0xffff) + carry;
    }
    return ~csum & 0xffff;
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
