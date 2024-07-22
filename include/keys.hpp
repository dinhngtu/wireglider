#pragma once

#include <algorithm>
#include <iterator>
#include <xxhash.h>

namespace wireglider {

struct PublicKey {
    uint8_t key[32];
};

bool parse_keybytes(uint8_t (&key)[32], const char *str);

} // namespace wireglider

namespace std {
template <>
struct hash<wireglider::PublicKey> {
    size_t operator()(const wireglider::PublicKey &a) const noexcept {
        return XXH3_64bits(&a.key[0], sizeof(a.key));
    }
};
} // namespace std

static constexpr bool operator==(const wireglider::PublicKey &a, const wireglider::PublicKey &b) noexcept {
    return std::equal(std::begin(a.key), std::end(a.key), std::begin(b.key));
}

static constexpr auto operator<=>(const wireglider::PublicKey &a, const wireglider::PublicKey &b) noexcept {
    return std::lexicographical_compare_three_way(
        std::begin(a.key),
        std::end(a.key),
        std::begin(b.key),
        std::end(b.key));
}
