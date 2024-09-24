#pragma once

#include <algorithm>
#include <iterator>
#include <xxhash.h>

namespace wireglider {

// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays)

struct Key256 {
    uint8_t key[32];
};

bool parse_keybytes(uint8_t (&key)[32], const char *str);

// NOLINTEND(cppcoreguidelines-avoid-c-arrays)

static constexpr bool operator==(const wireglider::Key256 &a, const wireglider::Key256 &b) noexcept {
    return std::equal(std::begin(a.key), std::end(a.key), std::begin(b.key));
}

static constexpr auto operator<=>(const wireglider::Key256 &a, const wireglider::Key256 &b) noexcept {
    return std::lexicographical_compare_three_way(
        std::begin(a.key),
        std::end(a.key),
        std::begin(b.key),
        std::end(b.key));
}

} // namespace wireglider

namespace std {
template <>
struct hash<wireglider::Key256> {
    size_t operator()(const wireglider::Key256 &a) const noexcept {
        return XXH3_64bits(&a.key[0], sizeof(a.key));
    }
};
} // namespace std
