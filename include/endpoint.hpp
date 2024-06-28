#pragma once

#include <utility>
#include <variant>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "xxhash.h"

namespace wgss {

using ClientEndpoint = std::variant<sockaddr_in, sockaddr_in6>;

static inline bool operator==(const ClientEndpoint &a, const ClientEndpoint &b) noexcept {
    if (a.index() != b.index())
        return 0;
    if (auto sina = std::get_if<sockaddr_in>(&a)) {
        auto sinb = std::get_if<sockaddr_in>(&b);
        return *sina == *sinb;
    } else if (auto sin6a = std::get_if<sockaddr_in6>(&a)) {
        auto sin6b = std::get_if<sockaddr_in6>(&a);
        return *sin6a == *sin6b;
    } else {
        return 0;
    }
}

static inline std::strong_ordering operator<=>(const ClientEndpoint &a, const ClientEndpoint &b) noexcept {
    if (a.index() != b.index()) {
        return a.index() <=> b.index();
    } else if (auto sina = std::get_if<sockaddr_in>(&a)) {
        auto sinb = std::get_if<sockaddr_in>(&b);
        return *sina <=> *sinb;
    } else if (auto sin6a = std::get_if<sockaddr_in6>(&a)) {
        auto sin6b = std::get_if<sockaddr_in6>(&a);
        return *sin6a <=> *sin6b;
    } else {
        return a.index() <=> b.index();
    }
}

// I swear that all of the crap above compiles down to fairly efficient code...

} // namespace wgss

namespace std {
template <>
struct hash<wgss::ClientEndpoint> {
    constexpr size_t operator()(const wgss::ClientEndpoint &a) const noexcept {
        if (auto sin = std::get_if<sockaddr_in>(&a))
            return XXH3_64bits(sin, offsetof(sockaddr_in, sin_zero));
        else if (auto sin6 = std::get_if<sockaddr_in6>(&a))
            return XXH3_64bits(sin6, sizeof(a));
        else
            return 0;
    }
};
} // namespace std