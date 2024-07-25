#pragma once

#include <variant>
#include <cstring>
#include <string>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <boost/endian.hpp>
#include <boost/container_hash/hash.hpp>
#include <fmt/format.h>
#include <xxhash.h>

#include <tdutil/util.hpp>

// IWYU pragma: always_keep

namespace wireglider {

struct Ifr {
    Ifr() {
        memset(&ifr, 0, sizeof(ifreq));
    }
    Ifr(const char *name) : Ifr() {
        strncpy(&ifr.ifr_name[0], name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = 0;
    }
    Ifr(const std::string &name) : Ifr(name.c_str()) {
    }
    Ifr(Ifr &&) = default;
    Ifr &operator=(Ifr &&) = default;
    ~Ifr() {
    }

    Ifr(const Ifr &other) {
        memcpy(&ifr, &other.ifr, sizeof(ifreq));
    }
    Ifr &operator=(const Ifr &other) {
        memcpy(&ifr, &other.ifr, sizeof(ifreq));
        return *this;
    }

    constexpr ifreq *operator->() {
        return &ifr;
    }
    constexpr const ifreq *operator->() const {
        return &ifr;
    }
    constexpr ifreq &operator*() {
        return ifr;
    }
    constexpr const ifreq &operator*() const {
        return ifr;
    }
    constexpr ifreq *operator&() {
        return &ifr;
    }
    constexpr const ifreq *operator&() const {
        return &ifr;
    }

    ifreq ifr;
};

using IpRange4 = std::pair<in_addr, unsigned int>;
using IpRange6 = std::pair<in6_addr, unsigned int>;
using IpRange = std::variant<IpRange4, IpRange6>;

std::variant<std::monostate, in_addr, in6_addr> parse_inaddr(const char *str);
std::variant<std::monostate, sockaddr_in, sockaddr_in6> parse_ipport(const char *str);
std::variant<std::monostate, IpRange4, IpRange6> parse_iprange(const char *str);

} // namespace wireglider

static inline size_t hash_value(const wireglider::IpRange &a) {
    if (auto ip4 = std::get_if<wireglider::IpRange4>(&a)) {
        size_t seed = XXH3_64bits(&ip4->first, sizeof(ip4->first));
        boost::hash_combine(seed, ip4->second);
        return seed;
    } else if (auto ip6 = std::get_if<wireglider::IpRange6>(&a)) {
        size_t seed = XXH3_64bits(&ip6->first, sizeof(ip6->first));
        boost::hash_combine(seed, ip6->second);
        return seed;
    } else {
        tdutil::unreachable();
    }
}

static inline bool operator==(const sockaddr_in &a, const sockaddr_in &b) noexcept {
    return !memcmp(&a, &b, offsetof(sockaddr_in, sin_zero));
}

static inline auto operator<=>(const sockaddr_in &a, const sockaddr_in &b) noexcept {
    return memcmp(&a, &b, offsetof(sockaddr_in, sin_zero)) <=> 0;
}

static inline bool operator==(const sockaddr_in6 &a, const sockaddr_in6 &b) noexcept {
    return !memcmp(&a, &b, sizeof(a));
}

static inline auto operator<=>(const sockaddr_in6 &a, const sockaddr_in6 &b) noexcept {
    return memcmp(&a, &b, sizeof(a)) <=> 0;
}

static inline bool operator==(const in_addr &a, const in_addr &b) noexcept {
    return a.s_addr == b.s_addr;
}

static inline auto operator<=>(const in_addr &a, const in_addr &b) noexcept {
    return memcmp(&a, &b, sizeof(a)) <=> 0;
}

static inline bool operator==(const in6_addr &a, const in6_addr &b) noexcept {
    return !memcmp(&a, &b, sizeof(a));
}

static inline auto operator<=>(const in6_addr &a, const in6_addr &b) noexcept {
    return memcmp(&a, &b, sizeof(a)) <=> 0;
}

static inline auto format_as(const in_addr &a) {
    uint8_t b[4];
    boost::endian::store_big_u32(b, boost::endian::big_to_native(a.s_addr));
    return fmt::format("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
}

static inline auto format_as(const in6_addr &a) {
    return fmt::format(
        "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
        boost::endian::big_to_native(a.s6_addr16[0]),
        boost::endian::big_to_native(a.s6_addr16[1]),
        boost::endian::big_to_native(a.s6_addr16[2]),
        boost::endian::big_to_native(a.s6_addr16[3]),
        boost::endian::big_to_native(a.s6_addr16[4]),
        boost::endian::big_to_native(a.s6_addr16[5]),
        boost::endian::big_to_native(a.s6_addr16[6]),
        boost::endian::big_to_native(a.s6_addr16[7]));
}

static inline auto format_as(const struct ip &ip) {
    return fmt::format("ip4 {}->{} proto {}", ip.ip_src, ip.ip_dst, ip.ip_p);
}

static inline auto format_as(const ip6_hdr &ip) {
    return fmt::format("ip6 {}->{} proto {}", ip.ip6_src, ip.ip6_dst, ip.ip6_nxt);
}

static inline auto format_as(const sockaddr_in &sin) {
    return fmt::format("{}:{}", format_as(sin.sin_addr), boost::endian::big_to_native(sin.sin_port));
}

static inline auto format_as(const sockaddr_in6 &sin6) {
    return fmt::format("[{}]:{}", format_as(sin6.sin6_addr), boost::endian::big_to_native(sin6.sin6_port));
}
