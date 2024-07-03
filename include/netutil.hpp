#pragma once

#include <vector>
#include <variant>
#include <cstring>
#include <string>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <tdutil/util.hpp>

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
