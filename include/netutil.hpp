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

namespace wgss {

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

std::variant<std::monostate, sockaddr_in, sockaddr_in6> parse_sockaddr(const char *str);

static constexpr bool is_eagain(int e = errno) {
    return e == EAGAIN || e == EWOULDBLOCK;
}

} // namespace wgss

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
