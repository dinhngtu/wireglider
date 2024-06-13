#pragma once

#include <variant>
#include <cstring>
#include <string>
#include <linux/if.h>
#include <netinet/in.h>

namespace wgss {

struct Ifr {
    Ifr() {
        memset(&ifr, 0, sizeof(ifreq));
    }
    Ifr(const char *name) : Ifr() {
        strncpy(&ifr.ifr_name[0], name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = 0;
    }
    Ifr(const std::string &name) : Ifr(name.c_str()) {}

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

std::variant<sockaddr_in, sockaddr_in6> parse_ip(const char *str);

} // namespace wgss
