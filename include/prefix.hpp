#pragma once

#include <climits>
#include <utility>
#include <algorithm>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "netutil.hpp"

namespace wireglider {

struct NetPrefix4 {
    static const unsigned int bits = 32;
    constexpr NetPrefix4() {
    }
    constexpr NetPrefix4([[maybe_unused]] in_addr, [[maybe_unused]] unsigned int) {
    }
    explicit constexpr NetPrefix4([[maybe_unused]] const IpRange4 &net) {
    }
    std::pair<unsigned long, unsigned long> get_range(const in_addr &addr, unsigned int prefix) const;
    unsigned long reduce(const in_addr &addr) const;
    unsigned int quantum = 0;
};

struct NetPrefix6 {
    static constexpr const unsigned int bits = CHAR_BIT * sizeof(unsigned long);
    constexpr NetPrefix6() {
    }
    constexpr NetPrefix6([[maybe_unused]] in6_addr net, unsigned int prefix) : quantum(std::max(prefix, bits) - bits) {
    }
    explicit constexpr NetPrefix6(const IpRange6 &net) : NetPrefix6(net.first, net.second) {
    }
    std::pair<unsigned long, unsigned long> get_range(const in6_addr &addr, unsigned int prefix) const;
    unsigned long reduce(const in6_addr &addr) const;
    unsigned int quantum = 0;
};

} // namespace wireglider
