#include <tdutil/util.hpp>
#include "prefix.hpp"
#include "endian.hpp"

namespace wireglider {

std::pair<unsigned long, unsigned long> NetPrefix4::get_range(const in_addr &addr, unsigned int prefix) const {
    assert(prefix <= 32);
    auto mask = (1ul << (32 - prefix)) - 1;
    auto ip = boost::endian::big_to_native(addr.s_addr);
    auto begin = ip & ~mask;
    auto end = ip | mask;
    return std::make_pair(begin, end);
}

unsigned long NetPrefix4::reduce([[maybe_unused]] const in_addr &addr) const {
    return 0;
}

unsigned __int128 load_ip6(const in6_addr &addr) {
    auto ip_hi = boost::endian::load_big_u64(&addr.s6_addr[0]);
    auto ip_lo = boost::endian::load_big_u64(&addr.s6_addr[8]);
    return (static_cast<unsigned __int128>(ip_hi) << 64) | ip_lo;
}

std::pair<unsigned long, unsigned long> NetPrefix6::get_range(const in6_addr &addr, unsigned int prefix) const {
    assert(prefix >= quantum && prefix <= 128);
    unsigned __int128 mask = (static_cast<unsigned __int128>(1) << (128 - prefix)) - 1;
    auto ip = load_ip6(addr);
    auto begin = (ip & ~mask) >> quantum;
    auto end = (ip | mask) >> quantum;
    return std::make_pair(static_cast<unsigned long>(begin & ULONG_MAX), static_cast<unsigned long>(end & ULONG_MAX));
}

unsigned long NetPrefix6::reduce(const in6_addr &addr) const {
    auto ip = load_ip6(addr);
    return static_cast<unsigned long>((ip >> quantum) & ULONG_MAX);
}

} // namespace wireglider
