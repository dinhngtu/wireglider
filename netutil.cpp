#include "netutil.hpp"

#include <stdexcept>
#include <arpa/inet.h>

namespace wgss {

std::variant<sockaddr_in, sockaddr_in6> parse_ip(const char *str) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sockaddr_in6 sin6{};
    sin6.sin6_family = AF_INET6;
    if (inet_pton(AF_INET, str, &sin.sin_addr)) {
        return sin;
    } else if (inet_pton(AF_INET6, str, &sin6.sin6_addr)) {
        return sin6;
    } else {
        throw std::invalid_argument("invalid address");
    }
}

} // namespace wgss
