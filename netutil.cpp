#include <string>
#include <regex>
#include <stdexcept>
#include <arpa/inet.h>

#include "netutil.hpp"

namespace wgss {

std::variant<std::monostate, sockaddr_in, sockaddr_in6> parse_sockaddr(const char *str) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sockaddr_in6 sin6{};
    sin6.sin6_family = AF_INET6;
    if (inet_pton(AF_INET, str, &sin.sin_addr) > 0) {
        return sin;
    } else if (inet_pton(AF_INET6, str, &sin6.sin6_addr) > 0) {
        return sin6;
    } else {
        return {};
    }
}

std::variant<std::monostate, sockaddr_in, sockaddr_in6> parse_ipport(const char *str) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sockaddr_in6 sin6{};
    sin6.sin6_family = AF_INET6;

    std::string input(str);
    std::regex pattern4("([0-9.]+):([0-9]+)");
    std::regex pattern6("\\[([0-9a-f:]+)\\]:([0-9]+)", std::regex::icase);
    std::smatch match;
    if (std::regex_match(input, match, pattern4)) {
        auto ip = match[1].str();
        if (inet_pton(AF_INET, ip.c_str(), &sin.sin_addr) > 0) {
            auto port = stoul(match[2].str());
            if (port > 0 && port <= UINT16_MAX) {
                sin.sin_port = port;
                return sin;
            }
        }
    } else if (std::regex_match(input, match, pattern6)) {
        auto ip = match[1].str();
        if (inet_pton(AF_INET6, ip.c_str(), &sin.sin_addr) > 0) {
            auto port = stoul(match[2].str());
            if (port > 0 && port <= UINT16_MAX) {
                sin.sin_port = port;
                return sin;
            }
        }
    }
    return {};
}

} // namespace wgss
