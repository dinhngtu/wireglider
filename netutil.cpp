#include <string>
#include <regex>
#include <stdexcept>
#include <arpa/inet.h>
#include <boost/algorithm/string.hpp>

#include "netutil.hpp"

namespace wireglider {

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
    std::string input(str);
    std::regex pattern4("([0-9.]+):([0-9]+)");
    std::regex pattern6("\\[([0-9a-f:]+)\\]:([0-9]+)", std::regex::icase);
    std::smatch match;
    if (std::regex_match(input, match, pattern4)) {
        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        auto ip = match[1].str();
        if (inet_pton(AF_INET, ip.c_str(), &sin.sin_addr) > 0) {
            auto port = stoul(match[2].str());
            if (port > 0 && port <= UINT16_MAX) {
                sin.sin_port = port;
                return sin;
            }
        }
    } else if (std::regex_match(input, match, pattern6)) {
        sockaddr_in6 sin6{};
        sin6.sin6_family = AF_INET6;
        auto ip = match[1].str();
        if (inet_pton(AF_INET6, ip.c_str(), &sin6.sin6_addr) > 0) {
            auto port = stoul(match[2].str());
            if (port > 0 && port <= UINT16_MAX) {
                sin6.sin6_port = port;
                return sin6;
            }
        }
    }
    return {};
}

std::variant<std::monostate, std::pair<in_addr, unsigned int>, std::pair<in6_addr, unsigned int>> parse_iprange(
    const char *str) {
    std::string cidr(str);
    std::vector<std::string> cidr_parts;
    boost::split(cidr_parts, cidr, boost::is_any_of("/"));
    if (cidr_parts.size() != 2)
        return {};
    unsigned int prefix = strtoul(cidr_parts[1].c_str(), nullptr, 10);
    auto addr = parse_sockaddr(cidr_parts[0].c_str());
    if (auto sin = std::get_if<sockaddr_in>(&addr)) {
        if (prefix <= 32)
            return std::make_pair(sin->sin_addr, prefix);
    } else if (auto sin6 = std::get_if<sockaddr_in6>(&addr)) {
        if (prefix <= 128)
            return std::make_pair(sin6->sin6_addr, prefix);
    }
    return {};
}

} // namespace wireglider
