#include <string>
#include <regex>
#include <stdexcept>
#include <arpa/inet.h>
#include <boost/algorithm/string.hpp>

#include "netutil.hpp"
#include "endian.hpp"

namespace wireglider {

std::variant<std::monostate, in_addr, in6_addr> parse_inaddr(const char *str) {
    in_addr addr4;
    in6_addr addr6;
    if (inet_pton(AF_INET, str, &addr4) > 0) {
        return addr4;
    } else if (inet_pton(AF_INET6, str, &addr6) > 0) {
        return addr6;
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
                assign_big_from_native(sin.sin_port, port);
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
                assign_big_from_native(sin6.sin6_port, port);
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
    auto addr = parse_inaddr(cidr_parts[0].c_str());
    if (auto addr4 = std::get_if<in_addr>(&addr)) {
        if (prefix <= 32)
            return std::make_pair(*addr4, prefix);
    } else if (auto addr6 = std::get_if<in6_addr>(&addr)) {
        if (prefix <= 128)
            return std::make_pair(*addr6, prefix);
    }
    return {};
}

} // namespace wireglider
