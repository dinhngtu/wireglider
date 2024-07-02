#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <msgpack.hpp>

#include "client.hpp"

#define WGSS_MSGPACK_VERSION "6.1.1"
static_assert(std::equal(
    std::begin(MSGPACK_VERSION),
    std::end(MSGPACK_VERSION),
    std::begin(WGSS_MSGPACK_VERSION),
    std::end(WGSS_MSGPACK_VERSION)));

namespace wgss {

namespace control {

enum ControlCode : unsigned int {
    ADD_PEER,
    REMOVE_PEER,
    CONTROL_MAX,
};

struct AddPeer {
    std::string pubkey;
    std::string psk;
    std::string endpoint;
    uint16_t keepalive;
    std::vector<std::string> allowed_ips;
    MSGPACK_DEFINE(pubkey, psk, endpoint, keepalive, allowed_ips);
};

struct RemovePeer {
    std::string pubkey;
    MSGPACK_DEFINE(pubkey);
};

using ControlRequest = std::map<ControlCode, msgpack::type::variant>;

struct ControlResponse {
    int32_t result;
    MSGPACK_DEFINE(result);
};

} // namespace control

} // namespace wgss

MSGPACK_ADD_ENUM(wgss::control::ControlCode);
