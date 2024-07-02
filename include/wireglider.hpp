#pragma once

#include <csignal>
#include <system_error>

#include "endpoint.hpp"
#include "client.hpp"

namespace wireglider {

using ClientTable = CdsHashtable<x25519_key, Client::PubkeyTag, Client>;
using EndpointTable = CdsHashtable<ClientEndpoint, Client::EndpointTag, Client>;

struct QuitException : public std::exception {};

static inline void make_exit_sigset(sigset_t &sigs) {
    if (sigemptyset(&sigs) < 0 || sigaddset(&sigs, SIGINT) < 0 || sigaddset(&sigs, SIGTERM) < 0)
        throw std::system_error(errno, std::system_category(), "sigset");
}

} // namespace wireglider
