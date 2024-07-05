#pragma once

#include <atomic>
#include <csignal>
#include <system_error>

#include "endpoint.hpp"
#include "client.hpp"
#include "rundown.hpp"
#include "prefix.hpp"

namespace wireglider {

using ClientTable = CdsHashtable<x25519_key, Client::PubkeyTag, const Client>;
using EndpointTable = CdsHashtable<ClientEndpoint, Client::EndpointTag, const Client>;

struct QuitException : public std::exception {};

struct Config {
    rcu_head rcu;
    x25519_key privkey;
    NetPrefix4 prefix4;
    NetPrefix6 prefix6;

    static void rcu_deleter(rcu_head *rcu) {
        auto config = caa_container_of(rcu, Config, rcu);
        delete config;
    }
};
using ConfigRef = std::atomic_ref<Config *>;

static inline void make_exit_sigset(sigset_t &sigs) {
    if (sigemptyset(&sigs) < 0 || sigaddset(&sigs, SIGINT) < 0 || sigaddset(&sigs, SIGTERM) < 0)
        throw std::system_error(errno, std::system_category(), "sigset");
}

} // namespace wireglider
