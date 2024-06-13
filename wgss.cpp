#include <vector>
#include <thread>
#include <memory>
#include <cxxopts.hpp>
#include <fmt/format.h>
#include <boost/algorithm/string.hpp>

#include "tun.hpp"
#include "udpsock.hpp"
#include "worker.hpp"
#include "netutil.hpp"

/*
 * schema:
 * - open tun -> get tun fd. tun if is the *user and applications* side
 * - bind udp socket to ep -> get udp fd. ep socket is the *encrypted traffic* side
 * - read tun -> encap -> write udp
 * - read udp -> decap -> write tun
 */

using namespace tdutil;
using namespace wgss;

static cxxopts::Options make_options() {
    cxxopts::Options opt{"wgss"};
    auto g = opt.add_options();
    g("a,listen-address", "listen address", cxxopts::value<std::string>());
    g("A,tunnel-address", "tunnel CIDR", cxxopts::value<std::string>());
    g("p,port", "port number", cxxopts::value<uint16_t>()->default_value("7477"));
    g("j,jobs", "thread count", cxxopts::value<int>()->default_value("1"));
    return opt;
}

int main(int argc, char **argv) {
    auto opts = make_options();
    cxxopts::ParseResult argm;
    try {
        argm = opts.parse(argc, argv);
    } catch (const std::exception &) {
        fmt::print("{}\n", opts.help());
        return 1;
    }

    std::unique_ptr<UdpServer> server;
    auto listen_ip = argm["listen-address"].as<std::string>();
    auto listen_port = argm["port"].as<uint16_t>();
    auto listen_addr = parse_ip(listen_ip.c_str());
    if (auto sin = std::get_if<sockaddr_in>(&listen_addr)) {
        sin->sin_port = htons(listen_port);
        server = std::make_unique<UdpServer>(*sin);
    } else if (auto sin6 = std::get_if<sockaddr_in6>(&listen_addr)) {
        sin6->sin6_port = htons(listen_port);
        server = std::make_unique<UdpServer>(*sin6);
    } else {
        throw std::runtime_error("invalid listen address");
    }

    server->fd().set_nonblock();

    Tun tun;
    auto devname = tun.name();
    tun.fd().set_nonblock();

    auto tun_cidr = argm["tunnel-address"].as<std::string>();
    std::vector<std::string> tun_cidr_parts;
    boost::split(tun_cidr_parts, tun_cidr, boost::is_any_of("/"));
    if (tun_cidr_parts.size() != 2)
        throw std::runtime_error("invalid tunnel address");
    auto tun_prefix = strtoul(tun_cidr_parts[1].c_str(), nullptr, 10);
    auto tun_addr = parse_ip(tun_cidr_parts[0].c_str());
    if (auto tun_sin = std::get_if<sockaddr_in>(&tun_addr)) {
        if (tun_prefix > 32)
            throw std::runtime_error("invalid tunnel prefix");
        tun.set_address(*tun_sin, tun_prefix);
    } else if (auto tun_sin6 = std::get_if<sockaddr_in6>(&tun_addr)) {
        if (tun_prefix > 128)
            throw std::runtime_error("invalid tunnel prefix");
        tun.set_address6(*tun_sin6, tun_prefix);
    } else {
        throw std::runtime_error("invalid tunnel address");
    }

    tun.set_up(true);

    auto njobs = argm["jobs"].as<int>();
    std::vector<std::jthread> workers;
    for (int i = 0; i < njobs; i++) {
        workers.emplace_back(
            worker_func,
            WorkerArg{
                .tun = &tun,
                .server = server.get(),
            });
    }
}
