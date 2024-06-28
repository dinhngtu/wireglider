#include <vector>
#include <thread>
#include <memory>
#include <string>
#include <stdexcept>
#include <cxxopts.hpp>
#include <fmt/format.h>
#include <boost/algorithm/string.hpp>

#include "tun.hpp"
#include "udpsock.hpp"
#include "worker.hpp"
#include "netutil.hpp"
#include "maple_tree.hpp"

/*
 * schema:
 * - open tun -> get tun fd. tun if is the *user and applications* side
 * - bind udp socket to ep -> get udp fd. ep socket is the *encrypted traffic* side
 * - read tun -> encap -> write udp
 * - read udp -> decap -> write tun
 */

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
    std::variant<std::monostate, sockaddr_in, sockaddr_in6> listen_addr;
    uint16_t listen_port;
    std::variant<std::monostate, sockaddr_in, sockaddr_in6> tun_addr;
    unsigned int tun_prefix;

    auto opts = make_options();
    cxxopts::ParseResult argm;
    try {
        argm = opts.parse(argc, argv);

        auto listen_ip = argm["listen-address"].as<std::string>();
        listen_port = argm["port"].as<uint16_t>();
        listen_addr = parse_sockaddr(listen_ip.c_str());
        if (std::holds_alternative<std::monostate>(listen_addr))
            throw std::invalid_argument("invalid listen address");

        auto tun_cidr = argm["tunnel-address"].as<std::string>();
        std::vector<std::string> tun_cidr_parts;
        boost::split(tun_cidr_parts, tun_cidr, boost::is_any_of("/"));
        if (tun_cidr_parts.size() != 2)
            throw std::invalid_argument("invalid tunnel address");
        tun_prefix = static_cast<unsigned int>(strtoul(tun_cidr_parts[1].c_str(), nullptr, 10));
        tun_addr = parse_sockaddr(tun_cidr_parts[0].c_str());
        if (std::holds_alternative<sockaddr_in>(tun_addr)) {
            if (tun_prefix > 32)
                throw std::invalid_argument("invalid tunnel prefix");
        } else if (std::holds_alternative<sockaddr_in6>(tun_addr)) {
            if (tun_prefix > 128)
                throw std::invalid_argument("invalid tunnel prefix");
        } else {
            throw std::invalid_argument("invalid tunnel address");
        }
    } catch (const std::exception &ex) {
        fmt::print("{}\n", ex.what());
        fmt::print("{}\n", opts.help());
        return 1;
    }

    std::vector<std::unique_ptr<UdpServer>> server;
    if (auto sin = std::get_if<sockaddr_in>(&listen_addr)) {
        sin->sin_port = htons(listen_port);
        server.push_back(std::make_unique<UdpServer>(*sin));
    } else if (auto sin6 = std::get_if<sockaddr_in6>(&listen_addr)) {
        sin6->sin6_port = htons(listen_port);
        server.push_back(std::make_unique<UdpServer>(*sin6));
    } else {
        throw std::runtime_error("cannot get server address");
    }

    std::vector<std::unique_ptr<Tun>> tun;
    tun.push_back(std::make_unique<Tun>("wg%d"));
    tun[0]->fd().set_nonblock();
    if (auto tun_sin = std::get_if<sockaddr_in>(&tun_addr)) {
        tun[0]->set_address(*tun_sin, tun_prefix);
    } else if (auto tun_sin6 = std::get_if<sockaddr_in6>(&tun_addr)) {
        tun[0]->set_address6(*tun_sin6, tun_prefix);
    } else {
        throw std::runtime_error("cannot get tunnel address");
    }
    tun[0]->set_up(true);

    auto clients = std::make_unique<CdsHashtable<ClientEndpoint, Client>>(1024, 1024, 0, CDS_LFHT_AUTO_RESIZE, nullptr);

    maple_tree allowed_ips = MTREE_INIT("allowed_ips", MT_FLAGS_USE_RCU);

    auto njobs = argm["jobs"].as<int>();
    std::vector<std::jthread> workers;
    workers.emplace_back(
        worker_func,
        WorkerArg{
            .id = 0,
            .tun = tun[0].get(),
            .server = server[0].get(),
            .clients = clients.get(),
            .allowed_ips = &allowed_ips,
        });
    if (tun[0]->features() & IFF_MULTI_QUEUE) {
        for (int i = 1; i < njobs; i++) {
            tun.push_back(std::make_unique<Tun>(tun[0]->clone()));
            if (auto sin = std::get_if<sockaddr_in>(&listen_addr))
                server.push_back(std::make_unique<UdpServer>(*sin));
            else if (auto sin6 = std::get_if<sockaddr_in6>(&listen_addr))
                server.push_back(std::make_unique<UdpServer>(*sin6));
            workers.emplace_back(
                worker_func,
                WorkerArg{
                    .id = i,
                    .tun = tun[i].get(),
                    .server = server[i].get(),
                    .clients = clients.get(),
                    .allowed_ips = &allowed_ips,
                });
        }
    } else {
        fmt::print("IFF_MULTI_QUEUE not supported, not spawning more workers\n");
    }
}
