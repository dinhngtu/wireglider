#include <vector>
#include <thread>
#include <memory>
#include <string>
#include <stdexcept>
#include <system_error>
#include <cxxopts.hpp>
#include <fmt/format.h>

#include "wireglider.hpp"
#include "tun.hpp"
#include "udpsock.hpp"
#include "worker.hpp"
#include "netutil.hpp"
#include "maple_tree.hpp"
#include "control.hpp"
#include "unix.hpp"
#include "timer.hpp"

/*
 * schema:
 * - open tun -> get tun fd. tun if is the *user and applications* side
 * - bind udp socket to ep -> get udp fd. ep socket is the *encrypted traffic* side
 * - read tun -> encap -> write udp
 * - read udp -> decap -> write tun
 */

using namespace wireglider;
using namespace tdutil;

static cxxopts::Options make_options() {
    cxxopts::Options opt{"wireglider"};
    auto g = opt.add_options();
    g("a,listen-address", "listen ip:port or [ip6]:port", cxxopts::value<std::string>());
    g("A,tunnel-address", "tunnel CIDR", cxxopts::value<std::string>());
    g("j,jobs", "thread count", cxxopts::value<unsigned int>()->default_value("1"));
    g("J,timer-jobs", "timer thread count", cxxopts::value<unsigned int>()->default_value("1"));
    g("X,control-path",
      "control socket path, with %s for interface name",
      cxxopts::value<std::string>()->default_value("/run/wireguard/%s.sock"));
    opt.parse_positional({"interface-name"});
    return opt;
}

struct Args {
    std::variant<std::monostate, sockaddr_in, sockaddr_in6> listen_addr;
    uint16_t listen_port;
    std::variant<std::monostate, std::pair<in_addr, unsigned int>, std::pair<in6_addr, unsigned int>> tun_cidr;
    std::string control_path;
    unsigned int njobs;
    unsigned int ntimers;
};

static void doit(Args &args) {
    sigset_t sigs, oldsigs;
    make_exit_sigset(sigs);
    if (pthread_sigmask(SIG_BLOCK, &sigs, &oldsigs) < 0)
        throw std::system_error(errno, std::system_category(), "pthread_sigmask(sigs)");

    std::vector<std::unique_ptr<UdpServer>> server;
    if (auto sin = std::get_if<sockaddr_in>(&args.listen_addr)) {
        sin->sin_port = htons(args.listen_port);
        server.push_back(std::make_unique<UdpServer>(*sin));
    } else if (auto sin6 = std::get_if<sockaddr_in6>(&args.listen_addr)) {
        sin6->sin6_port = htons(args.listen_port);
        server.push_back(std::make_unique<UdpServer>(*sin6));
    } else {
        throw std::runtime_error("cannot get server address");
    }

    std::vector<std::unique_ptr<Tun>> tun;
    tun.push_back(std::make_unique<Tun>("wg%d"));
    std::string tunname = tun[0]->name();
    tun[0]->fd().set_nonblock();
    if (auto tun4 = std::get_if<std::pair<in_addr, unsigned int>>(&args.tun_cidr)) {
        tun[0]->set_address(tun4->first, tun4->second);
    } else if (auto tun6 = std::get_if<std::pair<in6_addr, unsigned int>>(&args.tun_cidr)) {
        tun[0]->set_address6(tun6->first, tun6->second);
    } else {
        throw std::runtime_error("cannot get tunnel address");
    }
    tun[0]->set_up(true);

    ClientTable clients(1024, 1024, 0, CDS_LFHT_AUTO_RESIZE, nullptr);
    EndpointTable client_eps(1024, 1024, 0, CDS_LFHT_AUTO_RESIZE, nullptr);
    maple_tree allowed_ips = MTREE_INIT("allowed_ips", MT_FLAGS_USE_RCU);

    std::vector<std::jthread> timers;
    for (unsigned int i = 0; i < args.ntimers; i++) {
        timers.emplace_back(
            timer_func,
            TimerArg{
                .id = i,
                .clients = &clients,
            });
    }

    std::vector<std::jthread> workers;
    workers.emplace_back(
        worker_func,
        WorkerArg{
            .id = 0,
            .tun = tun[0].get(),
            .server = server[0].get(),
            .clients = &clients,
            .client_eps = &client_eps,
            .allowed_ips = &allowed_ips,
        });
    if (tun[0]->features() & IFF_MULTI_QUEUE) {
        for (unsigned int i = 1; i < args.njobs; i++) {
            tun.push_back(std::make_unique<Tun>(tun[0]->clone()));
            if (auto sin = std::get_if<sockaddr_in>(&args.listen_addr))
                server.push_back(std::make_unique<UdpServer>(*sin));
            else if (auto sin6 = std::get_if<sockaddr_in6>(&args.listen_addr))
                server.push_back(std::make_unique<UdpServer>(*sin6));
            workers.emplace_back(
                worker_func,
                WorkerArg{
                    .id = i,
                    .tun = tun[i].get(),
                    .server = server[i].get(),
                    .clients = &clients,
                    .client_eps = &client_eps,
                    .allowed_ips = &allowed_ips,
                });
        }
    } else {
        fmt::print("IFF_MULTI_QUEUE not supported, not spawning more workers\n");
    }

    size_t pct = args.control_path.find("%s");
    if (pct != std::string::npos)
        args.control_path = args.control_path.replace(pct, 2, tunname);
    auto unx = std::make_unique<UnixServer>(args.control_path);
    unx->fd().set_nonblock();

    std::jthread control(
        control_func,
        ControlArg{
            args.ntimers,
            unx.get(),
            &clients,
            &client_eps,
            &allowed_ips,
        });
}

int main(int argc, char **argv) {
    Args args;

    auto opts = make_options();
    cxxopts::ParseResult argm;
    try {
        argm = opts.parse(argc, argv);

        auto listen_ipport = argm["listen-address"].as<std::string>();
        args.listen_addr = parse_ipport(listen_ipport.c_str());
        if (std::holds_alternative<std::monostate>(args.listen_addr))
            throw std::invalid_argument("invalid listen address");

        auto tun_cidr = argm["tunnel-address"].as<std::string>();
        args.tun_cidr = parse_iprange(tun_cidr.c_str());
        if (std::holds_alternative<std::monostate>(args.tun_cidr))
            throw std::invalid_argument("invalid tunnel address");

        if (argm.count("control-path"))
            args.control_path = argm["control-path"].as<std::string>();
        args.njobs = argm["jobs"].as<unsigned int>();
        args.ntimers = argm["timer-jobs"].as<unsigned int>();
    } catch (const std::exception &ex) {
        fmt::print("{}\n", ex.what());
        fmt::print("{}\n", opts.help());
        return 1;
    }

    doit(args);
    return 0;
}
