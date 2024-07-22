#include <vector>
#include <thread>
#include <memory>
#include <string>
#include <stdexcept>
#include <system_error>
#include <cxxopts.hpp>
#include <fmt/format.h>
#include <tdutil/util.hpp>

#include "keys.hpp"
#include "wireglider.hpp"
#include "tun.hpp"
#include "udpsock.hpp"
#include "worker.hpp"
#include "netutil.hpp"
#include "liblinux/maple_tree.hpp"
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
    g("k,private-key", "server x25519 private key", cxxopts::value<std::string>());
    g("X,control-path",
      "control socket path, with %s for interface name",
      cxxopts::value<std::string>()->default_value("/run/wireguard/%s.sock"));
    g("M,mtu", "tun mtu", cxxopts::value<int>()->default_value("1420"));
    opt.parse_positional({"interface-name"});
    return opt;
}

struct Args {
    std::variant<std::monostate, sockaddr_in, sockaddr_in6> listen_addr;
    std::variant<std::monostate, IpRange4, IpRange6> tun_cidr;
    unsigned int njobs;
    unsigned int ntimers;
    std::string private_key;
    std::string control_path;
    int mtu;
    std::string iface_name;
};

static Config *make_config(const Args &args) {
    NetPrefix4 prefix4;
    NetPrefix6 prefix6;
    if (auto tun4 = std::get_if<IpRange4>(&args.tun_cidr))
        prefix4 = NetPrefix4(tun4->first, tun4->second);
    else if (auto tun6 = std::get_if<IpRange6>(&args.tun_cidr))
        prefix6 = NetPrefix6(tun6->first, tun6->second);
    auto cfg = new Config();
    cfg->prefix4 = prefix4;
    cfg->prefix6 = prefix6;
    if (!parse_keybytes(cfg->privkey.key, args.private_key.c_str()))
        throw std::invalid_argument("invalid server private key");
    return cfg;
}

static void doit(Args &args) {
    sigset_t sigs, oldsigs;
    make_exit_sigset(sigs);
    auto err = pthread_sigmask(SIG_BLOCK, &sigs, &oldsigs);
    if (err)
        throw std::system_error(err, std::system_category(), "pthread_sigmask(sigs)");

    alignas(ConfigRef::required_alignment) Config *config = make_config(args);

    boost::container::stable_vector<UdpServer> server;
    if (auto sin = std::get_if<sockaddr_in>(&args.listen_addr))
        server.emplace_back(*sin, true, true);
    else if (auto sin6 = std::get_if<sockaddr_in6>(&args.listen_addr))
        server.emplace_back(*sin6, true, true);
    else
        throw std::runtime_error("cannot get server address");

    boost::container::stable_vector<Tun> tun;
    tun.emplace_back(args.iface_name.c_str());
    std::string tunname = tun[0].name();
    tun[0].fd().set_nonblock(true);
    if (auto tun4 = std::get_if<IpRange4>(&args.tun_cidr)) {
        tun[0].set_address(tun4->first, tun4->second);
    } else if (auto tun6 = std::get_if<IpRange6>(&args.tun_cidr)) {
        tun[0].set_address6(tun6->first, tun6->second);
    } else {
        throw std::runtime_error("cannot get tunnel address");
    }
    bool has_uso = tun[0].set_offloads();
    if (has_uso)
        fmt::print("TUN USO enabled on {}\n", tunname);
    else
        fmt::print("TUN USO is not available on {}\n", tunname);
    tun[0].set_mtu(args.mtu);
    tun[0].set_up(true);

    ClientTable clients(1024, 1024, 0, CDS_LFHT_AUTO_RESIZE, nullptr);
    EndpointTable client_eps(1024, 1024, 0, CDS_LFHT_AUTO_RESIZE, nullptr);
    maple_tree allowed_ip4 = MTREE_INIT(allowed_ip4, MT_FLAGS_USE_RCU);
    maple_tree allowed_ip6 = MTREE_INIT(allowed_ip6, MT_FLAGS_USE_RCU);

    std::vector<std::jthread> workers;
    workers.emplace_back(
        worker_func,
        WorkerArg{
            .id = 0,
            .tun_has_uso = has_uso,
            .tun = &tun[0],
            .server = &server[0],
            ._config = ConfigRef(config),
            .clients = &clients,
            .client_eps = &client_eps,
            .allowed_ip4 = &allowed_ip4,
            .allowed_ip6 = &allowed_ip6,
        });
    if (tun[0].features() & IFF_MULTI_QUEUE) {
        for (unsigned int i = 1; i < args.njobs; i++) {
            tun.emplace_back(tun[0].clone()).fd().set_nonblock(true);
            if (auto sin = std::get_if<sockaddr_in>(&args.listen_addr))
                server.emplace_back(*sin, true, true);
            else if (auto sin6 = std::get_if<sockaddr_in6>(&args.listen_addr))
                server.emplace_back(*sin6, true, true);
            workers.emplace_back(
                worker_func,
                WorkerArg{
                    .id = i,
                    .tun_has_uso = has_uso,
                    .tun = &tun[i],
                    .server = &server[i],
                    ._config = ConfigRef(config),
                    .clients = &clients,
                    .client_eps = &client_eps,
                    .allowed_ip4 = &allowed_ip4,
                    .allowed_ip6 = &allowed_ip6,
                });
        }
    } else {
        fmt::print("IFF_MULTI_QUEUE not supported, not spawning more workers\n");
    }

    std::vector<std::jthread> timers;
    boost::container::stable_vector<timer_impl::TimerQueue> timerq;
    for (unsigned int i = 0; i < args.ntimers; i++) {
        timerq.emplace_back();
        // We only send packets in timer threads, so we're not affected by offloads.
        // However the nonblocking status is inherited.
        timers.emplace_back(
            timer_func,
            TimerArg{
                .id = i,
                .clients = &clients,
                .queue = &timerq[i],
                .server = &server[i % server.size()],
            });
    }

    size_t pct = args.control_path.find("%s");
    if (pct != std::string::npos)
        args.control_path = args.control_path.replace(pct, 2, tunname);
    auto unx = std::make_unique<UnixServer>(args.control_path);
    unx->fd().set_nonblock(true);

    std::jthread control(
        control_func,
        ControlArg{
            ._config = ConfigRef(config),
            .unx = unx.get(),
            .clients = &clients,
            .client_eps = &client_eps,
            .allowed_ip4 = &allowed_ip4,
            .allowed_ip6 = &allowed_ip6,
            .timerq = &timerq,
        });
}

int main(int argc, char **argv) {
    Args args{};

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

        args.njobs = argm["jobs"].as<unsigned int>();
        args.ntimers = argm["timer-jobs"].as<unsigned int>();
        args.private_key = argm["private-key"].as<std::string>();
        args.control_path = argm["control-path"].as<std::string>();
        args.mtu = argm["mtu"].as<int>();
        if (argm.count("interface-name"))
            args.iface_name = argm["interface-name"].as<std::string>();
        else
            args.iface_name = "wg%d";
    } catch (const std::exception &ex) {
        fmt::print("{}\n", ex.what());
        fmt::print("{}\n", opts.help());
        return 1;
    }

    doit(args);
    return 0;
}
