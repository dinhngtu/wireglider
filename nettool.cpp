#include <vector>
#include <variant>
#include <stdexcept>
#include <system_error>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cxxopts.hpp>
#include <fmt/format.h>

#include "netutil.hpp"
#include "udpsock.hpp"

using namespace tdutil;
using namespace wireglider;

static cxxopts::Options make_options() {
    cxxopts::Options opt{"wireglider"};
    auto g = opt.add_options();
    g("a,address", "ip:port or [ip6]:port", cxxopts::value<std::string>());
    g("n,count", "packet count", cxxopts::value<size_t>()->default_value("1"));
    g("r,rate", "SO_MAX_PACING_RATE", cxxopts::value<int>()->default_value("0"));
    g("batch", "send batch size", cxxopts::value<int>()->default_value("32"));
    g("batchsleep", "sleep ms per batch", cxxopts::value<long>()->default_value("0"));
    g("s,pktsize", "send packet size", cxxopts::value<size_t>()->default_value("64"));
    g("recv-timeout", "receive timeout in ms", cxxopts::value<long>()->default_value("2000"));
    return opt;
}

struct Args {
    std::variant<std::monostate, sockaddr_in, sockaddr_in6> addr;
    size_t count;
    int rate;
    int batch;
    long batchsleep;
    size_t pktsize;
    long recv_timeout;
};

static void doit(Args &args) {
    UdpServer udp;
    auto sending = true;
    void *sin = nullptr;
    socklen_t slen = 0;
    if ((sin = std::get_if<sockaddr_in>(&args.addr))) {
        slen = sizeof(sockaddr_in);
    } else if ((sin = std::get_if<sockaddr_in6>(&args.addr))) {
        slen = sizeof(sockaddr_in6);
    } else {
        sending = false;
        sockaddr_in sin_listen{
            .sin_family = AF_INET,
            .sin_port = htons(61666),
            .sin_addr = INADDR_ANY,
            .sin_zero = {0},
        };
        udp = UdpServer(sin_listen, false, false);
    }

    /*
    if (!sending) {
        sigset_t maskint;
        sigemptyset(&maskint);
        struct sigaction actint;
        actint.sa_handler = SIG_IGN;
        actint.sa_mask = maskint;
        actint.sa_flags = 0;
        actint.sa_restorer = nullptr;
        if (sigaction(SIGINT, &actint, nullptr) < 0)
            throw std::system_error(errno, std::system_category(), "sigaction");
    }
     */

    ssize_t pkts = 0;
    ssize_t totbytes = 0;
    if (sending) {
        std::vector<uint8_t> buf(args.pktsize);
        std::vector<iovec> iovs;
        iovs.reserve(args.batch);
        std::vector<mmsghdr> mhs;
        mhs.reserve(args.batch);
        for (int i = 0; i < args.batch; i++) {
            auto &iov = iovs.emplace_back(iovec{buf.data(), buf.size()});
            mhs.push_back({
                {
                    .msg_name = sin,
                    .msg_namelen = slen,
                    .msg_iov = &iov,
                    .msg_iovlen = 1,
                    .msg_control = nullptr,
                    .msg_controllen = 0,
                    .msg_flags = 0,
                },
                0,
            });
        }

        if (args.rate > 0) {
            if (setsockopt(udp.fd(), SOL_SOCKET, SO_MAX_PACING_RATE, &args.rate, sizeof(args.rate)) < 0)
                throw std::system_error(errno, std::system_category(), "setsockopt");
        }

        while (std::cmp_less(pkts, args.count)) {
            auto sent = sendmmsg(udp.fd(), mhs.data(), mhs.size(), 0);
            if (sent < 0)
                throw std::system_error(errno, std::system_category(), "sendto");
            pkts += sent;
            for (ssize_t i = 0; i < sent; i++)
                totbytes += mhs[i].msg_len;
            if (args.batchsleep > 0) {
                auto sleepns = 1000000l * args.batchsleep;
                timespec sleepspec{sleepns / 1000000000, sleepns % 1000000000};
                nanosleep(&sleepspec, nullptr);
            }
        }

    } else {
        std::vector<uint8_t> buf(64 * 4096);
        std::vector<iovec> iovs;
        iovs.reserve(64);
        std::vector<mmsghdr> mhs;
        mhs.reserve(64);
        for (int i = 0; i < 64; i++) {
            auto &iov = iovs.emplace_back(iovec{&buf[i * 4096], 4096});
            mhs.push_back({
                {
                    .msg_name = nullptr,
                    .msg_namelen = 0,
                    .msg_iov = &iov,
                    .msg_iovlen = 1,
                    .msg_control = nullptr,
                    .msg_controllen = 0,
                    .msg_flags = 0,
                },
                0,
            });
        }

        pollfd p{udp.fd(), POLLIN, 0};
        poll(&p, 1, -1);

        long to_ns = 1000000l * args.recv_timeout;
        timeval tv{to_ns / 1000000000, to_ns % 1000000000};
        timespec ts{to_ns / 1000000000, to_ns % 1000000000};
        if (setsockopt(udp.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            throw std::system_error(errno, std::system_category(), "recv");
        while (1) {
            auto received = recvmmsg(udp.fd(), mhs.data(), mhs.size(), 0, &ts);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    break;
                else
                    throw std::system_error(errno, std::system_category(), "recv");
            }
            pkts += received;
            for (ssize_t i = 0; i < received; i++)
                totbytes += mhs[i].msg_len;
        }
    }

    fmt::print("{} {} packets {} bytes\n", sending ? "sent" : "received", pkts, totbytes);
}

int main(int argc, char **argv) {
    Args args{};

    auto opts = make_options();
    cxxopts::ParseResult argm;
    try {
        argm = opts.parse(argc, argv);

        if (argm.count("address")) {
            auto ipport = argm["address"].as<std::string>();
            args.addr = parse_ipport(ipport.c_str());
            if (std::holds_alternative<std::monostate>(args.addr))
                throw std::invalid_argument("invalid target address");
        }
        args.count = argm["count"].as<decltype(args.count)>();
        args.rate = argm["rate"].as<decltype(args.rate)>();
        args.batch = argm["batch"].as<decltype(args.batch)>();
        if (args.batch <= 0)
            throw std::invalid_argument("invalid batch size");
        args.batchsleep = argm["batchsleep"].as<decltype(args.batchsleep)>();
        args.pktsize = argm["pktsize"].as<decltype(args.pktsize)>();
        args.recv_timeout = argm["recv-timeout"].as<decltype(args.recv_timeout)>();

    } catch (const std::exception &ex) {
        fmt::print("{}\n", ex.what());
        fmt::print("{}\n", opts.help());
        return 1;
    }

    doit(args);
    return 0;
}
