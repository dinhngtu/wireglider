#include <cstdio>
#include <array>
#include <utility>
#include <span>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fmt/format.h>
#include <boost/endian.hpp>
#include <tdutil/io.hpp>
#include <tdutil/util.hpp>

#include "worker.hpp"
#include "checksum.hpp"

using namespace tdutil;
using namespace boost::endian;

namespace wgss {

void worker_func(WorkerArg arg) {
    Worker w(arg);
    w.run();
}

Worker::Worker(const WorkerArg &arg) : _arg(arg) {
    if (_arg.tun_is_v6) {
        // TODO
    }
    _overhead = calc_overhead();
}

void Worker::run() {
    rcu_register_thread();

    // there are only 2 file descriptors to watch
    std::array<epoll_event, 2> evbuf;

    _poll.add(_arg.tun->fd(), EPOLLIN);
    _poll.add(_arg.server->fd(), EPOLLIN);

    while (1) {
        auto nevents = _poll.wait(evbuf, -1);
        if (nevents < 0)
            perror("poll error");
        for (int i = 0; i < nevents; i++) {
            if (evbuf[i].events) {
                if (evbuf[i].data.fd == _arg.tun->fd()) {
                    do_tun(&evbuf[i]);
                } else if (evbuf[i].data.fd == _arg.server->fd()) {
                    do_server(&evbuf[i]);
                }
            }
        }
        rcu_quiescent_state();
    }
}

void Worker::do_tun(epoll_event *ev) {
    if (ev->events & EPOLLIN) {
        std::vector<std::vector<uint8_t>> out;
        auto vnethdr = do_tun_read(out, ev);
        do_server_write(vnethdr, out);
    }
}

/*
 * Parsing logic adapted from wireguard-go:
 * https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/offload_linux.go#L901
 *
 * The received tun buffer looks like this:
 * ╔════════════════════ virtio_net_hdr ════════════════════╦═════ iphdr ══════╦═════ l4hdr ═════╦═══════════════════╗
 * ║ flags gso_type hdr_len gso_size csum_start csum_offset ║ ... iph_csum ... ║ ... l4_csum ... ║ giant payload ... ║
 * ╚═════════════════════│═════│═════════│═══════════│══════╩══════════════════╩═════════════════╩═══════════════════╝
 *                    ┌──│─────│─────────┘           │      └──────────── == sizeof ─────────────┘
 *                    │  │  ┌──│─────────────────────┘                        ↑
 *                    │  │  │  └───────────────┐                              │
 *                    │  └──│──────────────────│──────────────────────────────┘
 *                    ├─ + →┤                  ↓
 *                    ↓     │            ┌─ >= sizeof ──┐
 * ╔══════════════════╦═════↓════════════╦══════════════╗
 * ║ ... iph_csum ... ║ ... │l4_csum ... ║ payload part ║
 * ╚════════↑═════════╩═════════↑════════╩══════════════╝
 * │        │    Check│sums  to │ calculate             │
 * └→───────┴────────←┤         │                       │
 *                    └→─ (+pseudoheader if needed) ───←┘
 * GSO processing results in multiple split IP packets...
 * │ ... iph_csum ... │ ...  l4_csum ... │ payload part │
 * │ ... iph_csum ... │ ...  l4_csum ... │ payload part │
 *   ...
 */
virtio_net_hdr Worker::do_tun_read(std::vector<std::vector<uint8_t>> &out, epoll_event *ev) {
    // don't use directly
    static std::vector<uint8_t> _recvbuf(65536 + sizeof(virtio_net_hdr));
    auto msize = read(_arg.tun->fd(), _recvbuf.data(), _recvbuf.size());
    if (msize < 0)
        return {};
    auto rest = std::span(_recvbuf).subspan(0, msize);

    if (rest.size() < sizeof(virtio_net_hdr))
        return {};
    auto vnethdr = *reinterpret_cast<virtio_net_hdr *>(rest.data());
    rest = rest.subspan(sizeof(virtio_net_hdr));
    // rest now contains iphdr+l4hdr+giant payload

    // clear ipv4 header checksum
    if (!_arg.tun_is_v6)
        reinterpret_cast<iphdr *>(rest.data())->check = 0;
    // clear tcp/udp checksum
    auto l4_csum_offset = vnethdr.csum_start + vnethdr.csum_offset;
    convert_span<uint16_t>(rest.subspan(l4_csum_offset, sizeof(uint16_t)))[0] = 0;

    bool istcp = vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4 || vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6;
    uint32_t tcpseq0;
    if (istcp)
        tcpseq0 = big_to_native(reinterpret_cast<tcphdr *>(&rest[vnethdr.csum_start])->seq);

    auto seghdr = rest.subspan(0, vnethdr.hdr_len);
    rest = rest.subspan(vnethdr.hdr_len);
    // rest now only contains the giant payload

    size_t i = 0;
    for (; !rest.empty(); i++) {
        auto datalen = std::min(rest.size(), static_cast<size_t>(vnethdr.gso_size));
        auto &_outbuf = out.emplace_back(seghdr.size() + datalen + _overhead);
        std::span outbuf(_outbuf.begin(), seghdr.size() + datalen);
        std::copy(seghdr.begin(), seghdr.end(), outbuf.begin());
        std::copy(&rest[0], &rest[datalen], &outbuf[seghdr.size()]);

        if (_arg.tun_is_v6) {
            // For IPv6 we are responsible for updating the payload length field.
            auto &payload_len = reinterpret_cast<ipv6hdr *>(outbuf.data())->payload_len;
            payload_len = outbuf.size() - vnethdr.csum_start;
            native_to_big_inplace(payload_len);
        } else {
            // For IPv4 we are responsible for incrementing the ID field,
            // updating the total len field, and recalculating the header
            // checksum.
            auto ip = reinterpret_cast<iphdr *>(outbuf.data());
            if (i) {
                big_to_native_inplace(ip->id);
                ip->id += i;
                native_to_big_inplace(ip->id);
            }
            ip->tot_len = outbuf.size();
            native_to_big_inplace(ip->tot_len);
            ip->check = checksum(std::span(outbuf).subspan(0, vnethdr.csum_start), 0);
            native_to_big_inplace(ip->check);
        }

        if (istcp) {
            // set TCP seq and adjust TCP flags
            auto tcp = reinterpret_cast<tcphdr *>(&outbuf[vnethdr.csum_start]);
            auto &tcpseq = tcp->seq;
            tcpseq = tcpseq0 + static_cast<uint32_t>(vnethdr.gso_size) * i;
            native_to_big_inplace(tcpseq);
            if (datalen < rest.size())
                // FIN and PSH should only be set on last segment
                tcp->fin = tcp->psh = 0;
        } else {
            // set UDP header len
            auto udp = reinterpret_cast<udphdr *>(&outbuf[vnethdr.csum_start]);
            udp->len = seghdr.size() - vnethdr.csum_start;
            native_to_big_inplace(udp->len);
        }

        uint64_t l4_csum_tmp;
        if (_arg.tun_is_v6) {
            const auto addroff = offsetof(ip6_hdr, ip6_src);
            const auto addrsize = sizeof(in6_addr);
            auto srcaddr = outbuf.subspan<addroff, addrsize>();
            auto dstaddr = outbuf.subspan<addroff + addrsize, addrsize>();
            l4_csum_tmp = pseudo_header_checksum(istcp ? IPPROTO_TCP : IPPROTO_UDP, srcaddr, dstaddr, outbuf.size());
        } else {
            const auto addroff = offsetof(ip, ip_src);
            const auto addrsize = sizeof(in_addr);
            auto srcaddr = outbuf.subspan<addroff, addrsize>();
            auto dstaddr = outbuf.subspan<addroff + addrsize, addrsize>();
            l4_csum_tmp = pseudo_header_checksum(istcp ? IPPROTO_TCP : IPPROTO_UDP, srcaddr, dstaddr, outbuf.size());
        }
        auto l4_csum = checksum(outbuf.subspan(vnethdr.csum_start), l4_csum_tmp);
        store_big_u16(&outbuf[l4_csum_offset], l4_csum);

        // to next packet
        rest = rest.subspan(datalen);
    }

    return vnethdr;
}

void Worker::do_server_write(const virtio_net_hdr &vnethdr, std::vector<std::vector<uint8_t>> &out) {
    sockaddr_in caddr4;
    sockaddr_in6 caddr6;
    Client *client = nullptr;
    bool first = true;
    std::unique_lock<std::mutex> client_lock;

    if (out.empty())
        return;

    /*
    std::vector<uint8_t> encbuf(vnethdr.hdr_len + vnethdr.gso_size + _overhead);
    for (auto &pkt : out) {
        auto res = wireguard_write(client->tunnel, pkt.data(), pkt.size() - _overhead, encbuf.data(), encbuf.size());
        if (res.op == WRITE_TO_NETWORK) {
            room = room.subspan(res.size);
        }
    }
     */

    RundownGuard rcu;


    if (_arg.srv_is_v6) {
        _arg.clients->find(rcu, caddr6);
    } else {
        _arg.clients->find(rcu, caddr4);
    }

    //_arg.clients->find(rcu, )

    // TODO
    /*
    if (first) {
        _clients.visit(addr, [&client](Client &pc) { client = &pc; });
        if (!client)
            continue;
        client_lock = std::unique_lock<std::mutex>(client->mutex);
    }

    assert(client_lock);
    auto res = wireguard_write(client->tunnel, rest.data(), pktlen, room.data(), room.size());
    if (res.op == WRITE_TO_NETWORK) {
        room = room.subspan(res.size);
    }
    */
}

void Worker::do_server(epoll_event *ev) {
}

} // namespace wgss
