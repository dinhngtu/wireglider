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

Worker::Worker(const WorkerArg &arg) : _arg(arg), _recvbuf(65536 + sizeof(virtio_net_hdr)) {
    if (_arg.tun_is_v6) {
        // TODO
    }
    _overhead = calc_overhead(_arg.srv_is_v6);
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
        virtio_net_hdr vnethdr;
        std::vector<uint8_t> tunpkts;
        size_t segment_size, nr_segments;
        std::tie(segment_size, nr_segments) = do_tun_read(vnethdr, tunpkts, ev);
        if (!nr_segments)
            return;

        std::vector<uint8_t> crypted;
        size_t crypted_segment_size;
        ClientEndpoint ep;
        std::tie(crypted_segment_size, ep) = do_crypt_encap(crypted, vnethdr, tunpkts, segment_size, nr_segments);
        if (!crypted_segment_size)
            return;

        msghdr mh;
        memset(&mh, 0, sizeof(mh));
        if (auto sin6 = std::get_if<sockaddr_in6>(&ep)) {
            mh.msg_name = sin6;
            mh.msg_namelen = sizeof(sockaddr_in6);
        } else if (auto sin = std::get_if<sockaddr_in>(&ep)) {
            mh.msg_name = sin;
            mh.msg_namelen = sizeof(sockaddr_in);
        }
        iovec iov{crypted.data(), crypted.size()};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        std::array<uint8_t, CMSG_SPACE(sizeof(uint16_t))> _cm;
        auto cm = std::launder(reinterpret_cast<cmsghdr *>(_cm.data()));
        cm->cmsg_level = SOL_UDP;
        cm->cmsg_type = UDP_SEGMENT;
        cm->cmsg_len = _cm.size();
        *reinterpret_cast<uint16_t *>(CMSG_DATA(cm)) = crypted_segment_size;
        mh.msg_control = cm;
        mh.msg_controllen = _cm.size();

        if (sendmsg(_arg.server->fd(), &mh, 0) < 0)
            perror("sendmsg");
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
std::pair<size_t, size_t> Worker::do_tun_read(virtio_net_hdr &vnethdr, std::vector<uint8_t> &tunpkts, epoll_event *ev) {
    // don't use directly
    auto msize = read(_arg.tun->fd(), _recvbuf.data(), _recvbuf.size());
    if (msize < 0)
        return {};
    auto rest = std::span(_recvbuf).subspan(0, msize);

    if (rest.size() < sizeof(virtio_net_hdr))
        return {};
    vnethdr = *reinterpret_cast<virtio_net_hdr *>(rest.data());
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

    size_t nr_segments = round_up(rest.size(), vnethdr.gso_size);
    size_t segment_size = seghdr.size() + vnethdr.gso_size;
    tunpkts.resize(rest.size() + nr_segments * seghdr.size());

    size_t i = 0;
    for (; !rest.empty(); i++) {
        auto datalen = std::min(rest.size(), static_cast<size_t>(vnethdr.gso_size));
        assert(tunpkts.size() >= i * segment_size + seghdr.size() + datalen);
        std::span outbuf(&tunpkts[i * segment_size], seghdr.size() + datalen);
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
            auto ip = reinterpret_cast<struct ip *>(outbuf.data());
            if (i) {
                big_to_native_inplace(ip->ip_id);
                ip->ip_id += i;
                native_to_big_inplace(ip->ip_id);
            }
            ip->ip_len = outbuf.size();
            native_to_big_inplace(ip->ip_len);
            ip->ip_sum = checksum(std::span(outbuf).subspan(0, vnethdr.csum_start), 0);
            native_to_big_inplace(ip->ip_sum);
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

    return std::make_pair(segment_size, i);
}

std::pair<size_t, ClientEndpoint> Worker::do_crypt_encap(
    std::vector<uint8_t> &crypted,
    const virtio_net_hdr &vnethdr,
    const std::vector<uint8_t> &tunpkts,
    size_t segment_size,
    size_t nr_segments) {
    Client *client = nullptr;
    size_t crypted_segment_size = 0;

    if (tunpkts.empty())
        return {crypted_segment_size, {}};

    // be conservative
    crypted.resize(tunpkts.size() + _overhead * nr_segments);

    RundownGuard rcu;
    in_addr dstip4;
    in6_addr dstip6;
    if (_arg.tun_is_v6) {
        dstip6 = reinterpret_cast<const ip6_hdr *>(tunpkts.data())->ip6_dst;
        throw std::runtime_error("not implemented");
    } else {
        dstip4 = reinterpret_cast<const ip *>(tunpkts.data())->ip_dst;
        unsigned long ipkey = big_to_native(dstip4.s_addr);
        client = static_cast<Client *>(mtree_load(_arg.allowed_ips, ipkey));
    }

    if (!client)
        return {crypted_segment_size, {}};
    std::lock_guard<std::mutex> client_lock(client->mutex);

    std::span<const uint8_t> rest(tunpkts);
    std::span<uint8_t> remain(crypted);
    while (!rest.empty()) {
        auto datalen = std::min(rest.size(), segment_size);
        auto res = wireguard_write(client->tunnel, rest.data(), datalen, remain.data(), remain.size());
        if (res.op == WRITE_TO_NETWORK) {
            rest = rest.subspan(datalen);
            remain = remain.subspan(res.size);
            if (!crypted_segment_size)
                crypted_segment_size = res.size;
            else
                assert(rest.empty() || crypted_segment_size == res.size);
        }
    }
    crypted.resize(crypted.size() - remain.size());
    return {crypted_segment_size, client->_cds_lfht_key};
}

void Worker::do_server(epoll_event *ev) {
    if (ev->events & EPOLLIN) {
        msghdr mh;
        memset(&mh, 0, sizeof(mh));

        std::array<uint8_t, sizeof(sockaddr_in6)> _name;
        mh.msg_name = _name.data();
        mh.msg_namelen = _name.size();
        iovec iov{_recvbuf.data(), _recvbuf.size()};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        std::array<uint8_t, CMSG_LEN(sizeof(uint16_t))> _cm;
        mh.msg_control = _cm.data();
        mh.msg_controllen = _cm.size();

        if (recvmsg(_arg.server->fd(), &mh, 0) < 0) {
            perror("recvmsg");
            return;
        }

        size_t gro_size = 0;
        for (auto cm = std::launder(CMSG_FIRSTHDR(&mh)); cm; cm = CMSG_NXTHDR(&mh, cm)) {
            if (cm->cmsg_type == UDP_GRO) {
                gro_size = *reinterpret_cast<const uint16_t *>(CMSG_DATA(cm));
                break;
            }
        }

        if (!gro_size)
            gro_size = iov.iov_len;

        ClientEndpoint ep;
        if (std::launder(static_cast<sockaddr *>(mh.msg_name))->sa_family == AF_INET6) {
            assert(_arg.srv_is_v6);
            ep = *static_cast<sockaddr_in6 *>(mh.msg_name);
        } else {
            assert(!_arg.srv_is_v6);
            ep = *static_cast<sockaddr_in *>(mh.msg_name);
        }

        RundownGuard rcu;
        auto it = _arg.clients->find(rcu, ep);
        if (it == _arg.clients->end())
            return;

        std::lock_guard<std::mutex> client_lock(it->mutex);

        // TODO
    }
}

} // namespace wgss
