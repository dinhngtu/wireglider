#include <array>
#include <utility>
#include <span>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <tdutil/util.hpp>

#include "worker.hpp"
#include "checksum.hpp"

using namespace boost::endian;
using namespace tdutil;
using namespace wgss::worker_impl;

namespace wgss {

void Worker::do_tun(epoll_event *ev) {
    if (ev->events & EPOLLIN) {
        virtio_net_hdr vnethdr;
        auto read_pb = do_tun_recv(_recvbuf, vnethdr);
        if (!read_pb)
            return;

        auto tun_pb = do_tun_gso_split(read_pb.value(), _pktbuf, vnethdr);

        auto crypt = do_tun_encap(tun_pb, _sendbuf);
        if (!crypt)
            return;

        auto ret = do_server_send(crypt->first.data, crypt->first.segment_size, crypt->second, true);
        if (ret < 0 && !is_eagain(-ret))
            fmt::print("do_server_send: {}\n", strerrordesc_np(ret));
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
std::optional<PacketBatch> Worker::do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr) {
    // if (outbuf.size() < 65536 + sizeof(virtio_net_hdr))
    // outbuf.resize(65536 + sizeof(virtio_net_hdr));
    assert(outbuf.size() >= 65536 + sizeof(virtio_net_hdr));

    // don't use directly
    auto msize = read(_arg.tun->fd(), outbuf.data(), outbuf.size());
    if (msize < 0)
        return std::nullopt;
    auto rest = std::span(outbuf.begin(), msize);

    if (rest.size() < sizeof(virtio_net_hdr))
        return std::nullopt;
    vnethdr = *reinterpret_cast<virtio_net_hdr *>(rest.data());
    rest = rest.subspan(sizeof(virtio_net_hdr));
    // rest now contains iphdr+l4hdr+giant payload

    return PacketBatch{
        .prefix = rest.subspan(0, vnethdr.hdr_len),
        .data = rest.subspan(vnethdr.hdr_len),
        .segment_size = vnethdr.gso_size,
    };
}

PacketBatch Worker::do_tun_gso_split(PacketBatch &pb, std::vector<uint8_t> &outbuf, const virtio_net_hdr &vnethdr) {
    if (vnethdr.gso_type == VIRTIO_NET_HDR_GSO_NONE || !pb.segment_size)
        pb.segment_size = pb.data.size();

    [[maybe_unused]] auto reserve_size = pb.data.size() + pb.nr_segments() * pb.prefix.size();
    // if (outbuf.size() < reserve_size)
    // outbuf.resize(reserve_size);
    assert(outbuf.size() >= reserve_size);
    auto rest = pb.data;

    // clear ipv4 header checksum
    if (!_arg.tun_is_v6)
        reinterpret_cast<ip *>(pb.prefix.data())->ip_sum = 0;
    // clear tcp/udp checksum
    auto l4_csum_offset = vnethdr.csum_start + vnethdr.csum_offset;
    store_big_u16(&pb.prefix[l4_csum_offset], 0);

    bool istcp = vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4 || vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6;
    uint32_t tcpseq0 = 0;
    if (istcp)
        tcpseq0 = big_to_native(reinterpret_cast<tcphdr *>(&rest[vnethdr.csum_start])->seq);

    size_t i = 0, pbsize = 0;
    for (; !rest.empty(); i++) {
        auto datalen = std::min(rest.size(), pb.segment_size);
        auto pktlen = pb.prefix.size() + datalen;
        auto outbuf_begin = pbsize;
        pbsize += pktlen;
        assert(outbuf.size() >= pbsize);
        std::span thispkt(&outbuf[outbuf_begin], &outbuf[pbsize]);

        std::copy(pb.prefix.begin(), pb.prefix.end(), thispkt.begin());
        std::copy(&rest[0], &rest[datalen], &thispkt[pb.prefix.size()]);

        if (_arg.tun_is_v6) {
            // For IPv6 we are responsible for updating the payload length field.
            auto &payload_len = reinterpret_cast<ipv6hdr *>(thispkt.data())->payload_len;
            payload_len = thispkt.size() - vnethdr.csum_start;
            native_to_big_inplace(payload_len);
        } else {
            // For IPv4 we are responsible for incrementing the ID field,
            // updating the total len field, and recalculating the header
            // checksum.
            auto ip = reinterpret_cast<struct ip *>(thispkt.data());
            if (i) {
                big_to_native_inplace(ip->ip_id);
                ip->ip_id += i;
                native_to_big_inplace(ip->ip_id);
            }
            ip->ip_len = thispkt.size();
            native_to_big_inplace(ip->ip_len);
            ip->ip_sum = checksum(thispkt.subspan(0, vnethdr.csum_start), 0);
            native_to_big_inplace(ip->ip_sum);
        }

        if (istcp) {
            // set TCP seq and adjust TCP flags
            auto tcp = reinterpret_cast<tcphdr *>(&thispkt[vnethdr.csum_start]);
            auto &tcpseq = tcp->seq;
            tcpseq = tcpseq0 + static_cast<uint32_t>(pb.segment_size) * i;
            native_to_big_inplace(tcpseq);
            if (datalen < rest.size())
                // FIN and PSH should only be set on last segment
                tcp->fin = tcp->psh = 0;
        } else {
            // set UDP header len
            auto udp = reinterpret_cast<udphdr *>(&thispkt[vnethdr.csum_start]);
            udp->len = pb.prefix.size() - vnethdr.csum_start;
            native_to_big_inplace(udp->len);
        }

        uint64_t l4_csum_tmp;
        if (_arg.tun_is_v6) {
            const auto addroff = offsetof(ip6_hdr, ip6_src);
            const auto addrsize = sizeof(in6_addr);
            std::span<const uint8_t, addrsize> srcaddr = thispkt.subspan<addroff, addrsize>();
            std::span<const uint8_t, addrsize> dstaddr = thispkt.subspan<addroff + addrsize, addrsize>();
            l4_csum_tmp = pseudo_header_checksum(istcp ? IPPROTO_TCP : IPPROTO_UDP, srcaddr, dstaddr, thispkt.size());
        } else {
            const auto addroff = offsetof(ip, ip_src);
            const auto addrsize = sizeof(in_addr);
            std::span<const uint8_t, addrsize> srcaddr = thispkt.subspan<addroff, addrsize>();
            std::span<const uint8_t, addrsize> dstaddr = thispkt.subspan<addroff + addrsize, addrsize>();
            l4_csum_tmp = pseudo_header_checksum(istcp ? IPPROTO_TCP : IPPROTO_UDP, srcaddr, dstaddr, thispkt.size());
        }
        auto l4_csum = checksum(thispkt.subspan(vnethdr.csum_start), l4_csum_tmp);
        store_big_u16(&thispkt[l4_csum_offset], l4_csum);

        // to next packet
        rest = rest.subspan(datalen);
    }

    return PacketBatch{
        .prefix = {},
        .data = std::span(outbuf.begin(), pbsize),
        .segment_size = pb.prefix.size() + pb.segment_size,
    };
}

std::optional<std::pair<PacketBatch, ClientEndpoint>> Worker::do_tun_encap(
    PacketBatch &pb,
    std::vector<uint8_t> &outbuf) {
    Client *client = nullptr;

    // be conservative
    [[maybe_unused]] auto reserve_size = pb.data.size() + _overhead * pb.nr_segments();
    // if (outbuf.size() < reserve_size)
    // outbuf.resize(reserve_size);
    assert(outbuf.size() >= reserve_size);

    RundownGuard rcu;
    in_addr dstip4;
    in6_addr dstip6;
    if (_arg.tun_is_v6) {
        dstip6 = reinterpret_cast<const ip6_hdr *>(pb.data.data())->ip6_dst;
        throw std::runtime_error("not implemented");
    } else {
        dstip4 = reinterpret_cast<const ip *>(pb.data.data())->ip_dst;
        unsigned long ipkey = big_to_native(dstip4.s_addr);
        client = static_cast<Client *>(mtree_load(_arg.allowed_ips, ipkey));
    }

    if (!client)
        return std::nullopt;
    std::lock_guard<std::mutex> client_lock(client->mutex);

    std::span<const uint8_t> rest(pb.data);
    std::span<uint8_t> remain(outbuf);
    size_t i = 0, crypted_segment_size = 0;
    for (; !rest.empty(); i++) {
        auto datalen = std::min(rest.size(), pb.segment_size);
        auto res = wireguard_write_raw(client->tunnel, rest.data(), datalen, remain.data(), remain.size());
        rest = rest.subspan(datalen);
        if (res.op == WRITE_TO_NETWORK) {
            remain = remain.subspan(res.size);
            if (!crypted_segment_size)
                crypted_segment_size = res.size;
            else
                assert(rest.empty() || crypted_segment_size == res.size);
        }
    }
    PacketBatch newpb{
        .prefix = {},
        .data = std::span(outbuf.data(), outbuf.size() - remain.size()),
        .segment_size = crypted_segment_size,
    };
    return std::make_pair(newpb, client->_cds_lfht_key);
}

int Worker::do_server_send(std::span<uint8_t> data, size_t segment_size, ClientEndpoint ep, bool queue_again) {
    msghdr mh;
    memset(&mh, 0, sizeof(mh));
    if (auto sin6 = std::get_if<sockaddr_in6>(&ep)) {
        mh.msg_name = sin6;
        mh.msg_namelen = sizeof(sockaddr_in6);
    } else if (auto sin = std::get_if<sockaddr_in>(&ep)) {
        mh.msg_name = sin;
        mh.msg_namelen = sizeof(sockaddr_in);
    }
    iovec iov{data.data(), data.size()};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    std::array<uint8_t, CMSG_SPACE(sizeof(uint16_t))> _cm;
    auto cm = reinterpret_cast<cmsghdr *>(_cm.data());
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = _cm.size();
    *reinterpret_cast<uint16_t *>(CMSG_DATA(cm)) = segment_size;
    mh.msg_control = cm;
    mh.msg_controllen = _cm.size();

    if (sendmsg(_arg.server->fd(), &mh, 0) < 0) {
        if (queue_again && is_eagain()) {
            auto tosend = new ServerSendBatch(data, segment_size, ep);
            _serversend.push_back(*tosend);
            server_enable(EPOLLOUT);
        }
        return -errno;
    } else {
        return 0;
    }
}

} // namespace wgss
