#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/unordered_map.hpp>

#include "worker.hpp"

using namespace boost::endian;
using namespace tdutil;
using namespace wgss::worker_impl;

namespace wgss {

namespace worker_impl {

template <typename T>
static void append_flow(FlowMap<T> *flow, const FlowKey<T> &fk, std::span<uint8_t> pkt, bool istcp) {
    auto it = flow->upper_bound(fk);
    if (it != flow->end() && it->second.is_appendable(pkt.size()) &&
        it->first.is_consecutive_with(fk, 1, istcp ? pkt.size() : 0)) {
        // insert into existing flow
        it->second.append(pkt);
    } else {
        // needs new flow
        auto &newflow = (*flow)[fk];
        newflow = OwnedPacketBatch(4 * fk.segment_size);
        newflow.append(pkt);
    }
    // merge with previous flow; map is in reverse order
    auto prev = it + 1;
    if (prev != flow->end() && prev->second.is_mergeable(it->second) &&
        prev->first.is_consecutive_with(it->first, prev->second.count, istcp ? prev->second.buf.size() : 0)) {
        prev->second.extend(it->second);
        flow->erase(it);
    }
}

static struct ip *fill_fk_ip4(FlowKey<in_addr> &fk, std::span<uint8_t> ippkt) {
    auto ip = reinterpret_cast<struct ip *>(ippkt.data());
    // no support for long ipv4 headers yet
    if (ip->ip_hl * 4u != sizeof(struct ip))
        return nullptr;
    if (ippkt.size() != ip->ip_len)
        return nullptr;
    fk.srcip = ip->ip_src;
    fk.dstip = ip->ip_dst;
    return ip;
}

static ip6_hdr *fill_fk_ip6(FlowKey<in6_addr> &fk, std::span<uint8_t> ippkt) {
    auto ip = reinterpret_cast<ip6_hdr *>(ippkt.data());
    auto rest = ippkt.subspan(sizeof(ip6_hdr));
    if (rest.size() != ip->ip6_ctlun.ip6_un1.ip6_un1_plen)
        return nullptr;
    fk.srcip = ip->ip6_src;
    fk.dstip = ip->ip6_dst;
    return ip;
}

template <typename T>
static tcphdr *fill_fk_tcp(FlowKey<T> &fk, std::span<uint8_t> l4pkt) {
    if (l4pkt.size() < sizeof(tcphdr))
        return nullptr;
    auto tcp = reinterpret_cast<tcphdr *>(l4pkt.data());
    if (tcp->doff != 5)
        return nullptr;
    // TODO: check tcp flags
    fk.srcport = big_to_native(tcp->source);
    fk.dstport = big_to_native(tcp->dest);
    fk.tcpack = big_to_native(tcp->ack_seq);
    fk.tcpseq = big_to_native(tcp->seq);
    return tcp;
}

template <typename T>
static udphdr *fill_fk_udp(FlowKey<T> &fk, std::span<uint8_t> l4pkt) {
    if (l4pkt.size() < sizeof(udphdr))
        return nullptr;
    auto udp = reinterpret_cast<udphdr *>(l4pkt.data());
    fk.srcport = big_to_native(udp->source);
    fk.dstport = big_to_native(udp->dest);
    fk.tcpack = fk.tcpseq = 0;
    return udp;
}

DecapBatch::Outcome DecapBatch::push_packet_v4(std::span<uint8_t> ippkt) {
    if (ippkt.size() < sizeof(struct ip))
        return GRO_DROP;

    FlowKey<in_addr> fk{};
    auto ip = fill_fk_ip4(fk, ippkt);
    if (!ip)
        return GRO_NOADD;
    auto rest = ippkt.subspan(sizeof(*ip));

    IP4Flow *flow;
    bool istcp;
    switch (ip->ip_p) {
    case IPPROTO_TCP: {
        if (!fill_fk_tcp(fk, rest))
            return GRO_NOADD;
        flow = &tcp4;
        istcp = true;
        rest = rest.subspan(sizeof(tcphdr));
        break;
    }
    case IPPROTO_UDP: {
        if (!fill_fk_udp(fk, rest))
            return GRO_NOADD;
        flow = &udp4;
        istcp = false;
        rest = rest.subspan(sizeof(udphdr));
        break;
    }
    default:
        return GRO_NOADD;
    }
    fk.segment_size = rest.size();

    append_flow(flow, fk, rest, istcp);
    return GRO_ADDED;
}

DecapBatch::Outcome DecapBatch::push_packet_v6(std::span<uint8_t> ippkt) {
    if (ippkt.size() < sizeof(ip6_hdr))
        return GRO_DROP;

    FlowKey<in6_addr> fk{};
    auto ip = fill_fk_ip6(fk, ippkt);
    if (!ip)
        return GRO_NOADD;
    auto rest = ippkt.subspan(sizeof(*ip));

    IP6Flow *flow;
    bool istcp;
    switch (ip->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
    case IPPROTO_TCP: {
        if (!fill_fk_tcp(fk, rest))
            return GRO_NOADD;
        flow = &tcp6;
        istcp = true;
        rest = rest.subspan(sizeof(tcphdr));
        break;
    }
    case IPPROTO_UDP: {
        if (!fill_fk_udp(fk, rest))
            return GRO_NOADD;
        flow = &udp6;
        istcp = false;
        rest = rest.subspan(sizeof(udphdr));
        break;
    }
    default:
        return GRO_NOADD;
    }
    fk.segment_size = rest.size();

    append_flow(flow, fk, rest, istcp);
    return GRO_ADDED;
}

} // namespace worker_impl

void Worker::do_server(epoll_event *ev) {
    if (ev->events & EPOLLOUT)
        do_server_send();
    if (ev->events & EPOLLIN) {
        auto crypt = do_server_recv(ev, _recvbuf);
        if (!crypt)
            return;

        auto batch = do_server_decap(crypt->first, crypt->second, _pktbuf);
        if (!batch)
            return;

        {
            auto sendlist = new ServerSendList(std::move(batch->retpkt), crypt->second);
            auto ret = server_send(sendlist);
            if (is_eagain(ret)) {
                _serversend.push_back(*sendlist);
                server_enable(EPOLLOUT);
            } else {
                assert(sendlist->pos == sendlist->mh.size());
                delete sendlist;
            }
        }

        // TODO
    }
}

std::optional<std::pair<PacketBatch, ClientEndpoint>> Worker::do_server_recv(
    [[maybe_unused]] epoll_event *ev,
    std::vector<uint8_t> &buf) {
    if (buf.size() < 65536)
        buf.resize(65536);

    msghdr mh;
    memset(&mh, 0, sizeof(mh));

    std::array<uint8_t, sizeof(sockaddr_in6)> _name;
    mh.msg_name = _name.data();
    mh.msg_namelen = _name.size();
    iovec iov{buf.data(), buf.size()};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    std::array<uint8_t, CMSG_LEN(sizeof(uint16_t))> _cm;
    mh.msg_control = _cm.data();
    mh.msg_controllen = _cm.size();

    auto bytes = recvmsg(_arg.server->fd(), &mh, 0);
    if (bytes < 0) {
        perror("recvmsg");
        return std::nullopt;
    }

    size_t gro_size = static_cast<size_t>(bytes);
    for (auto cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_type == UDP_GRO) {
            gro_size = *reinterpret_cast<const uint16_t *>(CMSG_DATA(cm));
            break;
        }
    }

    ClientEndpoint ep;
    bool isv6;
    if (static_cast<sockaddr *>(mh.msg_name)->sa_family == AF_INET6) {
        assert(_arg.srv_is_v6);
        ep = *static_cast<sockaddr_in6 *>(mh.msg_name);
        isv6 = true;
    } else {
        assert(!_arg.srv_is_v6);
        ep = *static_cast<sockaddr_in *>(mh.msg_name);
        isv6 = false;
    }

    PacketBatch pb{
        .prefix = {},
        .data = {buf.data(), iov.iov_len},
        .segment_size = gro_size,
        .isv6 = isv6,
    };
    return std::make_pair(pb, ep);
}

/*
 * packets sent from ep are decapsulated
 * each packet is a separate ip packet with:
 *  - src ip/port (sender side)
 *  - dst ip/port (may be client or tun destination elsewhere)
 *  - tcp/udp
 * the flowkey consists of:
 *  - src ip/port
 *  - dst ip/port
 *  - initial IP ID
 *  - initial sequence number (0 for UDP)
 */
std::optional<DecapBatch> Worker::do_server_decap(PacketBatch pb, ClientEndpoint ep, std::vector<uint8_t> &scratch) {
    RundownGuard rcu;
    auto it = _arg.clients->find(rcu, ep);
    if (it == _arg.clients->end())
        return std::nullopt;

    DecapBatch batch;
    std::lock_guard<std::mutex> client_lock(it->mutex);

    auto rest = pb.data;
    for (auto pkt : pb) {
        auto result = wireguard_read_raw(it->tunnel, pkt.data(), pkt.size(), scratch.data(), scratch.size());
        switch (result.op) {
        case WRITE_TO_TUNNEL_IPV4: {
            auto outpkt = std::span(&scratch[0], &scratch[result.size]);
            if (batch.push_packet_v4(outpkt) == DecapBatch::Outcome::GRO_NOADD)
                batch.unrel.emplace_back(outpkt.begin(), outpkt.end());
            break;
        }
        case WRITE_TO_TUNNEL_IPV6:
            // not implemented
            break;
        case WRITE_TO_NETWORK: {
            batch.retpkt.emplace_back(&scratch[0], &scratch[result.size]);
            tunnel_flush(rcu, client_lock, batch.retpkt, it->tunnel, scratch);
            break;
        }
        case WIREGUARD_ERROR:
        case WIREGUARD_DONE:
            break;
        }
    }

    return batch;
}

void Worker::tunnel_flush(
    [[maybe_unused]] RundownGuard &rcu,
    [[maybe_unused]] std::lock_guard<std::mutex> &lock,
    std::deque<std::vector<uint8_t>> &serversend,
    wireguard_tunnel_raw *tunnel,
    std::vector<uint8_t> &scratch) {
    while (1) {
        auto result = wireguard_read_raw(tunnel, nullptr, 0, scratch.data(), scratch.size());
        switch (result.op) {
        case WRITE_TO_NETWORK:
            serversend.emplace_back(&scratch[0], &scratch[result.size]);
            break;
        case WIREGUARD_DONE:
            return;
        default:
            break;
        }
    }
}

} // namespace wgss
