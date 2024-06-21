#include <utility>
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

DecapBatch::Outcome DecapBatch::push_packet_v4(std::span<uint8_t> ippkt) {
    if (ippkt.size() < sizeof(struct ip))
        return GRO_DROP;
    auto ip = reinterpret_cast<struct ip *>(ippkt.data());
    auto ihl_bytes = ip->ip_hl * 4;
    if (ihl_bytes < 20 || ippkt.size() < ihl_bytes)
        return GRO_DROP;
    auto rest = ippkt.subspan(ihl_bytes);

    FlowKey<in_addr> fk{
        .srcip = ip->ip_src,
        .dstip = ip->ip_dst,
        .ipid = big_to_native(ip->ip_id),
    };
    IP4Flow *flow4;
    bool istcp;
    switch (ip->ip_p) {
    case IPPROTO_TCP: {
        if (ippkt.size() - ihl_bytes < sizeof(tcphdr))
            return GRO_DROP;
        auto tcp = reinterpret_cast<tcphdr *>(&ippkt[ihl_bytes]);
        fk.srcport = big_to_native(tcp->source);
        fk.dstport = big_to_native(tcp->dest);
        fk.tcpseq = big_to_native(tcp->seq);
        flow4 = &tcp4;
        istcp = true;
        rest = rest.subspan(sizeof(tcphdr));
        break;
    }
    case IPPROTO_UDP: {
        if (ippkt.size() - ihl_bytes < sizeof(udphdr))
            return GRO_DROP;
        auto udp = reinterpret_cast<udphdr *>(&ippkt[ihl_bytes]);
        fk.srcport = big_to_native(udp->source);
        fk.dstport = big_to_native(udp->dest);
        fk.tcpseq = 0;
        flow4 = &udp4;
        istcp = false;
        rest = rest.subspan(sizeof(udphdr));
        break;
    }
    default:
        return GRO_NOADD;
    }
    fk.segment_size = rest.size();

    auto it = flow4->upper_bound(fk);
    if (it != flow4->end() && it->second.is_appendable(rest.size()) &&
        it->first.is_consecutive_with(fk, 1, istcp ? rest.size() : 0)) {
        // insert into existing flow
        it->second.append(rest);
    } else {
        // needs new flow
        auto &newflow = (*flow4)[fk];
        newflow = OwnedPacketBatch(4 * fk.segment_size);
        newflow.append(rest);
    }
    // merge with previous flow; map is in reverse order
    auto prev = it + 1;
    if (prev != flow4->end() && prev->second.is_mergeable(it->second) &&
        prev->first.is_consecutive_with(it->first, prev->second.count, istcp ? prev->second.buf.size() : 0)) {
        prev->second.extend(it->second);
        flow4->erase(it);
    }
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
    epoll_event *ev,
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
    if (static_cast<sockaddr *>(mh.msg_name)->sa_family == AF_INET6) {
        assert(_arg.srv_is_v6);
        ep = *static_cast<sockaddr_in6 *>(mh.msg_name);
    } else {
        assert(!_arg.srv_is_v6);
        ep = *static_cast<sockaddr_in *>(mh.msg_name);
    }

    PacketBatch pb{
        .prefix = {},
        .data = {buf.data(), iov.iov_len},
        .segment_size = gro_size,
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
    size_t i = 0;
    for (; !rest.empty(); i++) {
        auto datalen = std::min(rest.size(), pb.segment_size);
        auto result = wireguard_read_raw(it->tunnel, rest.data(), datalen, scratch.data(), scratch.size());
        rest = rest.subspan(datalen);
        switch (result.op) {
        case WRITE_TO_TUNNEL_IPV4: {
            auto pkt = std::span(&scratch[0], &scratch[result.size]);
            if (batch.push_packet_v4(pkt) == DecapBatch::Outcome::GRO_NOADD)
                batch.unrel.emplace_back(pkt.begin(), pkt.end());
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
