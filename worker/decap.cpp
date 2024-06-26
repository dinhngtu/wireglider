#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/unordered_map.hpp>
#include <tdutil/function_traits.hpp>

#include "worker.hpp"
#include "checksum.hpp"

using namespace boost::endian;
using namespace tdutil;
using namespace wgss::worker_impl;
using enum DecapBatch::Outcome;

namespace wgss {

namespace worker_impl {

template <typename T>
static std::pair<typename FlowMap<T>::iterator, bool> find_flow(
    FlowMap<T> &flow,
    const FlowKey<T> &fk,
    std::span<const uint8_t> pktdata,
    const PacketFlags &flags) {
    auto it = flow.lower_bound(fk);
    if (it == flow.end())
        return {it, false};
    if (!it->second.is_appendable(pktdata.size()))
        return {it, false};
    if (flags.istcp() ? !it->first.is_consecutive_with(fk, 1, pktdata.size()) : !it->first.matches(fk))
        return {it, false};
    if (flags.istcp() && it->second.flags.ispsh())
        return {it, false};
    return {it, true};
}

// returns true if the next flow was merged and erased
template <typename T>
static bool merge_next_flow(FlowMap<T> &flow, const typename FlowMap<T>::iterator &it) {
    if (it == flow.begin())
        return false;
    if (it->second.flags.ispsh())
        return false;
    auto next = it - 1;
    if (!it->second.is_mergeable(next->second))
        return false;
    if (it->second.flags.istcp() ? !it->first.is_consecutive_with(next->first, it->second.count, it->second.buf.size())
                                 : !it->first.matches(next->first))
        return false;
    it->second.extend(next->second);
    flow.erase(next);
    return true;
}

// returns true if this flow was merged with the previous flow and erased
template <typename T>
static bool merge_prev_flow(FlowMap<T> &flow, const typename FlowMap<T>::iterator &it) {
    auto prev = it + 1;
    if (prev == flow.end())
        return false;
    if (!prev->second.is_mergeable(it->second))
        return false;
    if (it->second.flags.istcp()
            ? !prev->first.is_consecutive_with(it->first, prev->second.count, prev->second.buf.size())
            : !prev->first.matches(it->first))
        return false;
    if (prev->second.flags.ispsh())
        return false;
    prev->second.extend(it->second);
    flow.erase(it);
    return true;
}

template <typename T>
static void append_flow(
    FlowMap<T> &flow,
    FlowKey<T> &fk,
    std::span<const uint8_t> pkthdr,
    std::span<const uint8_t> pktdata,
    const PacketFlags &flags) {
    auto [it, usable] = find_flow(flow, fk, pktdata, flags);
    bool created;
    if (!usable) {
        // create a new flow
        if (!flags.istcp())
            // udp: continue from last flow
            fk.seq = (it != flow.end()) ? (it->first.seq + 1) : 0;
        std::tie(it, created) = flow.emplace(fk, OwnedPacketBatch(pkthdr, 4 * fk.segment_size, flags));
        assert(created);
    }
    it->second.append(pktdata);
    if (flags.istcp() && flags.ispsh()) {
        it->second.tcphdr()->psh |= 1;
        it->second.flags.ispsh() = true;
    }

    /*
     * There are only two possibilities:
     * - Appending to an existing flow, bridging a gap (flow1-newdata->flow2)
     * - Creating a new flow, bridging with next flow (newdata->flow)
     * with `-` being a simple flow append and `->` being a flow merge.
     * IOW, merge_next_flow and merge_prev_flow can't happen at the same time.
     * Therefore there's no need to worry about iterator invalidation.
     */
    bool next_merged = merge_next_flow(flow, it);
    bool prev_merged = merge_prev_flow(flow, it);
    assert(!(next_merged && prev_merged));
}

static std::pair<const struct ip *, uint8_t> fill_fk_ip4(
    FlowKey<in_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags) {
    auto ip = reinterpret_cast<const struct ip *>(ippkt.data());
    // no support for long ipv4 headers yet
    if (ip->ip_hl * 4u != sizeof(struct ip))
        return {nullptr, IPPROTO_RAW};
    if (ippkt.size() != big_to_native(ip->ip_len))
        return {nullptr, IPPROTO_RAW};
    auto off = big_to_native(ip->ip_off);
    // no fragmenting
    if ((off & IP_MF) || (off & IP_OFFMASK))
        return {nullptr, IPPROTO_RAW};
    // iph checksum
    if (checksum(ippkt.subspan(0, sizeof(struct ip)), 0))
        return {nullptr, IPPROTO_RAW};
    flags.isv6() = false;
    fk.srcip = ip->ip_src;
    fk.dstip = ip->ip_dst;
    return std::make_pair(ip, ip->ip_p);
}

static std::pair<const ip6_hdr *, uint8_t> fill_fk_ip6(
    FlowKey<in6_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags) {
    auto ip = reinterpret_cast<const ip6_hdr *>(ippkt.data());
    auto rest = ippkt.subspan(sizeof(ip6_hdr));
    if (rest.size() != big_to_native(ip->ip6_ctlun.ip6_un1.ip6_un1_plen))
        return {nullptr, IPPROTO_RAW};
    flags.isv6() = true;
    fk.srcip = ip->ip6_src;
    fk.dstip = ip->ip6_dst;
    return std::make_pair(ip, ip->ip6_ctlun.ip6_un1.ip6_un1_nxt);
}

template <auto F>
using ip_header_of_t = std::remove_pointer_t<typename tdutil::result_type_t<decltype(F)>::first_type>;
template <auto F>
using address_type_of_t = std::remove_cvref_t<tdutil::first_argument_t<decltype(F)>>::address_type;

template <typename T>
static const tcphdr *fill_fk_tcp(FlowKey<T> &fk, std::span<const uint8_t> ippkt, PacketFlags &flags) {
    auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
    if (ippkt.size() - iphsize < sizeof(tcphdr))
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), true, iphsize))
        return nullptr;
    auto tcp = reinterpret_cast<const tcphdr *>(&ippkt[iphsize]);
    if (tcp->doff != 5)
        return nullptr;
    // TODO: check tcp flags
    flags.istcp() = true;
    flags.ispsh() = !!tcp->psh;
    fk.srcport = big_to_native(tcp->source);
    fk.dstport = big_to_native(tcp->dest);
    fk.tcpack = big_to_native(tcp->ack_seq);
    fk.seq = big_to_native(tcp->seq);
    return tcp;
}

template <typename T>
static const udphdr *fill_fk_udp(FlowKey<T> &fk, std::span<const uint8_t> ippkt, PacketFlags &flags) {
    auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
    if (ippkt.size() - iphsize < sizeof(tcphdr))
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), false, iphsize))
        return nullptr;
    auto udp = reinterpret_cast<const udphdr *>(&ippkt[iphsize]);
    flags.istcp() = false;
    flags.ispsh() = false;
    fk.srcport = big_to_native(udp->source);
    fk.dstport = big_to_native(udp->dest);
    fk.tcpack = 0;
    fk.seq = UINT32_MAX;
    return udp;
}

template <auto fill_ip>
static DecapBatch::Outcome evaluate_packet(
    std::span<const uint8_t> ippkt,
    FlowKey<address_type_of_t<fill_ip>> &fk,
    PacketFlags &flags) {
    using ip_header_type = ip_header_of_t<fill_ip>;

    if (ippkt.size() < sizeof(ip_header_type))
        return GRO_DROP;

    auto [ip, proto] = fill_ip(fk, ippkt, flags);
    if (!ip)
        return GRO_NOADD;

    bool istcp;
    switch (proto) {
    case IPPROTO_TCP: {
        if (!fill_fk_tcp(fk, ippkt, flags))
            return GRO_NOADD;
        break;
    }
    case IPPROTO_UDP: {
        if (!fill_fk_udp(fk, ippkt, flags))
            return GRO_NOADD;
        break;
    }
    default:
        return GRO_NOADD;
    }
    fk.segment_size = ippkt.size() - sizeof(*ip) - (flags.istcp() ? sizeof(tcphdr) : sizeof(udphdr));

    return GRO_ADDED;
}

template <auto fill_ip>
static DecapBatch::Outcome do_push_packet(
    std::span<const uint8_t> ippkt,
    FlowMap<address_type_of_t<fill_ip>> &tcpflow,
    FlowMap<address_type_of_t<fill_ip>> &udpflow,
    std::deque<std::vector<uint8_t>> &unrel) {
    using ip_header_type = ip_header_of_t<fill_ip>;
    FlowKey<address_type_of_t<fill_ip>> fk{};
    PacketFlags flags;
    auto res = evaluate_packet<fill_ip>(ippkt, fk, flags);
    switch (res) {
    case GRO_ADDED: {
        auto hsize = sizeof(ip_header_type) + (flags.istcp() ? sizeof(tcphdr) : sizeof(udphdr));
        auto pkthdr = ippkt.subspan(0, hsize);
        auto pktdata = ippkt.subspan(hsize);
        append_flow(flags.istcp() ? tcpflow : udpflow, fk, pkthdr, pktdata, flags);
        break;
    }
    case GRO_NOADD:
        unrel.emplace_back(ippkt.begin(), ippkt.end());
        break;
    case GRO_DROP:
        break;
    }
    return res;
}

DecapBatch::Outcome DecapBatch::push_packet_v4(std::span<const uint8_t> ippkt) {
    return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel);
}

DecapBatch::Outcome DecapBatch::push_packet_v6(std::span<const uint8_t> ippkt) {
    return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel);
}

DecapBatch::Outcome DecapBatch::push_packet(std::span<const uint8_t> ippkt) {
    if (ippkt.size() < sizeof(struct ip))
        return GRO_DROP;
    auto ip = reinterpret_cast<const struct ip *>(ippkt.data());
    if (ip->ip_v == 4)
        return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel);
    else
        return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel);
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
            batch.push_packet_v4(outpkt);
            break;
        }
        case WRITE_TO_TUNNEL_IPV6: {
            auto outpkt = std::span(&scratch[0], &scratch[result.size]);
            batch.push_packet_v6(outpkt);
            break;
        }
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
