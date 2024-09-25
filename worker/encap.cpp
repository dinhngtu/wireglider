#include <array>
#include <system_error>
#include <utility>
#include <span>
#include <sys/types.h>
#include <csignal>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <boost/endian.hpp>

#include "proto.hpp"
#include "worker.hpp"
#include "tai64n.hpp"

using namespace boost::endian;
using namespace wireglider::proto;
using namespace wireglider::worker_impl;
using namespace tdutil;

namespace wireglider {

void Worker::do_tun(epoll_event *ev) {
    static thread_local std::vector<uint8_t> tunbuf(65536 + sizeof(virtio_net_hdr));
    // max 64 segments
    // 60 bytes ipv4 header + 60 bytes tcp header
    static thread_local std::vector<uint8_t> splitbuf(65536 + 64 * (60 + 60));
    // 60 bytes ipv4 header + 60 bytes tcp header + WG overhead
    static thread_local constexpr size_t sendbuf_size = 65536 + 64 * (60 + 60) + 64 * calc_max_overhead_conservative();
    static thread_local std::vector<uint8_t> sendbuf(sendbuf_size), unrelbuf(sendbuf_size);
    static thread_local std::vector<iovec> unreliov(64);

    if (ev->events & (EPOLLHUP | EPOLLERR)) {
        throw QuitException();
    }
    if (ev->events & EPOLLOUT)
        do_tun_write();
    if (ev->events & EPOLLIN) {
        while (1) {
            virtio_net_hdr vnethdr;
            auto ret = do_tun_recv(tunbuf, vnethdr);
            if (!ret || ret.value().empty())
                break;
            auto read_pb = ret.value();

            auto tun_pb = do_tun_gso_split(read_pb, splitbuf, vnethdr);

            unreliov.clear();
            auto crypt = do_tun_encap(tun_pb, sendbuf, unrelbuf, unreliov);
            if (!crypt)
                continue;
            auto &[pb, ep] = *crypt;

            auto unrel_pending = server_send_reflist(pb.unrel, ep);
            if (unrel_pending) {
                auto tosend_unrel = new ServerSendList(ep);
                for (auto pkt : *unrel_pending)
                    tosend_unrel->push_back(pkt);
                tosend_unrel->finalize();
                _serversend.push_back(*tosend_unrel);

                auto tosend = new ServerSendBatch(pb.data, pb.segment_size, ep, pb.ecn);
                _serversend.push_back(*tosend);
            }

            ServerSendBatch batch(pb.segment_size, ep, pb.ecn);
            if (!batch.send(_arg.server->fd(), pb.data)) {
                auto tosend = new ServerSendBatch(pb.data.subspan(batch.pos), batch.segment_size, batch.ep, batch.ecn);
                _serversend.push_back(*tosend);
            }
        }
    }
}

outcome::result<std::span<uint8_t>> Worker::do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr) {
    // if (outbuf.size() < 65536 + sizeof(virtio_net_hdr))
    // outbuf.resize(65536 + sizeof(virtio_net_hdr));
    assert(outbuf.size() >= 65536 + sizeof(virtio_net_hdr));

    auto msize = read(_arg.tun->fd(), outbuf.data(), outbuf.size());
    if (msize < 0) {
        if (is_eagain())
            return fail(EAGAIN);
        else if (errno == EBADFD)
            throw QuitException();
        else
            throw std::system_error(errno, std::system_category(), "do_tun_recv read");
    }
    auto rest = std::span(outbuf.begin(), msize);

    if (rest.size() < sizeof(virtio_net_hdr))
        return fail(EIO);
    memcpy(&vnethdr, rest.data(), sizeof(vnethdr));
    rest = rest.subspan(sizeof(vnethdr));
    // rest now contains iphdr+l4hdr+giant payload

    return rest;
}

std::optional<std::pair<PacketBatch, ClientEndpoint>> Worker::do_tun_encap(
    PacketBatch &pb,
    std::vector<uint8_t> &outbuf,
    std::vector<uint8_t> &unrelbuf,
    std::vector<iovec> &unreliov) {
    const Client *client = nullptr;

    // be conservative
    [[maybe_unused]] auto reserve_size =
        pb.data.size() + Peer::expected_encrypt_overhead(pb.segment_size) * pb.nr_segments();
    // if (outbuf.size() < reserve_size)
    // outbuf.resize(reserve_size);
    assert(outbuf.size() >= reserve_size);

    RundownGuard rcu;
    auto config = _arg.config(rcu);

    if (pb.isv6) {
        in6_addr dstip6;
        memcpy(&dstip6, pb.data.data() + offsetof(ip6_hdr, ip6_dst), sizeof(dstip6));
        unsigned long ipkey = config->prefix6.reduce(dstip6);
        client = static_cast<const Client *>(mtree_load(_arg.allowed_ip6, ipkey));
    } else {
        in_addr dstip4;
        memcpy(&dstip4, pb.data.data() + offsetof(struct ip, ip_dst), sizeof(dstip4));
        unsigned long ipkey = config->prefix4.reduce(dstip4);
        client = static_cast<const Client *>(mtree_load(_arg.allowed_ip4, ipkey));
    }

    if (!client)
        return std::nullopt;

    std::span<uint8_t> remain(outbuf);
    auto expected_segment_size = Peer::expected_encrypt_size(pb.segment_size);
    auto now = time::gettime(CLOCK_MONOTONIC);
    {
        auto state = client->state.synchronize();
        if (!state->peer->encrypt_begin(now))
            return std::nullopt;
        for (auto pkt : pb) {
            auto result = state->peer->encrypt(remain, pkt);
            if (result) {
                remain = remain.subspan(result.assume_value().outsize);
            } else if (result.assume_error() == EncryptError::NoSession) {
                auto buf = new ClientBuffer(remain.begin(), remain.end(), pb.segment_size, true);
                state->buffer.push_back(*buf);
            }
        }
        auto protosgn = state->peer->encrypt_end(now);
        if (!!(protosgn & ProtoSignal::NeedsHandshake)) {
            auto hs = state->peer->write_handshake1(now, client->pubkey, unrelbuf);
            if (hs)
                unreliov.push_back({unrelbuf.data(), sizeof(Handshake1)});
            else
                return std::nullopt;
        } else if (!!(protosgn & ProtoSignal::NeedsKeepalive)) {
            auto ka = state->peer->encrypt(unrelbuf, {});
            if (ka)
                unreliov.push_back({unrelbuf.data(), ka.assume_value().outsize});
        }
    }
    PacketBatch newpb{
        .prefix = {},
        .data = std::span(outbuf.data(), outbuf.size() - remain.size()),
        .unrel = std::span(unreliov),
        .segment_size = expected_segment_size,
        .isv6 = pb.isv6,
        .ecn = pb.ecn,
    };
    return std::make_pair(newpb, client->epkey);
}

} // namespace wireglider
