#include <string>
#include <array>
#include <utility>
#include <span>
#include <sys/types.h>
#include <csignal>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <tdutil/util.hpp>

#include "worker.hpp"

using namespace boost::endian;
using namespace wireglider::worker_impl;

namespace wireglider {

void Worker::do_tun(epoll_event *ev) {
    static thread_local std::vector<uint8_t> tunbuf(65536 + sizeof(virtio_net_hdr));
    // max 64 segments
    // 60 bytes ipv4 header + 60 bytes tcp header
    static thread_local std::vector<uint8_t> splitbuf(65536 + 64 * (60 + 60));
    // 60 bytes ipv4 header + 60 bytes tcp header + 40 bytes WG overhead
    static thread_local constexpr size_t sendbuf_size = 65536 + 64 * (60 + 60) + 64 * calc_overhead();
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
    Client *client = nullptr;

    // be conservative
    [[maybe_unused]] auto reserve_size = pb.data.size() + calc_overhead() * pb.nr_segments();
    // if (outbuf.size() < reserve_size)
    // outbuf.resize(reserve_size);
    assert(outbuf.size() >= reserve_size);

    RundownGuard rcu;
    auto config = _arg.config(rcu);

    if (pb.isv6) {
        in6_addr dstip6;
        memcpy(&dstip6, pb.data.data() + offsetof(ip6_hdr, ip6_dst), sizeof(dstip6));
        unsigned long ipkey = config->prefix6.reduce(dstip6);
        client = static_cast<Client *>(mtree_load(_arg.allowed_ip6, ipkey));
    } else {
        in_addr dstip4;
        memcpy(&dstip4, pb.data.data() + offsetof(struct ip, ip_dst), sizeof(dstip4));
        unsigned long ipkey = config->prefix4.reduce(dstip4);
        client = static_cast<Client *>(mtree_load(_arg.allowed_ip4, ipkey));
    }

    if (!client)
        return std::nullopt;

    std::span<const uint8_t> rest(pb.data);
    std::span<uint8_t> remain(outbuf);
    auto expected_segment_size = pb.segment_size + calc_overhead();
    size_t unrel_current = 0;
    {
        std::lock_guard<std::mutex> client_lock(client->mutex);
        for (auto pkt : pb) {
            auto res = wireguard_write_raw(client->tunnel, pkt.data(), pkt.size(), remain.data(), remain.size());
            // op: handle error
            if (res.op == WRITE_TO_NETWORK) {
                if (res.size == expected_segment_size) {
                    // admit packets with the expected size into the pb
                    remain = remain.subspan(res.size);
                } else {
                    // a cached packet
                    assert(unrel_current + res.size <= unrelbuf.size());
                    memcpy(&unrelbuf[unrel_current], &remain[0], res.size);
                    unreliov.push_back({&unrelbuf[unrel_current], res.size});
                    unrel_current += res.size;
                }
            }
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
