#include <string>
#include <array>
#include <utility>
#include <span>
#include <typeinfo>
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
    if (ev->events & (EPOLLHUP | EPOLLERR)) {
        throw QuitException();
    }
    if (ev->events & EPOLLOUT)
        do_tun_write();
    if (ev->events & EPOLLIN) {
        virtio_net_hdr vnethdr;
        auto ret = do_tun_recv(_recvbuf, vnethdr);
        if (!ret || ret.value().empty())
            return;
        auto read_pb = ret.value();

        auto tun_pb = do_tun_gso_split(read_pb, _pktbuf, vnethdr);

        auto crypt = do_tun_encap(tun_pb, _sendbuf);
        if (!crypt)
            return;

        ServerSendBatch batch;
        batch.ep = crypt->second;
        batch.segment_size = crypt->first.segment_size;
        batch.ecn = crypt->first.ecn;

        auto batch_ret = server_send_batch(&batch, crypt->first.data);
        if (batch_ret.has_value()) {
            auto tosend = new ServerSendBatch(batch_ret.value(), batch.segment_size, batch.ep);
            _serversend.push_back(*tosend);
            server_enable(EPOLLOUT);
        }
    }
}

outcome::result<std::span<uint8_t>> Worker::do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr) {
    // if (outbuf.size() < 65536 + sizeof(virtio_net_hdr))
    // outbuf.resize(65536 + sizeof(virtio_net_hdr));
    assert(outbuf.size() >= 65536 + sizeof(virtio_net_hdr));

    // don't use directly
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
    std::vector<uint8_t> &outbuf) {
    Client *client = nullptr;

    // be conservative
    [[maybe_unused]] auto reserve_size = pb.data.size() + _overhead * pb.nr_segments();
    // if (outbuf.size() < reserve_size)
    // outbuf.resize(reserve_size);
    assert(outbuf.size() >= reserve_size);

    RundownGuard rcu;
    auto config = _arg.config(rcu);

    in_addr dstip4;
    in6_addr dstip6;
    if (pb.isv6) {
        memcpy(&dstip6, pb.data.data() + offsetof(ip6_hdr, ip6_dst), sizeof(dstip6));
        unsigned long ipkey = config->prefix6.reduce(dstip6);
        client = static_cast<Client *>(mtree_load(_arg.allowed_ip6, ipkey));
    } else {
        memcpy(&dstip4, pb.data.data() + offsetof(struct ip, ip_dst), sizeof(dstip4));
        unsigned long ipkey = config->prefix4.reduce(dstip4);
        client = static_cast<Client *>(mtree_load(_arg.allowed_ip4, ipkey));
    }

    if (!client)
        return std::nullopt;
    std::lock_guard<std::mutex> client_lock(client->mutex);

    std::span<const uint8_t> rest(pb.data);
    std::span<uint8_t> remain(outbuf);
    size_t crypted_segment_size = 0;
    for (auto pkt : pb) {
        auto res = wireguard_write_raw(client->tunnel, pkt.data(), pkt.size(), remain.data(), remain.size());
        // op: handle error
        if (res.op == WRITE_TO_NETWORK) {
            remain = remain.subspan(res.size);
            if (!crypted_segment_size)
                crypted_segment_size = res.size;
            else
                // TODO: handle the case of cached packets
                assert(rest.empty() || crypted_segment_size == res.size);
        }
    }
    PacketBatch newpb{
        .prefix = {},
        .data = std::span(outbuf.data(), outbuf.size() - remain.size()),
        .segment_size = crypted_segment_size,
        .isv6 = pb.isv6,
        .ecn = pb.ecn,
    };
    return std::make_pair(newpb, client->epkey);
}

} // namespace wireglider
