#include <string>
#include <array>
#include <utility>
#include <span>
#include <typeinfo>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <tdutil/util.hpp>
#include <fmt/format.h>

#include "worker.hpp"

using namespace boost::endian;
using namespace wgss::worker_impl;

namespace wgss {

void Worker::do_tun(epoll_event *ev) {
    if (ev->events & EPOLLOUT)
        do_tun_write();
    if (ev->events & EPOLLIN) {
        virtio_net_hdr vnethdr;
        auto read_pb = do_tun_recv(_recvbuf, vnethdr);
        if (!read_pb)
            return;

        auto tun_pb = do_tun_gso_split(read_pb.value(), _pktbuf, vnethdr);

        auto crypt = do_tun_encap(tun_pb, _sendbuf);
        if (!crypt)
            return;

        auto ret = server_send(crypt->first.data, crypt->first.segment_size, crypt->second, true);
        if (ret < 0 && !is_eagain(-ret))
            fmt::print("do_server_send: {}\n", strerrordesc_np(ret));
    }
}

std::optional<std::span<uint8_t>> Worker::do_tun_recv(std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr) {
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
    in_addr dstip4;
    in6_addr dstip6;
    if (pb.isv6) {
        dstip6 = reinterpret_cast<const ip6_hdr *>(pb.data.data())->ip6_dst;
        // not implemented
        return std::nullopt;
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
    size_t crypted_segment_size = 0;
    for (auto pkt : pb) {
        auto res = wireguard_write_raw(client->tunnel, pkt.data(), pkt.size(), remain.data(), remain.size());
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
        .isv6 = pb.isv6,
    };
    return std::make_pair(newpb, client->_cds_lfht_key);
}

} // namespace wgss