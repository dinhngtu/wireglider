#include <string>
#include <array>
#include <utility>
#include <span>
#include <typeinfo>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "virtio_net.hpp"
#include <boost/endian.hpp>
#include <tdutil/util.hpp>
#include <fmt/format.h>

#include "worker/offload.hpp"
#include "checksum.hpp"
#include "endian.hpp"

using namespace boost::endian;
using namespace wgss::worker_impl;

namespace wgss::worker_impl {

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
PacketBatch do_tun_gso_split(std::span<uint8_t> inbuf, std::vector<uint8_t> &outbuf, const virtio_net_hdr &vnethdr) {
    auto l4_csum_offset = vnethdr.csum_start + vnethdr.csum_offset;
    auto isv6 = reinterpret_cast<struct ip *>(inbuf.data())->ip_v == 6;

    if (vnethdr.gso_type == VIRTIO_NET_HDR_GSO_NONE) {
        if (vnethdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
            // clear ipv4 header checksum
            if (!isv6)
                reinterpret_cast<ip *>(inbuf.data())->ip_sum = 0;
            // clear tcp/udp checksum
            store_big_u16(&inbuf[l4_csum_offset], 0);

            auto istcp = reinterpret_cast<ip *>(inbuf.data())->ip_p == IPPROTO_TCP;
            auto l4_csum = calc_l4_checksum(inbuf, isv6, istcp, vnethdr.csum_start);
            store_big_u16(&inbuf[l4_csum_offset], l4_csum);
        }
        return PacketBatch{
            .prefix = {},
            .data = inbuf,
            .segment_size = inbuf.size(),
            .isv6 = isv6,
        };
    }

    if (inbuf.size() < vnethdr.hdr_len) {
        // shouldn't happen but this was a possible crash
        return PacketBatch{
            .prefix = {},
            .data = inbuf,
            .segment_size = inbuf.size(),
            .isv6 = isv6,
        };
    }

    auto prefix = inbuf.subspan(0, vnethdr.hdr_len);
    auto rest = inbuf.subspan(vnethdr.hdr_len);

    [[maybe_unused]] auto reserve_size =
        inbuf.size() + tdutil::round_up(rest.size(), vnethdr.gso_size) / vnethdr.gso_size * prefix.size();
    // if (outbuf.size() < reserve_size)
    // outbuf.resize(reserve_size);
    assert(outbuf.size() >= reserve_size);

    // clear ipv4 header checksum
    if (!isv6)
        reinterpret_cast<ip *>(prefix.data())->ip_sum = 0;
    // clear tcp/udp checksum
    store_big_u16(&prefix[l4_csum_offset], 0);

    bool istcp = vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4 || vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6;
    uint32_t tcpseq0 = 0;
    if (istcp)
        tcpseq0 = big_to_native(reinterpret_cast<tcphdr *>(&rest[vnethdr.csum_start])->seq);

    size_t i = 0, pbsize = 0;
    for (; !rest.empty(); i++) {
        auto datalen = std::min(rest.size(), size_t(vnethdr.gso_size));
        auto pktlen = prefix.size() + datalen;
        auto outbuf_begin = pbsize;
        pbsize += pktlen;
        assert(outbuf.size() >= pbsize);
        std::span thispkt(&outbuf[outbuf_begin], &outbuf[pbsize]);

        std::copy(prefix.begin(), prefix.end(), thispkt.begin());
        std::copy(&rest[0], &rest[datalen], &thispkt[prefix.size()]);

        if (isv6) {
            // For IPv6 we are responsible for updating the payload length field.
            assign_big_from_native(
                reinterpret_cast<ip6_hdr *>(thispkt.data())->ip6_plen,
                thispkt.size() - vnethdr.csum_start);
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
            assign_big_from_native(ip->ip_len, thispkt.size());
            assign_big_from_native(ip->ip_sum, checksum(thispkt.subspan(0, vnethdr.csum_start), 0));
        }

        if (istcp) {
            // set TCP seq and adjust TCP flags
            auto tcp = reinterpret_cast<tcphdr *>(&thispkt[vnethdr.csum_start]);
            assign_big_from_native(tcp->seq, tcpseq0 + vnethdr.gso_size * i);
            if (datalen < rest.size())
                // FIN and PSH should only be set on last segment
                tcp->fin = tcp->psh = 0;
        } else {
            // set UDP header len
            auto udp = reinterpret_cast<udphdr *>(&thispkt[vnethdr.csum_start]);
            assign_big_from_native(udp->len, prefix.size() - vnethdr.csum_start);
        }

        auto l4_csum = calc_l4_checksum(thispkt, isv6, istcp, vnethdr.csum_start);
        store_big_u16(&thispkt[l4_csum_offset], l4_csum);

        // to next packet
        rest = rest.subspan(datalen);
    }

    return PacketBatch{
        .prefix = {},
        .data = std::span(outbuf.begin(), pbsize),
        .segment_size = prefix.size() + vnethdr.gso_size,
        .isv6 = isv6,
    };
}

} // namespace wgss::worker_impl
