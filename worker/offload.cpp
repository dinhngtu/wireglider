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
#include "dbgprint.hpp"

using namespace boost::endian;
using namespace wireglider::worker_impl;

namespace wireglider::worker_impl {

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
PacketBatch do_tun_gso_split(std::span<uint8_t> inbuf, std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr) {
    auto l4_csum_offset = vnethdr.csum_start + vnethdr.csum_offset;
    auto isv6 = tdutil::start_lifetime_as<struct ip>(inbuf.data())->ip_v == 6;
    uint8_t ecn;
    if (isv6)
        ecn = IPTOS_ECN(big_to_native(tdutil::start_lifetime_as<ip6_hdr>(inbuf.data())->ip6_flow) >> 20);
    else
        ecn = IPTOS_ECN(tdutil::start_lifetime_as<struct ip>(inbuf.data())->ip_tos);

    switch (vnethdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
    case VIRTIO_NET_HDR_GSO_NONE:
        if (vnethdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
            auto ip = tdutil::start_lifetime_as<struct ip>(inbuf.data());

            // clear ipv4 header checksum
            if (!isv6)
                ip->ip_sum = 0;
            // clear tcp/udp checksum
            store_big_u16(&inbuf[l4_csum_offset], 0);

            bool istcp;
            if (isv6) {
                istcp = tdutil::start_lifetime_as<ip6_hdr>(inbuf.data())->ip6_nxt == IPPROTO_TCP;
            } else {
                istcp = ip->ip_p == IPPROTO_TCP;
                auto ip_csum = checksum(inbuf.subspan(0, vnethdr.csum_start), 0);
                // for some reason, need to put native byte order csum here
                memcpy(&ip->ip_sum, &ip_csum, sizeof(ip_csum));
            }
            auto l4_csum = calc_l4_checksum(inbuf, isv6, istcp, vnethdr.csum_start);
            // native order
            memcpy(&inbuf[l4_csum_offset], &l4_csum, sizeof(l4_csum));
        }
        return PacketBatch{
            .data = inbuf,
            .segment_size = inbuf.size(),
            .isv6 = isv6,
            .ecn = ecn,
        };
    case VIRTIO_NET_HDR_GSO_TCPV4:
    case VIRTIO_NET_HDR_GSO_TCPV6: {
        // Don't trust hdr.hdrLen from the kernel as it can be equal to the length
        // of the entire first packet when the kernel is handling it as part of a
        // FORWARD path. Instead, parse the transport header length and add it onto
        // csumStart, which is synonymous for IP header length.
        if (inbuf.size() - vnethdr.csum_start < sizeof(tcphdr)) {
            DBG_PRINT("packet is too short\n");
            return PacketBatch{
                .data = inbuf,
                .segment_size = inbuf.size(),
                .isv6 = isv6,
                .ecn = ecn,
            };
        }
        auto thlen = 4u * tdutil::start_lifetime_as<tcphdr>(&inbuf[vnethdr.csum_start])->doff;
        if (thlen < sizeof(tcphdr)) {
            DBG_PRINT("thlen too small: {}\n", thlen);
            return PacketBatch{
                .data = inbuf,
                .segment_size = inbuf.size(),
                .isv6 = isv6,
                .ecn = ecn,
            };
        }
        vnethdr.hdr_len = vnethdr.csum_start + thlen;
        break;
    }
    case WIREGLIDER_VIRTIO_NET_HDR_GSO_UDP_L4:
        vnethdr.hdr_len = vnethdr.csum_start + sizeof(udphdr);
        break;
    default:
        DBG_PRINT("unknown gso type {}\n", vnethdr.gso_type);
        return PacketBatch{
            .data = inbuf,
            .segment_size = inbuf.size(),
            .isv6 = isv6,
            .ecn = ecn,
        };
    }

    if (inbuf.size() < vnethdr.hdr_len) {
        // shouldn't happen but this was a possible crash
        return PacketBatch{
            .data = inbuf,
            .segment_size = inbuf.size(),
            .isv6 = isv6,
            .ecn = ecn,
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
        tdutil::start_lifetime_as<struct ip>(prefix.data())->ip_sum = 0;
    // clear tcp/udp checksum
    memset(&prefix[l4_csum_offset], 0, 2);

    bool istcp = vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4 || vnethdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6;
    uint32_t tcpseq0 = 0;
    if (istcp)
        tcpseq0 = big_to_native(tdutil::start_lifetime_as<tcphdr>(&prefix[vnethdr.csum_start])->seq);

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
                tdutil::start_lifetime_as<ip6_hdr>(thispkt.data())->ip6_plen,
                thispkt.size() - vnethdr.csum_start);
        } else {
            // For IPv4 we are responsible for incrementing the ID field,
            // updating the total len field, and recalculating the header
            // checksum.
            auto ip = tdutil::start_lifetime_as<struct ip>(thispkt.data());
            if (i) {
                big_to_native_inplace(ip->ip_id);
                ip->ip_id += i;
                native_to_big_inplace(ip->ip_id);
            }
            assign_big_from_native(ip->ip_len, thispkt.size());
            auto ip_csum = checksum(thispkt.subspan(0, vnethdr.csum_start), 0);
            // native order
            memcpy(&ip->ip_sum, &ip_csum, sizeof(ip_csum));
        }

        if (istcp) {
            // set TCP seq and adjust TCP flags
            auto tcp = tdutil::start_lifetime_as<tcphdr>(&thispkt[vnethdr.csum_start]);
            assign_big_from_native(tcp->seq, tcpseq0 + vnethdr.gso_size * i);
            if (datalen < rest.size())
                // FIN and PSH should only be set on last segment
                tcp->fin = tcp->psh = 0;
        } else {
            // set UDP header len
            auto udp = tdutil::start_lifetime_as<udphdr>(&thispkt[vnethdr.csum_start]);
            assign_big_from_native(udp->len, thispkt.size() - vnethdr.csum_start);
        }

        auto l4_csum = calc_l4_checksum(thispkt, isv6, istcp, vnethdr.csum_start);
        // native order
        memcpy(&thispkt[l4_csum_offset], &l4_csum, sizeof(l4_csum));

        // to next packet
        rest = rest.subspan(datalen);
    }

    return PacketBatch{
        .data = std::span(outbuf.begin(), pbsize),
        .segment_size = prefix.size() + vnethdr.gso_size,
        .isv6 = isv6,
        .ecn = ecn,
    };
}

} // namespace wireglider::worker_impl
