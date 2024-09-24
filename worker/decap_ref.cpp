#include "proto.hpp"
#include "worker.hpp"
#include <variant>

using namespace wireglider::proto;
using namespace wireglider::worker_impl;

namespace wireglider {

/*
static std::span<uint8_t> tunnel_flush(
    [[maybe_unused]] RundownGuard &rcu,
    [[maybe_unused]] std::lock_guard<std::mutex> &lock,
    boost::container::small_vector_base<iovec> &serversend,
    wireguard_tunnel_raw *tunnel,
    std::span<uint8_t> scratch) {
    auto remain = scratch;
    while (1) {
        auto result = wireguard_read_raw(tunnel, nullptr, 0, remain.data(), remain.size());
        switch (result.op) {
        case WRITE_TO_NETWORK:
            DBG_PRINT("tunnel flush v4 {}\n", result.size);
            serversend.push_back({&remain[0], result.size});
            remain = remain.subspan(result.size);
            break;
        case WIREGUARD_DONE:
            return remain;
        case WIREGUARD_ERROR:
        default:
            DBG_PRINT("unexpected tunnel_flush result {}\n", static_cast<int>(result.op));
            return remain;
        }
    }
}
 */

std::optional<DecapRefBatch> Worker::do_server_decap_ref(
    PacketBatch pb,
    ClientEndpoint ep,
    std::vector<uint8_t> &memory) {
    RundownGuard rcu;
    auto it = _arg.client_eps->find(rcu, ep);
    if (it == _arg.client_eps->end())
        return std::nullopt;

    DecapRefBatch batch(_arg.tun_has_uso);
    auto now = time::gettime(CLOCK_MONOTONIC);
    {
        std::span remain(memory);
        auto state = it->state.synchronize();
        auto protosgn = ProtoSignal::Ok;
        for (auto pkt : pb) {
            auto ptype = state->peer->decode_pkt(pkt);
            if (auto hs1 = std::get_if<const Handshake1 *>(&ptype)) {
                {
                    auto config = _arg.config(rcu);
                    if (!state->peer->configure_responder(now, config->privkey, config->psk.key))
                        continue;
                }
                if (!state->peer->read_handshake1(*hs1, it->pubkey))
                    continue;
                auto hs2 = state->peer->write_handshake2(now, it->pubkey, remain);
                if (hs2)
                    batch.retpkt.push_back({remain.data(), sizeof(Handshake2)});
                else
                    continue;
                remain = remain.subspan(0, sizeof(Handshake2));
            } else if (auto hs2 = std::get_if<const Handshake2 *>(&ptype)) {
                if (!state->peer->read_handshake2(*hs2, now))
                    continue;
            } else if (std::holds_alternative<const CookiePacket *>(ptype)) {
                // not implemented
            } else if (std::holds_alternative<std::span<const uint8_t>>(ptype)) {
                auto result = state->peer->decrypt(now, remain, pkt);
                if (result) {
                    auto outsize = result.assume_value().outsize;
                    auto outpkt = remain.subspan(0, outsize);
                    remain = remain.subspan(outsize);
                    batch.push_packet(outpkt, pb.ecn);
                    protosgn &= result.assume_value().signal;
                }
            }
        }
        if (!!(protosgn & ProtoSignal::NeedsHandshake)) {
            auto hs = state->peer->write_handshake1(now, it->pubkey, remain);
            if (hs)
                batch.retpkt.push_back({remain.data(), sizeof(Handshake1)});
            else
                return std::nullopt;
        } else if (!!(protosgn & ProtoSignal::NeedsKeepalive)) {
            auto ka = state->peer->encrypt(now, remain, {});
            if (ka)
                batch.retpkt.push_back({remain.data(), ka.assume_value().outsize});
        }
    }

    return batch;
}

} // namespace wireglider
