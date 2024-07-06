#pragma once

#include <deque>

#include "worker/flowkey.hpp"
#include "worker/flowkey_ref.hpp"

namespace wireglider::worker_impl {

using TunWriteQueue = std::deque<OwnedPacketBatch>;

outcome::result<void> write_opb(int fd, OwnedPacketBatch &opb);
outcome::result<void> write_opb(int fd, PacketRefBatch &opb);
outcome::result<void> do_tun_write_unrel(int fd, std::deque<std::vector<uint8_t>> &pkts);
outcome::result<void> do_tun_write_unrel(int fd, DecapRefBatch::unrel_type &pkts);

} // namespace wireglider::worker_impl
