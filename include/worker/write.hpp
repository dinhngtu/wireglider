#pragma once

#include <deque>
#include <vector>

#include "result.hpp"
#include "worker/flowkey_own.hpp"
#include "worker/flowkey_ref.hpp"

namespace wireglider::worker_impl {

using TunWriteQueue = std::deque<OwnedPacketBatch>;

outcome::result<void> write_one_batch(int fd, OwnedPacketBatch &opb);
outcome::result<void> write_one_batch(int fd, PacketRefBatch &prb);
outcome::result<void> do_tun_write_unrel(int fd, std::deque<std::vector<uint8_t>> &pkts);
outcome::result<void> do_tun_write_unrel(int fd, DecapRefBatch::unrel_type &pkts);
outcome::result<void> do_tun_write_batch(int fd, DecapBatch &batch);
outcome::result<void> do_tun_write_batch(int fd, DecapRefBatch &batch);

} // namespace wireglider::worker_impl
