#pragma once

#include <deque>

#include "worker/flowkey.hpp"

namespace wgss::worker_impl {

using TunWriteQueue = std::deque<OwnedPacketBatch>;

} // namespace wgss::worker_impl
