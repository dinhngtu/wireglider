#pragma once

#include <deque>

#include "worker/flowkey.hpp"

namespace wireglider::worker_impl {

using TunWriteQueue = std::deque<OwnedPacketBatch>;

} // namespace wireglider::worker_impl
