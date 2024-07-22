#pragma once

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

#include <cstddef>
#include <cstdint>
#include <climits>
#include <array>
#include <bit>

#include "disposable.hpp"

namespace wireglider::proto {

// Implements an efficient anti-replay algorithm as specified in RFC 6479.
template <typename T, size_t Size, typename BackingType = uint64_t>
class ReplayRing {
    static_assert(std::has_single_bit(sizeof(BackingType)));
    static const size_t BlockBits = sizeof(BackingType) * CHAR_BIT;
    static_assert(std::has_single_bit(Size) && Size > BlockBits);
    static const size_t BlockBitLog = std::countr_zero(BlockBits);
    static const size_t RingBlocks = Size / BlockBits;
    static const size_t BlockMask = RingBlocks - 1;
    static const T BitMask = BlockBits - 1;
    static const T WindowSize = Size - BlockBits;

public:
    ReplayRing(T limit) noexcept : _limit(limit) {
        _ring[0] = 0;
    }
    DISPOSABLE(ReplayRing);

    bool try_advance(T counter) noexcept {
        if (counter >= _limit) {
            return false;
        }
        size_t indexBlock = size_t(counter) >> BlockBitLog;
        if (counter > _last) { // move window forward
            size_t current = size_t(_last) >> BlockBitLog;
            // cap diff to clear the whole ring
            size_t diff = indexBlock - current;
            if (diff > RingBlocks) {
                diff = RingBlocks; // cap diff to clear the whole ring
            }
            for (size_t i = current + 1; i <= current + diff; i++) {
                _ring[i & BlockMask] = 0;
            }
            _last = counter;
        } else if (_last - counter > WindowSize) { // behind current window
            return false;
        }
        // check and set bit
        indexBlock &= BlockMask;
        auto indexBit = counter & BitMask;
        auto oldval = _ring[indexBlock];
        auto newval = oldval | (BackingType(1) << indexBit);
        _ring[indexBlock] = newval;
        return oldval != newval;
    }

    constexpr T window_size() const noexcept {
        return WindowSize;
    }

    void reset() noexcept {
        _last = 0;
        _ring[0] = 0;
    }

    constexpr DEFAULT_SWAP(ReplayRing, _ring, _last, _limit);

private:
    void dispose() noexcept {
        reset();
    }

    std::array<BackingType, RingBlocks> _ring;
    T _last = 0;
    T _limit;
};

} // namespace wireglider::proto
