#pragma once

#include <cstddef>
#include <cstdint>
#include <cassert>
#include <span>
#include <unistd.h>

namespace wireglider {

class PacketBatchIterator {
public:
    using difference_type = ssize_t;
    using value_type = std::span<const uint8_t>;

    constexpr PacketBatchIterator() {
    }
    template <typename It>
    constexpr explicit PacketBatchIterator(size_t segment_size, It first, It last)
        : _segment_size(segment_size), _span(first, last) {
    }

    PacketBatchIterator &operator++() {
        assert(!_span.empty());
        _span = _span.subspan(std::min(_span.size(), _segment_size));
        return *this;
    }
    PacketBatchIterator operator++(int) {
        PacketBatchIterator old = *this;
        ++*this;
        return old;
    }

    constexpr std::span<const uint8_t> operator*() const {
        return _span.subspan(0, std::min(_span.size(), _segment_size));
    }

    friend bool operator==(const PacketBatchIterator &a, const PacketBatchIterator &b) {
        return a._segment_size == b._segment_size &&
               ((a._span.empty() && b._span.empty()) ||
                (a._span.begin() == b._span.begin() && a._span.end() == b._span.end()));
    }

private:
    size_t _segment_size = 0;
    std::span<const uint8_t> _span{};
};

} // namespace wireglider
