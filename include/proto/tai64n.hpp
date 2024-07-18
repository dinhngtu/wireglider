#pragma once

#include <limits>
#include <time.h>
#include <boost/endian.hpp>

namespace wireglider::time {

constexpr uint64_t to_time(time_t sec, long nsec) {
    return static_cast<uint64_t>(sec) + static_cast<uint64_t>(nsec) * 1'000'000'000;
}

constexpr timespec to_timespec(uint64_t tm) {
    return timespec{
        static_cast<time_t>(tm / 1'000'000'000),
        static_cast<long>(tm % 1'000'000'000),
    };
}

// minimum valid timespec
static constexpr timespec timespec_min() {
    return {0, 0};
}

// maximum valid timespec
static constexpr timespec timespec_max() {
    return {std::numeric_limits<decltype(timespec::tv_sec)>::max(), 999999999};
}

static inline timespec gettime(clockid_t clockid) {
    timespec res;
    if (clock_gettime(clockid, &res) < 0)
        throw std::system_error(errno, std::system_category(), "clock_gettime");
    return res;
}

static inline uint64_t gettime64(clockid_t clockid) {
    timespec ts = gettime(clockid);
    return to_time(ts.tv_sec, ts.tv_nsec);
}

struct [[gnu::packed]] TAI64N {
    union {
        struct {
            boost::endian::big_uint64_t sec_be;
            boost::endian::big_uint32_t nsec_be;
        };
        uint8_t bytes[12];
    };

    constexpr TAI64N() {
        sec_be = 0;
        nsec_be = 0;
    }
    constexpr TAI64N(const timespec &ts) {
        sec_be = static_cast<uint64_t>(ts.tv_sec);
        nsec_be = static_cast<uint32_t>(ts.tv_nsec);
    }
};

constexpr auto operator<=>(const TAI64N &a, const TAI64N &b) {
    return std::tie(a.sec_be, a.nsec_be) <=> std::tie(b.sec_be, b.nsec_be);
}

class TAI64NClock {
public:
    TAI64NClock();
    TAI64N get(bool whiten = false);

private:
    timespec _realtime_origin, _mono_origin;
};

} // namespace wireglider::time
