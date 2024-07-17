#include <system_error>
#include <tdutil/time.hpp>
#include "tai64n.hpp"

using namespace tdutil::operators;

namespace wireglider::time {

TAI64NClock::TAI64NClock() {
    _realtime_origin = gettime(CLOCK_REALTIME);
    _mono_origin = gettime(CLOCK_MONOTONIC);
}

TAI64N TAI64NClock::get(bool whiten) {
    auto mono_now = gettime(CLOCK_MONOTONIC);
    auto time_now = _realtime_origin + (mono_now - _mono_origin);
    if (whiten)
        time_now.tv_nsec -= time_now.tv_nsec % 0x1000000l;
    return TAI64N(time_now);
}

} // namespace wireglider::time
