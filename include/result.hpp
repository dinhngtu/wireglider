#pragma once

#include <boost/outcome.hpp>
#include <system_error>

namespace outcome = BOOST_OUTCOME_V2_NAMESPACE;

namespace wgss {

static constexpr bool is_eagain(int e = errno) {
    return e == EAGAIN || e == EWOULDBLOCK;
}

static inline outcome::failure_type<std::error_code> fail(int e = errno) {
    return outcome::failure_type<std::error_code>(std::error_code(e, std::system_category()));
}

static inline outcome::failure_type<std::error_code> check_eagain(int e = errno, const char *what = nullptr) {
    if (is_eagain(e))
        return fail(e);
    else
        throw std::system_error(e, std::system_category(), what);
}

} // namespace wgss
