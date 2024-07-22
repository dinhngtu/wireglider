#pragma once

#include <cassert>
#include <sys/uio.h>
#include <mimalloc.h>

struct sq_ticket {
    constexpr sq_ticket() {
    }
    virtual ~sq_ticket() = default;
};
