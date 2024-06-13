#pragma once

#include <cassert>
#include <algorithm>
#include <fmt/format.h>

using gfp_t = unsigned int;

bool _do_warn(bool val, const char *warn);
bool _do_bug(bool val, const char *bug);

#define WARN_ON(x) _do_warn(x, #x)
#define WARN_ON_ONCE(x) WARN_ON(x)
#define BUG_ON(x) _do_bug(x, #x);
