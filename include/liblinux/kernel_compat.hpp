#pragma once

#include <cassert>
#include <algorithm>

using gfp_t = unsigned int;

bool _do_warn(bool val, const char *warn);
bool _do_bug(bool val, const char *bug);

#define WARN_ON(x) _do_warn(x, #x)
#define WARN_ON_ONCE(x) WARN_ON(x)
#define BUG_ON(x) _do_bug(x, #x);

using spinlock_t = pthread_mutex_t;
#define __SPIN_LOCK_UNLOCKED(x) PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#define spin_lock(x) pthread_mutex_lock(x)
#define spin_lock_nested(x, c) pthread_mutex_lock(x)
#define spin_unlock(x) pthread_mutex_unlock(x)
#define spin_lock_init(x) pthread_mutex_init((x), NULL);
#define container_of caa_container_of
