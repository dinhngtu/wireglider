#pragma once

// C++-compatible version of linux/virtio_net.h
#define class cmd_class
#include <linux/virtio_net.h> // IWYU pragma: export
#undef class
