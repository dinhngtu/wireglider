#pragma once

#include "uring.hpp"
#include "worker/arg.hpp"

namespace wireglider {

class RingWorker {
public:
    RingWorker(const WorkerArg &arg);

    void run();

private:
    WorkerArg _arg;
    uring::uring _ring;
    tdutil::FileDescriptor _sigfd;
};

void worker_ring_func(WorkerArg arg);

} // namespace wireglider
