#include <sys/signalfd.h>
#include <fmt/format.h>

#include "worker_ring.hpp"

using namespace boost::endian;
using namespace tdutil;
using namespace wireglider::uring;

namespace wireglider {

void worker_ring_func(WorkerArg arg) : _ring(512, 0) {
    RingWorker w(arg);
    w.run();
}

RingWorker::RingWorker(const WorkerArg &arg) : _arg(arg) {
}

void RingWorker::run() {
    auto wn = fmt::format("ring{}", _arg.id);
    pthread_setname_np(pthread_self(), wn.c_str());

    rcu_register_thread();

    sigset_t sigs;
    make_exit_sigset(sigs);
    _sigfd = FileDescriptor(signalfd(-1, &sigs, 0));

    sq_ticket sigfd_ticket;
    auto sigfd_sqe = _ring.queue_poll_add(&sigfd_ticket, false, _sigfd, POLLIN);
    sigfd_sqe->flags |= IOSQE_ASYNC;

    //bufring br(_ring, );

    sq_kick();
}

} // namespace wireglider
