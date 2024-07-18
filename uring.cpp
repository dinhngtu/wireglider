#include <cassert>
#include <algorithm>
#include <memory>
#include <exception>
#include <system_error>

#include "uring.hpp"

namespace wireglider::uring {

void uring::uring_deleter(struct io_uring *ring) {
    io_uring_queue_exit(ring);
    delete ring;
}

static tdutil::auto_handle<uring_free> uring_create(unsigned int entries, unsigned int flags) {
    auto ring = new io_uring();
    auto ret = io_uring_queue_init(entries, ring, flags);
    if (ret < 0) {
        delete ring;
        throw std::system_error(-ret, std::generic_category(), "io_uring_queue_init");
    }
    return tdutil::auto_handle<uring_free>(ring);
}

[[maybe_unused]] static bool is_in_range(const void *out_p, size_t out_s, const void *in_p, size_t in_s) {
    auto out_e = reinterpret_cast<uintptr_t>(out_p) + out_s;
    uintptr_t in_e = 0;
    if (__builtin_add_overflow(reinterpret_cast<uintptr_t>(in_p), in_s, &in_e))
        return false;
    return in_p >= out_p && in_e <= out_e;
}

uring::uring(unsigned int entries, unsigned int flags, std::span<const int> fixed_files, std::span<iovec> fixed_buffers)
    : _fixed(fixed_files.begin(), fixed_files.end()), _bufs(fixed_buffers.begin(), fixed_buffers.end()),
      _ring(uring_create(entries, flags)) {
    if (!fixed_files.empty()) {
        auto ret = io_uring_register_files(_ring.get(), _fixed.data(), _fixed.size());
        if (ret < 0) {
            throw std::system_error(-ret, std::generic_category(), "cannot register uring files");
        }
    }
    if (!fixed_buffers.empty()) {
        auto ret = io_uring_register_buffers(_ring.get(), _bufs.data(), _bufs.size());
        if (ret < 0) {
            throw std::system_error(-ret, std::generic_category(), "cannot register uring buffers");
        }
    }
}

io_uring_sqe *uring::queue_read(
    sq_ticket *ticket,
    void *buf,
    unsigned int nbytes,
    int buf_index,
    bool fixed,
    int fid,
    off_t offset) {
    auto sqe = get_sqe();
    if (buf_index >= 0) {
        assert(buf_index < _bufs.size());
        assert(is_in_range(_bufs[buf_index].iov_base, _bufs[buf_index].iov_len, buf, nbytes));
        io_uring_prep_read_fixed(sqe, fid, buf, nbytes, offset, buf_index);
    } else {
        io_uring_prep_read(sqe, fid, buf, nbytes, offset);
    }
    io_uring_sqe_set_flags(sqe, fixed ? IOSQE_FIXED_FILE : 0);
    io_uring_sqe_set_data(sqe, ticket);
    return sqe;
}

io_uring_sqe *uring::queue_write(
    sq_ticket *ticket,
    const void *buf,
    unsigned int nbytes,
    int buf_index,
    bool fixed,
    int fid,
    off_t offset) {
    auto sqe = get_sqe();
    if (buf_index >= 0) {
        assert(buf_index < _bufs.size());
        assert(is_in_range(_bufs[buf_index].iov_base, _bufs[buf_index].iov_len, buf, nbytes));
        io_uring_prep_write_fixed(sqe, fid, buf, nbytes, offset, buf_index);
    } else {
        io_uring_prep_write(sqe, fid, buf, nbytes, offset);
    }
    io_uring_sqe_set_flags(sqe, fixed ? IOSQE_FIXED_FILE : 0);
    io_uring_sqe_set_data(sqe, ticket);
    return sqe;
}

io_uring_sqe *uring::queue_readv(
    sq_ticket *ticket,
    std::span<const iovec> iovecs,
    bool fixed,
    int fid,
    off_t offset,
    int flags) {
    auto sqe = get_sqe();
    io_uring_prep_readv2(sqe, fid, iovecs.data(), iovecs.size(), offset, flags);
    io_uring_sqe_set_flags(sqe, fixed ? IOSQE_FIXED_FILE : 0);
    io_uring_sqe_set_data(sqe, ticket);
    return sqe;
}

io_uring_sqe *uring::queue_writev(
    sq_ticket *ticket,
    std::span<const iovec> iovecs,
    bool fixed,
    int fid,
    off_t offset,
    int flags) {
    auto sqe = get_sqe();
    io_uring_prep_writev2(sqe, fid, iovecs.data(), iovecs.size(), offset, flags);
    io_uring_sqe_set_flags(sqe, fixed ? IOSQE_FIXED_FILE : 0);
    io_uring_sqe_set_data(sqe, ticket);
    return sqe;
}

io_uring_sqe *uring::queue_fallocate(sq_ticket *ticket, bool fixed, int fid, int mode, off_t offset, off_t len) {
    auto sqe = get_sqe();
    io_uring_prep_fallocate(sqe, fid, mode, offset, len);
    io_uring_sqe_set_flags(sqe, fixed ? IOSQE_FIXED_FILE : 0);
    io_uring_sqe_set_data(sqe, ticket);
    return sqe;
}

io_uring_sqe *uring::queue_fsync(sq_ticket *ticket, bool fixed, int fid, unsigned int flags) {
    auto sqe = get_sqe();
    io_uring_prep_fsync(sqe, fid, flags);
    io_uring_sqe_set_flags(sqe, fixed ? IOSQE_FIXED_FILE : 0);
    io_uring_sqe_set_data(sqe, ticket);
    return sqe;
}

io_uring_sqe *uring::queue_poll_add(sq_ticket *ticket, bool fixed, int fid, unsigned int poll_mask) {
    auto sqe = get_sqe();
    io_uring_prep_poll_add(sqe, fid, poll_mask);
    io_uring_sqe_set_flags(sqe, fixed ? IOSQE_FIXED_FILE : 0);
    io_uring_sqe_set_data(sqe, ticket);
    return sqe;
}

cq_window uring::cq_get_ready(const std::span<io_uring_cqe *> &cqebuf) {
    auto rdy = io_uring_peek_batch_cqe(_ring.get(), cqebuf.data(), cqebuf.size());
    return cq_window(cqebuf.subspan(0, rdy));
}

std::span<sq_ticket *> uring::cq_commit(cq_window &wnd, const std::span<sq_ticket *> &ticketbuf) {
    size_t count = 0;
    auto it = wnd.cqes.begin();
    auto ot = ticketbuf.begin();
    for (; it != wnd.cqes.end() && ot != ticketbuf.end(); it++, ot++, count++)
        *ot = static_cast<sq_ticket *>(io_uring_cqe_get_data(*it));
    io_uring_cq_advance(_ring.get(), count);
    wnd.cqes = wnd.cqes.subspan(count);
    return ticketbuf.subspan(0, count);
}

void uring::cq_commit(cq_window &wnd) {
    io_uring_cq_advance(_ring.get(), wnd.cqes.size());
}

} // namespace wireglider::uring
