#pragma once

#include <algorithm>
#include <vector>
#include <span>
#include <liburing.h>

#include "tdutil/auto_handle.hpp"
#include "tagging.hpp"
#include "disposable.hpp"

namespace wireglider::uring {

template <typename T>
constexpr void iovec_append(T &t, uint8_t *iov_base, size_t iov_len) {
    if (!t.empty() && iov_base == static_cast<uint8_t *>(t.back().iov_base) + t.back().iov_len) {
        t.back().iov_len += iov_len;
    } else {
        t.push_back({iov_base, iov_len});
    }
}

template <typename T>
constexpr void iovec_append(T &t, std::span<uint8_t> s) {
    iovec_append(t, s.data(), s.size());
}

constexpr bool iovec_try_append(iovec &v, uint8_t *iov_base, size_t iov_len) {
    if (v.iov_base && iov_base == static_cast<uint8_t *>(v.iov_base) + v.iov_len) {
        v.iov_len += iov_len;
        return true;
    } else {
        v = {iov_base, iov_len};
        return false;
    }
}

constexpr bool iovec_try_append(iovec &v, std::span<uint8_t> s) {
    return iovec_try_append(v, s.data(), s.size());
}

struct cq_window {
    cq_window(const cq_window &) = delete;
    cq_window &operator=(const cq_window &) = delete;
    cq_window(cq_window &&other) {
        std::swap(this->cqes, other.cqes);
    }
    cq_window &operator=(cq_window &&other) {
        this->cqes = std::span<io_uring_cqe *>{};
        std::swap(this->cqes, other.cqes);
        return *this;
    }
    ~cq_window() = default;

    std::span<io_uring_cqe *> cqes;

private:
    friend class uring;

    explicit cq_window(const std::span<io_uring_cqe *> &cqebuf) : cqes(cqebuf) {
    }
};

class uring {
public:
    explicit uring(
        unsigned int entries,
        unsigned int flags,
        std::span<const int> fixed_files = {},
        std::span<iovec> fixed_buffers = {});
    uring(const uring &) = delete;
    uring &operator=(const uring &) = delete;
    uring(uring &&other) = default;
    uring &operator=(uring &&other) = default;
    ~uring() = default;

    int sq_kick() {
        return io_uring_submit(_ring.get());
    }

    io_uring_sqe *queue_read(
        sq_ticket *ticket,
        void *buf,
        unsigned int nbytes,
        // pass -1 if not registered buffer
        int buf_index,
        bool fixed,
        int fid,
        off_t offset);
    io_uring_sqe *queue_write(
        sq_ticket *ticket,
        const void *buf,
        unsigned int nbytes,
        // pass -1 if not registered buffer
        int buf_index,
        bool fixed,
        int fid,
        off_t offset);
    io_uring_sqe *queue_readv(
        sq_ticket *ticket,
        std::span<const iovec> iovecs,
        bool fixed,
        int fid,
        off_t offset,
        int flags = 0);
    io_uring_sqe *queue_writev(
        sq_ticket *ticket,
        std::span<const iovec> iovecs,
        bool fixed,
        int fid,
        off_t offset,
        int flags = 0);
    io_uring_sqe *queue_fallocate(sq_ticket *ticket, bool fixed, int fid, int mode, off_t offset, off_t len);
    io_uring_sqe *queue_fsync(sq_ticket *ticket, bool fixed, int fid, unsigned int flags);

    io_uring_sqe *queue_poll_add(sq_ticket *ticket, bool fixed, int fid, unsigned int poll_mask);

    cq_window cq_get_ready(const std::span<io_uring_cqe *> &cqebuf);
    std::span<sq_ticket *> cq_commit(cq_window &wnd, const std::span<sq_ticket *> &ticketbuf);
    void cq_commit(cq_window &wnd);
    void cq_commit(io_uring_cqe *cqe) {
        io_uring_cqe_seen(_ring.get(), cqe);
    }

    int fd(size_t idx) const {
        return _fixed[idx];
    }

    io_uring *get() {
        return _ring.get();
    }

private:
    static void uring_deleter(struct io_uring *ring);

    struct io_uring_sqe *get_sqe() {
        io_uring_sqe *ret = io_uring_get_sqe(_ring.get());
        if (!ret)
            throw std::runtime_error("sqe full");
        return ret;
    };

    std::vector<int> _fixed;
    std::vector<iovec> _bufs;
    tdutil::auto_handle<uring_deleter> _ring;
};

class bufring {
public:
    explicit bufring(uring &uring, unsigned int nentries, int bgid, unsigned int flags)
        : _ring(uring.get()), _nentries(nentries), _bgid(bgid) {
        int ret;
        _br = io_uring_setup_buf_ring(_ring, _nentries, _bgid, 0, &ret);
        if (!_br)
            throw std::system_error(-ret, std::generic_category(), "io_uring_setup_buf_ring");
    }
    DISPOSABLE(bufring);

    constexpr int bgid() const {
        return _bgid;
    }

    constexpr friend void swap(bufring &self, bufring &other) noexcept {
        using std::swap;
        swap(self._ring, other._ring);
        swap(self._br, other._br);
        swap(self._nentries, other._nentries);
        swap(self._bgid, other._bgid);
    }

    friend constexpr bool operator==(const bufring &a, const bufring &b) noexcept {
        return a._br == b._br;
    }

private:
    void dispose() {
        if (_br)
            io_uring_free_buf_ring(_ring, _br, _nentries, _bgid);
        _ring = nullptr;
        _br = nullptr;
        _nentries = 0;
        _bgid = -1;
    }

private:
    struct io_uring *_ring = nullptr;
    struct io_uring_buf_ring *_br = nullptr;
    unsigned int _nentries = 0;
    int _bgid = -1;
};

} // namespace wireglider::uring
