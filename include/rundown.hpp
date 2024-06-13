#pragma once

#include <exception>
#include <iterator>
#include <concepts>
#include <utility>
#include <optional>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvolatile"
#include <urcu-qsbr.h>
#include <urcu/rculfhash.h>
#pragma GCC diagnostic pop

namespace wgss {

class RundownGuard {
public:
    RundownGuard() {
        rcu_read_lock();
    }
    constexpr RundownGuard(const RundownGuard &) = delete;
    constexpr RundownGuard &operator=(const RundownGuard &) = delete;
    RundownGuard(RundownGuard &&other) = delete;
    RundownGuard &operator=(RundownGuard &&other) = delete;
    ~RundownGuard() {
        rcu_read_unlock();
    }
};

struct RundownException : public std::exception {};

struct CdsException : public std::exception {
    CdsException() {
    }
    explicit CdsException(int err) : errcode(err) {
    }
    std::optional<int> errcode;
};

// reversed typename order for use in constraints
template <typename V, typename K>
concept IsCdsHashtableNode = requires(V v) {
    { v._cds_lfht_key } -> std::same_as<K &>;
    { v._cds_lfht_node } -> std::same_as<cds_lfht_node &>;
};

template <typename K, typename V>
struct CdsHashtableNode {
    static V *get(cds_lfht_node *node) {
        return caa_container_of(node, V, _cds_lfht_node);
    }

    cds_lfht_node _cds_lfht_node;
    K _cds_lfht_key;
};

template <typename K, IsCdsHashtableNode<K> V>
class CdsHashtableIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type = V;
    using pointer = V *;
    using reference = V &;

    CdsHashtableIterator() {
    }

    CdsHashtableIterator &operator++() {
        cds_lfht_next(_tbl, &_iter);
    }
    CdsHashtableIterator operator++(int) {
        CdsHashtableIterator tmp(*this);
        ++*this;
        return tmp;
    }

    pointer get() const {
        return CdsHashtableNode<K, V>::get(_iter.node);
    }

    reference operator*() const {
        return *get();
    }
    pointer operator->() const {
        return get();
    }

    friend constexpr bool operator==(const CdsHashtableIterator &a, const CdsHashtableIterator &b) noexcept {
        return a._tbl == b._tbl && a._iter.node == b._iter.node;
    }

private:
    explicit CdsHashtableIterator(cds_lfht *tbl) : _tbl(tbl) {
    }

    cds_lfht *_tbl = nullptr;
    cds_lfht_iter _iter{};
};

template <std::totally_ordered K, IsCdsHashtableNode<K> V>
class CdsHashtable {
public:
    using iterator = CdsHashtableIterator<K, V>;

    CdsHashtable(
        unsigned long init_size,
        unsigned long min_nr_alloc_buckets,
        unsigned long max_nr_buckets,
        int flags,
        pthread_attr_t *attr) {
        _tbl = cds_lfht_new(init_size, min_nr_alloc_buckets, max_nr_buckets, flags, attr);
        if (!_tbl)
            throw CdsException();
    }
    constexpr CdsHashtable(const CdsHashtable &) = delete;
    constexpr CdsHashtable &operator=(const CdsHashtable &) = delete;
    CdsHashtable(CdsHashtable &&other) {
        swap(*this, other);
    }
    CdsHashtable &operator=(CdsHashtable &&other) {
        if (this != &other) {
            dispose();
            swap(*this, other);
        }
        return *this;
    };
    ~CdsHashtable() {
        dispose();
    }

    iterator begin() {
        iterator it(_tbl);
        cds_lfht_first(_tbl, &it._iter);
        return it;
    }
    iterator end() {
        iterator it(_tbl);
        return it;
    }

    std::pair<V *, bool> try_insert([[maybe_unused]] const RundownGuard &rcu, V *v) {
        auto old =
            cds_lfht_add_unique(_tbl, std::hash(v->_cds_lfht_key), compare, &v->_cds_lfht_key, &v->_cds_lfht_node);
        if (old == &v->_cds_lfht_node)
            return std::make_pair(v, true);
        else
            return std::make_pair(CdsHashtableNode<K, V>::get(old), false);
    }

    V *replace([[maybe_unused]] const RundownGuard &rcu, V *v) {
        auto old =
            cds_lfht_add_replace(_tbl, std::hash(v->_cds_lfht_key), compare, &v->_cds_lfht_key, &v->_cds_lfht_node);
        if (old)
            return CdsHashtableNode<K, V>::get(old);
        else
            return nullptr;
    }

    iterator find([[maybe_unused]] const RundownGuard &rcu, const K &k) {
        iterator it(_tbl);
        cds_lfht_lookup(_tbl, std::hash(k), compare, &k, &it._iter);
        return it;
    }

    void erase(iterator it) {
        auto err = cds_lfht_del(_tbl, it._iter.node);
        if (err)
            throw CdsException(err);
    }

    V *extract([[maybe_unused]] const RundownGuard &rcu, const K &k) {
        auto it = find(rcu, k);
        if (it != end()) {
            erase(it);
            return it.get();
        } else {
            return nullptr;
        }
    }

    void erase_at([[maybe_unused]] const RundownGuard &rcu, V *v) {
        auto err = cds_lfht_del(_tbl, v->_cds_lfht_node);
        if (err)
            throw CdsException(err);
    }

    bool is_erased([[maybe_unused]] const RundownGuard &rcu, V *v) {
        return cds_lfht_is_node_deleted(v._cds_lfht_node);
    }

    void resize(size_t newsize) {
        cds_lfht_resize(_tbl, newsize);
    }

    friend void swap(CdsHashtable &self, CdsHashtable &other) {
        using std::swap;
        swap(self._tbl, other._tbl);
    }

private:
    void dispose() {
        if (_tbl)
            cds_lfht_destroy(std::exchange(_tbl, nullptr), NULL);
    }

    static int compare(struct cds_lfht_node *node, const void *key) {
        K leftkey = CdsHashtableNode<K, V>::get(node)->_cds_lfht_key;
        switch (std::compare_three_way(leftkey, *static_cast<const K *>(key))) {
        case std::strong_ordering::less:
            return -1;
        case std::strong_ordering::equal:
            return 0;
        case std::strong_ordering::greater:
            return 1;
        }
    }

private:
    cds_lfht *_tbl = nullptr;
};

} // namespace wgss
