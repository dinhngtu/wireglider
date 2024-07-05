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

namespace wireglider {

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
template <typename V, typename K, typename Tag>
concept IsCdsHashtableNode = requires(V v, Tag tag, cds_lfht_node *node) {
    { v.key(tag) } -> std::convertible_to<const K &>;
    { v.node(tag) } -> std::convertible_to<cds_lfht_node &>;
    { V::get_from(node, tag) } -> std::convertible_to<V *>;
};

template <std::totally_ordered K, typename Tag, IsCdsHashtableNode<K, Tag> V>
class CdsHashtable;

template <typename K, typename Tag, IsCdsHashtableNode<K, Tag> V>
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
        return *this;
    }
    CdsHashtableIterator operator++(int) {
        CdsHashtableIterator tmp(*this);
        ++*this;
        return tmp;
    }

    pointer get() const {
        return _iter.node ? V::get_from(_iter.node, Tag{}) : nullptr;
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

    friend class CdsHashtable<K, Tag, V>;

private:
    explicit CdsHashtableIterator(cds_lfht *tbl) : _tbl(tbl) {
    }

    cds_lfht *_tbl = nullptr;
    cds_lfht_iter _iter{};
};

template <std::totally_ordered K, typename Tag, IsCdsHashtableNode<K, Tag> V>
class CdsHashtable {
public:
    using iterator = CdsHashtableIterator<K, Tag, V>;

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

    iterator begin([[maybe_unused]] const RundownGuard &rcu) {
        iterator it(_tbl);
        cds_lfht_first(_tbl, &it._iter);
        return it;
    }
    iterator end() {
        iterator it(_tbl);
        return it;
    }

    std::pair<V *, bool> try_insert([[maybe_unused]] const RundownGuard &rcu, V *v) {
        auto old = cds_lfht_add_unique(_tbl, std::hash<K>()(v->key(Tag{})), compare, &v->key(Tag{}), &v->node(Tag{}));
        // old is never null
        if (old == &v->node(Tag{}))
            return std::make_pair(v, true);
        else
            return std::make_pair(V::get_from(old, Tag{}), false);
    }

    V *replace([[maybe_unused]] const RundownGuard &rcu, V *v) {
        auto old = cds_lfht_add_replace(_tbl, std::hash<K>()(v->key(Tag{})), compare, &v->key(Tag{}), &v->node(Tag{}));
        if (old)
            return V::get_from(old, Tag{});
        else
            return nullptr;
    }

    iterator find([[maybe_unused]] const RundownGuard &rcu, const K &k) {
        iterator it(_tbl);
        cds_lfht_lookup(_tbl, std::hash<K>{}(k), compare, &k, &it._iter);
        return it;
    }

    bool erase([[maybe_unused]] const RundownGuard &rcu, iterator it) {
        auto err = cds_lfht_del(_tbl, it._iter.node);
        return err == 0;
    }

    void clear([[maybe_unused]] const RundownGuard &rcu) {
        cds_lfht_iter it;
        cds_lfht_node *node;
        cds_lfht_for_each(_tbl, &it, node) {
            cds_lfht_del(_tbl, node);
        }
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

    bool erase_at([[maybe_unused]] const RundownGuard &rcu, V *v) {
        auto err = cds_lfht_del(_tbl, &v->node(Tag{}));
        return err == 0;
    }

    bool is_erased([[maybe_unused]] const RundownGuard &rcu, V *v) {
        return cds_lfht_is_node_deleted(&v.node(Tag{}));
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
        const K &leftkey = V::get_from(node, Tag{})->key(Tag{});
        return leftkey == *static_cast<const K *>(key);
    }

private:
    cds_lfht *_tbl = nullptr;
};

template <std::totally_ordered K, typename Tag, IsCdsHashtableNode<K, Tag> V>
constexpr CdsHashtable<K, Tag, V>::iterator begin(CdsHashtable<K, Tag, V> &ht) {
    return ht.begin();
}

template <std::totally_ordered K, typename Tag, IsCdsHashtableNode<K, Tag> V>
constexpr CdsHashtable<K, Tag, V>::iterator end(CdsHashtable<K, Tag, V> &ht) {
    return ht.end();
}

} // namespace wireglider
