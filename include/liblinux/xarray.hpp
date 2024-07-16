#pragma once

/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * eXtensible Arrays
 * Copyright (c) 2017 Microsoft Corporation
 * Author: Matthew Wilcox <willy@infradead.org>
 *
 * See Documentation/core-api/xarray.rst for how to use the XArray.
 */

#include <cstdint>
#include <pthread.h>
#include "liblinux/kernel_compat_internal.hpp"
#include "rundown.hpp"

/*
 * The bottom two bits of the entry determine how the XArray interprets
 * the contents:
 *
 * 00: Pointer entry
 * 10: Internal entry
 * x1: Value entry or tagged pointer
 *
 * Attempting to store internal entries in the XArray is a bug.
 *
 * Most internal entries are pointers to the next node in the tree.
 * The following internal entries have a special meaning:
 *
 * 0-62: Sibling entries
 * 256: Retry entry
 * 257: Zero entry
 *
 * Errors are also represented as internal entries, but use the negative
 * space (-4094 to -2).  They're never stored in the slots array; only
 * returned by the normal API.
 */

#define BITS_PER_XA_VALUE (BITS_PER_LONG - 1)

/**
 * xa_mk_value() - Create an XArray entry from an integer.
 * @v: Value to store in XArray.
 *
 * Context: Any context.
 * Return: An entry suitable for storing in the XArray.
 */
static inline void *xa_mk_value(unsigned long v) {
    WARN_ON((long)v < 0);
    return (void *)((v << 1) | 1);
}

/**
 * xa_to_value() - Get value stored in an XArray entry.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: The value stored in the XArray entry.
 */
static inline unsigned long xa_to_value(const void *entry) {
    return (unsigned long)entry >> 1;
}

/**
 * xa_is_value() - Determine if an entry is a value.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: True if the entry is a value, false if it is a pointer.
 */
static inline bool xa_is_value(const void *entry) {
    return (unsigned long)entry & 1;
}

/**
 * xa_tag_pointer() - Create an XArray entry for a tagged pointer.
 * @p: Plain pointer.
 * @tag: Tag value (0, 1 or 3).
 *
 * If the user of the XArray prefers, they can tag their pointers instead
 * of storing value entries.  Three tags are available (0, 1 and 3).
 * These are distinct from the xa_mark_t as they are not replicated up
 * through the array and cannot be searched for.
 *
 * Context: Any context.
 * Return: An XArray entry.
 */
static inline void *xa_tag_pointer(void *p, unsigned long tag) {
    return (void *)((unsigned long)p | tag);
}

/**
 * xa_untag_pointer() - Turn an XArray entry into a plain pointer.
 * @entry: XArray entry.
 *
 * If you have stored a tagged pointer in the XArray, call this function
 * to get the untagged version of the pointer.
 *
 * Context: Any context.
 * Return: A pointer.
 */
static inline void *xa_untag_pointer(void *entry) {
    return (void *)((unsigned long)entry & ~3UL);
}

/**
 * xa_pointer_tag() - Get the tag stored in an XArray entry.
 * @entry: XArray entry.
 *
 * If you have stored a tagged pointer in the XArray, call this function
 * to get the tag of that pointer.
 *
 * Context: Any context.
 * Return: A tag.
 */
static inline unsigned int xa_pointer_tag(void *entry) {
    return (unsigned long)entry & 3UL;
}

/*
 * xa_mk_internal() - Create an internal entry.
 * @v: Value to turn into an internal entry.
 *
 * Internal entries are used for a number of purposes.  Entries 0-255 are
 * used for sibling entries (only 0-62 are used by the current code).  256
 * is used for the retry entry.  257 is used for the reserved / zero entry.
 * Negative internal entries are used to represent errnos.  Node pointers
 * are also tagged as internal entries in some situations.
 *
 * Context: Any context.
 * Return: An XArray internal entry corresponding to this value.
 */
static inline void *xa_mk_internal(unsigned long v) {
    return (void *)((v << 2) | 2);
}

/*
 * xa_to_internal() - Extract the value from an internal entry.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: The value which was stored in the internal entry.
 */
static inline unsigned long xa_to_internal(const void *entry) {
    return (unsigned long)entry >> 2;
}

/*
 * xa_is_internal() - Is the entry an internal entry?
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: %true if the entry is an internal entry.
 */
static inline bool xa_is_internal(const void *entry) {
    return ((unsigned long)entry & 3) == 2;
}

#define XA_ZERO_ENTRY xa_mk_internal(257)

/**
 * xa_is_zero() - Is the entry a zero entry?
 * @entry: Entry retrieved from the XArray
 *
 * The normal API will return NULL as the contents of a slot containing
 * a zero entry.  You can only see zero entries by using the advanced API.
 *
 * Return: %true if the entry is a zero entry.
 */
static inline bool xa_is_zero(const void *entry) {
    return unlikely(entry == XA_ZERO_ENTRY);
}

/**
 * xa_is_err() - Report whether an XArray operation returned an error
 * @entry: Result from calling an XArray function
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special value indicating an error.  This function tells you
 * whether an error occurred; xa_err() tells you which error occurred.
 *
 * Context: Any context.
 * Return: %true if the entry indicates an error.
 */
static inline bool xa_is_err(const void *entry) {
    return unlikely(xa_is_internal(entry) && entry >= xa_mk_internal(-MAX_ERRNO));
}

/**
 * xa_err() - Turn an XArray result into an errno.
 * @entry: Result from calling an XArray function.
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special pointer value which encodes an errno.  This function extracts
 * the errno from the pointer value, or returns 0 if the pointer does not
 * represent an errno.
 *
 * Context: Any context.
 * Return: A negative errno or 0.
 */
static inline int xa_err(void *entry) {
    /* xa_to_internal() would not do sign extension. */
    if (xa_is_err(entry))
        return (long)entry >> 2;
    return 0;
}

/* Private */
static inline void *xa_mk_node(const struct xa_node *node) {
    return (void *)((unsigned long)node | 2);
}

/* Private */
static inline struct xa_node *xa_to_node(const void *entry) {
    return (struct xa_node *)((unsigned long)entry - 2);
}

/* Private */
static inline bool xa_is_node(const void *entry) {
    return xa_is_internal(entry) && (unsigned long)entry > 4096;
}

#define XA_RETRY_ENTRY xa_mk_internal(256)

/**
 * xa_is_retry() - Is the entry a retry entry?
 * @entry: Entry retrieved from the XArray
 *
 * Return: %true if the entry is a retry entry.
 */
static inline bool xa_is_retry(const void *entry) {
    return unlikely(entry == XA_RETRY_ENTRY);
}

/**
 * xa_is_advanced() - Is the entry only permitted for the advanced API?
 * @entry: Entry to be stored in the XArray.
 *
 * Return: %true if the entry cannot be stored by the normal API.
 */
static inline bool xa_is_advanced(const void *entry) {
    return xa_is_internal(entry) && (entry <= XA_RETRY_ENTRY);
}
