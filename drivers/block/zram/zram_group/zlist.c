// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/block/zram/zram_group/zlist.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#define pr_fmt(fmt) "[ZLIST]" fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/bit_spinlock.h>

#include "zlist.h"

#define assert(expr)							\
	do {								\
		if (expr)						\
			break;						\
		pr_err("assertion [%s] failed: in func<%s> at %s:%d\n",	\
			#expr, __func__, __FILE__, __LINE__);		\
		BUG();							\
	} while (0)

static inline void zlist_node_lock(struct zlist_node *node)
{
	bit_spin_lock(ZLIST_LOCK_BIT, (unsigned long *)node);
}

static inline void zlist_node_unlock(struct zlist_node *node)
{
	bit_spin_unlock(ZLIST_LOCK_BIT, (unsigned long *)node);
}

#ifdef CONFIG_ZLIST_DEBUG
static inline void zlist_before_add_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next)
{
	assert(idx2node(prev->next, tab) == next);
	assert(idx2node(next->prev, tab) == prev);
	assert(idx2node(node->prev, tab) == node);
	assert(idx2node(node->next, tab) == node);
}

static inline void zlist_after_add_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next)
{
	assert(idx2node(prev->next, tab) == node);
	assert(idx2node(next->prev, tab) == node);
	assert(idx2node(node->prev, tab) == prev);
	assert(idx2node(node->next, tab) == next);
}

static inline void zlist_before_del_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next)
{
	assert(idx2node(prev->next, tab) == node);
	assert(idx2node(next->prev, tab) == node);
	assert(idx2node(node->prev, tab) == prev);
	assert(idx2node(node->next, tab) == next);
}

static inline void zlist_after_del_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next)
{
	assert(idx2node(prev->next, tab) == next);
	assert(idx2node(next->prev, tab) == prev);
	assert(idx2node(node->prev, tab) == node);
	assert(idx2node(node->next, tab) == node);
}
#else
static inline void zlist_before_add_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next) {};
static inline void zlist_after_add_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next) {};
static inline void zlist_before_del_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next) {};
static inline void zlist_after_del_check(struct zlist_table *tab,
		struct zlist_node *prev, struct zlist_node *node,
		struct zlist_node *next) {};
#endif

struct zlist_table *zlist_table_alloc(struct zlist_node *(*i2n)(u32, void*),
					void *private, gfp_t gfp)
{
	struct zlist_table *tab = kmalloc(sizeof(struct zlist_table), gfp);

	if (!tab)
		return NULL;
	tab->idx2node = i2n;
	tab->private = private;

	return tab;
}

void zlist_lock(u32 idx, struct zlist_table *tab)
{
	zlist_node_lock(idx2node(idx, tab));
}

void zlist_unlock(u32 idx, struct zlist_table *tab)
{
	zlist_node_unlock(idx2node(idx, tab));
}

void zlist_add_nolock(u32 hid, u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);
	struct zlist_node *head = idx2node(hid, tab);
	u32 nid = head->next;
	struct zlist_node *next = idx2node(nid, tab);

	zlist_before_add_check(tab, head, node, next);
	if (idx != hid)
		zlist_node_lock(node);
	node->prev = hid;
	node->next = nid;
	if (idx != hid)
		zlist_node_unlock(node);
	head->next = idx;
	if (nid != hid)
		zlist_node_lock(next);
	next->prev = idx;
	if (nid != hid)
		zlist_node_unlock(next);
	zlist_after_add_check(tab, head, node, next);
}

void zlist_add_tail_nolock(u32 hid, u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);
	struct zlist_node *head = idx2node(hid, tab);
	u32 tid = head->prev;
	struct zlist_node *tail = idx2node(tid, tab);

	zlist_before_add_check(tab, tail, node, head);
	if (idx != hid)
		zlist_node_lock(node);
	node->prev = tid;
	node->next = hid;
	if (idx != hid)
		zlist_node_unlock(node);
	head->prev = idx;
	if (tid != hid)
		zlist_node_lock(tail);
	tail->next = idx;
	if (tid != hid)
		zlist_node_unlock(tail);
	zlist_after_add_check(tab, tail, node, head);
}

bool zlist_del_nolock(u32 hid, u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);
	u32 pid = node->prev;
	u32 nid = node->next;
	struct zlist_node *prev = idx2node(pid, tab);
	struct zlist_node *next = idx2node(nid, tab);

	zlist_before_del_check(tab, prev, node, next);
	if (idx != hid)
		zlist_node_lock(node);
	node->prev = idx;
	node->next = idx;
	if (idx != hid)
		zlist_node_unlock(node);
	if (pid != hid)
		zlist_node_lock(prev);
	prev->next = nid;
	if (pid != hid)
		zlist_node_unlock(prev);
	if (nid != hid)
		zlist_node_lock(next);
	next->prev = pid;
	if (nid != hid)
		zlist_node_unlock(next);
	zlist_after_del_check(tab, prev, node, next);

	return zlist_is_isolated_nolock(hid, tab);
}

bool zlist_is_isolated_nolock(u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);

	return (node->prev == idx) && (node->next == idx);
}

bool zlist_set_priv(u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);
	bool ret = false;

	zlist_node_lock(node);
	ret = !test_and_set_bit(ZLIST_PRIV_BIT, (unsigned long *)node);
	zlist_node_unlock(node);

	return ret;
}

bool zlist_clr_priv_nolock(u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);
	bool ret = false;

	ret = !test_and_clear_bit(ZLIST_PRIV_BIT, (unsigned long *)node);

	return ret;
}

bool zlist_test_priv_nolock(u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);
	bool ret = false;

	ret = test_bit(ZLIST_PRIV_BIT, (unsigned long *)node);

	return ret;
}

void zlist_node_init(u32 idx, struct zlist_table *tab)
{
	struct zlist_node *node = idx2node(idx, tab);

	memset(node, 0, sizeof(struct zlist_node));
	node->prev = idx;
	node->next = idx;
}
