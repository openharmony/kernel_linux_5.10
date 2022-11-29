/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/block/zram/zram_group/zlist.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _ZLIST_H_
#define _ZLIST_H_

#define ZLIST_IDX_SHIFT 30
#define ZLIST_LOCK_BIT ZLIST_IDX_SHIFT
#define ZLIST_PRIV_BIT ((ZLIST_IDX_SHIFT << 1) + 1)

#define ZLIST_IDX_MAX (1 << ZLIST_IDX_SHIFT)

struct zlist_node {
	u64 prev	: ZLIST_IDX_SHIFT;
	u64 lock	: 1;
	u64 next	: ZLIST_IDX_SHIFT;
	u64 priv	: 1;
};

struct zlist_table {
	struct zlist_node *(*idx2node)(u32 idx, void *priv);
	void *private;
};

static inline struct zlist_node *idx2node(u32 idx, struct zlist_table *tab)
{
	return tab->idx2node(idx, tab->private);
}

static inline u32 next_idx(u32 idx, struct zlist_table *tab)
{
	return idx2node(idx, tab)->next;
}

static inline u32 prev_idx(u32 idx, struct zlist_table *tab)
{
	return idx2node(idx, tab)->prev;
}

static inline void zlist_table_free(struct zlist_table *tab)
{
	kfree(tab);
}

struct zlist_table *zlist_table_alloc(struct zlist_node *(*i2n)(u32, void*),
					void *private, gfp_t gfp);

void zlist_lock(u32 idx, struct zlist_table *tab);
void zlist_unlock(u32 idx, struct zlist_table *tab);

void zlist_add_nolock(u32 hid, u32 idx, struct zlist_table *tab);
void zlist_add_tail_nolock(u32 hid, u32 idx, struct zlist_table *tab);
bool zlist_del_nolock(u32 hid, u32 idx, struct zlist_table *tab);
bool zlist_is_isolated_nolock(u32 idx, struct zlist_table *tab);

static inline void zlist_add(u32 hid, u32 idx, struct zlist_table *tab)
{
	zlist_lock(hid, tab);
	zlist_add_nolock(hid, idx, tab);
	zlist_unlock(hid, tab);
}

static inline void zlist_add_tail(u32 hid, u32 idx, struct zlist_table *tab)
{
	zlist_lock(hid, tab);
	zlist_add_tail_nolock(hid, idx, tab);
	zlist_unlock(hid, tab);
}

static inline bool zlist_del(u32 hid, u32 idx, struct zlist_table *tab)
{
	bool ret = false;

	zlist_lock(hid, tab);
	ret = zlist_del_nolock(hid, idx, tab);
	zlist_unlock(hid, tab);

	return ret;
}

bool zlist_set_priv(u32 idx, struct zlist_table *tab);
bool zlist_clr_priv_nolock(u32 idx, struct zlist_table *tab);
bool zlist_test_priv_nolock(u32 idx, struct zlist_table *tab);

void zlist_node_init(u32 idx, struct zlist_table *tab);

#define zlist_for_each_entry(idx, hid, tab) \
	for ((idx) = next_idx(hid, tab); (idx) != (hid);  \
		(idx) = next_idx(idx, tab))
#define zlist_for_each_entry_reverse(idx, hid, tab) \
	for ((idx) = prev_idx(hid, tab); (idx) != (hid);  \
		(idx) = prev_idx(idx, tab))
#endif
