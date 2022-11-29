/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/block/zram/zram_group/zram_group.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _ZRAM_GROUP_H_
#define _ZRAM_GROUP_H_

#include <linux/kernel.h>
#include <linux/mutex.h>

#include "zlist.h"

#define ZGRP_MAX_GRP USHRT_MAX
#define ZGRP_MAX_OBJ (1 << 30)

enum {
	ZGRP_NONE = 0,
	ZGRP_TRACK,
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	ZGRP_WRITE,
#endif
};

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
#define ZGRP_MAX_EXT (ZLIST_IDX_MAX - ZGRP_MAX_GRP - ZGRP_MAX_OBJ)
struct writeback_group {
	bool enable;
	u32 nr_ext;
	struct zlist_node *grp_ext_head;
	struct zlist_node *ext;
	struct zlist_table *ext_tab;
	struct zlist_node *ext_obj_head;
	struct mutex init_lock;
	wait_queue_head_t fault_wq;
};
#endif

struct zram_group_stats {
	atomic64_t zram_size;
	atomic_t zram_pages;
	atomic64_t zram_fault;
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	atomic64_t wb_size;
	atomic_t wb_pages;
	atomic64_t wb_fault;
	atomic_t wb_exts;
	atomic64_t write_size;
	atomic64_t read_size;
#endif
};

struct zram_group {
	u32 nr_obj;
	u32 nr_grp;
	struct zlist_node *grp_obj_head;
	struct zlist_node *obj;
	struct zlist_table *obj_tab;
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	struct writeback_group wbgrp;
#endif
	struct group_swap_device *gsdev;
	struct zram_group_stats *stats;
};

void zram_group_meta_free(struct zram_group *zgrp);
struct zram_group *zram_group_meta_alloc(u32 nr_obj, u32 nr_grp);
void zgrp_obj_insert(struct zram_group *zgrp, u32 index, u16 gid);
bool zgrp_obj_delete(struct zram_group *zgrp, u32 index, u16 gid);
u32 zgrp_isolate_objs(struct zram_group *zgrp, u16 gid,	u32 *idxs, u32 nr, bool *last);
bool zgrp_obj_is_isolated(struct zram_group *zgrp, u32 index);
void zgrp_obj_putback(struct zram_group *zgrp, u32 index, u16 gid);
void zgrp_obj_stats_inc(struct zram_group *zgrp, u16 gid, u32 size);
void zgrp_obj_stats_dec(struct zram_group *zgrp, u16 gid, u32 size);
void zgrp_fault_stats_inc(struct zram_group *zgrp, u16 gid, u32 size);

#ifdef CONFIG_ZRAM_GROUP_DEBUG
void zram_group_dump(struct zram_group *zgrp, u16 gid, u32 index);
#endif

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
void zram_group_remove_writeback(struct zram_group *zgrp);
int zram_group_apply_writeback(struct zram_group *zgrp, u32 nr_ext);
void zgrp_ext_insert(struct zram_group *zgrp, u32 eid, u16 gid);
bool zgrp_ext_delete(struct zram_group *zgrp, u32 eid, u16 gid);
u32 zgrp_isolate_exts(struct zram_group *zgrp, u16 gid, u32 *eids, u32 nr, bool *last);
void zgrp_get_ext(struct zram_group *zgrp, u32 eid);
bool zgrp_put_ext(struct zram_group *zgrp, u32 eid);
void wbgrp_obj_insert(struct zram_group *zgrp, u32 index, u32 eid);
bool wbgrp_obj_delete(struct zram_group *zgrp, u32 index, u32 eid);
u32 wbgrp_isolate_objs(struct zram_group *zgrp, u32 eid, u32 *idxs, u32 nr, bool *last);
void wbgrp_obj_stats_inc(struct zram_group *zgrp, u16 gid, u32 eid, u32 size);
void wbgrp_obj_stats_dec(struct zram_group *zgrp, u16 gid, u32 eid, u32 size);
void wbgrp_fault_stats_inc(struct zram_group *zgrp, u16 gid, u32 eid, u32 size);
#endif
#endif
