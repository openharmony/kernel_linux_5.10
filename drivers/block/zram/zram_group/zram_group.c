// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/block/zram/zram_group/zram_group.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#define pr_fmt(fmt) "[ZRAM_GROUP]" fmt

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "zram_group.h"

#define CHECK(cond, ...) ((cond) || (pr_err(__VA_ARGS__), false))
#define CHECK_BOUND(var, min, max) \
	CHECK((var) >= (min) && (var) <= (max), \
			"%s %u out of bounds %u ~ %u!\n", \
			#var, (var), (min), (max))

/*
 * idx2node for obj table
 */
static struct zlist_node *get_obj(u32 index, void *private)
{
	struct zram_group *zgrp = private;

	if (index < zgrp->nr_obj)
		return &zgrp->obj[index];

	index -= zgrp->nr_obj;
	BUG_ON(!index);
	if (index < zgrp->nr_grp)
		return &zgrp->grp_obj_head[index];
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	index -= zgrp->nr_grp;
	BUG_ON(index >= zgrp->wbgrp.nr_ext);
	return &zgrp->wbgrp.ext_obj_head[index];
#endif
	BUG();
}

void zram_group_meta_free(struct zram_group *zgrp)
{
	if (!CHECK(zgrp, "zram group is not enable!\n"))
		return;

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	zram_group_remove_writeback(zgrp);
#endif
	vfree(zgrp->grp_obj_head);
	vfree(zgrp->obj);
	zlist_table_free(zgrp->obj_tab);
	vfree(zgrp->stats);
	kfree(zgrp);

	pr_info("zram group freed.\n");
}

struct zram_group *zram_group_meta_alloc(u32 nr_obj, u32 nr_grp)
{
	struct zram_group *zgrp = NULL;
	u32 i;

	if (!CHECK_BOUND(nr_grp, 1, ZGRP_MAX_GRP - 1))
		return NULL;

	/* reserve gid 0 */
	nr_grp++;
	if (!CHECK_BOUND(nr_obj, 1, ZGRP_MAX_OBJ))
		return NULL;
	zgrp = kzalloc(sizeof(struct zram_group), GFP_KERNEL);
	if (!zgrp)
		goto err;
	zgrp->nr_obj = nr_obj;
	zgrp->nr_grp = nr_grp;
	zgrp->grp_obj_head = vmalloc(sizeof(struct zlist_node) * zgrp->nr_grp);
	if (!zgrp->grp_obj_head)
		goto err;
	zgrp->obj = vmalloc(sizeof(struct zlist_node) * zgrp->nr_obj);
	if (!zgrp->obj)
		goto err;
	zgrp->obj_tab = zlist_table_alloc(get_obj, zgrp, GFP_KERNEL);
	if (!zgrp->obj_tab)
		goto err;
	zgrp->stats = vzalloc(sizeof(struct zram_group_stats) * zgrp->nr_grp);
	if (!zgrp->stats)
		goto err;
	zgrp->gsdev = NULL;

	for (i = 0; i < zgrp->nr_obj; i++)
		zlist_node_init(i, zgrp->obj_tab);
	for (i = 1; i < zgrp->nr_grp; i++)
		zlist_node_init(i + zgrp->nr_obj, zgrp->obj_tab);

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	zgrp->wbgrp.enable = false;
	mutex_init(&zgrp->wbgrp.init_lock);
#endif
	pr_info("zram_group alloc succ.\n");
	return zgrp;
err:
	pr_err("zram_group alloc failed!\n");
	zram_group_meta_free(zgrp);

	return NULL;
}

/*
 * insert obj at @index into group @gid as the HOTTEST obj
 */
void zgrp_obj_insert(struct zram_group *zgrp, u32 index, u16 gid)
{
	u32 hid;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(index, 0, zgrp->nr_obj - 1))
		return;
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;
	hid = gid + zgrp->nr_obj;
	zlist_add(hid, index, zgrp->obj_tab);
	pr_debug("insert obj %u to group %u\n", index, gid);
}

/*
 * remove obj at @index from group @gid
 */
bool zgrp_obj_delete(struct zram_group *zgrp, u32 index, u16 gid)
{
	u32 hid;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return false;
	}
	if (!CHECK_BOUND(index, 0, zgrp->nr_obj - 1))
		return false;
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return false;
	pr_debug("delete obj %u from group %u\n", index, gid);
	hid = gid + zgrp->nr_obj;

	return zlist_del(hid, index, zgrp->obj_tab);
}

/*
 * try to isolate the last @nr objs of @gid, store their indexes in array @idxs
 * and @return the obj cnt actually isolated. isolate all objs if nr is 0.
 */
u32 zgrp_isolate_objs(struct zram_group *zgrp, u16 gid, u32 *idxs, u32 nr, bool *last)
{
	u32 hid, idx;
	u32 cnt = 0;
	u32 i;

	if (last)
		*last = false;
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return 0;
	}
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return 0;
	if (!CHECK(idxs, "return array idxs is null!\n"))
		return 0;
	hid = gid + zgrp->nr_obj;
	zlist_lock(hid, zgrp->obj_tab);
	zlist_for_each_entry_reverse(idx, hid, zgrp->obj_tab) {
		idxs[cnt++] = idx;
		if (nr && cnt == nr)
			break;
	}
	for (i = 0; i < cnt; i++)
		zlist_del_nolock(hid, idxs[i], zgrp->obj_tab);
	if (last)
		*last = cnt && zlist_is_isolated_nolock(hid, zgrp->obj_tab);
	zlist_unlock(hid, zgrp->obj_tab);

	pr_debug("isolated %u objs from group %u.\n", cnt, gid);

	return cnt;
}

/*
 * check if the obj at @index is isolate from zram groups
 */
bool zgrp_obj_is_isolated(struct zram_group *zgrp, u32 index)
{
	bool ret = false;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return false;
	}
	if (!CHECK_BOUND(index, 0, zgrp->nr_obj - 1))
		return false;

	zlist_lock(index, zgrp->obj_tab);
	ret = zlist_is_isolated_nolock(index, zgrp->obj_tab);
	zlist_unlock(index, zgrp->obj_tab);

	return ret;
}
/*
 * insert obj at @index into group @gid as the COLDEST obj
 */
void zgrp_obj_putback(struct zram_group *zgrp, u32 index, u16 gid)
{
	u32 hid;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(index, 0, zgrp->nr_obj - 1))
		return;
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;
	hid = gid + zgrp->nr_obj;
	zlist_add_tail(hid, index, zgrp->obj_tab);
	pr_debug("putback obj %u to group %u\n", index, gid);
}

void zgrp_obj_stats_inc(struct zram_group *zgrp, u16 gid, u32 size)
{
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;

	atomic_inc(&zgrp->stats[gid].zram_pages);
	atomic64_add(size, &zgrp->stats[gid].zram_size);
	atomic_inc(&zgrp->stats[0].zram_pages);
	atomic64_add(size, &zgrp->stats[0].zram_size);
}

void zgrp_obj_stats_dec(struct zram_group *zgrp, u16 gid, u32 size)
{
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;

	atomic_dec(&zgrp->stats[gid].zram_pages);
	atomic64_sub(size, &zgrp->stats[gid].zram_size);
	atomic_dec(&zgrp->stats[0].zram_pages);
	atomic64_sub(size, &zgrp->stats[0].zram_size);
}

void zgrp_fault_stats_inc(struct zram_group *zgrp, u16 gid, u32 size)
{
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;

	atomic64_inc(&zgrp->stats[gid].zram_fault);
	atomic64_inc(&zgrp->stats[0].zram_fault);
}

#ifdef CONFIG_ZRAM_GROUP_DEBUG
void zram_group_dump(struct zram_group *zgrp, u16 gid, u32 index)
{
	u32 hid, idx;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	hid = gid + zgrp->nr_obj;
	if (gid == 0) {
		struct zlist_node *node = NULL;

		if (!CHECK_BOUND(index, 0, zgrp->nr_obj - 1))
			return;
		node = idx2node(index, zgrp->obj_tab);
		pr_err("dump index %u = %u %u %u %u\n", index,
				node->prev, node->next,
				node->lock, node->priv);
	} else {
		if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
			return;
		pr_err("dump index of group %u\n", gid);
		zlist_for_each_entry(idx, hid, zgrp->obj_tab)
			pr_err("%u\n", idx);
	}
}
#endif

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
/*
 * idx2node for ext table
 */
static struct zlist_node *get_ext(u32 index, void *private)
{
	struct zram_group *zgrp = private;

	if (index < zgrp->wbgrp.nr_ext)
		return &zgrp->wbgrp.ext[index];

	index -= zgrp->wbgrp.nr_ext;
	BUG_ON(!index);
	return &zgrp->wbgrp.grp_ext_head[index];
}

/*
 * disable writeback for zram group @zgrp
 */
void zram_group_remove_writeback(struct zram_group *zgrp)
{
	if (!CHECK(zgrp, "zram group is not enable!\n"))
		return;
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return;
	zgrp->wbgrp.enable = false;
	vfree(zgrp->wbgrp.grp_ext_head);
	vfree(zgrp->wbgrp.ext);
	zlist_table_free(zgrp->wbgrp.ext_tab);
	vfree(zgrp->wbgrp.ext_obj_head);
	pr_info("zram group writeback is removed.\n");
}

/*
 * init & enable writeback on exist zram group @zgrp with a backing device of
 * @nr_ext extents.
 */
int zram_group_apply_writeback(struct zram_group *zgrp, u32 nr_ext)
{
	struct writeback_group *wbgrp = NULL;
	u32 i;
	int ret = 0;

	if (!CHECK(zgrp, "zram group is not enable!\n"))
		return -EINVAL;

	mutex_lock(&zgrp->wbgrp.init_lock);
	if (!CHECK(!zgrp->wbgrp.enable, "zram group writeback is already enable!\n"))
		goto out;
	if (!CHECK_BOUND(nr_ext, 1, ZGRP_MAX_EXT)) {
		ret = -EINVAL;
		goto out;
	}
	wbgrp = &zgrp->wbgrp;
	wbgrp->nr_ext = nr_ext;
	wbgrp->grp_ext_head = vmalloc(sizeof(struct zlist_node) * zgrp->nr_grp);
	if (!wbgrp->grp_ext_head) {
		ret = -ENOMEM;
		goto out;
	}
	wbgrp->ext = vmalloc(sizeof(struct zlist_node) * wbgrp->nr_ext);
	if (!wbgrp->ext) {
		ret = -ENOMEM;
		goto out;
	}
	wbgrp->ext_obj_head = vmalloc(sizeof(struct zlist_node) * wbgrp->nr_ext);
	if (!wbgrp->ext_obj_head) {
		ret = -ENOMEM;
		goto out;
	}

	wbgrp->ext_tab = zlist_table_alloc(get_ext, zgrp, GFP_KERNEL);
	if (!wbgrp->ext_tab) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < wbgrp->nr_ext; i++)
		zlist_node_init(i, wbgrp->ext_tab);
	for (i = 1; i < zgrp->nr_grp; i++)
		zlist_node_init(i + wbgrp->nr_ext, wbgrp->ext_tab);

	for (i = 0; i < wbgrp->nr_ext; i++)
		zlist_node_init(i + zgrp->nr_obj + zgrp->nr_grp, zgrp->obj_tab);

	init_waitqueue_head(&wbgrp->fault_wq);
	wbgrp->enable = true;
	pr_info("zram group writeback is enabled.\n");
out:
	mutex_unlock(&zgrp->wbgrp.init_lock);

	if (ret) {
		zram_group_remove_writeback(zgrp);
		pr_err("zram group writeback enable failed!\n");
	}

	return ret;
}

/*
 * attach extent at @eid to group @gid as the HOTTEST extent
 */
void zgrp_ext_insert(struct zram_group *zgrp, u32 eid, u16 gid)
{
	u32 hid;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return;
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;
	hid = gid + zgrp->wbgrp.nr_ext;
	zlist_add(hid, eid, zgrp->wbgrp.ext_tab);
	pr_debug("insert extent %u to group %u\n", eid, gid);
}

/*
 * remove extent at @eid from group @gid
 */
bool zgrp_ext_delete(struct zram_group *zgrp, u32 eid, u16 gid)
{
	u32 hid;
	bool isolated = false;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return false;
	}
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return false;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return false;
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return false;

	zlist_lock(eid, zgrp->wbgrp.ext_tab);
	isolated = zlist_is_isolated_nolock(eid, zgrp->wbgrp.ext_tab);
	zlist_unlock(eid, zgrp->wbgrp.ext_tab);
	if (isolated) {
		pr_debug("extent %u is already isolated, skip delete.\n", eid);
		return false;
	}

	pr_debug("delete extent %u from group %u\n", eid, gid);
	hid = gid + zgrp->wbgrp.nr_ext;
	return zlist_del(hid, eid, zgrp->wbgrp.ext_tab);
}

/*
 * try to isolate the first @nr exts of @gid, store their eids in array @eids
 * and @return the cnt actually isolated. isolate all exts if nr is 0.
 */
u32 zgrp_isolate_exts(struct zram_group *zgrp, u16 gid, u32 *eids, u32 nr, bool *last)
{
	u32 hid, idx;
	u32 cnt = 0;
	u32 i;

	if (last)
		*last = false;
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return 0;
	}
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return 0;
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return 0;
	if (!CHECK(eids, "return array eids is null!\n"))
		return 0;
	hid = gid + zgrp->wbgrp.nr_ext;
	zlist_lock(hid, zgrp->wbgrp.ext_tab);
	zlist_for_each_entry_reverse(idx, hid, zgrp->wbgrp.ext_tab) {
		eids[cnt++] = idx;
		if (nr && cnt == nr)
			break;
	}
	for (i = 0; i < cnt; i++)
		zlist_del_nolock(hid, eids[i], zgrp->wbgrp.ext_tab);
	if (last)
		*last = cnt && zlist_is_isolated_nolock(hid, zgrp->wbgrp.ext_tab);
	zlist_unlock(hid, zgrp->wbgrp.ext_tab);

	pr_debug("isolated %u exts from group %u.\n", cnt, gid);

	return cnt;
}

void zgrp_get_ext(struct zram_group *zgrp, u32 eid)
{
	u32 hid;

	if (!CHECK(zgrp, "zram group is not enable!\n"))
		return;
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return;

	hid = eid + zgrp->nr_obj + zgrp->nr_grp;
	zlist_set_priv(hid, zgrp->obj_tab);
	pr_info("get extent %u\n", eid);
}

bool zgrp_put_ext(struct zram_group *zgrp, u32 eid)
{
	u32 hid;
	bool ret = false;

	if (!CHECK(zgrp, "zram group is not enable!\n"))
		return false;
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return false;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return false;

	hid = eid + zgrp->nr_obj + zgrp->nr_grp;
	zlist_lock(hid, zgrp->obj_tab);
	zlist_clr_priv_nolock(hid, zgrp->obj_tab);
	ret = zlist_is_isolated_nolock(hid, zgrp->obj_tab);
	zlist_unlock(hid, zgrp->obj_tab);

	pr_info("put extent %u, ret = %d\n", eid, ret);

	return ret;
}

/*
 * insert obj at @index into extent @eid
 */
void wbgrp_obj_insert(struct zram_group *zgrp, u32 index, u32 eid)
{
	u32 hid;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return;
	if (!CHECK_BOUND(index, 0, zgrp->nr_obj - 1))
		return;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return;
	hid = eid + zgrp->nr_obj + zgrp->nr_grp;
	zlist_add_tail(hid, index, zgrp->obj_tab);
	pr_debug("insert obj %u to extent %u\n", index, eid);
}

/*
 * remove obj at @index from extent @eid
 */
bool wbgrp_obj_delete(struct zram_group *zgrp, u32 index, u32 eid)
{
	u32 hid;
	bool ret = false;

	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return false;
	}
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return false;
	if (!CHECK_BOUND(index, 0, zgrp->nr_obj - 1))
		return false;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return false;
	pr_debug("delete obj %u from extent %u\n", index, eid);
	hid = eid + zgrp->nr_obj + zgrp->nr_grp;

	zlist_lock(hid, zgrp->obj_tab);
	ret = zlist_del_nolock(hid, index, zgrp->obj_tab)
		&& !zlist_test_priv_nolock(hid, zgrp->obj_tab);
	zlist_unlock(hid, zgrp->obj_tab);

	return ret;
}

/*
 * try to isolate the first @nr writeback objs of @eid, store their indexes in
 * array @idxs and @return the obj cnt actually isolated. isolate all objs if
 * @nr is 0.
 */
u32 wbgrp_isolate_objs(struct zram_group *zgrp, u32 eid, u32 *idxs, u32 nr, bool *last)
{
	u32 hid, idx;
	u32 cnt = 0;
	u32 i;

	if (last)
		*last = false;
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return 0;
	}
	if (!CHECK(zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return 0;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return 0;
	if (!CHECK(idxs, "return array idxs is null!\n"))
		return 0;
	hid = eid + zgrp->nr_obj + zgrp->nr_grp;
	zlist_lock(hid, zgrp->obj_tab);
	zlist_for_each_entry(idx, hid, zgrp->obj_tab) {
		idxs[cnt++] = idx;
		if (nr && cnt == nr)
			break;
	}
	for (i = 0; i < cnt; i++)
		zlist_del_nolock(hid, idxs[i], zgrp->obj_tab);
	if (last)
		*last = cnt && zlist_is_isolated_nolock(hid, zgrp->obj_tab)
			&& !zlist_test_priv_nolock(hid, zgrp->obj_tab);
	zlist_unlock(hid, zgrp->obj_tab);

	pr_debug("isolated %u objs from extent %u.\n", cnt, eid);

	return cnt;
}

void wbgrp_obj_stats_inc(struct zram_group *zgrp, u16 gid, u32 eid, u32 size)
{
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return;

	atomic_inc(&zgrp->stats[gid].wb_pages);
	atomic64_add(size, &zgrp->stats[gid].wb_size);
	atomic_inc(&zgrp->stats[0].wb_pages);
	atomic64_add(size, &zgrp->stats[0].wb_size);
}

void wbgrp_obj_stats_dec(struct zram_group *zgrp, u16 gid, u32 eid, u32 size)
{
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return;

	atomic_dec(&zgrp->stats[gid].wb_pages);
	atomic64_sub(size, &zgrp->stats[gid].wb_size);
	atomic_dec(&zgrp->stats[0].wb_pages);
	atomic64_sub(size, &zgrp->stats[0].wb_size);
}

void wbgrp_fault_stats_inc(struct zram_group *zgrp, u16 gid, u32 eid, u32 size)
{
	if (!zgrp) {
		pr_debug("zram group is not enable!");
		return;
	}
	if (!CHECK_BOUND(gid, 1, zgrp->nr_grp - 1))
		return;
	if (!CHECK_BOUND(eid, 0, zgrp->wbgrp.nr_ext - 1))
		return;

	atomic64_inc(&zgrp->stats[gid].wb_fault);
	atomic64_inc(&zgrp->stats[0].wb_fault);
}
#endif
