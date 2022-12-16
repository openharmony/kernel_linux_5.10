// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/block/zram/zram_group/group_writeback.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/blk_types.h>
#include <linux/zswapd.h>

#include "../zram_drv.h"
#include "zram_group.h"

#ifdef CONFIG_HYPERHOLD
#include "hyperhold.h"
#endif

#define CHECK(cond, ...) ((cond) || (pr_err(__VA_ARGS__), false))
#define CHECK_BOUND(var, min, max) \
	CHECK((var) >= (min) && (var) <= (max), \
			"%s %u out of bounds %u ~ %u!\n", \
			#var, (var), (min), (max))

static u16 zram_get_memcg_id(struct zram *zram, u32 index)
{
	return (zram->table[index].flags & ZRAM_GRPID_MASK) >> ZRAM_SIZE_SHIFT;
}

static void zram_set_memcg_id(struct zram *zram, u32 index, u16 gid)
{
	unsigned long old = zram->table[index].flags & (~ZRAM_GRPID_MASK);

	zram->table[index].flags = old | ((u64)gid << ZRAM_SIZE_SHIFT);
}

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
static bool obj_can_wb(struct zram *zram, u32 index, u16 gid)
{
	/* overwrited obj, just skip */
	if (zram_get_memcg_id(zram, index) != gid) {
		pr_debug("obj %u is from group %u instead of group %u.\n",
				index, zram_get_memcg_id(zram, index), gid);
		return false;
	}
	if (!zgrp_obj_is_isolated(zram->zgrp, index)) {
		pr_debug("obj %u is not isolated.\n", index);
		return false;
	}
	/* need not to writeback, put back the obj as HOTEST */
	if (zram_test_flag(zram, index, ZRAM_SAME)) {
		pr_debug("obj %u is filled with same element.\n", index);
		goto insert;
	}
	if (zram_test_flag(zram, index, ZRAM_WB)) {
		pr_debug("obj %u is writeback.\n", index);
		goto insert;
	}
	/* obj is needed by a pagefault req, do not writeback it. */
	if (zram_test_flag(zram, index, ZRAM_FAULT)) {
		pr_debug("obj %u is needed by a pagefault request.\n", index);
		goto insert;
	}
	/* should never happen */
	if (zram_test_flag(zram, index, ZRAM_GWB)) {
		pr_debug("obj %u is group writeback.\n", index);
		BUG();
		return false;
	}

	return true;
insert:
	zgrp_obj_insert(zram->zgrp, index, gid);

	return false;
}

static void copy_obj(struct hpio *hpio, u32 offset, char *obj, u32 size, bool to)
{
	u32 page_id, start;
	char *buf = NULL;

	page_id = offset / PAGE_SIZE;
	start = offset % PAGE_SIZE;
	if (size + start <= PAGE_SIZE) {
		buf = page_to_virt(hyperhold_io_page(hpio, page_id));
		if (to)
			memcpy(buf + start, obj, size);
		else
			memcpy(obj, buf + start, size);

		return;
	}
	buf = page_to_virt(hyperhold_io_page(hpio, page_id));
	if (to)
		memcpy(buf + start, obj, PAGE_SIZE - start);
	else
		memcpy(obj, buf + start, PAGE_SIZE - start);
	buf = page_to_virt(hyperhold_io_page(hpio, page_id + 1));
	if (to)
		memcpy(buf, obj + PAGE_SIZE - start, size + start - PAGE_SIZE);
	else
		memcpy(obj + PAGE_SIZE - start, buf, size + start - PAGE_SIZE);
}

static u32 move_obj_to_hpio(struct zram *zram, u32 index, u16 gid,
				struct hpio *hpio, u32 offset)
{
	u32 size = 0;
	unsigned long handle;
	char *src = NULL;
	u32 ext_size;
	u32 eid;

	eid = hyperhold_io_extent(hpio);
	ext_size = hyperhold_extent_size(eid);

	zram_slot_lock(zram, index);
	if (!obj_can_wb(zram, index, gid))
		goto unlock;
	size = zram_get_obj_size(zram, index);
	/* no space, put back the obj as COLDEST */
	if (size + offset > ext_size) {
		pr_debug("obj %u size is %u, but ext %u only %u space left.\n",
				index, size, eid, ext_size - offset);
		zgrp_obj_putback(zram->zgrp, index, gid);
		size = 0;
		goto unlock;
	}
	handle = zram_get_handle(zram, index);
	src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	copy_obj(hpio, offset, src, size, true);
	zs_unmap_object(zram->mem_pool, handle);
	zs_free(zram->mem_pool, handle);
	zram_set_handle(zram, index, hyperhold_address(eid, offset));
	zram_set_flag(zram, index, ZRAM_GWB);
	wbgrp_obj_insert(zram->zgrp, index, eid);
	wbgrp_obj_stats_inc(zram->zgrp, gid, eid, size);
	zgrp_obj_stats_dec(zram->zgrp, gid, size);
	pr_debug("move obj %u of group %u to hpio %p of eid %u, size = %u, offset = %u\n",
		index, gid, hpio, eid, size, offset);
unlock:
	zram_slot_unlock(zram, index);

	return size;
}

static void move_obj_from_hpio(struct zram *zram, int index, struct hpio *hpio)
{
	u32 size = 0;
	unsigned long handle = 0;
	u32 eid, offset;
	u64 addr;
	char *dst = NULL;
	u16 gid;

	eid = hyperhold_io_extent(hpio);
retry:
	zram_slot_lock(zram, index);
	if (!zram_test_flag(zram, index, ZRAM_GWB))
		goto unlock;
	addr = zram_get_handle(zram, index);
	if (hyperhold_addr_extent(addr) != eid)
		goto unlock;
	size = zram_get_obj_size(zram, index);
	if (handle)
		goto move;
	handle = zs_malloc(zram->mem_pool, size, GFP_NOWAIT);
	if (handle)
		goto move;
	zram_slot_unlock(zram, index);
	handle = zs_malloc(zram->mem_pool, size, GFP_NOIO | __GFP_NOFAIL);
	if (handle)
		goto retry;
	BUG();

	return;
move:
	offset = hyperhold_addr_offset(addr);
	dst = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);
	copy_obj(hpio, offset, dst, size, false);
	zs_unmap_object(zram->mem_pool, handle);
	zram_set_handle(zram, index, handle);
	zram_clear_flag(zram, index, ZRAM_GWB);
	gid = zram_get_memcg_id(zram, index);
	zgrp_obj_insert(zram->zgrp, index, gid);
	wbgrp_obj_stats_dec(zram->zgrp, gid, eid, size);
	zgrp_obj_stats_inc(zram->zgrp, gid, size);
	pr_debug("move obj %u of group %u from hpio %p of eid %u, size = %u, offset = %u\n",
		index, gid, hpio, eid, size, offset);
unlock:
	zram_slot_unlock(zram, index);
}


#define NR_ISOLATE 32
static bool move_extent_from_hpio(struct zram *zram, struct hpio *hpio)
{
	u32 idxs[NR_ISOLATE];
	u32 eid;
	u32 nr;
	int i;
	bool last = false;

	eid = hyperhold_io_extent(hpio);
repeat:
	nr = wbgrp_isolate_objs(zram->zgrp, eid, idxs, NR_ISOLATE, &last);
	for (i = 0; i < nr; i++)
		move_obj_from_hpio(zram, idxs[i], hpio);
	if (last)
		return true;
	if (nr)
		goto repeat;

	return false;
}

struct hpio_priv {
	struct zram *zram;
	u16 gid;
};

static void write_endio(struct hpio *hpio)
{
	struct hpio_priv *priv = hyperhold_io_private(hpio);
	struct zram *zram = priv->zram;
	u16 gid = priv->gid;
	u32 eid = hyperhold_io_extent(hpio);

	if (hyperhold_io_success(hpio))
		goto out;
	if (move_extent_from_hpio(zram, hpio)) {
		zgrp_ext_delete(zram->zgrp, eid, gid);
		hyperhold_should_free_extent(eid);
	}
out:
	hyperhold_io_complete(hpio);
	hyperhold_io_put(hpio);
	kfree(priv);
}

static u32 collect_objs(struct zram *zram, u16 gid, struct hpio *hpio, u32 ext_size)
{
	u32 offset = 0;
	u32 last_offset;
	u32 nr;
	u32 idxs[NR_ISOLATE];
	int i;

more:
	last_offset = offset;
	nr = zgrp_isolate_objs(zram->zgrp, gid, idxs, NR_ISOLATE, NULL);
	for (i = 0; i < nr; i++)
		offset += move_obj_to_hpio(zram, idxs[i], gid, hpio, offset);
	pr_debug("%u data attached, offset = %u.\n", offset - last_offset, offset);
	if (offset < ext_size && offset != last_offset)
		goto more;

	return offset;
}

static u64 write_one_extent(struct zram *zram, u16 gid)
{
	int eid;
	struct hpio *hpio = NULL;
	struct hpio_priv *priv = NULL;
	u32 size = 0;
	int ret;

	priv = kmalloc(sizeof(struct hpio_priv), GFP_NOIO);
	if (!priv)
		return 0;
	priv->gid = gid;
	priv->zram = zram;
	eid = hyperhold_alloc_extent();
	if (eid < 0)
		goto err;
	hpio = hyperhold_io_get(eid, GFP_NOIO, REQ_OP_WRITE);
	if (!hpio)
		goto free_extent;

	zgrp_get_ext(zram->zgrp, eid);
	size = collect_objs(zram, gid, hpio, hyperhold_extent_size(eid));
	if (size == 0) {
		pr_err("group %u has no data in zram.\n", gid);
		zgrp_put_ext(zram->zgrp, eid);
		goto put_hpio;
	}
	zgrp_ext_insert(zram->zgrp, eid, gid);
	if (zgrp_put_ext(zram->zgrp, eid)) {
		zgrp_ext_delete(zram->zgrp, eid, gid);
		hyperhold_should_free_extent(eid);
	}

	ret = hyperhold_write_async(hpio, write_endio, priv);
	if (ret)
		goto move_back;

	return size;
move_back:
	if (move_extent_from_hpio(zram, hpio)) {
		zgrp_ext_delete(zram->zgrp, eid, gid);
		hyperhold_should_free_extent(eid);
	}
	eid = -EINVAL;
put_hpio:
	hyperhold_io_put(hpio);
free_extent:
	if (eid >= 0)
		hyperhold_free_extent(eid);
err:
	kfree(priv);

	return 0;
}

static void read_endio(struct hpio *hpio)
{
	struct hpio_priv *priv = hyperhold_io_private(hpio);
	struct zram *zram = priv->zram;
	u16 gid = priv->gid;
	u32 eid = hyperhold_io_extent(hpio);

	if (!hyperhold_io_success(hpio)) {
		BUG();
		goto out;
	}
	if (move_extent_from_hpio(zram, hpio)) {
		zgrp_ext_delete(zram->zgrp, eid, gid);
		hyperhold_should_free_extent(eid);
	}
out:
	hyperhold_io_complete(hpio);
	hyperhold_io_put(hpio);
	kfree(priv);
}

static u64 read_one_extent(struct zram *zram, u32 eid, u16 gid)
{
	struct hpio *hpio = NULL;
	u32 ext_size = 0;
	int ret;
	struct hpio_priv *priv = NULL;

	priv = kmalloc(sizeof(struct hpio_priv), GFP_NOIO);
	if (!priv)
		goto err;
	priv->gid = gid;
	priv->zram = zram;
	hpio = hyperhold_io_get(eid, GFP_NOIO, REQ_OP_READ);
	if (!hpio)
		goto err;
	ext_size = hyperhold_extent_size(eid);
	ret = hyperhold_read_async(hpio, read_endio, priv);
	if (ret)
		goto err;

	return ext_size;
err:
	hyperhold_io_put(hpio);
	kfree(priv);

	return 0;
}

static void sync_read_endio(struct hpio *hpio)
{
	hyperhold_io_complete(hpio);
}

static int read_one_obj_sync(struct zram *zram, u32 index)
{
	struct hpio *hpio = NULL;
	int ret;
	u32 eid;
	u16 gid;
	u32 size;

	if (!zram_test_flag(zram, index, ZRAM_GWB))
		return 0;

	pr_debug("read obj %u.\n", index);

	gid = zram_get_memcg_id(zram, index);
	eid = hyperhold_addr_extent(zram_get_handle(zram, index));
	size = zram_get_obj_size(zram, index);
	wbgrp_fault_stats_inc(zram->zgrp, gid, eid, size);
check:
	if (!zram_test_flag(zram, index, ZRAM_GWB))
		return 0;
	if (!zram_test_flag(zram, index, ZRAM_FAULT))
		goto read;
	zram_slot_unlock(zram, index);
	wait_event(zram->zgrp->wbgrp.fault_wq, !zram_test_flag(zram, index, ZRAM_FAULT));
	zram_slot_lock(zram, index);
	goto check;
read:
	zram_set_flag(zram, index, ZRAM_FAULT);
	zram_slot_unlock(zram, index);

	hpio = hyperhold_io_get(eid, GFP_NOIO, REQ_OP_READ);
	if (!hpio) {
		ret = -ENOMEM;
		goto out;
	}
	ret = hyperhold_read_async(hpio, sync_read_endio, NULL);
	/* io submit error */
	if (ret && ret != -EAGAIN)
		goto out;

	hyperhold_io_wait(hpio);

	/* if not reset to zero, will return err sometimes and cause SIG_BUS error */
	ret = 0;

	/* get a write io, data is ready, copy the pages even write failed */
	if (op_is_write(hyperhold_io_operate(hpio)))
		goto move;
	/* read io failed, return -EIO */
	if (!hyperhold_io_success(hpio)) {
		ret = -EIO;
		goto out;
	}
	/* success, copy the data and free extent */
move:
	if (move_extent_from_hpio(zram, hpio)) {
		zgrp_ext_delete(zram->zgrp, eid, gid);
		hyperhold_should_free_extent(eid);
	}
	move_obj_from_hpio(zram, index, hpio);
out:
	hyperhold_io_put(hpio);
	zram_slot_lock(zram, index);
	zram_clear_flag(zram, index, ZRAM_FAULT);
	wake_up(&zram->zgrp->wbgrp.fault_wq);

	return ret;
}

u64 read_group_objs(struct zram *zram, u16 gid, u64 req_size)
{
	u32 eid;
	u64 read_size = 0;
	u32 nr;

	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return 0;
	}
	if (!CHECK_BOUND(gid, 1, zram->zgrp->nr_grp - 1))
		return 0;

	pr_debug("read %llu data of group %u.\n", req_size, gid);

	while (!req_size || req_size > read_size) {
		nr = zgrp_isolate_exts(zram->zgrp, gid, &eid, 1, NULL);
		if (!nr)
			break;
		read_size += read_one_extent(zram, eid, gid);
	}

	return read_size;
}

u64 write_group_objs(struct zram *zram, u16 gid, u64 req_size)
{
	u64 write_size = 0;
	u64 size = 0;

	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return 0;
	}
	if (!CHECK(zram->zgrp->wbgrp.enable, "zram group writeback is not enable!\n"))
		return 0;
	if (!CHECK_BOUND(gid, 1, zram->zgrp->nr_grp - 1))
		return 0;

	pr_debug("write %llu data of group %u.\n", req_size, gid);

	while (!req_size || req_size > write_size) {
		size = write_one_extent(zram, gid);
		if (!size)
			break;
		write_size += size;
	}

	atomic64_add(write_size, &zram->zgrp->stats[0].write_size);
	atomic64_add(write_size, &zram->zgrp->stats[gid].write_size);
	return write_size;
}
#endif

#ifdef CONFIG_ZRAM_GROUP_DEBUG
#include <linux/random.h>
#define ZGRP_TEST_MAX_GRP 101
#endif

int zram_group_fault_obj(struct zram *zram, u32 index)
{
	u16 gid;
	u32 size;

	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return 0;
	}
	if (!CHECK_BOUND(index, 0, zram->zgrp->nr_obj - 1))
		return 0;

	gid = zram_get_memcg_id(zram, index);
	size = zram_get_obj_size(zram, index);
	zgrp_fault_stats_inc(zram->zgrp, gid, size);
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	return read_one_obj_sync(zram, index);
#else
	return 0;
#endif
}

void zram_group_track_obj(struct zram *zram, u32 index, struct mem_cgroup *memcg)
{
	u16 gid;

	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return;
	}
	if (!CHECK_BOUND(index, 0, zram->zgrp->nr_obj - 1))
		return;
	if (!CHECK(memcg || !memcg->id.id, "obj %u has no memcg!\n", index))
		return;
	gid = zram_get_memcg_id(zram, index);
	if (!CHECK(!gid, "obj %u has gid %u.\n", index, gid))
		BUG();

	gid = memcg->id.id;
	zram_set_memcg_id(zram, index, gid);
	zgrp_obj_insert(zram->zgrp, index, gid);
	zgrp_obj_stats_inc(zram->zgrp, gid, zram_get_obj_size(zram, index));
}

void zram_group_untrack_obj(struct zram *zram, u32 index)
{
	u16 gid;
	u32 size;

	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return;
	}
	if (!CHECK_BOUND(index, 0, zram->zgrp->nr_obj - 1))
		return;

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
check:
	if (!zram_test_flag(zram, index, ZRAM_FAULT))
		goto clear;
	zram_slot_unlock(zram, index);
	wait_event(zram->zgrp->wbgrp.fault_wq, !zram_test_flag(zram, index, ZRAM_FAULT));
	zram_slot_lock(zram, index);
	goto check;
clear:
#endif
	gid = zram_get_memcg_id(zram, index);
	size = zram_get_obj_size(zram, index);
	if (!gid)
		return;
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	if (zram_test_flag(zram, index, ZRAM_GWB)) {
		u32 eid = hyperhold_addr_extent(zram_get_handle(zram, index));

		if (wbgrp_obj_delete(zram->zgrp, index, eid)) {
			zgrp_ext_delete(zram->zgrp, eid, gid);
			hyperhold_should_free_extent(eid);
		}
		zram_clear_flag(zram, index, ZRAM_GWB);
		zram_set_memcg_id(zram, index, 0);
		wbgrp_obj_stats_dec(zram->zgrp, gid, eid, size);
		zram_set_handle(zram, index, 0);
		return;
	}
#endif
	zgrp_obj_delete(zram->zgrp, index, gid);
	zram_set_memcg_id(zram, index, 0);
	zgrp_obj_stats_dec(zram->zgrp, gid, size);
}

#ifdef CONFIG_ZRAM_GROUP_DEBUG
void group_debug(struct zram *zram, u32 op, u32 index, u32 gid)
{
	if (op == 0)
		zram_group_dump(zram->zgrp, gid, index);

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	if (op == 22)
		read_group_objs(zram, gid, index);
	if (op == 23)
		write_group_objs(zram, gid, index);
	if (op == 20) {
		if (index)
			zram_group_apply_writeback(zram->zgrp, hyperhold_nr_extent());
		else
			zram_group_remove_writeback(zram->zgrp);
	}
#endif
}
#endif

static u64 group_obj_stats(struct zram *zram, u16 gid, int type)
{
	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return 0;
	}
	if (!CHECK_BOUND(gid, 0, zram->zgrp->nr_grp - 1))
		return 0;

	if (type == CACHE_SIZE)
		return atomic64_read(&zram->zgrp->stats[gid].zram_size);
	else if (type == CACHE_PAGE)
		return atomic_read(&zram->zgrp->stats[gid].zram_pages);
	else if (type == CACHE_FAULT)
		return atomic64_read(&zram->zgrp->stats[gid].zram_fault);
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	else if (type == SWAP_SIZE)
		return atomic64_read(&zram->zgrp->stats[gid].wb_size);
	else if (type == SWAP_PAGE)
		return atomic_read(&zram->zgrp->stats[gid].wb_pages);
	else if (type == READ_SIZE)
		return atomic64_read(&zram->zgrp->stats[gid].read_size);
	else if (type == WRITE_SIZE)
		return atomic64_read(&zram->zgrp->stats[gid].write_size);
	else if (type == SWAP_FAULT)
		return atomic64_read(&zram->zgrp->stats[gid].wb_fault);
	BUG();
#endif

	return 0;
}

#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
static u64 zram_group_read(u16 gid, u64 req_size, void *priv)
{
	if (!CHECK(priv, "priv is NULL!\n"))
		return 0;

	return read_group_objs((struct zram *)priv, gid, req_size);
}

static u64 zram_group_write(u16 gid, u64 req_size, void *priv)
{
	if (!CHECK(priv, "priv is NULL!\n"))
		return 0;

	return write_group_objs((struct zram *)priv, gid, req_size);
}
#else
static u64 zram_group_read(u16 gid, u64 req_size, void *priv)
{
	return 0;
}
static u64 zram_group_write(u16 gid, u64 req_size, void *priv)
{
	return 0;
}
#endif


static u64 zram_group_data_size(u16 gid, int type, void *priv)
{
	if (!CHECK(priv, "priv is NULL!\n"))
		return 0;

	return group_obj_stats((struct zram *)priv, gid, type);
}

struct group_swap_ops zram_group_ops = {
	.group_read = zram_group_read,
	.group_write = zram_group_write,
	.group_data_size = zram_group_data_size,
};

static int register_zram_group(struct zram *zram)
{
	if (!CHECK(zram, "zram is NULL!\n"))
		return -EINVAL;
	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return -EINVAL;
	}

	zram->zgrp->gsdev = register_group_swap(&zram_group_ops, zram);
	if (!zram->zgrp->gsdev) {
		pr_err("register zram group failed!\n");
		return -ENOMEM;
	}

	return 0;
}

static void unregister_zram_group(struct zram *zram)
{
	if (!CHECK(zram, "zram is NULL!\n"))
		return;
	if (!(zram->zgrp)) {
		pr_debug("zram group is not enable!\n");
		return;
	}

	unregister_group_swap(zram->zgrp->gsdev);
	zram->zgrp->gsdev = NULL;
}

void zram_group_init(struct zram *zram, u32 nr_obj)
{
	unsigned int ctrl = zram->zgrp_ctrl;

	if (ctrl == ZGRP_NONE)
		return;
	zram->zgrp = zram_group_meta_alloc(nr_obj, ZGRP_MAX_GRP - 1);
#ifdef CONFIG_ZRAM_GROUP_WRITEBACK
	if (ctrl == ZGRP_WRITE)
		zram_group_apply_writeback(zram->zgrp, hyperhold_nr_extent());
#endif
	register_zram_group(zram);
}

void zram_group_deinit(struct zram *zram)
{
	unregister_zram_group(zram);
	zram_group_meta_free(zram->zgrp);
	zram->zgrp = NULL;
}
