// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/hyperhold/hp_iotab.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#define pr_fmt(fmt) "[HYPERHOLD]" fmt

#include <linux/slab.h>
#include <linux/mm.h>

#include "hp_iotab.h"

atomic64_t hpio_mem = ATOMIC64_INIT(0);
u64 hpio_memory(void)
{
	return atomic64_read(&hpio_mem);
}

struct hp_iotab {
	struct list_head io_list;
	rwlock_t lock;
	u32 io_cnt;
	wait_queue_head_t empty_wq;
};

/* store all inflight hpio in iotab */
struct hp_iotab iotab = {
	.io_list = LIST_HEAD_INIT(iotab.io_list),
	.lock = __RW_LOCK_UNLOCKED(iotab.lock),
	.io_cnt = 0,
	.empty_wq = __WAIT_QUEUE_HEAD_INITIALIZER(iotab.empty_wq),
};

static struct hpio *__iotab_search_get(struct hp_iotab *iotab, u32 eid)
{
	struct hpio *hpio = NULL;

	list_for_each_entry(hpio, &iotab->io_list, list)
		if (hpio->eid == eid && kref_get_unless_zero(&hpio->refcnt))
			return hpio;

	return NULL;
}

static struct hpio *iotab_search_get(struct hp_iotab *iotab, u32 eid)
{
	struct hpio *hpio = NULL;
	unsigned long flags;

	read_lock_irqsave(&iotab->lock, flags);
	hpio = __iotab_search_get(iotab, eid);
	read_unlock_irqrestore(&iotab->lock, flags);

	pr_info("find hpio %p for eid %u.\n", hpio, eid);

	return hpio;
}

/*
 * insert @hpio into @iotab, cancel insertion if there is a hpio of the same
 * @eid, inc the refcnt of duplicated hpio and return it
 */
static struct hpio *iotab_insert(struct hp_iotab *iotab, struct hpio *hpio)
{
	struct hpio *dup = NULL;
	unsigned long flags;

	write_lock_irqsave(&iotab->lock, flags);
	dup = __iotab_search_get(iotab, hpio->eid);
	if (dup) {
		pr_info("find exist hpio %p for eid %u, insert hpio %p failed.\n",
				dup, hpio->eid, hpio);
		goto unlock;
	}
	list_add(&hpio->list, &iotab->io_list);
	iotab->io_cnt++;
	pr_info("insert new hpio %p for eid %u.\n", hpio, hpio->eid);
unlock:
	write_unlock_irqrestore(&iotab->lock, flags);

	return dup;
}

static void iotab_delete(struct hp_iotab *iotab, struct hpio *hpio)
{
	unsigned long flags;

	write_lock_irqsave(&iotab->lock, flags);
	list_del(&hpio->list);
	iotab->io_cnt--;
	if (!iotab->io_cnt)
		wake_up(&iotab->empty_wq);
	write_unlock_irqrestore(&iotab->lock, flags);

	pr_info("delete hpio %p for eid %u from iotab.\n", hpio, hpio->eid);
}

static void hpio_clear_pages(struct hpio *hpio)
{
	int i;

	if (!hpio->pages)
		return;

	for (i = 0; i < hpio->nr_page; i++)
		if (hpio->pages[i]) {
			put_page(hpio->pages[i]);
			atomic64_sub(PAGE_SIZE, &hpio_mem);
		}
	kfree(hpio->pages);
	atomic64_sub(sizeof(struct page *) * hpio->nr_page, &hpio_mem);
	hpio->nr_page = 0;
	hpio->pages = NULL;
}

/*
 * alloc pages array for @hpio, fill in new alloced pages if @new_page
 */
static bool hpio_fill_pages(struct hpio *hpio, u32 nr_page, gfp_t gfp, bool new_page)
{
	int i;

	BUG_ON(hpio->pages);
	hpio->nr_page = nr_page;
	hpio->pages = kcalloc(hpio->nr_page, sizeof(struct page *), gfp);
	if (!hpio->pages)
		goto err;
	atomic64_add(sizeof(struct page *) * hpio->nr_page, &hpio_mem);

	if (!new_page)
		goto out;
	for (i = 0; i < hpio->nr_page; i++) {
		hpio->pages[i] = alloc_page(gfp);
		if (!hpio->pages[i])
			goto err;
		atomic64_add(PAGE_SIZE, &hpio_mem);
	}
out:
	return true;
err:
	hpio_clear_pages(hpio);

	return false;
}

void hpio_free(struct hpio *hpio)
{
	if (!hpio)
		return;

	pr_info("free hpio = %p.\n", hpio);

	hpio_clear_pages(hpio);
	kfree(hpio);
	atomic64_sub(sizeof(struct hpio), &hpio_mem);
}

struct hpio *hpio_alloc(u32 nr_page, gfp_t gfp, unsigned int op, bool new_page)
{
	struct hpio *hpio = NULL;

	hpio = kzalloc(sizeof(struct hpio), gfp);
	if (!hpio)
		goto err;
	atomic64_add(sizeof(struct hpio), &hpio_mem);
	if (!hpio_fill_pages(hpio, nr_page, gfp, new_page))
		goto err;
	hpio->op = op;
	atomic_set(&hpio->state, HPIO_INIT);
	kref_init(&hpio->refcnt);
	init_completion(&hpio->wait);

	return hpio;
err:
	hpio_free(hpio);

	return NULL;
}

struct hpio *hpio_get(u32 eid)
{
	return iotab_search_get(&iotab, eid);
}

struct hpio *hpio_get_alloc(u32 eid, u32 nr_page, gfp_t gfp, unsigned int op)
{
	struct hpio *hpio = NULL;
	struct hpio *dup = NULL;

	hpio = iotab_search_get(&iotab, eid);
	if (hpio) {
		pr_info("find exist hpio %p for eid %u.\n", hpio, eid);
		goto out;
	}
	hpio = hpio_alloc(nr_page, gfp, op, true);
	if (!hpio)
		goto out;
	hpio->eid = eid;

	pr_info("alloc hpio %p for eid %u.\n", hpio, eid);

	dup = iotab_insert(&iotab, hpio);
	if (dup) {
		hpio_free(hpio);
		hpio = dup;
	}
out:
	return hpio;
}

static void hpio_release(struct kref *kref)
{
	struct hpio *hpio = container_of(kref, struct hpio, refcnt);

	iotab_delete(&iotab, hpio);
	if (hpio->free_extent)
		hpio->free_extent(hpio->eid);
	hpio_free(hpio);
}

bool hpio_put(struct hpio *hpio)
{
	pr_info("put hpio %p for eid %u, ref = %u.\n", hpio, hpio->eid, kref_read(&hpio->refcnt));
	return kref_put(&hpio->refcnt, hpio_release);
}

void hpio_complete(struct hpio *hpio)
{
	pr_info("complete hpio %p for eid %u.\n", hpio, hpio->eid);
	complete_all(&hpio->wait);
}

void hpio_wait(struct hpio *hpio)
{
	wait_for_completion(&hpio->wait);
}

enum hpio_state hpio_get_state(struct hpio *hpio)
{
	return atomic_read(&hpio->state);
}

void hpio_set_state(struct hpio *hpio, enum hpio_state state)
{
	atomic_set(&hpio->state, state);
}

bool hpio_change_state(struct hpio *hpio, enum hpio_state from, enum hpio_state to)
{
	return atomic_cmpxchg(&hpio->state, from, to) == from;
}

static void dump_iotab(struct hp_iotab *iotab)
{
	struct hpio *hpio = NULL;
	unsigned long flags;

	pr_info("dump inflight hpio in iotab.\n");
	read_lock_irqsave(&iotab->lock, flags);
	list_for_each_entry(hpio, &iotab->io_list, list)
		pr_info("hpio %p for eid %u is inflight.\n", hpio, hpio->eid);
	read_unlock_irqrestore(&iotab->lock, flags);
}

void wait_for_iotab_empty(void)
{
	dump_iotab(&iotab);
	wait_event(iotab.empty_wq, !iotab.io_cnt);
}
