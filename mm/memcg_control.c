// SPDX-License-Identifier: GPL-2.0
/*
 * mm/memcg_control.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */
#include <linux/memcontrol.h>
#include <linux/types.h>
#include <linux/cgroup-defs.h>
#include <linux/cgroup.h>
#include <linux/zswapd.h>
#include "internal.h"

#include "zswapd_internal.h"

#ifdef CONFIG_HYPERHOLD_MEMCG

struct list_head score_head;
bool score_head_inited;
DEFINE_RWLOCK(score_list_lock);
DEFINE_MUTEX(reclaim_para_lock);

/**
 * get_next_memcg - iterate over memory cgroup score_list
 * @prev: previously returned memcg, NULL on first invocation
 *
 * Returns references to the next memg on score_list of @prev,
 * or %NULL after a full round-trip.
 *
 * Caller must pass the return value in @prev on subsequent
 * invocations for reference counting, or use get_next_memcg_break()
 * to cancel a walk before the round-trip is complete.
 */
struct mem_cgroup *get_next_memcg(struct mem_cgroup *prev)
{
	struct mem_cgroup *memcg = NULL;
	struct list_head *pos = NULL;
	unsigned long flags;

	if (unlikely(!score_head_inited))
		return NULL;

	read_lock_irqsave(&score_list_lock, flags);

	if (unlikely(!prev))
		pos = &score_head;
	else
		pos = &(prev->score_node);

	if (list_empty(pos)) /* deleted node */
		goto unlock;

	if (pos->next == &score_head)
		goto unlock;

	memcg = list_entry(pos->next,
			struct mem_cgroup, score_node);

	if (!css_tryget(&memcg->css))
		memcg = NULL;

unlock:
	read_unlock_irqrestore(&score_list_lock, flags);

	if (prev)
		css_put(&prev->css);

	return memcg;
}

void get_next_memcg_break(struct mem_cgroup *memcg)
{
	if (memcg)
		css_put(&memcg->css);
}

struct mem_cgroup *get_prev_memcg(struct mem_cgroup *next)
{
	struct mem_cgroup *memcg = NULL;
	struct list_head *pos = NULL;
	unsigned long flags;

	if (unlikely(!score_head_inited))
		return NULL;

	read_lock_irqsave(&score_list_lock, flags);

	if (unlikely(!next))
		pos = &score_head;
	else
		pos = &next->score_node;

	if (list_empty(pos)) /* deleted node */
		goto unlock;

	if (pos->prev == &score_head)
		goto unlock;

	memcg = list_entry(pos->prev,
			struct mem_cgroup, score_node);

	if (unlikely(!memcg))
		goto unlock;

	if (!css_tryget(&memcg->css))
		memcg = NULL;

unlock:
	read_unlock_irqrestore(&score_list_lock, flags);

	if (next)
		css_put(&next->css);
	return memcg;
}

void get_prev_memcg_break(struct mem_cgroup *memcg)
{
	if (memcg)
		css_put(&memcg->css);
}

void memcg_app_score_update(struct mem_cgroup *target)
{
	struct list_head *pos = NULL;
	struct list_head *tmp;
	unsigned long flags;

	write_lock_irqsave(&score_list_lock, flags);
	list_for_each_prev_safe(pos, tmp, &score_head) {
		struct mem_cgroup *memcg = list_entry(pos,
				struct mem_cgroup, score_node);
		if (atomic64_read(&memcg->memcg_reclaimed.app_score) <
			atomic64_read(&target->memcg_reclaimed.app_score))
			break;
	}
	list_move_tail(&target->score_node, pos);
	write_unlock_irqrestore(&score_list_lock, flags);
}

static u64 mem_cgroup_app_score_read(struct cgroup_subsys_state *css,
				struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	return atomic64_read(&memcg->memcg_reclaimed.app_score);
}

static int mem_cgroup_app_score_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	if (val > MAX_APP_SCORE)
		return -EINVAL;

	if (atomic64_read(&memcg->memcg_reclaimed.app_score) != val) {
		atomic64_set(&memcg->memcg_reclaimed.app_score, val);
		memcg_app_score_update(memcg);
	}

	return 0;
}

static unsigned long move_pages_to_page_list(struct lruvec *lruvec, enum lru_list lru,
					     struct list_head *page_list)
{
	struct list_head *src = &lruvec->lists[lru];
	unsigned long nr_isolated = 0;
	struct page *page;

	while (!list_empty(src)) {
		page = lru_to_page(src);

		if (PageUnevictable(page))
			continue;

		if (likely(get_page_unless_zero(page))) {
			if (isolate_lru_page(page)) {
				put_page(page);
				continue;
			}
			put_page(page);

		} else {
			continue;
		}


		if (PageUnevictable(page)) {
			putback_lru_page(page);
			continue;
		}

		if (PageAnon(page) && !PageSwapBacked(page)) {
			putback_lru_page(page);
			continue;
		}

		list_add(&page->lru, page_list);
		nr_isolated++;
	}

	return nr_isolated;
}


unsigned long reclaim_all_anon_memcg(struct pglist_data *pgdat, struct mem_cgroup *memcg)
{
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
	unsigned long nr_reclaimed;
	LIST_HEAD(page_list);
	struct page *page;
	struct reclaim_stat stat = {};
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
	};

#ifdef CONFIG_RECLAIM_ACCT
	reclaimacct_substage_start(RA_SHRINKANON);
#endif
	count_vm_event(FREEZE_RECLAIME_COUNT);
	move_pages_to_page_list(lruvec, LRU_INACTIVE_ANON, &page_list);

	nr_reclaimed = shrink_page_list(&page_list, pgdat, &sc, &stat, true);
	count_vm_event(FREEZE_RECLAIMED);

	while (!list_empty(&page_list)) {
		page = lru_to_page(&page_list);
		list_del(&page->lru);
		putback_lru_page(page);
	}

#ifdef CONFIG_RECLAIM_ACCT
	reclaimacct_substage_end(RA_SHRINKANON, nr_reclaimed, NULL);
#endif

	return nr_reclaimed;
}

static ssize_t memcg_force_shrink_anon(struct kernfs_open_file *of,
				   char *buf, size_t nbytes,
				   loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	struct pglist_data *pgdat;
	int nid;

	for_each_online_node(nid) {
		pgdat = NODE_DATA(nid);
		reclaim_all_anon_memcg(pgdat, memcg);
	}

	return nbytes;
}

static int memcg_name_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));

	seq_printf(m, "%s\n", memcg->name);
	return 0;
}

static ssize_t memcg_name_write(struct kernfs_open_file *of, char *buf,
				     size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));

	buf = strstrip(buf);
	if (nbytes >= MEM_CGROUP_NAME_MAX_LEN)
		return -EINVAL;

	mutex_lock(&reclaim_para_lock);
	if (memcg)
		strcpy(memcg->name, buf);
	mutex_unlock(&reclaim_para_lock);

	return nbytes;
}

static int memcg_total_info_per_app_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = NULL;
	struct mem_cgroup_per_node *mz = NULL;
	struct lruvec *lruvec = NULL;
	unsigned long anon_size;
	unsigned long zram_compress_size;
	unsigned long eswap_compress_size;


	while ((memcg = get_next_memcg(memcg))) {
		mz = mem_cgroup_nodeinfo(memcg, 0);
		if (!mz) {
			get_next_memcg_break(memcg);
			return 0;
		}

		lruvec = &mz->lruvec;
		if (!lruvec) {
			get_next_memcg_break(memcg);
			return 0;
		}

		anon_size = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON, MAX_NR_ZONES) +
			    lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES);
		zram_compress_size = memcg_data_size(memcg, CACHE_SIZE);
		eswap_compress_size = memcg_data_size(memcg, SWAP_SIZE);
		anon_size *= PAGE_SIZE / SZ_1K;
		zram_compress_size /= SZ_1K;
		eswap_compress_size /= SZ_1K;

		if (!strlen(memcg->name))
			continue;

		seq_printf(m, "%s %lu %lu %lu\n", memcg->name, anon_size,
			   zram_compress_size, eswap_compress_size);
	}

	return 0;
}

static int memcg_ub_ufs2zram_ratio_write(struct cgroup_subsys_state *css,
					 struct cftype *cft, u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	const unsigned int ratio = 100;

	if (val > ratio)
		return -EINVAL;

	atomic64_set(&memcg->memcg_reclaimed.ub_ufs2zram_ratio, val);

	return 0;
}

static u64 memcg_ub_ufs2zram_ratio_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	return atomic64_read(&memcg->memcg_reclaimed.ub_ufs2zram_ratio);
}

static int memcg_force_swapin_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	u64 size;
	const unsigned int ratio = 100;

	size = memcg_data_size(memcg, SWAP_SIZE);
	size = div_u64(atomic64_read(&memcg->memcg_reclaimed.ub_ufs2zram_ratio) * size, ratio);

	swapin_memcg(memcg, size);

	return 0;
}

#ifdef CONFIG_MEM_PURGEABLE
static unsigned long purgeable_memcg_node(pg_data_t *pgdata,
	struct scan_control *sc, struct mem_cgroup *memcg)
{
	unsigned long nr = 0;
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdata);
	if (!lruvec)
		return 0;

	shrink_list(LRU_ACTIVE_PURGEABLE, -1, lruvec, sc);
	nr += shrink_list(LRU_INACTIVE_PURGEABLE, -1, lruvec, sc);

	pr_info("reclaim %lu purgeable pages \n", nr);
	return nr;
}

static int memcg_force_shrink_purgeable_bysize(struct cgroup_subsys_state *css,
	struct cftype *cft, u64 reclaim_size)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	if (!memcg)
		return 0;

	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.order = 0,
		.priority = DEF_PRIORITY,
		.may_deactivate = DEACTIVATE_ANON,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
		.reclaim_idx = MAX_NR_ZONES -1,
	};
	int nid = 0;
	sc.nr_to_reclaim = div_u64(reclaim_size, PAGE_SIZE);

	for_each_node_state(nid, N_MEMORY)
		purgeable_memcg_node(NODE_DATA(nid), &sc, memcg);
	return 0;
}
#endif

static struct cftype memcg_policy_files[] = {
	{
		.name = "name",
		.write = memcg_name_write,
		.seq_show = memcg_name_show,
	},
	{
		.name = "ub_ufs2zram_ratio",
		.write_u64 = memcg_ub_ufs2zram_ratio_write,
		.read_u64 = memcg_ub_ufs2zram_ratio_read,
	},
	{
		.name = "total_info_per_app",
		.seq_show = memcg_total_info_per_app_show,
	},
	{
		.name = "app_score",
		.write_u64 = mem_cgroup_app_score_write,
		.read_u64 = mem_cgroup_app_score_read,
	},
	{
		.name = "force_shrink_anon",
		.write = memcg_force_shrink_anon
	},
	{
		.name = "force_swapin",
		.write_u64 = memcg_force_swapin_write,
	},
#ifdef CONFIG_MEM_PURGEABLE
	{
		.name = "force_shrink_purgeable_bysize",
		.write_u64 = memcg_force_shrink_purgeable_bysize,
	},
#endif
	{ },	/* terminate */
};

static int __init memcg_policy_init(void)
{
	if (!mem_cgroup_disabled())
		WARN_ON(cgroup_add_legacy_cftypes(&memory_cgrp_subsys,
						memcg_policy_files));

	return 0;
}
subsys_initcall(memcg_policy_init);
#else
struct mem_cgroup *get_next_memcg(struct mem_cgroup *prev)
{
	return NULL;
}

void get_next_memcg_break(struct mem_cgroup *memcg)
{
}


struct mem_cgroup *get_prev_memcg(struct mem_cgroup *next)
{
	return NULL;
}

void get_prev_memcg_break(struct mem_cgroup *memcg)
{
}

static u64 mem_cgroup_app_score_read(struct cgroup_subsys_state *css,
				struct cftype *cft)
{
	return 0;
}

static int mem_cgroup_app_score_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	return 0;
}

void memcg_app_score_update(struct mem_cgroup *target)
{
}
#endif
