// SPDX-License-Identifier: GPL-2.0
/*
 * mm/zswapd.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#include <linux/freezer.h>
#include <linux/memcg_policy.h>
#include <trace/events/vmscan.h>
#include <uapi/linux/sched/types.h>
#include <linux/zswapd.h>
#ifdef CONFIG_RECLAIM_ACCT
#include <linux/reclaim_acct.h>
#endif

#include "zswapd_internal.h"
#include "internal.h"

#define UNSET_ZRAM_WM_RATIO 0
#define DEFAULT_ZRAM_WM_RATIO 37
#define SWAP_MORE_ZRAM (50 * (SZ_1M))

static wait_queue_head_t snapshotd_wait;
static atomic_t snapshotd_wait_flag;
static atomic_t snapshotd_init_flag = ATOMIC_INIT(0);
static struct task_struct *snapshotd_task;

static pid_t zswapd_pid = -1;
static unsigned long long last_anon_pagefault;
static unsigned long long anon_refault_ratio;
static unsigned long long zswapd_skip_interval;
static unsigned long last_zswapd_time;
static unsigned long last_snapshot_time;
bool last_round_is_empty;


DECLARE_RWSEM(gs_lock);
LIST_HEAD(gs_list);

void unregister_group_swap(struct group_swap_device *gsdev)
{
	down_write(&gs_lock);
	list_del(&gsdev->list);
	up_write(&gs_lock);

	kfree(gsdev);
}
EXPORT_SYMBOL(unregister_group_swap);

struct group_swap_device *register_group_swap(struct group_swap_ops *ops, void *priv)
{
	struct group_swap_device *gsdev = kzalloc(sizeof(struct group_swap_device), GFP_KERNEL);

	if (!gsdev)
		return NULL;

	gsdev->priv = priv;
	gsdev->ops = ops;

	down_write(&gs_lock);
	list_add(&gsdev->list, &gs_list);
	up_write(&gs_lock);

	return gsdev;
}
EXPORT_SYMBOL(register_group_swap);

u64 memcg_data_size(struct mem_cgroup *memcg, int type)
{
	struct group_swap_device *gsdev = NULL;
	u64 size = 0;

	down_read(&gs_lock);
	list_for_each_entry(gsdev, &gs_list, list)
		size += gsdev->ops->group_data_size(memcg->id.id, type, gsdev->priv);
	up_read(&gs_lock);

	return size;
}

u64 swapin_memcg(struct mem_cgroup *memcg, u64 req_size)
{
	u64 swap_size = memcg_data_size(memcg, SWAP_SIZE);
	u64 read_size = 0;
	u64 ratio = atomic64_read(&memcg->memcg_reclaimed.ub_ufs2zram_ratio);
	struct group_swap_device *gsdev = NULL;

	if (req_size > swap_size * ratio)
		req_size = swap_size * ratio;
	down_read(&gs_lock);
	list_for_each_entry(gsdev, &gs_list, list) {
		read_size += gsdev->ops->group_write(memcg->id.id, req_size - read_size,
							gsdev->priv);
		if (read_size >= req_size)
			break;
	}
	up_read(&gs_lock);

	return read_size;
}

static u64 swapout_memcg(struct mem_cgroup *memcg, u64 req_size)
{
	u64 cache_size = memcg_data_size(memcg, CACHE_SIZE);
	u64 swap_size = memcg_data_size(memcg, SWAP_SIZE);
	u64 all_size = cache_size + swap_size;
	u64 write_size = 0;
	u32 ratio = atomic_read(&memcg->memcg_reclaimed.ub_zram2ufs_ratio);
	struct group_swap_device *gsdev = NULL;

	if (all_size * ratio <= swap_size)
		return 0;
	if (req_size > all_size * ratio - swap_size)
		req_size = all_size * ratio - swap_size;
	down_read(&gs_lock);
	list_for_each_entry(gsdev, &gs_list, list) {
		write_size += gsdev->ops->group_write(memcg->id.id, req_size - write_size,
							gsdev->priv);
		if (write_size >= req_size)
			break;
	}
	up_read(&gs_lock);

	return write_size;
}

static u64 swapout(u64 req_size)
{
	struct mem_cgroup *memcg = NULL;
	u64 write_size = 0;

	while ((memcg = get_next_memcg(memcg)) != NULL) {
		write_size += swapout_memcg(memcg, req_size - write_size);
		if (write_size >= req_size)
			break;
	}

	return write_size;
}

static unsigned long long get_zram_used_pages(void)
{
	struct mem_cgroup *memcg = NULL;
	unsigned long long zram_pages = 0;

	while ((memcg = get_next_memcg(memcg)) != NULL)
		zram_pages += memcg_data_size(memcg, CACHE_PAGE);

	return zram_pages;
}

static unsigned long long get_eswap_used_pages(void)
{
	struct mem_cgroup *memcg = NULL;
	unsigned long long eswap_pages = 0;

	while ((memcg = get_next_memcg(memcg)) != NULL)
		eswap_pages += memcg_data_size(memcg, SWAP_PAGE);

	return eswap_pages;
}

static unsigned long long get_zram_pagefault(void)
{
	struct mem_cgroup *memcg = NULL;
	unsigned long long cache_fault = 0;

	while ((memcg = get_next_memcg(memcg)) != NULL)
		cache_fault += memcg_data_size(memcg, CACHE_FAULT);

	return cache_fault;
}

static unsigned int calc_sys_cur_avail_buffers(void)
{
	const unsigned int percent_constant = 100;
	unsigned long freemem;
	unsigned long active_file;
	unsigned long inactive_file;
	unsigned long buffers;

	freemem = global_zone_page_state(NR_FREE_PAGES) * PAGE_SIZE / SZ_1K;
	active_file = global_node_page_state(NR_ACTIVE_FILE) * PAGE_SIZE / SZ_1K;
	inactive_file = global_node_page_state(NR_INACTIVE_FILE) * PAGE_SIZE / SZ_1K;

	buffers = freemem + inactive_file * get_inactive_file_ratio() / percent_constant +
		active_file * get_active_file_ratio() / percent_constant;

	return (buffers * SZ_1K / SZ_1M); /* kb to mb */
}

void zswapd_status_show(struct seq_file *m)
{
	unsigned int buffers = calc_sys_cur_avail_buffers();

	seq_printf(m, "buffer_size:%u\n", buffers);
	seq_printf(m, "recent_refault:%llu\n", anon_refault_ratio);
}

pid_t get_zswapd_pid(void)
{
	return zswapd_pid;
}

static bool min_buffer_is_suitable(void)
{
	unsigned int buffers = calc_sys_cur_avail_buffers();

	if (buffers >= get_min_avail_buffers())
		return true;

	return false;
}

static bool buffer_is_suitable(void)
{
	unsigned int buffers = calc_sys_cur_avail_buffers();

	if (buffers >= get_avail_buffers())
		return true;

	return false;
}

static bool high_buffer_is_suitable(void)
{
	unsigned int buffers = calc_sys_cur_avail_buffers();

	if (buffers >= get_high_avail_buffers())
		return true;

	return false;
}

static void snapshot_anon_refaults(void)
{
	struct mem_cgroup *memcg = NULL;

	while ((memcg = get_next_memcg(memcg)) != NULL)
		memcg->memcg_reclaimed.reclaimed_pagefault = memcg_data_size(memcg, CACHE_FAULT);

	last_anon_pagefault = get_zram_pagefault();
	last_snapshot_time = jiffies;
}

/*
 * Return true if refault changes between two read operations.
 */
static bool get_memcg_anon_refault_status(struct mem_cgroup *memcg)
{
	const unsigned int percent_constant = 100;
	unsigned long long anon_pagefault;
	unsigned long long anon_total;
	unsigned long long ratio;
	struct mem_cgroup_per_node *mz = NULL;
	struct lruvec *lruvec = NULL;

	if (!memcg)
		return false;

	anon_pagefault = memcg_data_size(memcg, CACHE_FAULT);
	if (anon_pagefault == memcg->memcg_reclaimed.reclaimed_pagefault)
		return false;

	mz = mem_cgroup_nodeinfo(memcg, 0);
	if (!mz)
		return false;

	lruvec = &mz->lruvec;
	if (!lruvec)
		return false;

	anon_total = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES) +
		memcg_data_size(memcg, SWAP_PAGE) + memcg_data_size(memcg, CACHE_PAGE);

	ratio = div64_u64((anon_pagefault - memcg->memcg_reclaimed.reclaimed_pagefault) *
			percent_constant, (anon_total + 1));
	if (ratio > atomic_read(&memcg->memcg_reclaimed.refault_threshold))
		return true;

	return false;
}

static bool get_area_anon_refault_status(void)
{
	const unsigned int percent_constant = 1000;
	unsigned long long anon_pagefault;
	unsigned long long ratio;
	unsigned long long time;

	anon_pagefault = get_zram_pagefault();
	time = jiffies;
	if (anon_pagefault == last_anon_pagefault || time == last_snapshot_time)
		return false;

	ratio = div_u64((anon_pagefault - last_anon_pagefault) * percent_constant,
			(jiffies_to_msecs(time - last_snapshot_time) + 1));
	anon_refault_ratio = ratio;

	if (ratio > get_area_anon_refault_threshold())
		return true;

	return false;
}

void wakeup_snapshotd(void)
{
	unsigned long snapshot_interval;

	snapshot_interval = jiffies_to_msecs(jiffies - last_snapshot_time);
	if (snapshot_interval >= get_anon_refault_snapshot_min_interval()) {
		atomic_set(&snapshotd_wait_flag, 1);
		wake_up_interruptible(&snapshotd_wait);
	}
}

static int snapshotd(void *p)
{
	int ret;

	while (!kthread_should_stop()) {
		ret = wait_event_interruptible(snapshotd_wait, atomic_read(&snapshotd_wait_flag));
		if (ret)
			continue;

		atomic_set(&snapshotd_wait_flag, 0);

		snapshot_anon_refaults();
		count_vm_event(ZSWAPD_SNAPSHOT_TIMES);
	}

	return 0;
}

void set_snapshotd_init_flag(unsigned int val)
{
	atomic_set(&snapshotd_init_flag, val);
}

/*
 * This snapshotd start function will be called by init.
 */
int snapshotd_run(void)
{
	atomic_set(&snapshotd_wait_flag, 0);
	init_waitqueue_head(&snapshotd_wait);

	snapshotd_task = kthread_run(snapshotd, NULL, "snapshotd");
	if (IS_ERR(snapshotd_task)) {
		pr_err("Failed to start snapshotd\n");
		return PTR_ERR(snapshotd_task);
	}

	return 0;
}

static int __init snapshotd_init(void)
{
	snapshotd_run();

	return 0;
}
module_init(snapshotd_init);

static int get_zswapd_eswap_policy(void)
{
	if (get_zram_wm_ratio() == UNSET_ZRAM_WM_RATIO)
		return CHECK_BUFFER_ONLY;
	else
		return CHECK_BUFFER_ZRAMRATIO_BOTH;
}

static unsigned int get_policy_zram_wm_ratio(void)
{
	enum zswapd_eswap_policy policy = get_zswapd_eswap_policy();

	if (policy == CHECK_BUFFER_ONLY)
		return DEFAULT_ZRAM_WM_RATIO;
	else
		return get_zram_wm_ratio();
}

int get_zram_current_watermark(void)
{
	long long diff_buffers;
	const unsigned int percent_constant = 10;
	u64 nr_total;
	unsigned int zram_wm_ratio = get_policy_zram_wm_ratio();

	nr_total = totalram_pages();
	/* B_target - B_current */
	diff_buffers = get_avail_buffers() - calc_sys_cur_avail_buffers();
	/* MB to page */
	diff_buffers *= SZ_1M / PAGE_SIZE;
	/* after_comp to before_comp */
	diff_buffers *= get_compress_ratio();
	/* page to ratio */
	diff_buffers = div64_s64(diff_buffers * percent_constant, nr_total);

	return min((long long)zram_wm_ratio, zram_wm_ratio - diff_buffers);
}

bool zram_watermark_ok(void)
{
	const unsigned int percent_constant = 100;
	u64 nr_zram_used;
	u64 nr_wm;
	u64 ratio;

	ratio = get_zram_current_watermark();
	nr_zram_used = get_zram_used_pages();
	nr_wm = div_u64(totalram_pages() * ratio, percent_constant);
	if (nr_zram_used > nr_wm)
		return true;

	return false;
}

bool zram_watermark_exceed(void)
{
	u64 nr_zram_used;
	const unsigned long long nr_wm = get_zram_critical_threshold() * (SZ_1M / PAGE_SIZE);

	if (!nr_wm)
		return false;

	nr_zram_used = get_zram_used_pages();
	if (nr_zram_used > nr_wm)
		return true;
	return false;
}

void wakeup_zswapd(pg_data_t *pgdat)
{
	unsigned long interval;

	if (IS_ERR(pgdat->zswapd))
		return;

	if (!wq_has_sleeper(&pgdat->zswapd_wait))
		return;

	/*
	 * make anon pagefault snapshots
	 * wake up snapshotd
	 */
	if (atomic_read(&snapshotd_init_flag) == 1)
		wakeup_snapshotd();

	/* wake up when the buffer is lower than min_avail_buffer */
	if (min_buffer_is_suitable())
		return;

	interval = jiffies_to_msecs(jiffies - last_zswapd_time);
	if (interval < zswapd_skip_interval) {
		count_vm_event(ZSWAPD_EMPTY_ROUND_SKIP_TIMES);
		return;
	}

	atomic_set(&pgdat->zswapd_wait_flag, 1);
	wake_up_interruptible(&pgdat->zswapd_wait);
}

void wake_all_zswapd(void)
{
	pg_data_t *pgdat = NULL;
	int nid;

	for_each_online_node(nid) {
		pgdat = NODE_DATA(nid);
		wakeup_zswapd(pgdat);
	}
}

#ifdef CONFIG_HYPERHOLD_FILE_LRU
static void zswapd_shrink_active_list(unsigned long nr_to_scan,
	struct lruvec *lruvec, struct scan_control *sc, enum lru_list lru)
{
	unsigned int nr_deactivate;
	unsigned long nr_scanned;
	unsigned long nr_taken;

	struct page *page = NULL;
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	unsigned long *node_anon_cost = &pgdat->__lruvec.anon_cost;
	unsigned long *anon_cost = &lruvec->anon_cost;
	LIST_HEAD(l_inactive);
	LIST_HEAD(l_hold);

	lru_add_drain();

	spin_lock_irq(&pgdat->lru_lock);
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &l_hold, &nr_scanned, sc, lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON, nr_taken);
	*anon_cost += nr_taken;
	*node_anon_cost += nr_taken;
	__count_vm_events(PGREFILL, nr_scanned);
	count_memcg_events(lruvec_memcg(lruvec), PGREFILL, nr_scanned);
	spin_unlock_irq(&pgdat->lru_lock);

	while (!list_empty(&l_hold)) {
		cond_resched();
		page = lru_to_page(&l_hold);
		list_del(&page->lru);

		if (unlikely(!page_evictable(page))) {
			putback_lru_page(page);
			continue;
		}

		ClearPageActive(page);
		SetPageWorkingset(page);
		list_add(&page->lru, &l_inactive);
	}

	spin_lock_irq(&pgdat->lru_lock);
	nr_deactivate = move_pages_to_lru(lruvec, &l_inactive);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON, -nr_taken);
	spin_unlock_irq(&pgdat->lru_lock);

	mem_cgroup_uncharge_list(&l_inactive);
	free_unref_page_list(&l_inactive);

	trace_mm_vmscan_lru_zswapd_shrink_active(pgdat->node_id, nr_taken,
			nr_deactivate, sc->priority);
}

static unsigned long zswapd_shrink_list(enum lru_list lru,
		unsigned long nr_to_scan, struct lruvec *lruvec,
		struct scan_control *sc)
{
#ifdef CONFIG_RECLAIM_ACCT
	unsigned long nr_reclaimed;

	reclaimacct_substage_start(RA_SHRINKANON);
#endif
	if (is_active_lru(lru)) {
		if (sc->may_deactivate & (1 << is_file_lru(lru)))
			zswapd_shrink_active_list(nr_to_scan, lruvec, sc, lru);
		else
			sc->skipped_deactivate = 1;
#ifdef CONFIG_RECLAIM_ACCT
		reclaimacct_substage_end(RA_SHRINKANON, 0, NULL);
#endif
		return 0;
	}

#ifdef CONFIG_RECLAIM_ACCT
	nr_reclaimed = shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
	reclaimacct_substage_end(RA_SHRINKANON, nr_reclaimed, NULL);
	return nr_reclaimed;
#else
	return shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
#endif
}

static void zswapd_shrink_anon_memcg(struct pglist_data *pgdat,
	struct mem_cgroup *memcg, struct scan_control *sc, unsigned long *nr)
{
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
	unsigned long nr_reclaimed = 0;
	unsigned long nr_to_scan;
	struct blk_plug plug;
	enum lru_list lru;

	blk_start_plug(&plug);

	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_ANON]) {
		for (lru = 0; lru <= LRU_ACTIVE_ANON; lru++) {
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;
				nr_reclaimed += zswapd_shrink_list(lru,
							nr_to_scan, lruvec, sc);
			}
		}
	}

	blk_finish_plug(&plug);
	sc->nr_reclaimed += nr_reclaimed;
}
#endif

static bool zswapd_shrink_anon(pg_data_t *pgdat, struct scan_control *sc)
{
	const unsigned int percent_constant = 100;
	struct mem_cgroup *memcg = NULL;
	unsigned long nr[NR_LRU_LISTS];

	while ((memcg = get_next_memcg(memcg)) != NULL) {
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
		u64 nr_active, nr_inactive, nr_zram, nr_eswap, zram_ratio;

		/* reclaim and try to meet the high buffer watermark */
		if (high_buffer_is_suitable()) {
			get_next_memcg_break(memcg);
			break;
		}

		if (get_memcg_anon_refault_status(memcg)) {
			count_vm_event(ZSWAPD_MEMCG_REFAULT_SKIP);
			continue;
		}

		nr_active = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON, MAX_NR_ZONES);
		nr_inactive = lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES);
		nr_zram = memcg_data_size(memcg, CACHE_PAGE);
		nr_eswap = memcg_data_size(memcg, SWAP_PAGE);

		zram_ratio = div64_u64((nr_zram + nr_eswap) * percent_constant,
				(nr_inactive + nr_active + nr_zram + nr_eswap + 1));
		if (zram_ratio >= (u32)atomic_read(&memcg->memcg_reclaimed.ub_mem2zram_ratio)) {
			count_vm_event(ZSWAPD_MEMCG_RATIO_SKIP);
			continue;
		}

		nr[LRU_ACTIVE_ANON] = nr_active >> (unsigned int)sc->priority;
		nr[LRU_INACTIVE_ANON] = nr_inactive >> (unsigned int)sc->priority;
		nr[LRU_ACTIVE_FILE] = 0;
		nr[LRU_INACTIVE_FILE] = 0;

#ifdef CONFIG_HYPERHOLD_FILE_LRU
		zswapd_shrink_anon_memcg(pgdat, memcg, sc, nr);
#else
		shrink_lruvec(lruvec, sc);
#endif
		shrink_slab(sc->gfp_mask, pgdat->node_id, memcg, sc->priority);

		if (sc->nr_reclaimed >= sc->nr_to_reclaim) {
			get_next_memcg_break(memcg);
			break;
		}
	}

	return sc->nr_scanned >= sc->nr_to_reclaim;
}

static u64 __calc_nr_to_reclaim(void)
{
	unsigned int buffers;
	unsigned int high_buffers;
	unsigned int max_reclaim_size;
	u64 reclaim_size = 0;

	high_buffers = get_high_avail_buffers();
	buffers = calc_sys_cur_avail_buffers();
	max_reclaim_size = get_zswapd_max_reclaim_size();
	if (buffers < high_buffers)
		reclaim_size = high_buffers - buffers;

	/* once max reclaim target is max_reclaim_size */
	reclaim_size = min(reclaim_size, (u64)max_reclaim_size);

	/* MB to pages */
	return div_u64(reclaim_size * SZ_1M, PAGE_SIZE);
}

static void zswapd_shrink_node(pg_data_t *pgdat)
{
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.order = 0,
		.priority = DEF_PRIORITY / 2,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
	};
	const unsigned int increase_rate = 2;

	do {
		unsigned long nr_reclaimed = sc.nr_reclaimed;
		bool raise_priority = true;

		/* reclaim and try to meet the high buffer watermark */
		if (high_buffer_is_suitable())
			break;

		sc.nr_scanned = 0;
		sc.nr_to_reclaim = __calc_nr_to_reclaim();

		if (zswapd_shrink_anon(pgdat, &sc))
			raise_priority = false;
		count_vm_events(ZSWAPD_SCANNED, sc.nr_scanned);
		count_vm_events(ZSWAPD_RECLAIMED, sc.nr_reclaimed);
		if (try_to_freeze() || kthread_should_stop())
			break;

		nr_reclaimed = sc.nr_reclaimed - nr_reclaimed;
		if (raise_priority || !nr_reclaimed)
			sc.priority--;
	} while (sc.priority >= 1);

	/*
	 * When meets the first empty round, set the interval to t.
	 * If the following round is still empty, set the intervall
	 * to 2t. If the round is always empty, then 4t, 8t, and so on.
	 * But make sure the interval is not more than the max_skip_interval.
	 * Once a non-empty round occurs, reset the interval to 0.
	 */
	if (sc.nr_reclaimed < get_empty_round_check_threshold()) {
		count_vm_event(ZSWAPD_EMPTY_ROUND);
		if (last_round_is_empty)
			zswapd_skip_interval = min(zswapd_skip_interval *
				increase_rate, get_max_skip_interval());
		else
			zswapd_skip_interval = get_empty_round_skip_interval();
		last_round_is_empty = true;
	} else {
		zswapd_skip_interval = 0;
		last_round_is_empty = false;
	}
}

u64 zram_watermark_diff(void)
{
	const unsigned int percent_constant = 100;
	u64 nr_zram_used;
	u64 nr_wm;
	u64 ratio;

	ratio = get_zram_current_watermark();
	nr_zram_used = get_zram_used_pages();
	nr_wm = div_u64(totalram_pages() * ratio, percent_constant);
	if (nr_zram_used > nr_wm)
		return (nr_zram_used - nr_wm) * PAGE_SIZE + SWAP_MORE_ZRAM;

	return 0;
}

u64 zswapd_buffer_diff(void)
{
	u64 buffers;
	u64 avail;

	buffers = calc_sys_cur_avail_buffers();
	avail = get_high_avail_buffers();
	if (buffers < avail)
		return (avail - buffers) * SZ_1M;

	return 0;
}

u64 get_do_eswap_size(bool refault)
{
	u64 size = 0;
	enum zswapd_eswap_policy policy = get_zswapd_eswap_policy();

	if (policy == CHECK_BUFFER_ZRAMRATIO_BOTH)
		size = max(zram_watermark_diff(), zswapd_buffer_diff());
	else if (policy == CHECK_BUFFER_ONLY && (zram_watermark_ok() || refault))
		size = zswapd_buffer_diff();

	return size;
}

static int zswapd(void *p)
{
	struct task_struct *tsk = current;
	pg_data_t *pgdat = (pg_data_t *)p;
	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);
#ifdef CONFIG_RECLAIM_ACCT
	struct reclaim_acct ra = {0};
#endif

	/* save zswapd pid for schedule strategy */
	zswapd_pid = tsk->pid;


	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(tsk, cpumask);

	set_freezable();

	while (!kthread_should_stop()) {
		bool refault = false;
		u64 size = 0;

		(void)wait_event_freezable(pgdat->zswapd_wait,
			atomic_read(&pgdat->zswapd_wait_flag));
		atomic_set(&pgdat->zswapd_wait_flag, 0);
		count_vm_event(ZSWAPD_WAKEUP);
		zswapd_pressure_report(LEVEL_LOW);

		if (get_area_anon_refault_status()) {
			refault = true;
			count_vm_event(ZSWAPD_REFAULT);
			goto do_eswap;
		}

#ifdef CONFIG_RECLAIM_ACCT
		reclaimacct_start(ZSWAPD_RECLAIM, &ra);
#endif
		zswapd_shrink_node(pgdat);
#ifdef CONFIG_RECLAIM_ACCT
		reclaimacct_end(ZSWAPD_RECLAIM);
#endif
		last_zswapd_time = jiffies;

do_eswap:
		size = get_do_eswap_size(refault);
		if (size >= SZ_1M) {
			count_vm_event(ZSWAPD_SWAPOUT);
			size = swapout(size);
		}

		if (!buffer_is_suitable()) {
			if (free_swap_is_low() || zram_watermark_exceed()) {
				zswapd_pressure_report(LEVEL_CRITICAL);
				count_vm_event(ZSWAPD_CRITICAL_PRESS);
				pr_info("%s:zrampages:%llu, eswappages:%llu\n", __func__,
					get_zram_used_pages(), get_eswap_used_pages());
			} else {
				zswapd_pressure_report(LEVEL_MEDIUM);
				count_vm_event(ZSWAPD_MEDIUM_PRESS);
			}
		}
	}

	return 0;
}

/*
 * This zswapd start function will be called by init and node-hot-add.
 */
int zswapd_run(int nid)
{
	const unsigned int priority_less = 5;
	struct sched_param param = {
		.sched_priority = MAX_PRIO - priority_less,
	};
	pg_data_t *pgdat = NODE_DATA(nid);

	if (pgdat->zswapd)
		return 0;

	atomic_set(&pgdat->zswapd_wait_flag, 0);
	pgdat->zswapd = kthread_create(zswapd, pgdat, "zswapd%d", nid);
	if (IS_ERR(pgdat->zswapd)) {
		pr_err("Failed to start zswapd on node %d\n", nid);
		return PTR_ERR(pgdat->zswapd);
	}

	sched_setscheduler_nocheck(pgdat->zswapd, SCHED_NORMAL, &param);
	set_user_nice(pgdat->zswapd, PRIO_TO_NICE(param.sched_priority));
	wake_up_process(pgdat->zswapd);

	return 0;
}

/*
 * Called by memory hotplug when all memory in a node is offlined. Caller must
 * hold mem_hotplug_begin/end().
 */
void zswapd_stop(int nid)
{
	struct task_struct *zswapd = NODE_DATA(nid)->zswapd;

	if (zswapd) {
		kthread_stop(zswapd);
		NODE_DATA(nid)->zswapd = NULL;
	}

	zswapd_pid = -1;
}

/*
 * It's optimal to keep kswapds on the same CPUs as their memory, but
 * not required for correctness. So if the last cpu in a node goes away,
 * we get changed to run anywhere: as the first one comes back, restore
 * their cpu bindings.
 */
static int zswapd_cpu_online(unsigned int cpu)
{
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		pg_data_t *pgdat = NODE_DATA(nid);
		const struct cpumask *mask;

		mask = cpumask_of_node(pgdat->node_id);
		if (cpumask_any_and(cpu_online_mask, mask) < nr_cpu_ids)
			/* One of our CPUs online: restore mask */
			set_cpus_allowed_ptr(pgdat->zswapd, mask);
	}

	return 0;
}

static int __init zswapd_init(void)
{
	int nid;
	int ret;

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "mm/zswapd:online",
					zswapd_cpu_online, NULL);
	if (ret < 0) {
		pr_err("zswapd: failed to register hotplug callbacks.\n");
		return ret;
	}

	for_each_node_state(nid, N_MEMORY)
		zswapd_run(nid);

	return 0;
}
module_init(zswapd_init)
