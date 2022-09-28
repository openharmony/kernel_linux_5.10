// SPDX-License-Identifier: GPL-2.0
/*
 * mm/memcg_reclaim.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/hyperhold_inf.h>

#ifdef CONFIG_HYPERHOLD_FILE_LRU
#include <linux/memcg_policy.h>
#include "internal.h"
#endif

static inline bool is_swap_not_allowed(struct scan_control *sc, int swappiness)
{
	return !sc->may_swap || !swappiness || !get_nr_swap_pages();
}

/*
 * From 0 .. 100.  Higher means more swappy.
 */
#define HYPERHOLD_SWAPPINESS 100

static int get_hyperhold_swappiness(void)
{
	return is_hyperhold_enable() ? HYPERHOLD_SWAPPINESS : vm_swappiness;
}

static void get_scan_count_hyperhold(struct pglist_data *pgdat,
		struct scan_control *sc, unsigned long *nr,
		unsigned long *lru_pages)
{
	int swappiness = get_hyperhold_swappiness();
	struct lruvec *lruvec = node_lruvec(pgdat);
	u64 fraction[2];
	u64 denominator;
	enum scan_balance scan_balance;
	unsigned long ap, fp;
	enum lru_list lru;
	unsigned long pgdatfile;
	unsigned long pgdatfree;
	int z;
	unsigned long anon_cost, file_cost, total_cost;
	unsigned long total_high_wmark = 0;


	if (cgroup_reclaim(sc) && !swappiness) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	/*
	 * Do not apply any pressure balancing cleverness when the
	 * system is close to OOM, scan both anon and file equally
	 * (unless the swappiness setting disagrees with swapping).
	 */
	if (!sc->priority && swappiness) {
		scan_balance = SCAN_EQUAL;
		goto out;
	}

	if (!cgroup_reclaim(sc)) {
		pgdatfree = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
		pgdatfile = node_page_state(pgdat, NR_ACTIVE_FILE) +
			node_page_state(pgdat, NR_INACTIVE_FILE);

		for (z = 0; z < MAX_NR_ZONES; z++) {
			struct zone *zone = &pgdat->node_zones[z];

			if (!managed_zone(zone))
				continue;

			total_high_wmark += high_wmark_pages(zone);
		}

		if (unlikely(pgdatfile + pgdatfree <= total_high_wmark)) {
			/*
			 * Force SCAN_ANON if there are enough inactive
			 * anonymous pages on the LRU in eligible zones.
			 * Otherwise, the small LRU gets thrashed.
			 */
			if (!inactive_is_low(lruvec, LRU_INACTIVE_ANON) &&
				(lruvec_lru_size(lruvec, LRU_INACTIVE_ANON,
					sc->reclaim_idx) >>
					(unsigned int)sc->priority)) {
				scan_balance = SCAN_ANON;
				goto out;
			}
		}
	}

	/*
	 * If there is enough inactive page cache, i.e. if the size of the
	 * inactive list is greater than that of the active list *and* the
	 * inactive list actually has some pages to scan on this priority, we
	 * do not reclaim anything from the anonymous working set right now.
	 * Without the second condition we could end up never scanning an
	 * lruvec even if it has plenty of old anonymous pages unless the
	 * system is under heavy pressure.
	 */

	if (!IS_ENABLED(CONFIG_BALANCE_ANON_FILE_RECLAIM) &&
	    !inactive_is_low(lruvec, LRU_INACTIVE_FILE) &&
	    lruvec_lru_size(lruvec, LRU_INACTIVE_FILE, sc->reclaim_idx) >> sc->priority) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	scan_balance = SCAN_FRACT;

	/*
	 * Calculate the pressure balance between anon and file pages.
	 *
	 * The amount of pressure we put on each LRU is inversely
	 * proportional to the cost of reclaiming each list, as
	 * determined by the share of pages that are refaulting, times
	 * the relative IO cost of bringing back a swapped out
	 * anonymous page vs reloading a filesystem page (swappiness).
	 *
	 * Although we limit that influence to ensure no list gets
	 * left behind completely: at least a third of the pressure is
	 * applied, before swappiness.
	 *
	 * With swappiness at 100, anon and file have equal IO cost.
	 */
	total_cost = sc->anon_cost + sc->file_cost;
	anon_cost = total_cost + sc->anon_cost;
	file_cost = total_cost + sc->file_cost;
	total_cost = anon_cost + file_cost;

	ap = swappiness * (total_cost + 1);
	ap /= anon_cost + 1;

	fp = (200 - swappiness) * (total_cost + 1);
	fp /= file_cost + 1;

	fraction[0] = ap;
	fraction[1] = fp;
	denominator = ap + fp;

out:
	*lru_pages = 0;
	for_each_evictable_lru(lru) {
		int file = is_file_lru(lru);
		unsigned long lruvec_size;
		unsigned long scan;

		lruvec_size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);
		scan = lruvec_size;
		*lru_pages += scan;
		scan >>= sc->priority;

		switch (scan_balance) {
		case SCAN_EQUAL:
			/* Scan lists relative to size */
			break;
		case SCAN_FRACT:
			/*
			 * Scan types proportional to swappiness and
			 * their relative recent reclaim efficiency.
			 * Make sure we don't miss the last page on
			 * the offlined memory cgroups because of a
			 * round-off error.
			 */
			scan = DIV64_U64_ROUND_UP(scan * fraction[file],
						  denominator);
			break;
		case SCAN_FILE:
		case SCAN_ANON:
			/* Scan one type exclusively */
			if ((scan_balance == SCAN_FILE) != file)
				scan = 0;
			break;
		default:
			/* Look ma, no brain */
			BUG();
		}

		nr[lru] = scan;
	}
}

#define ISOLATE_LIMIT_CNT 5
void shrink_anon_memcg(struct pglist_data *pgdat,
		struct mem_cgroup *memcg, struct scan_control *sc,
		unsigned long *nr)
{
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	struct blk_plug plug;

	blk_start_plug(&plug);

	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_ANON]) {
		for (lru = 0; lru <= LRU_ACTIVE_ANON; lru++) {
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;
				nr_reclaimed +=
					shrink_list(lru, nr_to_scan,
							lruvec, sc);
			}
		}
		if (sc->nr_reclaimed >= sc->nr_to_reclaim ||
				(sc->isolate_count > ISOLATE_LIMIT_CNT &&
				sc->invoker == DIRECT_RECLAIM))
			break;
	}
	blk_finish_plug(&plug);
	sc->nr_reclaimed += nr_reclaimed;
	sc->nr_reclaimed_anon += nr_reclaimed;
}

static inline bool memcg_is_child_of(struct mem_cgroup *mcg, struct mem_cgroup *tmcg)
{
	if (tmcg == NULL)
		return true;

	while (!mem_cgroup_is_root(mcg)) {
		if (mcg == tmcg)
			break;

		mcg = parent_mem_cgroup(mcg);
	}

	return (mcg == tmcg);
}

static void shrink_anon(struct pglist_data *pgdat,
		struct scan_control *sc, unsigned long *nr)
{
	unsigned long reclaimed;
	unsigned long scanned;
	struct mem_cgroup *memcg = NULL;
	struct mem_cgroup *target_memcg = sc->target_mem_cgroup;
	unsigned long nr_memcg[NR_LRU_LISTS];
	unsigned long nr_node_active = lruvec_lru_size(
			node_lruvec(pgdat), LRU_ACTIVE_ANON, MAX_NR_ZONES);
	unsigned long nr_node_inactive = lruvec_lru_size(
			node_lruvec(pgdat), LRU_INACTIVE_ANON, MAX_NR_ZONES);

	while ((memcg = get_next_memcg(memcg))) {
		struct lruvec *lruvec = NULL;

		if (!memcg_is_child_of(memcg, target_memcg))
			continue;

		lruvec = mem_cgroup_lruvec(memcg, pgdat);

		reclaimed = sc->nr_reclaimed;
		scanned = sc->nr_scanned;

		nr_memcg[LRU_ACTIVE_ANON] = nr[LRU_ACTIVE_ANON] *
			lruvec_lru_size(lruvec, LRU_ACTIVE_ANON,
					MAX_NR_ZONES) / (nr_node_active + 1);
		nr_memcg[LRU_INACTIVE_ANON] = nr[LRU_INACTIVE_ANON] *
			lruvec_lru_size(lruvec, LRU_INACTIVE_ANON,
					MAX_NR_ZONES) / (nr_node_inactive + 1);
		nr_memcg[LRU_ACTIVE_FILE] = 0;
		nr_memcg[LRU_INACTIVE_FILE] = 0;

		/*
		 * This loop can become CPU-bound when target memcgs
		 * aren't eligible for reclaim - either because they
		 * don't have any reclaimable pages, or because their
		 * memory is explicitly protected. Avoid soft lockups.
		 */
		cond_resched();

		mem_cgroup_calculate_protection(target_memcg, memcg);

		if (mem_cgroup_below_min(memcg)) {
			/*
			 * Hard protection.
			 * If there is no reclaimable memory, OOM.
			 */
			continue;
		} else if (mem_cgroup_below_low(memcg)) {
			/*
			 * Soft protection.
			 * Respect the protection only as long as
			 * there is an unprotected supply
			 * of reclaimable memory from other cgroups.
			 */
			if (!sc->memcg_low_reclaim) {
				sc->memcg_low_skipped = 1;
				continue;
			}
			memcg_memory_event(memcg, MEMCG_LOW);
		}

		shrink_anon_memcg(pgdat, memcg, sc, nr_memcg);
		shrink_slab(sc->gfp_mask, pgdat->node_id, memcg,
					sc->priority);

		vmpressure(sc->gfp_mask, memcg, false,
				sc->nr_scanned - scanned,
				sc->nr_reclaimed - reclaimed);

		if (sc->nr_reclaimed >= sc->nr_to_reclaim ||
			(sc->isolate_count > ISOLATE_LIMIT_CNT &&
			sc->invoker == DIRECT_RECLAIM)) {
			get_next_memcg_break(memcg);
			break;
		}
	}
}

static void shrink_file(struct pglist_data *pgdat,
		struct scan_control *sc, unsigned long *nr)
{
	struct lruvec *lruvec = node_lruvec(pgdat);
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	struct blk_plug plug;

	blk_start_plug(&plug);

	while (nr[LRU_ACTIVE_FILE] || nr[LRU_INACTIVE_FILE]) {
		for (lru = LRU_INACTIVE_FILE; lru <= LRU_ACTIVE_FILE; lru++) {
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;
				nr_reclaimed +=
					shrink_list(lru,
							nr_to_scan,
							lruvec, sc);
			}
		}
	}
	blk_finish_plug(&plug);
	sc->nr_reclaimed += nr_reclaimed;
	sc->nr_reclaimed_file += nr_reclaimed;
}

bool shrink_node_hyperhold(struct pglist_data *pgdat, struct scan_control *sc)
{
	unsigned long nr_reclaimed;
	struct lruvec *target_lruvec;
	bool reclaimable = false;
	unsigned long file;

	target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);
	do {
		/* Get scan count for file and anon */
		unsigned long node_lru_pages = 0;
		unsigned long nr[NR_LRU_LISTS] = {0};

		memset(&sc->nr, 0, sizeof(sc->nr));
		nr_reclaimed = sc->nr_reclaimed;

		/*
		 * Determine the scan balance between anon and file LRUs.
		 */
		spin_lock_irq(&pgdat->lru_lock);
		sc->anon_cost = mem_cgroup_lruvec(NULL, pgdat)->anon_cost;
		sc->file_cost = node_lruvec(pgdat)->file_cost;
		spin_unlock_irq(&pgdat->lru_lock);

		/*
		 * Target desirable inactive:active list ratios for the anon
		 * and file LRU lists.
		 */
		if (!sc->force_deactivate) {
			unsigned long refaults;

			refaults = lruvec_page_state(target_lruvec,
					WORKINGSET_ACTIVATE_ANON);
			if (refaults != target_lruvec->refaults[0] ||
					inactive_is_low(target_lruvec, LRU_INACTIVE_ANON))
				sc->may_deactivate |= DEACTIVATE_ANON;
			else
				sc->may_deactivate &= ~DEACTIVATE_ANON;

			/*
			 * When refaults are being observed, it means a new
			 * workingset is being established. Deactivate to get
			 * rid of any stale active pages quickly.
			 */
#ifdef CONFIG_HYPERHOLD_FILE_LRU
			refaults = lruvec_page_state(node_lruvec(pgdat),
					WORKINGSET_ACTIVATE_FILE);
			if (refaults != node_lruvec(pgdat)->refaults[1] ||
					inactive_is_low(node_lruvec(pgdat), LRU_INACTIVE_FILE))
				sc->may_deactivate |= DEACTIVATE_FILE;
#else
			refaults = lruvec_page_state(target_lruvec,
					WORKINGSET_ACTIVATE_FILE);
			if (refaults != target_lruvec->refaults[1] ||
					inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
				sc->may_deactivate |= DEACTIVATE_FILE;
#endif
			else
				sc->may_deactivate &= ~DEACTIVATE_FILE;
		} else
			sc->may_deactivate = DEACTIVATE_ANON | DEACTIVATE_FILE;

		/*
		 * If we have plenty of inactive file pages that aren't
		 * thrashing, try to reclaim those first before touching
		 * anonymous pages.
		 */
#ifdef CONFIG_HYPERHOLD_FILE_LRU
		file = lruvec_page_state(node_lruvec(pgdat), NR_INACTIVE_FILE);
#else
		file = lruvec_page_state(target_lruvec, NR_INACTIVE_FILE);
#endif
		if (file >> sc->priority && !(sc->may_deactivate & DEACTIVATE_FILE))
			sc->cache_trim_mode = 1;
		else
			sc->cache_trim_mode = 0;

		/*
		 * Prevent the reclaimer from falling into the cache trap: as
		 * cache pages start out inactive, every cache fault will tip
		 * the scan balance towards the file LRU.  And as the file LRU
		 * shrinks, so does the window for rotation from references.
		 * This means we have a runaway feedback loop where a tiny
		 * thrashing file LRU becomes infinitely more attractive than
		 * anon pages.  Try to detect this based on file LRU size.
		 */
		if (!cgroup_reclaim(sc)) {
			unsigned long total_high_wmark = 0;
			unsigned long free, anon;
			int z;

			free = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
			file = node_page_state(pgdat, NR_ACTIVE_FILE) +
				node_page_state(pgdat, NR_INACTIVE_FILE);

			for (z = 0; z < MAX_NR_ZONES; z++) {
				struct zone *zone = &pgdat->node_zones[z];

				if (!managed_zone(zone))
					continue;

				total_high_wmark += high_wmark_pages(zone);
			}

			/*
			 * Consider anon: if that's low too, this isn't a
			 * runaway file reclaim problem, but rather just
			 * extreme pressure. Reclaim as per usual then.
			 */
			anon = node_page_state(pgdat, NR_INACTIVE_ANON);

			sc->file_is_tiny =
				file + free <= total_high_wmark &&
				!(sc->may_deactivate & DEACTIVATE_ANON) &&
				anon >> sc->priority;
		}

		get_scan_count_hyperhold(pgdat, sc, nr, &node_lru_pages);

		if (!cgroup_reclaim(sc)) {
			/* Shrink the Total-File-LRU */
			shrink_file(pgdat, sc, nr);
		}

		/* Shrink Anon by iterating score_list */
		shrink_anon(pgdat, sc, nr);

		if (sc->nr_reclaimed - nr_reclaimed)
			reclaimable = true;

		if (current_is_kswapd()) {
			/*
			 * If reclaim is isolating dirty pages under writeback,
			 * it implies that the long-lived page allocation rate
			 * is exceeding the page laundering rate. Either the
			 * global limits are not being effective at throttling
			 * processes due to the page distribution throughout
			 * zones or there is heavy usage of a slow backing
			 * device. The only option is to throttle from reclaim
			 * context which is not ideal as there is no guarantee
			 * the dirtying process is throttled in the same way
			 * balance_dirty_pages() manages.
			 *
			 * Once a node is flagged PGDAT_WRITEBACK, kswapd will
			 * count the number of pages under pages flagged for
			 * immediate reclaim and stall if any are encountered
			 * in the nr_immediate check below.
			 */
			if (sc->nr.writeback && sc->nr.writeback == sc->nr.taken)
				set_bit(PGDAT_WRITEBACK, &pgdat->flags);

			/* Allow kswapd to start writing pages during reclaim. */
			if (sc->nr.unqueued_dirty == sc->nr.file_taken)
				set_bit(PGDAT_DIRTY, &pgdat->flags);

			/*
			 * If kswapd scans pages marked for immediate
			 * reclaim and under writeback (nr_immediate), it
			 * implies that pages are cycling through the LRU
			 * faster than they are written so also forcibly stall.
			 */
			if (sc->nr.immediate)
				congestion_wait(BLK_RW_ASYNC, HZ/10);
		}
		/*
		 * Legacy memcg will stall in page writeback so avoid forcibly
		 * stalling in wait_iff_congested().
		 */
		if ((current_is_kswapd() ||
		    (cgroup_reclaim(sc) && writeback_throttling_sane(sc))) &&
		    sc->nr.dirty && sc->nr.dirty == sc->nr.congested)
			set_bit(LRUVEC_CONGESTED, &target_lruvec->flags);

		/*
		 * Stall direct reclaim for IO completions if underlying BDIs
		 * and node is congested. Allow kswapd to continue until it
		 * starts encountering unqueued dirty pages or cycling through
		 * the LRU too quickly.
		 */
		if (!current_is_kswapd() && current_may_throttle() &&
		    !sc->hibernation_mode &&
		    test_bit(LRUVEC_CONGESTED, &target_lruvec->flags))
			wait_iff_congested(BLK_RW_ASYNC, HZ/10);

	} while (should_continue_reclaim(pgdat, sc->nr_reclaimed - nr_reclaimed,
					 sc));
	/*
	 * Kswapd gives up on balancing particular nodes after too
	 * many failures to reclaim anything from them and goes to
	 * sleep. On reclaim progress, reset the failure counter. A
	 * successful direct reclaim run will revive a dormant kswapd.
	 */
	if (reclaimable)
		pgdat->kswapd_failures = 0;

	return reclaimable;
}
