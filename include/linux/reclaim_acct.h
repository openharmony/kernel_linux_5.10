/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/reclaim_acct.h
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 */

#ifndef _RECLAIM_ACCT_H
#define _RECLAIM_ACCT_H

#include <linux/sched.h>
#include <linux/shrinker.h>

/* RA is the abbreviation of reclaim accouting */
enum reclaimacct_stubs {
	RA_RECLAIM = 0,
	RA_DRAINALLPAGES,
	RA_SHRINKFILE,
	RA_SHRINKANON,
	RA_SHRINKSLAB,
	NR_RA_STUBS
};

enum reclaim_type {
	DIRECT_RECLAIMS = 0,
	KSWAPD_RECLAIM,
	ZSWAPD_RECLAIM,
	RECLAIM_TYPES
};

#ifdef CONFIG_RECLAIM_ACCT
static inline bool is_system_reclaim(enum reclaim_type type)
{
	return (type == KSWAPD_RECLAIM || type == ZSWAPD_RECLAIM);
}

void reclaimacct_tsk_init(struct task_struct *tsk);
void reclaimacct_init(void);

void reclaimacct_start(enum reclaim_type type, struct reclaim_acct *ra);
void reclaimacct_end(enum reclaim_type type);

void reclaimacct_substage_start(enum reclaimacct_stubs stub);
void reclaimacct_substage_end(enum reclaimacct_stubs stub, unsigned long freed,
				const struct shrinker *shrinker);
#endif

#endif /* _RECLAIM_ACCT_H */
