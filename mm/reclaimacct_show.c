// SPDX-License-Identifier: GPL-2.0
/*
 * mm/reclaimacct_show.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 */

#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/time64.h>

#include "internal.h"

/* Store reclaim accounting data */
static struct reclaimacct_show {
	u64 delay[NR_DELAY_LV][NR_RA_STUBS];
	u64 count[NR_DELAY_LV][NR_RA_STUBS];
	u64 max_delay;
	u64 max_delay_time;
} *ra_show;
static DEFINE_SPINLOCK(ra_show_lock);

static struct reclaim_efficiency {
	u64 time[NR_RA_STUBS];
	u64 freed[NR_RA_STUBS];
} *ra_eff;
static DEFINE_SPINLOCK(ra_eff_lock);

bool reclaimacct_initialize_show_data(void)
{
	ra_show = kzalloc(sizeof(struct reclaimacct_show), GFP_KERNEL);
	if (!ra_show)
		goto fail_show;

	ra_eff = kzalloc(sizeof(struct reclaim_efficiency) * RECLAIM_TYPES, GFP_KERNEL);
	if (!ra_eff)
		goto fail_eff;
	return true;

fail_eff:
	kfree(ra_show);
	ra_show = NULL;

fail_show:
	return false;
}

void reclaimacct_reinitialize_show_data(void)
{
	if (ra_show)
		memset(ra_show, 0, sizeof(struct reclaimacct_show));

	if (ra_eff)
		memset(ra_eff, 0, sizeof(struct reclaim_efficiency) * RECLAIM_TYPES);
}

void reclaimacct_destroy_show_data(void)
{
	kfree(ra_show);
	ra_show = NULL;

	kfree(ra_eff);
	ra_eff = NULL;
}

static void __reclaimacct_collect_data(int level, struct reclaim_acct *ra)
{
	int i;

	spin_lock(&ra_show_lock);
	for (i = 0; i < NR_RA_STUBS; i++) {
		ra_show->delay[level][i] += ra->delay[i];
		ra_show->count[level][i] += ra->count[i];
	}

	if (ra->delay[RA_RECLAIM] > ra_show->max_delay) {
		ra_show->max_delay = ra->delay[RA_RECLAIM];
		ra_show->max_delay_time = sched_clock();
	}
	spin_unlock(&ra_show_lock);
}

void reclaimacct_collect_data(void)
{
	int i;
	const u64 delay[NR_DELAY_LV] = {
		DELAY_LV0, DELAY_LV1, DELAY_LV2, DELAY_LV3, DELAY_LV4, DELAY_LV5
	};

	if (!ra_show || !current->reclaim_acct)
		return;

	for (i = 0; i < NR_DELAY_LV; i++) {
		if (current->reclaim_acct->delay[RA_RECLAIM] < delay[i]) {
			__reclaimacct_collect_data(i, current->reclaim_acct);
			break;
		}
	}
}

static int reclaimacct_proc_show(struct seq_file *m, void *v)
{
	int i, j;
	struct reclaimacct_show show;
	const char *stub_name[NR_RA_STUBS] = {
		"direct_reclaim",
		"drain_all_pages",
		"shrink_file_list",
		"shrink_anon_list",
		"shrink_slab",
	};

	if (!ra_show)
		return 0;

	spin_lock(&ra_show_lock);
	memcpy(&show, ra_show, sizeof(struct reclaimacct_show));
	spin_unlock(&ra_show_lock);

	seq_puts(m, "watch_point(unit:ms/-)\t\t0-5ms\t\t5-10ms\t\t");
	seq_puts(m, "10-50ms\t\t50-100ms\t100-2000ms\t2000-50000ms\n");
	for (i = 0; i < NR_RA_STUBS; i++) {
		seq_printf(m, "%s_delay\t\t", stub_name[i]);
		for (j = 0; j < NR_DELAY_LV; j++)
			seq_printf(m, "%-15llu ", div_u64(show.delay[j][i], NSEC_PER_MSEC));
		seq_puts(m, "\n");

		seq_printf(m, "%s_count\t\t", stub_name[i]);
		for (j = 0; j < NR_DELAY_LV; j++)
			seq_printf(m, "%-15llu ", show.count[j][i]);
		seq_puts(m, "\n");
	}
	seq_printf(m, "Max delay: %llu\tHappened: %llu\n", show.max_delay, show.max_delay_time);

	return 0;
}

static int reclaimacct_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, reclaimacct_proc_show, NULL);
}

static const struct proc_ops reclaimacct_proc_fops = {
	.proc_open = reclaimacct_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static void __reclaimacct_collect_reclaim_efficiency(
	struct reclaim_acct *ra, enum reclaim_type type)
{
	int i;

	ra->freed[RA_RECLAIM] = ra->freed[RA_SHRINKFILE] + ra->freed[RA_SHRINKANON];

	/* system_reclaim(kswapd/zswapd) is single thread, do not need lock */
	if (!is_system_reclaim(type))
		spin_lock(&ra_eff_lock);

	for (i = 0; i < NR_RA_STUBS; i++) {
		ra_eff[type].time[i] += ra->delay[i];
		ra_eff[type].freed[i] += ra->freed[i];
	}

	if (!is_system_reclaim(type))
		spin_unlock(&ra_eff_lock);
}

void reclaimacct_collect_reclaim_efficiency(void)
{
	if (!ra_eff || !current->reclaim_acct)
		return;

	__reclaimacct_collect_reclaim_efficiency(current->reclaim_acct,
		current->reclaim_acct->reclaim_type);
}

static int reclaim_efficiency_proc_show(struct seq_file *m, void *v)
{
	int i, j;
	struct reclaim_efficiency eff[RECLAIM_TYPES];
	const char *stage[NR_RA_STUBS] = {
		"total_process",
		"drain_pages  ",
		"shrink_file  ",
		"shrink_anon  ",
		"shrink_slab  "
	};
	const char *type[RECLAIM_TYPES] = {
		"direct reclaim",
		"kswapd        ",
		"zswapd        "
	};

	if (!ra_eff)
		return 0;

	spin_lock(&ra_eff_lock);
	memcpy(&eff, ra_eff, sizeof(eff));
	spin_unlock(&ra_eff_lock);

	for (i = 0; i < RECLAIM_TYPES; i++) {
		seq_printf(m, "%s time(ms)        freed(page/obj)\n", type[i]);
		for (j = 0; j < NR_RA_STUBS; j++)
			seq_printf(m, "%s  %-15llu %-15llu\n", stage[j],
				div_u64(eff[i].time[j], NSEC_PER_MSEC),
				eff[i].freed[j]);
	}

	return 0;
}

static int reclaim_efficiency_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, reclaim_efficiency_proc_show, NULL);
}

static const struct proc_ops reclaim_effi_proc_fops = {
	.proc_open = reclaim_efficiency_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init proc_reclaimacct_init(void)
{
	proc_create("reclaimacct", 0440, NULL, &reclaimacct_proc_fops);
	proc_create("reclaim_efficiency", 0440, NULL, &reclaim_effi_proc_fops);
	return 0;
}
fs_initcall(proc_reclaimacct_init);
