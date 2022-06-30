// SPDX-License-Identifier: GPL-2.0
/*
 * mm/reclaim_acct.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 */

#include <linux/slab.h>
#include <linux/types.h>

#include "internal.h"


const char *stub_name[NR_RA_STUBS] = {
	"direct_reclaim",
	"drain_all_pages",
	"shrink_file_list",
	"shrink_anon_list",
	"shrink_slab",
};

/* Once initialized, the variable should never be changed */
static bool reclaimacct_is_off = true;
static int reclaimacct_disable = 1;

static void reclaimacct_free(struct reclaim_acct *ra, enum reclaim_type type)
{
	memset(ra, 0, sizeof(struct reclaim_acct));
}

static void __reclaimacct_end(struct reclaim_acct *ra, u64 freed,
	enum reclaimacct_stubs stub, const struct shrinker *shrinker)
{
	u64 now, delay, start;

	start = ra->start[stub];
	now = ktime_get_ns();
	if (now < start)
		return;

	delay = now - start;
	if (delay < DELAY_LV5 || is_system_reclaim(ra->reclaim_type)) {
		ra->delay[stub] += delay;
		ra->count[stub]++;
		ra->freed[stub] += freed;
	}

	if (delay > DELAY_LV4 && delay < DELAY_LV5) {
		pr_warn_ratelimited("%s timeout:%llu\n", stub_name[stub], delay);
		if (shrinker)
			pr_warn_ratelimited("shrinker = %pF\n", shrinker);
	}
}

void reclaimacct_tsk_init(struct task_struct *tsk)
{
	if (tsk)
		tsk->reclaim_acct = NULL;
}

/* Reinitialize in case parent's non-null pointer was duped */
void reclaimacct_init(void)
{
	reclaimacct_tsk_init(&init_task);
}

void reclaimacct_substage_start(enum reclaimacct_stubs stub)
{
	if (!current->reclaim_acct)
		return;

	current->reclaim_acct->start[stub] = ktime_get_ns();
}

void reclaimacct_substage_end(enum reclaimacct_stubs stub, unsigned long freed,
	const struct shrinker *shrinker)
{
	if (!current->reclaim_acct)
		return;

	__reclaimacct_end(current->reclaim_acct, freed, stub, shrinker);
}

static void reclaimacct_directreclaim_end(struct reclaim_acct *ra)
{
	int i;

	if (ra->delay[RA_RECLAIM] > DELAY_LV4) {
		pr_warn_ratelimited("Summary");
		for (i = 0; i < NR_RA_STUBS; i++)
			pr_warn_ratelimited(" %s=%llu %llu", stub_name[i],
				ra->delay[i], ra->count[i]);
		pr_warn_ratelimited("\n");
	}

	reclaimacct_collect_data();
	reclaimacct_free(ra, ra->reclaim_type);
}

static void reclaimacct_system_reclaim_end(struct reclaim_acct *ra)
{
	reclaimacct_free(ra, ra->reclaim_type);
}

void reclaimacct_start(enum reclaim_type type, struct reclaim_acct *ra)
{
	if (reclaimacct_disable || reclaimacct_is_off)
		return;

	if (!current->reclaim_acct)
		current->reclaim_acct = ra;

	current->reclaim_acct->reclaim_type = type;
	current->reclaim_acct->start[RA_RECLAIM] = ktime_get_ns();
}

void reclaimacct_end(enum reclaim_type type)
{
	if (!current->reclaim_acct)
		return;

	__reclaimacct_end(current->reclaim_acct, 0, RA_RECLAIM, NULL);

	reclaimacct_collect_reclaim_efficiency();

	if (is_system_reclaim(type))
		reclaimacct_system_reclaim_end(current->reclaim_acct);
	else
		reclaimacct_directreclaim_end(current->reclaim_acct);

	current->reclaim_acct = NULL;
}

/* Reclaim accounting module initialize */
static int reclaimacct_init_handle(void *p)
{
	if (!reclaimacct_initialize_show_data())
		goto alloc_show_failed;

	reclaimacct_is_off = false;
	pr_info("enabled\n");
	return 0;

alloc_show_failed:
	reclaimacct_is_off = true;
	pr_err("disabled\n");
	return 0;
}

static int __init reclaimacct_module_init(void)
{
	struct task_struct *task = NULL;

	task = kthread_run(reclaimacct_init_handle, NULL, "reclaimacct_init");
	if (IS_ERR(task))
		pr_err("run reclaimacct_init failed\n");
	else
		pr_info("run reclaimacct_init successfully\n");
	return 0;
}

late_initcall(reclaimacct_module_init);

static int reclaimacct_disable_set(const char *val, const struct kernel_param *kp)
{
	int ret;

	ret = param_set_int(val, kp);
	if (ret)
		return ret;

	if (!reclaimacct_disable)
		reclaimacct_reinitialize_show_data();
	return 0;
}

static const struct kernel_param_ops reclaimacct_disable_ops = {
	.set = reclaimacct_disable_set,
	.get = param_get_int,
};

module_param_cb(disable, &reclaimacct_disable_ops, &reclaimacct_disable, 0644);
