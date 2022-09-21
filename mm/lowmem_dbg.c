// SPDX-License-Identifier: GPL-2.0
/*
 * mm/lowmem_dbg.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */
#define pr_fmt(fmt) "lowmem:" fmt

#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/freezer.h>
#include <linux/lowmem_dbg.h>

#define LMK_PRT_TSK_RSS 0
#define LMK_INTERVAL 15

/* SERVICE_ADJ(5) * OOM_SCORE_ADJ_MAX / -OOM_DISABLE */
#define LMK_SERVICE_ADJ 1000
/* defiine TASK STATE String */
#define TASK_STATE_TO_CHAR_STR "RSDTtXZxKWPNn"

static unsigned long long last_jiffs;
static const char state_to_char[] = TASK_STATE_TO_CHAR_STR;
static void lowmem_dump(struct work_struct *work);

static DEFINE_MUTEX(lowmem_dump_mutex);
static DECLARE_WORK(lowmem_dbg_verbose_wk, lowmem_dump);

static int task_state_char(unsigned long state)
{
	int bit = state ? __ffs(state) + 1 : 0;

	return bit < sizeof(state_to_char) - 1 ? state_to_char[bit] : '?';
}

static void tasks_dump(bool verbose)
{
	struct task_struct *p = NULL;
	struct task_struct *task = NULL;
	short tsk_oom_adj = 0;
	unsigned long tsk_nr_ptes = 0;
	char frozen_mark = ' ';

	pr_info("[ pid ]    uid  tgid total_vm    rss nptes  swap   adj s name\n");

	rcu_read_lock();
	for_each_process(p) {
		task = find_lock_task_mm(p);
		if (!task) {
			/*
			 * This is a kthread or all of p's threads have already
			 * detached their mm's. There's no need to report
			 * them; they can't be oom killed anyway.
			 */
			continue;
		}

		tsk_oom_adj = task->signal->oom_score_adj;
		if (!verbose && tsk_oom_adj &&
		    (tsk_oom_adj <= LMK_SERVICE_ADJ) &&
		    (get_mm_rss(task->mm) < LMK_PRT_TSK_RSS)) {
			task_unlock(task);
			continue;
		}

		tsk_nr_ptes = mm_pgtables_bytes(task->mm);

		frozen_mark = frozen(task) ? '*' : ' ';

		pr_info("[%5d] %5d %5d %8lu %6lu %5lu %5lu %5hd %c %s%c\n",
		    task->pid, from_kuid(&init_user_ns, task_uid(task)),
		    task->tgid, task->mm->total_vm, get_mm_rss(task->mm),
		    tsk_nr_ptes,
		    get_mm_counter(task->mm, MM_SWAPENTS),
		    tsk_oom_adj,
		    task_state_char(task->state),
		    task->comm,
		    frozen_mark); /*lint !e1058*/
		task_unlock(task);
	}
	rcu_read_unlock();
}

static void lowmem_dump(struct work_struct *work)
{
	bool verbose = (work == &lowmem_dbg_verbose_wk) ? true : false;

	mutex_lock(&lowmem_dump_mutex);
#if defined(SHOW_MEM_FILTER_PAGE_COUNT)
	show_mem(SHOW_MEM_FILTER_NODES |
	    (verbose ? 0 : SHOW_MEM_FILTER_PAGE_COUNT), NULL);
#else
	show_mem(SHOW_MEM_FILTER_NODES, NULL);
#endif
	tasks_dump(verbose);
	mutex_unlock(&lowmem_dump_mutex);
}

void lowmem_dbg(short oom_score_adj)
{
	unsigned long long jiffs = get_jiffies_64();

	if (oom_score_adj == 0) {
		schedule_work(&lowmem_dbg_verbose_wk);
	} else if (time_after64(jiffs, (last_jiffs + LMK_INTERVAL * HZ))) {
		last_jiffs = get_jiffies_64();
		schedule_work(&lowmem_dbg_verbose_wk);
	}
}

