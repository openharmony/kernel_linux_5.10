/* SPDX-License-Identifier: GPL-2.0 */
/*
 * related thread group sched header
 */
#ifndef __RTG_H
#define __RTG_H

#include <linux/types.h>
#include <linux/sched.h>

#ifdef CONFIG_SCHED_RTG
void init_task_rtg(struct task_struct *p);
int alloc_related_thread_groups(void);
struct related_thread_group *lookup_related_thread_group(unsigned int group_id);
struct related_thread_group *task_related_thread_group(struct task_struct *p);
void update_group_nr_running(struct task_struct *p, int event);
struct rq;
void update_group_demand(struct task_struct *p, struct rq *rq,
				int event, u64 wallclock);
int sched_set_group_window_size(unsigned int grp_id, unsigned int window_size);
int sched_set_group_window_rollover(unsigned int grp_id);
struct group_cpu_time *group_update_cpu_time(struct rq *rq,
	struct related_thread_group *grp);
#else
static inline int alloc_related_thread_groups(void) { return 0; }
#endif /* CONFIG_SCHED_RTG */
#endif
