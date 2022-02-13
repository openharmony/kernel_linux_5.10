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
#else
static inline int alloc_related_thread_groups(void) { return 0; }
#endif /* CONFIG_SCHED_RTG */
#endif
