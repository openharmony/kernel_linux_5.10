/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SCHED_RTG_H
#define __SCHED_RTG_H

#ifdef CONFIG_SCHED_RTG

#define DEFAULT_RTG_GRP_ID	0
#define DEFAULT_CGROUP_COLOC_ID	1
#define MAX_NUM_CGROUP_COLOC_ID	21

struct related_thread_group {
	int id;
	raw_spinlock_t lock;
	struct list_head tasks;
	struct list_head list;

	unsigned int nr_running;
};

int sched_set_group_id(struct task_struct *p, unsigned int group_id);
unsigned int sched_get_group_id(struct task_struct *p);
#endif /* CONFIG_SCHED_RTG */
#endif
