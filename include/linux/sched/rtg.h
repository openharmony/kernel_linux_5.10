/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SCHED_RTG_H
#define __SCHED_RTG_H

#ifdef CONFIG_SCHED_RTG
struct related_thread_group {
	int id;
	raw_spinlock_t lock;
	struct list_head tasks;
	struct list_head list;

	unsigned int nr_running;
};
#endif /* CONFIG_SCHED_RTG */
#endif
