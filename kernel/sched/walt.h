/* SPDX-License-Identifier: GPL-2.0 */
/*
 * walt.h
 *
 * head file for Window-Assistant-Load-Tracking
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __WALT_H
#define __WALT_H

#ifdef CONFIG_SCHED_WALT

#include <linux/sched/sysctl.h>

#define WINDOW_STATS_RECENT		0
#define WINDOW_STATS_MAX		1
#define WINDOW_STATS_MAX_RECENT_AVG	2
#define WINDOW_STATS_AVG		3
#define WINDOW_STATS_INVALID_POLICY	4

#define EXITING_TASK_MARKER	0xdeaddead

#define SCHED_NEW_TASK_WINDOWS 5

extern unsigned int sched_ravg_window;
extern unsigned int sysctl_sched_walt_init_task_load_pct;

static inline int exiting_task(struct task_struct *p)
{
	return (p->ravg.sum_history[0] == EXITING_TASK_MARKER);
}

static inline struct sched_cluster *cpu_cluster(int cpu)
{
	return cpu_rq(cpu)->cluster;
}

static inline int same_cluster(int src_cpu, int dst_cpu)
{
	return cpu_rq(src_cpu)->cluster == cpu_rq(dst_cpu)->cluster;
}

static inline u64 scale_exec_time(u64 delta, struct rq *rq)
{
	unsigned long capcurr = capacity_curr_of(cpu_of(rq));

	delta = (delta * capcurr) >> SCHED_CAPACITY_SHIFT;

	return delta;
}

static inline bool is_new_task(struct task_struct *p)
{
	return p->ravg.active_windows < SCHED_NEW_TASK_WINDOWS;
}

static inline unsigned int max_task_load(void)
{
	return sched_ravg_window;
}

static inline void
move_list(struct list_head *dst, struct list_head *src, bool sync_rcu)
{
	struct list_head *first, *last;

	first = src->next;
	last = src->prev;

	if (sync_rcu) {
		INIT_LIST_HEAD_RCU(src);
		synchronize_rcu();
	}

	first->prev = dst;
	dst->prev = last;
	last->next = dst;

	/* Ensure list sanity before making the head visible to all CPUs. */
	smp_mb();
	dst->next = first;
}

extern void reset_task_stats(struct task_struct *p);
extern void update_cluster_topology(void);
extern void init_clusters(void);
extern void update_task_ravg(struct task_struct *p, struct rq *rq, int event,
						u64 wallclock, u64 irqtime);

static inline void
fixup_cumulative_runnable_avg(struct walt_sched_stats *stats,
			      s64 demand_scaled_delta)
{
	if (sched_disable_window_stats)
		return;

	stats->cumulative_runnable_avg_scaled += demand_scaled_delta;
	BUG_ON((s64)stats->cumulative_runnable_avg_scaled < 0);
}

static inline void
walt_inc_cumulative_runnable_avg(struct rq *rq, struct task_struct *p)
{
	if (sched_disable_window_stats)
		return;

	fixup_cumulative_runnable_avg(&rq->walt_stats, p->ravg.demand_scaled);

	/*
	 * Add a task's contribution to the cumulative window demand when
	 *
	 * (1) task is enqueued with on_rq = 1 i.e migration,
	 *     prio/cgroup/class change.
	 * (2) task is waking for the first time in this window.
	 */
	if (p->on_rq || (p->last_sleep_ts < rq->window_start))
		walt_fixup_cum_window_demand(rq, p->ravg.demand_scaled);
}

static inline void
walt_dec_cumulative_runnable_avg(struct rq *rq, struct task_struct *p)
{
	if (sched_disable_window_stats)
		return;

	fixup_cumulative_runnable_avg(&rq->walt_stats,
				      -(s64)p->ravg.demand_scaled);

	/*
	 * on_rq will be 1 for sleeping tasks. So check if the task
	 * is migrating or dequeuing in RUNNING state to change the
	 * prio/cgroup/class.
	 */
	if (task_on_rq_migrating(p) || p->state == TASK_RUNNING)
		walt_fixup_cum_window_demand(rq, -(s64)p->ravg.demand_scaled);
}
extern void fixup_walt_sched_stats_common(struct rq *rq, struct task_struct *p,
					  u16 updated_demand_scaled);
extern void inc_rq_walt_stats(struct rq *rq, struct task_struct *p);
extern void dec_rq_walt_stats(struct rq *rq, struct task_struct *p);
extern void fixup_busy_time(struct task_struct *p, int new_cpu);
extern void init_new_task_load(struct task_struct *p);
extern void mark_task_starting(struct task_struct *p);
extern void set_window_start(struct rq *rq);
void account_irqtime(int cpu, struct task_struct *curr, u64 delta, u64 wallclock);

void walt_irq_work(struct irq_work *irq_work);

void walt_sched_init_rq(struct rq *rq);

extern void sched_account_irqtime(int cpu, struct task_struct *curr,
				  u64 delta, u64 wallclock);

#define SCHED_HIGH_IRQ_TIMEOUT 3
static inline u64 sched_irqload(int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	s64 delta;

	delta = get_jiffies_64() - rq->irqload_ts;
	/*
	 * Current context can be preempted by irq and rq->irqload_ts can be
	 * updated by irq context so that delta can be negative.
	 * But this is okay and we can safely return as this means there
	 * was recent irq occurrence.
	 */

	if (delta < SCHED_HIGH_IRQ_TIMEOUT)
		return rq->avg_irqload;
	else
		return 0;
}

static inline int sched_cpu_high_irqload(int cpu)
{
	return sched_irqload(cpu) >= sysctl_sched_cpu_high_irqload;
}

extern int
sysctl_sched_walt_init_task_load_pct_sysctl_handler(struct ctl_table *table,
	int write, void __user *buffer, size_t *length, loff_t *ppos);

static inline unsigned int cpu_cur_freq(int cpu)
{
	return cpu_rq(cpu)->cluster->cur_freq;
}

static inline void assign_cluster_ids(struct list_head *head)
{
	struct sched_cluster *cluster;
	int pos = 0;

	list_for_each_entry(cluster, head, list) {
		cluster->id = pos;
		sched_cluster[pos++] = cluster;
	}
}

extern void update_cluster_load_subtractions(struct task_struct *p,
		int cpu, u64 ws, bool new_task);
#else /* CONFIG_SCHED_WALT */
static inline void walt_sched_init_rq(struct rq *rq) { }

static inline void update_task_ravg(struct task_struct *p, struct rq *rq,
				int event, u64 wallclock, u64 irqtime) { }

static inline void walt_inc_cumulative_runnable_avg(struct rq *rq,
		struct task_struct *p) { }

static inline void walt_dec_cumulative_runnable_avg(struct rq *rq,
		struct task_struct *p) { }

static inline void
inc_rq_walt_stats(struct rq *rq, struct task_struct *p) { }

static inline void
dec_rq_walt_stats(struct rq *rq, struct task_struct *p) { }

static inline void fixup_busy_time(struct task_struct *p, int new_cpu) { }
static inline void init_new_task_load(struct task_struct *p) { }
static inline void mark_task_starting(struct task_struct *p) { }
static inline void set_window_start(struct rq *rq) { }
static inline void update_cluster_topology(void) { }
static inline void init_clusters(void) { }

static inline void
fixup_walt_sched_stats_common(struct rq *rq, struct task_struct *p,
			      u16 updated_demand_scaled) { }

static inline void sched_account_irqtime(int cpu, struct task_struct *curr,
					 u64 delta, u64 wallclock) { }

static inline u64 sched_irqload(int cpu)
{
	return 0;
}
static inline int sched_cpu_high_irqload(int cpu)
{
	return 0;
}
static inline int same_cluster(int src_cpu, int dst_cpu) { return 1; }
#endif /* CONFIG_SCHED_WALT */

#endif /* __WALT_H */
