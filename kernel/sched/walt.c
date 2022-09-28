// SPDX-License-Identifier: GPL-2.0
/*
 * walt.c
 *
 * Window Assistant Load Tracking
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

#include <linux/syscore_ops.h>
#include <linux/cpufreq.h>
#include <linux/list_sort.h>
#include <linux/jiffies.h>
#include <linux/sched/stat.h>
#include <trace/events/sched.h>
#include "sched.h"
#include "walt.h"
#include "core_ctl.h"
#include "rtg/rtg.h"
#define CREATE_TRACE_POINTS
#include <trace/events/walt.h>
#undef CREATE_TRACE_POINTS

const char *task_event_names[] = {"PUT_PREV_TASK", "PICK_NEXT_TASK",
				  "TASK_WAKE", "TASK_MIGRATE", "TASK_UPDATE",
				  "IRQ_UPDATE"};
const char *migrate_type_names[] = {"GROUP_TO_RQ", "RQ_TO_GROUP",
					"RQ_TO_RQ", "GROUP_TO_GROUP"};

#define SCHED_FREQ_ACCOUNT_WAIT_TIME 0
#define SCHED_ACCOUNT_WAIT_TIME 1

static ktime_t ktime_last;
static bool sched_ktime_suspended;
DEFINE_MUTEX(cluster_lock);
static atomic64_t walt_irq_work_lastq_ws;
u64 walt_load_reported_window;

static struct irq_work walt_cpufreq_irq_work;
static struct irq_work walt_migration_irq_work;

u64 sched_ktime_clock(void)
{
	if (unlikely(sched_ktime_suspended))
		return ktime_to_ns(ktime_last);
	return ktime_get_ns();
}

static void sched_resume(void)
{
	sched_ktime_suspended = false;
}

static int sched_suspend(void)
{
	ktime_last = ktime_get();
	sched_ktime_suspended = true;
	return 0;
}

static struct syscore_ops sched_syscore_ops = {
	.resume = sched_resume,
	.suspend = sched_suspend
};

static int __init sched_init_ops(void)
{
	register_syscore_ops(&sched_syscore_ops);
	return 0;
}
late_initcall(sched_init_ops);

static void acquire_rq_locks_irqsave(const cpumask_t *cpus,
				     unsigned long *flags)
{
	int cpu;
	int level = 0;

	local_irq_save(*flags);
	for_each_cpu(cpu, cpus) {
		if (level == 0)
			raw_spin_lock(&cpu_rq(cpu)->lock);
		else
			raw_spin_lock_nested(&cpu_rq(cpu)->lock, level);
		level++;
	}
}

static void release_rq_locks_irqrestore(const cpumask_t *cpus,
					unsigned long *flags)
{
	int cpu;

	for_each_cpu(cpu, cpus)
		raw_spin_unlock(&cpu_rq(cpu)->lock);
	local_irq_restore(*flags);
}

#ifdef CONFIG_HZ_300
/*
 * Tick interval becomes to 3333333 due to
 * rounding error when HZ=300.
 */
#define MIN_SCHED_RAVG_WINDOW (3333333 * 6)
#else
/* Min window size (in ns) = 20ms */
#define MIN_SCHED_RAVG_WINDOW 20000000
#endif

/* Max window size (in ns) = 1s */
#define MAX_SCHED_RAVG_WINDOW 1000000000

/* 1 -> use PELT based load stats, 0 -> use window-based load stats */
unsigned int __read_mostly walt_disabled;

__read_mostly unsigned int sysctl_sched_cpu_high_irqload = (10 * NSEC_PER_MSEC);

/*
 * sched_window_stats_policy and sched_ravg_hist_size have a 'sysctl' copy
 * associated with them. This is required for atomic update of those variables
 * when being modifed via sysctl interface.
 *
 * IMPORTANT: Initialize both copies to same value!!
 */

__read_mostly unsigned int sched_ravg_hist_size = 5;
__read_mostly unsigned int sysctl_sched_ravg_hist_size = 5;

__read_mostly unsigned int sched_window_stats_policy = WINDOW_STATS_MAX_RECENT_AVG;
__read_mostly unsigned int sysctl_sched_window_stats_policy = WINDOW_STATS_MAX_RECENT_AVG;

static __read_mostly unsigned int sched_io_is_busy = 1;

unsigned int sysctl_sched_use_walt_cpu_util = 1;
unsigned int sysctl_sched_use_walt_task_util = 1;
unsigned int sysctl_sched_walt_init_task_load_pct = 15;
__read_mostly unsigned int sysctl_sched_walt_cpu_high_irqload = (10 * NSEC_PER_MSEC);

/* Window size (in ns) */
__read_mostly unsigned int sched_ravg_window = MIN_SCHED_RAVG_WINDOW;

/*
 * A after-boot constant divisor for cpu_util_freq_walt() to apply the load
 * boost.
 */
__read_mostly unsigned int walt_cpu_util_freq_divisor;

/* Initial task load. Newly created tasks are assigned this load. */
unsigned int __read_mostly sched_init_task_load_windows;
unsigned int __read_mostly sched_init_task_load_windows_scaled;
unsigned int __read_mostly sysctl_sched_init_task_load_pct = 15;

/*
 * Maximum possible frequency across all cpus. Task demand and cpu
 * capacity (cpu_power) metrics are scaled in reference to it.
 */
unsigned int max_possible_freq = 1;

/*
 * Minimum possible max_freq across all cpus. This will be same as
 * max_possible_freq on homogeneous systems and could be different from
 * max_possible_freq on heterogenous systems. min_max_freq is used to derive
 */
unsigned int min_max_freq = 1;

unsigned int max_capacity = 1024; /* max(rq->capacity) */
unsigned int min_capacity = 1024; /* min(rq->capacity) */
unsigned int max_possible_capacity = 1024; /* max(rq->max_possible_capacity) */
unsigned int
min_max_possible_capacity = 1024; /* min(rq->max_possible_capacity) */

/* Temporarily disable window-stats activity on all cpus */
unsigned int __read_mostly sched_disable_window_stats;

/*
 * This governs what load needs to be used when reporting CPU busy time
 * to the cpufreq governor.
 */
__read_mostly unsigned int sysctl_sched_freq_reporting_policy;

static int __init set_sched_ravg_window(char *str)
{
	unsigned int window_size;

	get_option(&str, &window_size);

	if (window_size < MIN_SCHED_RAVG_WINDOW ||
			window_size > MAX_SCHED_RAVG_WINDOW) {
		WARN_ON(1);
		return -EINVAL;
	}

	sched_ravg_window = window_size;
	return 0;
}
early_param("sched_ravg_window", set_sched_ravg_window);

__read_mostly unsigned int walt_scale_demand_divisor;
#define scale_demand(d) ((d)/walt_scale_demand_divisor)

void inc_rq_walt_stats(struct rq *rq, struct task_struct *p)
{
	walt_inc_cumulative_runnable_avg(rq, p);
}

void dec_rq_walt_stats(struct rq *rq, struct task_struct *p)
{
	walt_dec_cumulative_runnable_avg(rq, p);
}

void fixup_walt_sched_stats_common(struct rq *rq, struct task_struct *p,
				   u16 updated_demand_scaled)
{
	s64 task_load_delta = (s64)updated_demand_scaled -
			      p->ravg.demand_scaled;

	fixup_cumulative_runnable_avg(&rq->walt_stats, task_load_delta);

	walt_fixup_cum_window_demand(rq, task_load_delta);
}

static u64
update_window_start(struct rq *rq, u64 wallclock, int event)
{
	s64 delta;
	int nr_windows;
	u64 old_window_start = rq->window_start;

	delta = wallclock - rq->window_start;
	BUG_ON(delta < 0);
	if (delta < sched_ravg_window)
		return old_window_start;

	nr_windows = div64_u64(delta, sched_ravg_window);
	rq->window_start += (u64)nr_windows * (u64)sched_ravg_window;

	rq->cum_window_demand_scaled =
			rq->walt_stats.cumulative_runnable_avg_scaled;

	return old_window_start;
}

void sched_account_irqtime(int cpu, struct task_struct *curr,
				 u64 delta, u64 wallclock)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags, nr_windows;
	u64 cur_jiffies_ts;

	raw_spin_lock_irqsave(&rq->lock, flags);

	/*
	 * cputime (wallclock) uses sched_clock so use the same here for
	 * consistency.
	 */
	delta += sched_clock() - wallclock;
	cur_jiffies_ts = get_jiffies_64();

	if (is_idle_task(curr))
		update_task_ravg(curr, rq, IRQ_UPDATE, sched_ktime_clock(),
				 delta);

	nr_windows = cur_jiffies_ts - rq->irqload_ts;

	if (nr_windows) {
		if (nr_windows < 10) {
			/* Decay CPU's irqload by 3/4 for each window. */
			rq->avg_irqload *= (3 * nr_windows);
			rq->avg_irqload = div64_u64(rq->avg_irqload,
						    4 * nr_windows);
		} else {
			rq->avg_irqload = 0;
		}
		rq->avg_irqload += rq->cur_irqload;
		rq->cur_irqload = 0;
	}

	rq->cur_irqload += delta;
	rq->irqload_ts = cur_jiffies_ts;
	raw_spin_unlock_irqrestore(&rq->lock, flags);
}

static int
account_busy_for_task_demand(struct rq *rq, struct task_struct *p, int event)
{
	/*
	 * No need to bother updating task demand for exiting tasks
	 * or the idle task.
	 */
	if (exiting_task(p) || is_idle_task(p))
		return 0;

	/*
	 * When a task is waking up it is completing a segment of non-busy
	 * time. Likewise, if wait time is not treated as busy time, then
	 * when a task begins to run or is migrated, it is not running and
	 * is completing a segment of non-busy time.
	 */
	if (event == TASK_WAKE || (!SCHED_ACCOUNT_WAIT_TIME &&
			(event == PICK_NEXT_TASK || event == TASK_MIGRATE)))
		return 0;

	/*
	 * The idle exit time is not accounted for the first task _picked_ up to
	 * run on the idle CPU.
	 */
	if (event == PICK_NEXT_TASK && rq->curr == rq->idle)
		return 0;

	/*
	 * TASK_UPDATE can be called on sleeping task, when its moved between
	 * related groups
	 */
	if (event == TASK_UPDATE) {
		if (rq->curr == p)
			return 1;

		return p->on_rq ? SCHED_ACCOUNT_WAIT_TIME : 0;
	}

	return 1;
}

/*
 * In this function we match the accumulated subtractions with the current
 * and previous windows we are operating with. Ignore any entries where
 * the window start in the load_subtraction struct does not match either
 * the curent or the previous window. This could happen whenever CPUs
 * become idle or busy with interrupts disabled for an extended period.
 */
static inline void account_load_subtractions(struct rq *rq)
{
	u64 ws = rq->window_start;
	u64 prev_ws = ws - sched_ravg_window;
	struct load_subtractions *ls = rq->load_subs;
	int i;

	for (i = 0; i < NUM_TRACKED_WINDOWS; i++) {
		if (ls[i].window_start == ws) {
			rq->curr_runnable_sum -= ls[i].subs;
			rq->nt_curr_runnable_sum -= ls[i].new_subs;
		} else if (ls[i].window_start == prev_ws) {
			rq->prev_runnable_sum -= ls[i].subs;
			rq->nt_prev_runnable_sum -= ls[i].new_subs;
		}

		ls[i].subs = 0;
		ls[i].new_subs = 0;
	}

	BUG_ON((s64)rq->prev_runnable_sum < 0);
	BUG_ON((s64)rq->curr_runnable_sum < 0);
	BUG_ON((s64)rq->nt_prev_runnable_sum < 0);
	BUG_ON((s64)rq->nt_curr_runnable_sum < 0);
}

static inline void create_subtraction_entry(struct rq *rq, u64 ws, int index)
{
	rq->load_subs[index].window_start = ws;
	rq->load_subs[index].subs = 0;
	rq->load_subs[index].new_subs = 0;
}

static bool get_subtraction_index(struct rq *rq, u64 ws)
{
	int i;
	u64 oldest = ULLONG_MAX;
	int oldest_index = 0;

	for (i = 0; i < NUM_TRACKED_WINDOWS; i++) {
		u64 entry_ws = rq->load_subs[i].window_start;

		if (ws == entry_ws)
			return i;

		if (entry_ws < oldest) {
			oldest = entry_ws;
			oldest_index = i;
		}
	}

	create_subtraction_entry(rq, ws, oldest_index);
	return oldest_index;
}

static void update_rq_load_subtractions(int index, struct rq *rq,
					u32 sub_load, bool new_task)
{
	rq->load_subs[index].subs +=  sub_load;
	if (new_task)
		rq->load_subs[index].new_subs += sub_load;
}

void update_cluster_load_subtractions(struct task_struct *p,
				      int cpu, u64 ws, bool new_task)
{
	struct sched_cluster *cluster = cpu_cluster(cpu);
	struct cpumask cluster_cpus = cluster->cpus;
	u64 prev_ws = ws - sched_ravg_window;
	int i;

	cpumask_clear_cpu(cpu, &cluster_cpus);
	raw_spin_lock(&cluster->load_lock);

	for_each_cpu(i, &cluster_cpus) {
		struct rq *rq = cpu_rq(i);
		int index;

		if (p->ravg.curr_window_cpu[i]) {
			index = get_subtraction_index(rq, ws);
			update_rq_load_subtractions(index, rq,
				p->ravg.curr_window_cpu[i], new_task);
			p->ravg.curr_window_cpu[i] = 0;
		}

		if (p->ravg.prev_window_cpu[i]) {
			index = get_subtraction_index(rq, prev_ws);
			update_rq_load_subtractions(index, rq,
				p->ravg.prev_window_cpu[i], new_task);
			p->ravg.prev_window_cpu[i] = 0;
		}
	}

	raw_spin_unlock(&cluster->load_lock);
}

static inline void inter_cluster_migration_fixup
	(struct task_struct *p, int new_cpu, int task_cpu, bool new_task)
{
	struct rq *dest_rq = cpu_rq(new_cpu);
	struct rq *src_rq = cpu_rq(task_cpu);

	if (same_freq_domain(new_cpu, task_cpu))
		return;

	p->ravg.curr_window_cpu[new_cpu] = p->ravg.curr_window;
	p->ravg.prev_window_cpu[new_cpu] = p->ravg.prev_window;

	dest_rq->curr_runnable_sum += p->ravg.curr_window;
	dest_rq->prev_runnable_sum += p->ravg.prev_window;

	src_rq->curr_runnable_sum -=  p->ravg.curr_window_cpu[task_cpu];
	src_rq->prev_runnable_sum -=  p->ravg.prev_window_cpu[task_cpu];

	if (new_task) {
		dest_rq->nt_curr_runnable_sum += p->ravg.curr_window;
		dest_rq->nt_prev_runnable_sum += p->ravg.prev_window;

		src_rq->nt_curr_runnable_sum -=
				p->ravg.curr_window_cpu[task_cpu];
		src_rq->nt_prev_runnable_sum -=
				p->ravg.prev_window_cpu[task_cpu];
	}

	p->ravg.curr_window_cpu[task_cpu] = 0;
	p->ravg.prev_window_cpu[task_cpu] = 0;

	update_cluster_load_subtractions(p, task_cpu,
			src_rq->window_start, new_task);

	BUG_ON((s64)src_rq->prev_runnable_sum < 0);
	BUG_ON((s64)src_rq->curr_runnable_sum < 0);
	BUG_ON((s64)src_rq->nt_prev_runnable_sum < 0);
	BUG_ON((s64)src_rq->nt_curr_runnable_sum < 0);
}

void fixup_busy_time(struct task_struct *p, int new_cpu)
{
	struct rq *src_rq = task_rq(p);
	struct rq *dest_rq = cpu_rq(new_cpu);
	u64 wallclock;
	bool new_task;
#ifdef CONFIG_SCHED_RTG
	u64 *src_curr_runnable_sum, *dst_curr_runnable_sum;
	u64 *src_prev_runnable_sum, *dst_prev_runnable_sum;
	u64 *src_nt_curr_runnable_sum, *dst_nt_curr_runnable_sum;
	u64 *src_nt_prev_runnable_sum, *dst_nt_prev_runnable_sum;
	struct related_thread_group *grp;
#endif

	if (!p->on_rq && p->state != TASK_WAKING)
		return;

	if (exiting_task(p))
		return;

	if (p->state == TASK_WAKING)
		double_rq_lock(src_rq, dest_rq);

	if (sched_disable_window_stats)
		goto done;

	wallclock = sched_ktime_clock();

	update_task_ravg(task_rq(p)->curr, task_rq(p),
			 TASK_UPDATE,
			 wallclock, 0);
	update_task_ravg(dest_rq->curr, dest_rq,
			 TASK_UPDATE, wallclock, 0);

	update_task_ravg(p, task_rq(p), TASK_MIGRATE,
			 wallclock, 0);

	/*
	 * When a task is migrating during the wakeup, adjust
	 * the task's contribution towards cumulative window
	 * demand.
	 */
	if (p->state == TASK_WAKING && p->last_sleep_ts >=
				       src_rq->window_start) {
		walt_fixup_cum_window_demand(src_rq,
					     -(s64)p->ravg.demand_scaled);
		walt_fixup_cum_window_demand(dest_rq, p->ravg.demand_scaled);
	}

	new_task = is_new_task(p);
#ifdef CONFIG_SCHED_RTG
	/* Protected by rq_lock */
	grp = task_related_thread_group(p);

	/*
	 * For frequency aggregation, we continue to do migration fixups
	 * even for intra cluster migrations. This is because, the aggregated
	 * load has to reported on a single CPU regardless.
	 */
	if (grp) {
		struct group_cpu_time *cpu_time;

		cpu_time = &src_rq->grp_time;
		src_curr_runnable_sum = &cpu_time->curr_runnable_sum;
		src_prev_runnable_sum = &cpu_time->prev_runnable_sum;
		src_nt_curr_runnable_sum = &cpu_time->nt_curr_runnable_sum;
		src_nt_prev_runnable_sum = &cpu_time->nt_prev_runnable_sum;

		cpu_time = &dest_rq->grp_time;
		dst_curr_runnable_sum = &cpu_time->curr_runnable_sum;
		dst_prev_runnable_sum = &cpu_time->prev_runnable_sum;
		dst_nt_curr_runnable_sum = &cpu_time->nt_curr_runnable_sum;
		dst_nt_prev_runnable_sum = &cpu_time->nt_prev_runnable_sum;

		if (p->ravg.curr_window) {
			*src_curr_runnable_sum -= p->ravg.curr_window;
			*dst_curr_runnable_sum += p->ravg.curr_window;
			if (new_task) {
				*src_nt_curr_runnable_sum -=
							p->ravg.curr_window;
				*dst_nt_curr_runnable_sum +=
							p->ravg.curr_window;
			}
		}

		if (p->ravg.prev_window) {
			*src_prev_runnable_sum -= p->ravg.prev_window;
			*dst_prev_runnable_sum += p->ravg.prev_window;
			if (new_task) {
				*src_nt_prev_runnable_sum -=
							p->ravg.prev_window;
				*dst_nt_prev_runnable_sum +=
							p->ravg.prev_window;
			}
		}
	} else {
#endif
		inter_cluster_migration_fixup(p, new_cpu,
						task_cpu(p), new_task);
#ifdef CONFIG_SCHED_RTG
	}
#endif

	if (!same_freq_domain(new_cpu, task_cpu(p)))
		irq_work_queue(&walt_migration_irq_work);

done:
	if (p->state == TASK_WAKING)
		double_rq_unlock(src_rq, dest_rq);
}

void set_window_start(struct rq *rq)
{
	static int sync_cpu_available;

	if (likely(rq->window_start))
		return;

	if (!sync_cpu_available) {
		rq->window_start = 1;
		sync_cpu_available = 1;
		atomic64_set(&walt_irq_work_lastq_ws, rq->window_start);
		walt_load_reported_window =
					atomic64_read(&walt_irq_work_lastq_ws);

	} else {
		struct rq *sync_rq = cpu_rq(cpumask_any(cpu_online_mask));

		raw_spin_unlock(&rq->lock);
		double_rq_lock(rq, sync_rq);
		rq->window_start = sync_rq->window_start;
		rq->curr_runnable_sum = rq->prev_runnable_sum = 0;
		rq->nt_curr_runnable_sum = rq->nt_prev_runnable_sum = 0;
		raw_spin_unlock(&sync_rq->lock);
	}

	rq->curr->ravg.mark_start = rq->window_start;
}

/*
 * Called when new window is starting for a task, to record cpu usage over
 * recently concluded window(s). Normally 'samples' should be 1. It can be > 1
 * when, say, a real-time task runs without preemption for several windows at a
 * stretch.
 */
static void update_history(struct rq *rq, struct task_struct *p,
			   u32 runtime, int samples, int event)
{
	u32 *hist = &p->ravg.sum_history[0];
	int ridx, widx;
	u32 max = 0, avg, demand;
	u64 sum = 0;
	u16 demand_scaled;

	/* Ignore windows where task had no activity */
	if (!runtime || is_idle_task(p) || exiting_task(p) || !samples)
		goto done;

	/* Push new 'runtime' value onto stack */
	widx = sched_ravg_hist_size - 1;
	ridx = widx - samples;
	for (; ridx >= 0; --widx, --ridx) {
		hist[widx] = hist[ridx];
		sum += hist[widx];
		if (hist[widx] > max)
			max = hist[widx];
	}

	for (widx = 0; widx < samples && widx < sched_ravg_hist_size; widx++) {
		hist[widx] = runtime;
		sum += hist[widx];
		if (hist[widx] > max)
			max = hist[widx];
	}

	p->ravg.sum = 0;

	if (sched_window_stats_policy == WINDOW_STATS_RECENT) {
		demand = runtime;
	} else if (sched_window_stats_policy == WINDOW_STATS_MAX) {
		demand = max;
	} else {
		avg = div64_u64(sum, sched_ravg_hist_size);
		if (sched_window_stats_policy == WINDOW_STATS_AVG)
			demand = avg;
		else
			demand = max(avg, runtime);
	}
	demand_scaled = scale_demand(demand);

	/*
	 * A throttled deadline sched class task gets dequeued without
	 * changing p->on_rq. Since the dequeue decrements walt stats
	 * avoid decrementing it here again.
	 *
	 * When window is rolled over, the cumulative window demand
	 * is reset to the cumulative runnable average (contribution from
	 * the tasks on the runqueue). If the current task is dequeued
	 * already, it's demand is not included in the cumulative runnable
	 * average. So add the task demand separately to cumulative window
	 * demand.
	 */
	if (!task_has_dl_policy(p) || !p->dl.dl_throttled) {
		if (task_on_rq_queued(p)
				&& p->sched_class->fixup_walt_sched_stats)
			p->sched_class->fixup_walt_sched_stats(rq, p,
					demand_scaled);
		else if (rq->curr == p)
			walt_fixup_cum_window_demand(rq, demand_scaled);
	}

	p->ravg.demand = demand;
	p->ravg.demand_scaled = demand_scaled;

done:
	trace_sched_update_history(rq, p, runtime, samples, event);
}

#define DIV64_U64_ROUNDUP(X, Y) div64_u64((X) + (Y - 1), Y)

static u64 add_to_task_demand(struct rq *rq, struct task_struct *p, u64 delta)
{
	delta = scale_exec_time(delta, rq);
	p->ravg.sum += delta;
	if (unlikely(p->ravg.sum > sched_ravg_window))
		p->ravg.sum = sched_ravg_window;

	return delta;
}

/*
 * Account cpu demand of task and/or update task's cpu demand history
 *
 * ms = p->ravg.mark_start;
 * wc = wallclock
 * ws = rq->window_start
 *
 * Three possibilities:
 *
 *	a) Task event is contained within one window.
 *		window_start < mark_start < wallclock
 *
 *		ws   ms  wc
 *		|    |   |
 *		V    V   V
 *		|---------------|
 *
 *	In this case, p->ravg.sum is updated *iff* event is appropriate
 *	(ex: event == PUT_PREV_TASK)
 *
 *	b) Task event spans two windows.
 *		mark_start < window_start < wallclock
 *
 *		ms   ws   wc
 *		|    |    |
 *		V    V    V
 *		-----|-------------------
 *
 *	In this case, p->ravg.sum is updated with (ws - ms) *iff* event
 *	is appropriate, then a new window sample is recorded followed
 *	by p->ravg.sum being set to (wc - ws) *iff* event is appropriate.
 *
 *	c) Task event spans more than two windows.
 *
 *		ms ws_tmp			   ws  wc
 *		|  |				   |   |
 *		V  V				   V   V
 *		---|-------|-------|-------|-------|------
 *		   |				   |
 *		   |<------ nr_full_windows ------>|
 *
 *	In this case, p->ravg.sum is updated with (ws_tmp - ms) first *iff*
 *	event is appropriate, window sample of p->ravg.sum is recorded,
 *	'nr_full_window' samples of window_size is also recorded *iff*
 *	event is appropriate and finally p->ravg.sum is set to (wc - ws)
 *	*iff* event is appropriate.
 *
 * IMPORTANT : Leave p->ravg.mark_start unchanged, as update_cpu_busy_time()
 * depends on it!
 */
static u64 update_task_demand(struct task_struct *p, struct rq *rq,
			      int event, u64 wallclock)
{
	u64 mark_start = p->ravg.mark_start;
	u64 delta, window_start = rq->window_start;
	int new_window, nr_full_windows;
	u32 window_size = sched_ravg_window;
	u64 runtime;

#ifdef CONFIG_SCHED_RTG
	update_group_demand(p, rq, event, wallclock);
#endif

	new_window = mark_start < window_start;
	if (!account_busy_for_task_demand(rq, p, event)) {
		if (new_window)
			/*
			 * If the time accounted isn't being accounted as
			 * busy time, and a new window started, only the
			 * previous window need be closed out with the
			 * pre-existing demand. Multiple windows may have
			 * elapsed, but since empty windows are dropped,
			 * it is not necessary to account those.
			 */
			update_history(rq, p, p->ravg.sum, 1, event);
		return 0;
	}

	if (!new_window) {
		/*
		 * The simple case - busy time contained within the existing
		 * window.
		 */
		return add_to_task_demand(rq, p, wallclock - mark_start);
	}

	/*
	 * Busy time spans at least two windows. Temporarily rewind
	 * window_start to first window boundary after mark_start.
	 */
	delta = window_start - mark_start;
	nr_full_windows = div64_u64(delta, window_size);
	window_start -= (u64)nr_full_windows * (u64)window_size;

	/* Process (window_start - mark_start) first */
	runtime = add_to_task_demand(rq, p, window_start - mark_start);

	/* Push new sample(s) into task's demand history */
	update_history(rq, p, p->ravg.sum, 1, event);
	if (nr_full_windows) {
		u64 scaled_window = scale_exec_time(window_size, rq);

		update_history(rq, p, scaled_window, nr_full_windows, event);
		runtime += nr_full_windows * scaled_window;
	}

	/*
	 * Roll window_start back to current to process any remainder
	 * in current window.
	 */
	window_start += (u64)nr_full_windows * (u64)window_size;

	/* Process (wallclock - window_start) next */
	mark_start = window_start;
	runtime += add_to_task_demand(rq, p, wallclock - mark_start);

	return runtime;
}

static u32 empty_windows[NR_CPUS];

static void rollover_task_window(struct task_struct *p, bool full_window)
{
	u32 *curr_cpu_windows = empty_windows;
	u32 curr_window;
	int i;

	/* Rollover the sum */
	curr_window = 0;

	if (!full_window) {
		curr_window = p->ravg.curr_window;
		curr_cpu_windows = p->ravg.curr_window_cpu;
	}

	p->ravg.prev_window = curr_window;
	p->ravg.curr_window = 0;

	/* Roll over individual CPU contributions */
	for (i = 0; i < nr_cpu_ids; i++) {
		p->ravg.prev_window_cpu[i] = curr_cpu_windows[i];
		p->ravg.curr_window_cpu[i] = 0;
	}
}

static void rollover_cpu_window(struct rq *rq, bool full_window)
{
	u64 curr_sum = rq->curr_runnable_sum;
	u64 nt_curr_sum = rq->nt_curr_runnable_sum;

	if (unlikely(full_window)) {
		curr_sum = 0;
		nt_curr_sum = 0;
	}

	rq->prev_runnable_sum = curr_sum;
	rq->nt_prev_runnable_sum = nt_curr_sum;

	rq->curr_runnable_sum = 0;
	rq->nt_curr_runnable_sum = 0;
}

static inline int cpu_is_waiting_on_io(struct rq *rq)
{
	if (!sched_io_is_busy)
		return 0;

	return atomic_read(&rq->nr_iowait);
}

static int account_busy_for_cpu_time(struct rq *rq, struct task_struct *p,
				     u64 irqtime, int event)
{
	if (is_idle_task(p)) {
		/* TASK_WAKE && TASK_MIGRATE is not possible on idle task! */
		if (event == PICK_NEXT_TASK)
			return 0;

		/* PUT_PREV_TASK, TASK_UPDATE && IRQ_UPDATE are left */
		return irqtime || cpu_is_waiting_on_io(rq);
	}

	if (event == TASK_WAKE)
		return 0;

	if (event == PUT_PREV_TASK || event == IRQ_UPDATE)
		return 1;

	/*
	 * TASK_UPDATE can be called on sleeping task, when its moved between
	 * related groups
	 */
	if (event == TASK_UPDATE) {
		if (rq->curr == p)
			return 1;

		return p->on_rq ? SCHED_FREQ_ACCOUNT_WAIT_TIME : 0;
	}

	/* TASK_MIGRATE, PICK_NEXT_TASK left */
	return SCHED_FREQ_ACCOUNT_WAIT_TIME;
}

/*
 * Account cpu activity in its busy time counters (rq->curr/prev_runnable_sum)
 */
static void update_cpu_busy_time(struct task_struct *p, struct rq *rq,
				 int event, u64 wallclock, u64 irqtime)
{
	int new_window, full_window = 0;
	int p_is_curr_task = (p == rq->curr);
	u64 mark_start = p->ravg.mark_start;
	u64 window_start = rq->window_start;
	u32 window_size = sched_ravg_window;
	u64 delta;
	u64 *curr_runnable_sum = &rq->curr_runnable_sum;
	u64 *prev_runnable_sum = &rq->prev_runnable_sum;
	u64 *nt_curr_runnable_sum = &rq->nt_curr_runnable_sum;
	u64 *nt_prev_runnable_sum = &rq->nt_prev_runnable_sum;
	bool new_task;
	int cpu = rq->cpu;
#ifdef CONFIG_SCHED_RTG
	struct group_cpu_time *cpu_time;
	struct related_thread_group *grp;
#endif

	new_window = mark_start < window_start;
	if (new_window) {
		full_window = (window_start - mark_start) >= window_size;
		if (p->ravg.active_windows < USHRT_MAX)
			p->ravg.active_windows++;
	}

	new_task = is_new_task(p);

	/*
	 * Handle per-task window rollover. We don't care about the idle
	 * task or exiting tasks.
	 */
	if (!is_idle_task(p) && !exiting_task(p)) {
		if (new_window)
			rollover_task_window(p, full_window);
	}

	if (p_is_curr_task && new_window)
		rollover_cpu_window(rq, full_window);

	if (!account_busy_for_cpu_time(rq, p, irqtime, event))
		goto done;

#ifdef CONFIG_SCHED_RTG
	grp = task_related_thread_group(p);
	if (grp) {
		cpu_time = &rq->grp_time;

		curr_runnable_sum = &cpu_time->curr_runnable_sum;
		prev_runnable_sum = &cpu_time->prev_runnable_sum;

		nt_curr_runnable_sum = &cpu_time->nt_curr_runnable_sum;
		nt_prev_runnable_sum = &cpu_time->nt_prev_runnable_sum;
	}
#endif

	if (!new_window) {
		/*
		 * account_busy_for_cpu_time() = 1 so busy time needs
		 * to be accounted to the current window. No rollover
		 * since we didn't start a new window. An example of this is
		 * when a task starts execution and then sleeps within the
		 * same window.
		 */

		if (!irqtime || !is_idle_task(p) || cpu_is_waiting_on_io(rq))
			delta = wallclock - mark_start;
		else
			delta = irqtime;
		delta = scale_exec_time(delta, rq);
		*curr_runnable_sum += delta;
		if (new_task)
			*nt_curr_runnable_sum += delta;

		if (!is_idle_task(p) && !exiting_task(p)) {
			p->ravg.curr_window += delta;
			p->ravg.curr_window_cpu[cpu] += delta;
		}

		goto done;
	}

	if (!p_is_curr_task) {
		/*
		 * account_busy_for_cpu_time() = 1 so busy time needs
		 * to be accounted to the current window. A new window
		 * has also started, but p is not the current task, so the
		 * window is not rolled over - just split up and account
		 * as necessary into curr and prev. The window is only
		 * rolled over when a new window is processed for the current
		 * task.
		 *
		 * Irqtime can't be accounted by a task that isn't the
		 * currently running task.
		 */

		if (!full_window) {
			/*
			 * A full window hasn't elapsed, account partial
			 * contribution to previous completed window.
			 */
			delta = scale_exec_time(window_start - mark_start, rq);
			if (!exiting_task(p)) {
				p->ravg.prev_window += delta;
				p->ravg.prev_window_cpu[cpu] += delta;
			}
		} else {
			/*
			 * Since at least one full window has elapsed,
			 * the contribution to the previous window is the
			 * full window (window_size).
			 */
			delta = scale_exec_time(window_size, rq);
			if (!exiting_task(p)) {
				p->ravg.prev_window = delta;
				p->ravg.prev_window_cpu[cpu] = delta;
			}
		}

		*prev_runnable_sum += delta;
		if (new_task)
			*nt_prev_runnable_sum += delta;

		/* Account piece of busy time in the current window. */
		delta = scale_exec_time(wallclock - window_start, rq);
		*curr_runnable_sum += delta;
		if (new_task)
			*nt_curr_runnable_sum += delta;

		if (!exiting_task(p)) {
			p->ravg.curr_window = delta;
			p->ravg.curr_window_cpu[cpu] = delta;
		}

		goto done;
	}

	if (!irqtime || !is_idle_task(p) || cpu_is_waiting_on_io(rq)) {
		/*
		 * account_busy_for_cpu_time() = 1 so busy time needs
		 * to be accounted to the current window. A new window
		 * has started and p is the current task so rollover is
		 * needed. If any of these three above conditions are true
		 * then this busy time can't be accounted as irqtime.
		 *
		 * Busy time for the idle task or exiting tasks need not
		 * be accounted.
		 *
		 * An example of this would be a task that starts execution
		 * and then sleeps once a new window has begun.
		 */

		if (!full_window) {
			/*
			 * A full window hasn't elapsed, account partial
			 * contribution to previous completed window.
			 */
			delta = scale_exec_time(window_start - mark_start, rq);
			if (!is_idle_task(p) && !exiting_task(p)) {
				p->ravg.prev_window += delta;
				p->ravg.prev_window_cpu[cpu] += delta;
			}
		} else {
			/*
			 * Since at least one full window has elapsed,
			 * the contribution to the previous window is the
			 * full window (window_size).
			 */
			delta = scale_exec_time(window_size, rq);
			if (!is_idle_task(p) && !exiting_task(p)) {
				p->ravg.prev_window = delta;
				p->ravg.prev_window_cpu[cpu] = delta;
			}
		}

		/*
		 * Rollover is done here by overwriting the values in
		 * prev_runnable_sum and curr_runnable_sum.
		 */
		*prev_runnable_sum += delta;
		if (new_task)
			*nt_prev_runnable_sum += delta;

		/* Account piece of busy time in the current window. */
		delta = scale_exec_time(wallclock - window_start, rq);
		*curr_runnable_sum += delta;
		if (new_task)
			*nt_curr_runnable_sum += delta;

		if (!is_idle_task(p) && !exiting_task(p)) {
			p->ravg.curr_window = delta;
			p->ravg.curr_window_cpu[cpu] = delta;
		}

		goto done;
	}

	if (irqtime) {
		/*
		 * account_busy_for_cpu_time() = 1 so busy time needs
		 * to be accounted to the current window. A new window
		 * has started and p is the current task so rollover is
		 * needed. The current task must be the idle task because
		 * irqtime is not accounted for any other task.
		 *
		 * Irqtime will be accounted each time we process IRQ activity
		 * after a period of idleness, so we know the IRQ busy time
		 * started at wallclock - irqtime.
		 */

		BUG_ON(!is_idle_task(p));
		mark_start = wallclock - irqtime;

		/*
		 * Roll window over. If IRQ busy time was just in the current
		 * window then that is all that need be accounted.
		 */
		if (mark_start > window_start) {
			*curr_runnable_sum = scale_exec_time(irqtime, rq);
			return;
		}

		/*
		 * The IRQ busy time spanned multiple windows. Process the
		 * window then that is all that need be accounted.
		 */
		delta = window_start - mark_start;
		if (delta > window_size)
			delta = window_size;
		delta = scale_exec_time(delta, rq);
		*prev_runnable_sum += delta;

		/* Process the remaining IRQ busy time in the current window. */
		delta = wallclock - window_start;
		rq->curr_runnable_sum = scale_exec_time(delta, rq);

		return;
	}

done:
	return;
}

static inline void run_walt_irq_work(u64 old_window_start, struct rq *rq)
{
	u64 result;

	if (old_window_start == rq->window_start)
		return;

	result = atomic64_cmpxchg(&walt_irq_work_lastq_ws, old_window_start,
				   rq->window_start);
	if (result == old_window_start)
		irq_work_queue(&walt_cpufreq_irq_work);
}

/* Reflect task activity on its demand and cpu's busy time statistics */
void update_task_ravg(struct task_struct *p, struct rq *rq, int event,
						u64 wallclock, u64 irqtime)
{
	u64 old_window_start;

	if (!rq->window_start || sched_disable_window_stats ||
	    p->ravg.mark_start == wallclock)
		return;

	lockdep_assert_held(&rq->lock);

	old_window_start = update_window_start(rq, wallclock, event);

#ifdef CONFIG_SCHED_RTG
	update_group_nr_running(p, event, wallclock);
#endif
	if (!p->ravg.mark_start)
		goto done;

	update_task_demand(p, rq, event, wallclock);
	update_cpu_busy_time(p, rq, event, wallclock, irqtime);

	if (exiting_task(p))
		goto done;

	trace_sched_update_task_ravg(p, rq, event, wallclock, irqtime);
done:
	p->ravg.mark_start = wallclock;

	run_walt_irq_work(old_window_start, rq);
}

int sysctl_sched_walt_init_task_load_pct_sysctl_handler(struct ctl_table *table,
		int write, void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	sysctl_sched_init_task_load_pct = sysctl_sched_walt_init_task_load_pct;

	return 0;
}

u32 sched_get_init_task_load(struct task_struct *p)
{
	return p->init_load_pct;
}

int sched_set_init_task_load(struct task_struct *p, int init_load_pct)
{
	if (init_load_pct < 0 || init_load_pct > 100)
		return -EINVAL;

	p->init_load_pct = init_load_pct;

	return 0;
}

void init_new_task_load(struct task_struct *p)
{
	int i;
	u32 init_load_windows = sched_init_task_load_windows;
	u32 init_load_windows_scaled = sched_init_task_load_windows_scaled;
	u32 init_load_pct = current->init_load_pct;

#ifdef CONFIG_SCHED_RTG
	init_task_rtg(p);
#endif

	p->last_sleep_ts = 0;
	p->init_load_pct = 0;
	memset(&p->ravg, 0, sizeof(struct ravg));

	p->ravg.curr_window_cpu = kcalloc(nr_cpu_ids, sizeof(u32),
					  GFP_KERNEL | __GFP_NOFAIL);
	p->ravg.prev_window_cpu = kcalloc(nr_cpu_ids, sizeof(u32),
					  GFP_KERNEL | __GFP_NOFAIL);

	if (init_load_pct) {
		init_load_windows = div64_u64((u64)init_load_pct *
			  (u64)sched_ravg_window, 100);
		init_load_windows_scaled = scale_demand(init_load_windows);
	}

	p->ravg.demand = init_load_windows;
	p->ravg.demand_scaled = init_load_windows_scaled;
	for (i = 0; i < RAVG_HIST_SIZE_MAX; ++i)
		p->ravg.sum_history[i] = init_load_windows;
}

void free_task_load_ptrs(struct task_struct *p)
{
	kfree(p->ravg.curr_window_cpu);
	kfree(p->ravg.prev_window_cpu);

	/*
	 * update_task_ravg() can be called for exiting tasks. While the
	 * function itself ensures correct behavior, the corresponding
	 * trace event requires that these pointers be NULL.
	 */
	p->ravg.curr_window_cpu = NULL;
	p->ravg.prev_window_cpu = NULL;
}

void reset_task_stats(struct task_struct *p)
{
	u32 sum = 0;
	u32 *curr_window_ptr = NULL;
	u32 *prev_window_ptr = NULL;

	if (exiting_task(p)) {
		sum = EXITING_TASK_MARKER;
	} else {
		curr_window_ptr =  p->ravg.curr_window_cpu;
		prev_window_ptr = p->ravg.prev_window_cpu;
		memset(curr_window_ptr, 0, sizeof(u32) * nr_cpu_ids);
		memset(prev_window_ptr, 0, sizeof(u32) * nr_cpu_ids);
	}

	memset(&p->ravg, 0, sizeof(struct ravg));

	p->ravg.curr_window_cpu = curr_window_ptr;
	p->ravg.prev_window_cpu = prev_window_ptr;

	/* Retain EXITING_TASK marker */
	p->ravg.sum_history[0] = sum;
}

void mark_task_starting(struct task_struct *p)
{
	u64 wallclock;
	struct rq *rq = task_rq(p);

	if (!rq->window_start || sched_disable_window_stats) {
		reset_task_stats(p);
		return;
	}

	wallclock = sched_ktime_clock();
	p->ravg.mark_start = wallclock;
}

unsigned int max_possible_efficiency = 1;
unsigned int min_possible_efficiency = UINT_MAX;
unsigned int max_power_cost = 1;

static cpumask_t all_cluster_cpus = CPU_MASK_NONE;
DECLARE_BITMAP(all_cluster_ids, NR_CPUS);
struct sched_cluster *sched_cluster[NR_CPUS];
int num_clusters;

struct list_head cluster_head;

static void
insert_cluster(struct sched_cluster *cluster, struct list_head *head)
{
	struct sched_cluster *tmp;
	struct list_head *iter = head;

	list_for_each_entry(tmp, head, list) {
		if (cluster->max_power_cost < tmp->max_power_cost)
			break;
		iter = &tmp->list;
	}

	list_add(&cluster->list, iter);
}

static struct sched_cluster *alloc_new_cluster(const struct cpumask *cpus)
{
	struct sched_cluster *cluster = NULL;

	cluster = kzalloc(sizeof(struct sched_cluster), GFP_ATOMIC);
	if (!cluster) {
		pr_warn("Cluster allocation failed. Possible bad scheduling\n");
		return NULL;
	}

	INIT_LIST_HEAD(&cluster->list);
	cluster->max_power_cost		=	1;
	cluster->min_power_cost		=	1;
	cluster->capacity		=	1024;
	cluster->max_possible_capacity	=	1024;
	cluster->efficiency		=	1;
	cluster->load_scale_factor	=	1024;
	cluster->cur_freq		=	1;
	cluster->max_freq		=	1;
	cluster->min_freq		=	1;
	cluster->max_possible_freq	=	1;
	cluster->freq_init_done		=	false;

	raw_spin_lock_init(&cluster->load_lock);
	cluster->cpus = *cpus;
	cluster->efficiency = topology_get_cpu_scale(cpumask_first(cpus));

	if (cluster->efficiency > max_possible_efficiency)
		max_possible_efficiency = cluster->efficiency;
	if (cluster->efficiency < min_possible_efficiency)
		min_possible_efficiency = cluster->efficiency;

	return cluster;
}

static void add_cluster(const struct cpumask *cpus, struct list_head *head)
{
	struct sched_cluster *cluster = alloc_new_cluster(cpus);
	int i;

	if (!cluster)
		return;

	for_each_cpu(i, cpus)
		cpu_rq(i)->cluster = cluster;

	insert_cluster(cluster, head);
	set_bit(num_clusters, all_cluster_ids);
	num_clusters++;
}

static int compute_max_possible_capacity(struct sched_cluster *cluster)
{
	int capacity = 1024;

	capacity *= capacity_scale_cpu_efficiency(cluster);
	capacity >>= 10;

	capacity *= (1024 * cluster->max_possible_freq) / min_max_freq;
	capacity >>= 10;

	return capacity;
}

void walt_update_min_max_capacity(void)
{
	unsigned long flags;

	acquire_rq_locks_irqsave(cpu_possible_mask, &flags);
	__update_min_max_capacity();
	release_rq_locks_irqrestore(cpu_possible_mask, &flags);
}

static int
compare_clusters(void *priv, const struct list_head *a, const struct list_head *b)
{
	struct sched_cluster *cluster1, *cluster2;
	int ret;

	cluster1 = container_of(a, struct sched_cluster, list);
	cluster2 = container_of(b, struct sched_cluster, list);

	/*
	 * Don't assume higher capacity means higher power. If the
	 * power cost is same, sort the higher capacity cluster before
	 * the lower capacity cluster to start placing the tasks
	 * on the higher capacity cluster.
	 */
	ret = cluster1->max_power_cost > cluster2->max_power_cost ||
		(cluster1->max_power_cost == cluster2->max_power_cost &&
		cluster1->max_possible_capacity <
				cluster2->max_possible_capacity);

	return ret;
}

void sort_clusters(void)
{
	struct sched_cluster *cluster;
	struct list_head new_head;
	unsigned int tmp_max = 1;

	INIT_LIST_HEAD(&new_head);

	for_each_sched_cluster(cluster) {
		cluster->max_power_cost = power_cost(cluster_first_cpu(cluster),
							       max_task_load());
		cluster->min_power_cost = power_cost(cluster_first_cpu(cluster),
							       0);

		if (cluster->max_power_cost > tmp_max)
			tmp_max = cluster->max_power_cost;
	}
	max_power_cost = tmp_max;

	move_list(&new_head, &cluster_head, true);

	list_sort(NULL, &new_head, compare_clusters);
	assign_cluster_ids(&new_head);

	/*
	 * Ensure cluster ids are visible to all CPUs before making
	 * cluster_head visible.
	 */
	move_list(&cluster_head, &new_head, false);
}

static void update_all_clusters_stats(void)
{
	struct sched_cluster *cluster;
	u64 highest_mpc = 0, lowest_mpc = U64_MAX;
	unsigned long flags;

	acquire_rq_locks_irqsave(cpu_possible_mask, &flags);

	for_each_sched_cluster(cluster) {
		u64 mpc;

		cluster->capacity = compute_capacity(cluster);
		mpc = cluster->max_possible_capacity =
			compute_max_possible_capacity(cluster);
		cluster->load_scale_factor = compute_load_scale_factor(cluster);

		cluster->exec_scale_factor =
			DIV_ROUND_UP(cluster->efficiency * 1024,
				     max_possible_efficiency);

		if (mpc > highest_mpc)
			highest_mpc = mpc;

		if (mpc < lowest_mpc)
			lowest_mpc = mpc;
	}

	max_possible_capacity = highest_mpc;
	min_max_possible_capacity = lowest_mpc;

	__update_min_max_capacity();
	release_rq_locks_irqrestore(cpu_possible_mask, &flags);
}

void update_cluster_topology(void)
{
	struct cpumask cpus = *cpu_possible_mask;
	const struct cpumask *cluster_cpus;
	struct list_head new_head;
	int i;

	INIT_LIST_HEAD(&new_head);

	for_each_cpu(i, &cpus) {
		cluster_cpus = cpu_coregroup_mask(i);
		cpumask_or(&all_cluster_cpus, &all_cluster_cpus, cluster_cpus);
		cpumask_andnot(&cpus, &cpus, cluster_cpus);
		add_cluster(cluster_cpus, &new_head);
	}

	assign_cluster_ids(&new_head);

	/*
	 * Ensure cluster ids are visible to all CPUs before making
	 * cluster_head visible.
	 */
	move_list(&cluster_head, &new_head, false);
	update_all_clusters_stats();
}

struct sched_cluster init_cluster = {
	.list			=	LIST_HEAD_INIT(init_cluster.list),
	.id			=	0,
	.max_power_cost		=	1,
	.min_power_cost		=	1,
	.capacity		=	1024,
	.max_possible_capacity	=	1024,
	.efficiency		=	1,
	.load_scale_factor	=	1024,
	.cur_freq		=	1,
	.max_freq		=	1,
	.min_freq		=	1,
	.max_possible_freq	=	1,
	.exec_scale_factor	=	1024,
};

void init_clusters(void)
{
	bitmap_clear(all_cluster_ids, 0, NR_CPUS);
	init_cluster.cpus = *cpu_possible_mask;
	raw_spin_lock_init(&init_cluster.load_lock);
	INIT_LIST_HEAD(&cluster_head);
}

static unsigned long cpu_max_table_freq[NR_CPUS];

void update_cpu_cluster_capacity(const cpumask_t *cpus)
{
	int i;
	struct sched_cluster *cluster;
	struct cpumask cpumask;
	unsigned long flags;

	cpumask_copy(&cpumask, cpus);
	acquire_rq_locks_irqsave(cpu_possible_mask, &flags);

	for_each_cpu(i, &cpumask) {
		cluster = cpu_rq(i)->cluster;
		cpumask_andnot(&cpumask, &cpumask, &cluster->cpus);

		cluster->capacity = compute_capacity(cluster);
		cluster->load_scale_factor = compute_load_scale_factor(cluster);
	}

	__update_min_max_capacity();

	release_rq_locks_irqrestore(cpu_possible_mask, &flags);
}

static int cpufreq_notifier_policy(struct notifier_block *nb,
		unsigned long val, void *data)
{
	struct cpufreq_policy *policy = (struct cpufreq_policy *)data;
	struct sched_cluster *cluster = NULL;
	struct cpumask policy_cluster = *policy->related_cpus;
	unsigned int orig_max_freq = 0;
	int i, j, update_capacity = 0;

	if (val != CPUFREQ_CREATE_POLICY)
		return 0;

	walt_update_min_max_capacity();

	max_possible_freq = max(max_possible_freq, policy->cpuinfo.max_freq);
	if (min_max_freq == 1)
		min_max_freq = UINT_MAX;
	min_max_freq = min(min_max_freq, policy->cpuinfo.max_freq);
	BUG_ON(!min_max_freq);
	BUG_ON(!policy->max);

	for_each_cpu(i, &policy_cluster)
		cpu_max_table_freq[i] = policy->cpuinfo.max_freq;

	for_each_cpu(i, &policy_cluster) {
		cluster = cpu_rq(i)->cluster;
		cpumask_andnot(&policy_cluster, &policy_cluster,
						&cluster->cpus);

		orig_max_freq = cluster->max_freq;
		cluster->min_freq = policy->min;
		cluster->max_freq = policy->max;
		cluster->cur_freq = policy->cur;

		if (!cluster->freq_init_done) {
			mutex_lock(&cluster_lock);
			for_each_cpu(j, &cluster->cpus)
				cpumask_copy(&cpu_rq(j)->freq_domain_cpumask,
						policy->related_cpus);
			cluster->max_possible_freq = policy->cpuinfo.max_freq;
			cluster->max_possible_capacity =
				compute_max_possible_capacity(cluster);
			cluster->freq_init_done = true;

			sort_clusters();
			update_all_clusters_stats();
			mutex_unlock(&cluster_lock);
			continue;
		}

		update_capacity += (orig_max_freq != cluster->max_freq);
	}

	if (update_capacity)
		update_cpu_cluster_capacity(policy->related_cpus);

	return 0;
}

static struct notifier_block notifier_policy_block = {
	.notifier_call = cpufreq_notifier_policy
};

static int cpufreq_notifier_trans(struct notifier_block *nb,
		unsigned long val, void *data)
{
	struct cpufreq_freqs *freq = (struct cpufreq_freqs *)data;
	unsigned int cpu = freq->policy->cpu, new_freq = freq->new;
	unsigned long flags;
	struct sched_cluster *cluster;
	struct cpumask policy_cpus = cpu_rq(cpu)->freq_domain_cpumask;
	int i, j;

	if (val != CPUFREQ_POSTCHANGE)
		return NOTIFY_DONE;

	if (cpu_cur_freq(cpu) == new_freq)
		return NOTIFY_OK;

	for_each_cpu(i, &policy_cpus) {
		cluster = cpu_rq(i)->cluster;

		for_each_cpu(j, &cluster->cpus) {
			struct rq *rq = cpu_rq(j);

			raw_spin_lock_irqsave(&rq->lock, flags);
			update_task_ravg(rq->curr, rq, TASK_UPDATE,
					 sched_ktime_clock(), 0);
			raw_spin_unlock_irqrestore(&rq->lock, flags);
		}

		cluster->cur_freq = new_freq;
		cpumask_andnot(&policy_cpus, &policy_cpus, &cluster->cpus);
	}

	return NOTIFY_OK;
}

static struct notifier_block notifier_trans_block = {
	.notifier_call = cpufreq_notifier_trans
};

static int register_walt_callback(void)
{
	int ret;

	ret = cpufreq_register_notifier(&notifier_policy_block,
					CPUFREQ_POLICY_NOTIFIER);
	if (!ret)
		ret = cpufreq_register_notifier(&notifier_trans_block,
						CPUFREQ_TRANSITION_NOTIFIER);

	return ret;
}
/*
 * cpufreq callbacks can be registered at core_initcall or later time.
 * Any registration done prior to that is "forgotten" by cpufreq. See
 * initialization of variable init_cpufreq_transition_notifier_list_called
 * for further information.
 */
core_initcall(register_walt_callback);

/*
 * Runs in hard-irq context. This should ideally run just after the latest
 * window roll-over.
 */
void walt_irq_work(struct irq_work *irq_work)
{
	struct sched_cluster *cluster;
	struct rq *rq;
	int cpu;
	u64 wc;
	bool is_migration = false;
	int level = 0;

	/* Am I the window rollover work or the migration work? */
	if (irq_work == &walt_migration_irq_work)
		is_migration = true;

	for_each_cpu(cpu, cpu_possible_mask) {
		if (level == 0)
			raw_spin_lock(&cpu_rq(cpu)->lock);
		else
			raw_spin_lock_nested(&cpu_rq(cpu)->lock, level);
		level++;
	}

	wc = sched_ktime_clock();
	walt_load_reported_window = atomic64_read(&walt_irq_work_lastq_ws);
	for_each_sched_cluster(cluster) {
		raw_spin_lock(&cluster->load_lock);

		for_each_cpu(cpu, &cluster->cpus) {
			rq = cpu_rq(cpu);
			if (rq->curr) {
				update_task_ravg(rq->curr, rq,
						TASK_UPDATE, wc, 0);
				account_load_subtractions(rq);
			}
		}

		raw_spin_unlock(&cluster->load_lock);
	}

	for_each_sched_cluster(cluster) {
		cpumask_t cluster_online_cpus;
		unsigned int num_cpus, i = 1;

		cpumask_and(&cluster_online_cpus, &cluster->cpus,
						cpu_online_mask);
		num_cpus = cpumask_weight(&cluster_online_cpus);
		for_each_cpu(cpu, &cluster_online_cpus) {
			int flag = SCHED_CPUFREQ_WALT;

			rq = cpu_rq(cpu);

			if (i == num_cpus)
				cpufreq_update_util(cpu_rq(cpu), flag);
			else
				cpufreq_update_util(cpu_rq(cpu), flag |
							SCHED_CPUFREQ_CONTINUE);
			i++;
		}
	}

	for_each_cpu(cpu, cpu_possible_mask)
		raw_spin_unlock(&cpu_rq(cpu)->lock);

	if (!is_migration)
		core_ctl_check(this_rq()->window_start);
}

static void walt_init_once(void)
{
	init_irq_work(&walt_migration_irq_work, walt_irq_work);
	init_irq_work(&walt_cpufreq_irq_work, walt_irq_work);

	walt_cpu_util_freq_divisor =
	    (sched_ravg_window >> SCHED_CAPACITY_SHIFT) * 100;
	walt_scale_demand_divisor = sched_ravg_window >> SCHED_CAPACITY_SHIFT;

	sched_init_task_load_windows =
		div64_u64((u64)sysctl_sched_init_task_load_pct *
			  (u64)sched_ravg_window, 100);
	sched_init_task_load_windows_scaled =
		scale_demand(sched_init_task_load_windows);
}

void walt_sched_init_rq(struct rq *rq)
{
	static bool init;
	int j;

	if (!init) {
		walt_init_once();
		init = true;
	}

	cpumask_set_cpu(cpu_of(rq), &rq->freq_domain_cpumask);

	rq->walt_stats.cumulative_runnable_avg_scaled = 0;
	rq->window_start = 0;
	rq->walt_flags = 0;
	rq->cur_irqload = 0;
	rq->avg_irqload = 0;
	rq->irqload_ts = 0;

	/*
	 * All cpus part of same cluster by default. This avoids the
	 * need to check for rq->cluster being non-NULL in hot-paths
	 * like select_best_cpu()
	 */
	rq->cluster = &init_cluster;
	rq->curr_runnable_sum = rq->prev_runnable_sum = 0;
	rq->nt_curr_runnable_sum = rq->nt_prev_runnable_sum = 0;
	rq->cum_window_demand_scaled = 0;

	for (j = 0; j < NUM_TRACKED_WINDOWS; j++)
		memset(&rq->load_subs[j], 0, sizeof(struct load_subtractions));
}

#define min_cap_cluster() \
	list_first_entry(&cluster_head, struct sched_cluster, list)
#define max_cap_cluster() \
	list_last_entry(&cluster_head, struct sched_cluster, list)
static int sched_cluster_debug_show(struct seq_file *file, void *param)
{
	struct sched_cluster *cluster = NULL;

	seq_printf(file, "min_id:%d, max_id:%d\n",
		min_cap_cluster()->id,
		max_cap_cluster()->id);

	for_each_sched_cluster(cluster) {
		seq_printf(file, "id:%d, cpumask:%d(%*pbl)\n",
			   cluster->id,
			   cpumask_first(&cluster->cpus),
			   cpumask_pr_args(&cluster->cpus));
	}

	return 0;
}

static int sched_cluster_debug_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sched_cluster_debug_show, NULL);
}

static const struct proc_ops sched_cluster_fops = {
	.proc_open		= sched_cluster_debug_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release		= seq_release,
};

static int __init init_sched_cluster_debug_procfs(void)
{
	struct proc_dir_entry *pe = NULL;

	pe = proc_create("sched_cluster",
		0444, NULL, &sched_cluster_fops);
	if (!pe)
		return -ENOMEM;
	return 0;
}
late_initcall(init_sched_cluster_debug_procfs);
