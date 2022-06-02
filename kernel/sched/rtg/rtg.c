// SPDX-License-Identifier: GPL-2.0
/*
 * related thread group sched
 *
 */
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <trace/events/walt.h>
#define CREATE_TRACE_POINTS
#include <trace/events/rtg.h>
#undef CREATE_TRACE_POINTS

#include "../sched.h"
#include "rtg.h"
#include "../walt.h"

#ifdef CONFIG_SCHED_RTG_FRAME
#include "frame_rtg.h"
#endif

#define ADD_TASK	0
#define REM_TASK	1

#define DEFAULT_GROUP_RATE		60 /* 60FPS */
#define DEFAULT_UTIL_INVALID_INTERVAL	(~0U) /* ns */
#define DEFAULT_UTIL_UPDATE_TIMEOUT	20000000  /* ns */
#define DEFAULT_FREQ_UPDATE_INTERVAL	8000000  /* ns */

struct related_thread_group *related_thread_groups[MAX_NUM_CGROUP_COLOC_ID];
static DEFINE_RWLOCK(related_thread_group_lock);
static LIST_HEAD(active_related_thread_groups);

#define for_each_related_thread_group(grp) \
	list_for_each_entry(grp, &active_related_thread_groups, list)

void init_task_rtg(struct task_struct *p)
{
	rcu_assign_pointer(p->grp, NULL);
	INIT_LIST_HEAD(&p->grp_list);
}

struct related_thread_group *task_related_thread_group(struct task_struct *p)
{
	return rcu_dereference(p->grp);
}

struct related_thread_group *
lookup_related_thread_group(unsigned int group_id)
{
	return related_thread_groups[group_id];
}

int alloc_related_thread_groups(void)
{
	int i, ret;
	struct related_thread_group *grp = NULL;

	/* groupd_id = 0 is invalid as it's special id to remove group. */
	for (i = 1; i < MAX_NUM_CGROUP_COLOC_ID; i++) {
		grp = kzalloc(sizeof(*grp), GFP_NOWAIT);
		if (!grp) {
			ret = -ENOMEM;
			goto err;
		}

		grp->id = i;
		INIT_LIST_HEAD(&grp->tasks);
		INIT_LIST_HEAD(&grp->list);
		grp->window_size = NSEC_PER_SEC / DEFAULT_GROUP_RATE;
		grp->util_invalid_interval = DEFAULT_UTIL_INVALID_INTERVAL;
		grp->util_update_timeout = DEFAULT_UTIL_UPDATE_TIMEOUT;
		grp->max_boost = 0;
		grp->freq_update_interval = DEFAULT_FREQ_UPDATE_INTERVAL;
		raw_spin_lock_init(&grp->lock);

		related_thread_groups[i] = grp;
	}

	return 0;

err:
	for (i = 1; i < MAX_NUM_CGROUP_COLOC_ID; i++) {
		grp = lookup_related_thread_group(i);
		if (grp) {
			kfree(grp);
			related_thread_groups[i] = NULL;
		} else {
			break;
		}
	}

	return ret;
}

/*
 * Task's cpu usage is accounted in:
 *	rq->curr/prev_runnable_sum,  when its ->grp is NULL
 *	grp->cpu_time[cpu]->curr/prev_runnable_sum, when its ->grp is !NULL
 *
 * Transfer task's cpu usage between those counters when transitioning between
 * groups
 */
static void transfer_busy_time(struct rq *rq, struct related_thread_group *grp,
				struct task_struct *p, int event)
{
	u64 wallclock;
	struct group_cpu_time *cpu_time;
	u64 *src_curr_runnable_sum, *dst_curr_runnable_sum;
	u64 *src_prev_runnable_sum, *dst_prev_runnable_sum;
	u64 *src_nt_curr_runnable_sum, *dst_nt_curr_runnable_sum;
	u64 *src_nt_prev_runnable_sum, *dst_nt_prev_runnable_sum;
	int migrate_type;
	int cpu = cpu_of(rq);
	bool new_task;
	int i;

	wallclock = sched_ktime_clock();

	update_task_ravg(rq->curr, rq, TASK_UPDATE, wallclock, 0);
	update_task_ravg(p, rq, TASK_UPDATE, wallclock, 0);
	new_task = is_new_task(p);

	cpu_time = &rq->grp_time;
	if (event == ADD_TASK) {
		migrate_type = RQ_TO_GROUP;

		src_curr_runnable_sum = &rq->curr_runnable_sum;
		dst_curr_runnable_sum = &cpu_time->curr_runnable_sum;
		src_prev_runnable_sum = &rq->prev_runnable_sum;
		dst_prev_runnable_sum = &cpu_time->prev_runnable_sum;

		src_nt_curr_runnable_sum = &rq->nt_curr_runnable_sum;
		dst_nt_curr_runnable_sum = &cpu_time->nt_curr_runnable_sum;
		src_nt_prev_runnable_sum = &rq->nt_prev_runnable_sum;
		dst_nt_prev_runnable_sum = &cpu_time->nt_prev_runnable_sum;

		*src_curr_runnable_sum -= p->ravg.curr_window_cpu[cpu];
		*src_prev_runnable_sum -= p->ravg.prev_window_cpu[cpu];
		if (new_task) {
			*src_nt_curr_runnable_sum -=
					p->ravg.curr_window_cpu[cpu];
			*src_nt_prev_runnable_sum -=
					p->ravg.prev_window_cpu[cpu];
		}

		update_cluster_load_subtractions(p, cpu,
				rq->window_start, new_task);

	} else {
		migrate_type = GROUP_TO_RQ;

		src_curr_runnable_sum = &cpu_time->curr_runnable_sum;
		dst_curr_runnable_sum = &rq->curr_runnable_sum;
		src_prev_runnable_sum = &cpu_time->prev_runnable_sum;
		dst_prev_runnable_sum = &rq->prev_runnable_sum;

		src_nt_curr_runnable_sum = &cpu_time->nt_curr_runnable_sum;
		dst_nt_curr_runnable_sum = &rq->nt_curr_runnable_sum;
		src_nt_prev_runnable_sum = &cpu_time->nt_prev_runnable_sum;
		dst_nt_prev_runnable_sum = &rq->nt_prev_runnable_sum;

		*src_curr_runnable_sum -= p->ravg.curr_window;
		*src_prev_runnable_sum -= p->ravg.prev_window;
		if (new_task) {
			*src_nt_curr_runnable_sum -= p->ravg.curr_window;
			*src_nt_prev_runnable_sum -= p->ravg.prev_window;
		}

		/*
		 * Need to reset curr/prev windows for all CPUs, not just the
		 * ones in the same cluster. Since inter cluster migrations
		 * did not result in the appropriate book keeping, the values
		 * per CPU would be inaccurate.
		 */
		for_each_possible_cpu(i) {
			p->ravg.curr_window_cpu[i] = 0;
			p->ravg.prev_window_cpu[i] = 0;
		}
	}

	*dst_curr_runnable_sum += p->ravg.curr_window;
	*dst_prev_runnable_sum += p->ravg.prev_window;
	if (new_task) {
		*dst_nt_curr_runnable_sum += p->ravg.curr_window;
		*dst_nt_prev_runnable_sum += p->ravg.prev_window;
	}

	/*
	 * When a task enter or exits a group, it's curr and prev windows are
	 * moved to a single CPU. This behavior might be sub-optimal in the
	 * exit case, however, it saves us the overhead of handling inter
	 * cluster migration fixups while the task is part of a related group.
	 */
	p->ravg.curr_window_cpu[cpu] = p->ravg.curr_window;
	p->ravg.prev_window_cpu[cpu] = p->ravg.prev_window;

	trace_sched_migration_update_sum(p, migrate_type, rq);
}

static void _set_preferred_cluster(struct related_thread_group *grp,
				   int sched_cluster_id);
static void remove_task_from_group(struct task_struct *p)
{
	struct related_thread_group *grp = p->grp;
	struct rq *rq = NULL;
	bool empty_group = true;
	struct rq_flags flag;
	unsigned long irqflag;

	rq = __task_rq_lock(p, &flag);
	transfer_busy_time(rq, p->grp, p, REM_TASK);

	raw_spin_lock_irqsave(&grp->lock, irqflag);
	list_del_init(&p->grp_list);
	rcu_assign_pointer(p->grp, NULL);

	if (p->on_cpu)
		grp->nr_running--;

	if ((int)grp->nr_running < 0) {
		WARN_ON(1);
		grp->nr_running = 0;
	}

	if (!list_empty(&grp->tasks)) {
		empty_group = false;
	} else {
#ifdef CONFIG_UCLAMP_TASK
		grp->max_boost = 0;
#endif
		_set_preferred_cluster(grp, -1);
		grp->ravg.normalized_util = 0;
	}

	raw_spin_unlock_irqrestore(&grp->lock, irqflag);
	__task_rq_unlock(rq, &flag);

	/* Reserved groups cannot be destroyed */
	if (empty_group && grp->id != DEFAULT_CGROUP_COLOC_ID) {
		 /*
		  * We test whether grp->list is attached with list_empty()
		  * hence re-init the list after deletion.
		  */
		write_lock(&related_thread_group_lock);
		list_del_init(&grp->list);
		write_unlock(&related_thread_group_lock);
	}
}

static int
add_task_to_group(struct task_struct *p, struct related_thread_group *grp)
{
	struct rq *rq = NULL;
	struct rq_flags flag;
	unsigned long irqflag;
#ifdef CONFIG_UCLAMP_TASK
	int boost;
#endif

	/*
	 * Change p->grp under rq->lock. Will prevent races with read-side
	 * reference of p->grp in various hot-paths
	 */
	rq = __task_rq_lock(p, &flag);
	transfer_busy_time(rq, grp, p, ADD_TASK);

	raw_spin_lock_irqsave(&grp->lock, irqflag);
	list_add(&p->grp_list, &grp->tasks);
	rcu_assign_pointer(p->grp, grp);
	if (p->on_cpu) {
		grp->nr_running++;
		if (grp->nr_running == 1)
			grp->mark_start = max(grp->mark_start,
					      sched_ktime_clock());
	}

#ifdef CONFIG_UCLAMP_TASK
	boost = (int)uclamp_eff_value(p, UCLAMP_MIN);
	if (boost > grp->max_boost)
		grp->max_boost = boost;
#endif
	raw_spin_unlock_irqrestore(&grp->lock, irqflag);
	__task_rq_unlock(rq, &flag);

	return 0;
}

static int __sched_set_group_id(struct task_struct *p, unsigned int group_id)
{
	int rc = 0;
	unsigned long flags;
	struct related_thread_group *grp = NULL;
	struct related_thread_group *old_grp = NULL;

	if (group_id >= MAX_NUM_CGROUP_COLOC_ID)
		return -EINVAL;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	old_grp = p->grp;
	if ((current != p && (p->flags & PF_EXITING)) ||
	    (!old_grp && !group_id))
		goto done;

	/*
	 * If the system has CONFIG_SCHED_RTG_CGROUP, only tasks in DEFAULT group
	 * can be directly switched to other groups.
	 *
	 * In other cases, Switching from one group to another directly is not permitted.
	 */
	if (old_grp && group_id) {
#ifdef CONFIG_SCHED_RTG_CGROUP
		if (old_grp->id == DEFAULT_CGROUP_COLOC_ID) {
			remove_task_from_group(p);
		} else {
#endif
			rc = -EINVAL;
			goto done;
#ifdef CONFIG_SCHED_RTG_CGROUP
		}
#endif
	}

	if (!group_id) {
		remove_task_from_group(p);
		goto done;
	}

	grp = lookup_related_thread_group(group_id);
	write_lock(&related_thread_group_lock);
	if (list_empty(&grp->list))
		list_add(&grp->list, &active_related_thread_groups);
	write_unlock(&related_thread_group_lock);

	rc = add_task_to_group(p, grp);
done:
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return rc;
}

/* group_id == 0: remove task from rtg */
int sched_set_group_id(struct task_struct *p, unsigned int group_id)
{
	/* DEFAULT_CGROUP_COLOC_ID is a reserved id */
	if (group_id == DEFAULT_CGROUP_COLOC_ID)
		return -EINVAL;

	return __sched_set_group_id(p, group_id);
}

unsigned int sched_get_group_id(struct task_struct *p)
{
	unsigned int group_id;
	struct related_thread_group *grp = NULL;

	rcu_read_lock();
	grp = task_related_thread_group(p);
	group_id = grp ? grp->id : 0;
	rcu_read_unlock();

	return group_id;
}

void update_group_nr_running(struct task_struct *p, int event, u64 wallclock)
{
	struct related_thread_group *grp;
	bool need_update = false;

	rcu_read_lock();
	grp = task_related_thread_group(p);
	if (!grp) {
		rcu_read_unlock();
		return;
	}

	raw_spin_lock(&grp->lock);

	if (event == PICK_NEXT_TASK)
		grp->nr_running++;
	else if (event == PUT_PREV_TASK)
		grp->nr_running--;

	if ((int)grp->nr_running < 0) {
		WARN_ON(1);
		grp->nr_running = 0;
	}

	/* update preferred cluster if no update long */
	if (wallclock - grp->last_util_update_time > grp->util_update_timeout)
		need_update = true;

	raw_spin_unlock(&grp->lock);

	rcu_read_unlock();

	if (need_update && grp->rtg_class && grp->rtg_class->sched_update_rtg_tick &&
	    grp->id != DEFAULT_CGROUP_COLOC_ID)
		grp->rtg_class->sched_update_rtg_tick(grp);
}

int sched_set_group_window_size(unsigned int grp_id, unsigned int window_size)
{
	struct related_thread_group *grp = NULL;
	unsigned long flag;

	if (!window_size)
		return -EINVAL;

	grp = lookup_related_thread_group(grp_id);
	if (!grp) {
		pr_err("set window size for group %d fail\n", grp_id);
		return -ENODEV;
	}

	raw_spin_lock_irqsave(&grp->lock, flag);
	grp->window_size = window_size;
	raw_spin_unlock_irqrestore(&grp->lock, flag);

	return 0;
}

void group_time_rollover(struct group_ravg *ravg)
{
	ravg->prev_window_load = ravg->curr_window_load;
	ravg->curr_window_load = 0;
	ravg->prev_window_exec = ravg->curr_window_exec;
	ravg->curr_window_exec = 0;
}

int sched_set_group_window_rollover(unsigned int grp_id)
{
	struct related_thread_group *grp = NULL;
	u64 wallclock;
	unsigned long flag;
#ifdef CONFIG_UCLAMP_TASK
	struct task_struct *p = NULL;
	int boost;
#endif

	grp = lookup_related_thread_group(grp_id);
	if (!grp) {
		pr_err("set window start for group %d fail\n", grp_id);
		return -ENODEV;
	}

	raw_spin_lock_irqsave(&grp->lock, flag);

	wallclock = sched_ktime_clock();
	grp->prev_window_time = wallclock - grp->window_start;
	grp->window_start = wallclock;
	grp->max_boost = 0;

#ifdef CONFIG_UCLAMP_TASK
	list_for_each_entry(p, &grp->tasks, grp_list) {
		boost = (int)uclamp_eff_value(p, UCLAMP_MIN);
		if (boost > 0)
			grp->max_boost = boost;
	}
#endif

	group_time_rollover(&grp->ravg);
	raw_spin_unlock_irqrestore(&grp->lock, flag);

	return 0;
}

static void add_to_group_time(struct related_thread_group *grp, struct rq *rq, u64 wallclock)
{
	u64 delta_exec, delta_load;
	u64 mark_start = grp->mark_start;
	u64 window_start = grp->window_start;

	if (unlikely(wallclock <= mark_start))
		return;

	/* per group load tracking in RTG */
	if (likely(mark_start >= window_start)) {
		/*
		 *   ws   ms  wc
		 *   |    |   |
		 *   V    V   V
		 *   |---------------|
		 */
		delta_exec = wallclock - mark_start;
		grp->ravg.curr_window_exec += delta_exec;

		delta_load = scale_exec_time(delta_exec, rq);
		grp->ravg.curr_window_load += delta_load;
	} else {
		/*
		 *   ms   ws  wc
		 *   |    |   |
		 *   V    V   V
		 *   -----|----------
		 */
		/* prev window statistic */
		delta_exec = window_start - mark_start;
		grp->ravg.prev_window_exec += delta_exec;

		delta_load = scale_exec_time(delta_exec, rq);
		grp->ravg.prev_window_load += delta_load;

		/* curr window statistic */
		delta_exec = wallclock - window_start;
		grp->ravg.curr_window_exec += delta_exec;

		delta_load = scale_exec_time(delta_exec, rq);
		grp->ravg.curr_window_load += delta_load;
	}
}

static inline void add_to_group_demand(struct related_thread_group *grp,
				struct rq *rq, u64 wallclock)
{
	if (unlikely(wallclock <= grp->window_start))
		return;

	add_to_group_time(grp, rq, wallclock);
}

static int account_busy_for_group_demand(struct task_struct *p, int event)
{
	/*
	 *No need to bother updating task demand for exiting tasks
	 * or the idle task.
	 */
	if (exiting_task(p) || is_idle_task(p))
		return 0;

	if (event == TASK_WAKE || event == TASK_MIGRATE)
		return 0;

	return 1;
}

void update_group_demand(struct task_struct *p, struct rq *rq,
				int event, u64 wallclock)
{
	struct related_thread_group *grp;

	if (!account_busy_for_group_demand(p, event))
		return;

	rcu_read_lock();
	grp = task_related_thread_group(p);
	if (!grp) {
		rcu_read_unlock();
		return;
	}

	raw_spin_lock(&grp->lock);

	if (grp->nr_running == 1)
		grp->mark_start = max(grp->mark_start, p->ravg.mark_start);

	add_to_group_demand(grp, rq, wallclock);

	grp->mark_start = wallclock;

	raw_spin_unlock(&grp->lock);

	rcu_read_unlock();
}

void sched_update_rtg_tick(struct task_struct *p)
{
	struct related_thread_group *grp = NULL;

	rcu_read_lock();
	grp = task_related_thread_group(p);
	if (!grp || list_empty(&grp->tasks)) {
		rcu_read_unlock();
		return;
	}

	if (grp->rtg_class && grp->rtg_class->sched_update_rtg_tick)
		grp->rtg_class->sched_update_rtg_tick(grp);

	rcu_read_unlock();
}

int preferred_cluster(struct sched_cluster *cluster, struct task_struct *p)
{
	struct related_thread_group *grp = NULL;
	int rc = 1;

	rcu_read_lock();

	grp = task_related_thread_group(p);
	if (grp != NULL)
		rc = (grp->preferred_cluster == cluster);

	rcu_read_unlock();
	return rc;
}

unsigned int get_cluster_grp_running(int cluster_id)
{
	struct related_thread_group *grp = NULL;
	unsigned int total_grp_running = 0;
	unsigned long flag, rtg_flag;
	unsigned int i;

	read_lock_irqsave(&related_thread_group_lock, rtg_flag);

	/* grp_id 0 is used for exited tasks */
	for (i = 1; i < MAX_NUM_CGROUP_COLOC_ID; i++) {
		grp = lookup_related_thread_group(i);
		if (!grp)
			continue;

		raw_spin_lock_irqsave(&grp->lock, flag);
		if (grp->preferred_cluster != NULL &&
		    grp->preferred_cluster->id == cluster_id)
			total_grp_running += grp->nr_running;
		raw_spin_unlock_irqrestore(&grp->lock, flag);
	}
	read_unlock_irqrestore(&related_thread_group_lock, rtg_flag);

	return total_grp_running;
}

static void _set_preferred_cluster(struct related_thread_group *grp,
				   int sched_cluster_id)
{
	struct sched_cluster *cluster = NULL;
	struct sched_cluster *cluster_found = NULL;

	if (sched_cluster_id == -1) {
		grp->preferred_cluster = NULL;
		return;
	}

	for_each_sched_cluster_reverse(cluster) {
		if (cluster->id == sched_cluster_id) {
			cluster_found = cluster;
			break;
		}
	}

	if (cluster_found != NULL)
		grp->preferred_cluster = cluster_found;
	else
		pr_err("cannot found sched_cluster_id=%d\n", sched_cluster_id);
}

/*
 * sched_cluster_id == -1: grp will set to NULL
 */
static void set_preferred_cluster(struct related_thread_group *grp,
				  int sched_cluster_id)
{
	unsigned long flag;

	raw_spin_lock_irqsave(&grp->lock, flag);
	_set_preferred_cluster(grp, sched_cluster_id);
	raw_spin_unlock_irqrestore(&grp->lock, flag);
}

int sched_set_group_preferred_cluster(unsigned int grp_id, int sched_cluster_id)
{
	struct related_thread_group *grp = NULL;

	/* DEFAULT_CGROUP_COLOC_ID is a reserved id */
	if (grp_id == DEFAULT_CGROUP_COLOC_ID ||
	    grp_id >= MAX_NUM_CGROUP_COLOC_ID)
		return -EINVAL;

	grp = lookup_related_thread_group(grp_id);
	if (!grp) {
		pr_err("set preferred cluster for group %d fail\n", grp_id);
		return -ENODEV;
	}
	set_preferred_cluster(grp, sched_cluster_id);

	return 0;
}

struct cpumask *find_rtg_target(struct task_struct *p)
{
	struct related_thread_group *grp = NULL;
	struct sched_cluster *preferred_cluster = NULL;
	struct cpumask *rtg_target = NULL;

	rcu_read_lock();
	grp = task_related_thread_group(p);
	rcu_read_unlock();

	if (!grp)
		return NULL;

	preferred_cluster = grp->preferred_cluster;
	if (!preferred_cluster)
		return NULL;

	rtg_target = &preferred_cluster->cpus;
	if (!task_fits_max(p, cpumask_first(rtg_target)))
		return NULL;

	return rtg_target;
}

int find_rtg_cpu(struct task_struct *p)
{
	int i;
	cpumask_t search_cpus = CPU_MASK_NONE;
	int max_spare_cap_cpu = -1;
	unsigned long max_spare_cap = 0;
	int idle_backup_cpu = -1;
	struct cpumask *preferred_cpus = find_rtg_target(p);

	if (!preferred_cpus)
		return -1;

	cpumask_and(&search_cpus, p->cpus_ptr, cpu_online_mask);
#ifdef CONFIG_CPU_ISOLATION_OPT
	cpumask_andnot(&search_cpus, &search_cpus, cpu_isolated_mask);
#endif

	/* search the perferred idle cpu */
	for_each_cpu_and(i, &search_cpus, preferred_cpus) {
		if (is_reserved(i))
			continue;

		if (idle_cpu(i) || (i == task_cpu(p) && p->state == TASK_RUNNING)) {
			trace_find_rtg_cpu(p, preferred_cpus, "prefer_idle", i);
			return i;
		}
	}

	for_each_cpu(i, &search_cpus) {
		unsigned long spare_cap;

		if (sched_cpu_high_irqload(i))
			continue;

		if (is_reserved(i))
			continue;

		/* take the Active LB CPU as idle_backup_cpu */
		if (idle_cpu(i) || (i == task_cpu(p) && p->state == TASK_RUNNING)) {
			/* find the idle_backup_cpu with max capacity */
			if (idle_backup_cpu == -1 ||
				capacity_orig_of(i) > capacity_orig_of(idle_backup_cpu))
				idle_backup_cpu = i;

			continue;
		}

		spare_cap = capacity_spare_without(i, p);
		if (spare_cap > max_spare_cap) {
			max_spare_cap = spare_cap;
			max_spare_cap_cpu = i;
		}
	}

	if (idle_backup_cpu != -1) {
		trace_find_rtg_cpu(p, preferred_cpus, "idle_backup", idle_backup_cpu);
		return idle_backup_cpu;
	}

	trace_find_rtg_cpu(p, preferred_cpus, "max_spare", max_spare_cap_cpu);

	return max_spare_cap_cpu;
}

int sched_set_group_util_invalid_interval(unsigned int grp_id,
					  unsigned int interval)
{
	struct related_thread_group *grp = NULL;
	unsigned long flag;

	if (interval == 0)
		return -EINVAL;

	/* DEFAULT_CGROUP_COLOC_ID is a reserved id */
	if (grp_id == DEFAULT_CGROUP_COLOC_ID ||
	    grp_id >= MAX_NUM_CGROUP_COLOC_ID)
		return -EINVAL;

	grp = lookup_related_thread_group(grp_id);
	if (!grp) {
		pr_err("set invalid interval for group %d fail\n", grp_id);
		return -ENODEV;
	}

	raw_spin_lock_irqsave(&grp->lock, flag);
	if ((signed int)interval < 0)
		grp->util_invalid_interval = DEFAULT_UTIL_INVALID_INTERVAL;
	else
		grp->util_invalid_interval = interval * NSEC_PER_MSEC;

	raw_spin_unlock_irqrestore(&grp->lock, flag);

	return 0;
}

static inline bool
group_should_invalid_util(struct related_thread_group *grp, u64 now)
{
	if (grp->util_invalid_interval == DEFAULT_UTIL_INVALID_INTERVAL)
		return false;

	return (now - grp->last_freq_update_time >= grp->util_invalid_interval);
}

static inline bool valid_normalized_util(struct related_thread_group *grp)
{
	struct task_struct *p = NULL;
	cpumask_t rtg_cpus = CPU_MASK_NONE;
	bool valid = false;

	if (grp->nr_running != 0) {
		list_for_each_entry(p, &grp->tasks, grp_list) {
			get_task_struct(p);
			if (p->state == TASK_RUNNING)
				cpumask_set_cpu(task_cpu(p), &rtg_cpus);
			trace_sched_rtg_task_each(grp->id, grp->nr_running, p);
			put_task_struct(p);
		}

		valid = cpumask_intersects(&rtg_cpus,
					  &grp->preferred_cluster->cpus);
	}
	trace_sched_rtg_valid_normalized_util(grp->id, grp->nr_running, &rtg_cpus, valid);

	return valid;
}

void sched_get_max_group_util(const struct cpumask *query_cpus,
			      unsigned long *util, unsigned int *freq)
{
	struct related_thread_group *grp = NULL;
	unsigned long max_grp_util = 0;
	unsigned int max_grp_freq = 0;
	u64 now = ktime_get_ns();
	unsigned long rtg_flag;
	unsigned long flag;

	/*
	 *  sum the prev_runnable_sum for each rtg,
	 *  return the max rtg->load
	 */
	read_lock_irqsave(&related_thread_group_lock, rtg_flag);
	if (list_empty(&active_related_thread_groups))
		goto unlock;

	for_each_related_thread_group(grp) {
		raw_spin_lock_irqsave(&grp->lock, flag);
		if (!list_empty(&grp->tasks) &&
		    grp->preferred_cluster != NULL &&
		    cpumask_intersects(query_cpus,
				       &grp->preferred_cluster->cpus) &&
		    !group_should_invalid_util(grp, now)) {

			if (grp->ravg.normalized_util > max_grp_util)
				max_grp_util = grp->ravg.normalized_util;
		}
		raw_spin_unlock_irqrestore(&grp->lock, flag);
	}

unlock:
	read_unlock_irqrestore(&related_thread_group_lock, rtg_flag);

	*freq = max_grp_freq;
	*util = max_grp_util;
}

static struct sched_cluster *best_cluster(struct related_thread_group *grp)
{
	struct sched_cluster *cluster = NULL;
	struct sched_cluster *max_cluster = NULL;
	int cpu;
	unsigned long util = grp->ravg.normalized_util;
	unsigned long boosted_grp_util = util + grp->max_boost;
	unsigned long max_cap = 0;
	unsigned long cap = 0;

	/* find new cluster */
	for_each_sched_cluster(cluster) {
		cpu = cpumask_first(&cluster->cpus);
		cap = capacity_orig_of(cpu);
		if (cap > max_cap) {
			max_cap = cap;
			max_cluster = cluster;
		}

		if (boosted_grp_util <= cap)
			return cluster;
	}

	return max_cluster;
}

static bool group_should_update_freq(struct related_thread_group *grp,
			      int cpu, unsigned int flags, u64 now)
{
	if (!grp)
		return true;

	if (flags & RTG_FREQ_FORCE_UPDATE) {
		return true;
	} else if (flags & RTG_FREQ_NORMAL_UPDATE) {
		if (now - grp->last_freq_update_time >=
		    grp->freq_update_interval)
			return true;
	}

	return false;
}

int sched_set_group_normalized_util(unsigned int grp_id, unsigned long util,
				    unsigned int flag)
{
	struct related_thread_group *grp = NULL;
	bool need_update_prev_freq = false;
	bool need_update_next_freq = false;
	u64 now;
	unsigned long flags;
	struct sched_cluster *preferred_cluster = NULL;
	int prev_cpu;
	int next_cpu;

	grp = lookup_related_thread_group(grp_id);
	if (!grp) {
		pr_err("set normalized util for group %d fail\n", grp_id);
		return -ENODEV;
	}

	raw_spin_lock_irqsave(&grp->lock, flags);

	if (list_empty(&grp->tasks)) {
		raw_spin_unlock_irqrestore(&grp->lock, flags);
		return 0;
	}

	grp->ravg.normalized_util = util;

	preferred_cluster = best_cluster(grp);

	/* update prev_cluster force when preferred_cluster changed */
	if (!grp->preferred_cluster) {
		grp->preferred_cluster = preferred_cluster;
	} else if (grp->preferred_cluster != preferred_cluster) {
		prev_cpu = cpumask_first(&grp->preferred_cluster->cpus);
		grp->preferred_cluster = preferred_cluster;

		need_update_prev_freq = true;
	}

	if (grp->preferred_cluster != NULL)
		next_cpu = cpumask_first(&grp->preferred_cluster->cpus);
	else
		next_cpu = 0;

	now = ktime_get_ns();
	grp->last_util_update_time = now;
	need_update_next_freq =
		group_should_update_freq(grp, next_cpu, flag, now);
	if (need_update_next_freq)
		grp->last_freq_update_time = now;

	raw_spin_unlock_irqrestore(&grp->lock, flags);

	if (need_update_prev_freq)
		cpufreq_update_util(cpu_rq(prev_cpu),
				SCHED_CPUFREQ_FORCE_UPDATE | SCHED_CPUFREQ_WALT);

	if (need_update_next_freq)
		cpufreq_update_util(cpu_rq(next_cpu),
				SCHED_CPUFREQ_FORCE_UPDATE | SCHED_CPUFREQ_WALT);

	return 0;
}

int sched_set_group_freq_update_interval(unsigned int grp_id, unsigned int interval)
{
	struct related_thread_group *grp = NULL;
	unsigned long flag;

	if ((signed int)interval <= 0)
		return -EINVAL;

	/* DEFAULT_CGROUP_COLOC_ID is a reserved id */
	if (grp_id == DEFAULT_CGROUP_COLOC_ID ||
	    grp_id >= MAX_NUM_CGROUP_COLOC_ID)
		return -EINVAL;

	grp = lookup_related_thread_group(grp_id);
	if (!grp) {
		pr_err("set update interval for group %d fail\n", grp_id);
		return -ENODEV;
	}

	raw_spin_lock_irqsave(&grp->lock, flag);
	grp->freq_update_interval = interval * NSEC_PER_MSEC;
	raw_spin_unlock_irqrestore(&grp->lock, flag);

	return 0;
}

#ifdef CONFIG_SCHED_RTG_CGROUP
#ifdef CONFIG_UCLAMP_TASK_GROUP
static inline bool uclamp_task_colocated(struct task_struct *p)
{
	struct cgroup_subsys_state *css;
	struct task_group *tg;
	bool colocate;

	rcu_read_lock();
	css = task_css(p, cpu_cgrp_id);
	if (!css) {
		rcu_read_unlock();
		return false;
	}
	tg = container_of(css, struct task_group, css);
	colocate = tg->colocate;
	rcu_read_unlock();

	return colocate;
}
#else
static inline bool uclamp_task_colocated(struct task_struct *p)
{
	return false;
}
#endif /* CONFIG_UCLAMP_TASK_GROUP */

void add_new_task_to_grp(struct task_struct *new)
{
	struct related_thread_group *grp = NULL;
	unsigned long flag;

	/*
	 * If the task does not belong to colocated schedtune
	 * cgroup, nothing to do. We are checking this without
	 * lock. Even if there is a race, it will be added
	 * to the co-located cgroup via cgroup attach.
	 */
	if (!uclamp_task_colocated(new))
		return;

	grp = lookup_related_thread_group(DEFAULT_CGROUP_COLOC_ID);
	write_lock_irqsave(&related_thread_group_lock, flag);

	/*
	 * It's possible that someone already added the new task to the
	 * group. or it might have taken out from the colocated schedtune
	 * cgroup. check these conditions under lock.
	 */
	if (!uclamp_task_colocated(new) || new->grp) {
		write_unlock_irqrestore(&related_thread_group_lock, flag);
		return;
	}

	raw_spin_lock(&grp->lock);

	rcu_assign_pointer(new->grp, grp);
	list_add(&new->grp_list, &grp->tasks);

	raw_spin_unlock(&grp->lock);
	write_unlock_irqrestore(&related_thread_group_lock, flag);
}


/*
 * We create a default colocation group at boot. There is no need to
 * synchronize tasks between cgroups at creation time because the
 * correct cgroup hierarchy is not available at boot. Therefore cgroup
 * colocation is turned off by default even though the colocation group
 * itself has been allocated. Furthermore this colocation group cannot
 * be destroyted once it has been created. All of this has been as part
 * of runtime optimizations.
 *
 * The job of synchronizing tasks to the colocation group is done when
 * the colocation flag in the cgroup is turned on.
 */
static int __init create_default_coloc_group(void)
{
	struct related_thread_group *grp = NULL;
	unsigned long flags;

	grp = lookup_related_thread_group(DEFAULT_CGROUP_COLOC_ID);
	write_lock_irqsave(&related_thread_group_lock, flags);
	list_add(&grp->list, &active_related_thread_groups);
	write_unlock_irqrestore(&related_thread_group_lock, flags);

	return 0;
}
late_initcall(create_default_coloc_group);

int sync_cgroup_colocation(struct task_struct *p, bool insert)
{
	unsigned int grp_id = insert ? DEFAULT_CGROUP_COLOC_ID : 0;
	unsigned int old_grp_id;

	if (p) {
		old_grp_id = sched_get_group_id(p);
		/*
		 * If the task is already in a group which is not DEFAULT_CGROUP_COLOC_ID,
		 * we should not change the group id during switch to background.
		 */
		if ((old_grp_id != DEFAULT_CGROUP_COLOC_ID) && (grp_id == 0))
			return 0;
	}

	return __sched_set_group_id(p, grp_id);
}
#endif /* CONFIG_SCHED_RTG_CGROUP */

#ifdef CONFIG_SCHED_RTG_DEBUG
#define seq_printf_rtg(m, x...) \
do { \
	if (m) \
		seq_printf(m, x); \
	else \
		printk(x); \
} while (0)

static void print_rtg_info(struct seq_file *file,
	const struct related_thread_group *grp)
{
	seq_printf_rtg(file, "RTG_ID          : %d\n", grp->id);
	seq_printf_rtg(file, "RTG_INTERVAL    : UPDATE:%lums#INVALID:%lums\n",
		grp->freq_update_interval / NSEC_PER_MSEC,
		grp->util_invalid_interval / NSEC_PER_MSEC);
	seq_printf_rtg(file, "RTG_CLUSTER     : %d\n",
		grp->preferred_cluster ? grp->preferred_cluster->id : -1);
#ifdef CONFIG_SCHED_RTG_RT_THREAD_LIMIT
	seq_printf_rtg(file, "RTG_RT_THREAD_NUM   : %d/%d\n",
		read_rtg_rt_thread_num(), RTG_MAX_RT_THREAD_NUM);
#endif
}

static char rtg_task_state_to_char(const struct task_struct *tsk)
{
	static const char state_char[] = "RSDTtXZPI";
	unsigned int tsk_state = READ_ONCE(tsk->state);
	unsigned int state = (tsk_state | tsk->exit_state) & TASK_REPORT;

	BUILD_BUG_ON_NOT_POWER_OF_2(TASK_REPORT_MAX);
	BUILD_BUG_ON(1 + ilog2(TASK_REPORT_MAX) != sizeof(state_char) - 1);

	if (tsk_state == TASK_IDLE)
		state = TASK_REPORT_IDLE;
	return state_char[fls(state)];
}

static inline void print_rtg_task_header(struct seq_file *file,
	const char *header, int run, int nr)
{
	seq_printf_rtg(file,
		"%s   : %d/%d\n"
		"STATE		COMM	   PID	PRIO	CPU\n"
		"---------------------------------------------------------\n",
		header, run, nr);
}

static inline void print_rtg_task(struct seq_file *file,
	const struct task_struct *tsk)
{
	seq_printf_rtg(file, "%5c %15s %5d %5d %5d(%*pbl)\n",
		rtg_task_state_to_char(tsk), tsk->comm, tsk->pid,
		tsk->prio, task_cpu(tsk), cpumask_pr_args(tsk->cpus_ptr));
}

static void print_rtg_threads(struct seq_file *file,
	const struct related_thread_group *grp)
{
	struct task_struct *tsk = NULL;
	int nr_thread = 0;

	list_for_each_entry(tsk, &grp->tasks, grp_list)
		nr_thread++;

	if (!nr_thread)
		return;

	print_rtg_task_header(file, "RTG_THREADS",
		grp->nr_running, nr_thread);
	list_for_each_entry(tsk, &grp->tasks, grp_list) {
		if (unlikely(!tsk))
			continue;
		get_task_struct(tsk);
		print_rtg_task(file, tsk);
		put_task_struct(tsk);
	}
	seq_printf_rtg(file, "---------------------------------------------------------\n");
}

static int sched_rtg_debug_show(struct seq_file *file, void *param)
{
	struct related_thread_group *grp = NULL;
	unsigned long flags;
	bool have_task = false;

	for_each_related_thread_group(grp) {
		if (unlikely(!grp)) {
			seq_printf_rtg(file, "RTG none\n");
			return 0;
		}

		raw_spin_lock_irqsave(&grp->lock, flags);
		if (list_empty(&grp->tasks)) {
			raw_spin_unlock_irqrestore(&grp->lock, flags);
			continue;
		}

		if (!have_task)
			have_task = true;

		seq_printf_rtg(file, "\n\n");
		print_rtg_info(file, grp);
		print_rtg_threads(file, grp);
		raw_spin_unlock_irqrestore(&grp->lock, flags);
	}

	if (!have_task)
		seq_printf_rtg(file, "RTG tasklist empty\n");

	return 0;
}

static int sched_rtg_debug_release(struct inode *inode, struct file *file)
{
	seq_release(inode, file);
	return 0;
}

static int sched_rtg_debug_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sched_rtg_debug_show, NULL);
}

static const struct proc_ops sched_rtg_debug_fops = {
	.proc_open = sched_rtg_debug_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = sched_rtg_debug_release,
};

static int __init init_sched_rtg_debug_procfs(void)
{
	struct proc_dir_entry *pe = NULL;

	pe = proc_create("sched_rtg_debug",
		0400, NULL, &sched_rtg_debug_fops);
	if (unlikely(!pe))
		return -ENOMEM;
	return 0;
}
late_initcall(init_sched_rtg_debug_procfs);
#endif
