/* SPDX-License-Identifier: GPL-2.0 */
/*
 * related thread group sched header
 */
#ifndef __RTG_H
#define __RTG_H

#include <linux/types.h>
#include <linux/sched.h>

#define for_each_sched_cluster_reverse(cluster) \
	list_for_each_entry_reverse(cluster, &cluster_head, list)

#ifdef CONFIG_SCHED_RTG
void init_task_rtg(struct task_struct *p);
int alloc_related_thread_groups(void);
struct related_thread_group *lookup_related_thread_group(unsigned int group_id);
struct related_thread_group *task_related_thread_group(struct task_struct *p);
void update_group_nr_running(struct task_struct *p, int event, u64 wallclock);
struct rq;
void update_group_demand(struct task_struct *p, struct rq *rq,
				int event, u64 wallclock);
int sched_set_group_window_size(unsigned int grp_id, unsigned int window_size);
int sched_set_group_window_rollover(unsigned int grp_id);
struct group_cpu_time *group_update_cpu_time(struct rq *rq,
	struct related_thread_group *grp);
void sched_update_rtg_tick(struct task_struct *p);
int preferred_cluster(struct sched_cluster *cluster, struct task_struct *p);
int sched_set_group_preferred_cluster(unsigned int grp_id, int sched_cluster_id);
struct cpumask *find_rtg_target(struct task_struct *p);
int find_rtg_cpu(struct task_struct *p);
int sched_set_group_util_invalid_interval(unsigned int grp_id,
					  unsigned int interval);
int sched_set_group_normalized_util(unsigned int grp_id, unsigned long util,
				    unsigned int flag);
void sched_get_max_group_util(const struct cpumask *query_cpus,
			      unsigned long *util, unsigned int *freq);
int sched_set_group_freq_update_interval(unsigned int grp_id,
					 unsigned int interval);
#ifdef CONFIG_SCHED_RTG_CGROUP
int sync_cgroup_colocation(struct task_struct *p, bool insert);
void add_new_task_to_grp(struct task_struct *new);
#else
static inline void add_new_task_to_grp(struct task_struct *new) {}
#endif /* CONFIG_SCHED_RTG_CGROUP */
#else
static inline int alloc_related_thread_groups(void) { return 0; }
static inline int sched_set_group_preferred_cluster(unsigned int grp_id,
						    int sched_cluster_id)
{
	return 0;
}
static inline int sched_set_group_normalized_util(unsigned int grp_id, unsigned long util,
				    unsigned int flag)
{
	return 0;
}
static inline void sched_get_max_group_util(const struct cpumask *query_cpus,
			      unsigned long *util, unsigned int *freq)
{
}
static inline void add_new_task_to_grp(struct task_struct *new) {}
#endif /* CONFIG_SCHED_RTG */
#endif
