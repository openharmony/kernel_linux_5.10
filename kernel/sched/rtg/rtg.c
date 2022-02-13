// SPDX-License-Identifier: GPL-2.0
/*
 * related thread group sched
 *
 */
#include <linux/sched.h>

#include "../sched.h"
#include "rtg.h"

struct related_thread_group *related_thread_groups[MAX_NUM_CGROUP_COLOC_ID];
static DEFINE_RWLOCK(related_thread_group_lock);
static LIST_HEAD(active_related_thread_groups);

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

static void remove_task_from_group(struct task_struct *p)
{
	struct related_thread_group *grp = p->grp;
	struct rq *rq = NULL;
	bool empty_group = true;
	struct rq_flags flag;
	unsigned long irqflag;

	rq = __task_rq_lock(p, &flag);

	raw_spin_lock_irqsave(&grp->lock, irqflag);
	list_del_init(&p->grp_list);
	rcu_assign_pointer(p->grp, NULL);

	if (p->on_cpu)
		grp->nr_running--;

	if ((int)grp->nr_running < 0) {
		WARN_ON(1);
		grp->nr_running = 0;
	}

	if (!list_empty(&grp->tasks))
		empty_group = false;

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

	/*
	 * Change p->grp under rq->lock. Will prevent races with read-side
	 * reference of p->grp in various hot-paths
	 */
	rq = __task_rq_lock(p, &flag);

	raw_spin_lock_irqsave(&grp->lock, irqflag);
	list_add(&p->grp_list, &grp->tasks);
	rcu_assign_pointer(p->grp, grp);
	if (p->on_cpu)
		grp->nr_running++;

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
		pr_err("%s[%d] switching group from %d to %d failed.\n",
		       p->comm, p->pid, old_grp->id, group_id);
		rc = -EINVAL;
		goto done;
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

void update_group_nr_running(struct task_struct *p, int event)
{
	struct related_thread_group *grp;

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

	raw_spin_unlock(&grp->lock);

	rcu_read_unlock();
}
