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
