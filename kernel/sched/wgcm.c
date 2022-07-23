// SPDX-License-Identifier: GPL-2.0-only

/* WGCM: Workergroup Control Monitor */

#include <linux/wgcm.h>
#include <linux/types.h>
#include <linux/mm.h>

#include "sched.h"

void wgcm_clear_child(struct task_struct *p)
{
	if (p->wgcm_task) {
		WRITE_ONCE(p->wgcm_task, NULL);
		p->flags &= ~PF_WGCM_WORKER;
	}
	p->wgcm_server_task = NULL;
}


static void wgcm_clear_task(struct task_struct *tsk)
{
	/*
	 * This is either called for the current task, or for a newly forked
	 * task that is not yet running, so we don't need strict atomicity
	 * below.
	 */
	if (tsk->wgcm_task) {
		kfree(tsk->wgcm_task);
		tsk->flags &= ~PF_WGCM_WORKER;
	}

	tsk->wgcm_server_task = NULL;
}

void wgcm_upd_blk_workers_sum(struct task_struct *p, bool active)
{
	struct wgcm_task *server = p->wgcm_server_task;

	if (!server) {
		pr_err("[WGCM]The WGCM worker is not bound to it's server");
		return;
	}

	if (active)
		atomic_dec(&server->blk_workers_sum);
	else
		atomic_inc(&server->blk_workers_sum);
}

static void wgcm_upd_workers_sum(struct wgcm_task *server, bool regist)
{
	if (regist)
		atomic_inc(&server->workers_sum);
	else
		atomic_dec(&server->workers_sum);
}

void wgcm_activate_task(struct task_struct *p)
{
	if (!(p->flags & PF_WGCM_WORKER) || p->on_rq)
		return;

	trace_tracing_mark_wgcm(current->tgid, "active_task", true);
	wgcm_upd_blk_workers_sum(p, true);
	trace_tracing_mark_wgcm(current->tgid, "", false);
}

void wgcm_deactivate_task(struct task_struct *p, int flags)
{
	unsigned int old_state = p->on_rq;
	unsigned int new_state = (flags & DEQUEUE_SLEEP) ? 0 : TASK_ON_RQ_MIGRATING;

	if (!(p->flags & PF_WGCM_WORKER) || !old_state || new_state)
		return;

	trace_tracing_mark_wgcm(current->tgid, "deactive_task", true);
	wgcm_upd_blk_workers_sum(p, false);
	trace_tracing_mark_wgcm(current->tgid, "", false);
}

void wgcm_do_exit(struct task_struct *tsk)
{
	struct wgcm_task *server = tsk->wgcm_server_task;
	struct wgcm_task *self = tsk->wgcm_task;

	if (!server)
		return;

	if (tsk->flags & PF_WGCM_WORKER)
		wgcm_upd_workers_sum(server, false);

	kfree(self);
}

int wgcm_get_taskinfo(struct wgcm_task __user *self)
{
	struct task_struct *tsk = current;
	int ret;

	if (tsk->flags & PF_WGCM_WORKER || !tsk->wgcm_task)
		return -EINVAL;

	ret = copy_to_user(self, tsk->wgcm_task, sizeof(*self));
	if (ret) {
		pr_err("[WGCM] wgcm_task copy to user fail, ret = %d.", ret);
		return ret;
	}

	return 0;
}

static int wgcm_register(unsigned long flags, unsigned int __user *server_tid)
{
	unsigned int tid;
	struct task_struct *server;
	struct wgcm_task *wt;
	struct task_struct *tsk = current;

	if (copy_from_user(&tid, server_tid, sizeof(tid))) {
		return -EFAULT;
	}

	if (tsk->wgcm_task || tid == 0) {
		pr_err("[WGCM][PID:%d]server_tid = %ld", current->pid, tid);
		return -EINVAL;
	}

	wt = kzalloc(sizeof(*wt), GFP_KERNEL);
	if (!wt) {
		pr_err("[WGCM_REG] alloc wgcm task fail!\n");
		return -ENOMEM;
	}

	wt->server_tid = tid;

	rcu_read_lock();
	server = find_task_by_vpid(tid);
	if (!server)
		pr_err("[WGCM][PID:%d]find server(%d) fail", tsk->pid, tid);
	if (server && server->mm == current->mm) {
		if (flags == WGCM_CTL_WORKER) {
			if (!server->wgcm_task || (server->flags & PF_WGCM_WORKER))
				server = NULL;
		} else {
			if (server != current)
				server = NULL;
		}
	} else {
		server = NULL;
	}
	rcu_read_unlock();

	if (!server) {
		kfree(wt);
		return -ESRCH;
	}

	if (flags == WGCM_CTL_WORKER) {
		WRITE_ONCE(tsk->wgcm_task, wt);
		WRITE_ONCE(tsk->wgcm_server_task, server->wgcm_task);
		wgcm_upd_workers_sum(tsk->wgcm_server_task, true);
		current->flags |= PF_WGCM_WORKER;	/* hook schedule() */
	} else {
		WRITE_ONCE(tsk->wgcm_task, wt);
	}

	return 0;
}

static int wgcm_unregister(void)
{
	if (current->wgcm_server_task)
		wgcm_upd_workers_sum(current->wgcm_server_task, false);

	wgcm_clear_task(current);
	return 0;
}

#define WGCM_CTL_CMD	0xff

/**
 * wgcm_ctl: (un)register the current task as a WGCM task.
 * @flags:       ORed values from enum umcg_ctl_flag; see below;
 * @server_tid:  server's(monitor's) thread id.
 *
 * @flags & WGCM_CTL_REGISTER: register a WGCM task:
 *
 * @flags & WGCM_CTL_UNREGISTER: unregister a WGCM task.
 *
 *	WGCM workers:
 *	 - @flags & WGCM_CTL_WORKER
 *
 *	WGCM server:
 *	 - !(@flags & WGCM_CTL_WORKER)
 *
 *	All tasks:
 *	 - server_tid must be valid(e.g. not zero).
 *
 *	If the conditions above are met, wgcm_ctl() immediately returns
 *	if the registered task is a server. If the registered task is a
 *	worker, it's server's workers_sum will be added. Conversely, if
 *	the unregisted task is a worker, it's server's workers_sum will
 *	be decreased.
 *
 * Return:
 * 0		- success
 * -EFAULT	- failed to read @self
 * -EINVAL	- some other error occurred
 * -ESRCH	- no such server_tid
 */
int wgcm_ctl(unsigned long flags, unsigned long addr)
{
	int cmd = flags & WGCM_CTL_CMD;

	flags &= ~WGCM_CTL_CMD;

	if (!addr)
		return -EINVAL;

	if (flags & ~WGCM_CTL_WORKER)
		return -EINVAL;

	switch (cmd) {
	case WGCM_CTL_REGISTER:
		return wgcm_register(flags, (unsigned int __user *)addr);

	case WGCM_CTL_UNREGISTER:
		return wgcm_unregister();

	case WGCM_CTL_GET:
		return wgcm_get_taskinfo((struct wgcm_task __user *)addr);

	default:
		break;
	}

	return -EINVAL;
}
