// SPDX-License-Identifier: GPL-2.0
/*
 * WGCM: Workergroup Control Monitor
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#ifndef _LINUX_WGCM_H
#define _LINUX_WGCM_H

#include <linux/sched.h>

#ifdef CONFIG_WGCM
#include <linux/types.h>
#include <uapi/linux/wgcm.h>

/*
 * struct wgcm_task: controls the state of WGCM tasks.
 */
struct wgcm_task {
	unsigned int	server_tid;

	/* count the number of workers which is bound with server */
	atomic_t	workers_sum;

	/* count the number of block workers */
	atomic_t	blk_workers_sum;
};

/*
 * use sys_prctl() (see kernel/sys.c) :
 *	wgcm_ctl():	register/unregister WGCM tasks.
 */
extern int wgcm_ctl(unsigned long flags, unsigned long server_tid);

extern void wgcm_do_exit(struct task_struct *tsk);
extern void wgcm_clear_child(struct task_struct *p);
extern void wgcm_activate_task(struct task_struct *p);
extern void wgcm_deactivate_task(struct task_struct *p, int flags);
#else
static inline int wgcm_ctl(unsigned long flags, unsigned long server_tid)
{
	return -EOPNOTSUPP;
}

static inline void wgcm_do_exit(struct task_struct *tsk)
{
}

static inline void wgcm_clear_child(struct task_struct *p)
{
}

static inline void wgcm_activate_task(struct task_struct *p)
{
}

static inline void wgcm_deactivate_task(struct task_struct *p, int flags)
{
}
#endif /* CONFIG_WGCM */

#endif /* _LINUX_WGCM_H */
