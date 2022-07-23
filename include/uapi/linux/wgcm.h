/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_WGCM_H
#define _UAPI_LINUX_WGCM_H

#include <linux/types.h>

/*
 * WGCM: Workegroup Control Monitor.
 *
 * use sys_prctl() (see kernel/sys.c) :
 *	wgcm_ctl():	register/unregister WGCM tasks.
 *
 */

#define UMCG_TASK_ALIGN			64

#define UMCG_TID_MASK			0x3fffffffU

/**
 * struct wgcm_task: controls the state of WGCM tasks.
 *
 * The struct is aligned at 64 bytes to ensure that it fits into
 * a single cache line.
 */
struct wgcm_task {
	/**
	 * @server_tid: server's tid.
	 */
	__u32	server_tid;			/* r w */

	/**
	 * @workers_sum: count the number of workers which is bound with server

	 * Read-only for the userspace
	 */
	atomic_t	workers_sum;			/* r   */

	/**
	 * @blk_workers_sum: count the number of block workers
	 *
	 * Read-only for the userspace
	 */
	atomic_t	blk_workers_sum;		/* r   */

	__u32	__zero[1];

} __attribute__((packed, aligned(UMCG_TASK_ALIGN)));

/**
 * enum wgcm_ctl_flag - flags to pass to wgcm_ctl()
 * @WGCM_CTL_REGISTER:   register the current task as a WGCM task
 * @WGCM_CTL_UNREGISTER: unregister the current task as a WGCM task
 * @WGCM_CTL_WORKER:     register the current task as a WGCM worker
 */
enum wgcm_ctl_flag {
	WGCM_CTL_REGISTER	= 0x0001,
	WGCM_CTL_UNREGISTER	= 0x0002,
	WGCM_CTL_GET		= 0x0004,
	WGCM_CTL_WORKER		= 0x0100,
};

#endif /* _UAPI_LINUX_WGCM_H */
