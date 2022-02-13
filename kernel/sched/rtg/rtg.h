/* SPDX-License-Identifier: GPL-2.0 */
/*
 * related thread group sched header
 */
#ifndef __RTG_H
#define __RTG_H

#include <linux/types.h>
#include <linux/sched.h>

#ifdef CONFIG_SCHED_RTG
void init_task_rtg(struct task_struct *p);
#endif /* CONFIG_SCHED_RTG */
#endif
