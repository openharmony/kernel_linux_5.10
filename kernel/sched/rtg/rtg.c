// SPDX-License-Identifier: GPL-2.0
/*
 * related thread group sched
 *
 */
#include <linux/sched.h>
#include "rtg.h"

void init_task_rtg(struct task_struct *p)
{
	rcu_assign_pointer(p->grp, NULL);
	INIT_LIST_HEAD(&p->grp_list);
}
