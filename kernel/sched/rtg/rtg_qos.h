/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rtg qos interface
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#ifndef __RTG_QOS_H
#define __RTG_QOS_H

#ifdef CONFIG_SCHED_RTG_QOS
#include <linux/sched/rtg_ctrl.h>

enum qos_manipulate_type {
	QOS_APPLY = 1,
	QOS_LEAVE,
	QOS_MAX_NR,
};

#define NR_QOS 5
#define RTG_QOS_NUM_MAX 10

struct rtg_authority;

int qos_apply(struct rtg_qos_data *data);
int qos_leave(struct rtg_qos_data *data);

void qos_pause(struct rtg_authority *auth);
void qos_resume(struct rtg_authority *auth);

void init_task_qos(struct task_struct *p);
void sched_exit_qos_list(struct task_struct *p);

typedef int (*rtg_qos_manipulate_func)(struct rtg_qos_data *data);
#endif

#endif /* __RTG_QOS_H */
