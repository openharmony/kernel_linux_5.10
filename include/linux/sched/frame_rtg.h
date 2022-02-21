/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Frame declaration
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#ifndef __SCHED_FRAME_RTG_H
#define __SCHED_FRAME_RTG_H

#ifdef CONFIG_SCHED_RTG_FRAME

#define MAX_TID_NUM 5

struct frame_info {
	rwlock_t lock;
	struct related_thread_group *rtg;
	struct task_struct *thread[MAX_TID_NUM];
	int thread_num;
	unsigned int frame_rate; // frame rate
	u64 frame_time;
};

struct frame_info *rtg_frame_info(int id);
#endif
#endif
