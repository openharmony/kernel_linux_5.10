/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Frame declaration
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#ifndef __FRAME_RTG_H
#define __FRAME_RTG_H

#include <linux/sched.h>
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/sched/frame_rtg.h>

#define MULTI_FRAME_ID (DEFAULT_CGROUP_COLOC_ID + 1)
#define MULTI_FRAME_NUM (MAX_NUM_CGROUP_COLOC_ID - DEFAULT_CGROUP_COLOC_ID - 1)

#define FRAME_START (1 << 0)
#define FRAME_END (1 << 1)
#define FRAME_INVALID (1 << 2)

#define DEFAULT_FRAME_RATE 60
#define MIN_FRAME_RATE 1
#define MAX_FRAME_RATE 120

/* MARGIN value : [-100, 100] */
#define DEFAULT_VLOAD_MARGIN 16
#define MIN_VLOAD_MARGIN (-100)
#define MAX_VLOAD_MARGIN 0xffff

#define FRAME_MAX_VLOAD SCHED_CAPACITY_SCALE
#define FRAME_MAX_LOAD SCHED_CAPACITY_SCALE
#define FRAME_UTIL_INVALID_FACTOR 4
#define FRAME_DEFAULT_MIN_UTIL 0
#define FRAME_DEFAULT_MAX_UTIL SCHED_CAPACITY_SCALE
#define FRAME_DEFAULT_MIN_PREV_UTIL 0
#define FRAME_DEFAULT_MAX_PREV_UTIL SCHED_CAPACITY_SCALE

struct multi_frame_id_manager {
	DECLARE_BITMAP(id_map, MULTI_FRAME_NUM);
	unsigned int offset;
	rwlock_t lock;
};

bool is_frame_rtg(int id);
int set_frame_rate(struct frame_info *frame_info, int rate);
int alloc_multi_frame_info(void);
struct frame_info *rtg_active_multi_frame_info(int id);
struct frame_info *rtg_multi_frame_info(int id);
void release_multi_frame_info(int id);
void clear_multi_frame_info(void);
#endif
