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

#define NOT_RT_PRIO (-1)
#define STATIC_RTG_DEPTH (-1)

#define FRAME_START (1 << 0)
#define FRAME_END (1 << 1)
#define FRAME_INVALID (1 << 2)
#define FRAME_USE_MARGIN_IMME (1 << 4)
#define FRAME_TIMESTAMP_SKIP_START (1 << 5)
#define FRAME_TIMESTAMP_SKIP_END (1 << 6)
#define FRAME_SETTIME (FRAME_START | FRAME_END | \
	FRAME_USE_MARGIN_IMME)
#define FRAME_SETTIME_PARAM (-1)

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

#define DEFAULT_MAX_RT_THREAD 5
/*
 * RTG_MAX_RT_THREAD_NUM should be CONFIG_NR_CPUS in previous version
 * fit for FFRT here
 */
#define RTG_MAX_RT_THREAD_NUM 20
#define INVALID_PREFERRED_CLUSTER 10

enum rtg_type {
	VIP = 0,
	TOP_TASK_KEY,
	NORMAL_TASK,
	RTG_TYPE_MAX,
};

struct frame_thread_info {
	int prio;
	int thread[MAX_TID_NUM];
	int thread_num;
};

struct multi_frame_id_manager {
	DECLARE_BITMAP(id_map, MULTI_FRAME_NUM);
	unsigned int offset;
	rwlock_t lock;
};

struct rtg_info {
	int rtg_num;
	int rtgs[MULTI_FRAME_NUM];
};

bool is_frame_rtg(int id);
int set_frame_rate(struct frame_info *frame_info, int rate);
int alloc_multi_frame_info(void);
struct frame_info *rtg_active_multi_frame_info(int id);
struct frame_info *rtg_multi_frame_info(int id);
void release_multi_frame_info(int id);
void clear_multi_frame_info(void);
void set_frame_prio(struct frame_info *frame_info, int prio);
struct task_struct *update_frame_thread(struct frame_info *frame_info,
					int old_prio, int prio, int pid,
					struct task_struct *old_task);
void update_frame_thread_info(struct frame_info *frame_info,
			      struct frame_thread_info *frame_thread_info);
#ifdef CONFIG_SCHED_RTG_RT_THREAD_LIMIT
int read_rtg_rt_thread_num(void);
#else
static inline int read_rtg_rt_thread_num(void)
{
	return 0;
}
#endif
static inline
struct group_ravg *frame_info_rtg_load(const struct frame_info *frame_info)
{
	return &frame_info_rtg(frame_info)->ravg;
}
void set_frame_sched_state(struct frame_info *frame_info, bool enable);
int set_frame_margin(struct frame_info *frame_info, int margin);
int set_frame_timestamp(struct frame_info *frame_info, unsigned long timestamp);
int set_frame_max_util(struct frame_info *frame_info, int max_util);
int set_frame_min_util(struct frame_info *frame_info, int min_util, bool is_boost);
struct frame_info *lookup_frame_info_by_grp_id(int grp_id);
int list_rtg_group(struct rtg_info *rs_data);
int search_rtg(int pid);
#endif
