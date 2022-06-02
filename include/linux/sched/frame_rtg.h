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
	/*
	 * use rtg load tracking in frame_info
	 * rtg->curr_window_load  -=> the workload of current frame
	 * rtg->prev_window_load  -=> the workload of last frame
	 * rtg->curr_window_exec  -=> the thread's runtime of current frame
	 * rtg->prev_window_exec  -=> the thread's runtime of last frame
	 * rtg->prev_window_time  -=> the actual time of the last frame
	 */
	struct mutex lock;
	struct related_thread_group *rtg;
	int prio;
	struct task_struct *thread[MAX_TID_NUM];
	atomic_t thread_prio[MAX_TID_NUM];
	int thread_num;
	unsigned int frame_rate; // frame rate
	u64 frame_time;
	atomic_t curr_rt_thread_num;
	atomic_t max_rt_thread_num;
	atomic_t frame_sched_state;
	atomic_t start_frame_freq;
	atomic_t frame_state;

	/*
	 * frame_vload : the emergency level of current frame.
	 * max_vload_time : the timeline frame_load increase to FRAME_MAX_VLOAD
	 * it's always equal to 2 * frame_time / NSEC_PER_MSEC
	 *
	 * The closer to the deadline, the higher emergency of current
	 * frame, so the frame_vload is only related to frame time,
	 * and grown with time.
	 */
	u64 frame_vload;
	int vload_margin;
	int max_vload_time;

	u64 frame_util;
	unsigned long status;
	unsigned long prev_fake_load_util;
	unsigned long prev_frame_load_util;
	unsigned long prev_frame_time;
	unsigned long prev_frame_exec;
	unsigned long prev_frame_load;
	unsigned int frame_min_util;
	unsigned int frame_max_util;
	unsigned int prev_min_util;
	unsigned int prev_max_util;
	unsigned int frame_boost_min_util;

	bool margin_imme;
	bool timestamp_skipped;
};

struct frame_info *rtg_frame_info(int id);
static inline
struct related_thread_group *frame_info_rtg(const struct frame_info *frame_info)
{
	return frame_info->rtg;
}
#endif
#endif
