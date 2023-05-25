/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rtg control interface
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#ifndef __RTG_CTL_H
#define __RTG_CTL_H

#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/sched/rtg_ctrl.h>

#include "frame_rtg.h"

/* set rtg */
#define INVALID_VALUE 0xffff
#define DEFAULT_RT_PRIO 97

#define MAX_DATA_LEN 256
#define DECIMAL 10
#define DEFAULT_MAX_UTIL 1024
#define MAX_SUBPROCESS_NUM 8

#define RTG_ID_INVALID (-1)
/* fit for FFRT, original DEFAULT_MAX_RT_FRAME is 3 */
#define DEFAULT_MAX_RT_FRAME 10
#define MAX_RT_THREAD (MAX_TID_NUM + 2)
#define INIT_VALUE		(-1)
#define UPDATE_RTG_FRAME (1 << 0)
#define ADD_RTG_FRAME (1 << 1)
#define CLEAR_RTG_FRAME (1 << 2)

#define DEFAULT_FREQ_CYCLE 4
#define MIN_FREQ_CYCLE 1
#define MAX_FREQ_CYCLE 16
#define DEFAULT_INVALID_INTERVAL 50

/* proc_state */
enum proc_state {
	STATE_MIN = 0,
	FRAME_DRAWING,
	FRAME_RME_MAX = 19,
	/* rme end */
	FRAME_END_STATE = FRAME_RME_MAX + 1,

	FRAME_CLICK = 100,
	STATE_MAX,
};

enum rtg_config {
	RTG_FREQ_CYCLE,
	RTG_FRAME_MAX_UTIL,
	RTG_INVALID_INTERVAL,
	RTG_CONFIG_NUM,
};

enum rtg_err_no {
	SUCC = 0,
	RTG_DISABLED = 1,
	INVALID_ARG,
	INVALID_MAGIC,
	INVALID_CMD,
	FRAME_ERR_PID = 100,
	NO_FREE_MULTI_FRAME,
	NOT_MULTI_FRAME,
	INVALID_RTG_ID,
	NO_RT_FRAME,
};

struct rtg_grp_data {
	int rtg_cmd;
	int grp_id;
	int grp_type;
	int rt_cnt;
	int tid_num;
	int tids[MAX_TID_NUM];
};

struct rtg_proc_data {
	int rtgid;
	int type;
	int thread[MAX_TID_NUM];
	int rtcnt;
};

#endif
