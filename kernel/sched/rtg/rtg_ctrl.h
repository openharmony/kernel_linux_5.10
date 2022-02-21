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
#define DEFAULT_MAX_RT_FRAME 3
#define MAX_RT_THREAD (MAX_TID_NUM + 2)
#define INIT_VALUE		(-1)
#define UPDATE_RTG_FRAME (1 << 0)
#define ADD_RTG_FRAME (1 << 1)
#define CLEAR_RTG_FRAME (1 << 2)

/* rtg_ctrl func list */
long ctrl_set_enable(int abi, void __user *uarg);
enum rtg_err_no {
	SUCC = 0,
	RTG_DISABLED = 1,
	INVALID_ARG,
	INVALID_MAGIC,
	INVALID_CMD,
};
#endif
