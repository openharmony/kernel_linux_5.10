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
#ifdef CONFIG_SCHED_RTG_AUTHORITY
#include <linux/spinlock.h>
#include <linux/list.h>
#endif

#include "frame_rtg.h"
#include "rtg_qos.h"

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

#define DEFAULT_FREQ_CYCLE 4
#define MIN_FREQ_CYCLE 1
#define MAX_FREQ_CYCLE 16
#define DEFAULT_INVALID_INTERVAL 50


#ifdef CONFIG_SCHED_RTG_AUTHORITY
/*
 * RTG authority flags for SYSTEM or ROOT
 *
 * keep sync with rtg_sched_cmdid
 * when add a new cmd to rtg_sched_cmdid
 * keep new_flag = (old_flag << 1) + 1
 * up to now, next flag value is 0xbfff
 */
#define AF_RTG_ALL		0x7fff

/*
 * delegated authority for normal uid
 * no AUTH_MANIPULATE (rtg_sched_cmdid = 14)
 */
#define AF_RTG_DELEGATED	0x5fff

#define ROOT_UID   0
#define SYSTEM_UID 1000

#define UID_FOR_SUPER SYSTEM_UID
#define super_uid(uid) (uid == ROOT_UID || uid == SYSTEM_UID)

enum auth_manipulate_type {
	AUTH_ENABLE = 1,
	AUTH_PAUSE,
	AUTH_DELETE,
	AUTH_GET,
	AUTH_MAX_NR,
};

enum rtg_auth_status {
	AUTH_STATUS_CACHED = 0,
	AUTH_STATUS_ENABLE,
	AUTH_STATUS_DEAD,
};

extern int init_rtg_authority_control(void);
struct rtg_authority *get_authority(struct task_struct *p);
void get_rtg_auth(struct rtg_authority *auth);
void put_rtg_auth(struct rtg_authority *auth);
#endif

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
#ifdef CONFIG_SCHED_RTG_AUTHORITY
	UID_NOT_AUTHORIZED,
	UID_NOT_FOUND,
	PID_DUPLICATE,
	PID_NOT_EXIST,
	INVALID_AUTH,
#endif
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

#ifdef CONFIG_SCHED_RTG_AUTHORITY
struct rtg_authority {
	raw_spinlock_t auth_lock;
	refcount_t usage;
	unsigned int status;
	unsigned int flag;
#ifdef CONFIG_SCHED_RTG_QOS
	unsigned int num[NR_QOS + 1];
	struct list_head tasks[NR_QOS + 1];
#endif
};
#endif

#endif
