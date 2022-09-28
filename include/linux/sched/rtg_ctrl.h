/* SPDX-License-Identifier: GPL-2.0 */
/*
 * rtg control interface
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#ifndef __SCHED_RTG_CTL_H
#define __SCHED_RTG_CTL_H

#include <linux/fs.h>

#define SYSTEM_SERVER_UID 1000
#define MIN_APP_UID 10000
#define MAX_BOOST_DURATION_MS 5000

#define RTG_SCHED_IPC_MAGIC 0XAB

#define CMD_ID_SET_ENABLE \
	_IOWR(RTG_SCHED_IPC_MAGIC, SET_ENABLE, struct rtg_enable_data)
#define CMD_ID_SET_RTG \
	_IOWR(RTG_SCHED_IPC_MAGIC, SET_RTG, struct rtg_str_data)
#define CMD_ID_SET_CONFIG \
	_IOWR(RTG_SCHED_IPC_MAGIC, SET_CONFIG, struct rtg_str_data)
#define CMD_ID_SET_RTG_ATTR \
	_IOWR(RTG_SCHED_IPC_MAGIC, SET_RTG_ATTR, struct rtg_str_data)
#define CMD_ID_BEGIN_FRAME_FREQ \
	_IOWR(RTG_SCHED_IPC_MAGIC, BEGIN_FRAME_FREQ, struct proc_state_data)
#define CMD_ID_END_FRAME_FREQ \
	_IOWR(RTG_SCHED_IPC_MAGIC, END_FRAME_FREQ, struct proc_state_data)
#define CMD_ID_END_SCENE \
	_IOWR(RTG_SCHED_IPC_MAGIC, END_SCENE, struct proc_state_data)
#define CMD_ID_SET_MIN_UTIL \
	_IOWR(RTG_SCHED_IPC_MAGIC, SET_MIN_UTIL, struct proc_state_data)
#define CMD_ID_SET_MARGIN \
	_IOWR(RTG_SCHED_IPC_MAGIC, SET_MARGIN, struct proc_state_data)
#define CMD_ID_LIST_RTG \
	_IOWR(RTG_SCHED_IPC_MAGIC, LIST_RTG, struct rtg_info)
#define CMD_ID_LIST_RTG_THREAD \
	_IOWR(RTG_SCHED_IPC_MAGIC, LIST_RTG_THREAD, struct rtg_grp_data)
#define CMD_ID_SEARCH_RTG \
	_IOWR(RTG_SCHED_IPC_MAGIC, SEARCH_RTG, struct proc_state_data)
#define CMD_ID_GET_ENABLE \
	_IOWR(RTG_SCHED_IPC_MAGIC, GET_ENABLE, struct rtg_enable_data)

int proc_rtg_open(struct inode *inode, struct file *filp);
long proc_rtg_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long proc_rtg_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#endif

enum ioctl_abi_format {
	IOCTL_ABI_ARM32,
	IOCTL_ABI_AARCH64,
};

enum rtg_sched_cmdid {
	SET_ENABLE = 1,
	SET_RTG,
	SET_CONFIG,
	SET_RTG_ATTR,
	BEGIN_FRAME_FREQ = 5,
	END_FRAME_FREQ,
	END_SCENE,
	SET_MIN_UTIL,
	SET_MARGIN,
	LIST_RTG = 10,
	LIST_RTG_THREAD,
	SEARCH_RTG,
	GET_ENABLE,
	RTG_CTRL_MAX_NR,
};

/* proc_state */
enum grp_ctrl_cmd {
	CMD_CREATE_RTG_GRP,
	CMD_ADD_RTG_THREAD,
	CMD_REMOVE_RTG_THREAD,
	CMD_CLEAR_RTG_GRP,
	CMD_DESTROY_RTG_GRP
};

struct rtg_enable_data {
	int enable;
	int len;
	char *data;
};

struct rtg_str_data {
	int type;
	int len;
	char *data;
};

struct proc_state_data {
	int grp_id;
	int state_param;
};
#endif
