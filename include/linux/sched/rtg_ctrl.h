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

enum ioctl_abi_format {
	IOCTL_ABI_ARM32,
	IOCTL_ABI_AARCH64,
};

enum rtg_sched_cmdid {
	SET_ENABLE = 1,
	RTG_CTRL_MAX_NR,
};

struct rtg_enable_data {
	int enable;
	int len;
	char *data;
};
#endif
