/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/epfs/epfs.h
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#ifndef __FS_EPFS_H__
#define __FS_EPFS_H__

#include <linux/ioctl.h>
#include <linux/printk.h>
#include <linux/types.h>

#define EPFS_MAX_RANGES 127

struct __attribute__((__packed__)) epfs_range {
	__u64 num;
	__u64 reserved;
	struct {
		__u64 begin;
		__u64 end;
	} range[0];
};

#define EPFS_IOCTL_MAGIC 0x71
#define IOC_SET_ORIGIN_FD _IOW(EPFS_IOCTL_MAGIC, 1, __s32)
#define IOC_SET_EPFS_RANGE _IOW(EPFS_IOCTL_MAGIC, 2, struct epfs_range)

#define EPFS_TAG "Epfs"

#define epfs_err(fmt, ...)						\
	pr_err("%s:%s:%d: " fmt, EPFS_TAG, __func__, __LINE__, ##__VA_ARGS__)
#define epfs_info(fmt, ...)						\
	pr_info("%s:%s:%d: " fmt, EPFS_TAG, __func__, __LINE__, ##__VA_ARGS__)
#define epfs_warn(fmt, ...)						\
	pr_warn("%s:%s:%d: " fmt, EPFS_TAG, __func__, __LINE__, ##__VA_ARGS__)
#define epfs_debug(fmt, ...)						\
	pr_debug("%s:%s:%d: " fmt, EPFS_TAG, __func__, __LINE__, ##__VA_ARGS__)

#endif // __FS_EPFS_H__
