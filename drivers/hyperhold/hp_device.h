/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/hyperhold/hp_device.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _HP_DEVICE_H_
#define _HP_DEVICE_H_

#include <linux/kernel.h>

struct hp_device {
	struct file *filp;
	struct block_device *bdev;
	u32 old_block_size;
	u64 dev_size;
	u32 sec_size;
};

void unbind_bdev(struct hp_device *dev);
bool bind_bdev(struct hp_device *dev, const char *name);
#endif
