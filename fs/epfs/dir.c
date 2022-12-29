// SPDX-License-Identifier: GPL-2.0
/*
 * fs/epfs/dir.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#include <linux/fs.h>

#include "internal.h"

static int epfs_iterate(struct file *file, struct dir_context *ctx)
{
	return 0;
}

const struct file_operations epfs_dir_fops = { .iterate = epfs_iterate };
