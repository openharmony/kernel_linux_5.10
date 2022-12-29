// SPDX-License-Identifier: GPL-2.0
/*
 * fs/epfs/main.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#include "internal.h"

static int epfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	return 1;
}

static void epfs_d_release(struct dentry *dentry)
{
}

const struct dentry_operations epfs_dops = {
	.d_revalidate = epfs_d_revalidate,
	.d_release = epfs_d_release,
};
