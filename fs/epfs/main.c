// SPDX-License-Identifier: GPL-2.0
/*
 * fs/epfs/main.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "internal.h"

struct kmem_cache *epfs_inode_cachep;

static int __init epfs_init(void)
{
	int ret;

	epfs_inode_cachep =
		kmem_cache_create("epfs_inode_cache",
				  sizeof(struct epfs_inode_info), 0, 0,
				  NULL);
	if (!epfs_inode_cachep)
		return -ENOMEM;
	ret = register_filesystem(&epfs_fs_type);
	if (ret)
		kmem_cache_destroy(epfs_inode_cachep);
	return ret;
}

static void __exit epfs_exit(void)
{
	unregister_filesystem(&epfs_fs_type);
	kmem_cache_destroy(epfs_inode_cachep);
}

module_init(epfs_init)
module_exit(epfs_exit)
MODULE_DESCRIPTION("Enhanced Proxy File System for OpenHarmony");
MODULE_AUTHOR("LongPing Wei weilongping@huawei.com");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_FS("epfs");
