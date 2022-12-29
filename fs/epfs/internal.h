/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/epfs/internal.h
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#ifndef __FS_EPFS_INTERNAL_H__
#define __FS_EPFS_INTERNAL_H__

#include <linux/fs.h>
#include <linux/mutex.h>
#include <stdbool.h>

#include "epfs.h"

#define EPFS_SUPER_MAGIC 0x20220607

struct epfs_inode_info {
	struct inode vfs_inode;
	struct file *origin_file;
	struct epfs_range *range;
	struct mutex lock;
};

static inline struct epfs_inode_info *epfs_inode_to_private(struct inode *inode)
{
	return container_of(inode, struct epfs_inode_info, vfs_inode);
}

struct inode *epfs_iget(struct super_block *sb, bool is_dir);
extern const struct dentry_operations epfs_dops;
extern const struct file_operations epfs_dir_fops;
extern const struct file_operations epfs_file_fops;
extern struct file_system_type epfs_fs_type;
extern struct kmem_cache *epfs_inode_cachep;

#endif // __FS_EPFS_INTERNAL_H__
