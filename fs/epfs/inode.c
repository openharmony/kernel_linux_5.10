// SPDX-License-Identifier: GPL-2.0
/*
 * fs/epfs/inode.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/version.h>

#include "internal.h"

#define USER_DATA_RW		1008
#define USER_DATA_RW_UID	KUIDT_INIT(USER_DATA_RW)
#define USER_DATA_RW_GID	KGIDT_INIT(USER_DATA_RW)

struct dentry *epfs_lookup(struct inode *dir, struct dentry *dentry,
				unsigned int flags)
{
	return ERR_PTR(-ENOENT);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int epfs_tmpfile(struct user_namespace *, struct inode *dir,
			     struct dentry *dentry, umode_t mode)
#else
static int epfs_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
#endif
{
	struct inode *inode = epfs_iget(dir->i_sb, false);

	if (!inode)
		return -ENOSPC;
	d_tmpfile(dentry, inode);
	if (IS_ENABLED(CONFIG_EPFS_DEBUG))
		epfs_debug("epfs: tmpfile %p", inode);
	return 0;
}

const struct inode_operations epfs_dir_iops = {
	.tmpfile = epfs_tmpfile,
	.lookup = epfs_lookup,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int epfs_getattr(struct user_namespace *mnt_userns,
			     const struct path *path, struct kstat *stat,
			     u32 request_mask, unsigned int flags)
#else
static int epfs_getattr(const struct path *path, struct kstat *stat,
			     u32 request_mask, unsigned int flags)
#endif
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = d_inode(dentry);
	struct epfs_inode_info *info = epfs_inode_to_private(inode);
	struct file *origin_file;
	struct kstat origin_stat;
	int ret;

	mutex_lock(&info->lock);
	origin_file = info->origin_file;
	if (!origin_file) {
		ret = -ENOENT;
		goto out_getattr;
	}
	ret = vfs_getattr(&(origin_file->f_path), &origin_stat, request_mask,
			  flags);
	if (ret)
		goto out_getattr;
	fsstack_copy_attr_all(inode, file_inode(origin_file));
	fsstack_copy_inode_size(inode, file_inode(origin_file));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	generic_fillattr(mnt_userns, d_inode(dentry), stat);
#else
	generic_fillattr(d_inode(dentry), stat);
#endif
	stat->blocks = origin_stat.blocks;

out_getattr:
	mutex_unlock(&info->lock);
	return ret;
}

const struct inode_operations epfs_file_iops = {
	.getattr = epfs_getattr,
};

struct inode *epfs_iget(struct super_block *sb, bool is_dir)
{
	struct inode *inode = new_inode(sb);

	if (!inode) {
		epfs_err("Failed to allocate new inode");
		return NULL;
	}
	if (is_dir) {
		inode->i_op = &epfs_dir_iops;
		inode->i_fop = &epfs_dir_fops;
		inode->i_mode = S_IFDIR | 0770;
	} else {
		inode->i_op = &epfs_file_iops;
		inode->i_fop = &epfs_file_fops;
		inode->i_mode = S_IFREG;
	}
	inode->i_uid = USER_DATA_RW_UID;
	inode->i_gid = USER_DATA_RW_GID;
	return inode;
}
