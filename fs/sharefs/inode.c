// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/sharefs/inode.c
 * 
 * Copyright (c) 1998-2022 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2022 Stony Brook University
 * Copyright (c) 2003-2022 The Research Foundation of SUNY
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "sharefs.h"

static const char *sharefs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	DEFINE_DELAYED_CALL(lower_done);
	struct dentry *lower_dentry;
	struct path lower_path;
	char *buf;
	const char *lower_link;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	sharefs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	/*
	 * get link from lower file system, but use a separate
	 * delayed_call callback.
	 */
	lower_link = vfs_get_link(lower_dentry, &lower_done);
	if (IS_ERR(lower_link)) {
		buf = ERR_CAST(lower_link);
		goto out;
	}

	/*
	 * we can't pass lower link up: have to make private copy and
	 * pass that.
	 */
	buf = kstrdup(lower_link, GFP_KERNEL);
	do_delayed_call(&lower_done);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

	set_delayed_call(done, kfree_link, buf);
out:
	sharefs_put_lower_path(dentry, &lower_path);
	return buf;
}

static int sharefs_getattr(const struct path *path, struct kstat *stat, 
                          u32 request_mask, unsigned int flags)
{
	struct path lower_path;
	int ret;

	sharefs_get_lower_path(path->dentry, &lower_path);
	ret = vfs_getattr(&lower_path, stat, request_mask, flags);
	stat->ino = d_inode(path->dentry)->i_ino;
	stat->uid = d_inode(path->dentry)->i_uid;
	stat->gid = d_inode(path->dentry)->i_gid;
	stat->mode = d_inode(path->dentry)->i_mode;
	stat->dev = 0;
	stat->rdev = 0;
	sharefs_put_lower_path(path->dentry, &lower_path);

	return ret;
}

static ssize_t
sharefs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sharefs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sharefs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sharefs_permission(struct inode *inode, int mask)
{
	unsigned short mode = inode->i_mode;
	kuid_t cur_uid = current_fsuid();
	if (uid_eq(cur_uid, ROOT_UID))
		return 0;
	if (uid_eq(cur_uid, inode->i_uid)) {
		mode >>= 6;
	} else if (in_group_p(inode->i_gid)) {
		mode >>= 3;
	}

	if ((mask & ~mode & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		return 0;

	return -EACCES;
}

const struct inode_operations sharefs_symlink_iops = {
	.permission	= sharefs_permission,
	.getattr	= sharefs_getattr,
	.get_link	= sharefs_get_link,
	.listxattr	= sharefs_listxattr,
};

const struct inode_operations sharefs_dir_iops = {
	.lookup		= sharefs_lookup,
	.permission	= sharefs_permission,
	.getattr	= sharefs_getattr,
	.listxattr	= sharefs_listxattr,
};

const struct inode_operations sharefs_main_iops = {
	.permission	= sharefs_permission,
	.getattr	= sharefs_getattr,
	.listxattr	= sharefs_listxattr,
};
