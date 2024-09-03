// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/sharefs/dentry.c
 *
 * Copyright (c) 1998-2022 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2022 Stony Brook University
 * Copyright (c) 2003-2022 The Research Foundation of SUNY
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "sharefs.h"
#include "authentication.h"

/*
 * returns: 0: tell VFS to invalidate dentry in share directory
 */
static int sharefs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	return 0;
}

static void sharefs_d_release(struct dentry *dentry)
{
	/*
	 * It is possible that the dentry private data is NULL in case we
	 * ran out of memory while initializing it in
	 * new_dentry_private_data.  So check for NULL before attempting to
	 * release resources.
	 */
	if (SHAREFS_D(dentry)) {
		/* release and reset the lower paths */
		sharefs_reset_lower_path(dentry);
		free_dentry_private_data(dentry);
	}
	return;
}

const struct dentry_operations sharefs_dops = {
	.d_revalidate	= sharefs_d_revalidate,
	.d_release	= sharefs_d_release,
};

static int try_to_create_lower_path(struct dentry *d, struct path *lower_path)
{
	int err;
	struct path lower_dir_path;
	struct qstr this;
	struct dentry *parent;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode;

	parent = dget_parent(d);
	err = sharefs_get_lower_path(parent, &lower_dir_path, 0);
	dput(parent);
	if (err)
		return err;
	/* instantiate a new negative dentry */
	this.name = d->d_name.name;
	this.len = strlen(d->d_name.name);
	this.hash = full_name_hash(lower_dir_path.dentry, this.name, this.len);
	lower_dentry = d_alloc(lower_dir_path.dentry, &this);
	if (!lower_dentry) {
		err = -ENOMEM;
		goto out;
	}
	lower_dir_inode = d_inode(lower_dir_path.dentry);
	if (lower_dir_inode->i_op && lower_dir_inode->i_op->lookup)
		lower_dir_inode->i_op->lookup(lower_dir_inode, lower_dentry, 0);

	spin_lock(&SHAREFS_D(d)->lock);
	lower_path->dentry = lower_dentry;
	lower_path->mnt = lower_dir_path.mnt;
	spin_unlock(&SHAREFS_D(d)->lock);

out:
	sharefs_put_lower_path(parent, &lower_dir_path);
	return err;
}

/* Returns struct path.  Caller must path_put it. */
int sharefs_get_lower_path(struct dentry *d, struct path *lower_path,
			   bool try_to_create)
{
	int err = -ENOMEM;
	char *path_buf;
	char *path_name = NULL;
	struct path lower_root_path;
	const struct cred *saved_cred = NULL;

	if (unlikely(!d))
		goto out;

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!path_buf)) 
		goto out;
	path_name = dentry_path_raw(d, path_buf, PATH_MAX);
	if (IS_ERR(path_name)) {
		err = PTR_ERR(path_name);
		goto out_free;
	}

	sharefs_get_lower_root_path(d, &lower_root_path);
	saved_cred = sharefs_override_file_fsids(d_inode(lower_root_path.dentry));
	if (!saved_cred) {
		sharefs_put_lower_path(d, &lower_root_path);
		goto out_free;
	}
	spin_lock(&SHAREFS_D(d)->lock);
	err = vfs_path_lookup(lower_root_path.dentry, lower_root_path.mnt,
		path_name, LOOKUP_CREATE, lower_path);
	spin_unlock(&SHAREFS_D(d)->lock);
	sharefs_revert_fsids(saved_cred);
	sharefs_put_lower_path(d, &lower_root_path);

	if (err != -ENOENT || !try_to_create)
		goto out_free;
	err = try_to_create_lower_path(d, lower_path);

out_free:
	kfree(path_buf);
out:
	return err;
}

int sharefs_get_lower_inode(struct dentry *d, struct inode **lower_inode)
{
	int err = 0;
	struct path lower_path;

	err = sharefs_get_lower_path(d, &lower_path, 0);
	if (err)
		goto out;

	*lower_inode = d_inode(lower_path.dentry);
	if ((*lower_inode)->i_flags & S_DEAD) {
		err = -ENOENT;
	} else if (!igrab(*lower_inode)) {
		err = -ESTALE;
	}

	sharefs_put_lower_path(d, &lower_path);
out:
	return err;
}