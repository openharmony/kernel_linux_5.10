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
#ifdef CONFIG_SHAREFS_SUPPORT_WRITE
#include "authentication.h"
#endif

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
#ifdef CONFIG_SHAREFS_SUPPORT_OVERRIDE
	return 0;
#endif
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

#ifdef CONFIG_SHAREFS_SUPPORT_WRITE
static int sharefs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	const struct cred *saved_cred = NULL;
	__u16 child_perm;

	saved_cred = sharefs_override_file_fsids(dir, &child_perm);
	if (!saved_cred) {
		err = -ENOMEM;
		return err;
	}

	sharefs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sharefs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sharefs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sharefs_put_lower_path(dentry, &lower_path);
	sharefs_revert_fsids(saved_cred);
	return err;
}

static int sharefs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;
	const struct cred *saved_cred = NULL;
	__u16 child_perm;

	saved_cred = sharefs_override_file_fsids(dir, &child_perm);
	if (!saved_cred) {
		err = -ENOMEM;
		return err;
	}

	sharefs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sharefs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sharefs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sharefs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sharefs_put_lower_path(dentry, &lower_path);
	sharefs_revert_fsids(saved_cred);
	return err;
}

static int sharefs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry = NULL;
	struct inode *lower_dir_inode = sharefs_lower_inode(dir);
	struct dentry *lower_dir_dentry = NULL;
	struct path lower_path;

	sharefs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode,
		  sharefs_lower_inode(dentry->d_inode)->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry);

out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sharefs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sharefs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	sharefs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);
	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sharefs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sharefs_rename(struct inode *old_dir, struct dentry *old_dentry,
				struct inode *new_dir, struct dentry *new_dentry,
				unsigned int flags)
{
	int err;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	if (flags)
		return -EINVAL;

	sharefs_get_lower_path(old_dentry, &lower_old_path);
	sharefs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				    lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
					lower_old_dir_dentry->d_inode);
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sharefs_put_lower_path(old_dentry, &lower_old_path);
	sharefs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}
#endif

static int sharefs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;
	
	inode = dentry->d_inode;
	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */

	err = setattr_prepare(dentry, ia);
	if (err)
		goto out_err;

	sharefs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sharefs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sharefs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */

	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));

	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sharefs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
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
#ifdef CONFIG_SHAREFS_SUPPORT_WRITE
	.unlink		= sharefs_unlink,
	.rmdir		= sharefs_rmdir,
	.rename		= sharefs_rename,
	.create		= sharefs_create,
	.mkdir		= sharefs_mkdir,
#endif
	.setattr	= sharefs_setattr,
};

const struct inode_operations sharefs_main_iops = {
	.permission	= sharefs_permission,
	.getattr	= sharefs_getattr,
	.listxattr	= sharefs_listxattr,
	.setattr        = sharefs_setattr,
};
