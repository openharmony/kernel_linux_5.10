// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/sharefs/file.c
 *
 * Copyright (c) 1998-2022 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2022 Stony Brook University
 * Copyright (c) 2003-2022 The Research Foundation of SUNY
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "sharefs.h"

static int sharefs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sharefs_file_info), GFP_KERNEL);
	if (!SHAREFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sharefs's file struct to lower's */
	sharefs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sharefs_lower_file(file);
		if (lower_file) {
			sharefs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sharefs_set_lower_file(file, lower_file);
	}

	if (err) {
		kfree(SHAREFS_F(file));
	} else {
		kuid_t uid = inode->i_uid;
		kgid_t gid = inode->i_gid;
		mode_t mode = inode->i_mode;
		fsstack_copy_attr_all(inode, sharefs_lower_inode(inode));
		inode->i_uid = uid;
		inode->i_gid = gid;
		inode->i_mode = mode;
	}
out_err:
	return err;
}

static int sharefs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sharefs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sharefs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sharefs_lower_file(file);
	if (lower_file) {
		sharefs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SHAREFS_F(file));
	return 0;
}

static int sharefs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sharefs_lower_file(file);
	sharefs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sharefs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sharefs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sharefs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sharefs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sharefs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sharefs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sharefs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sharefs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp;
	struct file *lower_file;

	lower_file = sharefs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	/* prevent lower_file from being released */
	get_file(lower_file);
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);

	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sharefs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sharefs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp;
	struct file *lower_file;

	lower_file = sharefs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sharefs_main_fops = {
	.llseek		= sharefs_file_llseek,
	.open		= sharefs_open,
	.flush		= sharefs_flush,
	.release	= sharefs_file_release,
	.fsync		= sharefs_fsync,
	.fasync		= sharefs_fasync,
	.read_iter	= sharefs_read_iter,
	.write_iter	= sharefs_write_iter,
};

/* trimmed directory options */
const struct file_operations sharefs_dir_fops = {
	.llseek		= sharefs_file_llseek,
	.open		= sharefs_open,
	.release	= sharefs_file_release,
	.flush		= sharefs_flush,
	.fsync		= sharefs_fsync,
	.fasync		= sharefs_fasync,
};
