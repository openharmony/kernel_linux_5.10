// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/inode_cloud_merge.c
 *
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 */

#include "hmdfs_merge_view.h"
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/types.h>
#include "authority/authentication.h"
#include "hmdfs_trace.h"

static struct inode *fill_inode_merge(struct super_block *sb,
				      struct inode *parent_inode,
				      struct dentry *child_dentry,
				      struct dentry *lo_d_dentry)
{
	int ret = 0;
	struct dentry *fst_lo_d = NULL;
	struct hmdfs_inode_info *info = NULL;
	struct inode *inode = NULL;
	umode_t mode;

	if (lo_d_dentry) {
		fst_lo_d = lo_d_dentry;
		dget(fst_lo_d);
	} else {
		fst_lo_d = hmdfs_get_fst_lo_d(child_dentry);
	}
	if (!fst_lo_d) {
		inode = ERR_PTR(-EINVAL);
		goto out;
	}
	if (hmdfs_i(parent_inode)->inode_type == HMDFS_LAYER_ZERO)
		inode = hmdfs_iget_locked_root(sb, HMDFS_ROOT_MERGE, NULL,
					       NULL);
	else
		inode = hmdfs_iget5_locked_merge(sb, fst_lo_d);
	if (!inode) {
		hmdfs_err("iget5_locked get inode NULL");
		inode = ERR_PTR(-ENOMEM);
		goto out;
	}
	if (!(inode->i_state & I_NEW))
		goto out;
	info = hmdfs_i(inode);
	if (hmdfs_i(parent_inode)->inode_type == HMDFS_LAYER_ZERO)
		info->inode_type = HMDFS_LAYER_FIRST_MERGE;
	else
		info->inode_type = HMDFS_LAYER_OTHER_MERGE;

	inode->i_uid = USER_DATA_RW_UID;
	inode->i_gid = USER_DATA_RW_GID;

	update_inode_attr(inode, child_dentry);
	mode = d_inode(fst_lo_d)->i_mode;

	if (S_ISREG(mode)) {
		inode->i_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
		inode->i_op = &hmdfs_file_iops_cloud_merge;
		inode->i_fop = &hmdfs_file_fops_merge;
		set_nlink(inode, 1);
	} else if (S_ISDIR(mode)) {
		inode->i_mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IXOTH;
		inode->i_op = &hmdfs_dir_iops_cloud_merge;
		inode->i_fop = &hmdfs_dir_fops_merge;
		set_nlink(inode, get_num_comrades(child_dentry) + 2);
	} else {
		ret = -EIO;
		goto bad_inode;
	}

	unlock_new_inode(inode);
out:
	dput(fst_lo_d);
	return inode;
bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}

static int lookup_merge_normal(struct dentry *dentry, unsigned int flags)
{
	int ret = -ENOMEM;
	int err = 0;
	int devid = -1;
	struct dentry *pdentry = dget_parent(dentry);
	struct hmdfs_dentry_info_merge *mdi = hmdfs_dm(dentry);
	struct hmdfs_sb_info *sbi = hmdfs_sb(dentry->d_sb);
	char *rname, *ppath, *cpath;

	rname = hmdfs_get_real_dname(dentry, &devid, &mdi->type);
	if (unlikely(!rname)) {
		goto out;
	}

	ppath = hmdfs_merge_get_dentry_relative_path(pdentry);
	if (unlikely(!ppath)) {
		hmdfs_err("failed to get parent relative path");
		goto out_rname;
	}

	cpath = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!cpath)) {
		hmdfs_err("failed to get child device_view path");
		goto out_ppath;
	}

	mutex_lock(&mdi->work_lock);
	mutex_lock(&sbi->connections.node_lock);
	if (mdi->type != DT_REG || devid == 0) {
		snprintf(cpath, PATH_MAX, "device_view/local%s/%s", ppath,
			rname);
		err = merge_lookup_async(mdi, sbi, 0, cpath, flags);
		if (err)
			hmdfs_err("failed to create local lookup work");
	}

	snprintf(cpath, PATH_MAX, "device_view/%s%s/%s", CLOUD_CID,
			ppath, rname);
	err = merge_lookup_async(mdi, sbi, CLOUD_DEVICE, cpath,
			flags);
	if (err)
		hmdfs_err("failed  lookup cloud");
	mutex_unlock(&sbi->connections.node_lock);
	mutex_unlock(&mdi->work_lock);

	wait_event(mdi->wait_queue, is_merge_lookup_end(mdi));

	ret = -ENOENT;
	if (!is_comrade_list_empty(mdi))
		ret = 0;

	kfree(cpath);
out_ppath:
	kfree(ppath);
out_rname:
	kfree(rname);
out:
	dput(pdentry);
	return ret;
}

/**
 * do_lookup_merge_root - lookup the root of the merge view(root/merge_view)
 *
 * It's common for a network filesystem to incur various of faults, so we
 * intent to show mercy for faults here, except faults reported by the local.
 */
static int do_lookup_cloud_merge_root(struct path path_dev,
				struct dentry *child_dentry, unsigned int flags)
{
	struct hmdfs_dentry_comrade *comrade;
	const int buf_len =
		max((int)HMDFS_CID_SIZE + 1, (int)sizeof(DEVICE_VIEW_LOCAL));
	char *buf = kzalloc(buf_len, GFP_KERNEL);
	LIST_HEAD(head);
	int ret;

	if (!buf)
		return -ENOMEM;

	// lookup real_dst/device_view/local
	memcpy(buf, DEVICE_VIEW_LOCAL, sizeof(DEVICE_VIEW_LOCAL));
	comrade = lookup_comrade(path_dev, buf, HMDFS_DEVID_LOCAL, flags);
	if (IS_ERR(comrade)) {
		ret = PTR_ERR(comrade);
		goto out;
	}
	link_comrade(&head, comrade);

	memcpy(buf, CLOUD_CID, 6);
	buf[5] = '\0';
	comrade = lookup_comrade(path_dev, buf, CLOUD_DEVICE, flags);
	if (IS_ERR(comrade)) {
		ret = PTR_ERR(comrade);
		goto out;
	}

	link_comrade(&head, comrade);

	assign_comrades_unlocked(child_dentry, &head);
	ret = 0;

out:
	kfree(buf);
	return ret;
}

static int lookup_cloud_merge_root(struct inode *root_inode,
			     struct dentry *child_dentry, unsigned int flags)
{
	struct hmdfs_sb_info *sbi = hmdfs_sb(child_dentry->d_sb);
	struct path path_dev;
	int ret = -ENOENT;
	int buf_len;
	char *buf = NULL;
	bool locked, down;

	// consider additional one slash and one '\0'
	buf_len = strlen(sbi->real_dst) + 1 + sizeof(DEVICE_VIEW_ROOT);
	if (buf_len > PATH_MAX)
		return -ENAMETOOLONG;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (unlikely(!buf))
		return -ENOMEM;

	sprintf(buf, "%s/%s", sbi->real_dst, DEVICE_VIEW_ROOT);
	lock_root_inode_shared(root_inode, &locked, &down);
	ret = hmdfs_get_path_in_sb(child_dentry->d_sb, buf, LOOKUP_DIRECTORY,
				   &path_dev);
	if (ret)
		goto free_buf;

	ret = do_lookup_cloud_merge_root(path_dev, child_dentry, flags);
	path_put(&path_dev);

free_buf:
	kfree(buf);
	restore_root_inode_sem(root_inode, locked, down);
	return ret;
}

static void update_dm(struct dentry *dst, struct dentry *src)
{
	struct hmdfs_dentry_info_merge *dmi_dst = hmdfs_dm(dst);
	struct hmdfs_dentry_info_merge *dmi_src = hmdfs_dm(src);

	trace_hmdfs_merge_update_dentry_info_enter(src, dst);

	spin_lock(&dst->d_lock);
	spin_lock(&src->d_lock);
	dst->d_fsdata = dmi_src;
	src->d_fsdata = dmi_dst;
	spin_unlock(&src->d_lock);
	spin_unlock(&dst->d_lock);

	trace_hmdfs_merge_update_dentry_info_exit(src, dst);
}

// do this in a map-reduce manner
struct dentry *hmdfs_lookup_cloud_merge(struct inode *parent_inode,
				  struct dentry *child_dentry,
				  unsigned int flags)
{
	bool create = flags & (LOOKUP_CREATE | LOOKUP_RENAME_TARGET);
	struct hmdfs_sb_info *sbi = hmdfs_sb(child_dentry->d_sb);
	struct hmdfs_inode_info *pii = hmdfs_i(parent_inode);
	struct inode *child_inode = NULL;
	struct dentry *ret_dentry = NULL;
	int err = 0;

	/*
	 * Internal flags like LOOKUP_CREATE should not pass to device view.
	 * LOOKUP_REVAL is needed because dentry cache in hmdfs might be stale
	 * after rename in lower fs. LOOKUP_DIRECTORY is not needed because
	 * merge_view can do the judgement that whether result is directory or
	 * not.
	 */
	flags = flags & LOOKUP_REVAL;

	child_dentry->d_fsdata = NULL;

	if (child_dentry->d_name.len > NAME_MAX) {
		err = -ENAMETOOLONG;
		goto out;
	}

	err = init_hmdfs_dentry_info_merge(sbi, child_dentry);
	if (unlikely(err))
		goto out;

	if (pii->inode_type == HMDFS_LAYER_ZERO) {
		hmdfs_dm(child_dentry)->dentry_type = HMDFS_LAYER_FIRST_MERGE;
		err = lookup_cloud_merge_root(parent_inode, child_dentry, flags);
	} else {
		hmdfs_dm(child_dentry)->dentry_type = HMDFS_LAYER_OTHER_MERGE;
		err = lookup_merge_normal(child_dentry, flags);
	}

	if (!err) {
		struct hmdfs_inode_info *info = NULL;

		child_inode = fill_inode_merge(parent_inode->i_sb, parent_inode,
					       child_dentry, NULL);
		ret_dentry = d_splice_alias(child_inode, child_dentry);
		if (IS_ERR(ret_dentry)) {
			clear_comrades(child_dentry);
			err = PTR_ERR(ret_dentry);
			goto out;
		}
		if (ret_dentry) {
			update_dm(ret_dentry, child_dentry);
			child_dentry = ret_dentry;
		}
		info = hmdfs_i(child_inode);
		if (info->inode_type == HMDFS_LAYER_FIRST_MERGE)
			hmdfs_root_inode_perm_init(child_inode);
		else
			check_and_fixup_ownership_remote(parent_inode,
							 child_dentry);

		goto out;
	}

	if ((err == -ENOENT) && create)
		err = 0;

out:
	hmdfs_trace_merge(trace_hmdfs_lookup_merge_end, parent_inode,
			  child_dentry, err);
	return err ? ERR_PTR(err) : ret_dentry;
}

const struct inode_operations hmdfs_file_iops_cloud_merge = {
	.getattr = hmdfs_getattr_merge,
	.setattr = hmdfs_setattr_merge,
	.permission = hmdfs_permission,
};

int do_mkdir_cloud_merge(struct inode *parent_inode, struct dentry *child_dentry,
		   umode_t mode, struct inode *lo_i_parent,
		   struct dentry *lo_d_child)
{
	int ret = 0;
	struct super_block *sb = parent_inode->i_sb;
	struct inode *child_inode = NULL;

	ret = vfs_mkdir(lo_i_parent, lo_d_child, mode);
	if (ret)
		goto out;

	child_inode =
		fill_inode_merge(sb, parent_inode, child_dentry, lo_d_child);
	if (IS_ERR(child_inode)) {
		ret = PTR_ERR(child_inode);
		goto out;
	}

	d_add(child_dentry, child_inode);
	/* nlink should be increased with the joining of children */
	set_nlink(parent_inode, 2);
out:
	return ret;
}

int do_create_cloud_merge(struct inode *parent_inode, struct dentry *child_dentry,
		    umode_t mode, bool want_excl, struct inode *lo_i_parent,
		    struct dentry *lo_d_child)
{
	int ret = 0;
	struct super_block *sb = parent_inode->i_sb;
	struct inode *child_inode = NULL;

	ret = vfs_create(lo_i_parent, lo_d_child, mode, want_excl);
	if (ret)
		goto out;

	child_inode =
		fill_inode_merge(sb, parent_inode, child_dentry, lo_d_child);
	if (IS_ERR(child_inode)) {
		ret = PTR_ERR(child_inode);
		goto out;
	}

	d_add(child_dentry, child_inode);
	/* nlink should be increased with the joining of children */
	set_nlink(parent_inode, 2);
out:
	return ret;
}

int hmdfs_do_ops_cloud_merge(struct inode *i_parent, struct dentry *d_child,
		       struct dentry *lo_d_child, struct path path,
		       struct hmdfs_recursive_para *rec_op_para)
{
	int ret = 0;

	if (rec_op_para->is_last) {
		switch (rec_op_para->opcode) {
		case F_MKDIR_MERGE:
			ret = do_mkdir_cloud_merge(i_parent, d_child,
					     rec_op_para->mode,
					     d_inode(path.dentry), lo_d_child);
			break;
		case F_CREATE_MERGE:
			ret = do_create_cloud_merge(i_parent, d_child,
					      rec_op_para->mode,
					      rec_op_para->want_excl,
					      d_inode(path.dentry), lo_d_child);
			break;
		default:
			ret = -EINVAL;
			break;
		}
	} else {
		ret = vfs_mkdir(d_inode(path.dentry), lo_d_child,
				rec_op_para->mode);
	}
	if (ret)
		hmdfs_err("vfs_ops failed, ops %d, err = %d",
			  rec_op_para->opcode, ret);
	return ret;
}

int hmdfs_create_lower_cloud_dentry(struct inode *i_parent, struct dentry *d_child,
			      struct dentry *lo_d_parent, bool is_dir,
			      struct hmdfs_recursive_para *rec_op_para)
{
	struct hmdfs_sb_info *sbi = i_parent->i_sb->s_fs_info;
	struct hmdfs_dentry_comrade *new_comrade = NULL;
	struct dentry *lo_d_child = NULL;
	char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	char *absolute_path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	char *path_name = NULL;
	struct path path = { .mnt = NULL, .dentry = NULL };
	int ret = 0;

	if (unlikely(!path_buf || !absolute_path_buf)) {
		ret = -ENOMEM;
		goto out;
	}

	path_name = dentry_path_raw(lo_d_parent, path_buf, PATH_MAX);
	if (IS_ERR(path_name)) {
		ret = PTR_ERR(path_name);
		goto out;
	}
	if ((strlen(sbi->real_dst) + strlen(path_name) +
	     strlen(d_child->d_name.name) + 2) > PATH_MAX) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	sprintf(absolute_path_buf, "%s%s/%s", sbi->real_dst, path_name,
		d_child->d_name.name);

	if (is_dir)
		lo_d_child = kern_path_create(AT_FDCWD, absolute_path_buf,
					      &path, LOOKUP_DIRECTORY);
	else
		lo_d_child = kern_path_create(AT_FDCWD, absolute_path_buf,
					      &path, 0);
	if (IS_ERR(lo_d_child)) {
		ret = PTR_ERR(lo_d_child);
		goto out;
	}
	// to ensure link_comrade after vfs_mkdir succeed
	ret = hmdfs_do_ops_cloud_merge(i_parent, d_child, lo_d_child, path,
				 rec_op_para);
	if (ret)
		goto out_put;
	new_comrade = alloc_comrade(lo_d_child, HMDFS_DEVID_LOCAL);
	if (IS_ERR(new_comrade)) {
		ret = PTR_ERR(new_comrade);
		goto out_put;
	} else {
		link_comrade_unlocked(d_child, new_comrade);
	}

out_put:
	done_path_create(&path, lo_d_child);
out:
	kfree(absolute_path_buf);
	kfree(path_buf);
	return ret;
}

static int create_lo_d_parent_recur(struct dentry *d_parent,
				    struct dentry *d_child, umode_t mode,
				    struct hmdfs_recursive_para *rec_op_para)
{
	struct dentry *lo_d_parent, *d_pparent;
	struct hmdfs_dentry_info_merge *pmdi = NULL;
	int ret = 0;

	pmdi = hmdfs_dm(d_parent);
	wait_event(pmdi->wait_queue, !has_merge_lookup_work(pmdi));
	lo_d_parent = hmdfs_get_lo_d(d_parent, HMDFS_DEVID_LOCAL);
	if (!lo_d_parent) {
		d_pparent = dget_parent(d_parent);
		ret = create_lo_d_parent_recur(d_pparent, d_parent,
					       d_inode(d_parent)->i_mode,
					       rec_op_para);
		dput(d_pparent);
		if (ret)
			goto out;
		lo_d_parent = hmdfs_get_lo_d(d_parent, HMDFS_DEVID_LOCAL);
		if (!lo_d_parent) {
			ret = -ENOENT;
			goto out;
		}
	}
	rec_op_para->is_last = false;
	rec_op_para->mode = mode;
	ret = hmdfs_create_lower_cloud_dentry(d_inode(d_parent), d_child, lo_d_parent,
					true, rec_op_para);
out:
	dput(lo_d_parent);
	return ret;
}

int create_lo_d_cloud_child(struct inode *i_parent, struct dentry *d_child,
		      bool is_dir, struct hmdfs_recursive_para *rec_op_para)
{
	struct dentry *d_pparent, *lo_d_parent, *lo_d_child;
	struct dentry *d_parent = dget_parent(d_child);
	struct hmdfs_dentry_info_merge *pmdi = hmdfs_dm(d_parent);
	int ret = 0;
	mode_t d_child_mode = rec_op_para->mode;

	wait_event(pmdi->wait_queue, !has_merge_lookup_work(pmdi));

	lo_d_parent = hmdfs_get_lo_d(d_parent, HMDFS_DEVID_LOCAL);
	if (!lo_d_parent) {
		d_pparent = dget_parent(d_parent);
		ret = create_lo_d_parent_recur(d_pparent, d_parent,
					       d_inode(d_parent)->i_mode,
					       rec_op_para);
		dput(d_pparent);
		if (unlikely(ret)) {
			lo_d_child = ERR_PTR(ret);
			goto out;
		}
		lo_d_parent = hmdfs_get_lo_d(d_parent, HMDFS_DEVID_LOCAL);
		if (!lo_d_parent) {
			lo_d_child = ERR_PTR(-ENOENT);
			goto out;
		}
	}
	rec_op_para->is_last = true;
	rec_op_para->mode = d_child_mode;
	ret = hmdfs_create_lower_cloud_dentry(i_parent, d_child, lo_d_parent, is_dir,
					rec_op_para);

out:
	dput(d_parent);
	dput(lo_d_parent);
	return ret;
}

int hmdfs_mkdir_cloud_merge(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int ret = 0;
	struct hmdfs_recursive_para *rec_op_para = NULL;

	// confict_name  & file_type is checked by hmdfs_mkdir_local
	if (hmdfs_file_type(dentry->d_name.name) != HMDFS_TYPE_COMMON) {
		ret = -EACCES;
		goto out;
	}
	rec_op_para = kmalloc(sizeof(*rec_op_para), GFP_KERNEL);
	if (!rec_op_para) {
		ret = -ENOMEM;
		goto out;
	}

	hmdfs_init_recursive_para(rec_op_para, F_MKDIR_MERGE, mode, false,
				  NULL);
	ret = create_lo_d_cloud_child(dir, dentry, true, rec_op_para);
out:
	hmdfs_trace_merge(trace_hmdfs_mkdir_merge, dir, dentry, ret);
	if (ret)
		d_drop(dentry);
	kfree(rec_op_para);
	return ret;
}

int hmdfs_create_cloud_merge(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool want_excl)
{
	struct hmdfs_recursive_para *rec_op_para = NULL;
	int ret = 0;

	rec_op_para = kmalloc(sizeof(*rec_op_para), GFP_KERNEL);
	if (!rec_op_para) {
		ret = -ENOMEM;
		goto out;
	}
	hmdfs_init_recursive_para(rec_op_para, F_CREATE_MERGE, mode, want_excl,
				  NULL);
	// confict_name  & file_type is checked by hmdfs_create_local
	ret = create_lo_d_cloud_child(dir, dentry, false, rec_op_para);
out:
	hmdfs_trace_merge(trace_hmdfs_create_merge, dir, dentry, ret);
	if (ret)
		d_drop(dentry);
	kfree(rec_op_para);
	return ret;
}

static int rename_lo_d_cloud_child(struct hmdfs_rename_para *rename_para,
				   struct hmdfs_recursive_para *rec_op_para)
{
	struct dentry *d_pparent, *lo_d_parent;
	struct dentry *d_parent = dget_parent(rename_para->new_dentry);
	struct hmdfs_dentry_info_merge *pmdi = hmdfs_dm(d_parent);
	int ret = 0;

	wait_event(pmdi->wait_queue, !has_merge_lookup_work(pmdi));

	lo_d_parent = hmdfs_get_lo_d(d_parent, HMDFS_DEVID_LOCAL);
	if (!lo_d_parent) {
		d_pparent = dget_parent(d_parent);
		ret = create_lo_d_parent_recur(d_pparent, d_parent,
					       d_inode(d_parent)->i_mode,
					       rec_op_para);
		dput(d_pparent);
		if (unlikely(ret))
			goto out;
		lo_d_parent = hmdfs_get_lo_d(d_parent, HMDFS_DEVID_LOCAL);
		if (!lo_d_parent) {
			ret = -ENOENT;
			goto out;
		}
	}
	ret = do_rename_merge(rename_para->old_dir, rename_para->old_dentry,
			      rename_para->new_dir, rename_para->new_dentry,
			      rename_para->flags);

out:
	dput(d_parent);
	dput(lo_d_parent);
	return ret;
}

static int hmdfs_rename_cloud_merge(struct inode *old_dir,
				    struct dentry *old_dentry,
				    struct inode *new_dir,
				    struct dentry *new_dentry,
				    unsigned int flags)
{
	struct hmdfs_recursive_para *rec_op_para = NULL;
	struct hmdfs_rename_para rename_para = { old_dir, old_dentry, new_dir,
						 new_dentry, flags };
	int ret = 0;

	if (hmdfs_file_type(old_dentry->d_name.name) != HMDFS_TYPE_COMMON ||
	    hmdfs_file_type(new_dentry->d_name.name) != HMDFS_TYPE_COMMON) {
		ret = -EACCES;
		goto rename_out;
	}
	rec_op_para = kmalloc(sizeof(*rec_op_para), GFP_KERNEL);
	if (!rec_op_para) {
		ret = -ENOMEM;
		goto rename_out;
	}
	trace_hmdfs_rename_merge(old_dir, old_dentry, new_dir, new_dentry,
				 flags);

	hmdfs_init_recursive_para(rec_op_para, F_MKDIR_MERGE, 0, 0, NULL);
	ret = rename_lo_d_cloud_child(&rename_para, rec_op_para);
	if (ret != 0)
		d_drop(new_dentry);

	if (S_ISREG(old_dentry->d_inode->i_mode) && !ret)
		d_invalidate(old_dentry);
rename_out:
	hmdfs_trace_rename_merge(old_dir, old_dentry, new_dir, new_dentry, ret);
	kfree(rec_op_para);
	return ret;
}

const struct inode_operations hmdfs_dir_iops_cloud_merge = {
	.lookup = hmdfs_lookup_cloud_merge,
	.mkdir = hmdfs_mkdir_cloud_merge,
	.create = hmdfs_create_cloud_merge,
	.rmdir = hmdfs_rmdir_merge,
	.unlink = hmdfs_unlink_merge,
	.rename = hmdfs_rename_cloud_merge,
	.permission = hmdfs_permission,
};
