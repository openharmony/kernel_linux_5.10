// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/inode_cloud.c
 *
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 */

#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/string.h>

#include "comm/socket_adapter.h"
#include "hmdfs.h"
#include "hmdfs_client.h"
#include "hmdfs_dentryfile.h"
#include "hmdfs_dentryfile_cloud.h"
#include "hmdfs_share.h"
#include "hmdfs_trace.h"
#include "authority/authentication.h"
#include "stash.h"

struct hmdfs_lookup_cloud_ret {
	uint64_t i_size;
	uint64_t i_mtime;
	uint8_t record_id[CLOUD_RECORD_ID_LEN];
	uint16_t i_mode;
};

uint32_t make_ino_raw_cloud(uint8_t *cloud_id)
{
	struct qstr str;

	str.len = CLOUD_RECORD_ID_LEN;
	str.name = cloud_id;
	return hmdfs_dentry_hash(&str, CLOUD_RECORD_ID_LEN);
}

struct hmdfs_lookup_cloud_ret *lookup_cloud_dentry(struct dentry *child_dentry,
					      const struct qstr *qstr,
					      uint64_t dev_id)
{
	struct hmdfs_lookup_cloud_ret *lookup_ret;
	struct hmdfs_dentry_cloud *dentry = NULL;
	struct clearcache_item *cache_item = NULL;
	struct hmdfs_dcache_lookup_ctx_cloud ctx;
	struct hmdfs_sb_info *sbi = hmdfs_sb(child_dentry->d_sb);

	get_cloud_cache_file(child_dentry->d_parent, sbi);
	cache_item = hmdfs_find_cache_item(dev_id, child_dentry->d_parent);
	if (!cache_item)
		return NULL;

	lookup_ret = kmalloc(sizeof(*lookup_ret), GFP_KERNEL);
	if (!lookup_ret)
		goto out;

	hmdfs_init_dcache_lookup_ctx_cloud(&ctx, sbi, qstr, cache_item->filp);
	dentry = hmdfs_find_dentry_cloud(child_dentry, &ctx);
	if (!dentry) {
		kfree(lookup_ret);
		lookup_ret = NULL;
		goto out;
	}

	lookup_ret->i_mode = le16_to_cpu(dentry->i_mode);
	lookup_ret->i_size = le64_to_cpu(dentry->i_size);
	lookup_ret->i_mtime = le64_to_cpu(dentry->i_mtime);
	memcpy(lookup_ret->record_id, dentry->record_id, CLOUD_RECORD_ID_LEN);

	hmdfs_unlock_file(ctx.filp, get_dentry_group_pos(ctx.bidx),
			  DENTRYGROUP_SIZE);
	kfree(ctx.page);
out:
	kref_put(&cache_item->ref, release_cache_item);
	return lookup_ret;
}

struct hmdfs_lookup_cloud_ret *hmdfs_lookup_by_cloud(struct dentry *dentry,
					     struct qstr *qstr,
					     unsigned int flags,
					     const char *relative_path)
{
	struct hmdfs_lookup_cloud_ret *result = NULL;

	result = lookup_cloud_dentry(dentry, qstr, CLOUD_DEVICE);
	return result;
}

/*
 * hmdfs_update_inode_size - update inode size when finding aready existed
 * inode.
 *
 * First of all, if the file is opened for writing, we don't update inode size
 * here, because inode size is about to be changed after writing.
 *
 * If the file is not opened, simply update getattr_isize(not actual inode size,
 * just a value showed to user). This is safe because inode size will be
 * up-to-date after open.
 *
 * If the file is opened for read:
 * a. getattr_isize == HMDFS_STALE_REMOTE_ISIZE
 *   1) i_size == new_size, nothing need to be done.
 *   2) i_size > new_size, we keep the i_size and set getattr_isize to new_size,
 *      stale data might be readed in this case, which is fine because file is
 *      opened before remote truncate the file.
 *   3) i_size < new_size, we drop the last page of the file if i_size is not
 *      aligned to PAGE_SIZE, clear getattr_isize, and update i_size to
 *      new_size.
 * b. getattr_isize != HMDFS_STALE_REMOTE_ISIZE, getattr_isize will only be set
 *    after 2).
 *   4) getattr_isize > i_size, this situation is impossible.
 *   5) i_size >= new_size, this case is the same as 2).
 *   6) i_size < new_size, this case is the same as 3).
 */
static void hmdfs_update_inode_size(struct inode *inode, uint64_t new_size)
{
	struct hmdfs_inode_info *info = hmdfs_i(inode);
	int writecount;
	uint64_t size;

	inode_lock(inode);
	size = info->getattr_isize;
	if (size == HMDFS_STALE_REMOTE_ISIZE)
		size = i_size_read(inode);
	if (size == new_size) {
		inode_unlock(inode);
		return;
	}

	writecount = atomic_read(&inode->i_writecount);
	/* check if writing is in progress */
	if (writecount > 0) {
		info->getattr_isize = HMDFS_STALE_REMOTE_ISIZE;
		inode_unlock(inode);
		return;
	}

	/* check if there is no one who opens the file */
	if (kref_read(&info->ref) == 0)
		goto update_info;

	/* check if there is someone who opens the file for read */
	if (writecount == 0) {
		uint64_t aligned_size;

		/* use inode size here instead of getattr_isize */
		size = i_size_read(inode);
		if (new_size <= size)
			goto update_info;
		/*
		 * if the old inode size is not aligned to HMDFS_PAGE_SIZE, we
		 * need to drop the last page of the inode, otherwise zero will
		 * be returned while reading the new range in the page after
		 * chaning inode size.
		 */
		aligned_size = round_down(size, HMDFS_PAGE_SIZE);
		if (aligned_size != size)
			truncate_inode_pages(inode->i_mapping, aligned_size);
		i_size_write(inode, new_size);
		info->getattr_isize = HMDFS_STALE_REMOTE_ISIZE;
		inode_unlock(inode);
		return;
	}

update_info:
	info->getattr_isize = new_size;
	inode_unlock(inode);
}

static void hmdfs_update_inode(struct inode *inode,
			       struct hmdfs_lookup_cloud_ret *lookup_result)
{
	struct hmdfs_time_t remote_mtime = {
		.tv_sec = lookup_result->i_mtime,
		.tv_nsec = 0,
	};

	/*
	 * We only update mtime if the file is not opened for writing. If we do
	 * update it before writing is about to start, user might see the mtime
	 * up-and-down if system time in server and client do not match. However
	 * mtime in client will eventually match server after timeout without
	 * writing.
	 */
	if (!inode_is_open_for_write(inode))
		inode->i_mtime = remote_mtime;

	/*
	 * We don't care i_size of dir, and lock inode for dir
	 * might cause deadlock.
	 */
	if (S_ISREG(inode->i_mode))
		hmdfs_update_inode_size(inode, lookup_result->i_size);
}

static void hmdfs_fill_inode_permission(struct inode *inode, struct inode *dir,
				     umode_t mode)
{
#ifdef CONFIG_HMDFS_FS_PERMISSION
	inode->i_uid = dir->i_uid;
	inode->i_gid = dir->i_gid;
#endif
}

struct hmdfs_peer peer;

struct inode *fill_inode_cloud(struct super_block *sb, struct hmdfs_lookup_cloud_ret *res, struct inode *dir)
{
	int ret = 0;
	struct inode *inode = NULL;
	struct hmdfs_inode_info *info;
	umode_t mode = res->i_mode;
	peer.device_id = CLOUD_DEVICE;

	inode = hmdfs_iget5_locked_cloud(sb, &peer, res->record_id);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	info = hmdfs_i(inode);
	info->inode_type = HMDFS_LAYER_OTHER_CLOUD;
	/* the inode was found in cache */
	if (!(inode->i_state & I_NEW)) {
		hmdfs_fill_inode_permission(inode, dir, mode);
		hmdfs_update_inode(inode, res);
		return inode;
	}

	inode->i_ctime.tv_sec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_mtime.tv_sec = res->i_mtime;
	inode->i_mtime.tv_nsec = 0;

	inode->i_uid = KUIDT_INIT((uid_t)0);
	inode->i_gid = KGIDT_INIT((gid_t)0);

	if (S_ISDIR(mode))
		inode->i_mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IXOTH;
	else if (S_ISREG(mode))
		inode->i_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	else {
		ret = -EIO;
		goto bad_inode;
	}

	if (S_ISREG(mode)) {
		inode->i_op = &hmdfs_dev_file_iops_cloud;
		inode->i_fop = &hmdfs_dev_file_fops_cloud;
		inode->i_size = res->i_size;
		set_nlink(inode, 1);
	} else if (S_ISDIR(mode)) {
		inode->i_op = &hmdfs_dev_dir_inode_ops_cloud;
		inode->i_fop = &hmdfs_dev_dir_ops_cloud;
		set_nlink(inode, 2);
	} else {
		ret = -EIO;
		goto bad_inode;
	}

	inode->i_mapping->a_ops = &hmdfs_dev_file_aops_cloud;

	hmdfs_fill_inode_permission(inode, dir, mode);
	unlock_new_inode(inode);
	return inode;
bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}

static struct dentry *hmdfs_lookup_cloud_dentry(struct inode *parent_inode,
						 struct dentry *child_dentry,
						 int flags)
{
	struct dentry *ret = NULL;
	struct inode *inode = NULL;
	struct super_block *sb = parent_inode->i_sb;
	struct hmdfs_lookup_cloud_ret *lookup_result = NULL;
	char *file_name = NULL;
	int file_name_len = child_dentry->d_name.len;
	struct qstr qstr;
	struct hmdfs_dentry_info *gdi = hmdfs_d(child_dentry);
	char *relative_path = NULL;

	file_name = kzalloc(NAME_MAX + 1, GFP_KERNEL);
	if (!file_name)
		return ERR_PTR(-ENOMEM);
	strncpy(file_name, child_dentry->d_name.name, file_name_len);

	qstr.name = file_name;
	qstr.len = strlen(file_name);

	relative_path = hmdfs_get_dentry_relative_path(child_dentry->d_parent);
	if (unlikely(!relative_path)) {
		ret = ERR_PTR(-ENOMEM);
		hmdfs_err("get relative path failed %d", -ENOMEM);
		goto done;
	}

	lookup_result = hmdfs_lookup_by_cloud(child_dentry, &qstr, flags,
					    relative_path);
	if (lookup_result != NULL) {
		if (in_share_dir(child_dentry))
			gdi->file_type = HM_SHARE;
		inode = fill_inode_cloud(sb, lookup_result, parent_inode);
		ret = d_splice_alias(inode, child_dentry);
		if (!IS_ERR_OR_NULL(ret))
			child_dentry = ret;
		if (!IS_ERR(ret))
			check_and_fixup_ownership_remote(parent_inode,
							 child_dentry);
	} else {
		ret = ERR_PTR(-ENOENT);
	}

done:
	kfree(relative_path);
	kfree(lookup_result);
	kfree(file_name);
	return ret;
}

struct dentry *hmdfs_lookup_cloud(struct inode *parent_inode,
				   struct dentry *child_dentry,
				   unsigned int flags)
{
	int err = 0;
	struct dentry *ret = NULL;
	struct hmdfs_dentry_info *gdi = NULL;
	struct hmdfs_sb_info *sbi = hmdfs_sb(child_dentry->d_sb);

	trace_hmdfs_lookup_remote(parent_inode, child_dentry, flags);
	if (child_dentry->d_name.len > NAME_MAX) {
		err = -ENAMETOOLONG;
		ret = ERR_PTR(-ENAMETOOLONG);
		goto out;
	}

	err = init_hmdfs_dentry_info(sbi, child_dentry,
				     HMDFS_LAYER_OTHER_CLOUD);
	if (err) {
		ret = ERR_PTR(err);
		goto out;
	}
	gdi = hmdfs_d(child_dentry);
	gdi->device_id = hmdfs_d(child_dentry->d_parent)->device_id;

	ret = hmdfs_lookup_cloud_dentry(parent_inode, child_dentry, flags);
	/*
	 * don't return error if inode do not exist, so that vfs can continue
	 * to create it.
	 */
	if (IS_ERR_OR_NULL(ret)) {
		err = PTR_ERR(ret);
		if (err == -ENOENT)
			ret = NULL;
	} else {
		child_dentry = ret;
	}

out:
	if (!err)
		hmdfs_set_time(child_dentry, jiffies);
	trace_hmdfs_lookup_remote_end(parent_inode, child_dentry, err);
	return ret;
}

int hmdfs_mkdir_cloud(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return -EPERM;
}

int hmdfs_create_cloud(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool want_excl)
{
	return -EPERM;
}

int hmdfs_rmdir_cloud(struct inode *dir, struct dentry *dentry)
{
	return -EPERM;
}

int hmdfs_unlink_cloud(struct inode *dir, struct dentry *dentry)
{
	return -EPERM;
}

int hmdfs_rename_cloud(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	return -EPERM;
}

static int hmdfs_dir_setattr_cloud(struct dentry *dentry, struct iattr *ia)
{
	// Do not support dir setattr
	return 0;
}

const struct inode_operations hmdfs_dev_dir_inode_ops_cloud = {
	.lookup = hmdfs_lookup_cloud,
	.mkdir = hmdfs_mkdir_cloud,
	.create = hmdfs_create_cloud,
	.rmdir = hmdfs_rmdir_cloud,
	.unlink = hmdfs_unlink_cloud,
	.rename = hmdfs_rename_cloud,
	.setattr = hmdfs_dir_setattr_cloud,
	.permission = hmdfs_permission,
};

static int hmdfs_setattr_cloud(struct dentry *dentry, struct iattr *ia)
{
	struct hmdfs_inode_info *info = hmdfs_i(d_inode(dentry));
	struct inode *inode = d_inode(dentry);
	int err = 0;

	if (hmdfs_inode_is_stashing(info))
		return -EAGAIN;

	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			return err;
		truncate_setsize(inode, ia->ia_size);
		info->getattr_isize = HMDFS_STALE_REMOTE_ISIZE;
	}
	if (ia->ia_valid & ATTR_MTIME)
		inode->i_mtime = ia->ia_mtime;

	return err;
}


static int hmdfs_get_cached_attr_cloud(const struct path *path,
					struct kstat *stat, u32 request_mask,
					unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct hmdfs_inode_info *info = hmdfs_i(inode);
	uint64_t size = info->getattr_isize;

	stat->ino = inode->i_ino;
	stat->mtime = inode->i_mtime;
	stat->mode = inode->i_mode;
	stat->uid.val = inode->i_uid.val;
	stat->gid.val = inode->i_gid.val;
	if (size == HMDFS_STALE_REMOTE_ISIZE)
		size = i_size_read(inode);

	stat->size = size;
	return 0;
}

const struct inode_operations hmdfs_dev_file_iops_cloud = {
	.setattr = hmdfs_setattr_cloud,
	.permission = hmdfs_permission,
	.getattr = hmdfs_get_cached_attr_cloud,
	.listxattr = NULL,
};
