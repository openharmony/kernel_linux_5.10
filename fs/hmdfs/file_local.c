// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/file_local.c
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

#include "hmdfs_client.h"
#include "hmdfs_dentryfile.h"
#include "hmdfs_device_view.h"
#include "hmdfs_merge_view.h"
#include "hmdfs_trace.h"

int hmdfs_file_open_local(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;
	struct super_block *sb = inode->i_sb;
	const struct cred *cred = hmdfs_sb(sb)->cred;
	struct hmdfs_file_info *gfi = kzalloc(sizeof(*gfi), GFP_KERNEL);

	if (!gfi) {
		err = -ENOMEM;
		goto out_err;
	}

	hmdfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, cred);
	hmdfs_put_lower_path(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		kfree(gfi);
	} else {
		gfi->lower_file = lower_file;
		file->private_data = gfi;
	}
out_err:
	return err;
}

int hmdfs_file_release_local(struct inode *inode, struct file *file)
{
	struct hmdfs_file_info *gfi = hmdfs_f(file);

	file->private_data = NULL;
	fput(gfi->lower_file);
	kfree(gfi);
	return 0;
}

static void hmdfs_file_accessed(struct file *file)
{
	struct file *lower_file = hmdfs_f(file)->lower_file;
	struct inode *inode = file_inode(file);
	struct inode *lower_inode = file_inode(lower_file);

	if (file->f_flags & O_NOATIME)
		return;

	inode->i_atime = lower_inode->i_atime;
}

ssize_t hmdfs_do_read_iter(struct file *file, struct iov_iter *iter,
	loff_t *ppos)
{
	ssize_t ret;
	struct file *lower_file = hmdfs_f(file)->lower_file;

	if (!iov_iter_count(iter))
		return 0;

	ret = vfs_iter_read(lower_file, iter, ppos, 0);
	hmdfs_file_accessed(file);

	return ret;
}

static ssize_t hmdfs_local_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	return hmdfs_do_read_iter(iocb->ki_filp, iter, &iocb->ki_pos);
}

static void hmdfs_file_modified(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct dentry *dentry = file_dentry(file);
	struct file *lower_file = hmdfs_f(file)->lower_file;
	struct inode *lower_inode = file_inode(lower_file);

	inode->i_atime = lower_inode->i_atime;
	inode->i_ctime = lower_inode->i_ctime;
	inode->i_mtime = lower_inode->i_mtime;
	i_size_write(inode, i_size_read(lower_inode));

	if (!hmdfs_i_merge(hmdfs_i(inode)))
		update_inode_to_dentry(dentry, inode);
}

ssize_t hmdfs_do_write_iter(struct file *file, struct iov_iter *iter,
	loff_t *ppos)
{
	ssize_t ret;
	struct file *lower_file = hmdfs_f(file)->lower_file;
	struct inode *inode = file_inode(file);

	if (!iov_iter_count(iter))
		return 0;

	inode_lock(inode);

	ret = file_remove_privs(file);
	if (ret)
		goto out_unlock;

	file_start_write(lower_file);
	ret = vfs_iter_write(lower_file, iter, ppos, 0);
	file_end_write(lower_file);

	hmdfs_file_modified(file);

out_unlock:
	inode_unlock(inode);
	return ret;
}

ssize_t hmdfs_local_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	return hmdfs_do_write_iter(iocb->ki_filp, iter, &iocb->ki_pos);
}

int hmdfs_fsync_local(struct file *file, loff_t start, loff_t end, int datasync)
{
	int err;
	struct file *lower_file = hmdfs_f(file)->lower_file;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;

	err = vfs_fsync_range(lower_file, start, end, datasync);
out:
	return err;
}

loff_t hmdfs_file_llseek_local(struct file *file, loff_t offset, int whence)
{
	int err = 0;
	struct file *lower_file = NULL;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;
	lower_file = hmdfs_f(file)->lower_file;
	err = generic_file_llseek(lower_file, offset, whence);
out:
	return err;
}

int hmdfs_file_mmap_local(struct file *file, struct vm_area_struct *vma)
{
	struct hmdfs_file_info *private_data = file->private_data;
	struct file *realfile = NULL;
	int ret;

	if (!private_data)
		return -EINVAL;

	realfile = private_data->lower_file;
	if (!realfile)
		return -EINVAL;

	if (!realfile->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(realfile);
	ret = call_mmap(vma->vm_file, vma);
	if (ret)
		fput(realfile);
	else
		fput(file);

	file_accessed(file);

	return ret;
}

const struct file_operations hmdfs_file_fops_local = {
	.owner = THIS_MODULE,
	.llseek = hmdfs_file_llseek_local,
	.read_iter = hmdfs_local_read_iter,
	.write_iter = hmdfs_local_write_iter,
	.mmap = hmdfs_file_mmap_local,
	.open = hmdfs_file_open_local,
	.release = hmdfs_file_release_local,
	.fsync = hmdfs_fsync_local,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
};

static int hmdfs_iterate_local(struct file *file, struct dir_context *ctx)
{
	int err = 0;
	loff_t start_pos = ctx->pos;
	struct file *lower_file = hmdfs_f(file)->lower_file;

	if (ctx->pos == -1)
		return 0;

	lower_file->f_pos = file->f_pos;
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;

	if (err < 0)
		ctx->pos = -1;

	trace_hmdfs_iterate_local(file->f_path.dentry, start_pos, ctx->pos,
				  err);
	return err;
}

int hmdfs_dir_open_local(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct path lower_path;
	struct super_block *sb = inode->i_sb;
	const struct cred *cred = hmdfs_sb(sb)->cred;
	struct hmdfs_file_info *gfi = kzalloc(sizeof(*gfi), GFP_KERNEL);

	if (!gfi)
		return -ENOMEM;

	if (IS_ERR_OR_NULL(cred)) {
		err = -EPERM;
		goto out_err;
	}
	hmdfs_get_lower_path(dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, cred);
	hmdfs_put_lower_path(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		goto out_err;
	} else {
		gfi->lower_file = lower_file;
		file->private_data = gfi;
	}
	return err;

out_err:
	kfree(gfi);
	return err;
}

static int hmdfs_dir_release_local(struct inode *inode, struct file *file)
{
	struct hmdfs_file_info *gfi = hmdfs_f(file);

	file->private_data = NULL;
	fput(gfi->lower_file);
	kfree(gfi);
	return 0;
}

static inline bool hmdfs_is_dst_path(struct path *src, struct path *dst)
{
	return (src->dentry == dst->dentry) && (src->mnt == dst->mnt);
}

bool hmdfs_is_share_file(struct file *file)
{
	struct file *cur_file = file;
	struct hmdfs_dentry_info *gdi;
	struct hmdfs_file_info *gfi;

	while (cur_file->f_inode->i_sb->s_magic == HMDFS_SUPER_MAGIC) {
		gdi = hmdfs_d(cur_file->f_path.dentry);
		gfi = hmdfs_f(cur_file);
		if (hm_isshare(gdi->file_type))
			return true;
		if (gfi->lower_file)
			cur_file = gfi->lower_file;
		else
			break;
	}

	return false;
}

bool hmdfs_is_share_item_still_valid(struct hmdfs_share_item *item)
{
	if (kref_read(&item->ref) == 1 && time_after(jiffies, item->timeout))
		return false;

	return true;
}

inline void release_share_item(struct hmdfs_share_item *item)
{
	kfree(item->relative_path.name);
	fput(item->file);
	kfree(item);
}

void hmdfs_remove_share_item(struct kref *ref)
{
	struct hmdfs_share_item *item =
			container_of(ref, struct hmdfs_share_item, ref);

	list_del(&item->list);
	release_share_item(item);
}

struct hmdfs_share_item *hmdfs_lookup_share_item(struct hmdfs_share_table *st,
						struct qstr *cur_relative_path)
{
	struct hmdfs_share_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, &st->item_list_head, list) {
		if (hmdfs_is_share_item_still_valid(item)) {
			if (qstr_eq(&item->relative_path, cur_relative_path))
				return item;
		} else {
			kref_put(&item->ref, hmdfs_remove_share_item);
			st->item_cnt--;
		}
	}

	return NULL;
}

inline void set_item_timeout(struct hmdfs_share_item *item)
{
	item->timeout = jiffies + HZ * HMDFS_SHARE_ITEM_TIMEOUT_S;
}

static int hmdfs_insert_share_item(struct hmdfs_share_table *st,
		struct qstr *relative_path, struct file *file, char *cid)
{
	struct hmdfs_share_item *new_item = NULL;
	int ret = 0;

	if (st->item_cnt >= st->max_cnt) {
		ret = -EMFILE;
		goto out;
	}

	new_item = kmalloc(sizeof(*new_item), GFP_KERNEL);
	if (new_item) {
		new_item->file = file;
		get_file(file);
		new_item->relative_path = *relative_path;
		memcpy(new_item->cid, cid, HMDFS_CID_SIZE);
		kref_init(&new_item->ref);
		list_add_tail(&new_item->list, &st->item_list_head);
		set_item_timeout(new_item);
		st->item_cnt++;
	} else {
		ret = -ENOMEM;
	}

out:
	return ret;
}

static int hmdfs_update_share_item(struct hmdfs_share_item *item,
					struct file *file, char *cid)
{
	/* if not the same file, we need to update struct file */
	if (!hmdfs_is_dst_path(&file->f_path, &item->file->f_path)) {
		fput(item->file);
		item->file = file;
		get_file(file);
	}
	memcpy(item->cid, cid, HMDFS_CID_SIZE);
	set_item_timeout(item);

	return 0;
}

static int hmdfs_add_to_share_table(struct file *file,
		struct hmdfs_sb_info *sbi, struct hmdfs_share_control *sc)
{
	struct fd src = fdget(sc->src_fd);
	struct hmdfs_share_table *st = &sbi->share_table;
	struct hmdfs_share_item *item;
	struct dentry *dentry;
	const char *dir_path, *cur_path;
	struct qstr relative_path;
	int err = 0;

	if (!src.file)
		return -EBADF;

	if (!S_ISREG(src.file->f_inode->i_mode)) {
		err = -EPERM;
		goto err_out;
	}

	if (hmdfs_is_share_file(src.file)) {
		err = -EPERM;
		goto err_out;
	}

	dir_path = hmdfs_get_dentry_relative_path(file->f_path.dentry);
	if (unlikely(!dir_path)) {
		err = -ENOMEM;
		goto err_out;
	}

	dentry = src.file->f_path.dentry;
	if (dentry->d_name.len > NAME_MAX) {
		kfree(dir_path);
		err = -ENAMETOOLONG;
		goto err_out;
	}

	cur_path = hmdfs_connect_path(dir_path, dentry->d_name.name);
	if (unlikely(!cur_path)) {
		kfree(dir_path);
		err = -ENOMEM;
		goto err_out;
	}
	relative_path.name = cur_path;
	relative_path.len = strlen(cur_path);

	spin_lock(&sbi->share_table.item_list_lock);
	item = hmdfs_lookup_share_item(st, &relative_path);
	if (!item)
		err = hmdfs_insert_share_item(st, &relative_path,
							src.file, sc->cid);
	else {
		if (kref_read(&item->ref) != 1)
			err = -EEXIST;
		else
			hmdfs_update_share_item(item, src.file, sc->cid);
	}
	spin_unlock(&sbi->share_table.item_list_lock);

	if (err < 0)
		kfree(cur_path);
	kfree(dir_path);

err_out:
	fdput(src);
	return err;
}

static int hmdfs_ioc_set_share_path(struct file *file, unsigned long arg)
{
	struct hmdfs_share_control sc;
	struct super_block *sb = file->f_inode->i_sb;
	struct hmdfs_sb_info *sbi = hmdfs_sb(sb);
	int error;

	if (copy_from_user(&sc, (struct hmdfs_share_control __user *)arg,
							sizeof(sc)))
		return -EFAULT;

	error = hmdfs_add_to_share_table(file, sbi, &sc);

	return error;
}

static long hmdfs_dir_ioctl_local(struct file *file, unsigned int cmd,
						unsigned long arg)
{
	switch (cmd) {
	case HMDFS_IOC_SET_SHARE_PATH:
		return hmdfs_ioc_set_share_path(file, arg);
	default:
		return -ENOTTY;
	}
}

const struct file_operations hmdfs_dir_ops_local = {
	.owner = THIS_MODULE,
	.iterate = hmdfs_iterate_local,
	.open = hmdfs_dir_open_local,
	.release = hmdfs_dir_release_local,
	.fsync = hmdfs_fsync_local,
};

const struct file_operations hmdfs_dir_ops_share = {
	.owner = THIS_MODULE,
	.iterate = hmdfs_iterate_local,
	.open = hmdfs_dir_open_local,
	.release = hmdfs_dir_release_local,
	.fsync = hmdfs_fsync_local,
	.unlocked_ioctl = hmdfs_dir_ioctl_local,
	.compat_ioctl = hmdfs_dir_ioctl_local,
};
