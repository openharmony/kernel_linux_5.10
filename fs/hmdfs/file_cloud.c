// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/file_cloud.c
 *
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 */

#include <linux/backing-dev.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "file_remote.h"

#include "comm/socket_adapter.h"
#include "hmdfs.h"
#include "hmdfs_client.h"
#include "hmdfs_dentryfile.h"
#include "hmdfs_trace.h"
#define DATA_CLOUD "/mnt/hmdfs/100/cloud"

static const struct vm_operations_struct hmdfs_cloud_vm_ops = {
	.fault = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = NULL,
};

int hmdfs_file_open_cloud(struct inode *inode, struct file *file)
{
	const char *dir_path;
	const char *root_name = DATA_CLOUD;
	struct path root_path;
	struct file *lower_file;
	struct hmdfs_file_info *gfi = kzalloc(sizeof(*gfi), GFP_KERNEL);
	int err = 0;

	err = kern_path(root_name, 0, &root_path);
	if (err) {
		hmdfs_info("kern_path failed: %d", err);
		return ERR_PTR(err);
	}

	dir_path = hmdfs_get_dentry_relative_path(file->f_path.dentry);
	if(dir_path)
		hmdfs_info("path %s", dir_path);
	else
		hmdfs_err("get cloud path failed");

	lower_file = file_open_root(&root_path, dir_path,
			      file->f_flags, file->f_mode);
	if (IS_ERR(lower_file)) {
		hmdfs_info("file_open_root failed: %ld", PTR_ERR(lower_file));
		err = PTR_ERR(lower_file);
		kfree(gfi);
	} else {
		gfi->lower_file = lower_file;
		file->private_data = gfi;
	}
	path_put(&root_path);

	return err;
}

int hmdfs_file_release_cloud(struct inode *inode, struct file *file)
{
	struct hmdfs_file_info *gfi = hmdfs_f(file);

	file->private_data = NULL;
	fput(gfi->lower_file);
	kfree(gfi);
	return 0;
}

static int hmdfs_file_flush_cloud(struct file *file, fl_owner_t id)
{
	struct hmdfs_file_info *gfi = hmdfs_f(file);

	if(!gfi || !gfi->lower_file)
		return 0;

	if (gfi->lower_file->f_op->flush)
		return gfi->lower_file->f_op->flush(gfi->lower_file, id);
	return 0;
}

const struct file_operations hmdfs_dev_file_fops_cloud = {
	.owner = THIS_MODULE,
	.llseek = generic_file_llseek,
	.read_iter = NULL,
	.write_iter = NULL,
	.mmap = NULL,
	.open = hmdfs_file_open_cloud,
	.release = hmdfs_file_release_cloud,
	.flush = hmdfs_file_flush_cloud,
	.fsync = NULL,
	.splice_read = NULL,
	.splice_write = NULL,
};


const struct address_space_operations hmdfs_dev_file_aops_cloud = {
	.readpage = NULL,
	.write_begin = NULL,
	.write_end = NULL,
	.writepage = NULL,
	.set_page_dirty = NULL,
};

static int hmdfs_iterate_cloud(struct file *file, struct dir_context *ctx)
{
	int err = 0;
	loff_t start_pos = ctx->pos;
	uint64_t dev_id = CLOUD_DEVICE;

	if (ctx->pos == -1)
		return 0;
	ctx->pos = hmdfs_set_pos(dev_id, 0, 0);
	err = analysis_dentry_file_from_con(
		file->f_inode->i_sb->s_fs_info, file, file->private_data, ctx);

	if (err <= 0)
		ctx->pos = -1;

	trace_hmdfs_iterate_remote(file->f_path.dentry, start_pos, ctx->pos,
				   err);
	return err;
}

int hmdfs_dir_open_cloud(struct inode *inode, struct file *file)
{
	struct clearcache_item *cache_item = NULL;

	get_cloud_cache_file(file->f_path.dentry, file->f_inode->i_sb->s_fs_info);
	cache_item = hmdfs_find_cache_item(CLOUD_DEVICE,
					   file->f_path.dentry);
	if (cache_item) {
		file->private_data = cache_item->filp;
		get_file(file->private_data);
		kref_put(&cache_item->ref, release_cache_item);
		return 0;
	}
	/* need to return -ENOENT */
	return 0;
}

static int hmdfs_dir_release_cloud(struct inode *inode, struct file *file)
{
	if (file->private_data)
		fput(file->private_data);
	file->private_data = NULL;
	return 0;
}

const struct file_operations hmdfs_dev_dir_ops_cloud = {
	.owner = THIS_MODULE,
	.iterate = hmdfs_iterate_cloud,
	.open = hmdfs_dir_open_cloud,
	.release = hmdfs_dir_release_cloud,
	.fsync = __generic_file_fsync,
};
