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
#include "hmdfs_dentryfile_cloud.h"
#include "hmdfs_trace.h"

static const struct vm_operations_struct hmdfs_cloud_vm_ops = {
	.fault = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = NULL,
};

struct cloud_readpages_work {
	struct file *filp;
	loff_t pos;
	int cnt;
	struct work_struct work;
	struct page *pages[0];
};

static ssize_t hmdfs_file_read_iter_cloud(struct kiocb *iocb,
					  struct iov_iter *iter)
{
	ssize_t ret = -ENOENT;
	struct file *filp = iocb->ki_filp;
	struct hmdfs_file_info *gfi = filp->private_data;
	struct file *lower_file = NULL;

	if (gfi)
		lower_file = gfi->lower_file;

	if (lower_file) {
		kiocb_clone(iocb, iocb, lower_file);
		ret = vfs_iter_read(lower_file, iter, &iocb->ki_pos, 0);
	}

	return ret;
}

int hmdfs_file_open_cloud(struct inode *inode, struct file *file)
{
	const char *dir_path;
	struct hmdfs_sb_info *sbi = inode->i_sb->s_fs_info;
	struct path root_path;
	struct file *lower_file;
	int err = 0;

	struct hmdfs_file_info *gfi = kzalloc(sizeof(*gfi), GFP_KERNEL);
	if (!gfi)
		return -ENOMEM;

	if (!sbi->cloud_dir) {
		hmdfs_info("no cloud_dir");
		kfree(gfi);
		return -EPERM;
	}

	err = kern_path(sbi->cloud_dir, 0, &root_path);
	if (err) {
		hmdfs_info("kern_path failed: %d", err);
		kfree(gfi);
		return err;
	}

	dir_path = hmdfs_get_dentry_relative_path(file->f_path.dentry);
	if(!dir_path) {
		hmdfs_err("get cloud path failed");
		kfree(gfi);
		return -ENOENT;
	}

	lower_file = file_open_root(&root_path, dir_path,
			      file->f_flags, file->f_mode);
	path_put(&root_path);
	if (IS_ERR(lower_file)) {
		hmdfs_info("file_open_root failed: %ld", PTR_ERR(lower_file));
		err = PTR_ERR(lower_file);
		kfree(gfi);
	} else {
		gfi->lower_file = lower_file;
		file->private_data = gfi;
	}
	kfree(dir_path);
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

int hmdfs_file_mmap_cloud(struct file *file, struct vm_area_struct *vma)
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

static void cloud_readpages_work_func(struct work_struct *work)
{
	void *pages_buf;
	int idx, ret;
	ssize_t read_len;
	struct cloud_readpages_work *cr_work;

	cr_work = container_of(work, struct cloud_readpages_work, work);

	read_len = cr_work->cnt * HMDFS_PAGE_SIZE;
	pages_buf = vmap(cr_work->pages, cr_work->cnt, VM_MAP, PAGE_KERNEL);
	if (!pages_buf)
		goto out;

	ret = kernel_read(cr_work->filp, pages_buf, read_len, &cr_work->pos);
	if (ret < 0)
		goto out_vunmap;

	if (ret != read_len)
		memset(pages_buf + ret, 0, read_len - ret);

out_vunmap:
	vunmap(pages_buf);
out:
	for (idx = 0; idx < cr_work->cnt; ++idx) {
		SetPageUptodate(cr_work->pages[idx]);
		unlock_page(cr_work->pages[idx]);
	}
	kfree(cr_work);
}

static int prepare_cloud_readpage_work(struct file *filp, int cnt,
				       struct page **vec)
{
	struct cloud_readpages_work *cr_work;
	struct hmdfs_file_info *gfi = filp->private_data;

	cr_work = kzalloc(sizeof(*cr_work) +
			  sizeof(cr_work->pages[0]) * cnt,
			  GFP_KERNEL);
	if (!cr_work) {
		hmdfs_warning("cannot alloc work");
		kfree(vec);
		return -ENOMEM;
	}

	if (gfi)
		cr_work->filp = gfi->lower_file;
	else
		cr_work->filp = filp;
	cr_work->pos = (loff_t)(vec[0]->index) << HMDFS_PAGE_OFFSET;
	cr_work->cnt = cnt;
	memcpy(cr_work->pages, vec, cnt * sizeof(*vec));

	INIT_WORK(&cr_work->work, cloud_readpages_work_func);
	schedule_work(&cr_work->work);
	return 0;
}

static int hmdfs_readpages_cloud(struct file *filp,
				 struct address_space *mapping,
				 struct list_head *pages,
				 unsigned int nr_pages)
{
	struct hmdfs_inode_info *info = hmdfs_i(file_inode(filp));
	unsigned int idx, cnt, limit;
	unsigned long next_index;
	gfp_t gfp = readahead_gfp_mask(mapping);
	struct page **vec = NULL;

	limit = info->conn->sbi->s_readpages_nr;
	vec = kmalloc(limit * sizeof(*vec), GFP_KERNEL);
	if (!vec) {
		hmdfs_warning("cannot alloc vec (%u pages)", limit);
		return -ENOMEM;
	}

	cnt = 0;
	next_index = 0;
	for (idx = 0; idx < nr_pages; ++idx) {
		struct page *page = lru_to_page(pages);

		list_del(&page->lru);
		if (add_to_page_cache_lru(page, mapping, page->index, gfp))
			goto next_page;

		if (cnt && (cnt >= limit || page->index != next_index)) {
			prepare_cloud_readpage_work(filp, cnt, vec);
			cnt = 0;
		}
		next_index = page->index + 1;
		vec[cnt++] = page;
next_page:
		put_page(page);
	}

	if (cnt)
		prepare_cloud_readpage_work(filp, cnt, vec);

	kfree(vec);
	return 0;
}

const struct file_operations hmdfs_dev_file_fops_cloud = {
	.owner = THIS_MODULE,
	.llseek = generic_file_llseek,
	.read_iter = hmdfs_file_read_iter_cloud,
	.write_iter = NULL,
	.mmap = hmdfs_file_mmap_cloud,
	.open = hmdfs_file_open_cloud,
	.release = hmdfs_file_release_cloud,
	.flush = hmdfs_file_flush_cloud,
	.fsync = NULL,
	.splice_read = NULL,
	.splice_write = NULL,
};


const struct address_space_operations hmdfs_dev_file_aops_cloud = {
	.readpage = NULL,
	.readpages = NULL,
	.write_begin = NULL,
	.write_end = NULL,
	.writepage = NULL,
	.set_page_dirty = NULL,
};

const struct address_space_operations hmdfs_aops_cloud = {
	.readpages = hmdfs_readpages_cloud,
};

int analysis_dentry_file_from_cloud(struct hmdfs_sb_info *sbi,
				    struct file *file, struct file *handler,
				    struct dir_context *ctx)
{
	struct hmdfs_dentry_group_cloud *dentry_group = NULL;
	loff_t pos = ctx->pos;
	unsigned long dev_id = (unsigned long)((pos << 1) >> (POS_BIT_NUM - DEV_ID_BIT_NUM));
	unsigned long group_id = (unsigned long)((pos << (1 + DEV_ID_BIT_NUM)) >>
				 (POS_BIT_NUM - GROUP_ID_BIT_NUM));
	loff_t offset = pos & OFFSET_BIT_MASK;
	int group_num = 0;
	char *dentry_name = NULL;
	int iterate_result = 0;
	int i, j;

	dentry_group = kzalloc(sizeof(*dentry_group), GFP_KERNEL);

	if (!dentry_group)
		return -ENOMEM;

	if (IS_ERR_OR_NULL(handler)) {
		kfree(dentry_group);
		return -ENOENT;
	}

	group_num = get_dentry_group_cnt(file_inode(handler));
	dentry_name = kzalloc(DENTRY_NAME_MAX_LEN, GFP_KERNEL);
	if (!dentry_name) {
		kfree(dentry_group);
		return -ENOMEM;
	}

	for (i = group_id; i < group_num; i++) {
		int ret = hmdfs_metainfo_read_nocred(handler, dentry_group,
					      sizeof(struct hmdfs_dentry_group_cloud),
					      i);
		if (ret != sizeof(struct hmdfs_dentry_group_cloud)) {
			hmdfs_err("read dentry group failed ret:%d", ret);
			goto done;
		}

		for (j = offset; j < DENTRY_PER_GROUP_CLOUD; j++) {
			int len;
			int file_type = DT_UNKNOWN;
			bool is_continue;

			len = le16_to_cpu(dentry_group->nsl[j].namelen);
			if (!test_bit_le(j, dentry_group->bitmap) || len == 0)
				continue;

			memset(dentry_name, 0, DENTRY_NAME_MAX_LEN);
			if (S_ISDIR(le16_to_cpu(dentry_group->nsl[j].i_mode)))
				file_type = DT_DIR;
			else if (S_ISREG(le16_to_cpu(
					 dentry_group->nsl[j].i_mode)))
				file_type = DT_REG;

			strncat(dentry_name, dentry_group->filename[j], len);
			pos = hmdfs_set_pos(dev_id, i, j);
			is_continue =
				dir_emit(ctx, dentry_name, len,
					 pos + INUNUMBER_START, file_type);
			if (!is_continue) {
				ctx->pos = pos;
				iterate_result = 1;
				goto done;
			}
		}
		offset = 0;
	}

done:
	kfree(dentry_name);
	kfree(dentry_group);
	return iterate_result;
}

static int hmdfs_iterate_cloud(struct file *file, struct dir_context *ctx)
{
	int err = 0;
	loff_t start_pos = ctx->pos;

	if (ctx->pos == -1)
		return 0;
	err = analysis_dentry_file_from_cloud(
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

	return -ENOENT;
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
