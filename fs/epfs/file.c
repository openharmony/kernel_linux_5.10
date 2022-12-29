// SPDX-License-Identifier: GPL-2.0
/*
 * fs/epfs/file.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "internal.h"

long epfs_set_origin_fd(struct file *file, unsigned long arg)
{
	int fd = -1;
	struct file *origin_file;
	struct inode *inode = file->f_inode;
	struct epfs_inode_info *info = epfs_inode_to_private(inode);
	int ret = 0;

	if (copy_from_user(&fd, (int *)arg, sizeof(fd)))
		return -EFAULT;
	if (IS_ENABLED(CONFIG_EPFS_DEBUG))
		epfs_debug("original fd: %d", fd);
	origin_file = fget(fd);
	if (!origin_file) {
		epfs_err("Original file not exist!");
		return -EBADF;
	}

	mutex_lock(&info->lock);
	if (info->origin_file) {
		// origin_file had been set.
		ret = -EEXIST;
		fput(origin_file);
	} else if (file_inode(origin_file) == inode) {
		epfs_err("Could not set itself as origin_file!");
		fput(origin_file);
		ret = -EINVAL;
	} else {
		info->origin_file = origin_file;
		fsstack_copy_attr_all(inode, file_inode(origin_file));
		fsstack_copy_inode_size(inode, file_inode(origin_file));
	}
	mutex_unlock(&info->lock);
	return ret;
}

int check_range(struct epfs_range *range)
{
	__u64 index;

	if (range->range[0].begin >= range->range[0].end) {
		epfs_err("Invalid range: [%llu, %llu)", range->range[0].begin,
		       range->range[0].end);
		return -EINVAL;
	}

	for (index = 1; index < range->num; index++) {
		if ((range->range[index].begin >= range->range[index].end) ||
		    (range->range[index].begin < range->range[index - 1].end)) {
			epfs_err("Invalid range: [%llu, %llu), [%llu, %llu)",
			       range->range[index - 1].begin,
			       range->range[index - 1].end,
			       range->range[index].begin,
			       range->range[index].end);
			return -EINVAL;
		}
	}
	if (IS_ENABLED(CONFIG_EPFS_DEBUG)) {
		epfs_debug("epfs_range recv %llu ranges:", range->num);
		for (index = 0; index < range->num; index++) {
			epfs_debug("range:[%llu %llu)",
				 range->range[index].begin,
				 range->range[index].end);
		}
		epfs_debug("\n");
	}
	return 0;
}

long epfs_set_range(struct file *file, unsigned long arg)
{
	struct inode *inode = file->f_inode;
	struct epfs_inode_info *info = epfs_inode_to_private(inode);
	int ret = 0;
	struct epfs_range *range;
	struct epfs_range header;

	mutex_lock(&info->lock);
	if (!info->origin_file) {
		epfs_err("origin file not exist!");
		ret = -EBADF;
		goto out_set_range;
	}

	if (copy_from_user(&header, (struct epfs_range *)arg,
			   sizeof(header))) {
		ret = -EFAULT;
		epfs_err("get header failed!");
		goto out_set_range;
	}

	if (header.num > EPFS_MAX_RANGES || header.num == 0) {
		ret = -EINVAL;
		epfs_err("illegal num: %llu", header.num);
		goto out_set_range;
	}

	range = kzalloc(sizeof(header) + sizeof(header.range[0]) * header.num,
			GFP_KERNEL);
	if (!range) {
		ret = -ENOMEM;
		goto out_set_range;
	}

	if (copy_from_user(range, (struct epfs_range *)arg,
		sizeof(header) + sizeof(header.range[0]) * header.num)) {
		ret = -EFAULT;
		epfs_err("Failed to get range! num: %llu", header.num);
		kfree(range);
		goto out_set_range;
	}

	ret = check_range(range);
	if (ret) {
		kfree(range);
		goto out_set_range;
	}

	info->range = range;
out_set_range:
	mutex_unlock(&info->lock);
	return ret;
}

static long __epfs_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	long rc = -ENOTTY;

	switch (cmd) {
	case IOC_SET_ORIGIN_FD:
		return epfs_set_origin_fd(file, arg);
	case IOC_SET_EPFS_RANGE:
		return epfs_set_range(file, arg);
	default:
		epfs_info("Exit epfs unsupported ioctl, ret: %ld", rc);
		return rc;
	}
}

static long epfs_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	return __epfs_ioctl(file, cmd, arg);
}

static long epfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				     unsigned long arg)
{
	return __epfs_ioctl(file, cmd, arg);
}

static ssize_t epfs_read(struct file *file, char __user *buf, size_t count,
			      loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	struct epfs_inode_info *info = epfs_inode_to_private(inode);
	struct file *origin_file;
	struct epfs_range *range;
	ssize_t ret = 0;
	loff_t pos = *ppos;
	loff_t file_size;
	int current_range_index = 0;

	mutex_lock(&info->lock);
	range = info->range;
	if (!range) {
		ret = -EINVAL;
		epfs_err("Invalid inode range!");
		goto out_read;
	}

	origin_file = info->origin_file;

	if (!origin_file) {
		ret = -ENOENT;
		epfs_err("origin file not exist!");
		goto out_read;
	}

	// Reduce count when it will read over file size.
	file_size = i_size_read(file_inode(origin_file));
	if (IS_ENABLED(CONFIG_EPFS_DEBUG))
		if (count > (file_size - pos))
			epfs_debug(
				"count will be truncated to %llu, as file_size=%llu, pos=%llu",
				file_size - pos, file_size, pos);
	count = count <= (file_size - pos) ? count : (file_size - pos);

	// Skip ranges before pos.
	while ((range->range[current_range_index].end <= pos) &&
	       (current_range_index < range->num))
		current_range_index++;

	while (count > 0) {
		__u64 current_begin, current_end;

		if (current_range_index >= range->num) {
			// read directly when epfs range gone;
			if (IS_ENABLED(CONFIG_EPFS_DEBUG))
				epfs_debug(
					"read from %llu with len %lu at the end.",
					pos, count);
			ret = vfs_read(origin_file, buf, count, &pos);
			break;
		}
		current_begin = range->range[current_range_index].begin;
		current_end = range->range[current_range_index].end;
		if (current_begin <= pos) {
			// Clear user memory
			unsigned long clear_len = current_end - pos;

			clear_len = clear_len < count ? clear_len : count;
			if (IS_ENABLED(CONFIG_EPFS_DEBUG))
				epfs_debug(
					"clear user memory from %llu with len %lu",
					pos, clear_len);
			if (clear_user(buf, clear_len)) {
				ret = EFAULT;
				break;
			}
			buf += clear_len;
			pos += clear_len;
			count -= clear_len;
			current_range_index++;
		} else {
			// Read from pos to (next)current_begin
			unsigned long read_len = current_begin - pos;

			read_len = read_len < count ? read_len : count;
			if (IS_ENABLED(CONFIG_EPFS_DEBUG))
				epfs_debug(
					"read from %llu with len %lu",
					pos, read_len);
			ret = vfs_read(origin_file, buf, read_len, &pos);
			if (ret < 0 || ret < read_len) {
				// Could not read enough bytes;
				break;
			}
			buf += ret;
			count -= ret;
		}
	}

	if (ret >= 0) {
		ret = pos - *ppos;
		*ppos = pos;
	}
out_read:
	mutex_unlock(&info->lock);
	return ret;
}

const struct file_operations epfs_file_fops = {
	.unlocked_ioctl = epfs_unlocked_ioctl,
	.compat_ioctl = epfs_compat_ioctl,
	.read = epfs_read,
	.llseek = generic_file_llseek,
};
