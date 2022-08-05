// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
 */

#include <linux/blackbox.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/syscalls.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/blackbox_common.h>

void sys_reset(void)
{
	bbox_print_info("reset the system now!\n");
	emergency_restart();
	bbox_print_info("reset the system failed!\n");
}

void change_own(char *path, int uid, int gid)
{
	mm_segment_t old_fs;
	int ret = -1;

	if (unlikely(!path || uid == -1 || gid == -1)) {
		bbox_print_err("path or uid or gid error.\n");
		return;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = ksys_chown(path, uid, gid);
	if (ret != 0)
		bbox_print_err("ksys_chown [%s] failed, ret: %d\n", path, ret);

	set_fs(old_fs);
}

int full_write_file(const char *pfile_path, char *buf,
		size_t buf_size, bool is_append)
{
	struct file *filp = NULL;
	char *pathname = NULL;
	mm_segment_t old_fs;
	loff_t pos = 0;
	int ret = -1;

	if (unlikely(!pfile_path || !buf)) {
		bbox_print_err("pfile_path or buf is NULL!\n");
		return -EINVAL;
	}

	filp = file_open(pfile_path, O_CREAT | O_RDWR |
			(is_append ? O_APPEND : O_TRUNC), BBOX_FILE_LIMIT);
	if (IS_ERR(filp)) {
		bbox_print_err("open %s failed! [%ld]\n", pfile_path, PTR_ERR(filp));
		return -EBADF;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	ret = vfs_write(filp, buf, buf_size, &pos);

	set_fs(old_fs);

	file_close(filp);

	if (ret < 0) {
		pathname = getfullpath(filp);
		bbox_print_err("write [%s] failed! [%d]\n", pathname ? pathname : "", ret);
		return ret;
	}

	return 0;
}

int file_exists(const char *name)
{
	struct path path;
	int ret;

	ret = kern_path(name, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;

	ret = inode_permission(d_inode(path.dentry), MAY_ACCESS);
	path_put(&path);
	return ret;
}

static int create_new_dir(char *name)
{
	struct dentry *dentry;
	struct path path;
	int ret;

	if (unlikely(!name)) {
		bbox_print_err("name is NULL!\n");
		return -EINVAL;
	}

	ret = file_exists(name);
	if (ret) {
		dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
		if (IS_ERR(dentry))
			return PTR_ERR(dentry);

		ret = vfs_mkdir(d_inode(path.dentry), dentry, BBOX_DIR_LIMIT);
		if (ret && ret != -EEXIST)
			bbox_print_err("Create dir [%s] failed! ret: %d\n", name, ret);

		done_path_create(&path, dentry);
	}

	return 0;
}

int create_log_dir(const char *path)
{
	char *cur_path = NULL;
	int index = 0;

	if (unlikely(!path)) {
		bbox_print_err("path is NULL!\n");
		return -EINVAL;
	}

	if (*path != '/')
		return -EINVAL;
	cur_path = kmalloc(PATH_MAX_LEN + 1, GFP_KERNEL);
	if (unlikely(!cur_path)) {
		bbox_print_err("kmalloc failed!\n");
		return -ENOMEM;
	}
	memset(cur_path, 0, PATH_MAX_LEN + 1);
	cur_path[index++] = *path++;
	while (*path != '\0') {
		if (*path == '/')
			create_new_dir(cur_path);
		cur_path[index] = *path;
		path++;
		index++;
	}
	create_new_dir(cur_path);
	kfree(cur_path);

	return 0;
}

void get_timestamp(char *buf, size_t buf_size)
{
	struct rtc_time tm;
	struct timespec64 tv;

	if (unlikely(!buf || buf_size == 0)) {
		bbox_print_err("buf: %p, buf_size: %u\n", buf, (unsigned int)buf_size);
		return;
	}

	memset(buf, 0, buf_size);
	memset(&tm, 0, sizeof(tm));

	memset(&tv, 0, sizeof(tv));
	ktime_get_real_ts64(&tv);
	tv.tv_sec -= (long)sys_tz.tz_minuteswest * SECONDS_PER_MINUTE;
	rtc_time64_to_tm(tv.tv_sec, &tm);

	(void)scnprintf(buf, buf_size, TIMESTAMP_FORMAT,
			tm.tm_year + YEAR_BASE, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec, get_ticks());
	buf[buf_size - 1] = '\0';
}
EXPORT_SYMBOL_GPL(get_timestamp);

unsigned long long get_ticks(void)
{
	/* use only one int value to save time: */

	struct timespec64 uptime;

	ktime_get_ts64(&uptime);

	ktime_get_boottime_ts64(&uptime);

	return (u64)uptime.tv_sec;
}

static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dentry)
{
	inode_unlock(d_inode(dentry));
	dput(dentry);
}

struct file *file_open(const char *filename, int open_mode, int mode)
{
	struct file *filp = NULL;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	filp = filp_open(filename, open_mode, mode);
	set_fs(old_fs);

	return filp;
}

void file_close(struct file *filp)
{
	if (likely(filp))
		filp_close(filp, NULL);
}

int file_delete(struct file *filp)
{
	struct dentry *dentry = NULL;
	struct dentry *parent = NULL;
	int ret = 0;

	if (unlikely(!filp)) {
		bbox_print_err("file is NULL!\n");
		return -EINVAL;
	}

	dentry = file_dentry(filp);
	parent = lock_parent(dentry);

	if (dentry->d_parent == parent) {
		dget(dentry);
		ret = vfs_unlink(d_inode(parent), dentry, NULL);
		dput(dentry);
	}

	unlock_dir(parent);

	return ret;
}

char *getfullpath(struct file *filp)
{
	char *buf = NULL, *path = NULL;

	if (unlikely(!filp))
		return NULL;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!buf))
		return NULL;
	memset(buf, 0, PATH_MAX);

	// get the path
	path = d_path(&filp->f_path, buf, PATH_MAX);

	kfree(buf);

	return path;
}
