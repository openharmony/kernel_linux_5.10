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
#include <linux/vmalloc.h>
#include <linux/blackbox_common.h>

void sys_reset(void)
{
	bbox_print_info("reset the system now!\n");
	emergency_restart();
	bbox_print_info("reset the system failed!\n");
}

void change_own_mode(char *path, int uid, int gid, int mode)
{
	mm_segment_t old_fs;
	int ret = -1;

	if (unlikely(!path || uid == -1 || gid == -1)) {
		bbox_print_err("path or uid or gid error.\n");
		return;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = sys_chown(path, uid, gid);
	if (ret != 0) {
		bbox_print_err("sys_chown [%s] failed, ret: %d\n", path, ret);
		goto __out;
	}

	ret = sys_chmod(path, mode);
	if (ret != 0) {
		bbox_print_err("sys_chmod [%s] failed, ret: %d\n", path, ret);
		goto __out;
	}

__out:
	set_fs(old_fs);
}

int full_write_file(const char *pfile_path, char *buf,
		size_t buf_size, bool is_append)
{
	mm_segment_t old_fs;
	long total_to_write = (long)buf_size;
	long total_write = 0;
	long write_this_time;
	char *ptemp = buf;
	int fd = -1;

	if (unlikely(!pfile_path || !buf)) {
		bbox_print_err("fd or buf is NULL!\n");
		return -EINVAL;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = sys_open(pfile_path, O_CREAT | O_RDWR |
		(is_append ? O_APPEND : O_TRUNC), 0);
	if (fd < 0) {
		bbox_print_err("Create file [%s] failed! ret: %d\n", pfile_path, fd);
		goto __out;
	}

	while (total_to_write > 0) {
		write_this_time = ksys_write(fd, ptemp, total_to_write);
		if (write_this_time < 0) {
			bbox_print_err("%s\n", "Failed to write file!\n");
			break;
		}
		ptemp += write_this_time;
		total_to_write -= write_this_time;
		total_write += write_this_time;
	}

__out:
	if (fd >= 0) {
		ksys_sync();
		ksys_close(fd);
	}
	set_fs(old_fs);

	return total_write == (long)buf_size ? 0 : -1;
}

static int create_new_dir(char *path)
{
	int ret;
	mm_segment_t old_fs;

	if (unlikely(!path)) {
		bbox_print_err("path is NULL!\n");
		return -EINVAL;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = sys_access(path, 0);
	if (ret != 0) {
		ret = sys_mkdir(path, BBOX_DIR_LIMIT);
		if (ret < 0) {
			bbox_print_err("Create dir [%s] failed! ret: %d\n", path, ret);
			set_fs(old_fs);
			return -EINVAL;
		}
		change_own_mode(path, AID_ROOT, AID_SYSTEM, BBOX_DIR_LIMIT);
	}
	set_fs(old_fs);

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
	cur_path = vmalloc(PATH_MAX_LEN + 1);
	if (!cur_path) {
		bbox_print_err("vmalloc failed!\n");
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
	vfree(cur_path);

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

unsigned long long get_ticks(void)
{
	/* use only one int value to save time: */

	struct timespec64 uptime;

	ktime_get_ts64(&uptime);

	ktime_get_boottime_ts64(&uptime);

	return (u64)uptime.tv_sec;
}
