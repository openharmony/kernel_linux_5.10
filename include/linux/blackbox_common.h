/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef BLACKBOX_COMMON_H
#define BLACKBOX_COMMON_H

#include <linux/types.h>

/* bbox/BBOX - blackbox */
#define YEAR_BASE            1900
#define SECONDS_PER_MINUTE   60
#define AID_ROOT             0
#define AID_SYSTEM           1000
#define BBOX_DIR_LIMIT       0775
#define BBOX_FILE_LIMIT      0664
#define PATH_MAX_LEN         256

/*
 * format:
 * [topCategoryName],module[moduleName],category[categoryName],\
 * event[eventName],time[seconds from 1970-01-01 00:00:00 UTC-tick],\
 * sysreboot[true|false],errordesc[errorDescription],logpath[logpath]\n
 */
#define HISTORY_LOG_FORMAT "[%s],module[%s],category[%s],event[%s],"\
	"time[%s],sysreboot[%s],errdesc[%s],logpath[%s]\n"
#define TIMESTAMP_FORMAT "%04d%02d%02d%02d%02d%02d-%08llu"

void sys_reset(void);
void change_own(char *path, int uid, int gid);
int full_write_file(const char *pfile_path, char *buf,
		size_t buf_size, bool read_file);
int file_exists(const char *name);
int create_log_dir(const char *path);
unsigned long long get_ticks(void);
struct file *file_open(const char *filename, int open_mode, int mode);
void file_close(struct file *filp);
ssize_t file_read(struct file *file, loff_t offset, unsigned char *data,
				  size_t size);
int file_delete(struct file *filp);
char *getfullpath(struct file *filp);

#endif /* BLACKBOX_COMMON_H */
