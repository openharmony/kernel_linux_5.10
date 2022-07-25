/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef BLACKBOX_H
#define BLACKBOX_H

#include <linux/printk.h>
#include <linux/time.h>

#define PATH_MAX_LEN         256
#define EVENT_MAX_LEN        32
#define CATEGORY_MAX_LEN     32
#define MODULE_MAX_LEN       32
#define TIMESTAMP_MAX_LEN    24
#define ERROR_DESC_MAX_LEN   512
#define LOG_FLAG             "VALIDLOG"

/* module type */
#define MODULE_SYSTEM        "SYSTEM"

/* fault category type */
#define CATEGORY_SYSTEM_REBOOT         "SYSREBOOT"
#define CATEGORY_SYSTEM_POWEROFF       "POWEROFF"
#define CATEGORY_SYSTEM_PANIC          "PANIC"
#define CATEGORY_SYSTEM_OOPS           "OOPS"
#define CATEGORY_SYSTEM_CUSTOM         "CUSTOM"
#define CATEGORY_SYSTEM_WATCHDOG       "HWWATCHDOG"
#define CATEGORY_SYSTEM_HUNGTASK       "HUNGTASK"
#define CATEGORY_SUBSYSTEM_CUSTOM      "CUSTOM"

/* fault event type */
#define EVENT_SYSREBOOT      "SYSREBOOT"
#define EVENT_LONGPRESS      "LONGPRESS"
#define EVENT_COMBINATIONKEY "COMBINATIONKEY"
#define EVENT_SUBSYSREBOOT   "SUBSYSREBOOT"
#define EVENT_POWEROFF       "POWEROFF"
#define EVENT_PANIC          "PANIC"
#define EVENT_OOPS           "OOPS"
#define EVENT_SYS_WATCHDOG   "SYSWATCHDOG"
#define EVENT_HUNGTASK       "HUNGTASK"
#define EVENT_BOOTFAIL       "BOOTFAIL"

#define FILE_NAME(x) (strrchr(x, '/') ? (strrchr(x, '/') + 1) : x)
#define BBOX_DECORATOR_HILOG(level, fmt, args...)  \
	pr_err("bbox:[%s][%s:%d] " fmt, level, FILE_NAME(__FILE__), __LINE__, ##args)

#define bbox_print_fatal(fmt, args...) BBOX_DECORATOR_HILOG("fatal", fmt, ##args)
#define bbox_print_err(fmt, args...) BBOX_DECORATOR_HILOG("err", fmt, ##args)
#define bbox_print_warn(fmt, args...) BBOX_DECORATOR_HILOG("warn", fmt, ##args)
#define bbox_print_info(fmt, args...) BBOX_DECORATOR_HILOG("info", fmt, ##args)
#define bbox_print_debug(fmt, args...) BBOX_DECORATOR_HILOG("debug", fmt, ##args)

struct error_info {
	char event[EVENT_MAX_LEN];
	char category[CATEGORY_MAX_LEN];
	char module[MODULE_MAX_LEN];
	char error_time[TIMESTAMP_MAX_LEN];
	char error_desc[ERROR_DESC_MAX_LEN];
};

struct fault_log_info {
	char flag[8]; /* 8 is the length of the flag */
	size_t len; /* length of the kernel fault log */
	struct error_info info;
};

struct module_ops {
	char module[MODULE_MAX_LEN];
	void (*dump)(const char *log_dir, struct error_info *info);
	void (*reset)(struct error_info *info);
	int (*get_last_log_info)(struct error_info *info);
	int (*save_last_log)(const char *log_dir, struct error_info *info);
};

void get_timestamp(char *buf, size_t buf_size);
int bbox_register_module_ops(struct module_ops *ops);
int bbox_notify_error(const char event[EVENT_MAX_LEN],
		const char module[MODULE_MAX_LEN],
		const char error_desc[ERROR_DESC_MAX_LEN],
		int need_sys_reset);

#endif /* BLACKBOX_H */
