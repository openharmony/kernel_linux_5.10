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
#define MODULE_MAX_LEN       32
#define TIMESTAMP_MAX_LEN    24
#define ERROR_DESC_MAX_LEN   512
#define LOG_FLAG             "VALIDLOG"

/* module type */
#define MODULE_SYSTEM        "SYSTEM"

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

#define bbox_print_err(format, ...)  \
	pr_err("bbox: func: %s, line: %d, err: " \
	format, __func__, __LINE__, ##__VA_ARGS__)
#define bbox_print_info(format, ...)  \
	pr_err("bbox: info: " format,  ##__VA_ARGS__)

struct error_info {
	char event[EVENT_MAX_LEN];
	char module[MODULE_MAX_LEN];
	char error_time[TIMESTAMP_MAX_LEN];
	char error_desc[ERROR_DESC_MAX_LEN];
};

struct fault_log_info {
	char flag[8];  /* 8 is the length of the flag */
	int len;  /* length of the kernel fault log */
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
