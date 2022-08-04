// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
 */

#include <linux/blackbox.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/sched/debug.h>
#ifdef CONFIG_DFX_ZEROHUNG
#include <dfx/zrhung.h>
#endif
#include <linux/blackbox_common.h>
#include <linux/blackbox_storage.h>

/* ---- local macroes ---- */
/* bbox/BBOX - blackbox */
#define HISTORY_LOG_NAME		"history.log"
#define LOG_PART_WAIT_TIME		1000 /* unit: ms */
#define HISTORY_LOG_MAX_LEN		1024
#define TOP_CATEGORY_SYSTEM_RESET	"System Reset"
#define TOP_CATEGORY_FREEZE		"System Freeze"
#define TOP_CATEGORY_SYSTEM_POWEROFF	"POWEROFF"
#define TOP_CATEGORY_SUBSYSTEM_CRASH	"Subsystem Crash"

#ifndef CONFIG_BLACKBOX_LOG_ROOT_PATH
#error no blackbox log root path
#endif
#ifndef CONFIG_BLACKBOX_LOG_PART_REPRESENTATIVE
#error no representative of the blackbox log part
#endif

/* ---- local prototypes ---- */
struct bbox_ops {
	struct list_head list;
	struct module_ops ops;
};

struct error_info_to_category {
	const char *module;
	struct {
		const char *event;
		const char *category;
		const char *top_category;
	} map;
};

/* ---- local variables ---- */
static LIST_HEAD(ops_list);
static DEFINE_SPINLOCK(ops_list_lock);
static DEFINE_SEMAPHORE(temp_error_info_sem);
static struct error_info_to_category error_info_categories[] = {
	{
		MODULE_SYSTEM,
		{EVENT_SYSREBOOT, CATEGORY_SYSTEM_REBOOT, TOP_CATEGORY_SYSTEM_RESET}
	},
	{
		MODULE_SYSTEM,
		{EVENT_LONGPRESS, CATEGORY_SYSTEM_REBOOT, TOP_CATEGORY_SYSTEM_RESET}
	},
	{
		MODULE_SYSTEM,
		{EVENT_COMBINATIONKEY, CATEGORY_SYSTEM_REBOOT, TOP_CATEGORY_SYSTEM_RESET}
	},
	{
		MODULE_SYSTEM,
		{EVENT_SUBSYSREBOOT, CATEGORY_SYSTEM_REBOOT, TOP_CATEGORY_SYSTEM_RESET}
	},
	{
		MODULE_SYSTEM,
		{EVENT_POWEROFF, CATEGORY_SYSTEM_POWEROFF, TOP_CATEGORY_SYSTEM_POWEROFF}
	},
	{
		MODULE_SYSTEM,
		{EVENT_PANIC, CATEGORY_SYSTEM_PANIC, TOP_CATEGORY_SYSTEM_RESET}
	},
	{
		MODULE_SYSTEM,
		{EVENT_OOPS, CATEGORY_SYSTEM_OOPS, TOP_CATEGORY_SYSTEM_RESET}
	},
	{
		MODULE_SYSTEM,
		{EVENT_SYS_WATCHDOG, CATEGORY_SYSTEM_WATCHDOG, TOP_CATEGORY_FREEZE}
	},
	{
		MODULE_SYSTEM,
		{EVENT_HUNGTASK, CATEGORY_SYSTEM_HUNGTASK, TOP_CATEGORY_FREEZE}
	},
#ifdef CONFIG_BLACKBOX_EXPAND_EVENT
	#include <linux/blackbox_expand_event.h>
#endif
};

struct error_info *temp_error_info;

/* ---- local function prototypes ---- */
static const char *get_top_category(const char *module, const char *event);
static const char *get_category(const char *module, const char *event);
static void format_log_dir(char *buf, size_t buf_size, const char *log_root_dir,
			   const char *timestamp);
static void save_history_log(const char *log_root_dir, struct error_info *info,
			     const char *timestamp, int need_sys_reset);
#ifdef CONFIG_BLACKBOX_DEBUG
static void save_invalid_log(const struct bbox_ops *ops, const struct error_info *info);
#endif
static void wait_for_log_part(void);
static void format_error_info(struct error_info *info, const char event[EVENT_MAX_LEN],
			      const char module[MODULE_MAX_LEN],
			      const char error_desc[ERROR_DESC_MAX_LEN]);
static void save_last_log(void);
static int save_error_log(void *pparam);

/* ---- global function prototypes ---- */

/* ---- function definitions ---- */
static const char *get_top_category(const char *module, const char *event)
{
	int i;
	int count = (int)ARRAY_SIZE(error_info_categories);

	if (unlikely(!module || !event)) {
		bbox_print_err("module: %p, event: %p\n", module, event);
		return TOP_CATEGORY_SUBSYSTEM_CRASH;
	}

	for (i = 0; i < count; i++) {
		if (!strcmp(error_info_categories[i].module, module) &&
		    !strcmp(error_info_categories[i].map.event, event))
			return error_info_categories[i].map.top_category;
	}
	if (!strcmp(module, MODULE_SYSTEM))
		return TOP_CATEGORY_SYSTEM_RESET;

	return TOP_CATEGORY_SUBSYSTEM_CRASH;
}

static const char *get_category(const char *module, const char *event)
{
	int i;
	int count = (int)ARRAY_SIZE(error_info_categories);

	if (unlikely(!module || !event)) {
		bbox_print_err("module: %p, event: %p\n", module, event);
		return CATEGORY_SUBSYSTEM_CUSTOM;
	}

	for (i = 0; i < count; i++) {
		if (!strcmp(error_info_categories[i].module, module) &&
		    !strcmp(error_info_categories[i].map.event, event))
			return error_info_categories[i].map.category;
	}
	if (!strcmp(module, MODULE_SYSTEM))
		return CATEGORY_SYSTEM_CUSTOM;

	return CATEGORY_SUBSYSTEM_CUSTOM;
}

static void format_log_dir(char *buf, size_t buf_size, const char *log_root_dir,
			   const char *timestamp)
{
	if (unlikely(!buf || buf_size == 0 || !log_root_dir ||
				 !timestamp)) {
		bbox_print_err("buf: %p, buf_size: %u, log_root_dir: %p, timestamp: %p\n",
			       buf, (unsigned int)buf_size, log_root_dir, timestamp);
		return;
	}

	memset(buf, 0, buf_size);
	scnprintf(buf, buf_size - 1, "%s/%s", log_root_dir, timestamp);
}

static void format_error_info(struct error_info *info, const char event[EVENT_MAX_LEN],
			      const char module[MODULE_MAX_LEN],
			      const char error_desc[ERROR_DESC_MAX_LEN])
{
	if (unlikely(!info || !event || !module || !error_desc)) {
		bbox_print_err("info: %p, event: %p, module: %p, error_desc: %p\n",
				info, event, module, error_desc);
		return;
	}

	memset(info, 0, sizeof(*info));
	strncpy(info->event, event, min(strlen(event),
				sizeof(info->event) - 1));
	strncpy(info->module, module, min(strlen(module),
				sizeof(info->module) - 1));
	strncpy(info->category, get_category(module, event),
				min(strlen(get_category(module, event)), sizeof(info->category) - 1));
	get_timestamp(info->error_time, TIMESTAMP_MAX_LEN);
	strncpy(info->error_desc, error_desc, min(strlen(error_desc),
				sizeof(info->error_desc) - 1));
}

static void save_history_log(const char *log_root_dir, struct error_info *info,
			     const char *timestamp, int need_sys_reset)
{
	char history_log_path[PATH_MAX_LEN];
	char *buf;

	if (unlikely(!log_root_dir || !info || !timestamp)) {
		bbox_print_err("log_root_dir: %p, info: %p, timestamp: %p\n",
				log_root_dir, info, timestamp);
		return;
	}

	buf = kmalloc(HISTORY_LOG_MAX_LEN + 1, GFP_KERNEL);
	if (!buf)
		return;
	memset(buf, 0, HISTORY_LOG_MAX_LEN + 1);

	scnprintf(buf, HISTORY_LOG_MAX_LEN, HISTORY_LOG_FORMAT,
			get_top_category(info->module, info->event), info->module,
			info->category, info->event, timestamp,
			need_sys_reset ? "true" : "false", info->error_desc, log_root_dir);
#ifdef CONFIG_DFX_ZEROHUNG
	zrhung_send_event("KERNEL_VENDOR", info->category, info->error_desc);
#endif
	memset(history_log_path, 0, sizeof(history_log_path));
	scnprintf(history_log_path, sizeof(history_log_path) - 1,
			"%s/%s", log_root_dir, HISTORY_LOG_NAME);
	full_write_file(history_log_path, buf, strlen(buf), 1);
	ksys_sync();
	kfree(buf);
}

#ifdef CONFIG_BLACKBOX_DEBUG
static void save_invalid_log(const struct bbox_ops *ops, const struct error_info *info)
{
	char invalid_log_path[PATH_MAX_LEN];
	char timestamp[TIMESTAMP_MAX_LEN];

	if (unlikely(!ops || !info)) {
		bbox_print_err("ops: %p, info: %p\n", ops, info);
		return;
	}

	get_timestamp(timestamp, sizeof(timestamp));
	format_log_dir(invalid_log_path, PATH_MAX_LEN, CONFIG_BLACKBOX_LOG_PART_REPRESENTATIVE,
		       timestamp);
	create_log_dir(invalid_log_path);
	if (ops->ops.save_last_log(invalid_log_path, (struct error_info *)info) != 0)
		bbox_print_err("[%s] failed to save invalid log!\n", ops->ops.module);
}
#endif

static bool is_log_part_mounted(void)
{
	return file_exists(CONFIG_BLACKBOX_LOG_PART_REPRESENTATIVE) == 0;
}

static void wait_for_log_part(void)
{
	bbox_print_info("wait for log part [%s] begin!\n",
			CONFIG_BLACKBOX_LOG_PART_REPRESENTATIVE);
	while (!is_log_part_mounted())
		msleep(LOG_PART_WAIT_TIME);

	bbox_print_info("wait for log part [%s] end!\n",
			CONFIG_BLACKBOX_LOG_PART_REPRESENTATIVE);
}

static bool find_module_ops(struct error_info *info, struct bbox_ops **ops)
{
	struct bbox_ops *cur = NULL;
	bool find_module = false;

	if (unlikely(!info || !ops)) {
		bbox_print_err("info: %p, ops: %p!\n", info, ops);
		return find_module;
	}

	list_for_each_entry(cur, &ops_list, list) {
		if (!strcmp(cur->ops.module, info->module)) {
			*ops = cur;
			find_module = true;
			break;
		}
	}
	if (!find_module)
		bbox_print_err("[%s] hasn't been registered!\n", info->module);

	return find_module;
}

static void invoke_module_ops(const char *log_dir, struct error_info *info,
					struct bbox_ops *ops)
{
	if (unlikely(!info || !ops)) {
		bbox_print_err("info: %p, ops: %p!\n", info, ops);
		return;
	}

	if (ops->ops.dump && log_dir) {
		bbox_print_info("[%s] starts dumping data!\n", ops->ops.module);
		ops->ops.dump(log_dir, info);
		bbox_print_info("[%s] ends dumping data!\n", ops->ops.module);
	}
	if (ops->ops.reset) {
		bbox_print_info("[%s] starts resetting!\n", ops->ops.module);
		ops->ops.reset(info);
		bbox_print_info("[%s] ends resetting!\n", ops->ops.module);
	}
}

static void save_log_without_reset(struct error_info *info)
{
	unsigned long flags;
	struct bbox_ops *ops = NULL;
	char *log_dir = NULL;
	char timestamp[TIMESTAMP_MAX_LEN];

	if (unlikely(!info)) {
		bbox_print_err("info: %p!\n", info);
		return;
	}

	/* get timestamp */
	get_timestamp(timestamp, sizeof(timestamp));

	/* get bbox ops */
	spin_lock_irqsave(&ops_list_lock, flags);
	if (!find_module_ops(info, &ops)) {
		spin_unlock_irqrestore(&ops_list_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&ops_list_lock, flags);
	create_log_dir(CONFIG_BLACKBOX_LOG_ROOT_PATH);
	if (ops->ops.dump) {
		/* create log root path */
		log_dir = kmalloc(PATH_MAX_LEN, GFP_KERNEL);
		if (log_dir) {
			format_log_dir(log_dir, PATH_MAX_LEN,
						CONFIG_BLACKBOX_LOG_ROOT_PATH, timestamp);
			create_log_dir(log_dir);
		} else
			bbox_print_err("kmalloc failed!\n");
	}
	invoke_module_ops(log_dir, info, ops);
	save_history_log(CONFIG_BLACKBOX_LOG_ROOT_PATH, info, timestamp, 0);
	kfree(log_dir);
}

static void save_log_with_reset(struct error_info *info)
{
	struct bbox_ops *ops = NULL;

	if (unlikely(!info)) {
		bbox_print_err("info: %p!\n", info);
		return;
	}

	if (!find_module_ops(info, &ops))
		return;

	invoke_module_ops("", info, ops);
	if (strcmp(info->category, CATEGORY_SYSTEM_REBOOT) &&
		strcmp(info->category, CATEGORY_SYSTEM_PANIC))
		sys_reset();
}

static void save_temp_error_info(const char event[EVENT_MAX_LEN],
				const char module[MODULE_MAX_LEN],
				const char error_desc[ERROR_DESC_MAX_LEN])
{
	if (unlikely(!event || !module || !error_desc)) {
		bbox_print_err("event: %p, module: %p, error_desc: %p\n",
					event, module, error_desc);
		return;
	}

	down(&temp_error_info_sem);
	format_error_info(temp_error_info, event, module, error_desc);
	up(&temp_error_info_sem);
}

static void do_save_last_log(const struct bbox_ops *ops, struct error_info *info)
{
	char *log_dir = NULL;
	int ret;

	if (unlikely(!ops || !info)) {
		bbox_print_err("ops: %p, info: %p\n",
					ops, info);
		return;
	}

	memset((void *)info, 0, sizeof(*info));
	ret = ops->ops.get_last_log_info((struct error_info *)info);
	if (ret) {
		bbox_print_err("[%s] failed to get log info!\n", ops->ops.module);
#ifdef CONFIG_BLACKBOX_DEBUG
		if (ret == -ENOMSG)
			save_invalid_log(ops, info);
#endif
		return;
	}

	strncpy(info->category, get_category(info->module, info->event),
	       min(strlen(get_category(info->module, info->event)), sizeof(info->category) - 1));

	bbox_print_info("[%s] starts saving log!\n", ops->ops.module);
	bbox_print_info("event: [%s] module: [%s], time is [%s]!\n",
			info->event, info->module, info->error_time);

	log_dir = kmalloc(PATH_MAX_LEN, GFP_KERNEL);
	if (!log_dir)
		return;

	if (!strlen(info->error_time))
		get_timestamp((char *)info->error_time, TIMESTAMP_MAX_LEN);

	format_log_dir(log_dir, PATH_MAX_LEN, CONFIG_BLACKBOX_LOG_ROOT_PATH,
				   info->error_time);
	create_log_dir(log_dir);
	if (ops->ops.save_last_log(log_dir, (struct error_info *)info) == 0)
		save_history_log(CONFIG_BLACKBOX_LOG_ROOT_PATH,
					(struct error_info *)info, info->error_time, 1);
	else
		bbox_print_err("[%s] failed to save log!\n", ops->ops.module);
	kfree(log_dir);
}

static void save_last_log(void)
{
	unsigned long flags;
	struct error_info *info = NULL;
	struct bbox_ops *ops = NULL;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return;

	spin_lock_irqsave(&ops_list_lock, flags);
	list_for_each_entry(ops, &ops_list, list) {
		if (ops->ops.get_last_log_info &&
			ops->ops.save_last_log) {
			spin_unlock_irqrestore(&ops_list_lock, flags);
			do_save_last_log(ops, info);
			spin_lock_irqsave(&ops_list_lock, flags);
		} else {
			bbox_print_err("[%s] get_last_log_info: %p, %s: %p\n",
						ops->ops.module, ops->ops.get_last_log_info,
						__func__, ops->ops.save_last_log);
		}
	}
	spin_unlock_irqrestore(&ops_list_lock, flags);
	kfree(info);
}

static void save_temp_error_log(void)
{
	down(&temp_error_info_sem);
	if (!temp_error_info) {
		bbox_print_err("temp_error_info: %p\n", temp_error_info);
		up(&temp_error_info_sem);
		return;
	}

	if (strlen(temp_error_info->event) != 0)
		save_log_without_reset(temp_error_info);

	kfree(temp_error_info);
	temp_error_info = NULL;
	up(&temp_error_info_sem);
}

static int save_error_log(void *pparam)
{
	wait_for_log_part();
	save_last_log();
	save_temp_error_log();

	return 0;
}

int bbox_register_module_ops(struct module_ops *ops)
{
	struct bbox_ops *new_ops = NULL;
	struct bbox_ops *temp = NULL;
	unsigned long flags;

	if (unlikely(!ops)) {
		bbox_print_err("ops: %p\n", ops);
		return -EINVAL;
	}

	new_ops = kmalloc(sizeof(*new_ops), GFP_KERNEL);
	if (!new_ops)
		return -ENOMEM;
	memset(new_ops, 0, sizeof(*new_ops));
	memcpy(&new_ops->ops, ops, sizeof(*ops));
	spin_lock_irqsave(&ops_list_lock, flags);
	if (list_empty(&ops_list))
		goto __out;

	list_for_each_entry(temp, &ops_list, list) {
		if (!strcmp(temp->ops.module, ops->module)) {
			spin_unlock_irqrestore(&ops_list_lock, flags);
			kfree(new_ops);
			bbox_print_info("[%s] has been registered!\n", temp->ops.module);
			return -ENODATA;
		}
	}

__out:
	bbox_print_info("[%s] is registered successfully!\n", ops->module);
	list_add_tail(&new_ops->list, &ops_list);
	spin_unlock_irqrestore(&ops_list_lock, flags);

	return 0;
}

int bbox_notify_error(const char event[EVENT_MAX_LEN], const char module[MODULE_MAX_LEN],
				const char error_desc[ERROR_DESC_MAX_LEN], int need_sys_reset)
{
	struct error_info *info = NULL;

	if (unlikely(!event || !module || !error_desc)) {
		bbox_print_err("event: %p, module: %p, error_desc: %p\n", event,
				module, error_desc);
		return -EINVAL;
	}

	info = kmalloc(sizeof(*info), GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	format_error_info(info, event, module, error_desc);
	show_stack(current, NULL, KERN_DEFAULT);
	if (!need_sys_reset) {
		/* handle the error which do not need reset */
		if (!is_log_part_mounted())
			save_temp_error_info(event, module, error_desc);
		else
			save_log_without_reset(info);
	} else {
		/* handle the error which need reset */
		save_log_with_reset(info);
	}

	kfree(info);

	return 0;
}

static void __init select_storage_material(void)
{
	const struct reboot_crashlog_storage *tmp = NULL;

	if (!storage_material)
		return;

	for (tmp = storage_lastwords; tmp->material; tmp++) {
		if (!strcmp(storage_material, tmp->material)) {
			storage_lastword = tmp;
			return;
		}
	}
}

static int __init blackbox_core_init(void)
{
	struct task_struct *tsk = NULL;

	select_storage_material();

	temp_error_info = kmalloc(sizeof(*temp_error_info), GFP_KERNEL);
	if (!temp_error_info)
		return -ENOMEM;

	memset(temp_error_info, 0, sizeof(*temp_error_info));

	/* Create a kernel thread to save log */
	tsk = kthread_run(save_error_log, NULL, "save_error_log");
	if (IS_ERR(tsk)) {
		kfree(temp_error_info);
		temp_error_info = NULL;
		bbox_print_err("kthread_run failed!\n");
		return -ESRCH;
	}

	return 0;
}

core_initcall(blackbox_core_init);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Blackbox core framework");
MODULE_AUTHOR("OHOS");
