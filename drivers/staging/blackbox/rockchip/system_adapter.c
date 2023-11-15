// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
 */

#include <asm/cacheflush.h>
#include <linux/blackbox.h>
#include <linux/kmsg_dump.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/reboot.h>
#include <linux/ctype.h>
#include <linux/blackbox_common.h>
#include <linux/blackbox_storage.h>

/* ---- local macroes ---- */
#define BOOTLOADER_LOG_NAME       "fastboot_log"
#define KERNEL_LOG_NAME           "last_kmsg"
#define SIZE_1K                   1024
#define KERNEL_LOG_MAX_SIZE               \
	round_up((0x80000 + sizeof(struct fault_log_info)), SIZE_1K)
#define CALLSTACK_MAX_ENTRIES     20

/* ---- local prototypes ---- */

/* ---- local function prototypes ---- */
static int save_kmsg_from_buffer(const char *log_dir,
				 const char *file_name, int clean_buf);
static void dump(const char *log_dir, struct error_info *info);
static void reset(struct error_info *info);
static int get_last_log_info(struct error_info *info);
static int save_last_log(const char *log_dir, struct error_info *info);
static int bbox_reboot_notify(struct notifier_block *nb,
					unsigned long code, void *unused);
static int bbox_task_panic(struct notifier_block *this,
					unsigned long event, void *ptr);

/* ---- local variables ---- */
static char *kernel_log;
static DEFINE_SEMAPHORE(kmsg_sem);
static struct notifier_block bbox_reboot_nb = {
	.notifier_call = bbox_reboot_notify,
};

static struct notifier_block bbox_panic_block = {
	.notifier_call = bbox_task_panic,
};

/* ---- function definitions ---- */
static void dump_stacktrace(char *pbuf, size_t buf_size, bool is_panic)
{
	int i;
	size_t stack_len = 0;
	size_t com_len = 0;
	unsigned long entries[CALLSTACK_MAX_ENTRIES];
	unsigned int nr_entries;
	char tmp_buf[ERROR_DESC_MAX_LEN];
	bool find_panic = false;

	if (unlikely(!pbuf || !buf_size))
		return;

	memset(pbuf, 0, buf_size);
	memset(tmp_buf, 0, sizeof(tmp_buf));
	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
	com_len = scnprintf(pbuf, buf_size, "Comm:%s,CPU:%d,Stack:",
						current->comm, raw_smp_processor_id());
	for (i = 0; i < nr_entries; i++) {
		if (stack_len >= sizeof(tmp_buf)) {
			tmp_buf[sizeof(tmp_buf) - 1] = '\0';
			break;
		}
		stack_len += scnprintf(tmp_buf + stack_len, sizeof(tmp_buf) - stack_len,
				"%pS-", (void *)entries[i]);
		if (!find_panic && is_panic) {
			if (strncmp(tmp_buf, "panic", strlen("panic")) == 0)
				find_panic = true;
			else
				(void)memset(tmp_buf, 0, sizeof(tmp_buf));
		}
	}
	if (com_len >= buf_size)
		return;
	stack_len = min(buf_size - com_len, strlen(tmp_buf));
	memcpy(pbuf + com_len, tmp_buf, stack_len);
	*(pbuf + buf_size - 1) = '\0';
}

static int save_kmsg_from_buffer(const char *log_dir,
				const char *file_name, int clean_buf)
{
	int ret = -1;
	char path[PATH_MAX_LEN];
	struct fault_log_info *pinfo = NULL;

	if (unlikely(!log_dir || !file_name)) {
		bbox_print_err("log_dir: %p, file_name: %p!\n", log_dir, file_name);
		return -EINVAL;
	}

	memset(path, 0, sizeof(path));
	(void)scnprintf(path, sizeof(path) - 1, "%s/%s", log_dir, file_name);
	down(&kmsg_sem);
	if (kernel_log) {
		pinfo = (struct fault_log_info *)kernel_log;
		ret = full_write_file(path, kernel_log + sizeof(*pinfo),
					min(KERNEL_LOG_MAX_SIZE - sizeof(*pinfo),
						(size_t)pinfo->len), 0);
		if (clean_buf)
			memset(kernel_log, 0, KERNEL_LOG_MAX_SIZE);
	} else {
		bbox_print_err("kernel_log: %p!\n", kernel_log);
	}
	up(&kmsg_sem);

	return ret;
}

static void dump(const char *log_dir, struct error_info *info)
{
	if (unlikely(!log_dir || !info)) {
		bbox_print_err("log_dir: %p, info: %p!\n", log_dir, info);
		return;
	}

	if (!strcmp(info->category, CATEGORY_SYSTEM_PANIC) ||
		!strcmp(info->category, CATEGORY_SYSTEM_REBOOT) ||
		!strcmp(info->category, CATEGORY_SYSTEM_POWEROFF)) {
		struct fault_log_info *pinfo = (struct fault_log_info *)kernel_log;

		if (down_trylock(&kmsg_sem) != 0) {
			bbox_print_err("down_trylock failed!\n");
			return;
		}

		if (kernel_log) {
			memcpy(pinfo->flag, LOG_FLAG, strlen(LOG_FLAG));
			memcpy(&pinfo->info, info, sizeof(*info));

#if  __BITS_PER_LONG == 64
			__flush_dcache_area(kernel_log, KERNEL_LOG_MAX_SIZE);
#else
			__cpuc_flush_dcache_area(kernel_log, KERNEL_LOG_MAX_SIZE);
#endif
		}

		up(&kmsg_sem);
	} else {
		bbox_print_info("module [%s] starts saving log for event [%s]!\n",
				info->module, info->event);
		save_kmsg_from_buffer(log_dir, KERNEL_LOG_NAME, 0);
		bbox_print_info("module [%s] ends saving log for event [%s]!\n",
				info->module, info->event);
	}
}

static void reset(struct error_info *info)
{
	if (unlikely(!info)) {
		bbox_print_err("info: %p!\n", info);
		return;
	}

	if (!strcmp(info->category, CATEGORY_SYSTEM_PANIC))
		emergency_restart();
}

static int get_last_log_info(struct error_info *info)
{
	struct fault_log_info *pinfo = (struct fault_log_info *)kernel_log;
	int log_size = KERNEL_LOG_MAX_SIZE;
	unsigned int i = 0;

	if (unlikely(!info || !kernel_log))
		return -EINVAL;

	if (storage_lastword->get_log((void *)kernel_log, log_size) < 0) {
		bbox_print_err("Get last log from strorage failed!\n");
		return -ENOENT;
	}

	down(&kmsg_sem);
	if (!memcmp(pinfo->flag, LOG_FLAG, strlen(LOG_FLAG))) {
		memcpy(info, &pinfo->info, sizeof(*info));
		for (i = 0; i < strlen((*info).event); i++)
			(*info).event[i] = toupper((*info).event[i]);

		if (strncmp((*info).module, "PSTORE", strlen("PSTORE")) == 0)
			memcpy((*info).module, MODULE_SYSTEM, sizeof((*info).module));

		up(&kmsg_sem);
		return 0;
	}
	up(&kmsg_sem);
	bbox_print_info("There's no valid fault log!\n");

	return -ENOMSG;
}

static int save_last_log(const char *log_dir, struct error_info *info)
{
	int ret = -1;

	if (unlikely(!log_dir || !info)) {
		bbox_print_err("log_dir: %p, info: %p!\n", log_dir, info);
		return -EINVAL;
	}

	ret = save_kmsg_from_buffer(log_dir, KERNEL_LOG_NAME, 1);
	bbox_print_info("save last fault log %s!\n",
			ret ? "failed" : "successfully");

	return ret;
}

static int bbox_reboot_notify(struct notifier_block *nb,
					unsigned long code, void *unused)
{
	char error_desc[ERROR_DESC_MAX_LEN];

	/* notify blackbox to do dump */
	memset(error_desc, 0, sizeof(error_desc));
	dump_stacktrace(error_desc, sizeof(error_desc), false);
	kmsg_dump(KMSG_DUMP_UNDEF);

	switch (code) {
	case SYS_RESTART:
		bbox_notify_error(EVENT_SYSREBOOT, MODULE_SYSTEM, error_desc, 1);
		break;
	case SYS_POWER_OFF:
		bbox_notify_error(EVENT_POWEROFF, MODULE_SYSTEM, error_desc, 0);
		break;
	default:
		bbox_print_err("Invalid event code: %lu!\n", code);
		break;
	}

	return NOTIFY_DONE;
}

static int bbox_task_panic(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	char error_desc[ERROR_DESC_MAX_LEN];

	/* notify blackbox to do dump */
	kmsg_dump(KMSG_DUMP_PANIC);
	memset(error_desc, 0, sizeof(error_desc));
	bbox_notify_error(EVENT_PANIC, MODULE_SYSTEM, error_desc, 1);

	return NOTIFY_DONE;
}

static int __init blackbox_init(void)
{
	int ret = -1;
	struct kmsg_dumper *dumper = NULL;
	struct module_ops ops = {
		.module = MODULE_SYSTEM,
		.dump = dump,
		.reset = reset,
		.get_last_log_info = get_last_log_info,
		.save_last_log = save_last_log,
	};

	if (bbox_register_module_ops(&ops) != 0) {
		bbox_print_err("bbox_register_module_ops failed!\n");
		return -EINVAL;
	}

	/* allocate buffer for kmsg */
	kernel_log = kmalloc(KERNEL_LOG_MAX_SIZE, GFP_KERNEL);
	if (!kernel_log)
		goto __err;
	memset(kernel_log, 0, KERNEL_LOG_MAX_SIZE);

	/* register kdumper */
	dumper = kmalloc(sizeof(*dumper), GFP_KERNEL);
	if (!dumper)
		goto __err;

	memset(dumper, 0, sizeof(*dumper));
	dumper->max_reason = KMSG_DUMP_OOPS;
	dumper->dump = storage_lastword->blackbox_dump;
	ret = kmsg_dump_register(dumper);
	if (ret != 0) {
		bbox_print_err("kmsg_dump_register failed!\n");
		goto __err;
	}
	atomic_notifier_chain_register(&panic_notifier_list, &bbox_panic_block);

	register_reboot_notifier(&bbox_reboot_nb);
	return 0;

__err:
	kfree(kernel_log);
	kernel_log = NULL;

	if (dumper) {
		kfree(dumper);
		dumper = NULL;
	}

	return ret;
}

postcore_initcall(blackbox_init);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Blackbox for system");
MODULE_AUTHOR("OHOS");
