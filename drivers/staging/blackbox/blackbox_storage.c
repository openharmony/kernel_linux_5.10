// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
 */

#include <linux/blackbox.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/pstore.h>
#include <linux/blackbox_storage.h>
#include <linux/blackbox_common.h>

char *storage_material =
#ifdef CONFIG_DEF_BLACKBOX_STORAGE
		CONFIG_DEF_BLACKBOX_STORAGE;
#else
		NULL;
#endif
const struct reboot_crashlog_storage *storage_lastword __ro_after_init;

#if IS_ENABLED(CONFIG_DEF_BLACKBOX_STORAGE_BY_MEMORY)
static DEFINE_SEMAPHORE(kmsg_sem);
static char *lastlog;
unsigned int lastlog_len;
static int get_log_by_memory(void *in, unsigned int inlen)
{
	return 0;
}

static int storage_log_by_memory(void *out, unsigned int outlen)
{
	if (unlikely(!out))
		return -EINVAL;

	/* Initialized from caller. */
	lastlog = out;
	lastlog_len = outlen;
	return 0;
}

/* Called after storage_log_by_memory successfully. */
static void do_kmsg_dump(struct kmsg_dumper *dumper,
				enum kmsg_dump_reason reason)
{
	struct fault_log_info *pinfo;

	if (unlikely(!lastlog))
		return;

	/* get kernel log from kmsg dump module */
	if (down_trylock(&kmsg_sem) != 0) {
		bbox_print_err("down_trylock failed!\n");
		return;
	}
	pinfo = (struct fault_log_info *)lastlog;
	(void)kmsg_dump_get_buffer(dumper, true, lastlog + sizeof(*pinfo),
			lastlog_len - sizeof(*pinfo), (size_t *)&pinfo->len);
	up(&kmsg_sem);
}
#endif

#if defined(CONFIG_DEF_BLACKBOX_STORAGE_BY_PSTORE_BLK) ||  \
	defined(CONFIG_DEF_BLACKBOX_STORAGE_BY_PSTORE_RAM)
#define LOG_FILE_WAIT_TIME               1000 /* unit: ms */
#define RETRY_MAX_COUNT                  10
#define PSTORE_MOUNT_POINT               "/sys/fs/pstore/"
#define FILE_LIMIT                       (0660)

static bool is_pstore_part_ready(char *pstore_file)
{
	const char *cur_name = NULL;
	struct dentry *root_dentry;
	struct dentry *cur_dentry;
	struct file *filp = NULL;
	char *full_path = NULL;
	bool is_ready = false;

	if (unlikely(!pstore_file))
		return -EINVAL;
	memset(pstore_file, 0, sizeof(*pstore_file));

	filp = file_open(PSTORE_MOUNT_POINT, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		bbox_print_err("open %s failed! err is [%ld]\n", PSTORE_MOUNT_POINT, PTR_ERR(filp));
		return -EBADF;
	}

	full_path = vmalloc(PATH_MAX_LEN);
	if (!full_path)
		goto __out;

	root_dentry = filp->f_path.dentry;
	list_for_each_entry(cur_dentry, &root_dentry->d_subdirs, d_child) {
		cur_name = cur_dentry->d_name.name;

		memset(full_path, 0, PATH_MAX_LEN);
		snprintf(full_path, PATH_MAX_LEN - 1, "%s%s", PSTORE_MOUNT_POINT, cur_name);

		if (S_ISREG(d_inode(cur_dentry)->i_mode) && !strncmp(cur_name, "blackbox",
								     strlen("blackbox"))) {
			is_ready = true;
			if (strcmp(full_path, pstore_file) > 0)
				strncpy(pstore_file, full_path, strlen(full_path));
		}
	}

	if (is_ready && strlen(pstore_file))
		bbox_print_info("get pstore file name %s successfully!\n", pstore_file);

__out:
	file_close(filp);
	vfree(full_path);

	return is_ready;
}

static int get_log_by_pstore(void *in, unsigned int inlen)
{
	char pstore_file[PATH_MAX_LEN];
	struct file *filp = NULL;
	char *pathname = NULL;
	mm_segment_t old_fs;
	void *pbuf = NULL;
	loff_t pos = 0;
	static int retry;
	int ret = -1;

	memset(pstore_file, 0, PATH_MAX_LEN);
	while (!is_pstore_part_ready((char *)&pstore_file)) {
		msleep(LOG_FILE_WAIT_TIME);
		retry++;
		if (retry >= RETRY_MAX_COUNT)
			return -ENOENT;
	}

	if (likely(in)) {
		filp = file_open(pstore_file, O_RDONLY, FILE_LIMIT);
		if (IS_ERR(filp)) {
			bbox_print_err("open %s failed! err is [%ld]\n", pstore_file,
				       PTR_ERR(filp));
			return -EBADF;
		}
		memset(in, 0, inlen);
		pbuf = in;

		old_fs = get_fs();
		set_fs(KERNEL_DS);

		ret = vfs_read(filp, pbuf, inlen, &pos);
		if (ret < 0) {
			pathname = getfullpath(filp);
			bbox_print_err("read %s failed! err is [%d]\n", pathname ? pathname : "",
				       ret);
			goto __error;
		}

		set_fs(old_fs);
		file_close(filp);
		file_delete(filp);
		return 0;
	}

	return -EBADF;
__error:
	set_fs(old_fs);
	file_close(filp);
	return -EIO;
}
#endif

const struct reboot_crashlog_storage storage_lastwords[] = {
#if IS_ENABLED(CONFIG_DEF_BLACKBOX_STORAGE_BY_MEMORY)
	{
		.get_log = get_log_by_memory,
		.storage_log = storage_log_by_memory,
		.blackbox_dump = do_kmsg_dump,
		.material = "memory",
	},
#endif
#if IS_ENABLED(CONFIG_DEF_BLACKBOX_STORAGE_BY_PSTORE_BLK)
	{
		.get_log = get_log_by_pstore,
		.blackbox_dump = pstore_blackbox_dump,
		.material = "pstore_blk",
	},
#endif
#if IS_ENABLED(CONFIG_DEF_BLACKBOX_STORAGE_BY_PSTORE_RAM)
	{
		.get_log = get_log_by_pstore,
		.blackbox_dump = pstore_blackbox_dump,
		.material = "pstore_ram",
	},
#endif
#if IS_ENABLED(CONFIG_DEF_BLACKBOX_STORAGE_BY_RAW_PARTITION)
	{
		.material = "raw_partition",
	},
#endif
	{ }
};

