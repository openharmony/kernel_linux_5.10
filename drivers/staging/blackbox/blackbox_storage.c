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
			lastlog_len - sizeof(*pinfo), &pinfo->len);
	up(&kmsg_sem);
}
#endif

#if IS_ENABLED(CONFIG_DEF_BLACKBOX_STORAGE_BY_PSTORE_BLK)
#define LOG_FILE_WAIT_TIME               1000 /* unit: ms */
#define RETRY_MAX_COUNT                  10
#define PSTORE_MOUNT_POINT               "/sys/fs/pstore/"
#define FILE_LIMIT                       (0660)

#if __BITS_PER_LONG == 64
#define      sys_lstat    sys_newlstat
#else
#define      sys_lstat    sys_lstat64
#endif

struct sys_st {
#if __BITS_PER_LONG == 64
	struct stat __st;
#else
	struct stat64 __st;
#endif
};

static bool is_pstore_part_ready(char *pstore_file)
{
	mm_segment_t old_fs;
	int fd = -1;
	void *buf = NULL;
	char *full_path = NULL;
	struct linux_dirent64 *dirp;
	int num;
	int ret = -1;
	struct sys_st st;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	fd = sys_open(PSTORE_MOUNT_POINT, O_RDONLY, 0);
	if (fd < 0) {
		bbox_print_err("open dir [%s] failed!\n", PSTORE_MOUNT_POINT);
		goto __out;
	}

	buf = vmalloc(PATH_MAX_LEN);
	if (!buf)
		goto __out;

	full_path = vmalloc(PATH_MAX_LEN);
	if (!full_path)
		goto __out;

	dirp = buf;

	num = sys_getdents64(fd, dirp, PATH_MAX_LEN);
	while (num > 0) {
		while (num > 0) {
			if ((strcmp(dirp->d_name, ".") == 0) || (strcmp(dirp->d_name, "..") == 0)) {
				num -= dirp->d_reclen;
				dirp = (void *)dirp + dirp->d_reclen;
				continue;
			}

			memset(full_path, 0, PATH_MAX_LEN);
			snprintf(full_path, PATH_MAX_LEN - 1, "%s%s", PSTORE_MOUNT_POINT, dirp->d_name);

			memset((void *)&st, 0, sizeof(struct sys_st));

			ret = sys_lstat(full_path, &st.__st);
			if ((ret == 0) && (S_ISREG(st.__st.st_mode)) &&
				(strncmp(dirp->d_name, "blackbox", strlen("blackbox")) == 0)) {
				if (strcmp(full_path, pstore_file) > 0)
					strncpy(pstore_file, full_path, strlen(full_path));
				bbox_print_info("get pstore file name %s %s!\n", pstore_file,
						ret ? "failed" : "successfully");
			}

			num -= dirp->d_reclen;
			dirp = (void *)dirp + dirp->d_reclen;
		}

		dirp = buf;
		memset(buf, 0, PATH_MAX_LEN);
		num = sys_getdents64(fd, dirp, PATH_MAX_LEN);
	}

__out:
	if (fd >= 0)
		sys_close(fd);

	set_fs(old_fs);

	vfree(buf);
	vfree(full_path);

	return ret == 0;
}

static int get_log_by_pstore_blk(void *in, unsigned int inlen)
{
	char pstore_file[PATH_MAX_LEN];
	void *pbuf = NULL;
	void *pbuf_temp = NULL;
	static int retry;
	int need_read_size = 0;
	int fd = -1;
	int ret = 0;

	memset(pstore_file, 0, PATH_MAX_LEN);
	while (!is_pstore_part_ready((char *)&pstore_file)) {
		msleep(LOG_FILE_WAIT_TIME);
		retry++;
		if (retry >= RETRY_MAX_COUNT)
			return -ENOENT;
	}

	if (likely(in)) {
		fd = sys_open(pstore_file, O_RDONLY, FILE_LIMIT);
		if (fd < 0) {
			bbox_print_err("%s():%d: open %s failed! [%d]\n", __func__,
					__LINE__, pstore_file, fd);
			return -EBADF;
		}
		memset(in, 0, inlen);
		need_read_size = inlen;
		pbuf = in;

		pbuf_temp = kzalloc(SZ_4K, GFP_KERNEL);
		if (!pbuf_temp)
			goto __out;

		while (need_read_size > 0) {
			ret = sys_read(fd, pbuf_temp, SZ_4K);
			if (ret < 0) {
				bbox_print_err("%s():%d: read failed! [%d]\n", __func__,
					__LINE__, ret);
				goto __error;
			}

			if (ret == 0)
				break;

			memcpy((void *)pbuf, (const void *)pbuf_temp, ret);
			pbuf += ret;
			need_read_size -= ret;
		}
		kfree(pbuf_temp);
	}

	sys_close(fd);

	return 0;

__error:
	kfree(pbuf_temp);
__out:
	sys_close(fd);
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
		.get_log = get_log_by_pstore_blk,
		.blackbox_dump = pstore_blackbox_dump,
		.material = "pstore_blk",
	},
#endif
#if IS_ENABLED(CONFIG_DEF_BLACKBOX_STORAGE_BY_PSTORE_RAM)
	{
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

