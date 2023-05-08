// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#include <linux/ptrace.h>
#include <linux/sched/mm.h>
#include "internal.h"

#define XPM_REGION_LEN 48
static int xpm_region_open(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = proc_mem_open(inode, PTRACE_MODE_READ);

	if (IS_ERR(mm))
		return PTR_ERR(mm);

	file->private_data = mm;
	return 0;
}

static ssize_t xpm_region_read(struct file *file, char __user *buf,
	size_t count, loff_t *pos)
{
	struct mm_struct *mm = file->private_data;
	char xpm_region[XPM_REGION_LEN] = {0};
	size_t len;

	if (!mm)
		return 0;

	len = snprintf(xpm_region, XPM_REGION_LEN - 1, "%lx-%lx",
		mm->xpm_region.addr_start,
		mm->xpm_region.addr_end);

	return simple_read_from_buffer(buf, count, pos, xpm_region, len);
}

static int xpm_region_release(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = file->private_data;

	if (mm)
		mmdrop(mm);

	return 0;
}

const struct file_operations proc_xpm_region_operations = {
	.open = xpm_region_open,
	.read = xpm_region_read,
	.llseek = generic_file_llseek,
	.release = xpm_region_release,
};