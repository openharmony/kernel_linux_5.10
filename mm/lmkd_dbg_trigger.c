// SPDX-License-Identifier: GPL-2.0
/*
 * mm/lmkd_dbg_trigger.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/oom.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/lowmem_dbg.h>
#define PROC_NUMBUF 8

static int lmkd_oom_score_adj;
static atomic64_t lmkd_no_cma_cnt = ATOMIC64_INIT(0);

static int lmkd_dbg_trigger_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "lmkd_oom_score_adj: %d\n", lmkd_oom_score_adj);
	seq_printf(m, "lmkd_no_cma_cnt: %lld\n",
		atomic64_read(&lmkd_no_cma_cnt));
	return 0;
}

static int lmkd_dbg_trigger_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, lmkd_dbg_trigger_proc_show, NULL);
}

static ssize_t lmkd_dbg_trigger_write(struct file *file, const char __user *buf,
	       size_t count, loff_t *ppos)
{
	char buffer[PROC_NUMBUF];
	int oom_score_adj;
	int err;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count)) {
		err = -EFAULT;
		goto out;
	}

	err = kstrtoint(strstrip(buffer), 0, &oom_score_adj);
	if (err)
		goto out;

	if (oom_score_adj < OOM_SCORE_ADJ_MIN ||
		oom_score_adj > OOM_SCORE_ADJ_MAX) {
		err = -EINVAL;
		goto out;
	}

	lmkd_oom_score_adj = oom_score_adj;
	lowmem_dbg(oom_score_adj);

out:
	return err < 0 ? err : count;
}

static const struct proc_ops lmkd_dbg_trigger_proc_fops = {
	.proc_open		= lmkd_dbg_trigger_proc_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release		= single_release,
	.proc_write		= lmkd_dbg_trigger_write,
};

static int __init proc_lmkd_dbg_trigger_init(void)
{
	proc_create("lmkd_dbg_trigger", 0660, NULL,
			&lmkd_dbg_trigger_proc_fops);
	return 0;
}

fs_initcall(proc_lmkd_dbg_trigger_init);

