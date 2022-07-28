// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rss_threshold.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 */
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include "../fs/proc/internal.h"

int proc_pid_rss(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm = get_task_mm(task);
	unsigned long total_rss;

	if (mm) {
		total_rss = get_mm_rss(mm);
		seq_printf(m, "VMRss:%lu KB\n", total_rss << (PAGE_SHIFT - 10));
		mmput(mm);
	}
	return 0;
}

void listen_rss_threshold(struct mm_struct *mm)
{
	unsigned long total_rss;

	total_rss = get_mm_rss(mm);

	if (!(mm->owner) || mm->rss_threshold == 0)
		return;

	total_rss = total_rss  << (PAGE_SHIFT - 10);

	if (likely(total_rss <= mm->rss_threshold))
		return;

	if (mm->owner->comm)
		pr_err("rss_threshold monitor:Pid:%d [%s] rss size:%lu KB is out of range:%lu KB\n",
				mm->owner->pid, mm->owner->comm,
				total_rss,
				mm->rss_threshold);
	else
		pr_err("rss_threshold monitor:Pid:%d [NULL] rss size:%lu KB is out of range:%lu KB\n",
				mm->owner->pid,
				total_rss,
				mm->rss_threshold);
}

static ssize_t rss_threshold_write(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	struct task_struct *p;
	struct mm_struct *mm = NULL;
	unsigned long mem_total;
	unsigned long rss_threshold;
	int err;

	err = kstrtoul_from_user(buf, count, 0, &rss_threshold);
	if (err < 0)
		return err;

	mem_total = totalram_pages() << (PAGE_SHIFT - 10);
	if (rss_threshold < 0 || rss_threshold > mem_total)
		return -EINVAL;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	mm = get_task_mm(p);
	if (mm) {
		mm->rss_threshold = rss_threshold;
		listen_rss_threshold(mm);
		mmput(mm);
	}

	put_task_struct(p);

	return count;
}

static int rss_threshold_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct task_struct *p;
	struct mm_struct *mm = NULL;

	p = get_proc_task(inode);
	if (!p)
		return -ESRCH;

	mm = get_task_mm(p);
	if (mm) {
		seq_printf(m, "Threshold:%lu KB\n", mm->rss_threshold);
		mmput(mm);
	}
	put_task_struct(p);

	return 0;
}

static int rss_threshold_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, rss_threshold_show, inode);
}

const struct file_operations proc_pid_rss_threshold_operations = {
	.open		= rss_threshold_open,
	.read		= seq_read,
	.write		= rss_threshold_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};
