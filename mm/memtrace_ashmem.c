// SPDX-License-Identifier: GPL-2.0
/*
 * mm/memtrace_ashmem.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 */
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fdtable.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/memcheck.h>
#include "../drivers/staging/android/ashmem.h"

static int ashmem_debug_process_info_open(struct inode *inode,
		struct file *file);

struct ashmem_debug_process_info_args {
	struct seq_file *seq;
	struct task_struct *tsk;
};

static const struct proc_ops debug_process_ashmem_info_fops = {
	.proc_open = ashmem_debug_process_info_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int ashmem_debug_process_info_cb(const void *data,
	struct file *f, unsigned int fd)
{
	const struct ashmem_debug_process_info_args *args = data;
	struct task_struct *tsk = args->tsk;

	if (!is_ashmem_file(f))
		return 0;
	seq_printf(args->seq,
		"%s %u %u %s %zu\n",
		tsk->comm, tsk->pid, fd,
		get_ashmem_name_by_file(f),
		get_ashmem_size_by_file(f));
	return 0;
}

static int ashmem_debug_process_info_show(struct seq_file *s, void *d)
{
	struct task_struct *tsk = NULL;
	struct ashmem_debug_process_info_args cb_args;

	seq_puts(s, "Process ashmem detail info:\n");
	seq_puts(s, "----------------------------------------------------\n");
	seq_printf(s, "%s %s %s %s %s\n",
			"Process name", "Process ID",
			"fd", "ashmem_name", "size");

	ashmem_mutex_lock();
	rcu_read_lock();
	for_each_process(tsk) {
		if (tsk->flags & PF_KTHREAD)
			continue;
		cb_args.seq = s;
		cb_args.tsk = tsk;

		task_lock(tsk);
		iterate_fd(tsk->files, 0,
			ashmem_debug_process_info_cb, (void *)&cb_args);
		task_unlock(tsk);
	}
	rcu_read_unlock();
	ashmem_mutex_unlock();
	seq_puts(s, "----------------------------------------------------\n");
	return 0;
}

static int ashmem_debug_process_info_open(struct inode *inode,
	struct file *file)
{
	return single_open(file, ashmem_debug_process_info_show,
			inode->i_private);
}

void init_ashmem_process_info(void)
{
	struct proc_dir_entry *entry = NULL;

	entry = proc_create_data("ashmem_process_info", 0444,
			NULL, &debug_process_ashmem_info_fops, NULL);
	if (!entry)
		pr_err("Failed to create ashmem debug info\n");
}

