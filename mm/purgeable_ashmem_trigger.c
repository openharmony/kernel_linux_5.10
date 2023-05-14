// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Huawei Technologies Co., Ltd.
 */

#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fdtable.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include "../drivers/staging/android/ashmem.h"

#define PURGEABLE_ASHMEM_SHRINKALL_ARG 0

struct purgeable_ashmem_trigger_args {
	struct seq_file *seq;
	struct task_struct *tsk;
};

static int purgeable_ashmem_trigger_cb(const void *data,
	struct file *f, unsigned int fd)
{
	const struct purgeable_ashmem_trigger_args *args = data;
	struct task_struct *tsk = args->tsk;
	struct purgeable_ashmem_metadata pmdata;

	if (!is_ashmem_file(f))
		return 0;
	if (!get_purgeable_ashmem_metadata(f, &pmdata))
		return 0;
	if (pmdata.is_purgeable) {
		pmdata.name = pmdata.name == NULL ? "" : pmdata.name;
		seq_printf(args->seq,
			"%s,%u,%u,%ld,%s,%zu,%u,%u,%d,%d\n",
			tsk->comm, tsk->pid, fd, (long)tsk->signal->oom_score_adj,
			pmdata.name, pmdata.size, pmdata.id, pmdata.create_time,
			pmdata.refc, pmdata.purged);
	}
	return 0;
}

static ssize_t purgeable_ashmem_trigger_write(struct file *file,
	const char __user *buffer, size_t count, loff_t *ppos)
{
	char *buf;
	unsigned int ashmem_id = 0;
	unsigned int create_time = 0;
	const unsigned int params_num = 2;
	const struct cred *cred = current_cred();

	if (!cred)
		return 0;

	if (!uid_eq(cred->euid, GLOBAL_MEMMGR_UID) &&
	    !uid_eq(cred->euid, GLOBAL_ROOT_UID)) {
		pr_err("no permission to shrink purgeable ashmem!\n");
		return 0;
	}
	buf = memdup_user_nul(buffer, count);
	buf = strstrip(buf);
	if (sscanf(buf, "%u %u", &ashmem_id, &create_time) != params_num)
		return -EINVAL;
	if (ashmem_id == PURGEABLE_ASHMEM_SHRINKALL_ARG &&
	    create_time == PURGEABLE_ASHMEM_SHRINKALL_ARG)
		ashmem_shrinkall();
	else
		ashmem_shrink_by_id(ashmem_id, create_time);
	return count;
}

static int purgeable_ashmem_trigger_show(struct seq_file *s, void *d)
{
	struct task_struct *tsk = NULL;
	struct purgeable_ashmem_trigger_args cb_args;
	const struct cred *cred = current_cred();

	if (!cred)
		return -EINVAL;

	if (!uid_eq(cred->euid, GLOBAL_MEMMGR_UID) &&
	    !uid_eq(cred->euid, GLOBAL_ROOT_UID)) {
		pr_err("no permission to shrink purgeable ashmem!\n");
		return -EINVAL;
	}
	seq_puts(s, "Process purgeable ashmem detail info:\n");
	seq_puts(s, "----------------------------------------------------\n");
	seq_printf(s, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			"process_name", "pid", "adj", "fd",
			"ashmem_name", "size", "id", "time", "ref_count", "purged");

	ashmem_mutex_lock();
	rcu_read_lock();
	for_each_process(tsk) {
		if (tsk->flags & PF_KTHREAD)
			continue;
		cb_args.seq = s;
		cb_args.tsk = tsk;

		task_lock(tsk);
		iterate_fd(tsk->files, 0,
			purgeable_ashmem_trigger_cb, (void *)&cb_args);
		task_unlock(tsk);
	}
	rcu_read_unlock();
	ashmem_mutex_unlock();
	seq_puts(s, "----------------------------------------------------\n");
	return 0;
}

static int purgeable_ashmem_trigger_open(struct inode *inode,
	struct file *file)
{
	return single_open(file, purgeable_ashmem_trigger_show,
					   inode->i_private);
}

static const struct proc_ops purgeable_ashmem_trigger_fops = {
	.proc_open = purgeable_ashmem_trigger_open,
	.proc_write = purgeable_ashmem_trigger_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

void init_purgeable_ashmem_trigger(void)
{
	struct proc_dir_entry *entry = NULL;

	entry = proc_create_data("purgeable_ashmem_trigger", 0666,
			NULL, &purgeable_ashmem_trigger_fops, NULL);
	if (!entry)
		pr_err("Failed to create purgeable ashmem trigger\n");
}
