// SPDX-License-Identifier: GPL-2.0
/*
 * DMA-BUF: dmabuf usage of all processes statistics.
 *
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#include <linux/debugfs.h>
#include <linux/dma-buf.h>
#include <linux/fdtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "dma-buf-process-info.h"

static struct proc_dir_entry *proc_dmabuf_entry;

struct dmabuf_task_info_args {
	struct seq_file *seq;
	struct task_struct *tsk;
	size_t tsk_dmabuf_bytes;
};

void init_dma_buf_task_info(struct dma_buf *buf)
{
	struct task_struct *tsk = NULL;

	if (IS_ERR_OR_NULL(buf))
		return;

	get_task_struct(current->group_leader);
	task_lock(current->group_leader);
	tsk = current->group_leader;
	buf->exp_pid = task_pid_nr(tsk);
	if (tsk->flags & PF_KTHREAD)
		tsk = NULL;
	task_unlock(current->group_leader);
	put_task_struct(current->group_leader);

	if (tsk)
		get_task_comm(buf->exp_task_comm, tsk);
	else /* kernel task */
		strncpy(buf->exp_task_comm, "[kernel task]",
			sizeof(buf->exp_task_comm));
}

pid_t dma_buf_exp_pid(const struct dma_buf *buf)
{
	if (IS_ERR_OR_NULL(buf))
		return 0;

	return buf->exp_pid;
}

const char *dma_buf_exp_task_comm(const struct dma_buf *buf)
{
	if (IS_ERR_OR_NULL(buf))
		return NULL;

	return buf->exp_task_comm;
}

static int dma_buf_single_file_show(const void *data, struct file *f,
				    unsigned int fd)
{
	struct dmabuf_task_info_args *tsk_info = NULL;
	struct task_struct *tsk = NULL;
	struct dma_buf *buf = NULL;

	tsk_info = (struct dmabuf_task_info_args *)data;
	if (IS_ERR_OR_NULL(tsk_info) || IS_ERR_OR_NULL(tsk_info->seq))
		return 0;

	tsk = tsk_info->tsk;
	buf = get_dma_buf_from_file(f);
	if (IS_ERR_OR_NULL(tsk) || IS_ERR_OR_NULL(buf))
		return 0;

	tsk_info->tsk_dmabuf_bytes += buf->size;

	spin_lock(&buf->name_lock);
	seq_printf(tsk_info->seq,
		   "%-16s %-16d %-16u %-16zu %-16lu %-16d %-16s %s \t %s\n",
		   tsk->comm,
		   tsk->pid,
		   fd,
		   buf->size,
		   file_inode(buf->file)->i_ino,
		   buf->exp_pid,
		   buf->exp_task_comm,
		   buf->name ?: "NULL",
		   buf->exp_name ?: "NULL");
	spin_unlock(&buf->name_lock);

	return 0;
}

static int dma_buf_process_info_show(struct seq_file *s, void *unused)
{
	struct dmabuf_task_info_args task_info = { NULL, NULL, 0 };
	struct task_struct *tsk = NULL;

	seq_puts(s, "Dma-buf objects usage of processes:\n");
	seq_printf(s, "%-16s %-16s %-16s %-16s %-16s %-16s %-16s %s \t %s\n",
		   "Process", "pid", "fd", "size_bytes", "ino", "exp_pid",
		   "exp_task_comm", "buf_name", "exp_name");

	task_info.seq = s;

	rcu_read_lock();
	for_each_process(tsk) {
		task_info.tsk = tsk;
		task_info.tsk_dmabuf_bytes = 0;

		task_lock(tsk);
		iterate_fd(tsk->files, 0, dma_buf_single_file_show,
			   (void *)&task_info);
		if (task_info.tsk_dmabuf_bytes)
			seq_printf(s, "Total dmabuf size of %s: %zu bytes\n",
				   tsk->comm, task_info.tsk_dmabuf_bytes);
		task_unlock(tsk);
	}
	rcu_read_unlock();

	return 0;
}

void dma_buf_process_info_init_procfs(void)
{
	proc_dmabuf_entry = proc_create_single("process_dmabuf_info", 0444,
					       NULL,
					       dma_buf_process_info_show);
	if (!proc_dmabuf_entry)
		pr_err("%s: create node /proc/process_dmabuf_info failed\n",
		       __func__);
}

void dma_buf_process_info_uninit_procfs(void)
{
	if (!proc_dmabuf_entry)
		return;

	proc_remove(proc_dmabuf_entry);
}

DEFINE_SHOW_ATTRIBUTE(dma_buf_process_info);

int dma_buf_process_info_init_debugfs(struct dentry *parent)
{
	struct dentry *debugfs_file = NULL;
	int err = 0;

	if (IS_ERR_OR_NULL(parent))
		return -EINVAL;

	debugfs_file = debugfs_create_file("process_bufinfo", 0444,
					   parent, NULL,
					   &dma_buf_process_info_fops);
	if (IS_ERR(debugfs_file)) {
		pr_err("dma_buf: debugfs: create process_bufinfo failed\n");
		err = PTR_ERR(debugfs_file);
	}

	return err;
}
