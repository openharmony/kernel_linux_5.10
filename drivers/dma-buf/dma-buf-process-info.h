/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DMA-BUF: dmabuf usage of all processes statistics.
 *
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#ifndef __DMA_BUF_PROCESS_INFO_H
#define __DMA_BUF_PROCESS_INFO_H

#ifdef CONFIG_DMABUF_PROCESS_INFO
/**
 * init_dma_buf_task_info - init exp_pid and exp_task_comm of dma_buf
 * @buf:	[in]	pointer to struct dma_buf. If @buf IS_ERR_OR_NULL,
 *		return with doing nothing.
 */
void init_dma_buf_task_info(struct dma_buf *buf);

/**
 * dma_buf_exp_pid - return exp_pid of @buf
 * @buf:	[in]	pointer to struct dma_buf
 *
 * Return 0 if @buf IS_ERR_OR_NULL, else return buf->exp_pid
 */
pid_t dma_buf_exp_pid(const struct dma_buf *buf);

/**
 * dma_buf_exp_task_comm - return exp_task_comm of @buf
 * @buf:	[in]	pointer to struct dma_buf
 *
 * Return NULL if @buf IS_ERR_OR_NULL, else return buf->exp_task_comm
 */
const char *dma_buf_exp_task_comm(const struct dma_buf *buf);

/**
 * dma_buf_process_info_init_procfs - module init: create node in procfs
 */
void dma_buf_process_info_init_procfs(void);

/**
 * dma_buf_process_info_uninit_procfs - module exit: remove node in procfs
 */
void dma_buf_process_info_uninit_procfs(void);

/**
 * dma_buf_process_info_init_debugfs - create debug node under @parent
 * in debugfs.
 * @parent:	[in]	pointer to struct dentry. If @parent IS_ERR_OR_NULL,
 *		return -EINVAL
 *
 * Return 0 if success, otherwise return errno.
 *
 * Note that there is no related uninit function, since the debug node will
 * be removed in dma_buf_uninit_debugfs() when dma_buf_deinit() called.
 */
int dma_buf_process_info_init_debugfs(struct dentry *parent);

#else /* CONFIG_DMABUF_PROCESS_INFO */

static inline void init_dma_buf_task_info(struct dma_buf *buf) {}

static inline pid_t dma_buf_exp_pid(const struct dma_buf *buf)
{
	return 0;
}

static inline const char *dma_buf_exp_task_comm(const struct dma_buf *buf)
{
	return NULL;
}

static inline void dma_buf_process_info_init_procfs(void) {}

static inline void dma_buf_process_info_uninit_procfs(void) {}

static inline int
dma_buf_process_info_init_debugfs(struct dentry *parent)
{
	return 0;
}
#endif /* CONFIG_DMABUF_PROCESS_INFO */
#endif /* __DMA_BUF_PROCESS_INFO_H */

