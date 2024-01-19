/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * DMABUF Heaps Userspace API
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2019 Linaro Ltd.
 */
#ifndef _UAPI_LINUX_DMABUF_POOL_H
#define _UAPI_LINUX_DMABUF_POOL_H

#include <linux/ioctl.h>
#include <linux/types.h>

/**
 * DOC: DMABUF Heaps Userspace API
 */

/* Valid FD_FLAGS are O_CLOEXEC, O_RDONLY, O_WRONLY, O_RDWR */
#define DMA_HEAP_VALID_FD_FLAGS (O_CLOEXEC | O_ACCMODE)

/* Currently no heap flags */
#define DMA_HEAP_VALID_HEAP_FLAGS (0)

/**
 * struct dma_heap_allocation_data - metadata passed from userspace for
 *                                      allocations
 * @len:		size of the allocation
 * @fd:			will be populated with a fd which provides the
 *			handle to the allocated dma-buf
 * @fd_flags:		file descriptor flags used when allocating
 * @heap_flags:		flags passed to heap
 *
 * Provided by userspace as an argument to the ioctl
 */
struct dma_heap_allocation_data {
	__u64 len;
	__u32 fd;
	__u32 fd_flags;
	__u64 heap_flags;
};

#define DMA_HEAP_IOC_MAGIC		'H'

enum dma_heap_flag_owner_id {
	OWNER_DEFAULT = 0,
	OWNER_GPU,
	OWNER_MEDIA_CODEC,
	COUNT_DMA_HEAP_FLAG_OWNER,
};

#define OWNER_OFFSET_BIT 27 /* 27 bit */
#define OWNER_MASK (0xfUL << OWNER_OFFSET_BIT)

/* Use the 27-30 bits of heap flags as owner_id flag */
static inline void set_owner_id_for_heap_flags(__u64 *heap_flags, __u64 owner_id)
{
	if (heap_flags == NULL || owner_id >= COUNT_DMA_HEAP_FLAG_OWNER) {
		return;
	}
	*heap_flags |= owner_id << OWNER_OFFSET_BIT;
}

/* To get the binary number of owner_id */
static inline __u64 get_owner_id_from_heap_flags(__u64 heap_flags)
{
	return (heap_flags & OWNER_MASK) >> OWNER_OFFSET_BIT;
}

/**
 * DOC: DMA_HEAP_IOCTL_ALLOC - allocate memory from pool
 *
 * Takes a dma_heap_allocation_data struct and returns it with the fd field
 * populated with the dmabuf handle of the allocation.
 */
#define DMA_HEAP_IOCTL_ALLOC	_IOWR(DMA_HEAP_IOC_MAGIC, 0x0,\
				      struct dma_heap_allocation_data)

#endif /* _UAPI_LINUX_DMABUF_POOL_H */
