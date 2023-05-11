/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * include/linux/ashmem.h
 *
 * Copyright 2008 Google Inc.
 * Author: Robert Love
 */

#ifndef _LINUX_ASHMEM_H
#define _LINUX_ASHMEM_H

#include <linux/limits.h>
#include <linux/ioctl.h>
#include <linux/compat.h>

#include "uapi/ashmem.h"

/* support of 32bit userspace on 64bit platforms */
#ifdef CONFIG_COMPAT
#define COMPAT_ASHMEM_SET_SIZE		_IOW(__ASHMEMIOC, 3, compat_size_t)
#define COMPAT_ASHMEM_SET_PROT_MASK	_IOW(__ASHMEMIOC, 5, unsigned int)
#endif

int is_ashmem_file(struct file *file);
size_t get_ashmem_size_by_file(struct file *f);
char *get_ashmem_name_by_file(struct file *f);
void ashmem_mutex_lock(void);
void ashmem_mutex_unlock(void);

#ifdef CONFIG_PURGEABLE_ASHMEM
struct purgeable_ashmem_metadata {
	char *name;
	size_t size;
	int refc;
	bool purged;
	bool is_purgeable;
	unsigned int id;
	unsigned int create_time;
};

void ashmem_shrinkall(void);
void ashmem_shrink_by_id(const unsigned int ashmem_id,
			 const unsigned int create_time);
bool get_purgeable_ashmem_metadata(struct file *f,
				   struct purgeable_ashmem_metadata *pmdata);
#endif
#endif	/* _LINUX_ASHMEM_H */
