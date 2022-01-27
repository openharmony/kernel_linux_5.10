// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef DFX_HUNGTASK_USER_H
#define DFX_HUNGTASK_USER_H

#include <linux/types.h>

#ifdef CONFIG_DFX_HUNGTASK_USER
void htuser_post_process_userlist(void);
ssize_t htuser_list_store(struct kobject *kobj,
			  struct kobj_attribute *attr, const char *buf, size_t count);
ssize_t htuser_list_show(struct kobject *kobj,
			 struct kobj_attribute *attr, char *buf);
#else
static inline void htuser_post_process_userlist(void)
{
}

static inline ssize_t htuser_list_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	return 0;
}
static inline ssize_t htuser_list_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buf)
{
	return 0;
}

#endif

#endif /* DFX_HUNGTASK_USER_H */
