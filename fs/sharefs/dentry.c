// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/sharefs/dentry.c
 *
 * Copyright (c) 1998-2022 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2022 Stony Brook University
 * Copyright (c) 2003-2022 The Research Foundation of SUNY
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "sharefs.h"

/*
 * returns: 0: tell VFS to invalidate dentry in share directory
 */
static int sharefs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	return 0;
}

static void sharefs_d_release(struct dentry *dentry)
{
	/*
	 * It is possible that the dentry private data is NULL in case we
	 * ran out of memory while initializing it in
	 * new_dentry_private_data.  So check for NULL before attempting to
	 * release resources.
	 */
	if (SHAREFS_D(dentry)) {
		/* release and reset the lower paths */
		sharefs_put_reset_lower_path(dentry);
		free_dentry_private_data(dentry);
	}
	return;
}

const struct dentry_operations sharefs_dops = {
	.d_revalidate	= sharefs_d_revalidate,
	.d_release	= sharefs_d_release,
};
