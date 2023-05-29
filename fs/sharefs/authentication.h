/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/sharefs/authentication.h
 *
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include "sharefs.h"

#define OID_ROOT             	0

#define SHAREFS_PERM_MASK     0x000F

#define SHAREFS_PERM_FIX           0
#define SHAREFS_PERM_MNT           1
#define SHAREFS_PERM_DFS           2
#define SHAREFS_PERM_OTHER         3

#define SHAREFS_READ_DIR  "r"
#define SHAREFS_READWRITE_DIR "rw"

#define BASE_USER_RANGE     200000 /* offset for uid ranges for each user */


#define SHAREFS_DIR_TYPE_MASK	       0x00F0
#define SHAREFS_DIR_TYPE_READONLY      0x0010
#define SHAREFS_DIR_TYPE_READWRITE     0x0020

#define SHAREFS_PERM_READONLY_DIR   00550
#define SHAREFS_PERM_READONLY_FILE  00440
#define SHAREFS_PERM_READWRITE_DIR  00550
#define SHAREFS_PERM_READWRITE_FILE 00660

extern int get_bid_config(const char *bname);
extern int __init sharefs_init_configfs(void);
extern void sharefs_exit_configfs(void);

void sharefs_root_inode_perm_init(struct inode *root_inode);
void fixup_perm_from_level(struct inode *dir, struct dentry *dentry);

static inline bool is_read_only_auth(__u16 perm)
{
	return (perm & SHAREFS_DIR_TYPE_MASK) == SHAREFS_DIR_TYPE_READONLY;
}

static inline bool is_read_write_auth(__u16 perm)
{
	return (perm & SHAREFS_DIR_TYPE_MASK) == SHAREFS_DIR_TYPE_READWRITE;
}

static inline void sharefs_set_read_perm(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode))
		inode->i_mode = (inode->i_mode & S_IFMT) | SHAREFS_PERM_READONLY_DIR;
	else
		inode->i_mode = (inode->i_mode & S_IFMT) | SHAREFS_PERM_READONLY_FILE;
}

static inline void sharefs_set_read_write_perm(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode))
		inode->i_mode = (inode->i_mode & S_IFMT) | SHAREFS_PERM_READWRITE_DIR;
	else
		inode->i_mode = (inode->i_mode & S_IFMT) | SHAREFS_PERM_READWRITE_FILE;
}

static inline int get_bundle_uid(struct sharefs_sb_info *sbi, const char *bname)
{
	return sbi->user_id * BASE_USER_RANGE + get_bid_config(bname);
}
