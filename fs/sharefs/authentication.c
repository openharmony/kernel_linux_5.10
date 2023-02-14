/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/sharefs/authentication.c
 *
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */
#include "authentication.h"

static inline __u16 perm_get_next_level(__u16 perm)
{
	__u16 level = (perm & SHAREFS_PERM_MASK) + 1;

	if (level <= SHAREFS_PERM_OTHER)
		return level;
	else
		return SHAREFS_PERM_OTHER;
}

void fixup_perm_from_level(struct inode *dir, struct dentry *dentry)
{
	struct sharefs_inode_info *hii = SHAREFS_I(dir);
	struct inode *dinode = d_inode(dentry);
	struct sharefs_inode_info *dinfo = SHAREFS_I(dinode);
	const unsigned char* cur_name =  dentry->d_name.name;
	__u16 level = perm_get_next_level(hii->perm);
	__u16 perm = 0;
	int bid = 0;

	if (IS_ERR_OR_NULL(dinode))
		return;
	dinode->i_uid = dir->i_uid;
	dinode->i_gid = dir->i_gid;
	switch (level)
	{
	case SHAREFS_PERM_MNT:
		bid = get_bundle_uid(SHAREFS_SB(dentry->d_sb),
					 dentry->d_name.name);
		perm = level;
		if (bid != 0) {
			dinode->i_uid = KUIDT_INIT(bid);
			dinode->i_gid = KGIDT_INIT(bid);
		} else {
			dinode->i_uid = ROOT_UID;
			dinode->i_gid = ROOT_GID;
		}
		dinode->i_mode = (dinode->i_mode & S_IFMT) | SHAREFS_PERM_READONLY_DIR;
		break;
	case SHAREFS_PERM_DFS:
		if (!strcmp(cur_name, SHAREFS_READ_DIR)) {
			perm = SHAREFS_DIR_TYPE_READONLY | level;
			sharefs_set_read_perm(dinode);
		} else if (!strcmp(cur_name, SHAREFS_READWRITE_DIR)) {
			perm = SHAREFS_DIR_TYPE_READWRITE | level;
			sharefs_set_read_write_perm(dinode);
		}
		break;
	case SHAREFS_PERM_OTHER:
		if (is_read_only_auth(hii->perm)) {
			perm = SHAREFS_DIR_TYPE_READONLY | SHAREFS_PERM_DFS;
			sharefs_set_read_perm(dinode);
		} else if (is_read_write_auth(hii->perm)) {
			perm = SHAREFS_DIR_TYPE_READWRITE | SHAREFS_PERM_DFS;
			sharefs_set_read_write_perm(dinode);
		}
		break;
	default:
		/* ! it should not get to here */
		sharefs_err("sharedfs perm incorrect got default case, level:%u", level);
		break;
	}
	dinfo->perm = perm;
}

void sharefs_root_inode_perm_init(struct inode *root_inode)
{
	struct sharefs_inode_info *hii = SHAREFS_I(root_inode);
	hii->perm = SHAREFS_PERM_FIX;
}