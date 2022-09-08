// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/comm/authority/authentication.c
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#include "authentication.h"
#include <linux/fsnotify.h>
#include <linux/security.h>

#include "hmdfs.h"

struct fs_struct *hmdfs_override_fsstruct(struct fs_struct *saved_fs)
{
#if (defined CONFIG_HMDFS_FS_PERMISSION) && (defined CONFIG_SDCARD_FS)
	struct fs_struct *copied_fs = copy_fs_struct(saved_fs);

	if (!copied_fs)
		return NULL;
	copied_fs->umask = 0;
	task_lock(current);
	current->fs = copied_fs;
	task_unlock(current);
	return copied_fs;
#else
	return saved_fs;
#endif
}

void hmdfs_revert_fsstruct(struct fs_struct *saved_fs,
			   struct fs_struct *copied_fs)
{
#if (defined CONFIG_HMDFS_FS_PERMISSION) && (defined CONFIG_SDCARD_FS)
	task_lock(current);
	current->fs = saved_fs;
	task_unlock(current);
	free_fs_struct(copied_fs);
#endif
}

const struct cred *hmdfs_override_fsids(bool is_recv_thread)
{
	struct cred *cred = NULL;
	const struct cred *old_cred = NULL;

	cred = prepare_creds();
	if (!cred)
		return NULL;

	cred->fsuid = is_recv_thread ? SYSTEM_UID : USER_DATA_RW_UID;
	cred->fsgid = is_recv_thread ? SYSTEM_GID : USER_DATA_RW_GID;

	old_cred = override_creds(cred);

	return old_cred;
}

const struct cred *hmdfs_override_dir_fsids(struct inode *dir,
					    struct dentry *dentry, __u16 *_perm)
{
	struct hmdfs_inode_info *hii = hmdfs_i(dir);
	struct cred *cred = NULL;
	const struct cred *old_cred = NULL;
	__u16 level = hmdfs_perm_get_next_level(hii->perm);
	__u16 perm = 0;

	cred = prepare_creds();
	if (!cred)
		return NULL;

	switch (level) {
	case HMDFS_PERM_MNT:
		/* system : media_rw */
		cred->fsuid = USER_DATA_RW_UID;
		cred->fsgid = USER_DATA_RW_GID;
		perm = (hii->perm & HMDFS_DIR_TYPE_MASK) | level;
		break;
	case HMDFS_PERM_DFS:
		/*
		 * data  : system : media_rw
		 * system: system : media_rw, need authority
		 * services: dfs_share : dfs_share
		 * other : media_rw : media_rw
		 **/
		if (!strcmp(dentry->d_name.name, DFS_SHARE_NAME)) {
			perm = HMDFS_DIR_SERVICES | level;
			cred->fsuid = DFS_SHARE_UID;
			cred->fsgid = DFS_SHARE_GID;
			break;
		}
		if (!strcmp(dentry->d_name.name, PKG_ROOT_NAME)) {
			perm = HMDFS_DIR_DATA | level;
		} else {
			perm = HMDFS_DIR_PUBLIC | level;
		}
		cred->fsuid = USER_DATA_RW_UID;
		cred->fsgid = USER_DATA_RW_GID;
		break;
	case HMDFS_PERM_PKG:
		if (is_service_dir(hii->perm)) {
			cred->fsuid = DFS_SHARE_UID;
			cred->fsgid = DFS_SHARE_GID;
			perm = AUTH_SERVICES | HMDFS_DIR_PKG | level;
			break;
		}
		if (is_data_dir(hii->perm)) {
			/*
			 * Mkdir for app pkg.
			 * Get the appid by passing pkgname to configfs.
			 * Set ROOT + media_rw for remote install,
			 * local uninstall.
			 * Set appid + media_rw for local install.
			 */
			int bid = get_bundle_uid(hmdfs_sb(dentry->d_sb),
				dentry->d_name.name);

			if (bid != 0) {
				cred->fsuid = KUIDT_INIT(bid);
				cred->fsgid = KGIDT_INIT(bid);
			} else {
				cred->fsuid = ROOT_UID;
				cred->fsgid = ROOT_GID;
			}
			perm = AUTH_PKG | HMDFS_DIR_PKG | level;
		} else {
			cred->fsuid = dir->i_uid;
			cred->fsgid = dir->i_gid;
			perm = (hii->perm & AUTH_MASK) | HMDFS_DIR_DEFAULT | level;
		}
		break;
	case HMDFS_PERM_OTHER:
		cred->fsuid = dir->i_uid;
		cred->fsgid = dir->i_gid;
		if (is_pkg_auth(hii->perm))
			perm = AUTH_PKG | HMDFS_DIR_PKG_SUB | level;
		else
			perm = (hii->perm & AUTH_MASK) | HMDFS_DIR_DEFAULT | level;
		break;
	default:
		/* ! it should not get to here */
		hmdfs_err("hmdfs perm incorrect got default case, level:%u", level);
		break;
	}

	*_perm = perm;
	old_cred = override_creds(cred);

	return old_cred;
}

int hmdfs_override_dir_id_fs(struct cache_fs_override *or,
			struct inode *dir,
			struct dentry *dentry,
			__u16 *perm)
{
	or->saved_cred = hmdfs_override_dir_fsids(dir, dentry, perm);
	if (!or->saved_cred)
		return -ENOMEM;

	or->saved_fs = current->fs;
	or->copied_fs = hmdfs_override_fsstruct(or->saved_fs);
	if (!or->copied_fs) {
		hmdfs_revert_fsids(or->saved_cred);
		return -ENOMEM;
	}

	return 0;
}

void hmdfs_revert_dir_id_fs(struct cache_fs_override *or)
{
	hmdfs_revert_fsstruct(or->saved_fs, or->copied_fs);
	hmdfs_revert_fsids(or->saved_cred);
}

const struct cred *hmdfs_override_file_fsids(struct inode *dir, __u16 *_perm)
{
	struct hmdfs_inode_info *hii = hmdfs_i(dir);
	struct cred *cred = NULL;
	const struct cred *old_cred = NULL;
	__u16 level = hmdfs_perm_get_next_level(hii->perm);
	uint16_t perm;

	perm = HMDFS_FILE_DEFAULT | level;

	cred = prepare_creds();
	if (!cred)
		return NULL;

	cred->fsuid = dir->i_uid;
	cred->fsgid = dir->i_gid;
	if (is_pkg_auth(hii->perm))
		perm = AUTH_PKG | HMDFS_FILE_PKG_SUB | level;
	else
		perm = (hii->perm & AUTH_MASK) | HMDFS_FILE_DEFAULT | level;

	*_perm = perm;
	old_cred = override_creds(cred);

	return old_cred;
}

void hmdfs_revert_fsids(const struct cred *old_cred)
{
	const struct cred *cur_cred;

	cur_cred = current->cred;
	revert_creds(old_cred);
	put_cred(cur_cred);
}

int hmdfs_persist_perm(struct dentry *dentry, __u16 *perm)
{
	int err;
	struct inode *minode = d_inode(dentry);

	if (!minode)
		return -EINVAL;

	inode_lock(minode);
	err = __vfs_setxattr(dentry, minode, HMDFS_PERM_XATTR, perm,
			     sizeof(*perm), XATTR_CREATE);
	if (!err)
		fsnotify_xattr(dentry);
	else if (err && err != -EEXIST)
		hmdfs_err("failed to setxattr, err=%d", err);
	inode_unlock(minode);
	return err;
}

__u16 hmdfs_read_perm(struct inode *inode)
{
	__u16 ret = 0;
	int size = 0;
	struct dentry *dentry = d_find_alias(inode);

	if (!dentry)
		return ret;

	size = __vfs_getxattr(dentry, inode, HMDFS_PERM_XATTR, &ret,
			     sizeof(ret));
	 /*
	  * some file may not set setxattr with perm
	  * eg. files created in sdcard dir by other user
	  **/
	if (size < 0 || size != sizeof(ret))
		ret = HMDFS_ALL_MASK;

	dput(dentry);
	return ret;
}

static __u16 __inherit_perm_dir(struct inode *parent, struct inode *inode)
{
	__u16 perm = 0;
	struct hmdfs_inode_info *info = hmdfs_i(parent);
	__u16 level = hmdfs_perm_get_next_level(info->perm);
	struct dentry *dentry = d_find_alias(inode);

	if (!dentry)
		return perm;

	switch (level) {
	case HMDFS_PERM_MNT:
		/* system : media_rw */
		perm = (info->perm & HMDFS_DIR_TYPE_MASK) | level;
		break;
	case HMDFS_PERM_DFS:
		/*
		 * data  : system : media_rw
		 * system: system : media_rw, need authority
		 * services: dfs_share : dfs_share
		 * other : media_rw : media_rw
		 **/
		if (!strcmp(dentry->d_name.name, DFS_SHARE_NAME)) {
			// "services"
			perm = HMDFS_DIR_SERVICES | level;
		} else if (!strcmp(dentry->d_name.name, PKG_ROOT_NAME)) {
			// "data"
			perm = HMDFS_DIR_DATA | level;
		} else if (!strcmp(dentry->d_name.name, SYSTEM_NAME)) {
			 // "system"
			perm = AUTH_SYSTEM | HMDFS_DIR_SYSTEM | level;
		} else {
			perm = HMDFS_DIR_PUBLIC | level;
		}
		break;
	case HMDFS_PERM_PKG:
		if (is_service_dir(info->perm)) {
			perm = AUTH_SERVICES | HMDFS_DIR_PKG | level;
			break;
		}
		if (is_data_dir(info->perm)) {
			/*
			 * Mkdir for app pkg.
			 * Get the appid by passing pkgname to configfs.
			 * Set ROOT + media_rw for remote install,
			 * local uninstall.
			 * Set appid + media_rw for local install.
			 */
			perm = AUTH_PKG | HMDFS_DIR_PKG | level;
		} else {
			perm = (info->perm & AUTH_MASK) | HMDFS_DIR_DEFAULT | level;
		}
		break;
	case HMDFS_PERM_OTHER:
		if (is_pkg_auth(info->perm))
			perm = AUTH_PKG | HMDFS_DIR_PKG_SUB | level;
		else
			perm = (info->perm & AUTH_MASK) | HMDFS_DIR_DEFAULT | level;
		break;
	default:
		/* ! it should not get to here */
		hmdfs_err("hmdfs perm incorrect got default case, level:%u", level);
		break;
	}
	dput(dentry);
	return perm;
}

static __u16 __inherit_perm_file(struct inode *parent)
{
	struct hmdfs_inode_info *hii = hmdfs_i(parent);
	__u16 level = hmdfs_perm_get_next_level(hii->perm);
	uint16_t perm;

	perm = HMDFS_FILE_DEFAULT | level;

	if (is_pkg_auth(hii->perm))
		perm = AUTH_PKG | HMDFS_FILE_PKG_SUB | level;
	else
		perm = (hii->perm & AUTH_MASK) | HMDFS_FILE_DEFAULT | level;

	return perm;
}

__u16 hmdfs_perm_inherit(struct inode *parent_inode, struct inode *child)
{
	__u16 perm;

	if (S_ISDIR(child->i_mode))
		perm = __inherit_perm_dir(parent_inode, child);
	else
		perm = __inherit_perm_file(parent_inode);
	return perm;
}

void check_and_fixup_ownership(struct inode *parent_inode, struct inode *child)
{
	struct hmdfs_inode_info *info = hmdfs_i(child);
	struct hmdfs_inode_info *dir = hmdfs_i(parent_inode);

	if (info->perm == HMDFS_ALL_MASK)
		info->perm = hmdfs_perm_inherit(parent_inode, child);
	if (is_service_dir(dir->perm))
		child->i_mode = child->i_mode | S_IRWXG;
}

void check_and_fixup_ownership_remote(struct inode *dir,
				      struct dentry *dentry)
{
	struct hmdfs_inode_info *hii = hmdfs_i(dir);
	struct inode *dinode = d_inode(dentry);
	struct hmdfs_inode_info *dinfo = hmdfs_i(dinode);
	__u16 level = hmdfs_perm_get_next_level(hii->perm);
	__u16 perm = 0;

	hmdfs_debug("level:0x%X", level);
	switch (level) {
	case HMDFS_PERM_MNT:
		/* system : media_rw */
		dinode->i_uid = USER_DATA_RW_UID;
		dinode->i_gid = USER_DATA_RW_GID;
		perm = (hii->perm & HMDFS_DIR_TYPE_MASK) | level;
		break;
	case HMDFS_PERM_DFS:
		/*
		 * data  : system : media_rw
		 * system: system : media_rw, need authority
		 * other : media_rw : media_rw
		 **/
		if (!strcmp(dentry->d_name.name, DFS_SHARE_NAME)) {
			perm = HMDFS_DIR_SERVICES | level;
			dinode->i_uid = DFS_SHARE_UID;
			dinode->i_gid = DFS_SHARE_GID;
			dinode->i_mode = dinode->i_mode | S_IRWXG;
			break;
		}
		if (!strcmp(dentry->d_name.name, PKG_ROOT_NAME)) {
			perm = HMDFS_DIR_DATA | level;
		} else {
			perm = HMDFS_DIR_PUBLIC | level;
		}
		dinode->i_uid = USER_DATA_RW_UID;
		dinode->i_gid = USER_DATA_RW_GID;
		break;
	case HMDFS_PERM_PKG:
		if (is_service_dir(hii->perm)) {
			dinode->i_uid = DFS_SHARE_UID;
			dinode->i_gid = DFS_SHARE_GID;
			dinode->i_mode = dinode->i_mode | S_IRWXG;
			perm = AUTH_SERVICES | HMDFS_DIR_PKG | level;
			break;
		}
		if (is_data_dir(hii->perm)) {
			/*
			 * Mkdir for app pkg.
			 * Get the appid by passing pkgname to configfs.
			 * Set ROOT + media_rw for remote install,
			 * local uninstall.
			 * Set appid + media_rw for local install.
			 */
			int bid = get_bundle_uid(hmdfs_sb(dentry->d_sb),
				dentry->d_name.name);
			if (bid != 0) {
				dinode->i_uid = KUIDT_INIT(bid);
				dinode->i_gid = KGIDT_INIT(bid);
			} else {
				dinode->i_uid = ROOT_UID;
				dinode->i_gid = ROOT_GID;
			}
			perm = AUTH_PKG | HMDFS_DIR_PKG | level;
		} else {
			dinode->i_uid = dir->i_uid;
			dinode->i_gid = dir->i_gid;
			perm = (hii->perm & AUTH_MASK) | HMDFS_DIR_DEFAULT | level;
		}
		break;
	case HMDFS_PERM_OTHER:
		dinode->i_uid = dir->i_uid;
		dinode->i_gid = dir->i_gid;
		if (is_service_auth(hii->perm)) {
			dinode->i_mode = dir->i_mode | S_IRWXG;
			perm = AUTH_PKG | HMDFS_DIR_PKG_SUB | level;
			break;
		}
		if (is_pkg_auth(hii->perm))
			perm = AUTH_PKG | HMDFS_DIR_PKG_SUB | level;
		else
			perm = (hii->perm & AUTH_MASK) | HMDFS_DIR_DEFAULT | level;
		break;
	default:
		/* ! it should not get to here */
		hmdfs_err("hmdfs perm incorrect got default case, level:%u", level);
		break;
	}

	dinfo->perm = perm;
}

void hmdfs_root_inode_perm_init(struct inode *root_inode)
{
	struct hmdfs_inode_info *hii = hmdfs_i(root_inode);

	hii->perm = HMDFS_DIR_ROOT | HMDFS_PERM_MNT;
	set_inode_uid(root_inode, USER_DATA_RW_UID);
	set_inode_gid(root_inode, USER_DATA_RW_GID);
}
