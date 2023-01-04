// SPDX-License-Identifier: GPL-2.0
/*
 * access_tokenid.c
 *
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 *
 */

#define pr_fmt(fmt) "access_token_id: " fmt

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/sched.h>
#include "access_tokenid.h"

int access_tokenid_get_tokenid(struct file *file, void __user *uarg)
{
	return copy_to_user(uarg, &current->token,
			    sizeof(current->token)) ? -EFAULT : 0;
}

static bool check_permission_for_set_tokenid(struct file *file)
{
	kuid_t uid = current_uid();
	struct inode *inode = file->f_inode;

	if (inode == NULL) {
		pr_err("%s: file inode is null\n", __func__);
		return false;
	}

	if (uid_eq(uid, GLOBAL_ROOT_UID) ||
	    uid_eq(uid, inode->i_uid)) {
		return true;
	}

	return false;
}

int access_tokenid_set_tokenid(struct file *file, void __user *uarg)
{
	unsigned long long tmp = 0;

	if (!check_permission_for_set_tokenid(file))
		return -EPERM;

	if (copy_from_user(&tmp, uarg, sizeof(tmp)))
		return -EFAULT;

	current->token = tmp;
	return 0;
}

static bool check_permission_for_ftokenid(struct file *file)
{
	int i;
	struct group_info *group_info;
	kuid_t uid = current_uid();
	struct inode *inode = file->f_inode;

	if (inode == NULL) {
		pr_err("%s: file inode is null\n", __func__);
		return false;
	}

	if (uid_eq(uid, GLOBAL_ROOT_UID))
		return true;

	group_info = get_current_groups();
	for (i = 0; i < group_info->ngroups; i++) {
		kgid_t gid = group_info->gid[i];

		if (gid_eq(gid, inode->i_gid)) {
			put_group_info(group_info);
			return true;
		}
	}

	put_group_info(group_info);
	return false;
}

int access_tokenid_get_ftokenid(struct file *file, void __user *uarg)
{
	if (!check_permission_for_ftokenid(file))
		return -EPERM;

	return copy_to_user(uarg, &current->ftoken,
			    sizeof(current->ftoken)) ? -EFAULT : 0;
}

int access_tokenid_set_ftokenid(struct file *file, void __user *uarg)
{
	unsigned long long tmp = 0;

	if (!check_permission_for_ftokenid(file))
		return -EPERM;

	if (copy_from_user(&tmp, uarg, sizeof(tmp)))
		return -EFAULT;

	current->ftoken = tmp;
	return 0;
}

typedef int (*access_token_id_func)(struct file *file, void __user *arg);

static access_token_id_func g_func_array[ACCESS_TOKENID_MAX_NR] = {
	NULL, /* reserved */
	access_tokenid_get_tokenid,
	access_tokenid_set_tokenid,
	access_tokenid_get_ftokenid,
	access_tokenid_set_ftokenid,
};

static long access_tokenid_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	unsigned int func_cmd = _IOC_NR(cmd);

	if (uarg == NULL) {
		pr_err("%s: invalid user uarg\n", __func__);
		return -EINVAL;
	}

	if (_IOC_TYPE(cmd) != ACCESS_TOKEN_ID_IOCTL_BASE) {
		pr_err("%s: access tokenid magic fail, TYPE=%d\n",
		       __func__, _IOC_TYPE(cmd));
		return -EINVAL;
	}

	if (func_cmd >= ACCESS_TOKENID_MAX_NR) {
		pr_err("%s: access tokenid cmd error, cmd:%d\n",
			__func__, func_cmd);
		return -EINVAL;
	}

	if (g_func_array[func_cmd])
		return (*g_func_array[func_cmd])(file, uarg);

	return -EINVAL;
}

static const struct file_operations access_tokenid_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= access_tokenid_ioctl,
	.compat_ioctl	= access_tokenid_ioctl,
};

static struct miscdevice access_tokenid_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "access_token_id",
	.fops	= &access_tokenid_fops,
};

static int access_tokenid_init_module(void)
{
	int err;

	err = misc_register(&access_tokenid_device);
	if (err < 0) {
		pr_err("access_tokenid register failed\n");
		return err;
	}

	pr_info("access_tokenid init success\n");
	return 0;
}

static void access_tokenid_exit_module(void)
{
	misc_deregister(&access_tokenid_device);
}

/* module entry points */
module_init(access_tokenid_init_module);
module_exit(access_tokenid_exit_module);
