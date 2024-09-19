// SPDX-License-Identifier: GPL-2.0
/*
 * access_tokenid.c
 *
 * Copyright (C) 2022-2023 Huawei Technologies Co., Ltd. All rights reserved.
 *
 */

#define pr_fmt(fmt) "access_token_id: " fmt

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "access_tokenid.h"

DEFINE_RWLOCK(token_rwlock);
#define ACCESS_TOKEN_UID KUIDT_INIT(3020)
#define MAX_NODE_NUM 500
#define UINT32_T_BITS 32

static struct kmem_cache *g_cache = NULL;
static struct token_perm_node *g_token_perm_root = NULL;
static size_t g_total_node_num = 0;

int access_tokenid_get_tokenid(struct file *file, void __user *uarg)
{
	return copy_to_user(uarg, &current->token,
			    sizeof(current->token)) ? -EFAULT : 0;
}

static bool check_permission_for_set_tokenid(struct file *file, unsigned long long tokenid)
{
	kuid_t uid = current_uid();
	struct inode *inode = file->f_inode;
	access_tokenid_inner *tokenid_inner = (access_tokenid_inner *)&tokenid;

	if (inode == NULL) {
		pr_err("%s: file inode is null\n", __func__);
		return false;
	}

	if (uid_eq(uid, GLOBAL_ROOT_UID) ||
	    uid_eq(uid, inode->i_uid)) {
		return true;
	} else if (uid_eq(uid, NWEBSPAWN_UID) && (tokenid_inner->render_flag == 1)) {
		return true;
	}

	return false;
}

int access_tokenid_set_tokenid(struct file *file, void __user *uarg)
{
	unsigned long long tmp = 0;

	if (copy_from_user(&tmp, uarg, sizeof(tmp)))
		return -EFAULT;

	if (!check_permission_for_set_tokenid(file, tmp))
		return -EPERM;

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

static bool check_permission_for_set_token_permission()
{
	kuid_t uid = current_uid();
	return uid_eq(uid, ACCESS_TOKEN_UID);
}

static void add_node_to_left_tree_tail(struct token_perm_node *root_node, struct token_perm_node *node)
{
	if ((root_node == NULL) || (node == NULL))
		return;

	struct token_perm_node *current_node = root_node;
	while (true) {
		if (current_node->left == NULL) {
			current_node->left = node;
			break;
		}
		current_node = current_node->left;
	}
}

static void find_node_by_token(struct token_perm_node *root_node, uint32_t token,
	struct token_perm_node **target_node, struct token_perm_node **parent_node)
{
	*target_node = NULL;
	*parent_node = NULL;
	struct token_perm_node *current_node = root_node;
	while (current_node != NULL) {
		if (current_node->perm_data.token == token) {
			*target_node = current_node;
			break;
		}
		*parent_node = current_node;
		if (current_node->perm_data.token > token) {
			current_node = current_node->left;
		} else {
			current_node = current_node->right;
		}
	}
}

static int add_node_to_tree(struct token_perm_node **root_node, struct token_perm_node *node)
{
	if (root_node == NULL) {
		pr_err("%s: invalid root_node.\n", __func__);
		return -EINVAL;
	}
	struct token_perm_node *target_node = NULL;
	struct token_perm_node *parent_node = NULL;
	find_node_by_token(*root_node, node->perm_data.token, &target_node, &parent_node);
	if (target_node != NULL) {
		target_node->perm_data = node->perm_data;
		return 0;
	}
	if (g_total_node_num >= MAX_NODE_NUM) {
		pr_err("%s: the number of token nodes is exceeded.\n", __func__);
		return -EDQUOT;
	}
	if (parent_node == NULL) {
		*root_node = node;
	} else if (parent_node->perm_data.token > node->perm_data.token) {
		parent_node->left = node;
	} else {
		parent_node->right = node;
	}
	g_total_node_num++;
	return 1;
}

static struct token_perm_node *remove_node_by_token(struct token_perm_node **root_node, uint32_t token)
{
	if (root_node == NULL) {
		pr_err("%s: invalid root_node.\n", __func__);
		return NULL;
	}
	struct token_perm_node *target_node = NULL;
	struct token_perm_node *parent_node = NULL;
	find_node_by_token(*root_node, token, &target_node, &parent_node);
	if (target_node == NULL) {
		pr_err("%s: target token to be removed not found.\n", __func__);
		return NULL;
	}

	struct token_perm_node **new_node_addr = NULL;
	if (parent_node == NULL) {
		new_node_addr = root_node;
	} else if (parent_node->perm_data.token > token) {
		new_node_addr = &(parent_node->left);
	} else {
		new_node_addr = &(parent_node->right);
	}
	if (target_node->right != NULL) {
		*new_node_addr = target_node->right;
		add_node_to_left_tree_tail(target_node->right, target_node->left);
	} else {
		*new_node_addr = target_node->left;
	}
	g_total_node_num--;
	return target_node;
}

int access_tokenid_add_permission(struct file *file, void __user *uarg)
{
	if (!check_permission_for_set_token_permission())
		return -EPERM;

	struct token_perm_node *node = kmem_cache_zalloc(g_cache, GFP_KERNEL);
	if (node == NULL)
		return -ENOMEM;
	if (copy_from_user(&(node->perm_data), uarg, sizeof(ioctl_add_perm_data))) {
		kmem_cache_free(g_cache, node);
		return -EFAULT;
	}

	write_lock(&token_rwlock);
	int ret = add_node_to_tree(&g_token_perm_root, node);
	write_unlock(&token_rwlock);
	if (ret <= 0) {
		kmem_cache_free(g_cache, node);
		return ret;
	}
	return 0;
}

int access_tokenid_remove_permission(struct file *file, void __user *uarg)
{
	if (!check_permission_for_set_token_permission())
		return -EPERM;

	uint32_t token = 0;
	if (copy_from_user(&token, uarg, sizeof(token)))
		return -EFAULT;

	write_lock(&token_rwlock);
	struct token_perm_node *target_node = remove_node_by_token(&g_token_perm_root, token);
	if (target_node != NULL)
		kmem_cache_free(g_cache, target_node);
	write_unlock(&token_rwlock);

	return 0;
}

int access_tokenid_set_permission(struct file *file, void __user *uarg)
{
	if (!check_permission_for_set_token_permission())
		return -EPERM;

	ioctl_set_get_perm_data set_perm_data;
	if (copy_from_user(&set_perm_data, uarg, sizeof(set_perm_data)))
		return -EFAULT;

	uint32_t idx = set_perm_data.op_code / UINT32_T_BITS;
	if (idx >= MAX_PERM_GROUP_NUM) {
		pr_err("%s: invalid op_code.\n", __func__);
		return -EINVAL;
	}

	struct token_perm_node *target_node = NULL;
	struct token_perm_node *parent_node = NULL;
	write_lock(&token_rwlock);
	find_node_by_token(g_token_perm_root, set_perm_data.token, &target_node, &parent_node);
	if (target_node == NULL) {
		write_unlock(&token_rwlock);
		pr_err("%s: token not found.\n", __func__);
		return -ENODATA;
	}
	uint32_t bit_idx = set_perm_data.op_code % UINT32_T_BITS;
	if (set_perm_data.is_granted) {
		target_node->perm_data.perm[idx] |= (uint32_t)0x01 << bit_idx;
	} else {
		target_node->perm_data.perm[idx] &= ~((uint32_t)0x01 << bit_idx);
	}
	write_unlock(&token_rwlock);
	return 0;
}

int access_tokenid_get_permission(struct file *file, void __user *uarg)
{
	ioctl_set_get_perm_data get_perm_data;
	if (copy_from_user(&get_perm_data, uarg, sizeof(get_perm_data)))
		return -EFAULT;

	uint32_t idx = get_perm_data.op_code / UINT32_T_BITS;
	if (idx >= MAX_PERM_GROUP_NUM) {
		pr_err("%s: invalid op_code.\n", __func__);
		return -EINVAL;
	}

	struct token_perm_node *target_node = NULL;
	struct token_perm_node *parent_node = NULL;
	read_lock(&token_rwlock);
	find_node_by_token(g_token_perm_root, get_perm_data.token, &target_node, &parent_node);
	if (target_node == NULL) {
		read_unlock(&token_rwlock);
		return -ENODATA;
	}

	uint32_t bit_idx = get_perm_data.op_code % UINT32_T_BITS;
	int ret = (target_node->perm_data.perm[idx] & ((uint32_t)0x01 << bit_idx)) >> bit_idx;
	read_unlock(&token_rwlock);
	return ret;
}

typedef int (*access_token_id_func)(struct file *file, void __user *arg);

static access_token_id_func g_func_array[ACCESS_TOKENID_MAX_NR] = {
	NULL, /* reserved */
	access_tokenid_get_tokenid,
	access_tokenid_set_tokenid,
	access_tokenid_get_ftokenid,
	access_tokenid_set_ftokenid,
	access_tokenid_add_permission,
	access_tokenid_remove_permission,
	access_tokenid_get_permission,
	access_tokenid_set_permission,
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

	g_cache = kmem_cache_create("access_token_node", sizeof(struct token_perm_node), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (g_cache == NULL) {
		pr_err("access_tokenid kmem_cache create failed\n");
		return -ENOMEM;
	}
	pr_info("access_tokenid init success\n");
	return 0;
}

static void access_tokenid_exit_module(void)
{
	kmem_cache_destroy(g_cache);
	misc_deregister(&access_tokenid_device);
}

/* module entry points */
module_init(access_tokenid_init_module);
module_exit(access_tokenid_exit_module);
