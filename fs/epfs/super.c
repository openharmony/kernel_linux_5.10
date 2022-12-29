// SPDX-License-Identifier: GPL-2.0
/*
 * fs/epfs/super.c
 *
 * Copyright (c) 2022 Huawei Technologies Co., Ltd.
 * Author: weilongping@huawei.com
 * Create: 2022-06-10
 */
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/version.h>

#include "internal.h"

static struct inode *epfs_alloc_inode(struct super_block *sb)
{
	struct epfs_inode_info *info =
		kmem_cache_zalloc(epfs_inode_cachep, GFP_KERNEL);
	if (IS_ENABLED(CONFIG_EPFS_DEBUG))
		epfs_debug("inode info: %p", info);
	inode_init_once(&info->vfs_inode);
	mutex_init(&info->lock);
	return &info->vfs_inode;
}

// Free epfs_inode_info
static void epfs_free_inode(struct inode *inode)
{
	if (IS_ENABLED(CONFIG_EPFS_DEBUG))
		epfs_debug("free_inode: %p", inode);
	kmem_cache_free(epfs_inode_cachep,
			epfs_inode_to_private(inode));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
static void i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	epfs_free_inode(inode);
}
#endif

// Destroy epfs_range
static void epfs_destroy_inode(struct inode *inode)
{
	struct epfs_inode_info *info = epfs_inode_to_private(inode);

	mutex_lock(&info->lock);
	kfree(info->range);
	info->range = NULL;
	mutex_unlock(&info->lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	call_rcu(&inode->i_rcu, i_callback);
#endif
}

// Clear vfs_inode
static void epfs_evict_inode(struct inode *inode)
{
	struct epfs_inode_info *info = epfs_inode_to_private(inode);

	clear_inode(inode);
	mutex_lock(&info->lock);
	if (info->origin_file) {
		fput(info->origin_file);
		info->origin_file = NULL;
	}
	mutex_unlock(&info->lock);
}

static int epfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	buf->f_type = EPFS_SUPER_MAGIC;
	return 0;
}
struct super_operations epfs_sops = {
	.alloc_inode = epfs_alloc_inode,
	.destroy_inode = epfs_destroy_inode,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	.free_inode = epfs_free_inode,
#endif
	.evict_inode = epfs_evict_inode,
	.statfs = epfs_statfs,
};

static int epfs_fill_super(struct super_block *s, void *data, int silent)
{
	struct inode *inode;

	s->s_op = &epfs_sops;
	s->s_d_op = &epfs_dops;
	s->s_magic = EPFS_SUPER_MAGIC;
	inode = epfs_iget(s, true /* dir */);
	if (!inode) {
		epfs_err("Failed to get root inode!");
		return -ENOMEM;
	}

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		epfs_err("Failed to make root inode");
		return -ENOMEM;
	}

	return 0;
}

struct dentry *epfs_mount(struct file_system_type *fs_type, int flags,
			       const char *dev_name, void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, epfs_fill_super);
}

void epfs_kill_sb(struct super_block *sb)
{
	kill_anon_super(sb);
}

struct file_system_type epfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "epfs",
	.mount = epfs_mount,
	.kill_sb = epfs_kill_sb,
};
