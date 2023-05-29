// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/sharefs/main.c
 *
 * Copyright (c) 1998-2022 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2022 Stony Brook University
 * Copyright (c) 2003-2022 The Research Foundation of SUNY
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/module.h>
#include "sharefs.h"
#include "authentication.h"


struct sharefs_mount_priv {
	const char *dev_name;
	const char *raw_data;
};

/*
 * There is no need to lock the sharefs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sharefs_fill_super(struct super_block *sb, void *data, int silent)
{

	struct sharefs_mount_priv *priv = (struct sharefs_mount_priv *)data;
	const char *dev_name = priv->dev_name;
	const char *raw_data = priv->raw_data;

	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	struct inode *inode;

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sharefs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sharefs_sb_info), GFP_KERNEL);
	if (!SHAREFS_SB(sb)) {
		printk(KERN_CRIT "sharefs: fill_super: out of memory\n");
		err = -ENOMEM;
		goto out_pput;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sharefs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sharefs_sops;

	/* get a new inode and allocate our root dentry */
	inode = sharefs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_pput;
	}
	sharefs_root_inode_perm_init(inode);
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_pput;
	}
	d_set_d_op(sb->s_root, &sharefs_dops);

	err = sharefs_parse_options(sb->s_fs_info, raw_data);
	if (err)
		goto out_pput;

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_pput;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sharefs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "sharefs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/*
	 * path_put is the only resource we need to free if an error occurred
	 * because returning an error from this function will cause
	 * generic_shutdown_super to be called, which will call
	 * sharefs_put_super, and that function will release any other
	 * resources we took.
	 */
out_pput:
	path_put(&lower_path);
out:
	return err;
}

struct dentry *sharefs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	struct sharefs_mount_priv priv = {
		.dev_name = dev_name,
		.raw_data = raw_data,
	};

	/* sharefs needs a valid dev_name to get the lower_sb's metadata */
	if (!dev_name || !*dev_name)
		return ERR_PTR(-EINVAL);

	return mount_nodev(fs_type, flags, &priv,
			   sharefs_fill_super);
}

static struct file_system_type sharefs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SHAREFS_NAME,
	.mount		= sharefs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SHAREFS_NAME);

static int __init init_sharefs_fs(void)
{
	int err;

	pr_info("Registering sharefs");

	err = sharefs_init_inode_cache();
	if (err)
		goto out_err;
	err = sharefs_init_dentry_cache();
	if (err)
		goto out_err;
	err = register_filesystem(&sharefs_fs_type);
	if (err) {
		sharefs_err("share register failed!");
		goto out_err;
	}

	err = sharefs_init_configfs();
	if (err)
		goto out_err;
	return 0;
out_err:
	sharefs_exit_configfs();
	sharefs_destroy_inode_cache();
	sharefs_destroy_dentry_cache();
	sharefs_err("sharefs init failed!");
	return err;
}

static void __exit exit_sharefs_fs(void)
{
	sharefs_destroy_inode_cache();
	sharefs_destroy_dentry_cache();
	unregister_filesystem(&sharefs_fs_type);
	pr_info("Completed sharefs module unload\n");
}

MODULE_AUTHOR("Jingjing Mao");
MODULE_DESCRIPTION("Sharefs");
MODULE_LICENSE("GPL");

module_init(init_sharefs_fs);
module_exit(exit_sharefs_fs);
