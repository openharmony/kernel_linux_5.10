// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2022 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2022 Stony Brook University
 * Copyright (c) 2003-2022 The Research Foundation of SUNY
 */
#include <linux/backing-dev-defs.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include "sharefs.h"

enum {
	OPT_USER_ID,
        OPT_ERR,
};

static match_table_t sharefs_tokens = {
	{ OPT_USER_ID, "user_id=%s" },
        { OPT_ERR, NULL }
};

int sharefs_parse_options(struct sharefs_sb_info *sbi, const char *data)
{
	char *p = NULL;
	char *name = NULL;
	char *options = NULL;
	char *options_src = NULL;
	substring_t args[MAX_OPT_ARGS];
	unsigned int user_id = 0;
	int err = 0;

	options = kstrdup(data, GFP_KERNEL);
	if (data && !options) {
		err = -ENOMEM;
		goto out;
	}
	options_src = options;

	while ((p = strsep(&options_src, ",")) != NULL) {
		int token;

		if (!*p)
			continue;
		args[0].to = args[0].from = NULL;
		token = match_token(p, sharefs_tokens, args);

		switch (token) {
		case OPT_USER_ID:
			name = match_strdup(&args[0]);
			if (name) {
				err = kstrtouint(name, 10, &user_id);
				kfree(name);
				name = NULL;
				if (err)
					goto out;
				sbi->user_id = user_id;
			}
			break;
		default:
			err = -EINVAL;
			goto out;
		}
	}
out:
	kfree(options);

	return err;
}

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *sharefs_inode_cachep;

/* final actions when unmounting a file system */
static void sharefs_put_super(struct super_block *sb)
{
	struct sharefs_sb_info *spd;
	struct super_block *s;

	spd = SHAREFS_SB(sb);
	if (!spd)
		return;

	/* decrement lower super references */
	s = sharefs_lower_super(sb);
	sharefs_set_lower_super(sb, NULL);
	atomic_dec(&s->s_active);

	kfree(spd);
	sb->s_fs_info = NULL;
}

static int sharefs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path;

	sharefs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	sharefs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = SHAREFS_SUPER_MAGIC;

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void sharefs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = sharefs_lower_inode(inode);
	sharefs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

void __sharefs_log(const char *level, const bool ratelimited,
		 const char *function, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	if (ratelimited)
		printk_ratelimited("%s sharefs: %s() %pV\n", level,
				   function, &vaf);
	else
		printk("%s sharefs: %s() %pV\n", level, function, &vaf);
	va_end(args);
}

static struct inode *sharefs_alloc_inode(struct super_block *sb)
{
	struct sharefs_inode_info *i;

	i = kmem_cache_alloc(sharefs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct sharefs_inode_info, vfs_inode));

        atomic64_set(&i->vfs_inode.i_version, 1);
	return &i->vfs_inode;
}

static void sharefs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(sharefs_inode_cachep, SHAREFS_I(inode));
}

/* sharefs inode cache constructor */
static void init_once(void *obj)
{
	struct sharefs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int sharefs_init_inode_cache(void)
{
	int err = 0;

	sharefs_inode_cachep =
		kmem_cache_create("sharefs_inode_cache",
				  sizeof(struct sharefs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!sharefs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* sharefs inode cache destructor */
void sharefs_destroy_inode_cache(void)
{
	if (sharefs_inode_cachep)
		kmem_cache_destroy(sharefs_inode_cachep);
}

const struct super_operations sharefs_sops = {
	.put_super	= sharefs_put_super,
	.statfs		= sharefs_statfs,
	.evict_inode	= sharefs_evict_inode,
	.alloc_inode	= sharefs_alloc_inode,
	.destroy_inode	= sharefs_destroy_inode,
};
