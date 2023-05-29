// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2022 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2022 Stony Brook University
 * Copyright (c) 2003-2022 The Research Foundation of SUNY
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _SHAREFS_H_
#define _SHAREFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>

/* the file system name */
#define SHAREFS_NAME "sharefs"

/* sharefs root inode number */
#define SHAREFS_ROOT_INO        1
#define OID_ROOT             	0
#define ROOT_UID 		KUIDT_INIT(OID_ROOT)
#define ROOT_GID 		KGIDT_INIT(OID_ROOT)
#define SHAREFS_SUPER_MAGIC 0x20230212

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* file private data */
struct sharefs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* sharefs inode data in memory */
struct sharefs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
	__u16 perm;
};

/* sharefs dentry data in memory */
struct sharefs_dentry_info {
	spinlock_t lock; /* protects lower_path */
	struct path lower_path;
};

/* sharefs super-block data in memory */
struct sharefs_sb_info {
	struct super_block *lower_sb;
	/* multi user */
	unsigned int user_id;
};

/* operations vectors defined in specific files */
extern const struct file_operations sharefs_main_fops;
extern const struct file_operations sharefs_dir_fops;
extern const struct inode_operations sharefs_main_iops;
extern const struct inode_operations sharefs_dir_iops;
extern const struct inode_operations sharefs_symlink_iops;
extern const struct super_operations sharefs_sops;
extern const struct dentry_operations sharefs_dops;

extern int sharefs_init_inode_cache(void);
extern void sharefs_destroy_inode_cache(void);
extern int sharefs_init_dentry_cache(void);
extern void sharefs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *sharefs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags);
extern struct inode *sharefs_iget(struct super_block *sb,
				  struct inode *lower_inode);
extern int sharefs_interpose(struct dentry *dentry, struct super_block *sb,
			     struct path *lower_path);
extern int vfs_path_lookup(struct dentry *dentry, struct vfsmount *mnt,
			   const char *name, unsigned int flags,
			   struct path *path);
extern int sharefs_parse_options(struct sharefs_sb_info *sbi,
				 const char *data);

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * sharefs_inode_info structure, SHAREFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct sharefs_inode_info *SHAREFS_I(const struct inode *inode)
{
	return container_of(inode, struct sharefs_inode_info, vfs_inode);
}

/* dentry to private data */
#define SHAREFS_D(dent) ((struct sharefs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define SHAREFS_SB(super) ((struct sharefs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define SHAREFS_F(file) ((struct sharefs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *sharefs_lower_file(const struct file *f)
{
	return SHAREFS_F(f)->lower_file;
}

static inline void sharefs_set_lower_file(struct file *f, struct file *val)
{
	SHAREFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *sharefs_lower_inode(const struct inode *i)
{
	return SHAREFS_I(i)->lower_inode;
}

static inline void sharefs_set_lower_inode(struct inode *i, struct inode *val)
{
	SHAREFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *sharefs_lower_super(
	const struct super_block *sb)
{
	return SHAREFS_SB(sb)->lower_sb;
}

static inline void sharefs_set_lower_super(struct super_block *sb,
					   struct super_block *val)
{
	SHAREFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void sharefs_get_lower_path(const struct dentry *dent,
					  struct path *lower_path)
{
	spin_lock(&SHAREFS_D(dent)->lock);
	pathcpy(lower_path, &SHAREFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&SHAREFS_D(dent)->lock);
	return;
}
static inline void sharefs_put_lower_path(const struct dentry *dent,
					  struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void sharefs_set_lower_path(const struct dentry *dent,
					  struct path *lower_path)
{
	spin_lock(&SHAREFS_D(dent)->lock);
	pathcpy(&SHAREFS_D(dent)->lower_path, lower_path);
	spin_unlock(&SHAREFS_D(dent)->lock);
	return;
}
static inline void sharefs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&SHAREFS_D(dent)->lock);
	SHAREFS_D(dent)->lower_path.dentry = NULL;
	SHAREFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SHAREFS_D(dent)->lock);
	return;
}
static inline void sharefs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&SHAREFS_D(dent)->lock);
	pathcpy(&lower_path, &SHAREFS_D(dent)->lower_path);
	SHAREFS_D(dent)->lower_path.dentry = NULL;
	SHAREFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SHAREFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}

static inline bool str_n_case_eq(const char *s1, const char *s2, size_t len)
{
	return !strncasecmp(s1, s2, len);
}

static inline bool qstr_case_eq(const struct qstr *q1, const struct qstr *q2)
{
	return q1->len == q2->len && str_n_case_eq(q1->name, q2->name, q2->len);
}
/*****************************************************************************
 * log print helpers
 *****************************************************************************/
__printf(4, 5) void __sharefs_log(const char *level, const bool ratelimited,
				const char *function, const char *fmt, ...);
#define sharefs_err(fmt, ...)	\
	__sharefs_log(KERN_ERR, false, __func__, fmt, ##__VA_ARGS__)
#define sharefs_warning(fmt, ...) \
	__sharefs_log(KERN_WARNING, false, __func__, fmt, ##__VA_ARGS__)
#define sharefs_info(fmt, ...) \
	__sharefs_log(KERN_INFO, false, __func__, fmt, ##__VA_ARGS__)
#define sharefs_err_ratelimited(fmt, ...)	\
	__sharefs_log(KERN_ERR, true, __func__, fmt, ##__VA_ARGS__)
#define sharefs_warning_ratelimited(fmt, ...) \
	__sharefs_log(KERN_WARNING, true, __func__, fmt, ##__VA_ARGS__)
#define sharefs_info_ratelimited(fmt, ...) \
	__sharefs_log(KERN_INFO, true, __func__, fmt, ##__VA_ARGS__)

#endif /* not _SHAREFS_H_ */
