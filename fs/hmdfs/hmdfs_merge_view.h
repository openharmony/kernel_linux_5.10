/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_merge_view.h
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#ifndef HMDFS_MERGE_VIEW_H
#define HMDFS_MERGE_VIEW_H

#include "hmdfs.h"

#include "comm/connection.h"
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

/*****************************************************************************
 * Dentires for merge view and their comrades.
 * A dentry's lower dentry is named COMRADE.
 *****************************************************************************/

struct merge_lookup_work {
	char *name;
	int devid;
	unsigned int flags;
	struct hmdfs_sb_info *sbi;
	wait_queue_head_t *wait_queue;
	struct work_struct work;
};

struct hmdfs_dentry_info_merge {
	unsigned long ctime;
	int type;
	int work_count;
	struct mutex work_lock;
	wait_queue_head_t wait_queue;
	__u8 dentry_type;
	struct mutex comrade_list_lock;
	struct list_head comrade_list;
};

struct hmdfs_dentry_comrade {
	uint64_t dev_id;
	struct dentry *lo_d;
	struct list_head list;
};

enum FILE_CMD_MERGE {
	F_MKDIR_MERGE = 0,
	F_CREATE_MERGE = 1,
};

struct hmdfs_recursive_para {
	bool is_last;
	int opcode;
	umode_t mode;
	bool want_excl;
	const char *name;
};

static inline struct hmdfs_dentry_info_merge *hmdfs_dm(struct dentry *dentry)
{
	return dentry->d_fsdata;
}

static inline umode_t hmdfs_cm(struct hmdfs_dentry_comrade *comrade)
{
	return d_inode(comrade->lo_d)->i_mode;
}

static inline bool comrade_is_local(struct hmdfs_dentry_comrade *comrade)
{
	return comrade->dev_id == HMDFS_DEVID_LOCAL;
}

struct hmdfs_cache_entry *allocate_entry(const char *name, int namelen,
					 int d_type);

struct dentry *hmdfs_lookup_cloud_merge(struct inode *parent_inode,
				  struct dentry *child_dentry,
				  unsigned int flags);

struct dentry *hmdfs_lookup_merge(struct inode *parent_inode,
				  struct dentry *child_dentry,
				  unsigned int flags);
struct hmdfs_file_info *
get_next_hmdfs_file_info(struct hmdfs_file_info *fi_head, int device_id);

struct hmdfs_file_info *get_hmdfs_file_info(struct hmdfs_file_info *fi_head,
					    int device_id);
int insert_filename(struct rb_root *root, struct hmdfs_cache_entry **new_entry);
struct hmdfs_dentry_comrade *alloc_comrade(struct dentry *lo_d, int dev_id);
int check_filename(const char *name, int len);
int init_hmdfs_dentry_info_merge(struct hmdfs_sb_info *sbi,
	struct dentry *dentry);
void hmdfs_init_recursive_para(struct hmdfs_recursive_para *rec_op_para,
			       int opcode, mode_t mode, bool want_excl,
			       const char *name);
void link_comrade(struct list_head *onstack_comrades_head,
		  struct hmdfs_dentry_comrade *comrade);
void update_inode_attr(struct inode *inode, struct dentry *child_dentry);
int get_num_comrades(struct dentry *dentry);
void assign_comrades_unlocked(struct dentry *child_dentry,
			      struct list_head *onstack_comrades_head);
struct hmdfs_dentry_comrade *lookup_comrade(struct path lower_path,
					    const char *d_name,
					    int dev_id,
					    unsigned int flags);
int merge_lookup_async(struct hmdfs_dentry_info_merge *mdi,
		       struct hmdfs_sb_info *sbi, int devid,
		       const char *name, unsigned int flags);
char *hmdfs_get_real_dname(struct dentry *dentry, int *devid, int *type);
void lock_root_inode_shared(struct inode *root, bool *locked, bool *down);
void restore_root_inode_sem(struct inode *root, bool locked, bool down);
int hmdfs_getattr_merge(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int flags);
int hmdfs_setattr_merge(struct dentry *dentry, struct iattr *ia);
int hmdfs_rmdir_merge(struct inode *dir, struct dentry *dentry);
int hmdfs_unlink_merge(struct inode *dir, struct dentry *dentry);
int hmdfs_rename_merge(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags);

static inline void destroy_comrade(struct hmdfs_dentry_comrade *comrade)
{
	dput(comrade->lo_d);
	kfree(comrade);
}

void clear_comrades(struct dentry *dentry);

static inline void link_comrade_unlocked(struct dentry *dentry,
					 struct hmdfs_dentry_comrade *comrade)
{
	mutex_lock(&hmdfs_dm(dentry)->comrade_list_lock);
	link_comrade(&hmdfs_dm(dentry)->comrade_list, comrade);
	mutex_unlock(&hmdfs_dm(dentry)->comrade_list_lock);
}

void clear_comrades_locked(struct list_head *comrade_list);

static inline bool is_comrade_list_empty(struct hmdfs_dentry_info_merge *mdi)
{
	bool ret;

	mutex_lock(&mdi->comrade_list_lock);
	ret = list_empty(&mdi->comrade_list);
	mutex_unlock(&mdi->comrade_list_lock);

	return ret;
}

static inline bool has_merge_lookup_work(struct hmdfs_dentry_info_merge *mdi)
{
	bool ret;

	mutex_lock(&mdi->work_lock);
	ret = (mdi->work_count != 0);
	mutex_unlock(&mdi->work_lock);

	return ret;
}

static inline bool is_merge_lookup_end(struct hmdfs_dentry_info_merge *mdi)
{
	bool ret;

	mutex_lock(&mdi->work_lock);
	ret = mdi->work_count == 0 || !is_comrade_list_empty(mdi);
	mutex_unlock(&mdi->work_lock);

	return ret;
}

#define for_each_comrade_locked(_dentry, _comrade)                             \
	list_for_each_entry(_comrade, &(hmdfs_dm(_dentry)->comrade_list), list)

#define hmdfs_trace_merge(_trace_func, _parent_inode, _child_dentry, err)      \
	{                                                                      \
		struct hmdfs_dentry_comrade *comrade;                          \
		struct hmdfs_dentry_info_merge *dm = hmdfs_dm(_child_dentry);  \
		_trace_func(_parent_inode, _child_dentry, err);                \
		if (likely(dm)) {                                              \
			mutex_lock(&dm->comrade_list_lock);                    \
			for_each_comrade_locked(_child_dentry, comrade)        \
				trace_hmdfs_show_comrade(_child_dentry,        \
							 comrade->lo_d,        \
							 comrade->dev_id);     \
			mutex_unlock(&dm->comrade_list_lock);                  \
		}                                                              \
	}

#define hmdfs_trace_rename_merge(olddir, olddentry, newdir, newdentry, err)    \
	{                                                                      \
		struct hmdfs_dentry_comrade *comrade;                          \
		trace_hmdfs_rename_merge(olddir, olddentry, newdir, newdentry, \
					 err);                                 \
		mutex_lock(&hmdfs_dm(olddentry)->comrade_list_lock);           \
		for_each_comrade_locked(olddentry, comrade)                    \
			trace_hmdfs_show_comrade(olddentry, comrade->lo_d,     \
						 comrade->dev_id);             \
		mutex_unlock(&hmdfs_dm(olddentry)->comrade_list_lock);         \
		mutex_lock(&hmdfs_dm(newdentry)->comrade_list_lock);           \
		for_each_comrade_locked(newdentry, comrade)                    \
			trace_hmdfs_show_comrade(newdentry, comrade->lo_d,     \
						 comrade->dev_id);             \
		mutex_unlock(&hmdfs_dm(newdentry)->comrade_list_lock);         \
	}

/*****************************************************************************
 * Helper functions abstarcting out comrade
 *****************************************************************************/

static inline bool hmdfs_i_merge(struct hmdfs_inode_info *hii)
{
	__u8 t = hii->inode_type;
	return t == HMDFS_LAYER_FIRST_MERGE || t == HMDFS_LAYER_OTHER_MERGE;
}

struct dentry *hmdfs_get_lo_d(struct dentry *dentry, int dev_id);
struct dentry *hmdfs_get_fst_lo_d(struct dentry *dentry);

/*****************************************************************************
 * Inode operations for the merge view
 *****************************************************************************/

extern const struct inode_operations hmdfs_file_iops_merge;
extern const struct file_operations hmdfs_file_fops_merge;
extern const struct inode_operations hmdfs_dir_iops_merge;
extern const struct file_operations hmdfs_dir_fops_merge;
extern const struct inode_operations hmdfs_file_iops_cloud_merge;
extern const struct inode_operations hmdfs_dir_iops_cloud_merge;
extern const struct dentry_operations hmdfs_dops_merge;

/*****************************************************************************
 * dentry cache for the merge view
 *****************************************************************************/
extern struct kmem_cache *hmdfs_dentry_merge_cachep;

#endif // HMDFS_MERGE_H
