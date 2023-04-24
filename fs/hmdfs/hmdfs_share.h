/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_share.h
 *
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 */

#ifndef HMDFS_SHARE_H
#define HMDFS_SHARE_H

#include <linux/file.h>
#include <linux/slab.h>
#include <linux/namei.h>

#include "hmdfs_device_view.h"
#include "comm/connection.h"

#define HMDFS_SHARE_ITEM_TIMEOUT_S 120
#define HMDFS_SHARE_ITEMS_MAX 128

#define SHARE_RESERVED_DIR ".share"
#define SHARE_ALL_DEVICE "0"

struct hmdfs_share_control {
	__u32 src_fd;
	char cid[HMDFS_CID_SIZE];
};

struct hmdfs_share_item {
	struct file *file;
	struct qstr relative_path;
	char cid[HMDFS_CID_SIZE];
	bool opened;
	bool timeout;
	struct list_head list;
	struct delayed_work d_work;
	struct hmdfs_share_table *hst;
};

bool hmdfs_is_share_file(struct file *file);
struct hmdfs_share_item *hmdfs_lookup_share_item(struct hmdfs_share_table *st,
						struct qstr *cur_relative_path);
int insert_share_item(struct hmdfs_share_table *st, struct qstr *relative_path,
			struct file *file, char *cid);
void update_share_item(struct hmdfs_share_item *item, struct file *file,
			char *cid);
bool in_share_dir(struct dentry *child_dentry);
inline bool is_share_dir(struct inode *inode, const char *name);
int get_path_from_share_table(struct hmdfs_sb_info *sbi,
			        struct dentry *cur_dentry, struct path *src_path);

void hmdfs_clear_share_item_offline(struct hmdfs_peer *conn);
void reset_item_opened_status(struct hmdfs_sb_info *sbi, const char *filename);
void hmdfs_close_share_item(struct hmdfs_sb_info *sbi, struct file *file,
			    char *cid);
int hmdfs_check_share_access_permission(struct hmdfs_sb_info *sbi,
					const char *filename, char *cid);

int hmdfs_init_share_table(struct hmdfs_sb_info *sbi);
void hmdfs_clear_share_table(struct hmdfs_sb_info *sbi);
int hmdfs_clear_first_item(struct hmdfs_share_table *st);

#endif // HMDFS_SHARE_H
