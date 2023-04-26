/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/hmdfs_dentryfile_cloud.h
 *
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 */

#ifndef HMDFS_DENTRYFILE_CLOUD_H
#define HMDFS_DENTRYFILE_CLOUD_H

#include "inode.h"
#include "hmdfs_dentryfile.h"

/*
 * 4096 = version(1) + bitmap(8) + reserved(7)
 *        + nsl(60 * 60) + filename(60 * 8)
 */
#define DENTRY_BITMAP_LENGTH_CLOUD   8
#define DENTRY_PER_GROUP_CLOUD       60
#define DENTRY_GROUP_RESERVED_CLOUD 7
struct hmdfs_dentry_cloud {
	__le32 hash;
	__le16 i_mode;
	__le16 namelen;
	__le64 i_size;
	__le64 i_mtime;
	__u8 record_id[CLOUD_RECORD_ID_LEN];
	/* reserved bytes for long term extend, total 60 bytes */
	__u8 reserved[DENTRY_RESERVED_LENGTH];
} __packed;

/* 4K/68 Bytes = 60 dentries for per dentrygroup */
struct hmdfs_dentry_group_cloud {
	__u8 dentry_version;
	__u8 bitmap[DENTRY_BITMAP_LENGTH_CLOUD];
	struct hmdfs_dentry_cloud nsl[DENTRY_PER_GROUP_CLOUD];
	__u8 filename[DENTRY_PER_GROUP_CLOUD][DENTRY_NAME_LEN];
	__u8 reserved[DENTRY_GROUP_RESERVED_CLOUD];
} __packed;

struct hmdfs_dcache_lookup_ctx_cloud {
	struct hmdfs_sb_info *sbi;
	const struct qstr *name;
	struct file *filp;
	__u32 hash;

	/* for case sensitive */
	unsigned int bidx;
	struct hmdfs_dentry_group_cloud *page;

	/* for case insensitive */
	struct hmdfs_dentry_cloud *insense_de;
	unsigned int insense_bidx;
	struct hmdfs_dentry_group_cloud *insense_page;
};

void hmdfs_init_dcache_lookup_ctx_cloud(
	struct hmdfs_dcache_lookup_ctx_cloud *ctx, struct hmdfs_sb_info *sbi,
	const struct qstr *qstr, struct file *filp);
struct hmdfs_dentry_cloud *
hmdfs_find_dentry_cloud(struct dentry *child_dentry,
			struct hmdfs_dcache_lookup_ctx_cloud *ctx);
#endif
