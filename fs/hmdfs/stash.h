/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/stash.h
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#ifndef HMDFS_STASH_H
#define HMDFS_STASH_H

#include "hmdfs.h"
#include "hmdfs_client.h"

extern void hmdfs_stash_add_node_evt_cb(void);

extern void hmdfs_exit_stash(struct hmdfs_sb_info *sbi);
extern int hmdfs_init_stash(struct hmdfs_sb_info *sbi);

extern int hmdfs_stash_writepage(struct hmdfs_peer *conn,
				 struct hmdfs_writepage_context *ctx);

extern void hmdfs_remote_init_stash_status(struct hmdfs_peer *conn,
					   struct inode *inode, umode_t mode);

#endif
