// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/inode.c
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#include "hmdfs_device_view.h"
#include "inode.h"
#include "comm/connection.h"

/**
 * Rules to generate inode numbers:
 *
 * "/", "/device_view", "/merge_view", "/device_view/local", "/device_view/cid"
 * = DOMAIN {3} : dev_id {29} : HMDFS_ROOT {32}
 *
 * "/device_view/cid/xxx"
 * = DOMAIN {3} : dev_id {29} : hash(remote_ino){32}
 *
 * "/merge_view/xxx"
 * = DOMAIN {3} : lower's dev_id {29} : lower's ino_raw {32}
 */

#define BIT_WIDE_TOTAL 64

#define BIT_WIDE_DOMAIN 3
#define BIT_WIDE_DEVID 29
#define BIT_WIDE_INO_RAW 32

enum DOMAIN {
	DOMAIN_ROOT,
	DOMAIN_DEVICE_LOCAL,
	DOMAIN_DEVICE_REMOTE,
	DOMAIN_DEVICE_CLOUD,
	DOMAIN_MERGE_VIEW,
	DOMAIN_INVALID,
};

union hmdfs_ino {
	const uint64_t ino_output;
	struct {
		uint64_t ino_raw : BIT_WIDE_INO_RAW;
		uint64_t dev_id : BIT_WIDE_DEVID;
		uint8_t domain : BIT_WIDE_DOMAIN;
	};
};

static uint8_t read_ino_domain(uint64_t ino)
{
	union hmdfs_ino _ino = {
		.ino_output = ino,
	};

	return _ino.domain;
}

struct iget_args {
	/* The lower inode of local/merge/root(part) inode */
	struct inode *lo_i;
	/* The peer of remote inode */
	struct hmdfs_peer *peer;
	/* The ino of remote inode */
	uint64_t remote_ino;

	/* The recordId of cloud inode */
	uint8_t *cloud_record_id;

	/* Returned inode's ino */
	union hmdfs_ino ino;
};

/**
 * iget_test - whether or not the inode with matched hashval is the one we are
 * looking for
 *
 * @inode: the local inode we found in inode cache with matched hashval
 * @data: struct iget_args
 */
static int iget_test(struct inode *inode, void *data)
{
	struct hmdfs_inode_info *hii = hmdfs_i(inode);
	struct iget_args *ia = data;
	int res = 0;

	WARN_ON(ia->ino.domain < DOMAIN_ROOT ||
		ia->ino.domain >= DOMAIN_INVALID);

	if (read_ino_domain(inode->i_ino) == DOMAIN_ROOT)
		return 0;

	switch (ia->ino.domain) {
	case DOMAIN_MERGE_VIEW:
		res = (ia->lo_i == hii->lower_inode);
		break;
	case DOMAIN_DEVICE_LOCAL:
		res = (ia->lo_i == hii->lower_inode);
		break;
	case DOMAIN_DEVICE_REMOTE:
		res = (ia->peer == hii->conn &&
		       ia->remote_ino == hii->remote_ino);
		break;
	case DOMAIN_DEVICE_CLOUD:
		res = (ia->cloud_record_id && hii->cloud_record_id &&
		       (memcmp(ia->cloud_record_id, hii->cloud_record_id,
			       CLOUD_RECORD_ID_LEN) == 0));
		break;
	}

	return res;
}

/**
 * iget_set - initialize a inode with iget_args
 *
 * @sb: the superblock of current hmdfs instance
 * @data: struct iget_args
 */
static int iget_set(struct inode *inode, void *data)
{
	struct hmdfs_inode_info *hii = hmdfs_i(inode);
	struct iget_args *ia = (struct iget_args *)data;

	inode->i_ino = ia->ino.ino_output;
	inode_inc_iversion(inode);

	hii->conn = ia->peer;
	hii->remote_ino = ia->remote_ino;
	hii->lower_inode = ia->lo_i;

	if (ia->cloud_record_id)
		memcpy(hii->cloud_record_id, ia->cloud_record_id, CLOUD_RECORD_ID_LEN);

	return 0;
}

static uint64_t make_ino_raw_dev_local(uint64_t lo_ino)
{
	if (!(lo_ino >> BIT_WIDE_INO_RAW))
		return lo_ino;

	return lo_ino * GOLDEN_RATIO_64 >> BIT_WIDE_INO_RAW;
}

static uint64_t make_ino_raw_dev_remote(uint64_t remote_ino)
{
	return hash_long(remote_ino, BIT_WIDE_INO_RAW);
}

/**
 * hmdfs_iget5_locked_merge - obtain an inode for the merge-view
 *
 * @sb: superblock of current instance
 * @fst_lo_i: the lower inode of it's first comrade
 *
 * Simply replace the lower's domain for a new ino.
 */
struct inode *hmdfs_iget5_locked_merge(struct super_block *sb,
				       struct dentry *fst_lo_d)
{
	struct iget_args ia = {
		.lo_i = d_inode(fst_lo_d),
		.peer = NULL,
		.remote_ino = 0,
		.cloud_record_id = NULL,
		.ino.ino_output = 0,
	};

	if (unlikely(!d_inode(fst_lo_d))) {
		hmdfs_err("Received a invalid lower inode");
		return NULL;
	}

	ia.ino.ino_raw = d_inode(fst_lo_d)->i_ino;
	ia.ino.dev_id = hmdfs_d(fst_lo_d)->device_id;
	ia.ino.domain = DOMAIN_MERGE_VIEW;
	return iget5_locked(sb, ia.ino.ino_output, iget_test, iget_set, &ia);
}

/**
 * hmdfs_iget5_locked_local - obtain an inode for the local-dev-view
 *
 * @sb: superblock of current instance
 * @lo_i: the lower inode from local filesystem
 *
 * Hashing local inode's ino to generate our ino. We continue to compare the
 * address of the lower_inode for uniqueness when collisions occurred.
 */
struct inode *hmdfs_iget5_locked_local(struct super_block *sb,
				       struct inode *lo_i)
{
	struct iget_args ia = {
		.lo_i = lo_i,
		.peer = NULL,
		.remote_ino = 0,
		.cloud_record_id = NULL,
		.ino.ino_output = 0,
	};

	if (unlikely(!lo_i)) {
		hmdfs_err("Received a invalid lower inode");
		return NULL;
	}
	ia.ino.ino_raw = make_ino_raw_dev_local(lo_i->i_ino);
	ia.ino.dev_id = 0;
	ia.ino.domain = DOMAIN_DEVICE_LOCAL;
	return iget5_locked(sb, ia.ino.ino_output, iget_test, iget_set, &ia);
}

/**
 * hmdfs_iget5_locked_remote - obtain an inode for the remote-dev-view
 *
 * @sb: superblock of current instance
 * @peer: corresponding device node
 * @remote_ino: remote inode's ino
 *
 * Hash remote ino for ino's 32bit~1bit.
 *
 * Note that currenly implementation assume the each remote inode has unique
 * ino. Thus the combination of the peer's unique dev_id and the remote_ino
 * is enough to determine a unique remote inode.
 */
struct inode *hmdfs_iget5_locked_remote(struct super_block *sb,
					struct hmdfs_peer *peer,
					uint64_t remote_ino)
{
	struct iget_args ia = {
		.lo_i = NULL,
		.peer = peer,
		.remote_ino = remote_ino,
		.cloud_record_id = NULL,
		.ino.ino_output = 0,
	};

	if (unlikely(!peer)) {
		hmdfs_err("Received a invalid peer");
		return NULL;
	}

	ia.ino.ino_raw = make_ino_raw_dev_remote(remote_ino);
	ia.ino.dev_id = peer->device_id;
	ia.ino.domain = DOMAIN_DEVICE_REMOTE;
	return iget5_locked(sb, ia.ino.ino_output, iget_test, iget_set, &ia);
}

/**
 * hmdfs_iget5_locked_cloud - obtain an inode for the cloud-dev-view
 *
 * @sb: superblock of current instance
 * @peer: corresponding device node
 * @cloud_id: cloud file record id
 *
 * Hash remote ino for ino's 32bit~1bit.
 *
 * Note that currenly implementation assume the each remote inode has unique
 * ino. Thus the combination of the peer's unique dev_id and the remote_ino
 * is enough to determine a unique remote inode.
 */
struct inode *hmdfs_iget5_locked_cloud(struct super_block *sb,
					struct hmdfs_peer *peer,
					uint8_t *cloud_id)
{
	struct iget_args ia = {
		.lo_i = NULL,
		.peer = peer,
		.remote_ino = 0,
		.cloud_record_id = cloud_id,
		.ino.ino_output = 0,
	};

	if (unlikely(!peer)) {
		hmdfs_err("Received a invalid peer");
		return NULL;
	}

	ia.ino.ino_raw = make_ino_raw_cloud(cloud_id);
	ia.ino.dev_id = peer->device_id;
	ia.ino.domain = DOMAIN_DEVICE_CLOUD;
	return iget5_locked(sb, ia.ino.ino_output, iget_test, iget_set, &ia);
}

struct inode *hmdfs_iget_locked_root(struct super_block *sb, uint64_t root_ino,
				     struct inode *lo_i,
				     struct hmdfs_peer *peer)
{
	struct iget_args ia = {
		.lo_i = lo_i,
		.peer = peer,
		.remote_ino = 0,
		.cloud_record_id = NULL,
		.ino.ino_raw = root_ino,
		.ino.dev_id = peer ? peer->device_id : 0,
		.ino.domain = DOMAIN_ROOT,
	};

	if (unlikely(root_ino < 0 || root_ino >= HMDFS_ROOT_INVALID)) {
		hmdfs_err("Root %llu is invalid", root_ino);
		return NULL;
	}
	if (unlikely(root_ino == HMDFS_ROOT_DEV_REMOTE && !peer)) {
		hmdfs_err("Root %llu received a invalid peer", root_ino);
		return NULL;
	}

	return iget5_locked(sb, ia.ino.ino_output, iget_test, iget_set, &ia);
}
