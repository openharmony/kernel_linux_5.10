// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/hmdfs_dentryfile_cloud.c
 *
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
 */

#include "hmdfs_dentryfile_cloud.h"

#include <linux/slab.h>

void hmdfs_init_dcache_lookup_ctx_cloud(
	struct hmdfs_dcache_lookup_ctx_cloud *ctx, struct hmdfs_sb_info *sbi,
	const struct qstr *qstr, struct file *filp)
{
	ctx->sbi = sbi;
	ctx->name = qstr;
	ctx->filp = filp;
	ctx->bidx = 0;
	ctx->page = NULL;
	ctx->insense_de = NULL;
	ctx->insense_bidx = 0;
	ctx->insense_page = NULL;
}

static struct hmdfs_dentry_group_cloud *find_dentry_page(struct hmdfs_sb_info *sbi,
					    pgoff_t index, struct file *filp)
{
	int size;
	struct hmdfs_dentry_group_cloud *dentry_blk = NULL;
	loff_t pos = get_dentry_group_pos(index);
	int err;

	dentry_blk = kmalloc(sizeof(*dentry_blk), GFP_KERNEL);
	if (!dentry_blk)
		return NULL;

	err = hmdfs_wlock_file(filp, pos, DENTRYGROUP_SIZE);
	if (err) {
		hmdfs_err("lock file pos %lld failed", pos);
		kfree(dentry_blk);
		return NULL;
	}

	size = cache_file_read(sbi, filp, dentry_blk, (size_t)DENTRYGROUP_SIZE,
			       &pos);
	if (size != DENTRYGROUP_SIZE) {
		kfree(dentry_blk);
		dentry_blk = NULL;
	}

	return dentry_blk;
}

static struct hmdfs_dentry_cloud *
find_in_block(struct hmdfs_dentry_group_cloud *dentry_blk, __u32 namehash,
	      const struct qstr *qstr, struct hmdfs_dentry_cloud **insense_de,
	      bool case_sense)
{
	struct hmdfs_dentry_cloud *de;
	unsigned long bit_pos = 0;
	int max_len = 0;

	while (bit_pos < DENTRY_PER_GROUP_CLOUD) {
		if (!test_bit_le(bit_pos, dentry_blk->bitmap)) {
			bit_pos++;
			max_len++;
		}
		de = &dentry_blk->nsl[bit_pos];
		if (unlikely(!de->namelen)) {
			bit_pos++;
			continue;
		}

		if (le32_to_cpu(de->hash) == namehash &&
		    le16_to_cpu(de->namelen) == qstr->len &&
		    !memcmp(qstr->name, dentry_blk->filename[bit_pos],
			    le16_to_cpu(de->namelen)))
			goto found;
		if (!(*insense_de) && !case_sense &&
		    le32_to_cpu(de->hash) == namehash &&
		    le16_to_cpu(de->namelen) == qstr->len &&
		    str_n_case_eq(qstr->name, dentry_blk->filename[bit_pos],
				  le16_to_cpu(de->namelen)))
			*insense_de = de;
		max_len = 0;
		bit_pos += get_dentry_slots(le16_to_cpu(de->namelen));
	}
	de = NULL;
found:
	return de;
}

static struct hmdfs_dentry_cloud *
hmdfs_in_level(struct dentry *child_dentry, unsigned int level,
	       struct hmdfs_dcache_lookup_ctx_cloud *ctx)
{
	unsigned int nbucket;
	unsigned int bidx, end_block;
	struct hmdfs_dentry_cloud *de = NULL;
	struct hmdfs_dentry_cloud *tmp_insense_de = NULL;
	struct hmdfs_dentry_group_cloud *dentry_blk;

	nbucket = get_bucket_by_level(level);
	if (!nbucket)
		return de;

	bidx = get_bucketaddr(level, ctx->hash % nbucket) * BUCKET_BLOCKS;
	end_block = bidx + BUCKET_BLOCKS;

	for (; bidx < end_block; bidx++) {
		dentry_blk = find_dentry_page(ctx->sbi, bidx, ctx->filp);
		if (!dentry_blk)
			break;

		de = find_in_block(dentry_blk, ctx->hash, ctx->name,
				   &tmp_insense_de, ctx->sbi->s_case_sensitive);
		if (!de && !(ctx->insense_de) && tmp_insense_de) {
			ctx->insense_de = tmp_insense_de;
			ctx->insense_page = dentry_blk;
			ctx->insense_bidx = bidx;
		} else if (!de) {
			hmdfs_unlock_file(ctx->filp, get_dentry_group_pos(bidx),
					  DENTRYGROUP_SIZE);
			kfree(dentry_blk);
		} else {
			ctx->page = dentry_blk;
			break;
		}
	}
	ctx->bidx = bidx;
	return de;
}

struct hmdfs_dentry_cloud *
hmdfs_find_dentry_cloud(struct dentry *child_dentry,
			struct hmdfs_dcache_lookup_ctx_cloud *ctx)
{
	struct hmdfs_dentry_cloud *de = NULL;
	unsigned int max_depth;
	unsigned int level;

	if (!ctx->filp)
		return NULL;

	ctx->hash = hmdfs_dentry_hash(ctx->name, ctx->sbi->s_case_sensitive);
	max_depth = get_max_depth(ctx->filp);
	for (level = 0; level < max_depth; level++) {
		de = hmdfs_in_level(child_dentry, level, ctx);
		if (de) {
			if (ctx->insense_page) {
				hmdfs_unlock_file(ctx->filp,
					get_dentry_group_pos(ctx->insense_bidx),
					DENTRYGROUP_SIZE);
				kfree(ctx->insense_page);
				ctx->insense_page = NULL;
			}
			return de;
		}
	}
	if (ctx->insense_de) {
		ctx->bidx = ctx->insense_bidx;
		ctx->page = ctx->insense_page;
		ctx->insense_bidx = 0;
		ctx->insense_page = NULL;
	}
	return ctx->insense_de;
}
