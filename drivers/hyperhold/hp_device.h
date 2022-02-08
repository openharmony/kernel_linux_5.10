/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/hyperhold/hp_device.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _HP_DEVICE_H_
#define _HP_DEVICE_H_

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <crypto/skcipher.h>

enum {
	HP_DEV_ENCRYPT,
	HP_DEV_DECRYPT,
};

struct hp_device {
	struct file *filp;
	struct block_device *bdev;
	u32 old_block_size;
	u64 dev_size;
	u32 sec_size;

	struct crypto_skcipher *ctfm;
	struct blk_crypto_key *blk_key;
};

void unbind_bdev(struct hp_device *dev);
bool bind_bdev(struct hp_device *dev, const char *name);
bool crypto_init(struct hp_device *dev, bool soft);
void crypto_deinit(struct hp_device *dev);
int soft_crypt_page(struct crypto_skcipher *ctfm,
	struct page *dst_page, struct page *src_page, unsigned int op);
void inline_crypt_bio(struct blk_crypto_key *blk_key, struct bio *bio);
#endif
