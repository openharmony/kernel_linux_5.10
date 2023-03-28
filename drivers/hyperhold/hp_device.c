// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/hyperhold/hp_device.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#define pr_fmt(fmt) "[HYPERHOLD]" fmt

#include <linux/random.h>
#include <linux/blk-crypto.h>

#include "hp_device.h"

#define HP_CIPHER_MODE BLK_ENCRYPTION_MODE_AES_256_XTS
#define HP_CIPHER_NAME "xts(aes)"
#define HP_KEY_SIZE (64)
#define HP_IV_SIZE (16)

union hp_iv {
	__le64 index;
	__le64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE];
};

void unbind_bdev(struct hp_device *dev)
{
	int ret;

	if (!dev->bdev)
		goto close;
	if (!dev->old_block_size)
		goto put;
	ret = set_blocksize(dev->bdev, dev->old_block_size);
	if (ret)
		pr_err("set old block size %d failed, err = %d!\n",
				dev->old_block_size, ret);
	dev->old_block_size = 0;
put:
	blkdev_put(dev->bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	dev->bdev = NULL;
close:
	if (dev->filp)
		filp_close(dev->filp, NULL);
	dev->filp = NULL;

	pr_info("hyperhold bdev unbinded.\n");
}

bool bind_bdev(struct hp_device *dev, const char *name)
{
	struct inode *inode = NULL;
	int ret;

	dev->filp = filp_open(name, O_RDWR | O_LARGEFILE, 0);
	if (IS_ERR(dev->filp)) {
		pr_err("open file %s failed, err = %ld!\n", name, PTR_ERR(dev->filp));
		dev->filp = NULL;
		goto err;
	}
	inode = dev->filp->f_mapping->host;
	if (!S_ISBLK(inode->i_mode)) {
		pr_err("%s is not a block device!\n", name);
		goto err;
	}
	dev->bdev = blkdev_get_by_dev(inode->i_rdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL, dev);
	if (IS_ERR(dev->bdev)) {
		ret = PTR_ERR(dev->bdev);
		dev->bdev = NULL;
		pr_err("get blkdev %s failed, err = %d!\n", name, ret);
		goto err;
	}
	dev->old_block_size = block_size(dev->bdev);
	ret = set_blocksize(dev->bdev, PAGE_SIZE);
	if (ret) {
		pr_err("set %s block size failed, err = %d!\n", name, ret);
		goto err;
	}
	dev->dev_size = (u64)i_size_read(inode);
	dev->sec_size = SECTOR_SIZE;

	pr_info("hyperhold bind bdev %s of size %llu / %u succ.\n",
			name, dev->dev_size, dev->sec_size);

	return true;
err:
	unbind_bdev(dev);

	return false;
}

int soft_crypt_page(struct crypto_skcipher *ctfm, struct page *dst_page,
		    struct page *src_page, unsigned int op)
{
	struct skcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist dst, src;
	int ret = 0;
	union hp_iv iv;

	memset(&iv, 0, sizeof(union hp_iv));
	iv.index = cpu_to_le64(src_page->index);

	req = skcipher_request_alloc(ctfm, GFP_NOIO);
	if (!req) {
		pr_err("alloc skcipher request failed!\n");
		return -ENOMEM;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &wait);
	sg_init_table(&dst, 1);
	sg_set_page(&dst, dst_page, PAGE_SIZE, 0);
	sg_init_table(&src, 1);
	sg_set_page(&src, src_page, PAGE_SIZE, 0);
	skcipher_request_set_crypt(req, &src, &dst, PAGE_SIZE, &iv);
	if (op == HP_DEV_ENCRYPT)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	else if (op == HP_DEV_DECRYPT)
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	else
		BUG();

	skcipher_request_free(req);

	if (ret)
		pr_err("%scrypt failed!\n", op == HP_DEV_ENCRYPT ? "en" : "de");

	return ret;
}

static struct crypto_skcipher *soft_crypto_init(const u8 *key)
{
	char *cipher = HP_CIPHER_NAME;
	u32 key_len = HP_KEY_SIZE;
	struct crypto_skcipher *ctfm = NULL;
	int ret;

	ctfm = crypto_alloc_skcipher(cipher, 0, 0);
	if (IS_ERR(ctfm)) {
		pr_err("alloc ctfm failed, ret = %ld!\n", PTR_ERR(ctfm));
		ctfm = NULL;
		goto err;
	}
	crypto_skcipher_clear_flags(ctfm, ~0);
	crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);
	ret = crypto_skcipher_setkey(ctfm, key, key_len);
	if (ret) {
		pr_err("ctfm setkey failed, ret = %d!\n", ret);
		goto err;
	}

	return ctfm;
err:
	if (ctfm)
		crypto_free_skcipher(ctfm);

	return NULL;
}

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
void inline_crypt_bio(struct blk_crypto_key *blk_key, struct bio *bio)
{
	union hp_iv iv;

	memset(&iv, 0, sizeof(union hp_iv));
	iv.index = cpu_to_le64(bio->bi_iter.bi_sector);

	bio_crypt_set_ctx(bio, blk_key, iv.dun, GFP_NOIO);
}

static struct blk_crypto_key *inline_crypto_init(const u8 *key)
{
	struct blk_crypto_key *blk_key = NULL;
	u32 dun_bytes = HP_IV_SIZE - sizeof(__le64);
	int ret;

	blk_key = kzalloc(sizeof(struct blk_crypto_key), GFP_KERNEL);
	if (!blk_key) {
		pr_err("blk key alloc failed!\n");
		goto err;
	}
	ret = blk_crypto_init_key(blk_key, key, HP_CIPHER_MODE, dun_bytes, PAGE_SIZE);
	if (ret) {
		pr_err("blk key init failed, ret = %d!\n", ret);
		goto err;
	}

	return blk_key;
err:
	if (blk_key)
		kfree_sensitive(blk_key);

	return NULL;
}
#else
void inline_crypt_bio(struct blk_crypto_key *blk_key, struct bio *bio) {}
static struct blk_crypto_key *inline_crypto_init(const u8 *key)
{
	pr_err("CONFIG_BLK_INLINE_ENCRYPTION is not enabled!\n");
	return NULL;
}
#endif

bool crypto_init(struct hp_device *dev, bool soft)
{
	u8 key[HP_KEY_SIZE];
	bool ret = false;

	get_random_bytes(key, HP_KEY_SIZE);
	if (soft) {
		dev->ctfm = soft_crypto_init(key);
		ret = dev->ctfm;
	} else {
		dev->blk_key = inline_crypto_init(key);
		ret = dev->blk_key;
		if (ret)
			pr_warn("soft crypt has been turned off, now apply hard crypt!\n");
	}
	memzero_explicit(key, HP_KEY_SIZE);

	return ret;
}

void crypto_deinit(struct hp_device *dev)
{
	if (dev->ctfm) {
		crypto_free_skcipher(dev->ctfm);
		dev->ctfm = NULL;
	}
	if (dev->blk_key) {
		kfree_sensitive(dev->blk_key);
		dev->blk_key = NULL;
	}
}
