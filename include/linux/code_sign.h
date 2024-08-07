/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef LINUX_INCLUDE_CODE_SIGN_H
#define LINUX_INCLUDE_CODE_SIGN_H

#include <linux/hck/lite_hck_code_sign.h>

/*
 * Merkle tree properties.  The file measurement is the hash of this structure
 * excluding the signature and with the sig_size field set to 0, while version
 * is replaced by code sign version.
 */
struct code_sign_descriptor {
	__u8 version;		/* must be 1 */
	__u8 hash_algorithm;	/* Merkle tree hash algorithm */
	__u8 log_blocksize;	/* log2 of size of data and tree blocks */
	__u8 salt_size;		/* size of salt in bytes; 0 if none */
	__le32 sig_size;	/* size of signature in bytes; 0 if none */
	__le64 data_size;	/* size of file the Merkle tree is built over */
	__u8 root_hash[64];	/* Merkle tree root hash */
	__u8 salt[32];		/* salt prepended to each hashed block */
	__u32 flags;
	__u32 pgtypeinfo_size;   /* size of page type info (in number of btis) */
	__u64 tree_offset;  /* merkle tree offset in file */
	__u64 pgtypeinfo_off;  /* offset of page type info */
	__u8 __reserved2[119]; /* must be 0's */
	__u8 cs_version;    /* code sign version */
	__u8 signature[];	/* optional PKCS#7 signature */
};

enum {
	RELEASE_CODE_START = 0x0,
	RELEASE_PLATFORM_CODE,
	RELEASE_AUTHED_CODE,
	RELEASE_DEVELOPER_CODE,
	RELEASE_BLOCK_CODE,
	RELEASE_CODE_END,

	DEBUG_CODE_START = 0x100,
	DEBUG_PLATFORM_CODE,
	DEBUG_AUTHED_CODE,
	DEBUG_DEVELOPER_CODE,
	DEBUG_BLOCK_CODE,
	DEBUG_DEBUG_CODE,
	DEBUG_CODE_END,

	MAY_LOCAL_CODE = 0x201,
};

#define FLAG_INSIDE_TREE	(1 << 0) /* Merkle tree in file */
#define IS_INSIDE_TREE(desc)	((desc)->flags & FLAG_INSIDE_TREE)

#define CONST_CAST_CODE_SIGN_DESC(desc) ((const struct code_sign_descriptor *)(desc))
#define CAST_CODE_SIGN_DESC(desc) ((struct code_sign_descriptor *)(desc))

static inline u64 get_tree_offset_compact(const void *desc)
{
	return CONST_CAST_CODE_SIGN_DESC(desc)->tree_offset;
}

static inline bool is_inside_tree_compact(const void *_desc)
{
	const struct code_sign_descriptor *desc = CONST_CAST_CODE_SIGN_DESC(_desc);

	return desc->cs_version && IS_INSIDE_TREE(desc);
}

static inline int code_sign_check_descriptor_hook(const struct inode *inode, const void *desc)
{
	int ret = 0;

	CALL_HCK_LITE_HOOK(code_sign_check_descriptor_lhck, inode, desc, &ret);
	return ret;
}

static inline int code_sign_before_measurement_hook(void *desc)
{
	int ret = 0;

	CALL_HCK_LITE_HOOK(code_sign_before_measurement_lhck, desc, &ret);
	return ret;
}

static inline void code_sign_after_measurement_hook(void *desc, int version)
{
	CALL_HCK_LITE_HOOK(code_sign_after_measurement_lhck, desc, version);
}

#endif /* LINUX_INCLUDE_CODE_SIGN_H */
