/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/comm/crypto.h
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#ifndef HMDFS_FS_ENCRYPTION_H
#define HMDFS_FS_ENCRYPTION_H

#include "transport.h"

#define MAX_LABLE_SIZE	   30
#define CRYPTO_IV_OFFSET   0
#define CRYPTO_SALT_OFFSET (CRYPTO_IV_OFFSET + TLS_CIPHER_AES_GCM_128_IV_SIZE)
#define CRYPTO_SEQ_OFFSET                                                      \
	(CRYPTO_SALT_OFFSET + TLS_CIPHER_AES_GCM_128_SALT_SIZE)
#define REKEY_LIFETIME (60 * 60 * HZ)

enum HKDF_TYPE {
	HKDF_TYPE_KEY_INITIATOR = 0,
	HKDF_TYPE_KEY_ACCEPTER = 1,
	HKDF_TYPE_REKEY = 2,
	HKDF_TYPE_IV = 3,
};

enum SET_CRYPTO_TYPE {
	SET_CRYPTO_SEND = 0,
	SET_CRYPTO_RECV = 1,
};

int tls_crypto_info_init(struct connection *conn_impl);
int set_crypto_info(struct connection *conn_impl, int set_type);
int update_key(__u8 *old_key, __u8 *new_key, int type);

#endif
