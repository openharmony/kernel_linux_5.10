/* SPDX-License-Identifier: GPL-2.0 */
/*
 * access_tokenid.h
 *
 * Copyright (C) 2022-2023 Huawei Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _ACCESS_TOKEN_ID_H
#define _ACCESS_TOKEN_ID_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define	ACCESS_TOKEN_ID_IOCTL_BASE	'A'
#define MAX_PERM_GROUP_NUM 64

enum {
	GET_TOKEN_ID = 1,
	SET_TOKEN_ID,
	GET_FTOKEN_ID,
	SET_FTOKEN_ID,
	ADD_PERMISSIONS,
	REMOVE_PERMISSIONS,
	GET_PERMISSION,
	SET_PERMISSION,
	ACCESS_TOKENID_MAX_NR
};

typedef struct {
	unsigned int token_uniqueid : 20;
	unsigned int res : 5;
	unsigned int render_flag : 1;
	unsigned int dlp_flag : 1;
	unsigned int type : 2;
	unsigned int version : 3;
} access_tokenid_inner;

typedef struct {
	uint32_t token;
	uint32_t op_code;
	bool is_granted;
} ioctl_set_get_perm_data;

typedef struct {
	uint32_t token;
	uint32_t perm[MAX_PERM_GROUP_NUM];
} ioctl_add_perm_data;

struct token_perm_node {
	ioctl_add_perm_data perm_data;
	struct token_perm_node *left;
	struct token_perm_node *right;
};

#define	ACCESS_TOKENID_GET_TOKENID \
	_IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_TOKEN_ID, unsigned long long)
#define	ACCESS_TOKENID_SET_TOKENID \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_TOKEN_ID, unsigned long long)
#define	ACCESS_TOKENID_GET_FTOKENID \
	_IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_FTOKEN_ID, unsigned long long)
#define	ACCESS_TOKENID_SET_FTOKENID \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_FTOKEN_ID, unsigned long long)
#define	ACCESS_TOKENID_ADD_PERMISSIONS \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, ADD_PERMISSIONS, ioctl_add_perm_data)
#define	ACCESS_TOKENID_REMOVE_PERMISSIONS \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, REMOVE_PERMISSIONS, uint32_t)
#define	ACCESS_TOKENID_GET_PERMISSION \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, GET_PERMISSION, ioctl_set_get_perm_data)
#define	ACCESS_TOKENID_SET_PERMISSION \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_PERMISSION, ioctl_set_get_perm_data)

#endif /* _ACCESS_TOKEN_ID_H */
