/* SPDX-License-Identifier: GPL-2.0 */
/*
 * access_tokenid.h
 *
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _ACCESS_TOKEN_ID_H
#define _ACCESS_TOKEN_ID_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define	ACCESS_TOKEN_ID_IOCTL_BASE	'A'

enum {
	GET_TOKEN_ID = 1,
	SET_TOKEN_ID,
	GET_FTOKEN_ID,
	SET_FTOKEN_ID,
	ACCESS_TOKENID_MAX_NR
};

#define	ACCESS_TOKENID_GET_TOKENID \
	_IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_TOKEN_ID, unsigned long long)
#define	ACCESS_TOKENID_SET_TOKENID \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_TOKEN_ID, unsigned long long)
#define	ACCESS_TOKENID_GET_FTOKENID \
	_IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_FTOKEN_ID, unsigned long long)
#define	ACCESS_TOKENID_SET_FTOKENID \
	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_FTOKEN_ID, unsigned long long)

#endif /* _ACCESS_TOKEN_ID_H */
