/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/hyperhold_inf.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef HYPERHOLD_INF_H
#define HYPERHOLD_INF_H

#ifdef CONFIG_HYPERHOLD

extern bool is_hyperhold_enable(void);

#else

static inline is_hyperhold_enable(void)
{
	return false;
}
#endif

#endif
