/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_TYPES_H
#define _XPM_TYPES_H

#include <linux/types.h>

struct xpm_region {
	unsigned long addr_start; /* start adress of xpm region */
	unsigned long addr_end;   /* end address of xpm region */
};

#endif /* _XPM_TYPES_H */