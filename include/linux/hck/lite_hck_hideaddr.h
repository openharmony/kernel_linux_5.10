/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _LITE_HCK_HIDEADDR_H
#define _LITE_HCK_HIDEADDR_H

#include "linux/seq_file.h"
#include "linux/mm_types.h"
#include <linux/hck/lite_vendor_hooks.h>

#ifndef CONFIG_HCK
#define CALL_HCK_LITE_HOOK(name, args...)
#define REGISTER_HCK_LITE_HOOK(name, probe)
#define REGISTER_HCK_LITE_DATA_HOOK(name, probe, data)
#else


DECLARE_HCK_LITE_HOOK(hideaddr_header_prefix_lhck,
	TP_PROTO(unsigned long *start, unsigned long *end, vm_flags_t *flags, struct seq_file *m, struct vm_area_struct *vma),
	TP_ARGS(start, end, flags, m, vma));

#endif /* CONFIG_HCK */
#endif /* _LITE_HCK_HIDEADDR_H */
