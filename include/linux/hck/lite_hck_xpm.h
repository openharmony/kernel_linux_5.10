/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _LITE_HCK_XPM_H
#define _LITE_HCK_XPM_H

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/hck/lite_vendor_hooks.h>

#ifndef CONFIG_HCK
#undef CALL_HCK_LITE_HOOK
#define CALL_HCK_LITE_HOOK(name, args...)
#undef REGISTER_HCK_LITE_HOOK
#define REGISTER_HCK_LITE_HOOK(name, probe)
#undef REGISTER_HCK_LITE_DATA_HOOK
#define REGISTER_HCK_LITE_DATA_HOOK(name, probe, data)
#else
DECLARE_HCK_LITE_HOOK(xpm_delete_cache_node_lhck,
	TP_PROTO(struct inode *file_node),
	TP_ARGS(file_node));

DECLARE_HCK_LITE_HOOK(xpm_region_outer_lhck,
	TP_PROTO(unsigned long addr_start, unsigned long addr_end,
		unsigned long flags, bool *ret),
	TP_ARGS(addr_start, addr_end, flags, ret));

DECLARE_HCK_LITE_HOOK(xpm_get_unmapped_area_lhck,
	TP_PROTO(unsigned long addr, unsigned long len, unsigned long map_flags,
		unsigned long unmapped_flags, unsigned long *ret),
	TP_ARGS(addr, len, map_flags, unmapped_flags, ret));

DECLARE_HCK_LITE_HOOK(xpm_integrity_equal_lhck,
	TP_PROTO(struct page *page, struct page *kpage, bool *ret),
	TP_ARGS(page, kpage, ret));

DECLARE_HCK_LITE_HOOK(xpm_integrity_check_lhck,
	TP_PROTO(struct vm_area_struct *vma, unsigned int vflags,
		unsigned long addr, struct page *page, vm_fault_t *ret),
	TP_ARGS(vma, vflags, addr, page, ret));

DECLARE_HCK_LITE_HOOK(xpm_integrity_validate_lhck,
	TP_PROTO(struct vm_area_struct *vma, unsigned int vflags,
		unsigned long addr, struct page *page, vm_fault_t *ret),
	TP_ARGS(vma, vflags, addr, page, ret));

DECLARE_HCK_LITE_HOOK(xpm_integrity_update_lhck,
	TP_PROTO(struct vm_area_struct *vma, unsigned int vflags,
		struct page *page),
	TP_ARGS(vma, vflags, page));
#endif /* CONFIG_HCK */

#endif /* _LITE_HCK_XPM_H */
