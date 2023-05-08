/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _XPM_H
#define _XPM_H

#include <linux/mm.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/xpm_types.h>
#include <linux/hck/lite_hck_xpm.h>

/**
 * when inodes are destroyed, the corresponding cache must be destroyed
 */
static inline void xpm_delete_cache_node_hook(struct inode *file_node)
{
	CALL_HCK_LITE_HOOK(xpm_delete_cache_node_lhck, file_node);
}

/**
 * check whether input address range is out of the xpm region
 */
static inline bool xpm_region_outer_hook(unsigned long addr_start,
	unsigned long addr_end, unsigned long flags)
{
	bool ret = true;

	CALL_HCK_LITE_HOOK(xpm_region_outer_lhck, addr_start,
		addr_end, flags, &ret);
	return ret;
}

/**
 * get unmapped area in xpm region
 */
static inline unsigned long xpm_get_unmapped_area_hook(unsigned long addr,
	unsigned long len, unsigned long map_flags,
	unsigned long unmapped_flags)
{
	unsigned long ret = 0;

	CALL_HCK_LITE_HOOK(xpm_get_unmapped_area_lhck, addr, len,
		map_flags, unmapped_flags, &ret);
	return ret;
}

/*
 * check the confliction of a page's xpm flags, make sure a process will
 * not map any RO page into a writable vma or a WT page into a execuable/XPM
 * memory region.
 */
static inline vm_fault_t xpm_integrity_check_hook(struct vm_area_struct *vma,
	unsigned int vflags, unsigned long addr, struct page *page)
{
	vm_fault_t ret = 0;

	CALL_HCK_LITE_HOOK(xpm_integrity_check_lhck, vma, vflags,
		addr, page, &ret);
	return ret;
}

static inline
vm_fault_t xpm_integrity_validate_hook(struct vm_area_struct *vma,
	unsigned int vflags, unsigned long addr, struct page *page)
{
	vm_fault_t ret = 0;

	CALL_HCK_LITE_HOOK(xpm_integrity_validate_lhck, vma, vflags,
		addr, page, &ret);
	return ret;
}

static inline
void xpm_integrity_update_hook(struct vm_area_struct *vma,
	unsigned int vflags, struct page *page)
{
	CALL_HCK_LITE_HOOK(xpm_integrity_update_lhck, vma, vflags, page);
}

static inline bool xpm_integrity_check_one_page_merge(struct page *page,
	struct page *kpage)
{
	bool ret = true;

	CALL_HCK_LITE_HOOK(xpm_integrity_equal_lhck, page, kpage, &ret);
	return ret;
}

#ifdef CONFIG_ARM64
#define pte_user_mkexec(oldpte, ptent) \
	((!pte_user_exec(oldpte) && pte_user_exec(ptent)))
#else
#define pte_user_mkexec(oldpte, ptent) 1
#endif

#endif /* _XPM_H */
