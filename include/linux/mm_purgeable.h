/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#ifndef __MM_PURGEABLE_MEM_H
#define __MM_PURGEABLE_MEM_H

#ifdef CONFIG_MEM_PURGEABLE

void mm_init_uxpgd(struct mm_struct *mm);
void mm_clear_uxpgd(struct mm_struct *mm);
bool lock_uxpte(struct vm_area_struct *vma, unsigned long addr);
void unlock_uxpte(struct vm_area_struct *vma, unsigned long addr);
vm_fault_t do_uxpte_page_fault(struct vm_fault *vmf, pte_t *entry);
bool uxpte_set_present(struct vm_area_struct *vma, unsigned long addr);
void uxpte_clear_present(struct vm_area_struct *vma, unsigned long addr);

/*
 * mm_purg_pages_info: get purgeable pages count of @mm
 * @mm:	[in]	pointer to mm
 * @total_purg_pages:	[out]	total purgeable pages of @mm
 * @pined_purg_pages:	[out]	pined purgeable pages of @mm
 * If @mm is NULL, return with doing nothing.
 * If @total_purg_pages and @pined_purg_pages are both NULL, return with doing nothing.
 * If one of @total_purg_pages and @pined_purg_pages is NULL, other one will be counted.
 */
void mm_purg_pages_info(struct mm_struct *mm, unsigned long *total_purg_pages,
	unsigned long *pined_purg_pages);

/*
 * purg_pages_info: get global purgeable pages in system
 * @total_purg_pages:	[out]	total purgeable pages in system
 * @pined_purg_pages:	[out]	pined purgeable pages in system
 * If @total_purg_pages and @pined_purg_pages are both NULL, return with doing nothing.
 * If one of @total_purg_pages and @pined_purg_pages is NULL, other one will be counted.
 */
void purg_pages_info(unsigned long *total_purg_pages, unsigned long *pined_purg_pages);

#else /* CONFIG_MEM_PURGEABLE */

static inline void mm_init_uxpgd(struct mm_struct *mm) {}

static inline void mm_clear_uxpgd(struct mm_struct *mm) {}

static inline bool lock_uxpte(struct vm_area_struct *vma,
	unsigned long addr)
{
	return false;
}

static inline void unlock_uxpte(struct vm_area_struct *vma,
	unsigned long addr) {}

static inline vm_fault_t do_uxpte_page_fault(struct vm_fault *vmf,
	pte_t *entry)
{
	return 0;
}

static inline bool uxpte_set_present(struct vm_area_struct *vma,
	unsigned long addr)
{
	return false;
}

static inline void uxpte_clear_present(struct vm_area_struct *vma,
	unsigned long addr) {}

static inline void mm_purg_pages_info(struct mm_struct *mm,
	unsigned long *total_purg_pages, unsigned long *pined_purg_pages) {}

static inline void purg_pages_info(unsigned long *total_purg_pages,
	unsigned long *pined_purg_pages) {}
#endif /* CONFIG_MEM_PURGEABLE */
#endif /* __MM_PURGEABLE_MEM_H */

