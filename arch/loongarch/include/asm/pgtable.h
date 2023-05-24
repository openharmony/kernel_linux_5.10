/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_PGTABLE_H
#define _ASM_PGTABLE_H

#include <linux/mm_types.h>
#include <linux/mmzone.h>
#include <asm/pgtable-bits.h>
#include <asm/pgtable-64.h>

struct mm_struct;
struct vm_area_struct;

/*
 * ZERO_PAGE is a global shared page that is always zero; used
 * for zero-mapped memory areas etc..
 */

extern unsigned long empty_zero_page;
extern unsigned long zero_page_mask;

#define ZERO_PAGE(vaddr) \
	(virt_to_page((void *)(empty_zero_page + (((unsigned long)(vaddr)) & zero_page_mask))))
#define __HAVE_COLOR_ZERO_PAGE

extern void paging_init(void);

#define pte_none(pte)		(!(pte_val(pte) & ~_PAGE_GLOBAL))
#define pte_present(pte)	(pte_val(pte) & (_PAGE_PRESENT | _PAGE_PROTNONE))
#define pte_no_exec(pte)	(pte_val(pte) & _PAGE_NO_EXEC)

static inline void set_pte(pte_t *ptep, pte_t pteval)
{
	*ptep = pteval;
	if (pte_val(pteval) & _PAGE_GLOBAL) {
		pte_t *buddy = ptep_buddy(ptep);
		/*
		 * Make sure the buddy is global too (if it's !none,
		 * it better already be global)
		 */
#ifdef CONFIG_SMP
		/*
		 * For SMP, multiple CPUs can race, so we need to do
		 * this atomically.
		 */
		unsigned long page_global = _PAGE_GLOBAL;
		unsigned long tmp;

		__asm__ __volatile__ (
		"1:"	__LL	"%[tmp], %[buddy]		\n"
		"	bnez	%[tmp], 2f			\n"
		"	 or	%[tmp], %[tmp], %[global]	\n"
			__SC	"%[tmp], %[buddy]		\n"
		"	beqz	%[tmp], 1b			\n"
		"	nop					\n"
		"2:						\n"
		__WEAK_LLSC_MB
		: [buddy] "+m" (buddy->pte), [tmp] "=&r" (tmp)
		: [global] "r" (page_global));
#else /* !CONFIG_SMP */
		if (pte_none(*buddy))
			pte_val(*buddy) = pte_val(*buddy) | _PAGE_GLOBAL;
#endif /* CONFIG_SMP */
	}
}

static inline void set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pteval)
{
	set_pte(ptep, pteval);
}

static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	/* Preserve global status for the pair */
	if (pte_val(*ptep_buddy(ptep)) & _PAGE_GLOBAL)
		set_pte_at(mm, addr, ptep, __pte(_PAGE_GLOBAL));
	else
		set_pte_at(mm, addr, ptep, __pte(0));
}

#define PGD_T_LOG2	(__builtin_ffs(sizeof(pgd_t)) - 1)
#define PMD_T_LOG2	(__builtin_ffs(sizeof(pmd_t)) - 1)
#define PTE_T_LOG2	(__builtin_ffs(sizeof(pte_t)) - 1)

extern pgd_t swapper_pg_dir[];
extern pgd_t invalid_pg_dir[];

/*
 * The following only work if pte_present() is true.
 * Undefined behaviour if not..
 */
static inline int pte_write(pte_t pte)	{ return pte_val(pte) & _PAGE_WRITE; }
static inline int pte_young(pte_t pte)	{ return pte_val(pte) & _PAGE_ACCESSED; }
static inline int pte_dirty(pte_t pte)	{ return pte_val(pte) & _PAGE_MODIFIED; }

static inline pte_t pte_mkold(pte_t pte)
{
	pte_val(pte) &= ~_PAGE_ACCESSED;
	return pte;
}

static inline pte_t pte_mkyoung(pte_t pte)
{
	pte_val(pte) |= _PAGE_ACCESSED;
	return pte;
}

static inline pte_t pte_mkclean(pte_t pte)
{
	pte_val(pte) &= ~(_PAGE_DIRTY | _PAGE_MODIFIED);
	return pte;
}

static inline pte_t pte_mkdirty(pte_t pte)
{
	pte_val(pte) |= _PAGE_MODIFIED;
	if (pte_val(pte) & _PAGE_WRITE)
		pte_val(pte) |= _PAGE_DIRTY;
	return pte;
}

static inline pte_t pte_mkwrite(pte_t pte)
{
	pte_val(pte) |= _PAGE_WRITE;
	if (pte_val(pte) & _PAGE_MODIFIED)
		pte_val(pte) |= _PAGE_DIRTY;
	return pte;
}

static inline pte_t pte_wrprotect(pte_t pte)
{
	pte_val(pte) &= ~(_PAGE_WRITE | _PAGE_DIRTY);
	return pte;
}

static inline int pte_huge(pte_t pte)	{ return pte_val(pte) & _PAGE_HUGE; }

static inline pte_t pte_mkhuge(pte_t pte)
{
	pte_val(pte) |= _PAGE_HUGE;
	return pte;
}

#if defined(CONFIG_ARCH_HAS_PTE_SPECIAL)
static inline int pte_special(pte_t pte)	{ return pte_val(pte) & _PAGE_SPECIAL; }
static inline pte_t pte_mkspecial(pte_t pte)	{ pte_val(pte) |= _PAGE_SPECIAL; return pte; }
#endif /* CONFIG_ARCH_HAS_PTE_SPECIAL */

#define pte_accessible pte_accessible
static inline unsigned long pte_accessible(struct mm_struct *mm, pte_t a)
{
	if (pte_val(a) & _PAGE_PRESENT)
		return true;

	if ((pte_val(a) & _PAGE_PROTNONE) &&
			mm_tlb_flush_pending(mm))
		return true;

	return false;
}

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 */
#define mk_pte(page, pgprot)	pfn_pte(page_to_pfn(page), (pgprot))

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	return __pte((pte_val(pte) & _PAGE_CHG_MASK) |
		     (pgprot_val(newprot) & ~_PAGE_CHG_MASK));
}

extern void __update_tlb(struct vm_area_struct *vma,
			unsigned long address, pte_t *ptep);

static inline void update_mmu_cache(struct vm_area_struct *vma,
			unsigned long address, pte_t *ptep)
{
	__update_tlb(vma, address, ptep);
}

#define __HAVE_ARCH_UPDATE_MMU_TLB
#define update_mmu_tlb	update_mmu_cache

static inline void update_mmu_cache_pmd(struct vm_area_struct *vma,
			unsigned long address, pmd_t *pmdp)
{
	__update_tlb(vma, address, (pte_t *)pmdp);
}

#define kern_addr_valid(addr)	(1)

#ifdef CONFIG_TRANSPARENT_HUGEPAGE

/* We don't have hardware dirty/accessed bits, generic_pmdp_establish is fine.*/
#define pmdp_establish generic_pmdp_establish

static inline int pmd_trans_huge(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_HUGE) && pmd_present(pmd);
}

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
	pmd_val(pmd) = (pmd_val(pmd) & ~(_PAGE_GLOBAL)) |
		((pmd_val(pmd) & _PAGE_GLOBAL) << (_PAGE_HGLOBAL_SHIFT - _PAGE_GLOBAL_SHIFT));
	pmd_val(pmd) |= _PAGE_HUGE;

	return pmd;
}

#define pmd_write pmd_write
static inline int pmd_write(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_WRITE);
}

static inline pmd_t pmd_mkwrite(pmd_t pmd)
{
	pmd_val(pmd) |= _PAGE_WRITE;
	if (pmd_val(pmd) & _PAGE_MODIFIED)
		pmd_val(pmd) |= _PAGE_DIRTY;
	return pmd;
}

static inline pmd_t pmd_wrprotect(pmd_t pmd)
{
	pmd_val(pmd) &= ~(_PAGE_WRITE | _PAGE_DIRTY);
	return pmd;
}

static inline int pmd_dirty(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_MODIFIED);
}

static inline pmd_t pmd_mkclean(pmd_t pmd)
{
	pmd_val(pmd) &= ~(_PAGE_DIRTY | _PAGE_MODIFIED);
	return pmd;
}

static inline pmd_t pmd_mkdirty(pmd_t pmd)
{
	pmd_val(pmd) |= _PAGE_MODIFIED;
	if (pmd_val(pmd) & _PAGE_WRITE)
		pmd_val(pmd) |= _PAGE_DIRTY;
	return pmd;
}

static inline int pmd_young(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_ACCESSED);
}

static inline pmd_t pmd_mkold(pmd_t pmd)
{
	pmd_val(pmd) &= ~_PAGE_ACCESSED;
	return pmd;
}

static inline pmd_t pmd_mkyoung(pmd_t pmd)
{
	pmd_val(pmd) |= _PAGE_ACCESSED;
	return pmd;
}

static inline unsigned long pmd_pfn(pmd_t pmd)
{
	return (pmd_val(pmd) & _PFN_MASK) >> _PFN_SHIFT;
}

static inline struct page *pmd_page(pmd_t pmd)
{
	if (pmd_trans_huge(pmd))
		return pfn_to_page(pmd_pfn(pmd));

	return pfn_to_page(pmd_phys(pmd) >> PAGE_SHIFT);
}

static inline pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	pmd_val(pmd) = (pmd_val(pmd) & _HPAGE_CHG_MASK) |
				(pgprot_val(newprot) & ~_HPAGE_CHG_MASK);
	return pmd;
}

static inline pmd_t pmd_mkinvalid(pmd_t pmd)
{
	pmd_val(pmd) |= _PAGE_PRESENT_INVALID;
	pmd_val(pmd) &= ~(_PAGE_PRESENT | _PAGE_VALID | _PAGE_DIRTY | _PAGE_PROTNONE);

	return pmd;
}

/*
 * The generic version pmdp_huge_get_and_clear uses a version of pmd_clear() with a
 * different prototype.
 */
#define __HAVE_ARCH_PMDP_HUGE_GET_AND_CLEAR
static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
					    unsigned long address, pmd_t *pmdp)
{
	pmd_t old = *pmdp;

	pmd_clear(pmdp);

	return old;
}

#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#ifdef CONFIG_NUMA_BALANCING
static inline long pte_protnone(pte_t pte)
{
	return (pte_val(pte) & _PAGE_PROTNONE);
}

static inline long pmd_protnone(pmd_t pmd)
{
	return (pmd_val(pmd) & _PAGE_PROTNONE);
}
#endif /* CONFIG_NUMA_BALANCING */

/*
 * We provide our own get_unmapped area to cope with the virtual aliasing
 * constraints placed on us by the cache architecture.
 */
#define HAVE_ARCH_UNMAPPED_AREA
#define HAVE_ARCH_UNMAPPED_AREA_TOPDOWN

#endif /* _ASM_PGTABLE_H */
