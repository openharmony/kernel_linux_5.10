/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_PGTABLE_64_H
#define _ASM_PGTABLE_64_H

#include <linux/compiler.h>
#include <linux/linkage.h>

#include <asm/addrspace.h>

#if CONFIG_PGTABLE_LEVELS == 2
#include <asm-generic/pgtable-nopmd.h>
#elif CONFIG_PGTABLE_LEVELS == 3
#include <asm-generic/pgtable-nopud.h>
#else
#include <asm-generic/pgtable-nop4d.h>
#endif

#define PGD_ORDER		0
#define PUD_ORDER		0
#define PMD_ORDER		0
#define PTE_ORDER		0

#if CONFIG_PGTABLE_LEVELS == 2
#define PGDIR_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT + PTE_ORDER - 3))
#elif CONFIG_PGTABLE_LEVELS == 3
#define PMD_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT + PTE_ORDER - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))
#define PGDIR_SHIFT	(PMD_SHIFT + (PAGE_SHIFT + PMD_ORDER - 3))
#elif CONFIG_PGTABLE_LEVELS == 4
#define PMD_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT + PTE_ORDER - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))
#define PUD_SHIFT	(PMD_SHIFT + (PAGE_SHIFT + PMD_ORDER - 3))
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE-1))
#define PGDIR_SHIFT	(PUD_SHIFT + (PAGE_SHIFT + PUD_ORDER - 3))
#endif

#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))

#define VA_BITS		(PGDIR_SHIFT + (PAGE_SHIFT + PGD_ORDER - 3))

#define PTRS_PER_PGD	((PAGE_SIZE << PGD_ORDER) >> 3)
#if CONFIG_PGTABLE_LEVELS > 3
#define PTRS_PER_PUD	((PAGE_SIZE << PUD_ORDER) >> 3)
#endif
#if CONFIG_PGTABLE_LEVELS > 2
#define PTRS_PER_PMD	((PAGE_SIZE << PMD_ORDER) >> 3)
#endif
#define PTRS_PER_PTE	((PAGE_SIZE << PTE_ORDER) >> 3)

#define USER_PTRS_PER_PGD       ((TASK_SIZE64 / PGDIR_SIZE)?(TASK_SIZE64 / PGDIR_SIZE):1)
#define FIRST_USER_ADDRESS	0UL

#ifndef __ASSEMBLY__

#include <asm/fixmap.h>
#include <asm/sparsemem.h>

/*
 * TLB refill handlers may also map the vmalloc area into xkvrange.
 * Avoid the first couple of pages so NULL pointer dereferences will
 * still reliably trap.
 */
#define MODULES_VADDR	(vm_map_base + PCI_IOSIZE + (2 * PAGE_SIZE))
#define MODULES_END	(MODULES_VADDR + SZ_256M)

#define VMALLOC_START	MODULES_END

#ifndef CONFIG_KASAN
#define VMALLOC_END	\
	(vm_map_base +	\
	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
#else
#define VMALLOC_END	\
	(vm_map_base +	\
	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits) / 2) - PMD_SIZE - VMEMMAP_SIZE)
#endif

#define vmemmap		((struct page *)((VMALLOC_END + PMD_SIZE) & PMD_MASK))
#define VMEMMAP_END	((unsigned long)vmemmap + VMEMMAP_SIZE - 1)

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val(e))
#ifndef __PAGETABLE_PMD_FOLDED
#define pmd_ERROR(e) \
	printk("%s:%d: bad pmd %016lx.\n", __FILE__, __LINE__, pmd_val(e))
#endif
#ifndef __PAGETABLE_PUD_FOLDED
#define pud_ERROR(e) \
	printk("%s:%d: bad pud %016lx.\n", __FILE__, __LINE__, pud_val(e))
#endif
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %016lx.\n", __FILE__, __LINE__, pgd_val(e))

extern pte_t invalid_pte_table[PTRS_PER_PTE];

#ifndef __PAGETABLE_PUD_FOLDED

typedef struct { unsigned long pud; } pud_t;
#define pud_val(x)	((x).pud)
#define __pud(x)	((pud_t) { (x) })

extern pud_t invalid_pud_table[PTRS_PER_PUD];

/*
 * Empty pgd/p4d entries point to the invalid_pud_table.
 */
static inline int p4d_none(p4d_t p4d)
{
	return p4d_val(p4d) == (unsigned long)invalid_pud_table;
}

static inline int p4d_bad(p4d_t p4d)
{
	return p4d_val(p4d) & ~PAGE_MASK;
}

static inline int p4d_present(p4d_t p4d)
{
	return p4d_val(p4d) != (unsigned long)invalid_pud_table;
}

static inline void p4d_clear(p4d_t *p4dp)
{
	p4d_val(*p4dp) = (unsigned long)invalid_pud_table;
}

static inline pud_t *p4d_pgtable(p4d_t p4d)
{
	return (pud_t *)p4d_val(p4d);
}

static inline void set_p4d(p4d_t *p4d, p4d_t p4dval)
{
	*p4d = p4dval;
}

#define p4d_phys(p4d)		PHYSADDR(p4d_val(p4d))
#define p4d_page(p4d)		(pfn_to_page(p4d_phys(p4d) >> PAGE_SHIFT))

#endif

#ifndef __PAGETABLE_PMD_FOLDED

typedef struct { unsigned long pmd; } pmd_t;
#define pmd_val(x)	((x).pmd)
#define __pmd(x)	((pmd_t) { (x) } )

extern pmd_t invalid_pmd_table[PTRS_PER_PMD];

/*
 * Empty pud entries point to the invalid_pmd_table.
 */
static inline int pud_none(pud_t pud)
{
	return pud_val(pud) == (unsigned long)invalid_pmd_table;
}

static inline int pud_bad(pud_t pud)
{
	return pud_val(pud) & ~PAGE_MASK;
}

static inline int pud_present(pud_t pud)
{
	return pud_val(pud) != (unsigned long)invalid_pmd_table;
}

static inline void pud_clear(pud_t *pudp)
{
	pud_val(*pudp) = ((unsigned long)invalid_pmd_table);
}

static inline pmd_t *pud_pgtable(pud_t pud)
{
	return (pmd_t *)pud_val(pud);
}

#define set_pud(pudptr, pudval) do { *(pudptr) = (pudval); } while (0)

#define pud_phys(pud)		PHYSADDR(pud_val(pud))
#define pud_page(pud)		(pfn_to_page(pud_phys(pud) >> PAGE_SHIFT))

#endif

/*
 * Empty pmd entries point to the invalid_pte_table.
 */
static inline int pmd_none(pmd_t pmd)
{
	return pmd_val(pmd) == (unsigned long)invalid_pte_table;
}

static inline int pmd_bad(pmd_t pmd)
{
	return (pmd_val(pmd) & ~PAGE_MASK);
}

static inline int pmd_present(pmd_t pmd)
{
	if (unlikely(pmd_val(pmd) & _PAGE_HUGE))
		return !!(pmd_val(pmd) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_PRESENT_INVALID));

	return pmd_val(pmd) != (unsigned long)invalid_pte_table;
}

static inline void pmd_clear(pmd_t *pmdp)
{
	pmd_val(*pmdp) = ((unsigned long)invalid_pte_table);
}

#define set_pmd(pmdptr, pmdval) do { *(pmdptr) = (pmdval); } while (0)

#define pmd_phys(pmd)		PHYSADDR(pmd_val(pmd))

#ifndef CONFIG_TRANSPARENT_HUGEPAGE
#define pmd_page(pmd)		(pfn_to_page(pmd_phys(pmd) >> PAGE_SHIFT))
#endif /* CONFIG_TRANSPARENT_HUGEPAGE  */

#define pmd_page_vaddr(pmd)	pmd_val(pmd)

extern pmd_t mk_pmd(struct page *page, pgprot_t prot);
extern void set_pmd_at(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp, pmd_t pmd);

#define pte_page(x)		pfn_to_page(pte_pfn(x))
#define pte_pfn(x)		((unsigned long)(((x).pte & _PFN_MASK) >> _PFN_SHIFT))
#define pfn_pte(pfn, prot)	__pte(((pfn) << _PFN_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot)	__pmd(((pfn) << _PFN_SHIFT) | pgprot_val(prot))

/*
 * Initialize a new pgd / pmd table with invalid pointers.
 */
extern void pgd_init(unsigned long page);
extern void pud_init(unsigned long page, unsigned long pagetable);
extern void pmd_init(unsigned long page, unsigned long pagetable);

/*
 * Non-present pages:  high 40 bits are offset, next 8 bits type,
 * low 16 bits zero.
 */
static inline pte_t mk_swap_pte(unsigned long type, unsigned long offset)
{ pte_t pte; pte_val(pte) = (type << 16) | (offset << 24); return pte; }

#define __swp_type(x)		(((x).val >> 16) & 0xff)
#define __swp_offset(x)		((x).val >> 24)
#define __swp_entry(type, offset) ((swp_entry_t) { pte_val(mk_swap_pte((type), (offset))) })
#define __pte_to_swp_entry(pte) ((swp_entry_t) { pte_val(pte) })
#define __swp_entry_to_pte(x)	((pte_t) { (x).val })
#define __pmd_to_swp_entry(pmd) ((swp_entry_t) { pmd_val(pmd) })
#define __swp_entry_to_pmd(x)	((pmd_t) { (x).val | _PAGE_HUGE })

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_PGTABLE_64_H */
