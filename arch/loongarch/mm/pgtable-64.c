// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#include <linux/export.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

void pgd_init(unsigned long page)
{
	unsigned long *p, *end;
	unsigned long entry;

#if !defined(__PAGETABLE_PUD_FOLDED)
	entry = (unsigned long)invalid_pud_table;
#elif !defined(__PAGETABLE_PMD_FOLDED)
	entry = (unsigned long)invalid_pmd_table;
#else
	entry = (unsigned long)invalid_pte_table;
#endif

	p = (unsigned long *) page;
	end = p + PTRS_PER_PGD;

	do {
		p[0] = entry;
		p[1] = entry;
		p[2] = entry;
		p[3] = entry;
		p[4] = entry;
		p += 8;
		p[-3] = entry;
		p[-2] = entry;
		p[-1] = entry;
	} while (p != end);
}
EXPORT_SYMBOL_GPL(pgd_init);

#ifndef __PAGETABLE_PMD_FOLDED
void pmd_init(unsigned long addr, unsigned long pagetable)
{
	unsigned long *p, *end;

	p = (unsigned long *) addr;
	end = p + PTRS_PER_PMD;

	do {
		p[0] = pagetable;
		p[1] = pagetable;
		p[2] = pagetable;
		p[3] = pagetable;
		p[4] = pagetable;
		p += 8;
		p[-3] = pagetable;
		p[-2] = pagetable;
		p[-1] = pagetable;
	} while (p != end);
}
EXPORT_SYMBOL_GPL(pmd_init);
#endif

#ifndef __PAGETABLE_PUD_FOLDED
void pud_init(unsigned long addr, unsigned long pagetable)
{
	unsigned long *p, *end;

	p = (unsigned long *)addr;
	end = p + PTRS_PER_PUD;

	do {
		p[0] = pagetable;
		p[1] = pagetable;
		p[2] = pagetable;
		p[3] = pagetable;
		p[4] = pagetable;
		p += 8;
		p[-3] = pagetable;
		p[-2] = pagetable;
		p[-1] = pagetable;
	} while (p != end);
}
#endif

pmd_t mk_pmd(struct page *page, pgprot_t prot)
{
	pmd_t pmd;

	pmd_val(pmd) = (page_to_pfn(page) << _PFN_SHIFT) | pgprot_val(prot);

	return pmd;
}

void set_pmd_at(struct mm_struct *mm, unsigned long addr,
		pmd_t *pmdp, pmd_t pmd)
{
	*pmdp = pmd;
	flush_tlb_all();
}

void __init pagetable_init(void)
{
	unsigned long vaddr;

	/* Initialize the entire pgd.  */
	pgd_init((unsigned long)swapper_pg_dir);
	pgd_init((unsigned long)invalid_pg_dir);
#ifndef __PAGETABLE_PUD_FOLDED
	pud_init((unsigned long)invalid_pud_table, (unsigned long)invalid_pmd_table);
#endif
#ifndef __PAGETABLE_PMD_FOLDED
	pmd_init((unsigned long)invalid_pmd_table, (unsigned long)invalid_pte_table);
#endif
	/*
	 * Fixed mappings:
	 */
	vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
}
