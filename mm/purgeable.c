// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 */

#include <asm/page.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/radix-tree.h>
#include <linux/rmap.h>
#include <linux/slab.h>
#include <linux/oom.h> /* find_lock_task_mm */

#include <linux/mm_purgeable.h>

struct uxpte_t {
	atomic64_t val;
};

#define UXPTE_SIZE_SHIFT 3
#define UXPTE_SIZE (1 << UXPTE_SIZE_SHIFT)

#define UXPTE_PER_PAGE_SHIFT (PAGE_SHIFT - UXPTE_SIZE_SHIFT)
#define UXPTE_PER_PAGE (1 << UXPTE_PER_PAGE_SHIFT)

#define UXPTE_PRESENT_BIT 1
#define UXPTE_PRESENT_MASK ((1 << UXPTE_PRESENT_BIT) - 1)
#define UXPTE_REFCNT_ONE (1 << UXPTE_PRESENT_BIT)
#define UXPTE_UNDER_RECLAIM (-UXPTE_REFCNT_ONE)

#define vpn(vaddr) ((vaddr) >> PAGE_SHIFT)
#define uxpte_pn(vaddr) (vpn(vaddr) >> UXPTE_PER_PAGE_SHIFT)
#define uxpte_off(vaddr) (vpn(vaddr) & (UXPTE_PER_PAGE - 1))
#define uxpn2addr(uxpn) ((uxpn) << (UXPTE_PER_PAGE_SHIFT + PAGE_SHIFT))
#define uxpte_refcnt(uxpte) ((uxpte) >> UXPTE_PRESENT_BIT)
#define uxpte_present(uxpte) ((uxpte) & UXPTE_PRESENT_MASK)

static inline long uxpte_read(struct uxpte_t *uxpte)
{
	return atomic64_read(&uxpte->val);
}

static inline void uxpte_set(struct uxpte_t *uxpte, long val)
{
	atomic64_set(&uxpte->val, val);
}

static inline bool uxpte_cas(struct uxpte_t *uxpte, long old, long new)
{
	return atomic64_cmpxchg(&uxpte->val, old, new) == old;
}

void mm_init_uxpgd(struct mm_struct *mm)
{
	mm->uxpgd = NULL;
	spin_lock_init(&mm->uxpgd_lock);
}

void mm_clear_uxpgd(struct mm_struct *mm)
{
	struct page *page = NULL;
	void **slot = NULL;
	struct radix_tree_iter iter;

	spin_lock(&mm->uxpgd_lock);
	if (!mm->uxpgd)
		goto out;
	radix_tree_for_each_slot(slot, mm->uxpgd, &iter, 0) {
		page = radix_tree_delete(mm->uxpgd, iter.index);
		put_page(page);
	}
out:
	kfree(mm->uxpgd);
	mm->uxpgd = NULL;
	spin_unlock(&mm->uxpgd_lock);
}

/* should hold uxpgd_lock before invoke */
static struct page *lookup_uxpte_page(struct vm_area_struct *vma,
	unsigned long addr, bool alloc)
{
	struct radix_tree_root *uxpgd = NULL;
	struct page *page = NULL;
	struct page *new_page = NULL;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long uxpn = uxpte_pn(addr);

	if (mm->uxpgd)
		goto lookup;
	if (!alloc)
		goto out;
	spin_unlock(&mm->uxpgd_lock);
	uxpgd = kzalloc(sizeof(struct radix_tree_root), GFP_KERNEL);
	if (!uxpgd) {
		pr_err("uxpgd alloc failed.\n");
		spin_lock(&mm->uxpgd_lock);
		goto out;
	}
	INIT_RADIX_TREE(uxpgd, GFP_KERNEL);
	spin_lock(&mm->uxpgd_lock);
	if (mm->uxpgd)
		kfree(uxpgd);
	else
		mm->uxpgd = uxpgd;
lookup:
	page = radix_tree_lookup(mm->uxpgd, uxpn);
	if (page)
		goto out;
	if (!alloc)
		goto out;
	spin_unlock(&mm->uxpgd_lock);
	new_page = alloc_zeroed_user_highpage_movable(vma, addr);
	if (!new_page) {
		pr_err("uxpte page alloc fail.\n");
		spin_lock(&mm->uxpgd_lock);
		goto out;
	}
	if (radix_tree_preload(GFP_KERNEL)) {
		put_page(new_page);
		pr_err("radix preload fail.\n");
		spin_lock(&mm->uxpgd_lock);
		goto out;
	}
	spin_lock(&mm->uxpgd_lock);
	page = radix_tree_lookup(mm->uxpgd, uxpn);
	if (page) {
		put_page(new_page);
	} else {
		page = new_page;
		radix_tree_insert(mm->uxpgd, uxpn, page);
	}
	radix_tree_preload_end();
out:
	return page;
}

/* should hold uxpgd_lock before invoke */
static struct uxpte_t *lookup_uxpte(struct vm_area_struct *vma,
		unsigned long addr, bool alloc)
{
	struct uxpte_t *uxpte = NULL;
	struct page *page = NULL;

	page = lookup_uxpte_page(vma, addr, alloc);
	if (!page)
		return NULL;
	uxpte = page_to_virt(page);

	return uxpte + uxpte_off(addr);
}

bool lock_uxpte(struct vm_area_struct *vma, unsigned long addr)
{
	struct uxpte_t *uxpte = NULL;
	long val = 0;

	spin_lock(&vma->vm_mm->uxpgd_lock);
	uxpte = lookup_uxpte(vma, addr, true);
	if (!uxpte)
		goto unlock;
retry:
	val = uxpte_read(uxpte);
	if (val >> 1)
		goto unlock;
	if (!uxpte_cas(uxpte, val, UXPTE_UNDER_RECLAIM))
		goto retry;
	val = UXPTE_UNDER_RECLAIM;
unlock:
	spin_unlock(&vma->vm_mm->uxpgd_lock);

	return val == UXPTE_UNDER_RECLAIM;
}

void unlock_uxpte(struct vm_area_struct *vma, unsigned long addr)
{
	struct uxpte_t *uxpte = NULL;

	spin_lock(&vma->vm_mm->uxpgd_lock);
	uxpte = lookup_uxpte(vma, addr, false);
	if (!uxpte)
		goto unlock;
	uxpte_set(uxpte, 0);
unlock:
	spin_unlock(&vma->vm_mm->uxpgd_lock);
}

bool uxpte_set_present(struct vm_area_struct *vma, unsigned long addr)
{
	struct uxpte_t *uxpte = NULL;
	long val = 0;

	spin_lock(&vma->vm_mm->uxpgd_lock);
	uxpte = lookup_uxpte(vma, addr, true);
	if (!uxpte)
		goto unlock;
retry:
	val = uxpte_read(uxpte);
	if (val & 1)
		goto unlock;
	if (!uxpte_cas(uxpte, val, val + 1))
		goto retry;
	val++;
unlock:
	spin_unlock(&vma->vm_mm->uxpgd_lock);

	return val & 1;
}

void uxpte_clear_present(struct vm_area_struct *vma, unsigned long addr)
{
	struct uxpte_t *uxpte = NULL;
	long val = 0;

	spin_lock(&vma->vm_mm->uxpgd_lock);
	uxpte = lookup_uxpte(vma, addr, false);
	if (!uxpte)
		goto unlock;
retry:
	val = uxpte_read(uxpte);
	if (!(val & 1))
		goto unlock;
	if (!uxpte_cas(uxpte, val, val - 1))
		goto retry;
unlock:
	spin_unlock(&vma->vm_mm->uxpgd_lock);
}

vm_fault_t do_uxpte_page_fault(struct vm_fault *vmf, pte_t *entry)
{
	struct vm_area_struct *vma = vmf->vma;
	unsigned long vma_uxpn = vma->vm_pgoff;
	unsigned long off_uxpn = vpn(vmf->address - vma->vm_start);
	unsigned long addr = uxpn2addr(vma_uxpn + off_uxpn);
	struct page *page = NULL;

	if (unlikely(anon_vma_prepare(vma)))
		return VM_FAULT_OOM;

	spin_lock(&vma->vm_mm->uxpgd_lock);
	page = lookup_uxpte_page(vma, addr, true);
	spin_unlock(&vma->vm_mm->uxpgd_lock);

	if (!page)
		return VM_FAULT_OOM;

	*entry = mk_pte(page, vma->vm_page_prot);
	*entry = pte_sw_mkyoung(*entry);
	if (vma->vm_flags & VM_WRITE)
		*entry = pte_mkwrite(pte_mkdirty(*entry));
	return 0;
}

static void __mm_purg_pages_info(struct mm_struct *mm, unsigned long *total_purg_pages,
	unsigned long *pined_purg_pages)
{
	struct page *page = NULL;
	void **slot = NULL;
	struct radix_tree_iter iter;
	struct uxpte_t *uxpte = NULL;
	long pte_entry = 0;
	int index = 0;
	unsigned long nr_total = 0, nr_pined = 0;

	spin_lock(&mm->uxpgd_lock);
	if (!mm->uxpgd)
		goto out;
	radix_tree_for_each_slot(slot, mm->uxpgd, &iter, 0) {
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;
		uxpte = page_to_virt(page);
		for (index = 0; index < UXPTE_PER_PAGE; index++) {
			pte_entry = uxpte_read(&(uxpte[index]));
			if (uxpte_present(pte_entry) == 0) /* not present */
				continue;
			nr_total++;
			if (uxpte_refcnt(pte_entry) > 0) /* pined by user */
				nr_pined++;
		}
	}
out:
	spin_unlock(&mm->uxpgd_lock);

	if (total_purg_pages)
		*total_purg_pages = nr_total;

	if (pined_purg_pages)
		*pined_purg_pages = nr_pined;
}

void mm_purg_pages_info(struct mm_struct *mm, unsigned long *total_purg_pages,
	unsigned long *pined_purg_pages)
{
	if (unlikely(!mm))
		return;

	if (!total_purg_pages && !pined_purg_pages)
		return;

	__mm_purg_pages_info(mm, total_purg_pages, pined_purg_pages);
}

void purg_pages_info(unsigned long *total_purg_pages, unsigned long *pined_purg_pages)
{
	struct task_struct *p = NULL;
	struct task_struct *tsk = NULL;
	unsigned long mm_nr_purge = 0, mm_nr_pined = 0;
	unsigned long nr_total = 0, nr_pined = 0;

	if (!total_purg_pages && !pined_purg_pages)
		return;

	if (total_purg_pages)
		*total_purg_pages = 0;

	if (pined_purg_pages)
		*pined_purg_pages = 0;

	rcu_read_lock();
	for_each_process(p) {
		tsk = find_lock_task_mm(p);
		if (!tsk) {
			/*
			 * It is a kthread or all of p's threads have already
			 * detached their mm's.
			 */
			continue;
		}
		__mm_purg_pages_info(tsk->mm, &mm_nr_purge, &mm_nr_pined);
		nr_total += mm_nr_purge;
		nr_pined += mm_nr_pined;
		task_unlock(tsk);

		if (mm_nr_purge > 0) {
			pr_info("purgemm: tsk: %s %lu pined in %lu pages\n", tsk->comm ?: "NULL",
				mm_nr_pined, mm_nr_purge);
		}
	}
	rcu_read_unlock();
	if (total_purg_pages)
		*total_purg_pages = nr_total;

	if (pined_purg_pages)
		*pined_purg_pages = nr_pined;
	pr_info("purgemm: Sum: %lu pined in %lu pages\n", nr_pined, nr_total);
}
