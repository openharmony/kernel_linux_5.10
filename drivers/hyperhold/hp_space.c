// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/hyperhold/hp_space.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#define pr_fmt(fmt) "[HYPERHOLD]" fmt

#include <linux/mm.h>

#include "hp_space.h"

atomic64_t spc_mem = ATOMIC64_INIT(0);

u64 space_memory(void)
{
	return atomic64_read(&spc_mem);
}

void deinit_space(struct hp_space *spc)
{
	kvfree(spc->bitmap);
	atomic64_sub(BITS_TO_LONGS(spc->nr_ext) * sizeof(long), &spc_mem);
	spc->ext_size = 0;
	spc->nr_ext = 0;
	atomic_set(&spc->last_alloc_bit, 0);
	atomic_set(&spc->nr_alloced, 0);

	pr_info("hyperhold space deinited.\n");
}

bool init_space(struct hp_space *spc, u64 dev_size, u32 ext_size)
{
	if (ext_size & (PAGE_SIZE - 1)) {
		pr_err("extent size %u do not align to page size %lu!", ext_size, PAGE_SIZE);
		return false;
	}
	if (dev_size & (ext_size - 1)) {
		pr_err("device size %llu do not align to extent size %u!", dev_size, ext_size);
		return false;
	}
	spc->ext_size = ext_size;
	spc->nr_ext = div_u64(dev_size, ext_size);
	atomic_set(&spc->last_alloc_bit, 0);
	atomic_set(&spc->nr_alloced, 0);
	init_waitqueue_head(&spc->empty_wq);
	spc->bitmap = kvzalloc(BITS_TO_LONGS(spc->nr_ext) * sizeof(long), GFP_KERNEL);
	if (!spc->bitmap) {
		pr_err("hyperhold bitmap alloc failed.\n");
		return false;
	}
	atomic64_add(BITS_TO_LONGS(spc->nr_ext) * sizeof(long), &spc_mem);

	pr_info("hyperhold space init succ, capacity = %u x %u.\n", ext_size, spc->nr_ext);

	return true;
}

int alloc_eid(struct hp_space *spc)
{
	u32 bit;
	u32 last_bit;

retry:
	last_bit = atomic_read(&spc->last_alloc_bit);
	bit = find_next_zero_bit(spc->bitmap, spc->nr_ext, last_bit);
	if (bit == spc->nr_ext)
		bit = find_next_zero_bit(spc->bitmap, spc->nr_ext, 0);
	if (bit == spc->nr_ext)
		goto full;
	if (test_and_set_bit(bit, spc->bitmap))
		goto retry;

	atomic_set(&spc->last_alloc_bit, bit);
	atomic_inc(&spc->nr_alloced);

	pr_info("hyperhold alloc extent %u.\n", bit);

	return bit;
full:
	pr_err("hyperhold space is full.\n");

	return -ENOSPC;
}

void free_eid(struct hp_space *spc, u32 eid)
{
	if (!test_and_clear_bit(eid, spc->bitmap)) {
		pr_err("eid is not alloced!\n");
		BUG();
		return;
	}
	if (atomic_dec_and_test(&spc->nr_alloced)) {
		pr_info("notify space empty.\n");
		wake_up(&spc->empty_wq);
	}
	pr_info("hyperhold free extent %u.\n", eid);
}

static void dump_space(struct hp_space *spc)
{
	u32 i = 0;

	pr_info("dump alloced extent in space.\n");
	for (i = 0; i < spc->nr_ext; i++)
		if (test_bit(i, spc->bitmap))
			pr_info("alloced eid %u.\n", i);
}

bool wait_for_space_empty(struct hp_space *spc, bool force)
{
	if (!atomic_read(&spc->nr_alloced))
		return true;
	if (!force)
		return false;

	dump_space(spc);
	wait_event(spc->empty_wq, !atomic_read(&spc->nr_alloced));

	return true;
}
