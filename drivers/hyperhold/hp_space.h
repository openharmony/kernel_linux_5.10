/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/hyperhold/hp_space.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _HP_SPACE_H_
#define _HP_SPACE_H_

#include <linux/kernel.h>

struct hp_space {
	u32 ext_size;
	u32 nr_ext;
	unsigned long *bitmap;
	atomic_t last_alloc_bit;
	atomic_t nr_alloced;
	wait_queue_head_t empty_wq;
};

void deinit_space(struct hp_space *spc);
bool init_space(struct hp_space *spc, u64 dev_size, u32 ext_size);
int alloc_eid(struct hp_space *spc);
void free_eid(struct hp_space *spc, u32 eid);

bool wait_for_space_empty(struct hp_space *spc, bool force);

u64 space_memory(void);
#endif
