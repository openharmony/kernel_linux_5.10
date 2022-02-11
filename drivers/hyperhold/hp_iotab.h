/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/hyperhold/hp_iotab.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _HP_IOTAB_H_
#define _HP_IOTAB_H_

#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/completion.h>
#include <linux/workqueue.h>

enum hpio_state {
	HPIO_INIT,
	HPIO_SUBMIT,
	HPIO_DONE,
	HPIO_FAIL,
};

struct hpio;

typedef void (*hp_endio)(struct hpio *);

struct hpio {
	u32 eid;
	struct page **pages;
	u32 nr_page;
	void *private;

	unsigned int op;
	void (*free_extent)(u32 eid);

	atomic_t state;
	struct kref refcnt;
	struct completion wait;
	hp_endio endio;
	struct work_struct endio_work;

	struct bio *bio;
	struct list_head list;
};

struct hpio *hpio_alloc(u32 nr_page, gfp_t gfp, unsigned int op, bool new_page);
void hpio_free(struct hpio *hpio);

struct hpio *hpio_get(u32 eid);
bool hpio_put(struct hpio *hpio);
struct hpio *hpio_get_alloc(u32 eid, u32 nr_page, gfp_t gfp, unsigned int op);

void hpio_complete(struct hpio *hpio);
void hpio_wait(struct hpio *hpio);

enum hpio_state hpio_get_state(struct hpio *hpio);
void hpio_set_state(struct hpio *hpio, enum hpio_state state);
bool hpio_change_state(struct hpio *hpio, enum hpio_state from, enum hpio_state to);

void wait_for_iotab_empty(void);

u64 hpio_memory(void);
#endif
