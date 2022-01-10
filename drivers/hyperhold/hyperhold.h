/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/hyperhold/hyperhold.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _HYPERHOLD_H_
#define _HYPERHOLD_H_

#include <linux/kernel.h>

struct hpio;

typedef void (*hp_endio)(struct hpio *);

void hyperhold_disable(bool force);
void hyperhold_enable(void);
bool is_hyperhold_enable(void);

u32 hyperhold_nr_extent(void);
u32 hyperhold_extent_size(u32 eid);
long hyperhold_address(u32 eid, u32 offset);
int hyperhold_addr_extent(u64 addr);
int hyperhold_addr_offset(u64 addr);

int hyperhold_alloc_extent(void);
void hyperhold_free_extent(u32 eid);
void hyperhold_should_free_extent(u32 eid);

struct hpio *hyperhold_io_alloc(u32 eid, gfp_t gfp, unsigned int op, bool new_page);
void hyperhold_io_free(struct hpio *hpio);

struct hpio *hyperhold_io_get(u32 eid, gfp_t gfp, unsigned int op);
bool hyperhold_io_put(struct hpio *hpio);

void hyperhold_io_complete(struct hpio *hpio);
void hyperhold_io_wait(struct hpio *hpio);

bool hyperhold_io_success(struct hpio *hpio);

int hyperhold_io_extent(struct hpio *hpio);
int hyperhold_io_operate(struct hpio *hpio);
struct page *hyperhold_io_page(struct hpio *hpio, u32 index);
bool hyperhold_io_add_page(struct hpio *hpio, u32 index, struct page *page);
u32 hyperhold_io_nr_page(struct hpio *hpio);
void *hyperhold_io_private(struct hpio *hpio);

int hyperhold_write_async(struct hpio *hpio, hp_endio endio, void *priv);
int hyperhold_read_async(struct hpio *hpio, hp_endio endio, void *priv);

#endif
