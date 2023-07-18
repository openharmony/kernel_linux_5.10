/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/comm/node_cb.h
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#ifndef HMDFS_NODE_CB_H
#define HMDFS_NODE_CB_H

#include "hmdfs.h"

/* async & sync */
#define NODE_EVT_TYPE_NR 2

enum {
	NODE_EVT_ADD = 0,
	NODE_EVT_ONLINE,
	NODE_EVT_OFFLINE,
	NODE_EVT_DEL,
	NODE_EVT_NR,
};

struct hmdfs_peer;

typedef void (*hmdfs_node_evt_cb)(struct hmdfs_peer *conn,
				  int evt, unsigned int seq);

struct hmdfs_node_cb_desc {
	int evt;
	bool sync;
	hmdfs_node_evt_cb fn;
	struct list_head list;
};

extern void hmdfs_node_evt_cb_init(void);

/* Only initialize during module init */
extern void hmdfs_node_add_evt_cb(struct hmdfs_node_cb_desc *desc, int nr);
extern void hmdfs_node_call_evt_cb(struct hmdfs_peer *node, int evt, bool sync,
				   unsigned int seq);

#endif /* HMDFS_NODE_CB_H */
