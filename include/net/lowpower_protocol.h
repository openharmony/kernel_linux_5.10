/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 *
 * Operations on the lowpower protocol
 * Authors: yangyanjun
 */
#ifndef __LOWPOWER_PROTOCOL_H
#define __LOWPOWER_PROTOCOL_H

#ifdef CONFIG_LOWPOWER_PROTOCOL
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/printk.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>

#define FOREGROUND_UID_INIT 0xEFFFFFFF
#define TCP_RCV_WND_INIT 133120
#define BIG_DATA_BYTES 200000
#define TCP_ACK_NUM 30

void __net_init lowpower_protocol_net_init(struct net *net);
int tcp_ack_num(struct sock *sk);
bool netfilter_bypass_enable(struct net *net, struct sk_buff *skb,
			     int (*fun)(struct net *, struct sock *, struct sk_buff *),
			     int *ret);
bool dpa_uid_match(uid_t kuid);
#endif /* CONFIG_LOWPOWER_PROTOCOL */
#endif /* __LOWPOWER_PROTOCOL_H */