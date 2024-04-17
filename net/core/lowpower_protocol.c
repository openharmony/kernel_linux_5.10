// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 *
 * Operations on the lowpower protocol
 * Authors: yangyanjun
 */
#ifdef CONFIG_LOWPOWER_PROTOCOL
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/printk.h>
#include <linux/net_namespace.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/lowpower_protocol.h>

static atomic_t g_foreground_uid = ATOMIC_INIT(FOREGROUND_UID_INIT);

static void foreground_uid_atomic_set(uid_t val)
{
	atomic_set(&g_foreground_uid, val);
}

static uid_t foreground_uid_atomic_read(void)
{
	return (uid_t)atomic_read(&g_foreground_uid);
}

static int foreground_uid_show(struct seq_file *seq, void *v)
{
	uid_t uid = foreground_uid_atomic_read();

	seq_printf(seq, "%u\n", uid);
	return 0;
}

// echo xx > /proc/net/foreground_uid
static int foreground_uid_write(struct file *file, char *buf, size_t size)
{
	char *p = buf;
	uid_t uid = simple_strtoul(p, &p, 10);

	if (!p)
		return -EINVAL;

	foreground_uid_atomic_set(uid);
	return 0;
}

// call this fun in net/ipv4/af_inet.c inet_init_net()
void __net_init lowpower_protocol_net_init(struct net *net)
{
	if (!proc_create_net_single_write("foreground_uid", 0644,
					  net->proc_net,
					  foreground_uid_show,
					  foreground_uid_write,
					  NULL))
		pr_err("fail to register /proc/net/foreground_uid");
}

static bool foreground_uid_match(struct net *net, struct sock *sk)
{
	uid_t kuid;
	uid_t foreground_uid;

	if (!sk)
		return false;

	kuid = sock_net_uid(net, sk).val;
	foreground_uid = foreground_uid_atomic_read();
	if (kuid != foreground_uid)
		return false;

	return true;
}

/* 
 * ack optimization is only enable for large data receiving tasks and
 * there is no packet loss scenario
 */
int tcp_ack_num(struct sock *sk)
{
	if (!sk)
		return 1;

	if (foreground_uid_match(sock_net(sk), sk) == false)
		return 1;

	if (tcp_sk(sk)->bytes_received >= BIG_DATA_BYTES &&
	    tcp_sk(sk)->dup_ack_counter < TCP_FASTRETRANS_THRESH)
		return TCP_ACK_NUM;
	return 1;
}

bool netfilter_bypass_enable(struct net *net, struct sk_buff *skb,
			     int (*fun)(struct net *, struct sock *, struct sk_buff *),
			     int *ret)
{
	if (!net || !skb || ip_hdr(skb)->protocol != IPPROTO_TCP)
		return false;

	if (foreground_uid_match(net, skb->sk)) {
		*ret = fun(net, NULL, skb);
		return true;
	}
	return false;
}
#endif /* CONFIG_LOWPOWER_PROTOCOL */
