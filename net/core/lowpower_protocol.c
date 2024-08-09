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
#include <linux/list.h>
#include <linux/rwlock_types.h>
#include <linux/net_namespace.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/lowpower_protocol.h>

static atomic_t g_foreground_uid = ATOMIC_INIT(FOREGROUND_UID_INIT);
#define OPT_LEN 3
#define TO_DECIMAL 10
#define DPA_UID_LIST_CNT_MAX 500
#define DECIMAL_CHAR_NUM 10 // u32 decimal characters (4,294,967,295)
static DEFINE_RWLOCK(g_dpa_rwlock);
static u32 g_dpa_uid_list_cnt;
static struct list_head g_dpa_uid_list;
struct dpa_node {
	struct list_head list_node;
	uid_t uid;
};

static void foreground_uid_atomic_set(uid_t val)
{
	atomic_set(&g_foreground_uid, val);
}

static uid_t foreground_uid_atomic_read(void)
{
	return (uid_t)atomic_read(&g_foreground_uid);
}

// cat /proc/net/foreground_uid
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
	uid_t uid = simple_strtoul(p, &p, TO_DECIMAL);

	if (!p)
		return -EINVAL;

	foreground_uid_atomic_set(uid);
	return 0;
}

// cat /proc/net/dpa_uid
static int dpa_uid_show(struct seq_file *seq, void *v)
{
	struct dpa_node *node = NULL;
	struct dpa_node *tmp_node = NULL;

	read_lock(&g_dpa_rwlock);
	list_for_each_entry_safe(node, tmp_node, &g_dpa_uid_list, list_node)
		seq_printf(seq, "%u\n", node->uid);
	read_unlock(&g_dpa_rwlock);
	return 0;
}

static int dpa_uid_add(uid_t uid);
static int dpa_uid_del(uid_t uid);
static uid_t get_dpa_uid_from_buf(char *buf, size_t size);
static int dpa_uid_write(struct file *file, char *buf, size_t size)
{
	uid_t uid = get_dpa_uid_from_buf(buf, size);

	if (!uid)
		return -EINVAL;

	if (strncmp(buf, "add", OPT_LEN) == 0) {
		return dpa_uid_add(uid);
	} else if (strncmp(buf, "del", OPT_LEN) == 0) {
		return dpa_uid_del(uid);
	} else {
		pr_err("[dpa-uid-cfg] opt unknown\n");
		return -EINVAL;
	}
}

// echo "add xx" > /proc/net/dpa_uid
static int dpa_uid_add(uid_t uid)
{
	bool exist = false;
	struct dpa_node *node = NULL;
	struct dpa_node *tmp_node = NULL;

	write_lock(&g_dpa_rwlock);
	if (g_dpa_uid_list_cnt >= DPA_UID_LIST_CNT_MAX) {
		write_unlock(&g_dpa_rwlock);
		return -EFBIG;
	}

	list_for_each_entry_safe(node, tmp_node, &g_dpa_uid_list, list_node) {
		if (node->uid == uid) {
			exist = true;
			break;
		}
	}

	if (!exist) {
		node = kzalloc(sizeof(*node), GFP_ATOMIC);
		if (node) {
			node->uid = uid;
			list_add_tail(&node->list_node, &g_dpa_uid_list);
			g_dpa_uid_list_cnt++;
		}
	}
	write_unlock(&g_dpa_rwlock);
	return 0;
}

// echo "del xx" > /proc/net/dpa_uid
static int dpa_uid_del(uid_t uid)
{
	struct dpa_node *node = NULL;
	struct dpa_node *tmp_node = NULL;

	write_lock(&g_dpa_rwlock);
	list_for_each_entry_safe(node, tmp_node, &g_dpa_uid_list, list_node) {
		if (node->uid == uid) {
			list_del(&node->list_node);
			if (g_dpa_uid_list_cnt)
				--g_dpa_uid_list_cnt;
			break;
		}
	}
	write_unlock(&g_dpa_rwlock);
	return 0;
}

static uid_t get_dpa_uid_from_buf(char *buf, size_t size)
{
	char *args = NULL;
	char *args1 = NULL;
	uid_t uid = 0;
	u32 len = 0;
	u32 opt_len;
	u32 data_len;

	// split into command and argslist
	args = strchr(buf, ' ');
	if (!args) {
		pr_err("[dpa-uid-cfg] no space separator\n");
		return uid;
	}

	// opt cmd is add or del, len is 3
	opt_len = args - buf;
	if (opt_len != OPT_LEN) {
		pr_err("[dpa-uid-cfg] opt len invalid\n");
		return uid;
	}

	data_len = size - (opt_len + 1);
	if (data_len > DECIMAL_CHAR_NUM + 1) {
		pr_err("[dpa-uid-cfg] characters len(%u) out of scope\n", data_len);
		return uid;
	}

	// u32 decimal characters (4,294,967,295)
	args1 = ++args;
	while (*args1 != '\n' && len < data_len) {
		if (*args1 < '0' || *args1 > '9') {
			pr_err("[dpa-uid-cfg] uid contains invalid character '%c'\n", *args1);
			return uid;
		}
		args1++;
		len++;
	}

	if (*args1 != '\n') {
		pr_err("[dpa-uid-cfg] u32 characters len(%u) out of scope\n", len);
		return uid;
	}

	uid = simple_strtoul(args, &args, TO_DECIMAL);
	if (!args || !uid)
		pr_err("[dpa-uid-cfg] fail to change uid-str to uid-data\n");
	return uid;
}

bool dpa_uid_match(uid_t kuid)
{
	bool match = false;
	struct dpa_node *node = NULL;
	struct dpa_node *tmp_node = NULL;

	if (kuid == 0)
		return match;

	read_lock(&g_dpa_rwlock);
	list_for_each_entry_safe(node, tmp_node, &g_dpa_uid_list, list_node) {
		if (node->uid == kuid) {
			match = true;
			break;
		}
	}
	read_unlock(&g_dpa_rwlock);
	return match;
}
EXPORT_SYMBOL(dpa_uid_match);

// call this fun in net/ipv4/af_inet.c inet_init_net()
void __net_init lowpower_protocol_net_init(struct net *net)
{
	if (!proc_create_net_single_write("foreground_uid", 0644,
					  net->proc_net,
					  foreground_uid_show,
					  foreground_uid_write,
					  NULL))
		pr_err("fail to create /proc/net/foreground_uid");

	INIT_LIST_HEAD(&g_dpa_uid_list);
	if (!proc_create_net_single_write("dpa_uid", 0644,
					  net->proc_net,
					  dpa_uid_show,
					  dpa_uid_write,
					  NULL))
		pr_err("fail to create /proc/net/dpa_uid");
}

static bool foreground_uid_match(struct net *net, struct sock *sk)
{
	uid_t kuid;
	uid_t foreground_uid;
	struct sock *fullsk;

	if (!net || !sk)
		return false;

	fullsk = sk_to_full_sk(sk);
	if (!fullsk || !sk_fullsock(fullsk))
		return false;

	kuid = sock_net_uid(net, fullsk).val;
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
	if (!net || !skb || !ip_hdr(skb) || ip_hdr(skb)->protocol != IPPROTO_TCP)
		return false;

	if (foreground_uid_match(net, skb->sk)) {
		*ret = fun(net, NULL, skb);
		return true;
	}
	return false;
}
#endif /* CONFIG_LOWPOWER_PROTOCOL */
