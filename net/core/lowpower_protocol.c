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
#define LIST_MAX 500
#define DECIMAL_CHAR_NUM 10 // u32 decimal characters (4,294,967,295)
static DEFINE_RWLOCK(g_dpa_rwlock);
static u32 g_dpa_uid_list_cnt;
static struct list_head g_dpa_uid_list;
struct dpa_node {
	struct list_head list_node;
	uid_t uid;
};
static ext_init g_dpa_init_fun;

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
	seq_printf(seq, "uid list num: %u\n", g_dpa_uid_list_cnt);
	list_for_each_entry_safe(node, tmp_node, &g_dpa_uid_list, list_node)
		seq_printf(seq, "%u\n", node->uid);
	read_unlock(&g_dpa_rwlock);
	return 0;
}

// echo "add xx yy zz" > /proc/net/dpa_uid
// echo "del xx yy zz" > /proc/net/dpa_uid
static int dpa_uid_add(uid_t uid);
static int dpa_uid_del(uid_t uid);
static int get_dpa_uids(char *buf, size_t size, u32 *uid_list,
			u32 index_max, u32 *index);
static void dpa_ext_init(void);
static int dpa_uid_write(struct file *file, char *buf, size_t size)
{
	u32 dpa_list[LIST_MAX];
	u32 index = 0;
	int ret = -EINVAL;
	int i;

	if (get_dpa_uids(buf, size, dpa_list, LIST_MAX, &index) != 0) {
		pr_err("[dpa-uid-cfg] fail to parse dpa uids\n");
		return ret;
	}

	if (strncmp(buf, "add", OPT_LEN) == 0) {
		dpa_ext_init();
		for (i = 0; i < index; i++) {
			ret = dpa_uid_add(dpa_list[i]);
			if (ret != 0) {
				pr_err("[dpa-uid-cfg] add fail, index=%u\n", i);
				return ret;
			}
		}
	} else if (strncmp(buf, "del", OPT_LEN) == 0) {
		for (i = 0; i < index; i++) {
			ret = dpa_uid_del(dpa_list[i]);
			if (ret != 0) {
				pr_err("[dpa-uid-cfg] del fail, index=%u\n", i);
				return ret;
			}
		}
	} else {
		pr_err("[dpa-uid-cfg] cmd unknown\n");
	}
	return ret;
}

static int dpa_uid_add(uid_t uid)
{
	bool exist = false;
	struct dpa_node *node = NULL;
	struct dpa_node *tmp_node = NULL;

	write_lock(&g_dpa_rwlock);
	if (g_dpa_uid_list_cnt >= LIST_MAX) {
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

static uid_t parse_single_uid(char *begin, char *end)
{
	char *cur = NULL;
	uid_t uid = 0;
	u32 len = end - begin;

	// u32 decimal characters (4,294,967,295)
	if (len > DECIMAL_CHAR_NUM) {
		pr_err("[dpa-uid-cfg] single uid len(%u) overflow\n", len);
		return uid;
	}

	cur = begin;
	while (cur < end) {
		if (*cur < '0' || *cur > '9') {
			pr_err("[dpa-uid-cfg] invalid character '%c'\n", *cur);
			return uid;
		}
		cur++;
	}

	uid = simple_strtoul(begin, &begin, TO_DECIMAL);
	if (!begin || !uid) {
		pr_err("[dpa-uid-cfg] fail to change str to data");
		return uid;
	}

	return uid;
}

static int parse_uids(char *args, u32 args_len, u32 *uid_list,
		      u32 index_max, u32 *index)
{
	char *begin = args;
	char *end = strchr(args, ' ');
	uid_t uid = 0;
	u32 len = 0;

	while (end) {
		// cur decimal characters cnt + ' ' or '\n'
		len += end - begin + 1;
		if (len > args_len || *index > index_max) {
			pr_err("[dpa-uid-cfg] str len(%u) or index(%u) overflow\n",
			       len, *index);
			return -EINVAL;
		}

		uid = parse_single_uid(begin, end);
		if (!uid)
			return -EINVAL;
		uid_list[(*index)++] = uid;
		begin = ++end; // next decimal characters (skip ' ' or '\n')
		end = strchr(begin, ' ');
	}

	// find last uid characters
	end = strchr(begin, '\n');
	if (!end) {
		pr_err("[dpa-uid-cfg] last character is not '\\n'");
		return -EINVAL;
	}

	// cur decimal characters cnt + ' ' or '\n'
	len += end - begin + 1;
	if (len > args_len || *index > index_max) {
		pr_err("[dpa-uid-cfg] str len(%u) or last index(%u) overflow\n",
			len, *index);
		return -EINVAL;
	}
	uid = parse_single_uid(begin, end);
	if (!uid)
		return -EINVAL;
	uid_list[(*index)++] = uid;
	return 0;
}

static int get_dpa_uids(char *buf, size_t size, u32 *uid_list,
			u32 index_max, u32 *index)
{
	char *args = NULL;
	u32 opt_len;
	u32 data_len;

	// split into cmd and argslist
	args = strchr(buf, ' ');
	if (!args) {
		pr_err("[dpa-uid-cfg] cmd fmt invalid\n");
		return -EINVAL;
	}

	// cmd is add or del, len is 3
	opt_len = args - buf;
	if (opt_len != OPT_LEN) {
		pr_err("[dpa-uid-cfg] cmd len invalid\n");
		return -EINVAL;
	}

	data_len = size - (opt_len + 1);
	return parse_uids(args + 1, data_len, uid_list, index_max, index);
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

void regist_dpa_init(ext_init fun)
{
	if (!fun)
		return;
	g_dpa_init_fun = fun;
}

static void dpa_ext_init(void)
{
	if (g_dpa_init_fun)
		g_dpa_init_fun();
}

// call this fun in net/ipv4/af_inet.c inet_init_net()
void __net_init lowpower_protocol_net_init(struct net *net)
{
	if (!proc_create_net_single_write("foreground_uid", 0644,
					  net->proc_net,
					  foreground_uid_show,
					  foreground_uid_write,
					  NULL))
		pr_err("fail to create /proc/net/foreground_uid");

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

static int __init lowpower_register(void)
{
	INIT_LIST_HEAD(&g_dpa_uid_list);
	return 0;
}

module_init(lowpower_register);
#endif /* CONFIG_LOWPOWER_PROTOCOL */
