// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Facebook
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/sched/signal.h>
#include <net/bpf_sk_storage.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/error-injection.h>
#include <linux/smp.h>

#define CREATE_TRACE_POINTS
#include <trace/events/bpf_test_run.h>

static int bpf_test_run(struct bpf_prog *prog, void *ctx, u32 repeat,
			u32 *retval, u32 *time, bool xdp)
{
	struct bpf_prog_array_item item = {.prog = prog};
	struct bpf_run_ctx *old_ctx;
	struct bpf_cg_run_ctx run_ctx;
	enum bpf_cgroup_storage_type stype;
	u64 time_start, time_spent = 0;
	int ret = 0;
	u32 i;

	for_each_cgroup_storage_type(stype) {
		item.cgroup_storage[stype] = bpf_cgroup_storage_alloc(prog, stype);
		if (IS_ERR(item.cgroup_storage[stype])) {
			item.cgroup_storage[stype] = NULL;
			for_each_cgroup_storage_type(stype)
				bpf_cgroup_storage_free(item.cgroup_storage[stype]);
			return -ENOMEM;
		}
	}

	if (!repeat)
		repeat = 1;

	rcu_read_lock();
	migrate_disable();
	time_start = ktime_get_ns();
	old_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
	for (i = 0; i < repeat; i++) {
		run_ctx.prog_item = &item;

		if (xdp)
			*retval = bpf_prog_run_xdp(prog, ctx);
		else
			*retval = BPF_PROG_RUN(prog, ctx);

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (need_resched()) {
			time_spent += ktime_get_ns() - time_start;
			migrate_enable();
			rcu_read_unlock();

			cond_resched();

			rcu_read_lock();
			migrate_disable();
			time_start = ktime_get_ns();
		}
	}
	bpf_reset_run_ctx(old_ctx);
	time_spent += ktime_get_ns() - time_start;
	migrate_enable();
	rcu_read_unlock();

	do_div(time_spent, repeat);
	*time = time_spent > U32_MAX ? U32_MAX : (u32)time_spent;

	for_each_cgroup_storage_type(stype)
		bpf_cgroup_storage_free(item.cgroup_storage[stype]);

	return ret;
}

static int bpf_test_finish(const union bpf_attr *kattr,
			   union bpf_attr __user *uattr, const void *data,
			   u32 size, u32 retval, u32 duration)
{
	void __user *data_out = u64_to_user_ptr(kattr->test.data_out);
	int err = -EFAULT;
	u32 copy_size = size;

	/* Clamp copy if the user has provided a size hint, but copy the full
	 * buffer if not to retain old behaviour.
	 */
	if (kattr->test.data_size_out &&
	    copy_size > kattr->test.data_size_out) {
		copy_size = kattr->test.data_size_out;
		err = -ENOSPC;
	}

	if (data_out && copy_to_user(data_out, data, copy_size))
		goto out;
	if (copy_to_user(&uattr->test.data_size_out, &size, sizeof(size)))
		goto out;
	if (copy_to_user(&uattr->test.retval, &retval, sizeof(retval)))
		goto out;
	if (copy_to_user(&uattr->test.duration, &duration, sizeof(duration)))
		goto out;
	if (err != -ENOSPC)
		err = 0;
out:
	trace_bpf_test_finish(&err);
	return err;
}

/* Integer types of various sizes and pointer combinations cover variety of
 * architecture dependent calling conventions. 7+ can be supported in the
 * future.
 */
__diag_push();
__diag_ignore(GCC, 8, "-Wmissing-prototypes",
	      "Global functions as their definitions will be in vmlinux BTF");
int noinline bpf_fentry_test1(int a)
{
	return a + 1;
}

int noinline bpf_fentry_test2(int a, u64 b)
{
	return a + b;
}

int noinline bpf_fentry_test3(char a, int b, u64 c)
{
	return a + b + c;
}

int noinline bpf_fentry_test4(void *a, char b, int c, u64 d)
{
	return (long)a + b + c + d;
}

int noinline bpf_fentry_test5(u64 a, void *b, short c, int d, u64 e)
{
	return a + (long)b + c + d + e;
}

int noinline bpf_fentry_test6(u64 a, void *b, short c, int d, void *e, u64 f)
{
	return a + (long)b + c + d + (long)e + f;
}

struct bpf_fentry_test_t {
	struct bpf_fentry_test_t *a;
};

int noinline bpf_fentry_test7(struct bpf_fentry_test_t *arg)
{
	return (long)arg;
}

int noinline bpf_fentry_test8(struct bpf_fentry_test_t *arg)
{
	return (long)arg->a;
}

int noinline bpf_modify_return_test(int a, int *b)
{
	*b += 1;
	return a + *b;
}
__diag_pop();

ALLOW_ERROR_INJECTION(bpf_modify_return_test, ERRNO);

static void *bpf_test_init(const union bpf_attr *kattr, u32 size,
			   u32 headroom, u32 tailroom)
{
	void __user *data_in = u64_to_user_ptr(kattr->test.data_in);
	u32 user_size = kattr->test.data_size_in;
	void *data;

	if (size < ETH_HLEN || size > PAGE_SIZE - headroom - tailroom)
		return ERR_PTR(-EINVAL);

	if (user_size > size)
		return ERR_PTR(-EMSGSIZE);

	size = SKB_DATA_ALIGN(size);
	data = kzalloc(size + headroom + tailroom, GFP_USER);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(data + headroom, data_in, user_size)) {
		kfree(data);
		return ERR_PTR(-EFAULT);
	}

	return data;
}

int bpf_prog_test_run_tracing(struct bpf_prog *prog,
			      const union bpf_attr *kattr,
			      union bpf_attr __user *uattr)
{
	struct bpf_fentry_test_t arg = {};
	u16 side_effect = 0, ret = 0;
	int b = 2, err = -EFAULT;
	u32 retval = 0;

	if (kattr->test.flags || kattr->test.cpu)
		return -EINVAL;

	switch (prog->expected_attach_type) {
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
		if (bpf_fentry_test1(1) != 2 ||
		    bpf_fentry_test2(2, 3) != 5 ||
		    bpf_fentry_test3(4, 5, 6) != 15 ||
		    bpf_fentry_test4((void *)7, 8, 9, 10) != 34 ||
		    bpf_fentry_test5(11, (void *)12, 13, 14, 15) != 65 ||
		    bpf_fentry_test6(16, (void *)17, 18, 19, (void *)20, 21) != 111 ||
		    bpf_fentry_test7((struct bpf_fentry_test_t *)0) != 0 ||
		    bpf_fentry_test8(&arg) != 0)
			goto out;
		break;
	case BPF_MODIFY_RETURN:
		ret = bpf_modify_return_test(1, &b);
		if (b != 2)
			side_effect = 1;
		break;
	default:
		goto out;
	}

	retval = ((u32)side_effect << 16) | ret;
	if (copy_to_user(&uattr->test.retval, &retval, sizeof(retval)))
		goto out;

	err = 0;
out:
	trace_bpf_test_finish(&err);
	return err;
}

struct bpf_raw_tp_test_run_info {
	struct bpf_prog *prog;
	void *ctx;
	u32 retval;
};

static void
__bpf_prog_test_run_raw_tp(void *data)
{
	struct bpf_raw_tp_test_run_info *info = data;

	rcu_read_lock();
	info->retval = BPF_PROG_RUN(info->prog, info->ctx);
	rcu_read_unlock();
}

int bpf_prog_test_run_raw_tp(struct bpf_prog *prog,
			     const union bpf_attr *kattr,
			     union bpf_attr __user *uattr)
{
	void __user *ctx_in = u64_to_user_ptr(kattr->test.ctx_in);
	__u32 ctx_size_in = kattr->test.ctx_size_in;
	struct bpf_raw_tp_test_run_info info;
	int cpu = kattr->test.cpu, err = 0;
	int current_cpu;

	/* doesn't support data_in/out, ctx_out, duration, or repeat */
	if (kattr->test.data_in || kattr->test.data_out ||
	    kattr->test.ctx_out || kattr->test.duration ||
	    kattr->test.repeat)
		return -EINVAL;

	if (ctx_size_in < prog->aux->max_ctx_offset ||
	    ctx_size_in > MAX_BPF_FUNC_ARGS * sizeof(u64))
		return -EINVAL;

	if ((kattr->test.flags & BPF_F_TEST_RUN_ON_CPU) == 0 && cpu != 0)
		return -EINVAL;

	if (ctx_size_in) {
		info.ctx = kzalloc(ctx_size_in, GFP_USER);
		if (!info.ctx)
			return -ENOMEM;
		if (copy_from_user(info.ctx, ctx_in, ctx_size_in)) {
			err = -EFAULT;
			goto out;
		}
	} else {
		info.ctx = NULL;
	}

	info.prog = prog;

	current_cpu = get_cpu();
	if ((kattr->test.flags & BPF_F_TEST_RUN_ON_CPU) == 0 ||
	    cpu == current_cpu) {
		__bpf_prog_test_run_raw_tp(&info);
	} else if (cpu >= nr_cpu_ids || !cpu_online(cpu)) {
		/* smp_call_function_single() also checks cpu_online()
		 * after csd_lock(). However, since cpu is from user
		 * space, let's do an extra quick check to filter out
		 * invalid value before smp_call_function_single().
		 */
		err = -ENXIO;
	} else {
		err = smp_call_function_single(cpu, __bpf_prog_test_run_raw_tp,
					       &info, 1);
	}
	put_cpu();

	if (!err &&
	    copy_to_user(&uattr->test.retval, &info.retval, sizeof(u32)))
		err = -EFAULT;

out:
	kfree(info.ctx);
	return err;
}

static void *bpf_ctx_init(const union bpf_attr *kattr, u32 max_size)
{
	void __user *data_in = u64_to_user_ptr(kattr->test.ctx_in);
	void __user *data_out = u64_to_user_ptr(kattr->test.ctx_out);
	u32 size = kattr->test.ctx_size_in;
	void *data;
	int err;

	if (!data_in && !data_out)
		return NULL;

	data = kzalloc(max_size, GFP_USER);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (data_in) {
		err = bpf_check_uarg_tail_zero(data_in, max_size, size);
		if (err) {
			kfree(data);
			return ERR_PTR(err);
		}

		size = min_t(u32, max_size, size);
		if (copy_from_user(data, data_in, size)) {
			kfree(data);
			return ERR_PTR(-EFAULT);
		}
	}
	return data;
}

static int bpf_ctx_finish(const union bpf_attr *kattr,
			  union bpf_attr __user *uattr, const void *data,
			  u32 size)
{
	void __user *data_out = u64_to_user_ptr(kattr->test.ctx_out);
	int err = -EFAULT;
	u32 copy_size = size;

	if (!data || !data_out)
		return 0;

	if (copy_size > kattr->test.ctx_size_out) {
		copy_size = kattr->test.ctx_size_out;
		err = -ENOSPC;
	}

	if (copy_to_user(data_out, data, copy_size))
		goto out;
	if (copy_to_user(&uattr->test.ctx_size_out, &size, sizeof(size)))
		goto out;
	if (err != -ENOSPC)
		err = 0;
out:
	return err;
}

/**
 * range_is_zero - test whether buffer is initialized
 * @buf: buffer to check
 * @from: check from this position
 * @to: check up until (excluding) this position
 *
 * This function returns true if the there is a non-zero byte
 * in the buf in the range [from,to).
 */
static inline bool range_is_zero(void *buf, size_t from, size_t to)
{
	return !memchr_inv((u8 *)buf + from, 0, to - from);
}

static int convert___skb_to_skb(struct sk_buff *skb, struct __sk_buff *__skb)
{
	struct qdisc_skb_cb *cb = (struct qdisc_skb_cb *)skb->cb;

	if (!__skb)
		return 0;

	/* make sure the fields we don't use are zeroed */
	if (!range_is_zero(__skb, 0, offsetof(struct __sk_buff, mark)))
		return -EINVAL;

	/* mark is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, mark),
			   offsetof(struct __sk_buff, priority)))
		return -EINVAL;

	/* priority is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, priority),
			   offsetof(struct __sk_buff, ifindex)))
		return -EINVAL;

	/* ifindex is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, ifindex),
			   offsetof(struct __sk_buff, cb)))
		return -EINVAL;

	/* cb is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, cb),
			   offsetof(struct __sk_buff, tstamp)))
		return -EINVAL;

	/* tstamp is allowed */
	/* wire_len is allowed */
	/* gso_segs is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, gso_segs),
			   offsetof(struct __sk_buff, gso_size)))
		return -EINVAL;

	/* gso_size is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, gso_size),
			   sizeof(struct __sk_buff)))
		return -EINVAL;

	skb->mark = __skb->mark;
	skb->priority = __skb->priority;
	skb->tstamp = __skb->tstamp;
	memcpy(&cb->data, __skb->cb, QDISC_CB_PRIV_LEN);

	if (__skb->wire_len == 0) {
		cb->pkt_len = skb->len;
	} else {
		if (__skb->wire_len < skb->len ||
		    __skb->wire_len > GSO_MAX_SIZE)
			return -EINVAL;
		cb->pkt_len = __skb->wire_len;
	}

	if (__skb->gso_segs > GSO_MAX_SEGS)
		return -EINVAL;
	skb_shinfo(skb)->gso_segs = __skb->gso_segs;
	skb_shinfo(skb)->gso_size = __skb->gso_size;

	return 0;
}

static void convert_skb_to___skb(struct sk_buff *skb, struct __sk_buff *__skb)
{
	struct qdisc_skb_cb *cb = (struct qdisc_skb_cb *)skb->cb;

	if (!__skb)
		return;

	__skb->mark = skb->mark;
	__skb->priority = skb->priority;
	__skb->ifindex = skb->dev->ifindex;
	__skb->tstamp = skb->tstamp;
	memcpy(__skb->cb, &cb->data, QDISC_CB_PRIV_LEN);
	__skb->wire_len = cb->pkt_len;
	__skb->gso_segs = skb_shinfo(skb)->gso_segs;
}

static struct proto bpf_dummy_proto = {
	.name   = "bpf_dummy",
	.owner  = THIS_MODULE,
	.obj_size = sizeof(struct sock),
};

int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr)
{
	bool is_l2 = false, is_direct_pkt_access = false;
	struct net *net = current->nsproxy->net_ns;
	struct net_device *dev = net->loopback_dev;
	u32 size = kattr->test.data_size_in;
	u32 repeat = kattr->test.repeat;
	struct __sk_buff *ctx = NULL;
	u32 retval, duration;
	int hh_len = ETH_HLEN;
	struct sk_buff *skb;
	struct sock *sk;
	void *data;
	int ret;

	if (kattr->test.flags || kattr->test.cpu)
		return -EINVAL;

	data = bpf_test_init(kattr, size, NET_SKB_PAD + NET_IP_ALIGN,
			     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	if (IS_ERR(data))
		return PTR_ERR(data);

	ctx = bpf_ctx_init(kattr, sizeof(struct __sk_buff));
	if (IS_ERR(ctx)) {
		kfree(data);
		return PTR_ERR(ctx);
	}

	switch (prog->type) {
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		is_l2 = true;
		fallthrough;
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
		is_direct_pkt_access = true;
		break;
	default:
		break;
	}

	sk = sk_alloc(net, AF_UNSPEC, GFP_USER, &bpf_dummy_proto, 1);
	if (!sk) {
		kfree(data);
		kfree(ctx);
		return -ENOMEM;
	}
	sock_init_data(NULL, sk);

	skb = build_skb(data, 0);
	if (!skb) {
		kfree(data);
		kfree(ctx);
		sk_free(sk);
		return -ENOMEM;
	}
	skb->sk = sk;

	skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
	__skb_put(skb, size);
	if (ctx && ctx->ifindex > 1) {
		dev = dev_get_by_index(net, ctx->ifindex);
		if (!dev) {
			ret = -ENODEV;
			goto out;
		}
	}
	skb->protocol = eth_type_trans(skb, dev);
	skb_reset_network_header(skb);

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		sk->sk_family = AF_INET;
		if (sizeof(struct iphdr) <= skb_headlen(skb)) {
			sk->sk_rcv_saddr = ip_hdr(skb)->saddr;
			sk->sk_daddr = ip_hdr(skb)->daddr;
		}
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		sk->sk_family = AF_INET6;
		if (sizeof(struct ipv6hdr) <= skb_headlen(skb)) {
			sk->sk_v6_rcv_saddr = ipv6_hdr(skb)->saddr;
			sk->sk_v6_daddr = ipv6_hdr(skb)->daddr;
		}
		break;
#endif
	default:
		break;
	}

	if (is_l2)
		__skb_push(skb, hh_len);
	if (is_direct_pkt_access)
		bpf_compute_data_pointers(skb);
	ret = convert___skb_to_skb(skb, ctx);
	if (ret)
		goto out;
	ret = bpf_test_run(prog, skb, repeat, &retval, &duration, false);
	if (ret)
		goto out;
	if (!is_l2) {
		if (skb_headroom(skb) < hh_len) {
			int nhead = HH_DATA_ALIGN(hh_len - skb_headroom(skb));

			if (pskb_expand_head(skb, nhead, 0, GFP_USER)) {
				ret = -ENOMEM;
				goto out;
			}
		}
		memset(__skb_push(skb, hh_len), 0, hh_len);
	}
	convert_skb_to___skb(skb, ctx);

	size = skb->len;
	/* bpf program can never convert linear skb to non-linear */
	if (WARN_ON_ONCE(skb_is_nonlinear(skb)))
		size = skb_headlen(skb);
	ret = bpf_test_finish(kattr, uattr, skb->data, size, retval, duration);
	if (!ret)
		ret = bpf_ctx_finish(kattr, uattr, ctx,
				     sizeof(struct __sk_buff));
out:
	if (dev && dev != net->loopback_dev)
		dev_put(dev);
	kfree_skb(skb);
	sk_free(sk);
	kfree(ctx);
	return ret;
}

int bpf_prog_test_run_xdp(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr)
{
	u32 tailroom = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	u32 headroom = XDP_PACKET_HEADROOM;
	u32 size = kattr->test.data_size_in;
	u32 repeat = kattr->test.repeat;
	struct netdev_rx_queue *rxqueue;
	struct xdp_buff xdp = {};
	u32 retval, duration;
	u32 max_data_sz;
	void *data;
	int ret;

	if (prog->expected_attach_type == BPF_XDP_DEVMAP ||
	    prog->expected_attach_type == BPF_XDP_CPUMAP)
		return -EINVAL;
	if (kattr->test.ctx_in || kattr->test.ctx_out)
		return -EINVAL;

	/* XDP have extra tailroom as (most) drivers use full page */
	max_data_sz = 4096 - headroom - tailroom;

	data = bpf_test_init(kattr, max_data_sz, headroom, tailroom);
	if (IS_ERR(data))
		return PTR_ERR(data);

	xdp.data_hard_start = data;
	xdp.data = data + headroom;
	xdp.data_meta = xdp.data;
	xdp.data_end = xdp.data + size;
	xdp.frame_sz = headroom + max_data_sz + tailroom;

	rxqueue = __netif_get_rx_queue(current->nsproxy->net_ns->loopback_dev, 0);
	xdp.rxq = &rxqueue->xdp_rxq;
	bpf_prog_change_xdp(NULL, prog);
	ret = bpf_test_run(prog, &xdp, repeat, &retval, &duration, true);
	if (ret)
		goto out;
	if (xdp.data != data + headroom || xdp.data_end != xdp.data + size)
		size = xdp.data_end - xdp.data;
	ret = bpf_test_finish(kattr, uattr, xdp.data, size, retval, duration);
out:
	bpf_prog_change_xdp(prog, NULL);
	kfree(data);
	return ret;
}

static int verify_user_bpf_flow_keys(struct bpf_flow_keys *ctx)
{
	/* make sure the fields we don't use are zeroed */
	if (!range_is_zero(ctx, 0, offsetof(struct bpf_flow_keys, flags)))
		return -EINVAL;

	/* flags is allowed */

	if (!range_is_zero(ctx, offsetofend(struct bpf_flow_keys, flags),
			   sizeof(struct bpf_flow_keys)))
		return -EINVAL;

	return 0;
}

int bpf_prog_test_run_flow_dissector(struct bpf_prog *prog,
				     const union bpf_attr *kattr,
				     union bpf_attr __user *uattr)
{
	u32 size = kattr->test.data_size_in;
	struct bpf_flow_dissector ctx = {};
	u32 repeat = kattr->test.repeat;
	struct bpf_flow_keys *user_ctx;
	struct bpf_flow_keys flow_keys;
	u64 time_start, time_spent = 0;
	const struct ethhdr *eth;
	unsigned int flags = 0;
	u32 retval, duration;
	void *data;
	int ret;
	u32 i;

	if (prog->type != BPF_PROG_TYPE_FLOW_DISSECTOR)
		return -EINVAL;

	if (kattr->test.flags || kattr->test.cpu)
		return -EINVAL;

	if (size < ETH_HLEN)
		return -EINVAL;

	data = bpf_test_init(kattr, size, 0, 0);
	if (IS_ERR(data))
		return PTR_ERR(data);

	eth = (struct ethhdr *)data;

	if (!repeat)
		repeat = 1;

	user_ctx = bpf_ctx_init(kattr, sizeof(struct bpf_flow_keys));
	if (IS_ERR(user_ctx)) {
		kfree(data);
		return PTR_ERR(user_ctx);
	}
	if (user_ctx) {
		ret = verify_user_bpf_flow_keys(user_ctx);
		if (ret)
			goto out;
		flags = user_ctx->flags;
	}

	ctx.flow_keys = &flow_keys;
	ctx.data = data;
	ctx.data_end = (__u8 *)data + size;

	rcu_read_lock();
	preempt_disable();
	time_start = ktime_get_ns();
	for (i = 0; i < repeat; i++) {
		retval = bpf_flow_dissect(prog, &ctx, eth->h_proto, ETH_HLEN,
					  size, flags);

		if (signal_pending(current)) {
			preempt_enable();
			rcu_read_unlock();

			ret = -EINTR;
			goto out;
		}

		if (need_resched()) {
			time_spent += ktime_get_ns() - time_start;
			preempt_enable();
			rcu_read_unlock();

			cond_resched();

			rcu_read_lock();
			preempt_disable();
			time_start = ktime_get_ns();
		}
	}
	time_spent += ktime_get_ns() - time_start;
	preempt_enable();
	rcu_read_unlock();

	do_div(time_spent, repeat);
	duration = time_spent > U32_MAX ? U32_MAX : (u32)time_spent;

	ret = bpf_test_finish(kattr, uattr, &flow_keys, sizeof(flow_keys),
			      retval, duration);
	if (!ret)
		ret = bpf_ctx_finish(kattr, uattr, user_ctx,
				     sizeof(struct bpf_flow_keys));

out:
	kfree(user_ctx);
	kfree(data);
	return ret;
}
