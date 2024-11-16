// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 *
 * Network and Application-driven Transport Augmentation (NATA).
 * Authors: yangyanjun
 */
#if defined(CONFIG_TCP_NATA_URC) || defined(CONFIG_TCP_NATA_STL)
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/nata.h>
#include <net/tcp.h>

#define NATA_THIN_STREAM 4
bool nata_thin_stream_check(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* The server side focuses on syn-ack retransmission,
	 * and the client side focuses on syn retransmission.
	 */
	if ((sk->sk_state == TCP_ESTABLISHED &&
	    tp->packets_out <= NATA_THIN_STREAM) ||
	    sk->sk_state == TCP_SYN_SENT)
		return true;
	return false;
}

#ifdef CONFIG_TCP_NATA_URC
int na_push_rto_ms __read_mostly = 200;
module_param(na_push_rto_ms, int, 0644);
MODULE_PARM_DESC(na_push_rto_ms, "config the max rto, default 200ms, < 150 means disable");
EXPORT_SYMBOL(na_push_rto_ms);

int na_push_data_retries __read_mostly = 10;
module_param(na_push_data_retries, int, 0644);
MODULE_PARM_DESC(na_push_data_retries, "config the data-pkt fast retransmit change times, default 10, 0 means disable, cannot greater than 50");
EXPORT_SYMBOL(na_push_data_retries);

int na_push_syn_retries __read_mostly = 16;
module_param(na_push_syn_retries, int, 0644);
MODULE_PARM_DESC(na_push_syn_retries, "config the syn-pkt max reties, default 16, 0 means disable, cannot greater than 50");
EXPORT_SYMBOL(na_push_syn_retries);

static int na_push_port_list[PUSH_PORT_CNT_MAX] __read_mostly = {0};
static int na_push_port_count = PUSH_PORT_CNT_MAX;
module_param_array(na_push_port_list, int, &na_push_port_count, 0644);
MODULE_PARM_DESC(na_push_port_list, "config listen port list, up to 10 elms");

bool na_push_port_check(__u16 port)
{
	int i;
	for (i = 0; i < na_push_port_count; i++) {
		if (na_push_port_list[i] && na_push_port_list[i] == port)
		return true;
	}

	return false;
}

void tcp_set_nata_push_urc(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (!na_push_port_check(ntohs(icsk->icsk_inet.inet_dport)))
		return ;

	if (na_push_rto_ms < NATA_URC_RTO_MS_MIN) {
		na_push_rto_ms = NATA_URC_RTO_MS_MIN;
	} else if (na_push_rto_ms > NATA_URC_RTO_MS_MAX) {
		na_push_rto_ms = NATA_URC_RTO_MS_MAX;
	}

	if (na_push_data_retries > NATA_DATA_RETRIES_MAX)
		na_push_data_retries = NATA_DATA_RETRIES_MAX;

	if (na_push_syn_retries > NATA_SYN_RETRIES_MAX)
		na_push_syn_retries = NATA_SYN_RETRIES_MAX;

	icsk->nata_retries_enabled = true;
	icsk->nata_retries_type = NATA_URC;
	icsk->icsk_syn_retries = na_push_syn_retries;
	icsk->nata_data_retries = na_push_data_retries;
	icsk->nata_data_rto = na_push_rto_ms * HZ / NATA_URC_RTO_MS_TO_HZ;
	icsk->nata_syn_rto = na_push_rto_ms;
}

int tcp_set_nata_urc(struct sock *sk, sockptr_t optval, int optlen)
{
	int err = -EINVAL;
	struct tcp_nata_urc opt = {};
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (optlen != sizeof(struct tcp_nata_urc))
		return err;

	if (copy_from_sockptr(&opt, optval, optlen))
		return err;

	if (!opt.nata_urc_enabled) {
		icsk->nata_retries_enabled = opt.nata_urc_enabled;
		icsk->nata_retries_type = NATA_NA;
		icsk->icsk_syn_retries = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_syn_retries);
		icsk->nata_data_retries = 0;
		icsk->nata_syn_rto = TCP_TIMEOUT_INIT;
		icsk->nata_data_rto = TCP_TIMEOUT_INIT;
		return 0;
	}

	if (opt.nata_rto_ms < NATA_URC_RTO_MS_MIN ||
		opt.nata_rto_ms > NATA_URC_RTO_MS_MAX )
		return err;

	if (opt.nata_data_retries > NATA_DATA_RETRIES_MAX ||
		opt.nata_syn_retries > NATA_SYN_RETRIES_MAX)
		return err;

	icsk->nata_retries_enabled = opt.nata_urc_enabled;
	icsk->nata_retries_type = NATA_URC;
	icsk->icsk_syn_retries = opt.nata_syn_retries;
	icsk->nata_data_retries = opt.nata_data_retries;
	icsk->nata_data_rto = opt.nata_rto_ms * HZ / NATA_URC_RTO_MS_TO_HZ;
	icsk->nata_syn_rto = icsk->nata_data_rto;
	return 0;
}
#endif /* CONFIG_TCP_NATA_URC */

#ifdef CONFIG_TCP_NATA_STL
int tcp_set_nata_stl(struct sock *sk, sockptr_t optval, int optlen)
{
	int err = -EINVAL;
	struct tcp_nata_stl opt = {};
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (optlen != sizeof(struct tcp_nata_stl))
		return err;

	if (copy_from_sockptr(&opt, optval, optlen))
		return err;

	if (!opt.nata_stl_enabled) {
		icsk->nata_retries_enabled = opt.nata_stl_enabled;
		icsk->nata_retries_type = NATA_NA;
		icsk->icsk_syn_retries = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_syn_retries);
		icsk->nata_data_retries = 0;
		icsk->nata_syn_rto = TCP_TIMEOUT_INIT;
		icsk->nata_data_rto = TCP_TIMEOUT_INIT;
		return 0;
	}

	if ((opt.nata_syn_rto_ms < NATA_STL_SYN_RTO_MS_MIN ||
		opt.nata_syn_rto_ms > NATA_STL_RTO_MS_MAX ||
		opt.nata_data_rto_ms < NATA_STL_DATA_RTO_MS_MIN ||
		opt.nata_data_rto_ms > NATA_STL_RTO_MS_MAX))
		return err;

	if (opt.nata_data_retries > NATA_DATA_RETRIES_MAX ||
		opt.nata_syn_retries > NATA_SYN_RETRIES_MAX)
		return err;

	icsk->nata_retries_enabled = opt.nata_stl_enabled;
	icsk->nata_retries_type = NATA_STL;
	icsk->icsk_syn_retries = opt.nata_syn_retries;
	icsk->nata_data_retries = opt.nata_data_retries;
	icsk->nata_syn_rto = opt.nata_syn_rto_ms * HZ / NATA_STL_RTO_MS_TO_HZ;
	icsk->nata_data_rto = opt.nata_data_rto_ms * HZ / NATA_STL_RTO_MS_TO_HZ;
	return 0;
}
#endif /* CONFIG_TCP_NATA_STL */
#endif