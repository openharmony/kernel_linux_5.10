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