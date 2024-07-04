// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 *
 * Network and Application-driven Transport Augmentation (NATA).
 * Authors: yangyanjun
 */
#ifndef _INET_NATA_H
#define _INET_NATA_H
#if defined(CONFIG_TCP_NATA_URC) || defined(CONFIG_TCP_NATA_STL)
#include <net/inet_sock.h>
#include <net/sock.h>

#define NATA_DATA_RETRIES_MAX	50
#define NATA_SYN_RETRIES_MAX	50
#define BITS_PRE_BYTE		8
#define NATA_RTO_MAX_SHIFT	17
#define NATA_RTO_MAX		((unsigned)(120*HZ))
#define MAX_SHIFT (sizeof(unsigned long) * BITS_PER_BYTE - NATA_RTO_MAX_SHIFT)

enum nata_retries_type_t {
	NATA_NA = 0,
	NATA_URC = 1,
	NATA_STL = 2,
};

#ifdef CONFIG_TCP_NATA_URC
#define NATA_URC_RTO_MS_MIN   200      // 200ms
#define NATA_URC_RTO_MS_MAX   120000   // 120s
#define NATA_URC_RTO_MS_TO_HZ 1000
int tcp_set_nata_urc(struct sock *sk, sockptr_t optval, int optlen);
#endif /* CONFIG_TCP_NATA_URC */

#ifdef CONFIG_TCP_NATA_STL
#define NATA_STL_SYN_RTO_MS_MIN  800    // 800ms
#define NATA_STL_DATA_RTO_MS_MIN 1800   // 1800ms
#define NATA_STL_RTO_MS_MAX      120000 // 120s
#define NATA_STL_RTO_MS_TO_HZ    1000
int tcp_set_nata_stl(struct sock *sk, sockptr_t optval, int optlen);
#endif /* CONFIG_TCP_NATA_STL */

#endif
#endif /* _INET_NATA_H */
