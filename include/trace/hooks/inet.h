/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Huawei Device Co., Ltd. */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM       inet

#define TRACE_INCLUDE_PATH trace/hooks
#if !defined(_TRACE_HOOK_INET_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_INET_H

#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>

DECLARE_HOOK(vendor_ninet_ehashfn,
		TP_PROTO(const struct sock *sk, u32 *ret),
		TP_ARGS(sk, ret)
);

DECLARE_HOOK(vendor_ninet_gifconf,
		TP_PROTO(struct net_device *dev, char __user *buf, int len, int size, int *ret),
		TP_ARGS(dev, buf, len, size, ret)
);

#endif

/* This part must be outside protection */
#include <trace/define_trace.h>

