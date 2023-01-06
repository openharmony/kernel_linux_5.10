// SPDX-License-Identifier: GPL-2.0-only
/* vendor_hooks.c
 *
 * Vendor Hook Support
 *
 * Copyright (C) 2020 Google, Inc.
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 */

#define CREATE_TRACE_POINTS
#include <trace/hooks/vendor_hooks.h>
#include <trace/hooks/mm.h>
#include <trace/hooks/inet.h>

/*
 * Export tracepoints that act as a bare tracehook(ie: have no trace event
 * associated with them) to allow external modules to probe them.
 *
 * For example:
 *   EXPORT_TRACEPOINT_SYMBOL_GPL(vendor_foo);
 */

EXPORT_TRACEPOINT_SYMBOL_GPL(vendor_do_mmap);
EXPORT_TRACEPOINT_SYMBOL_GPL(vendor_do_mprotect_pkey);
EXPORT_TRACEPOINT_SYMBOL_GPL(vendor_ninet_ehashfn);
EXPORT_TRACEPOINT_SYMBOL_GPL(vendor_ninet_gifconf);
