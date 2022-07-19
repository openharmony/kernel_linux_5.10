/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM mm

#define TRACE_INCLUDE_PATH trace/hooks
#if !defined(_TRACE_HOOKS_MM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOKS_MM_H

#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>

DECLARE_HOOK(vendor_do_mmap,
	TP_PROTO(vm_flags_t *vm_flags, int *err),
	TP_ARGS(vm_flags, err)
);

DECLARE_HOOK(vendor_do_mprotect_pkey,
	TP_PROTO(unsigned long prot, int *err),
	TP_ARGS(prot, err)
);

#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
