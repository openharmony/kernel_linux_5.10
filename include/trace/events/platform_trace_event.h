/* SPDX-License-Identifier: GPL-2.0-or-later */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM platform_trace_event

#if !defined(_TRACE_PLATFORM_TRACE_EVENT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PLATFORM_TRACE_EVENT_H

#include <linux/tracepoint.h>

TRACE_EVENT(platfrom_trace_record_messages,
    TP_PROTO(
        const char *buf
    ),

    TP_ARGS(buf),

    TP_STRUCT__entry(
        __string(msg, buf)
    ),

    TP_fast_assign(
        __assign_str(msg, buf)
    ),

    TP_printk("platform trace info msg='%s'", __get_str(msg))
);
#endif /* _TRACE_PLATFORM_TRACE_EVENT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>