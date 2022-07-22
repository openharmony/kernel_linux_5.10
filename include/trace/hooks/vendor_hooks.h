/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/tracepoint.h>

#if defined(CONFIG_TRACEPOINTS) && defined(CONFIG_VENDOR_HOOKS)

#define DECLARE_HOOK DECLARE_TRACE

#else /* !CONFIG_TRACEPOINTS || !CONFIG_VENDOR_HOOKS */

#define DECLARE_HOOK DECLARE_EVENT_NOP

#endif
