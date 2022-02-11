/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2016, 2019-2020, The Linux Foundation. All rights reserved.
 */

#ifndef __CORE_CTL_H
#define __CORE_CTL_H

#ifdef CONFIG_SCHED_CORE_CTRL
extern void core_ctl_check(u64 wallclock);
#else
static inline void core_ctl_check(u64 wallclock) { }
#endif
#endif
