/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/arch/loongarch/include/asm/perf_event.h
 *
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __LOONGARCH_PERF_EVENT_H__
#define __LOONGARCH_PERF_EVENT_H__

#define perf_arch_bpf_user_pt_regs(regs) (struct user_pt_regs *)regs

#endif /* __LOONGARCH_PERF_EVENT_H__ */
