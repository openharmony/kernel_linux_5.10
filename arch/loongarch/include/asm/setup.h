/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */

#ifndef _LOONGARCH_SETUP_H
#define _LOONGARCH_SETUP_H

#include <linux/types.h>
#include <uapi/asm/setup.h>

#define VECSIZE 0x200

extern unsigned long eentry;
extern unsigned long tlbrentry;
extern void tlb_init(int cpu);
extern void cpu_cache_init(void);
extern void cache_error_setup(void);
extern void per_cpu_trap_init(int cpu);
extern void set_handler(unsigned long offset, void *addr, unsigned long len);
extern void set_merr_handler(unsigned long offset, void *addr, unsigned long len);

#ifdef CONFIG_USE_OF

struct boot_param_header;

extern void device_tree_init(void);

#else /* CONFIG_OF */
static inline void device_tree_init(void) { }
#endif /* CONFIG_OF */

#endif /* __SETUP_H */
