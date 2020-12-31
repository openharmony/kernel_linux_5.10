/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 */
#ifndef _ASM_LBT_H
#define _ASM_LBT_H

#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/loongarchregs.h>

#ifdef CONFIG_CPU_HAS_LBT

#define STR(x)  __STR(x)
#define __STR(x)  #x

extern void _init_lbt(void);

static inline void save_lbt_registers(struct loongarch_lbt *prev)
{
	unsigned long tmp = 0;

	__asm__ __volatile__ (
	"movscr2gr  %[tmp], $scr0					\n"
	"stptr.d %[tmp], %[prev], " STR(THREAD_SCR0) "		\n"
	"movscr2gr  %[tmp], $scr1					\n"
	"stptr.d %[tmp], %[prev], " STR(THREAD_SCR1) "		\n"
	"movscr2gr  %[tmp], $scr2					\n"
	"stptr.d %[tmp], %[prev], " STR(THREAD_SCR2) "		\n"
	"movscr2gr  %[tmp], $scr3					\n"
	"stptr.d %[tmp], %[prev], " STR(THREAD_SCR3) "		\n"
	"x86mfflag %[tmp], 0x3f					\n"
	"stptr.d %[tmp], %[prev], " STR(THREAD_EFLAGS) "	\n"
	:
	: [prev] "r" (prev), [tmp] "r" (tmp)
	: "memory"
	);
}

static inline void restore_lbt_registers(struct loongarch_lbt *next)
{
	unsigned long tmp = 0;

	__asm__ __volatile__ (
	"ldptr.d %[tmp], %[next], " STR(THREAD_SCR0) "		\n"
	"movgr2scr  $scr0, %[tmp]					\n"
	"ldptr.d %[tmp], %[next], " STR(THREAD_SCR1) "		\n"
	"movgr2scr  $scr1, %[tmp]					\n"
	"ldptr.d %[tmp], %[next], " STR(THREAD_SCR2) "		\n"
	"movgr2scr  $scr2, %[tmp]					\n"
	"ldptr.d %[tmp], %[next], " STR(THREAD_SCR3) "		\n"
	"movgr2scr  $scr3, %[tmp]					\n"
	"ldptr.d %[tmp], %[next], " STR(THREAD_EFLAGS) "	\n"
	"x86mtflag %[tmp], 0x3f					\n"
	:
	: [next] "r" (next), [tmp] "r" (tmp)
	:
	);
}

static inline void enable_lbt(void)
{
	if (cpu_has_lbt)
		csr_xchg32(CSR_EUEN_LBTEN, CSR_EUEN_LBTEN, LOONGARCH_CSR_EUEN);
}

static inline void disable_lbt(void)
{
	if (cpu_has_lbt)
		csr_xchg32(0, CSR_EUEN_LBTEN, LOONGARCH_CSR_EUEN);
}

static inline int is_lbt_enabled(void)
{
	if (!cpu_has_lbt)
		return 0;

	return (csr_read32(LOONGARCH_CSR_EUEN) & CSR_EUEN_LBTEN) ?
		1 : 0;
}

static inline int is_lbt_owner(void)
{
	return test_thread_flag(TIF_USEDLBT);
}

static inline void __own_lbt(void)
{
	enable_lbt();
	set_thread_flag(TIF_USEDLBT);
	KSTK_EUEN(current) |= CSR_EUEN_LBTEN;
}

static inline void init_lbt(void)
{
	__own_lbt();
	_init_lbt();
}

static inline void own_lbt_inatomic(int restore)
{
	if (cpu_has_lbt && !is_lbt_owner()) {
		__own_lbt();
		if (restore)
			restore_lbt_registers(&current->thread.lbt);
	}
}

static inline void lose_lbt_inatomic(int save, struct task_struct *tsk)
{
	if (is_lbt_owner()) {
		if (save)
			save_lbt_registers(&tsk->thread.lbt);

		disable_lbt();
		clear_tsk_thread_flag(tsk, TIF_USEDLBT);
	}
	KSTK_EUEN(tsk) &= ~(CSR_EUEN_LBTEN);
}

static inline void lose_lbt(int save)
{
	preempt_disable();
	lose_lbt_inatomic(save, current);
	preempt_enable();
}

#else
static inline void own_lbt_inatomic(int restore) {}
static inline void lose_lbt_inatomic(int save, struct task_struct *tsk) {}
static inline void init_lbt(void) {}
static inline void lose_lbt(int save) {}
#endif

static inline int thread_lbt_context_live(void)
{
	if (__builtin_constant_p(cpu_has_lbt) && !cpu_has_lbt)
		return 0;

	return test_thread_flag(TIF_LBT_CTX_LIVE);
}

#endif
