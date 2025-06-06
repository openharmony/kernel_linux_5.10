/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Author: Jinyang He <hejinyang@loongson.cn>
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020-2021 Loongson Technology Corporation Limited
 */

#include <asm/export.h>
#include <asm/regdef.h>
#include <asm/stackframe.h>
#include <asm/ftrace.h>
#include <asm/unwind_hints.h>

	.text
/*
 * Due to -fpatchable-function-entry=2: the compiler inserted 2 NOPs before the
 * regular C function prologue. When PC arrived here, the last 2 instructions
 * as follows,
 * 	move		t0, ra
 * 	bl		callsite (for modules, callsite is a tramplione)
 *
 * modules tramplione as follows,
 * 	addu16i.d	t1, zero, callsite[31:16]
 * 	lu32i.d		t1, callsite[51:32]
 * 	lu52i.d		t1, t1, callsite[63:52]
 * 	jirl		zero, t1, callsite[15:0] >> 2
 *
 * See arch/loongarch/kernel/ftrace_dyn.c for details. Here, pay attention to
 * that the T series regs are available and safe because each C functions
 * follows the LoongArch psABI well.
 */

	.macro  ftrace_regs_entry allregs=0
	PTR_ADDI sp, sp, -PT_SIZE
	/* Save trace function ra at PT_ERA */
	PTR_S	ra, sp, PT_ERA
	/* Save parent ra at PT_R1(RA) */
	PTR_S	t0, sp, PT_R1
	PTR_S	a0, sp, PT_R4
	PTR_S	a1, sp, PT_R5
	PTR_S	a2, sp, PT_R6
	PTR_S	a3, sp, PT_R7
	PTR_S	a4, sp, PT_R8
	PTR_S	a5, sp, PT_R9
	PTR_S	a6, sp, PT_R10
	PTR_S	a7, sp, PT_R11
	PTR_S	fp, sp, PT_R22

	.if \allregs
	PTR_S	t0, sp, PT_R12
	PTR_S	t1, sp, PT_R13
	PTR_S	t2, sp, PT_R14
	PTR_S	t3, sp, PT_R15
	PTR_S	t4, sp, PT_R16
	PTR_S	t5, sp, PT_R17
	PTR_S	t6, sp, PT_R18
	PTR_S	t7, sp, PT_R19
	PTR_S	t8, sp, PT_R20
	PTR_S	s0, sp, PT_R23
	PTR_S	s1, sp, PT_R24
	PTR_S	s2, sp, PT_R25
	PTR_S	s3, sp, PT_R26
	PTR_S	s4, sp, PT_R27
	PTR_S	s5, sp, PT_R28
	PTR_S	s6, sp, PT_R29
	PTR_S	s7, sp, PT_R30
	PTR_S	s8, sp, PT_R31
	PTR_S	tp, sp, PT_R2
	/* Clear it for later use as a flag sometimes. */
	PTR_S	zero, sp, PT_R0
	PTR_S	$r21, sp, PT_R21
	.endif

	PTR_ADDI t8, sp, PT_SIZE
	PTR_S   t8, sp, PT_R3

	UNWIND_HINT_REGS
	.endm

SYM_CODE_START(ftrace_caller)
	UNWIND_HINT sp_reg=ORC_REG_SP type=ORC_TYPE_CALL
	ftrace_regs_entry allregs=0
	b	ftrace_common
SYM_CODE_END(ftrace_caller)

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
SYM_CODE_START(ftrace_regs_caller)
	UNWIND_HINT sp_reg=ORC_REG_SP type=ORC_TYPE_CALL
	ftrace_regs_entry allregs=1
	b	ftrace_common
SYM_CODE_END(ftrace_regs_caller)
#endif

SYM_CODE_START(ftrace_common)
	UNWIND_HINT_REGS
	PTR_ADDI	a0, ra, -8	/* arg0: ip */
	move		a1, t0		/* arg1: parent_ip */
	la.pcrel	t1, function_trace_op
	PTR_L		a2, t1, 0	/* arg2: op */
	move		a3, sp		/* arg3: regs */
	.globl ftrace_call
ftrace_call:
	bl		ftrace_stub
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	.globl ftrace_graph_call
ftrace_graph_call:
	nop				/* b ftrace_graph_caller */
#endif
/*
 * As we didn't use S series regs in this assmembly code and all calls
 * are C function which will save S series regs by themselves, there is
 * no need to restore S series regs. The T series is available and safe
 * at the callsite, so there is no need to restore the T series regs.
 */
ftrace_common_return:
	PTR_L	a0, sp, PT_R4
	PTR_L	a1, sp, PT_R5
	PTR_L	a2, sp, PT_R6
	PTR_L	a3, sp, PT_R7
	PTR_L	a4, sp, PT_R8
	PTR_L	a5, sp, PT_R9
	PTR_L	a6, sp, PT_R10
	PTR_L	a7, sp, PT_R11
	PTR_L	fp, sp, PT_R22
	PTR_L	ra, sp, PT_R1
	PTR_L	t0, sp, PT_ERA
	PTR_ADDI sp, sp, PT_SIZE
	UNWIND_HINT sp_reg=ORC_REG_SP type=ORC_TYPE_CALL
	jirl	zero, t0, 0
SYM_CODE_END(ftrace_common)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
SYM_CODE_START(ftrace_graph_caller)
	UNWIND_HINT_REGS
	PTR_L		a0, sp, PT_ERA
	PTR_ADDI	a0, a0, -8	/* arg0: self_addr */
	PTR_ADDI	a1, sp, PT_R1	/* arg1: parent */
	bl		prepare_ftrace_return
	b		ftrace_common_return
SYM_CODE_END(ftrace_graph_caller)

SYM_CODE_START(return_to_handler)
	UNWIND_HINT sp_reg=ORC_REG_SP type=ORC_TYPE_CALL
	/* save return value regs */
	PTR_ADDI 	sp, sp, -2 * SZREG
	PTR_S		a0, sp, 0
	PTR_S		a1, sp, SZREG

	move		a0, zero	/* Has no check FP now. */
	bl		ftrace_return_to_handler
	move		ra, a0		/* parent ra */

	/* restore return value regs */
	PTR_L		a0, sp, 0
	PTR_L		a1, sp, SZREG
	PTR_ADDI 	sp, sp, 2 * SZREG

	jirl		zero, ra, 0
SYM_CODE_END(return_to_handler)
#endif

SYM_FUNC_START(ftrace_stub)
	jirl	zero, ra, 0
SYM_FUNC_END(ftrace_stub)
