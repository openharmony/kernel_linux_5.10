/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */

#include <linux/linkage.h>
#include <asm/addrspace.h>
#include <asm/asm.h>
#include <asm/loongarchregs.h>
#include <asm/regdef.h>

SYM_CODE_START(start)
	/* Save boot rom start args */
	move	s0, a0
	move	s1, a1
	move	s2, a2

	/* Config Direct Mapping */
	li.d	t0, CSR_DMW0_INIT
	csrwr	t0, LOONGARCH_CSR_DMWIN0
	li.d	t0, CSR_DMW1_INIT
	csrwr	t0, LOONGARCH_CSR_DMWIN1

	/* Clear BSS */
	la.abs	a0, _edata
	la.abs	a2, _end
1:	st.d	zero, a0, 0
	addi.d	a0, a0, 8
	bne	a2, a0, 1b

	la.abs	a0, .heap	   /* heap address */
	la.abs	sp, .stack + 8192  /* stack address */

	la.pcrel ra, 2f
	la.pcrel t4, decompress_kernel
	jirl	zero, t4, 0
2:
	move	a0, s0
	move	a1, s1
	move	a2, s2
	PTR_LI	t4, KERNEL_ENTRY
	jirl	zero, t4, 0
3:
	b	3b
SYM_CODE_END(start)

	.comm .heap,BOOT_HEAP_SIZE,4
	.comm .stack,4096*2,4
