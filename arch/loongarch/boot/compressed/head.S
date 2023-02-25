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
	move	s3, a3 /* for kdump */

	/* Config Direct Mapping */
	li.d	t0, CSR_DMW0_INIT
	csrwr	t0, LOONGARCH_CSR_DMWIN0
	li.d	t0, CSR_DMW1_INIT
	csrwr	t0, LOONGARCH_CSR_DMWIN1

	/* Clear BSS */
	la.pcrel a0, _edata
	la.pcrel a2, _end
1:	st.d	zero, a0, 0
	addi.d	a0, a0, 8
	bne	a2, a0, 1b

	la.pcrel a0, .heap	   /* heap address */
	la.pcrel sp, .stack + 8192  /* stack address */

	la.pcrel a0, .heap	  /* heap address */
	move	a1, a3		  /* kdump relocate offset */
	bnez	a3, 2f
	li.w	a1, 0
	li.w	s3, 0
2:
	la.pcrel ra, 3f
	la.pcrel t4, decompress_kernel
	jirl	zero, t4, 0
3:
	move	a0, s0
	move	a1, s1
	move	a2, s2
	move	a3, s3
	PTR_LI	t4, KERNEL_ENTRY
	add.d	t4, t4, a3
	jirl	zero, t4, 0
4:
	b	4b
SYM_CODE_END(start)

	.comm .heap,BOOT_HEAP_SIZE,4
	.comm .stack,4096*2,4
