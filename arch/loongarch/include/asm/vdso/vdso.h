/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 */

#ifndef __ASSEMBLY__

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/vdso.h>

static inline unsigned long get_vdso_base(void)
{
	unsigned long addr;

	__asm__(
	" la.pcrel %0, _start \n"
	: "=r" (addr)
	:
	:);

	return addr;
}

static inline const struct vdso_data *get_vdso_data(void)
{
	return (const struct vdso_data *)(get_vdso_base() - PAGE_SIZE);
}

#endif /* __ASSEMBLY__ */
