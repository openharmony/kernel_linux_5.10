// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/export.h>
#include <linux/sched.h>

#include <asm/cpu-features.h>
#include <asm/cpu-info.h>

int arch_elf_pt_proc(void *_ehdr, void *_phdr, struct file *elf,
		     bool is_interp, struct arch_elf_state *state)
{
	return 0;
}

int arch_check_elf(void *_ehdr, bool has_interpreter, void *_interp_ehdr,
		   struct arch_elf_state *state)
{
	return 0;
}
