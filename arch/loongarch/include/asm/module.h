/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_MODULE_H
#define _ASM_MODULE_H

#include <asm/inst.h>
#include <asm-generic/module.h>
#include <asm/orc_types.h>

#define RELA_STACK_DEPTH 16

struct mod_section {
	int shndx;
	int num_entries;
	int max_entries;
};

struct mod_arch_specific {
	struct mod_section got;
	struct mod_section plt;
	struct mod_section plt_idx;
#ifdef CONFIG_UNWINDER_ORC
	unsigned int num_orcs;
	int *orc_unwind_ip;
	struct orc_entry *orc_unwind;
#endif

	/* for CONFIG_DYNAMIC_FTRACE */
	struct plt_entry *ftrace_trampolines;
};

struct got_entry {
	Elf_Addr symbol_addr;
};

struct plt_entry {
	u32 inst_addu16id;
	u32 inst_lu32id;
	u32 inst_lu52id;
	u32 inst_jirl;
};

struct plt_idx_entry {
	Elf_Addr symbol_addr;
};

Elf_Addr module_emit_got_entry(struct module *mod, Elf_Shdr *sechdrs, Elf_Addr val);
Elf_Addr module_emit_plt_entry(struct module *mod, Elf_Shdr *sechdrs, Elf_Addr val);

static inline struct got_entry emit_got_entry(Elf_Addr val)
{
	return (struct got_entry) { val };
}

static inline struct plt_entry emit_plt_entry(unsigned long val)
{
	u32 addu16id, lu32id, lu52id, jirl;

	addu16id = larch_insn_gen_addu16id(REG_T1, REG_ZERO, ADDR_IMM(val, ADDU16ID));
	lu32id = larch_insn_gen_lu32id(REG_T1, ADDR_IMM(val, LU32ID));
	lu52id = larch_insn_gen_lu52id(REG_T1, REG_T1, ADDR_IMM(val, LU52ID));
	jirl = larch_insn_gen_jirl(0, REG_T1, 0, (val & 0xffff));

	return (struct plt_entry) { addu16id, lu32id, lu52id, jirl };
}

static inline struct plt_idx_entry emit_plt_idx_entry(unsigned long val)
{
	return (struct plt_idx_entry) { val };
}

static inline int get_plt_idx(unsigned long val, Elf_Shdr *sechdrs, const struct mod_section *sec)
{
	int i;
	struct plt_idx_entry *plt_idx = (struct plt_idx_entry *)sechdrs[sec->shndx].sh_addr;

	for (i = 0; i < sec->num_entries; i++) {
		if (plt_idx[i].symbol_addr == val)
			return i;
	}

	return -1;
}

static inline struct plt_entry *get_plt_entry(unsigned long val,
					      Elf_Shdr *sechdrs,
					      const struct mod_section *sec_plt,
					      const struct mod_section *sec_plt_idx)
{
	int plt_idx = get_plt_idx(val, sechdrs, sec_plt_idx);
	struct plt_entry *plt = (struct plt_entry *)sechdrs[sec_plt->shndx].sh_addr;

	if (plt_idx < 0)
		return NULL;

	return plt + plt_idx;
}

static inline struct got_entry *get_got_entry(Elf_Addr val,
					      Elf_Shdr *sechdrs,
					      const struct mod_section *sec)
{
	int i;
	struct got_entry *got = (struct got_entry *)sechdrs[sec->shndx].sh_addr;

	for (i = 0; i < sec->num_entries; i++)
		if (got[i].symbol_addr == val)
			return &got[i];
	return NULL;
}

#endif /* _ASM_MODULE_H */
