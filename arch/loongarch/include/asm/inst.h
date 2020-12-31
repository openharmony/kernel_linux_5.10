/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Format of an instruction in memory.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#ifndef _ASM_INST_H
#define _ASM_INST_H

#include <asm/asm.h>
#include <uapi/asm/inst.h>

/* HACHACHAHCAHC ...  */

/* In case some other massaging is needed, keep LOONGARCHInst as wrapper */

#define LOONGARCHInst(x) x

#define I_OPCODE_SFT	26
#define LOONGARCHInst_OPCODE(x) (LOONGARCHInst(x) >> I_OPCODE_SFT)

#define I_JTARGET_SFT	0
#define LOONGARCHInst_JTARGET(x) (LOONGARCHInst(x) & 0x03ffffff)

#define I_RS_SFT	21
#define LOONGARCHInst_RS(x) ((LOONGARCHInst(x) & 0x03e00000) >> I_RS_SFT)

#define I_RT_SFT	16
#define LOONGARCHInst_RT(x) ((LOONGARCHInst(x) & 0x001f0000) >> I_RT_SFT)

#define I_IMM_SFT	0
#define LOONGARCHInst_SIMM(x) ((int)((short)(LOONGARCHInst(x) & 0xffff)))
#define LOONGARCHInst_UIMM(x) (LOONGARCHInst(x) & 0xffff)

#define I_CACHEOP_SFT	18
#define LOONGARCHInst_CACHEOP(x) ((LOONGARCHInst(x) & 0x001c0000) >> I_CACHEOP_SFT)

#define I_CACHESEL_SFT	16
#define LOONGARCHInst_CACHESEL(x) ((LOONGARCHInst(x) & 0x00030000) >> I_CACHESEL_SFT)

#define I_RD_SFT	11
#define LOONGARCHInst_RD(x) ((LOONGARCHInst(x) & 0x0000f800) >> I_RD_SFT)

#define I_RE_SFT	6
#define LOONGARCHInst_RE(x) ((LOONGARCHInst(x) & 0x000007c0) >> I_RE_SFT)

#define I_FUNC_SFT	0
#define LOONGARCHInst_FUNC(x) (LOONGARCHInst(x) & 0x0000003f)

#define I_FFMT_SFT	21
#define LOONGARCHInst_FFMT(x) ((LOONGARCHInst(x) & 0x01e00000) >> I_FFMT_SFT)

#define I_FT_SFT	16
#define LOONGARCHInst_FT(x) ((LOONGARCHInst(x) & 0x001f0000) >> I_FT_SFT)

#define I_FS_SFT	11
#define LOONGARCHInst_FS(x) ((LOONGARCHInst(x) & 0x0000f800) >> I_FS_SFT)

#define I_FD_SFT	6
#define LOONGARCHInst_FD(x) ((LOONGARCHInst(x) & 0x000007c0) >> I_FD_SFT)

#define I_FR_SFT	21
#define LOONGARCHInst_FR(x) ((LOONGARCHInst(x) & 0x03e00000) >> I_FR_SFT)

#define I_FMA_FUNC_SFT	2
#define LOONGARCHInst_FMA_FUNC(x) ((LOONGARCHInst(x) & 0x0000003c) >> I_FMA_FUNC_SFT)

#define I_FMA_FFMT_SFT	0
#define LOONGARCHInst_FMA_FFMT(x) (LOONGARCHInst(x) & 0x00000003)

struct pt_regs;
typedef unsigned int loongarch_instruction;

/* Recode table from 16-bit register notation to 32-bit GPR. Do NOT export!!! */
extern const int reg16to32[];

void emulate_load_store_insn(struct pt_regs *regs, void __user *addr, unsigned int *pc);
unsigned long unaligned_read(void __user *addr, void *value, unsigned long n, bool sign);
unsigned long unaligned_write(void __user *addr, unsigned long value, unsigned long n);

#endif /* _ASM_INST_H */
