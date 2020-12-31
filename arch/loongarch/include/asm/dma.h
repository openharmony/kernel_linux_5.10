/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 */
#ifndef __ASM_DMA_H
#define __ASM_DMA_H

#define MAX_DMA_ADDRESS	PAGE_OFFSET
#define MAX_DMA32_PFN	(1UL << (32 - PAGE_SHIFT))

extern int isa_dma_bridge_buggy;

#endif
