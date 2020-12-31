// SPDX-License-Identifier: GPL-2.0
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 */
#include <linux/dma-direct.h>
#include <linux/init.h>
#include <linux/sizes.h>
#include <linux/acpi.h>
#include <linux/dma-direct.h>
#include <linux/dma-mapping.h>
#include <linux/dma-map-ops.h>
#include <linux/scatterlist.h>
#include <linux/swiotlb.h>

#include <asm/bootinfo.h>
#include <asm/dma.h>
#include <loongson.h>

static int node_id_offset;

dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	/* We extract 4bit node id (bit 44~47) from Loongson-3's
	 * 48bit address space and embed it into 40bit */
	long nid = (paddr >> 44) & 0xf;
	return ((nid << 44) ^ paddr) | (nid << node_id_offset);
}

phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	/* We extract 4bit node id (bit 44~47) from Loongson-3's
	 * 48bit address space and embed it into 40bit */
	long nid = (daddr >> node_id_offset) & 0xf;
	return ((nid << node_id_offset) ^ daddr) | (nid << 44);
}

void __init plat_swiotlb_setup(void)
{
	swiotlb_init(1);
	node_id_offset = ((readl(LS7A_DMA_CFG) & LS7A_DMA_NODE_MASK) >> LS7A_DMA_NODE_SHF) + 36;
}
