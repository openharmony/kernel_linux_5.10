/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#ifndef _ASM_BOOTINFO_H
#define _ASM_BOOTINFO_H

#include <linux/types.h>
#include <asm/setup.h>

const char *get_system_type(void);

extern void memblock_init(void);
extern void detect_memory_region(phys_addr_t start, phys_addr_t sz_min,  phys_addr_t sz_max);

extern void early_init(void);
extern void init_environ(void);
extern void platform_init(void);
extern void plat_mem_setup(void);
extern void plat_swiotlb_setup(void);
extern int __init init_numa_memory(void);

struct loongson_board_info {
	int bios_size;
	const char *bios_vendor;
	const char *bios_version;
	const char *bios_release_date;
	const char *board_name;
	const char *board_vendor;
};

struct loongson_system_configuration {
	int nr_cpus;
	int nr_nodes;
	int nr_io_pics;
	int boot_cpu_id;
	int cores_per_node;
	int cores_per_package;
	const char *cpuname;
	u64 suspend_addr;
};

extern u64 efi_system_table;
extern struct loongson_board_info b_info;
extern struct loongson_system_configuration loongson_sysconf;
extern unsigned long fw_arg0, fw_arg1, fw_arg2;

#endif /* _ASM_BOOTINFO_H */
