/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 * Author: Jianmin Lv <lvjianmin@loongson.cn>
 *         Huacai Chen <chenhuacai@loongson.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _ASM_LOONGARCH_ACPI_H
#define _ASM_LOONGARCH_ACPI_H

#ifdef CONFIG_ACPI
extern int acpi_strict;
extern int acpi_disabled;
extern int acpi_pci_disabled;
extern int acpi_noirq;
extern int pptt_enabled;

#define acpi_os_ioremap acpi_os_ioremap
void __iomem *acpi_os_ioremap(acpi_physical_address phys, acpi_size size);

static inline void disable_acpi(void)
{
	acpi_disabled = 1;
	acpi_pci_disabled = 1;
	acpi_noirq = 1;
}

static inline bool acpi_has_cpu_in_madt(void)
{
	return true;
}

#define MAX_CORE_PIC 256

extern struct list_head acpi_wakeup_device_list;
extern struct acpi_madt_core_pic acpi_core_pic[MAX_CORE_PIC];

extern int __init parse_acpi_topology(void);

static inline u32 get_acpi_id_for_cpu(unsigned int cpu)
{
	return acpi_core_pic[cpu_logical_map(cpu)].processor_id;
}

#endif /* !CONFIG_ACPI */

#define ACPI_TABLE_UPGRADE_MAX_PHYS ARCH_LOW_ADDRESS_LIMIT

extern int loongarch_acpi_suspend(void);
extern int (*acpi_suspend_lowlevel)(void);
extern void loongarch_suspend_enter(void);

static inline unsigned long acpi_get_wakeup_address(void)
{
#ifdef CONFIG_SUSPEND
	extern void loongarch_wakeup_start(void);
	return (unsigned long)loongarch_wakeup_start;
#endif
	return 0UL;
}

#endif /* _ASM_LOONGARCH_ACPI_H */
