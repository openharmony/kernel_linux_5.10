// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/stddef.h>
#include <asm/irq.h>
#include <asm/setup.h>
#include <asm/loongarchregs.h>
#include <loongson.h>

struct acpi_madt_lio_pic *acpi_liointc;
struct acpi_madt_eio_pic *acpi_eiointc[MAX_IO_PICS];

struct acpi_madt_ht_pic *acpi_htintc;
struct acpi_madt_lpc_pic *acpi_pchlpc;
struct acpi_madt_msi_pic *acpi_pchmsi[MAX_IO_PICS];
struct acpi_madt_bio_pic *acpi_pchpic[MAX_IO_PICS];

struct irq_domain *cpu_domain;
struct irq_domain *liointc_domain;
struct irq_domain *pch_lpc_domain;
struct irq_domain *pch_msi_domain[MAX_IO_PICS];
struct irq_domain *pch_pic_domain[MAX_IO_PICS];

int find_pch_pic(u32 gsi)
{
	int i, start, end;

	/* Find the PCH_PIC that manages this GSI. */
	for(i = 0; i < loongson_sysconf.nr_io_pics; i++) {
		struct acpi_madt_bio_pic *irq_cfg = acpi_pchpic[i];

		start = irq_cfg->gsi_base;
		end   = irq_cfg->gsi_base + irq_cfg->size;
		if (gsi >= start && gsi < end)
			return i;
	}

	printk(KERN_ERR "ERROR: Unable to locate PCH_PIC for GSI %d\n", gsi);
	return -1;
}

void __init setup_IRQ(void)
{
	int i;
	struct irq_domain *parent_domain;

	if (!acpi_eiointc[0])
		cpu_data[0].options &= ~LOONGARCH_CPU_EXTIOI;

	cpu_domain = loongarch_cpu_irq_init();
	liointc_domain = liointc_acpi_init(cpu_domain, acpi_liointc);

	if (cpu_has_extioi) {
		pr_info("Using EIOINTC interrupt mode\n");
		for(i = 0; i < loongson_sysconf.nr_io_pics; i++) {
			parent_domain = eiointc_acpi_init(cpu_domain, acpi_eiointc[i]);
			pch_pic_domain[i] = pch_pic_acpi_init(parent_domain, acpi_pchpic[i]);
			pch_msi_domain[i] = pch_msi_acpi_init(parent_domain, acpi_pchmsi[i]);
		}
	} else {
		pr_info("Using HTVECINTC interrupt mode\n");
		parent_domain = htvec_acpi_init(liointc_domain, acpi_htintc);
		pch_pic_domain[0] = pch_pic_acpi_init(parent_domain, acpi_pchpic[0]);
		pch_msi_domain[0] = pch_msi_acpi_init(parent_domain, acpi_pchmsi[0]);
	}

	irq_set_default_host(pch_pic_domain[0]);
	pch_lpc_domain = pch_lpc_acpi_init(pch_pic_domain[0], acpi_pchlpc);
}

void __init arch_init_irq(void)
{
	int r, ipi_irq;
	static int ipi_dummy_dev;

	clear_csr_ecfg(ECFG0_IM);
	clear_csr_estat(ESTATF_IP);

	setup_IRQ();
#ifdef CONFIG_SMP
	ipi_irq = get_ipi_irq();
	irq_set_percpu_devid(ipi_irq);
	r = request_percpu_irq(ipi_irq, loongson3_ipi_interrupt, "IPI", &ipi_dummy_dev);
	if (r < 0)
		panic("IPI IRQ request failed\n");
#endif

	set_csr_ecfg(ECFGF_IP0 | ECFGF_IP1 | ECFGF_IP2 | ECFGF_IPI | ECFGF_PMC);
}
