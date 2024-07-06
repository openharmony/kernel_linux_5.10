// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/task_stack.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/syscore_ops.h>
#include <linux/tracepoint.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <loongson.h>

struct secondary_data cpuboot_data;

static DEFINE_PER_CPU(int, cpu_state);
DEFINE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat);
EXPORT_PER_CPU_SYMBOL(irq_stat);

#define MAX_CPUS 64

#define STATUS  0x00
#define EN      0x04
#define SET     0x08
#define CLEAR   0x0c
#define MBUF    0x20

extern unsigned long long smp_group[MAX_PACKAGES];
static u32 core_offsets[4] = {0x000, 0x100, 0x200, 0x300};

static volatile void *ipi_set_regs[MAX_CPUS];
static volatile void *ipi_clear_regs[MAX_CPUS];
static volatile void *ipi_status_regs[MAX_CPUS];
static volatile void *ipi_en_regs[MAX_CPUS];
static volatile void *ipi_mailbox_buf[MAX_CPUS];

static u32 (*ipi_read_clear)(int cpu);
static void (*ipi_write_action)(int cpu, u32 action);

enum ipi_msg_type {
	IPI_RESCHEDULE,
	IPI_CALL_FUNCTION,
};

static const char *ipi_types[NR_IPI] __tracepoint_string = {
	[IPI_RESCHEDULE] = "Rescheduling interrupts",
	[IPI_CALL_FUNCTION] = "Function call interrupts",
};

void show_ipi_list(struct seq_file *p, int prec)
{
	unsigned int cpu, i;

	for (i = 0; i < NR_IPI; i++) {
		seq_printf(p, "%*s%u:%s", prec - 1, "IPI", i, prec >= 4 ? " " : "");
		for_each_online_cpu(cpu)
			seq_printf(p, "%10u ", per_cpu(irq_stat, cpu).ipi_irqs[i]);
		seq_printf(p, " LoongArch  %d  %s\n", i + 1, ipi_types[i]);
	}
}

/* Send mail buffer via Mail_Send */
static void csr_mail_send(uint64_t data, int cpu, int mailbox)
{
	uint64_t val;

	/* Send high 32 bits */
	val = IOCSR_MBUF_SEND_BLOCKING;
	val |= (IOCSR_MBUF_SEND_BOX_HI(mailbox) << IOCSR_MBUF_SEND_BOX_SHIFT);
	val |= (cpu << IOCSR_MBUF_SEND_CPU_SHIFT);
	val |= (data & IOCSR_MBUF_SEND_H32_MASK);
	iocsr_write64(val, LOONGARCH_IOCSR_MBUF_SEND);

	/* Send low 32 bits */
	val = IOCSR_MBUF_SEND_BLOCKING;
	val |= (IOCSR_MBUF_SEND_BOX_LO(mailbox) << IOCSR_MBUF_SEND_BOX_SHIFT);
	val |= (cpu << IOCSR_MBUF_SEND_CPU_SHIFT);
	val |= (data << IOCSR_MBUF_SEND_BUF_SHIFT);
	iocsr_write64(val, LOONGARCH_IOCSR_MBUF_SEND);
};

static u32 csr_ipi_read_clear(int cpu)
{
	u32 action;

	/* Load the ipi register to figure out what we're supposed to do */
	action = iocsr_read32(LOONGARCH_IOCSR_IPI_STATUS);
	/* Clear the ipi register to clear the interrupt */
	iocsr_write32(action, LOONGARCH_IOCSR_IPI_CLEAR);

	return action;
}

static void csr_ipi_write_action(int cpu, u32 action)
{
	unsigned int irq = 0;

	while ((irq = ffs(action))) {
		uint32_t val = IOCSR_IPI_SEND_BLOCKING;
		val |= (irq - 1);
		val |= (cpu << IOCSR_IPI_SEND_CPU_SHIFT);
		iocsr_write32(val, LOONGARCH_IOCSR_IPI_SEND);
		action &= ~BIT(irq - 1);
	}
}

static u32 legacy_ipi_read_clear(int cpu)
{
	u32 action;

	/* Load the ipi register to figure out what we're supposed to do */
	action = xconf_readl(ipi_status_regs[cpu]);
	/* Clear the ipi register to clear the interrupt */
	xconf_writel(action, ipi_clear_regs[cpu]);

	return action;
}

static void legacy_ipi_write_action(int cpu, u32 action)
{
	xconf_writel((u32)action, ipi_set_regs[cpu]);
}

static void ipi_method_init(void)
{
	if (cpu_has_csripi) {
		ipi_read_clear = csr_ipi_read_clear;
		ipi_write_action = csr_ipi_write_action;
	} else {
		ipi_read_clear = legacy_ipi_read_clear;
		ipi_write_action = legacy_ipi_write_action;
	}
}

static void ipi_regaddrs_init(void)
{
	int i, node, core;

	for (i = 0; i< MAX_CPUS; i++) {
		node = i / 4;
		core = i % 4;
		ipi_set_regs[i] = (void *)
			(smp_group[node] + core_offsets[core] + SET);
		ipi_clear_regs[i] = (void *)
			(smp_group[node] + core_offsets[core] + CLEAR);
		ipi_status_regs[i] = (void *)
			(smp_group[node] + core_offsets[core] + STATUS);
		ipi_en_regs[i] = (void *)
			(smp_group[node] + core_offsets[core] + EN);
		ipi_mailbox_buf[i] = (void *)
			(smp_group[node] + core_offsets[core] + MBUF);
	}
}

/*
 * Simple enough, just poke the appropriate ipi register
 */
static void loongson3_send_ipi_single(int cpu, unsigned int action)
{
	ipi_write_action(cpu_logical_map(cpu), (u32)action);
}

static void
loongson3_send_ipi_mask(const struct cpumask *mask, unsigned int action)
{
	unsigned int i;

	for_each_cpu(i, mask)
		ipi_write_action(cpu_logical_map(i), (u32)action);
}

irqreturn_t loongson3_ipi_interrupt(int irq, void *dev)
{
	unsigned int action;
	unsigned int cpu = smp_processor_id();

	action = ipi_read_clear(cpu_logical_map(cpu));

	wbflush();

	if (action & SMP_RESCHEDULE) {
		scheduler_ipi();
		per_cpu(irq_stat, cpu).ipi_irqs[IPI_RESCHEDULE]++;
	}

	if (action & SMP_CALL_FUNCTION) {
		generic_smp_call_function_interrupt();
		per_cpu(irq_stat, cpu).ipi_irqs[IPI_CALL_FUNCTION]++;
	}

	return IRQ_HANDLED;
}

/*
 * SMP init and finish on secondary CPUs
 */
static void loongson3_init_secondary(void)
{
	unsigned int cpu = smp_processor_id();
	unsigned int imask = ECFGF_IP0 | ECFGF_IP1 | ECFGF_IP2 |
			     ECFGF_IPI | ECFGF_PMC | ECFGF_TIMER;

	change_csr_ecfg(ECFG0_IM, imask);

	if (cpu_has_csripi)
		iocsr_write32(0xffffffff, LOONGARCH_IOCSR_IPI_EN);
	else
		xconf_writel(0xffffffff, ipi_en_regs[cpu_logical_map(cpu)]);

#ifdef CONFIG_NUMA
	numa_add_cpu(cpu);
#endif
	per_cpu(cpu_state, cpu) = CPU_ONLINE;
	cpu_data[cpu].package =
		     cpu_logical_map(cpu) / loongson_sysconf.cores_per_package;
	cpu_data[cpu].core = pptt_enabled ? cpu_data[cpu].core :
		     cpu_logical_map(cpu) % loongson_sysconf.cores_per_package;
}

static void loongson3_smp_finish(void)
{
	int cpu = smp_processor_id();

	local_irq_enable();

	if (cpu_has_csripi)
		iocsr_write64(0, LOONGARCH_IOCSR_MBUF0);
	else
		xconf_writeq(0, ipi_mailbox_buf[cpu_logical_map(cpu)]+0x0);

	pr_info("CPU#%d finished\n", smp_processor_id());
}

static void __init loongson3_smp_setup(void)
{
	ipi_method_init();
	ipi_regaddrs_init();

	if (cpu_has_csripi)
		iocsr_write32(0xffffffff, LOONGARCH_IOCSR_IPI_EN);
	else
		xconf_writel(0xffffffff, ipi_en_regs[cpu_logical_map(0)]);

	pr_info("Detected %i available CPU(s)\n", loongson_sysconf.nr_cpus);

	cpu_data[0].core = cpu_logical_map(0) % loongson_sysconf.cores_per_package;
	cpu_data[0].package = cpu_logical_map(0) / loongson_sysconf.cores_per_package;
}

static void __init loongson3_prepare_cpus(unsigned int max_cpus)
{
	int i = 0;

	parse_acpi_topology();

	for (i = 0; i < loongson_sysconf.nr_cpus; i++) {
		set_cpu_present(i, true);
		cpu_data[i].global_id = __cpu_logical_map[i];

		if (cpu_has_csripi)
			csr_mail_send(0, __cpu_logical_map[i], 0);
		else
			xconf_writeq(0, ipi_mailbox_buf[__cpu_logical_map[i]]+0x0);
	}

	per_cpu(cpu_state, smp_processor_id()) = CPU_ONLINE;
}

/*
 * Setup the PC, SP, and TP of a secondary processor and start it runing!
 */
static int loongson3_boot_secondary(int cpu, struct task_struct *idle)
{
	unsigned long entry;

	pr_info("Booting CPU#%d...\n", cpu);

	entry = __pa_symbol((unsigned long)&smpboot_entry);
	cpuboot_data.stack = (unsigned long)__KSTK_TOS(idle);
	cpuboot_data.thread_info = (unsigned long)task_thread_info(idle);

	if (cpu_has_csripi)
		csr_mail_send(entry, cpu_logical_map(cpu), 0);
	else
		xconf_writeq(entry, ipi_mailbox_buf[cpu_logical_map(cpu)]+0x0);

	loongson3_send_ipi_single(cpu, SMP_BOOT_CPU);

	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU

static bool io_master(int cpu)
{
	int i, node, master;

	if (cpu == 0)
		return true;

	for (i = 1; i < loongson_sysconf.nr_io_pics; i++) {
		node = eiointc_get_node(i);
		master = cpu_number_map(node * CORES_PER_EIO_NODE);
		if (cpu == master)
			return true;
	}

	return false;
}

static int loongson3_cpu_disable(void)
{
	unsigned long flags;
	unsigned int cpu = smp_processor_id();

	if (io_master(cpu))
		return -EBUSY;

#ifdef CONFIG_NUMA
	numa_remove_cpu(cpu);
#endif
	set_cpu_online(cpu, false);
	clear_cpu_sibling_map(cpu);
	calculate_cpu_foreign_map();
	local_irq_save(flags);
	irq_migrate_all_off_this_cpu();
	clear_csr_ecfg(ECFG0_IM);
	local_irq_restore(flags);
	local_flush_tlb_all();

	return 0;
}


static void loongson3_cpu_die(unsigned int cpu)
{
	while (per_cpu(cpu_state, cpu) != CPU_DEAD)
		cpu_relax();

	mb();
}

void __noreturn arch_cpu_idle_dead(void)
{
	register long cpuid, core, node, count;
	register void *addr, *base;
	register void (*init_fn)(void);

	idle_task_exit();
	local_irq_enable();
	change_csr_ecfg(ECFG0_IM, ECFGF_IPI);
	__this_cpu_write(cpu_state, CPU_DEAD);

	__smp_mb();
	__asm__ __volatile__(
		"   idle   0			       \n"
		"   csrrd  %[cpuid], 0x20              \n"
		"   andi   %[cpuid], %[cpuid], 0x1ff   \n"
		"   li.d   %[base], 0x800000001fe01000 \n"
		"   andi   %[core], %[cpuid], 0x3      \n"
		"   slli.w %[core], %[core], 8         \n" /* Get core id */
		"   or     %[base], %[base], %[core]   \n"
		"   andi   %[node], %[cpuid], 0x3c     \n"
		"   slli.d %[node], %[node], 42        \n" /* Get node id */
		"   or     %[base], %[base], %[node]   \n"
		"   ld.d   %[init_fn], %[base], 0x20   \n" /* Get init PC */
		"   nop                                \n"
		: [core] "=&r" (core), [node] "=&r" (node),
		  [base] "=&r" (base), [cpuid] "=&r" (cpuid),
		  [count] "=&r" (count), [init_fn] "=&r" (addr)
		: /* No Input */
		: "a1");

	local_irq_disable();
	init_fn = __va(addr);

	init_fn();
	unreachable();
}

#endif

const struct plat_smp_ops loongson3_smp_ops = {
	.send_ipi_single = loongson3_send_ipi_single,
	.send_ipi_mask = loongson3_send_ipi_mask,
	.smp_setup = loongson3_smp_setup,
	.prepare_cpus = loongson3_prepare_cpus,
	.boot_secondary = loongson3_boot_secondary,
	.init_secondary = loongson3_init_secondary,
	.smp_finish = loongson3_smp_finish,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_disable = loongson3_cpu_disable,
	.cpu_die = loongson3_cpu_die,
#endif
};

/*
 * Power management
 */
#ifdef CONFIG_PM

static int loongson3_ipi_suspend(void)
{
        return 0;
}

static void loongson3_ipi_resume(void)
{
	if (cpu_has_csripi)
		iocsr_write32(0xffffffff, LOONGARCH_IOCSR_IPI_EN);
	else
		xconf_writel(0xffffffff, ipi_en_regs[cpu_logical_map(0)]);
}

static struct syscore_ops loongson3_ipi_syscore_ops = {
	.resume         = loongson3_ipi_resume,
	.suspend        = loongson3_ipi_suspend,
};

/*
 * Enable boot cpu ipi before enabling nonboot cpus
 * during syscore_resume.
 * */
static int __init ipi_pm_init(void)
{
	register_syscore_ops(&loongson3_ipi_syscore_ops);
	return 0;
}

core_initcall(ipi_pm_init);
#endif
