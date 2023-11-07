// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#include <linux/cache.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/profile.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/threads.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/sched/mm.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/ftrace.h>
#include <linux/of.h>
#include <linux/of_irq.h>

#include <asm/cpu.h>
#include <asm/processor.h>
#include <asm/idle.h>
#include <asm/mmu_context.h>
#include <asm/numa.h>
#include <asm/time.h>
#include <asm/setup.h>

int __cpu_number_map[NR_CPUS];   /* Map physical to logical */
EXPORT_SYMBOL(__cpu_number_map);

int __cpu_logical_map[NR_CPUS];		/* Map logical to physical */
EXPORT_SYMBOL(__cpu_logical_map);

/* Representing the threads (siblings) of each logical CPU */
cpumask_t cpu_sibling_map[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(cpu_sibling_map);

/* Representing the core map of multi-core chips of each logical CPU */
cpumask_t cpu_core_map[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(cpu_core_map);

static DECLARE_COMPLETION(cpu_starting);
static DECLARE_COMPLETION(cpu_running);

/*
 * A logcal cpu mask containing only one VPE per core to
 * reduce the number of IPIs on large MT systems.
 */
cpumask_t cpu_foreign_map[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(cpu_foreign_map);

/* representing cpus for which sibling maps can be computed */
static cpumask_t cpu_sibling_setup_map;

/* representing cpus for which core maps can be computed */
static cpumask_t cpu_core_setup_map;

static inline void set_cpu_sibling_map(int cpu)
{
	int i;

	cpumask_set_cpu(cpu, &cpu_sibling_setup_map);

	for_each_cpu(i, &cpu_sibling_setup_map) {
		if (cpus_are_siblings(cpu, i)) {
			cpumask_set_cpu(i, &cpu_sibling_map[cpu]);
			cpumask_set_cpu(cpu, &cpu_sibling_map[i]);
		}
	}
}

static inline void set_cpu_core_map(int cpu)
{
	int i;

	cpumask_set_cpu(cpu, &cpu_core_setup_map);

	for_each_cpu(i, &cpu_core_setup_map) {
		if (cpu_data[cpu].package == cpu_data[i].package) {
			cpumask_set_cpu(i, &cpu_core_map[cpu]);
			cpumask_set_cpu(cpu, &cpu_core_map[i]);
		}
	}
}

/*
 * Calculate a new cpu_foreign_map mask whenever a
 * new cpu appears or disappears.
 */
void calculate_cpu_foreign_map(void)
{
	int i, k, core_present;
	cpumask_t temp_foreign_map;

	/* Re-calculate the mask */
	cpumask_clear(&temp_foreign_map);
	for_each_online_cpu(i) {
		core_present = 0;
		for_each_cpu(k, &temp_foreign_map)
			if (cpus_are_siblings(i, k))
				core_present = 1;
		if (!core_present)
			cpumask_set_cpu(i, &temp_foreign_map);
	}

	for_each_online_cpu(i)
		cpumask_andnot(&cpu_foreign_map[i],
			       &temp_foreign_map, &cpu_sibling_map[i]);
}

const struct plat_smp_ops *mp_ops;
EXPORT_SYMBOL(mp_ops);

void register_smp_ops(const struct plat_smp_ops *ops)
{
	if (mp_ops)
		printk(KERN_WARNING "Overriding previously set SMP ops\n");

	mp_ops = ops;
}

/*
 * First C code run on the secondary CPUs after being started up by
 * the master.
 */
asmlinkage void start_secondary(void)
{
	unsigned int cpu;

	sync_counter();
	cpu = raw_smp_processor_id();
	set_my_cpu_offset(per_cpu_offset(cpu));
	rcu_cpu_starting(cpu);

	cpu_probe();
	constant_clockevent_init();
	mp_ops->init_secondary();

	set_cpu_sibling_map(cpu);
	set_cpu_core_map(cpu);

	notify_cpu_starting(cpu);

	/* Notify boot CPU that we're starting */
	complete(&cpu_starting);

	/* The CPU is running, now mark it online */
	set_cpu_online(cpu, true);

	calculate_cpu_foreign_map();

	/*
	 * Notify boot CPU that we're up & online and it can safely return
	 * from __cpu_up
	 */
	complete(&cpu_running);

	/*
	 * irq will be enabled in ->smp_finish(), enabling it too early
	 * is dangerous.
	 */
	WARN_ON_ONCE(!irqs_disabled());
	mp_ops->smp_finish();

	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);
}

static void stop_this_cpu(void *dummy)
{
	/*
	 * Remove this CPU:
	 */

	set_cpu_online(smp_processor_id(), false);
	calculate_cpu_foreign_map();
	local_irq_disable();
	while (1);
}

void smp_send_stop(void)
{
	smp_call_function(stop_this_cpu, NULL, 0);
}

void __init smp_cpus_done(unsigned int max_cpus)
{
}

/* called from main before smp_init() */
void __init smp_prepare_cpus(unsigned int max_cpus)
{
	init_new_context(current, &init_mm);
	current_thread_info()->cpu = 0;
	mp_ops->prepare_cpus(max_cpus);
	set_cpu_sibling_map(0);
	set_cpu_core_map(0);
	calculate_cpu_foreign_map();
#ifndef CONFIG_HOTPLUG_CPU
	init_cpu_present(cpu_possible_mask);
#endif
}

/* Preload SMP state for boot cpu */
void smp_prepare_boot_cpu(void)
{
	unsigned int cpu, node, rr_node;

	set_cpu_possible(0, true);
	set_cpu_online(0, true);
	set_my_cpu_offset(per_cpu_offset(0));

	rr_node = first_node(node_online_map);
	for_each_possible_cpu(cpu) {
		node = early_cpu_to_node(cpu);

		/*
		 * The mapping between present cpus and nodes has been
		 * built during MADT and SRAT parsing.
		 *
		 * If possible cpus = present cpus here, early_cpu_to_node
		 * will return valid node.
		 *
		 * If possible cpus > present cpus here (e.g. some possible
		 * cpus will be added by cpu-hotplug later), for possible but
		 * not present cpus, early_cpu_to_node will return NUMA_NO_NODE,
		 * and we just map them to online nodes in round-robin way.
		 * Once hotplugged, new correct mapping will be built for them.
		 * */
		if (node != NUMA_NO_NODE)
			set_cpu_numa_node(cpu, node);
		else {
			set_cpu_numa_node(cpu, rr_node);
			rr_node = next_node_in(rr_node, node_online_map);
		}
	}
}

int __cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	int err;

	err = mp_ops->boot_secondary(cpu, tidle);
	if (err)
		return err;

	/* Wait for CPU to start and be ready to sync counters */
	if (!wait_for_completion_timeout(&cpu_starting,
					 msecs_to_jiffies(5000))) {
		pr_crit("CPU%u: failed to start\n", cpu);
		return -EIO;
	}

	/* Wait for CPU to finish startup & mark itself online before return */
	wait_for_completion(&cpu_running);
	return 0;
}

#ifdef CONFIG_PROFILING
/* Not really SMP stuff ... */
int setup_profiling_timer(unsigned int multiplier)
{
	return 0;
}
#endif

static void flush_tlb_all_ipi(void *info)
{
	local_flush_tlb_all();
}

void flush_tlb_all(void)
{
	on_each_cpu(flush_tlb_all_ipi, NULL, 1);
}

static void flush_tlb_mm_ipi(void *mm)
{
	local_flush_tlb_mm((struct mm_struct *)mm);
}

/*
 * Special Variant of smp_call_function for use by TLB functions:
 *
 *  o No return value
 *  o collapses to normal function call on UP kernels
 *  o collapses to normal function call on systems with a single shared
 *    primary cache.
 */
static inline void smp_on_other_tlbs(void (*func) (void *info), void *info)
{
	smp_call_function(func, info, 1);
}

static inline void smp_on_each_tlb(void (*func) (void *info), void *info)
{
	preempt_disable();

	smp_on_other_tlbs(func, info);
	func(info);

	preempt_enable();
}

/*
 * The following tlb flush calls are invoked when old translations are
 * being torn down, or pte attributes are changing. For single threaded
 * address spaces, a new context is obtained on the current cpu, and tlb
 * context on other cpus are invalidated to force a new context allocation
 * at switch_mm time, should the mm ever be used on other cpus. For
 * multithreaded address spaces, intercpu interrupts have to be sent.
 * Another case where intercpu interrupts are required is when the target
 * mm might be active on another cpu (eg debuggers doing the flushes on
 * behalf of debugees, kswapd stealing pages from another process etc).
 */

void flush_tlb_mm(struct mm_struct *mm)
{
	if (atomic_read(&mm->mm_users) == 0)
		return;		/* happens as a result of exit_mmap() */

	preempt_disable();

	if ((atomic_read(&mm->mm_users) != 1) || (current->mm != mm)) {
		on_each_cpu_mask(mm_cpumask(mm), flush_tlb_mm_ipi, mm, 1);
	} else {
		unsigned int cpu;

		for_each_online_cpu(cpu) {
			if (cpu != smp_processor_id() && cpu_context(cpu, mm))
				cpu_context(cpu, mm) = 0;
		}
		local_flush_tlb_mm(mm);
	}

	preempt_enable();
}

struct flush_tlb_data {
	struct vm_area_struct *vma;
	unsigned long addr1;
	unsigned long addr2;
};

static void flush_tlb_range_ipi(void *info)
{
	struct flush_tlb_data *fd = info;

	local_flush_tlb_range(fd->vma, fd->addr1, fd->addr2);
}

void flush_tlb_range(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	struct mm_struct *mm = vma->vm_mm;

	preempt_disable();
	if ((atomic_read(&mm->mm_users) != 1) || (current->mm != mm)) {
		struct flush_tlb_data fd = {
			.vma = vma,
			.addr1 = start,
			.addr2 = end,
		};

		on_each_cpu_mask(mm_cpumask(mm), flush_tlb_range_ipi, &fd, 1);
	} else {
		unsigned int cpu;

		for_each_online_cpu(cpu) {
			if (cpu != smp_processor_id() && cpu_context(cpu, mm))
				cpu_context(cpu, mm) = 0;
		}
		local_flush_tlb_range(vma, start, end);
	}
	preempt_enable();
}

static void flush_tlb_kernel_range_ipi(void *info)
{
	struct flush_tlb_data *fd = info;

	local_flush_tlb_kernel_range(fd->addr1, fd->addr2);
}

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	struct flush_tlb_data fd = {
		.addr1 = start,
		.addr2 = end,
	};

	on_each_cpu(flush_tlb_kernel_range_ipi, &fd, 1);
}

static void flush_tlb_page_ipi(void *info)
{
	struct flush_tlb_data *fd = info;

	local_flush_tlb_page(fd->vma, fd->addr1);
}

void flush_tlb_page(struct vm_area_struct *vma, unsigned long page)
{
	preempt_disable();
	if ((atomic_read(&vma->vm_mm->mm_users) != 1) || (current->mm != vma->vm_mm)) {
		struct flush_tlb_data fd = {
			.vma = vma,
			.addr1 = page,
		};

		on_each_cpu_mask(mm_cpumask(vma->vm_mm), flush_tlb_page_ipi, &fd, 1);
	} else {
		unsigned int cpu;

		for_each_online_cpu(cpu) {
			if (cpu != smp_processor_id() && cpu_context(cpu, vma->vm_mm))
				cpu_context(cpu, vma->vm_mm) = 0;
		}
		local_flush_tlb_page(vma, page);
	}
	preempt_enable();
}

static void flush_tlb_one_ipi(void *info)
{
	unsigned long vaddr = (unsigned long) info;

	local_flush_tlb_one(vaddr);
}

void flush_tlb_one(unsigned long vaddr)
{
	smp_on_each_tlb(flush_tlb_one_ipi, (void *) vaddr);
}

EXPORT_SYMBOL(flush_tlb_page);
EXPORT_SYMBOL(flush_tlb_one);
