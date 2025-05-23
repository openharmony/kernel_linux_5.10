// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2020, Jianmin Lv <lvjianmin@loongson.cn>
 *  Loongson Extend I/O Interrupt Vector support
 */

#define pr_fmt(fmt) "eiointc: " fmt

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/syscore_ops.h>

#define EIOINTC_REG_NODEMAP	0x14a0
#define EIOINTC_REG_IPMAP	0x14c0
#define EIOINTC_REG_ENABLE	0x1600
#define EIOINTC_REG_BOUNCE	0x1680
#define EIOINTC_REG_ISR		0x1800
#define EIOINTC_REG_ROUTE	0x1c00

#define VEC_REG_COUNT		4
#define VEC_COUNT_PER_REG	64
#define VEC_COUNT		(VEC_REG_COUNT * VEC_COUNT_PER_REG)
#define VEC_REG_IDX(irq_id)	((irq_id) / VEC_COUNT_PER_REG)
#define VEC_REG_BIT(irq_id)     ((irq_id) % VEC_COUNT_PER_REG)
#define EIOINTC_ALL_ENABLE	0xffffffff

#define MAX_EIO_NODES		(NR_CPUS / CORES_PER_EIO_NODE)

static int nr_pics;

struct eiointc_priv {
	u32			node;
	nodemask_t		node_map;
	cpumask_t		cpuspan_map;
	struct fwnode_handle	*domain_handle;
	struct irq_domain	*eiointc_domain;
};

static struct eiointc_priv *eiointc_priv[MAX_IO_PICS];

int eiointc_get_node(int id)
{
	return eiointc_priv[id]->node;
}

static int cpu_to_eio_node(int cpu)
{
	return cpu_logical_map(cpu) / CORES_PER_EIO_NODE;
}

static unsigned int cpumask_nth(unsigned int idx, const struct cpumask *srcp)
{
	int cpu;

	for_each_cpu(cpu, srcp)
		if (idx-- == 0)
			return cpu;

	BUG();
}

static void eiointc_set_irq_route(int pos, unsigned int cpu, unsigned int mnode, nodemask_t *node_map)
{
	int i, node, cpu_node, route_node;
	unsigned char coremap[MAX_EIO_NODES];
	uint32_t pos_off, data, data_byte, data_mask;

	pos_off = pos & ~3;
	data_byte = pos & 3;
	data_mask = ~BIT_MASK(data_byte) & 0xf;

	memset(coremap, 0, sizeof(unsigned char) * MAX_EIO_NODES);

	/* Calculate node and coremap of target irq */
	cpu_node = cpu_logical_map(cpu) / CORES_PER_EIO_NODE;
	coremap[cpu_node] |= BIT(cpu_logical_map(cpu) % CORES_PER_EIO_NODE);

	for_each_online_cpu(i) {
		node = cpu_to_eio_node(i);
		if (!node_isset(node, *node_map))
			continue;

		/* EIO node 0 is in charge of inter-node interrupt dispatch */
		route_node = (node == mnode) ? cpu_node : node;
		data = ((coremap[node] | (route_node << 4)) << (data_byte * 8));
		csr_any_send(EIOINTC_REG_ROUTE + pos_off, data, data_mask, node * CORES_PER_EIO_NODE);
	}
}

#ifdef CONFIG_LOONGARCH
static void virt_eiointc_set_irq_route(int pos, unsigned int cpu)
{
	iocsr_write8(cpu_logical_map(cpu), EIOINTC_REG_ROUTE + pos);
}
#endif

static DEFINE_RAW_SPINLOCK(affinity_lock);

static int eiointc_set_irq_affinity(struct irq_data *d, const struct cpumask *affinity, bool force)
{
	unsigned int cpu;
	unsigned long flags;
	uint32_t vector, regaddr;
	struct cpumask online_affinity;
	struct cpumask intersect_affinity;
	struct eiointc_priv *priv = d->domain->host_data;

	if (!IS_ENABLED(CONFIG_SMP))
		return -EPERM;

	raw_spin_lock_irqsave(&affinity_lock, flags);

	cpumask_and(&online_affinity, affinity, cpu_online_mask);
	if (cpumask_empty(&online_affinity)) {
		raw_spin_unlock_irqrestore(&affinity_lock, flags);
		return -EINVAL;
	}
	cpumask_and(&intersect_affinity, &online_affinity, &priv->cpuspan_map);

	if (!cpumask_empty(&intersect_affinity))
		cpu = cpumask_first(&intersect_affinity);
	else {
		int c, idx = 0;
		struct cpumask complement_map;
		struct cpumask cpuspan_online_map;

		cpu = cpumask_first(&online_affinity);
		cpumask_complement(&complement_map, &priv->cpuspan_map);
		cpumask_and(&cpuspan_online_map, &priv->cpuspan_map, cpu_online_mask);

		for_each_cpu(c, &complement_map) {
			if (c == cpu) break;
			idx++;
		}

		idx = idx % cpumask_weight(&cpuspan_online_map);
		cpu = cpumask_nth(idx, &cpuspan_online_map);
	}

	if (!d->parent_data)
		vector = d->hwirq;
	else
		vector = d->parent_data->hwirq;

	regaddr = EIOINTC_REG_ENABLE + ((vector >> 5) << 2);

	if (!cpu_has_hypervisor) {
		/* Mask target vector */
		csr_any_send(regaddr, EIOINTC_ALL_ENABLE & (~BIT(vector & 0x1F)),
				0x0, priv->node * CORES_PER_EIO_NODE);
		/* Set route for target vector */
		eiointc_set_irq_route(vector, cpu, priv->node, &priv->node_map);
		/* Unmask target vector */
		csr_any_send(regaddr, EIOINTC_ALL_ENABLE,
				0x0, priv->node * CORES_PER_EIO_NODE);
	} else {
		iocsr_write32(EIOINTC_ALL_ENABLE & (~((1 << (vector & 0x1F)))), regaddr);
		virt_eiointc_set_irq_route(vector, cpu);
		iocsr_write32(EIOINTC_ALL_ENABLE, regaddr);
	}

	irq_data_update_effective_affinity(d, cpumask_of(cpu));

	raw_spin_unlock_irqrestore(&affinity_lock, flags);

	return IRQ_SET_MASK_OK;
}

static int eiointc_index(int node)
{
	int i;

	for (i = 0; i < nr_pics; i++) {
		if (node_isset(node, eiointc_priv[i]->node_map))
			return i;
	}

	return -1;
}

static int eiointc_router_init(unsigned int cpu)
{
	int i, bit;
	int node = cpu_to_eio_node(cpu);
	int index = eiointc_index(node);
	uint32_t data;

	if (index < 0) {
		pr_err("Error: invalid nodemap!\n");
		return -1;
	}

	if ((cpu_logical_map(cpu) % CORES_PER_EIO_NODE) == 0) {
		eiointc_enable();

		for (i = 0; i < VEC_COUNT / 32; i++) {
			data = (((1 << (i * 2 + 1)) << 16) | (1 << (i * 2)));
			iocsr_write32(data, EIOINTC_REG_NODEMAP + i * 4);
		}

		for (i = 0; i < VEC_COUNT / 32 / 4; i++) {
			bit = BIT(1 + index); /* Route to IP[1 + index] */
			data = bit | (bit << 8) | (bit << 16) | (bit << 24);
			iocsr_write32(data, EIOINTC_REG_IPMAP + i * 4);
		}

		for (i = 0; i < VEC_COUNT / 4; i++) {
			/* Route to Node-0 Core-0 */
			if (index == 0)
				bit = BIT(cpu_logical_map(0));
			else
				bit = (eiointc_priv[index]->node << 4) | 1;
			if (cpu_has_hypervisor)
				bit = cpu_logical_map(0);

			data = bit | (bit << 8) | (bit << 16) | (bit << 24);
			iocsr_write32(data, EIOINTC_REG_ROUTE + i * 4);
		}

		for (i = 0; i < VEC_COUNT / 32; i++) {
			data = 0xffffffff;
			iocsr_write32(data, EIOINTC_REG_ENABLE + i * 4);
			iocsr_write32(data, EIOINTC_REG_BOUNCE + i * 4);
		}
	}

	return 0;
}

static void eiointc_irq_dispatch(struct irq_desc *desc)
{
	int i;
	u64 pending;
	bool handled = false;
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct eiointc_priv *priv = irq_desc_get_handler_data(desc);

	chained_irq_enter(chip, desc);

	for (i = 0; i < VEC_REG_COUNT; i++) {
		pending = iocsr_read64(EIOINTC_REG_ISR + (i << 3));
		iocsr_write64(pending, EIOINTC_REG_ISR + (i << 3));
		while (pending) {
			int bit = __ffs(pending);
			int virq = irq_linear_revmap(priv->eiointc_domain, bit + VEC_COUNT_PER_REG * i);

			generic_handle_irq(virq);
			pending &= ~BIT(bit);
			handled = true;
		}
	}

	if (!handled)
		spurious_interrupt();

	chained_irq_exit(chip, desc);
}

static void eiointc_ack_irq(struct irq_data *d)
{
	if (d->parent_data)
		irq_chip_ack_parent(d);
}

static void eiointc_mask_irq(struct irq_data *d)
{
	if (d->parent_data)
		irq_chip_mask_parent(d);
}

static void eiointc_unmask_irq(struct irq_data *d)
{
	if (d->parent_data)
		irq_chip_unmask_parent(d);
}

static struct irq_chip eiointc_irq_chip = {
	.name			= "EIOINTC",
	.irq_ack		= eiointc_ack_irq,
	.irq_mask		= eiointc_mask_irq,
	.irq_unmask		= eiointc_unmask_irq,
	.irq_set_affinity	= eiointc_set_irq_affinity,
};

static int eiointc_domain_alloc(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
	int ret;
	unsigned int i, type;
	unsigned long hwirq = 0;
	struct eiointc *priv = domain->host_data;

	ret = irq_domain_translate_onecell(domain, arg, &hwirq, &type);
	if (ret < 0)
		return -EINVAL;

	if (hwirq >= IOCSR_EXTIOI_VECTOR_NUM)
		return -EINVAL;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, hwirq + i, &eiointc_irq_chip,
					priv, handle_edge_irq, NULL, NULL);
	}

	return 0;
}

static void eiointc_domain_free(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);

		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static const struct irq_domain_ops eiointc_domain_ops = {
	.translate	= irq_domain_translate_onecell,
	.alloc		= eiointc_domain_alloc,
	.free		= eiointc_domain_free,
};

static int eiointc_suspend(void)
{
	return 0;
}

static void eiointc_resume(void)
{
	int i, j;
	struct irq_desc *desc;
	struct irq_data *irq_data;

	eiointc_router_init(0);

	for (i = 0; i < nr_pics; i++) {
		for (j = 0; j < VEC_COUNT; j++) {
			desc = irq_to_desc(irq_find_mapping(eiointc_priv[i]->eiointc_domain, j));
			if (desc && desc->handle_irq && desc->handle_irq != handle_bad_irq) {
				raw_spin_lock(&desc->lock);
				irq_data = irq_domain_get_irq_data(eiointc_priv[i]->eiointc_domain, irq_desc_get_irq(desc));
				if (irq_data) eiointc_set_irq_affinity(irq_data, irq_data->common->affinity, 0);
				raw_spin_unlock(&desc->lock);
			}
		}
	}
}

static struct syscore_ops eiointc_syscore_ops = {
	.suspend = eiointc_suspend,
	.resume = eiointc_resume,
};

struct irq_domain *eiointc_acpi_init(struct irq_domain *parent,
				     struct acpi_madt_eio_pic *acpi_eiointc)
{
	int i, parent_irq;
	unsigned long node_map;
	struct eiointc_priv *priv;

	if (!acpi_eiointc)
		return NULL;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->domain_handle = irq_domain_alloc_fwnode((phys_addr_t *)acpi_eiointc);
	if (!priv->domain_handle) {
		pr_err("Unable to allocate domain handle\n");
		goto out_free_priv;
	}

	priv->node = acpi_eiointc->node;
	node_map = acpi_eiointc->node_map ? : -1ULL;

	for_each_possible_cpu(i) {
		if (node_map & (1ULL << cpu_to_eio_node(i))) {
			node_set(cpu_to_eio_node(i), priv->node_map);
			cpumask_or(&priv->cpuspan_map, &priv->cpuspan_map, cpumask_of(i));
		}
	}

	/* Setup IRQ domain */
	priv->eiointc_domain = irq_domain_create_linear(priv->domain_handle, VEC_COUNT,
					&eiointc_domain_ops, priv);
	if (!priv->eiointc_domain) {
		pr_err("loongson-eiointc: cannot add IRQ domain\n");
		goto out_free_priv;
	}

	eiointc_priv[nr_pics++] = priv;

	eiointc_router_init(0);

	parent_irq = irq_create_mapping(parent, acpi_eiointc->cascade);
	irq_set_chained_handler_and_data(parent_irq, eiointc_irq_dispatch, priv);

	register_syscore_ops(&eiointc_syscore_ops);
	cpuhp_setup_state_nocalls(CPUHP_AP_IRQ_LOONGARCH_STARTING,
				  "irqchip/loongarch/intc:starting",
				  eiointc_router_init, NULL);

	return irq_find_matching_fwnode(priv->domain_handle, DOMAIN_BUS_ANY);

out_free_priv:
	priv->domain_handle = NULL;
	kfree(priv);

	return NULL;
}
