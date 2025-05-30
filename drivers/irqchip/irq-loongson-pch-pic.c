// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2020, Jiaxun Yang <jiaxun.yang@flygoat.com>
 *			Jianmin Lv <lvjianmin@loongson.cn>
 *			Huacai Chen <chenhuacai@loongson.cn>
 *  Loongson PCH PIC support
 */

#define pr_fmt(fmt) "pch-pic: " fmt

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/syscore_ops.h>

/* Registers */
#define PCH_PIC_MASK		0x20
#define PCH_PIC_HTMSI_EN	0x40
#define PCH_PIC_EDGE		0x60
#define PCH_PIC_CLR		0x80
#define PCH_PIC_AUTO0		0xc0
#define PCH_PIC_AUTO1		0xe0
#define PCH_INT_ROUTE(irq)	(0x100 + irq)
#define PCH_INT_HTVEC(irq)	(0x200 + irq)
#define PCH_PIC_POL		0x3e0

#define PIC_COUNT_PER_REG	32
#define PIC_REG_COUNT		2
#define PIC_COUNT		(PIC_COUNT_PER_REG * PIC_REG_COUNT)
#define PIC_REG_IDX(irq_id)	((irq_id) / PIC_COUNT_PER_REG)
#define PIC_REG_BIT(irq_id)	((irq_id) % PIC_COUNT_PER_REG)
#define PCH_PIC_SIZE		0x400

static int nr_pics;

struct pch_pic {
	void __iomem		*base;
	struct irq_domain	*pic_domain;
	struct fwnode_handle	*domain_handle;
	u32			ht_vec_base;
	raw_spinlock_t		pic_lock;
	u32			saved_vec_en[PIC_REG_COUNT];
	u32			saved_vec_pol[PIC_REG_COUNT];
	u32			saved_vec_edge[PIC_REG_COUNT];
};

static struct pch_pic *pch_pic_priv[MAX_IO_PICS];

static void pch_pic_bitset(struct pch_pic *priv, int offset, int bit)
{
	u32 reg;
	void __iomem *addr = priv->base + offset + PIC_REG_IDX(bit) * 4;

	raw_spin_lock(&priv->pic_lock);
	reg = readl(addr);
	reg |= BIT(PIC_REG_BIT(bit));
	writel(reg, addr);
	raw_spin_unlock(&priv->pic_lock);
}

static void pch_pic_bitclr(struct pch_pic *priv, int offset, int bit)
{
	u32 reg;
	void __iomem *addr = priv->base + offset + PIC_REG_IDX(bit) * 4;

	raw_spin_lock(&priv->pic_lock);
	reg = readl(addr);
	reg &= ~BIT(PIC_REG_BIT(bit));
	writel(reg, addr);
	raw_spin_unlock(&priv->pic_lock);
}

static void pch_pic_mask_irq(struct irq_data *d)
{
	struct pch_pic *priv = irq_data_get_irq_chip_data(d);

	pch_pic_bitset(priv, PCH_PIC_MASK, d->hwirq);
	irq_chip_mask_parent(d);
}

static void pch_pic_unmask_irq(struct irq_data *d)
{
	struct pch_pic *priv = irq_data_get_irq_chip_data(d);

	writel(BIT(PIC_REG_BIT(d->hwirq)),
			priv->base + PCH_PIC_CLR + PIC_REG_IDX(d->hwirq) * 4);

	irq_chip_unmask_parent(d);
	pch_pic_bitclr(priv, PCH_PIC_MASK, d->hwirq);
}

static int pch_pic_set_type(struct irq_data *d, unsigned int type)
{
	struct pch_pic *priv = irq_data_get_irq_chip_data(d);
	int ret = 0;

	switch (type) {
	case IRQ_TYPE_EDGE_RISING:
		pch_pic_bitset(priv, PCH_PIC_EDGE, d->hwirq);
		pch_pic_bitclr(priv, PCH_PIC_POL, d->hwirq);
		irq_set_handler_locked(d, handle_edge_irq);
		break;
	case IRQ_TYPE_EDGE_FALLING:
		pch_pic_bitset(priv, PCH_PIC_EDGE, d->hwirq);
		pch_pic_bitset(priv, PCH_PIC_POL, d->hwirq);
		irq_set_handler_locked(d, handle_edge_irq);
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		pch_pic_bitclr(priv, PCH_PIC_EDGE, d->hwirq);
		pch_pic_bitclr(priv, PCH_PIC_POL, d->hwirq);
		irq_set_handler_locked(d, handle_level_irq);
		break;
	case IRQ_TYPE_LEVEL_LOW:
		pch_pic_bitclr(priv, PCH_PIC_EDGE, d->hwirq);
		pch_pic_bitset(priv, PCH_PIC_POL, d->hwirq);
		irq_set_handler_locked(d, handle_level_irq);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static void pch_pic_ack_irq(struct irq_data *d)
{
	unsigned int reg;
	struct pch_pic *priv = irq_data_get_irq_chip_data(d);

	reg = readl(priv->base + PCH_PIC_EDGE + PIC_REG_IDX(d->hwirq) * 4);
	if (reg & BIT(PIC_REG_BIT(d->hwirq))) {
		writel(BIT(PIC_REG_BIT(d->hwirq)),
			priv->base + PCH_PIC_CLR + PIC_REG_IDX(d->hwirq) * 4);
	}
	irq_chip_ack_parent(d);
}

static struct irq_chip pch_pic_irq_chip = {
	.name			= "PCH PIC",
	.irq_mask		= pch_pic_mask_irq,
	.irq_unmask		= pch_pic_unmask_irq,
	.irq_ack		= pch_pic_ack_irq,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_set_type		= pch_pic_set_type,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

static int pch_pic_alloc(struct irq_domain *domain, unsigned int virq,
			      unsigned int nr_irqs, void *arg)
{
	int err;
	unsigned int type;
	unsigned long hwirq;
	struct irq_fwspec *fwspec = arg;
	struct irq_fwspec parent_fwspec;
	struct pch_pic *priv = domain->host_data;

	err = irq_domain_translate_twocell(domain, fwspec, &hwirq, &type);
	if (err)
		return err;

	parent_fwspec.fwnode = domain->parent->fwnode;
	parent_fwspec.param_count = 1;
	parent_fwspec.param[0] = hwirq + priv->ht_vec_base;

	err = irq_domain_alloc_irqs_parent(domain, virq, 1, &parent_fwspec);
	if (err)
		return err;

	irq_domain_set_info(domain, virq, hwirq,
			    &pch_pic_irq_chip, priv,
			    handle_level_irq, NULL, NULL);
	irq_set_probe(virq);

	return 0;
}

static const struct irq_domain_ops pch_pic_domain_ops = {
	.translate	= irq_domain_translate_twocell,
	.alloc		= pch_pic_alloc,
	.free		= irq_domain_free_irqs_parent,
};

static void pch_pic_reset(struct pch_pic *priv)
{
	int i;

	for (i = 0; i < PIC_COUNT; i++) {
		/* Write vector ID */
		writeb(priv->ht_vec_base + i, priv->base + PCH_INT_HTVEC(i));
		/* Hardcode route to HT0 Lo */
		writeb(1, priv->base + PCH_INT_ROUTE(i));
	}

	for (i = 0; i < PIC_REG_COUNT; i++) {
		/* Clear IRQ cause registers, mask all interrupts */
		writel_relaxed(0xFFFFFFFF, priv->base + PCH_PIC_MASK + 4 * i);
		writel_relaxed(0xFFFFFFFF, priv->base + PCH_PIC_CLR + 4 * i);
		/* Clear auto bounce, we don't need that */
		writel_relaxed(0, priv->base + PCH_PIC_AUTO0 + 4 * i);
		writel_relaxed(0, priv->base + PCH_PIC_AUTO1 + 4 * i);
		/* Enable HTMSI transformer */
		writel_relaxed(0xFFFFFFFF, priv->base + PCH_PIC_HTMSI_EN + 4 * i);
	}
}

static int pch_pic_suspend(void)
{
	int i, j;

	for (i = 0; i < nr_pics; i++) {
		for (j = 0; j < PIC_REG_COUNT; j++) {
			pch_pic_priv[i]->saved_vec_pol[j] =
				readl(pch_pic_priv[i]->base + PCH_PIC_POL + 4 * j);
			pch_pic_priv[i]->saved_vec_edge[j] =
				readl(pch_pic_priv[i]->base + PCH_PIC_EDGE + 4 * j);
			pch_pic_priv[i]->saved_vec_en[j] =
				readl(pch_pic_priv[i]->base + PCH_PIC_MASK + 4 * j);
		}
	}

	return 0;
}

static void pch_pic_resume(void)
{
	int i, j;

	for (i = 0; i < nr_pics; i++) {
		pch_pic_reset(pch_pic_priv[i]);
		for (j = 0; j < PIC_REG_COUNT; j++) {
			writel(pch_pic_priv[i]->saved_vec_pol[j],
					pch_pic_priv[i]->base + PCH_PIC_POL + 4 * j);
			writel(pch_pic_priv[i]->saved_vec_edge[j],
					pch_pic_priv[i]->base + PCH_PIC_EDGE + 4 * j);
			writel(pch_pic_priv[i]->saved_vec_en[j],
					pch_pic_priv[i]->base + PCH_PIC_MASK + 4 * j);
		}
	}
}

static struct syscore_ops pch_pic_syscore_ops = {
	.suspend =  pch_pic_suspend,
	.resume =  pch_pic_resume,
};

static int pch_pic_init(phys_addr_t addr, unsigned long size, int vec_base,
			struct irq_domain *parent_domain, struct fwnode_handle *domain_handle)
{
	int vec_count;
	struct pch_pic *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	raw_spin_lock_init(&priv->pic_lock);
	priv->base = ioremap(addr, size);
	if (!priv->base)
		goto free_priv;

	priv->domain_handle = domain_handle;

	priv->ht_vec_base = vec_base;
	vec_count = ((readq(priv->base) >> 48) & 0xff) + 1;

	priv->pic_domain = irq_domain_create_hierarchy(parent_domain, 0,
						vec_count, priv->domain_handle,
						&pch_pic_domain_ops, priv);

	if (!priv->pic_domain) {
		pr_err("Failed to create IRQ domain\n");
		goto iounmap_base;
	}

	pch_pic_reset(priv);
	pch_pic_priv[nr_pics++] = priv;

	register_syscore_ops(&pch_pic_syscore_ops);

	return 0;

iounmap_base:
	iounmap(priv->base);
free_priv:
	kfree(priv);

	return -EINVAL;
}

#ifdef CONFIG_OF

static int pch_pic_of_init(struct device_node *node,
				struct device_node *parent)
{
	int err, vec_base;
	struct resource res;
	struct irq_domain *parent_domain;

	if (of_address_to_resource(node, 0, &res))
		return -EINVAL;

	parent_domain = irq_find_host(parent);
	if (!parent_domain) {
		pr_err("Failed to find the parent domain\n");
		return -ENXIO;
	}

	if (of_property_read_u32(node, "loongson,pic-base-vec", &vec_base)) {
		pr_err("Failed to determine pic-base-vec\n");
		return -EINVAL;
	}

	err = pch_pic_init(res.start, resource_size(&res), vec_base,
				parent_domain, of_node_to_fwnode(node));
	if (err < 0)
		return err;

	return 0;
}

IRQCHIP_DECLARE(pch_pic, "loongson,pch-pic-1.0", pch_pic_of_init);

#endif

#ifdef CONFIG_ACPI

struct irq_domain *pch_pic_acpi_init(struct irq_domain *parent,
					struct acpi_madt_bio_pic *acpi_pchpic)
{
	int ret, vec_base;
	struct fwnode_handle *domain_handle;

	if (!acpi_pchpic)
		return NULL;

	vec_base = acpi_pchpic->gsi_base - GSI_MIN_PCH_IRQ;

	domain_handle = irq_domain_alloc_fwnode((phys_addr_t *)acpi_pchpic);
	if (!domain_handle) {
		pr_err("Unable to allocate domain handle\n");
		return NULL;
	}

	ret = pch_pic_init(acpi_pchpic->address, acpi_pchpic->size,
				vec_base, parent, domain_handle);
	if (ret < 0)
		return NULL;

	return irq_find_matching_fwnode(domain_handle, DOMAIN_BUS_ANY);
}

#endif
