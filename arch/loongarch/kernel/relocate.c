// SPDX-License-Identifier: GPL-2.0
/*
 * Support for Kernel relocation at boot time
 *
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 * Authors: Huacai Chen (chenhuacai@loongson.cn)
 */
#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/start_kernel.h>
#include <linux/of_fdt.h>
#include <linux/printk.h>
#include <asm/bootinfo.h>
#include <asm/io.h>
#include <asm/inst.h>
#include <asm/sections.h>

#define RELOCATED(x) ((void *)((long)x + offset))

extern u32 _relocation_start[];	/* End kernel image / start relocation table */
extern u32 _relocation_end[];	/* End relocation table */

static void __init apply_r_loongarch_32_rel(u32 *loc_new, long offset)
{
	*loc_new += offset;
}

static void __init apply_r_loongarch_64_rel(u32 *loc_new, long offset)
{
	*(u64 *)loc_new += offset;
}

/*
 * The details about la.abs $r1, x on LoongArch
 *
 * lu12i.w $r1, 0
 * ori     $r1, $r1, 0x0
 * lu32i.d $r1, 0
 * lu52i.d $r1, $r1, 0
 *
 * LoongArch use lu12i.w, ori, lu32i.d, lu52i.d to load a 64bit imm.
 * lu12i.w load bit31~bit12, ori load bit11~bit0,
 * lu32i.d load bit51~bit32, lu52i.d load bit63~bit52
 */
static void __init apply_r_loongarch_mark_la_rel(u32 *loc_new, long offset)
{
	unsigned long long dest;
	union loongarch_instruction *ori, *lu12iw, *lu32id, *lu52id;

	ori = (union loongarch_instruction *)&loc_new[1];
	lu12iw = (union loongarch_instruction *)&loc_new[0];
	lu32id = (union loongarch_instruction *)&loc_new[2];
	lu52id = (union loongarch_instruction *)&loc_new[3];

	dest = ori->reg2ui12_format.simmediate & 0xfff;
	dest |= (lu12iw->reg1i20_format.simmediate & 0xfffff) << 12;
	dest |= ((u64)lu32id->reg1i20_format.simmediate & 0xfffff) << 32;
	dest |= ((u64)lu52id->reg2i12_format.simmediate & 0xfff) << 52;
	dest += offset;

	ori->reg2ui12_format.simmediate = dest & 0xfff;
	lu12iw->reg1i20_format.simmediate = (dest >> 12) & 0xfffff;
	lu32id->reg1i20_format.simmediate = (dest >> 32) & 0xfffff;
	lu52id->reg2i12_format.simmediate = (dest >> 52) & 0xfff;
}

static void (*reloc_handlers_rel[]) (u32 *, long) __initdata = {
	[R_LARCH_32]		= apply_r_loongarch_32_rel,
	[R_LARCH_64]		= apply_r_loongarch_64_rel,
	[R_LARCH_MARK_LA]	= apply_r_loongarch_mark_la_rel,
};

static int __init do_relocations(void *kbase_old, void *kbase_new, long offset)
{
	int type;
	u32 *r;
	u32 *loc_new;
	u32 *loc_orig;

	for (r = _relocation_start; r < _relocation_end; r++) {
		/* Sentinel for last relocation */
		if (*r == 0)
			break;

		type = (*r >> 24) & 0xff;
		loc_orig = (void *)(kbase_old + ((*r & 0x00ffffff) << 2));
		loc_new = RELOCATED(loc_orig);

		if (reloc_handlers_rel[type] == NULL) {
			/* Unsupported relocation */
			pr_err("Unhandled relocation type %d at 0x%pK\n",
			       type, loc_orig);
			return -ENOEXEC;
		}

		reloc_handlers_rel[type](loc_new, offset);
	}

	return 0;
}

#ifdef CONFIG_RANDOMIZE_BASE

static inline __init unsigned long rotate_xor(unsigned long hash,
					      const void *area, size_t size)
{
	size_t i, diff;
	const typeof(hash) *ptr = PTR_ALIGN(area, sizeof(hash));

	diff = (void *)ptr - area;
	if (unlikely(size < diff + sizeof(hash)))
		return hash;

	size = ALIGN_DOWN(size - diff, sizeof(hash));

	for (i = 0; i < size / sizeof(hash); i++) {
		/* Rotate by odd number of bits and XOR. */
		hash = (hash << ((sizeof(hash) * 8) - 7)) | (hash >> 7);
		hash ^= ptr[i];
	}

	return hash;
}

static inline __init unsigned long get_random_boot(void)
{
	unsigned long hash = 0;
	unsigned long entropy = random_get_entropy();

	/* Attempt to create a simple but unpredictable starting entropy. */
	hash = rotate_xor(hash, linux_banner, strlen(linux_banner));

	/* Add in any runtime entropy we can get */
	hash = rotate_xor(hash, &entropy, sizeof(entropy));

	return hash;
}

static inline __init bool kaslr_disabled(void)
{
	char *str;

	const char *builtin_cmdline = CONFIG_CMDLINE;

	str = strstr(builtin_cmdline, "nokaslr");
	if (str == builtin_cmdline ||
	    (str > builtin_cmdline && *(str - 1) == ' '))
		return true;

	str = strstr(boot_command_line, "nokaslr");
	if (str == boot_command_line || (str > boot_command_line && *(str - 1) == ' '))
		return true;

	return false;
}

static inline void __init *determine_relocation_address(void)
{
	/* Choose a new address for the kernel */
	unsigned long kernel_length;
	void *dest = &_text;
	unsigned long offset;

	if (kaslr_disabled())
		return dest;

	kernel_length = (long)_end - (long)(&_text);

	offset = get_random_boot() << 16;
	offset &= (CONFIG_RANDOMIZE_BASE_MAX_OFFSET - 1);
	if (offset < kernel_length)
		offset += ALIGN(kernel_length, 0xffff);

	return RELOCATED(dest);
}

#else

static inline void __init *determine_relocation_address(void)
{
	/*
	 * Choose a new address for the kernel
	 * For now we'll hard code the destination
	 */
	return (void *)(CACHE_BASE + 0x02000000);
}

#endif

static inline int __init relocation_addr_valid(void *loc_new)
{
	if ((unsigned long)loc_new & 0x00000ffff)
		return 0; /* Inappropriately aligned new location */

	if ((unsigned long)loc_new < (unsigned long)_end)
		return 0; /* New location overlaps original kernel */

	return 1;
}

static inline void __init update_kaslr_offset(unsigned long *addr, long offset)
{
	unsigned long *new_addr = (unsigned long *)RELOCATED(addr);

	*new_addr = (unsigned long)offset;
}

void *__init relocate_kernel(void)
{
	void *loc_new;
	unsigned long kernel_length;
	unsigned long bss_length;
	long offset = 0;
	int res = 1;
	/* Default to original kernel entry point */
	void *kernel_entry = start_kernel;

	early_init_dt_scan(early_ioremap(fw_arg1, SZ_64K));

	kernel_length = (long)(&_relocation_start) - (long)(&_text);
	bss_length = (long)&__bss_stop - (long)&__bss_start;

	loc_new = determine_relocation_address();

	/* Sanity check relocation address */
	if (relocation_addr_valid(loc_new))
		offset = (unsigned long)loc_new - (unsigned long)(&_text);

	if (offset) {
		/* Copy the kernel to it's new location */
		memcpy(loc_new, &_text, kernel_length);

		/* Perform relocations on the new kernel */
		res = do_relocations(&_text, loc_new, offset);
		if (res < 0)
			goto out;

		/* Sync the caches ready for execution of new kernel */
		asm volatile (
		"	ibar 0					\n"
		"	dbar 0					\n");

		/*
		 * The original .bss has already been cleared, and
		 * some variables such as command line parameters
		 * stored to it so make a copy in the new location.
		 */
		memcpy(RELOCATED(&__bss_start), &__bss_start, bss_length);

		/* The current thread is now within the relocated image */
		__current_thread_info = RELOCATED(__current_thread_info);

		/* Return the new kernel's entry point */
		kernel_entry = RELOCATED(start_kernel);

		update_kaslr_offset(&__kaslr_offset, offset);
	}
out:
	return kernel_entry;
}

/*
 * Show relocation information on panic.
 */
void show_kernel_relocation(const char *level)
{
	if (__kaslr_offset > 0) {
		printk(level);
		pr_cont("Kernel relocated by 0x%pK\n", (void *)__kaslr_offset);
		pr_cont(" .text @ 0x%pK\n", _text);
		pr_cont(" .data @ 0x%pK\n", _sdata);
		pr_cont(" .bss  @ 0x%pK\n", __bss_start);
	}
}

static int kernel_location_notifier_fn(struct notifier_block *self,
				       unsigned long v, void *p)
{
	show_kernel_relocation(KERN_EMERG);
	return NOTIFY_DONE;
}

static struct notifier_block kernel_location_notifier = {
	.notifier_call = kernel_location_notifier_fn
};

static int __init register_kernel_offset_dumper(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &kernel_location_notifier);
	return 0;
}
__initcall(register_kernel_offset_dumper);
