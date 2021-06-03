/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/sizes.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>

#define PAGE_SIZE _PAGE_SIZE
#define RO_EXCEPTION_TABLE_ALIGN	4
#define RUNTIME_DISCARD_EXIT

/*
 * Put .bss..swapper_pg_dir as the first thing in .bss. This will
 * ensure that it has .bss alignment (64K).
 */
#define BSS_FIRST_SECTIONS *(.bss..swapper_pg_dir)

#include <asm-generic/vmlinux.lds.h>

OUTPUT_ARCH(loongarch)
ENTRY(kernel_entry)
PHDRS {
	text PT_LOAD FLAGS(7);	/* RWX */
	note PT_NOTE FLAGS(4);	/* R__ */
}

jiffies	 = jiffies_64;

SECTIONS
{
	. = VMLINUX_LOAD_ADDRESS;
	/* Read-only */
	_text = .;	/* Text and read-only data */
	.text : {
		TEXT_TEXT
		SCHED_TEXT
		CPUIDLE_TEXT
		LOCK_TEXT
		KPROBES_TEXT
		IRQENTRY_TEXT
		SOFTIRQENTRY_TEXT
		*(.fixup)
		*(.gnu.warning)
	} :text = 0
	_etext = .;	/* End of text section */

	/*
	 * struct alt_inst entries. From the header (alternative.h):
	 * "Alternative instructions for different CPU types or capabilities"
	 * Think locking instructions on spinlocks.
	 */
	. = ALIGN(4);
	.altinstructions : AT(ADDR(.altinstructions) - LOAD_OFFSET) {
		__alt_instructions = .;
		*(.altinstructions)
		__alt_instructions_end = .;
	}

	.got : ALIGN(16) { *(.got) }
	.plt : ALIGN(16) { *(.plt) }
	.got.plt : ALIGN(16) { *(.got.plt) }

	_sdata = .;			/* Start of data section */
	RO_DATA(4096)
	RW_DATA(1 << CONFIG_L1_CACHE_SHIFT, PAGE_SIZE, THREAD_SIZE)

	/* We want the small data sections together, so single-instruction offsets
	   can access them all, and initialized data all before uninitialized, so
	   we can shorten the on-disk segment size.  */
	.sdata : {
		*(.sdata)
	}
	_edata =  .;			/* End of data section */

	/* Will be freed after init */
	. = ALIGN(PAGE_SIZE);		/* Init code and data */
	__init_begin = .;
	INIT_TEXT_SECTION(PAGE_SIZE)
	INIT_DATA_SECTION(16)

	. = ALIGN(4);

	/* .exit.text is discarded at runtime, not link time, to deal with
	 * references from .rodata
	 */
	.exit.text : {
		EXIT_TEXT
	}
	.exit.data : {
		EXIT_DATA
	}
#ifdef CONFIG_SMP
	PERCPU_SECTION(1 << CONFIG_L1_CACHE_SHIFT)
#endif

	.rela.dyn : ALIGN(8) { *(.rela.dyn) *(.rela*) }

#ifdef CONFIG_RELOCATABLE
	. = ALIGN(4);

	.data.reloc : {
		_relocation_start = .;
		/*
		 * Space for relocation table
		 * This needs to be filled so that the
		 * relocs tool can overwrite the content.
		 * An invalid value is left at the start of the
		 * section to abort relocation if the table
		 * has not been filled in.
		 */
		LONG(0xFFFFFFFF);
		FILL(0);
		. += CONFIG_RELOCATION_TABLE_SIZE - 4;
		_relocation_end = .;
	}
#endif

	/*
	 * Align to 64K in attempt to eliminate holes before the
	 * .bss..swapper_pg_dir section at the start of .bss.  This
	 * also satisfies PAGE_SIZE alignment as the largest page size
	 * allowed is 64K.
	 */
	. = ALIGN(0x10000);
	__init_end = .;
	/* freed after init ends here */

	/*
	 * Force .bss to 64K alignment so that .bss..swapper_pg_dir
	 * gets that alignment.	 .sbss should be empty, so there will be
	 * no holes after __init_end. */
	BSS_SECTION(0, 0x10000, 8)

	_end = . ;

	STABS_DEBUG
	DWARF_DEBUG
	ELF_DETAILS

	/* These must appear regardless of  .  */
	.gptab.sdata : {
		*(.gptab.data)
		*(.gptab.sdata)
	}
	.gptab.sbss : {
		*(.gptab.bss)
		*(.gptab.sbss)
	}

	/* Sections to be discarded */
	DISCARDS
	/DISCARD/ : {
		*(.gnu.attributes)
		*(.options)
		*(.eh_frame)
	}
}
