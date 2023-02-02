# SPDX-License-Identifier: GPL-2.0
#
# Author: Huacai Chen <chenhuacai@loongson.cn>
# Copyright (C) 2020 Loongson Technology Corporation Limited

archscripts: scripts_basic
	$(Q)$(MAKE) $(build)=arch/loongarch/tools elf-entry
	$(Q)$(MAKE) $(build)=arch/loongarch/boot/tools relocs

#
# Select the object file format to substitute into the linker script.
#
64bit-tool-archpref	= loongarch64
32bit-bfd		= elf32-loongarch
64bit-bfd		= elf64-loongarch
32bit-emul		= elf32loongarch
64bit-emul		= elf64loongarch

ifdef CONFIG_64BIT
tool-archpref		= $(64bit-tool-archpref)
UTS_MACHINE		:= loongarch64
endif

ifneq ($(SUBARCH),$(ARCH))
  ifeq ($(CROSS_COMPILE),)
    CROSS_COMPILE := $(call cc-cross-prefix, $(tool-archpref)-linux-  $(tool-archpref)-linux-gnu-  $(tool-archpref)-unknown-linux-gnu-)
  endif
endif

cflags-y += $(call cc-option, -mno-check-zero-division)

ifdef CONFIG_64BIT
ld-emul			= $(64bit-emul)
cflags-y		+= -mabi=lp64s
endif

all-y			:= vmlinux
all-$(CONFIG_SYS_SUPPORTS_ZBOOT)+= vmlinuz
all-$(CONFIG_EFI_STUB) 	+= vmlinuz.efi

vmlinuz.efi: vmlinuz

cflags-y			+= -G0 -pipe -msoft-float
LDFLAGS_vmlinux			+= -G0 -static -n -nostdlib

# When the assembler supports explicit relocation hint, we must use it.
# GCC may have -mexplicit-relocs off by default if it was built with an old
# assembler, so we force it via an option.
#
# When the assembler does not supports explicit relocation hint, we can't use
# it.  Disable it if the compiler supports it.
#
# If you've seen "unknown reloc hint" message building the kernel and you are
# now wondering why "-mexplicit-relocs" is not wrapped with cc-option: the
# combination of a "new" assembler and "old" compiler is not supported.  Either
# upgrade the compiler or downgrade the assembler.
ifdef CONFIG_AS_HAS_EXPLICIT_RELOCS
cflags-y			+= -mexplicit-relocs
KBUILD_CFLAGS_KERNEL		+= -mdirect-extern-access
else
cflags-y			+= $(call cc-option,-mno-explicit-relocs)
KBUILD_AFLAGS_KERNEL		+= -Wa,-mla-global-with-pcrel
KBUILD_CFLAGS_KERNEL		+= -Wa,-mla-global-with-pcrel
KBUILD_AFLAGS_MODULE		+= -Wa,-mla-global-with-abs
KBUILD_CFLAGS_MODULE		+= -fplt -Wa,-mla-global-with-abs,-mla-local-with-abs
endif

ifeq ($(CONFIG_RELOCATABLE),y)
LDFLAGS_vmlinux		+= --emit-relocs
endif

cflags-y += -ffreestanding

#
# Kernel compression
#
ifdef CONFIG_SYS_SUPPORTS_ZBOOT
KBUILD_IMAGE	= vmlinuz
else
KBUILD_IMAGE	= vmlinux
endif

#
# Board-dependent options and extra files
#
include arch/loongarch/Kbuild.platforms

ifdef CONFIG_PHYSICAL_START
load-y				= $(CONFIG_PHYSICAL_START)
endif

entry-y				= $(shell $(objtree)/arch/loongarch/tools/elf-entry vmlinux)
drivers-$(CONFIG_PCI)		+= arch/loongarch/pci/

KBUILD_AFLAGS	+= $(cflags-y)
KBUILD_CFLAGS	+= $(cflags-y)
KBUILD_CPPFLAGS += -DVMLINUX_LOAD_ADDRESS=$(load-y)

bootvars-y	= VMLINUX_LOAD_ADDRESS=$(load-y) \
		  VMLINUX_ENTRY_ADDRESS=$(entry-y) PLATFORM="$(platform-y)"

ifdef CONFIG_64BIT
bootvars-y	+= ADDR_BITS=64
endif

# This is required to get dwarf unwinding tables into .debug_frame
# instead of .eh_frame so we don't discard them.
KBUILD_CFLAGS += -fno-asynchronous-unwind-tables
ifdef CONFIG_ARCH_STRICT_ALIGN
KBUILD_CFLAGS += $(call cc-option,-mstrict-align)
else
KBUILD_CFLAGS += $(call cc-option,-mno-strict-align)
endif

KBUILD_LDFLAGS	+= -m $(ld-emul)

ifdef CONFIG_LOONGARCH
CHECKFLAGS += $(shell $(CC) $(KBUILD_CFLAGS) -dM -E -x c /dev/null | \
	grep -E -vw '__GNUC_(MINOR_|PATCHLEVEL_)?_' | \
	sed -e "s/^\#define /-D'/" -e "s/ /'='/" -e "s/$$/'/" -e 's/\$$/&&/g')
endif

head-y := arch/loongarch/kernel/head.o

libs-y += arch/loongarch/lib/

# See arch/loongarch/Kbuild for content of core part of the kernel
core-y += arch/loongarch/

# suspend and hibernation support
drivers-$(CONFIG_PM)	+= arch/loongarch/power/

ifeq ($(KBUILD_EXTMOD),)
prepare: vdso_prepare
vdso_prepare: prepare0
	$(Q)$(MAKE) $(build)=arch/loongarch/vdso include/generated/vdso-offsets.h
endif

PHONY += vdso_install
vdso_install:
	$(Q)$(MAKE) $(build)=arch/loongarch/vdso $@

# boot image targets (arch/loongarch/boot/)
boot-y			:= vmlinux.bin

# compressed boot image targets (arch/loongarch/boot/compressed/)
bootz-y			:= vmlinuz
bootz-y			+= vmlinuz.bin
bootz-$(CONFIG_EFI_STUB)+= vmlinuz.efi

all:	$(all-y)

# boot
$(boot-y): vmlinux FORCE
	$(Q)$(MAKE) $(build)=arch/loongarch/boot VMLINUX=vmlinux \
		$(bootvars-y) arch/loongarch/boot/$@

ifdef CONFIG_SYS_SUPPORTS_ZBOOT
# boot/compressed
$(bootz-y): vmlinux FORCE
	$(Q)$(MAKE) $(build)=arch/loongarch/boot/compressed \
		$(bootvars-y) 64bit-bfd=$(64bit-bfd) $@
else
vmlinuz: FORCE
	@echo '   CONFIG_SYS_SUPPORTS_ZBOOT is not enabled'
	/bin/false
endif

CLEAN_FILES += vmlinux

install:
	$(Q)install -D -m 755 vmlinux $(INSTALL_PATH)/vmlinux-$(KERNELRELEASE)
ifdef CONFIG_SYS_SUPPORTS_ZBOOT
	$(Q)install -D -m 755 vmlinuz $(INSTALL_PATH)/vmlinuz-$(KERNELRELEASE)
endif
	$(Q)install -D -m 644 .config $(INSTALL_PATH)/config-$(KERNELRELEASE)
	$(Q)install -D -m 644 System.map $(INSTALL_PATH)/System.map-$(KERNELRELEASE)

archclean:
	$(Q)$(MAKE) $(clean)=arch/loongarch/boot
	$(Q)$(MAKE) $(clean)=arch/loongarch/boot/compressed
	$(Q)$(MAKE) $(clean)=arch/loongarch/boot/tools
	$(Q)$(MAKE) $(clean)=arch/loongarch/tools

define archhelp
	echo '  install              - install kernel into $(INSTALL_PATH)'
	echo '  vmlinux.bin          - Raw binary boot image'
	echo '  vmlinuz              - Compressed boot(zboot) image'
	echo '  vmlinuz.bin          - Raw binary zboot image'
	echo
endef
