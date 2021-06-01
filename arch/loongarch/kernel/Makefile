# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux/LoongArch kernel.
#

extra-y		:= head.o vmlinux.lds

obj-y		+= cpu-probe.o elf.o entry.o genex.o idle.o irq.o \
		   process.o ptrace.o reset.o setup.o signal.o io.o \
		   syscall.o time.o topology.o traps.o unaligned.o \
		   switch.o cacheinfo.o cmpxchg.o vdso.o

obj-$(CONFIG_ACPI)		+= acpi.o
obj-$(CONFIG_EFI) 		+= efi.o

obj-$(CONFIG_MODULES)		+= module.o module-sections.o

obj-$(CONFIG_CPU_HAS_FPU)	+= fpu.o

obj-$(CONFIG_SMP)		+= smp.o

obj-$(CONFIG_PROC_FS)		+= proc.o

CPPFLAGS_vmlinux.lds		:= $(KBUILD_CFLAGS)
