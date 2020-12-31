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
obj-$(CONFIG_STACKTRACE)	+= stacktrace.o

obj-$(CONFIG_CPU_HAS_FPU)	+= fpu.o

obj-$(CONFIG_SMP)		+= smp.o

obj-$(CONFIG_PROC_FS)		+= proc.o
obj-$(CONFIG_MAGIC_SYSRQ)	+= sysrq.o

obj-$(CONFIG_RELOCATABLE)	+= relocate.o

obj-$(CONFIG_UNWINDER_GUESS)	+= unwind_guess.o
obj-$(CONFIG_UNWINDER_PROLOGUE)	+= unwind_prologue.o

CPPFLAGS_vmlinux.lds		:= $(KBUILD_CFLAGS)
