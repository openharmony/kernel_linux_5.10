# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux/LoongArch kernel.
#

extra-y		:= head.o vmlinux.lds

obj-y		+= cpu-probe.o elf.o entry.o genex.o idle.o irq.o \
		   process.o ptrace.o reset.o setup.o signal.o io.o \
		   syscall.o time.o topology.o traps.o switch.o \
		   cacheinfo.o cmpxchg.o vdso.o

obj-$(CONFIG_ACPI)		+= acpi.o
obj-$(CONFIG_EFI) 		+= efi.o

obj-$(CONFIG_ARCH_STRICT_ALIGN)	+= unaligned.o

CFLAGS_module.o		+= $(call cc-option,-Wno-override-init,)
CFLAGS_syscall.o	+= $(call cc-option,-Wno-override-init,)
CFLAGS_perf_event.o	+= $(call cc-option,-Wno-override-init,)

obj-$(CONFIG_MODULES)		+= module.o module-sections.o
obj-$(CONFIG_STACKTRACE)	+= stacktrace.o

obj-$(CONFIG_CPU_HAS_FPU)	+= fpu.o kfpu.o

obj-$(CONFIG_SMP)		+= smp.o

obj-$(CONFIG_PROC_FS)		+= proc.o
obj-$(CONFIG_MAGIC_SYSRQ)	+= sysrq.o

obj-$(CONFIG_RELOCATABLE)	+= relocate.o

obj-$(CONFIG_KEXEC)		+= machine_kexec.o relocate_kernel.o
obj-$(CONFIG_CRASH_DUMP)	+= crash_dump.o

obj-$(CONFIG_UNWINDER_GUESS)	+= unwind_guess.o
obj-$(CONFIG_UNWINDER_PROLOGUE)	+= unwind_prologue.o

obj-$(CONFIG_PERF_EVENTS)	+= perf_event.o perf_regs.o
obj-$(CONFIG_HARDWARE_WATCHPOINTS)	+= watch.o

CPPFLAGS_vmlinux.lds		:= $(KBUILD_CFLAGS)
