// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/kvm_para.h>
#include <asm/fpu.h>
#include <asm/lbt.h>

/* FPU/LSX context management */
void __kvm_save_fpu(struct loongarch_fpu *fpu);
void __kvm_restore_fpu(struct loongarch_fpu *fpu);

void kvm_save_fpu(struct kvm_vcpu *cpu)
{
	return __kvm_save_fpu(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_save_fpu);

void kvm_restore_fpu(struct kvm_vcpu *cpu)
{
	return __kvm_restore_fpu(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_restore_fpu);

#ifdef CONFIG_CPU_HAS_LSX
void __kvm_save_lsx(struct loongarch_fpu *fpu);
void __kvm_restore_lsx(struct loongarch_fpu *fpu);
void __kvm_restore_lsx_upper(struct loongarch_fpu *fpu);

void kvm_save_lsx(struct kvm_vcpu *cpu)
{
	return __kvm_save_lsx(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_save_lsx);

void kvm_restore_lsx(struct kvm_vcpu *cpu)
{
	return __kvm_restore_lsx(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_restore_lsx);

void kvm_restore_lsx_upper(struct kvm_vcpu *cpu)
{
	return __kvm_restore_lsx_upper(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_restore_lsx_upper);

#endif

#ifdef CONFIG_CPU_HAS_LSX
void __kvm_save_lasx(struct loongarch_fpu *fpu);
void __kvm_restore_lasx(struct loongarch_fpu *fpu);
void __kvm_restore_lasx_upper(struct loongarch_fpu *fpu);

void kvm_save_lasx(struct kvm_vcpu *cpu)
{
	return __kvm_save_lasx(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_save_lasx);

void kvm_restore_lasx(struct kvm_vcpu *cpu)
{
	return __kvm_restore_lasx(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_restore_lasx);

void kvm_restore_lasx_upper(struct kvm_vcpu *cpu)
{
	return _restore_lasx_upper(&cpu->arch.fpu);
}
EXPORT_SYMBOL_GPL(kvm_restore_lasx_upper);
#endif

#ifdef CONFIG_CPU_HAS_LBT
void kvm_restore_lbt(struct kvm_vcpu *cpu)
{
	restore_lbt_registers(&cpu->arch.lbt);
}
EXPORT_SYMBOL_GPL(kvm_restore_lbt);

void kvm_save_lbt(struct kvm_vcpu *cpu)
{
	save_lbt_registers(&cpu->arch.lbt);
}
EXPORT_SYMBOL_GPL(kvm_save_lbt);
#endif


EXPORT_SYMBOL_GPL(kvm_enter_guest);
EXPORT_SYMBOL_GPL(kvm_exception_entry);

