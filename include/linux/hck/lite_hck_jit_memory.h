/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
*/

#ifndef LITE_HCK_JIT_MEMORY_H
#define LITE_HCK_JIT_MEMORY_H

#include <linux/sched.h>
#include <linux/hck/lite_vendor_hooks.h>

#ifndef CONFIG_HCK
#undef CALL_HCK_LITE_HOOK
#define CALL_HCK_LITE_HOOK(name, args...)
#undef REGISTER_HCK_LITE_HOOK
#define REGISTER_HCK_LITE_HOOK(name, probe)
#undef REGISTER_HCK_LITE_DATA_HOOK
#define REGISTER_HCK_LITE_DATA_HOOK(name, probe, data)

#else

DECLARE_HCK_LITE_HOOK(find_jit_memory_lhck,
	TP_PROTO(struct task_struct *task, unsigned long start, unsigned long size, int *err),
	TP_ARGS(task, start, size, err));

DECLARE_HCK_LITE_HOOK(check_jit_memory_lhck,
	TP_PROTO(struct task_struct *task, unsigned long cookie, unsigned long prot,
		unsigned long flag, unsigned long size, unsigned long *err),
	TP_ARGS(task, cookie, prot, flag, size, err));

DECLARE_HCK_LITE_HOOK(delete_jit_memory_lhck,
	TP_PROTO(struct task_struct *task, unsigned long start, unsigned long size, int *err),
	TP_ARGS(task, start, size, err));

DECLARE_HCK_LITE_HOOK(exit_jit_memory_lhck,
	TP_PROTO(struct task_struct *task),
	TP_ARGS(task));

#endif /* CONFIG_HCK */

#endif /* LITE_HCK_JIT_MEMORY_H */
