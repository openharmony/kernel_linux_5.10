/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef _LITE_HCK_CED_H
#define _LITE_HCK_CED_H

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/hck/lite_vendor_hooks.h>

#ifndef CONFIG_HCK
#undef CALL_HCK_LITE_HOOK
#define CALL_HCK_LITE_HOOK(name, args...)
#undef REGISTER_HCK_LITE_HOOK
#define REGISTER_HCK_LITE_HOOK(name, probe)
#undef REGISTER_HCK_LITE_DATA_HOOK
#define REGISTER_HCK_LITE_DATA_HOOK(name, probe, data)
#else
DECLARE_HCK_LITE_HOOK(ced_setattr_insert_lhck,
	TP_PROTO(struct task_struct *task),
	TP_ARGS(task));

DECLARE_HCK_LITE_HOOK(ced_switch_task_namespaces_lhck,
	TP_PROTO(const struct nsproxy *new),
	TP_ARGS(new));

DECLARE_HCK_LITE_HOOK(ced_detection_lhck,
	TP_PROTO(struct task_struct *task),
	TP_ARGS(task));

DECLARE_HCK_LITE_HOOK(ced_exit_lhck,
	TP_PROTO(struct task_struct *task),
	TP_ARGS(task));

DECLARE_HCK_LITE_HOOK(ced_kernel_clone_lhck,
	TP_PROTO(struct task_struct *task),
	TP_ARGS(task));

DECLARE_HCK_LITE_HOOK(ced_commit_creds_lhck,
	TP_PROTO(const struct cred *new),
	TP_ARGS(new));

DECLARE_HCK_LITE_HOOK(ced_switch_task_namespaces_permission_lhck,
	TP_PROTO(const struct nsproxy *new, int *ret),
	TP_ARGS(new, ret));
#endif /* CONFIG_HCK */

#endif /* _LITE_HCK_CED_H */
