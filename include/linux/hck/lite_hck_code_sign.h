/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#ifndef LITE_HCK_CODE_SIGN_H
#define LITE_HCK_CODE_SIGN_H

#include <linux/hck/lite_vendor_hooks.h>

#ifndef CONFIG_HCK

#define CALL_HCK_LITE_HOOK(name, args...)
#define REGISTER_HCK_LITE_HOOK(name, probe)
#define REGISTER_HCK_LITE_DATA_HOOK(name, probe, data)

#else

DECLARE_HCK_LITE_HOOK(code_sign_verify_certchain_lhck,
	TP_PROTO(const void *raw_pkcs7, size_t pkcs7_len, struct cs_info *cs_info,
	int *ret),
	TP_ARGS(raw_pkcs7, pkcs7_len, cs_info, ret));

DECLARE_HCK_LITE_HOOK(code_sign_check_descriptor_lhck,
	TP_PROTO(const struct inode *inode, const void *desc, int *ret),
	TP_ARGS(inode, desc, ret));

DECLARE_HCK_LITE_HOOK(code_sign_before_measurement_lhck,
	TP_PROTO(void *desc, int *ret),
	TP_ARGS(desc, ret));

DECLARE_HCK_LITE_HOOK(code_sign_after_measurement_lhck,
	TP_PROTO(void *desc, int version),
	TP_ARGS(desc, version));

#endif /* CONFIG_HCK */

#endif /* LITE_HCK_CODE_SIGN_H */
