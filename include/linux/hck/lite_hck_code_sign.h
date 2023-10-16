//SPDX-License-Identifier: GPL-2.0-only
/*lite_hck_sample.h
 *
 *OpenHarmony Common Kernel Vendor Hook Smaple
 *
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
	TP_PROTO(const void *raw_pkcs7, size_t pkcs7_len, int *ret),
	TP_ARGS(raw_pkcs7, pkcs7_len, ret));

#endif /* CONFIG_HCK */

#endif /* LITE_HCK_CODE_SIGN_H */
