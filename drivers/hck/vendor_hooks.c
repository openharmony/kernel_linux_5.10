//SPDX-License-Identifier: GPL-2.0-only
/*vendor_hooks.c
 *
 *OpenHarmony Common Kernel Vendor Hook Support
 *
 */

/* lite vendor hook */
#define CREATE_LITE_VENDOR_HOOK
/* add your lite vendor hook header file here */
#include <linux/hck/lite_hck_sample.h>
#include <linux/hck/lite_hck_xpm.h>
#include <linux/hck/lite_hck_ced.h>
#include <linux/hck/lite_hck_inet.h>
#include <linux/hck/lite_hck_hideaddr.h>
#include <linux/hck/lite_hck_code_sign.h>
#include <linux/hck/lite_hck_jit_memory.h>
