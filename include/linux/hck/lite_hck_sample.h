//SPDX-License-Identifier: GPL-2.0-only
/*lite_hck_sample.h
 *
 *OpenHarmony Common Kernel Vendor Hook Smaple
 *
 */

#ifndef LITE_HCK_SAMPLE_H
#define LITE_HCK_SAMPLE_H

#include <linux/hck/lite_vendor_hooks.h>


struct sample_hck_data {
	int   stat;
	char* name;
};

/*
 * Follwing tracepoints are not exported in trace and provide a
 * mechanism for vendor modules to hok and extend functionality
 */
#ifndef CONFIG_HCK

#define CALL_HCK_LITE_HOOK(name, args...)
#define REGISTER_HCK_LITE_HOOK(name, probe)
#define REGISTER_HCK_LITE_DATA_HOOK(name, probe, data)

#else

DECLARE_HCK_LITE_HOOK(get_boot_config_lhck, TP_PROTO(int* s), TP_ARGS(s));
DECLARE_HCK_LITE_HOOK(set_boot_stat_lhck, TP_PROTO(int m), TP_ARGS(m));

#endif

#endif /* LITE_HCK_SAMPLE_H */
