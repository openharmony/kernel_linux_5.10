// SPDX-License-Identifier: GPL-2.0
/*
 * Sample Call HCK
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/hck/lite_hck_sample.h>

static int __init samplecallhck_init(void)
{
	int val = 0;

	pr_info("hck sample: call\n");

	CALL_HCK_LITE_HOOK(get_boot_config_lhck, &val);
	pr_info("hck sample val changed: %d\n", val);

	CALL_HCK_LITE_HOOK(set_boot_stat_lhck, val);
	pr_info("hck sample val not changed: %d\n", val);

	return 0;
}
late_initcall(samplecallhck_init);