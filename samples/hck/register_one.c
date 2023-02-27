// SPDX-License-Identifier: GPL-2.0
/*
 * Sample HCK
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/hck/lite_hck_sample.h>

void get_boot_power_config(int* info)
{
	pr_info("hck sample: intf-2 run\n");
	*info = 2;
}

static int __init samplehckone_init(void)
{
	pr_info("hck sample register_one\n");
	REGISTER_HCK_LITE_HOOK(get_boot_config_lhck, get_boot_power_config);

	return 0;
}

static void __exit samplehckone_exit(void)
{
}

module_init(samplehckone_init);
module_exit(samplehckone_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("zhujiaxin <zhujiaxin@huawei.com>");
