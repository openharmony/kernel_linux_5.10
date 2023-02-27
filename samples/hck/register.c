// SPDX-License-Identifier: GPL-2.0
/*
 * Sample HCK
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/hck/lite_hck_sample.h>

static struct sample_hck_data data = {
	.stat = 999,
	.name = "sample tesst",
};

void get_boot_config(int* info)
{
	pr_info("hck sample: %s\n", __func__);
	*info = 1;
}

void set_boot_stat(void* data, int info)
{
	pr_info("hck sample: %s\n", __func__);
	info = 2;
	struct sample_hck_data *hdata = data;

	pr_info("hck data: stat = %d, name = %s\n", hdata->stat, hdata->name);
}

static int __init samplehck_init(void)
{
	pr_info("hck sample register\n");

	REGISTER_HCK_LITE_HOOK(get_boot_config_lhck, get_boot_config);
	REGISTER_HCK_LITE_DATA_HOOK(set_boot_stat_lhck, set_boot_stat, &data);

	return 0;
}

static void __exit samplehck_exit(void)
{
}

module_init(samplehck_init);
module_exit(samplehck_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("zhujiaxin <zhujiaxin@huawei.com>");
