// SPDX-License-Identifier: GPL-2.0
/*
 * rtg control entry
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#include "rtg.h"
#include "rtg_ctrl.h"

#include <linux/module.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#include <trace/events/rtg.h>

atomic_t g_rtg_enable = ATOMIC_INIT(0);
typedef long (*rtg_ctrl_func)(int abi, void __user *arg);

static rtg_ctrl_func g_func_array[RTG_CTRL_MAX_NR] = {
	NULL, /* reserved */
	ctrl_set_enable,  // 1
};

static void rtg_enable(const struct rtg_enable_data *data)
{
	char temp[MAX_DATA_LEN];

	if (atomic_read(&g_rtg_enable) == 1) {
		pr_info("[SCHED_RTG] already enabled!\n");
		return;
	}
	if ((data->len <= 0) || (data->len >= MAX_DATA_LEN)) {
		pr_err("[SCHED_RTG] %s data len invalid\n", __func__);
		return;
	}
	if (copy_from_user(&temp, (void __user *)data->data, data->len)) {
		pr_err("[SCHED_RTG] %s copy user data failed\n", __func__);
		return;
	}

	atomic_set(&g_rtg_enable, 1);
	pr_info("[SCHED_RTG] enabled!\n");
}

long ctrl_set_enable(int abi, void __user *uarg)
{
	struct rtg_enable_data rs_enable;

	if (copy_from_user(&rs_enable, uarg, sizeof(rs_enable))) {
		pr_err("[SCHED_RTG] CMD_ID_SET_ENABLE copy data failed\n");
		return -INVALID_ARG;
	}
	rtg_enable(&rs_enable);

	return SUCC;
}

static long do_proc_rtg_ioctl(int abi, struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)(uintptr_t)arg;
	unsigned int func_id = _IOC_NR(cmd);

	if (uarg == NULL) {
		pr_err("[SCHED_RTG] %s: invalid user uarg\n", __func__);
		return -EINVAL;
	}

	if ((cmd != CMD_ID_SET_ENABLE) && !atomic_read(&g_rtg_enable)) {
		pr_err("[SCHED_RTG] Rtg not enabled yet.\n");
		return -RTG_DISABLED;
	}

	if (_IOC_TYPE(cmd) != RTG_SCHED_IPC_MAGIC) {
		pr_err("[SCHED_RTG] %s: RTG_SCHED_IPC_MAGIC fail, TYPE=%d\n",
			__func__, _IOC_TYPE(cmd));
		return -INVALID_MAGIC;
	}
	if (func_id >= RTG_CTRL_MAX_NR) {
		pr_err("[SCHED_RTG] %s: RTG_MAX_NR fail, _IOC_NR(cmd)=%d, MAX_NR=%d\n",
			__func__, _IOC_NR(cmd), RTG_CTRL_MAX_NR);
		return -INVALID_CMD;
	}

	if (g_func_array[func_id] != NULL)
		return (*g_func_array[func_id])(abi, uarg);

	return -EINVAL;
}

static int proc_rtg_open(struct inode *inode, struct file *filp)
{
	return SUCC;
}

static int proc_rtg_release(struct inode *inode, struct file *filp)
{
	return SUCC;
}

static long proc_rtg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return do_proc_rtg_ioctl(IOCTL_ABI_AARCH64, file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long proc_rtg_compat_ioctl(struct file *file,
				  unsigned int cmd, unsigned long arg)
{
	return do_proc_rtg_ioctl(IOCTL_ABI_ARM32, file, cmd,
		(unsigned long)(compat_ptr((compat_uptr_t)arg)));
}
#endif

static const struct file_operations rtg_ctrl_fops = {
	.open = proc_rtg_open,
	.release = proc_rtg_release,
	.unlocked_ioctl = proc_rtg_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= proc_rtg_compat_ioctl,
#endif
};

static struct miscdevice rtg_ctrl_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sched_rtg_ctrl",
	.fops = &rtg_ctrl_fops,
	.mode = 0666,
};

static int __init rtg_ctrl_dev_init(void)
{
	return misc_register(&rtg_ctrl_device);
}

static void __exit rtg_ctrl_dev_exit(void)
{
	misc_deregister(&rtg_ctrl_device);
}

module_init(rtg_ctrl_dev_init);
module_exit(rtg_ctrl_dev_exit);
