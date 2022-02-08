// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/hyperhold/hp_device.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#define pr_fmt(fmt) "[HYPERHOLD]" fmt

#include <linux/blkdev.h>

#include "hp_device.h"

void unbind_bdev(struct hp_device *dev)
{
	int ret;

	if (!dev->bdev)
		goto close;
	if (!dev->old_block_size)
		goto put;
	ret = set_blocksize(dev->bdev, dev->old_block_size);
	if (ret)
		pr_err("set old block size %d failed, err = %d!\n",
				dev->old_block_size, ret);
	dev->old_block_size = 0;
put:
	blkdev_put(dev->bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	dev->bdev = NULL;
close:
	if (dev->filp)
		filp_close(dev->filp, NULL);
	dev->filp = NULL;

	pr_info("hyperhold bdev unbinded.\n");
}

bool bind_bdev(struct hp_device *dev, const char *name)
{
	struct inode *inode = NULL;
	int ret;

	dev->filp = filp_open(name, O_RDWR | O_LARGEFILE, 0);
	if (IS_ERR(dev->filp)) {
		pr_err("open file %s failed, err = %ld!\n", name, PTR_ERR(dev->filp));
		dev->filp = NULL;
		goto err;
	}
	inode = dev->filp->f_mapping->host;
	if (!S_ISBLK(inode->i_mode)) {
		pr_err("%s is not a block device!\n", name);
		goto err;
	}
	dev->bdev = blkdev_get_by_dev(inode->i_rdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL, dev);
	if (IS_ERR(dev->bdev)) {
		ret = PTR_ERR(dev->bdev);
		dev->bdev = NULL;
		pr_err("get blkdev %s failed, err = %d!\n", name, ret);
		goto err;
	}
	dev->old_block_size = block_size(dev->bdev);
	ret = set_blocksize(dev->bdev, PAGE_SIZE);
	if (ret) {
		pr_err("set %s block size failed, err = %d!\n", name, ret);
		goto err;
	}
	dev->dev_size = (u64)i_size_read(inode);
	dev->sec_size = SECTOR_SIZE;

	pr_info("hyperhold bind bdev %s of size %llu / %u succ.\n",
			name, dev->dev_size, dev->sec_size);

	return true;
err:
	unbind_bdev(dev);

	return false;
}
