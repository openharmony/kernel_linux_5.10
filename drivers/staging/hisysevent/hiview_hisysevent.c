// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2023 Huawei Technologies Co., Ltd. All rights reserved.
 */

#include <dfx/hiview_hisysevent.h>

#ifdef CONFIG_HISYSEVENT

#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <asm/current.h>

#include "hisysevent_builder.h"
#include "hisysevent_raw_data.h"

#define HISYSEVENT_WRITER_DEV "/dev/bbox"

static int CHECK_CODE = 0x7BCDABCD;

#define HISYSEVENT_INFO_BUF_LEN (2048 - 6)  // 2KB - 6 (read_gap)

/* hisysevent struct */
struct hiview_hisysevent {
	/* hisysevent builder */
	struct hisysevent_builder *builder;
};

struct hiview_hisysevent *
hisysevent_create(const char *domain, const char *name, enum hisysevent_type type)
{
	struct hiview_hisysevent *event;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return NULL;

	event->builder = hisysevent_builder_create(domain, name, type);
	if (!event->builder)
		goto create_err;
	return event;

create_err:
	hisysevent_destroy(&event);
	return NULL;
}
EXPORT_SYMBOL_GPL(hisysevent_create);

void hisysevent_destroy(struct hiview_hisysevent **event)
{
	if (!event || !*event) {
		pr_err("invalid event");
		return;
	}

	hisysevent_builder_destroy((*event)->builder);

	kfree(*event);
	*event = NULL;
}
EXPORT_SYMBOL_GPL(hisysevent_destroy);

int hisysevent_put_integer(struct hiview_hisysevent *event, const char *key, long long value)
{
	if (!event) {
		pr_err("invalid event");
		return -EINVAL;
	}
	return hisysevent_builder_put_integer(event->builder, key, value);
}
EXPORT_SYMBOL_GPL(hisysevent_put_integer);

int hisysevent_put_string(struct hiview_hisysevent *event, const char *key, const char *value)
{
	if (!event) {
		pr_err("invalid event");
		return -EINVAL;
	}
	return hisysevent_builder_put_string(event->builder, key, value);
}
EXPORT_SYMBOL_GPL(hisysevent_put_string);

int hisysevent_write(struct hiview_hisysevent *event)
{
	struct hisysevent_raw_data *raw_data;
	int ret;
	struct file *filp;
	unsigned long vcount;
	struct iovec vec[3];
	mm_segment_t oldfs;
	struct iov_iter iter;

	if (!event) {
		pr_err("invalid event");
		return -EINVAL;
	}

	raw_data = raw_data_create();
	if (!raw_data) {
		pr_err("failed to create a new raw data");
		return -EINVAL;
	}

	ret = hisysevent_builder_build(event->builder, raw_data);
	if (ret != 0) {
		pr_err("hisysevent builder build failed");
		goto event_wrote_err;
	}
	pr_info("total block size of hisysevent data is %d", raw_data->len);

	if (raw_data->len > HISYSEVENT_INFO_BUF_LEN) {
		pr_err("content of sysevent exceeds limit");
		goto event_wrote_err;
	}

	filp = filp_open(HISYSEVENT_WRITER_DEV, O_WRONLY, 0);

	if (!filp || IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		pr_err("failed to access '%s', res=%d", HISYSEVENT_WRITER_DEV, ret);
		goto event_wrote_err;
	}

	vcount = 0;
	vec[vcount].iov_base = &CHECK_CODE;
	vec[vcount++].iov_len = sizeof(CHECK_CODE);
	vec[vcount].iov_base = raw_data->data;
	vec[vcount++].iov_len = raw_data->len + 1;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	iov_iter_init(&iter, WRITE, vec, vcount, iov_length(vec, vcount));
	ret = vfs_iter_write(filp, &iter, &filp->f_pos, 0);
	set_fs(oldfs);

	if (ret < 0)
		pr_err("failed to write hisysevent, ret=%d", ret);

	filp_close(filp, NULL);

event_wrote_err:
	raw_data_destroy(raw_data);
	return ret;
}
EXPORT_SYMBOL_GPL(hisysevent_write);

#endif /* CONFIG_HISYSEVENT */
