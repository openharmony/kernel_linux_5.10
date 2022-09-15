// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 */

#define pr_fmt(fmt) "zrhung " fmt

#include <dfx/hiview_hisysevent.h>
#include <dfx/zrhung.h>

#include <linux/errno.h>
#include <linux/printk.h>

int zrhung_send_event(const char *domain, const char *event_name, const char *msg_buf)
{
	struct hiview_hisysevent *event = NULL;
	int ret = 0;

	event = hisysevent_create(domain, event_name, FAULT);
	if (!event) {
		pr_err("failed to create event");
		return -EINVAL;
	}
	ret = hisysevent_put_string(event, "MSG", msg_buf);
	if (ret != 0) {
		pr_err("failed to put sting to event, ret=%d", ret);
		goto hisysevent_end;
	}
	ret = hisysevent_write(event);

hisysevent_end:
	hisysevent_destroy(&event);
	return ret;
}
