/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef HIVIEW_HISYSEVENT_H
#define HIVIEW_HISYSEVENT_H

enum hisysevent_type {
	/* fault event */
	FAULT = 1,

	/* statistic event */
	STATISTIC = 2,

	/* security event */
	SECURITY = 3,

	/* behavior event */
	BEHAVIOR = 4
};

struct hiview_hisysevent;

struct hiview_hisysevent *
hisysevent_create(const char *domain, const char *name, enum hisysevent_type type);
void hisysevent_destroy(struct hiview_hisysevent **event);
int hisysevent_put_integer(struct hiview_hisysevent *event, const char *key, long long value);
int hisysevent_put_string(struct hiview_hisysevent *event, const char *key, const char *value);
int hisysevent_write(struct hiview_hisysevent *event);

#endif /* HIVIEW_HISYSEVENT_H */
