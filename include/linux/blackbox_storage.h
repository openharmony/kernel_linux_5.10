/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef BLACKBOX_STORAGE_H
#define BLACKBOX_STORAGE_H

#include <linux/kmsg_dump.h>

struct reboot_crashlog_storage {
	int (*storage_log)(void *out, unsigned int outlen);
	int (*get_log)(void *in, unsigned int inlen);
	void (*blackbox_dump)(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason);
	const char *material;
};

extern char *storage_material;
extern const struct reboot_crashlog_storage *storage_lastword;
extern const struct reboot_crashlog_storage storage_lastwords[];

#endif /* BLACKBOX_STORAGE_H */
