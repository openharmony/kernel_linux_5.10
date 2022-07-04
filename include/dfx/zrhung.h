/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef ZRHUNG_H
#define ZRHUNG_H

int zrhung_send_event(const char *domain, const char *event_name, const char *msg_buf);

#endif /* ZRHUNG_H */
