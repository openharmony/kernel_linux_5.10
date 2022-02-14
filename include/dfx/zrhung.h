// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef ZRHUNG_H
#define ZRHUNG_H

#define ZRHUNG_EVENT_TYPE 1

int zrhung_send_event(const char *domain, const char *event_name, const char *msg_buf);

#endif /* ZRHUNG_H */
