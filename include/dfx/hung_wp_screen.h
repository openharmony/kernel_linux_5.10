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

#ifndef HUNG_WP_SCREEN_H
#define HUNG_WP_SCREEN_H

#define WP_SCREEN_PWK_RELEASE 0
#define WP_SCREEN_PWK_PRESS 1

#define ZRHUNG_WP_NONE 0
#define ZRHUNG_WP_SCREENON 1
#define ZRHUNG_WP_SCREENOFF 2

#define WP_SCREEN_DOMAIN "KERNEL_VENDOR"
#define WP_SCREEN_PWK_NAME "POWERKEY"
#define WP_SCREEN_LPRESS_NAME "LONGPRESS"
#define WP_SCREEN_ON_NAME "SCREEN_ON"
#define WP_SCREEN_OFF_NAME "SCREEN_OFF"

void hung_wp_screen_powerkey_ncb(int event);

#endif /* HUNG_WP_SCREEN_H */
