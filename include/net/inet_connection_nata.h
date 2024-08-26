// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 *
 * Network and Application-driven Transport Augmentation (NATA).
 * Authors: yangyanjun
 */
#ifndef _INET_CONNECTION_NATA_H
#define _INET_CONNECTION_NATA_H
#if defined(CONFIG_TCP_NATA_URC) || defined(CONFIG_TCP_NATA_STL)
#include <net/sock.h>

bool nata_thin_stream_check(struct sock *sk);

#endif
#endif /* _INET_CONNECTION_NATA_H */
