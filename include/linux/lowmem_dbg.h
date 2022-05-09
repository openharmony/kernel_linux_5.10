/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/lowmem_dbg.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */
#ifndef __LMK_DBG_H
#define __LMK_DBG_H

#ifdef CONFIG_LOWMEM
void lowmem_dbg(short oom_score_adj);
#else
static inline void lowmem_dbg(short oom_score_adj) {}
#endif
#endif

