/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/linux/memcheck.h
 *
 *  Copyright (c) 2022 Huawei Technologies Co., Ltd.
 */
#ifndef _MEMCHECK_H
#define _MEMCHECK_H

#ifdef CONFIG_MEMTRACE_ASHMEM
void init_ashmem_process_info(void);
#else
static inline void init_ashmem_process_info(void) {}
#endif

#endif /* _MEMCHECK_H */

