/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/zswapd_internal.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _ZSWAPD_INTERNAL_H
#define _ZSWAPD_INTERNAL_H

enum zswapd_pressure_level {
	LEVEL_LOW = 0,
	LEVEL_MEDIUM,
	LEVEL_CRITICAL,
	LEVEL_COUNT
};

enum zswapd_eswap_policy {
	CHECK_BUFFER_ONLY = 0,
	CHECK_BUFFER_ZRAMRATIO_BOTH
};

void zswapd_pressure_report(enum zswapd_pressure_level level);
inline unsigned int get_zram_wm_ratio(void);
inline unsigned int get_compress_ratio(void);
inline unsigned int get_avail_buffers(void);
inline unsigned int get_min_avail_buffers(void);
inline unsigned int get_high_avail_buffers(void);
inline unsigned int get_zswapd_max_reclaim_size(void);
inline unsigned int get_inactive_file_ratio(void);
inline unsigned int get_active_file_ratio(void);
inline unsigned long long get_area_anon_refault_threshold(void);
inline unsigned long long get_anon_refault_snapshot_min_interval(void);
inline unsigned long long get_empty_round_skip_interval(void);
inline unsigned long long get_max_skip_interval(void);
inline unsigned long long get_empty_round_check_threshold(void);
inline unsigned long long get_zram_critical_threshold(void);
u64 memcg_data_size(struct mem_cgroup *memcg, int type);
u64 swapin_memcg(struct mem_cgroup *memcg, u64 req_size);

#endif /* MM_ZSWAPD_INTERNAL_H */
