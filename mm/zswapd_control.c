// SPDX-License-Identifier: GPL-2.0
/*
 * mm/zswapd_control.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#include <linux/memcontrol.h>
#include <linux/types.h>
#include <linux/cgroup-defs.h>
#include <linux/cgroup.h>
#include <linux/memcg_policy.h>
#include <linux/zswapd.h>

#include "zswapd_internal.h"

#define ANON_REFAULT_SNAPSHOT_MIN_INTERVAL 200
#define AREA_ANON_REFAULT_THRESHOLD 22000
#define EMPTY_ROUND_CHECK_THRESHOLD 10
#define EMPTY_ROUND_SKIP_INTERVAL 20
#define ZSWAPD_MAX_LEVEL_NUM 10
#define MAX_SKIP_INTERVAL 1000
#define MAX_RECLAIM_SIZE 100

#define INACTIVE_FILE_RATIO 90
#define ACTIVE_FILE_RATIO 70
#define COMPRESS_RATIO 30
#define ZRAM_WM_RATIO 0
#define MAX_RATIO 100

#define CHECK_BUFFER_VALID(var1, var2) (((var2) != 0) && ((var1) > (var2)))

struct zswapd_param {
	unsigned int min_score;
	unsigned int max_score;
	unsigned int ub_mem2zram_ratio;
	unsigned int ub_zram2ufs_ratio;
	unsigned int refault_threshold;
};

static struct zswapd_param zswap_param[ZSWAPD_MAX_LEVEL_NUM];
struct eventfd_ctx *zswapd_press_efd[LEVEL_COUNT];
static DEFINE_MUTEX(pressure_event_lock);
static DEFINE_MUTEX(reclaim_para_lock);

atomic_t avail_buffers = ATOMIC_INIT(0);
atomic_t min_avail_buffers = ATOMIC_INIT(0);
atomic_t high_avail_buffers = ATOMIC_INIT(0);
atomic_t max_reclaim_size = ATOMIC_INIT(MAX_RECLAIM_SIZE);

atomic_t inactive_file_ratio = ATOMIC_INIT(INACTIVE_FILE_RATIO);
atomic_t active_file_ratio = ATOMIC_INIT(ACTIVE_FILE_RATIO);
atomic_t zram_wm_ratio = ATOMIC_INIT(ZRAM_WM_RATIO);
atomic_t compress_ratio = ATOMIC_INIT(COMPRESS_RATIO);

atomic64_t zram_critical_threshold = ATOMIC_LONG_INIT(0);
atomic64_t free_swap_threshold = ATOMIC_LONG_INIT(0);
atomic64_t area_anon_refault_threshold = ATOMIC_LONG_INIT(AREA_ANON_REFAULT_THRESHOLD);
atomic64_t anon_refault_snapshot_min_interval =
	ATOMIC_LONG_INIT(ANON_REFAULT_SNAPSHOT_MIN_INTERVAL);
atomic64_t empty_round_skip_interval = ATOMIC_LONG_INIT(EMPTY_ROUND_SKIP_INTERVAL);
atomic64_t max_skip_interval = ATOMIC_LONG_INIT(MAX_SKIP_INTERVAL);
atomic64_t empty_round_check_threshold = ATOMIC_LONG_INIT(EMPTY_ROUND_CHECK_THRESHOLD);

inline unsigned int get_zram_wm_ratio(void)
{
	return atomic_read(&zram_wm_ratio);
}

inline unsigned int get_compress_ratio(void)
{
	return atomic_read(&compress_ratio);
}

inline unsigned int get_inactive_file_ratio(void)
{
	return atomic_read(&inactive_file_ratio);
}

inline unsigned int get_active_file_ratio(void)
{
	return atomic_read(&active_file_ratio);
}

inline unsigned int get_avail_buffers(void)
{
	return atomic_read(&avail_buffers);
}

inline unsigned int get_min_avail_buffers(void)
{
	return atomic_read(&min_avail_buffers);
}

inline unsigned int get_high_avail_buffers(void)
{
	return atomic_read(&high_avail_buffers);
}

inline unsigned int get_zswapd_max_reclaim_size(void)
{
	return atomic_read(&max_reclaim_size);
}

inline unsigned long long get_free_swap_threshold(void)
{
	return atomic64_read(&free_swap_threshold);
}

inline unsigned long long get_area_anon_refault_threshold(void)
{
	return atomic64_read(&area_anon_refault_threshold);
}

inline unsigned long long get_anon_refault_snapshot_min_interval(void)
{
	return atomic64_read(&anon_refault_snapshot_min_interval);
}

inline unsigned long long get_empty_round_skip_interval(void)
{
	return atomic64_read(&empty_round_skip_interval);
}

inline unsigned long long get_max_skip_interval(void)
{
	return atomic64_read(&max_skip_interval);
}

inline unsigned long long get_empty_round_check_threshold(void)
{
	return atomic64_read(&empty_round_check_threshold);
}

inline unsigned long long get_zram_critical_threshold(void)
{
	return atomic64_read(&zram_critical_threshold);
}

static ssize_t avail_buffers_params_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	unsigned long long threshold;
	unsigned int high_buffers;
	unsigned int min_buffers;
	unsigned int buffers;

	buf = strstrip(buf);

	if (sscanf(buf, "%u %u %u %llu", &buffers, &min_buffers, &high_buffers, &threshold) != 4)
		return -EINVAL;

	if (CHECK_BUFFER_VALID(min_buffers, buffers) ||
	    CHECK_BUFFER_VALID(min_buffers, high_buffers) ||
	    CHECK_BUFFER_VALID(buffers, high_buffers))
		return -EINVAL;

	atomic_set(&avail_buffers, buffers);
	atomic_set(&min_avail_buffers, min_buffers);
	atomic_set(&high_avail_buffers, high_buffers);
	atomic64_set(&free_swap_threshold, (threshold * (SZ_1M / PAGE_SIZE)));

	if (atomic_read(&min_avail_buffers) == 0)
		set_snapshotd_init_flag(0);
	else
		set_snapshotd_init_flag(1);

	wake_all_zswapd();

	return nbytes;
}

static ssize_t zswapd_max_reclaim_size_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	u32 max;
	int ret;

	buf = strstrip(buf);
	ret = kstrtouint(buf, 10, &max);
	if (ret)
		return -EINVAL;

	atomic_set(&max_reclaim_size, max);

	return nbytes;
}

static ssize_t buffers_ratio_params_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	unsigned int inactive;
	unsigned int active;

	buf = strstrip(buf);

	if (sscanf(buf, "%u %u", &inactive, &active) != 2)
		return -EINVAL;

	if (inactive > MAX_RATIO || active > MAX_RATIO)
		return -EINVAL;

	atomic_set(&inactive_file_ratio, inactive);
	atomic_set(&active_file_ratio, active);

	return nbytes;
}

static int area_anon_refault_threshold_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	atomic64_set(&area_anon_refault_threshold, val);

	return 0;
}

static int empty_round_skip_interval_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	atomic64_set(&empty_round_skip_interval, val);

	return 0;
}

static int max_skip_interval_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	atomic64_set(&max_skip_interval, val);

	return 0;
}

static int empty_round_check_threshold_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	atomic64_set(&empty_round_check_threshold, val);

	return 0;
}

static int anon_refault_snapshot_min_interval_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	atomic64_set(&anon_refault_snapshot_min_interval, val);

	return 0;
}

static int zram_critical_thres_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	atomic64_set(&zram_critical_threshold, val);

	return 0;
}

static ssize_t zswapd_pressure_event_control(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	unsigned int level;
	unsigned int efd;
	struct fd efile;
	int ret;

	buf = strstrip(buf);
	if (sscanf(buf, "%u %u", &efd, &level) != 2)
		return -EINVAL;

	if (level >= LEVEL_COUNT)
		return -EINVAL;

	mutex_lock(&pressure_event_lock);
	efile = fdget(efd);
	if (!efile.file) {
		ret = -EBADF;
		goto out;
	}

	zswapd_press_efd[level] = eventfd_ctx_fileget(efile.file);
	if (IS_ERR(zswapd_press_efd[level])) {
		ret = PTR_ERR(zswapd_press_efd[level]);
		goto out_put_efile;
	}
	fdput(efile);
	mutex_unlock(&pressure_event_lock);
	return nbytes;

out_put_efile:
	fdput(efile);
out:
	mutex_unlock(&pressure_event_lock);

	return ret;
}

void zswapd_pressure_report(enum zswapd_pressure_level level)
{
	int ret;

	if (zswapd_press_efd[level] == NULL)
		return;

	ret = eventfd_signal(zswapd_press_efd[level], 1);
	if (ret < 0)
		pr_err("SWAP-MM: %s : level:%u, ret:%d ", __func__, level, ret);
}

static u64 zswapd_pid_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return get_zswapd_pid();
}

static void zswapd_memcgs_param_parse(int level_num)
{
	struct mem_cgroup *memcg = NULL;
	u64 score;
	int i;

	while ((memcg = get_next_memcg(memcg))) {
		score = atomic64_read(&memcg->memcg_reclaimed.app_score);
		for (i = 0; i < level_num; ++i)
			if (score >= zswap_param[i].min_score &&
			    score <= zswap_param[i].max_score)
				break;

		atomic_set(&memcg->memcg_reclaimed.ub_mem2zram_ratio,
			zswap_param[i].ub_mem2zram_ratio);
		atomic_set(&memcg->memcg_reclaimed.ub_zram2ufs_ratio,
			zswap_param[i].ub_zram2ufs_ratio);
		atomic_set(&memcg->memcg_reclaimed.refault_threshold,
			zswap_param[i].refault_threshold);
	}
}

static ssize_t zswapd_memcgs_param_write(struct kernfs_open_file *of, char *buf,
				size_t nbytes, loff_t off)
{
	char *token = NULL;
	int level_num;
	int i;

	buf = strstrip(buf);
	token = strsep(&buf, " ");

	if (!token)
		return -EINVAL;

	if (kstrtoint(token, 0, &level_num))
		return -EINVAL;

	if (level_num > ZSWAPD_MAX_LEVEL_NUM)
		return -EINVAL;

	mutex_lock(&reclaim_para_lock);
	for (i = 0; i < level_num; ++i) {
		token = strsep(&buf, " ");
		if (!token)
			goto out;

		if (kstrtoint(token, 0, &zswap_param[i].min_score) ||
			zswap_param[i].min_score > MAX_APP_SCORE)
			goto out;

		token = strsep(&buf, " ");
		if (!token)
			goto out;

		if (kstrtoint(token, 0, &zswap_param[i].max_score) ||
			zswap_param[i].max_score > MAX_APP_SCORE)
			goto out;

		token = strsep(&buf, " ");
		if (!token)
			goto out;

		if (kstrtoint(token, 0, &zswap_param[i].ub_mem2zram_ratio) ||
			zswap_param[i].ub_mem2zram_ratio > MAX_RATIO)
			goto out;

		token = strsep(&buf, " ");
		if (!token)
			goto out;

		if (kstrtoint(token, 0, &zswap_param[i].ub_zram2ufs_ratio) ||
			zswap_param[i].ub_zram2ufs_ratio > MAX_RATIO)
			goto out;

		token = strsep(&buf, " ");
		if (!token)
			goto out;

		if (kstrtoint(token, 0, &zswap_param[i].refault_threshold))
			goto out;
	}

	zswapd_memcgs_param_parse(level_num);
	mutex_unlock(&reclaim_para_lock);

	return nbytes;

out:
	mutex_unlock(&reclaim_para_lock);
	return -EINVAL;
}

static ssize_t zswapd_single_memcg_param_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	unsigned int ub_mem2zram_ratio;
	unsigned int ub_zram2ufs_ratio;
	unsigned int refault_threshold;

	buf = strstrip(buf);

	if (sscanf(buf, "%u %u %u", &ub_mem2zram_ratio, &ub_zram2ufs_ratio,
			&refault_threshold) != 3)
		return -EINVAL;

	if (ub_mem2zram_ratio > MAX_RATIO || ub_zram2ufs_ratio > MAX_RATIO ||
	    refault_threshold > MAX_RATIO)
		return -EINVAL;

	atomic_set(&memcg->memcg_reclaimed.ub_mem2zram_ratio,
		ub_mem2zram_ratio);
	atomic_set(&memcg->memcg_reclaimed.ub_zram2ufs_ratio,
		ub_zram2ufs_ratio);
	atomic_set(&memcg->memcg_reclaimed.refault_threshold,
		refault_threshold);

	return nbytes;
}

static ssize_t mem_cgroup_zram_wm_ratio_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	unsigned int ratio;
	int ret;

	buf = strstrip(buf);

	ret = kstrtouint(buf, 10, &ratio);
	if (ret)
		return -EINVAL;

	if (ratio > MAX_RATIO)
		return -EINVAL;

	atomic_set(&zram_wm_ratio, ratio);

	return nbytes;
}

static ssize_t mem_cgroup_compress_ratio_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	unsigned int ratio;
	int ret;

	buf = strstrip(buf);

	ret = kstrtouint(buf, 10, &ratio);
	if (ret)
		return -EINVAL;

	if (ratio > MAX_RATIO)
		return -EINVAL;

	atomic_set(&compress_ratio, ratio);

	return nbytes;
}

static int zswapd_pressure_show(struct seq_file *m, void *v)
{
	zswapd_status_show(m);

	return 0;
}

static int memcg_active_app_info_list_show(struct seq_file *m, void *v)
{
	struct mem_cgroup_per_node *mz = NULL;
	struct mem_cgroup *memcg = NULL;
	struct lruvec *lruvec = NULL;
	unsigned long eswap_size;
	unsigned long anon_size;
	unsigned long zram_size;

	while ((memcg = get_next_memcg(memcg))) {
		u64 score = atomic64_read(&memcg->memcg_reclaimed.app_score);

		mz = mem_cgroup_nodeinfo(memcg, 0);
		if (!mz) {
			get_next_memcg_break(memcg);
			return 0;
		}

		lruvec = &mz->lruvec;
		if (!lruvec) {
			get_next_memcg_break(memcg);
			return 0;
		}

		anon_size = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON,
			MAX_NR_ZONES) +	lruvec_lru_size(lruvec,
			LRU_INACTIVE_ANON, MAX_NR_ZONES);
		eswap_size = memcg_data_size(memcg, SWAP_SIZE);
		zram_size = memcg_data_size(memcg, CACHE_SIZE);

		if (anon_size + zram_size + eswap_size == 0)
			continue;

		if (!strlen(memcg->name))
			continue;

		anon_size *= PAGE_SIZE / SZ_1K;
		zram_size *= PAGE_SIZE / SZ_1K;
		eswap_size *= PAGE_SIZE / SZ_1K;

		seq_printf(m, "%s %llu %lu %lu %lu %llu\n", memcg->name, score,
			anon_size, zram_size, eswap_size,
			memcg->memcg_reclaimed.reclaimed_pagefault);
	}
	return 0;
}

#ifdef CONFIG_HYPERHOLD_DEBUG
static int avail_buffers_params_show(struct seq_file *m, void *v)
{
	seq_printf(m, "avail_buffers: %u\n", atomic_read(&avail_buffers));
	seq_printf(m, "min_avail_buffers: %u\n", atomic_read(&min_avail_buffers));
	seq_printf(m, "high_avail_buffers: %u\n", atomic_read(&high_avail_buffers));
	seq_printf(m, "free_swap_threshold: %llu\n",
		atomic64_read(&free_swap_threshold) * PAGE_SIZE / SZ_1M);

	return 0;
}

static int zswapd_max_reclaim_size_show(struct seq_file *m, void *v)
{
	seq_printf(m, "zswapd_max_reclaim_size: %u\n",
		atomic_read(&max_reclaim_size));

	return 0;
}

static int buffers_ratio_params_show(struct seq_file *m, void *v)
{
	seq_printf(m, "inactive_file_ratio: %u\n", atomic_read(&inactive_file_ratio));
	seq_printf(m, "active_file_ratio: %u\n", atomic_read(&active_file_ratio));

	return 0;
}

static u64 area_anon_refault_threshold_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	return atomic64_read(&area_anon_refault_threshold);
}

static u64 empty_round_skip_interval_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	return atomic64_read(&empty_round_skip_interval);
}

static u64 max_skip_interval_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	return atomic64_read(&max_skip_interval);
}

static u64 empty_round_check_threshold_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	return atomic64_read(&empty_round_check_threshold);
}

static u64 anon_refault_snapshot_min_interval_read(
		struct cgroup_subsys_state *css, struct cftype *cft)
{
	return atomic64_read(&anon_refault_snapshot_min_interval);
}

static u64 zram_critical_threshold_read(struct cgroup_subsys_state *css,
					struct cftype *cft)
{
	return atomic64_read(&zram_critical_threshold);
}

static int zswapd_memcgs_param_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < ZSWAPD_MAX_LEVEL_NUM; ++i) {
		seq_printf(m, "level %d min score: %u\n", i,
			zswap_param[i].min_score);
		seq_printf(m, "level %d max score: %u\n", i,
			zswap_param[i].max_score);
		seq_printf(m, "level %d ub_mem2zram_ratio: %u\n", i,
			zswap_param[i].ub_mem2zram_ratio);
		seq_printf(m, "level %d ub_zram2ufs_ratio: %u\n", i,
			zswap_param[i].ub_zram2ufs_ratio);
		seq_printf(m, "level %d refault_threshold: %u\n", i,
			zswap_param[i].refault_threshold);
	}

	return 0;
}

static int zswapd_single_memcg_param_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));

	seq_printf(m, "memcg score: %llu\n",
		atomic64_read(&memcg->memcg_reclaimed.app_score));
	seq_printf(m, "memcg ub_mem2zram_ratio: %u\n",
		atomic_read(&memcg->memcg_reclaimed.ub_mem2zram_ratio));
	seq_printf(m, "memcg ub_zram2ufs_ratio: %u\n",
		atomic_read(&memcg->memcg_reclaimed.ub_zram2ufs_ratio));
	seq_printf(m, "memcg refault_threshold: %u\n",
		atomic_read(&memcg->memcg_reclaimed.refault_threshold));

	return 0;
}

static int zram_wm_ratio_show(struct seq_file *m, void *v)
{
	seq_printf(m, "zram_wm_ratio: %u\n", atomic_read(&zram_wm_ratio));

	return 0;
}

static int compress_ratio_show(struct seq_file *m, void *v)
{
	seq_printf(m, "compress_ratio: %u\n", atomic_read(&compress_ratio));

	return 0;
}

static int zswapd_vmstat_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_VM_EVENT_COUNTERS
	unsigned long *vm_buf = NULL;

	vm_buf = kzalloc(sizeof(struct vm_event_state), GFP_KERNEL);
	if (!vm_buf)
		return -ENOMEM;
	all_vm_events(vm_buf);

	seq_printf(m, "zswapd_wake_up:%lu\n", vm_buf[ZSWAPD_WAKEUP]);
	seq_printf(m, "zswapd_area_refault:%lu\n", vm_buf[ZSWAPD_REFAULT]);
	seq_printf(m, "zswapd_medium_press:%lu\n", vm_buf[ZSWAPD_MEDIUM_PRESS]);
	seq_printf(m, "zswapd_critical_press:%lu\n", vm_buf[ZSWAPD_CRITICAL_PRESS]);
	seq_printf(m, "zswapd_memcg_ratio_skip:%lu\n", vm_buf[ZSWAPD_MEMCG_RATIO_SKIP]);
	seq_printf(m, "zswapd_memcg_refault_skip:%lu\n", vm_buf[ZSWAPD_MEMCG_REFAULT_SKIP]);
	seq_printf(m, "zswapd_swapout:%lu\n", vm_buf[ZSWAPD_SWAPOUT]);
	seq_printf(m, "zswapd_snapshot_times:%lu\n", vm_buf[ZSWAPD_SNAPSHOT_TIMES]);
	seq_printf(m, "zswapd_reclaimed:%lu\n", vm_buf[ZSWAPD_RECLAIMED]);
	seq_printf(m, "zswapd_scanned:%lu\n", vm_buf[ZSWAPD_SCANNED]);

	kfree(vm_buf);
#endif

	return 0;
}

static int eswap_info_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	unsigned long long eswap_size;

	eswap_size = memcg_data_size(memcg, WRITE_SIZE) / SZ_1K;
	seq_printf(m, "Total Swapout Size: %llu kB\n", eswap_size);

	return 0;
}

void memcg_eswap_info_show(struct seq_file *m)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	struct mem_cgroup_per_node *mz = NULL;
	struct lruvec *lruvec = NULL;
	unsigned long anon;
	unsigned long file;
	unsigned long zram;
	unsigned long eswap;

	mz = mem_cgroup_nodeinfo(memcg, 0);
	if (!mz)
		return;

	lruvec = &mz->lruvec;
	if (!lruvec)
		return;

	anon = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES);
	file = lruvec_lru_size(lruvec, LRU_ACTIVE_FILE, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_FILE, MAX_NR_ZONES);
	zram = memcg_data_size(memcg, CACHE_SIZE) / SZ_1K;
	eswap = memcg_data_size(memcg, SWAP_SIZE) / SZ_1K;
	anon *= PAGE_SIZE / SZ_1K;
	file *= PAGE_SIZE / SZ_1K;
	seq_printf(m, "Anon:\t%12lu kB\nFile:\t%12lu kB\nzram:\t%12lu kB\nEswap:\t%12lu kB\n",
		anon, file, zram, eswap);
}
#endif

static struct cftype zswapd_policy_files[] = {
	{
		.name = "active_app_info_list",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = memcg_active_app_info_list_show,
	},
	{
		.name = "zram_wm_ratio",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write = mem_cgroup_zram_wm_ratio_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.seq_show = zram_wm_ratio_show,
#endif
	},
	{
		.name = "compress_ratio",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write = mem_cgroup_compress_ratio_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.seq_show = compress_ratio_show,
#endif
	},
	{
		.name = "zswapd_pressure",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write = zswapd_pressure_event_control,
	},
	{
		.name = "zswapd_pid",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.read_u64 = zswapd_pid_read,
	},
	{
		.name = "avail_buffers",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write = avail_buffers_params_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.seq_show = avail_buffers_params_show,
#endif
	},
	{
		.name = "zswapd_max_reclaim_size",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write = zswapd_max_reclaim_size_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.seq_show = zswapd_max_reclaim_size_show,
#endif
	},
	{
		.name = "area_anon_refault_threshold",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write_u64 = area_anon_refault_threshold_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.read_u64 = area_anon_refault_threshold_read,
#endif
	},
	{
		.name = "empty_round_skip_interval",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write_u64 = empty_round_skip_interval_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.read_u64 = empty_round_skip_interval_read,
#endif
	},
	{
		.name = "max_skip_interval",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write_u64 = max_skip_interval_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.read_u64 = max_skip_interval_read,
#endif
	},
	{
		.name = "empty_round_check_threshold",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write_u64 = empty_round_check_threshold_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.read_u64 = empty_round_check_threshold_read,
#endif
	},
	{
		.name = "anon_refault_snapshot_min_interval",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write_u64 = anon_refault_snapshot_min_interval_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.read_u64 = anon_refault_snapshot_min_interval_read,
#endif
	},
	{
		.name = "zswapd_memcgs_param",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write = zswapd_memcgs_param_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.seq_show = zswapd_memcgs_param_show,
#endif
	},
	{
		.name = "zswapd_single_memcg_param",
		.write = zswapd_single_memcg_param_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.seq_show = zswapd_single_memcg_param_show,
#endif
	},
	{
		.name = "buffer_ratio_params",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write = buffers_ratio_params_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.seq_show = buffers_ratio_params_show,
#endif
	},
	{
		.name = "zswapd_pressure_show",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = zswapd_pressure_show,
	},
	{
		.name = "zram_critical_threshold",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.write_u64 = zram_critical_thres_write,
#ifdef CONFIG_HYPERHOLD_DEBUG
		.read_u64 = zram_critical_threshold_read,
#endif
	},

#ifdef CONFIG_HYPERHOLD_DEBUG
	{
		.name = "zswapd_vmstat_show",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = zswapd_vmstat_show,
	},
#endif
	{
		.name = "eswap_info",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = eswap_info_show,
	},

	{ },	/* terminate */
};

static int __init zswapd_policy_init(void)
{
	if (!mem_cgroup_disabled())
		WARN_ON(cgroup_add_legacy_cftypes(&memory_cgrp_subsys, zswapd_policy_files));

	return 0;
}
subsys_initcall(zswapd_policy_init);
