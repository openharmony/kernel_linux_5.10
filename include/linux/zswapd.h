/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/zswapd.h
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

#ifndef _ZSWAPD_H
#define _ZSWAPD_H

enum {
	CACHE_SIZE,
	SWAP_SIZE,
	CACHE_PAGE,
	SWAP_PAGE,
	CACHE_FAULT,
	SWAP_FAULT,
	READ_SIZE,
	WRITE_SIZE,
};

struct group_swap_ops {
	u64 (*group_read)(u16 gid, u64 req_size, void *priv);
	u64 (*group_write)(u16 gid, u64 req_size, void *priv);
	u64 (*group_data_size)(u16 gid, int type, void *priv);
};

struct group_swap_device {
	void *priv;
	struct group_swap_ops *ops;
	struct list_head list;
};

#ifdef CONFIG_HYPERHOLD_ZSWAPD
extern int zswapd_run(int nid);
extern void zswapd_stop(int nid);
extern void wakeup_zswapd(pg_data_t *pgdat);
extern bool zram_watermark_ok(void);
extern void zswapd_status_show(struct seq_file *m);
extern void wake_all_zswapd(void);
extern void set_snapshotd_init_flag(unsigned int val);
extern pid_t get_zswapd_pid(void);
extern unsigned long long get_free_swap_threshold(void);
extern struct group_swap_device *register_group_swap(struct group_swap_ops *ops, void *priv);
extern void unregister_group_swap(struct group_swap_device *gsdev);
extern void memcg_eswap_info_show(struct seq_file *m);
#else
static inline int zswap_run(int nid)
{
	return 0;
}

static inline void zswapd_stop(int nid)
{
}

static inline void wakeup_zswapd(pg_data_t *pgdat)
{
}

static inline bool zram_watermark_ok(void)
{
	return true;
}

static inline void zswapd_status_show(struct seq_file *m)
{
}

static inline void wake_all_zswapd(void)
{
}

static inline void set_snapshotd_init_flag(unsigned int val)
{
}

static inline pid_t get_zswapd_pid(void)
{
	return -EINVAL;
}

static inline u64 get_free_swap_threshold(void)
{
	return 0;
}

static struct group_swap_device *register_group_swap(struct group_swap_ops *ops, void *priv)
{
	return NULL;
}

static void unregister_group_swap(struct group_swap_device *gsdev)
{
}

static void memcg_eswap_info_show(struct seq_file *m)
{
}
#endif

#endif /* _LINUX_ZSWAPD_H */
