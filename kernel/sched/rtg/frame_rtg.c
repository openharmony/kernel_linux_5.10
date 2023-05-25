// SPDX-License-Identifier: GPL-2.0
/*
 * Frame-based load tracking for rt_frame and RTG
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */

#include "frame_rtg.h"
#include "rtg.h"

#include <linux/sched.h>
#include <trace/events/rtg.h>
#include <../kernel/sched/sched.h>
#include <uapi/linux/sched/types.h>

static struct multi_frame_id_manager g_id_manager = {
	.id_map = {0},
	.offset = 0,
	.lock = __RW_LOCK_UNLOCKED(g_id_manager.lock)
};

static struct frame_info g_multi_frame_info[MULTI_FRAME_NUM];

static bool is_rtg_rt_task(struct task_struct *task)
{
	bool ret = false;

	if (!task)
		return ret;

	ret = ((task->prio < MAX_RT_PRIO) &&
	       (task->rtg_depth == STATIC_RTG_DEPTH));

	return ret;
}

#ifdef CONFIG_SCHED_RTG_RT_THREAD_LIMIT
static atomic_t g_rtg_rt_thread_num = ATOMIC_INIT(0);

static unsigned int _get_rtg_rt_thread_num(struct related_thread_group *grp)
{
	unsigned int rtg_rt_thread_num = 0;
	struct task_struct *p = NULL;

	if (list_empty(&grp->tasks))
		goto out;

	list_for_each_entry(p, &grp->tasks, grp_list) {
		if (is_rtg_rt_task(p))
			++rtg_rt_thread_num;
	}

out:
	return rtg_rt_thread_num;
}

static unsigned int get_rtg_rt_thread_num(void)
{
	struct related_thread_group *grp = NULL;
	unsigned int total_rtg_rt_thread_num = 0;
	unsigned long flag;
	unsigned int i;

	for (i = MULTI_FRAME_ID; i < MULTI_FRAME_ID + MULTI_FRAME_NUM; i++) {
		grp = lookup_related_thread_group(i);
		if (grp == NULL)
			continue;
		raw_spin_lock_irqsave(&grp->lock, flag);
		total_rtg_rt_thread_num += _get_rtg_rt_thread_num(grp);
		raw_spin_unlock_irqrestore(&grp->lock, flag);
	}

	return total_rtg_rt_thread_num;
}

static void inc_rtg_rt_thread_num(void)
{
	atomic_inc(&g_rtg_rt_thread_num);
}

static void dec_rtg_rt_thread_num(void)
{
	atomic_dec_if_positive(&g_rtg_rt_thread_num);
}

static int test_and_read_rtg_rt_thread_num(void)
{
	if (atomic_read(&g_rtg_rt_thread_num) >= RTG_MAX_RT_THREAD_NUM)
		atomic_set(&g_rtg_rt_thread_num, get_rtg_rt_thread_num());

	return atomic_read(&g_rtg_rt_thread_num);
}

int read_rtg_rt_thread_num(void)
{
	return atomic_read(&g_rtg_rt_thread_num);
}
#else
static inline void inc_rtg_rt_thread_num(void) { }
static inline void dec_rtg_rt_thread_num(void) { }
static inline int test_and_read_rtg_rt_thread_num(void)
{
	return 0;
}
#endif

bool is_frame_rtg(int id)
{
	return (id >= MULTI_FRAME_ID) &&
		(id < (MULTI_FRAME_ID + MULTI_FRAME_NUM));
}

static struct related_thread_group *frame_rtg(int id)
{
	if (!is_frame_rtg(id))
		return NULL;

	return lookup_related_thread_group(id);
}

struct frame_info *rtg_frame_info(int id)
{
	if (!is_frame_rtg(id))
		return NULL;

	return rtg_active_multi_frame_info(id);
}

static int alloc_rtg_id(void)
{
	unsigned int id_offset;
	int id;

	write_lock(&g_id_manager.lock);
	id_offset = find_next_zero_bit(g_id_manager.id_map, MULTI_FRAME_NUM,
				       g_id_manager.offset);
	if (id_offset >= MULTI_FRAME_NUM) {
		id_offset = find_first_zero_bit(g_id_manager.id_map,
						MULTI_FRAME_NUM);
		if (id_offset >= MULTI_FRAME_NUM) {
			write_unlock(&g_id_manager.lock);
			return -EINVAL;
		}
	}

	set_bit(id_offset, g_id_manager.id_map);
	g_id_manager.offset = id_offset;
	id = id_offset + MULTI_FRAME_ID;
	write_unlock(&g_id_manager.lock);
	pr_debug("[FRAME_RTG] %s id_offset=%u, id=%d\n", __func__, id_offset, id);

	return id;
}

static void free_rtg_id(int id)
{
	unsigned int id_offset = id - MULTI_FRAME_ID;

	if (id_offset >= MULTI_FRAME_NUM) {
		pr_err("[FRAME_RTG] %s id_offset is invalid, id=%d, id_offset=%u.\n",
		       __func__, id, id_offset);
		return;
	}

	pr_debug("[FRAME_RTG] %s id=%d id_offset=%u\n", __func__, id, id_offset);
	write_lock(&g_id_manager.lock);
	clear_bit(id_offset, g_id_manager.id_map);
	write_unlock(&g_id_manager.lock);
}

int set_frame_rate(struct frame_info *frame_info, int rate)
{
	int id;

	if ((rate < MIN_FRAME_RATE) || (rate > MAX_FRAME_RATE)) {
		pr_err("[FRAME_RTG]: %s invalid QOS(rate) value\n",
			__func__);
		return -EINVAL;
	}

	if (!frame_info || !frame_info->rtg)
		return -EINVAL;

	frame_info->frame_rate = (unsigned int)rate;
	frame_info->frame_time = div_u64(NSEC_PER_SEC, rate);
	frame_info->max_vload_time =
		div_u64(frame_info->frame_time, NSEC_PER_MSEC) +
		frame_info->vload_margin;
	id = frame_info->rtg->id;
	trace_rtg_frame_sched(id, "FRAME_QOS", rate);
	trace_rtg_frame_sched(id, "FRAME_MAX_TIME", frame_info->max_vload_time);

	return 0;
}

int alloc_multi_frame_info(void)
{
	struct frame_info *frame_info = NULL;
	int id;
	int i;

	id = alloc_rtg_id();
	if (id < 0)
		return id;

	frame_info = rtg_frame_info(id);
	if (!frame_info) {
		free_rtg_id(id);
		return -EINVAL;
	}

	set_frame_rate(frame_info, DEFAULT_FRAME_RATE);
	atomic_set(&frame_info->curr_rt_thread_num, 0);
	atomic_set(&frame_info->max_rt_thread_num, DEFAULT_MAX_RT_THREAD);
	for (i = 0; i < MAX_TID_NUM; i++)
		atomic_set(&frame_info->thread_prio[i], 0);

	return id;
}

void release_multi_frame_info(int id)
{
	if ((id < MULTI_FRAME_ID) || (id >= MULTI_FRAME_ID + MULTI_FRAME_NUM)) {
		pr_err("[FRAME_RTG] %s frame(id=%d) not found.\n", __func__, id);
		return;
	}

	read_lock(&g_id_manager.lock);
	if (!test_bit(id - MULTI_FRAME_ID, g_id_manager.id_map)) {
		read_unlock(&g_id_manager.lock);
		return;
	}
	read_unlock(&g_id_manager.lock);

	pr_debug("[FRAME_RTG] %s release frame(id=%d).\n", __func__, id);
	free_rtg_id(id);
}

void clear_multi_frame_info(void)
{
	write_lock(&g_id_manager.lock);
	bitmap_zero(g_id_manager.id_map, MULTI_FRAME_NUM);
	g_id_manager.offset = 0;
	write_unlock(&g_id_manager.lock);
}

struct frame_info *rtg_active_multi_frame_info(int id)
{
	struct frame_info *frame_info = NULL;

	if ((id < MULTI_FRAME_ID) || (id >= MULTI_FRAME_ID + MULTI_FRAME_NUM))
		return NULL;

	read_lock(&g_id_manager.lock);
	if (test_bit(id - MULTI_FRAME_ID, g_id_manager.id_map))
		frame_info = &g_multi_frame_info[id - MULTI_FRAME_ID];
	read_unlock(&g_id_manager.lock);
	if (!frame_info)
		pr_debug("[FRAME_RTG] %s frame %d has been released\n",
			 __func__, id);

	return frame_info;
}

struct frame_info *rtg_multi_frame_info(int id)
{
	if ((id < MULTI_FRAME_ID) || (id >= MULTI_FRAME_ID + MULTI_FRAME_NUM))
		return NULL;

	return &g_multi_frame_info[id - MULTI_FRAME_ID];
}

static void do_update_frame_task_prio(struct frame_info *frame_info,
				      struct task_struct *task, int prio)
{
	int policy = SCHED_NORMAL;
	struct sched_param sp = {0};
	bool is_rt_task = (prio != NOT_RT_PRIO);
	bool need_dec_flag = false;
	bool need_inc_flag = false;
	int err;

	trace_rtg_frame_sched(frame_info->rtg->id, "rtg_rt_thread_num",
			      read_rtg_rt_thread_num());
	/* change policy to RT */
	if (is_rt_task && (atomic_read(&frame_info->curr_rt_thread_num) <
			   atomic_read(&frame_info->max_rt_thread_num))) {
		/* change policy from CFS to RT */
		if (!is_rtg_rt_task(task)) {
			if (test_and_read_rtg_rt_thread_num() >= RTG_MAX_RT_THREAD_NUM)
				goto out;
			need_inc_flag = true;
		}
		/* change RT priority */
		policy = SCHED_FIFO | SCHED_RESET_ON_FORK;
		sp.sched_priority = MAX_USER_RT_PRIO - 1 - prio;
		atomic_inc(&frame_info->curr_rt_thread_num);
	} else {
		/* change policy from RT to CFS */
		if (!is_rt_task && is_rtg_rt_task(task))
			need_dec_flag = true;
	}
out:
	trace_rtg_frame_sched(frame_info->rtg->id, "rtg_rt_thread_num",
			      read_rtg_rt_thread_num());
	trace_rtg_frame_sched(frame_info->rtg->id, "curr_rt_thread_num",
			      atomic_read(&frame_info->curr_rt_thread_num));
	err = sched_setscheduler_nocheck(task, policy, &sp);
	if (err == 0) {
		if (need_dec_flag)
			dec_rtg_rt_thread_num();
		else if (need_inc_flag)
			inc_rtg_rt_thread_num();
	}
}

int list_rtg_group(struct rtg_info *rs_data)
{
	int i;
	int num = 0;

	read_lock(&g_id_manager.lock);
	for (i = MULTI_FRAME_ID; i < MULTI_FRAME_ID + MULTI_FRAME_NUM; i++) {
		if (test_bit(i - MULTI_FRAME_ID, g_id_manager.id_map)) {
			rs_data->rtgs[num] = i;
			num++;
		}
	}
	read_unlock(&g_id_manager.lock);
	rs_data->rtg_num = num;

	return num;
}

int search_rtg(int pid)
{
	struct rtg_info grp_info;
	struct frame_info *frame_info = NULL;
	int i = 0;
	int j = 0;

	grp_info.rtg_num = 0;
	read_lock(&g_id_manager.lock);
	for (i = MULTI_FRAME_ID; i < MULTI_FRAME_ID + MULTI_FRAME_NUM; i++) {
		if (test_bit(i - MULTI_FRAME_ID, g_id_manager.id_map)) {
			grp_info.rtgs[grp_info.rtg_num] = i;
			grp_info.rtg_num++;
		}
	}
	read_unlock(&g_id_manager.lock);
	for (i = 0; i < grp_info.rtg_num; i++) {
		frame_info = lookup_frame_info_by_grp_id(grp_info.rtgs[i]);
		if (!frame_info) {
			pr_err("[FRAME_RTG] unexpected grp %d find error.", i);
			return -EINVAL;
		}

		for (j = 0; j < frame_info->thread_num; j++) {
			if (frame_info->thread[j] && frame_info->thread[j]->pid == pid)
				return grp_info.rtgs[i];
		}
	}

	return 0;
}

static void update_frame_task_prio(struct frame_info *frame_info, int prio)
{
	int i;
	struct task_struct *thread = NULL;

	/* reset curr_rt_thread_num */
	atomic_set(&frame_info->curr_rt_thread_num, 0);

	for (i = 0; i < MAX_TID_NUM; i++) {
		thread = frame_info->thread[i];
		if (thread)
			do_update_frame_task_prio(frame_info, thread, prio);
	}
}

void set_frame_prio(struct frame_info *frame_info, int prio)
{
	if (!frame_info)
		return;

	mutex_lock(&frame_info->lock);
	if (frame_info->prio == prio)
		goto out;

	update_frame_task_prio(frame_info, prio);
	frame_info->prio = prio;
out:
	mutex_unlock(&frame_info->lock);
}

static int do_set_rtg_sched(struct task_struct *task, bool is_rtg,
			    int grp_id, int prio)
{
	int err;
	int policy = SCHED_NORMAL;
	int grpid = DEFAULT_RTG_GRP_ID;
	bool is_rt_task = (prio != NOT_RT_PRIO);
	struct sched_param sp = {0};

	if (is_rtg) {
		if (is_rt_task) {
			if (test_and_read_rtg_rt_thread_num() >= RTG_MAX_RT_THREAD_NUM)
				// rtg_rt_thread_num is inavailable, set policy to CFS
				goto skip_setpolicy;
			policy = SCHED_FIFO | SCHED_RESET_ON_FORK;
			sp.sched_priority = MAX_USER_RT_PRIO - 1 - prio;
		}
skip_setpolicy:
		grpid = grp_id;
	}
	err = sched_setscheduler_nocheck(task, policy, &sp);
	if (err < 0) {
		pr_err("[FRAME_RTG]: %s task:%d setscheduler err:%d\n",
				__func__, task->pid, err);
		return err;
	}
	err = sched_set_group_id(task, grpid);
	if (err < 0) {
		pr_err("[FRAME_RTG]: %s task:%d set_group_id err:%d\n",
				__func__, task->pid, err);
		if (is_rtg) {
			policy = SCHED_NORMAL;
			sp.sched_priority = 0;
			sched_setscheduler_nocheck(task, policy, &sp);
		}
	}
	if (err == 0) {
		if (is_rtg) {
			if (policy != SCHED_NORMAL)
				inc_rtg_rt_thread_num();
		} else {
			dec_rtg_rt_thread_num();
		}
	}

	return err;
}

static int set_rtg_sched(struct task_struct *task, bool is_rtg,
			 int grp_id, int prio)
{
	int err = -1;
	bool is_rt_task = (prio != NOT_RT_PRIO);

	if (!task)
		return err;

	if (is_rt_task && is_rtg && ((prio < 0) ||
		(prio > MAX_USER_RT_PRIO - 1)))
		return err;
	/*
	 * original logic deny the non-cfs task st rt.
	 * add !fair_policy(task->policy) if needed
	 *
	 * if CONFIG_HW_FUTEX_PI is set, task->prio and task->sched_class
	 * may be modified by rtmutex. So we use task->policy instead.
	 */
	if (is_rtg && task->flags & PF_EXITING)
		return err;

	if (in_interrupt()) {
		pr_err("[FRAME_RTG]: %s is in interrupt\n", __func__);
		return err;
	}

	return do_set_rtg_sched(task, is_rtg, grp_id, prio);
}

static bool set_frame_rtg_thread(int grp_id, struct task_struct *task,
				 bool is_rtg, int prio)
{
	int depth;

	if (!task)
		return false;
	depth = task->rtg_depth;
	if (is_rtg)
		task->rtg_depth = STATIC_RTG_DEPTH;
	else
		task->rtg_depth = 0;

	if (set_rtg_sched(task, is_rtg, grp_id, prio) < 0) {
		task->rtg_depth = depth;
		return false;
	}

	return true;
}

struct task_struct *update_frame_thread(struct frame_info *frame_info,
					int old_prio, int prio, int pid,
					struct task_struct *old_task)
{
	struct task_struct *task = NULL;
	bool is_rt_task = (prio != NOT_RT_PRIO);
	int new_prio = prio;
	bool update_ret = false;

	if (pid > 0) {
		if (old_task && (pid == old_task->pid) && (old_prio == new_prio)) {
			if (is_rt_task && atomic_read(&frame_info->curr_rt_thread_num) <
			    atomic_read(&frame_info->max_rt_thread_num) &&
			    (atomic_read(&frame_info->frame_sched_state) == 1))
				atomic_inc(&frame_info->curr_rt_thread_num);
			trace_rtg_frame_sched(frame_info->rtg->id, "curr_rt_thread_num",
					      atomic_read(&frame_info->curr_rt_thread_num));
			return old_task;
		}
		rcu_read_lock();
		task = find_task_by_vpid(pid);
		if (task)
			get_task_struct(task);
		rcu_read_unlock();
	}
	trace_rtg_frame_sched(frame_info->rtg->id, "FRAME_SCHED_ENABLE",
			      atomic_read(&frame_info->frame_sched_state));
	if (atomic_read(&frame_info->frame_sched_state) == 1) {
		if (task && is_rt_task) {
			if (atomic_read(&frame_info->curr_rt_thread_num) <
			    atomic_read(&frame_info->max_rt_thread_num))
				atomic_inc(&frame_info->curr_rt_thread_num);
			else
				new_prio = NOT_RT_PRIO;
		}
		trace_rtg_frame_sched(frame_info->rtg->id, "curr_rt_thread_num",
				      atomic_read(&frame_info->curr_rt_thread_num));
		trace_rtg_frame_sched(frame_info->rtg->id, "rtg_rt_thread_num",
				      read_rtg_rt_thread_num());

		set_frame_rtg_thread(frame_info->rtg->id, old_task, false, NOT_RT_PRIO);
		update_ret = set_frame_rtg_thread(frame_info->rtg->id, task, true, new_prio);
	}
	if (old_task)
		put_task_struct(old_task);
	if (!update_ret)
		return NULL;

	return task;
}

void update_frame_thread_info(struct frame_info *frame_info,
			      struct frame_thread_info *frame_thread_info)
{
	int i;
	int old_prio;
	int prio;
	int thread_num;
	int real_thread;

	if (!frame_info || !frame_thread_info ||
		frame_thread_info->thread_num < 0)
		return;

	prio = frame_thread_info->prio;
	thread_num = frame_thread_info->thread_num;
	if (thread_num > MAX_TID_NUM)
		thread_num = MAX_TID_NUM;

	// reset curr_rt_thread_num
	atomic_set(&frame_info->curr_rt_thread_num, 0);
	mutex_lock(&frame_info->lock);
	old_prio = frame_info->prio;
	real_thread = 0;
	for (i = 0; i < thread_num; i++) {
		atomic_set(&frame_info->thread_prio[i], 0);
		frame_info->thread[i] = update_frame_thread(frame_info, old_prio, prio,
							    frame_thread_info->thread[i],
							    frame_info->thread[i]);
		if (frame_info->thread[i] && (frame_thread_info->thread[i] > 0))
			real_thread++;
	}
	frame_info->prio = prio;
	frame_info->thread_num = real_thread;
	mutex_unlock(&frame_info->lock);
}

static void do_set_frame_sched_state(struct frame_info *frame_info,
				     struct task_struct *task,
				     bool enable, int prio)
{
	int new_prio = prio;
	bool is_rt_task = (prio != NOT_RT_PRIO);

	if (enable && is_rt_task) {
		if (atomic_read(&frame_info->curr_rt_thread_num) <
		    atomic_read(&frame_info->max_rt_thread_num))
			atomic_inc(&frame_info->curr_rt_thread_num);
		else
			new_prio = NOT_RT_PRIO;
	}
	trace_rtg_frame_sched(frame_info->rtg->id, "curr_rt_thread_num",
			      atomic_read(&frame_info->curr_rt_thread_num));
	trace_rtg_frame_sched(frame_info->rtg->id, "rtg_rt_thread_num",
			      read_rtg_rt_thread_num());
	set_frame_rtg_thread(frame_info->rtg->id, task, enable, new_prio);
}

void set_frame_sched_state(struct frame_info *frame_info, bool enable)
{
	atomic_t *frame_sched_state = NULL;
	int prio;
	int i;

	if (!frame_info || !frame_info->rtg)
		return;

	frame_sched_state = &(frame_info->frame_sched_state);
	if (enable) {
		if (atomic_read(frame_sched_state) == 1)
			return;
		atomic_set(frame_sched_state, 1);
		trace_rtg_frame_sched(frame_info->rtg->id, "FRAME_SCHED_ENABLE", 1);

		frame_info->prev_fake_load_util = 0;
		frame_info->prev_frame_load_util = 0;
		frame_info->frame_vload = 0;
		frame_info_rtg_load(frame_info)->curr_window_load = 0;
	} else {
		if (atomic_read(frame_sched_state) == 0)
			return;
		atomic_set(frame_sched_state, 0);
		trace_rtg_frame_sched(frame_info->rtg->id, "FRAME_SCHED_ENABLE", 0);

		(void)sched_set_group_normalized_util(frame_info->rtg->id,
						      0, RTG_FREQ_NORMAL_UPDATE);
		trace_rtg_frame_sched(frame_info->rtg->id, "preferred_cluster",
			INVALID_PREFERRED_CLUSTER);
		frame_info->status = FRAME_END;
	}

	/* reset curr_rt_thread_num */
	atomic_set(&frame_info->curr_rt_thread_num, 0);
	mutex_lock(&frame_info->lock);
	for (i = 0; i < MAX_TID_NUM; i++) {
		if (frame_info->thread[i]) {
			prio = atomic_read(&frame_info->thread_prio[i]);
			do_set_frame_sched_state(frame_info, frame_info->thread[i],
						 enable, prio);
		}
	}
	mutex_unlock(&frame_info->lock);

	trace_rtg_frame_sched(frame_info->rtg->id, "FRAME_STATUS",
			      frame_info->status);
	trace_rtg_frame_sched(frame_info->rtg->id, "frame_status",
			      frame_info->status);
}

static inline bool check_frame_util_invalid(const struct frame_info *frame_info,
	u64 timeline)
{
	return ((frame_info_rtg(frame_info)->util_invalid_interval <= timeline) &&
		(frame_info_rtg_load(frame_info)->curr_window_exec * FRAME_UTIL_INVALID_FACTOR
		 <= timeline));
}

static u64 calc_prev_fake_load_util(const struct frame_info *frame_info)
{
	u64 prev_frame_load = frame_info->prev_frame_load;
	u64 prev_frame_time = max_t(unsigned long, frame_info->prev_frame_time,
		frame_info->frame_time);
	u64 frame_util = 0;

	if (prev_frame_time > 0)
		frame_util = div_u64((prev_frame_load << SCHED_CAPACITY_SHIFT),
			prev_frame_time);
	frame_util = clamp_t(unsigned long, frame_util,
		frame_info->prev_min_util,
		frame_info->prev_max_util);

	return frame_util;
}

static u64 calc_prev_frame_load_util(const struct frame_info *frame_info)
{
	u64 prev_frame_load = frame_info->prev_frame_load;
	u64 frame_time = frame_info->frame_time;
	u64 frame_util = 0;

	if (prev_frame_load >= frame_time)
		frame_util = FRAME_MAX_LOAD;
	else
		frame_util = div_u64((prev_frame_load << SCHED_CAPACITY_SHIFT),
			frame_info->frame_time);
	frame_util = clamp_t(unsigned long, frame_util,
		frame_info->prev_min_util,
		frame_info->prev_max_util);

	return frame_util;
}

/* last frame load tracking */
static void update_frame_prev_load(struct frame_info *frame_info, bool fake)
{
	/* last frame load tracking */
	frame_info->prev_frame_exec =
		frame_info_rtg_load(frame_info)->prev_window_exec;
	frame_info->prev_frame_time =
		frame_info_rtg(frame_info)->prev_window_time;
	frame_info->prev_frame_load =
		frame_info_rtg_load(frame_info)->prev_window_load;

	if (fake)
		frame_info->prev_fake_load_util =
			calc_prev_fake_load_util(frame_info);
	else
		frame_info->prev_frame_load_util =
			calc_prev_frame_load_util(frame_info);
}

static void do_frame_end(struct frame_info *frame_info, bool fake)
{
	unsigned long prev_util;
	int id = frame_info->rtg->id;

	frame_info->status = FRAME_END;
	trace_rtg_frame_sched(id, "frame_status", frame_info->status);

	/* last frame load tracking */
	update_frame_prev_load(frame_info, fake);

	/* reset frame_info */
	frame_info->frame_vload = 0;

	/* reset frame_min_util */
	frame_info->frame_min_util = 0;

	if (fake)
		prev_util = frame_info->prev_fake_load_util;
	else
		prev_util = frame_info->prev_frame_load_util;

	frame_info->frame_util = clamp_t(unsigned long, prev_util,
		frame_info->frame_min_util,
		frame_info->frame_max_util);

	trace_rtg_frame_sched(id, "frame_last_task_time",
		frame_info->prev_frame_exec);
	trace_rtg_frame_sched(id, "frame_last_time", frame_info->prev_frame_time);
	trace_rtg_frame_sched(id, "frame_last_load", frame_info->prev_frame_load);
	trace_rtg_frame_sched(id, "frame_last_load_util",
		frame_info->prev_frame_load_util);
	trace_rtg_frame_sched(id, "frame_util", frame_info->frame_util);
	trace_rtg_frame_sched(id, "frame_vload", frame_info->frame_vload);
}

/*
 * frame_load : calculate frame load using exec util
 */
static inline u64 calc_frame_exec(const struct frame_info *frame_info)
{
	if (frame_info->frame_time > 0)
		return div_u64((frame_info_rtg_load(frame_info)->curr_window_exec <<
			SCHED_CAPACITY_SHIFT), frame_info->frame_time);
	else
		return 0;
}

/*
 * real_util:
 * max(last_util, virtual_util, boost_util, phase_util, frame_min_util)
 */
static u64 calc_frame_util(const struct frame_info *frame_info, bool fake)
{
	unsigned long load_util;

	if (fake)
		load_util = frame_info->prev_fake_load_util;
	else
		load_util = frame_info->prev_frame_load_util;

	load_util = max_t(unsigned long, load_util, frame_info->frame_vload);
	load_util = clamp_t(unsigned long, load_util,
		frame_info->frame_min_util,
		frame_info->frame_max_util);

	return load_util;
}

/*
 * frame_vload [0~1024]
 * vtime: now - timestamp
 * max_time: frame_info->frame_time + vload_margin
 * load = F(vtime)
 *      = vtime ^ 2 - vtime * max_time + FRAME_MAX_VLOAD * vtime / max_time;
 *      = vtime * (vtime + FRAME_MAX_VLOAD / max_time - max_time);
 * [0, 0] -=> [max_time, FRAME_MAX_VLOAD]
 *
 */
static u64 calc_frame_vload(const struct frame_info *frame_info, u64 timeline)
{
	u64 vload;
	int vtime = div_u64(timeline, NSEC_PER_MSEC);
	int max_time = frame_info->max_vload_time;
	int factor;

	if ((max_time <= 0) || (vtime > max_time))
		return FRAME_MAX_VLOAD;

	factor = vtime + FRAME_MAX_VLOAD / max_time;
	/* margin maybe negative */
	if ((vtime <= 0) || (factor <= max_time))
		return 0;

	vload = (u64)vtime * (u64)(factor - max_time);

	return vload;
}

static int update_frame_info_tick_inner(int id, struct frame_info *frame_info,
	u64 timeline)
{
	switch (frame_info->status) {
	case FRAME_INVALID:
	case FRAME_END:
		if (timeline >= frame_info->frame_time) {
			/*
			 * fake FRAME_END here to rollover frame_window.
			 */
			sched_set_group_window_rollover(id);
			do_frame_end(frame_info, true);
		} else {
			frame_info->frame_vload = calc_frame_exec(frame_info);
			frame_info->frame_util =
				calc_frame_util(frame_info, true);
		}

		/* when not in boost, start tick timer */
		break;
	case FRAME_START:
		/* check frame_util invalid */
		if (!check_frame_util_invalid(frame_info, timeline)) {
			/* frame_vload statistic */
			frame_info->frame_vload = calc_frame_vload(frame_info, timeline);
			/* frame_util statistic */
			frame_info->frame_util =
				calc_frame_util(frame_info, false);
		} else {
			frame_info->status = FRAME_INVALID;
			trace_rtg_frame_sched(id, "FRAME_STATUS",
				frame_info->status);
			trace_rtg_frame_sched(id, "frame_status",
				frame_info->status);

			/*
			 * trigger FRAME_END to rollover frame_window,
			 * we treat FRAME_INVALID as FRAME_END.
			 */
			sched_set_group_window_rollover(id);
			do_frame_end(frame_info, false);
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static inline struct frame_info *rtg_frame_info_inner(
	const struct related_thread_group *grp)
{
	return (struct frame_info *)grp->private_data;
}

static inline void frame_boost(struct frame_info *frame_info)
{
	if (frame_info->frame_util < frame_info->frame_boost_min_util)
		frame_info->frame_util = frame_info->frame_boost_min_util;
}

/*
 * update CPUFREQ and PLACEMENT when frame task running (in tick) and migration
 */
static void update_frame_info_tick(struct related_thread_group *grp)
{
	u64 window_start;
	u64 wallclock;
	u64 timeline;
	struct frame_info *frame_info = NULL;
	int id = grp->id;

	rcu_read_lock();
	frame_info = rtg_frame_info_inner(grp);
	window_start = grp->window_start;
	rcu_read_unlock();
	if (unlikely(!frame_info))
		return;

	if (atomic_read(&frame_info->frame_sched_state) == 0)
		return;
	trace_rtg_frame_sched(id, "frame_status", frame_info->status);

	wallclock = ktime_get_ns();
	timeline = wallclock - window_start;

	trace_rtg_frame_sched(id, "update_curr_pid", current->pid);
	trace_rtg_frame_sched(id, "frame_timeline", div_u64(timeline, NSEC_PER_MSEC));

	if (update_frame_info_tick_inner(grp->id, frame_info, timeline) == -EINVAL)
		return;

	frame_boost(frame_info);
	trace_rtg_frame_sched(id, "frame_vload", frame_info->frame_vload);
	trace_rtg_frame_sched(id, "frame_util", frame_info->frame_util);

	sched_set_group_normalized_util(grp->id,
		frame_info->frame_util, RTG_FREQ_NORMAL_UPDATE);

	if (grp->preferred_cluster)
		trace_rtg_frame_sched(id, "preferred_cluster",
			grp->preferred_cluster->id);
}

const struct rtg_class frame_rtg_class = {
	.sched_update_rtg_tick = update_frame_info_tick,
};

int set_frame_margin(struct frame_info *frame_info, int margin)
{
	int id;

	if ((margin < MIN_VLOAD_MARGIN) || (margin > MAX_VLOAD_MARGIN)) {
		pr_err("[FRAME_RTG]: %s invalid MARGIN value\n",
			__func__);
		return -EINVAL;
	}

	if (!frame_info || !frame_info->rtg)
		return -EINVAL;

	frame_info->vload_margin = margin;
	frame_info->max_vload_time =
		div_u64(frame_info->frame_time, NSEC_PER_MSEC) +
		frame_info->vload_margin;
	id = frame_info->rtg->id;
	trace_rtg_frame_sched(id, "FRAME_MARGIN", -margin);
	trace_rtg_frame_sched(id, "FRAME_MAX_TIME", frame_info->max_vload_time);

	return 0;
}

static void set_frame_start(struct frame_info *frame_info)
{
	int id = frame_info->rtg->id;

	if (likely(frame_info->status == FRAME_START)) {
		/*
		 * START -=> START -=> ......
		 * FRMAE_START is
		 *	the end of last frame
		 *	the start of the current frame
		 */
		update_frame_prev_load(frame_info, false);
	} else if ((frame_info->status == FRAME_END) ||
		(frame_info->status == FRAME_INVALID)) {
		/* START -=> END -=> [START]
		 *  FRAME_START is
		 *	only the start of current frame
		 * we shoudn't tracking the last rtg-window
		 * [FRAME_END, FRAME_START]
		 * it's not an available frame window
		 */
		update_frame_prev_load(frame_info, true);
		frame_info->status = FRAME_START;
	}
	trace_rtg_frame_sched(id, "FRAME_STATUS", frame_info->status);
	trace_rtg_frame_sched(id, "frame_last_task_time",
		frame_info->prev_frame_exec);
	trace_rtg_frame_sched(id, "frame_last_time", frame_info->prev_frame_time);
	trace_rtg_frame_sched(id, "frame_last_load", frame_info->prev_frame_load);
	trace_rtg_frame_sched(id, "frame_last_load_util",
		frame_info->prev_frame_load_util);

	/* new_frame_start */
	if (!frame_info->margin_imme) {
		frame_info->frame_vload = 0;
		frame_info->frame_util = clamp_t(unsigned long,
			frame_info->prev_frame_load_util,
			frame_info->frame_min_util,
			frame_info->frame_max_util);
	} else {
		frame_info->frame_vload = calc_frame_vload(frame_info, 0);
		frame_info->frame_util = calc_frame_util(frame_info, false);
	}

	trace_rtg_frame_sched(id, "frame_vload", frame_info->frame_vload);
}

static void set_frame_end(struct frame_info *frame_info)
{
	trace_rtg_frame_sched(frame_info->rtg->id, "FRAME_STATUS", FRAME_END);
	do_frame_end(frame_info, false);
}

static int update_frame_timestamp(unsigned long status,
	struct frame_info *frame_info, struct related_thread_group *grp)
{
	int id = frame_info->rtg->id;

	/* SCHED_FRAME timestamp */
	switch (status) {
	case FRAME_START:
		/* collect frame_info when frame_end timestamp coming */
		set_frame_start(frame_info);
		break;
	case FRAME_END:
		/* FRAME_END should only set and update freq once */
		if (unlikely(frame_info->status == FRAME_END))
			return 0;
		set_frame_end(frame_info);
		break;
	default:
		pr_err("[FRAME_RTG]: %s invalid timestamp(status)\n",
			__func__);
		return -EINVAL;
	}

	frame_boost(frame_info);
	trace_rtg_frame_sched(id, "frame_util", frame_info->frame_util);

	/* update cpufreq force when frame_stop */
	sched_set_group_normalized_util(grp->id,
		frame_info->frame_util, RTG_FREQ_FORCE_UPDATE);
	if (grp->preferred_cluster)
		trace_rtg_frame_sched(id, "preferred_cluster",
			grp->preferred_cluster->id);

	return 0;
}

static int set_frame_status(struct frame_info *frame_info, unsigned long status)
{
	struct related_thread_group *grp = NULL;
	int id;

	if (!frame_info)
		return -EINVAL;

	grp = frame_info->rtg;
	if (unlikely(!grp))
		return -EINVAL;

	if (atomic_read(&frame_info->frame_sched_state) == 0)
		return -EINVAL;

	if (!(status & FRAME_SETTIME) ||
		(status == (unsigned long)FRAME_SETTIME_PARAM)) {
		pr_err("[FRAME_RTG]: %s invalid timetsamp(status)\n",
			__func__);
		return -EINVAL;
	}

	if (status & FRAME_TIMESTAMP_SKIP_START) {
		frame_info->timestamp_skipped = true;
		status &= ~FRAME_TIMESTAMP_SKIP_START;
	} else if (status & FRAME_TIMESTAMP_SKIP_END) {
		frame_info->timestamp_skipped = false;
		status &= ~FRAME_TIMESTAMP_SKIP_END;
	} else if (frame_info->timestamp_skipped) {
		/*
		 * skip the following timestamp until
		 * FRAME_TIMESTAMP_SKIPPED reset
		 */
		return 0;
	}
	id = grp->id;
	trace_rtg_frame_sched(id, "FRAME_TIMESTAMP_SKIPPED",
		frame_info->timestamp_skipped);
	trace_rtg_frame_sched(id, "FRAME_MAX_UTIL", frame_info->frame_max_util);

	if (status & FRAME_USE_MARGIN_IMME) {
		frame_info->margin_imme = true;
		status &= ~FRAME_USE_MARGIN_IMME;
	} else {
		frame_info->margin_imme = false;
	}
	trace_rtg_frame_sched(id, "FRAME_MARGIN_IMME", frame_info->margin_imme);
	trace_rtg_frame_sched(id, "FRAME_TIMESTAMP", status);

	return update_frame_timestamp(status, frame_info, grp);
}

int set_frame_timestamp(struct frame_info *frame_info, unsigned long timestamp)
{
	int ret;

	if (!frame_info || !frame_info->rtg)
		return -EINVAL;

	if (atomic_read(&frame_info->frame_sched_state) == 0)
		return -EINVAL;

	ret = sched_set_group_window_rollover(frame_info->rtg->id);
	if (!ret)
		ret = set_frame_status(frame_info, timestamp);

	return ret;
}

int set_frame_min_util(struct frame_info *frame_info, int min_util, bool is_boost)
{
	int id;

	if (unlikely((min_util < 0) || (min_util > SCHED_CAPACITY_SCALE))) {
		pr_err("[FRAME_RTG]: %s invalid min_util value\n",
			__func__);
		return -EINVAL;
	}

	if (!frame_info || !frame_info->rtg)
		return -EINVAL;

	id = frame_info->rtg->id;
	if (is_boost) {
		frame_info->frame_boost_min_util = min_util;
		trace_rtg_frame_sched(id, "FRAME_BOOST_MIN_UTIL", min_util);
	} else {
		frame_info->frame_min_util = min_util;

		frame_info->frame_util = calc_frame_util(frame_info, false);
		trace_rtg_frame_sched(id, "frame_util", frame_info->frame_util);
		sched_set_group_normalized_util(id,
			frame_info->frame_util, RTG_FREQ_FORCE_UPDATE);
	}

	return 0;
}

int set_frame_max_util(struct frame_info *frame_info, int max_util)
{
	int id;

	if ((max_util < 0) || (max_util > SCHED_CAPACITY_SCALE)) {
		pr_err("[FRAME_RTG]: %s invalid max_util value\n",
			__func__);
		return -EINVAL;
	}

	if (!frame_info || !frame_info->rtg)
		return -EINVAL;

	frame_info->frame_max_util = max_util;
	id = frame_info->rtg->id;
	trace_rtg_frame_sched(id, "FRAME_MAX_UTIL", frame_info->frame_max_util);

	return 0;
}

struct frame_info *lookup_frame_info_by_grp_id(int grp_id)
{
	if (grp_id >= (MULTI_FRAME_ID + MULTI_FRAME_NUM) || (grp_id <= 0))
		return NULL;
	if (grp_id >= MULTI_FRAME_ID) {
		read_lock(&g_id_manager.lock);
		if (!test_bit(grp_id - MULTI_FRAME_ID, g_id_manager.id_map)) {
			read_unlock(&g_id_manager.lock);
			return NULL;
		}
		read_unlock(&g_id_manager.lock);
		return rtg_frame_info(grp_id);
	} else
		return rtg_frame_info(grp_id);
}

static int _init_frame_info(struct frame_info *frame_info, int id)
{
	struct related_thread_group *grp = NULL;
	unsigned long flags;

	memset(frame_info, 0, sizeof(struct frame_info));
	mutex_init(&frame_info->lock);

	mutex_lock(&frame_info->lock);
	frame_info->frame_rate = DEFAULT_FRAME_RATE;
	frame_info->frame_time = div_u64(NSEC_PER_SEC, frame_info->frame_rate);
	frame_info->thread_num = 0;
	frame_info->prio = NOT_RT_PRIO;
	atomic_set(&(frame_info->curr_rt_thread_num), 0);
	atomic_set(&(frame_info->frame_sched_state), 0);
	frame_info->vload_margin = DEFAULT_VLOAD_MARGIN;
	frame_info->max_vload_time =
		div_u64(frame_info->frame_time, NSEC_PER_MSEC) +
		frame_info->vload_margin;
	frame_info->frame_min_util = FRAME_DEFAULT_MIN_UTIL;
	frame_info->frame_max_util = FRAME_DEFAULT_MAX_UTIL;
	frame_info->prev_min_util = FRAME_DEFAULT_MIN_PREV_UTIL;
	frame_info->prev_max_util = FRAME_DEFAULT_MAX_PREV_UTIL;
	frame_info->margin_imme = false;
	frame_info->timestamp_skipped = false;
	frame_info->status = FRAME_END;

	grp = frame_rtg(id);
	if (unlikely(!grp)) {
		mutex_unlock(&frame_info->lock);
		return -EINVAL;
	}

	raw_spin_lock_irqsave(&grp->lock, flags);
	grp->private_data = frame_info;
	grp->rtg_class = &frame_rtg_class;
	raw_spin_unlock_irqrestore(&grp->lock, flags);

	frame_info->rtg = grp;
	mutex_unlock(&frame_info->lock);

	return 0;
}

static int __init init_frame_info(void)
{
	int ret = 0;
	int id;

	for (id = MULTI_FRAME_ID; id < (MULTI_FRAME_ID + MULTI_FRAME_NUM); id++) {
		if (ret != 0)
			break;
		ret = _init_frame_info(rtg_multi_frame_info(id), id);
	}

	return ret;
}
late_initcall(init_frame_info);
