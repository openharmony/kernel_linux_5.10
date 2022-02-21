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
	frame_info->frame_time = frame_info->frame_time = div_u64(NSEC_PER_SEC, rate);
	id = frame_info->rtg->id;
	trace_rtg_frame_sched(id, "FRAME_QOS", rate);

	return 0;
}

int alloc_multi_frame_info(void)
{
	struct frame_info *frame_info = NULL;
	int id;

	id = alloc_rtg_id();
	if (id < 0)
		return id;

	frame_info = rtg_frame_info(id);
	if (!frame_info) {
		free_rtg_id(id);
		return -EINVAL;
	}

	set_frame_rate(frame_info, DEFAULT_FRAME_RATE);

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

	policy = SCHED_FIFO | SCHED_RESET_ON_FORK;
	sp.sched_priority = MAX_USER_RT_PRIO - 1 - prio;
	sched_setscheduler_nocheck(task, policy, &sp);
}

static void update_frame_task_prio(struct frame_info *frame_info, int prio)
{
	int i;
	struct task_struct *thread = NULL;

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

	write_lock(&frame_info->lock);
	if (frame_info->prio == prio)
		goto out;

	update_frame_task_prio(frame_info, prio);
	frame_info->prio = prio;
out:
	write_unlock(&frame_info->lock);
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
			policy = SCHED_FIFO | SCHED_RESET_ON_FORK;
			sp.sched_priority = MAX_USER_RT_PRIO - 1 - prio;
		}
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
	 * if CONFIG_HW_FUTEX_PI is set, task->prio and task->sched_class
	 * may be modified by rtmutex. So we use task->policy instead.
	 */
	if (is_rtg && (!fair_policy(task->policy) || (task->flags & PF_EXITING)))
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
	int new_prio = prio;
	bool update_ret = false;

	if (pid > 0) {
		if (old_task && (pid == old_task->pid) && (old_prio == new_prio))
			return old_task;
		rcu_read_lock();
		task = find_task_by_vpid(pid);
		if (task)
			get_task_struct(task);
		rcu_read_unlock();
	}
	set_frame_rtg_thread(frame_info->rtg->id, old_task, false, NOT_RT_PRIO);
	update_ret = set_frame_rtg_thread(frame_info->rtg->id, task, true, new_prio);
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

	write_lock(&frame_info->lock);
	old_prio = frame_info->prio;
	real_thread = 0;
	for (i = 0; i < thread_num; i++) {
		frame_info->thread[i] = update_frame_thread(frame_info, old_prio, prio,
							    frame_thread_info->thread[i],
							    frame_info->thread[i]);
		if (frame_info->thread[i] && (frame_thread_info->thread[i] > 0))
			real_thread++;
	}
	frame_info->prio = prio;
	frame_info->thread_num = real_thread;
	write_unlock(&frame_info->lock);
}

static int _init_frame_info(struct frame_info *frame_info, int id)
{
	struct related_thread_group *grp = NULL;
	unsigned long flags;

	memset(frame_info, 0, sizeof(struct frame_info));
	rwlock_init(&frame_info->lock);

	write_lock(&frame_info->lock);
	frame_info->frame_rate = DEFAULT_FRAME_RATE;
	frame_info->frame_time = div_u64(NSEC_PER_SEC, frame_info->frame_rate);
	frame_info->thread_num = 0;
	frame_info->prio = NOT_RT_PRIO;

	grp = frame_rtg(id);
	if (unlikely(!grp)) {
		write_unlock(&frame_info->lock);
		return -EINVAL;
	}

	raw_spin_lock_irqsave(&grp->lock, flags);
	grp->private_data = frame_info;
	raw_spin_unlock_irqrestore(&grp->lock, flags);

	frame_info->rtg = grp;
	write_unlock(&frame_info->lock);

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
