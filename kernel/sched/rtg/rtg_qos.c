// SPDX-License-Identifier: GPL-2.0
/*
 * rtg control entry
 *
 * Copyright (c) 2022-2023 Huawei Technologies Co., Ltd.
 */
#include "rtg.h"
#include "rtg_ctrl.h"
#include "rtg_qos.h"

/*
 * Pause uid-own-tasks' qos supply
 * Called after get auth->auth_lock
 */
void qos_pause(struct rtg_authority *auth)
{
	int i;
	struct task_struct *task;

	if (auth->status == AUTH_STATUS_ENABLE) {
		for (i = 0; i <= NR_QOS; ++i) {
			list_for_each_entry(task, &auth->tasks[i], qos_list) {
				/* remove_latency_nice || remove_from_rtg_nocheck*/
				/* what if reset failed on some task ? */
			}
		}
	}

	auth->status = AUTH_STATUS_CACHED;
}

/*
 * Resume uid-own-tasks' qos supply
 * Called after get auth->auth_lock
 */
void qos_resume(struct rtg_authority *auth)
{
	int i;
	struct task_struct *task;

	if (!auth) {
		pr_err("[SCHED_RTG] auth no exist, qos resume failed\n");
		return;
	}

	if (auth->status == AUTH_STATUS_CACHED) {
		for (i = 0; i <= NR_QOS; ++i) {
			list_for_each_entry(task, &auth->tasks[i], qos_list) {
				/* add_latency_nice || add_to_rtg_nocheck */
				/* what if resume failed on some task ? */
			}
		}
	}
}

static int insert_task(struct task_struct *p, struct list_head *head, unsigned int level)
{
	if (p->in_qos) {
		pr_err("[SCHED_RTG] qos apply request has cached, duplicate add\n");
		return -PID_DUPLICATE;
	}

	list_add(&p->qos_list, head);
	p->in_qos = level;

	return 0;
}

static int remove_task(struct task_struct *p)
{
	if (!p->in_qos) {
		pr_err("[SCHED_RTG] qos apply request not cached, stop failed\n");
		return -PID_NOT_EXIST;
	}

	list_del_init(&p->qos_list);
	p->in_qos = 0;

	return 0;
}

int qos_apply(struct rtg_qos_data *data)
{
	unsigned int level = data->level;
	struct rtg_authority *auth;
	int ret;

	if (level > NR_QOS || level == 0) {
		pr_err("[SCHED_RTG] no this qos level, qos apply failed\n");
		ret = -INVALID_ARG;
		goto out;
	}

	auth = get_authority(NULL);
	if (!auth) {
		pr_err("[SCHED_RTG] no auth data for pid=%d(%s) this uid=%d, qos apply failed\n",
		       current->pid, current->comm, current->cred->uid.val);
		return -UID_NOT_FOUND;
	}

	raw_spin_lock(&auth->auth_lock);
	if (auth->status == AUTH_STATUS_DEAD) {
		pr_err("[SCHED_RTG] this auth data has been deleted\n");
		ret = -INVALID_AUTH;
		goto out_unlock;
	}

	if (auth->num[level] >= RTG_QOS_NUM_MAX) {
		pr_notice("[SCHED_RTG] qos num exceeds limit, cached only\n");
		ret = 0;
		goto out_unlock;
	}

	ret = insert_task(current, &auth->tasks[level], level);
	if (ret < 0)
		goto out_unlock;

	++auth->num[level];

	if (auth->status == AUTH_STATUS_ENABLE) {
		switch (level) {
		case 5:
			/* add_to_rtg_nocheck*/
			break;
		case 4:
			/* add_to_latency_nice */
			break;
		default:
			break;
		}
	}

	ret = 0;

out_unlock:
	raw_spin_unlock(&auth->auth_lock);
	put_rtg_auth(auth);
out:
	return ret;
}

int qos_leave(struct rtg_qos_data *data)
{
	unsigned int level;
	struct rtg_authority *auth;
	int ret;

	auth = get_authority(NULL);
	if (!auth) {
		pr_err("[SCHED_RTG] no auth data for pid=%d(%s) this uid=%d, qos stop failed\n",
		       current->pid, current->comm, current->cred->uid.val);
		ret = -UID_NOT_FOUND;
	}

	raw_spin_lock(&auth->auth_lock);
	level = current->in_qos;
	if (level == 0) {
		pr_err("[SCHED_RTG] no this qos level, qos stop failed\n");
		ret = -INVALID_ARG;
		goto out_unlock;
	}

	if (auth->status == AUTH_STATUS_DEAD) {
		pr_err("[SCHED_RTG] this auth data has been deleted\n");
		ret = -INVALID_AUTH;
		goto out_unlock;
	}

	ret = remove_task(current);
	if (ret < 0)
		goto out_unlock;

	--auth->num[level];

	if (auth->status == AUTH_STATUS_ENABLE) {
		switch (level) {
		case 5:
			/* remove_from_rtg_nocheck*/
			break;
		case 4:
			/* remove_latency_nice */
			break;
		default:
			break;
		}
	}

	ret = 0;

out_unlock:
	raw_spin_unlock(&auth->auth_lock);
	put_rtg_auth(auth);

	return ret;
}

void init_task_qos(struct task_struct *p)
{
	INIT_LIST_HEAD(&p->qos_list);
	p->in_qos = 0;
}

/*
 * Remove statistic info in auth when task exit
 */
void sched_exit_qos_list(struct task_struct *p)
{
	struct rtg_authority *auth;

	/*
	 * For common tasks(the vast majority):
	 * skip get authority, fast return here.
	 *
	 * For qos tasks:
	 * If contend with auth_delete() happens,
	 * 1. function return here, auth_delete() will do the clean up
	 * 2. function go on, either no auth return, either do clean up here
	 * Both cases guarantee data synchronization
	 */
	if (likely(!p->in_qos))
		return;

	auth = get_authority(p);
	if (!auth)
		goto out;

	raw_spin_lock(&auth->auth_lock);
	if (!p->in_qos) {
		raw_spin_unlock(&auth->auth_lock);
		goto out_put_auth;
	}
	--auth->num[p->in_qos];
	list_del_init(&p->qos_list);
	p->in_qos = 0;
	raw_spin_unlock(&auth->auth_lock);

out_put_auth:
	put_rtg_auth(auth);
out:
	return;
}
