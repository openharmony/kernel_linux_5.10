// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 */

#define pr_fmt(fmt) "zrhung " fmt

#include <linux/sched/clock.h>
#include <linux/sched/debug.h>
#include <linux/kernel.h>
#include <linux/fb.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/time.h>
#include <linux/input.h>
#include <linux/jiffies.h>
#include <linux/sched/debug.h>
#include <dfx/zrhung.h>
#include <dfx/hung_wp_screen.h>

#define TIME_CONVERT_UNIT 1000
#define DEFAULT_TIMEOUT 10

#define LPRESSEVENT_TIME 5
#define POWERKEYEVENT_MAX_COUNT 10
#define POWERKEYEVENT_DEFAULT_COUNT 3
#define POWERKEYEVENT_DEFAULT_TIMEWINDOW 5
#define POWERKEYEVENT_DEFAULT_LIMIT_MS 300
#define POWERKEYEVENT_DEFAULT_REPORT_MIN 2
#define POWERKEYEVENT_TIME_LEN (POWERKEYEVENT_MAX_COUNT + 2)

struct hung_wp_screen_data {
	struct timer_list timer;
	struct timer_list long_press_timer;
	struct workqueue_struct *workq;
	struct work_struct send_work;
	spinlock_t lock;
	int fb_blank;
	int check_id;
	int tag_id;
};

static bool init_done;
static struct hung_wp_screen_data g_hung_data;
static unsigned int lastreport_time;
static unsigned int lastprkyevt_time;
static unsigned int powerkeyevent_time[POWERKEYEVENT_TIME_LEN] = {0};
static unsigned int newevt;
static unsigned int headevt;
static int *check_off_point;
struct work_struct powerkeyevent_sendwork;
struct work_struct lpressevent_sendwork;
static struct notifier_block hung_wp_screen_setblank_ncb;

static void zrhung_lpressevent_send_work(struct work_struct *work)
{
	pr_info("LONGPRESS_EVENT send to zerohung\n");
	zrhung_send_event(WP_SCREEN_DOMAIN, WP_SCREEN_LPRESS_NAME, "none");
}

static void zrhung_wp_lpress_send(struct timer_list *t)
{
	int *check_off = check_off_point;

	del_timer(&g_hung_data.long_press_timer);
	*check_off = 0;
	queue_work(g_hung_data.workq, &lpressevent_sendwork);
}

static void zrhung_powerkeyevent_send_work(struct work_struct *work)
{
	pr_info("POWERKEY_EVENT send to zerohung\n");
	zrhung_send_event(WP_SCREEN_DOMAIN, WP_SCREEN_PWK_NAME, "none");
}

static void zrhung_powerkeyevent_report(unsigned int dur, unsigned int end)
{
	unsigned int send_interval;

	send_interval = end > lastreport_time ?
	    ((end - lastreport_time) / TIME_CONVERT_UNIT) : POWERKEYEVENT_DEFAULT_REPORT_MIN;
	if (unlikely(lastreport_time == 0)) {
		lastreport_time = end;
	} else if (send_interval < POWERKEYEVENT_DEFAULT_REPORT_MIN) {
		pr_info("powerkeyevent too fast to report: %d\n", end);
		return;
	}
	lastreport_time = end;
	queue_work(g_hung_data.workq, &powerkeyevent_sendwork);
}

static unsigned int refresh_prkyevt_index(unsigned int event)
{
	unsigned int evt = event;

	if (evt < POWERKEYEVENT_MAX_COUNT)
		evt++;
	else
		evt = 0;
	return evt;
}

static void zrhung_new_powerkeyevent(unsigned int tmescs)
{
	unsigned int prkyevt_interval;
	unsigned int evt_index;
	int diff;

	powerkeyevent_time[newevt] = tmescs;
	evt_index = (newevt >= headevt) ?
	    (newevt - headevt) : (newevt + POWERKEYEVENT_MAX_COUNT + 1 - headevt);
	if (evt_index < (POWERKEYEVENT_DEFAULT_COUNT - 1)) {
		pr_info("powerkeyevent not enough-%d\n", POWERKEYEVENT_DEFAULT_COUNT);
	} else {
		diff = powerkeyevent_time[newevt] - powerkeyevent_time[headevt];
		if (diff < 0) {
			pr_info("powerkeyevent sth wrong in record time\n");
			return;
		}

		prkyevt_interval = (unsigned int)(diff / TIME_CONVERT_UNIT);
		if (prkyevt_interval <= POWERKEYEVENT_DEFAULT_TIMEWINDOW)
			zrhung_powerkeyevent_report(prkyevt_interval, tmescs);
		headevt = refresh_prkyevt_index(headevt);
	}
	newevt = refresh_prkyevt_index(newevt);
}

static void zrhung_powerkeyevent_handler(void)
{
	unsigned int curtime;
	unsigned long curjiff;

	pr_info("powerkeyevent check start");
	curjiff = jiffies;
	curtime = jiffies_to_msecs(curjiff);
	if (unlikely(lastprkyevt_time > curtime)) {
		pr_info("powerkeyevent check but time overflow");
		lastprkyevt_time = curtime;
		return;
	} else if ((curtime - lastprkyevt_time) < POWERKEYEVENT_DEFAULT_LIMIT_MS) {
		pr_info("powerkeyevent user press powerkey too fast-time:%d", curtime);
		return;
	}
	lastprkyevt_time = curtime;
	zrhung_new_powerkeyevent(curtime);
}

static int hung_wp_screen_setblank(struct notifier_block *self, unsigned long event, void *data)
{
	unsigned long flags;
	struct fb_event *evdata = data;
	int blank;

	if (!init_done)
		return 0;

	if (event != FB_EVENT_BLANK)
		return 0;

	blank = *(int *)evdata->data;
	spin_lock_irqsave(&(g_hung_data.lock), flags);
	g_hung_data.fb_blank = blank;
	if (((g_hung_data.check_id == ZRHUNG_WP_SCREENON) && (blank == 0)) ||
	    ((g_hung_data.check_id == ZRHUNG_WP_SCREENOFF) && (blank != 0))) {
		pr_info("check_id=%d, blank=%d", g_hung_data.check_id, g_hung_data.fb_blank);
		del_timer(&g_hung_data.timer);
		g_hung_data.check_id = ZRHUNG_WP_NONE;
	}
	spin_unlock_irqrestore(&(g_hung_data.lock), flags);

	return 0;
}

static void hung_wp_screen_send_work(struct work_struct *work)
{
	unsigned long flags = 0;

	show_state_filter(TASK_UNINTERRUPTIBLE);

	if (g_hung_data.check_id == 1)
		zrhung_send_event(WP_SCREEN_DOMAIN, WP_SCREEN_ON_NAME, "none");
	else
		zrhung_send_event(WP_SCREEN_DOMAIN, WP_SCREEN_OFF_NAME, "none");
	pr_info("send event: %d\n", g_hung_data.check_id);
	spin_lock_irqsave(&(g_hung_data.lock), flags);
	g_hung_data.check_id = ZRHUNG_WP_NONE;
	spin_unlock_irqrestore(&(g_hung_data.lock), flags);
}

static void hung_wp_screen_send(struct timer_list *t)
{
	del_timer(&g_hung_data.timer);
	pr_info("hung_wp_screen_%d end\n", g_hung_data.tag_id);
	queue_work(g_hung_data.workq, &g_hung_data.send_work);
}

static void hung_wp_screen_start(int check_id)
{
	if (g_hung_data.check_id != ZRHUNG_WP_NONE) {
		pr_info("already in check_id: %d\n", g_hung_data.check_id);
		return;
	}

	g_hung_data.check_id = check_id;
	if (timer_pending(&g_hung_data.timer))
		del_timer(&g_hung_data.timer);

	g_hung_data.timer.expires = jiffies + msecs_to_jiffies(DEFAULT_TIMEOUT * TIME_CONVERT_UNIT);
	add_timer(&g_hung_data.timer);
	pr_info("going to check ID=%d timeout=%d\n", check_id, DEFAULT_TIMEOUT);
}

void hung_wp_screen_powerkey_ncb(int event)
{
	static int check_off;
	unsigned long flags = 0;

	if (!init_done)
		return;

	spin_lock_irqsave(&(g_hung_data.lock), flags);
	if (event == WP_SCREEN_PWK_PRESS) {
		pr_info("hung_wp_screen_%d start! fb_blank=%d",
			++g_hung_data.tag_id, g_hung_data.fb_blank);
		check_off = 0;
		if (g_hung_data.fb_blank != 0) {
			hung_wp_screen_start(ZRHUNG_WP_SCREENON);
		} else {
			check_off = 1;
			pr_info("start longpress test timer\n");
			check_off_point = &check_off;
			g_hung_data.long_press_timer.expires = jiffies +
				msecs_to_jiffies(LPRESSEVENT_TIME * TIME_CONVERT_UNIT);
			if (!timer_pending(&g_hung_data.long_press_timer))
				add_timer(&g_hung_data.long_press_timer);
		}
		zrhung_powerkeyevent_handler();
	} else if (check_off) {
		check_off = 0;
		del_timer(&g_hung_data.long_press_timer);
		if (event == WP_SCREEN_PWK_RELEASE && g_hung_data.fb_blank == 0)
			hung_wp_screen_start(ZRHUNG_WP_SCREENOFF);
	}
	spin_unlock_irqrestore(&(g_hung_data.lock), flags);
}

static int __init hung_wp_screen_init(void)
{
	init_done = false;
	pr_info("%s start\n", __func__);
	g_hung_data.fb_blank = 0;
	g_hung_data.tag_id = 0;
	g_hung_data.check_id = ZRHUNG_WP_NONE;
	spin_lock_init(&(g_hung_data.lock));

	timer_setup(&g_hung_data.timer, hung_wp_screen_send, 0);
	timer_setup(&g_hung_data.long_press_timer, zrhung_wp_lpress_send, 0);

	g_hung_data.workq = create_workqueue("hung_wp_screen_workq");
	if (g_hung_data.workq == NULL) {
		pr_err("create workq failed\n");
		return -EFAULT;
	}
	INIT_WORK(&g_hung_data.send_work, hung_wp_screen_send_work);
	INIT_WORK(&powerkeyevent_sendwork, zrhung_powerkeyevent_send_work);
	INIT_WORK(&lpressevent_sendwork, zrhung_lpressevent_send_work);

	hung_wp_screen_setblank_ncb.notifier_call = hung_wp_screen_setblank;
	fb_register_client(&hung_wp_screen_setblank_ncb);

	init_done = true;
	pr_info("%s done\n", __func__);
	return 0;
}

static void __exit hung_wp_screen_exit(void)
{
	fb_unregister_client(&hung_wp_screen_setblank_ncb);

	cancel_work_sync(&lpressevent_sendwork);
	cancel_work_sync(&powerkeyevent_sendwork);
	cancel_work_sync(&g_hung_data.send_work);

	destroy_workqueue(g_hung_data.workq);

	del_timer_sync(&g_hung_data.timer);
	del_timer_sync(&g_hung_data.long_press_timer);
}

module_init(hung_wp_screen_init);
module_exit(hung_wp_screen_exit);

MODULE_AUTHOR("OHOS");
MODULE_DESCRIPTION("Reporting the frozen screen alarm event");
MODULE_LICENSE("GPL");
