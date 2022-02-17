// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 */

#define pr_fmt(fmt) "zrhung " fmt

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <asm/current.h>
#include <dfx/zrhung.h>

#define MINUTE_TO_SECS 60
#define SEC_TO_MILLISEC 1000
#define MILLISEC_TO_NANOSEC (1000 * 1000)
#define TIME_ZONE_LEN 6
#define HISYSEVENT_MAX_STR_LEN 1024
#define HISYSEVENT_INFO_BUF_LEN 1024
#define HISYSEVENT_WRITER_DEV "/dev/bbox"
static int CHECK_CODE = 0x7BCDABCD;

#define BUF_POINTER_FORWARD                     \
do {                                            \
	if (tmp_len >= 0 && tmp_len < len) {    \
		tmp += tmp_len;                 \
		len -= tmp_len;                 \
	} else {                                \
		pr_err("string over length");   \
		tmp += len;                     \
		len = 0;                        \
	}                                       \
} while (0)

struct hisysevent {
	char *domain;
	char *event_name;
	unsigned int type;
	long long time;
	char *tz;
	unsigned int pid;
	unsigned int tid;
	unsigned int uid;
	char *msg;
};

int hisysevent_set_time(struct hisysevent *event)
{
	struct timespec64 ts;
	struct timezone tz = sys_tz;
	int tz_index = 0;
	char time_zone[TIME_ZONE_LEN];
	int tz_hour;
	int tz_min;
	long long millisecs = 0;

	if (!event) {
		pr_err("invalid event");
		return -EINVAL;
	}

	ktime_get_real_ts64(&ts);
	millisecs = ts.tv_sec * SEC_TO_MILLISEC + ts.tv_nsec / MILLISEC_TO_NANOSEC;
	event->time = millisecs;
	tz_hour = (-tz.tz_minuteswest) / MINUTE_TO_SECS;
	time_zone[tz_index++] = tz_hour >= 0 ? '+' : '-';
	tz_min = (-tz.tz_minuteswest) % MINUTE_TO_SECS;
	sprintf(&time_zone[tz_index], "%02u%02u", abs(tz_hour), abs(tz_min));
	time_zone[TIME_ZONE_LEN - 1] = '\0';
	event->tz = kstrdup(time_zone, GFP_ATOMIC);

	return 0;
}

int hisysevent_set_msg(struct hisysevent *event, const char *msg_buf)
{
	int len;

	if (!event) {
		pr_err("invalid event");
		return -EINVAL;
	}

	len = strlen(msg_buf);
	if ((!msg_buf) || (msg_buf[0] == 0) || len > HISYSEVENT_MAX_STR_LEN) {
		pr_err("invalid msg_buf");
		return -EINVAL;
	}

	event->msg = kstrdup(msg_buf, GFP_ATOMIC);

	return 0;
}

struct hisysevent *create_hisysevent(const char *domain, const char *event_name)
{
	struct hisysevent *event = NULL;

	event = vmalloc(sizeof(*event));
	if (!event) {
		pr_err("failed to vmalloc for event");
		return NULL;
	}

	memset(event, 0, sizeof(*event));

	if ((!domain) || (domain[0] == 0)) {
		pr_err("valid domain");
		vfree(event);
		return NULL;
	}
	event->domain = kstrdup(domain, GFP_ATOMIC);

	if ((!event_name) || (event_name[0] == 0)) {
		pr_err("valid event_name");
		kfree(event->domain);
		vfree(event);
		return NULL;
	}
	event->event_name = kstrdup(event_name, GFP_ATOMIC);
	event->type = ZRHUNG_EVENT_TYPE;

	pr_info("create hisysevent succ, domain=%s, event_name=%s, type=%u", event->domain,
		event->event_name, event->type);

	return (void *)event;
}

struct hisysevent *inner_build_hisysevent(const char *domain, const char *event_name,
	const char *msg_buf)
{
	struct hisysevent *event = NULL;

	event = create_hisysevent(domain, event_name);
	hisysevent_set_time(event);
	event->pid = current->pid;
	event->tid = current->tgid;
	event->uid = current_uid().val;
	hisysevent_set_msg(event, msg_buf);

	return (void *)event;
}

void zrhung_hisysevent_destroy(struct hisysevent *event)
{
	if (!event->domain) {
		kfree(event->domain);
		event->domain = NULL;
	}
	if (!event->event_name) {
		kfree(event->event_name);
		event->event_name = NULL;
	}
	if (!event->tz) {
		kfree(event->tz);
		event->tz = NULL;
	}
	if (!event->msg) {
		kfree(event->msg);
		event->msg = NULL;
	}

	vfree(event);
}

int hisysevent_convert_string(struct hisysevent *event, char **buf_ptr)
{
	int len;
	char *tmp;
	int tmp_len;
	int base_index = 0;
	static const char * const base_param_keys[] = {"domain_", "name_", "type_", "time_", "tz_",
		"pid_", "tid_", "uid_", "MSG"};
	int buf_len = HISYSEVENT_INFO_BUF_LEN;
	char *buf = vmalloc(buf_len);

	if (!buf) {
		pr_err("failed to malloc buff for convert_string");
		return -ENOMEM;
	}
	memset(buf, 0, buf_len);

	len = buf_len;
	tmp = buf;

	tmp_len = snprintf(tmp, len, "{\"%s\":\"%s\",", base_param_keys[base_index++], event->domain);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":\"%s\",", base_param_keys[base_index++], event->event_name);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":%u,", base_param_keys[base_index++], event->type);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":%lld,", base_param_keys[base_index++], event->time);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":\"%s\",", base_param_keys[base_index++], event->tz);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":%u,", base_param_keys[base_index++], event->pid);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":%u,", base_param_keys[base_index++], event->tid);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":%u,", base_param_keys[base_index++], event->uid);
	BUF_POINTER_FORWARD;

	tmp_len = snprintf(tmp, len, "\"%s\":\"%s\"}", base_param_keys[base_index++], event->msg);
	BUF_POINTER_FORWARD;

	*buf_ptr = buf;

	return (HISYSEVENT_INFO_BUF_LEN - len);
}

int zrhung_hisysevent_write(struct hisysevent *event)
{
	struct iov_iter iter;
	mm_segment_t oldfs;
	char *data = NULL;
	struct file *filp = NULL;
	struct iovec vec[3];
	unsigned long vcount = 0;
	int ret;

	hisysevent_convert_string(event, &data);
	if (!data) {
		pr_err("failed to convert string");
		return -EINVAL;
	}

	filp = filp_open(HISYSEVENT_WRITER_DEV, O_WRONLY, 0);

	if ((!filp) || IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		pr_err("access '%s' failed, res=%d", HISYSEVENT_WRITER_DEV, ret);
		vfree(data);
		return -ENODEV;
	}

	vec[vcount].iov_base = &CHECK_CODE;
	vec[vcount++].iov_len = sizeof(CHECK_CODE);
	vec[vcount].iov_base = data;
	vec[vcount++].iov_len = strlen(data) + 1;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	iov_iter_init(&iter, WRITE, vec, vcount, iov_length(vec, vcount));
	ret = vfs_iter_write(filp, &iter, &filp->f_pos, 0);
	set_fs(oldfs);

	if (ret < 0) {
		pr_err("write '%s' failed, res=%d", HISYSEVENT_WRITER_DEV, ret);
		ret = -EIO;
		goto out;
	}

out:
	filp_close(filp, NULL);
	vfree(data);
	return ret;
}

int zrhung_send_event(const char *domain, const char *event_name, const char *msg_buf)
{
	struct hisysevent *event = NULL;
	int ret = 0;

	event = inner_build_hisysevent(domain, event_name, msg_buf);

	if (!event) {
		pr_err("failed to build event");
		return -EINVAL;
	}

	ret = zrhung_hisysevent_write(event);
	zrhung_hisysevent_destroy(event);
	return ret;
}
