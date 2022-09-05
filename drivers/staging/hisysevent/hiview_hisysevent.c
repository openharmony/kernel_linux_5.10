// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <dfx/hiview_hisysevent.h>

#ifdef CONFIG_HISYSEVENT

#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <asm/current.h>

#define PARAM_INT_MAX_LEN	21   // 21 = 20 (max len) + 1 ('\0')
#define PARAM_STR_MAX_LEN	1536 // 1.5KB

#define MAX_DOMAIN_LENGTH 16
#define MAX_EVENT_NAME_LENGTH 32
#define MAX_PARAM_NAME_LENGTH 48
#define MAX_PARAM_NUMBER 128

#define HISYSEVENT_WRITER_DEV "/dev/bbox"
#define HISYSEVENT_INFO_BUF_LEN (2048 - 6)  // 2KB - 6 (read_gap)

#define MINUTE_TO_SECS 60
#define SEC_TO_MILLISEC 1000
#define MILLISEC_TO_NANOSEC (1000 * 1000)
#define TIME_ZONE_LEN 6

#define BUF_POINTER_FORWARD	\
	do {	\
		if (tmp_len >= 0 && tmp_len < len) {	\
			tmp += tmp_len;	\
			len -= tmp_len;	\
		} else {	\
			pr_err("string over length");	\
			tmp += len;	\
			len = 0;	\
		}	\
	} while (0)

static int CHECK_CODE = 0x7BCDABCD;

struct hisysevent_payload {
	/* key of the event param */
	char *key;

	/* value of the event param */
	char *value;

	/* next param */
	struct hisysevent_payload *next;
};

/* hisysevent struct */
struct hiview_hisysevent {
	/* event domain */
	char *domain;

	/* event name */
	char *name;

	/* event type */
	int type;

	/* event time */
	long long time;

	/* time zone */
	char *tz;

	/* process id */
	int pid;

	/* thread id */
	int tid;

	/* user id */
	int uid;

	/* payload linked list */
	struct hisysevent_payload *head;

	/* length of payload */
	int payload_cnt;
};

static struct hisysevent_payload *hisysevent_payload_create(void)
{
	struct hisysevent_payload *payload = NULL;

	payload = kmalloc(sizeof(*payload), GFP_KERNEL);
	if (!payload)
		return NULL;

	payload->key = NULL;
	payload->value = NULL;
	payload->next = NULL;
	return payload;
}

static void hisysevent_payload_destroy(struct hisysevent_payload *p)
{
	if (!p)
		return;

	kfree(p->value);
	kfree(p->key);
	kfree(p);
}

static void
hisysevent_add_payload(struct hiview_hisysevent *event, struct hisysevent_payload *payload)
{
	if (!event->head) {
		event->head = payload;
	} else {
		struct hisysevent_payload *temp = event->head;

		while (temp->next)
			temp = temp->next;
		temp->next = payload;
	}
}

static struct hisysevent_payload *
hisysevent_get_payload(struct hiview_hisysevent *event, const char *key)
{
	struct hisysevent_payload *p = event->head;

	if (!key)
		return NULL;

	while (p) {
		if (p->key && strcmp(p->key, key) == 0)
			return p;
		p = p->next;
	}

	return NULL;
}

static struct hisysevent_payload *
hisysevent_get_or_create_payload(struct hiview_hisysevent *event, const char *key)
{
	struct hisysevent_payload *payload = hisysevent_get_payload(event, key);

	if (payload) {
		kfree(payload->value);
		return payload;
	}

	payload = hisysevent_payload_create();
	if (!payload)
		return NULL;

	payload->key = kstrdup(key, GFP_ATOMIC);
	if (!payload->key) {
		hisysevent_payload_destroy(payload);
		return NULL;
	}

	hisysevent_add_payload(event, payload);
	return payload;
}

static int json_add_number(char *json, size_t len, const char *key, long long num)
{
	return snprintf(json, len, "\"%s\":%lld,", key, num);
}

static int json_add_string(char *json, size_t len, const char *key, const char *str)
{
	return snprintf(json, len, "\"%s\":%s,", key, str);
}

static int json_add_string2(char *json, size_t len, const char *key, const char *str)
{
	return snprintf(json, len, "\"%s\":\"%s\",", key, str);
}

static int hisysevent_convert_base(const struct hiview_hisysevent *event, char **buf, int len)
{
	int tmp_len = 0;
	char *tmp = *buf;

	tmp_len = json_add_string2(tmp, len, "domain_", event->domain);
	BUF_POINTER_FORWARD;
	tmp_len = json_add_string2(tmp, len, "name_", event->name);
	BUF_POINTER_FORWARD;
	tmp_len = json_add_number(tmp, len, "type_", event->type);
	BUF_POINTER_FORWARD;
	tmp_len = json_add_number(tmp, len, "time_", event->time);
	BUF_POINTER_FORWARD;
	tmp_len = json_add_string2(tmp, len, "tz_", event->tz);
	BUF_POINTER_FORWARD;
	tmp_len = json_add_number(tmp, len, "pid_", event->pid);
	BUF_POINTER_FORWARD;
	tmp_len = json_add_number(tmp, len, "tid_", event->tid);
	BUF_POINTER_FORWARD;
	tmp_len = json_add_number(tmp, len, "uid_", event->uid);
	BUF_POINTER_FORWARD;
	*buf = tmp;
	return len;
}

static int hisysevent_convert_payload(struct hisysevent_payload *payload, char **buf, int len)
{
	int tmp_len = 0;
	char *tmp = *buf;
	struct hisysevent_payload *tmp_payload = payload;

	while (tmp_payload) {
		if (!tmp_payload->key || !tmp_payload->value) {
			pr_err("drop invalid payload");
			tmp_payload = tmp_payload->next;
			continue;
		}
		tmp_len = json_add_string(tmp, len, tmp_payload->key, tmp_payload->value);
		BUF_POINTER_FORWARD;
		tmp_payload = tmp_payload->next;
	}
	*buf = tmp;
	return len;
}

static int hisysevent_convert_json(const struct hiview_hisysevent *event, char **buf_ptr)
{
	char *tmp;
	int tmp_len = 0;
	int buf_len = HISYSEVENT_INFO_BUF_LEN;
	int len = buf_len;
	char *buf = vmalloc(buf_len + 1);

	if (!buf)
		return -ENOMEM;
	memset(buf, 0, buf_len + 1);

	tmp = buf;
	tmp_len = snprintf(tmp, len, "%c", '{');
	BUF_POINTER_FORWARD;

	len = hisysevent_convert_base(event, &tmp, len);
	if (!event->head)
		goto convert_end;
	len = hisysevent_convert_payload(event->head, &tmp, len);

convert_end:
	if (len <= 1) { // remaining len must > 1, for '}' and '\0'
		vfree(buf);
		return -EINVAL;
	}

	tmp_len = snprintf(tmp - 1, len, "%c", '}');
	BUF_POINTER_FORWARD;
	*buf_ptr = buf;
	return 0;
}

static void hisysevent_set_time(struct hiview_hisysevent *event)
{
	struct timespec64 ts;
	struct timezone tz = sys_tz;
	int tz_index = 0;
	char time_zone[TIME_ZONE_LEN];
	int tz_hour;
	int tz_min;
	long long millisecs = 0;

	ktime_get_real_ts64(&ts);
	millisecs = ts.tv_sec * SEC_TO_MILLISEC + ts.tv_nsec / MILLISEC_TO_NANOSEC;
	event->time = millisecs;

	tz_hour = (-tz.tz_minuteswest) / MINUTE_TO_SECS;
	time_zone[tz_index++] = tz_hour >= 0 ? '+' : '-';
	tz_min = (-tz.tz_minuteswest) % MINUTE_TO_SECS;
	sprintf(&time_zone[tz_index], "%02u%02u", abs(tz_hour), abs(tz_min));
	time_zone[TIME_ZONE_LEN - 1] = '\0';
	event->tz = kstrdup(time_zone, GFP_ATOMIC);
}

static bool is_valid_string(const char *str, unsigned int max_len)
{
	unsigned int len = 0;
	unsigned int i;

	if (!str)
		return false;

	len = strlen(str);
	if (len == 0 || len > max_len)
		return false;

	for (i = 0; i < len; i++) {
		if (!isalpha(str[i]) && str[i] != '_')
			return false;
	}
	return true;
}

static bool is_valid_num_of_param(struct hiview_hisysevent *event)
{
	if (!event)
		return false;

	return (event->payload_cnt) < MAX_PARAM_NUMBER;
}

struct hiview_hisysevent *
hisysevent_create(const char *domain, const char *name, enum hisysevent_type type)
{
	struct hiview_hisysevent *event = NULL;

	if (!is_valid_string(domain, MAX_DOMAIN_LENGTH)) {
		pr_err("invalid event domain");
		return NULL;
	}
	if (!is_valid_string(name, MAX_EVENT_NAME_LENGTH)) {
		pr_err("invalid event name");
		return NULL;
	}

	event = kmalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return NULL;
	memset(event, 0, sizeof(*event));

	event->domain = kstrdup(domain, GFP_ATOMIC);
	if (!(event->domain))
		goto create_err;

	event->name = kstrdup(name, GFP_ATOMIC);
	if (!(event->name))
		goto create_err;

	event->type = type;
	event->pid = current->pid;
	event->tid = current->tgid;
	event->uid = current_uid().val;
	hisysevent_set_time(event);
	if (!(event->tz))
		goto create_err;

	event->payload_cnt = 0;
	pr_info("create hisysevent succ, domain=%s, name=%s, type=%d",
		event->domain, event->name, event->type);
	return (void *)event;

create_err:
	hisysevent_destroy(&event);
	return NULL;
}
EXPORT_SYMBOL_GPL(hisysevent_create);

void hisysevent_destroy(struct hiview_hisysevent **event)
{
	struct hisysevent_payload *payload = NULL;

	if (!event || !*event)
		return;

	kfree((*event)->domain);
	kfree((*event)->name);
	kfree((*event)->tz);
	payload = (*event)->head;
	while (payload) {
		struct hisysevent_payload *temp = payload;

		payload = payload->next;
		hisysevent_payload_destroy(temp);
	}
	kfree(*event);
	*event = NULL;
}
EXPORT_SYMBOL_GPL(hisysevent_destroy);

int hisysevent_put_integer(struct hiview_hisysevent *event, const char *key, long long value)
{
	struct hisysevent_payload *payload = NULL;

	if (!event) {
		pr_err("invalid event");
		return -EINVAL;
	}
	if (!is_valid_num_of_param(event)) {
		pr_err("invalid num of param");
		return -EINVAL;
	}
	if (!is_valid_string(key, MAX_PARAM_NAME_LENGTH)) {
		pr_err("invalid key");
		return -EINVAL;
	}

	payload = hisysevent_get_or_create_payload(event, key);
	if (!payload) {
		pr_err("failed to get or create payload");
		return -ENOMEM;
	}

	payload->value = kmalloc(PARAM_INT_MAX_LEN, GFP_KERNEL);
	if (!payload->value)
		return -ENOMEM;

	memset(payload->value, 0, PARAM_INT_MAX_LEN);
	snprintf(payload->value, PARAM_INT_MAX_LEN, "%lld", value);
	event->payload_cnt++;
	return 0;
}
EXPORT_SYMBOL_GPL(hisysevent_put_integer);

int hisysevent_put_string(struct hiview_hisysevent *event, const char *key, const char *value)
{
	struct hisysevent_payload *payload = NULL;
	int len = 0;
	int tmp_len = 0;
	char *tmp_value = NULL;

	if (!event) {
		pr_err("invalid event");
		return -EINVAL;
	}
	if (!is_valid_num_of_param(event)) {
		pr_err("invalid num of param");
		return -EINVAL;
	}
	if (!is_valid_string(key, MAX_PARAM_NAME_LENGTH)) {
		pr_err("invalid key");
		return -EINVAL;
	}
	if (!value) {
		pr_err("invalid value");
		return -EINVAL;
	}

	payload = hisysevent_get_or_create_payload(event, key);
	if (!payload) {
		pr_err("failed to get or create payload");
		return -ENOMEM;
	}

	len = strlen(value);
	if (len > PARAM_STR_MAX_LEN) {
		pr_warn("string cannot exceed 1536 Byte, len=%d", len);
		len = PARAM_STR_MAX_LEN;
	}

	tmp_len = len + 3; // 3 for \", \", \0
	payload->value = kmalloc(tmp_len, GFP_KERNEL);
	if (!payload->value)
		return -ENOMEM;
	memset(payload->value, 0, tmp_len);

	tmp_value = payload->value;
	snprintf(tmp_value++, tmp_len--, "%c", '\"');
	memcpy(tmp_value, value, len);
	snprintf(tmp_value + len, tmp_len - len, "%c", '\"');
	event->payload_cnt++;
	return 0;
}
EXPORT_SYMBOL_GPL(hisysevent_put_string);

int hisysevent_write(struct hiview_hisysevent *event)
{
	struct iov_iter iter;
	mm_segment_t oldfs;
	char *data = NULL;
	struct file *filp = NULL;
	struct iovec vec[3];
	unsigned long vcount = 0;
	int ret;

	if (!event)
		return -EINVAL;

	ret = hisysevent_convert_json(event, &data);
	if (ret != 0 || !data) {
		pr_err("failed to convert event to string");
		return -EINVAL;
	}
	pr_info("write hisysevent data=%s", data);

	filp = filp_open(HISYSEVENT_WRITER_DEV, O_WRONLY, 0);

	if (!filp || IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		pr_err("failed to access '%s', res=%d", HISYSEVENT_WRITER_DEV, ret);
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

	if (ret < 0)
		pr_err("failed to write hisysevent, ret=%d", ret);

	filp_close(filp, NULL);
	vfree(data);
	return ret;
}
EXPORT_SYMBOL_GPL(hisysevent_write);

#endif /* CONFIG_HISYSEVENT */
