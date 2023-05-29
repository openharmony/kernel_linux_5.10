// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/comm/message_verify.c
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#include "message_verify.h"

#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/statfs.h>

#include "connection.h"
#include "hmdfs.h"
#include "hmdfs_server.h"

size_t message_length[C_FLAG_SIZE][F_SIZE][HMDFS_MESSAGE_MIN_MAX];
bool need_response[F_SIZE];

void hmdfs_message_verify_init(void)
{
	int flag, cmd;

	for (cmd = 0; cmd < F_SIZE; cmd++)
		need_response[cmd] = true;
	need_response[F_RELEASE] = false;
	need_response[F_CONNECT_REKEY] = false;
	need_response[F_DROP_PUSH] = false;

	for (flag = 0; flag < C_FLAG_SIZE; flag++) {
		for (cmd = 0; cmd < F_SIZE; cmd++) {
			message_length[flag][cmd][HMDFS_MESSAGE_MIN_INDEX] = 1;
			message_length[flag][cmd][HMDFS_MESSAGE_MAX_INDEX] = 0;
			message_length[flag][cmd][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
				MESSAGE_LEN_JUDGE_RANGE;
		}
	}

	message_length[C_REQUEST][F_OPEN][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct open_request);
	message_length[C_REQUEST][F_OPEN][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct open_request) + PATH_MAX + 1;
	message_length[C_REQUEST][F_OPEN][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_OPEN][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_OPEN][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct open_response);
	message_length[C_RESPONSE][F_OPEN][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_ATOMIC_OPEN][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct atomic_open_request);
	message_length[C_REQUEST][F_ATOMIC_OPEN][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct atomic_open_request) + PATH_MAX + NAME_MAX + 1;
	message_length[C_REQUEST][F_ATOMIC_OPEN][HMDFS_MESSAGE_LEN_JUDGE_INDEX]
		= MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_ATOMIC_OPEN][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_ATOMIC_OPEN][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct atomic_open_response);
	message_length[C_RESPONSE][F_ATOMIC_OPEN][HMDFS_MESSAGE_LEN_JUDGE_INDEX]
		= MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_RELEASE][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct release_request);
	message_length[C_REQUEST][F_RELEASE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct release_request);
	message_length[C_REQUEST][F_RELEASE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_FSYNC][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct fsync_request);
	message_length[C_REQUEST][F_FSYNC][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct fsync_request);
	message_length[C_REQUEST][F_FSYNC][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;
	message_length[C_RESPONSE][F_FSYNC][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_FSYNC][HMDFS_MESSAGE_MAX_INDEX] = 0;
	message_length[C_RESPONSE][F_FSYNC][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_READPAGE][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct readpage_request);
	message_length[C_REQUEST][F_READPAGE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct readpage_request);
	message_length[C_REQUEST][F_READPAGE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;
	message_length[C_RESPONSE][F_READPAGE][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_READPAGE][HMDFS_MESSAGE_MAX_INDEX] =
		HMDFS_PAGE_SIZE;
	message_length[C_RESPONSE][F_READPAGE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;

	message_length[C_REQUEST][F_WRITEPAGE][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct writepage_request) + HMDFS_PAGE_SIZE;
	message_length[C_REQUEST][F_WRITEPAGE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct writepage_request) + HMDFS_PAGE_SIZE;
	message_length[C_REQUEST][F_WRITEPAGE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;
	message_length[C_RESPONSE][F_WRITEPAGE][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_WRITEPAGE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct writepage_response);
	message_length[C_RESPONSE][F_WRITEPAGE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_ITERATE][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct readdir_request);
	message_length[C_REQUEST][F_ITERATE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct readdir_request) + PATH_MAX + 1;
	message_length[C_REQUEST][F_ITERATE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_ITERATE][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_ITERATE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(__le64) + HMDFS_MAX_MESSAGE_LEN;
	message_length[C_RESPONSE][F_ITERATE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;

	message_length[C_REQUEST][F_MKDIR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct mkdir_request);
	message_length[C_REQUEST][F_MKDIR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct mkdir_request) + PATH_MAX + NAME_MAX + 2;
	message_length[C_REQUEST][F_MKDIR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_MKDIR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct hmdfs_inodeinfo_response);
	message_length[C_RESPONSE][F_MKDIR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct hmdfs_inodeinfo_response);
	message_length[C_RESPONSE][F_MKDIR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_CREATE][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct create_request);
	message_length[C_REQUEST][F_CREATE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct create_request) + PATH_MAX + NAME_MAX + 2;
	message_length[C_REQUEST][F_CREATE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_CREATE][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct hmdfs_inodeinfo_response);
	message_length[C_RESPONSE][F_CREATE][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct hmdfs_inodeinfo_response);
	message_length[C_RESPONSE][F_CREATE][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_RMDIR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct rmdir_request);
	message_length[C_REQUEST][F_RMDIR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct rmdir_request) + PATH_MAX + NAME_MAX + 2;
	message_length[C_REQUEST][F_RMDIR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_RMDIR][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_RMDIR][HMDFS_MESSAGE_MAX_INDEX] = 0;
	message_length[C_RESPONSE][F_RMDIR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_UNLINK][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct unlink_request);
	message_length[C_REQUEST][F_UNLINK][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct unlink_request) + PATH_MAX + NAME_MAX + 2;
	message_length[C_REQUEST][F_UNLINK][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_UNLINK][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_UNLINK][HMDFS_MESSAGE_MAX_INDEX] = 0;
	message_length[C_RESPONSE][F_UNLINK][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_RENAME][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct rename_request);
	message_length[C_REQUEST][F_RENAME][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct rename_request) + 4 + 4 * PATH_MAX;
	message_length[C_REQUEST][F_RENAME][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_RENAME][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_RENAME][HMDFS_MESSAGE_MAX_INDEX] = 0;
	message_length[C_RESPONSE][F_RENAME][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_SETATTR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct setattr_request);
	message_length[C_REQUEST][F_SETATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct setattr_request) + PATH_MAX + 1;
	message_length[C_REQUEST][F_SETATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_SETATTR][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_SETATTR][HMDFS_MESSAGE_MAX_INDEX] = 0;
	message_length[C_RESPONSE][F_SETATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_GETATTR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct getattr_request);
	message_length[C_REQUEST][F_GETATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct getattr_request) + PATH_MAX + 1;
	message_length[C_REQUEST][F_GETATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_GETATTR][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_GETATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct getattr_response);
	message_length[C_RESPONSE][F_GETATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_STATFS][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct statfs_request);
	message_length[C_REQUEST][F_STATFS][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct statfs_request) + PATH_MAX + 1;
	message_length[C_REQUEST][F_STATFS][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_STATFS][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_STATFS][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct statfs_response);
	message_length[C_RESPONSE][F_STATFS][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_SYNCFS][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct syncfs_request);
	message_length[C_REQUEST][F_SYNCFS][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct syncfs_request);
	message_length[C_REQUEST][F_SYNCFS][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;
	message_length[C_RESPONSE][F_SYNCFS][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_SYNCFS][HMDFS_MESSAGE_MAX_INDEX] = 0;
	message_length[C_RESPONSE][F_SYNCFS][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_GETXATTR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct getxattr_request);
	message_length[C_REQUEST][F_GETXATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct getxattr_request) + PATH_MAX + XATTR_NAME_MAX + 2;
	message_length[C_REQUEST][F_GETXATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_GETXATTR][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_GETXATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct getxattr_response) + HMDFS_XATTR_SIZE_MAX;
	message_length[C_RESPONSE][F_GETXATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;

	message_length[C_REQUEST][F_SETXATTR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct setxattr_request);
	message_length[C_REQUEST][F_SETXATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct setxattr_request) + PATH_MAX + XATTR_NAME_MAX +
		HMDFS_XATTR_SIZE_MAX + 2;
	message_length[C_REQUEST][F_SETXATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_SETXATTR][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_SETXATTR][HMDFS_MESSAGE_MAX_INDEX] = 0;
	message_length[C_RESPONSE][F_SETXATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_LISTXATTR][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct listxattr_request);
	message_length[C_REQUEST][F_LISTXATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct listxattr_request) + PATH_MAX + 1;
	message_length[C_REQUEST][F_LISTXATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
	message_length[C_RESPONSE][F_LISTXATTR][HMDFS_MESSAGE_MIN_INDEX] = 0;
	message_length[C_RESPONSE][F_LISTXATTR][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct listxattr_response) + HMDFS_LISTXATTR_SIZE_MAX;
	message_length[C_RESPONSE][F_LISTXATTR][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;

	message_length[C_REQUEST][F_CONNECT_REKEY][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct connection_rekey_request);
	message_length[C_REQUEST][F_CONNECT_REKEY][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct connection_rekey_request);
	message_length[C_REQUEST][F_CONNECT_REKEY]
		      [HMDFS_MESSAGE_LEN_JUDGE_INDEX] = MESSAGE_LEN_JUDGE_BIN;

	message_length[C_REQUEST][F_DROP_PUSH][HMDFS_MESSAGE_MIN_INDEX] =
		sizeof(struct drop_push_request);
	message_length[C_REQUEST][F_DROP_PUSH][HMDFS_MESSAGE_MAX_INDEX] =
		sizeof(struct drop_push_request) + PATH_MAX + 1;
	message_length[C_REQUEST][F_DROP_PUSH][HMDFS_MESSAGE_LEN_JUDGE_INDEX] =
		MESSAGE_LEN_JUDGE_RANGE;
}

static void find_first_no_slash(const char **name, int *len)
{
	const char *s = *name;
	int l = *len;

	while (*s == '/' && l > 0) {
		s++;
		l--;
	}

	*name = s;
	*len = l;
}

static void find_first_slash(const char **name, int *len)
{
	const char *s = *name;
	int l = *len;

	while (*s != '/' && l > 0) {
		s++;
		l--;
	}

	*name = s;
	*len = l;
}

static bool path_contain_dotdot(const char *name, int len)
{
	while (true) {
		find_first_no_slash(&name, &len);

		if (len == 0)
			return false;

		if (len >= 2 && name[0] == '.' && name[1] == '.' &&
		    (len == 2 || name[2] == '/'))
			return true;

		find_first_slash(&name, &len);
	}
}

static int is_str_msg_valid(char *msg, int str_len[], size_t str_num)
{
	int i = 0;
	int pos = 0;

	for (i = 0; i < str_num; i++) {
		if (msg[pos + str_len[i]] != '\0' ||
			strnlen(msg + pos, PATH_MAX) != str_len[i]) {
			return -EINVAL;
		} 

		pos += str_len[i] + 1;
	}

	return 0;
}

static int verify_open_req(size_t msg_len, void *msg)
{
	struct open_request *req = msg;
	int str_len[] = { req->path_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1)
		return -EINVAL;

	str_len[0] = req->path_len;
	if (is_str_msg_valid(req->buf, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	/*
	 * We only allow server to open file in hmdfs, thus we need to
	 * make sure path don't contain "..".
	 */
	if (path_contain_dotdot(req->buf, req->path_len)) {
		hmdfs_err("verify fail, path contain dotdot");
		return -EINVAL;
	}

	return 0;
}

static int verify_open_resp(size_t msg_len, void *msg)
{
	struct open_response *resp = msg;

	if (msg_len != sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_open_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_open_req(msg_len, msg);
	else
		return verify_open_resp(msg_len, msg);
}

static int verify_atomic_open_req(size_t msg_len, void *msg)
{
	struct atomic_open_request *req = msg;
	int str_len[] = { req->path_len, req->file_len};

	if (req->path_len < 0 || req->path_len >= PATH_MAX ||
		req->file_len < 0 || req->file_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1 + req->file_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->buf, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int verify_atomic_open_resp(size_t msg_len, void *msg)
{
	struct atomic_open_response *resp = msg;

	if (msg_len != sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_atomic_open_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_atomic_open_req(msg_len, msg);
	else
		return verify_atomic_open_resp(msg_len, msg);
}

static int verify_iterate_req(size_t msg_len, void *msg)
{
	struct readdir_request *req = msg;
	int str_len[] = { req->path_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int hmdfs_iterate_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_iterate_req(msg_len, msg);

	return 0;
}

static int verify_mkdir_req(size_t msg_len, void *msg)
{
	struct mkdir_request *req = msg;
	int str_len[] = { req->path_len, req->name_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX ||
		req->name_len < 0 || req->name_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1 + req->name_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int verify_mkdir_resp(size_t msg_len, void *msg)
{
	struct hmdfs_inodeinfo_response *resp = msg;

	if (msg_len != sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_mkdir_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_mkdir_req(msg_len, msg);
	else
		return verify_mkdir_resp(msg_len, msg);
}

static int verify_create_req(size_t msg_len, void *msg)
{
	struct create_request *req = msg;
	int str_len[] = { req->path_len, req->name_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX ||
		req->name_len < 0 || req->name_len >= PATH_MAX)
			return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1 + req->name_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int verify_create_resp(size_t msg_len, void *msg)
{
	struct hmdfs_inodeinfo_response *resp = msg;

	if (msg_len != sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_create_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_create_req(msg_len, msg);
	else
		return verify_create_resp(msg_len, msg);
}

static int verify_rmdir_req(size_t msg_len, void *msg)
{
	struct rmdir_request *req = msg;
	int str_len[] = { req->path_len, req->name_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX ||
		req->name_len < 0 || req->name_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1 + req->name_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int hmdfs_rmdir_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_rmdir_req(msg_len, msg);

	return 0;
}

static int verify_unlink_req(size_t msg_len, void *msg)
{
	struct unlink_request *req = msg;
	int str_len[] = { req->path_len, req->name_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX ||
		req->name_len < 0 || req->name_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1 + req->name_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int hmdfs_unlink_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_unlink_req(msg_len, msg);

	return 0;
}

static int verify_rename_req(size_t msg_len, void *msg)
{
	struct rename_request *req = msg;
	int str_len[] = { req->old_path_len, req->new_path_len,
		req->old_name_len, req->new_name_len };

	if (req->old_path_len < 0 || req->old_path_len >= PATH_MAX ||
		req->new_path_len < 0 || req->new_path_len >= PATH_MAX ||
		req->old_name_len < 0 || req->old_name_len >= PATH_MAX ||
		req->new_name_len < 0 || req->new_name_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->old_path_len + 1 +
		req->new_path_len + 1 + req->old_name_len + 1 +
		req->new_name_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int hmdfs_rename_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_rename_req(msg_len, msg);

	return 0;
}

static int verify_setattr_req(size_t msg_len, void *msg)
{
	struct setattr_request *req = msg;
	int str_len[] = { req->path_len };

	req = msg;
	if (req->path_len < 0 || req->path_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->buf, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int hmdfs_setattr_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_setattr_req(msg_len, msg);

	return 0;
}

static int verify_getattr_req(size_t msg_len, void *msg)
{
	struct getattr_request *req = msg;
	int str_len[] = { req->path_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->buf, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int verify_getattr_resp(size_t msg_len, void *msg)
{
	struct getattr_response *resp = msg;

	if (msg_len != sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_getattr_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_getattr_req(msg_len, msg);
	else
		return verify_getattr_resp(msg_len, msg);
}

static int verify_getxattr_req(size_t msg_len, void *msg)
{
	struct getxattr_request *req = msg;
	int str_len[] = { req->path_len, req->name_len};

	if (req->path_len < 0 || req->path_len >= PATH_MAX ||
		req->name_len < 0 || req->name_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1 + req->name_len + 1)
		return -EINVAL;
	
	if (is_str_msg_valid(req->buf, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int verify_getxattr_resp(size_t msg_len, void *msg)
{
	struct getxattr_response *resp = msg;

	if (msg_len < sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_getxattr_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_getxattr_req(msg_len, msg);
	else
		return verify_getxattr_resp(msg_len, msg);
}

static int verify_setxattr_req(size_t msg_len, void *msg)
{
	struct setxattr_request *req = msg;
	int str_len[] = { req->path_len, req->name_len};

	if (req->path_len < 0 || req->path_len >= PATH_MAX ||
		req->name_len < 0 || req->name_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1 + req->name_len + 1 +
		req->size)
		return -EINVAL;

	if (is_str_msg_valid(req->buf, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int hmdfs_setxattr_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_setxattr_req(msg_len, msg);

	return 0;
}

static int verify_listxattr_req(size_t msg_len, void *msg)
{
	struct listxattr_request *req = msg;
	int str_len[] = { req->path_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->buf, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int verify_listxattr_resp(size_t msg_len, void *msg)
{
	struct listxattr_response *resp = msg;

	if (msg_len < sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_listxattr_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_listxattr_req(msg_len, msg);
	else
		return verify_listxattr_resp(msg_len, msg);
}

static int hmdfs_readpage_verify(int flag, size_t msg_len, void *msg)
{
	struct readpage_request *req = NULL;

	if (flag != C_REQUEST || !msg || !msg_len)
		return 0;

	req = msg;
	if (msg_len != sizeof(*req))
		return -EINVAL;

	return 0;
}

static int hmdfs_writepage_verify(int flag, size_t msg_len, void *msg)
{
	struct writepage_request *req = NULL;

	if (flag != C_REQUEST || !msg || !msg_len)
		return 0;

	req = msg;
	if (req->count <= 0 || req->count > HMDFS_PAGE_SIZE)
		return -EINVAL;

	if (msg_len != sizeof(*req) + HMDFS_PAGE_SIZE)
		return -EINVAL;

	return 0;
}

static int verify_statfs_req(size_t msg_len, void *msg)
{
	struct statfs_request *req = msg;
	int str_len[] = { req->path_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int verify_statfs_resp(size_t msg_len, void *msg)
{
	struct statfs_response *resp = msg;

	if (msg_len != sizeof(*resp))
		return -EINVAL;

	return 0;
}

static int hmdfs_statfs_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_statfs_req(msg_len, msg);
	else
		return verify_statfs_resp(msg_len, msg);
}

static int verify_drop_push_req(size_t msg_len, void *msg)
{
	struct drop_push_request *req = msg;
	int str_len[] = { req->path_len };

	if (req->path_len < 0 || req->path_len >= PATH_MAX)
		return -EINVAL;

	if (msg_len != sizeof(*req) + req->path_len + 1)
		return -EINVAL;

	if (is_str_msg_valid(req->path, str_len, sizeof(str_len) / sizeof(int)))
		return -EINVAL;

	return 0;
}

static int hmdfs_drop_push_verify(int flag, size_t msg_len, void *msg)
{
	if (!msg || !msg_len)
		return 0;

	if (flag == C_REQUEST)
		return verify_drop_push_req(msg_len, msg);

	return 0;
}

typedef int (*hmdfs_message_verify_func)(int, size_t, void *);

static const hmdfs_message_verify_func message_verify[F_SIZE] = {
	[F_OPEN] = hmdfs_open_verify,
	[F_READPAGE] = hmdfs_readpage_verify,
	[F_WRITEPAGE] = hmdfs_writepage_verify,
	[F_ITERATE] = hmdfs_iterate_verify,
	[F_MKDIR] = hmdfs_mkdir_verify,
	[F_RMDIR] = hmdfs_rmdir_verify,
	[F_CREATE] = hmdfs_create_verify,
	[F_UNLINK] = hmdfs_unlink_verify,
	[F_RENAME] = hmdfs_rename_verify,
	[F_SETATTR] = hmdfs_setattr_verify,
	[F_STATFS] = hmdfs_statfs_verify,
	[F_DROP_PUSH] = hmdfs_drop_push_verify,
	[F_GETATTR] = hmdfs_getattr_verify,
	[F_GETXATTR] = hmdfs_getxattr_verify,
	[F_SETXATTR] = hmdfs_setxattr_verify,
	[F_LISTXATTR] = hmdfs_listxattr_verify,
	[F_ATOMIC_OPEN] = hmdfs_atomic_open_verify,
};

static void handle_bad_message(struct hmdfs_peer *con,
			       struct hmdfs_head_cmd *head, int *err)
{
	/*
	 * Bad message won't be awared by upper layer, so ETIME is
	 * always given to upper layer. It is prefer to pass EOPNOTSUPP
	 * to upper layer when bad message (eg. caused by wrong len)
	 * received.
	 */
	if (head->operations.cmd_flag == C_RESPONSE) {
		/*
		 * Change msg ret code. To let upper layer handle
		 * EOPNOTSUPP, hmdfs_message_verify() should return
		 * 0, so err code is modified either.
		 */
		head->ret_code = cpu_to_le32(-EOPNOTSUPP);
		*err = 0;
	} else {
		if (head->operations.command >= F_SIZE)
			return;
		/*
		 * Some request messages do not need to be responded.
		 * Even if a response is returned, the response msg
		 * is automatically ignored in hmdfs_response_recv().
		 * Therefore, it is normal to directly return a response.
		 */
		if (need_response[head->operations.command])
			hmdfs_send_err_response(con, head, -EOPNOTSUPP);
	}
}

int hmdfs_message_verify(struct hmdfs_peer *con, struct hmdfs_head_cmd *head,
			 void *data)
{
	int err = 0;
	int flag, cmd, len_type;
	size_t len, min, max;

	if (!head)
		return -EINVAL;

	flag = head->operations.cmd_flag;
	if (flag != C_REQUEST && flag != C_RESPONSE)
		return -EINVAL;

	cmd = head->operations.command;
	if (cmd >= F_SIZE || cmd < F_OPEN ||
		(cmd >= F_RESERVED_1 && cmd <= F_RESERVED_4) ||
		cmd == F_RESERVED_5 || cmd == F_RESERVED_6 ||
		cmd == F_RESERVED_7 || cmd == F_RESERVED_8) {
		err = -EINVAL;
		goto handle_bad_msg;
	}

	if (head->version != DFS_2_0) {
		err = -EINVAL;
	} else {
		len = le32_to_cpu(head->data_len) -
		      sizeof(struct hmdfs_head_cmd);
		min = message_length[flag][cmd][HMDFS_MESSAGE_MIN_INDEX];
		if (head->operations.command == F_ITERATE && flag == C_RESPONSE)
			max = sizeof(struct slice_descriptor) + PAGE_SIZE;
		else
			max = message_length[flag][cmd][HMDFS_MESSAGE_MAX_INDEX];
		len_type =
			message_length[flag][cmd][HMDFS_MESSAGE_LEN_JUDGE_INDEX];

		if (len_type == MESSAGE_LEN_JUDGE_RANGE) {
			if (len < min || len > max) {
				hmdfs_err(
					"cmd %d -> %d message verify fail, len = %zu",
					cmd, flag, len);
				err = -EINVAL;
				goto handle_bad_msg;
			}
		} else {
			if (len != min && len != max) {
				hmdfs_err(
					"cmd %d -> %d message verify fail, len = %zu",
					cmd, flag, len);
				err = -EINVAL;
				goto handle_bad_msg;
			}
		}

		if (message_verify[cmd])
			err = message_verify[cmd](flag, len, data);

		if (err)
			goto handle_bad_msg;

		return err;
	}

handle_bad_msg:
	handle_bad_message(con, head, &err);
	return err;
}
