/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/inode_share.h
 *
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 */

#include "hmdfs_share.h"

static inline bool hmdfs_is_dst_path(struct path *src, struct path *dst)
{
	return (src->dentry == dst->dentry) && (src->mnt == dst->mnt);
}

static inline bool is_dst_device(char *src_cid, char *dst_cid)
{
	return strncmp(src_cid, dst_cid, HMDFS_CID_SIZE) == 0;
}

bool hmdfs_is_share_file(struct file *file)
{
	struct file *cur_file = file;
	struct hmdfs_dentry_info *gdi;
	struct hmdfs_file_info *gfi;

	while (cur_file->f_inode->i_sb->s_magic == HMDFS_SUPER_MAGIC) {
		gdi = hmdfs_d(cur_file->f_path.dentry);
		gfi = hmdfs_f(cur_file);
		if (hm_isshare(gdi->file_type))
			return true;
		if (gfi->lower_file)
			cur_file = gfi->lower_file;
		else
			break;
	}

	return false;
}

static void remove_and_release_share_item(struct hmdfs_share_item *item)
{
	list_del(&item->list);
	item->hst->item_cnt--;
	fput(item->file);
	kfree(item->relative_path.name);
	kfree(item);
}

static inline bool is_share_item_timeout(struct hmdfs_share_item *item)
{
	return !item->opened && item->timeout;
}

struct hmdfs_share_item *hmdfs_lookup_share_item(struct hmdfs_share_table *st,
						struct qstr *cur_relative_path)
{
	struct hmdfs_share_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, &st->item_list_head, list) {
		if (is_share_item_timeout(item)){
			remove_and_release_share_item(item);
		} else {
			if (qstr_eq(&item->relative_path, cur_relative_path))
				return item;
		}
	}

	return NULL;
}

static void share_item_timeout_work(struct work_struct *work) {
	struct hmdfs_share_item *item =
		container_of(work, struct hmdfs_share_item, d_work.work);

	item->timeout = true;
}

int insert_share_item(struct hmdfs_share_table *st, struct qstr *relative_path,
			struct file *file, char *cid)
{
	struct hmdfs_share_item *new_item = NULL;
	char *path_name;
	int err = 0;

	if (st->item_cnt >= st->max_cnt) {
		int ret = hmdfs_clear_first_item(st);
		if (unlikely(ret)) {
			err = -EMFILE;
			goto err_out;
		}
	}

	path_name = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!path_name)) {
		err = -EMFILE;
		goto err_out;
	}
	strcpy(path_name, relative_path->name);

	new_item = kmalloc(sizeof(*new_item), GFP_KERNEL);
	if (unlikely(!new_item)) {
		err = -ENOMEM;
		kfree(path_name);
		goto err_out;
	}

	new_item->file = file;
	get_file(file);
	new_item->relative_path.name = path_name;
	new_item->relative_path.len = relative_path->len;
	memcpy(new_item->cid, cid, HMDFS_CID_SIZE);
	new_item->opened = false;
	new_item->timeout = false;
	list_add_tail(&new_item->list, &st->item_list_head);
	new_item->hst = st;

	INIT_DELAYED_WORK(&new_item->d_work, share_item_timeout_work);
	queue_delayed_work(new_item->hst->share_item_timeout_wq,
			&new_item->d_work, HZ * HMDFS_SHARE_ITEM_TIMEOUT_S);

	st->item_cnt++;

err_out:
	return err;
}

void update_share_item(struct hmdfs_share_item *item, struct file *file,
			char *cid)
{
	/* if not the same file, we need to update struct file */
	if (!hmdfs_is_dst_path(&file->f_path, &item->file->f_path)) {
		fput(item->file);
		get_file(file);
		item->file = file;
	}
	memcpy(item->cid, cid, HMDFS_CID_SIZE);

	if (!cancel_delayed_work_sync(&item->d_work))
		item->timeout = false;

	queue_delayed_work(item->hst->share_item_timeout_wq, &item->d_work,
			HZ * HMDFS_SHARE_ITEM_TIMEOUT_S);
}

bool in_share_dir(struct dentry *child_dentry)
{
	struct dentry *parent_dentry = dget_parent(child_dentry);
	bool ret = false;

	if (!strncmp(parent_dentry->d_name.name, SHARE_RESERVED_DIR,
			strlen(SHARE_RESERVED_DIR)))
		ret = true;

	dput(parent_dentry);
	return ret;
}

inline bool is_share_dir(struct inode *inode, const char *name)
{
        return (S_ISDIR(inode->i_mode) &&
		!strncmp(name, SHARE_RESERVED_DIR, strlen(SHARE_RESERVED_DIR)));
}

int get_path_from_share_table(struct hmdfs_sb_info *sbi,
			        struct dentry *cur_dentry,
                                struct path *src_path)
{
	struct hmdfs_share_item *item;
	const char *path_name;
	struct qstr relative_path;
	int err = 0;

	path_name = hmdfs_get_dentry_relative_path(cur_dentry);
	if (unlikely(!path_name)) {
		err = -ENOMEM;
		goto err_out;
	}
	relative_path.name = path_name;
	relative_path.len = strlen(path_name);

	spin_lock(&sbi->share_table.item_list_lock);
	item = hmdfs_lookup_share_item(&sbi->share_table, &relative_path);
	if (!item) {
		err = -ENOENT;
		goto unlock;
	}
	path_get(&item->file->f_path);
	*src_path = item->file->f_path;
unlock:
	spin_unlock(&sbi->share_table.item_list_lock);
	kfree(path_name);
err_out:
	return err;
}

void hmdfs_clear_share_item_offline(struct hmdfs_peer *conn)
{
	struct hmdfs_sb_info *sbi = conn->sbi;
	struct hmdfs_share_item *item, *tmp;

	spin_lock(&sbi->share_table.item_list_lock);
	list_for_each_entry_safe(item, tmp, &sbi->share_table.item_list_head,
				list) {
		if (is_dst_device(item->cid, conn->cid)) {
			/* release the item that was not closed properly */
			if (item->opened)
				remove_and_release_share_item(item);
		}
	}
	spin_unlock(&sbi->share_table.item_list_lock);
}

void reset_item_opened_status(struct hmdfs_sb_info *sbi, const char *filename)
{
	struct qstr candidate = QSTR_INIT(filename, strlen(filename));
	struct hmdfs_share_item *item = NULL;

	spin_lock(&sbi->share_table.item_list_lock);
	item = hmdfs_lookup_share_item(&sbi->share_table, &candidate);
	if (item) {
		item->opened = false;
		queue_delayed_work(item->hst->share_item_timeout_wq,
				&item->d_work, HZ * HMDFS_SHARE_ITEM_TIMEOUT_S);
	}
	spin_unlock(&sbi->share_table.item_list_lock);
}

void hmdfs_close_share_item(struct hmdfs_sb_info *sbi, struct file *file,
			    char *cid)
{
	struct qstr relativepath;
	const char *path_name;
	struct hmdfs_share_item *item = NULL;

	path_name = hmdfs_get_dentry_relative_path(file->f_path.dentry);
	if (unlikely(!path_name)) {
		hmdfs_err("get dentry relative path error");
		return;
	}

	relativepath.name = path_name;
	relativepath.len = strlen(path_name);

	spin_lock(&sbi->share_table.item_list_lock);
	item = hmdfs_lookup_share_item(&sbi->share_table, &relativepath);
	if (unlikely(!item)) {
		hmdfs_err("cannot get share item %s", relativepath.name);
		goto unlock;
	}

	/*
	 * If the item is shared to all device, we should close the item directly.
	 */
	if (!strcmp(item->cid, SHARE_ALL_DEVICE)) {
		goto close;
	}

	if (unlikely(!is_dst_device(item->cid, cid))) {
		hmdfs_err("item not right, dst cid is: %s", item->cid);
		goto unlock;
	}

	/*
	 * After remote close, we should reset the opened status and restart
	 * delayed timeout work.
	 */
close:
	item->opened = false;
	queue_delayed_work(item->hst->share_item_timeout_wq, &item->d_work,
				HZ * HMDFS_SHARE_ITEM_TIMEOUT_S);

unlock:
	spin_unlock(&sbi->share_table.item_list_lock);
	kfree(path_name);
}

int hmdfs_check_share_access_permission(struct hmdfs_sb_info *sbi,
						const char *filename,
						char *cid)
{
	struct qstr candidate = QSTR_INIT(filename, strlen(filename));
	struct hmdfs_share_item *item = NULL;
	int ret = -ENOENT;

	spin_lock(&sbi->share_table.item_list_lock);
	item = hmdfs_lookup_share_item(&sbi->share_table, &candidate);
	/*
	 * When cid matches, we set the item status opened and canel
	 * its delayed work to ensure that the open process can get
	 * the correct path
	 */
	if (item && (is_dst_device(item->cid, cid) || !strcmp(item->cid, SHARE_ALL_DEVICE))) {
		item->opened = true;
		if (!cancel_delayed_work_sync(&item->d_work)) {
			item->timeout = false;
		}
		ret = 0;
	}
	spin_unlock(&sbi->share_table.item_list_lock);

	return ret;
}


int hmdfs_init_share_table(struct hmdfs_sb_info *sbi)
{
	spin_lock_init(&sbi->share_table.item_list_lock);
	INIT_LIST_HEAD(&sbi->share_table.item_list_head);
	sbi->share_table.item_cnt = 0;
	sbi->share_table.max_cnt = HMDFS_SHARE_ITEMS_MAX;
	sbi->share_table.share_item_timeout_wq =
			create_singlethread_workqueue("share_item_timeout_wq");

	if (!sbi->share_table.share_item_timeout_wq)
		return -ENOMEM;
	return 0;
}

void hmdfs_clear_share_table(struct hmdfs_sb_info *sbi)
{
	struct hmdfs_share_table *st = &sbi->share_table;
	struct hmdfs_share_item *item, *tmp;

	spin_lock(&sbi->share_table.item_list_lock);
	list_for_each_entry_safe(item, tmp, &sbi->share_table.item_list_head,
				list) {
		flush_delayed_work(&item->d_work);
		remove_and_release_share_item(item);
	}
	spin_unlock(&sbi->share_table.item_list_lock);

	destroy_workqueue(st->share_item_timeout_wq);
}

int hmdfs_clear_first_item(struct hmdfs_share_table *st)
{
	int ret = -EMFILE;
	struct hmdfs_share_item *item, *tmp;
	list_for_each_entry_safe(item, tmp, &st->item_list_head, list) {
		if (!item->timeout) {
			cancel_delayed_work_sync(&item->d_work);
		}
		remove_and_release_share_item(item);
		ret = 0;
		break;
	}
	return ret;
}
