// SPDX-License-Identifier: GPL-2.0
/*
 * fs/hmdfs/file_merge.c
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#include "hmdfs_merge_view.h"

#include <linux/file.h>

#include "hmdfs.h"
#include "hmdfs_trace.h"
#include "authority/authentication.h"

struct hmdfs_iterate_callback_merge {
	struct dir_context ctx;
	struct dir_context *caller;
	/*
	 * Record the return value of 'caller->actor':
	 *
	 * -EINVAL, buffer is exhausted
	 * -EINTR, current task is pending
	 * -EFAULT, something is wrong
	 * 0, success and can do more
	 */
	int result;
	struct rb_root *root;
	uint64_t dev_id;
};

struct hmdfs_cache_entry {
	struct rb_node rb_node;
	int name_len;
	char *name;
	int file_type;
};

struct hmdfs_user_info {
	char *local_path;
	char *distributed_path;
	char *bundle_name;
};

struct hmdfs_cache_entry *allocate_entry(const char *name, int namelen,
					 int d_type)
{
	struct hmdfs_cache_entry *data;

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	data->name = kstrndup(name, namelen, GFP_KERNEL);
	if (!data->name) {
		kfree(data);
		return ERR_PTR(-ENOMEM);
	}

	data->name_len = namelen;
	data->file_type = d_type;

	return data;
}

int insert_filename(struct rb_root *root, struct hmdfs_cache_entry **new_entry)
{
	struct rb_node *parent = NULL;
	struct rb_node **new_node = &(root->rb_node);
	int cmp_res = 0;
	struct hmdfs_cache_entry *data = *new_entry;

	while (*new_node) {
		struct hmdfs_cache_entry *entry = container_of(
			*new_node, struct hmdfs_cache_entry, rb_node);
		parent = *new_node;

		if (data->name_len < entry->name_len)
			cmp_res = -1;
		else if (data->name_len > entry->name_len)
			cmp_res = 1;
		else
			cmp_res = strncmp(data->name, entry->name,
					  data->name_len);

		if (!cmp_res) {
			kfree(data->name);
			kfree(data);
			*new_entry = entry;
			return entry->file_type;
		}

		if (cmp_res < 0)
			new_node = &((*new_node)->rb_left);
		else if (cmp_res > 0)
			new_node = &((*new_node)->rb_right);
	}

	rb_link_node(&data->rb_node, parent, new_node);
	rb_insert_color(&data->rb_node, root);

	return 0;
}

static void recursive_delete(struct rb_node *node)
{
	struct hmdfs_cache_entry *entry = NULL;

	if (!node)
		return;

	recursive_delete(node->rb_left);
	recursive_delete(node->rb_right);

	entry = container_of(node, struct hmdfs_cache_entry, rb_node);
	kfree(entry->name);
	kfree(entry);
}

static void destroy_tree(struct rb_root *root)
{
	if (!root)
		return;
	recursive_delete(root->rb_node);
	root->rb_node = NULL;
}

static void delete_filename(struct rb_root *root,
			    struct hmdfs_cache_entry *data)
{
	struct rb_node **node = &(root->rb_node);
	struct hmdfs_cache_entry *entry = NULL;
	int cmp_res = 0;

	while (*node) {
		entry = container_of(*node, struct hmdfs_cache_entry, rb_node);
		if (data->name_len < entry->name_len)
			cmp_res = -1;
		else if (data->name_len > entry->name_len)
			cmp_res = 1;
		else
			cmp_res = strncmp(data->name, entry->name,
					  data->name_len);

		if (!cmp_res)
			goto found;

		if (cmp_res < 0)
			node = &((*node)->rb_left);
		else if (cmp_res > 0)
			node = &((*node)->rb_right);
	}
	return;

found:
	rb_erase(*node, root);
	kfree(entry->name);
	kfree(entry);
}

static void rename_conflicting_file(char *dentry_name, int *len,
				    unsigned int dev_id)
{
	int i = *len - 1;
	int dot_pos = -1;
	char *buffer;

	buffer = kzalloc(DENTRY_NAME_MAX_LEN, GFP_KERNEL);
	if (!buffer)
		return;

	while (i >= 0) {
		if (dentry_name[i] == '/')
			break;
		if (dentry_name[i] == '.') {
			// TODO: 这个修改同步到 CT01
			dot_pos = i;
			break;
		}
		i--;
	}

	if (dot_pos == -1) {
		snprintf(dentry_name + *len, DENTRY_NAME_MAX_LEN - *len,
			 CONFLICTING_FILE_SUFFIX, dev_id);
		goto done;
	}

	for (i = 0; i < *len - dot_pos; i++)
		buffer[i] = dentry_name[i + dot_pos];

	buffer[i] = '\0';
	snprintf(dentry_name + dot_pos, DENTRY_NAME_MAX_LEN - dot_pos,
		 CONFLICTING_FILE_SUFFIX, dev_id);
	strcat(dentry_name, buffer);

done:
	*len = strlen(dentry_name);
	kfree(buffer);
}

static void rename_conflicting_directory(char *dentry_name, int *len)
{
	snprintf(dentry_name + *len, DENTRY_NAME_MAX_LEN - *len,
		 CONFLICTING_DIR_SUFFIX);
	*len += strlen(CONFLICTING_DIR_SUFFIX);
}

static int hmdfs_actor_merge(struct dir_context *ctx, const char *name,
			     int namelen, loff_t offset, u64 ino,
			     unsigned int d_type)
{
	int ret = 0;
	int insert_res = 0;
	int max_devid_len = 2;
	char *dentry_name = NULL;
	int dentry_len = namelen;
	struct hmdfs_cache_entry *cache_entry = NULL;
	struct hmdfs_iterate_callback_merge *iterate_callback_merge = NULL;
	struct dir_context *org_ctx = NULL;

	if (hmdfs_file_type(name) != HMDFS_TYPE_COMMON)
		return 0;

	if (namelen > NAME_MAX)
		return -EINVAL;
	dentry_name = kzalloc(NAME_MAX + 1, GFP_KERNEL);
	if (!dentry_name)
		return -ENOMEM;

	strncpy(dentry_name, name, dentry_len);

	cache_entry = allocate_entry(dentry_name, dentry_len, d_type);
	if (IS_ERR(cache_entry)) {
		ret = PTR_ERR(cache_entry);
		goto done;
	}

	iterate_callback_merge =
		container_of(ctx, struct hmdfs_iterate_callback_merge, ctx);
	insert_res =
		insert_filename(iterate_callback_merge->root, &cache_entry);
	if (d_type == DT_DIR && insert_res == DT_DIR) {
		goto done;
	} else if (d_type == DT_DIR &&
		  (insert_res == DT_REG || insert_res == DT_LNK)) {
		if (strlen(CONFLICTING_DIR_SUFFIX) > NAME_MAX - dentry_len) {
			ret = -ENAMETOOLONG;
			goto delete;
		}
		rename_conflicting_directory(dentry_name, &dentry_len);
		cache_entry->file_type = DT_DIR;
	} else if ((d_type == DT_REG || d_type == DT_LNK) && insert_res > 0) {
		if (strlen(CONFLICTING_FILE_SUFFIX) + max_devid_len >
		    NAME_MAX - dentry_len) {
			ret = -ENAMETOOLONG;
			goto delete;
		}
		rename_conflicting_file(dentry_name, &dentry_len,
					iterate_callback_merge->dev_id);
	}

	org_ctx = iterate_callback_merge->caller;
	ret = org_ctx->actor(org_ctx, dentry_name, dentry_len, org_ctx->pos,
			     ino, d_type);
	/*
	 * Record original return value, so that the caller can be aware of
	 * different situations.
	 */
	iterate_callback_merge->result = ret;
	ret = ret == 0 ? 0 : 1;
	if (ret && d_type == DT_DIR && cache_entry->file_type == DT_DIR &&
	   (insert_res == DT_REG || insert_res == DT_LNK))
		cache_entry->file_type = DT_REG;

delete:
	if (ret && !insert_res)
		delete_filename(iterate_callback_merge->root, cache_entry);
done:
	kfree(dentry_name);
	return ret;
}

struct hmdfs_file_info *
get_next_hmdfs_file_info(struct hmdfs_file_info *fi_head, int device_id)
{
	struct hmdfs_file_info *fi_iter = NULL;
	struct hmdfs_file_info *fi_result = NULL;

	mutex_lock(&fi_head->comrade_list_lock);
	list_for_each_entry_safe(fi_iter, fi_result, &(fi_head->comrade_list),
				  comrade_list) {
		if (fi_iter->device_id == device_id)
			break;
	}
	mutex_unlock(&fi_head->comrade_list_lock);

	return fi_result != fi_head ? fi_result : NULL;
}

struct hmdfs_file_info *get_hmdfs_file_info(struct hmdfs_file_info *fi_head,
					    int device_id)
{
	struct hmdfs_file_info *fi_iter = NULL;

	mutex_lock(&fi_head->comrade_list_lock);
	list_for_each_entry(fi_iter, &(fi_head->comrade_list), comrade_list) {
		if (fi_iter->device_id == device_id) {
			mutex_unlock(&fi_head->comrade_list_lock);
			return fi_iter;
		}
	}
	mutex_unlock(&fi_head->comrade_list_lock);

	return NULL;
}

int hmdfs_iterate_merge(struct file *file, struct dir_context *ctx)
{
	int err = 0;
	struct hmdfs_file_info *fi_head = hmdfs_f(file);
	struct hmdfs_file_info *fi_iter = NULL;
	struct file *lower_file_iter = NULL;
	loff_t start_pos = ctx->pos;
	unsigned long device_id = (unsigned long)((ctx->pos) << 1 >>
				  (POS_BIT_NUM - DEV_ID_BIT_NUM));
	struct hmdfs_iterate_callback_merge ctx_merge = {
		.ctx.actor = hmdfs_actor_merge,
		.caller = ctx,
		.root = &fi_head->root,
		.dev_id = device_id
	};

	/* pos = -1 indicates that all devices have been traversed
	 * or an error has occurred.
	 */
	if (ctx->pos == -1)
		return 0;

	fi_iter = get_hmdfs_file_info(fi_head, device_id);
	if (!fi_iter) {
		fi_iter = get_next_hmdfs_file_info(fi_head, device_id);
		// dev_id is changed, parameter is set 0 to get next file info
		if (fi_iter)
			ctx_merge.ctx.pos =
				hmdfs_set_pos(fi_iter->device_id, 0, 0);
	}
	while (fi_iter) {
		ctx_merge.dev_id = fi_iter->device_id;
		device_id = ctx_merge.dev_id;
		lower_file_iter = fi_iter->lower_file;
		lower_file_iter->f_pos = file->f_pos;
		err = iterate_dir(lower_file_iter, &ctx_merge.ctx);
		file->f_pos = lower_file_iter->f_pos;
		ctx->pos = file->f_pos;

		if (err)
			goto done;
		/*
		 * ctx->actor return nonzero means buffer is exhausted or
		 * something is wrong, thus we should not continue.
		 */
		if (ctx_merge.result)
			goto done;
		fi_iter = get_next_hmdfs_file_info(fi_head, device_id);
		if (fi_iter) {
			file->f_pos = hmdfs_set_pos(fi_iter->device_id, 0, 0);
			ctx->pos = file->f_pos;
		}
	}
done:
	trace_hmdfs_iterate_merge(file->f_path.dentry, start_pos, ctx->pos,
				  err);
	return err;
}

int do_dir_open_merge(struct file *file, const struct cred *cred,
		      struct hmdfs_file_info *fi_head)
{
	int ret = -EINVAL;
	struct hmdfs_dentry_info_merge *dim = hmdfs_dm(file->f_path.dentry);
	struct hmdfs_dentry_comrade *comrade = NULL;
	struct hmdfs_file_info *fi = NULL;
	struct path lo_p = { .mnt = file->f_path.mnt };
	struct file *lower_file = NULL;

	if (IS_ERR_OR_NULL(cred))
		return ret;

	wait_event(dim->wait_queue, !has_merge_lookup_work(dim));

	mutex_lock(&dim->comrade_list_lock);
	list_for_each_entry(comrade, &(dim->comrade_list), list) {
		fi = kzalloc(sizeof(*fi), GFP_KERNEL);
		if (!fi) {
			ret = ret ? -ENOMEM : 0;
			continue; // allow some dir to fail to open
		}
		lo_p.dentry = comrade->lo_d;
		// make sure that dentry will not be dentry_kill before open
		dget(lo_p.dentry);
		if (unlikely(d_is_negative(lo_p.dentry))) {
			hmdfs_info("dentry is negative, try again");
			kfree(fi);
			dput(lo_p.dentry);
			continue;  // skip this device
		}
		lower_file = dentry_open(&lo_p, file->f_flags, cred);
		dput(lo_p.dentry);
		if (IS_ERR(lower_file)) {
			kfree(fi);
			continue;
		}
		ret = 0;
		fi->device_id = comrade->dev_id;
		fi->lower_file = lower_file;
		mutex_lock(&fi_head->comrade_list_lock);
		list_add_tail(&fi->comrade_list, &fi_head->comrade_list);
		mutex_unlock(&fi_head->comrade_list_lock);
	}
	mutex_unlock(&dim->comrade_list_lock);
	return ret;
}

int hmdfs_dir_open_merge(struct inode *inode, struct file *file)
{
	int ret = 0;
	struct hmdfs_file_info *fi = NULL;

	fi = kzalloc(sizeof(*fi), GFP_KERNEL);
	if (!fi)
		return -ENOMEM;

	file->private_data = fi;
	fi->root = RB_ROOT;
	mutex_init(&fi->comrade_list_lock);
	INIT_LIST_HEAD(&fi->comrade_list);

	ret = do_dir_open_merge(file, hmdfs_sb(inode->i_sb)->cred, fi);
	if (ret)
		kfree(fi);

	return ret;
}

int hmdfs_dir_release_merge(struct inode *inode, struct file *file)
{
	struct hmdfs_file_info *fi_head = hmdfs_f(file);
	struct hmdfs_file_info *fi_iter = NULL;
	struct hmdfs_file_info *fi_temp = NULL;

	mutex_lock(&fi_head->comrade_list_lock);
	list_for_each_entry_safe(fi_iter, fi_temp, &(fi_head->comrade_list),
				  comrade_list) {
		list_del_init(&(fi_iter->comrade_list));
		fput(fi_iter->lower_file);
		kfree(fi_iter);
	}
	mutex_unlock(&fi_head->comrade_list_lock);
	destroy_tree(&fi_head->root);
	file->private_data = NULL;
	kfree(fi_head);

	return 0;
}

static long hmdfs_ioc_get_dst_path(struct file *filp, unsigned long arg);

long hmdfs_dir_unlocked_ioctl_merge(struct file *file, unsigned int cmd,
							unsigned long arg)
{
	struct hmdfs_file_info *fi_head = hmdfs_f(file);
	struct hmdfs_file_info *fi_iter = NULL;
	struct hmdfs_file_info *fi_temp = NULL;
	struct file *lower_file = NULL;
	int error = -ENOTTY;

	if (cmd == HMDFS_IOC_GET_DST_PATH)
		return hmdfs_ioc_get_dst_path(file, arg);
	mutex_lock(&fi_head->comrade_list_lock);
	list_for_each_entry_safe(fi_iter, fi_temp, &(fi_head->comrade_list),
				  comrade_list) {
		if (fi_iter->device_id == 0) {
			lower_file = fi_iter->lower_file;
			if (lower_file->f_op->unlocked_ioctl)
				error = lower_file->f_op->unlocked_ioctl(
					lower_file, cmd, arg);
			break;
		}
	}
	mutex_unlock(&fi_head->comrade_list_lock);
	return error;
}

long hmdfs_dir_compat_ioctl_merge(struct file *file, unsigned int cmd,
							unsigned long arg)
{
	struct hmdfs_file_info *fi_head = hmdfs_f(file);
	struct hmdfs_file_info *fi_iter = NULL;
	struct hmdfs_file_info *fi_temp = NULL;
	struct file *lower_file = NULL;
	int error = -ENOTTY;

	if (cmd == HMDFS_IOC_GET_DST_PATH)
		return hmdfs_ioc_get_dst_path(file, arg);
	mutex_lock(&fi_head->comrade_list_lock);
	list_for_each_entry_safe(fi_iter, fi_temp, &(fi_head->comrade_list),
				  comrade_list) {
		if (fi_iter->device_id == 0) {
			lower_file = fi_iter->lower_file;
			if (lower_file->f_op->compat_ioctl)
				error = lower_file->f_op->compat_ioctl(
					lower_file, cmd, arg);
			break;
		}
	}
	mutex_unlock(&fi_head->comrade_list_lock);
	return error;
}

const struct file_operations hmdfs_dir_fops_merge = {
	.owner = THIS_MODULE,
	.iterate = hmdfs_iterate_merge,
	.open = hmdfs_dir_open_merge,
	.release = hmdfs_dir_release_merge,
	.unlocked_ioctl = hmdfs_dir_unlocked_ioctl_merge,
	.compat_ioctl = hmdfs_dir_compat_ioctl_merge,
};

static ssize_t hmdfs_merge_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	return hmdfs_do_read_iter(iocb->ki_filp, iter, &iocb->ki_pos);
}

ssize_t hmdfs_merge_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	return hmdfs_do_write_iter(iocb->ki_filp, iter, &iocb->ki_pos);
}

int hmdfs_file_open_merge(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lo_p = { .mnt = file->f_path.mnt };
	struct super_block *sb = inode->i_sb;
	const struct cred *cred = hmdfs_sb(sb)->cred;
	struct hmdfs_file_info *gfi = NULL;
	struct dentry *parent = NULL;

	lo_p.dentry = hmdfs_get_fst_lo_d(file->f_path.dentry);
	if (!lo_p.dentry) {
		err = -EINVAL;
		goto out_err;
	}

	gfi = kzalloc(sizeof(*gfi), GFP_KERNEL);
	if (!gfi) {
		err = -ENOMEM;
		goto out_err;
	}

	parent = dget_parent(file->f_path.dentry);
	lower_file = dentry_open(&lo_p, file->f_flags, cred);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		kfree(gfi);
	} else {
		gfi->lower_file = lower_file;
		file->private_data = gfi;
		hmdfs_update_upper_file(file, lower_file);
	}
	dput(parent);
out_err:
	dput(lo_p.dentry);
	return err;
}

int hmdfs_file_flush_merge(struct file *file, fl_owner_t id)
{
	struct hmdfs_file_info *gfi = hmdfs_f(file);
	struct file *lower_file = gfi->lower_file;

	if (lower_file->f_op->flush)
		return lower_file->f_op->flush(lower_file, id);

	return 0;
}

static long hmdfs_ioc_get_writeopen_cnt(struct file *filp, unsigned long arg)
{
	struct hmdfs_file_info *gfi = hmdfs_f(filp);
	struct file *lower_file = gfi->lower_file;
	struct inode *lower_inode = file_inode(lower_file);

	u32 wo_cnt = atomic_read(&(hmdfs_i(lower_inode))->write_opened);

	return put_user(wo_cnt, (int __user *)arg);
}

static int copy_string_from_user(unsigned long pos, unsigned long len,
				char **data)
{
	char *tmp_data;

	if (len >= PATH_MAX)
		return -EINVAL;
	if (!access_ok(pos, len))
		return -EFAULT;

	tmp_data = kzalloc(len + 1, GFP_KERNEL);
	if (!tmp_data)
		return -ENOMEM;
	*data = tmp_data;

	if (copy_from_user(tmp_data, (char __user *)pos, len))
		return -EFAULT;

	return 0;
}

static int hmdfs_get_info_from_user(unsigned long pos,
		struct hmdfs_dst_info *hdi, struct hmdfs_user_info *data)
{
	int ret = 0;

	if (!access_ok((struct hmdfs_dst_info __user *)pos,
			sizeof(struct hmdfs_dst_info)))
		return -ENOMEM;
	if (copy_from_user(hdi, (struct hmdfs_dst_info __user *)pos,
			sizeof(struct hmdfs_dst_info)))
		return -EFAULT;

	ret = copy_string_from_user(hdi->local_path_pos, hdi->local_path_len,
				    &data->local_path);
	if (ret != 0)
		return ret;

	ret = copy_string_from_user(hdi->distributed_path_pos,
				    hdi->distributed_path_len,
				    &data->distributed_path);
	if (ret != 0)
		return ret;

	ret = copy_string_from_user(hdi->bundle_name_pos, hdi->bundle_name_len,
				    &data->bundle_name);
	if (ret != 0)
		return ret;

	return 0;
}

static const struct cred *change_cred(struct dentry *dentry,
				      const char *bundle_name)
{
	int bid;
	struct cred *cred = NULL;
	const struct cred *old_cred = NULL;

	cred = prepare_creds();
	if (!cred) {
		return NULL;
	}
	bid = get_bundle_uid(hmdfs_sb(dentry->d_sb), bundle_name);
	if (bid != 0) {
		cred->fsuid = KUIDT_INIT(bid);
		cred->fsgid = KGIDT_INIT(bid);
		old_cred = override_creds(cred);
	}

	return old_cred;
}

static int get_file_size(const char *path_value, uint64_t pos)
{
	int ret;
	uint64_t size;
	struct path path;
	struct kstat buf;

	ret = kern_path(path_value, 0, &path);
	if (ret)
		return ret;
	ret = vfs_getattr(&path, &buf, STATX_BASIC_STATS | STATX_BTIME, 0);
	path_put(&path);
	if (ret) {
		hmdfs_err("call vfs_getattr failed, err %d", ret);
		return ret;
	}

	size = buf.size;
	ret = copy_to_user((uint64_t __user *)pos, &size, sizeof(uint64_t));
	return ret;
}

static int create_link_file(struct hmdfs_user_info *data)
{
	int ret;
	struct dentry *dentry;
	struct path path;

	ret = kern_path(data->distributed_path, 0, &path);
	if (ret == 0){
		path_put(&path);
		return ret;
	}

	dentry = kern_path_create(AT_FDCWD, data->distributed_path, &path, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	ret = vfs_symlink(path.dentry->d_inode, dentry, data->local_path);
	done_path_create(&path, dentry);

	return ret;
}

static int create_dir(const char *path_value, mode_t mode)
{
	int err = 0;
	struct path path;
	struct dentry *dentry;

	dentry = kern_path_create(AT_FDCWD, path_value, &path, LOOKUP_DIRECTORY);
	if(PTR_ERR(dentry) == -EEXIST)
		return 0;
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	err = vfs_mkdir(d_inode(path.dentry), dentry, mode);
	if (err && err != -EEXIST)
		hmdfs_err("vfs_mkdir failed, err = %d", err);
	done_path_create(&path, dentry);

	return err;
}

static int create_dir_recursive(const char *path_value, mode_t mode)
{
	int err = 0;
	char *tmp_path = kstrdup(path_value, GFP_KERNEL);
	char *p = tmp_path;

	if (!tmp_path)
		return -ENOMEM;

	if (*p == '/')
		p++;

	while (*p) {
		if (*p == '/') {
			*p = '\0';
			err = create_dir(tmp_path, mode);
			if (err != 0)
				break;
			*p = '/';
		}
		p++;
	}

	kfree(tmp_path);
	return err;
}

static long hmdfs_ioc_get_dst_path(struct file *filp, unsigned long arg)
{
	int ret = 0;
	const struct cred *old_cred;
	struct hmdfs_dst_info hdi;
	struct hmdfs_user_info *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto err_free_data;
	}

	ret = hmdfs_get_info_from_user(arg, &hdi, data);
	if (ret != 0)
		goto err_free_all;

	old_cred = change_cred(filp->f_path.dentry, data->bundle_name);
	if (!old_cred) {
		ret = -EACCES;
		goto err_free_all;
	}

	ret = create_dir_recursive(data->distributed_path, DIR_MODE);
	if (ret != 0)
		goto err_revert;

	ret = create_link_file(data);
	if (ret != 0 && ret != -EEXIST)
		goto err_revert;

	ret = get_file_size(data->local_path, hdi.size);

err_revert:
	revert_creds(old_cred);
err_free_all:
	kfree(data->local_path);
	kfree(data->distributed_path);
	kfree(data->bundle_name);
err_free_data:
	kfree(data);
	return ret;
}

static long hmdfs_file_ioctl_merge(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case HMDFS_IOC_GET_WRITEOPEN_CNT:
		return hmdfs_ioc_get_writeopen_cnt(filp, arg);
	case HMDFS_IOC_GET_DST_PATH:
		return hmdfs_ioc_get_dst_path(filp, arg);
	default:
		return -ENOTTY;
	}
}

/* Transparent transmission of parameters to device_view level,
 * so file operations are same as device_view local operations.
 */
const struct file_operations hmdfs_file_fops_merge = {
	.owner = THIS_MODULE,
	.llseek = hmdfs_file_llseek_local,
	.read_iter = hmdfs_merge_read_iter,
	.write_iter = hmdfs_merge_write_iter,
	.mmap = hmdfs_file_mmap_local,
	.open = hmdfs_file_open_merge,
	.flush = hmdfs_file_flush_merge,
	.release = hmdfs_file_release_local,
	.fsync = hmdfs_fsync_local,
	.unlocked_ioctl	= hmdfs_file_ioctl_merge,
	.compat_ioctl = hmdfs_file_ioctl_merge,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
};
