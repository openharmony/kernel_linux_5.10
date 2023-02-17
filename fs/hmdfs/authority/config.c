/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/hmdfs/comm/authority/config.c
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 */

#include <linux/configfs.h>
#include <linux/ctype.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include "hmdfs.h"

#define UID_ATTR_TYPE 0
#define GID_ATTR_TYPE 1

static struct kmem_cache *hmdfs_bid_entry_cachep;

struct hmdfs_bid_entry {
	struct hlist_node node;
	struct qstr str;
	int id;
};

struct hmdfs_config_bitem {
	struct config_item item;
	struct qstr str;
};

static unsigned int make_hash(const char *name, unsigned int len)
{
	unsigned long hash;
	
	hash = init_name_hash(0);
	while (len--)
		hash = partial_name_hash(tolower(*name++), hash);

	return end_name_hash(hash);
}

static struct qstr make_qstr(const char *name)
{
	struct qstr str;
	str.name = name;
	str.len = strlen(name);
	str.hash = make_hash(str.name, str.len);

	return str;
}

static struct hmdfs_bid_entry *alloc_bid_entry(const char *name, int id)
{
	struct hmdfs_bid_entry *bid_entry;
	char *bid_entry_name;

	bid_entry = kmem_cache_alloc(hmdfs_bid_entry_cachep, GFP_KERNEL);
	if (!bid_entry) {
		bid_entry = ERR_PTR(-ENOMEM);
		goto out;
	}

	bid_entry_name = kstrdup(name, GFP_KERNEL);
	if (!bid_entry_name) {
		kmem_cache_free(hmdfs_bid_entry_cachep, bid_entry);
		bid_entry = ERR_PTR(-ENOMEM);
		goto out;
	}

	INIT_HLIST_NODE(&bid_entry->node);
	bid_entry->str = make_qstr(bid_entry_name);
	bid_entry->id = id;
out:
	return bid_entry;
}

static void free_bid_entry(struct hmdfs_bid_entry *bid_entry)
{
	if (bid_entry == NULL)
		return;

	kfree(bid_entry->str.name);
	kmem_cache_free(hmdfs_bid_entry_cachep, bid_entry);
}

static struct hmdfs_config_bitem *alloc_bitem(const char *name)
{
	struct hmdfs_config_bitem *bitem;
	char *bitem_name;

	bitem = kzalloc(sizeof(*bitem), GFP_KERNEL);
	if (!bitem) {
		bitem = ERR_PTR(-ENOMEM);
		goto out;
	}

	bitem_name = kstrdup(name, GFP_KERNEL);
	if (!bitem_name) {
		kfree(bitem);
		bitem = ERR_PTR(-ENOMEM);
		goto out;
	}

	bitem->str = make_qstr(bitem_name);
out:
	return bitem;
}

static void free_bitem(struct hmdfs_config_bitem *bitem)
{
	if (bitem == NULL)
		return;

	kfree(bitem->str.name);
	kfree(bitem);
}

#define HMDFS_BUNDLE_ATTRIBUTE(_attr_)					\
									\
static DEFINE_HASHTABLE(hmdfs_##_attr_##_hash_table, 4);		\
									\
static DEFINE_MUTEX(hmdfs_##_attr_##_hash_mutex);			\
									\
static int query_##_attr_##_hash_entry(struct qstr *str)		\
{									\
	int id = 0;							\
	struct hmdfs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	mutex_lock(&hmdfs_##_attr_##_hash_mutex);			\
	hash_for_each_possible_safe(hmdfs_##_attr_##_hash_table,	\
		bid_entry, hash_node, node, str->hash) {		\
		if (qstr_case_eq(str, &bid_entry->str)) {		\
			id = bid_entry->id;				\
			break;						\
		}							\
	}								\
	mutex_unlock(&hmdfs_##_attr_##_hash_mutex);			\
									\
	return id;							\
}									\
									\
static int insert_##_attr_##_hash_entry(struct qstr *str, int id)	\
{									\
	int err = 0;							\
	struct hmdfs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	hmdfs_info("insert name = %s", str->name);			\
									\
	mutex_lock(&hmdfs_##_attr_##_hash_mutex);			\
	hash_for_each_possible_safe(hmdfs_##_attr_##_hash_table,	\
		bid_entry, hash_node, node, str->hash) {		\
		if (qstr_case_eq(str, &bid_entry->str)) {		\
			bid_entry->id = id;				\
			mutex_unlock(&hmdfs_##_attr_##_hash_mutex);	\
			goto out;					\
		}							\
	}								\
	mutex_unlock(&hmdfs_##_attr_##_hash_mutex);			\
									\
	bid_entry = alloc_bid_entry(str->name, id);			\
	if (IS_ERR(bid_entry)) {					\
		err = PTR_ERR(bid_entry);				\
		goto out;						\
	} 								\
									\
	hash_add_rcu(hmdfs_##_attr_##_hash_table, &bid_entry->node,	\
		 bid_entry->str.hash);					\
out:									\
	return err;							\
}									\
									\
static void remove_##_attr_##_hash_entry(struct qstr *str)		\
{									\
	struct hmdfs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	hmdfs_info("remove name = %s", str->name);			\
									\
	mutex_lock(&hmdfs_##_attr_##_hash_mutex);			\
	hash_for_each_possible_safe(hmdfs_##_attr_##_hash_table,	\
		bid_entry, hash_node, node, str->hash) {		\
		if (qstr_case_eq(str, &bid_entry->str)) {		\
			hash_del_rcu(&bid_entry->node);			\
			free_bid_entry(bid_entry);			\
			break;						\
		}							\
	}								\
	mutex_unlock(&hmdfs_##_attr_##_hash_mutex);			\
}									\
									\
static void clear_##_attr_##_hash_entry(void)				\
{									\
	int index;							\
	struct hmdfs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	hmdfs_info("clear bid entry");					\
									\
	mutex_lock(&hmdfs_##_attr_##_hash_mutex);			\
	hash_for_each_safe(hmdfs_##_attr_##_hash_table, index,		\
		hash_node, bid_entry, node) {				\
		hash_del_rcu(&bid_entry->node);				\
		kfree(bid_entry->str.name);				\
		kmem_cache_free(hmdfs_bid_entry_cachep, bid_entry);	\
	}								\
	mutex_unlock(&hmdfs_##_attr_##_hash_mutex);			\
}									\
									\
static int hmdfs_##_attr_##_get(const char *bname)			\
{									\
	struct qstr str;						\
									\
	str = make_qstr(bname);						\
	return query_##_attr_##_hash_entry(&str);			\
}									\
									\
static ssize_t hmdfs_##_attr_##_show(struct config_item *item,		\
	char *page)							\
{									\
	int id;								\
	struct hmdfs_config_bitem *bitem;				\
									\
	hmdfs_info("show bundle id");					\
									\
	bitem = container_of(item, struct hmdfs_config_bitem, item);	\
	id = query_##_attr_##_hash_entry(&bitem->str);			\
									\
	return scnprintf(page, PAGE_SIZE, "%u\n", id);			\
}									\
									\
static ssize_t hmdfs_##_attr_##_store(struct config_item *item,	\
	const char *page, size_t count)					\
{									\
	int id;								\
	int err;							\
	size_t size;							\
	struct hmdfs_config_bitem *bitem;				\
									\
	hmdfs_info("store bundle id");					\
									\
	bitem = container_of(item, struct hmdfs_config_bitem, item);	\
									\
	if (kstrtouint(page, 10, &id)) {				\
		size = -EINVAL;						\
		goto out; 						\
	}								\
									\
	err = insert_##_attr_##_hash_entry(&bitem->str, id);		\
	if (err) {							\
		size = err;						\
		goto out;						\
	}								\
									\
	size = count;							\
out:									\
	return size;							\
}									\
									\
static struct configfs_attribute hmdfs_##_attr_##_attr = {		\
	.ca_name	= __stringify(_attr_),				\
	.ca_mode	= S_IRUGO | S_IWUGO,				\
	.ca_owner	= THIS_MODULE,					\
	.show		= hmdfs_##_attr_##_show,			\
	.store		= hmdfs_##_attr_##_store,			\
};					

HMDFS_BUNDLE_ATTRIBUTE(appid)

static struct configfs_attribute *hmdfs_battrs[] = {
	&hmdfs_appid_attr,
	NULL,
};

static void hmdfs_config_bitem_release(struct config_item *item)
{
	struct hmdfs_config_bitem *bitem;

	hmdfs_info("release bundle item");

	bitem = container_of(item, struct hmdfs_config_bitem, item);
	remove_appid_hash_entry(&bitem->str);
	remove_appid_hash_entry(&bitem->str);
	free_bitem(bitem);
}

static struct configfs_item_operations hmdfs_config_bitem_ops = {
	.release = hmdfs_config_bitem_release,
};

static struct config_item_type hmdfs_config_bitem_type = {
	.ct_item_ops	= &hmdfs_config_bitem_ops,
	.ct_attrs	= hmdfs_battrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item *hmdfs_make_bitem(struct config_group *group,
					      const char *name)
{
	struct config_item *item;
	struct hmdfs_config_bitem *bitem;

	hmdfs_info("make bundle item = %s", name);

	bitem = alloc_bitem(name);
	if (IS_ERR(bitem)) {
		item = ERR_PTR(-ENOMEM);
		goto out;
	}

	config_item_init_type_name(&bitem->item, name,
		&hmdfs_config_bitem_type);
	item = &bitem->item;
out:
	return item;
}

static struct configfs_group_operations hmdfs_group_ops = {
	.make_item = hmdfs_make_bitem,
};

static struct config_item_type hmdfs_group_type = {
    .ct_group_ops     = &hmdfs_group_ops,
    .ct_owner     = THIS_MODULE,
};

static struct configfs_subsystem hmdfs_subsystem = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "hmdfs",
			.ci_type = &hmdfs_group_type,
		},
	},
};

int get_bid(const char *bname)
{
	return hmdfs_appid_get(bname);
}

int __init hmdfs_init_configfs(void)
{
	int err;
	struct configfs_subsystem *subsys;

	hmdfs_info("init configfs");

	hmdfs_bid_entry_cachep = kmem_cache_create("hmdfs_bid_entry_cachep",
		sizeof(struct hmdfs_bid_entry), 0, 0, NULL);
	if (!hmdfs_bid_entry_cachep) {
		hmdfs_err("failed to create bid entry cachep");
		err = -ENOMEM;
		goto out;
	}

	subsys = &hmdfs_subsystem;
	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);

	err = configfs_register_subsystem(subsys);
	if (err)
		hmdfs_err("failed to register subsystem");

out:
	return err;
}

void hmdfs_exit_configfs(void)
{
	hmdfs_info("hmdfs exit configfs");

	configfs_unregister_subsystem(&hmdfs_subsystem);
	clear_appid_hash_entry();

	kmem_cache_destroy(hmdfs_bid_entry_cachep);
}