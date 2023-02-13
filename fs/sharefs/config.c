/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/sharefs/config.c
 *
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 */

#include <linux/configfs.h>
#include <linux/ctype.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include "sharefs.h"

static struct kmem_cache *sharefs_bid_entry_cachep;

struct sharefs_bid_entry {
	struct hlist_node node;
	struct qstr str;
	int id;
};

struct sharefs_config_bitem {
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

static struct sharefs_bid_entry *alloc_bid_entry(const char *name, int id)
{
	struct sharefs_bid_entry *bid_entry;
	char *bid_entry_name;

	bid_entry = kmem_cache_alloc(sharefs_bid_entry_cachep, GFP_KERNEL);
	if (!bid_entry) {
		bid_entry = ERR_PTR(-ENOMEM);
		goto out;
	}

	bid_entry_name = kstrdup(name, GFP_KERNEL);
	if (!bid_entry_name) {
		kmem_cache_free(sharefs_bid_entry_cachep, bid_entry);
		bid_entry = ERR_PTR(-ENOMEM);
		goto out;
	}

	INIT_HLIST_NODE(&bid_entry->node);
	bid_entry->str = make_qstr(bid_entry_name);
	bid_entry->id = id;
out:
	return bid_entry;
}

static void free_bid_entry(struct sharefs_bid_entry *bid_entry)
{
	if (bid_entry == NULL)
		return;

	kfree(bid_entry->str.name);
	kmem_cache_free(sharefs_bid_entry_cachep, bid_entry);
}

static struct sharefs_config_bitem *alloc_bitem(const char *name)
{
	struct sharefs_config_bitem *bitem;
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

static void free_bitem(struct sharefs_config_bitem *bitem)
{
	if (bitem == NULL)
		return;

	kfree(bitem->str.name);
	kfree(bitem);
}

#define SHAREFS_BUNDLE_ATTRIBUTE(_attr_)					\
									\
static DEFINE_HASHTABLE(sharefs_##_attr_##_hash_table, 4);		\
									\
static DEFINE_MUTEX(sharefs_##_attr_##_hash_mutex);			\
									\
static int query_##_attr_##_hash_entry(struct qstr *str)		\
{									\
	int id = 0;							\
	struct sharefs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	mutex_lock(&sharefs_##_attr_##_hash_mutex);			\
	hash_for_each_possible_safe(sharefs_##_attr_##_hash_table,	\
		bid_entry, hash_node, node, str->hash) {		\
		if (qstr_case_eq(str, &bid_entry->str)) {		\
			id = bid_entry->id;				\
			break;						\
		}							\
	}								\
	mutex_unlock(&sharefs_##_attr_##_hash_mutex);			\
									\
	return id;							\
}									\
									\
static int insert_##_attr_##_hash_entry(struct qstr *str, int id)	\
{									\
	int err = 0;							\
	struct sharefs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	sharefs_info("insert name = %s", str->name);			\
									\
	mutex_lock(&sharefs_##_attr_##_hash_mutex);			\
	hash_for_each_possible_safe(sharefs_##_attr_##_hash_table,	\
		bid_entry, hash_node, node, str->hash) {		\
		if (qstr_case_eq(str, &bid_entry->str)) {		\
			bid_entry->id = id;				\
			mutex_unlock(&sharefs_##_attr_##_hash_mutex);	\
			goto out;					\
		}							\
	}								\
	mutex_unlock(&sharefs_##_attr_##_hash_mutex);			\
									\
	bid_entry = alloc_bid_entry(str->name, id);			\
	if (IS_ERR(bid_entry)) {					\
		err = PTR_ERR(bid_entry);				\
		goto out;						\
	} 								\
									\
	hash_add_rcu(sharefs_##_attr_##_hash_table, &bid_entry->node,	\
		 bid_entry->str.hash);					\
out:									\
	return err;							\
}									\
									\
static void remove_##_attr_##_hash_entry(struct qstr *str)		\
{									\
	struct sharefs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	sharefs_info("remove name = %s", str->name);			\
									\
	mutex_lock(&sharefs_##_attr_##_hash_mutex);			\
	hash_for_each_possible_safe(sharefs_##_attr_##_hash_table,	\
		bid_entry, hash_node, node, str->hash) {		\
		if (qstr_case_eq(str, &bid_entry->str)) {		\
			hash_del_rcu(&bid_entry->node);			\
			free_bid_entry(bid_entry);			\
			break;						\
		}							\
	}								\
	mutex_unlock(&sharefs_##_attr_##_hash_mutex);			\
}									\
									\
static void clear_##_attr_##_hash_entry(void)				\
{									\
	int index;							\
	struct sharefs_bid_entry *bid_entry;				\
	struct hlist_node *hash_node;					\
									\
	sharefs_info("clear bid entry");					\
									\
	mutex_lock(&sharefs_##_attr_##_hash_mutex);			\
	hash_for_each_safe(sharefs_##_attr_##_hash_table, index,		\
		hash_node, bid_entry, node) {				\
		hash_del_rcu(&bid_entry->node);				\
		kfree(bid_entry->str.name);				\
		kmem_cache_free(sharefs_bid_entry_cachep, bid_entry);	\
	}								\
	mutex_unlock(&sharefs_##_attr_##_hash_mutex);			\
}									\
									\
static int sharefs_##_attr_##_get(const char *bname)			\
{									\
	struct qstr str;						\
									\
	str = make_qstr(bname);						\
	return query_##_attr_##_hash_entry(&str);			\
}									\
									\
static ssize_t sharefs_##_attr_##_show(struct config_item *item,		\
	char *page)							\
{									\
	int id;								\
	struct sharefs_config_bitem *bitem;				\
									\
	sharefs_info("show bundle id");					\
									\
	bitem = container_of(item, struct sharefs_config_bitem, item);	\
	id = query_##_attr_##_hash_entry(&bitem->str);			\
									\
	return scnprintf(page, PAGE_SIZE, "%u\n", id);			\
}									\
									\
static ssize_t sharefs_##_attr_##_store(struct config_item *item,	\
	const char *page, size_t count)					\
{									\
	int id;								\
	int err;							\
	size_t size;							\
	struct sharefs_config_bitem *bitem;				\
									\
	sharefs_info("store bundle id");					\
									\
	bitem = container_of(item, struct sharefs_config_bitem, item);	\
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
static struct configfs_attribute sharefs_##_attr_##_attr = {		\
	.ca_name	= __stringify(_attr_),				\
	.ca_mode	= S_IRUGO | S_IWUGO,				\
	.ca_owner	= THIS_MODULE,					\
	.show		= sharefs_##_attr_##_show,			\
	.store		= sharefs_##_attr_##_store,			\
};					

SHAREFS_BUNDLE_ATTRIBUTE(bid)

static struct configfs_attribute *sharefs_battrs[] = {
	&sharefs_bid_attr,
	NULL,
};

static void sharefs_config_bitem_release(struct config_item *item)
{
	struct sharefs_config_bitem *bitem;

	sharefs_info("release bundle item");

	bitem = container_of(item, struct sharefs_config_bitem, item);
	remove_bid_hash_entry(&bitem->str);
	remove_bid_hash_entry(&bitem->str);
	free_bitem(bitem);
}

static struct configfs_item_operations sharefs_config_bitem_ops = {
	.release = sharefs_config_bitem_release,
};

static struct config_item_type sharefs_config_bitem_type = {
	.ct_item_ops	= &sharefs_config_bitem_ops,
	.ct_attrs	= sharefs_battrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item *sharefs_make_bitem(struct config_group *group,
					      const char *name)
{
	struct config_item *item;
	struct sharefs_config_bitem *bitem;

	bitem = alloc_bitem(name);
	if (IS_ERR(bitem)) {
		item = ERR_PTR(-ENOMEM);
		goto out;
	}

	config_item_init_type_name(&bitem->item, name,
		&sharefs_config_bitem_type);
	item = &bitem->item;
out:
	return item;
}

static struct configfs_group_operations sharefs_group_ops = {
	.make_item = sharefs_make_bitem,
};

static struct config_item_type sharefs_group_type = {
    .ct_group_ops     = &sharefs_group_ops,
    .ct_owner         = THIS_MODULE,
};

static struct configfs_subsystem sharefs_subsystem = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "sharefs",
			.ci_type = &sharefs_group_type,
		},
	},
};

int get_bid_config(const char *bname)
{
	return sharefs_bid_get(bname);
}

int __init sharefs_init_configfs(void)
{
	int err;
	struct configfs_subsystem *subsys;

	sharefs_info("init configfs");

	sharefs_bid_entry_cachep = kmem_cache_create("sharefs_bid_entry_cachep",
		sizeof(struct sharefs_bid_entry), 0, 0, NULL);
	if (!sharefs_bid_entry_cachep) {
		sharefs_err("failed to create bid entry cachep");
		err = -ENOMEM;
		goto out;
	}

	subsys = &sharefs_subsystem;
	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);

	err = configfs_register_subsystem(subsys);
	if (err)
		sharefs_err("failed to register subsystem");

out:
	return err;
}

void sharefs_exit_configfs(void)
{
	sharefs_info("sharefs exit configfs");

	configfs_unregister_subsystem(&sharefs_subsystem);
	clear_bid_hash_entry();

	kmem_cache_destroy(sharefs_bid_entry_cachep);
}