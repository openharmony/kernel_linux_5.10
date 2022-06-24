// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/hyperhold/hp_core.c
 *
 * Copyright (c) 2020-2022 Huawei Technologies Co., Ltd.
 */

 #define pr_fmt(fmt) "[HYPERHOLD]" fmt

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/sysctl.h>

#include "hyperhold.h"
#include "hp_device.h"
#include "hp_space.h"
#include "hp_iotab.h"

#define HP_DFLT_DEVICE "/dev/by-name/hyperhold"
#define HP_DFLT_EXT_SIZE (1 << 15)
#define HP_DEV_NAME_LEN 256
#define HP_STATE_LEN 10

#define CHECK(cond, ...) ((cond) || (pr_err(__VA_ARGS__), false))
#define CHECK_BOUND(var, min, max) \
	CHECK((var) >= (min) && (var) <= (max), \
		"%s %u out of bounds %u ~ %u!\n", #var, (var), (min), (max))
#define CHECK_INITED CHECK(hyperhold.inited, "hyperhold is not enable!\n")
#define CHECK_ENABLE (CHECK_INITED && CHECK(hyperhold.enable, "hyperhold is readonly!\n"))

struct hyperhold {
	bool enable;
	bool inited;

	char device_name[HP_DEV_NAME_LEN];
	u32 extent_size;
	u32 enable_soft_crypt;

	struct hp_device dev;
	struct hp_space spc;

	struct workqueue_struct *read_wq;
	struct workqueue_struct *write_wq;

	struct mutex init_lock;
};

struct hyperhold hyperhold;

atomic64_t mem_used = ATOMIC64_INIT(0);
#ifdef CONFIG_HYPERHOLD_DEBUG
/*
 * return the memory overhead of hyperhold module
 */
u64 hyperhold_memory_used(void)
{
	return atomic64_read(&mem_used) + hpio_memory() + space_memory();
}
#endif

void hyperhold_disable(bool force)
{
	if (!CHECK_INITED)
		return;
	if (!force && !CHECK_ENABLE)
		return;

	mutex_lock(&hyperhold.init_lock);
	hyperhold.enable = false;
	if (!wait_for_space_empty(&hyperhold.spc, force))
		goto out;
	hyperhold.inited = false;
	wait_for_iotab_empty();
	destroy_workqueue(hyperhold.read_wq);
	destroy_workqueue(hyperhold.write_wq);
	deinit_space(&hyperhold.spc);
	crypto_deinit(&hyperhold.dev);
	unbind_bdev(&hyperhold.dev);
out:
	if (hyperhold.inited)
		pr_info("hyperhold is disabled, read only.\n");
	else
		pr_info("hyperhold is totally disabled!\n");
	mutex_unlock(&hyperhold.init_lock);
}
EXPORT_SYMBOL(hyperhold_disable);

void hyperhold_enable(void)
{
	bool enable = true;

	if (hyperhold.inited)
		goto out;

	mutex_lock(&hyperhold.init_lock);
	if (hyperhold.inited)
		goto unlock;
	if (!bind_bdev(&hyperhold.dev, hyperhold.device_name))
		goto err1;
	if (!crypto_init(&hyperhold.dev, hyperhold.enable_soft_crypt))
		goto err2;
	if (!init_space(&hyperhold.spc, hyperhold.dev.dev_size, hyperhold.extent_size))
		goto err3;
	hyperhold.read_wq = alloc_workqueue("hyperhold_read", WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!hyperhold.read_wq)
		goto err4;
	hyperhold.write_wq = alloc_workqueue("hyperhold_write", 0, 0);
	if (!hyperhold.write_wq)
		goto err5;
	hyperhold.inited = true;
	goto unlock;
err5:
	destroy_workqueue(hyperhold.read_wq);
err4:
	deinit_space(&hyperhold.spc);
err3:
	crypto_deinit(&hyperhold.dev);
err2:
	unbind_bdev(&hyperhold.dev);
err1:
	enable = false;
unlock:
	mutex_unlock(&hyperhold.init_lock);
out:
	if (enable) {
		hyperhold.enable = true;
		pr_info("hyperhold is enabled.\n");
	} else {
		hyperhold.enable = false;
		pr_err("hyperhold enable failed!\n");
	}
}
EXPORT_SYMBOL(hyperhold_enable);

static int enable_sysctl_handler(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	const struct cred *cred = current_cred();
	char *filter_buf;

	filter_buf = strstrip((char *)buffer);
	if (write) {
		if (!uid_eq(cred->euid, GLOBAL_MEMMGR_UID) &&
			!uid_eq(cred->euid, GLOBAL_ROOT_UID)) {
			pr_err("no permission to enable/disable eswap!\n");
			return 0;
		}
		if (!strcmp(filter_buf, "enable"))
			hyperhold_enable();
		else if (!strcmp(filter_buf, "disable"))
			hyperhold_disable(false);
		else if (!strcmp(filter_buf, "force_disable"))
			hyperhold_disable(true);
	} else {
		if (*lenp < HP_STATE_LEN || *ppos) {
			*lenp = 0;
			return 0;
		}
		if (hyperhold.enable)
			strcpy(buffer, "enable\n");
		else if (hyperhold.inited)
			strcpy(buffer, "readonly\n");
		else
			strcpy(buffer, "disable\n");
		*lenp = strlen(buffer);
		*ppos += *lenp;
#ifdef CONFIG_HYPERHOLD_DEBUG
		pr_info("hyperhold memory overhead = %llu.\n", hyperhold_memory_used());
#endif
	}
	return 0;
}

static int device_sysctl_handler(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	mutex_lock(&hyperhold.init_lock);
	if (write && hyperhold.inited) {
		pr_err("hyperhold device is busy!\n");
		ret = -EBUSY;
		goto unlock;
	}
	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (write && !ret) {
		hyperhold.enable_soft_crypt = 1;
		pr_info("device changed, default enable soft crypt.\n");
	}
unlock:
	mutex_unlock(&hyperhold.init_lock);

	return ret;
}

static int extent_sysctl_handler(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	mutex_lock(&hyperhold.init_lock);
	if (write && hyperhold.inited) {
		pr_err("hyperhold device is busy!\n");
		ret = -EBUSY;
		goto unlock;
	}
	ret = proc_douintvec(table, write, buffer, lenp, ppos);
unlock:
	mutex_unlock(&hyperhold.init_lock);

	return ret;
}

static int crypto_sysctl_handler(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	mutex_lock(&hyperhold.init_lock);
	if (write && hyperhold.inited) {
		pr_err("hyperhold device is busy!\n");
		ret = -EBUSY;
		goto unlock;
	}
	ret = proc_douintvec_minmax(table, write, buffer, lenp, ppos);
unlock:
	mutex_unlock(&hyperhold.init_lock);

	return ret;
}

static struct ctl_table_header *hp_sysctl_header;
static struct ctl_table hp_table[] = {
	{
		.procname = "enable",
		.mode = 0666,
		.proc_handler = enable_sysctl_handler,
	},
	{
		.procname = "device",
		.data = &hyperhold.device_name,
		.maxlen = sizeof(hyperhold.device_name),
		.mode = 0644,
		.proc_handler = device_sysctl_handler,
	},
	{
		.procname = "extent_size",
		.data = &hyperhold.extent_size,
		.maxlen = sizeof(hyperhold.extent_size),
		.mode = 0644,
		.proc_handler = extent_sysctl_handler,
	},
	{
		.procname = "soft_crypt",
		.data = &hyperhold.enable_soft_crypt,
		.maxlen = sizeof(hyperhold.enable_soft_crypt),
		.mode = 0644,
		.proc_handler = crypto_sysctl_handler,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	},
	{}
};
static struct ctl_table hp_kernel_table[] = {
	{
		.procname = "hyperhold",
		.mode = 0555,
		.child = hp_table,
	},
	{}
};
static struct ctl_table hp_sys_table[] = {
	{
		.procname = "kernel",
		.mode = 0555,
		.child = hp_kernel_table,
	},
	{}
};

bool is_hyperhold_enable(void)
{
	return hyperhold.enable;
}

static int __init hyperhold_init(void)
{
	strcpy(hyperhold.device_name, HP_DFLT_DEVICE);
	hyperhold.extent_size = HP_DFLT_EXT_SIZE;
	hyperhold.enable_soft_crypt = 1;
	mutex_init(&hyperhold.init_lock);
	hp_sysctl_header = register_sysctl_table(hp_sys_table);
	if (!hp_sysctl_header) {
		pr_err("register hyperhold sysctl table failed!\n");
		return -EINVAL;
	}

	return 0;
}

static void __exit hyperhold_exit(void)
{
	unregister_sysctl_table(hp_sysctl_header);
	hyperhold_disable(true);
}

static struct hp_space *space_of(u32 eid)
{
	return &hyperhold.spc;
}

/* replace this func for multi devices */
static struct hp_device *device_of(u32 eid)
{
	return &hyperhold.dev;
}

/* replace this func for multi devices */
u32 hyperhold_nr_extent(void)
{
	if (!CHECK_INITED)
		return 0;

	return hyperhold.spc.nr_ext;
}
EXPORT_SYMBOL(hyperhold_nr_extent);

u32 hyperhold_extent_size(u32 eid)
{
	struct hp_space *spc = NULL;

	if (!CHECK_INITED)
		return 0;
	spc = space_of(eid);
	if (!CHECK(spc, "invalid eid %u!\n", eid))
		return 0;

	return spc->ext_size;
}
EXPORT_SYMBOL(hyperhold_extent_size);

/* replace this func for multi devices */
long hyperhold_address(u32 eid, u32 offset)
{
	struct hp_space *spc = NULL;

	if (!CHECK_INITED)
		return -EINVAL;
	spc = space_of(eid);
	if (!CHECK(spc, "invalid eid %u!\n", eid))
		return -EINVAL;
	if (!CHECK_BOUND(offset, 0, spc->ext_size - 1))
		return -EINVAL;

	return (u64)eid * spc->ext_size + offset;
}
EXPORT_SYMBOL(hyperhold_address);

/* replace this func for multi devices */
int hyperhold_addr_extent(u64 addr)
{
	struct hp_space *spc = NULL;
	u32 eid;

	if (!CHECK_INITED)
		return -EINVAL;
	eid = div_u64(addr, hyperhold.spc.ext_size);
	spc = space_of(eid);
	if (!CHECK(spc, "invalid eid %u!\n", eid))
		return -EINVAL;

	return eid;
}
EXPORT_SYMBOL(hyperhold_addr_extent);

/* replace this func for multi devices */
int hyperhold_addr_offset(u64 addr)
{
	if (!CHECK_INITED)
		return -EINVAL;

	return do_div(addr, hyperhold.spc.ext_size);
}
EXPORT_SYMBOL(hyperhold_addr_offset);

/* replace this func for multi devices */
int hyperhold_alloc_extent(void)
{
	if (!CHECK_ENABLE)
		return -EINVAL;

	return alloc_eid(&hyperhold.spc);
}
EXPORT_SYMBOL(hyperhold_alloc_extent);

void hyperhold_free_extent(u32 eid)
{
	struct hp_space *spc = NULL;

	if (!CHECK_INITED)
		return;
	spc = space_of(eid);
	if (!CHECK(spc, "invalid eid %u!\n", eid))
		return;

	free_eid(spc, eid);
}
EXPORT_SYMBOL(hyperhold_free_extent);

void hyperhold_should_free_extent(u32 eid)
{
	struct hpio *hpio = NULL;
	struct hp_space *spc = NULL;

	if (!CHECK_INITED)
		return;
	spc = space_of(eid);
	if (!CHECK(spc, "invalid eid %u", eid))
		return;

	hpio = hpio_get(eid);
	if (!hpio) {
		free_eid(spc, eid);
		return;
	}
	hpio->free_extent = hyperhold_free_extent;
	hpio_put(hpio);
}
EXPORT_SYMBOL(hyperhold_should_free_extent);

/*
 * alloc hpio struct for r/w extent at @eid, will fill hpio with new alloced
 * pages if @new_page. @return NULL on fail.
 */
struct hpio *hyperhold_io_alloc(u32 eid, gfp_t gfp, unsigned int op, bool new_page)
{
	struct hpio *hpio = NULL;
	struct hp_space *spc;
	u32 nr_page;

	if (!CHECK_ENABLE)
		return NULL;
	spc = space_of(eid);
	if (!CHECK(spc, "invalid eid  %u!\n", eid))
		return NULL;

	nr_page = spc->ext_size / PAGE_SIZE;
	hpio = hpio_alloc(nr_page, gfp, op, new_page);
	if (!hpio)
		goto err;
	hpio->eid = eid;

	return hpio;
err:
	hpio_free(hpio);

	return NULL;
}
EXPORT_SYMBOL(hyperhold_io_alloc);

void hyperhold_io_free(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return;
	if (!CHECK(hpio, "hpio is null!\n"))
		return;

	hpio_free(hpio);
}
EXPORT_SYMBOL(hyperhold_io_free);

/*
 * find exist read hpio of the extent @eid in iotab and inc its refcnt,
 * alloc a new hpio and insert it into iotab if there is no hpio for @eid
 */
struct hpio *hyperhold_io_get(u32 eid, gfp_t gfp, unsigned int op)
{
	struct hp_space *spc = NULL;
	u32 nr_page;

	if (!CHECK_INITED)
		return NULL;
	spc = space_of(eid);
	if (!CHECK(spc, "invalid eid %u", eid))
		return NULL;

	nr_page = spc->ext_size / PAGE_SIZE;
	return hpio_get_alloc(eid, nr_page, gfp, op);
}
EXPORT_SYMBOL(hyperhold_io_get);

bool hyperhold_io_put(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return false;
	if (!CHECK(hpio, "hpio is null!\n"))
		return false;

	return hpio_put(hpio);
}
EXPORT_SYMBOL(hyperhold_io_put);

/*
 * notify all threads waiting for this hpio
 */
void hyperhold_io_complete(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return;
	if (!CHECK(hpio, "hpio is null!\n"))
		return;

	hpio_complete(hpio);
}
EXPORT_SYMBOL(hyperhold_io_complete);

void hyperhold_io_wait(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return;
	if (!CHECK(hpio, "hpio is null!\n"))
		return;

	hpio_wait(hpio);
}
EXPORT_SYMBOL(hyperhold_io_wait);

bool hyperhold_io_success(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return false;
	if (!CHECK(hpio, "hpio is null!\n"))
		return false;

	return hpio_get_state(hpio) == HPIO_DONE;
}
EXPORT_SYMBOL(hyperhold_io_success);

int hyperhold_io_extent(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return -EINVAL;
	if (!CHECK(hpio, "hpio is null!\n"))
		return -EINVAL;

	return hpio->eid;
}
EXPORT_SYMBOL(hyperhold_io_extent);

int hyperhold_io_operate(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return -EINVAL;
	if (!CHECK(hpio, "hpio is null!\n"))
		return -EINVAL;

	return hpio->op;
}
EXPORT_SYMBOL(hyperhold_io_operate);

struct page *hyperhold_io_page(struct hpio *hpio, u32 index)
{
	if (!CHECK_INITED)
		return NULL;
	if (!CHECK(hpio, "hpio is null!\n"))
		return NULL;
	if (!CHECK_BOUND(index, 0, hpio->nr_page - 1))
		return NULL;

	return hpio->pages[index];
}
EXPORT_SYMBOL(hyperhold_io_page);

bool hyperhold_io_add_page(struct hpio *hpio, u32 index, struct page *page)
{
	if (!CHECK_INITED)
		return false;
	if (!CHECK(hpio, "hpio is null!\n"))
		return false;
	if (!CHECK(page, "page is null!\n"))
		return false;
	if (!CHECK_BOUND(index, 0, hpio->nr_page - 1))
		return false;

	get_page(page);
	atomic64_add(PAGE_SIZE, &mem_used);
	BUG_ON(hpio->pages[index]);
	hpio->pages[index] = page;

	return true;
}
EXPORT_SYMBOL(hyperhold_io_add_page);

u32 hyperhold_io_nr_page(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return 0;
	if (!CHECK(hpio, "hpio is null!\n"))
		return 0;

	return hpio->nr_page;
}
EXPORT_SYMBOL(hyperhold_io_nr_page);

void *hyperhold_io_private(struct hpio *hpio)
{
	if (!CHECK_INITED)
		return NULL;
	if (!CHECK(hpio, "hpio is null!\n"))
		return NULL;

	return hpio->private;
}
EXPORT_SYMBOL(hyperhold_io_private);

static struct page *get_encrypted_page(struct hp_device *dev, struct page *page, unsigned int op)
{
	struct page *encrypted_page = NULL;

	if (!dev->ctfm) {
		encrypted_page = page;
		get_page(encrypted_page);
		goto out;
	}

	encrypted_page = alloc_page(GFP_NOIO);
	if (!encrypted_page) {
		pr_err("alloc encrypted page failed!\n");
		goto out;
	}
	encrypted_page->index = page->index;

	/* just alloc a new page for read */
	if (!op_is_write(op))
		goto out;

	/* encrypt page for write */
	if (soft_crypt_page(dev->ctfm, encrypted_page, page, HP_DEV_ENCRYPT)) {
		put_page(encrypted_page);
		encrypted_page = NULL;
	}
out:
	return encrypted_page;
}

static void put_encrypted_pages(struct bio *bio)
{
	struct bio_vec *bv = NULL;
	struct bvec_iter_all iter;

	bio_for_each_segment_all(bv, bio, iter)
		put_page(bv->bv_page);
}

static void hp_endio_work(struct work_struct *work)
{
	struct hpio *hpio = container_of(work, struct hpio, endio_work);
	struct hp_device *dev = NULL;
	struct bio_vec *bv = NULL;
	struct bvec_iter_all iter;
	struct page *page = NULL;
	u32 ext_size;
	sector_t sec;
	int i;

	if (op_is_write(hpio->op))
		goto endio;
	ext_size = space_of(hpio->eid)->ext_size;
	dev = device_of(hpio->eid);
	sec = hpio->eid * ext_size / dev->sec_size;
	i = 0;
	bio_for_each_segment_all(bv, hpio->bio, iter) {
		page = bv->bv_page;
		BUG_ON(i >= hpio->nr_page);
		BUG_ON(!hpio->pages[i]);
		if (dev->ctfm)
			BUG_ON(soft_crypt_page(dev->ctfm, hpio->pages[i], page, HP_DEV_DECRYPT));
		sec += PAGE_SIZE / dev->sec_size;
		i++;
	}
endio:
	put_encrypted_pages(hpio->bio);
	bio_put(hpio->bio);
	if (hpio->endio)
		hpio->endio(hpio);
}

static void hpio_endio(struct bio *bio)
{
	struct hpio *hpio = bio->bi_private;
	struct workqueue_struct *wq = NULL;

	pr_info("hpio %p for eid %u returned %d.\n",
			hpio, hpio->eid, bio->bi_status);
	hpio_set_state(hpio, bio->bi_status ? HPIO_FAIL : HPIO_DONE);
	wq = op_is_write(hpio->op) ? hyperhold.write_wq : hyperhold.read_wq;
	queue_work(wq, &hpio->endio_work);
	atomic64_sub(sizeof(struct bio), &mem_used);
}

static int hpio_submit(struct hpio *hpio)
{
	struct hp_device *dev = NULL;
	struct bio *bio = NULL;
	struct page *page = NULL;
	u32 ext_size;
	sector_t sec;
	int i;

	bio = bio_alloc(GFP_NOIO, BIO_MAX_PAGES);
	if (!bio) {
		pr_err("bio alloc failed!\n");
		return -ENOMEM;
	}
	atomic64_add(sizeof(struct bio), &mem_used);

	dev = device_of(hpio->eid);
	bio_set_op_attrs(bio, hpio->op, 0);
	bio_set_dev(bio, dev->bdev);

	ext_size = space_of(hpio->eid)->ext_size;
	sec = div_u64((u64)hpio->eid * ext_size, dev->sec_size);
	bio->bi_iter.bi_sector = sec;
	for (i = 0; i < hpio->nr_page; i++) {
		if (!hpio->pages[i])
			break;
		hpio->pages[i]->index = sec;
		page = get_encrypted_page(dev, hpio->pages[i], hpio->op);
		if (!page)
			goto err;
		if (!bio_add_page(bio, page, PAGE_SIZE, 0)) {
			put_page(page);
			goto err;
		}
		sec += PAGE_SIZE / dev->sec_size;
	}

	if (dev->blk_key)
		inline_crypt_bio(dev->blk_key, bio);
	bio->bi_private = hpio;
	bio->bi_end_io = hpio_endio;
	hpio->bio = bio;
	submit_bio(bio);
	pr_info("submit hpio %p for eid %u.\n", hpio, hpio->eid);

	return 0;
err:
	put_encrypted_pages(bio);
	bio_put(bio);
	atomic64_sub(sizeof(struct bio), &mem_used);
	return -EIO;
}

static int rw_extent_async(struct hpio *hpio, hp_endio endio, void *priv, unsigned int op)
{
	int ret = 0;

	if (!hpio_change_state(hpio, HPIO_INIT, HPIO_SUBMIT))
		return -EAGAIN;

	hpio->private = priv;
	hpio->endio = endio;
	INIT_WORK(&hpio->endio_work, hp_endio_work);

	ret = hpio_submit(hpio);
	if (ret) {
		hpio_set_state(hpio, HPIO_FAIL);
		hpio_complete(hpio);
	}

	return ret;
}

int hyperhold_write_async(struct hpio *hpio, hp_endio endio, void *priv)
{
	if (!CHECK_ENABLE) {
		hpio_set_state(hpio, HPIO_FAIL);
		hpio_complete(hpio);
		return -EINVAL;
	}

	BUG_ON(!op_is_write(hpio->op));

	return rw_extent_async(hpio, endio, priv, REQ_OP_WRITE);
}
EXPORT_SYMBOL(hyperhold_write_async);

int hyperhold_read_async(struct hpio *hpio, hp_endio endio, void *priv)
{
	if (!CHECK_INITED) {
		hpio_set_state(hpio, HPIO_FAIL);
		hpio_complete(hpio);
		return -EINVAL;
	}

	if (op_is_write(hpio->op))
		return -EAGAIN;

	return rw_extent_async(hpio, endio, priv, REQ_OP_READ);
}
EXPORT_SYMBOL(hyperhold_read_async);

module_init(hyperhold_init)
module_exit(hyperhold_exit)
