// SPDX-License-Identifier: GPL-2.0
/*
 * fs/verity/enable.c: ioctl to enable verity on a file
 *
 * Copyright 2019 Google LLC
 */

#include "fsverity_private.h"

#include <crypto/hash.h>
#include <linux/backing-dev.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>

static int check_file_and_enable_verity(struct file *filp,
	const struct fsverity_enable_arg *arg);

#ifdef CONFIG_SECURITY_CODE_SIGN

static int code_sign_init_descriptor(struct inode *inode,
	const struct fsverity_enable_arg *_arg, struct fsverity_descriptor *_desc);

static int code_sign_copy_merkle_tree(struct file *filp, const void *_desc,
	const struct merkle_tree_params *params);

#else /* !CONFIG_SECURITY_CODE_SIGN */

static inline int code_sign_init_descriptor(struct inode *inode,
	const struct fsverity_enable_arg *_arg, struct fsverity_descriptor *_desc)
{
	return 0;
}

static int code_sign_copy_merkle_tree(struct file *filp,
	const void *_desc,
	const struct merkle_tree_params *params)
{
	return 0;
}
#endif /* !CONFIG_SECURITY_CODE_SIGN */

/*
 * Read a file data page for Merkle tree construction.  Do aggressive readahead,
 * since we're sequentially reading the entire file.
 */
static struct page *read_file_data_page(struct file *filp, pgoff_t index,
					struct file_ra_state *ra,
					unsigned long remaining_pages)
{
	struct page *page;

	page = find_get_page_flags(filp->f_mapping, index, FGP_ACCESSED);
	if (!page || !PageUptodate(page)) {
		if (page)
			put_page(page);
		else
			page_cache_sync_readahead(filp->f_mapping, ra, filp,
						  index, remaining_pages);
		page = read_mapping_page(filp->f_mapping, index, NULL);
		if (IS_ERR(page))
			return page;
	}
	if (PageReadahead(page))
		page_cache_async_readahead(filp->f_mapping, ra, filp, page,
					   index, remaining_pages);
	return page;
}

static int build_merkle_tree_level(struct file *filp, unsigned int level,
				   u64 num_blocks_to_hash,
				   const struct merkle_tree_params *params,
				   u8 *pending_hashes,
				   struct ahash_request *req)
{
	struct inode *inode = file_inode(filp);
	const struct fsverity_operations *vops = inode->i_sb->s_vop;
	struct file_ra_state ra = { 0 };
	unsigned int pending_size = 0;
	u64 dst_block_num;
	u64 i;
	int err;

	if (WARN_ON(params->block_size != PAGE_SIZE)) /* checked earlier too */
		return -EINVAL;

	if (level < params->num_levels) {
		dst_block_num = params->level_start[level];
	} else {
		if (WARN_ON(num_blocks_to_hash != 1))
			return -EINVAL;
		dst_block_num = 0; /* unused */
	}

	file_ra_state_init(&ra, filp->f_mapping);

	for (i = 0; i < num_blocks_to_hash; i++) {
		struct page *src_page;

		if ((pgoff_t)i % 10000 == 0 || i + 1 == num_blocks_to_hash)
			pr_debug("Hashing block %llu of %llu for level %u\n",
				 i + 1, num_blocks_to_hash, level);

		if (level == 0) {
			/* Leaf: hashing a data block */
			src_page = read_file_data_page(filp, i, &ra,
						       num_blocks_to_hash - i);
			if (IS_ERR(src_page)) {
				err = PTR_ERR(src_page);
				fsverity_err(inode,
					     "Error %d reading data page %llu",
					     err, i);
				return err;
			}
		} else {
			unsigned long num_ra_pages =
				min_t(unsigned long, num_blocks_to_hash - i,
				      inode->i_sb->s_bdi->io_pages);

			/* Non-leaf: hashing hash block from level below */
			src_page = vops->read_merkle_tree_page(inode,
					params->level_start[level - 1] + i,
					num_ra_pages);
			if (IS_ERR(src_page)) {
				err = PTR_ERR(src_page);
				fsverity_err(inode,
					     "Error %d reading Merkle tree page %llu",
					     err, params->level_start[level - 1] + i);
				return err;
			}
		}

		err = fsverity_hash_page(params, inode, req, src_page,
					 &pending_hashes[pending_size]);
		put_page(src_page);
		if (err)
			return err;
		pending_size += params->digest_size;

		if (level == params->num_levels) /* Root hash? */
			return 0;

		if (pending_size + params->digest_size > params->block_size ||
		    i + 1 == num_blocks_to_hash) {
			/* Flush the pending hash block */
			memset(&pending_hashes[pending_size], 0,
			       params->block_size - pending_size);
			err = vops->write_merkle_tree_block(inode,
					pending_hashes,
					dst_block_num,
					params->log_blocksize);
			if (err) {
				fsverity_err(inode,
					     "Error %d writing Merkle tree block %llu",
					     err, dst_block_num);
				return err;
			}
			dst_block_num++;
			pending_size = 0;
		}

		if (fatal_signal_pending(current))
			return -EINTR;
		cond_resched();
	}
	return 0;
}

/*
 * Build the Merkle tree for the given file using the given parameters, and
 * return the root hash in @root_hash.
 *
 * The tree is written to a filesystem-specific location as determined by the
 * ->write_merkle_tree_block() method.  However, the blocks that comprise the
 * tree are the same for all filesystems.
 */
static int build_merkle_tree(struct file *filp,
			     const struct merkle_tree_params *params,
			     u8 *root_hash,
			     size_t data_size)
{
	struct inode *inode = file_inode(filp);
	u8 *pending_hashes;
	struct ahash_request *req;
	u64 blocks;
	unsigned int level;
	int err = -ENOMEM;

	if (data_size == 0) {
		/* Empty file is a special case; root hash is all 0's */
		memset(root_hash, 0, params->digest_size);
		return 0;
	}

	/* This allocation never fails, since it's mempool-backed. */
	req = fsverity_alloc_hash_request(params->hash_alg, GFP_KERNEL);

	pending_hashes = kmalloc(params->block_size, GFP_KERNEL);
	if (!pending_hashes)
		goto out;

	/*
	 * Build each level of the Merkle tree, starting at the leaf level
	 * (level 0) and ascending to the root node (level 'num_levels - 1').
	 * Then at the end (level 'num_levels'), calculate the root hash.
	 */
	blocks = ((u64)data_size + params->block_size - 1) >>
		 params->log_blocksize;
	for (level = 0; level <= params->num_levels; level++) {
		err = build_merkle_tree_level(filp, level, blocks, params,
					      pending_hashes, req);
		if (err)
			goto out;
		blocks = (blocks + params->hashes_per_block - 1) >>
			 params->log_arity;
	}
	memcpy(root_hash, pending_hashes, params->digest_size);
	err = 0;
out:
	kfree(pending_hashes);
	fsverity_free_hash_request(params->hash_alg, req);
	return err;
}

static int enable_verity(struct file *filp,
			 const struct fsverity_enable_arg *arg)
{
	struct inode *inode = file_inode(filp);
	struct fsverity_descriptor *desc;
	size_t desc_size = sizeof(*desc) + arg->sig_size;
	int err;

	/* Start initializing the fsverity_descriptor */
	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	desc->version = 1;
	desc->hash_algorithm = arg->hash_algorithm;
	desc->log_blocksize = ilog2(arg->block_size);

	/* Get the salt if the user provided one */
	if (arg->salt_size &&
	    copy_from_user(desc->salt, u64_to_user_ptr(arg->salt_ptr),
			   arg->salt_size)) {
		err = -EFAULT;
		goto out;
	}
	desc->salt_size = arg->salt_size;

	/* Get the signature if the user provided one */
	if (arg->sig_size &&
	    copy_from_user(desc->signature, u64_to_user_ptr(arg->sig_ptr),
			   arg->sig_size)) {
		err = -EFAULT;
		goto out;
	}
	desc->sig_size = cpu_to_le32(arg->sig_size);

	desc->data_size = cpu_to_le64(inode->i_size);

	err = code_sign_init_descriptor(inode, arg, desc);
	if (err) {
		fsverity_err(inode, "Init code sign descriptor err: %u", err);
		goto out;
	}

	err = fsverity_enable_with_descriptor(filp, (void *)desc, desc_size);
out:
	kfree(desc);
	return err;
}

int fsverity_enable_with_descriptor(struct file *filp,
	void *_desc, size_t desc_size)
{
	struct inode *inode = file_inode(filp);
	const struct fsverity_operations *vops = inode->i_sb->s_vop;
	struct merkle_tree_params params = { };
	struct fsverity_descriptor *desc = (struct fsverity_descriptor *)_desc;
	struct fsverity_info *vi;
	int err;

	if (vops == NULL) {
		fsverity_err(inode, "current filesystem doesn't support fs-verity.");
		return -ENOTTY;
	}

	/* Prepare the Merkle tree parameters */
	err = fsverity_init_merkle_tree_params(&params, inode,
					       desc->hash_algorithm,
					       desc->log_blocksize,
					       desc->salt, desc->salt_size,
					       desc->data_size);
	if (err)
		goto out;

	/*
	 * Start enabling verity on this file, serialized by the inode lock.
	 * Fail if verity is already enabled or is already being enabled.
	 */
	inode_lock(inode);
	if (IS_VERITY(inode))
		err = -EEXIST;
	else
		err = vops->begin_enable_verity(filp);
	inode_unlock(inode);
	if (err)
		goto out;

	err = code_sign_copy_merkle_tree(filp, _desc, &params);
	if (err < 0) {
		fsverity_err(inode, "Error %d copying Merkle tree", err);
		goto rollback;
	} else if (err == 1) /* already copy merkle tree */
		goto skip_build;

	/*
	 * Build the Merkle tree.  Don't hold the inode lock during this, since
	 * on huge files this may take a very long time and we don't want to
	 * force unrelated syscalls like chown() to block forever.  We don't
	 * need the inode lock here because deny_write_access() already prevents
	 * the file from being written to or truncated, and we still serialize
	 * ->begin_enable_verity() and ->end_enable_verity() using the inode
	 * lock and only allow one process to be here at a time on a given file.
	 */
	pr_debug("Building Merkle tree...\n");
	BUILD_BUG_ON(sizeof(desc->root_hash) < FS_VERITY_MAX_DIGEST_SIZE);
	err = build_merkle_tree(filp, &params, desc->root_hash, desc->data_size);
	if (err) {
		fsverity_err(inode, "Error %d building Merkle tree", err);
		goto rollback;
	}

skip_build:
	pr_debug("Done building Merkle tree.  Root hash is %s:%*phN\n",
		 params.hash_alg->name, params.digest_size, desc->root_hash);

	/*
	 * Create the fsverity_info.  Don't bother trying to save work by
	 * reusing the merkle_tree_params from above.  Instead, just create the
	 * fsverity_info from the fsverity_descriptor as if it were just loaded
	 * from disk.  This is simpler, and it serves as an extra check that the
	 * metadata we're writing is valid before actually enabling verity.
	 */
	vi = fsverity_create_info(inode, desc, desc_size);
	if (IS_ERR(vi)) {
		err = PTR_ERR(vi);
		goto rollback;
	}

	if (desc->sig_size)
		pr_debug("Storing a %u-byte PKCS#7 signature alongside the file\n",
			 desc->sig_size);

	/*
	 * Tell the filesystem to finish enabling verity on the file.
	 * Serialized with ->begin_enable_verity() by the inode lock.
	 */
	inode_lock(inode);
	err = vops->end_enable_verity(filp, desc, desc_size, params.tree_size);
	inode_unlock(inode);
	if (err) {
		fsverity_err(inode, "%ps() failed with err %d",
			     vops->end_enable_verity, err);
		fsverity_free_info(vi);
	} else if (WARN_ON(!IS_VERITY(inode))) {
		err = -EINVAL;
		fsverity_free_info(vi);
	} else {
		/* Successfully enabled verity */

		/*
		 * Readers can start using ->i_verity_info immediately, so it
		 * can't be rolled back once set.  So don't set it until just
		 * after the filesystem has successfully enabled verity.
		 */
		fsverity_set_info(inode, vi);
	}
out:
	kfree(params.hashstate);
	return err;

rollback:
	inode_lock(inode);
	(void)vops->end_enable_verity(filp, NULL, 0, params.tree_size);
	inode_unlock(inode);
	goto out;
}
EXPORT_SYMBOL_GPL(fsverity_enable_with_descriptor);

/**
 * fsverity_ioctl_enable() - enable verity on a file
 * @filp: file to enable verity on
 * @uarg: user pointer to fsverity_enable_arg
 *
 * Enable fs-verity on a file.  See the "FS_IOC_ENABLE_VERITY" section of
 * Documentation/filesystems/fsverity.rst for the documentation.
 *
 * Return: 0 on success, -errno on failure
 */
int fsverity_ioctl_enable(struct file *filp, const void __user *uarg)
{
	struct inode *inode = file_inode(filp);
	struct fsverity_enable_arg arg;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (arg.version != 1)
		return -EINVAL;

	if (arg.__reserved1 ||
	    memchr_inv(arg.__reserved2, 0, sizeof(arg.__reserved2)))
		return -EINVAL;

	if (arg.block_size != PAGE_SIZE)
		return -EINVAL;

	if (arg.salt_size > sizeof_field(struct fsverity_descriptor, salt))
		return -EMSGSIZE;

	if (arg.sig_size > FS_VERITY_MAX_SIGNATURE_SIZE)
		return -EMSGSIZE;

	return check_file_and_enable_verity(filp, &arg);
}
EXPORT_SYMBOL_GPL(fsverity_ioctl_enable);

static int check_file_and_enable_verity(struct file *filp,
	const struct fsverity_enable_arg *arg)
{
	struct inode *inode = file_inode(filp);
	int err;
	/*
	 * Require a regular file with write access.  But the actual fd must
	 * still be readonly so that we can lock out all writers.  This is
	 * needed to guarantee that no writable fds exist to the file once it
	 * has verity enabled, and to stabilize the data being hashed.
	 */

	err = inode_permission(inode, MAY_WRITE);
	if (err)
		return err;

	if (IS_APPEND(inode))
		return -EPERM;

	if (S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	err = mnt_want_write_file(filp);
	if (err) /* -EROFS */
		return err;

	err = deny_write_access(filp);
	if (err) /* -ETXTBSY */
		goto out_drop_write;

	err = enable_verity(filp, arg);

	/*
	 * We no longer drop the inode's pagecache after enabling verity.  This
	 * used to be done to try to avoid a race condition where pages could be
	 * evicted after being used in the Merkle tree construction, then
	 * re-instantiated by a concurrent read.  Such pages are unverified, and
	 * the backing storage could have filled them with different content, so
	 * they shouldn't be used to fulfill reads once verity is enabled.
	 *
	 * But, dropping the pagecache has a big performance impact, and it
	 * doesn't fully solve the race condition anyway.  So for those reasons,
	 * and also because this race condition isn't very important relatively
	 * speaking (especially for small-ish files, where the chance of a page
	 * being used, evicted, *and* re-instantiated all while enabling verity
	 * is quite small), we no longer drop the inode's pagecache.
	 */

	/*
	 * allow_write_access() is needed to pair with deny_write_access().
	 * Regardless, the filesystem won't allow writing to verity files.
	 */
	allow_write_access(filp);
out_drop_write:
	mnt_drop_write_file(filp);
	return err;
}

#ifdef CONFIG_SECURITY_CODE_SIGN
static int code_sign_copy_merkle_tree(struct file *filp,
				 const void *_desc,
				 const struct merkle_tree_params *params)
{
	struct inode *inode = file_inode(filp);
	const struct fsverity_operations *vops = inode->i_sb->s_vop;
	u8 *tree_data;
	u64 blocks, i;
	int err = -ENOMEM;
	struct file_ra_state ra = { 0 };
	struct page *src_page;
	void *addr;
	u64 tree_offset, tree_start_index;

	if (!is_inside_tree_compact(_desc))
		return 0;

	tree_offset = get_tree_offset_compact(_desc);

	if (inode->i_size < tree_offset + params->tree_size) {
		fsverity_err(inode, "File is too small to contain Merkle tree.");
		return -EFAULT;
	}

	tree_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!tree_data)
		goto out;

	file_ra_state_init(&ra, filp->f_mapping);

	tree_start_index = tree_offset >> PAGE_SHIFT;
	blocks = params->tree_size >> PAGE_SHIFT;
	for (i = 0; i < blocks; i++) {
		pr_debug("Copy Merkle tree page at %d\n", tree_start_index + i);
		src_page = read_file_data_page(filp, tree_start_index + i, &ra,
							blocks - i);
		if (IS_ERR(src_page)) {
			err = PTR_ERR(src_page);
			fsverity_err(inode,
						"Error %d reading Merkle tree page %llu",
						err, tree_start_index + i);
			goto out;
		}

		addr = kmap_atomic(src_page);
		memcpy(tree_data, addr, PAGE_SIZE);
		kunmap_atomic(addr);
		put_page(src_page);
		err = vops->write_merkle_tree_block(inode, tree_data, i,
				params->log_blocksize);
		if (err) {
			fsverity_err(inode,
					"Error %d writing Merkle tree block %llu",
					err, i);
			goto out;
		}
	}
	/* already copy merkle tree */
	err = 1;
out:
	kfree(tree_data);
	return err;
}

static int code_sign_init_descriptor(struct inode *inode,
	const struct fsverity_enable_arg *_arg,
	struct fsverity_descriptor *_desc)
{
	struct code_sign_descriptor *desc = CAST_CODE_SIGN_DESC(_desc);
	const struct code_sign_enable_arg *arg = (const struct code_sign_enable_arg *)_arg;
	int algo_index;

	if (!arg->cs_version)
		return 0;

	/* init extended fields */
	desc->flags = cpu_to_le32(arg->flags);
	desc->data_size = cpu_to_le64(arg->data_size);
	desc->tree_offset = cpu_to_le64(arg->tree_offset);
	desc->cs_version = arg->cs_version;
	desc->pgtypeinfo_size = cpu_to_le32(arg->pgtypeinfo_size);
	desc->pgtypeinfo_off = cpu_to_le64(arg->pgtypeinfo_off);

	/* Get root hash if a Merkle tree carried in file */
	if (!IS_INSIDE_TREE(desc))
		return 0;

	/* Get size of root hash */
	algo_index = desc->hash_algorithm;
	if (algo_index >= g_fsverity_hash_algs_num ||
			!fsverity_hash_algs[algo_index].name) {
		fsverity_err(inode, "Unknown hash algorithm: %u", algo_index);
		return -EINVAL;
	}

	if (copy_from_user(desc->root_hash, u64_to_user_ptr(arg->root_hash_ptr),
			fsverity_hash_algs[algo_index].digest_size)) {
		return -EFAULT;
	}

	return 0;
}

/**
 * fsverity_ioctl_enable_code_sign() - enable code signing on a file
 * @filp: file to enable code signing on
 * @uarg: user pointer to code_sign_enable_arg
 *
 * Enable fs-verity on a file with code signing features.
 *
 * Return: 0 on success, -errno on failure
 */
int fsverity_ioctl_enable_code_sign(struct file *filp, const void __user *uarg)
{
	struct inode *inode = file_inode(filp);
	struct code_sign_enable_arg arg;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (arg.version != 1)
		return -EINVAL;

	if (arg.__reserved1 ||
	    memchr_inv(arg.__reserved2, 0, sizeof(arg.__reserved2)))
		return -EINVAL;

	if (arg.data_size > inode->i_size)
		return -EINVAL;

	if (arg.tree_offset % PAGE_SIZE != 0)
		return -EINVAL;

	if (arg.block_size != PAGE_SIZE)
		return -EINVAL;

	if (arg.salt_size > sizeof_field(struct code_sign_descriptor, salt))
		return -EMSGSIZE;

	if (arg.sig_size > FS_VERITY_MAX_SIGNATURE_SIZE)
		return -EMSGSIZE;

	// when calc pgtypeinfo_size trans bit size to byte size
	if (arg.pgtypeinfo_off > arg.data_size - arg.pgtypeinfo_size / 8)
		return -EINVAL;

	return check_file_and_enable_verity(filp, (struct fsverity_enable_arg *)&arg);
}
EXPORT_SYMBOL_GPL(fsverity_ioctl_enable_code_sign);
#endif /* CONFIG_SECURITY_CODE_SIGN */
