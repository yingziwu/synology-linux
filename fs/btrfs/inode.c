#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/buffer_head.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mpage.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/compat.h>
#include <linux/aio.h>
#include <linux/bit_spinlock.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/falloc.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/mount.h>
#include <linux/btrfs.h>
#include <linux/blkdev.h>
#include <linux/posix_acl_xattr.h>
#include <linux/swap.h>
#include <asm/unaligned.h>
#include "ctree.h"
#include "disk-io.h"
#if defined(MY_DEF_HERE)
#include "csum.h"
#endif /* MY_DEF_HERE */
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "ordered-data.h"
#include "xattr.h"
#include "tree-log.h"
#include "volumes.h"
#include "compression.h"
#include "locking.h"
#include "free-space-cache.h"
#include "inode-map.h"
#include "backref.h"
#include "hash.h"
#include "props.h"
#ifdef MY_ABC_HERE
#include "qgroup.h"
#endif /* MY_ABC_HERE */

#ifdef MY_DEF_HERE
#include "syno_acl.h"
#include "../synoacl_int.h"
#endif
#ifdef MY_DEF_HERE
#include <linux/namei.h>
#endif
#ifdef MY_DEF_HERE
#include <linux/fsnotify.h>
#endif /* MY_DEF_HERE */

struct btrfs_iget_args {
	struct btrfs_key *location;
	struct btrfs_root *root;
};

struct btrfs_dio_data {
	u64 outstanding_extents;
	u64 reserve;
	u64 unsubmitted_oe_range_start;
	u64 unsubmitted_oe_range_end;
};

static const struct inode_operations btrfs_dir_inode_operations;
static const struct inode_operations btrfs_symlink_inode_operations;
static const struct inode_operations btrfs_dir_ro_inode_operations;
static const struct inode_operations btrfs_special_inode_operations;
static const struct inode_operations btrfs_file_inode_operations;
static const struct address_space_operations btrfs_aops;
static const struct address_space_operations btrfs_symlink_aops;
static const struct file_operations btrfs_dir_file_operations;
static struct extent_io_ops btrfs_extent_io_ops;

static struct kmem_cache *btrfs_inode_cachep;
static struct kmem_cache *btrfs_delalloc_work_cachep;
struct kmem_cache *btrfs_trans_handle_cachep;
struct kmem_cache *btrfs_transaction_cachep;
struct kmem_cache *btrfs_path_cachep;
struct kmem_cache *btrfs_free_space_cachep;

#define S_SHIFT 12
static unsigned char btrfs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= BTRFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= BTRFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= BTRFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= BTRFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= BTRFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= BTRFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= BTRFS_FT_SYMLINK,
};

static int btrfs_setsize(struct inode *inode, struct iattr *attr);
static int btrfs_truncate(struct inode *inode, bool skip_writeback);
static int btrfs_finish_ordered_io(struct btrfs_ordered_extent *ordered_extent);
#ifdef MY_DEF_HERE
static noinline int cow_file_range(struct inode *inode,
				   struct page *locked_page,
				   u64 start, u64 end, int *page_started,
				   unsigned long *nr_written, int unlock, int write_sync);
#else
static noinline int cow_file_range(struct inode *inode,
				   struct page *locked_page,
				   u64 start, u64 end, int *page_started,
				   unsigned long *nr_written, int unlock);
#endif /* MY_DEF_HERE */
static struct extent_map *create_pinned_em(struct inode *inode, u64 start,
					   u64 len, u64 orig_start,
					   u64 block_start, u64 block_len,
					   u64 orig_block_len, u64 ram_bytes,
					   int type);

static void __endio_write_update_ordered(struct inode *inode,
					 const u64 offset, const u64 bytes,
					 const bool uptodate);

/*
 * Cleanup all submitted ordered extents in specified range to handle errors
 * from the fill_dellaloc() callback.
 *
 * NOTE: caller must ensure that when an error happens, it can not call
 * extent_clear_unlock_delalloc() to clear both the bits EXTENT_DO_ACCOUNTING
 * and EXTENT_DELALLOC simultaneously, because that causes the reserved metadata
 * to be released, which we want to happen only when finishing the ordered
 * extent (btrfs_finish_ordered_io()). Also note that the caller of the
 * fill_delalloc() callback already does proper cleanup for the first page of
 * the range, that is, it invokes the callback writepage_end_io_hook() for the
 * range of the first page.
 */
static inline void btrfs_cleanup_ordered_extents(struct inode *inode,
						 const u64 offset,
						 const u64 bytes)
{
	unsigned long index = offset >> PAGE_SHIFT;
	unsigned long end_index = (offset + bytes - 1) >> PAGE_SHIFT;
	struct page *page;

	while (index <= end_index) {
		page = find_get_page(inode->i_mapping, index);
		index++;
		if (!page)
			continue;
		ClearPagePrivate2(page);
		put_page(page);
	}
	return __endio_write_update_ordered(inode, offset + PAGE_SIZE,
					    bytes - PAGE_SIZE, false);
}

static int btrfs_dirty_inode(struct inode *inode);

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
static int btrfs_syno_init_attr(struct btrfs_trans_handle *trans, struct inode *inode)
{
	int err = -EINVAL;
#ifdef MY_DEF_HERE
	struct btrfs_timespec crtime;
#endif
#ifdef MY_DEF_HERE
	__le32 archive_bit;
#endif

#ifdef MY_DEF_HERE
	inode->i_create_time = inode->i_mtime;
	crtime.sec = cpu_to_le64(inode->i_create_time.tv_sec);
	crtime.nsec = cpu_to_le32(inode->i_create_time.tv_nsec);
	err = __btrfs_setxattr(trans, inode, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME, &crtime, sizeof(crtime), XATTR_CREATE);
	if (err)
		goto out;
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
	inode->i_archive_bit = ALL_SYNO_ARCHIVE;
	archive_bit = cpu_to_le32(inode->i_archive_bit);
	err = __btrfs_setxattr(trans, inode, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_BIT, &archive_bit, sizeof(archive_bit), XATTR_CREATE);
#endif /* MY_DEF_HERE */
out:
	return err;
}
#endif /* MY_DEF_HERE || MY_DEF_HERE */

#ifdef MY_DEF_HERE
static int btrfs_syno_set_crtime(struct dentry *dentry, struct timespec *time)
{
	int err = -EINVAL;
	struct btrfs_timespec crtime;

	if (!dentry->d_inode->i_op->setxattr) {
		// ex.
		// btrfs subvolume create /volume1/abc
		// btrfs subvolume create /volume1/abc/123
		// btrfs subvolume snapshot /volume1/abc /volume1/111
		// /volume1/111/123 <-- i_op = btrfs_dir_ro_inode_operations
		printk(KERN_ERR "BTRFS:Can't set create time on dir_ro_inode %s\n", dentry->d_name.name);
		goto out;
	}
	crtime.sec = cpu_to_le64(time->tv_sec);
	crtime.nsec = cpu_to_le32(time->tv_nsec);
	err = btrfs_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME, &crtime, sizeof(crtime), 0);
	if (!err) {
		dentry->d_inode->i_create_time = *time;
		dentry->d_inode->i_flags |= S_CREATE_TIME_CACHED;
	}
out:
	return err;
}
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static int btrfs_syno_set_archive_bit(struct dentry *dentry, u32 archive_bit)
{
	int err = -EINVAL;
	__le32 archive_le32;

	if (!dentry->d_inode->i_op->setxattr) {
		printk(KERN_ERR "BTRFS:Can't set archive bit on dir_ro_inode %s\n", dentry->d_name.name);
		goto out;
	}
	archive_le32 = cpu_to_le32(archive_bit);
	err = btrfs_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_BIT, &archive_le32, sizeof(archive_le32), 0);
out:
	return err;
}
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static int btrfs_syno_set_archive_ver(struct dentry *dentry, u32 version)
{
	struct inode *inode = dentry->d_inode;
	struct syno_xattr_archive_version value;
	int err;

	if (!dentry->d_inode->i_op->setxattr) {
		printk(KERN_ERR "BTRFS:Can't set archive ver on dir_ro_inode %s\n", dentry->d_name.name);
		return -EINVAL;
	}
	value.v_magic = cpu_to_le16(0x2552);
	value.v_struct_version = cpu_to_le16(1);
	value.v_archive_version = cpu_to_le32(version);
	err = btrfs_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION, &value, sizeof(value), 0);
	if (!err) {
		inode->i_archive_version = version;
		inode->i_flags |= S_ARCHIVE_VERSION_CACHED;
	}
	return err;
}

static int btrfs_syno_get_archive_ver(struct dentry *dentry, u32 *version)
{
	struct inode *inode = dentry->d_inode;
	struct syno_xattr_archive_version value;
	int err;

	if (IS_ARCHIVE_VERSION_CACHED(inode)) {
		*version = inode->i_archive_version;
		return 0;
	}

	err = __btrfs_getxattr(inode, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION, &value, sizeof(value));
	if (0 < err) {
		inode->i_archive_version = le32_to_cpu(value.v_archive_version);
	} else if (-ENODATA == err) {
		inode->i_archive_version = 0;
	} else {
		*version = 0;
		return err;
	}
	*version = inode->i_archive_version;
	inode->i_flags |= S_ARCHIVE_VERSION_CACHED;
	return 0;
}
#endif /* MY_DEF_HERE */

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
void btrfs_test_inode_set_ops(struct inode *inode)
{
	BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;
}
#endif

static int btrfs_init_inode_security(struct btrfs_trans_handle *trans,
				     struct inode *inode,  struct inode *dir,
				     const struct qstr *qstr)
{
	int err;

	err = btrfs_init_acl(trans, inode, dir);
	if (!err)
		err = btrfs_xattr_security_init(trans, inode, dir, qstr);
	return err;
}

/*
 * this does all the hard work for inserting an inline extent into
 * the btree.  The caller should have done a btrfs_drop_extents so that
 * no overlapping inline items exist in the btree
 */
static int insert_inline_extent(struct btrfs_trans_handle *trans,
				struct btrfs_path *path, int extent_inserted,
				struct btrfs_root *root, struct inode *inode,
				u64 start, size_t size, size_t compressed_size,
				int compress_type,
				struct page **compressed_pages)
{
	struct extent_buffer *leaf;
	struct page *page = NULL;
	char *kaddr;
	unsigned long ptr;
	struct btrfs_file_extent_item *ei;
	int err = 0;
	int ret;
	size_t cur_size = size;
	unsigned long offset;

	if (compressed_size && compressed_pages)
		cur_size = compressed_size;

	inode_add_bytes(inode, size);

	if (!extent_inserted) {
		struct btrfs_key key;
		size_t datasize;

		key.objectid = btrfs_ino(inode);
		key.offset = start;
		btrfs_set_key_type(&key, BTRFS_EXTENT_DATA_KEY);

		datasize = btrfs_file_extent_calc_inline_size(cur_size);
		path->leave_spinning = 1;
		ret = btrfs_insert_empty_item(trans, root, path, &key,
					      datasize);
		if (ret) {
			err = ret;
			goto fail;
		}
	}
	leaf = path->nodes[0];
	ei = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	btrfs_set_file_extent_generation(leaf, ei, trans->transid);
	btrfs_set_file_extent_type(leaf, ei, BTRFS_FILE_EXTENT_INLINE);
	btrfs_set_file_extent_encryption(leaf, ei, 0);
	btrfs_set_file_extent_other_encoding(leaf, ei, 0);
	btrfs_set_file_extent_ram_bytes(leaf, ei, size);
	ptr = btrfs_file_extent_inline_start(ei);

	if (compress_type != BTRFS_COMPRESS_NONE) {
		struct page *cpage;
		int i = 0;
		while (compressed_size > 0) {
			cpage = compressed_pages[i];
			cur_size = min_t(unsigned long, compressed_size,
				       PAGE_CACHE_SIZE);

			kaddr = kmap_atomic(cpage);
			write_extent_buffer(leaf, kaddr, ptr, cur_size);
			kunmap_atomic(kaddr);

			i++;
			ptr += cur_size;
			compressed_size -= cur_size;
		}
		btrfs_set_file_extent_compression(leaf, ei,
						  compress_type);
	} else {
		page = find_get_page(inode->i_mapping,
				     start >> PAGE_CACHE_SHIFT);
		btrfs_set_file_extent_compression(leaf, ei, 0);
		kaddr = kmap_atomic(page);
		offset = start & (PAGE_CACHE_SIZE - 1);
		write_extent_buffer(leaf, kaddr + offset, ptr, size);
		kunmap_atomic(kaddr);
		page_cache_release(page);
	}
	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(path);

	/*
	 * we're an inline extent, so nobody can
	 * extend the file past i_size without locking
	 * a page we already have locked.
	 *
	 * We must do any isize and inode updates
	 * before we unlock the pages.  Otherwise we
	 * could end up racing with unlink.
	 */
	BTRFS_I(inode)->disk_i_size = inode->i_size;
	ret = btrfs_update_inode(trans, root, inode);

	return ret;
fail:
	return err;
}


/*
 * conditionally insert an inline extent into the file.  This
 * does the checks required to make sure the data is small enough
 * to fit as an inline extent.
 */
static noinline int cow_file_range_inline(struct btrfs_root *root,
					  struct inode *inode, u64 start,
					  u64 end, size_t compressed_size,
					  int compress_type,
					  struct page **compressed_pages)
{
	struct btrfs_trans_handle *trans;
	u64 isize = i_size_read(inode);
	u64 actual_end = min(end + 1, isize);
	u64 inline_len = actual_end - start;
	u64 aligned_end = ALIGN(end, root->sectorsize);
	u64 data_len = inline_len;
	int ret;
	struct btrfs_path *path;
	int extent_inserted = 0;
	u32 extent_item_size;

	if (compressed_size)
		data_len = compressed_size;

	if (start > 0 ||
	    actual_end >= PAGE_CACHE_SIZE ||
	    data_len >= BTRFS_MAX_INLINE_DATA_SIZE(root) ||
	    (!compressed_size &&
	    (actual_end & (root->sectorsize - 1)) == 0) ||
	    end + 1 < isize ||
	    data_len > root->fs_info->max_inline) {
		return 1;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		btrfs_free_path(path);
		return PTR_ERR(trans);
	}
	trans->block_rsv = &root->fs_info->delalloc_block_rsv;

	if (compressed_size && compressed_pages)
		extent_item_size = btrfs_file_extent_calc_inline_size(
		   compressed_size);
	else
		extent_item_size = btrfs_file_extent_calc_inline_size(
		    inline_len);

	ret = __btrfs_drop_extents(trans, root, inode, path,
#ifdef MY_DEF_HERE
				   start, aligned_end, NULL, NULL, NULL, NULL,
#else
				   start, aligned_end, NULL,
#endif /* MY_DEF_HERE */
				   1, 1, extent_item_size, &extent_inserted);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

	if (isize > actual_end)
		inline_len = min_t(u64, isize, actual_end);
	ret = insert_inline_extent(trans, path, extent_inserted,
				   root, inode, start,
				   inline_len, compressed_size,
				   compress_type, compressed_pages);
	if (ret && ret != -ENOSPC) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	} else if (ret == -ENOSPC) {
		ret = 1;
		goto out;
	}

	set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &BTRFS_I(inode)->runtime_flags);
	btrfs_delalloc_release_metadata(inode, end + 1 - start);
	btrfs_drop_extent_cache(inode, start, aligned_end - 1, 0);
out:
	btrfs_free_path(path);
	btrfs_end_transaction(trans, root);
	return ret;
}

struct async_extent {
	u64 start;
	u64 ram_size;
	u64 compressed_size;
	struct page **pages;
	unsigned long nr_pages;
	int compress_type;
	struct list_head list;
};

struct async_cow {
	struct inode *inode;
	struct btrfs_root *root;
	struct page *locked_page;
	u64 start;
	u64 end;
	struct list_head extents;
	struct btrfs_work work;
};

static noinline int add_async_extent(struct async_cow *cow,
				     u64 start, u64 ram_size,
				     u64 compressed_size,
				     struct page **pages,
				     unsigned long nr_pages,
				     int compress_type)
{
	struct async_extent *async_extent;

	async_extent = kmalloc(sizeof(*async_extent), GFP_NOFS);
	BUG_ON(!async_extent); /* -ENOMEM */
	async_extent->start = start;
	async_extent->ram_size = ram_size;
	async_extent->compressed_size = compressed_size;
	async_extent->pages = pages;
	async_extent->nr_pages = nr_pages;
	async_extent->compress_type = compress_type;
	list_add_tail(&async_extent->list, &cow->extents);
	return 0;
}

static inline int inode_need_compress(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;

	/* force compress */
	if (btrfs_test_opt(root, FORCE_COMPRESS))
		return 1;
	/* bad compression ratios */
	if (BTRFS_I(inode)->flags & BTRFS_INODE_NOCOMPRESS)
		return 0;
	if (btrfs_test_opt(root, COMPRESS) ||
	    BTRFS_I(inode)->flags & BTRFS_INODE_COMPRESS ||
	    BTRFS_I(inode)->force_compress)
		return 1;
	return 0;
}

/*
 * we create compressed extents in two phases.  The first
 * phase compresses a range of pages that have already been
 * locked (both pages and state bits are locked).
 *
 * This is done inside an ordered work queue, and the compression
 * is spread across many cpus.  The actual IO submission is step
 * two, and the ordered work queue takes care of making sure that
 * happens in the same order things were put onto the queue by
 * writepages and friends.
 *
 * If this code finds it can't get good compression, it puts an
 * entry onto the work queue to write the uncompressed bytes.  This
 * makes sure that both compressed inodes and uncompressed inodes
 * are written in the same order that the flusher thread sent them
 * down.
 */
static noinline void compress_file_range(struct inode *inode,
					struct page *locked_page,
					u64 start, u64 end,
					struct async_cow *async_cow,
					int *num_added)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 num_bytes;
	u64 blocksize = root->sectorsize;
	u64 actual_end;
	u64 i_size;
	int ret = 0;
	struct page **pages = NULL;
	unsigned long nr_pages;
	unsigned long total_compressed = 0;
	unsigned long total_in = 0;
	int i;
	int will_compress;
	int compress_type = root->fs_info->compress_type;
	int redirty = 0;

	/* if this is a small write inside eof, kick off a defrag */
	if ((end - start + 1) < 16 * 1024 &&
	    (start > 0 || end + 1 < BTRFS_I(inode)->disk_i_size))
#ifdef MY_DEF_HERE
		btrfs_add_inode_defrag(NULL, inode, 0, 0, BTRFS_INODE_DEFRAG_NORMAL);
#else
		btrfs_add_inode_defrag(NULL, inode);
#endif /* MY_DEF_HERE */

	/*
	 * We need to save i_size before now because it could change in between
	 * us evaluating the size and assigning it.  This is because we lock and
	 * unlock the page in truncate and fallocate, and then modify the i_size
	 * later on.
	 *
	 * The barriers are to emulate READ_ONCE, remove that once i_size_read
	 * does that for us.
	 */
	barrier();
	i_size = i_size_read(inode);
	barrier();
	actual_end = min_t(u64, i_size, end + 1);
again:
	will_compress = 0;
	nr_pages = (end >> PAGE_CACHE_SHIFT) - (start >> PAGE_CACHE_SHIFT) + 1;
	BUILD_BUG_ON((BTRFS_MAX_COMPRESSED % PAGE_CACHE_SIZE) != 0);
	nr_pages = min_t(unsigned long, nr_pages,
			BTRFS_MAX_COMPRESSED / PAGE_CACHE_SIZE);

	/*
	 * we don't want to send crud past the end of i_size through
	 * compression, that's just a waste of CPU time.  So, if the
	 * end of the file is before the start of our current
	 * requested range of bytes, we bail out to the uncompressed
	 * cleanup code that can deal with all of this.
	 *
	 * It isn't really the fastest way to fix things, but this is a
	 * very uncommon corner.
	 */
	if (actual_end <= start)
		goto cleanup_and_bail_uncompressed;

	total_compressed = actual_end - start;

	/*
	 * skip compression for a small file range(<=blocksize) that
	 * isn't an inline extent, since it dosen't save disk space at all.
	 */
	if (total_compressed <= blocksize &&
	   (start > 0 || end + 1 < BTRFS_I(inode)->disk_i_size))
		goto cleanup_and_bail_uncompressed;

	total_compressed = min_t(unsigned long, total_compressed,
			BTRFS_MAX_UNCOMPRESSED);
	num_bytes = ALIGN(end - start + 1, blocksize);
	num_bytes = max(blocksize,  num_bytes);
	total_in = 0;
	ret = 0;

	/*
	 * we do compression for mount -o compress and when the
	 * inode has not been flagged as nocompress.  This flag can
	 * change at any time if we discover bad compression ratios.
	 */
	if (inode_need_compress(inode)) {
		WARN_ON(pages);
		pages = kzalloc(sizeof(struct page *) * nr_pages, GFP_NOFS);
		if (!pages) {
			/* just bail out to the uncompressed code */
			goto cont;
		}

		if (BTRFS_I(inode)->force_compress)
			compress_type = BTRFS_I(inode)->force_compress;

		/*
		 * we need to call clear_page_dirty_for_io on each
		 * page in the range.  Otherwise applications with the file
		 * mmap'd can wander in and change the page contents while
		 * we are compressing them.
		 *
		 * If the compression fails for any reason, we set the pages
		 * dirty again later on.
		 */
		extent_range_clear_dirty_for_io(inode, start, end);
		redirty = 1;
		ret = btrfs_compress_pages(compress_type,
					   inode->i_mapping, start,
					   pages,
					   &nr_pages,
					   &total_in,
					   &total_compressed);

		if (!ret) {
			unsigned long offset = total_compressed &
				(PAGE_CACHE_SIZE - 1);
			struct page *page = pages[nr_pages - 1];
			char *kaddr;

			/* zero the tail end of the last page, we might be
			 * sending it down to disk
			 */
			if (offset) {
				kaddr = kmap_atomic(page);
				memset(kaddr + offset, 0,
				       PAGE_CACHE_SIZE - offset);
				kunmap_atomic(kaddr);
			}
			will_compress = 1;
		}
	}
cont:
	if (start == 0) {
		/* lets try to make an inline extent */
		if (ret || total_in < (actual_end - start)) {
			/* we didn't compress the entire range, try
			 * to make an uncompressed inline extent.
			 */
			ret = cow_file_range_inline(root, inode, start, end,
						    0, 0, NULL);
		} else {
			/* try making a compressed inline extent */
			ret = cow_file_range_inline(root, inode, start, end,
						    total_compressed,
						    compress_type, pages);
		}
		if (ret <= 0) {
			unsigned long clear_flags = EXTENT_DELALLOC |
				EXTENT_DEFRAG;
			clear_flags |= (ret < 0) ? EXTENT_DO_ACCOUNTING : 0;

			/*
			 * inline extent creation worked or returned error,
			 * we don't need to create any more async work items.
			 * Unlock and free up our temp pages.
			 */
			extent_clear_unlock_delalloc(inode, start, end, NULL,
						     clear_flags, PAGE_UNLOCK |
						     PAGE_CLEAR_DIRTY |
						     PAGE_SET_WRITEBACK |
						     PAGE_END_WRITEBACK);
			goto free_pages_out;
		}
	}

	if (will_compress) {
		/*
		 * we aren't doing an inline extent round the compressed size
		 * up to a block size boundary so the allocator does sane
		 * things
		 */
		total_compressed = ALIGN(total_compressed, blocksize);

		/*
		 * one last check to make sure the compression is really a
		 * win, compare the page count read with the blocks on disk,
		 * compression must free at least one sector size
		 */
		total_in = ALIGN(total_in, PAGE_CACHE_SIZE);
		if (total_compressed + blocksize <= total_in) {
			num_bytes = total_in;
			*num_added += 1;

			/*
			 * The async work queues will take care of doing actual
			 * allocation on disk for these compressed pages, and
			 * will submit them to the elevator.
			 */
			add_async_extent(async_cow, start, num_bytes,
					total_compressed, pages, nr_pages,
					compress_type);

			if (start + num_bytes < end) {
				start += num_bytes;
				pages = NULL;
				cond_resched();
				goto again;
			}
			return;
		}
	}
	if (pages) {
		/*
		 * the compression code ran but failed to make things smaller,
		 * free any pages it allocated and our page pointer array
		 */
		for (i = 0; i < nr_pages; i++) {
			WARN_ON(pages[i]->mapping);
			page_cache_release(pages[i]);
		}
		kfree(pages);
		pages = NULL;
		total_compressed = 0;
		nr_pages = 0;

		/* flag the file so we don't compress in the future */
		if (!btrfs_test_opt(root, FORCE_COMPRESS) &&
		    !(BTRFS_I(inode)->force_compress)) {
			BTRFS_I(inode)->flags |= BTRFS_INODE_NOCOMPRESS;
		}
	}
cleanup_and_bail_uncompressed:
	/*
	 * No compression, but we still need to write the pages in the file
	 * we've been given so far.  redirty the locked page if it corresponds
	 * to our extent and set things up for the async work queue to run
	 * cow_file_range to do the normal delalloc dance.
	 */
	if (locked_page &&
	    page_offset(locked_page) >= start &&
	    page_offset(locked_page) <= end)
		__set_page_dirty_nobuffers(locked_page);
		/* unlocked later on in the async handlers */

	if (redirty)
		extent_range_redirty_for_io(inode, start, end);
	add_async_extent(async_cow, start, end - start + 1, 0, NULL, 0,
			 BTRFS_COMPRESS_NONE);
	*num_added += 1;

	return;

free_pages_out:
	/*
	 * Ensure we only free the compressed pages if we have
	 * them allocated, as we can still reach here with
	 * inode_need_compress() == false.
	 */
	if (pages) {
		for (i = 0; i < nr_pages; i++) {
			WARN_ON(pages[i]->mapping);
			page_cache_release(pages[i]);
		}
		kfree(pages);
	}
}

static void free_async_extent_pages(struct async_extent *async_extent)
{
	int i;

	if (!async_extent->pages)
		return;

	for (i = 0; i < async_extent->nr_pages; i++) {
		WARN_ON(async_extent->pages[i]->mapping);
		page_cache_release(async_extent->pages[i]);
	}
	kfree(async_extent->pages);
	async_extent->nr_pages = 0;
	async_extent->pages = NULL;
}

/*
 * phase two of compressed writeback.  This is the ordered portion
 * of the code, which only gets called in the order the work was
 * queued.  We walk all the async extents created by compress_file_range
 * and send them down to the disk.
 */
static noinline int submit_compressed_extents(struct inode *inode,
					      struct async_cow *async_cow)
{
	struct async_extent *async_extent;
	u64 alloc_hint = 0;
	struct btrfs_key ins;
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_io_tree *io_tree;
	int ret = 0;

	if (list_empty(&async_cow->extents))
		return 0;

again:
	while (!list_empty(&async_cow->extents)) {
		async_extent = list_entry(async_cow->extents.next,
					  struct async_extent, list);
		list_del(&async_extent->list);

		io_tree = &BTRFS_I(inode)->io_tree;

retry:
		/* did the compression code fall back to uncompressed IO? */
		if (!async_extent->pages) {
			int page_started = 0;
			unsigned long nr_written = 0;

			lock_extent(io_tree, async_extent->start,
					 async_extent->start +
					 async_extent->ram_size - 1);

			/* allocate blocks */
#ifdef MY_DEF_HERE
			ret = cow_file_range(inode, async_cow->locked_page,
					     async_extent->start,
					     async_extent->start +
					     async_extent->ram_size - 1,
					     &page_started, &nr_written, 0, 0);
#else
			ret = cow_file_range(inode, async_cow->locked_page,
					     async_extent->start,
					     async_extent->start +
					     async_extent->ram_size - 1,
					     &page_started, &nr_written, 0);
#endif /* MY_DEF_HERE */

			/* JDM XXX */

			/*
			 * if page_started, cow_file_range inserted an
			 * inline extent and took care of all the unlocking
			 * and IO for us.  Otherwise, we need to submit
			 * all those pages down to the drive.
			 */
			if (!page_started && !ret)
				extent_write_locked_range(io_tree,
						  inode, async_extent->start,
						  async_extent->start +
						  async_extent->ram_size - 1,
						  btrfs_get_extent,
						  WB_SYNC_ALL);
			else if (ret && async_cow->locked_page)
				unlock_page(async_cow->locked_page);
			kfree(async_extent);
			cond_resched();
			continue;
		}

		lock_extent(io_tree, async_extent->start,
			    async_extent->start + async_extent->ram_size - 1);

		ret = btrfs_reserve_extent(root,
					   async_extent->compressed_size,
					   async_extent->compressed_size,
					   0, alloc_hint, &ins, 1, 1);
		if (ret) {
			free_async_extent_pages(async_extent);

			if (ret == -ENOSPC) {
				unlock_extent(io_tree, async_extent->start,
					      async_extent->start +
					      async_extent->ram_size - 1);

				/*
				 * we need to redirty the pages if we decide to
				 * fallback to uncompressed IO, otherwise we
				 * will not submit these pages down to lower
				 * layers.
				 */
				extent_range_redirty_for_io(inode,
						async_extent->start,
						async_extent->start +
						async_extent->ram_size - 1);

				goto retry;
			}
			goto out_free;
		}

		/*
		 * here we're doing allocation and writeback of the
		 * compressed pages
		 */
		btrfs_drop_extent_cache(inode, async_extent->start,
					async_extent->start +
					async_extent->ram_size - 1, 0);

		em = alloc_extent_map();
		if (!em) {
			ret = -ENOMEM;
			goto out_free_reserve;
		}
		em->start = async_extent->start;
		em->len = async_extent->ram_size;
		em->orig_start = em->start;
		em->mod_start = em->start;
		em->mod_len = em->len;

		em->block_start = ins.objectid;
		em->block_len = ins.offset;
		em->orig_block_len = ins.offset;
		em->ram_bytes = async_extent->ram_size;
		em->bdev = root->fs_info->fs_devices->latest_bdev;
		em->compress_type = async_extent->compress_type;
		set_bit(EXTENT_FLAG_PINNED, &em->flags);
		set_bit(EXTENT_FLAG_COMPRESSED, &em->flags);
		em->generation = -1;

		while (1) {
			write_lock(&em_tree->lock);
			ret = add_extent_mapping(em_tree, em, 1);
			write_unlock(&em_tree->lock);
			if (ret != -EEXIST) {
				free_extent_map(em);
				break;
			}
			btrfs_drop_extent_cache(inode, async_extent->start,
						async_extent->start +
						async_extent->ram_size - 1, 0);
		}

		if (ret)
			goto out_free_reserve;

		ret = btrfs_add_ordered_extent_compress(inode,
						async_extent->start,
						ins.objectid,
						async_extent->ram_size,
						ins.offset,
						BTRFS_ORDERED_COMPRESSED,
						async_extent->compress_type);
		if (ret) {
			btrfs_drop_extent_cache(inode, async_extent->start,
						async_extent->start +
						async_extent->ram_size - 1, 0);
			goto out_free_reserve;
		}

		/*
		 * clear dirty, set writeback and unlock the pages.
		 */
		extent_clear_unlock_delalloc(inode, async_extent->start,
				async_extent->start +
				async_extent->ram_size - 1,
				NULL, EXTENT_LOCKED | EXTENT_DELALLOC,
				PAGE_UNLOCK | PAGE_CLEAR_DIRTY |
				PAGE_SET_WRITEBACK);
		ret = btrfs_submit_compressed_write(inode,
				    async_extent->start,
				    async_extent->ram_size,
				    ins.objectid,
				    ins.offset, async_extent->pages,
				    async_extent->nr_pages);
		if (ret) {
			struct extent_io_tree *tree = &BTRFS_I(inode)->io_tree;
			struct page *p = async_extent->pages[0];
			const u64 start = async_extent->start;
			const u64 end = start + async_extent->ram_size - 1;

			p->mapping = inode->i_mapping;
			tree->ops->writepage_end_io_hook(p, start, end,
							 NULL, 0);
			p->mapping = NULL;
			extent_clear_unlock_delalloc(inode, start, end, NULL, 0,
						     PAGE_END_WRITEBACK |
						     PAGE_SET_ERROR);
			free_async_extent_pages(async_extent);
		}
		alloc_hint = ins.objectid + ins.offset;
		kfree(async_extent);
		cond_resched();
	}
	return 0;
out_free_reserve:
	btrfs_free_reserved_extent(root, ins.objectid, ins.offset, 1);
out_free:
	extent_clear_unlock_delalloc(inode, async_extent->start,
				     async_extent->start +
				     async_extent->ram_size - 1,
				     NULL, EXTENT_LOCKED | EXTENT_DELALLOC |
				     EXTENT_DEFRAG | EXTENT_DO_ACCOUNTING,
				     PAGE_UNLOCK | PAGE_CLEAR_DIRTY |
				     PAGE_SET_WRITEBACK | PAGE_END_WRITEBACK |
				     PAGE_SET_ERROR);
	free_async_extent_pages(async_extent);
	kfree(async_extent);
	goto again;
}

static u64 get_extent_allocation_hint(struct inode *inode, u64 start,
				      u64 num_bytes)
{
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_map *em;
	u64 alloc_hint = 0;

#ifdef MY_DEF_HERE
	if (btrfs_test_opt(BTRFS_I(inode)->root, SSD))
		return 0;
#endif /* MY_DEF_HERE */

	read_lock(&em_tree->lock);
	em = search_extent_mapping(em_tree, start, num_bytes);
	if (em) {
		/*
		 * if block start isn't an actual block number then find the
		 * first block in this inode and use that as a hint.  If that
		 * block is also bogus then just don't worry about it.
		 */
		if (em->block_start >= EXTENT_MAP_LAST_BYTE) {
			free_extent_map(em);
			em = search_extent_mapping(em_tree, 0, 0);
			if (em && em->block_start < EXTENT_MAP_LAST_BYTE)
				alloc_hint = em->block_start;
			if (em)
				free_extent_map(em);
		} else {
			alloc_hint = em->block_start;
			free_extent_map(em);
		}
	}
	read_unlock(&em_tree->lock);

	return alloc_hint;
}

/*
 * when extent_io.c finds a delayed allocation range in the file,
 * the call backs end up in this code.  The basic idea is to
 * allocate extents on disk for the range, and create ordered data structs
 * in ram to track those extents.
 *
 * locked_page is the page that writepage had locked already.  We use
 * it to make sure we don't do extra locks or unlocks.
 *
 * *page_started is set to one if we unlock locked_page and do everything
 * required to start IO on it.  It may be clean and already done with
 * IO when we return.
 */
#ifdef MY_DEF_HERE
static noinline int cow_file_range(struct inode *inode,
				   struct page *locked_page,
				   u64 start, u64 end, int *page_started,
				   unsigned long *nr_written,
				   int unlock, int write_sync)
#else
static noinline int cow_file_range(struct inode *inode,
				   struct page *locked_page,
				   u64 start, u64 end, int *page_started,
				   unsigned long *nr_written,
				   int unlock)
#endif /* MY_DEF_HERE */
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u64 alloc_hint = 0;
	u64 num_bytes;
	unsigned long ram_size;
	u64 disk_num_bytes;
	u64 cur_alloc_size;
	u64 blocksize = root->sectorsize;
	struct btrfs_key ins;
	struct extent_map *em;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	int ret = 0;

	if (btrfs_is_free_space_inode(inode)) {
		WARN_ON_ONCE(1);
		ret = -EINVAL;
		goto out_unlock;
	}

	num_bytes = ALIGN(end - start + 1, blocksize);
	num_bytes = max(blocksize,  num_bytes);
	disk_num_bytes = num_bytes;

	/* if this is a small write inside eof, kick off defrag */
	if (num_bytes < 64 * 1024 &&
	    (start > 0 || end + 1 < BTRFS_I(inode)->disk_i_size))
#ifdef MY_DEF_HERE
		btrfs_add_inode_defrag(NULL, inode, 0, 0, BTRFS_INODE_DEFRAG_NORMAL);
#else
		btrfs_add_inode_defrag(NULL, inode);
#endif /* MY_DEF_HERE */

	if (start == 0) {
		/* lets try to make an inline extent */
		ret = cow_file_range_inline(root, inode, start, end, 0, 0,
					    NULL);
		if (ret == 0) {
			extent_clear_unlock_delalloc(inode, start, end, NULL,
				     EXTENT_LOCKED | EXTENT_DELALLOC |
				     EXTENT_DEFRAG, PAGE_UNLOCK |
				     PAGE_CLEAR_DIRTY | PAGE_SET_WRITEBACK |
				     PAGE_END_WRITEBACK);

			*nr_written = *nr_written +
			     (end - start + PAGE_CACHE_SIZE) / PAGE_CACHE_SIZE;
			*page_started = 1;
			goto out;
		} else if (ret < 0) {
			goto out_unlock;
		}
	}

	BUG_ON(disk_num_bytes >
	       btrfs_super_total_bytes(root->fs_info->super_copy));

	alloc_hint = get_extent_allocation_hint(inode, start, num_bytes);
	btrfs_drop_extent_cache(inode, start, start + num_bytes - 1, 0);

	while (disk_num_bytes > 0) {
		unsigned long op;

		cur_alloc_size = disk_num_bytes;
		ret = btrfs_reserve_extent(root, cur_alloc_size,
					   root->sectorsize, 0, alloc_hint,
					   &ins, 1, 1);
		if (ret < 0)
			goto out_unlock;

		em = alloc_extent_map();
		if (!em) {
			ret = -ENOMEM;
			goto out_reserve;
		}
		em->start = start;
		em->orig_start = em->start;
		ram_size = ins.offset;
		em->len = ins.offset;
		em->mod_start = em->start;
		em->mod_len = em->len;

		em->block_start = ins.objectid;
		em->block_len = ins.offset;
		em->orig_block_len = ins.offset;
		em->ram_bytes = ram_size;
		em->bdev = root->fs_info->fs_devices->latest_bdev;
		set_bit(EXTENT_FLAG_PINNED, &em->flags);
		em->generation = -1;

		while (1) {
			write_lock(&em_tree->lock);
			ret = add_extent_mapping(em_tree, em, 1);
			write_unlock(&em_tree->lock);
			if (ret != -EEXIST) {
				free_extent_map(em);
				break;
			}
			btrfs_drop_extent_cache(inode, start,
						start + ram_size - 1, 0);
		}
		if (ret)
			goto out_reserve;

		cur_alloc_size = ins.offset;
#ifdef MY_DEF_HERE
		ret = btrfs_add_ordered_extent(inode, start, ins.objectid,
					       ram_size, cur_alloc_size, 0, write_sync);
#else
		ret = btrfs_add_ordered_extent(inode, start, ins.objectid,
					       ram_size, cur_alloc_size, 0);
#endif /* MY_DEF_HERE */
		if (ret)
			goto out_drop_extent_cache;

		if (root->root_key.objectid ==
		    BTRFS_DATA_RELOC_TREE_OBJECTID) {
			ret = btrfs_reloc_clone_csums(inode, start,
						      cur_alloc_size);
			/*
			 * Only drop cache here, and process as normal.
			 *
			 * We must not allow extent_clear_unlock_delalloc()
			 * at out_unlock label to free meta of this ordered
			 * extent, as its meta should be freed by
			 * btrfs_finish_ordered_io().
			 *
			 * So we must continue until @start is increased to
			 * skip current ordered extent.
			 */
			if (ret)
				btrfs_drop_extent_cache(inode, start,
						start + ram_size - 1, 0);
		}

		/* we're not doing compressed IO, don't unlock the first
		 * page (which the caller expects to stay locked), don't
		 * clear any dirty bits and don't set any writeback bits
		 *
		 * Do set the Private2 bit so we know this page was properly
		 * setup for writepage
		 */
		op = unlock ? PAGE_UNLOCK : 0;
		op |= PAGE_SET_PRIVATE2;

		extent_clear_unlock_delalloc(inode, start,
					     start + ram_size - 1, locked_page,
					     EXTENT_LOCKED | EXTENT_DELALLOC,
					     op);
		if (disk_num_bytes < cur_alloc_size)
			disk_num_bytes = 0;
		else
			disk_num_bytes -= cur_alloc_size;
		num_bytes -= cur_alloc_size;
		alloc_hint = ins.objectid + ins.offset;
		start += cur_alloc_size;

		/*
		 * btrfs_reloc_clone_csums() error, since start is increased
		 * extent_clear_unlock_delalloc() at out_unlock label won't
		 * free metadata of current ordered extent, we're OK to exit.
		 */
		if (ret)
			goto out_unlock;
	}
out:
	return ret;

out_drop_extent_cache:
	btrfs_drop_extent_cache(inode, start, start + ram_size - 1, 0);
out_reserve:
	btrfs_free_reserved_extent(root, ins.objectid, ins.offset, 1);
out_unlock:
	extent_clear_unlock_delalloc(inode, start, end, locked_page,
				     EXTENT_LOCKED | EXTENT_DO_ACCOUNTING |
				     EXTENT_DELALLOC | EXTENT_DEFRAG,
				     PAGE_UNLOCK | PAGE_CLEAR_DIRTY |
				     PAGE_SET_WRITEBACK | PAGE_END_WRITEBACK);
	goto out;
}

/*
 * work queue call back to started compression on a file and pages
 */
static noinline void async_cow_start(struct btrfs_work *work)
{
	struct async_cow *async_cow;
	int num_added = 0;
	async_cow = container_of(work, struct async_cow, work);

	compress_file_range(async_cow->inode, async_cow->locked_page,
			    async_cow->start, async_cow->end, async_cow,
			    &num_added);
	if (num_added == 0) {
		btrfs_add_delayed_iput(async_cow->inode);
		async_cow->inode = NULL;
	}
}

/*
 * work queue call back to submit previously compressed pages
 */
static noinline void async_cow_submit(struct btrfs_work *work)
{
	struct async_cow *async_cow;
	struct btrfs_root *root;
	unsigned long nr_pages;

	async_cow = container_of(work, struct async_cow, work);

	root = async_cow->root;
	nr_pages = (async_cow->end - async_cow->start + PAGE_CACHE_SIZE) >>
		PAGE_CACHE_SHIFT;

	if (atomic_sub_return(nr_pages, &root->fs_info->async_delalloc_pages) <
	    5 * 1024 * 1024 &&
	    waitqueue_active(&root->fs_info->async_submit_wait))
		wake_up(&root->fs_info->async_submit_wait);

	if (async_cow->inode)
		submit_compressed_extents(async_cow->inode, async_cow);
}

static noinline void async_cow_free(struct btrfs_work *work)
{
	struct async_cow *async_cow;
	async_cow = container_of(work, struct async_cow, work);
	if (async_cow->inode)
		btrfs_add_delayed_iput(async_cow->inode);
	kfree(async_cow);
}

static int cow_file_range_async(struct inode *inode, struct page *locked_page,
				u64 start, u64 end, int *page_started,
				unsigned long *nr_written)
{
	struct async_cow *async_cow;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	unsigned long nr_pages;
	u64 cur_end;
	int limit = 10 * 1024 * 1024;

	clear_extent_bit(&BTRFS_I(inode)->io_tree, start, end, EXTENT_LOCKED,
			 1, 0, NULL, GFP_NOFS);
	while (start < end) {
		async_cow = kmalloc(sizeof(*async_cow), GFP_NOFS);
		BUG_ON(!async_cow); /* -ENOMEM */
		async_cow->inode = igrab(inode);
		async_cow->root = root;
		async_cow->start = start;

		if (BTRFS_I(inode)->flags & BTRFS_INODE_NOCOMPRESS &&
		    !btrfs_test_opt(root, FORCE_COMPRESS))
			cur_end = end;
		else
			cur_end = min(end, start + 512 * 1024 - 1);

		async_cow->end = cur_end;
		INIT_LIST_HEAD(&async_cow->extents);

		/*
		 * The locked_page comes all the way from writepage and its
		 * the original page we were actually given.  As we spread
		 * this large delalloc region across multiple async_chunk
		 * structs, only the first struct needs a pointer to locked_page
		 *
		 * This way we don't need racey decisions about who is supposed
		 * to unlock it.
		 */
		if (locked_page) {
			async_cow->locked_page = locked_page;
			locked_page = NULL;
		} else {
			async_cow->locked_page = NULL;
		}

		btrfs_init_work(&async_cow->work,
				btrfs_delalloc_helper,
				async_cow_start, async_cow_submit,
				async_cow_free);

		nr_pages = (cur_end - start + PAGE_CACHE_SIZE) >>
			PAGE_CACHE_SHIFT;
		atomic_add(nr_pages, &root->fs_info->async_delalloc_pages);

		btrfs_queue_work(root->fs_info->delalloc_workers,
				 &async_cow->work);

		if (atomic_read(&root->fs_info->async_delalloc_pages) > limit) {
			wait_event(root->fs_info->async_submit_wait,
			   (atomic_read(&root->fs_info->async_delalloc_pages) <
			    limit));
		}

		while (atomic_read(&root->fs_info->async_submit_draining) &&
		      atomic_read(&root->fs_info->async_delalloc_pages)) {
			wait_event(root->fs_info->async_submit_wait,
			  (atomic_read(&root->fs_info->async_delalloc_pages) ==
			   0));
		}

		*nr_written += nr_pages;
		start = cur_end + 1;
	}
	*page_started = 1;
	return 0;
}

static noinline int csum_exist_in_range(struct btrfs_root *root,
					u64 bytenr, u64 num_bytes)
{
	int ret;
	struct btrfs_ordered_sum *sums;
	LIST_HEAD(list);

	ret = btrfs_lookup_csums_range(root->fs_info->csum_root, bytenr,
				       bytenr + num_bytes - 1, &list, 0);
	if (ret == 0 && list_empty(&list))
		return 0;

	while (!list_empty(&list)) {
		sums = list_entry(list.next, struct btrfs_ordered_sum, list);
		list_del(&sums->list);
		kfree(sums);
	}
	return 1;
}

/*
 * when nowcow writeback call back.  This checks for snapshots or COW copies
 * of the extents that exist in the file, and COWs the file as required.
 *
 * If no cow copies or snapshots exist, we write directly to the existing
 * blocks on disk
 */
#ifdef MY_DEF_HERE
static noinline int run_delalloc_nocow(struct inode *inode,
				       struct page *locked_page,
			      u64 start, u64 end, int *page_started, int force,
			      unsigned long *nr_written, int write_sync)
#else
static noinline int run_delalloc_nocow(struct inode *inode,
				       struct page *locked_page,
			      u64 start, u64 end, int *page_started, int force,
			      unsigned long *nr_written)
#endif /* MY_DEF_HERE */
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_buffer *leaf;
	struct btrfs_path *path;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key found_key;
	u64 cow_start;
	u64 cur_offset;
	u64 extent_end;
	u64 extent_offset;
	u64 disk_bytenr;
	u64 num_bytes;
	u64 disk_num_bytes;
	u64 ram_bytes;
	int extent_type;
#ifdef MY_DEF_HERE
	int ret;
#else
	int ret, err;
#endif /* MY_DEF_HERE */
	int type;
	int nocow;
	int check_prev = 1;
	bool nolock;
	u64 ino = btrfs_ino(inode);

	path = btrfs_alloc_path();
	if (!path) {
		extent_clear_unlock_delalloc(inode, start, end, locked_page,
					     EXTENT_LOCKED | EXTENT_DELALLOC |
					     EXTENT_DO_ACCOUNTING |
					     EXTENT_DEFRAG, PAGE_UNLOCK |
					     PAGE_CLEAR_DIRTY |
					     PAGE_SET_WRITEBACK |
					     PAGE_END_WRITEBACK);
		return -ENOMEM;
	}

	nolock = btrfs_is_free_space_inode(inode);

	cow_start = (u64)-1;
	cur_offset = start;
	while (1) {
		ret = btrfs_lookup_file_extent(NULL, root, path, ino,
					       cur_offset, 0);
		if (ret < 0)
			goto error;
		if (ret > 0 && path->slots[0] > 0 && check_prev) {
			leaf = path->nodes[0];
			btrfs_item_key_to_cpu(leaf, &found_key,
					      path->slots[0] - 1);
			if (found_key.objectid == ino &&
			    found_key.type == BTRFS_EXTENT_DATA_KEY)
				path->slots[0]--;
		}
		check_prev = 0;
next_slot:
		leaf = path->nodes[0];
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto error;
			if (ret > 0)
				break;
			leaf = path->nodes[0];
		}

		nocow = 0;
		disk_bytenr = 0;
		num_bytes = 0;
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

		if (found_key.objectid > ino)
			break;
		if (WARN_ON_ONCE(found_key.objectid < ino) ||
		    found_key.type < BTRFS_EXTENT_DATA_KEY) {
			path->slots[0]++;
			goto next_slot;
		}
		if (found_key.type > BTRFS_EXTENT_DATA_KEY ||
		    found_key.offset > end)
			break;

		if (found_key.offset > cur_offset) {
			extent_end = found_key.offset;
			extent_type = 0;
			goto out_check;
		}

		fi = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_file_extent_item);
		extent_type = btrfs_file_extent_type(leaf, fi);

		ram_bytes = btrfs_file_extent_ram_bytes(leaf, fi);
		if (extent_type == BTRFS_FILE_EXTENT_REG ||
		    extent_type == BTRFS_FILE_EXTENT_PREALLOC) {
			disk_bytenr = btrfs_file_extent_disk_bytenr(leaf, fi);
			extent_offset = btrfs_file_extent_offset(leaf, fi);
			extent_end = found_key.offset +
				btrfs_file_extent_num_bytes(leaf, fi);
			disk_num_bytes =
				btrfs_file_extent_disk_num_bytes(leaf, fi);
			if (extent_end <= start) {
				path->slots[0]++;
				goto next_slot;
			}
			if (disk_bytenr == 0)
				goto out_check;
			if (btrfs_file_extent_compression(leaf, fi) ||
			    btrfs_file_extent_encryption(leaf, fi) ||
			    btrfs_file_extent_other_encoding(leaf, fi))
				goto out_check;
			if (extent_type == BTRFS_FILE_EXTENT_REG && !force)
				goto out_check;
#ifdef MY_DEF_HERE
			if (btrfs_file_extent_generation(leaf, fi) <=
					btrfs_root_last_snapshot(&root->root_item))
				goto out_check;
#endif /* MY_DEF_HERE */
			if (btrfs_extent_readonly(root, disk_bytenr))
				goto out_check;
#ifdef MY_DEF_HERE
			if (btrfs_cross_ref_exist(root, ino,
						  found_key.offset - extent_offset, disk_bytenr,
						  CHECK_CROSS_REF_NORMAL))
#else
			if (btrfs_cross_ref_exist(root, ino,
						  found_key.offset -
						  extent_offset, disk_bytenr))
#endif /* MY_DEF_HERE */
				goto out_check;
			disk_bytenr += extent_offset;
			disk_bytenr += cur_offset - found_key.offset;
			num_bytes = min(end + 1, extent_end) - cur_offset;
			/*
			 * if there are pending snapshots for this root,
			 * we fall into common COW way.
			 */
#ifdef MY_DEF_HERE
			if (!nolock && unlikely(atomic_read(&root->force_cow))) {
				goto out_check;
			}
#else
			if (!nolock) {
				err = btrfs_start_write_no_snapshoting(root);
				if (!err)
					goto out_check;
			}
#endif /* MY_DEF_HERE */
			/*
			 * force cow if csum exists in the range.
			 * this ensure that csum for a given extent are
			 * either valid or do not exist.
			 */
#ifdef MY_DEF_HERE
			if (csum_exist_in_range(root, disk_bytenr, num_bytes)) {
#ifdef MY_DEF_HERE
#else
				if (!nolock) {
					btrfs_end_write_no_snapshoting(root);
				}
#endif /* MY_DEF_HERE */
				goto out_check;
			}
#else
			if (csum_exist_in_range(root, disk_bytenr, num_bytes))
				goto out_check;
#endif /* MY_DEF_HERE */
			nocow = 1;
		} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
			extent_end = found_key.offset +
				btrfs_file_extent_inline_len(leaf,
						     path->slots[0], fi);
			extent_end = ALIGN(extent_end, root->sectorsize);
		} else {
			BUG_ON(1);
		}
out_check:
		if (extent_end <= start) {
			path->slots[0]++;
#ifdef MY_DEF_HERE
#else
			if (!nolock && nocow)
				btrfs_end_write_no_snapshoting(root);
#endif /* MY_DEF_HERE */
			goto next_slot;
		}
		if (!nocow) {
			if (cow_start == (u64)-1)
				cow_start = cur_offset;
			cur_offset = extent_end;
			if (cur_offset > end)
				break;
			path->slots[0]++;
			goto next_slot;
		}

		btrfs_release_path(path);
		if (cow_start != (u64)-1) {
#ifdef MY_DEF_HERE
			ret = cow_file_range(inode, locked_page,
					     cow_start, found_key.offset - 1,
					     page_started, nr_written, 1, write_sync);
#else
			ret = cow_file_range(inode, locked_page,
					     cow_start, found_key.offset - 1,
					     page_started, nr_written, 1);
#endif /* MY_DEF_HERE */
			if (ret) {
#ifdef MY_DEF_HERE
#else
				if (!nolock && nocow)
					btrfs_end_write_no_snapshoting(root);
#endif /* MY_DEF_HERE */
				goto error;
			}
			cow_start = (u64)-1;
		}

		if (extent_type == BTRFS_FILE_EXTENT_PREALLOC) {
			struct extent_map *em;
			struct extent_map_tree *em_tree;
			em_tree = &BTRFS_I(inode)->extent_tree;
			em = alloc_extent_map();
			BUG_ON(!em); /* -ENOMEM */
			em->start = cur_offset;
			em->orig_start = found_key.offset - extent_offset;
			em->len = num_bytes;
			em->block_len = num_bytes;
			em->block_start = disk_bytenr;
			em->orig_block_len = disk_num_bytes;
			em->ram_bytes = ram_bytes;
			em->bdev = root->fs_info->fs_devices->latest_bdev;
			em->mod_start = em->start;
			em->mod_len = em->len;
			set_bit(EXTENT_FLAG_PINNED, &em->flags);
			set_bit(EXTENT_FLAG_FILLING, &em->flags);
			em->generation = -1;
			while (1) {
				write_lock(&em_tree->lock);
				ret = add_extent_mapping(em_tree, em, 1);
				write_unlock(&em_tree->lock);
				if (ret != -EEXIST) {
					free_extent_map(em);
					break;
				}
				btrfs_drop_extent_cache(inode, em->start,
						em->start + em->len - 1, 0);
			}
			type = BTRFS_ORDERED_PREALLOC;
		} else {
			type = BTRFS_ORDERED_NOCOW;
		}

#ifdef MY_DEF_HERE
		ret = btrfs_add_ordered_extent(inode, cur_offset, disk_bytenr,
					       num_bytes, num_bytes, type, write_sync);
#else
		ret = btrfs_add_ordered_extent(inode, cur_offset, disk_bytenr,
					       num_bytes, num_bytes, type);
#endif /* MY_DEF_HERE */
		BUG_ON(ret); /* -ENOMEM */

		if (root->root_key.objectid ==
		    BTRFS_DATA_RELOC_TREE_OBJECTID)
			/*
			 * Error handled later, as we must prevent
			 * extent_clear_unlock_delalloc() in error handler
			 * from freeing metadata of created ordered extent.
			 */
			ret = btrfs_reloc_clone_csums(inode, cur_offset,
						      num_bytes);

		extent_clear_unlock_delalloc(inode, cur_offset,
					     cur_offset + num_bytes - 1,
					     locked_page, EXTENT_LOCKED |
					     EXTENT_DELALLOC, PAGE_UNLOCK |
					     PAGE_SET_PRIVATE2);
#ifdef MY_DEF_HERE
#else
		if (!nolock && nocow)
			btrfs_end_write_no_snapshoting(root);
#endif /* MY_DEF_HERE */
		cur_offset = extent_end;

		/*
		 * btrfs_reloc_clone_csums() error, now we're OK to call error
		 * handler, as metadata for created ordered extent will only
		 * be freed by btrfs_finish_ordered_io().
		 */
		if (ret)
			goto error;
		if (cur_offset > end)
			break;
	}
	btrfs_release_path(path);

	if (cur_offset <= end && cow_start == (u64)-1) {
		cow_start = cur_offset;
#ifdef MY_DEF_HERE
#else
		cur_offset = end;
#endif /* MY_DEF_HERE */
	}

	if (cow_start != (u64)-1) {
#ifdef MY_DEF_HERE
		cur_offset = end;
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
		ret = cow_file_range(inode, locked_page, cow_start, end,
				     page_started, nr_written, 1, write_sync);
#else
		ret = cow_file_range(inode, locked_page, cow_start, end,
				     page_started, nr_written, 1);
#endif /* MY_DEF_HERE */
		if (ret)
			goto error;
	}

error:
	if (ret && cur_offset < end)
		extent_clear_unlock_delalloc(inode, cur_offset, end,
					     locked_page, EXTENT_LOCKED |
					     EXTENT_DELALLOC | EXTENT_DEFRAG |
					     EXTENT_DO_ACCOUNTING, PAGE_UNLOCK |
					     PAGE_CLEAR_DIRTY |
					     PAGE_SET_WRITEBACK |
					     PAGE_END_WRITEBACK);
	btrfs_free_path(path);
	return ret;
}

static inline int need_force_cow(struct inode *inode, u64 start, u64 end)
{

	if (!(BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW) &&
	    !(BTRFS_I(inode)->flags & BTRFS_INODE_PREALLOC))
		return 0;

	/*
	 * @defrag_bytes is a hint value, no spinlock held here,
	 * if is not zero, it means the file is defragging.
	 * Force cow if given extent needs to be defragged.
	 */
	if (BTRFS_I(inode)->defrag_bytes &&
	    test_range_bit(&BTRFS_I(inode)->io_tree, start, end,
			   EXTENT_DEFRAG, 0, NULL))
		return 1;

	return 0;
}

/*
 * extent_io.c call back to do delayed allocation processing
 */
#ifdef MY_DEF_HERE
static int run_delalloc_range(struct inode *inode, struct page *locked_page,
			      u64 start, u64 end, int *page_started,
			      unsigned long *nr_written, int write_sync)
#else
static int run_delalloc_range(struct inode *inode, struct page *locked_page,
			      u64 start, u64 end, int *page_started,
			      unsigned long *nr_written)
#endif /* MY_DEF_HERE */
{
	int ret;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int force_cow = need_force_cow(inode, start, end);

	if (BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW && !force_cow) {
#ifdef MY_DEF_HERE
		ret = run_delalloc_nocow(inode, locked_page, start, end,
					 page_started, 1, nr_written, write_sync);
#else
		ret = run_delalloc_nocow(inode, locked_page, start, end,
					 page_started, 1, nr_written);
#endif /* MY_DEF_HERE */
	} else if (BTRFS_I(inode)->flags & BTRFS_INODE_PREALLOC && !force_cow) {
#ifdef MY_DEF_HERE
		ret = run_delalloc_nocow(inode, locked_page, start, end,
					 page_started, 0, nr_written, write_sync);
#else
		ret = run_delalloc_nocow(inode, locked_page, start, end,
					 page_started, 0, nr_written);
#endif /* MY_DEF_HERE */
	} else if (!btrfs_test_opt(root, COMPRESS) &&
		   !(BTRFS_I(inode)->force_compress) &&
		   !(BTRFS_I(inode)->flags & BTRFS_INODE_COMPRESS)) {
#ifdef MY_DEF_HERE
		ret = cow_file_range(inode, locked_page, start, end,
				      page_started, nr_written, 1, write_sync);
#else
		ret = cow_file_range(inode, locked_page, start, end,
				      page_started, nr_written, 1);
#endif /* MY_DEF_HERE */
	} else {
		set_bit(BTRFS_INODE_HAS_ASYNC_EXTENT,
			&BTRFS_I(inode)->runtime_flags);
		ret = cow_file_range_async(inode, locked_page, start, end,
					   page_started, nr_written);
	}
	if (ret)
		btrfs_cleanup_ordered_extents(inode, start, end - start + 1);
	return ret;
}

static void btrfs_split_extent_hook(struct inode *inode,
				    struct extent_state *orig, u64 split)
{
	u64 size;

	/* not delalloc, ignore it */
	if (!(orig->state & EXTENT_DELALLOC))
		return;

	size = orig->end - orig->start + 1;
	if (size > BTRFS_MAX_EXTENT_SIZE) {
		u64 num_extents;
		u64 new_size;

		/*
		 * See the explanation in btrfs_merge_extent_hook, the same
		 * applies here, just in reverse.
		 */
		new_size = orig->end - split + 1;
		num_extents = div64_u64(new_size + BTRFS_MAX_EXTENT_SIZE - 1,
					BTRFS_MAX_EXTENT_SIZE);
		new_size = split - orig->start;
		num_extents += div64_u64(new_size + BTRFS_MAX_EXTENT_SIZE - 1,
					BTRFS_MAX_EXTENT_SIZE);
		if (div64_u64(size + BTRFS_MAX_EXTENT_SIZE - 1,
			      BTRFS_MAX_EXTENT_SIZE) >= num_extents)
			return;
	}

	spin_lock(&BTRFS_I(inode)->lock);
	BTRFS_I(inode)->outstanding_extents++;
	spin_unlock(&BTRFS_I(inode)->lock);
}

/*
 * extent_io.c merge_extent_hook, used to track merged delayed allocation
 * extents so we can keep track of new extents that are just merged onto old
 * extents, such as when we are doing sequential writes, so we can properly
 * account for the metadata space we'll need.
 */
static void btrfs_merge_extent_hook(struct inode *inode,
				    struct extent_state *new,
				    struct extent_state *other)
{
	u64 new_size, old_size;
	u64 num_extents;

	/* not delalloc, ignore it */
	if (!(other->state & EXTENT_DELALLOC))
		return;

	if (new->start > other->start)
		new_size = new->end - other->start + 1;
	else
		new_size = other->end - new->start + 1;

	/* we're not bigger than the max, unreserve the space and go */
	if (new_size <= BTRFS_MAX_EXTENT_SIZE) {
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->outstanding_extents--;
		spin_unlock(&BTRFS_I(inode)->lock);
		return;
	}

	/*
	 * We have to add up either side to figure out how many extents were
	 * accounted for before we merged into one big extent.  If the number of
	 * extents we accounted for is <= the amount we need for the new range
	 * then we can return, otherwise drop.  Think of it like this
	 *
	 * [ 4k][MAX_SIZE]
	 *
	 * So we've grown the extent by a MAX_SIZE extent, this would mean we
	 * need 2 outstanding extents, on one side we have 1 and the other side
	 * we have 1 so they are == and we can return.  But in this case
	 *
	 * [MAX_SIZE+4k][MAX_SIZE+4k]
	 *
	 * Each range on their own accounts for 2 extents, but merged together
	 * they are only 3 extents worth of accounting, so we need to drop in
	 * this case.
	 */
	old_size = other->end - other->start + 1;
	num_extents = div64_u64(old_size + BTRFS_MAX_EXTENT_SIZE - 1,
				BTRFS_MAX_EXTENT_SIZE);
	old_size = new->end - new->start + 1;
	num_extents += div64_u64(old_size + BTRFS_MAX_EXTENT_SIZE - 1,
				 BTRFS_MAX_EXTENT_SIZE);

	if (div64_u64(new_size + BTRFS_MAX_EXTENT_SIZE - 1,
		      BTRFS_MAX_EXTENT_SIZE) >= num_extents)
		return;

	spin_lock(&BTRFS_I(inode)->lock);
	BTRFS_I(inode)->outstanding_extents--;
	spin_unlock(&BTRFS_I(inode)->lock);
}

static void btrfs_add_delalloc_inodes(struct btrfs_root *root,
				      struct inode *inode)
{
	spin_lock(&root->delalloc_lock);
	if (list_empty(&BTRFS_I(inode)->delalloc_inodes)) {
		list_add_tail(&BTRFS_I(inode)->delalloc_inodes,
			      &root->delalloc_inodes);
		set_bit(BTRFS_INODE_IN_DELALLOC_LIST,
			&BTRFS_I(inode)->runtime_flags);
		root->nr_delalloc_inodes++;
		if (root->nr_delalloc_inodes == 1) {
			spin_lock(&root->fs_info->delalloc_root_lock);
			BUG_ON(!list_empty(&root->delalloc_root));
			list_add_tail(&root->delalloc_root,
				      &root->fs_info->delalloc_roots);
			spin_unlock(&root->fs_info->delalloc_root_lock);
		}
	}
	spin_unlock(&root->delalloc_lock);
}

static void btrfs_del_delalloc_inode(struct btrfs_root *root,
				     struct inode *inode)
{
	spin_lock(&root->delalloc_lock);
	if (!list_empty(&BTRFS_I(inode)->delalloc_inodes)) {
		list_del_init(&BTRFS_I(inode)->delalloc_inodes);
		clear_bit(BTRFS_INODE_IN_DELALLOC_LIST,
			  &BTRFS_I(inode)->runtime_flags);
		root->nr_delalloc_inodes--;
		if (!root->nr_delalloc_inodes) {
			spin_lock(&root->fs_info->delalloc_root_lock);
			BUG_ON(list_empty(&root->delalloc_root));
			list_del_init(&root->delalloc_root);
			spin_unlock(&root->fs_info->delalloc_root_lock);
		}
	}
	spin_unlock(&root->delalloc_lock);
}

#ifdef MY_DEF_HERE
static void btrfs_syno_add_dirty_lru_inode(struct btrfs_fs_info *fs_info,
				      struct inode *inode)
{
	spin_lock(&fs_info->syno_multiple_writeback_lock);
	if (list_empty(&BTRFS_I(inode)->syno_dirty_lru_inode)) {
		list_add_tail(&BTRFS_I(inode)->syno_dirty_lru_inode,
			      &fs_info->syno_dirty_lru_inodes);
		set_bit(BTRFS_INODE_SYNO_WRITEBACK_LRU_LIST,
			&BTRFS_I(inode)->runtime_flags);
	}
	spin_unlock(&fs_info->syno_multiple_writeback_lock);
}

static void btrfs_syno_del_dirty_lru_inode(struct btrfs_fs_info *fs_info,
				     struct inode *inode)
{
	spin_lock(&fs_info->syno_multiple_writeback_lock);
	if (!list_empty(&BTRFS_I(inode)->syno_dirty_lru_inode)) {
		list_del_init(&BTRFS_I(inode)->syno_dirty_lru_inode);
		clear_bit(BTRFS_INODE_SYNO_WRITEBACK_LRU_LIST,
			  &BTRFS_I(inode)->runtime_flags);
	}
	spin_unlock(&fs_info->syno_multiple_writeback_lock);
}
#endif /* MY_DEF_HERE */

/*
 * extent_io.c set_bit_hook, used to track delayed allocation
 * bytes in this file, and to maintain the list of inodes that
 * have pending delalloc work to be done.
 */
static void btrfs_set_bit_hook(struct inode *inode,
			       struct extent_state *state, unsigned long *bits)
{

	if ((*bits & EXTENT_DEFRAG) && !(*bits & EXTENT_DELALLOC))
		WARN_ON(1);
	/*
	 * set_bit and clear bit hooks normally require _irqsave/restore
	 * but in this case, we are only testing for the DELALLOC
	 * bit, which is only set or cleared with irqs on
	 */
	if (!(state->state & EXTENT_DELALLOC) && (*bits & EXTENT_DELALLOC)) {
		struct btrfs_root *root = BTRFS_I(inode)->root;
		u64 len = state->end + 1 - state->start;
		bool do_list = !btrfs_is_free_space_inode(inode);

		if (*bits & EXTENT_FIRST_DELALLOC) {
			*bits &= ~EXTENT_FIRST_DELALLOC;
		} else {
			spin_lock(&BTRFS_I(inode)->lock);
			BTRFS_I(inode)->outstanding_extents++;
			spin_unlock(&BTRFS_I(inode)->lock);
		}

		/* For sanity tests */
		if (btrfs_test_is_dummy_root(root))
			return;

		__percpu_counter_add(&root->fs_info->delalloc_bytes, len,
				     root->fs_info->delalloc_batch);
#ifdef MY_DEF_HERE
		if (root->syno_delalloc_bytes)
			__percpu_counter_add(root->syno_delalloc_bytes, len, root->fs_info->delalloc_batch);
#endif /* MY_DEF_HERE */
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->delalloc_bytes += len;
		if (*bits & EXTENT_DEFRAG)
			BTRFS_I(inode)->defrag_bytes += len;
		if (do_list && !test_bit(BTRFS_INODE_IN_DELALLOC_LIST,
					 &BTRFS_I(inode)->runtime_flags))
			btrfs_add_delalloc_inodes(root, inode);
#ifdef MY_DEF_HERE
		if (do_list && !test_bit(BTRFS_INODE_SYNO_WRITEBACK_LRU_LIST, &BTRFS_I(inode)->runtime_flags))
			btrfs_syno_add_dirty_lru_inode(root->fs_info, inode);
#endif /* MY_DEF_HERE */
		spin_unlock(&BTRFS_I(inode)->lock);
	}
}

/*
 * extent_io.c clear_bit_hook, see set_bit_hook for why
 */
static void btrfs_clear_bit_hook(struct inode *inode,
				 struct extent_state *state,
				 unsigned long *bits)
{
	u64 len = state->end + 1 - state->start;
	u64 num_extents = div64_u64(len + BTRFS_MAX_EXTENT_SIZE -1,
				    BTRFS_MAX_EXTENT_SIZE);

	spin_lock(&BTRFS_I(inode)->lock);
	if ((state->state & EXTENT_DEFRAG) && (*bits & EXTENT_DEFRAG))
		BTRFS_I(inode)->defrag_bytes -= len;
	spin_unlock(&BTRFS_I(inode)->lock);

	/*
	 * set_bit and clear bit hooks normally require _irqsave/restore
	 * but in this case, we are only testing for the DELALLOC
	 * bit, which is only set or cleared with irqs on
	 */
	if ((state->state & EXTENT_DELALLOC) && (*bits & EXTENT_DELALLOC)) {
		struct btrfs_root *root = BTRFS_I(inode)->root;
		bool do_list = !btrfs_is_free_space_inode(inode);

		if (*bits & EXTENT_FIRST_DELALLOC) {
			*bits &= ~EXTENT_FIRST_DELALLOC;
		} else if (!(*bits & EXTENT_DO_ACCOUNTING)) {
			spin_lock(&BTRFS_I(inode)->lock);
			BTRFS_I(inode)->outstanding_extents -= num_extents;
			spin_unlock(&BTRFS_I(inode)->lock);
		}

		/*
		 * We don't reserve metadata space for space cache inodes so we
		 * don't need to call dellalloc_release_metadata if there is an
		 * error.
		 */
		if (*bits & EXTENT_DO_ACCOUNTING &&
		    root != root->fs_info->tree_root)
			btrfs_delalloc_release_metadata(inode, len);

		/* For sanity tests. */
		if (btrfs_test_is_dummy_root(root))
			return;

		if (root->root_key.objectid != BTRFS_DATA_RELOC_TREE_OBJECTID
		    && do_list && !(state->state & EXTENT_NORESERVE))
			btrfs_free_reserved_data_space(inode, len);

		__percpu_counter_add(&root->fs_info->delalloc_bytes, -len,
				     root->fs_info->delalloc_batch);
#ifdef MY_DEF_HERE
		if (root->syno_delalloc_bytes)
			__percpu_counter_add(root->syno_delalloc_bytes, -len, root->fs_info->delalloc_batch);
#endif /* MY_DEF_HERE */
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->delalloc_bytes -= len;
		if (do_list && BTRFS_I(inode)->delalloc_bytes == 0 &&
		    test_bit(BTRFS_INODE_IN_DELALLOC_LIST,
			     &BTRFS_I(inode)->runtime_flags))
			btrfs_del_delalloc_inode(root, inode);
#ifdef MY_DEF_HERE
		if (do_list && BTRFS_I(inode)->delalloc_bytes == 0 &&
			test_bit(BTRFS_INODE_SYNO_WRITEBACK_LRU_LIST, &BTRFS_I(inode)->runtime_flags))
			btrfs_syno_del_dirty_lru_inode(root->fs_info, inode);
#endif /* MY_DEF_HERE */
		spin_unlock(&BTRFS_I(inode)->lock);
	}
}

/*
 * extent_io.c merge_bio_hook, this must check the chunk tree to make sure
 * we don't create bios that span stripes or chunks
 *
 * return 1 if page cannot be merged to bio
 * return 0 if page can be merged to bio
 * return error otherwise
 */
int btrfs_merge_bio_hook(int rw, struct page *page, unsigned long offset,
			 size_t size, struct bio *bio,
			 unsigned long bio_flags)
{
	struct btrfs_root *root = BTRFS_I(page->mapping->host)->root;
	u64 logical = (u64)bio->bi_sector << 9;
	u64 length = 0;
	u64 map_length;
	int ret;

	if (bio_flags & EXTENT_BIO_COMPRESSED)
		return 0;

	length = bio->bi_size;
	map_length = length;
	ret = btrfs_map_block(root->fs_info, rw, logical,
			      &map_length, NULL, 0);
	if (ret < 0)
		return ret;
	if (map_length < length + size)
		return 1;
	return 0;
}

/*
 * in order to insert checksums into the metadata in large chunks,
 * we wait until bio submission time.   All the pages in the bio are
 * checksummed and sums are attached onto the ordered extent record.
 *
 * At IO completion time the cums attached on the ordered extent record
 * are inserted into the btree
 */
static int __btrfs_submit_bio_start(struct inode *inode, int rw,
				    struct bio *bio, int mirror_num,
				    unsigned long bio_flags,
				    u64 bio_offset)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret = 0;

	ret = btrfs_csum_one_bio(root, inode, bio, 0, 0);
	BUG_ON(ret); /* -ENOMEM */
	return 0;
}

/*
 * in order to insert checksums into the metadata in large chunks,
 * we wait until bio submission time.   All the pages in the bio are
 * checksummed and sums are attached onto the ordered extent record.
 *
 * At IO completion time the cums attached on the ordered extent record
 * are inserted into the btree
 */
static int __btrfs_submit_bio_done(struct inode *inode, int rw, struct bio *bio,
			  int mirror_num, unsigned long bio_flags,
			  u64 bio_offset)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

#ifdef MY_DEF_HERE
	ret = btrfs_map_bio(root, rw, bio, mirror_num, 0);
#else
	ret = btrfs_map_bio(root, rw, bio, mirror_num, 1);
#endif /* MY_DEF_HERE */
	if (ret)
		bio_endio(bio, ret);
	return ret;
}

/*
 * extent_io.c submission hook. This does the right thing for csum calculation
 * on write, or reading the csums from the tree before a read
 */
static int btrfs_submit_bio_hook(struct inode *inode, int rw, struct bio *bio,
			  int mirror_num, unsigned long bio_flags,
			  u64 bio_offset)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret = 0;
	int skip_sum;
	int metadata = 0;
	int async = !atomic_read(&BTRFS_I(inode)->sync_writers);

	skip_sum = BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM;

	if (btrfs_is_free_space_inode(inode))
		metadata = 2;

	if (!(rw & REQ_WRITE)) {
		ret = btrfs_bio_wq_end_io(root->fs_info, bio, metadata);
		if (ret)
			goto out;

		if (bio_flags & EXTENT_BIO_COMPRESSED) {
			ret = btrfs_submit_compressed_read(inode, bio,
							   mirror_num,
							   bio_flags);
			goto out;
		} else if (!skip_sum) {
			ret = btrfs_lookup_bio_sums(root, inode, bio, NULL);
			if (ret)
				goto out;
		}
		goto mapit;
	} else if (async && !skip_sum) {
		/* csum items have already been cloned */
		if (root->root_key.objectid == BTRFS_DATA_RELOC_TREE_OBJECTID)
			goto mapit;

#ifdef MY_DEF_HERE
		if (root->objectid == BTRFS_FS_TREE_OBJECTID ||
			(root->objectid >= BTRFS_FIRST_FREE_OBJECTID && root->objectid <= BTRFS_LAST_FREE_OBJECTID)) {
			if (root->fs_info->syno_async_submit_throttle && atomic_read(&root->fs_info->syno_async_submit_nr) > root->fs_info->syno_async_submit_throttle) {
				wait_event(root->fs_info->syno_async_submit_queue_wait, atomic_read(&root->fs_info->syno_async_submit_nr) <= root->fs_info->syno_async_submit_throttle);
			}
		}

		/* we're doing a write, do the async checksumming */
		ret = btrfs_wq_submit_bio(BTRFS_I(inode)->root->fs_info,
				   inode, rw, bio, mirror_num,
				   bio_flags, bio_offset,
				   __btrfs_submit_bio_start,
				   __btrfs_submit_bio_done, 1);
#else
		/* we're doing a write, do the async checksumming */
		ret = btrfs_wq_submit_bio(BTRFS_I(inode)->root->fs_info,
				   inode, rw, bio, mirror_num,
				   bio_flags, bio_offset,
				   __btrfs_submit_bio_start,
				   __btrfs_submit_bio_done);
#endif /* MY_DEF_HERE */
		goto out;
	} else if (!skip_sum) {
		ret = btrfs_csum_one_bio(root, inode, bio, 0, 0);
		if (ret)
			goto out;
	}

mapit:
	ret = btrfs_map_bio(root, rw, bio, mirror_num, 0);

out:
	if (ret < 0)
		bio_endio(bio, ret);
	return ret;
}

/*
 * given a list of ordered sums record them in the inode.  This happens
 * at IO completion time based on sums calculated at bio submission time.
 */
static noinline int add_pending_csums(struct btrfs_trans_handle *trans,
			     struct inode *inode, u64 file_offset,
			     struct list_head *list)
{
	struct btrfs_ordered_sum *sum;

	list_for_each_entry(sum, list, list) {
		trans->adding_csums = 1;
		btrfs_csum_file_blocks(trans,
		       BTRFS_I(inode)->root->fs_info->csum_root, sum);
		trans->adding_csums = 0;
	}
	return 0;
}

int btrfs_set_extent_delalloc(struct inode *inode, u64 start, u64 end,
			      struct extent_state **cached_state)
{
	WARN_ON((end & (PAGE_CACHE_SIZE - 1)) == 0);
	return set_extent_delalloc(&BTRFS_I(inode)->io_tree, start, end,
				   cached_state, GFP_NOFS);
}

/* see btrfs_writepage_start_hook for details on why this is required */
struct btrfs_writepage_fixup {
	struct page *page;
	struct btrfs_work work;
};

static void btrfs_writepage_fixup_worker(struct btrfs_work *work)
{
	struct btrfs_writepage_fixup *fixup;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	struct page *page;
	struct inode *inode;
	u64 page_start;
	u64 page_end;
	int ret;

	fixup = container_of(work, struct btrfs_writepage_fixup, work);
	page = fixup->page;
again:
	lock_page(page);
	if (!page->mapping || !PageDirty(page) || !PageChecked(page)) {
		ClearPageChecked(page);
		goto out_page;
	}

	inode = page->mapping->host;
	page_start = page_offset(page);
	page_end = page_offset(page) + PAGE_CACHE_SIZE - 1;

	lock_extent_bits(&BTRFS_I(inode)->io_tree, page_start, page_end, 0,
			 &cached_state);

	/* already ordered? We're done */
	if (PagePrivate2(page))
		goto out;

	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		unlock_extent_cached(&BTRFS_I(inode)->io_tree, page_start,
				     page_end, &cached_state, GFP_NOFS);
		unlock_page(page);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
		goto again;
	}

	ret = btrfs_delalloc_reserve_space(inode, PAGE_CACHE_SIZE);
	if (ret) {
		mapping_set_error(page->mapping, ret);
		end_extent_writepage(page, ret, page_start, page_end);
		ClearPageChecked(page);
		goto out;
	 }

	btrfs_set_extent_delalloc(inode, page_start, page_end, &cached_state);
	ClearPageChecked(page);
	set_page_dirty(page);
out:
	unlock_extent_cached(&BTRFS_I(inode)->io_tree, page_start, page_end,
			     &cached_state, GFP_NOFS);
out_page:
	unlock_page(page);
	page_cache_release(page);
	kfree(fixup);
}

/*
 * There are a few paths in the higher layers of the kernel that directly
 * set the page dirty bit without asking the filesystem if it is a
 * good idea.  This causes problems because we want to make sure COW
 * properly happens and the data=ordered rules are followed.
 *
 * In our case any range that doesn't have the ORDERED bit set
 * hasn't been properly setup for IO.  We kick off an async process
 * to fix it up.  The async helper will wait for ordered extents, set
 * the delalloc bit and make it safe to write the page.
 */
static int btrfs_writepage_start_hook(struct page *page, u64 start, u64 end)
{
	struct inode *inode = page->mapping->host;
	struct btrfs_writepage_fixup *fixup;
	struct btrfs_root *root = BTRFS_I(inode)->root;

	/* this page is properly in the ordered list */
	if (TestClearPagePrivate2(page))
		return 0;

	if (PageChecked(page))
		return -EAGAIN;

	fixup = kzalloc(sizeof(*fixup), GFP_NOFS);
	if (!fixup)
		return -EAGAIN;

	SetPageChecked(page);
	page_cache_get(page);
	btrfs_init_work(&fixup->work, btrfs_fixup_helper,
			btrfs_writepage_fixup_worker, NULL, NULL);
	fixup->page = page;
	btrfs_queue_work(root->fs_info->fixup_workers, &fixup->work);
	return -EBUSY;
}

static int insert_reserved_file_extent(struct btrfs_trans_handle *trans,
				       struct inode *inode, u64 file_pos,
				       u64 disk_bytenr, u64 disk_num_bytes,
				       u64 num_bytes, u64 ram_bytes,
				       u8 compression, u8 encryption,
				       u16 other_encoding, int extent_type)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_file_extent_item *fi;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_key ins;
	int extent_inserted = 0;
	int ret;
#ifdef MY_DEF_HERE
	int syno_usage;
#endif /* MY_DEF_HERE */

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	/*
	 * we may be replacing one extent in the tree with another.
	 * The new extent is pinned in the extent map, and we don't want
	 * to drop it from the cache until it is completely in the btree.
	 *
	 * So, tell btrfs_drop_extents to leave this extent in the cache.
	 * the caller is expected to unpin it and allow it to be merged
	 * with the others.
	 */
	ret = __btrfs_drop_extents(trans, root, inode, path, file_pos,
#ifdef MY_DEF_HERE
				   file_pos + num_bytes, NULL, NULL, NULL, NULL, 0,
#else
				   file_pos + num_bytes, NULL, 0,
#endif /* MY_DEF_HERE */
				   1, sizeof(*fi), &extent_inserted);
	if (ret)
		goto out;

	if (!extent_inserted) {
		ins.objectid = btrfs_ino(inode);
		ins.offset = file_pos;
		ins.type = BTRFS_EXTENT_DATA_KEY;

		path->leave_spinning = 1;
		ret = btrfs_insert_empty_item(trans, root, path, &ins,
					      sizeof(*fi));
		if (ret)
			goto out;
	}
	leaf = path->nodes[0];
	fi = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	btrfs_set_file_extent_generation(leaf, fi, trans->transid);
	btrfs_set_file_extent_type(leaf, fi, extent_type);
	btrfs_set_file_extent_disk_bytenr(leaf, fi, disk_bytenr);
	btrfs_set_file_extent_disk_num_bytes(leaf, fi, disk_num_bytes);
	btrfs_set_file_extent_offset(leaf, fi, 0);
	btrfs_set_file_extent_num_bytes(leaf, fi, num_bytes);
	btrfs_set_file_extent_ram_bytes(leaf, fi, ram_bytes);
	btrfs_set_file_extent_compression(leaf, fi, compression);
	btrfs_set_file_extent_encryption(leaf, fi, encryption);
	btrfs_set_file_extent_other_encoding(leaf, fi, other_encoding);

	btrfs_mark_buffer_dirty(leaf);

#ifdef MY_DEF_HERE
	syno_usage = btrfs_syno_usage_ref_check(root, btrfs_ino(inode), file_pos);
#endif /* MY_DEF_HERE */

	btrfs_release_path(path);

	inode_add_bytes(inode, num_bytes);

	ins.objectid = disk_bytenr;
	ins.offset = disk_num_bytes;
	ins.type = BTRFS_EXTENT_ITEM_KEY;
	ret = btrfs_alloc_reserved_file_extent(trans, root,
					root->root_key.objectid,
					btrfs_ino(inode), file_pos,
					&ins
#ifdef MY_DEF_HERE
					,ram_bytes
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
					,inode, i_uid_read(inode)
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
					,syno_usage
#endif /* MY_DEF_HERE */
					);
out:
	btrfs_free_path(path);

	return ret;
}

/* snapshot-aware defrag */
struct sa_defrag_extent_backref {
	struct rb_node node;
	struct old_sa_defrag_extent *old;
	u64 root_id;
	u64 inum;
	u64 file_pos;
	u64 extent_offset;
	u64 num_bytes;
	u64 generation;
};

struct old_sa_defrag_extent {
	struct list_head list;
	struct new_sa_defrag_extent *new;

	u64 extent_offset;
	u64 bytenr;
	u64 offset;
	u64 len;
	int count;
};

struct new_sa_defrag_extent {
	struct rb_root root;
	struct list_head head;
	struct btrfs_path *path;
	struct inode *inode;
	u64 file_pos;
	u64 len;
	u64 bytenr;
	u64 disk_len;
	u8 compress_type;
};

static int backref_comp(struct sa_defrag_extent_backref *b1,
			struct sa_defrag_extent_backref *b2)
{
	if (b1->root_id < b2->root_id)
		return -1;
	else if (b1->root_id > b2->root_id)
		return 1;

	if (b1->inum < b2->inum)
		return -1;
	else if (b1->inum > b2->inum)
		return 1;

	if (b1->file_pos < b2->file_pos)
		return -1;
	else if (b1->file_pos > b2->file_pos)
		return 1;

	/*
	 * [------------------------------] ===> (a range of space)
	 *     |<--->|   |<---->| =============> (fs/file tree A)
	 * |<---------------------------->| ===> (fs/file tree B)
	 *
	 * A range of space can refer to two file extents in one tree while
	 * refer to only one file extent in another tree.
	 *
	 * So we may process a disk offset more than one time(two extents in A)
	 * and locate at the same extent(one extent in B), then insert two same
	 * backrefs(both refer to the extent in B).
	 */
	return 0;
}

static void backref_insert(struct rb_root *root,
			   struct sa_defrag_extent_backref *backref)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct sa_defrag_extent_backref *entry;
	int ret;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct sa_defrag_extent_backref, node);

		ret = backref_comp(backref, entry);
		if (ret < 0)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&backref->node, parent, p);
	rb_insert_color(&backref->node, root);
}

/*
 * Note the backref might has changed, and in this case we just return 0.
 */
static noinline int record_one_backref(u64 inum, u64 offset, u64 root_id,
				       void *ctx)
{
	struct btrfs_file_extent_item *extent;
	struct btrfs_fs_info *fs_info;
	struct old_sa_defrag_extent *old = ctx;
	struct new_sa_defrag_extent *new = old->new;
	struct btrfs_path *path = new->path;
	struct btrfs_key key;
	struct btrfs_root *root;
	struct sa_defrag_extent_backref *backref;
	struct extent_buffer *leaf;
	struct inode *inode = new->inode;
	int slot;
	int ret;
	u64 extent_offset;
	u64 num_bytes;

	if (BTRFS_I(inode)->root->root_key.objectid == root_id &&
	    inum == btrfs_ino(inode))
		return 0;

	key.objectid = root_id;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	fs_info = BTRFS_I(inode)->root->fs_info;
	root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(root)) {
		if (PTR_ERR(root) == -ENOENT)
			return 0;
		WARN_ON(1);
		pr_debug("inum=%llu, offset=%llu, root_id=%llu\n",
			 inum, offset, root_id);
		return PTR_ERR(root);
	}

	key.objectid = inum;
	key.type = BTRFS_EXTENT_DATA_KEY;
	if (offset > (u64)-1 << 32)
		key.offset = 0;
	else
		key.offset = offset;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (WARN_ON(ret < 0))
		return ret;
	ret = 0;

	while (1) {
		cond_resched();

		leaf = path->nodes[0];
		slot = path->slots[0];

		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				goto out;
			} else if (ret > 0) {
				ret = 0;
				goto out;
			}
			continue;
		}

		path->slots[0]++;

		btrfs_item_key_to_cpu(leaf, &key, slot);

		if (key.objectid > inum)
			goto out;

		if (key.objectid < inum || key.type != BTRFS_EXTENT_DATA_KEY)
			continue;

		extent = btrfs_item_ptr(leaf, slot,
					struct btrfs_file_extent_item);

		if (btrfs_file_extent_disk_bytenr(leaf, extent) != old->bytenr)
			continue;

		/*
		 * 'offset' refers to the exact key.offset,
		 * NOT the 'offset' field in btrfs_extent_data_ref, ie.
		 * (key.offset - extent_offset).
		 */
		if (key.offset != offset)
			continue;

		extent_offset = btrfs_file_extent_offset(leaf, extent);
		num_bytes = btrfs_file_extent_num_bytes(leaf, extent);

		if (extent_offset >= old->extent_offset + old->offset +
		    old->len || extent_offset + num_bytes <=
		    old->extent_offset + old->offset)
			continue;
		break;
	}

	backref = kmalloc(sizeof(*backref), GFP_NOFS);
	if (!backref) {
		ret = -ENOENT;
		goto out;
	}

	backref->root_id = root_id;
	backref->inum = inum;
	backref->file_pos = offset;
	backref->num_bytes = num_bytes;
	backref->extent_offset = extent_offset;
	backref->generation = btrfs_file_extent_generation(leaf, extent);
	backref->old = old;
	backref_insert(&new->root, backref);
	old->count++;
out:
	btrfs_release_path(path);
	WARN_ON(ret);
	return ret;
}

static noinline bool record_extent_backrefs(struct btrfs_path *path,
				   struct new_sa_defrag_extent *new)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(new->inode)->root->fs_info;
	struct old_sa_defrag_extent *old, *tmp;
	int ret;

	new->path = path;

	list_for_each_entry_safe(old, tmp, &new->head, list) {
		ret = iterate_inodes_from_logical(old->bytenr +
						  old->extent_offset, fs_info,
						  path, record_one_backref,
						  old);
		if (ret < 0 && ret != -ENOENT)
			return false;

		/* no backref to be processed for this extent */
		if (!old->count) {
			list_del(&old->list);
			kfree(old);
		}
	}

	if (list_empty(&new->head))
		return false;

	return true;
}

static int relink_is_mergable(struct extent_buffer *leaf,
			      struct btrfs_file_extent_item *fi,
			      struct new_sa_defrag_extent *new)
{
	if (btrfs_file_extent_disk_bytenr(leaf, fi) != new->bytenr)
		return 0;

	if (btrfs_file_extent_type(leaf, fi) != BTRFS_FILE_EXTENT_REG)
		return 0;

	if (btrfs_file_extent_compression(leaf, fi) != new->compress_type)
		return 0;

	if (btrfs_file_extent_encryption(leaf, fi) ||
	    btrfs_file_extent_other_encoding(leaf, fi))
		return 0;

	return 1;
}

/*
 * Note the backref might has changed, and in this case we just return 0.
 */
static noinline int relink_extent_backref(struct btrfs_path *path,
				 struct sa_defrag_extent_backref *prev,
				 struct sa_defrag_extent_backref *backref)
{
	struct btrfs_file_extent_item *extent;
	struct btrfs_file_extent_item *item;
	struct btrfs_ordered_extent *ordered;
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info;
	struct btrfs_root *root;
	struct btrfs_key key;
	struct extent_buffer *leaf;
	struct old_sa_defrag_extent *old = backref->old;
	struct new_sa_defrag_extent *new = old->new;
	struct inode *src_inode = new->inode;
	struct inode *inode;
	struct extent_state *cached = NULL;
	int ret = 0;
	u64 start;
	u64 len;
	u64 lock_start;
	u64 lock_end;
	bool merge = false;
	int index;
#ifdef MY_DEF_HERE
	int syno_usage;
#endif /* MY_DEF_HERE */

	if (prev && prev->root_id == backref->root_id &&
	    prev->inum == backref->inum &&
	    prev->file_pos + prev->num_bytes == backref->file_pos)
		merge = true;

	/* step 1: get root */
	key.objectid = backref->root_id;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	fs_info = BTRFS_I(src_inode)->root->fs_info;
	index = srcu_read_lock(&fs_info->subvol_srcu);

	root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, index);
		if (PTR_ERR(root) == -ENOENT)
			return 0;
		return PTR_ERR(root);
	}

	if (btrfs_root_readonly(root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, index);
		return 0;
	}
#ifdef MY_DEF_HERE
	btrfs_hold_fs_root(root);
	srcu_read_unlock(&fs_info->subvol_srcu, index);
#endif /* MY_DEF_HERE */

	/* step 2: get inode */
	key.objectid = backref->inum;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;

	inode = btrfs_iget(fs_info->sb, &key, root, NULL);
#ifdef MY_DEF_HERE
	btrfs_release_fs_root(root);
	if (IS_ERR(inode))
		return 0;
#else
	if (IS_ERR(inode)) {
		srcu_read_unlock(&fs_info->subvol_srcu, index);
		return 0;
	}

	srcu_read_unlock(&fs_info->subvol_srcu, index);
#endif /* MY_DEF_HERE */

	/* step 3: relink backref */
	lock_start = backref->file_pos;
	lock_end = backref->file_pos + backref->num_bytes - 1;
	lock_extent_bits(&BTRFS_I(inode)->io_tree, lock_start, lock_end,
			 0, &cached);

	ordered = btrfs_lookup_first_ordered_extent(inode, lock_end);
	if (ordered) {
		btrfs_put_ordered_extent(ordered);
		goto out_unlock;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_unlock;
	}

	key.objectid = backref->inum;
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = backref->file_pos;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0) {
		goto out_free_path;
	} else if (ret > 0) {
		ret = 0;
		goto out_free_path;
	}

	extent = btrfs_item_ptr(path->nodes[0], path->slots[0],
				struct btrfs_file_extent_item);

	if (btrfs_file_extent_generation(path->nodes[0], extent) !=
	    backref->generation)
		goto out_free_path;

	btrfs_release_path(path);

	start = backref->file_pos;
	if (backref->extent_offset < old->extent_offset + old->offset)
		start += old->extent_offset + old->offset -
			 backref->extent_offset;

	len = min(backref->extent_offset + backref->num_bytes,
		  old->extent_offset + old->offset + old->len);
	len -= max(backref->extent_offset, old->extent_offset + old->offset);

	ret = btrfs_drop_extents(trans, root, inode, start,
				 start + len, 1);
	if (ret)
		goto out_free_path;
again:
	key.objectid = btrfs_ino(inode);
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = start;

	path->leave_spinning = 1;
	if (merge) {
		struct btrfs_file_extent_item *fi;
		u64 extent_len;
		struct btrfs_key found_key;

		ret = btrfs_search_slot(trans, root, &key, path, 0, 1);
		if (ret < 0)
			goto out_free_path;

		path->slots[0]--;
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

		fi = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_file_extent_item);
		extent_len = btrfs_file_extent_num_bytes(leaf, fi);

		if (extent_len + found_key.offset == start &&
		    relink_is_mergable(leaf, fi, new)) {
			btrfs_set_file_extent_num_bytes(leaf, fi,
							extent_len + len);
			btrfs_mark_buffer_dirty(leaf);
			inode_add_bytes(inode, len);

			ret = 1;
			goto out_free_path;
		} else {
			merge = false;
			btrfs_release_path(path);
			goto again;
		}
	}

	ret = btrfs_insert_empty_item(trans, root, path, &key,
					sizeof(*extent));
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_free_path;
	}

	leaf = path->nodes[0];
	item = btrfs_item_ptr(leaf, path->slots[0],
				struct btrfs_file_extent_item);
	btrfs_set_file_extent_disk_bytenr(leaf, item, new->bytenr);
	btrfs_set_file_extent_disk_num_bytes(leaf, item, new->disk_len);
	btrfs_set_file_extent_offset(leaf, item, start - new->file_pos);
	btrfs_set_file_extent_num_bytes(leaf, item, len);
	btrfs_set_file_extent_ram_bytes(leaf, item, new->len);
	btrfs_set_file_extent_generation(leaf, item, trans->transid);
	btrfs_set_file_extent_type(leaf, item, BTRFS_FILE_EXTENT_REG);
	btrfs_set_file_extent_compression(leaf, item, new->compress_type);
	btrfs_set_file_extent_encryption(leaf, item, 0);
	btrfs_set_file_extent_other_encoding(leaf, item, 0);

	btrfs_mark_buffer_dirty(leaf);
	inode_add_bytes(inode, len);
#ifdef MY_DEF_HERE
	syno_usage = btrfs_syno_usage_ref_check(root, key.objectid, key.offset);
#endif /* MY_DEF_HERE */
	btrfs_release_path(path);

#ifdef MY_DEF_HERE
	ret = btrfs_inc_extent_ref_uid(trans, root, new->bytenr,
			new->disk_len, 0,
			backref->root_id, backref->inum,
			new->file_pos, 0, new->len, /* start - extent_offset */
			inode, i_uid_read(inode)
#ifdef MY_DEF_HERE
			,syno_usage
#endif /* MY_DEF_HERE */
			);
#else
	ret = btrfs_inc_extent_ref(trans, root, new->bytenr,
			new->disk_len, 0,
			backref->root_id, backref->inum,
			new->file_pos,	/* start - extent_offset */
			0
#ifdef MY_DEF_HERE
			,new->len
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
			,syno_usage
#endif /* MY_DEF_HERE */
			)
#endif /* MY_DEF_HERE */
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_free_path;
	}

	ret = 1;
out_free_path:
	btrfs_release_path(path);
	path->leave_spinning = 0;
	btrfs_end_transaction(trans, root);
out_unlock:
	unlock_extent_cached(&BTRFS_I(inode)->io_tree, lock_start, lock_end,
			     &cached, GFP_NOFS);
	iput(inode);
	return ret;
}

static void free_sa_defrag_extent(struct new_sa_defrag_extent *new)
{
	struct old_sa_defrag_extent *old, *tmp;

	if (!new)
		return;

	list_for_each_entry_safe(old, tmp, &new->head, list) {
		list_del(&old->list);
		kfree(old);
	}
	kfree(new);
}

static void relink_file_extents(struct new_sa_defrag_extent *new)
{
	struct btrfs_path *path;
	struct sa_defrag_extent_backref *backref;
	struct sa_defrag_extent_backref *prev = NULL;
	struct inode *inode;
	struct btrfs_root *root;
	struct rb_node *node;
	int ret;

	inode = new->inode;
	root = BTRFS_I(inode)->root;

	path = btrfs_alloc_path();
	if (!path)
		return;

	if (!record_extent_backrefs(path, new)) {
		btrfs_free_path(path);
		goto out;
	}
	btrfs_release_path(path);

	while (1) {
		node = rb_first(&new->root);
		if (!node)
			break;
		rb_erase(node, &new->root);

		backref = rb_entry(node, struct sa_defrag_extent_backref, node);

		ret = relink_extent_backref(path, prev, backref);
		WARN_ON(ret < 0);

		kfree(prev);

		if (ret == 1)
			prev = backref;
		else
			prev = NULL;
		cond_resched();
	}
	kfree(prev);

	btrfs_free_path(path);
out:
	free_sa_defrag_extent(new);

	atomic_dec(&root->fs_info->defrag_running);
	wake_up(&root->fs_info->transaction_wait);
}

static struct new_sa_defrag_extent *
record_old_file_extents(struct inode *inode,
			struct btrfs_ordered_extent *ordered)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct old_sa_defrag_extent *old;
	struct new_sa_defrag_extent *new;
	int ret;

	new = kmalloc(sizeof(*new), GFP_NOFS);
	if (!new)
		return NULL;

	new->inode = inode;
	new->file_pos = ordered->file_offset;
	new->len = ordered->len;
	new->bytenr = ordered->start;
	new->disk_len = ordered->disk_len;
	new->compress_type = ordered->compress_type;
	new->root = RB_ROOT;
	INIT_LIST_HEAD(&new->head);

	path = btrfs_alloc_path();
	if (!path)
		goto out_kfree;

	key.objectid = btrfs_ino(inode);
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = new->file_pos;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out_free_path;
	if (ret > 0 && path->slots[0] > 0)
		path->slots[0]--;

	/* find out all the old extents for the file range */
	while (1) {
		struct btrfs_file_extent_item *extent;
		struct extent_buffer *l;
		int slot;
		u64 num_bytes;
		u64 offset;
		u64 end;
		u64 disk_bytenr;
		u64 extent_offset;

		l = path->nodes[0];
		slot = path->slots[0];

		if (slot >= btrfs_header_nritems(l)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto out_free_path;
			else if (ret > 0)
				break;
			continue;
		}

		btrfs_item_key_to_cpu(l, &key, slot);

		if (key.objectid != btrfs_ino(inode))
			break;
		if (key.type != BTRFS_EXTENT_DATA_KEY)
			break;
		if (key.offset >= new->file_pos + new->len)
			break;

		extent = btrfs_item_ptr(l, slot, struct btrfs_file_extent_item);

		num_bytes = btrfs_file_extent_num_bytes(l, extent);
		if (key.offset + num_bytes < new->file_pos)
			goto next;

		disk_bytenr = btrfs_file_extent_disk_bytenr(l, extent);
		if (!disk_bytenr)
			goto next;

		extent_offset = btrfs_file_extent_offset(l, extent);

		old = kmalloc(sizeof(*old), GFP_NOFS);
		if (!old)
			goto out_free_path;

		offset = max(new->file_pos, key.offset);
		end = min(new->file_pos + new->len, key.offset + num_bytes);

		old->bytenr = disk_bytenr;
		old->extent_offset = extent_offset;
		old->offset = offset - key.offset;
		old->len = end - offset;
		old->new = new;
		old->count = 0;
		list_add_tail(&old->list, &new->head);
next:
		path->slots[0]++;
		cond_resched();
	}

	btrfs_free_path(path);
	atomic_inc(&root->fs_info->defrag_running);

	return new;

out_free_path:
	btrfs_free_path(path);
out_kfree:
	free_sa_defrag_extent(new);
	return NULL;
}

static void btrfs_release_delalloc_bytes(struct btrfs_root *root,
					 u64 start, u64 len)
{
	struct btrfs_block_group_cache *cache;

	cache = btrfs_lookup_block_group(root->fs_info, start);
	ASSERT(cache);

	spin_lock(&cache->lock);
	cache->delalloc_bytes -= len;
	spin_unlock(&cache->lock);

	btrfs_put_block_group(cache);
}

/* as ordered data IO finishes, this gets called so we can finish
 * an ordered extent if the range of bytes in the file it covers are
 * fully written.
 */
static int btrfs_finish_ordered_io(struct btrfs_ordered_extent *ordered_extent)
{
	struct inode *inode = ordered_extent->inode;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans = NULL;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_state *cached_state = NULL;
	struct new_sa_defrag_extent *new = NULL;
	int compress_type = 0;
	int ret = 0;
	u64 logical_len = ordered_extent->len;
	bool nolock;
	bool truncated = false;
#ifdef MY_DEF_HERE
	bool need_quota_add_delay = false;
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	bool bl_throttle = true;
#endif /* MY_DEF_HERE */

	nolock = btrfs_is_free_space_inode(inode);

#ifdef MY_DEF_HERE
#ifdef MY_DEF_HERE
	if (ordered_extent->high_priority)
		bl_throttle = false;
#endif /* MY_DEF_HERE */
#endif /* MY_DEF_HERE */

	if (test_bit(BTRFS_ORDERED_IOERR, &ordered_extent->flags)) {
		ret = -EIO;
		goto out;
	}

	btrfs_free_io_failure_record(inode, ordered_extent->file_offset,
				     ordered_extent->file_offset +
				     ordered_extent->len - 1);

	if (test_bit(BTRFS_ORDERED_TRUNCATED, &ordered_extent->flags)) {
		truncated = true;
		logical_len = ordered_extent->truncated_len;
		/* Truncated the entire extent, don't bother adding */
		if (!logical_len)
			goto out;
	}

	if (test_bit(BTRFS_ORDERED_NOCOW, &ordered_extent->flags)) {
		BUG_ON(!list_empty(&ordered_extent->list)); /* Logic error */
		btrfs_ordered_update_i_size(inode, 0, ordered_extent);
		if (nolock)
			trans = btrfs_join_transaction_nolock(root);
		else
			trans = btrfs_join_transaction(root);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			trans = NULL;
			goto out;
		}
		trans->block_rsv = &root->fs_info->delalloc_block_rsv;
		ret = btrfs_update_inode_fallback(trans, root, inode);
		if (ret) /* -ENOMEM or corruption */
			btrfs_abort_transaction(trans, root, ret);
#ifdef MY_DEF_HERE
		bl_throttle = false;
#endif /* MY_DEF_HERE */
		goto out;
	}

	lock_extent_bits(io_tree, ordered_extent->file_offset,
			 ordered_extent->file_offset + ordered_extent->len - 1,
			 0, &cached_state);

	ret = test_range_bit(io_tree, ordered_extent->file_offset,
			ordered_extent->file_offset + ordered_extent->len - 1,
			EXTENT_DEFRAG, 1, cached_state);
	if (ret) {
		u64 last_snapshot = btrfs_root_last_snapshot(&root->root_item);
		if (0 && last_snapshot >= BTRFS_I(inode)->generation)
			/* the inode is shared */
			new = record_old_file_extents(inode, ordered_extent);

		clear_extent_bit(io_tree, ordered_extent->file_offset,
			ordered_extent->file_offset + ordered_extent->len - 1,
			EXTENT_DEFRAG, 0, 0, &cached_state, GFP_NOFS);
	}

	if (nolock)
		trans = btrfs_join_transaction_nolock(root);
	else
		trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		trans = NULL;
		goto out_unlock;
	}

	trans->block_rsv = &root->fs_info->delalloc_block_rsv;

	if (test_bit(BTRFS_ORDERED_COMPRESSED, &ordered_extent->flags))
		compress_type = ordered_extent->compress_type;
	if (test_bit(BTRFS_ORDERED_PREALLOC, &ordered_extent->flags)) {
		BUG_ON(compress_type);
		ret = btrfs_mark_extent_written(trans, inode,
						ordered_extent->file_offset,
						ordered_extent->file_offset +
						logical_len);
	} else {
		BUG_ON(root == root->fs_info->tree_root);
		ret = insert_reserved_file_extent(trans, inode,
						ordered_extent->file_offset,
						ordered_extent->start,
						ordered_extent->disk_len,
						logical_len, logical_len,
						compress_type, 0, 0,
						BTRFS_FILE_EXTENT_REG);
		if (!ret)
			btrfs_release_delalloc_bytes(root,
						     ordered_extent->start,
						     ordered_extent->disk_len);
#ifdef MY_DEF_HERE
		if (!ret)
			need_quota_add_delay = true;
#endif /* MY_DEF_HERE */
	}
	unpin_extent_cache(&BTRFS_I(inode)->extent_tree,
			   ordered_extent->file_offset, ordered_extent->len,
			   trans->transid);
	if (ret < 0) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_unlock;
	}


	add_pending_csums(trans, inode, ordered_extent->file_offset,
			  &ordered_extent->list);

	btrfs_ordered_update_i_size(inode, 0, ordered_extent);
	ret = btrfs_update_inode_fallback(trans, root, inode);
	if (ret) { /* -ENOMEM or corruption */
		btrfs_abort_transaction(trans, root, ret);
		goto out_unlock;
	}
	ret = 0;
out_unlock:
	unlock_extent_cached(io_tree, ordered_extent->file_offset,
			     ordered_extent->file_offset +
			     ordered_extent->len - 1, &cached_state, GFP_NOFS);
out:
#ifdef MY_DEF_HERE
	if (root != root->fs_info->tree_root) {
		if (need_quota_add_delay)
			btrfs_delalloc_release_metadata_add_delay(inode, ordered_extent->len);
		else
			btrfs_delalloc_release_metadata(inode, ordered_extent->len);
	}
#else
	if (root != root->fs_info->tree_root)
		btrfs_delalloc_release_metadata(inode, ordered_extent->len);
#endif /* MY_DEF_HERE */
	if (trans)
		btrfs_end_transaction(trans, root);

	if (ret || truncated) {
		u64 start, end;

		if (truncated)
			start = ordered_extent->file_offset + logical_len;
		else
			start = ordered_extent->file_offset;
		end = ordered_extent->file_offset + ordered_extent->len - 1;
		clear_extent_uptodate(io_tree, start, end, NULL, GFP_NOFS);

		/* Drop the cache for the part of the extent we didn't write. */
		btrfs_drop_extent_cache(inode, start, end, 0);

		/*
		 * If the ordered extent had an IOERR or something else went
		 * wrong we need to return the space for this ordered extent
		 * back to the allocator.  We only free the extent in the
		 * truncated case if we didn't write out the extent at all.
		 */
		if ((ret || !logical_len) &&
		    !test_bit(BTRFS_ORDERED_NOCOW, &ordered_extent->flags) &&
		    !test_bit(BTRFS_ORDERED_PREALLOC, &ordered_extent->flags))
			btrfs_free_reserved_extent(root, ordered_extent->start,
						   ordered_extent->disk_len, 1);
	}


	/*
	 * This needs to be done to make sure anybody waiting knows we are done
	 * updating everything for this ordered extent.
	 */
	btrfs_remove_ordered_extent(inode, ordered_extent);

	/* for snapshot-aware defrag */
	if (new) {
		if (ret) {
			free_sa_defrag_extent(new);
			atomic_dec(&root->fs_info->defrag_running);
		} else {
			relink_file_extents(new);
		}
	}

	/* once for us */
	btrfs_put_ordered_extent(ordered_extent);
	/* once for the tree */
	btrfs_put_ordered_extent(ordered_extent);

#ifdef MY_DEF_HERE
	if (bl_throttle && !ret && !nolock)
		btrfs_syno_btree_balance_dirty(root->fs_info, false);
#endif /* MY_DEF_HERE */

	return ret;
}

static void finish_ordered_fn(struct btrfs_work *work)
{
	struct btrfs_ordered_extent *ordered_extent;
	ordered_extent = container_of(work, struct btrfs_ordered_extent, work);
	btrfs_finish_ordered_io(ordered_extent);
}

static int btrfs_writepage_end_io_hook(struct page *page, u64 start, u64 end,
				struct extent_state *state, int uptodate)
{
	struct inode *inode = page->mapping->host;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ordered_extent *ordered_extent = NULL;
	struct btrfs_workqueue *wq;
	btrfs_work_func_t func;

	trace_btrfs_writepage_end_io_hook(page, start, end, uptodate);

	ClearPagePrivate2(page);
	if (!btrfs_dec_test_ordered_pending(inode, &ordered_extent, start,
					    end - start + 1, uptodate))
		return 0;

	if (btrfs_is_free_space_inode(inode)) {
		wq = root->fs_info->endio_freespace_worker;
		func = btrfs_freespace_write_helper;
#ifdef MY_DEF_HERE
	} else if (test_bit(BTRFS_ORDERED_SYNC, &ordered_extent->flags)) {
		wq = root->fs_info->endio_write_sync_workers;
		func = btrfs_endio_write_sync_helper;
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	} else if (ordered_extent->high_priority) {
		wq = root->fs_info->syno_high_priority_endio_workers;
		func = btrfs_syno_high_priority_endio_helper;
		set_bit(BTRFS_ORDERED_HIGH_PRIORITY, &ordered_extent->flags);
	} else if (test_bit(BTRFS_ORDERED_NOCOW, &ordered_extent->flags)) {
		wq = root->fs_info->syno_nocow_endio_workers;
		func = btrfs_syno_nocow_endio_helper;
#endif /* MY_DEF_HERE */
	} else {
		wq = root->fs_info->endio_write_workers;
		func = btrfs_endio_write_helper;
	}

	btrfs_init_work(&ordered_extent->work, func, finish_ordered_fn, NULL,
			NULL);
#ifdef MY_DEF_HERE
	if (!btrfs_is_free_space_inode(inode)) {
		set_bit(BTRFS_ORDERED_WORK_INITIALIZED, &ordered_extent->flags);
		if (ordered_extent->high_priority)
			btrfs_set_work_high_priority(&ordered_extent->work);
	}
#endif /* MY_DEF_HERE */
	btrfs_queue_work(wq, &ordered_extent->work);

	return 0;
}

/*
 * when reads are done, we need to check csums to verify the data is correct
 * if there's a match, we allow the bio to finish.  If not, the code in
 * extent_io.c will try to find good copies for us.
 */
static int btrfs_readpage_end_io_hook(struct btrfs_io_bio *io_bio,
				      u64 phy_offset, struct page *page,
				      u64 start, u64 end, int mirror)
{
	size_t offset = start - page_offset(page);
	struct inode *inode = page->mapping->host;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	char *kaddr;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	u32 csum_expected;
	u32 csum = ~(u32)0;
	static DEFINE_RATELIMIT_STATE(_rs, DEFAULT_RATELIMIT_INTERVAL,
	                              DEFAULT_RATELIMIT_BURST);

	if (PageChecked(page)) {
		ClearPageChecked(page);
		goto good;
	}

	if (BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)
		goto good;

	if (root->root_key.objectid == BTRFS_DATA_RELOC_TREE_OBJECTID &&
	    test_range_bit(io_tree, start, end, EXTENT_NODATASUM, 1, NULL)) {
		clear_extent_bits(io_tree, start, end, EXTENT_NODATASUM,
				  GFP_NOFS);
		return 0;
	}

#ifdef MY_DEF_HERE
	if (unlikely(test_bit(BIO_CORRECTION_ERR, &io_bio->bio.bi_flags)))
		return -EIO;
#endif

	phy_offset >>= inode->i_sb->s_blocksize_bits;
	csum_expected = *(((u32 *)io_bio->csum) + phy_offset);

#if defined(MY_DEF_HERE)
	btrfs_csum_page_digest(page, offset, end - start + 1, &csum);
#else /* MY_DEF_HERE */
	kaddr = kmap_atomic(page);
	csum = btrfs_csum_data(kaddr + offset, csum,  end - start + 1);
	btrfs_csum_final(csum, (char *)&csum);
#endif /* MY_DEF_HERE */
	if (csum != csum_expected)
		goto zeroit;

#if defined(MY_DEF_HERE)
	// do nothing
#else /* MY_DEF_HERE */
	kunmap_atomic(kaddr);
#endif /* MY_DEF_HERE */
good:
	return 0;

zeroit:
#if defined(MY_DEF_HERE)
	kaddr = kmap_atomic(page);
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	if ((root->fs_info->correction_suppress_log == 1 && __ratelimit(&_rs))
			|| !root->fs_info->correction_suppress_log)
		btrfs_warn(root->fs_info, "csum failed ino %llu off %llu csum %u expected csum %u",
			btrfs_ino(page->mapping->host), start, csum, csum_expected);

	if (io_bio->nr_retry) {
		// See comments in volumes.h
		u32 *prev_bad_csum = ((u32*)(io_bio->csum_inline)) + 1;

		if (io_bio->nr_retry != 1 && *prev_bad_csum == csum)
			io_bio->nr_retry = BTRFS_BIO_SHOULD_ABORT_RETRY;
		else
			*prev_bad_csum = csum;
	} else if (root->fs_info->correction_disable == 1)
		csum_expected = 0;
#else
	if (__ratelimit(&_rs))
		btrfs_info(root->fs_info, "csum failed ino %llu off %llu csum %u expected csum %u",
			btrfs_ino(page->mapping->host), start, csum, csum_expected);
	memset(kaddr + offset, 1, end - start + 1);
	flush_dcache_page(page);
#endif
	kunmap_atomic(kaddr);
	if (csum_expected == 0)
		return 0;
	return -EIO;
}

struct delayed_iput {
	struct list_head list;
	struct inode *inode;
};

/* JDM: If this is fs-wide, why can't we add a pointer to
 * btrfs_inode instead and avoid the allocation? */
void btrfs_add_delayed_iput(struct inode *inode)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct delayed_iput *delayed;

	if (atomic_add_unless(&inode->i_count, -1, 1))
		return;

	delayed = kmalloc(sizeof(*delayed), GFP_NOFS | __GFP_NOFAIL);
	delayed->inode = inode;

	spin_lock(&fs_info->delayed_iput_lock);
	list_add_tail(&delayed->list, &fs_info->delayed_iputs);
	spin_unlock(&fs_info->delayed_iput_lock);
}

void btrfs_run_delayed_iputs(struct btrfs_root *root)
{
	LIST_HEAD(list);
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct delayed_iput *delayed;
	int empty;

	spin_lock(&fs_info->delayed_iput_lock);
	empty = list_empty(&fs_info->delayed_iputs);
	spin_unlock(&fs_info->delayed_iput_lock);
	if (empty)
		return;

	down_read(&fs_info->delayed_iput_sem);

	spin_lock(&fs_info->delayed_iput_lock);
	list_splice_init(&fs_info->delayed_iputs, &list);
	spin_unlock(&fs_info->delayed_iput_lock);

	while (!list_empty(&list)) {
		delayed = list_entry(list.next, struct delayed_iput, list);
		list_del(&delayed->list);
		iput(delayed->inode);
		kfree(delayed);
	}

	up_read(&root->fs_info->delayed_iput_sem);
}

/*
 * This creates an orphan entry for the given inode in case something goes wrong
 * in the middle of an unlink.
 */
int btrfs_orphan_add(struct btrfs_trans_handle *trans, struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	ret = btrfs_insert_orphan_item(trans, root, btrfs_ino(inode));
	if (ret && ret != -EEXIST) {
		btrfs_abort_transaction(trans, root, ret);
		return ret;
	}

	return 0;
}

/*
 * We have done the delete so we can go ahead and remove the orphan item for
 * this particular inode.
 */
static int btrfs_orphan_del(struct btrfs_trans_handle *trans,
			    struct inode *inode)
{
	return btrfs_del_orphan_item(trans, BTRFS_I(inode)->root, btrfs_ino(inode));
}

/*
 * this cleans up any orphans that may be left on the list from the last use
 * of this root.
 */
int btrfs_orphan_cleanup(struct btrfs_root *root)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_key key, found_key;
	struct btrfs_trans_handle *trans;
	struct inode *inode;
	u64 last_objectid = 0;
	int ret = 0, nr_unlink = 0;

	if (cmpxchg(&root->orphan_cleanup_state, 0, ORPHAN_CLEANUP_STARTED))
		return 0;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}
	path->reada = READA_BACK;

	key.objectid = BTRFS_ORPHAN_OBJECTID;
	btrfs_set_key_type(&key, BTRFS_ORPHAN_ITEM_KEY);
	key.offset = (u64)-1;

	while (1) {
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			goto out;

		/*
		 * if ret == 0 means we found what we were searching for, which
		 * is weird, but possible, so only screw with path if we didn't
		 * find the key and see if we have stuff that matches
		 */
		if (ret > 0) {
			ret = 0;
			if (path->slots[0] == 0)
				break;
			path->slots[0]--;
		}

		/* pull out the item */
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

		/* make sure the item matches what we want */
		if (found_key.objectid != BTRFS_ORPHAN_OBJECTID)
			break;
		if (btrfs_key_type(&found_key) != BTRFS_ORPHAN_ITEM_KEY)
			break;

		/* release the path since we're done with it */
		btrfs_release_path(path);

		/*
		 * this is where we are basically btrfs_lookup, without the
		 * crossing root thing.  we store the inode number in the
		 * offset of the orphan item.
		 */

		if (found_key.offset == last_objectid) {
			btrfs_err(root->fs_info,
				"Error removing orphan entry, stopping orphan cleanup");
			ret = -EINVAL;
			goto out;
		}

		last_objectid = found_key.offset;

		found_key.objectid = found_key.offset;
		found_key.type = BTRFS_INODE_ITEM_KEY;
		found_key.offset = 0;
		inode = btrfs_iget(root->fs_info->sb, &found_key, root, NULL);
		ret = PTR_RET(inode);
		if (ret && ret != -ENOENT)
			goto out;

		if (ret == -ENOENT && root == root->fs_info->tree_root) {
			struct btrfs_root *dead_root;
			struct btrfs_fs_info *fs_info = root->fs_info;
			int is_dead_root = 0;

			/*
			 * this is an orphan in the tree root. Currently these
			 * could come from 2 sources:
			 *  a) a snapshot deletion in progress
			 *  b) a free space cache inode
			 * We need to distinguish those two, as the snapshot
			 * orphan must not get deleted.
			 * find_dead_roots already ran before us, so if this
			 * is a snapshot deletion, we should find the root
			 * in the dead_roots list
			 */

#ifdef MY_DEF_HERE
			spin_lock(&fs_info->fs_roots_radix_lock);
			dead_root = radix_tree_lookup(&fs_info->fs_roots_radix,
				 (unsigned long)found_key.objectid);
			if (dead_root && btrfs_root_refs(&dead_root->root_item) == 0)
				is_dead_root = 1;
			spin_unlock(&fs_info->fs_roots_radix_lock);
#else
			spin_lock(&fs_info->trans_lock);
			list_for_each_entry(dead_root, &fs_info->dead_roots,
					    root_list) {
				if (dead_root->root_key.objectid ==
				    found_key.objectid) {
					is_dead_root = 1;
					break;
				}
			}
			spin_unlock(&fs_info->trans_lock);
#endif /* MY_DEF_HERE */
			if (is_dead_root) {
				/* prevent this orphan from being found again */
				key.offset = found_key.objectid - 1;
				continue;
			}

		}

		/*
		 * If we have an inode with links, there are a couple of
		 * possibilities. Old kernels (before v3.12) used to create an
		 * orphan item for truncate indicating that there were possibly
		 * extent items past i_size that needed to be deleted. In v3.12,
		 * truncate was changed to update i_size in sync with the extent
		 * items, but the (useless) orphan item was still created. Since
		 * v4.18, we don't create the orphan item for truncate at all.
		 *
		 * So, this item could mean that we need to do a truncate, but
		 * only if this filesystem was last used on a pre-v3.12 kernel
		 * and was not cleanly unmounted. The odds of that are quite
		 * slim, and it's a pain to do the truncate now, so just delete
		 * the orphan item.
		 *
		 * It's also possible that this orphan item was supposed to be
		 * deleted but wasn't. The inode number may have been reused,
		 * but either way, we can delete the orphan item.
		 */
		if (ret == -ENOENT || inode->i_nlink) {
			if (!ret)
				iput(inode);
			trans = btrfs_start_transaction(root, 1);
			if (IS_ERR(trans)) {
				ret = PTR_ERR(trans);
				goto out;
			}
			btrfs_debug(root->fs_info, "auto deleting %Lu",
				found_key.objectid);
			ret = btrfs_del_orphan_item(trans, root,
						    found_key.objectid);
			btrfs_end_transaction(trans, root);
			if (ret)
				goto out;
			continue;
		}

		nr_unlink++;

		/* this will do delete_inode and everything for us */
		iput(inode);
		if (ret)
			goto out;
	}
	/* release the path since we're done with it */
	btrfs_release_path(path);

	root->orphan_cleanup_state = ORPHAN_CLEANUP_DONE;

	if (test_bit(BTRFS_ROOT_ORPHAN_ITEM_INSERTED, &root->state)) {
		trans = btrfs_join_transaction(root);
		if (!IS_ERR(trans))
			btrfs_end_transaction(trans, root);
	}

	if (nr_unlink)
		btrfs_debug(root->fs_info, "unlinked %d orphans", nr_unlink);

out:
	if (ret)
		btrfs_crit(root->fs_info,
			"could not do orphan cleanup %d", ret);
	btrfs_free_path(path);
	return ret;
}

/*
 * very simple check to peek ahead in the leaf looking for xattrs.  If we
 * don't find any xattrs, we know there can't be any acls.
 *
 * slot is the slot the inode is in, objectid is the objectid of the inode
 */
static noinline int acls_after_inode_item(struct extent_buffer *leaf,
					  int slot, u64 objectid,
					  int *first_xattr_slot)
{
	u32 nritems = btrfs_header_nritems(leaf);
	struct btrfs_key found_key;
	static u64 xattr_access = 0;
	static u64 xattr_default = 0;
	int scanned = 0;

	if (!xattr_access) {
		xattr_access = btrfs_name_hash(POSIX_ACL_XATTR_ACCESS,
					strlen(POSIX_ACL_XATTR_ACCESS));
		xattr_default = btrfs_name_hash(POSIX_ACL_XATTR_DEFAULT,
					strlen(POSIX_ACL_XATTR_DEFAULT));
	}

	slot++;
	*first_xattr_slot = -1;
	while (slot < nritems) {
		btrfs_item_key_to_cpu(leaf, &found_key, slot);

		/* we found a different objectid, there must not be acls */
		if (found_key.objectid != objectid)
			return 0;

		/* we found an xattr, assume we've got an acl */
		if (found_key.type == BTRFS_XATTR_ITEM_KEY) {
			if (*first_xattr_slot == -1)
				*first_xattr_slot = slot;
			if (found_key.offset == xattr_access ||
			    found_key.offset == xattr_default)
				return 1;
		}

		/*
		 * we found a key greater than an xattr key, there can't
		 * be any acls later on
		 */
		if (found_key.type > BTRFS_XATTR_ITEM_KEY)
			return 0;

		slot++;
		scanned++;

		/*
		 * it goes inode, inode backrefs, xattrs, extents,
		 * so if there are a ton of hard links to an inode there can
		 * be a lot of backrefs.  Don't waste time searching too hard,
		 * this is just an optimization
		 */
		if (scanned >= 8)
			break;
	}
	/* we hit the end of the leaf before we found an xattr or
	 * something larger than an xattr.  We have to assume the inode
	 * has acls
	 */
	if (*first_xattr_slot == -1)
		*first_xattr_slot = slot;
	return 1;
}

/*
 * read an inode from the btree into the in-memory inode
 */
static int btrfs_read_locked_inode(struct inode *inode)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_inode_item *inode_item;
	struct btrfs_timespec *tspec;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_key location;
#ifdef MY_DEF_HERE
#else
	unsigned long ptr;
#endif /* MY_DEF_HERE */
	int maybe_acls;
	u32 rdev;
	int ret;
	bool filled = false;
	int first_xattr_slot;

	ret = btrfs_fill_inode(inode, &rdev);
	if (!ret)
		filled = true;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto make_bad;
	}

	memcpy(&location, &BTRFS_I(inode)->location, sizeof(location));

	ret = btrfs_lookup_inode(NULL, root, path, &location, 0);
	if (ret) {
		if (ret > 0)
			ret = -ENOENT;
		goto make_bad;
	}

	leaf = path->nodes[0];

	if (filled)
		goto cache_index;

	inode_item = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_inode_item);
	inode->i_mode = btrfs_inode_mode(leaf, inode_item);
	set_nlink(inode, btrfs_inode_nlink(leaf, inode_item));
	i_uid_write(inode, btrfs_inode_uid(leaf, inode_item));
	i_gid_write(inode, btrfs_inode_gid(leaf, inode_item));
	btrfs_i_size_write(inode, btrfs_inode_size(leaf, inode_item));

	tspec = btrfs_inode_atime(inode_item);
	inode->i_atime.tv_sec = btrfs_timespec_sec(leaf, tspec);
	inode->i_atime.tv_nsec = btrfs_timespec_nsec(leaf, tspec);

	tspec = btrfs_inode_mtime(inode_item);
	inode->i_mtime.tv_sec = btrfs_timespec_sec(leaf, tspec);
	inode->i_mtime.tv_nsec = btrfs_timespec_nsec(leaf, tspec);

	tspec = btrfs_inode_ctime(inode_item);
	inode->i_ctime.tv_sec = btrfs_timespec_sec(leaf, tspec);
	inode->i_ctime.tv_nsec = btrfs_timespec_nsec(leaf, tspec);

	inode_set_bytes(inode, btrfs_inode_nbytes(leaf, inode_item));
	BTRFS_I(inode)->generation = btrfs_inode_generation(leaf, inode_item);
	BTRFS_I(inode)->last_trans = btrfs_inode_transid(leaf, inode_item);

	inode->i_version = btrfs_inode_sequence(leaf, inode_item);
	inode->i_generation = BTRFS_I(inode)->generation;
	inode->i_rdev = 0;
	rdev = btrfs_inode_rdev(leaf, inode_item);

	BTRFS_I(inode)->index_cnt = (u64)-1;
	BTRFS_I(inode)->flags = btrfs_inode_flags(leaf, inode_item);

#ifdef MY_DEF_HERE
	BTRFS_I(inode)->syno_uq_rfer_used = btrfs_inode_syno_uq_rfer_used(leaf, inode_item);
#endif /* MY_DEF_HERE */

cache_index:
	/*
	 * If we were modified in the current generation and evicted from memory
	 * and then re-read we need to do a full sync since we don't have any
	 * idea about which extents were modified before we were evicted from
	 * cache.
	 *
	 * This is required for both inode re-read from disk and delayed inode
	 * in delayed_nodes_tree.
	 */
	if (BTRFS_I(inode)->last_trans == root->fs_info->generation)
		set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
			&BTRFS_I(inode)->runtime_flags);

	/*
	 * We don't persist the id of the transaction where an unlink operation
	 * against the inode was last made. So here we assume the inode might
	 * have been evicted, and therefore the exact value of last_unlink_trans
	 * lost, and set it to last_trans to avoid metadata inconsistencies
	 * between the inode and its parent if the inode is fsync'ed and the log
	 * replayed. For example, in the scenario:
	 *
	 * touch mydir/foo
	 * ln mydir/foo mydir/bar
	 * sync
	 * unlink mydir/bar
	 * echo 2 > /proc/sys/vm/drop_caches   # evicts inode
	 * xfs_io -c fsync mydir/foo
	 * <power failure>
	 * mount fs, triggers fsync log replay
	 *
	 * We must make sure that when we fsync our inode foo we also log its
	 * parent inode, otherwise after log replay the parent still has the
	 * dentry with the "bar" name but our inode foo has a link count of 1
	 * and doesn't have an inode ref with the name "bar" anymore.
	 *
	 * Setting last_unlink_trans to last_trans is a pessimistic approach,
	 * but it guarantees correctness at the expense of ocassional full
	 * transaction commits on fsync if our inode is a directory, or if our
	 * inode is not a directory, logging its parent unnecessarily.
	 */
	BTRFS_I(inode)->last_unlink_trans = BTRFS_I(inode)->last_trans;

#ifdef MY_DEF_HERE
#else
	path->slots[0]++;
	if (inode->i_nlink != 1 ||
	    path->slots[0] >= btrfs_header_nritems(leaf))
		goto cache_acl;

	btrfs_item_key_to_cpu(leaf, &location, path->slots[0]);
	if (location.objectid != btrfs_ino(inode))
		goto cache_acl;

	ptr = btrfs_item_ptr_offset(leaf, path->slots[0]);
	if (location.type == BTRFS_INODE_REF_KEY) {
		struct btrfs_inode_ref *ref;

		ref = (struct btrfs_inode_ref *)ptr;
		BTRFS_I(inode)->dir_index = btrfs_inode_ref_index(leaf, ref);
	} else if (location.type == BTRFS_INODE_EXTREF_KEY) {
		struct btrfs_inode_extref *extref;

		extref = (struct btrfs_inode_extref *)ptr;
		BTRFS_I(inode)->dir_index = btrfs_inode_extref_index(leaf,
								     extref);
	}
cache_acl:
#endif /* MY_DEF_HERE */

	/*
	 * try to precache a NULL acl entry for files that don't have
	 * any xattrs or acls
	 */
	maybe_acls = acls_after_inode_item(leaf, path->slots[0],
					   btrfs_ino(inode), &first_xattr_slot);
	if (first_xattr_slot != -1) {
		path->slots[0] = first_xattr_slot;
		ret = btrfs_load_inode_props(inode, path);
		if (ret)
			btrfs_err(root->fs_info,
				  "error loading props for ino %llu (root %llu): %d",
				  btrfs_ino(inode),
				  root->root_key.objectid, ret);
	}
	btrfs_free_path(path);

	if (!maybe_acls)
		cache_no_acl(inode);

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_mapping->a_ops = &btrfs_aops;
		inode->i_mapping->backing_dev_info = &root->fs_info->bdi;
		BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;
		inode->i_fop = &btrfs_file_operations;
		inode->i_op = &btrfs_file_inode_operations;
		break;
	case S_IFDIR:
		inode->i_fop = &btrfs_dir_file_operations;
		if (root == root->fs_info->tree_root)
			inode->i_op = &btrfs_dir_ro_inode_operations;
		else
			inode->i_op = &btrfs_dir_inode_operations;
		break;
	case S_IFLNK:
		inode->i_op = &btrfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &btrfs_symlink_aops;
		inode->i_mapping->backing_dev_info = &root->fs_info->bdi;
		break;
	default:
		inode->i_op = &btrfs_special_inode_operations;
		init_special_inode(inode, inode->i_mode, rdev);
		break;
	}

	btrfs_update_iflags(inode);
	return 0;

make_bad:
	btrfs_free_path(path);
	make_bad_inode(inode);
	return ret;
}

/*
 * given a leaf and an inode, copy the inode fields into the leaf
 */
static void fill_inode_item(struct btrfs_trans_handle *trans,
			    struct extent_buffer *leaf,
			    struct btrfs_inode_item *item,
			    struct inode *inode)
{
	struct btrfs_map_token token;

	btrfs_init_map_token(&token);

	btrfs_set_token_inode_uid(leaf, item, i_uid_read(inode), &token);
	btrfs_set_token_inode_gid(leaf, item, i_gid_read(inode), &token);
	btrfs_set_token_inode_size(leaf, item, BTRFS_I(inode)->disk_i_size,
				   &token);
	btrfs_set_token_inode_mode(leaf, item, inode->i_mode, &token);
	btrfs_set_token_inode_nlink(leaf, item, inode->i_nlink, &token);

	btrfs_set_token_timespec_sec(leaf, btrfs_inode_atime(item),
				     inode->i_atime.tv_sec, &token);
	btrfs_set_token_timespec_nsec(leaf, btrfs_inode_atime(item),
				      inode->i_atime.tv_nsec, &token);

	btrfs_set_token_timespec_sec(leaf, btrfs_inode_mtime(item),
				     inode->i_mtime.tv_sec, &token);
	btrfs_set_token_timespec_nsec(leaf, btrfs_inode_mtime(item),
				      inode->i_mtime.tv_nsec, &token);

	btrfs_set_token_timespec_sec(leaf, btrfs_inode_ctime(item),
				     inode->i_ctime.tv_sec, &token);
	btrfs_set_token_timespec_nsec(leaf, btrfs_inode_ctime(item),
				      inode->i_ctime.tv_nsec, &token);

	btrfs_set_token_inode_nbytes(leaf, item, inode_get_bytes(inode),
				     &token);
	btrfs_set_token_inode_generation(leaf, item, BTRFS_I(inode)->generation,
					 &token);
	btrfs_set_token_inode_sequence(leaf, item, inode->i_version, &token);
	btrfs_set_token_inode_transid(leaf, item, trans->transid, &token);
	btrfs_set_token_inode_rdev(leaf, item, inode->i_rdev, &token);
	btrfs_set_token_inode_flags(leaf, item, BTRFS_I(inode)->flags, &token);
	btrfs_set_token_inode_block_group(leaf, item, 0, &token);
#ifdef MY_DEF_HERE
	btrfs_set_token_inode_syno_uq_rfer_used(leaf, item, BTRFS_I(inode)->syno_uq_rfer_used, &token);
#endif /* MY_DEF_HERE */
}

/*
 * copy everything in the in-memory inode into the btree.
 */
static noinline int btrfs_update_inode_item(struct btrfs_trans_handle *trans,
				struct btrfs_root *root, struct inode *inode)
{
	struct btrfs_inode_item *inode_item;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->leave_spinning = 1;
	ret = btrfs_lookup_inode(trans, root, path, &BTRFS_I(inode)->location,
				 1);
	if (ret) {
		if (ret > 0)
			ret = -ENOENT;
		goto failed;
	}

	leaf = path->nodes[0];
	inode_item = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_inode_item);

	fill_inode_item(trans, leaf, inode_item, inode);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_set_inode_last_trans(trans, inode);
	ret = 0;
failed:
	btrfs_free_path(path);
	return ret;
}

#ifdef MY_DEF_HERE
void block_dump___btrfs_update_inode(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct dentry *dentry;
	const char *name = "?";

	dentry = d_find_alias(inode);
	if (dentry) {
		spin_lock(&dentry->d_lock);
		name = (const char *) dentry->d_name.name;
	}
	printk(KERN_DEBUG
		   "ppid:%d(%s), pid:%d(%s), dirtied subvolume %llu inode %llu (%s) on %s\n",
		   task_pid_nr(current->parent), current->parent->comm,
		   task_pid_nr(current), current->comm,
		   root->objectid, btrfs_ino(inode),
		   name, inode->i_sb->s_id);
	if (dentry) {
		spin_unlock(&dentry->d_lock);
		dput(dentry);
	}
}
#endif /* MY_DEF_HERE */

/*
 * copy everything in the in-memory inode into the btree.
 */
noinline int btrfs_update_inode(struct btrfs_trans_handle *trans,
				struct btrfs_root *root, struct inode *inode)
{
	int ret;

#ifdef MY_DEF_HERE
	if (unlikely(block_dump))
		block_dump___btrfs_update_inode(inode);
#endif /* MY_DEF_HERE */

	/*
	 * If the inode is a free space inode, we can deadlock during commit
	 * if we put it into the delayed code.
	 *
	 * The data relocation inode should also be directly updated
	 * without delay
	 */
	if (!btrfs_is_free_space_inode(inode)
	    && root->root_key.objectid != BTRFS_DATA_RELOC_TREE_OBJECTID
	    && !root->fs_info->log_root_recovering) {
		btrfs_update_root_times(trans, root);

		ret = btrfs_delayed_update_inode(trans, root, inode);
		if (!ret)
			btrfs_set_inode_last_trans(trans, inode);
		return ret;
	}

	return btrfs_update_inode_item(trans, root, inode);
}

noinline int btrfs_update_inode_fallback(struct btrfs_trans_handle *trans,
					 struct btrfs_root *root,
					 struct inode *inode)
{
	int ret;

	ret = btrfs_update_inode(trans, root, inode);
	if (ret == -ENOSPC)
		return btrfs_update_inode_item(trans, root, inode);
	return ret;
}

#ifdef MY_DEF_HERE
static int btrfs_unlink_dir_item_caseless(struct btrfs_trans_handle *trans,
					struct btrfs_root *root,
					struct inode *dir,
					const char *name, int name_len)
{
	struct btrfs_path *path;
	int ret = 0;
	struct btrfs_dir_item *di;
	u64 dir_ino = btrfs_ino(dir);

	path = btrfs_alloc_path();
	if (!path) {
		return -ENOMEM;
	}
	path->caseless_key = 1;
	path->leave_spinning = 1;

	di = btrfs_lookup_dir_item(trans, root, path, dir_ino,
				    name, name_len, -1);
	if (IS_ERR(di)) {
		ret = PTR_ERR(di);
		goto err;
	}
	if (!di) {
		goto err;
	}
	ret = btrfs_delete_one_dir_name(trans, root, path, di);
	if (ret)
		goto err;
err:
	btrfs_free_path(path);
	return ret;

}
#endif /* MY_DEF_HERE */

/*
 * unlink helper that gets used here in inode.c and in the tree logging
 * recovery code.  It remove a link in a directory with a given name, and
 * also drops the back refs in the inode to the directory
 */
static int __btrfs_unlink_inode(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				struct inode *dir, struct inode *inode,
				const char *name, int name_len)
{
	struct btrfs_path *path;
	int ret = 0;
	struct extent_buffer *leaf;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	u64 index;
	u64 ino = btrfs_ino(inode);
	u64 dir_ino = btrfs_ino(dir);

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	path->leave_spinning = 1;
	di = btrfs_lookup_dir_item(trans, root, path, dir_ino,
				    name, name_len, -1);
	if (IS_ERR(di)) {
		ret = PTR_ERR(di);
		goto err;
	}
	if (!di) {
		ret = -ENOENT;
		goto err;
	}
	leaf = path->nodes[0];
	btrfs_dir_item_key_to_cpu(leaf, di, &key);
	ret = btrfs_delete_one_dir_name(trans, root, path, di);
	if (ret)
		goto err;
	btrfs_release_path(path);

#ifdef MY_DEF_HERE
	ret = btrfs_unlink_dir_item_caseless(trans, root, dir, name, name_len);
	if (ret)
		goto err;
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	/*
	 * It may deadlock if btrfs_sync_log() btrfs_delayed_delete_inode_ref() running
	 * at the same time. They are locked at root->log_mutex and root->inode_lock.
	 * We pin log_writer here to make btrfs_sync_log() waiting for
	 * btrfs_delayed_delete_inode_ref() done.
	 */
	btrfs_pin_log_trans(root);
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
#else
	/*
	 * If we don't have dir index, we have to get it by looking up
	 * the inode ref, since we get the inode ref, remove it directly,
	 * it is unnecessary to do delayed deletion.
	 *
	 * But if we have dir index, needn't search inode ref to get it.
	 * Since the inode ref is close to the inode item, it is better
	 * that we delay to delete it, and just do this deletion when
	 * we update the inode item.
	 */
	if (BTRFS_I(inode)->dir_index) {
		ret = btrfs_delayed_delete_inode_ref(inode);
		if (!ret) {
			index = BTRFS_I(inode)->dir_index;
#ifdef MY_DEF_HERE
			btrfs_end_log_trans(root);
#endif /* MY_DEF_HERE */
			goto skip_backref;
		}
	}
#endif /* MY_DEF_HERE */

	ret = btrfs_del_inode_ref(trans, root, name, name_len, ino,
				  dir_ino, &index);
	if (ret) {
		btrfs_info(root->fs_info,
			"failed to delete reference to %.*s, inode %llu parent %llu",
			name_len, name, ino, dir_ino);
#ifdef MY_DEF_HERE
		btrfs_end_log_trans(root);
#endif /* MY_DEF_HERE */
		btrfs_abort_transaction(trans, root, ret);
		goto err;
	}
#ifdef MY_DEF_HERE
	btrfs_end_log_trans(root);
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
#else
skip_backref:
#endif /* MY_DEF_HERE */
	ret = btrfs_delete_delayed_dir_index(trans, root, dir, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto err;
	}

	ret = btrfs_del_inode_ref_in_log(trans, root, name, name_len,
					 inode, dir_ino);
	if (ret != 0 && ret != -ENOENT) {
		btrfs_abort_transaction(trans, root, ret);
		goto err;
	}

	ret = btrfs_del_dir_entries_in_log(trans, root, name, name_len,
					   dir, index);
	if (ret == -ENOENT)
		ret = 0;
	else if (ret)
		btrfs_abort_transaction(trans, root, ret);
err:
	btrfs_free_path(path);
	if (ret)
		goto out;

	btrfs_i_size_write(dir, dir->i_size - name_len * 2);
	inode_inc_iversion(inode);
	inode_inc_iversion(dir);
	inode->i_ctime = dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	ret = btrfs_update_inode(trans, root, dir);
out:
	return ret;
}

int btrfs_unlink_inode(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root,
		       struct inode *dir, struct inode *inode,
		       const char *name, int name_len)
{
	int ret;
	ret = __btrfs_unlink_inode(trans, root, dir, inode, name, name_len);
	if (!ret) {
		drop_nlink(inode);
		ret = btrfs_update_inode(trans, root, inode);
	}
	return ret;
}

/*
 * helper to start transaction for unlink and rmdir.
 *
 * unlink and rmdir are special in btrfs, they do not always free space, so
 * if we cannot make our reservations the normal way try and see if there is
 * plenty of slack room in the global reserve to migrate, otherwise we cannot
 * allow the unlink to occur.
 */
static struct btrfs_trans_handle *__unlink_start_trans(struct inode *dir)
{
	struct btrfs_root *root = BTRFS_I(dir)->root;

	/*
	 * 1 for the possible orphan item
	 * 1 for the dir item
	 * 1 for the dir index
	 * 1 for the inode ref
	 * 1 for the inode
	 */
	return btrfs_start_transaction_fallback_global_rsv(root, 5, 5);
}

static int btrfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_trans_handle *trans;
	struct inode *inode = dentry->d_inode;
	int ret;

	trans = __unlink_start_trans(dir);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	btrfs_record_unlink_dir(trans, dir, dentry->d_inode, 0);

	ret = btrfs_unlink_inode(trans, root, dir, dentry->d_inode,
				 dentry->d_name.name, dentry->d_name.len);
	if (ret)
		goto out;

	if (inode->i_nlink == 0) {
		ret = btrfs_orphan_add(trans, inode);
		if (ret)
			goto out;
	}

out:
	btrfs_end_transaction(trans, root);
	btrfs_btree_balance_dirty(root);
	return ret;
}

int btrfs_unlink_subvol(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			struct inode *dir, u64 objectid,
			const char *name, int name_len)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	u64 index;
	int ret;
	u64 dir_ino = btrfs_ino(dir);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	di = btrfs_lookup_dir_item(trans, root, path, dir_ino,
				   name, name_len, -1);
	if (IS_ERR_OR_NULL(di)) {
		if (!di)
			ret = -ENOENT;
		else
			ret = PTR_ERR(di);
		goto out;
	}

	leaf = path->nodes[0];
	btrfs_dir_item_key_to_cpu(leaf, di, &key);
	WARN_ON(key.type != BTRFS_ROOT_ITEM_KEY || key.objectid != objectid);
	ret = btrfs_delete_one_dir_name(trans, root, path, di);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}
	btrfs_release_path(path);

#ifdef MY_DEF_HERE
	ret = btrfs_unlink_dir_item_caseless(trans, root, dir, name, name_len);
	if (ret)
		goto out;
#endif /* MY_DEF_HERE */
	ret = btrfs_del_root_ref(trans, root->fs_info->tree_root,
				 objectid, root->root_key.objectid,
				 dir_ino, &index, name, name_len);
	if (ret < 0) {
		if (ret != -ENOENT) {
			btrfs_abort_transaction(trans, root, ret);
			goto out;
		}
		di = btrfs_search_dir_index_item(root, path, dir_ino,
						 name, name_len);
		if (IS_ERR_OR_NULL(di)) {
			if (!di)
				ret = -ENOENT;
			else
				ret = PTR_ERR(di);
			btrfs_abort_transaction(trans, root, ret);
			goto out;
		}

		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
		btrfs_release_path(path);
		index = key.offset;
	}
	btrfs_release_path(path);

	ret = btrfs_delete_delayed_dir_index(trans, root, dir, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

	btrfs_i_size_write(dir, dir->i_size - name_len * 2);
	inode_inc_iversion(dir);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	ret = btrfs_update_inode_fallback(trans, root, dir);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
out:
	btrfs_free_path(path);
	return ret;
}

static int btrfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int err = 0;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_trans_handle *trans;

	if (inode->i_size > BTRFS_EMPTY_DIR_SIZE)
		return -ENOTEMPTY;
	if (btrfs_ino(inode) == BTRFS_FIRST_FREE_OBJECTID)
		return -EPERM;

	trans = __unlink_start_trans(dir);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	if (unlikely(btrfs_ino(inode) == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)) {
		err = btrfs_unlink_subvol(trans, root, dir,
					  BTRFS_I(inode)->location.objectid,
					  dentry->d_name.name,
					  dentry->d_name.len);
		goto out;
	}

	err = btrfs_orphan_add(trans, inode);
	if (err)
		goto out;

	/* now the directory is empty */
	err = btrfs_unlink_inode(trans, root, dir, dentry->d_inode,
				 dentry->d_name.name, dentry->d_name.len);
	if (!err)
		btrfs_i_size_write(inode, 0);
out:
	btrfs_end_transaction(trans, root);
	btrfs_btree_balance_dirty(root);

	return err;
}

static int truncate_space_check(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				u64 bytes_deleted)
{
	int ret;

	bytes_deleted = btrfs_csum_bytes_to_leaves(root, bytes_deleted);
	ret = btrfs_block_rsv_add(root, &root->fs_info->trans_block_rsv,
				  bytes_deleted, BTRFS_RESERVE_NO_FLUSH);
	if (!ret)
		trans->bytes_reserved += bytes_deleted;
	return ret;

}

/*
 * Return this if we need to call truncate_block for the last bit of the
 * truncate.
 */
#define NEED_TRUNCATE_BLOCK 1

/*
 * this can truncate away extent items, csum items and directory items.
 * It starts at a high offset and removes keys until it can't find
 * any higher than new_size
 *
 * csum items that cross the new i_size are truncated to the new size
 * as well.
 *
 * min_type is the minimum key type to truncate down to.  If set to 0, this
 * will kill all the items on this inode, including the INODE_ITEM_KEY.
 */
int btrfs_truncate_inode_items(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       struct inode *inode,
			       u64 new_size, u32 min_type)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	struct btrfs_key found_key;
	u64 extent_start = 0;
	u64 extent_num_bytes = 0;
#ifdef MY_DEF_HERE
	u64 ram_bytes = 0;
#endif /* MY_DEF_HERE */
	u64 extent_offset = 0;
	u64 item_end = 0;
	u64 last_size = new_size;
	u32 found_type = (u8)-1;
	int found_extent;
	int del_item;
	int pending_del_nr = 0;
	int pending_del_slot = 0;
	int extent_type = -1;
	int ret;
	u64 ino = btrfs_ino(inode);
	u64 bytes_deleted = 0;
	bool be_nice = 0;
	bool should_throttle = 0;
	bool should_end = 0;

	BUG_ON(new_size > 0 && min_type != BTRFS_EXTENT_DATA_KEY);

	/*
	 * for non-free space inodes and ref cows, we want to back off from
	 * time to time
	 */
	if (!btrfs_is_free_space_inode(inode) &&
	    test_bit(BTRFS_ROOT_REF_COWS, &root->state))
		be_nice = 1;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->reada = READA_BACK;

	/*
	 * We want to drop from the next block forward in case this new size is
	 * not block aligned since we will be keeping the last block of the
	 * extent just the way it is.
	 */
	if (test_bit(BTRFS_ROOT_REF_COWS, &root->state) ||
	    root == root->fs_info->tree_root)
		btrfs_drop_extent_cache(inode, ALIGN(new_size,
					root->sectorsize), (u64)-1, 0);

	/*
	 * This function is also used to drop the items in the log tree before
	 * we relog the inode, so if root != BTRFS_I(inode)->root, it means
	 * it is used to drop the loged items. So we shouldn't kill the delayed
	 * items.
	 */
	if (min_type == 0 && root == BTRFS_I(inode)->root)
		btrfs_kill_delayed_inode_items(inode);

	key.objectid = ino;
	key.offset = (u64)-1;
	key.type = (u8)-1;

search_again:
	/*
	 * with a 16K leaf size and 128MB extents, you can actually queue
	 * up a huge file in a single leaf.  Most of the time that
	 * bytes_deleted is > 0, it will be huge by the time we get here
	 */
	if (be_nice && bytes_deleted > SZ_32M &&
	    btrfs_should_end_transaction(trans, root)) {
		ret = -EAGAIN;
		goto out;
	}

	path->leave_spinning = 1;
	ret = btrfs_search_slot(trans, root, &key, path, -1, 1);
	if (ret < 0)
		goto out;

	if (ret > 0) {
		ret = 0;
		/* there are no items in the tree for us to truncate, we're
		 * done
		 */
		if (path->slots[0] == 0)
			goto out;
		path->slots[0]--;
	}

	while (1) {
		fi = NULL;
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		found_type = btrfs_key_type(&found_key);

		if (found_key.objectid != ino)
			break;

		if (found_type < min_type)
			break;

		item_end = found_key.offset;
		if (found_type == BTRFS_EXTENT_DATA_KEY) {
			fi = btrfs_item_ptr(leaf, path->slots[0],
					    struct btrfs_file_extent_item);
			extent_type = btrfs_file_extent_type(leaf, fi);
			if (extent_type != BTRFS_FILE_EXTENT_INLINE) {
				item_end +=
				    btrfs_file_extent_num_bytes(leaf, fi);
			} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
				item_end += btrfs_file_extent_inline_len(leaf,
							 path->slots[0], fi);
			}
			item_end--;
		}
		if (found_type > min_type) {
			del_item = 1;
		} else {
			if (item_end < new_size)
				break;
			if (found_key.offset >= new_size)
				del_item = 1;
			else
				del_item = 0;
		}
		found_extent = 0;
		/* FIXME, shrink the extent if the ref count is only 1 */
		if (found_type != BTRFS_EXTENT_DATA_KEY)
			goto delete;

		if (extent_type != BTRFS_FILE_EXTENT_INLINE) {
			u64 num_dec;
			extent_start = btrfs_file_extent_disk_bytenr(leaf, fi);
			if (!del_item) {
				u64 orig_num_bytes =
					btrfs_file_extent_num_bytes(leaf, fi);
				extent_num_bytes = ALIGN(new_size -
						found_key.offset,
						root->sectorsize);
				btrfs_set_file_extent_num_bytes(leaf, fi,
							 extent_num_bytes);
				num_dec = (orig_num_bytes -
					   extent_num_bytes);
				if (test_bit(BTRFS_ROOT_REF_COWS,
					     &root->state) &&
				    extent_start != 0)
					inode_sub_bytes(inode, num_dec);
				btrfs_mark_buffer_dirty(leaf);
			} else {
				extent_num_bytes =
					btrfs_file_extent_disk_num_bytes(leaf,
									 fi);
#ifdef MY_DEF_HERE
				ram_bytes = btrfs_file_extent_ram_bytes(leaf, fi);
#endif /* MY_DEF_HERE */
				extent_offset = found_key.offset -
					btrfs_file_extent_offset(leaf, fi);

				/* FIXME blocksize != 4096 */
				num_dec = btrfs_file_extent_num_bytes(leaf, fi);
				if (extent_start != 0) {
					found_extent = 1;
					if (test_bit(BTRFS_ROOT_REF_COWS,
						     &root->state))
						inode_sub_bytes(inode, num_dec);
				}
			}
		} else if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
			/*
			 * we can't truncate inline items that have had
			 * special encodings
			 */
			if (!del_item &&
			    btrfs_file_extent_encryption(leaf, fi) == 0 &&
			    btrfs_file_extent_other_encoding(leaf, fi) == 0 &&
			    btrfs_file_extent_compression(leaf, fi) == 0) {
				u32 size = (u32)(new_size - found_key.offset);

				btrfs_set_file_extent_ram_bytes(leaf, fi, size);
				size = btrfs_file_extent_calc_inline_size(size);
				btrfs_truncate_item(root, path, size, 1);
			} else if (!del_item) {
				/*
				 * We have to bail so the last_size is set to
				 * just before this extent.
				 */
				ret = NEED_TRUNCATE_BLOCK;
				break;
			}

			if (test_bit(BTRFS_ROOT_REF_COWS, &root->state))
				inode_sub_bytes(inode, item_end + 1 - new_size);
		}
delete:
		if (del_item)
			last_size = found_key.offset;
		else
			last_size = new_size;
		if (del_item) {
			if (!pending_del_nr) {
				/* no pending yet, add ourselves */
				pending_del_slot = path->slots[0];
				pending_del_nr = 1;
			} else if (pending_del_nr &&
				   path->slots[0] + 1 == pending_del_slot) {
				/* hop on the pending chunk */
				pending_del_nr++;
				pending_del_slot = path->slots[0];
			} else {
				BUG();
			}
		} else {
			break;
		}
		should_throttle = 0;

		if (found_extent &&
		    (test_bit(BTRFS_ROOT_REF_COWS, &root->state) ||
		     root == root->fs_info->tree_root)) {
			btrfs_set_path_blocking(path);
			bytes_deleted += extent_num_bytes;
#ifdef MY_DEF_HERE
			ret = btrfs_free_extent_uid(trans, root, extent_start,
						extent_num_bytes, 0,
						btrfs_header_owner(leaf),
						ino, extent_offset,
						0, ram_bytes,
						inode, i_uid_read(inode)
#ifdef MY_DEF_HERE
						,btrfs_syno_usage_ref_check(root, found_key.objectid, found_key.offset)
#endif /* MY_DEF_HERE */
						);
#else
			ret = btrfs_free_extent(trans, root, extent_start,
						extent_num_bytes, 0,
						btrfs_header_owner(leaf),
						ino, extent_offset,
						0
#ifdef MY_DEF_HERE
						,ram_bytes
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
						,btrfs_syno_usage_ref_check(root, found_key.objectid, found_key.offset)
#endif /* MY_DEF_HERE */
						);
#endif /* MY_DEF_HERE */
			if (ret) {
				btrfs_abort_transaction(trans, root, ret);
				break;
			}
			if (btrfs_should_throttle_delayed_refs(trans, root))
				btrfs_async_run_delayed_refs(root,
					trans->delayed_ref_updates * 2, 0);
			if (be_nice) {
				if (truncate_space_check(trans, root,
							 extent_num_bytes)) {
					should_end = 1;
				}
				if (btrfs_should_throttle_delayed_refs(trans,
								       root)) {
					should_throttle = 1;
				}
			}
		}

		if (found_type == BTRFS_INODE_ITEM_KEY)
			break;

		if (path->slots[0] == 0 ||
		    path->slots[0] != pending_del_slot ||
		    should_throttle || should_end) {
			if (pending_del_nr) {
				ret = btrfs_del_items(trans, root, path,
						pending_del_slot,
						pending_del_nr);
				if (ret) {
					btrfs_abort_transaction(trans,
								root, ret);
					break;
				}
				pending_del_nr = 0;
			}
			btrfs_release_path(path);
			if (should_throttle) {
				unsigned long updates = trans->delayed_ref_updates;
				if (updates) {
					trans->delayed_ref_updates = 0;
					ret = btrfs_run_delayed_refs(trans, root, updates * 2);
					if (ret)
						break;
				}
			}
			/*
			 * if we failed to refill our space rsv, bail out
			 * and let the transaction restart
			 */
			if (should_end) {
				ret = -EAGAIN;
				break;
			}
			goto search_again;
		} else {
			path->slots[0]--;
		}
	}
out:
	if (ret >= 0 && pending_del_nr) {
		int err;

		err = btrfs_del_items(trans, root, path, pending_del_slot,
				      pending_del_nr);
		if (err) {
			btrfs_abort_transaction(trans, root, err);
			ret = err;
		}
	}
	if (root->root_key.objectid != BTRFS_TREE_LOG_OBJECTID) {
		ASSERT(last_size >= new_size);
		if (!ret && last_size > new_size)
			last_size = new_size;
		btrfs_ordered_update_i_size(inode, last_size, NULL);
	}

	btrfs_free_path(path);

	if (be_nice && bytes_deleted > SZ_32M && (ret >= 0 || ret == -EAGAIN)) {
		unsigned long updates = trans->delayed_ref_updates;
		int err;

		if (updates) {
			trans->delayed_ref_updates = 0;
			err = btrfs_run_delayed_refs(trans, root, updates * 2);
			if (err)
				ret = err;
		}
	}
	return ret;
}

/*
 * btrfs_truncate_page - read, zero a chunk and write a page
 * @inode - inode that we're zeroing
 * @from - the offset to start zeroing
 * @len - the length to zero, 0 to zero the entire range respective to the
 *	offset
 * @front - zero up to the offset instead of from the offset on
 *
 * This will find the page for the "from" offset and cow the page and zero the
 * part we want to zero.  This is used with truncate and hole punching.
 */
int btrfs_truncate_page(struct inode *inode, loff_t from, loff_t len,
			int front)
{
	struct address_space *mapping = inode->i_mapping;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	char *kaddr;
	u32 blocksize = root->sectorsize;
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	struct page *page;
	gfp_t mask = btrfs_alloc_write_mask(mapping);
	int ret = 0;
	u64 page_start;
	u64 page_end;

	if ((offset & (blocksize - 1)) == 0 &&
	    (!len || ((len & (blocksize - 1)) == 0)))
		goto out;
	ret = btrfs_delalloc_reserve_space(inode, PAGE_CACHE_SIZE);
	if (ret)
		goto out;

again:
	page = find_or_create_page(mapping, index, mask);
	if (!page) {
		btrfs_delalloc_release_space(inode, PAGE_CACHE_SIZE);
		ret = -ENOMEM;
		goto out;
	}

	page_start = page_offset(page);
	page_end = page_start + PAGE_CACHE_SIZE - 1;

	if (!PageUptodate(page)) {
		ret = btrfs_readpage(NULL, page);
		lock_page(page);
		if (page->mapping != mapping) {
			unlock_page(page);
			page_cache_release(page);
			goto again;
		}
		if (!PageUptodate(page)) {
			ret = -EIO;
			goto out_unlock;
		}
	}
	wait_on_page_writeback(page);

	lock_extent_bits(io_tree, page_start, page_end, 0, &cached_state);
	set_page_extent_mapped(page);

	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		unlock_page(page);
		page_cache_release(page);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
		goto again;
	}

	clear_extent_bit(&BTRFS_I(inode)->io_tree, page_start, page_end,
			  EXTENT_DIRTY | EXTENT_DELALLOC |
			  EXTENT_DO_ACCOUNTING | EXTENT_DEFRAG,
			  0, 0, &cached_state, GFP_NOFS);

	ret = btrfs_set_extent_delalloc(inode, page_start, page_end,
					&cached_state);
	if (ret) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		goto out_unlock;
	}

	if (offset != PAGE_CACHE_SIZE) {
		if (!len)
			len = PAGE_CACHE_SIZE - offset;
		kaddr = kmap(page);
		if (front)
			memset(kaddr, 0, offset);
		else
			memset(kaddr + offset, 0, len);
		flush_dcache_page(page);
		kunmap(page);
	}
	ClearPageChecked(page);
	set_page_dirty(page);
	unlock_extent_cached(io_tree, page_start, page_end, &cached_state,
			     GFP_NOFS);

out_unlock:
	if (ret)
		btrfs_delalloc_release_space(inode, PAGE_CACHE_SIZE);
	unlock_page(page);
	page_cache_release(page);
out:
	return ret;
}

static int maybe_insert_hole(struct btrfs_root *root, struct inode *inode,
			     u64 offset, u64 len)
{
	struct btrfs_trans_handle *trans;
	int ret;

	/*
	 * Still need to make sure the inode looks like it's been updated so
	 * that any holes get logged if we fsync.
	 */
	if (btrfs_fs_incompat(root->fs_info, NO_HOLES)) {
		BTRFS_I(inode)->last_trans = root->fs_info->generation;
		BTRFS_I(inode)->last_sub_trans = root->log_transid;
		BTRFS_I(inode)->last_log_commit = root->last_log_commit;
		return 0;
	}

	/*
	 * 1 - for the one we're dropping
	 * 1 - for the one we're adding
	 * 1 - for updating the inode.
	 */
	trans = btrfs_start_transaction(root, 3);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	ret = btrfs_drop_extents(trans, root, inode, offset, offset + len, 1);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		btrfs_end_transaction(trans, root);
		return ret;
	}

	ret = btrfs_insert_file_extent(trans, root, btrfs_ino(inode), offset,
				       0, 0, len, 0, len, 0, 0, 0);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
	else
		btrfs_update_inode(trans, root, inode);
	btrfs_end_transaction(trans, root);
	return ret;
}

/*
 * This function puts in dummy file extents for the area we're creating a hole
 * for.  So if we are truncating this file to a larger size we need to insert
 * these file extents so that btrfs_get_extent will return a EXTENT_MAP_HOLE for
 * the range between oldsize and size
 */
int btrfs_cont_expand(struct inode *inode, loff_t oldsize, loff_t size)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_map *em = NULL;
	struct extent_state *cached_state = NULL;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	u64 hole_start = ALIGN(oldsize, root->sectorsize);
	u64 block_end = ALIGN(size, root->sectorsize);
	u64 last_byte;
	u64 cur_offset;
	u64 hole_size;
	int err = 0;

	/*
	 * If our size started in the middle of a page we need to zero out the
	 * rest of the page before we expand the i_size, otherwise we could
	 * expose stale data.
	 */
	err = btrfs_truncate_page(inode, oldsize, 0, 0);
	if (err)
		return err;

	if (size <= hole_start)
		return 0;

	while (1) {
		struct btrfs_ordered_extent *ordered;

		lock_extent_bits(io_tree, hole_start, block_end - 1, 0,
				 &cached_state);
		ordered = btrfs_lookup_ordered_range(inode, hole_start,
						     block_end - hole_start);
		if (!ordered)
			break;
		unlock_extent_cached(io_tree, hole_start, block_end - 1,
				     &cached_state, GFP_NOFS);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
	}

	cur_offset = hole_start;
	while (1) {
		em = btrfs_get_extent(inode, NULL, 0, cur_offset,
				block_end - cur_offset, 0);
		if (IS_ERR(em)) {
			err = PTR_ERR(em);
			em = NULL;
			break;
		}
		last_byte = min(extent_map_end(em), block_end);
		last_byte = ALIGN(last_byte , root->sectorsize);
		if (!test_bit(EXTENT_FLAG_PREALLOC, &em->flags)) {
			struct extent_map *hole_em;
			hole_size = last_byte - cur_offset;

			err = maybe_insert_hole(root, inode, cur_offset,
						hole_size);
			if (err)
				break;
			btrfs_drop_extent_cache(inode, cur_offset,
						cur_offset + hole_size - 1, 0);
			hole_em = alloc_extent_map();
			if (!hole_em) {
				set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
					&BTRFS_I(inode)->runtime_flags);
				goto next;
			}
			hole_em->start = cur_offset;
			hole_em->len = hole_size;
			hole_em->orig_start = cur_offset;

			hole_em->block_start = EXTENT_MAP_HOLE;
			hole_em->block_len = 0;
			hole_em->orig_block_len = 0;
			hole_em->ram_bytes = hole_size;
			hole_em->bdev = root->fs_info->fs_devices->latest_bdev;
			hole_em->compress_type = BTRFS_COMPRESS_NONE;
			hole_em->generation = root->fs_info->generation;

			while (1) {
				write_lock(&em_tree->lock);
				err = add_extent_mapping(em_tree, hole_em, 1);
				write_unlock(&em_tree->lock);
				if (err != -EEXIST)
					break;
				btrfs_drop_extent_cache(inode, cur_offset,
							cur_offset +
							hole_size - 1, 0);
			}
			free_extent_map(hole_em);
		}
next:
		free_extent_map(em);
		em = NULL;
		cur_offset = last_byte;
		if (cur_offset >= block_end)
			break;
	}
	free_extent_map(em);
	unlock_extent_cached(io_tree, hole_start, block_end - 1, &cached_state,
			     GFP_NOFS);
	return err;
}

static int wait_snapshoting_atomic_t(atomic_t *a)
{
	schedule();
	return 0;
}

static void wait_for_snapshot_creation(struct btrfs_root *root)
{
	while (true) {
		int ret;

		ret = btrfs_start_write_no_snapshoting(root);
		if (ret)
			break;
		wait_on_atomic_t(&root->will_be_snapshoted,
				 wait_snapshoting_atomic_t,
				 TASK_UNINTERRUPTIBLE);
	}
}

static int btrfs_setsize(struct inode *inode, struct iattr *attr)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	loff_t oldsize = i_size_read(inode);
	loff_t newsize = attr->ia_size;
	int mask = attr->ia_valid;
	int ret;

	/*
	 * The regular truncate() case without ATTR_CTIME and ATTR_MTIME is a
	 * special case where we need to update the times despite not having
	 * these flags set.  For all other operations the VFS set these flags
	 * explicitly if it wants a timestamp update.
	 */
	if (newsize != oldsize) {
		inode_inc_iversion(inode);
		if (!(mask & (ATTR_CTIME | ATTR_MTIME)))
			inode->i_ctime = inode->i_mtime =
				current_fs_time(inode->i_sb);
	}

	if (newsize > oldsize) {
		truncate_pagecache(inode, oldsize, newsize);
		/*
		 * Don't do an expanding truncate while snapshoting is ongoing.
		 * This is to ensure the snapshot captures a fully consistent
		 * state of this file - if the snapshot captures this expanding
		 * truncation, it must capture all writes that happened before
		 * this truncation.
		 */
		wait_for_snapshot_creation(root);
		ret = btrfs_cont_expand(inode, oldsize, newsize);
		if (ret) {
			btrfs_end_write_no_snapshoting(root);
			return ret;
		}

		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans)) {
			btrfs_end_write_no_snapshoting(root);
			return PTR_ERR(trans);
		}

		i_size_write(inode, newsize);
		btrfs_ordered_update_i_size(inode, i_size_read(inode), NULL);
		ret = btrfs_update_inode(trans, root, inode);
		btrfs_end_write_no_snapshoting(root);
		btrfs_end_transaction(trans, root);
	} else {

		/*
		 * We're truncating a file that used to have good data down to
		 * zero. Make sure it gets into the ordered flush list so that
		 * any new writes get down to disk quickly.
		 */
		if (newsize == 0
#ifdef MY_DEF_HERE
			&& oldsize != newsize
#endif /* MY_DEF_HERE */
			)
			set_bit(BTRFS_INODE_ORDERED_DATA_CLOSE,
				&BTRFS_I(inode)->runtime_flags);

#ifdef MY_DEF_HERE
#else
		/* we don't support swapfiles, so vmtruncate shouldn't fail */
		truncate_setsize(inode, newsize);
#endif /* MY_DEF_HERE */

		/* Disable nonlocked read DIO to avoid the end less truncate */
		btrfs_inode_block_unlocked_dio(inode);
		inode_dio_wait(inode);

#ifdef MY_DEF_HERE
		/* we don't support swapfiles, so vmtruncate shouldn't fail */
		truncate_setsize(inode, newsize);
#endif /* MY_DEF_HERE */

		btrfs_inode_resume_unlocked_dio(inode);

		ret = btrfs_truncate(inode, newsize == oldsize);
		if (ret && inode->i_nlink) {
			int err;

			/*
			 * Truncate failed, so fix up the in-memory size. We
			 * adjusted disk_i_size down as we removed extents, so
			 * wait for disk_i_size to be stable and then update the
			 * in-memory size to match.
			 */
			err = btrfs_wait_ordered_range(inode, 0, (u64)-1);
			if (err)
				return err;
			i_size_write(inode, BTRFS_I(inode)->disk_i_size);
		}
	}

	return ret;
}

static int btrfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int err;

	if (btrfs_root_readonly(root))
		return -EROFS;

#ifdef MY_DEF_HERE
	if (IS_SYNOACL(dentry))
		goto no_check_perm;
#endif
	err = inode_change_ok(inode, attr);
	if (err)
		return err;

#ifdef MY_DEF_HERE
no_check_perm:
#endif
	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		err = btrfs_setsize(inode, attr);
		if (err)
			return err;
	}

#ifdef MY_DEF_HERE
	if (attr->ia_valid & ATTR_UID && attr->ia_uid != inode->i_uid && S_ISREG(inode->i_mode)) {
		err = btrfs_usrquota_transfer(inode, attr->ia_uid);
		if (err) {
			return err;
		}
		inode->i_uid = attr->ia_uid;
	}
#endif
	if (attr->ia_valid) {
		setattr_copy(inode, attr);
		inode_inc_iversion(inode);
		err = btrfs_dirty_inode(inode);

		if (!err && attr->ia_valid & ATTR_MODE)
			err = btrfs_acl_chmod(inode);
	}

	return err;
}

/*
 * While truncating the inode pages during eviction, we get the VFS calling
 * btrfs_invalidatepage() against each page of the inode. This is slow because
 * the calls to btrfs_invalidatepage() result in a huge amount of calls to
 * lock_extent_bits() and clear_extent_bit(), which keep merging and splitting
 * extent_state structures over and over, wasting lots of time.
 *
 * Therefore if the inode is being evicted, let btrfs_invalidatepage() skip all
 * those expensive operations on a per page basis and do only the ordered io
 * finishing, while we release here the extent_map and extent_state structures,
 * without the excessive merging and splitting.
 */
static void evict_inode_truncate_pages(struct inode *inode)
{
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_map_tree *map_tree = &BTRFS_I(inode)->extent_tree;
	struct rb_node *node;
#ifdef MY_DEF_HERE
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
#endif

	ASSERT(inode->i_state & I_FREEING);
	truncate_inode_pages(&inode->i_data, 0);

#ifdef MY_DEF_HERE
	spin_lock(&fs_info->extent_map_inode_list_lock);
	WARN_ON(atomic_read(&BTRFS_I(inode)->free_extent_map_counts) != 0);
	list_del_init(&BTRFS_I(inode)->free_extent_map_inode);
	spin_unlock(&fs_info->extent_map_inode_list_lock);
#endif
	write_lock(&map_tree->lock);
	while (!RB_EMPTY_ROOT(&map_tree->map)) {
		struct extent_map *em;

		node = rb_first(&map_tree->map);
		em = rb_entry(node, struct extent_map, rb_node);
		clear_bit(EXTENT_FLAG_PINNED, &em->flags);
		clear_bit(EXTENT_FLAG_LOGGING, &em->flags);
		remove_extent_mapping(map_tree, em);
		free_extent_map(em);
	}
	write_unlock(&map_tree->lock);

	/*
	 * Keep looping until we have no more ranges in the io tree.
	 * We can have ongoing bios started by readpages (called from readahead)
	 * that didn't get their end io callbacks called yet or they are still
	 * in progress ((extent_io.c:end_bio_extent_readpage()). This means some
	 * ranges can still be locked and eviction started because before
	 * submitting those bios, which are executed by a separate task (work
	 * queue kthread), inode references (inode->i_count) were not taken
	 * (which would be dropped in the end io callback of each bio).
	 * Therefore here we effectively end up waiting for those bios and
	 * anyone else holding locked ranges without having bumped the inode's
	 * reference count - if we don't do it, when they access the inode's
	 * io_tree to unlock a range it may be too late, leading to an
	 * use-after-free issue.
	 */
	spin_lock(&io_tree->lock);
	while (!RB_EMPTY_ROOT(&io_tree->state)) {
		struct extent_state *state;
		struct extent_state *cached_state = NULL;
		u64 start;
		u64 end;

		node = rb_first(&io_tree->state);
		state = rb_entry(node, struct extent_state, rb_node);
#ifdef MY_DEF_HERE
		// It is possible that no one can unlock the extent for us, just free it all.
		if (unlikely(test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state))) {
			rb_erase(node, &io_tree->state);
			RB_CLEAR_NODE(node);
			free_extent_state(state);
			continue;
		}
#endif /* MY_DEF_HERE */
		start = state->start;
		end = state->end;
		spin_unlock(&io_tree->lock);

		lock_extent_bits(io_tree, start, end, 0, &cached_state);
		clear_extent_bit(io_tree, start, end,
				 EXTENT_LOCKED | EXTENT_DIRTY |
				 EXTENT_DELALLOC | EXTENT_DO_ACCOUNTING |
				 EXTENT_DEFRAG, 1, 1,
				 &cached_state, GFP_NOFS);

		spin_lock(&io_tree->lock);
	}
	spin_unlock(&io_tree->lock);
}

static struct btrfs_trans_handle *evict_refill_and_join(struct btrfs_root *root,
							struct btrfs_block_rsv *rsv,
							u64 min_size)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_block_rsv *global_rsv = &fs_info->global_block_rsv;
	int failures = 0;

	for (;;) {
		struct btrfs_trans_handle *trans;
		int ret;

		ret = btrfs_block_rsv_refill(root, rsv, min_size,
					     BTRFS_RESERVE_FLUSH_LIMIT);

		if (ret && ++failures > 2) {
			btrfs_warn(fs_info,
				   "could not allocate space for a delete; will truncate on mount");
			return ERR_PTR(-ENOSPC);
		}

		trans = btrfs_join_transaction(root);
		if (IS_ERR(trans) || !ret)
			return trans;

		/*
		 * Try to steal from the global reserve if there is space for
		 * it.
		 */
		if (!btrfs_check_space_for_delayed_refs(trans, root
#ifdef MY_DEF_HERE
			, false
#endif /* MY_DEF_HERE */
			) &&
		    !btrfs_block_rsv_migrate(global_rsv, rsv, min_size))
			return trans;

		/* If not, commit and try again. */
		ret = btrfs_commit_transaction(trans, root);
		if (ret)
			return ERR_PTR(ret);
	}
}

void btrfs_evict_inode(struct inode *inode)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_block_rsv *rsv;
	u64 min_size;
	int ret;
#ifdef MY_DEF_HERE
	u64 to_free = 0;
#endif /* MY_DEF_HERE */

	trace_btrfs_inode_evict(inode);

	if (!root) {
		clear_inode(inode);
		return;
	}

	min_size = btrfs_calc_trunc_metadata_size(root, 1);

	evict_inode_truncate_pages(inode);

#ifdef MY_DEF_HERE
	if (unlikely(test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state)))
		goto no_delete;
#endif

	if (inode->i_nlink &&
	    ((btrfs_root_refs(&root->root_item) != 0 &&
	      root->root_key.objectid != BTRFS_ROOT_TREE_OBJECTID) ||
	     btrfs_is_free_space_inode(inode)))
		goto no_delete;

	if (is_bad_inode(inode))
		goto no_delete;
	/* do we really want it for ->i_nlink > 0 and zero btrfs_root_refs? */
	if (!special_file(inode->i_mode))
		btrfs_wait_ordered_range(inode, 0, (u64)-1);

	btrfs_free_io_failure_record(inode, 0, (u64)-1);

	if (root->fs_info->log_root_recovering)
		goto no_delete;

	if (inode->i_nlink > 0) {
		BUG_ON(btrfs_root_refs(&root->root_item) != 0 &&
		       root->root_key.objectid != BTRFS_ROOT_TREE_OBJECTID);
		goto no_delete;
	}

	ret = btrfs_commit_inode_delayed_inode(inode);
	if (ret)
		goto no_delete;

	rsv = btrfs_alloc_block_rsv(root, BTRFS_BLOCK_RSV_TEMP);
	if (!rsv)
		goto no_delete;
	rsv->size = min_size;
	rsv->failfast = 1;

	btrfs_i_size_write(inode, 0);

	while (1) {
		trans = evict_refill_and_join(root, rsv, min_size);
		if (IS_ERR(trans))
			goto free_rsv;

		trans->block_rsv = rsv;

		ret = btrfs_truncate_inode_items(trans, root, inode, 0, 0);
		trans->block_rsv = &root->fs_info->trans_block_rsv;
		btrfs_end_transaction(trans, root);
		btrfs_btree_balance_dirty(root);
		if (ret && ret != -ENOSPC && ret != -EAGAIN)
			goto free_rsv;
		else if (!ret)
			break;
	}

	/*
	 * Errors here aren't a big deal, it just means we leave orphan items in
	 * the tree. They will be cleaned up on the next mount. If the inode
	 * number gets reused, cleanup deletes the orphan item without doing
	 * anything, and unlink reuses the existing orphan item.
	 *
	 * If it turns out that we are dropping too many of these, we might want
	 * to add a mechanism for retrying these after a commit.
	 */
	trans = evict_refill_and_join(root, rsv, min_size);
	if (!IS_ERR(trans)) {
		trans->block_rsv = rsv;
		btrfs_orphan_del(trans, inode);
		trans->block_rsv = &root->fs_info->trans_block_rsv;
		btrfs_end_transaction(trans, root);
	}

	if (!(root == root->fs_info->tree_root ||
	      root->root_key.objectid == BTRFS_TREE_RELOC_OBJECTID))
		btrfs_return_ino(root, btrfs_ino(inode));

free_rsv:
	btrfs_free_block_rsv(root, rsv);
no_delete:
#ifdef MY_DEF_HERE
	spin_lock(&BTRFS_I(inode)->lock);
	if (test_and_clear_bit(BTRFS_INODE_USRQUOTA_META_RESERVED,
			       &BTRFS_I(inode)->runtime_flags)) {
		to_free = btrfs_calc_trans_metadata_size(root, 1);
	}
	spin_unlock(&BTRFS_I(inode)->lock);
	if (to_free) {
		btrfs_block_rsv_release(root, &root->fs_info->delalloc_block_rsv, to_free);
	}
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	btrfs_syno_del_dirty_lru_inode(root->fs_info, inode);
#endif /* MY_DEF_HERE */
	/*
	 * If we didn't successfully delete, the orphan item will still be in
	 * the tree and we'll retry on the next mount. Again, we might also want
	 * to retry these periodically in the future.
	 */
	btrfs_remove_delayed_node(inode);
	clear_inode(inode);
	return;
}

/*
 * this returns the key found in the dir entry in the location pointer.
 * If no dir entries were found, location->objectid is 0.
 */
#ifdef MY_DEF_HERE
static int btrfs_inode_by_name(struct inode *dir, struct dentry *dentry,
			       struct btrfs_key *location, int caseless)
#else
static int btrfs_inode_by_name(struct inode *dir, struct dentry *dentry,
			       struct btrfs_key *location)
#endif /* MY_DEF_HERE */
{
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct btrfs_dir_item *di;
	struct btrfs_path *path;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

#ifdef MY_DEF_HERE
	if (caseless) {
		if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS) {
			path->caseless_key = 1;
		}
		path->caseless_name = 1;
	}
#endif /* MY_DEF_HERE */
	di = btrfs_lookup_dir_item(NULL, root, path, btrfs_ino(dir), name,
				    namelen, 0);
	if (IS_ERR(di))
		ret = PTR_ERR(di);

	if (IS_ERR_OR_NULL(di))
		goto out_err;

#ifdef MY_DEF_HERE
	if (caseless) {
		struct extent_buffer *leaf = path->nodes[0];
		int real_name_len = btrfs_dir_name_len(leaf, di);
		if (real_name_len > (DNAME_INLINE_LEN - 1) && real_name_len > dentry->d_name.len) {
			char *old_name = NULL;
			char *new_name = kmalloc(real_name_len + 1, GFP_KERNEL);
			if (!new_name) {
				goto out_err;
			}
			if (dentry->d_name.len > (DNAME_INLINE_LEN -1)) {
				old_name = (char *)dentry->d_name.name;
			}
			read_extent_buffer(leaf, (void *) new_name, (unsigned long)(di + 1), real_name_len);
			new_name[real_name_len] = 0;
			dentry->d_name.name = new_name;
			dentry->d_name.len = real_name_len;
			if (old_name)
				kfree(old_name);
		} else {
			read_extent_buffer(leaf, (void *) dentry->d_name.name, (unsigned long)(di + 1), real_name_len);
			((char *)dentry->d_name.name)[real_name_len] = 0;
			dentry->d_name.len = real_name_len;
		}
	}
#endif /* MY_DEF_HERE */
	btrfs_dir_item_key_to_cpu(path->nodes[0], di, location);
out:
	btrfs_free_path(path);
	return ret;
out_err:
	location->objectid = 0;
	goto out;
}

/*
 * when we hit a tree root in a directory, the btrfs part of the inode
 * needs to be changed to reflect the root directory of the tree root.  This
 * is kind of like crossing a mount point.
 */
static int fixup_tree_root_location(struct btrfs_root *root,
				    struct inode *dir,
				    struct dentry *dentry,
				    struct btrfs_key *location,
				    struct btrfs_root **sub_root)
{
	struct btrfs_path *path;
	struct btrfs_root *new_root;
	struct btrfs_root_ref *ref;
	struct extent_buffer *leaf;
	int ret;
	int err = 0;

	path = btrfs_alloc_path();
	if (!path) {
		err = -ENOMEM;
		goto out;
	}

	err = -ENOENT;
	ret = btrfs_find_item(root->fs_info->tree_root, path,
				BTRFS_I(dir)->root->root_key.objectid,
				location->objectid, BTRFS_ROOT_REF_KEY, NULL);
	if (ret) {
		if (ret < 0)
			err = ret;
		goto out;
	}

	leaf = path->nodes[0];
	ref = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_root_ref);
	if (btrfs_root_ref_dirid(leaf, ref) != btrfs_ino(dir) ||
	    btrfs_root_ref_name_len(leaf, ref) != dentry->d_name.len)
		goto out;

	ret = memcmp_extent_buffer(leaf, dentry->d_name.name,
				   (unsigned long)(ref + 1),
				   dentry->d_name.len);
	if (ret)
		goto out;

	btrfs_release_path(path);

	new_root = btrfs_read_fs_root_no_name(root->fs_info, location);
	if (IS_ERR(new_root)) {
		err = PTR_ERR(new_root);
		goto out;
	}

	*sub_root = new_root;
	location->objectid = btrfs_root_dirid(&new_root->root_item);
	location->type = BTRFS_INODE_ITEM_KEY;
	location->offset = 0;
	err = 0;
out:
	btrfs_free_path(path);
	return err;
}

static void inode_tree_add(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_inode *entry;
	struct rb_node **p;
	struct rb_node *parent;
	struct rb_node *new = &BTRFS_I(inode)->rb_node;
	u64 ino = btrfs_ino(inode);

	if (inode_unhashed(inode))
		return;
	parent = NULL;
	spin_lock(&root->inode_lock);
	p = &root->inode_tree.rb_node;
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct btrfs_inode, rb_node);

		if (ino < btrfs_ino(&entry->vfs_inode))
			p = &parent->rb_left;
		else if (ino > btrfs_ino(&entry->vfs_inode))
			p = &parent->rb_right;
		else {
			WARN_ON(!(entry->vfs_inode.i_state &
				  (I_WILL_FREE | I_FREEING)));
			rb_replace_node(parent, new, &root->inode_tree);
			RB_CLEAR_NODE(parent);
			spin_unlock(&root->inode_lock);
			return;
		}
	}
	rb_link_node(new, parent, p);
	rb_insert_color(new, &root->inode_tree);
	spin_unlock(&root->inode_lock);
}

static void inode_tree_del(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int empty = 0;

	spin_lock(&root->inode_lock);
	if (!RB_EMPTY_NODE(&BTRFS_I(inode)->rb_node)) {
		rb_erase(&BTRFS_I(inode)->rb_node, &root->inode_tree);
		RB_CLEAR_NODE(&BTRFS_I(inode)->rb_node);
		empty = RB_EMPTY_ROOT(&root->inode_tree);
	}
	spin_unlock(&root->inode_lock);

	if (empty && btrfs_root_refs(&root->root_item) == 0) {
#ifdef MY_DEF_HERE
		/*
		 * Don't backport the following patch:
		 * [PATCH] btrfs: do not call synchronize_srcu() in inode_tree_del
		 * we've fixed that deadlock through the other way.
		 * And that fix need this.
		 */
#endif /* MY_DEF_HERE */
		synchronize_srcu(&root->fs_info->subvol_srcu);
		spin_lock(&root->inode_lock);
		empty = RB_EMPTY_ROOT(&root->inode_tree);
		spin_unlock(&root->inode_lock);
#ifdef MY_DEF_HERE
		if (empty && atomic_read(&root->use_refs) == 0)
			btrfs_add_dead_root(root);
#else
		if (empty)
			btrfs_add_dead_root(root);
#endif /* MY_DEF_HERE */
	}
}

void btrfs_invalidate_inodes(struct btrfs_root *root)
{
	struct rb_node *node;
	struct rb_node *prev;
	struct btrfs_inode *entry;
	struct inode *inode;
	u64 objectid = 0;

	if (!test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state))
		WARN_ON(btrfs_root_refs(&root->root_item) != 0);

	spin_lock(&root->inode_lock);
again:
	node = root->inode_tree.rb_node;
	prev = NULL;
	while (node) {
		prev = node;
		entry = rb_entry(node, struct btrfs_inode, rb_node);

		if (objectid < btrfs_ino(&entry->vfs_inode))
			node = node->rb_left;
		else if (objectid > btrfs_ino(&entry->vfs_inode))
			node = node->rb_right;
		else
			break;
	}
	if (!node) {
		while (prev) {
			entry = rb_entry(prev, struct btrfs_inode, rb_node);
			if (objectid <= btrfs_ino(&entry->vfs_inode)) {
				node = prev;
				break;
			}
			prev = rb_next(prev);
		}
	}
	while (node) {
		entry = rb_entry(node, struct btrfs_inode, rb_node);
		objectid = btrfs_ino(&entry->vfs_inode) + 1;
		inode = igrab(&entry->vfs_inode);
		if (inode) {
			spin_unlock(&root->inode_lock);
			if (atomic_read(&inode->i_count) > 1)
				d_prune_aliases(inode);
			/*
			 * btrfs_drop_inode will have it removed from
			 * the inode cache when its usage count
			 * hits zero.
			 */
			iput(inode);
			cond_resched();
			spin_lock(&root->inode_lock);
			goto again;
		}

		if (cond_resched_lock(&root->inode_lock))
			goto again;

		node = rb_next(node);
	}
	spin_unlock(&root->inode_lock);
}

static int btrfs_init_locked_inode(struct inode *inode, void *p)
{
	struct btrfs_iget_args *args = p;
	inode->i_ino = args->location->objectid;
	memcpy(&BTRFS_I(inode)->location, args->location,
	       sizeof(*args->location));
	BTRFS_I(inode)->root = args->root;
	return 0;
}

static int btrfs_find_actor(struct inode *inode, void *opaque)
{
	struct btrfs_iget_args *args = opaque;
	return args->location->objectid == BTRFS_I(inode)->location.objectid &&
		args->root == BTRFS_I(inode)->root;
}

static struct inode *btrfs_iget_locked(struct super_block *s,
				       struct btrfs_key *location,
				       struct btrfs_root *root)
{
	struct inode *inode;
	struct btrfs_iget_args args;
	unsigned long hashval = btrfs_inode_hash(location->objectid, root);

	args.location = location;
	args.root = root;

	inode = iget5_locked(s, hashval, btrfs_find_actor,
			     btrfs_init_locked_inode,
			     (void *)&args);
	return inode;
}

/* Get an inode object given its location and corresponding root.
 * Returns in *is_new if the inode was read from disk
 */
struct inode *btrfs_iget(struct super_block *s, struct btrfs_key *location,
			 struct btrfs_root *root, int *new)
{
	struct inode *inode;

	inode = btrfs_iget_locked(s, location, root);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		int ret;

		ret = btrfs_read_locked_inode(inode);
		if (!is_bad_inode(inode)) {
#ifdef MY_DEF_HERE
			int retval;
			__le32 archive_bit;
#endif /* MY_DEF_HERE */
			inode_tree_add(inode);
			unlock_new_inode(inode);
			if (new)
				*new = 1;
#ifdef MY_DEF_HERE
			retval = __btrfs_getxattr(inode, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_BIT, &archive_bit, sizeof(archive_bit));
			if (0 < retval) {
				inode->i_archive_bit = le32_to_cpu(archive_bit);
			} else {
				inode->i_archive_bit = 0;
			}
#endif /* MY_DEF_HERE */
		} else {
			unlock_new_inode(inode);
			iput(inode);
			ASSERT(ret < 0);
			inode = ERR_PTR(ret < 0 ? ret : -ESTALE);
		}
	}

	return inode;
}

static struct inode *new_simple_dir(struct super_block *s,
				    struct btrfs_key *key,
				    struct btrfs_root *root)
{
	struct inode *inode = new_inode(s);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	BTRFS_I(inode)->root = root;
	memcpy(&BTRFS_I(inode)->location, key, sizeof(*key));
	set_bit(BTRFS_INODE_DUMMY, &BTRFS_I(inode)->runtime_flags);

	inode->i_ino = BTRFS_EMPTY_SUBVOL_DIR_OBJECTID;
	inode->i_op = &btrfs_dir_ro_inode_operations;
	inode->i_fop = &simple_dir_operations;
	inode->i_mode = S_IFDIR | S_IRUGO | S_IWUSR | S_IXUGO;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	return inode;
}

#ifdef MY_DEF_HERE
struct inode *btrfs_lookup_dentry(struct inode *dir, struct dentry *dentry, int caseless)
#else
struct inode *btrfs_lookup_dentry(struct inode *dir, struct dentry *dentry)
#endif /* MY_DEF_HERE */
{
	struct inode *inode;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_root *sub_root = root;
	struct btrfs_key location;
	int index;
	int ret = 0;

	if (dentry->d_name.len > BTRFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

#ifdef MY_DEF_HERE
	ret = btrfs_inode_by_name(dir, dentry, &location, caseless);
#else
	ret = btrfs_inode_by_name(dir, dentry, &location);
#endif /* MY_DEF_HERE */
	if (ret < 0)
		return ERR_PTR(ret);

	if (location.objectid == 0)
		return ERR_PTR(-ENOENT);

	if (location.type == BTRFS_INODE_ITEM_KEY) {
		inode = btrfs_iget(dir->i_sb, &location, root, NULL);
		return inode;
	}

	BUG_ON(location.type != BTRFS_ROOT_ITEM_KEY);

	index = srcu_read_lock(&root->fs_info->subvol_srcu);
	ret = fixup_tree_root_location(root, dir, dentry,
				       &location, &sub_root);
#ifdef MY_DEF_HERE
	if (!ret)
		btrfs_hold_fs_root(sub_root);
	srcu_read_unlock(&root->fs_info->subvol_srcu, index);
#endif /* MY_DEF_HERE */
	if (ret < 0) {
		if (ret != -ENOENT)
			inode = ERR_PTR(ret);
		else
			inode = new_simple_dir(dir->i_sb, &location, sub_root);
	} else {
		inode = btrfs_iget(dir->i_sb, &location, sub_root, NULL);
	}
#ifdef MY_DEF_HERE
	if (!ret)
		btrfs_release_fs_root(sub_root);
#else
	srcu_read_unlock(&root->fs_info->subvol_srcu, index);
#endif /* MY_DEF_HERE */

	if (!IS_ERR(inode) && root != sub_root) {
		down_read(&root->fs_info->cleanup_work_sem);
		if (!(inode->i_sb->s_flags & MS_RDONLY))
			ret = btrfs_orphan_cleanup(sub_root);
		up_read(&root->fs_info->cleanup_work_sem);
		if (ret) {
			iput(inode);
			inode = ERR_PTR(ret);
		}
	}

	return inode;
}

static int btrfs_dentry_delete(const struct dentry *dentry)
{
	struct btrfs_root *root;
	struct inode *inode = dentry->d_inode;

	if (!inode && !IS_ROOT(dentry))
		inode = dentry->d_parent->d_inode;

	if (inode) {
		root = BTRFS_I(inode)->root;
		if (btrfs_root_refs(&root->root_item) == 0)
			return 1;

		if (btrfs_ino(inode) == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)
			return 1;
	}
	return 0;
}

static void btrfs_dentry_release(struct dentry *dentry)
{
	kfree(dentry->d_fsdata);
}

static struct dentry *btrfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct inode *inode;

#ifdef MY_DEF_HERE
	inode = btrfs_lookup_dentry(dir, dentry, (flags & LOOKUP_CASELESS_COMPARE)?1:0);
#else
	inode = btrfs_lookup_dentry(dir, dentry);
#endif /* MY_DEF_HERE */
	if (IS_ERR(inode)) {
		if (PTR_ERR(inode) == -ENOENT)
			inode = NULL;
		else
			return ERR_CAST(inode);
	}

	return d_materialise_unique(dentry, inode);
}

unsigned char btrfs_filetype_table[] = {
	DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK
};

/*
 * All this infrastructure exists because dir_emit can fault, and we are holding
 * the tree lock when doing readdir.  For now just allocate a buffer and copy
 * our information into that, and then dir_emit from the buffer.  This is
 * similar to what NFS does, only we don't keep the buffer around in pagecache
 * because I'm afraid I'll mess that up.  Long term we need to make filldir do
 * copy_to_user_inatomic so we don't have to worry about page faulting under the
 * tree lock.
 */
static int btrfs_opendir(struct inode *inode, struct file *file)
{
	struct btrfs_file_private *private;

	private = kzalloc(sizeof(struct btrfs_file_private), GFP_KERNEL);
	if (!private)
		return -ENOMEM;
	private->filldir_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!private->filldir_buf) {
		kfree(private);
		return -ENOMEM;
	}
	file->private_data = private;
	return 0;
}

struct dir_entry {
	u64 ino;
	u64 offset;
	unsigned type;
	int name_len;
#ifdef MY_DEF_HERE
	int hidden;
#endif /* MY_DEF_HERE */
};

static int btrfs_filldir(struct file *filp, void *dirent, filldir_t filldir, void *addr, int entries)
{
	while (entries--) {
		struct dir_entry *entry = addr;
		char *name = (char *)(entry + 1);

		filp->f_pos = get_unaligned(&entry->offset);
#ifdef MY_DEF_HERE
		if (get_unaligned(&entry->hidden)) {
			goto skip;
		}
#endif /* MY_DEF_HERE */
		if (filldir(dirent, name, get_unaligned(&entry->name_len),
			       filp->f_pos, get_unaligned(&entry->ino),
			       get_unaligned(&entry->type)))
			return 1;
#ifdef MY_DEF_HERE
skip:
#endif /* MY_DEF_HERE */
		addr += sizeof(struct dir_entry) +
			get_unaligned(&entry->name_len);
		filp->f_pos++;
	}
	return 0;
}

static int btrfs_real_readdir(struct file *filp, void *dirent,
			      filldir_t filldir)
{
	struct inode *inode = file_inode(filp);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_file_private *private = filp->private_data;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct btrfs_path *path;
	void *addr;
	struct list_head ins_list;
	struct list_head del_list;
	int ret;
	struct extent_buffer *leaf;
	int slot;
	int over = 0;
	char *name_ptr;
	int name_len;
	int entries = 0;
	int total_len = 0;
	struct btrfs_key location;

	/* special case for "." */
	if (filp->f_pos == 0) {
		over = filldir(dirent, ".", 1,
			       filp->f_pos, btrfs_ino(inode), DT_DIR);
		if (over)
			return 0;
		filp->f_pos = 1;
	}
	/* special case for .., just use the back ref */
	if (filp->f_pos == 1) {
		u64 pino = parent_ino(filp->f_path.dentry);
		over = filldir(dirent, "..", 2,
			       filp->f_pos, pino, DT_DIR);
		if (over)
			return 0;
		filp->f_pos = 2;
	}
	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	addr = private->filldir_buf;
	path->reada = READA_FORWARD;

	INIT_LIST_HEAD(&ins_list);
	INIT_LIST_HEAD(&del_list);
	btrfs_get_delayed_items(inode, &ins_list, &del_list);

again:
	key.type = BTRFS_DIR_INDEX_KEY;
	key.offset = filp->f_pos;
	key.objectid = btrfs_ino(inode);

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto err;

	while (1) {
		struct dir_entry *entry;

		leaf = path->nodes[0];
		slot = path->slots[0];
		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto err;
			else if (ret > 0)
				break;
			continue;
		}

		btrfs_item_key_to_cpu(leaf, &found_key, slot);

		if (found_key.objectid != key.objectid)
			break;
		if (found_key.type != BTRFS_DIR_INDEX_KEY)
			break;
		if (found_key.offset < filp->f_pos)
			goto next;
		if (btrfs_should_delete_dir_index(&del_list, found_key.offset))
			goto next;
		di = btrfs_item_ptr(leaf, slot, struct btrfs_dir_item);
		if (verify_dir_item(root, leaf, di))
			goto next;

		name_len = btrfs_dir_name_len(leaf, di);
		if ((total_len + sizeof(struct dir_entry) + name_len) >=
		    PAGE_SIZE) {
			btrfs_release_path(path);
			ret = btrfs_filldir(filp, dirent, filldir, private->filldir_buf, entries);
			if (ret)
				goto nopos;
			addr = private->filldir_buf;
			entries = 0;
			total_len = 0;
			goto again;
		}

		entry = addr;
		put_unaligned(name_len, &entry->name_len);
		name_ptr = (char *)(entry + 1);
		read_extent_buffer(leaf, name_ptr, (unsigned long)(di + 1),
				   name_len);
		put_unaligned(btrfs_filetype_table[btrfs_dir_type(leaf, di)],
				&entry->type);
		btrfs_dir_item_key_to_cpu(leaf, di, &location);

#ifdef MY_DEF_HERE
		put_unaligned(0, &entry->hidden);
		if (location.type == BTRFS_ROOT_ITEM_KEY) {
			struct btrfs_root *subvol_root = btrfs_read_fs_root_no_name(root->fs_info, &location);
			if (!IS_ERR(subvol_root) && btrfs_root_hide(subvol_root)) {
				put_unaligned(1, &entry->hidden);
			}
		}
#endif /* MY_DEF_HERE */

		put_unaligned(location.objectid, &entry->ino);
		put_unaligned(found_key.offset, &entry->offset);
		entries++;
		addr += sizeof(struct dir_entry) + name_len;
		total_len += sizeof(struct dir_entry) + name_len;
next:
		path->slots[0]++;
	}
	btrfs_release_path(path);

	ret = btrfs_filldir(filp, dirent, filldir, private->filldir_buf, entries);
	if (ret)
		goto nopos;

	ret = btrfs_readdir_delayed_dir_index(filp, dirent, filldir,
					      &ins_list);
	if (ret)
		goto nopos;

	/*
	 * Stop new entries from being returned after we return the last
	 * entry.
	 *
	 * New directory entries are assigned a strictly increasing
	 * offset.  This means that new entries created during readdir
	 * are *guaranteed* to be seen in the future by that readdir.
	 * This has broken buggy programs which operate on names as
	 * they're returned by readdir.  Until we re-use freed offsets
	 * we have this hack to stop new entries from being returned
	 * under the assumption that they'll never reach this huge
	 * offset.
	 *
	 * This is being careful not to overflow 32bit loff_t unless the
	 * last entry requires it because doing so has broken 32bit apps
	 * in the past.
	 */
	if (filp->f_pos >= INT_MAX)
		filp->f_pos = LLONG_MAX;
	else
		filp->f_pos = INT_MAX;
nopos:
	ret = 0;
err:
	btrfs_put_delayed_items(&ins_list, &del_list);
	btrfs_free_path(path);
	return ret;
}

int btrfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	int ret = 0;
	bool nolock = false;

	if (test_bit(BTRFS_INODE_DUMMY, &BTRFS_I(inode)->runtime_flags))
		return 0;

	if (btrfs_fs_closing(root->fs_info) && btrfs_is_free_space_inode(inode))
		nolock = true;

	if (wbc->sync_mode == WB_SYNC_ALL) {
		if (nolock)
			trans = btrfs_join_transaction_nolock(root);
		else
			trans = btrfs_join_transaction(root);
		if (IS_ERR(trans))
			return PTR_ERR(trans);
		ret = btrfs_commit_transaction(trans, root);
	}
	return ret;
}

/*
 * This is somewhat expensive, updating the tree every time the
 * inode changes.  But, it is most likely to find the inode in cache.
 * FIXME, needs more benchmarking...there are no reasons other than performance
 * to keep or drop this code.
 */
static int btrfs_dirty_inode(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	int ret;

	if (test_bit(BTRFS_INODE_DUMMY, &BTRFS_I(inode)->runtime_flags))
		return 0;

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	ret = btrfs_update_inode(trans, root, inode);
	if (ret && ret == -ENOSPC) {
		/* whoops, lets try again with the full transaction */
		btrfs_end_transaction(trans, root);
		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans))
			return PTR_ERR(trans);

		ret = btrfs_update_inode(trans, root, inode);
	}
	btrfs_end_transaction(trans, root);
	if (BTRFS_I(inode)->delayed_node)
		btrfs_balance_delayed_items(root);

	return ret;
}

/*
 * This is a copy of file_update_time.  We need this so we can return error on
 * ENOSPC for updating the inode in the case of file write and mmap writes.
 */
static int btrfs_update_time(struct inode *inode, struct timespec *now,
			     int flags)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (btrfs_root_readonly(root))
		return -EROFS;

	if (flags & S_VERSION)
		inode_inc_iversion(inode);
	if (flags & S_CTIME)
		inode->i_ctime = *now;
	if (flags & S_MTIME)
		inode->i_mtime = *now;
	if (flags & S_ATIME)
		inode->i_atime = *now;
	return btrfs_dirty_inode(inode);
}

/*
 * find the highest existing sequence number in a directory
 * and then set the in-memory index_cnt variable to reflect
 * free sequence numbers
 */
static int btrfs_set_inode_index_count(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_key key, found_key;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	int ret;

	key.objectid = btrfs_ino(inode);
	btrfs_set_key_type(&key, BTRFS_DIR_INDEX_KEY);
	key.offset = (u64)-1;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto out;
	/* FIXME: we should be able to handle this */
	if (ret == 0)
		goto out;
	ret = 0;

	/*
	 * MAGIC NUMBER EXPLANATION:
	 * since we search a directory based on f_pos we have to start at 2
	 * since '.' and '..' have f_pos of 0 and 1 respectively, so everybody
	 * else has to start at 2
	 */
	if (path->slots[0] == 0) {
		BTRFS_I(inode)->index_cnt = 2;
		goto out;
	}

	path->slots[0]--;

	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);

	if (found_key.objectid != btrfs_ino(inode) ||
	    btrfs_key_type(&found_key) != BTRFS_DIR_INDEX_KEY) {
		BTRFS_I(inode)->index_cnt = 2;
		goto out;
	}

	BTRFS_I(inode)->index_cnt = found_key.offset + 1;
out:
	btrfs_free_path(path);
	return ret;
}

/*
 * helper to find a free sequence number in a given directory.  This current
 * code is very simple, later versions will do smarter things in the btree
 */
int btrfs_set_inode_index(struct inode *dir, u64 *index)
{
	int ret = 0;

	if (BTRFS_I(dir)->index_cnt == (u64)-1) {
		ret = btrfs_inode_delayed_dir_index_count(dir);
		if (ret) {
			ret = btrfs_set_inode_index_count(dir);
			if (ret)
				return ret;
		}
	}

	*index = BTRFS_I(dir)->index_cnt;
	BTRFS_I(dir)->index_cnt++;

	return ret;
}

static int btrfs_insert_inode_locked(struct inode *inode)
{
	struct btrfs_iget_args args;
	args.location = &BTRFS_I(inode)->location;
	args.root = BTRFS_I(inode)->root;

	return insert_inode_locked4(inode,
		   btrfs_inode_hash(inode->i_ino, BTRFS_I(inode)->root),
		   btrfs_find_actor, &args);
}

static struct inode *btrfs_new_inode(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     struct inode *dir,
				     const char *name, int name_len,
				     u64 ref_objectid, u64 objectid,
				     umode_t mode, u64 *index)
{
	struct inode *inode;
	struct btrfs_inode_item *inode_item;
	struct btrfs_key *location;
	struct btrfs_path *path;
	struct btrfs_inode_ref *ref;
	struct btrfs_key key[2];
	u32 sizes[2];
	unsigned long ptr;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return ERR_PTR(-ENOMEM);

	inode = new_inode(root->fs_info->sb);
	if (!inode) {
		btrfs_free_path(path);
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * we have to initialize this early, so we can reclaim the inode
	 * number if we fail afterwards in this function.
	 */
	inode->i_ino = objectid;

	if (dir) {
		trace_btrfs_inode_request(dir);

		ret = btrfs_set_inode_index(dir, index);
		if (ret) {
			btrfs_free_path(path);
			iput(inode);
			return ERR_PTR(ret);
		}
	}
	/*
	 * index_cnt is ignored for everything but a dir,
	 * btrfs_get_inode_index_count has an explanation for the magic
	 * number
	 */
	BTRFS_I(inode)->index_cnt = 2;
#ifdef MY_DEF_HERE
#else
	BTRFS_I(inode)->dir_index = *index;
#endif /* MY_DEF_HERE */
	BTRFS_I(inode)->root = root;
	BTRFS_I(inode)->generation = trans->transid;
	inode->i_generation = BTRFS_I(inode)->generation;

	/*
	 * We could have gotten an inode number from somebody who was fsynced
	 * and then removed in this same transaction, so let's just set full
	 * sync since it will be a full sync anyway and this will blow away the
	 * old info in the log.
	 */
	set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &BTRFS_I(inode)->runtime_flags);

	key[0].objectid = objectid;
	btrfs_set_key_type(&key[0], BTRFS_INODE_ITEM_KEY);
	key[0].offset = 0;

	/*
	 * Start new inodes with an inode_ref. This is slightly more
	 * efficient for small numbers of hard links since they will
	 * be packed into one item. Extended refs will kick in if we
	 * add more hard links than can fit in the ref item.
	 */
	key[1].objectid = objectid;
	btrfs_set_key_type(&key[1], BTRFS_INODE_REF_KEY);
	key[1].offset = ref_objectid;

	sizes[0] = sizeof(struct btrfs_inode_item);
	sizes[1] = name_len + sizeof(*ref);

	location = &BTRFS_I(inode)->location;
	location->objectid = objectid;
	location->offset = 0;
	btrfs_set_key_type(location, BTRFS_INODE_ITEM_KEY);

	ret = btrfs_insert_inode_locked(inode);
	if (ret < 0)
		goto fail;

	path->leave_spinning = 1;
	ret = btrfs_insert_empty_items(trans, root, path, key, sizes, 2);
	if (ret != 0)
		goto fail_unlock;

	inode_init_owner(inode, dir, mode);
	inode_set_bytes(inode, 0);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode_item = btrfs_item_ptr(path->nodes[0], path->slots[0],
				  struct btrfs_inode_item);
	memset_extent_buffer(path->nodes[0], 0, (unsigned long)inode_item,
			     sizeof(*inode_item));
	fill_inode_item(trans, path->nodes[0], inode_item, inode);

	ref = btrfs_item_ptr(path->nodes[0], path->slots[0] + 1,
			     struct btrfs_inode_ref);
	btrfs_set_inode_ref_name_len(path->nodes[0], ref, name_len);
	btrfs_set_inode_ref_index(path->nodes[0], ref, *index);
	ptr = (unsigned long)(ref + 1);
	write_extent_buffer(path->nodes[0], name, ptr, name_len);

	btrfs_mark_buffer_dirty(path->nodes[0]);
	btrfs_free_path(path);

	btrfs_inherit_iflags(inode, dir);

	if (S_ISREG(mode)) {
		if (btrfs_test_opt(root, NODATASUM))
			BTRFS_I(inode)->flags |= BTRFS_INODE_NODATASUM;
		if (btrfs_test_opt(root, NODATACOW))
			BTRFS_I(inode)->flags |= BTRFS_INODE_NODATACOW |
				BTRFS_INODE_NODATASUM;
#ifdef MY_DEF_HERE
		if (root->fs_info->usrquota_enabled &&
#ifdef MY_DEF_HERE
			!btrfs_root_disable_quota(root) &&
#endif /* MY_DEF_HERE */
			btrfs_usrquota_compat_inode_quota(root->fs_info) &&
			(root->objectid == BTRFS_FS_TREE_OBJECTID || (root->objectid >= BTRFS_FIRST_FREE_OBJECTID && root->objectid <= BTRFS_LAST_FREE_OBJECTID))) {
			BTRFS_I(inode)->flags |= BTRFS_INODE_UQ_REF_USED;
		}
#endif /* MY_DEF_HERE */
	}

	inode_tree_add(inode);

	trace_btrfs_inode_new(inode);
	btrfs_set_inode_last_trans(trans, inode);

	btrfs_update_root_times(trans, root);

	ret = btrfs_inode_inherit_props(trans, inode, dir);
	if (ret)
		btrfs_err(root->fs_info,
			  "error inheriting props for ino %llu (root %llu): %d",
			  btrfs_ino(inode), root->root_key.objectid, ret);

	return inode;

fail_unlock:
	unlock_new_inode(inode);
fail:
	if (dir)
		BTRFS_I(dir)->index_cnt--;
	btrfs_free_path(path);
	iput(inode);
	return ERR_PTR(ret);
}

static inline u8 btrfs_inode_type(struct inode *inode)
{
	return btrfs_type_by_mode[(inode->i_mode & S_IFMT) >> S_SHIFT];
}

/*
 * utility function to add 'inode' into 'parent_inode' with
 * a give name and a given sequence number.
 * if 'add_backref' is true, also insert a backref from the
 * inode to the parent directory.
 */
int btrfs_add_link(struct btrfs_trans_handle *trans,
		   struct inode *parent_inode, struct inode *inode,
		   const char *name, int name_len, int add_backref, u64 index)
{
	int ret = 0;
	struct btrfs_key key;
	struct btrfs_root *root = BTRFS_I(parent_inode)->root;
	u64 ino = btrfs_ino(inode);
	u64 parent_ino = btrfs_ino(parent_inode);

	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		memcpy(&key, &BTRFS_I(inode)->root->root_key, sizeof(key));
	} else {
		key.objectid = ino;
		btrfs_set_key_type(&key, BTRFS_INODE_ITEM_KEY);
		key.offset = 0;
	}

	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		ret = btrfs_add_root_ref(trans, root->fs_info->tree_root,
					 key.objectid, root->root_key.objectid,
					 parent_ino, index, name, name_len);
	} else if (add_backref) {
		ret = btrfs_insert_inode_ref(trans, root, name, name_len, ino,
					     parent_ino, index);
	}

	/* Nothing to clean up yet */
	if (ret)
		return ret;

	ret = btrfs_insert_dir_item(trans, root, name, name_len,
				    parent_inode, &key,
				    btrfs_inode_type(inode), index);
	if (ret == -EEXIST || ret == -EOVERFLOW)
		goto fail_dir_item;
	else if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		return ret;
	}

	btrfs_i_size_write(parent_inode, parent_inode->i_size +
			   name_len * 2);
	inode_inc_iversion(parent_inode);
	parent_inode->i_mtime = parent_inode->i_ctime = CURRENT_TIME;
	ret = btrfs_update_inode(trans, root, parent_inode);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
	return ret;

fail_dir_item:
	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		u64 local_index;
		int err;
		err = btrfs_del_root_ref(trans, root->fs_info->tree_root,
				 key.objectid, root->root_key.objectid,
				 parent_ino, &local_index, name, name_len);

	} else if (add_backref) {
		u64 local_index;
		int err;

		err = btrfs_del_inode_ref(trans, root, name, name_len,
					  ino, parent_ino, &local_index);
	}
	return ret;
}

static int btrfs_add_nondir(struct btrfs_trans_handle *trans,
			    struct inode *dir, struct dentry *dentry,
			    struct inode *inode, int backref, u64 index)
{
	int err = btrfs_add_link(trans, dir, inode,
				 dentry->d_name.name, dentry->d_name.len,
				 backref, index);
	if (err > 0)
		err = -EEXIST;
	return err;
}

static int btrfs_mknod(struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct inode *inode = NULL;
	int err;
	int drop_inode = 0;
	u64 objectid;
	u64 index = 0;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	int credit_for_syno = 0;
#endif

	if (!new_valid_dev(rdev))
		return -EINVAL;

#ifdef MY_DEF_HERE
	err = btrfs_check_dir_item_collision(root, dir->i_ino, 0,
			     dentry->d_name.name, dentry->d_name.len);
	if (err)
		return err;
	// 1 for dir_item_caseless
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		credit_for_syno++;
#endif

#ifdef MY_DEF_HERE
	// 1 for the prop for compression
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif
	/*
	 * 2 for inode item and ref
	 * 2 for dir items
	 * 1 for xattr if selinux is on
	 */
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	trans = btrfs_start_transaction(root, 5 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 5);
#endif /* MY_DEF_HERE || MY_DEF_HERE */
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_unlock;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				mode, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_unlock;
	}

	/*
	* If the active LSM wants to access the inode during
	* d_instantiate it needs these. Smack checks to see
	* if the filesystem supports xattrs by looking at the
	* ops vector.
	*/
	inode->i_op = &btrfs_special_inode_operations;
	init_special_inode(inode, inode->i_mode, rdev);

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_unlock_inode;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err)
		goto out_unlock_inode;
#endif /* MY_DEF_HERE || MY_DEF_HERE */

	err = btrfs_add_nondir(trans, dir, dentry, inode, 0, index);
	if (err) {
		goto out_unlock_inode;
	} else {
		btrfs_update_inode(trans, root, inode);
		unlock_new_inode(inode);
		d_instantiate(dentry, inode);
	}

out_unlock:
	btrfs_end_transaction(trans, root);
	btrfs_balance_delayed_items(root);
	btrfs_btree_balance_dirty(root);
	if (drop_inode) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	return err;

out_unlock_inode:
	drop_inode = 1;
	unlock_new_inode(inode);
	goto out_unlock;

}

static int btrfs_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, bool excl)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct inode *inode = NULL;
	int drop_inode_on_err = 0;
	int err;
	u64 objectid;
	u64 index = 0;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	int credit_for_syno = 0;
#endif

#ifdef MY_DEF_HERE
	err = btrfs_check_dir_item_collision(root, dir->i_ino, 0,
			     dentry->d_name.name, dentry->d_name.len);
	if (err)
		return err;
	// 1 for dir_item_caseless
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		credit_for_syno++;
#endif

#ifdef MY_DEF_HERE
	// 1 for the prop for compression
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif
	/*
	 * 2 for inode item and ref
	 * 2 for dir items
	 * 1 for xattr if selinux is on
	 */
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	trans = btrfs_start_transaction(root, 5 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 5);
#endif /* MY_DEF_HERE || MY_DEF_HERE */
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_unlock;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				mode, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_unlock;
	}
	drop_inode_on_err = 1;

	/*
	* If the active LSM wants to access the inode during
	* d_instantiate it needs these. Smack checks to see
	* if the filesystem supports xattrs by looking at the
	* ops vector.
	*/
	inode->i_fop = &btrfs_file_operations;
	inode->i_op = &btrfs_file_inode_operations;
	inode->i_mapping->a_ops = &btrfs_aops;
	inode->i_mapping->backing_dev_info = &root->fs_info->bdi;

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_unlock_inode;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err)
		goto out_unlock_inode;
#endif /* MY_DEF_HERE || MY_DEF_HERE */

	err = btrfs_update_inode(trans, root, inode);
	if (err)
		goto out_unlock_inode;

	err = btrfs_add_nondir(trans, dir, dentry, inode, 0, index);
	if (err)
		goto out_unlock_inode;

	BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;
	unlock_new_inode(inode);
	d_instantiate(dentry, inode);

out_unlock:
	btrfs_end_transaction(trans, root);
	if (err && drop_inode_on_err) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	btrfs_balance_delayed_items(root);
	btrfs_btree_balance_dirty(root);
	return err;

out_unlock_inode:
	unlock_new_inode(inode);
	goto out_unlock;

}

static int btrfs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct inode *inode = old_dentry->d_inode;
	u64 index;
	int err;
	int drop_inode = 0;
#ifdef MY_DEF_HERE
	int credit_for_syno = 0;
#endif /* MY_DEF_HERE */

	/* do not allow sys_link's with other subvols of the same device */
	if (root->objectid != BTRFS_I(inode)->root->objectid)
		return -EXDEV;

	if (inode->i_nlink >= BTRFS_LINK_MAX)
		return -EMLINK;

#ifdef MY_DEF_HERE
	err = btrfs_check_dir_item_collision(root, dir->i_ino, 0,
			     dentry->d_name.name, dentry->d_name.len);
	if (err)
		return err;
#endif /* MY_DEF_HERE */

	err = btrfs_set_inode_index(dir, &index);
	if (err)
		goto fail;

	/*
	 * 2 items for inode and inode ref
	 * 2 items for dir items
	 * 1 item for parent inode
	 * 1 item for orphan item deletion if O_TMPFILE
	 */
#ifdef MY_DEF_HERE
	/*
	 * 1 item for dir caseless item if CASELESS FEATURE support
	 */
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		credit_for_syno++;
#endif /* MY_DEF_HERE */

	trans = btrfs_start_transaction(root
#ifdef MY_DEF_HERE
									, inode->i_nlink ? 5 + credit_for_syno: 6 + credit_for_syno
#else
									, inode->i_nlink ? 5 : 6
#endif /* MY_DEF_HERE */
									);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto fail;
	}

#ifdef MY_DEF_HERE
#else
	/* There are several dir indexes for this inode, clear the cache. */
	BTRFS_I(inode)->dir_index = 0ULL;
#endif /* MY_DEF_HERE */
	inc_nlink(inode);
	inode_inc_iversion(inode);
	inode->i_ctime = CURRENT_TIME;
	ihold(inode);
	set_bit(BTRFS_INODE_COPY_EVERYTHING, &BTRFS_I(inode)->runtime_flags);

	err = btrfs_add_nondir(trans, dir, dentry, inode, 1, index);

	if (err) {
		drop_inode = 1;
	} else {
		struct dentry *parent = dentry->d_parent;
		err = btrfs_update_inode(trans, root, inode);
		if (err)
			goto fail;
		d_instantiate(dentry, inode);
		btrfs_log_new_name(trans, inode, NULL, parent);
	}

	btrfs_end_transaction(trans, root);
	btrfs_balance_delayed_items(root);
fail:
	if (drop_inode) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	btrfs_btree_balance_dirty(root);
	return err;
}

static int btrfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = NULL;
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	int err = 0;
	int drop_on_err = 0;
	u64 objectid = 0;
	u64 index = 0;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	int credit_for_syno = 0;
#endif

#ifdef MY_DEF_HERE
	err = btrfs_check_dir_item_collision(root, dir->i_ino, 0,
			     dentry->d_name.name, dentry->d_name.len);
	if (err)
		return err;
	// 1 for dir_item_caseless
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		credit_for_syno++;
#endif

#ifdef MY_DEF_HERE
	// 1 for the prop for compression
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif
	/*
	 * 2 items for inode and ref
	 * 2 items for dir items
	 * 1 for xattr if selinux is on
	 */
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	trans = btrfs_start_transaction(root, 5 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 5);
#endif /* MY_DEF_HERE || MY_DEF_HERE */
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_fail;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				S_IFDIR | mode, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_fail;
	}

	drop_on_err = 1;
	/* these must be set before we unlock the inode */
	inode->i_op = &btrfs_dir_inode_operations;
	inode->i_fop = &btrfs_dir_file_operations;

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_fail_inode;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err)
		goto out_fail_inode;
#endif /* MY_DEF_HERE || MY_DEF_HERE */

	btrfs_i_size_write(inode, 0);
	err = btrfs_update_inode(trans, root, inode);
	if (err)
		goto out_fail_inode;

	err = btrfs_add_link(trans, dir, inode, dentry->d_name.name,
			     dentry->d_name.len, 0, index);
	if (err)
		goto out_fail_inode;

	d_instantiate(dentry, inode);
	/*
	 * mkdir is special.  We're unlocking after we call d_instantiate
	 * to avoid a race with nfsd calling d_instantiate.
	 */
	unlock_new_inode(inode);
	drop_on_err = 0;

out_fail:
	btrfs_end_transaction(trans, root);
	if (drop_on_err)
		iput(inode);
	btrfs_balance_delayed_items(root);
	btrfs_btree_balance_dirty(root);
	return err;

out_fail_inode:
	unlock_new_inode(inode);
	goto out_fail;
}

static noinline int uncompress_inline(struct btrfs_path *path,
				      struct inode *inode, struct page *page,
				      size_t pg_offset, u64 extent_offset,
				      struct btrfs_file_extent_item *item)
{
	int ret;
	struct extent_buffer *leaf = path->nodes[0];
	char *tmp;
	size_t max_size;
	unsigned long inline_size;
	unsigned long ptr;
	int compress_type;

	WARN_ON(pg_offset != 0);
	compress_type = btrfs_file_extent_compression(leaf, item);
	max_size = btrfs_file_extent_ram_bytes(leaf, item);
	inline_size = btrfs_file_extent_inline_item_len(leaf,
					btrfs_item_nr(path->slots[0]));
	tmp = kmalloc(inline_size, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	ptr = btrfs_file_extent_inline_start(item);

	read_extent_buffer(leaf, tmp, ptr, inline_size);

	max_size = min_t(unsigned long, PAGE_CACHE_SIZE, max_size);
	ret = btrfs_decompress(compress_type, tmp, page,
			       extent_offset, inline_size, max_size);
	kfree(tmp);
	return ret;
}

/*
 * a bit scary, this does extent mapping from logical file offset to the disk.
 * the ugly parts come from merging extents from the disk with the in-ram
 * representation.  This gets more complex because of the data=ordered code,
 * where the in-ram extents might be locked pending data=ordered completion.
 *
 * This also copies inline extents directly into the page.
 */

struct extent_map *btrfs_get_extent(struct inode *inode, struct page *page,
				    size_t pg_offset, u64 start, u64 len,
				    int create)
{
	int ret;
	int err = 0;
	u64 extent_start = 0;
	u64 extent_end = 0;
	u64 objectid = btrfs_ino(inode);
	u32 found_type;
	struct btrfs_path *path = NULL;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_file_extent_item *item;
	struct extent_buffer *leaf;
	struct btrfs_key found_key;
	struct extent_map *em = NULL;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_trans_handle *trans = NULL;
	const bool new_inline = !page || create;

again:
	read_lock(&em_tree->lock);
	em = lookup_extent_mapping(em_tree, start, len);
	if (em)
		em->bdev = root->fs_info->fs_devices->latest_bdev;
	read_unlock(&em_tree->lock);

	if (em) {
		if (em->start > start || em->start + em->len <= start)
			free_extent_map(em);
		else if (em->block_start == EXTENT_MAP_INLINE && page)
			free_extent_map(em);
		else
			goto out;
	}
	em = alloc_extent_map();
	if (!em) {
		err = -ENOMEM;
		goto out;
	}
	em->bdev = root->fs_info->fs_devices->latest_bdev;
	em->start = EXTENT_MAP_HOLE;
	em->orig_start = EXTENT_MAP_HOLE;
	em->len = (u64)-1;
	em->block_len = (u64)-1;

	if (!path) {
		path = btrfs_alloc_path();
		if (!path) {
			err = -ENOMEM;
			goto out;
		}
		/*
		 * Chances are we'll be called again, so go ahead and do
		 * readahead
		 */
		path->reada = READA_FORWARD;
	}

	ret = btrfs_lookup_file_extent(trans, root, path,
				       objectid, start, trans != NULL);
	if (ret < 0) {
		err = ret;
		goto out;
	}

	if (ret != 0) {
		if (path->slots[0] == 0)
			goto not_found;
		path->slots[0]--;
	}

	leaf = path->nodes[0];
	item = btrfs_item_ptr(leaf, path->slots[0],
			      struct btrfs_file_extent_item);
	/* are we inside the extent that was found? */
	btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
	found_type = btrfs_key_type(&found_key);
	if (found_key.objectid != objectid ||
	    found_type != BTRFS_EXTENT_DATA_KEY) {
		/*
		 * If we backup past the first extent we want to move forward
		 * and see if there is an extent in front of us, otherwise we'll
		 * say there is a hole for our whole search range which can
		 * cause problems.
		 */
		extent_end = start;
		goto next;
	}

	found_type = btrfs_file_extent_type(leaf, item);
	extent_start = found_key.offset;
	if (found_type == BTRFS_FILE_EXTENT_REG ||
	    found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		extent_end = extent_start +
		       btrfs_file_extent_num_bytes(leaf, item);
	} else if (found_type == BTRFS_FILE_EXTENT_INLINE) {
		size_t size;
		size = btrfs_file_extent_inline_len(leaf, path->slots[0], item);
		extent_end = ALIGN(extent_start + size, root->sectorsize);
	}
next:
	if (start >= extent_end) {
		path->slots[0]++;
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				err = ret;
				goto out;
			}
			if (ret > 0)
				goto not_found;
			leaf = path->nodes[0];
		}
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		if (found_key.objectid != objectid ||
		    found_key.type != BTRFS_EXTENT_DATA_KEY)
			goto not_found;
		if (start + len <= found_key.offset)
			goto not_found;
		em->start = start;
		em->orig_start = start;
		em->len = found_key.offset - start;
		goto not_found_em;
	}

	btrfs_extent_item_to_extent_map(inode, path, item, new_inline, em);

	if (found_type == BTRFS_FILE_EXTENT_REG ||
	    found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		goto insert;
	} else if (found_type == BTRFS_FILE_EXTENT_INLINE) {
		unsigned long ptr;
		char *map;
		size_t size;
		size_t extent_offset;
		size_t copy_size;

		if (new_inline)
			goto out;

		size = btrfs_file_extent_inline_len(leaf, path->slots[0], item);
		extent_offset = page_offset(page) + pg_offset - extent_start;
		copy_size = min_t(u64, PAGE_CACHE_SIZE - pg_offset,
				size - extent_offset);
		em->start = extent_start + extent_offset;
		em->len = ALIGN(copy_size, root->sectorsize);
		em->orig_block_len = em->len;
		em->orig_start = em->start;
		ptr = btrfs_file_extent_inline_start(item) + extent_offset;
		if (create == 0 && !PageUptodate(page)) {
			if (btrfs_file_extent_compression(leaf, item) !=
			    BTRFS_COMPRESS_NONE) {
				ret = uncompress_inline(path, inode, page,
							pg_offset,
							extent_offset, item);
				if (ret) {
					err = ret;
					goto out;
				}
			} else {
				map = kmap(page);
				read_extent_buffer(leaf, map + pg_offset, ptr,
						   copy_size);
				if (pg_offset + copy_size < PAGE_CACHE_SIZE) {
					memset(map + pg_offset + copy_size, 0,
					       PAGE_CACHE_SIZE - pg_offset -
					       copy_size);
				}
				kunmap(page);
			}
			flush_dcache_page(page);
		} else if (create && PageUptodate(page)) {
			BUG();
			if (!trans) {
				kunmap(page);
				free_extent_map(em);
				em = NULL;

				btrfs_release_path(path);
				trans = btrfs_join_transaction(root);

				if (IS_ERR(trans))
					return ERR_CAST(trans);
				goto again;
			}
			map = kmap(page);
			write_extent_buffer(leaf, map + pg_offset, ptr,
					    copy_size);
			kunmap(page);
			btrfs_mark_buffer_dirty(leaf);
		}
		set_extent_uptodate(io_tree, em->start,
				    extent_map_end(em) - 1, NULL, GFP_NOFS);
		goto insert;
	}
not_found:
	em->start = start;
	em->orig_start = start;
	em->len = len;
not_found_em:
	em->block_start = EXTENT_MAP_HOLE;
	set_bit(EXTENT_FLAG_VACANCY, &em->flags);
insert:
	btrfs_release_path(path);
	if (em->start > start || extent_map_end(em) <= start) {
		btrfs_err(root->fs_info, "bad extent! em: [%llu %llu] passed [%llu %llu]",
			em->start, em->len, start, len);
		err = -EIO;
		goto out;
	}

	err = 0;
	write_lock(&em_tree->lock);
	err = btrfs_add_extent_mapping(em_tree, &em, start, len);
	write_unlock(&em_tree->lock);
out:

	trace_btrfs_get_extent(root, em);

	if (path)
		btrfs_free_path(path);
	if (trans) {
		ret = btrfs_end_transaction(trans, root);
		if (!err)
			err = ret;
	}
	if (err) {
		free_extent_map(em);
		return ERR_PTR(err);
	}
	BUG_ON(!em); /* Error is always set */
	return em;
}

struct extent_map *btrfs_get_extent_fiemap(struct inode *inode, struct page *page,
					   size_t pg_offset, u64 start, u64 len,
					   int create)
{
	struct extent_map *em;
	struct extent_map *hole_em = NULL;
	u64 range_start = start;
	u64 end;
	u64 found;
	u64 found_end;
	int err = 0;

	em = btrfs_get_extent(inode, page, pg_offset, start, len, create);
	if (IS_ERR(em))
		return em;
	if (em) {
		/*
		 * if our em maps to
		 * -  a hole or
		 * -  a pre-alloc extent,
		 * there might actually be delalloc bytes behind it.
		 */
		if (em->block_start != EXTENT_MAP_HOLE &&
		    !test_bit(EXTENT_FLAG_PREALLOC, &em->flags))
			return em;
		else
			hole_em = em;
	}

	/* check to see if we've wrapped (len == -1 or similar) */
	end = start + len;
	if (end < start)
		end = (u64)-1;
	else
		end -= 1;

	em = NULL;

	/* ok, we didn't find anything, lets look for delalloc */
	found = count_range_bits(&BTRFS_I(inode)->io_tree, &range_start,
				 end, len, EXTENT_DELALLOC, 1);
	found_end = range_start + found;
	if (found_end < range_start)
		found_end = (u64)-1;

	/*
	 * we didn't find anything useful, return
	 * the original results from get_extent()
	 */
	if (range_start > end || found_end <= start) {
		em = hole_em;
		hole_em = NULL;
		goto out;
	}

	/* adjust the range_start to make sure it doesn't
	 * go backwards from the start they passed in
	 */
	range_start = max(start, range_start);
	found = found_end - range_start;

	if (found > 0) {
		u64 hole_start = start;
		u64 hole_len = len;

		em = alloc_extent_map();
		if (!em) {
			err = -ENOMEM;
			goto out;
		}
		/*
		 * when btrfs_get_extent can't find anything it
		 * returns one huge hole
		 *
		 * make sure what it found really fits our range, and
		 * adjust to make sure it is based on the start from
		 * the caller
		 */
		if (hole_em) {
			u64 calc_end = extent_map_end(hole_em);

			if (calc_end <= start || (hole_em->start > end)) {
				free_extent_map(hole_em);
				hole_em = NULL;
			} else {
				hole_start = max(hole_em->start, start);
				hole_len = calc_end - hole_start;
			}
		}
		em->bdev = NULL;
		if (hole_em && range_start > hole_start) {
			/* our hole starts before our delalloc, so we
			 * have to return just the parts of the hole
			 * that go until  the delalloc starts
			 */
			em->len = min(hole_len,
				      range_start - hole_start);
			em->start = hole_start;
			em->orig_start = hole_start;
			/*
			 * don't adjust block start at all,
			 * it is fixed at EXTENT_MAP_HOLE
			 */
			em->block_start = hole_em->block_start;
			em->block_len = hole_len;
			if (test_bit(EXTENT_FLAG_PREALLOC, &hole_em->flags))
				set_bit(EXTENT_FLAG_PREALLOC, &em->flags);
		} else {
			em->start = range_start;
			em->len = found;
			em->orig_start = range_start;
			em->block_start = EXTENT_MAP_DELALLOC;
			em->block_len = found;
		}
	} else if (hole_em) {
		return hole_em;
	}
out:

	free_extent_map(hole_em);
	if (err) {
		free_extent_map(em);
		return ERR_PTR(err);
	}
	return em;
}

static struct extent_map *btrfs_create_dio_extent(struct inode *inode,
						  const u64 start,
						  const u64 len,
						  const u64 orig_start,
						  const u64 block_start,
						  const u64 block_len,
						  const u64 orig_block_len,
						  const u64 ram_bytes,
						  const int type)
{
	struct extent_map *em = NULL;
	int ret;

	if (type != BTRFS_ORDERED_NOCOW) {
		em = create_pinned_em(inode, start, len, orig_start,
				      block_start, block_len, orig_block_len,
				      ram_bytes, type);
		if (IS_ERR(em))
			goto out;
	}
	ret = btrfs_add_ordered_extent_dio(inode, start, block_start,
					   len, block_len, type);
	if (ret) {
		if (em) {
			free_extent_map(em);
			btrfs_drop_extent_cache(inode, start,
						start + len - 1, 0);
		}
		em = ERR_PTR(ret);
	}
 out:

	return em;
}

static struct extent_map *btrfs_new_extent_direct(struct inode *inode,
						  u64 start, u64 len)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_map *em;
	struct btrfs_key ins;
	u64 alloc_hint;
	int ret;

	alloc_hint = get_extent_allocation_hint(inode, start, len);
	ret = btrfs_reserve_extent(root, len, root->sectorsize, 0,
				   alloc_hint, &ins, 1, 1);
	if (ret)
		return ERR_PTR(ret);

	em = btrfs_create_dio_extent(inode, start, ins.offset, start,
				     ins.objectid, ins.offset, ins.offset,
				     ins.offset, 0);
	if (IS_ERR(em))
		btrfs_free_reserved_extent(root, ins.objectid, ins.offset, 1);

	return em;
}

/*
 * returns 1 when the nocow is safe, < 1 on error, 0 if the
 * block must be cow'd
 */
noinline int can_nocow_extent(struct inode *inode, u64 offset, u64 *len,
			      u64 *orig_start, u64 *orig_block_len,
			      u64 *ram_bytes)
{
	struct btrfs_path *path;
	int ret;
	struct extent_buffer *leaf;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	u64 disk_bytenr;
	u64 backref_offset;
	u64 extent_end;
	u64 num_bytes;
	int slot;
	int found_type;
	bool nocow = (BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ret = btrfs_lookup_file_extent(NULL, root, path, btrfs_ino(inode),
				       offset, 0);
	if (ret < 0)
		goto out;

	slot = path->slots[0];
	if (ret == 1) {
		if (slot == 0) {
			/* can't find the item, must cow */
			ret = 0;
			goto out;
		}
		slot--;
	}
	ret = 0;
	leaf = path->nodes[0];
	btrfs_item_key_to_cpu(leaf, &key, slot);
	if (key.objectid != btrfs_ino(inode) ||
	    key.type != BTRFS_EXTENT_DATA_KEY) {
		/* not our file or wrong item type, must cow */
		goto out;
	}

	if (key.offset > offset) {
		/* Wrong offset, must cow */
		goto out;
	}

	fi = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);
	found_type = btrfs_file_extent_type(leaf, fi);
	if (found_type != BTRFS_FILE_EXTENT_REG &&
	    found_type != BTRFS_FILE_EXTENT_PREALLOC) {
		/* not a regular extent, must cow */
		goto out;
	}

	if (!nocow && found_type == BTRFS_FILE_EXTENT_REG)
		goto out;

	extent_end = key.offset + btrfs_file_extent_num_bytes(leaf, fi);
	if (extent_end <= offset)
		goto out;

	disk_bytenr = btrfs_file_extent_disk_bytenr(leaf, fi);
	if (disk_bytenr == 0)
		goto out;

	if (btrfs_file_extent_compression(leaf, fi) ||
	    btrfs_file_extent_encryption(leaf, fi) ||
	    btrfs_file_extent_other_encoding(leaf, fi))
		goto out;

	backref_offset = btrfs_file_extent_offset(leaf, fi);

	if (orig_start) {
		*orig_start = key.offset - backref_offset;
		*orig_block_len = btrfs_file_extent_disk_num_bytes(leaf, fi);
		*ram_bytes = btrfs_file_extent_ram_bytes(leaf, fi);
	}

	if (btrfs_extent_readonly(root, disk_bytenr))
		goto out;

	num_bytes = min(offset + *len, extent_end) - offset;
	if (!nocow && found_type == BTRFS_FILE_EXTENT_PREALLOC) {
		u64 range_end;

		range_end = round_up(offset + num_bytes, root->sectorsize) - 1;
		ret = test_range_bit(io_tree, offset, range_end,
				     EXTENT_DELALLOC, 0, NULL);
		if (ret) {
			ret = -EAGAIN;
			goto out;
		}
	}

	btrfs_release_path(path);

	/*
	 * look for other files referencing this extent, if we
	 * find any we must cow
	 */

#ifdef MY_DEF_HERE
	ret = btrfs_cross_ref_exist(root, btrfs_ino(inode),
				    key.offset - backref_offset, disk_bytenr,
				    CHECK_CROSS_REF_NORMAL);
#else
	ret = btrfs_cross_ref_exist(root, btrfs_ino(inode),
				    key.offset - backref_offset, disk_bytenr);
#endif /* MY_DEF_HERE */
	if (ret) {
		ret = 0;
		goto out;
	}

	/*
	 * adjust disk_bytenr and num_bytes to cover just the bytes
	 * in this extent we are about to write.  If there
	 * are any csums in that range we have to cow in order
	 * to keep the csums correct
	 */
	disk_bytenr += backref_offset;
	disk_bytenr += offset - key.offset;
	if (csum_exist_in_range(root, disk_bytenr, num_bytes))
				goto out;
	/*
	 * all of the above have passed, it is safe to overwrite this extent
	 * without cow
	 */
	*len = num_bytes;
	ret = 1;
out:
	btrfs_free_path(path);
	return ret;
}

bool btrfs_page_exists_in_range(struct inode *inode, loff_t start, loff_t end)
{
	struct radix_tree_root *root = &inode->i_mapping->page_tree;
	int found = false;
	void **pagep = NULL;
	struct page *page = NULL;
	unsigned long start_idx;
	unsigned long end_idx;

	start_idx = start >> PAGE_CACHE_SHIFT;

	/*
	 * end is the last byte in the last page.  end == start is legal
	 */
	end_idx = end >> PAGE_CACHE_SHIFT;

	rcu_read_lock();

	/* Most of the code in this while loop is lifted from
	 * find_get_page.  It's been modified to begin searching from a
	 * page and return just the first page found in that range.  If the
	 * found idx is less than or equal to the end idx then we know that
	 * a page exists.  If no pages are found or if those pages are
	 * outside of the range then we're fine (yay!) */
	while (page == NULL &&
	       radix_tree_gang_lookup_slot(root, &pagep, NULL, start_idx, 1)) {
		page = radix_tree_deref_slot(pagep);
		if (unlikely(!page))
			break;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				page = NULL;
				continue;
			}
			/*
			 * Otherwise, shmem/tmpfs must be storing a swap entry
			 * here as an exceptional entry: so return it without
			 * attempting to raise page count.
			 */
			page = NULL;
			break; /* TODO: Is this relevant for this use case? */
		}

		if (!page_cache_get_speculative(page)) {
			page = NULL;
			continue;
		}

		/*
		 * Has the page moved?
		 * This is part of the lockless pagecache protocol. See
		 * include/linux/pagemap.h for details.
		 */
		if (unlikely(page != *pagep)) {
			page_cache_release(page);
			page = NULL;
		}
	}

	if (page) {
		if (page->index <= end_idx)
			found = true;
		page_cache_release(page);
	}

	rcu_read_unlock();
	return found;
}

static int lock_extent_direct(struct inode *inode, u64 lockstart, u64 lockend,
			      struct extent_state **cached_state, int writing)
{
	struct btrfs_ordered_extent *ordered;
	int ret = 0;

	while (1) {
		lock_extent_bits(&BTRFS_I(inode)->io_tree, lockstart, lockend,
				 0, cached_state);
		/*
		 * We're concerned with the entire range that we're going to be
		 * doing DIO to, so we need to make sure theres no ordered
		 * extents in this range.
		 */
		ordered = btrfs_lookup_ordered_range(inode, lockstart,
						     lockend - lockstart + 1);

		/*
		 * We need to make sure there are no buffered pages in this
		 * range either, we could have raced between the invalidate in
		 * generic_file_direct_write and locking the extent.  The
		 * invalidate needs to happen so that reads after a write do not
		 * get stale data.
		 */
		if (!ordered &&
		    (!writing ||
		     !btrfs_page_exists_in_range(inode, lockstart, lockend)))
			break;

		unlock_extent_cached(&BTRFS_I(inode)->io_tree, lockstart, lockend,
				     cached_state, GFP_NOFS);

		if (ordered) {
			/*
			 * If we are doing a DIO read and the ordered extent we
			 * found is for a buffered write, we can not wait for it
			 * to complete and retry, because if we do so we can
			 * deadlock with concurrent buffered writes on page
			 * locks. This happens only if our DIO read covers more
			 * than one extent map, if at this point has already
			 * created an ordered extent for a previous extent map
			 * and locked its range in the inode's io tree, and a
			 * concurrent write against that previous extent map's
			 * range and this range started (we unlock the ranges
			 * in the io tree only when the bios complete and
			 * buffered writes always lock pages before attempting
			 * to lock range in the io tree).
			 */
			if (writing ||
			    test_bit(BTRFS_ORDERED_DIRECT, &ordered->flags))
				btrfs_start_ordered_extent(inode, ordered, 1);
			else
				ret = -ENOTBLK;
			btrfs_put_ordered_extent(ordered);
		} else {
			/*
			 * We could trigger writeback for this range (and wait
			 * for it to complete) and then invalidate the pages for
			 * this range (through invalidate_inode_pages2_range()),
			 * but that can lead us to a deadlock with a concurrent
			 * call to readpages() (a buffered read or a defrag call
			 * triggered a readahead) on a page lock due to an
			 * ordered dio extent we created before but did not have
			 * yet a corresponding bio submitted (whence it can not
			 * complete), which makes readpages() wait for that
			 * ordered extent to complete while holding a lock on
			 * that page.
			 */
			ret = -ENOTBLK;
		}

		if (ret)
			break;

		cond_resched();
	}

	return ret;
}

static struct extent_map *create_pinned_em(struct inode *inode, u64 start,
					   u64 len, u64 orig_start,
					   u64 block_start, u64 block_len,
					   u64 orig_block_len, u64 ram_bytes,
					   int type)
{
	struct extent_map_tree *em_tree;
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	em_tree = &BTRFS_I(inode)->extent_tree;
	em = alloc_extent_map();
	if (!em)
		return ERR_PTR(-ENOMEM);

	em->start = start;
	em->orig_start = orig_start;
	em->mod_start = start;
	em->mod_len = len;
	em->len = len;
	em->block_len = block_len;
	em->block_start = block_start;
	em->bdev = root->fs_info->fs_devices->latest_bdev;
	em->orig_block_len = orig_block_len;
	em->ram_bytes = ram_bytes;
	em->generation = -1;
	set_bit(EXTENT_FLAG_PINNED, &em->flags);
	if (type == BTRFS_ORDERED_PREALLOC)
		set_bit(EXTENT_FLAG_FILLING, &em->flags);

	do {
		btrfs_drop_extent_cache(inode, em->start,
				em->start + em->len - 1, 0);
		write_lock(&em_tree->lock);
		ret = add_extent_mapping(em_tree, em, 1);
		write_unlock(&em_tree->lock);
	} while (ret == -EEXIST);

	if (ret) {
		free_extent_map(em);
		return ERR_PTR(ret);
	}

	return em;
}

static void adjust_dio_outstanding_extents(struct inode *inode,
					   struct btrfs_dio_data *dio_data,
					   const u64 len)
{
	unsigned num_extents;

	num_extents = (unsigned) div64_u64(len + BTRFS_MAX_EXTENT_SIZE - 1,
					   BTRFS_MAX_EXTENT_SIZE);
	/*
	 * If we have an outstanding_extents count still set then we're
	 * within our reservation, otherwise we need to adjust our inode
	 * counter appropriately.
	 */
	if (dio_data->outstanding_extents >= num_extents) {
		dio_data->outstanding_extents -= num_extents;
	} else {
		/*
		 * If dio write length has been split due to no large enough
		 * contiguous space, we need to compensate our inode counter
		 * appropriately.
		 */
		u64 num_needed = num_extents - dio_data->outstanding_extents;

		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->outstanding_extents += num_needed;
		spin_unlock(&BTRFS_I(inode)->lock);
	}
}

static int btrfs_get_blocks_direct(struct inode *inode, sector_t iblock,
				   struct buffer_head *bh_result, int create)
{
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_state *cached_state = NULL;
	struct btrfs_dio_data *dio_data = NULL;
	u64 start = iblock << inode->i_blkbits;
	u64 lockstart, lockend;
	u64 len = bh_result->b_size;
	int unlock_bits = EXTENT_LOCKED;
	int ret = 0;

	if (create)
		unlock_bits |= EXTENT_DIRTY;
	else
		len = min_t(u64, len, root->sectorsize);

	lockstart = start;
	lockend = start + len - 1;

	if (current->journal_info) {
		/*
		 * Need to pull our outstanding extents and set journal_info to NULL so
		 * that anything that needs to check if there's a transction doesn't get
		 * confused.
		 */
		dio_data = current->journal_info;
		current->journal_info = NULL;
	}

	/*
	 * If this errors out it's because we couldn't invalidate pagecache for
	 * this range and we need to fallback to buffered.
	 */
	if (lock_extent_direct(inode, lockstart, lockend, &cached_state,
			       create)) {
		ret = -ENOTBLK;
		goto err;
	}

	em = btrfs_get_extent(inode, NULL, 0, start, len, 0);
	if (IS_ERR(em)) {
		ret = PTR_ERR(em);
		goto unlock_err;
	}

	/*
	 * Ok for INLINE and COMPRESSED extents we need to fallback on buffered
	 * io.  INLINE is special, and we could probably kludge it in here, but
	 * it's still buffered so for safety lets just fall back to the generic
	 * buffered path.
	 *
	 * For COMPRESSED we _have_ to read the entire extent in so we can
	 * decompress it, so there will be buffering required no matter what we
	 * do, so go ahead and fallback to buffered.
	 *
	 * We return -ENOTBLK because thats what makes DIO go ahead and go back
	 * to buffered IO.  Don't blame me, this is the price we pay for using
	 * the generic code.
	 */
	if (test_bit(EXTENT_FLAG_COMPRESSED, &em->flags) ||
	    em->block_start == EXTENT_MAP_INLINE) {
		free_extent_map(em);
		ret = -ENOTBLK;
		goto unlock_err;
	}

	/* Just a good old fashioned hole, return */
	if (!create && (em->block_start == EXTENT_MAP_HOLE ||
			test_bit(EXTENT_FLAG_PREALLOC, &em->flags))) {
		free_extent_map(em);
		goto unlock_err;
	}

	/*
	 * We don't allocate a new extent in the following cases
	 *
	 * 1) The inode is marked as NODATACOW.  In this case we'll just use the
	 * existing extent.
	 * 2) The extent is marked as PREALLOC.  We're good to go here and can
	 * just use the extent.
	 *
	 */
	if (!create) {
		len = min(len, em->len - (start - em->start));
		lockstart = start + len;
		goto unlock;
	}

	if (test_bit(EXTENT_FLAG_PREALLOC, &em->flags) ||
	    ((BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW) &&
	     em->block_start != EXTENT_MAP_HOLE)) {
		int type;
		u64 block_start, orig_start, orig_block_len, ram_bytes;

		if (test_bit(EXTENT_FLAG_PREALLOC, &em->flags))
			type = BTRFS_ORDERED_PREALLOC;
		else
			type = BTRFS_ORDERED_NOCOW;
		len = min(len, em->len - (start - em->start));
		block_start = em->block_start + (start - em->start);

		if (can_nocow_extent(inode, start, &len, &orig_start,
				     &orig_block_len, &ram_bytes) == 1) {
			struct extent_map *em2;

			em2 = btrfs_create_dio_extent(inode, start, len,
						      orig_start, block_start,
						      len, orig_block_len,
						      ram_bytes, type);
			if (type == BTRFS_ORDERED_PREALLOC) {
				free_extent_map(em);
				em = em2;
			}
			if (em2 && IS_ERR(em2)) {
				ret = PTR_ERR(em2);
				goto unlock_err;
			}
			goto unlock;
		}
	}

	/*
	 * this will cow the extent, reset the len in case we changed
	 * it above
	 */
	len = bh_result->b_size;
	free_extent_map(em);
	em = btrfs_new_extent_direct(inode, start, len);
	if (IS_ERR(em)) {
		ret = PTR_ERR(em);
		goto unlock_err;
	}
	len = min(len, em->len - (start - em->start));
unlock:
	bh_result->b_blocknr = (em->block_start + (start - em->start)) >>
		inode->i_blkbits;
	bh_result->b_size = len;
	bh_result->b_bdev = em->bdev;
	set_buffer_mapped(bh_result);
	if (create) {
		if (!test_bit(EXTENT_FLAG_PREALLOC, &em->flags))
			set_buffer_new(bh_result);

		/*
		 * Need to update the i_size under the extent lock so buffered
		 * readers will get the updated i_size when we unlock.
		 */
		if (start + len > i_size_read(inode))
			i_size_write(inode, start + len);

		adjust_dio_outstanding_extents(inode, dio_data, len);
		btrfs_free_reserved_data_space(inode, len);
		WARN_ON(dio_data->reserve < len);
		dio_data->reserve -= len;
		dio_data->unsubmitted_oe_range_end = start + len;
		current->journal_info = dio_data;
	}

	/*
	 * In the case of write we need to clear and unlock the entire range,
	 * in the case of read we need to unlock only the end area that we
	 * aren't using if there is any left over space.
	 */
	if (lockstart < lockend) {
		clear_extent_bit(&BTRFS_I(inode)->io_tree, lockstart,
				 lockend, unlock_bits, 1, 0,
				 &cached_state, GFP_NOFS);
	} else {
		free_extent_state(cached_state);
	}

	free_extent_map(em);

	return 0;

unlock_err:
	clear_extent_bit(&BTRFS_I(inode)->io_tree, lockstart, lockend,
			 unlock_bits, 1, 0, &cached_state, GFP_NOFS);
err:
	if (dio_data)
		current->journal_info = dio_data;
	/*
	 * Compensate the delalloc release we do in btrfs_direct_IO() when we
	 * write less data then expected, so that we don't underflow our inode's
	 * outstanding extents counter.
	 */
	if (create && dio_data)
		adjust_dio_outstanding_extents(inode, dio_data, len);

	return ret;
}

static void btrfs_endio_direct_read(struct bio *bio, int err)
{
	struct btrfs_dio_private *dip = bio->bi_private;
	struct bio_vec *bvec_end = bio->bi_io_vec + bio->bi_vcnt - 1;
	struct bio_vec *bvec = bio->bi_io_vec;
	struct inode *inode = dip->inode;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct bio *dio_bio;
	u32 *csums = (u32 *)dip->csum;
	int index = 0;
	u64 start;

	start = dip->logical_offset;
	do {
		if (!(BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)) {
			struct page *page = bvec->bv_page;
			char *kaddr;
			u32 csum = ~(u32)0;
			unsigned long flags;

			local_irq_save(flags);
			kaddr = kmap_atomic(page);
			csum = btrfs_csum_data(kaddr + bvec->bv_offset,
					       csum, bvec->bv_len);
			btrfs_csum_final(csum, (char *)&csum);
			kunmap_atomic(kaddr);
			local_irq_restore(flags);

			flush_dcache_page(bvec->bv_page);
			if (csum != csums[index]) {
				btrfs_err(root->fs_info, "csum failed ino %llu off %llu csum %u expected csum %u",
					  btrfs_ino(inode), start, csum,
					  csums[index]);
				err = -EIO;
			}
		}

		start += bvec->bv_len;
		bvec++;
		index++;
	} while (bvec <= bvec_end);

	unlock_extent(&BTRFS_I(inode)->io_tree, dip->logical_offset,
		      dip->logical_offset + dip->bytes - 1);
	dio_bio = dip->dio_bio;

	kfree(dip);

	/* If we had a csum failure make sure to clear the uptodate flag */
	if (err)
		clear_bit(BIO_UPTODATE, &dio_bio->bi_flags);
	dio_end_io(dio_bio, err);
	bio_put(bio);
}

static void __endio_write_update_ordered(struct inode *inode,
					 const u64 offset, const u64 bytes,
					 const bool uptodate)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ordered_extent *ordered = NULL;
	struct btrfs_workqueue *wq;
	btrfs_work_func_t func;
	u64 ordered_offset = offset;
	u64 ordered_bytes = bytes;
	u64 last_offset;
	int ret;

	if (btrfs_is_free_space_inode(inode)) {
		wq = root->fs_info->endio_freespace_worker;
		func = btrfs_freespace_write_helper;
	} else {
		wq = root->fs_info->endio_write_workers;
		func = btrfs_endio_write_helper;
	}

again:
	last_offset = ordered_offset;
	ret = btrfs_dec_test_first_ordered_pending(inode, &ordered,
						   &ordered_offset,
						   ordered_bytes,
						   uptodate);
	if (!ret)
		goto out_test;

	btrfs_init_work(&ordered->work, func, finish_ordered_fn, NULL, NULL);
	btrfs_queue_work(wq, &ordered->work);
out_test:
	/*
	 * If btrfs_dec_test_ordered_pending does not find any ordered extent
	 * in the range, we can exit.
	 */
	if (ordered_offset == last_offset)
		return;
	/*
	 * our bio might span multiple ordered extents.  If we haven't
	 * completed the accounting for the whole dio, go back and try again
	 */
	if (ordered_offset < offset + bytes) {
		ordered_bytes = offset + bytes - ordered_offset;
		ordered = NULL;
		goto again;
	}
}

static void btrfs_endio_direct_write(struct bio *bio, int err)
{
	struct btrfs_dio_private *dip = bio->bi_private;
	struct bio *dio_bio = dip->dio_bio;

	__endio_write_update_ordered(dip->inode, dip->logical_offset,
				     dip->bytes, !err);

	kfree(dip);

	/* If we had an error make sure to clear the uptodate flag */
	if (err)
		clear_bit(BIO_UPTODATE, &dio_bio->bi_flags);
	dio_end_io(dio_bio, err);
	bio_put(bio);
}

static int __btrfs_submit_bio_start_direct_io(struct inode *inode, int rw,
				    struct bio *bio, int mirror_num,
				    unsigned long bio_flags, u64 offset)
{
	int ret;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	ret = btrfs_csum_one_bio(root, inode, bio, offset, 1);
	BUG_ON(ret); /* -ENOMEM */
	return 0;
}

static void btrfs_end_dio_bio(struct bio *bio, int err)
{
	struct btrfs_dio_private *dip = bio->bi_private;

	if (err) {
		btrfs_err(BTRFS_I(dip->inode)->root->fs_info,
			  "direct IO failed ino %llu rw %lu sector %#Lx len %u err no %d",
		      btrfs_ino(dip->inode), bio->bi_rw,
		      (unsigned long long)bio->bi_sector, bio->bi_size, err);
		dip->errors = 1;

		/*
		 * before atomic variable goto zero, we must make sure
		 * dip->errors is perceived to be set.
		 */
		smp_mb__before_atomic_dec();
	}

	/* if there are more bios still pending for this dio, just exit */
	if (!atomic_dec_and_test(&dip->pending_bios))
		goto out;

	if (dip->errors) {
		bio_io_error(dip->orig_bio);
	} else {
		set_bit(BIO_UPTODATE, &dip->dio_bio->bi_flags);
		bio_endio(dip->orig_bio, 0);
	}
out:
	bio_put(bio);
}

static struct bio *btrfs_dio_bio_alloc(struct block_device *bdev,
#ifdef MY_DEF_HERE
				       u64 first_sector, gfp_t gfp_flags, int rw)
#else
				       u64 first_sector, gfp_t gfp_flags)
#endif /* MY_DEF_HERE */
{
	int nr_vecs = bio_get_nr_vecs(bdev);
#ifdef MY_DEF_HERE
	return btrfs_bio_alloc(bdev, first_sector, nr_vecs, gfp_flags, rw);
#else
	return btrfs_bio_alloc(bdev, first_sector, nr_vecs, gfp_flags);
#endif /* MY_DEF_HERE */
}

static inline int __btrfs_submit_dio_bio(struct bio *bio, struct inode *inode,
					 int rw, u64 file_offset, int skip_sum,
					 int async_submit)
{
	struct btrfs_dio_private *dip = bio->bi_private;
	int write = rw & REQ_WRITE;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	if (async_submit)
		async_submit = !atomic_read(&BTRFS_I(inode)->sync_writers);

	bio_get(bio);

	if (!write) {
		ret = btrfs_bio_wq_end_io(root->fs_info, bio, 0);
		if (ret)
			goto err;
	}

	if (skip_sum)
		goto map;

	if (write && async_submit) {
#ifdef MY_DEF_HERE
		if (root->objectid == BTRFS_FS_TREE_OBJECTID ||
			(root->objectid >= BTRFS_FIRST_FREE_OBJECTID && root->objectid <= BTRFS_LAST_FREE_OBJECTID)) {
			if (root->fs_info->syno_async_submit_throttle && atomic_read(&root->fs_info->syno_async_submit_nr) > root->fs_info->syno_async_submit_throttle) {
				wait_event(root->fs_info->syno_async_submit_queue_wait, atomic_read(&root->fs_info->syno_async_submit_nr) <= root->fs_info->syno_async_submit_throttle);
			}
		}
		ret = btrfs_wq_submit_bio(root->fs_info,
				   inode, rw, bio, 0, 0,
				   file_offset,
				   __btrfs_submit_bio_start_direct_io,
				   __btrfs_submit_bio_done, 1);
#else
		ret = btrfs_wq_submit_bio(root->fs_info,
				   inode, rw, bio, 0, 0,
				   file_offset,
				   __btrfs_submit_bio_start_direct_io,
				   __btrfs_submit_bio_done);
#endif /* MY_DEF_HERE */
		goto err;
	} else if (write) {
		/*
		 * If we aren't doing async submit, calculate the csum of the
		 * bio now.
		 */
		ret = btrfs_csum_one_bio(root, inode, bio, file_offset, 1);
		if (ret)
			goto err;
	} else if (!skip_sum) {
		ret = btrfs_lookup_bio_sums_dio(root, inode, dip, bio,
						file_offset);
		if (ret)
			goto err;
	}

map:
	ret = btrfs_map_bio(root, rw, bio, 0, async_submit);
err:
	bio_put(bio);
	return ret;
}

static int btrfs_submit_direct_hook(int rw, struct btrfs_dio_private *dip,
				    int skip_sum)
{
	struct inode *inode = dip->inode;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct bio *bio;
	struct bio *orig_bio = dip->orig_bio;
	struct bio_vec *bvec = orig_bio->bi_io_vec;
	u64 start_sector = orig_bio->bi_sector;
	u64 file_offset = dip->logical_offset;
	u64 submit_len = 0;
	u64 map_length;
	int nr_pages = 0;
	int ret = 0;
	int async_submit = 0;

	map_length = orig_bio->bi_size;
	ret = btrfs_map_block(root->fs_info, rw, start_sector << 9,
			      &map_length, NULL, 0);
	if (ret) {
		bio_put(orig_bio);
		return -EIO;
	}

	if (map_length >= orig_bio->bi_size) {
		bio = orig_bio;
		goto submit;
	}

	/* async crcs make it difficult to collect full stripe writes. */
	if (btrfs_get_alloc_profile(root, 1) &
	    (BTRFS_BLOCK_GROUP_RAID5 | BTRFS_BLOCK_GROUP_RAID6))
		async_submit = 0;
	else
		async_submit = 1;

#ifdef MY_DEF_HERE
	bio = btrfs_dio_bio_alloc(orig_bio->bi_bdev, start_sector, GFP_NOFS, rw);
#else
	bio = btrfs_dio_bio_alloc(orig_bio->bi_bdev, start_sector, GFP_NOFS);
#endif /* MY_DEF_HERE */
	if (!bio)
		return -ENOMEM;
	bio->bi_private = dip;
	bio->bi_end_io = btrfs_end_dio_bio;
	atomic_inc(&dip->pending_bios);

	while (bvec <= (orig_bio->bi_io_vec + orig_bio->bi_vcnt - 1)) {
		if (unlikely(map_length < submit_len + bvec->bv_len ||
		    bio_add_page(bio, bvec->bv_page, bvec->bv_len,
				 bvec->bv_offset) < bvec->bv_len)) {
			/*
			 * inc the count before we submit the bio so
			 * we know the end IO handler won't happen before
			 * we inc the count. Otherwise, the dip might get freed
			 * before we're done setting it up
			 */
			atomic_inc(&dip->pending_bios);
			ret = __btrfs_submit_dio_bio(bio, inode, rw,
						     file_offset, skip_sum,
						     async_submit);
			if (ret) {
				bio_put(bio);
				atomic_dec(&dip->pending_bios);
				goto out_err;
			}

			start_sector += submit_len >> 9;
			file_offset += submit_len;

			submit_len = 0;
			nr_pages = 0;

			bio = btrfs_dio_bio_alloc(orig_bio->bi_bdev,
#ifdef MY_DEF_HERE
						  start_sector, GFP_NOFS, rw);
#else
						  start_sector, GFP_NOFS);
#endif /* MY_DEF_HERE */
			if (!bio)
				goto out_err;
			bio->bi_private = dip;
			bio->bi_end_io = btrfs_end_dio_bio;

			map_length = orig_bio->bi_size;
			ret = btrfs_map_block(root->fs_info, rw,
					      start_sector << 9,
					      &map_length, NULL, 0);
			if (ret) {
				bio_put(bio);
				goto out_err;
			}
		} else {
			submit_len += bvec->bv_len;
			nr_pages++;
			bvec++;
		}
	}

submit:
	ret = __btrfs_submit_dio_bio(bio, inode, rw, file_offset, skip_sum,
				     async_submit);
	if (!ret)
		return 0;

	bio_put(bio);
out_err:
	dip->errors = 1;
	/*
	 * before atomic variable goto zero, we must
	 * make sure dip->errors is perceived to be set.
	 */
	smp_mb__before_atomic_dec();
	if (atomic_dec_and_test(&dip->pending_bios))
		bio_io_error(dip->orig_bio);

	/* bio_end_io() will handle error, so we needn't return it */
	return 0;
}

static void btrfs_submit_direct(int rw, struct bio *dio_bio,
				struct inode *inode, loff_t file_offset)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_dio_private *dip = NULL;
	struct bio *io_bio = NULL;
	int skip_sum;
	int sum_len;
	int write = rw & REQ_WRITE;
	int ret = 0;
	u16 csum_size;

	skip_sum = BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM;

	io_bio = btrfs_bio_clone(dio_bio, GFP_NOFS);
	if (!io_bio) {
		ret = -ENOMEM;
		goto free_ordered;
	}

	if (!skip_sum && !write) {
		csum_size = btrfs_super_csum_size(root->fs_info->super_copy);
		sum_len = dio_bio->bi_size >> inode->i_sb->s_blocksize_bits;
		sum_len *= csum_size;
	} else {
		sum_len = 0;
	}

	dip = kmalloc(sizeof(*dip) + sum_len, GFP_NOFS);
	if (!dip) {
		ret = -ENOMEM;
		goto free_ordered;
	}

	dip->private = dio_bio->bi_private;
	dip->inode = inode;
	dip->logical_offset = file_offset;
	dip->bytes = dio_bio->bi_size;
	dip->disk_bytenr = (u64)dio_bio->bi_sector << 9;
	io_bio->bi_private = dip;
	dip->errors = 0;
	dip->orig_bio = io_bio;
	dip->dio_bio = dio_bio;
	atomic_set(&dip->pending_bios, 0);

	if (write)
		io_bio->bi_end_io = btrfs_endio_direct_write;
	else
		io_bio->bi_end_io = btrfs_endio_direct_read;

	/*
	 * Reset the range for unsubmitted ordered extents (to a 0 length range)
	 * even if we fail to submit a bio, because in such case we do the
	 * corresponding error handling below and it must not be done a second
	 * time by btrfs_direct_IO().
	 */
	if (write) {
		struct btrfs_dio_data *dio_data = current->journal_info;

		dio_data->unsubmitted_oe_range_end = dip->logical_offset +
			dip->bytes;
		dio_data->unsubmitted_oe_range_start =
			dio_data->unsubmitted_oe_range_end;
	}

	ret = btrfs_submit_direct_hook(rw, dip, skip_sum);
	if (!ret)
		return;

free_ordered:
	/*
	 * If we arrived here it means either we failed to submit the dip
	 * or we either failed to clone the dio_bio or failed to allocate the
	 * dip. If we cloned the dio_bio and allocated the dip, we can just
	 * call bio_endio against our io_bio so that we get proper resource
	 * cleanup if we fail to submit the dip, otherwise, we must do the
	 * same as btrfs_endio_direct_[write|read] because we can't call these
	 * callbacks - they require an allocated dip and a clone of dio_bio.
	 */
	if (io_bio && dip) {
		bio_endio(io_bio, ret);
		/*
		 * The end io callbacks free our dip, do the final put on io_bio
		 * and all the cleanup and final put for dio_bio (through
		 * dio_end_io()).
		 */
		dip = NULL;
		io_bio = NULL;
	} else {
		if (write)
			__endio_write_update_ordered(inode,
						file_offset,
						dio_bio->bi_size,
						false);
		else
			unlock_extent(&BTRFS_I(inode)->io_tree, file_offset,
			      file_offset + dio_bio->bi_size - 1);

		clear_bit(BIO_UPTODATE, &dio_bio->bi_flags);
		/*
		 * Releases and cleans up our dio_bio, no need to bio_put()
		 * nor bio_endio()/bio_io_error() against dio_bio.
		 */
		dio_end_io(dio_bio, ret);
	}
	if (io_bio)
		bio_put(io_bio);
	kfree(dip);
}

static ssize_t check_direct_IO(struct btrfs_root *root, int rw, struct kiocb *iocb,
			const struct iovec *iov, loff_t offset,
			unsigned long nr_segs)
{
	int seg;
	int i;
	size_t size;
	unsigned long addr;
	unsigned blocksize_mask = root->sectorsize - 1;
	ssize_t retval = -EINVAL;
	loff_t end = offset;

	if (offset & blocksize_mask)
		goto out;

	/* Check the memory alignment.  Blocks cannot straddle pages */
	for (seg = 0; seg < nr_segs; seg++) {
		addr = (unsigned long)iov[seg].iov_base;
		size = iov[seg].iov_len;
		end += size;
		if ((addr & blocksize_mask) || (size & blocksize_mask))
			goto out;

		/* If this is a write we don't need to check anymore */
		if (rw & WRITE)
			continue;

		/*
		 * Check to make sure we don't have duplicate iov_base's in this
		 * iovec, if so return EINVAL, otherwise we'll get csum errors
		 * when reading back.
		 */
		for (i = seg + 1; i < nr_segs; i++) {
			if (iov[seg].iov_base == iov[i].iov_base)
				goto out;
		}
	}
	retval = 0;
out:
	return retval;
}

static ssize_t btrfs_direct_IO(int rw, struct kiocb *iocb,
			const struct iovec *iov, loff_t offset,
			unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_dio_data dio_data = { 0 };
	size_t count = 0;
	int flags = 0;
	bool wakeup = true;
	bool relock = false;
	ssize_t ret;

	if (check_direct_IO(BTRFS_I(inode)->root, rw, iocb, iov,
			    offset, nr_segs))
		return 0;

	atomic_inc(&inode->i_dio_count);
	smp_mb__after_atomic_inc();

	/*
	 * The generic stuff only does filemap_write_and_wait_range, which
	 * isn't enough if we've written compressed pages to this area, so
	 * we need to flush the dirty pages again to make absolutely sure
	 * that any outstanding dirty pages are on disk.
	 */
	count = iov_length(iov, nr_segs);
	if (test_bit(BTRFS_INODE_HAS_ASYNC_EXTENT,
		     &BTRFS_I(inode)->runtime_flags))
		filemap_fdatawrite_range(inode->i_mapping, offset,
					 offset + count - 1);

	if (rw & WRITE) {
		/*
		 * If the write DIO is beyond the EOF, we need update
		 * the isize, but it is protected by i_mutex. So we can
		 * not unlock the i_mutex at this case.
		 */
		if (offset + count <= inode->i_size) {
			mutex_unlock(&inode->i_mutex);
			relock = true;
		}
		ret = btrfs_delalloc_reserve_space(inode, count);
		if (ret)
			goto out;
		dio_data.outstanding_extents = div64_u64(count +
						BTRFS_MAX_EXTENT_SIZE - 1,
						BTRFS_MAX_EXTENT_SIZE);

		/*
		 * We need to know how many extents we reserved so that we can
		 * do the accounting properly if we go over the number we
		 * originally calculated.  Abuse current->journal_info for this.
		 */
		dio_data.reserve = round_up(count, root->sectorsize);
		dio_data.unsubmitted_oe_range_start = (u64)offset;
		dio_data.unsubmitted_oe_range_end = (u64)offset;
		current->journal_info = &dio_data;
		down_read(&BTRFS_I(inode)->dio_sem);
	} else if (unlikely(test_bit(BTRFS_INODE_READDIO_NEED_LOCK,
				     &BTRFS_I(inode)->runtime_flags))) {
		inode_dio_done(inode);
#ifdef MY_DEF_HERE
		flags = DIO_LOCKING | DIO_SKIP_HOLES | DIO_NO_ASYNC;
		wakeup = false;
	} else {
		flags = DIO_NO_ASYNC;
#else
		flags = DIO_LOCKING | DIO_SKIP_HOLES;
		wakeup = false;
#endif /* MY_DEF_HERE */
	}

	ret = __blockdev_direct_IO(rw, iocb, inode,
			BTRFS_I(inode)->root->fs_info->fs_devices->latest_bdev,
			iov, offset, nr_segs, btrfs_get_blocks_direct, NULL,
			btrfs_submit_direct, flags);
	if (rw & WRITE) {
		up_read(&BTRFS_I(inode)->dio_sem);
		current->journal_info = NULL;
		if (ret < 0 && ret != -EIOCBQUEUED) {
			if (dio_data.reserve)
				btrfs_delalloc_release_space(inode,
							dio_data.reserve);
			/*
			 * On error we might have left some ordered extents
			 * without submitting corresponding bios for them, so
			 * cleanup them up to avoid other tasks getting them
			 * and waiting for them to complete forever.
			 */
			if (dio_data.unsubmitted_oe_range_start <
			    dio_data.unsubmitted_oe_range_end)
				__endio_write_update_ordered(inode,
					dio_data.unsubmitted_oe_range_start,
					dio_data.unsubmitted_oe_range_end -
					dio_data.unsubmitted_oe_range_start,
					false);
		} else if (ret >= 0 && (size_t)ret < count)
			btrfs_delalloc_release_space(inode,
						     count - (size_t)ret);
	}
out:
	if (wakeup)
		inode_dio_done(inode);
	if (relock)
		mutex_lock(&inode->i_mutex);

	return ret;
}

#define BTRFS_FIEMAP_FLAGS	(FIEMAP_FLAG_SYNC)

static int btrfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		__u64 start, __u64 len)
{
	int	ret;

	ret = fiemap_check_flags(fieinfo, BTRFS_FIEMAP_FLAGS);
	if (ret)
		return ret;

	return extent_fiemap(inode, fieinfo, start, len, btrfs_get_extent_fiemap);
}

int btrfs_readpage(struct file *file, struct page *page)
{
	struct extent_io_tree *tree;
	tree = &BTRFS_I(page->mapping->host)->io_tree;
	return extent_read_full_page(tree, page, btrfs_get_extent, 0);
}

static int btrfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct extent_io_tree *tree;
	struct inode *inode = page->mapping->host;
	int ret;

	if (current->flags & PF_MEMALLOC) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return 0;
	}

	/*
	 * If we are under memory pressure we will call this directly from the
	 * VM, we need to make sure we have the inode referenced for the ordered
	 * extent.  If not just return like we didn't do anything.
	 */
	if (!igrab(inode)) {
		redirty_page_for_writepage(wbc, page);
		return AOP_WRITEPAGE_ACTIVATE;
	}
	tree = &BTRFS_I(page->mapping->host)->io_tree;
	ret = extent_write_full_page(tree, page, btrfs_get_extent, wbc);
	btrfs_add_delayed_iput(inode);
	return ret;
}

static int btrfs_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct extent_io_tree *tree;

	tree = &BTRFS_I(mapping->host)->io_tree;
	return extent_writepages(tree, mapping, btrfs_get_extent, wbc);
}

static int
btrfs_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	struct extent_io_tree *tree;
	tree = &BTRFS_I(mapping->host)->io_tree;
	return extent_readpages(tree, mapping, pages, nr_pages,
				btrfs_get_extent);
}
static int __btrfs_releasepage(struct page *page, gfp_t gfp_flags)
{
	struct extent_io_tree *tree;
	struct extent_map_tree *map;
	int ret;

	tree = &BTRFS_I(page->mapping->host)->io_tree;
	map = &BTRFS_I(page->mapping->host)->extent_tree;
	ret = try_release_extent_mapping(map, tree, page, gfp_flags);
	if (ret == 1) {
		ClearPagePrivate(page);
		set_page_private(page, 0);
		page_cache_release(page);
	}
	return ret;
}

static int btrfs_releasepage(struct page *page, gfp_t gfp_flags)
{
	if (PageWriteback(page) || PageDirty(page))
		return 0;
	return __btrfs_releasepage(page, gfp_flags & GFP_NOFS);
}

static void btrfs_invalidatepage(struct page *page, unsigned long offset)
{
	struct inode *inode = page->mapping->host;
	struct extent_io_tree *tree;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	u64 page_start = page_offset(page);
	u64 page_end = page_start + PAGE_CACHE_SIZE - 1;
	int inode_evicting = inode->i_state & I_FREEING;

	/*
	 * we have the page locked, so new writeback can't start,
	 * and the dirty bit won't be cleared while we are here.
	 *
	 * Wait for IO on this page so that we can safely clear
	 * the PagePrivate2 bit and do ordered accounting
	 */
	wait_on_page_writeback(page);

	tree = &BTRFS_I(inode)->io_tree;
	if (offset) {
		btrfs_releasepage(page, GFP_NOFS);
		return;
	}

	if (!inode_evicting)
		lock_extent_bits(tree, page_start, page_end, 0, &cached_state);
	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		/*
		 * IO on this page will never be started, so we need
		 * to account for any ordered extents now
		 */
		if (!inode_evicting)
			clear_extent_bit(tree, page_start, page_end,
					 EXTENT_DIRTY | EXTENT_DELALLOC |
					 EXTENT_LOCKED | EXTENT_DO_ACCOUNTING |
					 EXTENT_DEFRAG, 1, 0, &cached_state,
					 GFP_NOFS);
		/*
		 * whoever cleared the private bit is responsible
		 * for the finish_ordered_io
		 */
		if (TestClearPagePrivate2(page)) {
			struct btrfs_ordered_inode_tree *tree;
			u64 new_len;

			tree = &BTRFS_I(inode)->ordered_tree;

			spin_lock_irq(&tree->lock);
			set_bit(BTRFS_ORDERED_TRUNCATED, &ordered->flags);
			new_len = page_start - ordered->file_offset;
			if (new_len < ordered->truncated_len)
				ordered->truncated_len = new_len;
			spin_unlock_irq(&tree->lock);

			if (btrfs_dec_test_ordered_pending(inode, &ordered,
							   page_start,
							   PAGE_CACHE_SIZE, 1))
				btrfs_finish_ordered_io(ordered);
		}
		btrfs_put_ordered_extent(ordered);
		if (!inode_evicting) {
			cached_state = NULL;
			lock_extent_bits(tree, page_start, page_end, 0,
					 &cached_state);
		}
	}

	if (!inode_evicting) {
		clear_extent_bit(tree, page_start, page_end,
				 EXTENT_LOCKED | EXTENT_DIRTY |
				 EXTENT_DELALLOC | EXTENT_DO_ACCOUNTING |
				 EXTENT_DEFRAG, 1, 1,
				 &cached_state, GFP_NOFS);

		__btrfs_releasepage(page, GFP_NOFS);
	}

	ClearPageChecked(page);
	if (PagePrivate(page)) {
		ClearPagePrivate(page);
		set_page_private(page, 0);
		page_cache_release(page);
	}
}

/*
 * btrfs_page_mkwrite() is not allowed to change the file size as it gets
 * called from a page fault handler when a page is first dirtied. Hence we must
 * be careful to check for EOF conditions here. We set the page up correctly
 * for a written page which means we get ENOSPC checking when writing into
 * holes and correct delalloc and unwritten extent mapping on filesystems that
 * support these features.
 *
 * We are not allowed to take the i_mutex here so we have to play games to
 * protect against truncate races as the page could now be beyond EOF.  Because
 * vmtruncate() writes the inode size before removing pages, once we have the
 * page lock we can determine safely if the page is beyond EOF. If it is not
 * beyond EOF, then the page is guaranteed safe against truncation until we
 * unlock the page.
 */
int btrfs_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	char *kaddr;
	unsigned long zero_start;
	loff_t size;
	int ret;
	int reserved = 0;
	u64 page_start;
	u64 page_end;

#ifdef MY_DEF_HERE
	syno_ordered_extent_throttle(root->fs_info);
#endif /* MY_DEF_HERE */

	sb_start_pagefault(inode->i_sb);
	ret  = btrfs_delalloc_reserve_space(inode, PAGE_CACHE_SIZE);
	if (!ret) {
		ret = file_update_time(vma->vm_file);
#ifdef MY_DEF_HERE
		fsnotify_modify(vma->vm_file);
#endif /* MY_DEF_HERE */
		reserved = 1;
	}
	if (ret) {
		if (ret == -ENOMEM)
			ret = VM_FAULT_OOM;
		else /* -ENOSPC, -EIO, etc */
			ret = VM_FAULT_SIGBUS;
		if (reserved)
			goto out;
		goto out_noreserve;
	}

	ret = VM_FAULT_NOPAGE; /* make the VM retry the fault */
again:
	lock_page(page);
	size = i_size_read(inode);
	page_start = page_offset(page);
	page_end = page_start + PAGE_CACHE_SIZE - 1;

	if ((page->mapping != inode->i_mapping) ||
	    (page_start >= size)) {
		/* page got truncated out from underneath us */
		goto out_unlock;
	}
	wait_on_page_writeback(page);

	lock_extent_bits(io_tree, page_start, page_end, 0, &cached_state);
	set_page_extent_mapped(page);

	/*
	 * we can't set the delalloc bits if there are pending ordered
	 * extents.  Drop our locks and wait for them to finish
	 */
	ordered = btrfs_lookup_ordered_extent(inode, page_start);
	if (ordered) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		unlock_page(page);
		btrfs_start_ordered_extent(inode, ordered, 1);
		btrfs_put_ordered_extent(ordered);
		goto again;
	}

	/*
	 * XXX - page_mkwrite gets called every time the page is dirtied, even
	 * if it was already dirty, so for space accounting reasons we need to
	 * clear any delalloc bits for the range we are fixing to save.  There
	 * is probably a better way to do this, but for now keep consistent with
	 * prepare_pages in the normal write path.
	 */
	clear_extent_bit(&BTRFS_I(inode)->io_tree, page_start, page_end,
			  EXTENT_DIRTY | EXTENT_DELALLOC |
			  EXTENT_DO_ACCOUNTING | EXTENT_DEFRAG,
			  0, 0, &cached_state, GFP_NOFS);

	ret = btrfs_set_extent_delalloc(inode, page_start, page_end,
					&cached_state);
	if (ret) {
		unlock_extent_cached(io_tree, page_start, page_end,
				     &cached_state, GFP_NOFS);
		ret = VM_FAULT_SIGBUS;
		goto out_unlock;
	}
	ret = 0;

	/* page is wholly or partially inside EOF */
	if (page_start + PAGE_CACHE_SIZE > size)
		zero_start = size & ~PAGE_CACHE_MASK;
	else
		zero_start = PAGE_CACHE_SIZE;

	if (zero_start != PAGE_CACHE_SIZE) {
		kaddr = kmap(page);
		memset(kaddr + zero_start, 0, PAGE_CACHE_SIZE - zero_start);
		flush_dcache_page(page);
		kunmap(page);
	}
	ClearPageChecked(page);
	set_page_dirty(page);
	SetPageUptodate(page);

	BTRFS_I(inode)->last_trans = root->fs_info->generation;
	BTRFS_I(inode)->last_sub_trans = BTRFS_I(inode)->root->log_transid;
	BTRFS_I(inode)->last_log_commit = BTRFS_I(inode)->root->last_log_commit;

	unlock_extent_cached(io_tree, page_start, page_end, &cached_state, GFP_NOFS);

out_unlock:
	if (!ret) {
		sb_end_pagefault(inode->i_sb);
		return VM_FAULT_LOCKED;
	}
	unlock_page(page);
out:
	btrfs_delalloc_release_space(inode, PAGE_CACHE_SIZE);
out_noreserve:
	sb_end_pagefault(inode->i_sb);
	return ret;
}

static int btrfs_truncate(struct inode *inode, bool skip_writeback)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_block_rsv *rsv;
	int ret = 0;
	int err = 0;
	struct btrfs_trans_handle *trans;
	u64 mask = root->sectorsize - 1;
	u64 min_size = btrfs_calc_trunc_metadata_size(root, 1);

	if (!skip_writeback) {
		ret = btrfs_wait_ordered_range(inode, inode->i_size & (~mask),
					       (u64)-1);
		if (ret)
			return ret;
	}

	/*
	 * Yes ladies and gentlemen, this is indeed ugly.  We have a couple of
	 * things going on here:
	 *
	 * 1) We need to reserve space to update our inode.
	 *
	 * 2) We need to have something to cache all the space that is going to
	 * be free'd up by the truncate operation, but also have some slack
	 * space reserved in case it uses space during the truncate (thank you
	 * very much snapshotting).
	 *
	 * And we need these to be separate.  The fact is we can use a lot of
	 * space doing the truncate, and we have no earthly idea how much space
	 * we will use, so we need the truncate reservation to be separate so it
	 * doesn't end up using space reserved for updating the inode.  We also
	 * need to be able to stop the transaction and start a new one, which
	 * means we need to be able to update the inode several times, and we
	 * have no idea of knowing how many times that will be, so we can't just
	 * reserve 1 item for the entirety of the operation, so that has to be
	 * done separately as well.
	 *
	 * So that leaves us with
	 *
	 * 1) rsv - for the truncate reservation, which we will steal from the
	 * transaction reservation.
	 * 2) fs_info->trans_block_rsv - this will have 1 items worth left for
	 * updating the inode.
	 */
	rsv = btrfs_alloc_block_rsv(root, BTRFS_BLOCK_RSV_TEMP);
	if (!rsv)
		return -ENOMEM;
	rsv->size = min_size;
	rsv->failfast = 1;

	/*
	 * 1 for the truncate slack space
	 * 1 for updating the inode.
	 */
	trans = btrfs_start_transaction(root, 2);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto out;
	}

	/* Migrate the slack space for the truncate to our reserve */
	ret = btrfs_block_rsv_migrate(&root->fs_info->trans_block_rsv, rsv,
				      min_size);
	BUG_ON(ret);

	/*
	 * So if we truncate and then write and fsync we normally would just
	 * write the extents that changed, which is a problem if we need to
	 * first truncate that entire inode.  So set this flag so we write out
	 * all of the extents in the inode to the sync log so we're completely
	 * safe.
	 */
	set_bit(BTRFS_INODE_NEEDS_FULL_SYNC, &BTRFS_I(inode)->runtime_flags);
	trans->block_rsv = rsv;

	while (1) {
		ret = btrfs_truncate_inode_items(trans, root, inode,
						 inode->i_size,
						 BTRFS_EXTENT_DATA_KEY);
		trans->block_rsv = &root->fs_info->trans_block_rsv;
		if (ret != -ENOSPC && ret != -EAGAIN) {
			if (ret < 0)
				err = ret;
			break;
		}

		ret = btrfs_update_inode(trans, root, inode);
		if (ret) {
			err = ret;
			break;
		}

		btrfs_end_transaction(trans, root);
		btrfs_btree_balance_dirty(root);

		trans = btrfs_start_transaction(root, 2);
		if (IS_ERR(trans)) {
			ret = err = PTR_ERR(trans);
			trans = NULL;
			break;
		}

		ret = btrfs_block_rsv_migrate(&root->fs_info->trans_block_rsv,
					      rsv, min_size);
		BUG_ON(ret);	/* shouldn't happen */
		trans->block_rsv = rsv;
	}

	/*
	 * We can't call btrfs_truncate_block inside a trans handle as we could
	 * deadlock with freeze, if we got NEED_TRUNCATE_BLOCK then we know
	 * we've truncated everything except the last little bit, and can do
	 * btrfs_truncate_block and then update the disk_i_size.
	 */
	if (ret == NEED_TRUNCATE_BLOCK) {
		btrfs_end_transaction(trans, root);
		btrfs_btree_balance_dirty(root);

		ret = btrfs_truncate_page(inode, inode->i_size, 0, 0);
		if (ret)
			goto out;
		trans = btrfs_start_transaction(root, 1);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out;
		}
		btrfs_ordered_update_i_size(inode, inode->i_size, NULL);
	}

	if (trans) {
		trans->block_rsv = &root->fs_info->trans_block_rsv;
		ret = btrfs_update_inode(trans, root, inode);
		if (ret && !err)
			err = ret;

		ret = btrfs_end_transaction(trans, root);
		btrfs_btree_balance_dirty(root);
	}

out:
	btrfs_free_block_rsv(root, rsv);

	if (ret && !err)
		err = ret;

	return err;
}

/*
 * create a new subvolume directory/inode (helper for the ioctl).
 */
int btrfs_create_subvol_root(struct btrfs_trans_handle *trans,
			     struct btrfs_root *new_root,
			     struct btrfs_root *parent_root,
			     u64 new_dirid)
{
	struct inode *inode;
	int err;
	u64 index = 0;

	inode = btrfs_new_inode(trans, new_root, NULL, "..", 2,
				new_dirid, new_dirid,
				S_IFDIR | (~current_umask() & S_IRWXUGO),
				&index);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &btrfs_dir_inode_operations;
	inode->i_fop = &btrfs_dir_file_operations;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err) {
		unlock_new_inode(inode);
		goto out;
	}
#endif /* MY_DEF_HERE || MY_DEF_HERE */

	set_nlink(inode, 1);
	btrfs_i_size_write(inode, 0);
	unlock_new_inode(inode);

	err = btrfs_subvol_inherit_props(trans, new_root, parent_root);
	if (err)
		btrfs_err(new_root->fs_info,
			  "error inheriting subvolume %llu properties: %d",
			  new_root->root_key.objectid, err);

	err = btrfs_update_inode(trans, new_root, inode);

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
out:
#endif
	iput(inode);
	return err;
}

struct inode *btrfs_alloc_inode(struct super_block *sb)
{
	struct btrfs_inode *ei;
	struct inode *inode;

	ei = kmem_cache_alloc(btrfs_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	ei->root = NULL;
	ei->generation = 0;
	ei->last_trans = 0;
	ei->last_sub_trans = 0;
	ei->logged_trans = 0;
	ei->delalloc_bytes = 0;
	ei->defrag_bytes = 0;
	ei->disk_i_size = 0;
	ei->flags = 0;
	ei->csum_bytes = 0;
	ei->index_cnt = (u64)-1;
#ifdef MY_DEF_HERE
#else
	ei->dir_index = 0;
#endif /* MY_DEF_HERE */
	ei->last_unlink_trans = 0;
	ei->last_log_commit = 0;

	spin_lock_init(&ei->lock);
	ei->outstanding_extents = 0;
	ei->reserved_extents = 0;

	ei->runtime_flags = 0;
	ei->force_compress = BTRFS_COMPRESS_NONE;

	ei->delayed_node = NULL;

	inode = &ei->vfs_inode;
	extent_map_tree_init(&ei->extent_tree);
#ifdef MY_DEF_HERE
	ei->extent_tree.inode = ei;
	INIT_LIST_HEAD(&ei->free_extent_map_inode);
	atomic_set(&ei->free_extent_map_counts, 0);
#endif
	extent_io_tree_init(&ei->io_tree, &inode->i_data);
	extent_io_tree_init(&ei->io_failure_tree, &inode->i_data);
	ei->io_tree.track_uptodate = 1;
	ei->io_failure_tree.track_uptodate = 1;
	atomic_set(&ei->sync_writers, 0);
	mutex_init(&ei->log_mutex);
	mutex_init(&ei->delalloc_mutex);
	btrfs_ordered_inode_tree_init(&ei->ordered_tree);
	INIT_LIST_HEAD(&ei->delalloc_inodes);
#ifdef MY_DEF_HERE
	INIT_LIST_HEAD(&ei->syno_dirty_lru_inode);
#endif /* MY_DEF_HERE */
	RB_CLEAR_NODE(&ei->rb_node);
	init_rwsem(&ei->dio_sem);

#ifdef MY_DEF_HERE
	atomic_set(&ei->syno_uq_refs, 0);
	ei->syno_uq_rfer_used = 0;
	ei->syno_uq_reserved = 0;
#ifdef MY_DEF_HERE
	ei->syno_uq_delayed_free = 0;
#endif /* MY_DEF_HERE */
#endif /* MY_DEF_HERE */

	return inode;
}

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
void btrfs_test_destroy_inode(struct inode *inode)
{
	btrfs_drop_extent_cache(inode, 0, (u64)-1, 0);
	kmem_cache_free(btrfs_inode_cachep, BTRFS_I(inode));
}
#endif

static void btrfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(btrfs_inode_cachep, BTRFS_I(inode));
}

void btrfs_destroy_inode(struct inode *inode)
{
	struct btrfs_ordered_extent *ordered;
	struct btrfs_root *root = BTRFS_I(inode)->root;

	WARN_ON(!hlist_empty(&inode->i_dentry));
	WARN_ON(inode->i_data.nrpages);
	WARN_ON(BTRFS_I(inode)->outstanding_extents);
	WARN_ON(BTRFS_I(inode)->reserved_extents);
	WARN_ON(BTRFS_I(inode)->delalloc_bytes);
	WARN_ON(BTRFS_I(inode)->csum_bytes);
	WARN_ON(BTRFS_I(inode)->defrag_bytes);

	/*
	 * This can happen where we create an inode, but somebody else also
	 * created the same inode and we need to destroy the one we already
	 * created.
	 */
	if (!root)
		goto free;

	while (1) {
		ordered = btrfs_lookup_first_ordered_extent(inode, (u64)-1);
		if (!ordered)
			break;
		else {
			btrfs_err(root->fs_info, "found ordered extent %llu %llu on inode cleanup",
				ordered->file_offset, ordered->len);
			btrfs_remove_ordered_extent(inode, ordered);
			btrfs_put_ordered_extent(ordered);
			btrfs_put_ordered_extent(ordered);
		}
	}
	inode_tree_del(inode);
	btrfs_drop_extent_cache(inode, 0, (u64)-1, 0);
free:
	call_rcu(&inode->i_rcu, btrfs_i_callback);
}

int btrfs_drop_inode(struct inode *inode)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;

	if (root == NULL)
		return 1;

	/* the snap/subvol tree is on deleting */
	if (btrfs_root_refs(&root->root_item) == 0)
		return 1;
	else
		return generic_drop_inode(inode);
}

static void init_once(void *foo)
{
	struct btrfs_inode *ei = (struct btrfs_inode *) foo;

	inode_init_once(&ei->vfs_inode);
}

void btrfs_destroy_cachep(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	if (btrfs_inode_cachep)
		kmem_cache_destroy(btrfs_inode_cachep);
	if (btrfs_trans_handle_cachep)
		kmem_cache_destroy(btrfs_trans_handle_cachep);
	if (btrfs_transaction_cachep)
		kmem_cache_destroy(btrfs_transaction_cachep);
	if (btrfs_path_cachep)
		kmem_cache_destroy(btrfs_path_cachep);
	if (btrfs_free_space_cachep)
		kmem_cache_destroy(btrfs_free_space_cachep);
	if (btrfs_delalloc_work_cachep)
		kmem_cache_destroy(btrfs_delalloc_work_cachep);
}

int __init btrfs_init_cachep(void)
{
	btrfs_inode_cachep = kmem_cache_create("btrfs_inode",
			sizeof(struct btrfs_inode), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, init_once);
	if (!btrfs_inode_cachep)
		goto fail;

	btrfs_trans_handle_cachep = kmem_cache_create("btrfs_trans_handle",
			sizeof(struct btrfs_trans_handle), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_trans_handle_cachep)
		goto fail;

	btrfs_transaction_cachep = kmem_cache_create("btrfs_transaction",
			sizeof(struct btrfs_transaction), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_transaction_cachep)
		goto fail;

	btrfs_path_cachep = kmem_cache_create("btrfs_path",
			sizeof(struct btrfs_path), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_path_cachep)
		goto fail;

	btrfs_free_space_cachep = kmem_cache_create("btrfs_free_space",
			sizeof(struct btrfs_free_space), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_free_space_cachep)
		goto fail;

	btrfs_delalloc_work_cachep = kmem_cache_create("btrfs_delalloc_work",
			sizeof(struct btrfs_delalloc_work), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
			NULL);
	if (!btrfs_delalloc_work_cachep)
		goto fail;

	return 0;
fail:
	btrfs_destroy_cachep();
	return -ENOMEM;
}

static int btrfs_getattr(struct vfsmount *mnt,
			 struct dentry *dentry, struct kstat *stat)
{
	u64 delalloc_bytes;
	struct inode *inode = dentry->d_inode;
	u32 blocksize = inode->i_sb->s_blocksize;

	generic_fillattr(inode, stat);
	stat->dev = BTRFS_I(inode)->root->anon_dev;
	stat->blksize = PAGE_CACHE_SIZE;

	spin_lock(&BTRFS_I(inode)->lock);
	delalloc_bytes = BTRFS_I(inode)->delalloc_bytes;
	spin_unlock(&BTRFS_I(inode)->lock);
	stat->blocks = (ALIGN(inode_get_bytes(inode), blocksize) +
			ALIGN(delalloc_bytes, blocksize)) >> 9;
	return 0;
}

#ifdef MY_DEF_HERE
static int btrfs_is_inode_inline(struct inode *inode)
{
	struct btrfs_path *path;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	struct btrfs_file_extent_item *fi;
	u64 delalloc_bytes;
	int ret;

	// Deal with unflushed extents
	spin_lock(&BTRFS_I(inode)->lock);
	delalloc_bytes = BTRFS_I(inode)->delalloc_bytes;
	spin_unlock(&BTRFS_I(inode)->lock);
	if (delalloc_bytes) {
		if (i_size_read(inode) > BTRFS_DEFAULT_MAX_INLINE)
			return 0;
		else
			return 1;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->leave_spinning = 1;

	ret = btrfs_lookup_file_extent(NULL, root, path, btrfs_ino(inode), 0, 0);
	if (ret == 0) {
		leaf = path->nodes[0];
		btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
		if (key.objectid == btrfs_ino(inode) && key.type == BTRFS_EXTENT_DATA_KEY) {
			fi = btrfs_item_ptr(leaf, path->slots[0],
				struct btrfs_file_extent_item);
			if (btrfs_file_extent_type(leaf, fi) == BTRFS_FILE_EXTENT_INLINE) {
				btrfs_free_path(path);
				return 1;
			}
		}
	}
	btrfs_free_path(path);
	if (ret < 0)
		return ret;

	return 0;
}
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
int btrfs_syno_getattr(struct dentry *d, struct kstat *stat, int flags)
{
	int err = 0;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	struct inode *inode = d->d_inode;
#endif

#ifdef MY_DEF_HERE
	if (flags & SYNOST_CREATE_TIME) {
		struct btrfs_timespec crtime;

		if (0 == (inode->i_flags & S_CREATE_TIME_CACHED)) {
			err = __btrfs_getxattr(inode, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME, &crtime, sizeof(crtime));
			if (0 < err) {
				inode->i_create_time.tv_sec = le64_to_cpu(crtime.sec);
				inode->i_create_time.tv_nsec = le32_to_cpu(crtime.nsec);
			} else if (-ENODATA == err) {
				inode->i_create_time.tv_sec = 0;
				inode->i_create_time.tv_nsec = 0;
			} else {
				return err;
			}
			inode->i_flags |= S_CREATE_TIME_CACHED;
		}
		stat->syno_create_time = inode->i_create_time;
		err = 0;
	}
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	if (flags & SYNOST_ARCHIVE_BIT) {
		stat->syno_archive_bit = inode->i_archive_bit;
	}
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	if (flags & SYNOST_ARCHIVE_VER) {
		err = btrfs_syno_get_archive_ver(d, &stat->syno_archive_version);
		if (err < 0)
			return err;
	}
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	if (flags & SYNOST_COMPRESSION) {
		stat->syno_compressed = BTRFS_I(inode)->flags & BTRFS_INODE_COMPRESS ? 1 : 0;
	}
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
	if (flags & SYNOST_IS_INLINE) {
		err = btrfs_is_inode_inline(inode);
		if (err < 0)
			return err;
		stat->is_inline = (bool)err;
		err = 0;
	}
#endif /* MY_DEF_HERE */

	return err;
}
#endif /* MY_DEF_HERE */

static int btrfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(old_dir)->root;
	struct btrfs_root *dest = BTRFS_I(new_dir)->root;
	struct inode *new_inode = new_dentry->d_inode;
	struct inode *old_inode = old_dentry->d_inode;
	struct timespec ctime = CURRENT_TIME;
	u64 index = 0;
	u64 root_objectid;
	int ret;
	u64 old_ino = btrfs_ino(old_inode);
#if defined(MY_DEF_HERE)
	int credit_for_syno = 0;
#endif /* MY_DEF_HERE */

	if (btrfs_ino(new_dir) == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)
		return -EPERM;

	/* we only allow rename subvolume link between subvolumes */
	if (old_ino != BTRFS_FIRST_FREE_OBJECTID && root != dest)
		return -EXDEV;

	if (old_ino == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID ||
	    (new_inode && btrfs_ino(new_inode) == BTRFS_FIRST_FREE_OBJECTID))
		return -ENOTEMPTY;

	if (S_ISDIR(old_inode->i_mode) && new_inode &&
	    new_inode->i_size > BTRFS_EMPTY_DIR_SIZE)
		return -ENOTEMPTY;


	/* check for collisions, even if the  name isn't there */
	ret = btrfs_check_dir_item_collision(dest, new_dir->i_ino,
#ifdef MY_DEF_HERE
			     1,
#endif /* MY_DEF_HERE */
			     new_dentry->d_name.name,
			     new_dentry->d_name.len);

	if (ret) {
		if (ret == -EEXIST) {
			/* we shouldn't get
			 * eexist without a new_inode */
			if (WARN_ON(!new_inode)) {
				return ret;
			}
		} else {
			/* maybe -EOVERFLOW */
			return ret;
		}
	}
	ret = 0;

	/*
	 * we're using rename to replace one file with another.  Start IO on it
	 * now so  we don't add too much work to the end of the transaction
	 */
	if (new_inode && S_ISREG(old_inode->i_mode) && new_inode->i_size)
		filemap_flush(old_inode->i_mapping);

	/* close the racy window with snapshot create/destroy ioctl */
	if (old_ino == BTRFS_FIRST_FREE_OBJECTID)
		down_read(&root->fs_info->subvol_sem);
	/*
	 * We want to reserve the absolute worst case amount of items.  So if
	 * both inodes are subvols and we need to unlink them then that would
	 * require 4 item modifications, but if they are both normal inodes it
	 * would require 5 item modifications, so we'll assume their normal
	 * inodes.  So 5 * 2 is 10, plus 1 for the new link, so 11 total items
	 * should cover the worst case number of items we'll modify.
	 */
#if defined(MY_DEF_HERE)
	// 1 for dir_item_caseless
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		credit_for_syno++;

	trans = btrfs_start_transaction(root, 11 + credit_for_syno);
#else /* MY_DEF_HERE */
	trans = btrfs_start_transaction(root, 11);
#endif /* MY_DEF_HERE */
	if (IS_ERR(trans)) {
                ret = PTR_ERR(trans);
                goto out_notrans;
        }

	if (dest != root)
		btrfs_record_root_in_trans(trans, dest);

	ret = btrfs_set_inode_index(new_dir, &index);
	if (ret)
		goto out_fail;

#ifdef MY_DEF_HERE
#else
	BTRFS_I(old_inode)->dir_index = 0ULL;
#endif /* MY_DEF_HERE */
	if (unlikely(old_ino == BTRFS_FIRST_FREE_OBJECTID)) {
		/* force full log commit if subvolume involved. */
		btrfs_set_log_full_commit(root->fs_info, trans);
	} else {
		ret = btrfs_insert_inode_ref(trans, dest,
					     new_dentry->d_name.name,
					     new_dentry->d_name.len,
					     old_ino,
					     btrfs_ino(new_dir), index);
		if (ret)
			goto out_fail;
		/*
		 * this is an ugly little race, but the rename is required
		 * to make sure that if we crash, the inode is either at the
		 * old name or the new one.  pinning the log transaction lets
		 * us make sure we don't allow a log commit to come in after
		 * we unlink the name but before we add the new name back in.
		 */
		btrfs_pin_log_trans(root);
	}

	inode_inc_iversion(old_dir);
	inode_inc_iversion(new_dir);
	inode_inc_iversion(old_inode);
	old_dir->i_ctime = old_dir->i_mtime = ctime;
	new_dir->i_ctime = new_dir->i_mtime = ctime;
	old_inode->i_ctime = ctime;

	if (old_dentry->d_parent != new_dentry->d_parent)
		btrfs_record_unlink_dir(trans, old_dir, old_inode, 1);

	if (unlikely(old_ino == BTRFS_FIRST_FREE_OBJECTID)) {
		root_objectid = BTRFS_I(old_inode)->root->root_key.objectid;
		ret = btrfs_unlink_subvol(trans, root, old_dir, root_objectid,
					old_dentry->d_name.name,
					old_dentry->d_name.len);
	} else {
		ret = __btrfs_unlink_inode(trans, root, old_dir,
					old_dentry->d_inode,
					old_dentry->d_name.name,
					old_dentry->d_name.len);
		if (!ret)
			ret = btrfs_update_inode(trans, root, old_inode);
	}
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_fail;
	}

	if (new_inode) {
		inode_inc_iversion(new_inode);
		new_inode->i_ctime = CURRENT_TIME;
		if (unlikely(btrfs_ino(new_inode) ==
			     BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)) {
			root_objectid = BTRFS_I(new_inode)->location.objectid;
			ret = btrfs_unlink_subvol(trans, dest, new_dir,
						root_objectid,
						new_dentry->d_name.name,
						new_dentry->d_name.len);
			BUG_ON(new_inode->i_nlink == 0);
		} else {
			ret = btrfs_unlink_inode(trans, dest, new_dir,
						 new_dentry->d_inode,
						 new_dentry->d_name.name,
						 new_dentry->d_name.len);
		}
		if (!ret && new_inode->i_nlink == 0)
			ret = btrfs_orphan_add(trans, new_dentry->d_inode);
		if (ret) {
			btrfs_abort_transaction(trans, root, ret);
			goto out_fail;
		}
	}

	ret = btrfs_add_link(trans, new_dir, old_inode,
			     new_dentry->d_name.name,
			     new_dentry->d_name.len, 0, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_fail;
	}

#ifdef MY_DEF_HERE
#else
	if (old_inode->i_nlink == 1)
		BTRFS_I(old_inode)->dir_index = index;
#endif /* MY_DEF_HERE */

	if (old_ino != BTRFS_FIRST_FREE_OBJECTID) {
		struct dentry *parent = new_dentry->d_parent;
		btrfs_log_new_name(trans, old_inode, old_dir, parent);
		btrfs_end_log_trans(root);
	}
out_fail:
	btrfs_end_transaction(trans, root);
out_notrans:
	if (old_ino == BTRFS_FIRST_FREE_OBJECTID)
		up_read(&root->fs_info->subvol_sem);

	return ret;
}

static void btrfs_run_delalloc_work(struct btrfs_work *work)
{
	struct btrfs_delalloc_work *delalloc_work;
	struct inode *inode;
#ifdef MY_DEF_HERE
	struct btrfs_fs_info *fs_info = NULL;
	bool syno_writeback = false;
#endif /* MY_DEF_HERE */

	delalloc_work = container_of(work, struct btrfs_delalloc_work,
				     work);
	inode = delalloc_work->inode;
	if (delalloc_work->wait) {
		btrfs_wait_ordered_range(inode, 0, (u64)-1);
	} else {
		filemap_flush(inode->i_mapping);
		if (test_bit(BTRFS_INODE_HAS_ASYNC_EXTENT,
			     &BTRFS_I(inode)->runtime_flags))
			filemap_flush(inode->i_mapping);
	}

#ifdef MY_DEF_HERE
	if (delalloc_work->syno_writeback) {
		syno_writeback = true;
		fs_info = BTRFS_I(inode)->root->fs_info;

		clear_bit(BTRFS_INODE_SYNO_WRITEBACK_RUNNING, &BTRFS_I(inode)->runtime_flags);
	}
#endif /* MY_DEF_HERE */

	if (delalloc_work->delay_iput)
		btrfs_add_delayed_iput(inode);
	else
		iput(inode);
	complete(&delalloc_work->completion);
#ifdef MY_DEF_HERE
	if (syno_writeback && fs_info) {
		atomic_dec(&fs_info->syno_writeback_thread_count);
		kmem_cache_free(btrfs_delalloc_work_cachep, delalloc_work);
	}
#endif /* MY_DEF_HERE */
}

struct btrfs_delalloc_work *btrfs_alloc_delalloc_work(struct inode *inode,
						    int wait, int delay_iput)
{
	struct btrfs_delalloc_work *work;

	work = kmem_cache_zalloc(btrfs_delalloc_work_cachep, GFP_NOFS);
	if (!work)
		return NULL;

	init_completion(&work->completion);
	INIT_LIST_HEAD(&work->list);
	work->inode = inode;
	work->wait = wait;
	work->delay_iput = delay_iput;
#ifdef MY_DEF_HERE
	work->syno_writeback = 0;
#endif /* MY_DEF_HERE */
	WARN_ON_ONCE(!inode);
	btrfs_init_work(&work->work, btrfs_flush_delalloc_helper,
			btrfs_run_delalloc_work, NULL, NULL);

	return work;
}

void btrfs_wait_and_free_delalloc_work(struct btrfs_delalloc_work *work)
{
	wait_for_completion(&work->completion);
	kmem_cache_free(btrfs_delalloc_work_cachep, work);
}

/*
 * some fairly slow code that needs optimization. This walks the list
 * of all the inodes with pending delalloc and forces them to disk.
 */
#ifdef MY_DEF_HERE
static int __start_delalloc_inodes(struct btrfs_root *root, int delay_iput,
				   int nr, int snapshot)
#else
static int __start_delalloc_inodes(struct btrfs_root *root, int delay_iput,
				   int nr)
#endif /* MY_DEF_HERE */
{
	struct btrfs_inode *binode;
	struct inode *inode;
	struct btrfs_delalloc_work *work, *next;
	struct list_head works;
	struct list_head splice;
	int ret = 0;

	INIT_LIST_HEAD(&works);
	INIT_LIST_HEAD(&splice);

	mutex_lock(&root->delalloc_mutex);
	spin_lock(&root->delalloc_lock);
	list_splice_init(&root->delalloc_inodes, &splice);
	while (!list_empty(&splice)) {
		binode = list_entry(splice.next, struct btrfs_inode,
				    delalloc_inodes);

		list_move_tail(&binode->delalloc_inodes,
			       &root->delalloc_inodes);
		inode = igrab(&binode->vfs_inode);
		if (!inode) {
			cond_resched_lock(&root->delalloc_lock);
			continue;
		}
		spin_unlock(&root->delalloc_lock);

#ifdef MY_DEF_HERE
		if (snapshot)
			set_bit(BTRFS_INODE_SNAP_FLUSH, &binode->runtime_flags);
#endif /* MY_DEF_HERE */
		work = btrfs_alloc_delalloc_work(inode, 0, delay_iput);
		if (unlikely(!work)) {
			if (delay_iput)
				btrfs_add_delayed_iput(inode);
			else
				iput(inode);
			ret = -ENOMEM;
			goto out;
		}
		list_add_tail(&work->list, &works);
		btrfs_queue_work(root->fs_info->flush_workers,
				 &work->work);
		ret++;
		if (nr != -1 && ret >= nr)
			goto out;
		cond_resched();
		spin_lock(&root->delalloc_lock);
	}
	spin_unlock(&root->delalloc_lock);

out:
	list_for_each_entry_safe(work, next, &works, list) {
		list_del_init(&work->list);
		btrfs_wait_and_free_delalloc_work(work);
	}

	if (!list_empty_careful(&splice)) {
		spin_lock(&root->delalloc_lock);
		list_splice_tail(&splice, &root->delalloc_inodes);
		spin_unlock(&root->delalloc_lock);
	}
	mutex_unlock(&root->delalloc_mutex);
	return ret;
}

#ifdef MY_DEF_HERE
void syno_writeback_balance_dirty_pages(struct btrfs_fs_info *fs_info)
{
	struct btrfs_delalloc_work *work;
	struct btrfs_inode *binode, *first_binode = NULL;
	struct inode *inode;
	int nr_retry = 8;

	if (fs_info->closing || fs_info->syno_writeback_thread_max == 0)
		goto out;

	if (!writeback_in_progress(&fs_info->bdi))
		goto out;

	if (list_empty(&fs_info->syno_dirty_lru_inodes))
		goto out;

	if (atomic_read(&fs_info->syno_writeback_thread_count) >= fs_info->syno_writeback_thread_max)
		goto out;

	if (!atomic_add_unless(&fs_info->syno_writeback_thread_count, 1, fs_info->syno_writeback_thread_max))
		goto out;

	spin_lock(&fs_info->syno_multiple_writeback_lock);
again:
	if (list_empty(&fs_info->syno_dirty_lru_inodes)) {
		spin_unlock(&fs_info->syno_multiple_writeback_lock);
		goto out_dec;
	}
	binode = list_first_entry(&fs_info->syno_dirty_lru_inodes, struct btrfs_inode, syno_dirty_lru_inode);
	if (first_binode == binode)
		nr_retry = 0;
	if (!first_binode)
		first_binode = binode;
	if (test_bit(BTRFS_INODE_SYNO_WRITEBACK_RUNNING, &binode->runtime_flags)) {
		if (nr_retry-- > 0) {
			list_move_tail(&binode->syno_dirty_lru_inode, &fs_info->syno_dirty_lru_inodes);
			goto again;
		}
		spin_unlock(&fs_info->syno_multiple_writeback_lock);
		goto out_dec;
	}
	inode = igrab(&binode->vfs_inode);
	if (!inode) {
		list_del_init(&binode->syno_dirty_lru_inode);
		clear_bit(BTRFS_INODE_SYNO_WRITEBACK_LRU_LIST, &binode->runtime_flags);
		if (first_binode == binode)
			first_binode = NULL;
		goto again;
	}
	set_bit(BTRFS_INODE_SYNO_WRITEBACK_RUNNING, &BTRFS_I(inode)->runtime_flags);
	list_move_tail(&BTRFS_I(inode)->syno_dirty_lru_inode, &fs_info->syno_dirty_lru_inodes);
	spin_unlock(&fs_info->syno_multiple_writeback_lock);

	work = btrfs_alloc_delalloc_work(inode, 0, 0);
	if (!work)
		goto out_inode;
	work->syno_writeback = 1;
	btrfs_queue_work(fs_info->syno_multiple_writeback_workers, &work->work);

out:
	return;

out_inode:
	clear_bit(BTRFS_INODE_SYNO_WRITEBACK_RUNNING, &BTRFS_I(inode)->runtime_flags);
	iput(inode);
out_dec:
	atomic_dec(&fs_info->syno_writeback_thread_count);
	goto out;
}
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
int btrfs_start_delalloc_inodes(struct btrfs_root *root, int delay_iput, int snapshot)
#else
int btrfs_start_delalloc_inodes(struct btrfs_root *root, int delay_iput)
#endif /* MY_DEF_HERE */
{
	int ret;

	if (test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state))
		return -EROFS;

#ifdef MY_DEF_HERE
	ret = __start_delalloc_inodes(root, delay_iput, -1, snapshot);
#else
	ret = __start_delalloc_inodes(root, delay_iput, -1);
#endif /* MY_DEF_HERE */
	if (ret > 0)
		ret = 0;
	/*
	 * the filemap_flush will queue IO into the worker threads, but
	 * we have to make sure the IO is actually started and that
	 * ordered extents get created before we return
	 */
	atomic_inc(&root->fs_info->async_submit_draining);
	while (atomic_read(&root->fs_info->nr_async_submits) ||
	      atomic_read(&root->fs_info->async_delalloc_pages)) {
		wait_event(root->fs_info->async_submit_wait,
		   (atomic_read(&root->fs_info->nr_async_submits) == 0 &&
		    atomic_read(&root->fs_info->async_delalloc_pages) == 0));
	}
	atomic_dec(&root->fs_info->async_submit_draining);
	return ret;
}

int btrfs_start_delalloc_roots(struct btrfs_fs_info *fs_info, int delay_iput,
			       int nr)
{
	struct btrfs_root *root;
	struct list_head splice;
	int ret;

	if (test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state))
		return -EROFS;

	INIT_LIST_HEAD(&splice);

	mutex_lock(&fs_info->delalloc_root_mutex);
	spin_lock(&fs_info->delalloc_root_lock);
	list_splice_init(&fs_info->delalloc_roots, &splice);
	while (!list_empty(&splice) && nr) {
		root = list_first_entry(&splice, struct btrfs_root,
					delalloc_root);
		root = btrfs_grab_fs_root(root);
		BUG_ON(!root);
		list_move_tail(&root->delalloc_root,
			       &fs_info->delalloc_roots);
		spin_unlock(&fs_info->delalloc_root_lock);

#ifdef MY_DEF_HERE
		ret = __start_delalloc_inodes(root, delay_iput, nr, 0);
#else
		ret = __start_delalloc_inodes(root, delay_iput, nr);
#endif /* MY_DEF_HERE */
		btrfs_put_fs_root(root);
		if (ret < 0)
			goto out;

		if (nr != -1) {
			nr -= ret;
			WARN_ON(nr < 0);
		}
		spin_lock(&fs_info->delalloc_root_lock);
	}
	spin_unlock(&fs_info->delalloc_root_lock);

	ret = 0;
	atomic_inc(&fs_info->async_submit_draining);
	while (atomic_read(&fs_info->nr_async_submits) ||
	      atomic_read(&fs_info->async_delalloc_pages)) {
		wait_event(fs_info->async_submit_wait,
		   (atomic_read(&fs_info->nr_async_submits) == 0 &&
		    atomic_read(&fs_info->async_delalloc_pages) == 0));
	}
	atomic_dec(&fs_info->async_submit_draining);
out:
	if (!list_empty_careful(&splice)) {
		spin_lock(&fs_info->delalloc_root_lock);
		list_splice_tail(&splice, &fs_info->delalloc_roots);
		spin_unlock(&fs_info->delalloc_root_lock);
	}
	mutex_unlock(&fs_info->delalloc_root_mutex);
	return ret;
}

static int btrfs_symlink(struct inode *dir, struct dentry *dentry,
			 const char *symname)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct inode *inode = NULL;
	int err;
	int drop_inode = 0;
	u64 objectid;
	u64 index = 0;
	int name_len;
	int datasize;
	unsigned long ptr;
	struct btrfs_file_extent_item *ei;
	struct extent_buffer *leaf;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	int credit_for_syno = 0;
#endif

	name_len = strlen(symname);
	if (name_len > BTRFS_MAX_INLINE_DATA_SIZE(root))
		return -ENAMETOOLONG;

#ifdef MY_DEF_HERE
	err = btrfs_check_dir_item_collision(root, dir->i_ino, 0,
			     dentry->d_name.name, dentry->d_name.len);
	if (err)
		return err;
	// 1 for dir_item_caseless
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		credit_for_syno++;
#endif

#ifdef MY_DEF_HERE
	// 1 for the prop for compression
	if (test_bit(BTRFS_INODE_HAS_PROPS, &BTRFS_I(dir)->runtime_flags))
		credit_for_syno++;
#endif
	/*
	 * 2 items for inode item and ref
	 * 2 items for dir items
	 * 1 item for updating parent inode item
	 * 1 item for the inline extent item
	 * 1 item for xattr if selinux is on
	 */
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	trans = btrfs_start_transaction(root, 7 + credit_for_syno);
#else
	trans = btrfs_start_transaction(root, 7);
#endif /* MY_DEF_HERE || MY_DEF_HERE */
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	err = btrfs_find_free_ino(root, &objectid);
	if (err)
		goto out_unlock;

	inode = btrfs_new_inode(trans, root, dir, dentry->d_name.name,
				dentry->d_name.len, btrfs_ino(dir), objectid,
				S_IFLNK|S_IRWXUGO, &index);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_unlock;
	}

	/*
	* If the active LSM wants to access the inode during
	* d_instantiate it needs these. Smack checks to see
	* if the filesystem supports xattrs by looking at the
	* ops vector.
	*/
	inode->i_fop = &btrfs_file_operations;
	inode->i_op = &btrfs_file_inode_operations;
	inode->i_mapping->a_ops = &btrfs_aops;
	inode->i_mapping->backing_dev_info = &root->fs_info->bdi;
	BTRFS_I(inode)->io_tree.ops = &btrfs_extent_io_ops;

	err = btrfs_init_inode_security(trans, inode, dir, &dentry->d_name);
	if (err)
		goto out_unlock_inode;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	err = btrfs_syno_init_attr(trans, inode);
	if (err)
		goto out_unlock_inode;
#endif /* MY_DEF_HERE || MY_DEF_HERE */

	path = btrfs_alloc_path();
	if (!path) {
		err = -ENOMEM;
		goto out_unlock_inode;
	}
	key.objectid = btrfs_ino(inode);
	key.offset = 0;
	btrfs_set_key_type(&key, BTRFS_EXTENT_DATA_KEY);
	datasize = btrfs_file_extent_calc_inline_size(name_len);
	err = btrfs_insert_empty_item(trans, root, path, &key,
				      datasize);
	if (err) {
		btrfs_free_path(path);
		goto out_unlock_inode;
	}
	leaf = path->nodes[0];
	ei = btrfs_item_ptr(leaf, path->slots[0],
			    struct btrfs_file_extent_item);
	btrfs_set_file_extent_generation(leaf, ei, trans->transid);
	btrfs_set_file_extent_type(leaf, ei,
				   BTRFS_FILE_EXTENT_INLINE);
	btrfs_set_file_extent_encryption(leaf, ei, 0);
	btrfs_set_file_extent_compression(leaf, ei, 0);
	btrfs_set_file_extent_other_encoding(leaf, ei, 0);
	btrfs_set_file_extent_ram_bytes(leaf, ei, name_len);

	ptr = btrfs_file_extent_inline_start(ei);
	write_extent_buffer(leaf, symname, ptr, name_len);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_free_path(path);

	inode->i_op = &btrfs_symlink_inode_operations;
	inode->i_mapping->a_ops = &btrfs_symlink_aops;
	inode->i_mapping->backing_dev_info = &root->fs_info->bdi;
	inode_set_bytes(inode, name_len);
	btrfs_i_size_write(inode, name_len);
	err = btrfs_update_inode(trans, root, inode);
	/*
	 * Last step, add directory indexes for our symlink inode. This is the
	 * last step to avoid extra cleanup of these indexes if an error happens
	 * elsewhere above.
	 */
	if (!err)
		err = btrfs_add_nondir(trans, dir, dentry, inode, 0, index);
	if (err) {
		drop_inode = 1;
		goto out_unlock_inode;
	}

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);

out_unlock:
	btrfs_end_transaction(trans, root);
	if (drop_inode) {
		inode_dec_link_count(inode);
		iput(inode);
	}
	btrfs_btree_balance_dirty(root);
	return err;

out_unlock_inode:
	drop_inode = 1;
	unlock_new_inode(inode);
	goto out_unlock;
}

static int __btrfs_prealloc_file_range(struct inode *inode, int mode,
				       u64 start, u64 num_bytes, u64 min_size,
				       loff_t actual_len, u64 *alloc_hint,
				       struct btrfs_trans_handle *trans)
{
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_map *em;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_key ins;
	u64 cur_offset = start;
	u64 i_size;
	u64 cur_bytes;
	u64 last_alloc = (u64)-1;
	int ret = 0;
	bool own_trans = true;
#ifdef MY_DEF_HERE
	int no_sync_delayed = 1;
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	int mark_written = (mode & FALLOC_FL_MARK_WRITTEN);
	int extent_type = BTRFS_FILE_EXTENT_PREALLOC;

	if (mark_written)
		extent_type = BTRFS_FILE_EXTENT_REG;
#endif /* MY_DEF_HERE */
	if (trans)
		own_trans = false;
	while (num_bytes > 0) {
		if (own_trans) {
			trans = btrfs_start_transaction(root, 3);
			if (IS_ERR(trans)) {
				ret = PTR_ERR(trans);
				break;
			}
		}

		cur_bytes = min(num_bytes, 256ULL * 1024 * 1024);
		cur_bytes = max(cur_bytes, min_size);
		/*
		 * If we are severely fragmented we could end up with really
		 * small allocations, so if the allocator is returning small
		 * chunks lets make its job easier by only searching for those
		 * sized chunks.
		 */
		cur_bytes = min(cur_bytes, last_alloc);
		ret = btrfs_reserve_extent(root, cur_bytes, min_size, 0,
					   *alloc_hint, &ins, 1, 0);
		if (ret) {
			if (own_trans)
				btrfs_end_transaction(trans, root);
			break;
		}

		last_alloc = ins.offset;
#ifdef MY_DEF_HERE
		ret = insert_reserved_file_extent(trans, inode,
						  cur_offset, ins.objectid,
						  ins.offset, ins.offset,
						  ins.offset, 0, 0, 0,
						  extent_type);
#else
		ret = insert_reserved_file_extent(trans, inode,
						  cur_offset, ins.objectid,
						  ins.offset, ins.offset,
						  ins.offset, 0, 0, 0,
						  BTRFS_FILE_EXTENT_PREALLOC);
#endif /* MY_DEF_HERE */
		if (ret) {
			btrfs_free_reserved_extent(root, ins.objectid,
						   ins.offset, 0);
			btrfs_abort_transaction(trans, root, ret);
			if (own_trans)
				btrfs_end_transaction(trans, root);
			break;
		}
		btrfs_drop_extent_cache(inode, cur_offset,
					cur_offset + ins.offset -1, 0);

		em = alloc_extent_map();
		if (!em) {
			set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
				&BTRFS_I(inode)->runtime_flags);
			goto next;
		}

		em->start = cur_offset;
		em->orig_start = cur_offset;
		em->len = ins.offset;
		em->block_start = ins.objectid;
		em->block_len = ins.offset;
		em->orig_block_len = ins.offset;
		em->ram_bytes = ins.offset;
		em->bdev = root->fs_info->fs_devices->latest_bdev;
#ifdef MY_DEF_HERE
		if (!mark_written)
#endif /* MY_DEF_HERE */
		set_bit(EXTENT_FLAG_PREALLOC, &em->flags);
		em->generation = trans->transid;

		while (1) {
			write_lock(&em_tree->lock);
			ret = add_extent_mapping(em_tree, em, 1);
			write_unlock(&em_tree->lock);
			if (ret != -EEXIST)
				break;
			btrfs_drop_extent_cache(inode, cur_offset,
						cur_offset + ins.offset - 1,
						0);
		}
		free_extent_map(em);
next:
		num_bytes -= ins.offset;
		cur_offset += ins.offset;
		*alloc_hint = ins.objectid + ins.offset;

		inode_inc_iversion(inode);
		inode->i_ctime = CURRENT_TIME;
#ifdef MY_DEF_HERE
		if (!mark_written)
#endif /* MY_DEF_HERE */
		BTRFS_I(inode)->flags |= BTRFS_INODE_PREALLOC;
		if (!(mode & FALLOC_FL_KEEP_SIZE) &&
		    (actual_len > inode->i_size) &&
		    (cur_offset > inode->i_size)) {
			if (cur_offset > actual_len)
				i_size = actual_len;
			else
				i_size = cur_offset;
			i_size_write(inode, i_size);
			btrfs_ordered_update_i_size(inode, i_size, NULL);
		}

		ret = btrfs_update_inode(trans, root, inode);

		if (ret) {
			btrfs_abort_transaction(trans, root, ret);
			if (own_trans)
				btrfs_end_transaction(trans, root);
			break;
		}

#ifdef MY_DEF_HERE
		if (own_trans) {
			if (no_sync_delayed)
				btrfs_end_transaction_nosync_delayed(trans, root);
			else
				btrfs_end_transaction(trans, root);
		}
		no_sync_delayed = 0;
#else
		if (own_trans)
			btrfs_end_transaction(trans, root);
#endif /* MY_DEF_HERE */
	}
	return ret;
}

int btrfs_prealloc_file_range(struct inode *inode, int mode,
			      u64 start, u64 num_bytes, u64 min_size,
			      loff_t actual_len, u64 *alloc_hint)
{
	return __btrfs_prealloc_file_range(inode, mode, start, num_bytes,
					   min_size, actual_len, alloc_hint,
					   NULL);
}

int btrfs_prealloc_file_range_trans(struct inode *inode,
				    struct btrfs_trans_handle *trans, int mode,
				    u64 start, u64 num_bytes, u64 min_size,
				    loff_t actual_len, u64 *alloc_hint)
{
	return __btrfs_prealloc_file_range(inode, mode, start, num_bytes,
					   min_size, actual_len, alloc_hint, trans);
}

static int btrfs_set_page_dirty(struct page *page)
{
	return __set_page_dirty_nobuffers(page);
}

static int btrfs_permission(struct inode *inode, int mask)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	umode_t mode = inode->i_mode;

	if (mask & MAY_WRITE &&
	    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))) {
		if (btrfs_root_readonly(root))
			return -EROFS;
		if (BTRFS_I(inode)->flags & BTRFS_INODE_READONLY)
			return -EACCES;
	}
	return generic_permission(inode, mask);
}

#ifdef MY_DEF_HERE
static int btrfs_syno_permission(struct dentry *dentry, int mask)
{
	struct inode *inode = dentry->d_inode;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	umode_t mode = inode->i_mode;

	if (mask & MASK_RDONLY_CHECK &&
	    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))) {
		if (btrfs_root_readonly(root))
			return -EROFS;
		if (BTRFS_I(inode)->flags & BTRFS_INODE_READONLY)
			return -EACCES;
	}
	return synoacl_mod_permission(dentry, mask);
}

static int btrfs_syno_may_delete(struct dentry *victim, struct inode *dir)
{
	struct btrfs_root *root = BTRFS_I(dir)->root;

	if (btrfs_root_readonly(root))
		return -EROFS;
	if (BTRFS_I(dir)->flags & BTRFS_INODE_READONLY)
		return -EACCES;
	return synoacl_mod_may_delete(victim, dir);
}
#endif

#ifdef CONFIG_SWAP
/*
 * Add an entry indicating a block group or device which is pinned by a
 * swapfile. Returns 0 on success, 1 if there is already an entry for it, or a
 * negative errno on failure.
 */
static int btrfs_add_swapfile_pin(struct inode *inode, void *ptr,
				  bool is_block_group)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct btrfs_swapfile_pin *sp, *entry;
	struct rb_node **p;
	struct rb_node *parent = NULL;

	sp = kmalloc(sizeof(*sp), GFP_NOFS);
	if (!sp)
		return -ENOMEM;
	sp->ptr = ptr;
	sp->inode = inode;
	sp->is_block_group = is_block_group;

	spin_lock(&fs_info->swapfile_pins_lock);
	p = &fs_info->swapfile_pins.rb_node;
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct btrfs_swapfile_pin, node);
		if (sp->ptr < entry->ptr ||
		    (sp->ptr == entry->ptr && sp->inode < entry->inode)) {
			p = &(*p)->rb_left;
		} else if (sp->ptr > entry->ptr ||
			   (sp->ptr == entry->ptr && sp->inode > entry->inode)) {
			p = &(*p)->rb_right;
		} else {
			spin_unlock(&fs_info->swapfile_pins_lock);
			kfree(sp);
			return 1;
		}
	}
	rb_link_node(&sp->node, parent, p);
	rb_insert_color(&sp->node, &fs_info->swapfile_pins);
	spin_unlock(&fs_info->swapfile_pins_lock);
	return 0;
}

/* Free all of the entries pinned by this swapfile. */
static void btrfs_free_swapfile_pins(struct inode *inode)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct btrfs_swapfile_pin *sp;
	struct rb_node *node, *next;

	spin_lock(&fs_info->swapfile_pins_lock);
	node = rb_first(&fs_info->swapfile_pins);
	while (node) {
		next = rb_next(node);
		sp = rb_entry(node, struct btrfs_swapfile_pin, node);
		if (sp->inode == inode) {
			rb_erase(&sp->node, &fs_info->swapfile_pins);
			if (sp->is_block_group)
				btrfs_put_block_group(sp->ptr);
			kfree(sp);
		}
		node = next;
	}
	spin_unlock(&fs_info->swapfile_pins_lock);
}

struct btrfs_swap_info {
	u64 start;
	u64 block_start;
	u64 block_len;
	u64 lowest_ppage;
	u64 highest_ppage;
	unsigned long nr_pages;
	int nr_extents;
};

static int btrfs_add_swap_extent(struct swap_info_struct *sis,
				 struct btrfs_swap_info *bsi)
{
	unsigned long nr_pages;
	u64 first_ppage, first_ppage_reported, next_ppage;
	int ret;

	first_ppage = ALIGN(bsi->block_start, PAGE_SIZE) >> PAGE_SHIFT;
	next_ppage = ALIGN_DOWN(bsi->block_start + bsi->block_len,
				PAGE_SIZE) >> PAGE_SHIFT;

	if (first_ppage >= next_ppage)
		return 0;
	nr_pages = next_ppage - first_ppage;

	first_ppage_reported = first_ppage;
	if (bsi->start == 0)
		first_ppage_reported++;
	if (bsi->lowest_ppage > first_ppage_reported)
		bsi->lowest_ppage = first_ppage_reported;
	if (bsi->highest_ppage < (next_ppage - 1))
		bsi->highest_ppage = next_ppage - 1;

	ret = add_swap_extent(sis, bsi->nr_pages, nr_pages, first_ppage);
	if (ret < 0)
		return ret;
	bsi->nr_extents += ret;
	bsi->nr_pages += nr_pages;
	return 0;
}

static void btrfs_swap_deactivate(struct file *file)
{
	struct inode *inode = file_inode(file);

	btrfs_free_swapfile_pins(inode);
	atomic_dec(&BTRFS_I(inode)->root->nr_swapfiles);
}

static int btrfs_swap_activate(struct swap_info_struct *sis, struct file *file,
			       sector_t *span)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_state *cached_state = NULL;
	struct extent_map *em = NULL;
	struct btrfs_device *device = NULL;
	struct btrfs_swap_info bsi = {
		.lowest_ppage = (sector_t)-1ULL,
	};
	int ret = 0;
	u64 isize;
	u64 start;

	/*
	 * If the swap file was just created, make sure delalloc is done. If the
	 * file changes again after this, the user is doing something stupid and
	 * we don't really care.
	 */
	ret = btrfs_wait_ordered_range(inode, 0, (u64)-1);
	if (ret)
		return ret;

	/*
	 * The inode is locked, so these flags won't change after we check them.
	 */
	if (BTRFS_I(inode)->flags & BTRFS_INODE_COMPRESS) {
		btrfs_warn(fs_info, "swapfile must not be compressed");
		return -EINVAL;
	}
	if (!(BTRFS_I(inode)->flags & BTRFS_INODE_NODATACOW)) {
		btrfs_warn(fs_info, "swapfile must not be copy-on-write");
		return -EINVAL;
	}
	if (!(BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)) {
		btrfs_warn(fs_info, "swapfile must not be checksummed");
		return -EINVAL;
	}

	/*
	 * Balance or device remove/replace/resize can move stuff around from
	 * under us. The EXCL_OP flag makes sure they aren't running/won't run
	 * concurrently while we are mapping the swap extents, and
	 * fs_info->swapfile_pins prevents them from running while the swap file
	 * is active and moving the extents. Note that this also prevents a
	 * concurrent device add which isn't actually necessary, but it's not
	 * really worth the trouble to allow it.
	 */
	if (atomic_xchg(&fs_info->mutually_exclusive_operation_running, 1)) {
		btrfs_warn(fs_info,
	   "cannot activate swapfile while exclusive operation is running");
		return -EBUSY;
	}
	/*
	 * Snapshots can create extents which require COW even if NODATACOW is
	 * set. We use this counter to prevent snapshots. We must increment it
	 * before walking the extents because we don't want a concurrent
	 * snapshot to run after we've already checked the extents.
	 */
	atomic_inc(&BTRFS_I(inode)->root->nr_swapfiles);

	isize = ALIGN_DOWN(inode->i_size, root->sectorsize);

	lock_extent_bits(io_tree, 0, isize - 1, 0, &cached_state);
	start = 0;
	while (start < isize) {
		u64 logical_block_start, physical_block_start;
		struct btrfs_block_group_cache *bg;
		u64 len = isize - start;

		em = btrfs_get_extent(inode, NULL, 0, start, len, 0);
		if (IS_ERR(em)) {
			ret = PTR_ERR(em);
			goto out;
		}

		if (em->block_start == EXTENT_MAP_HOLE) {
			btrfs_warn(fs_info, "swapfile must not have holes");
			ret = -EINVAL;
			goto out;
		}
		if (em->block_start == EXTENT_MAP_INLINE) {
			/*
			 * It's unlikely we'll ever actually find ourselves
			 * here, as a file small enough to fit inline won't be
			 * big enough to store more than the swap header, but in
			 * case something changes in the future, let's catch it
			 * here rather than later.
			 */
			btrfs_warn(fs_info, "swapfile must not be inline");
			ret = -EINVAL;
			goto out;
		}
		if (test_bit(EXTENT_FLAG_COMPRESSED, &em->flags)) {
			btrfs_warn(fs_info, "swapfile must not be compressed");
			ret = -EINVAL;
			goto out;
		}

		logical_block_start = em->block_start + (start - em->start);
		len = min(len, em->len - (start - em->start));
		free_extent_map(em);
		em = NULL;

		ret = can_nocow_extent(inode, start, &len, NULL, NULL, NULL);
		if (ret < 0) {
			goto out;
		} else if (ret) {
			ret = 0;
		} else {
			btrfs_warn(fs_info,
				   "swapfile must not be copy-on-write");
			ret = -EINVAL;
			goto out;
		}

		em = btrfs_get_chunk_map(fs_info, logical_block_start, len);
		if (IS_ERR(em)) {
			ret = PTR_ERR(em);
			goto out;
		}

		if (em->map_lookup->type & BTRFS_BLOCK_GROUP_PROFILE_MASK) {
			btrfs_warn(fs_info,
				   "swapfile must have single data profile");
			ret = -EINVAL;
			goto out;
		}

		if (device == NULL) {
			device = em->map_lookup->stripes[0].dev;
			ret = btrfs_add_swapfile_pin(inode, device, false);
			if (ret == 1)
				ret = 0;
			else if (ret)
				goto out;
		} else if (device != em->map_lookup->stripes[0].dev) {
			btrfs_warn(fs_info, "swapfile must be on one device");
			ret = -EINVAL;
			goto out;
		}

		physical_block_start = (em->map_lookup->stripes[0].physical +
					(logical_block_start - em->start));
		len = min(len, em->len - (logical_block_start - em->start));
		free_extent_map(em);
		em = NULL;

		bg = btrfs_lookup_block_group(fs_info, logical_block_start);
		if (!bg) {
			btrfs_warn(fs_info,
			   "could not find block group containing swapfile");
			ret = -EINVAL;
			goto out;
		}

		ret = btrfs_add_swapfile_pin(inode, bg, true);
		if (ret) {
			btrfs_put_block_group(bg);
			if (ret == 1)
				ret = 0;
			else
				goto out;
		}

		if (bsi.block_len &&
		    bsi.block_start + bsi.block_len == physical_block_start) {
			bsi.block_len += len;
		} else {
			if (bsi.block_len) {
				ret = btrfs_add_swap_extent(sis, &bsi);
				if (ret)
					goto out;
			}
			bsi.start = start;
			bsi.block_start = physical_block_start;
			bsi.block_len = len;
		}

		start += len;
	}

	if (bsi.block_len)
		ret = btrfs_add_swap_extent(sis, &bsi);

out:
	if (!IS_ERR_OR_NULL(em))
		free_extent_map(em);

	unlock_extent_cached(io_tree, 0, isize - 1, &cached_state, GFP_NOFS);

	if (ret)
		btrfs_swap_deactivate(file);

	atomic_set(&fs_info->mutually_exclusive_operation_running, 0);

	if (ret)
		return ret;

	if (device)
		sis->bdev = device->bdev;
	*span = bsi.highest_ppage - bsi.lowest_ppage + 1;
	sis->max = bsi.nr_pages;
	sis->pages = bsi.nr_pages - 1;
	sis->highest_bit = bsi.nr_pages - 1;
	return bsi.nr_extents;
}
#else
static void btrfs_swap_deactivate(struct file *file)
{
}

static int btrfs_swap_activate(struct swap_info_struct *sis, struct file *file,
			       sector_t *span)
{
	return -EOPNOTSUPP;
}
#endif

#ifdef MY_ABC_HERE
int btrfs_quota_query(struct file *file, u64 *used, u64 *reserved, u64 *limit)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_qgroup_query_args qqa;
	int ret;

	memset(&qqa, 0, sizeof(qqa));
	// use subvol id as qgroup id
	ret = btrfs_qgroup_query(root->fs_info, root->root_key.objectid, &qqa);
	if (!ret) {
		*used = qqa.rfer;
		*reserved = qqa.reserved;
		*limit = qqa.max_rfer;
	}

	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
int btrfs_syno_space_usage(struct file *file, struct syno_space_usage_info *info)
{
	int ret;
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;

	if (!info) {
		ret = -EINVAL;
		goto out;
	}
	memset(&info->result_mask, 0, sizeof(*info) - offsetof(struct syno_space_usage_info, result_mask));

	if (!info->request_mask)
		goto success;

#ifdef MY_DEF_HERE
	if ((info->request_mask & SYNO_SPACE_USAGE_REQUEST_DATA_USED) &&
		root->syno_usage_enabled) {
		info->data_used = root->syno_usage_root_status.num_bytes;
		if (root->syno_usage_root_status.flags & BTRFS_SYNO_USAGE_ROOT_FLAG_FULL_RESCAN)
			info->flags |= SYNO_SPACE_USAGE_FLAG_RESCAN;
		info->result_mask |= SYNO_SPACE_USAGE_REQUEST_DATA_USED;
	}

	if (info->request_mask & SYNO_SPACE_USAGE_REQUEST_DATA_DELAY_ALLOCATED &&
		root->syno_delalloc_bytes) {
		info->data_delay_allocated = percpu_counter_sum_positive(root->syno_delalloc_bytes);
		info->result_mask |= SYNO_SPACE_USAGE_REQUEST_DATA_DELAY_ALLOCATED;
	}
#endif /* MY_DEF_HERE */

	if (info->request_mask & SYNO_SPACE_USAGE_REQUEST_METADATA_USED) {
		info->metadata_used = btrfs_root_used(&root->root_item);
		info->result_mask |= SYNO_SPACE_USAGE_REQUEST_METADATA_USED;
	}

	if (!info->result_mask) {
		ret = -EOPNOTSUPP;
		goto out;
	}

success:
	ret = 0;
out:
	return ret;
}
#endif /* MY_ABC_HERE */

static const struct inode_operations btrfs_dir_inode_operations = {
#ifdef MY_DEF_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif
#ifdef MY_DEF_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif
	.getattr	= btrfs_getattr,
	.lookup		= btrfs_lookup,
	.create		= btrfs_create,
	.unlink		= btrfs_unlink,
	.link		= btrfs_link,
	.mkdir		= btrfs_mkdir,
	.rmdir		= btrfs_rmdir,
	.rename		= btrfs_rename,
	.symlink	= btrfs_symlink,
	.setattr	= btrfs_setattr,
	.mknod		= btrfs_mknod,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
	.permission	= btrfs_permission,
#ifdef MY_DEF_HERE
	.syno_acl_get   = btrfs_get_syno_acl,
	.syno_acl_set   = btrfs_set_syno_acl,
	.syno_permission = btrfs_syno_permission,
	.syno_may_delete = btrfs_syno_may_delete,
#endif
	.get_acl	= btrfs_get_acl,
	.update_time	= btrfs_update_time,
};
static const struct inode_operations btrfs_dir_ro_inode_operations = {
#ifdef MY_DEF_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif
#ifdef MY_DEF_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif
	.lookup		= btrfs_lookup,
	.permission	= btrfs_permission,
	.get_acl	= btrfs_get_acl,
	.update_time	= btrfs_update_time,
};

static const struct file_operations btrfs_dir_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= btrfs_real_readdir,
	.open		= btrfs_opendir,
	.unlocked_ioctl	= btrfs_ioctl,
#ifdef CONFIG_COMPAT
#ifdef MY_DEF_HERE
	.compat_ioctl = btrfs_compat_ioctl,
#else
	.compat_ioctl	= btrfs_ioctl,
#endif /* MY_DEF_HERE */
#endif
	.release        = btrfs_release_file,
	.fsync		= btrfs_sync_file,
#ifdef MY_ABC_HERE
	.quota_query = btrfs_quota_query,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	.syno_space_usage = btrfs_syno_space_usage,
#endif /* MY_ABC_HERE */
};

static struct extent_io_ops btrfs_extent_io_ops = {
	.fill_delalloc = run_delalloc_range,
	.submit_bio_hook = btrfs_submit_bio_hook,
	.merge_bio_hook = btrfs_merge_bio_hook,
	.readpage_end_io_hook = btrfs_readpage_end_io_hook,
	.writepage_end_io_hook = btrfs_writepage_end_io_hook,
	.writepage_start_hook = btrfs_writepage_start_hook,
	.set_bit_hook = btrfs_set_bit_hook,
	.clear_bit_hook = btrfs_clear_bit_hook,
	.merge_extent_hook = btrfs_merge_extent_hook,
	.split_extent_hook = btrfs_split_extent_hook,
};

/*
 * btrfs doesn't support the bmap operation because swapfiles
 * use bmap to make a mapping of extents in the file.  They assume
 * these extents won't change over the life of the file and they
 * use the bmap result to do IO directly to the drive.
 *
 * the btrfs bmap call would return logical addresses that aren't
 * suitable for IO and they also will change frequently as COW
 * operations happen.  So, swapfile + btrfs == corruption.
 *
 * For now we're avoiding this by dropping bmap.
 */
static const struct address_space_operations btrfs_aops = {
	.readpage	= btrfs_readpage,
	.writepage	= btrfs_writepage,
	.writepages	= btrfs_writepages,
	.readpages	= btrfs_readpages,
	.direct_IO	= btrfs_direct_IO,
	.invalidatepage = btrfs_invalidatepage,
	.releasepage	= btrfs_releasepage,
	.set_page_dirty	= btrfs_set_page_dirty,
	.error_remove_page = generic_error_remove_page,
	.swap_activate	= btrfs_swap_activate,
	.swap_deactivate = btrfs_swap_deactivate,
};

static const struct address_space_operations btrfs_symlink_aops = {
	.readpage	= btrfs_readpage,
	.writepage	= btrfs_writepage,
	.invalidatepage = btrfs_invalidatepage,
	.releasepage	= btrfs_releasepage,
};

static const struct inode_operations btrfs_file_inode_operations = {
#ifdef MY_DEF_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif
#ifdef MY_DEF_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif
	.getattr	= btrfs_getattr,
	.setattr	= btrfs_setattr,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr      = btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
	.permission	= btrfs_permission,
	.fiemap		= btrfs_fiemap,
#ifdef MY_DEF_HERE
	.syno_acl_get	= btrfs_get_syno_acl,
	.syno_acl_set	= btrfs_set_syno_acl,
	.syno_permission = btrfs_syno_permission,
	.syno_may_delete = btrfs_syno_may_delete,
#endif
	.get_acl	= btrfs_get_acl,
	.update_time	= btrfs_update_time,
};
static const struct inode_operations btrfs_special_inode_operations = {
#ifdef MY_DEF_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif
#ifdef MY_DEF_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif
	.getattr	= btrfs_getattr,
	.setattr	= btrfs_setattr,
	.permission	= btrfs_permission,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
#ifdef MY_DEF_HERE
	.syno_acl_get	= btrfs_get_syno_acl,
	.syno_acl_set	= btrfs_set_syno_acl,
	.syno_permission = btrfs_syno_permission,
	.syno_may_delete = btrfs_syno_may_delete,
#endif
	.get_acl	= btrfs_get_acl,
	.update_time	= btrfs_update_time,
};
static const struct inode_operations btrfs_symlink_inode_operations = {
#ifdef MY_DEF_HERE
	.syno_getattr	= btrfs_syno_getattr,
#endif
#ifdef MY_DEF_HERE
	.syno_set_crtime = btrfs_syno_set_crtime,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_bit = btrfs_syno_set_archive_bit,
#endif
#ifdef MY_DEF_HERE
	.syno_set_archive_ver = btrfs_syno_set_archive_ver,
	.syno_get_archive_ver = btrfs_syno_get_archive_ver,
#endif
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.getattr	= btrfs_getattr,
	.setattr	= btrfs_setattr,
	.permission	= btrfs_permission,
	.setxattr	= btrfs_setxattr,
	.getxattr	= btrfs_getxattr,
	.listxattr	= btrfs_listxattr,
	.removexattr	= btrfs_removexattr,
	.get_acl	= btrfs_get_acl,
	.update_time	= btrfs_update_time,
};

#ifdef MY_DEF_HERE
/* Hash a string to an integer in a caseless way */
static int btrfs_dentry_hash(const struct dentry *dentry, const struct inode *inode, struct qstr *this)
{
	int ret;
	u32 hash;
	ret = btrfs_upper_name_hash(this->name, this->len, &hash);
	if (!ret) {
		this->hash = hash;
	}
	return ret;
}

/* return 1 on failure and 0 on success */
static int btrfs_dentry_compare(const struct dentry *dentry, unsigned int len, const char *str, const struct qstr *name, int caseless)
{
	if (caseless) {
		return syno_utf8_strcmp(str, name->name, len, name->len, NULL);
	} else {
		if (len != name->len)
			return 1;
		return dentry_cmp(dentry, name->name, name->len);
	}
}
#endif /* MY_DEF_HERE */
const struct dentry_operations btrfs_dentry_operations = {
	.d_delete	= btrfs_dentry_delete,
	.d_release	= btrfs_dentry_release,
#ifdef MY_DEF_HERE
	.d_hash		= btrfs_dentry_hash,
	.d_compare_case	= btrfs_dentry_compare,
#endif /* MY_DEF_HERE */
};
