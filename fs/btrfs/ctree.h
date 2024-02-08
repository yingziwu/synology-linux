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

#ifndef __BTRFS_CTREE__
#define __BTRFS_CTREE__

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <trace/events/btrfs.h>
#include <asm/kmap_types.h>
#include <linux/pagemap.h>
#include <linux/btrfs.h>
#include <linux/workqueue.h>
#ifdef MY_ABC_HERE
#include <linux/kfifo.h>
#endif
#ifdef MY_ABC_HERE
#include <linux/sizes.h>
#endif /* MY_ABC_HERE */
#include "extent_io.h"
#include "extent_map.h"
#include "async-thread.h"

struct btrfs_trans_handle;
struct btrfs_transaction;
struct btrfs_pending_snapshot;
extern struct kmem_cache *btrfs_trans_handle_cachep;
extern struct kmem_cache *btrfs_transaction_cachep;
extern struct kmem_cache *btrfs_bit_radix_cachep;
extern struct kmem_cache *btrfs_path_cachep;
extern struct kmem_cache *btrfs_free_space_cachep;
struct btrfs_ordered_sum;

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
#define STATIC noinline
#else
#define STATIC static noinline
#endif

#define BTRFS_MAGIC 0x4D5F53665248425FULL /* ascii _BHRfS_M, no null */

#define BTRFS_MAX_MIRRORS 3

#define BTRFS_MAX_LEVEL 8

#define BTRFS_COMPAT_EXTENT_TREE_V0

/*
 * files bigger than this get some pre-flushing when they are added
 * to the ordered operations list.  That way we limit the total
 * work done by the commit
 */
#define BTRFS_ORDERED_OPERATIONS_FLUSH_LIMIT (8 * 1024 * 1024)

/* holds pointers to all of the tree roots */
#define BTRFS_ROOT_TREE_OBJECTID 1ULL

/* stores information about which extents are in use, and reference counts */
#define BTRFS_EXTENT_TREE_OBJECTID 2ULL

/*
 * chunk tree stores translations from logical -> physical block numbering
 * the super block points to the chunk tree
 */
#define BTRFS_CHUNK_TREE_OBJECTID 3ULL

/*
 * stores information about which areas of a given device are in use.
 * one per device.  The tree of tree roots points to the device tree
 */
#define BTRFS_DEV_TREE_OBJECTID 4ULL

/* one per subvolume, storing files and directories */
#define BTRFS_FS_TREE_OBJECTID 5ULL

/* directory objectid inside the root tree */
#define BTRFS_ROOT_TREE_DIR_OBJECTID 6ULL

/* holds checksums of all the data extents */
#define BTRFS_CSUM_TREE_OBJECTID 7ULL

/* holds quota configuration and tracking */
#ifdef MY_ABC_HERE
#define BTRFS_QUOTA_TREE_OBJECTID 201ULL
#else
#define BTRFS_QUOTA_TREE_OBJECTID 8ULL
#endif

/* for storing items that use the BTRFS_UUID_KEY* types */
#define BTRFS_UUID_TREE_OBJECTID 9ULL

/* tracks free space in block groups. */
#define BTRFS_FREE_SPACE_TREE_OBJECTID 10ULL

#ifdef MY_ABC_HERE
/* holds subvolume usr quota configuration and tracking */
#define BTRFS_USRQUOTA_TREE_OBJECTID 200ULL
#endif

#ifdef MY_ABC_HERE
#define BTRFS_BLOCK_GROUP_HINT_TREE_OBJECTID 202ULL
#define BTRFS_BLOCK_GROUP_CACHE_TREE_OBJECTID 203ULL
#endif

#ifdef MY_ABC_HERE
/*
 * syno usage tree
 */
#define BTRFS_SYNO_USAGE_TREE_OBJECTID 205ULL
/*
 * syno extent usage tree
 */
#define BTRFS_SYNO_EXTENT_USAGE_TREE_OBJECTID 206ULL
#endif /* MY_ABC_HERE */

/* for storing balance parameters in the root tree */
#define BTRFS_BALANCE_OBJECTID -4ULL

/* orhpan objectid for tracking unlinked/truncated files */
#define BTRFS_ORPHAN_OBJECTID -5ULL

/* does write ahead logging to speed up fsyncs */
#define BTRFS_TREE_LOG_OBJECTID -6ULL
#define BTRFS_TREE_LOG_FIXUP_OBJECTID -7ULL

/* for space balancing */
#define BTRFS_TREE_RELOC_OBJECTID -8ULL
#define BTRFS_DATA_RELOC_TREE_OBJECTID -9ULL

/*
 * extent checksums all have this objectid
 * this allows them to share the logging tree
 * for fsyncs
 */
#define BTRFS_EXTENT_CSUM_OBJECTID -10ULL

/* For storing free space cache */
#define BTRFS_FREE_SPACE_OBJECTID -11ULL

/*
 * The inode number assigned to the special inode for storing
 * free ino cache
 */
#define BTRFS_FREE_INO_OBJECTID -12ULL

#ifdef MY_ABC_HERE
/*
 * syno subvol usage objectid in fs_tree
 */
#define BTRFS_SYNO_SUBVOL_USAGE_OBJECTID -206ULL
#endif /* MY_ABC_HERE */

/* dummy objectid represents multiple objectids */
#define BTRFS_MULTIPLE_OBJECTIDS -255ULL

/*
 * All files have objectids in this range.
 */
#define BTRFS_FIRST_FREE_OBJECTID 256ULL
#define BTRFS_LAST_FREE_OBJECTID -256ULL
#define BTRFS_FIRST_CHUNK_TREE_OBJECTID 256ULL


/*
 * the device items go into the chunk tree.  The key is in the form
 * [ 1 BTRFS_DEV_ITEM_KEY device_id ]
 */
#define BTRFS_DEV_ITEMS_OBJECTID 1ULL

#define BTRFS_BTREE_INODE_OBJECTID 1

#define BTRFS_EMPTY_SUBVOL_DIR_OBJECTID 2

#define BTRFS_DEV_REPLACE_DEVID 0ULL

/*
 * the max metadata block size.  This limit is somewhat artificial,
 * but the memmove costs go through the roof for larger blocks.
 */
#ifdef MY_ABC_HERE
#define BTRFS_MAX_METADATA_BLOCKSIZE 16384
#else
#define BTRFS_MAX_METADATA_BLOCKSIZE 65536
#endif

/*
 * we can actually store much bigger names, but lets not confuse the rest
 * of linux
 */
#define BTRFS_NAME_LEN 255

/*
 * Theoretical limit is larger, but we keep this down to a sane
 * value. That should limit greatly the possibility of collisions on
 * inode ref items.
 */
#define BTRFS_LINK_MAX 65535U

/* 32 bytes in various csum fields */
#define BTRFS_CSUM_SIZE 32

/* csum types */
#define BTRFS_CSUM_TYPE_CRC32	0

static int btrfs_csum_sizes[] = { 4, 0 };

/* four bytes for CRC32 */
#define BTRFS_EMPTY_DIR_SIZE 0

/* spefic to btrfs_map_block(), therefore not in include/linux/blk_types.h */
#define REQ_GET_READ_MIRRORS	(1 << 30)

#define BTRFS_FT_UNKNOWN	0
#define BTRFS_FT_REG_FILE	1
#define BTRFS_FT_DIR		2
#define BTRFS_FT_CHRDEV		3
#define BTRFS_FT_BLKDEV		4
#define BTRFS_FT_FIFO		5
#define BTRFS_FT_SOCK		6
#define BTRFS_FT_SYMLINK	7
#define BTRFS_FT_XATTR		8
#define BTRFS_FT_MAX		9

/* ioprio of readahead is set to idle */
#define BTRFS_IOPRIO_READA (IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0))

#define BTRFS_DIRTY_METADATA_THRESH	(32 * 1024 * 1024)

#define BTRFS_MAX_EXTENT_SIZE (128 * 1024 * 1024)

/*
 * The key defines the order in the tree, and so it also defines (optimal)
 * block layout.
 *
 * objectid corresponds to the inode number.
 *
 * type tells us things about the object, and is a kind of stream selector.
 * so for a given inode, keys with type of 1 might refer to the inode data,
 * type of 2 may point to file data in the btree and type == 3 may point to
 * extents.
 *
 * offset is the starting byte offset for this key in the stream.
 *
 * btrfs_disk_key is in disk byte order.  struct btrfs_key is always
 * in cpu native order.  Otherwise they are identical and their sizes
 * should be the same (ie both packed)
 */
struct btrfs_disk_key {
	__le64 objectid;
	u8 type;
	__le64 offset;
} __attribute__ ((__packed__));

struct btrfs_key {
	u64 objectid;
	u8 type;
	u64 offset;
} __attribute__ ((__packed__));

struct btrfs_mapping_tree {
	struct extent_map_tree map_tree;
};

struct btrfs_dev_item {
	/* the internal btrfs device id */
	__le64 devid;

	/* size of the device */
	__le64 total_bytes;

	/* bytes used */
	__le64 bytes_used;

	/* optimal io alignment for this device */
	__le32 io_align;

	/* optimal io width for this device */
	__le32 io_width;

	/* minimal io size for this device */
	__le32 sector_size;

	/* type and info about this device */
	__le64 type;

	/* expected generation for this device */
	__le64 generation;

	/*
	 * starting byte of this partition on the device,
	 * to allow for stripe alignment in the future
	 */
	__le64 start_offset;

	/* grouping information for allocation decisions */
	__le32 dev_group;

	/* seek speed 0-100 where 100 is fastest */
	u8 seek_speed;

	/* bandwidth 0-100 where 100 is fastest */
	u8 bandwidth;

	/* btrfs generated uuid for this device */
	u8 uuid[BTRFS_UUID_SIZE];

	/* uuid of FS who owns this device */
	u8 fsid[BTRFS_UUID_SIZE];
} __attribute__ ((__packed__));

struct btrfs_stripe {
	__le64 devid;
	__le64 offset;
	u8 dev_uuid[BTRFS_UUID_SIZE];
} __attribute__ ((__packed__));

struct btrfs_chunk {
	/* size of this chunk in bytes */
	__le64 length;

	/* objectid of the root referencing this chunk */
	__le64 owner;

	__le64 stripe_len;
	__le64 type;

	/* optimal io alignment for this chunk */
	__le32 io_align;

	/* optimal io width for this chunk */
	__le32 io_width;

	/* minimal io size for this chunk */
	__le32 sector_size;

	/* 2^16 stripes is quite a lot, a second limit is the size of a single
	 * item in the btree
	 */
	__le16 num_stripes;

	/* sub stripes only matter for raid10 */
	__le16 sub_stripes;
	struct btrfs_stripe stripe;
	/* additional stripes go here */
} __attribute__ ((__packed__));

#define BTRFS_FREE_SPACE_EXTENT	1
#define BTRFS_FREE_SPACE_BITMAP	2

struct btrfs_free_space_entry {
	__le64 offset;
	__le64 bytes;
	u8 type;
} __attribute__ ((__packed__));

struct btrfs_free_space_header {
	struct btrfs_disk_key location;
	__le64 generation;
	__le64 num_entries;
	__le64 num_bitmaps;
} __attribute__ ((__packed__));

static inline unsigned long btrfs_chunk_item_size(int num_stripes)
{
	BUG_ON(num_stripes == 0);
	return sizeof(struct btrfs_chunk) +
		sizeof(struct btrfs_stripe) * (num_stripes - 1);
}

#define BTRFS_HEADER_FLAG_WRITTEN	(1ULL << 0)
#define BTRFS_HEADER_FLAG_RELOC		(1ULL << 1)

/*
 * File system states
 */
#define BTRFS_FS_STATE_ERROR		0
#define BTRFS_FS_STATE_REMOUNTING	1
#define BTRFS_FS_STATE_TRANS_ABORTED	2
#ifdef MY_ABC_HERE
#else
#define BTRFS_FS_STATE_DEV_REPLACING	3
#endif /* MY_ABC_HERE */

/* Super block flags */
/* Errors detected */
#define BTRFS_SUPER_FLAG_ERROR		(1ULL << 2)

#define BTRFS_SUPER_FLAG_SEEDING	(1ULL << 32)
#define BTRFS_SUPER_FLAG_METADUMP	(1ULL << 33)
#define BTRFS_SUPER_FLAG_CHANGING_FSID_V2 (1ULL << 36)

#define BTRFS_BACKREF_REV_MAX		256
#define BTRFS_BACKREF_REV_SHIFT		56
#define BTRFS_BACKREF_REV_MASK		(((u64)BTRFS_BACKREF_REV_MAX - 1) << \
					 BTRFS_BACKREF_REV_SHIFT)

#define BTRFS_OLD_BACKREF_REV		0
#define BTRFS_MIXED_BACKREF_REV		1

#ifdef MY_ABC_HERE
#define BTRFS_SYNO_USAGE_STATUS_VERSION        1

struct btrfs_syno_extent_usage_item {
	u8 type;
	__le64 reserved[1];
} __attribute__ ((__packed__));

struct btrfs_syno_extent_usage_inline_ref {
	u8 type;
	__le32 count;
	__le64 reserved[1];
} __attribute__ ((__packed__));

struct btrfs_syno_subvol_usage_item {
	__le32 refs;
	__le32 num_bytes;
	__le64 reserved[1];
} __attribute__ ((__packed__));

#define BTRFS_SYNO_USAGE_ROOT_FLAG_READONLY	(1ULL << 0)
#define BTRFS_SYNO_USAGE_ROOT_FLAG_FAST_RESCAN	(1ULL << 1)
#define BTRFS_SYNO_USAGE_ROOT_FLAG_FULL_RESCAN	(1ULL << 2)
#define BTRFS_SYNO_USAGE_ROOT_FLAG_RESCAN_PROGRESS_ACCOUNTING	(1ULL << 3)
#define BTRFS_SYNO_USAGE_ROOT_FLAG_RESCAN_MASK	(BTRFS_SYNO_USAGE_ROOT_FLAG_FAST_RESCAN |	\
												BTRFS_SYNO_USAGE_ROOT_FLAG_FULL_RESCAN |	\
												BTRFS_SYNO_USAGE_ROOT_FLAG_RESCAN_PROGRESS_ACCOUNTING)
#define BTRFS_SYNO_USAGE_ROOT_FLAG_FORCE_EXTENT	(1ULL << 4)
#define BTRFS_SYNO_USAGE_ROOT_FLAG_RESET_MASK	(BTRFS_SYNO_USAGE_ROOT_FLAG_READONLY |	\
												BTRFS_SYNO_USAGE_ROOT_FLAG_FAST_RESCAN |	\
												BTRFS_SYNO_USAGE_ROOT_FLAG_RESCAN_PROGRESS_ACCOUNTING |	\
												BTRFS_SYNO_USAGE_ROOT_FLAG_FORCE_EXTENT)
struct btrfs_syno_usage_root_status_item {
	u8 type;
	u8 new_type;
	__le64 state;
	__le64 flags;
	__le64 num_bytes;
	/* for subvol delete */
	struct btrfs_disk_key drop_progress;
	/* for rescan */
	struct btrfs_disk_key fast_rescan_progress;
	struct btrfs_disk_key full_rescan_progress;
	__le64 cur_full_rescan_size;
	__le64 total_full_rescan_size;
	/* for disable */
	__le64 total_syno_subvol_usage_items;
	__le64 reserved[4];
} __attribute__ ((__packed__));

struct btrfs_syno_usage_global_type_item {
	__le64 num_bytes;
	__le64 reserved[4];
} __attribute__ ((__packed__));

#define BTRFS_SYNO_USAGE_FLAG_INCONSISTENT	(1ULL << 0)

struct btrfs_syno_usage_status_item {
	__le64 version;
	__le64 state;
	__le64 flags;
	__le64 generation;
	/* for rescan */
	struct btrfs_disk_key extent_rescan_progress;
	__le64 cur_full_rescan_size;
	__le64 total_full_rescan_size;
	__le64 extent_tree_cur_rescan_size;
	__le64 extent_tree_total_rescan_size;
	/* for disable */
	__le64 total_syno_extent_tree_items;
	__le64 total_syno_subvol_usage_items;
	__le64 reserved[4];
} __attribute__ ((__packed__));
#endif /* MY_ABC_HERE */

/*
 * every tree block (leaf or node) starts with this header.
 */
struct btrfs_header {
	/* these first four must match the super block */
	u8 csum[BTRFS_CSUM_SIZE];
	u8 fsid[BTRFS_FSID_SIZE]; /* FS specific uuid */
	__le64 bytenr; /* which block this node is supposed to live in */
	__le64 flags;

	/* allowed to be different from the super from here on down */
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	__le64 generation;
	__le64 owner;
	__le32 nritems;
	u8 level;
} __attribute__ ((__packed__));

#define BTRFS_NODEPTRS_PER_BLOCK(r) (((r)->nodesize - \
				      sizeof(struct btrfs_header)) / \
				     sizeof(struct btrfs_key_ptr))
#define __BTRFS_LEAF_DATA_SIZE(bs) ((bs) - sizeof(struct btrfs_header))
#define BTRFS_LEAF_DATA_SIZE(r) (__BTRFS_LEAF_DATA_SIZE(r->leafsize))
#define BTRFS_MAX_INLINE_DATA_SIZE(r) (BTRFS_LEAF_DATA_SIZE(r) - \
					sizeof(struct btrfs_item) - \
					sizeof(struct btrfs_file_extent_item))
#define BTRFS_MAX_XATTR_SIZE(r)	(BTRFS_LEAF_DATA_SIZE(r) - \
				 sizeof(struct btrfs_item) -\
				 sizeof(struct btrfs_dir_item))


/*
 * this is a very generous portion of the super block, giving us
 * room to translate 14 chunks with 3 stripes each.
 */
#define BTRFS_SYSTEM_CHUNK_ARRAY_SIZE 2048
#define BTRFS_LABEL_SIZE 256

/*
 * just in case we somehow lose the roots and are not able to mount,
 * we store an array of the roots from previous transactions
 * in the super.
 */
#define BTRFS_NUM_BACKUP_ROOTS 4
struct btrfs_root_backup {
	__le64 tree_root;
	__le64 tree_root_gen;

	__le64 chunk_root;
	__le64 chunk_root_gen;

	__le64 extent_root;
	__le64 extent_root_gen;

	__le64 fs_root;
	__le64 fs_root_gen;

	__le64 dev_root;
	__le64 dev_root_gen;

	__le64 csum_root;
	__le64 csum_root_gen;

	__le64 total_bytes;
	__le64 bytes_used;
	__le64 num_devices;
	/* future */
	__le64 unused_64[4];

	u8 tree_root_level;
	u8 chunk_root_level;
	u8 extent_root_level;
	u8 fs_root_level;
	u8 dev_root_level;
	u8 csum_root_level;
	/* future and to align */
	u8 unused_8[10];
} __attribute__ ((__packed__));

/*
 * the super block basically lists the main trees of the FS
 * it currently lacks any block count etc etc
 */
struct btrfs_super_block {
	/* the first 4 fields must match struct btrfs_header */
	u8 csum[BTRFS_CSUM_SIZE];
	/* FS specific UUID, visible to user */
	u8 fsid[BTRFS_FSID_SIZE];
	__le64 bytenr; /* this block number */
	__le64 flags;

	/* allowed to be different from the btrfs_header from here own down */
	__le64 magic;
	__le64 generation;
	__le64 root;
	__le64 chunk_root;
	__le64 log_root;

	/* this will help find the new super based on the log root */
	__le64 log_root_transid;
	__le64 total_bytes;
	__le64 bytes_used;
	__le64 root_dir_objectid;
	__le64 num_devices;
	__le32 sectorsize;
	__le32 nodesize;
	__le32 leafsize;
	__le32 stripesize;
	__le32 sys_chunk_array_size;
	__le64 chunk_root_generation;
	__le64 compat_flags;
	__le64 compat_ro_flags;
	__le64 incompat_flags;
	__le16 csum_type;
	u8 root_level;
	u8 chunk_root_level;
	u8 log_root_level;
	struct btrfs_dev_item dev_item;

	char label[BTRFS_LABEL_SIZE];

	__le64 cache_generation;
	__le64 uuid_tree_generation;

	/* the UUID written into btree blocks */
	u8 metadata_uuid[BTRFS_FSID_SIZE];

	/* future expansion */
	__le64 reserved[28];
	u8 sys_chunk_array[BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];
	struct btrfs_root_backup super_roots[BTRFS_NUM_BACKUP_ROOTS];
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	u8 syno_reserved[525];
	__le64 syno_rbd_reserved[3]; /* Reserve for synorbd */
	__le64 log_tree_rsv;
	__le64 syno_generation;
#endif
} __attribute__ ((__packed__));

/*
 * Compat flags that we support.  If any incompat flags are set other than the
 * ones specified below then we will fail to mount
 */
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define BTRFS_FEATURE_COMPAT_BLOCK_GROUP_CACHE_TREE_AUTO	(1ULL << 61)
#define BTRFS_FEATURE_COMPAT_BLOCK_GROUP_CACHE_TREE	(1ULL << 62)
#define BTRFS_FEATURE_COMPAT_SYNO_CASELESS	(1ULL << 63)

#define BTRFS_FEATURE_COMPAT_SUPP		\
	(BTRFS_FEATURE_COMPAT_BLOCK_GROUP_CACHE_TREE	|	\
	 BTRFS_FEATURE_COMPAT_BLOCK_GROUP_CACHE_TREE_AUTO	|	\
	 BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
#else
#define BTRFS_FEATURE_COMPAT_SUPP		0ULL
#endif /* MY_ABC_HERE || MY_ABC_HERE */

#define BTRFS_FEATURE_COMPAT_SAFE_SET		0ULL
#define BTRFS_FEATURE_COMPAT_SAFE_CLEAR		0ULL

#define BTRFS_FEATURE_COMPAT_RO_SUPP			\
	(BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE |	\
	 BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID)

#define BTRFS_FEATURE_COMPAT_RO_SAFE_SET	0ULL
#define BTRFS_FEATURE_COMPAT_RO_SAFE_CLEAR	0ULL

#define BTRFS_FEATURE_INCOMPAT_SUPP			\
	(BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF |		\
	 BTRFS_FEATURE_INCOMPAT_DEFAULT_SUBVOL |	\
	 BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS |		\
	 BTRFS_FEATURE_INCOMPAT_BIG_METADATA |		\
	 BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO |		\
	 BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD |		\
	 BTRFS_FEATURE_INCOMPAT_RAID56 |		\
	 BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF |		\
	 BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA |	\
	 BTRFS_FEATURE_INCOMPAT_NO_HOLES	|	\
	 BTRFS_FEATURE_INCOMPAT_METADATA_UUID)

#define BTRFS_FEATURE_INCOMPAT_SAFE_SET			\
	(BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF)
#define BTRFS_FEATURE_INCOMPAT_SAFE_CLEAR		0ULL

/*
 * A leaf is full of items. offset and size tell us where to find
 * the item in the leaf (relative to the start of the data area)
 */
struct btrfs_item {
	struct btrfs_disk_key key;
	__le32 offset;
	__le32 size;
} __attribute__ ((__packed__));

/*
 * leaves have an item area and a data area:
 * [item0, item1....itemN] [free space] [dataN...data1, data0]
 *
 * The data is separate from the items to get the keys closer together
 * during searches.
 */
struct btrfs_leaf {
	struct btrfs_header header;
	struct btrfs_item items[];
} __attribute__ ((__packed__));

/*
 * all non-leaf blocks are nodes, they hold only keys and pointers to
 * other blocks
 */
struct btrfs_key_ptr {
	struct btrfs_disk_key key;
	__le64 blockptr;
	__le64 generation;
} __attribute__ ((__packed__));

struct btrfs_node {
	struct btrfs_header header;
	struct btrfs_key_ptr ptrs[];
} __attribute__ ((__packed__));

#ifdef MY_ABC_HERE
/* these are bit numbers for test/set bit */
#define SYNO_USAGE_ROOT_RUNTIME_FLAG_RESCAN 0
#define SYNO_USAGE_ROOT_RUNTIME_FLAG_FAST_RESCAN 1
#define SYNO_USAGE_ROOT_RUNTIME_FLAG_FULL_RESCAN 2

struct btrfs_syno_usage_status {
	/* on-disk */
	u64 version;
	u64 state;
	u64 flags;
	struct btrfs_key extent_rescan_progress;
	u64 cur_full_rescan_size;
	u64 total_full_rescan_size;
	u64 extent_tree_cur_rescan_size;
	u64 extent_tree_total_rescan_size;
	u64 total_syno_extent_tree_items;
	u64 total_syno_subvol_usage_items;

	/* in memory */
	u64 syno_usage_type_num_bytes[SYNO_USAGE_TYPE_MAX];
	bool syno_usage_type_num_bytes_valid[SYNO_USAGE_TYPE_MAX];
	s32 error_code;
} __attribute__ ((__packed__));

struct btrfs_syno_usage_root_status {
	u8 type;
	u8 new_type;
	u64 state;
	u64 flags;
	u64 num_bytes;
	struct btrfs_key drop_progress;
	struct btrfs_key fast_rescan_progress;
	struct btrfs_key full_rescan_progress;
	u64 cur_full_rescan_size;
	u64 total_full_rescan_size;
	u64 total_syno_subvol_usage_items;
} __attribute__ ((__packed__));
#endif /* MY_ABC_HERE */

/* Read ahead values for struct btrfs_path.reada */
enum {
	READA_NONE,
	READA_BACK,
	READA_FORWARD,
	/*
	 * Similar to READA_FORWARD but unlike it:
	 *
	 * 1) It will trigger readahead even for leaves that are not close to
	 *    each other on disk;
	 * 2) It also triggers readahead for nodes;
	 * 3) During a search, even when a node or leaf is already in memory, it
	 *    will still trigger readahead for other nodes and leaves that follow
	 *    it.
	 *
	 * This is meant to be used only when we know we are iterating over the
	 * entire tree or a very large part of it.
	 */
	READA_FORWARD_ALWAYS,
#ifdef MY_ABC_HERE
	READA_FORWARD_FORCE,
#endif /* MY_ABC_HERE */
};

/*
 * btrfs_paths remember the path taken from the root down to the leaf.
 * level 0 is always the leaf, and nodes[1...BTRFS_MAX_LEVEL] will point
 * to any other levels that are present.
 *
 * The slots array records the index of the item or block pointer
 * used while walking the tree.
 */
struct btrfs_path {
	struct extent_buffer *nodes[BTRFS_MAX_LEVEL];
	int slots[BTRFS_MAX_LEVEL];
	/* if there is real range locking, this locks field will change */
	int locks[BTRFS_MAX_LEVEL];
	int reada;
	/* keep some upper locks as we walk down */
	int lowest_level;

	/*
	 * set by btrfs_split_item, tells search_slot to keep all locks
	 * and to force calls to keep space in the nodes
	 */
	unsigned int search_for_split:1;
	unsigned int keep_locks:1;
	unsigned int skip_locking:1;
	unsigned int leave_spinning:1;
	unsigned int search_commit_root:1;
	unsigned int need_commit_sem:1;
	unsigned int skip_release_on_error:1;
#ifdef MY_ABC_HERE
	unsigned int caseless_key:1;
	unsigned int caseless_name:1;
#endif /* MY_ABC_HERE */
};

/*
 * items in the extent btree are used to record the objectid of the
 * owner of the block and the number of references
 */

struct btrfs_extent_item {
	__le64 refs;
	__le64 generation;
	__le64 flags;
} __attribute__ ((__packed__));

struct btrfs_extent_item_v0 {
	__le32 refs;
} __attribute__ ((__packed__));

#define BTRFS_MAX_EXTENT_ITEM_SIZE(r) ((BTRFS_LEAF_DATA_SIZE(r) >> 4) - \
					sizeof(struct btrfs_item))

#define BTRFS_EXTENT_FLAG_DATA		(1ULL << 0)
#define BTRFS_EXTENT_FLAG_TREE_BLOCK	(1ULL << 1)

/* following flags only apply to tree blocks */

/* use full backrefs for extent pointers in the block */
#define BTRFS_BLOCK_FLAG_FULL_BACKREF	(1ULL << 8)

/*
 * this flag is only used internally by scrub and may be changed at any time
 * it is only declared here to avoid collisions
 */
#define BTRFS_EXTENT_FLAG_SUPER		(1ULL << 48)

#ifdef MY_ABC_HERE
/*
 * This flag is used to indicate that the extent item has more than
 * one backrefs for a particular file. This could be done by calling
 * BTRFS_IOC_CLONE_RANGE or dedup. Since our quota reference needs to
 * drop only if we find out that this is the file's last reference
 * to this extent item. After enabling dedup and iocl, things become
 * much more complicated because the variable "last_ref" in
 * __btrfs_free_extent doesn't serve our purpose for indicating we
 * need to drop quota due to dropping of file's last reference to
 * this file.
 */
#define BTRFS_EXTENT_FLAG_HAS_CLONE_RANGE	(1ULL << 59)
#endif /* MY_ABC_HERE */

struct btrfs_tree_block_info {
	struct btrfs_disk_key key;
	u8 level;
} __attribute__ ((__packed__));

struct btrfs_extent_data_ref {
	__le64 root;
	__le64 objectid;
	__le64 offset;
	__le32 count;
} __attribute__ ((__packed__));

struct btrfs_shared_data_ref {
	__le32 count;
} __attribute__ ((__packed__));

struct btrfs_extent_inline_ref {
	u8 type;
	__le64 offset;
} __attribute__ ((__packed__));

/* old style backrefs item */
struct btrfs_extent_ref_v0 {
	__le64 root;
	__le64 generation;
	__le64 objectid;
	__le32 count;
} __attribute__ ((__packed__));


/* dev extents record free space on individual devices.  The owner
 * field points back to the chunk allocation mapping tree that allocated
 * the extent.  The chunk tree uuid field is a way to double check the owner
 */
struct btrfs_dev_extent {
	__le64 chunk_tree;
	__le64 chunk_objectid;
	__le64 chunk_offset;
	__le64 length;
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
} __attribute__ ((__packed__));

struct btrfs_inode_ref {
	__le64 index;
	__le16 name_len;
	/* name goes here */
} __attribute__ ((__packed__));

struct btrfs_inode_extref {
	__le64 parent_objectid;
	__le64 index;
	__le16 name_len;
	__u8   name[0];
	/* name goes here */
} __attribute__ ((__packed__));

struct btrfs_timespec {
	__le64 sec;
	__le32 nsec;
} __attribute__ ((__packed__));

struct btrfs_inode_item {
	/* nfs style generation number */
	__le64 generation;
	/* transid that last touched this inode */
	__le64 transid;
	__le64 size;
	__le64 nbytes;
	__le64 block_group;
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le64 rdev;
	__le64 flags;

	/* modification sequence number for NFS */
	__le64 sequence;

	/*
	 * a little future expansion, for more than this we can
	 * just grow the inode item and version it
	 */
#ifdef MY_ABC_HERE
	__le64 reserved[3];
	__le64 syno_uq_rfer_used;
#else
	__le64 reserved[4];
#endif /* MY_ABC_HERE */
	struct btrfs_timespec atime;
	struct btrfs_timespec ctime;
	struct btrfs_timespec mtime;
	struct btrfs_timespec otime;
} __attribute__ ((__packed__));

struct btrfs_dir_log_item {
	__le64 end;
} __attribute__ ((__packed__));

struct btrfs_dir_item {
	struct btrfs_disk_key location;
	__le64 transid;
	__le16 data_len;
	__le16 name_len;
	u8 type;
} __attribute__ ((__packed__));

#define BTRFS_ROOT_SUBVOL_RDONLY	(1ULL << 0)
#ifdef MY_ABC_HERE
#define BTRFS_ROOT_SUBVOL_HIDE		(1ULL << 32)
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_ROOT_SUBVOL_NOLOAD_USRQUOTA (1ULL << 33)
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_ROOT_SUBVOL_CMPR_RATIO    (1ULL << 34)
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#define BTRFS_ROOT_SUBVOL_DISABLE_QUOTA (1ULL << 35)
#endif /* MY_ABC_HERE */

/*
 * Internal in-memory flag that a subvolume has been marked for deletion but
 * still visible as a directory
 */
#define BTRFS_ROOT_SUBVOL_DEAD		(1ULL << 48)

struct btrfs_root_item {
	struct btrfs_inode_item inode;
	__le64 generation;
	__le64 root_dirid;
	__le64 bytenr;
	__le64 byte_limit;
	__le64 bytes_used;
	__le64 last_snapshot;
	__le64 flags;
	__le32 refs;
	struct btrfs_disk_key drop_progress;
	u8 drop_level;
	u8 level;

	/*
	 * The following fields appear after subvol_uuids+subvol_times
	 * were introduced.
	 */

	/*
	 * This generation number is used to test if the new fields are valid
	 * and up to date while reading the root item. Everytime the root item
	 * is written out, the "generation" field is copied into this field. If
	 * anyone ever mounted the fs with an older kernel, we will have
	 * mismatching generation values here and thus must invalidate the
	 * new fields. See btrfs_update_root and btrfs_find_last_root for
	 * details.
	 * the offset of generation_v2 is also used as the start for the memset
	 * when invalidating the fields.
	 */
	__le64 generation_v2;
	u8 uuid[BTRFS_UUID_SIZE];
	u8 parent_uuid[BTRFS_UUID_SIZE];
	u8 received_uuid[BTRFS_UUID_SIZE];
	__le64 ctransid; /* updated when an inode changes */
	__le64 otransid; /* trans when created */
	__le64 stransid; /* trans when sent. non-zero for received subvol */
	__le64 rtransid; /* trans when received. non-zero for received subvol */
	struct btrfs_timespec ctime;
	struct btrfs_timespec otime;
	struct btrfs_timespec stime;
	struct btrfs_timespec rtime;
	__le64 reserved[8]; /* for future */
} __attribute__ ((__packed__));

/*
 * this is used for both forward and backward root refs
 */
struct btrfs_root_ref {
	__le64 dirid;
	__le64 sequence;
	__le16 name_len;
} __attribute__ ((__packed__));

struct btrfs_disk_balance_args {
	/*
	 * profiles to operate on, single is denoted by
	 * BTRFS_AVAIL_ALLOC_BIT_SINGLE
	 */
	__le64 profiles;

	/* usage filter */
	__le64 usage;

	/* devid filter */
	__le64 devid;

	/* devid subset filter [pstart..pend) */
	__le64 pstart;
	__le64 pend;

	/* btrfs virtual address space subset filter [vstart..vend) */
	__le64 vstart;
	__le64 vend;

	/*
	 * profile to convert to, single is denoted by
	 * BTRFS_AVAIL_ALLOC_BIT_SINGLE
	 */
	__le64 target;

	/* BTRFS_BALANCE_ARGS_* */
	__le64 flags;

	/* BTRFS_BALANCE_ARGS_LIMIT value */
	__le64 limit;

	__le64 unused[7];
} __attribute__ ((__packed__));

/*
 * store balance parameters to disk so that balance can be properly
 * resumed after crash or unmount
 */
struct btrfs_balance_item {
	/* BTRFS_BALANCE_* */
	__le64 flags;

	struct btrfs_disk_balance_args data;
	struct btrfs_disk_balance_args meta;
	struct btrfs_disk_balance_args sys;

	__le64 unused[4];
} __attribute__ ((__packed__));

#define BTRFS_FILE_EXTENT_INLINE 0
#define BTRFS_FILE_EXTENT_REG 1
#define BTRFS_FILE_EXTENT_PREALLOC 2

struct btrfs_file_extent_item {
	/*
	 * transaction id that created this extent
	 */
	__le64 generation;
	/*
	 * max number of bytes to hold this extent in ram
	 * when we split a compressed extent we can't know how big
	 * each of the resulting pieces will be.  So, this is
	 * an upper limit on the size of the extent in ram instead of
	 * an exact limit.
	 */
	__le64 ram_bytes;

	/*
	 * 32 bits for the various ways we might encode the data,
	 * including compression and encryption.  If any of these
	 * are set to something a given disk format doesn't understand
	 * it is treated like an incompat flag for reading and writing,
	 * but not for stat.
	 */
	u8 compression;
	u8 encryption;
	__le16 other_encoding; /* spare for later use */

	/* are we inline data or a real extent? */
	u8 type;

	/*
	 * disk space consumed by the extent, checksum blocks are included
	 * in these numbers
	 */
	__le64 disk_bytenr;
	__le64 disk_num_bytes;
	/*
	 * the logical offset in file blocks (no csums)
	 * this extent record is for.  This allows a file extent to point
	 * into the middle of an existing extent on disk, sharing it
	 * between two snapshots (useful if some bytes in the middle of the
	 * extent have changed
	 */
	__le64 offset;
	/*
	 * the logical number of file blocks (no csums included).  This
	 * always reflects the size uncompressed and without encoding.
	 */
	__le64 num_bytes;

} __attribute__ ((__packed__));

struct btrfs_csum_item {
	u8 csum;
} __attribute__ ((__packed__));

struct btrfs_dev_stats_item {
	/*
	 * grow this item struct at the end for future enhancements and keep
	 * the existing values unchanged
	 */
	__le64 values[BTRFS_DEV_STAT_VALUES_MAX];
} __attribute__ ((__packed__));

#define BTRFS_DEV_REPLACE_ITEM_CONT_READING_FROM_SRCDEV_MODE_ALWAYS	0
#define BTRFS_DEV_REPLACE_ITEM_CONT_READING_FROM_SRCDEV_MODE_AVOID	1
#define BTRFS_DEV_REPLACE_ITEM_STATE_NEVER_STARTED	0
#define BTRFS_DEV_REPLACE_ITEM_STATE_STARTED		1
#define BTRFS_DEV_REPLACE_ITEM_STATE_SUSPENDED		2
#define BTRFS_DEV_REPLACE_ITEM_STATE_FINISHED		3
#define BTRFS_DEV_REPLACE_ITEM_STATE_CANCELED		4

struct btrfs_dev_replace {
	u64 replace_state;	/* see #define above */
	u64 time_started;	/* seconds since 1-Jan-1970 */
	u64 time_stopped;	/* seconds since 1-Jan-1970 */
	atomic64_t num_write_errors;
	atomic64_t num_uncorrectable_read_errors;

	u64 cursor_left;
	u64 committed_cursor_left;
	u64 cursor_left_last_write_of_item;
	u64 cursor_right;

	u64 cont_reading_from_srcdev_mode;	/* see #define above */

	int is_valid;
	int item_needs_writeback;
	struct btrfs_device *srcdev;
	struct btrfs_device *tgtdev;

	pid_t lock_owner;
	atomic_t nesting_level;
	struct mutex lock_finishing_cancel_unmount;
	struct mutex lock_management_lock;
	struct mutex lock;

	struct btrfs_scrub_progress scrub_progress;
};

struct btrfs_dev_replace_item {
	/*
	 * grow this item struct at the end for future enhancements and keep
	 * the existing values unchanged
	 */
	__le64 src_devid;
	__le64 cursor_left;
	__le64 cursor_right;
	__le64 cont_reading_from_srcdev_mode;

	__le64 replace_state;
	__le64 time_started;
	__le64 time_stopped;
	__le64 num_write_errors;
	__le64 num_uncorrectable_read_errors;
} __attribute__ ((__packed__));

/* different types of block groups (and chunks) */
#define BTRFS_BLOCK_GROUP_DATA		(1ULL << 0)
#define BTRFS_BLOCK_GROUP_SYSTEM	(1ULL << 1)
#define BTRFS_BLOCK_GROUP_METADATA	(1ULL << 2)
#define BTRFS_BLOCK_GROUP_RAID0		(1ULL << 3)
#define BTRFS_BLOCK_GROUP_RAID1		(1ULL << 4)
#define BTRFS_BLOCK_GROUP_DUP		(1ULL << 5)
#define BTRFS_BLOCK_GROUP_RAID10	(1ULL << 6)
#define BTRFS_BLOCK_GROUP_RAID5         (1ULL << 7)
#define BTRFS_BLOCK_GROUP_RAID6         (1ULL << 8)
#define BTRFS_BLOCK_GROUP_RESERVED	(BTRFS_AVAIL_ALLOC_BIT_SINGLE | \
					 BTRFS_SPACE_INFO_GLOBAL_RSV)

enum btrfs_raid_types {
	BTRFS_RAID_RAID10,
	BTRFS_RAID_RAID1,
	BTRFS_RAID_DUP,
	BTRFS_RAID_RAID0,
	BTRFS_RAID_SINGLE,
	BTRFS_RAID_RAID5,
	BTRFS_RAID_RAID6,
	BTRFS_NR_RAID_TYPES
};

#define BTRFS_BLOCK_GROUP_TYPE_MASK	(BTRFS_BLOCK_GROUP_DATA |    \
					 BTRFS_BLOCK_GROUP_SYSTEM |  \
					 BTRFS_BLOCK_GROUP_METADATA)

#define BTRFS_BLOCK_GROUP_PROFILE_MASK	(BTRFS_BLOCK_GROUP_RAID0 |   \
					 BTRFS_BLOCK_GROUP_RAID1 |   \
					 BTRFS_BLOCK_GROUP_RAID5 |   \
					 BTRFS_BLOCK_GROUP_RAID6 |   \
					 BTRFS_BLOCK_GROUP_DUP |     \
					 BTRFS_BLOCK_GROUP_RAID10)
/*
 * We need a bit for restriper to be able to tell when chunks of type
 * SINGLE are available.  This "extended" profile format is used in
 * fs_info->avail_*_alloc_bits (in-memory) and balance item fields
 * (on-disk).  The corresponding on-disk bit in chunk.type is reserved
 * to avoid remappings between two formats in future.
 */
#define BTRFS_AVAIL_ALLOC_BIT_SINGLE	(1ULL << 48)

/*
 * A fake block group type that is used to communicate global block reserve
 * size to userspace via the SPACE_INFO ioctl.
 */
#define BTRFS_SPACE_INFO_GLOBAL_RSV	(1ULL << 49)

#define BTRFS_EXTENDED_PROFILE_MASK	(BTRFS_BLOCK_GROUP_PROFILE_MASK | \
					 BTRFS_AVAIL_ALLOC_BIT_SINGLE)

static inline u64 chunk_to_extended(u64 flags)
{
	if ((flags & BTRFS_BLOCK_GROUP_PROFILE_MASK) == 0)
		flags |= BTRFS_AVAIL_ALLOC_BIT_SINGLE;

	return flags;
}
static inline u64 extended_to_chunk(u64 flags)
{
	return flags & ~BTRFS_AVAIL_ALLOC_BIT_SINGLE;
}

struct btrfs_block_group_item {
	__le64 used;
	__le64 chunk_objectid;
	__le64 flags;
} __attribute__ ((__packed__));

struct btrfs_free_space_info {
	__le32 extent_count;
	__le32 flags;
} __attribute__ ((__packed__));

#define BTRFS_FREE_SPACE_USING_BITMAPS (1ULL << 0)

#ifdef MY_ABC_HERE

#define BTRFS_USRQUOTA_STATUS_FLAG_ON            (1ULL << 0)
#define BTRFS_USRQUOTA_STATUS_FLAG_RESCAN        (1ULL << 1)
#define BTRFS_USRQUOTA_STATUS_FLAG_INCONSISTENT  (1ULL << 2)
#define BTRFS_USRQUOTA_STATUS_V1                 1
#define BTRFS_USRQUOTA_STATUS_VERSION            BTRFS_USRQUOTA_STATUS_V1


#define BTRFS_USRQUOTA_COMPAT_FLAG_INODE_QUOTA   (1ULL << 0)
#define BTRFS_USRQUOTA_COMPAT_FLAG	\
	(BTRFS_USRQUOTA_COMPAT_FLAG_INODE_QUOTA)

struct btrfs_usrquota_status_item {
	__le64 version;
	__le64 generation;
	__le64 flags;
	__le64 rescan_rootid;
	__le64 rescan_objectid;
	__le64 reserved[3];
} __attribute__ ((__packed__));

struct btrfs_usrquota_compat_item {
	__le64 generation;
	__le64 flags;
	__le64 reserved[4];
} __attribute__ ((__packed__));

struct btrfs_usrquota_root_item {
	__le64 info_item_cnt;
	__le64 limit_item_cnt;
} __attribute__ ((__packed__));

struct btrfs_usrquota_info_item {
	__le64 generation;
	__le64 rfer_used;
} __attribute__ ((__packed__));

struct btrfs_usrquota_limit_item {
	__le64 rfer_soft;
	__le64 rfer_hard;
} __attribute__ ((__packed__));

union btrfs_usrquota_item_union {
	struct btrfs_usrquota_info_item info_item;
	struct btrfs_usrquota_limit_item limit_item;
};

#define BTRFS_USRQUOTA_MAX_ITEMS_LEAF(r) (BTRFS_LEAF_DATA_SIZE(r) / \
							(sizeof(union btrfs_usrquota_item_union) + \
							 sizeof(struct btrfs_item)))

#define BTRFS_ANY_QUOTA_ENABLED(fs_info) (fs_info->quota_enabled || fs_info->usrquota_enabled)
#define BTRFS_USRQUOTA_DELAYED_REF_SCAN ((unsigned long)-2)
#endif /* MY_ABC_HERE */

/*
 * is subvolume quota turned on?
 */
#define BTRFS_QGROUP_STATUS_FLAG_ON		(1ULL << 0)
/*
 * RESCAN is set during the initialization phase
 */
#define BTRFS_QGROUP_STATUS_FLAG_RESCAN		(1ULL << 1)
/*
 * Some qgroup entries are known to be out of date,
 * either because the configuration has changed in a way that
 * makes a rescan necessary, or because the fs has been mounted
 * with a non-qgroup-aware version.
 * Turning qouta off and on again makes it inconsistent, too.
 */
#define BTRFS_QGROUP_STATUS_FLAG_INCONSISTENT	(1ULL << 2)

#define BTRFS_QGROUP_STATUS_VERSION        1

struct btrfs_qgroup_status_item {
	__le64 version;
	/*
	 * the generation is updated during every commit. As older
	 * versions of btrfs are not aware of qgroups, it will be
	 * possible to detect inconsistencies by checking the
	 * generation on mount time
	 */
	__le64 generation;

	/* flag definitions see above */
	__le64 flags;

	/*
	 * only used during scanning to record the progress
	 * of the scan. It contains a logical address
	 */
	__le64 rescan;
} __attribute__ ((__packed__));

struct btrfs_qgroup_info_item {
	__le64 generation;
	__le64 rfer;
	__le64 rfer_cmpr;
	__le64 excl;
	__le64 excl_cmpr;
} __attribute__ ((__packed__));

/* flags definition for qgroup limits */
#define BTRFS_QGROUP_LIMIT_MAX_RFER	(1ULL << 0)
#define BTRFS_QGROUP_LIMIT_MAX_EXCL	(1ULL << 1)
#define BTRFS_QGROUP_LIMIT_RSV_RFER	(1ULL << 2)
#define BTRFS_QGROUP_LIMIT_RSV_EXCL	(1ULL << 3)
#define BTRFS_QGROUP_LIMIT_RFER_CMPR	(1ULL << 4)
#define BTRFS_QGROUP_LIMIT_EXCL_CMPR	(1ULL << 5)

struct btrfs_qgroup_limit_item {
	/*
	 * only updated when any of the other values change
	 */
	__le64 flags;
	__le64 max_rfer;
	__le64 max_excl;
	__le64 rsv_rfer;
	__le64 rsv_excl;
} __attribute__ ((__packed__));

/* For raid type sysfs entries */
struct raid_kobject {
	int raid_type;
	struct kobject kobj;
};

struct btrfs_space_info {
	spinlock_t lock;

	u64 total_bytes;	/* total bytes in the space,
				   this doesn't take mirrors into account */
	u64 bytes_used;		/* total bytes used,
				   this doesn't take mirrors into account */
	u64 bytes_pinned;	/* total bytes pinned, will be freed when the
				   transaction finishes */
	u64 bytes_reserved;	/* total bytes the allocator has reserved for
				   current allocations */
	u64 bytes_may_use;	/* number of bytes that may be used for
				   delalloc/allocations */
	u64 bytes_readonly;	/* total bytes that are read only */

	u64 max_extent_size;	/* This will hold the maximum extent size of
				   the space info if we had an ENOSPC in the
				   allocator. */

	unsigned int full:1;	/* indicates that we cannot allocate any more
				   chunks for this space */
	unsigned int chunk_alloc:1;	/* set if we are allocating a chunk */

	unsigned int flush:1;		/* set if we are trying to make space */

	unsigned int force_alloc;	/* set if we need to force a chunk
					   alloc for this space */

	u64 disk_used;		/* total bytes used on disk */
	u64 disk_total;		/* total bytes on disk, takes mirrors into
				   account */

	u64 flags;

	/*
	 * bytes_pinned is kept in line with what is actually pinned, as in
	 * we've called update_block_group and dropped the bytes_used counter
	 * and increased the bytes_pinned counter.  However this means that
	 * bytes_pinned does not reflect the bytes that will be pinned once the
	 * delayed refs are flushed, so this counter is inc'ed everytime we call
	 * btrfs_free_extent so it is a realtime count of what will be freed
	 * once the transaction is committed.  It will be zero'ed everytime the
	 * transaction commits.
	 */
	struct percpu_counter total_bytes_pinned;

	struct list_head list;
	/* Protected by the spinlock 'lock'. */
	struct list_head ro_bgs;

	struct rw_semaphore groups_sem;
	/* for block groups in our same type */
	struct list_head block_groups[BTRFS_NR_RAID_TYPES];
	wait_queue_head_t wait;

	struct kobject kobj;
	struct kobject *block_group_kobjs[BTRFS_NR_RAID_TYPES];

#ifdef MY_ABC_HERE
	struct {
		spinlock_t lock;
		/* for trim/bg_ro */
		struct rw_semaphore allocation_sem;
		/* for block group */
		struct rb_root_cached free_space_bytes;
		struct rb_root_cached free_space_max_length;
		struct rb_root_cached free_space_max_length_with_extent;
		struct rb_root_cached preload; /* for auto scan after mount */
		struct mutex syno_allocator_mutex;
		bool force_cluster_disable;
		struct btrfs_block_group_cache *cache_bg;
		u64 cache_offset;
#ifdef MY_ABC_HERE
		u64 log_bg_offset;
#endif /* MY_ABC_HERE */
		atomic64_t fallback_relink_count;
		atomic64_t fallback_full_scan_count;
	} syno_allocator;
#endif /* MY_ABC_HERE */
};

#define	BTRFS_BLOCK_RSV_GLOBAL		1
#define	BTRFS_BLOCK_RSV_DELALLOC	2
#define	BTRFS_BLOCK_RSV_TRANS		3
#define	BTRFS_BLOCK_RSV_CHUNK		4
#define	BTRFS_BLOCK_RSV_DELOPS		5
#define	BTRFS_BLOCK_RSV_EMPTY		6
#define	BTRFS_BLOCK_RSV_TEMP		7

struct btrfs_block_rsv {
	u64 size;
	u64 reserved;
	struct btrfs_space_info *space_info;
	spinlock_t lock;
	unsigned short full;
	unsigned short type;
	unsigned short failfast;
};

/*
 * free clusters are used to claim free space in relatively large chunks,
 * allowing us to do less seeky writes.  They are used for all metadata
 * allocations and data allocations in ssd mode.
 */
struct btrfs_free_cluster {
	spinlock_t lock;
	spinlock_t refill_lock;
	struct rb_root root;

	/* largest extent in this cluster */
	u64 max_size;

	/* first extent starting offset */
	u64 window_start;

#ifdef MY_ABC_HERE
	u64 reserve_bytes;

	u64 empty_cluster; // only used for data cluster.

	u64 min_bytes;     // only used for data cluser. Only extents with size larger than this will be collected by cluster.

	u64 excluded_size; // only used for data cluster. don't use cluster allocation for size bigger than this.
#endif /* MY_ABC_HERE */

	/* We did a full search and couldn't create a cluster */
	bool fragmented;

	struct btrfs_block_group_cache *block_group;
	/*
	 * when a cluster is allocated from a block group, we put the
	 * cluster onto a list in the block group so that it can
	 * be freed before the block group is freed.
	 */
	struct list_head block_group_list;
};

enum btrfs_caching_type {
	BTRFS_CACHE_NO		= 0,
	BTRFS_CACHE_STARTED	= 1,
	BTRFS_CACHE_FAST	= 2,
	BTRFS_CACHE_FINISHED	= 3,
	BTRFS_CACHE_ERROR	= 4,
};

enum btrfs_disk_cache_state {
	BTRFS_DC_WRITTEN	= 0,
	BTRFS_DC_ERROR		= 1,
	BTRFS_DC_CLEAR		= 2,
	BTRFS_DC_SETUP		= 3,
};

struct btrfs_caching_control {
	struct list_head list;
	struct mutex mutex;
	wait_queue_head_t wait;
	struct btrfs_work work;
	struct btrfs_block_group_cache *block_group;
	u64 progress;
	atomic_t count;
};

/* Once caching_thread() finds this much free space, it will wake up waiters. */
#define CACHING_CTL_WAKE_UP (1024 * 1024 * 2)

struct btrfs_io_ctl {
	void *cur, *orig;
	struct page *page;
	struct page **pages;
	struct btrfs_root *root;
	struct inode *inode;
	unsigned long size;
	int index;
	int num_pages;
	int entries;
	int bitmaps;
	unsigned check_crcs:1;
};

struct btrfs_block_group_cache {
	struct btrfs_key key;
	struct btrfs_block_group_item item;
	struct btrfs_fs_info *fs_info;
	struct inode *inode;
	spinlock_t lock;
	u64 pinned;
	u64 reserved;
	u64 delalloc_bytes;
	u64 bytes_super;
	u64 flags;
	u64 cache_generation;
	u32 sectorsize;

	/*
	 * If the free space extent count exceeds this number, convert the block
	 * group to bitmaps.
	 */
	u32 bitmap_high_thresh;

	/*
	 * If the free space extent count drops below this number, convert the
	 * block group back to extents.
	 */
	u32 bitmap_low_thresh;

	/*
	 * It is just used for the delayed data space allocation because
	 * only the data space allocation and the relative metadata update
	 * can be done cross the transaction.
	 */
	struct rw_semaphore data_rwsem;

	/* for raid56, this is a full stripe, without parity */
	unsigned long full_stripe_len;

	unsigned int ro:1;
	unsigned int iref:1;
	unsigned int has_caching_ctl:1;
	unsigned int removed:1;

	int disk_cache_state;

	/* cache tracking stuff */
	int cached;
	struct btrfs_caching_control *caching_ctl;
	u64 last_byte_to_unpin;

	struct btrfs_space_info *space_info;

	/* free space cache stuff */
	struct btrfs_free_space_ctl *free_space_ctl;

	/* block group cache stuff */
	struct rb_node cache_node;

	/* for block groups in the same raid type */
	struct list_head list;

	/* usage count */
	atomic_t count;

	/* List of struct btrfs_free_clusters for this block group.
	 * Today it will only have one thing on it, but that may change
	 */
	struct list_head cluster_list;

	/* For delayed block group creation or deletion of empty block groups */
	struct list_head bg_list;

	/* For read-only block groups */
	struct list_head ro_list;

	atomic_t trimming;

	/* For dirty block groups */
	struct list_head dirty_list;
	struct list_head io_list;

	struct btrfs_io_ctl io_ctl;

	/* Lock for free space tree operations. */
	struct mutex free_space_lock;

	/*
	 * Does the block group need to be added to the free space tree?
	 * Protected by free_space_lock.
	 */
	int needs_free_space;

#ifdef MY_ABC_HERE
	struct {
		struct btrfs_space_info *space_info;
		/* protect with space_info->syno_allocator.lock */
		struct rb_node bytes_index;
		struct rb_node max_length_index;
		struct rb_node max_length_with_extent_index;
		u64 last_bytes, last_max_length, last_max_length_with_extent;
		struct rb_node preload_index;
		u64 preload_free_space;
		bool ro;
		bool cache_error;
		bool removed;
		bool initialized;
		atomic_t refs;
	} syno_allocator;
#endif /* MY_ABC_HERE */
};

/* delayed seq elem */
struct seq_list {
	struct list_head list;
	u64 seq;
};

enum btrfs_orphan_cleanup_state {
	ORPHAN_CLEANUP_STARTED	= 1,
	ORPHAN_CLEANUP_DONE	= 2,
};

#ifdef MY_ABC_HERE
enum btrfs_fix_meta_key_state {
	CAN_FIX_META_KEY = 0, // can trigger another thread to fix metadata key
	DOING_FIX_META_KEY = 1, // others are fixing metadata key and we cannot trigger another thread
};
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
enum btrfs_check_cross_ref_type {
	CHECK_CROSS_REF_NORMAL = 0,
	CHECK_CROSS_REF_SKIP_FAST_SNAPSHOT = 1,
};
#endif /* MY_ABC_HERE */

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
enum {
	SYNO_PERF_INDICATROT_FLAG_DIRTY_LIMIT_UPDATE,
};
#endif /* defined(MY_ABC_HERE) || defined(MY_ABC_HERE) */

/* used by the raid56 code to lock stripes for read/modify/write */
struct btrfs_stripe_hash {
	struct list_head hash_list;
	wait_queue_head_t wait;
	spinlock_t lock;
};

/* used by the raid56 code to lock stripes for read/modify/write */
struct btrfs_stripe_hash_table {
	struct list_head stripe_cache;
	spinlock_t cache_lock;
	int cache_size;
	struct btrfs_stripe_hash table[];
};

#define BTRFS_STRIPE_HASH_TABLE_BITS 11

void btrfs_init_async_reclaim_work(struct work_struct *work);
#ifdef MY_ABC_HERE
void btrfs_init_async_data_flush_work(struct work_struct *work);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
void btrfs_init_async_metadata_flush_work(struct work_struct *work);
void btrfs_syno_btree_balance_dirty(struct btrfs_fs_info *fs_info, bool throttle);
#endif /* MY_ABC_HERE */

/* fs_info */
struct reloc_control;
struct btrfs_device;
struct btrfs_fs_devices;
struct btrfs_balance_control;
struct btrfs_delayed_root;

#ifdef MY_ABC_HERE
struct cksumfailed_file_rec {
	u64 sub_vol;
	u64 ino;
};
#endif

/*
 * Block group or device which contains an active swapfile. Used for preventing
 * unsafe operations while a swapfile is active.
 *
 * These are sorted on (ptr, inode) (note that a block group or device can
 * contain more than one swapfile). We compare the pointer values because we
 * don't actually care what the object is, we just need a quick check whether
 * the object exists in the rbtree.
 */
struct btrfs_swapfile_pin {
	struct rb_node node;
	void *ptr;
	struct inode *inode;
	/*
	 * If true, ptr points to a struct btrfs_block_group_cache. Otherwise,
	 * ptr points to a struct btrfs_device.
	 */
	bool is_block_group;
};

bool btrfs_pinned_by_swapfile(struct btrfs_fs_info *fs_info, void *ptr);

#ifdef MY_ABC_HERE
struct btrfs_delayed_ref_throttle_ticket {
	u64 count;
	struct list_head list;
};
#endif /* MY_ABC_HERE */

struct btrfs_fs_info {
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	struct btrfs_root *extent_root;
	struct btrfs_root *tree_root;
	struct btrfs_root *chunk_root;
	struct btrfs_root *dev_root;
	struct btrfs_root *fs_root;
	struct btrfs_root *csum_root;
	struct btrfs_root *quota_root;
	struct btrfs_root *uuid_root;
	struct btrfs_root *free_space_root;
#ifdef MY_ABC_HERE
	struct btrfs_root *usrquota_root;
#endif
#ifdef MY_ABC_HERE
	struct btrfs_root *block_group_hint_root;
	struct btrfs_root *block_group_cache_root;
#endif

	/* the log root tree is a directory of all the other log roots */
	struct btrfs_root *log_root_tree;

	spinlock_t fs_roots_radix_lock;
	struct radix_tree_root fs_roots_radix;

	/* block group cache stuff */
	spinlock_t block_group_cache_lock;
	u64 first_logical_byte;
	struct rb_root block_group_cache_tree;

	/* keep track of unallocated space */
	spinlock_t free_chunk_lock;
	u64 free_chunk_space;

	struct extent_io_tree freed_extents[2];
	struct extent_io_tree *pinned_extents;

	/* logical->physical extent mapping */
	struct btrfs_mapping_tree mapping_tree;

#ifdef MY_ABC_HERE
	atomic_t nr_extent_maps;
	struct list_head extent_map_inode_list;
	spinlock_t extent_map_inode_list_lock;
#endif

	/*
	 * block reservation for extent, checksum, root tree and
	 * delayed dir index item
	 */
	struct btrfs_block_rsv global_block_rsv;
	/* block reservation for delay allocation */
	struct btrfs_block_rsv delalloc_block_rsv;
	/* block reservation for metadata operations */
	struct btrfs_block_rsv trans_block_rsv;
	/* block reservation for chunk tree */
	struct btrfs_block_rsv chunk_block_rsv;
	/* block reservation for delayed operations */
	struct btrfs_block_rsv delayed_block_rsv;

	struct btrfs_block_rsv empty_block_rsv;
#ifdef MY_ABC_HERE
	struct btrfs_block_rsv cleaner_block_rsv;
#endif /* MY_ABC_HERE */

	u64 generation;
	u64 last_trans_committed;
	u64 avg_delayed_ref_runtime;

	/*
	 * this is updated to the current trans every time a full commit
	 * is required instead of the faster short fsync log commits
	 */
	u64 last_trans_log_full_commit;
#ifdef MY_ABC_HERE
	unsigned long long mount_opt;
#else
	unsigned long mount_opt;
#endif /* MY_ABC_HERE */
	unsigned long compress_type:4;
	int commit_interval;
	/*
	 * It is a suggestive number, the read side is safe even it gets a
	 * wrong number because we will write out the data into a regular
	 * extent. The write side(mount/remount) is under ->s_umount lock,
	 * so it is also safe.
	 */
	u64 max_inline;
	/*
	 * Protected by ->chunk_mutex and sb->s_umount.
	 *
	 * The reason that we use two lock to protect it is because only
	 * remount and mount operations can change it and these two operations
	 * are under sb->s_umount, but the read side (chunk allocation) can not
	 * acquire sb->s_umount or the deadlock would happen. So we use two
	 * locks to protect it. On the write side, we must acquire two locks,
	 * and on the read side, we just need acquire one of them.
	 */
	u64 alloc_start;
	struct btrfs_transaction *running_transaction;
	wait_queue_head_t transaction_throttle;
	wait_queue_head_t transaction_wait;
	wait_queue_head_t transaction_blocked_wait;
	wait_queue_head_t async_submit_wait;

	/*
	 * Used to protect the incompat_flags, compat_flags, compat_ro_flags
	 * when they are updated.
	 *
	 * Because we do not clear the flags for ever, so we needn't use
	 * the lock on the read side.
	 *
	 * We also needn't use the lock when we mount the fs, because
	 * there is no other task which will update the flag.
	 */
	spinlock_t super_lock;
	struct btrfs_super_block *super_copy;
	struct btrfs_super_block *super_for_commit;
	struct block_device *__bdev;
	struct super_block *sb;
	struct inode *btree_inode;
	struct backing_dev_info bdi;
	struct mutex tree_log_mutex;
	struct mutex transaction_kthread_mutex;
	struct mutex cleaner_mutex;
	struct mutex chunk_mutex;
	struct mutex volume_mutex;

	/*
	 * this is taken to make sure we don't set block groups ro after
	 * the free space cache has been allocated on them
	 */
	struct mutex ro_block_group_mutex;

	/* this is used during read/modify/write to make sure
	 * no two ios are trying to mod the same stripe at the same
	 * time
	 */
	struct btrfs_stripe_hash_table *stripe_hash_table;

	/*
	 * this protects the ordered operations list only while we are
	 * processing all of the entries on it.  This way we make
	 * sure the commit code doesn't find the list temporarily empty
	 * because another function happens to be doing non-waiting preflush
	 * before jumping into the main commit.
	 */
	struct mutex ordered_operations_mutex;

	/*
	 * Same as ordered_operations_mutex except this is for ordered extents
	 * and not the operations.
	 */
	struct mutex ordered_extent_flush_mutex;

	struct rw_semaphore commit_root_sem;

	struct rw_semaphore cleanup_work_sem;

	struct rw_semaphore subvol_sem;
	struct srcu_struct subvol_srcu;

	spinlock_t trans_lock;
	/*
	 * the reloc mutex goes with the trans lock, it is taken
	 * during commit to protect us from the relocation code
	 */
	struct mutex reloc_mutex;

	struct list_head trans_list;
	struct list_head dead_roots;
	struct list_head caching_block_groups;
#ifdef MY_ABC_HERE
	spinlock_t caching_block_groups_lock;
#endif /* MY_ABC_HERE */

	spinlock_t delayed_iput_lock;
	struct list_head delayed_iputs;
	struct rw_semaphore delayed_iput_sem;

	atomic64_t tree_mod_seq;

	/* this protects tree_mod_log and tree_mod_seq_list */
	rwlock_t tree_mod_log_lock;
	struct rb_root tree_mod_log;
	struct list_head tree_mod_seq_list;

	atomic_t nr_async_submits;
	atomic_t async_submit_draining;
	atomic_t nr_async_bios;
	atomic_t async_delalloc_pages;
	atomic_t open_ioctl_trans;

	/*
	 * this is used to protect the following list -- ordered_roots.
	 */
	spinlock_t ordered_root_lock;

	/*
	 * all fs/file tree roots in which there are data=ordered extents
	 * pending writeback are added into this list.
	 *
	 * these can span multiple transactions and basically include
	 * every dirty data page that isn't from nodatacow
	 */
	struct list_head ordered_roots;

	struct mutex delalloc_root_mutex;
	spinlock_t delalloc_root_lock;
	/* all fs/file tree roots that have delalloc inodes. */
	struct list_head delalloc_roots;

	/*
	 * there is a pool of worker threads for checksumming during writes
	 * and a pool for checksumming after reads.  This is because readers
	 * can run with FS locks held, and the writers may be waiting for
	 * those locks.  We don't want ordering in the pending list to cause
	 * deadlocks, and so the two are serviced separately.
	 *
	 * A third pool does submit_bio to avoid deadlocking with the other
	 * two
	 */
	struct btrfs_workqueue *workers;
	struct btrfs_workqueue *delalloc_workers;
	struct btrfs_workqueue *flush_workers;
	struct btrfs_workqueue *endio_workers;
	struct btrfs_workqueue *endio_meta_workers;
#ifdef MY_ABC_HERE
	struct btrfs_workqueue *endio_meta_fix_workers;
#endif /* MY_ABC_HERE */
	struct btrfs_workqueue *endio_raid56_workers;
	struct btrfs_workqueue *rmw_workers;
	struct btrfs_workqueue *endio_meta_write_workers;
	struct btrfs_workqueue *endio_write_workers;
#ifdef MY_ABC_HERE
	struct btrfs_workqueue *endio_write_sync_workers;
#endif /* MY_ABC_HERE */
	struct btrfs_workqueue *endio_freespace_worker;
	struct btrfs_workqueue *submit_workers;
	struct btrfs_workqueue *caching_workers;
	struct btrfs_workqueue *readahead_workers;
#ifdef MY_ABC_HERE
	struct btrfs_workqueue *reada_path_workers;
#endif
#ifdef MY_ABC_HERE
	struct btrfs_workqueue *syno_cow_endio_workers;
	struct btrfs_workqueue *syno_nocow_endio_workers;
	struct btrfs_workqueue *syno_high_priority_endio_workers;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	struct btrfs_workqueue *syno_multiple_writeback_workers;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	struct btrfs_workqueue *syno_cow_async_workers;
#endif /* MY_ABC_HERE */

	/*
	 * fixup workers take dirty pages that didn't properly go through
	 * the cow mechanism and make them safe to write.  It happens
	 * for the sys_munmap function call path
	 */
	struct btrfs_workqueue *fixup_workers;
	struct btrfs_workqueue *delayed_workers;

	/* the extent workers do delayed refs on the extent allocation tree */
	struct btrfs_workqueue *extent_workers;
	struct task_struct *transaction_kthread;
	struct task_struct *cleaner_kthread;
	int thread_pool_size;

	struct kobject super_kobj;
	struct kobject *space_info_kobj;
	struct kobject *device_dir_kobj;
#ifdef MY_ABC_HERE
	struct kobject *free_space_tree_kobj;
#endif /* MY_ABC_HERE */
	struct completion kobj_unregister;
	int do_barriers;
	int closing;
	int log_root_recovering;
#ifdef MY_ABC_HERE
	int avoid_fs_root_null_pointer_dereference;
#endif /* MY_ABC_HERE */
	int open;

	u64 total_pinned;

	/* used to keep from writing metadata until there is a nice batch */
	struct percpu_counter dirty_metadata_bytes;
	struct percpu_counter delalloc_bytes;
	s32 dirty_metadata_batch;
	s32 delalloc_batch;

	struct list_head dirty_cowonly_roots;

	struct btrfs_fs_devices *fs_devices;

	/*
	 * the space_info list is almost entirely read only.  It only changes
	 * when we add a new raid type to the FS, and that happens
	 * very rarely.  RCU is used to protect it.
	 */
	struct list_head space_info;

	struct btrfs_space_info *data_sinfo;

	struct reloc_control *reloc_ctl;

	/* data_alloc_cluster is only used in ssd mode */
	struct btrfs_free_cluster data_alloc_cluster;

	/* all metadata allocations go through this cluster */
	struct btrfs_free_cluster meta_alloc_cluster;

	/* auto defrag inodes go here */
	spinlock_t defrag_inodes_lock;
	struct rb_root defrag_inodes;
#ifdef MY_ABC_HERE
	/* list 0 for reclaim space, list 1 for original defrag */
	struct list_head defrag_inodes_list[2];
	int reclaim_space_entry_count;
#endif /* MY_ABC_HERE */
	atomic_t defrag_running;

	/* Used to protect avail_{data, metadata, system}_alloc_bits */
	seqlock_t profiles_lock;
	/*
	 * these three are in extended format (availability of single
	 * chunks is denoted by BTRFS_AVAIL_ALLOC_BIT_SINGLE bit, other
	 * types are denoted by corresponding BTRFS_BLOCK_GROUP_* bits)
	 */
	u64 avail_data_alloc_bits;
	u64 avail_metadata_alloc_bits;
	u64 avail_system_alloc_bits;

	/* restriper state */
	spinlock_t balance_lock;
	struct mutex balance_mutex;
	atomic_t balance_running;
	atomic_t balance_pause_req;
	atomic_t balance_cancel_req;
	struct btrfs_balance_control *balance_ctl;
	wait_queue_head_t balance_wait_q;

#ifdef MY_ABC_HERE
#else
	unsigned data_chunk_allocations;
#endif
	unsigned metadata_ratio;

	void *bdev_holder;

	/* private scrub information */
	struct mutex scrub_lock;
	atomic_t scrubs_running;
	atomic_t scrub_pause_req;
	atomic_t scrubs_paused;
	atomic_t scrub_cancel_req;
	wait_queue_head_t scrub_pause_wait;
	int scrub_workers_refcnt;
	struct btrfs_workqueue *scrub_workers;
	struct btrfs_workqueue *scrub_wr_completion_workers;
	struct btrfs_workqueue *scrub_nocow_workers;

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	u32 check_integrity_print_mask;
#endif
#ifdef MY_ABC_HERE
	unsigned int usrquota_enabled:1;
	/* usrquota_enable only changes state after a commit */
	unsigned int pending_usrquota_state:1;

	u64 usrquota_flags;
	u64 usrquota_compat_flags;
	struct rb_root usrquota_tree;
	/* protects in-moemory usrquota tree */
	spinlock_t usrquota_lock;
	/* protects on-disk usrquota tree */
	struct mutex usrquota_tree_lock;
	/*
	 * Protect user change for usrquota operations. If a transaction is needed,
	 * it must be started before locking this lock.
	 */
	struct mutex usrquota_ioctl_lock;

	/* rescan items */
	/* protects progress items */
	struct mutex usrquota_rescan_lock;
	u64 usrquota_rescan_rootid;
	u64 usrquota_rescan_objectid;
	struct btrfs_key usrquota_rescan_progress;
	struct btrfs_root *usrquota_rescan_root;
	struct btrfs_workqueue *usrquota_rescan_workers;
	struct completion usrquota_rescan_completion;
	struct btrfs_work usrquota_rescan_work;

	struct list_head usrquota_dirty;

	/* protect usrquota_ro_roots */
	struct mutex usrquota_ro_roots_lock;
	struct list_head usrquota_ro_roots;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	atomic_t syno_async_submit_nr;
	u32 syno_async_submit_throttle;
	wait_queue_head_t syno_async_submit_queue_wait;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	atomic64_t syno_ordered_extent_nr;
	u64 syno_max_ordered_queue_size;
	wait_queue_head_t syno_ordered_queue_wait;
	atomic64_t syno_ordered_extent_processed_nr;
	u64 syno_ordered_extent_processed_bw;
	u64 syno_ordered_extent_processed_stamp;
	unsigned long syno_ordered_extent_processed_bw_time_stamp;    /* last time updated */
#endif /* MY_ABC_HERE */

	/*
	 * quota information
	 */
	unsigned int quota_enabled:1;

	/*
	 * quota_enabled only changes state after a commit. This holds the
	 * next state.
	 */
	unsigned int pending_quota_state:1;

	/* is qgroup tracking in a consistent state? */
	u64 qgroup_flags;

	/* holds configuration and tracking. Protected by qgroup_lock */
	struct rb_root qgroup_tree;
	struct rb_root qgroup_op_tree;
	spinlock_t qgroup_lock;
	spinlock_t qgroup_op_lock;
	atomic_t qgroup_op_seq;

	/*
	 * used to avoid frequently calling ulist_alloc()/ulist_free()
	 * when doing qgroup accounting, it must be protected by qgroup_lock.
	 */
	struct ulist *qgroup_ulist;

	/*
	 * Protect user change for quota operations. If a transaction is needed,
	 * it must be started before locking this lock.
	 */
	struct mutex qgroup_ioctl_lock;

	/* list of dirty qgroups to be written at next commit */
	struct list_head dirty_qgroups;

	/* used by btrfs_qgroup_record_ref for an efficient tree traversal */
	u64 qgroup_seq;

	/* qgroup rescan items */
	struct mutex qgroup_rescan_lock; /* protects the progress item */
	struct btrfs_key qgroup_rescan_progress;
	struct btrfs_workqueue *qgroup_rescan_workers;
	struct completion qgroup_rescan_completion;
	struct btrfs_work qgroup_rescan_work;

	/* filesystem state */
	unsigned long fs_state;

	struct btrfs_delayed_root *delayed_root;

	/* readahead tree */
	spinlock_t reada_lock;
	struct radix_tree_root reada_tree;

	/* readahead works cnt */
	atomic_t reada_works_cnt;

	/* Extent buffer radix tree */
	spinlock_t buffer_lock;
	struct radix_tree_root buffer_radix;

	/* next backup root to be overwritten */
	int backup_root_index;

	int num_tolerated_disk_barrier_failures;

	/* device replace state */
	struct btrfs_dev_replace dev_replace;

	atomic_t mutually_exclusive_operation_running;

#ifdef MY_ABC_HERE
#else
	struct percpu_counter bio_counter;
	wait_queue_head_t replace_wait;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	char mount_path[SYNO_MOUNT_PATH_LEN];
	struct kfifo cksumfailed_files;
	spinlock_t cksumfailed_files_write_lock;
	// 0 prints all logs, 1 use rate_limit (default), 2 suppress all logs.
	u8 correction_suppress_log;
	u8 correction_disable;

	struct rb_root correction_record;
	spinlock_t correction_record_lock;
#endif

#ifdef MY_ABC_HERE
	unsigned long can_fix_meta_key;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	unsigned int snapshot_cleaner; // 1 -> cleaner will drop snapshot, 0 -> cleaner skip drop snapshot
#endif /* MY_ABC_HERE */

	struct semaphore uuid_tree_rescan_sem;
	unsigned int update_uuid_tree_gen:1;

	/* Used to reclaim the metadata space in the background. */
	struct work_struct async_reclaim_work;

	spinlock_t unused_bgs_lock;
	struct list_head unused_bgs;
	struct mutex unused_bg_unpin_mutex;
	struct mutex delete_unused_bgs_mutex;

	/*
	 * Chunks that can't be freed yet (under a trim/discard operation)
	 * and will be latter freed. Protected by fs_info->chunk_mutex.
	 */
	struct list_head pinned_chunks;

	int creating_free_space_tree;

#ifdef MY_ABC_HERE
	unsigned int abort_free_space_tree:1;
	unsigned free_space_tree_processed_block_group_cnt;
#endif /* MY_ABC_HERE */

	/* Block groups and devices containing active swapfiles. */
	spinlock_t swapfile_pins_lock;
	struct rb_root swapfile_pins;
#ifdef MY_ABC_HERE
	unsigned int btrfs_umount_hang;
#endif

#ifdef MY_ABC_HERE
	atomic_t reada_block_group_threads; // Number of running threads; use atomic type since threads can modify it.
	struct mutex block_group_hint_tree_mutex; // Portect block group hint tree creation.
	unsigned int no_block_group_hint:1;
	int creating_block_group_cache_tree;
	int block_group_cache_tree_broken;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	unsigned block_group_cnt;
#endif /* MY_ABC_HERE */

	/* Used to record internally whether fs has been frozen */
	int fs_frozen;
#ifdef MY_ABC_HERE
	atomic_t syno_writeback_thread_count;
	int syno_writeback_thread_max;
	spinlock_t syno_multiple_writeback_lock;
	struct list_head syno_dirty_lru_inodes;
	/*
	 * It's simple to avoid dev_replace mutex for writeback thread,
	 * because we not support replace disk.
	 */
	int dev_replace_may_start;
#ifdef MY_ABC_HERE
	struct work_struct async_data_flush_work;
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	struct work_struct async_metadata_flush_work;
#endif /* MY_ABC_HERE */
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	struct {
		unsigned long flags;
		unsigned long dirty_thresh;
		unsigned long dirty_background_thresh;
		unsigned long dirty_limit_stamp;
	} syno_perf_indicator;
#endif /* defined(MY_ABC_HERE) || defined(MY_ABC_HERE) */

#ifdef MY_ABC_HERE
	struct dentry *btrfs_pervolume_debugfs_root_dentry;

	struct percpu_counter eb_hit;
	struct percpu_counter eb_miss;
	struct percpu_counter meta_write_pages;
	struct percpu_counter data_write_pages;
	struct percpu_counter delayed_meta_ref;
	struct percpu_counter delayed_data_ref;
	struct percpu_counter write_flush;
	struct percpu_counter write_fua;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	u64 log_tree_rsv_start;
	u64 log_tree_rsv_size;
	struct mutex log_tree_rsv_alloc;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	spinlock_t syno_delayed_ref_throttle_lock;
	struct list_head syno_delayed_ref_throttle_tickets;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	struct work_struct async_metadata_cache_work;
	atomic_t syno_metadata_block_group_update_count;
	int metadata_cache_enable;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	struct btrfs_root *syno_usage_root;
	struct btrfs_root *syno_extent_usage_root;
	unsigned int syno_usage_enabled:1;
	struct work_struct syno_usage_rescan_work;
	struct work_struct syno_usage_fast_rescan_work;
	struct work_struct syno_usage_full_rescan_work;
	struct list_head syno_usage_pending_fast_rescan_roots;
	struct list_head syno_usage_pending_full_rescan_roots;
	pid_t syno_usage_fast_rescan_pid;
	pid_t syno_usage_full_rescan_pid;
	atomic_t syno_usage_pending_fast_rescan_count;
	atomic_t syno_usage_pending_full_rescan_count;
	spinlock_t syno_usage_fast_rescan_lock;
	spinlock_t syno_usage_full_rescan_lock;
	struct mutex syno_usage_ioctl_lock;
	struct btrfs_syno_usage_status syno_usage_status;
	spinlock_t syno_usage_lock;
	int syno_usage_rescan_preload;
	int syno_usage_rescan_check_all;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	atomic64_t fsync_cnt;
	atomic64_t fsync_full_commit_cnt;
	unsigned int commit_time_debug:1;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	struct mutex free_space_analyze_ioctl_lock;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	struct {
		bool root_tree_cleanup;
		bool fs_tree_cleanup;
		spinlock_t lock;
		struct list_head roots;
		bool enable; /* default:on */
		bool orphan_inode_delayed; /* default:off */
	} syno_orphan_cleanup;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	atomic_t syno_async_delayed_ref_count;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	atomic_t syno_metadata_reserve_pending;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	struct {
		atomic_t syno_allocator_refs;
		wait_queue_head_t syno_allocator_wait;
		atomic_t legacy_allocator_refs;
		wait_queue_head_t legacy_allocator_wait;
		struct btrfs_workqueue *caching_workers;
		struct work_struct bg_prefetch_work;
		bool bg_prefetch_running;
	} syno_allocator;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	struct {
		atomic64_t eb_disk_read;
		atomic64_t search_key;
		atomic64_t search_forward;
		atomic64_t next_leaf;
	} syno_meta_statistics;
#endif /* MY_ABC_HERE */
};

struct btrfs_subvolume_writers {
	struct percpu_counter	counter;
	wait_queue_head_t	wait;
};

/*
 * The state of btrfs root
 */
/*
 * btrfs_record_root_in_trans is a multi-step process,
 * and it can race with the balancing code.   But the
 * race is very small, and only the first time the root
 * is added to each transaction.  So IN_TRANS_SETUP
 * is used to tell us when more checks are required
 */
#define BTRFS_ROOT_IN_TRANS_SETUP	0
#define BTRFS_ROOT_REF_COWS		1
#define BTRFS_ROOT_TRACK_DIRTY		2
#define BTRFS_ROOT_IN_RADIX		3
#define BTRFS_ROOT_DUMMY_ROOT		4
#define BTRFS_ROOT_ORPHAN_ITEM_INSERTED	5
#define BTRFS_ROOT_DEFRAG_RUNNING	6
#define BTRFS_ROOT_FORCE_COW		7
#define BTRFS_ROOT_MULTI_LOG_TASKS	8
#define BTRFS_ROOT_DIRTY		9
#define BTRFS_ROOT_DELETING		10
#define BTRFS_ROOT_DEAD_TREE	11

/*
 * in ram representation of the tree.  extent_root is used for all allocations
 * and for the extent tree extent_root root.
 */
struct btrfs_root {
	struct extent_buffer *node;

	struct extent_buffer *commit_root;
	struct btrfs_root *log_root;
	struct btrfs_root *reloc_root;

	unsigned long state;
	struct btrfs_root_item root_item;
	struct btrfs_key root_key;
	struct btrfs_fs_info *fs_info;
	struct extent_io_tree dirty_log_pages;

	struct kobject root_kobj;
	struct completion kobj_unregister;
	struct mutex objectid_mutex;

	spinlock_t accounting_lock;
	struct btrfs_block_rsv *block_rsv;

	/* free ino cache stuff */
	struct btrfs_free_space_ctl *free_ino_ctl;
	enum btrfs_caching_type cached;
	spinlock_t cache_lock;
	wait_queue_head_t cache_wait;
	struct btrfs_free_space_ctl *free_ino_pinned;
	u64 cache_progress;
	struct inode *cache_inode;

	struct mutex log_mutex;
	wait_queue_head_t log_writer_wait;
	wait_queue_head_t log_commit_wait[2];
	struct list_head log_ctxs[2];
	atomic_t log_writers;
	atomic_t log_commit[2];
	atomic_t log_batch;
	int log_transid;
#ifdef MY_ABC_HERE
#else
	/* No matter the commit succeeds or not*/
	int log_transid_committed;
	/* Just be updated when the commit succeeds. */
#endif /* MY_ABC_HERE */
	int last_log_commit;
	pid_t log_start_pid;

	u64 objectid;
	u64 last_trans;

	/* data allocations are done in sectorsize units */
	u32 sectorsize;

	/* node allocations are done in nodesize units */
	u32 nodesize;

	/* leaf allocations are done in leafsize units */
	u32 leafsize;

	u32 stripesize;

	u32 type;

	u64 highest_objectid;

	/* only used with CONFIG_BTRFS_FS_RUN_SANITY_TESTS is enabled */
	u64 alloc_bytenr;

	u64 defrag_trans_start;
	struct btrfs_key defrag_progress;
	struct btrfs_key defrag_max;
	char *name;

	/* the dirty list is only used by non-reference counted roots */
	struct list_head dirty_list;

	struct list_head root_list;

	spinlock_t log_extents_lock[2];
	struct list_head logged_list[2];

	int orphan_cleanup_state;

	spinlock_t inode_lock;
	/* red-black tree that keeps track of in-memory inodes */
	struct rb_root inode_tree;

	/*
	 * radix tree that keeps track of delayed nodes of every inode,
	 * protected by inode_lock
	 */
	struct radix_tree_root delayed_nodes_tree;
	/*
	 * right now this just gets used so that a root has its own devid
	 * for stat.  It may be used for more later
	 */
	dev_t anon_dev;

	spinlock_t root_item_lock;
	atomic_t refs;

	struct mutex delalloc_mutex;
	spinlock_t delalloc_lock;
	/*
	 * all of the inodes that have delalloc bytes.  It is possible for
	 * this list to be empty even when there is still dirty data=ordered
	 * extents waiting to finish IO.
	 */
	struct list_head delalloc_inodes;
	struct list_head delalloc_root;
	u64 nr_delalloc_inodes;

	struct mutex ordered_extent_mutex;
#ifdef MY_ABC_HERE
	struct mutex ordered_extent_worker_mutex;
#endif
	/*
	 * this is used by the balancing code to wait for all the pending
	 * ordered extents
	 */
	spinlock_t ordered_extent_lock;

	/*
	 * all of the data=ordered extents pending writeback
	 * these can span multiple transactions and basically include
	 * every dirty data page that isn't from nodatacow
	 */
	struct list_head ordered_extents;
	struct list_head ordered_root;
	u64 nr_ordered_extents;

	/*
	 * Number of currently running SEND ioctls to prevent
	 * manipulation with the read-only status via SUBVOL_SETFLAGS
	 */
	int send_in_progress;
	struct btrfs_subvolume_writers *subv_writers;
	atomic_t will_be_snapshoted;
#ifdef MY_ABC_HERE
	atomic_t force_cow;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	/*
	 * Keep track of generation when read-only subvolume usrquota subtree loaded
	 */
	 struct list_head usrquota_ro_root;
	 u64 usrquota_loaded_gen;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	 struct percpu_counter eb_hit;
	 struct percpu_counter eb_miss;
	 struct dentry *eb_hit_dentry;
	 struct dentry *eb_miss_dentry;
#endif /* MY_ABC_HERE */

	/* Number of active swapfiles */
	atomic_t nr_swapfiles;

#ifdef MY_ABC_HERE
	unsigned int syno_usage_enabled:1;
	struct btrfs_syno_usage_root_status syno_usage_root_status;
	unsigned long syno_usage_runtime_flags;
	spinlock_t syno_usage_lock; /* protects the syno_usage_root_status [type,new_type,state,flags,num_bytes,fast_rescan_progress] */
	rwlock_t syno_usage_rwlock; /* protects the syno_usage_root_status [full_rescan_progress] */
	struct list_head syno_usage_rescan_list;
	struct percpu_counter *syno_delalloc_bytes;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	/*
	 * This refs is to make sure subvolume won't be added to
	 * dead root until this count reaches zero.
	 * Contrary to btrfs_root::refs in the above, that refs only
	 * make sure btrfs_root structure is not freed, but the
	 * content it points to is not guaranteed.
	 */
	atomic_t use_refs;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	struct {
		struct list_head root; /* protect with fs_info->syno_orphan_cleanup.lock */
		int cleanup_in_progress; /* protect with root->root_item_lock */
	} syno_orphan_cleanup;
#endif /* MY_ABC_HERE */
};

#ifdef MY_ABC_HERE
struct btrfs_snapshot_size_entry {
	u64 root_id;
	struct btrfs_root *root;
	struct btrfs_path *path;
	struct btrfs_key key;
	struct rb_node node;
	int root_level;
	int level;
	u64 snap_exclusive_size;
};

struct btrfs_file_private {
	struct btrfs_trans_handle *trans;
	void *filldir_buf;
};

struct btrfs_snapshot_size_ctx {
	u64 flags;
	struct file *out_filp;
	struct rb_root root;
	struct btrfs_snapshot_size_entry snaps[0];
};
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
/* Arguments for btrfs_punch_hole/btrfs_punch_hole_range */
struct btrfs_punch_hole_args {
	bool non_blocking; /* in */
	bool need_restart; /* out */
	loff_t next_offset; /* out */
};
#endif /* MY_ABC_HERE */

struct btrfs_clone_extent_info {
	u64 disk_offset;
	u64 disk_len;
	u64 data_offset;
	u64 data_len;
	u64 file_offset;
	char *extent_buf;
	u32 item_size;

	/* for original quota */
	bool same_root;

#ifdef MY_ABC_HERE
	// Used in syno quota v1.
	bool quota_enabled;
	bool same_inode;
	bool check_backref;
	bool accounting_reserve;
	bool set_clone_range_flag;
	u64 ram_bytes;
	struct ulist *disko_ulist;
	bool ulist_overflow;
#endif /* MY_ABC_HERE */
};

/* Arguments for btrfs_drop_extents() */
struct btrfs_drop_extents_args {
	/* Input parameters */

	/*
	 * If NULL, btrfs_drop_extents() will allocate and free its own path.
	 * If 'replace_extent' is true, this must not be NULL. Also the path
	 * is always released except if 'replace_extent' is true and
	 * btrfs_drop_extents() sets 'extent_inserted' to true, in which case
	 * the path is kept locked.
	 */
	struct btrfs_path *path;
	/* Start offset of the range to drop extents from */
	u64 start;
	/* End (exclusive, last byte + 1) of the range to drop extents from */
	u64 end;
	/* If true drop all the extent maps in the range */
	bool drop_cache;
	/*
	 * If true it means we want to insert a new extent after dropping all
	 * the extents in the range. If this is true, the 'extent_item_size'
	 * parameter must be set as well and the 'extent_inserted' field will
	 * be set to true by btrfs_drop_extents() if it could insert the new
	 * extent.
	 * Note: when this is set to true the path must not be NULL.
	 */
	bool replace_extent;
	/*
	 * Used if 'replace_extent' is true. Size of the file extent item to
	 * insert after dropping all existing extents in the range
	 */
	u32 extent_item_size;

	/* Output parameters */

	/*
	 * Set to the minimum between the input parameter 'end' and the end
	 * (exclusive, last byte + 1) of the last dropped extent. This is always
	 * set even if btrfs_drop_extents() returns an error.
	 */
	u64 drop_end;
	/*
	 * The number of allocated bytes found in the range. This can be smaller
	 * than the range's length when there are holes in the range.
	 */
	u64 bytes_found;
	/*
	 * Only set if 'replace_extent' is true. Set to true if we were able
	 * to insert a replacement extent after dropping all extents in the
	 * range, otherwise set to false by btrfs_drop_extents().
	 * Also, if btrfs_drop_extents() has set this to true it means it
	 * returned with the path locked, otherwise if it has set this to
	 * false it has returned with the path released.
	 */
	bool extent_inserted;

#ifdef MY_ABC_HERE
	u64 *first_punch_pos;
	u64 *last_punch_pos;
	int *partial_punch;
#endif /* MY_ABC_HERE */
};

/*
 * inode items have the data typically returned from stat and store other
 * info about object characteristics.  There is one for every file and dir in
 * the FS
 */
#define BTRFS_INODE_ITEM_KEY		1
#define BTRFS_INODE_REF_KEY		12
#define BTRFS_INODE_EXTREF_KEY		13
#define BTRFS_XATTR_ITEM_KEY		24
#define BTRFS_ORPHAN_ITEM_KEY		48
/* reserve 2-15 close to the inode for later flexibility */

/*
 * dir items are the name -> inode pointers in a directory.  There is one
 * for every name in a directory.
 */
#define BTRFS_DIR_LOG_ITEM_KEY  60
#define BTRFS_DIR_LOG_INDEX_KEY 72
#define BTRFS_DIR_ITEM_KEY	84
#ifdef MY_ABC_HERE
#define BTRFS_DIR_ITEM_CASELESS_KEY 91
#endif /* MY_ABC_HERE */
#define BTRFS_DIR_INDEX_KEY	96
/*
 * extent data is for file data
 */
#define BTRFS_EXTENT_DATA_KEY	108

/*
 * extent csums are stored in a separate tree and hold csums for
 * an entire extent on disk.
 */
#define BTRFS_EXTENT_CSUM_KEY	128

/*
 * root items point to tree roots.  They are typically in the root
 * tree used by the super block to find all the other trees
 */
#define BTRFS_ROOT_ITEM_KEY	132

/*
 * root backrefs tie subvols and snapshots to the directory entries that
 * reference them
 */
#define BTRFS_ROOT_BACKREF_KEY	144

/*
 * root refs make a fast index for listing all of the snapshots and
 * subvolumes referenced by a given root.  They point directly to the
 * directory item in the root that references the subvol
 */
#define BTRFS_ROOT_REF_KEY	156

#ifdef MY_ABC_HERE
/*
 * syno usage tree
 * syno usage status key : 158
 * global type key : 159
 * root status key : 160
 */
#define SYNO_BTRFS_USAGE_STATUS_KEY 158
#define SYNO_BTRFS_USAGE_GLOBAL_TYPE_KEY 159
#define SYNO_BTRFS_USAGE_ROOT_STATUS_KEY 160

/*
 * fs tree
 * syno subvol dummy key 162
 * syno subvol usage key 163
 */
#define SYNO_BTRFS_SUBVOL_DUMMY_KEY 162
#define SYNO_BTRFS_SUBVOL_USAGE_KEY 163

/*
 * syno extent usage key
 */
#define SYNO_BTRFS_EXTENT_USAGE_KEY 165
#endif /* MY_ABC_HERE */

/*
 * extent items are in the extent map tree.  These record which blocks
 * are used, and how many references there are to each block
 */
#define BTRFS_EXTENT_ITEM_KEY	168

/*
 * The same as the BTRFS_EXTENT_ITEM_KEY, except it's metadata we already know
 * the length, so we save the level in key->offset instead of the length.
 */
#define BTRFS_METADATA_ITEM_KEY	169

#define BTRFS_TREE_BLOCK_REF_KEY	176

#define BTRFS_EXTENT_DATA_REF_KEY	178

#define BTRFS_EXTENT_REF_V0_KEY		180

#define BTRFS_SHARED_BLOCK_REF_KEY	182

#define BTRFS_SHARED_DATA_REF_KEY	184

/*
 * block groups give us hints into the extent allocation trees.  Which
 * blocks are free etc etc
 */
#define BTRFS_BLOCK_GROUP_ITEM_KEY 192

/*
 * Every block group is represented in the free space tree by a free space info
 * item, which stores some accounting information. It is keyed on
 * (block_group_start, FREE_SPACE_INFO, block_group_length).
 */
#define BTRFS_FREE_SPACE_INFO_KEY 198

/*
 * A free space extent tracks an extent of space that is free in a block group.
 * It is keyed on (start, FREE_SPACE_EXTENT, length).
 */
#define BTRFS_FREE_SPACE_EXTENT_KEY 199

/*
 * When a block group becomes very fragmented, we convert it to use bitmaps
 * instead of extents. A free space bitmap is keyed on
 * (start, FREE_SPACE_BITMAP, length); the corresponding item is a bitmap with
 * (length / sectorsize) bits.
 */
#define BTRFS_FREE_SPACE_BITMAP_KEY 200

#define BTRFS_DEV_EXTENT_KEY	204
#define BTRFS_DEV_ITEM_KEY	216
#define BTRFS_CHUNK_ITEM_KEY	228

/*
 * Records the overall state of the qgroups.
 * There's only one instance of this key present,
 * (0, BTRFS_QGROUP_STATUS_KEY, 0)
 */
#define BTRFS_QGROUP_STATUS_KEY         240
/*
 * Records the currently used space of the qgroup.
 * One key per qgroup, (0, BTRFS_QGROUP_INFO_KEY, qgroupid).
 */
#define BTRFS_QGROUP_INFO_KEY           242
/*
 * Contains the user configured limits for the qgroup.
 * One key per qgroup, (0, BTRFS_QGROUP_LIMIT_KEY, qgroupid).
 */
#define BTRFS_QGROUP_LIMIT_KEY          244
/*
 * Records the child-parent relationship of qgroups. For
 * each relation, 2 keys are present:
 * (childid, BTRFS_QGROUP_RELATION_KEY, parentid)
 * (parentid, BTRFS_QGROUP_RELATION_KEY, childid)
 */
#define BTRFS_QGROUP_RELATION_KEY       246

#ifdef MY_ABC_HERE
/*
 * Records the overall state of the usrquota.
 * There's only one instance of this key present,
 * (0, BTRFS_USRQUOTA_STATUS_KEY, 0)
 */
#define BTRFS_USRQUOTA_STATUS_KEY       240
/*
 * Records the per root (subvolume) usrquota infomation.
 * One key per root, (root_id, BTRFS_USRQUOTA_ROOT_KEY, 0).
 */
#define BTRFS_USRQUOTA_ROOT_KEY         241
/*
 * Records the currently used space of the usrquota.
 * One key per usrquota, (root_id, BTRFS_USRQUOTA_INFO_KEY, uid).
 */
#define BTRFS_USRQUOTA_INFO_KEY         242
/*
 * Contains the user configured limits for the usrquota.
 * One key per usrquota, (root_id, BTRFS_USRGROUP_LIMIT_KEY, uid).
 */
#define BTRFS_USRQUOTA_LIMIT_KEY        244

#define BTRFS_USRQUOTA_COMPAT_KEY        245
#endif /* MY_ABC_HERE */

#define BTRFS_BALANCE_ITEM_KEY	248

/*
 * Persistantly stores the io stats in the device tree.
 * One key for all stats, (0, BTRFS_DEV_STATS_KEY, devid).
 */
#define BTRFS_DEV_STATS_KEY	249

/*
 * Persistantly stores the device replace state in the device tree.
 * The key is built like this: (0, BTRFS_DEV_REPLACE_KEY, 0).
 */
#define BTRFS_DEV_REPLACE_KEY	250

/*
 * Stores items that allow to quickly map UUIDs to something else.
 * These items are part of the filesystem UUID tree.
 * The key is built like this:
 * (UUID_upper_64_bits, BTRFS_UUID_KEY*, UUID_lower_64_bits).
 */
#if BTRFS_UUID_SIZE != 16
#error "UUID items require BTRFS_UUID_SIZE == 16!"
#endif
#define BTRFS_UUID_KEY_SUBVOL	251	/* for UUIDs assigned to subvols */
#define BTRFS_UUID_KEY_RECEIVED_SUBVOL	252	/* for UUIDs assigned to
						 * received subvols */

/*
 * string items are for debugging.  They just store a short string of
 * data in the FS
 */
#define BTRFS_STRING_ITEM_KEY	253

/*
 * Flags for mount options.
 *
 * Note: don't forget to add new options to btrfs_show_options()
 */
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_NODATASUM		(1ULL << 0)
#define BTRFS_MOUNT_NODATACOW		(1ULL << 1)
#define BTRFS_MOUNT_NOBARRIER		(1ULL << 2)
#define BTRFS_MOUNT_SSD			(1ULL << 3)
#define BTRFS_MOUNT_DEGRADED		(1ULL << 4)
#define BTRFS_MOUNT_COMPRESS		(1ULL << 5)
#define BTRFS_MOUNT_NOTREELOG           (1ULL << 6)
#define BTRFS_MOUNT_FLUSHONCOMMIT       (1ULL << 7)
#define BTRFS_MOUNT_SSD_SPREAD		(1ULL << 8)
#define BTRFS_MOUNT_NOSSD		(1ULL << 9)
#define BTRFS_MOUNT_DISCARD		(1ULL << 10)
#define BTRFS_MOUNT_FORCE_COMPRESS      (1ULL << 11)
#define BTRFS_MOUNT_SPACE_CACHE		(1ULL << 12)
#define BTRFS_MOUNT_CLEAR_CACHE		(1ULL << 13)
#define BTRFS_MOUNT_USER_SUBVOL_RM_ALLOWED (1ULL << 14)
#define BTRFS_MOUNT_ENOSPC_DEBUG	 (1ULL << 15)
#define BTRFS_MOUNT_AUTO_DEFRAG		(1ULL << 16)
#define BTRFS_MOUNT_INODE_MAP_CACHE	(1ULL << 17)
#define BTRFS_MOUNT_RECOVERY		(1ULL << 18)
#define BTRFS_MOUNT_SKIP_BALANCE	(1ULL << 19)
#define BTRFS_MOUNT_CHECK_INTEGRITY	(1ULL << 20)
#define BTRFS_MOUNT_CHECK_INTEGRITY_INCLUDING_EXTENT_DATA (1ULL << 21)
#define BTRFS_MOUNT_PANIC_ON_FATAL_ERROR	(1ULL << 22)
#define BTRFS_MOUNT_RESCAN_UUID_TREE	(1ULL << 23)
#define	BTRFS_MOUNT_CHANGE_INODE_CACHE	(1ULL << 24)
#define BTRFS_MOUNT_FREE_SPACE_TREE	(1ULL << 26)
#define BTRFS_MOUNT_NOLOGREPLAY		(1ULL << 27)
#else
#define BTRFS_MOUNT_NODATASUM		(1 << 0)
#define BTRFS_MOUNT_NODATACOW		(1 << 1)
#define BTRFS_MOUNT_NOBARRIER		(1 << 2)
#define BTRFS_MOUNT_SSD			(1 << 3)
#define BTRFS_MOUNT_DEGRADED		(1 << 4)
#define BTRFS_MOUNT_COMPRESS		(1 << 5)
#define BTRFS_MOUNT_NOTREELOG           (1 << 6)
#define BTRFS_MOUNT_FLUSHONCOMMIT       (1 << 7)
#define BTRFS_MOUNT_SSD_SPREAD		(1 << 8)
#define BTRFS_MOUNT_NOSSD		(1 << 9)
#define BTRFS_MOUNT_DISCARD		(1 << 10)
#define BTRFS_MOUNT_FORCE_COMPRESS      (1 << 11)
#define BTRFS_MOUNT_SPACE_CACHE		(1 << 12)
#define BTRFS_MOUNT_CLEAR_CACHE		(1 << 13)
#define BTRFS_MOUNT_USER_SUBVOL_RM_ALLOWED (1 << 14)
#define BTRFS_MOUNT_ENOSPC_DEBUG	 (1 << 15)
#define BTRFS_MOUNT_AUTO_DEFRAG		(1 << 16)
#define BTRFS_MOUNT_INODE_MAP_CACHE	(1 << 17)
#define BTRFS_MOUNT_RECOVERY		(1 << 18)
#define BTRFS_MOUNT_SKIP_BALANCE	(1 << 19)
#define BTRFS_MOUNT_CHECK_INTEGRITY	(1 << 20)
#define BTRFS_MOUNT_CHECK_INTEGRITY_INCLUDING_EXTENT_DATA (1 << 21)
#define BTRFS_MOUNT_PANIC_ON_FATAL_ERROR	(1 << 22)
#define BTRFS_MOUNT_RESCAN_UUID_TREE	(1 << 23)
#define	BTRFS_MOUNT_CHANGE_INODE_CACHE	(1 << 24)
#define BTRFS_MOUNT_FREE_SPACE_TREE	(1 << 26)
#define BTRFS_MOUNT_NOLOGREPLAY		(1 << 27)
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_BLOCK_GROUP_CACHE_TREE	(1ULL << 28)
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_NO_QUOTA_TREE	(1ULL << 29)
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_NO_BLOCK_GROUP	(1ULL << 30)
#endif /*MY_ABC_HERE*/
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_AUTO_RECLAIM_SPACE	(1ULL << 31)
#endif /*MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_SYNO_ACL        (1ULL << 32)
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_DROP_LOG_TREE	(1ULL << 33)
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_SKIP_CLEANER       (1ULL << 34)
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BTRFS_MOUNT_SYNO_ALLOCATOR	(1ULL << 36)
#endif /* MY_ABC_HERE */

#define BTRFS_DEFAULT_COMMIT_INTERVAL	(30)
#ifdef MY_ABC_HERE
#define BTRFS_DEFAULT_MAX_INLINE	(512)
#else
#define BTRFS_DEFAULT_MAX_INLINE	(2048)
#endif /* MY_ABC_HERE=*/

#define btrfs_clear_opt(o, opt)		((o) &= ~BTRFS_MOUNT_##opt)
#define btrfs_set_opt(o, opt)		((o) |= BTRFS_MOUNT_##opt)
#define btrfs_raw_test_opt(o, opt)	((o) & BTRFS_MOUNT_##opt)
#define btrfs_test_opt(root, opt)	((root)->fs_info->mount_opt & \
					 BTRFS_MOUNT_##opt)
#define btrfs_set_and_info(root, opt, fmt, args...)			\
{									\
	if (!btrfs_test_opt(root, opt))					\
		btrfs_info(root->fs_info, fmt, ##args);			\
	btrfs_set_opt(root->fs_info->mount_opt, opt);			\
}

#define btrfs_clear_and_info(root, opt, fmt, args...)			\
{									\
	if (btrfs_test_opt(root, opt))					\
		btrfs_info(root->fs_info, fmt, ##args);			\
	btrfs_clear_opt(root->fs_info->mount_opt, opt);			\
}

/*
 * Inode flags
 */
#define BTRFS_INODE_NODATASUM		(1 << 0)
#define BTRFS_INODE_NODATACOW		(1 << 1)
#define BTRFS_INODE_READONLY		(1 << 2)
#define BTRFS_INODE_NOCOMPRESS		(1 << 3)
#define BTRFS_INODE_PREALLOC		(1 << 4)
#define BTRFS_INODE_SYNC		(1 << 5)
#define BTRFS_INODE_IMMUTABLE		(1 << 6)
#define BTRFS_INODE_APPEND		(1 << 7)
#define BTRFS_INODE_NODUMP		(1 << 8)
#define BTRFS_INODE_NOATIME		(1 << 9)
#define BTRFS_INODE_DIRSYNC		(1 << 10)
#define BTRFS_INODE_COMPRESS		(1 << 11)

#ifdef MY_ABC_HERE
#define BTRFS_INODE_UQ_REF_USED		(1 << 30)
#endif /* MY_ABC_HERE */
#define BTRFS_INODE_ROOT_ITEM_INIT	(1 << 31)

struct btrfs_map_token {
	struct extent_buffer *eb;
	char *kaddr;
	unsigned long offset;
};

static inline void btrfs_init_map_token (struct btrfs_map_token *token)
{
	token->kaddr = NULL;
}

/* some macros to generate set/get funcs for the struct fields.  This
 * assumes there is a lefoo_to_cpu for every type, so lets make a simple
 * one for u8:
 */
#define le8_to_cpu(v) (v)
#define cpu_to_le8(v) (v)
#define __le8 u8

#define read_eb_member(eb, ptr, type, member, result) (			\
	read_extent_buffer(eb, (char *)(result),			\
			   ((unsigned long)(ptr)) +			\
			    offsetof(type, member),			\
			   sizeof(((type *)0)->member)))

#define write_eb_member(eb, ptr, type, member, result) (		\
	write_extent_buffer(eb, (char *)(result),			\
			   ((unsigned long)(ptr)) +			\
			    offsetof(type, member),			\
			   sizeof(((type *)0)->member)))

#define DECLARE_BTRFS_SETGET_BITS(bits)					\
u##bits btrfs_get_token_##bits(struct extent_buffer *eb, void *ptr,	\
			       unsigned long off,			\
                              struct btrfs_map_token *token);		\
void btrfs_set_token_##bits(struct extent_buffer *eb, void *ptr,	\
			    unsigned long off, u##bits val,		\
			    struct btrfs_map_token *token);		\
static inline u##bits btrfs_get_##bits(struct extent_buffer *eb, void *ptr, \
				       unsigned long off)		\
{									\
	return btrfs_get_token_##bits(eb, ptr, off, NULL);		\
}									\
static inline void btrfs_set_##bits(struct extent_buffer *eb, void *ptr, \
				    unsigned long off, u##bits val)	\
{									\
       btrfs_set_token_##bits(eb, ptr, off, val, NULL);			\
}

DECLARE_BTRFS_SETGET_BITS(8)
DECLARE_BTRFS_SETGET_BITS(16)
DECLARE_BTRFS_SETGET_BITS(32)
DECLARE_BTRFS_SETGET_BITS(64)

#define BTRFS_SETGET_FUNCS(name, type, member, bits)			\
static inline u##bits btrfs_##name(struct extent_buffer *eb, type *s)	\
{									\
	BUILD_BUG_ON(sizeof(u##bits) != sizeof(((type *)0))->member);	\
	return btrfs_get_##bits(eb, s, offsetof(type, member));		\
}									\
static inline void btrfs_set_##name(struct extent_buffer *eb, type *s,	\
				    u##bits val)			\
{									\
	BUILD_BUG_ON(sizeof(u##bits) != sizeof(((type *)0))->member);	\
	btrfs_set_##bits(eb, s, offsetof(type, member), val);		\
}									\
static inline u##bits btrfs_token_##name(struct extent_buffer *eb, type *s, \
					 struct btrfs_map_token *token)	\
{									\
	BUILD_BUG_ON(sizeof(u##bits) != sizeof(((type *)0))->member);	\
	return btrfs_get_token_##bits(eb, s, offsetof(type, member), token); \
}									\
static inline void btrfs_set_token_##name(struct extent_buffer *eb,	\
					  type *s, u##bits val,		\
                                         struct btrfs_map_token *token)	\
{									\
	BUILD_BUG_ON(sizeof(u##bits) != sizeof(((type *)0))->member);	\
	btrfs_set_token_##bits(eb, s, offsetof(type, member), val, token); \
}

#define BTRFS_SETGET_HEADER_FUNCS(name, type, member, bits)		\
static inline u##bits btrfs_##name(struct extent_buffer *eb)		\
{									\
	type *p = page_address(eb->pages[0]);				\
	u##bits res = le##bits##_to_cpu(p->member);			\
	return res;							\
}									\
static inline void btrfs_set_##name(struct extent_buffer *eb,		\
				    u##bits val)			\
{									\
	type *p = page_address(eb->pages[0]);				\
	p->member = cpu_to_le##bits(val);				\
}

#define BTRFS_SETGET_STACK_FUNCS(name, type, member, bits)		\
static inline u##bits btrfs_##name(type *s)				\
{									\
	return le##bits##_to_cpu(s->member);				\
}									\
static inline void btrfs_set_##name(type *s, u##bits val)		\
{									\
	s->member = cpu_to_le##bits(val);				\
}

BTRFS_SETGET_FUNCS(device_type, struct btrfs_dev_item, type, 64);
BTRFS_SETGET_FUNCS(device_total_bytes, struct btrfs_dev_item, total_bytes, 64);
BTRFS_SETGET_FUNCS(device_bytes_used, struct btrfs_dev_item, bytes_used, 64);
BTRFS_SETGET_FUNCS(device_io_align, struct btrfs_dev_item, io_align, 32);
BTRFS_SETGET_FUNCS(device_io_width, struct btrfs_dev_item, io_width, 32);
BTRFS_SETGET_FUNCS(device_start_offset, struct btrfs_dev_item,
		   start_offset, 64);
BTRFS_SETGET_FUNCS(device_sector_size, struct btrfs_dev_item, sector_size, 32);
BTRFS_SETGET_FUNCS(device_id, struct btrfs_dev_item, devid, 64);
BTRFS_SETGET_FUNCS(device_group, struct btrfs_dev_item, dev_group, 32);
BTRFS_SETGET_FUNCS(device_seek_speed, struct btrfs_dev_item, seek_speed, 8);
BTRFS_SETGET_FUNCS(device_bandwidth, struct btrfs_dev_item, bandwidth, 8);
BTRFS_SETGET_FUNCS(device_generation, struct btrfs_dev_item, generation, 64);

BTRFS_SETGET_STACK_FUNCS(stack_device_type, struct btrfs_dev_item, type, 64);
BTRFS_SETGET_STACK_FUNCS(stack_device_total_bytes, struct btrfs_dev_item,
			 total_bytes, 64);
BTRFS_SETGET_STACK_FUNCS(stack_device_bytes_used, struct btrfs_dev_item,
			 bytes_used, 64);
BTRFS_SETGET_STACK_FUNCS(stack_device_io_align, struct btrfs_dev_item,
			 io_align, 32);
BTRFS_SETGET_STACK_FUNCS(stack_device_io_width, struct btrfs_dev_item,
			 io_width, 32);
BTRFS_SETGET_STACK_FUNCS(stack_device_sector_size, struct btrfs_dev_item,
			 sector_size, 32);
BTRFS_SETGET_STACK_FUNCS(stack_device_id, struct btrfs_dev_item, devid, 64);
BTRFS_SETGET_STACK_FUNCS(stack_device_group, struct btrfs_dev_item,
			 dev_group, 32);
BTRFS_SETGET_STACK_FUNCS(stack_device_seek_speed, struct btrfs_dev_item,
			 seek_speed, 8);
BTRFS_SETGET_STACK_FUNCS(stack_device_bandwidth, struct btrfs_dev_item,
			 bandwidth, 8);
BTRFS_SETGET_STACK_FUNCS(stack_device_generation, struct btrfs_dev_item,
			 generation, 64);

static inline unsigned long btrfs_device_uuid(struct btrfs_dev_item *d)
{
	return (unsigned long)d + offsetof(struct btrfs_dev_item, uuid);
}

static inline unsigned long btrfs_device_fsid(struct btrfs_dev_item *d)
{
	return (unsigned long)d + offsetof(struct btrfs_dev_item, fsid);
}

BTRFS_SETGET_FUNCS(chunk_length, struct btrfs_chunk, length, 64);
BTRFS_SETGET_FUNCS(chunk_owner, struct btrfs_chunk, owner, 64);
BTRFS_SETGET_FUNCS(chunk_stripe_len, struct btrfs_chunk, stripe_len, 64);
BTRFS_SETGET_FUNCS(chunk_io_align, struct btrfs_chunk, io_align, 32);
BTRFS_SETGET_FUNCS(chunk_io_width, struct btrfs_chunk, io_width, 32);
BTRFS_SETGET_FUNCS(chunk_sector_size, struct btrfs_chunk, sector_size, 32);
BTRFS_SETGET_FUNCS(chunk_type, struct btrfs_chunk, type, 64);
BTRFS_SETGET_FUNCS(chunk_num_stripes, struct btrfs_chunk, num_stripes, 16);
BTRFS_SETGET_FUNCS(chunk_sub_stripes, struct btrfs_chunk, sub_stripes, 16);
BTRFS_SETGET_FUNCS(stripe_devid, struct btrfs_stripe, devid, 64);
BTRFS_SETGET_FUNCS(stripe_offset, struct btrfs_stripe, offset, 64);

static inline char *btrfs_stripe_dev_uuid(struct btrfs_stripe *s)
{
	return (char *)s + offsetof(struct btrfs_stripe, dev_uuid);
}

BTRFS_SETGET_STACK_FUNCS(stack_chunk_length, struct btrfs_chunk, length, 64);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_owner, struct btrfs_chunk, owner, 64);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_stripe_len, struct btrfs_chunk,
			 stripe_len, 64);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_io_align, struct btrfs_chunk,
			 io_align, 32);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_io_width, struct btrfs_chunk,
			 io_width, 32);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_sector_size, struct btrfs_chunk,
			 sector_size, 32);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_type, struct btrfs_chunk, type, 64);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_num_stripes, struct btrfs_chunk,
			 num_stripes, 16);
BTRFS_SETGET_STACK_FUNCS(stack_chunk_sub_stripes, struct btrfs_chunk,
			 sub_stripes, 16);
BTRFS_SETGET_STACK_FUNCS(stack_stripe_devid, struct btrfs_stripe, devid, 64);
BTRFS_SETGET_STACK_FUNCS(stack_stripe_offset, struct btrfs_stripe, offset, 64);

static inline struct btrfs_stripe *btrfs_stripe_nr(struct btrfs_chunk *c,
						   int nr)
{
	unsigned long offset = (unsigned long)c;
	offset += offsetof(struct btrfs_chunk, stripe);
	offset += nr * sizeof(struct btrfs_stripe);
	return (struct btrfs_stripe *)offset;
}

static inline char *btrfs_stripe_dev_uuid_nr(struct btrfs_chunk *c, int nr)
{
	return btrfs_stripe_dev_uuid(btrfs_stripe_nr(c, nr));
}

static inline u64 btrfs_stripe_offset_nr(struct extent_buffer *eb,
					 struct btrfs_chunk *c, int nr)
{
	return btrfs_stripe_offset(eb, btrfs_stripe_nr(c, nr));
}

static inline u64 btrfs_stripe_devid_nr(struct extent_buffer *eb,
					 struct btrfs_chunk *c, int nr)
{
	return btrfs_stripe_devid(eb, btrfs_stripe_nr(c, nr));
}

/* struct btrfs_block_group_item */
BTRFS_SETGET_STACK_FUNCS(block_group_used, struct btrfs_block_group_item,
			 used, 64);
BTRFS_SETGET_FUNCS(disk_block_group_used, struct btrfs_block_group_item,
			 used, 64);
BTRFS_SETGET_STACK_FUNCS(block_group_chunk_objectid,
			struct btrfs_block_group_item, chunk_objectid, 64);

BTRFS_SETGET_FUNCS(disk_block_group_chunk_objectid,
		   struct btrfs_block_group_item, chunk_objectid, 64);
BTRFS_SETGET_FUNCS(disk_block_group_flags,
		   struct btrfs_block_group_item, flags, 64);
BTRFS_SETGET_STACK_FUNCS(block_group_flags,
			struct btrfs_block_group_item, flags, 64);

/* struct btrfs_free_space_info */
BTRFS_SETGET_FUNCS(free_space_extent_count, struct btrfs_free_space_info,
		   extent_count, 32);
BTRFS_SETGET_FUNCS(free_space_flags, struct btrfs_free_space_info, flags, 32);

/* struct btrfs_inode_ref */
BTRFS_SETGET_FUNCS(inode_ref_name_len, struct btrfs_inode_ref, name_len, 16);
BTRFS_SETGET_FUNCS(inode_ref_index, struct btrfs_inode_ref, index, 64);

/* struct btrfs_inode_extref */
BTRFS_SETGET_FUNCS(inode_extref_parent, struct btrfs_inode_extref,
		   parent_objectid, 64);
BTRFS_SETGET_FUNCS(inode_extref_name_len, struct btrfs_inode_extref,
		   name_len, 16);
BTRFS_SETGET_FUNCS(inode_extref_index, struct btrfs_inode_extref, index, 64);

/* struct btrfs_inode_item */
BTRFS_SETGET_FUNCS(inode_generation, struct btrfs_inode_item, generation, 64);
BTRFS_SETGET_FUNCS(inode_sequence, struct btrfs_inode_item, sequence, 64);
BTRFS_SETGET_FUNCS(inode_transid, struct btrfs_inode_item, transid, 64);
BTRFS_SETGET_FUNCS(inode_size, struct btrfs_inode_item, size, 64);
BTRFS_SETGET_FUNCS(inode_nbytes, struct btrfs_inode_item, nbytes, 64);
BTRFS_SETGET_FUNCS(inode_block_group, struct btrfs_inode_item, block_group, 64);
BTRFS_SETGET_FUNCS(inode_nlink, struct btrfs_inode_item, nlink, 32);
BTRFS_SETGET_FUNCS(inode_uid, struct btrfs_inode_item, uid, 32);
BTRFS_SETGET_FUNCS(inode_gid, struct btrfs_inode_item, gid, 32);
BTRFS_SETGET_FUNCS(inode_mode, struct btrfs_inode_item, mode, 32);
BTRFS_SETGET_FUNCS(inode_rdev, struct btrfs_inode_item, rdev, 64);
BTRFS_SETGET_FUNCS(inode_flags, struct btrfs_inode_item, flags, 64);
#ifdef MY_ABC_HERE
BTRFS_SETGET_FUNCS(inode_syno_uq_rfer_used, struct btrfs_inode_item, syno_uq_rfer_used, 64);
#endif /* MY_ABC_HERE */
BTRFS_SETGET_STACK_FUNCS(stack_inode_generation, struct btrfs_inode_item,
			 generation, 64);
BTRFS_SETGET_STACK_FUNCS(stack_inode_sequence, struct btrfs_inode_item,
			 sequence, 64);
BTRFS_SETGET_STACK_FUNCS(stack_inode_transid, struct btrfs_inode_item,
			 transid, 64);
BTRFS_SETGET_STACK_FUNCS(stack_inode_size, struct btrfs_inode_item, size, 64);
BTRFS_SETGET_STACK_FUNCS(stack_inode_nbytes, struct btrfs_inode_item,
			 nbytes, 64);
BTRFS_SETGET_STACK_FUNCS(stack_inode_block_group, struct btrfs_inode_item,
			 block_group, 64);
BTRFS_SETGET_STACK_FUNCS(stack_inode_nlink, struct btrfs_inode_item, nlink, 32);
BTRFS_SETGET_STACK_FUNCS(stack_inode_uid, struct btrfs_inode_item, uid, 32);
BTRFS_SETGET_STACK_FUNCS(stack_inode_gid, struct btrfs_inode_item, gid, 32);
BTRFS_SETGET_STACK_FUNCS(stack_inode_mode, struct btrfs_inode_item, mode, 32);
BTRFS_SETGET_STACK_FUNCS(stack_inode_rdev, struct btrfs_inode_item, rdev, 64);
BTRFS_SETGET_STACK_FUNCS(stack_inode_flags, struct btrfs_inode_item, flags, 64);
#ifdef MY_ABC_HERE
BTRFS_SETGET_STACK_FUNCS(stack_inode_syno_uq_rfer_used, struct btrfs_inode_item, syno_uq_rfer_used, 64);
#endif /* MY_ABC_HERE */

static inline struct btrfs_timespec *
btrfs_inode_atime(struct btrfs_inode_item *inode_item)
{
	unsigned long ptr = (unsigned long)inode_item;
	ptr += offsetof(struct btrfs_inode_item, atime);
	return (struct btrfs_timespec *)ptr;
}

static inline struct btrfs_timespec *
btrfs_inode_mtime(struct btrfs_inode_item *inode_item)
{
	unsigned long ptr = (unsigned long)inode_item;
	ptr += offsetof(struct btrfs_inode_item, mtime);
	return (struct btrfs_timespec *)ptr;
}

static inline struct btrfs_timespec *
btrfs_inode_ctime(struct btrfs_inode_item *inode_item)
{
	unsigned long ptr = (unsigned long)inode_item;
	ptr += offsetof(struct btrfs_inode_item, ctime);
	return (struct btrfs_timespec *)ptr;
}

BTRFS_SETGET_FUNCS(timespec_sec, struct btrfs_timespec, sec, 64);
BTRFS_SETGET_FUNCS(timespec_nsec, struct btrfs_timespec, nsec, 32);
BTRFS_SETGET_STACK_FUNCS(stack_timespec_sec, struct btrfs_timespec, sec, 64);
BTRFS_SETGET_STACK_FUNCS(stack_timespec_nsec, struct btrfs_timespec, nsec, 32);

/* struct btrfs_dev_extent */
BTRFS_SETGET_FUNCS(dev_extent_chunk_tree, struct btrfs_dev_extent,
		   chunk_tree, 64);
BTRFS_SETGET_FUNCS(dev_extent_chunk_objectid, struct btrfs_dev_extent,
		   chunk_objectid, 64);
BTRFS_SETGET_FUNCS(dev_extent_chunk_offset, struct btrfs_dev_extent,
		   chunk_offset, 64);
BTRFS_SETGET_FUNCS(dev_extent_length, struct btrfs_dev_extent, length, 64);

static inline unsigned long btrfs_dev_extent_chunk_tree_uuid(struct btrfs_dev_extent *dev)
{
	unsigned long ptr = offsetof(struct btrfs_dev_extent, chunk_tree_uuid);
	return (unsigned long)dev + ptr;
}

BTRFS_SETGET_FUNCS(extent_refs, struct btrfs_extent_item, refs, 64);
BTRFS_SETGET_FUNCS(extent_generation, struct btrfs_extent_item,
		   generation, 64);
BTRFS_SETGET_FUNCS(extent_flags, struct btrfs_extent_item, flags, 64);

BTRFS_SETGET_FUNCS(extent_refs_v0, struct btrfs_extent_item_v0, refs, 32);


BTRFS_SETGET_FUNCS(tree_block_level, struct btrfs_tree_block_info, level, 8);

static inline void btrfs_tree_block_key(struct extent_buffer *eb,
					struct btrfs_tree_block_info *item,
					struct btrfs_disk_key *key)
{
	read_eb_member(eb, item, struct btrfs_tree_block_info, key, key);
}

static inline void btrfs_set_tree_block_key(struct extent_buffer *eb,
					    struct btrfs_tree_block_info *item,
					    struct btrfs_disk_key *key)
{
	write_eb_member(eb, item, struct btrfs_tree_block_info, key, key);
}

BTRFS_SETGET_FUNCS(extent_data_ref_root, struct btrfs_extent_data_ref,
		   root, 64);
BTRFS_SETGET_FUNCS(extent_data_ref_objectid, struct btrfs_extent_data_ref,
		   objectid, 64);
BTRFS_SETGET_FUNCS(extent_data_ref_offset, struct btrfs_extent_data_ref,
		   offset, 64);
BTRFS_SETGET_FUNCS(extent_data_ref_count, struct btrfs_extent_data_ref,
		   count, 32);

BTRFS_SETGET_FUNCS(shared_data_ref_count, struct btrfs_shared_data_ref,
		   count, 32);

BTRFS_SETGET_FUNCS(extent_inline_ref_type, struct btrfs_extent_inline_ref,
		   type, 8);
BTRFS_SETGET_FUNCS(extent_inline_ref_offset, struct btrfs_extent_inline_ref,
		   offset, 64);

static inline u32 btrfs_extent_inline_ref_size(int type)
{
	if (type == BTRFS_TREE_BLOCK_REF_KEY ||
	    type == BTRFS_SHARED_BLOCK_REF_KEY)
		return sizeof(struct btrfs_extent_inline_ref);
	if (type == BTRFS_SHARED_DATA_REF_KEY)
		return sizeof(struct btrfs_shared_data_ref) +
		       sizeof(struct btrfs_extent_inline_ref);
	if (type == BTRFS_EXTENT_DATA_REF_KEY)
		return sizeof(struct btrfs_extent_data_ref) +
		       offsetof(struct btrfs_extent_inline_ref, offset);
	BUG();
	return 0;
}

#ifdef MY_ABC_HERE
BTRFS_SETGET_FUNCS(syno_usage_status_version, struct btrfs_syno_usage_status_item, version, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_state, struct btrfs_syno_usage_status_item, state, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_flags, struct btrfs_syno_usage_status_item, flags, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_generation, struct btrfs_syno_usage_status_item, generation, 64);
static inline void btrfs_syno_usage_status_extent_rescan_progress_key(struct extent_buffer *eb,
				      struct btrfs_syno_usage_status_item *item,
				      struct btrfs_disk_key *key)
{
	read_eb_member(eb, item, struct btrfs_syno_usage_status_item, extent_rescan_progress, key);
}

static inline void btrfs_set_syno_usage_status_extent_rescan_progress_key(struct extent_buffer *eb,
					  struct btrfs_syno_usage_status_item *item,
					  struct btrfs_disk_key *key)
{
	write_eb_member(eb, item, struct btrfs_syno_usage_status_item, extent_rescan_progress, key);
}
BTRFS_SETGET_FUNCS(syno_usage_status_cur_full_rescan_size, struct btrfs_syno_usage_status_item, cur_full_rescan_size, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_total_full_rescan_size, struct btrfs_syno_usage_status_item, total_full_rescan_size, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_extent_tree_cur_rescan_size, struct btrfs_syno_usage_status_item, extent_tree_cur_rescan_size, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_extent_tree_total_rescan_size, struct btrfs_syno_usage_status_item, extent_tree_total_rescan_size, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_total_syno_extent_tree_items, struct btrfs_syno_usage_status_item, total_syno_extent_tree_items, 64);
BTRFS_SETGET_FUNCS(syno_usage_status_total_syno_subvol_usage_items, struct btrfs_syno_usage_status_item, total_syno_subvol_usage_items, 64);

BTRFS_SETGET_FUNCS(syno_usage_global_type_num_bytes, struct btrfs_syno_usage_global_type_item, num_bytes, 64);

BTRFS_SETGET_FUNCS(syno_usage_root_status_type, struct btrfs_syno_usage_root_status_item, type, 8);
BTRFS_SETGET_FUNCS(syno_usage_root_status_new_type, struct btrfs_syno_usage_root_status_item, new_type, 8);
BTRFS_SETGET_FUNCS(syno_usage_root_status_state, struct btrfs_syno_usage_root_status_item, state, 64);
BTRFS_SETGET_FUNCS(syno_usage_root_status_flags, struct btrfs_syno_usage_root_status_item, flags, 64);
BTRFS_SETGET_FUNCS(syno_usage_root_status_num_bytes, struct btrfs_syno_usage_root_status_item, num_bytes, 64);
static inline void btrfs_syno_usage_root_status_drop_progress_key(struct extent_buffer *eb,
				      struct btrfs_syno_usage_root_status_item *item,
				      struct btrfs_disk_key *key)
{
	read_eb_member(eb, item, struct btrfs_syno_usage_root_status_item, drop_progress, key);
}
static inline void btrfs_set_syno_usage_root_status_drop_progress_key(struct extent_buffer *eb,
					  struct btrfs_syno_usage_root_status_item *item,
					  struct btrfs_disk_key *key)
{
	write_eb_member(eb, item, struct btrfs_syno_usage_root_status_item, drop_progress, key);
}
static inline void btrfs_syno_usage_root_status_fast_rescan_progress_key(struct extent_buffer *eb,
				      struct btrfs_syno_usage_root_status_item *item,
				      struct btrfs_disk_key *key)
{
	read_eb_member(eb, item, struct btrfs_syno_usage_root_status_item, fast_rescan_progress, key);
}
static inline void btrfs_set_syno_usage_root_status_fast_rescan_progress_key(struct extent_buffer *eb,
					  struct btrfs_syno_usage_root_status_item *item,
					  struct btrfs_disk_key *key)
{
	write_eb_member(eb, item, struct btrfs_syno_usage_root_status_item, fast_rescan_progress, key);
}
static inline void btrfs_syno_usage_root_status_full_rescan_progress_key(struct extent_buffer *eb,
				      struct btrfs_syno_usage_root_status_item *item,
				      struct btrfs_disk_key *key)
{
	read_eb_member(eb, item, struct btrfs_syno_usage_root_status_item, full_rescan_progress, key);
}
static inline void btrfs_set_syno_usage_root_status_full_rescan_progress_key(struct extent_buffer *eb,
					  struct btrfs_syno_usage_root_status_item *item,
					  struct btrfs_disk_key *key)
{
	write_eb_member(eb, item, struct btrfs_syno_usage_root_status_item, full_rescan_progress, key);
}
BTRFS_SETGET_FUNCS(syno_usage_root_status_cur_full_rescan_size, struct btrfs_syno_usage_root_status_item, cur_full_rescan_size, 64);
BTRFS_SETGET_FUNCS(syno_usage_root_status_total_full_rescan_size, struct btrfs_syno_usage_root_status_item, total_full_rescan_size, 64);
BTRFS_SETGET_FUNCS(syno_usage_root_status_total_syno_subvol_usage_items, struct btrfs_syno_usage_root_status_item, total_syno_subvol_usage_items, 64);

BTRFS_SETGET_FUNCS(syno_extent_usage_type, struct btrfs_syno_extent_usage_item, type, 8);
BTRFS_SETGET_FUNCS(syno_extent_usage_inline_ref_type, struct btrfs_syno_extent_usage_inline_ref, type, 8);
BTRFS_SETGET_FUNCS(syno_extent_usage_inline_ref_count, struct btrfs_syno_extent_usage_inline_ref, count, 32);

BTRFS_SETGET_FUNCS(syno_subvol_usage_ref_count, struct btrfs_syno_subvol_usage_item, refs, 32);
BTRFS_SETGET_FUNCS(syno_subvol_usage_num_bytes, struct btrfs_syno_subvol_usage_item, num_bytes, 32);
#endif /* MY_ABC_HERE */

BTRFS_SETGET_FUNCS(ref_root_v0, struct btrfs_extent_ref_v0, root, 64);
BTRFS_SETGET_FUNCS(ref_generation_v0, struct btrfs_extent_ref_v0,
		   generation, 64);
BTRFS_SETGET_FUNCS(ref_objectid_v0, struct btrfs_extent_ref_v0, objectid, 64);
BTRFS_SETGET_FUNCS(ref_count_v0, struct btrfs_extent_ref_v0, count, 32);

/* struct btrfs_node */
BTRFS_SETGET_FUNCS(key_blockptr, struct btrfs_key_ptr, blockptr, 64);
BTRFS_SETGET_FUNCS(key_generation, struct btrfs_key_ptr, generation, 64);
BTRFS_SETGET_STACK_FUNCS(stack_key_blockptr, struct btrfs_key_ptr,
			 blockptr, 64);
BTRFS_SETGET_STACK_FUNCS(stack_key_generation, struct btrfs_key_ptr,
			 generation, 64);

static inline u64 btrfs_node_blockptr(struct extent_buffer *eb, int nr)
{
	unsigned long ptr;
	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	return btrfs_key_blockptr(eb, (struct btrfs_key_ptr *)ptr);
}

static inline void btrfs_set_node_blockptr(struct extent_buffer *eb,
					   int nr, u64 val)
{
	unsigned long ptr;
	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	btrfs_set_key_blockptr(eb, (struct btrfs_key_ptr *)ptr, val);
}

static inline u64 btrfs_node_ptr_generation(struct extent_buffer *eb, int nr)
{
	unsigned long ptr;
	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	return btrfs_key_generation(eb, (struct btrfs_key_ptr *)ptr);
}

static inline void btrfs_set_node_ptr_generation(struct extent_buffer *eb,
						 int nr, u64 val)
{
	unsigned long ptr;
	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	btrfs_set_key_generation(eb, (struct btrfs_key_ptr *)ptr, val);
}

static inline unsigned long btrfs_node_key_ptr_offset(int nr)
{
	return offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
}

void btrfs_node_key(struct extent_buffer *eb,
		    struct btrfs_disk_key *disk_key, int nr);

static inline void btrfs_set_node_key(struct extent_buffer *eb,
				      struct btrfs_disk_key *disk_key, int nr)
{
	unsigned long ptr;
	ptr = btrfs_node_key_ptr_offset(nr);
	write_eb_member(eb, (struct btrfs_key_ptr *)ptr,
		       struct btrfs_key_ptr, key, disk_key);
}

/* struct btrfs_item */
BTRFS_SETGET_FUNCS(item_offset, struct btrfs_item, offset, 32);
BTRFS_SETGET_FUNCS(item_size, struct btrfs_item, size, 32);
BTRFS_SETGET_STACK_FUNCS(stack_item_offset, struct btrfs_item, offset, 32);
BTRFS_SETGET_STACK_FUNCS(stack_item_size, struct btrfs_item, size, 32);

static inline unsigned long btrfs_item_nr_offset(int nr)
{
	return offsetof(struct btrfs_leaf, items) +
		sizeof(struct btrfs_item) * nr;
}

static inline struct btrfs_item *btrfs_item_nr(int nr)
{
	return (struct btrfs_item *)btrfs_item_nr_offset(nr);
}

static inline u32 btrfs_item_end(struct extent_buffer *eb,
				 struct btrfs_item *item)
{
	return btrfs_item_offset(eb, item) + btrfs_item_size(eb, item);
}

static inline u32 btrfs_item_end_nr(struct extent_buffer *eb, int nr)
{
	return btrfs_item_end(eb, btrfs_item_nr(nr));
}

static inline u32 btrfs_item_offset_nr(struct extent_buffer *eb, int nr)
{
	return btrfs_item_offset(eb, btrfs_item_nr(nr));
}

static inline u32 btrfs_item_size_nr(struct extent_buffer *eb, int nr)
{
	return btrfs_item_size(eb, btrfs_item_nr(nr));
}

static inline void btrfs_item_key(struct extent_buffer *eb,
			   struct btrfs_disk_key *disk_key, int nr)
{
	struct btrfs_item *item = btrfs_item_nr(nr);
	read_eb_member(eb, item, struct btrfs_item, key, disk_key);
}

static inline void btrfs_set_item_key(struct extent_buffer *eb,
			       struct btrfs_disk_key *disk_key, int nr)
{
	struct btrfs_item *item = btrfs_item_nr(nr);
	write_eb_member(eb, item, struct btrfs_item, key, disk_key);
}

BTRFS_SETGET_FUNCS(dir_log_end, struct btrfs_dir_log_item, end, 64);

/*
 * struct btrfs_root_ref
 */
BTRFS_SETGET_FUNCS(root_ref_dirid, struct btrfs_root_ref, dirid, 64);
BTRFS_SETGET_FUNCS(root_ref_sequence, struct btrfs_root_ref, sequence, 64);
BTRFS_SETGET_FUNCS(root_ref_name_len, struct btrfs_root_ref, name_len, 16);

/* struct btrfs_dir_item */
BTRFS_SETGET_FUNCS(dir_data_len, struct btrfs_dir_item, data_len, 16);
BTRFS_SETGET_FUNCS(dir_type, struct btrfs_dir_item, type, 8);
BTRFS_SETGET_FUNCS(dir_name_len, struct btrfs_dir_item, name_len, 16);
BTRFS_SETGET_FUNCS(dir_transid, struct btrfs_dir_item, transid, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dir_type, struct btrfs_dir_item, type, 8);
BTRFS_SETGET_STACK_FUNCS(stack_dir_data_len, struct btrfs_dir_item,
			 data_len, 16);
BTRFS_SETGET_STACK_FUNCS(stack_dir_name_len, struct btrfs_dir_item,
			 name_len, 16);
BTRFS_SETGET_STACK_FUNCS(stack_dir_transid, struct btrfs_dir_item,
			 transid, 64);

static inline void btrfs_dir_item_key(struct extent_buffer *eb,
				      struct btrfs_dir_item *item,
				      struct btrfs_disk_key *key)
{
	read_eb_member(eb, item, struct btrfs_dir_item, location, key);
}

static inline void btrfs_set_dir_item_key(struct extent_buffer *eb,
					  struct btrfs_dir_item *item,
					  struct btrfs_disk_key *key)
{
	write_eb_member(eb, item, struct btrfs_dir_item, location, key);
}

BTRFS_SETGET_FUNCS(free_space_entries, struct btrfs_free_space_header,
		   num_entries, 64);
BTRFS_SETGET_FUNCS(free_space_bitmaps, struct btrfs_free_space_header,
		   num_bitmaps, 64);
BTRFS_SETGET_FUNCS(free_space_generation, struct btrfs_free_space_header,
		   generation, 64);

static inline void btrfs_free_space_key(struct extent_buffer *eb,
					struct btrfs_free_space_header *h,
					struct btrfs_disk_key *key)
{
	read_eb_member(eb, h, struct btrfs_free_space_header, location, key);
}

static inline void btrfs_set_free_space_key(struct extent_buffer *eb,
					    struct btrfs_free_space_header *h,
					    struct btrfs_disk_key *key)
{
	write_eb_member(eb, h, struct btrfs_free_space_header, location, key);
}

/* struct btrfs_disk_key */
BTRFS_SETGET_STACK_FUNCS(disk_key_objectid, struct btrfs_disk_key,
			 objectid, 64);
BTRFS_SETGET_STACK_FUNCS(disk_key_offset, struct btrfs_disk_key, offset, 64);
BTRFS_SETGET_STACK_FUNCS(disk_key_type, struct btrfs_disk_key, type, 8);

static inline void btrfs_disk_key_to_cpu(struct btrfs_key *cpu,
					 struct btrfs_disk_key *disk)
{
	cpu->offset = le64_to_cpu(disk->offset);
	cpu->type = disk->type;
	cpu->objectid = le64_to_cpu(disk->objectid);
}

static inline void btrfs_cpu_key_to_disk(struct btrfs_disk_key *disk,
					 struct btrfs_key *cpu)
{
	disk->offset = cpu_to_le64(cpu->offset);
	disk->type = cpu->type;
	disk->objectid = cpu_to_le64(cpu->objectid);
}

static inline void btrfs_node_key_to_cpu(struct extent_buffer *eb,
				  struct btrfs_key *key, int nr)
{
	struct btrfs_disk_key disk_key;
	btrfs_node_key(eb, &disk_key, nr);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

static inline void btrfs_item_key_to_cpu(struct extent_buffer *eb,
				  struct btrfs_key *key, int nr)
{
	struct btrfs_disk_key disk_key;
	btrfs_item_key(eb, &disk_key, nr);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

static inline void btrfs_dir_item_key_to_cpu(struct extent_buffer *eb,
				      struct btrfs_dir_item *item,
				      struct btrfs_key *key)
{
	struct btrfs_disk_key disk_key;
	btrfs_dir_item_key(eb, item, &disk_key);
	btrfs_disk_key_to_cpu(key, &disk_key);
}


static inline u8 btrfs_key_type(struct btrfs_key *key)
{
	return key->type;
}

static inline void btrfs_set_key_type(struct btrfs_key *key, u8 val)
{
	key->type = val;
}

/* struct btrfs_header */
BTRFS_SETGET_HEADER_FUNCS(header_bytenr, struct btrfs_header, bytenr, 64);
BTRFS_SETGET_HEADER_FUNCS(header_generation, struct btrfs_header,
			  generation, 64);
BTRFS_SETGET_HEADER_FUNCS(header_owner, struct btrfs_header, owner, 64);
BTRFS_SETGET_HEADER_FUNCS(header_nritems, struct btrfs_header, nritems, 32);
BTRFS_SETGET_HEADER_FUNCS(header_flags, struct btrfs_header, flags, 64);
BTRFS_SETGET_HEADER_FUNCS(header_level, struct btrfs_header, level, 8);
BTRFS_SETGET_STACK_FUNCS(stack_header_generation, struct btrfs_header,
			 generation, 64);
BTRFS_SETGET_STACK_FUNCS(stack_header_owner, struct btrfs_header, owner, 64);
BTRFS_SETGET_STACK_FUNCS(stack_header_nritems, struct btrfs_header,
			 nritems, 32);
BTRFS_SETGET_STACK_FUNCS(stack_header_bytenr, struct btrfs_header, bytenr, 64);

static inline int btrfs_header_flag(struct extent_buffer *eb, u64 flag)
{
	return (btrfs_header_flags(eb) & flag) == flag;
}

static inline int btrfs_set_header_flag(struct extent_buffer *eb, u64 flag)
{
	u64 flags = btrfs_header_flags(eb);
	btrfs_set_header_flags(eb, flags | flag);
	return (flags & flag) == flag;
}

static inline int btrfs_clear_header_flag(struct extent_buffer *eb, u64 flag)
{
	u64 flags = btrfs_header_flags(eb);
	btrfs_set_header_flags(eb, flags & ~flag);
	return (flags & flag) == flag;
}

static inline int btrfs_header_backref_rev(struct extent_buffer *eb)
{
	u64 flags = btrfs_header_flags(eb);
	return flags >> BTRFS_BACKREF_REV_SHIFT;
}

static inline void btrfs_set_header_backref_rev(struct extent_buffer *eb,
						int rev)
{
	u64 flags = btrfs_header_flags(eb);
	flags &= ~BTRFS_BACKREF_REV_MASK;
	flags |= (u64)rev << BTRFS_BACKREF_REV_SHIFT;
	btrfs_set_header_flags(eb, flags);
}

static inline unsigned long btrfs_header_fsid(void)
{
	return offsetof(struct btrfs_header, fsid);
}

static inline unsigned long btrfs_header_chunk_tree_uuid(struct extent_buffer *eb)
{
	return offsetof(struct btrfs_header, chunk_tree_uuid);
}

static inline int btrfs_is_leaf(struct extent_buffer *eb)
{
	return btrfs_header_level(eb) == 0;
}

/* struct btrfs_root_item */
BTRFS_SETGET_FUNCS(disk_root_generation, struct btrfs_root_item,
		   generation, 64);
BTRFS_SETGET_FUNCS(disk_root_refs, struct btrfs_root_item, refs, 32);
BTRFS_SETGET_FUNCS(disk_root_bytenr, struct btrfs_root_item, bytenr, 64);
BTRFS_SETGET_FUNCS(disk_root_level, struct btrfs_root_item, level, 8);

BTRFS_SETGET_STACK_FUNCS(root_generation, struct btrfs_root_item,
			 generation, 64);
BTRFS_SETGET_STACK_FUNCS(root_bytenr, struct btrfs_root_item, bytenr, 64);
BTRFS_SETGET_STACK_FUNCS(root_level, struct btrfs_root_item, level, 8);
BTRFS_SETGET_STACK_FUNCS(root_dirid, struct btrfs_root_item, root_dirid, 64);
BTRFS_SETGET_STACK_FUNCS(root_refs, struct btrfs_root_item, refs, 32);
BTRFS_SETGET_STACK_FUNCS(root_flags, struct btrfs_root_item, flags, 64);
BTRFS_SETGET_STACK_FUNCS(root_used, struct btrfs_root_item, bytes_used, 64);
BTRFS_SETGET_STACK_FUNCS(root_limit, struct btrfs_root_item, byte_limit, 64);
BTRFS_SETGET_STACK_FUNCS(root_last_snapshot, struct btrfs_root_item,
			 last_snapshot, 64);
BTRFS_SETGET_STACK_FUNCS(root_generation_v2, struct btrfs_root_item,
			 generation_v2, 64);
BTRFS_SETGET_STACK_FUNCS(root_ctransid, struct btrfs_root_item,
			 ctransid, 64);
BTRFS_SETGET_STACK_FUNCS(root_otransid, struct btrfs_root_item,
			 otransid, 64);
BTRFS_SETGET_STACK_FUNCS(root_stransid, struct btrfs_root_item,
			 stransid, 64);
BTRFS_SETGET_STACK_FUNCS(root_rtransid, struct btrfs_root_item,
			 rtransid, 64);

static inline bool btrfs_root_readonly(struct btrfs_root *root)
{
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_RDONLY)) != 0;
}

#ifdef MY_ABC_HERE
static inline bool btrfs_root_disable_quota(const struct btrfs_root *root)
{
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_DISABLE_QUOTA)) != 0;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static inline bool btrfs_root_hide(struct btrfs_root *root)
{
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_HIDE)) != 0;
}
#endif /* MY_ABC_HERE */

static inline bool btrfs_root_dead(struct btrfs_root *root)
{
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_DEAD)) != 0;
}

#ifdef MY_ABC_HERE
static inline bool btrfs_root_noload_usrquota(struct btrfs_root *root)
{
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_NOLOAD_USRQUOTA)) != 0;
}
static inline bool btrfs_usrquota_compat_inode_quota(struct btrfs_fs_info *fs_info)
{
	return fs_info->usrquota_compat_flags & BTRFS_USRQUOTA_COMPAT_FLAG_INODE_QUOTA;
}
#endif

#ifdef MY_ABC_HERE
static inline bool btrfs_root_cmpr_ratio(struct btrfs_root *root)
{
	return (root->root_item.flags & cpu_to_le64(BTRFS_ROOT_SUBVOL_CMPR_RATIO)) != 0;
}
#endif /* MY_ABC_HERE */

/* struct btrfs_root_backup */
BTRFS_SETGET_STACK_FUNCS(backup_tree_root, struct btrfs_root_backup,
		   tree_root, 64);
BTRFS_SETGET_STACK_FUNCS(backup_tree_root_gen, struct btrfs_root_backup,
		   tree_root_gen, 64);
BTRFS_SETGET_STACK_FUNCS(backup_tree_root_level, struct btrfs_root_backup,
		   tree_root_level, 8);

BTRFS_SETGET_STACK_FUNCS(backup_chunk_root, struct btrfs_root_backup,
		   chunk_root, 64);
BTRFS_SETGET_STACK_FUNCS(backup_chunk_root_gen, struct btrfs_root_backup,
		   chunk_root_gen, 64);
BTRFS_SETGET_STACK_FUNCS(backup_chunk_root_level, struct btrfs_root_backup,
		   chunk_root_level, 8);

BTRFS_SETGET_STACK_FUNCS(backup_extent_root, struct btrfs_root_backup,
		   extent_root, 64);
BTRFS_SETGET_STACK_FUNCS(backup_extent_root_gen, struct btrfs_root_backup,
		   extent_root_gen, 64);
BTRFS_SETGET_STACK_FUNCS(backup_extent_root_level, struct btrfs_root_backup,
		   extent_root_level, 8);

BTRFS_SETGET_STACK_FUNCS(backup_fs_root, struct btrfs_root_backup,
		   fs_root, 64);
BTRFS_SETGET_STACK_FUNCS(backup_fs_root_gen, struct btrfs_root_backup,
		   fs_root_gen, 64);
BTRFS_SETGET_STACK_FUNCS(backup_fs_root_level, struct btrfs_root_backup,
		   fs_root_level, 8);

BTRFS_SETGET_STACK_FUNCS(backup_dev_root, struct btrfs_root_backup,
		   dev_root, 64);
BTRFS_SETGET_STACK_FUNCS(backup_dev_root_gen, struct btrfs_root_backup,
		   dev_root_gen, 64);
BTRFS_SETGET_STACK_FUNCS(backup_dev_root_level, struct btrfs_root_backup,
		   dev_root_level, 8);

BTRFS_SETGET_STACK_FUNCS(backup_csum_root, struct btrfs_root_backup,
		   csum_root, 64);
BTRFS_SETGET_STACK_FUNCS(backup_csum_root_gen, struct btrfs_root_backup,
		   csum_root_gen, 64);
BTRFS_SETGET_STACK_FUNCS(backup_csum_root_level, struct btrfs_root_backup,
		   csum_root_level, 8);
BTRFS_SETGET_STACK_FUNCS(backup_total_bytes, struct btrfs_root_backup,
		   total_bytes, 64);
BTRFS_SETGET_STACK_FUNCS(backup_bytes_used, struct btrfs_root_backup,
		   bytes_used, 64);
BTRFS_SETGET_STACK_FUNCS(backup_num_devices, struct btrfs_root_backup,
		   num_devices, 64);

/* struct btrfs_balance_item */
BTRFS_SETGET_FUNCS(balance_flags, struct btrfs_balance_item, flags, 64);

static inline void btrfs_balance_data(struct extent_buffer *eb,
				      struct btrfs_balance_item *bi,
				      struct btrfs_disk_balance_args *ba)
{
	read_eb_member(eb, bi, struct btrfs_balance_item, data, ba);
}

static inline void btrfs_set_balance_data(struct extent_buffer *eb,
					  struct btrfs_balance_item *bi,
					  struct btrfs_disk_balance_args *ba)
{
	write_eb_member(eb, bi, struct btrfs_balance_item, data, ba);
}

static inline void btrfs_balance_meta(struct extent_buffer *eb,
				      struct btrfs_balance_item *bi,
				      struct btrfs_disk_balance_args *ba)
{
	read_eb_member(eb, bi, struct btrfs_balance_item, meta, ba);
}

static inline void btrfs_set_balance_meta(struct extent_buffer *eb,
					  struct btrfs_balance_item *bi,
					  struct btrfs_disk_balance_args *ba)
{
	write_eb_member(eb, bi, struct btrfs_balance_item, meta, ba);
}

static inline void btrfs_balance_sys(struct extent_buffer *eb,
				     struct btrfs_balance_item *bi,
				     struct btrfs_disk_balance_args *ba)
{
	read_eb_member(eb, bi, struct btrfs_balance_item, sys, ba);
}

static inline void btrfs_set_balance_sys(struct extent_buffer *eb,
					 struct btrfs_balance_item *bi,
					 struct btrfs_disk_balance_args *ba)
{
	write_eb_member(eb, bi, struct btrfs_balance_item, sys, ba);
}

static inline void
btrfs_disk_balance_args_to_cpu(struct btrfs_balance_args *cpu,
			       struct btrfs_disk_balance_args *disk)
{
	memset(cpu, 0, sizeof(*cpu));

	cpu->profiles = le64_to_cpu(disk->profiles);
	cpu->usage = le64_to_cpu(disk->usage);
	cpu->devid = le64_to_cpu(disk->devid);
	cpu->pstart = le64_to_cpu(disk->pstart);
	cpu->pend = le64_to_cpu(disk->pend);
	cpu->vstart = le64_to_cpu(disk->vstart);
	cpu->vend = le64_to_cpu(disk->vend);
	cpu->target = le64_to_cpu(disk->target);
	cpu->flags = le64_to_cpu(disk->flags);
	cpu->limit = le64_to_cpu(disk->limit);
}

static inline void
btrfs_cpu_balance_args_to_disk(struct btrfs_disk_balance_args *disk,
			       struct btrfs_balance_args *cpu)
{
	memset(disk, 0, sizeof(*disk));

	disk->profiles = cpu_to_le64(cpu->profiles);
	disk->usage = cpu_to_le64(cpu->usage);
	disk->devid = cpu_to_le64(cpu->devid);
	disk->pstart = cpu_to_le64(cpu->pstart);
	disk->pend = cpu_to_le64(cpu->pend);
	disk->vstart = cpu_to_le64(cpu->vstart);
	disk->vend = cpu_to_le64(cpu->vend);
	disk->target = cpu_to_le64(cpu->target);
	disk->flags = cpu_to_le64(cpu->flags);
	disk->limit = cpu_to_le64(cpu->limit);
}

/* struct btrfs_super_block */
BTRFS_SETGET_STACK_FUNCS(super_bytenr, struct btrfs_super_block, bytenr, 64);
BTRFS_SETGET_STACK_FUNCS(super_flags, struct btrfs_super_block, flags, 64);
BTRFS_SETGET_STACK_FUNCS(super_generation, struct btrfs_super_block,
			 generation, 64);
#ifdef MY_ABC_HERE
BTRFS_SETGET_STACK_FUNCS(super_syno_generation, struct btrfs_super_block,
			 syno_generation, 64);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
BTRFS_SETGET_STACK_FUNCS(super_syno_log_tree_rsv, struct btrfs_super_block,
			 log_tree_rsv, 64);
#endif /* MY_ABC_HERE */
BTRFS_SETGET_STACK_FUNCS(super_root, struct btrfs_super_block, root, 64);
BTRFS_SETGET_STACK_FUNCS(super_sys_array_size,
			 struct btrfs_super_block, sys_chunk_array_size, 32);
BTRFS_SETGET_STACK_FUNCS(super_chunk_root_generation,
			 struct btrfs_super_block, chunk_root_generation, 64);
BTRFS_SETGET_STACK_FUNCS(super_root_level, struct btrfs_super_block,
			 root_level, 8);
BTRFS_SETGET_STACK_FUNCS(super_chunk_root, struct btrfs_super_block,
			 chunk_root, 64);
BTRFS_SETGET_STACK_FUNCS(super_chunk_root_level, struct btrfs_super_block,
			 chunk_root_level, 8);
BTRFS_SETGET_STACK_FUNCS(super_log_root, struct btrfs_super_block,
			 log_root, 64);
BTRFS_SETGET_STACK_FUNCS(super_log_root_transid, struct btrfs_super_block,
			 log_root_transid, 64);
BTRFS_SETGET_STACK_FUNCS(super_log_root_level, struct btrfs_super_block,
			 log_root_level, 8);
BTRFS_SETGET_STACK_FUNCS(super_total_bytes, struct btrfs_super_block,
			 total_bytes, 64);
BTRFS_SETGET_STACK_FUNCS(super_bytes_used, struct btrfs_super_block,
			 bytes_used, 64);
BTRFS_SETGET_STACK_FUNCS(super_sectorsize, struct btrfs_super_block,
			 sectorsize, 32);
BTRFS_SETGET_STACK_FUNCS(super_nodesize, struct btrfs_super_block,
			 nodesize, 32);
BTRFS_SETGET_STACK_FUNCS(super_leafsize, struct btrfs_super_block,
			 leafsize, 32);
BTRFS_SETGET_STACK_FUNCS(super_stripesize, struct btrfs_super_block,
			 stripesize, 32);
BTRFS_SETGET_STACK_FUNCS(super_root_dir, struct btrfs_super_block,
			 root_dir_objectid, 64);
BTRFS_SETGET_STACK_FUNCS(super_num_devices, struct btrfs_super_block,
			 num_devices, 64);
BTRFS_SETGET_STACK_FUNCS(super_compat_flags, struct btrfs_super_block,
			 compat_flags, 64);
BTRFS_SETGET_STACK_FUNCS(super_compat_ro_flags, struct btrfs_super_block,
			 compat_ro_flags, 64);
BTRFS_SETGET_STACK_FUNCS(super_incompat_flags, struct btrfs_super_block,
			 incompat_flags, 64);
BTRFS_SETGET_STACK_FUNCS(super_csum_type, struct btrfs_super_block,
			 csum_type, 16);
BTRFS_SETGET_STACK_FUNCS(super_cache_generation, struct btrfs_super_block,
			 cache_generation, 64);
BTRFS_SETGET_STACK_FUNCS(super_magic, struct btrfs_super_block, magic, 64);
BTRFS_SETGET_STACK_FUNCS(super_uuid_tree_generation, struct btrfs_super_block,
			 uuid_tree_generation, 64);

static inline int btrfs_super_csum_size(struct btrfs_super_block *s)
{
	u16 t = btrfs_super_csum_type(s);
	/*
	 * csum type is validated at mount time
	 */
	return btrfs_csum_sizes[t];
}

static inline unsigned long btrfs_leaf_data(struct extent_buffer *l)
{
	return offsetof(struct btrfs_leaf, items);
}

/*
 * The leaf data grows from end-to-front in the node.
 * this returns the address of the start of the last item,
 * which is the stop of the leaf data stack
 */
static inline unsigned int leaf_data_end(struct btrfs_root *root,
					 struct extent_buffer *leaf)
{
	u32 nr = btrfs_header_nritems(leaf);

	if (nr == 0)
		return BTRFS_LEAF_DATA_SIZE(root);
	return btrfs_item_offset_nr(leaf, nr - 1);
}

/* struct btrfs_file_extent_item */
BTRFS_SETGET_FUNCS(file_extent_type, struct btrfs_file_extent_item, type, 8);
BTRFS_SETGET_STACK_FUNCS(stack_file_extent_disk_bytenr,
			 struct btrfs_file_extent_item, disk_bytenr, 64);
BTRFS_SETGET_STACK_FUNCS(stack_file_extent_offset,
			 struct btrfs_file_extent_item, offset, 64);
BTRFS_SETGET_STACK_FUNCS(stack_file_extent_generation,
			 struct btrfs_file_extent_item, generation, 64);
BTRFS_SETGET_STACK_FUNCS(stack_file_extent_num_bytes,
			 struct btrfs_file_extent_item, num_bytes, 64);
BTRFS_SETGET_STACK_FUNCS(stack_file_extent_disk_num_bytes,
			 struct btrfs_file_extent_item, disk_num_bytes, 64);
BTRFS_SETGET_STACK_FUNCS(stack_file_extent_compression,
			 struct btrfs_file_extent_item, compression, 8);

static inline unsigned long
btrfs_file_extent_inline_start(struct btrfs_file_extent_item *e)
{
	unsigned long offset = (unsigned long)e;
	offset += offsetof(struct btrfs_file_extent_item, disk_bytenr);
	return offset;
}

static inline u32 btrfs_file_extent_calc_inline_size(u32 datasize)
{
	return offsetof(struct btrfs_file_extent_item, disk_bytenr) + datasize;
}

BTRFS_SETGET_FUNCS(file_extent_disk_bytenr, struct btrfs_file_extent_item,
		   disk_bytenr, 64);
BTRFS_SETGET_FUNCS(file_extent_generation, struct btrfs_file_extent_item,
		   generation, 64);
BTRFS_SETGET_FUNCS(file_extent_disk_num_bytes, struct btrfs_file_extent_item,
		   disk_num_bytes, 64);
BTRFS_SETGET_FUNCS(file_extent_offset, struct btrfs_file_extent_item,
		  offset, 64);
BTRFS_SETGET_FUNCS(file_extent_num_bytes, struct btrfs_file_extent_item,
		   num_bytes, 64);
BTRFS_SETGET_FUNCS(file_extent_ram_bytes, struct btrfs_file_extent_item,
		   ram_bytes, 64);
BTRFS_SETGET_FUNCS(file_extent_compression, struct btrfs_file_extent_item,
		   compression, 8);
BTRFS_SETGET_FUNCS(file_extent_encryption, struct btrfs_file_extent_item,
		   encryption, 8);
BTRFS_SETGET_FUNCS(file_extent_other_encoding, struct btrfs_file_extent_item,
		   other_encoding, 16);

/*
 * this returns the number of bytes used by the item on disk, minus the
 * size of any extent headers.  If a file is compressed on disk, this is
 * the compressed size
 */
static inline u32 btrfs_file_extent_inline_item_len(struct extent_buffer *eb,
						    struct btrfs_item *e)
{
	unsigned long offset;
	offset = offsetof(struct btrfs_file_extent_item, disk_bytenr);
	return btrfs_item_size(eb, e) - offset;
}

/* this returns the number of file bytes represented by the inline item.
 * If an item is compressed, this is the uncompressed size
 */
static inline u32 btrfs_file_extent_inline_len(struct extent_buffer *eb,
					       int slot,
					       struct btrfs_file_extent_item *fi)
{
	struct btrfs_map_token token;

	btrfs_init_map_token(&token);
	/*
	 * return the space used on disk if this item isn't
	 * compressed or encoded
	 */
	if (btrfs_token_file_extent_compression(eb, fi, &token) == 0 &&
	    btrfs_token_file_extent_encryption(eb, fi, &token) == 0 &&
	    btrfs_token_file_extent_other_encoding(eb, fi, &token) == 0) {
		return btrfs_file_extent_inline_item_len(eb,
							 btrfs_item_nr(slot));
	}

	/* otherwise use the ram bytes field */
	return btrfs_token_file_extent_ram_bytes(eb, fi, &token);
}


/* btrfs_dev_stats_item */
static inline u64 btrfs_dev_stats_value(struct extent_buffer *eb,
					struct btrfs_dev_stats_item *ptr,
					int index)
{
	u64 val;

	read_extent_buffer(eb, &val,
			   offsetof(struct btrfs_dev_stats_item, values) +
			    ((unsigned long)ptr) + (index * sizeof(u64)),
			   sizeof(val));
	return val;
}

static inline void btrfs_set_dev_stats_value(struct extent_buffer *eb,
					     struct btrfs_dev_stats_item *ptr,
					     int index, u64 val)
{
	write_extent_buffer(eb, &val,
			    offsetof(struct btrfs_dev_stats_item, values) +
			     ((unsigned long)ptr) + (index * sizeof(u64)),
			    sizeof(val));
}

/* btrfs_qgroup_status_item */
BTRFS_SETGET_FUNCS(qgroup_status_generation, struct btrfs_qgroup_status_item,
		   generation, 64);
BTRFS_SETGET_FUNCS(qgroup_status_version, struct btrfs_qgroup_status_item,
		   version, 64);
BTRFS_SETGET_FUNCS(qgroup_status_flags, struct btrfs_qgroup_status_item,
		   flags, 64);
BTRFS_SETGET_FUNCS(qgroup_status_rescan, struct btrfs_qgroup_status_item,
		   rescan, 64);

/* btrfs_qgroup_info_item */
BTRFS_SETGET_FUNCS(qgroup_info_generation, struct btrfs_qgroup_info_item,
		   generation, 64);
BTRFS_SETGET_FUNCS(qgroup_info_rfer, struct btrfs_qgroup_info_item, rfer, 64);
BTRFS_SETGET_FUNCS(qgroup_info_rfer_cmpr, struct btrfs_qgroup_info_item,
		   rfer_cmpr, 64);
BTRFS_SETGET_FUNCS(qgroup_info_excl, struct btrfs_qgroup_info_item, excl, 64);
BTRFS_SETGET_FUNCS(qgroup_info_excl_cmpr, struct btrfs_qgroup_info_item,
		   excl_cmpr, 64);

BTRFS_SETGET_STACK_FUNCS(stack_qgroup_info_generation,
			 struct btrfs_qgroup_info_item, generation, 64);
BTRFS_SETGET_STACK_FUNCS(stack_qgroup_info_rfer, struct btrfs_qgroup_info_item,
			 rfer, 64);
BTRFS_SETGET_STACK_FUNCS(stack_qgroup_info_rfer_cmpr,
			 struct btrfs_qgroup_info_item, rfer_cmpr, 64);
BTRFS_SETGET_STACK_FUNCS(stack_qgroup_info_excl, struct btrfs_qgroup_info_item,
			 excl, 64);
BTRFS_SETGET_STACK_FUNCS(stack_qgroup_info_excl_cmpr,
			 struct btrfs_qgroup_info_item, excl_cmpr, 64);

/* btrfs_qgroup_limit_item */
BTRFS_SETGET_FUNCS(qgroup_limit_flags, struct btrfs_qgroup_limit_item,
		   flags, 64);
BTRFS_SETGET_FUNCS(qgroup_limit_max_rfer, struct btrfs_qgroup_limit_item,
		   max_rfer, 64);
BTRFS_SETGET_FUNCS(qgroup_limit_max_excl, struct btrfs_qgroup_limit_item,
		   max_excl, 64);
BTRFS_SETGET_FUNCS(qgroup_limit_rsv_rfer, struct btrfs_qgroup_limit_item,
		   rsv_rfer, 64);
BTRFS_SETGET_FUNCS(qgroup_limit_rsv_excl, struct btrfs_qgroup_limit_item,
		   rsv_excl, 64);

#ifdef MY_ABC_HERE
/* btrfs_usrquota_status_item */
BTRFS_SETGET_FUNCS(usrquota_status_version, struct btrfs_usrquota_status_item, version, 64);
BTRFS_SETGET_FUNCS(usrquota_status_generation, struct btrfs_usrquota_status_item, generation, 64);
BTRFS_SETGET_FUNCS(usrquota_status_flags, struct btrfs_usrquota_status_item, flags, 64);
BTRFS_SETGET_FUNCS(usrquota_status_rescan_rootid, struct btrfs_usrquota_status_item, rescan_rootid, 64);
BTRFS_SETGET_FUNCS(usrquota_status_rescan_objectid, struct btrfs_usrquota_status_item, rescan_objectid, 64);
/* btrfs_usrquota_compat_item */
BTRFS_SETGET_FUNCS(usrquota_compat_generation, struct btrfs_usrquota_compat_item, generation, 64);
BTRFS_SETGET_FUNCS(usrquota_compat_flags, struct btrfs_usrquota_compat_item, flags, 64);
/* btrfs_usrquota_root_item */
BTRFS_SETGET_FUNCS(usrquota_root_info_item_cnt, struct btrfs_usrquota_root_item, info_item_cnt, 64);
BTRFS_SETGET_FUNCS(usrquota_root_limit_item_cnt, struct btrfs_usrquota_root_item, limit_item_cnt, 64);
/* btrfs_usrquota_info_item */
BTRFS_SETGET_FUNCS(usrquota_info_generation, struct btrfs_usrquota_info_item, generation, 64);
BTRFS_SETGET_FUNCS(usrquota_info_rfer_used, struct btrfs_usrquota_info_item, rfer_used, 64);
/* btrfs_usrquota_limit_item */
BTRFS_SETGET_FUNCS(usrquota_limit_rfer_soft, struct btrfs_usrquota_limit_item, rfer_soft, 64);
BTRFS_SETGET_FUNCS(usrquota_limit_rfer_hard, struct btrfs_usrquota_limit_item, rfer_hard, 64);
#endif /* MY_ABC_HERE */

/* btrfs_dev_replace_item */
BTRFS_SETGET_FUNCS(dev_replace_src_devid,
		   struct btrfs_dev_replace_item, src_devid, 64);
BTRFS_SETGET_FUNCS(dev_replace_cont_reading_from_srcdev_mode,
		   struct btrfs_dev_replace_item, cont_reading_from_srcdev_mode,
		   64);
BTRFS_SETGET_FUNCS(dev_replace_replace_state, struct btrfs_dev_replace_item,
		   replace_state, 64);
BTRFS_SETGET_FUNCS(dev_replace_time_started, struct btrfs_dev_replace_item,
		   time_started, 64);
BTRFS_SETGET_FUNCS(dev_replace_time_stopped, struct btrfs_dev_replace_item,
		   time_stopped, 64);
BTRFS_SETGET_FUNCS(dev_replace_num_write_errors, struct btrfs_dev_replace_item,
		   num_write_errors, 64);
BTRFS_SETGET_FUNCS(dev_replace_num_uncorrectable_read_errors,
		   struct btrfs_dev_replace_item, num_uncorrectable_read_errors,
		   64);
BTRFS_SETGET_FUNCS(dev_replace_cursor_left, struct btrfs_dev_replace_item,
		   cursor_left, 64);
BTRFS_SETGET_FUNCS(dev_replace_cursor_right, struct btrfs_dev_replace_item,
		   cursor_right, 64);

BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_src_devid,
			 struct btrfs_dev_replace_item, src_devid, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_cont_reading_from_srcdev_mode,
			 struct btrfs_dev_replace_item,
			 cont_reading_from_srcdev_mode, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_replace_state,
			 struct btrfs_dev_replace_item, replace_state, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_time_started,
			 struct btrfs_dev_replace_item, time_started, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_time_stopped,
			 struct btrfs_dev_replace_item, time_stopped, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_num_write_errors,
			 struct btrfs_dev_replace_item, num_write_errors, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_num_uncorrectable_read_errors,
			 struct btrfs_dev_replace_item,
			 num_uncorrectable_read_errors, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_cursor_left,
			 struct btrfs_dev_replace_item, cursor_left, 64);
BTRFS_SETGET_STACK_FUNCS(stack_dev_replace_cursor_right,
			 struct btrfs_dev_replace_item, cursor_right, 64);

static inline struct btrfs_fs_info *btrfs_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline u32 btrfs_level_size(struct btrfs_root *root, int level)
{
	if (level == 0)
		return root->leafsize;
	return root->nodesize;
}

/* helper function to cast into the data area of the leaf. */
#define btrfs_item_ptr(leaf, slot, type) \
	((type *)(btrfs_leaf_data(leaf) + \
	btrfs_item_offset_nr(leaf, slot)))

#define btrfs_item_ptr_offset(leaf, slot) \
	((unsigned long)(btrfs_leaf_data(leaf) + \
	btrfs_item_offset_nr(leaf, slot)))

static inline bool btrfs_mixed_space_info(struct btrfs_space_info *space_info)
{
	return ((space_info->flags & BTRFS_BLOCK_GROUP_METADATA) &&
		(space_info->flags & BTRFS_BLOCK_GROUP_DATA));
}

static inline gfp_t btrfs_alloc_write_mask(struct address_space *mapping)
{
	return mapping_gfp_mask(mapping) & ~__GFP_FS;
}

/* extent-tree.c */

u64 btrfs_csum_bytes_to_leaves(struct btrfs_root *root, u64 csum_bytes);

static inline u64 btrfs_calc_trans_metadata_size(struct btrfs_root *root,
						 unsigned num_items)
{
	return ((u64)root->leafsize + root->nodesize * (BTRFS_MAX_LEVEL - 1)) *
		2 * num_items;
}

/*
 * Doing a truncate won't result in new nodes or leaves, just what we need for
 * COW.
 */
static inline u64 btrfs_calc_trunc_metadata_size(struct btrfs_root *root,
						 unsigned num_items)
{
	return ((u64)root->leafsize + root->nodesize * (BTRFS_MAX_LEVEL - 1)) *
		num_items;
}

int btrfs_should_throttle_delayed_refs(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root);
int btrfs_check_space_for_delayed_refs(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root
#ifdef MY_ABC_HERE
				       , bool throttle
#endif /* MY_ABC_HERE */
				       );
void btrfs_put_block_group(struct btrfs_block_group_cache *cache);
#ifdef MY_ABC_HERE
int btrfs_run_delayed_refs_and_get_processed(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, unsigned long count,
			   unsigned long *processed_count);
static inline int btrfs_run_delayed_refs(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, unsigned long count)
{
	return btrfs_run_delayed_refs_and_get_processed(trans, root, count, NULL);
}
#else /* MY_ABC_HERE */
int btrfs_run_delayed_refs(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, unsigned long count);
#endif /* MY_ABC_HERE */
int btrfs_async_run_delayed_refs(struct btrfs_root *root,
				 unsigned long count, int wait);
int btrfs_lookup_data_extent(struct btrfs_root *root, u64 start, u64 len);
int btrfs_lookup_extent_info(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root, u64 bytenr,
			     u64 offset, int metadata, u64 *refs, u64 *flags);
int btrfs_pin_extent(struct btrfs_root *root,
		     u64 bytenr, u64 num, int reserved);
int btrfs_pin_extent_for_log_replay(struct btrfs_root *root,
				    u64 bytenr, u64 num_bytes);
int btrfs_exclude_logged_extents(struct btrfs_root *root,
				 struct extent_buffer *eb);
#ifdef MY_ABC_HERE
int btrfs_cross_ref_exist(struct btrfs_root *root,
			  u64 objectid, u64 offset, u64 bytenr, u64 mode);
#else
int btrfs_cross_ref_exist(struct btrfs_root *root,
			  u64 objectid, u64 offset, u64 bytenr);
#endif /* MY_ABC_HERE */
struct btrfs_block_group_cache *btrfs_lookup_block_group(
						 struct btrfs_fs_info *info,
						 u64 bytenr);
#ifdef MY_ABC_HERE
struct btrfs_block_group_cache *btrfs_lookup_first_block_group(struct btrfs_fs_info *info, u64 bytenr);
struct btrfs_block_group_cache *next_block_group(struct btrfs_root *root, struct btrfs_block_group_cache *cache);
#endif /* MY_ABC_HERE */
void btrfs_put_block_group(struct btrfs_block_group_cache *cache);
int get_block_group_index(struct btrfs_block_group_cache *cache);
struct extent_buffer *btrfs_alloc_tree_block(struct btrfs_trans_handle *trans,
					struct btrfs_root *root, u64 parent,
					u64 root_objectid,
					struct btrfs_disk_key *key, int level,
					u64 hint, u64 empty_size);
void btrfs_free_tree_block(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct extent_buffer *buf,
			   u64 parent, int last_ref);
int btrfs_alloc_reserved_file_extent(struct btrfs_trans_handle *trans,
				     struct btrfs_root *root,
				     u64 root_objectid, u64 owner, u64 offset,
				     struct btrfs_key *ins
#ifdef MY_ABC_HERE
				     ,u64 ram_bytes
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
				     ,struct inode *inode, uid_t uid
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
				     ,int syno_usage
#endif /* MY_ABC_HERE */
				     );
int btrfs_alloc_logged_file_extent(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   u64 root_objectid, u64 owner, u64 offset,
#ifdef MY_ABC_HERE
				   struct btrfs_key *ins, struct inode *inode, uid_t uid);
#else
				   struct btrfs_key *ins);
#endif
int btrfs_reserve_extent(struct btrfs_root *root, u64 num_bytes,
			 u64 min_alloc_size, u64 empty_size, u64 hint_byte,
			 struct btrfs_key *ins, int is_data, int delalloc);
int btrfs_inc_ref(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		  struct extent_buffer *buf, int full_backref);
int btrfs_dec_ref(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		  struct extent_buffer *buf, int full_backref);
int btrfs_set_disk_extent_flags(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				u64 bytenr, u64 num_bytes, u64 flags,
				int level, int is_data);
int btrfs_free_extent(struct btrfs_trans_handle *trans,
		      struct btrfs_root *root,
		      u64 bytenr, u64 num_bytes, u64 parent, u64 root_objectid,
		      u64 owner, u64 offset, int no_quota
#ifdef MY_ABC_HERE
		      ,u64 ram_bytes
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		      ,int syno_usage
#endif /* MY_ABC_HERE */
		      );
#ifdef MY_ABC_HERE
int btrfs_free_extent_uid(struct btrfs_trans_handle *trans, struct btrfs_root *root,
			  u64 bytenr, u64 num_bytes, u64 parent, u64 root_objectid,
			  u64 owner, u64 offset, int for_cow, u64 ram_bytes,
			  struct inode *inode, uid_t uid
#ifdef MY_ABC_HERE
			  ,int syno_usage
#endif /* MY_ABC_HERE */
			  );
#endif /* MY_ABC_HERE */

int btrfs_free_reserved_extent(struct btrfs_root *root, u64 start, u64 len,
			       int delalloc);
int btrfs_free_and_pin_reserved_extent(struct btrfs_root *root,
				       u64 start, u64 len);
void btrfs_prepare_extent_commit(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root);
int btrfs_finish_extent_commit(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root);
int btrfs_inc_extent_ref(struct btrfs_trans_handle *trans,
			 struct btrfs_root *root,
			 u64 bytenr, u64 num_bytes, u64 parent,
			 u64 root_objectid, u64 owner, u64 offset,
			 int no_quota
#ifdef MY_ABC_HERE
			 ,u64 ram_bytes
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			 ,int syno_usage
#endif /* MY_ABC_HERE */
			 );
#ifdef MY_ABC_HERE
int btrfs_inc_extent_ref_uid(struct btrfs_trans_handle *trans,
			 struct btrfs_root *root,
			 u64 bytenr, u64 num_bytes, u64 parent,
			 u64 root_objectid, u64 owner, u64 offset,
			 int no_quota, u64 ram_bytes,
			 struct inode *inode, uid_t uid
#ifdef MY_ABC_HERE
			 ,int syno_usage
#endif /* MY_ABC_HERE */
			 );
#endif /* MY_ABC_HERE */

int btrfs_start_dirty_block_groups(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root);
int btrfs_write_dirty_block_groups(struct btrfs_trans_handle *trans,
				    struct btrfs_root *root);
int btrfs_setup_space_cache(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root);
int btrfs_extent_readonly(struct btrfs_root *root, u64 bytenr);
int btrfs_free_block_groups(struct btrfs_fs_info *info);
#ifdef MY_ABC_HERE
int btrfs_clean_block_group_cache_tree(struct btrfs_fs_info *fs_info);
int btrfs_create_block_group_cache_tree(struct btrfs_fs_info *fs_info);
int btrfs_check_syno_block_group_cache_tree(struct btrfs_fs_info *fs_info);
static inline int btrfs_syno_block_group_cache_tree_enabled(struct btrfs_root *root) {
	if (!root || root->fs_info->block_group_cache_tree_broken) {
		return 0;
	}
	return 1;
}
int btrfs_clean_tree_by_root(struct btrfs_trans_handle *trans, struct btrfs_root *root);
#endif /* MY_ABC_HERE */
int btrfs_read_block_groups(struct btrfs_root *root);
int btrfs_can_relocate(struct btrfs_root *root, u64 bytenr);
int btrfs_make_block_group(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root, u64 bytes_used,
			   u64 type, u64 chunk_objectid, u64 chunk_offset,
			   u64 size);
struct btrfs_trans_handle *btrfs_start_trans_remove_block_group(
				struct btrfs_fs_info *fs_info,
				const u64 chunk_offset);
int btrfs_remove_block_group(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root, u64 group_start,
			     struct extent_map *em);
void btrfs_delete_unused_bgs(struct btrfs_fs_info *fs_info);
void btrfs_create_pending_block_groups(struct btrfs_trans_handle *trans,
				       struct btrfs_root *root);
u64 btrfs_get_alloc_profile(struct btrfs_root *root, int data);
void btrfs_clear_space_info_full(struct btrfs_fs_info *info);

enum btrfs_reserve_flush_enum {
	/* If we are in the transaction, we can't flush anything.*/
	BTRFS_RESERVE_NO_FLUSH,
	/*
	 * Flushing delalloc may cause deadlock somewhere, in this
	 * case, use FLUSH LIMIT
	 */
	BTRFS_RESERVE_FLUSH_LIMIT,
	BTRFS_RESERVE_FLUSH_ALL,
};

int btrfs_check_data_free_space(struct inode *inode, u64 bytes);
void btrfs_free_reserved_data_space(struct inode *inode, u64 bytes);
void btrfs_trans_release_metadata(struct btrfs_trans_handle *trans,
				struct btrfs_root *root);
void btrfs_trans_release_chunk_metadata(struct btrfs_trans_handle *trans);
int btrfs_subvolume_reserve_metadata(struct btrfs_root *root,
				     struct btrfs_block_rsv *rsv,
				     int nitems,
				     u64 *qgroup_reserved, bool use_global_rsv);
void btrfs_subvolume_release_metadata(struct btrfs_root *root,
				      struct btrfs_block_rsv *rsv,
				      u64 qgroup_reserved);
int btrfs_delalloc_reserve_metadata(struct inode *inode, u64 num_bytes);
void btrfs_delalloc_release_metadata(struct inode *inode, u64 num_bytes);
#ifdef MY_ABC_HERE
void btrfs_delalloc_release_metadata_add_delay(struct inode *inode, u64 num_bytes);
#endif
int btrfs_delalloc_reserve_space(struct inode *inode, u64 num_bytes);
void btrfs_delalloc_release_space(struct inode *inode, u64 num_bytes);
void btrfs_init_block_rsv(struct btrfs_block_rsv *rsv, unsigned short type);
struct btrfs_block_rsv *btrfs_alloc_block_rsv(struct btrfs_root *root,
					      unsigned short type);
void btrfs_free_block_rsv(struct btrfs_root *root,
			  struct btrfs_block_rsv *rsv);
void __btrfs_free_block_rsv(struct btrfs_block_rsv *rsv);
int btrfs_block_rsv_add(struct btrfs_root *root,
			struct btrfs_block_rsv *block_rsv, u64 num_bytes,
			enum btrfs_reserve_flush_enum flush);
int btrfs_block_rsv_check(struct btrfs_root *root,
			  struct btrfs_block_rsv *block_rsv, int min_factor);
int btrfs_block_rsv_refill(struct btrfs_root *root,
			   struct btrfs_block_rsv *block_rsv, u64 min_reserved,
			   enum btrfs_reserve_flush_enum flush);
int btrfs_block_rsv_migrate(struct btrfs_block_rsv *src_rsv,
			    struct btrfs_block_rsv *dst_rsv,
			    u64 num_bytes);
int btrfs_cond_migrate_bytes(struct btrfs_fs_info *fs_info,
			     struct btrfs_block_rsv *dest, u64 num_bytes,
			     int min_factor);
void btrfs_block_rsv_release(struct btrfs_root *root,
			     struct btrfs_block_rsv *block_rsv,
			     u64 num_bytes);
int btrfs_set_block_group_ro(struct btrfs_root *root,
			     struct btrfs_block_group_cache *cache);
void btrfs_set_block_group_rw(struct btrfs_root *root,
			      struct btrfs_block_group_cache *cache);
void btrfs_put_block_group_cache(struct btrfs_fs_info *info);
u64 btrfs_account_ro_block_groups_free_space(struct btrfs_space_info *sinfo);
int btrfs_error_unpin_extent_range(struct btrfs_root *root,
				   u64 start, u64 end);
#ifdef MY_ABC_HERE
int btrfs_discard_extent(struct btrfs_root *root, u64 bytenr,
			 u64 num_bytes, u64 *actual_bytes, enum trim_act act);
#else /* MY_ABC_HERE */
int btrfs_discard_extent(struct btrfs_root *root, u64 bytenr,
			 u64 num_bytes, u64 *actual_bytes);
#endif /* MY_ABC_HERE */
int btrfs_force_chunk_alloc(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root, u64 type);
#ifdef MY_ABC_HERE
int btrfs_trim_fs(struct btrfs_root *root, struct fstrim_range *range,
				  enum trim_act act);
#else /* MY_ABC_HERE */
int btrfs_trim_fs(struct btrfs_root *root, struct fstrim_range *range);
#endif /* MY_ABC_HERE */

int btrfs_init_space_info(struct btrfs_fs_info *fs_info);
int btrfs_delayed_refs_qgroup_accounting(struct btrfs_trans_handle *trans,
					 struct btrfs_fs_info *fs_info);
int __get_raid_index(u64 flags);
int btrfs_start_write_no_snapshoting(struct btrfs_root *root);
void btrfs_end_write_no_snapshoting(struct btrfs_root *root);
#ifdef MY_ABC_HERE
int btrfs_reserve_log_tree_bg(struct btrfs_root *root,
			  u64 *rsv_start, u64 *rsv_size);
#endif /* MY_ABC_HERE */
void check_system_chunk(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			const u64 type,
			const bool is_allocation);
u64 add_new_free_space(struct btrfs_block_group_cache *block_group,
		       struct btrfs_fs_info *info, u64 start, u64 end);
#ifdef MY_ABC_HERE
void btrfs_init_syno_allocator_bg_prefetch_work(struct work_struct *work);
#endif /* MY_ABC_HERE */

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
void syno_perf_indicator_dirty_limit_update(struct btrfs_fs_info *fs_info);
#endif /* defined(MY_ABC_HERE) || defined(MY_ABC_HERE) */

#ifdef MY_ABC_HERE
u64 get_bg_offset_with_free_space_bytes(struct btrfs_fs_info *fs_info);
#endif /* MY_ABC_HERE */

/* ctree.c */
int btrfs_bin_search(struct extent_buffer *eb, struct btrfs_key *key,
		     int level, int *slot);
int btrfs_comp_cpu_keys(struct btrfs_key *k1, struct btrfs_key *k2);
int btrfs_previous_item(struct btrfs_root *root,
			struct btrfs_path *path, u64 min_objectid,
			int type);
int btrfs_previous_extent_item(struct btrfs_root *root,
			struct btrfs_path *path, u64 min_objectid);
void btrfs_set_item_key_safe(struct btrfs_root *root, struct btrfs_path *path,
			     struct btrfs_key *new_key);
struct extent_buffer *btrfs_root_node(struct btrfs_root *root);
struct extent_buffer *btrfs_lock_root_node(struct btrfs_root *root);
int btrfs_find_next_key(struct btrfs_root *root, struct btrfs_path *path,
			struct btrfs_key *key, int lowest_level,
			u64 min_trans);
int btrfs_search_forward(struct btrfs_root *root, struct btrfs_key *min_key,
			 struct btrfs_path *path,
			 u64 min_trans);
enum btrfs_compare_tree_result {
	BTRFS_COMPARE_TREE_NEW,
	BTRFS_COMPARE_TREE_DELETED,
	BTRFS_COMPARE_TREE_CHANGED,
	BTRFS_COMPARE_TREE_SAME,
};
typedef int (*btrfs_changed_cb_t)(struct btrfs_root *left_root,
				  struct btrfs_root *right_root,
				  struct btrfs_path *left_path,
				  struct btrfs_path *right_path,
				  struct btrfs_key *key,
				  enum btrfs_compare_tree_result result,
				  void *ctx);
int btrfs_compare_trees(struct btrfs_root *left_root,
			struct btrfs_root *right_root,
			btrfs_changed_cb_t cb, void *ctx);
#ifdef MY_ABC_HERE
int syno_send_skip_clone(struct btrfs_root *root, u64 ino);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
int btrfs_snapshot_size_query(struct file *file,
				  struct btrfs_ioctl_snapshot_size_query_args *snap_args,
				  int (*cb)(struct btrfs_fs_info *, u64,
				            u64, u64, u64 *, struct ulist *,
				            struct btrfs_snapshot_size_entry *,
				            struct btrfs_snapshot_size_ctx *));
#endif /* MY_ABC_HERE */
int btrfs_cow_block(struct btrfs_trans_handle *trans,
		    struct btrfs_root *root, struct extent_buffer *buf,
		    struct extent_buffer *parent, int parent_slot,
		    struct extent_buffer **cow_ret);
int btrfs_copy_root(struct btrfs_trans_handle *trans,
		      struct btrfs_root *root,
		      struct extent_buffer *buf,
		      struct extent_buffer **cow_ret, u64 new_root_objectid);
int btrfs_block_can_be_shared(struct btrfs_root *root,
			      struct extent_buffer *buf);
void btrfs_extend_item(struct btrfs_root *root, struct btrfs_path *path,
		       u32 data_size);
void btrfs_truncate_item(struct btrfs_root *root, struct btrfs_path *path,
			 u32 new_size, int from_end);
int btrfs_split_item(struct btrfs_trans_handle *trans,
		     struct btrfs_root *root,
		     struct btrfs_path *path,
		     struct btrfs_key *new_key,
		     unsigned long split_offset);
int btrfs_duplicate_item(struct btrfs_trans_handle *trans,
			 struct btrfs_root *root,
			 struct btrfs_path *path,
			 struct btrfs_key *new_key);
int btrfs_find_item(struct btrfs_root *fs_root, struct btrfs_path *path,
		u64 inum, u64 ioff, u8 key_type, struct btrfs_key *found_key);
int btrfs_search_slot(struct btrfs_trans_handle *trans, struct btrfs_root
		      *root, struct btrfs_key *key, struct btrfs_path *p, int
		      ins_len, int cow);
int btrfs_search_old_slot(struct btrfs_root *root, struct btrfs_key *key,
			  struct btrfs_path *p, u64 time_seq);
int btrfs_search_slot_for_read(struct btrfs_root *root,
			       struct btrfs_key *key, struct btrfs_path *p,
			       int find_higher, int return_any);
int btrfs_realloc_node(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root, struct extent_buffer *parent,
		       int start_slot, u64 *last_ret,
		       struct btrfs_key *progress);
void btrfs_release_path(struct btrfs_path *p);
struct btrfs_path *btrfs_alloc_path(void);
void btrfs_free_path(struct btrfs_path *p);
void btrfs_set_path_blocking(struct btrfs_path *p);
void btrfs_unlock_up_safe(struct btrfs_path *p, int level);

int btrfs_del_items(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		   struct btrfs_path *path, int slot, int nr);
static inline int btrfs_del_item(struct btrfs_trans_handle *trans,
				 struct btrfs_root *root,
				 struct btrfs_path *path)
{
	return btrfs_del_items(trans, root, path, path->slots[0], 1);
}

void setup_items_for_insert(struct btrfs_root *root, struct btrfs_path *path,
			    struct btrfs_key *cpu_key, u32 *data_size,
			    u32 total_data, u32 total_size, int nr);
int btrfs_insert_item(struct btrfs_trans_handle *trans, struct btrfs_root
		      *root, struct btrfs_key *key, void *data, u32 data_size);
int btrfs_insert_empty_items(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_path *path,
			     struct btrfs_key *cpu_key, u32 *data_size, int nr);

static inline int btrfs_insert_empty_item(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  struct btrfs_path *path,
					  struct btrfs_key *key,
					  u32 data_size)
{
	return btrfs_insert_empty_items(trans, root, path, key, &data_size, 1);
}

int btrfs_next_leaf(struct btrfs_root *root, struct btrfs_path *path);
int btrfs_prev_leaf(struct btrfs_root *root, struct btrfs_path *path);
int btrfs_next_old_leaf(struct btrfs_root *root, struct btrfs_path *path,
			u64 time_seq);
static inline int btrfs_next_old_item(struct btrfs_root *root,
				      struct btrfs_path *p, u64 time_seq)
{
	++p->slots[0];
	if (p->slots[0] >= btrfs_header_nritems(p->nodes[0]))
		return btrfs_next_old_leaf(root, p, time_seq);
	return 0;
}
static inline int btrfs_next_item(struct btrfs_root *root, struct btrfs_path *p)
{
	return btrfs_next_old_item(root, p, 0);
}
int btrfs_leaf_free_space(struct btrfs_root *root, struct extent_buffer *leaf);
int __must_check btrfs_drop_snapshot(struct btrfs_root *root,
				     struct btrfs_block_rsv *block_rsv,
				     int update_ref, int for_reloc);
int btrfs_drop_subtree(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			struct extent_buffer *node,
			struct extent_buffer *parent);
static inline int btrfs_fs_closing(struct btrfs_fs_info *fs_info)
{
	/*
	 * Get synced with close_ctree()
	 */
	smp_mb();
	return fs_info->closing;
}

/*
 * If we remount the fs to be R/O or umount the fs, the cleaner needn't do
 * anything except sleeping. This function is used to check the status of
 * the fs.
 */
static inline int btrfs_need_cleaner_sleep(struct btrfs_root *root)
{
	return (root->fs_info->sb->s_flags & MS_RDONLY ||
		btrfs_fs_closing(root->fs_info));
}

#ifdef MY_ABC_HERE
static inline void perf_stats_monitor_destroy(struct btrfs_fs_info *fs_info)
{
	percpu_counter_destroy(&fs_info->eb_hit);
	percpu_counter_destroy(&fs_info->eb_miss);
	percpu_counter_destroy(&fs_info->meta_write_pages);
	percpu_counter_destroy(&fs_info->data_write_pages);
	percpu_counter_destroy(&fs_info->delayed_meta_ref);
	percpu_counter_destroy(&fs_info->delayed_data_ref);
	percpu_counter_destroy(&fs_info->write_flush);
	percpu_counter_destroy(&fs_info->write_fua);
}
#endif /* MY_ABC_HERE */

static inline void free_fs_info(struct btrfs_fs_info *fs_info)
{
#ifdef MY_ABC_HERE
	perf_stats_monitor_destroy(fs_info);
#endif /* MY_ABC_HERE */
	kfree(fs_info->balance_ctl);
	kfree(fs_info->delayed_root);
	kfree(fs_info->extent_root);
	kfree(fs_info->tree_root);
	kfree(fs_info->chunk_root);
	kfree(fs_info->dev_root);
	kfree(fs_info->csum_root);
	kfree(fs_info->quota_root);
	kfree(fs_info->uuid_root);
	kfree(fs_info->free_space_root);
	kfree(fs_info->super_copy);
	kfree(fs_info->super_for_commit);
#ifdef MY_ABC_HERE
	kfree(fs_info->usrquota_root);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	kfree(fs_info->block_group_hint_root);
	kfree(fs_info->block_group_cache_root);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	kfree(fs_info->syno_usage_root);
	kfree(fs_info->syno_extent_usage_root);
#endif /* MY_ABC_HERE */
	kfree(fs_info);
}

/* tree mod log functions from ctree.c */
u64 btrfs_get_tree_mod_seq(struct btrfs_fs_info *fs_info,
			   struct seq_list *elem);
void btrfs_put_tree_mod_seq(struct btrfs_fs_info *fs_info,
			    struct seq_list *elem);
int btrfs_old_root_level(struct btrfs_root *root, u64 time_seq);

/* root-item.c */
int btrfs_find_root_ref(struct btrfs_root *tree_root,
			struct btrfs_path *path,
			u64 root_id, u64 ref_id);
int btrfs_add_root_ref(struct btrfs_trans_handle *trans,
		       struct btrfs_root *tree_root,
		       u64 root_id, u64 ref_id, u64 dirid, u64 sequence,
		       const char *name, int name_len);
int btrfs_del_root_ref(struct btrfs_trans_handle *trans,
		       struct btrfs_root *tree_root,
		       u64 root_id, u64 ref_id, u64 dirid, u64 *sequence,
		       const char *name, int name_len);
int btrfs_del_root(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		   struct btrfs_key *key);
int btrfs_insert_root(struct btrfs_trans_handle *trans, struct btrfs_root
		      *root, struct btrfs_key *key, struct btrfs_root_item
		      *item);
int __must_check btrfs_update_root(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct btrfs_key *key,
				   struct btrfs_root_item *item);
int btrfs_find_root(struct btrfs_root *root, struct btrfs_key *search_key,
		    struct btrfs_path *path, struct btrfs_root_item *root_item,
		    struct btrfs_key *root_key);
int btrfs_find_orphan_roots(struct btrfs_root *tree_root);
void btrfs_set_root_node(struct btrfs_root_item *item,
			 struct extent_buffer *node);
void btrfs_check_and_init_root_item(struct btrfs_root_item *item);
void btrfs_update_root_times(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root);

/* uuid-tree.c */
int btrfs_uuid_tree_add(struct btrfs_trans_handle *trans,
			struct btrfs_root *uuid_root, u8 *uuid, u8 type,
			u64 subid);
int btrfs_uuid_tree_rem(struct btrfs_trans_handle *trans,
			struct btrfs_root *uuid_root, u8 *uuid, u8 type,
			u64 subid);
int btrfs_uuid_tree_iterate(struct btrfs_fs_info *fs_info,
			    int (*check_func)(struct btrfs_fs_info *, u8 *, u8,
					      u64));

/* dir-item.c */
int btrfs_check_dir_item_collision(struct btrfs_root *root, u64 dir,
#ifdef MY_ABC_HERE
			   int check_dir_item,
#endif /* MY_ABC_HERE */
			  const char *name, int name_len);
int btrfs_insert_dir_item(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, const char *name,
			  int name_len, struct inode *dir,
			  struct btrfs_key *location, u8 type, u64 index);
struct btrfs_dir_item *btrfs_lookup_dir_item(struct btrfs_trans_handle *trans,
					     struct btrfs_root *root,
					     struct btrfs_path *path, u64 dir,
					     const char *name, int name_len,
					     int mod);
struct btrfs_dir_item *
btrfs_lookup_dir_index_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 dir,
			    u64 objectid, const char *name, int name_len,
			    int mod);
struct btrfs_dir_item *
btrfs_search_dir_index_item(struct btrfs_root *root,
			    struct btrfs_path *path, u64 dirid,
			    const char *name, int name_len);
int btrfs_delete_one_dir_name(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct btrfs_path *path,
			      struct btrfs_dir_item *di);
int btrfs_insert_xattr_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 objectid,
			    const char *name, u16 name_len,
			    const void *data, u16 data_len);
struct btrfs_dir_item *btrfs_lookup_xattr(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  struct btrfs_path *path, u64 dir,
					  const char *name, u16 name_len,
					  int mod);
int verify_dir_item(struct btrfs_root *root,
		    struct extent_buffer *leaf,
		    struct btrfs_dir_item *dir_item);
struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_root *root,
						 struct btrfs_path *path,
						 const char *name,
						 int name_len);

/* orphan.c */
int btrfs_insert_orphan_item(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root, u64 offset);
int btrfs_del_orphan_item(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, u64 offset);
int btrfs_find_orphan_item(struct btrfs_root *root, u64 offset);

/* inode-item.c */
int btrfs_insert_inode_ref(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   const char *name, int name_len,
			   u64 inode_objectid, u64 ref_objectid, u64 index);
int btrfs_del_inode_ref(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   const char *name, int name_len,
			   u64 inode_objectid, u64 ref_objectid, u64 *index);
int btrfs_insert_empty_inode(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_path *path, u64 objectid);
int btrfs_lookup_inode(struct btrfs_trans_handle *trans, struct btrfs_root
		       *root, struct btrfs_path *path,
		       struct btrfs_key *location, int mod);

struct btrfs_inode_extref *
btrfs_lookup_inode_extref(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root,
			  struct btrfs_path *path,
			  const char *name, int name_len,
			  u64 inode_objectid, u64 ref_objectid, int ins_len,
			  int cow);

int btrfs_find_name_in_ext_backref(struct btrfs_path *path,
				   u64 ref_objectid, const char *name,
				   int name_len,
				   struct btrfs_inode_extref **extref_ret);

/* file-item.c */
struct btrfs_dio_private;
int btrfs_del_csums(struct btrfs_trans_handle *trans,
		    struct btrfs_root *root, u64 bytenr, u64 len);
int btrfs_lookup_bio_sums(struct btrfs_root *root, struct inode *inode,
			  struct bio *bio, u32 *dst);
int btrfs_lookup_bio_sums_dio(struct btrfs_root *root, struct inode *inode,
			      struct btrfs_dio_private *dip, struct bio *bio,
			      u64 logical_offset);
int btrfs_insert_file_extent(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     u64 objectid, u64 pos,
			     u64 disk_offset, u64 disk_num_bytes,
			     u64 num_bytes, u64 offset, u64 ram_bytes,
			     u8 compression, u8 encryption, u16 other_encoding);
int btrfs_lookup_file_extent(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_path *path, u64 objectid,
			     u64 bytenr, int mod);
int btrfs_csum_file_blocks(struct btrfs_trans_handle *trans,
			   struct btrfs_root *root,
			   struct btrfs_ordered_sum *sums);
int btrfs_csum_one_bio(struct btrfs_root *root, struct inode *inode,
		       struct bio *bio, u64 file_start, int contig);
int btrfs_lookup_csums_range(struct btrfs_root *root, u64 start, u64 end,
			     struct list_head *list, int search_commit);
void btrfs_extent_item_to_extent_map(struct inode *inode,
				     const struct btrfs_path *path,
				     struct btrfs_file_extent_item *fi,
				     const bool new_inline,
				     struct extent_map *em);

/* inode.c */
struct btrfs_delalloc_work {
	struct inode *inode;
	int wait;
	int delay_iput;
#ifdef MY_ABC_HERE
	int syno_writeback;
#endif /* MY_ABC_HERE */
	struct completion completion;
	struct list_head list;
	struct btrfs_work work;
};

struct btrfs_delalloc_work *btrfs_alloc_delalloc_work(struct inode *inode,
						    int wait, int delay_iput);
void btrfs_wait_and_free_delalloc_work(struct btrfs_delalloc_work *work);

struct extent_map *btrfs_get_extent_fiemap(struct inode *inode, struct page *page,
					   size_t pg_offset, u64 start, u64 len,
					   int create);

noinline int can_nocow_extent(struct inode *inode, u64 offset, u64 *len,
			      u64 *orig_start, u64 *orig_block_len,
			      u64 *ram_bytes);

#ifdef MY_ABC_HERE
int btrfs_quota_query(struct file *file, u64 *used, u64 *reserved, u64 *limit);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
int btrfs_syno_space_usage(struct file *file, struct syno_space_usage_info *info);
#endif /* MY_ABC_HERE */

/* RHEL and EL kernels have a patch that renames PG_checked to FsMisc */
#if defined(ClearPageFsMisc) && !defined(ClearPageChecked)
#define ClearPageChecked ClearPageFsMisc
#define SetPageChecked SetPageFsMisc
#define PageChecked PageFsMisc
#endif

/* This forces readahead on a given range of bytes in an inode */
static inline void btrfs_force_ra(struct address_space *mapping,
				  struct file_ra_state *ra, struct file *file,
				  pgoff_t offset, unsigned long req_size)
{
	page_cache_sync_readahead(mapping, ra, file, offset, req_size);
}

#ifdef MY_ABC_HERE
struct inode *btrfs_lookup_dentry(struct inode *dir, struct dentry *dentry, int caseless);
#else
struct inode *btrfs_lookup_dentry(struct inode *dir, struct dentry *dentry);
#endif /* MY_ABC_HERE */
int btrfs_set_inode_index(struct inode *dir, u64 *index);
int btrfs_unlink_inode(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root,
		       struct inode *dir, struct inode *inode,
		       const char *name, int name_len);
int btrfs_add_link(struct btrfs_trans_handle *trans,
		   struct inode *parent_inode, struct inode *inode,
		   const char *name, int name_len, int add_backref, u64 index);
int btrfs_unlink_subvol(struct btrfs_trans_handle *trans,
			struct btrfs_root *root,
			struct inode *dir, u64 objectid,
			const char *name, int name_len);
int btrfs_truncate_page(struct inode *inode, loff_t from, loff_t len,
			int front);
int btrfs_truncate_inode_items(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       struct inode *inode, u64 new_size,
			       u32 min_type);

#ifdef MY_ABC_HERE
void syno_writeback_balance_dirty_pages(struct btrfs_fs_info *fs_info);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
int btrfs_start_delalloc_inodes(struct btrfs_root *root, int delay_iput, int snapshot);
#else
int btrfs_start_delalloc_inodes(struct btrfs_root *root, int delay_iput);
#endif /* MY_ABC_HERE */
int btrfs_start_delalloc_roots(struct btrfs_fs_info *fs_info, int delay_iput,
			       int nr);
int btrfs_set_extent_delalloc(struct inode *inode, u64 start, u64 end,
			      unsigned int extra_bits,
			      struct extent_state **cached_state);
int btrfs_create_subvol_root(struct btrfs_trans_handle *trans,
			     struct btrfs_root *new_root,
			     struct btrfs_root *parent_root,
			     u64 new_dirid);
int btrfs_merge_bio_hook(int rw, struct page *page, unsigned long offset,
			 size_t size, struct bio *bio,
			 unsigned long bio_flags);
int btrfs_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf);
int btrfs_readpage(struct file *file, struct page *page);
void btrfs_evict_inode(struct inode *inode);
int btrfs_write_inode(struct inode *inode, struct writeback_control *wbc);
struct inode *btrfs_alloc_inode(struct super_block *sb);
void btrfs_destroy_inode(struct inode *inode);
int btrfs_drop_inode(struct inode *inode);
int __init btrfs_init_cachep(void);
void btrfs_destroy_cachep(void);
long btrfs_ioctl_trans_end(struct file *file);
#ifdef MY_ABC_HERE
int btrfs_iget_uid(struct super_block *s, struct btrfs_key *location,
				       struct btrfs_root *root, uid_t *uid);
#endif /* MY_ABC_HERE */
struct inode *btrfs_iget(struct super_block *s, struct btrfs_key *location,
			 struct btrfs_root *root, int *was_new);
struct extent_map *btrfs_get_extent(struct inode *inode, struct page *page,
				    size_t pg_offset, u64 start, u64 end,
				    int create);
int btrfs_update_inode(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct inode *inode);
int btrfs_update_inode_fallback(struct btrfs_trans_handle *trans,
				struct btrfs_root *root, struct inode *inode);
int btrfs_orphan_add(struct btrfs_trans_handle *trans, struct inode *inode);
int btrfs_orphan_cleanup(struct btrfs_root *root);
int btrfs_cont_expand(struct inode *inode, loff_t oldsize, loff_t size);
void btrfs_invalidate_inodes(struct btrfs_root *root);
void btrfs_add_delayed_iput(struct inode *inode);
void btrfs_run_delayed_iputs(struct btrfs_root *root);
int btrfs_prealloc_file_range(struct inode *inode, int mode,
			      u64 start, u64 num_bytes, u64 min_size,
			      loff_t actual_len, u64 *alloc_hint);
int btrfs_prealloc_file_range_trans(struct inode *inode,
				    struct btrfs_trans_handle *trans, int mode,
				    u64 start, u64 num_bytes, u64 min_size,
				    loff_t actual_len, u64 *alloc_hint);
extern const struct dentry_operations btrfs_dentry_operations;
#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
void btrfs_test_inode_set_ops(struct inode *inode);
#endif

#ifdef MY_ABC_HERE
void block_dump___btrfs_update_inode(struct inode *inode);
#endif /* MY_ABC_HERE */

void btrfs_update_inode_bytes(struct btrfs_inode *inode,
			      const u64 add_bytes,
			      const u64 del_bytes);

/* ioctl.c */
long btrfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
void btrfs_update_iflags(struct inode *inode);
void btrfs_inherit_iflags(struct inode *inode, struct inode *dir);
int btrfs_is_empty_uuid(u8 *uuid);
int btrfs_defrag_file(struct inode *inode, struct file *file,
		      struct btrfs_ioctl_defrag_range_args *range,
		      u64 newer_than, unsigned long max_pages);
void btrfs_get_block_group_info(struct list_head *groups_list,
				struct btrfs_ioctl_space_info *space);
void update_ioctl_balance_args(struct btrfs_fs_info *fs_info, int lock,
			       struct btrfs_ioctl_balance_args *bargs);
#if defined(CONFIG_COMPAT) && defined(MY_DEF_HERE)
long btrfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#endif /* CONFIG_COMPAT && MY_DEF_HERE */

/* file.c */
int __init btrfs_auto_defrag_init(void);
void btrfs_auto_defrag_exit(void);
#ifdef MY_ABC_HERE
#define BTRFS_INODE_DEFRAG_NORMAL (1 << 0)
#define BTRFS_INODE_DEFRAG_SYNO (1 << 1)
int btrfs_add_inode_defrag(struct btrfs_trans_handle *trans,
			   struct inode *inode, u64 start, u64 end,
			   int defrag_type);
#else
int btrfs_add_inode_defrag(struct btrfs_trans_handle *trans,
			   struct inode *inode);
#endif /* MY_ABC_HERE */
int btrfs_run_defrag_inodes(struct btrfs_fs_info *fs_info);
void btrfs_cleanup_defrag_inodes(struct btrfs_fs_info *fs_info);
int btrfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync);
void btrfs_drop_extent_cache(struct inode *inode, u64 start, u64 end,
			     int skip_pinned);
extern const struct file_operations btrfs_file_operations;
int btrfs_drop_extents(struct btrfs_trans_handle *trans,
		       struct btrfs_root *root, struct inode *inode,
		       struct btrfs_drop_extents_args *args);
int btrfs_punch_hole_range(struct inode *inode, struct btrfs_path *path,
			   const u64 start, const u64 end,
			   struct btrfs_clone_extent_info *clone_info,
			   struct btrfs_trans_handle **trans_out
#ifdef MY_ABC_HERE
			   , struct btrfs_punch_hole_args *args
#endif /* MY_ABC_HERE */
			   );
int btrfs_mark_extent_written(struct btrfs_trans_handle *trans,
			      struct inode *inode, u64 start, u64 end);
int btrfs_release_file(struct inode *inode, struct file *file);
int btrfs_dirty_pages(struct btrfs_root *root, struct inode *inode,
		      struct page **pages, size_t num_pages,
		      loff_t pos, size_t write_bytes,
		      struct extent_state **cached);
int btrfs_fdatawrite_range(struct inode *inode, loff_t start, loff_t end);
int btrfs_clone_file_range(struct file *file_in, loff_t pos_in,
			   struct file *file_out, loff_t pos_out, u64 len);
#ifdef MY_ABC_HERE
int btrfs_clone_check_compr(struct file *file, struct file *file_src);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
void syno_ordered_extent_throttle(struct btrfs_fs_info *fs_info);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
int btrfs_fallocate_check_punch(struct file *file, loff_t offset, loff_t len, loff_t *extent_align_offset, loff_t *extent_len);
#endif /* MY_ABC_HERE */

/* tree-defrag.c */
int btrfs_defrag_leaves(struct btrfs_trans_handle *trans,
			struct btrfs_root *root);

/* sysfs.c */
int __init btrfs_init_sysfs(void);
void btrfs_exit_sysfs(void);
int btrfs_sysfs_add_one(struct btrfs_fs_info *fs_info);
void btrfs_sysfs_remove_one(struct btrfs_fs_info *fs_info);
#ifdef MY_ABC_HERE
int btrfs_debugfs_add_one(struct btrfs_fs_info *fs_info);
void btrfs_debugfs_remove_one(struct btrfs_fs_info *fs_info);
#endif /* MY_ABC_HERE */

/* xattr.c */
ssize_t btrfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

/* super.c */
int btrfs_parse_options(struct btrfs_root *root, char *options,
			unsigned long new_flags);
int btrfs_sync_fs(struct super_block *sb, int wait);

#ifdef CONFIG_PRINTK
__printf(2, 3)
void btrfs_printk(const struct btrfs_fs_info *fs_info, const char *fmt, ...);
#else
static inline __printf(2, 3)
void btrfs_printk(const struct btrfs_fs_info *fs_info, const char *fmt, ...)
{
}
#endif

#define btrfs_emerg(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_EMERG fmt, ##args)
#define btrfs_alert(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_ALERT fmt, ##args)
#define btrfs_crit(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_CRIT fmt, ##args)
#define btrfs_err(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_ERR fmt, ##args)
#define btrfs_warn(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_WARNING fmt, ##args)
#define btrfs_notice(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_NOTICE fmt, ##args)
#define btrfs_info(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_INFO fmt, ##args)

/*
 * Wrappers that use printk_in_rcu
 */
#define btrfs_emerg_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_EMERG fmt, ##args)
#define btrfs_alert_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_ALERT fmt, ##args)
#define btrfs_crit_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_CRIT fmt, ##args)
#define btrfs_err_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_ERR fmt, ##args)
#define btrfs_warn_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_WARNING fmt, ##args)
#define btrfs_notice_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_NOTICE fmt, ##args)
#define btrfs_info_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_INFO fmt, ##args)

#ifdef DEBUG
#define btrfs_debug(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_DEBUG fmt, ##args)
#define btrfs_debug_in_rcu(fs_info, fmt, args...) \
	btrfs_printk_in_rcu(fs_info, KERN_DEBUG fmt, ##args)
#else
#define btrfs_debug(fs_info, fmt, args...) \
    no_printk(KERN_DEBUG fmt, ##args)
#define btrfs_debug_in_rcu(fs_info, fmt, args...) \
	no_printk(KERN_DEBUG fmt, ##args)
#endif

#define btrfs_printk_in_rcu(fs_info, fmt, args...)	\
do {							\
	rcu_read_lock();				\
	btrfs_printk(fs_info, fmt, ##args);		\
	rcu_read_unlock();				\
} while (0)

#ifdef CONFIG_BTRFS_ASSERT

static inline void assfail(char *expr, char *file, int line)
{
	pr_err("BTRFS: assertion failed: %s, file: %s, line: %d",
	       expr, file, line);
	BUG();
}

#define ASSERT(expr)	\
	(likely(expr) ? (void)0 : assfail(#expr, __FILE__, __LINE__))
#else
#define ASSERT(expr)	((void)0)
#endif

#define btrfs_assert()
__printf(5, 6)
void __btrfs_std_error(struct btrfs_fs_info *fs_info, const char *function,
		     unsigned int line, int errno, const char *fmt, ...);


void __btrfs_abort_transaction(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root, const char *function,
			       unsigned int line, int errno);

#define btrfs_set_fs_incompat(__fs_info, opt) \
	__btrfs_set_fs_incompat((__fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

static inline void __btrfs_set_fs_incompat(struct btrfs_fs_info *fs_info,
					   u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info, "setting %llu feature flag",
					 flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_clear_fs_incompat(__fs_info, opt) \
	__btrfs_clear_fs_incompat((__fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

static inline void __btrfs_clear_fs_incompat(struct btrfs_fs_info *fs_info,
					     u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_incompat_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_incompat_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_incompat_flags(disk_super, features);
			btrfs_info(fs_info, "clearing %llu feature flag",
					 flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_fs_incompat(fs_info, opt) \
	__btrfs_fs_incompat((fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

static inline int __btrfs_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag)
{
	struct btrfs_super_block *disk_super;
	disk_super = fs_info->super_copy;
	return !!(btrfs_super_incompat_flags(disk_super) & flag);
}

#define btrfs_set_fs_compat_ro(__fs_info, opt) \
	__btrfs_set_fs_compat_ro((__fs_info), BTRFS_FEATURE_COMPAT_RO_##opt)

static inline void __btrfs_set_fs_compat_ro(struct btrfs_fs_info *fs_info,
					    u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info, "setting %llu ro feature flag",
				   flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_clear_fs_compat_ro(__fs_info, opt) \
	__btrfs_clear_fs_compat_ro((__fs_info), BTRFS_FEATURE_COMPAT_RO_##opt)

static inline void __btrfs_clear_fs_compat_ro(struct btrfs_fs_info *fs_info,
					      u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_ro_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_ro_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_compat_ro_flags(disk_super, features);
			btrfs_info(fs_info, "clearing %llu ro feature flag",
				   flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_fs_compat_ro(fs_info, opt) \
	__btrfs_fs_compat_ro((fs_info), BTRFS_FEATURE_COMPAT_RO_##opt)

static inline int __btrfs_fs_compat_ro(struct btrfs_fs_info *fs_info, u64 flag)
{
	struct btrfs_super_block *disk_super;
	disk_super = fs_info->super_copy;
	return !!(btrfs_super_compat_ro_flags(disk_super) & flag);
}


#ifdef MY_ABC_HERE
#define btrfs_set_fs_compat(__fs_info, opt) \
	__btrfs_set_fs_compat((__fs_info), BTRFS_FEATURE_COMPAT_##opt)

static inline void __btrfs_set_fs_compat(struct btrfs_fs_info *fs_info,
					    u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_flags(disk_super);
	if (!(features & flag)) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_flags(disk_super);
		if (!(features & flag)) {
			features |= flag;
			btrfs_set_super_compat_flags(disk_super, features);
			btrfs_info(fs_info, "setting %llu campat feature flag",
				   flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_clear_fs_compat(__fs_info, opt) \
	__btrfs_clear_fs_compat((__fs_info), BTRFS_FEATURE_COMPAT_##opt)

static inline void __btrfs_clear_fs_compat(struct btrfs_fs_info *fs_info,
					      u64 flag)
{
	struct btrfs_super_block *disk_super;
	u64 features;

	disk_super = fs_info->super_copy;
	features = btrfs_super_compat_flags(disk_super);
	if (features & flag) {
		spin_lock(&fs_info->super_lock);
		features = btrfs_super_compat_flags(disk_super);
		if (features & flag) {
			features &= ~flag;
			btrfs_set_super_compat_flags(disk_super, features);
			btrfs_info(fs_info, "clearing %llu compat feature flag",
				   flag);
		}
		spin_unlock(&fs_info->super_lock);
	}
}

#define btrfs_fs_compat(fs_info, opt) \
	__btrfs_fs_compat((fs_info), BTRFS_FEATURE_COMPAT_##opt)

static inline int __btrfs_fs_compat(struct btrfs_fs_info *fs_info, u64 flag)
{
	struct btrfs_super_block *disk_super;
	disk_super = fs_info->super_copy;
	return !!(btrfs_super_compat_flags(disk_super) & flag);
}
#endif /* MY_ABC_HERE */

/*
 * Call btrfs_abort_transaction as early as possible when an error condition is
 * detected, that way the exact line number is reported.
 */

#define btrfs_abort_transaction(trans, root, errno)		\
do {								\
	__btrfs_abort_transaction(trans, root, __func__,	\
				  __LINE__, errno);		\
} while (0)

#define btrfs_std_error(fs_info, errno)				\
do {								\
	if ((errno))						\
		__btrfs_std_error((fs_info), __func__,		\
				   __LINE__, (errno), NULL);	\
} while (0)

#define btrfs_error(fs_info, errno, fmt, args...)		\
do {								\
	__btrfs_std_error((fs_info), __func__, __LINE__,	\
			  (errno), fmt, ##args);		\
} while (0)

__printf(5, 6)
void __btrfs_panic(struct btrfs_fs_info *fs_info, const char *function,
		   unsigned int line, int errno, const char *fmt, ...);

/*
 * If BTRFS_MOUNT_PANIC_ON_FATAL_ERROR is in mount_opt, __btrfs_panic
 * will panic().  Otherwise we BUG() here.
 */
#define btrfs_panic(fs_info, errno, fmt, args...)			\
do {									\
	__btrfs_panic(fs_info, __func__, __LINE__, errno, fmt, ##args);	\
	BUG();								\
} while (0)

/* acl.c */
#ifdef CONFIG_BTRFS_FS_POSIX_ACL
struct posix_acl *btrfs_get_acl(struct inode *inode, int type);
int btrfs_init_acl(struct btrfs_trans_handle *trans,
		   struct inode *inode, struct inode *dir);
int btrfs_acl_chmod(struct inode *inode);
#else
#define btrfs_get_acl NULL
static inline int btrfs_init_acl(struct btrfs_trans_handle *trans,
				 struct inode *inode, struct inode *dir)
{
	return 0;
}
static inline int btrfs_acl_chmod(struct inode *inode)
{
	return 0;
}
#endif

/* relocation.c */
int btrfs_relocate_block_group(struct btrfs_root *root, u64 group_start);
int btrfs_init_reloc_root(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root);
int btrfs_update_reloc_root(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root);
int btrfs_recover_relocation(struct btrfs_root *root);
int btrfs_reloc_clone_csums(struct inode *inode, u64 file_pos, u64 len);
int btrfs_reloc_cow_block(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, struct extent_buffer *buf,
			  struct extent_buffer *cow);
void btrfs_reloc_pre_snapshot(struct btrfs_trans_handle *trans,
			      struct btrfs_pending_snapshot *pending,
			      u64 *bytes_to_reserve);
int btrfs_reloc_post_snapshot(struct btrfs_trans_handle *trans,
			      struct btrfs_pending_snapshot *pending);
int btrfs_should_cancel_balance(struct btrfs_fs_info *fs_info);

/* scrub.c */
int btrfs_scrub_dev(struct btrfs_fs_info *fs_info, u64 devid, u64 start,
		    u64 end, struct btrfs_scrub_progress *progress,
		    int readonly, int is_dev_replace);
void btrfs_scrub_pause(struct btrfs_root *root);
void btrfs_scrub_continue(struct btrfs_root *root);
int btrfs_scrub_cancel(struct btrfs_fs_info *info);
int btrfs_scrub_cancel_dev(struct btrfs_fs_info *info,
			   struct btrfs_device *dev);
int btrfs_scrub_progress(struct btrfs_root *root, u64 devid,
			 struct btrfs_scrub_progress *progress);

#ifdef MY_ABC_HERE
#else
/* dev-replace.c */
void btrfs_bio_counter_inc_blocked(struct btrfs_fs_info *fs_info);
void btrfs_bio_counter_inc_noblocked(struct btrfs_fs_info *fs_info);
void btrfs_bio_counter_dec(struct btrfs_fs_info *fs_info);
#endif /* MY_ABC_HERE */

/* reada.c */
struct reada_control {
	struct btrfs_root	*root;		/* tree to prefetch */
	struct btrfs_key	key_start;
	struct btrfs_key	key_end;	/* exclusive */
	atomic_t		elems;
	struct kref		refcnt;
	wait_queue_head_t	wait;
};
struct reada_control *btrfs_reada_add(struct btrfs_root *root,
			      struct btrfs_key *start, struct btrfs_key *end);
int btrfs_reada_wait(void *handle);
void btrfs_reada_detach(void *handle);
int btree_readahead_hook(struct btrfs_root *root, struct extent_buffer *eb,
			 u64 start, int err);

static inline int is_fstree(u64 rootid)
{
	if (rootid == BTRFS_FS_TREE_OBJECTID ||
	    (s64)rootid >= (s64)BTRFS_FIRST_FREE_OBJECTID)
		return 1;
	return 0;
}

static inline int btrfs_defrag_cancelled(struct btrfs_fs_info *fs_info)
{
	return signal_pending(current);
}

/* Sanity test specific functions */
#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
void btrfs_test_destroy_inode(struct inode *inode);
int btrfs_verify_qgroup_counts(struct btrfs_fs_info *fs_info, u64 qgroupid,
			       u64 rfer, u64 excl);
#endif

#ifdef MY_ABC_HERE
void SynoAutoErrorFsBtrfsReport(const u8* fsid);
#endif

#ifdef MY_ABC_HERE
/* usrquota.c */
int btrfs_usrquota_enable(struct btrfs_fs_info *fs_info);
int btrfs_usrquota_disable(struct btrfs_fs_info *fs_info);
int btrfs_usrquota_dumptree(struct btrfs_fs_info *fs_info);

int btrfs_usrquota_rescan(struct btrfs_fs_info *fs_info, u64 rootid);
void btrfs_usrquota_rescan_resume(struct btrfs_fs_info *fs_info);
int btrfs_usrquota_wait_for_completion(struct btrfs_fs_info *fs_info);
int btrfs_read_usrquota_config(struct btrfs_fs_info *fs_info);
void btrfs_free_usrquota_config(struct btrfs_fs_info *fs_info);

int btrfs_usrquota_limit(struct btrfs_trans_handle *trans,
                         struct btrfs_fs_info *fs_info,
                         u64 root_id, u64 uid, u64 rfer_soft, u64 rfer_hard);
int btrfs_usrquota_clean(struct btrfs_trans_handle *trans,
                         struct btrfs_fs_info *fs_info, u64 uid);

int btrfs_run_usrquota(struct btrfs_trans_handle *trans,
                       struct btrfs_fs_info *fs_info);

int btrfs_usrquota_reserve(struct btrfs_root *root,
                           struct inode *inode, uid_t uid, u64 num_bytes);
int btrfs_usrquota_free(struct btrfs_root *root,
                        struct inode *inode, uid_t uid, u64 num_bytes);
#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
int __btrfs_usrquota_free(struct btrfs_root *root, struct inode *inode, uid_t uid, u64 num_bytes, int free_type);
int btrfs_usrquota_free_add_delay(struct btrfs_root *root, struct inode *inode, uid_t uid, u64 num_bytes);
int btrfs_usrquota_release_delayed_free(struct btrfs_root *root, struct inode *inode, uid_t uid, u64 num_bytes);
#endif /* MY_ABC_HERE && MY_ABC_HERE */
struct btrfs_qgroup_operation;
int btrfs_usrquota_account_ref(struct btrfs_trans_handle *trans,
                               struct btrfs_fs_info *fs_info,
                               struct btrfs_qgroup_operation *oper);
// for chown
int btrfs_usrquota_transfer(struct inode *inode, uid_t new_uid);
int btrfs_usrquota_calc_reserve_snap(struct btrfs_root *root,
                                     u64 copy_limit_from, u64 *reserve_items);
int btrfs_usrquota_mksubvol(struct btrfs_trans_handle *trans,
                            struct btrfs_fs_info *fs_info, u64 objectid);
int btrfs_usrquota_mksnap(struct btrfs_trans_handle *trans,
                          struct btrfs_fs_info *fs_info, u64 srcid, u64 objectid,
                          bool readonly, u64 copy_limit_from);
int btrfs_usrquota_delsnap(struct btrfs_trans_handle *trans,
                           struct btrfs_fs_info *fs_info, u64 root_id);
int btrfs_usrquota_query(struct btrfs_fs_info *fs_info, u64 rootid,
                          struct btrfs_ioctl_usrquota_query_args *uqa);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
/* syno-extent-usage.c */
int btrfs_create_syno_usage_tree(struct btrfs_fs_info *fs_info);
int btrfs_clear_syno_usage_tree(struct btrfs_fs_info *fs_info);
int btrfs_syno_usage_root_status_lookup(struct btrfs_fs_info *fs_info, u64 root_objectid, struct btrfs_syno_usage_root_status *ret_item);
int btrfs_syno_usage_root_status_remove(struct btrfs_trans_handle *trans,
				struct btrfs_fs_info *fs_info, u64 root_objectid);
int btrfs_syno_usage_root_status_update(struct btrfs_trans_handle *trans,
				struct btrfs_fs_info *fs_info, u64 root_objectid, struct btrfs_syno_usage_root_status *syno_usage_root_status);
int btrfs_syno_usage_global_type_update(struct btrfs_trans_handle *trans,
				struct btrfs_fs_info *fs_info);
int btrfs_read_syno_usage_config(struct btrfs_fs_info *fs_info);
int btrfs_syno_extent_usage_add(struct btrfs_trans_handle *trans,
				struct btrfs_fs_info *fs_info, int want,
				u64 bytenr, u64 num_bytes, int refs_to_add);
int btrfs_syno_extent_usage_free(struct btrfs_trans_handle *trans,
				struct btrfs_fs_info *fs_info, int want,
				u64 bytenr, u64 num_bytes, int refs_to_drop, bool remove);
int btrfs_create_syno_extent_usage_tree(struct btrfs_fs_info *fs_info);
int btrfs_clear_syno_extent_usage_tree(struct btrfs_fs_info *fs_info);
int btrfs_syno_usage_ref_check(struct btrfs_root *root, u64 owner, u64 offset);
int btrfs_syno_subvol_usage_add(struct btrfs_trans_handle *trans, struct btrfs_fs_info *fs_info,
				u64 root_objectid, u64 bytenr, u64 num_bytes, int refs_to_add);
int btrfs_syno_subvol_usage_free(struct btrfs_trans_handle *trans, struct btrfs_fs_info *fs_info,
				u64 root_objectid, u64 bytenr, u64 num_bytes, int refs_to_drop);

int btrfs_syno_clear_subvol_usage_item_prepare(struct btrfs_root *root);
int btrfs_syno_clear_subvol_usage_item_doing(struct btrfs_root *root);
void btrfs_init_syno_usage_rescan_work(struct work_struct *work);
void btrfs_init_syno_usage_fast_rescan_work(struct work_struct *work);
void btrfs_init_syno_usage_full_rescan_work(struct work_struct *work);
void btrfs_syno_usage_rescan_resume(struct btrfs_fs_info *fs_info);
int btrfs_syno_usage_enable(struct btrfs_fs_info *fs_info);
int btrfs_syno_usage_disable(struct btrfs_fs_info *fs_info);
void btrfs_syno_usage_root_initialize(struct btrfs_root *subvol_root);
int btrfs_syno_usage_status_update(struct btrfs_trans_handle *trans,
				struct btrfs_fs_info *fs_info);
#endif /* MY_ABC_HERE */

static inline int btrfs_test_is_dummy_root(struct btrfs_root *root)
{
#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
	if (unlikely(test_bit(BTRFS_ROOT_DUMMY_ROOT, &root->state)))
		return 1;
#endif
	return 0;
}

#ifdef MY_ABC_HERE
/* free-space-analyze.c */
int btrfs_free_space_analyze(struct btrfs_fs_info *fs_info,
		struct btrfs_ioctl_free_space_analyze_args *args);
int btrfs_free_space_analyze_full(struct btrfs_fs_info *fs_info,
		struct btrfs_ioctl_free_space_analyze_args *args);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
int btrfs_syno_quota_status(struct btrfs_root *root,
			struct btrfs_ioctl_syno_quota_status_args *sa);
#endif /* MY_ABC_HERE */

#endif
