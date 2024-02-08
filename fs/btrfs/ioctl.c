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
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mount.h>
#include <linux/mpage.h>
#include <linux/namei.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/compat.h>
#include <linux/bit_spinlock.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/uuid.h>
#include <linux/btrfs.h>
#include <linux/uaccess.h>
#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "volumes.h"
#include "locking.h"
#include "inode-map.h"
#include "backref.h"
#include "rcu-string.h"
#include "send.h"
#include "dev-replace.h"
#include "props.h"
#include "sysfs.h"
#include "qgroup.h"
#include "tree-log.h"
#include "compression.h"

#ifdef CONFIG_64BIT
/* If we have a 32-bit userspace and 64-bit kernel, then the UAPI
 * structures are incorrect, as the timespec structure from userspace
 * is 4 bytes too small. We define these alternatives here to teach
 * the kernel about the 32-bit struct packing.
 */
struct btrfs_ioctl_timespec_32 {
	__u64 sec;
	__u32 nsec;
} __attribute__ ((__packed__));

struct btrfs_ioctl_received_subvol_args_32 {
	char	uuid[BTRFS_UUID_SIZE];	/* in */
	__u64	stransid;		/* in */
	__u64	rtransid;		/* out */
	struct btrfs_ioctl_timespec_32 stime; /* in */
	struct btrfs_ioctl_timespec_32 rtime; /* out */
	__u64	flags;			/* in */
#ifdef MY_ABC_HERE
	struct btrfs_ioctl_timespec_32 otime; /* in */
	//why 2 reserved is used(64+64=128bits) but
	//otime only occupies 64+32=96(bits)
	//This is for compatible to 32bits userspace
	//After this change, sizeof(btrfs_ioctl_received_subvol_args_32)
	//changed from 192 bytes to 188 bytes;
	__u64	reserved[14];
#else
	__u64	reserved[16];		/* in */
#endif /* MY_ABC_HERE */
} __attribute__ ((__packed__));

#define BTRFS_IOC_SET_RECEIVED_SUBVOL_32 _IOWR(BTRFS_IOCTL_MAGIC, 37, \
				struct btrfs_ioctl_received_subvol_args_32)
#endif


#ifdef MY_ABC_HERE
struct btrfs_syno_clone_range {
	u64 src_off;
	u64 src_len;
	u64 dest_off;
	u64 dest_len;
	u64 ref_limit;
	u32 flag;
};
#endif /* MY_ABC_HERE */

static int btrfs_clone(struct inode *src, struct inode *inode,
		       u64 off, u64 olen, u64 olen_aligned, u64 destoff,
#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
		       int no_time_update, int full_clone,
		       struct btrfs_syno_clone_range *args);
#else
		       int no_time_update,
		       struct btrfs_syno_clone_range *args);
#endif /* MY_ABC_HERE */
#else
#ifdef MY_ABC_HERE
		       int no_time_update, int full_clone);
#else
		       int no_time_update);
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __u32 btrfs_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & ~FS_DIRSYNC_FL;
	else
		return flags & (FS_NODUMP_FL | FS_NOATIME_FL);
}

/*
 * Export inode flags to the format expected by the FS_IOC_GETFLAGS ioctl.
 */
static unsigned int btrfs_flags_to_ioctl(unsigned int flags)
{
	unsigned int iflags = 0;

	if (flags & BTRFS_INODE_SYNC)
		iflags |= FS_SYNC_FL;
	if (flags & BTRFS_INODE_IMMUTABLE)
		iflags |= FS_IMMUTABLE_FL;
	if (flags & BTRFS_INODE_APPEND)
		iflags |= FS_APPEND_FL;
	if (flags & BTRFS_INODE_NODUMP)
		iflags |= FS_NODUMP_FL;
	if (flags & BTRFS_INODE_NOATIME)
		iflags |= FS_NOATIME_FL;
	if (flags & BTRFS_INODE_DIRSYNC)
		iflags |= FS_DIRSYNC_FL;
	if (flags & BTRFS_INODE_NODATACOW)
		iflags |= FS_NOCOW_FL;

	if (flags & BTRFS_INODE_NOCOMPRESS)
		iflags |= FS_NOCOMP_FL;
	else if (flags & BTRFS_INODE_COMPRESS)
		iflags |= FS_COMPR_FL;

	return iflags;
}

/*
 * Update inode->i_flags based on the btrfs internal flags.
 */
void btrfs_update_iflags(struct inode *inode)
{
	struct btrfs_inode *ip = BTRFS_I(inode);
	unsigned int new_fl = 0;

	if (ip->flags & BTRFS_INODE_SYNC)
		new_fl |= S_SYNC;
	if (ip->flags & BTRFS_INODE_IMMUTABLE)
		new_fl |= S_IMMUTABLE;
	if (ip->flags & BTRFS_INODE_APPEND)
		new_fl |= S_APPEND;
	if (ip->flags & BTRFS_INODE_NOATIME)
		new_fl |= S_NOATIME;
	if (ip->flags & BTRFS_INODE_DIRSYNC)
		new_fl |= S_DIRSYNC;

	set_mask_bits(&inode->i_flags,
		      S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC,
		      new_fl);
}

/*
 * Inherit flags from the parent inode.
 *
 * Currently only the compression flags and the cow flags are inherited.
 */
void btrfs_inherit_iflags(struct inode *inode, struct inode *dir)
{
	unsigned int flags;

	if (!dir)
		return;

	flags = BTRFS_I(dir)->flags;

	if (flags & BTRFS_INODE_NOCOMPRESS) {
		BTRFS_I(inode)->flags &= ~BTRFS_INODE_COMPRESS;
		BTRFS_I(inode)->flags |= BTRFS_INODE_NOCOMPRESS;
	} else if (flags & BTRFS_INODE_COMPRESS) {
		BTRFS_I(inode)->flags &= ~BTRFS_INODE_NOCOMPRESS;
		BTRFS_I(inode)->flags |= BTRFS_INODE_COMPRESS;
	}

	if (flags & BTRFS_INODE_NODATACOW) {
		BTRFS_I(inode)->flags |= BTRFS_INODE_NODATACOW;
		if (S_ISREG(inode->i_mode))
			BTRFS_I(inode)->flags |= BTRFS_INODE_NODATASUM;
	}

	btrfs_update_iflags(inode);
}

static int btrfs_ioctl_getflags(struct file *file, void __user *arg)
{
	struct btrfs_inode *ip = BTRFS_I(file_inode(file));
	unsigned int flags = btrfs_flags_to_ioctl(ip->flags);

	if (copy_to_user(arg, &flags, sizeof(flags)))
		return -EFAULT;
	return 0;
}

static int check_flags(unsigned int flags)
{
	if (flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL | \
		      FS_NOATIME_FL | FS_NODUMP_FL | \
		      FS_SYNC_FL | FS_DIRSYNC_FL | \
		      FS_NOCOMP_FL | FS_COMPR_FL |
		      FS_NOCOW_FL))
		return -EOPNOTSUPP;

	if ((flags & FS_NOCOMP_FL) && (flags & FS_COMPR_FL))
		return -EINVAL;

	return 0;
}

static int btrfs_ioctl_setflags(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_inode *ip = BTRFS_I(inode);
	struct btrfs_root *root = ip->root;
	struct btrfs_trans_handle *trans;
	unsigned int flags, oldflags;
	int ret;
	u64 ip_oldflags;
	unsigned int i_oldflags;
	umode_t mode;

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	if (btrfs_root_readonly(root))
		return -EROFS;

	if (copy_from_user(&flags, arg, sizeof(flags)))
		return -EFAULT;

	ret = check_flags(flags);
	if (ret)
		return ret;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	inode_lock(inode);

	ip_oldflags = ip->flags;
	i_oldflags = inode->i_flags;
	mode = inode->i_mode;

	flags = btrfs_mask_flags(inode->i_mode, flags);
	oldflags = btrfs_flags_to_ioctl(ip->flags);
	if ((flags ^ oldflags) & (FS_APPEND_FL | FS_IMMUTABLE_FL)) {
		if (!capable(CAP_LINUX_IMMUTABLE)) {
			ret = -EPERM;
			goto out_unlock;
		}
	}

	if (flags & FS_SYNC_FL)
		ip->flags |= BTRFS_INODE_SYNC;
	else
		ip->flags &= ~BTRFS_INODE_SYNC;
	if (flags & FS_IMMUTABLE_FL)
		ip->flags |= BTRFS_INODE_IMMUTABLE;
	else
		ip->flags &= ~BTRFS_INODE_IMMUTABLE;
	if (flags & FS_APPEND_FL)
		ip->flags |= BTRFS_INODE_APPEND;
	else
		ip->flags &= ~BTRFS_INODE_APPEND;
	if (flags & FS_NODUMP_FL)
		ip->flags |= BTRFS_INODE_NODUMP;
	else
		ip->flags &= ~BTRFS_INODE_NODUMP;
	if (flags & FS_NOATIME_FL)
		ip->flags |= BTRFS_INODE_NOATIME;
	else
		ip->flags &= ~BTRFS_INODE_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		ip->flags |= BTRFS_INODE_DIRSYNC;
	else
		ip->flags &= ~BTRFS_INODE_DIRSYNC;
	if (flags & FS_NOCOW_FL) {
		if (S_ISREG(mode)) {
			/*
			 * It's safe to turn csums off here, no extents exist.
			 * Otherwise we want the flag to reflect the real COW
			 * status of the file and will not set it.
			 */
			if (inode->i_size == 0)
				ip->flags |= BTRFS_INODE_NODATACOW
					   | BTRFS_INODE_NODATASUM;
		} else {
			ip->flags |= BTRFS_INODE_NODATACOW;
		}
	} else {
		/*
		 * Revert back under same assumptions as above
		 */
		if (S_ISREG(mode)) {
			if (inode->i_size == 0)
				ip->flags &= ~(BTRFS_INODE_NODATACOW
				             | BTRFS_INODE_NODATASUM);
		} else {
			ip->flags &= ~BTRFS_INODE_NODATACOW;
		}
	}

	/*
	 * The COMPRESS flag can only be changed by users, while the NOCOMPRESS
	 * flag may be changed automatically if compression code won't make
	 * things smaller.
	 */
	if (flags & FS_NOCOMP_FL) {
		ip->flags &= ~BTRFS_INODE_COMPRESS;
		ip->flags |= BTRFS_INODE_NOCOMPRESS;

		ret = btrfs_set_prop(inode, "btrfs.compression", NULL, 0, 0);
		if (ret && ret != -ENODATA)
			goto out_drop;
	} else if (flags & FS_COMPR_FL) {
		const char *comp;

		if (IS_SWAPFILE(inode)) {
			ret = -ETXTBSY;
			goto out_unlock;
		}

		ip->flags |= BTRFS_INODE_COMPRESS;
		ip->flags &= ~BTRFS_INODE_NOCOMPRESS;

#ifdef MY_ABC_HERE
		if (root->fs_info->compress_type == BTRFS_COMPRESS_ZLIB)
			comp = "zlib";
		else if (root->fs_info->compress_type == BTRFS_COMPRESS_ZSTD)
			comp = "zstd";
		else
			comp = "lzo";
#else
		if (root->fs_info->compress_type == BTRFS_COMPRESS_LZO)
			comp = "lzo";
		else if (root->fs_info->compress_type == BTRFS_COMPRESS_ZLIB)
			comp = "zlib";
		else
			comp = "zstd";
#endif /* MY_ABC_HERE */
		ret = btrfs_set_prop(inode, "btrfs.compression",
				     comp, strlen(comp), 0);
		if (ret)
			goto out_drop;

	} else {
		ret = btrfs_set_prop(inode, "btrfs.compression", NULL, 0, 0);
		if (ret && ret != -ENODATA)
			goto out_drop;
		ip->flags &= ~(BTRFS_INODE_COMPRESS | BTRFS_INODE_NOCOMPRESS);
	}

	trans = btrfs_start_transaction(root, 1);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_drop;
	}

	btrfs_update_iflags(inode);
	inode_inc_iversion(inode);
	inode->i_ctime = current_fs_time(inode->i_sb);
	ret = btrfs_update_inode(trans, root, inode);

	btrfs_end_transaction(trans, root);
 out_drop:
	if (ret) {
		ip->flags = ip_oldflags;
		inode->i_flags = i_oldflags;
	}

 out_unlock:
	inode_unlock(inode);
	mnt_drop_write_file(file);
	return ret;
}

static int btrfs_ioctl_getversion(struct file *file, int __user *arg)
{
	struct inode *inode = file_inode(file);

	return put_user(inode->i_generation, arg);
}

static noinline int btrfs_ioctl_fitrim(struct file *file, void __user *arg)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(file_inode(file)->i_sb);
	struct btrfs_device *device;
	struct request_queue *q;
	struct fstrim_range range;
	u64 minlen = ULLONG_MAX;
	u64 num_devices = 0;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	rcu_read_lock();
	list_for_each_entry_rcu(device, &fs_info->fs_devices->devices,
				dev_list) {
		if (!device->bdev)
			continue;
		q = bdev_get_queue(device->bdev);
		if (blk_queue_discard(q)) {
			num_devices++;
			minlen = min((u64)q->limits.discard_granularity,
				     minlen);
		}
	}
	rcu_read_unlock();

	if (!num_devices)
		return -EOPNOTSUPP;
	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;

	/*
	 * NOTE: Don't truncate the range using super->total_bytes.  Bytenr of
	 * block group is in the logical address space, which can be any
	 * sectorsize aligned bytenr in  the range [0, U64_MAX].
	 */
	if (range.len < fs_info->sb->s_blocksize)
		return -EINVAL;

	range.minlen = max(range.minlen, minlen);
#ifdef MY_ABC_HERE
	ret = btrfs_trim_fs(fs_info->tree_root, &range, TRIM_SEND_TRIM);
#else /* MY_ABC_HERE */
	ret = btrfs_trim_fs(fs_info->tree_root, &range);
#endif /* MY_ABC_HERE */
	if (ret < 0)
		return ret;

	if (copy_to_user(arg, &range, sizeof(range)))
		return -EFAULT;

	return 0;
}

#ifdef MY_ABC_HERE
static noinline int btrfs_ioctl_hint_unused(struct file *file, void __user *arg)
{
	struct fstrim_range range;
	struct btrfs_fs_info *fs_info = btrfs_sb(file_inode(file)->i_sb);
	struct btrfs_device *device;
	u64 num_devices = 0;
	u64 total_bytes = btrfs_super_total_bytes(fs_info->super_copy);
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	rcu_read_lock();
	list_for_each_entry_rcu(device, &fs_info->fs_devices->devices,
				dev_list) {
		if (!device->bdev)
			continue;
		if (blk_queue_unused_hint(bdev_get_queue(device->bdev)))
			num_devices++;
	}
	rcu_read_unlock();

	if (!num_devices)
		return -EOPNOTSUPP;

	if (copy_from_user(&range, (struct fstrim_range __user *)arg, sizeof(range)))
		return -EFAULT;

	if (range.start > total_bytes ||
	    range.len < fs_info->sb->s_blocksize)
		return -EINVAL;

	range.len = min(range.len, total_bytes - range.start);

	ret = btrfs_trim_fs(fs_info->tree_root, &range, TRIM_SEND_HINT);

	if (!ret)
		btrfs_notice(fs_info, "total send %llu bytes hints", range.len);

	return ret;
}
#endif /* MY_ABC_HERE */

int btrfs_is_empty_uuid(u8 *uuid)
{
	int i;

	for (i = 0; i < BTRFS_UUID_SIZE; i++) {
		if (uuid[i])
			return 0;
	}
	return 1;
}

static noinline int create_subvol(struct inode *dir,
				  struct dentry *dentry,
				  char *name, int namelen,
				  u64 *async_transid,
				  struct btrfs_qgroup_inherit *inherit)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_key key;
	struct btrfs_root_item *root_item;
	struct btrfs_inode_item *inode_item;
	struct extent_buffer *leaf;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_root *new_root;
	struct btrfs_block_rsv block_rsv;
	struct timespec cur_time = current_fs_time(dir->i_sb);
	struct inode *inode;
	int ret;
	int err;
	u64 objectid;
	u64 new_dirid = BTRFS_FIRST_FREE_OBJECTID;
	u64 index = 0;
	u64 qgroup_reserved;
	uuid_le new_uuid;
#ifdef MY_ABC_HERE
	int syno_metadata_reserve = 0;
#endif /* MY_ABC_HERE */

	root_item = kzalloc(sizeof(*root_item), GFP_KERNEL);
	if (!root_item)
		return -ENOMEM;

	ret = btrfs_find_free_objectid(root->fs_info->tree_root, &objectid);
	if (ret)
		goto fail_free;

	/*
	 * Don't create subvolume whose level is not zero. Or qgroup will be
	 * screwed up since it assumes subvolume qgroup's level to be 0.
	 */
	if (btrfs_qgroup_level(objectid)) {
		ret = -ENOSPC;
		goto fail_free;
	}

	btrfs_init_block_rsv(&block_rsv, BTRFS_BLOCK_RSV_TEMP);
	/*
	 * The same as the snapshot creation, please see the comment
	 * of create_snapshot().
	 */
#if defined(MY_ABC_HERE)
	// 1 for dir_item_caseless
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		syno_metadata_reserve++;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	ret = btrfs_subvolume_reserve_metadata(root, &block_rsv,
					       8 + syno_metadata_reserve, &qgroup_reserved, false);
#else /* MY_ABC_HERE */
	ret = btrfs_subvolume_reserve_metadata(root, &block_rsv,
					       8, &qgroup_reserved, false);
#endif /* MY_ABC_HERE */
	if (ret)
		goto fail_free;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		btrfs_subvolume_release_metadata(root, &block_rsv,
						 qgroup_reserved);
		goto fail_free;
	}
	trans->block_rsv = &block_rsv;
	trans->bytes_reserved = block_rsv.size;

	ret = btrfs_qgroup_inherit(trans, root->fs_info, 0, objectid, inherit);
	if (ret)
		goto fail;
#ifdef MY_ABC_HERE
	ret = btrfs_usrquota_mksubvol(trans, root->fs_info, objectid);
	if (ret)
		goto fail;
#endif /* MY_ABC_HERE */

	leaf = btrfs_alloc_tree_block(trans, root, 0, objectid, NULL, 0, 0, 0);
	if (IS_ERR(leaf)) {
		ret = PTR_ERR(leaf);
		goto fail;
	}

	memset_extent_buffer(leaf, 0, 0, sizeof(struct btrfs_header));
	btrfs_set_header_bytenr(leaf, leaf->start);
	btrfs_set_header_generation(leaf, trans->transid);
	btrfs_set_header_backref_rev(leaf, BTRFS_MIXED_BACKREF_REV);
	btrfs_set_header_owner(leaf, objectid);

	write_extent_buffer(leaf, root->fs_info->fsid, btrfs_header_fsid(),
			    BTRFS_FSID_SIZE);
	write_extent_buffer(leaf, root->fs_info->chunk_tree_uuid,
			    btrfs_header_chunk_tree_uuid(leaf),
			    BTRFS_UUID_SIZE);
	btrfs_mark_buffer_dirty(leaf);

	inode_item = &root_item->inode;
	btrfs_set_stack_inode_generation(inode_item, 1);
	btrfs_set_stack_inode_size(inode_item, 3);
	btrfs_set_stack_inode_nlink(inode_item, 1);
	btrfs_set_stack_inode_nbytes(inode_item, root->nodesize);
	btrfs_set_stack_inode_mode(inode_item, S_IFDIR | 0755);

#ifdef MY_ABC_HERE
	btrfs_set_root_flags(root_item, BTRFS_ROOT_SUBVOL_CMPR_RATIO);
#else
	btrfs_set_root_flags(root_item, 0);
#endif /* MY_ABC_HERE */
	btrfs_set_root_limit(root_item, 0);
	btrfs_set_stack_inode_flags(inode_item, BTRFS_INODE_ROOT_ITEM_INIT);

	btrfs_set_root_bytenr(root_item, leaf->start);
	btrfs_set_root_generation(root_item, trans->transid);
	btrfs_set_root_level(root_item, 0);
	btrfs_set_root_refs(root_item, 1);
	btrfs_set_root_used(root_item, leaf->len);
	btrfs_set_root_last_snapshot(root_item, 0);

	btrfs_set_root_generation_v2(root_item,
			btrfs_root_generation(root_item));
	uuid_le_gen(&new_uuid);
	memcpy(root_item->uuid, new_uuid.b, BTRFS_UUID_SIZE);
	btrfs_set_stack_timespec_sec(&root_item->otime, cur_time.tv_sec);
	btrfs_set_stack_timespec_nsec(&root_item->otime, cur_time.tv_nsec);
	root_item->ctime = root_item->otime;
	btrfs_set_root_ctransid(root_item, trans->transid);
	btrfs_set_root_otransid(root_item, trans->transid);

	btrfs_tree_unlock(leaf);
	free_extent_buffer(leaf);
	leaf = NULL;

	btrfs_set_root_dirid(root_item, new_dirid);

	key.objectid = objectid;
	key.offset = 0;
	key.type = BTRFS_ROOT_ITEM_KEY;
	ret = btrfs_insert_root(trans, root->fs_info->tree_root, &key,
				root_item);
	if (ret)
		goto fail;

	key.offset = (u64)-1;
	new_root = btrfs_read_fs_root_no_name(root->fs_info, &key);
	if (IS_ERR(new_root)) {
		ret = PTR_ERR(new_root);
		btrfs_abort_transaction(trans, root, ret);
		goto fail;
	}

	btrfs_record_root_in_trans(trans, new_root);

	ret = btrfs_create_subvol_root(trans, new_root, root, new_dirid);
	if (ret) {
		/* We potentially lose an unused inode item here */
		btrfs_abort_transaction(trans, root, ret);
		goto fail;
	}

	mutex_lock(&new_root->objectid_mutex);
	new_root->highest_objectid = new_dirid;
	mutex_unlock(&new_root->objectid_mutex);

	/*
	 * insert the directory item
	 */
	ret = btrfs_set_inode_index(dir, &index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto fail;
	}

	ret = btrfs_insert_dir_item(trans, root,
				    name, namelen, dir, &key,
				    BTRFS_FT_DIR, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto fail;
	}

	btrfs_i_size_write(dir, dir->i_size + namelen * 2);
	ret = btrfs_update_inode(trans, root, dir);
	BUG_ON(ret);

	ret = btrfs_add_root_ref(trans, root->fs_info->tree_root,
				 objectid, root->root_key.objectid,
				 btrfs_ino(dir), index, name, namelen);
	BUG_ON(ret);

	ret = btrfs_uuid_tree_add(trans, root->fs_info->uuid_root,
				  root_item->uuid, BTRFS_UUID_KEY_SUBVOL,
				  objectid);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);

fail:
	kfree(root_item);
	trans->block_rsv = NULL;
	trans->bytes_reserved = 0;
	btrfs_subvolume_release_metadata(root, &block_rsv, qgroup_reserved);

	if (async_transid) {
		*async_transid = trans->transid;
		err = btrfs_commit_transaction_async(trans, root, 1);
		if (err)
			err = btrfs_commit_transaction(trans, root);
	} else {
		err = btrfs_commit_transaction(trans, root);
	}
	if (err && !ret)
		ret = err;

	if (!ret) {
#ifdef MY_ABC_HERE
		inode = btrfs_lookup_dentry(dir, dentry, 0);
#else
		inode = btrfs_lookup_dentry(dir, dentry);
#endif /* MY_ABC_HERE */
		if (IS_ERR(inode))
			return PTR_ERR(inode);
		d_instantiate(dentry, inode);
	}
	return ret;

fail_free:
	kfree(root_item);
	return ret;
}

static void btrfs_wait_for_no_snapshoting_writes(struct btrfs_root *root)
{
	s64 writers;
	DEFINE_WAIT(wait);

	do {
		prepare_to_wait(&root->subv_writers->wait, &wait,
				TASK_UNINTERRUPTIBLE);

		writers = percpu_counter_sum(&root->subv_writers->counter);
		if (writers)
			schedule();

		finish_wait(&root->subv_writers->wait, &wait);
	} while (writers);
}

static int create_snapshot(struct btrfs_root *root, struct inode *dir,
			   struct dentry *dentry, char *name, int namelen,
			   u64 *async_transid, bool readonly,
#ifdef MY_ABC_HERE
			   struct btrfs_qgroup_inherit *inherit,
			   u64 copy_limit_from)
#else
			   struct btrfs_qgroup_inherit *inherit)
#endif /* MY_ABC_HERE */
{
	struct inode *inode;
	struct btrfs_pending_snapshot *pending_snapshot;
	struct btrfs_trans_handle *trans;
#ifdef MY_ABC_HERE
	u64 reserve_usrquota_items = 0;
	u64 reserve_usrquota_leafs;
#endif /* MY_ABC_HERE */
	int ret;
#ifdef MY_ABC_HERE
#else
	bool snapshot_force_cow = false;
#endif /* MY_ABC_HERE */
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	int syno_metadata_reserve = 0;
#endif /* MY_ABC_HERE || MY_ABC_HERE */

	if (!test_bit(BTRFS_ROOT_REF_COWS, &root->state))
		return -EINVAL;

	if (atomic_read(&root->nr_swapfiles)) {
		btrfs_warn(root->fs_info,
			   "cannot snapshot subvolume with active swapfile");
		return -ETXTBSY;
	}

	pending_snapshot = kzalloc(sizeof(*pending_snapshot), GFP_NOFS);
	if (!pending_snapshot)
		return -ENOMEM;

	pending_snapshot->root_item = kzalloc(sizeof(struct btrfs_root_item),
			GFP_NOFS);
	pending_snapshot->path = btrfs_alloc_path();
	if (!pending_snapshot->root_item || !pending_snapshot->path) {
		ret = -ENOMEM;
		goto free_pending;
	}

#ifdef MY_ABC_HERE
#else
	atomic_inc(&root->will_be_snapshoted);
	smp_mb__after_atomic();
	btrfs_wait_for_no_snapshoting_writes(root);

#ifdef MY_ABC_HERE
	ret = btrfs_start_delalloc_inodes(root, 0, 1);
#else
	ret = btrfs_start_delalloc_inodes(root, 0);
#endif /* MY_ABC_HERE */
	if (ret)
		goto dec_and_free;

	atomic_inc(&root->snapshot_force_cow);
	snapshot_force_cow = true;

	btrfs_wait_ordered_extents(root, -1, 0, (u64)-1);
#endif /* MY_ABC_HERE */

	btrfs_init_block_rsv(&pending_snapshot->block_rsv,
			     BTRFS_BLOCK_RSV_TEMP);
#ifdef MY_ABC_HERE
	ret = btrfs_usrquota_calc_reserve_snap(root, copy_limit_from, &reserve_usrquota_items);
	if (ret < 0)
		goto dec_and_free;
	reserve_usrquota_leafs = 1 + div_u64(reserve_usrquota_items,
					(u32)BTRFS_USRQUOTA_MAX_ITEMS_LEAF(root));
	syno_metadata_reserve += (int)reserve_usrquota_leafs;
#endif /* MY_ABC_HERE */
#if defined(MY_ABC_HERE)
	// 1 for dir_item_caseless
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS)
		syno_metadata_reserve++;
#endif /* MY_ABC_HERE */

	/*
	 * 1 - parent dir inode
	 * 2 - dir entries
	 * 1 - root item
	 * 2 - root ref/backref
	 * 1 - root of snapshot
	 * 1 - UUID item
	 */
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	ret = btrfs_subvolume_reserve_metadata(BTRFS_I(dir)->root,
					&pending_snapshot->block_rsv,
					(int)(8 + syno_metadata_reserve),
					&pending_snapshot->qgroup_reserved,
					false);
#else /* MY_ABC_HERE || MY_ABC_HERE */
	ret = btrfs_subvolume_reserve_metadata(BTRFS_I(dir)->root,
					&pending_snapshot->block_rsv, 8,
					&pending_snapshot->qgroup_reserved,
					false);
#endif /* MY_ABC_HERE || MY_ABC_HERE */
	if (ret)
		goto dec_and_free;

	pending_snapshot->dentry = dentry;
	pending_snapshot->root = root;
	pending_snapshot->readonly = readonly;
	pending_snapshot->dir = dir;
	pending_snapshot->inherit = inherit;
#ifdef MY_ABC_HERE
	pending_snapshot->copy_limit_from = copy_limit_from;
#endif /* MY_ABC_HERE */

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto fail;
	}

	spin_lock(&root->fs_info->trans_lock);
	list_add(&pending_snapshot->list,
		 &trans->transaction->pending_snapshots);
	spin_unlock(&root->fs_info->trans_lock);
#ifdef MY_ABC_HERE
	trans->pending_snap = pending_snapshot;
#endif /* MY_ABC_HERE */
	if (async_transid) {
		*async_transid = trans->transid;
		ret = btrfs_commit_transaction_async(trans,
				     root->fs_info->extent_root, 1);
		if (ret)
			ret = btrfs_commit_transaction(trans, root);
	} else {
		ret = btrfs_commit_transaction(trans,
					       root->fs_info->extent_root);
	}
	if (ret)
		goto fail;

	ret = pending_snapshot->error;
	if (ret)
		goto fail;

	ret = btrfs_orphan_cleanup(pending_snapshot->snap);
	if (ret)
		goto fail;

#ifdef MY_ABC_HERE
	inode = btrfs_lookup_dentry(d_inode(dentry->d_parent), dentry, 0);
#else
	inode = btrfs_lookup_dentry(d_inode(dentry->d_parent), dentry);
#endif /* MY_ABC_HERE */
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto fail;
	}

	d_instantiate(dentry, inode);
	ret = 0;
fail:
	btrfs_subvolume_release_metadata(BTRFS_I(dir)->root,
					 &pending_snapshot->block_rsv,
					 pending_snapshot->qgroup_reserved);
dec_and_free:
#ifdef MY_ABC_HERE
#else
	if (snapshot_force_cow)
		atomic_dec(&root->snapshot_force_cow);
	if (atomic_dec_and_test(&root->will_be_snapshoted))
		wake_up_atomic_t(&root->will_be_snapshoted);
#endif /* MY_ABC_HERE */
free_pending:
	kfree(pending_snapshot->root_item);
	btrfs_free_path(pending_snapshot->path);
	kfree(pending_snapshot);

	return ret;
}

/*  copy of may_delete in fs/namei.c()
 *	Check whether we can remove a link victim from directory dir, check
 *  whether the type of victim is right.
 *  1. We can't do it if dir is read-only (done in permission())
 *  2. We should have write and exec permissions on dir
 *  3. We can't remove anything from append-only dir
 *  4. We can't do anything with immutable dir (done in permission())
 *  5. If the sticky bit on dir is set we should either
 *	a. be owner of dir, or
 *	b. be owner of victim, or
 *	c. have CAP_FOWNER capability
 *  6. If the victim is append-only or immutable we can't do anything with
 *     links pointing to it.
 *  7. If we were asked to remove a directory and victim isn't one - ENOTDIR.
 *  8. If we were asked to remove a non-directory and victim isn't one - EISDIR.
 *  9. We can't remove a root or mountpoint.
 * 10. We don't allow removal of NFS sillyrenamed files; it's handled by
 *     nfs_async_unlink().
 */

static int btrfs_may_delete(struct inode *dir, struct dentry *victim, int isdir)
{
	int error;

	if (d_really_is_negative(victim))
		return -ENOENT;

	BUG_ON(d_inode(victim->d_parent) != dir);
	audit_inode_child(dir, victim, AUDIT_TYPE_CHILD_DELETE);

	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;
	if (check_sticky(dir, d_inode(victim)) || IS_APPEND(d_inode(victim)) ||
	    IS_IMMUTABLE(d_inode(victim)) || IS_SWAPFILE(d_inode(victim)))
		return -EPERM;
	if (isdir) {
		if (!d_is_dir(victim))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (d_is_dir(victim))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

/* copy of may_create in fs/namei.c() */
static inline int btrfs_may_create(struct inode *dir, struct dentry *child)
{
	if (d_really_is_positive(child))
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}

/*
 * Create a new subvolume below @parent.  This is largely modeled after
 * sys_mkdirat and vfs_mkdir, but we only do a single component lookup
 * inside this filesystem so it's quite a bit simpler.
 */
static noinline int btrfs_mksubvol(struct path *parent,
				   char *name, int namelen,
				   struct btrfs_root *snap_src,
				   u64 *async_transid, bool readonly,
#ifdef MY_ABC_HERE
				   struct btrfs_qgroup_inherit *inherit,
				   u64 copy_limit_from)
#else
				   struct btrfs_qgroup_inherit *inherit)
#endif /* MY_ABC_HERE */
{
	struct inode *dir  = d_inode(parent->dentry);
	struct dentry *dentry;
	int error;

	error = mutex_lock_killable_nested(&dir->i_mutex, I_MUTEX_PARENT);
	if (error == -EINTR)
		return error;

	dentry = lookup_one_len(name, parent->dentry, namelen);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_unlock;

	error = btrfs_may_create(dir, dentry);
	if (error)
		goto out_dput;

	/*
	 * even if this name doesn't exist, we may get hash collisions.
	 * check for them now when we can safely fail
	 */
	error = btrfs_check_dir_item_collision(BTRFS_I(dir)->root,
#ifdef MY_ABC_HERE
					       dir->i_ino, 1, name,
#else
					       dir->i_ino, name,
#endif /* MY_ABC_HERE */
					       namelen);
	if (error)
		goto out_dput;

	down_read(&BTRFS_I(dir)->root->fs_info->subvol_sem);

	if (btrfs_root_refs(&BTRFS_I(dir)->root->root_item) == 0)
		goto out_up_read;

	if (snap_src) {
		error = create_snapshot(snap_src, dir, dentry, name, namelen,
#ifdef MY_ABC_HERE
					async_transid, readonly, inherit, copy_limit_from);
#else
					async_transid, readonly, inherit);
#endif /* MY_ABC_HERE */
	} else {
		error = create_subvol(dir, dentry, name, namelen,
				      async_transid, inherit);
	}
	if (!error)
		fsnotify_mkdir(dir, dentry);
out_up_read:
	up_read(&BTRFS_I(dir)->root->fs_info->subvol_sem);
out_dput:
	dput(dentry);
out_unlock:
	inode_unlock(dir);
	return error;
}

#ifdef MY_ABC_HERE
static noinline int btrfs_mksnapshot(struct path *parent,
				   char *name, int namelen,
				   struct btrfs_root *root,
				   u64 *async_transid, bool readonly,
#ifdef MY_ABC_HERE
				   struct btrfs_qgroup_inherit *inherit,
				   u64 copy_limit_from)
#else
				   struct btrfs_qgroup_inherit *inherit)
#endif /* MY_ABC_HERE */
{
	int ret;
	bool snapshot_force_cow = false;

	atomic_inc(&root->will_be_snapshoted);
	smp_mb__after_atomic();
	btrfs_wait_for_no_snapshoting_writes(root);

#ifdef MY_ABC_HERE
	ret = btrfs_start_delalloc_inodes(root, 0, 1);
#else
	ret = btrfs_start_delalloc_inodes(root, 0);
#endif /* MY_ABC_HERE */
	if (ret)
		goto out;

	atomic_inc(&root->snapshot_force_cow);
	snapshot_force_cow = true;

	btrfs_wait_ordered_extents(root, -1, 0, (u64)-1);

	ret = btrfs_mksubvol(parent, name, namelen,
					     root,
#ifdef MY_ABC_HERE
					     async_transid, readonly, inherit,
					     copy_limit_from);
#else
					     transid, readonly, inherit);
#endif /* MY_ABC_HERE */

out:
	if (snapshot_force_cow)
		atomic_dec(&root->snapshot_force_cow);
	if (atomic_dec_and_test(&root->will_be_snapshoted))
		wake_up_atomic_t(&root->will_be_snapshoted);

	return ret;
}
#endif /* MY_ABC_HERE */

/*
 * When we're defragging a range, we don't want to kick it off again
 * if it is really just waiting for delalloc to send it down.
 * If we find a nice big extent or delalloc range for the bytes in the
 * file you want to defrag, we return 0 to let you know to skip this
 * part of the file
 */
static int check_defrag_in_cache(struct inode *inode, u64 offset, u32 thresh)
{
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_map *em = NULL;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	u64 end;

	read_lock(&em_tree->lock);
	em = lookup_extent_mapping(em_tree, offset, PAGE_CACHE_SIZE);
	read_unlock(&em_tree->lock);

	if (em) {
		end = extent_map_end(em);
		free_extent_map(em);
		if (end - offset > thresh)
			return 0;
	}
	/* if we already have a nice delalloc here, just stop */
	thresh /= 2;
	end = count_range_bits(io_tree, &offset, offset + thresh,
			       thresh, EXTENT_DELALLOC, 1);
	if (end >= thresh)
		return 0;
	return 1;
}

/*
 * helper function to walk through a file and find extents
 * newer than a specific transid, and smaller than thresh.
 *
 * This is used by the defragging code to find new and small
 * extents
 */
static int find_new_extents(struct btrfs_root *root,
			    struct inode *inode, u64 newer_than,
			    u64 *off, u32 thresh)
{
	struct btrfs_path *path;
	struct btrfs_key min_key;
	struct extent_buffer *leaf;
	struct btrfs_file_extent_item *extent;
	int type;
	int ret;
	u64 ino = btrfs_ino(inode);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	min_key.objectid = ino;
	min_key.type = BTRFS_EXTENT_DATA_KEY;
	min_key.offset = *off;

	while (1) {
		ret = btrfs_search_forward(root, &min_key, path, newer_than);
		if (ret != 0)
			goto none;
process_slot:
		if (min_key.objectid != ino)
			goto none;
		if (min_key.type != BTRFS_EXTENT_DATA_KEY)
			goto none;

		leaf = path->nodes[0];
		extent = btrfs_item_ptr(leaf, path->slots[0],
					struct btrfs_file_extent_item);

		type = btrfs_file_extent_type(leaf, extent);
		if (type == BTRFS_FILE_EXTENT_REG &&
		    btrfs_file_extent_num_bytes(leaf, extent) < thresh &&
		    check_defrag_in_cache(inode, min_key.offset, thresh)) {
			*off = min_key.offset;
			btrfs_free_path(path);
			return 0;
		}

		path->slots[0]++;
		if (path->slots[0] < btrfs_header_nritems(leaf)) {
			btrfs_item_key_to_cpu(leaf, &min_key, path->slots[0]);
			goto process_slot;
		}

		if (min_key.offset == (u64)-1)
			goto none;

		min_key.offset++;
		btrfs_release_path(path);
	}
none:
	btrfs_free_path(path);
	return -ENOENT;
}

static struct extent_map *defrag_lookup_extent(struct inode *inode, u64 start)
{
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_io_tree *io_tree = &BTRFS_I(inode)->io_tree;
	struct extent_map *em;
	u64 len = PAGE_CACHE_SIZE;

	/*
	 * hopefully we have this extent in the tree already, try without
	 * the full extent lock
	 */
	read_lock(&em_tree->lock);
	em = lookup_extent_mapping(em_tree, start, len);
	read_unlock(&em_tree->lock);

	if (!em) {
		struct extent_state *cached = NULL;
		u64 end = start + len - 1;

		/* get the big lock and read metadata off disk */
		lock_extent_bits(io_tree, start, end, &cached);
		em = btrfs_get_extent(inode, NULL, 0, start, len, 0);
		unlock_extent_cached(io_tree, start, end, &cached, GFP_NOFS);

		if (IS_ERR(em))
			return NULL;
	}

	return em;
}

#ifdef MY_ABC_HERE
/*
 * Check if extent item usage is below threshold, this traverse the file
 * extent data item in the way that clone range does.
 */
static int defrag_check_extent_usage(struct inode *inode,
			        struct btrfs_ioctl_defrag_range_args *range,
			        struct ulist *disko_ulist, u64 start, u64 *endoff, u64 *release_size)
{
	int ret = 0;
	int extent_rewrite = 0;
	int slot;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct ulist_node *unode;
	struct btrfs_path *path = NULL;
	struct btrfs_file_extent_item *item;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	struct btrfs_trans_handle *trans;
	u8 type;
	u64 extent_item_use = 0;
	u32 syno_ratio_denom = 3; // Use 2/3 as default value
	u32 syno_ratio_nom = 2;
	u32 syno_thresh = 8 * 1024 * 1024; // Default thresh is 8MiB
	u64 extent_disko = 0, extent_diskl = 0, extent_datao = 0;
	u64 num_bytes;
	u64 search_end = 0;
	u32 nritems;
	u64 relative_offset;
	u64 mode = CHECK_CROSS_REF_NORMAL;

	if (range->syno_ratio_denom != 0 && range->syno_ratio_nom != 0) {
		syno_ratio_denom = range->syno_ratio_denom;
		syno_ratio_nom = range->syno_ratio_nom;
	}
	if (range->syno_thresh != 0)
		syno_thresh = (u32)range->syno_thresh * 4096;
	if (range->flags & BTRFS_DEFRAG_RANGE_SKIP_FAST_SNAPSHOT_CHECK)
		mode = CHECK_CROSS_REF_SKIP_FAST_SNAPSHOT;

	path = btrfs_alloc_path();
	if (!path) {
		extent_rewrite = -ENOMEM;
		goto out;
	}

	path->reada = READA_FORWARD;
	path->leave_spinning = 1;

	key.objectid = btrfs_ino(inode);
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = start;

again:
	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0) {
		extent_rewrite = ret;
		goto out;
	}

	/*
	 * First search, if no extent item that starts at offset off was
	 * found but the previous item is an extent item, it's possible
	 * it might overlap our target range, therefore process it.
	 */
	if (key.offset == start && ret > 0 && path->slots[0] > 0) {
		btrfs_item_key_to_cpu(path->nodes[0], &key,
				      path->slots[0] - 1);
		if (key.type == BTRFS_EXTENT_DATA_KEY)
			path->slots[0]--;
	}
	nritems = btrfs_header_nritems(path->nodes[0]);
	if (path->slots[0] >= nritems) {
		ret = btrfs_next_leaf(root, path);
		if (ret < 0) {
			extent_rewrite = ret;
			goto out;
		}
		if (ret > 0) {
			*endoff = start + extent_diskl - 1;
			goto out;
		}
	}
	leaf = path->nodes[0];
	slot = path->slots[0];

	btrfs_item_key_to_cpu(leaf, &key, slot);
	if (btrfs_key_type(&key) > BTRFS_EXTENT_DATA_KEY ||
	    key.objectid != btrfs_ino(inode)) {
		*endoff = (u64)-1; // skip to the end
		goto out;
	}

	if (btrfs_key_type(&key) != BTRFS_EXTENT_DATA_KEY) {
		btrfs_release_path(path);
		key.offset++;
		goto again;
	}
	item = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);
	type = btrfs_file_extent_type(leaf, item);
	if (type == BTRFS_FILE_EXTENT_INLINE) {
		*endoff = (u64)-1; // skip to the end
		goto out;
	}
	extent_disko = btrfs_file_extent_disk_bytenr(leaf, item);
	extent_diskl = btrfs_file_extent_disk_num_bytes(leaf, item);
	extent_datao = btrfs_file_extent_offset(leaf, item);
	num_bytes = btrfs_file_extent_num_bytes(leaf, item);

	*endoff = key.offset + num_bytes - 1;
	if (extent_disko == 0) {
		goto out;
	}

	unode = ulist_search(disko_ulist, extent_disko);
	if (unode) {
		btrfs_free_path(path);
		return unode->aux;
	}

	if (btrfs_file_extent_compression(leaf, item) ||
	    btrfs_file_extent_encryption(leaf, item) ||
	    btrfs_file_extent_other_encoding(leaf, item) ||
	    btrfs_extent_readonly(root, extent_disko))
		goto add_list;

	/*
	 * If this EXTENT_ITEM spans across the file offset beyond our range,
	 * don't defrag it.
	 */
	relative_offset = key.offset - extent_datao;
	if (relative_offset >= LLONG_MAX)
		relative_offset = 0;
	if (relative_offset < range->start)
		goto add_list;

	btrfs_release_path(path);

	/*
	 * look for other files referencing this extent, if we
	 * find any we must cow
	 */
	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans))
		goto add_list;

	/*
	 * There's possible race between the time this check is done
	 * and before we actuaully rewrite all extent data key that
	 * reference this extent item.
	 */
	ret = btrfs_cross_ref_exist(root, btrfs_ino(inode),
				    key.offset - extent_datao, extent_disko, mode);
	btrfs_end_transaction(trans, root);
	if (ret)
		goto add_list;

	extent_item_use = num_bytes;
	search_end = key.offset + extent_diskl - extent_datao;
	key.offset += num_bytes;
	while (1) {
		u64 disko, datal;

		path->leave_spinning = 1;
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0) {
			extent_rewrite = ret;
			goto out;
		}
		nritems = btrfs_header_nritems(path->nodes[0]);
		if (path->slots[0] >= nritems) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0) {
				extent_rewrite = ret;
				goto out;
			}
			if (ret > 0)
				break;
		}
		leaf = path->nodes[0];
		slot = path->slots[0];
		btrfs_item_key_to_cpu(leaf, &key, slot);
		if (btrfs_key_type(&key) > BTRFS_EXTENT_DATA_KEY ||
		    key.objectid != btrfs_ino(inode))
			break;
		if (btrfs_key_type(&key) == BTRFS_EXTENT_DATA_KEY) {
			if (key.offset > search_end)
				break;
			item = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);
			type = btrfs_file_extent_type(leaf, item);
			if (type == BTRFS_FILE_EXTENT_INLINE)
				goto next;
			disko = btrfs_file_extent_disk_bytenr(leaf, item);
			datal = btrfs_file_extent_num_bytes(leaf, item);
			/*
			 * This extent data points to a hole
			 */
			if (disko == 0)
				goto next;
			/*
			 * <---written---><---prealloc--->
			 * <------- extent item 1 ------->
			 * There are some parts of extent that are prealloc, so don't
			 * rewrite this. Otherwise, we'll end up like the following,
			 * <---written--->                 <---prealloc--->
			 * <extent item 2>  <------- extent item 1 ------->
			 */
			if (disko < extent_disko || disko >= extent_disko + extent_diskl)
				goto next;
			if (type == BTRFS_FILE_EXTENT_PREALLOC)
				goto add_list;
			/*
			 * If this EXTENT_ITEM spans across the file offset beyond our range,
			 * don't defrag it.
			 */
			if (range->len != (u64) -1 && range->len != 0 &&
			    key.offset + datal > range->start + range->len)
				goto add_list;
			extent_item_use += datal;
		}
next:
		btrfs_release_path(path);
		key.offset++;
	}
	if (extent_item_use * syno_ratio_denom <= extent_diskl * syno_ratio_nom ||
		extent_diskl >= extent_item_use + syno_thresh) {
		extent_rewrite = 1;
		*release_size += extent_diskl - extent_item_use;
	}
add_list:
	btrfs_release_path(path);
	/*
	 * bytenr is stored in val.
	 * If the extent_item is to be rewritten, we have aux = 1.
	 * Otherwise, aux = 0.
	 */
	if (ulist_add_lru_adjust(disko_ulist, extent_disko, extent_rewrite, GFP_NOFS) &&
		disko_ulist->nnodes > ULIST_NODES_MAX)
		ulist_remove_first(disko_ulist);
out:
	btrfs_free_path(path);
	return extent_rewrite;
}
#endif /* MY_ABC_HERE */

static bool defrag_check_next_extent(struct inode *inode, struct extent_map *em)
{
	struct extent_map *next;
	bool ret = true;

	/* this is the last extent */
	if (em->start + em->len >= i_size_read(inode))
		return false;

	next = defrag_lookup_extent(inode, em->start + em->len);
	if (!next || next->block_start >= EXTENT_MAP_LAST_BYTE)
		ret = false;
	else if ((em->block_start + em->block_len == next->block_start) &&
		 (em->block_len > SZ_128K && next->block_len > SZ_128K))
		ret = false;

	free_extent_map(next);
	return ret;
}

static int should_defrag_range(struct inode *inode, u64 start, u32 thresh,
			       u64 *last_len, u64 *skip, u64 *defrag_end,
#ifdef MY_ABC_HERE
			       int compress,
			       struct btrfs_ioctl_defrag_range_args *range,
			       struct ulist *disko_ulist,
			       u64 *release_size)
#else
			       int compress)
#endif /* MY_ABC_HERE */
{
	struct extent_map *em;
	int ret = 1;
	bool next_mergeable = true;
	bool prev_mergeable = true;

#ifdef MY_ABC_HERE
	if (range->flags & BTRFS_DEFRAG_RANGE_SYNO_DEFRAG) {
		u64 endoff = 0;
		ret = defrag_check_extent_usage(inode, range,
				        disko_ulist, start, &endoff, release_size);
		*defrag_end = *skip = endoff;
		return ret;
	}
#endif /* MY_ABC_HERE */

	/*
	 * make sure that once we start defragging an extent, we keep on
	 * defragging it
	 */
	if (start < *defrag_end)
		return 1;

	*skip = 0;

	em = defrag_lookup_extent(inode, start);
	if (!em)
		return 0;

	/* this will cover holes, and inline extents */
	if (em->block_start >= EXTENT_MAP_LAST_BYTE) {
		ret = 0;
		goto out;
	}

	if (!*defrag_end)
		prev_mergeable = false;

	next_mergeable = defrag_check_next_extent(inode, em);
	/*
	 * we hit a real extent, if it is big or the next extent is not a
	 * real extent, don't bother defragging it
	 */
	if (!compress && (*last_len == 0 || *last_len >= thresh) &&
	    (em->len >= thresh || (!next_mergeable && !prev_mergeable)))
		ret = 0;
out:
	/*
	 * last_len ends up being a counter of how many bytes we've defragged.
	 * every time we choose not to defrag an extent, we reset *last_len
	 * so that the next tiny extent will force a defrag.
	 *
	 * The end result of this is that tiny extents before a single big
	 * extent will force at least part of that big extent to be defragged.
	 */
	if (ret) {
		*defrag_end = extent_map_end(em);
	} else {
		*last_len = 0;
		*skip = extent_map_end(em);
		*defrag_end = 0;
	}

	free_extent_map(em);
	return ret;
}

/*
 * it doesn't do much good to defrag one or two pages
 * at a time.  This pulls in a nice chunk of pages
 * to COW and defrag.
 *
 * It also makes sure the delalloc code has enough
 * dirty data to avoid making new small extents as part
 * of the defrag
 *
 * It's a good idea to start RA on this range
 * before calling this.
 */
static int cluster_pages_for_defrag(struct inode *inode,
				    struct page **pages,
				    unsigned long start_index,
				    unsigned long num_pages)
{
	unsigned long file_end;
	u64 isize = i_size_read(inode);
	u64 page_start;
	u64 page_end;
	u64 page_cnt;
	int ret;
	int i;
	int i_done;
	struct btrfs_ordered_extent *ordered;
	struct extent_state *cached_state = NULL;
	struct extent_io_tree *tree;
	gfp_t mask = btrfs_alloc_write_mask(inode->i_mapping);

	file_end = (isize - 1) >> PAGE_CACHE_SHIFT;
	if (!isize || start_index > file_end)
		return 0;

	page_cnt = min_t(u64, (u64)num_pages, (u64)file_end - start_index + 1);

	ret = btrfs_delalloc_reserve_space(inode,
			start_index << PAGE_CACHE_SHIFT,
			page_cnt << PAGE_CACHE_SHIFT);
	if (ret)
		return ret;
	i_done = 0;
	tree = &BTRFS_I(inode)->io_tree;

	/* step one, lock all the pages */
	for (i = 0; i < page_cnt; i++) {
		struct page *page;
again:
		page = find_or_create_page(inode->i_mapping,
					   start_index + i, mask);
		if (!page)
			break;

		page_start = page_offset(page);
		page_end = page_start + PAGE_CACHE_SIZE - 1;
		while (1) {
			lock_extent_bits(tree, page_start, page_end,
					 &cached_state);
			ordered = btrfs_lookup_ordered_extent(inode,
							      page_start);
			unlock_extent_cached(tree, page_start, page_end,
					     &cached_state, GFP_NOFS);
			if (!ordered)
				break;

			unlock_page(page);
			btrfs_start_ordered_extent(inode, ordered, 1);
			btrfs_put_ordered_extent(ordered);
			lock_page(page);
			/*
			 * we unlocked the page above, so we need check if
			 * it was released or not.
			 */
			if (page->mapping != inode->i_mapping) {
				unlock_page(page);
				page_cache_release(page);
				goto again;
			}
		}

		if (!PageUptodate(page)) {
			btrfs_readpage(NULL, page);
			lock_page(page);
			if (!PageUptodate(page)) {
				unlock_page(page);
				page_cache_release(page);
				ret = -EIO;
				break;
			}
		}

		if (page->mapping != inode->i_mapping) {
			unlock_page(page);
			page_cache_release(page);
			goto again;
		}

		pages[i] = page;
		i_done++;
	}
	if (!i_done || ret)
		goto out;

	if (!(inode->i_sb->s_flags & MS_ACTIVE))
		goto out;

	/*
	 * so now we have a nice long stream of locked
	 * and up to date pages, lets wait on them
	 */
	for (i = 0; i < i_done; i++)
		wait_on_page_writeback(pages[i]);

	page_start = page_offset(pages[0]);
	page_end = page_offset(pages[i_done - 1]) + PAGE_CACHE_SIZE;

	lock_extent_bits(&BTRFS_I(inode)->io_tree,
			 page_start, page_end - 1, &cached_state);
	clear_extent_bit(&BTRFS_I(inode)->io_tree, page_start,
			  page_end - 1, EXTENT_DIRTY | EXTENT_DELALLOC |
			  EXTENT_DO_ACCOUNTING | EXTENT_DEFRAG, 0, 0,
			  &cached_state, GFP_NOFS);

	if (i_done != page_cnt) {
		spin_lock(&BTRFS_I(inode)->lock);
		BTRFS_I(inode)->outstanding_extents++;
		spin_unlock(&BTRFS_I(inode)->lock);
		btrfs_delalloc_release_space(inode,
				start_index << PAGE_CACHE_SHIFT,
				(page_cnt - i_done) << PAGE_CACHE_SHIFT);
	}


	set_extent_defrag(&BTRFS_I(inode)->io_tree, page_start, page_end - 1,
			  &cached_state);

	unlock_extent_cached(&BTRFS_I(inode)->io_tree,
			     page_start, page_end - 1, &cached_state,
			     GFP_NOFS);

	for (i = 0; i < i_done; i++) {
		clear_page_dirty_for_io(pages[i]);
		ClearPageChecked(pages[i]);
		set_page_extent_mapped(pages[i]);
		set_page_dirty(pages[i]);
		unlock_page(pages[i]);
		page_cache_release(pages[i]);
	}
	return i_done;
out:
	for (i = 0; i < i_done; i++) {
		unlock_page(pages[i]);
		page_cache_release(pages[i]);
	}
	btrfs_delalloc_release_space(inode,
			start_index << PAGE_CACHE_SHIFT,
			page_cnt << PAGE_CACHE_SHIFT);
	return ret;

}

#ifdef MY_ABC_HERE
extern int write_buf(struct file *filp, const void *buf, u32 len, loff_t *off);
#endif

int btrfs_defrag_file(struct inode *inode, struct file *file,
		      struct btrfs_ioctl_defrag_range_args *range,
		      u64 newer_than, unsigned long max_to_defrag)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct file_ra_state *ra = NULL;
	unsigned long last_index;
	u64 isize = i_size_read(inode);
	u64 last_len = 0;
	u64 skip = 0;
	u64 defrag_end = 0;
	u64 newer_off = range->start;
	unsigned long i;
	unsigned long ra_index = 0;
	int ret;
	int defrag_count = 0;
#ifdef MY_ABC_HERE
	int compress_type = BTRFS_COMPRESS_DEFAULT;
#else
	int compress_type = BTRFS_COMPRESS_ZLIB;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	u64 last_rec_pos = 0;
	u64 one_tenth_isize = i_size_read(inode) / 10;
	int should_defrag_range_ret = 0;
	int defrag_success = 0;
	struct ulist *disko_ulist = NULL;
	time_t last_show = get_seconds();
	int print_stdout = 0;
	u64 release_size = 0;
	struct file *file_stdout = NULL;
	loff_t off;
	char buf[512];
#endif /* MY_ABC_HERE */
	u32 extent_thresh = range->extent_thresh;
	unsigned long max_cluster = SZ_256K >> PAGE_CACHE_SHIFT;
	unsigned long cluster = max_cluster;
	u64 new_align = ~((u64)SZ_128K - 1);
	struct page **pages = NULL;

	if (isize == 0)
		return 0;

#ifdef MY_ABC_HERE
	if (range->flags & BTRFS_DEFRAG_RANGE_SYNO_DEFRAG &&
	    range->flags & BTRFS_DEFRAG_RANGE_PRINT_STDOUT) {
		memset(buf, 0, sizeof(buf));
		off = 0;
		snprintf(buf, sizeof(buf), "[syno defrag] root:%llu ino:%llu "
		        "start:%llu len:%llu thresh:%u dem:%u nom:%u\n",
		        root->objectid, btrfs_ino(inode),
		        range->start, range->len,
		        range->syno_thresh, range->syno_ratio_denom,
		        range->syno_ratio_nom);
		printk(KERN_WARNING"%s", buf);
		file_stdout = fget(1);
		write_buf(file_stdout, buf, sizeof(buf), &off);
		if (one_tenth_isize < 256 * 1024 * 1024)
			one_tenth_isize = 256 * 1024 * 1024;
	}
	i = 0; // To avoid use maybe-uninitialized warning
#endif /* MY_ABC_HERE */
	if (range->start >= isize)
		return -EINVAL;

	if (range->flags & BTRFS_DEFRAG_RANGE_COMPRESS) {
		if (range->compress_type > BTRFS_COMPRESS_TYPES)
			return -EINVAL;
		if (range->compress_type)
			compress_type = range->compress_type;
	}

	if (extent_thresh == 0)
		extent_thresh = SZ_256K;

	/*
	 * if we were not given a file, allocate a readahead
	 * context
	 */
	if (!file) {
		ra = kzalloc(sizeof(*ra), GFP_NOFS);
		if (!ra)
			return -ENOMEM;
		file_ra_state_init(ra, inode->i_mapping);
	} else {
		ra = &file->f_ra;
	}

#ifdef MY_ABC_HERE
	if (range->flags & BTRFS_DEFRAG_RANGE_SYNO_DEFRAG) {
		disko_ulist = ulist_alloc(GFP_NOFS);
		if (!disko_ulist) {
			ret = -ENOMEM;
			goto out_ra;
		}
	}
#endif /* MY_ABC_HERE */
	pages = kmalloc_array(max_cluster, sizeof(struct page *),
			GFP_NOFS);
	if (!pages) {
		ret = -ENOMEM;
		goto out_ra;
	}

	/* find the last page to defrag */
	if (range->start + range->len > range->start) {
		last_index = min_t(u64, isize - 1,
			 range->start + range->len - 1) >> PAGE_CACHE_SHIFT;
	} else {
		last_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	}

	if (newer_than) {
		ret = find_new_extents(root, inode, newer_than,
				       &newer_off, SZ_64K);
		if (!ret) {
			range->start = newer_off;
			/*
			 * we always align our defrag to help keep
			 * the extents in the file evenly spaced
			 */
			i = (newer_off & new_align) >> PAGE_CACHE_SHIFT;
		} else
			goto out_ra;
	} else {
		i = range->start >> PAGE_CACHE_SHIFT;
	}
	if (!max_to_defrag)
		max_to_defrag = last_index - i + 1;

	/*
	 * make writeback starts from i, so the defrag range can be
	 * written sequentially.
	 */
	if (i < inode->i_mapping->writeback_index)
		inode->i_mapping->writeback_index = i;

	while (i <= last_index && defrag_count < max_to_defrag &&
	       (i < DIV_ROUND_UP(i_size_read(inode), PAGE_CACHE_SIZE))) {
		/*
		 * make sure we stop running if someone unmounts
		 * the FS
		 */
		if (!(inode->i_sb->s_flags & MS_ACTIVE))
			break;

		if (btrfs_defrag_cancelled(root->fs_info)) {
			btrfs_debug(root->fs_info, "defrag_file cancelled");
			ret = -EAGAIN;
			break;
		}

#ifdef MY_ABC_HERE
		if (range->flags & BTRFS_DEFRAG_RANGE_SYNO_DEFRAG &&
			range->flags & BTRFS_DEFRAG_RANGE_PRINT_STDOUT) {
			if (((u64)i << PAGE_CACHE_SHIFT) - last_rec_pos >= one_tenth_isize) {
				last_rec_pos = (u64)i << PAGE_CACHE_SHIFT;
				print_stdout = 1;
			}
			if (print_stdout || get_seconds() - last_show > 60) {
				memset(buf, 0, sizeof(buf));
				off = 0;
				snprintf(buf, sizeof(buf), "[syno defrag status] root:%llu ino:%llu progress:%lu/%lu release size:%llu\n",
					root->objectid, btrfs_ino(inode), i, last_index, release_size);
				write_buf(file_stdout, buf, sizeof(buf), &off);
				last_show = get_seconds();
				print_stdout = 0;
			}
		}
		should_defrag_range_ret = should_defrag_range(inode, (u64)i << PAGE_CACHE_SHIFT,
						 extent_thresh, &last_len, &skip,
						 &defrag_end, range->flags & BTRFS_DEFRAG_RANGE_COMPRESS,
						 range, disko_ulist, &release_size);
		if (should_defrag_range_ret < 0) {
			ret = should_defrag_range_ret;
			goto out_ra;
		}
		if (!should_defrag_range_ret) {
			unsigned long next;
			if (skip == (u64) -1)
				break;
#else
		if (!should_defrag_range(inode, (u64)i << PAGE_CACHE_SHIFT,
					 extent_thresh, &last_len, &skip,
					 &defrag_end, range->flags &
					 BTRFS_DEFRAG_RANGE_COMPRESS)) {
			unsigned long next;
#endif /* MY_ABC_HERE */
			/*
			 * the should_defrag function tells us how much to skip
			 * bump our counter by the suggested amount
			 */
			next = DIV_ROUND_UP(skip, PAGE_CACHE_SIZE);
			i = max(i + 1, next);
			continue;
		}

		if (!newer_than) {
			cluster = (PAGE_CACHE_ALIGN(defrag_end) >>
				   PAGE_CACHE_SHIFT) - i;
			cluster = min(cluster, max_cluster);
		} else {
			cluster = max_cluster;
		}

		if (i + cluster > ra_index) {
			ra_index = max(i, ra_index);
			btrfs_force_ra(inode->i_mapping, ra, file, ra_index,
				       cluster);
			ra_index += cluster;
		}

		inode_lock(inode);
		if (IS_SWAPFILE(inode)) {
			ret = -ETXTBSY;
		} else {
			if (range->flags & BTRFS_DEFRAG_RANGE_COMPRESS)
				BTRFS_I(inode)->force_compress = compress_type;
			ret = cluster_pages_for_defrag(inode, pages, i, cluster);
		}
		if (ret < 0) {
			inode_unlock(inode);
			goto out_ra;
		}
#ifdef MY_ABC_HERE
		defrag_success = 1;
#endif /* MY_ABC_HERE */

		defrag_count += ret;
		balance_dirty_pages_ratelimited(inode->i_mapping);
		inode_unlock(inode);

		if (newer_than) {
			if (newer_off == (u64)-1)
				break;

			if (ret > 0)
				i += ret;

			newer_off = max(newer_off + 1,
					(u64)i << PAGE_CACHE_SHIFT);

			ret = find_new_extents(root, inode, newer_than,
					       &newer_off, SZ_64K);
			if (!ret) {
				range->start = newer_off;
				i = (newer_off & new_align) >> PAGE_CACHE_SHIFT;
			} else {
				break;
			}
		} else {
			if (ret > 0) {
				i += ret;
				last_len += ret << PAGE_CACHE_SHIFT;
			} else {
				i++;
				last_len = 0;
			}
		}
	}

#ifdef MY_ABC_HERE
	if (defrag_success && (range->flags & BTRFS_DEFRAG_RANGE_START_IO_RANGE)) {
		btrfs_wait_ordered_range(inode, range->start, range->len);
	} else
#endif /* MY_ABC_HERE */
	if ((range->flags & BTRFS_DEFRAG_RANGE_START_IO)) {
		filemap_flush(inode->i_mapping);
		if (test_bit(BTRFS_INODE_HAS_ASYNC_EXTENT,
			     &BTRFS_I(inode)->runtime_flags))
			filemap_flush(inode->i_mapping);
	}

	if ((range->flags & BTRFS_DEFRAG_RANGE_COMPRESS)) {
		/* the filemap_flush will queue IO into the worker threads, but
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
	}

	if (range->compress_type == BTRFS_COMPRESS_LZO) {
		btrfs_set_fs_incompat(root->fs_info, COMPRESS_LZO);
	} else if (range->compress_type == BTRFS_COMPRESS_ZSTD) {
		btrfs_set_fs_incompat(root->fs_info, COMPRESS_ZSTD);
	}

	ret = defrag_count;

out_ra:
	if (range->flags & BTRFS_DEFRAG_RANGE_COMPRESS) {
		inode_lock(inode);
		BTRFS_I(inode)->force_compress = BTRFS_COMPRESS_NONE;
		inode_unlock(inode);
	}
#ifdef MY_ABC_HERE
	if (range->flags & BTRFS_DEFRAG_RANGE_SYNO_DEFRAG) {
		if (range->flags & BTRFS_DEFRAG_RANGE_PRINT_STDOUT) {
			memset(buf, 0, sizeof(buf));
			off = 0;
			snprintf(buf, sizeof(buf), "[syno defrag] finish root:%llu ino:%llu "
				"end_pos: %lu release size:%llu\n",
				root->objectid, btrfs_ino(inode), i, release_size);
			printk(KERN_WARNING"%s", buf);
			write_buf(file_stdout, buf, sizeof(buf), &off);
		}
		range->release_size = release_size;
		ulist_free(disko_ulist);
	}
	if (file_stdout)
		fput(file_stdout);
#endif /* MY_ABC_HERE */
	if (!file)
		kfree(ra);
	kfree(pages);
	return ret;
}

static noinline int btrfs_ioctl_resize(struct file *file,
					void __user *arg)
{
	u64 new_size;
	u64 old_size;
	u64 devid = 1;
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_vol_args *vol_args;
	struct btrfs_trans_handle *trans;
	struct btrfs_device *device = NULL;
	char *sizestr;
	char *retptr;
	char *devstr = NULL;
	int ret = 0;
	int mod = 0;
#ifdef MY_ABC_HERE
	int dry_run = 0;
#endif /* MY_ABC_HERE */

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (atomic_xchg(&root->fs_info->mutually_exclusive_operation_running,
			1)) {
		mnt_drop_write_file(file);
		return BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
	}

	mutex_lock(&root->fs_info->volume_mutex);
	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args)) {
		ret = PTR_ERR(vol_args);
		goto out;
	}

	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';

	sizestr = vol_args->name;
	devstr = strchr(sizestr, ':');
	if (devstr) {
		sizestr = devstr + 1;
		*devstr = '\0';
		devstr = vol_args->name;
		ret = kstrtoull(devstr, 10, &devid);
		if (ret)
			goto out_free;
		if (!devid) {
			ret = -EINVAL;
			goto out_free;
		}
		btrfs_info(root->fs_info, "resizing devid %llu", devid);
	}

	device = btrfs_find_device(root->fs_info, devid, NULL, NULL);
	if (!device) {
		btrfs_info(root->fs_info, "resizer unable to find device %llu",
		       devid);
		ret = -ENODEV;
		goto out_free;
	}

	if (!device->writeable) {
		btrfs_info(root->fs_info,
			   "resizer unable to apply on readonly device %llu",
		       devid);
		ret = -EPERM;
		goto out_free;
	}

	if (!strcmp(sizestr, "max"))
		new_size = device->bdev->bd_inode->i_size;
	else {
		if (sizestr[0] == '-') {
			mod = -1;
			sizestr++;
		} else if (sizestr[0] == '+') {
			mod = 1;
			sizestr++;
#ifdef MY_ABC_HERE
			if (sizestr[0] == '?') {
				dry_run = 1;
				sizestr++;
			}
#endif /* MY_ABC_HERE */
		}
		new_size = memparse(sizestr, &retptr);
		if (*retptr != '\0' || new_size == 0) {
			ret = -EINVAL;
			goto out_free;
		}
	}

	if (device->is_tgtdev_for_dev_replace) {
		ret = -EPERM;
		goto out_free;
	}

	old_size = btrfs_device_get_total_bytes(device);

	if (mod < 0) {
		if (new_size > old_size) {
			ret = -EINVAL;
			goto out_free;
		}
		new_size = old_size - new_size;
	} else if (mod > 0) {
		if (new_size > ULLONG_MAX - old_size) {
			ret = -ERANGE;
			goto out_free;
		}
		new_size = old_size + new_size;
	}

	if (new_size < SZ_256M) {
		ret = -EINVAL;
		goto out_free;
	}
	if (new_size > device->bdev->bd_inode->i_size) {
		ret = -EFBIG;
		goto out_free;
	}
#ifdef MY_ABC_HERE
	if (dry_run) {
		goto out_free;
	}
#endif /* MY_ABC_HERE */

	new_size = div_u64(new_size, root->sectorsize);
	new_size *= root->sectorsize;

	btrfs_info_in_rcu(root->fs_info, "new size for %s is %llu",
		      rcu_str_deref(device->name), new_size);

	if (new_size > old_size) {
		trans = btrfs_start_transaction(root, 0);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out_free;
		}
		ret = btrfs_grow_device(trans, device, new_size);
		btrfs_commit_transaction(trans, root);
	} else if (new_size < old_size) {
		ret = btrfs_shrink_device(device, new_size);
	} /* equal, nothing need to do */

out_free:
	kfree(vol_args);
out:
	mutex_unlock(&root->fs_info->volume_mutex);
	atomic_set(&root->fs_info->mutually_exclusive_operation_running, 0);
	mnt_drop_write_file(file);
	return ret;
}

static noinline int btrfs_ioctl_snap_create_transid(struct file *file,
				char *name, unsigned long fd, int subvol,
				u64 *transid, bool readonly,
#ifdef MY_ABC_HERE
				struct btrfs_qgroup_inherit *inherit,
				u64 copy_limit_from)
#else
				struct btrfs_qgroup_inherit *inherit)
#endif /* MY_ABC_HERE */
{
	int namelen;
	int ret = 0;

	if (!S_ISDIR(file_inode(file)->i_mode))
		return -ENOTDIR;

	ret = mnt_want_write_file(file);
	if (ret)
		goto out;

	namelen = strlen(name);
	if (strchr(name, '/')) {
		ret = -EINVAL;
		goto out_drop_write;
	}

	if (name[0] == '.' &&
	   (namelen == 1 || (name[1] == '.' && namelen == 2))) {
		ret = -EEXIST;
		goto out_drop_write;
	}

	if (subvol) {
		ret = btrfs_mksubvol(&file->f_path, name, namelen,
#ifdef MY_ABC_HERE
				     NULL, transid, readonly, inherit,
				     copy_limit_from);
#else
				     NULL, transid, readonly, inherit);
#endif /* MY_ABC_HERE */
	} else {
		struct fd src = fdget(fd);
		struct inode *src_inode;
		if (!src.file) {
			ret = -EINVAL;
			goto out_drop_write;
		}

		src_inode = file_inode(src.file);
		if (src_inode->i_sb != file_inode(file)->i_sb) {
			btrfs_info(BTRFS_I(file_inode(file))->root->fs_info,
				   "Snapshot src from another FS");
			ret = -EXDEV;
		} else if (!inode_owner_or_capable(src_inode)) {
			/*
			 * Subvolume creation is not restricted, but snapshots
			 * are limited to own subvolumes only
			 */
			ret = -EPERM;
		} else {
#ifdef MY_ABC_HERE
			ret = btrfs_mksnapshot(&file->f_path, name, namelen,
					     BTRFS_I(src_inode)->root,
#ifdef MY_ABC_HERE
					     transid, readonly, inherit,
					     copy_limit_from);
#else
					     transid, readonly, inherit);
#endif /* MY_ABC_HERE */
#else /* MY_ABC_HERE */
			ret = btrfs_mksubvol(&file->f_path, name, namelen,
					     BTRFS_I(src_inode)->root,
#ifdef MY_ABC_HERE
					     transid, readonly, inherit,
					     copy_limit_from);
#else
					     transid, readonly, inherit);
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */
		}
		fdput(src);
	}
out_drop_write:
	mnt_drop_write_file(file);
out:
	return ret;
}

static noinline int btrfs_ioctl_snap_create(struct file *file,
					    void __user *arg, int subvol)
{
	struct btrfs_ioctl_vol_args *vol_args;
	int ret;

	if (!S_ISDIR(file_inode(file)->i_mode))
		return -ENOTDIR;

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args))
		return PTR_ERR(vol_args);
	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';

	ret = btrfs_ioctl_snap_create_transid(file, vol_args->name,
					      vol_args->fd, subvol,
#ifdef MY_ABC_HERE
					      NULL, false, NULL, 0);
#else
					      NULL, false, NULL);
#endif /* MY_ABC_HERE */

	kfree(vol_args);
	return ret;
}

static noinline int btrfs_ioctl_snap_create_v2(struct file *file,
					       void __user *arg, int subvol)
{
	struct btrfs_ioctl_vol_args_v2 *vol_args;
	int ret;
	u64 transid = 0;
	u64 *ptr = NULL;
	bool readonly = false;
	struct btrfs_qgroup_inherit *inherit = NULL;

	if (!S_ISDIR(file_inode(file)->i_mode))
		return -ENOTDIR;

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args))
		return PTR_ERR(vol_args);
	vol_args->name[BTRFS_SUBVOL_NAME_MAX] = '\0';

	if (vol_args->flags &
	    ~(BTRFS_SUBVOL_CREATE_ASYNC | BTRFS_SUBVOL_RDONLY |
	      BTRFS_SUBVOL_QGROUP_INHERIT)) {
		ret = -EOPNOTSUPP;
		goto free_args;
	}

	if (vol_args->flags & BTRFS_SUBVOL_CREATE_ASYNC)
		ptr = &transid;
	if (vol_args->flags & BTRFS_SUBVOL_RDONLY)
		readonly = true;
	if (vol_args->flags & BTRFS_SUBVOL_QGROUP_INHERIT) {
		if (vol_args->size > PAGE_CACHE_SIZE) {
			ret = -EINVAL;
			goto free_args;
		}
		inherit = memdup_user(vol_args->qgroup_inherit, vol_args->size);
		if (IS_ERR(inherit)) {
			ret = PTR_ERR(inherit);
			goto free_args;
		}
	}

	ret = btrfs_ioctl_snap_create_transid(file, vol_args->name,
					      vol_args->fd, subvol, ptr,
#ifdef MY_ABC_HERE
					      readonly, inherit, vol_args->copy_limit_from);
#else
					      readonly, inherit);
#endif /* MY_ABC_HERE */
	if (ret)
		goto free_inherit;

	if (ptr && copy_to_user(arg +
				offsetof(struct btrfs_ioctl_vol_args_v2,
					transid),
				ptr, sizeof(*ptr)))
		ret = -EFAULT;

free_inherit:
	kfree(inherit);
free_args:
	kfree(vol_args);
	return ret;
}

static noinline int btrfs_ioctl_subvol_getflags(struct file *file,
						void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret = 0;
	u64 flags = 0;

	if (btrfs_ino(inode) != BTRFS_FIRST_FREE_OBJECTID)
		return -EINVAL;

	down_read(&root->fs_info->subvol_sem);
	if (btrfs_root_readonly(root))
		flags |= BTRFS_SUBVOL_RDONLY;
#ifdef MY_ABC_HERE
	if (btrfs_root_disable_quota(root))
		flags |= BTRFS_SUBVOL_DISABLE_QUOTA;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_root_hide(root))
		flags |= BTRFS_SUBVOL_HIDE;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_root_noload_usrquota(root))
		flags |= BTRFS_SUBVOL_NOLOAD_USRQUOTA;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_root_cmpr_ratio(root))
		flags |= BTRFS_SUBVOL_CMPR_RATIO;
#endif /* MY_ABC_HERE */
	up_read(&root->fs_info->subvol_sem);

	if (copy_to_user(arg, &flags, sizeof(flags)))
		ret = -EFAULT;

	return ret;
}

static noinline int btrfs_ioctl_subvol_setflags(struct file *file,
					      void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	u64 root_flags;
	u64 flags;
	int ret = 0;
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	u64 mask = BTRFS_SUBVOL_RDONLY;
#endif /* MY_ABC_HERE || MY_ABC_HERE || MY_ABC_HERE || MY_ABC_HERE */

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		goto out;

	if (btrfs_ino(inode) != BTRFS_FIRST_FREE_OBJECTID) {
		ret = -EINVAL;
		goto out_drop_write;
	}

	if (copy_from_user(&flags, arg, sizeof(flags))) {
		ret = -EFAULT;
		goto out_drop_write;
	}

	if (flags & BTRFS_SUBVOL_CREATE_ASYNC) {
		ret = -EINVAL;
		goto out_drop_write;
	}

#ifdef MY_ABC_HERE
	mask |= BTRFS_SUBVOL_HIDE;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	mask |= BTRFS_SUBVOL_NOLOAD_USRQUOTA;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	mask |= BTRFS_SUBVOL_CMPR_RATIO;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	mask |= BTRFS_SUBVOL_DISABLE_QUOTA;
#endif /* MY_ABC_HERE */

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	if (flags & ~mask) {
#else
	if (flags & ~BTRFS_SUBVOL_RDONLY) {
#endif /* MY_ABC_HERE || MY_ABC_HERE || MY_ABC_HERE || MY_ABC_HERE */
		ret = -EOPNOTSUPP;
		goto out_drop_write;
	}

	down_write(&root->fs_info->subvol_sem);

	/* nothing to do */
#ifdef MY_ABC_HERE
	if (!!(flags & BTRFS_SUBVOL_HIDE) != btrfs_root_hide(root))
		goto update_flags;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (!!(flags & BTRFS_SUBVOL_NOLOAD_USRQUOTA) != btrfs_root_noload_usrquota(root))
		goto update_flags;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (!!(flags & BTRFS_SUBVOL_CMPR_RATIO) != btrfs_root_cmpr_ratio(root))
		goto update_flags;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (!!(flags & BTRFS_SUBVOL_DISABLE_QUOTA) != btrfs_root_disable_quota(root))
		goto update_flags;
#endif /* MY_ABC_HERE */
	if (!!(flags & BTRFS_SUBVOL_RDONLY) == btrfs_root_readonly(root))
		goto out_drop_sem;

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
update_flags:
#endif /* MY_ABC_HERE || MY_ABC_HERE || MY_ABC_HERE || MY_ABC_HERE */
	root_flags = btrfs_root_flags(&root->root_item);
	if (flags & BTRFS_SUBVOL_RDONLY) {
		btrfs_set_root_flags(&root->root_item,
				     root_flags | BTRFS_ROOT_SUBVOL_RDONLY);
	} else {
		/*
		 * Block RO -> RW transition if this subvolume is involved in
		 * send
		 */
		spin_lock(&root->root_item_lock);
		if (root->send_in_progress == 0) {
			btrfs_set_root_flags(&root->root_item,
				     root_flags & ~BTRFS_ROOT_SUBVOL_RDONLY);
			spin_unlock(&root->root_item_lock);
		} else {
			spin_unlock(&root->root_item_lock);
			btrfs_warn(root->fs_info,
			"Attempt to set subvolume %llu read-write during send",
					root->root_key.objectid);
			ret = -EPERM;
			goto out_drop_sem;
		}
	}
#ifdef MY_ABC_HERE
	root_flags = btrfs_root_flags(&root->root_item);
	if (flags & BTRFS_SUBVOL_HIDE)
		btrfs_set_root_flags(&root->root_item,
					 root_flags | BTRFS_ROOT_SUBVOL_HIDE);
	else
		btrfs_set_root_flags(&root->root_item,
					root_flags & ~BTRFS_ROOT_SUBVOL_HIDE);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	root_flags = btrfs_root_flags(&root->root_item);
	if (flags & BTRFS_SUBVOL_NOLOAD_USRQUOTA)
		btrfs_set_root_flags(&root->root_item,
					 root_flags | BTRFS_ROOT_SUBVOL_NOLOAD_USRQUOTA);
	else
		btrfs_set_root_flags(&root->root_item,
					root_flags & ~BTRFS_ROOT_SUBVOL_NOLOAD_USRQUOTA);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	root_flags = btrfs_root_flags(&root->root_item);
	if (flags & BTRFS_SUBVOL_CMPR_RATIO)
		btrfs_set_root_flags(&root->root_item,
					root_flags | BTRFS_ROOT_SUBVOL_CMPR_RATIO);
	else
		btrfs_set_root_flags(&root->root_item,
					root_flags & ~BTRFS_ROOT_SUBVOL_CMPR_RATIO);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	root_flags = btrfs_root_flags(&root->root_item);
	if (flags & BTRFS_SUBVOL_DISABLE_QUOTA)
		btrfs_set_root_flags(&root->root_item,
					root_flags | BTRFS_ROOT_SUBVOL_DISABLE_QUOTA);
	else
		btrfs_set_root_flags(&root->root_item,
					root_flags & ~BTRFS_ROOT_SUBVOL_DISABLE_QUOTA);
#endif /* MY_ABC_HERE */

	trans = btrfs_start_transaction(root, 1);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_reset;
	}

	ret = btrfs_update_root(trans, root->fs_info->tree_root,
				&root->root_key, &root->root_item);

	btrfs_commit_transaction(trans, root);
out_reset:
	if (ret)
		btrfs_set_root_flags(&root->root_item, root_flags);
out_drop_sem:
	up_write(&root->fs_info->subvol_sem);
out_drop_write:
	mnt_drop_write_file(file);
out:
	return ret;
}

/*
 * helper to check if the subvolume references other subvolumes
 */
static noinline int may_destroy_subvol(struct btrfs_root *root)
{
	struct btrfs_path *path;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	u64 dir_id;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	/* Make sure this root isn't set as the default subvol */
	dir_id = btrfs_super_root_dir(root->fs_info->super_copy);
	di = btrfs_lookup_dir_item(NULL, root->fs_info->tree_root, path,
				   dir_id, "default", 7, 0);
	if (di && !IS_ERR(di)) {
		btrfs_dir_item_key_to_cpu(path->nodes[0], di, &key);
		if (key.objectid == root->root_key.objectid) {
			ret = -EPERM;
			btrfs_err(root->fs_info, "deleting default subvolume "
				  "%llu is not allowed", key.objectid);
			goto out;
		}
		btrfs_release_path(path);
	}

	key.objectid = root->root_key.objectid;
	key.type = BTRFS_ROOT_REF_KEY;
	key.offset = (u64)-1;

	ret = btrfs_search_slot(NULL, root->fs_info->tree_root,
				&key, path, 0, 0);
	if (ret < 0)
		goto out;
	BUG_ON(ret == 0);

	ret = 0;
	if (path->slots[0] > 0) {
		path->slots[0]--;
		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		if (key.objectid == root->root_key.objectid &&
		    key.type == BTRFS_ROOT_REF_KEY)
			ret = -ENOTEMPTY;
	}
out:
	btrfs_free_path(path);
	return ret;
}

static noinline int key_in_sk(struct btrfs_key *key,
			      struct btrfs_ioctl_search_key *sk)
{
	struct btrfs_key test;
	int ret;

	test.objectid = sk->min_objectid;
	test.type = sk->min_type;
	test.offset = sk->min_offset;

	ret = btrfs_comp_cpu_keys(key, &test);
	if (ret < 0)
		return 0;

	test.objectid = sk->max_objectid;
	test.type = sk->max_type;
	test.offset = sk->max_offset;

	ret = btrfs_comp_cpu_keys(key, &test);
	if (ret > 0)
		return 0;
	return 1;
}

static noinline int copy_to_sk(struct btrfs_root *root,
			       struct btrfs_path *path,
			       struct btrfs_key *key,
			       struct btrfs_ioctl_search_key *sk,
			       size_t *buf_size,
			       char __user *ubuf,
			       unsigned long *sk_offset,
			       int *num_found)
{
	u64 found_transid;
	struct extent_buffer *leaf;
	struct btrfs_ioctl_search_header sh;
	struct btrfs_key test;
	unsigned long item_off;
	unsigned long item_len;
	int nritems;
	int i;
	int slot;
	int ret = 0;

	leaf = path->nodes[0];
	slot = path->slots[0];
	nritems = btrfs_header_nritems(leaf);

	if (btrfs_header_generation(leaf) > sk->max_transid) {
		i = nritems;
		goto advance_key;
	}
	found_transid = btrfs_header_generation(leaf);

	for (i = slot; i < nritems; i++) {
		item_off = btrfs_item_ptr_offset(leaf, i);
		item_len = btrfs_item_size_nr(leaf, i);

		btrfs_item_key_to_cpu(leaf, key, i);
		if (!key_in_sk(key, sk))
			continue;

		if (sizeof(sh) + item_len > *buf_size) {
			if (*num_found) {
				ret = 1;
				goto out;
			}

			/*
			 * return one empty item back for v1, which does not
			 * handle -EOVERFLOW
			 */

			*buf_size = sizeof(sh) + item_len;
			item_len = 0;
			ret = -EOVERFLOW;
		}

		if (sizeof(sh) + item_len + *sk_offset > *buf_size) {
			ret = 1;
			goto out;
		}

		sh.objectid = key->objectid;
		sh.offset = key->offset;
		sh.type = key->type;
		sh.len = item_len;
		sh.transid = found_transid;

		/* copy search result header */
		if (copy_to_user(ubuf + *sk_offset, &sh, sizeof(sh))) {
			ret = -EFAULT;
			goto out;
		}

		*sk_offset += sizeof(sh);

		if (item_len) {
			char __user *up = ubuf + *sk_offset;
			/* copy the item */
			if (read_extent_buffer_to_user(leaf, up,
						       item_off, item_len)) {
				ret = -EFAULT;
				goto out;
			}

			*sk_offset += item_len;
		}
		(*num_found)++;

		if (ret) /* -EOVERFLOW from above */
			goto out;

		if (*num_found >= sk->nr_items) {
			ret = 1;
			goto out;
		}
	}
advance_key:
	ret = 0;
	test.objectid = sk->max_objectid;
	test.type = sk->max_type;
	test.offset = sk->max_offset;
	if (btrfs_comp_cpu_keys(key, &test) >= 0)
		ret = 1;
	else if (key->offset < (u64)-1)
		key->offset++;
	else if (key->type < (u8)-1) {
		key->offset = 0;
		key->type++;
	} else if (key->objectid < (u64)-1) {
		key->offset = 0;
		key->type = 0;
		key->objectid++;
	} else
		ret = 1;
out:
	/*
	 *  0: all items from this leaf copied, continue with next
	 *  1: * more items can be copied, but unused buffer is too small
	 *     * all items were found
	 *     Either way, it will stops the loop which iterates to the next
	 *     leaf
	 *  -EOVERFLOW: item was to large for buffer
	 *  -EFAULT: could not copy extent buffer back to userspace
	 */
	return ret;
}

static noinline int search_ioctl(struct inode *inode,
				 struct btrfs_ioctl_search_key *sk,
				 size_t *buf_size,
				 char __user *ubuf)
{
	struct btrfs_root *root;
	struct btrfs_key key;
	struct btrfs_path *path;
	struct btrfs_fs_info *info = BTRFS_I(inode)->root->fs_info;
	int ret;
	int num_found = 0;
	unsigned long sk_offset = 0;

	if (*buf_size < sizeof(struct btrfs_ioctl_search_header)) {
		*buf_size = sizeof(struct btrfs_ioctl_search_header);
		return -EOVERFLOW;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	if (sk->tree_id == 0) {
		/* search the root of the inode that was passed */
		root = BTRFS_I(inode)->root;
	} else {
		key.objectid = sk->tree_id;
		key.type = BTRFS_ROOT_ITEM_KEY;
		key.offset = (u64)-1;
		root = btrfs_read_fs_root_no_name(info, &key);
		if (IS_ERR(root)) {
			btrfs_free_path(path);
			return PTR_ERR(root);
		}
	}

	key.objectid = sk->min_objectid;
	key.type = sk->min_type;
	key.offset = sk->min_offset;

	while (1) {
		ret = btrfs_search_forward(root, &key, path, sk->min_transid);
		if (ret != 0) {
			if (ret > 0)
				ret = 0;
			goto err;
		}
		ret = copy_to_sk(root, path, &key, sk, buf_size, ubuf,
				 &sk_offset, &num_found);
		btrfs_release_path(path);
		if (ret)
			break;

	}
	if (ret > 0)
		ret = 0;
err:
	sk->nr_items = num_found;
	btrfs_free_path(path);
	return ret;
}

static noinline int btrfs_ioctl_tree_search(struct file *file,
					   void __user *argp)
{
	struct btrfs_ioctl_search_args __user *uargs;
	struct btrfs_ioctl_search_key sk;
	struct inode *inode;
	int ret;
	size_t buf_size;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	uargs = (struct btrfs_ioctl_search_args __user *)argp;

	if (copy_from_user(&sk, &uargs->key, sizeof(sk)))
		return -EFAULT;

	buf_size = sizeof(uargs->buf);

	inode = file_inode(file);
	ret = search_ioctl(inode, &sk, &buf_size, uargs->buf);

	/*
	 * In the origin implementation an overflow is handled by returning a
	 * search header with a len of zero, so reset ret.
	 */
	if (ret == -EOVERFLOW)
		ret = 0;

	if (ret == 0 && copy_to_user(&uargs->key, &sk, sizeof(sk)))
		ret = -EFAULT;
	return ret;
}

static noinline int btrfs_ioctl_tree_search_v2(struct file *file,
					       void __user *argp)
{
	struct btrfs_ioctl_search_args_v2 __user *uarg;
	struct btrfs_ioctl_search_args_v2 args;
	struct inode *inode;
	int ret;
	size_t buf_size;
	const size_t buf_limit = SZ_16M;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* copy search header and buffer size */
	uarg = (struct btrfs_ioctl_search_args_v2 __user *)argp;
	if (copy_from_user(&args, uarg, sizeof(args)))
		return -EFAULT;

	buf_size = args.buf_size;

	if (buf_size < sizeof(struct btrfs_ioctl_search_header))
		return -EOVERFLOW;

	/* limit result size to 16MB */
	if (buf_size > buf_limit)
		buf_size = buf_limit;

	inode = file_inode(file);
	ret = search_ioctl(inode, &args.key, &buf_size,
			   (char *)(&uarg->buf[0]));
	if (ret == 0 && copy_to_user(&uarg->key, &args.key, sizeof(args.key)))
		ret = -EFAULT;
	else if (ret == -EOVERFLOW &&
		copy_to_user(&uarg->buf_size, &buf_size, sizeof(buf_size)))
		ret = -EFAULT;

	return ret;
}

/*
 * Search INODE_REFs to identify path name of 'dirid' directory
 * in a 'tree_id' tree. and sets path name to 'name'.
 */
static noinline int btrfs_search_path_in_tree(struct btrfs_fs_info *info,
				u64 tree_id, u64 dirid, char *name)
{
	struct btrfs_root *root;
	struct btrfs_key key;
	char *ptr;
	int ret = -1;
	int slot;
	int len;
	int total_len = 0;
	struct btrfs_inode_ref *iref;
	struct extent_buffer *l;
	struct btrfs_path *path;

	if (dirid == BTRFS_FIRST_FREE_OBJECTID) {
		name[0]='\0';
		return 0;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ptr = &name[BTRFS_INO_LOOKUP_PATH_MAX - 1];

	key.objectid = tree_id;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	root = btrfs_read_fs_root_no_name(info, &key);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto out;
	}

	key.objectid = dirid;
	key.type = BTRFS_INODE_REF_KEY;
	key.offset = (u64)-1;

	while (1) {
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			goto out;
		else if (ret > 0) {
			ret = btrfs_previous_item(root, path, dirid,
						  BTRFS_INODE_REF_KEY);
			if (ret < 0)
				goto out;
			else if (ret > 0) {
				ret = -ENOENT;
				goto out;
			}
		}

		l = path->nodes[0];
		slot = path->slots[0];
		btrfs_item_key_to_cpu(l, &key, slot);

		iref = btrfs_item_ptr(l, slot, struct btrfs_inode_ref);
		len = btrfs_inode_ref_name_len(l, iref);
		ptr -= len + 1;
		total_len += len + 1;
		if (ptr < name) {
			ret = -ENAMETOOLONG;
			goto out;
		}

		*(ptr + len) = '/';
		read_extent_buffer(l, ptr, (unsigned long)(iref + 1), len);

		if (key.offset == BTRFS_FIRST_FREE_OBJECTID)
			break;

		btrfs_release_path(path);
		key.objectid = key.offset;
		key.offset = (u64)-1;
		dirid = key.objectid;
	}
	memmove(name, ptr, total_len);
	name[total_len] = '\0';
	ret = 0;
out:
	btrfs_free_path(path);
	return ret;
}

static noinline int btrfs_ioctl_ino_lookup(struct file *file,
					   void __user *argp)
{
	 struct btrfs_ioctl_ino_lookup_args *args;
	 struct inode *inode;
	int ret = 0;

	args = memdup_user(argp, sizeof(*args));
	if (IS_ERR(args))
		return PTR_ERR(args);

	inode = file_inode(file);

	/*
	 * Unprivileged query to obtain the containing subvolume root id. The
	 * path is reset so it's consistent with btrfs_search_path_in_tree.
	 */
	if (args->treeid == 0)
		args->treeid = BTRFS_I(inode)->root->root_key.objectid;

	if (args->objectid == BTRFS_FIRST_FREE_OBJECTID) {
		args->name[0] = 0;
		goto out;
	}

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	ret = btrfs_search_path_in_tree(BTRFS_I(inode)->root->fs_info,
					args->treeid, args->objectid,
					args->name);

out:
	if (ret == 0 && copy_to_user(argp, args, sizeof(*args)))
		ret = -EFAULT;

	kfree(args);
	return ret;
}

static noinline int btrfs_ioctl_snap_destroy(struct file *file,
					     void __user *arg)
{
	struct dentry *parent = file->f_path.dentry;
	struct dentry *dentry;
	struct inode *dir = d_inode(parent);
	struct inode *inode;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_root *dest = NULL;
	struct btrfs_ioctl_vol_args *vol_args;
	struct btrfs_trans_handle *trans;
	struct btrfs_block_rsv block_rsv;
	u64 root_flags;
	u64 qgroup_reserved;
	int namelen;
	int ret;
	int err = 0;

	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args))
		return PTR_ERR(vol_args);

	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';
	namelen = strlen(vol_args->name);
	if (strchr(vol_args->name, '/') ||
	    strncmp(vol_args->name, "..", namelen) == 0) {
		err = -EINVAL;
		goto out;
	}

	err = mnt_want_write_file(file);
	if (err)
		goto out;


	err = mutex_lock_killable_nested(&dir->i_mutex, I_MUTEX_PARENT);
	if (err == -EINTR)
		goto out_drop_write;
	dentry = lookup_one_len(vol_args->name, parent, namelen);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		goto out_unlock_dir;
	}

	if (d_really_is_negative(dentry)) {
		err = -ENOENT;
		goto out_dput;
	}

	inode = d_inode(dentry);
	dest = BTRFS_I(inode)->root;
	if (!capable(CAP_SYS_ADMIN)) {
		/*
		 * Regular user.  Only allow this with a special mount
		 * option, when the user has write+exec access to the
		 * subvol root, and when rmdir(2) would have been
		 * allowed.
		 *
		 * Note that this is _not_ check that the subvol is
		 * empty or doesn't contain data that we wouldn't
		 * otherwise be able to delete.
		 *
		 * Users who want to delete empty subvols should try
		 * rmdir(2).
		 */
		err = -EPERM;
		if (!btrfs_test_opt(root, USER_SUBVOL_RM_ALLOWED))
			goto out_dput;

		/*
		 * Do not allow deletion if the parent dir is the same
		 * as the dir to be deleted.  That means the ioctl
		 * must be called on the dentry referencing the root
		 * of the subvol, not a random directory contained
		 * within it.
		 */
		err = -EINVAL;
		if (root == dest)
			goto out_dput;

		err = inode_permission(inode, MAY_WRITE | MAY_EXEC);
		if (err)
			goto out_dput;
	}

	/* check if subvolume may be deleted by a user */
	err = btrfs_may_delete(dir, dentry, 1);
	if (err)
		goto out_dput;

	if (btrfs_ino(inode) != BTRFS_FIRST_FREE_OBJECTID) {
		err = -EINVAL;
		goto out_dput;
	}

	inode_lock(inode);

	/*
	 * Don't allow to delete a subvolume with send in progress. This is
	 * inside the i_mutex so the error handling that has to drop the bit
	 * again is not run concurrently.
	 */
	spin_lock(&dest->root_item_lock);
	root_flags = btrfs_root_flags(&dest->root_item);
	if (dest->send_in_progress == 0) {
		btrfs_set_root_flags(&dest->root_item,
				root_flags | BTRFS_ROOT_SUBVOL_DEAD);
		spin_unlock(&dest->root_item_lock);
	} else {
		spin_unlock(&dest->root_item_lock);
		btrfs_warn(root->fs_info,
			"Attempt to delete subvolume %llu during send",
			dest->root_key.objectid);
		err = -EPERM;
		goto out_unlock_inode;
	}

	down_write(&root->fs_info->subvol_sem);

	err = may_destroy_subvol(dest);
	if (err)
		goto out_up_write;

	btrfs_init_block_rsv(&block_rsv, BTRFS_BLOCK_RSV_TEMP);
	/*
	 * One for dir inode, two for dir entries, two for root
	 * ref/backref.
	 */
	err = btrfs_subvolume_reserve_metadata(root, &block_rsv,
					       5, &qgroup_reserved, true);
	if (err)
		goto out_up_write;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto out_release;
	}
	trans->block_rsv = &block_rsv;
	trans->bytes_reserved = block_rsv.size;

	btrfs_record_snapshot_destroy(trans, dir);

	ret = btrfs_unlink_subvol(trans, root, dir,
				dest->root_key.objectid,
				dentry->d_name.name,
				dentry->d_name.len);
	if (ret) {
		err = ret;
		btrfs_abort_transaction(trans, root, ret);
		goto out_end_trans;
	}

	btrfs_record_root_in_trans(trans, dest);

	memset(&dest->root_item.drop_progress, 0,
		sizeof(dest->root_item.drop_progress));
	dest->root_item.drop_level = 0;
	btrfs_set_root_refs(&dest->root_item, 0);

	if (!test_and_set_bit(BTRFS_ROOT_ORPHAN_ITEM_INSERTED, &dest->state)) {
		ret = btrfs_insert_orphan_item(trans,
					root->fs_info->tree_root,
					dest->root_key.objectid);
		if (ret) {
			btrfs_abort_transaction(trans, root, ret);
			err = ret;
			goto out_end_trans;
		}
	}

	ret = btrfs_uuid_tree_rem(trans, root->fs_info->uuid_root,
				  dest->root_item.uuid, BTRFS_UUID_KEY_SUBVOL,
				  dest->root_key.objectid);
	if (ret && ret != -ENOENT) {
		btrfs_abort_transaction(trans, root, ret);
		err = ret;
		goto out_end_trans;
	}
	if (!btrfs_is_empty_uuid(dest->root_item.received_uuid)) {
		ret = btrfs_uuid_tree_rem(trans, root->fs_info->uuid_root,
					  dest->root_item.received_uuid,
					  BTRFS_UUID_KEY_RECEIVED_SUBVOL,
					  dest->root_key.objectid);
		if (ret && ret != -ENOENT) {
			btrfs_abort_transaction(trans, root, ret);
			err = ret;
			goto out_end_trans;
		}
	}

out_end_trans:
	trans->block_rsv = NULL;
	trans->bytes_reserved = 0;
	ret = btrfs_end_transaction(trans, root);
	if (ret && !err)
		err = ret;
	inode->i_flags |= S_DEAD;
out_release:
	btrfs_subvolume_release_metadata(root, &block_rsv, qgroup_reserved);
out_up_write:
	up_write(&root->fs_info->subvol_sem);
	if (err) {
		spin_lock(&dest->root_item_lock);
		root_flags = btrfs_root_flags(&dest->root_item);
		btrfs_set_root_flags(&dest->root_item,
				root_flags & ~BTRFS_ROOT_SUBVOL_DEAD);
		spin_unlock(&dest->root_item_lock);
	}
out_unlock_inode:
	inode_unlock(inode);
	if (!err) {
		d_invalidate(dentry);
		btrfs_invalidate_inodes(dest);
		d_delete(dentry);
		ASSERT(dest->send_in_progress == 0);

		/* the last ref */
		if (dest->ino_cache_inode) {
			iput(dest->ino_cache_inode);
			dest->ino_cache_inode = NULL;
		}
	}
out_dput:
	dput(dentry);
out_unlock_dir:
	inode_unlock(dir);
out_drop_write:
	mnt_drop_write_file(file);
out:
	kfree(vol_args);
	return err;
}

static int btrfs_ioctl_defrag(struct file *file, void __user *argp)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_ioctl_defrag_range_args *range;
	int ret;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (btrfs_root_readonly(root)) {
		ret = -EROFS;
		goto out;
	}

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		if (!capable(CAP_SYS_ADMIN)) {
			ret = -EPERM;
			goto out;
		}
		ret = btrfs_defrag_root(root);
		if (ret)
			goto out;
		ret = btrfs_defrag_root(root->fs_info->extent_root);
		break;
	case S_IFREG:
		if (!(file->f_mode & FMODE_WRITE)) {
			ret = -EINVAL;
			goto out;
		}

		range = kzalloc(sizeof(*range), GFP_KERNEL);
		if (!range) {
			ret = -ENOMEM;
			goto out;
		}

		if (argp) {
			if (copy_from_user(range, argp,
					   sizeof(*range))) {
				ret = -EFAULT;
				kfree(range);
				goto out;
			}
			/* compression requires us to start the IO */
			if ((range->flags & BTRFS_DEFRAG_RANGE_COMPRESS)) {
				range->flags |= BTRFS_DEFRAG_RANGE_START_IO;
				range->extent_thresh = (u32)-1;
			}
		} else {
			/* the rest are all set to zero by kzalloc */
			range->len = (u64)-1;
		}
		ret = btrfs_defrag_file(file_inode(file), file,
					range, 0, 0);
		if (ret > 0)
			ret = 0;
		kfree(range);
		break;
	default:
		ret = -EINVAL;
	}
out:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_add_dev(struct btrfs_root *root, void __user *arg)
{
	struct btrfs_ioctl_vol_args *vol_args;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (atomic_xchg(&root->fs_info->mutually_exclusive_operation_running,
			1)) {
		return BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
	}

	mutex_lock(&root->fs_info->volume_mutex);
	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args)) {
		ret = PTR_ERR(vol_args);
		goto out;
	}

	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';
	ret = btrfs_init_new_device(root, vol_args->name);

	if (!ret)
		btrfs_info(root->fs_info, "disk added %s",vol_args->name);

	kfree(vol_args);
out:
	mutex_unlock(&root->fs_info->volume_mutex);
	atomic_set(&root->fs_info->mutually_exclusive_operation_running, 0);
	return ret;
}

static long btrfs_ioctl_rm_dev(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_vol_args *vol_args;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (atomic_xchg(&root->fs_info->mutually_exclusive_operation_running,
			1)) {
		ret = BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
		goto out_drop_write;
	}

	vol_args = memdup_user(arg, sizeof(*vol_args));
	if (IS_ERR(vol_args)) {
		ret = PTR_ERR(vol_args);
		goto out;
	}

	vol_args->name[BTRFS_PATH_NAME_MAX] = '\0';
	mutex_lock(&root->fs_info->volume_mutex);
	ret = btrfs_rm_device(root, vol_args->name);
	mutex_unlock(&root->fs_info->volume_mutex);

	if (!ret)
		btrfs_info(root->fs_info, "disk deleted %s",vol_args->name);
	kfree(vol_args);
out:
	atomic_set(&root->fs_info->mutually_exclusive_operation_running, 0);
out_drop_write:
	mnt_drop_write_file(file);

	return ret;
}

static long btrfs_ioctl_fs_info(struct btrfs_root *root, void __user *arg)
{
	struct btrfs_ioctl_fs_info_args *fi_args;
	struct btrfs_device *device;
	struct btrfs_fs_devices *fs_devices = root->fs_info->fs_devices;
	int ret = 0;

	fi_args = kzalloc(sizeof(*fi_args), GFP_KERNEL);
	if (!fi_args)
		return -ENOMEM;

	mutex_lock(&fs_devices->device_list_mutex);
	fi_args->num_devices = fs_devices->num_devices;
	memcpy(&fi_args->fsid, root->fs_info->fsid, sizeof(fi_args->fsid));

	list_for_each_entry(device, &fs_devices->devices, dev_list) {
		if (device->devid > fi_args->max_id)
			fi_args->max_id = device->devid;
	}
	mutex_unlock(&fs_devices->device_list_mutex);

	fi_args->nodesize = root->fs_info->super_copy->nodesize;
	fi_args->sectorsize = root->fs_info->super_copy->sectorsize;
	fi_args->clone_alignment = root->fs_info->super_copy->sectorsize;

	if (copy_to_user(arg, fi_args, sizeof(*fi_args)))
		ret = -EFAULT;

	kfree(fi_args);
	return ret;
}

static long btrfs_ioctl_dev_info(struct btrfs_root *root, void __user *arg)
{
	struct btrfs_ioctl_dev_info_args *di_args;
	struct btrfs_device *dev;
	struct btrfs_fs_devices *fs_devices = root->fs_info->fs_devices;
	int ret = 0;
	char *s_uuid = NULL;

	di_args = memdup_user(arg, sizeof(*di_args));
	if (IS_ERR(di_args))
		return PTR_ERR(di_args);

	if (!btrfs_is_empty_uuid(di_args->uuid))
		s_uuid = di_args->uuid;

	mutex_lock(&fs_devices->device_list_mutex);
	dev = btrfs_find_device(root->fs_info, di_args->devid, s_uuid, NULL);

	if (!dev) {
		ret = -ENODEV;
		goto out;
	}

	di_args->devid = dev->devid;
	di_args->bytes_used = btrfs_device_get_bytes_used(dev);
	di_args->total_bytes = btrfs_device_get_total_bytes(dev);
	memcpy(di_args->uuid, dev->uuid, sizeof(di_args->uuid));
	if (dev->name) {
		struct rcu_string *name;

		rcu_read_lock();
		name = rcu_dereference(dev->name);
		strncpy(di_args->path, name->str, sizeof(di_args->path));
		rcu_read_unlock();
		di_args->path[sizeof(di_args->path) - 1] = 0;
	} else {
		di_args->path[0] = '\0';
	}

out:
	mutex_unlock(&fs_devices->device_list_mutex);
	if (ret == 0 && copy_to_user(arg, di_args, sizeof(*di_args)))
		ret = -EFAULT;

	kfree(di_args);
	return ret;
}

static struct page *extent_same_get_page(struct inode *inode, pgoff_t index)
{
	struct page *page;

	page = grab_cache_page(inode->i_mapping, index);
	if (!page)
		return ERR_PTR(-ENOMEM);

	if (!PageUptodate(page)) {
		int ret;

		ret = btrfs_readpage(NULL, page);
		if (ret)
			return ERR_PTR(ret);
		lock_page(page);
		if (!PageUptodate(page)) {
			unlock_page(page);
			page_cache_release(page);
			return ERR_PTR(-EIO);
		}
		if (page->mapping != inode->i_mapping) {
			unlock_page(page);
			page_cache_release(page);
			return ERR_PTR(-EAGAIN);
		}
	}

	return page;
}

static int gather_extent_pages(struct inode *inode, struct page **pages,
			       int num_pages, u64 off)
{
	int i;
	pgoff_t index = off >> PAGE_CACHE_SHIFT;

	for (i = 0; i < num_pages; i++) {
again:
		pages[i] = extent_same_get_page(inode, index + i);
		if (IS_ERR(pages[i])) {
			int err = PTR_ERR(pages[i]);

			if (err == -EAGAIN)
				goto again;
			pages[i] = NULL;
			return err;
		}
	}
	return 0;
}

static int lock_extent_range(struct inode *inode, u64 off, u64 len,
			     bool retry_range_locking)
{
	/*
	 * Do any pending delalloc/csum calculations on inode, one way or
	 * another, and lock file content.
	 * The locking order is:
	 *
	 *   1) pages
	 *   2) range in the inode's io tree
	 */
	while (1) {
		struct btrfs_ordered_extent *ordered;
		lock_extent(&BTRFS_I(inode)->io_tree, off, off + len - 1);
		ordered = btrfs_lookup_first_ordered_extent(inode,
							    off + len - 1);
		if ((!ordered ||
		     ordered->file_offset + ordered->len <= off ||
		     ordered->file_offset >= off + len) &&
		    !test_range_bit(&BTRFS_I(inode)->io_tree, off,
				    off + len - 1, EXTENT_DELALLOC, 0, NULL)) {
			if (ordered)
				btrfs_put_ordered_extent(ordered);
			break;
		}
		unlock_extent(&BTRFS_I(inode)->io_tree, off, off + len - 1);
		if (ordered)
			btrfs_put_ordered_extent(ordered);
		if (!retry_range_locking)
			return -EAGAIN;
		btrfs_wait_ordered_range(inode, off, len);
	}
	return 0;
}

static void btrfs_double_extent_unlock(struct inode *inode1, u64 loff1,
				      struct inode *inode2, u64 loff2, u64 len)
{
	unlock_extent(&BTRFS_I(inode1)->io_tree, loff1, loff1 + len - 1);
	unlock_extent(&BTRFS_I(inode2)->io_tree, loff2, loff2 + len - 1);
}

static int btrfs_double_extent_lock(struct inode *inode1, u64 loff1,
				    struct inode *inode2, u64 loff2, u64 len,
				    bool retry_range_locking)
{
	int ret;

	if (inode1 < inode2) {
		swap(inode1, inode2);
		swap(loff1, loff2);
	}
	ret = lock_extent_range(inode1, loff1, len, retry_range_locking);
	if (ret)
		return ret;
	ret = lock_extent_range(inode2, loff2, len, retry_range_locking);
	if (ret)
		unlock_extent(&BTRFS_I(inode1)->io_tree, loff1,
			      loff1 + len - 1);
	return ret;
}

struct cmp_pages {
	int		num_pages;
	struct page	**src_pages;
	struct page	**dst_pages;
};

static void btrfs_cmp_data_free(struct cmp_pages *cmp)
{
	int i;
	struct page *pg;

	for (i = 0; i < cmp->num_pages; i++) {
		pg = cmp->src_pages[i];
		if (pg) {
			unlock_page(pg);
			page_cache_release(pg);
		}
		pg = cmp->dst_pages[i];
		if (pg) {
			unlock_page(pg);
			page_cache_release(pg);
		}
	}
	kfree(cmp->src_pages);
	kfree(cmp->dst_pages);
}

static int btrfs_cmp_data_prepare(struct inode *src, u64 loff,
				  struct inode *dst, u64 dst_loff,
				  u64 len, struct cmp_pages *cmp)
{
	int ret;
	int num_pages = PAGE_CACHE_ALIGN(len) >> PAGE_CACHE_SHIFT;
	struct page **src_pgarr, **dst_pgarr;

	/*
	 * We must gather up all the pages before we initiate our
	 * extent locking. We use an array for the page pointers. Size
	 * of the array is bounded by len, which is in turn bounded by
	 * BTRFS_MAX_DEDUPE_LEN.
	 */
	src_pgarr = kcalloc(num_pages, sizeof(struct page *), GFP_KERNEL);
	dst_pgarr = kcalloc(num_pages, sizeof(struct page *), GFP_KERNEL);
	if (!src_pgarr || !dst_pgarr) {
		kfree(src_pgarr);
		kfree(dst_pgarr);
		return -ENOMEM;
	}
	cmp->num_pages = num_pages;
	cmp->src_pages = src_pgarr;
	cmp->dst_pages = dst_pgarr;

	/*
	 * If deduping ranges in the same inode, locking rules make it mandatory
	 * to always lock pages in ascending order to avoid deadlocks with
	 * concurrent tasks (such as starting writeback/delalloc).
	 */
	if (src == dst && dst_loff < loff) {
		swap(src_pgarr, dst_pgarr);
		swap(loff, dst_loff);
	}

	ret = gather_extent_pages(src, src_pgarr, cmp->num_pages, loff);
	if (ret)
		goto out;

	ret = gather_extent_pages(dst, dst_pgarr, cmp->num_pages, dst_loff);

out:
	if (ret)
		btrfs_cmp_data_free(cmp);
	return ret;
}

static int btrfs_cmp_data(struct inode *src, u64 loff, struct inode *dst,
			  u64 dst_loff, u64 len, struct cmp_pages *cmp)
{
	int ret = 0;
	int i;
	struct page *src_page, *dst_page;
	unsigned int cmp_len = PAGE_CACHE_SIZE;
	void *addr, *dst_addr;

	i = 0;
	while (len) {
		if (len < PAGE_CACHE_SIZE)
			cmp_len = len;

		BUG_ON(i >= cmp->num_pages);

		src_page = cmp->src_pages[i];
		dst_page = cmp->dst_pages[i];
		ASSERT(PageLocked(src_page));
		ASSERT(PageLocked(dst_page));

		addr = kmap_atomic(src_page);
		dst_addr = kmap_atomic(dst_page);

		flush_dcache_page(src_page);
		flush_dcache_page(dst_page);

		if (memcmp(addr, dst_addr, cmp_len))
			ret = BTRFS_SAME_DATA_DIFFERS;

		kunmap_atomic(addr);
		kunmap_atomic(dst_addr);

		if (ret)
			break;

		len -= cmp_len;
		i++;
	}

	return ret;
}

static int extent_same_check_offsets(struct inode *inode, u64 off, u64 *plen,
				     u64 olen)
{
	u64 len = *plen;
	u64 bs = BTRFS_I(inode)->root->fs_info->sb->s_blocksize;

	if (off + olen > inode->i_size || off + olen < off)
		return -EINVAL;

	/* if we extend to eof, continue to block boundary */
	if (off + len == inode->i_size)
		*plen = len = ALIGN(inode->i_size, bs) - off;

	/* Check that we are block aligned - btrfs_clone() requires this */
	if (!IS_ALIGNED(off, bs) || !IS_ALIGNED(off + len, bs))
		return -EINVAL;

	return 0;
}

static int btrfs_extent_same(struct inode *src, u64 loff, u64 olen,
			     struct inode *dst, u64 dst_loff)
{
	int ret;
	u64 len = olen;
	struct cmp_pages cmp;
	int same_inode = 0;
	u64 same_lock_start = 0;
	u64 same_lock_len = 0;

	if (IS_SWAPFILE(src) || IS_SWAPFILE(dst)) {
		return -ETXTBSY;
	}

	if (src == dst)
		same_inode = 1;

	if (len == 0)
		return 0;

	if (same_inode) {
		inode_lock(src);

		ret = extent_same_check_offsets(src, loff, &len, olen);
		if (ret)
			goto out_unlock;
		ret = extent_same_check_offsets(src, dst_loff, &len, olen);
		if (ret)
			goto out_unlock;

		/*
		 * Single inode case wants the same checks, except we
		 * don't want our length pushed out past i_size as
		 * comparing that data range makes no sense.
		 *
		 * extent_same_check_offsets() will do this for an
		 * unaligned length at i_size, so catch it here and
		 * reject the request.
		 *
		 * This effectively means we require aligned extents
		 * for the single-inode case, whereas the other cases
		 * allow an unaligned length so long as it ends at
		 * i_size.
		 */
		if (len != olen) {
			ret = -EINVAL;
			goto out_unlock;
		}

		/* Check for overlapping ranges */
		if (dst_loff + len > loff && dst_loff < loff + len) {
			ret = -EINVAL;
			goto out_unlock;
		}

		same_lock_start = min_t(u64, loff, dst_loff);
		same_lock_len = max_t(u64, loff, dst_loff) + len - same_lock_start;
	} else {
		lock_two_nondirectories(src, dst);

		ret = extent_same_check_offsets(src, loff, &len, olen);
		if (ret)
			goto out_unlock;

		ret = extent_same_check_offsets(dst, dst_loff, &len, olen);
		if (ret)
			goto out_unlock;
	}

	/* don't make the dst file partly checksummed */
	if ((BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) !=
	    (BTRFS_I(dst)->flags & BTRFS_INODE_NODATASUM)) {
		ret = -EINVAL;
		goto out_unlock;
	}

again:
	ret = btrfs_cmp_data_prepare(src, loff, dst, dst_loff, olen, &cmp);
	if (ret)
		goto out_unlock;

	if (same_inode)
		ret = lock_extent_range(src, same_lock_start, same_lock_len,
					false);
	else
		ret = btrfs_double_extent_lock(src, loff, dst, dst_loff, len,
					       false);
	/*
	 * If one of the inodes has dirty pages in the respective range or
	 * ordered extents, we need to flush dellaloc and wait for all ordered
	 * extents in the range. We must unlock the pages and the ranges in the
	 * io trees to avoid deadlocks when flushing delalloc (requires locking
	 * pages) and when waiting for ordered extents to complete (they require
	 * range locking).
	 */
	if (ret == -EAGAIN) {
		/*
		 * Ranges in the io trees already unlocked. Now unlock all
		 * pages before waiting for all IO to complete.
		 */
		btrfs_cmp_data_free(&cmp);
		if (same_inode) {
			btrfs_wait_ordered_range(src, same_lock_start,
						 same_lock_len);
		} else {
			btrfs_wait_ordered_range(src, loff, len);
			btrfs_wait_ordered_range(dst, dst_loff, len);
		}
		goto again;
	}
	ASSERT(ret == 0);
	if (WARN_ON(ret)) {
		/* ranges in the io trees already unlocked */
		btrfs_cmp_data_free(&cmp);
		return ret;
	}

	/* pass original length for comparison so we stay within i_size */
	ret = btrfs_cmp_data(src, loff, dst, dst_loff, olen, &cmp);
	if (ret == 0)
#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
		ret = btrfs_clone(src, dst, loff, olen, len, dst_loff, 1, 0, NULL);
#else
		ret = btrfs_clone(src, dst, loff, olen, len, dst_loff, 1, NULL);
#endif /* MY_ABC_HERE */
#else
#ifdef MY_ABC_HERE
		ret = btrfs_clone(src, dst, loff, olen, len, dst_loff, 1, 0);
#else
		ret = btrfs_clone(src, dst, loff, olen, len, dst_loff, 1);
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */

	if (same_inode)
		unlock_extent(&BTRFS_I(src)->io_tree, same_lock_start,
			      same_lock_start + same_lock_len - 1);
	else
		btrfs_double_extent_unlock(src, loff, dst, dst_loff, len);

	btrfs_cmp_data_free(&cmp);
out_unlock:
	if (same_inode)
		inode_unlock(src);
	else
		unlock_two_nondirectories(src, dst);

	return ret;
}

#define BTRFS_MAX_DEDUPE_LEN	SZ_16M

static long btrfs_ioctl_file_extent_same(struct file *file,
			struct btrfs_ioctl_same_args __user *argp)
{
	struct btrfs_ioctl_same_args *same = NULL;
	struct btrfs_ioctl_same_extent_info *info;
	struct inode *src = file_inode(file);
	u64 off;
	u64 len;
	int i;
	int ret;
	unsigned long size;
	u64 bs = BTRFS_I(src)->root->fs_info->sb->s_blocksize;
	bool is_admin = capable(CAP_SYS_ADMIN);
	u16 count;

	if (!(file->f_mode & FMODE_READ))
		return -EINVAL;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (get_user(count, &argp->dest_count)) {
		ret = -EFAULT;
		goto out;
	}

	size = offsetof(struct btrfs_ioctl_same_args __user, info[count]);

	same = memdup_user(argp, size);

	if (IS_ERR(same)) {
		ret = PTR_ERR(same);
		same = NULL;
		goto out;
	}

	off = same->logical_offset;
	len = same->length;

	/*
	 * Limit the total length we will dedupe for each operation.
	 * This is intended to bound the total time spent in this
	 * ioctl to something sane.
	 */
	if (len > BTRFS_MAX_DEDUPE_LEN)
		len = BTRFS_MAX_DEDUPE_LEN;

	if (WARN_ON_ONCE(bs < PAGE_CACHE_SIZE)) {
		/*
		 * Btrfs does not support blocksize < page_size. As a
		 * result, btrfs_cmp_data() won't correctly handle
		 * this situation without an update.
		 */
		ret = -EINVAL;
		goto out;
	}

	ret = -EISDIR;
	if (S_ISDIR(src->i_mode))
		goto out;

	ret = -EACCES;
	if (!S_ISREG(src->i_mode))
		goto out;

	/* pre-format output fields to sane values */
	for (i = 0; i < count; i++) {
		same->info[i].bytes_deduped = 0ULL;
		same->info[i].status = 0;
	}

	for (i = 0, info = same->info; i < count; i++, info++) {
		struct inode *dst;
		struct fd dst_file = fdget(info->fd);
		if (!dst_file.file) {
			info->status = -EBADF;
			continue;
		}
		dst = file_inode(dst_file.file);

		if (!(is_admin || (dst_file.file->f_mode & FMODE_WRITE))) {
			info->status = -EINVAL;
		} else if (file->f_path.mnt != dst_file.file->f_path.mnt) {
			info->status = -EXDEV;
		} else if (S_ISDIR(dst->i_mode)) {
			info->status = -EISDIR;
		} else if (!S_ISREG(dst->i_mode)) {
			info->status = -EACCES;
		} else {
			info->status = btrfs_extent_same(src, off, len, dst,
							info->logical_offset);
			if (info->status == 0)
				info->bytes_deduped += len;
		}
		fdput(dst_file);
	}

	ret = copy_to_user(argp, same, size);
	if (ret)
		ret = -EFAULT;

out:
	mnt_drop_write_file(file);
	kfree(same);
	return ret;
}

static int clone_finish_inode_update(struct btrfs_trans_handle *trans,
				     struct inode *inode,
				     u64 endoff,
				     const u64 destoff,
				     const u64 olen,
				     int no_time_update)
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;

	inode_inc_iversion(inode);
	if (!no_time_update)
		inode->i_mtime = inode->i_ctime = current_fs_time(inode->i_sb);
	/*
	 * We round up to the block size at eof when determining which
	 * extents to clone above, but shouldn't round up the file size.
	 */
	if (endoff > destoff + olen)
		endoff = destoff + olen;
	if (endoff > inode->i_size)
		btrfs_i_size_write(inode, endoff);

	ret = btrfs_update_inode(trans, root, inode);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		btrfs_end_transaction(trans, root);
		goto out;
	}
	ret = btrfs_end_transaction(trans, root);
out:
	return ret;
}

static void clone_update_extent_map(struct inode *inode,
				    const struct btrfs_trans_handle *trans,
				    const struct btrfs_path *path,
				    const u64 hole_offset,
				    const u64 hole_len)
{
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct extent_map *em;
	int ret;

	em = alloc_extent_map();
	if (!em) {
		set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
			&BTRFS_I(inode)->runtime_flags);
		return;
	}

	if (path) {
		struct btrfs_file_extent_item *fi;

		fi = btrfs_item_ptr(path->nodes[0], path->slots[0],
				    struct btrfs_file_extent_item);
		btrfs_extent_item_to_extent_map(inode, path, fi, false, em);
#ifdef MY_ABC_HERE
		/*
		 * if em->generation = -1, and em->list not empty,
		 * this extent_map will never can be free, when btrfs clone stress will OOM.
		 * but this extent_map is for incremental fsync, avoid data lose,
		 * for the case, set to trans->transid it ok, when super block generation < transid,
		 * need to log this extent_map, otherwise can ignore.
		 * Run xfstests btrfs/056 is pass.
		 */
		em->generation = trans->transid;
#else
		em->generation = -1;
#endif /* MY_ABC_HERE */
		if (btrfs_file_extent_type(path->nodes[0], fi) ==
		    BTRFS_FILE_EXTENT_INLINE)
			set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
				&BTRFS_I(inode)->runtime_flags);
	} else {
		em->start = hole_offset;
		em->len = hole_len;
		em->ram_bytes = em->len;
		em->orig_start = hole_offset;
		em->block_start = EXTENT_MAP_HOLE;
		em->block_len = 0;
		em->orig_block_len = 0;
		em->compress_type = BTRFS_COMPRESS_NONE;
		em->generation = trans->transid;
	}

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

	if (ret)
		set_bit(BTRFS_INODE_NEEDS_FULL_SYNC,
			&BTRFS_I(inode)->runtime_flags);
}

/*
 * Make sure we do not end up inserting an inline extent into a file that has
 * already other (non-inline) extents. If a file has an inline extent it can
 * not have any other extents and the (single) inline extent must start at the
 * file offset 0. Failing to respect these rules will lead to file corruption,
 * resulting in EIO errors on read/write operations, hitting BUG_ON's in mm, etc
 *
 * We can have extents that have been already written to disk or we can have
 * dirty ranges still in delalloc, in which case the extent maps and items are
 * created only when we run delalloc, and the delalloc ranges might fall outside
 * the range we are currently locking in the inode's io tree. So we check the
 * inode's i_size because of that (i_size updates are done while holding the
 * i_mutex, which we are holding here).
 * We also check to see if the inode has a size not greater than "datal" but has
 * extents beyond it, due to an fallocate with FALLOC_FL_KEEP_SIZE (and we are
 * protected against such concurrent fallocate calls by the i_mutex).
 *
 * If the file has no extents but a size greater than datal, do not allow the
 * copy because we would need turn the inline extent into a non-inline one (even
 * with NO_HOLES enabled). If we find our destination inode only has one inline
 * extent, just overwrite it with the source inline extent if its size is less
 * than the source extent's size, or we could copy the source inline extent's
 * data into the destination inode's inline extent if the later is greater then
 * the former.
 */
static int clone_copy_inline_extent(struct inode *src,
				    struct inode *dst,
				    struct btrfs_trans_handle *trans,
				    struct btrfs_path *path,
				    struct btrfs_key *new_key,
				    const u64 drop_start,
				    const u64 datal,
				    const u64 skip,
				    const u64 size,
				    char *inline_data)
{
	struct btrfs_root *root = BTRFS_I(dst)->root;
	const u64 aligned_end = ALIGN(new_key->offset + datal,
				      root->sectorsize);
	int ret;
	struct btrfs_key key;

	if (new_key->offset > 0)
		return -EOPNOTSUPP;

	key.objectid = btrfs_ino(dst);
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = 0;
	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				return ret;
			else if (ret > 0)
				goto copy_inline_extent;
		}
		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		if (key.objectid == btrfs_ino(dst) &&
		    key.type == BTRFS_EXTENT_DATA_KEY) {
			ASSERT(key.offset > 0);
			return -EOPNOTSUPP;
		}
	} else if (i_size_read(dst) <= datal) {
		struct btrfs_file_extent_item *ei;
		u64 ext_len;

		/*
		 * If the file size is <= datal, make sure there are no other
		 * extents following (can happen do to an fallocate call with
		 * the flag FALLOC_FL_KEEP_SIZE).
		 */
		ei = btrfs_item_ptr(path->nodes[0], path->slots[0],
				    struct btrfs_file_extent_item);
		/*
		 * If it's an inline extent, it can not have other extents
		 * following it.
		 */
		if (btrfs_file_extent_type(path->nodes[0], ei) ==
		    BTRFS_FILE_EXTENT_INLINE)
			goto copy_inline_extent;

		ext_len = btrfs_file_extent_num_bytes(path->nodes[0], ei);
		if (ext_len > aligned_end)
			return -EOPNOTSUPP;

		ret = btrfs_next_item(root, path);
		if (ret < 0) {
			return ret;
		} else if (ret == 0) {
			btrfs_item_key_to_cpu(path->nodes[0], &key,
					      path->slots[0]);
			if (key.objectid == btrfs_ino(dst) &&
			    key.type == BTRFS_EXTENT_DATA_KEY)
				return -EOPNOTSUPP;
		}
	}

copy_inline_extent:
	/*
	 * We have no extent items, or we have an extent at offset 0 which may
	 * or may not be inlined. All these cases are dealt the same way.
	 */
	if (i_size_read(dst) > datal) {
		/*
		 * If the destination inode has an inline extent...
		 * This would require copying the data from the source inline
		 * extent into the beginning of the destination's inline extent.
		 * But this is really complex, both extents can be compressed
		 * or just one of them, which would require decompressing and
		 * re-compressing data (which could increase the new compressed
		 * size, not allowing the compressed data to fit anymore in an
		 * inline extent).
		 * So just don't support this case for now (it should be rare,
		 * we are not really saving space when cloning inline extents).
		 */
		return -EOPNOTSUPP;
	}

	btrfs_release_path(path);
	ret = btrfs_drop_extents(trans, root, dst, drop_start, aligned_end, 1);
	if (ret)
		return ret;
	ret = btrfs_insert_empty_item(trans, root, path, new_key, size);
	if (ret)
		return ret;

	if (skip) {
		const u32 start = btrfs_file_extent_calc_inline_size(0);

		memmove(inline_data + start, inline_data + start + skip, datal);
	}

	write_extent_buffer(path->nodes[0], inline_data,
			    btrfs_item_ptr_offset(path->nodes[0],
						  path->slots[0]),
			    size);
	inode_add_bytes(dst, datal);

	return 0;
}

#ifdef MY_ABC_HERE
int btrfs_get_extent_refs_count(struct btrfs_fs_info *fs_info, u64 bytenr,
		                      u64 num_bytes, u64 *refs)
{
	struct btrfs_key key;
	struct btrfs_path *path;
	struct btrfs_delayed_ref_head *head;
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_transaction *cur_trans;
	struct btrfs_extent_item *ei;
	struct extent_buffer *extent_leaf;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	key.objectid = bytenr;
	key.type = BTRFS_EXTENT_ITEM_KEY;
	key.offset = num_bytes;

	/* Check committed refs */
	ret = btrfs_search_slot(NULL, fs_info->extent_root, &key, path, 0, 0);
	if (ret < 0)
		goto out;
	if (!ret) {
		extent_leaf = path->nodes[0];
		ei = btrfs_item_ptr(extent_leaf, path->slots[0], struct btrfs_extent_item);
		*refs += btrfs_extent_refs(extent_leaf, ei);
	}
	ret = 0;
	/* Check delayed refs */
	spin_lock(&fs_info->trans_lock);
	cur_trans = fs_info->running_transaction;
	if (cur_trans)
		atomic_inc(&cur_trans->use_count);
	spin_unlock(&fs_info->trans_lock);
	if (!cur_trans) {
		goto out;
	}
	delayed_refs = &cur_trans->delayed_refs;
	spin_lock(&delayed_refs->lock);
	head = btrfs_find_delayed_ref_head(delayed_refs, bytenr);
	if (!head) {
		spin_unlock(&delayed_refs->lock);
		btrfs_put_transaction(cur_trans);
		goto out;
	}
	*refs += head->node.ref_mod;
	spin_unlock(&delayed_refs->lock);
	btrfs_put_transaction(cur_trans);
out:
	btrfs_free_path(path);
	return ret;
}
static int cluster_pages_for_defrag(struct inode *inode,
				    struct page **pages,
				    unsigned long start_index,
				    unsigned long num_pages);
static int btrfs_clone_auto_rewrite(struct inode *inode, u64 off, u64 len)
{
	int ret = -1;
	struct page **pages = NULL;
	unsigned long cluster = len/PAGE_CACHE_SIZE;

	pages = kmalloc_array(cluster, sizeof(struct page *), GFP_NOFS);
	if (!pages) {
		ret = -ENOMEM;
		goto err;
	}
	ret = cluster_pages_for_defrag(inode, pages, off >> PAGE_CACHE_SHIFT, cluster);
	if (0 > ret)
		goto err;
	balance_dirty_pages_ratelimited(inode->i_mapping);
	filemap_flush(inode->i_mapping);

err:
	kfree(pages);

	return ret;
}

#endif /* MY_ABC_HERE */

/**
 * btrfs_clone() - clone a range from inode file to another
 *
 * @src: Inode to clone from
 * @inode: Inode to clone to
 * @off: Offset within source to start clone from
 * @olen: Original length, passed by user, of range to clone
 * @olen_aligned: Block-aligned value of olen
 * @destoff: Offset within @inode to start clone
 * @no_time_update: Whether to update mtime/ctime on the target inode
 */
static int btrfs_clone(struct inode *src, struct inode *inode,
#ifdef MY_ABC_HERE
		       const u64 off, const u64 olen, const u64 olen_aligned,
#ifdef MY_ABC_HERE
		       const u64 destoff, int no_time_update,
		       const int full_clone,
		       struct btrfs_syno_clone_range *args)
#else
		       const u64 destoff, int no_time_update,
		       struct btrfs_syno_clone_range *args);
#endif /* MY_ABC_HERE */
#else
#ifdef MY_ABC_HERE
		       const u64 destoff, int no_time_update,
		       const int full_clone)
#else
		       const u64 destoff, int no_time_update)
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */
{
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_path *path = NULL;
	struct extent_buffer *leaf;
	struct btrfs_trans_handle *trans;
	char *buf = NULL;
	struct btrfs_key key;
	u32 nritems;
	int slot;
	int ret;
	const u64 len = olen_aligned;
	u64 last_dest_end = destoff;
#ifdef MY_ABC_HERE
	u64 reserved_size = 0;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	struct ulist *disko_ulist;
	int check_backref = (full_clone == 0);
	int no_quota;
	int quota_enable = 1;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	int need_rewrite_dst = 0;
#endif

	ret = -ENOMEM;
	buf = kmalloc(root->nodesize, GFP_KERNEL | __GFP_NOWARN);
	if (!buf) {
		buf = vmalloc(root->nodesize);
		if (!buf)
			return ret;
	}

	path = btrfs_alloc_path();
	if (!path) {
		kvfree(buf);
		return ret;
	}

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
	if (btrfs_root_disable_quota(root) || !BTRFS_ANY_QUOTA_ENABLED(root->fs_info))
#else
	if (!BTRFS_ANY_QUOTA_ENABLED(root->fs_info))
#endif /* MY_ABC_HERE */
		quota_enable = 0;
	disko_ulist = ulist_alloc(GFP_NOFS);
	if (!disko_ulist) {
		btrfs_free_path(path);
		kvfree(buf);
		return ret;
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (full_clone)
		reserved_size = inode_get_bytes(src) + BTRFS_I(src)->delalloc_bytes;
	else
		reserved_size = olen_aligned;

	ret = btrfs_quota_reserve(root, inode, reserved_size);
	if (ret)
		goto fail_reserve;
#endif /* MY_ABC_HERE */

	path->reada = READA_FORWARD;
	/* clone data */
	key.objectid = btrfs_ino(src);
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = off;

	while (1) {
		u64 next_key_min_offset = key.offset + 1;

		/*
		 * note the key will change type as we walk through the
		 * tree.
		 */
		path->leave_spinning = 1;
		ret = btrfs_search_slot(NULL, BTRFS_I(src)->root, &key, path,
				0, 0);
		if (ret < 0)
			goto out;
		/*
		 * First search, if no extent item that starts at offset off was
		 * found but the previous item is an extent item, it's possible
		 * it might overlap our target range, therefore process it.
		 */
		if (key.offset == off && ret > 0 && path->slots[0] > 0) {
			btrfs_item_key_to_cpu(path->nodes[0], &key,
					      path->slots[0] - 1);
			if (key.type == BTRFS_EXTENT_DATA_KEY)
				path->slots[0]--;
		}

		nritems = btrfs_header_nritems(path->nodes[0]);
process_slot:
		if (path->slots[0] >= nritems) {
			ret = btrfs_next_leaf(BTRFS_I(src)->root, path);
			if (ret < 0)
				goto out;
			if (ret > 0)
				break;
			nritems = btrfs_header_nritems(path->nodes[0]);
		}
		leaf = path->nodes[0];
		slot = path->slots[0];

		btrfs_item_key_to_cpu(leaf, &key, slot);
		if (key.type > BTRFS_EXTENT_DATA_KEY ||
		    key.objectid != btrfs_ino(src))
			break;

		if (key.type == BTRFS_EXTENT_DATA_KEY) {
			struct btrfs_file_extent_item *extent;
			int type;
			u32 size;
			struct btrfs_key new_key;
			u64 disko = 0, diskl = 0;
			u64 datao = 0, datal = 0;
#ifdef MY_ABC_HERE
			u64 ram_bytes = 0;
#endif /* MY_ABC_HERE */
			u8 comp;
			u64 drop_start;

			extent = btrfs_item_ptr(leaf, slot,
						struct btrfs_file_extent_item);
			comp = btrfs_file_extent_compression(leaf, extent);
			type = btrfs_file_extent_type(leaf, extent);
			if (type == BTRFS_FILE_EXTENT_REG ||
			    type == BTRFS_FILE_EXTENT_PREALLOC) {
				disko = btrfs_file_extent_disk_bytenr(leaf,
								      extent);
				diskl = btrfs_file_extent_disk_num_bytes(leaf,
								 extent);
				datao = btrfs_file_extent_offset(leaf, extent);
				datal = btrfs_file_extent_num_bytes(leaf,
								    extent);
#ifdef MY_ABC_HERE
				ram_bytes = btrfs_file_extent_ram_bytes(leaf, extent);
#endif /* MY_ABC_HERE */
			} else if (type == BTRFS_FILE_EXTENT_INLINE) {
				/* take upper bound, may be compressed */
				datal = btrfs_file_extent_ram_bytes(leaf,
								    extent);
			}

			/*
			 * The first search might have left us at an extent
			 * item that ends before our target range's start, can
			 * happen if we have holes and NO_HOLES feature enabled.
			 */
			if (key.offset + datal <= off) {
				path->slots[0]++;
				goto process_slot;
			} else if (key.offset >= off + len) {
				break;
			}
			next_key_min_offset = key.offset + datal;
			size = btrfs_item_size_nr(leaf, slot);
			read_extent_buffer(leaf, buf,
					   btrfs_item_ptr_offset(leaf, slot),
					   size);

			btrfs_release_path(path);
			path->leave_spinning = 0;

			memcpy(&new_key, &key, sizeof(new_key));
			new_key.objectid = btrfs_ino(inode);
			if (off <= key.offset)
				new_key.offset = key.offset + destoff - off;
			else
				new_key.offset = destoff;

#ifdef MY_ABC_HERE
			if (type == BTRFS_FILE_EXTENT_REG && disko != 0 &&
				args && args->ref_limit) {
				u64 refs = 0;
				if (!btrfs_get_extent_refs_count(root->fs_info, disko,
				        diskl, &refs) && refs >= args->ref_limit) {
					args->src_off = (off > key.offset)?off:key.offset;
					args->src_len = datal;
					args->ref_limit = refs;
					if (args->flag & BTRFS_CLONE_RANGE_V2_AUTO_REWRITE_DST) {
						need_rewrite_dst = 1;
					} else {
						ret = -EMLINK;
						goto out;
					}
				}
			}
#endif /* MY_ABC_HERE */
			/*
			 * Deal with a hole that doesn't have an extent item
			 * that represents it (NO_HOLES feature enabled).
			 * This hole is either in the middle of the cloning
			 * range or at the beginning (fully overlaps it or
			 * partially overlaps it).
			 */
			if (new_key.offset != last_dest_end)
				drop_start = last_dest_end;
			else
				drop_start = new_key.offset;

			/*
			 * 1 - adjusting old extent (we may have to split it)
			 * 1 - add new extent
			 * 1 - inode update
			 */
			trans = btrfs_start_transaction(root, 3);
			if (IS_ERR(trans)) {
				ret = PTR_ERR(trans);
				goto out;
			}

			if (type == BTRFS_FILE_EXTENT_REG ||
			    type == BTRFS_FILE_EXTENT_PREALLOC) {
				/*
				 *    a  | --- range to clone ---|  b
				 * | ------------- extent ------------- |
				 */

				/* subtract range b */
				if (key.offset + datal > off + len)
					datal = off + len - key.offset;

				/* subtract range a */
				if (off > key.offset) {
					datao += off - key.offset;
					datal -= off - key.offset;
				}

				ret = btrfs_drop_extents(trans, root, inode,
							 drop_start,
							 new_key.offset + datal,
							 1);
				if (ret) {
					if (ret != -EOPNOTSUPP)
						btrfs_abort_transaction(trans,
								root, ret);
					btrfs_end_transaction(trans, root);
					goto out;
				}

				ret = btrfs_insert_empty_item(trans, root, path,
							      &new_key, size);
				if (ret) {
					btrfs_abort_transaction(trans, root,
								ret);
					btrfs_end_transaction(trans, root);
					goto out;
				}

				leaf = path->nodes[0];
				slot = path->slots[0];
				write_extent_buffer(leaf, buf,
					    btrfs_item_ptr_offset(leaf, slot),
					    size);

				extent = btrfs_item_ptr(leaf, slot,
						struct btrfs_file_extent_item);

				/* disko == 0 means it's a hole */
				if (!disko)
					datao = 0;

				btrfs_set_file_extent_offset(leaf, extent,
							     datao);
				btrfs_set_file_extent_num_bytes(leaf, extent,
								datal);
#ifdef MY_ABC_HERE
				if (need_rewrite_dst)
					args->dest_len = datal;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
				/* If we have an implicit hole (NO_HOLES feature). */
				if (drop_start < new_key.offset)
					clone_update_extent_map(inode, trans,
							NULL, drop_start,
							new_key.offset - drop_start);

				clone_update_extent_map(inode, trans, path, 0, 0);

				btrfs_mark_buffer_dirty(leaf);
				btrfs_release_path(path);
#endif /* MY_ABC_HERE */

				if (disko) {
					inode_add_bytes(inode, datal);
#ifdef MY_ABC_HERE
					if (quota_enable && src != inode &&
						ulist_add_lru_adjust(disko_ulist, disko, 0, GFP_NOFS)) {
						no_quota = 0;
						if (check_backref) {
							no_quota = check_root_inode_ref(trans, root->fs_info,
							    disko, 0, root->objectid, btrfs_ino(inode),
							    (u64)-1, 0);
							if (no_quota < 0) {
								btrfs_abort_transaction(trans, root, ret);
								btrfs_end_transaction(trans, root);
								ret = no_quota;
								goto out;
							}
						}
						if (disko_ulist->nnodes > ULIST_NODES_MAX) {
							check_backref = 1;
							ulist_remove_first(disko_ulist);
						}
					} else {
						no_quota = 1;
					}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
					ret = btrfs_inc_extent_ref_uid(trans, root,
							disko, diskl, 0,
							root->root_key.objectid,
							btrfs_ino(inode),
							new_key.offset - datao,
							no_quota, no_quota ? 0 : ram_bytes,
							inode, i_uid_read(inode));
#else
					ret = btrfs_inc_extent_ref(trans, root,
							disko, diskl, 0,
							root->root_key.objectid,
							btrfs_ino(inode),
							new_key.offset - datao
#ifdef MY_ABC_HERE
							,no_quota, no_quota ? 0 : ram_bytes
#endif /* MY_ABC_HERE */
							);
#endif /* MY_ABC_HERE */
					if (ret) {
						btrfs_abort_transaction(trans,
									root,
									ret);
						btrfs_end_transaction(trans,
								      root);
						goto out;

					}
#ifdef MY_ABC_HERE
					if (reserved_size && !no_quota) {
#ifdef MY_ABC_HERE
						if (reserved_size >= ram_bytes)
							reserved_size -= ram_bytes;
#else
						if (reserved_size >= diskl)
							reserved_size -= diskl;
#endif /* MY_ABC_HERE */
						else
							reserved_size = 0;
					}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
					if (!full_clone && off != destoff) {
						ret = btrfs_set_disk_extent_flags(trans, root, disko,
						    diskl, BTRFS_EXTENT_FLAG_HAS_CLONE_RANGE, 0, 1);
						if (ret) {
							btrfs_abort_transaction(trans, root, ret);
							btrfs_end_transaction(trans, root);
							goto out;
						}
					}
#endif /* MY_ABC_HERE */
				}
			} else if (type == BTRFS_FILE_EXTENT_INLINE) {
				u64 skip = 0;
				u64 trim = 0;

				if (off > key.offset) {
					skip = off - key.offset;
					new_key.offset += skip;
				}

				if (key.offset + datal > off + len)
					trim = key.offset + datal - (off + len);

				if (comp && (skip || trim)) {
					ret = -EINVAL;
					btrfs_end_transaction(trans, root);
					goto out;
				}
				size -= skip + trim;
				datal -= skip + trim;

				ret = clone_copy_inline_extent(src, inode,
							       trans, path,
							       &new_key,
							       drop_start,
							       datal,
							       skip, size, buf);
				if (ret) {
					if (ret != -EOPNOTSUPP)
						btrfs_abort_transaction(trans,
									root,
									ret);
					btrfs_end_transaction(trans, root);
					goto out;
				}
				leaf = path->nodes[0];
				slot = path->slots[0];
			}

#ifdef MY_ABC_HERE
			if (type == BTRFS_FILE_EXTENT_INLINE) {
#endif /* MY_ABC_HERE */
			/* If we have an implicit hole (NO_HOLES feature). */
			if (drop_start < new_key.offset)
				clone_update_extent_map(inode, trans,
						NULL, drop_start,
						new_key.offset - drop_start);

			clone_update_extent_map(inode, trans, path, 0, 0);

			btrfs_mark_buffer_dirty(leaf);
			btrfs_release_path(path);
#ifdef MY_ABC_HERE
			}
#endif /* MY_ABC_HERE */

			last_dest_end = ALIGN(new_key.offset + datal,
					      root->sectorsize);
			ret = clone_finish_inode_update(trans, inode,
							last_dest_end,
							destoff, olen,
							no_time_update);
			if (ret)
				goto out;
			if (need_rewrite_dst) {
				ret = -EMLINK;
				goto out;
			}
			if (new_key.offset + datal >= destoff + len)
				break;
		}
		btrfs_release_path(path);
		key.offset = next_key_min_offset;

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
	}
	ret = 0;

	if (last_dest_end < destoff + len) {
		/*
		 * We have an implicit hole (NO_HOLES feature is enabled) that
		 * fully or partially overlaps our cloning range at its end.
		 */
		btrfs_release_path(path);

		/*
		 * 1 - remove extent(s)
		 * 1 - inode update
		 */
		trans = btrfs_start_transaction(root, 2);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out;
		}
		ret = btrfs_drop_extents(trans, root, inode,
					 last_dest_end, destoff + len, 1);
		if (ret) {
			if (ret != -EOPNOTSUPP)
				btrfs_abort_transaction(trans, root, ret);
			btrfs_end_transaction(trans, root);
			goto out;
		}
		clone_update_extent_map(inode, trans, NULL, last_dest_end,
					destoff + len - last_dest_end);
		ret = clone_finish_inode_update(trans, inode, destoff + len,
						destoff, olen, no_time_update);
	}

out:
#ifdef MY_ABC_HERE
	if (reserved_size) {
		btrfs_quota_reserve_free(root, inode, reserved_size);
	}
fail_reserve:
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	ulist_free(disko_ulist);
#endif /* MY_ABC_HERE */
	btrfs_free_path(path);
	kvfree(buf);
	return ret;
}

#ifdef MY_ABC_HERE
/*
 * caller need get inode lock
 */
static int syno_inode_clone_change_flags(struct inode *src, struct inode *inode, u64 destoff)
{
	int ret;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	unsigned int flags;
	u64 ip_oldflags;

	if ((BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) ==
		(BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)) {
		ret = 0;
		goto out;
	}

	if (0 != destoff) {
		ret = -EINVAL;
		goto out;
	}

	/* wait all lockless writes */
	down_write(&BTRFS_I(inode)->dio_sem);
	btrfs_wait_ordered_range(inode, 0, -1);

	if (0 != inode_get_bytes(inode)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	ip_oldflags = BTRFS_I(inode)->flags;
	flags = btrfs_flags_to_ioctl(BTRFS_I(inode)->flags);

	if (BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) {
		flags |= FS_NOCOW_FL;
		BTRFS_I(inode)->flags |= BTRFS_INODE_NODATASUM|BTRFS_INODE_NODATACOW;
	} else {
		flags &= ~FS_NOCOW_FL;
		BTRFS_I(inode)->flags &= ~(BTRFS_INODE_NODATASUM|BTRFS_INODE_NODATACOW);
	}

	trans = btrfs_start_transaction(root, 1);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_drop;
	}

	inode_inc_iversion(inode);
	inode->i_ctime = current_fs_time(inode->i_sb);
	ret = btrfs_update_inode(trans, root, inode);


	btrfs_end_transaction(trans, root);
out_drop:
	if (ret)
		BTRFS_I(inode)->flags = ip_oldflags;
out_unlock:
	up_write(&BTRFS_I(inode)->dio_sem);
out:
	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static noinline int btrfs_clone_files(struct file *file, struct file *file_src,
					u64 off, u64 olen, u64 destoff,
					struct btrfs_syno_clone_range *args)
#else
static noinline int btrfs_clone_files(struct file *file, struct file *file_src,
					u64 off, u64 olen, u64 destoff)
#endif /* MY_ABC_HERE */
{
	struct inode *inode = file_inode(file);
	struct inode *src = file_inode(file_src);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	int ret;
	u64 len = olen;
	u64 bs = root->fs_info->sb->s_blocksize;
	int same_inode = src == inode;
#ifdef MY_ABC_HERE
	int full_clone = 0;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	u64 truncate_destoff = 0, truncate_len = 0;
#endif /* MY_ABC_HERE */

	/*
	 * TODO:
	 * - split compressed inline extents.  annoying: we need to
	 *   decompress into destination's address_space (the file offset
	 *   may change, so source mapping won't do), then recompress (or
	 *   otherwise reinsert) a subrange.
	 *
	 * - split destination inode's inline extents.  The inline extents can
	 *   be either compressed or non-compressed.
	 */

	if (btrfs_root_readonly(root))
		return -EROFS;

	if (file_src->f_path.mnt != file->f_path.mnt ||
	    src->i_sb != inode->i_sb)
		return -EXDEV;

#ifdef MY_ABC_HERE
#else
	/* don't make the dst file partly checksummed */
	if ((BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) !=
	    (BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM))
		return -EINVAL;
#endif /* MY_ABC_HERE */

	if (S_ISDIR(src->i_mode) || S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (!same_inode) {
		lock_two_nondirectories(src, inode);
	} else {
		inode_lock(src);
	}

#ifdef MY_ABC_HERE
	ret = syno_inode_clone_change_flags(src, inode, destoff);
	if (ret)
		goto out_unlock;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (0 == off && 0 == olen && 0 == destoff && 0 == inode_get_bytes(inode))
		full_clone = 1;
#endif /* MY_ABC_HERE */

	if (IS_SWAPFILE(src) || IS_SWAPFILE(inode)) {
		ret = -ETXTBSY;
		goto out_unlock;
	}

	/* don't make the dst file partly checksummed */
	if ((BTRFS_I(src)->flags & BTRFS_INODE_NODATASUM) !=
	    (BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* determine range to clone */
	ret = -EINVAL;
	if (off + len > src->i_size || off + len < off)
		goto out_unlock;
	if (len == 0)
		olen = len = src->i_size - off;
	/*
	 * If we extend to eof, continue to block boundary if and only if the
	 * destination end offset matches the destination file's size, otherwise
	 * we would be corrupting data by placing the eof block into the middle
	 * of a file.
	 */
	if (off + len == src->i_size) {
		if (!IS_ALIGNED(len, bs) && destoff + len < inode->i_size)
			goto out_unlock;
		len = ALIGN(src->i_size, bs) - off;
	}

	if (len == 0) {
		ret = 0;
		goto out_unlock;
	}

	/* verify the end result is block aligned */
	if (!IS_ALIGNED(off, bs) || !IS_ALIGNED(off + len, bs) ||
	    !IS_ALIGNED(destoff, bs))
		goto out_unlock;

	/* verify if ranges are overlapped within the same file */
	if (same_inode) {
		if (destoff + len > off && destoff < off + len)
			goto out_unlock;
	}

	if (destoff > inode->i_size) {
		ret = btrfs_cont_expand(inode, inode->i_size, destoff);
		if (ret)
			goto out_unlock;
	}

#ifdef MY_ABC_HERE
	truncate_destoff = destoff;
	truncate_len = len;
clone_again:
#endif /* MY_ABC_HERE */
	/*
	 * Lock the target range too. Right after we replace the file extent
	 * items in the fs tree (which now point to the cloned data), we might
	 * have a worker replace them with extent items relative to a write
	 * operation that was issued before this clone operation (i.e. confront
	 * with inode.c:btrfs_finish_ordered_io).
	 */
	if (same_inode) {
		u64 lock_start = min_t(u64, off, destoff);
		u64 lock_len = max_t(u64, off, destoff) + len - lock_start;

		ret = lock_extent_range(src, lock_start, lock_len, true);
	} else {
		ret = btrfs_double_extent_lock(src, off, inode, destoff, len,
					       true);
	}
	ASSERT(ret == 0);
	if (WARN_ON(ret)) {
		/* ranges in the io trees already unlocked */
		goto out_unlock;
	}

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
	ret = btrfs_clone(src, inode, off, olen, len, destoff, 0, full_clone, args);
#else
	ret = btrfs_clone(src, inode, off, olen, len, destoff, 0, args);
#endif /* MY_ABC_HERE */
#else
#ifdef MY_ABC_HERE
	ret = btrfs_clone(src, inode, off, olen, len, destoff, 0, full_clone);
#else
	ret = btrfs_clone(src, inode, off, olen, len, destoff, 0);
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */

	if (same_inode) {
		u64 lock_start = min_t(u64, off, destoff);
		u64 lock_end = max_t(u64, off, destoff) + len - 1;

		unlock_extent(&BTRFS_I(src)->io_tree, lock_start, lock_end);
	} else {
		btrfs_double_extent_unlock(src, off, inode, destoff, len);
	}
#ifdef MY_ABC_HERE
	if (ret == -EMLINK) {
		if (args->flag & BTRFS_CLONE_RANGE_V2_AUTO_REWRITE_SRC) {
			ret = btrfs_clone_auto_rewrite(src, args->src_off, args->src_len);
			if (0 > ret)
				goto out_unlock;
			destoff = destoff + (args->src_off - off);
			len = len - (args->src_off - off);
			off = args->src_off;
			olen = len;
			goto clone_again;
		} else if (args->flag & BTRFS_CLONE_RANGE_V2_AUTO_REWRITE_DST) {
			ret = btrfs_clone_auto_rewrite(inode, destoff + (args->src_off - off), args->dest_len);
			if (0 > ret)
				goto out_unlock;
			destoff = destoff + (args->src_off - off) + args->dest_len;;
			len = len - (args->src_off - off) - args->dest_len;
			off = args->src_off + args->dest_len;
			olen = len;
			if (len)
				goto clone_again;
		}
	}
	/*
	 * Truncate page cache pages so that future reads will see the cloned
	 * data immediately and not the previous data.
	 */
	truncate_inode_pages_range(&inode->i_data, truncate_destoff,
				   PAGE_CACHE_ALIGN(truncate_destoff + truncate_len) - 1);
#else /* MY_ABC_HERE */
	/*
	 * Truncate page cache pages so that future reads will see the cloned
	 * data immediately and not the previous data.
	 */
	truncate_inode_pages_range(&inode->i_data, destoff,
				   PAGE_CACHE_ALIGN(destoff + len) - 1);
#endif /* MY_ABC_HERE */
out_unlock:
	if (!same_inode)
		unlock_two_nondirectories(src, inode);
	else
		inode_unlock(src);
	return ret;
}

#ifdef MY_ABC_HERE
int btrfs_clone_check_compr(struct file *file, struct file *file_src)
{
	struct inode *inode = file_inode(file);
	struct inode *src = file_inode(file_src);

	if ((BTRFS_I(src)->flags & BTRFS_INODE_COMPRESS) !=
		(BTRFS_I(inode)->flags & BTRFS_INODE_COMPRESS))
		return -EINVAL;
	return 0;
}
#endif /* MY_ABC_HERE */


#ifdef MY_ABC_HERE
static noinline long btrfs_ioctl_clone(struct file *file, unsigned long srcfd,
				       u64 off, u64 olen, u64 destoff)
{
	struct fd src_file;
	int ret;

	/* the destination must be opened for writing */
	if (!(file->f_mode & FMODE_WRITE) || (file->f_flags & O_APPEND))
		return -EINVAL;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	src_file = fdget(srcfd);
	if (!src_file.file) {
		ret = -EBADF;
		goto out_drop_write;
	}

	/* the src must be open for reading */
	if (!(src_file.file->f_mode & FMODE_READ)) {
		ret = -EINVAL;
		goto out_fput;
	}

#ifdef MY_ABC_HERE
	ret = btrfs_clone_check_compr(file, src_file.file);
	if (ret) {
		goto out_fput;
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	ret = btrfs_clone_files(file, src_file.file, off, olen, destoff, NULL);
#else
	ret = btrfs_clone_files(file, src_file.file, off, olen, destoff);
#endif /* MY_ABC_HERE */

out_fput:
	fdput(src_file);
out_drop_write:
	mnt_drop_write_file(file);
	return ret;
}

long btrfs_lazy_clone(struct file *file, unsigned long srcfd, u64 off,
	u64 olen, u64 destoff)
{
	return btrfs_ioctl_clone(file, srcfd, off, olen, destoff);
}
EXPORT_SYMBOL(btrfs_lazy_clone);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int clone_verify_area(struct file *file, loff_t pos, u64 len, bool write)
{
	struct inode *inode = file_inode(file);

	if (unlikely(pos < 0))
		return -EINVAL;

	 if (unlikely((loff_t) (pos + len) < 0))
		return -EINVAL;

	if (unlikely(inode->i_flctx && mandatory_lock(inode))) {
		loff_t end = len ? pos + len - 1 : OFFSET_MAX;
		int retval;

		retval = locks_mandatory_area(inode, file, pos, end,
				write ? F_WRLCK : F_RDLCK);
		if (retval < 0)
			return retval;
	}

	return security_file_permission(file, write ? MAY_WRITE : MAY_READ);
}

static int clone_argument_check(struct file *file_in, struct file *file_out,
							loff_t pos_in, loff_t pos_out, u64 len)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	int ret;

	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode)) {
		ret = -EISDIR;
		goto out;
	}
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode)) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * FICLONE/FICLONERANGE ioctls enforce that src and dest files are on
	 * the same mount. Practically, they only need to be on the same file
	 * system.
	 */
	if (inode_in->i_sb != inode_out->i_sb) {
		ret = -EXDEV;
		goto out;
	}

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE) ||
	    (file_out->f_flags & O_APPEND)) {
		ret = -EBADF;
		goto out;
	}

	ret = clone_verify_area(file_in, pos_in, len, false);
	if (ret)
		goto out;

	ret = clone_verify_area(file_out, pos_out, len, true);
	if (ret)
		goto out;

	if (pos_in + len > i_size_read(inode_in)) {
		ret = -EINVAL;
		goto out;
	}

	if (pos_in || pos_out || len) {
		ret = btrfs_clone_check_compr(file_in, file_out);
		if (ret)
			goto out;
	}

out:
	return ret;
}

int btrfs_ioctl_syno_clone_range_v2(struct file *dst_file, struct btrfs_ioctl_syno_clone_range_args_v2 __user *argp)
{
	struct fd src_file;
	int ret;
	__s64 src_fd = 0;
	struct btrfs_syno_clone_range args;

	memset(&args, 0, sizeof(args));
	if (copy_from_user(&args.src_off, &argp->src_offset, sizeof(args.src_off))||
		copy_from_user(&args.src_len, &argp->src_length, sizeof(args.src_len))||
		copy_from_user(&args.dest_off, &argp->dest_offset, sizeof(args.dest_off))||
		copy_from_user(&args.ref_limit, &argp->ref_limit, sizeof(args.ref_limit))||
		copy_from_user(&args.flag, &argp->flag, sizeof(args.flag))||
		copy_from_user(&src_fd, &argp->src_fd, sizeof(src_fd)))
		return -EFAULT;

	src_file = fdget(src_fd);
	if (!src_file.file)
		return -EBADF;

	ret = clone_argument_check(src_file.file, dst_file, args.src_off, args.dest_off, args.src_len);
	if (ret)
		goto fdput;

	ret = btrfs_clone_files(dst_file, src_file.file, args.src_off,
	               args.src_len, args.dest_off, &args);
	if (ret && ret == -EMLINK) {
		if (put_user(args.src_off, &argp->src_offset) ||
		    put_user(args.src_len, &argp->src_length) ||
		    put_user(args.ref_limit, &argp->ref_limit))
			ret = -EFAULT;
	}
fdput:
	fdput(src_file);
	return ret;
}
#endif /* MY_ABC_HERE */

int btrfs_clone_file_range(struct file *src_file, loff_t off,
		struct file *dst_file, loff_t destoff, u64 len)
{
#ifdef MY_ABC_HERE
	return btrfs_clone_files(dst_file, src_file, off, len, destoff, NULL);
#else
	return btrfs_clone_files(dst_file, src_file, off, len, destoff);
#endif /* MY_ABC_HERE */
}

/*
 * there are many ways the trans_start and trans_end ioctls can lead
 * to deadlocks.  They should only be used by applications that
 * basically own the machine, and have a very in depth understanding
 * of all the possible deadlocks and enospc problems.
 */
static long btrfs_ioctl_trans_start(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	struct btrfs_file_private *private;
	int ret;

	ret = -EPERM;
	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = -EINPROGRESS;
	private = file->private_data;
	if (private && private->trans)
		goto out;
	if (!private) {
		private = kzalloc(sizeof(struct btrfs_file_private),
				  GFP_KERNEL);
		if (!private)
			return -ENOMEM;
		file->private_data = private;
	}

	ret = -EROFS;
	if (btrfs_root_readonly(root))
		goto out;

	ret = mnt_want_write_file(file);
	if (ret)
		goto out;

	atomic_inc(&root->fs_info->open_ioctl_trans);

	ret = -ENOMEM;
	trans = btrfs_start_ioctl_transaction(root);
	if (IS_ERR(trans))
		goto out_drop;

	private->trans = trans;
	return 0;

out_drop:
	atomic_dec(&root->fs_info->open_ioctl_trans);
	mnt_drop_write_file(file);
out:
	return ret;
}

static long btrfs_ioctl_default_subvol(struct file *file, void __user *argp)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_root *new_root;
	struct btrfs_dir_item *di;
	struct btrfs_trans_handle *trans;
	struct btrfs_path *path;
	struct btrfs_key location;
	struct btrfs_disk_key disk_key;
	u64 objectid = 0;
	u64 dir_id;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (copy_from_user(&objectid, argp, sizeof(objectid))) {
		ret = -EFAULT;
		goto out;
	}

	if (!objectid)
		objectid = BTRFS_FS_TREE_OBJECTID;

	location.objectid = objectid;
	location.type = BTRFS_ROOT_ITEM_KEY;
	location.offset = (u64)-1;

	new_root = btrfs_read_fs_root_no_name(root->fs_info, &location);
	if (IS_ERR(new_root)) {
		ret = PTR_ERR(new_root);
		goto out;
	}
	if (!is_fstree(new_root->objectid)) {
		ret = -ENOENT;
		goto out;
	}

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}
	path->leave_spinning = 1;

	trans = btrfs_start_transaction(root, 1);
	if (IS_ERR(trans)) {
		btrfs_free_path(path);
		ret = PTR_ERR(trans);
		goto out;
	}

	dir_id = btrfs_super_root_dir(root->fs_info->super_copy);
	di = btrfs_lookup_dir_item(trans, root->fs_info->tree_root, path,
				   dir_id, "default", 7, 1);
	if (IS_ERR_OR_NULL(di)) {
		btrfs_free_path(path);
		btrfs_end_transaction(trans, root);
		btrfs_err(new_root->fs_info, "Umm, you don't have the default dir"
			   "item, this isn't going to work");
		ret = -ENOENT;
		goto out;
	}

	btrfs_cpu_key_to_disk(&disk_key, &new_root->root_key);
	btrfs_set_dir_item_key(path->nodes[0], di, &disk_key);
	btrfs_mark_buffer_dirty(path->nodes[0]);
	btrfs_free_path(path);

	btrfs_set_fs_incompat(root->fs_info, DEFAULT_SUBVOL);
	btrfs_end_transaction(trans, root);
out:
	mnt_drop_write_file(file);
	return ret;
}

void btrfs_get_block_group_info(struct list_head *groups_list,
				struct btrfs_ioctl_space_info *space)
{
	struct btrfs_block_group_cache *block_group;

	space->total_bytes = 0;
	space->used_bytes = 0;
	space->flags = 0;
	list_for_each_entry(block_group, groups_list, list) {
		space->flags = block_group->flags;
		space->total_bytes += block_group->key.offset;
		space->used_bytes +=
			btrfs_block_group_used(&block_group->item);
	}
}

static long btrfs_ioctl_space_info(struct btrfs_root *root, void __user *arg)
{
	struct btrfs_ioctl_space_args space_args;
	struct btrfs_ioctl_space_info space;
	struct btrfs_ioctl_space_info *dest;
	struct btrfs_ioctl_space_info *dest_orig;
	struct btrfs_ioctl_space_info __user *user_dest;
	struct btrfs_space_info *info;
	u64 types[] = {BTRFS_BLOCK_GROUP_DATA,
		       BTRFS_BLOCK_GROUP_SYSTEM,
		       BTRFS_BLOCK_GROUP_METADATA,
		       BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA};
	int num_types = 4;
	int alloc_size;
	int ret = 0;
	u64 slot_count = 0;
	int i, c;

	if (copy_from_user(&space_args,
			   (struct btrfs_ioctl_space_args __user *)arg,
			   sizeof(space_args)))
		return -EFAULT;

	for (i = 0; i < num_types; i++) {
		struct btrfs_space_info *tmp;

		info = NULL;
		rcu_read_lock();
		list_for_each_entry_rcu(tmp, &root->fs_info->space_info,
					list) {
			if (tmp->flags == types[i]) {
				info = tmp;
				break;
			}
		}
		rcu_read_unlock();

		if (!info)
			continue;

		down_read(&info->groups_sem);
		for (c = 0; c < BTRFS_NR_RAID_TYPES; c++) {
			if (!list_empty(&info->block_groups[c]))
				slot_count++;
		}
		up_read(&info->groups_sem);
	}

	/*
	 * Global block reserve, exported as a space_info
	 */
	slot_count++;

	/* space_slots == 0 means they are asking for a count */
	if (space_args.space_slots == 0) {
		space_args.total_spaces = slot_count;
		goto out;
	}

	slot_count = min_t(u64, space_args.space_slots, slot_count);

	alloc_size = sizeof(*dest) * slot_count;

	/* we generally have at most 6 or so space infos, one for each raid
	 * level.  So, a whole page should be more than enough for everyone
	 */
	if (alloc_size > PAGE_CACHE_SIZE)
		return -ENOMEM;

	space_args.total_spaces = 0;
	dest = kmalloc(alloc_size, GFP_KERNEL);
	if (!dest)
		return -ENOMEM;
	dest_orig = dest;

	/* now we have a buffer to copy into */
	for (i = 0; i < num_types; i++) {
		struct btrfs_space_info *tmp;

		if (!slot_count)
			break;

		info = NULL;
		rcu_read_lock();
		list_for_each_entry_rcu(tmp, &root->fs_info->space_info,
					list) {
			if (tmp->flags == types[i]) {
				info = tmp;
				break;
			}
		}
		rcu_read_unlock();

		if (!info)
			continue;
		down_read(&info->groups_sem);
		for (c = 0; c < BTRFS_NR_RAID_TYPES; c++) {
			if (!list_empty(&info->block_groups[c])) {
				btrfs_get_block_group_info(
					&info->block_groups[c], &space);
				memcpy(dest, &space, sizeof(space));
				dest++;
				space_args.total_spaces++;
				slot_count--;
			}
			if (!slot_count)
				break;
		}
		up_read(&info->groups_sem);
	}

	/*
	 * Add global block reserve
	 */
	if (slot_count) {
		struct btrfs_block_rsv *block_rsv = &root->fs_info->global_block_rsv;

		spin_lock(&block_rsv->lock);
		space.total_bytes = block_rsv->size;
		space.used_bytes = block_rsv->size - block_rsv->reserved;
		spin_unlock(&block_rsv->lock);
		space.flags = BTRFS_SPACE_INFO_GLOBAL_RSV;
		memcpy(dest, &space, sizeof(space));
		space_args.total_spaces++;
	}

	user_dest = (struct btrfs_ioctl_space_info __user *)
		(arg + sizeof(struct btrfs_ioctl_space_args));

	if (copy_to_user(user_dest, dest_orig, alloc_size))
		ret = -EFAULT;

	kfree(dest_orig);
out:
	if (ret == 0 && copy_to_user(arg, &space_args, sizeof(space_args)))
		ret = -EFAULT;

	return ret;
}

/*
 * there are many ways the trans_start and trans_end ioctls can lead
 * to deadlocks.  They should only be used by applications that
 * basically own the machine, and have a very in depth understanding
 * of all the possible deadlocks and enospc problems.
 */
long btrfs_ioctl_trans_end(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_file_private *private = file->private_data;

	if (!private || !private->trans)
		return -EINVAL;

	btrfs_end_transaction(private->trans, root);
	private->trans = NULL;

	atomic_dec(&root->fs_info->open_ioctl_trans);

	mnt_drop_write_file(file);
	return 0;
}

static noinline long btrfs_ioctl_start_sync(struct btrfs_root *root,
					    void __user *argp)
{
	struct btrfs_trans_handle *trans;
	u64 transid;
	int ret;

	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		if (PTR_ERR(trans) != -ENOENT)
			return PTR_ERR(trans);

		/* No running transaction, don't bother */
		transid = root->fs_info->last_trans_committed;
		goto out;
	}
	transid = trans->transid;
	ret = btrfs_commit_transaction_async(trans, root, 0);
	if (ret) {
		btrfs_end_transaction(trans, root);
		return ret;
	}
out:
	if (argp)
		if (copy_to_user(argp, &transid, sizeof(transid)))
			return -EFAULT;
	return 0;
}

static noinline long btrfs_ioctl_wait_sync(struct btrfs_root *root,
					   void __user *argp)
{
	u64 transid;

	if (argp) {
		if (copy_from_user(&transid, argp, sizeof(transid)))
			return -EFAULT;
	} else {
		transid = 0;  /* current trans */
	}
	return btrfs_wait_for_commit(root, transid);
}

static long btrfs_ioctl_scrub(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_scrub_args *sa;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	if (!(sa->flags & BTRFS_SCRUB_READONLY)) {
		ret = mnt_want_write_file(file);
		if (ret)
			goto out;
	}

	ret = btrfs_scrub_dev(root->fs_info, sa->devid, sa->start, sa->end,
			      &sa->progress, sa->flags & BTRFS_SCRUB_READONLY,
			      0);

	if (copy_to_user(arg, sa, sizeof(*sa)))
		ret = -EFAULT;

	if (!(sa->flags & BTRFS_SCRUB_READONLY))
		mnt_drop_write_file(file);
out:
	kfree(sa);
	return ret;
}

static long btrfs_ioctl_scrub_cancel(struct btrfs_root *root, void __user *arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return btrfs_scrub_cancel(root->fs_info);
}

static long btrfs_ioctl_scrub_progress(struct btrfs_root *root,
				       void __user *arg)
{
	struct btrfs_ioctl_scrub_args *sa;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	ret = btrfs_scrub_progress(root, sa->devid, &sa->progress);

	if (copy_to_user(arg, sa, sizeof(*sa)))
		ret = -EFAULT;

	kfree(sa);
	return ret;
}

static long btrfs_ioctl_get_dev_stats(struct btrfs_root *root,
				      void __user *arg)
{
	struct btrfs_ioctl_get_dev_stats *sa;
	int ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa))
		return PTR_ERR(sa);

	if ((sa->flags & BTRFS_DEV_STATS_RESET) && !capable(CAP_SYS_ADMIN)) {
		kfree(sa);
		return -EPERM;
	}

	ret = btrfs_get_dev_stats(root, sa);

	if (copy_to_user(arg, sa, sizeof(*sa)))
		ret = -EFAULT;

	kfree(sa);
	return ret;
}

static long btrfs_ioctl_dev_replace(struct btrfs_root *root, void __user *arg)
{
	struct btrfs_ioctl_dev_replace_args *p;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	p = memdup_user(arg, sizeof(*p));
	if (IS_ERR(p))
		return PTR_ERR(p);

	switch (p->cmd) {
	case BTRFS_IOCTL_DEV_REPLACE_CMD_START:
		if (root->fs_info->sb->s_flags & MS_RDONLY) {
			ret = -EROFS;
			goto out;
		}
		if (atomic_xchg(
			&root->fs_info->mutually_exclusive_operation_running,
			1)) {
			ret = BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
		} else {
			ret = btrfs_dev_replace_start(root, p);
			atomic_set(
			 &root->fs_info->mutually_exclusive_operation_running,
			 0);
		}
		break;
	case BTRFS_IOCTL_DEV_REPLACE_CMD_STATUS:
		btrfs_dev_replace_status(root->fs_info, p);
		ret = 0;
		break;
	case BTRFS_IOCTL_DEV_REPLACE_CMD_CANCEL:
		ret = btrfs_dev_replace_cancel(root->fs_info, p);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (copy_to_user(arg, p, sizeof(*p)))
		ret = -EFAULT;
out:
	kfree(p);
	return ret;
}

static long btrfs_ioctl_ino_to_path(struct btrfs_root *root, void __user *arg)
{
	int ret = 0;
	int i;
	u64 rel_ptr;
	int size;
	struct btrfs_ioctl_ino_path_args *ipa = NULL;
	struct inode_fs_paths *ipath = NULL;
	struct btrfs_path *path;

	if (!capable(CAP_DAC_READ_SEARCH))
		return -EPERM;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	ipa = memdup_user(arg, sizeof(*ipa));
	if (IS_ERR(ipa)) {
		ret = PTR_ERR(ipa);
		ipa = NULL;
		goto out;
	}

	size = min_t(u32, ipa->size, 4096);
	ipath = init_ipath(size, root, path);
	if (IS_ERR(ipath)) {
		ret = PTR_ERR(ipath);
		ipath = NULL;
		goto out;
	}

	ret = paths_from_inode(ipa->inum, ipath);
	if (ret < 0)
		goto out;

	for (i = 0; i < ipath->fspath->elem_cnt; ++i) {
		rel_ptr = ipath->fspath->val[i] -
			  (u64)(unsigned long)ipath->fspath->val;
		ipath->fspath->val[i] = rel_ptr;
	}

	ret = copy_to_user((void *)(unsigned long)ipa->fspath,
			   (void *)(unsigned long)ipath->fspath, size);
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

out:
	btrfs_free_path(path);
	free_ipath(ipath);
	kfree(ipa);

	return ret;
}

#ifdef MY_ABC_HERE
/*
 * Similar to BTRFS_IOC_INO_PATHS, but we only output one path, regardless of how many
 * links this inode should have, since the vfs caller should not know too much about
 * how to parse struct btrfs_ioctl_ino_path_args and struct inode_fs_paths.
 */
int btrfs_vfs_ino_to_path(struct inode *inode, u64 inum, char *outpath, int len)
{
	int ret = 0;
	struct inode_fs_paths *ipath = NULL;
	struct btrfs_path *path;
	struct btrfs_root *root;

	if (len < PATH_MAX)
		return -EINVAL;

	if (inode->i_sb->s_magic == BTRFS_SUPER_MAGIC)
		root = BTRFS_I(inode)->root;
	else
		return -EINVAL;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	ipath = init_ipath(len + sizeof(struct btrfs_data_container) + sizeof(u64), root, path);
	if (IS_ERR(ipath)) {
		ret = PTR_ERR(ipath);
		ipath = NULL;
		goto out;
	}

	ret = paths_from_inode(inum, ipath);
	if (ret < 0)
		goto out;

	if (ipath->fspath->elem_cnt > 0)
		strncpy(outpath, (char *)(ipath->fspath->val[0]), len);
	else
		ret = -ENOENT;

out:
	free_ipath(ipath);
	btrfs_free_path(path);

	return ret;
}
EXPORT_SYMBOL(btrfs_vfs_ino_to_path);
#endif /* MY_ABC_HERE */

static int build_ino_list(u64 inum, u64 offset, u64 root, void *ctx)
{
	struct btrfs_data_container *inodes = ctx;
	const size_t c = 3 * sizeof(u64);

	if (inodes->bytes_left >= c) {
		inodes->bytes_left -= c;
		inodes->val[inodes->elem_cnt] = inum;
		inodes->val[inodes->elem_cnt + 1] = offset;
		inodes->val[inodes->elem_cnt + 2] = root;
		inodes->elem_cnt += 3;
	} else {
		inodes->bytes_missing += c - inodes->bytes_left;
		inodes->bytes_left = 0;
		inodes->elem_missed += 3;
	}

	return 0;
}

static long btrfs_ioctl_logical_to_ino(struct btrfs_root *root,
					void __user *arg)
{
	int ret = 0;
	int size;
	struct btrfs_ioctl_logical_ino_args *loi;
	struct btrfs_data_container *inodes = NULL;
	struct btrfs_path *path = NULL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	loi = memdup_user(arg, sizeof(*loi));
	if (IS_ERR(loi)) {
		ret = PTR_ERR(loi);
		loi = NULL;
		goto out;
	}

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	size = min_t(u32, loi->size, SZ_64K);
	inodes = init_data_container(size);
	if (IS_ERR(inodes)) {
		ret = PTR_ERR(inodes);
		inodes = NULL;
		goto out;
	}

	ret = iterate_inodes_from_logical(loi->logical, root->fs_info, path,
					  build_ino_list, inodes);
	if (ret == -EINVAL)
		ret = -ENOENT;
	if (ret < 0)
		goto out;

	ret = copy_to_user((void *)(unsigned long)loi->inodes,
			   (void *)(unsigned long)inodes, size);
	if (ret)
		ret = -EFAULT;

out:
	btrfs_free_path(path);
	vfree(inodes);
	kfree(loi);

	return ret;
}

void update_ioctl_balance_args(struct btrfs_fs_info *fs_info, int lock,
			       struct btrfs_ioctl_balance_args *bargs)
{
	struct btrfs_balance_control *bctl = fs_info->balance_ctl;

	bargs->flags = bctl->flags;

	if (atomic_read(&fs_info->balance_running))
		bargs->state |= BTRFS_BALANCE_STATE_RUNNING;
	if (atomic_read(&fs_info->balance_pause_req))
		bargs->state |= BTRFS_BALANCE_STATE_PAUSE_REQ;
	if (atomic_read(&fs_info->balance_cancel_req))
		bargs->state |= BTRFS_BALANCE_STATE_CANCEL_REQ;

	memcpy(&bargs->data, &bctl->data, sizeof(bargs->data));
	memcpy(&bargs->meta, &bctl->meta, sizeof(bargs->meta));
	memcpy(&bargs->sys, &bctl->sys, sizeof(bargs->sys));

	if (lock) {
		spin_lock(&fs_info->balance_lock);
		memcpy(&bargs->stat, &bctl->stat, sizeof(bargs->stat));
		spin_unlock(&fs_info->balance_lock);
	} else {
		memcpy(&bargs->stat, &bctl->stat, sizeof(bargs->stat));
	}
}

static long btrfs_ioctl_balance(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_ioctl_balance_args *bargs;
	struct btrfs_balance_control *bctl;
	bool need_unlock; /* for mut. excl. ops lock */
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

again:
	if (!atomic_xchg(&fs_info->mutually_exclusive_operation_running, 1)) {
		mutex_lock(&fs_info->volume_mutex);
		mutex_lock(&fs_info->balance_mutex);
		need_unlock = true;
		goto locked;
	}

	/*
	 * mut. excl. ops lock is locked.  Three possibilities:
	 *   (1) some other op is running
	 *   (2) balance is running
	 *   (3) balance is paused -- special case (think resume)
	 */
	mutex_lock(&fs_info->balance_mutex);
	if (fs_info->balance_ctl) {
		/* this is either (2) or (3) */
		if (!atomic_read(&fs_info->balance_running)) {
			mutex_unlock(&fs_info->balance_mutex);
			if (!mutex_trylock(&fs_info->volume_mutex))
				goto again;
			mutex_lock(&fs_info->balance_mutex);

			if (fs_info->balance_ctl &&
			    !atomic_read(&fs_info->balance_running)) {
				/* this is (3) */
				need_unlock = false;
				goto locked;
			}

			mutex_unlock(&fs_info->balance_mutex);
			mutex_unlock(&fs_info->volume_mutex);
			goto again;
		} else {
			/* this is (2) */
			mutex_unlock(&fs_info->balance_mutex);
			ret = -EINPROGRESS;
			goto out;
		}
	} else {
		/* this is (1) */
		mutex_unlock(&fs_info->balance_mutex);
		ret = BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
		goto out;
	}

locked:
	BUG_ON(!atomic_read(&fs_info->mutually_exclusive_operation_running));

	if (arg) {
		bargs = memdup_user(arg, sizeof(*bargs));
		if (IS_ERR(bargs)) {
			ret = PTR_ERR(bargs);
			goto out_unlock;
		}

		if (bargs->flags & BTRFS_BALANCE_RESUME) {
			if (!fs_info->balance_ctl) {
				ret = -ENOTCONN;
				goto out_bargs;
			}

			bctl = fs_info->balance_ctl;
			spin_lock(&fs_info->balance_lock);
			bctl->flags |= BTRFS_BALANCE_RESUME;
			spin_unlock(&fs_info->balance_lock);

			goto do_balance;
		}
	} else {
		bargs = NULL;
	}

	if (fs_info->balance_ctl) {
		ret = -EINPROGRESS;
		goto out_bargs;
	}

	bctl = kzalloc(sizeof(*bctl), GFP_KERNEL);
	if (!bctl) {
		ret = -ENOMEM;
		goto out_bargs;
	}

	bctl->fs_info = fs_info;
	if (arg) {
		memcpy(&bctl->data, &bargs->data, sizeof(bctl->data));
		memcpy(&bctl->meta, &bargs->meta, sizeof(bctl->meta));
		memcpy(&bctl->sys, &bargs->sys, sizeof(bctl->sys));

		bctl->flags = bargs->flags;
	} else {
		/* balance everything - no filters */
		bctl->flags |= BTRFS_BALANCE_TYPE_MASK;
	}

	if (bctl->flags & ~(BTRFS_BALANCE_ARGS_MASK | BTRFS_BALANCE_TYPE_MASK)) {
		ret = -EINVAL;
		goto out_bctl;
	}

do_balance:
	/*
	 * Ownership of bctl and mutually_exclusive_operation_running
	 * goes to to btrfs_balance.  bctl is freed in __cancel_balance,
	 * or, if restriper was paused all the way until unmount, in
	 * free_fs_info.  mutually_exclusive_operation_running is
	 * cleared in __cancel_balance.
	 */
	need_unlock = false;

	ret = btrfs_balance(bctl, bargs);
	bctl = NULL;

	if (arg) {
		if (copy_to_user(arg, bargs, sizeof(*bargs)))
			ret = -EFAULT;
	}

out_bctl:
	kfree(bctl);
out_bargs:
	kfree(bargs);
out_unlock:
	mutex_unlock(&fs_info->balance_mutex);
	mutex_unlock(&fs_info->volume_mutex);
	if (need_unlock)
		atomic_set(&fs_info->mutually_exclusive_operation_running, 0);
out:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_balance_ctl(struct btrfs_root *root, int cmd)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (cmd) {
	case BTRFS_BALANCE_CTL_PAUSE:
		return btrfs_pause_balance(root->fs_info);
	case BTRFS_BALANCE_CTL_CANCEL:
		return btrfs_cancel_balance(root->fs_info);
	}

	return -EINVAL;
}

static long btrfs_ioctl_balance_progress(struct btrfs_root *root,
					 void __user *arg)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_ioctl_balance_args *bargs;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&fs_info->balance_mutex);
	if (!fs_info->balance_ctl) {
		ret = -ENOTCONN;
		goto out;
	}

	bargs = kzalloc(sizeof(*bargs), GFP_KERNEL);
	if (!bargs) {
		ret = -ENOMEM;
		goto out;
	}

	update_ioctl_balance_args(fs_info, 1, bargs);

	if (copy_to_user(arg, bargs, sizeof(*bargs)))
		ret = -EFAULT;

	kfree(bargs);
out:
	mutex_unlock(&fs_info->balance_mutex);
	return ret;
}

static long btrfs_ioctl_quota_ctl(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_quota_ctl_args *sa;
	struct btrfs_trans_handle *trans = NULL;
	int ret;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	down_write(&root->fs_info->subvol_sem);
	trans = btrfs_start_transaction(root->fs_info->tree_root, 2);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	switch (sa->cmd) {
	case BTRFS_QUOTA_CTL_ENABLE:
		ret = btrfs_quota_enable(trans, root->fs_info);
		break;
	case BTRFS_QUOTA_CTL_DISABLE:
		ret = btrfs_quota_disable(trans, root->fs_info);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	err = btrfs_commit_transaction(trans, root->fs_info->tree_root);
	if (err && !ret)
		ret = err;
out:
	kfree(sa);
	up_write(&root->fs_info->subvol_sem);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_qgroup_assign(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_qgroup_assign_args *sa;
	struct btrfs_trans_handle *trans;
	int ret;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	/* FIXME: check if the IDs really exist */
	if (sa->assign) {
		ret = btrfs_add_qgroup_relation(trans, root->fs_info,
						sa->src, sa->dst);
	} else {
		ret = btrfs_del_qgroup_relation(trans, root->fs_info,
						sa->src, sa->dst);
	}

	/* update qgroup status and info */
	err = btrfs_run_qgroups(trans, root->fs_info);
	if (err < 0)
		btrfs_handle_fs_error(root->fs_info, err,
			    "failed to update qgroup status and info");
	err = btrfs_end_transaction(trans, root);
	if (err && !ret)
		ret = err;

out:
	kfree(sa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_qgroup_create(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_qgroup_create_args *sa;
	struct btrfs_trans_handle *trans;
	int ret;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	if (!sa->qgroupid) {
		ret = -EINVAL;
		goto out;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	/* FIXME: check if the IDs really exist */
	if (sa->create) {
		ret = btrfs_create_qgroup(trans, root->fs_info, sa->qgroupid);
	} else {
		ret = btrfs_remove_qgroup(trans, root->fs_info, sa->qgroupid);
	}

	err = btrfs_end_transaction(trans, root);
	if (err && !ret)
		ret = err;

out:
	kfree(sa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_qgroup_limit(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_qgroup_limit_args *sa;
	struct btrfs_trans_handle *trans;
	int ret;
	int err;
	u64 qgroupid;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		goto drop_write;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	qgroupid = sa->qgroupid;
	if (!qgroupid) {
		/* take the current subvol as qgroup */
		qgroupid = root->root_key.objectid;
	}

	/* FIXME: check if the IDs really exist */
	ret = btrfs_limit_qgroup(trans, root->fs_info, qgroupid, &sa->lim);

	err = btrfs_end_transaction(trans, root);
	if (err && !ret)
		ret = err;

out:
	kfree(sa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

#ifdef MY_ABC_HERE
static long btrfs_ioctl_qgroup_query(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_qgroup_query_args *qqa;
	int ret = 0;

	qqa = kzalloc(sizeof(*qqa), GFP_NOFS);
	if (!qqa)
		return -ENOMEM;

	// use subvol id as qgroup id
	btrfs_qgroup_query(root->fs_info, root->root_key.objectid, qqa);

	if (copy_to_user(arg, qqa, sizeof(*qqa)))
		ret = -EFAULT;

	kfree(qqa);
	return ret;
}
#endif /* MY_ABC_HERE */

static long btrfs_ioctl_quota_rescan(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_quota_rescan_args *qsa;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	qsa = memdup_user(arg, sizeof(*qsa));
	if (IS_ERR(qsa)) {
		ret = PTR_ERR(qsa);
		goto drop_write;
	}

	if (qsa->flags) {
		ret = -EINVAL;
		goto out;
	}

	ret = btrfs_qgroup_rescan(root->fs_info);

out:
	kfree(qsa);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_quota_rescan_status(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_quota_rescan_args *qsa;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	qsa = kzalloc(sizeof(*qsa), GFP_KERNEL);
	if (!qsa)
		return -ENOMEM;

	if (root->fs_info->qgroup_flags & BTRFS_QGROUP_STATUS_FLAG_RESCAN) {
		qsa->flags = 1;
		qsa->progress = root->fs_info->qgroup_rescan_progress.objectid;
	}

	if (copy_to_user(arg, qsa, sizeof(*qsa)))
		ret = -EFAULT;

	kfree(qsa);
	return ret;
}

static long btrfs_ioctl_quota_rescan_wait(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return btrfs_qgroup_wait_for_completion(root->fs_info, true);
}

#ifdef MY_ABC_HERE
static long btrfs_ioctl_usrquota_ctl(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_usrquota_ctl_args *ctl_args;
	struct btrfs_trans_handle *trans = NULL;
	int ret;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	ctl_args = memdup_user(arg, sizeof(*ctl_args));
	if (IS_ERR(ctl_args)) {
		ret = PTR_ERR(ctl_args);
		goto drop_write;
	}

	if (ctl_args->cmd == BTRFS_USRQUOTA_CTL_DUMPTREE) {
		ret = btrfs_usrquota_dumptree(root->fs_info);
		goto out;
	}

	trans = btrfs_start_transaction(root->fs_info->tree_root, 2);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	switch (ctl_args->cmd) {
	case BTRFS_USRQUOTA_CTL_ENABLE:
		ret = btrfs_usrquota_enable(trans, root->fs_info);
		break;
	case BTRFS_USRQUOTA_CTL_DISABLE:
		ret = btrfs_usrquota_disable(trans, root->fs_info);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	err = btrfs_commit_transaction(trans, root->fs_info->tree_root);
	if (err && !ret)
		ret = err;
out:
	kfree(ctl_args);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_usrquota_limit(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_usrquota_limit_args *limit_args;
	struct btrfs_trans_handle *trans;
	int ret;
	int err;
	u64 rootid;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (btrfs_root_readonly(root))
		return -EROFS;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	limit_args = memdup_user(arg, sizeof(*limit_args));
	if (IS_ERR(limit_args)) {
		ret = PTR_ERR(limit_args);
		goto drop_write;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	rootid = root->root_key.objectid;
	ret = btrfs_usrquota_limit(trans, root->fs_info, rootid,
	                           limit_args->uid, limit_args->rfer_soft,
	                           limit_args->rfer_hard);

	err = btrfs_end_transaction(trans, root);
	if (err && !ret)
		ret = err;

out:
	kfree(limit_args);
drop_write:
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_usrquota_rescan(struct file *file)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	ret = btrfs_usrquota_rescan(root->fs_info, root->root_key.objectid);
	mnt_drop_write_file(file);
	return ret;
}

static long btrfs_ioctl_usrquota_rescan_status(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_usrquota_rescan_args *rescan_args;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	rescan_args = kzalloc(sizeof(*rescan_args), GFP_NOFS);
	if (!rescan_args)
		return -ENOMEM;

	if (root->fs_info->usrquota_flags & BTRFS_USRQUOTA_STATUS_FLAG_RESCAN) {
		rescan_args->flags = 1;
		rescan_args->rootid = root->fs_info->usrquota_rescan_rootid;
		rescan_args->objectid = root->fs_info->usrquota_rescan_objectid;
	}

	if (copy_to_user(arg, rescan_args, sizeof(*rescan_args)))
		ret = -EFAULT;

	kfree(rescan_args);
	return ret;
}

static inline long btrfs_ioctl_usrquota_rescan_wait(struct file *file)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;

	return btrfs_usrquota_wait_for_completion(root->fs_info);
}

static long btrfs_ioctl_usrquota_query(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_ioctl_usrquota_query_args *uqa;
	int ret = 0;

	uqa = kzalloc(sizeof(*uqa), GFP_NOFS);
	if (!uqa)
		return -ENOMEM;

	if (copy_from_user(&uqa->uid, arg, sizeof(__u64))) {
		ret = -EFAULT;
		goto out;
	}
	btrfs_usrquota_query(root->fs_info, root->root_key.objectid, uqa);

	if (copy_to_user(arg, uqa, sizeof(*uqa)))
		ret = -EFAULT;
out:
	kfree(uqa);
	return ret;
}

static long btrfs_ioctl_usrquota_clean(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_trans_handle *trans;
	int ret, err;
	u64 uid;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	if (copy_from_user(&uid, arg, sizeof(uid))) {
		ret = -EFAULT;
		goto out;
	}
	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	ret = btrfs_usrquota_clean(trans, root->fs_info, uid);
	err = btrfs_end_transaction(trans, root);
	if (err && !ret)
		ret = err;
out:
	mnt_drop_write_file(file);
	return ret;
}
#endif /* MY_ABC_HERE */

static long _btrfs_ioctl_set_received_subvol(struct file *file,
					    struct btrfs_ioctl_received_subvol_args *sa)
{
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_root_item *root_item = &root->root_item;
	struct btrfs_trans_handle *trans;
	struct timespec ct = current_fs_time(inode->i_sb);
	int ret = 0;
	int received_uuid_changed;

	if (!inode_owner_or_capable(inode))
		return -EPERM;

	ret = mnt_want_write_file(file);
	if (ret < 0)
		return ret;

	down_write(&root->fs_info->subvol_sem);

	if (btrfs_ino(inode) != BTRFS_FIRST_FREE_OBJECTID) {
		ret = -EINVAL;
		goto out;
	}

	if (btrfs_root_readonly(root)) {
		ret = -EROFS;
		goto out;
	}

	/*
	 * 1 - root item
	 * 2 - uuid items (received uuid + subvol uuid)
	 */
	trans = btrfs_start_transaction(root, 3);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		trans = NULL;
		goto out;
	}

	sa->rtransid = trans->transid;
	sa->rtime.sec = ct.tv_sec;
	sa->rtime.nsec = ct.tv_nsec;

	received_uuid_changed = memcmp(root_item->received_uuid, sa->uuid,
				       BTRFS_UUID_SIZE);
	if (received_uuid_changed &&
	    !btrfs_is_empty_uuid(root_item->received_uuid))
		btrfs_uuid_tree_rem(trans, root->fs_info->uuid_root,
				    root_item->received_uuid,
				    BTRFS_UUID_KEY_RECEIVED_SUBVOL,
				    root->root_key.objectid);
	memcpy(root_item->received_uuid, sa->uuid, BTRFS_UUID_SIZE);
	btrfs_set_root_stransid(root_item, sa->stransid);
	btrfs_set_root_rtransid(root_item, sa->rtransid);
	btrfs_set_stack_timespec_sec(&root_item->stime, sa->stime.sec);
	btrfs_set_stack_timespec_nsec(&root_item->stime, sa->stime.nsec);
	btrfs_set_stack_timespec_sec(&root_item->rtime, sa->rtime.sec);
	btrfs_set_stack_timespec_nsec(&root_item->rtime, sa->rtime.nsec);
#ifdef MY_ABC_HERE
	btrfs_set_stack_timespec_sec(&root_item->otime, sa->otime.sec);
	btrfs_set_stack_timespec_nsec(&root_item->otime, sa->otime.nsec);
#endif /* MY_ABC_HERE */

	ret = btrfs_update_root(trans, root->fs_info->tree_root,
				&root->root_key, &root->root_item);
	if (ret < 0) {
		btrfs_end_transaction(trans, root);
		goto out;
	}
	if (received_uuid_changed && !btrfs_is_empty_uuid(sa->uuid)) {
		ret = btrfs_uuid_tree_add(trans, root->fs_info->uuid_root,
					  sa->uuid,
					  BTRFS_UUID_KEY_RECEIVED_SUBVOL,
					  root->root_key.objectid);
		if (ret < 0 && ret != -EEXIST) {
			btrfs_abort_transaction(trans, root, ret);
			goto out;
		}
	}
	ret = btrfs_commit_transaction(trans, root);
	if (ret < 0) {
		btrfs_abort_transaction(trans, root, ret);
		goto out;
	}

out:
	up_write(&root->fs_info->subvol_sem);
	mnt_drop_write_file(file);
	return ret;
}

#ifdef CONFIG_64BIT
static long btrfs_ioctl_set_received_subvol_32(struct file *file,
						void __user *arg)
{
	struct btrfs_ioctl_received_subvol_args_32 *args32 = NULL;
	struct btrfs_ioctl_received_subvol_args *args64 = NULL;
	int ret = 0;

	args32 = memdup_user(arg, sizeof(*args32));
	if (IS_ERR(args32)) {
		ret = PTR_ERR(args32);
		args32 = NULL;
		goto out;
	}

	args64 = kmalloc(sizeof(*args64), GFP_KERNEL);
	if (!args64) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(args64->uuid, args32->uuid, BTRFS_UUID_SIZE);
	args64->stransid = args32->stransid;
	args64->rtransid = args32->rtransid;
	args64->stime.sec = args32->stime.sec;
	args64->stime.nsec = args32->stime.nsec;
	args64->rtime.sec = args32->rtime.sec;
	args64->rtime.nsec = args32->rtime.nsec;
#ifdef MY_ABC_HERE
	args64->otime.sec = args32->otime.sec;
	args64->otime.nsec = args32->otime.nsec;
#endif /* MY_ABC_HERE */
	args64->flags = args32->flags;

	ret = _btrfs_ioctl_set_received_subvol(file, args64);
	if (ret)
		goto out;

	memcpy(args32->uuid, args64->uuid, BTRFS_UUID_SIZE);
	args32->stransid = args64->stransid;
	args32->rtransid = args64->rtransid;
	args32->stime.sec = args64->stime.sec;
	args32->stime.nsec = args64->stime.nsec;
	args32->rtime.sec = args64->rtime.sec;
	args32->rtime.nsec = args64->rtime.nsec;
#ifdef MY_ABC_HERE
	args32->otime.sec = args64->otime.sec;
	args32->otime.nsec = args64->otime.nsec;
#endif /* MY_ABC_HERE */
	args32->flags = args64->flags;

	ret = copy_to_user(arg, args32, sizeof(*args32));
	if (ret)
		ret = -EFAULT;

out:
	kfree(args32);
	kfree(args64);
	return ret;
}
#endif

static long btrfs_ioctl_set_received_subvol(struct file *file,
					    void __user *arg)
{
	struct btrfs_ioctl_received_subvol_args *sa = NULL;
	int ret = 0;

	sa = memdup_user(arg, sizeof(*sa));
	if (IS_ERR(sa)) {
		ret = PTR_ERR(sa);
		sa = NULL;
		goto out;
	}

	ret = _btrfs_ioctl_set_received_subvol(file, sa);

	if (ret)
		goto out;

	ret = copy_to_user(arg, sa, sizeof(*sa));
	if (ret)
		ret = -EFAULT;

out:
	kfree(sa);
	return ret;
}

static int btrfs_ioctl_get_fslabel(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	size_t len;
	int ret;
	char label[BTRFS_LABEL_SIZE];

	spin_lock(&root->fs_info->super_lock);
	memcpy(label, root->fs_info->super_copy->label, BTRFS_LABEL_SIZE);
	spin_unlock(&root->fs_info->super_lock);

	len = strnlen(label, BTRFS_LABEL_SIZE);

	if (len == BTRFS_LABEL_SIZE) {
		btrfs_warn(root->fs_info,
			"label is too long, return the first %zu bytes", --len);
	}

	ret = copy_to_user(arg, label, len);

	return ret ? -EFAULT : 0;
}

static int btrfs_ioctl_set_fslabel(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_super_block *super_block = root->fs_info->super_copy;
	struct btrfs_trans_handle *trans;
	char label[BTRFS_LABEL_SIZE];
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(label, arg, sizeof(label)))
		return -EFAULT;

	if (strnlen(label, BTRFS_LABEL_SIZE) == BTRFS_LABEL_SIZE) {
		btrfs_err(root->fs_info, "unable to set label with more than %d bytes",
		       BTRFS_LABEL_SIZE - 1);
		return -EINVAL;
	}

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_unlock;
	}

	spin_lock(&root->fs_info->super_lock);
	strcpy(super_block->label, label);
	spin_unlock(&root->fs_info->super_lock);
	ret = btrfs_commit_transaction(trans, root);

out_unlock:
	mnt_drop_write_file(file);
	return ret;
}

#define INIT_FEATURE_FLAGS(suffix) \
	{ .compat_flags = BTRFS_FEATURE_COMPAT_##suffix, \
	  .compat_ro_flags = BTRFS_FEATURE_COMPAT_RO_##suffix, \
	  .incompat_flags = BTRFS_FEATURE_INCOMPAT_##suffix }

int btrfs_ioctl_get_supported_features(void __user *arg)
{
	static const struct btrfs_ioctl_feature_flags features[3] = {
		INIT_FEATURE_FLAGS(SUPP),
		INIT_FEATURE_FLAGS(SAFE_SET),
		INIT_FEATURE_FLAGS(SAFE_CLEAR)
	};

	if (copy_to_user(arg, &features, sizeof(features)))
		return -EFAULT;

	return 0;
}

static int btrfs_ioctl_get_features(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_super_block *super_block = root->fs_info->super_copy;
	struct btrfs_ioctl_feature_flags features;

	features.compat_flags = btrfs_super_compat_flags(super_block);
	features.compat_ro_flags = btrfs_super_compat_ro_flags(super_block);
	features.incompat_flags = btrfs_super_incompat_flags(super_block);

	if (copy_to_user(arg, &features, sizeof(features)))
		return -EFAULT;

	return 0;
}

static int check_feature_bits(struct btrfs_root *root,
			      enum btrfs_feature_set set,
			      u64 change_mask, u64 flags, u64 supported_flags,
			      u64 safe_set, u64 safe_clear)
{
	const char *type = btrfs_feature_set_names[set];
	char *names;
	u64 disallowed, unsupported;
	u64 set_mask = flags & change_mask;
	u64 clear_mask = ~flags & change_mask;

	unsupported = set_mask & ~supported_flags;
	if (unsupported) {
		names = btrfs_printable_features(set, unsupported);
		if (names) {
			btrfs_warn(root->fs_info,
			   "this kernel does not support the %s feature bit%s",
			   names, strchr(names, ',') ? "s" : "");
			kfree(names);
		} else
			btrfs_warn(root->fs_info,
			   "this kernel does not support %s bits 0x%llx",
			   type, unsupported);
		return -EOPNOTSUPP;
	}

	disallowed = set_mask & ~safe_set;
	if (disallowed) {
		names = btrfs_printable_features(set, disallowed);
		if (names) {
			btrfs_warn(root->fs_info,
			   "can't set the %s feature bit%s while mounted",
			   names, strchr(names, ',') ? "s" : "");
			kfree(names);
		} else
			btrfs_warn(root->fs_info,
			   "can't set %s bits 0x%llx while mounted",
			   type, disallowed);
		return -EPERM;
	}

	disallowed = clear_mask & ~safe_clear;
	if (disallowed) {
		names = btrfs_printable_features(set, disallowed);
		if (names) {
			btrfs_warn(root->fs_info,
			   "can't clear the %s feature bit%s while mounted",
			   names, strchr(names, ',') ? "s" : "");
			kfree(names);
		} else
			btrfs_warn(root->fs_info,
			   "can't clear %s bits 0x%llx while mounted",
			   type, disallowed);
		return -EPERM;
	}

	return 0;
}

#define check_feature(root, change_mask, flags, mask_base)	\
check_feature_bits(root, FEAT_##mask_base, change_mask, flags,	\
		   BTRFS_FEATURE_ ## mask_base ## _SUPP,	\
		   BTRFS_FEATURE_ ## mask_base ## _SAFE_SET,	\
		   BTRFS_FEATURE_ ## mask_base ## _SAFE_CLEAR)

static int btrfs_ioctl_set_features(struct file *file, void __user *arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_super_block *super_block = root->fs_info->super_copy;
	struct btrfs_ioctl_feature_flags flags[2];
	struct btrfs_trans_handle *trans;
	u64 newflags;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(flags, arg, sizeof(flags)))
		return -EFAULT;

	/* Nothing to do */
	if (!flags[0].compat_flags && !flags[0].compat_ro_flags &&
	    !flags[0].incompat_flags)
		return 0;

	ret = check_feature(root, flags[0].compat_flags,
			    flags[1].compat_flags, COMPAT);
	if (ret)
		return ret;

	ret = check_feature(root, flags[0].compat_ro_flags,
			    flags[1].compat_ro_flags, COMPAT_RO);
	if (ret)
		return ret;

	ret = check_feature(root, flags[0].incompat_flags,
			    flags[1].incompat_flags, INCOMPAT);
	if (ret)
		return ret;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out_drop_write;
	}

	spin_lock(&root->fs_info->super_lock);
	newflags = btrfs_super_compat_flags(super_block);
	newflags |= flags[0].compat_flags & flags[1].compat_flags;
	newflags &= ~(flags[0].compat_flags & ~flags[1].compat_flags);
	btrfs_set_super_compat_flags(super_block, newflags);

	newflags = btrfs_super_compat_ro_flags(super_block);
	newflags |= flags[0].compat_ro_flags & flags[1].compat_ro_flags;
	newflags &= ~(flags[0].compat_ro_flags & ~flags[1].compat_ro_flags);
	btrfs_set_super_compat_ro_flags(super_block, newflags);

	newflags = btrfs_super_incompat_flags(super_block);
	newflags |= flags[0].incompat_flags & flags[1].incompat_flags;
	newflags &= ~(flags[0].incompat_flags & ~flags[1].incompat_flags);
	btrfs_set_super_incompat_flags(super_block, newflags);
	spin_unlock(&root->fs_info->super_lock);

	ret = btrfs_commit_transaction(trans, root);
out_drop_write:
	mnt_drop_write_file(file);

	return ret;
}

#ifdef MY_ABC_HERE
static int btrfs_ioctl_cksumfailed_files_get(struct file *file, void __user *arg)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(file_inode(file))->root->fs_info;
	struct cksumfailed_file_rec rec;
	struct btrfs_ioctl_cksumfailed_files_args cksumfailed_files;
	unsigned int len;

	len = kfifo_out(&fs_info->cksumfailed_files, &rec, sizeof(struct cksumfailed_file_rec));
	if (len == sizeof(struct cksumfailed_file_rec)) {
		cksumfailed_files.sub_vol = rec.sub_vol;
		cksumfailed_files.ino = rec.ino;
	} else if (0 == len){
		return -ENOENT;
	} else {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cksumfailed_files, sizeof(struct btrfs_ioctl_cksumfailed_files_args))) {
		return -EFAULT;
	}

	return 0;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static long btrfs_ioctl_subvol_getinfo(struct file *file,
			struct btrfs_ioctl_subvol_info_args __user *arg)
{
	int ret = 0;
	struct inode *inode = file_inode(file);
	struct btrfs_root_item *root_item = &BTRFS_I(inode)->root->root_item;
	struct btrfs_root *root = BTRFS_I(inode)->root;

	ret = put_user(root->root_key.objectid, &arg->root_id);
	ret |= put_user(btrfs_root_flags(root_item), &arg->flags);
	ret |= put_user(btrfs_root_generation(root_item), &arg->gen);
	ret |= put_user(btrfs_root_otransid(root_item), &arg->ogen);
	ret |= copy_to_user(&arg->uuid, &root_item->uuid, BTRFS_UUID_SIZE);
	ret |= copy_to_user(&arg->puuid, &root_item->parent_uuid, BTRFS_UUID_SIZE);
	ret |= copy_to_user(&arg->ruuid, &root_item->received_uuid, BTRFS_UUID_SIZE);
	if (ret) {
		ret = -EFAULT;
	}
	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static long btrfs_ioctl_compr_ctl(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct btrfs_ioctl_compr_ctl_args compr_args;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_path *path = NULL;
	struct ulist *disko_ulist = NULL;
	struct extent_buffer *leaf;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key found_key;
	int ret = 0;
	int extent_type;
	u64 ino = btrfs_ino(inode);
	u64 disko;
	u64 len;
	u64 compressed_size = 0;
	u64 size = 0;

	if (S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (copy_from_user(&compr_args, arg, sizeof(compr_args)))
		return -EFAULT;

	if (compr_args.flags & BTRFS_COMPR_CTL_SET)
		return -EOPNOTSUPP;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	disko_ulist = ulist_alloc(GFP_NOFS);
	if (!disko_ulist) {
		ret = -ENOMEM;
		goto out_free;
	}

	mutex_lock(&inode->i_mutex);

	/*
	 * do any pending delalloc/csum calc on inode, one way or
	 * another, and lock file content
	 */
	btrfs_wait_ordered_range(inode, 0, (u64)-1);
	len = i_size_read(inode);
	lock_extent(&BTRFS_I(inode)->io_tree, 0, len);

	if (len > 20 * 1024 * 1024) // May be many file extent items, do readahead.
		path->reada = READA_FORWARD;

	ret = btrfs_lookup_file_extent(NULL, root, path, ino, 0, 0);
	if (ret < 0)
		goto out_unlock;
	leaf = path->nodes[0];

	while (1) {
		if (path->slots[0] >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				goto out_unlock;
			if (ret > 0)
				break;
			leaf = path->nodes[0];
		}

		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		if (found_key.objectid != ino ||
		    found_key.type != BTRFS_EXTENT_DATA_KEY)
			break;

		fi = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_file_extent_item);
		extent_type = btrfs_file_extent_type(leaf, fi);

		if (extent_type != BTRFS_FILE_EXTENT_INLINE) {
			disko = btrfs_file_extent_disk_bytenr(leaf, fi);
			btrfs_set_path_blocking(path);
			if (disko && ulist_add_lru_adjust(disko_ulist, disko, 0, GFP_NOFS)) {
				compressed_size += btrfs_file_extent_disk_num_bytes(leaf, fi);
				size += btrfs_file_extent_num_bytes(leaf, fi);
				if (disko_ulist->nnodes > ULIST_NODES_MAX)
					ulist_remove_first(disko_ulist);
			}
		} else {
			compressed_size += btrfs_file_extent_inline_item_len(leaf,
						btrfs_item_nr(path->slots[0]));
			size += btrfs_file_extent_inline_len(leaf, path->slots[0], fi);
		}
		path->slots[0]++;
	}
	ret = 0;

	compr_args.size = size;
	compr_args.compressed_size = compressed_size;
	if (BTRFS_I(inode)->force_compress == BTRFS_COMPRESS_ZLIB
		|| BTRFS_I(inode)->force_compress == BTRFS_COMPRESS_LZO)
		compr_args.flags |= BTRFS_COMPR_CTL_COMPR_FL;

	if (copy_to_user(arg, &compr_args, sizeof(compr_args)))
		ret = -EFAULT;

out_unlock:
	unlock_extent(&BTRFS_I(inode)->io_tree, 0, len);
	mutex_unlock(&inode->i_mutex);

out_free:
	btrfs_free_path(path);
	ulist_free(disko_ulist);

	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int btrfs_ioctl_snapshot_size_query(struct file *file, void __user *argp)
{
	struct btrfs_ioctl_snapshot_size_query_args snap_args;
	struct btrfs_ioctl_snapshot_size_id_size_map *user_id_maps;
	size_t id_maps_size;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&snap_args, argp, sizeof(snap_args)))
		return -EFAULT;

	if (!snap_args.snap_count || 0 > snap_args.fd)
		return -EINVAL;

	id_maps_size = sizeof(struct btrfs_ioctl_snapshot_size_id_size_map)*snap_args.snap_count;
	user_id_maps = snap_args.id_maps;

	if (!access_ok(VERIFY_READ, snap_args.id_maps, id_maps_size)) {
		ret = -EFAULT;
		goto out;
	}

	snap_args.id_maps = memdup_user(snap_args.id_maps, id_maps_size);
	if (IS_ERR(snap_args.id_maps))
		return PTR_ERR(snap_args.id_maps);

	ret = btrfs_snapshot_size_query(file, &snap_args, btrfs_find_shared_root);

	if (copy_to_user(argp + offsetof(struct btrfs_ioctl_snapshot_size_query_args,
	    calc_size), &snap_args.calc_size, sizeof(snap_args.calc_size))) {
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(argp + offsetof(struct btrfs_ioctl_snapshot_size_query_args,
	    processed_size), &snap_args.processed_size, sizeof(snap_args.processed_size))) {
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(user_id_maps, snap_args.id_maps, id_maps_size)) {
		ret = -EFAULT;
		goto out;
	}

	if (ret > 0)
		ret = 0;
out:
	kfree(snap_args.id_maps);
	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int btrfs_ioctl_syno_reserve_log_tree_bg(struct file *file,
			  struct btrfs_ioctl_log_tree_reserve_bg_args __user *argp)
{
	struct btrfs_ioctl_log_tree_reserve_bg_args rsv_args;
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_bio *multi = NULL;
	u64 rsv_start = 0;
	u64 rsv_size = 0;
	u64 length = 16384;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&rsv_args, argp, sizeof(rsv_args)))
		return -EFAULT;

	if ((rsv_args.flags & ~(BTRFS_LOG_TREE_BG_RSV_FLAGS)) ||
		!rsv_args.flags ||
		(rsv_args.flags & BTRFS_LOG_TREE_BG_RSV_FLAGS) == BTRFS_LOG_TREE_BG_RSV_FLAGS)
		return -EINVAL;

	mutex_lock(&fs_info->log_tree_rsv_alloc);
	if (rsv_args.flags & BTRFS_LOG_TREE_BG_RSV_REMOVE) {
		fs_info->log_tree_rsv_start = 0;
		fs_info->log_tree_rsv_size = 0;
		goto out;
	}
	if ((rsv_args.flags & BTRFS_LOG_TREE_BG_RSV_ADD) && fs_info->log_tree_rsv_start) {
		rsv_start = fs_info->log_tree_rsv_start;
		rsv_size = fs_info->log_tree_rsv_size;
		goto map_logical;
	}
	ret = btrfs_reserve_log_tree_bg(root, &rsv_start, &rsv_size);
	if (ret)
		goto out;
map_logical:
	ret = btrfs_map_block(fs_info, READ, rsv_start, &length, &multi, 1);
out:
	if (!ret && rsv_start) {
		if (put_user(rsv_start, &argp->start) ||
		    put_user(rsv_size, &argp->size) ||
		    put_user(multi->stripes[0].physical, &argp->map_start))
			ret = -EINVAL;
	}
	kfree(multi);
	mutex_unlock(&fs_info->log_tree_rsv_alloc);
	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int btrfs_ioctl_syno_punch_check(struct file *file,
			  struct btrfs_ioctl_syno_punch_check_args __user *argp)
{
	int ret = -1;
	struct btrfs_ioctl_syno_punch_check_args args;

	if (copy_from_user(&args, argp, sizeof(args))) {
		ret = -EFAULT;
		goto out;
	}

	ret = btrfs_fallocate_check_punch(file, args.offset, args.len, &args.extent_offset, &args.extent_len);
	if (ret < 0) {
		goto out;
	}

	if (copy_to_user(argp, &args, sizeof(args))) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;
out:
	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int btrfs_ioctl_free_space_analyze(struct file *file, struct btrfs_ioctl_free_space_analyze_args __user *argp)
{
	int ret = 0;
	struct inode *inode = file_inode(file);
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_ioctl_free_space_analyze_args args;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;

	if (!mutex_trylock(&fs_info->free_space_analyze_ioctl_lock)) {
		return -EBUSY;
	}
	if (args.flags & BTRFS_FREE_SPACE_ANALYZE_FLAG_FULL) {
		ret = btrfs_free_space_analyze_full(fs_info, &args);
	} else {
		ret = btrfs_free_space_analyze(fs_info, &args);
	}
	mutex_unlock(&fs_info->free_space_analyze_ioctl_lock);

	if (copy_to_user(argp, &args, sizeof(args))) {
		return -EFAULT;
	}

	return ret;
}
#endif /* MY_ABC_HERE */

long btrfs_ioctl(struct file *file, unsigned int
		cmd, unsigned long arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return btrfs_ioctl_getflags(file, argp);
	case FS_IOC_SETFLAGS:
		return btrfs_ioctl_setflags(file, argp);
	case FS_IOC_GETVERSION:
		return btrfs_ioctl_getversion(file, argp);
	case FITRIM:
		return btrfs_ioctl_fitrim(file, argp);
#ifdef MY_ABC_HERE
	case FIHINTUNUSED:
		return btrfs_ioctl_hint_unused(file, argp);
#endif /* MY_ABC_HERE */
	case BTRFS_IOC_SNAP_CREATE:
		return btrfs_ioctl_snap_create(file, argp, 0);
	case BTRFS_IOC_SNAP_CREATE_V2:
		return btrfs_ioctl_snap_create_v2(file, argp, 0);
	case BTRFS_IOC_SUBVOL_CREATE:
		return btrfs_ioctl_snap_create(file, argp, 1);
	case BTRFS_IOC_SUBVOL_CREATE_V2:
		return btrfs_ioctl_snap_create_v2(file, argp, 1);
	case BTRFS_IOC_SNAP_DESTROY:
		return btrfs_ioctl_snap_destroy(file, argp);
	case BTRFS_IOC_SUBVOL_GETFLAGS:
		return btrfs_ioctl_subvol_getflags(file, argp);
	case BTRFS_IOC_SUBVOL_SETFLAGS:
		return btrfs_ioctl_subvol_setflags(file, argp);
#ifdef MY_ABC_HERE
	case BTRFS_IOC_SUBVOL_GETINFO:
		return btrfs_ioctl_subvol_getinfo(file, argp);
#endif /* MY_ABC_HERE */
	case BTRFS_IOC_DEFAULT_SUBVOL:
		return btrfs_ioctl_default_subvol(file, argp);
	case BTRFS_IOC_DEFRAG:
		return btrfs_ioctl_defrag(file, NULL);
	case BTRFS_IOC_DEFRAG_RANGE:
		return btrfs_ioctl_defrag(file, argp);
	case BTRFS_IOC_RESIZE:
		return btrfs_ioctl_resize(file, argp);
	case BTRFS_IOC_ADD_DEV:
		return btrfs_ioctl_add_dev(root, argp);
	case BTRFS_IOC_RM_DEV:
		return btrfs_ioctl_rm_dev(file, argp);
	case BTRFS_IOC_FS_INFO:
		return btrfs_ioctl_fs_info(root, argp);
	case BTRFS_IOC_DEV_INFO:
		return btrfs_ioctl_dev_info(root, argp);
	case BTRFS_IOC_BALANCE:
		return btrfs_ioctl_balance(file, NULL);
	case BTRFS_IOC_TRANS_START:
		return btrfs_ioctl_trans_start(file);
	case BTRFS_IOC_TRANS_END:
		return btrfs_ioctl_trans_end(file);
	case BTRFS_IOC_TREE_SEARCH:
		return btrfs_ioctl_tree_search(file, argp);
	case BTRFS_IOC_TREE_SEARCH_V2:
		return btrfs_ioctl_tree_search_v2(file, argp);
	case BTRFS_IOC_INO_LOOKUP:
		return btrfs_ioctl_ino_lookup(file, argp);
	case BTRFS_IOC_INO_PATHS:
		return btrfs_ioctl_ino_to_path(root, argp);
	case BTRFS_IOC_LOGICAL_INO:
		return btrfs_ioctl_logical_to_ino(root, argp);
	case BTRFS_IOC_SPACE_INFO:
		return btrfs_ioctl_space_info(root, argp);
#ifdef MY_ABC_HERE
	case BTRFS_IOC_SYNC_SYNO:
#endif /* MY_ABC_HERE */
	case BTRFS_IOC_SYNC: {
		int ret;

#ifdef MY_ABC_HERE
		if (cmd == BTRFS_IOC_SYNC_SYNO) {
			goto skip_start_delalloc;
		}
#endif /* MY_ABC_HERE */
		ret = btrfs_start_delalloc_roots(root->fs_info, 0, -1);
		if (ret)
			return ret;
#ifdef MY_ABC_HERE
skip_start_delalloc:
#endif /* MY_ABC_HERE */
		ret = btrfs_sync_fs(file_inode(file)->i_sb, 1);
		/*
		 * The transaction thread may want to do more work,
		 * namely it pokes the cleaner kthread that will start
		 * processing uncleaned subvols.
		 */
		wake_up_process(root->fs_info->transaction_kthread);
		return ret;
	}
	case BTRFS_IOC_START_SYNC:
		return btrfs_ioctl_start_sync(root, argp);
	case BTRFS_IOC_WAIT_SYNC:
		return btrfs_ioctl_wait_sync(root, argp);
	case BTRFS_IOC_SCRUB:
		return btrfs_ioctl_scrub(file, argp);
	case BTRFS_IOC_SCRUB_CANCEL:
		return btrfs_ioctl_scrub_cancel(root, argp);
	case BTRFS_IOC_SCRUB_PROGRESS:
		return btrfs_ioctl_scrub_progress(root, argp);
	case BTRFS_IOC_BALANCE_V2:
		return btrfs_ioctl_balance(file, argp);
	case BTRFS_IOC_BALANCE_CTL:
		return btrfs_ioctl_balance_ctl(root, arg);
	case BTRFS_IOC_BALANCE_PROGRESS:
		return btrfs_ioctl_balance_progress(root, argp);
	case BTRFS_IOC_SET_RECEIVED_SUBVOL:
		return btrfs_ioctl_set_received_subvol(file, argp);
#ifdef CONFIG_64BIT
	case BTRFS_IOC_SET_RECEIVED_SUBVOL_32:
		return btrfs_ioctl_set_received_subvol_32(file, argp);
#endif
	case BTRFS_IOC_SEND:
		return btrfs_ioctl_send(file, argp);
	case BTRFS_IOC_GET_DEV_STATS:
		return btrfs_ioctl_get_dev_stats(root, argp);
	case BTRFS_IOC_QUOTA_CTL:
		return btrfs_ioctl_quota_ctl(file, argp);
	case BTRFS_IOC_QGROUP_ASSIGN:
		return btrfs_ioctl_qgroup_assign(file, argp);
	case BTRFS_IOC_QGROUP_CREATE:
		return btrfs_ioctl_qgroup_create(file, argp);
	case BTRFS_IOC_QGROUP_LIMIT:
		return btrfs_ioctl_qgroup_limit(file, argp);
	case BTRFS_IOC_QUOTA_RESCAN:
		return btrfs_ioctl_quota_rescan(file, argp);
	case BTRFS_IOC_QUOTA_RESCAN_STATUS:
		return btrfs_ioctl_quota_rescan_status(file, argp);
	case BTRFS_IOC_QUOTA_RESCAN_WAIT:
		return btrfs_ioctl_quota_rescan_wait(file, argp);
#ifdef MY_ABC_HERE
	case BTRFS_IOC_QGROUP_QUERY:
		return btrfs_ioctl_qgroup_query(file, argp);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	case BTRFS_IOC_USRQUOTA_CTL:
		return btrfs_ioctl_usrquota_ctl(file, argp);
	case BTRFS_IOC_USRQUOTA_LIMIT:
		return btrfs_ioctl_usrquota_limit(file, argp);
	case BTRFS_IOC_USRQUOTA_RESCAN:
		return btrfs_ioctl_usrquota_rescan(file);
	case BTRFS_IOC_USRQUOTA_RESCAN_STATUS:
		return btrfs_ioctl_usrquota_rescan_status(file, argp);
	case BTRFS_IOC_USRQUOTA_RESCAN_WAIT:
		return btrfs_ioctl_usrquota_rescan_wait(file);
	case BTRFS_IOC_USRQUOTA_QUERY:
		return btrfs_ioctl_usrquota_query(file, argp);
	case BTRFS_IOC_USRQUOTA_CLEAN:
		return btrfs_ioctl_usrquota_clean(file, argp);
#endif /* MY_ABC_HERE */
	case BTRFS_IOC_DEV_REPLACE:
		return btrfs_ioctl_dev_replace(root, argp);
	case BTRFS_IOC_GET_FSLABEL:
		return btrfs_ioctl_get_fslabel(file, argp);
	case BTRFS_IOC_SET_FSLABEL:
		return btrfs_ioctl_set_fslabel(file, argp);
	case BTRFS_IOC_FILE_EXTENT_SAME:
		return btrfs_ioctl_file_extent_same(file, argp);
	case BTRFS_IOC_GET_SUPPORTED_FEATURES:
		return btrfs_ioctl_get_supported_features(argp);
	case BTRFS_IOC_GET_FEATURES:
		return btrfs_ioctl_get_features(file, argp);
	case BTRFS_IOC_SET_FEATURES:
		return btrfs_ioctl_set_features(file, argp);
#ifdef MY_ABC_HERE
	case BTRFS_IOC_CKSUMFAILED_FILES_GET:
		return btrfs_ioctl_cksumfailed_files_get(file, argp);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	case BTRFS_IOC_COMPR_CTL:
		return btrfs_ioctl_compr_ctl(file, argp);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	case BTRFS_IOC_SNAPSHOT_SIZE_QUERY:
		return btrfs_ioctl_snapshot_size_query(file, argp);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	case BTRFS_IOC_SYNO_CLONE_RANGE_V2:
		return btrfs_ioctl_syno_clone_range_v2(file, argp);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	case BTRFS_IOC_SYNO_RESERVE_LOG_TREE_BLOCK_GROUP:
		return btrfs_ioctl_syno_reserve_log_tree_bg(file, argp);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	case BTRFS_IOC_SYNO_PUNCH_CHECK:
		return btrfs_ioctl_syno_punch_check(file, argp);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	case BTRFS_IOC_FREE_SPACE_ANALYZE:
		return btrfs_ioctl_free_space_analyze(file, argp);
#endif /* MY_ABC_HERE */
	}

	return -ENOTTY;
}

#ifdef CONFIG_COMPAT
long btrfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return btrfs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
