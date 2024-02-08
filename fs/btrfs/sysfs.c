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

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/kobject.h>
#include <linux/bug.h>
#include <linux/genhd.h>
#include <linux/debugfs.h>

#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "sysfs.h"
#include "volumes.h"
#ifdef MY_DEF_HERE
#include "qgroup.h"
#endif /* MY_DEF_HERE */

static inline struct btrfs_fs_info *to_fs_info(struct kobject *kobj);
static inline struct kobject *get_btrfs_kobj(struct kobject *kobj);

static u64 get_features(struct btrfs_fs_info *fs_info,
			enum btrfs_feature_set set)
{
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	if (set == FEAT_COMPAT)
		return btrfs_super_compat_flags(disk_super);
	else if (set == FEAT_COMPAT_RO)
		return btrfs_super_compat_ro_flags(disk_super);
	else
		return btrfs_super_incompat_flags(disk_super);
}

static void set_features(struct btrfs_fs_info *fs_info,
			 enum btrfs_feature_set set, u64 features)
{
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	if (set == FEAT_COMPAT)
		btrfs_set_super_compat_flags(disk_super, features);
	else if (set == FEAT_COMPAT_RO)
		btrfs_set_super_compat_ro_flags(disk_super, features);
	else
		btrfs_set_super_incompat_flags(disk_super, features);
}

static int can_modify_feature(struct btrfs_feature_attr *fa)
{
	int val = 0;
	u64 set, clear;
	switch (fa->feature_set) {
	case FEAT_COMPAT:
		set = BTRFS_FEATURE_COMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_SAFE_CLEAR;
		break;
	case FEAT_COMPAT_RO:
		set = BTRFS_FEATURE_COMPAT_RO_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_RO_SAFE_CLEAR;
		break;
	case FEAT_INCOMPAT:
		set = BTRFS_FEATURE_INCOMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_INCOMPAT_SAFE_CLEAR;
		break;
	default:
		printk(KERN_WARNING "btrfs: sysfs: unknown feature set %d\n",
				fa->feature_set);
		return 0;
	}

	if (set & fa->feature_bit)
		val |= 1;
	if (clear & fa->feature_bit)
		val |= 2;

	return val;
}

static ssize_t btrfs_feature_attr_show(struct kobject *kobj,
				       struct kobj_attribute *a, char *buf)
{
	int val = 0;
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	struct btrfs_feature_attr *fa = to_btrfs_feature_attr(a);
	if (fs_info) {
		u64 features = get_features(fs_info, fa->feature_set);
		if (features & fa->feature_bit)
			val = 1;
	} else
		val = can_modify_feature(fa);

	return snprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t btrfs_feature_attr_store(struct kobject *kobj,
					struct kobj_attribute *a,
					const char *buf, size_t count)
{
	struct btrfs_fs_info *fs_info;
	struct btrfs_feature_attr *fa = to_btrfs_feature_attr(a);
	struct btrfs_trans_handle *trans;
	u64 features, set, clear;
	unsigned long val;
	int ret;

	fs_info = to_fs_info(kobj);
	if (!fs_info)
		return -EPERM;

	ret = kstrtoul(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;

	if (fa->feature_set == FEAT_COMPAT) {
		set = BTRFS_FEATURE_COMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_SAFE_CLEAR;
	} else if (fa->feature_set == FEAT_COMPAT_RO) {
		set = BTRFS_FEATURE_COMPAT_RO_SAFE_SET;
		clear = BTRFS_FEATURE_COMPAT_RO_SAFE_CLEAR;
	} else {
		set = BTRFS_FEATURE_INCOMPAT_SAFE_SET;
		clear = BTRFS_FEATURE_INCOMPAT_SAFE_CLEAR;
	}

	features = get_features(fs_info, fa->feature_set);

	/* Nothing to do */
	if ((val && (features & fa->feature_bit)) ||
	    (!val && !(features & fa->feature_bit)))
		return count;

	if ((val && !(set & fa->feature_bit)) ||
	    (!val && !(clear & fa->feature_bit))) {
		btrfs_info(fs_info,
			"%sabling feature %s on mounted fs is not supported.",
			val ? "En" : "Dis", fa->kobj_attr.attr.name);
		return -EPERM;
	}

	btrfs_info(fs_info, "%s %s feature flag",
		   val ? "Setting" : "Clearing", fa->kobj_attr.attr.name);

	trans = btrfs_start_transaction(fs_info->fs_root, 0);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	spin_lock(&fs_info->super_lock);
	features = get_features(fs_info, fa->feature_set);
	if (val)
		features |= fa->feature_bit;
	else
		features &= ~fa->feature_bit;
	set_features(fs_info, fa->feature_set, features);
	spin_unlock(&fs_info->super_lock);

	ret = btrfs_commit_transaction(trans, fs_info->fs_root);
	if (ret)
		return ret;

	return count;
}

static umode_t btrfs_feature_visible(struct kobject *kobj,
				     struct attribute *attr, int unused)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	umode_t mode = attr->mode;

	if (fs_info) {
		struct btrfs_feature_attr *fa;
		u64 features;

		fa = attr_to_btrfs_feature_attr(attr);
		features = get_features(fs_info, fa->feature_set);

#ifdef MY_DEF_HERE
		if (fa->feature_set == FEAT_COMPAT_RO) {
			features |= BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE;
		}
#endif /* MY_DEF_HERE */

		if (can_modify_feature(fa))
			mode |= S_IWUSR;
#ifdef MY_DEF_HERE
		else if (fa->feature_bit & BTRFS_FEATURE_COMPAT_BLOCK_GROUP_CACHE_TREE) {}
#endif /* MY_DEF_HERE */
		else if (!(features & fa->feature_bit))
			mode = 0;
	}

	return mode;
}

BTRFS_FEAT_ATTR_INCOMPAT(mixed_backref, MIXED_BACKREF);
BTRFS_FEAT_ATTR_INCOMPAT(default_subvol, DEFAULT_SUBVOL);
BTRFS_FEAT_ATTR_INCOMPAT(mixed_groups, MIXED_GROUPS);
BTRFS_FEAT_ATTR_INCOMPAT(compress_lzo, COMPRESS_LZO);
BTRFS_FEAT_ATTR_INCOMPAT(compress_zstd, COMPRESS_ZSTD);
BTRFS_FEAT_ATTR_INCOMPAT(big_metadata, BIG_METADATA);
BTRFS_FEAT_ATTR_INCOMPAT(extended_iref, EXTENDED_IREF);
BTRFS_FEAT_ATTR_INCOMPAT(raid56, RAID56);
BTRFS_FEAT_ATTR_INCOMPAT(skinny_metadata, SKINNY_METADATA);
BTRFS_FEAT_ATTR_INCOMPAT(no_holes, NO_HOLES);
BTRFS_FEAT_ATTR_INCOMPAT(metadata_uuid, METADATA_UUID);
BTRFS_FEAT_ATTR_COMPAT_RO(free_space_tree, FREE_SPACE_TREE);
#ifdef MY_DEF_HERE
BTRFS_FEAT_ATTR_COMPAT(block_group_cache_tree, BLOCK_GROUP_CACHE_TREE);
#endif /* MY_DEF_HERE */

static struct attribute *btrfs_supported_feature_attrs[] = {
	BTRFS_FEAT_ATTR_PTR(mixed_backref),
	BTRFS_FEAT_ATTR_PTR(default_subvol),
	BTRFS_FEAT_ATTR_PTR(mixed_groups),
	BTRFS_FEAT_ATTR_PTR(compress_lzo),
	BTRFS_FEAT_ATTR_PTR(compress_zstd),
	BTRFS_FEAT_ATTR_PTR(big_metadata),
	BTRFS_FEAT_ATTR_PTR(extended_iref),
	BTRFS_FEAT_ATTR_PTR(raid56),
	BTRFS_FEAT_ATTR_PTR(skinny_metadata),
	BTRFS_FEAT_ATTR_PTR(no_holes),
	BTRFS_FEAT_ATTR_PTR(metadata_uuid),
	BTRFS_FEAT_ATTR_PTR(free_space_tree),
#ifdef MY_DEF_HERE
	BTRFS_FEAT_ATTR_PTR(block_group_cache_tree),
#endif /* MY_DEF_HERE */
	NULL
};

static const struct attribute_group btrfs_feature_attr_group = {
	.name = "features",
	.is_visible = btrfs_feature_visible,
	.attrs = btrfs_supported_feature_attrs,
};

static ssize_t btrfs_show_u64(u64 *value_ptr, spinlock_t *lock, char *buf)
{
	u64 val;
	if (lock)
		spin_lock(lock);
	val = *value_ptr;
	if (lock)
		spin_unlock(lock);
	return snprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static ssize_t global_rsv_size_show(struct kobject *kobj,
				    struct kobj_attribute *ka, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	return btrfs_show_u64(&block_rsv->size, &block_rsv->lock, buf);
}
BTRFS_ATTR(global_rsv_size, 0444, global_rsv_size_show);

static ssize_t global_rsv_reserved_show(struct kobject *kobj,
					struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	return btrfs_show_u64(&block_rsv->reserved, &block_rsv->lock, buf);
}
BTRFS_ATTR(global_rsv_reserved, 0444, global_rsv_reserved_show);

#ifdef MY_DEF_HERE
static ssize_t cleaner_rsv_size_show(struct kobject *kobj,
				    struct kobj_attribute *ka, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	struct btrfs_block_rsv *block_rsv = &fs_info->cleaner_block_rsv;
	return btrfs_show_u64(&block_rsv->size, &block_rsv->lock, buf);
}
BTRFS_ATTR(cleaner_rsv_size, 0444, cleaner_rsv_size_show);

static ssize_t cleaner_rsv_reserved_show(struct kobject *kobj,
					struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	struct btrfs_block_rsv *block_rsv = &fs_info->cleaner_block_rsv;
	return btrfs_show_u64(&block_rsv->reserved, &block_rsv->lock, buf);
}
BTRFS_ATTR(cleaner_rsv_reserved, 0444, cleaner_rsv_reserved_show);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t syno_bg_prefetch_enabled_show(struct kobject *kobj,
				    struct kobj_attribute *ka, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->syno_allocator.bg_prefetch_running ? 1 : 0);
}
static ssize_t syno_bg_prefetch_enabled_store(struct kobject *kobj,
						  struct kobj_attribute *a,
						  const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	u8 val;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtou8(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val == 1) {
		fs_info->syno_allocator.bg_prefetch_running = !!val;
		return len;
	}
	return -EINVAL;
}
BTRFS_ATTR_RW(syno_bg_prefetch_enabled, 0644, syno_bg_prefetch_enabled_show, syno_bg_prefetch_enabled_store);
#endif /* MY_DEF_HERE */

#define to_space_info(_kobj) container_of(_kobj, struct btrfs_space_info, kobj)
#define to_raid_kobj(_kobj) container_of(_kobj, struct raid_kobject, kobj)

static ssize_t raid_bytes_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf);
BTRFS_RAID_ATTR(total_bytes, raid_bytes_show);
BTRFS_RAID_ATTR(used_bytes, raid_bytes_show);

static ssize_t raid_bytes_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)

{
	struct btrfs_space_info *sinfo = to_space_info(kobj->parent);
	struct btrfs_block_group_cache *block_group;
	int index = to_raid_kobj(kobj)->raid_type;
	u64 val = 0;

	down_read(&sinfo->groups_sem);
	list_for_each_entry(block_group, &sinfo->block_groups[index], list) {
		if (&attr->attr == BTRFS_RAID_ATTR_PTR(total_bytes))
			val += block_group->key.offset;
		else
			val += btrfs_block_group_used(&block_group->item);
	}
	up_read(&sinfo->groups_sem);
	return snprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static struct attribute *raid_attributes[] = {
	BTRFS_RAID_ATTR_PTR(total_bytes),
	BTRFS_RAID_ATTR_PTR(used_bytes),
	NULL
};

static void release_raid_kobj(struct kobject *kobj)
{
	kfree(to_raid_kobj(kobj));
}

struct kobj_type btrfs_raid_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = release_raid_kobj,
	.default_attrs = raid_attributes,
};

static ssize_t btrfs_space_info_force_chunk_alloc_show(struct kobject *kobj,
						       struct kobj_attribute *a,
						       char *buf)
{
	return snprintf(buf, PAGE_SIZE, "0\n");
}

static ssize_t btrfs_space_info_force_chunk_alloc(struct kobject *kobj,
						  struct kobj_attribute *a,
						  const char *buf, size_t len)
{
	struct btrfs_space_info *space_info = to_space_info(kobj);
	struct btrfs_fs_info *fs_info = to_fs_info(get_btrfs_kobj(kobj));
	struct btrfs_trans_handle *trans;
	unsigned long val;
	int ret;

	if (!fs_info) {
		printk(KERN_ERR "couldn't get fs_info\n");
		return -EPERM;
	}

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (fs_info->sb->s_flags & MS_RDONLY)
		return -EROFS;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	/*
	 * We don't really care, but if we echo 0 > force it seems silly to do
	 * anything.
	 */
	if (val == 0)
		return -EINVAL;

	trans = btrfs_start_transaction(fs_info->extent_root, 0);
	if (!trans)
		return PTR_ERR(trans);
	ret = btrfs_force_chunk_alloc(trans, fs_info->extent_root, space_info->flags);
	btrfs_end_transaction(trans, fs_info->extent_root);
	if (ret == 1)
		return len;
	return -ENOSPC;
}
BTRFS_ATTR_RW(force_chunk_alloc, 0644,
	      btrfs_space_info_force_chunk_alloc_show,
	      btrfs_space_info_force_chunk_alloc);

#define SPACE_INFO_ATTR(field)						\
static ssize_t btrfs_space_info_show_##field(struct kobject *kobj,	\
					     struct kobj_attribute *a,	\
					     char *buf)			\
{									\
	struct btrfs_space_info *sinfo = to_space_info(kobj);		\
	return btrfs_show_u64(&sinfo->field, &sinfo->lock, buf);	\
}									\
BTRFS_ATTR(field, 0444, btrfs_space_info_show_##field)

static ssize_t btrfs_space_info_show_total_bytes_pinned(struct kobject *kobj,
						       struct kobj_attribute *a,
						       char *buf)
{
	struct btrfs_space_info *sinfo = to_space_info(kobj);
	s64 val = percpu_counter_sum(&sinfo->total_bytes_pinned);
	return snprintf(buf, PAGE_SIZE, "%lld\n", val);
}

SPACE_INFO_ATTR(flags);
SPACE_INFO_ATTR(total_bytes);
SPACE_INFO_ATTR(bytes_used);
SPACE_INFO_ATTR(bytes_pinned);
SPACE_INFO_ATTR(bytes_reserved);
SPACE_INFO_ATTR(bytes_may_use);
SPACE_INFO_ATTR(disk_used);
SPACE_INFO_ATTR(disk_total);
BTRFS_ATTR(total_bytes_pinned, 0444, btrfs_space_info_show_total_bytes_pinned);

#ifdef MY_DEF_HERE
static ssize_t btrfs_space_info_show_syno_allocation(struct kobject *kobj,
						       struct kobj_attribute *a,
						       char *buf)
{
	struct btrfs_space_info *sinfo = to_space_info(kobj);
	int len = 0;

	len += snprintf(buf + len, PAGE_SIZE, "fallback_relink_count:%llu\n", (u64)atomic64_read(&sinfo->syno_allocator.fallback_relink_count));
	len += snprintf(buf + len, PAGE_SIZE, "fallback_full_scan_count:%llu\n", (u64)atomic64_read(&sinfo->syno_allocator.fallback_full_scan_count));

	return len;
}
BTRFS_ATTR(syno_allocation, 0444, btrfs_space_info_show_syno_allocation);
#endif /* MY_DEF_HERE */

static struct attribute *space_info_attrs[] = {
	BTRFS_ATTR_PTR(flags),
	BTRFS_ATTR_PTR(total_bytes),
	BTRFS_ATTR_PTR(bytes_used),
	BTRFS_ATTR_PTR(bytes_pinned),
	BTRFS_ATTR_PTR(bytes_reserved),
	BTRFS_ATTR_PTR(bytes_may_use),
	BTRFS_ATTR_PTR(disk_used),
	BTRFS_ATTR_PTR(disk_total),
	BTRFS_ATTR_PTR(total_bytes_pinned),
	BTRFS_ATTR_PTR(force_chunk_alloc),
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_allocation),
#endif /* MY_DEF_HERE */
	NULL,
};

static void space_info_release(struct kobject *kobj)
{
	struct btrfs_space_info *sinfo = to_space_info(kobj);
	percpu_counter_destroy(&sinfo->total_bytes_pinned);
	kfree(sinfo);
}

struct kobj_type space_info_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = space_info_release,
	.default_attrs = space_info_attrs,
};

static const struct attribute *allocation_attrs[] = {
	BTRFS_ATTR_PTR(global_rsv_reserved),
	BTRFS_ATTR_PTR(global_rsv_size),
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(cleaner_rsv_reserved),
	BTRFS_ATTR_PTR(cleaner_rsv_size),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_bg_prefetch_enabled),
#endif /* MY_DEF_HERE */
	NULL,
};

static ssize_t btrfs_label_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%s\n", fs_info->super_copy->label);
}

static ssize_t btrfs_label_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = fs_info->fs_root;
	int ret;

	if (len >= BTRFS_LABEL_SIZE)
		return -EINVAL;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	spin_lock(&root->fs_info->super_lock);
	strcpy(fs_info->super_copy->label, buf);
	spin_unlock(&root->fs_info->super_lock);
	ret = btrfs_commit_transaction(trans, root);

	if (!ret)
		return len;

	return ret;
}
BTRFS_ATTR_RW(label, 0644, btrfs_label_show, btrfs_label_store);

static ssize_t btrfs_no_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	return -EPERM;
}

static ssize_t btrfs_nodesize_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->super_copy->nodesize);
}

BTRFS_ATTR_RW(nodesize, 0444, btrfs_nodesize_show, btrfs_no_store);

static ssize_t btrfs_sectorsize_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->super_copy->sectorsize);
}

BTRFS_ATTR_RW(sectorsize, 0444, btrfs_sectorsize_show, btrfs_no_store);

static ssize_t btrfs_clone_alignment_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->super_copy->sectorsize);
}

BTRFS_ATTR_RW(clone_alignment, 0444, btrfs_clone_alignment_show, btrfs_no_store);

#ifdef MY_DEF_HERE
static ssize_t btrfs_mount_path_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%s\n", fs_info->mount_path);
}

BTRFS_ATTR(mount_path, 0444, btrfs_mount_path_show);

static ssize_t btrfs_correction_suppress_log_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->correction_suppress_log);
}

static ssize_t btrfs_correction_suppress_log_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	u8 val;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtou8(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val == 1 || val == 2) {
		fs_info->correction_suppress_log = val;
		return len;
	}
	return -EINVAL;
}

BTRFS_ATTR_RW(correction_suppress_log, 0644, btrfs_correction_suppress_log_show, btrfs_correction_suppress_log_store);

static ssize_t btrfs_correction_disable_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->correction_disable);
}

static ssize_t btrfs_correction_disable_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	u8 val;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtou8(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val == 1) {
		fs_info->correction_disable = val;
		return len;
	}
	return -EINVAL;
}

BTRFS_ATTR_RW(correction_disable, 0644, btrfs_correction_disable_show, btrfs_correction_disable_store);

static ssize_t btrfs_correction_record_cnt_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%d\n", !RB_EMPTY_ROOT(&fs_info->correction_record));
}

static ssize_t btrfs_correction_record_cnt_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	struct rb_node *n;
	struct correction_record *record;
	u8 val;
	int cnt = 0;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtou8(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;

	if (val == 1) {
		spin_lock(&fs_info->correction_record_lock);
		for (n = rb_first(&fs_info->correction_record); n; n = rb_next(n)) {
			record = rb_entry(n, struct correction_record, node);
			printk(KERN_INFO "one correction record, logical = %llu\n", record->logical);
			cnt++;
		}
		spin_unlock(&fs_info->correction_record_lock);
		printk(KERN_INFO "Btrfs has %d unfinished correction record\n", cnt);
		return len;
	}
	return -EINVAL;
}

BTRFS_ATTR_RW(correction_record_cnt, 0644, btrfs_correction_record_cnt_show, btrfs_correction_record_cnt_store);
#endif

#ifdef MY_DEF_HERE
static ssize_t btrfs_syno_writeback_thread_max_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%d\n", fs_info->syno_writeback_thread_max);
}

static ssize_t btrfs_syno_writeback_thread_max_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	u8 val;
	int ret;

	ret = kstrtou8(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	fs_info->syno_writeback_thread_max = val;
	return len;
}

BTRFS_ATTR_RW(syno_writeback_thread_max, 0644, btrfs_syno_writeback_thread_max_show, btrfs_syno_writeback_thread_max_store);

static ssize_t btrfs_syno_writeback_thread_count_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%d\n", atomic_read(&fs_info->syno_writeback_thread_count));
}

BTRFS_ATTR(syno_writeback_thread_count, 0444, btrfs_syno_writeback_thread_count_show);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_block_group_cnt_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->block_group_cnt);
}
BTRFS_ATTR(block_group_cnt, 0444, btrfs_block_group_cnt_show);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_syno_async_submit_throttle_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->syno_async_submit_throttle);
}

static ssize_t btrfs_syno_async_submit_throttle_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	u32 val;
	int ret;

	ret = kstrtou32(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	fs_info->syno_async_submit_throttle = val;
	return len;
}

BTRFS_ATTR_RW(syno_async_submit_throttle, 0644, btrfs_syno_async_submit_throttle_show, btrfs_syno_async_submit_throttle_store);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_syno_max_ordered_queue_size_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%llu\n", fs_info->syno_max_ordered_queue_size);
}

static ssize_t btrfs_syno_max_ordered_queue_size_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	int val;
	int ret;

	ret = kstrtoint(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val < 0)
		return -EINVAL;
	fs_info->syno_max_ordered_queue_size = val;
	return len;
}

BTRFS_ATTR_RW(syno_max_ordered_queue_size, 0644, btrfs_syno_max_ordered_queue_size_show, btrfs_syno_max_ordered_queue_size_store);

static ssize_t btrfs_syno_ordered_extent_nr_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%llu\n", (u64)atomic64_read(&fs_info->syno_ordered_extent_nr));
}

BTRFS_ATTR(syno_ordered_extent_nr, 0444, btrfs_syno_ordered_extent_nr_show);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_snapshot_cleaner_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->snapshot_cleaner);
}

static ssize_t btrfs_snapshot_cleaner_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	unsigned int val;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtouint(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val == 1) {
		fs_info->snapshot_cleaner = val;
		return len;
	}
	return -EINVAL;
}

BTRFS_ATTR_RW(snapshot_cleaner, 0644, btrfs_snapshot_cleaner_show, btrfs_snapshot_cleaner_store);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_metadata_cache_enable_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->metadata_cache_enable);
}

static ssize_t btrfs_metadata_cache_enable_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	unsigned int val;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtouint(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val == 1) {
		fs_info->metadata_cache_enable = val;
		return len;
	}
	return -EINVAL;
}

BTRFS_ATTR_RW(metadata_cache_enable, 0644, btrfs_metadata_cache_enable_show, btrfs_metadata_cache_enable_store);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_fsync_cnt_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%ld\n", atomic64_read(&fs_info->fsync_cnt));
}
BTRFS_ATTR(fsync_cnt, 0444, btrfs_fsync_cnt_show);

static ssize_t btrfs_fsync_full_commit_cnt_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	return snprintf(buf, PAGE_SIZE, "%ld\n", atomic64_read(&fs_info->fsync_full_commit_cnt));
}
BTRFS_ATTR(fsync_full_commit_cnt, 0444, btrfs_fsync_full_commit_cnt_show);
static ssize_t btrfs_commit_time_debug_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	int ret;
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	ret = snprintf(buf, PAGE_SIZE, "%d\n", fs_info->commit_time_debug);
	return ret;
}

static ssize_t btrfs_commit_time_debug_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	u8 val;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtou8(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val == 1 ) {
		fs_info->commit_time_debug = val;
		return len;
	}
	return -EINVAL;
}

BTRFS_ATTR_RW(commit_time_debug, 0644, btrfs_commit_time_debug_show, btrfs_commit_time_debug_store);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static char* syno_usage_type_to_str(int type, char *ret, int max_size)
{
	int unknown = 0;
	const char* str;
	switch (type) {
	case SYNO_USAGE_TYPE_RO_SNAPSHOT:
		str = "Snapshot";
		break;
	default:
		unknown = 1;
		str = "Type";
		break;
	}
	if (unknown)
		snprintf(ret, max_size, "%s.%d", str, type);
	else
		snprintf(ret, max_size, "%s", str);
	return ret;
}

static ssize_t btrfs_syno_usage_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	int i;
	int len = 0;
	char type_str[32] = {0};

	for (i = SYNO_USAGE_TYPE_RO_SNAPSHOT; i < SYNO_USAGE_TYPE_MAX; i++) {
		if (i == SYNO_USAGE_TYPE_RO_SNAPSHOT || fs_info->syno_usage_status.syno_usage_type_num_bytes[i])
			len += snprintf(buf + len, PAGE_SIZE - len, "%s:%llu\n", syno_usage_type_to_str(i, type_str, sizeof(type_str)), fs_info->syno_usage_status.syno_usage_type_num_bytes[i]);
	}
	return len;
}

BTRFS_ATTR(syno_usage, 0444, btrfs_syno_usage_show);
#endif /* MY_DEF_HERE */

static ssize_t btrfs_metadata_uuid_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);

	return snprintf(buf, PAGE_SIZE, "%pU\n",
			fs_info->fs_devices->metadata_uuid);
}

BTRFS_ATTR(fs_metadata_uuid, 0444, btrfs_metadata_uuid_show);

#ifdef MY_DEF_HERE
static ssize_t btrfs_syno_meta_statistics_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	int len = 0;

	len += snprintf(buf + len, PAGE_SIZE - len, "Extent Buffer Disk Read:%llu\n", (u64)atomic64_read(&fs_info->syno_meta_statistics.eb_disk_read));
	len += snprintf(buf + len, PAGE_SIZE - len, "Search Key:%llu\n", (u64)atomic64_read(&fs_info->syno_meta_statistics.search_key));
	len += snprintf(buf + len, PAGE_SIZE - len, "Search Forward:%llu\n", (u64)atomic64_read(&fs_info->syno_meta_statistics.search_forward));
	len += snprintf(buf + len, PAGE_SIZE - len, "Next Leaf:%llu\n", (u64)atomic64_read(&fs_info->syno_meta_statistics.next_leaf));

	return len;
}
BTRFS_ATTR(syno_meta_statistics, 0444, btrfs_syno_meta_statistics_show);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_syno_orphan_cleanup_enable_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	int ret;
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	ret = snprintf(buf, PAGE_SIZE, "%d\n", fs_info->syno_orphan_cleanup.enable ? 1 : 0);
	return ret;
}
static ssize_t btrfs_syno_orphan_cleanup_enable_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	unsigned int val;
	int ret;

	ret = kstrtouint(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val != 0 && val != 1)
		return -EINVAL;
	fs_info->syno_orphan_cleanup.enable = !!val;
	return len;
}
BTRFS_ATTR_RW(syno_orphan_cleanup_enable, 0644, btrfs_syno_orphan_cleanup_enable_show, btrfs_syno_orphan_cleanup_enable_store);

static ssize_t btrfs_syno_orphan_cleanup_delayed_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	int ret;
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	ret = snprintf(buf, PAGE_SIZE, "%d\n", fs_info->syno_orphan_cleanup.orphan_inode_delayed ? 1 : 0);
	return ret;
}
static ssize_t btrfs_syno_orphan_cleanup_delayed_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	unsigned int val;
	int ret;

	ret = kstrtouint(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val != 0 && val != 1)
		return -EINVAL;
	fs_info->syno_orphan_cleanup.orphan_inode_delayed = !!val;
	return len;
}
BTRFS_ATTR_RW(syno_orphan_cleanup_delayed, 0644, btrfs_syno_orphan_cleanup_delayed_show, btrfs_syno_orphan_cleanup_delayed_store);
#endif /* MY_DEF_HERE */

static struct attribute *btrfs_attrs[] = {
	BTRFS_ATTR_PTR(label),
	BTRFS_ATTR_PTR(nodesize),
	BTRFS_ATTR_PTR(sectorsize),
	BTRFS_ATTR_PTR(clone_alignment),
	BTRFS_ATTR_PTR(fs_metadata_uuid),
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(mount_path),
	BTRFS_ATTR_PTR(correction_suppress_log),
	BTRFS_ATTR_PTR(correction_disable),
	BTRFS_ATTR_PTR(correction_record_cnt),
#endif
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_writeback_thread_max),
	BTRFS_ATTR_PTR(syno_writeback_thread_count),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(block_group_cnt),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_async_submit_throttle),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_max_ordered_queue_size),
	BTRFS_ATTR_PTR(syno_ordered_extent_nr),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(snapshot_cleaner),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(metadata_cache_enable),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(fsync_cnt),
	BTRFS_ATTR_PTR(fsync_full_commit_cnt),
	BTRFS_ATTR_PTR(commit_time_debug),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_usage),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_meta_statistics),
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	BTRFS_ATTR_PTR(syno_orphan_cleanup_enable),
	BTRFS_ATTR_PTR(syno_orphan_cleanup_delayed),
#endif /* MY_DEF_HERE */
	NULL,
};

#ifdef MY_ABC_HERE
static ssize_t btrfs_incompat_supp_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", BTRFS_FEATURE_INCOMPAT_SUPP);
}
BTRFS_ATTR(incompat_supp, 0444, btrfs_incompat_supp_show);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static ssize_t btrfs_compat_ro_supp_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", BTRFS_FEATURE_COMPAT_RO_SUPP);
}
BTRFS_ATTR(compat_ro_supp, 0444, btrfs_compat_ro_supp_show);
#endif /* MY_ABC_HERE */

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
static const struct attribute *btrfs_info_attrs[] = {
#ifdef MY_ABC_HERE
	BTRFS_ATTR_PTR(incompat_supp),
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	BTRFS_ATTR_PTR(compat_ro_supp),
#endif /* MY_ABC_HERE */
	NULL,
};
#endif /* MY_ABC_HERE | MY_ABC_HERE */

static void btrfs_release_super_kobj(struct kobject *kobj)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj);
	complete(&fs_info->kobj_unregister);
}

static struct kobj_type btrfs_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
	.release	= btrfs_release_super_kobj,
	.default_attrs	= btrfs_attrs,
};

static inline struct btrfs_fs_info *to_fs_info(struct kobject *kobj)
{
	if (kobj->ktype != &btrfs_ktype)
		return NULL;
	return container_of(kobj, struct btrfs_fs_info, super_kobj);
}

static inline struct kobject *get_btrfs_kobj(struct kobject *kobj)
{
	while (kobj) {
		if (kobj->ktype == &btrfs_ktype)
			return kobj;
		kobj = kobj->parent;
	}
	return NULL;
}

#define NUM_FEATURE_BITS 64
static char btrfs_unknown_feature_names[3][NUM_FEATURE_BITS][13];
static struct btrfs_feature_attr btrfs_feature_attrs[3][NUM_FEATURE_BITS];

static u64 supported_feature_masks[3] = {
	[FEAT_COMPAT]    = BTRFS_FEATURE_COMPAT_SUPP,
	[FEAT_COMPAT_RO] = BTRFS_FEATURE_COMPAT_RO_SUPP,
	[FEAT_INCOMPAT]  = BTRFS_FEATURE_INCOMPAT_SUPP,
};

#ifdef MY_DEF_HERE
static ssize_t btrfs_free_space_tree_create_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	return snprintf(buf, PAGE_SIZE, "%d\n", fs_info->creating_free_space_tree);
}
BTRFS_ATTR(free_space_tree_creating, 0444, btrfs_free_space_tree_create_show);

static ssize_t btrfs_free_space_tree_created_block_group_cnt_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->free_space_tree_processed_block_group_cnt);
}
BTRFS_ATTR(processed_block_group_cnt, 0444, btrfs_free_space_tree_created_block_group_cnt_show);

static ssize_t btrfs_free_space_tree_abort_show(struct kobject *kobj,
				struct kobj_attribute *a, char *buf)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	return snprintf(buf, PAGE_SIZE, "%u\n", fs_info->abort_free_space_tree);
}

static ssize_t btrfs_free_space_tree_abort_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	struct btrfs_fs_info *fs_info = to_fs_info(kobj->parent);
	int val;
	int ret;

	if (len > 2)
		return -EINVAL;
	ret = kstrtouint(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;
	if (val == 0 || val == 1) {
		fs_info->abort_free_space_tree = val;
		return len;
	}
	return -EINVAL;
}

BTRFS_ATTR_RW(abort_free_space_tree, 0644, btrfs_free_space_tree_abort_show, btrfs_free_space_tree_abort_store);

static const struct attribute *free_space_tree_attrs[] = {
	BTRFS_ATTR_PTR(free_space_tree_creating),
	BTRFS_ATTR_PTR(processed_block_group_cnt),
	BTRFS_ATTR_PTR(abort_free_space_tree),
	NULL,
};

int add_free_space_tree_attrs(struct btrfs_fs_info *fs_info)
{
	int error = 0;

	fs_info->free_space_tree_kobj = kobject_create_and_add("free_space_tree",
						  &fs_info->super_kobj);

	if (!fs_info->free_space_tree_kobj) {
		error = -ENOMEM;
		goto failure;
	}

	error = sysfs_create_files(fs_info->free_space_tree_kobj, free_space_tree_attrs);
	if (error)
		goto failure;

	return 0;
failure:
	return error;
}
#endif /* MY_DEF_HERE */

static int addrm_unknown_feature_attrs(struct btrfs_fs_info *fs_info, bool add)
{
	int set;

	for (set = 0; set < FEAT_MAX; set++) {
		int i;
		struct attribute *attrs[2];
		struct attribute_group agroup = {
			.name = "features",
			.attrs = attrs,
		};
		u64 features = get_features(fs_info, set);
		features &= ~supported_feature_masks[set];

		if (!features)
			continue;

		attrs[1] = NULL;
		for (i = 0; i < NUM_FEATURE_BITS; i++) {
			struct btrfs_feature_attr *fa;

			if (!(features & (1ULL << i)))
				continue;

			fa = &btrfs_feature_attrs[set][i];
			attrs[0] = &fa->kobj_attr.attr;
			if (add) {
				int ret;
				ret = sysfs_merge_group(&fs_info->super_kobj,
							&agroup);
				if (ret)
					return ret;
			} else
				sysfs_unmerge_group(&fs_info->super_kobj,
						    &agroup);
		}

	}
	return 0;
}

static void __btrfs_sysfs_remove_one(struct btrfs_fs_info *fs_info)
{
	kobject_del(&fs_info->super_kobj);
	kobject_put(&fs_info->super_kobj);
	wait_for_completion(&fs_info->kobj_unregister);
}

void btrfs_sysfs_remove_one(struct btrfs_fs_info *fs_info)
{
	if (fs_info->space_info_kobj) {
		sysfs_remove_files(fs_info->space_info_kobj, allocation_attrs);
		kobject_del(fs_info->space_info_kobj);
		kobject_put(fs_info->space_info_kobj);
	}

#ifdef MY_DEF_HERE
	if (fs_info->free_space_tree_kobj) {
		sysfs_remove_files(fs_info->free_space_tree_kobj, free_space_tree_attrs);
		kobject_del(fs_info->free_space_tree_kobj);
		kobject_put(fs_info->free_space_tree_kobj);
	}
#endif /* MY_DEF_HERE */

	kobject_del(fs_info->device_dir_kobj);
	kobject_put(fs_info->device_dir_kobj);
	addrm_unknown_feature_attrs(fs_info, false);

	sysfs_remove_group(&fs_info->super_kobj, &btrfs_feature_attr_group);
	__btrfs_sysfs_remove_one(fs_info);
}

const char * const btrfs_feature_set_names[3] = {
	[FEAT_COMPAT]	 = "compat",
	[FEAT_COMPAT_RO] = "compat_ro",
	[FEAT_INCOMPAT]	 = "incompat",
};

char *btrfs_printable_features(enum btrfs_feature_set set, u64 flags)
{
	size_t bufsize = 4096; /* safe max, 64 names * 64 bytes */
	int len = 0;
	int i;
	char *str;

	str = kmalloc(bufsize, GFP_KERNEL);
	if (!str)
		return str;

	for (i = 0; i < ARRAY_SIZE(btrfs_feature_attrs[set]); i++) {
		const char *name;

		if (!(flags & (1ULL << i)))
			continue;

		name = btrfs_feature_attrs[set][i].kobj_attr.attr.name;
		len += snprintf(str + len, bufsize - len, "%s%s",
				len ? "," : "", name);
	}

	return str;
}

static void init_feature_attrs(void)
{
	struct btrfs_feature_attr *fa;
	int set, i;

	BUILD_BUG_ON(ARRAY_SIZE(btrfs_unknown_feature_names) !=
		     ARRAY_SIZE(btrfs_feature_attrs));
	BUILD_BUG_ON(ARRAY_SIZE(btrfs_unknown_feature_names[0]) !=
		     ARRAY_SIZE(btrfs_feature_attrs[0]));

	memset(btrfs_feature_attrs, 0, sizeof(btrfs_feature_attrs));
	memset(btrfs_unknown_feature_names, 0,
	       sizeof(btrfs_unknown_feature_names));

	for (i = 0; btrfs_supported_feature_attrs[i]; i++) {
		struct btrfs_feature_attr *sfa;
		struct attribute *a = btrfs_supported_feature_attrs[i];
		int bit;
		sfa = attr_to_btrfs_feature_attr(a);
		bit = ilog2(sfa->feature_bit);
		fa = &btrfs_feature_attrs[sfa->feature_set][bit];

		fa->kobj_attr.attr.name = sfa->kobj_attr.attr.name;
	}

	for (set = 0; set < FEAT_MAX; set++) {
		for (i = 0; i < ARRAY_SIZE(btrfs_feature_attrs[set]); i++) {
			char *name = btrfs_unknown_feature_names[set][i];
			fa = &btrfs_feature_attrs[set][i];

			if (fa->kobj_attr.attr.name)
				continue;

			snprintf(name, 13, "%s:%u",
				 btrfs_feature_set_names[set], i);

			fa->kobj_attr.attr.name = name;
			fa->kobj_attr.attr.mode = S_IRUGO;
			fa->feature_set = set;
			fa->feature_bit = 1ULL << i;
		}
	}
}

int btrfs_kobj_rm_device(struct btrfs_fs_info *fs_info,
		struct btrfs_device *one_device)
{
	struct hd_struct *disk;
	struct kobject *disk_kobj;

	if (!fs_info->device_dir_kobj)
		return -EINVAL;

	if (one_device) {
		disk = one_device->bdev->bd_part;
		disk_kobj = &part_to_dev(disk)->kobj;

		sysfs_remove_link(fs_info->device_dir_kobj,
						disk_kobj->name);
	}

	return 0;
}

int btrfs_kobj_add_device(struct btrfs_fs_info *fs_info,
		struct btrfs_device *one_device)
{
	int error = 0;
	struct btrfs_fs_devices *fs_devices = fs_info->fs_devices;
	struct btrfs_device *dev;

	if (!fs_info->device_dir_kobj)
		fs_info->device_dir_kobj = kobject_create_and_add("devices",
						&fs_info->super_kobj);

	if (!fs_info->device_dir_kobj)
		return -ENOMEM;

	list_for_each_entry(dev, &fs_devices->devices, dev_list) {
		struct hd_struct *disk;
		struct kobject *disk_kobj;

		if (!dev->bdev)
			continue;

		if (one_device && one_device != dev)
			continue;

		disk = dev->bdev->bd_part;
		disk_kobj = &part_to_dev(disk)->kobj;

		error = sysfs_create_link(fs_info->device_dir_kobj,
					  disk_kobj, disk_kobj->name);
		if (error)
			break;
	}

	return error;
}

/* /sys/fs/btrfs/ entry */
static struct kset *btrfs_kset;

/* /sys/kernel/debug/btrfs */
static struct dentry *btrfs_debugfs_root_dentry;

/* Debugging tunables and exported data */
u64 btrfs_debugfs_test;

int btrfs_sysfs_add_one(struct btrfs_fs_info *fs_info)
{
	int error;

	init_completion(&fs_info->kobj_unregister);
	fs_info->super_kobj.kset = btrfs_kset;
	error = kobject_init_and_add(&fs_info->super_kobj, &btrfs_ktype, NULL,
				     "%pU", fs_info->fs_devices->fsid);
	if (error)
		return error;

	error = sysfs_create_group(&fs_info->super_kobj,
				   &btrfs_feature_attr_group);
	if (error) {
		__btrfs_sysfs_remove_one(fs_info);
		return error;
	}

#ifdef MY_DEF_HERE
	if (btrfs_test_opt(fs_info->tree_root, FREE_SPACE_TREE)) {
		error = add_free_space_tree_attrs(fs_info);
		if (error)
			goto failure;
	}
#endif /* MY_DEF_HERE */

	error = addrm_unknown_feature_attrs(fs_info, true);
	if (error)
		goto failure;

	error = btrfs_kobj_add_device(fs_info, NULL);
	if (error)
		goto failure;

	fs_info->space_info_kobj = kobject_create_and_add("allocation",
						  &fs_info->super_kobj);
	if (!fs_info->space_info_kobj) {
		error = -ENOMEM;
		goto failure;
	}

	error = sysfs_create_files(fs_info->space_info_kobj, allocation_attrs);
	if (error)
		goto failure;

	return 0;
failure:
	btrfs_sysfs_remove_one(fs_info);
	return error;
}

#ifdef MY_DEF_HERE
static int debugfs_percpu_counter_get(void *data, u64 *val)
{
	*val = percpu_counter_sum((struct percpu_counter *)data);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_percpu_counter_ro, debugfs_percpu_counter_get, NULL, "%llu\n");

static struct dentry *debugfs_create_percpu_counter(const char *name, struct dentry *parent,
		struct percpu_counter *counter)
{
	return debugfs_create_file(name, S_IRUSR, parent, counter, &fops_percpu_counter_ro);
}

static int add_one_root_file(void *data, u64 val)
{
	struct btrfs_fs_info *fs_info = (struct btrfs_fs_info *)data;
	struct btrfs_key key;
	struct btrfs_root *root;
	struct dentry *dentry;
	char buf[32];

	if ((val < BTRFS_FIRST_FREE_OBJECTID || val > BTRFS_LAST_FREE_OBJECTID) &&
			val != BTRFS_EXTENT_TREE_OBJECTID) {
		printk(KERN_INFO "BTRFS: can only monitor subvolume or extent tree\n");
		return -ENOENT;
	}

	key.objectid = val;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(root)) {
		printk(KERN_INFO "BTRFS: could not find root %llu\n", val);
		return -ENOENT;
	}

	snprintf(buf, 32, "root_""%llu""_hit", val);
	dentry = debugfs_create_percpu_counter(buf,
			fs_info->btrfs_pervolume_debugfs_root_dentry, &root->eb_hit);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create root_hit file for root %llu\n", val);
		return -EEXIST;
	}
	root->eb_hit_dentry = dentry;

	snprintf(buf, 32, "root_""%llu""_miss", val);
	dentry = debugfs_create_percpu_counter(buf,
			fs_info->btrfs_pervolume_debugfs_root_dentry, &root->eb_miss);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create root_miss file for root %llu\n", val);
		return -EEXIST;
	}
	root->eb_miss_dentry = dentry;

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_btrfs_add_one_root_file, NULL, add_one_root_file, "%llu\n");

void debugfs_remove_root_hook(struct btrfs_root *root)
{
	debugfs_remove(root->eb_hit_dentry);
	debugfs_remove(root->eb_miss_dentry);
}

void btrfs_debugfs_remove_one(struct btrfs_fs_info *fs_info)
{
	if (fs_info->btrfs_pervolume_debugfs_root_dentry)
		debugfs_remove_recursive(fs_info->btrfs_pervolume_debugfs_root_dentry);
	fs_info->btrfs_pervolume_debugfs_root_dentry = NULL;
}

int btrfs_debugfs_add_one(struct btrfs_fs_info *fs_info)
{
	struct dentry *dentry;
	char buf[BTRFS_UUID_UNPARSED_SIZE];
	int ret;

	if (IS_ERR_OR_NULL(btrfs_debugfs_root_dentry)) {
		printk(KERN_ERR "BTRFS: could not find btrfs_debugfs_root_dentry\n");
		return -ENOENT;
	}

	snprintf(buf, BTRFS_UUID_UNPARSED_SIZE, "%pU", fs_info->fs_devices->fsid);
	dentry = debugfs_create_dir(buf, btrfs_debugfs_root_dentry);
	if (!dentry)
		return -ENOMEM;
	fs_info->btrfs_pervolume_debugfs_root_dentry = dentry;

	dentry = debugfs_create_file("create_root", S_IWUSR,
			fs_info->btrfs_pervolume_debugfs_root_dentry, fs_info, &fops_btrfs_add_one_root_file);
	if (!dentry) {
		printk(KERN_ERR "BTRFS: could not create create_root\n");
		ret = -ENOENT;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("volume_eb_hit",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->eb_hit);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create volume_eb_hit file\n");
		ret = -ENOMEM;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("volume_eb_miss",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->eb_miss);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create volume_eb_miss file\n");
		ret = -ENOMEM;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("volume_meta_write_pages",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->meta_write_pages);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create volume_meta_write_pages file\n");
		ret = -ENOMEM;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("volume_data_write_pages",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->data_write_pages);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create volume_data_write_pages file\n");
		ret = -ENOMEM;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("delayed_meta_ref",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->delayed_meta_ref);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create delayed_meta_ref file\n");
		ret = -ENOMEM;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("delayed_data_ref",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->delayed_data_ref);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create delayed_data_ref file\n");
		ret = -ENOMEM;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("write_flush",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->write_flush);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create write_flush file\n");
		ret = -ENOMEM;
		goto out;
	}

	dentry = debugfs_create_percpu_counter("write_fua",
			fs_info->btrfs_pervolume_debugfs_root_dentry, &fs_info->write_fua);
	if (!dentry) {
		printk(KERN_INFO "BTRFS: could not create write_fua file\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;

out:
	if (ret)
		btrfs_debugfs_remove_one(fs_info);
	return ret;
}
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static ssize_t btrfs_qgroup_soft_limit_show(struct kobject *kobj,
				 struct kobj_attribute *a, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", qgroup_soft_limit);
}

static ssize_t btrfs_qgroup_soft_limit_store(struct kobject *kobj,
				 struct kobj_attribute *a,
				 const char *buf, size_t len)
{
	int ret;
	u64 val;

	ret = kstrtoull(skip_spaces(buf), 0, &val);
	if (ret)
		return ret;

	if (val > 100)
		return -EINVAL;

	qgroup_soft_limit = val;
	return len;
}
BTRFS_ATTR_RW(qgroup_soft_limit, 0644, btrfs_qgroup_soft_limit_show, btrfs_qgroup_soft_limit_store);

static struct attribute *btrfs_qgroup_soft_limit_feature_attrs[] = {
	BTRFS_ATTR_PTR(qgroup_soft_limit),
	NULL
};

static const struct attribute_group btrfs_qgroup_soft_limit_feature_attr_group = {
	.name = "features",
	.attrs = btrfs_qgroup_soft_limit_feature_attrs,
};
#endif /* MY_DEF_HERE */

static int btrfs_init_debugfs(void)
{
#ifdef CONFIG_DEBUG_FS
	btrfs_debugfs_root_dentry = debugfs_create_dir("btrfs", NULL);
	if (!btrfs_debugfs_root_dentry)
		return -ENOMEM;

	debugfs_create_u64("test", S_IRUGO | S_IWUGO, btrfs_debugfs_root_dentry,
			&btrfs_debugfs_test);
#endif
	return 0;
}

int __init btrfs_init_sysfs(void)
{
	int ret;

	btrfs_kset = kset_create_and_add("btrfs", NULL, fs_kobj);
	if (!btrfs_kset)
		return -ENOMEM;

	ret = btrfs_init_debugfs();
	if (ret)
		return ret;

	init_feature_attrs();
	ret = sysfs_create_group(&btrfs_kset->kobj, &btrfs_feature_attr_group);
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	if (!ret) {
		ret = sysfs_create_files(&btrfs_kset->kobj, btrfs_info_attrs);
		if (ret) {
			sysfs_remove_group(&btrfs_kset->kobj, &btrfs_feature_attr_group);
		}
	}
#endif /* MY_ABC_HERE | MY_ABC_HERE */
#ifdef MY_DEF_HERE
	ret = sysfs_merge_group(&btrfs_kset->kobj, &btrfs_qgroup_soft_limit_feature_attr_group);
#endif /* MY_DEF_HERE */
	return ret;
}

void btrfs_exit_sysfs(void)
{
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	sysfs_remove_files(&btrfs_kset->kobj, btrfs_info_attrs);
#endif /* MY_ABC_HERE | MY_ABC_HERE */
	sysfs_remove_group(&btrfs_kset->kobj, &btrfs_feature_attr_group);
	kset_unregister(btrfs_kset);
	debugfs_remove_recursive(btrfs_debugfs_root_dentry);
}

