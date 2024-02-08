#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mount.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/compat.h>
#include <linux/parser.h>
#include <linux/ctype.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/cleancache.h>
#include <linux/ratelimit.h>
#include <linux/crc32c.h>
#include <linux/btrfs.h>
#include "delayed-inode.h"
#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "props.h"
#include "xattr.h"
#include "volumes.h"
#include "export.h"
#include "compression.h"
#include "rcu-string.h"
#include "dev-replace.h"
#include "free-space-cache.h"
#include "backref.h"
#include "space-info.h"
#include "sysfs.h"
#include "tests/btrfs-tests.h"
#include "block-group.h"
#include "discard.h"

#include "qgroup.h"
#define CREATE_TRACE_POINTS
#include <trace/events/btrfs.h>

#ifdef MY_ABC_HERE
#include <linux/syno_acl.h>
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#include <linux/list_lru.h>
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#include "syno-rbd-meta.h"
#endif /* MY_ABC_HERE */

static const struct super_operations btrfs_super_ops;

/*
 * Types for mounting the default subvolume and a subvolume explicitly
 * requested by subvol=/path. That way the callchain is straightforward and we
 * don't have to play tricks with the mount options and recursive calls to
 * btrfs_mount.
 *
 * The new btrfs_root_fs_type also servers as a tag for the bdev_holder.
 */
static struct file_system_type btrfs_fs_type;
static struct file_system_type btrfs_root_fs_type;

static int btrfs_remount(struct super_block *sb, int *flags, char *data);

/*
 * Generally the error codes correspond to their respective errors, but there
 * are a few special cases.
 *
 * EUCLEAN: Any sort of corruption that we encounter.  The tree-checker for
 *          instance will return EUCLEAN if any of the blocks are corrupted in
 *          a way that is problematic.  We want to reserve EUCLEAN for these
 *          sort of corruptions.
 *
 * EROFS: If we check BTRFS_FS_STATE_ERROR and fail out with a return error, we
 *        need to use EROFS for this case.  We will have no idea of the
 *        original failure, that will have been reported at the time we tripped
 *        over the error.  Each subsequent error that doesn't have any context
 *        of the original error should use EROFS when handling BTRFS_FS_STATE_ERROR.
 */
const char * __attribute_const__ btrfs_decode_error(int errno)
{
	char *errstr = "unknown";

	switch (errno) {
	case -ENOENT:		/* -2 */
		errstr = "No such entry";
		break;
	case -EIO:		/* -5 */
		errstr = "IO failure";
		break;
	case -ENOMEM:		/* -12*/
		errstr = "Out of memory";
		break;
	case -EEXIST:		/* -17 */
		errstr = "Object already exists";
		break;
	case -ENOSPC:		/* -28 */
		errstr = "No space left";
		break;
	case -EROFS:		/* -30 */
		errstr = "Readonly filesystem";
		break;
	case -EOPNOTSUPP:	/* -95 */
		errstr = "Operation not supported";
		break;
	case -EUCLEAN:		/* -117 */
		errstr = "Filesystem corrupted";
		break;
	case -EDQUOT:		/* -122 */
		errstr = "Quota exceeded";
		break;
	}

	return errstr;
}

/*
 * __btrfs_handle_fs_error decodes expected errors from the caller and
 * invokes the appropriate error response.
 */
__cold
void __btrfs_handle_fs_error(struct btrfs_fs_info *fs_info, const char *function,
		       unsigned int line, int errno, const char *fmt, ...)
{
	struct super_block *sb = fs_info->sb;
#ifdef CONFIG_PRINTK
	const char *errstr;
#endif

	/*
	 * Special case: if the error is EROFS, and we're already
	 * under SB_RDONLY, then it is safe here.
	 */
	if (errno == -EROFS && sb_rdonly(sb))
  		return;

#ifdef CONFIG_PRINTK
	errstr = btrfs_decode_error(errno);
	if (fmt) {
		struct va_format vaf;
		va_list args;

		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;

		pr_crit("BTRFS: error (device %s) in %s:%d: errno=%d %s (%pV)\n",
			sb->s_id, function, line, errno, errstr, &vaf);
		va_end(args);
	} else {
		pr_crit("BTRFS: error (device %s) in %s:%d: errno=%d %s\n",
			sb->s_id, function, line, errno, errstr);
	}
#endif

	/*
	 * Today we only save the error info to memory.  Long term we'll
	 * also send it down to the disk
	 */
	set_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state);

	/* Don't go through full error handling during mount */
	if (!(sb->s_flags & SB_BORN))
		return;

	if (sb_rdonly(sb))
		return;

	btrfs_discard_stop(fs_info);

	/* btrfs handle error by forcing the filesystem readonly */
	sb->s_flags |= SB_RDONLY;
	btrfs_info(fs_info, "forced readonly");
	/*
	 * Note that a running device replace operation is not canceled here
	 * although there is no way to update the progress. It would add the
	 * risk of a deadlock, therefore the canceling is omitted. The only
	 * penalty is that some I/O remains active until the procedure
	 * completes. The next time when the filesystem is mounted writable
	 * again, the device replace operation continues.
	 */
}

#ifdef CONFIG_PRINTK
static const char * const logtypes[] = {
	"emergency",
	"alert",
	"critical",
	"error",
	"warning",
	"notice",
	"info",
	"debug",
};


/*
 * Use one ratelimit state per log level so that a flood of less important
 * messages doesn't cause more important ones to be dropped.
 */
static struct ratelimit_state printk_limits[] = {
	RATELIMIT_STATE_INIT(printk_limits[0], DEFAULT_RATELIMIT_INTERVAL, 100),
	RATELIMIT_STATE_INIT(printk_limits[1], DEFAULT_RATELIMIT_INTERVAL, 100),
	RATELIMIT_STATE_INIT(printk_limits[2], DEFAULT_RATELIMIT_INTERVAL, 100),
	RATELIMIT_STATE_INIT(printk_limits[3], DEFAULT_RATELIMIT_INTERVAL, 100),
	RATELIMIT_STATE_INIT(printk_limits[4], DEFAULT_RATELIMIT_INTERVAL, 100),
	RATELIMIT_STATE_INIT(printk_limits[5], DEFAULT_RATELIMIT_INTERVAL, 100),
	RATELIMIT_STATE_INIT(printk_limits[6], DEFAULT_RATELIMIT_INTERVAL, 100),
	RATELIMIT_STATE_INIT(printk_limits[7], DEFAULT_RATELIMIT_INTERVAL, 100),
};

void __cold btrfs_printk(const struct btrfs_fs_info *fs_info, const char *fmt, ...)
{
	char lvl[PRINTK_MAX_SINGLE_HEADER_LEN + 1] = "\0";
	struct va_format vaf;
	va_list args;
	int kern_level;
	const char *type = logtypes[4];
	struct ratelimit_state *ratelimit = &printk_limits[4];

	va_start(args, fmt);

	while ((kern_level = printk_get_level(fmt)) != 0) {
		size_t size = printk_skip_level(fmt) - fmt;

		if (kern_level >= '0' && kern_level <= '7') {
			memcpy(lvl, fmt,  size);
			lvl[size] = '\0';
			type = logtypes[kern_level - '0'];
			ratelimit = &printk_limits[kern_level - '0'];
		}
		fmt += size;
	}

	vaf.fmt = fmt;
	vaf.va = &args;

	if (__ratelimit(ratelimit))
		printk("%sBTRFS %s (device %s): %pV\n", lvl, type,
			fs_info ? fs_info->sb->s_id : "<unknown>", &vaf);

	va_end(args);
}
#endif

/*
 * We only mark the transaction aborted and then set the file system read-only.
 * This will prevent new transactions from starting or trying to join this
 * one.
 *
 * This means that error recovery at the call site is limited to freeing
 * any local memory allocations and passing the error code up without
 * further cleanup. The transaction should complete as it normally would
 * in the call path but will return -EIO.
 *
 * We'll complete the cleanup in btrfs_end_transaction and
 * btrfs_commit_transaction.
 */
__cold
void __btrfs_abort_transaction(struct btrfs_trans_handle *trans,
			       const char *function,
			       unsigned int line, int errno)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;

	WRITE_ONCE(trans->aborted, errno);
	/* Nothing used. The other threads that have joined this
	 * transaction may be able to continue. */
	if (!trans->dirty && list_empty(&trans->new_bgs)) {
		const char *errstr;

		errstr = btrfs_decode_error(errno);
		btrfs_warn(fs_info,
		           "%s:%d: Aborting unused transaction(%s).",
		           function, line, errstr);
		return;
	}
	WRITE_ONCE(trans->transaction->aborted, errno);
	/* Wake up anybody who may be waiting on this transaction */
	wake_up(&fs_info->transaction_wait);
	wake_up(&fs_info->transaction_blocked_wait);
	__btrfs_handle_fs_error(fs_info, function, line, errno, NULL);
}
/*
 * __btrfs_panic decodes unexpected, fatal errors from the caller,
 * issues an alert, and either panics or BUGs, depending on mount options.
 */
__cold
void __btrfs_panic(struct btrfs_fs_info *fs_info, const char *function,
		   unsigned int line, int errno, const char *fmt, ...)
{
	char *s_id = "<unknown>";
	const char *errstr;
	struct va_format vaf = { .fmt = fmt };
	va_list args;

	if (fs_info)
		s_id = fs_info->sb->s_id;

	va_start(args, fmt);
	vaf.va = &args;

	errstr = btrfs_decode_error(errno);
	if (fs_info && (btrfs_test_opt(fs_info, PANIC_ON_FATAL_ERROR)))
		panic(KERN_CRIT "BTRFS panic (device %s) in %s:%d: %pV (errno=%d %s)\n",
			s_id, function, line, &vaf, errno, errstr);

	btrfs_crit(fs_info, "panic in %s:%d: %pV (errno=%d %s)",
		   function, line, &vaf, errno, errstr);
	va_end(args);
	/* Caller calls BUG() */
}

static void btrfs_put_super(struct super_block *sb)
{
	close_ctree(btrfs_sb(sb));
}

enum {
	Opt_acl, Opt_noacl,
	Opt_clear_cache,
	Opt_commit_interval,
	Opt_compress,
	Opt_compress_force,
	Opt_compress_force_type,
	Opt_compress_type,
	Opt_degraded,
	Opt_device,
	Opt_fatal_errors,
	Opt_flushoncommit, Opt_noflushoncommit,
	Opt_inode_cache, Opt_noinode_cache,
	Opt_max_inline,
	Opt_barrier, Opt_nobarrier,
	Opt_datacow, Opt_nodatacow,
	Opt_datasum, Opt_nodatasum,
	Opt_defrag, Opt_nodefrag,
	Opt_discard, Opt_nodiscard,
	Opt_discard_mode,
	Opt_norecovery,
	Opt_ratio,
	Opt_rescan_uuid_tree,
	Opt_skip_balance,
	Opt_space_cache, Opt_no_space_cache,
	Opt_space_cache_version,
	Opt_ssd, Opt_nossd,
	Opt_ssd_spread, Opt_nossd_spread,
	Opt_subvol,
	Opt_subvol_empty,
	Opt_subvolid,
	Opt_thread_pool,
	Opt_treelog, Opt_notreelog,
	Opt_user_subvol_rm_allowed,

	/* Rescue options */
	Opt_rescue,
	Opt_usebackuproot,
	Opt_nologreplay,

	/* Deprecated options */
	Opt_recovery,

	/* Debugging options */
	Opt_check_integrity,
	Opt_check_integrity_including_extent_data,
	Opt_check_integrity_print_mask,
	Opt_enospc_debug, Opt_noenospc_debug,
#ifdef CONFIG_BTRFS_DEBUG
	Opt_fragment_data, Opt_fragment_metadata, Opt_fragment_all,
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
	Opt_ref_verify,
#endif
#ifdef MY_ABC_HERE
	Opt_reclaim_space, Opt_noreclaim_space,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_synoacl, Opt_nosynoacl,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_no_block_group_hint,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_block_group_cache_tree, Opt_clear_block_group_cache_tree,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_no_block_group,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_no_quota_tree,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_drop_log_tree,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_skip_cleaner, Opt_no_skip_cleaner,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	Opt_syno_allocator, Opt_clear_syno_allocator,
#endif /* MY_ABC_HERE */
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_clear_cache, "clear_cache"},
	{Opt_commit_interval, "commit=%u"},
	{Opt_compress, "compress"},
	{Opt_compress_type, "compress=%s"},
	{Opt_compress_force, "compress-force"},
	{Opt_compress_force_type, "compress-force=%s"},
	{Opt_degraded, "degraded"},
	{Opt_device, "device=%s"},
	{Opt_fatal_errors, "fatal_errors=%s"},
	{Opt_flushoncommit, "flushoncommit"},
	{Opt_noflushoncommit, "noflushoncommit"},
	{Opt_inode_cache, "inode_cache"},
	{Opt_noinode_cache, "noinode_cache"},
	{Opt_max_inline, "max_inline=%s"},
	{Opt_barrier, "barrier"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_datacow, "datacow"},
	{Opt_nodatacow, "nodatacow"},
	{Opt_datasum, "datasum"},
	{Opt_nodatasum, "nodatasum"},
	{Opt_defrag, "autodefrag"},
	{Opt_nodefrag, "noautodefrag"},
	{Opt_discard, "discard"},
	{Opt_discard_mode, "discard=%s"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_norecovery, "norecovery"},
	{Opt_ratio, "metadata_ratio=%u"},
	{Opt_rescan_uuid_tree, "rescan_uuid_tree"},
	{Opt_skip_balance, "skip_balance"},
	{Opt_space_cache, "space_cache"},
	{Opt_no_space_cache, "nospace_cache"},
	{Opt_space_cache_version, "space_cache=%s"},
	{Opt_ssd, "ssd"},
	{Opt_nossd, "nossd"},
	{Opt_ssd_spread, "ssd_spread"},
	{Opt_nossd_spread, "nossd_spread"},
	{Opt_subvol, "subvol=%s"},
	{Opt_subvol_empty, "subvol="},
	{Opt_subvolid, "subvolid=%s"},
	{Opt_thread_pool, "thread_pool=%u"},
	{Opt_treelog, "treelog"},
	{Opt_notreelog, "notreelog"},
	{Opt_user_subvol_rm_allowed, "user_subvol_rm_allowed"},

	/* Rescue options */
	{Opt_rescue, "rescue=%s"},
	/* Deprecated, with alias rescue=nologreplay */
	{Opt_nologreplay, "nologreplay"},
	/* Deprecated, with alias rescue=usebackuproot */
	{Opt_usebackuproot, "usebackuproot"},

	/* Deprecated options */
	{Opt_recovery, "recovery"},

	/* Debugging options */
	{Opt_check_integrity, "check_int"},
	{Opt_check_integrity_including_extent_data, "check_int_data"},
	{Opt_check_integrity_print_mask, "check_int_print_mask=%u"},
	{Opt_enospc_debug, "enospc_debug"},
	{Opt_noenospc_debug, "noenospc_debug"},
#ifdef CONFIG_BTRFS_DEBUG
	{Opt_fragment_data, "fragment=data"},
	{Opt_fragment_metadata, "fragment=metadata"},
	{Opt_fragment_all, "fragment=all"},
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
	{Opt_ref_verify, "ref_verify"},
#endif
#ifdef MY_ABC_HERE
	{Opt_reclaim_space, "auto_reclaim_space"},
	{Opt_noreclaim_space, "noauto_reclaim_space"},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_synoacl, SYNO_ACL_MNT_OPT},
	{Opt_nosynoacl, SYNO_ACL_NOT_MNT_OPT},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_no_block_group_hint, "no_block_group_hint"},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_block_group_cache_tree, "block_group_cache_tree"},
	{Opt_clear_block_group_cache_tree, "clear_block_group_cache_tree"},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_no_block_group, "no_block_group"},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_no_quota_tree, "no_quota_tree"},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_drop_log_tree, "drop_log_tree"},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_skip_cleaner, "skip_cleaner"},
	{Opt_no_skip_cleaner, "noskip_cleaner"},
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	{Opt_syno_allocator, "syno_allocator"},
	{Opt_clear_syno_allocator, "clear_syno_allocator"},
#endif /* MY_ABC_HERE */
	{Opt_err, NULL},
};

static const match_table_t rescue_tokens = {
	{Opt_usebackuproot, "usebackuproot"},
	{Opt_nologreplay, "nologreplay"},
	{Opt_err, NULL},
};

static int parse_rescue_options(struct btrfs_fs_info *info, const char *options)
{
	char *opts;
	char *orig;
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int ret = 0;

	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	orig = opts;

	while ((p = strsep(&opts, ":")) != NULL) {
		int token;

		if (!*p)
			continue;
		token = match_token(p, rescue_tokens, args);
		switch (token){
		case Opt_usebackuproot:
			btrfs_info(info,
				   "trying to use backup root at mount time");
			btrfs_set_opt(info->mount_opt, USEBACKUPROOT);
			break;
		case Opt_nologreplay:
			btrfs_set_and_info(info, NOLOGREPLAY,
					   "disabling log replay at mount time");
			break;
		case Opt_err:
			btrfs_info(info, "unrecognized rescue option '%s'", p);
			ret = -EINVAL;
			goto out;
		default:
			break;
		}

	}
out:
	kfree(orig);
	return ret;
}

/*
 * Regular mount options parser.  Everything that is needed only when
 * reading in a new superblock is parsed here.
 * XXX JDM: This needs to be cleaned up for remount.
 */
int btrfs_parse_options(struct btrfs_fs_info *info, char *options,
			unsigned long new_flags)
{
	substring_t args[MAX_OPT_ARGS];
	char *p, *num;
	int intarg;
	int ret = 0;
	char *compress_type;
	bool compress_force = false;
	enum btrfs_compression_type saved_compress_type;
	int saved_compress_level;
	bool saved_compress_force;
	int no_compress = 0;
#ifdef MY_ABC_HERE
	struct list_head *space_info_head = &info->space_info;
	struct btrfs_space_info *space_info_found;
#endif /* MY_ABC_HERE */

	if (btrfs_fs_compat_ro(info, FREE_SPACE_TREE))
		btrfs_set_opt(info->mount_opt, FREE_SPACE_TREE);
#ifdef MY_ABC_HERE
	else if (btrfs_fs_compat_ro(info, FREE_SPACE_TREE_VALID))
		btrfs_set_opt(info->mount_opt, FREE_SPACE_TREE);
#else /* MY_ABC_HERE */
	else if (btrfs_free_space_cache_v1_active(info)) {
		btrfs_set_opt(info->mount_opt, SPACE_CACHE);
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (btrfs_fs_compat(info, BLOCK_GROUP_CACHE_TREE) || btrfs_fs_compat(info, BLOCK_GROUP_CACHE_TREE_AUTO))
		btrfs_set_opt(info->mount_opt, BLOCK_GROUP_CACHE_TREE);
#endif /* MY_ABC_HERE */

	/*
	 * Even the options are empty, we still need to do extra check
	 * against new flags
	 */
	if (!options)
		goto check;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_degraded:
			btrfs_info(info, "allowing degraded mounts");
			btrfs_set_opt(info->mount_opt, DEGRADED);
			break;
		case Opt_subvol:
		case Opt_subvol_empty:
		case Opt_subvolid:
		case Opt_device:
			/*
			 * These are parsed by btrfs_parse_subvol_options or
			 * btrfs_parse_device_options and can be ignored here.
			 */
			break;
		case Opt_nodatasum:
			btrfs_set_and_info(info, NODATASUM,
					   "setting nodatasum");
			break;
		case Opt_datasum:
			if (btrfs_test_opt(info, NODATASUM)) {
				if (btrfs_test_opt(info, NODATACOW))
					btrfs_info(info,
						   "setting datasum, datacow enabled");
				else
					btrfs_info(info, "setting datasum");
			}
			btrfs_clear_opt(info->mount_opt, NODATACOW);
			btrfs_clear_opt(info->mount_opt, NODATASUM);
			break;
		case Opt_nodatacow:
			if (!btrfs_test_opt(info, NODATACOW)) {
				if (!btrfs_test_opt(info, COMPRESS) ||
				    !btrfs_test_opt(info, FORCE_COMPRESS)) {
					btrfs_info(info,
						   "setting nodatacow, compression disabled");
				} else {
					btrfs_info(info, "setting nodatacow");
				}
			}
			btrfs_clear_opt(info->mount_opt, COMPRESS);
			btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
			btrfs_set_opt(info->mount_opt, NODATACOW);
			btrfs_set_opt(info->mount_opt, NODATASUM);
			break;
		case Opt_datacow:
			btrfs_clear_and_info(info, NODATACOW,
					     "setting datacow");
			break;
		case Opt_compress_force:
		case Opt_compress_force_type:
			compress_force = true;
			fallthrough;
		case Opt_compress:
		case Opt_compress_type:
			saved_compress_type = btrfs_test_opt(info,
							     COMPRESS) ?
				info->compress_type : BTRFS_COMPRESS_NONE;
			saved_compress_force =
				btrfs_test_opt(info, FORCE_COMPRESS);
			saved_compress_level = info->compress_level;
			if (token == Opt_compress ||
			    token == Opt_compress_force ||
			    strncmp(args[0].from, "zlib", 4) == 0) {
				compress_type = "zlib";

				info->compress_type = BTRFS_COMPRESS_ZLIB;
				info->compress_level = BTRFS_ZLIB_DEFAULT_LEVEL;
				/*
				 * args[0] contains uninitialized data since
				 * for these tokens we don't expect any
				 * parameter.
				 */
				if (token != Opt_compress &&
				    token != Opt_compress_force)
					info->compress_level =
					  btrfs_compress_str2level(
							BTRFS_COMPRESS_ZLIB,
							args[0].from + 4);
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, NODATACOW);
				btrfs_clear_opt(info->mount_opt, NODATASUM);
				no_compress = 0;
			} else if (strncmp(args[0].from, "lzo", 3) == 0) {
				compress_type = "lzo";
				info->compress_type = BTRFS_COMPRESS_LZO;
				info->compress_level = 0;
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, NODATACOW);
				btrfs_clear_opt(info->mount_opt, NODATASUM);
				btrfs_set_fs_incompat(info, COMPRESS_LZO);
				no_compress = 0;
			} else if (strncmp(args[0].from, "zstd", 4) == 0) {
				compress_type = "zstd";
				info->compress_type = BTRFS_COMPRESS_ZSTD;
				info->compress_level =
					btrfs_compress_str2level(
							 BTRFS_COMPRESS_ZSTD,
							 args[0].from + 4);
				btrfs_set_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, NODATACOW);
				btrfs_clear_opt(info->mount_opt, NODATASUM);
				btrfs_set_fs_incompat(info, COMPRESS_ZSTD);
				no_compress = 0;
			} else if (strncmp(args[0].from, "no", 2) == 0) {
				compress_type = "no";
				info->compress_level = 0;
				info->compress_type = 0;
				btrfs_clear_opt(info->mount_opt, COMPRESS);
				btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
				compress_force = false;
				no_compress++;
			} else {
				ret = -EINVAL;
				goto out;
			}

			if (compress_force) {
				btrfs_set_opt(info->mount_opt, FORCE_COMPRESS);
			} else {
				/*
				 * If we remount from compress-force=xxx to
				 * compress=xxx, we need clear FORCE_COMPRESS
				 * flag, otherwise, there is no way for users
				 * to disable forcible compression separately.
				 */
				btrfs_clear_opt(info->mount_opt, FORCE_COMPRESS);
			}
			if (no_compress == 1) {
				btrfs_info(info, "use no compression");
			} else if ((info->compress_type != saved_compress_type) ||
				   (compress_force != saved_compress_force) ||
				   (info->compress_level != saved_compress_level)) {
				btrfs_info(info, "%s %s compression, level %d",
					   (compress_force) ? "force" : "use",
					   compress_type, info->compress_level);
			}
			compress_force = false;
			break;
		case Opt_ssd:
			btrfs_set_and_info(info, SSD,
					   "enabling ssd optimizations");
			btrfs_clear_opt(info->mount_opt, NOSSD);
			break;
		case Opt_ssd_spread:
			btrfs_set_and_info(info, SSD,
					   "enabling ssd optimizations");
			btrfs_set_and_info(info, SSD_SPREAD,
					   "using spread ssd allocation scheme");
			btrfs_clear_opt(info->mount_opt, NOSSD);
			break;
		case Opt_nossd:
			btrfs_set_opt(info->mount_opt, NOSSD);
			btrfs_clear_and_info(info, SSD,
					     "not using ssd optimizations");
			fallthrough;
		case Opt_nossd_spread:
			btrfs_clear_and_info(info, SSD_SPREAD,
					     "not using spread ssd allocation scheme");
			break;
		case Opt_barrier:
			btrfs_clear_and_info(info, NOBARRIER,
					     "turning on barriers");
			break;
		case Opt_nobarrier:
			btrfs_set_and_info(info, NOBARRIER,
					   "turning off barriers");
			break;
		case Opt_thread_pool:
			ret = match_int(&args[0], &intarg);
			if (ret) {
				goto out;
			} else if (intarg == 0) {
				ret = -EINVAL;
				goto out;
			}
			info->thread_pool_size = intarg;
			break;
		case Opt_max_inline:
			num = match_strdup(&args[0]);
			if (num) {
				info->max_inline = memparse(num, NULL);
				kfree(num);

				if (info->max_inline) {
					info->max_inline = min_t(u64,
						info->max_inline,
						info->sectorsize);
				}
				btrfs_info(info, "max_inline at %llu",
					   info->max_inline);
			} else {
				ret = -ENOMEM;
				goto out;
			}
			break;
		case Opt_acl:
#ifdef CONFIG_BTRFS_FS_POSIX_ACL
			info->sb->s_flags |= SB_POSIXACL;
			break;
#else
			btrfs_err(info, "support for ACL not compiled in!");
			ret = -EINVAL;
			goto out;
#endif
		case Opt_noacl:
			info->sb->s_flags &= ~SB_POSIXACL;
			break;
#ifdef MY_ABC_HERE
		case Opt_synoacl:
			btrfs_set_opt(info->mount_opt, SYNO_ACL);
			break;
		case Opt_nosynoacl:
			btrfs_clear_opt(info->mount_opt, SYNO_ACL);
			break;
#endif /* MY_ABC_HERE */
		case Opt_notreelog:
			btrfs_set_and_info(info, NOTREELOG,
					   "disabling tree log");
			break;
		case Opt_treelog:
			btrfs_clear_and_info(info, NOTREELOG,
					     "enabling tree log");
			break;
		case Opt_norecovery:
		case Opt_nologreplay:
			btrfs_warn(info,
		"'nologreplay' is deprecated, use 'rescue=nologreplay' instead");
			btrfs_set_and_info(info, NOLOGREPLAY,
					   "disabling log replay at mount time");
			break;
		case Opt_flushoncommit:
			btrfs_set_and_info(info, FLUSHONCOMMIT,
					   "turning on flush-on-commit");
			break;
		case Opt_noflushoncommit:
			btrfs_clear_and_info(info, FLUSHONCOMMIT,
					     "turning off flush-on-commit");
			break;
		case Opt_ratio:
			ret = match_int(&args[0], &intarg);
			if (ret)
				goto out;
			info->metadata_ratio = intarg;
			btrfs_info(info, "metadata ratio %u",
				   info->metadata_ratio);
			break;
		case Opt_discard:
		case Opt_discard_mode:
			if (token == Opt_discard ||
			    strcmp(args[0].from, "sync") == 0) {
				btrfs_clear_opt(info->mount_opt, DISCARD_ASYNC);
				btrfs_set_and_info(info, DISCARD_SYNC,
						   "turning on sync discard");
			} else if (strcmp(args[0].from, "async") == 0) {
				btrfs_clear_opt(info->mount_opt, DISCARD_SYNC);
				btrfs_set_and_info(info, DISCARD_ASYNC,
						   "turning on async discard");
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_nodiscard:
			btrfs_clear_and_info(info, DISCARD_SYNC,
					     "turning off discard");
			btrfs_clear_and_info(info, DISCARD_ASYNC,
					     "turning off async discard");
			break;
		case Opt_space_cache:
		case Opt_space_cache_version:
			if (token == Opt_space_cache ||
			    strcmp(args[0].from, "v1") == 0) {
				btrfs_clear_opt(info->mount_opt,
						FREE_SPACE_TREE);
				btrfs_set_and_info(info, SPACE_CACHE,
					   "enabling disk space caching");
			} else if (strcmp(args[0].from, "v2") == 0) {
				btrfs_clear_opt(info->mount_opt,
						SPACE_CACHE);
				btrfs_set_and_info(info, FREE_SPACE_TREE,
						   "enabling free space tree");
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_rescan_uuid_tree:
			btrfs_set_opt(info->mount_opt, RESCAN_UUID_TREE);
			break;
		case Opt_no_space_cache:
			if (btrfs_test_opt(info, SPACE_CACHE)) {
				btrfs_clear_and_info(info, SPACE_CACHE,
					     "disabling disk space caching");
			}
			if (btrfs_test_opt(info, FREE_SPACE_TREE)) {
				btrfs_clear_and_info(info, FREE_SPACE_TREE,
					     "disabling free space tree");
			}
			break;
		case Opt_inode_cache:
			btrfs_warn(info,
	"the 'inode_cache' option is deprecated and will have no effect from 5.11");
			btrfs_set_pending_and_info(info, INODE_MAP_CACHE,
					   "enabling inode map caching");
			break;
		case Opt_noinode_cache:
			btrfs_clear_pending_and_info(info, INODE_MAP_CACHE,
					     "disabling inode map caching");
			break;
		case Opt_clear_cache:
			btrfs_set_and_info(info, CLEAR_CACHE,
					   "force clearing of disk cache");
			break;
		case Opt_user_subvol_rm_allowed:
			btrfs_set_opt(info->mount_opt, USER_SUBVOL_RM_ALLOWED);
			break;
		case Opt_enospc_debug:
			btrfs_set_opt(info->mount_opt, ENOSPC_DEBUG);
			break;
		case Opt_noenospc_debug:
			btrfs_clear_opt(info->mount_opt, ENOSPC_DEBUG);
			break;
		case Opt_defrag:
			btrfs_set_and_info(info, AUTO_DEFRAG,
					   "enabling auto defrag");
			break;
		case Opt_nodefrag:
			btrfs_clear_and_info(info, AUTO_DEFRAG,
					     "disabling auto defrag");
			break;
		case Opt_recovery:
		case Opt_usebackuproot:
			btrfs_warn(info,
			"'%s' is deprecated, use 'rescue=usebackuproot' instead",
				   token == Opt_recovery ? "recovery" :
				   "usebackuproot");
			btrfs_info(info,
				   "trying to use backup root at mount time");
			btrfs_set_opt(info->mount_opt, USEBACKUPROOT);
			break;
		case Opt_skip_balance:
			btrfs_set_opt(info->mount_opt, SKIP_BALANCE);
			break;
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
		case Opt_check_integrity_including_extent_data:
			btrfs_info(info,
				   "enabling check integrity including extent data");
			btrfs_set_opt(info->mount_opt,
				      CHECK_INTEGRITY_INCLUDING_EXTENT_DATA);
			btrfs_set_opt(info->mount_opt, CHECK_INTEGRITY);
			break;
		case Opt_check_integrity:
			btrfs_info(info, "enabling check integrity");
			btrfs_set_opt(info->mount_opt, CHECK_INTEGRITY);
			break;
		case Opt_check_integrity_print_mask:
			ret = match_int(&args[0], &intarg);
			if (ret)
				goto out;
			info->check_integrity_print_mask = intarg;
			btrfs_info(info, "check_integrity_print_mask 0x%x",
				   info->check_integrity_print_mask);
			break;
#else
		case Opt_check_integrity_including_extent_data:
		case Opt_check_integrity:
		case Opt_check_integrity_print_mask:
			btrfs_err(info,
				  "support for check_integrity* not compiled in!");
			ret = -EINVAL;
			goto out;
#endif
		case Opt_fatal_errors:
			if (strcmp(args[0].from, "panic") == 0)
				btrfs_set_opt(info->mount_opt,
					      PANIC_ON_FATAL_ERROR);
			else if (strcmp(args[0].from, "bug") == 0)
				btrfs_clear_opt(info->mount_opt,
					      PANIC_ON_FATAL_ERROR);
			else {
				ret = -EINVAL;
				goto out;
			}
			break;
		case Opt_commit_interval:
			intarg = 0;
			ret = match_int(&args[0], &intarg);
			if (ret)
				goto out;
			if (intarg == 0) {
				btrfs_info(info,
					   "using default commit interval %us",
					   BTRFS_DEFAULT_COMMIT_INTERVAL);
				intarg = BTRFS_DEFAULT_COMMIT_INTERVAL;
			} else if (intarg > 300) {
				btrfs_warn(info, "excessive commit interval %d",
					   intarg);
			}
			info->commit_interval = intarg;
			break;
		case Opt_rescue:
			ret = parse_rescue_options(info, args[0].from);
			if (ret < 0)
				goto out;
			break;
#ifdef CONFIG_BTRFS_DEBUG
		case Opt_fragment_all:
			btrfs_info(info, "fragmenting all space");
			btrfs_set_opt(info->mount_opt, FRAGMENT_DATA);
			btrfs_set_opt(info->mount_opt, FRAGMENT_METADATA);
			break;
		case Opt_fragment_metadata:
			btrfs_info(info, "fragmenting metadata");
			btrfs_set_opt(info->mount_opt,
				      FRAGMENT_METADATA);
			break;
		case Opt_fragment_data:
			btrfs_info(info, "fragmenting data");
			btrfs_set_opt(info->mount_opt, FRAGMENT_DATA);
			break;
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
		case Opt_ref_verify:
			btrfs_info(info, "doing ref verification");
			btrfs_set_opt(info->mount_opt, REF_VERIFY);
			break;
#endif
#ifdef MY_ABC_HERE
		case Opt_reclaim_space:
			btrfs_set_and_info(info, AUTO_RECLAIM_SPACE,
					   "enabling auto syno reclaim space");
			break;
		case Opt_noreclaim_space:
			btrfs_clear_and_info(info, AUTO_RECLAIM_SPACE,
					   "disabling auto syno reclaim space");
			break;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		case Opt_no_block_group_hint:
			btrfs_clear_opt(info->mount_opt, BLOCK_GROUP_HINT_TREE);
			break;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		case Opt_block_group_cache_tree:
			btrfs_set_opt(info->mount_opt, BLOCK_GROUP_CACHE_TREE);
			break;
		case Opt_clear_block_group_cache_tree:
			btrfs_clear_opt(info->mount_opt, BLOCK_GROUP_CACHE_TREE);
			break;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		case Opt_no_block_group:
			btrfs_set_opt(info->mount_opt, NO_BLOCK_GROUP);
			break;
#endif /*MY_ABC_HERE*/
#ifdef MY_ABC_HERE
		case Opt_no_quota_tree:
			if (test_bit(BTRFS_FS_STATE_REMOUNTING, &info->fs_state)) {
				btrfs_info(info, "mount option '%s' cannot be used in remount", p);
				ret = -EINVAL;
				goto out;
			}
			btrfs_set_opt(info->mount_opt, NO_QUOTA_TREE);
			break;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		case Opt_drop_log_tree:
			btrfs_set_opt(info->mount_opt, DROP_LOG_TREE);
			break;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		case Opt_skip_cleaner:
			btrfs_set_opt(info->mount_opt, SKIP_CLEANER);
			break;
		case Opt_no_skip_cleaner:
			btrfs_clear_opt(info->mount_opt, SKIP_CLEANER);
			break;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		case Opt_syno_allocator:
			list_for_each_entry(space_info_found, space_info_head, list) {
				space_info_found->syno_allocator.force_cluster_disable = true;
			}
			btrfs_set_opt(info->mount_opt, SYNO_ALLOCATOR);
			break;
		case Opt_clear_syno_allocator:
			btrfs_clear_opt(info->mount_opt, SYNO_ALLOCATOR);
			break;
#endif /* MY_ABC_HERE */
		case Opt_err:
			btrfs_err(info, "unrecognized mount option '%s'", p);
			ret = -EINVAL;
			goto out;
		default:
			break;
		}
	}
check:
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, NO_BLOCK_GROUP) && !btrfs_test_opt(info, NOLOGREPLAY)) {
		btrfs_err(info,
			  "no_block_group must be used with nologreplay option");
		ret = -EINVAL;
	}
	if (btrfs_test_opt(info, NO_BLOCK_GROUP) && !(new_flags & SB_RDONLY)) {
		btrfs_err(info,
			  "no_block_group must be used with ro mount option");
		ret = -EINVAL;
	}
#endif /* MY_ABC_HERE */
	/*
	 * Extra check for current option against current flag
	 */
	if (btrfs_test_opt(info, NOLOGREPLAY) && !(new_flags & SB_RDONLY)) {
		btrfs_err(info,
			  "nologreplay must be used with ro mount option");
		ret = -EINVAL;
	}
out:
	if (btrfs_fs_compat_ro(info, FREE_SPACE_TREE) &&
	    !btrfs_test_opt(info, FREE_SPACE_TREE) &&
	    !btrfs_test_opt(info, CLEAR_CACHE)) {
		btrfs_err(info, "cannot disable free space tree");
		ret = -EINVAL;

	}
	if (!ret && btrfs_test_opt(info, SPACE_CACHE))
		btrfs_info(info, "disk space caching is enabled");
	if (!ret && btrfs_test_opt(info, FREE_SPACE_TREE))
		btrfs_info(info, "using free space tree");
#ifdef MY_ABC_HERE
	if (!ret && btrfs_test_opt(info, BLOCK_GROUP_CACHE_TREE))
		btrfs_info(info, "using block group cache tree");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (!ret && btrfs_test_opt(info, NO_QUOTA_TREE))
		btrfs_info(info, "skip quota trees");
#endif /* MY_ABC_HERE */
	return ret;
}

/*
 * Parse mount options that are required early in the mount process.
 *
 * All other options will be parsed on much later in the mount process and
 * only when we need to allocate a new super block.
 */
static int btrfs_parse_device_options(const char *options, fmode_t flags,
		void *holder)
{
	substring_t args[MAX_OPT_ARGS];
	char *device_name, *opts, *orig, *p;
	struct btrfs_device *device = NULL;
	int error = 0;

	lockdep_assert_held(&uuid_mutex);

	if (!options)
		return 0;

	/*
	 * strsep changes the string, duplicate it because btrfs_parse_options
	 * gets called later
	 */
	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	orig = opts;

	while ((p = strsep(&opts, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		if (token == Opt_device) {
			device_name = match_strdup(&args[0]);
			if (!device_name) {
				error = -ENOMEM;
				goto out;
			}
			device = btrfs_scan_one_device(device_name, flags,
					holder);
			kfree(device_name);
			if (IS_ERR(device)) {
				error = PTR_ERR(device);
				goto out;
			}
		}
	}

out:
	kfree(orig);
	return error;
}

/*
 * Parse mount options that are related to subvolume id
 *
 * The value is later passed to mount_subvol()
 */
static int btrfs_parse_subvol_options(const char *options, char **subvol_name,
		u64 *subvol_objectid)
{
	substring_t args[MAX_OPT_ARGS];
	char *opts, *orig, *p;
	int error = 0;
	u64 subvolid;

	if (!options)
		return 0;

	/*
	 * strsep changes the string, duplicate it because
	 * btrfs_parse_device_options gets called later
	 */
	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	orig = opts;

	while ((p = strsep(&opts, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_subvol:
			kfree(*subvol_name);
			*subvol_name = match_strdup(&args[0]);
			if (!*subvol_name) {
				error = -ENOMEM;
				goto out;
			}
			break;
		case Opt_subvolid:
			error = match_u64(&args[0], &subvolid);
			if (error)
				goto out;

			/* we want the original fs_tree */
			if (subvolid == 0)
				subvolid = BTRFS_FS_TREE_OBJECTID;

			*subvol_objectid = subvolid;
			break;
		default:
			break;
		}
	}

out:
	kfree(orig);
	return error;
}

char *btrfs_get_subvol_name_from_objectid(struct btrfs_fs_info *fs_info,
					  u64 subvol_objectid)
{
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_root *fs_root = NULL;
	struct btrfs_root_ref *root_ref;
	struct btrfs_inode_ref *inode_ref;
	struct btrfs_key key;
	struct btrfs_path *path = NULL;
	char *name = NULL, *ptr;
	u64 dirid;
	int len;
	int ret;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto err;
	}
	path->leave_spinning = 1;

	name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!name) {
		ret = -ENOMEM;
		goto err;
	}
	ptr = name + PATH_MAX - 1;
	ptr[0] = '\0';

	/*
	 * Walk up the subvolume trees in the tree of tree roots by root
	 * backrefs until we hit the top-level subvolume.
	 */
	while (subvol_objectid != BTRFS_FS_TREE_OBJECTID) {
		key.objectid = subvol_objectid;
		key.type = BTRFS_ROOT_BACKREF_KEY;
		key.offset = (u64)-1;

		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0) {
			goto err;
		} else if (ret > 0) {
			ret = btrfs_previous_item(root, path, subvol_objectid,
						  BTRFS_ROOT_BACKREF_KEY);
			if (ret < 0) {
				goto err;
			} else if (ret > 0) {
				ret = -ENOENT;
				goto err;
			}
		}

		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		subvol_objectid = key.offset;

		root_ref = btrfs_item_ptr(path->nodes[0], path->slots[0],
					  struct btrfs_root_ref);
		len = btrfs_root_ref_name_len(path->nodes[0], root_ref);
		ptr -= len + 1;
		if (ptr < name) {
			ret = -ENAMETOOLONG;
			goto err;
		}
		read_extent_buffer(path->nodes[0], ptr + 1,
				   (unsigned long)(root_ref + 1), len);
		ptr[0] = '/';
		dirid = btrfs_root_ref_dirid(path->nodes[0], root_ref);
		btrfs_release_path(path);

		fs_root = btrfs_get_fs_root(fs_info, subvol_objectid, true);
		if (IS_ERR(fs_root)) {
			ret = PTR_ERR(fs_root);
			fs_root = NULL;
			goto err;
		}

		/*
		 * Walk up the filesystem tree by inode refs until we hit the
		 * root directory.
		 */
		while (dirid != BTRFS_FIRST_FREE_OBJECTID) {
			key.objectid = dirid;
			key.type = BTRFS_INODE_REF_KEY;
			key.offset = (u64)-1;

			ret = btrfs_search_slot(NULL, fs_root, &key, path, 0, 0);
			if (ret < 0) {
				goto err;
			} else if (ret > 0) {
				ret = btrfs_previous_item(fs_root, path, dirid,
							  BTRFS_INODE_REF_KEY);
				if (ret < 0) {
					goto err;
				} else if (ret > 0) {
					ret = -ENOENT;
					goto err;
				}
			}

			btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
			dirid = key.offset;

			inode_ref = btrfs_item_ptr(path->nodes[0],
						   path->slots[0],
						   struct btrfs_inode_ref);
			len = btrfs_inode_ref_name_len(path->nodes[0],
						       inode_ref);
			ptr -= len + 1;
			if (ptr < name) {
				ret = -ENAMETOOLONG;
				goto err;
			}
			read_extent_buffer(path->nodes[0], ptr + 1,
					   (unsigned long)(inode_ref + 1), len);
			ptr[0] = '/';
			btrfs_release_path(path);
		}
		btrfs_put_root(fs_root);
		fs_root = NULL;
	}

	btrfs_free_path(path);
	if (ptr == name + PATH_MAX - 1) {
		name[0] = '/';
		name[1] = '\0';
	} else {
		memmove(name, ptr, name + PATH_MAX - ptr);
	}
	return name;

err:
	btrfs_put_root(fs_root);
	btrfs_free_path(path);
	kfree(name);
	return ERR_PTR(ret);
}

static int get_default_subvol_objectid(struct btrfs_fs_info *fs_info, u64 *objectid)
{
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_dir_item *di;
	struct btrfs_path *path;
	struct btrfs_key location;
	u64 dir_id;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->leave_spinning = 1;

	/*
	 * Find the "default" dir item which points to the root item that we
	 * will mount by default if we haven't been given a specific subvolume
	 * to mount.
	 */
	dir_id = btrfs_super_root_dir(fs_info->super_copy);
	di = btrfs_lookup_dir_item(NULL, root, path, dir_id, "default", 7, 0);
	if (IS_ERR(di)) {
		btrfs_free_path(path);
		return PTR_ERR(di);
	}
	if (!di) {
		/*
		 * Ok the default dir item isn't there.  This is weird since
		 * it's always been there, but don't freak out, just try and
		 * mount the top-level subvolume.
		 */
		btrfs_free_path(path);
		*objectid = BTRFS_FS_TREE_OBJECTID;
		return 0;
	}

	btrfs_dir_item_key_to_cpu(path->nodes[0], di, &location);
	btrfs_free_path(path);
	*objectid = location.objectid;
	return 0;
}

#ifdef MY_ABC_HERE
static void syno_fill_super_archive_version(struct super_block *sb, struct inode *inode)
{
	int err;
	struct syno_xattr_archive_version value;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);

	err = btrfs_getxattr(inode, XATTR_SYNO_ARCHIVE_VERSION_VOLUME,
			&value, sizeof(value));
	if (err == sizeof(value)) {
		sb->s_archive_version = le32_to_cpu(value.v_archive_version);
	} else {
		sb->s_archive_version = 0;
		if (err != -ENODATA)
			btrfs_warn(fs_info, "syno_fill_super_archive_version failed. err: %d", err);
	}
}
#endif /* MY_ABC_HERE */


static int btrfs_fill_super(struct super_block *sb,
			    struct btrfs_fs_devices *fs_devices,
			    void *data)
{
	struct inode *inode;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	int err;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = BTRFS_SUPER_MAGIC;
	sb->s_op = &btrfs_super_ops;
	sb->s_d_op = &btrfs_dentry_operations;
	sb->s_export_op = &btrfs_export_ops;
	sb->s_xattr = btrfs_xattr_handlers;
	sb->s_time_gran = 1;
#ifdef CONFIG_BTRFS_FS_POSIX_ACL
	sb->s_flags |= SB_POSIXACL;
#endif
	sb->s_flags |= SB_I_VERSION;
	sb->s_iflags |= SB_I_CGROUPWB;

	err = super_setup_bdi(sb);
	if (err) {
		btrfs_err(fs_info, "super_setup_bdi failed");
		return err;
	}

	err = open_ctree(sb, fs_devices, (char *)data);
	if (err) {
		btrfs_err(fs_info, "open_ctree failed");
		return err;
	}

	inode = btrfs_iget(sb, BTRFS_FIRST_FREE_OBJECTID, fs_info->fs_root);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto fail_close;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto fail_close;
	}

#ifdef MY_ABC_HERE
	syno_fill_super_archive_version(sb, inode);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (btrfs_raw_test_opt(fs_info->mount_opt, SYNO_ACL)) {
		if (syno_acl_module_get())
			sb->s_flags |= SB_SYNOACL;
		else
			btrfs_clear_opt(fs_info->mount_opt, SYNO_ACL);
	}
#endif /* MY_ABC_HERE */

	cleancache_init_fs(sb);
	sb->s_flags |= SB_ACTIVE;
	return 0;

fail_close:
	close_ctree(fs_info);
	return err;
}

int btrfs_sync_fs(struct super_block *sb, int wait)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_root *root = fs_info->tree_root;

	trace_btrfs_sync_fs(fs_info, wait);

	if (!wait) {
		filemap_flush(fs_info->btree_inode->i_mapping);
		return 0;
	}

	btrfs_wait_ordered_roots(fs_info, U64_MAX, 0, (u64)-1);

	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		/* no transaction, don't bother */
		if (PTR_ERR(trans) == -ENOENT) {
			/*
			 * Exit unless we have some pending changes
			 * that need to go through commit
			 */
			if (fs_info->pending_changes == 0)
				return 0;
			/*
			 * A non-blocking test if the fs is frozen. We must not
			 * start a new transaction here otherwise a deadlock
			 * happens. The pending operations are delayed to the
			 * next commit after thawing.
			 */
			if (sb_start_write_trylock(sb))
				sb_end_write(sb);
			else
				return 0;
			trans = btrfs_start_transaction(root, 0);
		}
		if (IS_ERR(trans))
			return PTR_ERR(trans);
	}
	return btrfs_commit_transaction(trans);
}

static int btrfs_show_options(struct seq_file *seq, struct dentry *dentry)
{
	struct btrfs_fs_info *info = btrfs_sb(dentry->d_sb);
	const char *compress_type;
	const char *subvol_name;

	if (btrfs_test_opt(info, DEGRADED))
		seq_puts(seq, ",degraded");
	if (btrfs_test_opt(info, NODATASUM))
		seq_puts(seq, ",nodatasum");
	if (btrfs_test_opt(info, NODATACOW))
		seq_puts(seq, ",nodatacow");
	if (btrfs_test_opt(info, NOBARRIER))
		seq_puts(seq, ",nobarrier");
	if (info->max_inline != BTRFS_DEFAULT_MAX_INLINE)
		seq_printf(seq, ",max_inline=%llu", info->max_inline);
	if (info->thread_pool_size !=  min_t(unsigned long,
					     num_online_cpus() + 2, 8))
		seq_printf(seq, ",thread_pool=%u", info->thread_pool_size);
	if (btrfs_test_opt(info, COMPRESS)) {
		compress_type = btrfs_compress_type2str(info->compress_type);
		if (btrfs_test_opt(info, FORCE_COMPRESS))
			seq_printf(seq, ",compress-force=%s", compress_type);
		else
			seq_printf(seq, ",compress=%s", compress_type);
		if (info->compress_level)
			seq_printf(seq, ":%d", info->compress_level);
	}
	if (btrfs_test_opt(info, NOSSD))
		seq_puts(seq, ",nossd");
	if (btrfs_test_opt(info, SSD_SPREAD))
		seq_puts(seq, ",ssd_spread");
	else if (btrfs_test_opt(info, SSD))
		seq_puts(seq, ",ssd");
	if (btrfs_test_opt(info, NOTREELOG))
		seq_puts(seq, ",notreelog");
	if (btrfs_test_opt(info, NOLOGREPLAY))
		seq_puts(seq, ",rescue=nologreplay");
	if (btrfs_test_opt(info, FLUSHONCOMMIT))
		seq_puts(seq, ",flushoncommit");
	if (btrfs_test_opt(info, DISCARD_SYNC))
		seq_puts(seq, ",discard");
	if (btrfs_test_opt(info, DISCARD_ASYNC))
		seq_puts(seq, ",discard=async");
	if (!(info->sb->s_flags & SB_POSIXACL))
		seq_puts(seq, ",noacl");
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, SYNO_ACL))
		seq_puts(seq, ","SYNO_ACL_MNT_OPT);
#endif /* MY_ABC_HERE */
	if (btrfs_free_space_cache_v1_active(info))
		seq_puts(seq, ",space_cache");
	else if (btrfs_fs_compat_ro(info, FREE_SPACE_TREE))
		seq_puts(seq, ",space_cache=v2");
	else
		seq_puts(seq, ",nospace_cache");
	if (btrfs_test_opt(info, RESCAN_UUID_TREE))
		seq_puts(seq, ",rescan_uuid_tree");
	if (btrfs_test_opt(info, CLEAR_CACHE))
		seq_puts(seq, ",clear_cache");
	if (btrfs_test_opt(info, USER_SUBVOL_RM_ALLOWED))
		seq_puts(seq, ",user_subvol_rm_allowed");
	if (btrfs_test_opt(info, ENOSPC_DEBUG))
		seq_puts(seq, ",enospc_debug");
	if (btrfs_test_opt(info, AUTO_DEFRAG))
		seq_puts(seq, ",autodefrag");
	if (btrfs_test_opt(info, INODE_MAP_CACHE))
		seq_puts(seq, ",inode_cache");
	if (btrfs_test_opt(info, SKIP_BALANCE))
		seq_puts(seq, ",skip_balance");
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	if (btrfs_test_opt(info, CHECK_INTEGRITY_INCLUDING_EXTENT_DATA))
		seq_puts(seq, ",check_int_data");
	else if (btrfs_test_opt(info, CHECK_INTEGRITY))
		seq_puts(seq, ",check_int");
	if (info->check_integrity_print_mask)
		seq_printf(seq, ",check_int_print_mask=%d",
				info->check_integrity_print_mask);
#endif
	if (info->metadata_ratio)
		seq_printf(seq, ",metadata_ratio=%u", info->metadata_ratio);
	if (btrfs_test_opt(info, PANIC_ON_FATAL_ERROR))
		seq_puts(seq, ",fatal_errors=panic");
	if (info->commit_interval != BTRFS_DEFAULT_COMMIT_INTERVAL)
		seq_printf(seq, ",commit=%u", info->commit_interval);
#ifdef CONFIG_BTRFS_DEBUG
	if (btrfs_test_opt(info, FRAGMENT_DATA))
		seq_puts(seq, ",fragment=data");
	if (btrfs_test_opt(info, FRAGMENT_METADATA))
		seq_puts(seq, ",fragment=metadata");
#endif
	if (btrfs_test_opt(info, REF_VERIFY))
		seq_puts(seq, ",ref_verify");
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, AUTO_RECLAIM_SPACE))
		seq_puts(seq, ",auto_reclaim_space");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (!btrfs_test_opt(info, BLOCK_GROUP_HINT_TREE))
		seq_puts(seq, ",no_block_group_hint");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, BLOCK_GROUP_CACHE_TREE))
		seq_puts(seq, ",block_group_cache_tree");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, NO_BLOCK_GROUP))
		seq_puts(seq, ",no_block_group");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, NO_QUOTA_TREE))
		seq_puts(seq, ",no_quota_tree");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, DROP_LOG_TREE))
		seq_puts(seq, ",drop_log_tree");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, SKIP_CLEANER))
		seq_puts(seq, ",skip_cleaner");
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	if (btrfs_test_opt(info, SYNO_ALLOCATOR))
		seq_puts(seq, ",syno_allocator");
#endif /* MY_ABC_HERE */
	seq_printf(seq, ",subvolid=%llu",
		  BTRFS_I(d_inode(dentry))->root->root_key.objectid);
	subvol_name = btrfs_get_subvol_name_from_objectid(info,
			BTRFS_I(d_inode(dentry))->root->root_key.objectid);
	if (!IS_ERR(subvol_name)) {
		seq_puts(seq, ",subvol=");
		seq_escape(seq, subvol_name, " \t\n\\");
		kfree(subvol_name);
	}
	return 0;
}

static int btrfs_test_super(struct super_block *s, void *data)
{
	struct btrfs_fs_info *p = data;
	struct btrfs_fs_info *fs_info = btrfs_sb(s);

	return fs_info->fs_devices == p->fs_devices;
}

static int btrfs_set_super(struct super_block *s, void *data)
{
	int err = set_anon_super(s, data);
	if (!err)
		s->s_fs_info = data;
	return err;
}

/*
 * subvolumes are identified by ino 256
 */
static inline int is_subvolume_inode(struct inode *inode)
{
	if (inode && inode->i_ino == BTRFS_FIRST_FREE_OBJECTID)
		return 1;
	return 0;
}

static struct dentry *mount_subvol(const char *subvol_name, u64 subvol_objectid,
				   struct vfsmount *mnt)
{
	struct dentry *root;
	int ret;

	if (!subvol_name) {
		if (!subvol_objectid) {
			ret = get_default_subvol_objectid(btrfs_sb(mnt->mnt_sb),
							  &subvol_objectid);
			if (ret) {
				root = ERR_PTR(ret);
				goto out;
			}
		}
		subvol_name = btrfs_get_subvol_name_from_objectid(
					btrfs_sb(mnt->mnt_sb), subvol_objectid);
		if (IS_ERR(subvol_name)) {
			root = ERR_CAST(subvol_name);
			subvol_name = NULL;
			goto out;
		}

	}

	root = mount_subtree(mnt, subvol_name);
	/* mount_subtree() drops our reference on the vfsmount. */
	mnt = NULL;

	if (!IS_ERR(root)) {
		struct super_block *s = root->d_sb;
		struct btrfs_fs_info *fs_info = btrfs_sb(s);
		struct inode *root_inode = d_inode(root);
		u64 root_objectid = BTRFS_I(root_inode)->root->root_key.objectid;

		ret = 0;
		if (!is_subvolume_inode(root_inode)) {
			btrfs_err(fs_info, "'%s' is not a valid subvolume",
			       subvol_name);
			ret = -EINVAL;
		}
		if (subvol_objectid && root_objectid != subvol_objectid) {
			/*
			 * This will also catch a race condition where a
			 * subvolume which was passed by ID is renamed and
			 * another subvolume is renamed over the old location.
			 */
			btrfs_err(fs_info,
				  "subvol '%s' does not match subvolid %llu",
				  subvol_name, subvol_objectid);
			ret = -EINVAL;
		}
		if (ret) {
			dput(root);
			root = ERR_PTR(ret);
			deactivate_locked_super(s);
		}
	}

out:
	mntput(mnt);
	kfree(subvol_name);
	return root;
}

/*
 * Find a superblock for the given device / mount point.
 *
 * Note: This is based on mount_bdev from fs/super.c with a few additions
 *       for multiple device setup.  Make sure to keep it in sync.
 */
static struct dentry *btrfs_mount_root(struct file_system_type *fs_type,
		int flags, const char *device_name, void *data)
{
	struct block_device *bdev = NULL;
	struct super_block *s;
	struct btrfs_device *device = NULL;
	struct btrfs_fs_devices *fs_devices = NULL;
	struct btrfs_fs_info *fs_info = NULL;
	void *new_sec_opts = NULL;
	fmode_t mode = FMODE_READ;
	int error = 0;

	if (!(flags & SB_RDONLY))
		mode |= FMODE_WRITE;

	if (data) {
		error = security_sb_eat_lsm_opts(data, &new_sec_opts);
		if (error)
			return ERR_PTR(error);
	}

	/*
	 * Setup a dummy root and fs_info for test/set super.  This is because
	 * we don't actually fill this stuff out until open_ctree, but we need
	 * then open_ctree will properly initialize the file system specific
	 * settings later.  btrfs_init_fs_info initializes the static elements
	 * of the fs_info (locks and such) to make cleanup easier if we find a
	 * superblock with our given fs_devices later on at sget() time.
	 */
	fs_info = kvzalloc(sizeof(struct btrfs_fs_info), GFP_KERNEL);
	if (!fs_info) {
		error = -ENOMEM;
		goto error_sec_opts;
	}
	btrfs_init_fs_info(fs_info);

	fs_info->super_copy = kzalloc(BTRFS_SUPER_INFO_SIZE, GFP_KERNEL);
	fs_info->super_for_commit = kzalloc(BTRFS_SUPER_INFO_SIZE, GFP_KERNEL);
	if (!fs_info->super_copy || !fs_info->super_for_commit) {
		error = -ENOMEM;
		goto error_fs_info;
	}

	mutex_lock(&uuid_mutex);
	error = btrfs_parse_device_options(data, mode, fs_type);
	if (error) {
		mutex_unlock(&uuid_mutex);
		goto error_fs_info;
	}

	device = btrfs_scan_one_device(device_name, mode, fs_type);
	if (IS_ERR(device)) {
		mutex_unlock(&uuid_mutex);
		error = PTR_ERR(device);
		goto error_fs_info;
	}

	fs_devices = device->fs_devices;
	fs_info->fs_devices = fs_devices;

	error = btrfs_open_devices(fs_devices, mode, fs_type);
	mutex_unlock(&uuid_mutex);
	if (error)
		goto error_fs_info;

	if (!(flags & SB_RDONLY) && fs_devices->rw_devices == 0) {
		error = -EACCES;
		goto error_close_devices;
	}

	bdev = fs_devices->latest_bdev;
	s = sget(fs_type, btrfs_test_super, btrfs_set_super, flags | SB_NOSEC,
		 fs_info);
	if (IS_ERR(s)) {
		error = PTR_ERR(s);
		goto error_close_devices;
	}

	if (s->s_root) {
		btrfs_close_devices(fs_devices);
		btrfs_free_fs_info(fs_info);
		if ((flags ^ s->s_flags) & SB_RDONLY)
			error = -EBUSY;
	} else {
		snprintf(s->s_id, sizeof(s->s_id), "%pg", bdev);
		btrfs_sb(s)->bdev_holder = fs_type;
		if (!strstr(crc32c_impl(), "generic"))
			set_bit(BTRFS_FS_CSUM_IMPL_FAST, &fs_info->flags);
		error = btrfs_fill_super(s, fs_devices, data);
	}
	if (!error)
		error = security_sb_set_mnt_opts(s, new_sec_opts, 0, NULL);
	security_free_mnt_opts(&new_sec_opts);
	if (error) {
		deactivate_locked_super(s);
		return ERR_PTR(error);
	}

	return dget(s->s_root);

error_close_devices:
	btrfs_close_devices(fs_devices);
error_fs_info:
	btrfs_free_fs_info(fs_info);
error_sec_opts:
	security_free_mnt_opts(&new_sec_opts);
	return ERR_PTR(error);
}

/*
 * Mount function which is called by VFS layer.
 *
 * In order to allow mounting a subvolume directly, btrfs uses mount_subtree()
 * which needs vfsmount* of device's root (/).  This means device's root has to
 * be mounted internally in any case.
 *
 * Operation flow:
 *   1. Parse subvol id related options for later use in mount_subvol().
 *
 *   2. Mount device's root (/) by calling vfs_kern_mount().
 *
 *      NOTE: vfs_kern_mount() is used by VFS to call btrfs_mount() in the
 *      first place. In order to avoid calling btrfs_mount() again, we use
 *      different file_system_type which is not registered to VFS by
 *      register_filesystem() (btrfs_root_fs_type). As a result,
 *      btrfs_mount_root() is called. The return value will be used by
 *      mount_subtree() in mount_subvol().
 *
 *   3. Call mount_subvol() to get the dentry of subvolume. Since there is
 *      "btrfs subvolume set-default", mount_subvol() is called always.
 */
static struct dentry *btrfs_mount(struct file_system_type *fs_type, int flags,
		const char *device_name, void *data)
{
	struct vfsmount *mnt_root;
	struct dentry *root;
	char *subvol_name = NULL;
	u64 subvol_objectid = 0;
	int error = 0;

	error = btrfs_parse_subvol_options(data, &subvol_name,
					&subvol_objectid);
	if (error) {
		kfree(subvol_name);
		return ERR_PTR(error);
	}

	/* mount device's root (/) */
	mnt_root = vfs_kern_mount(&btrfs_root_fs_type, flags, device_name, data);
	if (PTR_ERR_OR_ZERO(mnt_root) == -EBUSY) {
		if (flags & SB_RDONLY) {
			mnt_root = vfs_kern_mount(&btrfs_root_fs_type,
				flags & ~SB_RDONLY, device_name, data);
		} else {
			mnt_root = vfs_kern_mount(&btrfs_root_fs_type,
				flags | SB_RDONLY, device_name, data);
			if (IS_ERR(mnt_root)) {
				root = ERR_CAST(mnt_root);
				kfree(subvol_name);
				goto out;
			}

			down_write(&mnt_root->mnt_sb->s_umount);
			error = btrfs_remount(mnt_root->mnt_sb, &flags, NULL);
			up_write(&mnt_root->mnt_sb->s_umount);
			if (error < 0) {
				root = ERR_PTR(error);
				mntput(mnt_root);
				kfree(subvol_name);
				goto out;
			}
		}
	}
	if (IS_ERR(mnt_root)) {
		root = ERR_CAST(mnt_root);
		kfree(subvol_name);
		goto out;
	}

	/* mount_subvol() will free subvol_name and mnt_root */
	root = mount_subvol(subvol_name, subvol_objectid, mnt_root);

out:
	return root;
}

static void btrfs_resize_thread_pool(struct btrfs_fs_info *fs_info,
				     u32 new_pool_size, u32 old_pool_size)
{
	if (new_pool_size == old_pool_size)
		return;

	fs_info->thread_pool_size = new_pool_size;

	btrfs_info(fs_info, "resize thread pool %d -> %d",
	       old_pool_size, new_pool_size);

	btrfs_workqueue_set_max(fs_info->workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->delalloc_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->caching_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_meta_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_meta_write_workers,
				new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_write_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->endio_freespace_worker, new_pool_size);
	btrfs_workqueue_set_max(fs_info->delayed_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->readahead_workers, new_pool_size);
	btrfs_workqueue_set_max(fs_info->scrub_wr_completion_workers,
				new_pool_size);
#ifdef MY_ABC_HERE
	btrfs_workqueue_set_max(fs_info->syno_allocator.caching_workers, new_pool_size);
#endif /* MY_ABC_HERE */
}

static bool btrfs_defrag_running(struct btrfs_fs_info *fs_info,
				       unsigned long old_opts, bool rdonly)
{

	if (!btrfs_raw_test_opt(old_opts, AUTO_DEFRAG)
#ifdef MY_ABC_HERE
		&& !btrfs_raw_test_opt(old_opts, AUTO_RECLAIM_SPACE)
#endif /* MY_ABC_HERE */
		)
		return false;

	if (rdonly)
		return true;

	if (btrfs_raw_test_opt(old_opts, AUTO_DEFRAG) &&
	    !btrfs_raw_test_opt(fs_info->mount_opt, AUTO_DEFRAG))
		return true;

#ifdef MY_ABC_HERE
	if (btrfs_raw_test_opt(old_opts, AUTO_RECLAIM_SPACE) &&
	    !btrfs_raw_test_opt(fs_info->mount_opt, AUTO_RECLAIM_SPACE))
		return true;
#endif /* MY_ABC_HERE */

	return false;
}


static inline void btrfs_remount_begin(struct btrfs_fs_info *fs_info,
				       unsigned long old_opts, int flags)
{
	if (btrfs_defrag_running(fs_info, old_opts, !!(flags & SB_RDONLY))) {
		wait_event(fs_info->transaction_wait,
			   (atomic_read(&fs_info->defrag_running) == 0));
		if (flags & SB_RDONLY)
			sync_filesystem(fs_info->sb);
	}
}

static inline void btrfs_remount_cleanup(struct btrfs_fs_info *fs_info,
					 unsigned long old_opts)
{
	const bool cache_opt = btrfs_test_opt(fs_info, SPACE_CACHE);

	/*
	 * We need to cleanup all defragable inodes if the autodefragment is
	 * close or the filesystem is read only.
	 */
	if (btrfs_defrag_running(fs_info, old_opts, sb_rdonly(fs_info->sb)))
		btrfs_cleanup_defrag_inodes(fs_info);

	/* If we toggled discard async */
	if (!btrfs_raw_test_opt(old_opts, DISCARD_ASYNC) &&
	    btrfs_test_opt(fs_info, DISCARD_ASYNC))
		btrfs_discard_resume(fs_info);
	else if (btrfs_raw_test_opt(old_opts, DISCARD_ASYNC) &&
		 !btrfs_test_opt(fs_info, DISCARD_ASYNC))
		btrfs_discard_cleanup(fs_info);

	/* If we toggled space cache */
	if (cache_opt != btrfs_free_space_cache_v1_active(fs_info))
		btrfs_set_free_space_cache_v1_active(fs_info, cache_opt);
}

static int btrfs_remount(struct super_block *sb, int *flags, char *data)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	unsigned old_flags = sb->s_flags;
	unsigned long old_opts = fs_info->mount_opt;
	unsigned long old_compress_type = fs_info->compress_type;
	u64 old_max_inline = fs_info->max_inline;
	u32 old_thread_pool_size = fs_info->thread_pool_size;
	u32 old_metadata_ratio = fs_info->metadata_ratio;
	int ret;

	sync_filesystem(sb);
	set_bit(BTRFS_FS_STATE_REMOUNTING, &fs_info->fs_state);

	if (data) {
		void *new_sec_opts = NULL;

		ret = security_sb_eat_lsm_opts(data, &new_sec_opts);
		if (!ret)
			ret = security_sb_remount(sb, new_sec_opts);
		security_free_mnt_opts(&new_sec_opts);
		if (ret)
			goto restore;
	}

	ret = btrfs_parse_options(fs_info, data, *flags);
	if (ret)
		goto restore;

#ifdef MY_ABC_HERE
	if ((sb->s_flags & SB_SYNOACL) && !btrfs_test_opt(fs_info, SYNO_ACL)) {
		sb->s_flags = sb->s_flags & ~SB_SYNOACL;
		syno_acl_module_put();
	} else if((!(sb->s_flags & SB_SYNOACL)) && btrfs_test_opt(fs_info, SYNO_ACL)) {
		if (syno_acl_module_get())
			sb->s_flags |= SB_SYNOACL;
		else
			btrfs_clear_opt(fs_info->mount_opt, SYNO_ACL);
	}
#endif /* MY_ABC_HERE */

	btrfs_remount_begin(fs_info, old_opts, *flags);
	btrfs_resize_thread_pool(fs_info,
		fs_info->thread_pool_size, old_thread_pool_size);

	if ((bool)btrfs_test_opt(fs_info, FREE_SPACE_TREE) !=
	    (bool)btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE) &&
	    (!sb_rdonly(sb) || (*flags & SB_RDONLY))) {
		btrfs_warn(fs_info,
		"remount supports changing free space tree only from ro to rw");
		/* Make sure free space cache options match the state on disk */
		if (btrfs_fs_compat_ro(fs_info, FREE_SPACE_TREE)) {
			btrfs_set_opt(fs_info->mount_opt, FREE_SPACE_TREE);
			btrfs_clear_opt(fs_info->mount_opt, SPACE_CACHE);
		}
		if (btrfs_free_space_cache_v1_active(fs_info)) {
			btrfs_clear_opt(fs_info->mount_opt, FREE_SPACE_TREE);
			btrfs_set_opt(fs_info->mount_opt, SPACE_CACHE);
		}
	}

	if ((bool)(*flags & SB_RDONLY) == sb_rdonly(sb))
		goto out;

	if (*flags & SB_RDONLY) {
		/*
		 * this also happens on 'umount -rf' or on shutdown, when
		 * the filesystem is busy.
		 */
		cancel_work_sync(&fs_info->async_reclaim_work);
		cancel_work_sync(&fs_info->async_data_reclaim_work);
#ifdef MY_ABC_HERE
		cancel_work_sync(&fs_info->syno_async_metadata_reclaim_work);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		cancel_work_sync(&fs_info->syno_async_data_flush_work);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		cancel_work_sync(&fs_info->syno_async_metadata_flush_work);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		cancel_work_sync(&fs_info->async_metadata_cache_work);
#endif /* MY_ABC_HERE */

		btrfs_discard_cleanup(fs_info);

		/* wait for the uuid_scan task to finish */
		down(&fs_info->uuid_tree_rescan_sem);
		/* avoid complains from lockdep et al. */
		up(&fs_info->uuid_tree_rescan_sem);

		sb->s_flags |= SB_RDONLY;

		/*
		 * Setting SB_RDONLY will put the cleaner thread to
		 * sleep at the next loop if it's already active.
		 * If it's already asleep, we'll leave unused block
		 * groups on disk until we're mounted read-write again
		 * unless we clean them up here.
		 */
		btrfs_delete_unused_bgs(fs_info);

		btrfs_dev_replace_suspend_for_unmount(fs_info);
		btrfs_scrub_cancel(fs_info);
		btrfs_pause_balance(fs_info);
#ifdef MY_ABC_HERE
		cancel_work_sync(&fs_info->syno_usage_rescan_work);
		cancel_work_sync(&fs_info->syno_usage_fast_rescan_work);
		cancel_work_sync(&fs_info->syno_usage_full_rescan_work);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		cancel_work_sync(&fs_info->syno_allocator.bg_prefetch_work);
#endif /* MY_ABC_HERE */

		/*
		 * Pause the qgroup rescan worker if it is running. We don't want
		 * it to be still running after we are in RO mode, as after that,
		 * by the time we unmount, it might have left a transaction open,
		 * so we would leak the transaction and/or crash.
		 */
		btrfs_qgroup_wait_for_completion(fs_info, false);

		ret = btrfs_commit_super(fs_info);
		if (ret)
			goto restore;
	} else {
#ifdef MY_ABC_HERE
		if (btrfs_super_compat_ro_flags(fs_info->super_copy) & ~BTRFS_FEATURE_COMPAT_RO_SUPP) {
			btrfs_err(fs_info, "cannot mount read-write because of unsupported optional features");
			ret = -EINVAL;
			goto restore;
		}
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		if (btrfs_fs_compat_ro(fs_info, LOCKER) &&
		    !btrfs_syno_locker_feature_is_support()) {
			btrfs_err(fs_info, "cannot mount read-write because of no locker support");
			ret = -EINVAL;
			goto restore;
		}
#endif /* MY_ABC_HERE */
		if (test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state)) {
			btrfs_err(fs_info,
				"Remounting read-write after error is not allowed");
			ret = -EINVAL;
			goto restore;
		}
		if (fs_info->fs_devices->rw_devices == 0) {
			ret = -EACCES;
			goto restore;
		}

		if (!btrfs_check_rw_degradable(fs_info, NULL)) {
			btrfs_warn(fs_info,
		"too many missing devices, writable remount is not allowed");
			ret = -EACCES;
			goto restore;
		}

		if (btrfs_super_log_root(fs_info->super_copy) != 0) {
			btrfs_warn(fs_info,
		"mount required to replay tree-log, cannot remount read-write");
			ret = -EINVAL;
			goto restore;
		}

		/*
		 * NOTE: when remounting with a change that does writes, don't
		 * put it anywhere above this point, as we are not sure to be
		 * safe to write until we pass the above checks.
		 */
#ifdef MY_ABC_HERE
		ret = btrfs_start_pre_rw_mount(fs_info, NULL);
#else
		ret = btrfs_start_pre_rw_mount(fs_info);
#endif /* MY_ABC_HERE */
		if (ret)
			goto restore;

		sb->s_flags &= ~SB_RDONLY;

		set_bit(BTRFS_FS_OPEN, &fs_info->flags);

#ifdef MY_ABC_HERE
		btrfs_syno_usage_rescan_resume(fs_info);
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
		if (btrfs_test_opt(fs_info, SYNO_ALLOCATOR))
			queue_work(system_unbound_wq, &fs_info->syno_allocator.bg_prefetch_work);
#endif /* MY_ABC_HERE */
	}
out:
	/*
	 * We need to set SB_I_VERSION here otherwise it'll get cleared by VFS,
	 * since the absence of the flag means it can be toggled off by remount.
	 */
	*flags |= SB_I_VERSION;

	wake_up_process(fs_info->transaction_kthread);
	btrfs_remount_cleanup(fs_info, old_opts);
	btrfs_clear_oneshot_options(fs_info);
	clear_bit(BTRFS_FS_STATE_REMOUNTING, &fs_info->fs_state);

	return 0;

restore:
	/* We've hit an error - don't reset SB_RDONLY */
	if (sb_rdonly(sb))
		old_flags |= SB_RDONLY;
	sb->s_flags = old_flags;
	fs_info->mount_opt = old_opts;
	fs_info->compress_type = old_compress_type;
	fs_info->max_inline = old_max_inline;
	btrfs_resize_thread_pool(fs_info,
		old_thread_pool_size, fs_info->thread_pool_size);
	fs_info->metadata_ratio = old_metadata_ratio;
	btrfs_remount_cleanup(fs_info, old_opts);
	clear_bit(BTRFS_FS_STATE_REMOUNTING, &fs_info->fs_state);

	return ret;
}

/* Used to sort the devices by max_avail(descending sort) */
static inline int btrfs_cmp_device_free_bytes(const void *dev_info1,
				       const void *dev_info2)
{
	if (((struct btrfs_device_info *)dev_info1)->max_avail >
	    ((struct btrfs_device_info *)dev_info2)->max_avail)
		return -1;
	else if (((struct btrfs_device_info *)dev_info1)->max_avail <
		 ((struct btrfs_device_info *)dev_info2)->max_avail)
		return 1;
	else
	return 0;
}

/*
 * sort the devices by max_avail, in which max free extent size of each device
 * is stored.(Descending Sort)
 */
static inline void btrfs_descending_sort_devices(
					struct btrfs_device_info *devices,
					size_t nr_devices)
{
	sort(devices, nr_devices, sizeof(struct btrfs_device_info),
	     btrfs_cmp_device_free_bytes, NULL);
}

/*
 * The helper to calc the free space on the devices that can be used to store
 * file data.
 */
static inline int btrfs_calc_avail_data_space(struct btrfs_fs_info *fs_info,
					      u64 *free_bytes)
{
	struct btrfs_device_info *devices_info;
	struct btrfs_fs_devices *fs_devices = fs_info->fs_devices;
	struct btrfs_device *device;
	u64 type;
	u64 avail_space;
	u64 min_stripe_size;
	int num_stripes = 1;
	int i = 0, nr_devices;
	const struct btrfs_raid_attr *rattr;

	/*
	 * We aren't under the device list lock, so this is racy-ish, but good
	 * enough for our purposes.
	 */
	nr_devices = fs_info->fs_devices->open_devices;
	if (!nr_devices) {
		smp_mb();
		nr_devices = fs_info->fs_devices->open_devices;
		ASSERT(nr_devices);
		if (!nr_devices) {
			*free_bytes = 0;
			return 0;
		}
	}

	devices_info = kmalloc_array(nr_devices, sizeof(*devices_info),
			       GFP_KERNEL);
	if (!devices_info)
		return -ENOMEM;

	/* calc min stripe number for data space allocation */
	type = btrfs_data_alloc_profile(fs_info);
	rattr = &btrfs_raid_array[btrfs_bg_flags_to_raid_index(type)];

	if (type & BTRFS_BLOCK_GROUP_RAID0)
		num_stripes = nr_devices;
	else if (type & BTRFS_BLOCK_GROUP_RAID1)
		num_stripes = 2;
	else if (type & BTRFS_BLOCK_GROUP_RAID1C3)
		num_stripes = 3;
	else if (type & BTRFS_BLOCK_GROUP_RAID1C4)
		num_stripes = 4;
	else if (type & BTRFS_BLOCK_GROUP_RAID10)
		num_stripes = 4;

	/* Adjust for more than 1 stripe per device */
	min_stripe_size = rattr->dev_stripes * BTRFS_STRIPE_LEN;

	rcu_read_lock();
	list_for_each_entry_rcu(device, &fs_devices->devices, dev_list) {
		if (!test_bit(BTRFS_DEV_STATE_IN_FS_METADATA,
						&device->dev_state) ||
		    !device->bdev ||
		    test_bit(BTRFS_DEV_STATE_REPLACE_TGT, &device->dev_state))
			continue;

		if (i >= nr_devices)
			break;

		avail_space = device->total_bytes - device->bytes_used;

		/* align with stripe_len */
		avail_space = rounddown(avail_space, BTRFS_STRIPE_LEN);

		/*
		 * In order to avoid overwriting the superblock on the drive,
		 * btrfs starts at an offset of at least 1MB when doing chunk
		 * allocation.
		 *
		 * This ensures we have at least min_stripe_size free space
		 * after excluding 1MB.
		 */
		if (avail_space <= SZ_1M + min_stripe_size)
			continue;

		avail_space -= SZ_1M;

		devices_info[i].dev = device;
		devices_info[i].max_avail = avail_space;

		i++;
	}
	rcu_read_unlock();

	nr_devices = i;

	btrfs_descending_sort_devices(devices_info, nr_devices);

	i = nr_devices - 1;
	avail_space = 0;
	while (nr_devices >= rattr->devs_min) {
		num_stripes = min(num_stripes, nr_devices);

		if (devices_info[i].max_avail >= min_stripe_size) {
			int j;
			u64 alloc_size;

			avail_space += devices_info[i].max_avail * num_stripes;
			alloc_size = devices_info[i].max_avail;
			for (j = i + 1 - num_stripes; j <= i; j++)
				devices_info[j].max_avail -= alloc_size;
		}
		i--;
		nr_devices--;
	}

	kfree(devices_info);
	*free_bytes = avail_space;
	return 0;
}

/*
 * Calculate numbers for 'df', pessimistic in case of mixed raid profiles.
 *
 * If there's a redundant raid level at DATA block groups, use the respective
 * multiplier to scale the sizes.
 *
 * Unused device space usage is based on simulating the chunk allocator
 * algorithm that respects the device sizes and order of allocations.  This is
 * a close approximation of the actual use but there are other factors that may
 * change the result (like a new metadata chunk).
 *
 * If metadata is exhausted, f_bavail will be 0.
 */
static int btrfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(dentry->d_sb);
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	struct btrfs_space_info *found;
	u64 total_used = 0;
	u64 total_free_data = 0;
	u64 total_free_meta = 0;
	int bits = dentry->d_sb->s_blocksize_bits;
	__be32 *fsid = (__be32 *)fs_info->fs_devices->fsid;
	unsigned factor = 1;
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	int ret;
	u64 thresh = 0;
	int mixed = 0;
#ifdef MY_ABC_HERE
	u64 total_used_metadata = 0;
	u64 total_allocated_metadata = 0;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	struct btrfs_block_rsv *cleaner_rsv = &fs_info->cleaner_block_rsv;
#endif /* MY_ABC_HERE */

	list_for_each_entry(found, &fs_info->space_info, list) {
		if (found->flags & BTRFS_BLOCK_GROUP_DATA) {
			int i;

			total_free_data += found->disk_total - found->disk_used;
			total_free_data -=
				btrfs_account_ro_block_groups_free_space(found);

			for (i = 0; i < BTRFS_NR_RAID_TYPES; i++) {
				if (!list_empty(&found->block_groups[i]))
					factor = btrfs_bg_type_to_factor(
						btrfs_raid_array[i].bg_flag);
			}
		}

		/*
		 * Metadata in mixed block goup profiles are accounted in data
		 */
		if (!mixed && found->flags & BTRFS_BLOCK_GROUP_METADATA) {
			if (found->flags & BTRFS_BLOCK_GROUP_DATA)
				mixed = 1;
			else
				total_free_meta += found->disk_total -
					found->disk_used;
		}
#ifdef MY_ABC_HERE
		if (found->flags & BTRFS_BLOCK_GROUP_METADATA) {
			total_used_metadata += found->disk_used;
			total_allocated_metadata += found->disk_total;
		}
#endif /* MY_ABC_HERE */

		total_used += found->disk_used;
	}

	buf->f_blocks = div_u64(btrfs_super_total_bytes(disk_super), factor);
	buf->f_blocks >>= bits;
	buf->f_bfree = buf->f_blocks - (div_u64(total_used, factor) >> bits);

	/* Account global block reserve as used, it's in logical size already */
	spin_lock(&block_rsv->lock);
	/* Mixed block groups accounting is not byte-accurate, avoid overflow */
	if (buf->f_bfree >= block_rsv->size >> bits)
		buf->f_bfree -= block_rsv->size >> bits;
	else
		buf->f_bfree = 0;
	spin_unlock(&block_rsv->lock);
#ifdef MY_ABC_HERE
	spin_lock(&cleaner_rsv->lock);
	if (buf->f_bfree >= cleaner_rsv->size >> bits)
		buf->f_bfree -= cleaner_rsv->size >> bits;
	else
		buf->f_bfree = 0;
	spin_unlock(&cleaner_rsv->lock);
#endif /* MY_ABC_HERE */

	buf->f_bavail = div_u64(total_free_data, factor);
	ret = btrfs_calc_avail_data_space(fs_info, &total_free_data);
	if (ret)
		return ret;
	buf->f_bavail += div_u64(total_free_data, factor);
	buf->f_bavail = buf->f_bavail >> bits;

#ifdef MY_ABC_HERE
	if (fs_info->metadata_ratio) {
		u64 total_reserved_for_metadata;
		u64 extra_reserved_for_metadata;

		total_reserved_for_metadata = btrfs_syno_calc_reserve_for_metadata(fs_info);

		buf->f_blocks -= total_reserved_for_metadata >> bits;

		if (total_reserved_for_metadata > total_allocated_metadata) {
			extra_reserved_for_metadata = total_reserved_for_metadata - total_allocated_metadata;
			if (buf->f_bavail > (extra_reserved_for_metadata >> bits))
				buf->f_bavail -= extra_reserved_for_metadata >> bits;
			else
				buf->f_bavail = 0;
		}

		if (total_reserved_for_metadata > total_used_metadata) {
			extra_reserved_for_metadata = total_reserved_for_metadata - total_used_metadata;
			if (buf->f_bfree > (extra_reserved_for_metadata >> bits))
				buf->f_bfree -= extra_reserved_for_metadata >> bits;
			else
				buf->f_bfree = 0;
		}

		if (buf->f_bfree > buf->f_blocks)
			buf->f_bfree = buf->f_blocks;
		else if (buf->f_bavail > buf->f_bfree)
			buf->f_bavail = buf->f_bfree;
	}
#endif /* MY_ABC_HERE */

	/*
	 * We calculate the remaining metadata space minus global reserve. If
	 * this is (supposedly) smaller than zero, there's no space. But this
	 * does not hold in practice, the exhausted state happens where's still
	 * some positive delta. So we apply some guesswork and compare the
	 * delta to a 4M threshold.  (Practically observed delta was ~2M.)
	 *
	 * We probably cannot calculate the exact threshold value because this
	 * depends on the internal reservations requested by various
	 * operations, so some operations that consume a few metadata will
	 * succeed even if the Avail is zero. But this is better than the other
	 * way around.
	 */
	thresh = SZ_4M;

	/*
	 * We only want to claim there's no available space if we can no longer
	 * allocate chunks for our metadata profile and our global reserve will
	 * not fit in the free metadata space.  If we aren't ->full then we
	 * still can allocate chunks and thus are fine using the currently
	 * calculated f_bavail.
	 */
#ifdef MY_ABC_HERE
	if (!mixed && block_rsv->space_info && block_rsv->space_info->full &&
#else /* MY_ABC_HERE */
	if (!mixed && block_rsv->space_info->full &&
#endif /* MY_ABC_HERE */
	    total_free_meta - thresh < block_rsv->size)
		buf->f_bavail = 0;

	buf->f_type = BTRFS_SUPER_MAGIC;
	buf->f_bsize = dentry->d_sb->s_blocksize;
	buf->f_namelen = BTRFS_NAME_LEN;

	/* We treat it as constant endianness (it doesn't matter _which_)
	   because we want the fsid to come out the same whether mounted
	   on a big-endian or little-endian host */
	buf->f_fsid.val[0] = be32_to_cpu(fsid[0]) ^ be32_to_cpu(fsid[2]);
	buf->f_fsid.val[1] = be32_to_cpu(fsid[1]) ^ be32_to_cpu(fsid[3]);
	/* Mask in the root object ID too, to disambiguate subvols */
	buf->f_fsid.val[0] ^=
		BTRFS_I(d_inode(dentry))->root->root_key.objectid >> 32;
	buf->f_fsid.val[1] ^=
		BTRFS_I(d_inode(dentry))->root->root_key.objectid;

	return 0;
}

static void btrfs_kill_super(struct super_block *sb)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);

#ifdef MY_ABC_HERE
	if (SB_SYNOACL & sb->s_flags)
		syno_acl_module_put();
#endif /* MY_ABC_HERE */

	kill_anon_super(sb);
	btrfs_free_fs_info(fs_info);
}

static struct file_system_type btrfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "btrfs",
	.mount		= btrfs_mount,
	.kill_sb	= btrfs_kill_super,
	.fs_flags	= FS_REQUIRES_DEV | FS_BINARY_MOUNTDATA,
};

static struct file_system_type btrfs_root_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "btrfs",
	.mount		= btrfs_mount_root,
	.kill_sb	= btrfs_kill_super,
	.fs_flags	= FS_REQUIRES_DEV | FS_BINARY_MOUNTDATA,
};

#ifdef MY_ABC_HERE
struct file_system_type *__btrfs_root_fs_type = &btrfs_root_fs_type;
#endif /* MY_ABC_HERE */

MODULE_ALIAS_FS("btrfs");

static int btrfs_control_open(struct inode *inode, struct file *file)
{
	/*
	 * The control file's private_data is used to hold the
	 * transaction when it is started and is used to keep
	 * track of whether a transaction is already in progress.
	 */
	file->private_data = NULL;
	return 0;
}

/*
 * Used by /dev/btrfs-control for devices ioctls.
 */
static long btrfs_control_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct btrfs_ioctl_vol_args *vol;
	struct btrfs_device *device = NULL;
	int ret = -ENOTTY;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	vol = memdup_user((void __user *)arg, sizeof(*vol));
	if (IS_ERR(vol))
		return PTR_ERR(vol);
	vol->name[BTRFS_PATH_NAME_MAX] = '\0';

	switch (cmd) {
	case BTRFS_IOC_SCAN_DEV:
		mutex_lock(&uuid_mutex);
		device = btrfs_scan_one_device(vol->name, FMODE_READ,
					       &btrfs_root_fs_type);
		ret = PTR_ERR_OR_ZERO(device);
		mutex_unlock(&uuid_mutex);
		break;
	case BTRFS_IOC_FORGET_DEV:
		ret = btrfs_forget_devices(vol->name);
		break;
	case BTRFS_IOC_DEVICES_READY:
		mutex_lock(&uuid_mutex);
		device = btrfs_scan_one_device(vol->name, FMODE_READ,
					       &btrfs_root_fs_type);
		if (IS_ERR(device)) {
			mutex_unlock(&uuid_mutex);
			ret = PTR_ERR(device);
			break;
		}
		ret = !(device->fs_devices->num_devices ==
			device->fs_devices->total_devices);
		mutex_unlock(&uuid_mutex);
		break;
	case BTRFS_IOC_GET_SUPPORTED_FEATURES:
		ret = btrfs_ioctl_get_supported_features((void __user*)arg);
		break;
	}

	kfree(vol);
	return ret;
}

static int btrfs_freeze(struct super_block *sb)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_root *root = fs_info->tree_root;

	set_bit(BTRFS_FS_FROZEN, &fs_info->flags);
	/*
	 * We don't need a barrier here, we'll wait for any transaction that
	 * could be in progress on other threads (and do delayed iputs that
	 * we want to avoid on a frozen filesystem), or do the commit
	 * ourselves.
	 */
	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		/* no transaction, don't bother */
		if (PTR_ERR(trans) == -ENOENT)
			return 0;
		return PTR_ERR(trans);
	}
	return btrfs_commit_transaction(trans);
}

static int btrfs_unfreeze(struct super_block *sb)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);

	clear_bit(BTRFS_FS_FROZEN, &fs_info->flags);
	return 0;
}

static int btrfs_show_devname(struct seq_file *m, struct dentry *root)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(root->d_sb);
	struct btrfs_device *dev, *first_dev = NULL;

	/*
	 * Lightweight locking of the devices. We should not need
	 * device_list_mutex here as we only read the device data and the list
	 * is protected by RCU.  Even if a device is deleted during the list
	 * traversals, we'll get valid data, the freeing callback will wait at
	 * least until the rcu_read_unlock.
	 */
	rcu_read_lock();
	list_for_each_entry_rcu(dev, &fs_info->fs_devices->devices, dev_list) {
		if (test_bit(BTRFS_DEV_STATE_MISSING, &dev->dev_state))
			continue;
		if (!dev->name)
			continue;
		if (!first_dev || dev->devid < first_dev->devid)
			first_dev = dev;
	}

	if (first_dev)
		seq_escape(m, rcu_str_deref(first_dev->name), " \t\n\\");
	else
		WARN_ON(1);
	rcu_read_unlock();
	return 0;
}

#ifdef MY_ABC_HERE
static int btrfs_syno_get_sb_archive_version(struct super_block *sb, u32 *version)
{
        *version = sb->s_archive_version;
        return 0;
}

static int btrfs_syno_set_sb_archive_version(struct super_block *sb, u32 archive_ver)
{
	int ret;
	struct syno_xattr_archive_version value;

	value.v_magic = cpu_to_le16(0x2552);
	value.v_struct_version = cpu_to_le16(1);
	value.v_archive_version = cpu_to_le32(archive_ver);

	ret = btrfs_setxattr_trans(sb->s_root->d_inode,
			XATTR_SYNO_ARCHIVE_VERSION_VOLUME,
			&value, sizeof(value), 0);
	if (!ret)
		sb->s_archive_version = archive_ver;

	return ret;
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static long btrfs_nr_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
	return (long)atomic_read(&btrfs_sb(sb)->nr_extent_maps);
}

enum btrfs_free_extent_map_type {
	LOOP_FREE_EXTENT_NOT_MODIFIED,
	LOOP_FREE_EXTENT_MODIFIED,
	LOOP_FREE_EXTENT_END,
};

static int btrfs_drop_extent_maps(struct inode *inode, unsigned long nr_to_drop)
{
	struct extent_map *em, *next_em = NULL;
	struct extent_map_tree *em_tree = &BTRFS_I(inode)->extent_tree;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	unsigned long dropped = 0;
	u64 test_gen;
	struct list_head *head = NULL;
	enum btrfs_free_extent_map_type stage = LOOP_FREE_EXTENT_NOT_MODIFIED;

	while (nr_to_drop) {
		write_lock(&em_tree->lock);
		test_gen = root->fs_info->last_trans_committed;

		if (stage == LOOP_FREE_EXTENT_NOT_MODIFIED) {
			head = &em_tree->not_modified_extents;
		} else if (stage == LOOP_FREE_EXTENT_MODIFIED) {
			head = &em_tree->syno_modified_extents;
		} else {
			write_unlock(&em_tree->lock);
			ASSERT(0);
			break;
		}

		if (next_em != NULL && !extent_map_in_tree(next_em)) {
			free_extent_map(next_em);
			next_em = NULL;
		}

		if (next_em == NULL) {
			if (list_empty(head)) {
				write_unlock(&em_tree->lock);
				goto next;
			}
			em = list_entry(head->next, struct extent_map, free_list);
			refcount_inc(&em->refs);
		} else {
			em = next_em;
		}
		if (list_is_last(&em->free_list, &em_tree->not_modified_extents) ||
		    list_is_last(&em->free_list, &em_tree->syno_modified_extents) ||
		    list_empty(&em->free_list)) {
			next_em = NULL;
		} else {
			next_em = list_entry(em->free_list.next, struct extent_map, free_list);
			refcount_inc(&next_em->refs);
		}

		if (test_bit(EXTENT_FLAG_PINNED, &em->flags)) {
			free_extent_map(em);
			write_unlock(&em_tree->lock);
			goto next;
		}
		if (!list_empty(&em->list) && em->generation > test_gen) {
			free_extent_map(em);
			write_unlock(&em_tree->lock);
			if (stage == LOOP_FREE_EXTENT_MODIFIED)
				break;
			else
				goto next;
		}
		remove_extent_mapping(em_tree, em);
		write_unlock(&em_tree->lock);
		/* once for us */
		free_extent_map(em);
		/* once for the tree*/
		free_extent_map(em);
		dropped++;
		nr_to_drop--;
next:
		if (next_em == NULL)
			stage++;
		if (stage >= LOOP_FREE_EXTENT_END)
			break;
		cond_resched();
	}
	if (next_em) {
		/* once for us */
		free_extent_map(next_em);
	}
	return dropped;
}

static bool list_lru_item_empty(struct list_lru *lru, struct list_head *item)
{
	int nid = page_to_nid(virt_to_page(item));
	struct list_lru_node *nlru = &lru->node[nid];

	spin_lock(&nlru->lock);
	if (list_empty(item)) {
		spin_unlock(&nlru->lock);
		return true;
	}
	spin_unlock(&nlru->lock);
	return false;
}

static long btrfs_free_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
	struct inode *inode;
	struct inode *toput_inode = NULL;
	struct btrfs_inode *binode;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	unsigned long nr_to_drop = sc->nr_to_scan;

	spin_lock(&fs_info->extent_map_inode_list_lock);
	list_for_each_entry(binode, &fs_info->extent_map_inode_list,
			    free_extent_map_inode) {
		inode = &binode->vfs_inode;
		if (!list_lru_item_empty(&fs_info->sb->s_inode_lru,
					 &inode->i_lru))
			continue;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);

		atomic_inc(&binode->free_extent_map_counts);
		if (toput_inode &&
		    (atomic_read(&BTRFS_I(toput_inode)->free_extent_map_counts) == 0) &&
		    (atomic_read(&(BTRFS_I(toput_inode)->extent_tree.nr_extent_maps)) == 0))
			list_del_init(&BTRFS_I(toput_inode)->free_extent_map_inode);

		spin_unlock(&fs_info->extent_map_inode_list_lock);

		nr_to_drop -= btrfs_drop_extent_maps(inode, nr_to_drop);

		iput(toput_inode);
		toput_inode = inode;
		cond_resched();

		spin_lock(&fs_info->extent_map_inode_list_lock);
		WARN_ON(atomic_read(&binode->free_extent_map_counts) == 0);
		atomic_dec(&binode->free_extent_map_counts);
		if (!nr_to_drop)
			break;
	}
	if (toput_inode &&
	    (atomic_read(&BTRFS_I(toput_inode)->free_extent_map_counts) == 0) &&
	    (atomic_read(&(BTRFS_I(toput_inode)->extent_tree.nr_extent_maps)) == 0))
		list_del_init(&BTRFS_I(toput_inode)->free_extent_map_inode);

	spin_unlock(&fs_info->extent_map_inode_list_lock);
	iput(toput_inode);
	return (long)(sc->nr_to_scan - nr_to_drop);
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int btrfs_syno_rbd_set_first_mapping_table_offset(struct super_block *sb,
							 u64 offset)
{
	struct btrfs_root *root = BTRFS_I(d_inode(sb->s_root))->root;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_trans_handle *trans;

	trans = btrfs_start_transaction(root, 0);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	fs_info->syno_rbd.first_mapping_table_offset = offset;

	return btrfs_commit_transaction(trans);
}
#endif /* MY_ABC_HERE */

static const struct super_operations btrfs_super_ops = {
#ifdef MY_ABC_HERE
	.syno_get_sb_archive_version = btrfs_syno_get_sb_archive_version,
	.syno_set_sb_archive_version = btrfs_syno_set_sb_archive_version,
#endif /* MY_ABC_HERE */
	.drop_inode	= btrfs_drop_inode,
	.evict_inode	= btrfs_evict_inode,
	.put_super	= btrfs_put_super,
	.sync_fs	= btrfs_sync_fs,
	.show_options	= btrfs_show_options,
	.show_devname	= btrfs_show_devname,
	.alloc_inode	= btrfs_alloc_inode,
	.destroy_inode	= btrfs_destroy_inode,
	.free_inode	= btrfs_free_inode,
	.statfs		= btrfs_statfs,
	.remount_fs	= btrfs_remount,
	.freeze_fs	= btrfs_freeze,
	.unfreeze_fs	= btrfs_unfreeze,
#ifdef MY_ABC_HERE
	.nr_cached_objects = btrfs_nr_cached_objects,
	.free_cached_objects = btrfs_free_cached_objects,
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	.syno_rbd_set_first_mapping_table_offset = btrfs_syno_rbd_set_first_mapping_table_offset,
	.syno_rbd_meta_file_cleanup_all	= btrfs_delete_all_rbd_meta_file_records,
#endif /* MY_ABC_HERE */
};

static const struct file_operations btrfs_ctl_fops = {
	.open = btrfs_control_open,
	.unlocked_ioctl	 = btrfs_control_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.owner	 = THIS_MODULE,
	.llseek = noop_llseek,
};

static struct miscdevice btrfs_misc = {
	.minor		= BTRFS_MINOR,
	.name		= "btrfs-control",
	.fops		= &btrfs_ctl_fops
};

MODULE_ALIAS_MISCDEV(BTRFS_MINOR);
MODULE_ALIAS("devname:btrfs-control");

static int __init btrfs_interface_init(void)
{
	return misc_register(&btrfs_misc);
}

static __cold void btrfs_interface_exit(void)
{
	misc_deregister(&btrfs_misc);
}

static void __init btrfs_print_mod_info(void)
{
	static const char options[] = ""
#ifdef CONFIG_BTRFS_DEBUG
			", debug=on"
#endif
#ifdef CONFIG_BTRFS_ASSERT
			", assert=on"
#endif
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
			", integrity-checker=on"
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
			", ref-verify=on"
#endif
			;
	pr_info("Btrfs loaded, crc32c=%s%s\n", crc32c_impl(), options);
}

#ifdef MY_ABC_HERE
extern int (*funcSYNOSendErrorFsBtrfsEvent)(const u8*);

void SynoAutoErrorFsBtrfsReport(const u8* fsid)
{
	if (NULL == funcSYNOSendErrorFsBtrfsEvent) {
		printk(KERN_ERR "BTRFS-fs error: "
		       "Can't reference to function 'funcSYNOSendErrorFsBtrfsEvent'\n");
		return;
	}

	funcSYNOSendErrorFsBtrfsEvent(fsid);
}

extern int (*funcSYNOMetaCorruptedEvent)(const u8*, u64);

void SynoBtrfsMetaCorruptedReport(const u8* fsid, u64 start)
{
	if (NULL == funcSYNOMetaCorruptedEvent) {
		printk(KERN_ERR "BTRFS-fs error: "
				"Can't reference to function 'funcSYNOMetaCorruptedEvent'\n");
		return;
	}

	funcSYNOMetaCorruptedEvent(fsid, start);
}

#endif /* MY_ABC_HERE */


static int __init init_btrfs_fs(void)
{
	int err;

	btrfs_props_init();

	err = btrfs_init_sysfs();
	if (err)
		return err;

	btrfs_init_compress();

	err = btrfs_init_cachep();
	if (err)
		goto free_compress;

	err = extent_io_init();
	if (err)
		goto free_cachep;

	err = extent_state_cache_init();
	if (err)
		goto free_extent_io;

	err = extent_map_init();
	if (err)
		goto free_extent_state_cache;

	err = ordered_data_init();
	if (err)
		goto free_extent_map;

	err = btrfs_delayed_inode_init();
	if (err)
		goto free_ordered_data;

	err = btrfs_auto_defrag_init();
	if (err)
		goto free_delayed_inode;

	err = btrfs_delayed_ref_init();
	if (err)
		goto free_auto_defrag;

	err = btrfs_prelim_ref_init();
	if (err)
		goto free_delayed_ref;

	err = btrfs_end_io_wq_init();
	if (err)
		goto free_prelim_ref;

	err = btrfs_interface_init();
	if (err)
		goto free_end_io_wq;

#ifdef MY_ABC_HERE
	err = qgroup_netlink_init();
	if (err)
		goto free_btrfs_interface;
#endif /* MY_ABC_HERE */

	btrfs_init_lockdep();

	btrfs_print_mod_info();

	err = btrfs_run_sanity_tests();
	if (err)
		goto unregister_ioctl;

	err = register_filesystem(&btrfs_fs_type);
	if (err)
		goto unregister_ioctl;

	return 0;

unregister_ioctl:
#ifdef MY_ABC_HERE
	qgroup_netlink_exit();
free_btrfs_interface:
#endif /* MY_ABC_HERE */
	btrfs_interface_exit();
free_end_io_wq:
	btrfs_end_io_wq_exit();
free_prelim_ref:
	btrfs_prelim_ref_exit();
free_delayed_ref:
	btrfs_delayed_ref_exit();
free_auto_defrag:
	btrfs_auto_defrag_exit();
free_delayed_inode:
	btrfs_delayed_inode_exit();
free_ordered_data:
	ordered_data_exit();
free_extent_map:
	extent_map_exit();
free_extent_state_cache:
	extent_state_cache_exit();
free_extent_io:
	extent_io_exit();
free_cachep:
	btrfs_destroy_cachep();
free_compress:
	btrfs_exit_compress();
	btrfs_exit_sysfs();

	return err;
}

static void __exit exit_btrfs_fs(void)
{
#ifdef MY_ABC_HERE
	qgroup_netlink_exit();
#endif /* MY_ABC_HERE */
	btrfs_destroy_cachep();
	btrfs_delayed_ref_exit();
	btrfs_auto_defrag_exit();
	btrfs_delayed_inode_exit();
	btrfs_prelim_ref_exit();
	ordered_data_exit();
	extent_map_exit();
	extent_state_cache_exit();
	extent_io_exit();
	btrfs_interface_exit();
	btrfs_end_io_wq_exit();
	unregister_filesystem(&btrfs_fs_type);
	btrfs_exit_sysfs();
	btrfs_cleanup_fs_uuids();
	btrfs_exit_compress();
}

late_initcall(init_btrfs_fs);
module_exit(exit_btrfs_fs)

MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: crc32c");
MODULE_SOFTDEP("pre: xxhash64");
MODULE_SOFTDEP("pre: sha256");
MODULE_SOFTDEP("pre: blake2b-256");
