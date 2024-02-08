#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/time.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include "ext4.h"
#include "ext4_jbd2.h"
#include "mballoc.h"

void ext4_get_group_no_and_offset(struct super_block *sb, ext4_fsblk_t blocknr,
		ext4_group_t *blockgrpp, ext4_grpblk_t *offsetp)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	ext4_grpblk_t offset;

	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
	offset = do_div(blocknr, EXT4_BLOCKS_PER_GROUP(sb));
	if (offsetp)
		*offsetp = offset;
	if (blockgrpp)
		*blockgrpp = blocknr;

}

static int ext4_block_in_group(struct super_block *sb, ext4_fsblk_t block,
			ext4_group_t block_group)
{
	ext4_group_t actual_group;
	ext4_get_group_no_and_offset(sb, block, &actual_group, NULL);
	if (actual_group == block_group)
		return 1;
	return 0;
}

static int ext4_group_used_meta_blocks(struct super_block *sb,
				       ext4_group_t block_group,
				       struct ext4_group_desc *gdp)
{
	ext4_fsblk_t tmp;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	 
	int used_blocks = sbi->s_itb_per_group + 2;

	if (EXT4_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_FLEX_BG)) {
		if (!ext4_block_in_group(sb, ext4_block_bitmap(sb, gdp),
					block_group))
			used_blocks--;

		if (!ext4_block_in_group(sb, ext4_inode_bitmap(sb, gdp),
					block_group))
			used_blocks--;

		tmp = ext4_inode_table(sb, gdp);
		for (; tmp < ext4_inode_table(sb, gdp) +
				sbi->s_itb_per_group; tmp++) {
			if (!ext4_block_in_group(sb, tmp, block_group))
				used_blocks -= 1;
		}
	}
	return used_blocks;
}

unsigned ext4_init_block_bitmap(struct super_block *sb, struct buffer_head *bh,
		 ext4_group_t block_group, struct ext4_group_desc *gdp)
{
	int bit, bit_max;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	unsigned free_blocks, group_blocks;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (bh) {
		J_ASSERT_BH(bh, buffer_locked(bh));

		if (!ext4_group_desc_csum_verify(sbi, block_group, gdp)) {
			ext4_error(sb, __func__,
				  "Checksum bad for group %u", block_group);
			ext4_free_blks_set(sb, gdp, 0);
			ext4_free_inodes_set(sb, gdp, 0);
			ext4_itable_unused_set(sb, gdp, 0);
			memset(bh->b_data, 0xff, sb->s_blocksize);
			return 0;
		}
		memset(bh->b_data, 0, sb->s_blocksize);
	}

	bit_max = ext4_bg_has_super(sb, block_group);

	if (!EXT4_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_META_BG) ||
	    block_group < le32_to_cpu(sbi->s_es->s_first_meta_bg) *
			  sbi->s_desc_per_block) {
		if (bit_max) {
			bit_max += ext4_bg_num_gdb(sb, block_group);
			bit_max +=
				le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
		}
	} else {  
		bit_max += ext4_bg_num_gdb(sb, block_group);
	}

	if (block_group == ngroups - 1) {
		 
		group_blocks = ext4_blocks_count(sbi->s_es) -
			le32_to_cpu(sbi->s_es->s_first_data_block) -
			(EXT4_BLOCKS_PER_GROUP(sb) * (ngroups - 1));
	} else {
		group_blocks = EXT4_BLOCKS_PER_GROUP(sb);
	}

	free_blocks = group_blocks - bit_max;

	if (bh) {
		ext4_fsblk_t start, tmp;
		int flex_bg = 0;

		for (bit = 0; bit < bit_max; bit++)
			ext4_set_bit(bit, bh->b_data);

		start = ext4_group_first_block_no(sb, block_group);

		if (EXT4_HAS_INCOMPAT_FEATURE(sb,
					      EXT4_FEATURE_INCOMPAT_FLEX_BG))
			flex_bg = 1;

		tmp = ext4_block_bitmap(sb, gdp);
		if (!flex_bg || ext4_block_in_group(sb, tmp, block_group))
			ext4_set_bit(tmp - start, bh->b_data);

		tmp = ext4_inode_bitmap(sb, gdp);
		if (!flex_bg || ext4_block_in_group(sb, tmp, block_group))
			ext4_set_bit(tmp - start, bh->b_data);

		tmp = ext4_inode_table(sb, gdp);
		for (; tmp < ext4_inode_table(sb, gdp) +
				sbi->s_itb_per_group; tmp++) {
			if (!flex_bg ||
				ext4_block_in_group(sb, tmp, block_group))
				ext4_set_bit(tmp - start, bh->b_data);
		}
		 
		mark_bitmap_end(group_blocks, sb->s_blocksize * 8, bh->b_data);
	}
	return free_blocks - ext4_group_used_meta_blocks(sb, block_group, gdp);
}

#define in_range(b, first, len)	((b) >= (first) && (b) <= (first) + (len) - 1)

struct ext4_group_desc * ext4_get_group_desc(struct super_block *sb,
					     ext4_group_t block_group,
					     struct buffer_head **bh)
{
	unsigned int group_desc;
	unsigned int offset;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	struct ext4_group_desc *desc;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (block_group >= ngroups) {
		ext4_error(sb, "ext4_get_group_desc",
			   "block_group >= groups_count - "
			   "block_group = %u, groups_count = %u",
			   block_group, ngroups);

		return NULL;
	}

	group_desc = block_group >> EXT4_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (EXT4_DESC_PER_BLOCK(sb) - 1);
	if (!sbi->s_group_desc[group_desc]) {
		ext4_error(sb, "ext4_get_group_desc",
			   "Group descriptor not loaded - "
			   "block_group = %u, group_desc = %u, desc = %u",
			   block_group, group_desc, offset);
		return NULL;
	}

	desc = (struct ext4_group_desc *)(
		(__u8 *)sbi->s_group_desc[group_desc]->b_data +
		offset * EXT4_DESC_SIZE(sb));
	if (bh)
		*bh = sbi->s_group_desc[group_desc];
	return desc;
}

static int ext4_valid_block_bitmap(struct super_block *sb,
					struct ext4_group_desc *desc,
					unsigned int block_group,
					struct buffer_head *bh)
{
	ext4_grpblk_t offset;
	ext4_grpblk_t next_zero_bit;
	ext4_fsblk_t bitmap_blk;
	ext4_fsblk_t group_first_block;

	if (EXT4_HAS_INCOMPAT_FEATURE(sb, EXT4_FEATURE_INCOMPAT_FLEX_BG)) {
		 
		return 1;
	}
	group_first_block = ext4_group_first_block_no(sb, block_group);

	bitmap_blk = ext4_block_bitmap(sb, desc);
	offset = bitmap_blk - group_first_block;
	if (!ext4_test_bit(offset, bh->b_data))
		 
		goto err_out;

	bitmap_blk = ext4_inode_bitmap(sb, desc);
	offset = bitmap_blk - group_first_block;
	if (!ext4_test_bit(offset, bh->b_data))
		 
		goto err_out;

	bitmap_blk = ext4_inode_table(sb, desc);
	offset = bitmap_blk - group_first_block;
	next_zero_bit = ext4_find_next_zero_bit(bh->b_data,
				offset + EXT4_SB(sb)->s_itb_per_group,
				offset);
	if (next_zero_bit >= offset + EXT4_SB(sb)->s_itb_per_group)
		 
		return 1;

err_out:
	ext4_error(sb, __func__,
			"Invalid block bitmap - "
			"block_group = %d, block = %llu",
			block_group, bitmap_blk);
	return 0;
}
 
struct buffer_head *
ext4_read_block_bitmap(struct super_block *sb, ext4_group_t block_group)
{
	struct ext4_group_desc *desc;
	struct buffer_head *bh = NULL;
	ext4_fsblk_t bitmap_blk;

	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return NULL;
	bitmap_blk = ext4_block_bitmap(sb, desc);
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext4_error(sb, __func__,
			    "Cannot read block bitmap - "
			    "block_group = %u, block_bitmap = %llu",
			    block_group, bitmap_blk);
		return NULL;
	}

	if (bitmap_uptodate(bh))
		return bh;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		return bh;
	}
	ext4_lock_group(sb, block_group);
	if (desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		ext4_init_block_bitmap(sb, bh, block_group, desc);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		ext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		return bh;
	}
	ext4_unlock_group(sb, block_group);
	if (buffer_uptodate(bh)) {
		 
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		return bh;
	}
	 
	set_bitmap_uptodate(bh);
	if (bh_submit_read(bh) < 0) {
		put_bh(bh);
		ext4_error(sb, __func__,
			    "Cannot read block bitmap - "
			    "block_group = %u, block_bitmap = %llu",
			    block_group, bitmap_blk);
		return NULL;
	}
	ext4_valid_block_bitmap(sb, desc, block_group, bh);
	 
	return bh;
}

void ext4_add_groupblocks(handle_t *handle, struct super_block *sb,
			 ext4_fsblk_t block, unsigned long count)
{
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *gd_bh;
	ext4_group_t block_group;
	ext4_grpblk_t bit;
	unsigned int i;
	struct ext4_group_desc *desc;
	struct ext4_super_block *es;
	struct ext4_sb_info *sbi;
	int err = 0, ret, blk_free_count;
	ext4_grpblk_t blocks_freed;
	struct ext4_group_info *grp;

	sbi = EXT4_SB(sb);
	es = sbi->s_es;
	ext4_debug("Adding block(s) %llu-%llu\n", block, block + count - 1);

	ext4_get_group_no_and_offset(sb, block, &block_group, &bit);
	grp = ext4_get_group_info(sb, block_group);
	 
	if (bit + count > EXT4_BLOCKS_PER_GROUP(sb)) {
		goto error_return;
	}
	bitmap_bh = ext4_read_block_bitmap(sb, block_group);
	if (!bitmap_bh)
		goto error_return;
	desc = ext4_get_group_desc(sb, block_group, &gd_bh);
	if (!desc)
		goto error_return;

	if (in_range(ext4_block_bitmap(sb, desc), block, count) ||
	    in_range(ext4_inode_bitmap(sb, desc), block, count) ||
	    in_range(block, ext4_inode_table(sb, desc), sbi->s_itb_per_group) ||
	    in_range(block + count - 1, ext4_inode_table(sb, desc),
		     sbi->s_itb_per_group)) {
#ifdef MY_ABC_HERE
		if (printk_ratelimit())
#endif
		ext4_error(sb, __func__,
			   "Adding blocks in system zones - "
			   "Block = %llu, count = %lu",
			   block, count);
		goto error_return;
	}

	BUFFER_TRACE(bitmap_bh, "getting undo access");
	err = ext4_journal_get_undo_access(handle, bitmap_bh);
	if (err)
		goto error_return;

	BUFFER_TRACE(gd_bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, gd_bh);
	if (err)
		goto error_return;
	 
	down_write(&grp->alloc_sem);
	for (i = 0, blocks_freed = 0; i < count; i++) {
		BUFFER_TRACE(bitmap_bh, "clear bit");
		if (!ext4_clear_bit_atomic(ext4_group_lock_ptr(sb, block_group),
						bit + i, bitmap_bh->b_data)) {
			ext4_error(sb, __func__,
				   "bit already cleared for block %llu",
				   (ext4_fsblk_t)(block + i));
			BUFFER_TRACE(bitmap_bh, "bit already cleared");
		} else {
			blocks_freed++;
		}
	}
	ext4_lock_group(sb, block_group);
	blk_free_count = blocks_freed + ext4_free_blks_count(sb, desc);
	ext4_free_blks_set(sb, desc, blk_free_count);
	desc->bg_checksum = ext4_group_desc_csum(sbi, block_group, desc);
	ext4_unlock_group(sb, block_group);
	percpu_counter_add(&sbi->s_freeblocks_counter, blocks_freed);

	if (sbi->s_log_groups_per_flex) {
		ext4_group_t flex_group = ext4_flex_group(sbi, block_group);
		atomic_add(blocks_freed,
			   &sbi->s_flex_groups[flex_group].free_blocks);
	}
	 
	set_bit(EXT4_GROUP_INFO_NEED_INIT_BIT, &(grp->bb_state));
	grp->bb_free += blocks_freed;
	up_write(&grp->alloc_sem);

	BUFFER_TRACE(bitmap_bh, "dirtied bitmap block");
	err = ext4_handle_dirty_metadata(handle, NULL, bitmap_bh);

	BUFFER_TRACE(gd_bh, "dirtied group descriptor block");
	ret = ext4_handle_dirty_metadata(handle, NULL, gd_bh);
	if (!err)
		err = ret;
	sb->s_dirt = 1;

error_return:
	brelse(bitmap_bh);
	ext4_std_error(sb, err);
	return;
}

#ifndef MY_ABC_HERE
 
void ext4_free_blocks(handle_t *handle, struct inode *inode,
					   ext4_fsblk_t block, unsigned long count,
					   int metadata)
{
	struct super_block *sb;
	unsigned long dquot_freed_blocks;

	if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode))
		metadata = 1;

	if (metadata == 0 && !ext4_should_writeback_data(inode))
		metadata = 1;

	sb = inode->i_sb;

	ext4_mb_free_blocks(handle, inode, block, count,
					metadata, &dquot_freed_blocks);
	if (dquot_freed_blocks)
		vfs_dq_free_block(inode, dquot_freed_blocks);
	return;
}
#endif

int ext4_has_free_blocks(struct ext4_sb_info *sbi, s64 nblocks)
{
	s64 free_blocks, dirty_blocks, root_blocks;
	struct percpu_counter *fbc = &sbi->s_freeblocks_counter;
	struct percpu_counter *dbc = &sbi->s_dirtyblocks_counter;

	free_blocks  = percpu_counter_read_positive(fbc);
	dirty_blocks = percpu_counter_read_positive(dbc);
	root_blocks = ext4_r_blocks_count(sbi->s_es);

	if (free_blocks - (nblocks + root_blocks + dirty_blocks) <
						EXT4_FREEBLOCKS_WATERMARK) {
		free_blocks  = percpu_counter_sum_positive(fbc);
		dirty_blocks = percpu_counter_sum_positive(dbc);
		if (dirty_blocks < 0) {
			printk(KERN_CRIT "Dirty block accounting "
					"went wrong %lld\n",
					(long long)dirty_blocks);
		}
	}
	 
	if (free_blocks >= ((root_blocks + nblocks) + dirty_blocks))
		return 1;

	if (sbi->s_resuid == current_fsuid() ||
	    ((sbi->s_resgid != 0) && in_group_p(sbi->s_resgid)) ||
	    capable(CAP_SYS_RESOURCE)) {
		if (free_blocks >= (nblocks + dirty_blocks))
			return 1;
	}

	return 0;
}

int ext4_claim_free_blocks(struct ext4_sb_info *sbi,
						s64 nblocks)
{
	if (ext4_has_free_blocks(sbi, nblocks)) {
		percpu_counter_add(&sbi->s_dirtyblocks_counter, nblocks);
		return 0;
	} else
		return -ENOSPC;
}

int ext4_should_retry_alloc(struct super_block *sb, int *retries)
{
	if (!ext4_has_free_blocks(EXT4_SB(sb), 1) ||
	    (*retries)++ > 3 ||
	    !EXT4_SB(sb)->s_journal)
		return 0;

	jbd_debug(1, "%s: retrying operation after ENOSPC\n", sb->s_id);

	return jbd2_journal_force_commit_nested(EXT4_SB(sb)->s_journal);
}

ext4_fsblk_t ext4_new_meta_blocks(handle_t *handle, struct inode *inode,
		ext4_fsblk_t goal, unsigned long *count, int *errp)
{
	struct ext4_allocation_request ar;
	ext4_fsblk_t ret;

	memset(&ar, 0, sizeof(ar));
	 
	ar.inode = inode;
	ar.goal = goal;
	ar.len = count ? *count : 1;

	ret = ext4_mb_new_blocks(handle, &ar, errp);
	if (count)
		*count = ar.len;
	 
	if (!(*errp) && EXT4_I(inode)->i_delalloc_reserved_flag) {
		spin_lock(&EXT4_I(inode)->i_block_reservation_lock);
		EXT4_I(inode)->i_allocated_meta_blocks += ar.len;
		spin_unlock(&EXT4_I(inode)->i_block_reservation_lock);
#ifdef MY_ABC_HERE
		dquot_alloc_block_nofail(inode, ar.len);
#endif
	}
	return ret;
}

ext4_fsblk_t ext4_count_free_blocks(struct super_block *sb)
{
	ext4_fsblk_t desc_count;
	struct ext4_group_desc *gdp;
	ext4_group_t i;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
#ifdef EXT4FS_DEBUG
	struct ext4_super_block *es;
	ext4_fsblk_t bitmap_count;
	unsigned int x;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT4_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;

	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ext4_free_blks_count(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = ext4_read_block_bitmap(sb, i);
		if (bitmap_bh == NULL)
			continue;

		x = ext4_count_free(bitmap_bh, sb->s_blocksize);
		printk(KERN_DEBUG "group %u: stored = %d, counted = %u\n",
			i, ext4_free_blks_count(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "ext4_count_free_blocks: stored = %llu"
		", computed = %llu, %llu\n", ext4_free_blocks_count(es),
	       desc_count, bitmap_count);
	return bitmap_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = ext4_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += ext4_free_blks_count(sb, gdp);
	}

	return desc_count;
#endif
}

static inline int test_root(ext4_group_t a, int b)
{
	int num = b;

	while (a > num)
		num *= b;
	return num == a;
}

static int ext4_group_sparse(ext4_group_t group)
{
	if (group <= 1)
		return 1;
	if (!(group & 1))
		return 0;
	return (test_root(group, 7) || test_root(group, 5) ||
		test_root(group, 3));
}

int ext4_bg_has_super(struct super_block *sb, ext4_group_t group)
{
	if (EXT4_HAS_RO_COMPAT_FEATURE(sb,
				EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER) &&
			!ext4_group_sparse(group))
		return 0;
	return 1;
}

static unsigned long ext4_bg_num_gdb_meta(struct super_block *sb,
					ext4_group_t group)
{
	unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);
	ext4_group_t first = metagroup * EXT4_DESC_PER_BLOCK(sb);
	ext4_group_t last = first + EXT4_DESC_PER_BLOCK(sb) - 1;

	if (group == first || group == first + 1 || group == last)
		return 1;
	return 0;
}

static unsigned long ext4_bg_num_gdb_nometa(struct super_block *sb,
					ext4_group_t group)
{
	if (!ext4_bg_has_super(sb, group))
		return 0;

	if (EXT4_HAS_INCOMPAT_FEATURE(sb,EXT4_FEATURE_INCOMPAT_META_BG))
		return le32_to_cpu(EXT4_SB(sb)->s_es->s_first_meta_bg);
	else
		return EXT4_SB(sb)->s_gdb_count;
}

unsigned long ext4_bg_num_gdb(struct super_block *sb, ext4_group_t group)
{
	unsigned long first_meta_bg =
			le32_to_cpu(EXT4_SB(sb)->s_es->s_first_meta_bg);
	unsigned long metagroup = group / EXT4_DESC_PER_BLOCK(sb);

	if (!EXT4_HAS_INCOMPAT_FEATURE(sb,EXT4_FEATURE_INCOMPAT_META_BG) ||
			metagroup < first_meta_bg)
		return ext4_bg_num_gdb_nometa(sb, group);

	return ext4_bg_num_gdb_meta(sb,group);

}
