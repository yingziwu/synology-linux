#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _LINUX_QUOTAOPS_
#define _LINUX_QUOTAOPS_

#include <linux/fs.h>

#ifdef MY_ABC_HERE
#define DQUOT_SPACE_WARN	0x1
#define DQUOT_SPACE_RESERVE	0x2
#define DQUOT_SPACE_NOFAIL	0x4
#endif

static inline struct quota_info *sb_dqopt(struct super_block *sb)
{
	return &sb->s_dquot;
}

#if defined(CONFIG_QUOTA)

void sync_quota_sb(struct super_block *sb, int type);
static inline void writeout_quota_sb(struct super_block *sb, int type)
{
	if (sb->s_qcop->quota_sync)
		sb->s_qcop->quota_sync(sb, type);
}

void inode_add_rsv_space(struct inode *inode, qsize_t number);
void inode_claim_rsv_space(struct inode *inode, qsize_t number);
void inode_sub_rsv_space(struct inode *inode, qsize_t number);

int dquot_initialize(struct inode *inode, int type);
int dquot_drop(struct inode *inode);
struct dquot *dqget(struct super_block *sb, unsigned int id, int type);
void dqput(struct dquot *dquot);
int dquot_scan_active(struct super_block *sb,
		      int (*fn)(struct dquot *dquot, unsigned long priv),
		      unsigned long priv);
struct dquot *dquot_alloc(struct super_block *sb, int type);
void dquot_destroy(struct dquot *dquot);

#ifdef MY_ABC_HERE
int __dquot_alloc_space(struct inode *inode, qsize_t number, int flags);
void __dquot_free_space(struct inode *inode, qsize_t number, int flags);
#else
int dquot_alloc_space(struct inode *inode, qsize_t number, int prealloc);
int dquot_alloc_inode(const struct inode *inode, qsize_t number);
#endif

#ifdef MY_ABC_HERE
int dquot_alloc_inode(const struct inode *inode, qsize_t number);
#else
int dquot_reserve_space(struct inode *inode, qsize_t number, int prealloc);
int dquot_claim_space(struct inode *inode, qsize_t number);
void dquot_release_reserved_space(struct inode *inode, qsize_t number);
#endif

#ifdef MY_ABC_HERE
int dquot_claim_space_nodirty(struct inode *inode, qsize_t number);
#else
int dquot_free_space(struct inode *inode, qsize_t number);
#endif
int dquot_free_inode(const struct inode *inode, qsize_t number);

int dquot_transfer(struct inode *inode, struct iattr *iattr);
int dquot_commit(struct dquot *dquot);
int dquot_acquire(struct dquot *dquot);
int dquot_release(struct dquot *dquot);
int dquot_commit_info(struct super_block *sb, int type);
int dquot_mark_dquot_dirty(struct dquot *dquot);

int vfs_quota_on(struct super_block *sb, int type, int format_id,
 	char *path, int remount);
int vfs_quota_enable(struct inode *inode, int type, int format_id,
	unsigned int flags);
int vfs_quota_on_path(struct super_block *sb, int type, int format_id,
 	struct path *path);
int vfs_quota_on_mount(struct super_block *sb, char *qf_name,
 	int format_id, int type);
int vfs_quota_off(struct super_block *sb, int type, int remount);
int vfs_quota_disable(struct super_block *sb, int type, unsigned int flags);
int vfs_quota_sync(struct super_block *sb, int type);
int vfs_get_dqinfo(struct super_block *sb, int type, struct if_dqinfo *ii);
int vfs_set_dqinfo(struct super_block *sb, int type, struct if_dqinfo *ii);
int vfs_get_dqblk(struct super_block *sb, int type, qid_t id, struct if_dqblk *di);
int vfs_set_dqblk(struct super_block *sb, int type, qid_t id, struct if_dqblk *di);

void vfs_dq_drop(struct inode *inode);
int vfs_dq_transfer(struct inode *inode, struct iattr *iattr);
int vfs_dq_quota_on_remount(struct super_block *sb);

static inline struct mem_dqinfo *sb_dqinfo(struct super_block *sb, int type)
{
	return sb_dqopt(sb)->info + type;
}

static inline int sb_has_quota_usage_enabled(struct super_block *sb, int type)
{
	return sb_dqopt(sb)->flags &
				dquot_state_flag(DQUOT_USAGE_ENABLED, type);
}

static inline int sb_has_quota_limits_enabled(struct super_block *sb, int type)
{
	return sb_dqopt(sb)->flags &
				dquot_state_flag(DQUOT_LIMITS_ENABLED, type);
}

static inline int sb_has_quota_suspended(struct super_block *sb, int type)
{
	return sb_dqopt(sb)->flags &
				dquot_state_flag(DQUOT_SUSPENDED, type);
}

static inline int sb_any_quota_suspended(struct super_block *sb)
{
	return sb_has_quota_suspended(sb, USRQUOTA) ||
		sb_has_quota_suspended(sb, GRPQUOTA);
}

static inline int sb_has_quota_loaded(struct super_block *sb, int type)
{
	 
	return sb_has_quota_usage_enabled(sb, type);
}

static inline int sb_any_quota_loaded(struct super_block *sb)
{
	return sb_has_quota_loaded(sb, USRQUOTA) ||
		sb_has_quota_loaded(sb, GRPQUOTA);
}

static inline int sb_has_quota_active(struct super_block *sb, int type)
{
	return sb_has_quota_loaded(sb, type) &&
	       !sb_has_quota_suspended(sb, type);
}

static inline int sb_any_quota_active(struct super_block *sb)
{
	return sb_has_quota_active(sb, USRQUOTA) ||
	       sb_has_quota_active(sb, GRPQUOTA);
}

extern const struct dquot_operations dquot_operations;
extern const struct quotactl_ops vfs_quotactl_ops;

#define sb_dquot_ops (&dquot_operations)
#define sb_quotactl_ops (&vfs_quotactl_ops)

static inline void vfs_dq_init(struct inode *inode)
{
	BUG_ON(!inode->i_sb);
	if (sb_any_quota_active(inode->i_sb) && !IS_NOQUOTA(inode))
		inode->i_sb->dq_op->initialize(inode, -1);
}

#ifndef MY_ABC_HERE
 
static inline int vfs_dq_prealloc_space_nodirty(struct inode *inode, qsize_t nr)
{
	if (sb_any_quota_active(inode->i_sb)) {
		 
		if (inode->i_sb->dq_op->alloc_space(inode, nr, 1) == NO_QUOTA)
			return 1;
	}
	else
		inode_add_bytes(inode, nr);
	return 0;
}

static inline int vfs_dq_prealloc_space(struct inode *inode, qsize_t nr)
{
	int ret;
        if (!(ret =  vfs_dq_prealloc_space_nodirty(inode, nr)))
		mark_inode_dirty(inode);
	return ret;
}

static inline int vfs_dq_alloc_space_nodirty(struct inode *inode, qsize_t nr)
{
	if (sb_any_quota_active(inode->i_sb)) {
		 
		if (inode->i_sb->dq_op->alloc_space(inode, nr, 0) == NO_QUOTA)
			return 1;
	}
	else
		inode_add_bytes(inode, nr);
	return 0;
}

static inline int vfs_dq_alloc_space(struct inode *inode, qsize_t nr)
{
	int ret;
	if (!(ret = vfs_dq_alloc_space_nodirty(inode, nr)))
		mark_inode_dirty(inode);
	return ret;
}

static inline int vfs_dq_reserve_space(struct inode *inode, qsize_t nr)
{
	if (sb_any_quota_active(inode->i_sb)) {
		 
		if (inode->i_sb->dq_op->reserve_space(inode, nr, 0) == NO_QUOTA)
			return 1;
	}
	else
		inode_add_rsv_space(inode, nr);
	return 0;
}
#endif

static inline int vfs_dq_alloc_inode(struct inode *inode)
{
	if (sb_any_quota_active(inode->i_sb)) {
		vfs_dq_init(inode);
		if (inode->i_sb->dq_op->alloc_inode(inode, 1) == NO_QUOTA)
			return 1;
	}
	return 0;
}

#ifndef MY_ABC_HERE
 
static inline int vfs_dq_claim_space(struct inode *inode, qsize_t nr)
{
	if (sb_any_quota_active(inode->i_sb)) {
		if (inode->i_sb->dq_op->claim_space(inode, nr) == NO_QUOTA)
			return 1;
	} else
		inode_claim_rsv_space(inode, nr);

	mark_inode_dirty(inode);
	return 0;
}

static inline
void vfs_dq_release_reservation_space(struct inode *inode, qsize_t nr)
{
	if (sb_any_quota_active(inode->i_sb))
		inode->i_sb->dq_op->release_rsv(inode, nr);
	else
		inode_sub_rsv_space(inode, nr);
}

static inline void vfs_dq_free_space_nodirty(struct inode *inode, qsize_t nr)
{
	if (sb_any_quota_active(inode->i_sb))
		inode->i_sb->dq_op->free_space(inode, nr);
	else
		inode_sub_bytes(inode, nr);
}

static inline void vfs_dq_free_space(struct inode *inode, qsize_t nr)
{
	vfs_dq_free_space_nodirty(inode, nr);
	mark_inode_dirty(inode);
}
#endif

static inline void vfs_dq_free_inode(struct inode *inode)
{
	if (sb_any_quota_active(inode->i_sb))
		inode->i_sb->dq_op->free_inode(inode, 1);
}

static inline int vfs_dq_off(struct super_block *sb, int remount)
{
	int ret = -ENOSYS;

	if (sb->s_qcop && sb->s_qcop->quota_off)
		ret = sb->s_qcop->quota_off(sb, -1, remount);
	return ret;
}

#else

static inline int sb_has_quota_usage_enabled(struct super_block *sb, int type)
{
	return 0;
}

static inline int sb_has_quota_limits_enabled(struct super_block *sb, int type)
{
	return 0;
}

static inline int sb_has_quota_suspended(struct super_block *sb, int type)
{
	return 0;
}

static inline int sb_any_quota_suspended(struct super_block *sb)
{
	return 0;
}

static inline int sb_has_quota_loaded(struct super_block *sb, int type)
{
	return 0;
}

static inline int sb_any_quota_loaded(struct super_block *sb)
{
	return 0;
}

static inline int sb_has_quota_active(struct super_block *sb, int type)
{
	return 0;
}

static inline int sb_any_quota_active(struct super_block *sb)
{
	return 0;
}

#define sb_dquot_ops				(NULL)
#define sb_quotactl_ops				(NULL)

static inline void vfs_dq_init(struct inode *inode)
{
}

static inline void vfs_dq_drop(struct inode *inode)
{
}

static inline int vfs_dq_alloc_inode(struct inode *inode)
{
	return 0;
}

static inline void vfs_dq_free_inode(struct inode *inode)
{
}

static inline void sync_quota_sb(struct super_block *sb, int type)
{
}

static inline void writeout_quota_sb(struct super_block *sb, int type)
{
}

static inline int vfs_dq_off(struct super_block *sb, int remount)
{
	return 0;
}

static inline int vfs_dq_quota_on_remount(struct super_block *sb)
{
	return 0;
}

static inline int vfs_dq_transfer(struct inode *inode, struct iattr *iattr)
{
	return 0;
}

#ifdef MY_ABC_HERE
static inline int __dquot_alloc_space(struct inode *inode, qsize_t number,
		int flags)
{
	if (!(flags & DQUOT_SPACE_RESERVE))
		inode_add_bytes(inode, number);
	return 0;
}

static inline void __dquot_free_space(struct inode *inode, qsize_t number,
		int flags)
{
	if (!(flags & DQUOT_SPACE_RESERVE))
		inode_sub_bytes(inode, number);
}

static inline int dquot_claim_space_nodirty(struct inode *inode, qsize_t number)
{
	inode_add_bytes(inode, number);
	return 0;
}
#else
static inline int vfs_dq_prealloc_space_nodirty(struct inode *inode, qsize_t nr)
{
	inode_add_bytes(inode, nr);
	return 0;
}

static inline int vfs_dq_prealloc_space(struct inode *inode, qsize_t nr)
{
	vfs_dq_prealloc_space_nodirty(inode, nr);
	mark_inode_dirty(inode);
	return 0;
}

static inline int vfs_dq_alloc_space_nodirty(struct inode *inode, qsize_t nr)
{
	inode_add_bytes(inode, nr);
	return 0;
}

static inline int vfs_dq_alloc_space(struct inode *inode, qsize_t nr)
{
	vfs_dq_alloc_space_nodirty(inode, nr);
	mark_inode_dirty(inode);
	return 0;
}

static inline int vfs_dq_reserve_space(struct inode *inode, qsize_t nr)
{
	return 0;
}

static inline int vfs_dq_claim_space(struct inode *inode, qsize_t nr)
{
	return vfs_dq_alloc_space(inode, nr);
}

static inline
int vfs_dq_release_reservation_space(struct inode *inode, qsize_t nr)
{
	return 0;
}

static inline void vfs_dq_free_space_nodirty(struct inode *inode, qsize_t nr)
{
	inode_sub_bytes(inode, nr);
}

static inline void vfs_dq_free_space(struct inode *inode, qsize_t nr)
{
	vfs_dq_free_space_nodirty(inode, nr);
	mark_inode_dirty(inode);
}
#endif
#endif  

#ifdef MY_ABC_HERE
static inline int dquot_alloc_space_nodirty(struct inode *inode, qsize_t nr)
{
	return __dquot_alloc_space(inode, nr, DQUOT_SPACE_WARN);
}

static inline void dquot_alloc_space_nofail(struct inode *inode, qsize_t nr)
{
	__dquot_alloc_space(inode, nr, DQUOT_SPACE_WARN|DQUOT_SPACE_NOFAIL);
	mark_inode_dirty(inode);
}

static inline int dquot_alloc_space(struct inode *inode, qsize_t nr)
{
	int ret;

	ret = dquot_alloc_space_nodirty(inode, nr);
	if (!ret)
		mark_inode_dirty(inode);
	return ret;
}

static inline int dquot_alloc_block_nodirty(struct inode *inode, qsize_t nr)
{
	return dquot_alloc_space_nodirty(inode, nr << inode->i_blkbits);
}

static inline void dquot_alloc_block_nofail(struct inode *inode, qsize_t nr)
{
	dquot_alloc_space_nofail(inode, nr << inode->i_blkbits);
}

static inline int dquot_alloc_block(struct inode *inode, qsize_t nr)
{
	return dquot_alloc_space(inode, nr << inode->i_blkbits);
}

static inline int dquot_prealloc_block_nodirty(struct inode *inode, qsize_t nr)
{
	return __dquot_alloc_space(inode, nr << inode->i_blkbits, 0);
}

static inline int dquot_prealloc_block(struct inode *inode, qsize_t nr)
{
	int ret;

	ret = dquot_prealloc_block_nodirty(inode, nr);
	if (!ret)
		mark_inode_dirty(inode);
	return ret;
}

static inline int dquot_reserve_block(struct inode *inode, qsize_t nr)
{
	return __dquot_alloc_space(inode, nr << inode->i_blkbits,
				DQUOT_SPACE_WARN|DQUOT_SPACE_RESERVE);
}

static inline int dquot_claim_block(struct inode *inode, qsize_t nr)
{
	int ret;

	ret = dquot_claim_space_nodirty(inode, nr << inode->i_blkbits);
	if (!ret)
		mark_inode_dirty(inode);
	return ret;
}

static inline void dquot_free_space_nodirty(struct inode *inode, qsize_t nr)
{
	__dquot_free_space(inode, nr, 0);
}

static inline void dquot_free_space(struct inode *inode, qsize_t nr)
{
	dquot_free_space_nodirty(inode, nr);
	mark_inode_dirty(inode);
}

static inline void dquot_free_block_nodirty(struct inode *inode, qsize_t nr)
{
	dquot_free_space_nodirty(inode, nr << inode->i_blkbits);
}

static inline void dquot_free_block(struct inode *inode, qsize_t nr)
{
	dquot_free_space(inode, nr << inode->i_blkbits);
}

static inline void dquot_release_reservation_block(struct inode *inode,
		qsize_t nr)
{
	__dquot_free_space(inode, nr << inode->i_blkbits, DQUOT_SPACE_RESERVE);
}
#else
static inline int vfs_dq_prealloc_block_nodirty(struct inode *inode, qsize_t nr)
{
	return vfs_dq_prealloc_space_nodirty(inode, nr << inode->i_blkbits);
}

static inline int vfs_dq_prealloc_block(struct inode *inode, qsize_t nr)
{
	return vfs_dq_prealloc_space(inode, nr << inode->i_blkbits);
}

static inline int vfs_dq_alloc_block_nodirty(struct inode *inode, qsize_t nr)
{
	return vfs_dq_alloc_space_nodirty(inode, nr << inode->i_blkbits);
}

static inline int vfs_dq_alloc_block(struct inode *inode, qsize_t nr)
{
	return vfs_dq_alloc_space(inode, nr << inode->i_blkbits);
}

static inline int vfs_dq_reserve_block(struct inode *inode, qsize_t nr)
{
	return vfs_dq_reserve_space(inode, nr << inode->i_blkbits);
}

static inline int vfs_dq_claim_block(struct inode *inode, qsize_t nr)
{
	return vfs_dq_claim_space(inode, nr << inode->i_blkbits);
}

static inline
void vfs_dq_release_reservation_block(struct inode *inode, qsize_t nr)
{
	vfs_dq_release_reservation_space(inode, nr << inode->i_blkbits);
}

static inline void vfs_dq_free_block_nodirty(struct inode *inode, qsize_t nr)
{
	vfs_dq_free_space_nodirty(inode, nr << inode->i_blkbits);
}

static inline void vfs_dq_free_block(struct inode *inode, qsize_t nr)
{
	vfs_dq_free_space(inode, nr << inode->i_blkbits);
}
#endif
#endif  
