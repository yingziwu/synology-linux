#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/swap.h>
#include <linux/bootmem.h>
#include <linux/fs_struct.h>
#include <linux/hardirq.h>
#include "internal.h"

int sysctl_vfs_cache_pressure __read_mostly = 100;
EXPORT_SYMBOL_GPL(sysctl_vfs_cache_pressure);

 __cacheline_aligned_in_smp DEFINE_SPINLOCK(dcache_lock);
__cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);

EXPORT_SYMBOL(dcache_lock);

static struct kmem_cache *dentry_cache __read_mostly;

#define DNAME_INLINE_LEN (sizeof(struct dentry)-offsetof(struct dentry,d_iname))

#define D_HASHBITS     d_hash_shift
#define D_HASHMASK     d_hash_mask

static unsigned int d_hash_mask __read_mostly;
static unsigned int d_hash_shift __read_mostly;
static struct hlist_head *dentry_hashtable __read_mostly;

struct dentry_stat_t dentry_stat = {
	.age_limit = 45,
};

static void __d_free(struct dentry *dentry)
{
	WARN_ON(!list_empty(&dentry->d_alias));
	if (dname_external(dentry))
		kfree(dentry->d_name.name);
	kmem_cache_free(dentry_cache, dentry); 
}

static void d_callback(struct rcu_head *head)
{
	struct dentry * dentry = container_of(head, struct dentry, d_u.d_rcu);
	__d_free(dentry);
}

static void d_free(struct dentry *dentry)
{
	if (dentry->d_op && dentry->d_op->d_release)
		dentry->d_op->d_release(dentry);
	 
	if (hlist_unhashed(&dentry->d_hash))
		__d_free(dentry);
	else
		call_rcu(&dentry->d_u.d_rcu, d_callback);
}

static void dentry_iput(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
{
	struct inode *inode = dentry->d_inode;
	if (inode) {
		dentry->d_inode = NULL;
		list_del_init(&dentry->d_alias);
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
		if (!inode->i_nlink)
			fsnotify_inoderemove(inode);
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(dentry, inode);
		else
			iput(inode);
	} else {
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
	}
}

static void dentry_lru_add(struct dentry *dentry)
{
	list_add(&dentry->d_lru, &dentry->d_sb->s_dentry_lru);
	dentry->d_sb->s_nr_dentry_unused++;
	dentry_stat.nr_unused++;
}

static void dentry_lru_add_tail(struct dentry *dentry)
{
	list_add_tail(&dentry->d_lru, &dentry->d_sb->s_dentry_lru);
	dentry->d_sb->s_nr_dentry_unused++;
	dentry_stat.nr_unused++;
}

static void dentry_lru_del(struct dentry *dentry)
{
	if (!list_empty(&dentry->d_lru)) {
		list_del(&dentry->d_lru);
		dentry->d_sb->s_nr_dentry_unused--;
		dentry_stat.nr_unused--;
	}
}

static void dentry_lru_del_init(struct dentry *dentry)
{
	if (likely(!list_empty(&dentry->d_lru))) {
		list_del_init(&dentry->d_lru);
		dentry->d_sb->s_nr_dentry_unused--;
		dentry_stat.nr_unused--;
	}
}

static struct dentry *d_kill(struct dentry *dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
{
	struct dentry *parent;

	list_del(&dentry->d_u.d_child);
	dentry_stat.nr_dentry--;	 
	 
	dentry_iput(dentry);
	if (IS_ROOT(dentry))
		parent = NULL;
	else
		parent = dentry->d_parent;
	d_free(dentry);
	return parent;
}

void dput(struct dentry *dentry)
{
	if (!dentry)
		return;

repeat:
	if (atomic_read(&dentry->d_count) == 1)
		might_sleep();
	if (!atomic_dec_and_lock(&dentry->d_count, &dcache_lock))
		return;

	spin_lock(&dentry->d_lock);
	if (atomic_read(&dentry->d_count)) {
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
		return;
	}

	if (dentry->d_op && dentry->d_op->d_delete) {
		if (dentry->d_op->d_delete(dentry))
			goto unhash_it;
	}
	 
 	if (d_unhashed(dentry))
		goto kill_it;
  	if (list_empty(&dentry->d_lru)) {
  		dentry->d_flags |= DCACHE_REFERENCED;
		dentry_lru_add(dentry);
  	}
 	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	return;

unhash_it:
	__d_drop(dentry);
kill_it:
	 
	dentry_lru_del(dentry);
	dentry = d_kill(dentry);
	if (dentry)
		goto repeat;
}

int d_invalidate(struct dentry * dentry)
{
	 
	spin_lock(&dcache_lock);
	if (d_unhashed(dentry)) {
		spin_unlock(&dcache_lock);
		return 0;
	}
	 
	if (!list_empty(&dentry->d_subdirs)) {
		spin_unlock(&dcache_lock);
		shrink_dcache_parent(dentry);
		spin_lock(&dcache_lock);
	}

	spin_lock(&dentry->d_lock);
	if (atomic_read(&dentry->d_count) > 1) {
		if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)) {
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			return -EBUSY;
		}
	}

	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	return 0;
}

static inline struct dentry * __dget_locked(struct dentry *dentry)
{
	atomic_inc(&dentry->d_count);
	dentry_lru_del_init(dentry);
	return dentry;
}

struct dentry * dget_locked(struct dentry *dentry)
{
	return __dget_locked(dentry);
}

static struct dentry * __d_find_alias(struct inode *inode, int want_discon)
{
	struct list_head *head, *next, *tmp;
	struct dentry *alias, *discon_alias=NULL;

	head = &inode->i_dentry;
	next = inode->i_dentry.next;
	while (next != head) {
		tmp = next;
		next = tmp->next;
		prefetch(next);
		alias = list_entry(tmp, struct dentry, d_alias);
 		if (S_ISDIR(inode->i_mode) || !d_unhashed(alias)) {
			if (IS_ROOT(alias) &&
			    (alias->d_flags & DCACHE_DISCONNECTED))
				discon_alias = alias;
			else if (!want_discon) {
				__dget_locked(alias);
				return alias;
			}
		}
	}
	if (discon_alias)
		__dget_locked(discon_alias);
	return discon_alias;
}

struct dentry * d_find_alias(struct inode *inode)
{
	struct dentry *de = NULL;

	if (!list_empty(&inode->i_dentry)) {
		spin_lock(&dcache_lock);
		de = __d_find_alias(inode, 0);
		spin_unlock(&dcache_lock);
	}
	return de;
}

void d_prune_aliases(struct inode *inode)
{
	struct dentry *dentry;
restart:
	spin_lock(&dcache_lock);
	list_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		spin_lock(&dentry->d_lock);
		if (!atomic_read(&dentry->d_count)) {
			__dget_locked(dentry);
			__d_drop(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			dput(dentry);
			goto restart;
		}
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&dcache_lock);
}

static void prune_one_dentry(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
	__acquires(dcache_lock)
{
	__d_drop(dentry);
	dentry = d_kill(dentry);

	spin_lock(&dcache_lock);
	while (dentry) {
		if (!atomic_dec_and_lock(&dentry->d_count, &dentry->d_lock))
			return;

		if (dentry->d_op && dentry->d_op->d_delete)
			dentry->d_op->d_delete(dentry);
		dentry_lru_del_init(dentry);
		__d_drop(dentry);
		dentry = d_kill(dentry);
		spin_lock(&dcache_lock);
	}
}

static void __shrink_dcache_sb(struct super_block *sb, int *count, int flags)
{
	LIST_HEAD(referenced);
	LIST_HEAD(tmp);
	struct dentry *dentry;
	int cnt = 0;

	BUG_ON(!sb);
	BUG_ON((flags & DCACHE_REFERENCED) && count == NULL);
	spin_lock(&dcache_lock);
	if (count != NULL)
		 
		cnt = *count;
restart:
	if (count == NULL)
		list_splice_init(&sb->s_dentry_lru, &tmp);
	else {
		while (!list_empty(&sb->s_dentry_lru)) {
			dentry = list_entry(sb->s_dentry_lru.prev,
					struct dentry, d_lru);
			BUG_ON(dentry->d_sb != sb);

			spin_lock(&dentry->d_lock);
			 
			if ((flags & DCACHE_REFERENCED)
				&& (dentry->d_flags & DCACHE_REFERENCED)) {
				dentry->d_flags &= ~DCACHE_REFERENCED;
				list_move(&dentry->d_lru, &referenced);
				spin_unlock(&dentry->d_lock);
			} else {
				list_move_tail(&dentry->d_lru, &tmp);
				spin_unlock(&dentry->d_lock);
				cnt--;
				if (!cnt)
					break;
			}
			cond_resched_lock(&dcache_lock);
		}
	}
	while (!list_empty(&tmp)) {
		dentry = list_entry(tmp.prev, struct dentry, d_lru);
		dentry_lru_del_init(dentry);
		spin_lock(&dentry->d_lock);
		 
		if (atomic_read(&dentry->d_count)) {
			spin_unlock(&dentry->d_lock);
			continue;
		}
		prune_one_dentry(dentry);
		 
		cond_resched_lock(&dcache_lock);
	}
	if (count == NULL && !list_empty(&sb->s_dentry_lru))
		goto restart;
	if (count != NULL)
		*count = cnt;
	if (!list_empty(&referenced))
		list_splice(&referenced, &sb->s_dentry_lru);
	spin_unlock(&dcache_lock);
}

static void prune_dcache(int count)
{
	struct super_block *sb;
	int w_count;
	int unused = dentry_stat.nr_unused;
	int prune_ratio;
	int pruned;

	if (unused == 0 || count == 0)
		return;
	spin_lock(&dcache_lock);
restart:
	if (count >= unused)
		prune_ratio = 1;
	else
		prune_ratio = unused / count;
	spin_lock(&sb_lock);
	list_for_each_entry(sb, &super_blocks, s_list) {
		if (sb->s_nr_dentry_unused == 0)
			continue;
		sb->s_count++;
		 
		spin_unlock(&sb_lock);
		if (prune_ratio != 1)
			w_count = (sb->s_nr_dentry_unused / prune_ratio) + 1;
		else
			w_count = sb->s_nr_dentry_unused;
		pruned = w_count;
		 
		if (down_read_trylock(&sb->s_umount)) {
			if ((sb->s_root != NULL) &&
			    (!list_empty(&sb->s_dentry_lru))) {
				spin_unlock(&dcache_lock);
				__shrink_dcache_sb(sb, &w_count,
						DCACHE_REFERENCED);
				pruned -= w_count;
				spin_lock(&dcache_lock);
			}
			up_read(&sb->s_umount);
		}
		spin_lock(&sb_lock);
		count -= pruned;
		 
		if (__put_super_and_need_restart(sb) && count > 0) {
			spin_unlock(&sb_lock);
			goto restart;
		}
	}
	spin_unlock(&sb_lock);
	spin_unlock(&dcache_lock);
}

void shrink_dcache_sb(struct super_block * sb)
{
	__shrink_dcache_sb(sb, NULL, 0);
}

static void shrink_dcache_for_umount_subtree(struct dentry *dentry)
{
	struct dentry *parent;
	unsigned detached = 0;

	BUG_ON(!IS_ROOT(dentry));

	spin_lock(&dcache_lock);
	dentry_lru_del_init(dentry);
	__d_drop(dentry);
	spin_unlock(&dcache_lock);

	for (;;) {
		 
		while (!list_empty(&dentry->d_subdirs)) {
			struct dentry *loop;

			spin_lock(&dcache_lock);
			list_for_each_entry(loop, &dentry->d_subdirs,
					    d_u.d_child) {
				dentry_lru_del_init(loop);
				__d_drop(loop);
				cond_resched_lock(&dcache_lock);
			}
			spin_unlock(&dcache_lock);

			dentry = list_entry(dentry->d_subdirs.next,
					    struct dentry, d_u.d_child);
		}

		do {
			struct inode *inode;

#ifdef SYNO_FORCE_UNMOUNT
			if (atomic_read(&dentry->d_count) != 0 && strcmp(dentry->d_name.name, "forceumount")) {
#else
			if (atomic_read(&dentry->d_count) != 0) {
#endif
				printk(KERN_ERR
				       "BUG: Dentry %p{i=%lx,n=%s}"
				       " still in use (%d)"
				       " [unmount of %s %s]\n",
				       dentry,
				       dentry->d_inode ?
				       dentry->d_inode->i_ino : 0UL,
				       dentry->d_name.name,
				       atomic_read(&dentry->d_count),
				       dentry->d_sb->s_type->name,
				       dentry->d_sb->s_id);
#ifdef SYNO_FORCE_UNMOUNT
				dump_stack();
				goto out;
#else
				BUG();
#endif
			}

			if (IS_ROOT(dentry))
				parent = NULL;
			else {
				parent = dentry->d_parent;
				atomic_dec(&parent->d_count);
			}

			list_del(&dentry->d_u.d_child);
			detached++;

			inode = dentry->d_inode;
			if (inode) {
				dentry->d_inode = NULL;
				list_del_init(&dentry->d_alias);
				if (dentry->d_op && dentry->d_op->d_iput)
					dentry->d_op->d_iput(dentry, inode);
				else
					iput(inode);
			}

			d_free(dentry);

			if (!parent)
				goto out;

			dentry = parent;

		} while (list_empty(&dentry->d_subdirs));

		dentry = list_entry(dentry->d_subdirs.next,
				    struct dentry, d_u.d_child);
	}
out:
	 
	spin_lock(&dcache_lock);
	dentry_stat.nr_dentry -= detached;
	spin_unlock(&dcache_lock);
}

void shrink_dcache_for_umount(struct super_block *sb)
{
	struct dentry *dentry;

	if (down_read_trylock(&sb->s_umount))
		BUG();

	dentry = sb->s_root;
	sb->s_root = NULL;
	atomic_dec(&dentry->d_count);
	shrink_dcache_for_umount_subtree(dentry);

	while (!hlist_empty(&sb->s_anon)) {
		dentry = hlist_entry(sb->s_anon.first, struct dentry, d_hash);
		shrink_dcache_for_umount_subtree(dentry);
	}
}

int have_submounts(struct dentry *parent)
{
	struct dentry *this_parent = parent;
	struct list_head *next;

	spin_lock(&dcache_lock);
	if (d_mountpoint(parent))
		goto positive;
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;
		 
		if (d_mountpoint(dentry))
			goto positive;
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
	}
	 
	if (this_parent != parent) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
	spin_unlock(&dcache_lock);
	return 0;  
positive:
	spin_unlock(&dcache_lock);
	return 1;
}

static int select_parent(struct dentry * parent)
{
	struct dentry *this_parent = parent;
	struct list_head *next;
	int found = 0;

	spin_lock(&dcache_lock);
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;

		dentry_lru_del_init(dentry);
		 
		if (!atomic_read(&dentry->d_count)) {
			dentry_lru_add_tail(dentry);
			found++;
		}

		if (found && need_resched())
			goto out;

		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
	}
	 
	if (this_parent != parent) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
out:
	spin_unlock(&dcache_lock);
	return found;
}

void shrink_dcache_parent(struct dentry * parent)
{
	struct super_block *sb = parent->d_sb;
	int found;

	while ((found = select_parent(parent)) != 0)
		__shrink_dcache_sb(sb, &found, 0);
}

static int shrink_dcache_memory(int nr, gfp_t gfp_mask)
{
	if (nr) {
		if (!(gfp_mask & __GFP_FS))
			return -1;
		prune_dcache(nr);
	}
	return (dentry_stat.nr_unused / 100) * sysctl_vfs_cache_pressure;
}

static struct shrinker dcache_shrinker = {
	.shrink = shrink_dcache_memory,
	.seeks = DEFAULT_SEEKS,
};

struct dentry *d_alloc(struct dentry * parent, const struct qstr *name)
{
	struct dentry *dentry;
	char *dname;

	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
	if (!dentry)
		return NULL;

	if (name->len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(name->len + 1, GFP_KERNEL);
		if (!dname) {
			kmem_cache_free(dentry_cache, dentry); 
			return NULL;
		}
	} else  {
		dname = dentry->d_iname;
	}	
	dentry->d_name.name = dname;

	dentry->d_name.len = name->len;
	dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	atomic_set(&dentry->d_count, 1);
	dentry->d_flags = DCACHE_UNHASHED;
	spin_lock_init(&dentry->d_lock);
	dentry->d_inode = NULL;
	dentry->d_parent = NULL;
	dentry->d_sb = NULL;
	dentry->d_op = NULL;
	dentry->d_fsdata = NULL;
	dentry->d_mounted = 0;
	INIT_HLIST_NODE(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_lru);
	INIT_LIST_HEAD(&dentry->d_subdirs);
	INIT_LIST_HEAD(&dentry->d_alias);

	if (parent) {
		dentry->d_parent = dget(parent);
		dentry->d_sb = parent->d_sb;
	} else {
		INIT_LIST_HEAD(&dentry->d_u.d_child);
	}

	spin_lock(&dcache_lock);
	if (parent)
		list_add(&dentry->d_u.d_child, &parent->d_subdirs);
	dentry_stat.nr_dentry++;
	spin_unlock(&dcache_lock);

	return dentry;
}

struct dentry *d_alloc_name(struct dentry *parent, const char *name)
{
	struct qstr q;

	q.name = name;
	q.len = strlen(name);
	q.hash = full_name_hash(q.name, q.len);
	return d_alloc(parent, &q);
}

static void __d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (inode)
		list_add(&dentry->d_alias, &inode->i_dentry);
	dentry->d_inode = inode;
	fsnotify_d_instantiate(dentry, inode);
}

void d_instantiate(struct dentry *entry, struct inode * inode)
{
	BUG_ON(!list_empty(&entry->d_alias));
	spin_lock(&dcache_lock);
	__d_instantiate(entry, inode);
	spin_unlock(&dcache_lock);
	security_d_instantiate(entry, inode);
}

static struct dentry *__d_instantiate_unique(struct dentry *entry,
					     struct inode *inode)
{
	struct dentry *alias;
	int len = entry->d_name.len;
	const char *name = entry->d_name.name;
	unsigned int hash = entry->d_name.hash;

	if (!inode) {
		__d_instantiate(entry, NULL);
		return NULL;
	}

	list_for_each_entry(alias, &inode->i_dentry, d_alias) {
		struct qstr *qstr = &alias->d_name;

		if (qstr->hash != hash)
			continue;
		if (alias->d_parent != entry->d_parent)
			continue;
		if (qstr->len != len)
			continue;
		if (memcmp(qstr->name, name, len))
			continue;
		dget_locked(alias);
		return alias;
	}

	__d_instantiate(entry, inode);
	return NULL;
}

struct dentry *d_instantiate_unique(struct dentry *entry, struct inode *inode)
{
	struct dentry *result;

	BUG_ON(!list_empty(&entry->d_alias));

	spin_lock(&dcache_lock);
	result = __d_instantiate_unique(entry, inode);
	spin_unlock(&dcache_lock);

	if (!result) {
		security_d_instantiate(entry, inode);
		return NULL;
	}

	BUG_ON(!d_unhashed(result));
	iput(inode);
	return result;
}

EXPORT_SYMBOL(d_instantiate_unique);

struct dentry * d_alloc_root(struct inode * root_inode)
{
	struct dentry *res = NULL;

	if (root_inode) {
		static const struct qstr name = { .name = "/", .len = 1 };

		res = d_alloc(NULL, &name);
		if (res) {
			res->d_sb = root_inode->i_sb;
			res->d_parent = res;
			d_instantiate(res, root_inode);
		}
	}
	return res;
}

static inline struct hlist_head *d_hash(struct dentry *parent,
					unsigned long hash)
{
	hash += ((unsigned long) parent ^ GOLDEN_RATIO_PRIME) / L1_CACHE_BYTES;
	hash = hash ^ ((hash ^ GOLDEN_RATIO_PRIME) >> D_HASHBITS);
	return dentry_hashtable + (hash & D_HASHMASK);
}

struct dentry *d_obtain_alias(struct inode *inode)
{
	static const struct qstr anonstring = { .name = "" };
	struct dentry *tmp;
	struct dentry *res;

	if (!inode)
		return ERR_PTR(-ESTALE);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	res = d_find_alias(inode);
	if (res)
		goto out_iput;

	tmp = d_alloc(NULL, &anonstring);
	if (!tmp) {
		res = ERR_PTR(-ENOMEM);
		goto out_iput;
	}
	tmp->d_parent = tmp;  

	spin_lock(&dcache_lock);
	res = __d_find_alias(inode, 0);
	if (res) {
		spin_unlock(&dcache_lock);
		dput(tmp);
		goto out_iput;
	}

	spin_lock(&tmp->d_lock);
	tmp->d_sb = inode->i_sb;
	tmp->d_inode = inode;
	tmp->d_flags |= DCACHE_DISCONNECTED;
	tmp->d_flags &= ~DCACHE_UNHASHED;
	list_add(&tmp->d_alias, &inode->i_dentry);
	hlist_add_head(&tmp->d_hash, &inode->i_sb->s_anon);
	spin_unlock(&tmp->d_lock);

	spin_unlock(&dcache_lock);
	return tmp;

 out_iput:
	iput(inode);
	return res;
}
EXPORT_SYMBOL(d_obtain_alias);

struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
	struct dentry *new = NULL;

	if (inode && S_ISDIR(inode->i_mode)) {
		spin_lock(&dcache_lock);
		new = __d_find_alias(inode, 1);
		if (new) {
			BUG_ON(!(new->d_flags & DCACHE_DISCONNECTED));
			spin_unlock(&dcache_lock);
			security_d_instantiate(new, inode);
			d_rehash(dentry);
			d_move(new, dentry);
			iput(inode);
		} else {
			 
			__d_instantiate(dentry, inode);
			spin_unlock(&dcache_lock);
			security_d_instantiate(dentry, inode);
			d_rehash(dentry);
		}
	} else
		d_add(dentry, inode);
	return new;
}

struct dentry *d_add_ci(struct dentry *dentry, struct inode *inode,
			struct qstr *name)
{
	int error;
	struct dentry *found;
	struct dentry *new;

	found = d_hash_and_lookup(dentry->d_parent, name);
	if (!found) {
		new = d_alloc(dentry->d_parent, name);
		if (!new) {
			error = -ENOMEM;
			goto err_out;
		}

		found = d_splice_alias(inode, new);
		if (found) {
			dput(new);
			return found;
		}
		return new;
	}

	if (found->d_inode) {
		if (unlikely(found->d_inode != inode)) {
			 
			BUG_ON(!is_bad_inode(inode));
			BUG_ON(!is_bad_inode(found->d_inode));
		}
		iput(inode);
		return found;
	}

	spin_lock(&dcache_lock);
	if (!S_ISDIR(inode->i_mode) || list_empty(&inode->i_dentry)) {
		__d_instantiate(found, inode);
		spin_unlock(&dcache_lock);
		security_d_instantiate(found, inode);
		return found;
	}

	new = list_entry(inode->i_dentry.next, struct dentry, d_alias);
	dget_locked(new);
	spin_unlock(&dcache_lock);
	security_d_instantiate(found, inode);
	d_move(new, found);
	iput(inode);
	dput(found);
	return new;

err_out:
	iput(inode);
	return ERR_PTR(error);
}

struct dentry * d_lookup(struct dentry * parent, struct qstr * name)
{
	struct dentry * dentry = NULL;
	unsigned long seq;

        do {
                seq = read_seqbegin(&rename_lock);
                dentry = __d_lookup(parent, name);
                if (dentry)
			break;
	} while (read_seqretry(&rename_lock, seq));
	return dentry;
}

struct dentry * __d_lookup(struct dentry * parent, struct qstr * name)
{
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct hlist_head *head = d_hash(parent,hash);
	struct dentry *found = NULL;
	struct hlist_node *node;
	struct dentry *dentry;
#ifdef MY_ABC_HERE
	int lockFound = 0;
#endif

	rcu_read_lock();
	
	hlist_for_each_entry_rcu(dentry, node, head, d_hash) {
		struct qstr *qstr;

		if (dentry->d_name.hash != hash)
			continue;
		if (dentry->d_parent != parent)
			continue;

		spin_lock(&dentry->d_lock);

		if (dentry->d_parent != parent)
			goto next;

		if (d_unhashed(dentry))
			goto next;

		qstr = &dentry->d_name;
		if (parent->d_op && parent->d_op->d_compare) {
			if (parent->d_op->d_compare(parent, qstr, name))
				goto next;
#ifdef MY_ABC_HERE
			 
			if (DCACHE_CASELESS_COMPARE & parent->d_flags){
				if (!dentry->d_inode) {
					 
					if (!found) {
						atomic_inc(&dentry->d_count);
						found = dentry;
						lockFound++;
						 
						continue;
					}
					goto next;
				}
			}
#endif
		} else {
			if (qstr->len != len)
				goto next;
			if (memcmp(qstr->name, str, len))
				goto next;
		}
#ifdef MY_ABC_HERE
		 
		if (lockFound) {
			atomic_dec(&found->d_count);
			spin_unlock(&found->d_lock);
			lockFound = 0;
		}
#endif

		atomic_inc(&dentry->d_count);
		found = dentry;
		spin_unlock(&dentry->d_lock);
		break;
next:
		spin_unlock(&dentry->d_lock);
 	}
#ifdef MY_ABC_HERE
	 
	if (lockFound) {
		spin_unlock(&found->d_lock);
	}
#endif
 	rcu_read_unlock();

 	return found;
}

struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	struct dentry *dentry = NULL;

	name->hash = full_name_hash(name->name, name->len);
	if (dir->d_op && dir->d_op->d_hash) {
		if (dir->d_op->d_hash(dir, name) < 0)
			goto out;
	}
	dentry = d_lookup(dir, name);
out:
	return dentry;
}

int d_validate(struct dentry *dentry, struct dentry *dparent)
{
	struct hlist_head *base;
	struct hlist_node *lhp;

	if (!kmem_ptr_validate(dentry_cache, dentry))
		goto out;

	if (dentry->d_parent != dparent)
		goto out;

	spin_lock(&dcache_lock);
	base = d_hash(dparent, dentry->d_name.hash);
	hlist_for_each(lhp,base) { 
		 
		if (dentry == hlist_entry(lhp, struct dentry, d_hash)) {
			__dget_locked(dentry);
			spin_unlock(&dcache_lock);
			return 1;
		}
	}
	spin_unlock(&dcache_lock);
out:
	return 0;
}

void d_delete(struct dentry * dentry)
{
	int isdir = 0;
	 
	spin_lock(&dcache_lock);
	spin_lock(&dentry->d_lock);
	isdir = S_ISDIR(dentry->d_inode->i_mode);
	if (atomic_read(&dentry->d_count) == 1) {
		dentry_iput(dentry);
		fsnotify_nameremove(dentry, isdir);
		return;
	}

	if (!d_unhashed(dentry))
		__d_drop(dentry);

	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);

	fsnotify_nameremove(dentry, isdir);
}

static void __d_rehash(struct dentry * entry, struct hlist_head *list)
{

 	entry->d_flags &= ~DCACHE_UNHASHED;
 	hlist_add_head_rcu(&entry->d_hash, list);
}

static void _d_rehash(struct dentry * entry)
{
	__d_rehash(entry, d_hash(entry->d_parent, entry->d_name.hash));
}

void d_rehash(struct dentry * entry)
{
	spin_lock(&dcache_lock);
	spin_lock(&entry->d_lock);
	_d_rehash(entry);
	spin_unlock(&entry->d_lock);
	spin_unlock(&dcache_lock);
}

static void switch_names(struct dentry *dentry, struct dentry *target)
{
	if (dname_external(target)) {
		if (dname_external(dentry)) {
			 
			swap(target->d_name.name, dentry->d_name.name);
		} else {
			 
			memcpy(target->d_iname, dentry->d_name.name,
					dentry->d_name.len + 1);
			dentry->d_name.name = target->d_name.name;
			target->d_name.name = target->d_iname;
		}
	} else {
		if (dname_external(dentry)) {
			 
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			target->d_name.name = dentry->d_name.name;
			dentry->d_name.name = dentry->d_iname;
		} else {
			 
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			dentry->d_name.len = target->d_name.len;
			return;
		}
	}
	swap(dentry->d_name.len, target->d_name.len);
}

static void d_move_locked(struct dentry * dentry, struct dentry * target)
{
	struct hlist_head *list;

	if (!dentry->d_inode)
		printk(KERN_WARNING "VFS: moving negative dcache entry\n");

	write_seqlock(&rename_lock);
	 
	if (target < dentry) {
		spin_lock(&target->d_lock);
		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	} else {
		spin_lock(&dentry->d_lock);
		spin_lock_nested(&target->d_lock, DENTRY_D_LOCK_NESTED);
	}

	if (d_unhashed(dentry))
		goto already_unhashed;

	hlist_del_rcu(&dentry->d_hash);

already_unhashed:
	list = d_hash(target->d_parent, target->d_name.hash);
	__d_rehash(dentry, list);

	__d_drop(target);

	list_del(&dentry->d_u.d_child);
	list_del(&target->d_u.d_child);

	switch_names(dentry, target);
	swap(dentry->d_name.hash, target->d_name.hash);

	if (IS_ROOT(dentry)) {
		dentry->d_parent = target->d_parent;
		target->d_parent = target;
		INIT_LIST_HEAD(&target->d_u.d_child);
	} else {
		swap(dentry->d_parent, target->d_parent);

		list_add(&target->d_u.d_child, &target->d_parent->d_subdirs);
	}

	list_add(&dentry->d_u.d_child, &dentry->d_parent->d_subdirs);
	spin_unlock(&target->d_lock);
	fsnotify_d_move(dentry);
	spin_unlock(&dentry->d_lock);
	write_sequnlock(&rename_lock);
}

void d_move(struct dentry * dentry, struct dentry * target)
{
	spin_lock(&dcache_lock);
	d_move_locked(dentry, target);
	spin_unlock(&dcache_lock);
}

struct dentry *d_ancestor(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	for (p = p2; !IS_ROOT(p); p = p->d_parent) {
		if (p->d_parent == p1)
			return p;
	}
	return NULL;
}

static struct dentry *__d_unalias(struct dentry *dentry, struct dentry *alias)
	__releases(dcache_lock)
{
	struct mutex *m1 = NULL, *m2 = NULL;
	struct dentry *ret;

	if (alias->d_parent == dentry->d_parent)
		goto out_unalias;

	ret = ERR_PTR(-ELOOP);
	if (d_ancestor(alias, dentry))
		goto out_err;

	ret = ERR_PTR(-EBUSY);
	if (!mutex_trylock(&dentry->d_sb->s_vfs_rename_mutex))
		goto out_err;
	m1 = &dentry->d_sb->s_vfs_rename_mutex;
	if (!mutex_trylock(&alias->d_parent->d_inode->i_mutex))
		goto out_err;
	m2 = &alias->d_parent->d_inode->i_mutex;
out_unalias:
	d_move_locked(alias, dentry);
	ret = alias;
out_err:
	spin_unlock(&dcache_lock);
	if (m2)
		mutex_unlock(m2);
	if (m1)
		mutex_unlock(m1);
	return ret;
}

static void __d_materialise_dentry(struct dentry *dentry, struct dentry *anon)
{
	struct dentry *dparent, *aparent;

	switch_names(dentry, anon);
	swap(dentry->d_name.hash, anon->d_name.hash);

	dparent = dentry->d_parent;
	aparent = anon->d_parent;

	dentry->d_parent = (aparent == anon) ? dentry : aparent;
	list_del(&dentry->d_u.d_child);
	if (!IS_ROOT(dentry))
		list_add(&dentry->d_u.d_child, &dentry->d_parent->d_subdirs);
	else
		INIT_LIST_HEAD(&dentry->d_u.d_child);

	anon->d_parent = (dparent == dentry) ? anon : dparent;
	list_del(&anon->d_u.d_child);
	if (!IS_ROOT(anon))
		list_add(&anon->d_u.d_child, &anon->d_parent->d_subdirs);
	else
		INIT_LIST_HEAD(&anon->d_u.d_child);

	anon->d_flags &= ~DCACHE_DISCONNECTED;
}

struct dentry *d_materialise_unique(struct dentry *dentry, struct inode *inode)
{
	struct dentry *actual;

	BUG_ON(!d_unhashed(dentry));

	spin_lock(&dcache_lock);

	if (!inode) {
		actual = dentry;
		__d_instantiate(dentry, NULL);
		goto found_lock;
	}

	if (S_ISDIR(inode->i_mode)) {
		struct dentry *alias;

		alias = __d_find_alias(inode, 0);
		if (alias) {
			actual = alias;
			 
			if (IS_ROOT(alias)) {
				spin_lock(&alias->d_lock);
				__d_materialise_dentry(dentry, alias);
				__d_drop(alias);
				goto found;
			}
			 
			actual = __d_unalias(dentry, alias);
			if (IS_ERR(actual))
				dput(alias);
			goto out_nolock;
		}
	}

	actual = __d_instantiate_unique(dentry, inode);
	if (!actual)
		actual = dentry;
	else if (unlikely(!d_unhashed(actual)))
		goto shouldnt_be_hashed;

found_lock:
	spin_lock(&actual->d_lock);
found:
	_d_rehash(actual);
	spin_unlock(&actual->d_lock);
	spin_unlock(&dcache_lock);
out_nolock:
	if (actual == dentry) {
		security_d_instantiate(dentry, inode);
		return NULL;
	}

	iput(inode);
	return actual;

shouldnt_be_hashed:
	spin_unlock(&dcache_lock);
	BUG();
}

static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

static int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
	return prepend(buffer, buflen, name->name, name->len);
}

char *__d_path(const struct path *path, struct path *root,
	       char *buffer, int buflen)
{
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	char *end = buffer + buflen;
	char *retval;

	spin_lock(&vfsmount_lock);
	prepend(&end, &buflen, "\0", 1);
	if (d_unlinked(dentry) &&
		(prepend(&end, &buflen, " (deleted)", 10) != 0))
			goto Elong;

	if (buflen < 1)
		goto Elong;
	 
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (dentry == root->dentry && vfsmnt == root->mnt)
			break;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			 
			if (vfsmnt->mnt_parent == vfsmnt) {
				goto global_root;
			}
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		if ((prepend_name(&end, &buflen, &dentry->d_name) != 0) ||
		    (prepend(&end, &buflen, "/", 1) != 0))
			goto Elong;
		retval = end;
		dentry = parent;
	}

out:
	spin_unlock(&vfsmount_lock);
	return retval;

global_root:
	retval += 1;	 
	if (prepend_name(&retval, &buflen, &dentry->d_name) != 0)
		goto Elong;
	root->mnt = vfsmnt;
	root->dentry = dentry;
	goto out;

Elong:
	retval = ERR_PTR(-ENAMETOOLONG);
	goto out;
}

char *d_path(const struct path *path, char *buf, int buflen)
{
	char *res;
	struct path root;
	struct path tmp;

	if (path->dentry->d_op && path->dentry->d_op->d_dname)
		return path->dentry->d_op->d_dname(path->dentry, buf, buflen);

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);
	spin_lock(&dcache_lock);
	tmp = root;
	res = __d_path(path, &tmp, buf, buflen);
	spin_unlock(&dcache_lock);
	path_put(&root);
	return res;
}

char *dynamic_dname(struct dentry *dentry, char *buffer, int buflen,
			const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

char *dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *end = buf + buflen;
	char *retval;

	spin_lock(&dcache_lock);
	prepend(&end, &buflen, "\0", 1);
	if (d_unlinked(dentry) &&
		(prepend(&end, &buflen, "//deleted", 9) != 0))
			goto Elong;
	if (buflen < 1)
		goto Elong;
	 
	retval = end-1;
	*retval = '/';

	while (!IS_ROOT(dentry)) {
		struct dentry *parent = dentry->d_parent;

		prefetch(parent);
		if ((prepend_name(&end, &buflen, &dentry->d_name) != 0) ||
		    (prepend(&end, &buflen, "/", 1) != 0))
			goto Elong;

		retval = end;
		dentry = parent;
	}
	spin_unlock(&dcache_lock);
	return retval;
Elong:
	spin_unlock(&dcache_lock);
	return ERR_PTR(-ENAMETOOLONG);
}

SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	int error;
	struct path pwd, root;
	char *page = (char *) __get_free_page(GFP_USER);

	if (!page)
		return -ENOMEM;

	read_lock(&current->fs->lock);
	pwd = current->fs->pwd;
	path_get(&pwd);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);

	error = -ENOENT;
	spin_lock(&dcache_lock);
	if (!d_unlinked(pwd.dentry)) {
		unsigned long len;
		struct path tmp = root;
		char * cwd;

		cwd = __d_path(&pwd, &tmp, page, PAGE_SIZE);
		spin_unlock(&dcache_lock);

		error = PTR_ERR(cwd);
		if (IS_ERR(cwd))
			goto out;

		error = -ERANGE;
		len = PAGE_SIZE + page - cwd;
		if (len <= size) {
			error = len;
			if (copy_to_user(buf, cwd, len))
				error = -EFAULT;
		}
	} else
		spin_unlock(&dcache_lock);

out:
	path_put(&pwd);
	path_put(&root);
	free_page((unsigned long) page);
	return error;
}

int is_subdir(struct dentry *new_dentry, struct dentry *old_dentry)
{
	int result;
	unsigned long seq;

	if (new_dentry == old_dentry)
		return 1;

	rcu_read_lock();
	do {
		 
		seq = read_seqbegin(&rename_lock);
		if (d_ancestor(old_dentry, new_dentry))
			result = 1;
		else
			result = 0;
	} while (read_seqretry(&rename_lock, seq));
	rcu_read_unlock();

	return result;
}

void d_genocide(struct dentry *root)
{
	struct dentry *this_parent = root;
	struct list_head *next;

	spin_lock(&dcache_lock);
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;
		if (d_unhashed(dentry)||!dentry->d_inode)
			continue;
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
		atomic_dec(&dentry->d_count);
	}
	if (this_parent != root) {
		next = this_parent->d_u.d_child.next;
		atomic_dec(&this_parent->d_count);
		this_parent = this_parent->d_parent;
		goto resume;
	}
	spin_unlock(&dcache_lock);
}

ino_t find_inode_number(struct dentry *dir, struct qstr *name)
{
	struct dentry * dentry;
	ino_t ino = 0;

	dentry = d_hash_and_lookup(dir, name);
	if (dentry) {
		if (dentry->d_inode)
			ino = dentry->d_inode->i_ino;
		dput(dentry);
	}
	return ino;
}

static __initdata unsigned long dhash_entries;
static int __init set_dhash_entries(char *str)
{
	if (!str)
		return 0;
	dhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("dhash_entries=", set_dhash_entries);

static void __init dcache_init_early(void)
{
	int loop;

	if (hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					dhash_entries,
					13,
					HASH_EARLY,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1 << d_hash_shift); loop++)
		INIT_HLIST_HEAD(&dentry_hashtable[loop]);
}

static void __init dcache_init(void)
{
	int loop;

	dentry_cache = KMEM_CACHE(dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD);
	
	register_shrinker(&dcache_shrinker);

	if (!hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					dhash_entries,
					13,
					0,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1 << d_hash_shift); loop++)
		INIT_HLIST_HEAD(&dentry_hashtable[loop]);
}

struct kmem_cache *names_cachep __read_mostly;

EXPORT_SYMBOL(d_genocide);

void __init vfs_caches_init_early(void)
{
	dcache_init_early();
	inode_init_early();
}

void __init vfs_caches_init(unsigned long mempages)
{
	unsigned long reserve;

	reserve = min((mempages - nr_free_pages()) * 3/2, mempages - 1);
	mempages -= reserve;

	names_cachep = kmem_cache_create("names_cache", PATH_MAX, 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	dcache_init();
	inode_init();
	files_init(mempages);
	mnt_init();
	bdev_cache_init();
	chrdev_init();
}

EXPORT_SYMBOL(d_alloc);
EXPORT_SYMBOL(d_alloc_root);
EXPORT_SYMBOL(d_delete);
EXPORT_SYMBOL(d_find_alias);
EXPORT_SYMBOL(d_instantiate);
EXPORT_SYMBOL(d_invalidate);
EXPORT_SYMBOL(d_lookup);
EXPORT_SYMBOL(d_move);
EXPORT_SYMBOL_GPL(d_materialise_unique);
EXPORT_SYMBOL(d_path);
EXPORT_SYMBOL(d_prune_aliases);
EXPORT_SYMBOL(d_rehash);
EXPORT_SYMBOL(d_splice_alias);
EXPORT_SYMBOL(d_add_ci);
EXPORT_SYMBOL(d_validate);
EXPORT_SYMBOL(dget_locked);
EXPORT_SYMBOL(dput);
EXPORT_SYMBOL(find_inode_number);
EXPORT_SYMBOL(have_submounts);
EXPORT_SYMBOL(names_cachep);
EXPORT_SYMBOL(shrink_dcache_parent);
EXPORT_SYMBOL(shrink_dcache_sb);
