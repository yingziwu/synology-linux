#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 * Copyright (C) 2009 Oracle.  All rights reserved.
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
#include <linux/sort.h>
#include "ctree.h"
#ifdef MY_DEF_HERE
#include "qgroup.h"
#endif
#include "delayed-ref.h"
#include "transaction.h"
#ifdef MY_DEF_HERE
#include "disk-io.h"
#endif /* MY_DEF_HERE */

struct kmem_cache *btrfs_delayed_ref_head_cachep;
struct kmem_cache *btrfs_delayed_tree_ref_cachep;
struct kmem_cache *btrfs_delayed_data_ref_cachep;
struct kmem_cache *btrfs_delayed_extent_op_cachep;
/*
 * delayed back reference update tracking.  For subvolume trees
 * we queue up extent allocations and backref maintenance for
 * delayed processing.   This avoids deep call chains where we
 * add extents in the middle of btrfs_search_slot, and it allows
 * us to buffer up frequently modified backrefs in an rb tree instead
 * of hammering updates on the extent allocation tree.
 */

/*
 * compare two delayed tree backrefs with same bytenr and type
 */
static int comp_tree_refs(struct btrfs_delayed_tree_ref *ref2,
			  struct btrfs_delayed_tree_ref *ref1, int type)
{
	if (type == BTRFS_TREE_BLOCK_REF_KEY) {
		if (ref1->root < ref2->root)
			return -1;
		if (ref1->root > ref2->root)
			return 1;
	} else {
		if (ref1->parent < ref2->parent)
			return -1;
		if (ref1->parent > ref2->parent)
			return 1;
	}
	return 0;
}

/*
 * compare two delayed data backrefs with same bytenr and type
 */
static int comp_data_refs(struct btrfs_delayed_data_ref *ref2,
			  struct btrfs_delayed_data_ref *ref1)
{
	if (ref1->node.type == BTRFS_EXTENT_DATA_REF_KEY) {
		if (ref1->root < ref2->root)
			return -1;
		if (ref1->root > ref2->root)
			return 1;
		if (ref1->objectid < ref2->objectid)
			return -1;
		if (ref1->objectid > ref2->objectid)
			return 1;
		if (ref1->offset < ref2->offset)
			return -1;
		if (ref1->offset > ref2->offset)
			return 1;
#ifdef MY_DEF_HERE
		if (ref1->uid < ref2->uid)
			return -1;
		if (ref1->uid > ref2->uid)
			return 1;
#endif /* MY_DEF_HERE */
	} else {
		if (ref1->parent < ref2->parent)
			return -1;
		if (ref1->parent > ref2->parent)
			return 1;
	}
#ifdef MY_DEF_HERE
	if (ref1->syno_usage < ref2->syno_usage)
			return -1;
	if (ref1->syno_usage > ref2->syno_usage)
			return 1;
#endif /* MY_DEF_HERE */
	return 0;
}

/*
 * entries in the rb tree are ordered by the byte number of the extent,
 * type of the delayed backrefs and content of delayed backrefs.
 */
static int comp_entry(struct btrfs_delayed_ref_node *ref2,
		      struct btrfs_delayed_ref_node *ref1,
		      bool compare_seq)
{
	if (ref1->bytenr < ref2->bytenr)
		return -1;
	if (ref1->bytenr > ref2->bytenr)
		return 1;
	if (ref1->is_head && ref2->is_head)
		return 0;
	if (ref2->is_head)
		return -1;
	if (ref1->is_head)
		return 1;
	if (ref1->type < ref2->type)
		return -1;
	if (ref1->type > ref2->type)
		return 1;
	if (ref1->no_quota > ref2->no_quota)
		return 1;
	if (ref1->no_quota < ref2->no_quota)
		return -1;
	/* merging of sequenced refs is not allowed */
	if (compare_seq) {
		if (ref1->seq < ref2->seq)
			return -1;
		if (ref1->seq > ref2->seq)
			return 1;
	}
	if (ref1->type == BTRFS_TREE_BLOCK_REF_KEY ||
	    ref1->type == BTRFS_SHARED_BLOCK_REF_KEY) {
		return comp_tree_refs(btrfs_delayed_node_to_tree_ref(ref2),
				      btrfs_delayed_node_to_tree_ref(ref1),
				      ref1->type);
	} else if (ref1->type == BTRFS_EXTENT_DATA_REF_KEY ||
		   ref1->type == BTRFS_SHARED_DATA_REF_KEY) {
		return comp_data_refs(btrfs_delayed_node_to_data_ref(ref2),
				      btrfs_delayed_node_to_data_ref(ref1));
	}
	BUG();
	return 0;
}

/*
 * insert a new ref into the rbtree.  This returns any existing refs
 * for the same (bytenr,parent) tuple, or NULL if the new node was properly
 * inserted.
 */
static struct btrfs_delayed_ref_node *tree_insert(struct rb_root *root,
						  struct rb_node *node)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent_node = NULL;
	struct btrfs_delayed_ref_node *entry;
	struct btrfs_delayed_ref_node *ins;
	int cmp;

	ins = rb_entry(node, struct btrfs_delayed_ref_node, rb_node);
	while (*p) {
		parent_node = *p;
		entry = rb_entry(parent_node, struct btrfs_delayed_ref_node,
				 rb_node);

		cmp = comp_entry(entry, ins, 1);
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else
			return entry;
	}

	rb_link_node(node, parent_node, p);
	rb_insert_color(node, root);
	return NULL;
}

/* insert a new ref to head ref rbtree */
static struct btrfs_delayed_ref_head *htree_insert(struct rb_root *root,
						   struct rb_node *node)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent_node = NULL;
	struct btrfs_delayed_ref_head *entry;
	struct btrfs_delayed_ref_head *ins;
	u64 bytenr;

	ins = rb_entry(node, struct btrfs_delayed_ref_head, href_node);
	bytenr = ins->node.bytenr;
	while (*p) {
		parent_node = *p;
		entry = rb_entry(parent_node, struct btrfs_delayed_ref_head,
				 href_node);

		if (bytenr < entry->node.bytenr)
			p = &(*p)->rb_left;
		else if (bytenr > entry->node.bytenr)
			p = &(*p)->rb_right;
		else
			return entry;
	}

	rb_link_node(node, parent_node, p);
	rb_insert_color(node, root);
	return NULL;
}

/*
 * find an head entry based on bytenr. This returns the delayed ref
 * head if it was able to find one, or NULL if nothing was in that spot.
 * If return_bigger is given, the next bigger entry is returned if no exact
 * match is found.
 */
static struct btrfs_delayed_ref_head *
find_ref_head(struct rb_root *root, u64 bytenr,
	      int return_bigger)
{
	struct rb_node *n;
	struct btrfs_delayed_ref_head *entry;

	n = root->rb_node;
	entry = NULL;
	while (n) {
		entry = rb_entry(n, struct btrfs_delayed_ref_head, href_node);

		if (bytenr < entry->node.bytenr)
			n = n->rb_left;
		else if (bytenr > entry->node.bytenr)
			n = n->rb_right;
		else
			return entry;
	}
	if (entry && return_bigger) {
		if (bytenr > entry->node.bytenr) {
			n = rb_next(&entry->href_node);
			if (!n)
				n = rb_first(root);
			entry = rb_entry(n, struct btrfs_delayed_ref_head,
					 href_node);
			return entry;
		}
		return entry;
	}
	return NULL;
}

int btrfs_delayed_ref_lock(struct btrfs_trans_handle *trans,
			   struct btrfs_delayed_ref_head *head)
{
	struct btrfs_delayed_ref_root *delayed_refs;

	delayed_refs = &trans->transaction->delayed_refs;
	assert_spin_locked(&delayed_refs->lock);
	if (mutex_trylock(&head->mutex))
		return 0;

	atomic_inc(&head->node.refs);
	spin_unlock(&delayed_refs->lock);

	mutex_lock(&head->mutex);
	spin_lock(&delayed_refs->lock);
	if (!head->node.in_tree) {
		mutex_unlock(&head->mutex);
		btrfs_put_delayed_ref(&head->node);
		return -EAGAIN;
	}
	btrfs_put_delayed_ref(&head->node);
	return 0;
}

static inline void drop_delayed_ref(struct btrfs_trans_handle *trans,
				    struct btrfs_delayed_ref_root *delayed_refs,
				    struct btrfs_delayed_ref_head *head,
				    struct btrfs_delayed_ref_node *ref)
{
#ifdef MY_DEF_HERE
	struct btrfs_delayed_data_ref *data_ref = NULL;
#endif /* MY_DEF_HERE */
	if (btrfs_delayed_ref_is_head(ref)) {
		head = btrfs_delayed_node_to_head(ref);
		rb_erase(&head->href_node, &delayed_refs->href_root);
	} else {
		assert_spin_locked(&head->lock);
		rb_erase(&ref->rb_node, &head->ref_root);
#ifdef MY_DEF_HERE
		if (!list_empty(&ref->syno_list))
			list_del(&ref->syno_list);
#endif /* MY_DEF_HERE */
	}
	ref->in_tree = 0;
#ifdef MY_DEF_HERE
	if (ref->type == BTRFS_EXTENT_DATA_REF_KEY || ref->type == BTRFS_SHARED_DATA_REF_KEY) {
		data_ref = btrfs_delayed_node_to_data_ref(ref);
		if (data_ref->syno_usage) {
			atomic_dec(&delayed_refs->num_syno_usage_entries);
		}
	}
#endif /* MY_DEF_HERE */
	btrfs_put_delayed_ref(ref);
	atomic_dec(&delayed_refs->num_entries);
	if (trans->delayed_ref_updates)
		trans->delayed_ref_updates--;
}

static int merge_ref(struct btrfs_trans_handle *trans,
		     struct btrfs_delayed_ref_root *delayed_refs,
		     struct btrfs_delayed_ref_head *head,
		     struct btrfs_delayed_ref_node *ref, u64 seq)
{
	struct rb_node *node;
	int mod = 0;
	int done = 0;

	node = rb_next(&ref->rb_node);
	while (!done && node) {
		struct btrfs_delayed_ref_node *next;

		next = rb_entry(node, struct btrfs_delayed_ref_node, rb_node);
		node = rb_next(node);
		if (seq && next->seq >= seq)
			break;
		if (comp_entry(ref, next, 0))
			continue;

		if (ref->action == next->action) {
			mod = next->ref_mod;
		} else {
			if (ref->ref_mod < next->ref_mod) {
				struct btrfs_delayed_ref_node *tmp;

				tmp = ref;
				ref = next;
				next = tmp;
				done = 1;
			}
			mod = -next->ref_mod;
		}

		drop_delayed_ref(trans, delayed_refs, head, next);
		ref->ref_mod += mod;
		if (ref->ref_mod == 0) {
			drop_delayed_ref(trans, delayed_refs, head, ref);
			done = 1;
		} else {
			/*
			 * You can't have multiples of the same ref on a tree
			 * block.
			 */
			WARN_ON(ref->type == BTRFS_TREE_BLOCK_REF_KEY ||
				ref->type == BTRFS_SHARED_BLOCK_REF_KEY);
		}
	}
	return done;
}

void btrfs_merge_delayed_refs(struct btrfs_trans_handle *trans,
			      struct btrfs_fs_info *fs_info,
			      struct btrfs_delayed_ref_root *delayed_refs,
			      struct btrfs_delayed_ref_head *head)
{
	struct rb_node *node;
	u64 seq = 0;

	assert_spin_locked(&head->lock);
	/*
	 * We don't have too much refs to merge in the case of delayed data
	 * refs.
	 */
	if (head->is_data)
		return;

	read_lock(&fs_info->tree_mod_log_lock);
	if (!list_empty(&fs_info->tree_mod_seq_list)) {
		struct seq_list *elem;

		elem = list_first_entry(&fs_info->tree_mod_seq_list,
					struct seq_list, list);
		seq = elem->seq;
	}
	read_unlock(&fs_info->tree_mod_log_lock);

	node = rb_first(&head->ref_root);
	while (node) {
		struct btrfs_delayed_ref_node *ref;

		ref = rb_entry(node, struct btrfs_delayed_ref_node,
			       rb_node);
		/* We can't merge refs that are outside of our seq count */
		if (seq && ref->seq >= seq)
			break;
		if (merge_ref(trans, delayed_refs, head, ref, seq))
			node = rb_first(&head->ref_root);
		else
			node = rb_next(&ref->rb_node);
	}
}

int btrfs_check_delayed_seq(struct btrfs_fs_info *fs_info,
			    struct btrfs_delayed_ref_root *delayed_refs,
			    u64 seq)
{
	struct seq_list *elem;
	int ret = 0;

	read_lock(&fs_info->tree_mod_log_lock);
	if (!list_empty(&fs_info->tree_mod_seq_list)) {
		elem = list_first_entry(&fs_info->tree_mod_seq_list,
					struct seq_list, list);
		if (seq >= elem->seq) {
			pr_debug("holding back delayed_ref %#x.%x, lowest is %#x.%x (%p)\n",
				 (u32)(seq >> 32), (u32)seq,
				 (u32)(elem->seq >> 32), (u32)elem->seq,
				 delayed_refs);
			ret = 1;
		}
	}

	read_unlock(&fs_info->tree_mod_log_lock);
	return ret;
}

struct btrfs_delayed_ref_head *
btrfs_select_ref_head(struct btrfs_trans_handle *trans)
{
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_delayed_ref_head *head;
	u64 start;
	bool loop = false;

	delayed_refs = &trans->transaction->delayed_refs;

again:
	start = delayed_refs->run_delayed_start;
	head = find_ref_head(&delayed_refs->href_root, start, 1);
	if (!head && !loop) {
		delayed_refs->run_delayed_start = 0;
		start = 0;
		loop = true;
		head = find_ref_head(&delayed_refs->href_root, start, 1);
		if (!head)
			return NULL;
	} else if (!head && loop) {
		return NULL;
	}

	while (head->processing) {
		struct rb_node *node;

		node = rb_next(&head->href_node);
		if (!node) {
			if (loop)
				return NULL;
			delayed_refs->run_delayed_start = 0;
			start = 0;
			loop = true;
			goto again;
		}
		head = rb_entry(node, struct btrfs_delayed_ref_head,
				href_node);
	}

	head->processing = 1;
	WARN_ON(delayed_refs->num_heads_ready == 0);
	delayed_refs->num_heads_ready--;
#ifdef MY_DEF_HERE
	if (head->syno_usage) {
		WARN_ON(delayed_refs->num_syno_usage_heads_ready == 0);
		delayed_refs->num_syno_usage_heads_ready--;
	}
#endif /* MY_DEF_HERE */
	delayed_refs->run_delayed_start = head->node.bytenr +
		head->node.num_bytes;
	return head;
}

#ifdef MY_DEF_HERE
// Copied from btrfs_select_ref_head()
struct btrfs_delayed_ref_head *
btrfs_select_data_ref_head(struct btrfs_trans_handle *trans)
{
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_delayed_ref_head *head;
	struct rb_node *node;

	delayed_refs = &trans->transaction->delayed_refs;

	head = find_ref_head(&delayed_refs->href_root, delayed_refs->run_delayed_start, 1);
	if (!head)
		return NULL;
	// find_ref_head() may loop back.
	if (head->node.bytenr < delayed_refs->run_delayed_start)
		return NULL;

	while (!head->is_data) {
		node = rb_next(&head->href_node);
		if (!node)
			return NULL;
		head = rb_entry(node, struct btrfs_delayed_ref_head,
				href_node);
	}

	/*
	 * It should not happend. But if it does, we should reloop and wait on this
	 * head to complete.
	 */
	if (head->processing)
		return ERR_PTR(-EAGAIN);

	head->processing = 1;
	WARN_ON(delayed_refs->num_heads_ready == 0);
	delayed_refs->num_heads_ready--;
#ifdef MY_DEF_HERE
	if (head->syno_usage) {
		WARN_ON(delayed_refs->num_syno_usage_heads_ready == 0);
		delayed_refs->num_syno_usage_heads_ready--;
	}
#endif /* MY_DEF_HERE */
	delayed_refs->run_delayed_start = head->node.bytenr +
		head->node.num_bytes;
	return head;
}
#endif

/*
 * helper function to update an extent delayed ref in the
 * rbtree.  existing and update must both have the same
 * bytenr and parent
 *
 * This may free existing if the update cancels out whatever
 * operation it was doing.
 */
#if defined(MY_DEF_HERE) && defined(MY_DEF_HERE)
static noinline void
update_existing_ref(struct btrfs_trans_handle *trans,
		    struct btrfs_delayed_ref_root *delayed_refs,
		    struct btrfs_delayed_ref_head *head,
		    struct btrfs_delayed_ref_node *existing,
		    struct btrfs_delayed_ref_node *update, struct inode *inode, uid_t uid)
#else
static noinline void
update_existing_ref(struct btrfs_trans_handle *trans,
		    struct btrfs_delayed_ref_root *delayed_refs,
		    struct btrfs_delayed_ref_head *head,
		    struct btrfs_delayed_ref_node *existing,
		    struct btrfs_delayed_ref_node *update)
#endif /* MY_DEF_HERE && MY_DEF_HERE */
{
	if (update->action != existing->action) {
		/*
		 * this is effectively undoing either an add or a
		 * drop.  We decrement the ref_mod, and if it goes
		 * down to zero we just delete the entry without
		 * every changing the extent allocation tree.
		 */
		existing->ref_mod--;
		if (existing->ref_mod == 0)
#ifdef MY_DEF_HERE
		{
			if (BTRFS_EXTENT_DATA_REF_KEY == existing->type) {
				btrfs_qgroup_release_delayed_free(trans->root, existing->num_bytes);
#ifdef MY_DEF_HERE
				btrfs_usrquota_release_delayed_free(trans->root, inode, uid, existing->num_bytes);
#endif /* MY_DEF_HERE */
			}
			drop_delayed_ref(trans, delayed_refs, head, existing);
		}
#else
			drop_delayed_ref(trans, delayed_refs, head, existing);
#endif
		else
			WARN_ON(existing->type == BTRFS_TREE_BLOCK_REF_KEY ||
				existing->type == BTRFS_SHARED_BLOCK_REF_KEY);
	} else {
		WARN_ON(existing->type == BTRFS_TREE_BLOCK_REF_KEY ||
			existing->type == BTRFS_SHARED_BLOCK_REF_KEY);
		/*
		 * the action on the existing ref matches
		 * the action on the ref we're trying to add.
		 * Bump the ref_mod by one so the backref that
		 * is eventually added/removed has the correct
		 * reference count
		 */
		existing->ref_mod += update->ref_mod;
	}
}

/*
 * helper function to update the accounting in the head ref
 * existing and update must have the same bytenr
 */
static noinline void
#ifdef MY_DEF_HERE
update_existing_head_ref(struct btrfs_fs_info *fs_info,
			 struct btrfs_delayed_ref_root *delayed_refs,
			 struct btrfs_delayed_ref_node *existing,
			 struct btrfs_delayed_ref_node *update)
#else
update_existing_head_ref(struct btrfs_delayed_ref_root *delayed_refs,
			 struct btrfs_delayed_ref_node *existing,
			 struct btrfs_delayed_ref_node *update)
#endif /* MY_DEF_HERE */
{
	struct btrfs_delayed_ref_head *existing_ref;
	struct btrfs_delayed_ref_head *ref;
	int old_ref_mod;

	existing_ref = btrfs_delayed_node_to_head(existing);
	ref = btrfs_delayed_node_to_head(update);
	BUG_ON(existing_ref->is_data != ref->is_data);

	spin_lock(&existing_ref->lock);
	if (ref->must_insert_reserved) {
		/* if the extent was freed and then
		 * reallocated before the delayed ref
		 * entries were processed, we can end up
		 * with an existing head ref without
		 * the must_insert_reserved flag set.
		 * Set it again here
		 */
		existing_ref->must_insert_reserved = ref->must_insert_reserved;

		/*
		 * update the num_bytes so we make sure the accounting
		 * is done correctly
		 */
		existing->num_bytes = update->num_bytes;

	}

	if (ref->extent_op) {
		if (!existing_ref->extent_op) {
			existing_ref->extent_op = ref->extent_op;
		} else {
			if (ref->extent_op->update_key) {
				memcpy(&existing_ref->extent_op->key,
				       &ref->extent_op->key,
				       sizeof(ref->extent_op->key));
				existing_ref->extent_op->update_key = 1;
			}
			if (ref->extent_op->update_flags) {
				existing_ref->extent_op->flags_to_set |=
					ref->extent_op->flags_to_set;
				existing_ref->extent_op->update_flags = 1;
			}
			btrfs_free_delayed_extent_op(ref->extent_op);
		}
	}
	/*
	 * update the reference mod on the head to reflect this new operation,
	 * only need the lock for this case cause we could be processing it
	 * currently, for refs we just added we know we're a-ok.
	 */
	old_ref_mod = existing_ref->total_ref_mod;
	existing->ref_mod += update->ref_mod;
	existing_ref->total_ref_mod += update->ref_mod;

#ifdef MY_DEF_HERE
	if (!existing_ref->syno_usage && ref->syno_usage) {
		existing_ref->syno_usage = ref->syno_usage;
		if (existing_ref->processing == 0)
			delayed_refs->num_syno_usage_heads_ready++;
	}
#endif /* MY_DEF_HERE */

	/*
	 * If we are going to from a positive ref mod to a negative or vice
	 * versa we need to make sure to adjust pending_csums accordingly.
	 */
	if (existing_ref->is_data) {
#ifdef MY_DEF_HERE
		u64 csum_leaves = btrfs_csum_bytes_to_leaves(fs_info->tree_root, existing->num_bytes);
		if (existing_ref->total_ref_mod >= 0 && old_ref_mod < 0) {
			delayed_refs->pending_csums -= existing->num_bytes;
			delayed_refs->num_pending_csums_leafs -= csum_leaves;
		}
		if (existing_ref->total_ref_mod < 0 && old_ref_mod >= 0) {
			delayed_refs->pending_csums += existing->num_bytes;
			delayed_refs->num_pending_csums_leafs += csum_leaves;
		}
#else
		if (existing_ref->total_ref_mod >= 0 && old_ref_mod < 0)
			delayed_refs->pending_csums -= existing->num_bytes;
		if (existing_ref->total_ref_mod < 0 && old_ref_mod >= 0)
			delayed_refs->pending_csums += existing->num_bytes;
#endif /* MY_DEF_HERE */
	}
	spin_unlock(&existing_ref->lock);
}

/*
 * helper function to actually insert a head node into the rbtree.
 * this does all the dirty work in terms of maintaining the correct
 * overall modification count.
 */
static noinline struct btrfs_delayed_ref_head *
add_delayed_ref_head(struct btrfs_fs_info *fs_info,
		     struct btrfs_trans_handle *trans,
		     struct btrfs_delayed_ref_node *ref, u64 bytenr,
		     u64 num_bytes, int action, int is_data
#ifdef MY_DEF_HERE
		     ,int syno_usage
#endif /* MY_DEF_HERE */
		     )
{
	struct btrfs_delayed_ref_head *existing;
	struct btrfs_delayed_ref_head *head_ref = NULL;
	struct btrfs_delayed_ref_root *delayed_refs;
	int count_mod = 1;
	int must_insert_reserved = 0;

	/*
	 * the head node stores the sum of all the mods, so dropping a ref
	 * should drop the sum in the head node by one.
	 */
	if (action == BTRFS_UPDATE_DELAYED_HEAD)
		count_mod = 0;
	else if (action == BTRFS_DROP_DELAYED_REF)
		count_mod = -1;

	/*
	 * BTRFS_ADD_DELAYED_EXTENT means that we need to update
	 * the reserved accounting when the extent is finally added, or
	 * if a later modification deletes the delayed ref without ever
	 * inserting the extent into the extent allocation tree.
	 * ref->must_insert_reserved is the flag used to record
	 * that accounting mods are required.
	 *
	 * Once we record must_insert_reserved, switch the action to
	 * BTRFS_ADD_DELAYED_REF because other special casing is not required.
	 */
	if (action == BTRFS_ADD_DELAYED_EXTENT)
		must_insert_reserved = 1;
	else
		must_insert_reserved = 0;

	delayed_refs = &trans->transaction->delayed_refs;

	/* first set the basic ref node struct up */
	atomic_set(&ref->refs, 1);
	ref->bytenr = bytenr;
	ref->num_bytes = num_bytes;
	ref->ref_mod = count_mod;
	ref->type  = 0;
	ref->action  = 0;
	ref->is_head = 1;
	ref->in_tree = 1;
	ref->seq = 0;
#ifdef MY_DEF_HERE
	INIT_LIST_HEAD(&ref->syno_list);
#endif /* MY_DEF_HERE */

	head_ref = btrfs_delayed_node_to_head(ref);
	head_ref->must_insert_reserved = must_insert_reserved;
	head_ref->is_data = is_data;
	head_ref->ref_root = RB_ROOT;
	head_ref->processing = 0;
	head_ref->total_ref_mod = count_mod;
#ifdef MY_DEF_HERE
	head_ref->syno_usage = syno_usage;
	INIT_LIST_HEAD(&head_ref->ref_syno_list);
#endif /* MY_DEF_HERE */

	spin_lock_init(&head_ref->lock);
	mutex_init(&head_ref->mutex);

	trace_add_delayed_ref_head(fs_info, ref, head_ref, action);

	existing = htree_insert(&delayed_refs->href_root,
				&head_ref->href_node);
	if (existing) {
#ifdef MY_DEF_HERE
		update_existing_head_ref(fs_info, delayed_refs, &existing->node, ref);
#else
		update_existing_head_ref(delayed_refs, &existing->node, ref);
#endif /* MY_DEF_HERE */
		/*
		 * we've updated the existing ref, free the newly
		 * allocated ref
		 */
		kmem_cache_free(btrfs_delayed_ref_head_cachep, head_ref);
		head_ref = existing;
	} else {
#ifdef MY_DEF_HERE
		if (is_data && count_mod < 0) {
			delayed_refs->pending_csums += num_bytes;
			delayed_refs->num_pending_csums_leafs += btrfs_csum_bytes_to_leaves(fs_info->tree_root, num_bytes);
		}
#else
		if (is_data && count_mod < 0)
			delayed_refs->pending_csums += num_bytes;
#endif /* MY_DEF_HERE */
		delayed_refs->num_heads++;
		delayed_refs->num_heads_ready++;
#ifdef MY_DEF_HERE
		if (head_ref->syno_usage)
			delayed_refs->num_syno_usage_heads_ready++;
#endif /* MY_DEF_HERE */
		atomic_inc(&delayed_refs->num_entries);
		trans->delayed_ref_updates++;
	}
#ifdef MY_DEF_HERE
	if (is_data)
		__percpu_counter_add(&fs_info->delayed_data_ref, 1, SZ_128M);
	else
		__percpu_counter_add(&fs_info->delayed_meta_ref, 1, SZ_128M);
#endif /* MY_DEF_HERE */

	return head_ref;
}

/*
 * helper to insert a delayed tree ref into the rbtree.
 */
static noinline void
add_delayed_tree_ref(struct btrfs_fs_info *fs_info,
		     struct btrfs_trans_handle *trans,
		     struct btrfs_delayed_ref_head *head_ref,
		     struct btrfs_delayed_ref_node *ref, u64 bytenr,
		     u64 num_bytes, u64 parent, u64 ref_root, int level,
		     int action, int no_quota)
{
	struct btrfs_delayed_ref_node *existing;
	struct btrfs_delayed_tree_ref *full_ref;
	struct btrfs_delayed_ref_root *delayed_refs;
	u64 seq = 0;

	if (action == BTRFS_ADD_DELAYED_EXTENT)
		action = BTRFS_ADD_DELAYED_REF;

	if (is_fstree(ref_root))
		seq = atomic64_read(&fs_info->tree_mod_seq);
	delayed_refs = &trans->transaction->delayed_refs;

	/* first set the basic ref node struct up */
	atomic_set(&ref->refs, 1);
	ref->bytenr = bytenr;
	ref->num_bytes = num_bytes;
	ref->ref_mod = 1;
	ref->action = action;
	ref->is_head = 0;
	ref->in_tree = 1;
#ifdef MY_DEF_HERE
	/* we don't calculate metadata for quota */
	ref->no_quota = 1;
#else
	ref->no_quota = no_quota;
#endif /* MY_DEF_HERE */
	ref->seq = seq;
#ifdef MY_DEF_HERE
	INIT_LIST_HEAD(&ref->syno_list);
#endif /* MY_DEF_HERE */

	full_ref = btrfs_delayed_node_to_tree_ref(ref);
	full_ref->parent = parent;
	full_ref->root = ref_root;
	if (parent)
		ref->type = BTRFS_SHARED_BLOCK_REF_KEY;
	else
		ref->type = BTRFS_TREE_BLOCK_REF_KEY;
	full_ref->level = level;

	trace_add_delayed_tree_ref(fs_info, ref, full_ref, action);

	spin_lock(&head_ref->lock);
	existing = tree_insert(&head_ref->ref_root, &ref->rb_node);
	if (existing) {
#if defined(MY_DEF_HERE) && defined(MY_DEF_HERE)
		update_existing_ref(trans, delayed_refs, head_ref, existing,
				    ref, NULL, 0);
#else
		update_existing_ref(trans, delayed_refs, head_ref, existing,
				    ref);
#endif
		/*
		 * we've updated the existing ref, free the newly
		 * allocated ref
		 */
		kmem_cache_free(btrfs_delayed_tree_ref_cachep, full_ref);
	} else {
		atomic_inc(&delayed_refs->num_entries);
		trans->delayed_ref_updates++;
	}
	spin_unlock(&head_ref->lock);
}

/*
 * helper to insert a delayed data ref into the rbtree.
 */
static noinline void
add_delayed_data_ref(struct btrfs_fs_info *fs_info,
		     struct btrfs_trans_handle *trans,
		     struct btrfs_delayed_ref_head *head_ref,
		     struct btrfs_delayed_ref_node *ref, u64 bytenr,
		     u64 num_bytes, u64 parent, u64 ref_root, u64 owner,
		     int no_quota,
#ifdef MY_DEF_HERE
		     u64 ram_bytes,
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
		     struct inode *inode, uid_t uid,
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
		     int syno_usage,
#endif /* MY_DEF_HERE */
		     u64 offset, int action)
{
	struct btrfs_delayed_ref_node *existing;
	struct btrfs_delayed_data_ref *full_ref;
	struct btrfs_delayed_ref_root *delayed_refs;
	u64 seq = 0;

	if (action == BTRFS_ADD_DELAYED_EXTENT)
		action = BTRFS_ADD_DELAYED_REF;

	delayed_refs = &trans->transaction->delayed_refs;

	if (is_fstree(ref_root))
		seq = atomic64_read(&fs_info->tree_mod_seq);

	/* first set the basic ref node struct up */
	atomic_set(&ref->refs, 1);
	ref->bytenr = bytenr;
	ref->num_bytes = num_bytes;
	ref->ref_mod = 1;
	ref->action = action;
	ref->is_head = 0;
	ref->in_tree = 1;
	ref->no_quota = no_quota;
	ref->seq = seq;
#ifdef MY_DEF_HERE
	INIT_LIST_HEAD(&ref->syno_list);
#endif /* MY_DEF_HERE */

	full_ref = btrfs_delayed_node_to_data_ref(ref);
	full_ref->parent = parent;
	full_ref->root = ref_root;
	if (parent)
		ref->type = BTRFS_SHARED_DATA_REF_KEY;
	else
		ref->type = BTRFS_EXTENT_DATA_REF_KEY;

	full_ref->objectid = owner;
	full_ref->offset = offset;
#ifdef MY_DEF_HERE
	full_ref->ram_bytes = ram_bytes;
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	full_ref->uid = uid;
	if (!no_quota) {
		full_ref->inode = syno_usrquota_inode_get(inode);
	} else {
		full_ref->inode = NULL;
	}
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	full_ref->syno_usage = syno_usage;
#endif /* MY_DEF_HERE */

	trace_add_delayed_data_ref(fs_info, ref, full_ref, action);

	spin_lock(&head_ref->lock);
	existing = tree_insert(&head_ref->ref_root, &ref->rb_node);
	if (existing) {
#if defined(MY_DEF_HERE) && defined(MY_DEF_HERE)
		update_existing_ref(trans, delayed_refs, head_ref, existing,
				    ref, inode, uid);
#else
		update_existing_ref(trans, delayed_refs, head_ref, existing,
				    ref);
#endif
		/*
		 * we've updated the existing ref, free the newly
		 * allocated ref
		 */
#ifdef MY_DEF_HERE
		syno_usrquota_inode_put(full_ref->inode);
#endif /* MY_DEF_HERE */
		kmem_cache_free(btrfs_delayed_data_ref_cachep, full_ref);
	} else {
		atomic_inc(&delayed_refs->num_entries);
#ifdef MY_DEF_HERE
		if (full_ref->syno_usage)
			atomic_inc(&delayed_refs->num_syno_usage_entries);
#endif /* MY_DEF_HERE */
		trans->delayed_ref_updates++;
	}
	spin_unlock(&head_ref->lock);
}

/*
 * add a delayed tree ref.  This does all of the accounting required
 * to make sure the delayed ref is eventually processed before this
 * transaction commits.
 */
int btrfs_add_delayed_tree_ref(struct btrfs_fs_info *fs_info,
			       struct btrfs_trans_handle *trans,
			       u64 bytenr, u64 num_bytes, u64 parent,
			       u64 ref_root,  int level, int action,
			       struct btrfs_delayed_extent_op *extent_op,
			       int no_quota)
{
	struct btrfs_delayed_tree_ref *ref;
	struct btrfs_delayed_ref_head *head_ref;
	struct btrfs_delayed_ref_root *delayed_refs;
#ifdef MY_DEF_HERE
	struct btrfs_root *search_root = NULL;
	struct btrfs_key search_key;
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
	if (!is_fstree(ref_root) || !BTRFS_ANY_QUOTA_ENABLED(fs_info))
		no_quota = 1;
#else
	if (!is_fstree(ref_root) || !fs_info->quota_enabled)
		no_quota = 0;
#endif

#ifdef MY_DEF_HERE
	search_key.objectid = ref_root;
	search_key.type = BTRFS_ROOT_ITEM_KEY;
	search_key.offset = (u64)-1;
	search_root = btrfs_read_fs_root_no_name(fs_info, &search_key);
	if (!IS_ERR(search_root) && btrfs_root_disable_quota(search_root))
		no_quota = 1;
#endif /* MY_DEF_HERE */

	BUG_ON(extent_op && extent_op->is_data);
	ref = kmem_cache_alloc(btrfs_delayed_tree_ref_cachep, GFP_NOFS);
	if (!ref)
		return -ENOMEM;

	head_ref = kmem_cache_alloc(btrfs_delayed_ref_head_cachep, GFP_NOFS);
	if (!head_ref) {
		kmem_cache_free(btrfs_delayed_tree_ref_cachep, ref);
		return -ENOMEM;
	}

	head_ref->extent_op = extent_op;

	delayed_refs = &trans->transaction->delayed_refs;
	spin_lock(&delayed_refs->lock);

	/*
	 * insert both the head node and the new ref without dropping
	 * the spin lock
	 */
	head_ref = add_delayed_ref_head(fs_info, trans, &head_ref->node,
					bytenr, num_bytes, action, 0
#ifdef MY_DEF_HERE
					,0
#endif /* MY_DEF_HERE */
					);

	add_delayed_tree_ref(fs_info, trans, head_ref, &ref->node, bytenr,
				   num_bytes, parent, ref_root, level, action,
				   no_quota);
	spin_unlock(&delayed_refs->lock);

	return 0;
}

/*
 * add a delayed data ref. it's similar to btrfs_add_delayed_tree_ref.
 */
int btrfs_add_delayed_data_ref(struct btrfs_fs_info *fs_info,
			       struct btrfs_trans_handle *trans,
			       u64 bytenr, u64 num_bytes,
			       u64 parent, u64 ref_root,
			       u64 owner, u64 offset,
#ifdef MY_DEF_HERE
			       u64 ram_bytes,
#endif /* MY_DEF_HERE */
			       int no_quota,
#ifdef MY_DEF_HERE
			       struct inode *inode, uid_t uid,
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
			       int syno_usage,
#endif /* MY_DEF_HERE */
			       int action,
			       struct btrfs_delayed_extent_op *extent_op)
{
	struct btrfs_delayed_data_ref *ref;
	struct btrfs_delayed_ref_head *head_ref;
	struct btrfs_delayed_ref_root *delayed_refs;
#ifdef MY_DEF_HERE
	struct btrfs_root *search_root = NULL;
	struct btrfs_key search_key;
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
	if (!is_fstree(ref_root) || !BTRFS_ANY_QUOTA_ENABLED(fs_info))
		no_quota = 1;
#else
	if (!is_fstree(ref_root) || !fs_info->quota_enabled)
		no_quota = 0;
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
	search_key.objectid = ref_root;
	search_key.type = BTRFS_ROOT_ITEM_KEY;
	search_key.offset = (u64)-1;
	search_root = btrfs_read_fs_root_no_name(fs_info, &search_key);
	if (!IS_ERR(search_root) && btrfs_root_disable_quota(search_root))
		no_quota = 1;
#endif /* MY_DEF_HERE */

	BUG_ON(extent_op && !extent_op->is_data);
	ref = kmem_cache_alloc(btrfs_delayed_data_ref_cachep, GFP_NOFS);
	if (!ref)
		return -ENOMEM;

	head_ref = kmem_cache_alloc(btrfs_delayed_ref_head_cachep, GFP_NOFS);
	if (!head_ref) {
		kmem_cache_free(btrfs_delayed_data_ref_cachep, ref);
		return -ENOMEM;
	}

	head_ref->extent_op = extent_op;

	delayed_refs = &trans->transaction->delayed_refs;
	spin_lock(&delayed_refs->lock);

	/*
	 * insert both the head node and the new ref without dropping
	 * the spin lock
	 */
	head_ref = add_delayed_ref_head(fs_info, trans, &head_ref->node,
					bytenr, num_bytes, action, 1
#ifdef MY_DEF_HERE
					,syno_usage
#endif /* MY_DEF_HERE */
					);

	add_delayed_data_ref(fs_info, trans, head_ref, &ref->node, bytenr,
				   num_bytes, parent, ref_root, owner,
				   no_quota,
#ifdef MY_DEF_HERE
				   ram_bytes,
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
				   inode, uid,
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
				   syno_usage,
#endif /* MY_DEF_HERE */
				   offset, action);
	spin_unlock(&delayed_refs->lock);

	return 0;
}

int btrfs_add_delayed_extent_op(struct btrfs_fs_info *fs_info,
				struct btrfs_trans_handle *trans,
				u64 bytenr, u64 num_bytes,
				struct btrfs_delayed_extent_op *extent_op)
{
	struct btrfs_delayed_ref_head *head_ref;
	struct btrfs_delayed_ref_root *delayed_refs;

	head_ref = kmem_cache_alloc(btrfs_delayed_ref_head_cachep, GFP_NOFS);
	if (!head_ref)
		return -ENOMEM;

	head_ref->extent_op = extent_op;

	delayed_refs = &trans->transaction->delayed_refs;
	spin_lock(&delayed_refs->lock);

	add_delayed_ref_head(fs_info, trans, &head_ref->node, bytenr,
				   num_bytes, BTRFS_UPDATE_DELAYED_HEAD,
				   extent_op->is_data
#ifdef MY_DEF_HERE
				   ,0
#endif /* MY_DEF_HERE */
				   );

	spin_unlock(&delayed_refs->lock);
	return 0;
}

/*
 * this does a simple search for the head node for a given extent.
 * It must be called with the delayed ref spinlock held, and it returns
 * the head node if any where found, or NULL if not.
 */
struct btrfs_delayed_ref_head *
btrfs_find_delayed_ref_head(struct btrfs_delayed_ref_root *delayed_refs, u64 bytenr)
{
	return find_ref_head(&delayed_refs->href_root, bytenr, 0);
}

void btrfs_delayed_ref_exit(void)
{
	if (btrfs_delayed_ref_head_cachep)
		kmem_cache_destroy(btrfs_delayed_ref_head_cachep);
	if (btrfs_delayed_tree_ref_cachep)
		kmem_cache_destroy(btrfs_delayed_tree_ref_cachep);
	if (btrfs_delayed_data_ref_cachep)
		kmem_cache_destroy(btrfs_delayed_data_ref_cachep);
	if (btrfs_delayed_extent_op_cachep)
		kmem_cache_destroy(btrfs_delayed_extent_op_cachep);
}

int __init btrfs_delayed_ref_init(void)
{
	btrfs_delayed_ref_head_cachep = kmem_cache_create(
				"btrfs_delayed_ref_head",
				sizeof(struct btrfs_delayed_ref_head), 0,
				SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_delayed_ref_head_cachep)
		goto fail;

	btrfs_delayed_tree_ref_cachep = kmem_cache_create(
				"btrfs_delayed_tree_ref",
				sizeof(struct btrfs_delayed_tree_ref), 0,
				SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_delayed_tree_ref_cachep)
		goto fail;

	btrfs_delayed_data_ref_cachep = kmem_cache_create(
				"btrfs_delayed_data_ref",
				sizeof(struct btrfs_delayed_data_ref), 0,
				SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_delayed_data_ref_cachep)
		goto fail;

	btrfs_delayed_extent_op_cachep = kmem_cache_create(
				"btrfs_delayed_extent_op",
				sizeof(struct btrfs_delayed_extent_op), 0,
				SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);
	if (!btrfs_delayed_extent_op_cachep)
		goto fail;

	return 0;
fail:
	btrfs_delayed_ref_exit();
	return -ENOMEM;
}
