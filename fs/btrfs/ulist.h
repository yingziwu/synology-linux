#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2011 STRATO AG
 * written by Arne Jansen <sensille@gmx.net>
 */

#ifndef BTRFS_ULIST_H
#define BTRFS_ULIST_H

#include <linux/list.h>
#include <linux/rbtree.h>

/*
 * ulist is a generic data structure to hold a collection of unique u64
 * values. The only operations it supports is adding to the list and
 * enumerating it.
 * It is possible to store an auxiliary value along with the key.
 *
 */
struct ulist_iterator {
	struct list_head *cur_list;  /* hint to start search */
};

/*
 * element of the list
 */
struct ulist_node {
	u64 val;		/* value to store */
	u64 aux;		/* auxiliary value saved along with the val */

	struct list_head list;  /* used to link node */
	struct rb_node rb_node;	/* used to speed up search */
};

struct ulist {
	/*
	 * number of elements stored in list
	 */
	unsigned long nnodes;

	struct list_head nodes;
	struct rb_root root;
};

void ulist_init(struct ulist *ulist);
void ulist_release(struct ulist *ulist);
void ulist_reinit(struct ulist *ulist);
struct ulist *ulist_alloc(gfp_t gfp_mask);
void ulist_free(struct ulist *ulist);
int ulist_add(struct ulist *ulist, u64 val, u64 aux, gfp_t gfp_mask);
int ulist_add_merge(struct ulist *ulist, u64 val, u64 aux,
		    u64 *old_aux, gfp_t gfp_mask);
#ifdef MY_ABC_HERE
int ulist_add_for_prealloc(struct ulist *ulist, u64 val, u64 aux, gfp_t gfp_mask, struct ulist_node **prealloc_ulist_node);
int ulist_add_merge_for_prealloc(struct ulist *ulist, u64 val, u64 aux, u64 *old_aux, gfp_t gfp_mask, struct ulist_node **prealloc_ulist_node);
#endif /* MY_ABC_HERE */
int ulist_del(struct ulist *ulist, u64 val, u64 aux);

/* just like ulist_add_merge() but take a pointer for the aux data */
static inline int ulist_add_merge_ptr(struct ulist *ulist, u64 val, void *aux,
				      void **old_aux, gfp_t gfp_mask)
{
#if BITS_PER_LONG == 32
	u64 old64 = (uintptr_t)*old_aux;
	int ret = ulist_add_merge(ulist, val, (uintptr_t)aux, &old64, gfp_mask);
	*old_aux = (void *)((uintptr_t)old64);
	return ret;
#else
	return ulist_add_merge(ulist, val, (u64)aux, (u64 *)old_aux, gfp_mask);
#endif
}

struct ulist_node *ulist_next(struct ulist *ulist,
			      struct ulist_iterator *uiter);

#define ULIST_ITER_INIT(uiter) ((uiter)->cur_list = NULL)

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define ULIST_NODES_MAX 65536 // 256MiB / 4KiB = 65536; 65536 ulist_node = 3.5MiB
int ulist_add_lru_adjust(struct ulist *ulist, u64 val, u64 aux, gfp_t gfp_mask);
void ulist_remove_first(struct ulist *ulist);
#endif /* MY_ABC_HERE || MY_ABC_HERE */

#ifdef MY_ABC_HERE
struct ulist_node * ulist_search(struct ulist *ulist, u64 val);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
struct ulist_node * ulist_search_with_prev(struct ulist *ulist, u64 val);
#endif /* MY_ABC_HERE */

#endif
