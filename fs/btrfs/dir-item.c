#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"

/*
 * insert a name into a directory, doing overflow properly if there is a hash
 * collision.  data_size indicates how big the item inserted should be.  On
 * success a struct btrfs_dir_item pointer is returned, otherwise it is
 * an ERR_PTR.
 *
 * The name is not copied into the dir item, you have to do that yourself.
 */
static struct btrfs_dir_item *insert_with_overflow(struct btrfs_trans_handle
						   *trans,
						   struct btrfs_root *root,
						   struct btrfs_path *path,
						   struct btrfs_key *cpu_key,
						   u32 data_size,
						   const char *name,
						   int name_len)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	int ret;
	char *ptr;
	struct btrfs_item *item;
	struct extent_buffer *leaf;

	ret = btrfs_insert_empty_item(trans, root, path, cpu_key, data_size);
	if (ret == -EEXIST) {
		struct btrfs_dir_item *di;
		di = btrfs_match_dir_item_name(fs_info, path, name, name_len);
		if (di)
			return ERR_PTR(-EEXIST);
		btrfs_extend_item(path, data_size);
	} else if (ret < 0)
		return ERR_PTR(ret);
	WARN_ON(ret > 0);
	leaf = path->nodes[0];
	item = btrfs_item_nr(path->slots[0]);
	ptr = btrfs_item_ptr(leaf, path->slots[0], char);
	BUG_ON(data_size > btrfs_item_size(leaf, item));
	ptr += btrfs_item_size(leaf, item) - data_size;
	return (struct btrfs_dir_item *)ptr;
}

/*
 * xattrs work a lot like directories, this inserts an xattr item
 * into the tree
 */
int btrfs_insert_xattr_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 objectid,
			    const char *name, u16 name_len,
			    const void *data, u16 data_len)
{
	int ret = 0;
	struct btrfs_dir_item *dir_item;
	unsigned long name_ptr, data_ptr;
	struct btrfs_key key, location;
	struct btrfs_disk_key disk_key;
	struct extent_buffer *leaf;
	u32 data_size;

	if (name_len + data_len > BTRFS_MAX_XATTR_SIZE(root->fs_info))
		return -ENOSPC;

	key.objectid = objectid;
	key.type = BTRFS_XATTR_ITEM_KEY;
	key.offset = btrfs_name_hash(name, name_len);

	data_size = sizeof(*dir_item) + name_len + data_len;
	dir_item = insert_with_overflow(trans, root, path, &key, data_size,
					name, name_len);
	if (IS_ERR(dir_item))
		return PTR_ERR(dir_item);
	memset(&location, 0, sizeof(location));

	leaf = path->nodes[0];
	btrfs_cpu_key_to_disk(&disk_key, &location);
	btrfs_set_dir_item_key(leaf, dir_item, &disk_key);
	btrfs_set_dir_type(leaf, dir_item, BTRFS_FT_XATTR);
	btrfs_set_dir_name_len(leaf, dir_item, name_len);
	btrfs_set_dir_transid(leaf, dir_item, trans->transid);
	btrfs_set_dir_data_len(leaf, dir_item, data_len);
	name_ptr = (unsigned long)(dir_item + 1);
	data_ptr = (unsigned long)((char *)name_ptr + name_len);

	write_extent_buffer(leaf, name, name_ptr, name_len);
	write_extent_buffer(leaf, data, data_ptr, data_len);
	btrfs_mark_buffer_dirty(path->nodes[0]);

	return ret;
}

#ifdef MY_ABC_HERE
static int btrfs_insert_dir_item_caseless(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  const char *name, int name_len,
					  struct btrfs_inode *dir,
					  struct btrfs_disk_key *disk_key,
					  u8 type)
{
	int ret;
	unsigned long name_ptr;
	struct btrfs_path *path;
	struct btrfs_dir_item *dir_item;
	struct extent_buffer *leaf;
	struct btrfs_key key;
	u32 hash;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->leave_spinning = 1;

	key.objectid = btrfs_ino(dir);
	key.type = BTRFS_DIR_ITEM_CASELESS_KEY;
	ret = btrfs_upper_name_hash(name, name_len, &hash);
	if (ret)
		goto out_release;

	key.offset = hash;

	dir_item = insert_with_overflow(trans, root, path,
					&key, (sizeof(*dir_item) + name_len),
					name, name_len);
	if (IS_ERR(dir_item)) {
		ret = PTR_ERR(dir_item);
		if (ret == -EEXIST)
			ret = 0;
		goto out_release;
	}

	leaf = path->nodes[0];
	btrfs_set_dir_item_key(leaf, dir_item, disk_key);
	btrfs_set_dir_type(leaf, dir_item, type);
	btrfs_set_dir_data_len(leaf, dir_item, 0);
	btrfs_set_dir_name_len(leaf, dir_item, name_len);
	btrfs_set_dir_transid(leaf, dir_item, trans->transid);
	name_ptr = (unsigned long)(dir_item + 1);

	write_extent_buffer(leaf, name, name_ptr, name_len);
	btrfs_mark_buffer_dirty(leaf);
	ret = 0;

out_release:
	btrfs_free_path(path);
	return ret;
}
#endif /* MY_ABC_HERE */

/*
 * insert a directory item in the tree, doing all the magic for
 * both indexes. 'dir' indicates which objectid to insert it into,
 * 'location' is the key to stuff into the directory item, 'type' is the
 * type of the inode we're pointing to, and 'index' is the sequence number
 * to use for the second index (if one is created).
 * Will return 0 or -ENOMEM
 */
int btrfs_insert_dir_item(struct btrfs_trans_handle *trans, const char *name,
			  int name_len, struct btrfs_inode *dir,
			  struct btrfs_key *location, u8 type, u64 index)
{
	int ret = 0;
	int ret2 = 0;
	struct btrfs_root *root = dir->root;
	struct btrfs_path *path;
	struct btrfs_dir_item *dir_item;
	struct extent_buffer *leaf;
	unsigned long name_ptr;
	struct btrfs_key key;
	struct btrfs_disk_key disk_key;
	u32 data_size;

	key.objectid = btrfs_ino(dir);
	key.type = BTRFS_DIR_ITEM_KEY;
	key.offset = btrfs_name_hash(name, name_len);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;
	path->leave_spinning = 1;

	btrfs_cpu_key_to_disk(&disk_key, location);

	data_size = sizeof(*dir_item) + name_len;
	dir_item = insert_with_overflow(trans, root, path, &key, data_size,
					name, name_len);
	if (IS_ERR(dir_item)) {
		ret = PTR_ERR(dir_item);
		if (ret == -EEXIST)
			goto second_insert;
		goto out_free;
	}

	leaf = path->nodes[0];
	btrfs_set_dir_item_key(leaf, dir_item, &disk_key);
	btrfs_set_dir_type(leaf, dir_item, type);
	btrfs_set_dir_data_len(leaf, dir_item, 0);
	btrfs_set_dir_name_len(leaf, dir_item, name_len);
	btrfs_set_dir_transid(leaf, dir_item, trans->transid);
	name_ptr = (unsigned long)(dir_item + 1);

	write_extent_buffer(leaf, name, name_ptr, name_len);
	btrfs_mark_buffer_dirty(leaf);

second_insert:
	/* FIXME, use some real flag for selecting the extra index */
	if (root == root->fs_info->tree_root) {
		ret = 0;
		goto out_free;
	}
	btrfs_release_path(path);

	ret2 = btrfs_insert_delayed_dir_index(trans, name, name_len, dir,
					      &disk_key, type, index);
out_free:
	btrfs_free_path(path);
	if (ret)
		return ret;
	if (ret2)
		return ret2;
#ifdef MY_ABC_HERE
	if (btrfs_super_compat_flags(root->fs_info->super_copy) & BTRFS_FEATURE_COMPAT_SYNO_CASELESS) {
		ret = btrfs_insert_dir_item_caseless(trans, root,
						     name, name_len,
						     dir, &disk_key, type);
		if (ret) {
			btrfs_abort_transaction(trans, ret);
			return ret;
		}
	}
#endif /* MY_ABC_HERE */
	return 0;
}

#ifdef MY_ABC_HERE
/*
 *  linear lookup for syno btrfs caseless stat
 */
static struct btrfs_dir_item *btrfs_syno_linear_lookup_dir_item_caseless(
					     struct btrfs_root *root,
					     struct btrfs_path *path, u64 dir,
					     const char *name, int name_len)
{
	int ret;
	int slot;
	struct btrfs_item *item;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct extent_buffer *leaf;

	key.type = BTRFS_DIR_ITEM_KEY;
	key.offset = 0;
	key.objectid = dir;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		return ERR_PTR(ret);
	while (1) {
		leaf = path->nodes[0];
		slot = path->slots[0];
		if (slot >= btrfs_header_nritems(leaf)) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				return ERR_PTR(ret);
			if (ret > 0)
				return NULL;
			continue;
		}

		item = btrfs_item_nr(slot);
		btrfs_item_key_to_cpu(leaf, &found_key, slot);

		if (found_key.objectid != key.objectid)
			break;
		if (found_key.type != BTRFS_DIR_ITEM_KEY)
			break;
		if (NULL != (di = btrfs_match_dir_item_name(root->fs_info, path, name, name_len)))
			return di;

		path->slots[0]++;
	}
	return NULL;
}
#endif /* MY_ABC_HERE */

/*
 * lookup a directory item based on name.  'dir' is the objectid
 * we're searching in, and 'mod' tells us if you plan on deleting the
 * item (use mod < 0) or changing the options (use mod > 0)
 */
struct btrfs_dir_item *btrfs_lookup_dir_item(struct btrfs_trans_handle *trans,
					     struct btrfs_root *root,
					     struct btrfs_path *path, u64 dir,
					     const char *name, int name_len,
					     int mod)
{
	int ret;
	struct btrfs_key key;
	int ins_len = mod < 0 ? -1 : 0;
	int cow = mod != 0;
#ifdef MY_ABC_HERE
	u32 hash;
#endif /* MY_ABC_HERE */

	key.objectid = dir;
#ifdef MY_ABC_HERE
	if (path->search_caseless_key) {
		ret = btrfs_upper_name_hash(name, name_len, &hash);
		if (ret)
			return ERR_PTR(ret);
		key.offset = hash;
		key.type = BTRFS_DIR_ITEM_CASELESS_KEY;
		goto search;
	}
#endif /* MY_ABC_HERE */

	key.type = BTRFS_DIR_ITEM_KEY;

	key.offset = btrfs_name_hash(name, name_len);

#ifdef MY_ABC_HERE
search:
	if (!path->search_caseless_key && path->caseless_lookup)
		return btrfs_syno_linear_lookup_dir_item_caseless(root, path, dir, name, name_len);
#endif /* MY_ABC_HERE */

	ret = btrfs_search_slot(trans, root, &key, path, ins_len, cow);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret > 0)
		return NULL;

	return btrfs_match_dir_item_name(root->fs_info, path, name, name_len);
}

int btrfs_check_dir_item_collision(struct btrfs_root *root, u64 dir,
				   const char *name, int name_len
#ifdef MY_ABC_HERE
				   , int check_dir_item
#endif /* MY_ABC_HERE */
				   )
{
	int ret;
	struct btrfs_key key;
	struct btrfs_dir_item *di;
	int data_size;
	struct extent_buffer *leaf;
	int slot;
	struct btrfs_path *path;
#ifdef MY_ABC_HERE
	int caseless = 1;
	u32 hash;
#endif /* MY_ABC_HERE */

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

#ifdef MY_ABC_HERE
check_dir_item:
	key.objectid = dir;
	if (caseless) {
		if (!(btrfs_super_compat_flags(root->fs_info->super_copy) &
		      BTRFS_FEATURE_COMPAT_SYNO_CASELESS)) {
			ret = 0;
			goto out;
		}
		key.type = BTRFS_DIR_ITEM_CASELESS_KEY;
		ret = btrfs_upper_name_hash(name, name_len, &hash);
		if (ret)
			goto out;
		key.offset = hash;
	} else {
		key.type = BTRFS_DIR_ITEM_KEY;
		key.offset = btrfs_name_hash(name, name_len);
	}
#else /* MY_ABC_HERE */
	key.objectid = dir;
	key.type = BTRFS_DIR_ITEM_KEY;
	key.offset = btrfs_name_hash(name, name_len);
#endif /* MY_ABC_HERE */

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);

	/* return back any errors */
	if (ret < 0)
		goto out;

	/* nothing found, we're safe */
	if (ret > 0) {
		ret = 0;
		goto out;
	}

	/* we found an item, look for our name in the item */
	di = btrfs_match_dir_item_name(root->fs_info, path, name, name_len);
	if (di) {
		/* our exact name was found */
		ret = -EEXIST;
		goto out;
	}

	/*
	 * see if there is room in the item to insert this
	 * name
	 */
	data_size = sizeof(*di) + name_len;
	leaf = path->nodes[0];
	slot = path->slots[0];
	if (data_size + btrfs_item_size_nr(leaf, slot) +
	    sizeof(struct btrfs_item) > BTRFS_LEAF_DATA_SIZE(root->fs_info)) {
		ret = -EOVERFLOW;
	} else {
		/* plenty of insertion room */
		ret = 0;
	}
out:
#ifdef MY_ABC_HERE
	if (!ret && check_dir_item && caseless) {
		caseless = 0;
		btrfs_release_path(path);
		goto check_dir_item;
	}
#endif /* MY_ABC_HERE */
	btrfs_free_path(path);
	return ret;
}

/*
 * lookup a directory item based on index.  'dir' is the objectid
 * we're searching in, and 'mod' tells us if you plan on deleting the
 * item (use mod < 0) or changing the options (use mod > 0)
 *
 * The name is used to make sure the index really points to the name you were
 * looking for.
 */
struct btrfs_dir_item *
btrfs_lookup_dir_index_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 dir,
			    u64 objectid, const char *name, int name_len,
			    int mod)
{
	int ret;
	struct btrfs_key key;
	int ins_len = mod < 0 ? -1 : 0;
	int cow = mod != 0;

	key.objectid = dir;
	key.type = BTRFS_DIR_INDEX_KEY;
	key.offset = objectid;

	ret = btrfs_search_slot(trans, root, &key, path, ins_len, cow);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret > 0)
		return ERR_PTR(-ENOENT);
	return btrfs_match_dir_item_name(root->fs_info, path, name, name_len);
}

struct btrfs_dir_item *
btrfs_search_dir_index_item(struct btrfs_root *root,
			    struct btrfs_path *path, u64 dirid,
			    const char *name, int name_len)
{
	struct extent_buffer *leaf;
	struct btrfs_dir_item *di;
	struct btrfs_key key;
	u32 nritems;
	int ret;

	key.objectid = dirid;
	key.type = BTRFS_DIR_INDEX_KEY;
	key.offset = 0;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		return ERR_PTR(ret);

	leaf = path->nodes[0];
	nritems = btrfs_header_nritems(leaf);

	while (1) {
		if (path->slots[0] >= nritems) {
			ret = btrfs_next_leaf(root, path);
			if (ret < 0)
				return ERR_PTR(ret);
			if (ret > 0)
				break;
			leaf = path->nodes[0];
			nritems = btrfs_header_nritems(leaf);
			continue;
		}

		btrfs_item_key_to_cpu(leaf, &key, path->slots[0]);
		if (key.objectid != dirid || key.type != BTRFS_DIR_INDEX_KEY)
			break;

		di = btrfs_match_dir_item_name(root->fs_info, path,
					       name, name_len);
		if (di)
			return di;

		path->slots[0]++;
	}
	return NULL;
}

struct btrfs_dir_item *btrfs_lookup_xattr(struct btrfs_trans_handle *trans,
					  struct btrfs_root *root,
					  struct btrfs_path *path, u64 dir,
					  const char *name, u16 name_len,
					  int mod)
{
	int ret;
	struct btrfs_key key;
	int ins_len = mod < 0 ? -1 : 0;
	int cow = mod != 0;

	key.objectid = dir;
	key.type = BTRFS_XATTR_ITEM_KEY;
	key.offset = btrfs_name_hash(name, name_len);
	ret = btrfs_search_slot(trans, root, &key, path, ins_len, cow);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret > 0)
		return NULL;

	return btrfs_match_dir_item_name(root->fs_info, path, name, name_len);
}

/*
 * helper function to look at the directory item pointed to by 'path'
 * this walks through all the entries in a dir item and finds one
 * for a specific name.
 */
struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_fs_info *fs_info,
						 struct btrfs_path *path,
						 const char *name, int name_len)
{
	struct btrfs_dir_item *dir_item;
	unsigned long name_ptr;
	u32 total_len;
	u32 cur = 0;
	u32 this_len;
	struct extent_buffer *leaf;

	leaf = path->nodes[0];
	dir_item = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_dir_item);

	total_len = btrfs_item_size_nr(leaf, path->slots[0]);
	while (cur < total_len) {
		this_len = sizeof(*dir_item) +
			btrfs_dir_name_len(leaf, dir_item) +
			btrfs_dir_data_len(leaf, dir_item);
		name_ptr = (unsigned long)(dir_item + 1);

#ifdef MY_ABC_HERE
		if (path->caseless_lookup) {
			if (0 == memcmp_caseless_extent_buffer(leaf, name,
							       name_len,
							       name_ptr,
							       btrfs_dir_name_len(leaf, dir_item)))
				return dir_item;
		} else
#endif /* MY_ABC_HERE */
		if (btrfs_dir_name_len(leaf, dir_item) == name_len &&
		    memcmp_extent_buffer(leaf, name, name_ptr, name_len) == 0)
			return dir_item;

		cur += this_len;
		dir_item = (struct btrfs_dir_item *)((char *)dir_item +
						     this_len);
	}
	return NULL;
}

/*
 * given a pointer into a directory item, delete it.  This
 * handles items that have more than one entry in them.
 */
int btrfs_delete_one_dir_name(struct btrfs_trans_handle *trans,
			      struct btrfs_root *root,
			      struct btrfs_path *path,
			      struct btrfs_dir_item *di)
{

	struct extent_buffer *leaf;
	u32 sub_item_len;
	u32 item_len;
	int ret = 0;

	leaf = path->nodes[0];
	sub_item_len = sizeof(*di) + btrfs_dir_name_len(leaf, di) +
		btrfs_dir_data_len(leaf, di);
	item_len = btrfs_item_size_nr(leaf, path->slots[0]);
	if (sub_item_len == item_len) {
		ret = btrfs_del_item(trans, root, path);
	} else {
		/* MARKER */
		unsigned long ptr = (unsigned long)di;
		unsigned long start;

		start = btrfs_item_ptr_offset(leaf, path->slots[0]);
		memmove_extent_buffer(leaf, ptr, ptr + sub_item_len,
			item_len - (ptr + sub_item_len - start));
		btrfs_truncate_item(path, item_len - sub_item_len, 1);
	}
	return ret;
}
