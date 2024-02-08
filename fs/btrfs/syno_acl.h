/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2000-2021 Synology Inc.
 */

#ifndef _BTRFS_SYNO_ACL_H
#define _BTRFS_SYNO_ACL_H

#include <linux/syno_acl.h>

#define BTRFS_SYNO_ACL_VERSION  0x0002

typedef struct {
	__le16          e_tag;
	__le16          e_inherit;
	__le32          e_perm;
	__le32          e_id;
} __attribute__ ((__packed__)) btrfs_syno_acl_entry_t;

typedef struct {
	__le16          a_version;
} __attribute__ ((__packed__)) btrfs_syno_acl_header_t;

int btrfs_set_syno_acl(struct inode *inode, struct syno_acl *acl);
struct syno_acl *btrfs_get_syno_acl(struct inode *inode);
struct syno_acl *btrfs_syno_acl_from_disk(const void *value, size_t size);

#endif /* _BTRFS_SYNO_ACL_H */
