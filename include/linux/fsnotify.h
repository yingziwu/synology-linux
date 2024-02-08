#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _LINUX_FS_NOTIFY_H
#define _LINUX_FS_NOTIFY_H

#include <linux/fsnotify_backend.h>
#include <linux/audit.h>
#include <linux/slab.h>
#include <linux/nsproxy.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>

#ifdef MY_ABC_HERE
#include <linux/xattr.h>
#endif

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
static inline void SYNO_ArchiveModify(struct inode *TargetInode, int blSetSMBArchive)
{
	struct dentry *dentry;
#ifdef MY_ABC_HERE
	u32 new_archive_bit;
	u32 old_archive_bit;
#endif
#ifdef MY_ABC_HERE
	u32 old_version;
	u32 new_version;
	int err;
#endif
	if (NULL == TargetInode) {
		return;
	}
	if (S_ISCHR(TargetInode->i_mode) || S_ISBLK(TargetInode->i_mode) ||
		S_ISFIFO(TargetInode->i_mode) || S_ISSOCK(TargetInode->i_mode)) {
		return;
	}
	dentry = d_find_alias(TargetInode);
	if (!dentry)
		return;

#ifdef MY_ABC_HERE
	mutex_lock(&TargetInode->i_syno_mutex);
	if (IS_GLUSTER_FS(TargetInode) || syno_op_get_archive_bit(dentry, &old_archive_bit)) {
		goto next;
	}

	if (blSetSMBArchive) {
		new_archive_bit = old_archive_bit | (S2_SMB_ARCHIVE|ALL_IARCHIVE);
	} else {
		new_archive_bit = old_archive_bit | ALL_IARCHIVE;
	}
	if (new_archive_bit == old_archive_bit) {
		goto next;
	}
	syno_op_set_archive_bit_nolock(dentry, new_archive_bit);
next:
	mutex_unlock(&TargetInode->i_syno_mutex);
#endif
#ifdef MY_ABC_HERE
	if (!TargetInode->i_op->syno_get_archive_ver)
		goto out;

	err = TargetInode->i_op->syno_get_archive_ver(dentry, &old_version);
	if (err)
		goto out;

	TargetInode->i_sb->s_op->syno_get_sb_archive_ver(TargetInode->i_sb, &new_version);
	if (err)
		goto out;

	new_version += 1;
	if (new_version != old_version)
		TargetInode->i_op->syno_set_archive_ver(dentry, new_version);
out:
#endif
	if (dentry) {
		dput(dentry);
	}
}
#endif

#ifdef MY_ABC_HERE
 
static inline struct vfsmount *get_vfsmount_by_sb(struct super_block *sb)
{
	struct list_head *head = NULL;
	struct vfsmount *mnt = NULL;
	struct nsproxy *nsproxy = NULL;
	if (!sb)
		return NULL;

	nsproxy = current->nsproxy;
	if (nsproxy) {
		struct mnt_namespace *mnt_space = nsproxy->mnt_ns;
		if(mnt_space){
			list_for_each(head, &mnt_space->list) {
				mnt = list_entry(head, struct vfsmount, mnt_list);
				if (mnt && mnt->mnt_sb == sb) {
					return mnt;
				}
			}
		}
	}
	return NULL;
}

static inline int SYNONotify(struct dentry *dentry, __u32 mask)
{
	char *dentry_path = NULL;
	struct path path;
	char *dentry_buf = NULL;
	int ret = 0;
	memset (&path, 0, sizeof(struct path));
	if(!dentry){
		ret = -EINVAL;
		goto ERR;
	}
	path.mnt = get_vfsmount_by_sb(dentry->d_sb);
	if(!path.mnt){
		ret = -EINVAL;
		goto ERR;
	}
	path.dentry = dentry;
	mntget(path.mnt);
	dentry_buf = kmalloc(PATH_MAX, GFP_NOFS);
	if(!dentry_buf){
		ret = -ENOMEM;
		goto ERR;
	}
	dentry_path = dentry_path_raw(dentry, dentry_buf, PATH_MAX-1);
	if (IS_ERR(dentry_path)) {
		ret = PTR_ERR(dentry_path);
		goto ERR;
	}
	SYNOFsnotify(mask, &path, FSNOTIFY_EVENT_SYNO, dentry_path, 0);
ERR:
	if (path.mnt)
		mntput(path.mnt);
	kfree(dentry_buf);
	return ret;
}
#endif  

static inline void fsnotify_d_instantiate(struct dentry *dentry,
					  struct inode *inode)
{
	__fsnotify_d_instantiate(dentry, inode);
}

static inline int fsnotify_parent(struct path *path, struct dentry *dentry, __u32 mask)
{
	if (!dentry)
		dentry = path->dentry;

	return __fsnotify_parent(path, dentry, mask);
}

static inline int fsnotify_perm(struct file *file, int mask)
{
	struct path *path = &file->f_path;
	struct inode *inode = path->dentry->d_inode;
	__u32 fsnotify_mask = 0;
	int ret;

	if (file->f_mode & FMODE_NONOTIFY)
		return 0;
	if (!(mask & (MAY_READ | MAY_OPEN)))
		return 0;
	if (mask & MAY_OPEN)
		fsnotify_mask = FS_OPEN_PERM;
	else if (mask & MAY_READ)
		fsnotify_mask = FS_ACCESS_PERM;
	else
		BUG();

	ret = fsnotify_parent(path, NULL, fsnotify_mask);
	if (ret)
		return ret;

	return fsnotify(inode, fsnotify_mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
}

static inline void fsnotify_d_move(struct dentry *dentry)
{
	 
	__fsnotify_update_dcache_flags(dentry);
}

static inline void fsnotify_link_count(struct inode *inode)
{
	fsnotify(inode, FS_ATTRIB, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
}

#ifdef MY_ABC_HERE
static inline void fsnotify_move(struct inode *old_dir, struct inode *new_dir,
				 const unsigned char *old_name,
				 int isdir, struct inode *target, struct dentry *moved, char *old_full_name, char *new_full_name)
#else
static inline void fsnotify_move(struct inode *old_dir, struct inode *new_dir,
				 const unsigned char *old_name,
				 int isdir, struct inode *target, struct dentry *moved)
#endif
{
	struct inode *source = moved->d_inode;
	u32 fs_cookie = fsnotify_get_cookie();
	__u32 old_dir_mask = (FS_EVENT_ON_CHILD | FS_MOVED_FROM);
	__u32 new_dir_mask = (FS_EVENT_ON_CHILD | FS_MOVED_TO);
	const unsigned char *new_name = moved->d_name.name;

#ifdef MY_ABC_HERE
	struct path path;
	memset (&path, 0, sizeof(struct path));
#endif
	if (old_dir == new_dir)
		old_dir_mask |= FS_DN_RENAME;

	if (isdir) {
		old_dir_mask |= FS_ISDIR;
		new_dir_mask |= FS_ISDIR;
	}

#ifdef MY_ABC_HERE
	 
	path.mnt = get_vfsmount_by_sb(old_dir->i_sb);
	if(path.mnt){
		mntget(path.mnt);
		SYNOFsnotify(old_dir_mask, &path, FSNOTIFY_EVENT_SYNO, old_full_name, fs_cookie);
		SYNOFsnotify(new_dir_mask, &path, FSNOTIFY_EVENT_SYNO, new_full_name, fs_cookie);
		mntput(path.mnt);
	}
#endif

	fsnotify(old_dir, old_dir_mask, old_dir, FSNOTIFY_EVENT_INODE, old_name, fs_cookie);
	fsnotify(new_dir, new_dir_mask, new_dir, FSNOTIFY_EVENT_INODE, new_name, fs_cookie);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(old_dir, 0);
	if (old_dir != new_dir) {
		SYNO_ArchiveModify(new_dir, 0);
	}
#endif

	if (target) {
		fsnotify_link_count(target);
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
		SYNO_ArchiveModify(target, 0);
#endif
	}

	if (source) {
		fsnotify(source, FS_MOVE_SELF, moved->d_inode, FSNOTIFY_EVENT_INODE, NULL, 0);
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
		SYNO_ArchiveModify(source, 1);
#endif
	}
	audit_inode_child(moved, new_dir);
}

static inline void fsnotify_inode_delete(struct inode *inode)
{
	__fsnotify_inode_delete(inode);
}

static inline void fsnotify_vfsmount_delete(struct vfsmount *mnt)
{
	__fsnotify_vfsmount_delete(mnt);
}

static inline void fsnotify_nameremove(struct dentry *dentry, int isdir)
{
	__u32 mask = FS_DELETE;

	if (isdir)
		mask |= FS_ISDIR;

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(dentry->d_parent->d_inode, 0);
#endif

#ifdef MY_ABC_HERE
	SYNONotify(dentry, mask);
#endif

	fsnotify_parent(NULL, dentry, mask);
}

static inline void fsnotify_inoderemove(struct inode *inode)
{
	fsnotify(inode, FS_DELETE_SELF, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
	__fsnotify_inode_delete(inode);
}

static inline void fsnotify_create(struct inode *inode, struct dentry *dentry)
{
	audit_inode_child(dentry, inode);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(dentry->d_inode, 0);
#endif

#ifdef MY_ABC_HERE
	SYNONotify(dentry, FS_CREATE);
#endif

	fsnotify(inode, FS_CREATE, dentry->d_inode, FSNOTIFY_EVENT_INODE, dentry->d_name.name, 0);
}

static inline void fsnotify_link(struct inode *dir, struct inode *inode, struct dentry *new_dentry)
{
	fsnotify_link_count(inode);
	audit_inode_child(new_dentry, dir);

#ifdef MY_ABC_HERE
	SYNONotify(new_dentry, FS_CREATE);
#endif
	fsnotify(dir, FS_CREATE, inode, FSNOTIFY_EVENT_INODE, new_dentry->d_name.name, 0);
}

static inline void fsnotify_mkdir(struct inode *inode, struct dentry *dentry)
{
	__u32 mask = (FS_CREATE | FS_ISDIR);
	struct inode *d_inode = dentry->d_inode;

	audit_inode_child(dentry, inode);

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(d_inode, 0);
#endif

#ifdef MY_ABC_HERE
	SYNONotify(dentry, mask);
#endif
	fsnotify(inode, mask, d_inode, FSNOTIFY_EVENT_INODE, dentry->d_name.name, 0);
}

static inline void fsnotify_access(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = path->dentry->d_inode;
	__u32 mask = FS_ACCESS;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	if (!(file->f_mode & FMODE_NONOTIFY)) {
		fsnotify_parent(path, NULL, mask);
		fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
	}
}

static inline void fsnotify_modify(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = path->dentry->d_inode;
	__u32 mask = FS_MODIFY;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	if (!(file->f_mode & FMODE_NONOTIFY)) {
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
		SYNO_ArchiveModify(inode, 1);
#endif
		fsnotify_parent(path, NULL, mask);
		fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
	}
}

static inline void fsnotify_open(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = path->dentry->d_inode;
	__u32 mask = FS_OPEN;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	fsnotify_parent(path, NULL, mask);
	fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
}

static inline void fsnotify_close(struct file *file)
{
	struct path *path = &file->f_path;
	struct inode *inode = file->f_path.dentry->d_inode;
	fmode_t mode = file->f_mode;
	__u32 mask = (mode & FMODE_WRITE) ? FS_CLOSE_WRITE : FS_CLOSE_NOWRITE;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	if (!(file->f_mode & FMODE_NONOTIFY)) {
		fsnotify_parent(path, NULL, mask);
		fsnotify(inode, mask, path, FSNOTIFY_EVENT_PATH, NULL, 0);
	}
}

static inline void fsnotify_xattr(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	__u32 mask = FS_ATTRIB;

	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	SYNO_ArchiveModify(inode, 1);
#endif
	fsnotify_parent(NULL, dentry, mask);

#ifdef MY_ABC_HERE
	SYNONotify(dentry, mask);
#endif

	fsnotify(inode, mask, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
}

static inline void fsnotify_change(struct dentry *dentry, unsigned int ia_valid)
{
	struct inode *inode = dentry->d_inode;
	__u32 mask = 0;

	if (ia_valid & ATTR_UID)
		mask |= FS_ATTRIB;
	if (ia_valid & ATTR_GID)
		mask |= FS_ATTRIB;
	if (ia_valid & ATTR_SIZE)
#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
	{
		mask |= FS_MODIFY;
		SYNO_ArchiveModify(inode, 1);
	}
#else
		mask |= FS_MODIFY;
#endif

	if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
		mask |= FS_ATTRIB;
	else if (ia_valid & ATTR_ATIME)
		mask |= FS_ACCESS;
	else if (ia_valid & ATTR_MTIME)
		mask |= FS_MODIFY;

	if (ia_valid & ATTR_MODE)
		mask |= FS_ATTRIB;

	if (mask) {
		if (S_ISDIR(inode->i_mode))
			mask |= FS_ISDIR;

		fsnotify_parent(NULL, dentry, mask);
#ifdef MY_ABC_HERE
	SYNONotify(dentry, mask);
#endif
		fsnotify(inode, mask, inode, FSNOTIFY_EVENT_INODE, NULL, 0);
	}
}

#if defined(CONFIG_FSNOTIFY)	 

static inline const unsigned char *fsnotify_oldname_init(const unsigned char *name)
{
	return kstrdup(name, GFP_KERNEL);
}

static inline void fsnotify_oldname_free(const unsigned char *old_name)
{
	kfree(old_name);
}

#else	 

static inline const char *fsnotify_oldname_init(const unsigned char *name)
{
	return NULL;
}

static inline void fsnotify_oldname_free(const unsigned char *old_name)
{
}

#endif	 

#endif	 
