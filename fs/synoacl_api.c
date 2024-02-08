#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 * linux/fs/synoacl_api.c
 *
 * Copyright (c) 2000-2014 Synology Inc.
 */

#ifdef MY_ABC_HERE
#include <linux/syscalls.h>
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/file.h>

#include "synoacl_int.h"


#define SYSCALL_OPS             synoacl_mod_info->syscall_ops
#define VFS_OPS                 synoacl_mod_info->vfs_ops

#define IS_MOD_INFO_READY       (synoacl_mod_info && SYSCALL_OPS && VFS_OPS)
#define IS_SYSCALL_ACL_READY(x) (IS_MOD_INFO_READY && SYSCALL_OPS->x)
#define IS_VFS_ACL_READY(x)     (IS_MOD_INFO_READY && VFS_OPS->x)

#define DO_SYSCALL(x, ...)      SYSCALL_OPS->x(__VA_ARGS__)
#define DO_VFS(x, ...)          VFS_OPS->x(__VA_ARGS__)

struct synoacl_mod_info *synoacl_mod_info = NULL;
EXPORT_SYMBOL(synoacl_mod_info);

bool syno_acl_module_get(void)
{
	/* If synoacl_vfs.ko wasn't loaded earlier then load it now.
	 * When synoacl_vfs is built into vmlinux the module's __init
	 * function will populate synoacl_mod_info.
	 */
	if (!synoacl_mod_info) {
		request_module("synoacl_vfs");
		if (!synoacl_mod_info) {
			pr_err("synoacl_vfs request_module failed.\n");
			return false;
		}
	}

	/* And grab the reference, so the module doesn't disappear while the
	 * kernel is interacting with the kernel module.
	 */
	if (!try_module_get(synoacl_mod_info->owner)) {
		pr_err("synoacl_vfs try_module_get failed.\n");
		return false;
	}
	return true;
}
EXPORT_SYMBOL(syno_acl_module_get);

void syno_acl_module_put(void)
{
	if (synoacl_mod_info)
		module_put(synoacl_mod_info->owner);
}
EXPORT_SYMBOL(syno_acl_module_put);

/* --------------- VFS API ---------------- */
int synoacl_mod_archive_change_ok(struct dentry *d, unsigned int cmd, int tag, int mask)
{
	if (IS_VFS_ACL_READY(archive_change_ok)) {
		return DO_VFS(archive_change_ok, d, cmd, tag, mask);
	}
	return 0; //is settable
}
EXPORT_SYMBOL(synoacl_mod_archive_change_ok);

int synoacl_mod_may_delete(struct dentry *d, struct inode *dir)
{
	if (IS_VFS_ACL_READY(syno_acl_may_delete)) {
		return DO_VFS(syno_acl_may_delete, d, dir, 1);
	}
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}
EXPORT_SYMBOL(synoacl_mod_may_delete);

int synoacl_mod_setattr_post(struct dentry *dentry, struct iattr *attr)
{
	if (IS_VFS_ACL_READY(syno_acl_setattr_post)) {
		return DO_VFS(syno_acl_setattr_post, dentry, attr);
	}
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(synoacl_mod_setattr_post);

int synoacl_mod_inode_change_ok(struct dentry *d, struct iattr *attr)
{
	if (IS_VFS_ACL_READY(syno_inode_change_ok)) {
		return DO_VFS(syno_inode_change_ok, d, attr);
	}
	return inode_change_ok(d->d_inode, attr);
}
EXPORT_SYMBOL(synoacl_mod_inode_change_ok);

void synoacl_mod_to_mode(struct dentry *d, struct kstat *stat)
{
	if (IS_VFS_ACL_READY(syno_acl_to_mode)) {
		DO_VFS(syno_acl_to_mode, d, stat);
	}
}
EXPORT_SYMBOL(synoacl_mod_to_mode);

int synoacl_mod_access(struct dentry *d, int mask, int syno_acl_access)
{
	if (IS_VFS_ACL_READY(syno_acl_access)) {
		return DO_VFS(syno_acl_access, d, mask, syno_acl_access);
	}
	return inode_permission(d->d_inode, mask);
}
EXPORT_SYMBOL(synoacl_mod_access);

int synoacl_mod_exec_permission(struct dentry *d)
{
	if (IS_VFS_ACL_READY(syno_acl_exec_permission)) {
		return DO_VFS(syno_acl_exec_permission, d);
	}
	return 0;
}
EXPORT_SYMBOL(synoacl_mod_exec_permission);

int synoacl_mod_permission(struct dentry *d, int mask)
{
	if (IS_VFS_ACL_READY(syno_acl_permission)) {
		return DO_VFS(syno_acl_permission, d, mask);
	}
	return 0;
}
EXPORT_SYMBOL(synoacl_mod_permission);

int synoacl_mod_get_acl_xattr(struct dentry *d, int cmd, void *value, size_t size)
{
	if (IS_VFS_ACL_READY(syno_acl_xattr_get)) {
		return DO_VFS(syno_acl_xattr_get, d, cmd, value, size);
	}
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(synoacl_mod_get_acl_xattr);

int synoacl_mod_init_acl(struct dentry *dentry, struct inode *inode)
{
	if (IS_VFS_ACL_READY(syno_acl_init)) {
		return DO_VFS(syno_acl_init, dentry, inode);
	}
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(synoacl_mod_init_acl);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
SYSCALL_DEFINE2(syno_acl_check_perm, const char __user *, name, int , mask)
{
#ifdef MY_ABC_HERE
	int is_path_get = 0;
	struct path path;
	struct inode * inode = NULL;
	int error = -EINVAL;

	error = user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
	if (error)
		goto out;

	is_path_get = 1;

	if (path.dentry && path.dentry->d_inode) {
		inode = path.dentry->d_inode;
	} else {
		goto out;
	}

	if (inode->i_op->syno_acl_sys_check_perm) {
		error = inode->i_op->syno_acl_sys_check_perm(path.dentry, mask);
		if (error != -EOPNOTSUPP) {
			goto out;
		}
	}
	if (IS_SYSCALL_ACL_READY(check_perm)) {
		error = DO_SYSCALL(check_perm, path.dentry, mask);
	} else {
		error = -EOPNOTSUPP;
	}

out:
	if (is_path_get) {
		path_put(&path);
	}
	return error;
#else
	return 0;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE2(SYNOACLCheckPerm, const char __user *, name, int , mask)
{
	return sys_syno_acl_check_perm(name, mask);
}

SYSCALL_DEFINE3(syno_acl_is_support, const char __user *, name, int , fd, int , tag)
{
#ifdef MY_ABC_HERE
	int is_path_get = 0;
	struct path path;
	struct file *fp = NULL;
	struct inode *inode = NULL;
	struct dentry *dentry = NULL;
	int error = -EINVAL;

	if (name) {
		error = user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
		if (error)
			goto out;

		is_path_get = 1;

		if (!path.dentry || !path.dentry->d_inode) {
			goto out;
		}
		inode = path.dentry->d_inode;
		dentry = path.dentry;
	} else if (fd >= 0) {
		fp = fget(fd);
		if (!fp || !fp->f_path.dentry){
			error = -EBADF;
			goto out;
		}
		inode = fp->f_path.dentry->d_inode;
		dentry = fp->f_path.dentry;
	} else {
		goto out;
	}

	if (inode->i_op->syno_acl_sys_is_support) {
		error = inode->i_op->syno_acl_sys_is_support(dentry, tag);
		if (error != -EOPNOTSUPP) {
			goto out;
		}
	}
	if (IS_SYSCALL_ACL_READY(is_acl_support)) {
		error = DO_SYSCALL(is_acl_support, dentry, tag);
	} else {
		error = -EOPNOTSUPP;
	}
out:
	if (is_path_get) {
		path_put(&path);
	}
	if (fp) {
		fput(fp);
	}

	return error;
#else
	return 0;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE3(SYNOACLIsSupport, const char __user *, name, int , fd, int , tag)
{
	return sys_syno_acl_is_support(name, fd, tag);
}

SYSCALL_DEFINE2(syno_acl_get_perm, const char __user *, name, int __user *, out_perm)
{
#ifdef MY_ABC_HERE
	int is_path_get = 0;
	unsigned int perm_allow = 0;
	int error = -EINVAL;
	struct path path;
	struct inode * inode = NULL;

	error = user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
	if (error)
		goto err;

	is_path_get = 1;

	if (path.dentry && path.dentry->d_inode) {
		inode = path.dentry->d_inode;
	} else {
		goto err;
	}

	if (IS_SYNOACL_SUPERUSER()) {
		perm_allow = SYNO_PERM_FULL_CONTROL;
		error = 0;
		goto end;
	}

	if (inode->i_op->syno_acl_sys_get_perm) {
		error = inode->i_op->syno_acl_sys_get_perm(path.dentry, &perm_allow);
		if (error != -EOPNOTSUPP) {
			goto end;
		}
	}
	if (IS_SYSCALL_ACL_READY(get_perm)) {
		error = DO_SYSCALL(get_perm, path.dentry, &perm_allow);
	} else {
		error = -EOPNOTSUPP;
	}
end:
	if (copy_to_user(out_perm, &perm_allow, sizeof(perm_allow))){
		error = -EFAULT;
		goto err;
	}

err:
	if (is_path_get) {
		path_put(&path);
	}

	return error;
#else
	return 0;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE2(SYNOACLGetPerm, const char __user *, name, int __user *, out_perm)
{
	return sys_syno_acl_get_perm(name, out_perm);
}
#endif /* MY_ABC_HERE */
