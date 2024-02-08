#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 *  linux/fs/stat.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#include "synoacl_int.h"
#endif /* MY_ABC_HERE */
void generic_fillattr(struct inode *inode, struct kstat *stat)
{
	stat->dev = inode->i_sb->s_dev;
	stat->ino = inode->i_ino;
	stat->mode = inode->i_mode;
	stat->nlink = inode->i_nlink;
	stat->uid = inode->i_uid;
	stat->gid = inode->i_gid;
	stat->rdev = inode->i_rdev;
	stat->size = i_size_read(inode);
	stat->atime = inode->i_atime;
	stat->mtime = inode->i_mtime;
	stat->ctime = inode->i_ctime;
	stat->blksize = i_blocksize(inode);
	stat->blocks = inode->i_blocks;
}

EXPORT_SYMBOL(generic_fillattr);

/**
 * vfs_getattr_nosec - getattr without security checks
 * @path: file to get attributes from
 * @stat: structure to return attributes in
 *
 * Get attributes without calling security_inode_getattr.
 *
 * Currently the only caller other than vfs_getattr is internal to the
 * filehandle lookup code, which uses only the inode number and returns
 * no attributes to any user.  Any other code probably wants
 * vfs_getattr.
 */
int vfs_getattr_nosec(struct path *path, struct kstat *stat)
{
	struct inode *inode = d_backing_inode(path->dentry);
#ifdef MY_ABC_HERE
	int retval;
	if (IS_SYNOACL(path->dentry)) {
		if (inode->i_op->getattr) {
			if (0 != (retval = inode->i_op->getattr(path->mnt, path->dentry, stat)))
				return retval;
		} else {
			generic_fillattr(inode, stat);
		}

		synoacl_op_to_mode(path->dentry, stat);

		return 0;
	}
#endif /* MY_ABC_HERE */

	if (inode->i_op->getattr)
		return inode->i_op->getattr(path->mnt, path->dentry, stat);

	generic_fillattr(inode, stat);
	return 0;
}

EXPORT_SYMBOL(vfs_getattr_nosec);

int vfs_getattr(struct path *path, struct kstat *stat)
{
	int retval;

	retval = security_inode_getattr(path);
	if (retval)
		return retval;
	return vfs_getattr_nosec(path, stat);
}

EXPORT_SYMBOL(vfs_getattr);

int vfs_fstat(unsigned int fd, struct kstat *stat)
{
	struct fd f = fdget_raw(fd);
	int error = -EBADF;

	if (f.file) {
		error = vfs_getattr(&f.file->f_path, stat);
		fdput(f);
	}
	return error;
}
EXPORT_SYMBOL(vfs_fstat);

int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat,
		int flag)
{
	struct path path;
	int error = -EINVAL;
	unsigned int lookup_flags = 0;

	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
		      AT_EMPTY_PATH)) != 0)
		goto out;

	if (!(flag & AT_SYMLINK_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	if (flag & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;
retry:
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (error)
		goto out;

	error = vfs_getattr(&path, stat);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}
EXPORT_SYMBOL(vfs_fstatat);

int vfs_stat(const char __user *name, struct kstat *stat)
{
	return vfs_fstatat(AT_FDCWD, name, stat, 0);
}
EXPORT_SYMBOL(vfs_stat);

int vfs_lstat(const char __user *name, struct kstat *stat)
{
	return vfs_fstatat(AT_FDCWD, name, stat, AT_SYMLINK_NOFOLLOW);
}
EXPORT_SYMBOL(vfs_lstat);

#ifdef MY_ABC_HERE
int __always_inline syno_vfs_getattr(struct path *path, struct kstat *stat, int stat_flags)
{
	int error = 0;

	error = vfs_getattr(path, stat);
	if ((!error) && stat_flags) {
		struct inode *inode = path->dentry->d_inode;

		if (inode->i_op->syno_getattr) {
			error = inode->i_op->syno_getattr(path->dentry, stat, stat_flags);
		} else {
#ifdef MY_ABC_HERE
			stat->syno_archive_bit = inode->i_archive_bit;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			stat->syno_archive_version = inode->i_archive_version;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			stat->syno_create_time = inode->i_create_time;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
			stat->syno_compressed = 0;
#endif
		}
	}
	return error;
}

// copy from vfs_fstat
int syno_vfs_fstat(unsigned int fd, struct kstat *stat, int stat_flags)
{
	struct fd f = fdget_raw(fd);
	int error = -EBADF;

	if (f.file) {
		error = syno_vfs_getattr(&f.file->f_path, stat, stat_flags);
		fdput(f);
	}
	return error;
}
EXPORT_SYMBOL(syno_vfs_fstat);

int syno_vfs_fstatat(const char __user *name, struct kstat *stat, int lookup_flags, int stat_flags)
{
	struct path path;
	int error = -EINVAL;

retry:
	error = user_path_at(AT_FDCWD, name, lookup_flags, &path);
	if (error)
		goto out;

	error = syno_vfs_getattr(&path, stat, stat_flags);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}

out:
	return error;
}
EXPORT_SYMBOL(syno_vfs_fstatat);
#endif /* MY_ABC_HERE */

#ifdef __ARCH_WANT_OLD_STAT

/*
 * For backward compatibility?  Maybe this should be moved
 * into arch/i386 instead?
 */
static int cp_old_stat(struct kstat *stat, struct __old_kernel_stat __user * statbuf)
{
	static int warncount = 5;
	struct __old_kernel_stat tmp;
	
	if (warncount > 0) {
		warncount--;
		printk(KERN_WARNING "VFS: Warning: %s using old stat() call. Recompile your binary.\n",
			current->comm);
	} else if (warncount < 0) {
		/* it's laughable, but... */
		warncount = 0;
	}

	memset(&tmp, 0, sizeof(struct __old_kernel_stat));
	tmp.st_dev = old_encode_dev(stat->dev);
	tmp.st_ino = stat->ino;
	if (sizeof(tmp.st_ino) < sizeof(stat->ino) && tmp.st_ino != stat->ino)
		return -EOVERFLOW;
	tmp.st_mode = stat->mode;
	tmp.st_nlink = stat->nlink;
	if (tmp.st_nlink != stat->nlink)
		return -EOVERFLOW;
	SET_UID(tmp.st_uid, from_kuid_munged(current_user_ns(), stat->uid));
	SET_GID(tmp.st_gid, from_kgid_munged(current_user_ns(), stat->gid));
	tmp.st_rdev = old_encode_dev(stat->rdev);
#if BITS_PER_LONG == 32
	if (stat->size > MAX_NON_LFS)
		return -EOVERFLOW;
#endif	
	tmp.st_size = stat->size;
	tmp.st_atime = stat->atime.tv_sec;
	tmp.st_mtime = stat->mtime.tv_sec;
	tmp.st_ctime = stat->ctime.tv_sec;
	return copy_to_user(statbuf,&tmp,sizeof(tmp)) ? -EFAULT : 0;
}

SYSCALL_DEFINE2(stat, const char __user *, filename,
		struct __old_kernel_stat __user *, statbuf)
{
	struct kstat stat;
	int error;

#ifdef MY_ABC_HERE
	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_filename_log(filename);
	}
#endif /* MY_ABC_HERE */

	error = vfs_stat(filename, &stat);
	if (error)
		return error;

	return cp_old_stat(&stat, statbuf);
}

SYSCALL_DEFINE2(lstat, const char __user *, filename,
		struct __old_kernel_stat __user *, statbuf)
{
	struct kstat stat;
	int error;

	error = vfs_lstat(filename, &stat);
	if (error)
		return error;

	return cp_old_stat(&stat, statbuf);
}

SYSCALL_DEFINE2(fstat, unsigned int, fd, struct __old_kernel_stat __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_old_stat(&stat, statbuf);

	return error;
}

#endif /* __ARCH_WANT_OLD_STAT */

#if BITS_PER_LONG == 32
#  define choose_32_64(a,b) a
#else
#  define choose_32_64(a,b) b
#endif

#define valid_dev(x)  choose_32_64(old_valid_dev,new_valid_dev)(x)
#define encode_dev(x) choose_32_64(old_encode_dev,new_encode_dev)(x)

#ifndef INIT_STRUCT_STAT_PADDING
#  define INIT_STRUCT_STAT_PADDING(st) memset(&st, 0, sizeof(st))
#endif

static int cp_new_stat(struct kstat *stat, struct stat __user *statbuf)
{
	struct stat tmp;

	if (!valid_dev(stat->dev) || !valid_dev(stat->rdev))
		return -EOVERFLOW;
#if BITS_PER_LONG == 32
	if (stat->size > MAX_NON_LFS)
		return -EOVERFLOW;
#endif

	INIT_STRUCT_STAT_PADDING(tmp);
	tmp.st_dev = encode_dev(stat->dev);
	tmp.st_ino = stat->ino;
	if (sizeof(tmp.st_ino) < sizeof(stat->ino) && tmp.st_ino != stat->ino)
		return -EOVERFLOW;
	tmp.st_mode = stat->mode;
	tmp.st_nlink = stat->nlink;
	if (tmp.st_nlink != stat->nlink)
		return -EOVERFLOW;
	SET_UID(tmp.st_uid, from_kuid_munged(current_user_ns(), stat->uid));
	SET_GID(tmp.st_gid, from_kgid_munged(current_user_ns(), stat->gid));
	tmp.st_rdev = encode_dev(stat->rdev);
	tmp.st_size = stat->size;
	tmp.st_atime = stat->atime.tv_sec;
	tmp.st_mtime = stat->mtime.tv_sec;
	tmp.st_ctime = stat->ctime.tv_sec;
#ifdef STAT_HAVE_NSEC
	tmp.st_atime_nsec = stat->atime.tv_nsec;
	tmp.st_mtime_nsec = stat->mtime.tv_nsec;
	tmp.st_ctime_nsec = stat->ctime.tv_nsec;
#endif
	tmp.st_blocks = stat->blocks;
	tmp.st_blksize = stat->blksize;
	return copy_to_user(statbuf,&tmp,sizeof(tmp)) ? -EFAULT : 0;
}

SYSCALL_DEFINE2(newstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	struct kstat stat;
#ifdef MY_ABC_HERE
	int error;

	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_filename_log(filename);
	}
	error = vfs_stat(filename, &stat);
#else
	int error = vfs_stat(filename, &stat);
#endif /* MY_ABC_HERE */

	if (error)
		return error;
	return cp_new_stat(&stat, statbuf);
}

SYSCALL_DEFINE2(newlstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	struct kstat stat;
	int error;

	error = vfs_lstat(filename, &stat);
	if (error)
		return error;

	return cp_new_stat(&stat, statbuf);
}

#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)
SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
		struct stat __user *, statbuf, int, flag)
{
	struct kstat stat;
	int error;

	error = vfs_fstatat(dfd, filename, &stat, flag);
	if (error)
		return error;
	return cp_new_stat(&stat, statbuf);
}
#endif

SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	struct kstat stat;
#ifdef MY_ABC_HERE
	int error;

	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_fd_log(fd);
	}
	error = vfs_fstat(fd, &stat);
#else
	int error = vfs_fstat(fd, &stat);
#endif /* MY_ABC_HERE */

	if (!error)
		error = cp_new_stat(&stat, statbuf);

	return error;
}

SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
		char __user *, buf, int, bufsiz)
{
	struct path path;
	int error;
	int empty = 0;
	unsigned int lookup_flags = LOOKUP_EMPTY;

	if (bufsiz <= 0)
		return -EINVAL;

retry:
	error = user_path_at_empty(dfd, pathname, lookup_flags, &path, &empty);
	if (!error) {
		struct inode *inode = d_backing_inode(path.dentry);

		error = empty ? -ENOENT : -EINVAL;
		if (inode->i_op->readlink) {
			error = security_inode_readlink(path.dentry);
			if (!error) {
				touch_atime(&path);
				error = inode->i_op->readlink(path.dentry,
							      buf, bufsiz);
			}
		}
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf,
		int, bufsiz)
{
	return sys_readlinkat(AT_FDCWD, path, buf, bufsiz);
}


/* ---------- LFS-64 ----------- */
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)

#ifndef INIT_STRUCT_STAT64_PADDING
#  define INIT_STRUCT_STAT64_PADDING(st) memset(&st, 0, sizeof(st))
#endif

static long cp_new_stat64(struct kstat *stat, struct stat64 __user *statbuf)
{
	struct stat64 tmp;

	INIT_STRUCT_STAT64_PADDING(tmp);
#ifdef CONFIG_MIPS
	/* mips has weird padding, so we don't get 64 bits there */
	tmp.st_dev = new_encode_dev(stat->dev);
	tmp.st_rdev = new_encode_dev(stat->rdev);
#else
	tmp.st_dev = huge_encode_dev(stat->dev);
	tmp.st_rdev = huge_encode_dev(stat->rdev);
#endif
	tmp.st_ino = stat->ino;
	if (sizeof(tmp.st_ino) < sizeof(stat->ino) && tmp.st_ino != stat->ino)
		return -EOVERFLOW;
#ifdef STAT64_HAS_BROKEN_ST_INO
	tmp.__st_ino = stat->ino;
#endif
	tmp.st_mode = stat->mode;
	tmp.st_nlink = stat->nlink;
	tmp.st_uid = from_kuid_munged(current_user_ns(), stat->uid);
	tmp.st_gid = from_kgid_munged(current_user_ns(), stat->gid);
	tmp.st_atime = stat->atime.tv_sec;
	tmp.st_atime_nsec = stat->atime.tv_nsec;
	tmp.st_mtime = stat->mtime.tv_sec;
	tmp.st_mtime_nsec = stat->mtime.tv_nsec;
	tmp.st_ctime = stat->ctime.tv_sec;
	tmp.st_ctime_nsec = stat->ctime.tv_nsec;
	tmp.st_size = stat->size;
	tmp.st_blocks = stat->blocks;
	tmp.st_blksize = stat->blksize;
	return copy_to_user(statbuf,&tmp,sizeof(tmp)) ? -EFAULT : 0;
}

SYSCALL_DEFINE2(stat64, const char __user *, filename,
		struct stat64 __user *, statbuf)
{
	struct kstat stat;
#ifdef MY_ABC_HERE
	int error;

	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_filename_log(filename);
	}
	error = vfs_stat(filename, &stat);
#else
	int error = vfs_stat(filename, &stat);
#endif /* MY_ABC_HERE */

	if (!error)
		error = cp_new_stat64(&stat, statbuf);

	return error;
}

SYSCALL_DEFINE2(lstat64, const char __user *, filename,
		struct stat64 __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_lstat(filename, &stat);

	if (!error)
		error = cp_new_stat64(&stat, statbuf);

	return error;
}

SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)
{
	struct kstat stat;
	int error = vfs_fstat(fd, &stat);

	if (!error)
		error = cp_new_stat64(&stat, statbuf);

	return error;
}

SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
		struct stat64 __user *, statbuf, int, flag)
{
	struct kstat stat;
	int error;

	error = vfs_fstatat(dfd, filename, &stat, flag);
	if (error)
		return error;
	return cp_new_stat64(&stat, statbuf);
}
#endif /* __ARCH_WANT_STAT64 || __ARCH_WANT_COMPAT_STAT64 */

#ifdef MY_ABC_HERE
/* This stat is used by caseless protocol.
 * The filename will be convert to real filename and return to user space.
 * In caller, the length of filename must equal or be larger than SYNO_SMB_PSTRING_LEN.
*/
int __SYNOCaselessStat(char __user * filename, int nofollowLink, struct kstat *stat, int flags)
{
	struct path path;
	int error;
	int f;
	char *real_filename = NULL;
	int real_filename_len = 0;

	real_filename = kmalloc(SYNO_SMB_PSTRING_LEN, GFP_KERNEL);
	if (!real_filename) {
		return -ENOMEM;
	}

	if (nofollowLink) {
		f = LOOKUP_CASELESS_COMPARE;
	} else {
		f = LOOKUP_FOLLOW|LOOKUP_CASELESS_COMPARE;
	}
	error = syno_user_path_at(AT_FDCWD, filename, f, &path, &real_filename, &real_filename_len);
	if (!error) {
#ifdef MY_ABC_HERE
		error = syno_vfs_getattr(&path, stat, flags);
#else
		error = vfs_getattr(&path, stat);
#endif /*MY_ABC_HERE */
		path_put(&path);
		if (real_filename_len) {
			error = copy_to_user(filename, real_filename, real_filename_len) ? -EFAULT : error;
		}
	}

	kfree(real_filename);
	return error;
}
EXPORT_SYMBOL(__SYNOCaselessStat);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#if (defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64))
SYSCALL_DEFINE2(syno_caseless_stat64, char __user *, filename, struct stat64 __user *, statbuf)
{
#ifdef MY_ABC_HERE
	long error = -1;
	struct kstat stat;

	memset(&stat, 0, sizeof(stat));
	error = __SYNOCaselessStat(filename, 0, &stat, 0);
	if (!error) {
		error = cp_new_stat64(&stat, statbuf);
	}

	return error;
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE2(SYNOCaselessStat64, char __user *, filename, struct stat64 __user *, statbuf)
{
	return sys_syno_caseless_stat64(filename, statbuf);
}

SYSCALL_DEFINE2(syno_caseless_lstat64, char __user *, filename, struct stat64 __user *, statbuf)
{
#ifdef MY_ABC_HERE
	long error = -1;
	struct kstat stat;

	memset(&stat, 0, sizeof(stat));
	error = __SYNOCaselessStat(filename, 1, &stat, 0);
	if (!error) {
		error = cp_new_stat64(&stat, statbuf);
	}

	return error;
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE2(SYNOCaselessLStat64, char __user *, filename, struct stat64 __user *, statbuf)
{
	return sys_syno_caseless_lstat64(filename, statbuf);
}

#endif /* __ARCH_WANT_STAT64 || __ARCH_WANT_COMPAT_STAT64 */
SYSCALL_DEFINE2(syno_caseless_stat, char __user *, filename, struct stat __user *, statbuf)
{
#ifdef MY_ABC_HERE
	long error = -1;
	struct kstat stat;

	memset(&stat, 0, sizeof(stat));
	error = __SYNOCaselessStat(filename, 0, &stat, 0);
	if (!error) {
		error = cp_new_stat(&stat, statbuf);
	}

	return error;
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE2(SYNOCaselessStat, char __user *, filename, struct stat __user *, statbuf)
{
	return sys_syno_caseless_stat(filename, statbuf);
}

SYSCALL_DEFINE2(syno_caseless_lstat, char __user *, filename, struct stat __user *, statbuf)
{
#ifdef MY_ABC_HERE
	long error = -1;
	struct kstat stat;

	memset(&stat, 0, sizeof(stat));
	error = __SYNOCaselessStat(filename, 1, &stat, 0);
	if (!error) {
		error = cp_new_stat(&stat, statbuf);
	}

	return error;
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE2(SYNOCaselessLStat, char __user *, filename, struct stat __user *, statbuf)
{
	return sys_syno_caseless_lstat(filename, statbuf);
}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#if (defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64))
struct SYNOSTAT64 {
	struct stat64 st;
	struct SYNOSTAT_EXTRA ext;
};
static long SYNOStat64CopyToUser(struct kstat *kst, unsigned int flags, struct SYNOSTAT64 __user * synostat)
{
	long error = -EFAULT;

	if (!synostat) {
		error = -EINVAL;
		goto out;
	}

	if (flags & SYNOST_STAT) {
		if (0 != (error = cp_new_stat64(kst, &synostat->st))) {
			goto out;
		}
	}

	if (__put_user(kst->syno_flags, &synostat->ext.flags)) {
		goto out;
	}

#ifdef MY_ABC_HERE
	if (flags & SYNOST_ARCHIVE_BIT) {
		if (__put_user(kst->syno_archive_bit, &synostat->ext.archive_bit)) {
			goto out;
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (flags & SYNOST_ARCHIVE_VER) {
		if (__put_user(kst->syno_archive_version, &synostat->ext.archive_version)) {
			goto out;
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (flags & SYNOST_CREATE_TIME) {
		if (copy_to_user(&synostat->ext.create_time, &kst->syno_create_time,
			             sizeof(synostat->ext.create_time))){
			goto out;
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (flags & SYNOST_COMPRESSION) {
		if (copy_to_user(&synostat->ext.compressed, &kst->syno_compressed, sizeof(synostat->ext.compressed))){
			goto out;
		}
	}
#endif

	error = 0;
out:
	return error;
}

static int do_SYNOStat64(char __user * filename, int no_follow_link, int flags, struct SYNOSTAT64 __user * synostat)
{
	long error = -EINVAL;
	struct kstat kst;

	memset(&kst, 0, sizeof(kst));
	if (flags & SYNOST_IS_CASELESS) {
#ifdef MY_ABC_HERE
		error = __SYNOCaselessStat(filename, no_follow_link, &kst, flags);
#else
		error = -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
	} else {
		if (no_follow_link) {
			error = syno_vfs_fstatat(filename, &kst, 0, flags);
		} else {
			error = syno_vfs_fstatat(filename, &kst, LOOKUP_FOLLOW, flags);
		}
	}

	if (error) {
		goto out;
	}

	error = SYNOStat64CopyToUser(&kst, flags, synostat);
out:
	return error;
}
#endif /* __ARCH_WANT_STAT64 || __ARCH_WANT_COMPAT_STAT64 */
static int SYNOStatCopyToUser(struct kstat *kst, unsigned int flags, struct SYNOSTAT __user * synostat)
{
	int error = -EFAULT;

	if (!synostat) {
		error = -EINVAL;
		goto out;
	}

	if (flags & SYNOST_STAT) {
		if(0 != (error = cp_new_stat(kst, &synostat->st))){
			goto out;
		}
	}

	if (__put_user(kst->syno_flags, &synostat->ext.flags)) {
		goto out;
	}

#ifdef MY_ABC_HERE
	if (flags & SYNOST_ARCHIVE_BIT) {
		if (__put_user(kst->syno_archive_bit, &synostat->ext.archive_bit)) {
			goto out;
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (flags & SYNOST_ARCHIVE_VER) {
		if (__put_user(kst->syno_archive_version, &synostat->ext.archive_version)) {
			goto out;
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (flags & SYNOST_CREATE_TIME) {
		if (copy_to_user(&synostat->ext.create_time, &kst->syno_create_time,
			             sizeof(synostat->ext.create_time))){
			goto out;
		}
	}
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
	if (flags & SYNOST_COMPRESSION) {
		if (copy_to_user(&synostat->ext.compressed, &kst->syno_compressed, sizeof(synostat->ext.compressed))){
			goto out;
		}
	}
#endif

	error = 0;
out:
	return error;
}

static int do_SYNOStat(char __user * filename, int no_follow_link, int flags, struct SYNOSTAT __user * synostat)
{
	long error = -EINVAL;
	struct kstat kst;

	memset(&kst, 0, sizeof(kst));
	if (flags & SYNOST_IS_CASELESS) {
#ifdef MY_ABC_HERE
		error = __SYNOCaselessStat(filename, no_follow_link, &kst, flags);
#else
		error = -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
	} else {
		if (no_follow_link) {
			error = syno_vfs_fstatat(filename, &kst, 0, flags);
		} else {
			error = syno_vfs_fstatat(filename, &kst, LOOKUP_FOLLOW, flags);
		}
	}

	if (error) {
		goto out;
	}

	error = SYNOStatCopyToUser(&kst, flags, synostat);
out:
	return error;
}

#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#if (defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64))
SYSCALL_DEFINE3(syno_stat64, char __user *, filename, unsigned int, flags, struct SYNOSTAT64 __user *, synostat)
{
#ifdef MY_ABC_HERE
	return do_SYNOStat64(filename, 0, flags, synostat);
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE3(SYNOStat64, char __user *, filename, unsigned int, flags, struct SYNOSTAT64 __user *, synostat)
{
	return sys_syno_stat64(filename, flags, synostat);
}

SYSCALL_DEFINE3(syno_fstat64, unsigned int, fd, unsigned int, flags, struct SYNOSTAT64 __user *, synostat)
{
#ifdef MY_ABC_HERE
	int error;
	struct kstat kst;

	memset(&kst, 0, sizeof(kst));
	error = syno_vfs_fstat(fd, &kst, flags);
	if (error) {
		return error;
	}

	return SYNOStat64CopyToUser(&kst, flags, synostat);
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE3(SYNOFStat64, unsigned int, fd, unsigned int, flags, struct SYNOSTAT64 __user *, synostat)
{
	return sys_syno_fstat64(fd, flags, synostat);
}

SYSCALL_DEFINE3(syno_lstat64, char __user *, filename, unsigned int, flags, struct SYNOSTAT64 __user *, synostat)
{
#ifdef MY_ABC_HERE
	return do_SYNOStat64(filename, 1, flags, synostat);
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE3(SYNOLStat64, char __user *, filename, unsigned int, flags, struct SYNOSTAT64 __user *, synostat)
{
	return sys_syno_lstat64(filename, flags, synostat);
}

#endif /* __ARCH_WANT_STAT64 || __ARCH_WANT_COMPAT_STAT64 */

SYSCALL_DEFINE3(syno_stat, char __user *, filename, unsigned int, flags, struct SYNOSTAT __user *, synostat)

{
#ifdef MY_ABC_HERE
	return do_SYNOStat(filename, 0, flags, synostat);
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE3(SYNOStat, char __user *, filename, unsigned int, flags, struct SYNOSTAT __user *, synostat)
{
	return sys_syno_stat(filename, flags, synostat);
}

SYSCALL_DEFINE3(syno_fstat, unsigned int, fd, unsigned int, flags, struct SYNOSTAT __user *, synostat)
{
#ifdef MY_ABC_HERE
	int error;
	struct kstat kst;

	memset(&kst, 0, sizeof(kst));
	error = syno_vfs_fstat(fd, &kst, flags);
	if (error) {
		return error;
	}

	return SYNOStatCopyToUser(&kst, flags, synostat);
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE3(SYNOFStat, unsigned int, fd, unsigned int, flags, struct SYNOSTAT __user *, synostat)
{
	return sys_syno_fstat(fd, flags, synostat);
}

SYSCALL_DEFINE3(syno_lstat, char __user *, filename, unsigned int, flags, struct SYNOSTAT __user *, synostat)
{
#ifdef MY_ABC_HERE
	return do_SYNOStat(filename, 1, flags, synostat);
#else
	return -EOPNOTSUPP;
#endif /* MY_ABC_HERE */
}
SYSCALL_DEFINE3(SYNOLStat, char __user *, filename, unsigned int, flags, struct SYNOSTAT __user *, synostat)
{
	return sys_syno_lstat(filename, flags, synostat);
}

#endif /* MY_ABC_HERE */

/* Caller is here responsible for sufficient locking (ie. inode->i_lock) */
void __inode_add_bytes(struct inode *inode, loff_t bytes)
{
	inode->i_blocks += bytes >> 9;
	bytes &= 511;
	inode->i_bytes += bytes;
	if (inode->i_bytes >= 512) {
		inode->i_blocks++;
		inode->i_bytes -= 512;
	}
}
EXPORT_SYMBOL(__inode_add_bytes);

void inode_add_bytes(struct inode *inode, loff_t bytes)
{
	spin_lock(&inode->i_lock);
	__inode_add_bytes(inode, bytes);
	spin_unlock(&inode->i_lock);
}

EXPORT_SYMBOL(inode_add_bytes);

void __inode_sub_bytes(struct inode *inode, loff_t bytes)
{
	inode->i_blocks -= bytes >> 9;
	bytes &= 511;
	if (inode->i_bytes < bytes) {
		inode->i_blocks--;
		inode->i_bytes += 512;
	}
	inode->i_bytes -= bytes;
}

EXPORT_SYMBOL(__inode_sub_bytes);

void inode_sub_bytes(struct inode *inode, loff_t bytes)
{
	spin_lock(&inode->i_lock);
	__inode_sub_bytes(inode, bytes);
	spin_unlock(&inode->i_lock);
}

EXPORT_SYMBOL(inode_sub_bytes);

loff_t inode_get_bytes(struct inode *inode)
{
	loff_t ret;

	spin_lock(&inode->i_lock);
	ret = (((loff_t)inode->i_blocks) << 9) + inode->i_bytes;
	spin_unlock(&inode->i_lock);
	return ret;
}

EXPORT_SYMBOL(inode_get_bytes);

void inode_set_bytes(struct inode *inode, loff_t bytes)
{
	/* Caller is here responsible for sufficient locking
	 * (ie. inode->i_lock) */
	inode->i_blocks = bytes >> 9;
	inode->i_bytes = bytes & 511;
}

EXPORT_SYMBOL(inode_set_bytes);

#ifdef MY_ABC_HERE
int vfs_quota_query(struct file *file, u64 *used, u64 *reserved, u64 *limit)
{
	if (!file->f_op->quota_query)
		return -EOPNOTSUPP;
	return file->f_op->quota_query(file, used, reserved, limit);
}
EXPORT_SYMBOL(vfs_quota_query);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
int vfs_syno_space_usage(struct file *file, struct syno_space_usage_info *info)
{
	if (!file->f_op->syno_space_usage)
		return -EOPNOTSUPP;
	return file->f_op->syno_space_usage(file, info);
}
EXPORT_SYMBOL(vfs_syno_space_usage);
#endif /* MY_ABC_HERE */

