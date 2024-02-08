#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 *  linux/fs/read_write.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/slab.h> 
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include "internal.h"

#include <asm/uaccess.h>
#include <asm/unistd.h>
#ifdef CONFIG_SENDFILE_PATCH
    #include <net/sock.h>
#endif /* CONFIG_SENDFILE_PATCH */

#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#include <linux/backing-dev.h>
DEFINE_SPINLOCK(aggregate_lock);
#endif /* MY_ABC_HERE */

typedef ssize_t (*io_fn_t)(struct file *, char __user *, size_t, loff_t *);
typedef ssize_t (*iter_fn_t)(struct kiocb *, struct iov_iter *);

const struct file_operations generic_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_readonly_mmap,
	.splice_read	= generic_file_splice_read,
};

EXPORT_SYMBOL(generic_ro_fops);

static inline int unsigned_offsets(struct file *file)
{
	return file->f_mode & FMODE_UNSIGNED_OFFSET;
}

/**
 * vfs_setpos - update the file offset for lseek
 * @file:	file structure in question
 * @offset:	file offset to seek to
 * @maxsize:	maximum file size
 *
 * This is a low-level filesystem helper for updating the file offset to
 * the value specified by @offset if the given offset is valid and it is
 * not equal to the current file offset.
 *
 * Return the specified offset on success and -EINVAL on invalid offset.
 */
loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize)
{
	if (offset < 0 && !unsigned_offsets(file))
		return -EINVAL;
	if (offset > maxsize)
		return -EINVAL;

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}
	return offset;
}
EXPORT_SYMBOL(vfs_setpos);

/**
 * generic_file_llseek_size - generic llseek implementation for regular files
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 * @size:	max size of this file in file system
 * @eof:	offset used for SEEK_END position
 *
 * This is a variant of generic_file_llseek that allows passing in a custom
 * maximum file size and a custom EOF position, for e.g. hashed directories
 *
 * Synchronization:
 * SEEK_SET and SEEK_END are unsynchronized (but atomic on 64bit platforms)
 * SEEK_CUR is synchronized against other SEEK_CURs, but not read/writes.
 * read/writes behave like SEEK_SET against seeks.
 */
loff_t
generic_file_llseek_size(struct file *file, loff_t offset, int whence,
		loff_t maxsize, loff_t eof)
{
	switch (whence) {
	case SEEK_END:
		offset += eof;
		break;
	case SEEK_CUR:
		/*
		 * Here we special-case the lseek(fd, 0, SEEK_CUR)
		 * position-querying operation.  Avoid rewriting the "same"
		 * f_pos value back to the file because a concurrent read(),
		 * write() or lseek() might have altered it
		 */
		if (offset == 0)
			return file->f_pos;
		/*
		 * f_lock protects against read/modify/write race with other
		 * SEEK_CURs. Note that parallel writes and reads behave
		 * like SEEK_SET.
		 */
		spin_lock(&file->f_lock);
		offset = vfs_setpos(file, file->f_pos + offset, maxsize);
		spin_unlock(&file->f_lock);
		return offset;
	case SEEK_DATA:
		/*
		 * In the generic case the entire file is data, so as long as
		 * offset isn't at the end of the file then the offset is data.
		 */
		if ((unsigned long long)offset >= eof)
			return -ENXIO;
		break;
	case SEEK_HOLE:
		/*
		 * There is a virtual hole at the end of the file, so as long as
		 * offset isn't i_size or larger, return i_size.
		 */
		if ((unsigned long long)offset >= eof)
			return -ENXIO;
		offset = eof;
		break;
	}

	return vfs_setpos(file, offset, maxsize);
}
EXPORT_SYMBOL(generic_file_llseek_size);

/**
 * generic_file_llseek - generic llseek implementation for regular files
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 *
 * This is a generic implemenation of ->llseek useable for all normal local
 * filesystems.  It just updates the file offset to the value specified by
 * @offset and @whence.
 */
loff_t generic_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;

	return generic_file_llseek_size(file, offset, whence,
					inode->i_sb->s_maxbytes,
					i_size_read(inode));
}
EXPORT_SYMBOL(generic_file_llseek);

/**
 * fixed_size_llseek - llseek implementation for fixed-sized devices
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 * @size:	size of the file
 *
 */
loff_t fixed_size_llseek(struct file *file, loff_t offset, int whence, loff_t size)
{
	switch (whence) {
	case SEEK_SET: case SEEK_CUR: case SEEK_END:
		return generic_file_llseek_size(file, offset, whence,
						size, size);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL(fixed_size_llseek);

/**
 * noop_llseek - No Operation Performed llseek implementation
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 *
 * This is an implementation of ->llseek useable for the rare special case when
 * userspace expects the seek to succeed but the (device) file is actually not
 * able to perform the seek. In this case you use noop_llseek() instead of
 * falling back to the default implementation of ->llseek.
 */
loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
	return file->f_pos;
}
EXPORT_SYMBOL(noop_llseek);

loff_t no_llseek(struct file *file, loff_t offset, int whence)
{
	return -ESPIPE;
}
EXPORT_SYMBOL(no_llseek);

loff_t default_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t retval;

	inode_lock(inode);
	switch (whence) {
		case SEEK_END:
			offset += i_size_read(inode);
			break;
		case SEEK_CUR:
			if (offset == 0) {
				retval = file->f_pos;
				goto out;
			}
			offset += file->f_pos;
			break;
		case SEEK_DATA:
			/*
			 * In the generic case the entire file is data, so as
			 * long as offset isn't at the end of the file then the
			 * offset is data.
			 */
			if (offset >= inode->i_size) {
				retval = -ENXIO;
				goto out;
			}
			break;
		case SEEK_HOLE:
			/*
			 * There is a virtual hole at the end of the file, so
			 * as long as offset isn't i_size or larger, return
			 * i_size.
			 */
			if (offset >= inode->i_size) {
				retval = -ENXIO;
				goto out;
			}
			offset = inode->i_size;
			break;
	}
	retval = -EINVAL;
	if (offset >= 0 || unsigned_offsets(file)) {
		if (offset != file->f_pos) {
			file->f_pos = offset;
			file->f_version = 0;
		}
		retval = offset;
	}
out:
	inode_unlock(inode);
	return retval;
}
EXPORT_SYMBOL(default_llseek);

loff_t vfs_llseek(struct file *file, loff_t offset, int whence)
{
	loff_t (*fn)(struct file *, loff_t, int);

	fn = no_llseek;
	if (file->f_mode & FMODE_LSEEK) {
		if (file->f_op->llseek)
			fn = file->f_op->llseek;
	}
	return fn(file, offset, whence);
}
EXPORT_SYMBOL(vfs_llseek);

static inline struct fd fdget_pos(int fd)
{
	return __to_fd(__fdget_pos(fd));
}

static inline void fdput_pos(struct fd f)
{
	if (f.flags & FDPUT_POS_UNLOCK)
		mutex_unlock(&f.file->f_pos_lock);
	fdput(f);
}

SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
{
	off_t retval;
	struct fd f = fdget_pos(fd);
	if (!f.file)
		return -EBADF;

	retval = -EINVAL;
	if (whence <= SEEK_MAX) {
		loff_t res = vfs_llseek(f.file, offset, whence);
		retval = res;
		if (res != (loff_t)retval)
			retval = -EOVERFLOW;	/* LFS: should only happen on 32 bit platforms */
	}
	fdput_pos(f);
	return retval;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(lseek, unsigned int, fd, compat_off_t, offset, unsigned int, whence)
{
	return sys_lseek(fd, offset, whence);
}
#endif

#ifdef __ARCH_WANT_SYS_LLSEEK
SYSCALL_DEFINE5(llseek, unsigned int, fd, unsigned long, offset_high,
		unsigned long, offset_low, loff_t __user *, result,
		unsigned int, whence)
{
	int retval;
	struct fd f = fdget_pos(fd);
	loff_t offset;

	if (!f.file)
		return -EBADF;

	retval = -EINVAL;
	if (whence > SEEK_MAX)
		goto out_putf;

	offset = vfs_llseek(f.file, ((loff_t) offset_high << 32) | offset_low,
			whence);

	retval = (int)offset;
	if (offset >= 0) {
		retval = -EFAULT;
		if (!copy_to_user(result, &offset, sizeof(offset)))
			retval = 0;
	}
out_putf:
	fdput_pos(f);
	return retval;
}
#endif

ssize_t vfs_iter_read(struct file *file, struct iov_iter *iter, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	if (!file->f_op->read_iter)
		return -EINVAL;

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = *ppos;

	iter->type |= READ;
	ret = file->f_op->read_iter(&kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0)
		*ppos = kiocb.ki_pos;
	return ret;
}
EXPORT_SYMBOL(vfs_iter_read);

ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	if (!file->f_op->write_iter)
		return -EINVAL;

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = *ppos;

	iter->type |= WRITE;
	ret = file->f_op->write_iter(&kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0) {
		*ppos = kiocb.ki_pos;
		fsnotify_modify(file);
	}
	return ret;
}
EXPORT_SYMBOL(vfs_iter_write);

/*
 * rw_verify_area doesn't like huge counts. We limit
 * them to something that fits in "int" so that others
 * won't have to do range checks all the time.
 */
int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count)
{
	struct inode *inode;
	loff_t pos;
	int retval = -EINVAL;

	inode = file_inode(file);
	if (unlikely((ssize_t) count < 0))
		return retval;
	pos = *ppos;
	if (unlikely(pos < 0)) {
		if (!unsigned_offsets(file))
			return retval;
		if (count >= -pos) /* both values are in 0..LLONG_MAX */
			return -EOVERFLOW;
	} else if (unlikely((loff_t) (pos + count) < 0)) {
		if (!unsigned_offsets(file))
			return retval;
	}

	if (unlikely(inode->i_flctx && mandatory_lock(inode))) {
		retval = locks_mandatory_area(inode, file, pos, pos + count - 1,
				read_write == READ ? F_RDLCK : F_WRLCK);
		if (retval < 0)
			return retval;
	}
	retval = security_file_permission(file,
				read_write == READ ? MAY_READ : MAY_WRITE);
	if (retval)
		return retval;
	return count > MAX_RW_COUNT ? MAX_RW_COUNT : count;
}

static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	iov_iter_init(&iter, READ, &iov, 1, len);

	ret = filp->f_op->read_iter(&kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	*ppos = kiocb.ki_pos;
	return ret;
}

ssize_t __vfs_read(struct file *file, char __user *buf, size_t count,
		   loff_t *pos)
{
	if (file->f_op->read)
		return file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		return new_sync_read(file, buf, count, pos);
	else
		return -EINVAL;
}
EXPORT_SYMBOL(__vfs_read);

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
		return -EFAULT;

	ret = rw_verify_area(READ, file, pos, count);
	if (ret >= 0) {
		count = ret;
		ret = __vfs_read(file, buf, count, pos);
		if (ret > 0) {
			fsnotify_access(file);
			add_rchar(current, ret);
		}
		inc_syscr(current);
	}

	return ret;
}

EXPORT_SYMBOL(vfs_read);

static ssize_t new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	iov_iter_init(&iter, WRITE, &iov, 1, len);

	ret = filp->f_op->write_iter(&kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ret > 0)
		*ppos = kiocb.ki_pos;
	return ret;
}

ssize_t __vfs_write(struct file *file, const char __user *p, size_t count,
		    loff_t *pos)
{
	if (file->f_op->write)
		return file->f_op->write(file, p, count, pos);
	else if (file->f_op->write_iter)
		return new_sync_write(file, p, count, pos);
	else
		return -EINVAL;
}
EXPORT_SYMBOL(__vfs_write);

#ifdef CONFIG_AUFS_FHSM
vfs_readf_t vfs_readf(struct file *file)
{
	const struct file_operations *fop = file->f_op;

	if (fop->read)
		return fop->read;
	if (fop->read_iter)
		return new_sync_read;
	return ERR_PTR(-ENOSYS);
}
EXPORT_SYMBOL_GPL(vfs_readf);
#endif /* CONFIG_AUFS_FHSM */

#ifdef CONFIG_AUFS_FHSM
vfs_writef_t vfs_writef(struct file *file)
{
	const struct file_operations *fop = file->f_op;

	if (fop->write)
		return fop->write;
	if (fop->write_iter)
		return new_sync_write;
	return ERR_PTR(-ENOSYS);
}
EXPORT_SYMBOL_GPL(vfs_writef);
#endif /* CONFIG_AUFS_FHSM */

ssize_t __kernel_write(struct file *file, const char *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	const char __user *p;
	ssize_t ret;

	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	old_fs = get_fs();
	set_fs(get_ds());
	p = (__force const char __user *)buf;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;
	ret = __vfs_write(file, p, count, pos);
	set_fs(old_fs);
	if (ret > 0) {
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	return ret;
}

EXPORT_SYMBOL(__kernel_write);

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_READ, buf, count)))
		return -EFAULT;

	ret = rw_verify_area(WRITE, file, pos, count);
	if (ret >= 0) {
		count = ret;
		file_start_write(file);
		ret = __vfs_write(file, buf, count, pos);
		if (ret > 0) {
			fsnotify_modify(file);
			add_wchar(current, ret);
		}
		inc_syscw(current);
		file_end_write(file);
	}

	return ret;
}

EXPORT_SYMBOL(vfs_write);

static inline loff_t file_pos_read(struct file *file)
{
	return file->f_mode & FMODE_STREAM ? 0 : file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	if ((file->f_mode & FMODE_STREAM) == 0)
		file->f_pos = pos;
}

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

#ifdef MY_ABC_HERE
	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_fd_log(fd);
	}
#endif /* MY_ABC_HERE */

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_read(f.file, buf, count, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}
	return ret;
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

#ifdef MY_ABC_HERE
	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_fd_log(fd);
	}
#endif /* MY_ABC_HERE */

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_write(f.file, buf, count, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	return ret;
}

SYSCALL_DEFINE4(pread64, unsigned int, fd, char __user *, buf,
			size_t, count, loff_t, pos)
{
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PREAD)
			ret = vfs_read(f.file, buf, count, &pos);
		fdput(f);
	}

	return ret;
}

SYSCALL_DEFINE4(pwrite64, unsigned int, fd, const char __user *, buf,
			 size_t, count, loff_t, pos)
{
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PWRITE)  
			ret = vfs_write(f.file, buf, count, &pos);
		fdput(f);
	}

	return ret;
}

/*
 * Reduce an iovec's length in-place.  Return the resulting number of segments
 */
unsigned long iov_shorten(struct iovec *iov, unsigned long nr_segs, size_t to)
{
	unsigned long seg = 0;
	size_t len = 0;

	while (seg < nr_segs) {
		seg++;
		if (len + iov->iov_len >= to) {
			iov->iov_len = to - len;
			break;
		}
		len += iov->iov_len;
		iov++;
	}
	return seg;
}
EXPORT_SYMBOL(iov_shorten);

static ssize_t do_iter_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, iter_fn_t fn)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;

	ret = fn(&kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);
	*ppos = kiocb.ki_pos;
	return ret;
}

/* Do it by hand, with file-ops */
static ssize_t do_loop_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, io_fn_t fn)
{
	ssize_t ret = 0;

	while (iov_iter_count(iter)) {
		struct iovec iovec = iov_iter_iovec(iter);
		ssize_t nr;

		nr = fn(filp, iovec.iov_base, iovec.iov_len, ppos);

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (nr != iovec.iov_len)
			break;
		iov_iter_advance(iter, nr);
	}

	return ret;
}

/* A write operation does a read from user space and vice versa */
#define vrfy_dir(type) ((type) == READ ? VERIFY_WRITE : VERIFY_READ)

ssize_t rw_copy_check_uvector(int type, const struct iovec __user * uvector,
			      unsigned long nr_segs, unsigned long fast_segs,
			      struct iovec *fast_pointer,
			      struct iovec **ret_pointer)
{
	unsigned long seg;
	ssize_t ret;
	struct iovec *iov = fast_pointer;

	/*
	 * SuS says "The readv() function *may* fail if the iovcnt argument
	 * was less than or equal to 0, or greater than {IOV_MAX}.  Linux has
	 * traditionally returned zero for zero segments, so...
	 */
	if (nr_segs == 0) {
		ret = 0;
		goto out;
	}

	/*
	 * First get the "struct iovec" from user memory and
	 * verify all the pointers
	 */
	if (nr_segs > UIO_MAXIOV) {
		ret = -EINVAL;
		goto out;
	}
	if (nr_segs > fast_segs) {
		iov = kmalloc(nr_segs*sizeof(struct iovec), GFP_KERNEL);
		if (iov == NULL) {
			ret = -ENOMEM;
			goto out;
		}
	}
	if (copy_from_user(iov, uvector, nr_segs*sizeof(*uvector))) {
		ret = -EFAULT;
		goto out;
	}

	/*
	 * According to the Single Unix Specification we should return EINVAL
	 * if an element length is < 0 when cast to ssize_t or if the
	 * total length would overflow the ssize_t return value of the
	 * system call.
	 *
	 * Linux caps all read/write calls to MAX_RW_COUNT, and avoids the
	 * overflow case.
	 */
	ret = 0;
	for (seg = 0; seg < nr_segs; seg++) {
		void __user *buf = iov[seg].iov_base;
		ssize_t len = (ssize_t)iov[seg].iov_len;

		/* see if we we're about to use an invalid len or if
		 * it's about to overflow ssize_t */
		if (len < 0) {
			ret = -EINVAL;
			goto out;
		}
		if (type >= 0
		    && unlikely(!access_ok(vrfy_dir(type), buf, len))) {
			ret = -EFAULT;
			goto out;
		}
		if (len > MAX_RW_COUNT - ret) {
			len = MAX_RW_COUNT - ret;
			iov[seg].iov_len = len;
		}
		ret += len;
	}
out:
	*ret_pointer = iov;
	return ret;
}

static ssize_t do_readv_writev(int type, struct file *file,
			       const struct iovec __user * uvector,
			       unsigned long nr_segs, loff_t *pos)
{
	size_t tot_len;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	ssize_t ret;
	io_fn_t fn;
	iter_fn_t iter_fn;

	ret = import_iovec(type, uvector, nr_segs,
			   ARRAY_SIZE(iovstack), &iov, &iter);
	if (ret < 0)
		return ret;

	tot_len = iov_iter_count(&iter);
	if (!tot_len)
		goto out;
	ret = rw_verify_area(type, file, pos, tot_len);
	if (ret < 0)
		goto out;

	if (type == READ) {
		fn = file->f_op->read;
		iter_fn = file->f_op->read_iter;
	} else {
		fn = (io_fn_t)file->f_op->write;
		iter_fn = file->f_op->write_iter;
		file_start_write(file);
	}

	if (iter_fn)
		ret = do_iter_readv_writev(file, &iter, pos, iter_fn);
	else
		ret = do_loop_readv_writev(file, &iter, pos, fn);

	if (type != READ)
		file_end_write(file);

out:
	kfree(iov);
	if ((ret + (type == READ)) > 0) {
		if (type == READ)
			fsnotify_access(file);
		else
			fsnotify_modify(file);
	}
	return ret;
}

ssize_t vfs_readv(struct file *file, const struct iovec __user *vec,
		  unsigned long vlen, loff_t *pos)
{
	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;

	return do_readv_writev(READ, file, vec, vlen, pos);
}

EXPORT_SYMBOL(vfs_readv);

ssize_t vfs_writev(struct file *file, const struct iovec __user *vec,
		   unsigned long vlen, loff_t *pos)
{
	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	return do_readv_writev(WRITE, file, vec, vlen, pos);
}

EXPORT_SYMBOL(vfs_writev);

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_readv(f.file, vec, vlen, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_writev(f.file, vec, vlen, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

static inline loff_t pos_from_hilo(unsigned long high, unsigned long low)
{
#define HALF_LONG_BITS (BITS_PER_LONG / 2)
	return (((loff_t)high << HALF_LONG_BITS) << HALF_LONG_BITS) | low;
}

SYSCALL_DEFINE5(preadv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PREAD)
			ret = vfs_readv(f.file, vec, vlen, &pos);
		fdput(f);
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

SYSCALL_DEFINE5(pwritev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);
	struct fd f;
	ssize_t ret = -EBADF;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PWRITE)
			ret = vfs_writev(f.file, vec, vlen, &pos);
		fdput(f);
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

#ifdef CONFIG_COMPAT

static ssize_t compat_do_readv_writev(int type, struct file *file,
			       const struct compat_iovec __user *uvector,
			       unsigned long nr_segs, loff_t *pos)
{
	compat_ssize_t tot_len;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;
	ssize_t ret;
	io_fn_t fn;
	iter_fn_t iter_fn;

	ret = compat_import_iovec(type, uvector, nr_segs,
				  UIO_FASTIOV, &iov, &iter);
	if (ret < 0)
		return ret;

	tot_len = iov_iter_count(&iter);
	if (!tot_len)
		goto out;
	ret = rw_verify_area(type, file, pos, tot_len);
	if (ret < 0)
		goto out;

	if (type == READ) {
		fn = file->f_op->read;
		iter_fn = file->f_op->read_iter;
	} else {
		fn = (io_fn_t)file->f_op->write;
		iter_fn = file->f_op->write_iter;
		file_start_write(file);
	}

	if (iter_fn)
		ret = do_iter_readv_writev(file, &iter, pos, iter_fn);
	else
		ret = do_loop_readv_writev(file, &iter, pos, fn);

	if (type != READ)
		file_end_write(file);

out:
	kfree(iov);
	if ((ret + (type == READ)) > 0) {
		if (type == READ)
			fsnotify_access(file);
		else
			fsnotify_modify(file);
	}
	return ret;
}

static size_t compat_readv(struct file *file,
			   const struct compat_iovec __user *vec,
			   unsigned long vlen, loff_t *pos)
{
	ssize_t ret = -EBADF;

	if (!(file->f_mode & FMODE_READ))
		goto out;

	ret = -EINVAL;
	if (!(file->f_mode & FMODE_CAN_READ))
		goto out;

	ret = compat_do_readv_writev(READ, file, vec, vlen, pos);

out:
	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

COMPAT_SYSCALL_DEFINE3(readv, compat_ulong_t, fd,
		const struct compat_iovec __user *,vec,
		compat_ulong_t, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret;
	loff_t pos;

	if (!f.file)
		return -EBADF;
	pos = f.file->f_pos;
	ret = compat_readv(f.file, vec, vlen, &pos);
	if (ret >= 0)
		f.file->f_pos = pos;
	fdput_pos(f);
	return ret;
}

static long __compat_sys_preadv64(unsigned long fd,
				  const struct compat_iovec __user *vec,
				  unsigned long vlen, loff_t pos)
{
	struct fd f;
	ssize_t ret;

	if (pos < 0)
		return -EINVAL;
	f = fdget(fd);
	if (!f.file)
		return -EBADF;
	ret = -ESPIPE;
	if (f.file->f_mode & FMODE_PREAD)
		ret = compat_readv(f.file, vec, vlen, &pos);
	fdput(f);
	return ret;
}

#ifdef __ARCH_WANT_COMPAT_SYS_PREADV64
COMPAT_SYSCALL_DEFINE4(preadv64, unsigned long, fd,
		const struct compat_iovec __user *,vec,
		unsigned long, vlen, loff_t, pos)
{
	return __compat_sys_preadv64(fd, vec, vlen, pos);
}
#endif

COMPAT_SYSCALL_DEFINE5(preadv, compat_ulong_t, fd,
		const struct compat_iovec __user *,vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	return __compat_sys_preadv64(fd, vec, vlen, pos);
}

static size_t compat_writev(struct file *file,
			    const struct compat_iovec __user *vec,
			    unsigned long vlen, loff_t *pos)
{
	ssize_t ret = -EBADF;

	if (!(file->f_mode & FMODE_WRITE))
		goto out;

	ret = -EINVAL;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		goto out;

	ret = compat_do_readv_writev(WRITE, file, vec, vlen, pos);

out:
	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

COMPAT_SYSCALL_DEFINE3(writev, compat_ulong_t, fd,
		const struct compat_iovec __user *, vec,
		compat_ulong_t, vlen)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret;
	loff_t pos;

	if (!f.file)
		return -EBADF;
	pos = f.file->f_pos;
	ret = compat_writev(f.file, vec, vlen, &pos);
	if (ret >= 0)
		f.file->f_pos = pos;
	fdput_pos(f);
	return ret;
}

static long __compat_sys_pwritev64(unsigned long fd,
				   const struct compat_iovec __user *vec,
				   unsigned long vlen, loff_t pos)
{
	struct fd f;
	ssize_t ret;

	if (pos < 0)
		return -EINVAL;
	f = fdget(fd);
	if (!f.file)
		return -EBADF;
	ret = -ESPIPE;
	if (f.file->f_mode & FMODE_PWRITE)
		ret = compat_writev(f.file, vec, vlen, &pos);
	fdput(f);
	return ret;
}

#ifdef __ARCH_WANT_COMPAT_SYS_PWRITEV64
COMPAT_SYSCALL_DEFINE4(pwritev64, unsigned long, fd,
		const struct compat_iovec __user *,vec,
		unsigned long, vlen, loff_t, pos)
{
	return __compat_sys_pwritev64(fd, vec, vlen, pos);
}
#endif

COMPAT_SYSCALL_DEFINE5(pwritev, compat_ulong_t, fd,
		const struct compat_iovec __user *,vec,
		compat_ulong_t, vlen, u32, pos_low, u32, pos_high)
{
	loff_t pos = ((loff_t)pos_high << 32) | pos_low;

	return __compat_sys_pwritev64(fd, vec, vlen, pos);
}
#endif

#ifdef CONFIG_SENDFILE_PATCH
extern ssize_t generic_splice_from_socket(struct file *file, struct socket *sock,
                                    loff_t *ppos, size_t count, bool ppage);
#endif
static ssize_t do_sendfile(int out_fd, int in_fd, loff_t *ppos,
		  	   size_t count, loff_t max)
{
	struct fd in, out;
	struct inode *in_inode, *out_inode;
	loff_t pos;
	loff_t out_pos;
	ssize_t retval;
	int fl;

#ifdef CONFIG_SENDFILE_PATCH
	/* check if in_fd is a socket */
	int error;
	struct socket *sock = NULL;

	error = -EBADF;
	sock = sockfd_lookup(in_fd, &error);
	if (sock) {
		if (!sock->sk)
			goto done;
		out = fdget(out_fd);

		if (out.file) {
			if (!(out.file->f_mode & FMODE_WRITE))
				goto done;
			// Default to use generic splice
			if (out.file->f_op->splice_from_socket)
				error = (int)out.file->f_op->splice_from_socket(out.file, sock, ppos, count, false);
			else
				//goto done;
				error = (int)generic_splice_from_socket(out.file, sock, ppos, count, true);
		}
done:
		if(out.file)
			fdput(out);
		fput(sock->file);
		return (ssize_t)error;
	}
#endif

	/*
	 * Get input file, and verify that it is ok..
	 */
	retval = -EBADF;
	in = fdget(in_fd);
	if (!in.file)
		goto out;
	if (!(in.file->f_mode & FMODE_READ))
		goto fput_in;
	retval = -ESPIPE;
	if (!ppos) {
		pos = in.file->f_pos;
	} else {
		pos = *ppos;
		if (!(in.file->f_mode & FMODE_PREAD))
			goto fput_in;
	}
	retval = rw_verify_area(READ, in.file, &pos, count);
	if (retval < 0)
		goto fput_in;
	count = retval;

	/*
	 * Get output file, and verify that it is ok..
	 */
	retval = -EBADF;
	out = fdget(out_fd);
	if (!out.file)
		goto fput_in;
	if (!(out.file->f_mode & FMODE_WRITE))
		goto fput_out;
	retval = -EINVAL;
	in_inode = file_inode(in.file);
	out_inode = file_inode(out.file);
	out_pos = out.file->f_pos;
	retval = rw_verify_area(WRITE, out.file, &out_pos, count);
	if (retval < 0)
		goto fput_out;
	count = retval;

	if (!max)
		max = min(in_inode->i_sb->s_maxbytes, out_inode->i_sb->s_maxbytes);

	if (unlikely(pos + count > max)) {
		retval = -EOVERFLOW;
		if (pos >= max)
			goto fput_out;
		count = max - pos;
	}

	fl = 0;
#if 0
	/*
	 * We need to debate whether we can enable this or not. The
	 * man page documents EAGAIN return for the output at least,
	 * and the application is arguably buggy if it doesn't expect
	 * EAGAIN on a non-blocking file descriptor.
	 */
	if (in.file->f_flags & O_NONBLOCK)
		fl = SPLICE_F_NONBLOCK;
#endif
	file_start_write(out.file);
	retval = do_splice_direct(in.file, &pos, out.file, &out_pos, count, fl);
	file_end_write(out.file);

	if (retval > 0) {
		add_rchar(current, retval);
		add_wchar(current, retval);
		fsnotify_access(in.file);
		fsnotify_modify(out.file);
		out.file->f_pos = out_pos;
		if (ppos)
			*ppos = pos;
		else
			in.file->f_pos = pos;
	}

	inc_syscr(current);
	inc_syscw(current);
	if (pos > max)
		retval = -EOVERFLOW;

fput_out:
	fdput(out);
fput_in:
	fdput(in);
out:
	return retval;
}

SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count)
{
	loff_t pos;
	off_t off;
	ssize_t ret;

	if (offset) {
		if (unlikely(get_user(off, offset)))
			return -EFAULT;
		pos = off;
		ret = do_sendfile(out_fd, in_fd, &pos, count, MAX_NON_LFS);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count)
{
	loff_t pos;
	ssize_t ret;

	if (offset) {
		if (unlikely(copy_from_user(&pos, offset, sizeof(loff_t))))
			return -EFAULT;
		ret = do_sendfile(out_fd, in_fd, &pos, count, 0);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd,
		compat_off_t __user *, offset, compat_size_t, count)
{
	loff_t pos;
	off_t off;
	ssize_t ret;

	if (offset) {
		if (unlikely(get_user(off, offset)))
			return -EFAULT;
		pos = off;
		ret = do_sendfile(out_fd, in_fd, &pos, count, MAX_NON_LFS);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}

COMPAT_SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd,
		compat_loff_t __user *, offset, compat_size_t, count)
{
	loff_t pos;
	ssize_t ret;

	if (offset) {
		if (unlikely(copy_from_user(&pos, offset, sizeof(loff_t))))
			return -EFAULT;
		ret = do_sendfile(out_fd, in_fd, &pos, count, 0);
		if (unlikely(put_user(pos, offset)))
			return -EFAULT;
		return ret;
	}

	return do_sendfile(out_fd, in_fd, NULL, count, 0);
}
#endif

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
int aggregate_fd = -1;
atomic_t syno_aggregate_recvfile_count = ATOMIC_INIT(0);

static bool should_do_aggregate(struct file *file, int fd, loff_t pos, loff_t next_offset)
{
	struct file *aggregate_file;
	struct inode *inode = file_inode(file);
	static struct file *last_file = NULL;

	if (0 == strcmp("glusterfs", inode->i_sb->s_subtype))
		return false;

	spin_lock(&aggregate_lock);
	if (0 == atomic_read(&syno_aggregate_recvfile_count)) {
	// aggregate_recvfile() is available.
		if (aggregate_fd == -1 || (fd == aggregate_fd && pos == next_offset && file == last_file)) {
			// aggregate_fd == -1: there is no data to be flush.
			// (fd == aggregate_fd && pos == next_offset): keep writing last time.
			// (file == last_file): fd may be close and assign to another file.
			aggregate_fd = fd;
			last_file = file;
			atomic_inc(&syno_aggregate_recvfile_count);
			inode->aggregate_flag |= AGGREGATE_RECVFILE_DOING;
			spin_unlock(&aggregate_lock);
			return true;
		}
		// data in aggregate_recvfile need to be flush, flush it.
		aggregate_file = fget(aggregate_fd);
		// fd may be changed after close_fd, check aggregate_write_end() here.
		if (aggregate_file) {
			if (last_file == aggregate_file) {
				atomic_inc(&syno_aggregate_recvfile_count);
				spin_unlock(&aggregate_lock);
				aggregate_recvfile_flush_only(aggregate_file);
				atomic_dec(&syno_aggregate_recvfile_count);
				spin_lock(&aggregate_lock);
			}
			fput(aggregate_file);
		}
		// after flush, try again.
		if (0 == atomic_read(&syno_aggregate_recvfile_count) && aggregate_fd == -1) {
			aggregate_fd = fd;
			last_file = file;
			atomic_inc(&syno_aggregate_recvfile_count);
			inode->aggregate_flag |= AGGREGATE_RECVFILE_DOING;
			spin_unlock(&aggregate_lock);
			return true;
		}
	}
	spin_unlock(&aggregate_lock);
	if (inode->aggregate_flag & AGGREGATE_RECVFILE_DOING)
		flush_aggregate_recvfile(fd);
	return false;
}

static ssize_t generic_write_init_and_checks(struct file* filp, loff_t pos, size_t count)
{
	struct iovec iov = { .iov_base = NULL, .iov_len = count};
	struct kiocb kiocb;
	struct iov_iter iter;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = pos;
	iov_iter_init(&iter, WRITE, &iov, 1, count);

	return generic_write_checks(&kiocb, &iter);
}

ssize_t aggregate_recvfile(int fd, struct file *file, struct socket *sock,
		loff_t pos, size_t count, size_t *received, size_t *written)
{
	ssize_t ret;
	static loff_t next_offset = 0;
	bool aggregate;
	struct inode *inode = file_inode(file);

	ret = file_update_time(file);
	if (ret)
		return ret;

	aggregate = should_do_aggregate(file, fd, pos, next_offset);
	do {
		size_t bytes_received = 0;
		size_t bytes_written = 0;

		if (aggregate) {
			ret = do_aggregate_recvfile(file, sock, pos, (count >= MAX_RECVFILE_BUF) ?
						MAX_RECVFILE_BUF : count, &bytes_received, &bytes_written, 0);
			// trans aggregate_recvfile() to normal if it is flushing.
			if (inode->aggregate_flag & AGGREGATE_RECVFILE_FLUSH &&
			      !(inode->aggregate_flag & AGGREGATE_RECVFILE_DOING)) {
				next_offset = pos;
				atomic_dec(&syno_aggregate_recvfile_count);
				aggregate = false;
			}
		} else {
			ret = do_recvfile(file, sock, pos, (count > MAX_RECVFILE_BUF) ?
					   MAX_RECVFILE_BUF : count, &bytes_received, &bytes_written);
		}
		*received += bytes_received;
		*written += bytes_written;
		if (ret <= 0)
			break;
		count -= bytes_written;
		pos += bytes_written;
	} while (count > 0);

	if (aggregate) {
		next_offset = pos;
		atomic_dec(&syno_aggregate_recvfile_count);
	}
	return ret < 0 ? ret : *written;
}
EXPORT_SYMBOL(aggregate_recvfile);

ssize_t default_recvfile(struct file *file, struct socket *sock,
		loff_t pos, size_t count, size_t *received, size_t *written)
{
	ssize_t ret;

	ret = file_update_time(file);
	if (ret)
		return ret;

	do {
		size_t bytes_received = 0;
		size_t bytes_written = 0;

		ret = do_recvfile(file, sock, pos, (count > (MAX_RECVFILE_BUF - (pos & (PAGE_CACHE_SIZE - 1)))) ?
			   (MAX_RECVFILE_BUF - (pos & (PAGE_CACHE_SIZE - 1))) : count, &bytes_received, &bytes_written);
		*received += bytes_received;
		*written += bytes_written;
		if (ret <= 0)
			break;
		count -= bytes_written;
		pos += bytes_written;
	} while (count > 0);
	return ret < 0 ? ret : *written;
}

ssize_t vfs_recvfile(int fd, struct file *file, struct socket *sock,
		loff_t pos, size_t count, size_t *received, size_t *written)
{
	ssize_t ret;
	struct inode *inode = file_inode(file);

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;
	file_start_write(file);
	mutex_lock(&inode->i_mutex);
	/*
	 * We can write back this queue in page reclaim
	 */
	current->backing_dev_info = inode_to_bdi(inode);
	ret = generic_write_init_and_checks(file, pos, count);
	if (ret <= 0)
		goto out;
	ret = file_remove_privs(file);
	if (ret)
		goto out;

	if (file->f_op->syno_recvfile) {
		ret = file->f_op->syno_recvfile(fd, file, sock, pos, count, received, written);
	} else {
		ret = default_recvfile(file, sock, pos, count, received, written);
	}
	if (ret > 0)
		fsnotify_modify(file);
out:
	current->backing_dev_info = NULL;
	mutex_unlock(&inode->i_mutex);
	file_end_write(file);
	return ret;
}
EXPORT_SYMBOL(vfs_recvfile);

SYSCALL_DEFINE5(syno_recv_file, int, fd, int, s, loff_t *, offset, size_t, count, size_t *, rwbytes)
{
	ssize_t ret;
	int err;
	loff_t pos;
	size_t received = 0;
	size_t written = 0;
	struct file *file;
	struct socket *sock;

	if (!offset)
		return -EINVAL;
	if (!count)
		return 0;
	if (copy_from_user(&pos, offset, sizeof(loff_t)))
		return -EFAULT;
	file = fget(fd);
	if (!file)
		return -EBADF;

	sock = sockfd_lookup(s, &err);
	if (!sock) {
		fput(file);
		return err;
	}
	if (!sock->sk) {
		/* not a socket */
		ret = -EINVAL;
		goto out;
	}

	ret = vfs_recvfile(fd, file, sock, pos, count, &received, &written);
	if (ret < 0 && rwbytes) {
		if (copy_to_user(&rwbytes[0], &received, sizeof(size_t))) {
			ret = -EFAULT;
			goto out;
		}
		if (copy_to_user(&rwbytes[1], &written, sizeof(size_t))) {
			ret = -EFAULT;
			goto out;
		}
	}
	pos += written;
	if (unlikely(put_user(pos, offset))) {
		ret = -EFAULT;
		goto out;
	}

out:
	fput(file);
	sockfd_put(sock);
	return ret;
}
SYSCALL_DEFINE5(recvfile, int, fd, int, s, loff_t *, offset, size_t, count, size_t *, rwbytes)
{
	return sys_syno_recv_file(fd, s, offset, count, rwbytes);
}

SYSCALL_DEFINE1(syno_flush_aggregate, int, fd)
{
	return flush_aggregate_recvfile(fd);
}
SYSCALL_DEFINE1(SYNOFlushAggregate, int, fd)
{
	return sys_syno_flush_aggregate(fd);
}
#else
SYSCALL_DEFINE5(syno_recv_file, int, fd, int, s, loff_t *, offset, size_t, count, size_t *, rwbytes)
{
	return -EOPNOTSUPP;
}
SYSCALL_DEFINE5(recvfile, int, fd, int, s, loff_t *, offset, size_t, count, size_t *, rwbytes)
{
	return sys_syno_recv_file(fd, s, offset, count, rwbytes);
}
SYSCALL_DEFINE1(syno_flush_aggregate, int, fd)
{
	return -EOPNOTSUPP;
}
SYSCALL_DEFINE1(SYNOFlushAggregate, int, fd)
{
	return sys_syno_flush_aggregate(fd);
}
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */

/*
 * copy_file_range() differs from regular file read and write in that it
 * specifically allows return partial success.  When it does so is up to
 * the copy_file_range method.
 */
ssize_t vfs_copy_file_range(struct file *file_in, loff_t pos_in,
			    struct file *file_out, loff_t pos_out,
			    size_t len, unsigned int flags)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	ssize_t ret;

	if (flags != 0)
		return -EINVAL;

	/* copy_file_range allows full ssize_t len, ignoring MAX_RW_COUNT  */
	ret = rw_verify_area(READ, file_in, &pos_in, len);
	if (ret >= 0)
		ret = rw_verify_area(WRITE, file_out, &pos_out, len);
	if (ret < 0)
		return ret;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE) ||
	    (file_out->f_flags & O_APPEND))
		return -EBADF;

	/* this could be relaxed once a method supports cross-fs copies */
	if (inode_in->i_sb != inode_out->i_sb)
		return -EXDEV;

	if (len == 0)
		return 0;

	sb_start_write(inode_out->i_sb);

	/*
	 * Try cloning first, this is supported by more file systems, and
	 * more efficient if both clone and copy are supported (e.g. NFS).
	 */
	if (file_in->f_op->clone_file_range) {
#ifdef MY_ABC_HERE
		if (file_in->f_op->clone_check_compr) {
			ret = file_in->f_op->clone_check_compr(file_in, file_out);
			if (ret) {
				goto skip_clone;
			}
		}
#endif /* MY_ABC_HERE */

		ret = file_in->f_op->clone_file_range(file_in, pos_in,
				file_out, pos_out, len);
		if (ret == 0) {
			ret = len;
			goto done;
		}
	}
#ifdef MY_ABC_HERE
skip_clone:
#endif /* MY_ABC_HERE */

	if (file_out->f_op->copy_file_range) {
		ret = file_out->f_op->copy_file_range(file_in, pos_in, file_out,
						      pos_out, len, flags);
		if (ret != -EOPNOTSUPP)
			goto done;
	}

	ret = do_splice_direct(file_in, &pos_in, file_out, &pos_out,
			len > MAX_RW_COUNT ? MAX_RW_COUNT : len, 0);

done:
	if (ret > 0) {
		fsnotify_access(file_in);
		add_rchar(current, ret);
		fsnotify_modify(file_out);
		add_wchar(current, ret);
	}

	inc_syscr(current);
	inc_syscw(current);

	sb_end_write(inode_out->i_sb);

	return ret;
}
EXPORT_SYMBOL(vfs_copy_file_range);

SYSCALL_DEFINE6(copy_file_range, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	loff_t pos_in;
	loff_t pos_out;
	struct fd f_in;
	struct fd f_out;
	ssize_t ret = -EBADF;

	f_in = fdget(fd_in);
	if (!f_in.file)
		goto out2;

	f_out = fdget(fd_out);
	if (!f_out.file)
		goto out1;

	ret = -EFAULT;
	if (off_in) {
		if (copy_from_user(&pos_in, off_in, sizeof(loff_t)))
			goto out;
	} else {
		pos_in = f_in.file->f_pos;
	}

	if (off_out) {
		if (copy_from_user(&pos_out, off_out, sizeof(loff_t)))
			goto out;
	} else {
		pos_out = f_out.file->f_pos;
	}

	ret = vfs_copy_file_range(f_in.file, pos_in, f_out.file, pos_out, len,
				  flags);
	if (ret > 0) {
		pos_in += ret;
		pos_out += ret;

		if (off_in) {
			if (copy_to_user(off_in, &pos_in, sizeof(loff_t)))
				ret = -EFAULT;
		} else {
			f_in.file->f_pos = pos_in;
		}

		if (off_out) {
			if (copy_to_user(off_out, &pos_out, sizeof(loff_t)))
				ret = -EFAULT;
		} else {
			f_out.file->f_pos = pos_out;
		}
	}

out:
	fdput(f_out);
out1:
	fdput(f_in);
out2:
	return ret;
}

static int clone_verify_area(struct file *file, loff_t pos, u64 len, bool write)
{
	struct inode *inode = file_inode(file);

	if (unlikely(pos < 0))
		return -EINVAL;

	 if (unlikely((loff_t) (pos + len) < 0))
		return -EINVAL;

	if (unlikely(inode->i_flctx && mandatory_lock(inode))) {
		loff_t end = len ? pos + len - 1 : OFFSET_MAX;
		int retval;

		retval = locks_mandatory_area(inode, file, pos, end,
				write ? F_WRLCK : F_RDLCK);
		if (retval < 0)
			return retval;
	}

	return security_file_permission(file, write ? MAY_WRITE : MAY_READ);
}

#ifdef MY_ABC_HERE
int vfs_clone_file_range(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, u64 len, int check_compr)
#else
int vfs_clone_file_range(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, u64 len)
#endif /* MY_ABC_HERE */
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	int ret;

	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	/*
	 * FICLONE/FICLONERANGE ioctls enforce that src and dest files are on
	 * the same mount. Practically, they only need to be on the same file
	 * system.
	 */
	if (inode_in->i_sb != inode_out->i_sb)
		return -EXDEV;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE) ||
	    (file_out->f_flags & O_APPEND))
		return -EBADF;

	if (!file_in->f_op->clone_file_range)
		return -EOPNOTSUPP;

	ret = clone_verify_area(file_in, pos_in, len, false);
	if (ret)
		return ret;

	ret = clone_verify_area(file_out, pos_out, len, true);
	if (ret)
		return ret;

	if (pos_in + len > i_size_read(inode_in))
		return -EINVAL;

#ifdef MY_ABC_HERE
	if (check_compr && file_in->f_op->clone_check_compr) {
		ret = file_in->f_op->clone_check_compr(file_in, file_out);
		if (ret) {
			return ret;
		}
	}
#endif /* MY_ABC_HERE */

	ret = file_in->f_op->clone_file_range(file_in, pos_in,
			file_out, pos_out, len);
	if (!ret) {
		fsnotify_access(file_in);
		fsnotify_modify(file_out);
	}

	return ret;
}

#ifdef MY_ABC_HERE
extern int gSynoPatternCheckCharacter;
int syno_page_pattern_check(struct inode *inode, struct page *page, size_t offset, size_t bytes, int type)
{
	int ret = 0;
	char *kaddr;
	void *find = NULL;
	char type_string[20] = {'\0'};

	switch (type) {
		case SYNO_PATTERN_CHECK_CACHE_PAGES:
			snprintf(type_string, sizeof(type_string), "%s", "Cache Pages");
			break;
		case SYNO_PATTERN_CHECK_BIO:
			snprintf(type_string, sizeof(type_string), "%s", "Bio");
			break;
		default:
			snprintf(type_string, sizeof(type_string), "%s", "Unknown");
                        break;
	}

	kaddr = kmap(page);
	find = memchr_inv(kaddr + offset, gSynoPatternCheckCharacter, bytes);
	kunmap(page);
	if (find) {
		printk("Syno Pattern Check: %s:%d data err none 0xFF, type:%s, inode:%lu, file offset:%lld, page->index:%lu, offset:%zu, len:%zu\n", __FUNCTION__, __LINE__, type_string, inode ? inode->i_ino : 0, page_file_offset(page) + offset, page->index, offset, bytes);
		ret = -1;
	}
	return ret;
}
#endif /* MY_ABC_HERE */

EXPORT_SYMBOL(vfs_clone_file_range);
