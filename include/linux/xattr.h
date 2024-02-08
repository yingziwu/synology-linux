#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _LINUX_XATTR_H
#define _LINUX_XATTR_H

#define XATTR_CREATE	0x1	 
#define XATTR_REPLACE	0x2	 

#ifdef  __KERNEL__

#include <linux/types.h>

#define XATTR_OS2_PREFIX "os2."
#define XATTR_OS2_PREFIX_LEN (sizeof (XATTR_OS2_PREFIX) - 1)

#define XATTR_SECURITY_PREFIX	"security."
#define XATTR_SECURITY_PREFIX_LEN (sizeof (XATTR_SECURITY_PREFIX) - 1)

#define XATTR_SYSTEM_PREFIX "system."
#define XATTR_SYSTEM_PREFIX_LEN (sizeof (XATTR_SYSTEM_PREFIX) - 1)

#define XATTR_TRUSTED_PREFIX "trusted."
#define XATTR_TRUSTED_PREFIX_LEN (sizeof (XATTR_TRUSTED_PREFIX) - 1)

#define XATTR_USER_PREFIX "user."
#define XATTR_USER_PREFIX_LEN (sizeof (XATTR_USER_PREFIX) - 1)

#ifdef MY_ABC_HERE
#define XATTR_SYNO_PREFIX "syno."
#define XATTR_SYNO_PREFIX_LEN (sizeof (XATTR_SYNO_PREFIX) - 1)
#endif

#ifdef MY_ABC_HERE
#define XATTR_SYNO_ARCHIVE_VERSION "archive_version"
#endif

struct inode;
struct dentry;

struct xattr_handler {
	char *prefix;
	size_t (*list)(struct inode *inode, char *list, size_t list_size,
		       const char *name, size_t name_len);
	int (*get)(struct inode *inode, const char *name, void *buffer,
		   size_t size);
	int (*set)(struct inode *inode, const char *name, const void *buffer,
		   size_t size, int flags);
};

#ifdef MY_ABC_HERE
struct syno_xattr_archive_version {
	__le16	v_magic;
	__le16	v_struct_version;
	__le32	v_archive_version;
} __attribute__ ((__packed__));
#endif

ssize_t xattr_getsecurity(struct inode *, const char *, void *, size_t);
ssize_t vfs_getxattr(struct dentry *, const char *, void *, size_t);
ssize_t vfs_listxattr(struct dentry *d, char *list, size_t size);
int __vfs_setxattr_noperm(struct dentry *, const char *, const void *, size_t, int);
int vfs_setxattr(struct dentry *, const char *, const void *, size_t, int);
int vfs_removexattr(struct dentry *, const char *);

ssize_t generic_getxattr(struct dentry *dentry, const char *name, void *buffer, size_t size);
ssize_t generic_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size);
int generic_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags);
int generic_removexattr(struct dentry *dentry, const char *name);

#ifdef MY_ABC_HERE
int syno_generic_setxattr(struct inode *inode, const char *name, const void *value, size_t size, int flags);
#endif
#endif   

#endif	 
