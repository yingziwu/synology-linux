#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef _LINUX_STAT_H
#define _LINUX_STAT_H


#include <asm/stat.h>
#include <uapi/linux/stat.h>

#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

#define UTIME_NOW	((1l << 30) - 1l)
#define UTIME_OMIT	((1l << 30) - 2l)

#include <linux/types.h>
#include <linux/time.h>
#include <linux/uidgid.h>

struct kstat {
	u64		ino;
	dev_t		dev;
	umode_t		mode;
#ifdef MY_ABC_HERE
	__u32		syno_archive_bit;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	__u32		syno_archive_version;
#endif /* MY_ABC_HERE */
	unsigned int	nlink;
	kuid_t		uid;
	kgid_t		gid;
	dev_t		rdev;
	loff_t		size;
	struct timespec  atime;
	struct timespec	mtime;
	struct timespec	ctime;
#ifdef MY_ABC_HERE
	struct timespec syno_create_time;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	unsigned long syno_compressed;
#endif
	unsigned long	blksize;
	unsigned long long	blocks;
#ifdef MY_ABC_HERE
	bool		is_inline;
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
	unsigned int	syno_flags;
#endif
};

#ifdef MY_ABC_HERE
struct SYNOSTAT_EXTRA {
	struct timespec create_time;
	unsigned int archive_version;
	unsigned int archive_bit;
	unsigned int compressed;
	unsigned int flags;
	unsigned int reserved[7];
};
struct SYNOSTAT {
	struct stat st;
	struct SYNOSTAT_EXTRA ext;
};

#ifdef MY_ABC_HERE
/*
 * flags: decide which information to get.
 */
#define SYNOST_STAT         0x00000001  /* stat */
#define SYNOST_ARCHIVE_BIT  0x00000002  /* Archive Bit */
#define SYNOST_ARCHIVE_VER  0x00000004  /* Archive Version (aka Backup Version) */
#define SYNOST_CREATE_TIME  0x00000008  /* Create Time */
#define SYNOST_COMPRESSION  0x00000010  /* Compression Type */
#define SYNOST_IS_INLINE    0x00000020  /* Is inline file? */
#define SYNOST_OFFLINE      0x00000040  /* currently, only c2fs support offline */

#define SYNOST_ALL          (SYNOST_STAT|SYNOST_ARCHIVE_BIT|SYNOST_ARCHIVE_VER|SYNOST_CREATE_TIME|SYNOST_COMPRESSION|SYNOST_OFFLINE)
#define SYNOST_IS_CASELESS      0x10000000      /* Is Caseless */

#define SYNOST_FLAG_OFFLINE     0x00000001

#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */


#endif
