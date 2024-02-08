 
#ifndef _LINUX_FIEMAP_H
#define _LINUX_FIEMAP_H

#include <linux/types.h>

struct fiemap_extent {
	__u64 fe_logical;   
	__u64 fe_physical;  
	__u64 fe_length;    
	__u64 fe_reserved64[2];
	__u32 fe_flags;     
	__u32 fe_reserved[3];
};

struct fiemap {
	__u64 fm_start;		 
	__u64 fm_length;	 
	__u32 fm_flags;		 
	__u32 fm_mapped_extents; 
	__u32 fm_extent_count;   
	__u32 fm_reserved;
	struct fiemap_extent fm_extents[0];  
};

#define FIEMAP_MAX_OFFSET	(~0ULL)

#define FIEMAP_FLAG_SYNC	0x00000001  
#define FIEMAP_FLAG_XATTR	0x00000002  
#ifdef CONFIG_SYNO_PLX_PORTING
#define FIEMAP_KERNEL_READ  0x00000004  
#endif

#ifdef CONFIG_SYNO_PLX_PORTING
#define FIEMAP_FLAGS_COMPAT	(FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR | FIEMAP_KERNEL_READ)
#else
#define FIEMAP_FLAGS_COMPAT	(FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR)
#endif

#define FIEMAP_EXTENT_LAST		0x00000001  
#define FIEMAP_EXTENT_UNKNOWN		0x00000002  
#define FIEMAP_EXTENT_DELALLOC		0x00000004  
#define FIEMAP_EXTENT_ENCODED		0x00000008  
#define FIEMAP_EXTENT_DATA_ENCRYPTED	0x00000080  
#define FIEMAP_EXTENT_NOT_ALIGNED	0x00000100  
#define FIEMAP_EXTENT_DATA_INLINE	0x00000200  
#define FIEMAP_EXTENT_DATA_TAIL		0x00000400  
#define FIEMAP_EXTENT_UNWRITTEN		0x00000800  
#define FIEMAP_EXTENT_MERGED		0x00001000  

#endif  
