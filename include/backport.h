 /* clflushopt falls back to clflush
  * if clflushopt is not available */
 #define clflushopt clflush

/* from asm-generic/barrier.h */
#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic()        smp_mb()
#endif

#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic() smp_mb()
#endif


/* from include/acpi/acpi_io.h */
/* We apparently don't want to include linux/acpi_io.h directly as that
 * can cause build problems in our kernel */
#include <linux/acpi.h>
#include <linux/io.h>

static inline void __iomem *acpi_os_ioremap(acpi_physical_address phys,
                                           acpi_size size)
{
       return ioremap_cache(phys, size);
}


#undef dma_buf_export
#define dma_buf_export(priv, ops, size, flags, resv)	\
	dma_buf_export_named(priv, ops, size, flags, KBUILD_MODNAME)

struct name_snapshot {
	char *name;
};

static inline void take_dentry_name_snapshot(struct name_snapshot *name,
					     struct dentry *dentry)
{
	u32 len;

	spin_lock(&dentry->d_lock);
	len = dentry->d_name.len;
	spin_unlock(&dentry->d_lock);

	name->name = kmalloc(len + 1, GFP_KERNEL);
	if (!name->name)
		return;

	spin_lock(&dentry->d_lock);
	len = min(dentry->d_name.len, len);
	memcpy(name->name, dentry->d_name.name, len);
	name->name[len] = 0;
	spin_unlock(&dentry->d_lock);
}

static inline void release_dentry_name_snapshot(struct name_snapshot *name)
{
	kfree(name->name);
}
