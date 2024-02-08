#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/crypto.h>
#include <linux/fs_stack.h>
#include <asm/unaligned.h>
#include "ecryptfs_kernel.h"

#ifdef CONFIG_FS_SYNO_ACL
#include "../synoacl_int.h"
#endif

static struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir;

	dir = dget_parent(dentry);
	mutex_lock_nested(&(dir->d_inode->i_mutex), I_MUTEX_PARENT);
	return dir;
}

static void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

static int
ecryptfs_create_underlying_file(struct inode *lower_dir_inode,
				struct dentry *dentry, int mode,
				struct nameidata *nd)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	struct vfsmount *lower_mnt = ecryptfs_dentry_to_lower_mnt(dentry);
	struct dentry *dentry_save;
	struct vfsmount *vfsmount_save;
	int rc;

	dentry_save = nd->path.dentry;
	vfsmount_save = nd->path.mnt;
	nd->path.dentry = lower_dentry;
	nd->path.mnt = lower_mnt;
	rc = vfs_create(lower_dir_inode, lower_dentry, mode, nd);
	nd->path.dentry = dentry_save;
	nd->path.mnt = vfsmount_save;
	return rc;
}

static int
ecryptfs_do_create(struct inode *directory_inode,
		   struct dentry *ecryptfs_dentry, int mode,
		   struct nameidata *nd)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(ecryptfs_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_dir_dentry)) {
		ecryptfs_printk(KERN_ERR, "Error locking directory of "
				"dentry\n");
		rc = PTR_ERR(lower_dir_dentry);
		goto out;
	}
	rc = ecryptfs_create_underlying_file(lower_dir_dentry->d_inode,
					     ecryptfs_dentry, mode, nd);
	if (rc) {
		printk(KERN_ERR "%s: Failure to create dentry in lower fs; "
		       "rc = [%d]\n", __func__, rc);
		goto out_lock;
	}
	rc = ecryptfs_interpose(lower_dentry, ecryptfs_dentry,
				directory_inode->i_sb, 0);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Failure in ecryptfs_interpose\n");
		goto out_lock;
	}
	fsstack_copy_attr_times(directory_inode, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(directory_inode, lower_dir_dentry->d_inode);
out_lock:
	unlock_dir(lower_dir_dentry);
out:
	return rc;
}

static int grow_file(struct dentry *ecryptfs_dentry)
{
	struct inode *ecryptfs_inode = ecryptfs_dentry->d_inode;
	struct file fake_file;
	struct ecryptfs_file_info tmp_file_info;
	char zero_virt[] = { 0x00 };
	int rc = 0;

	memset(&fake_file, 0, sizeof(fake_file));
	fake_file.f_path.dentry = ecryptfs_dentry;
	memset(&tmp_file_info, 0, sizeof(tmp_file_info));
	ecryptfs_set_file_private(&fake_file, &tmp_file_info);
	ecryptfs_set_file_lower(
		&fake_file,
		ecryptfs_inode_to_private(ecryptfs_inode)->lower_file);
	rc = ecryptfs_write(&fake_file, zero_virt, 0, 1);
	i_size_write(ecryptfs_inode, 0);
	rc = ecryptfs_write_inode_size_to_metadata(ecryptfs_inode);
	ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat.flags |=
		ECRYPTFS_NEW_FILE;
	return rc;
}

static int ecryptfs_initialize_file(struct dentry *ecryptfs_dentry)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_dentry->d_inode)->crypt_stat;
	int rc = 0;

	if (S_ISDIR(ecryptfs_dentry->d_inode->i_mode)) {
		ecryptfs_printk(KERN_DEBUG, "This is a directory\n");
		crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
		goto out;
	}
	crypt_stat->flags |= ECRYPTFS_NEW_FILE;
	ecryptfs_printk(KERN_DEBUG, "Initializing crypto context\n");
	rc = ecryptfs_new_file_context(ecryptfs_dentry);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error creating new file "
				"context; rc = [%d]\n", rc);
		goto out;
	}
#ifdef MY_ABC_HERE
	rc = ecryptfs_get_lower_file(ecryptfs_dentry);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
		       "the lower file for the dentry with name "
		       "[%s]; rc = [%d]\n", __func__,
		       ecryptfs_dentry->d_name.name, rc);
		goto out;
	}
#else
	if (!ecryptfs_inode_to_private(ecryptfs_dentry->d_inode)->lower_file) {
		rc = ecryptfs_init_persistent_file(ecryptfs_dentry);
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to initialize "
			       "the persistent file for the dentry with name "
			       "[%s]; rc = [%d]\n", __func__,
			       ecryptfs_dentry->d_name.name, rc);
			goto out;
		}
	}
#endif  
	rc = ecryptfs_write_metadata(ecryptfs_dentry);
	if (rc) {
#ifdef MY_ABC_HERE
		if (-EDQUOT != rc)
#endif
		printk(KERN_ERR "Error writing headers; rc = [%d]\n", rc);
#ifdef MY_ABC_HERE
		goto out_put;
#else
		goto out;
#endif  
	}
	rc = grow_file(ecryptfs_dentry);
	if (rc)
		printk(KERN_ERR "Error growing file; rc = [%d]\n", rc);
#ifdef MY_ABC_HERE
out_put:
	ecryptfs_put_lower_file(ecryptfs_dentry->d_inode);
#endif  
out:
	return rc;
}

#ifdef MY_ABC_HERE
 
static int ecryptfs_unlink(struct inode *dir, struct dentry *dentry);
#endif
 
static int
ecryptfs_create(struct inode *directory_inode, struct dentry *ecryptfs_dentry,
		int mode, struct nameidata *nd)
{
	int rc;

	rc = ecryptfs_do_create(directory_inode, ecryptfs_dentry, mode, nd);
	if (unlikely(rc)) {
		ecryptfs_printk(KERN_WARNING, "Failed to create file in"
				"lower filesystem\n");
		goto out;
	}
	 
	rc = ecryptfs_initialize_file(ecryptfs_dentry);
#ifdef MY_ABC_HERE
	 
	if (-EDQUOT == rc) {
		ecryptfs_unlink(directory_inode, ecryptfs_dentry);
	}
#endif
out:
	return rc;
}

int ecryptfs_lookup_and_interpose_lower(struct dentry *ecryptfs_dentry,
					struct dentry *lower_dentry,
					struct inode *ecryptfs_dir_inode,
					struct nameidata *ecryptfs_nd)
{
	struct dentry *lower_dir_dentry;
	struct vfsmount *lower_mnt;
	struct inode *lower_inode;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_crypt_stat *crypt_stat;
	char *page_virt = NULL;
	u64 file_size;
#ifdef MY_ABC_HERE
	int put_lower = 0, rc = 0;
#else
	int rc = 0;
#endif  

	lower_dir_dentry = lower_dentry->d_parent;
	lower_mnt = mntget(ecryptfs_dentry_to_lower_mnt(
				   ecryptfs_dentry->d_parent));
	lower_inode = lower_dentry->d_inode;
	fsstack_copy_attr_atime(ecryptfs_dir_inode, lower_dir_dentry->d_inode);
	BUG_ON(!atomic_read(&lower_dentry->d_count));
	ecryptfs_set_dentry_private(ecryptfs_dentry,
				    kmem_cache_alloc(ecryptfs_dentry_info_cache,
						     GFP_KERNEL));
	if (!ecryptfs_dentry_to_private(ecryptfs_dentry)) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Out of memory whilst attempting "
		       "to allocate ecryptfs_dentry_info struct\n",
			__func__);
		goto out_dput;
	}
	ecryptfs_set_dentry_lower(ecryptfs_dentry, lower_dentry);
	ecryptfs_set_dentry_lower_mnt(ecryptfs_dentry, lower_mnt);
	if (!lower_dentry->d_inode) {
		 
		d_add(ecryptfs_dentry, NULL);
		goto out;
	}
	rc = ecryptfs_interpose(lower_dentry, ecryptfs_dentry,
				ecryptfs_dir_inode->i_sb, 1);
	if (rc) {
		printk(KERN_ERR "%s: Error interposing; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
	if (S_ISDIR(lower_inode->i_mode))
		goto out;
	if (S_ISLNK(lower_inode->i_mode))
		goto out;
	if (special_file(lower_inode->i_mode))
		goto out;
	if (!ecryptfs_nd)
		goto out;
	 
	page_virt = kmem_cache_zalloc(ecryptfs_header_cache_2, GFP_USER);
	if (!page_virt) {
		printk(KERN_ERR "%s: Cannot kmem_cache_zalloc() a page\n",
		       __func__);
		rc = -ENOMEM;
		goto out;
	}
#ifdef MY_ABC_HERE
	rc = ecryptfs_get_lower_file(ecryptfs_dentry);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
		       "the lower file for the dentry with name "
		       "[%s]; rc = [%d]\n", __func__,
		       ecryptfs_dentry->d_name.name, rc);
		goto out_free_kmem;
	}
	put_lower = 1;
#else
	if (!ecryptfs_inode_to_private(ecryptfs_dentry->d_inode)->lower_file) {
		rc = ecryptfs_init_persistent_file(ecryptfs_dentry);
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to initialize "
			       "the persistent file for the dentry with name "
			       "[%s]; rc = [%d]\n", __func__,
			       ecryptfs_dentry->d_name.name, rc);
			goto out_free_kmem;
		}
	}
#endif  
	crypt_stat = &ecryptfs_inode_to_private(
					ecryptfs_dentry->d_inode)->crypt_stat;
	 
	if (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED))
			ecryptfs_set_default_sizes(crypt_stat);
	rc = ecryptfs_read_and_validate_header_region(page_virt,
						      ecryptfs_dentry->d_inode);
	if (rc) {
		rc = ecryptfs_read_and_validate_xattr_region(page_virt,
							     ecryptfs_dentry);
		if (rc) {
			rc = 0;
			goto out_free_kmem;
		}
		crypt_stat->flags |= ECRYPTFS_METADATA_IN_XATTR;
	}
	mount_crypt_stat = &ecryptfs_superblock_to_private(
		ecryptfs_dentry->d_sb)->mount_crypt_stat;
	if (mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED) {
		if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR)
			file_size = (crypt_stat->num_header_bytes_at_front
				     + i_size_read(lower_dentry->d_inode));
		else
			file_size = i_size_read(lower_dentry->d_inode);
	} else {
		file_size = get_unaligned_be64(page_virt);
	}
	i_size_write(ecryptfs_dentry->d_inode, (loff_t)file_size);
out_free_kmem:
	kmem_cache_free(ecryptfs_header_cache_2, page_virt);
	goto out;
out_dput:
	dput(lower_dentry);
	d_drop(ecryptfs_dentry);
out:
#ifdef MY_ABC_HERE
	if (put_lower)
		ecryptfs_put_lower_file(ecryptfs_dentry->d_inode);
#endif  
	return rc;
}

static struct dentry *ecryptfs_lookup(struct inode *ecryptfs_dir_inode,
				      struct dentry *ecryptfs_dentry,
				      struct nameidata *ecryptfs_nd)
{
	char *encrypted_and_encoded_name = NULL;
	size_t encrypted_and_encoded_name_size;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat = NULL;
	struct dentry *lower_dir_dentry, *lower_dentry;
	int rc = 0;

	ecryptfs_dentry->d_op = &ecryptfs_dops;
	if ((ecryptfs_dentry->d_name.len == 1
	     && !strcmp(ecryptfs_dentry->d_name.name, "."))
	    || (ecryptfs_dentry->d_name.len == 2
		&& !strcmp(ecryptfs_dentry->d_name.name, ".."))) {
		goto out_d_drop;
	}
	lower_dir_dentry = ecryptfs_dentry_to_lower(ecryptfs_dentry->d_parent);
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(ecryptfs_dentry->d_name.name,
				      lower_dir_dentry,
				      ecryptfs_dentry->d_name.len);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		rc = PTR_ERR(lower_dentry);
#ifdef MY_ABC_HERE
		ecryptfs_printk(KERN_DEBUG, "%s: lookup_one_len() returned "
						"[%d] on lower_dentry = [%s]\n", __func__, rc,
						encrypted_and_encoded_name);
#else
		printk(KERN_ERR "%s: lookup_one_len() returned [%d] on "
		       "lower_dentry = [%s]\n", __func__, rc,
		       ecryptfs_dentry->d_name.name);
#endif
		goto out_d_drop;
	}
	if (lower_dentry->d_inode)
		goto lookup_and_interpose;
	mount_crypt_stat = &ecryptfs_superblock_to_private(
				ecryptfs_dentry->d_sb)->mount_crypt_stat;
	if (!(mount_crypt_stat
	    && (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)))
		goto lookup_and_interpose;
	dput(lower_dentry);
	rc = ecryptfs_encrypt_and_encode_filename(
		&encrypted_and_encoded_name, &encrypted_and_encoded_name_size,
		NULL, mount_crypt_stat, ecryptfs_dentry->d_name.name,
		ecryptfs_dentry->d_name.len);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to encrypt and encode "
			   "filename; rc = [%d]\n", __func__, rc);
		goto out_d_drop;
	}
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(encrypted_and_encoded_name,
				      lower_dir_dentry,
				      encrypted_and_encoded_name_size - 1);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		rc = PTR_ERR(lower_dentry);
#ifdef MY_ABC_HERE
		ecryptfs_printk(KERN_DEBUG, "%s: lookup_one_len() returned "
						"[%d] on lower_dentry = [%s]\n", __func__, rc,
						encrypted_and_encoded_name);
#else
		printk(KERN_ERR "%s: lookup_one_len() returned [%d] on "
		       "lower_dentry = [%s]\n", __func__, rc,
		       encrypted_and_encoded_name);
#endif
		goto out_d_drop;
	}
lookup_and_interpose:
	rc = ecryptfs_lookup_and_interpose_lower(ecryptfs_dentry, lower_dentry,
						 ecryptfs_dir_inode,
						 ecryptfs_nd);
	goto out;
out_d_drop:
	d_drop(ecryptfs_dentry);
out:
	kfree(encrypted_and_encoded_name);
	return ERR_PTR(rc);
}

static int ecryptfs_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int rc;

	file_size_save = i_size_read(old_dentry->d_inode);
	lower_old_dentry = ecryptfs_dentry_to_lower(old_dentry);
	lower_new_dentry = ecryptfs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_dir_dentry = lock_parent(lower_new_dentry);
	rc = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		      lower_new_dentry);
	if (rc || !lower_new_dentry->d_inode)
		goto out_lock;
	rc = ecryptfs_interpose(lower_new_dentry, new_dentry, dir->i_sb, 0);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	old_dentry->d_inode->i_nlink =
		ecryptfs_inode_to_lower(old_dentry->d_inode)->i_nlink;
	i_size_write(new_dentry->d_inode, file_size_save);
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	d_drop(lower_old_dentry);
	d_drop(new_dentry);
	d_drop(old_dentry);
	return rc;
}

static int ecryptfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int rc = 0;
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	struct inode *lower_dir_inode = ecryptfs_inode_to_lower(dir);
	struct dentry *lower_dir_dentry;

	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_unlink(lower_dir_inode, lower_dentry);
	if (rc) {
		printk(KERN_ERR "Error in vfs_unlink; rc = [%d]\n", rc);
		goto out_unlock;
	}
	fsstack_copy_attr_times(dir, lower_dir_inode);
	dentry->d_inode->i_nlink =
		ecryptfs_inode_to_lower(dentry->d_inode)->i_nlink;
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	return rc;
}

static int ecryptfs_symlink(struct inode *dir, struct dentry *dentry,
			    const char *symname)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	char *encoded_symname;
	size_t encoded_symlen;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat = NULL;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	mount_crypt_stat = &ecryptfs_superblock_to_private(
		dir->i_sb)->mount_crypt_stat;
	rc = ecryptfs_encrypt_and_encode_filename(&encoded_symname,
						  &encoded_symlen,
						  NULL,
						  mount_crypt_stat, symname,
						  strlen(symname));
	if (rc)
		goto out_lock;
	rc = vfs_symlink(lower_dir_dentry->d_inode, lower_dentry,
			 encoded_symname);
	kfree(encoded_symname);
	if (rc || !lower_dentry->d_inode)
		goto out_lock;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb, 0);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int ecryptfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mkdir(lower_dir_dentry->d_inode, lower_dentry, mode);
	if (rc || !lower_dentry->d_inode)
		goto out;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb, 0);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	dir->i_nlink = lower_dir_dentry->d_inode->i_nlink;
out:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int ecryptfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int rc;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	dget(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	dget(lower_dentry);
	rc = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	dput(lower_dentry);
	if (!rc)
		d_delete(lower_dentry);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	dir->i_nlink = lower_dir_dentry->d_inode->i_nlink;
	unlock_dir(lower_dir_dentry);
	if (!rc)
		d_drop(dentry);
	dput(dentry);
	return rc;
}

static int
ecryptfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mknod(lower_dir_dentry->d_inode, lower_dentry, mode, dev);
	if (rc || !lower_dentry->d_inode)
		goto out;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb, 0);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
out:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

#ifdef CONFIG_FS_SYNO_ACL
static void CopySynoArchive(struct dentry *ecrypt_entry, struct dentry *lower_entry)
{
	if (ecrypt_entry && ecrypt_entry->d_inode && lower_entry && lower_entry->d_inode) {
		ecrypt_entry->d_inode->i_archive_bit = lower_entry->d_inode->i_archive_bit;
	}
}
#endif

static int
ecryptfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	int rc;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;

	lower_old_dentry = ecryptfs_dentry_to_lower(old_dentry);
	lower_new_dentry = ecryptfs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);
	lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	rc = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			lower_new_dir_dentry->d_inode, lower_new_dentry);

#ifdef CONFIG_FS_SYNO_ACL
	CopySynoArchive(old_dentry, lower_old_dentry);
	CopySynoArchive(new_dentry, lower_new_dentry);
#endif

	if (rc)
		goto out_lock;
	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode, NULL);
	if (new_dir != old_dir)
		fsstack_copy_attr_all(old_dir, lower_old_dir_dentry->d_inode, NULL);
out_lock:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_new_dentry->d_parent);
	dput(lower_old_dentry->d_parent);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return rc;
}

static int ecryptfs_readlink_lower(struct dentry *dentry, char **buf,
				   size_t *bufsiz)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	char *lower_buf;
	size_t lower_bufsiz = PATH_MAX;
	mm_segment_t old_fs;
	int rc;

	lower_buf = kmalloc(lower_bufsiz, GFP_KERNEL);
	if (!lower_buf) {
		rc = -ENOMEM;
		goto out;
	}
	old_fs = get_fs();
	set_fs(get_ds());
	rc = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						   (char __user *)lower_buf,
						   lower_bufsiz);
	set_fs(old_fs);
	if (rc < 0)
		goto out;
	lower_bufsiz = rc;
	rc = ecryptfs_decode_and_decrypt_filename(buf, bufsiz, dentry,
						  lower_buf, lower_bufsiz);
out:
	kfree(lower_buf);
	return rc;
}

static int
ecryptfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	char *kbuf;
	size_t kbufsiz, copied;
	int rc;

	rc = ecryptfs_readlink_lower(dentry, &kbuf, &kbufsiz);
	if (rc)
		goto out;
	copied = min_t(size_t, bufsiz, kbufsiz);
	rc = copy_to_user(buf, kbuf, copied) ? -EFAULT : copied;
	kfree(kbuf);
	fsstack_copy_attr_atime(dentry->d_inode,
				ecryptfs_dentry_to_lower(dentry)->d_inode);
out:
	return rc;
}

static void *ecryptfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, rc;
	mm_segment_t old_fs;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}
	old_fs = get_fs();
	set_fs(get_ds());
	rc = dentry->d_inode->i_op->readlink(dentry, (char __user *)buf, len);
	set_fs(old_fs);
	if (rc < 0)
		goto out_free;
	else
		buf[rc] = '\0';
	rc = 0;
	nd_set_link(nd, buf);
	goto out;
out_free:
	kfree(buf);
out:
	return ERR_PTR(rc);
}

static void
ecryptfs_put_link(struct dentry *dentry, struct nameidata *nd, void *ptr)
{
	 
	kfree(nd_get_link(nd));
}

static loff_t
upper_size_to_lower_size(struct ecryptfs_crypt_stat *crypt_stat,
			 loff_t upper_size)
{
	loff_t lower_size;

	lower_size = crypt_stat->num_header_bytes_at_front;
	if (upper_size != 0) {
		loff_t num_extents;

		num_extents = upper_size >> crypt_stat->extent_shift;
		if (upper_size & ~crypt_stat->extent_mask)
			num_extents++;
		lower_size += (num_extents * crypt_stat->extent_size);
	}
	return lower_size;
}

int ecryptfs_truncate(struct dentry *dentry, loff_t new_length)
{
	int rc = 0;
	struct inode *inode = dentry->d_inode;
	struct dentry *lower_dentry;
	struct file fake_ecryptfs_file;
	struct ecryptfs_crypt_stat *crypt_stat;
	loff_t i_size = i_size_read(inode);
#ifdef MY_ABC_HERE
#else
	loff_t lower_size_before_truncate;
#endif
	loff_t lower_size_after_truncate;

	if (unlikely((new_length == i_size)))
#ifdef MY_ABC_HERE
		return 0;
	rc = ecryptfs_get_lower_file(dentry);
	if (rc)
		return rc;
#else
		goto out;
#endif  
	crypt_stat = &ecryptfs_inode_to_private(dentry->d_inode)->crypt_stat;
	 
	memset(&fake_ecryptfs_file, 0, sizeof(fake_ecryptfs_file));
	fake_ecryptfs_file.f_path.dentry = dentry;
	 
	ecryptfs_set_file_private(&fake_ecryptfs_file,
				  kmem_cache_alloc(ecryptfs_file_info_cache,
						   GFP_KERNEL));
	if (unlikely(!ecryptfs_file_to_private(&fake_ecryptfs_file))) {
		rc = -ENOMEM;
		goto out;
	}
	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	ecryptfs_set_file_lower(
		&fake_ecryptfs_file,
		ecryptfs_inode_to_private(dentry->d_inode)->lower_file);

#ifdef MY_ABC_HERE
	{
	if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		rc = ecryptfs_vmtruncate(inode, new_length);
		if (rc)
			goto out_free;
		rc = ecryptfs_vmtruncate(lower_dentry->d_inode, new_length);
		goto out_free;
	}

	ecryptfs_vmtruncate(inode, new_length);
	rc = ecryptfs_write_inode_size_to_metadata(inode);
	if (rc) {
#ifdef MY_ABC_HERE
		if (-EDQUOT != rc)
#endif
		printk(KERN_ERR	"Problem with "
			   "ecryptfs_write_inode_size_to_metadata; "
			   "rc = [%d]\n", rc);
		goto out_free;
	}

	lower_size_after_truncate =
	upper_size_to_lower_size(crypt_stat, new_length);
	ecryptfs_vmtruncate(lower_dentry->d_inode,
	lower_size_after_truncate);
	}
#else
	 
	if (new_length > i_size) {
		char zero[] = { 0x00 };

		rc = ecryptfs_write(&fake_ecryptfs_file, zero,
				    (new_length - 1), 1);
	} else {  
		 
		size_t num_zeros = (PAGE_CACHE_SIZE
				    - (new_length & ~PAGE_CACHE_MASK));

		if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
			rc = vmtruncate(inode, new_length);
			if (rc)
				goto out_free;
			rc = vmtruncate(lower_dentry->d_inode, new_length);
			goto out_free;
		}
		if (num_zeros) {
			char *zeros_virt;

			zeros_virt = kzalloc(num_zeros, GFP_KERNEL);
			if (!zeros_virt) {
				rc = -ENOMEM;
				goto out_free;
			}
			rc = ecryptfs_write(&fake_ecryptfs_file, zeros_virt,
					    new_length, num_zeros);
			kfree(zeros_virt);
			if (rc) {
				printk(KERN_ERR "Error attempting to zero out "
				       "the remainder of the end page on "
				       "reducing truncate; rc = [%d]\n", rc);
				goto out_free;
			}
		}
		vmtruncate(inode, new_length);
		rc = ecryptfs_write_inode_size_to_metadata(inode);
		if (rc) {
			printk(KERN_ERR	"Problem with "
			       "ecryptfs_write_inode_size_to_metadata; "
			       "rc = [%d]\n", rc);
			goto out_free;
		}
		 
		lower_size_before_truncate =
		    upper_size_to_lower_size(crypt_stat, i_size);
		lower_size_after_truncate =
		    upper_size_to_lower_size(crypt_stat, new_length);
		if (lower_size_after_truncate < lower_size_before_truncate)
			vmtruncate(lower_dentry->d_inode,
				   lower_size_after_truncate);
	}
#endif
out_free:
	if (ecryptfs_file_to_private(&fake_ecryptfs_file))
		kmem_cache_free(ecryptfs_file_info_cache,
				ecryptfs_file_to_private(&fake_ecryptfs_file));
out:
#ifdef MY_ABC_HERE
	ecryptfs_put_lower_file(inode);
#endif  
	return rc;
}

#ifdef MY_ABC_HERE
static int ecryptfs_syno_set_crtime(struct dentry *dentry, struct timespec *time)
{
	int error;
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	error = syno_op_set_crtime(lower_dentry, time);
	if (!error) {
		dentry->d_inode->i_create_time = *time;
	}
	return error;
}
#endif

#ifdef MY_ABC_HERE
static int ecryptfs_syno_set_archive_bit(struct dentry *dentry, unsigned int arbit)
{
	int error;
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	error = syno_op_set_archive_bit(lower_dentry, arbit);
	if (!error) {
		dentry->d_inode->i_archive_bit = arbit;
	}
	return error;
}
#endif  

#ifdef MY_ABC_HERE
static int ecryptfs_syno_set_archive_ver(struct dentry *dentry, u32 version)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	if (!lower_dentry->d_inode->i_op->syno_set_archive_ver)
		return -EINVAL;
	return lower_dentry->d_inode->i_op->syno_set_archive_ver(lower_dentry, version);
}

static int ecryptfs_syno_get_archive_ver(struct dentry *dentry, u32 *version)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	if (!lower_dentry->d_inode->i_op->syno_get_archive_ver)
		return -EINVAL;
	return lower_dentry->d_inode->i_op->syno_get_archive_ver(lower_dentry, version);
}
#endif

#ifdef CONFIG_FS_SYNO_ACL
static int ecryptfs_get_syno_acl_xattr(struct dentry *dentry, int cmd, void *value, size_t size)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_get_acl_xattr(lower_dentry, cmd, value, size);
}

static int
ecryptfs_syno_inode_change_ok(struct dentry *dentry, struct iattr *attr)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_inode_change_ok(lower_dentry, attr);
}

static int
ecryptfs_syno_arbit_chg_ok(struct dentry *dentry, unsigned int cmd, int tag, int mask)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_archive_change_ok(lower_dentry, cmd, tag, mask);
}

static int
ecryptfs_syno_setattr_post(struct dentry *dentry, struct iattr *attr)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_setattr_post(lower_dentry, attr);
}
 
static int
ecryptfs_syno_exec_permission(struct dentry *dentry)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_exec_permission(lower_dentry);
}

static int
ecryptfs_syno_acl_access(struct dentry *dentry, int mask, int syno_acl_access)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_access(lower_dentry, mask, syno_acl_access);
}

static void
ecryptfs_syno_acl_to_mode(struct dentry *dentry, struct kstat *stat)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	synoacl_mod_to_mode(lower_dentry, stat);
}
 
static int
ecryptfs_syno_permission(struct dentry *dentry, int mask)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_permission(lower_dentry, mask);
}
static int
ecryptfs_syno_acl_init(struct dentry *dentry, struct inode *inode)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	return synoacl_mod_init_acl(lower_dentry, lower_dentry->d_inode);
}
#endif  

static int
ecryptfs_permission(struct inode *inode, int mask)
{
	return inode_permission(ecryptfs_inode_to_lower(inode), mask);
}

static int ecryptfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int rc = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct ecryptfs_crypt_stat *crypt_stat;

	crypt_stat = &ecryptfs_inode_to_private(dentry->d_inode)->crypt_stat;
	if (!(crypt_stat->flags & ECRYPTFS_STRUCT_INITIALIZED))
		ecryptfs_init_crypt_stat(crypt_stat);
	inode = dentry->d_inode;
	lower_inode = ecryptfs_inode_to_lower(inode);
	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	mutex_lock(&crypt_stat->cs_mutex);
	if (S_ISDIR(dentry->d_inode->i_mode))
		crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
	else if (S_ISREG(dentry->d_inode->i_mode)
		 && (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED)
		     || !(crypt_stat->flags & ECRYPTFS_KEY_VALID))) {
		struct ecryptfs_mount_crypt_stat *mount_crypt_stat;

		mount_crypt_stat = &ecryptfs_superblock_to_private(
			dentry->d_sb)->mount_crypt_stat;
#ifdef MY_ABC_HERE
		rc = ecryptfs_get_lower_file(dentry);
		if (rc) {
			mutex_unlock(&crypt_stat->cs_mutex);
			goto out;
		}
		rc = ecryptfs_read_metadata(dentry);
		ecryptfs_put_lower_file(inode);
#else
		rc = ecryptfs_read_metadata(dentry);
#endif  
		if (rc) {
			if (!(mount_crypt_stat->flags
			      & ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED)) {
				rc = -EIO;
				printk(KERN_WARNING "Either the lower file "
				       "is not in a valid eCryptfs format, "
				       "or the key could not be retrieved. "
				       "Plaintext passthrough mode is not "
				       "enabled; returning -EIO\n");
				mutex_unlock(&crypt_stat->cs_mutex);
				goto out;
			}
			rc = 0;
			crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
		}
	}
	mutex_unlock(&crypt_stat->cs_mutex);
	if (ia->ia_valid & ATTR_SIZE) {
		ecryptfs_printk(KERN_DEBUG,
				"ia->ia_valid = [0x%x] ATTR_SIZE" " = [0x%x]\n",
				ia->ia_valid, ATTR_SIZE);
		rc = ecryptfs_truncate(dentry, ia->ia_size);
		 
		ia->ia_valid &= ~ATTR_SIZE;
		ecryptfs_printk(KERN_DEBUG, "ia->ia_valid = [%x]\n",
				ia->ia_valid);
		if (rc < 0)
			goto out;
	}

	if (ia->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		ia->ia_valid &= ~ATTR_MODE;

	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = notify_change(lower_dentry, ia);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	fsstack_copy_attr_all(inode, lower_inode, NULL);
	return rc;
}

int ecryptfs_getattr_link(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	int rc = 0;

	mount_crypt_stat = &ecryptfs_superblock_to_private(
						dentry->d_sb)->mount_crypt_stat;
	generic_fillattr(dentry->d_inode, stat);
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES) {
		char *target;
		size_t targetsiz;

		rc = ecryptfs_readlink_lower(dentry, &target, &targetsiz);
		if (!rc) {
			kfree(target);
			stat->size = targetsiz;
		}
	}
	return rc;
}

int ecryptfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		     struct kstat *stat)
{
	struct kstat lower_stat;
	int rc;

	rc = vfs_getattr(ecryptfs_dentry_to_lower_mnt(dentry),
			 ecryptfs_dentry_to_lower(dentry), &lower_stat);

	if (!rc) {
		generic_fillattr(dentry->d_inode, stat);
		stat->blocks = lower_stat.blocks;
#ifdef MY_ABC_HERE
		stat->syno_archive_bit = lower_stat.syno_archive_bit;
#endif
#ifdef MY_ABC_HERE
		stat->syno_create_time = lower_stat.syno_create_time;
#endif
#ifdef MY_ABC_HERE
		stat->syno_archive_version = lower_stat.syno_archive_version;
#endif
#ifdef CONFIG_FS_SYNO_ACL
		stat->mode = lower_stat.mode;
#endif
	}
	return rc;
}

int
ecryptfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		  size_t size, int flags)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->setxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->setxattr(lower_dentry, name, value,
						   size, flags);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
#ifdef CONFIG_FS_SYNO_ACL
	if (name && !strcmp(name, SYNO_ACL_XATTR_ACCESS)) {
		 
		dentry->d_inode->i_archive_bit = lower_dentry->d_inode->i_archive_bit;
	}
#endif
out:
	return rc;
}

ssize_t
ecryptfs_getxattr_lower(struct dentry *lower_dentry, const char *name,
			void *value, size_t size)
{
	int rc = 0;

	if (!lower_dentry->d_inode->i_op->getxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->getxattr(lower_dentry, name, value,
						   size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

static ssize_t
ecryptfs_getxattr(struct dentry *dentry, const char *name, void *value,
		  size_t size)
{
	return ecryptfs_getxattr_lower(ecryptfs_dentry_to_lower(dentry), name,
				       value, size);
}

static ssize_t
ecryptfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->listxattr(lower_dentry, list, size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

static int ecryptfs_removexattr(struct dentry *dentry, const char *name)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->removexattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

int ecryptfs_inode_test(struct inode *inode, void *candidate_lower_inode)
{
	if ((ecryptfs_inode_to_lower(inode)
	     == (struct inode *)candidate_lower_inode))
		return 1;
	else
		return 0;
}

int ecryptfs_inode_set(struct inode *inode, void *lower_inode)
{
	ecryptfs_init_inode(inode, (struct inode *)lower_inode);
	return 0;
}

const struct inode_operations ecryptfs_symlink_iops = {
#ifdef MY_ABC_HERE
	.syno_set_crtime = ecryptfs_syno_set_crtime,
#endif
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = ecryptfs_syno_set_archive_bit,
#endif
#ifdef MY_ABC_HERE
	.syno_get_archive_ver = ecryptfs_syno_get_archive_ver,
	.syno_set_archive_ver = ecryptfs_syno_set_archive_ver,
#endif
	.readlink = ecryptfs_readlink,
	.follow_link = ecryptfs_follow_link,
	.put_link = ecryptfs_put_link,
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.getattr = ecryptfs_getattr_link,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};

const struct inode_operations ecryptfs_dir_iops = {
	.create = ecryptfs_create,
	.lookup = ecryptfs_lookup,
	.link = ecryptfs_link,
	.unlink = ecryptfs_unlink,
	.symlink = ecryptfs_symlink,
	.mkdir = ecryptfs_mkdir,
	.rmdir = ecryptfs_rmdir,
	.mknod = ecryptfs_mknod,
	.rename = ecryptfs_rename,
#ifdef CONFIG_FS_SYNO_ACL
	.getattr = ecryptfs_getattr,
	.syno_permission = ecryptfs_syno_permission,
	.syno_acl_access = ecryptfs_syno_acl_access,
	.syno_acl_xattr_get = ecryptfs_get_syno_acl_xattr,
	.syno_exec_permission = ecryptfs_syno_exec_permission,
	.syno_inode_change_ok = ecryptfs_syno_inode_change_ok,
	.syno_arbit_chg_ok = ecryptfs_syno_arbit_chg_ok,
	.syno_setattr_post = ecryptfs_syno_setattr_post,
	.syno_acl_to_mode = ecryptfs_syno_acl_to_mode,
	.syno_acl_init = ecryptfs_syno_acl_init,
#endif
#ifdef MY_ABC_HERE
	.syno_set_crtime = ecryptfs_syno_set_crtime,
#endif
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = ecryptfs_syno_set_archive_bit,
#endif
#ifdef MY_ABC_HERE
	.syno_get_archive_ver = ecryptfs_syno_get_archive_ver,
	.syno_set_archive_ver = ecryptfs_syno_set_archive_ver,
#endif
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};

const struct inode_operations ecryptfs_main_iops = {
#ifdef CONFIG_FS_SYNO_ACL
	.syno_acl_xattr_get = ecryptfs_get_syno_acl_xattr,
	.syno_acl_access = ecryptfs_syno_acl_access,
	.syno_permission = ecryptfs_syno_permission,
	.syno_exec_permission = ecryptfs_syno_exec_permission,
	.syno_inode_change_ok = ecryptfs_syno_inode_change_ok,
	.syno_arbit_chg_ok = ecryptfs_syno_arbit_chg_ok,
	.syno_setattr_post = ecryptfs_syno_setattr_post,
	.syno_acl_to_mode = ecryptfs_syno_acl_to_mode,
	.syno_acl_init = ecryptfs_syno_acl_init,
#endif
#ifdef MY_ABC_HERE
	.syno_set_crtime = ecryptfs_syno_set_crtime,
#endif
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = ecryptfs_syno_set_archive_bit,
#endif
#ifdef MY_ABC_HERE
	.syno_get_archive_ver = ecryptfs_syno_get_archive_ver,
	.syno_set_archive_ver = ecryptfs_syno_set_archive_ver,
#endif
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.getattr = ecryptfs_getattr,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};
