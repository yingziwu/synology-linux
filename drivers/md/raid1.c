#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/seq_file.h>
#include "md.h"
#include "raid1.h"
#include "bitmap.h"
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
#include "hwraid.h"
#endif

#define DEBUG 0
#if DEBUG
#define PRINTK(x...) printk(x)
#else
#define PRINTK(x...)
#endif

#define	NR_RAID1_BIOS 256

static void unplug_slaves(mddev_t *mddev);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
void raid1_allow_barrier(conf_t *conf);
void raid1_lower_barrier(conf_t *conf);
#else
static void allow_barrier(conf_t *conf);
static void lower_barrier(conf_t *conf);
#endif

#ifdef MY_ABC_HERE
static unsigned char IsDiskErrorSet(mddev_t *mddev)
{
	int i;
	unsigned char res = 0;
	conf_t *conf = mddev->private;
	mdk_rdev_t *rdev_tmp = NULL;

	for (i = 0; i < conf->raid_disks; i++) {
		rdev_tmp = conf->mirrors[i].rdev;
		if (rdev_tmp && test_bit(DiskError, &rdev_tmp->flags)) {
			res = 1;
			goto END;
		}
	}
END:
	return res;
}
#endif

#ifdef MY_ABC_HERE
static inline unsigned char SynoIsRaidReachMaxDegrade(mddev_t *mddev)
{
    conf_t *conf = mddev->private;
    if (mddev->degraded >= conf->raid_disks - 1) {
        return true;
    }
    return false;
}
#endif

static void * r1bio_pool_alloc(gfp_t gfp_flags, void *data)
{
	struct pool_info *pi = data;
	r1bio_t *r1_bio;
	int size = offsetof(r1bio_t, bios[pi->raid_disks]);

	r1_bio = kzalloc(size, gfp_flags);
	if (!r1_bio && pi->mddev)
		unplug_slaves(pi->mddev);

	return r1_bio;
}

static void r1bio_pool_free(void *r1_bio, void *data)
{
	kfree(r1_bio);
}

#define RESYNC_BLOCK_SIZE (64*1024)
 
#define RESYNC_SECTORS (RESYNC_BLOCK_SIZE >> 9)
#define RESYNC_PAGES ((RESYNC_BLOCK_SIZE + PAGE_SIZE-1) / PAGE_SIZE)
#define RESYNC_WINDOW (2048*1024)

static void * r1buf_pool_alloc(gfp_t gfp_flags, void *data)
{
	struct pool_info *pi = data;
	struct page *page;
	r1bio_t *r1_bio;
	struct bio *bio;
	int i, j;

	r1_bio = r1bio_pool_alloc(gfp_flags, pi);
	if (!r1_bio) {
		unplug_slaves(pi->mddev);
		return NULL;
	}

	for (j = pi->raid_disks ; j-- ; ) {
		bio = bio_alloc(gfp_flags, RESYNC_PAGES);
		if (!bio)
			goto out_free_bio;
		r1_bio->bios[j] = bio;
	}
	 
	if (test_bit(MD_RECOVERY_REQUESTED, &pi->mddev->recovery))
		j = pi->raid_disks;
	else
		j = 1;
	while(j--) {
		bio = r1_bio->bios[j];
		for (i = 0; i < RESYNC_PAGES; i++) {
			page = alloc_page(gfp_flags);
			if (unlikely(!page))
				goto out_free_pages;

			bio->bi_io_vec[i].bv_page = page;
			bio->bi_vcnt = i+1;
		}
	}
	 
	if (!test_bit(MD_RECOVERY_REQUESTED, &pi->mddev->recovery)) {
		for (i=0; i<RESYNC_PAGES ; i++)
			for (j=1; j<pi->raid_disks; j++)
				r1_bio->bios[j]->bi_io_vec[i].bv_page =
					r1_bio->bios[0]->bi_io_vec[i].bv_page;
	}

	r1_bio->master_bio = NULL;

	return r1_bio;

out_free_pages:
	for (j=0 ; j < pi->raid_disks; j++)
		for (i=0; i < r1_bio->bios[j]->bi_vcnt ; i++)
			put_page(r1_bio->bios[j]->bi_io_vec[i].bv_page);
	j = -1;
out_free_bio:
	while ( ++j < pi->raid_disks )
		bio_put(r1_bio->bios[j]);
	r1bio_pool_free(r1_bio, data);
	return NULL;
}

static void r1buf_pool_free(void *__r1_bio, void *data)
{
	struct pool_info *pi = data;
	int i,j;
	r1bio_t *r1bio = __r1_bio;

	for (i = 0; i < RESYNC_PAGES; i++)
		for (j = pi->raid_disks; j-- ;) {
			if (j == 0 ||
			    r1bio->bios[j]->bi_io_vec[i].bv_page !=
			    r1bio->bios[0]->bi_io_vec[i].bv_page)
				safe_put_page(r1bio->bios[j]->bi_io_vec[i].bv_page);
		}
	for (i=0 ; i < pi->raid_disks; i++)
		bio_put(r1bio->bios[i]);

	r1bio_pool_free(r1bio, data);
}

static void put_all_bios(conf_t *conf, r1bio_t *r1_bio)
{
	int i;

	for (i = 0; i < conf->raid_disks; i++) {
		struct bio **bio = r1_bio->bios + i;
		if (*bio && *bio != IO_BLOCKED)
			bio_put(*bio);
		*bio = NULL;
	}
}

static void free_r1bio(r1bio_t *r1_bio)
{
	conf_t *conf = r1_bio->mddev->private;

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_allow_barrier(conf);
#else
	allow_barrier(conf);
#endif

	put_all_bios(conf, r1_bio);
	mempool_free(r1_bio, conf->r1bio_pool);
}

static void put_buf(r1bio_t *r1_bio)
{
	conf_t *conf = r1_bio->mddev->private;
	int i;

	for (i=0; i<conf->raid_disks; i++) {
		struct bio *bio = r1_bio->bios[i];
		if (bio->bi_end_io)
			rdev_dec_pending(conf->mirrors[i].rdev, r1_bio->mddev);
	}

	mempool_free(r1_bio, conf->r1buf_pool);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_lower_barrier(conf);
#else
	lower_barrier(conf);
#endif
}

static void reschedule_retry(r1bio_t *r1_bio)
{
	unsigned long flags;
	mddev_t *mddev = r1_bio->mddev;
	conf_t *conf = mddev->private;

	spin_lock_irqsave(&conf->device_lock, flags);
	list_add(&r1_bio->retry_list, &conf->retry_list);
	conf->nr_queued ++;
	spin_unlock_irqrestore(&conf->device_lock, flags);

	wake_up(&conf->wait_barrier);
	md_wakeup_thread(mddev->thread);
}

static void raid_end_bio_io(r1bio_t *r1_bio)
{
	struct bio *bio = r1_bio->master_bio;

	if (!test_and_set_bit(R1BIO_Returned, &r1_bio->state)) {
		PRINTK(KERN_DEBUG "raid1: sync end %s on sectors %llu-%llu\n",
			(bio_data_dir(bio) == WRITE) ? "write" : "read",
			(unsigned long long) bio->bi_sector,
			(unsigned long long) bio->bi_sector +
				(bio->bi_size >> 9) - 1);

		bio_endio(bio,
			test_bit(R1BIO_Uptodate, &r1_bio->state) ? 0 : -EIO);
	}
	free_r1bio(r1_bio);
}

static inline void update_head_pos(int disk, r1bio_t *r1_bio)
{
	conf_t *conf = r1_bio->mddev->private;

	conf->mirrors[disk].head_position =
		r1_bio->sector + (r1_bio->sectors);
}

static void raid1_end_read_request(struct bio *bio, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	r1bio_t * r1_bio = (r1bio_t *)(bio->bi_private);
	int mirror;
	conf_t *conf = r1_bio->mddev->private;

	mirror = r1_bio->read_disk;
	 
	update_head_pos(mirror, r1_bio);

#ifdef MY_ABC_HERE
	if (bio_flagged(bio, BIO_AUTO_REMAP)) {
		printk("%s:%s(%d) BIO_AUTO_REMAP detected\n", __FILE__,__FUNCTION__,__LINE__);
		SynoAutoRemapReport(conf->mddev, r1_bio->sector, conf->mirrors[mirror].rdev->bdev);
	}
#endif

	if (uptodate)
		set_bit(R1BIO_Uptodate, &r1_bio->state);
	else {
		 
		unsigned long flags;
		spin_lock_irqsave(&conf->device_lock, flags);
		if (r1_bio->mddev->degraded == conf->raid_disks ||
		    (r1_bio->mddev->degraded == conf->raid_disks-1 &&
		     !test_bit(Faulty, &conf->mirrors[mirror].rdev->flags)))
			uptodate = 1;
		spin_unlock_irqrestore(&conf->device_lock, flags);

#ifdef MY_ABC_HERE
		 
		if (IsDeviceDisappear(conf->mirrors[mirror].rdev->bdev)) {
			syno_md_error(r1_bio->mddev, conf->mirrors[mirror].rdev);
		}else{
#ifdef MY_ABC_HERE
			SynoReportBadSector(bio->bi_sector, READ,
								conf->mddev->md_minor, conf->mirrors[mirror].rdev->bdev, __FUNCTION__);

			if (uptodate) {
				 
				md_error(r1_bio->mddev, conf->mirrors[mirror].rdev);
			}
#endif
		}
#endif
	}

	if (uptodate) {
		raid_end_bio_io(r1_bio);
		rdev_dec_pending(conf->mirrors[mirror].rdev, conf->mddev);
	} else {
		 
		char b[BDEVNAME_SIZE];
		if (printk_ratelimit())
			printk(KERN_ERR "raid1: %s: rescheduling sector %llu\n",
			       bdevname(conf->mirrors[mirror].rdev->bdev,b), (unsigned long long)r1_bio->sector);
		reschedule_retry(r1_bio);
		 
	}
}

static void raid1_end_write_request(struct bio *bio, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	r1bio_t * r1_bio = (r1bio_t *)(bio->bi_private);
	int mirror, behind = test_bit(R1BIO_BehindIO, &r1_bio->state);
	conf_t *conf = r1_bio->mddev->private;
	struct bio *to_put = NULL;

	for (mirror = 0; mirror < conf->raid_disks; mirror++)
		if (r1_bio->bios[mirror] == bio)
			break;

	if (error == -EOPNOTSUPP && test_bit(R1BIO_Barrier, &r1_bio->state)) {
		set_bit(BarriersNotsupp, &conf->mirrors[mirror].rdev->flags);
		set_bit(R1BIO_BarrierRetry, &r1_bio->state);
		r1_bio->mddev->barriers_work = 0;
		 
	} else {
		 
		r1_bio->bios[mirror] = NULL;
		to_put = bio;
		if (!uptodate) {
#ifdef MY_ABC_HERE
			if (IsDeviceDisappear(conf->mirrors[mirror].rdev->bdev)) {
				syno_md_error(r1_bio->mddev, conf->mirrors[mirror].rdev);
			}else{
#ifdef MY_ABC_HERE
				SynoReportBadSector(bio->bi_sector, WRITE, conf->mddev->md_minor,
									conf->mirrors[mirror].rdev->bdev, __FUNCTION__);
#endif
				md_error(r1_bio->mddev, conf->mirrors[mirror].rdev);
			}
#else
			md_error(r1_bio->mddev, conf->mirrors[mirror].rdev);
#endif
			 
			set_bit(R1BIO_Degraded, &r1_bio->state);
		} else
			 
			set_bit(R1BIO_Uptodate, &r1_bio->state);

		update_head_pos(mirror, r1_bio);

		if (behind) {
			if (test_bit(WriteMostly, &conf->mirrors[mirror].rdev->flags))
				atomic_dec(&r1_bio->behind_remaining);

			if (atomic_read(&r1_bio->behind_remaining) >= (atomic_read(&r1_bio->remaining)-1) &&
			    test_bit(R1BIO_Uptodate, &r1_bio->state)) {
				 
				if (!test_and_set_bit(R1BIO_Returned, &r1_bio->state)) {
					struct bio *mbio = r1_bio->master_bio;
					PRINTK(KERN_DEBUG "raid1: behind end write sectors %llu-%llu\n",
					       (unsigned long long) mbio->bi_sector,
					       (unsigned long long) mbio->bi_sector +
					       (mbio->bi_size >> 9) - 1);
					bio_endio(mbio, 0);
				}
			}
		}
		rdev_dec_pending(conf->mirrors[mirror].rdev, conf->mddev);
	}
	 
	if (atomic_dec_and_test(&r1_bio->remaining)) {
		if (test_bit(R1BIO_BarrierRetry, &r1_bio->state))
			reschedule_retry(r1_bio);
		else {
			 
			if (test_bit(R1BIO_BehindIO, &r1_bio->state)) {
				 
				int i = bio->bi_vcnt;
				while (i--)
					safe_put_page(bio->bi_io_vec[i].bv_page);
			}
			 
			bitmap_endwrite(r1_bio->mddev->bitmap, r1_bio->sector,
					r1_bio->sectors,
					!test_bit(R1BIO_Degraded, &r1_bio->state),
					behind);
			md_write_end(r1_bio->mddev);
			raid_end_bio_io(r1_bio);
		}
	}

	if (to_put)
		bio_put(to_put);
}

static int read_balance(conf_t *conf, r1bio_t *r1_bio)
{
	const unsigned long this_sector = r1_bio->sector;
	int new_disk = conf->last_used, disk = new_disk;
	int wonly_disk = -1;
	const int sectors = r1_bio->sectors;
	sector_t new_distance, current_distance;
	mdk_rdev_t *rdev;

	rcu_read_lock();
	 
 retry:
	if (conf->mddev->recovery_cp < MaxSector &&
	    (this_sector + sectors >= conf->next_resync)) {
		 
		new_disk = 0;

		for (rdev = rcu_dereference(conf->mirrors[new_disk].rdev);
		     r1_bio->bios[new_disk] == IO_BLOCKED ||
		     !rdev || !test_bit(In_sync, &rdev->flags)
			     || test_bit(WriteMostly, &rdev->flags);
		     rdev = rcu_dereference(conf->mirrors[++new_disk].rdev)) {

			if (rdev && test_bit(In_sync, &rdev->flags) &&
				r1_bio->bios[new_disk] != IO_BLOCKED)
				wonly_disk = new_disk;

			if (new_disk == conf->raid_disks - 1) {
				new_disk = wonly_disk;
				break;
			}
		}
		goto rb_out;
	}

	for (rdev = rcu_dereference(conf->mirrors[new_disk].rdev);
	     r1_bio->bios[new_disk] == IO_BLOCKED ||
	     !rdev || !test_bit(In_sync, &rdev->flags) ||
		     test_bit(WriteMostly, &rdev->flags);
	     rdev = rcu_dereference(conf->mirrors[new_disk].rdev)) {

		if (rdev && test_bit(In_sync, &rdev->flags) &&
		    r1_bio->bios[new_disk] != IO_BLOCKED)
			wonly_disk = new_disk;

		if (new_disk <= 0)
			new_disk = conf->raid_disks;
		new_disk--;
		if (new_disk == disk) {
			new_disk = wonly_disk;
			break;
		}
	}

	if (new_disk < 0)
		goto rb_out;

	disk = new_disk;
	 
	if (conf->next_seq_sect == this_sector)
		goto rb_out;
	if (this_sector == conf->mirrors[new_disk].head_position)
		goto rb_out;

	current_distance = abs(this_sector - conf->mirrors[disk].head_position);

	do {
		if (disk <= 0)
			disk = conf->raid_disks;
		disk--;

		rdev = rcu_dereference(conf->mirrors[disk].rdev);

		if (!rdev || r1_bio->bios[disk] == IO_BLOCKED ||
		    !test_bit(In_sync, &rdev->flags) ||
		    test_bit(WriteMostly, &rdev->flags))
			continue;

		if (!atomic_read(&rdev->nr_pending)) {
			new_disk = disk;
			break;
		}
		new_distance = abs(this_sector - conf->mirrors[disk].head_position);
		if (new_distance < current_distance) {
			current_distance = new_distance;
			new_disk = disk;
		}
	} while (disk != conf->last_used);

 rb_out:

	if (new_disk >= 0) {
		rdev = rcu_dereference(conf->mirrors[new_disk].rdev);
		if (!rdev)
			goto retry;
		atomic_inc(&rdev->nr_pending);
		if (!test_bit(In_sync, &rdev->flags)) {
			 
			rdev_dec_pending(rdev, conf->mddev);
			goto retry;
		}
		conf->next_seq_sect = this_sector + sectors;
		conf->last_used = new_disk;
	}
	rcu_read_unlock();

	return new_disk;
}

static void unplug_slaves(mddev_t *mddev)
{
	conf_t *conf = mddev->private;
	int i;

	rcu_read_lock();
	for (i=0; i<mddev->raid_disks; i++) {
		mdk_rdev_t *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev && !test_bit(Faulty, &rdev->flags) && atomic_read(&rdev->nr_pending)) {
			struct request_queue *r_queue = bdev_get_queue(rdev->bdev);

			atomic_inc(&rdev->nr_pending);
			rcu_read_unlock();

			blk_unplug(r_queue);

			rdev_dec_pending(rdev, mddev);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();
}

static void raid1_unplug(struct request_queue *q)
{
	mddev_t *mddev = q->queuedata;

	unplug_slaves(mddev);
	md_wakeup_thread(mddev->thread);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	 
    if (mddev->hw_raid &&
        blk_queue_stopped(q) )
    {
        unsigned long flags;
        spin_lock_irqsave(q->queue_lock, flags);
        blk_start_queue(q);
        spin_unlock_irqrestore(q->queue_lock, flags);
    }
#endif
}

static int raid1_congested(void *data, int bits)
{
	mddev_t *mddev = data;
	conf_t *conf = mddev->private;
	int i, ret = 0;

	if (mddev_congested(mddev, bits))
		return 1;

	rcu_read_lock();
	for (i = 0; i < mddev->raid_disks; i++) {
		mdk_rdev_t *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev && !test_bit(Faulty, &rdev->flags)) {
			struct request_queue *q = bdev_get_queue(rdev->bdev);

			if ((bits & (1<<BDI_async_congested)) || 1)
				ret |= bdi_congested(&q->backing_dev_info, bits);
			else
				ret &= bdi_congested(&q->backing_dev_info, bits);
		}
	}
	rcu_read_unlock();
	return ret;
}

static int flush_pending_writes(conf_t *conf)
{
	 
	int rv = 0;

	spin_lock_irq(&conf->device_lock);

	if (conf->pending_bio_list.head) {
		struct bio *bio;
		bio = bio_list_get(&conf->pending_bio_list);
		blk_remove_plug(conf->mddev->queue);
		spin_unlock_irq(&conf->device_lock);
		 
		bitmap_unplug(conf->mddev->bitmap);

		while (bio) {  
			struct bio *next = bio->bi_next;
			bio->bi_next = NULL;
			generic_make_request(bio);
			bio = next;
		}
		rv = 1;
	} else
		spin_unlock_irq(&conf->device_lock);
	return rv;
}

#define RESYNC_DEPTH 32

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
void raid1_raise_barrier(conf_t *conf)
#else
static void raise_barrier(conf_t *conf)
#endif
{
	spin_lock_irq(&conf->resync_lock);

	wait_event_lock_irq(conf->wait_barrier, !conf->nr_waiting,
			    conf->resync_lock,
			    raid1_unplug(conf->mddev->queue));

	conf->barrier++;

	wait_event_lock_irq(conf->wait_barrier,
			    !conf->nr_pending && conf->barrier < RESYNC_DEPTH,
			    conf->resync_lock,
			    raid1_unplug(conf->mddev->queue));

	spin_unlock_irq(&conf->resync_lock);
}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
void raid1_lower_barrier(conf_t *conf)
#else
static void lower_barrier(conf_t *conf)
#endif
{
	unsigned long flags;
	spin_lock_irqsave(&conf->resync_lock, flags);
	conf->barrier--;
	spin_unlock_irqrestore(&conf->resync_lock, flags);
	wake_up(&conf->wait_barrier);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	 
    if (conf->mddev->hw_raid &&
        blk_queue_stopped(conf->mddev->queue))
    {
        unsigned long flags;
        spin_lock_irqsave(conf->mddev->queue->queue_lock, flags);
        blk_start_queue(conf->mddev->queue);
        spin_unlock_irqrestore(conf->mddev->queue->queue_lock, flags);
    }
#endif
}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
void raid1_wait_barrier(conf_t *conf)
#else
static void wait_barrier(conf_t *conf)
#endif
{
	spin_lock_irq(&conf->resync_lock);
	if (conf->barrier) {
		conf->nr_waiting++;
		wait_event_lock_irq(conf->wait_barrier, !conf->barrier,
				    conf->resync_lock,
				    raid1_unplug(conf->mddev->queue));
		conf->nr_waiting--;
	}
	conf->nr_pending++;
	spin_unlock_irq(&conf->resync_lock);
}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
void raid1_allow_barrier(conf_t *conf)
#else
static void allow_barrier(conf_t *conf)
#endif
{
	unsigned long flags;
	spin_lock_irqsave(&conf->resync_lock, flags);
	conf->nr_pending--;
	spin_unlock_irqrestore(&conf->resync_lock, flags);
	wake_up(&conf->wait_barrier);
}

static void freeze_array(conf_t *conf)
{
	 
	spin_lock_irq(&conf->resync_lock);
	conf->barrier++;
	conf->nr_waiting++;
	wait_event_lock_irq(conf->wait_barrier,
			    conf->nr_pending == conf->nr_queued+1,
			    conf->resync_lock,
			    ({ flush_pending_writes(conf);
			       raid1_unplug(conf->mddev->queue); }));
	spin_unlock_irq(&conf->resync_lock);
}
static void unfreeze_array(conf_t *conf)
{
	 
	spin_lock_irq(&conf->resync_lock);
	conf->barrier--;
	conf->nr_waiting--;
	wake_up(&conf->wait_barrier);
	spin_unlock_irq(&conf->resync_lock);
}

static struct page **alloc_behind_pages(struct bio *bio)
{
	int i;
	struct bio_vec *bvec;
	struct page **pages = kzalloc(bio->bi_vcnt * sizeof(struct page *),
					GFP_NOIO);
	if (unlikely(!pages))
		goto do_sync_io;

	bio_for_each_segment(bvec, bio, i) {
		pages[i] = alloc_page(GFP_NOIO);
		if (unlikely(!pages[i]))
			goto do_sync_io;
		memcpy(kmap(pages[i]) + bvec->bv_offset,
			kmap(bvec->bv_page) + bvec->bv_offset, bvec->bv_len);
		kunmap(pages[i]);
		kunmap(bvec->bv_page);
	}

	return pages;

do_sync_io:
	if (pages)
		for (i = 0; i < bio->bi_vcnt && pages[i]; i++)
			put_page(pages[i]);
	kfree(pages);
	PRINTK("%dB behind alloc failed, doing sync I/O\n", bio->bi_size);
	return NULL;
}

static int make_request(struct request_queue *q, struct bio * bio)
{
	mddev_t *mddev = q->queuedata;
	conf_t *conf = mddev->private;
	mirror_info_t *mirror;
	r1bio_t *r1_bio;
	struct bio *read_bio;
	int i, targets = 0, disks;
	struct bitmap *bitmap;
	unsigned long flags;
	struct bio_list bl;
	struct page **behind_pages = NULL;
	const int rw = bio_data_dir(bio);
	const bool do_sync = bio_rw_flagged(bio, BIO_RW_SYNCIO);
	bool do_barriers;
	mdk_rdev_t *blocked_rdev;

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
	if (mddev->nodev_and_crashed) {
#else
	if (0 == conf->raid_disks - mddev->degraded) {
#endif
		 
		bio_endio(bio, -EIO);
		return 0;
	}
#endif  

	md_write_start(mddev, bio);  

	if (unlikely(!mddev->barriers_work &&
		     bio_rw_flagged(bio, BIO_RW_BARRIER))) {
		if (rw == WRITE)
			md_write_end(mddev);
		bio_endio(bio, -EOPNOTSUPP);
		return 0;
	}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_wait_barrier(conf);
#else
	wait_barrier(conf);
#endif

	bitmap = mddev->bitmap;

	r1_bio = mempool_alloc(conf->r1bio_pool, GFP_NOIO);

	r1_bio->master_bio = bio;
	r1_bio->sectors = bio->bi_size >> 9;
	r1_bio->state = 0;
	r1_bio->mddev = mddev;
	r1_bio->sector = bio->bi_sector;

	if (rw == READ) {
		 
		int rdisk = read_balance(conf, r1_bio);

		if (rdisk < 0) {
			 
			raid_end_bio_io(r1_bio);
			return 0;
		}
		mirror = conf->mirrors + rdisk;

		r1_bio->read_disk = rdisk;

		read_bio = bio_clone(bio, GFP_NOIO);

		r1_bio->bios[rdisk] = read_bio;

		read_bio->bi_sector = r1_bio->sector + mirror->rdev->data_offset;
		read_bio->bi_bdev = mirror->rdev->bdev;
		read_bio->bi_end_io = raid1_end_read_request;
		read_bio->bi_rw = READ | (do_sync << BIO_RW_SYNCIO);
		read_bio->bi_private = r1_bio;

		generic_make_request(read_bio);
		return 0;
	}

	disks = conf->raid_disks;
#if 0
	{ static int first=1;
	if (first) printk("First Write sector %llu disks %d\n",
			  (unsigned long long)r1_bio->sector, disks);
	first = 0;
	}
#endif
 retry_write:
	blocked_rdev = NULL;
	rcu_read_lock();
	for (i = 0;  i < disks; i++) {
		mdk_rdev_t *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev && unlikely(test_bit(Blocked, &rdev->flags))) {
			atomic_inc(&rdev->nr_pending);
			blocked_rdev = rdev;
			break;
		}
		if (rdev && !test_bit(Faulty, &rdev->flags)) {
			atomic_inc(&rdev->nr_pending);
			if (test_bit(Faulty, &rdev->flags)) {
				rdev_dec_pending(rdev, mddev);
				r1_bio->bios[i] = NULL;
			} else
				r1_bio->bios[i] = bio;
			targets++;
		} else
			r1_bio->bios[i] = NULL;
	}
	rcu_read_unlock();

	if (unlikely(blocked_rdev)) {
		 
		int j;

		for (j = 0; j < i; j++)
			if (r1_bio->bios[j])
				rdev_dec_pending(conf->mirrors[j].rdev, mddev);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
		raid1_allow_barrier(conf);
#else
		allow_barrier(conf);
#endif
		md_wait_for_blocked_rdev(blocked_rdev, mddev);
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
		raid1_wait_barrier(conf);
#else
		wait_barrier(conf);
#endif
		goto retry_write;
	}

#ifdef MY_ABC_HERE
	 
	if (targets == 0) {
		bio_endio(bio, 0);
		free_r1bio(r1_bio);
		return 0;
	}
#else
	BUG_ON(targets == 0);  
#endif

	if (targets < conf->raid_disks) {
		 
		set_bit(R1BIO_Degraded, &r1_bio->state);
	}

	if (bitmap &&
	    atomic_read(&bitmap->behind_writes) < bitmap->max_write_behind &&
	    (behind_pages = alloc_behind_pages(bio)) != NULL)
		set_bit(R1BIO_BehindIO, &r1_bio->state);

	atomic_set(&r1_bio->remaining, 0);
	atomic_set(&r1_bio->behind_remaining, 0);

	do_barriers = bio_rw_flagged(bio, BIO_RW_BARRIER);
	if (do_barriers)
		set_bit(R1BIO_Barrier, &r1_bio->state);

	bio_list_init(&bl);
	for (i = 0; i < disks; i++) {
		struct bio *mbio;
		if (!r1_bio->bios[i])
			continue;

		mbio = bio_clone(bio, GFP_NOIO);
		r1_bio->bios[i] = mbio;

		mbio->bi_sector	= r1_bio->sector + conf->mirrors[i].rdev->data_offset;
		mbio->bi_bdev = conf->mirrors[i].rdev->bdev;
		mbio->bi_end_io	= raid1_end_write_request;
		mbio->bi_rw = WRITE | (do_barriers << BIO_RW_BARRIER) |
			(do_sync << BIO_RW_SYNCIO);
		mbio->bi_private = r1_bio;

		if (behind_pages) {
			struct bio_vec *bvec;
			int j;

			__bio_for_each_segment(bvec, mbio, j, 0)
				bvec->bv_page = behind_pages[j];
			if (test_bit(WriteMostly, &conf->mirrors[i].rdev->flags))
				atomic_inc(&r1_bio->behind_remaining);
		}

		atomic_inc(&r1_bio->remaining);

		bio_list_add(&bl, mbio);
	}
	kfree(behind_pages);  

	bitmap_startwrite(bitmap, bio->bi_sector, r1_bio->sectors,
				test_bit(R1BIO_BehindIO, &r1_bio->state));
	spin_lock_irqsave(&conf->device_lock, flags);
	bio_list_merge(&conf->pending_bio_list, &bl);
	bio_list_init(&bl);

	blk_plug_device(mddev->queue);
	spin_unlock_irqrestore(&conf->device_lock, flags);

	wake_up(&conf->wait_barrier);

	if (do_sync)
		md_wakeup_thread(mddev->thread);
#if 0
	while ((bio = bio_list_pop(&bl)) != NULL)
		generic_make_request(bio);
#endif

	return 0;
}

static void status(struct seq_file *seq, mddev_t *mddev)
{
	conf_t *conf = mddev->private;
	int i;

	seq_printf(seq, " [%d/%d] [", conf->raid_disks,
		   conf->raid_disks - mddev->degraded);
	rcu_read_lock();
	for (i = 0; i < conf->raid_disks; i++) {
		mdk_rdev_t *rdev = rcu_dereference(conf->mirrors[i].rdev);
#ifdef MY_ABC_HERE
		seq_printf(seq, "%s",
				   rdev && test_bit(In_sync, &rdev->flags) ?
				   (test_bit(DiskError, &rdev->flags) ?  "E" : "U") : "_");
#else
		seq_printf(seq, "%s",
			   rdev && test_bit(In_sync, &rdev->flags) ? "U" : "_");
#endif
	}
	rcu_read_unlock();
	seq_printf(seq, "]");
}

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
void syno_error_common(mddev_t *mddev, mdk_rdev_t *rdev)
{
	char b[BDEVNAME_SIZE];
	conf_t *conf = mddev->private;

	if (test_and_clear_bit(In_sync, &rdev->flags)) {
		unsigned long flags;
		spin_lock_irqsave(&conf->device_lock, flags);
		mddev->degraded++;
#ifdef MY_ABC_HERE
		if (mddev->degraded >= conf->raid_disks) {
			if (MD_NOT_CRASHED == mddev->nodev_and_crashed) {
				mddev->nodev_and_crashed = MD_CRASHED;
			}
		}
#ifdef MY_ABC_HERE
		clear_bit(DiskError, &rdev->flags);
#endif  
#endif
		set_bit(Faulty, &rdev->flags);
		spin_unlock_irqrestore(&conf->device_lock, flags);
		 
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	} else
		set_bit(Faulty, &rdev->flags);
	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	printk(KERN_ALERT "raid1: Disk failure on %s, disabling device. \n"
		"	Operation continuing on %d devices\n",
		bdevname(rdev->bdev,b), conf->raid_disks - mddev->degraded);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	if (mddev->hw_raid) {
	    hwraid1_error(mddev, rdev);
	}
#endif
}

void syno_error_for_hotplug(mddev_t *mddev, mdk_rdev_t *rdev)
{
	char b1[BDEVNAME_SIZE], b2[BDEVNAME_SIZE];
	conf_t *conf = mddev->private;
	mdk_rdev_t *rdev_tmp;

	if (test_bit(In_sync, &rdev->flags)
	    && (conf->raid_disks - mddev->degraded) == 1){
		list_for_each_entry(rdev_tmp, &mddev->disks, same_set) {
			if(!test_bit(Faulty, &rdev_tmp->flags) &&
			   !test_bit(In_sync, &rdev_tmp->flags) &&
			   0 != strcmp(bdevname(rdev_tmp->bdev, b1), bdevname(rdev->bdev, b2))) {
				printk("[%s] %d: %s is being to unplug, but %s is sync now, disable both\n",
					   __FILE__, __LINE__, bdevname(rdev->bdev, b2), bdevname(rdev_tmp->bdev, b1));
				SYNORaidRdevUnplug(mddev, rdev_tmp);
			}
		}
	}

	syno_error_common(mddev, rdev);
}

static
void syno_error_for_internal(mddev_t *mddev, mdk_rdev_t *rdev)
{
	conf_t *conf = mddev->private;
	unsigned char recovery_err = 0;
	mdk_rdev_t *rdev_tmp;
	char b1[BDEVNAME_SIZE];
	char b2[BDEVNAME_SIZE];

	if (test_bit(In_sync, &rdev->flags)
	    && (conf->raid_disks - mddev->degraded) == 1){
#ifdef MY_ABC_HERE
			 
			if (!test_bit(DiskError, &rdev->flags)) {
				set_bit(DiskError, &rdev->flags);
				set_bit(MD_CHANGE_DEVS, &mddev->flags);
			}
#endif  
			 
			list_for_each_entry(rdev_tmp, &mddev->disks, same_set) {
				if (!test_bit(Faulty, &rdev_tmp->flags) && !test_bit(In_sync, &rdev_tmp->flags)) {
					printk("[%s] %d: %s has read/write error, but there only has this device, so remove %s from raid\n",
					   __FILE__, __LINE__, bdevname(rdev->bdev, b1), bdevname(rdev_tmp->bdev, b2));
					SYNORaidRdevUnplug(mddev, rdev_tmp);
					recovery_err = 1;
				}
			}

			if(recovery_err) {
				set_bit(MD_RECOVERY_INTR, &mddev->recovery);
			}

			mddev->recovery_disabled = 1;

			return;
	}

	syno_error_common(mddev, rdev);
}

#else  

static void error(mddev_t *mddev, mdk_rdev_t *rdev)
{
	char b[BDEVNAME_SIZE];
	conf_t *conf = mddev->private;

#ifndef MY_ABC_HERE
	 
	if (test_bit(In_sync, &rdev->flags)
	    && (conf->raid_disks - mddev->degraded) == 1) {
		 
		mddev->recovery_disabled = 1;
		return;
	}
#endif
	if (test_and_clear_bit(In_sync, &rdev->flags)) {
		unsigned long flags;
		spin_lock_irqsave(&conf->device_lock, flags);
		mddev->degraded++;
		set_bit(Faulty, &rdev->flags);
		spin_unlock_irqrestore(&conf->device_lock, flags);
		 
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
	} else
		set_bit(Faulty, &rdev->flags);
	set_bit(MD_CHANGE_DEVS, &mddev->flags);
	printk(KERN_ALERT "raid1: Disk failure on %s, disabling device.\n"
		"raid1: Operation continuing on %d devices.\n",
		bdevname(rdev->bdev,b), conf->raid_disks - mddev->degraded);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	if (mddev->hw_raid) {
	    hwraid1_error(mddev, rdev);
	}
#endif
}
#endif  

static void print_conf(conf_t *conf)
{
	int i;

	printk("RAID1 conf printout:\n");
	if (!conf) {
		printk("(!conf)\n");
		return;
	}
	printk(" --- wd:%d rd:%d\n", conf->raid_disks - conf->mddev->degraded,
		conf->raid_disks);

	rcu_read_lock();
	for (i = 0; i < conf->raid_disks; i++) {
		char b[BDEVNAME_SIZE];
		mdk_rdev_t *rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev)
			printk(" disk %d, wo:%d, o:%d, dev:%s\n",
			       i, !test_bit(In_sync, &rdev->flags),
			       !test_bit(Faulty, &rdev->flags),
			       bdevname(rdev->bdev,b));
	}
	rcu_read_unlock();
}

static void close_sync(conf_t *conf)
{
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_wait_barrier(conf);
	raid1_allow_barrier(conf);
#else
	wait_barrier(conf);
	allow_barrier(conf);
#endif

	mempool_destroy(conf->r1buf_pool);
	conf->r1buf_pool = NULL;
}

static int raid1_spare_active(mddev_t *mddev)
{
	int i;
	conf_t *conf = mddev->private;

#ifdef MY_ABC_HERE
	if (IsDiskErrorSet(mddev)) {
		return 0;
	}
#endif

	for (i = 0; i < conf->raid_disks; i++) {
		mdk_rdev_t *rdev = conf->mirrors[i].rdev;
		if (rdev
		    && !test_bit(Faulty, &rdev->flags)
		    && !test_and_set_bit(In_sync, &rdev->flags)) {
			unsigned long flags;
			spin_lock_irqsave(&conf->device_lock, flags);
			mddev->degraded--;
			spin_unlock_irqrestore(&conf->device_lock, flags);
		}
	}

	print_conf(conf);
	return 0;
}

static int raid1_add_disk(mddev_t *mddev, mdk_rdev_t *rdev)
{
	conf_t *conf = mddev->private;
	int err = -EEXIST;
	int mirror = 0;
	mirror_info_t *p;
	int first = 0;
	int last = mddev->raid_disks - 1;

#ifdef MY_ABC_HERE
	if (IsDiskErrorSet(mddev)) {
		return -EINVAL;
	}
#endif

	if (rdev->raid_disk >= 0)
		first = last = rdev->raid_disk;

	for (mirror = first; mirror <= last; mirror++)
		if ( !(p=conf->mirrors+mirror)->rdev) {

			disk_stack_limits(mddev->gendisk, rdev->bdev,
					  rdev->data_offset << 9);
			 
			if (rdev->bdev->bd_disk->queue->merge_bvec_fn &&
			    queue_max_sectors(mddev->queue) > (PAGE_SIZE>>9))
				blk_queue_max_sectors(mddev->queue, PAGE_SIZE>>9);

			p->head_position = 0;
			rdev->raid_disk = mirror;
			err = 0;
			 
			if (rdev->saved_raid_disk < 0)
				conf->fullsync = 1;
			rcu_assign_pointer(p->rdev, rdev);
			break;
		}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	 
	if (!err && mddev->hw_raid) {
	    err = hwraid1_add_disk(mddev, rdev);
	}
#endif
	md_integrity_add_rdev(rdev, mddev);
	print_conf(conf);
	return err;
}

static int raid1_remove_disk(mddev_t *mddev, int number)
{
	conf_t *conf = mddev->private;
	int err = 0;
	mdk_rdev_t *rdev;
	mirror_info_t *p = conf->mirrors+ number;

	print_conf(conf);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	if (mddev->hw_raid && hwraid_stop_new_commands() ) {
	    printk(KERN_INFO"HW-RAID1: waiting for hwraid to go idle before removing disk\n");
        err = -EBUSY;
        goto abort;
	}
#endif

	rdev = p->rdev;
	if (rdev) {
		if (test_bit(In_sync, &rdev->flags) ||
		    atomic_read(&rdev->nr_pending)) {
			err = -EBUSY;
			goto abort;
		}
		 
		if (!test_bit(Faulty, &rdev->flags) &&
		    mddev->degraded < conf->raid_disks) {
			err = -EBUSY;
			goto abort;
		}
		p->rdev = NULL;
		synchronize_rcu();
		if (atomic_read(&rdev->nr_pending)) {
			 
			err = -EBUSY;
			p->rdev = rdev;
			goto abort;
		}
		md_integrity_register(mddev);
	}
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
    if (mddev->hw_raid) {
        err = hwraid1_remove_disk(mddev, number, rdev);
    }
#endif
abort:

	print_conf(conf);
	return err;
}

static void end_sync_read(struct bio *bio, int error)
{
	r1bio_t * r1_bio = (r1bio_t *)(bio->bi_private);
	int i;

#ifdef MY_ABC_HERE
	conf_t *conf = r1_bio->mddev->private;
	int mirror = r1_bio->read_disk;
	unsigned char uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
#endif
	for (i=r1_bio->mddev->raid_disks; i--; )
		if (r1_bio->bios[i] == bio)
			break;
	BUG_ON(i < 0);
	update_head_pos(i, r1_bio);

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
	if (bio_flagged(bio, BIO_AUTO_REMAP)) {
		printk("%s:%s(%d) BIO_AUTO_REMAP detected\n", __FILE__,__FUNCTION__,__LINE__);
		SynoAutoRemapReport(conf->mddev, r1_bio->sector, conf->mirrors[mirror].rdev->bdev);
	}
#endif

	if (uptodate) {
		set_bit(R1BIO_Uptodate, &r1_bio->state);
	}else{
		if (IsDeviceDisappear(conf->mirrors[mirror].rdev->bdev)) {
			syno_md_error(r1_bio->mddev, conf->mirrors[mirror].rdev);
		}else{
#ifdef MY_ABC_HERE
			 
			SynoReportBadSector(bio->bi_sector, READ, conf->mddev->md_minor,
								conf->mirrors[mirror].rdev->bdev, __FUNCTION__);
#endif
		}
	}
#else
	if (test_bit(BIO_UPTODATE, &bio->bi_flags))
		set_bit(R1BIO_Uptodate, &r1_bio->state);
#endif

	if (atomic_dec_and_test(&r1_bio->remaining))
		reschedule_retry(r1_bio);
}

static void end_sync_write(struct bio *bio, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	r1bio_t * r1_bio = (r1bio_t *)(bio->bi_private);
	mddev_t *mddev = r1_bio->mddev;
	conf_t *conf = mddev->private;
	int i;
	int mirror=0;

	for (i = 0; i < conf->raid_disks; i++)
		if (r1_bio->bios[i] == bio) {
			mirror = i;
			break;
		}
	if (!uptodate) {
		int sync_blocks = 0;
		sector_t s = r1_bio->sector;
		long sectors_to_go = r1_bio->sectors;
		 
		do {
			bitmap_end_sync(mddev->bitmap, s,
					&sync_blocks, 1);
			s += sync_blocks;
			sectors_to_go -= sync_blocks;
		} while (sectors_to_go > 0);
#ifdef MY_ABC_HERE
		if (IsDeviceDisappear(conf->mirrors[mirror].rdev->bdev)) {
			syno_md_error(mddev, conf->mirrors[mirror].rdev);
		}else{
#ifdef MY_ABC_HERE
			SynoReportBadSector(bio->bi_sector, WRITE,
								conf->mddev->md_minor, conf->mirrors[mirror].rdev->bdev, __FUNCTION__);
#endif
			md_error(mddev, conf->mirrors[mirror].rdev);
		}
#else
		md_error(mddev, conf->mirrors[mirror].rdev);
#endif
	}

	update_head_pos(mirror, r1_bio);

	if (atomic_dec_and_test(&r1_bio->remaining)) {
		sector_t s = r1_bio->sectors;
		put_buf(r1_bio);
		md_done_sync(mddev, s, uptodate);
	}
}

static void sync_request_write(mddev_t *mddev, r1bio_t *r1_bio)
{
	conf_t *conf = mddev->private;
	int i;
	int disks = conf->raid_disks;
	struct bio *bio, *wbio;

	bio = r1_bio->bios[r1_bio->read_disk];

	if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
		 
		int primary;
		if (!test_bit(R1BIO_Uptodate, &r1_bio->state)) {
			for (i=0; i<mddev->raid_disks; i++)
				if (r1_bio->bios[i]->bi_end_io == end_sync_read)
					md_error(mddev, conf->mirrors[i].rdev);

			md_done_sync(mddev, r1_bio->sectors, 1);
			put_buf(r1_bio);
			return;
		}
		for (primary=0; primary<mddev->raid_disks; primary++)
			if (r1_bio->bios[primary]->bi_end_io == end_sync_read &&
			    test_bit(BIO_UPTODATE, &r1_bio->bios[primary]->bi_flags)) {
				r1_bio->bios[primary]->bi_end_io = NULL;
				rdev_dec_pending(conf->mirrors[primary].rdev, mddev);
				break;
			}
		r1_bio->read_disk = primary;
		for (i=0; i<mddev->raid_disks; i++)
			if (r1_bio->bios[i]->bi_end_io == end_sync_read) {
				int j;
				int vcnt = r1_bio->sectors >> (PAGE_SHIFT- 9);
				struct bio *pbio = r1_bio->bios[primary];
				struct bio *sbio = r1_bio->bios[i];

				if (test_bit(BIO_UPTODATE, &sbio->bi_flags)) {
					for (j = vcnt; j-- ; ) {
						struct page *p, *s;
						p = pbio->bi_io_vec[j].bv_page;
						s = sbio->bi_io_vec[j].bv_page;
						if (memcmp(page_address(p),
							   page_address(s),
							   PAGE_SIZE))
							break;
					}
				} else
					j = 0;
				if (j >= 0)
					mddev->resync_mismatches += r1_bio->sectors;
				if (j < 0 || (test_bit(MD_RECOVERY_CHECK, &mddev->recovery)
					      && test_bit(BIO_UPTODATE, &sbio->bi_flags))) {
					sbio->bi_end_io = NULL;
					rdev_dec_pending(conf->mirrors[i].rdev, mddev);
				} else {
					 
					int size;
					sbio->bi_vcnt = vcnt;
					sbio->bi_size = r1_bio->sectors << 9;
					sbio->bi_idx = 0;
					sbio->bi_phys_segments = 0;
					sbio->bi_flags &= ~(BIO_POOL_MASK - 1);
					sbio->bi_flags |= 1 << BIO_UPTODATE;
					sbio->bi_next = NULL;
					sbio->bi_sector = r1_bio->sector +
						conf->mirrors[i].rdev->data_offset;
					sbio->bi_bdev = conf->mirrors[i].rdev->bdev;
					size = sbio->bi_size;
					for (j = 0; j < vcnt ; j++) {
						struct bio_vec *bi;
						bi = &sbio->bi_io_vec[j];
						bi->bv_offset = 0;
						if (size > PAGE_SIZE)
							bi->bv_len = PAGE_SIZE;
						else
							bi->bv_len = size;
						size -= PAGE_SIZE;
						memcpy(page_address(bi->bv_page),
						       page_address(pbio->bi_io_vec[j].bv_page),
						       PAGE_SIZE);
					}

				}
			}
	}
	if (!test_bit(R1BIO_Uptodate, &r1_bio->state)) {
		 
		sector_t sect = r1_bio->sector;
		int sectors = r1_bio->sectors;
		int idx = 0;

		while(sectors) {
			int s = sectors;
			int d = r1_bio->read_disk;
			int success = 0;
			mdk_rdev_t *rdev;

			if (s > (PAGE_SIZE>>9))
				s = PAGE_SIZE >> 9;
			do {
				if (r1_bio->bios[d]->bi_end_io == end_sync_read) {
					 
					rdev = conf->mirrors[d].rdev;
					if (sync_page_io(rdev->bdev,
							 sect + rdev->data_offset,
							 s<<9,
							 bio->bi_io_vec[idx].bv_page,
							 READ)) {
						success = 1;
						break;
					}
				}
				d++;
				if (d == conf->raid_disks)
					d = 0;
			} while (!success && d != r1_bio->read_disk);

			if (success) {
				int start = d;
				 
				set_bit(R1BIO_Uptodate, &r1_bio->state);
				while (d != r1_bio->read_disk) {
					if (d == 0)
						d = conf->raid_disks;
					d--;
					if (r1_bio->bios[d]->bi_end_io != end_sync_read)
						continue;
					rdev = conf->mirrors[d].rdev;
					atomic_add(s, &rdev->corrected_errors);
					if (sync_page_io(rdev->bdev,
							 sect + rdev->data_offset,
							 s<<9,
							 bio->bi_io_vec[idx].bv_page,
							 WRITE) == 0)
						md_error(mddev, rdev);
				}
				d = start;
				while (d != r1_bio->read_disk) {
					if (d == 0)
						d = conf->raid_disks;
					d--;
					if (r1_bio->bios[d]->bi_end_io != end_sync_read)
						continue;
					rdev = conf->mirrors[d].rdev;
					if (sync_page_io(rdev->bdev,
							 sect + rdev->data_offset,
							 s<<9,
							 bio->bi_io_vec[idx].bv_page,
							 READ) == 0)
						md_error(mddev, rdev);
				}
			} else {
				char b[BDEVNAME_SIZE];
				 
				md_error(mddev, conf->mirrors[r1_bio->read_disk].rdev);
#ifdef MY_ABC_HERE
				if (!IsDiskErrorSet(mddev)) {
					printk(KERN_ALERT "raid1: %s: unrecoverable I/O read error"
					       " for block %llu\n",
					       bdevname(bio->bi_bdev,b),
					       (unsigned long long)r1_bio->sector);
				}
#else
				printk(KERN_ALERT "raid1: %s: unrecoverable I/O read error"
				       " for block %llu\n",
				       bdevname(bio->bi_bdev,b),
				       (unsigned long long)r1_bio->sector);
#endif
				md_done_sync(mddev, r1_bio->sectors, 0);
				put_buf(r1_bio);
				return;
			}
			sectors -= s;
			sect += s;
			idx ++;
		}
	}

	atomic_set(&r1_bio->remaining, 1);
	for (i = 0; i < disks ; i++) {
		wbio = r1_bio->bios[i];
		if (wbio->bi_end_io == NULL ||
		    (wbio->bi_end_io == end_sync_read &&
		     (i == r1_bio->read_disk ||
		      !test_bit(MD_RECOVERY_SYNC, &mddev->recovery))))
			continue;

		wbio->bi_rw = WRITE;
		wbio->bi_end_io = end_sync_write;
		atomic_inc(&r1_bio->remaining);
		md_sync_acct(conf->mirrors[i].rdev->bdev, wbio->bi_size >> 9);

		generic_make_request(wbio);
	}

	if (atomic_dec_and_test(&r1_bio->remaining)) {
		 
		md_done_sync(mddev, r1_bio->sectors, 1);
		put_buf(r1_bio);
	}
}

static void fix_read_error(conf_t *conf, int read_disk,
			   sector_t sect, int sectors)
{
	mddev_t *mddev = conf->mddev;
	while(sectors) {
		int s = sectors;
		int d = read_disk;
		int success = 0;
		int start;
		mdk_rdev_t *rdev;

		if (s > (PAGE_SIZE>>9))
			s = PAGE_SIZE >> 9;

		do {
			 
			rdev = conf->mirrors[d].rdev;
			if (rdev &&
			    test_bit(In_sync, &rdev->flags) &&
			    sync_page_io(rdev->bdev,
					 sect + rdev->data_offset,
					 s<<9,
					 conf->tmppage, READ))
				success = 1;
			else {
				d++;
				if (d == conf->raid_disks)
					d = 0;
			}
		} while (!success && d != read_disk);

		if (!success) {
			 
			md_error(mddev, conf->mirrors[read_disk].rdev);
			break;
		}
		 
		start = d;
		while (d != read_disk) {
			if (d==0)
				d = conf->raid_disks;
			d--;
			rdev = conf->mirrors[d].rdev;
			if (rdev &&
			    test_bit(In_sync, &rdev->flags)) {
				if (sync_page_io(rdev->bdev,
						 sect + rdev->data_offset,
						 s<<9, conf->tmppage, WRITE)
				    == 0)
					 
					md_error(mddev, rdev);
			}
		}
		d = start;
		while (d != read_disk) {
			char b[BDEVNAME_SIZE];
			if (d==0)
				d = conf->raid_disks;
			d--;
			rdev = conf->mirrors[d].rdev;
			if (rdev &&
			    test_bit(In_sync, &rdev->flags)) {
				if (sync_page_io(rdev->bdev,
						 sect + rdev->data_offset,
						 s<<9, conf->tmppage, READ)
				    == 0)
					 
					md_error(mddev, rdev);
				else {
					atomic_add(s, &rdev->corrected_errors);
					printk(KERN_INFO
					       "raid1:%s: read error corrected "
					       "(%d sectors at %llu on %s)\n",
					       mdname(mddev), s,
					       (unsigned long long)(sect +
					           rdev->data_offset),
					       bdevname(rdev->bdev, b));
#ifdef MY_ABC_HERE
					SynoReportCorrectBadSector(sect + rdev->data_offset, mddev->md_minor, rdev->bdev, __FUNCTION__);
#endif  
				}
			}
		}
		sectors -= s;
		sect += s;
	}
}

static void raid1d(mddev_t *mddev)
{
	r1bio_t *r1_bio;
	struct bio *bio;
	unsigned long flags;
	conf_t *conf = mddev->private;
	struct list_head *head = &conf->retry_list;
	int unplug=0;
	mdk_rdev_t *rdev;

	md_check_recovery(mddev);

	for (;;) {
		char b[BDEVNAME_SIZE];

		unplug += flush_pending_writes(conf);

		spin_lock_irqsave(&conf->device_lock, flags);
		if (list_empty(head)) {
			spin_unlock_irqrestore(&conf->device_lock, flags);
			break;
		}
		r1_bio = list_entry(head->prev, r1bio_t, retry_list);
		list_del(head->prev);
		conf->nr_queued--;
		spin_unlock_irqrestore(&conf->device_lock, flags);

		mddev = r1_bio->mddev;
		conf = mddev->private;
		if (test_bit(R1BIO_IsSync, &r1_bio->state)) {
			sync_request_write(mddev, r1_bio);
			unplug = 1;
		} else if (test_bit(R1BIO_BarrierRetry, &r1_bio->state)) {
			 
			int i;
			const bool do_sync = bio_rw_flagged(r1_bio->master_bio, BIO_RW_SYNCIO);
			clear_bit(R1BIO_BarrierRetry, &r1_bio->state);
			clear_bit(R1BIO_Barrier, &r1_bio->state);
			for (i=0; i < conf->raid_disks; i++)
				if (r1_bio->bios[i])
					atomic_inc(&r1_bio->remaining);
			for (i=0; i < conf->raid_disks; i++)
				if (r1_bio->bios[i]) {
					struct bio_vec *bvec;
					int j;

					bio = bio_clone(r1_bio->master_bio, GFP_NOIO);
					 
					__bio_for_each_segment(bvec, bio, j, 0)
						bvec->bv_page = bio_iovec_idx(r1_bio->bios[i], j)->bv_page;
					bio_put(r1_bio->bios[i]);
					bio->bi_sector = r1_bio->sector +
						conf->mirrors[i].rdev->data_offset;
					bio->bi_bdev = conf->mirrors[i].rdev->bdev;
					bio->bi_end_io = raid1_end_write_request;
					bio->bi_rw = WRITE |
						(do_sync << BIO_RW_SYNCIO);
					bio->bi_private = r1_bio;
					r1_bio->bios[i] = bio;
					generic_make_request(bio);
				}
		} else {
			int disk;

			if (mddev->ro == 0) {
				freeze_array(conf);
				fix_read_error(conf, r1_bio->read_disk,
					       r1_bio->sector,
					       r1_bio->sectors);
				unfreeze_array(conf);
			} else
				md_error(mddev,
					 conf->mirrors[r1_bio->read_disk].rdev);
			rdev_dec_pending(conf->mirrors[r1_bio->read_disk].rdev, conf->mddev);

			bio = r1_bio->bios[r1_bio->read_disk];
			if ((disk=read_balance(conf, r1_bio)) == -1) {
#ifdef MY_ABC_HERE
				if (mddev->nodev_and_crashed) {
					 
					printk(KERN_ALERT "raid1: no bdev: unrecoverable I/O"
						   " read error for block %llu\n",
						   (unsigned long long)r1_bio->sector);
				}else
#endif
#ifdef MY_ABC_HERE
				printk(KERN_ALERT "raid1: unrecoverable I/O"
				       " read error for block %llu\n",
				       (unsigned long long)r1_bio->sector);
				raid_end_bio_io(r1_bio);
#else
				printk(KERN_ALERT "raid1: %s: unrecoverable I/O"
				       " read error for block %llu\n",
				       bdevname(bio->bi_bdev,b),
				       (unsigned long long)r1_bio->sector);
				raid_end_bio_io(r1_bio);
#endif
			} else {
				const bool do_sync = bio_rw_flagged(r1_bio->master_bio, BIO_RW_SYNCIO);
				r1_bio->bios[r1_bio->read_disk] =
					mddev->ro ? IO_BLOCKED : NULL;
				r1_bio->read_disk = disk;
				bio_put(bio);
				bio = bio_clone(r1_bio->master_bio, GFP_NOIO);
				r1_bio->bios[r1_bio->read_disk] = bio;
				rdev = conf->mirrors[disk].rdev;
				if (printk_ratelimit())
					printk(KERN_ERR "raid1: %s: redirecting sector %llu to"
					       " another mirror\n",
					       bdevname(rdev->bdev,b),
					       (unsigned long long)r1_bio->sector);
				bio->bi_sector = r1_bio->sector + rdev->data_offset;
				bio->bi_bdev = rdev->bdev;
				bio->bi_end_io = raid1_end_read_request;
				bio->bi_rw = READ | (do_sync << BIO_RW_SYNCIO);
				bio->bi_private = r1_bio;
				unplug = 1;
				generic_make_request(bio);
			}
		}
		cond_resched();
	}
	if (unplug)
		unplug_slaves(mddev);
}

static int init_resync(conf_t *conf)
{
	int buffs;

	buffs = RESYNC_WINDOW / RESYNC_BLOCK_SIZE;
	BUG_ON(conf->r1buf_pool);
	conf->r1buf_pool = mempool_create(buffs, r1buf_pool_alloc, r1buf_pool_free,
					  conf->poolinfo);
	if (!conf->r1buf_pool)
		return -ENOMEM;
	conf->next_resync = 0;
	return 0;
}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
static sector_t _sync_request(mddev_t *mddev, sector_t sector_nr, int *skipped, int go_faster)
#else
static sector_t sync_request(mddev_t *mddev, sector_t sector_nr, int *skipped, int go_faster)
#endif
{
	conf_t *conf = mddev->private;
	r1bio_t *r1_bio;
	struct bio *bio;
	sector_t max_sector, nr_sectors;
	int disk = -1;
	int i;
	int wonly = -1;
	int write_targets = 0, read_targets = 0;
	int sync_blocks;
	int still_degraded = 0;

	if (!conf->r1buf_pool)
	{
 
		if (init_resync(conf))
			return 0;
	}

#ifdef MY_ABC_HERE
	 
	if (mddev->degraded == mddev->raid_disks) {
		*skipped = 1;
		set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		 
		mddev->recovery_cp = MaxSector;
	}else{
		 
		if (IsDiskErrorSet(mddev)) {
			*skipped = 1;
			set_bit(MD_RECOVERY_INTR, &mddev->recovery);
		}
	}
#endif

	max_sector = mddev->dev_sectors;
#ifdef MY_ABC_HERE
	if (sector_nr >= max_sector || *skipped == 1) {
#else
	if (sector_nr >= max_sector) {
#endif
		 
		if (mddev->curr_resync < max_sector)  
			bitmap_end_sync(mddev->bitmap, mddev->curr_resync,
						&sync_blocks, 1);
		else  
			conf->fullsync = 0;

		bitmap_close_sync(mddev->bitmap);
		close_sync(conf);
		return 0;
	}

	if (mddev->bitmap == NULL &&
	    mddev->recovery_cp == MaxSector &&
	    !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery) &&
	    conf->fullsync == 0) {
		*skipped = 1;
		return max_sector - sector_nr;
	}
	 
	if (!bitmap_start_sync(mddev->bitmap, sector_nr, &sync_blocks, 1) &&
	    !conf->fullsync && !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
		 
		*skipped = 1;
		return sync_blocks;
	}
	 
	if (!go_faster && conf->nr_waiting)
		msleep_interruptible(1000);

	bitmap_cond_end_sync(mddev->bitmap, sector_nr);
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_raise_barrier(conf);
#else
	raise_barrier(conf);
#endif

	conf->next_resync = sector_nr;

	r1_bio = mempool_alloc(conf->r1buf_pool, GFP_NOIO);
	rcu_read_lock();
	 
	r1_bio->mddev = mddev;
	r1_bio->sector = sector_nr;
	r1_bio->state = 0;
	set_bit(R1BIO_IsSync, &r1_bio->state);

	for (i=0; i < conf->raid_disks; i++) {
		mdk_rdev_t *rdev;
		bio = r1_bio->bios[i];

		bio->bi_next = NULL;
		bio->bi_flags |= 1 << BIO_UPTODATE;
		bio->bi_rw = READ;
		bio->bi_vcnt = 0;
		bio->bi_idx = 0;
		bio->bi_phys_segments = 0;
		bio->bi_size = 0;
		bio->bi_end_io = NULL;
		bio->bi_private = NULL;

		rdev = rcu_dereference(conf->mirrors[i].rdev);
		if (rdev == NULL ||
			   test_bit(Faulty, &rdev->flags)) {
			still_degraded = 1;
			continue;
		} else if (!test_bit(In_sync, &rdev->flags)) {
			bio->bi_rw = WRITE;
			bio->bi_end_io = end_sync_write;
			write_targets ++;
		} else {
			 
			bio->bi_rw = READ;
			bio->bi_end_io = end_sync_read;
			if (test_bit(WriteMostly, &rdev->flags)) {
				if (wonly < 0)
					wonly = i;
			} else {
				if (disk < 0)
					disk = i;
			}
			read_targets++;
		}
		atomic_inc(&rdev->nr_pending);
		bio->bi_sector = sector_nr + rdev->data_offset;
		bio->bi_bdev = rdev->bdev;
		bio->bi_private = r1_bio;
	}
	rcu_read_unlock();
	if (disk < 0)
		disk = wonly;
	r1_bio->read_disk = disk;

	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery) && read_targets > 0)
		 
		write_targets += read_targets-1;

	if (write_targets == 0 || read_targets == 0) {
		 
		sector_t rv = max_sector - sector_nr;
		*skipped = 1;
		put_buf(r1_bio);
		return rv;
	}

	if (max_sector > mddev->resync_max)
		max_sector = mddev->resync_max;  
	nr_sectors = 0;
	sync_blocks = 0;
	do {
		struct page *page;
		int len = PAGE_SIZE;
		if (sector_nr + (len>>9) > max_sector)
			len = (max_sector - sector_nr) << 9;
		if (len == 0)
			break;
		if (sync_blocks == 0) {
			if (!bitmap_start_sync(mddev->bitmap, sector_nr,
					       &sync_blocks, still_degraded) &&
			    !conf->fullsync &&
			    !test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery))
				break;
			BUG_ON(sync_blocks < (PAGE_SIZE>>9));
			if (len > (sync_blocks<<9))
				len = sync_blocks<<9;
		}

		for (i=0 ; i < conf->raid_disks; i++) {
			bio = r1_bio->bios[i];
			if (bio->bi_end_io) {
				page = bio->bi_io_vec[bio->bi_vcnt].bv_page;
				if (bio_add_page(bio, page, len, 0) == 0) {
					 
					bio->bi_io_vec[bio->bi_vcnt].bv_page = page;
					while (i > 0) {
						i--;
						bio = r1_bio->bios[i];
						if (bio->bi_end_io==NULL)
							continue;
						 
						bio->bi_vcnt--;
						bio->bi_size -= len;
						bio->bi_flags &= ~(1<< BIO_SEG_VALID);
					}
					goto bio_full;
				}
			}
		}
		nr_sectors += len>>9;
		sector_nr += len>>9;
		sync_blocks -= (len>>9);
	} while (r1_bio->bios[disk]->bi_vcnt < RESYNC_PAGES);
 bio_full:
	r1_bio->sectors = nr_sectors;

	if (test_bit(MD_RECOVERY_REQUESTED, &mddev->recovery)) {
		atomic_set(&r1_bio->remaining, read_targets);
		for (i=0; i<conf->raid_disks; i++) {
			bio = r1_bio->bios[i];
			if (bio->bi_end_io == end_sync_read) {
				md_sync_acct(bio->bi_bdev, nr_sectors);
				generic_make_request(bio);
			}
		}
	} else {
		atomic_set(&r1_bio->remaining, 1);
		bio = r1_bio->bios[r1_bio->read_disk];
		md_sync_acct(bio->bi_bdev, nr_sectors);
		generic_make_request(bio);

	}
	return nr_sectors;
}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
static sector_t
sync_request(mddev_t *mddev, sector_t sector_nr, int *skipped, int go_faster)
{
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
    if (mddev->hw_raid) {
        return hwraid1_sync_request(mddev, sector_nr, skipped, go_faster);
    }
#endif
    return _sync_request(mddev, sector_nr, skipped, go_faster);
}
#endif

static sector_t raid1_size(mddev_t *mddev, sector_t sectors, int raid_disks)
{
	if (sectors)
		return sectors;

	return mddev->dev_sectors;
}

static int run(mddev_t *mddev)
{
	conf_t *conf;
	int i, j, disk_idx;
	mirror_info_t *disk;
	mdk_rdev_t *rdev;

	if (mddev->level != 1) {
		printk("raid1: %s: raid level not set to mirroring (%d)\n",
		       mdname(mddev), mddev->level);
		goto out;
	}
	if (mddev->reshape_position != MaxSector) {
		printk("raid1: %s: reshape_position set but not supported\n",
		       mdname(mddev));
		goto out;
	}
	 
	conf = kzalloc(sizeof(conf_t), GFP_KERNEL);
	mddev->private = conf;
	if (!conf)
		goto out_no_mem;

	conf->mirrors = kzalloc(sizeof(struct mirror_info)*mddev->raid_disks,
				 GFP_KERNEL);
	if (!conf->mirrors)
		goto out_no_mem;

	conf->tmppage = alloc_page(GFP_KERNEL);
	if (!conf->tmppage)
		goto out_no_mem;

	conf->poolinfo = kmalloc(sizeof(*conf->poolinfo), GFP_KERNEL);
	if (!conf->poolinfo)
		goto out_no_mem;
	conf->poolinfo->mddev = NULL;
	conf->poolinfo->raid_disks = mddev->raid_disks;
	conf->r1bio_pool = mempool_create(NR_RAID1_BIOS, r1bio_pool_alloc,
					  r1bio_pool_free,
					  conf->poolinfo);
	if (!conf->r1bio_pool)
		goto out_no_mem;
	conf->poolinfo->mddev = mddev;

	spin_lock_init(&conf->device_lock);
	mddev->queue->queue_lock = &conf->device_lock;

	list_for_each_entry(rdev, &mddev->disks, same_set) {
		disk_idx = rdev->raid_disk;
		if (disk_idx >= mddev->raid_disks
		    || disk_idx < 0)
			continue;
		disk = conf->mirrors + disk_idx;

		disk->rdev = rdev;
		disk_stack_limits(mddev->gendisk, rdev->bdev,
				  rdev->data_offset << 9);
		 
		if (rdev->bdev->bd_disk->queue->merge_bvec_fn &&
		    queue_max_sectors(mddev->queue) > (PAGE_SIZE>>9))
			blk_queue_max_sectors(mddev->queue, PAGE_SIZE>>9);

		disk->head_position = 0;
	}
	conf->raid_disks = mddev->raid_disks;
	conf->mddev = mddev;
	INIT_LIST_HEAD(&conf->retry_list);

	spin_lock_init(&conf->resync_lock);
	init_waitqueue_head(&conf->wait_barrier);

	bio_list_init(&conf->pending_bio_list);
	bio_list_init(&conf->flushing_bio_list);

	mddev->degraded = 0;
	for (i = 0; i < conf->raid_disks; i++) {

		disk = conf->mirrors + i;

		if (!disk->rdev ||
		    !test_bit(In_sync, &disk->rdev->flags)) {
			disk->head_position = 0;
			mddev->degraded++;
			if (disk->rdev)
				conf->fullsync = 1;
		}
	}
	if (mddev->degraded == conf->raid_disks) {
		printk(KERN_ERR "raid1: no operational mirrors for %s\n",
			mdname(mddev));
		goto out_free_conf;
	}
	if (conf->raid_disks - mddev->degraded == 1)
		mddev->recovery_cp = MaxSector;

	for (j = 0; j < conf->raid_disks &&
		     (!conf->mirrors[j].rdev ||
		      !test_bit(In_sync, &conf->mirrors[j].rdev->flags)) ; j++)
		 ;
	conf->last_used = j;

	mddev->thread = md_register_thread(raid1d, mddev, NULL);
	if (!mddev->thread) {
		printk(KERN_ERR
		       "raid1: couldn't allocate thread for %s\n",
		       mdname(mddev));
		goto out_free_conf;
	}

	if (mddev->recovery_cp != MaxSector)
		printk(KERN_NOTICE "raid1: %s is not clean"
		       " -- starting background reconstruction\n",
		       mdname(mddev));
	printk(KERN_INFO
		"raid1: raid set %s active with %d out of %d mirrors\n",
		mdname(mddev), mddev->raid_disks - mddev->degraded,
		mddev->raid_disks);
	 
	md_set_array_sectors(mddev, raid1_size(mddev, 0, 0));

	mddev->queue->unplug_fn = raid1_unplug;
	mddev->queue->backing_dev_info.congested_fn = raid1_congested;
	mddev->queue->backing_dev_info.congested_data = mddev;
	md_integrity_register(mddev);

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	 
	if (hwraid1_run(mddev, conf) < 0 ) {
	    printk(KERN_ERR"Unable to use HW RAID accelleration.");
	}
#endif
	return 0;

out_no_mem:
	printk(KERN_ERR "raid1: couldn't allocate memory for %s\n",
	       mdname(mddev));

out_free_conf:
	if (conf) {
		if (conf->r1bio_pool)
			mempool_destroy(conf->r1bio_pool);
		kfree(conf->mirrors);
		safe_put_page(conf->tmppage);
		kfree(conf->poolinfo);
		kfree(conf);
		mddev->private = NULL;
	}
out:
	return -EIO;
}

static int stop(mddev_t *mddev)
{
	conf_t *conf = mddev->private;
	struct bitmap *bitmap = mddev->bitmap;
	int behind_wait = 0;

	while (bitmap && atomic_read(&bitmap->behind_writes) > 0) {
		behind_wait++;
		printk(KERN_INFO "raid1: behind writes in progress on device %s, waiting to stop (%d)\n", mdname(mddev), behind_wait);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ);  
		 
	}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_raise_barrier(conf);
	raid1_lower_barrier(conf);
#else
	raise_barrier(conf);
	lower_barrier(conf);
#endif

	md_unregister_thread(mddev->thread);
	mddev->thread = NULL;

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	if (mddev->hw_raid) {
	    hwraid1_stop(mddev);
	} else
#endif
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	{
#endif
	blk_sync_queue(mddev->queue);  
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	}
#endif
	if (conf->r1bio_pool)
		mempool_destroy(conf->r1bio_pool);
	kfree(conf->mirrors);
	kfree(conf->poolinfo);
	kfree(conf);
	mddev->private = NULL;
	return 0;
}

static int raid1_resize(mddev_t *mddev, sector_t sectors)
{
	 
#ifdef MY_ABC_HERE
	if (IsDiskErrorSet(mddev)) {
		return -EINVAL;
	}
#endif

	md_set_array_sectors(mddev, raid1_size(mddev, sectors, 0));
	if (mddev->array_sectors > raid1_size(mddev, sectors, 0))
		return -EINVAL;
	set_capacity(mddev->gendisk, mddev->array_sectors);
	mddev->changed = 1;
	revalidate_disk(mddev->gendisk);
	if (sectors > mddev->dev_sectors &&
	    mddev->recovery_cp == MaxSector) {
		mddev->recovery_cp = mddev->dev_sectors;
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	}
	mddev->dev_sectors = sectors;
	mddev->resync_max_sectors = sectors;
	return 0;
}

static int raid1_reshape(mddev_t *mddev)
{
	 
	mempool_t *newpool, *oldpool;
	struct pool_info *newpoolinfo;
	mirror_info_t *newmirrors;
	conf_t *conf = mddev->private;
	int cnt, raid_disks;
	unsigned long flags;
	int d, d2, err;

	if (mddev->chunk_sectors != mddev->new_chunk_sectors ||
	    mddev->layout != mddev->new_layout ||
	    mddev->level != mddev->new_level) {
		mddev->new_chunk_sectors = mddev->chunk_sectors;
		mddev->new_layout = mddev->layout;
		mddev->new_level = mddev->level;
		return -EINVAL;
	}

#ifdef MY_ABC_HERE
	if (IsDiskErrorSet(mddev)) {
		return -EINVAL;
	}
#endif

	err = md_allow_write(mddev);
	if (err)
		return err;

	raid_disks = mddev->raid_disks + mddev->delta_disks;

	if (raid_disks < conf->raid_disks) {
		cnt=0;
		for (d= 0; d < conf->raid_disks; d++)
			if (conf->mirrors[d].rdev)
				cnt++;
		if (cnt > raid_disks)
			return -EBUSY;
	}

	newpoolinfo = kmalloc(sizeof(*newpoolinfo), GFP_KERNEL);
	if (!newpoolinfo)
		return -ENOMEM;
	newpoolinfo->mddev = mddev;
	newpoolinfo->raid_disks = raid_disks;

	newpool = mempool_create(NR_RAID1_BIOS, r1bio_pool_alloc,
				 r1bio_pool_free, newpoolinfo);
	if (!newpool) {
		kfree(newpoolinfo);
		return -ENOMEM;
	}
	newmirrors = kzalloc(sizeof(struct mirror_info) * raid_disks, GFP_KERNEL);
	if (!newmirrors) {
		kfree(newpoolinfo);
		mempool_destroy(newpool);
		return -ENOMEM;
	}

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_raise_barrier(conf);
#else
	raise_barrier(conf);
#endif

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	if (mddev->hw_raid) {
	    hwraid1_reshape_begin(mddev);
	}
#endif
	oldpool = conf->r1bio_pool;
	conf->r1bio_pool = newpool;

	for (d = d2 = 0; d < conf->raid_disks; d++) {
		mdk_rdev_t *rdev = conf->mirrors[d].rdev;
		if (rdev && rdev->raid_disk != d2) {
			char nm[20];
			sprintf(nm, "rd%d", rdev->raid_disk);
			sysfs_remove_link(&mddev->kobj, nm);
			rdev->raid_disk = d2;
			sprintf(nm, "rd%d", rdev->raid_disk);
			sysfs_remove_link(&mddev->kobj, nm);
			if (sysfs_create_link(&mddev->kobj,
					      &rdev->kobj, nm))
				printk(KERN_WARNING
				       "md/raid1: cannot register "
				       "%s for %s\n",
				       nm, mdname(mddev));
		}
		if (rdev)
			newmirrors[d2++].rdev = rdev;
	}
	kfree(conf->mirrors);
	conf->mirrors = newmirrors;
	kfree(conf->poolinfo);
	conf->poolinfo = newpoolinfo;

	spin_lock_irqsave(&conf->device_lock, flags);
	mddev->degraded += (raid_disks - conf->raid_disks);
	spin_unlock_irqrestore(&conf->device_lock, flags);
	conf->raid_disks = mddev->raid_disks = raid_disks;
	mddev->delta_disks = 0;

	conf->last_used = 0;  

#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	 
	if (mddev->hw_raid) {
	    hwraid1_reshape_end(mddev);
	}
#endif
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
	raid1_lower_barrier(conf);
#else
	lower_barrier(conf);
#endif

	set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
	md_wakeup_thread(mddev->thread);

	mempool_destroy(oldpool);
	return 0;
}

static void raid1_quiesce(mddev_t *mddev, int state)
{
	conf_t *conf = mddev->private;

	switch(state) {
	case 1:
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
		raid1_raise_barrier(conf);
#else
		raise_barrier(conf);
#endif
		break;
	case 0:
#ifdef CONFIG_SATA_OX820_DIRECT_HWRAID
		raid1_lower_barrier(conf);
#else
		lower_barrier(conf);
#endif
		break;
	}
}

static struct mdk_personality raid1_personality =
{
	.name		= "raid1",
	.level		= 1,
	.owner		= THIS_MODULE,
	.make_request	= make_request,
	.run		= run,
	.stop		= stop,
	.status		= status,
#ifdef MY_ABC_HERE
	.error_handler	= syno_error_for_internal,
	.syno_error_handler = syno_error_for_hotplug,
#else  
	.error_handler	= error,
#if defined(MY_ABC_HERE)
	.syno_error_handler = NULL,
#endif
#endif  
	.hot_add_disk	= raid1_add_disk,
	.hot_remove_disk= raid1_remove_disk,
	.spare_active	= raid1_spare_active,
	.sync_request	= sync_request,
	.resize		= raid1_resize,
	.size		= raid1_size,
	.check_reshape	= raid1_reshape,
	.quiesce	= raid1_quiesce,
#ifdef MY_ABC_HERE
	.ismaxdegrade = SynoIsRaidReachMaxDegrade,
#endif
};

static int __init raid_init(void)
{
	return register_md_personality(&raid1_personality);
}

static void raid_exit(void)
{
	unregister_md_personality(&raid1_personality);
}

module_init(raid_init);
module_exit(raid_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS("md-personality-3");  
MODULE_ALIAS("md-raid1");
MODULE_ALIAS("md-level-1");
