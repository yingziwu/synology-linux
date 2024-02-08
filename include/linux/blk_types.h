#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 * Block data types and constants.  Directly include this file only to
 * break include dependency loop.
 */
#ifndef __LINUX_BLK_TYPES_H
#define __LINUX_BLK_TYPES_H

#include <linux/types.h>

struct bio_set;
struct bio;
struct bio_integrity_payload;
struct page;
struct block_device;
struct io_context;
struct cgroup_subsys_state;
typedef void (bio_end_io_t) (struct bio *);
typedef void (bio_destructor_t) (struct bio *);

/*
 * was unsigned short, but we might as well be ready for > 64kB I/O pages
 */
struct bio_vec {
	struct page	*bv_page;
	unsigned int	bv_len;
	unsigned int	bv_offset;
};

#ifdef CONFIG_BLOCK

struct bvec_iter {
	sector_t		bi_sector;	/* device address in 512 byte
						   sectors */
	unsigned int		bi_size;	/* residual I/O count */

	unsigned int		bi_idx;		/* current index into bvl_vec */

	unsigned int            bi_bvec_done;	/* number of bytes completed in
						   current bvec */
};

/*
 * main unit of I/O for the block layer and lower layers (ie drivers and
 * stacking drivers)
 */
struct bio {
	struct bio		*bi_next;	/* request queue link */
	struct block_device	*bi_bdev;
	unsigned int		bi_flags;	/* status, command, etc */
	int			bi_error;
	unsigned long		bi_rw;		/* bottom bits READ/WRITE,
						 * top bits priority
						 */

	struct bvec_iter	bi_iter;

	/* Number of segments in this BIO after
	 * physical address coalescing is performed.
	 */
	unsigned int		bi_phys_segments;

	/*
	 * To keep track of the max segment size, we account for the
	 * sizes of the first and last mergeable segments in this bio.
	 */
	unsigned int		bi_seg_front_size;
	unsigned int		bi_seg_back_size;

	atomic_t		__bi_remaining;

	bio_end_io_t		*bi_end_io;

	void			*bi_private;
#ifdef CONFIG_BLK_CGROUP
	/*
	 * Optional ioc and css associated with this bio.  Put on bio
	 * release.  Read comment on top of bio_associate_current().
	 */
	struct io_context	*bi_ioc;
	struct cgroup_subsys_state *bi_css;
#endif
	union {
#if defined(CONFIG_BLK_DEV_INTEGRITY)
		struct bio_integrity_payload *bi_integrity; /* data integrity */
#endif
	};

	unsigned short		bi_vcnt;	/* how many bio_vec's */

	/*
	 * Everything starting with bi_max_vecs will be preserved by bio_reset()
	 */

	unsigned short		bi_max_vecs;	/* max bvl_vecs we can hold */

	atomic_t		__bi_cnt;	/* pin count */

	struct bio_vec		*bi_io_vec;	/* the actual vec list */

	struct bio_set		*bi_pool;

	/*
	 * We can inline a number of vecs at the end of the bio, to avoid
	 * double allocations for a small number of bio_vecs. This member
	 * MUST obviously be kept at the very end of the bio.
	 */
	struct bio_vec		bi_inline_vecs[0];
};

#define BIO_RESET_BYTES		offsetof(struct bio, bi_max_vecs)

/*
 * bio flags
 */
#define BIO_SEG_VALID	1	/* bi_phys_segments valid */
#define BIO_CLONED	2	/* doesn't own data */
#define BIO_BOUNCED	3	/* bio is a bounce bio */
#define BIO_USER_MAPPED 4	/* contains user pages */
#define BIO_NULL_MAPPED 5	/* contains invalid user pages */
#define BIO_QUIET	6	/* Make BIO Quiet */
#define BIO_CHAIN	7	/* chained bio, ->bi_remaining in effect */
#define BIO_REFFED	8	/* bio has elevated ->bi_cnt */
#ifdef MY_ABC_HERE
#define BIO_TRACE_COMPLETION	10	/* bio_endio() should trace the final completion of this bio */
#endif /* MY_ABC_HERE */

/*
 * Flags starting here get preserved by bio_reset() - this includes
 * BIO_POOL_IDX()
 */
#define BIO_RESET_BITS	13
#define BIO_OWNS_VEC	13	/* bio_free() should free bvec */
#ifdef MY_ABC_HERE
#define BIO_AUTO_REMAP 14	/* record if auto-remap occurred */
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
/*
 * Currently, our RAID1 device won't return error on make_reuest() when RAID1 is crashed
 * So we add this flag to told md layer that is should eturn error for flashcache * devices
 */
#define BIO_MD_RETURN_ERROR 15
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
/*
 * Tell lower layer to get the redundant version for this block.
 */
#define BIO_CORRECTION_RETRY 16

/*
 * Report to upper layer we have tried all dedundancies for this block.
 */
#define BIO_CORRECTION_ERR 17

/*
 * Tell lower layer that we give up the retry for this block.
 */
#define BIO_CORRECTION_ABORT 18
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#define BIO_SEND_SELF 19
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
/**
 * Make the bio be rearranged behind the other bios which are submitted
 * after it in current ->make_request_fn.
 *
 * generic_make_request() will sort bios by following order:
 * 1. bios to lower level.
 * 2. bios to same level.
 * 3. bios with BIO_DELAYED flags.
 * 4. bios submitted before current->make_request_fn.
 *
 * Note that bios with BIO_DELAYED flags will be sorted by
 * last-in-first-out order.
 */
#define BIO_DELAYED 20
#endif /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define BIO_SYNO_FULL_STRIPE_MERGE 21 /* This bio should apply full stripe merge */
#endif /* MY_ABC_HERE */

/*
 * top 4 bits of bio flags indicate the pool this bio came from
 */
#define BIO_POOL_BITS		(4)
#define BIO_POOL_NONE		((1UL << BIO_POOL_BITS) - 1)
#define BIO_POOL_OFFSET		(32 - BIO_POOL_BITS)
#define BIO_POOL_MASK		(1UL << BIO_POOL_OFFSET)
#define BIO_POOL_IDX(bio)	((bio)->bi_flags >> BIO_POOL_OFFSET)

#endif /* CONFIG_BLOCK */

/*
 * Request flags.  For use in the cmd_flags field of struct request, and in
 * bi_rw of struct bio.  Note that some flags are only valid in either one.
 */
enum rq_flag_bits {
	/* common flags */
	__REQ_WRITE,		/* not set, read. set, write */
	__REQ_FAILFAST_DEV,	/* no driver retries of device errors */
	__REQ_FAILFAST_TRANSPORT, /* no driver retries of transport errors */
	__REQ_FAILFAST_DRIVER,	/* no driver retries of driver errors */

	__REQ_SYNC,		/* request is sync (sync write or read) */
	__REQ_META,		/* metadata io request */
	__REQ_PRIO,		/* boost priority in cfq */
	__REQ_DISCARD,		/* request to discard sectors */
	__REQ_SECURE,		/* secure discard (used with __REQ_DISCARD) */
	__REQ_WRITE_SAME,	/* write same block many times */

	__REQ_NOIDLE,		/* don't anticipate more IO after this one */
	__REQ_INTEGRITY,	/* I/O includes block integrity payload */
	__REQ_FUA,		/* forced unit access */
	__REQ_FLUSH,		/* request for cache flush */
#ifdef MY_ABC_HERE
	__REQ_UNUSED_HINT,	/* unused space hint for RAID */
#endif /* MY_ABC_HERE */

	/* bio only flags */
	__REQ_RAHEAD,		/* read ahead, can fail anytime */
	__REQ_THROTTLED,	/* This bio has already been subjected to
				 * throttling rules. Don't do it again. */
#ifdef MY_ABC_HERE
	__REQ_SYNO_RBD, /* synorbd : this only for bio flag */
#endif /* MY_ABC_HERE */

	/* request only flags */
	__REQ_SORTED,		/* elevator knows about this request */
	__REQ_SOFTBARRIER,	/* may not be passed by ioscheduler */
	__REQ_NOMERGE,		/* don't touch this for merging */
	__REQ_STARTED,		/* drive already may have started this one */
	__REQ_DONTPREP,		/* don't call prep for this one */
	__REQ_QUEUED,		/* uses queueing */
	__REQ_ELVPRIV,		/* elevator private data attached */
	__REQ_FAILED,		/* set if the request failed */
	__REQ_QUIET,		/* don't worry about errors */
	__REQ_PREEMPT,		/* set for "ide_preempt" requests and also
				   for requests for which the SCSI "quiesce"
				   state must be ignored. */
	__REQ_ALLOCED,		/* request came from our alloc pool */
	__REQ_COPY_USER,	/* contains copies of user pages */
	__REQ_FLUSH_SEQ,	/* request for flush sequence */
	__REQ_IO_STAT,		/* account I/O stat */
	__REQ_MIXED_MERGE,	/* merge of different types, fail separately */
	__REQ_PM,		/* runtime pm request */
	__REQ_HASHED,		/* on IO scheduler merge hash */
	__REQ_MQ_INFLIGHT,	/* track inflight for MQ */
	__REQ_NO_TIMEOUT,	/* requests may never expire */
#ifdef MY_DEF_HERE
	__REQ_SYNO_COMPELETED_HARDIRQ_DONE, /* finish hard irq runtine after being marked compelete */
#endif
	__REQ_NR_BITS,		/* stops here */
#ifdef MY_ABC_HERE
	__REQ_SYNO_PATTERN_CHECK, /* pattern debug check flag */
#endif /* MY_ABC_HERE */

};

#define REQ_WRITE		(1ULL << __REQ_WRITE)
#define REQ_FAILFAST_DEV	(1ULL << __REQ_FAILFAST_DEV)
#define REQ_FAILFAST_TRANSPORT	(1ULL << __REQ_FAILFAST_TRANSPORT)
#define REQ_FAILFAST_DRIVER	(1ULL << __REQ_FAILFAST_DRIVER)
#define REQ_SYNC		(1ULL << __REQ_SYNC)
#define REQ_META		(1ULL << __REQ_META)
#define REQ_PRIO		(1ULL << __REQ_PRIO)
#define REQ_DISCARD		(1ULL << __REQ_DISCARD)
#define REQ_WRITE_SAME		(1ULL << __REQ_WRITE_SAME)
#define REQ_NOIDLE		(1ULL << __REQ_NOIDLE)
#define REQ_INTEGRITY		(1ULL << __REQ_INTEGRITY)
#ifdef MY_ABC_HERE
#define REQ_SYNO_PATTERN_CHECK	(1ULL << __REQ_SYNO_PATTERN_CHECK)
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#define REQ_UNUSED_HINT		(1ULL << __REQ_UNUSED_HINT)
#endif /* MY_ABC_HERE */

#define REQ_FAILFAST_MASK \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)
#ifdef  MY_ABC_HERE
#ifdef MY_ABC_HERE
#define REQ_COMMON_MASK \
        (REQ_WRITE | REQ_FAILFAST_MASK | REQ_SYNC | REQ_META | REQ_PRIO | \
         REQ_DISCARD | REQ_WRITE_SAME | REQ_NOIDLE | REQ_FLUSH | REQ_FUA | \
         REQ_SECURE | REQ_INTEGRITY | REQ_UNUSED_HINT | REQ_NOMERGE | REQ_SYNO_PATTERN_CHECK)
#else /* MY_ABC_HERE */
#define REQ_COMMON_MASK \
	(REQ_WRITE | REQ_FAILFAST_MASK | REQ_SYNC | REQ_META | REQ_PRIO | \
	 REQ_DISCARD | REQ_WRITE_SAME | REQ_NOIDLE | REQ_FLUSH | REQ_FUA | \
	 REQ_SECURE | REQ_INTEGRITY | REQ_UNUSED_HINT | REQ_NOMERGE)
#endif /* MY_ABC_HERE */
#else /* MY_ABC_HERE */
#ifdef MY_ABC_HERE
#define REQ_COMMON_MASK \
	(REQ_WRITE | REQ_FAILFAST_MASK | REQ_SYNC | REQ_META | REQ_PRIO | \
	 REQ_DISCARD | REQ_WRITE_SAME | REQ_NOIDLE | REQ_FLUSH | REQ_FUA | \
	 REQ_SECURE | REQ_INTEGRITY | REQ_NOMERGE | REQ_SYNO_PATTERN_CHECK)
#else /* MY_ABC_HERE */
#define REQ_COMMON_MASK \
	(REQ_WRITE | REQ_FAILFAST_MASK | REQ_SYNC | REQ_META | REQ_PRIO | \
	 REQ_DISCARD | REQ_WRITE_SAME | REQ_NOIDLE | REQ_FLUSH | REQ_FUA | \
	 REQ_SECURE | REQ_INTEGRITY | REQ_NOMERGE)
#endif /* MY_ABC_HERE */
#endif /* MY_ABC_HERE */
#define REQ_CLONE_MASK		REQ_COMMON_MASK

#define BIO_NO_ADVANCE_ITER_MASK	(REQ_DISCARD|REQ_WRITE_SAME)

/* This mask is used for both bio and request merge checking */
#define REQ_NOMERGE_FLAGS \
	(REQ_NOMERGE | REQ_STARTED | REQ_SOFTBARRIER | REQ_FLUSH | REQ_FUA | REQ_FLUSH_SEQ)

#define REQ_RAHEAD		(1ULL << __REQ_RAHEAD)
#define REQ_THROTTLED		(1ULL << __REQ_THROTTLED)
#ifdef MY_ABC_HERE
#define REQ_SYNO_RBD		(1ULL << __REQ_SYNO_RBD)
#endif /* MY_ABC_HERE */

#define REQ_SORTED		(1ULL << __REQ_SORTED)
#define REQ_SOFTBARRIER		(1ULL << __REQ_SOFTBARRIER)
#define REQ_FUA			(1ULL << __REQ_FUA)
#define REQ_NOMERGE		(1ULL << __REQ_NOMERGE)
#define REQ_STARTED		(1ULL << __REQ_STARTED)
#define REQ_DONTPREP		(1ULL << __REQ_DONTPREP)
#define REQ_QUEUED		(1ULL << __REQ_QUEUED)
#define REQ_ELVPRIV		(1ULL << __REQ_ELVPRIV)
#define REQ_FAILED		(1ULL << __REQ_FAILED)
#define REQ_QUIET		(1ULL << __REQ_QUIET)
#define REQ_PREEMPT		(1ULL << __REQ_PREEMPT)
#define REQ_ALLOCED		(1ULL << __REQ_ALLOCED)
#define REQ_COPY_USER		(1ULL << __REQ_COPY_USER)
#define REQ_FLUSH		(1ULL << __REQ_FLUSH)
#define REQ_FLUSH_SEQ		(1ULL << __REQ_FLUSH_SEQ)
#define REQ_IO_STAT		(1ULL << __REQ_IO_STAT)
#define REQ_MIXED_MERGE		(1ULL << __REQ_MIXED_MERGE)
#define REQ_SECURE		(1ULL << __REQ_SECURE)
#define REQ_PM			(1ULL << __REQ_PM)
#define REQ_HASHED		(1ULL << __REQ_HASHED)
#define REQ_MQ_INFLIGHT		(1ULL << __REQ_MQ_INFLIGHT)
#define REQ_NO_TIMEOUT		(1ULL << __REQ_NO_TIMEOUT)
#ifdef MY_DEF_HERE
#define REQ_SYNO_COMPELETED_HARDIRQ_DONE	(1ULL << __REQ_SYNO_COMPELETED_HARDIRQ_DONE)
#endif

typedef unsigned int blk_qc_t;
#define BLK_QC_T_NONE	-1U
#define BLK_QC_T_SHIFT	16

static inline bool blk_qc_t_valid(blk_qc_t cookie)
{
	return cookie != BLK_QC_T_NONE;
}

static inline blk_qc_t blk_tag_to_qc_t(unsigned int tag, unsigned int queue_num)
{
	return tag | (queue_num << BLK_QC_T_SHIFT);
}

static inline unsigned int blk_qc_t_to_queue_num(blk_qc_t cookie)
{
	return cookie >> BLK_QC_T_SHIFT;
}

static inline unsigned int blk_qc_t_to_tag(blk_qc_t cookie)
{
	return cookie & ((1u << BLK_QC_T_SHIFT) - 1);
}

#endif /* __LINUX_BLK_TYPES_H */
