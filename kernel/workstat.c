#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/ratelimit.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/hardirq.h>

#include "workqueue_internal.h"

#ifdef MY_ABC_HERE

#define KWORK_STAT_UPDATE_RATE_MS 	250

struct workstat {
	/* corresponding work function */
	work_func_t func;

	/**
	 * Please refer to task_io_accounting.h for the following
	 * I/O statistics
	 */
	atomic64_t read_bytes;
	atomic64_t write_bytes;
	atomic64_t cancelled_write_bytes;

	/* rb tree node */
	struct rb_node node;
};

struct workstat_records {
	rwlock_t lock;			/* lock for the tree and enable */
	u32 enable;			/* 1: enable. 0: disable */
	struct rb_root tree_root;
};

static struct workstat_records workstat_records = {0};

/**
 * Copy work_acct from current and init jiffies
 */
static inline void reset_work_acct(struct work_acct *acct)
{
	acct->read_bytes = current->ioac.read_bytes;
	acct->write_bytes = current->ioac.write_bytes;
	acct->cancelled_write_bytes = current->ioac.cancelled_write_bytes;
	acct->last_update_jiffies = jiffies;
}

/**
 * diff = current - acct
 * Return true if any non-zero value in acct
 */
static inline bool diff_work_acct(struct work_acct *diff,
				  const struct work_acct *acct)
{
	diff->func = acct->func;
	diff->read_bytes = current->ioac.read_bytes
			 - acct->read_bytes;
	diff->write_bytes = current->ioac.write_bytes
			  - acct->write_bytes;
	diff->cancelled_write_bytes = current->ioac.cancelled_write_bytes
				    - acct->cancelled_write_bytes;
	return (diff->read_bytes || diff->write_bytes ||
	        diff->cancelled_write_bytes);
}

/**
 * Allocate and init workstat.
 *
 * Return: Pointer to workstat on success and NULL on failure
 */
static inline struct workstat *alloc_workstat(work_func_t func,
					      struct work_acct *acct,
					      gfp_t gfp)
{
	struct workstat *stat = kmalloc(sizeof(struct workstat), gfp);
	if (!stat) {
		pr_err_ratelimited("Could not allocate workstat\n");
		return NULL;
	}

	stat->func = func;
	atomic64_set(&stat->read_bytes, acct->read_bytes);
	atomic64_set(&stat->write_bytes, acct->write_bytes);
	atomic64_set(&stat->cancelled_write_bytes, acct->cancelled_write_bytes);

	return stat;
}

/**
 * Search records by func.
 *
 * Return workstat* if we found it and NULL if not found
 * CONTEXT: read_lock(workstat_records.lock)
 */
static inline struct workstat *
workstat_records_search(struct workstat_records *records,
			work_func_t func)
{
	struct workstat *curr;
	struct rb_node *n = records->tree_root.rb_node;

	while (n) {
		curr = rb_entry(n, struct workstat, node);
		if (func < curr->func)
			n = n->rb_left;
		else if (func > curr->func)
			n = n->rb_right;
		else
			return curr;
	}
	return NULL;
}

/**
 * CONTEXT: write_lock(workstat_records.lock)
 */
static inline struct workstat *
workstat_records_insert(struct workstat_records *records,
			struct workstat *ins)
{
	struct rb_node **link = &records->tree_root.rb_node;
	struct rb_node *parent = NULL;
	struct workstat *curr = NULL;

	while (*link) {
		parent = *link;
		curr = rb_entry(parent, struct workstat, node);

		if (ins->func < curr->func)
			link = &((*link)->rb_left);
		else if (ins->func > curr->func)
			link = &((*link)->rb_right);
		else
			return curr;
	}

	/* add new node and rebalance tree. */
	rb_link_node(&ins->node, parent, link);
	rb_insert_color(&ins->node, &records->tree_root);

	return NULL;
}

/**
 * CONTEXT: write_lock(workstat_records.lock)
 */
static void workstat_records_reset(struct workstat_records *records)
{
	struct workstat *stat;
	struct rb_node *curr;

	while (!RB_EMPTY_ROOT(&records->tree_root)) {
		curr = rb_first(&records->tree_root);
		stat = rb_entry(curr, struct workstat, node);
		rb_erase(&stat->node, &records->tree_root);
		kfree(stat);
	}
}

static void update_kwork_stat(struct work_acct *curr_acct, gfp_t gfp)
{
	struct workstat *stat;
	struct workstat *exist;
	struct work_acct diff;
	unsigned long flags;

	if (!curr_acct || !workstat_records.enable)
		return;

	if (!diff_work_acct(&diff, curr_acct))
		return;

retry:
	read_lock_irqsave(&workstat_records.lock, flags);

	/*
	 * We will leave some records if we are racing with disabling
	 * workstat_records. That is safe.
	 */

	stat = workstat_records_search(&workstat_records, curr_acct->func);
	if (!stat) {
		read_unlock_irqrestore(&workstat_records.lock, flags);

		stat = alloc_workstat(curr_acct->func, &diff, gfp);
		/*
		 * It's ok if we alloc memory failed.
		 * We will have another try if we have I/O next time.
		 */
		if (!stat)
			goto out_no_update;

		write_lock_irqsave(&workstat_records.lock, flags);
		exist = workstat_records_insert(&workstat_records, stat);
		write_unlock_irqrestore(&workstat_records.lock, flags);
		if (exist) {
			/* We may race with other insertions */
			kfree(stat);
			stat = NULL;
			goto retry;
		}
		goto out;
	}

	/* accumulate workstat */
	atomic64_add(diff.read_bytes, &stat->read_bytes);
	atomic64_add(diff.write_bytes, &stat->write_bytes);
	atomic64_add(diff.cancelled_write_bytes, &stat->cancelled_write_bytes);

	read_unlock_irqrestore(&workstat_records.lock, flags);

out:
	reset_work_acct(curr_acct);

out_no_update:
	return;
}

void update_kwork_stat_ratelimited(gfp_t gfp)
{
	struct work_acct *curr_acct = current->workacct;

	if (!curr_acct)
		return;

	if (jiffies_to_msecs(jiffies - curr_acct->last_update_jiffies)
	    < KWORK_STAT_UPDATE_RATE_MS)
		return;

	update_kwork_stat(curr_acct, gfp);
}
EXPORT_SYMBOL(update_kwork_stat_ratelimited);

void worker_run_work(struct worker *worker, struct work_struct *work)
{
	struct work_acct acct = {0};
	volatile bool enable = workstat_records.enable;

	if (enable) {
		reset_work_acct(&acct);
		acct.func = worker->current_func;
		/*
		 * Saving pointer of local variable in current should be safe.
		 * Please refered to current->plug.
		 */
		current->workacct = &acct;
	}

	worker->current_func(work);

	if (enable)
		update_kwork_stat(&acct, GFP_KERNEL);

	current->workacct = NULL;
}
EXPORT_SYMBOL(worker_run_work);

/**
 * Interfaces for procfs
 */
static int workstat_stats_proc_show(struct seq_file *m, void *v)
{
	struct rb_node *n;
	struct workstat *stat;

	read_lock_irq(&workstat_records.lock);

	n = rb_first(&workstat_records.tree_root);
	while (n) {
		stat = rb_entry(n, struct workstat, node);
		seq_printf(m, "%pf: %llu %llu %llu\n",
			   stat->func,
			   (u64)atomic64_read(&stat->read_bytes),
			   (u64)atomic64_read(&stat->write_bytes),
			   (u64)atomic64_read(&stat->cancelled_write_bytes));
		n = rb_next(n);
	}

	read_unlock_irq(&workstat_records.lock);
	return 0;
}

static int workstat_stats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, workstat_stats_proc_show, NULL);
}

static const struct file_operations workstat_stats_proc_fops = {
	.open		= workstat_stats_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int workstat_enable_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d", workstat_records.enable);
	return 0;
}

static int workstat_enable_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, workstat_enable_proc_show, NULL);
}

static ssize_t workstat_enable_proc_write(struct file * file,
				      const char __user * buf,
				      size_t count, loff_t *ppos)
{
	u32 val;
	int ret;

	if (*ppos != 0) {
		/* No partial writes. */
		ret = -EINVAL;
		goto out;
	}

	ret = kstrtou32_from_user(buf, count, 10, &val);
	if (ret < 0)
		goto out;

	ret = count;
	if (val == workstat_records.enable)
		goto out;

	write_lock_irq(&workstat_records.lock);
	workstat_records.enable = !!val;
	if (!val)
		workstat_records_reset(&workstat_records);
	write_unlock_irq(&workstat_records.lock);

out:
	return ret;
}

static const struct file_operations workstat_enable_proc_fops = {
	.open		= workstat_enable_proc_open,
	.read		= seq_read,
	.write		= workstat_enable_proc_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_workstat_init(void)
{
	workstat_records.tree_root = RB_ROOT;
	rwlock_init(&workstat_records.lock);

	if (!proc_mkdir("workstat", NULL))
		return -ENOMEM;

	if (!proc_create("workstat/stats", 0, NULL,
			 &workstat_stats_proc_fops))
		goto err;

	if (!proc_create("workstat/enable", 0, NULL,
			 &workstat_enable_proc_fops))
		goto err;

	workstat_records.enable = 1;
	return 0;
err:
	remove_proc_subtree("workstat", NULL);
	return -ENOMEM;
}

static void __exit proc_workstat_exit(void)
{
	write_lock_irq(&workstat_records.lock);
	workstat_records.enable = 0;
	workstat_records_reset(&workstat_records);
	write_unlock_irq(&workstat_records.lock);
}

fs_initcall(proc_workstat_init);
module_exit(proc_workstat_exit);
#endif /* MY_ABC_HERE */