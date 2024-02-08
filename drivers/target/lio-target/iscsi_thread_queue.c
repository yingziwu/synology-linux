#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define ISCSI_THREAD_QUEUE_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>

#undef ISCSI_THREAD_QUEUE_C

static void iscsi_add_ts_to_active_list(se_thread_set_t *ts)
{
#if 0
	printk(KERN_INFO "Adding thread set %d to active list\n",
			ts->thread_id);
#endif
	spin_lock(&iscsi_global->active_ts_lock);
	list_add_tail(&ts->ts_list, &iscsi_global->active_ts_list);
	iscsi_global->active_ts++;
	spin_unlock(&iscsi_global->active_ts_lock);
}

extern void iscsi_add_ts_to_inactive_list(se_thread_set_t *ts)
{
#if 0
	printk(KERN_INFO "Adding thread set %d to inactive list\n",
			ts->thread_id);
#endif
	spin_lock(&iscsi_global->inactive_ts_lock);
	list_add_tail(&ts->ts_list, &iscsi_global->inactive_ts_list);
	iscsi_global->inactive_ts++;
	spin_unlock(&iscsi_global->inactive_ts_lock);
}

static void iscsi_del_ts_from_active_list(se_thread_set_t *ts)
{
#if 0
	printk(KERN_INFO "Remove thread set %d from active list\n",
			ts->thread_id);
#endif
	spin_lock(&iscsi_global->active_ts_lock);
	list_del(&ts->ts_list);
	iscsi_global->active_ts--;
	spin_unlock(&iscsi_global->active_ts_lock);

	if (ts->stop_active)
		up(&ts->stop_active_sem);
}

static se_thread_set_t *iscsi_get_ts_from_inactive_list(void)
{
	se_thread_set_t *ts;

	spin_lock(&iscsi_global->inactive_ts_lock);
	if (list_empty(&iscsi_global->inactive_ts_list)) {
		spin_unlock(&iscsi_global->inactive_ts_lock);
		return NULL;
	}

	list_for_each_entry(ts, &iscsi_global->inactive_ts_list, ts_list)
		break;

	list_del(&ts->ts_list);
	iscsi_global->inactive_ts--;
	spin_unlock(&iscsi_global->inactive_ts_lock);

	return ts;
}

extern int iscsi_allocate_thread_sets(u32 thread_pair_count, int role)
{
	int allocated_thread_pair_count = 0, i;
	se_thread_set_t *ts = NULL;

	for (i = 0; i < thread_pair_count; i++) {
		ts = kzalloc(sizeof(se_thread_set_t), GFP_KERNEL);
		if (!(ts)) {
			printk(KERN_ERR "Unable to allocate memory for"
					" thread set.\n");
			return allocated_thread_pair_count;
		}

		ts->status = ISCSI_THREAD_SET_FREE;
		INIT_LIST_HEAD(&ts->ts_list);
		spin_lock_init(&ts->ts_state_lock);
		init_MUTEX_LOCKED(&ts->stop_active_sem);
		init_MUTEX_LOCKED(&ts->rx_create_sem);
		init_MUTEX_LOCKED(&ts->tx_create_sem);
		init_MUTEX_LOCKED(&ts->rx_done_sem);
		init_MUTEX_LOCKED(&ts->tx_done_sem);
		init_MUTEX_LOCKED(&ts->rx_post_start_sem);
		init_MUTEX_LOCKED(&ts->tx_post_start_sem);
		init_MUTEX_LOCKED(&ts->rx_restart_sem);
		init_MUTEX_LOCKED(&ts->tx_restart_sem);
		init_MUTEX_LOCKED(&ts->rx_start_sem);
		init_MUTEX_LOCKED(&ts->tx_start_sem);

		ts->thread_id = iscsi_global->thread_id++;
		if (!ts->thread_id)
			ts->thread_id = iscsi_global->thread_id++;

		ts->create_threads = 1;
		kernel_thread(iscsi_target_rx_thread,
				(void *)ts, 0);
		down(&ts->rx_create_sem);

		kernel_thread(iscsi_target_tx_thread,
				(void *)ts, 0);
		down(&ts->tx_create_sem);
		ts->create_threads = 0;

		iscsi_add_ts_to_inactive_list(ts);
		allocated_thread_pair_count++;
	}

#ifndef MY_ABC_HERE
	printk(KERN_INFO "Spawned %d thread set(s) (%d total threads).\n",
		allocated_thread_pair_count, allocated_thread_pair_count * 2);
#endif
	return allocated_thread_pair_count;
}

extern void iscsi_deallocate_thread_sets(int role)
{
	u32 released_count = 0;
	se_thread_set_t *ts = NULL;

	while ((ts = iscsi_get_ts_from_inactive_list())) {
#if 0
		printk(KERN_INFO "Deallocating THREAD_ID: %d\n", ts->thread_id);
#endif
		spin_lock_bh(&ts->ts_state_lock);
		ts->status = ISCSI_THREAD_SET_DIE;
		spin_unlock_bh(&ts->ts_state_lock);

		if (ts->rx_thread) {
			send_sig(SIGKILL, ts->rx_thread, 1);
			down(&ts->rx_done_sem);
		}
		if (ts->tx_thread) {
			send_sig(SIGKILL, ts->tx_thread, 1);
			down(&ts->tx_done_sem);
		}
#if 0
		printk(KERN_INFO "Deallocated THREAD_ID: %d\n", ts->thread_id);
#endif
		released_count++;
		kfree(ts);
	}

#ifndef MY_ABC_HERE
	if (released_count)
		printk(KERN_INFO "Stopped %d thread set(s) (%d total threads)."
			"\n", released_count, released_count * 2);
#endif
}

static void iscsi_deallocate_extra_thread_sets(int role)
{
	u32 orig_count, released_count = 0;
	se_thread_set_t *ts = NULL;

	orig_count = ((role == INITIATOR) ? INITIATOR_THREAD_SET_COUNT :
			TARGET_THREAD_SET_COUNT);

	while ((iscsi_global->inactive_ts + 1) > orig_count) {
		ts = iscsi_get_ts_from_inactive_list();
		if (!(ts))
			break;
#if 0
		printk(KERN_INFO "Deallocating THREAD_ID: %d\n", ts->thread_id);
#endif
		spin_lock_bh(&ts->ts_state_lock);
		ts->status = ISCSI_THREAD_SET_DIE;
		spin_unlock_bh(&ts->ts_state_lock);

		if (ts->rx_thread) {
			send_sig(SIGKILL, ts->rx_thread, 1);
			down(&ts->rx_done_sem);
		}
		if (ts->tx_thread) {
			send_sig(SIGKILL, ts->tx_thread, 1);
			down(&ts->tx_done_sem);
		}
#if 0
		printk(KERN_INFO "Deallocated THREAD_ID: %d\n", ts->thread_id);
#endif
		released_count++;
		kfree(ts);
	}

#ifndef MY_ABC_HERE
	if (released_count) {
		printk(KERN_INFO "Stopped %d thread set(s) (%d total threads)."
			"\n", released_count, released_count * 2);
	}
#endif
}

void iscsi_activate_thread_set(iscsi_conn_t *conn, se_thread_set_t *ts)
{
	iscsi_add_ts_to_active_list(ts);
#if 0
	printk(KERN_ERR "Activating Thread Set ID: %u\n", ts->thread_id);
#endif
	spin_lock_bh(&ts->ts_state_lock);
	conn->thread_set = ts;
	ts->conn = conn;
	spin_unlock_bh(&ts->ts_state_lock);

	up(&ts->rx_start_sem);
	down(&ts->rx_post_start_sem);
}

static void iscsi_get_thread_set_timeout(unsigned long data)
{
	up((struct semaphore *)data);
}

se_thread_set_t *iscsi_get_thread_set(int role)
{
	int allocate_ts = 0;
	struct semaphore sem;
	struct timer_list timer;
	se_thread_set_t *ts = NULL;

get_set:
	ts = iscsi_get_ts_from_inactive_list();
	if (!(ts)) {
		if (allocate_ts == 2)
			iscsi_allocate_thread_sets(1, INITIATOR);

		init_MUTEX_LOCKED(&sem);
		init_timer(&timer);
		SETUP_TIMER(timer, 1, &sem, iscsi_get_thread_set_timeout);
		add_timer(&timer);

		down(&sem);
		del_timer_sync(&timer);
		allocate_ts++;
		goto get_set;
	}

	ts->delay_inactive = 1;
	ts->signal_sent = ts->stop_active = 0;
	ts->thread_count = 2;
	init_MUTEX_LOCKED(&ts->rx_restart_sem);
	init_MUTEX_LOCKED(&ts->tx_restart_sem);

	return ts;
}

void iscsi_set_thread_clear(iscsi_conn_t *conn, u8 thread_clear)
{
	se_thread_set_t *ts = NULL;

	if (!conn->thread_set) {
		printk(KERN_ERR "iscsi_conn_t->thread_set is NULL\n");
		return;
	}
	ts = conn->thread_set;

	spin_lock_bh(&ts->ts_state_lock);
	ts->thread_clear &= ~thread_clear;

	if ((thread_clear & ISCSI_CLEAR_RX_THREAD) &&
	    (ts->blocked_threads & ISCSI_BLOCK_RX_THREAD))
		up(&ts->rx_restart_sem);
	else if ((thread_clear & ISCSI_CLEAR_TX_THREAD) &&
		 (ts->blocked_threads & ISCSI_BLOCK_TX_THREAD))
		up(&ts->tx_restart_sem);
	spin_unlock_bh(&ts->ts_state_lock);
}

void iscsi_set_thread_set_signal(iscsi_conn_t *conn, u8 signal_sent)
{
	se_thread_set_t *ts = NULL;

	if (!conn->thread_set) {
		printk(KERN_ERR "iscsi_conn_t->thread_set is NULL\n");
		return;
	}
	ts = conn->thread_set;

	spin_lock_bh(&ts->ts_state_lock);
	ts->signal_sent |= signal_sent;
	spin_unlock_bh(&ts->ts_state_lock);
}

int iscsi_release_thread_set(iscsi_conn_t *conn, int role)
{
	int thread_called = 0;
	se_thread_set_t *ts = NULL;

	if (!conn || !conn->thread_set) {
		printk(KERN_ERR "connection or thread set pointer is NULL\n");
		BUG();
	}
	ts = conn->thread_set;
#if 0
	printk(KERN_ERR "Releasing thread set ID: %u for CID: %hu in SID:"
		" %u from %s:%d.\n", ts->thread_id, conn->cid,
			SESS(conn)->sid, current->comm, current->pid);
#endif
	spin_lock_bh(&ts->ts_state_lock);
	ts->status = ISCSI_THREAD_SET_RESET;

	if (!(strncmp(current->comm, ISCSI_RX_THREAD_NAME,
			strlen(ISCSI_RX_THREAD_NAME))))
		thread_called = ISCSI_RX_THREAD;
	else if (!(strncmp(current->comm, ISCSI_TX_THREAD_NAME,
			strlen(ISCSI_TX_THREAD_NAME))))
		thread_called = ISCSI_TX_THREAD;

	if (ts->rx_thread && (thread_called == ISCSI_TX_THREAD) &&
	   (ts->thread_clear & ISCSI_CLEAR_RX_THREAD)) {
#if 0
		printk(KERN_ERR "Stopping RX_THREAD for TS ID: %u\n",
				ts->thread_id);
#endif
		if (!(ts->signal_sent & ISCSI_SIGNAL_RX_THREAD)) {
			send_sig(SIGABRT, ts->rx_thread, 1);
			ts->signal_sent |= ISCSI_SIGNAL_RX_THREAD;
		}
		ts->blocked_threads |= ISCSI_BLOCK_RX_THREAD;
		spin_unlock_bh(&ts->ts_state_lock);
		down(&ts->rx_restart_sem);
		spin_lock_bh(&ts->ts_state_lock);
		ts->blocked_threads &= ~ISCSI_BLOCK_RX_THREAD;
	}
	if (ts->tx_thread && (thread_called == ISCSI_RX_THREAD) &&
	   (ts->thread_clear & ISCSI_CLEAR_TX_THREAD)) {
#if 0
		printk(KERN_ERR "Stopping TX_THREAD for TS ID: %u\n",
				ts->thread_id);
#endif
		if (!(ts->signal_sent & ISCSI_SIGNAL_TX_THREAD)) {
			send_sig(SIGABRT, ts->tx_thread, 1);
			ts->signal_sent |= ISCSI_SIGNAL_TX_THREAD;
		}
		ts->blocked_threads |= ISCSI_BLOCK_TX_THREAD;
		spin_unlock_bh(&ts->ts_state_lock);
		down(&ts->tx_restart_sem);
		spin_lock_bh(&ts->ts_state_lock);
		ts->blocked_threads &= ~ISCSI_BLOCK_TX_THREAD;
	}

#if 0
	printk(KERN_ERR "Released thread set ID: %u for CID: %hu in SID:"
		" %u.\n", ts->thread_id, conn->cid, SESS(conn)->sid);
#endif

	conn->thread_set = NULL;
	ts->conn = NULL;
	ts->status = ISCSI_THREAD_SET_FREE;
	spin_unlock_bh(&ts->ts_state_lock);

	return 0;
}

int iscsi_thread_set_force_reinstatement(iscsi_conn_t *conn)
{
	se_thread_set_t *ts;

	if (!conn->thread_set)
		return -1;
	ts = conn->thread_set;

	spin_lock_bh(&ts->ts_state_lock);
	if (ts->status != ISCSI_THREAD_SET_ACTIVE) {
		spin_unlock_bh(&ts->ts_state_lock);
		return -1;
	}

	if (ts->tx_thread && (!(ts->signal_sent & ISCSI_SIGNAL_TX_THREAD))) {
#if 0
		printk(KERN_ERR "Sending SIGABRT to TX_THREAD for thread id: %u\n",
				ts->thread_id);
#endif
		send_sig(SIGABRT, ts->tx_thread, 1);
		ts->signal_sent |= ISCSI_SIGNAL_TX_THREAD;
	}
	if (ts->rx_thread && (!(ts->signal_sent & ISCSI_SIGNAL_RX_THREAD))) {
#if 0
		printk(KERN_ERR "Sending SIGABRT to RX_THREAD for thread id: %u\n",
				ts->thread_id);
#endif
		send_sig(SIGABRT, ts->rx_thread, 1);
		ts->signal_sent |= ISCSI_SIGNAL_RX_THREAD;
	}
	spin_unlock_bh(&ts->ts_state_lock);

	return 0;
}

static void iscsi_check_to_add_additional_sets(int role)
{
	int thread_sets_add;

	spin_lock(&iscsi_global->inactive_ts_lock);
	thread_sets_add = iscsi_global->inactive_ts;
	spin_unlock(&iscsi_global->inactive_ts_lock);
	if (thread_sets_add == 1)
		iscsi_allocate_thread_sets(1, role);
}

static int iscsi_signal_thread_pre_handler(se_thread_set_t *ts)
{
#if 0
	printk(KERN_INFO "ts->thread_id: %d ts->status = %d%s\n", ts->thread_id,
		ts->status, (signal_pending(current)) ? " GOT_SIGNAL" : "");
#endif
	spin_lock_bh(&ts->ts_state_lock);
	if ((ts->status == ISCSI_THREAD_SET_DIE) || signal_pending(current)) {
		spin_unlock_bh(&ts->ts_state_lock);
		return -1;
	}
	spin_unlock_bh(&ts->ts_state_lock);

	return 0;
}

iscsi_conn_t *iscsi_rx_thread_pre_handler(se_thread_set_t *ts, int role)
{
	int ret;

	spin_lock_bh(&ts->ts_state_lock);
	if (ts->create_threads) {
		spin_unlock_bh(&ts->ts_state_lock);
		up(&ts->rx_create_sem);
		goto sleep;
	}

	flush_signals(current);

	if (ts->delay_inactive && (--ts->thread_count == 0)) {
		spin_unlock_bh(&ts->ts_state_lock);
#if 0
		printk(KERN_ERR "Releasing delayed inactive TS %u from RX pre"
			" handler\n", ts->thread_id);
#endif
		iscsi_del_ts_from_active_list(ts);

		if (!iscsi_global->in_shutdown)
			iscsi_deallocate_extra_thread_sets(INITIATOR);

		iscsi_add_ts_to_inactive_list(ts);
		spin_lock_bh(&ts->ts_state_lock);
	}

	if ((ts->status == ISCSI_THREAD_SET_RESET) &&
	    (ts->thread_clear & ISCSI_CLEAR_RX_THREAD))
		up(&ts->rx_restart_sem);

	ts->thread_clear &= ~ISCSI_CLEAR_RX_THREAD;
	spin_unlock_bh(&ts->ts_state_lock);
sleep:
	ret = down_interruptible(&ts->rx_start_sem);
	if (ret != 0)
		return NULL;

	if (iscsi_signal_thread_pre_handler(ts) < 0)
		return NULL;

	if (!ts->conn) {
		printk(KERN_ERR "se_thread_set_t->conn is NULL for"
			" thread_id: %d, going back to sleep\n", ts->thread_id);
		goto sleep;
	}
	iscsi_check_to_add_additional_sets(role);
	 
	ts->thread_clear |= ISCSI_CLEAR_RX_THREAD;
	up(&ts->tx_start_sem);
	down(&ts->tx_post_start_sem);

	return ts->conn;
}

iscsi_conn_t *iscsi_tx_thread_pre_handler(se_thread_set_t *ts, int role)
{
	int ret;

	spin_lock_bh(&ts->ts_state_lock);
	if (ts->create_threads) {
		spin_unlock_bh(&ts->ts_state_lock);
		up(&ts->tx_create_sem);
		goto sleep;
	}

	flush_signals(current);

	if (ts->delay_inactive && (--ts->thread_count == 0)) {
		spin_unlock_bh(&ts->ts_state_lock);
#if 0
		printk(KERN_ERR "Releasing delayed inactive TS %u from TX pre"
			" handler\n", ts->thread_id);
#endif
		iscsi_del_ts_from_active_list(ts);

		if (!iscsi_global->in_shutdown)
			iscsi_deallocate_extra_thread_sets(INITIATOR);

		iscsi_add_ts_to_inactive_list(ts);
		spin_lock_bh(&ts->ts_state_lock);
	}
	if ((ts->status == ISCSI_THREAD_SET_RESET) &&
	    (ts->thread_clear & ISCSI_CLEAR_TX_THREAD))
		up(&ts->tx_restart_sem);

	ts->thread_clear &= ~ISCSI_CLEAR_TX_THREAD;
	spin_unlock_bh(&ts->ts_state_lock);
sleep:
	ret = down_interruptible(&ts->tx_start_sem);
	if (ret != 0)
		return NULL;

	if (iscsi_signal_thread_pre_handler(ts) < 0)
		return NULL;

	if (!ts->conn) {
		printk(KERN_ERR "se_thread_set_t->conn is NULL for "
			" thread_id: %d, going back to sleep\n",
			ts->thread_id);
		goto sleep;
	}

	iscsi_check_to_add_additional_sets(role);
	 
	ts->thread_clear |= ISCSI_CLEAR_TX_THREAD;
	up(&ts->tx_post_start_sem);
	up(&ts->rx_post_start_sem);

	spin_lock_bh(&ts->ts_state_lock);
	ts->status = ISCSI_THREAD_SET_ACTIVE;
#if 0
	printk(KERN_ERR "Activated Thread Set ID: %u\n", ts->thread_id);
#endif
	spin_unlock_bh(&ts->ts_state_lock);
	return ts->conn;
}
