#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/rcupdate.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/nmi.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/export.h>
#include <linux/completion.h>
#include <linux/moduleparam.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/prefetch.h>

#include "rcutree.h"
#include <trace/events/rcu.h>

#include "rcu.h"

static struct lock_class_key rcu_node_class[NUM_RCU_LVLS];

#define RCU_STATE_INITIALIZER(structname) { \
	.level = { &structname##_state.node[0] }, \
	.levelcnt = { \
		NUM_RCU_LVL_0,    \
		NUM_RCU_LVL_1, \
		NUM_RCU_LVL_2, \
		NUM_RCU_LVL_3, \
		NUM_RCU_LVL_4,   \
	}, \
	.signaled = RCU_GP_IDLE, \
	.gpnum = -300, \
	.completed = -300, \
	.onofflock = __RAW_SPIN_LOCK_UNLOCKED(&structname##_state.onofflock), \
	.fqslock = __RAW_SPIN_LOCK_UNLOCKED(&structname##_state.fqslock), \
	.n_force_qs = 0, \
	.n_force_qs_ngp = 0, \
	.name = #structname, \
}

struct rcu_state rcu_sched_state = RCU_STATE_INITIALIZER(rcu_sched);
DEFINE_PER_CPU(struct rcu_data, rcu_sched_data);

struct rcu_state rcu_bh_state = RCU_STATE_INITIALIZER(rcu_bh);
DEFINE_PER_CPU(struct rcu_data, rcu_bh_data);

static struct rcu_state *rcu_state;

int rcu_scheduler_active __read_mostly;
EXPORT_SYMBOL_GPL(rcu_scheduler_active);

static int rcu_scheduler_fully_active __read_mostly;

#ifdef CONFIG_RCU_BOOST

static DEFINE_PER_CPU(struct task_struct *, rcu_cpu_kthread_task);
DEFINE_PER_CPU(unsigned int, rcu_cpu_kthread_status);
DEFINE_PER_CPU(int, rcu_cpu_kthread_cpu);
DEFINE_PER_CPU(unsigned int, rcu_cpu_kthread_loops);
DEFINE_PER_CPU(char, rcu_cpu_has_work);

#endif  

static void rcu_node_kthread_setaffinity(struct rcu_node *rnp, int outgoingcpu);
static void invoke_rcu_core(void);
static void invoke_rcu_callbacks(struct rcu_state *rsp, struct rcu_data *rdp);

unsigned long rcutorture_testseq;
unsigned long rcutorture_vernum;

static int rcu_gp_in_progress(struct rcu_state *rsp)
{
	return ACCESS_ONCE(rsp->completed) != ACCESS_ONCE(rsp->gpnum);
}

void rcu_sched_qs(int cpu)
{
	struct rcu_data *rdp = &per_cpu(rcu_sched_data, cpu);

	rdp->passed_quiesce_gpnum = rdp->gpnum;
	barrier();
	if (rdp->passed_quiesce == 0)
		trace_rcu_grace_period("rcu_sched", rdp->gpnum, "cpuqs");
	rdp->passed_quiesce = 1;
}

void rcu_bh_qs(int cpu)
{
	struct rcu_data *rdp = &per_cpu(rcu_bh_data, cpu);

	rdp->passed_quiesce_gpnum = rdp->gpnum;
	barrier();
	if (rdp->passed_quiesce == 0)
		trace_rcu_grace_period("rcu_bh", rdp->gpnum, "cpuqs");
	rdp->passed_quiesce = 1;
}

void rcu_note_context_switch(int cpu)
{
	trace_rcu_utilization("Start context switch");
	rcu_sched_qs(cpu);
	rcu_preempt_note_context_switch(cpu);
	trace_rcu_utilization("End context switch");
}
EXPORT_SYMBOL_GPL(rcu_note_context_switch);

#ifdef CONFIG_NO_HZ
DEFINE_PER_CPU(struct rcu_dynticks, rcu_dynticks) = {
	.dynticks_nesting = 1,
	.dynticks = ATOMIC_INIT(1),
};
#endif  

static long blimit = 10;	 
static long qhimark = 10000;	 
static long qlowmark = 100;	 

module_param(blimit, long, 0);
module_param(qhimark, long, 0);
module_param(qlowmark, long, 0);

#ifdef MY_ABC_HERE
int rcu_cpu_stall_suppress __read_mostly = 1;
#else
int rcu_cpu_stall_suppress __read_mostly;
#endif
module_param(rcu_cpu_stall_suppress, int, 0644);

static void force_quiescent_state(struct rcu_state *rsp, int relaxed);
static int rcu_pending(int cpu);

long rcu_batches_completed_sched(void)
{
	return rcu_sched_state.completed;
}
EXPORT_SYMBOL_GPL(rcu_batches_completed_sched);

long rcu_batches_completed_bh(void)
{
	return rcu_bh_state.completed;
}
EXPORT_SYMBOL_GPL(rcu_batches_completed_bh);

void rcu_bh_force_quiescent_state(void)
{
	force_quiescent_state(&rcu_bh_state, 0);
}
EXPORT_SYMBOL_GPL(rcu_bh_force_quiescent_state);

void rcutorture_record_test_transition(void)
{
	rcutorture_testseq++;
	rcutorture_vernum = 0;
}
EXPORT_SYMBOL_GPL(rcutorture_record_test_transition);

void rcutorture_record_progress(unsigned long vernum)
{
	rcutorture_vernum++;
}
EXPORT_SYMBOL_GPL(rcutorture_record_progress);

void rcu_sched_force_quiescent_state(void)
{
	force_quiescent_state(&rcu_sched_state, 0);
}
EXPORT_SYMBOL_GPL(rcu_sched_force_quiescent_state);

static int
cpu_has_callbacks_ready_to_invoke(struct rcu_data *rdp)
{
	return &rdp->nxtlist != rdp->nxttail[RCU_DONE_TAIL];
}

static int
cpu_needs_another_gp(struct rcu_state *rsp, struct rcu_data *rdp)
{
	return *rdp->nxttail[RCU_DONE_TAIL +
			     ACCESS_ONCE(rsp->completed) != rdp->completed] &&
	       !rcu_gp_in_progress(rsp);
}

static struct rcu_node *rcu_get_root(struct rcu_state *rsp)
{
	return &rsp->node[0];
}

#ifdef CONFIG_SMP

static int rcu_implicit_offline_qs(struct rcu_data *rdp)
{
	 
	if (cpu_is_offline(rdp->cpu)) {
		trace_rcu_fqs(rdp->rsp->name, rdp->gpnum, rdp->cpu, "ofl");
		rdp->offline_fqs++;
		return 1;
	}

	if (rdp->preemptible)
		return 0;

	if (rdp->cpu != smp_processor_id())
		smp_send_reschedule(rdp->cpu);
	else
		set_need_resched();
	rdp->resched_ipi++;
	return 0;
}

#endif  

#ifdef CONFIG_NO_HZ

void rcu_enter_nohz(void)
{
	unsigned long flags;
	struct rcu_dynticks *rdtp;

	local_irq_save(flags);
	rdtp = &__get_cpu_var(rcu_dynticks);
	if (--rdtp->dynticks_nesting) {
		local_irq_restore(flags);
		return;
	}
	trace_rcu_dyntick("Start");
	 
	smp_mb__before_atomic_inc();   
	atomic_inc(&rdtp->dynticks);
	smp_mb__after_atomic_inc();   
	WARN_ON_ONCE(atomic_read(&rdtp->dynticks) & 0x1);
	local_irq_restore(flags);
}

void rcu_exit_nohz(void)
{
	unsigned long flags;
	struct rcu_dynticks *rdtp;

	local_irq_save(flags);
	rdtp = &__get_cpu_var(rcu_dynticks);
	if (rdtp->dynticks_nesting++) {
		local_irq_restore(flags);
		return;
	}
	smp_mb__before_atomic_inc();   
	atomic_inc(&rdtp->dynticks);
	 
	smp_mb__after_atomic_inc();   
	WARN_ON_ONCE(!(atomic_read(&rdtp->dynticks) & 0x1));
	trace_rcu_dyntick("End");
	local_irq_restore(flags);
}

void rcu_nmi_enter(void)
{
	struct rcu_dynticks *rdtp = &__get_cpu_var(rcu_dynticks);

	if (rdtp->dynticks_nmi_nesting == 0 &&
	    (atomic_read(&rdtp->dynticks) & 0x1))
		return;
	rdtp->dynticks_nmi_nesting++;
	smp_mb__before_atomic_inc();   
	atomic_inc(&rdtp->dynticks);
	 
	smp_mb__after_atomic_inc();   
	WARN_ON_ONCE(!(atomic_read(&rdtp->dynticks) & 0x1));
}

void rcu_nmi_exit(void)
{
	struct rcu_dynticks *rdtp = &__get_cpu_var(rcu_dynticks);

	if (rdtp->dynticks_nmi_nesting == 0 ||
	    --rdtp->dynticks_nmi_nesting != 0)
		return;
	 
	smp_mb__before_atomic_inc();   
	atomic_inc(&rdtp->dynticks);
	smp_mb__after_atomic_inc();   
	WARN_ON_ONCE(atomic_read(&rdtp->dynticks) & 0x1);
}

void rcu_irq_enter(void)
{
	rcu_exit_nohz();
}

void rcu_irq_exit(void)
{
	rcu_enter_nohz();
}

#ifdef CONFIG_SMP

static int dyntick_save_progress_counter(struct rcu_data *rdp)
{
	rdp->dynticks_snap = atomic_add_return(0, &rdp->dynticks->dynticks);
	return 0;
}

static int rcu_implicit_dynticks_qs(struct rcu_data *rdp)
{
	unsigned int curr;
	unsigned int snap;

	curr = (unsigned int)atomic_add_return(0, &rdp->dynticks->dynticks);
	snap = (unsigned int)rdp->dynticks_snap;

	if ((curr & 0x1) == 0 || UINT_CMP_GE(curr, snap + 2)) {
		trace_rcu_fqs(rdp->rsp->name, rdp->gpnum, rdp->cpu, "dti");
		rdp->dynticks_fqs++;
		return 1;
	}

	return rcu_implicit_offline_qs(rdp);
}

#endif  

#else  

#ifdef CONFIG_SMP

static int dyntick_save_progress_counter(struct rcu_data *rdp)
{
	return 0;
}

static int rcu_implicit_dynticks_qs(struct rcu_data *rdp)
{
	return rcu_implicit_offline_qs(rdp);
}

#endif  

#endif  

#ifndef MY_ABC_HERE
int rcu_cpu_stall_suppress __read_mostly;
#endif

static void record_gp_stall_check_time(struct rcu_state *rsp)
{
	rsp->gp_start = jiffies;
	rsp->jiffies_stall = jiffies + RCU_SECONDS_TILL_STALL_CHECK;
}

static void print_other_cpu_stall(struct rcu_state *rsp)
{
	int cpu;
	long delta;
	unsigned long flags;
	int ndetected;
	struct rcu_node *rnp = rcu_get_root(rsp);

	raw_spin_lock_irqsave(&rnp->lock, flags);
	delta = jiffies - rsp->jiffies_stall;
	if (delta < RCU_STALL_RAT_DELAY || !rcu_gp_in_progress(rsp)) {
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
		return;
	}
	rsp->jiffies_stall = jiffies + RCU_SECONDS_TILL_STALL_RECHECK;

	ndetected = rcu_print_task_stall(rnp);
	raw_spin_unlock_irqrestore(&rnp->lock, flags);

	printk(KERN_ERR "INFO: %s detected stalls on CPUs/tasks: {",
	       rsp->name);
	rcu_for_each_leaf_node(rsp, rnp) {
		raw_spin_lock_irqsave(&rnp->lock, flags);
		ndetected += rcu_print_task_stall(rnp);
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
		if (rnp->qsmask == 0)
			continue;
		for (cpu = 0; cpu <= rnp->grphi - rnp->grplo; cpu++)
			if (rnp->qsmask & (1UL << cpu)) {
				printk(" %d", rnp->grplo + cpu);
				ndetected++;
			}
	}
	printk("} (detected by %d, t=%ld jiffies)\n",
	       smp_processor_id(), (long)(jiffies - rsp->gp_start));
	if (ndetected == 0)
		printk(KERN_ERR "INFO: Stall ended before state dump start\n");
	else if (!trigger_all_cpu_backtrace())
		dump_stack();

	rcu_print_detail_task_stall(rsp);

	force_quiescent_state(rsp, 0);   
}

static void print_cpu_stall(struct rcu_state *rsp)
{
	unsigned long flags;
	struct rcu_node *rnp = rcu_get_root(rsp);

	printk(KERN_ERR "INFO: %s detected stall on CPU %d (t=%lu jiffies)\n",
	       rsp->name, smp_processor_id(), jiffies - rsp->gp_start);
	if (!trigger_all_cpu_backtrace())
		dump_stack();

	raw_spin_lock_irqsave(&rnp->lock, flags);
	if (ULONG_CMP_GE(jiffies, rsp->jiffies_stall))
		rsp->jiffies_stall =
			jiffies + RCU_SECONDS_TILL_STALL_RECHECK;
	raw_spin_unlock_irqrestore(&rnp->lock, flags);

	set_need_resched();   
}

static void check_cpu_stall(struct rcu_state *rsp, struct rcu_data *rdp)
{
	unsigned long j;
	unsigned long js;
	struct rcu_node *rnp;

	if (rcu_cpu_stall_suppress)
		return;
	j = ACCESS_ONCE(jiffies);
	js = ACCESS_ONCE(rsp->jiffies_stall);
	rnp = rdp->mynode;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	if (rcu_gp_in_progress(rsp) &&
	    (ACCESS_ONCE(rnp->qsmask) & rdp->grpmask) && ULONG_CMP_GE(j, js)) {
#else
	if ((ACCESS_ONCE(rnp->qsmask) & rdp->grpmask) && ULONG_CMP_GE(j, js)) {
#endif
		 
		print_cpu_stall(rsp);

	} else if (rcu_gp_in_progress(rsp) &&
		   ULONG_CMP_GE(j, js + RCU_STALL_RAT_DELAY)) {

		print_other_cpu_stall(rsp);
	}
}

static int rcu_panic(struct notifier_block *this, unsigned long ev, void *ptr)
{
	rcu_cpu_stall_suppress = 1;
	return NOTIFY_DONE;
}

void rcu_cpu_stall_reset(void)
{
	rcu_sched_state.jiffies_stall = jiffies + ULONG_MAX / 2;
	rcu_bh_state.jiffies_stall = jiffies + ULONG_MAX / 2;
	rcu_preempt_stall_reset();
}

static struct notifier_block rcu_panic_block = {
	.notifier_call = rcu_panic,
};

static void __init check_cpu_stall_init(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &rcu_panic_block);
}

static void __note_new_gpnum(struct rcu_state *rsp, struct rcu_node *rnp, struct rcu_data *rdp)
{
	if (rdp->gpnum != rnp->gpnum) {
		 
		rdp->gpnum = rnp->gpnum;
		trace_rcu_grace_period(rsp->name, rdp->gpnum, "cpustart");
		if (rnp->qsmask & rdp->grpmask) {
			rdp->qs_pending = 1;
			rdp->passed_quiesce = 0;
		} else
			rdp->qs_pending = 0;
	}
}

static void note_new_gpnum(struct rcu_state *rsp, struct rcu_data *rdp)
{
	unsigned long flags;
	struct rcu_node *rnp;

	local_irq_save(flags);
	rnp = rdp->mynode;
	if (rdp->gpnum == ACCESS_ONCE(rnp->gpnum) ||  
	    !raw_spin_trylock(&rnp->lock)) {  
		local_irq_restore(flags);
		return;
	}
	__note_new_gpnum(rsp, rnp, rdp);
	raw_spin_unlock_irqrestore(&rnp->lock, flags);
}

static int
check_for_new_grace_period(struct rcu_state *rsp, struct rcu_data *rdp)
{
	unsigned long flags;
	int ret = 0;

	local_irq_save(flags);
	if (rdp->gpnum != rsp->gpnum) {
		note_new_gpnum(rsp, rdp);
		ret = 1;
	}
	local_irq_restore(flags);
	return ret;
}

static void
__rcu_process_gp_end(struct rcu_state *rsp, struct rcu_node *rnp, struct rcu_data *rdp)
{
	 
	if (rdp->completed != rnp->completed) {

		rdp->nxttail[RCU_DONE_TAIL] = rdp->nxttail[RCU_WAIT_TAIL];
		rdp->nxttail[RCU_WAIT_TAIL] = rdp->nxttail[RCU_NEXT_READY_TAIL];
		rdp->nxttail[RCU_NEXT_READY_TAIL] = rdp->nxttail[RCU_NEXT_TAIL];

		rdp->completed = rnp->completed;
		trace_rcu_grace_period(rsp->name, rdp->gpnum, "cpuend");

		if (ULONG_CMP_LT(rdp->gpnum, rdp->completed))
			rdp->gpnum = rdp->completed;

		if ((rnp->qsmask & rdp->grpmask) == 0)
			rdp->qs_pending = 0;
	}
}

static void
rcu_process_gp_end(struct rcu_state *rsp, struct rcu_data *rdp)
{
	unsigned long flags;
	struct rcu_node *rnp;

	local_irq_save(flags);
	rnp = rdp->mynode;
	if (rdp->completed == ACCESS_ONCE(rnp->completed) ||  
	    !raw_spin_trylock(&rnp->lock)) {  
		local_irq_restore(flags);
		return;
	}
	__rcu_process_gp_end(rsp, rnp, rdp);
	raw_spin_unlock_irqrestore(&rnp->lock, flags);
}

static void
rcu_start_gp_per_cpu(struct rcu_state *rsp, struct rcu_node *rnp, struct rcu_data *rdp)
{
	 
	__rcu_process_gp_end(rsp, rnp, rdp);

	rdp->nxttail[RCU_NEXT_READY_TAIL] = rdp->nxttail[RCU_NEXT_TAIL];
	rdp->nxttail[RCU_WAIT_TAIL] = rdp->nxttail[RCU_NEXT_TAIL];

	__note_new_gpnum(rsp, rnp, rdp);
}

static void
rcu_start_gp(struct rcu_state *rsp, unsigned long flags)
	__releases(rcu_get_root(rsp)->lock)
{
	struct rcu_data *rdp = this_cpu_ptr(rsp->rda);
	struct rcu_node *rnp = rcu_get_root(rsp);

	if (!rcu_scheduler_fully_active ||
	    !cpu_needs_another_gp(rsp, rdp)) {
		 
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
		return;
	}

	if (rsp->fqs_active) {
		 
		rsp->fqs_need_gp = 1;
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
		return;
	}

	rsp->gpnum++;
	trace_rcu_grace_period(rsp->name, rsp->gpnum, "start");
	WARN_ON_ONCE(rsp->signaled == RCU_GP_INIT);
	rsp->signaled = RCU_GP_INIT;  
	rsp->jiffies_force_qs = jiffies + RCU_JIFFIES_TILL_FORCE_QS;
	record_gp_stall_check_time(rsp);

	if (NUM_RCU_NODES == 1) {
		rcu_preempt_check_blocked_tasks(rnp);
		rnp->qsmask = rnp->qsmaskinit;
		rnp->gpnum = rsp->gpnum;
		rnp->completed = rsp->completed;
		rsp->signaled = RCU_SIGNAL_INIT;  
		rcu_start_gp_per_cpu(rsp, rnp, rdp);
		rcu_preempt_boost_start_gp(rnp);
		trace_rcu_grace_period_init(rsp->name, rnp->gpnum,
					    rnp->level, rnp->grplo,
					    rnp->grphi, rnp->qsmask);
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
		return;
	}

	raw_spin_unlock(&rnp->lock);   

	raw_spin_lock(&rsp->onofflock);   

	rcu_for_each_node_breadth_first(rsp, rnp) {
		raw_spin_lock(&rnp->lock);	 
		rcu_preempt_check_blocked_tasks(rnp);
		rnp->qsmask = rnp->qsmaskinit;
		rnp->gpnum = rsp->gpnum;
		rnp->completed = rsp->completed;
		if (rnp == rdp->mynode)
			rcu_start_gp_per_cpu(rsp, rnp, rdp);
		rcu_preempt_boost_start_gp(rnp);
		trace_rcu_grace_period_init(rsp->name, rnp->gpnum,
					    rnp->level, rnp->grplo,
					    rnp->grphi, rnp->qsmask);
		raw_spin_unlock(&rnp->lock);	 
	}

	rnp = rcu_get_root(rsp);
	raw_spin_lock(&rnp->lock);		 
	rsp->signaled = RCU_SIGNAL_INIT;  
	raw_spin_unlock(&rnp->lock);		 
	raw_spin_unlock_irqrestore(&rsp->onofflock, flags);
}

static void rcu_report_qs_rsp(struct rcu_state *rsp, unsigned long flags)
	__releases(rcu_get_root(rsp)->lock)
{
	unsigned long gp_duration;
	struct rcu_node *rnp = rcu_get_root(rsp);
	struct rcu_data *rdp = this_cpu_ptr(rsp->rda);

	WARN_ON_ONCE(!rcu_gp_in_progress(rsp));

	smp_mb();  
	gp_duration = jiffies - rsp->gp_start;
	if (gp_duration > rsp->gp_max)
		rsp->gp_max = gp_duration;

	if (*rdp->nxttail[RCU_WAIT_TAIL] == NULL) {
		raw_spin_unlock(&rnp->lock);	  

		rcu_for_each_node_breadth_first(rsp, rnp) {
			raw_spin_lock(&rnp->lock);  
			rnp->completed = rsp->gpnum;
			raw_spin_unlock(&rnp->lock);  
		}
		rnp = rcu_get_root(rsp);
		raw_spin_lock(&rnp->lock);  
	}

	rsp->completed = rsp->gpnum;   
	trace_rcu_grace_period(rsp->name, rsp->completed, "end");
	rsp->signaled = RCU_GP_IDLE;
	rcu_start_gp(rsp, flags);   
}

static void
rcu_report_qs_rnp(unsigned long mask, struct rcu_state *rsp,
		  struct rcu_node *rnp, unsigned long flags)
	__releases(rnp->lock)
{
	struct rcu_node *rnp_c;

	for (;;) {
		if (!(rnp->qsmask & mask)) {

			raw_spin_unlock_irqrestore(&rnp->lock, flags);
			return;
		}
		rnp->qsmask &= ~mask;
		trace_rcu_quiescent_state_report(rsp->name, rnp->gpnum,
						 mask, rnp->qsmask, rnp->level,
						 rnp->grplo, rnp->grphi,
						 !!rnp->gp_tasks);
		if (rnp->qsmask != 0 || rcu_preempt_blocked_readers_cgp(rnp)) {

			raw_spin_unlock_irqrestore(&rnp->lock, flags);
			return;
		}
		mask = rnp->grpmask;
		if (rnp->parent == NULL) {

			break;
		}
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
		rnp_c = rnp;
		rnp = rnp->parent;
		raw_spin_lock_irqsave(&rnp->lock, flags);
		WARN_ON_ONCE(rnp_c->qsmask);
	}

	rcu_report_qs_rsp(rsp, flags);  
}

static void
rcu_report_qs_rdp(int cpu, struct rcu_state *rsp, struct rcu_data *rdp, long lastgp)
{
	unsigned long flags;
	unsigned long mask;
	struct rcu_node *rnp;

	rnp = rdp->mynode;
	raw_spin_lock_irqsave(&rnp->lock, flags);
	if (lastgp != rnp->gpnum || rnp->completed == rnp->gpnum) {

		rdp->passed_quiesce = 0;	 
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
		return;
	}
	mask = rdp->grpmask;
	if ((rnp->qsmask & mask) == 0) {
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
	} else {
		rdp->qs_pending = 0;

		rdp->nxttail[RCU_NEXT_READY_TAIL] = rdp->nxttail[RCU_NEXT_TAIL];

		rcu_report_qs_rnp(mask, rsp, rnp, flags);  
	}
}

static void
rcu_check_quiescent_state(struct rcu_state *rsp, struct rcu_data *rdp)
{
	 
	if (check_for_new_grace_period(rsp, rdp))
		return;

	if (!rdp->qs_pending)
		return;

	if (!rdp->passed_quiesce)
		return;

	rcu_report_qs_rdp(rdp->cpu, rsp, rdp, rdp->passed_quiesce_gpnum);
}

#ifdef CONFIG_HOTPLUG_CPU

static void rcu_send_cbs_to_online(struct rcu_state *rsp)
{
	int i;
	 
	int receive_cpu = cpumask_any(cpu_online_mask);
	struct rcu_data *rdp = this_cpu_ptr(rsp->rda);
	struct rcu_data *receive_rdp = per_cpu_ptr(rsp->rda, receive_cpu);

	if (rdp->nxtlist == NULL)
		return;   

	*receive_rdp->nxttail[RCU_NEXT_TAIL] = rdp->nxtlist;
	receive_rdp->nxttail[RCU_NEXT_TAIL] = rdp->nxttail[RCU_NEXT_TAIL];
	receive_rdp->qlen += rdp->qlen;
	receive_rdp->n_cbs_adopted += rdp->qlen;
	rdp->n_cbs_orphaned += rdp->qlen;

	rdp->nxtlist = NULL;
	for (i = 0; i < RCU_NEXT_SIZE; i++)
		rdp->nxttail[i] = &rdp->nxtlist;
	rdp->qlen = 0;
}

static void __rcu_offline_cpu(int cpu, struct rcu_state *rsp)
{
	unsigned long flags;
	unsigned long mask;
	int need_report = 0;
	struct rcu_data *rdp = per_cpu_ptr(rsp->rda, cpu);
	struct rcu_node *rnp;

	rcu_stop_cpu_kthread(cpu);

	raw_spin_lock_irqsave(&rsp->onofflock, flags);

	rnp = rdp->mynode;	 
	mask = rdp->grpmask;	 
	do {
		raw_spin_lock(&rnp->lock);	 
		rnp->qsmaskinit &= ~mask;
		if (rnp->qsmaskinit != 0) {
			if (rnp != rdp->mynode)
				raw_spin_unlock(&rnp->lock);  
			else
				trace_rcu_grace_period(rsp->name,
						       rnp->gpnum + 1 -
						       !!(rnp->qsmask & mask),
						       "cpuofl");
			break;
		}
		if (rnp == rdp->mynode) {
			trace_rcu_grace_period(rsp->name,
					       rnp->gpnum + 1 -
					       !!(rnp->qsmask & mask),
					       "cpuofl");
			need_report = rcu_preempt_offline_tasks(rsp, rnp, rdp);
		} else
			raw_spin_unlock(&rnp->lock);  
		mask = rnp->grpmask;
		rnp = rnp->parent;
	} while (rnp != NULL);

	raw_spin_unlock(&rsp->onofflock);  
	rnp = rdp->mynode;
	if (need_report & RCU_OFL_TASKS_NORM_GP)
		rcu_report_unblock_qs_rnp(rnp, flags);
	else
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
	if (need_report & RCU_OFL_TASKS_EXP_GP)
		rcu_report_exp_rnp(rsp, rnp);
	rcu_node_kthread_setaffinity(rnp, -1);
}

static void rcu_offline_cpu(int cpu)
{
	__rcu_offline_cpu(cpu, &rcu_sched_state);
	__rcu_offline_cpu(cpu, &rcu_bh_state);
	rcu_preempt_offline_cpu(cpu);
}

#else  

static void rcu_send_cbs_to_online(struct rcu_state *rsp)
{
}

static void rcu_offline_cpu(int cpu)
{
}

#endif  

static void rcu_do_batch(struct rcu_state *rsp, struct rcu_data *rdp)
{
	unsigned long flags;
	struct rcu_head *next, *list, **tail;
	long bl, count;

	if (!cpu_has_callbacks_ready_to_invoke(rdp)) {
		trace_rcu_batch_start(rsp->name, 0, 0);
		trace_rcu_batch_end(rsp->name, 0);
		return;
	}

	local_irq_save(flags);
	bl = rdp->blimit;
	trace_rcu_batch_start(rsp->name, rdp->qlen, bl);
	list = rdp->nxtlist;
	rdp->nxtlist = *rdp->nxttail[RCU_DONE_TAIL];
	*rdp->nxttail[RCU_DONE_TAIL] = NULL;
	tail = rdp->nxttail[RCU_DONE_TAIL];
	for (count = RCU_NEXT_SIZE - 1; count >= 0; count--)
		if (rdp->nxttail[count] == rdp->nxttail[RCU_DONE_TAIL])
			rdp->nxttail[count] = &rdp->nxtlist;
	local_irq_restore(flags);

	count = 0;
	while (list) {
		next = list->next;
		prefetch(next);
		debug_rcu_head_unqueue(list);
		__rcu_reclaim(rsp->name, list);
		list = next;
		if (++count >= bl)
			break;
	}

	local_irq_save(flags);
	trace_rcu_batch_end(rsp->name, count);

	rdp->qlen -= count;
	rdp->n_cbs_invoked += count;
	if (list != NULL) {
		*tail = rdp->nxtlist;
		rdp->nxtlist = list;
		for (count = 0; count < RCU_NEXT_SIZE; count++)
			if (&rdp->nxtlist == rdp->nxttail[count])
				rdp->nxttail[count] = tail;
			else
				break;
	}

	if (rdp->blimit == LONG_MAX && rdp->qlen <= qlowmark)
		rdp->blimit = blimit;

	if (rdp->qlen == 0 && rdp->qlen_last_fqs_check != 0) {
		rdp->qlen_last_fqs_check = 0;
		rdp->n_force_qs_snap = rsp->n_force_qs;
	} else if (rdp->qlen < rdp->qlen_last_fqs_check - qhimark)
		rdp->qlen_last_fqs_check = rdp->qlen;

	local_irq_restore(flags);

	if (cpu_has_callbacks_ready_to_invoke(rdp))
		invoke_rcu_core();
}

void rcu_check_callbacks(int cpu, int user)
{
	trace_rcu_utilization("Start scheduler-tick");
	if (user ||
	    (idle_cpu(cpu) && rcu_scheduler_active &&
	     !in_softirq() && hardirq_count() <= (1 << HARDIRQ_SHIFT))) {

		rcu_sched_qs(cpu);
		rcu_bh_qs(cpu);

	} else if (!in_softirq()) {

		rcu_bh_qs(cpu);
	}
	rcu_preempt_check_callbacks(cpu);
	if (rcu_pending(cpu))
		invoke_rcu_core();
	trace_rcu_utilization("End scheduler-tick");
}

#ifdef CONFIG_SMP

static void force_qs_rnp(struct rcu_state *rsp, int (*f)(struct rcu_data *))
{
	unsigned long bit;
	int cpu;
	unsigned long flags;
	unsigned long mask;
	struct rcu_node *rnp;

	rcu_for_each_leaf_node(rsp, rnp) {
		mask = 0;
		raw_spin_lock_irqsave(&rnp->lock, flags);
		if (!rcu_gp_in_progress(rsp)) {
			raw_spin_unlock_irqrestore(&rnp->lock, flags);
			return;
		}
		if (rnp->qsmask == 0) {
			rcu_initiate_boost(rnp, flags);  
			continue;
		}
		cpu = rnp->grplo;
		bit = 1;
		for (; cpu <= rnp->grphi; cpu++, bit <<= 1) {
			if ((rnp->qsmask & bit) != 0 &&
			    f(per_cpu_ptr(rsp->rda, cpu)))
				mask |= bit;
		}
		if (mask != 0) {

			rcu_report_qs_rnp(mask, rsp, rnp, flags);
			continue;
		}
		raw_spin_unlock_irqrestore(&rnp->lock, flags);
	}
	rnp = rcu_get_root(rsp);
	if (rnp->qsmask == 0) {
		raw_spin_lock_irqsave(&rnp->lock, flags);
		rcu_initiate_boost(rnp, flags);  
	}
}

static void force_quiescent_state(struct rcu_state *rsp, int relaxed)
{
	unsigned long flags;
	struct rcu_node *rnp = rcu_get_root(rsp);

	trace_rcu_utilization("Start fqs");
	if (!rcu_gp_in_progress(rsp)) {
		trace_rcu_utilization("End fqs");
		return;   
	}
	if (!raw_spin_trylock_irqsave(&rsp->fqslock, flags)) {
		rsp->n_force_qs_lh++;  
		trace_rcu_utilization("End fqs");
		return;	 
	}
	if (relaxed && ULONG_CMP_GE(rsp->jiffies_force_qs, jiffies))
		goto unlock_fqs_ret;  
	rsp->n_force_qs++;
	raw_spin_lock(&rnp->lock);   
	rsp->jiffies_force_qs = jiffies + RCU_JIFFIES_TILL_FORCE_QS;
	if(!rcu_gp_in_progress(rsp)) {
		rsp->n_force_qs_ngp++;
		raw_spin_unlock(&rnp->lock);   
		goto unlock_fqs_ret;   
	}
	rsp->fqs_active = 1;
	switch (rsp->signaled) {
	case RCU_GP_IDLE:
	case RCU_GP_INIT:

		break;  

	case RCU_SAVE_DYNTICK:
		if (RCU_SIGNAL_INIT != RCU_SAVE_DYNTICK)
			break;  

		raw_spin_unlock(&rnp->lock);   

		force_qs_rnp(rsp, dyntick_save_progress_counter);
		raw_spin_lock(&rnp->lock);   
		if (rcu_gp_in_progress(rsp))
			rsp->signaled = RCU_FORCE_QS;
		break;

	case RCU_FORCE_QS:

		raw_spin_unlock(&rnp->lock);   
		force_qs_rnp(rsp, rcu_implicit_dynticks_qs);

		raw_spin_lock(&rnp->lock);   
		break;
	}
	rsp->fqs_active = 0;
	if (rsp->fqs_need_gp) {
		raw_spin_unlock(&rsp->fqslock);  
		rsp->fqs_need_gp = 0;
		rcu_start_gp(rsp, flags);  
		trace_rcu_utilization("End fqs");
		return;
	}
	raw_spin_unlock(&rnp->lock);   
unlock_fqs_ret:
	raw_spin_unlock_irqrestore(&rsp->fqslock, flags);
	trace_rcu_utilization("End fqs");
}

#else  

static void force_quiescent_state(struct rcu_state *rsp, int relaxed)
{
	set_need_resched();
}

#endif  

static void
__rcu_process_callbacks(struct rcu_state *rsp, struct rcu_data *rdp)
{
	unsigned long flags;

	WARN_ON_ONCE(rdp->beenonline == 0);

	if (ULONG_CMP_LT(ACCESS_ONCE(rsp->jiffies_force_qs), jiffies))
		force_quiescent_state(rsp, 1);

	rcu_process_gp_end(rsp, rdp);

	rcu_check_quiescent_state(rsp, rdp);

	if (cpu_needs_another_gp(rsp, rdp)) {
		raw_spin_lock_irqsave(&rcu_get_root(rsp)->lock, flags);
		rcu_start_gp(rsp, flags);   
	}

	if (cpu_has_callbacks_ready_to_invoke(rdp))
		invoke_rcu_callbacks(rsp, rdp);
}

static void rcu_process_callbacks(struct softirq_action *unused)
{
	trace_rcu_utilization("Start RCU core");
	__rcu_process_callbacks(&rcu_sched_state,
				&__get_cpu_var(rcu_sched_data));
	__rcu_process_callbacks(&rcu_bh_state, &__get_cpu_var(rcu_bh_data));
	rcu_preempt_process_callbacks();
	trace_rcu_utilization("End RCU core");
}

static void invoke_rcu_callbacks(struct rcu_state *rsp, struct rcu_data *rdp)
{
	if (unlikely(!ACCESS_ONCE(rcu_scheduler_fully_active)))
		return;
	if (likely(!rsp->boost)) {
		rcu_do_batch(rsp, rdp);
		return;
	}
	invoke_rcu_callbacks_kthread();
}

static void invoke_rcu_core(void)
{
	raise_softirq(RCU_SOFTIRQ);
}

static void
__call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *rcu),
	   struct rcu_state *rsp)
{
	unsigned long flags;
	struct rcu_data *rdp;

	debug_rcu_head_queue(head);
	head->func = func;
	head->next = NULL;

	smp_mb();  

	local_irq_save(flags);
	rdp = this_cpu_ptr(rsp->rda);

	*rdp->nxttail[RCU_NEXT_TAIL] = head;
	rdp->nxttail[RCU_NEXT_TAIL] = &head->next;
	rdp->qlen++;

	if (__is_kfree_rcu_offset((unsigned long)func))
		trace_rcu_kfree_callback(rsp->name, head, (unsigned long)func,
					 rdp->qlen);
	else
		trace_rcu_callback(rsp->name, head, rdp->qlen);

	if (irqs_disabled_flags(flags)) {
		local_irq_restore(flags);
		return;
	}

	if (unlikely(rdp->qlen > rdp->qlen_last_fqs_check + qhimark)) {

		rcu_process_gp_end(rsp, rdp);
		check_for_new_grace_period(rsp, rdp);

		if (!rcu_gp_in_progress(rsp)) {
			unsigned long nestflag;
			struct rcu_node *rnp_root = rcu_get_root(rsp);

			raw_spin_lock_irqsave(&rnp_root->lock, nestflag);
			rcu_start_gp(rsp, nestflag);   
		} else {
			 
			rdp->blimit = LONG_MAX;
			if (rsp->n_force_qs == rdp->n_force_qs_snap &&
			    *rdp->nxttail[RCU_DONE_TAIL] != head)
				force_quiescent_state(rsp, 0);
			rdp->n_force_qs_snap = rsp->n_force_qs;
			rdp->qlen_last_fqs_check = rdp->qlen;
		}
	} else if (ULONG_CMP_LT(ACCESS_ONCE(rsp->jiffies_force_qs), jiffies))
		force_quiescent_state(rsp, 1);
	local_irq_restore(flags);
}

void call_rcu_sched(struct rcu_head *head, void (*func)(struct rcu_head *rcu))
{
	__call_rcu(head, func, &rcu_sched_state);
}
EXPORT_SYMBOL_GPL(call_rcu_sched);

void call_rcu_bh(struct rcu_head *head, void (*func)(struct rcu_head *rcu))
{
	__call_rcu(head, func, &rcu_bh_state);
}
EXPORT_SYMBOL_GPL(call_rcu_bh);

void synchronize_sched(void)
{
	if (rcu_blocking_is_gp())
		return;
	wait_rcu_gp(call_rcu_sched);
}
EXPORT_SYMBOL_GPL(synchronize_sched);

void synchronize_rcu_bh(void)
{
	if (rcu_blocking_is_gp())
		return;
	wait_rcu_gp(call_rcu_bh);
}
EXPORT_SYMBOL_GPL(synchronize_rcu_bh);

static int __rcu_pending(struct rcu_state *rsp, struct rcu_data *rdp)
{
	struct rcu_node *rnp = rdp->mynode;

	rdp->n_rcu_pending++;

	check_cpu_stall(rsp, rdp);

	if (rcu_scheduler_fully_active &&
	    rdp->qs_pending && !rdp->passed_quiesce) {

		rdp->n_rp_qs_pending++;
		if (!rdp->preemptible &&
		    ULONG_CMP_LT(ACCESS_ONCE(rsp->jiffies_force_qs) - 1,
				 jiffies))
			set_need_resched();
	} else if (rdp->qs_pending && rdp->passed_quiesce) {
		rdp->n_rp_report_qs++;
		return 1;
	}

	if (cpu_has_callbacks_ready_to_invoke(rdp)) {
		rdp->n_rp_cb_ready++;
		return 1;
	}

	if (cpu_needs_another_gp(rsp, rdp)) {
		rdp->n_rp_cpu_needs_gp++;
		return 1;
	}

	if (ACCESS_ONCE(rnp->completed) != rdp->completed) {  
		rdp->n_rp_gp_completed++;
		return 1;
	}

	if (ACCESS_ONCE(rnp->gpnum) != rdp->gpnum) {  
		rdp->n_rp_gp_started++;
		return 1;
	}

	if (rcu_gp_in_progress(rsp) &&
	    ULONG_CMP_LT(ACCESS_ONCE(rsp->jiffies_force_qs), jiffies)) {
		rdp->n_rp_need_fqs++;
		return 1;
	}

	rdp->n_rp_need_nothing++;
	return 0;
}

static int rcu_pending(int cpu)
{
	return __rcu_pending(&rcu_sched_state, &per_cpu(rcu_sched_data, cpu)) ||
	       __rcu_pending(&rcu_bh_state, &per_cpu(rcu_bh_data, cpu)) ||
	       rcu_preempt_pending(cpu);
}

static int rcu_needs_cpu_quick_check(int cpu)
{
	 
	return per_cpu(rcu_sched_data, cpu).nxtlist ||
	       per_cpu(rcu_bh_data, cpu).nxtlist ||
	       rcu_preempt_needs_cpu(cpu);
}

static DEFINE_PER_CPU(struct rcu_head, rcu_barrier_head) = {NULL};
static atomic_t rcu_barrier_cpu_count;
static DEFINE_MUTEX(rcu_barrier_mutex);
static struct completion rcu_barrier_completion;

static void rcu_barrier_callback(struct rcu_head *notused)
{
	if (atomic_dec_and_test(&rcu_barrier_cpu_count))
		complete(&rcu_barrier_completion);
}

static void rcu_barrier_func(void *type)
{
	int cpu = smp_processor_id();
	struct rcu_head *head = &per_cpu(rcu_barrier_head, cpu);
	void (*call_rcu_func)(struct rcu_head *head,
			      void (*func)(struct rcu_head *head));

	atomic_inc(&rcu_barrier_cpu_count);
	call_rcu_func = type;
	call_rcu_func(head, rcu_barrier_callback);
}

static void _rcu_barrier(struct rcu_state *rsp,
			 void (*call_rcu_func)(struct rcu_head *head,
					       void (*func)(struct rcu_head *head)))
{
	BUG_ON(in_interrupt());
	 
	mutex_lock(&rcu_barrier_mutex);
	init_completion(&rcu_barrier_completion);
	 
	atomic_set(&rcu_barrier_cpu_count, 1);
	on_each_cpu(rcu_barrier_func, (void *)call_rcu_func, 1);
	if (atomic_dec_and_test(&rcu_barrier_cpu_count))
		complete(&rcu_barrier_completion);
	wait_for_completion(&rcu_barrier_completion);
	mutex_unlock(&rcu_barrier_mutex);
}

void rcu_barrier_bh(void)
{
	_rcu_barrier(&rcu_bh_state, call_rcu_bh);
}
EXPORT_SYMBOL_GPL(rcu_barrier_bh);

void rcu_barrier_sched(void)
{
	_rcu_barrier(&rcu_sched_state, call_rcu_sched);
}
EXPORT_SYMBOL_GPL(rcu_barrier_sched);

static void __init
rcu_boot_init_percpu_data(int cpu, struct rcu_state *rsp)
{
	unsigned long flags;
	int i;
	struct rcu_data *rdp = per_cpu_ptr(rsp->rda, cpu);
	struct rcu_node *rnp = rcu_get_root(rsp);

	raw_spin_lock_irqsave(&rnp->lock, flags);
	rdp->grpmask = 1UL << (cpu - rdp->mynode->grplo);
	rdp->nxtlist = NULL;
	for (i = 0; i < RCU_NEXT_SIZE; i++)
		rdp->nxttail[i] = &rdp->nxtlist;
	rdp->qlen = 0;
#ifdef CONFIG_NO_HZ
	rdp->dynticks = &per_cpu(rcu_dynticks, cpu);
#endif  
	rdp->cpu = cpu;
	rdp->rsp = rsp;
	raw_spin_unlock_irqrestore(&rnp->lock, flags);
}

static void __cpuinit
rcu_init_percpu_data(int cpu, struct rcu_state *rsp, int preemptible)
{
	unsigned long flags;
	unsigned long mask;
	struct rcu_data *rdp = per_cpu_ptr(rsp->rda, cpu);
	struct rcu_node *rnp = rcu_get_root(rsp);

	raw_spin_lock_irqsave(&rnp->lock, flags);
	rdp->beenonline = 1;	  
	rdp->preemptible = preemptible;
	rdp->qlen_last_fqs_check = 0;
	rdp->n_force_qs_snap = rsp->n_force_qs;
	rdp->blimit = blimit;
	raw_spin_unlock(&rnp->lock);		 

	raw_spin_lock(&rsp->onofflock);		 

	rnp = rdp->mynode;
	mask = rdp->grpmask;
	do {
		 
		raw_spin_lock(&rnp->lock);	 
		rnp->qsmaskinit |= mask;
		mask = rnp->grpmask;
		if (rnp == rdp->mynode) {
			 
			rdp->gpnum = rnp->completed;
			rdp->completed = rnp->completed;
			rdp->passed_quiesce = 0;
			rdp->qs_pending = 0;
			rdp->passed_quiesce_gpnum = rnp->gpnum - 1;
			trace_rcu_grace_period(rsp->name, rdp->gpnum, "cpuonl");
		}
		raw_spin_unlock(&rnp->lock);  
		rnp = rnp->parent;
	} while (rnp != NULL && !(rnp->qsmaskinit & mask));

	raw_spin_unlock_irqrestore(&rsp->onofflock, flags);
}

static void __cpuinit rcu_prepare_cpu(int cpu)
{
	rcu_init_percpu_data(cpu, &rcu_sched_state, 0);
	rcu_init_percpu_data(cpu, &rcu_bh_state, 0);
	rcu_preempt_init_percpu_data(cpu);
}

static int __cpuinit rcu_cpu_notify(struct notifier_block *self,
				    unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	struct rcu_data *rdp = per_cpu_ptr(rcu_state->rda, cpu);
	struct rcu_node *rnp = rdp->mynode;

	trace_rcu_utilization("Start CPU hotplug");
	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		rcu_prepare_cpu(cpu);
		rcu_prepare_kthreads(cpu);
		break;
	case CPU_ONLINE:
	case CPU_DOWN_FAILED:
		rcu_node_kthread_setaffinity(rnp, -1);
		rcu_cpu_kthread_setrt(cpu, 1);
		break;
	case CPU_DOWN_PREPARE:
		rcu_node_kthread_setaffinity(rnp, cpu);
		rcu_cpu_kthread_setrt(cpu, 0);
		break;
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		 
		rcu_send_cbs_to_online(&rcu_bh_state);
		rcu_send_cbs_to_online(&rcu_sched_state);
		rcu_preempt_send_cbs_to_online();
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		rcu_offline_cpu(cpu);
		break;
	default:
		break;
	}
	trace_rcu_utilization("End CPU hotplug");
	return NOTIFY_OK;
}

void rcu_scheduler_starting(void)
{
	WARN_ON(num_online_cpus() != 1);
	WARN_ON(nr_context_switches() > 0);
	rcu_scheduler_active = 1;
}

#ifdef CONFIG_RCU_FANOUT_EXACT
static void __init rcu_init_levelspread(struct rcu_state *rsp)
{
	int i;

	for (i = NUM_RCU_LVLS - 1; i > 0; i--)
		rsp->levelspread[i] = CONFIG_RCU_FANOUT;
	rsp->levelspread[0] = RCU_FANOUT_LEAF;
}
#else  
static void __init rcu_init_levelspread(struct rcu_state *rsp)
{
	int ccur;
	int cprv;
	int i;

	cprv = NR_CPUS;
	for (i = NUM_RCU_LVLS - 1; i >= 0; i--) {
		ccur = rsp->levelcnt[i];
		rsp->levelspread[i] = (cprv + ccur - 1) / ccur;
		cprv = ccur;
	}
}
#endif  

static void __init rcu_init_one(struct rcu_state *rsp,
		struct rcu_data __percpu *rda)
{
	static char *buf[] = { "rcu_node_level_0",
			       "rcu_node_level_1",
			       "rcu_node_level_2",
			       "rcu_node_level_3" };   
	int cpustride = 1;
	int i;
	int j;
	struct rcu_node *rnp;

	BUILD_BUG_ON(MAX_RCU_LVLS > ARRAY_SIZE(buf));   

	for (i = 1; i < NUM_RCU_LVLS; i++)
		rsp->level[i] = rsp->level[i - 1] + rsp->levelcnt[i - 1];
	rcu_init_levelspread(rsp);

	for (i = NUM_RCU_LVLS - 1; i >= 0; i--) {
		cpustride *= rsp->levelspread[i];
		rnp = rsp->level[i];
		for (j = 0; j < rsp->levelcnt[i]; j++, rnp++) {
			raw_spin_lock_init(&rnp->lock);
			lockdep_set_class_and_name(&rnp->lock,
						   &rcu_node_class[i], buf[i]);
			rnp->gpnum = 0;
			rnp->qsmask = 0;
			rnp->qsmaskinit = 0;
			rnp->grplo = j * cpustride;
			rnp->grphi = (j + 1) * cpustride - 1;
			if (rnp->grphi >= NR_CPUS)
				rnp->grphi = NR_CPUS - 1;
			if (i == 0) {
				rnp->grpnum = 0;
				rnp->grpmask = 0;
				rnp->parent = NULL;
			} else {
				rnp->grpnum = j % rsp->levelspread[i - 1];
				rnp->grpmask = 1UL << rnp->grpnum;
				rnp->parent = rsp->level[i - 1] +
					      j / rsp->levelspread[i - 1];
			}
			rnp->level = i;
			INIT_LIST_HEAD(&rnp->blkd_tasks);
		}
	}

	rsp->rda = rda;
	rnp = rsp->level[NUM_RCU_LVLS - 1];
	for_each_possible_cpu(i) {
		while (i > rnp->grphi)
			rnp++;
		per_cpu_ptr(rsp->rda, i)->mynode = rnp;
		rcu_boot_init_percpu_data(i, rsp);
	}
}

void __init rcu_init(void)
{
	int cpu;

	rcu_bootup_announce();
	rcu_init_one(&rcu_sched_state, &rcu_sched_data);
	rcu_init_one(&rcu_bh_state, &rcu_bh_data);
	__rcu_init_preempt();
	 open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);

	cpu_notifier(rcu_cpu_notify, 0);
	for_each_online_cpu(cpu)
		rcu_cpu_notify(NULL, CPU_UP_PREPARE, (void *)(long)cpu);
	check_cpu_stall_init();
}

#include "rcutree_plugin.h"
