 
#ifdef DEBUG_HARDER
#define pr_hard(args...)	printk(KERN_DEBUG args)
#define pr_hardcont(args...)	printk(KERN_CONT args)
#else
#define pr_hard(args...)	do { } while(0)
#define pr_hardcont(args...)	do { } while(0)
#endif

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/bootmem.h>
#include <linux/notifier.h>
#include <linux/cpu.h>

#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

static unsigned int first_context, last_context;
static unsigned int next_context, nr_free_contexts;
static unsigned long *context_map;
static unsigned long *stale_map[NR_CPUS];
static struct mm_struct **context_mm;
static DEFINE_SPINLOCK(context_lock);

#define CTX_MAP_SIZE	\
	(sizeof(unsigned long) * (last_context / BITS_PER_LONG + 1))

#ifdef CONFIG_SMP
static unsigned int steal_context_smp(unsigned int id)
{
	struct mm_struct *mm;
	unsigned int cpu, max, i;

	max = last_context - first_context;

	while (max--) {
		 
		mm = context_mm[id];

		if (mm->context.active) {
			id++;
			if (id > last_context)
				id = first_context;
			continue;
		}
		pr_hardcont(" | steal %d from 0x%p", id, mm);

		mm->context.id = MMU_NO_CONTEXT;

		for_each_cpu(cpu, mm_cpumask(mm)) {
			for (i = cpu_first_thread_in_core(cpu);
			     i <= cpu_last_thread_in_core(cpu); i++)
				__set_bit(id, stale_map[i]);
			cpu = i - 1;
		}
		return id;
	}

	spin_unlock(&context_lock);
	cpu_relax();
	spin_lock(&context_lock);

	return MMU_NO_CONTEXT;
}
#endif   

static unsigned int steal_context_up(unsigned int id)
{
	struct mm_struct *mm;
	int cpu = smp_processor_id();

	mm = context_mm[id];

	pr_hardcont(" | steal %d from 0x%p", id, mm);

	local_flush_tlb_mm(mm);

	mm->context.id = MMU_NO_CONTEXT;

	__clear_bit(id, stale_map[cpu]);

	return id;
}

#ifdef DEBUG_MAP_CONSISTENCY
static void context_check_map(void)
{
	unsigned int id, nrf, nact;

	nrf = nact = 0;
	for (id = first_context; id <= last_context; id++) {
		int used = test_bit(id, context_map);
		if (!used)
			nrf++;
		if (used != (context_mm[id] != NULL))
			pr_err("MMU: Context %d is %s and MM is %p !\n",
			       id, used ? "used" : "free", context_mm[id]);
		if (context_mm[id] != NULL)
			nact += context_mm[id]->context.active;
	}
	if (nrf != nr_free_contexts) {
		pr_err("MMU: Free context count out of sync ! (%d vs %d)\n",
		       nr_free_contexts, nrf);
		nr_free_contexts = nrf;
	}
	if (nact > num_online_cpus())
		pr_err("MMU: More active contexts than CPUs ! (%d vs %d)\n",
		       nact, num_online_cpus());
	if (first_context > 0 && !test_bit(0, context_map))
		pr_err("MMU: Context 0 has been freed !!!\n");
}
#else
static void context_check_map(void) { }
#endif

void switch_mmu_context(struct mm_struct *prev, struct mm_struct *next)
{
	unsigned int i, id, cpu = smp_processor_id();
	unsigned long *map;

	spin_lock(&context_lock);

	pr_hard("[%d] activating context for mm @%p, active=%d, id=%d",
		cpu, next, next->context.active, next->context.id);

#ifdef CONFIG_SMP
	 
	next->context.active++;
	if (prev) {
		pr_hardcont(" (old=0x%p a=%d)", prev, prev->context.active);
		WARN_ON(prev->context.active < 1);
		prev->context.active--;
	}

 again:
#endif  

	id = next->context.id;
	if (likely(id != MMU_NO_CONTEXT)) {
#ifdef DEBUG_MAP_CONSISTENCY
		if (context_mm[id] != next)
			pr_err("MMU: mm 0x%p has id %d but context_mm[%d] says 0x%p\n",
			       next, id, id, context_mm[id]);
#endif
		goto ctxt_ok;
	}

	id = next_context;
	if (id > last_context)
		id = first_context;
	map = context_map;

	if (nr_free_contexts == 0) {
#ifdef CONFIG_SMP
		if (num_online_cpus() > 1) {
			id = steal_context_smp(id);
			if (id == MMU_NO_CONTEXT)
				goto again;
			goto stolen;
		}
#endif  
		id = steal_context_up(id);
		goto stolen;
	}
	nr_free_contexts--;

	while (__test_and_set_bit(id, map)) {
		id = find_next_zero_bit(map, last_context+1, id);
		if (id > last_context)
			id = first_context;
	}
 stolen:
	next_context = id + 1;
	context_mm[id] = next;
	next->context.id = id;
	pr_hardcont(" | new id=%d,nrf=%d", id, nr_free_contexts);

	context_check_map();
 ctxt_ok:

	if (test_bit(id, stale_map[cpu])) {
		pr_hardcont(" | stale flush %d [%d..%d]",
			    id, cpu_first_thread_in_core(cpu),
			    cpu_last_thread_in_core(cpu));

		local_flush_tlb_mm(next);

		for (i = cpu_first_thread_in_core(cpu);
		     i <= cpu_last_thread_in_core(cpu); i++) {
			__clear_bit(id, stale_map[i]);
		}
	}

	pr_hardcont(" -> %d\n", id);
	set_context(id, next->pgd);
	spin_unlock(&context_lock);
}

int init_new_context(struct task_struct *t, struct mm_struct *mm)
{
	pr_hard("initing context for mm @%p\n", mm);

	mm->context.id = MMU_NO_CONTEXT;
	mm->context.active = 0;

	return 0;
}

void destroy_context(struct mm_struct *mm)
{
	unsigned long flags;
	unsigned int id;

	if (mm->context.id == MMU_NO_CONTEXT)
		return;

	WARN_ON(mm->context.active != 0);

	spin_lock_irqsave(&context_lock, flags);
	id = mm->context.id;
	if (id != MMU_NO_CONTEXT) {
		__clear_bit(id, context_map);
		mm->context.id = MMU_NO_CONTEXT;
#ifdef DEBUG_MAP_CONSISTENCY
		mm->context.active = 0;
#endif
		context_mm[id] = NULL;
		nr_free_contexts++;
	}
	spin_unlock_irqrestore(&context_lock, flags);
}

#ifdef CONFIG_SMP

static int __cpuinit mmu_context_cpu_notify(struct notifier_block *self,
					    unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned int)(long)hcpu;
#ifdef CONFIG_HOTPLUG_CPU
	struct task_struct *p;
#endif
	 
	if (cpu == 0)
		return NOTIFY_OK;

	switch (action) {
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		pr_devel("MMU: Allocating stale context map for CPU %d\n", cpu);
		stale_map[cpu] = kzalloc(CTX_MAP_SIZE, GFP_KERNEL);
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		pr_devel("MMU: Freeing stale context map for CPU %d\n", cpu);
		kfree(stale_map[cpu]);
		stale_map[cpu] = NULL;

		read_lock(&tasklist_lock);
		for_each_process(p) {
			if (p->mm)
#ifdef CONFIG_SYNO_QORIQ
				cpumask_clear_cpu(cpu, mm_cpumask(p->mm));
#else
				cpu_mask_clear_cpu(cpu, mm_cpumask(p->mm));
#endif
		}
		read_unlock(&tasklist_lock);
	break;
#endif  
	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata mmu_context_cpu_nb = {
	.notifier_call	= mmu_context_cpu_notify,
};

#endif  

void __init mmu_context_init(void)
{
	 
	init_mm.context.active = NR_CPUS;

	if (mmu_has_feature(MMU_FTR_TYPE_8xx)) {
		first_context = 0;
		last_context = 15;
	} else {
		first_context = 1;
		last_context = 255;
	}

#ifdef DEBUG_CLAMP_LAST_CONTEXT
	last_context = DEBUG_CLAMP_LAST_CONTEXT;
#endif
	 
	context_map = alloc_bootmem(CTX_MAP_SIZE);
	context_mm = alloc_bootmem(sizeof(void *) * (last_context + 1));
	stale_map[0] = alloc_bootmem(CTX_MAP_SIZE);

#ifdef CONFIG_SMP
	register_cpu_notifier(&mmu_context_cpu_nb);
#endif

	printk(KERN_INFO
	       "MMU: Allocated %zu bytes of context maps for %d contexts\n",
	       2 * CTX_MAP_SIZE + (sizeof(void *) * (last_context + 1)),
	       last_context - first_context + 1);

	context_map[0] = (1 << first_context) - 1;
	next_context = first_context;
	nr_free_contexts = last_context - first_context + 1;
}
