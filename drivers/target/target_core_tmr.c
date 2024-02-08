#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define TARGET_CORE_TMR_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_pr.h>
#include <target/target_core_seobj.h>
#include <target/target_core_tmr.h>
#include <target/target_core_transport.h>
#include <target/target_core_alua.h>
#include <target/target_core_transport_plugin.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>

#undef TARGET_CORE_TMR_C

#define DEBUG_LUN_RESET
#ifdef DEBUG_LUN_RESET
#define DEBUG_LR(x...) printk(KERN_INFO x)
#else
#define DEBUG_LR(x...)
#endif

se_tmr_req_t *core_tmr_alloc_req(
	se_cmd_t *se_cmd,
	void *fabric_tmr_ptr,
	u8 function)
{
	se_tmr_req_t *tmr;

	tmr = kmem_cache_zalloc(se_tmr_req_cache, GFP_KERNEL);
	if (!(tmr)) {
		printk(KERN_ERR "Unable to allocate se_tmr_req_t\n");
		return ERR_PTR(-ENOMEM);
	}
	tmr->task_cmd = se_cmd;
	tmr->fabric_tmr_ptr = fabric_tmr_ptr;
	tmr->function = function;
	INIT_LIST_HEAD(&tmr->tmr_list);

	return tmr;
}
EXPORT_SYMBOL(core_tmr_alloc_req);

void __core_tmr_release_req(
	se_tmr_req_t *tmr)
{
	list_del(&tmr->tmr_list);
	kmem_cache_free(se_tmr_req_cache, tmr);
}

void core_tmr_release_req(
	se_tmr_req_t *tmr)
{
	se_device_t *dev = tmr->tmr_dev;

	spin_lock(&dev->se_tmr_lock);
	__core_tmr_release_req(tmr);
	spin_unlock(&dev->se_tmr_lock);
}

int core_tmr_lun_reset(
	se_device_t *dev,
	se_tmr_req_t *tmr,
	struct list_head *preempt_and_abort_list,
	se_cmd_t *prout_cmd)
{
	se_cmd_t *cmd;
	se_queue_req_t *qr, *qr_tmp;
	se_node_acl_t *tmr_nacl = NULL;
	se_portal_group_t *tmr_tpg = NULL;
	se_queue_obj_t *qobj = dev->dev_queue_obj;
	se_tmr_req_t *tmr_p, *tmr_pp;
	se_task_t *task, *task_tmp;
	unsigned long flags;
	int fe_count, state, tas;
	 
	tas = DEV_ATTRIB(dev)->emulate_tas;
	 
	if (tmr && tmr->task_cmd && tmr->task_cmd->se_sess) {
		tmr_nacl = tmr->task_cmd->se_sess->se_node_acl;
		tmr_tpg = tmr->task_cmd->se_sess->se_tpg;
		if (tmr_nacl && tmr_tpg) {
			DEBUG_LR("LUN_RESET: TMR caller fabric: %s"
				" initiator port %s\n",
				TPG_TFO(tmr_tpg)->get_fabric_name(),
				tmr_nacl->initiatorname);
		}
	}
	DEBUG_LR("LUN_RESET: %s starting for [%s], tas: %d\n",
		(preempt_and_abort_list) ? "Preempt" : "TMR",
		TRANSPORT(dev)->name, tas);
	 
	spin_lock(&dev->se_tmr_lock);
	list_for_each_entry_safe(tmr_p, tmr_pp, &dev->dev_tmr_list, tmr_list) {
		 
		if (tmr && (tmr_p == tmr))
			continue;

		cmd = tmr_p->task_cmd;
		if (!(cmd)) {
			printk(KERN_ERR "Unable to locate se_cmd_t for TMR\n");
			continue;
		}
		 
		if ((preempt_and_abort_list != NULL) &&
		    (core_scsi3_check_cdb_abort_and_preempt(
					preempt_and_abort_list, cmd) != 0))
			continue;
		spin_unlock(&dev->se_tmr_lock);

#ifdef MY_ABC_HERE
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		if (!(atomic_read(&T_TASK(cmd)->t_transport_active))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
			spin_lock(&dev->se_tmr_lock);
			continue;
		}
		if (cmd->t_state == TRANSPORT_ISTATE_PROCESSING) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
			spin_lock(&dev->se_tmr_lock);
			continue;
		}
#endif
		DEBUG_LR("LUN_RESET: %s releasing TMR %p Function: 0x%02x,"
			" Response: 0x%02x, t_state: %d\n",
			(preempt_and_abort_list) ? "Preempt" : "", tmr_p,
			tmr_p->function, tmr_p->response, cmd->t_state);
#ifdef MY_ABC_HERE
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
#endif

		transport_cmd_finish_abort_tmr(cmd);
		spin_lock(&dev->se_tmr_lock);
	}
	spin_unlock(&dev->se_tmr_lock);
	 
	spin_lock_irqsave(&dev->execute_task_lock, flags);
	list_for_each_entry_safe(task, task_tmp, &dev->state_task_list,
				t_state_list) {
		if (!(TASK_CMD(task))) {
			printk(KERN_ERR "TASK_CMD(task) is NULL!\n");
			continue;
		}
		cmd = TASK_CMD(task);

		if (!T_TASK(cmd)) {
			printk(KERN_ERR "T_TASK(cmd) is NULL for task: %p cmd:"
				" %p ITT: 0x%08x\n", task, cmd,
				CMD_TFO(cmd)->get_task_tag(cmd));
			continue;
		}
		 
		if ((preempt_and_abort_list != NULL) &&
		    (core_scsi3_check_cdb_abort_and_preempt(
					preempt_and_abort_list, cmd) != 0))
			continue;
		 
		if (prout_cmd == cmd)
			continue;

		list_del(&task->t_state_list);
		atomic_set(&task->task_state_active, 0);
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		DEBUG_LR("LUN_RESET: %s cmd: %p task: %p ITT/CmdSN: 0x%08x/"
			"0x%08x, i_state: %d, t_state/def_t_state: %d/%d cdb:"
			" 0x%02x\n", (preempt_and_abort_list) ? "Preempt" : "",
			cmd, task, CMD_TFO(cmd)->get_task_tag(cmd),
			0, CMD_TFO(cmd)->get_cmd_state(cmd), cmd->t_state,
			cmd->deferred_t_state, T_TASK(cmd)->t_task_cdb[0]);
		DEBUG_LR("LUN_RESET: ITT[0x%08x] - pr_res_key: 0x%016Lx"
			" t_task_cdbs: %d t_task_cdbs_left: %d"
			" t_task_cdbs_sent: %d -- t_transport_active: %d"
			" t_transport_stop: %d t_transport_sent: %d\n",
			CMD_TFO(cmd)->get_task_tag(cmd), cmd->pr_res_key,
			T_TASK(cmd)->t_task_cdbs,
			atomic_read(&T_TASK(cmd)->t_task_cdbs_left),
			atomic_read(&T_TASK(cmd)->t_task_cdbs_sent),
			atomic_read(&T_TASK(cmd)->t_transport_active),
			atomic_read(&T_TASK(cmd)->t_transport_stop),
			atomic_read(&T_TASK(cmd)->t_transport_sent));

		if (atomic_read(&task->task_active)) {
			atomic_set(&task->task_stop, 1);
			spin_unlock_irqrestore(
				&T_TASK(cmd)->t_state_lock, flags);

			DEBUG_LR("LUN_RESET: Waiting for task: %p to shutdown"
				" for dev: %p\n", task, dev);
			wait_for_completion(&task->task_stop_comp);
			DEBUG_LR("LUN_RESET Completed task: %p shutdown for"
				" dev: %p\n", task, dev);
			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			atomic_dec(&T_TASK(cmd)->t_task_cdbs_left);

			atomic_set(&task->task_active, 0);
			atomic_set(&task->task_stop, 0);
		}
		__transport_stop_task_timer(task, &flags);

		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_ex_left))) {
			spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);
			DEBUG_LR("LUN_RESET: Skipping task: %p, dev: %p for"
				" t_task_cdbs_ex_left: %d\n", task, dev,
				atomic_read(&T_TASK(cmd)->t_task_cdbs_ex_left));

			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}
		fe_count = atomic_read(&T_TASK(cmd)->t_fe_count);

		if (atomic_read(&T_TASK(cmd)->t_transport_active)) {
			DEBUG_LR("LUN_RESET: got t_transport_active = 1 for"
				" task: %p, t_fe_count: %d dev: %p\n", task,
				fe_count, dev);
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
						flags);
			if (fe_count) {
				 
				if (((tmr_nacl != NULL) &&
				     (tmr_nacl == cmd->se_sess->se_node_acl)) ||
				     tas)
					transport_send_task_abort(cmd);
				transport_cmd_finish_abort(cmd, 0);
			} else
				transport_cmd_finish_abort(cmd, 1);

			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}
		DEBUG_LR("LUN_RESET: Got t_transport_active = 0 for task: %p,"
			" t_fe_count: %d dev: %p\n", task, fe_count, dev);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		if (fe_count) {
			 
			if (((tmr_nacl != NULL) &&
			    (tmr_nacl == cmd->se_sess->se_node_acl)) || tas)
				transport_send_task_abort(cmd);
			transport_cmd_finish_abort(cmd, 0);
		} else
			transport_cmd_finish_abort(cmd, 1);

		spin_lock_irqsave(&dev->execute_task_lock, flags);
	}
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);
	 
	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	list_for_each_entry_safe(qr, qr_tmp, &qobj->qobj_list, qr_list) {
		cmd = (se_cmd_t *)qr->cmd;
		if (!(cmd)) {
			 
			if (preempt_and_abort_list != NULL)
				continue;

			atomic_dec(&qobj->queue_cnt);
			list_del(&qr->qr_list);
			kfree(qr);
			continue;
		}
		 
		if ((preempt_and_abort_list != NULL) &&
		    (core_scsi3_check_cdb_abort_and_preempt(
					preempt_and_abort_list, cmd) != 0))
			continue;
		 
		if (prout_cmd == cmd)
			continue;

		atomic_dec(&T_TASK(cmd)->t_transport_queue_active);
		atomic_dec(&qobj->queue_cnt);
		list_del(&qr->qr_list);
		spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

		state = qr->state;
		kfree(qr);

		DEBUG_LR("LUN_RESET: %s from Device Queue: cmd: %p t_state:"
			" %d t_fe_count: %d\n", (preempt_and_abort_list) ?
			"Preempt" : "", cmd, state,
			atomic_read(&T_TASK(cmd)->t_fe_count));
#ifdef MY_ABC_HERE
		 
		transport_new_cmd_failure(cmd);
#endif

		if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
			 
			if (((tmr_nacl != NULL) &&
			     (tmr_nacl == cmd->se_sess->se_node_acl)) ||
			      tas)
				transport_send_task_abort(cmd);
			transport_cmd_finish_abort(cmd, 0);
		} else
			transport_cmd_finish_abort(cmd, 1);

		spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	}
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);
	 
	if (!(preempt_and_abort_list) &&
	     (dev->dev_flags & DF_SPC2_RESERVATIONS)) {
		spin_lock(&dev->dev_reservation_lock);
		dev->dev_reserved_node_acl = NULL;
		dev->dev_flags &= ~DF_SPC2_RESERVATIONS;
		spin_unlock(&dev->dev_reservation_lock);
		printk(KERN_INFO "LUN_RESET: SCSI-2 Released reservation\n");	
	}	

#ifdef SNMP_SUPPORT
	spin_lock(&dev->stats_lock);
	dev->num_resets++;
	spin_unlock(&dev->stats_lock);
#endif  

	DEBUG_LR("LUN_RESET: %s for [%s] Complete\n",
			(preempt_and_abort_list) ? "Preempt" : "TMR",
			TRANSPORT(dev)->name);
	return 0;
}
