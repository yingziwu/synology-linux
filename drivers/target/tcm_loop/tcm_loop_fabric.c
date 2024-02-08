/*******************************************************************************
 * Filename:  tcm_loop_fabric.c
 *
 * This file contains the TCM fabric module for initiator side virtual SAS
 * using emulated target mode SAS ports
 *
 * Copyright (c) 2009 Rising Tide, Inc.
 * Copyright (c) 2009 Linux-iSCSI.org
 *
 * Copyright (c) 2009 Nicholas A. Bellinger <nab@linux-iscsi.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ****************************************************************************/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/string.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_device.h>
#include <target/target_core_tpg.h>
#include <target/target_core_configfs.h>
#include <target/target_core_alua.h>

#include <tcm_loop_core.h>
#include <tcm_loop_configfs.h>
#include <tcm_loop_fabric_scsi.h>

struct kmem_cache *tcm_loop_cmd_cache;

char *tcm_loop_get_fabric_name(void)
{
	return "loopback";
}

u8 tcm_loop_get_fabric_proto_ident(void)
{
	/*
	 * Return a SAS Serial SCSI Protocol identifier for loopback operations
	 * This is defined in  section 7.5.1 Table 362 in spc4r17
	 */
	return 0x6;
}

char *tcm_loop_get_endpoint_wwn(se_portal_group_t *se_tpg)
{
	struct tcm_loop_tpg *tl_tpg =
		(struct tcm_loop_tpg *)se_tpg->se_tpg_fabric_ptr;	
	/*
	 * Return the passed NAA identifier for the SAS Target Port
	 */
	return &tl_tpg->tl_hba->naa_sas_address[0];
}

u16 tcm_loop_get_tag(se_portal_group_t *se_tpg)
{
	struct tcm_loop_tpg *tl_tpg =
		(struct tcm_loop_tpg *)se_tpg->se_tpg_fabric_ptr;
	/*
	 * This Tag is used when forming SCSI Name identifier in EVPD=1 0x83
	 * to represent the SCSI Target Port.
	 */
	return tl_tpg->tl_tpgt;
}

u32 tcm_loop_get_default_depth(se_portal_group_t *se_tpg)
{
	return 1;
}

u32 tcm_loop_get_pr_transport_id(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl,
	t10_pr_registration_t *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	unsigned char binary, *ptr;
	int i;
	u32 off = 4;
	/*
	 * Set PROTOCOL IDENTIFIER to 6h for SAS
	 */
	buf[0] = 0x06;
	/*
	 * From spc4r17, 7.5.4.7 TransportID for initiator ports using SCSI
	 * over SAS Serial SCSI Protocol
	 * 
	 * For TCM_Loop, we use the configfs group name of INIT_SAS_ADDRESS:
	 * and converting the 16-byte ASCII value into a 8-byte binary hex
	 * buffer.
	 *
	 * target/loopback/naa.<TGT_SAS_ADDRESS>/nexus/naa.<INIt_SAS_ADDRESS>
	 */
	ptr = &se_nacl->initiatorname[4]; /* Skip over 'naa. prefix */

	for (i = 0; i < 16; i += 2) {
		binary = transport_asciihex_to_binaryhex(&ptr[i]);	
		buf[off++] = binary;
	}
	/*
	 * The SAS Transport ID is a hardcoded 24-byte length
	 */
	return 24;
}

u32 tcm_loop_get_pr_transport_id_len(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl,
	t10_pr_registration_t *pr_reg,
	int *format_code)
{
	*format_code = 0;
	/*
	 * From spc4r17, 7.5.4.7 TransportID for initiator ports using SCSI
	 * over SAS Serial SCSI Protocol
	 *
	 * The SAS Transport ID is a hardcoded 24-byte length
	 */
	return 24;
}

/*
 * Used for handling SCSI fabric dependent TransportIDs in SPC-3 and above
 * Persistent Reservation SPEC_I_PT=1 and PROUT REGISTER_AND_MOVE operations.
 */
char *tcm_loop_parse_pr_out_transport_id(
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	/*
	 * Assume the FORMAT CODE 00b from spc4r17, 7.5.4.7 TransportID
	 * for initiator ports using SCSI over SAS Serial SCSI Protocol
	 *
	 * The TransportID for a SAS Initiator Port is of fixed size of
	 * 24 bytes, and SAS does not contain a I_T nexus identifier,
	 * so we return the **port_nexus_ptr set to NULL.
	 */
	*port_nexus_ptr = NULL;
	*out_tid_len = 24;

	return (char *)&buf[4];
}

/*
 * Returning (1) here allows for target_core_mod se_node_acl_t to be generated
 * based upon the incoming fabric dependent SCSI Initiator Port
 */
int tcm_loop_check_demo_mode(se_portal_group_t *se_tpg)
{
	return 1;
}

int tcm_loop_check_demo_mode_cache(se_portal_group_t *se_tpg)
{
	return 0;
}

/*
 * Allow I_T Nexus full READ-WRITE access without explict Initiator Node ACLs for
 * local virtual Linux/SCSI LLD passthrough into VM hypervisor guest
 */
int tcm_loop_check_demo_mode_write_protect(se_portal_group_t *se_tpg)
{
	return 0;
}

void *tcm_loop_tpg_alloc_fabric_acl(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl)
{
	struct tcm_loop_nacl *tl_nacl;

	tl_nacl = kzalloc(sizeof( struct tcm_loop_nacl), GFP_KERNEL);
	if (!(tl_nacl)) {
		printk(KERN_ERR "Unable to allocate struct tcm_loop_nacl\n");
		return NULL;
	}
	tl_nacl->se_nacl = se_nacl;

	return (void *)tl_nacl;
}

void tcm_loop_tpg_release_fabric_acl(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl)
{
	struct tcm_loop_nacl *tl_nacl =
			(struct tcm_loop_nacl *)se_nacl->fabric_acl_ptr;

	kfree(tl_nacl);
}

#ifdef SNMP_SUPPORT
u32 tcm_loop_get_tpg_inst_index(se_portal_group_t *se_tpg)
{
	struct tcm_loop_tpg *tl_tpg =
		(struct tcm_loop_tpg *)se_tpg->se_tpg_fabric_ptr;

//	return tpg->tpg_tiqn->tiqn_index;
	return 1;
}
#endif /* SNMP_SUPPORT */

void tcm_loop_new_cmd_failure(se_cmd_t *se_cmd)
{
	/*
	 * Since TCM_loop is already passing struct scatterlist data from
	 * struct scsi_cmnd, no more Linux/SCSI failure dependent state need
	 * to be handled here.
	 */
	return;
}

int tcm_loop_is_state_remove(se_cmd_t *se_cmd)
{
	/*
	 * Assume struct scsi_cmnd is not in remove state..
	 */
	return 0;
}

int tcm_loop_sess_logged_in(se_session_t *se_sess)
{
	/*
	 * Assume that TL Nexus is always active
	 */
	return 1;
}

#ifdef SNMP_SUPPORT
u32 tpg_loop_sess_get_index(se_session_t *se_sess)
{
	return 1;
}
#endif /* SNMP_SUPPORT */

void tcm_loop_set_default_node_attributes(se_node_acl_t *se_acl)
{
	return;
}

u32 tcm_loop_get_task_tag(se_cmd_t *se_cmd)
{
	return 1;
}

int tcm_loop_get_cmd_state(se_cmd_t *se_cmd)
{
	struct tcm_loop_cmd *tl_cmd =
			(struct tcm_loop_cmd *)se_cmd->se_fabric_cmd_ptr;

	return tl_cmd->sc_cmd_state;
}

#warning FIXME: tcm_loop_shutdown_session()
int tcm_loop_shutdown_session(se_session_t *se_sess)
{
	BUG();
	return 0;
}

#warning FIXME: tcm_loop_close_session()
void tcm_loop_close_session(se_session_t *se_sess)
{
	BUG();
};

#warning FIXME: tcm_loop_stop_session()
void tcm_loop_stop_session(
	se_session_t *se_sess,
	int sess_sleep,
	int conn_sleep)
{
	BUG();
}

#warning FIXME: tcm_loop_fall_back_to_erl0()
void tcm_loop_fall_back_to_erl0(se_session_t *se_sess)
{
	BUG();
}

int tcm_loop_write_pending(se_cmd_t *se_cmd)
{
	/*
	 * Since Linux/SCSI has already sent down a struct scsi_cmnd
	 * sc->sc_data_direction of DMA_TO_DEVICE with struct scatterlist array
	 * memory, and memory has already been mapped to se_cmd_t->t_mem_list
	 * format with transport_generic_map_mem_to_cmd().
	 *
	 * For the TCM control CDBs using a contiguous buffer, do the memcpy
	 * from the passed Linux/SCSI struct scatterlist located at
	 * T_TASK(se_cmd)->t_task_pt_buf to the contiguous buffer at
	 * T_TASK(se_cmd)->t_task_buf.
	 */
	if (se_cmd->se_cmd_flags & SCF_PASSTHROUGH_CONTIG_TO_SG) {
		TL_CDB_DEBUG("Calling transport_memcpy_read_contig()"
				" for SCF_PASSTHROUGH_CONTIG_TO_SG\n");
		transport_memcpy_read_contig(se_cmd,
				T_TASK(se_cmd)->t_task_buf,
				T_TASK(se_cmd)->t_task_pt_buf);
	}
	/*
	 * We now tell TCM to add this WRITE CDB directly into the TCM storage
	 * object execution queue.
	 */
	transport_generic_process_write(se_cmd);
	return 0;
}

int tcm_loop_write_pending_status(se_cmd_t *se_cmd)
{
	return 0;
}

int tcm_loop_queue_data_in(se_cmd_t *se_cmd)
{
	struct tcm_loop_cmd *tl_cmd =
			(struct tcm_loop_cmd *)se_cmd->se_fabric_cmd_ptr;
	struct scsi_cmnd *sc = tl_cmd->sc;
	unsigned long flags;

	TL_CDB_DEBUG( "tcm_loop_queue_data_in() called for scsi_cmnd: %p"
			" cdb: 0x%02x\n", sc, sc->cmnd[0]);

	if (se_cmd->se_cmd_flags & SCF_PASSTHROUGH_CONTIG_TO_SG) {
		TL_CDB_DEBUG("Calling transport_memcpy_write_contig()"
			" for SCF_PASSTHROUGH_CONTIG_TO_SG\n");
		transport_memcpy_write_contig(se_cmd,
			T_TASK(se_cmd)->t_task_pt_buf,
			T_TASK(se_cmd)->t_task_buf);
	}

	sc->result = host_byte(DID_OK) | SAM_STAT_GOOD;

	spin_lock_irqsave(sc->device->host->host_lock, flags);
	(*sc->scsi_done)(sc);
	spin_unlock_irqrestore(sc->device->host->host_lock, flags);
	return 0;
}

int tcm_loop_queue_status(se_cmd_t *se_cmd)
{
	struct tcm_loop_cmd *tl_cmd =
			(struct tcm_loop_cmd *)se_cmd->se_fabric_cmd_ptr;
	struct scsi_cmnd *sc = tl_cmd->sc;
	unsigned long flags;

	TL_CDB_DEBUG("tcm_loop_queue_status() called for scsi_cmnd: %p"
			" cdb: 0x%02x\n", sc, sc->cmnd[0]);

	if (se_cmd->sense_buffer &&
	   ((se_cmd->se_cmd_flags & SCF_TRANSPORT_TASK_SENSE) ||
	    (se_cmd->se_cmd_flags & SCF_EMULATED_TASK_SENSE))) {

		memcpy((void *)sc->sense_buffer, (void *)se_cmd->sense_buffer,
				SCSI_SENSE_BUFFERSIZE);	
		sc->result = host_byte(DID_OK) | driver_byte(DRIVER_SENSE) |
				SAM_STAT_CHECK_CONDITION;
	} else
		sc->result = host_byte(DID_OK) | se_cmd->scsi_status;

	spin_lock_irqsave(sc->device->host->host_lock, flags);
	(*sc->scsi_done)(sc);
	spin_unlock_irqrestore(sc->device->host->host_lock, flags);
	return 0;
}

int tcm_loop_queue_tm_rsp(se_cmd_t *se_cmd)
{
	return 0;
}

u16 tcm_loop_set_fabric_sense_len(se_cmd_t *se_cmd, u32 sense_length)
{
	return 0;
}

u16 tcm_loop_get_fabric_sense_len(void)
{
	return 0;
}

u64 tcm_loop_pack_lun(unsigned int lun)
{
	u64 result;

	/* LSB of lun into byte 1 big-endian */
	result = ((lun & 0xff) << 8);
	/* use flat space addressing method */
	result |= 0x40 | ((lun >> 8) & 0x3f);

	return cpu_to_le64(result);
}

static se_queue_req_t *tcm_loop_get_qr_from_queue(se_queue_obj_t *qobj)
{
	se_queue_req_t *qr;
	unsigned long flags;

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	if (list_empty(&qobj->qobj_list)) {
		spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);
		return NULL;
	}

	qr = list_first_entry(&qobj->qobj_list, se_queue_req_t, qr_list);
	list_del(&qr->qr_list);
	atomic_dec(&qobj->queue_cnt);
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	return qr;
}

int tcm_loop_processing_thread(void *p)
{
	struct scsi_cmnd *sc;
	struct tcm_loop_cmd *tl_cmd;
	struct tcm_loop_hba *tl_hba = (struct tcm_loop_hba *)p;
	se_queue_obj_t *qobj = tl_hba->tl_hba_qobj;
	se_queue_req_t *qr;
	int ret;

	current->policy = SCHED_NORMAL;
	set_user_nice(current, -20);
	spin_lock_irq(&current->sighand->siglock);
	siginitsetinv(&current->blocked, SHUTDOWN_SIGS);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	complete(&qobj->thread_create_comp);

	while (!(kthread_should_stop())) {
		ret = wait_event_interruptible(qobj->thread_wq,
			atomic_read(&qobj->queue_cnt) || kthread_should_stop());
		if (ret < 0)
			goto out;

		qr = tcm_loop_get_qr_from_queue(qobj);
		if (!(qr))
			continue;

		tl_cmd = (struct tcm_loop_cmd *)qr->cmd;
		sc = tl_cmd->sc;
		kfree(qr);

		TL_CDB_DEBUG("processing_thread, calling tcm_loop_execute"
			"_core_cmd() for tl_cmd: %p, sc: %p\n", tl_cmd, sc);
		tcm_loop_execute_core_cmd(tl_cmd, sc);
	}

out:
	complete(&qobj->thread_done_comp);
	return 0;
}

static int __init tcm_loop_fabric_init(void)
{
	int ret;

	tcm_loop_cmd_cache = kmem_cache_create("tcm_loop_cmd_cache",
				sizeof(struct tcm_loop_cmd),
				__alignof__(struct tcm_loop_cmd),
				0, NULL);
	if (!(tcm_loop_cmd_cache)) {
		printk(KERN_ERR "kmem_cache_create() for"
				" tcm_loop_cmd_cache failed\n");
		return -1;
	}

	ret = tcm_loop_alloc_core_bus();
	if (ret)
		return ret;

	ret = tcm_loop_register_configfs();
	if (ret) {
		tcm_loop_release_core_bus();
		return ret;
	}

	return 0;
}

static void tcm_loop_fabric_exit(void)
{
	tcm_loop_deregister_configfs();
	tcm_loop_release_core_bus();
	kmem_cache_destroy(tcm_loop_cmd_cache);
}

#ifdef MODULE
MODULE_DESCRIPTION("TCM loopback virtual Linux/SCSI fabric module");
MODULE_AUTHOR("Nicholas A. Bellinger <nab@Linux-iSCSI.org>");
MODULE_LICENSE("GPL");
module_init(tcm_loop_fabric_init);
module_exit(tcm_loop_fabric_exit);
#endif /* MODULE */
