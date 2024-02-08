#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define ISCSI_TARGET_ERL2_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_defs.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_crc.h>
#include <iscsi_debug.h>
#include <iscsi_target_core.h>
#include <target/target_core_base.h>
#include <iscsi_target_datain_values.h>
#include <target/target_core_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h>

#undef ISCSI_TARGET_ERL2_C

void iscsi_create_conn_recovery_datain_values(
	iscsi_cmd_t *cmd,
	u32 exp_data_sn)
{
	u32 data_sn = 0;
	iscsi_conn_t *conn = CONN(cmd);

	cmd->next_burst_len = 0;
	cmd->read_data_done = 0;

	while (exp_data_sn > data_sn) {
		if ((cmd->next_burst_len +
		     CONN_OPS(conn)->MaxRecvDataSegmentLength) <
		     SESS_OPS_C(conn)->MaxBurstLength) {
			cmd->read_data_done +=
			       CONN_OPS(conn)->MaxRecvDataSegmentLength;
			cmd->next_burst_len +=
			       CONN_OPS(conn)->MaxRecvDataSegmentLength;
		} else {
			cmd->read_data_done +=
				(SESS_OPS_C(conn)->MaxBurstLength -
				cmd->next_burst_len);
			cmd->next_burst_len = 0;
		}
		data_sn++;
	}
}

void iscsi_create_conn_recovery_dataout_values(
	iscsi_cmd_t *cmd)
{
	u32 write_data_done = 0;
	iscsi_conn_t *conn = CONN(cmd);

	cmd->data_sn = 0;
	cmd->next_burst_len = 0;

	while (cmd->write_data_done > write_data_done) {
		if ((write_data_done + SESS_OPS_C(conn)->MaxBurstLength) <=
		     cmd->write_data_done)
			write_data_done += SESS_OPS_C(conn)->MaxBurstLength;
		else
			break;
	}

	cmd->write_data_done = write_data_done;
}

static int iscsi_attach_active_connection_recovery_entry(
	iscsi_session_t *sess,
	iscsi_conn_recovery_t *cr)
{
	spin_lock(&sess->cr_a_lock);
	list_add_tail(&cr->cr_list, &sess->cr_active_list);
	spin_unlock(&sess->cr_a_lock);

	return 0;
}

static int iscsi_attach_inactive_connection_recovery_entry(
	iscsi_session_t *sess,
	iscsi_conn_recovery_t *cr)
{
	spin_lock(&sess->cr_i_lock);
	list_add_tail(&cr->cr_list, &sess->cr_inactive_list);

	sess->conn_recovery_count++;
	TRACE(TRACE_ERL2, "Incremented connection recovery count to %u for"
		" SID: %u\n", sess->conn_recovery_count, sess->sid);
	spin_unlock(&sess->cr_i_lock);

	return 0;
}

iscsi_conn_recovery_t *iscsi_get_inactive_connection_recovery_entry(
	iscsi_session_t *sess,
	u16 cid)
{
	iscsi_conn_recovery_t *cr;

	spin_lock(&sess->cr_i_lock);
	list_for_each_entry(cr, &sess->cr_inactive_list, cr_list) {
		if (cr->cid == cid)
			break;
	}
	spin_unlock(&sess->cr_i_lock);

	return (cr) ? cr : NULL;
}

void iscsi_free_connection_recovery_entires(iscsi_session_t *sess)
{
	iscsi_cmd_t *cmd, *cmd_tmp;
	iscsi_conn_recovery_t *cr, *cr_tmp;

	spin_lock(&sess->cr_a_lock);
	list_for_each_entry_safe(cr, cr_tmp, &sess->cr_active_list, cr_list) {
		list_del(&cr->cr_list);
		spin_unlock(&sess->cr_a_lock);

		spin_lock(&cr->conn_recovery_cmd_lock);
		list_for_each_entry_safe(cmd, cmd_tmp,
				&cr->conn_recovery_cmd_list, i_list) {

			list_del(&cmd->i_list);
			cmd->conn = NULL;
			spin_unlock(&cr->conn_recovery_cmd_lock);
			if (!(SE_CMD(cmd)) ||
			    !(SE_CMD(cmd)->se_cmd_flags & SCF_SE_LUN_CMD) ||
			    !(SE_CMD(cmd)->transport_wait_for_tasks))
				__iscsi_release_cmd_to_pool(cmd, sess);
			else
				SE_CMD(cmd)->transport_wait_for_tasks(
						SE_CMD(cmd), 1, 1);
			spin_lock(&cr->conn_recovery_cmd_lock);
		}
		spin_unlock(&cr->conn_recovery_cmd_lock);
		spin_lock(&sess->cr_a_lock);

		kfree(cr);
	}
	spin_unlock(&sess->cr_a_lock);

	spin_lock(&sess->cr_i_lock);
	list_for_each_entry_safe(cr, cr_tmp, &sess->cr_inactive_list, cr_list) {
		list_del(&cr->cr_list);
		spin_unlock(&sess->cr_i_lock);

		spin_lock(&cr->conn_recovery_cmd_lock);
		list_for_each_entry_safe(cmd, cmd_tmp,
				&cr->conn_recovery_cmd_list, i_list) {

			list_del(&cmd->i_list);
			cmd->conn = NULL;
			spin_unlock(&cr->conn_recovery_cmd_lock);
			if (!(SE_CMD(cmd)) ||
			    !(SE_CMD(cmd)->se_cmd_flags & SCF_SE_LUN_CMD) ||
			    !(SE_CMD(cmd)->transport_wait_for_tasks))
				__iscsi_release_cmd_to_pool(cmd, sess);
			else
				SE_CMD(cmd)->transport_wait_for_tasks(
						SE_CMD(cmd), 1, 1);
			spin_lock(&cr->conn_recovery_cmd_lock);
		}
		spin_unlock(&cr->conn_recovery_cmd_lock);
		spin_lock(&sess->cr_i_lock);

		kfree(cr);
	}
	spin_unlock(&sess->cr_i_lock);
}

int iscsi_remove_active_connection_recovery_entry(
	iscsi_conn_recovery_t *cr,
	iscsi_session_t *sess)
{
	spin_lock(&sess->cr_a_lock);
	list_del(&cr->cr_list);

	sess->conn_recovery_count--;
	TRACE(TRACE_ERL2, "Decremented connection recovery count to %u for"
		" SID: %u\n", sess->conn_recovery_count, sess->sid);
	spin_unlock(&sess->cr_a_lock);

	kfree(cr);

	return 0;
}

int iscsi_remove_inactive_connection_recovery_entry(
	iscsi_conn_recovery_t *cr,
	iscsi_session_t *sess)
{
	spin_lock(&sess->cr_i_lock);
	list_del(&cr->cr_list);
	spin_unlock(&sess->cr_i_lock);

	return 0;
}

int iscsi_remove_cmd_from_connection_recovery(
	iscsi_cmd_t *cmd,
	iscsi_session_t *sess)
{
	iscsi_conn_recovery_t *cr;

	if (!cmd->cr) {
		printk(KERN_ERR "iscsi_conn_recovery_t pointer for ITT: 0x%08x"
			" is NULL!\n", cmd->init_task_tag);
		BUG();
	}
	cr = cmd->cr;

	list_del(&cmd->i_list);
	return --cr->cmd_count;
}

void iscsi_discard_cr_cmds_by_expstatsn(
	iscsi_conn_recovery_t *cr,
	u32 exp_statsn)
{
	u32 dropped_count = 0;
	iscsi_cmd_t *cmd, *cmd_tmp;
	iscsi_session_t *sess = cr->sess;

	spin_lock(&cr->conn_recovery_cmd_lock);
	list_for_each_entry_safe(cmd, cmd_tmp,
			&cr->conn_recovery_cmd_list, i_list) {

		if (((cmd->deferred_i_state != ISTATE_SENT_STATUS) &&
		     (cmd->deferred_i_state != ISTATE_REMOVE)) ||
		     (cmd->stat_sn >= exp_statsn)) {
			continue;
		}

		dropped_count++;
		TRACE(TRACE_ERL2, "Dropping Acknowledged ITT: 0x%08x, StatSN:"
			" 0x%08x, CID: %hu.\n", cmd->init_task_tag,
				cmd->stat_sn, cr->cid);

		iscsi_remove_cmd_from_connection_recovery(cmd, sess);

		spin_unlock(&cr->conn_recovery_cmd_lock);
		if (!(SE_CMD(cmd)) ||
		    !(SE_CMD(cmd)->se_cmd_flags & SCF_SE_LUN_CMD) ||
		    !(SE_CMD(cmd)->transport_wait_for_tasks))
			__iscsi_release_cmd_to_pool(cmd, sess);
		else
			SE_CMD(cmd)->transport_wait_for_tasks(
					SE_CMD(cmd), 1, 0);
		spin_lock(&cr->conn_recovery_cmd_lock);
	}
	spin_unlock(&cr->conn_recovery_cmd_lock);

	TRACE(TRACE_ERL2, "Dropped %u total acknowledged commands on"
		" CID: %hu less than old ExpStatSN: 0x%08x\n",
			dropped_count, cr->cid, exp_statsn);

	if (!cr->cmd_count) {
		TRACE(TRACE_ERL2, "No commands to be reassigned for failed"
			" connection CID: %hu on SID: %u\n",
			cr->cid, sess->sid);
		iscsi_remove_inactive_connection_recovery_entry(cr, sess);
		iscsi_attach_active_connection_recovery_entry(sess, cr);
		printk(KERN_INFO "iSCSI connection recovery successful for CID:"
			" %hu on SID: %u\n", cr->cid, sess->sid);
		iscsi_remove_active_connection_recovery_entry(cr, sess);
	} else {
		iscsi_remove_inactive_connection_recovery_entry(cr, sess);
		iscsi_attach_active_connection_recovery_entry(sess, cr);
	}

	return;
}

int iscsi_discard_unacknowledged_ooo_cmdsns_for_conn(iscsi_conn_t *conn)
{
	u32 dropped_count = 0;
	iscsi_cmd_t *cmd, *cmd_tmp;
	iscsi_ooo_cmdsn_t *ooo_cmdsn, *ooo_cmdsn_tmp;
	iscsi_session_t *sess = SESS(conn);

	spin_lock(&sess->cmdsn_lock);
	list_for_each_entry_safe(ooo_cmdsn, ooo_cmdsn_tmp,
			&sess->sess_ooo_cmdsn_list, ooo_list) {

		if (ooo_cmdsn->cid != conn->cid)
			continue;

		dropped_count++;
		TRACE(TRACE_ERL2, "Dropping unacknowledged CmdSN:"
		" 0x%08x during connection recovery on CID: %hu\n",
			ooo_cmdsn->cmdsn, conn->cid);
		iscsi_remove_ooo_cmdsn(sess, ooo_cmdsn);
	}
	SESS(conn)->ooo_cmdsn_count -= dropped_count;
	spin_unlock(&sess->cmdsn_lock);

	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry_safe(cmd, cmd_tmp, &conn->conn_cmd_list, i_list) {
		if (!(cmd->cmd_flags & ICF_OOO_CMDSN))
			continue;

		iscsi_remove_cmd_from_conn_list(cmd, conn);

		spin_unlock_bh(&conn->cmd_lock);
		if (!(SE_CMD(cmd)) ||
		    !(SE_CMD(cmd)->se_cmd_flags & SCF_SE_LUN_CMD) ||
		    !(SE_CMD(cmd)->transport_wait_for_tasks))
			__iscsi_release_cmd_to_pool(cmd, sess);
		else
			SE_CMD(cmd)->transport_wait_for_tasks(
					SE_CMD(cmd), 1, 1);
		spin_lock_bh(&conn->cmd_lock);
	}
	spin_unlock_bh(&conn->cmd_lock);

	TRACE(TRACE_ERL2, "Dropped %u total unacknowledged commands on CID:"
		" %hu for ExpCmdSN: 0x%08x.\n", dropped_count, conn->cid,
				sess->exp_cmd_sn);
	return 0;
}

int iscsi_prepare_cmds_for_realligance(iscsi_conn_t *conn)
{
	u32 cmd_count = 0;
	iscsi_cmd_t *cmd, *cmd_tmp;
	iscsi_conn_recovery_t *cr;

	cr = kzalloc(sizeof(iscsi_conn_recovery_t), GFP_KERNEL);
	if (!(cr)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" iscsi_conn_recovery_t.\n");
		return -1;
	}
	INIT_LIST_HEAD(&cr->cr_list);
	INIT_LIST_HEAD(&cr->conn_recovery_cmd_list);
	spin_lock_init(&cr->conn_recovery_cmd_lock);
	 
	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry_safe(cmd, cmd_tmp, &conn->conn_cmd_list, i_list) {

		if ((cmd->iscsi_opcode != ISCSI_INIT_SCSI_CMND) &&
		    (cmd->iscsi_opcode != ISCSI_INIT_NOP_OUT)) {
			TRACE(TRACE_ERL2, "Not performing realligence on"
				" Opcode: 0x%02x, ITT: 0x%08x, CmdSN: 0x%08x,"
				" CID: %hu\n", cmd->iscsi_opcode,
				cmd->init_task_tag, cmd->cmd_sn, conn->cid);

			iscsi_remove_cmd_from_conn_list(cmd, conn);

			spin_unlock_bh(&conn->cmd_lock);
			if (!(SE_CMD(cmd)) ||
			    !(SE_CMD(cmd)->se_cmd_flags & SCF_SE_LUN_CMD) ||
			    !(SE_CMD(cmd)->transport_wait_for_tasks))
				__iscsi_release_cmd_to_pool(cmd, SESS(conn));
			else
				SE_CMD(cmd)->transport_wait_for_tasks(
						SE_CMD(cmd), 1, 0);
			spin_lock_bh(&conn->cmd_lock);
			continue;
		}

		if (!(cmd->cmd_flags & ICF_OOO_CMDSN) && !cmd->immediate_cmd &&
		     (cmd->cmd_sn >= SESS(conn)->exp_cmd_sn)) {
			iscsi_remove_cmd_from_conn_list(cmd, conn);

			spin_unlock_bh(&conn->cmd_lock);
			if (!(SE_CMD(cmd)) ||
			    !(SE_CMD(cmd)->se_cmd_flags & SCF_SE_LUN_CMD) ||
			    !(SE_CMD(cmd)->transport_wait_for_tasks))
				__iscsi_release_cmd_to_pool(cmd, SESS(conn));
			else
				SE_CMD(cmd)->transport_wait_for_tasks(
						SE_CMD(cmd), 1, 1);
			spin_lock_bh(&conn->cmd_lock);
			continue;
		}

		cmd_count++;
		TRACE(TRACE_ERL2, "Preparing Opcode: 0x%02x, ITT: 0x%08x,"
			" CmdSN: 0x%08x, StatSN: 0x%08x, CID: %hu for"
			" realligence.\n", cmd->iscsi_opcode,
			cmd->init_task_tag, cmd->cmd_sn, cmd->stat_sn,
			conn->cid);

		cmd->deferred_i_state = cmd->i_state;
		cmd->i_state = ISTATE_IN_CONNECTION_RECOVERY;

#ifdef MY_ABC_HERE
		if (cmd->data_direction == DMA_TO_DEVICE)
			iscsi_stop_dataout_timer(cmd);
#else
		if (cmd->data_direction == ISCSI_WRITE)
			iscsi_stop_dataout_timer(cmd);
#endif

		cmd->sess = SESS(conn);

		iscsi_remove_cmd_from_conn_list(cmd, conn);
		spin_unlock_bh(&conn->cmd_lock);

		iscsi_free_all_datain_reqs(cmd);

		if ((SE_CMD(cmd)) &&
		    (SE_CMD(cmd)->se_cmd_flags & SCF_SE_LUN_CMD) &&
		     SE_CMD(cmd)->transport_wait_for_tasks)
			SE_CMD(cmd)->transport_wait_for_tasks(SE_CMD(cmd),
					0, 0);
		 
		spin_lock(&cr->conn_recovery_cmd_lock);
		list_add_tail(&cmd->i_list, &cr->conn_recovery_cmd_list);
		spin_unlock(&cr->conn_recovery_cmd_lock);

		spin_lock_bh(&conn->cmd_lock);
		cmd->cr = cr;
		cmd->conn = NULL;
	}
	spin_unlock_bh(&conn->cmd_lock);

	cr->cid = conn->cid;
	cr->cmd_count = cmd_count;
	cr->maxrecvdatasegmentlength = CONN_OPS(conn)->MaxRecvDataSegmentLength;
	cr->sess = SESS(conn);

	iscsi_attach_inactive_connection_recovery_entry(SESS(conn), cr);

	return 0;
}

int iscsi_connection_recovery_transport_reset(iscsi_conn_t *conn)
{
	atomic_set(&conn->connection_recovery, 1);

	if (iscsi_close_connection(conn) < 0)
		return -1;

	return 0;
}
