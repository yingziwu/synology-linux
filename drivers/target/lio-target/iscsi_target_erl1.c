#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define ISCSI_TARGET_ERL1_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_defs.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_crc.h>
#include <iscsi_debug.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <iscsi_target_core.h>
#include <iscsi_target_datain_values.h>
#include <iscsi_target_device.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h>

#undef ISCSI_TARGET_ERL1_C

#define OFFLOAD_BUF_SIZE	32768

int iscsi_dump_data_payload(
	iscsi_conn_t *conn,
	u32 buf_len,
	int dump_padding_digest)
{
	char *buf, pad_bytes[4];
	int ret = DATAOUT_WITHIN_COMMAND_RECOVERY, rx_got;
	u32 length, padding, offset = 0, size;
	struct iovec iov;

	length = (buf_len > OFFLOAD_BUF_SIZE) ? OFFLOAD_BUF_SIZE : buf_len;

	buf = kzalloc(length, GFP_ATOMIC);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate %u bytes for offload"
				" buffer.\n", length);
		return -1;
	}
	memset(&iov, 0, sizeof(struct iovec));

	while (offset < buf_len) {
		size = ((offset + length) > buf_len) ?
			(buf_len - offset) : length;

		iov.iov_len = size;
		iov.iov_base = buf;

		rx_got = rx_data(conn, &iov, 1, size);
		if (rx_got != size) {
			ret = DATAOUT_CANNOT_RECOVER;
			goto out;
		}

		offset += size;
	}

	if (!dump_padding_digest)
		goto out;

	padding = ((-buf_len) & 3);
	if (padding != 0) {
		iov.iov_len = padding;
		iov.iov_base = pad_bytes;

		rx_got = rx_data(conn, &iov, 1, padding);
		if (rx_got != padding) {
			ret = DATAOUT_CANNOT_RECOVER;
			goto out;
		}
	}

	if (CONN_OPS(conn)->DataDigest) {
		u32 data_crc;

		iov.iov_len = CRC_LEN;
		iov.iov_base = &data_crc;

		rx_got = rx_data(conn, &iov, 1, CRC_LEN);
		if (rx_got != CRC_LEN) {
			ret = DATAOUT_CANNOT_RECOVER;
			goto out;
		}
	}

out:
	kfree(buf);
	return ret;
}

static int iscsi_send_recovery_r2t_for_snack(
	iscsi_cmd_t *cmd,
	iscsi_r2t_t *r2t)
{
	 
	spin_lock_bh(&cmd->r2t_lock);
	if (!r2t->sent_r2t) {
		spin_unlock_bh(&cmd->r2t_lock);
		return 0;
	}
	r2t->sent_r2t = 0;
	spin_unlock_bh(&cmd->r2t_lock);

	iscsi_add_cmd_to_immediate_queue(cmd, CONN(cmd), ISTATE_SEND_R2T);

	return 0;
}

static int iscsi_handle_r2t_snack(
	iscsi_cmd_t *cmd,
	unsigned char *buf,
	u32 begrun,
	u32 runlength)
{
	u32 last_r2tsn;
	iscsi_r2t_t *r2t;

	if ((cmd->cmd_flags & ICF_GOT_DATACK_SNACK) &&
	    (begrun <= cmd->acked_data_sn)) {
		printk(KERN_ERR "ITT: 0x%08x, R2T SNACK requesting"
			" retransmission of R2TSN: 0x%08x to 0x%08x but already"
			" acked to  R2TSN: 0x%08x by TMR TASK_REASSIGN,"
			" protocol error.\n", cmd->init_task_tag, begrun,
			(begrun + runlength), cmd->acked_data_sn);

			return iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR,
					1, 0, buf, cmd);
	}

	if (runlength) {
		if ((begrun + runlength) > cmd->r2t_sn) {
			printk(KERN_ERR "Command ITT: 0x%08x received R2T SNACK"
			" with BegRun: 0x%08x, RunLength: 0x%08x, exceeds"
			" current R2TSN: 0x%08x, protocol error.\n",
			cmd->init_task_tag, begrun, runlength, cmd->r2t_sn);
			return iscsi_add_reject_from_cmd(
				REASON_INVALID_PDU_FIELD, 1, 0, buf, cmd);
		}
		last_r2tsn = (begrun + runlength);
	} else
		last_r2tsn = cmd->r2t_sn;

	while (begrun < last_r2tsn) {
		r2t = iscsi_get_holder_for_r2tsn(cmd, begrun);
		if (!(r2t))
			return -1;
		if (iscsi_send_recovery_r2t_for_snack(cmd, r2t) < 0)
			return -1;

		begrun++;
	}

	return 0;
}

int iscsi_create_recovery_datain_values_datasequenceinorder_yes(
	iscsi_cmd_t *cmd,
	iscsi_datain_req_t *dr)
{
	u32 data_sn = 0, data_sn_count = 0;
	u32 pdu_start = 0, seq_no = 0;
	u32 begrun = dr->begrun;
	iscsi_conn_t *conn = CONN(cmd);

	while (begrun > data_sn++) {
		data_sn_count++;
		if ((dr->next_burst_len +
		     CONN_OPS(conn)->MaxRecvDataSegmentLength) <
		     SESS_OPS_C(conn)->MaxBurstLength) {
			dr->read_data_done +=
				CONN_OPS(conn)->MaxRecvDataSegmentLength;
			dr->next_burst_len +=
				CONN_OPS(conn)->MaxRecvDataSegmentLength;
		} else {
			dr->read_data_done +=
				(SESS_OPS_C(conn)->MaxBurstLength -
				 dr->next_burst_len);
			dr->next_burst_len = 0;
			pdu_start += data_sn_count;
			data_sn_count = 0;
			seq_no++;
		}
	}

	if (!SESS_OPS_C(conn)->DataPDUInOrder) {
		cmd->seq_no = seq_no;
		cmd->pdu_start = pdu_start;
		cmd->pdu_send_order = data_sn_count;
	}

	return 0;
}

int iscsi_create_recovery_datain_values_datasequenceinorder_no(
	iscsi_cmd_t *cmd,
	iscsi_datain_req_t *dr)
{
	int found_seq = 0, i;
	u32 data_sn, read_data_done = 0, seq_send_order = 0;
	u32 begrun = dr->begrun;
	u32 runlength = dr->runlength;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_seq_t *first_seq = NULL, *seq = NULL;

	if (!cmd->seq_list) {
		printk(KERN_ERR "iscsi_cmd_t->seq_list is NULL!\n");
		return -1;
	}

	for (i = 0; i < cmd->seq_count; i++) {
		seq = &cmd->seq_list[i];

		if (!seq->seq_send_order)
			first_seq = seq;

		if (!seq->sent) {
#if 0
			printk(KERN_ERR "Ignoring non-sent sequence 0x%08x ->"
				" 0x%08x\n\n", seq->first_datasn,
				seq->last_datasn);
#endif
			continue;
		}

		if ((seq->first_datasn < begrun) &&
				(seq->last_datasn < begrun)) {
#if 0
			printk(KERN_ERR "Pre BegRun sequence 0x%08x ->"
				" 0x%08x\n", seq->first_datasn,
				seq->last_datasn);
#endif
			read_data_done += cmd->seq_list[i].xfer_len;
			seq->next_burst_len = seq->pdu_send_order = 0;
			continue;
		}

		if ((seq->first_datasn <= begrun) &&
				(seq->last_datasn >= begrun)) {
#if 0
			printk(KERN_ERR "Found sequence begrun: 0x%08x in"
				" 0x%08x -> 0x%08x\n", begrun,
				seq->first_datasn, seq->last_datasn);
#endif
			seq_send_order = seq->seq_send_order;
			data_sn = seq->first_datasn;
			seq->next_burst_len = seq->pdu_send_order = 0;
			found_seq = 1;

			if (SESS_OPS_C(conn)->DataPDUInOrder) {
				while (data_sn < begrun) {
					seq->pdu_send_order++;
					read_data_done +=
						CONN_OPS(conn)->MaxRecvDataSegmentLength;
					seq->next_burst_len +=
						CONN_OPS(conn)->MaxRecvDataSegmentLength;
					data_sn++;
				}
			} else {
				int j;
				iscsi_pdu_t *pdu;

				while (data_sn < begrun) {
					seq->pdu_send_order++;

					for (j = 0; j < seq->pdu_count; j++) {
						pdu = &cmd->pdu_list[
							seq->pdu_start + j];
						if (pdu->data_sn == data_sn) {
							read_data_done +=
								pdu->length;
							seq->next_burst_len +=
								pdu->length;
						}
					}
					data_sn++;
				}
			}
			continue;
		}

		if ((seq->first_datasn > begrun) ||
				(seq->last_datasn > begrun)) {
#if 0
			printk(KERN_ERR "Post BegRun sequence 0x%08x -> 0x%08x\n",
					seq->first_datasn, seq->last_datasn);
#endif
			seq->next_burst_len = seq->pdu_send_order = 0;
			continue;
		}
	}

	if (!found_seq) {
		if (!begrun) {
			if (!first_seq) {
				printk(KERN_ERR "ITT: 0x%08x, Begrun: 0x%08x"
					" but first_seq is NULL\n",
					cmd->init_task_tag, begrun);
				return -1;
			}
			seq_send_order = first_seq->seq_send_order;
			seq->next_burst_len = seq->pdu_send_order = 0;
			goto done;
		}

		printk(KERN_ERR "Unable to locate iscsi_seq_t for ITT: 0x%08x,"
			" BegRun: 0x%08x, RunLength: 0x%08x while"
			" DataSequenceInOrder=No and DataPDUInOrder=%s.\n",
				cmd->init_task_tag, begrun, runlength,
			(SESS_OPS_C(conn)->DataPDUInOrder) ? "Yes" : "No");
		return -1;
	}

done:
	dr->read_data_done = read_data_done;
	dr->seq_send_order = seq_send_order;

	return 0;
}

static inline int iscsi_handle_recovery_datain(
	iscsi_cmd_t *cmd,
	unsigned char *buf,
	u32 begrun,
	u32 runlength)
{
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_datain_req_t *dr;
#ifdef SYNO_LIO_TRANSPORT_PATCHES
	se_cmd_t *se_cmd = &cmd->se_cmd;
#else
	se_cmd_t *se_cmd = cmd->se_cmd;
#endif

	if (!(atomic_read(&T_TASK(se_cmd)->t_transport_complete))) {
		printk(KERN_ERR "Ignoring ITT: 0x%08x Data SNACK\n",
				cmd->init_task_tag);
		return 0;
	}

	if ((cmd->cmd_flags & ICF_GOT_DATACK_SNACK) &&
	    (begrun <= cmd->acked_data_sn)) {
		printk(KERN_ERR "ITT: 0x%08x, Data SNACK requesting"
			" retransmission of DataSN: 0x%08x to 0x%08x but"
			" already acked to DataSN: 0x%08x by Data ACK SNACK,"
			" protocol error.\n", cmd->init_task_tag, begrun,
			(begrun + runlength), cmd->acked_data_sn);

		return iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR,
				1, 0, buf, cmd);
	}

	if ((begrun + runlength) > (cmd->data_sn - 1)) {
		printk(KERN_ERR "Initiator requesting BegRun: 0x%08x, RunLength"
			": 0x%08x greater than maximum DataSN: 0x%08x.\n",
				begrun, runlength, (cmd->data_sn - 1));
		return iscsi_add_reject_from_cmd(REASON_INVALID_PDU_FIELD,
				1, 0, buf, cmd);
	}

	dr = iscsi_allocate_datain_req();
	if (!(dr))
		return iscsi_add_reject_from_cmd(REASON_OUT_OF_RESOURCES,
				1, 0, buf, cmd);

	dr->data_sn = dr->begrun = begrun;
	dr->runlength = runlength;
	dr->generate_recovery_values = 1;
	dr->recovery = DATAIN_WITHIN_COMMAND_RECOVERY;

	iscsi_attach_datain_req(cmd, dr);

	cmd->i_state = ISTATE_SEND_DATAIN;
	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);

	return 0;
}

int iscsi_handle_recovery_datain_or_r2t(
	iscsi_conn_t *conn,
	unsigned char *buf,
	u32 init_task_tag,
	u32 targ_xfer_tag,
	u32 begrun,
	u32 runlength)
{
	iscsi_cmd_t *cmd;

	cmd = iscsi_find_cmd_from_itt(conn, init_task_tag);
	if (!(cmd))
		return 0;

	switch (cmd->data_direction) {
#ifdef MY_ABC_HERE
	case DMA_TO_DEVICE:
		return iscsi_handle_r2t_snack(cmd, buf, begrun, runlength);
	case DMA_FROM_DEVICE:
		return iscsi_handle_recovery_datain(cmd, buf, begrun,
				runlength);
#else
	case ISCSI_WRITE:
		return iscsi_handle_r2t_snack(cmd, buf, begrun, runlength);
	case ISCSI_READ:
		return iscsi_handle_recovery_datain(cmd, buf, begrun,
				runlength);
#endif
	default:
		printk(KERN_ERR "Unknown cmd->data_direction: 0x%02x\n",
				cmd->data_direction);
		return -1;
	}

	return 0;
}

int iscsi_handle_status_snack(
	iscsi_conn_t *conn,
	u32 init_task_tag,
	u32 targ_xfer_tag,
	u32 begrun,
	u32 runlength)
{
	u32 last_statsn;
	iscsi_cmd_t *cmd = NULL;

	if (conn->exp_statsn > begrun) {
		printk(KERN_ERR "Got Status SNACK Begrun: 0x%08x, RunLength:"
			" 0x%08x but already got ExpStatSN: 0x%08x on CID:"
			" %hu.\n", begrun, runlength, conn->exp_statsn,
			conn->cid);
		return 0;
	}

	last_statsn = (!runlength) ? conn->stat_sn : (begrun + runlength);

	while (begrun < last_statsn) {
		spin_lock_bh(&conn->cmd_lock);
		list_for_each_entry(cmd, &conn->conn_cmd_list, i_list) {
			if (cmd->stat_sn == begrun)
				break;
		}
		spin_unlock_bh(&conn->cmd_lock);

		if (!cmd) {
			printk(KERN_ERR "Unable to find StatSN: 0x%08x for"
				" a Status SNACK, assuming this was a"
				" protactic SNACK for an untransmitted"
				" StatSN, ignoring.\n", begrun);
			begrun++;
			continue;
		}

		spin_lock_bh(&cmd->istate_lock);
		if (cmd->i_state == ISTATE_SEND_DATAIN) {
			spin_unlock_bh(&cmd->istate_lock);
			printk(KERN_ERR "Ignoring Status SNACK for BegRun:"
				" 0x%08x, RunLength: 0x%08x, assuming this was"
				" a protactic SNACK for an untransmitted"
				" StatSN\n", begrun, runlength);
			begrun++;
			continue;
		}
		spin_unlock_bh(&cmd->istate_lock);

		cmd->i_state = ISTATE_SEND_STATUS_RECOVERY;
		iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
		begrun++;
	}

	return 0;
}

int iscsi_handle_data_ack(
	iscsi_conn_t *conn,
	u32 targ_xfer_tag,
	u32 begrun,
	u32 runlength)
{
	iscsi_cmd_t *cmd = NULL;

	cmd = iscsi_find_cmd_from_ttt(conn, targ_xfer_tag);
	if (!(cmd)) {
		printk(KERN_ERR "Data ACK SNACK for TTT: 0x%08x is"
			" invalid.\n", targ_xfer_tag);
		return -1;
	}

	if (begrun <= cmd->acked_data_sn) {
		printk(KERN_ERR "ITT: 0x%08x Data ACK SNACK BegRUN: 0x%08x is"
			" less than the already acked DataSN: 0x%08x.\n",
			cmd->init_task_tag, begrun, cmd->acked_data_sn);
		return -1;
	}

	cmd->cmd_flags |= ICF_GOT_DATACK_SNACK;
	cmd->acked_data_sn = (begrun - 1);

	TRACE(TRACE_ISCSI, "Received Data ACK SNACK for ITT: 0x%08x,"
		" updated acked DataSN to 0x%08x.\n",
			cmd->init_task_tag, cmd->acked_data_sn);

	return 0;
}

static int iscsi_send_recovery_r2t(
	iscsi_cmd_t *cmd,
	u32 offset,
	u32 xfer_len)
{
	int ret;

	spin_lock_bh(&cmd->r2t_lock);
	ret = iscsi_add_r2t_to_list(cmd, offset, xfer_len, 1, 0);
	spin_unlock_bh(&cmd->r2t_lock);

	return ret;
}

int iscsi_dataout_datapduinorder_no_fbit(
	iscsi_cmd_t *cmd,
	iscsi_pdu_t *pdu)
{
	int i, send_recovery_r2t = 0, recovery = 0;
	u32 length = 0, offset = 0, pdu_count = 0, xfer_len = 0;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_pdu_t *first_pdu = NULL;

	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		for (i = 0; i < cmd->pdu_count; i++) {
			if (cmd->pdu_list[i].seq_no == pdu->seq_no) {
				if (!first_pdu)
					first_pdu = &cmd->pdu_list[i];
				 xfer_len += cmd->pdu_list[i].length;
				 pdu_count++;
			} else if (pdu_count)
				break;
		}
	} else {
		iscsi_seq_t *seq = cmd->seq_ptr;

		first_pdu = &cmd->pdu_list[seq->pdu_start];
		pdu_count = seq->pdu_count;
	}

	if (!first_pdu || !pdu_count)
		return DATAOUT_CANNOT_RECOVER;

	for (i = 0; i < pdu_count; i++) {
		if (first_pdu[i].status == ISCSI_PDU_RECEIVED_OK) {
			if (!send_recovery_r2t)
				continue;

			if (iscsi_send_recovery_r2t(cmd, offset, length) < 0)
				return DATAOUT_CANNOT_RECOVER;

			send_recovery_r2t = length = offset = 0;
			continue;
		}
		 
		recovery = 1;

		if (first_pdu[i].status != ISCSI_PDU_NOT_RECEIVED)
			continue;

		if (!offset)
			offset = first_pdu[i].offset;
		length += first_pdu[i].length;

		send_recovery_r2t = 1;
	}

	if (send_recovery_r2t)
		if (iscsi_send_recovery_r2t(cmd, offset, length) < 0)
			return DATAOUT_CANNOT_RECOVER;

	return (!recovery) ? DATAOUT_NORMAL : DATAOUT_WITHIN_COMMAND_RECOVERY;
}

static int iscsi_recalculate_dataout_values(
	iscsi_cmd_t *cmd,
	u32 pdu_offset,
	u32 pdu_length,
	u32 *r2t_offset,
	u32 *r2t_length)
{
	int i;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_pdu_t *pdu = NULL;

	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		cmd->data_sn = 0;

		if (SESS_OPS_C(conn)->DataPDUInOrder) {
			*r2t_offset = cmd->write_data_done;
			*r2t_length = (cmd->seq_end_offset -
					cmd->write_data_done);
			return 0;
		}

		*r2t_offset = cmd->seq_start_offset;
		*r2t_length = (cmd->seq_end_offset - cmd->seq_start_offset);

		for (i = 0; i < cmd->pdu_count; i++) {
			pdu = &cmd->pdu_list[i];

			if (pdu->status != ISCSI_PDU_RECEIVED_OK)
				continue;

			if ((pdu->offset >= cmd->seq_start_offset) &&
			   ((pdu->offset + pdu->length) <=
			     cmd->seq_end_offset)) {
				if (!cmd->unsolicited_data)
					cmd->next_burst_len -= pdu->length;
				else
					cmd->first_burst_len -= pdu->length;

				cmd->write_data_done -= pdu->length;
				pdu->status = ISCSI_PDU_NOT_RECEIVED;
			}
		}
	} else {
		iscsi_seq_t *seq = NULL;

		seq = iscsi_get_seq_holder(cmd, pdu_offset, pdu_length);
		if (!(seq))
			return -1;

		*r2t_offset = seq->orig_offset;
		*r2t_length = seq->xfer_len;

		cmd->write_data_done -= (seq->offset - seq->orig_offset);
		if (cmd->immediate_data)
			cmd->first_burst_len = cmd->write_data_done;

		seq->data_sn = 0;
		seq->offset = seq->orig_offset;
		seq->next_burst_len = 0;
		seq->status = DATAOUT_SEQUENCE_WITHIN_COMMAND_RECOVERY;

		if (SESS_OPS_C(conn)->DataPDUInOrder)
			return 0;

		for (i = 0; i < seq->pdu_count; i++) {
			pdu = &cmd->pdu_list[i+seq->pdu_start];

			if (pdu->status != ISCSI_PDU_RECEIVED_OK)
				continue;

			pdu->status = ISCSI_PDU_NOT_RECEIVED;
		}
	}

	return 0;
}

int iscsi_recover_dataout_sequence(
	iscsi_cmd_t *cmd,
	u32 pdu_offset,
	u32 pdu_length)
{
	u32 r2t_length = 0, r2t_offset = 0;

	spin_lock_bh(&cmd->istate_lock);
	cmd->cmd_flags |= ICF_WITHIN_COMMAND_RECOVERY;
	spin_unlock_bh(&cmd->istate_lock);

	if (iscsi_recalculate_dataout_values(cmd, pdu_offset, pdu_length,
			&r2t_offset, &r2t_length) < 0)
		return DATAOUT_CANNOT_RECOVER;

	iscsi_send_recovery_r2t(cmd, r2t_offset, r2t_length);

	return DATAOUT_WITHIN_COMMAND_RECOVERY;
}

static inline iscsi_ooo_cmdsn_t *iscsi_allocate_ooo_cmdsn(void)
{
	iscsi_ooo_cmdsn_t *ooo_cmdsn = NULL;

	ooo_cmdsn = kmem_cache_zalloc(lio_ooo_cache, GFP_ATOMIC);
	if (!(ooo_cmdsn)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" iscsi_ooo_cmdsn_t.\n");
		return NULL;
	}
	INIT_LIST_HEAD(&ooo_cmdsn->ooo_list);

	return ooo_cmdsn;
}

static inline int iscsi_attach_ooo_cmdsn(
	iscsi_session_t *sess,
	iscsi_ooo_cmdsn_t *ooo_cmdsn)
{
	iscsi_ooo_cmdsn_t *ooo_tail, *ooo_tmp;
	 
	if (list_empty(&sess->sess_ooo_cmdsn_list))
		list_add_tail(&ooo_cmdsn->ooo_list,
				&sess->sess_ooo_cmdsn_list);
	else {
		ooo_tail = list_entry(sess->sess_ooo_cmdsn_list.prev,
				typeof(*ooo_tail), ooo_list);
		 
		if (ooo_tail->cmdsn < ooo_cmdsn->cmdsn)
			list_add_tail(&ooo_cmdsn->ooo_list,
					&sess->sess_ooo_cmdsn_list);
		else {
			 
			list_for_each_entry(ooo_tmp, &sess->sess_ooo_cmdsn_list,
						ooo_list) {
				while (ooo_tmp->cmdsn < ooo_cmdsn->cmdsn)
					continue;

				list_add(&ooo_cmdsn->ooo_list,
					&ooo_tmp->ooo_list);
				break;
			}
		}
	}
	sess->ooo_cmdsn_count++;

	TRACE(TRACE_CMDSN, "Set out of order CmdSN count for SID:"
		" %u to %hu.\n", sess->sid, sess->ooo_cmdsn_count);

	return 0;
}

void iscsi_remove_ooo_cmdsn(
	iscsi_session_t *sess,
	iscsi_ooo_cmdsn_t *ooo_cmdsn)
{
	list_del(&ooo_cmdsn->ooo_list);
	kmem_cache_free(lio_ooo_cache, ooo_cmdsn);
}

void iscsi_clear_ooo_cmdsns_for_conn(iscsi_conn_t *conn)
{
	iscsi_ooo_cmdsn_t *ooo_cmdsn;
	iscsi_session_t *sess = SESS(conn);

	spin_lock(&sess->cmdsn_lock);
	list_for_each_entry(ooo_cmdsn, &sess->sess_ooo_cmdsn_list, ooo_list) {
		if (ooo_cmdsn->cid != conn->cid)
			continue;

		ooo_cmdsn->cmd = NULL;
	}
	spin_unlock(&sess->cmdsn_lock);
}

int iscsi_execute_ooo_cmdsns(iscsi_session_t *sess)
{
	int ooo_count = 0;
	iscsi_cmd_t *cmd = NULL;
	iscsi_ooo_cmdsn_t *ooo_cmdsn, *ooo_cmdsn_tmp;

	list_for_each_entry_safe(ooo_cmdsn, ooo_cmdsn_tmp,
				&sess->sess_ooo_cmdsn_list, ooo_list) {
		if (ooo_cmdsn->cmdsn != sess->exp_cmd_sn)
			continue;

		if (!ooo_cmdsn->cmd) {
			sess->exp_cmd_sn++;
			iscsi_remove_ooo_cmdsn(sess, ooo_cmdsn);
			continue;
		}

		cmd = ooo_cmdsn->cmd;
		cmd->i_state = cmd->deferred_i_state;
		ooo_count++;
		sess->exp_cmd_sn++;
		TRACE(TRACE_CMDSN, "Executing out of order CmdSN: 0x%08x,"
			" incremented ExpCmdSN to 0x%08x.\n",
			cmd->cmd_sn, sess->exp_cmd_sn);

		iscsi_remove_ooo_cmdsn(sess, ooo_cmdsn);

		if (iscsi_execute_cmd(cmd, 1) < 0)
			return -1;

		continue;
	}

	return ooo_count;
}

int iscsi_execute_cmd(iscsi_cmd_t *cmd, int ooo)
{
#ifdef SYNO_LIO_TRANSPORT_PATCHES
	se_cmd_t *se_cmd = &cmd->se_cmd;
#else
	se_cmd_t *se_cmd = cmd->se_cmd;
#endif
	int lr = 0;

	spin_lock_bh(&cmd->istate_lock);
	if (ooo)
		cmd->cmd_flags &= ~ICF_OOO_CMDSN;

	switch (cmd->iscsi_opcode) {
	case ISCSI_INIT_SCSI_CMND:
		 
		if (se_cmd->se_cmd_flags & SCF_SCSI_CDB_EXCEPTION) {
			if (se_cmd->se_cmd_flags &
					SCF_SCSI_RESERVATION_CONFLICT) {
				cmd->i_state = ISTATE_SEND_STATUS;
				spin_unlock_bh(&cmd->istate_lock);
				iscsi_add_cmd_to_response_queue(cmd, CONN(cmd),
						cmd->i_state);
				return 0;
			}
			spin_unlock_bh(&cmd->istate_lock);
			 
			if (transport_check_aborted_status(se_cmd,
					(cmd->unsolicited_data == 0)) != 0)
				return 0;
			 
			return transport_send_check_condition_and_sense(se_cmd,
					se_cmd->scsi_sense_reason, 0);
		}
		 
		if (cmd->immediate_data) {
			if (cmd->cmd_flags & ICF_GOT_LAST_DATAOUT) {
				spin_unlock_bh(&cmd->istate_lock);
#ifdef SYNO_LIO_TRANSPORT_PATCHES
				return transport_generic_handle_data(
						&cmd->se_cmd);
#else
				return transport_generic_handle_data(
						cmd->se_cmd);
#endif
			}
			spin_unlock_bh(&cmd->istate_lock);

			if (!(cmd->cmd_flags &
					ICF_NON_IMMEDIATE_UNSOLICITED_DATA)) {
				 
				if (transport_check_aborted_status(se_cmd, 1)
						!= 0)
					return 0;

				iscsi_set_dataout_sequence_values(cmd);
				iscsi_build_r2ts_for_cmd(cmd, CONN(cmd), 0);
			}
			return 0;
		}
		 
		spin_unlock_bh(&cmd->istate_lock);

#ifdef MY_ABC_HERE
		if ((cmd->data_direction == DMA_TO_DEVICE) &&
		    !(cmd->cmd_flags & ICF_NON_IMMEDIATE_UNSOLICITED_DATA)) {
#else
		if ((cmd->data_direction == ISCSI_WRITE) &&
		    !(cmd->cmd_flags & ICF_NON_IMMEDIATE_UNSOLICITED_DATA)) {
#endif
			 
			if (transport_check_aborted_status(se_cmd, 1) != 0)
				return 0;

			iscsi_set_dataout_sequence_values(cmd);
			spin_lock_bh(&cmd->dataout_timeout_lock);
			iscsi_start_dataout_timer(cmd, CONN(cmd));
			spin_unlock_bh(&cmd->dataout_timeout_lock);
		}
#ifdef SYNO_LIO_TRANSPORT_PATCHES
		return transport_generic_handle_cdb(&cmd->se_cmd);
#else
		return transport_generic_handle_cdb(cmd->se_cmd);
#endif

	case ISCSI_INIT_NOP_OUT:
	case ISCSI_INIT_TEXT_CMND:
		spin_unlock_bh(&cmd->istate_lock);
		iscsi_add_cmd_to_response_queue(cmd, CONN(cmd), cmd->i_state);
		break;
	case ISCSI_INIT_TASK_MGMT_CMND:
		if (se_cmd->se_cmd_flags & SCF_SCSI_CDB_EXCEPTION) {
			spin_unlock_bh(&cmd->istate_lock);
			iscsi_add_cmd_to_response_queue(cmd, CONN(cmd),
					cmd->i_state);
			return 0;
		}
		spin_unlock_bh(&cmd->istate_lock);

		return transport_generic_handle_tmr(SE_CMD(cmd));
	case ISCSI_INIT_LOGOUT_CMND:
		spin_unlock_bh(&cmd->istate_lock);
		switch (cmd->logout_reason) {
		case CLOSESESSION:
			lr = iscsi_logout_closesession(cmd, CONN(cmd));
			break;
		case CLOSECONNECTION:
			lr = iscsi_logout_closeconnection(cmd, CONN(cmd));
			break;
		case REMOVECONNFORRECOVERY:
			lr = iscsi_logout_removeconnforrecovery(cmd, CONN(cmd));
			break;
		default:
			printk(KERN_ERR "Unknown iSCSI Logout Request Code:"
				" 0x%02x\n", cmd->logout_reason);
			return -1;
		}

		return lr;
	default:
		spin_unlock_bh(&cmd->istate_lock);
		printk(KERN_ERR "Cannot perform out of order execution for"
		" unknown iSCSI Opcode: 0x%02x\n", cmd->iscsi_opcode);
		return -1;
	}

	return 0;
}

void iscsi_free_all_ooo_cmdsns(iscsi_session_t *sess)
{
	iscsi_ooo_cmdsn_t *ooo_cmdsn, *ooo_cmdsn_tmp;

	spin_lock(&sess->cmdsn_lock);
	list_for_each_entry_safe(ooo_cmdsn, ooo_cmdsn_tmp,
			&sess->sess_ooo_cmdsn_list, ooo_list) {

		list_del(&ooo_cmdsn->ooo_list);
		kmem_cache_free(lio_ooo_cache, ooo_cmdsn);
	}
	spin_unlock(&sess->cmdsn_lock);
}

int iscsi_handle_ooo_cmdsn(
	iscsi_session_t *sess,
	iscsi_cmd_t *cmd,
	u32 cmdsn)
{
	int batch = 0;
	iscsi_ooo_cmdsn_t *ooo_cmdsn = NULL, *ooo_tail = NULL;

	sess->cmdsn_outoforder = 1;

	cmd->deferred_i_state		= cmd->i_state;
	cmd->i_state			= ISTATE_DEFERRED_CMD;
	cmd->cmd_flags			|= ICF_OOO_CMDSN;

	if (list_empty(&sess->sess_ooo_cmdsn_list))
		batch = 1;
	else {
		ooo_tail = list_entry(sess->sess_ooo_cmdsn_list.prev,
				typeof(*ooo_tail), ooo_list);
		if (ooo_tail->cmdsn != (cmdsn - 1))
			batch = 1;
	}

	ooo_cmdsn = iscsi_allocate_ooo_cmdsn();
	if (!(ooo_cmdsn))
		return CMDSN_ERROR_CANNOT_RECOVER;

	ooo_cmdsn->cmd			= cmd;
	ooo_cmdsn->batch_count		= (batch) ?
					  (cmdsn - sess->exp_cmd_sn) : 1;
	ooo_cmdsn->cid			= CONN(cmd)->cid;
	ooo_cmdsn->exp_cmdsn		= sess->exp_cmd_sn;
	ooo_cmdsn->cmdsn		= cmdsn;

	if (iscsi_attach_ooo_cmdsn(sess, ooo_cmdsn) < 0) {
		kmem_cache_free(lio_ooo_cache, ooo_cmdsn);
		return CMDSN_ERROR_CANNOT_RECOVER;
	}

	return CMDSN_HIGHER_THAN_EXP;
}

static int iscsi_set_dataout_timeout_values(
	iscsi_cmd_t *cmd,
	u32 *offset,
	u32 *length)
{
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_r2t_t *r2t;

	if (cmd->unsolicited_data) {
		*offset = 0;
		*length = (SESS_OPS_C(conn)->FirstBurstLength >
			   cmd->data_length) ?
			   cmd->data_length :
			   SESS_OPS_C(conn)->FirstBurstLength;
		return 0;
	}

	spin_lock_bh(&cmd->r2t_lock);
	if (list_empty(&cmd->cmd_r2t_list)) {
		printk(KERN_ERR "cmd->cmd_r2t_list is empty!\n");
		spin_unlock_bh(&cmd->r2t_lock);
		return -1;
	}

	list_for_each_entry(r2t, &cmd->cmd_r2t_list, r2t_list)
		if (r2t->sent_r2t && !r2t->recovery_r2t && !r2t->seq_complete)
			break;

	if (!r2t) {
		printk(KERN_ERR "Unable to locate any incomplete DataOUT"
			" sequences for ITT: 0x%08x.\n", cmd->init_task_tag);
		spin_unlock_bh(&cmd->r2t_lock);
		return -1;
	}

	*offset = r2t->offset;
	*length = r2t->xfer_len;

	spin_unlock_bh(&cmd->r2t_lock);
	return 0;
}

static void iscsi_handle_dataout_timeout(unsigned long data)
{
	u32 pdu_length = 0, pdu_offset = 0;
	u32 r2t_length = 0, r2t_offset = 0;
	iscsi_cmd_t *cmd = (iscsi_cmd_t *) data;
	iscsi_conn_t *conn = conn = CONN(cmd);
	iscsi_session_t *sess = NULL;
	iscsi_node_attrib_t *na;

	iscsi_inc_conn_usage_count(conn);

	spin_lock_bh(&cmd->dataout_timeout_lock);
	if (cmd->dataout_timer_flags & DATAOUT_TF_STOP) {
		spin_unlock_bh(&cmd->dataout_timeout_lock);
		iscsi_dec_conn_usage_count(conn);
		return;
	}
	cmd->dataout_timer_flags &= ~DATAOUT_TF_RUNNING;
	sess = SESS(conn);
	na = iscsi_tpg_get_node_attrib(sess);

	if (!SESS_OPS(sess)->ErrorRecoveryLevel) {
		TRACE(TRACE_ERL0, "Unable to recover from DataOut timeout while"
			" in ERL=0.\n");
		goto failure;
	}

	if (++cmd->dataout_timeout_retries == na->dataout_timeout_retries) {
		TRACE(TRACE_TIMER, "Command ITT: 0x%08x exceeded max retries"
			" for DataOUT timeout %u, closing iSCSI connection.\n",
			cmd->init_task_tag, na->dataout_timeout_retries);
		goto failure;
	}

	cmd->cmd_flags |= ICF_WITHIN_COMMAND_RECOVERY;

	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		if (SESS_OPS_C(conn)->DataPDUInOrder) {
			pdu_offset = cmd->write_data_done;
			if ((pdu_offset + (SESS_OPS_C(conn)->MaxBurstLength -
			     cmd->next_burst_len)) > cmd->data_length)
				pdu_length = (cmd->data_length -
					cmd->write_data_done);
			else
				pdu_length = (SESS_OPS_C(conn)->MaxBurstLength -
						cmd->next_burst_len);
		} else {
			pdu_offset = cmd->seq_start_offset;
			pdu_length = (cmd->seq_end_offset -
				cmd->seq_start_offset);
		}
	} else {
		if (iscsi_set_dataout_timeout_values(cmd, &pdu_offset,
				&pdu_length) < 0)
			goto failure;
	}

	if (iscsi_recalculate_dataout_values(cmd, pdu_offset, pdu_length,
			&r2t_offset, &r2t_length) < 0)
		goto failure;

	TRACE(TRACE_TIMER, "Command ITT: 0x%08x timed out waiting for"
		" completion of %sDataOUT Sequence Offset: %u, Length: %u\n",
		cmd->init_task_tag, (cmd->unsolicited_data) ? "Unsolicited " :
		"", r2t_offset, r2t_length);

	if (iscsi_send_recovery_r2t(cmd, r2t_offset, r2t_length) < 0)
		goto failure;

	iscsi_start_dataout_timer(cmd, conn);
	spin_unlock_bh(&cmd->dataout_timeout_lock);
	iscsi_dec_conn_usage_count(conn);

	return;

failure:
	spin_unlock_bh(&cmd->dataout_timeout_lock);
	iscsi_cause_connection_reinstatement(conn, 0);
	iscsi_dec_conn_usage_count(conn);

	return;
}

void iscsi_mod_dataout_timer(iscsi_cmd_t *cmd)
{
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_attrib_t *na = na = iscsi_tpg_get_node_attrib(sess);

	spin_lock_bh(&cmd->dataout_timeout_lock);
	if (!(cmd->dataout_timer_flags & DATAOUT_TF_RUNNING)) {
		spin_unlock_bh(&cmd->dataout_timeout_lock);
		return;
	}

	MOD_TIMER(&cmd->dataout_timer, na->dataout_timeout);
	TRACE(TRACE_TIMER, "Updated DataOUT timer for ITT: 0x%08x",
			cmd->init_task_tag);
	spin_unlock_bh(&cmd->dataout_timeout_lock);
}

void iscsi_start_dataout_timer(
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_attrib_t *na = na = iscsi_tpg_get_node_attrib(sess);

	if (cmd->dataout_timer_flags & DATAOUT_TF_RUNNING)
		return;

	TRACE(TRACE_TIMER, "Starting DataOUT timer for ITT: 0x%08x on"
		" CID: %hu.\n", cmd->init_task_tag, conn->cid);

	init_timer(&cmd->dataout_timer);
	SETUP_TIMER(cmd->dataout_timer, na->dataout_timeout, cmd,
			iscsi_handle_dataout_timeout);
	cmd->dataout_timer_flags &= ~DATAOUT_TF_STOP;
	cmd->dataout_timer_flags |= DATAOUT_TF_RUNNING;
	add_timer(&cmd->dataout_timer);
}

void iscsi_stop_dataout_timer(iscsi_cmd_t *cmd)
{
	spin_lock_bh(&cmd->dataout_timeout_lock);
	if (!(cmd->dataout_timer_flags & DATAOUT_TF_RUNNING)) {
		spin_unlock_bh(&cmd->dataout_timeout_lock);
		return;
	}
	cmd->dataout_timer_flags |= DATAOUT_TF_STOP;
	spin_unlock_bh(&cmd->dataout_timeout_lock);

	del_timer_sync(&cmd->dataout_timer);

	spin_lock_bh(&cmd->dataout_timeout_lock);
	cmd->dataout_timer_flags &= ~DATAOUT_TF_RUNNING;
	TRACE(TRACE_TIMER, "Stopped DataOUT Timer for ITT: 0x%08x\n",
			cmd->init_task_tag);
	spin_unlock_bh(&cmd->dataout_timeout_lock);
}
