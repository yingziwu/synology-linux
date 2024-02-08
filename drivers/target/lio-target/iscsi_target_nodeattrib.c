#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define ISCSI_TARGET_NODEATTRIB_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>

#include <iscsi_linux_defs.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <target/target_core_base.h>
#include <iscsi_target_device.h>
#include <iscsi_target_tpg.h>
#include <target/target_core_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_nodeattrib.h>

#undef ISCSI_TARGET_NODEATTRIB_C

static inline char *iscsi_na_get_initiatorname(
	iscsi_node_acl_t *nacl)
{
#ifdef MY_ABC_HERE
	 
	se_node_acl_t *se_nacl = nacl->se_node_acl;	
#else
	se_node_acl_t *se_nacl = &nacl->se_node_acl;	
#endif

	return &se_nacl->initiatorname[0];
}

void iscsi_set_default_node_attribues(
	iscsi_node_acl_t *acl)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	a->dataout_timeout = NA_DATAOUT_TIMEOUT;
	a->dataout_timeout_retries = NA_DATAOUT_TIMEOUT_RETRIES;
	a->nopin_timeout = NA_NOPIN_TIMEOUT;
	a->nopin_response_timeout = NA_NOPIN_RESPONSE_TIMEOUT;
	a->random_datain_pdu_offsets = NA_RANDOM_DATAIN_PDU_OFFSETS;
	a->random_datain_seq_offsets = NA_RANDOM_DATAIN_SEQ_OFFSETS;
	a->random_r2t_offsets = NA_RANDOM_R2T_OFFSETS;
	a->default_erl = NA_DEFAULT_ERL;
}

extern int iscsi_na_dataout_timeout(
	iscsi_node_acl_t *acl,
	u32 dataout_timeout)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	if (dataout_timeout > NA_DATAOUT_TIMEOUT_MAX) {
		printk(KERN_ERR "Requested DataOut Timeout %u larger than"
			" maximum %u\n", dataout_timeout,
			NA_DATAOUT_TIMEOUT_MAX);
		return -EINVAL;
	} else if (dataout_timeout < NA_DATAOUT_TIMEOUT_MIX) {
		printk(KERN_ERR "Requested DataOut Timeout %u smaller than"
			" minimum %u\n", dataout_timeout,
			NA_DATAOUT_TIMEOUT_MIX);
		return -EINVAL;
	}

	a->dataout_timeout = dataout_timeout;
	TRACE(TRACE_NODEATTRIB, "Set DataOut Timeout to %u for Initiator Node"
		" %s\n", a->dataout_timeout, iscsi_na_get_initiatorname(acl));

	return 0;
}

extern int iscsi_na_dataout_timeout_retries(
	iscsi_node_acl_t *acl,
	u32 dataout_timeout_retries)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	if (dataout_timeout_retries > NA_DATAOUT_TIMEOUT_RETRIES_MAX) {
		printk(KERN_ERR "Requested DataOut Timeout Retries %u larger"
			" than maximum %u", dataout_timeout_retries,
				NA_DATAOUT_TIMEOUT_RETRIES_MAX);
		return -EINVAL;
	} else if (dataout_timeout_retries < NA_DATAOUT_TIMEOUT_RETRIES_MIN) {
		printk(KERN_ERR "Requested DataOut Timeout Retries %u smaller"
			" than minimum %u", dataout_timeout_retries,
				NA_DATAOUT_TIMEOUT_RETRIES_MIN);
		return -EINVAL;
	}

	a->dataout_timeout_retries = dataout_timeout_retries;
	TRACE(TRACE_NODEATTRIB, "Set DataOut Timeout Retries to %u for"
		" Initiator Node %s\n", a->dataout_timeout_retries,
		iscsi_na_get_initiatorname(acl));

	return 0;
}

extern int iscsi_na_nopin_timeout(
	iscsi_node_acl_t *acl,
	u32 nopin_timeout)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;
	iscsi_session_t *sess;
	iscsi_conn_t *conn;
	se_node_acl_t *se_nacl = a->nacl->se_node_acl;
	se_session_t *se_sess;
	u32 orig_nopin_timeout = a->nopin_timeout;

	if (nopin_timeout > NA_NOPIN_TIMEOUT_MAX) {
		printk(KERN_ERR "Requested NopIn Timeout %u larger than maximum"
			" %u\n", nopin_timeout, NA_NOPIN_TIMEOUT_MAX);
		return -EINVAL;
	} else if ((nopin_timeout < NA_NOPIN_TIMEOUT_MIN) &&
		   (nopin_timeout != 0)) {
		printk(KERN_ERR "Requested NopIn Timeout %u smaller than"
			" minimum %u and not 0\n", nopin_timeout,
			NA_NOPIN_TIMEOUT_MIN);
		return -EINVAL;
	}

	a->nopin_timeout = nopin_timeout;
	TRACE(TRACE_NODEATTRIB, "Set NopIn Timeout to %u for Initiator"
		" Node %s\n", a->nopin_timeout,
		iscsi_na_get_initiatorname(acl));
	 
	if (!(orig_nopin_timeout)) {
		spin_lock_bh(&se_nacl->nacl_sess_lock);
		se_sess = se_nacl->nacl_sess;
		if (se_sess) {
			sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

			spin_lock(&sess->conn_lock);
			list_for_each_entry(conn, &sess->sess_conn_list,
					conn_list) {
				if (conn->conn_state !=
						TARG_CONN_STATE_LOGGED_IN)
					continue;

				spin_lock(&conn->nopin_timer_lock);
				__iscsi_start_nopin_timer(conn);
				spin_unlock(&conn->nopin_timer_lock);
			}
			spin_unlock(&sess->conn_lock);
		}
		spin_unlock_bh(&se_nacl->nacl_sess_lock);
	}

	return 0;
}

extern int iscsi_na_nopin_response_timeout(
	iscsi_node_acl_t *acl,
	u32 nopin_response_timeout)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	if (nopin_response_timeout > NA_NOPIN_RESPONSE_TIMEOUT_MAX) {
		printk(KERN_ERR "Requested NopIn Response Timeout %u larger"
			" than maximum %u\n", nopin_response_timeout,
				NA_NOPIN_RESPONSE_TIMEOUT_MAX);
		return -EINVAL;
	} else if (nopin_response_timeout < NA_NOPIN_RESPONSE_TIMEOUT_MIN) {
		printk(KERN_ERR "Requested NopIn Response Timeout %u smaller"
			" than minimum %u\n", nopin_response_timeout,
				NA_NOPIN_RESPONSE_TIMEOUT_MIN);
		return -EINVAL;
	}

	a->nopin_response_timeout = nopin_response_timeout;
	TRACE(TRACE_NODEATTRIB, "Set NopIn Response Timeout to %u for"
		" Initiator Node %s\n", a->nopin_timeout,
		iscsi_na_get_initiatorname(acl));

	return 0;
}

extern int iscsi_na_random_datain_pdu_offsets(
	iscsi_node_acl_t *acl,
	u32 random_datain_pdu_offsets)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	if (random_datain_pdu_offsets != 0 && random_datain_pdu_offsets != 1) {
		printk(KERN_ERR "Requested Random DataIN PDU Offsets: %u not"
			" 0 or 1\n", random_datain_pdu_offsets);
		return -EINVAL;
	}

	a->random_datain_pdu_offsets = random_datain_pdu_offsets;
	TRACE(TRACE_NODEATTRIB, "Set Random DataIN PDU Offsets to %u for"
		" Initiator Node %s\n", a->random_datain_pdu_offsets,
		iscsi_na_get_initiatorname(acl));

	return 0;
}

extern int iscsi_na_random_datain_seq_offsets(
	iscsi_node_acl_t *acl,
	u32 random_datain_seq_offsets)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	if (random_datain_seq_offsets != 0 && random_datain_seq_offsets != 1) {
		printk(KERN_ERR "Requested Random DataIN Sequence Offsets: %u"
			" not 0 or 1\n", random_datain_seq_offsets);
		return -EINVAL;
	}

	a->random_datain_seq_offsets = random_datain_seq_offsets;
	TRACE(TRACE_NODEATTRIB, "Set Random DataIN Sequence Offsets to %u for"
		" Initiator Node %s\n", a->random_datain_seq_offsets,
		iscsi_na_get_initiatorname(acl));

	return 0;
}

extern int iscsi_na_random_r2t_offsets(
	iscsi_node_acl_t *acl,
	u32 random_r2t_offsets)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	if (random_r2t_offsets != 0 && random_r2t_offsets != 1) {
		printk(KERN_ERR "Requested Random R2T Offsets: %u not"
			" 0 or 1\n", random_r2t_offsets);
		return -EINVAL;
	}

	a->random_r2t_offsets = random_r2t_offsets;
	TRACE(TRACE_NODEATTRIB, "Set Random R2T Offsets to %u for"
		" Initiator Node %s\n", a->random_r2t_offsets,
		iscsi_na_get_initiatorname(acl));

	return 0;
}

extern int iscsi_na_default_erl(
	iscsi_node_acl_t *acl,
	u32 default_erl)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	if (default_erl != 0 && default_erl != 1 && default_erl != 2) {
		printk(KERN_ERR "Requested default ERL: %u not 0, 1, or 2\n",
				default_erl);
		return -EINVAL;
	}

	a->default_erl = default_erl;
	TRACE(TRACE_NODEATTRIB, "Set use ERL0 flag to %u for Initiator"
		" Node %s\n", a->default_erl,
		iscsi_na_get_initiatorname(acl));

	return 0;
}
