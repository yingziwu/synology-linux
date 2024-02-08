#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define ISCSI_TARGET_LOGIN_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/ipv6.h>

#include <iscsi_linux_defs.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_debug.h>
#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <iscsi_target_core.h>
#include <iscsi_target_device.h>
#include <iscsi_target_nego.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl2.h>
#include <iscsi_target_login.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

#undef ISCSI_TARGET_LOGIN_C

static void iscsi_login_init_conn(iscsi_conn_t *conn)
{
	INIT_LIST_HEAD(&conn->conn_list);
	INIT_LIST_HEAD(&conn->conn_cmd_list);
	INIT_LIST_HEAD(&conn->immed_queue_list);
	INIT_LIST_HEAD(&conn->response_queue_list);
	init_MUTEX_LOCKED(&conn->conn_post_wait_sem);
	init_MUTEX_LOCKED(&conn->conn_wait_sem);
	init_MUTEX_LOCKED(&conn->conn_wait_rcfr_sem);
	init_MUTEX_LOCKED(&conn->conn_waiting_on_uc_sem);
	init_MUTEX_LOCKED(&conn->conn_logout_sem);
	init_MUTEX_LOCKED(&conn->rx_half_close_sem);
	init_MUTEX_LOCKED(&conn->tx_half_close_sem);
	init_MUTEX_LOCKED(&conn->tx_sem);
	spin_lock_init(&conn->cmd_lock);
	spin_lock_init(&conn->conn_usage_lock);
	spin_lock_init(&conn->immed_queue_lock);
	spin_lock_init(&conn->netif_lock);
	spin_lock_init(&conn->nopin_timer_lock);
	spin_lock_init(&conn->response_queue_lock);
	spin_lock_init(&conn->state_lock);
}

static int iscsi_login_check_initiator_version(
	iscsi_conn_t *conn,
	u8 version_max,
	u8 version_min)
{
	if ((version_max != 0x00) || (version_min != 0x00)) {
		printk(KERN_ERR "Unsupported iSCSI IETF Pre-RFC Revision,"
			" version Min/Max 0x%02x/0x%02x, rejecting login.\n",
			version_min, version_max);
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_VERSION_NOT_SUPPORTED);
		return -1;
	}

	return 0;
}

int iscsi_check_for_session_reinstatement(iscsi_conn_t *conn)
{
	int sessiontype;
	iscsi_param_t *initiatorname_param = NULL, *sessiontype_param = NULL;
	iscsi_portal_group_t *tpg = conn->tpg;
	iscsi_session_t *sess = NULL, *sess_p = NULL;
	se_portal_group_t *se_tpg = tpg->tpg_se_tpg;
	se_session_t *se_sess, *se_sess_tmp;

	initiatorname_param = iscsi_find_param_from_key(
			INITIATORNAME, conn->param_list);
	if (!(initiatorname_param))
		return -1;

	sessiontype_param = iscsi_find_param_from_key(
			SESSIONTYPE, conn->param_list);
	if (!(sessiontype_param))
		return -1;

	sessiontype = (strncmp(sessiontype_param->value, NORMAL, 6)) ? 1 : 0;

	spin_lock_bh(&se_tpg->session_lock);
	list_for_each_entry_safe(se_sess, se_sess_tmp, &se_tpg->tpg_sess_list,
			sess_list) {

		sess_p = (iscsi_session_t *)se_sess->fabric_sess_ptr;
		spin_lock(&sess_p->conn_lock);
		if (atomic_read(&sess_p->session_fall_back_to_erl0) ||
		    atomic_read(&sess_p->session_logout) ||
		    (sess_p->time2retain_timer_flags & T2R_TF_EXPIRED)) {
			spin_unlock(&sess_p->conn_lock);
			continue;
		}
		if (!memcmp((void *)sess_p->isid, (void *)SESS(conn)->isid, 6) &&
		   (!strcmp((void *)SESS_OPS(sess_p)->InitiatorName,
			    (void *)initiatorname_param->value) &&
		   (SESS_OPS(sess_p)->SessionType == sessiontype))) {
			atomic_set(&sess_p->session_reinstatement, 1);
			spin_unlock(&sess_p->conn_lock);
			iscsi_inc_session_usage_count(sess_p);
			iscsi_stop_time2retain_timer(sess_p);
			sess = sess_p;
			break;
		}
		spin_unlock(&sess_p->conn_lock);
	}
	spin_unlock_bh(&se_tpg->session_lock);
	 
	if (!sess)
		return 0;

	TRACE(TRACE_ERL0, "%s iSCSI Session SID %u is still active for %s,"
		" preforming session reinstatement.\n", (sessiontype) ?
		"Discovery" : "Normal", sess->sid,
		SESS_OPS(sess)->InitiatorName);

	spin_lock_bh(&sess->conn_lock);
	if (sess->session_state == TARG_SESS_STATE_FAILED) {
		spin_unlock_bh(&sess->conn_lock);
		iscsi_dec_session_usage_count(sess);
		return iscsi_close_session(sess);
	}
	spin_unlock_bh(&sess->conn_lock);

	iscsi_stop_session(sess, 1, 1);
	iscsi_dec_session_usage_count(sess);

	return iscsi_close_session(sess);
}

static void iscsi_login_set_conn_values(
	iscsi_session_t *sess,
	iscsi_conn_t *conn,
	u16 cid)
{
	conn->sess		= sess;
	conn->cid 		= cid;
	 
	get_random_bytes(&conn->stat_sn, sizeof(u32));

	down(&iscsi_global->auth_id_sem);
	conn->auth_id		= iscsi_global->auth_id++;
	up(&iscsi_global->auth_id_sem);
}

static int iscsi_login_zero_tsih_s1(
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	iscsi_session_t *sess = NULL;
	struct iscsi_init_login_cmnd *pdu = (struct iscsi_init_login_cmnd *)buf;

	sess = kmem_cache_zalloc(lio_sess_cache, GFP_KERNEL);
	if (!(sess)) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		printk(KERN_ERR "Could not allocate memory for session\n");
		return -1;
	}

	iscsi_login_set_conn_values(sess, conn, pdu->cid);
	sess->init_task_tag	= pdu->init_task_tag;
	memcpy((void *)&sess->isid, (void *)pdu->isid, 6);
	sess->exp_cmd_sn	= pdu->cmd_sn;
	INIT_LIST_HEAD(&sess->sess_conn_list);
	INIT_LIST_HEAD(&sess->sess_ooo_cmdsn_list);
	INIT_LIST_HEAD(&sess->cr_active_list);
	INIT_LIST_HEAD(&sess->cr_inactive_list);
	init_MUTEX_LOCKED(&sess->async_msg_sem);
	init_MUTEX_LOCKED(&sess->reinstatement_sem);
	init_MUTEX_LOCKED(&sess->session_wait_sem);
	init_MUTEX_LOCKED(&sess->session_waiting_on_uc_sem);
	spin_lock_init(&sess->cmdsn_lock);
	spin_lock_init(&sess->conn_lock);
	spin_lock_init(&sess->cr_a_lock);
	spin_lock_init(&sess->cr_i_lock);
	spin_lock_init(&sess->session_usage_lock);
	spin_lock_init(&sess->ttt_lock);
#ifdef SNMP_SUPPORT
	sess->session_index = iscsi_get_new_index(ISCSI_SESSION_INDEX);
	sess->creation_time = get_jiffies_64();
	spin_lock_init(&sess->session_stats_lock);
#endif  

	sess->max_cmd_sn	= pdu->cmd_sn;

	sess->sess_ops = kzalloc(sizeof(iscsi_sess_ops_t), GFP_KERNEL);
	if (!(sess->sess_ops)) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		printk(KERN_ERR "Unable to allocate memory for"
				" iscsi_sess_ops_t.\n");
		return -1;
	}

	sess->se_sess = transport_init_session();
	if (!(sess->se_sess)) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}

	return 0;
}

static int iscsi_login_zero_tsih_s2 (
	iscsi_conn_t *conn)
{
	iscsi_node_attrib_t *na;
	iscsi_session_t *sess = conn->sess;
	unsigned char buf[32];

	sess->tpg = conn->tpg;

	sess->tsih = ++ISCSI_TPG_S(sess)->ntsih;
	if (!(sess->tsih))
		sess->tsih = ++ISCSI_TPG_S(sess)->ntsih;

	if (iscsi_copy_param_list(&conn->param_list,
				ISCSI_TPG_C(conn)->param_list, 1) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}

	iscsi_set_keys_to_negotiate(TARGET, 0, conn->param_list);

	if (SESS_OPS(sess)->SessionType)
		return iscsi_set_keys_irrelevant_for_discovery(
				conn->param_list);

	na = iscsi_tpg_get_node_attrib(sess);

	memset(buf, 0, 32);
	sprintf(buf, "TargetPortalGroupTag=%hu", ISCSI_TPG_S(sess)->tpgt);
	if (iscsi_change_param_value(buf, TARGET, conn->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}

	memset(buf, 0, 32);
	sprintf(buf, "ErrorRecoveryLevel=%d", na->default_erl);
	if (iscsi_change_param_value(buf, TARGET, conn->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}

	if (iscsi_login_disable_FIM_keys(conn->param_list, conn) < 0)
		return -1;

	return 0;
}

int iscsi_login_disable_FIM_keys(
	iscsi_param_list_t *param_list,
	iscsi_conn_t *conn)
{
	iscsi_param_t *param;

	param = iscsi_find_param_from_key("OFMarker", param_list);
	if (!(param)) {
		printk(KERN_ERR "iscsi_find_param_from_key() for"
				" OFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}
	param->state &= ~PSTATE_NEGOTIATE;

	param = iscsi_find_param_from_key("OFMarkInt", param_list);
	if (!(param)) {
		printk(KERN_ERR "iscsi_find_param_from_key() for"
				" IFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}
	param->state &= ~PSTATE_NEGOTIATE;

	param = iscsi_find_param_from_key("IFMarker", param_list);
	if (!(param)) {
		printk(KERN_ERR "iscsi_find_param_from_key() for"
				" IFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}
	param->state &= ~PSTATE_NEGOTIATE;

	param = iscsi_find_param_from_key("IFMarkInt", param_list);
	if (!(param)) {
		printk(KERN_ERR "iscsi_find_param_from_key() for"
				" IFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}
	param->state &= ~PSTATE_NEGOTIATE;

	return 0;
}

static int iscsi_login_non_zero_tsih_s1 (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	struct iscsi_init_login_cmnd *pdu = (struct iscsi_init_login_cmnd *)buf;

	iscsi_login_set_conn_values(NULL, conn, pdu->cid);
	return 0;
}

static int iscsi_login_non_zero_tsih_s2(
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	iscsi_portal_group_t *tpg = conn->tpg;
	iscsi_session_t *sess = NULL, *sess_p = NULL;
	se_portal_group_t *se_tpg = tpg->tpg_se_tpg;
	se_session_t *se_sess, *se_sess_tmp;
	struct iscsi_init_login_cmnd *pdu = (struct iscsi_init_login_cmnd *)buf;

	spin_lock_bh(&se_tpg->session_lock);
	list_for_each_entry_safe(se_sess, se_sess_tmp, &se_tpg->tpg_sess_list,
			sess_list) {

		sess_p = (iscsi_session_t *)se_sess->fabric_sess_ptr;
		if (atomic_read(&sess_p->session_fall_back_to_erl0) ||
		    atomic_read(&sess_p->session_logout) ||
		   (sess_p->time2retain_timer_flags & T2R_TF_EXPIRED))
			continue;
		if (!(memcmp((const void *)sess_p->isid,
		     (const void *)pdu->isid, 6)) &&
		     (sess_p->tsih == pdu->tsih)) {
			iscsi_inc_session_usage_count(sess_p);
			iscsi_stop_time2retain_timer(sess_p);
			sess = sess_p;
			break;
		}
	}
	spin_unlock_bh(&se_tpg->session_lock);

	if (!sess) {
		printk(KERN_ERR "Initiator attempting to add a connection to"
			" a non-existent session, rejecting iSCSI Login.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_SESSION_DOES_NOT_EXIST);
		return -1;
	}

	spin_lock_bh(&sess->conn_lock);
	if (sess->session_state == TARG_SESS_STATE_FAILED)
		atomic_set(&sess->session_continuation, 1);
	spin_unlock_bh(&sess->conn_lock);

	iscsi_login_set_conn_values(sess, conn, pdu->cid);

	if (iscsi_copy_param_list(&conn->param_list,
			ISCSI_TPG_C(conn)->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}

	iscsi_set_keys_to_negotiate(TARGET, 0, conn->param_list);

	memset(buf, 0, 32);
	sprintf(buf, "TargetPortalGroupTag=%hu", ISCSI_TPG_S(sess)->tpgt);
	if (iscsi_change_param_value(buf, TARGET, conn->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return -1;
	}

	return iscsi_login_disable_FIM_keys(conn->param_list, conn);
}

int iscsi_login_post_auth_non_zero_tsih(
	iscsi_conn_t *conn,
	u16 cid,
	u32 exp_statsn)
{
	iscsi_conn_t *conn_ptr = NULL;
	iscsi_conn_recovery_t *cr = NULL;
	iscsi_session_t *sess = SESS(conn);

	conn_ptr = iscsi_get_conn_from_cid_rcfr(sess, cid);
	if ((conn_ptr)) {
		printk(KERN_ERR "Connection exists with CID %hu for %s,"
			" performing connection reinstatement.\n",
			conn_ptr->cid, SESS_OPS(sess)->InitiatorName);

		iscsi_connection_reinstatement_rcfr(conn_ptr);
		iscsi_dec_conn_usage_count(conn_ptr);
	}

	if (SESS_OPS(sess)->ErrorRecoveryLevel == 2) {
		cr = iscsi_get_inactive_connection_recovery_entry(
				sess, cid);
		if ((cr)) {
			TRACE(TRACE_ERL2, "Performing implicit logout"
				" for connection recovery on CID: %hu\n",
					conn->cid);
			iscsi_discard_cr_cmds_by_expstatsn(cr, exp_statsn);
		}
	}

	TRACE(TRACE_LOGIN, "Adding CID %hu to existing session for %s.\n",
			cid, SESS_OPS(sess)->InitiatorName);

	if ((atomic_read(&sess->nconn) + 1) > SESS_OPS(sess)->MaxConnections) {
		printk(KERN_ERR "Adding additional connection to this session"
			" would exceed MaxConnections %d, login failed.\n",
				SESS_OPS(sess)->MaxConnections);
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_TOO_MANY_CONNECTIONS);
		return -1;
	}

	return 0;
}

static void iscsi_post_login_start_timers(iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);

#if 0
	iscsi_get_network_interface_from_conn(conn);

	spin_lock_bh(&conn->netif_lock);
	iscsi_start_netif_timer(conn);
	spin_unlock_bh(&conn->netif_lock);
#endif
	if (!SESS_OPS(sess)->SessionType)
		iscsi_start_nopin_timer(conn);
}

static int iscsi_post_login_handler(
	iscsi_np_t *np,
	iscsi_conn_t *conn,
	u8 zero_tsih)
{
	int stop_timer = 0;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf1_ipv4[IPV4_BUF_SIZE];
	unsigned char *ip, *ip_np;
	iscsi_session_t *sess = SESS(conn);
	se_session_t *se_sess = sess->se_sess;
	iscsi_portal_group_t *tpg = ISCSI_TPG_S(sess);
	se_portal_group_t *se_tpg = tpg->tpg_se_tpg;
	se_thread_set_t *ts;

	iscsi_inc_conn_usage_count(conn);

#ifdef SNMP_SUPPORT
	iscsi_collect_login_stats(conn, STAT_CLASS_SUCCESS,
			STAT_DETAIL_SUCCESS);
#endif

	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_LOGGED_IN.\n");
	conn->conn_state = TARG_CONN_STATE_LOGGED_IN;

	iscsi_set_connection_parameters(conn->conn_ops, conn->param_list);
	iscsi_set_sync_and_steering_values(conn);

	if (np->np_net_size == IPV6_ADDRESS_SPACE) {
		ip = &conn->ipv6_login_ip[0];
		ip_np = &np->np_ipv6[0];
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		memset(buf1_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, conn->login_ip);
		iscsi_ntoa2(buf1_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
		ip_np = &buf1_ipv4[0];
	}

	ts = iscsi_get_thread_set(TARGET);
	if (!zero_tsih) {
		iscsi_set_session_parameters(sess->sess_ops,
				conn->param_list, 0);
		iscsi_release_param_list(conn->param_list);
		conn->param_list = NULL;

		spin_lock_bh(&sess->conn_lock);
		atomic_set(&sess->session_continuation, 0);
		if (sess->session_state == TARG_SESS_STATE_FAILED) {
			TRACE(TRACE_STATE, "Moving to"
					" TARG_SESS_STATE_LOGGED_IN.\n");
			sess->session_state = TARG_SESS_STATE_LOGGED_IN;
			stop_timer = 1;
		}

#ifdef MY_ABC_HERE
		if( sess->sess_ops->SessionType ) {
			printk(KERN_ERR "iSCSI - Discovery session from [%s]\n", ip);
		} else {
			printk(KERN_ERR "iSCSI - Client [%s] logged in from [%s] to [%s:%hu]\n",
					sess->sess_ops->InitiatorName, ip, ip_np, np->np_port);
		}
#else
		printk(KERN_INFO "iSCSI Login successful on CID: %hu from %s to"
			" %s:%hu,%hu\n", conn->cid, ip, ip_np,
				np->np_port, tpg->tpgt);
#endif

		list_add_tail(&conn->conn_list, &sess->sess_conn_list);
		atomic_inc(&sess->nconn);
#ifndef MY_ABC_HERE
		printk(KERN_INFO "Incremented iSCSI Connection count to %hu"
			" from node: %s\n", atomic_read(&sess->nconn),
			SESS_OPS(sess)->InitiatorName);
#endif
		spin_unlock_bh(&sess->conn_lock);

		iscsi_post_login_start_timers(conn);
		iscsi_activate_thread_set(conn, ts);
		iscsi_dec_conn_usage_count(conn);
		if (stop_timer) {
			spin_lock_bh(&se_tpg->session_lock);
			iscsi_stop_time2retain_timer(sess);
			spin_unlock_bh(&se_tpg->session_lock);
		}
		iscsi_dec_session_usage_count(sess);
		return 0;
	}

	iscsi_set_session_parameters(sess->sess_ops, conn->param_list, 1);
	iscsi_release_param_list(conn->param_list);
	conn->param_list = NULL;

	iscsi_determine_maxcmdsn(sess);

	spin_lock_bh(&se_tpg->session_lock);
	__transport_register_session(sess->tpg->tpg_se_tpg,
			se_sess->se_node_acl, se_sess, (void *)sess);
	TRACE(TRACE_STATE, "Moving to TARG_SESS_STATE_LOGGED_IN.\n");
	sess->session_state = TARG_SESS_STATE_LOGGED_IN;

#ifdef MY_ABC_HERE
	if( sess->sess_ops->SessionType ) {
		printk(KERN_ERR "iSCSI - Discovery session from [%s]\n", ip);
	} else {
		printk(KERN_ERR "iSCSI - Client [%s] logged in from [%s] to [%s:%hu]\n",
			sess->sess_ops->InitiatorName, ip, ip_np, np->np_port);
	}
#else
	printk(KERN_INFO "iSCSI Login successful on CID: %hu from %s to %s:%hu,%hu\n",
		conn->cid, ip, ip_np, np->np_port, tpg->tpgt);
#endif

	spin_lock_bh(&sess->conn_lock);
	list_add_tail(&conn->conn_list, &sess->sess_conn_list);
	atomic_inc(&sess->nconn);
#ifndef MY_ABC_HERE
	printk(KERN_INFO "Incremented iSCSI Connection count to %hu from node:"
		" %s\n", atomic_read(&sess->nconn),
		SESS_OPS(sess)->InitiatorName);
#endif
	spin_unlock_bh(&sess->conn_lock);

	sess->sid = tpg->sid++;
	if (!sess->sid)
		sess->sid = tpg->sid++;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "Established iSCSI session from node: %s\n",
			SESS_OPS(sess)->InitiatorName);
#endif

#ifdef MY_ABC_HERE
	atomic_inc(&tpg->nr_sessions);
#endif
	tpg->nsessions++;
	if (tpg->tpg_tiqn)
		tpg->tpg_tiqn->tiqn_nsessions++;

#ifndef MY_ABC_HERE
	printk(KERN_INFO "Incremented number of active iSCSI sessions to %u on"
		" iSCSI Target Portal Group: %hu\n", tpg->nsessions, tpg->tpgt);
#endif
	spin_unlock_bh(&se_tpg->session_lock);

	iscsi_post_login_start_timers(conn);
	iscsi_activate_thread_set(conn, ts);

	iscsi_dec_conn_usage_count(conn);

	return 0;
}

static void iscsi_handle_login_thread_timeout(unsigned long data)
{
	unsigned char buf_ipv4[IPV4_BUF_SIZE];
	iscsi_np_t *np = (iscsi_np_t *) data;

	memset(buf_ipv4, 0, IPV4_BUF_SIZE);
	spin_lock_bh(&np->np_thread_lock);
	iscsi_ntoa2(buf_ipv4, np->np_ipv4);

#ifdef MY_ABC_HERE
	printk(KERN_ERR "iSCSI - Login timeout on Network Portal %s:%hu\n",
			buf_ipv4, np->np_port);
#else
	printk(KERN_ERR "iSCSI Login timeout on Network Portal %s:%hu\n",
			buf_ipv4, np->np_port);
#endif

	if (np->np_login_timer_flags & TPG_NP_TF_STOP) {
		spin_unlock_bh(&np->np_thread_lock);
		return;
	}

	if (np->np_thread)
		send_sig(SIGKILL, np->np_thread, 1);

	np->np_login_timer_flags &= ~TPG_NP_TF_RUNNING;
	spin_unlock_bh(&np->np_thread_lock);
}

static void iscsi_start_login_thread_timer(iscsi_np_t *np)
{
	 
	spin_lock_bh(&np->np_thread_lock);
	init_timer(&np->np_login_timer);
	SETUP_TIMER(np->np_login_timer, TA_LOGIN_TIMEOUT, np,
			iscsi_handle_login_thread_timeout);
	np->np_login_timer_flags &= ~TPG_NP_TF_STOP;
	np->np_login_timer_flags |= TPG_NP_TF_RUNNING;
	add_timer(&np->np_login_timer);

	TRACE(TRACE_LOGIN, "Added timeout timer to iSCSI login request for"
			" %u seconds.\n", TA_LOGIN_TIMEOUT);
	spin_unlock_bh(&np->np_thread_lock);
}

static void iscsi_stop_login_thread_timer(iscsi_np_t *np)
{
	spin_lock_bh(&np->np_thread_lock);
	if (!(np->np_login_timer_flags & TPG_NP_TF_RUNNING)) {
		spin_unlock_bh(&np->np_thread_lock);
		return;
	}
	np->np_login_timer_flags |= TPG_NP_TF_STOP;
	spin_unlock_bh(&np->np_thread_lock);

	del_timer_sync(&np->np_login_timer);

	spin_lock_bh(&np->np_thread_lock);
	np->np_login_timer_flags &= ~TPG_NP_TF_RUNNING;
	spin_unlock_bh(&np->np_thread_lock);
}

static struct socket *iscsi_target_setup_login_socket(iscsi_np_t *np)
{
	const char *end;
	struct socket *sock;
	int backlog = 5, ip_proto, sock_type, ret, opt = 0;
	struct sockaddr_in sock_in;
	struct sockaddr_in6 sock_in6;

	switch (np->np_network_transport) {
	case ISCSI_TCP:
		ip_proto = IPPROTO_TCP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_TCP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_UDP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_SEQPACKET;
		break;
	case ISCSI_IWARP_TCP:
	case ISCSI_IWARP_SCTP:
	case ISCSI_INFINIBAND:
	default:
		printk(KERN_ERR "Unsupported network_transport: %d\n",
				np->np_network_transport);
		goto fail;
	}

	if (sock_create((np->np_flags & NPF_NET_IPV6) ? AF_INET6 : AF_INET,
			sock_type, ip_proto, &sock) < 0) {
		printk(KERN_ERR "sock_create() failed.\n");
		goto fail;
	}
	np->np_socket = sock;

	if ((np->np_network_transport == ISCSI_SCTP_TCP) ||
	    (np->np_network_transport == ISCSI_SCTP_UDP)) {
		if (!sock->file) {
			sock->file = kzalloc(sizeof(struct file), GFP_KERNEL);
			if (!(sock->file)) {
				printk(KERN_ERR "Unable to allocate struct"
						" file for SCTP\n");
				goto fail;
			}
			np->np_flags |= NPF_SCTP_STRUCT_FILE;
		}
	}

	if (np->np_flags & NPF_NET_IPV6) {
		memset(&sock_in6, 0, sizeof(struct sockaddr_in6));
		sock_in6.sin6_family = AF_INET6;
		sock_in6.sin6_port = htons(np->np_port);
#if 1
		ret = in6_pton(&np->np_ipv6[0], IPV6_ADDRESS_SPACE,
				(void *)&sock_in6.sin6_addr.in6_u, -1, &end);
		if (ret <= 0) {
			printk(KERN_ERR "in6_pton returned: %d\n", ret);
			goto fail;
		}
#else
		ret = iscsi_pton6(&np->np_ipv6[0],
				(unsigned char *)&sock_in6.sin6_addr.in6_u);
		if (ret <= 0) {
			printk(KERN_ERR "iscsi_pton6() returned: %d\n", ret);
			goto fail;
		}
#endif
	} else {
		memset(&sock_in, 0, sizeof(struct sockaddr_in));
		sock_in.sin_family = AF_INET;
		sock_in.sin_port = htons(np->np_port);
		sock_in.sin_addr.s_addr = htonl(np->np_ipv4);
	}

	opt = 1;
	if (np->np_network_transport == ISCSI_TCP) {
		ret = kernel_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
				(char *)&opt, sizeof(opt));
		if (ret < 0) {
			printk(KERN_ERR "kernel_setsockopt() for TCP_NODELAY"
				" failed: %d\n", ret);
			goto fail;
		}
	}
	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&opt, sizeof(opt));
	if (ret < 0) {
		printk(KERN_ERR "kernel_setsockopt() for SO_REUSEADDR"
			" failed\n");
		goto fail;
	}

	if (np->np_flags & NPF_NET_IPV6) {
		ret = kernel_bind(sock, (struct sockaddr *)&sock_in6,
				sizeof(struct sockaddr_in6));
		if (ret < 0) {
			printk(KERN_ERR "kernel_bind() failed: %d\n", ret);
			goto fail;
		}
	} else {
		ret = kernel_bind(sock, (struct sockaddr *)&sock_in,
				sizeof(struct sockaddr));
		if (ret < 0) {
			printk(KERN_ERR "kernel_bind() failed: %d\n", ret);
			goto fail;
		}
	}

	if (kernel_listen(sock, backlog)) {
		printk(KERN_ERR "kernel_listen() failed.\n");
		goto fail;
	}

	return sock;

fail:
	np->np_socket = NULL;
	if (sock) {
		if (np->np_flags & NPF_SCTP_STRUCT_FILE) {
			kfree(sock->file);
			sock->file = NULL;
		}

		sock_release(sock);
	}
	return NULL;
}

int iscsi_target_login_thread(void *arg)
{
	u8 buffer[ISCSI_HDR_LEN], iscsi_opcode, zero_tsih = 0;
	unsigned char *ip = NULL, *ip_init_buf = NULL;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf1_ipv4[IPV4_BUF_SIZE];
	int err, ret = 0, start = 1, ip_proto;
	int sock_type, set_sctp_conn_flag = 0;
	iscsi_conn_t *conn = NULL;
	iscsi_login_t *login;
	iscsi_portal_group_t *tpg = NULL;
	struct socket *new_sock, *sock;
	iscsi_np_t *np = (iscsi_np_t *) arg;
	struct iovec iov;
	struct iscsi_init_login_cmnd *pdu;
	struct sockaddr_in sock_in;
	struct sockaddr_in6 sock_in6;
#ifdef MY_ABC_HERE
	const size_t MAX_LOGIN_RETRY = 30;
	size_t i = 0;
#endif

	{
	char name[16];
	memset(name, 0, 16);
	sprintf(name, "iscsi_np");
	iscsi_daemon(np->np_thread, name, SHUTDOWN_SIGS);
	}

	sock = iscsi_target_setup_login_socket(np);
	if (!(sock)) {
		up(&np->np_start_sem);
		return -1;
	}

get_new_sock:
	flush_signals(current);
	ip_proto = sock_type = set_sctp_conn_flag = 0;

	switch (np->np_network_transport) {
	case ISCSI_TCP:
		ip_proto = IPPROTO_TCP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_TCP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_UDP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_SEQPACKET;
		break;
	case ISCSI_IWARP_TCP:
	case ISCSI_IWARP_SCTP:
	case ISCSI_INFINIBAND:
	default:
		printk(KERN_ERR "Unsupported network_transport: %d\n",
			np->np_network_transport);
		if (start)
			up(&np->np_start_sem);
		return -1;
	}

	spin_lock_bh(&np->np_thread_lock);
	if (np->np_thread_state == ISCSI_NP_THREAD_SHUTDOWN)
		goto out;
	else if (np->np_thread_state == ISCSI_NP_THREAD_RESET) {
		if (atomic_read(&np->np_shutdown)) {
			spin_unlock_bh(&np->np_thread_lock);
			up(&np->np_restart_sem);
			down(&np->np_shutdown_sem);
			goto out;
		}
		np->np_thread_state = ISCSI_NP_THREAD_ACTIVE;
		up(&np->np_restart_sem);
	} else {
		np->np_thread_state = ISCSI_NP_THREAD_ACTIVE;

		if (start) {
			start = 0;
			up(&np->np_start_sem);
		}
	}
	spin_unlock_bh(&np->np_thread_lock);

	if (kernel_accept(sock, &new_sock, 0) < 0) {
		if (signal_pending(current)) {
			spin_lock_bh(&np->np_thread_lock);
			if (np->np_thread_state == ISCSI_NP_THREAD_RESET) {
				if (atomic_read(&np->np_shutdown)) {
					spin_unlock_bh(&np->np_thread_lock);
					up(&np->np_restart_sem);
					down(&np->np_shutdown_sem);
					goto out;
				}
				spin_unlock_bh(&np->np_thread_lock);
				goto get_new_sock;
			}
			spin_unlock_bh(&np->np_thread_lock);
			goto out;
		}
		goto get_new_sock;
	}
	 
	if ((np->np_network_transport == ISCSI_SCTP_TCP) ||
	    (np->np_network_transport == ISCSI_SCTP_UDP)) {
		if (!new_sock->file) {
			new_sock->file = kzalloc(
					sizeof(struct file), GFP_KERNEL);
			if (!(new_sock->file)) {
				printk(KERN_ERR "Unable to allocate struct"
						" file for SCTP\n");
				sock_release(new_sock);
				goto get_new_sock;
			}
			set_sctp_conn_flag = 1;
		}
	}

	iscsi_start_login_thread_timer(np);

	conn = kmem_cache_zalloc(lio_conn_cache, GFP_KERNEL);
	if (!(conn)) {
		printk(KERN_ERR "Could not allocate memory for"
			" new connection\n");
		if (set_sctp_conn_flag) {
			kfree(new_sock->file);
			new_sock->file = NULL;
		}
		sock_release(new_sock);

		goto get_new_sock;
	}

	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_FREE.\n");
	conn->conn_state = TARG_CONN_STATE_FREE;
	conn->sock = new_sock;

	if (set_sctp_conn_flag)
		conn->conn_flags |= CONNFLAG_SCTP_STRUCT_FILE;

	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_XPT_UP.\n");
	conn->conn_state = TARG_CONN_STATE_XPT_UP;

	conn->conn_ops = kzalloc(sizeof(iscsi_conn_ops_t), GFP_KERNEL);
	if (!(conn->conn_ops)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" iscsi_conn_ops_t.\n");
		goto new_sess_out;
	}
	iscsi_login_init_conn(conn);

	memset(buffer, 0, ISCSI_HDR_LEN);
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base	= buffer;
	iov.iov_len	= ISCSI_HDR_LEN;

	if (rx_data(conn, &iov, 1, ISCSI_HDR_LEN) <= 0) {
		printk(KERN_ERR "rx_data() returned an error.\n");
		goto new_sess_out;
	}

	iscsi_opcode = (buffer[0] & ISCSI_OPCODE);
	if (!(iscsi_opcode & ISCSI_INIT_LOGIN_CMND)) {
		printk(KERN_ERR "First opcode is not login request,"
			" failing login request.\n");
		goto new_sess_out;
	}

	pdu			= (struct iscsi_init_login_cmnd *) buffer;
	pdu->length		= be32_to_cpu(pdu->length);
	pdu->cid		= be16_to_cpu(pdu->cid);
	pdu->tsih		= be16_to_cpu(pdu->tsih);
	pdu->init_task_tag	= be32_to_cpu(pdu->init_task_tag);
	pdu->cmd_sn		= be32_to_cpu(pdu->cmd_sn);
	pdu->exp_stat_sn	= be32_to_cpu(pdu->exp_stat_sn);
	 
	conn->login_itt		= pdu->init_task_tag;

#ifdef DEBUG_OPCODES
	print_init_login_cmnd(pdu);
#endif
	if (np->np_net_size == IPV6_ADDRESS_SPACE)
		ip = &np->np_ipv6[0];
	else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
	}

	spin_lock_bh(&np->np_thread_lock);
	if ((atomic_read(&np->np_shutdown)) ||
	    (np->np_thread_state != ISCSI_NP_THREAD_ACTIVE)) {
		spin_unlock_bh(&np->np_thread_lock);
		printk(KERN_ERR "iSCSI Network Portal on %s:%hu currently not"
			" active.\n", ip, np->np_port);
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_SERVICE_UNAVAILABLE);
		goto new_sess_out;
	}
	spin_unlock_bh(&np->np_thread_lock);

	if (np->np_net_size == IPV6_ADDRESS_SPACE) {
		memset(&sock_in6, 0, sizeof(struct sockaddr_in6));

		if (conn->sock->ops->getname(conn->sock,
				(struct sockaddr *)&sock_in6, &err, 1) < 0) {
			printk(KERN_ERR "sock_ops->getname() failed.\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			goto new_sess_out;
		}
#ifdef MY_ABC_HERE
		if (!(iscsi_ntop6((const unsigned char *)
				&sock_in6.sin6_addr.in6_u,
				(char *)&conn->ipv6_login_ip[0],
				IPV6_ADDRESS_SPACE))) {
			printk(KERN_ERR "iscsi_ntop6() failed\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			goto new_sess_out;
		}
		conn->net_size = IPV6_ADDRESS_SPACE;
#else
#if 0
		if (!(iscsi_ntop6((const unsigned char *)
				&sock_in6.sin6_addr.in6_u,
				(char *)&conn->ipv6_login_ip[0],
				IPV6_ADDRESS_SPACE))) {
			printk(KERN_ERR "iscsi_ntop6() failed\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			goto new_sess_out;
		}
#else
		printk(KERN_INFO "Skipping iscsi_ntop6()\n");
#endif
#endif
		ip_init_buf = &conn->ipv6_login_ip[0];
	} else {
		memset(&sock_in, 0, sizeof(struct sockaddr_in));

		if (conn->sock->ops->getname(conn->sock,
				(struct sockaddr *)&sock_in, &err, 1) < 0) {
			printk(KERN_ERR "sock_ops->getname() failed.\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			goto new_sess_out;
		}
		memset(buf1_ipv4, 0, IPV4_BUF_SIZE);
		conn->login_ip = ntohl(sock_in.sin_addr.s_addr);
		conn->login_port = ntohs(sock_in.sin_port);
		iscsi_ntoa2(buf1_ipv4, conn->login_ip);
		ip_init_buf = &buf1_ipv4[0];
	}

	conn->network_transport = np->np_network_transport;
	snprintf(conn->net_dev, ISCSI_NETDEV_NAME_SIZE, "%s", np->np_net_dev);

#ifdef SNMP_SUPPORT
	conn->conn_index = iscsi_get_new_index(ISCSI_CONNECTION_INDEX);
	conn->local_ip = np->np_ipv4;
	conn->local_port = np->np_port;
#endif

#ifndef MY_ABC_HERE
	printk(KERN_INFO "Received iSCSI login request from %s on %s Network"
			" Portal %s:%hu\n", ip_init_buf,
		(conn->network_transport == ISCSI_TCP) ? "TCP" : "SCTP",
			ip, np->np_port);
#endif

	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_IN_LOGIN.\n");
	conn->conn_state	= TARG_CONN_STATE_IN_LOGIN;

	if (iscsi_login_check_initiator_version(conn, pdu->version_max,
			pdu->version_min) < 0)
		goto new_sess_out;

	zero_tsih = (pdu->tsih == 0x0000);
	if ((zero_tsih)) {
		 
		if (iscsi_login_zero_tsih_s1(conn, buffer) < 0)
			goto new_sess_out;
	} else {
		 
		if (iscsi_login_non_zero_tsih_s1(conn, buffer) < 0)
			goto new_sess_out;
	}

	login = iscsi_target_init_negotiation(np, conn, buffer);
	if (!(login)) {
		tpg = conn->tpg;
		goto new_sess_out;
	}

	tpg = conn->tpg;
	if (!(tpg)) {
		printk(KERN_ERR "Unable to locate iscsi_conn_t->tpg\n");
		goto new_sess_out;
	}

	if (zero_tsih) {
		if (iscsi_login_zero_tsih_s2(conn) < 0) {
			iscsi_target_nego_release(login, conn);
			goto new_sess_out;
		}
	} else {
		if (iscsi_login_non_zero_tsih_s2(conn, buffer) < 0) {
			iscsi_target_nego_release(login, conn);
			goto old_sess_out;
		}
	}

#ifdef MY_ABC_HERE
	for( i = 0; i <= MAX_LOGIN_RETRY; ++i ) {
		spin_lock_bh(&tpg->tpg_se_tpg->session_lock);
		if( (SESS(conn) && SESS(conn)->sess_ops->SessionType) ||  
		    (atomic_read(&tpg->nr_sessions) < atomic_read(&tpg->max_nr_sessions)) ) {
			spin_unlock_bh(&tpg->tpg_se_tpg->session_lock);
			break;
		} else if( i < MAX_LOGIN_RETRY ) {
			unsigned long cur_jiffies = (unsigned long)get_jiffies_64();
			spin_unlock_bh(&tpg->tpg_se_tpg->session_lock);
			while( time_is_after_jiffies(cur_jiffies + msecs_to_jiffies(100)) ) {
				schedule();
			}
		} else {
			spin_unlock_bh(&tpg->tpg_se_tpg->session_lock);
			iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR, STAT_DETAIL_TOO_MANY_CONNECTIONS);
			printk(KERN_ERR "iSCSI - The number(%d) of current sessions will exceed the maximum number(%d).",
					atomic_read(&tpg->nr_sessions), atomic_read(&tpg->max_nr_sessions));
			goto new_sess_out;
		}
	}
#endif

	if (iscsi_target_start_negotiation(login, conn) < 0)
		goto new_sess_out;

	if (!SESS(conn)) {
		printk(KERN_ERR "iscsi_conn_t session pointer is NULL!\n");
		goto new_sess_out;
	}

	iscsi_stop_login_thread_timer(np);

	if (signal_pending(current))
		goto new_sess_out;

	ret = iscsi_post_login_handler(np, conn, zero_tsih);

	if (ret < 0)
		goto new_sess_out;

	core_deaccess_np(np, tpg);
	tpg = NULL;
	goto get_new_sock;

new_sess_out:
#ifdef MY_ABC_HERE
	if( ip ) {
		printk(KERN_ERR "iSCSI - Login negotiation failed from [%s]\n", ip);
	} else {
		printk(KERN_ERR "iSCSI - Login negotiation failed.\n");
	}
#else
	printk(KERN_ERR "iSCSI Login negotiation failed.\n");
#endif
#ifdef SNMP_SUPPORT
	iscsi_collect_login_stats(conn, STAT_CLASS_INITIATOR,
				  STAT_DETAIL_INIT_ERROR);
#endif
	if (!zero_tsih || !SESS(conn))
		goto old_sess_out;
	if (SESS(conn)->se_sess)
		transport_free_session(SESS(conn)->se_sess);
	if (SESS(conn)->sess_ops)
		kfree(SESS(conn)->sess_ops);
	if (SESS(conn))
		kmem_cache_free(lio_sess_cache, SESS(conn));
old_sess_out:
	iscsi_stop_login_thread_timer(np);
	 
	if (!zero_tsih && SESS(conn)) {
		spin_lock_bh(&SESS(conn)->conn_lock);
		if (SESS(conn)->session_state == TARG_SESS_STATE_FAILED) {
			se_portal_group_t *se_tpg =
					ISCSI_TPG_C(conn)->tpg_se_tpg;

			atomic_set(&SESS(conn)->session_continuation, 0);
			spin_unlock_bh(&SESS(conn)->conn_lock);
			spin_lock_bh(&se_tpg->session_lock);
			iscsi_start_time2retain_handler(SESS(conn));
			spin_unlock_bh(&se_tpg->session_lock);
		} else
			spin_unlock_bh(&SESS(conn)->conn_lock);
		iscsi_dec_session_usage_count(SESS(conn));
	}

	kfree(conn->conn_ops);

	if (conn->param_list) {
		iscsi_release_param_list(conn->param_list);
		conn->param_list = NULL;
	}
	if (conn->sock) {
		if (conn->conn_flags & CONNFLAG_SCTP_STRUCT_FILE) {
			kfree(conn->sock->file);
			conn->sock->file = NULL;
		}
		sock_release(conn->sock);
	}
	kmem_cache_free(lio_conn_cache, conn);

	if (tpg) {
		core_deaccess_np(np, tpg);
		tpg = NULL;
	}

	if (!(signal_pending(current)))
		goto get_new_sock;

	spin_lock_bh(&np->np_thread_lock);
	if (atomic_read(&np->np_shutdown)) {
		spin_unlock_bh(&np->np_thread_lock);
		up(&np->np_restart_sem);
		down(&np->np_shutdown_sem);
		goto out;
	}
	if (np->np_thread_state != ISCSI_NP_THREAD_SHUTDOWN) {
		spin_unlock_bh(&np->np_thread_lock);
		goto get_new_sock;
	}
	spin_unlock_bh(&np->np_thread_lock);
out:
	iscsi_stop_login_thread_timer(np);
	spin_lock_bh(&np->np_thread_lock);
	np->np_thread_state = ISCSI_NP_THREAD_EXIT;
	np->np_thread = NULL;
	spin_unlock_bh(&np->np_thread_lock);
	up(&np->np_done_sem);
	return 0;
}
