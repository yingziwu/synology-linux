#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define ISCSI_TARGET_TPG_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <iscsi_linux_defs.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>
#include <target/target_core_hba.h>
#include <target/target_core_tpg.h>

#include <iscsi_target_core.h>
#include <iscsi_target_device.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_login.h>
#include <iscsi_target_nodeattrib.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>

#undef ISCSI_TARGET_TPG_C

char *lio_tpg_get_endpoint_wwn(se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return &tpg->tpg_tiqn->tiqn[0];
}

u16 lio_tpg_get_tag(se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return tpg->tpgt;
}

u32 lio_tpg_get_default_depth(se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->default_cmdsn_depth;
}

u32 lio_tpg_get_pr_transport_id(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl,
	t10_pr_registration_t *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	u32 off = 4, padding = 0;
	u16 len = 0;

	spin_lock(&se_nacl->nacl_sess_lock);
	 
	buf[0] = 0x05;
	 
	len = sprintf(&buf[off], "%s", se_nacl->initiatorname);
	 
	len++;
	 
	if ((*format_code == 1) &&
	    (pr_reg->pr_reg_flags & PRF_ISID_PRESENT_AT_REG)) {
		 
		buf[0] |= 0x40;
		 
		buf[off+len] = 0x2c; off++;  
		buf[off+len] = 0x69; off++;  
		buf[off+len] = 0x2c; off++;  
		buf[off+len] = 0x30; off++;  
		buf[off+len] = 0x78; off++;  
		len += 5;
		buf[off+len] = pr_reg->pr_reg_isid[0]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[1]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[2]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[3]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[4]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[5]; off++;
		buf[off+len] = '\0'; off++;
		len += 7;
	}
	spin_unlock(&se_nacl->nacl_sess_lock);
	 
	padding = ((-len) & 3);
	if (padding != 0)
		len += padding;

	buf[2] = ((len >> 8) & 0xff);
	buf[3] = (len & 0xff);
	 
	len += 4;

	return len;
}

u32 lio_tpg_get_pr_transport_id_len(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl,
	t10_pr_registration_t *pr_reg,
	int *format_code)
{
	u32 len = 0, padding = 0;

	spin_lock(&se_nacl->nacl_sess_lock);
	len = strlen(se_nacl->initiatorname);
	 
	len++;
	 
	if (pr_reg->pr_reg_flags & PRF_ISID_PRESENT_AT_REG) {
		len += 5;  
		len += 7;  
		*format_code = 1;
	} else
		*format_code = 0;
	spin_unlock(&se_nacl->nacl_sess_lock);
	 
	padding = ((-len) & 3);
	if (padding != 0)
		len += padding;
	 
	len += 4;

	return len;
}

char *lio_tpg_parse_pr_out_transport_id(
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	char *p;
	u32 tid_len, padding;
	int i;
	u16 add_len;
	u8 format_code = (buf[0] & 0xc0);
	 
	if ((format_code != 0x00) && (format_code != 0x40)) {
		printk(KERN_ERR "Illegal format code: 0x%02x for iSCSI"
			" Initiator Transport ID\n", format_code);
		return NULL;
	}
	 
	if (out_tid_len != NULL) {
		add_len = ((buf[2] >> 8) & 0xff);
		add_len |= (buf[3] & 0xff);

		tid_len = strlen((char *)&buf[4]);
		tid_len += 4;  
		tid_len += 1;  
		padding = ((-tid_len) & 3);
		if (padding != 0)
			tid_len += padding;

		if ((add_len + 4) != tid_len) {
			printk(KERN_INFO "LIO-Target Extracted add_len: %hu "
				"does not match calculated tid_len: %u,"
				" using tid_len instead\n", add_len+4, tid_len);
			*out_tid_len = tid_len;
		} else
			*out_tid_len = (add_len + 4);
	}
	 
	if (format_code == 0x40) {
		p = strstr((char *)&buf[4], ",i,0x");
		if (!(p)) {
			printk(KERN_ERR "Unable to locate \",i,0x\" seperator"
				" for Initiator port identifier: %s\n",
				(char *)&buf[4]);
			return NULL;
		}
		*p = '\0';  
		p += 5;  

		*port_nexus_ptr = p;
		 
		for (i = 0; i < 12; i++) {
			if (isdigit(*p)) {
				p++;
				continue;
			}
			*p = tolower(*p);
			p++;
		}
	}

	return (char *)&buf[4];
}

int lio_tpg_check_demo_mode(se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg =
			 (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->generate_node_acls;
}

int lio_tpg_check_demo_mode_cache(se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->cache_dynamic_acls;
}

int lio_tpg_check_demo_mode_write_protect(se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->demo_mode_write_protect;
}

void *lio_tpg_alloc_fabric_acl(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl)
{
	iscsi_node_acl_t *acl;

	acl = kzalloc(sizeof(iscsi_node_acl_t), GFP_KERNEL);
	if (!(acl)) {
		printk(KERN_ERR "Unable to allocate memory for iscsi_node_acl_t\n");
		return NULL;
	}
	acl->se_node_acl = se_nacl;

	return acl;
}

void lio_tpg_release_fabric_acl(
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_acl)
{
	iscsi_node_acl_t *acl = (iscsi_node_acl_t *)se_acl->fabric_acl_ptr;
	kfree(acl);
}

int lio_tpg_shutdown_session(se_session_t *se_sess)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

	spin_lock(&sess->conn_lock);
	if (atomic_read(&sess->session_fall_back_to_erl0) ||
	    atomic_read(&sess->session_logout) ||
	    (sess->time2retain_timer_flags & T2R_TF_EXPIRED)) {
		spin_unlock(&sess->conn_lock);
		return 0;
	}
	atomic_set(&sess->session_reinstatement, 1);
	spin_unlock(&sess->conn_lock);

	iscsi_inc_session_usage_count(sess);
	iscsi_stop_time2retain_timer(sess);

	return 1;
}

void lio_tpg_close_session(se_session_t *se_sess)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;
	 
	iscsi_stop_session(sess, 1, 1);
	iscsi_dec_session_usage_count(sess);
	iscsi_close_session(sess);
}

void lio_tpg_stop_session(se_session_t *se_sess, int sess_sleep, int conn_sleep)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

	iscsi_stop_session(sess, sess_sleep, conn_sleep);
}

void lio_tpg_fall_back_to_erl0(se_session_t *se_sess)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

	iscsi_fall_back_to_erl0(sess);
}

#ifdef SNMP_SUPPORT
u32 lio_tpg_get_inst_index(se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return tpg->tpg_tiqn->tiqn_index;
}
#endif  

void lio_set_default_node_attributes(se_node_acl_t *se_acl)
{
	iscsi_node_acl_t *acl = (iscsi_node_acl_t *)se_acl->fabric_acl_ptr;

	ISCSI_NODE_ATTRIB(acl)->nacl = acl;
	iscsi_set_default_node_attribues(acl);
}

#ifdef MY_ABC_HERE
void lio_dup_node_attributes(se_node_acl_t* dst, se_node_acl_t* src)
{
	iscsi_node_acl_t* dst_acl = (iscsi_node_acl_t*)dst->fabric_acl_ptr;
	iscsi_node_acl_t* src_acl = (iscsi_node_acl_t*)src->fabric_acl_ptr;
	iscsi_node_attrib_t* src_attr = &src_acl->node_attrib;
	iscsi_node_attrib_t* dst_attr = &dst_acl->node_attrib;
	iscsi_node_auth_t* src_auth = &src_acl->node_auth;
	iscsi_node_auth_t* dst_auth = &dst_acl->node_auth;

	ISCSI_NODE_ATTRIB(dst_acl)->nacl = dst_acl;

	dst_attr->dataout_timeout = src_attr->dataout_timeout;
	dst_attr->dataout_timeout_retries = src_attr->dataout_timeout_retries;
	dst_attr->nopin_timeout = src_attr->nopin_timeout;
	dst_attr->nopin_response_timeout = src_attr->nopin_response_timeout;
	dst_attr->random_datain_pdu_offsets = src_attr->random_datain_pdu_offsets;
	dst_attr->random_datain_seq_offsets = src_attr->random_datain_seq_offsets;
	dst_attr->random_r2t_offsets = src_attr->random_r2t_offsets;
	dst_attr->default_erl = src_attr->default_erl;

	dst_auth->naf_flags = src_auth->naf_flags;
	dst_auth->authenticate_target = src_auth->authenticate_target;
	strcpy(dst_auth->userid, src_auth->userid);
	strcpy(dst_auth->password, src_auth->password);
	strcpy(dst_auth->userid_mutual, src_auth->userid_mutual);
	strcpy(dst_auth->password_mutual, src_auth->password_mutual);
}
#endif

iscsi_portal_group_t *core_alloc_portal_group(iscsi_tiqn_t *tiqn, u16 tpgt)
{
	iscsi_portal_group_t *tpg;

	tpg = kmem_cache_zalloc(lio_tpg_cache, GFP_KERNEL);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to get tpg from lio_tpg_cache\n");
		return NULL;
	}

#ifdef MY_ABC_HERE
	atomic_set(&tpg->nr_sessions, 0);
	atomic_set(&tpg->max_nr_sessions, 1);
#endif
	tpg->tpgt = tpgt;
	tpg->tpg_state = TPG_STATE_FREE;
	tpg->tpg_tiqn = tiqn;
	INIT_LIST_HEAD(&tpg->tpg_gnp_list);
	INIT_LIST_HEAD(&tpg->g_tpg_list);
	INIT_LIST_HEAD(&tpg->tpg_list);
	init_MUTEX(&tpg->tpg_access_sem);
	init_MUTEX(&tpg->np_login_sem);
	spin_lock_init(&tpg->tpg_state_lock);
	spin_lock_init(&tpg->tpg_np_lock);
	tpg->sid        = 1;  

	return tpg;
}

static void iscsi_set_default_tpg_attribs(iscsi_portal_group_t *);

int core_load_discovery_tpg(void)
{
	iscsi_param_t *param;
	iscsi_portal_group_t *tpg;

	tpg = core_alloc_portal_group(NULL, 1);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to allocate iscsi_portal_group_t\n");
		return -1;
	}

	tpg->tpg_se_tpg = core_tpg_register(
			&lio_target_fabric_configfs->tf_ops, (void *)tpg,
			TRANSPORT_TPG_TYPE_DISCOVERY);
	if (IS_ERR(tpg->tpg_se_tpg)) {
		kfree(tpg);
		return -1;
	}

	tpg->sid        = 1;  
	INIT_LIST_HEAD(&tpg->tpg_gnp_list);
	INIT_LIST_HEAD(&tpg->g_tpg_list);
	INIT_LIST_HEAD(&tpg->tpg_list);
	init_MUTEX(&tpg->tpg_access_sem);
	init_MUTEX(&tpg->np_login_sem);
	spin_lock_init(&tpg->tpg_state_lock);
	spin_lock_init(&tpg->tpg_np_lock);

	iscsi_set_default_tpg_attribs(tpg);

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto out;
	 
	param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list);
	if (!(param))
		goto out;

	if (iscsi_update_param_value(param, "CHAP,None") < 0)
		goto out;

	tpg->tpg_attrib.authentication = 0;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state  = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_global->discovery_tpg = tpg;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE[0] - Allocated Discovery TPG\n");
#endif

	return 0;
out:
	if (tpg->tpg_se_tpg)
		core_tpg_deregister(tpg->tpg_se_tpg);
	kfree(tpg);
	return -1;
}

void core_release_discovery_tpg(void)
{
	iscsi_portal_group_t *tpg = iscsi_global->discovery_tpg;

	if (!(tpg))
		return;

	core_tpg_deregister(tpg->tpg_se_tpg);

	kmem_cache_free(lio_tpg_cache, tpg);
	iscsi_global->discovery_tpg = NULL;
}

iscsi_portal_group_t *core_get_tpg_from_np(
	iscsi_tiqn_t *tiqn,
	iscsi_np_t *np)
{
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tpg_np_t *tpg_np;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {

		spin_lock(&tpg->tpg_state_lock);
		if (tpg->tpg_state == TPG_STATE_FREE) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);

		spin_lock(&tpg->tpg_np_lock);
		list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
			if (tpg_np->tpg_np == np) {
				spin_unlock(&tpg->tpg_np_lock);
				spin_unlock(&tiqn->tiqn_tpg_lock);
				return tpg;
			}
		}
		spin_unlock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return NULL;
}

int iscsi_get_tpg(
	iscsi_portal_group_t *tpg)
{
	int ret;

	ret = down_interruptible(&tpg->tpg_access_sem);
	return ((ret != 0) || signal_pending(current)) ? -1 : 0;
}

void iscsi_put_tpg(iscsi_portal_group_t *tpg)
{
	up(&tpg->tpg_access_sem);
}

static void iscsi_clear_tpg_np_login_thread(
	iscsi_tpg_np_t *tpg_np,
	iscsi_portal_group_t *tpg,
	int shutdown)
{
	if (!tpg_np->tpg_np) {
		printk(KERN_ERR "iscsi_tpg_np_t->tpg_np is NULL!\n");
		return;
	}

	core_reset_np_thread(tpg_np->tpg_np, tpg_np, tpg, shutdown);
	return;
}

void iscsi_clear_tpg_np_login_threads(
	iscsi_portal_group_t *tpg,
	int shutdown)
{
	iscsi_tpg_np_t *tpg_np;

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
		if (!tpg_np->tpg_np) {
			printk(KERN_ERR "iscsi_tpg_np_t->tpg_np is NULL!\n");
			continue;
		}
		spin_unlock(&tpg->tpg_np_lock);
		iscsi_clear_tpg_np_login_thread(tpg_np, tpg, shutdown);
		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);
}

void iscsi_tpg_dump_params(iscsi_portal_group_t *tpg)
{
	iscsi_print_params(tpg->param_list);
}

static void iscsi_tpg_free_network_portals(iscsi_portal_group_t *tpg)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np, *tpg_np_t;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], *ip;

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry_safe(tpg_np, tpg_np_t, &tpg->tpg_gnp_list,
				tpg_np_list) {
		np = tpg_np->tpg_np;
		list_del(&tpg_np->tpg_np_list);
		tpg->num_tpg_nps--;
		tpg->tpg_tiqn->tiqn_num_tpg_nps--;

		if (np->np_net_size == IPV6_ADDRESS_SPACE)
			ip = &np->np_ipv6[0];
		else {
			memset(buf_ipv4, 0, IPV4_BUF_SIZE);
			iscsi_ntoa2(buf_ipv4, np->np_ipv4);
			ip = &buf_ipv4[0];
		}

#ifndef MY_ABC_HERE
		printk(KERN_INFO "CORE[%s] - Removed Network Portal: %s:%hu,%hu"
			" on %s on network device: %s\n", tpg->tpg_tiqn->tiqn,
			ip, np->np_port, tpg->tpgt,
			(np->np_network_transport == ISCSI_TCP) ?
			"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
			(char *)np->np_net_dev : "None");
#endif

		tpg_np->tpg_np = NULL;
		kfree(tpg_np);
		spin_unlock(&tpg->tpg_np_lock);

		spin_lock(&np->np_state_lock);
		np->np_exports--;
#ifndef MY_ABC_HERE
		printk(KERN_INFO "CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
			tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
#endif
		spin_unlock(&np->np_state_lock);

		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);
}

static void iscsi_set_default_tpg_attribs(iscsi_portal_group_t *tpg)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	a->authentication = TA_AUTHENTICATION;
	a->login_timeout = TA_LOGIN_TIMEOUT;
	a->netif_timeout = TA_NETIF_TIMEOUT;
	a->default_cmdsn_depth = TA_DEFAULT_CMDSN_DEPTH;
	a->generate_node_acls = TA_GENERATE_NODE_ACLS;
	a->cache_dynamic_acls = TA_CACHE_DYNAMIC_ACLS;
	a->demo_mode_write_protect = TA_DEMO_MODE_WRITE_PROTECT;
	a->prod_mode_write_protect = TA_PROD_MODE_WRITE_PROTECT;
	a->cache_core_nps = TA_CACHE_CORE_NPS;
}

int iscsi_tpg_add_portal_group(iscsi_tiqn_t *tiqn, iscsi_portal_group_t *tpg)
{
	if (tpg->tpg_state != TPG_STATE_FREE) {
		printk(KERN_ERR "Unable to add iSCSI Target Portal Group: %d"
			" while not in TPG_STATE_FREE state.\n", tpg->tpgt);
		return -EEXIST;
	}
	iscsi_set_default_tpg_attribs(tpg);

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto err_out;

	ISCSI_TPG_ATTRIB(tpg)->tpg = tpg;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state	= TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_add_tail(&tpg->tpg_list, &tiqn->tiqn_tpg_list);
	tiqn->tiqn_ntpgs++;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Added iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);
#endif
	spin_unlock(&tiqn->tiqn_tpg_lock);

	spin_lock_bh(&iscsi_global->g_tpg_lock);
	list_add_tail(&tpg->g_tpg_list, &iscsi_global->g_tpg_list);
	spin_unlock_bh(&iscsi_global->g_tpg_lock);

	return 0;
err_out:
	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}
	kfree(tpg);
	return -ENOMEM;
}

int iscsi_tpg_del_portal_group(
	iscsi_tiqn_t *tiqn,
	iscsi_portal_group_t *tpg,
	int force)
{
	u8 old_state = tpg->tpg_state;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_clear_tpg_np_login_threads(tpg, 1);

	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		printk(KERN_ERR "Unable to delete iSCSI Target Portal Group:"
			" %hu while active sessions exist, and force=0\n",
			tpg->tpgt);
		tpg->tpg_state = old_state;
		return -EPERM;
	}

	core_tpg_clear_object_luns(tpg->tpg_se_tpg);
	iscsi_tpg_free_network_portals(tpg);
	core_tpg_free_node_acls(tpg->tpg_se_tpg);

	spin_lock_bh(&iscsi_global->g_tpg_lock);
	list_del(&tpg->g_tpg_list);
	spin_unlock_bh(&iscsi_global->g_tpg_lock);

	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}

	core_tpg_deregister(tpg->tpg_se_tpg);
	tpg->tpg_se_tpg = NULL;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_FREE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_ntpgs--;
	list_del(&tpg->tpg_list);
	spin_unlock(&tiqn->tiqn_tpg_lock);

#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Deleted iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);
#endif

	kmem_cache_free(lio_tpg_cache, tpg);
	return 0;
}

#ifdef MY_ABC_HERE
void iscsi_tpg_active_portal_group(iscsi_portal_group_t* tpg)
{
	spin_lock_bh(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_ACTIVE;
	spin_unlock_bh(&tpg->tpg_state_lock);
}

void iscsi_tpg_deactive_portal_group(iscsi_portal_group_t* tpg)
{
	spin_lock_bh(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock_bh(&tpg->tpg_state_lock);
}
#endif

int iscsi_tpg_enable_portal_group(iscsi_portal_group_t *tpg)
{
	iscsi_param_t *param;
	iscsi_tiqn_t *tiqn = tpg->tpg_tiqn;

	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_ACTIVE) {
		printk(KERN_ERR "iSCSI target portal group: %hu is already"
			" active, ignoring request.\n", tpg->tpgt);
		spin_unlock(&tpg->tpg_state_lock);
		return -EINVAL;
	}
	 
	param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list);
	if (!(param)) {
		spin_unlock(&tpg->tpg_state_lock);
		return -ENOMEM;
	}

	if (ISCSI_TPG_ATTRIB(tpg)->authentication) {
		if (!strcmp(param->value, NONE))
			if (iscsi_update_param_value(param, CHAP) < 0) {
				spin_unlock(&tpg->tpg_state_lock);
				return -ENOMEM;
			}
		if (iscsi_ta_authentication(tpg, 1) < 0) {
			spin_unlock(&tpg->tpg_state_lock);
			return -ENOMEM;
		}
	}

	tpg->tpg_state = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs++;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "iSCSI_TPG[%hu] - Enabled iSCSI Target Portal Group\n",
			tpg->tpgt);
#endif
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return 0;
}

int iscsi_tpg_disable_portal_group(iscsi_portal_group_t *tpg, int force)
{
	iscsi_tiqn_t *tiqn = tpg->tpg_tiqn;
	u8 old_state = tpg->tpg_state;

	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_INACTIVE) {
#ifndef MY_ABC_HERE
		printk(KERN_ERR "iSCSI Target Portal Group: %hu is already"
			" inactive, ignoring request.\n", tpg->tpgt);
#endif
		spin_unlock(&tpg->tpg_state_lock);
		return -EINVAL;
	}
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_clear_tpg_np_login_threads(tpg, 0);

	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		spin_lock(&tpg->tpg_state_lock);
		tpg->tpg_state = old_state;
		spin_unlock(&tpg->tpg_state_lock);
		printk(KERN_ERR "Unable to disable iSCSI Target Portal Group:"
			" %hu while active sessions exist, and force=0\n",
			tpg->tpgt);
		return -EPERM;
	}

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs--;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "iSCSI_TPG[%hu] - Disabled iSCSI Target Portal Group\n",
			tpg->tpgt);
#endif
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return 0;
}

iscsi_node_acl_t *iscsi_tpg_add_initiator_node_acl(
	iscsi_portal_group_t *tpg,
	const char *initiatorname,
	u32 queue_depth)
{
	se_node_acl_t *se_nacl;

	se_nacl = core_tpg_add_initiator_node_acl(tpg->tpg_se_tpg,
			initiatorname, queue_depth);
	if ((IS_ERR(se_nacl)) || !(se_nacl))
		return NULL;

	return (iscsi_node_acl_t *)se_nacl->fabric_acl_ptr;
}

void iscsi_tpg_del_initiator_node_acl(
	iscsi_portal_group_t *tpg,
	se_node_acl_t *se_nacl)
{
	 
	core_tpg_del_initiator_node_acl(tpg->tpg_se_tpg, se_nacl, 1);
}

iscsi_node_attrib_t *iscsi_tpg_get_node_attrib(
	iscsi_session_t *sess)
{
	se_session_t *se_sess = sess->se_sess;
	se_node_acl_t *se_nacl = se_sess->se_node_acl;
	iscsi_node_acl_t *acl = (iscsi_node_acl_t *)se_nacl->fabric_acl_ptr;

	return &acl->node_attrib;
}

iscsi_tpg_np_t *iscsi_tpg_locate_child_np(
	iscsi_tpg_np_t *tpg_np,
	int network_transport)
{
	iscsi_tpg_np_t *tpg_np_child, *tpg_np_child_tmp;

	spin_lock(&tpg_np->tpg_np_parent_lock);
	list_for_each_entry_safe(tpg_np_child, tpg_np_child_tmp,
			&tpg_np->tpg_np_parent_list, tpg_np_child_list) {
		if (tpg_np_child->tpg_np->np_network_transport ==
				network_transport) {
			spin_unlock(&tpg_np->tpg_np_parent_lock);
			return tpg_np_child;
		}
	}
	spin_unlock(&tpg_np->tpg_np_parent_lock);

	return NULL;
}

iscsi_tpg_np_t *iscsi_tpg_add_network_portal(
	iscsi_portal_group_t *tpg,
	iscsi_np_addr_t *np_addr,
	iscsi_tpg_np_t *tpg_np_parent,
	int network_transport)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np;
	char *ip_buf;
	void *ip;
	int ret = 0;
	unsigned char buf_ipv4[IPV4_BUF_SIZE];

	if (np_addr->np_flags & NPF_NET_IPV6) {
		ip_buf = (char *)&np_addr->np_ipv6[0];
		ip = (void *)&np_addr->np_ipv6[0];
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np_addr->np_ipv4);
		ip_buf = &buf_ipv4[0];
		ip = (void *)&np_addr->np_ipv4;
	}
	 
	np = core_get_np(ip, np_addr->np_port, network_transport);
	if (!(np)) {
		np = core_add_np(np_addr, network_transport, &ret);
		if (!(np))
			return ERR_PTR(ret);
	}

	tpg_np = kzalloc(sizeof(iscsi_tpg_np_t), GFP_KERNEL);
	if (!(tpg_np)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" iscsi_tpg_np_t.\n");
		return ERR_PTR(-ENOMEM);
	}
#ifdef SNMP_SUPPORT
	tpg_np->tpg_np_index	= iscsi_get_new_index(ISCSI_PORTAL_INDEX);
#endif  
	INIT_LIST_HEAD(&tpg_np->tpg_np_list);
	INIT_LIST_HEAD(&tpg_np->tpg_np_child_list);
	INIT_LIST_HEAD(&tpg_np->tpg_np_parent_list);
	spin_lock_init(&tpg_np->tpg_np_parent_lock);
	tpg_np->tpg_np		= np;
	tpg_np->tpg		= tpg;

	spin_lock(&tpg->tpg_np_lock);
	list_add_tail(&tpg_np->tpg_np_list, &tpg->tpg_gnp_list);
	tpg->num_tpg_nps++;
	if (tpg->tpg_tiqn)
		tpg->tpg_tiqn->tiqn_num_tpg_nps++;
	spin_unlock(&tpg->tpg_np_lock);

	if (tpg_np_parent) {
		tpg_np->tpg_np_parent = tpg_np_parent;
		spin_lock(&tpg_np_parent->tpg_np_parent_lock);
		list_add_tail(&tpg_np->tpg_np_child_list,
			&tpg_np_parent->tpg_np_parent_list);
		spin_unlock(&tpg_np_parent->tpg_np_parent_lock);
	}

#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE[%s] - Added Network Portal: %s:%hu,%hu on %s on"
		" network device: %s\n", tpg->tpg_tiqn->tiqn, ip_buf,
		np->np_port, tpg->tpgt,
		(np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP", (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");
#endif

	spin_lock(&np->np_state_lock);
	np->np_exports++;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Incremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
#endif
	spin_unlock(&np->np_state_lock);

	return tpg_np;
}

static int iscsi_tpg_release_np(
	iscsi_tpg_np_t *tpg_np,
	iscsi_portal_group_t *tpg,
	iscsi_np_t *np)
{
	char *ip;
	char buf_ipv4[IPV4_BUF_SIZE];

	if (np->np_net_size == IPV6_ADDRESS_SPACE)
		ip = &np->np_ipv6[0];
	else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
	}

	iscsi_clear_tpg_np_login_thread(tpg_np, tpg, 1);

#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE[%s] - Removed Network Portal: %s:%hu,%hu on %s"
		" on network device: %s\n", tpg->tpg_tiqn->tiqn, ip,
		np->np_port, tpg->tpgt,
		(np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");
#endif

	tpg_np->tpg_np = NULL;
	tpg_np->tpg = NULL;
	kfree(tpg_np);

	spin_lock(&np->np_state_lock);
	if ((--np->np_exports == 0) && !(ISCSI_TPG_ATTRIB(tpg)->cache_core_nps))
		atomic_set(&np->np_shutdown, 1);
#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
#endif
	spin_unlock(&np->np_state_lock);

	if (atomic_read(&np->np_shutdown))
		core_del_np(np);

	return 0;
}

int iscsi_tpg_del_network_portal(
	iscsi_portal_group_t *tpg,
	iscsi_tpg_np_t *tpg_np)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np_child, *tpg_np_child_tmp;
	int ret = 0;

	np = tpg_np->tpg_np;
	if (!(np)) {
		printk(KERN_ERR "Unable to locate iscsi_np_t from"
				" iscsi_tpg_np_t\n");
		return -EINVAL;
	}

	if (!tpg_np->tpg_np_parent) {
		 
		list_for_each_entry_safe(tpg_np_child, tpg_np_child_tmp,
				&tpg_np->tpg_np_parent_list,
				tpg_np_child_list) {
			ret = iscsi_tpg_del_network_portal(tpg, tpg_np_child);
			if (ret < 0)
				printk(KERN_ERR "iscsi_tpg_del_network_portal()"
					" failed: %d\n", ret);
		}
	} else {
		 
		spin_lock(&tpg_np->tpg_np_parent->tpg_np_parent_lock);
		list_del(&tpg_np->tpg_np_child_list);
		spin_unlock(&tpg_np->tpg_np_parent->tpg_np_parent_lock);
	}

	spin_lock(&tpg->tpg_np_lock);
	list_del(&tpg_np->tpg_np_list);
	tpg->num_tpg_nps--;
	if (tpg->tpg_tiqn)
		tpg->tpg_tiqn->tiqn_num_tpg_nps--;
	spin_unlock(&tpg->tpg_np_lock);

	return iscsi_tpg_release_np(tpg_np, tpg, np);
}

int iscsi_tpg_set_initiator_node_queue_depth(
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname,
	u32 queue_depth,
	int force)
{
	return core_tpg_set_initiator_node_queue_depth(tpg->tpg_se_tpg,
		initiatorname, queue_depth, force);
}

int iscsi_ta_authentication(iscsi_portal_group_t *tpg, u32 authentication)
{
	unsigned char buf1[256], buf2[256], *none = NULL;
	int len;
	iscsi_param_t *param;
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((authentication != 1) && (authentication != 0)) {
		printk(KERN_ERR "Illegal value for authentication parameter:"
			" %u, ignoring request.\n", authentication);
		return -1;
	}

	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));

	param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list);
	if (!(param))
		return -EINVAL;

	if (authentication) {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		none = strstr(buf1, NONE);
		if (!(none))
			goto out;
		if (!strncmp(none + 4, ",", 1)) {
			if (!strcmp(buf1, none))
				sprintf(buf2, "%s", none+5);
			else {
				none--;
				*none = '\0';
				len = sprintf(buf2, "%s", buf1);
				none += 5;
				sprintf(buf2 + len, "%s", none);
			}
		} else {
			none--;
			*none = '\0';
			sprintf(buf2, "%s", buf1);
		}
		if (iscsi_update_param_value(param, buf2) < 0)
			return -EINVAL;
	} else {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		none = strstr(buf1, NONE);
		if ((none))
			goto out;
		strncat(buf1, ",", strlen(","));
		strncat(buf1, NONE, strlen(NONE));
		if (iscsi_update_param_value(param, buf1) < 0)
			return -EINVAL;
	}

out:
	a->authentication = authentication;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "%s iSCSI Authentication Methods for TPG: %hu.\n",
		a->authentication ? "Enforcing" : "Disabling", tpg->tpgt);
#endif

	return 0;
}

int iscsi_ta_login_timeout(
	iscsi_portal_group_t *tpg,
	u32 login_timeout)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if (login_timeout > TA_LOGIN_TIMEOUT_MAX) {
		printk(KERN_ERR "Requested Login Timeout %u larger than maximum"
			" %u\n", login_timeout, TA_LOGIN_TIMEOUT_MAX);
		return -EINVAL;
	} else if (login_timeout < TA_LOGIN_TIMEOUT_MIN) {
		printk(KERN_ERR "Requested Logout Timeout %u smaller than"
			" minimum %u\n", login_timeout, TA_LOGIN_TIMEOUT_MIN);
		return -EINVAL;
	}

	a->login_timeout = login_timeout;
	printk(KERN_INFO "Set Logout Timeout to %u for Target Portal Group"
		" %hu\n", a->login_timeout, tpg->tpgt);

	return 0;
}

int iscsi_ta_netif_timeout(
	iscsi_portal_group_t *tpg,
	u32 netif_timeout)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if (netif_timeout > TA_NETIF_TIMEOUT_MAX) {
		printk(KERN_ERR "Requested Network Interface Timeout %u larger"
			" than maximum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MAX);
		return -EINVAL;
	} else if (netif_timeout < TA_NETIF_TIMEOUT_MIN) {
		printk(KERN_ERR "Requested Network Interface Timeout %u smaller"
			" than minimum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MIN);
		return -EINVAL;
	}

	a->netif_timeout = netif_timeout;
	printk(KERN_INFO "Set Network Interface Timeout to %u for"
		" Target Portal Group %hu\n", a->netif_timeout, tpg->tpgt);

	return 0;
}

int iscsi_ta_generate_node_acls(
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->generate_node_acls = flag;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "iSCSI_TPG[%hu] - Generate Initiator Portal Group ACLs: %s\n",
		tpg->tpgt, (a->generate_node_acls) ? "Enabled" : "Disabled");
#endif

	return 0;
}

int iscsi_ta_default_cmdsn_depth(
	iscsi_portal_group_t *tpg,
	u32 tcq_depth)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if (tcq_depth > TA_DEFAULT_CMDSN_DEPTH_MAX) {
		printk(KERN_ERR "Requested Default Queue Depth: %u larger"
			" than maximum %u\n", tcq_depth,
				TA_DEFAULT_CMDSN_DEPTH_MAX);
		return -EINVAL;
	} else if (tcq_depth < TA_DEFAULT_CMDSN_DEPTH_MIN) {
		printk(KERN_ERR "Requested Default Queue Depth: %u smaller"
			" than minimum %u\n", tcq_depth,
				TA_DEFAULT_CMDSN_DEPTH_MIN);
		return -EINVAL;
	}

	a->default_cmdsn_depth = tcq_depth;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "iSCSI_TPG[%hu] - Set Default CmdSN TCQ Depth to %u\n",
		tpg->tpgt, a->default_cmdsn_depth);
#endif

	return 0;
}

int iscsi_ta_cache_dynamic_acls(
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->cache_dynamic_acls = flag;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "iSCSI_TPG[%hu] - Cache Dynamic Initiator Portal Group"
		" ACLs %s\n", tpg->tpgt, (a->cache_dynamic_acls) ?
		"Enabled" : "Disabled");
#endif

	return 0;
}

int iscsi_ta_demo_mode_write_protect(
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->demo_mode_write_protect = flag;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "iSCSI_TPG[%hu] - Demo Mode Write Protect bit: %s\n",
		tpg->tpgt, (a->demo_mode_write_protect) ? "ON" : "OFF");
#endif

	return 0;
}

int iscsi_ta_prod_mode_write_protect(
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->prod_mode_write_protect = flag;
#ifndef MY_ABC_HERE
	printk(KERN_INFO "iSCSI_TPG[%hu] - Production Mode Write Protect bit:"
		" %s\n", tpg->tpgt, (a->prod_mode_write_protect) ?
		"ON" : "OFF");
#endif

	return 0;
}

void iscsi_disable_tpgs(iscsi_tiqn_t *tiqn)
{
	iscsi_portal_group_t *tpg;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {

		spin_lock(&tpg->tpg_state_lock);
		if ((tpg->tpg_state == TPG_STATE_FREE) ||
		    (tpg->tpg_state == TPG_STATE_INACTIVE)) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);
		spin_unlock(&tiqn->tiqn_tpg_lock);

		iscsi_tpg_disable_portal_group(tpg, 1);

		spin_lock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);
}

void iscsi_disable_all_tpgs(void)
{
	iscsi_tiqn_t *tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_disable_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);
}

void iscsi_remove_tpgs(iscsi_tiqn_t *tiqn)
{
	iscsi_portal_group_t *tpg, *tpg_tmp;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry_safe(tpg, tpg_tmp, &tiqn->tiqn_tpg_list, tpg_list) {

		spin_lock(&tpg->tpg_state_lock);
		if (tpg->tpg_state == TPG_STATE_FREE) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);
		spin_unlock(&tiqn->tiqn_tpg_lock);

		iscsi_tpg_del_portal_group(tiqn, tpg, 1);

		spin_lock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);
}

void iscsi_remove_all_tpgs(void)
{
	iscsi_tiqn_t *tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_remove_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);
}
