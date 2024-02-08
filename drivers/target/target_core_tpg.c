#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define TARGET_CORE_TPG_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_tpg.h>
#include <target/target_core_transport.h>
#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>
#include <target/target_core_fabric_ops.h>

#undef TARGET_CORE_TPG_C

static void core_clear_initiator_node_from_tpg(
	se_node_acl_t *nacl,
	se_portal_group_t *tpg)
{
	int i;
	se_dev_entry_t *deve;
	se_lun_t *lun;
	se_lun_acl_t *acl, *acl_tmp;

	spin_lock_bh(&nacl->device_list_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		deve = &nacl->device_list[i];

		if (!(deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS))
			continue;

		if (!deve->se_lun) {
			printk(KERN_ERR "%s device entries device pointer is"
				" NULL, but Initiator has access.\n",
				TPG_TFO(tpg)->get_fabric_name());
			continue;
		}

		lun = deve->se_lun;
		spin_unlock_bh(&nacl->device_list_lock);
		core_update_device_list_for_node(lun, NULL, deve->mapped_lun,
			TRANSPORT_LUNFLAGS_NO_ACCESS, nacl, tpg, 0);

		spin_lock(&lun->lun_acl_lock);
		list_for_each_entry_safe(acl, acl_tmp,
					&lun->lun_acl_list, lacl_list) {
			if (!(strcmp(acl->initiatorname,
					nacl->initiatorname)) &&
			     (acl->mapped_lun == deve->mapped_lun))
				break;
		}

		if (!acl) {
			printk(KERN_ERR "Unable to locate se_lun_acl_t for %s,"
				" mapped_lun: %u\n", nacl->initiatorname,
				deve->mapped_lun);
			spin_unlock(&lun->lun_acl_lock);
			spin_lock_bh(&nacl->device_list_lock);
			continue;
		}

		list_del(&acl->lacl_list);
		spin_unlock(&lun->lun_acl_lock);

		spin_lock_bh(&nacl->device_list_lock);
		kfree(acl);
	}
	spin_unlock_bh(&nacl->device_list_lock);
}

se_node_acl_t *__core_tpg_get_initiator_node_acl(
	se_portal_group_t *tpg,
	const char *initiatorname)
{
	se_node_acl_t *acl;

	list_for_each_entry(acl, &tpg->acl_node_list, acl_list) {
#ifdef MY_ABC_HERE
		if( !tpg->default_acl && !(strcmp(acl->initiatorname, SYNO_LIO_DEFAULT_ACL_INITIATOR)) ) {
			tpg->default_acl = acl;
		}
#endif
		if (!(strcmp(acl->initiatorname, initiatorname)))
			return acl;
	}

	return NULL;
}

se_node_acl_t *core_tpg_get_initiator_node_acl(
	se_portal_group_t *tpg,
	unsigned char *initiatorname)
{
	se_node_acl_t *acl;

	spin_lock_bh(&tpg->acl_node_lock);
	list_for_each_entry(acl, &tpg->acl_node_list, acl_list) {
#ifdef MY_ABC_HERE
		if( !tpg->default_acl && !(strcmp(acl->initiatorname, SYNO_LIO_DEFAULT_ACL_INITIATOR)) ) {
			tpg->default_acl = acl;
		}
#endif
		if (!(strcmp(acl->initiatorname, initiatorname)) &&
		   (!(acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL))) {
			spin_unlock_bh(&tpg->acl_node_lock);
			return acl;
		}
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	return NULL;
}

void core_tpg_add_node_to_devs(
	se_node_acl_t *acl,
	se_portal_group_t *tpg)
{
	int i = 0;
	u32 lun_access = 0;
	se_lun_t *lun;
#ifdef MY_ABC_HERE
	struct se_device_s *dev;
#endif

	spin_lock(&tpg->tpg_lun_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		lun = &tpg->tpg_lun_list[i];
		if (lun->lun_status != TRANSPORT_LUN_STATUS_ACTIVE)
			continue;

#ifdef MY_ABC_HERE
		dev = lun->se_dev;
#endif
		spin_unlock(&tpg->tpg_lun_lock);
		 
		if (!(TPG_TFO(tpg)->tpg_check_demo_mode_write_protect(tpg))) {
#ifdef MY_ABC_HERE
			if (dev->dev_flags & DF_READ_ONLY)
				lun_access = TRANSPORT_LUNFLAGS_READ_ONLY;
			else
				lun_access = TRANSPORT_LUNFLAGS_READ_WRITE;
#else
			if (LUN_OBJ_API(lun)->get_device_access) {
				if (LUN_OBJ_API(lun)->get_device_access(
						lun->lun_type_ptr) == 0)
					lun_access =
						TRANSPORT_LUNFLAGS_READ_ONLY;
				else
					lun_access =
						TRANSPORT_LUNFLAGS_READ_WRITE;
			} else
				lun_access = TRANSPORT_LUNFLAGS_READ_WRITE;
#endif
		} else {
			 
#ifdef MY_ABC_HERE
			if (TRANSPORT(dev)->get_device_type(dev) == TYPE_DISK)
				lun_access = TRANSPORT_LUNFLAGS_READ_ONLY;
			else
				lun_access = TRANSPORT_LUNFLAGS_READ_WRITE;
#else
			if (LUN_OBJ_API(lun)->get_device_type(
					lun->lun_type_ptr) == TYPE_DISK)
				lun_access = TRANSPORT_LUNFLAGS_READ_ONLY;
			else
				lun_access = TRANSPORT_LUNFLAGS_READ_WRITE;
#endif
		}

#ifndef MY_ABC_HERE
		printk(KERN_INFO "TARGET_CORE[%s]->TPG[%u]_LUN[%u] - Adding %s"
			" access for LUN in Demo Mode\n",
			TPG_TFO(tpg)->get_fabric_name(),
			TPG_TFO(tpg)->tpg_get_tag(tpg), lun->unpacked_lun,
			(lun_access == TRANSPORT_LUNFLAGS_READ_WRITE) ?
			"READ-WRITE" : "READ-ONLY");
#endif

		core_update_device_list_for_node(lun, NULL, lun->unpacked_lun,
				lun_access, acl, tpg, 1);
		spin_lock(&tpg->tpg_lun_lock);
	}
	spin_unlock(&tpg->tpg_lun_lock);
}

static int core_set_queue_depth_for_node(
	se_portal_group_t *tpg,
	se_node_acl_t *acl)
{
	if (!acl->queue_depth) {
		printk(KERN_ERR "Queue depth for %s Initiator Node: %s is 0,"
			"defaulting to 1.\n", TPG_TFO(tpg)->get_fabric_name(),
			acl->initiatorname);
		acl->queue_depth = 1;
	}

	return 0;
}

static int core_create_device_list_for_node(se_node_acl_t *nacl)
{
	se_dev_entry_t *deve;
	int i;

	nacl->device_list = kzalloc(sizeof(se_dev_entry_t) *
				TRANSPORT_MAX_LUNS_PER_TPG, GFP_KERNEL);
	if (!(nacl->device_list)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" se_node_acl_t->device_list\n");
		return -1;
	}
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		deve = &nacl->device_list[i];

		atomic_set(&deve->ua_count, 0);
		atomic_set(&deve->pr_ref_count, 0);
		spin_lock_init(&deve->ua_lock);
		INIT_LIST_HEAD(&deve->alua_port_list);
		INIT_LIST_HEAD(&deve->ua_list);
	}

	return 0;
}

#ifdef MY_ABC_HERE
static void core_tpg_default_acl_dup_devs(se_node_acl_t* dst_acl, se_node_acl_t* src_acl, se_portal_group_t* tpg)
{
	size_t i = 0;
	u32 lun_access = 0;
	se_lun_t* lun = NULL;
	se_dev_entry_t* deve = NULL;

	spin_lock_bh(&src_acl->device_list_lock);
	for( i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; ++i ) {
		if( !(&src_acl->device_list[i]) ) {
			continue;
		}

#ifdef MY_ABC_HERE
		 
		if( (lun = src_acl->device_list[i].se_lun) ) {
#else
		if( lun = src_acl->device_list[i].se_lun ) {
#endif
			if( TRANSPORT_LUN_STATUS_ACTIVE != lun->lun_status ) {
				continue;
			}

			if( src_acl->device_list[i].lun_flags & TRANSPORT_LUNFLAGS_READ_WRITE ) {
				lun_access = TRANSPORT_LUNFLAGS_READ_WRITE;
			} else {
				lun_access = TRANSPORT_LUNFLAGS_READ_ONLY;
			}

#ifndef MY_ABC_HERE
			printk(KERN_INFO "TARGET_CORE[%s]->TPG[%u]_LUN[%u] - Adding %s access for LUN\n",
				TPG_TFO(tpg)->get_fabric_name(),
				TPG_TFO(tpg)->tpg_get_tag(tpg), lun->unpacked_lun,
				(lun_access == TRANSPORT_LUNFLAGS_READ_WRITE) ?
				"READ-WRITE" : "READ-ONLY");
#endif

			deve = &src_acl->device_list[i];
			core_update_device_list_for_node(lun, deve->se_lun_acl, lun->unpacked_lun, lun_access, dst_acl, tpg, 1);
		}

	}
	spin_unlock_bh(&src_acl->device_list_lock);
}
#endif

se_node_acl_t *core_tpg_check_initiator_node_acl(
	se_portal_group_t *tpg,
	unsigned char *initiatorname)
{
	se_node_acl_t *acl;

	acl = core_tpg_get_initiator_node_acl(tpg, initiatorname);
	if ((acl))
		return acl;

#ifdef MY_ABC_HERE
	if( !tpg->default_acl && !(TPG_TFO(tpg)->tpg_check_demo_mode(tpg)) ) {
			return NULL;
	}
#else
	if (!(TPG_TFO(tpg)->tpg_check_demo_mode(tpg)))
		return NULL;
#endif

	acl = kzalloc(sizeof(se_node_acl_t), GFP_KERNEL);
	if (!(acl)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" se_node_acl_t.\n");
		return NULL;
	}

	INIT_LIST_HEAD(&acl->acl_list);
	INIT_LIST_HEAD(&acl->acl_sess_list);
	spin_lock_init(&acl->device_list_lock);
	spin_lock_init(&acl->nacl_sess_lock);
	atomic_set(&acl->acl_pr_ref_count, 0);
	acl->queue_depth = TPG_TFO(tpg)->tpg_get_default_depth(tpg);
	snprintf(acl->initiatorname, TRANSPORT_IQN_LEN, "%s", initiatorname);
	acl->se_tpg = tpg;
#ifdef SNMP_SUPPORT
	acl->acl_index = scsi_get_new_index(SCSI_AUTH_INTR_INDEX);
	spin_lock_init(&acl->stats_lock);
#endif  
	acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;

	acl->fabric_acl_ptr = TPG_TFO(tpg)->tpg_alloc_fabric_acl(tpg,
			acl);
	if (!(acl->fabric_acl_ptr)) {
		kfree(acl);
		return NULL;
	}
	TPG_TFO(tpg)->set_default_node_attributes(acl);
#ifdef MY_ABC_HERE
	if( tpg->default_acl && !(TPG_TFO(tpg)->tpg_check_demo_mode(tpg)) ) {
		TPG_TFO(tpg)->dup_node_attributes(acl, tpg->default_acl);
	}
#endif

	if (core_create_device_list_for_node(acl) < 0) {
		TPG_TFO(tpg)->tpg_release_fabric_acl(tpg, acl);
		kfree(acl);
		return NULL;
	}

	if (core_set_queue_depth_for_node(tpg, acl) < 0) {
		core_free_device_list_for_node(acl, tpg);
		TPG_TFO(tpg)->tpg_release_fabric_acl(tpg, acl);
		kfree(acl);
		return NULL;
	}

#ifdef MY_ABC_HERE
	if( tpg->default_acl && !(TPG_TFO(tpg)->tpg_check_demo_mode(tpg)) ) {
		core_tpg_default_acl_dup_devs(acl, tpg->default_acl, tpg);
	} else
#endif
	core_tpg_add_node_to_devs(acl, tpg);

	spin_lock_bh(&tpg->acl_node_lock);
	list_add_tail(&acl->acl_list, &tpg->acl_node_list);
	tpg->num_node_acls++;
	spin_unlock_bh(&tpg->acl_node_lock);

#ifndef MY_ABC_HERE
	printk("%s_TPG[%u] - Added DYNAMIC ACL with TCQ Depth: %d for %s"
		" Initiator Node: %s\n", TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg), acl->queue_depth,
		TPG_TFO(tpg)->get_fabric_name(), initiatorname);
#endif

	return acl;
}
EXPORT_SYMBOL(core_tpg_check_initiator_node_acl);

void core_tpg_wait_for_nacl_pr_ref(se_node_acl_t *nacl)
{
	while (atomic_read(&nacl->acl_pr_ref_count) != 0)
		msleep(100);
}

void core_tpg_free_node_acls(se_portal_group_t *tpg)
{
	se_node_acl_t *acl, *acl_tmp;

	spin_lock_bh(&tpg->acl_node_lock);
	list_for_each_entry_safe(acl, acl_tmp, &tpg->acl_node_list, acl_list) {
		 
		if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL)
			continue;

		core_tpg_wait_for_nacl_pr_ref(acl);
		kfree(acl);
		tpg->num_node_acls--;
	}
	spin_unlock_bh(&tpg->acl_node_lock);
}
EXPORT_SYMBOL(core_tpg_free_node_acls);

void core_tpg_clear_object_luns(se_portal_group_t *tpg)
{
	int i, ret;
	se_lun_t *lun;

	spin_lock(&tpg->tpg_lun_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		lun = &tpg->tpg_lun_list[i];

		if ((lun->lun_status != TRANSPORT_LUN_STATUS_ACTIVE) ||
		    (lun->lun_type_ptr == NULL))
			continue;

		spin_unlock(&tpg->tpg_lun_lock);
#ifdef MY_ABC_HERE
		ret = core_dev_del_lun(tpg, lun->unpacked_lun);
#else
		ret = LUN_OBJ_API(lun)->del_obj_from_lun(tpg, lun);
#endif
		spin_lock(&tpg->tpg_lun_lock);
	}
	spin_unlock(&tpg->tpg_lun_lock);
}
EXPORT_SYMBOL(core_tpg_clear_object_luns);

se_node_acl_t *core_tpg_add_initiator_node_acl(
	se_portal_group_t *tpg,
	const char *initiatorname,
	u32 queue_depth)
{
	se_node_acl_t *acl = NULL;

	spin_lock_bh(&tpg->acl_node_lock);
	acl = __core_tpg_get_initiator_node_acl(tpg, initiatorname);
	if ((acl)) {
		if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
			acl->nodeacl_flags &= ~NAF_DYNAMIC_NODE_ACL;
			printk(KERN_INFO "%s_TPG[%u] - Replacing dynamic ACL"
				" for %s\n", TPG_TFO(tpg)->get_fabric_name(),
				TPG_TFO(tpg)->tpg_get_tag(tpg), initiatorname);
			spin_unlock_bh(&tpg->acl_node_lock);
			goto done;
		}

		printk(KERN_ERR "ACL entry for %s Initiator"
			" Node %s already exists for TPG %u, ignoring"
			" request.\n",  TPG_TFO(tpg)->get_fabric_name(),
			initiatorname, TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock_bh(&tpg->acl_node_lock);
		return ERR_PTR(-EEXIST);
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	acl = kzalloc(sizeof(se_node_acl_t), GFP_KERNEL);
	if (!(acl)) {
		printk(KERN_ERR "Unable to allocate memory for senode_acl_t.\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&acl->acl_list);
	INIT_LIST_HEAD(&acl->acl_sess_list);
	spin_lock_init(&acl->device_list_lock);
	spin_lock_init(&acl->nacl_sess_lock);
	atomic_set(&acl->acl_pr_ref_count, 0);
	acl->queue_depth = queue_depth;
	snprintf(acl->initiatorname, TRANSPORT_IQN_LEN, "%s", initiatorname);
	acl->se_tpg = tpg;
#ifdef SNMP_SUPPORT
	acl->acl_index = scsi_get_new_index(SCSI_AUTH_INTR_INDEX);
	spin_lock_init(&acl->stats_lock);
#endif  

	acl->fabric_acl_ptr = TPG_TFO(tpg)->tpg_alloc_fabric_acl(tpg,
			acl);
	if (!(acl->fabric_acl_ptr)) {
		kfree(acl);
		return ERR_PTR(-ENOMEM);
	}
	TPG_TFO(tpg)->set_default_node_attributes(acl);

	if (core_create_device_list_for_node(acl) < 0) {
		TPG_TFO(tpg)->tpg_release_fabric_acl(tpg, acl);
		kfree(acl);
		return ERR_PTR(-ENOMEM);
	}

	if (core_set_queue_depth_for_node(tpg, acl) < 0) {
		core_free_device_list_for_node(acl, tpg);
		TPG_TFO(tpg)->tpg_release_fabric_acl(tpg, acl);
		kfree(acl);
		return ERR_PTR(-EINVAL);
	}

	spin_lock_bh(&tpg->acl_node_lock);
	list_add_tail(&acl->acl_list, &tpg->acl_node_list);
	tpg->num_node_acls++;
	spin_unlock_bh(&tpg->acl_node_lock);

done:
#ifndef MY_ABC_HERE
	printk(KERN_INFO "%s_TPG[%hu] - Added ACL with TCQ Depth: %d for %s"
		" Initiator Node: %s\n", TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg), acl->queue_depth,
		TPG_TFO(tpg)->get_fabric_name(), initiatorname);
#endif

	return acl;
}
EXPORT_SYMBOL(core_tpg_add_initiator_node_acl);

int core_tpg_del_initiator_node_acl(
	se_portal_group_t *tpg,
	se_node_acl_t *acl,
	int force)
{
	se_session_t *sess, *sess_tmp;
	int dynamic_acl = 0;

	spin_lock_bh(&tpg->acl_node_lock);
	if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
		acl->nodeacl_flags &= ~NAF_DYNAMIC_NODE_ACL;
		dynamic_acl = 1;
	}
	list_del(&acl->acl_list);
	tpg->num_node_acls--;
	spin_unlock_bh(&tpg->acl_node_lock);

	spin_lock_bh(&tpg->session_lock);
	list_for_each_entry_safe(sess, sess_tmp,
				&tpg->tpg_sess_list, sess_list) {
		if (sess->se_node_acl != acl)
			continue;
		 
		if (!(TPG_TFO(tpg)->shutdown_session(sess)))
			continue;

		spin_unlock_bh(&tpg->session_lock);
		 
		TPG_TFO(tpg)->close_session(sess);

		spin_lock_bh(&tpg->session_lock);
	}
	spin_unlock_bh(&tpg->session_lock);

	core_tpg_wait_for_nacl_pr_ref(acl);
	core_clear_initiator_node_from_tpg(acl, tpg);
	core_free_device_list_for_node(acl, tpg);

	TPG_TFO(tpg)->tpg_release_fabric_acl(tpg, acl);
	acl->fabric_acl_ptr = NULL;

#ifndef MY_ABC_HERE
	printk(KERN_INFO "%s_TPG[%hu] - Deleted ACL with TCQ Depth: %d for %s"
		" Initiator Node: %s\n", TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg), acl->queue_depth,
		TPG_TFO(tpg)->get_fabric_name(), acl->initiatorname);
#endif

	kfree(acl);
	return 0;
}
EXPORT_SYMBOL(core_tpg_del_initiator_node_acl);

int core_tpg_set_initiator_node_queue_depth(
	se_portal_group_t *tpg,
	unsigned char *initiatorname,
	u32 queue_depth,
	int force)
{
	se_session_t *sess, *init_sess = NULL;
	se_node_acl_t *acl;
	int dynamic_acl = 0;

	spin_lock_bh(&tpg->acl_node_lock);
	acl = __core_tpg_get_initiator_node_acl(tpg, initiatorname);
	if (!(acl)) {
		printk(KERN_ERR "Access Control List entry for %s Initiator"
			" Node %s does not exists for TPG %hu, ignoring"
			" request.\n", TPG_TFO(tpg)->get_fabric_name(),
			initiatorname, TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock_bh(&tpg->acl_node_lock);
		return -ENODEV;
	}
	if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
		acl->nodeacl_flags &= ~NAF_DYNAMIC_NODE_ACL;
		dynamic_acl = 1;
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	spin_lock_bh(&tpg->session_lock);
	list_for_each_entry(sess, &tpg->tpg_sess_list, sess_list) {
		if (sess->se_node_acl != acl)
			continue;

		if (!force) {
			printk(KERN_ERR "Unable to change queue depth for %s"
				" Initiator Node: %s while session is"
				" operational.  To forcefully change the queue"
				" depth and force session reinstatement"
				" use the \"force=1\" parameter.\n",
				TPG_TFO(tpg)->get_fabric_name(), initiatorname);
			spin_unlock_bh(&tpg->session_lock);

			spin_lock_bh(&tpg->acl_node_lock);
			if (dynamic_acl)
				acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;
			spin_unlock_bh(&tpg->acl_node_lock);
			return -EEXIST;
		}
		 
		if (!(TPG_TFO(tpg)->shutdown_session(sess)))
			continue;

		init_sess = sess;
		break;
	}

	acl->queue_depth = queue_depth;

	if (core_set_queue_depth_for_node(tpg, acl) < 0) {
		spin_unlock_bh(&tpg->session_lock);
		 
		if (init_sess)
			TPG_TFO(tpg)->close_session(init_sess);

		spin_lock_bh(&tpg->acl_node_lock);
		if (dynamic_acl)
			acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;
		spin_unlock_bh(&tpg->acl_node_lock);
		return -EINVAL;
	}
	spin_unlock_bh(&tpg->session_lock);
	 
	if (init_sess)
		TPG_TFO(tpg)->close_session(init_sess);

	printk(KERN_INFO "Successfuly changed queue depth to: %d for Initiator"
		" Node: %s on %s Target Portal Group: %u\n", queue_depth,
		initiatorname, TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg));

	spin_lock_bh(&tpg->acl_node_lock);
	if (dynamic_acl)
		acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;
	spin_unlock_bh(&tpg->acl_node_lock);

	return 0;
}
EXPORT_SYMBOL(core_tpg_set_initiator_node_queue_depth);

static int core_tpg_setup_virtual_lun0(struct se_portal_group_s *se_tpg)
{
	 
	struct se_device_s *dev = se_global->g_lun0_dev;
	struct se_lun_s *lun = &se_tpg->tpg_virt_lun0;
	u32 lun_access = TRANSPORT_LUNFLAGS_READ_ONLY;
	int ret;

	lun->unpacked_lun = 0;	
	lun->lun_type_ptr = NULL;
	lun->lun_status = TRANSPORT_LUN_STATUS_FREE;
	atomic_set(&lun->lun_acl_count, 0);
#ifdef MY_ABC_HERE
	init_completion(&lun->lun_shutdown_comp);
#endif
	INIT_LIST_HEAD(&lun->lun_acl_list);
	INIT_LIST_HEAD(&lun->lun_cmd_list);
	spin_lock_init(&lun->lun_acl_lock);
	spin_lock_init(&lun->lun_cmd_lock);
	spin_lock_init(&lun->lun_sep_lock);

#ifdef MY_ABC_HERE
	ret = core_tpg_post_addlun(se_tpg, lun, TRANSPORT_LUN_TYPE_DEVICE,
			lun_access, dev);
#else
	ret = core_tpg_post_addlun(se_tpg, lun, TRANSPORT_LUN_TYPE_DEVICE,	
			lun_access, dev, dev->dev_obj_api);
#endif
	if (ret < 0)
		return -1;

	return 0;
}

static void core_tpg_release_virtual_lun0(struct se_portal_group_s *se_tpg)
{
	struct se_lun_s *lun = &se_tpg->tpg_virt_lun0;

	core_tpg_post_dellun(se_tpg, lun);
}

se_portal_group_t *core_tpg_register(
	struct target_core_fabric_ops *tfo,
	void *tpg_fabric_ptr,
	int se_tpg_type)
{
	se_lun_t *lun;
	se_portal_group_t *se_tpg;
	u32 i;

	se_tpg = kzalloc(sizeof(se_portal_group_t), GFP_KERNEL);
	if (!(se_tpg)) {
		printk(KERN_ERR "Unable to allocate se_portal_group_t\n");
		return ERR_PTR(-ENOMEM);
	}

	se_tpg->tpg_lun_list = kzalloc((sizeof(se_lun_t) *
				TRANSPORT_MAX_LUNS_PER_TPG), GFP_KERNEL);
	if (!(se_tpg->tpg_lun_list)) {
		printk(KERN_ERR "Unable to allocate se_portal_group_t->"
				"tpg_lun_list\n");
		kfree(se_tpg);
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		lun = &se_tpg->tpg_lun_list[i];
		lun->unpacked_lun = i;
		lun->lun_type_ptr = NULL;
		lun->lun_status = TRANSPORT_LUN_STATUS_FREE;
		atomic_set(&lun->lun_acl_count, 0);
#ifdef MY_ABC_HERE
		init_completion(&lun->lun_shutdown_comp);
#endif
		INIT_LIST_HEAD(&lun->lun_acl_list);
		INIT_LIST_HEAD(&lun->lun_cmd_list);
		spin_lock_init(&lun->lun_acl_lock);
		spin_lock_init(&lun->lun_cmd_lock);
		spin_lock_init(&lun->lun_sep_lock);
	}

	se_tpg->se_tpg_type = se_tpg_type;
	se_tpg->se_tpg_fabric_ptr = tpg_fabric_ptr;
	se_tpg->se_tpg_tfo = tfo;
	atomic_set(&se_tpg->tpg_pr_ref_count, 0);
	INIT_LIST_HEAD(&se_tpg->acl_node_list);
	INIT_LIST_HEAD(&se_tpg->se_tpg_list);
	INIT_LIST_HEAD(&se_tpg->tpg_sess_list);
	spin_lock_init(&se_tpg->acl_node_lock);
	spin_lock_init(&se_tpg->session_lock);
	spin_lock_init(&se_tpg->tpg_lun_lock);

	if (se_tpg->se_tpg_type == TRANSPORT_TPG_TYPE_NORMAL) {
		if (core_tpg_setup_virtual_lun0(se_tpg) < 0) {
			kfree(se_tpg);
			return ERR_PTR(-ENOMEM);
		}
	}

	spin_lock_bh(&se_global->se_tpg_lock);
	list_add_tail(&se_tpg->se_tpg_list, &se_global->g_se_tpg_list);
	spin_unlock_bh(&se_global->se_tpg_lock);

#ifndef MY_ABC_HERE
	printk(KERN_INFO "TARGET_CORE[%s]: Allocated %s se_portal_group_t for"
		" endpoint: %s, Portal Tag: %u\n", tfo->get_fabric_name(),
		(se_tpg->se_tpg_type == TRANSPORT_TPG_TYPE_NORMAL) ?
		"Normal" : "Discovery", (tfo->tpg_get_wwn(se_tpg) == NULL) ?
		"None" : tfo->tpg_get_wwn(se_tpg), tfo->tpg_get_tag(se_tpg));
#endif

	return se_tpg;
}
EXPORT_SYMBOL(core_tpg_register);

int core_tpg_deregister(se_portal_group_t *se_tpg)
{
#ifndef MY_ABC_HERE
	printk(KERN_INFO "TARGET_CORE[%s]: Deallocating %s se_portal_group_t"
		" for endpoint: %s Portal Tag %u\n",
		(se_tpg->se_tpg_type == TRANSPORT_TPG_TYPE_NORMAL) ?
		"Normal" : "Discovery", TPG_TFO(se_tpg)->get_fabric_name(),
		TPG_TFO(se_tpg)->tpg_get_wwn(se_tpg),
		TPG_TFO(se_tpg)->tpg_get_tag(se_tpg));
#endif

	spin_lock_bh(&se_global->se_tpg_lock);
	list_del(&se_tpg->se_tpg_list);
	spin_unlock_bh(&se_global->se_tpg_lock);

	while (atomic_read(&se_tpg->tpg_pr_ref_count) != 0)
		msleep(100);

	if (se_tpg->se_tpg_type == TRANSPORT_TPG_TYPE_NORMAL)
		core_tpg_release_virtual_lun0(se_tpg);

	se_tpg->se_tpg_fabric_ptr = NULL;
	kfree(se_tpg->tpg_lun_list);
	kfree(se_tpg);
	return 0;
}
EXPORT_SYMBOL(core_tpg_deregister);

se_lun_t *core_tpg_pre_addlun(
	se_portal_group_t *tpg,
	u32 unpacked_lun)
{
	se_lun_t *lun;

	if (unpacked_lun > (TRANSPORT_MAX_LUNS_PER_TPG-1)) {
		printk(KERN_ERR "%s LUN: %u exceeds TRANSPORT_MAX_LUNS_PER_TPG"
			"-1: %u for Target Portal Group: %u\n",
			TPG_TFO(tpg)->get_fabric_name(),
			unpacked_lun, TRANSPORT_MAX_LUNS_PER_TPG-1,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		return ERR_PTR(-EOVERFLOW);
	}

	spin_lock(&tpg->tpg_lun_lock);
	lun = &tpg->tpg_lun_list[unpacked_lun];
	if (lun->lun_status == TRANSPORT_LUN_STATUS_ACTIVE) {
		printk(KERN_ERR "TPG Logical Unit Number: %u is already active"
			" on %s Target Portal Group: %u, ignoring request.\n",
			unpacked_lun, TPG_TFO(tpg)->get_fabric_name(),
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock(&tpg->tpg_lun_lock);
		return ERR_PTR(-EINVAL);
	}
	spin_unlock(&tpg->tpg_lun_lock);

	return lun;
}
EXPORT_SYMBOL(core_tpg_pre_addlun);

#ifdef MY_ABC_HERE
int core_tpg_post_addlun(
	se_portal_group_t *tpg,
	se_lun_t *lun,
	int lun_type,
	u32 lun_access,
	void *lun_ptr)
{
	lun->lun_type_ptr = lun_ptr;
	if (dev_obj_export(lun_ptr, tpg, lun) < 0) {
		lun->lun_type_ptr = NULL;
		return -1;
	}

	spin_lock(&tpg->tpg_lun_lock);
	lun->lun_access = lun_access;
	lun->lun_type = lun_type;
	lun->lun_status = TRANSPORT_LUN_STATUS_ACTIVE;
	spin_unlock(&tpg->tpg_lun_lock);

	return 0;
}
#else
int core_tpg_post_addlun(
	se_portal_group_t *tpg,
	se_lun_t *lun,
	int lun_type,
	u32 lun_access,
	void *lun_ptr,
	struct se_obj_lun_type_s *obj_api)
{
	lun->lun_obj_api = obj_api;
	lun->lun_type_ptr = lun_ptr;
	if (LUN_OBJ_API(lun)->export_obj(lun_ptr, tpg, lun) < 0) {
		lun->lun_type_ptr = NULL;
		lun->lun_obj_api = NULL;
		return -1;
	}

	spin_lock(&tpg->tpg_lun_lock);
	lun->lun_access = lun_access;
	lun->lun_type = lun_type;
	lun->lun_status = TRANSPORT_LUN_STATUS_ACTIVE;
	spin_unlock(&tpg->tpg_lun_lock);

	return 0;
}
#endif
EXPORT_SYMBOL(core_tpg_post_addlun);

#ifdef MY_ABC_HERE
void core_tpg_shutdown_lun(
	struct se_portal_group_s *tpg,
	struct se_lun_s *lun)
{
	core_clear_lun_from_tpg(lun, tpg);
	transport_clear_lun_from_sessions(lun);
}
#endif

se_lun_t *core_tpg_pre_dellun(
	se_portal_group_t *tpg,
	u32 unpacked_lun,
	int lun_type,
	int *ret)
{
	se_lun_t *lun;

	if (unpacked_lun > (TRANSPORT_MAX_LUNS_PER_TPG-1)) {
		printk(KERN_ERR "%s LUN: %u exceeds TRANSPORT_MAX_LUNS_PER_TPG"
			"-1: %u for Target Portal Group: %u\n",
			TPG_TFO(tpg)->get_fabric_name(), unpacked_lun,
			TRANSPORT_MAX_LUNS_PER_TPG-1,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		return ERR_PTR(-EOVERFLOW);
	}

	spin_lock(&tpg->tpg_lun_lock);
	lun = &tpg->tpg_lun_list[unpacked_lun];
	if (lun->lun_status != TRANSPORT_LUN_STATUS_ACTIVE) {
		printk(KERN_ERR "%s Logical Unit Number: %u is not active on"
			" Target Portal Group: %u, ignoring request.\n",
			TPG_TFO(tpg)->get_fabric_name(), unpacked_lun,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock(&tpg->tpg_lun_lock);
		return ERR_PTR(-ENODEV);
	}

	if (lun->lun_type != lun_type) {
		printk(KERN_ERR "%s Logical Unit Number: %u type: %d does not"
			" match passed type: %d\n",
			TPG_TFO(tpg)->get_fabric_name(),
			unpacked_lun, lun->lun_type, lun_type);
		spin_unlock(&tpg->tpg_lun_lock);
		return ERR_PTR(-EINVAL);
	}
	spin_unlock(&tpg->tpg_lun_lock);

#ifndef MY_ABC_HERE
	core_clear_lun_from_tpg(lun, tpg);
#endif

	return lun;
}
EXPORT_SYMBOL(core_tpg_pre_dellun);

int core_tpg_post_dellun(
	se_portal_group_t *tpg,
	se_lun_t *lun)
{
	se_lun_acl_t *acl, *acl_tmp;

#ifdef MY_ABC_HERE
	core_tpg_shutdown_lun(tpg, lun);
#else
	transport_clear_lun_from_sessions(lun);
#endif

#ifdef MY_ABC_HERE
	dev_obj_unexport(lun->lun_type_ptr, tpg, lun);
	transport_generic_release_phydevice(lun->lun_type_ptr, 1);
#else
	LUN_OBJ_API(lun)->unexport_obj(lun->lun_type_ptr, tpg, lun);
	LUN_OBJ_API(lun)->release_obj(lun->lun_type_ptr);
#endif

	spin_lock(&tpg->tpg_lun_lock);
	lun->lun_status = TRANSPORT_LUN_STATUS_FREE;
	lun->lun_type = 0;
	lun->lun_type_ptr = NULL;
	spin_unlock(&tpg->tpg_lun_lock);

	spin_lock(&lun->lun_acl_lock);
	list_for_each_entry_safe(acl, acl_tmp, &lun->lun_acl_list, lacl_list) {
		kfree(acl);
	}
	spin_unlock(&lun->lun_acl_lock);

	return 0;
}
EXPORT_SYMBOL(core_tpg_post_dellun);
