#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define TARGET_CORE_HBA_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_tpg.h>
#include <target/target_core_transport.h>
#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>

#undef TARGET_CORE_HBA_C

int core_get_hba(se_hba_t *hba)
{
	return ((mutex_lock_interruptible(&hba->hba_access_mutex) != 0) ?
		-1 : 0);
}

se_hba_t *core_alloc_hba(int hba_type)
{
	se_hba_t *hba;

	hba = kmem_cache_zalloc(se_hba_cache, GFP_KERNEL);
	if (!(hba)) {
		printk(KERN_ERR "Unable to allocate se_hba_t\n");
		return NULL;
	}

	hba->hba_status |= HBA_STATUS_FREE;
	hba->type = hba_type;
	INIT_LIST_HEAD(&hba->hba_dev_list);
	spin_lock_init(&hba->device_lock);
	spin_lock_init(&hba->hba_queue_lock);
	mutex_init(&hba->hba_access_mutex);
#ifdef SNMP_SUPPORT
	hba->hba_index = scsi_get_new_index(SCSI_INST_INDEX);
#endif

	return hba;
}
EXPORT_SYMBOL(core_alloc_hba);

void core_put_hba(se_hba_t *hba)
{
	mutex_unlock(&hba->hba_access_mutex);
}
EXPORT_SYMBOL(core_put_hba);

int se_core_add_hba(
	se_hba_t *hba,
	u32 plugin_dep_id)
{
	se_subsystem_api_t *t;
	int ret = 0;

	if (hba->hba_status & HBA_STATUS_ACTIVE)
		return -EEXIST;

	atomic_set(&hba->max_queue_depth, 0);
	atomic_set(&hba->left_queue_depth, 0);

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
				hba->type, &ret);
	if (!(t))
		return -EINVAL;

	ret = t->attach_hba(hba, plugin_dep_id);
	if (ret < 0)
		return ret;

	hba->hba_status &= ~HBA_STATUS_FREE;
	hba->hba_status |= HBA_STATUS_ACTIVE;

	spin_lock(&se_global->hba_lock);
	hba->hba_id = se_global->g_hba_id_counter++;
	list_add_tail(&hba->hba_list, &se_global->g_hba_list);
	spin_unlock(&se_global->hba_lock);

#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE_HBA[%d] - Attached HBA to Generic Target"
			" Core\n", hba->hba_id);
#endif

	return 0;
}
EXPORT_SYMBOL(se_core_add_hba);

static int se_core_shutdown_hba(
	se_hba_t *hba)
{
	int ret = 0;
	se_subsystem_api_t *t;

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
				hba->type, &ret);
	if (!(t))
		return ret;

	if (t->detach_hba(hba) < 0)
		return -1;

	return 0;
}

int se_core_del_hba(
	se_hba_t *hba)
{
	se_device_t *dev, *dev_tmp;

	if (!(hba->hba_status & HBA_STATUS_ACTIVE)) {
		printk(KERN_ERR "HBA ID: %d Status: INACTIVE, ignoring"
			" delhbafromtarget request\n", hba->hba_id);
		return -EINVAL;
	}

#ifndef MY_ABC_HERE
	 
	if (se_check_devices_access(hba) < 0) {
		printk(KERN_ERR "CORE_HBA[%u] - **ERROR** - Unable to release"
			" HBA with active LUNs\n", hba->hba_id);
		return -EINVAL;
	}
#endif

	spin_lock(&hba->device_lock);
	list_for_each_entry_safe(dev, dev_tmp, &hba->hba_dev_list, dev_list) {

		se_clear_dev_ports(dev);
		spin_unlock(&hba->device_lock);

		se_release_device_for_hba(dev);

		spin_lock(&hba->device_lock);
	}
	spin_unlock(&hba->device_lock);

	se_core_shutdown_hba(hba);

	spin_lock(&se_global->hba_lock);
	list_del(&hba->hba_list);
	spin_unlock(&se_global->hba_lock);

	hba->type = 0;
	hba->transport = NULL;
	hba->hba_status &= ~HBA_STATUS_ACTIVE;
	hba->hba_status |= HBA_STATUS_FREE;

#ifndef MY_ABC_HERE
	printk(KERN_INFO "CORE_HBA[%d] - Detached HBA from Generic Target"
			" Core\n", hba->hba_id);
#endif

	kmem_cache_free(se_hba_cache, hba);
	return 0;
}
EXPORT_SYMBOL(se_core_del_hba);
