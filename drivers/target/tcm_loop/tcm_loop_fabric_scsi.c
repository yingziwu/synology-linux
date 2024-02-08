#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libsas.h>  

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_device.h>
#include <target/target_core_seobj.h>
#include <target/target_core_tpg.h>

#include <tcm_loop_core.h>
#include <tcm_loop_fabric.h>
#include <tcm_loop_fabric_scsi.h>

#define to_tcm_loop_hba(hba)	container_of(hba, struct tcm_loop_hba, dev)

static struct tcm_loop_cmd *tcm_loop_allocate_core_cmd(
	struct tcm_loop_hba *tl_hba,
	se_portal_group_t *se_tpg,
	struct scsi_cmnd *sc,
	int data_direction)
{
	se_session_t *se_sess = tl_hba->tl_nexus->se_sess;
	struct tcm_loop_cmd *tl_cmd;
	int sam_task_attr;

	tl_cmd = kmem_cache_zalloc(tcm_loop_cmd_cache, GFP_ATOMIC);
	if (!(tl_cmd)) {
		printk(KERN_ERR "Unable to allocate struct tcm_loop_cmd\n");
		return NULL;
	}
	 
	tl_cmd->sc = sc;

	if (sc->device->tagged_supported) {
		switch (sc->tag) {
		case HEAD_OF_QUEUE_TAG:
			sam_task_attr = TASK_ATTR_HOQ;
			break;
		case ORDERED_QUEUE_TAG:
			sam_task_attr = TASK_ATTR_ORDERED;
			break;
		default:
			sam_task_attr = TASK_ATTR_SIMPLE;
			break;
		}
	} else
		sam_task_attr = TASK_ATTR_SIMPLE;
	 
	tl_cmd->tl_se_cmd = transport_alloc_se_cmd(se_tpg->se_tpg_tfo,
			se_sess, (void *)tl_cmd, scsi_bufflen(sc),
			data_direction, sam_task_attr);
	if (!(tl_cmd->tl_se_cmd)) {
		kmem_cache_free(tcm_loop_cmd_cache, tl_cmd);
		return NULL;
	}
			
	return tl_cmd;
}

static int tcm_loop_queue_core_cmd(
	se_queue_obj_t *qobj,
	struct tcm_loop_cmd *tl_cmd)
{
	se_queue_req_t *qr;
	unsigned long flags;

	qr = kzalloc(sizeof(se_queue_req_t), GFP_ATOMIC);
	if (!(qr)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" se_queue_req_t\n");
		return -1;	
	}
	INIT_LIST_HEAD(&qr->qr_list);

	qr->cmd = (void *)tl_cmd;
	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	list_add_tail(&qr->qr_list, &qobj->qobj_list);
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	atomic_inc(&qobj->queue_cnt);
	wake_up_interruptible(&qobj->thread_wq);
	return 0;
}

int tcm_loop_execute_core_cmd(struct tcm_loop_cmd *tl_cmd, struct scsi_cmnd *sc)
{
	se_cmd_t *se_cmd = tl_cmd->tl_se_cmd;
	void *mem_ptr;
	int ret;
	 
	if (transport_get_lun_for_cmd(se_cmd, NULL,
				tl_cmd->sc->device->lun) < 0) {
		 
		transport_send_check_condition_and_sense(se_cmd,
				se_cmd->scsi_sense_reason, 0);
		return 0;
	}
	 
	ret = transport_generic_allocate_tasks(se_cmd, tl_cmd->sc->cmnd);
	if (ret == -1) {
		 
		transport_send_check_condition_and_sense(se_cmd,
				LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
		return 0;
	} else if (ret == -2) {
		 
		if (se_cmd->se_cmd_flags & SCF_SCSI_RESERVATION_CONFLICT) {
			tcm_loop_queue_status(se_cmd);
			return 0;
		}
		 
		transport_send_check_condition_and_sense(se_cmd,
				se_cmd->scsi_sense_reason, 0);
		return 0;
	}
	 
	if (scsi_sg_count(sc)) {
		se_cmd->se_cmd_flags |= SCF_PASSTHROUGH_SG_TO_MEM;
		mem_ptr = (void *)scsi_sglist(sc);
	} else {
		 
                mem_ptr = NULL;
        }
	 
	ret = transport_generic_map_mem_to_cmd(se_cmd, mem_ptr,
				scsi_sg_count(sc));
	if (ret < 0) {
		transport_send_check_condition_and_sense(se_cmd,
				LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
		return 0;
	}
	 
	return transport_generic_handle_cdb(se_cmd);
}

void tcm_loop_check_stop_free(se_cmd_t *se_cmd)
{
	 
	transport_generic_free_cmd(se_cmd, 0, 1, 0);
}

void tcm_loop_deallocate_core_cmd(se_cmd_t *se_cmd)
{
	struct tcm_loop_cmd *tl_cmd =
			(struct tcm_loop_cmd *)se_cmd->se_fabric_cmd_ptr;

	kmem_cache_free(tcm_loop_cmd_cache, tl_cmd);
}

void tcm_loop_scsi_forget_host(struct Scsi_Host *shost)
{
        struct scsi_device *sdev, *tmp;
        unsigned long flags;

        spin_lock_irqsave(shost->host_lock, flags);
        list_for_each_entry_safe(sdev, tmp, &shost->__devices, siblings) {
                spin_unlock_irqrestore(shost->host_lock, flags);
                scsi_remove_device(sdev);
                spin_lock_irqsave(shost->host_lock, flags);
        }
        spin_unlock_irqrestore(shost->host_lock, flags);
}

static int tcm_loop_proc_info(struct Scsi_Host *host, char *buffer,
				char **start, off_t offset,
				int length, int inout)
{
	return sprintf(buffer, "tcm_loop_proc_info()\n");
}

static int tcm_loop_driver_probe(struct device *);
static int tcm_loop_driver_remove(struct device *);

static int pseudo_lld_bus_match(struct device *dev,
				struct device_driver *dev_driver)
{
	return 1;
}

static struct bus_type tcm_loop_lld_bus = {
	.name			= "tcm_loop_bus",
	.match			= pseudo_lld_bus_match,
	.probe			= tcm_loop_driver_probe,
	.remove			= tcm_loop_driver_remove,
};

static struct device_driver tcm_loop_driverfs = {
	.name			= "tcm_loop",
	.bus			= &tcm_loop_lld_bus,
};

static void tcm_loop_primary_release(struct device *dev)
{
	return;
}

static struct device tcm_loop_primary = {
	.init_name		= "tcm_loop_0",
	.release		= tcm_loop_primary_release,
};

static inline struct tcm_loop_hba *tcm_loop_get_hba(struct scsi_cmnd *sc)
{
	return (struct tcm_loop_hba *)sc->device->host->hostdata[0];
}

static int tcm_loop_queuecommand(
	struct scsi_cmnd *sc,
	void (*done)(struct scsi_cmnd *))
{
	se_portal_group_t *se_tpg;
	struct tcm_loop_cmd *tl_cmd;
	struct tcm_loop_hba *tl_hba;
	struct tcm_loop_tpg *tl_tpg;
	int data_direction;

	sc->scsi_done = done;

	TL_CDB_DEBUG("tcm_loop_queuecommand() %d:%d:%d:%d got CDB: 0x%02x"
		" scsi_buf_len: %u\n", sc->device->host->host_no,
		sc->device->id, sc->device->channel, sc->device->lun,
		sc->cmnd[0], scsi_bufflen(sc));

	spin_unlock_irq(sc->device->host->host_lock);
	 
	tl_hba = tcm_loop_get_hba(sc);
	if (!(tl_hba)) {
		printk(KERN_ERR "Unable to locate struct tcm_loop_hba from"
				" struct scsi_cmnd\n");
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;	
	}
	tl_tpg = &tl_hba->tl_hba_tpgs[sc->device->id];
	se_tpg = tl_tpg->tl_se_tpg;

#ifdef MY_ABC_HERE
	if (sc->sc_data_direction == DMA_TO_DEVICE)
		data_direction = DMA_TO_DEVICE;
	else if (sc->sc_data_direction == DMA_FROM_DEVICE)
		data_direction = DMA_FROM_DEVICE;
	else if (sc->sc_data_direction == DMA_NONE)
		data_direction = DMA_NONE;
#else
	if (sc->sc_data_direction == DMA_TO_DEVICE)
		data_direction = SE_DIRECTION_WRITE;
	else if (sc->sc_data_direction == DMA_FROM_DEVICE)
		data_direction = SE_DIRECTION_READ;
	else if (sc->sc_data_direction == DMA_NONE)
		data_direction = SE_DIRECTION_NONE;
#endif
	else {
		spin_lock_irq(sc->device->host->host_lock);
		printk(KERN_ERR "Unsupported sc->sc_data_direction: %d\n",
			sc->sc_data_direction);	
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;
	}
	 
	tl_cmd = tcm_loop_allocate_core_cmd(tl_hba, se_tpg, sc, data_direction);
	if (!(tl_cmd)) {
		spin_lock_irq(sc->device->host->host_lock);
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;
	}
	 
	if (tcm_loop_queue_core_cmd(tl_hba->tl_hba_qobj, tl_cmd) < 0) {
		 
		transport_release_cmd_to_pool(tl_cmd->tl_se_cmd);
		 
		spin_lock_irq(sc->device->host->host_lock);
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;
	}
	 
	spin_lock_irq(sc->device->host->host_lock);
	return 0;
}

static struct scsi_host_template tcm_loop_driver_template = {
	.proc_info		= tcm_loop_proc_info,
	.proc_name		= "tcm_loopback",
	.name			= "TCM_Loopback",
	.info			= NULL,
	.slave_alloc		= NULL,
	.slave_configure	= NULL,
	.slave_destroy		= NULL,
	.ioctl			= NULL,
	.queuecommand		= tcm_loop_queuecommand,
	.eh_abort_handler	= NULL,
	.eh_bus_reset_handler	= NULL,
	.eh_device_reset_handler = NULL,
	.eh_host_reset_handler	= NULL,
	.bios_param		= NULL,
	.can_queue		= TL_SCSI_CAN_QUEUE,
	.this_id		= -1,
	.sg_tablesize		= TL_SCSI_SG_TABLESIZE,
	.cmd_per_lun		= TL_SCSI_CMD_PER_LUN,
	.max_sectors		= TL_SCSI_MAX_SECTORS,
	.use_clustering		= DISABLE_CLUSTERING,
	.module			= THIS_MODULE,
};

static int tcm_loop_driver_probe(struct device *dev)
{
	struct tcm_loop_hba *tl_hba;
	struct Scsi_Host *sh;
	int error;

	tl_hba = to_tcm_loop_hba(dev);

	sh = scsi_host_alloc(&tcm_loop_driver_template,
			sizeof(struct tcm_loop_hba));
	if (!(sh)) {
		printk(KERN_ERR "Unable to allocate struct scsi_host\n");
		return -ENODEV;
	}
	tl_hba->sh = sh;

	sh->hostdata[0] = (unsigned long)tl_hba;
	 
	sh->max_id = 2;
	sh->max_lun = 0;
	sh->max_channel = 0;
	sh->max_cmd_len = TL_SCSI_MAX_CMD_LEN;

	error = scsi_add_host(sh, &tl_hba->dev);
	if (error) {
		printk(KERN_ERR "%s: scsi_add_host failed\n", __func__);
		scsi_host_put(sh);
		return -ENODEV;
	}
	return 0;
}

static int tcm_loop_driver_remove(struct device *dev)
{
	struct tcm_loop_hba *tl_hba;
	struct Scsi_Host *sh;

	tl_hba = to_tcm_loop_hba(dev);
	sh = tl_hba->sh;

	scsi_remove_host(sh);
	scsi_host_put(sh);
	return 0;
}

static void tcm_loop_release_adapter(struct device *dev)
{
	struct tcm_loop_hba *tl_hba = to_tcm_loop_hba(dev);

	kfree(tl_hba->tl_hba_qobj);
	kfree(tl_hba);
}

int tcm_loop_setup_hba_bus(struct tcm_loop_hba *tl_hba, int tcm_loop_host_id)
{
	int ret;

	tl_hba->dev.bus = &tcm_loop_lld_bus;
	tl_hba->dev.parent = &tcm_loop_primary;
	tl_hba->dev.release = &tcm_loop_release_adapter;
	dev_set_name(&tl_hba->dev, "tcm_loop_adapter_%d", tcm_loop_host_id);

	ret = device_register(&tl_hba->dev);
	if (ret) {
		printk(KERN_ERR "device_register() failed for"
				" tl_hba->dev: %d\n", ret);
		return -ENODEV;
	}

	return 0;
}

int tcm_loop_alloc_core_bus(void)
{
	int ret;

	ret = device_register(&tcm_loop_primary);
	if (ret) {
		printk(KERN_ERR "device_register() failed for"
				" tcm_loop_primary\n");
		return ret;
	}
	
	ret = bus_register(&tcm_loop_lld_bus);
	if (ret) {
		printk(KERN_ERR "bus_register() failed for tcm_loop_lld_bus\n");
		goto dev_unreg;
	}

	ret = driver_register(&tcm_loop_driverfs);
	if (ret) {
		printk(KERN_ERR "driver_register() failed for"
				"tcm_loop_driverfs\n");
		goto bus_unreg;
	}

	printk(KERN_INFO "Initialized TCM Loop Core Bus\n");
	return ret;

bus_unreg:
	bus_unregister(&tcm_loop_lld_bus);
dev_unreg:
	device_unregister(&tcm_loop_primary);
	return ret;
}

void tcm_loop_release_core_bus(void)
{
	driver_unregister(&tcm_loop_driverfs);
	bus_unregister(&tcm_loop_lld_bus);
	device_unregister(&tcm_loop_primary);

	printk(KERN_INFO "Releasing TCM Loop Core BUS\n");
}
