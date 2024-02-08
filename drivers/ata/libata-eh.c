#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/pci.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include "../scsi/scsi_transport_api.h"

#include <linux/libata.h>

#include "libata.h"

enum {
	 
	ATA_EH_SPDN_NCQ_OFF		= (1 << 0),
	ATA_EH_SPDN_SPEED_DOWN		= (1 << 1),
	ATA_EH_SPDN_FALLBACK_TO_PIO	= (1 << 2),
	ATA_EH_SPDN_KEEP_ERRORS		= (1 << 3),

	ATA_EFLAG_IS_IO			= (1 << 0),
	ATA_EFLAG_DUBIOUS_XFER		= (1 << 1),

	ATA_ECAT_NONE			= 0,
	ATA_ECAT_ATA_BUS		= 1,
	ATA_ECAT_TOUT_HSM		= 2,
	ATA_ECAT_UNK_DEV		= 3,
	ATA_ECAT_DUBIOUS_NONE		= 4,
	ATA_ECAT_DUBIOUS_ATA_BUS	= 5,
	ATA_ECAT_DUBIOUS_TOUT_HSM	= 6,
	ATA_ECAT_DUBIOUS_UNK_DEV	= 7,
	ATA_ECAT_NR			= 8,

	ATA_EH_CMD_DFL_TIMEOUT		=  5000,

#ifdef MY_ABC_HERE
	ATA_EH_RESET_COOL_DOWN		=  2000,
#else
	 
	ATA_EH_RESET_COOL_DOWN		=  5000,
#endif

	ATA_EH_PRERESET_TIMEOUT		= 10000,
	ATA_EH_FASTDRAIN_INTERVAL	=  3000,

	ATA_EH_UA_TRIES			= 5,

	ATA_EH_PROBE_TRIAL_INTERVAL	= 60000,	 
	ATA_EH_PROBE_TRIALS		= 2,
};

#ifdef MY_ABC_HERE
extern unsigned int guiWakeupDisksNum;
#endif

static const unsigned long ata_eh_reset_timeouts[] = {
	10000,	 
	10000,	 
	35000,	 
	 5000,	 
	ULONG_MAX,  
};

static const unsigned long ata_eh_identify_timeouts[] = {
	 5000,	 
	10000,   
	30000,	 
	ULONG_MAX,
};

#ifdef MY_ABC_HERE
static const unsigned long ata_eh_flush_timeouts[] = {
	15000,	 
	15000,   
	30000,	 
	ULONG_MAX,
};
#endif

static const unsigned long ata_eh_other_timeouts[] = {
	 5000,	 
	10000,	 
	 
	ULONG_MAX,
};

struct ata_eh_cmd_timeout_ent {
	const u8		*commands;
	const unsigned long	*timeouts;
};

#define CMDS(cmds...)	(const u8 []){ cmds, 0 }
static const struct ata_eh_cmd_timeout_ent
ata_eh_cmd_timeout_table[ATA_EH_CMD_TIMEOUT_TABLE_SIZE] = {
	{ .commands = CMDS(ATA_CMD_ID_ATA, ATA_CMD_ID_ATAPI),
	  .timeouts = ata_eh_identify_timeouts, },
	{ .commands = CMDS(ATA_CMD_READ_NATIVE_MAX, ATA_CMD_READ_NATIVE_MAX_EXT),
	  .timeouts = ata_eh_other_timeouts, },
	{ .commands = CMDS(ATA_CMD_SET_MAX, ATA_CMD_SET_MAX_EXT),
	  .timeouts = ata_eh_other_timeouts, },
	{ .commands = CMDS(ATA_CMD_SET_FEATURES),
	  .timeouts = ata_eh_other_timeouts, },
	{ .commands = CMDS(ATA_CMD_INIT_DEV_PARAMS),
	  .timeouts = ata_eh_other_timeouts, },
#ifdef MY_ABC_HERE
	{ .commands = CMDS(ATA_CMD_FLUSH, ATA_CMD_FLUSH_EXT),
	  .timeouts = ata_eh_flush_timeouts },
#endif
};
#undef CMDS

static void __ata_port_freeze(struct ata_port *ap);
#ifdef CONFIG_PM
static void ata_eh_handle_port_suspend(struct ata_port *ap);
static void ata_eh_handle_port_resume(struct ata_port *ap);
#else  
static void ata_eh_handle_port_suspend(struct ata_port *ap)
{ }

static void ata_eh_handle_port_resume(struct ata_port *ap)
{ }
#endif  

static void __ata_ehi_pushv_desc(struct ata_eh_info *ehi, const char *fmt,
				 va_list args)
{
	ehi->desc_len += vscnprintf(ehi->desc + ehi->desc_len,
				     ATA_EH_DESC_LEN - ehi->desc_len,
				     fmt, args);
}

void __ata_ehi_push_desc(struct ata_eh_info *ehi, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	__ata_ehi_pushv_desc(ehi, fmt, args);
	va_end(args);
}

void ata_ehi_push_desc(struct ata_eh_info *ehi, const char *fmt, ...)
{
	va_list args;

	if (ehi->desc_len)
		__ata_ehi_push_desc(ehi, ", ");

	va_start(args, fmt);
	__ata_ehi_pushv_desc(ehi, fmt, args);
	va_end(args);
}

void ata_ehi_clear_desc(struct ata_eh_info *ehi)
{
	ehi->desc[0] = '\0';
	ehi->desc_len = 0;
}

void ata_port_desc(struct ata_port *ap, const char *fmt, ...)
{
	va_list args;

	WARN_ON(!(ap->pflags & ATA_PFLAG_INITIALIZING));

	if (ap->link.eh_info.desc_len)
		__ata_ehi_push_desc(&ap->link.eh_info, " ");

	va_start(args, fmt);
	__ata_ehi_pushv_desc(&ap->link.eh_info, fmt, args);
	va_end(args);
}

#ifdef CONFIG_PCI

void ata_port_pbar_desc(struct ata_port *ap, int bar, ssize_t offset,
			const char *name)
{
	struct pci_dev *pdev = to_pci_dev(ap->host->dev);
	char *type = "";
	unsigned long long start, len;

	if (pci_resource_flags(pdev, bar) & IORESOURCE_MEM)
		type = "m";
	else if (pci_resource_flags(pdev, bar) & IORESOURCE_IO)
		type = "i";

	start = (unsigned long long)pci_resource_start(pdev, bar);
	len = (unsigned long long)pci_resource_len(pdev, bar);

	if (offset < 0)
		ata_port_desc(ap, "%s %s%llu@0x%llx", name, type, len, start);
	else
		ata_port_desc(ap, "%s 0x%llx", name,
				start + (unsigned long long)offset);
}

#endif  

static int ata_lookup_timeout_table(u8 cmd)
{
	int i;

	for (i = 0; i < ATA_EH_CMD_TIMEOUT_TABLE_SIZE; i++) {
		const u8 *cur;

		for (cur = ata_eh_cmd_timeout_table[i].commands; *cur; cur++)
			if (*cur == cmd)
				return i;
	}

	return -1;
}

unsigned long ata_internal_cmd_timeout(struct ata_device *dev, u8 cmd)
{
	struct ata_eh_context *ehc = &dev->link->eh_context;
	int ent = ata_lookup_timeout_table(cmd);
	int idx;

	if (ent < 0)
		return ATA_EH_CMD_DFL_TIMEOUT;

	idx = ehc->cmd_timeout_idx[dev->devno][ent];
	return ata_eh_cmd_timeout_table[ent].timeouts[idx];
}

void ata_internal_cmd_timed_out(struct ata_device *dev, u8 cmd)
{
	struct ata_eh_context *ehc = &dev->link->eh_context;
	int ent = ata_lookup_timeout_table(cmd);
	int idx;

	if (ent < 0)
		return;

	idx = ehc->cmd_timeout_idx[dev->devno][ent];
	if (ata_eh_cmd_timeout_table[ent].timeouts[idx + 1] != ULONG_MAX)
		ehc->cmd_timeout_idx[dev->devno][ent]++;
}

static void ata_ering_record(struct ata_ering *ering, unsigned int eflags,
			     unsigned int err_mask)
{
	struct ata_ering_entry *ent;

	WARN_ON(!err_mask);

	ering->cursor++;
	ering->cursor %= ATA_ERING_SIZE;

	ent = &ering->ring[ering->cursor];
	ent->eflags = eflags;
	ent->err_mask = err_mask;
	ent->timestamp = get_jiffies_64();
}

static struct ata_ering_entry *ata_ering_top(struct ata_ering *ering)
{
	struct ata_ering_entry *ent = &ering->ring[ering->cursor];

	if (ent->err_mask)
		return ent;
	return NULL;
}

static void ata_ering_clear(struct ata_ering *ering)
{
	memset(ering, 0, sizeof(*ering));
}

static int ata_ering_map(struct ata_ering *ering,
			 int (*map_fn)(struct ata_ering_entry *, void *),
			 void *arg)
{
	int idx, rc = 0;
	struct ata_ering_entry *ent;

	idx = ering->cursor;
	do {
		ent = &ering->ring[idx];
		if (!ent->err_mask)
			break;
		rc = map_fn(ent, arg);
		if (rc)
			break;
		idx = (idx - 1 + ATA_ERING_SIZE) % ATA_ERING_SIZE;
	} while (idx != ering->cursor);

	return rc;
}

static unsigned int ata_eh_dev_action(struct ata_device *dev)
{
	struct ata_eh_context *ehc = &dev->link->eh_context;

	return ehc->i.action | ehc->i.dev_action[dev->devno];
}

static void ata_eh_clear_action(struct ata_link *link, struct ata_device *dev,
				struct ata_eh_info *ehi, unsigned int action)
{
	struct ata_device *tdev;

	if (!dev) {
		ehi->action &= ~action;
		ata_for_each_dev(tdev, link, ALL)
			ehi->dev_action[tdev->devno] &= ~action;
	} else {
		 
		WARN_ON(!(action & ATA_EH_PERDEV_MASK));

		if (ehi->action & action) {
			ata_for_each_dev(tdev, link, ALL)
				ehi->dev_action[tdev->devno] |=
					ehi->action & action;
			ehi->action &= ~action;
		}

		ehi->dev_action[dev->devno] &= ~action;
	}
}

enum blk_eh_timer_return ata_scsi_timed_out(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *host = cmd->device->host;
	struct ata_port *ap = ata_shost_to_port(host);
	unsigned long flags;
	struct ata_queued_cmd *qc;
	enum blk_eh_timer_return ret;

	DPRINTK("ENTER\n");

	if (ap->ops->error_handler) {
		ret = BLK_EH_NOT_HANDLED;
		goto out;
	}

	ret = BLK_EH_HANDLED;
	spin_lock_irqsave(ap->lock, flags);
	qc = ata_qc_from_tag(ap, ap->link.active_tag);
	if (qc) {
		WARN_ON(qc->scsicmd != cmd);
		qc->flags |= ATA_QCFLAG_EH_SCHEDULED;
		qc->err_mask |= AC_ERR_TIMEOUT;
		ret = BLK_EH_NOT_HANDLED;
	}
	spin_unlock_irqrestore(ap->lock, flags);

 out:
	DPRINTK("EXIT, ret=%d\n", ret);
	return ret;
}

static void ata_eh_unload(struct ata_port *ap)
{
	struct ata_link *link;
	struct ata_device *dev;
	unsigned long flags;

	ata_for_each_link(link, ap, PMP_FIRST) {
		sata_scr_write(link, SCR_CONTROL, link->saved_scontrol & 0xff0);
		ata_for_each_dev(dev, link, ALL)
			ata_dev_disable(dev);
	}

	spin_lock_irqsave(ap->lock, flags);

	ata_port_freeze(ap);			 
	ap->pflags &= ~ATA_PFLAG_EH_PENDING;	 
	ap->pflags |= ATA_PFLAG_UNLOADED;

	spin_unlock_irqrestore(ap->lock, flags);
}

void ata_scsi_error(struct Scsi_Host *host)
{
	struct ata_port *ap = ata_shost_to_port(host);
	int i;
	unsigned long flags;

	DPRINTK("ENTER\n");

#ifdef MY_ABC_HERE
	spin_lock_irqsave(ap->lock, flags);
	while(ap->pflags & ATA_PFLAG_PMP_PMCTL) {
		spin_unlock_irqrestore(ap->lock, flags);
		schedule_timeout_uninterruptible(HZ);
		spin_lock_irqsave(ap->lock, flags);
	}
	spin_unlock_irqrestore(ap->lock, flags);
#endif
	
	ata_port_flush_task(ap);

	if (ap->ops->error_handler) {
		struct scsi_cmnd *scmd, *tmp;
		int nr_timedout = 0;

		spin_lock_irqsave(ap->lock, flags);
		
		if (ap->ops->lost_interrupt)
			ap->ops->lost_interrupt(ap);
			
		list_for_each_entry_safe(scmd, tmp, &host->eh_cmd_q, eh_entry) {
			struct ata_queued_cmd *qc;

			for (i = 0; i < ATA_MAX_QUEUE; i++) {
				qc = __ata_qc_from_tag(ap, i);
				if (qc->flags & ATA_QCFLAG_ACTIVE &&
				    qc->scsicmd == scmd)
					break;
			}

			if (i < ATA_MAX_QUEUE) {
				 
				if (!(qc->flags & ATA_QCFLAG_FAILED)) {
					 
					qc->err_mask |= AC_ERR_TIMEOUT;
					qc->flags |= ATA_QCFLAG_FAILED;
					nr_timedout++;
				}
			} else {
				 
				scmd->retries = scmd->allowed;
				scsi_eh_finish_cmd(scmd, &ap->eh_done_q);
			}
		}

		if (nr_timedout)
			__ata_port_freeze(ap);

		spin_unlock_irqrestore(ap->lock, flags);

		ap->eh_tries = ATA_EH_MAX_TRIES;
	} else
		spin_unlock_wait(ap->lock);
		
 repeat:
	 
	if (ap->ops->error_handler) {
		struct ata_link *link;

		del_timer_sync(&ap->fastdrain_timer);

		ata_eh_handle_port_resume(ap);

		spin_lock_irqsave(ap->lock, flags);

		ata_for_each_link(link, ap, HOST_FIRST) {
			struct ata_eh_context *ehc = &link->eh_context;
			struct ata_device *dev;

			memset(&link->eh_context, 0, sizeof(link->eh_context));
			link->eh_context.i = link->eh_info;
			memset(&link->eh_info, 0, sizeof(link->eh_info));

			ata_for_each_dev(dev, link, ENABLED) {
				int devno = dev->devno;

				ehc->saved_xfer_mode[devno] = dev->xfer_mode;
				if (ata_ncq_enabled(dev))
					ehc->saved_ncq_enabled |= 1 << devno;
			}
		}

		ap->pflags |= ATA_PFLAG_EH_IN_PROGRESS;
		ap->pflags &= ~ATA_PFLAG_EH_PENDING;
		ap->excl_link = NULL;	 

		spin_unlock_irqrestore(ap->lock, flags);

		if (!(ap->pflags & (ATA_PFLAG_UNLOADING | ATA_PFLAG_SUSPENDED)))
#ifdef CONFIG_SYNO_QORIQ
			if (PM_EVENT_SUSPEND != ap->pm_mesg.event)
#endif
			ap->ops->error_handler(ap);
#ifdef CONFIG_SYNO_QORIQ
			else
				DBGMESG("port %d is in SUSPEND mode, skip reset\n", ap->print_id);
#endif
		else {
			 
			if ((ap->pflags & ATA_PFLAG_UNLOADING) &&
			    !(ap->pflags & ATA_PFLAG_UNLOADED))
				ata_eh_unload(ap);
			ata_eh_finish(ap);
		}

		ata_eh_handle_port_suspend(ap);

		spin_lock_irqsave(ap->lock, flags);

		if (ap->pflags & ATA_PFLAG_EH_PENDING) {
			if (--ap->eh_tries) {
				spin_unlock_irqrestore(ap->lock, flags);
				goto repeat;
			}
			ata_port_printk(ap, KERN_ERR, "EH pending after %d "
					"tries, giving up\n", ATA_EH_MAX_TRIES);
			ap->pflags &= ~ATA_PFLAG_EH_PENDING;
		}

		ata_for_each_link(link, ap, HOST_FIRST)
			memset(&link->eh_info, 0, sizeof(link->eh_info));

		host->host_eh_scheduled = 0;

		spin_unlock_irqrestore(ap->lock, flags);
	} else {
		WARN_ON(ata_qc_from_tag(ap, ap->link.active_tag) == NULL);
		ap->ops->eng_timeout(ap);
	}

	WARN_ON(host->host_failed || !list_empty(&host->eh_cmd_q));

	scsi_eh_flush_done_q(&ap->eh_done_q);

	spin_lock_irqsave(ap->lock, flags);

	if (ap->pflags & ATA_PFLAG_LOADING)
		ap->pflags &= ~ATA_PFLAG_LOADING;
#ifdef MY_ABC_HERE
	else if (ap->pflags & ATA_PFLAG_SCSI_HOTPLUG) {
		if (!(ap->pflags & ATA_PFLAG_SYNC_SCSI_DEVICE)) {
			queue_delayed_work(ata_aux_wq, &ap->hotplug_task, 0);
		} else {
			ap->pflags &= ~(ATA_PFLAG_SYNC_SCSI_DEVICE);
		}
	}
#else
	else if (ap->pflags & ATA_PFLAG_SCSI_HOTPLUG)
		queue_delayed_work(ata_aux_wq, &ap->hotplug_task, 0);
#endif
#ifdef MY_ABC_HERE
	else if (ap->pflags & ATA_PFLAG_PMP_DISCONNECT ||
			 ap->pflags & ATA_PFLAG_PMP_CONNECT) {
		 
#if defined(MY_ABC_HERE)
		queue_delayed_work(ata_aux_wq, &ap->hotplug_task, 0);
#else
		ap->pflags &= ~ATA_PFLAG_PMP_DISCONNECT;
		ap->pflags &= ~ATA_PFLAG_PMP_CONNECT;
#endif  
	}
#endif
#ifdef MY_ABC_HERE
	if (ap->pflags & ATA_PFLAG_SYNO_BOOT_PROBE) {
		ap->pflags &= ~ATA_PFLAG_SYNO_BOOT_PROBE;
	}
#endif

	if (ap->pflags & ATA_PFLAG_RECOVERED)
		ata_port_printk(ap, KERN_INFO, "EH complete\n");

	ap->pflags &= ~(ATA_PFLAG_SCSI_HOTPLUG | ATA_PFLAG_RECOVERED);

	ap->pflags &= ~ATA_PFLAG_EH_IN_PROGRESS;
	wake_up_all(&ap->eh_wait_q);

	spin_unlock_irqrestore(ap->lock, flags);

	DPRINTK("EXIT\n");
}

void ata_port_wait_eh(struct ata_port *ap)
{
	unsigned long flags;
	DEFINE_WAIT(wait);

 retry:
	spin_lock_irqsave(ap->lock, flags);

	while (ap->pflags & (ATA_PFLAG_EH_PENDING | ATA_PFLAG_EH_IN_PROGRESS)) {
		prepare_to_wait(&ap->eh_wait_q, &wait, TASK_UNINTERRUPTIBLE);
		spin_unlock_irqrestore(ap->lock, flags);
		schedule();
		spin_lock_irqsave(ap->lock, flags);
	}
	finish_wait(&ap->eh_wait_q, &wait);

	spin_unlock_irqrestore(ap->lock, flags);

	if (scsi_host_in_recovery(ap->scsi_host)) {
		msleep(10);
		goto retry;
	}
}

static int ata_eh_nr_in_flight(struct ata_port *ap)
{
	unsigned int tag;
	int nr = 0;

#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
	for (tag = 0; tag < ATA_MAX_QUEUE - 1; tag++) {
		struct ata_queued_cmd *qc = ata_qc_from_tag(ap, tag);
		struct ata_taskfile *tf = &qc->tf;

		if (ata_qc_from_tag(ap, tag) && !((IS_SYNO_PMP_CMD(tf) && NULL == qc->scsicmd) || IS_SYNO_SPINUP_CMD(qc)))
#else
	for (tag = 0; tag < ATA_MAX_QUEUE - 1; tag++)
		if (ata_qc_from_tag(ap, tag))
#endif
			nr++;

#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
	}
#endif

	return nr;
}

void ata_eh_fastdrain_timerfn(unsigned long arg)
{
	struct ata_port *ap = (void *)arg;
	unsigned long flags;
	int cnt;

	spin_lock_irqsave(ap->lock, flags);

	cnt = ata_eh_nr_in_flight(ap);

	if (!cnt)
		goto out_unlock;

	if (cnt == ap->fastdrain_cnt) {
		unsigned int tag;

#if defined(MY_ABC_HERE)
		ata_port_printk(ap, KERN_ERR, "All qcs time out, freeze the port\n");
#endif
		 
		for (tag = 0; tag < ATA_MAX_QUEUE - 1; tag++) {
			struct ata_queued_cmd *qc = ata_qc_from_tag(ap, tag);
			if (qc)
				qc->err_mask |= AC_ERR_TIMEOUT;
		}

		ata_port_freeze(ap);
	} else {
		 
		ap->fastdrain_cnt = cnt;
		ap->fastdrain_timer.expires =
			ata_deadline(jiffies, ATA_EH_FASTDRAIN_INTERVAL);
		add_timer(&ap->fastdrain_timer);
	}

 out_unlock:
	spin_unlock_irqrestore(ap->lock, flags);
}

static void ata_eh_set_pending(struct ata_port *ap, int fastdrain)
{
	int cnt;

	if (ap->pflags & ATA_PFLAG_EH_PENDING)
		return;

	ap->pflags |= ATA_PFLAG_EH_PENDING;

	if (!fastdrain)
		return;

	cnt = ata_eh_nr_in_flight(ap);
	if (!cnt)
		return;

	ap->fastdrain_cnt = cnt;
	ap->fastdrain_timer.expires =
		ata_deadline(jiffies, ATA_EH_FASTDRAIN_INTERVAL);
	add_timer(&ap->fastdrain_timer);
}

void ata_qc_schedule_eh(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;

	WARN_ON(!ap->ops->error_handler);

	qc->flags |= ATA_QCFLAG_FAILED;
	ata_eh_set_pending(ap, 1);

	blk_abort_request(qc->scsicmd->request);
}

void ata_port_schedule_eh(struct ata_port *ap)
{
	WARN_ON(!ap->ops->error_handler);

	if (ap->pflags & ATA_PFLAG_INITIALIZING)
		return;

	ata_eh_set_pending(ap, 1);
	scsi_schedule_eh(ap->scsi_host);

	DPRINTK("port EH scheduled\n");
}

static int ata_do_link_abort(struct ata_port *ap, struct ata_link *link)
{
	int tag, nr_aborted = 0;

	WARN_ON(!ap->ops->error_handler);

	ata_eh_set_pending(ap, 0);

	for (tag = 0; tag < ATA_MAX_QUEUE; tag++) {
		struct ata_queued_cmd *qc = ata_qc_from_tag(ap, tag);

		if (qc && (!link || qc->dev->link == link)) {
			qc->flags |= ATA_QCFLAG_FAILED;
			ata_qc_complete(qc);
			nr_aborted++;
		}
	}

	if (!nr_aborted)
		ata_port_schedule_eh(ap);

	return nr_aborted;
}

int ata_link_abort(struct ata_link *link)
{
	return ata_do_link_abort(link->ap, link);
}

int ata_port_abort(struct ata_port *ap)
{
	return ata_do_link_abort(ap, NULL);
}

static void __ata_port_freeze(struct ata_port *ap)
{
	WARN_ON(!ap->ops->error_handler);

	if (ap->ops->freeze)
		ap->ops->freeze(ap);

	ap->pflags |= ATA_PFLAG_FROZEN;

	DPRINTK("ata%u port frozen\n", ap->print_id);
}

int ata_port_freeze(struct ata_port *ap)
{
	int nr_aborted;

	WARN_ON(!ap->ops->error_handler);

	__ata_port_freeze(ap);
	nr_aborted = ata_port_abort(ap);

	return nr_aborted;
}

int sata_async_notification(struct ata_port *ap)
{
	u32 sntf;
	int rc;

	if (!(ap->flags & ATA_FLAG_AN))
		return 0;

	rc = sata_scr_read(&ap->link, SCR_NOTIFICATION, &sntf);
	if (rc == 0)
		sata_scr_write(&ap->link, SCR_NOTIFICATION, sntf);

	if (!sata_pmp_attached(ap) || rc) {
		 
		if (!sata_pmp_attached(ap)) {
			 
			struct ata_device *dev = ap->link.device;

			if ((dev->class == ATA_DEV_ATAPI) &&
			    (dev->flags & ATA_DFLAG_AN))
				ata_scsi_media_change_notify(dev);
			return 0;
		} else {
			 
			ata_port_schedule_eh(ap);
			return 1;
		}
	} else {
		 
		struct ata_link *link;

		ata_for_each_link(link, ap, EDGE) {
			if (!(sntf & (1 << link->pmp)))
				continue;

			if ((link->device->class == ATA_DEV_ATAPI) &&
			    (link->device->flags & ATA_DFLAG_AN))
				ata_scsi_media_change_notify(link->device);
		}

		if (sntf & (1 << SATA_PMP_CTRL_PORT)) {
			ata_port_schedule_eh(ap);
			return 1;
		}

		return 0;
	}
}

void ata_eh_freeze_port(struct ata_port *ap)
{
	unsigned long flags;

	if (!ap->ops->error_handler)
		return;

	spin_lock_irqsave(ap->lock, flags);
	__ata_port_freeze(ap);
	spin_unlock_irqrestore(ap->lock, flags);
}

void ata_eh_thaw_port(struct ata_port *ap)
{
	unsigned long flags;

	if (!ap->ops->error_handler)
		return;

	spin_lock_irqsave(ap->lock, flags);

	ap->pflags &= ~ATA_PFLAG_FROZEN;

	if (ap->ops->thaw)
		ap->ops->thaw(ap);

	spin_unlock_irqrestore(ap->lock, flags);

	DPRINTK("ata%u port thawed\n", ap->print_id);
}

static void ata_eh_scsidone(struct scsi_cmnd *scmd)
{
	 
}

static void __ata_eh_qc_complete(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct scsi_cmnd *scmd = qc->scsicmd;
	unsigned long flags;

	spin_lock_irqsave(ap->lock, flags);
	qc->scsidone = ata_eh_scsidone;
	__ata_qc_complete(qc);
	WARN_ON(ata_tag_valid(qc->tag));
	spin_unlock_irqrestore(ap->lock, flags);

	scsi_eh_finish_cmd(scmd, &ap->eh_done_q);
}

void ata_eh_qc_complete(struct ata_queued_cmd *qc)
{
	struct scsi_cmnd *scmd = qc->scsicmd;
	scmd->retries = scmd->allowed;
	__ata_eh_qc_complete(qc);
}

void ata_eh_qc_retry(struct ata_queued_cmd *qc)
{
	struct scsi_cmnd *scmd = qc->scsicmd;
	if (!qc->err_mask && scmd->retries)
		scmd->retries--;
	__ata_eh_qc_complete(qc);
}

void ata_dev_disable(struct ata_device *dev)
{
	if (!ata_dev_enabled(dev))
		return;

	if (ata_msg_drv(dev->link->ap))
		ata_dev_printk(dev, KERN_WARNING, "disabled\n");
	ata_acpi_on_disable(dev);
	ata_down_xfermask_limit(dev, ATA_DNXFER_FORCE_PIO0 | ATA_DNXFER_QUIET);
	dev->class++;

	ata_ering_clear(&dev->ering);
}

void ata_eh_detach_dev(struct ata_device *dev)
{
	struct ata_link *link = dev->link;
	struct ata_port *ap = link->ap;
	struct ata_eh_context *ehc = &link->eh_context;
	unsigned long flags;

	ata_dev_disable(dev);

	spin_lock_irqsave(ap->lock, flags);

	dev->flags &= ~ATA_DFLAG_DETACH;

	if (ata_scsi_offline_dev(dev)) {
		dev->flags |= ATA_DFLAG_DETACHED;
		ap->pflags |= ATA_PFLAG_SCSI_HOTPLUG;
	}

	ata_eh_clear_action(link, dev, &link->eh_info, ATA_EH_PERDEV_MASK);
	ata_eh_clear_action(link, dev, &link->eh_context.i, ATA_EH_PERDEV_MASK);
	ehc->saved_xfer_mode[dev->devno] = 0;
	ehc->saved_ncq_enabled &= ~(1 << dev->devno);

	spin_unlock_irqrestore(ap->lock, flags);
}

void ata_eh_about_to_do(struct ata_link *link, struct ata_device *dev,
			unsigned int action)
{
	struct ata_port *ap = link->ap;
	struct ata_eh_info *ehi = &link->eh_info;
	struct ata_eh_context *ehc = &link->eh_context;
	unsigned long flags;

	spin_lock_irqsave(ap->lock, flags);

	ata_eh_clear_action(link, dev, ehi, action);

	if (!(ehc->i.flags & ATA_EHI_QUIET) && link != ap->slave_link)
		ap->pflags |= ATA_PFLAG_RECOVERED;

	spin_unlock_irqrestore(ap->lock, flags);
}

void ata_eh_done(struct ata_link *link, struct ata_device *dev,
		 unsigned int action)
{
	struct ata_eh_context *ehc = &link->eh_context;

	ata_eh_clear_action(link, dev, &ehc->i, action);
}

static const char *ata_err_string(unsigned int err_mask)
{
	if (err_mask & AC_ERR_HOST_BUS)
		return "host bus error";
	if (err_mask & AC_ERR_ATA_BUS)
		return "ATA bus error";
	if (err_mask & AC_ERR_TIMEOUT)
		return "timeout";
	if (err_mask & AC_ERR_HSM)
		return "HSM violation";
	if (err_mask & AC_ERR_SYSTEM)
		return "internal error";
	if (err_mask & AC_ERR_MEDIA)
		return "media error";
	if (err_mask & AC_ERR_INVALID)
		return "invalid argument";
	if (err_mask & AC_ERR_DEV)
		return "device error";
	return "unknown error";
}

static unsigned int ata_read_log_page(struct ata_device *dev,
				      u8 page, void *buf, unsigned int sectors)
{
	struct ata_taskfile tf;
	unsigned int err_mask;

	DPRINTK("read log page - page %d\n", page);

	ata_tf_init(dev, &tf);
	tf.command = ATA_CMD_READ_LOG_EXT;
	tf.lbal = page;
	tf.nsect = sectors;
	tf.hob_nsect = sectors >> 8;
	tf.flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_LBA48 | ATA_TFLAG_DEVICE;
	tf.protocol = ATA_PROT_PIO;

	err_mask = ata_exec_internal(dev, &tf, NULL, DMA_FROM_DEVICE,
				     buf, sectors * ATA_SECT_SIZE, 0);

	DPRINTK("EXIT, err_mask=%x\n", err_mask);
	return err_mask;
}

static int ata_eh_read_log_10h(struct ata_device *dev,
			       int *tag, struct ata_taskfile *tf)
{
	u8 *buf = dev->link->ap->sector_buf;
	unsigned int err_mask;
	u8 csum;
	int i;

	err_mask = ata_read_log_page(dev, ATA_LOG_SATA_NCQ, buf, 1);
	if (err_mask)
		return -EIO;

	csum = 0;
	for (i = 0; i < ATA_SECT_SIZE; i++)
		csum += buf[i];
	if (csum)
		ata_dev_printk(dev, KERN_WARNING,
			       "invalid checksum 0x%x on log page 10h\n", csum);

	if (buf[0] & 0x80)
		return -ENOENT;

	*tag = buf[0] & 0x1f;

	tf->command = buf[2];
	tf->feature = buf[3];
	tf->lbal = buf[4];
	tf->lbam = buf[5];
	tf->lbah = buf[6];
	tf->device = buf[7];
	tf->hob_lbal = buf[8];
	tf->hob_lbam = buf[9];
	tf->hob_lbah = buf[10];
	tf->nsect = buf[12];
	tf->hob_nsect = buf[13];

	return 0;
}

static unsigned int atapi_eh_tur(struct ata_device *dev, u8 *r_sense_key)
{
	u8 cdb[ATAPI_CDB_LEN] = { TEST_UNIT_READY, 0, 0, 0, 0, 0 };
	struct ata_taskfile tf;
	unsigned int err_mask;

	ata_tf_init(dev, &tf);

	tf.flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE;
	tf.command = ATA_CMD_PACKET;
	tf.protocol = ATAPI_PROT_NODATA;

	err_mask = ata_exec_internal(dev, &tf, cdb, DMA_NONE, NULL, 0, 0);
	if (err_mask == AC_ERR_DEV)
		*r_sense_key = tf.feature >> 4;
	return err_mask;
}

static unsigned int atapi_eh_request_sense(struct ata_device *dev,
					   u8 *sense_buf, u8 dfl_sense_key)
{
	u8 cdb[ATAPI_CDB_LEN] =
		{ REQUEST_SENSE, 0, 0, 0, SCSI_SENSE_BUFFERSIZE, 0 };
	struct ata_port *ap = dev->link->ap;
	struct ata_taskfile tf;

	DPRINTK("ATAPI request sense\n");

	memset(sense_buf, 0, SCSI_SENSE_BUFFERSIZE);

	sense_buf[0] = 0x70;
	sense_buf[2] = dfl_sense_key;

	ata_tf_init(dev, &tf);

	tf.flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE;
	tf.command = ATA_CMD_PACKET;

	if (ap->flags & ATA_FLAG_PIO_DMA) {
		tf.protocol = ATAPI_PROT_DMA;
		tf.feature |= ATAPI_PKT_DMA;
	} else {
		tf.protocol = ATAPI_PROT_PIO;
		tf.lbam = SCSI_SENSE_BUFFERSIZE;
		tf.lbah = 0;
	}

	return ata_exec_internal(dev, &tf, cdb, DMA_FROM_DEVICE,
				 sense_buf, SCSI_SENSE_BUFFERSIZE, 0);
}

static void ata_eh_analyze_serror(struct ata_link *link)
{
	struct ata_eh_context *ehc = &link->eh_context;
	u32 serror = ehc->i.serror;
	unsigned int err_mask = 0, action = 0;
	u32 hotplug_mask;

	if (serror & (SERR_PERSISTENT | SERR_DATA)) {
		err_mask |= AC_ERR_ATA_BUS;
		action |= ATA_EH_RESET;
	}
	if (serror & SERR_PROTOCOL) {
		err_mask |= AC_ERR_HSM;
		action |= ATA_EH_RESET;
	}
	if (serror & SERR_INTERNAL) {
		err_mask |= AC_ERR_SYSTEM;
		action |= ATA_EH_RESET;
	}

	hotplug_mask = 0;

	if (!(link->flags & ATA_LFLAG_DISABLED) || ata_is_host_link(link))
		hotplug_mask = SERR_PHYRDY_CHG | SERR_DEV_XCHG;
	else
		hotplug_mask = SERR_PHYRDY_CHG;

	if (serror & hotplug_mask)
		ata_ehi_hotplugged(&ehc->i);

	ehc->i.err_mask |= err_mask;
	ehc->i.action |= action;
}

void ata_eh_analyze_ncq_error(struct ata_link *link)
{
	struct ata_port *ap = link->ap;
	struct ata_eh_context *ehc = &link->eh_context;
	struct ata_device *dev = link->device;
	struct ata_queued_cmd *qc;
	struct ata_taskfile tf;
	int tag, rc;

	if (ap->pflags & ATA_PFLAG_FROZEN)
		return;

	if (!link->sactive || !(ehc->i.err_mask & AC_ERR_DEV))
		return;

	for (tag = 0; tag < ATA_MAX_QUEUE; tag++) {
		qc = __ata_qc_from_tag(ap, tag);

		if (!(qc->flags & ATA_QCFLAG_FAILED))
			continue;

		if (qc->err_mask)
			return;
	}

	rc = ata_eh_read_log_10h(dev, &tag, &tf);
	if (rc) {
		ata_link_printk(link, KERN_ERR, "failed to read log page 10h "
				"(errno=%d)\n", rc);
		return;
	}

	if (!(link->sactive & (1 << tag))) {
		ata_link_printk(link, KERN_ERR, "log page 10h reported "
				"inactive tag %d\n", tag);
		return;
	}

	qc = __ata_qc_from_tag(ap, tag);
	memcpy(&qc->result_tf, &tf, sizeof(tf));
	qc->result_tf.flags = ATA_TFLAG_ISADDR | ATA_TFLAG_LBA | ATA_TFLAG_LBA48;
	qc->err_mask |= AC_ERR_DEV | AC_ERR_NCQ;
	ehc->i.err_mask &= ~AC_ERR_DEV;
}

#ifdef MY_ABC_HERE
extern unsigned char
blSectorNeedAutoRemap(struct scsi_cmnd *scsi_cmd, sector_t lba);
static unsigned int
syno_ata_writes_sector(struct ata_queued_cmd *qc)
{
	struct ata_taskfile tf;
	u8 buf[ATA_SECT_SIZE];
	u8 blLBA48 = 0;
	sector_t lba = 0;
	struct bio* b = NULL;
	unsigned int len = 0;
	int i = 0;

	blLBA48 = (qc->tf.flags & ATA_TFLAG_LBA48) ? 1 : 0;

	lba =   (qc->result_tf.lbal & 0xff) |
			((sector_t)qc->result_tf.lbam << 8) |
			((sector_t)qc->result_tf.lbah << 16);
	if (blLBA48) {
		lba |=  ((sector_t)qc->result_tf.hob_lbal << 24) |
				((sector_t)qc->result_tf.hob_lbam << 32) |
				((sector_t)qc->result_tf.hob_lbah << 40);
	} else {
		lba |= (((sector_t)qc->result_tf.device & 0x0f) << 24);
	}

	ata_dev_printk(qc->dev, KERN_ERR, "%s unc at %llu\n",
				   (qc->tf.flags & ATA_TFLAG_WRITE) ? "write" : "read",
				   (unsigned long long)lba);

	if (!(qc->tf.flags & ATA_TFLAG_WRITE) &&
		!blSectorNeedAutoRemap(qc->scsicmd, lba)) {
		return 0;
	}

#ifdef MY_ABC_HERE
	 
	if (!(qc->tf.flags & ATA_TFLAG_WRITE)) {
		if (qc->scsicmd) {
			if (qc->scsicmd->request) {
				for (b = qc->scsicmd->request->bio; b; b = b->bi_next) {
					len = 0;
					for (i = 0; i < b->bi_vcnt; i++) {
						len += b->bi_io_vec[i].bv_len;
					}
					if (b->bi_sector <= lba && lba < b->bi_sector + (len >> 9)) {
						set_bit(BIO_AUTO_REMAP, &b->bi_flags);
						printk("%s:%s(%d) set bio BIO_AUTO_REMAP bit on\n",
							__FILE__, __FUNCTION__, __LINE__);
					}
				}
			} else {
				printk("%s:%s(%d) cannot trace request from scsi_cmd\n",
					__FILE__, __FUNCTION__, __LINE__);
			}
		} else {
			printk("%s:%s(%d) cannot trace scsicmd from ata_queued_cmd\n",
				__FILE__, __FUNCTION__, __LINE__);
		}
	}
#endif

	tf = qc->result_tf;
	tf.protocol = ATA_PROT_PIO;
	tf.flags = (ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE | ATA_TFLAG_WRITE);
	tf.flags |= ((blLBA48) ? ATA_TFLAG_LBA48 : 0);
	tf.command = ((blLBA48) ? ATA_CMD_PIO_WRITE_EXT : ATA_CMD_PIO_WRITE);
	tf.hob_feature = 0;
	tf.hob_nsect = 0;  
	tf.hob_lbah = ((blLBA48) ? tf.hob_lbah : 0);
	tf.hob_lbam = ((blLBA48) ? tf.hob_lbam : 0);
	tf.hob_lbal = ((blLBA48) ? tf.hob_lbal : 0);
	tf.feature = 0;
	tf.nsect = 1;
	tf.ctl = qc->dev->link->ap->ctl;
	tf.device &= ((blLBA48) ? 0 : 0x0f);  
	tf.device |= ATA_LBA | ATA_DEVICE_OBS;  
	tf.device = (qc->dev->devno ?
					tf.device | ATA_DEV1 : tf.device & ~ATA_DEV1);  

	ata_dev_printk(qc->dev, KERN_ERR,
				   "insert remap command %02x/%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x/%02x ctl %02x flag %lu proto %02x\n",
				   tf.command, tf.feature, tf.nsect,
				   tf.lbal, tf.lbam, tf.lbah,
				   tf.hob_feature, tf.hob_nsect,
				   tf.hob_lbal, tf.hob_lbam, tf.hob_lbah,
				   tf.device, tf.ctl, tf.flags, tf.protocol);

	memset(buf, 0, sizeof(buf));
	ata_dev_printk(qc->dev, KERN_WARNING,
			       "Insert write command result %d\n",
				   ata_exec_internal(qc->dev, &tf, NULL, DMA_TO_DEVICE,
									 buf, ATA_SECT_SIZE, 0));
	return 0;
}
#endif

static unsigned int ata_eh_analyze_tf(struct ata_queued_cmd *qc,
				      const struct ata_taskfile *tf)
{
	unsigned int tmp, action = 0;
	u8 stat = tf->command, err = tf->feature;

	if ((stat & (ATA_BUSY | ATA_DRQ | ATA_DRDY)) != ATA_DRDY) {
		qc->err_mask |= AC_ERR_HSM;
		return ATA_EH_RESET;
	}

	if (stat & (ATA_ERR | ATA_DF))
		qc->err_mask |= AC_ERR_DEV;
	else
		return 0;

	switch (qc->dev->class) {
	case ATA_DEV_ATA:
		if (err & ATA_ICRC)
			qc->err_mask |= AC_ERR_ATA_BUS;
		if (err & ATA_UNC)
			qc->err_mask |= AC_ERR_MEDIA;
		if (err & ATA_IDNF)
			qc->err_mask |= AC_ERR_INVALID;
#ifdef MY_ABC_HERE
		 
		if (!(qc->ap->pflags & ATA_PFLAG_FROZEN) &&
			(!ata_is_ncq(qc->tf.protocol) || qc->err_mask & AC_ERR_NCQ) &&
			err & ATA_UNC) {
			syno_ata_writes_sector(qc);
		}
#endif
		break;

	case ATA_DEV_ATAPI:
		if (!(qc->ap->pflags & ATA_PFLAG_FROZEN)) {
			tmp = atapi_eh_request_sense(qc->dev,
						qc->scsicmd->sense_buffer,
						qc->result_tf.feature >> 4);
			if (!tmp) {
				 
				qc->flags |= ATA_QCFLAG_SENSE_VALID;
			} else
				qc->err_mask |= tmp;
		}
	}

	if (qc->err_mask & (AC_ERR_HSM | AC_ERR_TIMEOUT | AC_ERR_ATA_BUS))
		action |= ATA_EH_RESET;

	return action;
}

static int ata_eh_categorize_error(unsigned int eflags, unsigned int err_mask,
				   int *xfer_ok)
{
	int base = 0;

	if (!(eflags & ATA_EFLAG_DUBIOUS_XFER))
		*xfer_ok = 1;

	if (!*xfer_ok)
		base = ATA_ECAT_DUBIOUS_NONE;

	if (err_mask & AC_ERR_ATA_BUS)
		return base + ATA_ECAT_ATA_BUS;

	if (err_mask & AC_ERR_TIMEOUT)
		return base + ATA_ECAT_TOUT_HSM;

	if (eflags & ATA_EFLAG_IS_IO) {
		if (err_mask & AC_ERR_HSM)
			return base + ATA_ECAT_TOUT_HSM;
		if ((err_mask &
		     (AC_ERR_DEV|AC_ERR_MEDIA|AC_ERR_INVALID)) == AC_ERR_DEV)
			return base + ATA_ECAT_UNK_DEV;
	}

	return 0;
}

struct speed_down_verdict_arg {
	u64 since;
	int xfer_ok;
	int nr_errors[ATA_ECAT_NR];
};

static int speed_down_verdict_cb(struct ata_ering_entry *ent, void *void_arg)
{
	struct speed_down_verdict_arg *arg = void_arg;
	int cat;

	if (ent->timestamp < arg->since)
		return -1;

	cat = ata_eh_categorize_error(ent->eflags, ent->err_mask,
				      &arg->xfer_ok);
	arg->nr_errors[cat]++;

	return 0;
}

static unsigned int ata_eh_speed_down_verdict(struct ata_device *dev)
{
	const u64 j5mins = 5LLU * 60 * HZ, j10mins = 10LLU * 60 * HZ;
	u64 j64 = get_jiffies_64();
	struct speed_down_verdict_arg arg;
	unsigned int verdict = 0;

	memset(&arg, 0, sizeof(arg));
	arg.since = j64 - min(j64, j5mins);
	ata_ering_map(&dev->ering, speed_down_verdict_cb, &arg);

	if (arg.nr_errors[ATA_ECAT_DUBIOUS_ATA_BUS] +
	    arg.nr_errors[ATA_ECAT_DUBIOUS_TOUT_HSM] > 1)
		verdict |= ATA_EH_SPDN_SPEED_DOWN |
			ATA_EH_SPDN_FALLBACK_TO_PIO | ATA_EH_SPDN_KEEP_ERRORS;

	if (arg.nr_errors[ATA_ECAT_DUBIOUS_TOUT_HSM] +
	    arg.nr_errors[ATA_ECAT_DUBIOUS_UNK_DEV] > 1)
		verdict |= ATA_EH_SPDN_NCQ_OFF | ATA_EH_SPDN_KEEP_ERRORS;

	if (arg.nr_errors[ATA_ECAT_ATA_BUS] +
	    arg.nr_errors[ATA_ECAT_TOUT_HSM] +
	    arg.nr_errors[ATA_ECAT_UNK_DEV] > 6)
		verdict |= ATA_EH_SPDN_FALLBACK_TO_PIO;

	memset(&arg, 0, sizeof(arg));
	arg.since = j64 - min(j64, j10mins);
	ata_ering_map(&dev->ering, speed_down_verdict_cb, &arg);

	if (arg.nr_errors[ATA_ECAT_TOUT_HSM] +
	    arg.nr_errors[ATA_ECAT_UNK_DEV] > 3)
		verdict |= ATA_EH_SPDN_NCQ_OFF;

	if (arg.nr_errors[ATA_ECAT_ATA_BUS] +
	    arg.nr_errors[ATA_ECAT_TOUT_HSM] > 3 ||
	    arg.nr_errors[ATA_ECAT_UNK_DEV] > 6)
		verdict |= ATA_EH_SPDN_SPEED_DOWN;

	return verdict;
}

static unsigned int ata_eh_speed_down(struct ata_device *dev,
				unsigned int eflags, unsigned int err_mask)
{
	struct ata_link *link = ata_dev_phys_link(dev);
	int xfer_ok = 0;
	unsigned int verdict;
	unsigned int action = 0;

	if (ata_eh_categorize_error(eflags, err_mask, &xfer_ok) == 0)
		return 0;

	ata_ering_record(&dev->ering, eflags, err_mask);
	verdict = ata_eh_speed_down_verdict(dev);

	if ((verdict & ATA_EH_SPDN_NCQ_OFF) &&
	    (dev->flags & (ATA_DFLAG_PIO | ATA_DFLAG_NCQ |
			   ATA_DFLAG_NCQ_OFF)) == ATA_DFLAG_NCQ) {
		dev->flags |= ATA_DFLAG_NCQ_OFF;
		ata_dev_printk(dev, KERN_WARNING,
			       "NCQ disabled due to excessive errors\n");
		goto done;
	}

	if (verdict & ATA_EH_SPDN_SPEED_DOWN) {
		 
		if (sata_down_spd_limit(link, 0) == 0) {
			action |= ATA_EH_RESET;
			goto done;
		}

		if (dev->spdn_cnt < 2) {
			static const int dma_dnxfer_sel[] =
				{ ATA_DNXFER_DMA, ATA_DNXFER_40C };
			static const int pio_dnxfer_sel[] =
				{ ATA_DNXFER_PIO, ATA_DNXFER_FORCE_PIO0 };
			int sel;

			if (dev->xfer_shift != ATA_SHIFT_PIO)
				sel = dma_dnxfer_sel[dev->spdn_cnt];
			else
				sel = pio_dnxfer_sel[dev->spdn_cnt];

			dev->spdn_cnt++;

			if (ata_down_xfermask_limit(dev, sel) == 0) {
				action |= ATA_EH_RESET;
				goto done;
			}
		}
	}

	if ((verdict & ATA_EH_SPDN_FALLBACK_TO_PIO) && (dev->spdn_cnt >= 2) &&
	    (link->ap->cbl != ATA_CBL_SATA || dev->class == ATA_DEV_ATAPI) &&
	    (dev->xfer_shift != ATA_SHIFT_PIO)) {
		if (ata_down_xfermask_limit(dev, ATA_DNXFER_FORCE_PIO) == 0) {
			dev->spdn_cnt = 0;
			action |= ATA_EH_RESET;
			goto done;
		}
	}

	return 0;
 done:
	 
	if (!(verdict & ATA_EH_SPDN_KEEP_ERRORS))
		ata_ering_clear(&dev->ering);
	return action;
}

static void ata_eh_link_autopsy(struct ata_link *link)
{
	struct ata_port *ap = link->ap;
	struct ata_eh_context *ehc = &link->eh_context;
	struct ata_device *dev;
	unsigned int all_err_mask = 0, eflags = 0;
	int tag;
	u32 serror;
	int rc;

	DPRINTK("ENTER\n");

	if (ehc->i.flags & ATA_EHI_NO_AUTOPSY)
		return;

	rc = sata_scr_read(link, SCR_ERROR, &serror);
	if (rc == 0) {
		ehc->i.serror |= serror;
		ata_eh_analyze_serror(link);
	} else if (rc != -EOPNOTSUPP) {
		 
		ehc->i.probe_mask |= ATA_ALL_DEVICES;
		ehc->i.action |= ATA_EH_RESET;
		ehc->i.err_mask |= AC_ERR_OTHER;
	}

	ata_eh_analyze_ncq_error(link);

	if (ehc->i.err_mask & ~AC_ERR_OTHER)
		ehc->i.err_mask &= ~AC_ERR_OTHER;

	all_err_mask |= ehc->i.err_mask;

	for (tag = 0; tag < ATA_MAX_QUEUE; tag++) {
		struct ata_queued_cmd *qc = __ata_qc_from_tag(ap, tag);

		if (!(qc->flags & ATA_QCFLAG_FAILED) ||
		    ata_dev_phys_link(qc->dev) != link)
			continue;

		qc->err_mask |= ehc->i.err_mask;

		ehc->i.action |= ata_eh_analyze_tf(qc, &qc->result_tf);

		if (qc->err_mask & AC_ERR_ATA_BUS)
			qc->err_mask &= ~(AC_ERR_DEV | AC_ERR_MEDIA |
					  AC_ERR_INVALID);

		if (qc->err_mask & ~AC_ERR_OTHER)
			qc->err_mask &= ~AC_ERR_OTHER;

		if (qc->flags & ATA_QCFLAG_SENSE_VALID)
			qc->err_mask &= ~(AC_ERR_DEV | AC_ERR_OTHER);

		if (qc->flags & ATA_QCFLAG_IO ||
		    (!(qc->err_mask & AC_ERR_INVALID) &&
		     qc->err_mask != AC_ERR_DEV))
			qc->flags |= ATA_QCFLAG_RETRY;

		ehc->i.dev = qc->dev;
		all_err_mask |= qc->err_mask;
		if (qc->flags & ATA_QCFLAG_IO)
			eflags |= ATA_EFLAG_IS_IO;
	}

	if (ap->pflags & ATA_PFLAG_FROZEN ||
	    all_err_mask & (AC_ERR_HSM | AC_ERR_TIMEOUT))
		ehc->i.action |= ATA_EH_RESET;
	else if (((eflags & ATA_EFLAG_IS_IO) && all_err_mask) ||
		 (!(eflags & ATA_EFLAG_IS_IO) && (all_err_mask & ~AC_ERR_DEV)))
		ehc->i.action |= ATA_EH_REVALIDATE;

	if (ehc->i.dev) {
		ehc->i.dev_action[ehc->i.dev->devno] |=
			ehc->i.action & ATA_EH_PERDEV_MASK;
		ehc->i.action &= ~ATA_EH_PERDEV_MASK;
	}

	if ((all_err_mask & AC_ERR_TIMEOUT) && !ata_is_host_link(link))
		ap->link.eh_context.i.err_mask |= AC_ERR_TIMEOUT;

	dev = ehc->i.dev;
	if (!dev && ((ata_link_max_devices(link) == 1 &&
		      ata_dev_enabled(link->device))))
	    dev = link->device;

	if (dev) {
		if (dev->flags & ATA_DFLAG_DUBIOUS_XFER)
			eflags |= ATA_EFLAG_DUBIOUS_XFER;
		ehc->i.action |= ata_eh_speed_down(dev, eflags, all_err_mask);
	}
#ifdef MY_ABC_HERE
	if (ap->nr_pmp_links &&
		ehc->i.serror & SERR_PHYRDY_CHG &&
		ehc->i.serror & SERR_COMM_WAKE) {
		ap->link.eh_context.i.action |= ATA_EH_HARDRESET;
	}
#endif

	DPRINTK("EXIT\n");
}

void ata_eh_autopsy(struct ata_port *ap)
{
	struct ata_link *link;

	ata_for_each_link(link, ap, EDGE)
		ata_eh_link_autopsy(link);

	if (ap->slave_link) {
		struct ata_eh_context *mehc = &ap->link.eh_context;
		struct ata_eh_context *sehc = &ap->slave_link->eh_context;

		sehc->i.flags |= mehc->i.flags & ATA_EHI_TO_SLAVE_MASK;

		ata_eh_link_autopsy(ap->slave_link);

		ata_eh_about_to_do(ap->slave_link, NULL, ATA_EH_ALL_ACTIONS);
		mehc->i.action		|= sehc->i.action;
		mehc->i.dev_action[1]	|= sehc->i.dev_action[1];
		mehc->i.flags		|= sehc->i.flags;
		ata_eh_done(ap->slave_link, NULL, ATA_EH_ALL_ACTIONS);
	}

	if (sata_pmp_attached(ap))
		ata_eh_link_autopsy(&ap->link);
}

const char *ata_get_cmd_descript(u8 command)
{
#ifdef CONFIG_ATA_VERBOSE_ERROR
	static const struct
	{
		u8 command;
		const char *text;
	} cmd_descr[] = {
		{ ATA_CMD_DEV_RESET,		"DEVICE RESET" },
		{ ATA_CMD_CHK_POWER, 		"CHECK POWER MODE" },
		{ ATA_CMD_STANDBY, 		"STANDBY" },
		{ ATA_CMD_IDLE, 		"IDLE" },
		{ ATA_CMD_EDD, 			"EXECUTE DEVICE DIAGNOSTIC" },
		{ ATA_CMD_DOWNLOAD_MICRO,   	"DOWNLOAD MICROCODE" },
		{ ATA_CMD_NOP,			"NOP" },
		{ ATA_CMD_FLUSH, 		"FLUSH CACHE" },
		{ ATA_CMD_FLUSH_EXT, 		"FLUSH CACHE EXT" },
		{ ATA_CMD_ID_ATA,  		"IDENTIFY DEVICE" },
		{ ATA_CMD_ID_ATAPI, 		"IDENTIFY PACKET DEVICE" },
		{ ATA_CMD_SERVICE, 		"SERVICE" },
		{ ATA_CMD_READ, 		"READ DMA" },
		{ ATA_CMD_READ_EXT, 		"READ DMA EXT" },
		{ ATA_CMD_READ_QUEUED, 		"READ DMA QUEUED" },
		{ ATA_CMD_READ_STREAM_EXT, 	"READ STREAM EXT" },
		{ ATA_CMD_READ_STREAM_DMA_EXT,  "READ STREAM DMA EXT" },
		{ ATA_CMD_WRITE, 		"WRITE DMA" },
		{ ATA_CMD_WRITE_EXT, 		"WRITE DMA EXT" },
		{ ATA_CMD_WRITE_QUEUED, 	"WRITE DMA QUEUED EXT" },
		{ ATA_CMD_WRITE_STREAM_EXT, 	"WRITE STREAM EXT" },
		{ ATA_CMD_WRITE_STREAM_DMA_EXT, "WRITE STREAM DMA EXT" },
		{ ATA_CMD_WRITE_FUA_EXT,	"WRITE DMA FUA EXT" },
		{ ATA_CMD_WRITE_QUEUED_FUA_EXT, "WRITE DMA QUEUED FUA EXT" },
		{ ATA_CMD_FPDMA_READ,		"READ FPDMA QUEUED" },
		{ ATA_CMD_FPDMA_WRITE,		"WRITE FPDMA QUEUED" },
		{ ATA_CMD_PIO_READ,		"READ SECTOR(S)" },
		{ ATA_CMD_PIO_READ_EXT,		"READ SECTOR(S) EXT" },
		{ ATA_CMD_PIO_WRITE,		"WRITE SECTOR(S)" },
		{ ATA_CMD_PIO_WRITE_EXT,	"WRITE SECTOR(S) EXT" },
		{ ATA_CMD_READ_MULTI,		"READ MULTIPLE" },
		{ ATA_CMD_READ_MULTI_EXT,	"READ MULTIPLE EXT" },
		{ ATA_CMD_WRITE_MULTI,		"WRITE MULTIPLE" },
		{ ATA_CMD_WRITE_MULTI_EXT,	"WRITE MULTIPLE EXT" },
		{ ATA_CMD_WRITE_MULTI_FUA_EXT, 	"WRITE MULTIPLE FUA EXT" },
		{ ATA_CMD_SET_FEATURES,		"SET FEATURES" },
		{ ATA_CMD_SET_MULTI,		"SET MULTIPLE MODE" },
		{ ATA_CMD_VERIFY,		"READ VERIFY SECTOR(S)" },
		{ ATA_CMD_VERIFY_EXT,		"READ VERIFY SECTOR(S) EXT" },
		{ ATA_CMD_WRITE_UNCORR_EXT,	"WRITE UNCORRECTABLE EXT" },
		{ ATA_CMD_STANDBYNOW1,		"STANDBY IMMEDIATE" },
		{ ATA_CMD_IDLEIMMEDIATE,	"IDLE IMMEDIATE" },
		{ ATA_CMD_SLEEP,		"SLEEP" },
		{ ATA_CMD_INIT_DEV_PARAMS,	"INITIALIZE DEVICE PARAMETERS" },
		{ ATA_CMD_READ_NATIVE_MAX,	"READ NATIVE MAX ADDRESS" },
		{ ATA_CMD_READ_NATIVE_MAX_EXT,	"READ NATIVE MAX ADDRESS EXT" },
		{ ATA_CMD_SET_MAX,		"SET MAX ADDRESS" },
		{ ATA_CMD_SET_MAX_EXT,		"SET MAX ADDRESS EXT" },
		{ ATA_CMD_READ_LOG_EXT,		"READ LOG EXT" },
		{ ATA_CMD_WRITE_LOG_EXT,	"WRITE LOG EXT" },
		{ ATA_CMD_READ_LOG_DMA_EXT,	"READ LOG DMA EXT" },
		{ ATA_CMD_WRITE_LOG_DMA_EXT, 	"WRITE LOG DMA EXT" },
		{ ATA_CMD_TRUSTED_RCV,		"TRUSTED RECEIVE" },
		{ ATA_CMD_TRUSTED_RCV_DMA, 	"TRUSTED RECEIVE DMA" },
		{ ATA_CMD_TRUSTED_SND,		"TRUSTED SEND" },
		{ ATA_CMD_TRUSTED_SND_DMA, 	"TRUSTED SEND DMA" },
		{ ATA_CMD_PMP_READ,		"READ BUFFER" },
		{ ATA_CMD_PMP_WRITE,		"WRITE BUFFER" },
		{ ATA_CMD_CONF_OVERLAY,		"DEVICE CONFIGURATION OVERLAY" },
		{ ATA_CMD_SEC_SET_PASS,		"SECURITY SET PASSWORD" },
		{ ATA_CMD_SEC_UNLOCK,		"SECURITY UNLOCK" },
		{ ATA_CMD_SEC_ERASE_PREP,	"SECURITY ERASE PREPARE" },
		{ ATA_CMD_SEC_ERASE_UNIT,	"SECURITY ERASE UNIT" },
		{ ATA_CMD_SEC_FREEZE_LOCK,	"SECURITY FREEZE LOCK" },
		{ ATA_CMD_SEC_DISABLE_PASS,	"SECURITY DISABLE PASSWORD" },
		{ ATA_CMD_CONFIG_STREAM,	"CONFIGURE STREAM" },
		{ ATA_CMD_SMART,		"SMART" },
		{ ATA_CMD_MEDIA_LOCK,		"DOOR LOCK" },
		{ ATA_CMD_MEDIA_UNLOCK,		"DOOR UNLOCK" },
		{ ATA_CMD_CHK_MED_CRD_TYP, 	"CHECK MEDIA CARD TYPE" },
		{ ATA_CMD_CFA_REQ_EXT_ERR, 	"CFA REQUEST EXTENDED ERROR" },
		{ ATA_CMD_CFA_WRITE_NE,		"CFA WRITE SECTORS WITHOUT ERASE" },
		{ ATA_CMD_CFA_TRANS_SECT,	"CFA TRANSLATE SECTOR" },
		{ ATA_CMD_CFA_ERASE,		"CFA ERASE SECTORS" },
		{ ATA_CMD_CFA_WRITE_MULT_NE, 	"CFA WRITE MULTIPLE WITHOUT ERASE" },
		{ ATA_CMD_READ_LONG,		"READ LONG (with retries)" },
		{ ATA_CMD_READ_LONG_ONCE,	"READ LONG (without retries)" },
		{ ATA_CMD_WRITE_LONG,		"WRITE LONG (with retries)" },
		{ ATA_CMD_WRITE_LONG_ONCE,	"WRITE LONG (without retries)" },
		{ ATA_CMD_RESTORE,		"RECALIBRATE" },
		{ 0,				NULL }  
	};

	unsigned int i;
	for (i = 0; cmd_descr[i].text; i++)
		if (cmd_descr[i].command == command)
			return cmd_descr[i].text;
#endif

	return NULL;
}

static void ata_eh_link_report(struct ata_link *link)
{
	struct ata_port *ap = link->ap;
	struct ata_eh_context *ehc = &link->eh_context;
	const char *frozen, *desc;
	char tries_buf[6];
	int tag, nr_failed = 0;

	if (ehc->i.flags & ATA_EHI_QUIET)
		return;

	desc = NULL;
	if (ehc->i.desc[0] != '\0')
		desc = ehc->i.desc;

	for (tag = 0; tag < ATA_MAX_QUEUE; tag++) {
		struct ata_queued_cmd *qc = __ata_qc_from_tag(ap, tag);

		if (!(qc->flags & ATA_QCFLAG_FAILED) ||
		    ata_dev_phys_link(qc->dev) != link ||
		    ((qc->flags & ATA_QCFLAG_QUIET) &&
		     qc->err_mask == AC_ERR_DEV))
			continue;
		if (qc->flags & ATA_QCFLAG_SENSE_VALID && !qc->err_mask)
			continue;

		nr_failed++;
	}

	if (!nr_failed && !ehc->i.err_mask)
		return;

	frozen = "";
	if (ap->pflags & ATA_PFLAG_FROZEN)
		frozen = " frozen";

	memset(tries_buf, 0, sizeof(tries_buf));
	if (ap->eh_tries < ATA_EH_MAX_TRIES)
		snprintf(tries_buf, sizeof(tries_buf) - 1, " t%d",
			 ap->eh_tries);

	if (ehc->i.dev) {
		ata_dev_printk(ehc->i.dev, KERN_ERR, "exception Emask 0x%x "
			       "SAct 0x%x SErr 0x%x action 0x%x%s%s\n",
			       ehc->i.err_mask, link->sactive, ehc->i.serror,
			       ehc->i.action, frozen, tries_buf);
		if (desc)
			ata_dev_printk(ehc->i.dev, KERN_ERR, "%s\n", desc);
	} else {
		ata_link_printk(link, KERN_ERR, "exception Emask 0x%x "
				"SAct 0x%x SErr 0x%x action 0x%x%s%s\n",
				ehc->i.err_mask, link->sactive, ehc->i.serror,
				ehc->i.action, frozen, tries_buf);
		if (desc)
			ata_link_printk(link, KERN_ERR, "%s\n", desc);
	}

#ifdef CONFIG_ATA_VERBOSE_ERROR
	if (ehc->i.serror)
		ata_link_printk(link, KERN_ERR,
		  "SError: { %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s}\n",
		  ehc->i.serror & SERR_DATA_RECOVERED ? "RecovData " : "",
		  ehc->i.serror & SERR_COMM_RECOVERED ? "RecovComm " : "",
		  ehc->i.serror & SERR_DATA ? "UnrecovData " : "",
		  ehc->i.serror & SERR_PERSISTENT ? "Persist " : "",
		  ehc->i.serror & SERR_PROTOCOL ? "Proto " : "",
		  ehc->i.serror & SERR_INTERNAL ? "HostInt " : "",
		  ehc->i.serror & SERR_PHYRDY_CHG ? "PHYRdyChg " : "",
		  ehc->i.serror & SERR_PHY_INT_ERR ? "PHYInt " : "",
		  ehc->i.serror & SERR_COMM_WAKE ? "CommWake " : "",
		  ehc->i.serror & SERR_10B_8B_ERR ? "10B8B " : "",
		  ehc->i.serror & SERR_DISPARITY ? "Dispar " : "",
		  ehc->i.serror & SERR_CRC ? "BadCRC " : "",
		  ehc->i.serror & SERR_HANDSHAKE ? "Handshk " : "",
		  ehc->i.serror & SERR_LINK_SEQ_ERR ? "LinkSeq " : "",
		  ehc->i.serror & SERR_TRANS_ST_ERROR ? "TrStaTrns " : "",
		  ehc->i.serror & SERR_UNRECOG_FIS ? "UnrecFIS " : "",
		  ehc->i.serror & SERR_DEV_XCHG ? "DevExch " : "");
#endif
	for (tag = 0; tag < ATA_MAX_QUEUE; tag++) {
		struct ata_queued_cmd *qc = __ata_qc_from_tag(ap, tag);
		struct ata_taskfile *cmd = &qc->tf, *res = &qc->result_tf;
		const u8 *cdb = qc->cdb;
		char data_buf[20] = "";
		char cdb_buf[70] = "";

		if (!(qc->flags & ATA_QCFLAG_FAILED) ||
		    ata_dev_phys_link(qc->dev) != link || !qc->err_mask)
			continue;

		if (qc->dma_dir != DMA_NONE) {
			static const char *dma_str[] = {
				[DMA_BIDIRECTIONAL]	= "bidi",
				[DMA_TO_DEVICE]		= "out",
				[DMA_FROM_DEVICE]	= "in",
			};
			static const char *prot_str[] = {
				[ATA_PROT_PIO]		= "pio",
				[ATA_PROT_DMA]		= "dma",
				[ATA_PROT_NCQ]		= "ncq",
				[ATAPI_PROT_PIO]	= "pio",
				[ATAPI_PROT_DMA]	= "dma",
			};

			snprintf(data_buf, sizeof(data_buf), " %s %u %s",
				 prot_str[qc->tf.protocol], qc->nbytes,
				 dma_str[qc->dma_dir]);
		}

		if (ata_is_atapi(qc->tf.protocol)) {
			if (qc->scsicmd)
				scsi_print_command(qc->scsicmd);
			else
				snprintf(cdb_buf, sizeof(cdb_buf),
				 "cdb %02x %02x %02x %02x %02x %02x %02x %02x  "
				 "%02x %02x %02x %02x %02x %02x %02x %02x\n         ",
				 cdb[0], cdb[1], cdb[2], cdb[3],
				 cdb[4], cdb[5], cdb[6], cdb[7],
				 cdb[8], cdb[9], cdb[10], cdb[11],
				 cdb[12], cdb[13], cdb[14], cdb[15]);
		} else {
			const char *descr = ata_get_cmd_descript(cmd->command);
			if (descr)
				ata_dev_printk(qc->dev, KERN_ERR,
					"failed command: %s\n", descr);
		}

		ata_dev_printk(qc->dev, KERN_ERR,
			"cmd %02x/%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x/%02x "
			"tag %d%s\n         %s"
			"res %02x/%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x/%02x "
			"Emask 0x%x (%s)%s\n",
			cmd->command, cmd->feature, cmd->nsect,
			cmd->lbal, cmd->lbam, cmd->lbah,
			cmd->hob_feature, cmd->hob_nsect,
			cmd->hob_lbal, cmd->hob_lbam, cmd->hob_lbah,
			cmd->device, qc->tag, data_buf, cdb_buf,
			res->command, res->feature, res->nsect,
			res->lbal, res->lbam, res->lbah,
			res->hob_feature, res->hob_nsect,
			res->hob_lbal, res->hob_lbam, res->hob_lbah,
			res->device, qc->err_mask, ata_err_string(qc->err_mask),
			qc->err_mask & AC_ERR_NCQ ? " <F>" : "");

#ifdef CONFIG_ATA_VERBOSE_ERROR
		if (res->command & (ATA_BUSY | ATA_DRDY | ATA_DF | ATA_DRQ |
				    ATA_ERR)) {
			if (res->command & ATA_BUSY)
				ata_dev_printk(qc->dev, KERN_ERR,
				  "status: { Busy }\n");
			else
				ata_dev_printk(qc->dev, KERN_ERR,
				  "status: { %s%s%s%s}\n",
				  res->command & ATA_DRDY ? "DRDY " : "",
				  res->command & ATA_DF ? "DF " : "",
				  res->command & ATA_DRQ ? "DRQ " : "",
				  res->command & ATA_ERR ? "ERR " : "");
		}

		if (cmd->command != ATA_CMD_PACKET &&
		    (res->feature & (ATA_ICRC | ATA_UNC | ATA_IDNF |
				     ATA_ABORTED)))
			ata_dev_printk(qc->dev, KERN_ERR,
			  "error: { %s%s%s%s}\n",
			  res->feature & ATA_ICRC ? "ICRC " : "",
			  res->feature & ATA_UNC ? "UNC " : "",
			  res->feature & ATA_IDNF ? "IDNF " : "",
			  res->feature & ATA_ABORTED ? "ABRT " : "");
#endif
	}
}

void ata_eh_report(struct ata_port *ap)
{
	struct ata_link *link;

	ata_for_each_link(link, ap, HOST_FIRST)
		ata_eh_link_report(link);
}

static int ata_do_reset(struct ata_link *link, ata_reset_fn_t reset,
			unsigned int *classes, unsigned long deadline,
			bool clear_classes)
{
	struct ata_device *dev;

	if (clear_classes)
		ata_for_each_dev(dev, link, ALL)
			classes[dev->devno] = ATA_DEV_UNKNOWN;

	return reset(link, classes, deadline);
}

static int ata_eh_followup_srst_needed(struct ata_link *link,
				       int rc, const unsigned int *classes)
{
	if ((link->flags & ATA_LFLAG_NO_SRST) || ata_link_offline(link))
		return 0;
	if (rc == -EAGAIN)
		return 1;
	if (sata_pmp_supported(link->ap) && ata_is_host_link(link))
		return 1;
	return 0;
}

int ata_eh_reset(struct ata_link *link, int classify,
		 ata_prereset_fn_t prereset, ata_reset_fn_t softreset,
		 ata_reset_fn_t hardreset, ata_postreset_fn_t postreset)
{
	struct ata_port *ap = link->ap;
	struct ata_link *slave = ap->slave_link;
	struct ata_eh_context *ehc = &link->eh_context;
	struct ata_eh_context *sehc = slave ? &slave->eh_context : NULL;
	unsigned int *classes = ehc->classes;
	unsigned int lflags = link->flags;
	int verbose = !(ehc->i.flags & ATA_EHI_QUIET);
	int max_tries = 0, try = 0;
	struct ata_link *failed_link;
	struct ata_device *dev;
	unsigned long deadline, now;
	ata_reset_fn_t reset;
	unsigned long flags;
	u32 sstatus;
	int nr_unknown, rc;

	while (ata_eh_reset_timeouts[max_tries] != ULONG_MAX)
		max_tries++;
	if (link->flags & ATA_LFLAG_NO_HRST)
		hardreset = NULL;
	if (link->flags & ATA_LFLAG_NO_SRST)
		softreset = NULL;

	if (ehc->i.flags & ATA_EHI_DID_RESET) {
		now = jiffies;
		WARN_ON(time_after(ehc->last_reset, now));
		deadline = ata_deadline(ehc->last_reset,
					ATA_EH_RESET_COOL_DOWN);
		if (time_before(now, deadline))
			schedule_timeout_uninterruptible(deadline - now);
	}

	spin_lock_irqsave(ap->lock, flags);
	ap->pflags |= ATA_PFLAG_RESETTING;
	spin_unlock_irqrestore(ap->lock, flags);

	ata_eh_about_to_do(link, NULL, ATA_EH_RESET);

	ata_for_each_dev(dev, link, ALL) {
		 
		dev->pio_mode = XFER_PIO_0;

		if (ap->ops->set_piomode)
			ap->ops->set_piomode(ap, dev);
	}

	reset = NULL;
	ehc->i.action &= ~ATA_EH_RESET;
	if (hardreset) {
		reset = hardreset;
		ehc->i.action |= ATA_EH_HARDRESET;
	} else if (softreset) {
		reset = softreset;
		ehc->i.action |= ATA_EH_SOFTRESET;
	}

	if (prereset) {
		unsigned long deadline = ata_deadline(jiffies,
						      ATA_EH_PRERESET_TIMEOUT);

		if (slave) {
			sehc->i.action &= ~ATA_EH_RESET;
			sehc->i.action |= ehc->i.action;
		}

		rc = prereset(link, deadline);

		if (slave && (rc == 0 || rc == -ENOENT)) {
			int tmp;

			tmp = prereset(slave, deadline);
			if (tmp != -ENOENT)
				rc = tmp;

			ehc->i.action |= sehc->i.action;
		}

		if (rc) {
			if (rc == -ENOENT) {
				ata_link_printk(link, KERN_DEBUG,
						"port disabled. ignoring.\n");
				ehc->i.action &= ~ATA_EH_RESET;

				ata_for_each_dev(dev, link, ALL)
					classes[dev->devno] = ATA_DEV_NONE;

				rc = 0;
			} else
				ata_link_printk(link, KERN_ERR,
					"prereset failed (errno=%d)\n", rc);
			goto out;
		}

		if (reset && !(ehc->i.action & ATA_EH_RESET)) {
			ata_for_each_dev(dev, link, ALL)
				classes[dev->devno] = ATA_DEV_NONE;
			if ((ap->pflags & ATA_PFLAG_FROZEN) &&
			    ata_is_host_link(link))
				ata_eh_thaw_port(ap);
			rc = 0;
			goto out;
		}
	}

 retry:
	 
	if (ata_is_host_link(link))
		ata_eh_freeze_port(ap);

	deadline = ata_deadline(jiffies, ata_eh_reset_timeouts[try++]);

	if (reset) {
		if (verbose)
			ata_link_printk(link, KERN_INFO, "%s resetting link\n",
					reset == softreset ? "soft" : "hard");

		ehc->last_reset = jiffies;
		if (reset == hardreset)
			ehc->i.flags |= ATA_EHI_DID_HARDRESET;
		else
			ehc->i.flags |= ATA_EHI_DID_SOFTRESET;

		rc = ata_do_reset(link, reset, classes, deadline, true);
		if (rc && rc != -EAGAIN) {
			failed_link = link;
			goto fail;
		}

		if (slave && reset == hardreset) {
			int tmp;

			if (verbose)
				ata_link_printk(slave, KERN_INFO,
						"hard resetting link\n");

			ata_eh_about_to_do(slave, NULL, ATA_EH_RESET);
			tmp = ata_do_reset(slave, reset, classes, deadline,
					   false);
			switch (tmp) {
			case -EAGAIN:
				rc = -EAGAIN;
			case 0:
				break;
			default:
				failed_link = slave;
				rc = tmp;
				goto fail;
			}
		}

		if (reset == hardreset &&
		    ata_eh_followup_srst_needed(link, rc, classes)) {
			reset = softreset;

			if (!reset) {
				ata_link_printk(link, KERN_ERR,
						"follow-up softreset required "
						"but no softreset avaliable\n");
				failed_link = link;
				rc = -EINVAL;
				goto fail;
			}

			ata_eh_about_to_do(link, NULL, ATA_EH_RESET);
			rc = ata_do_reset(link, reset, classes, deadline, true);
			if (rc) {
				failed_link = link;
				goto fail;
			}
		}
	} else {
		if (verbose)
			ata_link_printk(link, KERN_INFO, "no reset method "
					"available, skipping reset\n");
		if (!(lflags & ATA_LFLAG_ASSUME_CLASS))
			lflags |= ATA_LFLAG_ASSUME_ATA;
	}

	ata_for_each_dev(dev, link, ALL) {
		 
		dev->pio_mode = XFER_PIO_0;
		dev->flags &= ~ATA_DFLAG_SLEEPING;

		if (ata_phys_link_offline(ata_dev_phys_link(dev)))
			continue;

		if (lflags & ATA_LFLAG_ASSUME_ATA)
			classes[dev->devno] = ATA_DEV_ATA;
		else if (lflags & ATA_LFLAG_ASSUME_SEMB)
			classes[dev->devno] = ATA_DEV_SEMB_UNSUP;
	}

	if (sata_scr_read(link, SCR_STATUS, &sstatus) == 0)
		link->sata_spd = (sstatus >> 4) & 0xf;
	if (slave && sata_scr_read(slave, SCR_STATUS, &sstatus) == 0)
		slave->sata_spd = (sstatus >> 4) & 0xf;

	if (ata_is_host_link(link))
		ata_eh_thaw_port(ap);

	if (postreset) {
		postreset(link, classes);
		if (slave)
			postreset(slave, classes);
	}

	spin_lock_irqsave(link->ap->lock, flags);
	memset(&link->eh_info, 0, sizeof(link->eh_info));
	if (slave)
		memset(&slave->eh_info, 0, sizeof(link->eh_info));
	ap->pflags &= ~ATA_PFLAG_EH_PENDING;
	spin_unlock_irqrestore(link->ap->lock, flags);

	nr_unknown = 0;
	ata_for_each_dev(dev, link, ALL) {
		if (ata_phys_link_online(ata_dev_phys_link(dev))) {
			if (classes[dev->devno] == ATA_DEV_UNKNOWN) {
				ata_dev_printk(dev, KERN_DEBUG, "link online "
					       "but device misclassifed\n");
				classes[dev->devno] = ATA_DEV_NONE;
				nr_unknown++;
			}
		} else if (ata_phys_link_offline(ata_dev_phys_link(dev))) {
			if (ata_class_enabled(classes[dev->devno]))
				ata_dev_printk(dev, KERN_DEBUG, "link offline, "
					       "clearing class %d to NONE\n",
					       classes[dev->devno]);
			classes[dev->devno] = ATA_DEV_NONE;
		} else if (classes[dev->devno] == ATA_DEV_UNKNOWN) {
			ata_dev_printk(dev, KERN_DEBUG, "link status unknown, "
				       "clearing UNKNOWN to NONE\n");
			classes[dev->devno] = ATA_DEV_NONE;
		}
	}

	if (classify && nr_unknown) {
		if (try < max_tries) {
			ata_link_printk(link, KERN_WARNING, "link online but "
					"%d devices misclassified, retrying\n",
					nr_unknown);
			failed_link = link;
			rc = -EAGAIN;
			goto fail;
		}
		ata_link_printk(link, KERN_WARNING,
				"link online but %d devices misclassified, "
				"device detection might fail\n", nr_unknown);
	}

	ata_eh_done(link, NULL, ATA_EH_RESET);
	if (slave)
		ata_eh_done(slave, NULL, ATA_EH_RESET);
	ehc->last_reset = jiffies;	 
	ehc->i.action |= ATA_EH_REVALIDATE;

	rc = 0;
 out:
	 
	ehc->i.flags &= ~ATA_EHI_HOTPLUGGED;
	if (slave)
		sehc->i.flags &= ~ATA_EHI_HOTPLUGGED;

	spin_lock_irqsave(ap->lock, flags);
	ap->pflags &= ~ATA_PFLAG_RESETTING;
	spin_unlock_irqrestore(ap->lock, flags);

	return rc;

 fail:
	 
	if (!ata_is_host_link(link) &&
	    sata_scr_read(link, SCR_STATUS, &sstatus))
		rc = -ERESTART;

	if (rc == -ERESTART || try >= max_tries)
		goto out;

	now = jiffies;
	if (time_before(now, deadline)) {
		unsigned long delta = deadline - now;

		ata_link_printk(failed_link, KERN_WARNING,
			"reset failed (errno=%d), retrying in %u secs\n",
			rc, DIV_ROUND_UP(jiffies_to_msecs(delta), 1000));

		while (delta)
			delta = schedule_timeout_uninterruptible(delta);
	}

	if (try == max_tries - 1) {
		sata_down_spd_limit(link, 0);
		if (slave)
			sata_down_spd_limit(slave, 0);
	} else if (rc == -EPIPE)
		sata_down_spd_limit(failed_link, 0);

	if (hardreset)
		reset = hardreset;
	goto retry;
}

static inline void ata_eh_pull_park_action(struct ata_port *ap)
{
	struct ata_link *link;
	struct ata_device *dev;
	unsigned long flags;

	spin_lock_irqsave(ap->lock, flags);
	INIT_COMPLETION(ap->park_req_pending);
	ata_for_each_link(link, ap, EDGE) {
		ata_for_each_dev(dev, link, ALL) {
			struct ata_eh_info *ehi = &link->eh_info;

			link->eh_context.i.dev_action[dev->devno] |=
				ehi->dev_action[dev->devno] & ATA_EH_PARK;
			ata_eh_clear_action(link, dev, ehi, ATA_EH_PARK);
		}
	}
	spin_unlock_irqrestore(ap->lock, flags);
}

static void ata_eh_park_issue_cmd(struct ata_device *dev, int park)
{
	struct ata_eh_context *ehc = &dev->link->eh_context;
	struct ata_taskfile tf;
	unsigned int err_mask;

	ata_tf_init(dev, &tf);
	if (park) {
		ehc->unloaded_mask |= 1 << dev->devno;
		tf.command = ATA_CMD_IDLEIMMEDIATE;
		tf.feature = 0x44;
		tf.lbal = 0x4c;
		tf.lbam = 0x4e;
		tf.lbah = 0x55;
	} else {
		ehc->unloaded_mask &= ~(1 << dev->devno);
		tf.command = ATA_CMD_CHK_POWER;
	}

	tf.flags |= ATA_TFLAG_DEVICE | ATA_TFLAG_ISADDR;
	tf.protocol |= ATA_PROT_NODATA;
	err_mask = ata_exec_internal(dev, &tf, NULL, DMA_NONE, NULL, 0, 0);
	if (park && (err_mask || tf.lbal != 0xc4)) {
		ata_dev_printk(dev, KERN_ERR, "head unload failed!\n");
		ehc->unloaded_mask &= ~(1 << dev->devno);
	}
}

static int ata_eh_revalidate_and_attach(struct ata_link *link,
					struct ata_device **r_failed_dev)
{
	struct ata_port *ap = link->ap;
	struct ata_eh_context *ehc = &link->eh_context;
	struct ata_device *dev;
	unsigned int new_mask = 0;
	unsigned long flags;
	int rc = 0;

	DPRINTK("ENTER\n");

	ata_for_each_dev(dev, link, ALL_REVERSE) {
		unsigned int action = ata_eh_dev_action(dev);
		unsigned int readid_flags = 0;

		if (ehc->i.flags & ATA_EHI_DID_RESET)
			readid_flags |= ATA_READID_POSTRESET;

		if ((action & ATA_EH_REVALIDATE) && ata_dev_enabled(dev)) {
			WARN_ON(dev->class == ATA_DEV_PMP);

			if (ata_phys_link_offline(ata_dev_phys_link(dev))) {
				rc = -EIO;
				goto err;
			}

			ata_eh_about_to_do(link, dev, ATA_EH_REVALIDATE);
			rc = ata_dev_revalidate(dev, ehc->classes[dev->devno],
						readid_flags);
			if (rc)
				goto err;

			ata_eh_done(link, dev, ATA_EH_REVALIDATE);

			ehc->i.flags |= ATA_EHI_SETMODE;

			queue_work(ata_aux_wq, &(ap->scsi_rescan_task));
		} else if (dev->class == ATA_DEV_UNKNOWN &&
			   ehc->tries[dev->devno] &&
			   ata_class_enabled(ehc->classes[dev->devno])) {
			 
			dev->class = ehc->classes[dev->devno];

			if (dev->class == ATA_DEV_PMP)
				rc = sata_pmp_attach(dev);
			else
				rc = ata_dev_read_id(dev, &dev->class,
						     readid_flags, dev->id);

			ehc->classes[dev->devno] = dev->class;
			dev->class = ATA_DEV_UNKNOWN;

			switch (rc) {
			case 0:
				 
				ata_ering_clear(&dev->ering);
				new_mask |= 1 << dev->devno;
				break;
			case -ENOENT:
				 
				ata_eh_thaw_port(ap);
#ifdef MY_ABC_HERE
				ata_link_printk(link, KERN_ERR, "Issued IDENTIFY to non-existent device ?!\n");
				goto err;
#endif
				break;
			default:
				goto err;
			}
		}
	}

	if ((ehc->i.flags & ATA_EHI_DID_RESET) && ata_is_host_link(link)) {
		if (ap->ops->cable_detect)
			ap->cbl = ap->ops->cable_detect(ap);
		ata_force_cbl(ap);
	}

	ata_for_each_dev(dev, link, ALL) {
		if (!(new_mask & (1 << dev->devno)))
			continue;

		dev->class = ehc->classes[dev->devno];

		if (dev->class == ATA_DEV_PMP)
			continue;

		ehc->i.flags |= ATA_EHI_PRINTINFO;
		rc = ata_dev_configure(dev);
		ehc->i.flags &= ~ATA_EHI_PRINTINFO;
		if (rc) {
			dev->class = ATA_DEV_UNKNOWN;
			goto err;
		}

		spin_lock_irqsave(ap->lock, flags);
		ap->pflags |= ATA_PFLAG_SCSI_HOTPLUG;
		spin_unlock_irqrestore(ap->lock, flags);

		ehc->i.flags |= ATA_EHI_SETMODE;
	}

	return 0;

 err:
	*r_failed_dev = dev;
	DPRINTK("EXIT rc=%d\n", rc);
	return rc;
}

int ata_set_mode(struct ata_link *link, struct ata_device **r_failed_dev)
{
	struct ata_port *ap = link->ap;
	struct ata_device *dev;
	int rc;

	ata_for_each_dev(dev, link, ENABLED) {
		if (!(dev->flags & ATA_DFLAG_DUBIOUS_XFER)) {
			struct ata_ering_entry *ent;

			ent = ata_ering_top(&dev->ering);
			if (ent)
				ent->eflags &= ~ATA_EFLAG_DUBIOUS_XFER;
		}
	}

	if (ap->ops->set_mode)
		rc = ap->ops->set_mode(link, r_failed_dev);
	else
		rc = ata_do_set_mode(link, r_failed_dev);

	ata_for_each_dev(dev, link, ENABLED) {
		struct ata_eh_context *ehc = &link->eh_context;
		u8 saved_xfer_mode = ehc->saved_xfer_mode[dev->devno];
		u8 saved_ncq = !!(ehc->saved_ncq_enabled & (1 << dev->devno));

		if (dev->xfer_mode != saved_xfer_mode ||
		    ata_ncq_enabled(dev) != saved_ncq)
			dev->flags |= ATA_DFLAG_DUBIOUS_XFER;
	}

	return rc;
}

static int atapi_eh_clear_ua(struct ata_device *dev)
{
	int i;

	for (i = 0; i < ATA_EH_UA_TRIES; i++) {
		u8 *sense_buffer = dev->link->ap->sector_buf;
		u8 sense_key = 0;
		unsigned int err_mask;

		err_mask = atapi_eh_tur(dev, &sense_key);
		if (err_mask != 0 && err_mask != AC_ERR_DEV) {
			ata_dev_printk(dev, KERN_WARNING, "TEST_UNIT_READY "
				"failed (err_mask=0x%x)\n", err_mask);
			return -EIO;
		}

		if (!err_mask || sense_key != UNIT_ATTENTION)
			return 0;

		err_mask = atapi_eh_request_sense(dev, sense_buffer, sense_key);
		if (err_mask) {
			ata_dev_printk(dev, KERN_WARNING, "failed to clear "
				"UNIT ATTENTION (err_mask=0x%x)\n", err_mask);
			return -EIO;
		}
	}

	ata_dev_printk(dev, KERN_WARNING,
		"UNIT ATTENTION persists after %d tries\n", ATA_EH_UA_TRIES);

	return 0;
}

#ifdef MY_ABC_HERE
 
static int ata_eh_maybe_retry_flush(struct ata_device *dev)
{
	struct ata_link *link = dev->link;
	struct ata_port *ap = link->ap;
	struct ata_queued_cmd *qc;
	struct ata_taskfile tf;
	unsigned int err_mask;
	int rc = 0;

	if (!ata_tag_valid(link->active_tag))
		return 0;

	qc = __ata_qc_from_tag(ap, link->active_tag);
	if (qc->dev != dev || (qc->tf.command != ATA_CMD_FLUSH_EXT &&
			       qc->tf.command != ATA_CMD_FLUSH))
		return 0;

#ifdef MY_ABC_HERE 
	if ((qc->err_mask & AC_ERR_DEV) && ATA_DEV_UNKNOWN == dev->class) {
#else
	if (qc->err_mask & AC_ERR_DEV) {
#endif
		return 0;
	}

	ata_tf_init(dev, &tf);

	tf.command = qc->tf.command;
	tf.flags |= ATA_TFLAG_DEVICE;
	tf.protocol = ATA_PROT_NODATA;

	ata_dev_printk(dev, KERN_WARNING, "retrying FLUSH 0x%x Emask 0x%x\n",
		       tf.command, qc->err_mask);

	err_mask = ata_exec_internal(dev, &tf, NULL, DMA_NONE, NULL, 0, 0);
	if (!err_mask) {
		 
		qc->scsicmd->allowed = max(qc->scsicmd->allowed, 1);
	} else {
		ata_dev_printk(dev, KERN_WARNING, "FLUSH failed Emask 0x%x\n",
			       err_mask);
		rc = -EIO;

		if (err_mask & AC_ERR_DEV) {
			qc->err_mask |= AC_ERR_DEV;
			qc->result_tf = tf;
			if (!(ap->pflags & ATA_PFLAG_FROZEN))
				rc = 0;
		}
	}
	return rc;
}
#endif   

static int ata_link_nr_enabled(struct ata_link *link)
{
	struct ata_device *dev;
	int cnt = 0;

	ata_for_each_dev(dev, link, ENABLED)
		cnt++;
	return cnt;
}

static int ata_link_nr_vacant(struct ata_link *link)
{
	struct ata_device *dev;
	int cnt = 0;

	ata_for_each_dev(dev, link, ALL)
		if (dev->class == ATA_DEV_UNKNOWN)
			cnt++;
	return cnt;
}

static int ata_eh_skip_recovery(struct ata_link *link)
{
	struct ata_port *ap = link->ap;
	struct ata_eh_context *ehc = &link->eh_context;
	struct ata_device *dev;

	if (link->flags & ATA_LFLAG_DISABLED)
		return 1;

	if ((ap->pflags & ATA_PFLAG_FROZEN) || ata_link_nr_enabled(link))
		return 0;

	if ((ehc->i.action & ATA_EH_RESET) &&
	    !(ehc->i.flags & ATA_EHI_DID_RESET))
		return 0;

	ata_for_each_dev(dev, link, ALL) {
		if (dev->class == ATA_DEV_UNKNOWN &&
		    ehc->classes[dev->devno] != ATA_DEV_NONE)
			return 0;
	}

	return 1;
}

static int ata_count_probe_trials_cb(struct ata_ering_entry *ent, void *void_arg)
{
	u64 interval = msecs_to_jiffies(ATA_EH_PROBE_TRIAL_INTERVAL);
	u64 now = get_jiffies_64();
	int *trials = void_arg;

	if (ent->timestamp < now - min(now, interval))
		return -1;

	(*trials)++;
	return 0;
}

static int ata_eh_schedule_probe(struct ata_device *dev)
{
	struct ata_eh_context *ehc = &dev->link->eh_context;
	struct ata_link *link = ata_dev_phys_link(dev);
	int trials = 0;

	if (!(ehc->i.probe_mask & (1 << dev->devno)) ||
	    (ehc->did_probe_mask & (1 << dev->devno)))
		return 0;

	ata_eh_detach_dev(dev);
	ata_dev_init(dev);
	ehc->did_probe_mask |= (1 << dev->devno);
	ehc->i.action |= ATA_EH_RESET;
	ehc->saved_xfer_mode[dev->devno] = 0;
	ehc->saved_ncq_enabled &= ~(1 << dev->devno);

	ata_ering_record(&dev->ering, 0, AC_ERR_OTHER);
	ata_ering_map(&dev->ering, ata_count_probe_trials_cb, &trials);

	if (trials > ATA_EH_PROBE_TRIALS)
		sata_down_spd_limit(link, 1);

	return 1;
}

static int ata_eh_handle_dev_fail(struct ata_device *dev, int err)
{
	struct ata_eh_context *ehc = &dev->link->eh_context;

	if (err != -EAGAIN)
		ehc->tries[dev->devno]--;

	switch (err) {
	case -ENODEV:
		 
		ehc->i.probe_mask |= (1 << dev->devno);
	case -EINVAL:
		 
		ehc->tries[dev->devno] = min(ehc->tries[dev->devno], 1);
	case -EIO:
		if (ehc->tries[dev->devno] == 1) {
			 
			sata_down_spd_limit(ata_dev_phys_link(dev), 0);
			if (dev->pio_mode > XFER_PIO_0)
				ata_down_xfermask_limit(dev, ATA_DNXFER_PIO);
		}
	}

	if (ata_dev_enabled(dev) && !ehc->tries[dev->devno]) {
		 
		ata_dev_disable(dev);

		if (ata_phys_link_offline(ata_dev_phys_link(dev)))
			ata_eh_detach_dev(dev);
#ifdef MY_ABC_HERE
		else if(-EIO == err) {
			ata_dev_printk(dev, KERN_WARNING,"handle -EIO dev fail, detach this dev\n");
			ata_eh_detach_dev(dev);
		}
#endif

		if (ata_eh_schedule_probe(dev)) {
			ehc->tries[dev->devno] = ATA_EH_DEV_TRIES;
			memset(ehc->cmd_timeout_idx[dev->devno], 0,
			       sizeof(ehc->cmd_timeout_idx[dev->devno]));
		}

		return 1;
	} else {
		ehc->i.action |= ATA_EH_RESET;
		return 0;
	}
}

int ata_eh_recover(struct ata_port *ap, ata_prereset_fn_t prereset,
		   ata_reset_fn_t softreset, ata_reset_fn_t hardreset,
		   ata_postreset_fn_t postreset,
		   struct ata_link **r_failed_link)
{
	struct ata_link *link;
	struct ata_device *dev;
	int nr_failed_devs;
	int rc;
	unsigned long flags, deadline;

	DPRINTK("ENTER\n");

	ata_for_each_link(link, ap, EDGE) {
		struct ata_eh_context *ehc = &link->eh_context;

		if (ehc->i.action & ATA_EH_ENABLE_LINK) {
			ata_eh_about_to_do(link, NULL, ATA_EH_ENABLE_LINK);
			spin_lock_irqsave(ap->lock, flags);
			link->flags &= ~ATA_LFLAG_DISABLED;
			spin_unlock_irqrestore(ap->lock, flags);
			ata_eh_done(link, NULL, ATA_EH_ENABLE_LINK);
		}

		ata_for_each_dev(dev, link, ALL) {
			if (link->flags & ATA_LFLAG_NO_RETRY)
				ehc->tries[dev->devno] = 1;
			else
				ehc->tries[dev->devno] = ATA_EH_DEV_TRIES;

			ehc->i.action |= ehc->i.dev_action[dev->devno] &
					 ~ATA_EH_PERDEV_MASK;
			ehc->i.dev_action[dev->devno] &= ATA_EH_PERDEV_MASK;

			if (dev->flags & ATA_DFLAG_DETACH)
				ata_eh_detach_dev(dev);

			if (!ata_dev_enabled(dev))
				ata_eh_schedule_probe(dev);
		}
	}

 retry:
	rc = 0;
	nr_failed_devs = 0;

	if (ap->pflags & ATA_PFLAG_UNLOADING)
		goto out;

	ata_for_each_link(link, ap, EDGE) {
		struct ata_eh_context *ehc = &link->eh_context;

		if (ata_eh_skip_recovery(link))
			ehc->i.action = 0;

		ata_for_each_dev(dev, link, ALL)
			ehc->classes[dev->devno] = ATA_DEV_UNKNOWN;
	}

#ifdef MY_ABC_HERE
	if (ap->nr_pmp_links &&
		ap->pflags & ATA_PFLAG_SYNO_BOOT_PROBE) {
		ata_port_printk(ap, KERN_INFO, "Apply Synology fast PMP boot\n");
		ata_for_each_link(link, ap, EDGE) {
			int class = 0;

			if (ap->ops->pmp_hardreset)	
				ap->ops->pmp_hardreset(link, &class, 0);
		}
	}
#endif
	 
	ata_for_each_link(link, ap, EDGE) {
		struct ata_eh_context *ehc = &link->eh_context;

		if (!(ehc->i.action & ATA_EH_RESET))
			continue;

		rc = ata_eh_reset(link, ata_link_nr_vacant(link),
				  prereset, softreset, hardreset, postreset);
		if (rc) {
			ata_link_printk(link, KERN_ERR,
					"reset failed, giving up\n");
			goto out;
		}
	}

	do {
		unsigned long now;

		ata_eh_pull_park_action(ap);

		deadline = jiffies;
		ata_for_each_link(link, ap, EDGE) {
			ata_for_each_dev(dev, link, ALL) {
				struct ata_eh_context *ehc = &link->eh_context;
				unsigned long tmp;

				if (dev->class != ATA_DEV_ATA)
					continue;
				if (!(ehc->i.dev_action[dev->devno] &
				      ATA_EH_PARK))
					continue;
				tmp = dev->unpark_deadline;
				if (time_before(deadline, tmp))
					deadline = tmp;
				else if (time_before_eq(tmp, jiffies))
					continue;
				if (ehc->unloaded_mask & (1 << dev->devno))
					continue;

				ata_eh_park_issue_cmd(dev, 1);
			}
		}

		now = jiffies;
		if (time_before_eq(deadline, now))
			break;

		deadline = wait_for_completion_timeout(&ap->park_req_pending,
						       deadline - now);
	} while (deadline);
	ata_for_each_link(link, ap, EDGE) {
		ata_for_each_dev(dev, link, ALL) {
			if (!(link->eh_context.unloaded_mask &
			      (1 << dev->devno)))
				continue;

			ata_eh_park_issue_cmd(dev, 0);
			ata_eh_done(link, dev, ATA_EH_PARK);
		}
	}

	ata_for_each_link(link, ap, EDGE) {
		struct ata_eh_context *ehc = &link->eh_context;

		rc = ata_eh_revalidate_and_attach(link, &dev);
		if (rc)
			goto dev_fail;

		if (link->device->class == ATA_DEV_PMP) {
#ifdef MY_ABC_HERE
			if (ehc->i.action & ATA_EH_SYNO_PWON) {
				ehc->i.action = 0;
				ehc->i.action |= ATA_EH_HARDRESET;
			}else {
				ehc->i.action = 0;
			}
#else
			ehc->i.action = 0;
#endif
			return 0;
		}

		if (ehc->i.flags & ATA_EHI_SETMODE) {
			rc = ata_set_mode(link, &dev);
			if (rc)
				goto dev_fail;
			ehc->i.flags &= ~ATA_EHI_SETMODE;
		}

		if (ehc->i.flags & ATA_EHI_DID_RESET) {
			ata_for_each_dev(dev, link, ALL) {
				if (dev->class != ATA_DEV_ATAPI)
					continue;
				rc = atapi_eh_clear_ua(dev);
				if (rc)
					goto dev_fail;
			}
		}

#ifdef MY_ABC_HERE
		 
		ata_for_each_dev(dev, link, ALL) {
			if (dev->class != ATA_DEV_ATA)
				continue;
			rc = ata_eh_maybe_retry_flush(dev);
			if (rc)
				goto dev_fail;
		}
#endif

		if (ehc->i.action & ATA_EH_LPM)
			ata_for_each_dev(dev, link, ALL)
				ata_dev_enable_pm(dev, ap->pm_policy);

#ifdef MY_ABC_HERE
		if (ehc->i.action & ATA_EH_WCACHE_DISABLE) {
			ata_for_each_dev(dev, link, ALL) {
				unsigned int err_mask = 0;
				if (dev->class != ATA_DEV_ATA || !(dev->flags & ATA_DFLAG_NO_WCACHE))
					continue;

				ata_dev_printk(dev, KERN_ERR, "Disable disk write cache in EH");
				err_mask = ata_dev_set_feature(dev, SETFEATURES_WC_OFF, 0);
				if (err_mask)
					ata_dev_printk(dev, KERN_ERR,
						"failed to dsiable write cache "
						"(err_mask=0x%x)\n", err_mask);
			}
		}
#endif

		ehc->i.flags = 0;
		continue;

dev_fail:
		nr_failed_devs++;
		ata_eh_handle_dev_fail(dev, rc);

		if (ap->pflags & ATA_PFLAG_FROZEN) {
			 
			if (sata_pmp_attached(ap))
				goto out;
			break;
		}
	}

	if (nr_failed_devs)
		goto retry;

 out:
	if (rc && r_failed_link)
		*r_failed_link = link;

	DPRINTK("EXIT, rc=%d\n", rc);
	return rc;
}

void ata_eh_finish(struct ata_port *ap)
{
	int tag;

	for (tag = 0; tag < ATA_MAX_QUEUE; tag++) {
		struct ata_queued_cmd *qc = __ata_qc_from_tag(ap, tag);

#ifdef MY_ABC_HERE
		if (0 < guiWakeupDisksNum && 1 == ap->nr_active_links &&
			(qc->flags & ATA_QCFLAG_ACTIVE) && IS_SYNO_SPINUP_CMD(qc)) {
			DBGMESG("ata%u eh finish, set failed to spinup cmd 0x%x\n", ap->print_id, qc->tf.command);
			qc->flags |= ATA_QCFLAG_FAILED;
			__ata_qc_complete(qc);
			continue;
		}
#endif

		if (!(qc->flags & ATA_QCFLAG_FAILED))
			continue;

		if (qc->err_mask) {
			 
			if (qc->flags & ATA_QCFLAG_RETRY)
				ata_eh_qc_retry(qc);
			else
				ata_eh_qc_complete(qc);
		} else {
			if (qc->flags & ATA_QCFLAG_SENSE_VALID) {
				ata_eh_qc_complete(qc);
			} else {
				 
				memset(&qc->result_tf, 0, sizeof(qc->result_tf));
				ata_eh_qc_retry(qc);
			}
		}
	}

	WARN_ON(ap->nr_active_links);
	ap->nr_active_links = 0;
}

void ata_do_eh(struct ata_port *ap, ata_prereset_fn_t prereset,
	       ata_reset_fn_t softreset, ata_reset_fn_t hardreset,
	       ata_postreset_fn_t postreset)
{
	struct ata_device *dev;
	int rc;

	ata_eh_autopsy(ap);
	ata_eh_report(ap);

	rc = ata_eh_recover(ap, prereset, softreset, hardreset, postreset,
			    NULL);
	if (rc) {
		ata_for_each_dev(dev, &ap->link, ALL)
			ata_dev_disable(dev);
	}

	ata_eh_finish(ap);
}

void ata_std_error_handler(struct ata_port *ap)
{
	struct ata_port_operations *ops = ap->ops;
	ata_reset_fn_t hardreset = ops->hardreset;

	if (ata_is_builtin_hardreset(hardreset) && !sata_scr_valid(&ap->link))
		hardreset = NULL;

	ata_do_eh(ap, ops->prereset, ops->softreset, hardreset, ops->postreset);
}

#ifdef CONFIG_PM
 
static void ata_eh_handle_port_suspend(struct ata_port *ap)
{
	unsigned long flags;
	int rc = 0;

	spin_lock_irqsave(ap->lock, flags);
	if (!(ap->pflags & ATA_PFLAG_PM_PENDING) ||
	    ap->pm_mesg.event == PM_EVENT_ON) {
		spin_unlock_irqrestore(ap->lock, flags);
		return;
	}
	spin_unlock_irqrestore(ap->lock, flags);

	WARN_ON(ap->pflags & ATA_PFLAG_SUSPENDED);

	rc = ata_acpi_on_suspend(ap);
	if (rc)
		goto out;

	ata_eh_freeze_port(ap);

	if (ap->ops->port_suspend)
		rc = ap->ops->port_suspend(ap, ap->pm_mesg);

	ata_acpi_set_state(ap, PMSG_SUSPEND);
 out:
	 
	spin_lock_irqsave(ap->lock, flags);

	ap->pflags &= ~ATA_PFLAG_PM_PENDING;
	if (rc == 0)
		ap->pflags |= ATA_PFLAG_SUSPENDED;
	else if (ap->pflags & ATA_PFLAG_FROZEN)
		ata_port_schedule_eh(ap);

	if (ap->pm_result) {
		*ap->pm_result = rc;
		ap->pm_result = NULL;
	}

	spin_unlock_irqrestore(ap->lock, flags);

	return;
}

static void ata_eh_handle_port_resume(struct ata_port *ap)
{
	struct ata_link *link;
	struct ata_device *dev;
	unsigned long flags;
	int rc = 0;

	spin_lock_irqsave(ap->lock, flags);
	if (!(ap->pflags & ATA_PFLAG_PM_PENDING) ||
	    ap->pm_mesg.event != PM_EVENT_ON) {
		spin_unlock_irqrestore(ap->lock, flags);
		return;
	}
	spin_unlock_irqrestore(ap->lock, flags);

	WARN_ON(!(ap->pflags & ATA_PFLAG_SUSPENDED));

	ata_for_each_link(link, ap, HOST_FIRST)
		ata_for_each_dev(dev, link, ALL)
			ata_ering_clear(&dev->ering);

	ata_acpi_set_state(ap, PMSG_ON);

	if (ap->ops->port_resume)
		rc = ap->ops->port_resume(ap);

	ata_acpi_on_resume(ap);

	spin_lock_irqsave(ap->lock, flags);
	ap->pflags &= ~(ATA_PFLAG_PM_PENDING | ATA_PFLAG_SUSPENDED);
	if (ap->pm_result) {
		*ap->pm_result = rc;
		ap->pm_result = NULL;
	}
	spin_unlock_irqrestore(ap->lock, flags);
}
#endif  
