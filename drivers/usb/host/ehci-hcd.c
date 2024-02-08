#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/dmapool.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/usb.h>
#include <linux/moduleparam.h>
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>

#include "../core/hcd.h"

#include <asm/byteorder.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/system.h>
#include <asm/unaligned.h>

#define DRIVER_AUTHOR "David Brownell"
#define DRIVER_DESC "USB 2.0 'Enhanced' Host Controller (EHCI) Driver"

static const char	hcd_name [] = "ehci_hcd";

#undef VERBOSE_DEBUG
#undef EHCI_URB_TRACE

#ifdef DEBUG
#define EHCI_STATS
#endif

#define	EHCI_TUNE_CERR		3	 
#define	EHCI_TUNE_RL_HS		4	 
#define	EHCI_TUNE_RL_TT		0
#define	EHCI_TUNE_MULT_HS	1	 
#define	EHCI_TUNE_MULT_TT	1
#define	EHCI_TUNE_FLS		2	 

#define EHCI_IAA_MSECS		10		 
#define EHCI_IO_JIFFIES		(HZ/10)		 
#define EHCI_ASYNC_JIFFIES	(HZ/20)		 
#define EHCI_SHRINK_FRAMES	5		 

static int log2_irq_thresh = 0;		 
module_param (log2_irq_thresh, int, S_IRUGO);
MODULE_PARM_DESC (log2_irq_thresh, "log2 IRQ latency, 1-64 microframes");

static unsigned park = 0;
module_param (park, uint, S_IRUGO);
MODULE_PARM_DESC (park, "park setting; 1-3 back-to-back async packets");

static int ignore_oc = 0;
module_param (ignore_oc, bool, S_IRUGO);
MODULE_PARM_DESC (ignore_oc, "ignore bogus hardware overcurrent indications");

#define	INTR_MASK (STS_IAA | STS_FATAL | STS_PCD | STS_ERR | STS_INT)

#include "ehci.h"
#include "ehci-dbg.c"

static void
timer_action(struct ehci_hcd *ehci, enum ehci_timer_action action)
{
	 
	if (timer_pending(&ehci->watchdog)
			&& ((BIT(TIMER_ASYNC_SHRINK) | BIT(TIMER_ASYNC_OFF))
				& ehci->actions))
		return;

	if (!test_and_set_bit(action, &ehci->actions)) {
		unsigned long t;

		switch (action) {
		case TIMER_IO_WATCHDOG:
			if (!ehci->need_io_watchdog)
				return;
			t = EHCI_IO_JIFFIES;
			break;
		case TIMER_ASYNC_OFF:
			t = EHCI_ASYNC_JIFFIES;
			break;
		 
		default:
			 
			t = DIV_ROUND_UP(EHCI_SHRINK_FRAMES * HZ, 1000) + 1;
			break;
		}
		mod_timer(&ehci->watchdog, t + jiffies);
	}
}

static int handshake (struct ehci_hcd *ehci, void __iomem *ptr,
		      u32 mask, u32 done, int usec)
{
	u32	result;

	do {
		result = ehci_readl(ehci, ptr);
		if (result == ~(u32)0)		 
			return -ENODEV;
		result &= mask;
		if (result == done)
			return 0;
		udelay (1);
		usec--;
	} while (usec > 0);
	return -ETIMEDOUT;
}

static int ehci_halt (struct ehci_hcd *ehci)
{
	u32	temp = ehci_readl(ehci, &ehci->regs->status);

	ehci_writel(ehci, 0, &ehci->regs->intr_enable);

	if ((temp & STS_HALT) != 0)
		return 0;

	temp = ehci_readl(ehci, &ehci->regs->command);
	temp &= ~CMD_RUN;
	ehci_writel(ehci, temp, &ehci->regs->command);
	return handshake (ehci, &ehci->regs->status,
			  STS_HALT, STS_HALT, 16 * 125);
}

static int handshake_on_error_set_halt(struct ehci_hcd *ehci, void __iomem *ptr,
				       u32 mask, u32 done, int usec)
{
	int error;

	error = handshake(ehci, ptr, mask, done, usec);
	if (error) {
		ehci_halt(ehci);
		ehci_to_hcd(ehci)->state = HC_STATE_HALT;
		ehci_err(ehci, "force halt; handhake %p %08x %08x -> %d\n",
			ptr, mask, done, error);
	}

	return error;
}

static void tdi_reset (struct ehci_hcd *ehci)
{
	u32 __iomem	*reg_ptr;
	u32		tmp;

#ifdef CONFIG_SYNO_PLX_PORTING
	reg_ptr = (u32 __iomem *)&ehci->regs->usbmode;
#else
	reg_ptr = (u32 __iomem *)(((u8 __iomem *)ehci->regs) + USBMODE);
#endif
	tmp = ehci_readl(ehci, reg_ptr);
	tmp |= USBMODE_CM_HC;

#if defined(CONFIG_MV_INCLUDE_USB) || defined(MY_ABC_HERE)
	tmp |= (1 << 4);  
#endif

	if (ehci_big_endian_mmio(ehci))
		tmp |= USBMODE_BE;
	ehci_writel(ehci, tmp, reg_ptr);

#ifdef CONFIG_SYNO_PLX_PORTING
#if defined(CONFIG_ARCH_OXNAS) || defined(CONFIG_ARCH_OX820)
	reg_ptr = (u32 __iomem *)&ehci->regs->txfilltuning;
	tmp = ehci_readl(ehci, reg_ptr);
	tmp &= ~0x00ff0000;
#ifndef CONFIG_ARCH_OX820
	tmp |= 0x003f0000;  
	tmp |= 0x16;  
#else
	tmp |= 0x003f0000;  
	tmp |= 0x16;  
#endif
	ehci_writel(ehci, tmp, reg_ptr);

	reg_ptr = (u32 __iomem *)&ehci->regs->txttfilltuning;
	tmp = readl (reg_ptr);
	tmp |= 0x2;  
	writel (tmp, reg_ptr);
#endif  
#endif
}

static int ehci_reset (struct ehci_hcd *ehci)
{
	int	retval;
	u32	command = ehci_readl(ehci, &ehci->regs->command);

	if (ehci->debug && !dbgp_reset_prep())
		ehci->debug = NULL;

	command |= CMD_RESET;
	dbg_cmd (ehci, "reset", command);
	ehci_writel(ehci, command, &ehci->regs->command);
	ehci_to_hcd(ehci)->state = HC_STATE_HALT;
	ehci->next_statechange = jiffies;
	retval = handshake (ehci, &ehci->regs->command,
			    CMD_RESET, 0, 250 * 1000);

	if (ehci->has_hostpc) {
		ehci_writel(ehci, USBMODE_EX_HC | USBMODE_EX_VBPS,
			(u32 __iomem *)(((u8 *)ehci->regs) + USBMODE_EX));
		ehci_writel(ehci, TXFIFO_DEFAULT,
			(u32 __iomem *)(((u8 *)ehci->regs) + TXFILLTUNING));
	}
	if (retval)
		return retval;

#ifdef CONFIG_SYNO_PLX_PORTING
	if (ehci->is_tdi_rh_tt)
		tdi_reset(ehci);  
#if defined(CONFIG_ARCH_OXNAS)
	command=readl(&ehci->regs->port_status[1]);
	command |=0xc0000000;  
	writel(command,&ehci->regs->port_status[1]); 

	command=readl(&ehci->regs->port_status[2]);
	command |=0xc0000000;  
	writel(command,&ehci->regs->port_status[2]); 
#endif  
#else
	if (ehci_is_TDI(ehci))
		tdi_reset (ehci);
#endif

	if (ehci->debug)
		dbgp_external_startup();

	return retval;
}

static void ehci_quiesce (struct ehci_hcd *ehci)
{
	u32	temp;

#ifdef DEBUG
	if (!HC_IS_RUNNING (ehci_to_hcd(ehci)->state))
		BUG ();
#endif

	temp = ehci_readl(ehci, &ehci->regs->command) << 10;
	temp &= STS_ASS | STS_PSS;
	if (handshake_on_error_set_halt(ehci, &ehci->regs->status,
					STS_ASS | STS_PSS, temp, 16 * 125))
		return;

	temp = ehci_readl(ehci, &ehci->regs->command);
	temp &= ~(CMD_ASE | CMD_IAAD | CMD_PSE);
	ehci_writel(ehci, temp, &ehci->regs->command);

	handshake_on_error_set_halt(ehci, &ehci->regs->status,
				    STS_ASS | STS_PSS, 0, 16 * 125);
}

static void end_unlink_async(struct ehci_hcd *ehci);
static void ehci_work(struct ehci_hcd *ehci);

#include "ehci-hub.c"
#include "ehci-mem.c"
#include "ehci-q.c"
#include "ehci-sched.c"

static void ehci_iaa_watchdog(unsigned long param)
{
	struct ehci_hcd		*ehci = (struct ehci_hcd *) param;
	unsigned long		flags;

	spin_lock_irqsave (&ehci->lock, flags);

	if (ehci->reclaim
			&& !timer_pending(&ehci->iaa_watchdog)
			&& HC_IS_RUNNING(ehci_to_hcd(ehci)->state)) {
		u32 cmd, status;

		cmd = ehci_readl(ehci, &ehci->regs->command);
		if (cmd & CMD_IAAD)
			ehci_writel(ehci, cmd & ~CMD_IAAD,
					&ehci->regs->command);

		status = ehci_readl(ehci, &ehci->regs->status);
		if ((status & STS_IAA) || !(cmd & CMD_IAAD)) {
			COUNT (ehci->stats.lost_iaa);
			ehci_writel(ehci, STS_IAA, &ehci->regs->status);
		}

		ehci_vdbg(ehci, "IAA watchdog: status %x cmd %x\n",
				status, cmd);
		end_unlink_async(ehci);
	}

	spin_unlock_irqrestore(&ehci->lock, flags);
}

static void ehci_watchdog(unsigned long param)
{
	struct ehci_hcd		*ehci = (struct ehci_hcd *) param;
	unsigned long		flags;

	spin_lock_irqsave(&ehci->lock, flags);

	if (test_bit (TIMER_ASYNC_OFF, &ehci->actions))
		start_unlink_async (ehci, ehci->async);

	ehci_work (ehci);

	spin_unlock_irqrestore (&ehci->lock, flags);
}

static void ehci_turn_off_all_ports(struct ehci_hcd *ehci)
{
	int	port = HCS_N_PORTS(ehci->hcs_params);

	while (port--)
		ehci_writel(ehci, PORT_RWC_BITS,
				&ehci->regs->port_status[port]);
}

static void ehci_silence_controller(struct ehci_hcd *ehci)
{
	ehci_halt(ehci);
	ehci_turn_off_all_ports(ehci);

	ehci_writel(ehci, 0, &ehci->regs->configured_flag);

	ehci_readl(ehci, &ehci->regs->configured_flag);
}

static void ehci_shutdown(struct usb_hcd *hcd)
{
	struct ehci_hcd	*ehci = hcd_to_ehci(hcd);

	del_timer_sync(&ehci->watchdog);
	del_timer_sync(&ehci->iaa_watchdog);

	spin_lock_irq(&ehci->lock);
	ehci_silence_controller(ehci);
	spin_unlock_irq(&ehci->lock);
}

static void ehci_port_power (struct ehci_hcd *ehci, int is_on)
{
	unsigned port;

	if (!HCS_PPC (ehci->hcs_params))
		return;

	ehci_dbg (ehci, "...power%s ports...\n", is_on ? "up" : "down");
	for (port = HCS_N_PORTS (ehci->hcs_params); port > 0; )
		(void) ehci_hub_control(ehci_to_hcd(ehci),
				is_on ? SetPortFeature : ClearPortFeature,
				USB_PORT_FEAT_POWER,
				port--, NULL, 0);
	 
	ehci_readl(ehci, &ehci->regs->command);
	msleep(20);
}

static void ehci_work (struct ehci_hcd *ehci)
{
	timer_action_done (ehci, TIMER_IO_WATCHDOG);

	if (ehci->scanning)
		return;
	ehci->scanning = 1;
	scan_async (ehci);
	if (ehci->next_uframe != -1)
		scan_periodic (ehci);
	ehci->scanning = 0;

	if (HC_IS_RUNNING (ehci_to_hcd(ehci)->state) &&
			(ehci->async->qh_next.ptr != NULL ||
			 ehci->periodic_sched != 0))
		timer_action (ehci, TIMER_IO_WATCHDOG);
}

static void ehci_stop (struct usb_hcd *hcd)
{
	struct ehci_hcd		*ehci = hcd_to_ehci (hcd);

	ehci_dbg (ehci, "stop\n");

	del_timer_sync (&ehci->watchdog);
	del_timer_sync(&ehci->iaa_watchdog);

	spin_lock_irq(&ehci->lock);
	if (HC_IS_RUNNING (hcd->state))
		ehci_quiesce (ehci);

	ehci_silence_controller(ehci);
	ehci_reset (ehci);
	spin_unlock_irq(&ehci->lock);

	remove_companion_file(ehci);
	remove_debug_files (ehci);

	spin_lock_irq (&ehci->lock);
	if (ehci->async)
		ehci_work (ehci);
	spin_unlock_irq (&ehci->lock);
	ehci_mem_cleanup (ehci);

#ifdef	EHCI_STATS
	ehci_dbg (ehci, "irq normal %ld err %ld reclaim %ld (lost %ld)\n",
		ehci->stats.normal, ehci->stats.error, ehci->stats.reclaim,
		ehci->stats.lost_iaa);
	ehci_dbg (ehci, "complete %ld unlink %ld\n",
		ehci->stats.complete, ehci->stats.unlink);
#endif

	dbg_status (ehci, "ehci_stop completed",
		    ehci_readl(ehci, &ehci->regs->status));
}

static int ehci_init(struct usb_hcd *hcd)
{
	struct ehci_hcd		*ehci = hcd_to_ehci(hcd);
	u32			temp;
	int			retval;
	u32			hcc_params;
	struct ehci_qh_hw	*hw;

	spin_lock_init(&ehci->lock);

	ehci->need_io_watchdog = 1;
	init_timer(&ehci->watchdog);
	ehci->watchdog.function = ehci_watchdog;
	ehci->watchdog.data = (unsigned long) ehci;

	init_timer(&ehci->iaa_watchdog);
	ehci->iaa_watchdog.function = ehci_iaa_watchdog;
	ehci->iaa_watchdog.data = (unsigned long) ehci;

	ehci->periodic_size = DEFAULT_I_TDPS;
	INIT_LIST_HEAD(&ehci->cached_itd_list);
	if ((retval = ehci_mem_init(ehci, GFP_KERNEL)) < 0)
		return retval;

	hcc_params = ehci_readl(ehci, &ehci->caps->hcc_params);
	if (HCC_ISOC_CACHE(hcc_params))		 
		ehci->i_thresh = 8;
	else					 
		ehci->i_thresh = 2 + HCC_ISOC_THRES(hcc_params);

	ehci->reclaim = NULL;
	ehci->next_uframe = -1;
	ehci->clock_frame = -1;

	ehci->async->qh_next.qh = NULL;
	hw = ehci->async->hw;
	hw->hw_next = QH_NEXT(ehci, ehci->async->qh_dma);
	hw->hw_info1 = cpu_to_hc32(ehci, QH_HEAD);
	hw->hw_token = cpu_to_hc32(ehci, QTD_STS_HALT);
	hw->hw_qtd_next = EHCI_LIST_END(ehci);
	ehci->async->qh_state = QH_STATE_LINKED;
	hw->hw_alt_next = QTD_NEXT(ehci, ehci->async->dummy->qtd_dma);

	if (log2_irq_thresh < 0 || log2_irq_thresh > 6)
		log2_irq_thresh = 0;
	temp = 1 << (16 + log2_irq_thresh);
	if (HCC_CANPARK(hcc_params)) {
		 
		if (park) {
			park = min(park, (unsigned) 3);
			temp |= CMD_PARK;
			temp |= park << 8;
		}
		ehci_dbg(ehci, "park %d\n", park);
	}
	if (HCC_PGM_FRAMELISTLEN(hcc_params)) {
		 
		temp &= ~(3 << 2);
		temp |= (EHCI_TUNE_FLS << 2);
		switch (EHCI_TUNE_FLS) {
		case 0: ehci->periodic_size = 1024; break;
		case 1: ehci->periodic_size = 512; break;
		case 2: ehci->periodic_size = 256; break;
		default:	BUG();
		}
	}
	ehci->command = temp;

	return 0;
}

static int ehci_run (struct usb_hcd *hcd)
{
	struct ehci_hcd		*ehci = hcd_to_ehci (hcd);
	int			retval;
	u32			temp;
	u32			hcc_params;

	hcd->uses_new_polling = 1;
	hcd->poll_rh = 0;

	if ((retval = ehci_reset(ehci)) != 0) {
		ehci_mem_cleanup(ehci);
		return retval;
	}
	ehci_writel(ehci, ehci->periodic_dma, &ehci->regs->frame_list);
	ehci_writel(ehci, (u32)ehci->async->qh_dma, &ehci->regs->async_next);

	hcc_params = ehci_readl(ehci, &ehci->caps->hcc_params);
	if (HCC_64BIT_ADDR(hcc_params)) {
		ehci_writel(ehci, 0, &ehci->regs->segment);
#if 0
 
		if (!dma_set_mask(hcd->self.controller, DMA_BIT_MASK(64)))
			ehci_info(ehci, "enabled 64bit DMA\n");
#endif
	}

	ehci->command &= ~(CMD_LRESET|CMD_IAAD|CMD_PSE|CMD_ASE|CMD_RESET);
	ehci->command |= CMD_RUN;
	ehci_writel(ehci, ehci->command, &ehci->regs->command);
	dbg_cmd (ehci, "init", ehci->command);

	down_write(&ehci_cf_port_reset_rwsem);
	hcd->state = HC_STATE_RUNNING;
	ehci_writel(ehci, FLAG_CF, &ehci->regs->configured_flag);
	ehci_readl(ehci, &ehci->regs->command);	 
	msleep(5);
	up_write(&ehci_cf_port_reset_rwsem);
	ehci->last_periodic_enable = ktime_get_real();

	temp = HC_VERSION(ehci_readl(ehci, &ehci->caps->hc_capbase));
	ehci_info (ehci,
		"USB %x.%x started, EHCI %x.%02x%s\n",
		((ehci->sbrn & 0xf0)>>4), (ehci->sbrn & 0x0f),
		temp >> 8, temp & 0xff,
		ignore_oc ? ", overcurrent ignored" : "");

	ehci_writel(ehci, INTR_MASK,
		    &ehci->regs->intr_enable);  

	create_debug_files(ehci);
	create_companion_file(ehci);

	return 0;
}

static irqreturn_t ehci_irq (struct usb_hcd *hcd)
{
	struct ehci_hcd		*ehci = hcd_to_ehci (hcd);
	u32			status, masked_status, pcd_status = 0, cmd;
	int			bh;

	spin_lock (&ehci->lock);

	status = ehci_readl(ehci, &ehci->regs->status);

	if (status == ~(u32) 0) {
		ehci_dbg (ehci, "device removed\n");
		goto dead;
	}

	masked_status = status & INTR_MASK;
	if (!masked_status) {		 
		spin_unlock(&ehci->lock);
		return IRQ_NONE;
	}

	ehci_writel(ehci, masked_status, &ehci->regs->status);
	cmd = ehci_readl(ehci, &ehci->regs->command);
	bh = 0;

#ifdef	VERBOSE_DEBUG
	 
	dbg_status (ehci, "irq", status);
#endif

	if (likely ((status & (STS_INT|STS_ERR)) != 0)) {
		if (likely ((status & STS_ERR) == 0))
			COUNT (ehci->stats.normal);
		else
			COUNT (ehci->stats.error);
		bh = 1;
	}

	if (status & STS_IAA) {
		 
		if (cmd & CMD_IAAD) {
			ehci_writel(ehci, cmd & ~CMD_IAAD,
					&ehci->regs->command);
			ehci_dbg(ehci, "IAA with IAAD still set?\n");
		}
		if (ehci->reclaim) {
			COUNT(ehci->stats.reclaim);
			end_unlink_async(ehci);
		} else
			ehci_dbg(ehci, "IAA with nothing to reclaim?\n");
	}

	if (status & STS_PCD) {
		unsigned	i = HCS_N_PORTS (ehci->hcs_params);

		pcd_status = status;

		if (!(cmd & CMD_RUN))
			usb_hcd_resume_root_hub(hcd);

		while (i--) {
			int pstatus = ehci_readl(ehci,
						 &ehci->regs->port_status [i]);

			if (pstatus & PORT_OWNER)
				continue;
			if (!(test_bit(i, &ehci->suspended_ports) &&
					((pstatus & PORT_RESUME) ||
						!(pstatus & PORT_SUSPEND)) &&
					(pstatus & PORT_PE) &&
					ehci->reset_done[i] == 0))
				continue;

			ehci->reset_done[i] = jiffies + msecs_to_jiffies(25);
			ehci_dbg (ehci, "port %d remote wakeup\n", i + 1);
			mod_timer(&hcd->rh_timer, ehci->reset_done[i]);
		}
	}

	if (unlikely ((status & STS_FATAL) != 0)) {
		ehci_err(ehci, "fatal error\n");
		dbg_cmd(ehci, "fatal", cmd);
		dbg_status(ehci, "fatal", status);
		ehci_halt(ehci);
dead:
		ehci_reset(ehci);
		ehci_writel(ehci, 0, &ehci->regs->configured_flag);
		 
		bh = 1;
	}

	if (bh)
		ehci_work (ehci);
	spin_unlock (&ehci->lock);
	if (pcd_status)
		usb_hcd_poll_rh_status(hcd);
	return IRQ_HANDLED;
}

static int ehci_urb_enqueue (
	struct usb_hcd	*hcd,
	struct urb	*urb,
	gfp_t		mem_flags
) {
	struct ehci_hcd		*ehci = hcd_to_ehci (hcd);
	struct list_head	qtd_list;

	INIT_LIST_HEAD (&qtd_list);

	switch (usb_pipetype (urb->pipe)) {
	case PIPE_CONTROL:
		 
		if (urb->transfer_buffer_length > (16 * 1024))
			return -EMSGSIZE;
		 
	default:
		if (!qh_urb_transaction (ehci, urb, &qtd_list, mem_flags))
			return -ENOMEM;
		return submit_async(ehci, urb, &qtd_list, mem_flags);

	case PIPE_INTERRUPT:
		if (!qh_urb_transaction (ehci, urb, &qtd_list, mem_flags))
			return -ENOMEM;
		return intr_submit(ehci, urb, &qtd_list, mem_flags);

	case PIPE_ISOCHRONOUS:
		if (urb->dev->speed == USB_SPEED_HIGH)
			return itd_submit (ehci, urb, mem_flags);
		else
			return sitd_submit (ehci, urb, mem_flags);
	}
}

static void unlink_async (struct ehci_hcd *ehci, struct ehci_qh *qh)
{
	 
	if (!HC_IS_RUNNING(ehci_to_hcd(ehci)->state) && ehci->reclaim)
		end_unlink_async(ehci);

	if (qh->qh_state != QH_STATE_LINKED) {
		if (qh->qh_state == QH_STATE_COMPLETING)
			qh->needs_rescan = 1;
		return;
	}

	if (ehci->reclaim) {
		struct ehci_qh		*last;

		for (last = ehci->reclaim;
				last->reclaim;
				last = last->reclaim)
			continue;
		qh->qh_state = QH_STATE_UNLINK_WAIT;
		last->reclaim = qh;

	} else
		start_unlink_async (ehci, qh);
}

static int ehci_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	struct ehci_hcd		*ehci = hcd_to_ehci (hcd);
	struct ehci_qh		*qh;
	unsigned long		flags;
	int			rc;

	spin_lock_irqsave (&ehci->lock, flags);
	rc = usb_hcd_check_unlink_urb(hcd, urb, status);
	if (rc)
		goto done;

	switch (usb_pipetype (urb->pipe)) {
	 
	default:
		qh = (struct ehci_qh *) urb->hcpriv;
		if (!qh)
			break;
		switch (qh->qh_state) {
		case QH_STATE_LINKED:
		case QH_STATE_COMPLETING:
			unlink_async(ehci, qh);
			break;
		case QH_STATE_UNLINK:
		case QH_STATE_UNLINK_WAIT:
			 
			break;
		case QH_STATE_IDLE:
			 
			qh_completions(ehci, qh);
			break;
		}
		break;

	case PIPE_INTERRUPT:
		qh = (struct ehci_qh *) urb->hcpriv;
		if (!qh)
			break;
		switch (qh->qh_state) {
		case QH_STATE_LINKED:
		case QH_STATE_COMPLETING:
			intr_deschedule (ehci, qh);
			break;
		case QH_STATE_IDLE:
			qh_completions (ehci, qh);
			break;
		default:
			ehci_dbg (ehci, "bogus qh %p state %d\n",
					qh, qh->qh_state);
			goto done;
		}
		break;

	case PIPE_ISOCHRONOUS:
		 
		break;
	}
done:
	spin_unlock_irqrestore (&ehci->lock, flags);
	return rc;
}

static void
ehci_endpoint_disable (struct usb_hcd *hcd, struct usb_host_endpoint *ep)
{
	struct ehci_hcd		*ehci = hcd_to_ehci (hcd);
	unsigned long		flags;
	struct ehci_qh		*qh, *tmp;

rescan:
	spin_lock_irqsave (&ehci->lock, flags);
	qh = ep->hcpriv;
	if (!qh)
		goto done;

	if (qh->hw == NULL) {
		ehci_vdbg (ehci, "iso delay\n");
		goto idle_timeout;
	}

	if (!HC_IS_RUNNING (hcd->state))
		qh->qh_state = QH_STATE_IDLE;
	switch (qh->qh_state) {
	case QH_STATE_LINKED:
	case QH_STATE_COMPLETING:
		for (tmp = ehci->async->qh_next.qh;
				tmp && tmp != qh;
				tmp = tmp->qh_next.qh)
			continue;
		 
		if (!tmp)
			goto nogood;
		unlink_async (ehci, qh);
		 
	case QH_STATE_UNLINK:		 
	case QH_STATE_UNLINK_WAIT:
idle_timeout:
		spin_unlock_irqrestore (&ehci->lock, flags);
		schedule_timeout_uninterruptible(1);
		goto rescan;
	case QH_STATE_IDLE:		 
		if (qh->clearing_tt)
			goto idle_timeout;
		if (list_empty (&qh->qtd_list)) {
			qh_put (qh);
			break;
		}
		 
	default:
nogood:
		 
		ehci_err (ehci, "qh %p (#%02x) state %d%s\n",
			qh, ep->desc.bEndpointAddress, qh->qh_state,
			list_empty (&qh->qtd_list) ? "" : "(has tds)");
		break;
	}
	ep->hcpriv = NULL;
done:
	spin_unlock_irqrestore (&ehci->lock, flags);
}

static void
ehci_endpoint_reset(struct usb_hcd *hcd, struct usb_host_endpoint *ep)
{
	struct ehci_hcd		*ehci = hcd_to_ehci(hcd);
	struct ehci_qh		*qh;
	int			eptype = usb_endpoint_type(&ep->desc);
	int			epnum = usb_endpoint_num(&ep->desc);
	int			is_out = usb_endpoint_dir_out(&ep->desc);
	unsigned long		flags;

	if (eptype != USB_ENDPOINT_XFER_BULK && eptype != USB_ENDPOINT_XFER_INT)
		return;

	spin_lock_irqsave(&ehci->lock, flags);
	qh = ep->hcpriv;

	if (qh) {
		usb_settoggle(qh->dev, epnum, is_out, 0);
		if (!list_empty(&qh->qtd_list)) {
			WARN_ONCE(1, "clear_halt for a busy endpoint\n");
		} else if (qh->qh_state == QH_STATE_LINKED ||
				qh->qh_state == QH_STATE_COMPLETING) {

			if (eptype == USB_ENDPOINT_XFER_BULK)
				unlink_async(ehci, qh);
			else
				intr_deschedule(ehci, qh);
		}
	}
	spin_unlock_irqrestore(&ehci->lock, flags);
}

static int ehci_get_frame (struct usb_hcd *hcd)
{
	struct ehci_hcd		*ehci = hcd_to_ehci (hcd);
	return (ehci_readl(ehci, &ehci->regs->frame_index) >> 3) %
		ehci->periodic_size;
}

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR (DRIVER_AUTHOR);
MODULE_LICENSE ("GPL");

#ifndef CONFIG_SYNO_PLX_PORTING
#ifdef CONFIG_PCI
#include "ehci-pci.c"
#define	PCI_DRIVER		ehci_pci_driver
#endif
#else
#if defined(CONFIG_ARCH_OXNAS) || defined(CONFIG_ARCH_OX820)
#include "ehci-oxnas.c"
#define	PLATFORM_DRIVER		ehci_hcd_oxnas_driver
#else  
#ifdef CONFIG_PCI
#include "ehci-pci.c"
#define	PCI_DRIVER		ehci_pci_driver
#endif  
#endif  
#endif

#ifdef CONFIG_USB_EHCI_FSL
#include "ehci-fsl.c"
#define	PLATFORM_DRIVER		ehci_fsl_driver
#endif

#ifdef CONFIG_SOC_AU1200
#include "ehci-au1xxx.c"
#define	PLATFORM_DRIVER		ehci_hcd_au1xxx_driver
#endif

#ifdef CONFIG_PPC_PS3
#include "ehci-ps3.c"
#define	PS3_SYSTEM_BUS_DRIVER	ps3_ehci_driver
#endif

#ifdef CONFIG_USB_EHCI_HCD_PPC_OF
#include "ehci-ppc-of.c"
#define OF_PLATFORM_DRIVER	ehci_hcd_ppc_of_driver
#endif

#ifdef CONFIG_PLAT_ORION
#include "ehci-orion.c"
#define	PLATFORM_DRIVER		ehci_orion_driver
#endif

#if defined(CONFIG_ARCH_FEROCEON) || defined(CONFIG_MARVELL)
#ifdef MY_ABC_HERE
#include "ehci-orion.c"
#define	PLATFORM_DRIVER		ehci_orion_driver
#else
#include "ehci_marvell.c"
#define PLATFORM_DRIVER     ehci_marvell_driver
#endif
#endif

#ifdef CONFIG_ARCH_IXP4XX
#include "ehci-ixp4xx.c"
#define	PLATFORM_DRIVER		ixp4xx_ehci_driver
#endif

#ifdef CONFIG_USB_W90X900_EHCI
#include "ehci-w90x900.c"
#define	PLATFORM_DRIVER		ehci_hcd_w90x900_driver
#endif

#ifdef CONFIG_ARCH_AT91
#include "ehci-atmel.c"
#define	PLATFORM_DRIVER		ehci_atmel_driver
#endif

#if !defined(PCI_DRIVER) && !defined(PLATFORM_DRIVER) && \
    !defined(PS3_SYSTEM_BUS_DRIVER) && !defined(OF_PLATFORM_DRIVER)
#error "missing bus glue for ehci-hcd"
#endif

static int __init ehci_hcd_init(void)
{
	int retval = 0;

	if (usb_disabled())
		return -ENODEV;

	printk(KERN_INFO "%s: " DRIVER_DESC "\n", hcd_name);
	set_bit(USB_EHCI_LOADED, &usb_hcds_loaded);
	if (test_bit(USB_UHCI_LOADED, &usb_hcds_loaded) ||
			test_bit(USB_OHCI_LOADED, &usb_hcds_loaded))
		printk(KERN_WARNING "Warning! ehci_hcd should always be loaded"
				" before uhci_hcd and ohci_hcd, not after\n");

	pr_debug("%s: block sizes: qh %Zd qtd %Zd itd %Zd sitd %Zd\n",
		 hcd_name,
		 sizeof(struct ehci_qh), sizeof(struct ehci_qtd),
		 sizeof(struct ehci_itd), sizeof(struct ehci_sitd));

#ifdef DEBUG
	ehci_debug_root = debugfs_create_dir("ehci", usb_debug_root);
	if (!ehci_debug_root) {
		retval = -ENOENT;
		goto err_debug;
	}
#endif

#ifdef PLATFORM_DRIVER
	retval = platform_driver_register(&PLATFORM_DRIVER);
	if (retval < 0)
		goto clean0;
#endif

#ifdef PCI_DRIVER
	retval = pci_register_driver(&PCI_DRIVER);
	if (retval < 0)
		goto clean1;
#endif

#ifdef PS3_SYSTEM_BUS_DRIVER
	retval = ps3_ehci_driver_register(&PS3_SYSTEM_BUS_DRIVER);
	if (retval < 0)
		goto clean2;
#endif

#ifdef OF_PLATFORM_DRIVER
	retval = of_register_platform_driver(&OF_PLATFORM_DRIVER);
	if (retval < 0)
		goto clean3;
#endif
	return retval;

#ifdef OF_PLATFORM_DRIVER
	 
clean3:
#endif
#ifdef PS3_SYSTEM_BUS_DRIVER
	ps3_ehci_driver_unregister(&PS3_SYSTEM_BUS_DRIVER);
clean2:
#endif
#ifdef PCI_DRIVER
	pci_unregister_driver(&PCI_DRIVER);
clean1:
#endif
#ifdef PLATFORM_DRIVER
	platform_driver_unregister(&PLATFORM_DRIVER);
clean0:
#endif
#ifdef DEBUG
	debugfs_remove(ehci_debug_root);
	ehci_debug_root = NULL;
err_debug:
#endif
	clear_bit(USB_EHCI_LOADED, &usb_hcds_loaded);
	return retval;
}
module_init(ehci_hcd_init);

static void __exit ehci_hcd_cleanup(void)
{
#ifdef OF_PLATFORM_DRIVER
	of_unregister_platform_driver(&OF_PLATFORM_DRIVER);
#endif
#ifdef PLATFORM_DRIVER
	platform_driver_unregister(&PLATFORM_DRIVER);
#endif
#ifdef PCI_DRIVER
	pci_unregister_driver(&PCI_DRIVER);
#endif
#ifdef PS3_SYSTEM_BUS_DRIVER
	ps3_ehci_driver_unregister(&PS3_SYSTEM_BUS_DRIVER);
#endif
#ifdef DEBUG
	debugfs_remove(ehci_debug_root);
#endif
	clear_bit(USB_EHCI_LOADED, &usb_hcds_loaded);
}
module_exit(ehci_hcd_cleanup);
