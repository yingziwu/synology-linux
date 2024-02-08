#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined (MY_DEF_HERE)
/*******************************************************************************
 * Copyright (C) 2016 Marvell International Ltd.
 *
 * This software file (the "File") is owned and distributed by Marvell
 * International Ltd. and/or its affiliates ("Marvell") under the following
 * alternative licensing terms.  Once you have made an election to distribute the
 * File under one of the following license alternatives, please (i) delete this
 * introductory statement regarding license alternatives, (ii) delete the three
 * license alternatives that you have not elected to use and (iii) preserve the
 * Marvell copyright notice above.
 *
 * ********************************************************************************
 * Marvell Commercial License Option
 *
 * If you received this File from Marvell and you have entered into a commercial
 * license agreement (a "Commercial License") with Marvell, the File is licensed
 * to you under the terms of the applicable Commercial License.
 *
 * ********************************************************************************
 * Marvell GPL License Option
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 2 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * ********************************************************************************
 * Marvell GNU General Public License FreeRTOS Exception
 *
 * If you received this File from Marvell, you may opt to use, redistribute and/or
 * modify this File in accordance with the terms and conditions of the Lesser
 * General Public License Version 2.1 plus the following FreeRTOS exception.
 * An independent module is a module which is not derived from or based on
 * FreeRTOS.
 * Clause 1:
 * Linking FreeRTOS statically or dynamically with other modules is making a
 * combined work based on FreeRTOS. Thus, the terms and conditions of the GNU
 * General Public License cover the whole combination.
 * As a special exception, the copyright holder of FreeRTOS gives you permission
 * to link FreeRTOS with independent modules that communicate with FreeRTOS solely
 * through the FreeRTOS API interface, regardless of the license terms of these
 * independent modules, and to copy and distribute the resulting combined work
 * under terms of your choice, provided that:
 * 1. Every copy of the combined work is accompanied by a written statement that
 * details to the recipient the version of FreeRTOS used and an offer by yourself
 * to provide the FreeRTOS source code (including any modifications you may have
 * made) should the recipient request it.
 * 2. The combined work is not itself an RTOS, scheduler, kernel or related
 * product.
 * 3. The independent modules add significant and primary functionality to
 * FreeRTOS and do not merely extend the existing functionality already present in
 * FreeRTOS.
 * Clause 2:
 * FreeRTOS may not be used for any competitive or comparative purpose, including
 * the publication of any form of run time or compile time metric, without the
 * express permission of Real Time Engineers Ltd. (this is the norm within the
 * industry and is intended to ensure information accuracy).
 *
 * ********************************************************************************
 * Marvell BSD License Option
 *
 * If you received this File from Marvell, you may opt to use, redistribute and/or
 * modify this File under the following licensing terms.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *	* Redistributions of source code must retain the above copyright notice,
 *	  this list of conditions and the following disclaimer.
 *
 *	* Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 *	* Neither the name of Marvell nor the names of its contributors may be
 *	  used to endorse or promote products derived from this software without
 *	  specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <slic/drv_dxt_if.h>
#include <slic/silabs_if.h>
#include <slic/zarlink_if.h>
#include <tal/tal.h>
#include <tal/tal_dev.h>
#include "mv_phone.h"

#define DRV_NAME "mvebu_phone"

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
long int tdm_base;
int use_pclk_external;
int mv_phone_enabled;
struct mv_phone_dev *priv;

#define TDM_STOP_MAX_POLLING_TIME 20 /* ms */

#endif /* MY_DEF_HERE */
/* TDM Interrupt Service Routine */
static irqreturn_t tdm_if_isr(int irq, void *dev_id);

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
/* PCM start/stop */
static void tdm_if_pcm_start(void);
static void tdm_if_pcm_stop(void);

#endif /* MY_DEF_HERE */
/* Rx/Tx Tasklets  */
#if defined(MY_DEF_HERE)
static void tdm2c_if_pcm_rx_process(unsigned long arg);
static void tdmmc_if_pcm_rx_process(unsigned long arg);
static void tdm2c_if_pcm_tx_process(unsigned long arg);
static void tdmmc_if_pcm_tx_process(unsigned long arg);
static void tdm2c_if_reset_channels(unsigned long arg);
#else /* MY_DEF_HERE */
#if !(defined CONFIG_MV_PHONE_USE_IRQ_PROCESSING) && !(defined CONFIG_MV_PHONE_USE_FIQ_PROCESSING)
static void tdm_if_pcm_rx_process(unsigned long arg);
static void tdm_if_pcm_tx_process(unsigned long arg);
#else
static inline void tdm_if_pcm_rx_process(void);
static inline void tdm_if_pcm_tx_process(void);
#endif
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
/* Globals */
static struct mv_phone_dev *priv;
static DECLARE_TASKLET(tdm2c_if_rx_tasklet, tdm2c_if_pcm_rx_process, 0);
static DECLARE_TASKLET(tdmmc_if_rx_tasklet, tdmmc_if_pcm_rx_process, 0);
static DECLARE_TASKLET(tdm2c_if_tx_tasklet, tdm2c_if_pcm_tx_process, 0);
static DECLARE_TASKLET(tdmmc_if_tx_tasklet, tdmmc_if_pcm_tx_process, 0);
static DECLARE_TASKLET(tdm2c_if_reset_tasklet, tdm2c_if_reset_channels, 0);

/* Statistic printout in userspace via /proc/tdm */
static int mv_phone_status_show(struct seq_file *m, void *v)
{
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	struct mv_phone_extended_stats tdm_ext_stats;
#else /* MY_DEF_HERE */
/* TDM SW Reset */
#ifdef CONFIG_MV_TDM2C_SUPPORT
static void tdm2c_if_stop_channels(unsigned long args);
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	seq_printf(m, "tdm_init:	%u\n", priv->tdm_init);
	seq_printf(m, "rx_miss:		%u\n", priv->rx_miss);
	seq_printf(m, "tx_miss:		%u\n", priv->tx_miss);
	seq_printf(m, "rx_over:		%u\n", priv->rx_over);
	seq_printf(m, "tx_under:	%u\n", priv->tx_under);
#else /* MY_DEF_HERE */
/* Module */
static int tdm_if_module_init(void);
static void tdm_if_module_exit(void);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
/* Globals */
#if !(defined CONFIG_MV_PHONE_USE_IRQ_PROCESSING) && !(defined CONFIG_MV_PHONE_USE_FIQ_PROCESSING)
static DECLARE_TASKLET(tdm_if_rx_tasklet, tdm_if_pcm_rx_process, 0);
static DECLARE_TASKLET(tdm_if_tx_tasklet, tdm_if_pcm_tx_process, 0);
#endif
#ifdef CONFIG_MV_TDM2C_SUPPORT
static DECLARE_TASKLET(tdm2c_if_stop_tasklet, tdm2c_if_stop_channels, 0);
#endif
static DEFINE_SPINLOCK(tdm_if_lock);
static u8 *rx_buff, *tx_buff;
static char irqnr[3];
static u32 rx_miss, tx_miss;
static u32 rx_over, tx_under;
static struct proc_dir_entry *tdm_stats;
static int pcm_enable;
static int irq_init;
static int tdm_init;
static int buff_size;
static u16 test_enable;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	if (!priv->use_tdm_ext_stats)
		return 0;

#else /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	tdm2c_ext_stats_get(&tdm_ext_stats);

	seq_puts(m, "\nTDM Extended Statistics:\n");
	seq_printf(m, "int_rx_count	= %u\n", tdm_ext_stats.int_rx_count);
	seq_printf(m, "int_tx_count	= %u\n", tdm_ext_stats.int_tx_count);
	seq_printf(m, "int_rx0_count	= %u\n", tdm_ext_stats.int_rx0_count);
	seq_printf(m, "int_tx0_count	= %u\n", tdm_ext_stats.int_tx0_count);
	seq_printf(m, "int_rx1_count	= %u\n", tdm_ext_stats.int_rx1_count);
	seq_printf(m, "int_tx1_count	= %u\n", tdm_ext_stats.int_tx1_count);
	seq_printf(m, "int_rx0_miss	= %u\n", tdm_ext_stats.int_rx0_miss);
	seq_printf(m, "int_tx0_miss	= %u\n", tdm_ext_stats.int_tx0_miss);
	seq_printf(m, "int_tx1_miss	= %u\n", tdm_ext_stats.int_rx1_miss);
	seq_printf(m, "int_tx1_miss	= %u\n", tdm_ext_stats.int_tx1_miss);
	seq_printf(m, "pcm_restart_count= %u\n", tdm_ext_stats.pcm_restart_count);
	seq_printf(m, "pcm_stop_fail	= %u\n", priv->pcm_stop_fail);
#else /* MY_DEF_HERE */
static u32 pcm_stop_fail;
#endif
#ifdef CONFIG_MV_TDM2C_SUPPORT
static int pcm_stop_flag;
static int pcm_stop_status;
static u32 pcm_start_stop_state;
static u32 is_pcm_stopping;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)

#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	return 0;
}
#else /* MY_DEF_HERE */
static u32 mv_tdm_unit_type;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
static int mv_phone_status_open(struct inode *inode, struct file *file)
#else /* MY_DEF_HERE */
/* Get TDM unit interrupt number */
static u32 mv_phone_get_irq(int id)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	return single_open(file, mv_phone_status_show, PDE_DATA(inode));
#else /* MY_DEF_HERE */
	return priv->irq[id];
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static const struct file_operations mv_phone_operations = {
	.open		= mv_phone_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* TAL callbacks */

/* PCM start */
static void tdm2c_if_pcm_start(void)
#else /* MY_DEF_HERE */
/* Get TDM unit type. */
static enum mv_phone_unit_type mv_phone_get_unit_type(void)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	unsigned long flags;
	u32 max_poll = 0;

	spin_lock_irqsave(&priv->lock, flags);

	if (priv->pcm_enable) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return;
	}

	priv->pcm_enable = true;
	if (!priv->pcm_is_stopping) {
		priv->pcm_stop_flag = false;
		priv->pcm_stop_status = false;
		priv->pcm_start_stop_state = 0;
		priv->rx_buff = NULL;
		priv->tx_buff = NULL;
		tdm2c_pcm_start();
	} else {
		priv->pcm_start_stop_state++;
		while (priv->pcm_is_stopping && max_poll < MV_TDM_STOP_POLLING_TIMEOUT) {
			spin_unlock_irqrestore(&priv->lock, flags);
			mdelay(1);
			max_poll++;
			spin_lock_irqsave(&priv->lock, flags);
		}

		if (priv->pcm_is_stopping) {
			/* Issue found or timeout */
			if (tdm2c_pcm_stop_int_miss())
				dev_dbg(priv->dev, "pcm stop issue found\n");
			else
				dev_dbg(priv->dev, "pcm stop timeout\n");

#else /* MY_DEF_HERE */
	if (!mv_phone_enabled)
		return MV_TDM_UNIT_NONE;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
			priv->pcm_is_stopping = false;
			priv->pcm_stop_flag = false;
			priv->pcm_stop_status = false;
			priv->pcm_start_stop_state = 0;
			priv->rx_buff = NULL;
			priv->tx_buff = NULL;
			tdm2c_pcm_start();
		} else {
			dev_dbg(priv->dev, "pcm_start_stop_state(%d), max_poll=%d\n",
				priv->pcm_start_stop_state, max_poll);
		}
	}
#else /* MY_DEF_HERE */
	return priv->tdm_type;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	spin_unlock_irqrestore(&priv->lock, flags);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static void tdmmc_if_pcm_start(void)
#else /* MY_DEF_HERE */
/* Initialize the TDM subsystem. */
static int mv_phone_init(struct mv_phone_params *tdm_params)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
	struct mv_phone_data hal_data;
	u8 spi_mode = 0;
	int ret;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	if (priv->pcm_enable) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return;
	}

	priv->pcm_enable = true;
	priv->rx_buff = NULL;
	priv->tx_buff = NULL;
	tdmmc_pcm_start();

	spin_unlock_irqrestore(&priv->lock, flags);
}

/* PCM stop */
static void tdm2c_if_pcm_stop(void)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	if (!priv->pcm_enable) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return;
	}

	priv->pcm_enable = false;
	if (!priv->pcm_is_stopping) {
		priv->pcm_is_stopping = true;
		tdm2c_pcm_stop();
	} else {
		priv->pcm_start_stop_state--;
		dev_dbg(priv->dev, "pcm_start_stop_state(%d)\n",
			priv->pcm_start_stop_state);
	}

	spin_unlock_irqrestore(&priv->lock, flags);
}

static void tdmmc_if_pcm_stop(void)
{
	unsigned long flags;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	spin_lock_irqsave(&priv->lock, flags);

	if (!priv->pcm_enable) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return;
	}

	priv->pcm_enable = false;
	tdmmc_pcm_stop();

	spin_unlock_irqrestore(&priv->lock, flags);
}

/* TDM low-level initialization */
static int tdm_hw_init(struct mv_phone_params *tdm_params)
{
	enum mv_phone_frame_ts frame_ts;
	int ret;
#else /* MY_DEF_HERE */
	hal_data.spi_mode = spi_mode;
#endif /* MY_DEF_HERE */

	switch (priv->pclk_freq_mhz) {
	case 8:
#if defined(MY_DEF_HERE)
		frame_ts = MV_FRAME_128TS;
#else /* MY_DEF_HERE */
		hal_data.frame_ts = MV_FRAME_128TS;
#endif /* MY_DEF_HERE */
		break;
	case 4:
#if defined(MY_DEF_HERE)
		frame_ts = MV_FRAME_64TS;
#else /* MY_DEF_HERE */
		hal_data.frame_ts = MV_FRAME_64TS;
#endif /* MY_DEF_HERE */
		break;
	case 2:
#if defined(MY_DEF_HERE)
		frame_ts = MV_FRAME_32TS;
#else /* MY_DEF_HERE */
		hal_data.frame_ts = MV_FRAME_32TS;
#endif /* MY_DEF_HERE */
		break;
	default:
#if defined(MY_DEF_HERE)
		frame_ts = MV_FRAME_128TS;
#else /* MY_DEF_HERE */
		hal_data.frame_ts = MV_FRAME_128TS;
#endif /* MY_DEF_HERE */
		break;
	}

	switch (priv->tdm_type) {
	case MV_TDM_UNIT_TDM2C:
#if defined(MY_DEF_HERE)
		ret = tdm2c_init(priv->tdm_base, priv->dev, tdm_params,
				 frame_ts, priv->tdm2c_spi_mode,
				 priv->use_pclk_external);

		/* Soft reset to PCM I/F */
		tdm2c_pcm_if_reset();

#else /* MY_DEF_HERE */
		ret = tdm2c_init(priv->tdm_base, priv->dev, tdm_params, &hal_data);
#endif /* MY_DEF_HERE */
		break;
	case MV_TDM_UNIT_TDMMC:
#if defined(MY_DEF_HERE)
		ret = tdmmc_init(priv->tdm_base, priv->dev, tdm_params,
				 frame_ts, priv->tdmmc_ip_ver);

#else /* MY_DEF_HERE */
		ret = tdmmc_init(priv->tdm_base, priv->dev, tdm_params, &hal_data);
#endif /* MY_DEF_HERE */
		/* Issue SLIC reset */
		ret |= tdmmc_reset_slic();
#if defined(MY_DEF_HERE)

		/* WA to stop the MCDMA gracefully after tdmmc initialization */
		tdmmc_if_pcm_stop();

#endif /* MY_DEF_HERE */
		break;
	default:
		dev_err(&priv->parent->dev, "%s: undefined TDM type\n",
			__func__);
		return -EINVAL;
	}

	priv->tdm_params = tdm_params;

	return ret;
}

#if defined(MY_DEF_HERE)
/* Main TDM initialization routine */
#else /* MY_DEF_HERE */
static int proc_tdm_status_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_MV_TDM_EXT_STATS
	struct mv_phone_extended_stats tdm_ext_stats;
#endif

	seq_printf(m, "tdm_init:	%u\n", tdm_init);
	seq_printf(m, "rx_miss:		%u\n", rx_miss);
	seq_printf(m, "tx_miss:		%u\n", tx_miss);
	seq_printf(m, "rx_over:		%u\n", rx_over);
	seq_printf(m, "tx_under:	%u\n", tx_under);

#ifdef CONFIG_MV_TDM_EXT_STATS
	tdm2c_ext_stats_get(&tdm_ext_stats);

	seq_puts(m, "\nTDM Extended Statistics:\n");
	seq_printf(m, "int_rx_count	= %u\n", tdm_ext_stats.int_rx_count);
	seq_printf(m, "int_tx_count	= %u\n", tdm_ext_stats.int_tx_count);
	seq_printf(m, "int_rx0_count	= %u\n", tdm_ext_stats.int_rx0_count);
	seq_printf(m, "int_tx0_count	= %u\n", tdm_ext_stats.int_tx0_count);
	seq_printf(m, "int_rx1_count	= %u\n", tdm_ext_stats.int_rx1_count);
	seq_printf(m, "int_tx1_count	= %u\n", tdm_ext_stats.int_tx1_count);
	seq_printf(m, "int_rx0_miss	= %u\n", tdm_ext_stats.int_rx0_miss);
	seq_printf(m, "int_tx0_miss	= %u\n", tdm_ext_stats.int_tx0_miss);
	seq_printf(m, "int_tx1_miss	= %u\n", tdm_ext_stats.int_rx1_miss);
	seq_printf(m, "int_tx1_miss	= %u\n", tdm_ext_stats.int_tx1_miss);
	seq_printf(m, "pcm_restart_count= %u\n", tdm_ext_stats.pcm_restart_count);
	seq_printf(m, "pcm_stop_fail	= %u\n", pcm_stop_fail);
#endif
	return 0;
}

static int proc_tdm_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_tdm_status_show, PDE_DATA(inode));
}

static const struct file_operations proc_tdm_operations = {
	.open		= proc_tdm_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static void tdm_if_unit_type_set(u32 tdm_unit)
{
	unsigned long flags;

	spin_lock_irqsave(&tdm_if_lock, flags);

	mv_tdm_unit_type = tdm_unit;
	spin_unlock_irqrestore(&tdm_if_lock, flags);
}

static u32 tdm_if_unit_type_get(void)
{
	return mv_tdm_unit_type;
}

#endif /* MY_DEF_HERE */
int tdm_if_init(struct tal_params *tal_params)
{
	struct mv_phone_params tdm_params;
#if defined(MY_DEF_HERE)
	int i, irqs_requested, ret;
#else /* MY_DEF_HERE */
	int ret;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (priv->tdm_init) {
#else /* MY_DEF_HERE */
	if (tdm_init) {
#endif /* MY_DEF_HERE */
		dev_warn(priv->dev, "Marvell Telephony Driver already started...\n");
		return 0;
	}

	dev_info(priv->dev, "Loading Marvell Telephony Driver\n");

	if (!tal_params) {
		dev_err(priv->dev, "%s: bad parameters\n", __func__);
		return -EINVAL;

	}

#if defined(MY_DEF_HERE)
	/* Reset operation flags */
	priv->tdm_init = false;
	priv->pcm_enable = false;
	priv->pcm_is_stopping = false;
	priv->pcm_stop_flag = false;
	priv->pcm_stop_status = false;
#else /* MY_DEF_HERE */
	/* Reset globals */
	rx_buff = tx_buff = NULL;
	irq_init = 0;
	tdm_init = 0;

#ifdef CONFIG_MV_TDM2C_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C) {

		pcm_enable = 0;
		is_pcm_stopping = 0;
		pcm_stop_flag = 0;
		pcm_stop_status = 0;
	}
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDMMC)
		pcm_enable = 1;
#endif

#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	priv->pcm_stop_fail = 0;
#else /* MY_DEF_HERE */
	pcm_stop_fail = 0;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)

#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
	/* Calculate Rx/Tx buffer size(use in callbacks) */
#if defined(MY_DEF_HERE)
	priv->buff_size = (tal_params->pcm_format * tal_params->total_lines * 80 *
#else /* MY_DEF_HERE */
	buff_size = (tal_params->pcm_format * tal_params->total_lines * 80 *
#endif /* MY_DEF_HERE */
			(tal_params->sampling_period/MV_TDM_BASE_SAMPLING_PERIOD));

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	/* Extract TDM irq number */
	irqnr[0] = mv_phone_get_irq(0);
#if (!(defined(CONFIG_MACH_ARMADA_38X) || defined(CONFIG_MACH_ARMADA_XP)))
	irqnr[1] = mv_phone_get_irq(1);
	irqnr[2] = mv_phone_get_irq(2);
#endif

#endif /* MY_DEF_HERE */
	/* Assign TDM parameters */
	memcpy(&tdm_params, tal_params, sizeof(struct mv_phone_params));

#if defined(MY_DEF_HERE)
	/* TDM hardware initialization */
	ret = tdm_hw_init(&tdm_params);
#else /* MY_DEF_HERE */
	/* TDM init */
	ret = mv_phone_init(&tdm_params);
#endif /* MY_DEF_HERE */
	if (ret) {
#if defined(MY_DEF_HERE)
		dev_err(priv->dev, "%s: TDM initialization failed\n", __func__);
#else /* MY_DEF_HERE */
		dev_err(priv->dev, "%s: Error, TDM initialization failed !!!\n", __func__);
#endif /* MY_DEF_HERE */
		return ret;
	}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	tdm_init = 1;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Create TDM procfs statistics */
	priv->tdm_stats = proc_mkdir("tdm", NULL);
	if (priv->tdm_stats) {
		if (!proc_create("tdm_stats", S_IRUGO,
				 priv->tdm_stats, &mv_phone_operations))
			return -ENOMEM;
#else /* MY_DEF_HERE */
	/* Soft reset to PCM I/F */
#ifdef CONFIG_MV_TDM2C_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C)
		tdm2c_pcm_if_reset();
#endif

	/* Register TDM interrupt */
#ifdef CONFIG_MV_PHONE_USE_FIQ_PROCESSING
	ret = request_fiq(irqnr[0], tdm_if_isr, 0x0, "tdm", NULL);
	if (ret) {
		dev_err(priv->dev, "%s: Failed to connect fiq(%d)\n", __func__, irqnr[0]);
		return ret;
#endif /* MY_DEF_HERE */
	}
#if defined(MY_DEF_HERE)

	/* Register TDM interrupts */
	irqs_requested = 0;
	for (i = 0; i < priv->irq_count; i++) {
		ret = request_irq(priv->irq[i], tdm_if_isr, 0x0, "tdm", NULL);
#else /* MY_DEF_HERE */
#else /* CONFIG_MV_PHONE_USE_FIQ_PROCESSING */
	ret = request_irq(irqnr[0], tdm_if_isr, 0x0, "tdm", NULL);
#endif /* MY_DEF_HERE */
	if (ret) {
#if defined(MY_DEF_HERE)
			dev_err(priv->dev, "%s: Failed to connect irq(%d)\n",
				__func__, priv->irq[i]);
			goto err_irq;
#else /* MY_DEF_HERE */
		dev_err(priv->dev, "%s: Failed to connect irq(%d)\n", __func__, irqnr[0]);
		return ret;
#endif /* MY_DEF_HERE */
	}
#if defined(MY_DEF_HERE)
		irqs_requested++;
#else /* MY_DEF_HERE */
#if (!(defined(CONFIG_MACH_ARMADA_38X) || defined(CONFIG_MACH_ARMADA_XP)))
	/* XXX add proper error path */
	ret = request_irq(irqnr[1], tdm_if_isr, 0x0, "tdm", NULL);
	if (ret) {
		dev_err(priv->dev, "%s: Failed to connect irq(%d)\n", __func__, irqnr[1]);
		return ret;
#endif /* MY_DEF_HERE */
	}
#if defined(MY_DEF_HERE)

	priv->tdm_init = true;

	return 0;

err_irq:
	for (i = 0; i < irqs_requested; i++)
		free_irq(priv->irq[i], NULL);

#else /* MY_DEF_HERE */
	ret = request_irq(irqnr[2], tdm_if_isr, 0x0, "tdm", NULL);
	if (ret) {
		dev_err(priv->dev, "%s: Failed to connect irq(%d)\n", __func__, irqnr[2]);
#endif /* MY_DEF_HERE */
		return ret;
#if defined(MY_DEF_HERE)
}

/* Disable TDM2C PCM */
void tdm2c_pcm_disable(void)
{
	u32 max_poll = 0;
#else /* MY_DEF_HERE */
	}
#endif
#endif /* CONFIG_MV_PHONE_USE_FIQ_PROCESSING */
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	tdm2c_if_pcm_stop();
#else /* MY_DEF_HERE */
	irq_init = 1;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	while (priv->pcm_is_stopping && (max_poll < MV_TDM_STOP_POLLING_TIMEOUT)) {
		mdelay(1);
		max_poll++;
#else /* MY_DEF_HERE */
	/* Create TDM procFS statistics */
	tdm_stats = proc_mkdir("tdm", NULL);
	if (tdm_stats != NULL) {
		if (!proc_create("tdm_stats", S_IRUGO, tdm_stats, &proc_tdm_operations))
			return -ENOMEM;
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	if (max_poll >= MV_TDM_STOP_POLLING_TIMEOUT)
		dev_warn(priv->dev, "\n%s: Channels disabling timeout (%dms)\n",
			 __func__, MV_TDM_STOP_POLLING_TIMEOUT);
#else /* MY_DEF_HERE */
	/* WA to stop the MCDMA gracefully after commUnit initialization */
#ifdef CONFIG_MV_TDMMC_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDMMC)
		tdm_if_pcm_stop();
#endif
	return 0;
}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
/* Main TDM deinitialization routine */
#endif /* MY_DEF_HERE */
void tdm_if_exit(void)
{
#if defined(MY_DEF_HERE)
	int i;

#endif /* MY_DEF_HERE */
	/* Check if already stopped */
#if defined(MY_DEF_HERE)
	if (!priv->pcm_enable && !priv->tdm_init)
#else /* MY_DEF_HERE */
	if (!irq_init && !pcm_enable && !tdm_init)
#endif /* MY_DEF_HERE */
		return;

	/* Stop PCM channels */
#if defined(MY_DEF_HERE)
	if (priv->pcm_enable) {
		switch (priv->tdm_type) {
		case MV_TDM_UNIT_TDM2C:
			tdm2c_pcm_disable();
			break;
		case MV_TDM_UNIT_TDMMC:
			tdmmc_if_pcm_stop();
			break;
		default:
			dev_err(&priv->parent->dev, "%s: undefined TDM type\n",
				__func__);
#else /* MY_DEF_HERE */
	if (pcm_enable)
		tdm_if_pcm_stop();

#ifdef CONFIG_MV_TDM2C_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C) {
			u32 max_poll = 0;

			while ((is_pcm_stopping != 0) && (max_poll < 20)) {
				mdelay(1);
				max_poll++;
			}

			if (max_poll >= 20)
				dev_warn(priv->dev, "%s: waiting for pcm channels to stop exceeded 20ms\n", __func__);
#endif /* MY_DEF_HERE */
		}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif

	if (irq_init) {
		/* Release interrupt */
#ifndef CONFIG_MV_PHONE_USE_FIQ_PROCESSING
		free_irq(irqnr[0], NULL);
#if (!(defined(CONFIG_MACH_ARMADA_38X) || defined(CONFIG_MACH_ARMADA_XP)))
		free_irq(irqnr[1], NULL);
		free_irq(irqnr[2], NULL);
#endif
#else /* !CONFIG_MV_PHONE_USE_FIQ_PROCESSING */
		free_fiq(irqnr[0], NULL);
#endif /* !CONFIG_MV_PHONE_USE_FIQ_PROCESSING */
		irq_init = 0;
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	/* Disable TDM and release resources */
	if (priv->tdm_init) {
		switch (priv->tdm_type) {
		case MV_TDM_UNIT_TDM2C:
#else /* MY_DEF_HERE */
	if (tdm_init) {
#ifdef CONFIG_MV_TDM2C_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C)
#endif /* MY_DEF_HERE */
			tdm2c_release();
#if defined(MY_DEF_HERE)
			break;
		case MV_TDM_UNIT_TDMMC:
#else /* MY_DEF_HERE */
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDMMC)
#endif /* MY_DEF_HERE */
			tdmmc_release();
#if defined(MY_DEF_HERE)
			break;
		default:
			dev_err(&priv->parent->dev, "%s: undefined TDM type\n",
				__func__);
		}

#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
		/* Remove proc directory & entries */
#if defined(MY_DEF_HERE)
		remove_proc_entry("tdm_stats", priv->tdm_stats);
#else /* MY_DEF_HERE */
		remove_proc_entry("tdm_stats", tdm_stats);
#endif /* MY_DEF_HERE */
		remove_proc_entry("tdm", NULL);

#if defined(MY_DEF_HERE)
		/* Release interrupt */
		for (i = 0; i < priv->irq_count; i++)
			free_irq(priv->irq[i], NULL);

		priv->tdm_init = false;
#else /* MY_DEF_HERE */
		tdm_init = 0;
#endif /* MY_DEF_HERE */
	}
}

#if defined(MY_DEF_HERE)
static int tdm_if_control(int cmd, void *arg)
#else /* MY_DEF_HERE */
static void tdm_if_pcm_start(void)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	switch (cmd) {
	case TDM_DEV_TDM_TEST_MODE_ENABLE:
		priv->test_enable = true;
		break;
#else /* MY_DEF_HERE */
	unsigned long flags;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	case TDM_DEV_TDM_TEST_MODE_DISABLE:
		priv->test_enable = false;
		break;

	default:
		return -EINVAL;
	};

	return 0;
}
#else /* MY_DEF_HERE */
	spin_lock_irqsave(&tdm_if_lock, flags);
	if (!pcm_enable) {
		pcm_enable = 1;
#ifdef CONFIG_MV_TDM2C_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C) {
			u32 max_poll = 0;

			if (is_pcm_stopping == 0) {
				pcm_stop_flag = 0;
				pcm_stop_status = 0;
				pcm_start_stop_state = 0;
				rx_buff = tx_buff = NULL;
				tdm2c_pcm_start();
			} else {
				pcm_start_stop_state++;
				while (is_pcm_stopping && max_poll < TDM_STOP_MAX_POLLING_TIME) {
					spin_unlock_irqrestore(&tdm_if_lock, flags);
					mdelay(1);
					max_poll++;
					spin_lock_irqsave(&tdm_if_lock, flags);
				}

				if (is_pcm_stopping) {
					/* Issue found or timeout */
					if (tdm2c_pcm_stop_int_miss())
						dev_dbg(priv->dev, "pcm stop issue found\n");
					else
						dev_dbg(priv->dev, "pcm stop timeout\n");

					is_pcm_stopping = 0;
					pcm_stop_flag = 0;
					pcm_stop_status = 0;
					pcm_start_stop_state = 0;
					rx_buff = tx_buff = NULL;
					tdm2c_pcm_start();
				} else {
					dev_dbg(priv->dev, "pcm_start_stop_state(%d), max_poll=%d\n",
						pcm_start_stop_state, max_poll);
				}
			}
		}
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDMMC) {
			rx_buff = tx_buff = NULL;
			tdmmc_pcm_start();
		}
#endif
	}
	spin_unlock_irqrestore(&tdm_if_lock, flags);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
static int tdm2c_if_write(u8 *buffer, int size)
{
	if (priv->test_enable)
		return tdm2c_tx(buffer);

	return 0;
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static int tdmmc_if_write(u8 *buffer, int size)
#else /* MY_DEF_HERE */
static void tdm_if_pcm_stop(void)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	if (priv->test_enable)
		return tdmmc_tx(buffer);
#else /* MY_DEF_HERE */
	unsigned long flags;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	return 0;
}

static void tdm_if_stats_get(struct tal_stats *tdm_if_stats)
{
	if (!priv->tdm_init)
		return;

	tdm_if_stats->tdm_init = priv->tdm_init;
	tdm_if_stats->rx_miss = priv->rx_miss;
	tdm_if_stats->tx_miss = priv->tx_miss;
	tdm_if_stats->rx_over = priv->rx_over;
	tdm_if_stats->tx_under = priv->tx_under;
#if defined(MY_DEF_HERE)

	if (priv->use_tdm_ext_stats)
		tdm2c_ext_stats_get(&tdm_if_stats->tdm_ext_stats);
#else /* MY_DEF_HERE */
#ifdef CONFIG_MV_TDM_EXT_STATS
	tdm2c_ext_stats_get(&tdm_if_stats->tdm_ext_stats);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	spin_lock_irqsave(&tdm_if_lock, flags);
	if (pcm_enable) {
		pcm_enable = 0;
#ifdef CONFIG_MV_TDM2C_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C) {
			if (is_pcm_stopping == 0) {
				is_pcm_stopping = 1;
				tdm2c_pcm_stop();
			} else {
				pcm_start_stop_state--;
				dev_dbg(priv->dev, "pcm_start_stop_state(%d)\n",
					pcm_start_stop_state);
			}
		}
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDMMC)
			tdmmc_pcm_stop();
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	}
	spin_unlock_irqrestore(&tdm_if_lock, flags);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static struct tal_if tdm2c_if = {
	.pcm_start	= tdm2c_if_pcm_start,
	.pcm_stop	= tdm2c_if_pcm_stop,
	.init		= tdm_if_init,
	.exit		= tdm_if_exit,
	.control	= tdm_if_control,
	.write		= tdm2c_if_write,
	.stats_get	= tdm_if_stats_get,
};

static struct tal_if tdmmc_if = {
	.pcm_start	= tdmmc_if_pcm_start,
	.pcm_stop	= tdmmc_if_pcm_stop,
	.init		= tdm_if_init,
	.exit		= tdm_if_exit,
	.control	= tdm_if_control,
	.write		= tdmmc_if_write,
	.stats_get	= tdm_if_stats_get,
};

/* Interrupt handling and tasklet callbacks */

/* Common interrupt top-half handler */
#endif /* MY_DEF_HERE */
static irqreturn_t tdm_if_isr(int irq, void *dev_id)
{
	struct mv_phone_intr_info tdm_int_info;
#if defined(MY_DEF_HERE)
	struct tasklet_struct *tdm_rx_tasklet = NULL;
	struct tasklet_struct *tdm_tx_tasklet = NULL;
#endif /* MY_DEF_HERE */
	u32 int_type;
	int ret = 0;

	/* Extract interrupt information from low level ISR */
#if defined(MY_DEF_HERE)
	switch (priv->tdm_type) {
	case MV_TDM_UNIT_TDM2C:
#else /* MY_DEF_HERE */
#ifdef CONFIG_MV_TDM2C_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C)
#endif /* MY_DEF_HERE */
		ret = tdm2c_intr_low(&tdm_int_info);
#if defined(MY_DEF_HERE)
		tdm_rx_tasklet = &tdm2c_if_rx_tasklet;
		tdm_tx_tasklet = &tdm2c_if_tx_tasklet;
		break;
	case MV_TDM_UNIT_TDMMC:
		tdmmc_intr_low(&tdm_int_info);
		tdm_rx_tasklet = &tdmmc_if_rx_tasklet;
		tdm_tx_tasklet = &tdmmc_if_tx_tasklet;
		break;
	default:
		dev_err(&priv->parent->dev, "%s: undefined TDM type\n", __func__);
		return IRQ_NONE;
	}
#else /* MY_DEF_HERE */
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDMMC)
		ret = tdmmc_intr_low(&tdm_int_info);
#endif
#endif /* MY_DEF_HERE */

	int_type = tdm_int_info.int_type;
#if defined(MY_DEF_HERE)

	/* Nothing to do - return */
	if (int_type == MV_EMPTY_INT)
		return IRQ_HANDLED;
#else /* MY_DEF_HERE */
	/*device_id = tdm_int_info.cs;*/
#endif /* MY_DEF_HERE */

	/* Handle ZSI interrupts */
	if (mv_phone_get_slic_board_type() == MV_BOARD_SLIC_ZSI_ID)
		zarlink_if_zsi_interrupt();
	/* Handle ISI interrupts */
	else if (mv_phone_get_slic_board_type() == MV_BOARD_SLIC_ISI_ID)
		silabs_if_isi_interrupt();

#if defined(MY_DEF_HERE)
	if (ret && !priv->pcm_stop_status)	{
		priv->pcm_stop_status = true;
#else /* MY_DEF_HERE */
	/* Nothing to do - return */
	if (int_type == MV_EMPTY_INT)
		goto out;

#ifdef CONFIG_MV_TDM2C_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C) {
		if ((ret == -1) && (pcm_stop_status == 0))	{
			pcm_stop_status = 1;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
		/* If Rx/Tx tasklets are already scheduled, let them do the work */
		if (!priv->rx_buff && !priv->tx_buff) {
#else /* MY_DEF_HERE */
			/* If Rx/Tx tasklets already scheduled, let them do the work. */
			if ((!rx_buff) && (!tx_buff)) {
#endif /* MY_DEF_HERE */
				dev_dbg(priv->dev, "Stopping the TDM\n");
#if defined(MY_DEF_HERE)
			tdm2c_if_pcm_stop();
			priv->pcm_stop_flag = false;
			tasklet_hi_schedule(&tdm2c_if_reset_tasklet);
#else /* MY_DEF_HERE */
				tdm_if_pcm_stop();
				pcm_stop_flag = 0;
				tasklet_hi_schedule(&tdm2c_if_stop_tasklet);
#endif /* MY_DEF_HERE */
			} else {
#if defined(MY_DEF_HERE)
			dev_dbg(priv->dev, "Tasklet already runningstop_flag\n");
			priv->pcm_stop_flag = true;
#else /* MY_DEF_HERE */
				dev_dbg(priv->dev, "Some tasklet is running, mark pcm_stop_flag\n");
				pcm_stop_flag = 1;
#endif /* MY_DEF_HERE */
			}
		}

		/* Restarting PCM, skip Rx/Tx handling */
#if defined(MY_DEF_HERE)
	if (priv->pcm_stop_status)
#else /* MY_DEF_HERE */
		if (pcm_stop_status)
#endif /* MY_DEF_HERE */
			goto skip_rx_tx;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	}
#endif
#endif /* MY_DEF_HERE */

	/* Support multiple interrupt handling */
	/* RX interrupt */
	if (int_type & MV_RX_INT) {
#if defined(MY_DEF_HERE)
		if (priv->rx_buff) {
			priv->rx_miss++;
			dev_dbg(priv->dev, "%s: Rx buffer not ready\n", __func__);
#else /* MY_DEF_HERE */
		if (rx_buff != NULL) {
			rx_miss++;
			dev_dbg(priv->dev, "%s: Warning, missed Rx buffer processing !!!\n", __func__);
#endif /* MY_DEF_HERE */
		} else {
#if defined(MY_DEF_HERE)
			priv->rx_buff = tdm_int_info.tdm_rx_buff;
#else /* MY_DEF_HERE */
			rx_buff = tdm_int_info.tdm_rx_buff;
#if (defined CONFIG_MV_PHONE_USE_IRQ_PROCESSING) || (defined CONFIG_MV_PHONE_USE_FIQ_PROCESSING)
			dev_dbg(priv->dev, "%s: running Rx in ISR\n", __func__);
			tdm_if_pcm_rx_process();
#else
#endif /* MY_DEF_HERE */
			/* Schedule Rx processing within SOFT_IRQ context */
			dev_dbg(priv->dev, "%s: schedule Rx tasklet\n", __func__);
#if defined(MY_DEF_HERE)
			tasklet_hi_schedule(tdm_rx_tasklet);
#else /* MY_DEF_HERE */
			tasklet_hi_schedule(&tdm_if_rx_tasklet);
#endif
#endif /* MY_DEF_HERE */
		}
	}

	/* TX interrupt */
	if (int_type & MV_TX_INT) {
#if defined(MY_DEF_HERE)
		if (priv->tx_buff) {
			priv->tx_miss++;
			dev_dbg(priv->dev, "%s: Tx buffer not ready\n", __func__);
#else /* MY_DEF_HERE */
		if (tx_buff != NULL) {
			tx_miss++;
			dev_dbg(priv->dev, "%s: Warning, missed Tx buffer processing !!!\n", __func__);
#endif /* MY_DEF_HERE */
		} else {
#if defined(MY_DEF_HERE)
			priv->tx_buff = tdm_int_info.tdm_tx_buff;
#else /* MY_DEF_HERE */
			tx_buff = tdm_int_info.tdm_tx_buff;
#if (defined CONFIG_MV_PHONE_USE_IRQ_PROCESSING) || (defined CONFIG_MV_PHONE_USE_FIQ_PROCESSING)
			dev_dbg(priv->dev, "%s: running Tx in ISR\n", __func__);
			tdm_if_pcm_tx_process();
#else
#endif /* MY_DEF_HERE */
			/* Schedule Tx processing within SOFT_IRQ context */
			dev_dbg(priv->dev, "%s: schedule Tx tasklet\n", __func__);
#if defined(MY_DEF_HERE)
			tasklet_hi_schedule(tdm_tx_tasklet);
#else /* MY_DEF_HERE */
			tasklet_hi_schedule(&tdm_if_tx_tasklet);
#endif
#endif /* MY_DEF_HERE */
		}
	}

#if defined(MY_DEF_HERE)
// do nothing
#else /* MY_DEF_HERE */
#ifdef CONFIG_MV_TDM2C_SUPPORT
	if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C) {
#endif /* MY_DEF_HERE */
		/* TDM2CH PCM channels stop indication */
		if ((int_type & MV_CHAN_STOP_INT) && (tdm_int_info.data == 4)) {
#if defined(MY_DEF_HERE)
		dev_dbg(priv->dev, "%s: Received MV_CHAN_STOP_INT indication\n",
			__func__);
		priv->pcm_is_stopping = false;
		if (priv->pcm_start_stop_state) {
			dev_dbg(priv->dev, "%s: Resetting controller\n", __func__);
			priv->pcm_enable = false;
			/* Issue SW reset */
			tasklet_hi_schedule(&tdm2c_if_reset_tasklet);
#else /* MY_DEF_HERE */
			dev_dbg(priv->dev, "%s: Received MV_CHAN_STOP_INT indication\n", __func__);
			is_pcm_stopping = 0;
			if (pcm_start_stop_state) {
				dev_dbg(priv->dev, "%s: calling to tdm_if_pcm_start()\n", __func__);
				pcm_enable = 0;
				tdm_if_pcm_start();
			}
#endif /* MY_DEF_HERE */
		}
	}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
skip_rx_tx:
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif

#endif /* MY_DEF_HERE */
	/* PHONE interrupt, Lantiq specific */
#if defined(MY_DEF_HERE)
	if (int_type & MV_PHONE_INT)
#else /* MY_DEF_HERE */
	if (int_type & MV_PHONE_INT) {
		/* TBD */
#endif /* MY_DEF_HERE */
		drv_dxt_if_signal_interrupt();
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	}
#endif /* MY_DEF_HERE */

	/* ERROR interrupt */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	if (int_type & MV_ERROR_INT) {
#endif /* MY_DEF_HERE */
		if (int_type & MV_RX_ERROR_INT)
#if defined(MY_DEF_HERE)
		priv->rx_over++;
#else /* MY_DEF_HERE */
			rx_over++;
#endif /* MY_DEF_HERE */

		if (int_type & MV_TX_ERROR_INT)
#if defined(MY_DEF_HERE)
		priv->tx_under++;
#else /* MY_DEF_HERE */
			tx_under++;
	}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
out:
#endif /* MY_DEF_HERE */
	return IRQ_HANDLED;
}
#if defined(MY_DEF_HERE)

/* Rx tasklets */
static void tdm2c_if_pcm_rx_process(unsigned long arg)
#else /* MY_DEF_HERE */
#if (defined CONFIG_MV_PHONE_USE_IRQ_PROCESSING) || (defined CONFIG_MV_PHONE_USE_FIQ_PROCESSING)
static inline void tdm_if_pcm_rx_process(void)
#else
/* Rx tasklet */
static void tdm_if_pcm_rx_process(unsigned long arg)
#endif
#endif /* MY_DEF_HERE */
{
	unsigned long flags;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	u32 tdm_type;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (priv->pcm_enable) {
		if (!priv->rx_buff) {
#else /* MY_DEF_HERE */
	tdm_type = tdm_if_unit_type_get();
	if (pcm_enable) {
		if (rx_buff == NULL) {
#endif /* MY_DEF_HERE */
			dev_warn(priv->dev, "%s: Error, empty Rx processing\n", __func__);
			return;
		}
#if defined(MY_DEF_HERE)

#else /* MY_DEF_HERE */
		/* Fill TDM Rx aggregated buffer */
#if defined(MY_DEF_HERE)
		if (tdm2c_rx(priv->rx_buff) == 0)
			/* Dispatch Rx handler */
			tal_mmp_rx(priv->rx_buff, priv->buff_size);
#else /* MY_DEF_HERE */
		if (tdm_type == MV_TDM_UNIT_TDM2C) {
			if (tdm2c_rx(rx_buff) == 0)
				tal_mmp_rx(rx_buff, buff_size); /* Dispatch Rx handler */
#endif /* MY_DEF_HERE */
			else
#if defined(MY_DEF_HERE)
			dev_warn(priv->dev, "%s: Could not fill Rx buffer\n", __func__);
#else /* MY_DEF_HERE */
				dev_warn(priv->dev, "%s: could not fill Rx buffer\n", __func__);
		}
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
		if (tdm_type == MV_TDM_UNIT_TDMMC) {
			if (tdmmc_rx(rx_buff) == 0)
				tal_mmp_rx(rx_buff, buff_size); /* Dispatch Rx handler */
			else
				dev_warn(priv->dev, "%s: could not fill Rx buffer\n", __func__);
		}
#endif
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	spin_lock_irqsave(&priv->lock, flags);
	/* Clear Rx buff for next iteration */
	priv->rx_buff = NULL;
	spin_unlock_irqrestore(&priv->lock, flags);
#else /* MY_DEF_HERE */
	spin_lock_irqsave(&tdm_if_lock, flags);
	/* Clear rx_buff for next iteration */
	rx_buff = NULL;
	spin_unlock_irqrestore(&tdm_if_lock, flags);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (priv->pcm_stop_flag && !priv->tx_buff) {
#else /* MY_DEF_HERE */
#ifdef CONFIG_MV_TDM2C_SUPPORT
	if (tdm_type == MV_TDM_UNIT_TDM2C) {
		if ((pcm_stop_flag == 1) && !tx_buff) {
#endif /* MY_DEF_HERE */
			dev_dbg(priv->dev, "Stopping TDM from Rx tasklet\n");
#if defined(MY_DEF_HERE)
		tdm2c_if_pcm_stop();
		spin_lock_irqsave(&priv->lock, flags);
		priv->pcm_stop_flag = false;
		spin_unlock_irqrestore(&priv->lock, flags);
		tasklet_hi_schedule(&tdm2c_if_reset_tasklet);
#else /* MY_DEF_HERE */
			tdm_if_pcm_stop();
			spin_lock_irqsave(&tdm_if_lock, flags);
			pcm_stop_flag = 0;
			spin_unlock_irqrestore(&tdm_if_lock, flags);
			tasklet_hi_schedule(&tdm2c_if_stop_tasklet);
		}
#endif /* MY_DEF_HERE */
	}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static void tdmmc_if_pcm_rx_process(unsigned long arg)
#else /* MY_DEF_HERE */
#if (defined CONFIG_MV_PHONE_USE_IRQ_PROCESSING) || (defined CONFIG_MV_PHONE_USE_FIQ_PROCESSING)
static inline void tdm_if_pcm_tx_process(void)
#else
/* Tx tasklet */
static void tdm_if_pcm_tx_process(unsigned long arg)
#endif
#endif /* MY_DEF_HERE */
{
	unsigned long flags;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	u32 tdm_type;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (priv->pcm_enable) {
		if (!priv->rx_buff) {
			dev_warn(priv->dev, "%s: Error, empty Rx processing\n", __func__);
			return;
		}

		if (tdmmc_rx(priv->rx_buff) == 0)
			/* Dispatch Rx handler */
			tal_mmp_rx(priv->rx_buff, priv->buff_size);
		else
			dev_warn(priv->dev, "%s: could not fill Rx buffer\n", __func__);
	}

	spin_lock_irqsave(&priv->lock, flags);
	/* Clear priv->rx_buff for next iteration */
	priv->rx_buff = NULL;
	spin_unlock_irqrestore(&priv->lock, flags);
}

/* Tx tasklets */
static void tdm2c_if_pcm_tx_process(unsigned long arg)
{
	unsigned long flags;
#else /* MY_DEF_HERE */
	tdm_type = tdm_if_unit_type_get();
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (priv->pcm_enable) {
		if (!priv->tx_buff) {
#else /* MY_DEF_HERE */
	if (pcm_enable) {
		if (tx_buff == NULL) {
#endif /* MY_DEF_HERE */
			dev_warn(priv->dev, "%s: Error, empty Tx processing\n", __func__);
			return;
		}

		/* Dispatch Tx handler */
#if defined(MY_DEF_HERE)
		tal_mmp_tx(priv->tx_buff, priv->buff_size);
#else /* MY_DEF_HERE */
		tal_mmp_tx(tx_buff, buff_size);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
		if (!priv->test_enable) {
#else /* MY_DEF_HERE */
		if (test_enable == 0) {
			/* Fill Tx aggregated buffer */
#if defined(MY_DEF_HERE)
			if (tdm2c_tx(priv->tx_buff) != 0)
				dev_warn(priv->dev, "%s: Could not fill Tx buffer\n", __func__);
#else /* MY_DEF_HERE */
			if (tdm_type == MV_TDM_UNIT_TDM2C) {
				if (tdm2c_tx(tx_buff) != 0)
					dev_warn(priv->dev, "%s: could not fill Tx buffer\n", __func__);
			}
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
			if (tdm_type == MV_TDM_UNIT_TDMMC) {
				if (tdmmc_tx(tx_buff) != 0)
					dev_warn(priv->dev, "%s: could not fill Tx buffer\n", __func__);
			}
#endif
#endif /* MY_DEF_HERE */
		}
	}

#if defined(MY_DEF_HERE)
	spin_lock_irqsave(&priv->lock, flags);
	/* Clear Tx buff for next iteration */
	priv->tx_buff = NULL;
	spin_unlock_irqrestore(&priv->lock, flags);
#else /* MY_DEF_HERE */
	spin_lock_irqsave(&tdm_if_lock, flags);
	/* Clear tx_buff for next iteration */
	tx_buff = NULL;
	spin_unlock_irqrestore(&tdm_if_lock, flags);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (priv->pcm_stop_flag && !priv->rx_buff) {
#else /* MY_DEF_HERE */
#ifdef CONFIG_MV_TDM2C_SUPPORT
	if (tdm_type == MV_TDM_UNIT_TDM2C) {
		if ((pcm_stop_flag == 1) && !rx_buff) {
#endif /* MY_DEF_HERE */
			dev_dbg(priv->dev, "Stopping TDM from Tx tasklet\n");
#if defined(MY_DEF_HERE)
		tdm2c_if_pcm_stop();
		spin_lock_irqsave(&priv->lock, flags);
		priv->pcm_stop_flag = false;
		spin_unlock_irqrestore(&priv->lock, flags);
		tasklet_hi_schedule(&tdm2c_if_reset_tasklet);
#else /* MY_DEF_HERE */
			tdm_if_pcm_stop();
			spin_lock_irqsave(&tdm_if_lock, flags);
			pcm_stop_flag = 0;
			spin_unlock_irqrestore(&tdm_if_lock, flags);
			tasklet_hi_schedule(&tdm2c_if_stop_tasklet);
#endif /* MY_DEF_HERE */
		}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	}
#endif
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static void tdmmc_if_pcm_tx_process(unsigned long arg)
#else /* MY_DEF_HERE */
static void tdm_if_stats_get(struct tal_stats *tdm_if_stats)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	unsigned long flags;

	if (priv->pcm_enable) {
		if (!priv->tx_buff) {
			dev_warn(priv->dev, "%s: Error, empty Tx processing\n", __func__);
#else /* MY_DEF_HERE */
	if (tdm_init == 0)
#endif /* MY_DEF_HERE */
		return;
#if defined(MY_DEF_HERE)
		}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
		/* Dispatch Tx handler */
		tal_mmp_tx(priv->tx_buff, priv->buff_size);

		if (!priv->test_enable) {
			if (tdmmc_tx(priv->tx_buff) != 0)
				dev_warn(priv->dev, "%s: Could not fill Tx buffer\n", __func__);
		}
	}

	spin_lock_irqsave(&priv->lock, flags);
	/* Clear Tx buff for next iteration */
	priv->tx_buff = NULL;
	spin_unlock_irqrestore(&priv->lock, flags);
#else /* MY_DEF_HERE */
	tdm_if_stats->tdm_init = tdm_init;
	tdm_if_stats->rx_miss = rx_miss;
	tdm_if_stats->tx_miss = tx_miss;
	tdm_if_stats->rx_over = rx_over;
	tdm_if_stats->tx_under = tx_under;
#ifdef CONFIG_MV_TDM_EXT_STATS
	tdm2c_ext_stats_get(&tdm_if_stats->tdm_ext_stats);
#endif
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
/* TDM2C restart channel callback */
static void tdm2c_if_reset_channels(unsigned long arg)
#else /* MY_DEF_HERE */
#ifdef CONFIG_MV_TDM2C_SUPPORT
static void tdm2c_if_stop_channels(unsigned long arg)
#endif /* MY_DEF_HERE */
{
	u32 max_poll = 0;
	unsigned long flags;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	void __iomem *tdm_base = get_tdm_base();
#endif /* MY_DEF_HERE */

	/* Wait for all channels to stop  */
#if defined(MY_DEF_HERE)
	while (((readl(priv->tdm_base + CH_ENABLE_REG(0)) & CH_RXTX_EN_MASK) ||
		(readl(priv->tdm_base + CH_ENABLE_REG(1)) & CH_RXTX_EN_MASK)) &&
		(max_poll < MV_TDM_STOP_POLLING_TIMEOUT)) {

#else /* MY_DEF_HERE */
	while (((readl(tdm_base + CH_ENABLE_REG(0)) & 0x101) ||
		(readl(tdm_base + CH_ENABLE_REG(1)) & 0x101)) && (max_poll < 30)) {
#endif /* MY_DEF_HERE */
		mdelay(1);
		max_poll++;
	}

	dev_dbg(priv->dev, "Finished polling on channels disable\n");
#if defined(MY_DEF_HERE)
	if (max_poll >= MV_TDM_STOP_POLLING_TIMEOUT) {
		writel(0, priv->tdm_base + CH_ENABLE_REG(0));
		writel(0, priv->tdm_base + CH_ENABLE_REG(1));
		dev_warn(priv->dev, "\n%s: Channels disabling timeout (%dms)\n",
			 __func__, MV_TDM_STOP_POLLING_TIMEOUT);
#else /* MY_DEF_HERE */
	if (max_poll >= 30) {
		writel(0, tdm_base + CH_ENABLE_REG(0));
		writel(0, tdm_base + CH_ENABLE_REG(1));
		dev_warn(priv->dev, "\n\npolling on channels disabling exceeded 30ms\n\n");
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
		priv->pcm_stop_fail++;
#else /* MY_DEF_HERE */
		pcm_stop_fail++;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#endif
#endif /* MY_DEF_HERE */
		mdelay(10);
	}

#if defined(MY_DEF_HERE)
	spin_lock_irqsave(&priv->lock, flags);
	priv->pcm_is_stopping = false;
	spin_unlock_irqrestore(&priv->lock, flags);
#else /* MY_DEF_HERE */
	spin_lock_irqsave(&tdm_if_lock, flags);
	is_pcm_stopping = 0;
	spin_unlock_irqrestore(&tdm_if_lock, flags);
	tdm_if_pcm_start();
}
#endif
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Restart channels */
	tdm2c_if_pcm_start();
#else /* MY_DEF_HERE */
static int tdm_if_control(int cmd, void *arg)
{
	switch (cmd) {
	case TDM_DEV_TDM_TEST_MODE_ENABLE:
		test_enable = 1;
		break;

	case TDM_DEV_TDM_TEST_MODE_DISABLE:
		test_enable = 0;
		break;

	default:
		return -EINVAL;
	};

	return 0;
}

static int tdm_if_write(u8 *buffer, int size)
{
	if (test_enable) {
#ifdef CONFIG_MV_TDM2C_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDM2C)
			return tdm2c_tx(buffer);
#endif
#ifdef CONFIG_MV_TDMMC_SUPPORT
		if (tdm_if_unit_type_get() == MV_TDM_UNIT_TDMMC)
			return tdmmc_tx(buffer);
#endif
	}
	return 0;
}

static struct tal_if tdm_if = {
	.init		= tdm_if_init,
	.exit		= tdm_if_exit,
	.pcm_start	= tdm_if_pcm_start,
	.pcm_stop	= tdm_if_pcm_stop,
	.control	= tdm_if_control,
	.write		= tdm_if_write,
	.stats_get	= tdm_if_stats_get,
};

static int tdm_if_module_init(void)
{
	u32 tdm_unit;

	tdm_unit = mv_phone_get_unit_type();

	if ((tdm_unit == MV_TDM_UNIT_TDM2C) ||
		tdm_unit == MV_TDM_UNIT_TDMMC) {
		tal_set_if(&tdm_if);
		tdm_if_unit_type_set(tdm_unit);
	}
	return 0;
}

static void tdm_if_module_exit(void)
{
	u32 tdm_unit;

	tdm_unit = mv_phone_get_unit_type();
	if (tdm_unit == MV_TDM_UNIT_TDM2C ||
	    tdm_unit == MV_TDM_UNIT_TDMMC)
		tal_set_if(NULL);
#endif /* MY_DEF_HERE */
}

/* Enable device interrupts. */
void mv_phone_intr_enable(u8 dev_id)
{
	switch (priv->tdm_type) {
	case MV_TDM_UNIT_TDM2C:
		tdm2c_intr_enable();
		break;
	case MV_TDM_UNIT_TDMMC:
		tdmmc_intr_enable(dev_id);
		break;
	default:
		dev_err(&priv->parent->dev, "%s: undefined TDM type\n",
			__func__);
	}
}

/* Disable device interrupts. */
void mv_phone_intr_disable(u8 dev_id)
{
	switch (priv->tdm_type) {
	case MV_TDM_UNIT_TDM2C:
		tdm2c_intr_disable();
		break;
	case MV_TDM_UNIT_TDMMC:
		tdmmc_intr_disable(dev_id);
		break;
	default:
		dev_err(&priv->parent->dev, "%s: undefined TDM type\n",
			__func__);
	}
}

/* Get board type for SLIC unit (pre-defined). */
u32 mv_phone_get_slic_board_type(void)
{
	return MV_BOARD_SLIC_DISABLED;
}

/* Configure PLL to 24MHz */
static int mv_phone_tdm_clk_pll_config(struct platform_device *pdev)
{
	struct resource *mem;
	u32 reg_val;
	u16 freq_offset = 0x22b0;
	u8 tdm_postdiv = 0x6, fb_clk_div = 0x1d;

	if (!priv->pll_base) {
		mem = platform_get_resource_byname(pdev, IORESOURCE_MEM,
						   "pll_regs");
		priv->pll_base = devm_ioremap_resource(&pdev->dev, mem);
		if (IS_ERR(priv->pll_base))
			return -ENOMEM;
	}

	/* Set frequency offset value to not valid and enable PLL reset */
	reg_val = readl(priv->pll_base + TDM_PLL_CONF_REG1);
	reg_val &= ~TDM_PLL_FREQ_OFFSET_VALID;
	reg_val &= ~TDM_PLL_SW_RESET;
	writel(reg_val, priv->pll_base + TDM_PLL_CONF_REG1);

	udelay(1);

	/* Update PLL parameters */
	reg_val = readl(priv->pll_base + TDM_PLL_CONF_REG0);
	reg_val &= ~TDM_PLL_FB_CLK_DIV_MASK;
	reg_val |= (fb_clk_div << TDM_PLL_FB_CLK_DIV_OFFSET);
	writel(reg_val, priv->pll_base + TDM_PLL_CONF_REG0);

	reg_val = readl(priv->pll_base + TDM_PLL_CONF_REG2);
	reg_val &= ~TDM_PLL_POSTDIV_MASK;
	reg_val |= tdm_postdiv;
	writel(reg_val, priv->pll_base + TDM_PLL_CONF_REG2);

	reg_val = readl(priv->pll_base + TDM_PLL_CONF_REG1);
	reg_val &= ~TDM_PLL_FREQ_OFFSET_MASK;
	reg_val |= freq_offset;
	writel(reg_val, priv->pll_base + TDM_PLL_CONF_REG1);

	udelay(1);

	/* Disable reset */
	reg_val |= TDM_PLL_SW_RESET;
	writel(reg_val, priv->pll_base + TDM_PLL_CONF_REG1);

	/* Wait 50us for PLL to lock */
	udelay(50);

	/* Restore frequency offset value validity */
	reg_val |= TDM_PLL_FREQ_OFFSET_VALID;
	writel(reg_val, priv->pll_base + TDM_PLL_CONF_REG1);

	return 0;
}

/* Set DCO post divider in respect of 24MHz PLL output */
static int mv_phone_dco_post_div_config(struct platform_device *pdev,
					u32 pclk_freq_mhz)
{
	struct resource *mem;
	u32 reg_val, pcm_clk_ratio;

	if (!priv->dco_div_reg) {
		mem = platform_get_resource_byname(pdev, IORESOURCE_MEM,
						   "dco_div");
		priv->dco_div_reg = devm_ioremap_resource(&pdev->dev, mem);
		if (IS_ERR(priv->dco_div_reg))
			return -ENOMEM;
	}

	switch (pclk_freq_mhz) {
	case 8:
		pcm_clk_ratio = DCO_CLK_DIV_RATIO_8M;
		break;
	case 4:
		pcm_clk_ratio = DCO_CLK_DIV_RATIO_4M;
		break;
	case 2:
		pcm_clk_ratio = DCO_CLK_DIV_RATIO_2M;
		break;
	default:
		pcm_clk_ratio = DCO_CLK_DIV_RATIO_8M;
		break;
	}

	/* Disable output clock */
	reg_val = readl(priv->dco_div_reg);
	reg_val &= ~DCO_CLK_DIV_RESET_MASK;
	writel(reg_val, priv->dco_div_reg);

	/* Set DCO source ratio */
	reg_val = readl(priv->dco_div_reg);
	writel((reg_val & ~DCO_CLK_DIV_RATIO_MASK) | pcm_clk_ratio,
	       priv->dco_div_reg);

	/* Reload new DCO source ratio */
	reg_val = readl(priv->dco_div_reg);
	reg_val |= DCO_CLK_DIV_APPLY_MASK;
	writel(reg_val, priv->dco_div_reg);
	mdelay(1);

	reg_val = readl(priv->dco_div_reg);
	reg_val &= ~DCO_CLK_DIV_APPLY_MASK;
	writel(reg_val, priv->dco_div_reg);
	mdelay(1);

	/* Enable output clock */
	reg_val = readl(priv->dco_div_reg);
	reg_val |= DCO_CLK_DIV_RESET_MASK;
	writel(reg_val, priv->dco_div_reg);

	return 0;
}

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
/* Initialize decoding windows */
static int mv_tdm2c_mbus_windows(struct device *dev, void __iomem *regs,
				 const struct mbus_dram_target_info *dram)
{
	int i;

	if (!dram) {
		dev_err(dev, "no mbus dram info\n");
		return -EINVAL;
	}

	for (i = 0; i < TDM_MBUS_MAX_WIN; i++) {
		writel(0, regs + TDM_WIN_CTRL_REG(i));
		writel(0, regs + TDM_WIN_BASE_REG(i));
	}

	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;

		/* Write size, attributes and target id to control register */
		writel(((cs->size - 1) & 0xffff0000) |
			(cs->mbus_attr << 8) |
			(dram->mbus_dram_target_id << 4) | 1,
			regs + TDM_WIN_CTRL_REG(i));
		/* Write base address to base register */
		writel(cs->base, regs + TDM_WIN_BASE_REG(i));
	}

	return 0;
}

/* Initialize decoding windows */
static int mv_tdmmc_a8k_windows(struct device *dev, void __iomem *regs)
{
	int i;

	for (i = 0; i < COMM_UNIT_MBUS_MAX_WIN; i++) {
		writel(0xce00, regs + COMM_UNIT_WIN_CTRL_REG(i));
		writel(0xffff0000, regs + COMM_UNIT_WIN_SIZE_REG(i));
		if (i > 0)
			writel(0x0, regs + COMM_UNIT_WIN_ENABLE_REG(i));
	}

	return 0;
}

#endif /* MY_DEF_HERE */
static int mvebu_phone_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct resource *mem;
#if defined(MY_DEF_HERE)
	int err, i;
#else /* MY_DEF_HERE */
	int err;
#endif /* MY_DEF_HERE */

	priv = devm_kzalloc(&pdev->dev, sizeof(struct mv_phone_dev),
			    GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->np = np;

	mem = platform_get_resource_byname(pdev, IORESOURCE_MEM, "tdm_regs");
	priv->tdm_base = devm_ioremap_resource(&pdev->dev, mem);
	if (IS_ERR(priv->tdm_base))
		return PTR_ERR(priv->tdm_base);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	tdm_base = (long int)priv->tdm_base;

	/* Get the first IRQ */
	priv->irq[0] = platform_get_irq(pdev, 0);
	if (priv->irq[0] <= 0) {
		dev_err(&pdev->dev, "platform_get_irq failed\n");
		return -ENXIO;
	}
#endif /* MY_DEF_HERE */

	priv->clk = devm_clk_get(&pdev->dev, "gateclk");
	if (PTR_ERR(priv->clk) == -EPROBE_DEFER)
		return -EPROBE_DEFER;

	if (IS_ERR(priv->clk)) {
		dev_err(&pdev->dev, "no clock\n");
		return PTR_ERR(priv->clk);
	}

	err = clk_prepare_enable(priv->clk);
	if (err)
		return err;

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	if (of_property_read_bool(np, "use-external-pclk")) {
		dev_info(&pdev->dev, "using external pclk\n");
		use_pclk_external = 1;
	} else {
		dev_info(&pdev->dev, "using internal pclk\n");
		use_pclk_external = 0;
	}

#endif /* MY_DEF_HERE */
	if (of_property_read_u32(np, "pclk-freq-mhz", &priv->pclk_freq_mhz) ||
	    (priv->pclk_freq_mhz != 8 && priv->pclk_freq_mhz != 4 &&
	     priv->pclk_freq_mhz != 2)) {
		priv->pclk_freq_mhz = 8;
		dev_info(&pdev->dev, "wrong pclk frequency in the DT\n");
	}
	dev_info(&pdev->dev, "setting pclk frequency to %d MHz\n",
		 priv->pclk_freq_mhz);

	if (of_device_is_compatible(np, "marvell,armada-380-tdm")) {
		priv->tdm_type = MV_TDM_UNIT_TDM2C;
		err = mv_phone_tdm_clk_pll_config(pdev);
		err |= mv_phone_dco_post_div_config(pdev, priv->pclk_freq_mhz);
#if defined(MY_DEF_HERE)
		err |= tdm2c_set_mbus_windows(&pdev->dev, priv->tdm_base,
#else /* MY_DEF_HERE */
		err |= mv_tdm2c_mbus_windows(&pdev->dev, priv->tdm_base,
#endif /* MY_DEF_HERE */
					     mv_mbus_dram_info());
		if (err < 0)
			goto err_clk;
#if defined(MY_DEF_HERE)

		priv->irq_count = 1;

		tal_set_if(&tdm2c_if);
#endif /* MY_DEF_HERE */
	}

	if (of_device_is_compatible(priv->np, "marvell,armada-xp-tdm")) {
		priv->tdm_type = MV_TDM_UNIT_TDMMC;
		err = tdmmc_set_mbus_windows(&pdev->dev, priv->tdm_base);
		if (err < 0)
			goto err_clk;
#if defined(MY_DEF_HERE)

		priv->irq_count = 1;
		priv->tdmmc_ip_ver = TDMMC_REV1;

		tal_set_if(&tdmmc_if);
#endif /* MY_DEF_HERE */
	}

	if (of_device_is_compatible(priv->np, "marvell,armada-a8k-tdm")) {
		priv->tdm_type = MV_TDM_UNIT_TDMMC;
#if defined(MY_DEF_HERE)
		tdmmc_set_a8k_windows(&pdev->dev, priv->tdm_base);
#else /* MY_DEF_HERE */
		mv_tdmmc_a8k_windows(&pdev->dev, priv->tdm_base);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
		priv->irq_count = 3;
		priv->tdmmc_ip_ver = TDMMC_REV1;

		tal_set_if(&tdmmc_if);
#else /* MY_DEF_HERE */
		/* Get the second and third IRQ - in A8k there are 3 IRQs */
		priv->irq[1] = platform_get_irq(pdev, 1);
		if (priv->irq[1] <= 0) {
			dev_err(&pdev->dev, "platform_get_irq failed\n");
			return -ENXIO;
#endif /* MY_DEF_HERE */
		}
#if defined(MY_DEF_HERE)

	/* Obtain IRQ numbers */
	for (i = 0; i < priv->irq_count; i++) {
		priv->irq[i] = platform_get_irq(pdev, i);
		if (priv->irq[i] <= 0) {
			dev_err(&pdev->dev, "platform_get_irq %d failed\n", i);
			err = priv->irq[i];
			goto err_clk;
#else /* MY_DEF_HERE */
		priv->irq[2] = platform_get_irq(pdev, 2);
		if (priv->irq[2] <= 0) {
			dev_err(&pdev->dev, "platform_get_irq failed\n");
			return -ENXIO;
#endif /* MY_DEF_HERE */
		}
	}

#if defined(MY_DEF_HERE)
	if (priv->tdm_type == MV_TDM_UNIT_TDM2C) {
		priv->use_pclk_external = of_property_read_bool(np, "use-external-pclk");
		dev_info(&pdev->dev, "using %s pclk\n",
			 priv->use_pclk_external ? "external" : "internal");

		if (of_property_read_u32(np, "spi-mode", &priv->tdm2c_spi_mode) ||
		    (priv->tdm2c_spi_mode != 0 && priv->tdm2c_spi_mode != 1))
			priv->tdm2c_spi_mode = 0;

		dev_info(&pdev->dev, "using %s SPI mode\n",
			 priv->tdm2c_spi_mode ? "daisy-chain" : "direct");
#if defined(MY_DEF_HERE)

#ifdef CONFIG_MV_TDM_EXT_STATS
		priv->use_tdm_ext_stats = true;
#endif
#endif /* MY_DEF_HERE */
	}
#else /* MY_DEF_HERE */
	mv_phone_enabled = 1;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	spin_lock_init(&priv->lock);
#else /* MY_DEF_HERE */
	tdm_if_module_init();
#endif /* MY_DEF_HERE */

	priv->dev = &pdev->dev;
	return 0;

err_clk:
	clk_disable_unprepare(priv->clk);

	return err;
}

static int mvebu_phone_remove(struct platform_device *pdev)
{
#if defined(MY_DEF_HERE)
	tal_set_if(NULL);
#else /* MY_DEF_HERE */
	tdm_if_module_exit();
#endif /* MY_DEF_HERE */

	clk_disable_unprepare(priv->clk);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int mvebu_phone_suspend(struct device *dev)
{
	int i;

	for (i = 0; i < TDM_CTRL_REGS_NUM; i++)
		priv->tdm_ctrl_regs[i] = readl(priv->tdm_base + i);

	for (i = 0; i < TDM_SPI_REGS_NUM; i++)
		priv->tdm_spi_regs[i] = readl(priv->tdm_base +
					      TDM_SPI_REGS_OFFSET + i);

	priv->tdm_spi_mux_reg = readl(priv->tdm_base + TDM_SPI_MUX_REG);
	priv->tdm_mbus_config_reg = readl(priv->tdm_base + TDM_MBUS_CONFIG_REG);
	priv->tdm_misc_reg = readl(priv->tdm_base + TDM_MISC_REG);

	return 0;
}

static int mvebu_phone_resume(struct device *dev)
{
	struct platform_device *pdev = priv->parent;
	int err, i;

#if defined(MY_DEF_HERE)
	err = tdm2c_set_mbus_windows(dev, priv->tdm_base,
#else /* MY_DEF_HERE */
	err = mv_tdm2c_mbus_windows(dev, priv->tdm_base,
#endif /* MY_DEF_HERE */
				    mv_mbus_dram_info());
	if (err < 0)
		return err;

	if (of_device_is_compatible(priv->np, "marvell,armada-380-tdm")) {
		err = mv_phone_tdm_clk_pll_config(pdev);
		err |= mv_phone_dco_post_div_config(pdev, priv->pclk_freq_mhz);
		if (err < 0)
			return err;
	}

	for (i = 0; i < TDM_CTRL_REGS_NUM; i++)
		writel(priv->tdm_ctrl_regs[i], priv->tdm_base + i);

	for (i = 0; i < TDM_SPI_REGS_NUM; i++)
		writel(priv->tdm_spi_regs[i], priv->tdm_base +
					      TDM_SPI_REGS_OFFSET + i);

	writel(priv->tdm_spi_mux_reg, priv->tdm_base + TDM_SPI_MUX_REG);
	writel(priv->tdm_mbus_config_reg, priv->tdm_base + TDM_MBUS_CONFIG_REG);
	writel(priv->tdm_misc_reg, priv->tdm_base + TDM_MISC_REG);

	return 0;
}
#endif

#ifdef CONFIG_PM
static const struct dev_pm_ops mvebu_phone_pmops = {
	SET_SYSTEM_SLEEP_PM_OPS(mvebu_phone_suspend, mvebu_phone_resume)
};

#define MVEBU_PHONE_PMOPS (&mvebu_phone_pmops)

#else
#define MVEBU_PHONE_PMOPS NULL
#endif

static const struct of_device_id mvebu_phone_match[] = {
	{ .compatible = "marvell,armada-380-tdm" },
	{ .compatible = "marvell,armada-a8k-tdm" },
	{ .compatible = "marvell,armada-xp-tdm" },
	{ }
};
MODULE_DEVICE_TABLE(of, mvebu_phone_match);

static struct platform_driver mvebu_phone_driver = {
	.probe	= mvebu_phone_probe,
	.remove	= mvebu_phone_remove,
	.driver	= {
		.name	= DRV_NAME,
		.of_match_table = mvebu_phone_match,
		.owner	= THIS_MODULE,
		.pm	= MVEBU_PHONE_PMOPS,
	},
};

module_platform_driver(mvebu_phone_driver);

MODULE_DESCRIPTION("Marvell Telephony Driver");
MODULE_AUTHOR("Marcin Wojtas <mw@semihalf.com>");
#endif /* MY_DEF_HERE */
