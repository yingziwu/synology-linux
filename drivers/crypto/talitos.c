#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/crypto.h>
#include <linux/hw_random.h>
#include <linux/of_platform.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/rtnetlink.h>
#include <linux/dmaengine.h>
#include <linux/raid/xor.h>

#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/sha.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/skcipher.h>
#include <crypto/scatterwalk.h>

#include "talitos.h"

#define TALITOS_TIMEOUT 100000
#define TALITOS_MAX_DATA_LEN 65535

#define DESC_TYPE(desc_hdr) ((be32_to_cpu(desc_hdr) >> 3) & 0x1f)
#define PRIMARY_EU(desc_hdr) ((be32_to_cpu(desc_hdr) >> 28) & 0xf)
#define SECONDARY_EU(desc_hdr) ((be32_to_cpu(desc_hdr) >> 16) & 0xf)

struct talitos_ptr {
	__be16 len;	 
	u8 j_extent;	 
	u8 eptr;	 
	__be32 ptr;	 
};

struct talitos_desc {
	__be32 hdr;			 
	__be32 hdr_lo;			 
	struct talitos_ptr ptr[7];	 
};

struct talitos_request {
	struct talitos_desc *desc;
	dma_addr_t dma_desc;
	void (*callback) (struct device *dev, struct talitos_desc *desc,
	                  void *context, int error);
	void *context;
};

struct talitos_channel {
	 
	struct talitos_request *fifo;

	atomic_t submit_count ____cacheline_aligned;

	spinlock_t head_lock ____cacheline_aligned;
	 
	int head;

	spinlock_t tail_lock ____cacheline_aligned;
	 
	int tail;
};

struct talitos_private {
	struct device *dev;
	struct of_device *ofdev;
	void __iomem *reg;
	int irq;

	unsigned int num_channels;
	unsigned int chfifo_len;
	unsigned int exec_units;
	unsigned int desc_types;

	unsigned long features;

	unsigned int fifo_len;

	struct talitos_channel *chan;

	atomic_t last_chan ____cacheline_aligned;

	struct tasklet_struct done_task;

	struct list_head alg_list;

	struct hwrng rng;

	struct dma_device dma_dev_common;
};

#define TALITOS_FTR_SRC_LINK_TBL_LEN_INCLUDES_EXTENT 0x00000001
#define TALITOS_FTR_HW_AUTH_CHECK 0x00000002

static void to_talitos_ptr(struct talitos_ptr *talitos_ptr, dma_addr_t dma_addr)
{
	talitos_ptr->ptr = cpu_to_be32(lower_32_bits(dma_addr));
	talitos_ptr->eptr = cpu_to_be32(upper_32_bits(dma_addr));
}

static void map_single_talitos_ptr(struct device *dev,
				   struct talitos_ptr *talitos_ptr,
				   unsigned short len, void *data,
				   unsigned char extent,
				   enum dma_data_direction dir)
{
	dma_addr_t dma_addr = dma_map_single(dev, data, len, dir);

	talitos_ptr->len = cpu_to_be16(len);
	to_talitos_ptr(talitos_ptr, dma_addr);
	talitos_ptr->j_extent = extent;
}

static void unmap_single_talitos_ptr(struct device *dev,
				     struct talitos_ptr *talitos_ptr,
				     enum dma_data_direction dir)
{
	dma_unmap_single(dev, be32_to_cpu(talitos_ptr->ptr),
			 be16_to_cpu(talitos_ptr->len), dir);
}

static int reset_channel(struct device *dev, int ch)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	unsigned int timeout = TALITOS_TIMEOUT;

	setbits32(priv->reg + TALITOS_CCCR(ch), TALITOS_CCCR_RESET);

	while ((in_be32(priv->reg + TALITOS_CCCR(ch)) & TALITOS_CCCR_RESET)
	       && --timeout)
		cpu_relax();

	if (timeout == 0) {
		dev_err(dev, "failed to reset channel %d\n", ch);
		return -EIO;
	}

	setbits32(priv->reg + TALITOS_CCCR_LO(ch), TALITOS_CCCR_LO_EAE |
		  TALITOS_CCCR_LO_CDWE | TALITOS_CCCR_LO_CDIE);

	if (priv->features & TALITOS_FTR_HW_AUTH_CHECK)
		setbits32(priv->reg + TALITOS_CCCR_LO(ch),
		          TALITOS_CCCR_LO_IWSE);

	return 0;
}

static int reset_device(struct device *dev)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	unsigned int timeout = TALITOS_TIMEOUT;

	setbits32(priv->reg + TALITOS_MCR, TALITOS_MCR_SWR);

	while ((in_be32(priv->reg + TALITOS_MCR) & TALITOS_MCR_SWR)
	       && --timeout)
		cpu_relax();

	if (timeout == 0) {
		dev_err(dev, "failed to reset device\n");
		return -EIO;
	}

	return 0;
}

static int init_device(struct device *dev)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	int ch, err;

	err = reset_device(dev);
	if (err)
		return err;

	err = reset_device(dev);
	if (err)
		return err;

	for (ch = 0; ch < priv->num_channels; ch++) {
		err = reset_channel(dev, ch);
		if (err)
			return err;
	}

	setbits32(priv->reg + TALITOS_IMR, TALITOS_IMR_INIT);
	setbits32(priv->reg + TALITOS_IMR_LO, TALITOS_IMR_LO_INIT);

	if (priv->features & TALITOS_FTR_HW_AUTH_CHECK)
		setbits32(priv->reg + TALITOS_MDEUICR_LO,
		          TALITOS_MDEUICR_LO_ICE);

	return 0;
}

#ifdef MY_ABC_HERE
static void talitos_release_xor(struct device *dev, struct talitos_desc *hwdesc,
				void *context, int error);
#endif
 
static int talitos_submit(struct device *dev, struct talitos_desc *desc,
			  void (*callback)(struct device *dev,
					   struct talitos_desc *desc,
					   void *context, int error),
			  void *context)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	struct talitos_request *request;
	unsigned long flags, ch;
	int head;

	desc->hdr |= DESC_HDR_DONE_NOTIFY;

	ch = atomic_inc_return(&priv->last_chan) & (priv->num_channels - 1);

#ifdef MY_ABC_HERE
	 
	if (callback == talitos_release_xor) {
		ch = 0;
	} else {
		if ( 0 == ch ) {
			ch++;
		} 
	}
#endif
	spin_lock_irqsave(&priv->chan[ch].head_lock, flags);

	if (!atomic_inc_not_zero(&priv->chan[ch].submit_count)) {
		 
		spin_unlock_irqrestore(&priv->chan[ch].head_lock, flags);
		return -EAGAIN;
	}

	head = priv->chan[ch].head;
	request = &priv->chan[ch].fifo[head];

	request->dma_desc = dma_map_single(dev, desc, sizeof(*desc),
					   DMA_BIDIRECTIONAL);
	request->callback = callback;
	request->context = context;

	priv->chan[ch].head = (priv->chan[ch].head + 1) & (priv->fifo_len - 1);

	smp_wmb();
	request->desc = desc;

	wmb();
	out_be32(priv->reg + TALITOS_FF(ch),
		 cpu_to_be32(upper_32_bits(request->dma_desc)));
	out_be32(priv->reg + TALITOS_FF_LO(ch),
		 cpu_to_be32(lower_32_bits(request->dma_desc)));

	spin_unlock_irqrestore(&priv->chan[ch].head_lock, flags);

	return -EINPROGRESS;
}

static void flush_channel(struct device *dev, int ch, int error, int reset_ch)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	struct talitos_request *request, saved_req;
	unsigned long flags;
	int tail, status;

	spin_lock_irqsave(&priv->chan[ch].tail_lock, flags);

	tail = priv->chan[ch].tail;
	while (priv->chan[ch].fifo[tail].desc) {
		request = &priv->chan[ch].fifo[tail];

		rmb();
		if ((request->desc->hdr & DESC_HDR_DONE) == DESC_HDR_DONE)
			status = 0;
		else
			if (!error)
				break;
			else
				status = error;

		dma_unmap_single(dev, request->dma_desc,
				 sizeof(struct talitos_desc),
				 DMA_BIDIRECTIONAL);

		saved_req.desc = request->desc;
		saved_req.callback = request->callback;
		saved_req.context = request->context;

		smp_wmb();
		request->desc = NULL;

		priv->chan[ch].tail = (tail + 1) & (priv->fifo_len - 1);

		spin_unlock_irqrestore(&priv->chan[ch].tail_lock, flags);

		atomic_dec(&priv->chan[ch].submit_count);

		saved_req.callback(dev, saved_req.desc, saved_req.context,
				   status);
		 
		if (error && !reset_ch && status == error)
			return;
		spin_lock_irqsave(&priv->chan[ch].tail_lock, flags);
		tail = priv->chan[ch].tail;
	}

	spin_unlock_irqrestore(&priv->chan[ch].tail_lock, flags);
}

static void talitos_done(unsigned long data)
{
	struct device *dev = (struct device *)data;
	struct talitos_private *priv = dev_get_drvdata(dev);
	int ch;

	for (ch = 0; ch < priv->num_channels; ch++)
		flush_channel(dev, ch, 0, 0);

	setbits32(priv->reg + TALITOS_IMR, TALITOS_IMR_INIT);
	setbits32(priv->reg + TALITOS_IMR_LO, TALITOS_IMR_LO_INIT);
}

static struct talitos_desc *current_desc(struct device *dev, int ch)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	int tail = priv->chan[ch].tail;
	dma_addr_t cur_desc;

	cur_desc = in_be32(priv->reg + TALITOS_CDPR_LO(ch));

	while (priv->chan[ch].fifo[tail].dma_desc != cur_desc) {
		tail = (tail + 1) & (priv->fifo_len - 1);
		if (tail == priv->chan[ch].tail) {
			dev_err(dev, "couldn't locate current descriptor\n");
			return NULL;
		}
	}

	return priv->chan[ch].fifo[tail].desc;
}

static void report_eu_error(struct device *dev, int ch,
			    struct talitos_desc *desc)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	int i;

	switch (desc->hdr & DESC_HDR_SEL0_MASK) {
	case DESC_HDR_SEL0_AFEU:
		dev_err(dev, "AFEUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_AFEUISR),
			in_be32(priv->reg + TALITOS_AFEUISR_LO));
		break;
	case DESC_HDR_SEL0_DEU:
		dev_err(dev, "DEUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_DEUISR),
			in_be32(priv->reg + TALITOS_DEUISR_LO));
		break;
	case DESC_HDR_SEL0_MDEUA:
	case DESC_HDR_SEL0_MDEUB:
		dev_err(dev, "MDEUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_MDEUISR),
			in_be32(priv->reg + TALITOS_MDEUISR_LO));
		break;
	case DESC_HDR_SEL0_RNG:
		dev_err(dev, "RNGUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_RNGUISR),
			in_be32(priv->reg + TALITOS_RNGUISR_LO));
		break;
	case DESC_HDR_SEL0_PKEU:
		dev_err(dev, "PKEUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_PKEUISR),
			in_be32(priv->reg + TALITOS_PKEUISR_LO));
		break;
	case DESC_HDR_SEL0_AESU:
		dev_err(dev, "AESUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_AESUISR),
			in_be32(priv->reg + TALITOS_AESUISR_LO));
		break;
	case DESC_HDR_SEL0_CRCU:
		dev_err(dev, "CRCUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_CRCUISR),
			in_be32(priv->reg + TALITOS_CRCUISR_LO));
		break;
	case DESC_HDR_SEL0_KEU:
		dev_err(dev, "KEUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_KEUISR),
			in_be32(priv->reg + TALITOS_KEUISR_LO));
		break;
	}

	switch (desc->hdr & DESC_HDR_SEL1_MASK) {
	case DESC_HDR_SEL1_MDEUA:
	case DESC_HDR_SEL1_MDEUB:
		dev_err(dev, "MDEUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_MDEUISR),
			in_be32(priv->reg + TALITOS_MDEUISR_LO));
		break;
	case DESC_HDR_SEL1_CRCU:
		dev_err(dev, "CRCUISR 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_CRCUISR),
			in_be32(priv->reg + TALITOS_CRCUISR_LO));
		break;
	}

	for (i = 0; i < 8; i++)
		dev_err(dev, "DESCBUF 0x%08x_%08x\n",
			in_be32(priv->reg + TALITOS_DESCBUF(ch) + 8*i),
			in_be32(priv->reg + TALITOS_DESCBUF_LO(ch) + 8*i));
}

static void talitos_error(unsigned long data, u32 isr, u32 isr_lo)
{
	struct device *dev = (struct device *)data;
	struct talitos_private *priv = dev_get_drvdata(dev);
	unsigned int timeout = TALITOS_TIMEOUT;
	int ch, error, reset_dev = 0, reset_ch = 0;
	u32 v, v_lo;

	for (ch = 0; ch < priv->num_channels; ch++) {
		 
		if (!(isr & (1 << (ch * 2 + 1))))
			continue;

		error = -EINVAL;

		v = in_be32(priv->reg + TALITOS_CCPSR(ch));
		v_lo = in_be32(priv->reg + TALITOS_CCPSR_LO(ch));

		if (v_lo & TALITOS_CCPSR_LO_DOF) {
			dev_err(dev, "double fetch fifo overflow error\n");
			error = -EAGAIN;
			reset_ch = 1;
		}
		if (v_lo & TALITOS_CCPSR_LO_SOF) {
			 
			dev_err(dev, "single fetch fifo overflow error\n");
			error = -EAGAIN;
		}
		if (v_lo & TALITOS_CCPSR_LO_MDTE)
			dev_err(dev, "master data transfer error\n");
		if (v_lo & TALITOS_CCPSR_LO_SGDLZ)
			dev_err(dev, "s/g data length zero error\n");
		if (v_lo & TALITOS_CCPSR_LO_FPZ)
			dev_err(dev, "fetch pointer zero error\n");
		if (v_lo & TALITOS_CCPSR_LO_IDH)
			dev_err(dev, "illegal descriptor header error\n");
		if (v_lo & TALITOS_CCPSR_LO_IEU)
			dev_err(dev, "invalid execution unit error\n");
		if (v_lo & TALITOS_CCPSR_LO_EU)
			report_eu_error(dev, ch, current_desc(dev, ch));
		if (v_lo & TALITOS_CCPSR_LO_GB)
			dev_err(dev, "gather boundary error\n");
		if (v_lo & TALITOS_CCPSR_LO_GRL)
			dev_err(dev, "gather return/length error\n");
		if (v_lo & TALITOS_CCPSR_LO_SB)
			dev_err(dev, "scatter boundary error\n");
		if (v_lo & TALITOS_CCPSR_LO_SRL)
			dev_err(dev, "scatter return/length error\n");

		flush_channel(dev, ch, error, reset_ch);

		if (reset_ch) {
			reset_channel(dev, ch);
		} else {
			setbits32(priv->reg + TALITOS_CCCR(ch),
				  TALITOS_CCCR_CONT);
			setbits32(priv->reg + TALITOS_CCCR_LO(ch), 0);
			while ((in_be32(priv->reg + TALITOS_CCCR(ch)) &
			       TALITOS_CCCR_CONT) && --timeout)
				cpu_relax();
			if (timeout == 0) {
				dev_err(dev, "failed to restart channel %d\n",
					ch);
				reset_dev = 1;
			}
		}
	}
	if (reset_dev || isr & ~TALITOS_ISR_CHERR || isr_lo) {
		dev_err(dev, "done overflow, internal time out, or rngu error: "
		        "ISR 0x%08x_%08x\n", isr, isr_lo);

		for (ch = 0; ch < priv->num_channels; ch++)
			flush_channel(dev, ch, -EIO, 1);

		init_device(dev);
	}
}

static irqreturn_t talitos_interrupt(int irq, void *data)
{
	struct device *dev = data;
	struct talitos_private *priv = dev_get_drvdata(dev);
	u32 isr, isr_lo;

	isr = in_be32(priv->reg + TALITOS_ISR);
	isr_lo = in_be32(priv->reg + TALITOS_ISR_LO);
	 
	out_be32(priv->reg + TALITOS_ICR, isr);
	out_be32(priv->reg + TALITOS_ICR_LO, isr_lo);

	if (unlikely((isr & ~TALITOS_ISR_CHDONE) || isr_lo))
		talitos_error((unsigned long)data, isr, isr_lo);
	else
		if (likely(isr & TALITOS_ISR_CHDONE)) {
			 
			clrbits32(priv->reg + TALITOS_IMR, TALITOS_IMR_DONE);
			 
			tasklet_schedule(&priv->done_task);
		}

	return (isr || isr_lo) ? IRQ_HANDLED : IRQ_NONE;
}

static int talitos_rng_data_present(struct hwrng *rng, int wait)
{
	struct device *dev = (struct device *)rng->priv;
	struct talitos_private *priv = dev_get_drvdata(dev);
	u32 ofl;
	int i;

	for (i = 0; i < 20; i++) {
		ofl = in_be32(priv->reg + TALITOS_RNGUSR_LO) &
		      TALITOS_RNGUSR_LO_OFL;
		if (ofl || !wait)
			break;
		udelay(10);
	}

	return !!ofl;
}

static int talitos_rng_data_read(struct hwrng *rng, u32 *data)
{
	struct device *dev = (struct device *)rng->priv;
	struct talitos_private *priv = dev_get_drvdata(dev);

	*data = in_be32(priv->reg + TALITOS_RNGU_FIFO);
	*data = in_be32(priv->reg + TALITOS_RNGU_FIFO_LO);

	return sizeof(u32);
}

static int talitos_rng_init(struct hwrng *rng)
{
	struct device *dev = (struct device *)rng->priv;
	struct talitos_private *priv = dev_get_drvdata(dev);
	unsigned int timeout = TALITOS_TIMEOUT;

	setbits32(priv->reg + TALITOS_RNGURCR_LO, TALITOS_RNGURCR_LO_SR);
	while (!(in_be32(priv->reg + TALITOS_RNGUSR_LO) & TALITOS_RNGUSR_LO_RD)
	       && --timeout)
		cpu_relax();
	if (timeout == 0) {
		dev_err(dev, "failed to reset rng hw\n");
		return -ENODEV;
	}

	setbits32(priv->reg + TALITOS_RNGUDSR_LO, 0);

	return 0;
}

static int talitos_register_rng(struct device *dev)
{
	struct talitos_private *priv = dev_get_drvdata(dev);

	priv->rng.name		= dev_driver_string(dev),
	priv->rng.init		= talitos_rng_init,
	priv->rng.data_present	= talitos_rng_data_present,
	priv->rng.data_read	= talitos_rng_data_read,
	priv->rng.priv		= (unsigned long)dev;

	return hwrng_register(&priv->rng);
}

static void talitos_unregister_rng(struct device *dev)
{
	struct talitos_private *priv = dev_get_drvdata(dev);

	hwrng_unregister(&priv->rng);
}

struct talitos_xor_chan {
	dma_cookie_t completed_cookie;
	spinlock_t desc_lock;
	unsigned int total_desc;
	struct list_head submit_q;
	struct list_head pending_q;
	struct list_head in_progress_q;
	struct list_head free_desc;
	struct device *dev;
	struct dma_chan common;
};

struct talitos_xor_desc {
	struct dma_async_tx_descriptor async_tx;
	struct list_head tx_list;
	struct list_head node;
	struct talitos_desc hwdesc;
};

static void talitos_release_xor(struct device *dev, struct talitos_desc *hwdesc,
				void *context, int error);

static enum dma_status talitos_is_tx_complete(struct dma_chan *chan,
					      dma_cookie_t cookie,
					      dma_cookie_t *done,
					      dma_cookie_t *used)
{
	struct talitos_xor_chan *xor_chan;
	dma_cookie_t last_used;
	dma_cookie_t last_complete;

	xor_chan = container_of(chan, struct talitos_xor_chan, common);

	last_used = chan->cookie;
	last_complete = xor_chan->completed_cookie;

	if (done)
		*done = last_complete;

	if (used)
		*used = last_used;

	return dma_async_is_complete(cookie, last_complete, last_used);
}

static void talitos_process_pending(struct talitos_xor_chan *xor_chan)
{
	struct talitos_xor_desc *desc, *_desc;
	unsigned long flags;
	int status;

	spin_lock_irqsave(&xor_chan->desc_lock, flags);

	list_for_each_entry_safe(desc, _desc, &xor_chan->pending_q, node) {
		status = talitos_submit(xor_chan->dev, &desc->hwdesc,
					talitos_release_xor, desc);
		if (status != -EINPROGRESS)
			break;

		list_del(&desc->node);
		list_add_tail(&desc->node, &xor_chan->in_progress_q);
	}

	spin_unlock_irqrestore(&xor_chan->desc_lock, flags);
}

static void talitos_release_xor(struct device *dev, struct talitos_desc *hwdesc,
				void *context, int error)
{
	struct talitos_xor_desc *desc = context;
	struct talitos_xor_chan *xor_chan;
	dma_async_tx_callback callback;
	void *callback_param;

	if (unlikely(error)) {
		dev_err(dev, "xor operation: talitos error %d\n", error);
		BUG();
	}

	xor_chan = container_of(desc->async_tx.chan, struct talitos_xor_chan,
				common);
	spin_lock_bh(&xor_chan->desc_lock);
	if (xor_chan->completed_cookie < desc->async_tx.cookie)
		xor_chan->completed_cookie = desc->async_tx.cookie;

	callback = desc->async_tx.callback;
	callback_param = desc->async_tx.callback_param;

	if (callback) {
		spin_unlock_bh(&xor_chan->desc_lock);
		callback(callback_param);
		spin_lock_bh(&xor_chan->desc_lock);
	}

	list_del(&desc->node);
	list_add_tail(&desc->node, &xor_chan->free_desc);
	spin_unlock_bh(&xor_chan->desc_lock);
	if (!list_empty(&xor_chan->pending_q))
		talitos_process_pending(xor_chan);
}

static void talitos_issue_pending(struct dma_chan *chan)
{
	struct talitos_xor_chan *xor_chan;

	xor_chan = container_of(chan, struct talitos_xor_chan, common);
	spin_lock_bh(&xor_chan->desc_lock);
	list_splice_tail_init(&xor_chan->submit_q,
				 &xor_chan->pending_q);
	spin_unlock_bh(&xor_chan->desc_lock);
	talitos_process_pending(xor_chan);
}

static dma_cookie_t talitos_async_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct talitos_xor_desc *desc;
	struct talitos_xor_chan *xor_chan;
	dma_cookie_t cookie;

	desc = container_of(tx, struct talitos_xor_desc, async_tx);
	xor_chan = container_of(tx->chan, struct talitos_xor_chan, common);

	spin_lock_bh(&xor_chan->desc_lock);

	cookie = xor_chan->common.cookie + 1;
	if (cookie < 0)
		cookie = 1;

	desc->async_tx.cookie = cookie;
	xor_chan->common.cookie = desc->async_tx.cookie;

	list_splice_tail_init(&desc->tx_list,
				 &xor_chan->submit_q);

	spin_unlock_bh(&xor_chan->desc_lock);

	return cookie;
}

static struct talitos_xor_desc *talitos_xor_alloc_descriptor(
				struct talitos_xor_chan *xor_chan, gfp_t flags)
{
	struct talitos_xor_desc *desc;

	desc = kmalloc(sizeof(*desc), flags);
	if (desc) {
		xor_chan->total_desc++;
		desc->async_tx.tx_submit = talitos_async_tx_submit;
	}

	return desc;
}

static void talitos_free_chan_resources(struct dma_chan *chan)
{
	struct talitos_xor_chan *xor_chan;
	struct talitos_xor_desc *desc, *_desc;

	xor_chan = container_of(chan, struct talitos_xor_chan, common);

	spin_lock_bh(&xor_chan->desc_lock);

	list_for_each_entry_safe(desc, _desc, &xor_chan->submit_q, node) {
		list_del(&desc->node);
		xor_chan->total_desc--;
		kfree(desc);
	}
	list_for_each_entry_safe(desc, _desc, &xor_chan->pending_q, node) {
		list_del(&desc->node);
		xor_chan->total_desc--;
		kfree(desc);
	}
	list_for_each_entry_safe(desc, _desc, &xor_chan->in_progress_q, node) {
		list_del(&desc->node);
		xor_chan->total_desc--;
		kfree(desc);
	}
	list_for_each_entry_safe(desc, _desc, &xor_chan->free_desc, node) {
		list_del(&desc->node);
		xor_chan->total_desc--;
		kfree(desc);
	}
	BUG_ON(unlikely(xor_chan->total_desc));	 

	spin_unlock_bh(&xor_chan->desc_lock);
}

static int talitos_alloc_chan_resources(struct dma_chan *chan)
{
	struct talitos_xor_chan *xor_chan;
	struct talitos_xor_desc *desc;
	LIST_HEAD(tmp_list);
	int i;

	xor_chan = container_of(chan, struct talitos_xor_chan, common);

	if (!list_empty(&xor_chan->free_desc))
		return xor_chan->total_desc;

	for (i = 0; i < 256; i++) {
		desc = talitos_xor_alloc_descriptor(xor_chan, GFP_KERNEL);
		if (!desc) {
			dev_err(xor_chan->common.device->dev,
				"Only %d initial descriptors\n", i);
			break;
		}
		list_add_tail(&desc->node, &tmp_list);
	}

	if (!i)
		return -ENOMEM;

	spin_lock_bh(&xor_chan->desc_lock);
	list_splice_init(&tmp_list, &xor_chan->free_desc);
	spin_unlock_bh(&xor_chan->desc_lock);

	return xor_chan->total_desc;
}

static struct dma_async_tx_descriptor * talitos_prep_dma_xor(
			struct dma_chan *chan, dma_addr_t dest, dma_addr_t *src,
			unsigned int src_cnt, size_t len, unsigned long flags)
{
	struct talitos_xor_chan *xor_chan;
	struct talitos_xor_desc *new;
	struct talitos_desc *desc;
	int i, j;

	BUG_ON(unlikely(len > TALITOS_MAX_DATA_LEN));

	xor_chan = container_of(chan, struct talitos_xor_chan, common);

	spin_lock_bh(&xor_chan->desc_lock);
	if (!list_empty(&xor_chan->free_desc)) {
		new = container_of(xor_chan->free_desc.next,
				   struct talitos_xor_desc, node);
		list_del(&new->node);
	} else {
		new = talitos_xor_alloc_descriptor(xor_chan, GFP_KERNEL);
	}
	spin_unlock_bh(&xor_chan->desc_lock);

	if (!new) {
		dev_err(xor_chan->common.device->dev,
			"No free memory for XOR DMA descriptor\n");
		return NULL;
	}
	dma_async_tx_descriptor_init(&new->async_tx, &xor_chan->common);

	INIT_LIST_HEAD(&new->node);
	INIT_LIST_HEAD(&new->tx_list);

	desc = &new->hwdesc;
	 
	to_talitos_ptr(&desc->ptr[6], dest);
	desc->ptr[6].len = cpu_to_be16(len);
	desc->ptr[6].j_extent = 0;

	for (i = 5, j = 0; (j < src_cnt) && (i > 0); i--, j++) {
		to_talitos_ptr(&desc->ptr[i], src[j]);
		desc->ptr[i].len = cpu_to_be16(len);
		desc->ptr[i].j_extent = 0;
	}

	for (; i >= 0; i--) {
		to_talitos_ptr(&desc->ptr[i], 0);
		desc->ptr[i].len = 0;
		desc->ptr[i].j_extent = 0;
	}

	desc->hdr = DESC_HDR_SEL0_AESU | DESC_HDR_MODE0_AESU_XOR
		    | DESC_HDR_TYPE_RAID_XOR;

	new->async_tx.parent = NULL;
	new->async_tx.next = NULL;
	new->async_tx.cookie = 0;
	async_tx_ack(&new->async_tx);

	list_add_tail(&new->node, &new->tx_list);

	new->async_tx.flags = flags;
	new->async_tx.cookie = -EBUSY;

	return &new->async_tx;
}

static void talitos_unregister_async_xor(struct device *dev)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	struct talitos_xor_chan *xor_chan;
	struct dma_chan *chan;

	if (priv->dma_dev_common.chancnt)
		dma_async_device_unregister(&priv->dma_dev_common);

	list_for_each_entry(chan, &priv->dma_dev_common.channels, device_node) {
		xor_chan = container_of(chan, struct talitos_xor_chan, common);
		list_del(&chan->device_node);
		priv->dma_dev_common.chancnt--;
		kfree(xor_chan);
	}
}

static int talitos_register_async_tx(struct device *dev, int max_xor_srcs)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	struct dma_device *dma_dev = &priv->dma_dev_common;
	struct talitos_xor_chan *xor_chan;
	int err;

	xor_chan = kzalloc(sizeof(struct talitos_xor_chan), GFP_KERNEL);
	if (!xor_chan) {
		dev_err(dev, "unable to allocate xor channel\n");
		return -ENOMEM;
	}

	dma_dev->dev = dev;
	dma_dev->device_alloc_chan_resources = talitos_alloc_chan_resources;
	dma_dev->device_free_chan_resources = talitos_free_chan_resources;
	dma_dev->device_prep_dma_xor = talitos_prep_dma_xor;
	dma_dev->max_xor = max_xor_srcs;
	dma_dev->device_is_tx_complete = talitos_is_tx_complete;
	dma_dev->device_issue_pending = talitos_issue_pending;
	INIT_LIST_HEAD(&dma_dev->channels);
	dma_cap_set(DMA_XOR, dma_dev->cap_mask);

	xor_chan->dev = dev;
	xor_chan->common.device = dma_dev;
	xor_chan->total_desc = 0;
	INIT_LIST_HEAD(&xor_chan->submit_q);
	INIT_LIST_HEAD(&xor_chan->pending_q);
	INIT_LIST_HEAD(&xor_chan->in_progress_q);
	INIT_LIST_HEAD(&xor_chan->free_desc);
	spin_lock_init(&xor_chan->desc_lock);

	list_add_tail(&xor_chan->common.device_node, &dma_dev->channels);
	dma_dev->chancnt++;

	err = dma_async_device_register(dma_dev);
	if (err) {
		dev_err(dev, "Unable to register XOR with Async_tx\n");
		goto err_out;
	}

	return err;

err_out:
	talitos_unregister_async_xor(dev);
	return err;
}
 
#define TALITOS_CRA_PRIORITY		3000
#define TALITOS_MAX_KEY_SIZE		64
#define TALITOS_MAX_IV_LENGTH		16  

#define MD5_DIGEST_SIZE   16

struct talitos_ctx {
	struct device *dev;
	__be32 desc_hdr_template;
	u8 key[TALITOS_MAX_KEY_SIZE];
	u8 iv[TALITOS_MAX_IV_LENGTH];
	unsigned int keylen;
	unsigned int enckeylen;
	unsigned int authkeylen;
	unsigned int authsize;
};

static int aead_setauthsize(struct crypto_aead *authenc,
			    unsigned int authsize)
{
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);

	ctx->authsize = authsize;

	return 0;
}

static int aead_setkey(struct crypto_aead *authenc,
		       const u8 *key, unsigned int keylen)
{
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);
	struct rtattr *rta = (void *)key;
	struct crypto_authenc_key_param *param;
	unsigned int authkeylen;
	unsigned int enckeylen;

	if (!RTA_OK(rta, keylen))
		goto badkey;

	if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
		goto badkey;

	if (RTA_PAYLOAD(rta) < sizeof(*param))
		goto badkey;

	param = RTA_DATA(rta);
	enckeylen = be32_to_cpu(param->enckeylen);

	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);

	if (keylen < enckeylen)
		goto badkey;

	authkeylen = keylen - enckeylen;

	if (keylen > TALITOS_MAX_KEY_SIZE)
		goto badkey;

	memcpy(&ctx->key, key, keylen);

	ctx->keylen = keylen;
	ctx->enckeylen = enckeylen;
	ctx->authkeylen = authkeylen;

	return 0;

badkey:
	crypto_aead_set_flags(authenc, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

struct talitos_edesc {
	int src_nents;
	int dst_nents;
	int src_is_chained;
	int dst_is_chained;
	int dma_len;
	dma_addr_t dma_link_tbl;
	struct talitos_desc desc;
	struct talitos_ptr link_tbl[0];
};

static int talitos_map_sg(struct device *dev, struct scatterlist *sg,
			  unsigned int nents, enum dma_data_direction dir,
			  int chained)
{
	if (unlikely(chained))
		while (sg) {
			dma_map_sg(dev, sg, 1, dir);
			sg = scatterwalk_sg_next(sg);
		}
	else
		dma_map_sg(dev, sg, nents, dir);
	return nents;
}

static void talitos_unmap_sg_chain(struct device *dev, struct scatterlist *sg,
				   enum dma_data_direction dir)
{
	while (sg) {
		dma_unmap_sg(dev, sg, 1, dir);
		sg = scatterwalk_sg_next(sg);
	}
}

static void talitos_sg_unmap(struct device *dev,
			     struct talitos_edesc *edesc,
			     struct scatterlist *src,
			     struct scatterlist *dst)
{
	unsigned int src_nents = edesc->src_nents ? : 1;
	unsigned int dst_nents = edesc->dst_nents ? : 1;

	if (src != dst) {
		if (edesc->src_is_chained)
			talitos_unmap_sg_chain(dev, src, DMA_TO_DEVICE);
		else
			dma_unmap_sg(dev, src, src_nents, DMA_TO_DEVICE);

		if (edesc->dst_is_chained)
			talitos_unmap_sg_chain(dev, dst, DMA_FROM_DEVICE);
		else
			dma_unmap_sg(dev, dst, dst_nents, DMA_FROM_DEVICE);
	} else
		if (edesc->src_is_chained)
			talitos_unmap_sg_chain(dev, src, DMA_BIDIRECTIONAL);
		else
			dma_unmap_sg(dev, src, src_nents, DMA_BIDIRECTIONAL);
}

static void ipsec_esp_unmap(struct device *dev,
			    struct talitos_edesc *edesc,
			    struct aead_request *areq)
{
	unmap_single_talitos_ptr(dev, &edesc->desc.ptr[6], DMA_FROM_DEVICE);
	unmap_single_talitos_ptr(dev, &edesc->desc.ptr[3], DMA_TO_DEVICE);
	unmap_single_talitos_ptr(dev, &edesc->desc.ptr[2], DMA_TO_DEVICE);
	unmap_single_talitos_ptr(dev, &edesc->desc.ptr[0], DMA_TO_DEVICE);

	dma_unmap_sg(dev, areq->assoc, 1, DMA_TO_DEVICE);

	talitos_sg_unmap(dev, edesc, areq->src, areq->dst);

	if (edesc->dma_len)
		dma_unmap_single(dev, edesc->dma_link_tbl, edesc->dma_len,
				 DMA_BIDIRECTIONAL);
}

static void ipsec_esp_encrypt_done(struct device *dev,
				   struct talitos_desc *desc, void *context,
				   int err)
{
	struct aead_request *areq = context;
	struct crypto_aead *authenc = crypto_aead_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);
	struct talitos_edesc *edesc;
	struct scatterlist *sg;
	void *icvdata;

	edesc = container_of(desc, struct talitos_edesc, desc);

	ipsec_esp_unmap(dev, edesc, areq);

	if (edesc->dma_len) {
		icvdata = &edesc->link_tbl[edesc->src_nents +
					   edesc->dst_nents + 2];
		sg = sg_last(areq->dst, edesc->dst_nents);
		memcpy((char *)sg_virt(sg) + sg->length - ctx->authsize,
		       icvdata, ctx->authsize);
	}

	kfree(edesc);

	aead_request_complete(areq, err);
}

static void ipsec_esp_decrypt_swauth_done(struct device *dev,
					  struct talitos_desc *desc,
					  void *context, int err)
{
	struct aead_request *req = context;
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);
	struct talitos_edesc *edesc;
	struct scatterlist *sg;
	void *icvdata;

	edesc = container_of(desc, struct talitos_edesc, desc);

	ipsec_esp_unmap(dev, edesc, req);

	if (!err) {
		 
		if (edesc->dma_len)
			icvdata = &edesc->link_tbl[edesc->src_nents +
						   edesc->dst_nents + 2];
		else
			icvdata = &edesc->link_tbl[0];

		sg = sg_last(req->dst, edesc->dst_nents ? : 1);
		err = memcmp(icvdata, (char *)sg_virt(sg) + sg->length -
			     ctx->authsize, ctx->authsize) ? -EBADMSG : 0;
	}

	kfree(edesc);

	aead_request_complete(req, err);
}

static void ipsec_esp_decrypt_hwauth_done(struct device *dev,
					  struct talitos_desc *desc,
					  void *context, int err)
{
	struct aead_request *req = context;
	struct talitos_edesc *edesc;

	edesc = container_of(desc, struct talitos_edesc, desc);

	ipsec_esp_unmap(dev, edesc, req);

	if (!err && ((desc->hdr_lo & DESC_HDR_LO_ICCR1_MASK) !=
		     DESC_HDR_LO_ICCR1_PASS))
		err = -EBADMSG;

	kfree(edesc);

	aead_request_complete(req, err);
}

static int sg_to_link_tbl(struct scatterlist *sg, int sg_count,
			   int cryptlen, struct talitos_ptr *link_tbl_ptr)
{
	int n_sg = sg_count;

	while (n_sg--) {
		to_talitos_ptr(link_tbl_ptr, sg_dma_address(sg));
		link_tbl_ptr->len = cpu_to_be16(sg_dma_len(sg));
		link_tbl_ptr->j_extent = 0;
		link_tbl_ptr++;
		cryptlen -= sg_dma_len(sg);
		sg = scatterwalk_sg_next(sg);
	}

	link_tbl_ptr--;
	while (be16_to_cpu(link_tbl_ptr->len) <= (-cryptlen)) {
		 
		cryptlen += be16_to_cpu(link_tbl_ptr->len);
		link_tbl_ptr->len = 0;
		sg_count--;
		link_tbl_ptr--;
	}
	link_tbl_ptr->len = cpu_to_be16(be16_to_cpu(link_tbl_ptr->len)
					+ cryptlen);

	link_tbl_ptr->j_extent = DESC_PTR_LNKTBL_RETURN;

	return sg_count;
}

static int ipsec_esp(struct talitos_edesc *edesc, struct aead_request *areq,
		     u8 *giv, u64 seq,
		     void (*callback) (struct device *dev,
				       struct talitos_desc *desc,
				       void *context, int error))
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_aead_ctx(aead);
	struct device *dev = ctx->dev;
	struct talitos_desc *desc = &edesc->desc;
	unsigned int cryptlen = areq->cryptlen;
	unsigned int authsize = ctx->authsize;
	unsigned int ivsize = crypto_aead_ivsize(aead);
	int sg_count, ret;
	int sg_link_tbl_len;

	map_single_talitos_ptr(dev, &desc->ptr[0], ctx->authkeylen, &ctx->key,
			       0, DMA_TO_DEVICE);
	 
	map_single_talitos_ptr(dev, &desc->ptr[1], areq->assoclen + ivsize,
			       sg_virt(areq->assoc), 0, DMA_TO_DEVICE);
	 
	map_single_talitos_ptr(dev, &desc->ptr[2], ivsize, giv ?: areq->iv, 0,
			       DMA_TO_DEVICE);

	map_single_talitos_ptr(dev, &desc->ptr[3], ctx->enckeylen,
			       (char *)&ctx->key + ctx->authkeylen, 0,
			       DMA_TO_DEVICE);

	desc->ptr[4].len = cpu_to_be16(cryptlen);
	desc->ptr[4].j_extent = authsize;

	sg_count = talitos_map_sg(dev, areq->src, edesc->src_nents ? : 1,
				  (areq->src == areq->dst) ? DMA_BIDIRECTIONAL
							   : DMA_TO_DEVICE,
				  edesc->src_is_chained);

	if (sg_count == 1) {
		to_talitos_ptr(&desc->ptr[4], sg_dma_address(areq->src));
	} else {
		sg_link_tbl_len = cryptlen;

		if (edesc->desc.hdr & DESC_HDR_MODE1_MDEU_CICV)
			sg_link_tbl_len = cryptlen + authsize;

		sg_count = sg_to_link_tbl(areq->src, sg_count, sg_link_tbl_len,
					  &edesc->link_tbl[0]);
		if (sg_count > 1) {
			desc->ptr[4].j_extent |= DESC_PTR_LNKTBL_JUMP;
			to_talitos_ptr(&desc->ptr[4], edesc->dma_link_tbl);
			dma_sync_single_for_device(dev, edesc->dma_link_tbl,
						   edesc->dma_len,
						   DMA_BIDIRECTIONAL);
		} else {
			 
			to_talitos_ptr(&desc->ptr[4],
				       sg_dma_address(areq->src));
		}
	}

	desc->ptr[5].len = cpu_to_be16(cryptlen);
	desc->ptr[5].j_extent = authsize;

	if (areq->src != areq->dst)
		sg_count = talitos_map_sg(dev, areq->dst,
					  edesc->dst_nents ? : 1,
					  DMA_FROM_DEVICE,
					  edesc->dst_is_chained);

	if (sg_count == 1) {
		to_talitos_ptr(&desc->ptr[5], sg_dma_address(areq->dst));
	} else {
		struct talitos_ptr *link_tbl_ptr =
			&edesc->link_tbl[edesc->src_nents + 1];

		to_talitos_ptr(&desc->ptr[5], edesc->dma_link_tbl +
			       (edesc->src_nents + 1) *
			       sizeof(struct talitos_ptr));
		sg_count = sg_to_link_tbl(areq->dst, sg_count, cryptlen,
					  link_tbl_ptr);

		link_tbl_ptr += sg_count - 1;
		link_tbl_ptr->j_extent = 0;
		sg_count++;
		link_tbl_ptr++;
		link_tbl_ptr->j_extent = DESC_PTR_LNKTBL_RETURN;
		link_tbl_ptr->len = cpu_to_be16(authsize);

		to_talitos_ptr(link_tbl_ptr, edesc->dma_link_tbl +
			       (edesc->src_nents + edesc->dst_nents + 2) *
			       sizeof(struct talitos_ptr));
		desc->ptr[5].j_extent |= DESC_PTR_LNKTBL_JUMP;
		dma_sync_single_for_device(ctx->dev, edesc->dma_link_tbl,
					   edesc->dma_len, DMA_BIDIRECTIONAL);
	}

	map_single_talitos_ptr(dev, &desc->ptr[6], ivsize, ctx->iv, 0,
			       DMA_FROM_DEVICE);

	ret = talitos_submit(dev, desc, callback, areq);
	if (ret != -EINPROGRESS) {
		ipsec_esp_unmap(dev, edesc, areq);
		kfree(edesc);
	}
	return ret;
}

static int sg_count(struct scatterlist *sg_list, int nbytes, int *chained)
{
	struct scatterlist *sg = sg_list;
	int sg_nents = 0;

	*chained = 0;
	while (nbytes > 0) {
		sg_nents++;
		nbytes -= sg->length;
		if (!sg_is_last(sg) && (sg + 1)->length == 0)
			*chained = 1;
		sg = scatterwalk_sg_next(sg);
	}

	return sg_nents;
}

static struct talitos_edesc *talitos_edesc_alloc(struct device *dev,
						 struct scatterlist *src,
						 struct scatterlist *dst,
						 unsigned int cryptlen,
						 unsigned int authsize,
						 int icv_stashing,
						 u32 cryptoflags)
{
	struct talitos_edesc *edesc;
	int src_nents, dst_nents, alloc_len, dma_len;
	int src_chained, dst_chained = 0;
	gfp_t flags = cryptoflags & CRYPTO_TFM_REQ_MAY_SLEEP ? GFP_KERNEL :
		      GFP_ATOMIC;

	if (cryptlen + authsize > TALITOS_MAX_DATA_LEN) {
		dev_err(dev, "length exceeds h/w max limit\n");
		return ERR_PTR(-EINVAL);
	}

	src_nents = sg_count(src, cryptlen + authsize, &src_chained);
	src_nents = (src_nents == 1) ? 0 : src_nents;

	if (dst == src) {
		dst_nents = src_nents;
	} else {
		dst_nents = sg_count(dst, cryptlen + authsize, &dst_chained);
		dst_nents = (dst_nents == 1) ? 0 : dst_nents;
	}

	alloc_len = sizeof(struct talitos_edesc);
	if (src_nents || dst_nents) {
		dma_len = (src_nents + dst_nents + 2) *
				 sizeof(struct talitos_ptr) + authsize;
		alloc_len += dma_len;
	} else {
		dma_len = 0;
		alloc_len += icv_stashing ? authsize : 0;
	}

	edesc = kmalloc(alloc_len, GFP_DMA | flags);
	if (!edesc) {
		dev_err(dev, "could not allocate edescriptor\n");
		return ERR_PTR(-ENOMEM);
	}

	edesc->src_nents = src_nents;
	edesc->dst_nents = dst_nents;
	edesc->src_is_chained = src_chained;
	edesc->dst_is_chained = dst_chained;
	edesc->dma_len = dma_len;
	edesc->dma_link_tbl = dma_map_single(dev, &edesc->link_tbl[0],
					     edesc->dma_len, DMA_BIDIRECTIONAL);

	return edesc;
}

static struct talitos_edesc *aead_edesc_alloc(struct aead_request *areq,
					      int icv_stashing)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);

	return talitos_edesc_alloc(ctx->dev, areq->src, areq->dst,
				   areq->cryptlen, ctx->authsize, icv_stashing,
				   areq->base.flags);
}

static int aead_encrypt(struct aead_request *req)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);
	struct talitos_edesc *edesc;

	edesc = aead_edesc_alloc(req, 0);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	edesc->desc.hdr = ctx->desc_hdr_template | DESC_HDR_MODE0_ENCRYPT;

	return ipsec_esp(edesc, req, NULL, 0, ipsec_esp_encrypt_done);
}

static int aead_decrypt(struct aead_request *req)
{
	struct crypto_aead *authenc = crypto_aead_reqtfm(req);
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);
	unsigned int authsize = ctx->authsize;
	struct talitos_private *priv = dev_get_drvdata(ctx->dev);
	struct talitos_edesc *edesc;
	struct scatterlist *sg;
	void *icvdata;

	req->cryptlen -= authsize;

	edesc = aead_edesc_alloc(req, 1);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	if ((priv->features & TALITOS_FTR_HW_AUTH_CHECK) &&
	    ((!edesc->src_nents && !edesc->dst_nents) ||
	     priv->features & TALITOS_FTR_SRC_LINK_TBL_LEN_INCLUDES_EXTENT)) {

		edesc->desc.hdr = ctx->desc_hdr_template |
				  DESC_HDR_DIR_INBOUND |
				  DESC_HDR_MODE1_MDEU_CICV;

		edesc->desc.hdr_lo = 0;

		return ipsec_esp(edesc, req, NULL, 0,
				 ipsec_esp_decrypt_hwauth_done);

	}

	edesc->desc.hdr = ctx->desc_hdr_template | DESC_HDR_DIR_INBOUND;

	if (edesc->dma_len)
		icvdata = &edesc->link_tbl[edesc->src_nents +
					   edesc->dst_nents + 2];
	else
		icvdata = &edesc->link_tbl[0];

	sg = sg_last(req->src, edesc->src_nents ? : 1);

	memcpy(icvdata, (char *)sg_virt(sg) + sg->length - ctx->authsize,
	       ctx->authsize);

	return ipsec_esp(edesc, req, NULL, 0, ipsec_esp_decrypt_swauth_done);
}

static int aead_givencrypt(struct aead_givcrypt_request *req)
{
	struct aead_request *areq = &req->areq;
	struct crypto_aead *authenc = crypto_aead_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_aead_ctx(authenc);
	struct talitos_edesc *edesc;

	edesc = aead_edesc_alloc(areq, 0);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	edesc->desc.hdr = ctx->desc_hdr_template | DESC_HDR_MODE0_ENCRYPT;

	memcpy(req->giv, ctx->iv, crypto_aead_ivsize(authenc));
	 
	*(__be64 *)req->giv ^= cpu_to_be64(req->seq);

	return ipsec_esp(edesc, areq, req->giv, req->seq,
			 ipsec_esp_encrypt_done);
}

static int ablkcipher_setkey(struct crypto_ablkcipher *cipher,
			     const u8 *key, unsigned int keylen)
{
	struct talitos_ctx *ctx = crypto_ablkcipher_ctx(cipher);
	struct ablkcipher_alg *alg = crypto_ablkcipher_alg(cipher);

	if (keylen > TALITOS_MAX_KEY_SIZE)
		goto badkey;

	if (keylen < alg->min_keysize || keylen > alg->max_keysize)
		goto badkey;

	memcpy(&ctx->key, key, keylen);
	ctx->keylen = keylen;

	return 0;

badkey:
	crypto_ablkcipher_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static void common_nonsnoop_unmap(struct device *dev,
				  struct talitos_edesc *edesc,
				  struct ablkcipher_request *areq)
{
	unmap_single_talitos_ptr(dev, &edesc->desc.ptr[5], DMA_FROM_DEVICE);
	unmap_single_talitos_ptr(dev, &edesc->desc.ptr[2], DMA_TO_DEVICE);
	unmap_single_talitos_ptr(dev, &edesc->desc.ptr[1], DMA_TO_DEVICE);

	talitos_sg_unmap(dev, edesc, areq->src, areq->dst);

	if (edesc->dma_len)
		dma_unmap_single(dev, edesc->dma_link_tbl, edesc->dma_len,
				 DMA_BIDIRECTIONAL);
}

static void ablkcipher_done(struct device *dev,
			    struct talitos_desc *desc, void *context,
			    int err)
{
	struct ablkcipher_request *areq = context;
	struct talitos_edesc *edesc;

	edesc = container_of(desc, struct talitos_edesc, desc);

	common_nonsnoop_unmap(dev, edesc, areq);

	kfree(edesc);

	areq->base.complete(&areq->base, err);
}

static int common_nonsnoop(struct talitos_edesc *edesc,
			   struct ablkcipher_request *areq,
			   u8 *giv,
			   void (*callback) (struct device *dev,
					     struct talitos_desc *desc,
					     void *context, int error))
{
	struct crypto_ablkcipher *cipher = crypto_ablkcipher_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_ablkcipher_ctx(cipher);
	struct device *dev = ctx->dev;
	struct talitos_desc *desc = &edesc->desc;
	unsigned int cryptlen = areq->nbytes;
	unsigned int ivsize;
	int sg_count, ret;

	desc->ptr[0].len = 0;
	to_talitos_ptr(&desc->ptr[0], 0);
	desc->ptr[0].j_extent = 0;

	ivsize = crypto_ablkcipher_ivsize(cipher);
	map_single_talitos_ptr(dev, &desc->ptr[1], ivsize, giv ?: areq->info, 0,
			       DMA_TO_DEVICE);

	map_single_talitos_ptr(dev, &desc->ptr[2], ctx->keylen,
			       (char *)&ctx->key, 0, DMA_TO_DEVICE);

	desc->ptr[3].len = cpu_to_be16(cryptlen);
	desc->ptr[3].j_extent = 0;

	sg_count = talitos_map_sg(dev, areq->src, edesc->src_nents ? : 1,
				  (areq->src == areq->dst) ? DMA_BIDIRECTIONAL
							   : DMA_TO_DEVICE,
				  edesc->src_is_chained);

	if (sg_count == 1) {
		to_talitos_ptr(&desc->ptr[3], sg_dma_address(areq->src));
	} else {
		sg_count = sg_to_link_tbl(areq->src, sg_count, cryptlen,
					  &edesc->link_tbl[0]);
		if (sg_count > 1) {
			to_talitos_ptr(&desc->ptr[3], edesc->dma_link_tbl);
			desc->ptr[3].j_extent |= DESC_PTR_LNKTBL_JUMP;
			dma_sync_single_for_device(dev, edesc->dma_link_tbl,
						   edesc->dma_len,
						   DMA_BIDIRECTIONAL);
		} else {
			 
			to_talitos_ptr(&desc->ptr[3],
				       sg_dma_address(areq->src));
		}
	}

	desc->ptr[4].len = cpu_to_be16(cryptlen);
	desc->ptr[4].j_extent = 0;

	if (areq->src != areq->dst)
		sg_count = talitos_map_sg(dev, areq->dst,
					  edesc->dst_nents ? : 1,
					  DMA_FROM_DEVICE,
					  edesc->dst_is_chained);

	if (sg_count == 1) {
		to_talitos_ptr(&desc->ptr[4], sg_dma_address(areq->dst));
	} else {
		struct talitos_ptr *link_tbl_ptr =
			&edesc->link_tbl[edesc->src_nents + 1];

		to_talitos_ptr(&desc->ptr[4], edesc->dma_link_tbl +
					      (edesc->src_nents + 1) *
					      sizeof(struct talitos_ptr));
		desc->ptr[4].j_extent |= DESC_PTR_LNKTBL_JUMP;
		sg_count = sg_to_link_tbl(areq->dst, sg_count, cryptlen,
					  link_tbl_ptr);
		dma_sync_single_for_device(ctx->dev, edesc->dma_link_tbl,
					   edesc->dma_len, DMA_BIDIRECTIONAL);
	}

	map_single_talitos_ptr(dev, &desc->ptr[5], ivsize, ctx->iv, 0,
			       DMA_FROM_DEVICE);

	desc->ptr[6].len = 0;
	to_talitos_ptr(&desc->ptr[6], 0);
	desc->ptr[6].j_extent = 0;

	ret = talitos_submit(dev, desc, callback, areq);
	if (ret != -EINPROGRESS) {
		common_nonsnoop_unmap(dev, edesc, areq);
		kfree(edesc);
	}
	return ret;
}

static struct talitos_edesc *ablkcipher_edesc_alloc(struct ablkcipher_request *
						    areq)
{
	struct crypto_ablkcipher *cipher = crypto_ablkcipher_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_ablkcipher_ctx(cipher);

	return talitos_edesc_alloc(ctx->dev, areq->src, areq->dst, areq->nbytes,
				   0, 0, areq->base.flags);
}

static int ablkcipher_encrypt(struct ablkcipher_request *areq)
{
	struct crypto_ablkcipher *cipher = crypto_ablkcipher_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_ablkcipher_ctx(cipher);
	struct talitos_edesc *edesc;

	edesc = ablkcipher_edesc_alloc(areq);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	edesc->desc.hdr = ctx->desc_hdr_template | DESC_HDR_MODE0_ENCRYPT;

	return common_nonsnoop(edesc, areq, NULL, ablkcipher_done);
}

static int ablkcipher_decrypt(struct ablkcipher_request *areq)
{
	struct crypto_ablkcipher *cipher = crypto_ablkcipher_reqtfm(areq);
	struct talitos_ctx *ctx = crypto_ablkcipher_ctx(cipher);
	struct talitos_edesc *edesc;

	edesc = ablkcipher_edesc_alloc(areq);
	if (IS_ERR(edesc))
		return PTR_ERR(edesc);

	edesc->desc.hdr = ctx->desc_hdr_template | DESC_HDR_DIR_INBOUND;

	return common_nonsnoop(edesc, areq, NULL, ablkcipher_done);
}

struct talitos_alg_template {
	struct crypto_alg alg;
	__be32 desc_hdr_template;
};

static struct talitos_alg_template driver_algs[] = {
	 
	{
		.alg = {
			.cra_name = "authenc(hmac(sha1),cbc(aes))",
			.cra_driver_name = "authenc-hmac-sha1-cbc-aes-talitos",
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_aead_type,
			.cra_aead = {
				.setkey = aead_setkey,
				.setauthsize = aead_setauthsize,
				.encrypt = aead_encrypt,
				.decrypt = aead_decrypt,
				.givencrypt = aead_givencrypt,
				.geniv = "<built-in>",
				.ivsize = AES_BLOCK_SIZE,
				.maxauthsize = SHA1_DIGEST_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_IPSEC_ESP |
			             DESC_HDR_SEL0_AESU |
		                     DESC_HDR_MODE0_AESU_CBC |
		                     DESC_HDR_SEL1_MDEUA |
		                     DESC_HDR_MODE1_MDEU_INIT |
		                     DESC_HDR_MODE1_MDEU_PAD |
		                     DESC_HDR_MODE1_MDEU_SHA1_HMAC,
	},
	{
		.alg = {
			.cra_name = "authenc(hmac(sha1),cbc(des3_ede))",
			.cra_driver_name = "authenc-hmac-sha1-cbc-3des-talitos",
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_aead_type,
			.cra_aead = {
				.setkey = aead_setkey,
				.setauthsize = aead_setauthsize,
				.encrypt = aead_encrypt,
				.decrypt = aead_decrypt,
				.givencrypt = aead_givencrypt,
				.geniv = "<built-in>",
				.ivsize = DES3_EDE_BLOCK_SIZE,
				.maxauthsize = SHA1_DIGEST_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_IPSEC_ESP |
			             DESC_HDR_SEL0_DEU |
		                     DESC_HDR_MODE0_DEU_CBC |
		                     DESC_HDR_MODE0_DEU_3DES |
		                     DESC_HDR_SEL1_MDEUA |
		                     DESC_HDR_MODE1_MDEU_INIT |
		                     DESC_HDR_MODE1_MDEU_PAD |
		                     DESC_HDR_MODE1_MDEU_SHA1_HMAC,
	},
	{
		.alg = {
			.cra_name = "authenc(hmac(sha256),cbc(aes))",
			.cra_driver_name = "authenc-hmac-sha256-cbc-aes-talitos",
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_aead_type,
			.cra_aead = {
				.setkey = aead_setkey,
				.setauthsize = aead_setauthsize,
				.encrypt = aead_encrypt,
				.decrypt = aead_decrypt,
				.givencrypt = aead_givencrypt,
				.geniv = "<built-in>",
				.ivsize = AES_BLOCK_SIZE,
				.maxauthsize = SHA256_DIGEST_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_IPSEC_ESP |
			             DESC_HDR_SEL0_AESU |
		                     DESC_HDR_MODE0_AESU_CBC |
		                     DESC_HDR_SEL1_MDEUA |
		                     DESC_HDR_MODE1_MDEU_INIT |
		                     DESC_HDR_MODE1_MDEU_PAD |
		                     DESC_HDR_MODE1_MDEU_SHA256_HMAC,
	},
	{
		.alg = {
			.cra_name = "authenc(hmac(sha256),cbc(des3_ede))",
			.cra_driver_name = "authenc-hmac-sha256-cbc-3des-talitos",
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_aead_type,
			.cra_aead = {
				.setkey = aead_setkey,
				.setauthsize = aead_setauthsize,
				.encrypt = aead_encrypt,
				.decrypt = aead_decrypt,
				.givencrypt = aead_givencrypt,
				.geniv = "<built-in>",
				.ivsize = DES3_EDE_BLOCK_SIZE,
				.maxauthsize = SHA256_DIGEST_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_IPSEC_ESP |
			             DESC_HDR_SEL0_DEU |
		                     DESC_HDR_MODE0_DEU_CBC |
		                     DESC_HDR_MODE0_DEU_3DES |
		                     DESC_HDR_SEL1_MDEUA |
		                     DESC_HDR_MODE1_MDEU_INIT |
		                     DESC_HDR_MODE1_MDEU_PAD |
		                     DESC_HDR_MODE1_MDEU_SHA256_HMAC,
	},
	{
		.alg = {
			.cra_name = "authenc(hmac(md5),cbc(aes))",
			.cra_driver_name = "authenc-hmac-md5-cbc-aes-talitos",
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_aead_type,
			.cra_aead = {
				.setkey = aead_setkey,
				.setauthsize = aead_setauthsize,
				.encrypt = aead_encrypt,
				.decrypt = aead_decrypt,
				.givencrypt = aead_givencrypt,
				.geniv = "<built-in>",
				.ivsize = AES_BLOCK_SIZE,
				.maxauthsize = MD5_DIGEST_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_IPSEC_ESP |
			             DESC_HDR_SEL0_AESU |
		                     DESC_HDR_MODE0_AESU_CBC |
		                     DESC_HDR_SEL1_MDEUA |
		                     DESC_HDR_MODE1_MDEU_INIT |
		                     DESC_HDR_MODE1_MDEU_PAD |
		                     DESC_HDR_MODE1_MDEU_MD5_HMAC,
	},
	{
		.alg = {
			.cra_name = "authenc(hmac(md5),cbc(des3_ede))",
			.cra_driver_name = "authenc-hmac-md5-cbc-3des-talitos",
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_aead_type,
			.cra_aead = {
				.setkey = aead_setkey,
				.setauthsize = aead_setauthsize,
				.encrypt = aead_encrypt,
				.decrypt = aead_decrypt,
				.givencrypt = aead_givencrypt,
				.geniv = "<built-in>",
				.ivsize = DES3_EDE_BLOCK_SIZE,
				.maxauthsize = MD5_DIGEST_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_IPSEC_ESP |
			             DESC_HDR_SEL0_DEU |
		                     DESC_HDR_MODE0_DEU_CBC |
		                     DESC_HDR_MODE0_DEU_3DES |
		                     DESC_HDR_SEL1_MDEUA |
		                     DESC_HDR_MODE1_MDEU_INIT |
		                     DESC_HDR_MODE1_MDEU_PAD |
		                     DESC_HDR_MODE1_MDEU_MD5_HMAC,
	},
	 
	{
		.alg = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "cbc-aes-talitos",
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER |
                                     CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_ablkcipher_type,
			.cra_ablkcipher = {
				.setkey = ablkcipher_setkey,
				.encrypt = ablkcipher_encrypt,
				.decrypt = ablkcipher_decrypt,
				.geniv = "eseqiv",
				.min_keysize = AES_MIN_KEY_SIZE,
				.max_keysize = AES_MAX_KEY_SIZE,
				.ivsize = AES_BLOCK_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU |
				     DESC_HDR_SEL0_AESU |
				     DESC_HDR_MODE0_AESU_CBC,
	},
	{
		.alg = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "cbc-3des-talitos",
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER |
                                     CRYPTO_ALG_ASYNC,
			.cra_type = &crypto_ablkcipher_type,
			.cra_ablkcipher = {
				.setkey = ablkcipher_setkey,
				.encrypt = ablkcipher_encrypt,
				.decrypt = ablkcipher_decrypt,
				.geniv = "eseqiv",
				.min_keysize = DES3_EDE_KEY_SIZE,
				.max_keysize = DES3_EDE_KEY_SIZE,
				.ivsize = DES3_EDE_BLOCK_SIZE,
			}
		},
		.desc_hdr_template = DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU |
			             DESC_HDR_SEL0_DEU |
		                     DESC_HDR_MODE0_DEU_CBC |
		                     DESC_HDR_MODE0_DEU_3DES,
	}
};

struct talitos_crypto_alg {
	struct list_head entry;
	struct device *dev;
	__be32 desc_hdr_template;
	struct crypto_alg crypto_alg;
};

static int talitos_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct talitos_crypto_alg *talitos_alg;
	struct talitos_ctx *ctx = crypto_tfm_ctx(tfm);

	talitos_alg =  container_of(alg, struct talitos_crypto_alg, crypto_alg);

	ctx->dev = talitos_alg->dev;

	ctx->desc_hdr_template = talitos_alg->desc_hdr_template;

	get_random_bytes(ctx->iv, TALITOS_MAX_IV_LENGTH);

	return 0;
}

static int hw_supports(struct device *dev, __be32 desc_hdr_template)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	int ret;

	ret = (1 << DESC_TYPE(desc_hdr_template) & priv->desc_types) &&
	      (1 << PRIMARY_EU(desc_hdr_template) & priv->exec_units);

	if (SECONDARY_EU(desc_hdr_template))
		ret = ret && (1 << SECONDARY_EU(desc_hdr_template)
		              & priv->exec_units);

	return ret;
}

static int talitos_remove(struct of_device *ofdev)
{
	struct device *dev = &ofdev->dev;
	struct talitos_private *priv = dev_get_drvdata(dev);
	struct talitos_crypto_alg *t_alg, *n;
	int i;

	list_for_each_entry_safe(t_alg, n, &priv->alg_list, entry) {
		crypto_unregister_alg(&t_alg->crypto_alg);
		list_del(&t_alg->entry);
		kfree(t_alg);
	}

	if (hw_supports(dev, DESC_HDR_SEL0_RNG))
		talitos_unregister_rng(dev);

	for (i = 0; i < priv->num_channels; i++)
		if (priv->chan[i].fifo)
			kfree(priv->chan[i].fifo);

	kfree(priv->chan);

	if (priv->irq != NO_IRQ) {
		free_irq(priv->irq, dev);
		irq_dispose_mapping(priv->irq);
	}

	tasklet_kill(&priv->done_task);

	iounmap(priv->reg);
	if (priv->dma_dev_common.chancnt)
		talitos_unregister_async_xor(dev);

	dev_set_drvdata(dev, NULL);

	kfree(priv);

	return 0;
}

static struct talitos_crypto_alg *talitos_alg_alloc(struct device *dev,
						    struct talitos_alg_template
						           *template)
{
	struct talitos_crypto_alg *t_alg;
	struct crypto_alg *alg;

	t_alg = kzalloc(sizeof(struct talitos_crypto_alg), GFP_KERNEL);
	if (!t_alg)
		return ERR_PTR(-ENOMEM);

	alg = &t_alg->crypto_alg;
	*alg = template->alg;

	alg->cra_module = THIS_MODULE;
	alg->cra_init = talitos_cra_init;
	alg->cra_priority = TALITOS_CRA_PRIORITY;
	alg->cra_alignmask = 0;
	alg->cra_ctxsize = sizeof(struct talitos_ctx);

	t_alg->desc_hdr_template = template->desc_hdr_template;
	t_alg->dev = dev;

	return t_alg;
}

static int talitos_probe(struct of_device *ofdev,
			 const struct of_device_id *match)
{
	struct device *dev = &ofdev->dev;
	struct device_node *np = ofdev->node;
	struct talitos_private *priv;
	const unsigned int *prop;
	int i, err;

	priv = kzalloc(sizeof(struct talitos_private), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	dev_set_drvdata(dev, priv);

	priv->ofdev = ofdev;

	tasklet_init(&priv->done_task, talitos_done, (unsigned long)dev);

	INIT_LIST_HEAD(&priv->alg_list);

	priv->irq = irq_of_parse_and_map(np, 0);

	if (priv->irq == NO_IRQ) {
		dev_err(dev, "failed to map irq\n");
		err = -EINVAL;
		goto err_out;
	}

	err = request_irq(priv->irq, talitos_interrupt, 0,
			  dev_driver_string(dev), dev);
	if (err) {
		dev_err(dev, "failed to request irq %d\n", priv->irq);
		irq_dispose_mapping(priv->irq);
		priv->irq = NO_IRQ;
		goto err_out;
	}

	priv->reg = of_iomap(np, 0);
	if (!priv->reg) {
		dev_err(dev, "failed to of_iomap\n");
		err = -ENOMEM;
		goto err_out;
	}

#ifdef CONFIG_SYNO_MPC8533
	 
	prop = of_get_property(np, "num-channels", NULL);
	if (prop)
		priv->num_channels = *prop;

	prop = of_get_property(np, "channel-fifo-len", NULL);
	if (prop)
		priv->chfifo_len = *prop;

	prop = of_get_property(np, "exec-units-mask", NULL);
	if (prop)
		priv->exec_units = *prop;

	prop = of_get_property(np, "descriptor-types-mask", NULL);
	if (prop)
		priv->desc_types = *prop;
#else
	 
	prop = of_get_property(np, "fsl,num-channels", NULL);
	if (prop)
		priv->num_channels = *prop;

	prop = of_get_property(np, "fsl,channel-fifo-len", NULL);
	if (prop)
		priv->chfifo_len = *prop;

	prop = of_get_property(np, "fsl,exec-units-mask", NULL);
	if (prop)
		priv->exec_units = *prop;

	prop = of_get_property(np, "fsl,descriptor-types-mask", NULL);
	if (prop)
		priv->desc_types = *prop;
#endif

	if (!is_power_of_2(priv->num_channels) || !priv->chfifo_len ||
	    !priv->exec_units || !priv->desc_types) {
		dev_err(dev, "invalid property data in device tree node\n");
		err = -EINVAL;
		goto err_out;
	}

	if (of_device_is_compatible(np, "fsl,sec3.0"))
		priv->features |= TALITOS_FTR_SRC_LINK_TBL_LEN_INCLUDES_EXTENT;

#ifdef CONFIG_SYNO_MPC8533
	 
	priv->features |= TALITOS_FTR_HW_AUTH_CHECK;
#else
	if (of_device_is_compatible(np, "fsl,sec2.1"))
		priv->features |= TALITOS_FTR_HW_AUTH_CHECK;
#endif

	priv->chan = kzalloc(sizeof(struct talitos_channel) *
			     priv->num_channels, GFP_KERNEL);
	if (!priv->chan) {
		dev_err(dev, "failed to allocate channel management space\n");
		err = -ENOMEM;
		goto err_out;
	}

	for (i = 0; i < priv->num_channels; i++) {
		spin_lock_init(&priv->chan[i].head_lock);
		spin_lock_init(&priv->chan[i].tail_lock);
	}

	priv->fifo_len = roundup_pow_of_two(priv->chfifo_len);

	for (i = 0; i < priv->num_channels; i++) {
		priv->chan[i].fifo = kzalloc(sizeof(struct talitos_request) *
					     priv->fifo_len, GFP_KERNEL);
		if (!priv->chan[i].fifo) {
			dev_err(dev, "failed to allocate request fifo %d\n", i);
			err = -ENOMEM;
			goto err_out;
		}
	}

	for (i = 0; i < priv->num_channels; i++)
		atomic_set(&priv->chan[i].submit_count,
			   -(priv->chfifo_len - 1));

	dma_set_mask(dev, DMA_BIT_MASK(36));

	err = init_device(dev);
	if (err) {
		dev_err(dev, "failed to initialize device\n");
		goto err_out;
	}

	if (hw_supports(dev, DESC_HDR_SEL0_RNG)) {
		err = talitos_register_rng(dev);
		if (err) {
			dev_err(dev, "failed to register hwrng: %d\n", err);
			goto err_out;
		} else
			dev_info(dev, "hwrng\n");
	}

	if (hw_supports(dev, DESC_HDR_SEL0_AESU | DESC_HDR_TYPE_RAID_XOR)) {
		int max_xor_srcs = 3;
		if (of_device_is_compatible(np, "fsl,sec3.0"))
			max_xor_srcs = 6;

		err = talitos_register_async_tx(dev, max_xor_srcs);
		if (err) {
			dev_err(dev, "failed to register async_tx xor: %d\n",
				err);
			goto err_out;
		}
		dev_info(dev, "max_xor_srcs %d\n", max_xor_srcs);
	}

	for (i = 0; i < ARRAY_SIZE(driver_algs); i++) {
		if (hw_supports(dev, driver_algs[i].desc_hdr_template)) {
			struct talitos_crypto_alg *t_alg;

			t_alg = talitos_alg_alloc(dev, &driver_algs[i]);
			if (IS_ERR(t_alg)) {
				err = PTR_ERR(t_alg);
				goto err_out;
			}

			err = crypto_register_alg(&t_alg->crypto_alg);
			if (err) {
				dev_err(dev, "%s alg registration failed\n",
					t_alg->crypto_alg.cra_driver_name);
				kfree(t_alg);
			} else {
				list_add_tail(&t_alg->entry, &priv->alg_list);
				dev_info(dev, "%s\n",
					 t_alg->crypto_alg.cra_driver_name);
			}
		}
	}

	return 0;

err_out:
	talitos_remove(ofdev);

	return err;
}

#ifdef CONFIG_SYNO_QORIQ_TALITOS_PM_SUPPORT
#ifdef CONFIG_PM
static int talitos_suspend(struct of_device* dev, pm_message_t state)
{
	return 0;
}

static int talitos_resume(struct of_device* dev)
{
	init_device(&dev->dev);
	return 0;
}
#endif  
#endif

static struct of_device_id talitos_match[] = {
	{
#ifdef CONFIG_SYNO_MPC8533
		.type = "crypto",
		.compatible = "talitos",
#else
		.compatible = "fsl,sec2.0",
#endif
	},
	{},
};
MODULE_DEVICE_TABLE(of, talitos_match);

static struct of_platform_driver talitos_driver = {
	.name = "talitos",
	.match_table = talitos_match,
	.probe = talitos_probe,
	.remove = talitos_remove,
#ifdef CONFIG_SYNO_QORIQ_TALITOS_PM_SUPPORT
#ifdef CONFIG_PM
	.suspend = talitos_suspend,
	.resume = talitos_resume,
#endif
#endif
};

static int __init talitos_init(void)
{
	return of_register_platform_driver(&talitos_driver);
}
module_init(talitos_init);

static void __exit talitos_exit(void)
{
	of_unregister_platform_driver(&talitos_driver);
}
module_exit(talitos_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kim Phillips <kim.phillips@freescale.com>");
MODULE_DESCRIPTION("Freescale integrated security engine (SEC) driver");
