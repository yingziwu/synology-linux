#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/memory.h>
#include <plat/mv_xor.h>
#if defined(MY_DEF_HERE)
#include <linux/prefetch.h>
#endif
#include "mv_xor.h"

static void mv_xor_issue_pending(struct dma_chan *chan);

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
unsigned int dummy1[MV_XOR_MIN_BYTE_COUNT];
unsigned int dummy2[MV_XOR_MIN_BYTE_COUNT];
dma_addr_t dummy1_addr, dummy2_addr;
#ifdef CONFIG_PM
static struct mv_xor_save_regs saved_regs;
#endif
#endif

#define to_mv_xor_chan(chan)		\
	container_of(chan, struct mv_xor_chan, common)

#define to_mv_xor_device(dev)		\
	container_of(dev, struct mv_xor_device, common)

#define to_mv_xor_slot(tx)		\
	container_of(tx, struct mv_xor_desc_slot, async_tx)

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
static void mv_desc_init(struct mv_xor_desc_slot *desc, unsigned int srcs, unsigned long flags)
#else
static void mv_desc_init(struct mv_xor_desc_slot *desc, unsigned long flags)
#endif
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	u32 command = 0;
#endif

	hw_desc->status = (1 << 31);
	hw_desc->phy_next_desc = 0;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
	hw_desc->desc_command = (1 << 31);
#endif

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	if (flags & DMA_PREP_INTERRUPT)
		command = (1 << 31);

	if (desc->type == DMA_XOR)
		command |= (1 << srcs) - 1;

	hw_desc->desc_command = command;
#endif
}

static u32 mv_desc_get_dest_addr(struct mv_xor_desc_slot *desc)
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
	return hw_desc->phy_dest_addr;
}

static u32 mv_desc_get_src_addr(struct mv_xor_desc_slot *desc,
				int src_idx)
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
#if defined(MY_DEF_HERE)
	return hw_desc->phy_src_addr[mv_phy_src_idx(src_idx)];
#else
	return hw_desc->phy_src_addr[src_idx];
#endif
}

static void mv_desc_set_byte_count(struct mv_xor_desc_slot *desc,
				   u32 byte_count)
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
	hw_desc->byte_count = byte_count;
}

static void mv_desc_set_next_desc(struct mv_xor_desc_slot *desc,
				  u32 next_desc_addr)
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
	BUG_ON(hw_desc->phy_next_desc);
	hw_desc->phy_next_desc = next_desc_addr;
}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
static void mv_desc_clear_next_desc(struct mv_xor_desc_slot *desc)
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
	hw_desc->phy_next_desc = 0;
}
#endif

static void mv_desc_set_block_fill_val(struct mv_xor_desc_slot *desc, u32 val)
{
	desc->value = val;
}

static void mv_desc_set_dest_addr(struct mv_xor_desc_slot *desc,
				  dma_addr_t addr)
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
	hw_desc->phy_dest_addr = addr;
}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
static int mv_chan_memset_slot_count(size_t len)
{
	return 1;
}

#define mv_chan_memcpy_slot_count(c) mv_chan_memset_slot_count(c)

#endif

static void mv_desc_set_src_addr(struct mv_xor_desc_slot *desc,
				 int index, dma_addr_t addr)
{
	struct mv_xor_desc *hw_desc = desc->hw_desc;
#if defined(MY_DEF_HERE)
	hw_desc->phy_src_addr[mv_phy_src_idx(index)] = addr;
#else
	hw_desc->phy_src_addr[index] = addr;
#endif
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
	if (desc->type == DMA_XOR)
		hw_desc->desc_command |= (1 << index);
#endif
}

static u32 mv_chan_get_current_desc(struct mv_xor_chan *chan)
{
#if defined(MY_DEF_HERE)
	return readl_relaxed(XOR_CURR_DESC(chan));
#else
	return __raw_readl(XOR_CURR_DESC(chan));
#endif
}

static void mv_chan_set_next_descriptor(struct mv_xor_chan *chan,
					u32 next_desc_addr)
{
#if defined(MY_DEF_HERE)
	writel_relaxed(next_desc_addr, XOR_NEXT_DESC(chan));
#else
	__raw_writel(next_desc_addr, XOR_NEXT_DESC(chan));
#endif
}

static void mv_chan_set_dest_pointer(struct mv_xor_chan *chan, u32 desc_addr)
{
#if defined(MY_DEF_HERE)
	writel_relaxed(desc_addr, XOR_DEST_POINTER(chan));
#else
	__raw_writel(desc_addr, XOR_DEST_POINTER(chan));
#endif
}

static void mv_chan_set_block_size(struct mv_xor_chan *chan, u32 block_size)
{
#if defined(MY_DEF_HERE)
	writel_relaxed(block_size, XOR_BLOCK_SIZE(chan));
#else
	__raw_writel(block_size, XOR_BLOCK_SIZE(chan));
#endif
}

static void mv_chan_set_value(struct mv_xor_chan *chan, u32 value)
{
#if defined(MY_DEF_HERE)
	writel_relaxed(value, XOR_INIT_VALUE_LOW(chan));
	writel_relaxed(value, XOR_INIT_VALUE_HIGH(chan));
#else
	__raw_writel(value, XOR_INIT_VALUE_LOW(chan));
	__raw_writel(value, XOR_INIT_VALUE_HIGH(chan));
#endif
}

#if defined(MY_DEF_HERE)
static void mv_chan_set_outstanding_reads_value(struct mv_xor_chan *chan, u32 value)
{
	writel_relaxed(value, XOR_OUTSTANDING_RDEADS(chan));
}
#endif

static void mv_chan_unmask_interrupts(struct mv_xor_chan *chan)
{
#if defined(MY_DEF_HERE)
	u32 val = readl_relaxed(XOR_INTR_MASK(chan));
	val |= XOR_INTR_MASK_VALUE << (chan->idx * 16);
	writel_relaxed(val, XOR_INTR_MASK(chan));
#else
	u32 val = __raw_readl(XOR_INTR_MASK(chan));
	val |= XOR_INTR_MASK_VALUE << (chan->idx * 16);
	__raw_writel(val, XOR_INTR_MASK(chan));
#endif
}

static u32 mv_chan_get_intr_cause(struct mv_xor_chan *chan)
{
#if defined(MY_DEF_HERE)
	u32 intr_cause = readl_relaxed(XOR_INTR_CAUSE(chan));
#else
	u32 intr_cause = __raw_readl(XOR_INTR_CAUSE(chan));
#endif
	intr_cause = (intr_cause >> (chan->idx * 16)) & 0xFFFF;
	return intr_cause;
}

static int mv_is_err_intr(u32 intr_cause)
{
	if (intr_cause & ((1<<4)|(1<<5)|(1<<6)|(1<<7)|(1<<8)|(1<<9)))
		return 1;

	return 0;
}

static void mv_xor_device_clear_eoc_cause(struct mv_xor_chan *chan)
{
#if defined(MY_DEF_HERE)
	u32 val = ~(3 << (chan->idx * 16));
	dev_dbg(chan->device->common.dev, "%s, val 0x%08x\n", __func__, val);
	writel_relaxed(val, XOR_INTR_CAUSE(chan));
#else
#if defined(MY_DEF_HERE)
	u32 val = ~(3 << (chan->idx * 16));
#else
	u32 val = ~(1 << (chan->idx * 16));
#endif
	dev_dbg(chan->device->common.dev, "%s, val 0x%08x\n", __func__, val);
	__raw_writel(val, XOR_INTR_CAUSE(chan));
#endif  
}

static void mv_xor_device_clear_err_status(struct mv_xor_chan *chan)
{
	u32 val = 0xFFFF0000 >> (chan->idx * 16);
#if defined(MY_DEF_HERE)
	writel_relaxed(val, XOR_INTR_CAUSE(chan));
#else
	__raw_writel(val, XOR_INTR_CAUSE(chan));
#endif
}

static int mv_can_chain(struct mv_xor_desc_slot *desc)
{
	struct mv_xor_desc_slot *chain_old_tail = list_entry(
		desc->chain_node.prev, struct mv_xor_desc_slot, chain_node);

	if (chain_old_tail->type != desc->type)
		return 0;
	if (desc->type == DMA_MEMSET)
		return 0;

	return 1;
}

static void mv_set_mode(struct mv_xor_chan *chan,
			       enum dma_transaction_type type)
{
	u32 op_mode;
#if defined(MY_DEF_HERE)
	u32 config = readl_relaxed(XOR_CONFIG(chan));
#else
	u32 config = __raw_readl(XOR_CONFIG(chan));
#endif
	switch (type) {
	case DMA_XOR:
		op_mode = XOR_OPERATION_MODE_XOR;
		break;
	case DMA_MEMCPY:
		op_mode = XOR_OPERATION_MODE_MEMCPY;
		break;
	case DMA_MEMSET:
		op_mode = XOR_OPERATION_MODE_MEMSET;
		break;
	default:
		dev_printk(KERN_ERR, chan->device->common.dev,
			   "error: unsupported operation %d.\n",
			   type);
		BUG();
		return;
	}

	config &= ~0x7;
	config |= op_mode;

#if defined(MY_DEF_HERE)
#if defined(__BIG_ENDIAN)
	config |= XOR_DESCRIPTOR_SWAP;
#else
	config &= ~XOR_DESCRIPTOR_SWAP;
#endif

	writel_relaxed(config, XOR_CONFIG(chan));
#else
	__raw_writel(config, XOR_CONFIG(chan));
#endif
	chan->current_type = type;
}

static void mv_chan_activate(struct mv_xor_chan *chan)
{
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
	u32 activation;
#endif

	dev_dbg(chan->device->common.dev, " activate chan.\n");

#if defined(MY_DEF_HERE)
	writel_relaxed(1, XOR_ACTIVATION(chan));
#elif defined(MY_DEF_HERE)
	__raw_writel(1, XOR_ACTIVATION(chan));
#else
	activation = __raw_readl(XOR_ACTIVATION(chan));
	activation |= 0x1;
	__raw_writel(activation, XOR_ACTIVATION(chan));
#endif
}

static char mv_chan_is_busy(struct mv_xor_chan *chan)
{
#if defined(MY_DEF_HERE)
	u32 state = readl_relaxed(XOR_ACTIVATION(chan));
#else
	u32 state = __raw_readl(XOR_ACTIVATION(chan));
#endif
	state = (state >> 4) & 0x3;

	return (state == 1) ? 1 : 0;
}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
static int mv_chan_xor_slot_count(size_t len, int src_cnt)
{
	return 1;
}
#endif

static void mv_xor_free_slots(struct mv_xor_chan *mv_chan,
			      struct mv_xor_desc_slot *slot)
{
	dev_dbg(mv_chan->device->common.dev, "%s %d slot %p\n",
		__func__, __LINE__, slot);

	slot->slots_per_op = 0;

}

static void mv_xor_start_new_chain(struct mv_xor_chan *mv_chan,
				   struct mv_xor_desc_slot *sw_desc)
{
	dev_dbg(mv_chan->device->common.dev, "%s %d: sw_desc %p\n",
		__func__, __LINE__, sw_desc);
	if (sw_desc->type != mv_chan->current_type)
		mv_set_mode(mv_chan, sw_desc->type);

	if (sw_desc->type == DMA_MEMSET) {
		 
		struct mv_xor_desc *hw_desc = sw_desc->hw_desc;
		mv_chan_set_dest_pointer(mv_chan, hw_desc->phy_dest_addr);
		mv_chan_set_block_size(mv_chan, sw_desc->unmap_len);
		mv_chan_set_value(mv_chan, sw_desc->value);
	} else {
		 
		mv_chan_set_next_descriptor(mv_chan, sw_desc->async_tx.phys);
	}
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	mv_chan_activate(mv_chan);
#else
	mv_chan->pending += sw_desc->slot_cnt;
	mv_xor_issue_pending(&mv_chan->common);
#endif
}

static dma_cookie_t
mv_xor_run_tx_complete_actions(struct mv_xor_desc_slot *desc,
	struct mv_xor_chan *mv_chan, dma_cookie_t cookie)
{
	BUG_ON(desc->async_tx.cookie < 0);

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	dev_dbg(mv_chan->device->common.dev, "%s %d: desc %p\n",
		__func__, __LINE__, desc);
#endif
	if (desc->async_tx.cookie > 0) {
		cookie = desc->async_tx.cookie;

		if (desc->async_tx.callback)
			desc->async_tx.callback(
				desc->async_tx.callback_param);

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		if (desc->unmap_len) {
			struct mv_xor_desc_slot *unmap = desc;
#else
		if (desc->group_head && desc->unmap_len) {
			struct mv_xor_desc_slot *unmap = desc->group_head;
#endif
			struct device *dev =
				&mv_chan->device->pdev->dev;
			u32 len = unmap->unmap_len;
			enum dma_ctrl_flags flags = desc->async_tx.flags;
			u32 src_cnt;
			dma_addr_t addr;
			dma_addr_t dest;

			src_cnt = unmap->unmap_src_cnt;
			dest = mv_desc_get_dest_addr(unmap);
			if (!(flags & DMA_COMPL_SKIP_DEST_UNMAP)) {
				enum dma_data_direction dir;

				if (src_cnt > 1)  
					dir = DMA_BIDIRECTIONAL;
				else
					dir = DMA_FROM_DEVICE;
				dma_unmap_page(dev, dest, len, dir);
			}

			if (!(flags & DMA_COMPL_SKIP_SRC_UNMAP)) {
				while (src_cnt--) {
					addr = mv_desc_get_src_addr(unmap,
								    src_cnt);
					if (addr == dest)
						continue;
					dma_unmap_page(dev, addr, len,
						       DMA_TO_DEVICE);
				}
			}
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
			desc->group_head = NULL;
#endif
		}
	}

	dma_run_dependencies(&desc->async_tx);

	return cookie;
}

static int
mv_xor_clean_completed_slots(struct mv_xor_chan *mv_chan)
{
	struct mv_xor_desc_slot *iter, *_iter;

	dev_dbg(mv_chan->device->common.dev, "%s %d\n", __func__, __LINE__);
	list_for_each_entry_safe(iter, _iter, &mv_chan->completed_slots,
				 completed_node) {

		if (async_tx_test_ack(&iter->async_tx)) {
			list_del(&iter->completed_node);
			mv_xor_free_slots(mv_chan, iter);
		}
	}
	return 0;
}

static int
mv_xor_clean_slot(struct mv_xor_desc_slot *desc,
	struct mv_xor_chan *mv_chan)
{
	dev_dbg(mv_chan->device->common.dev, "%s %d: desc %p flags %d\n",
		__func__, __LINE__, desc, desc->async_tx.flags);
	list_del(&desc->chain_node);
	 
	if (!async_tx_test_ack(&desc->async_tx)) {
		 
		list_add_tail(&desc->completed_node, &mv_chan->completed_slots);
		return 0;
	}

	mv_xor_free_slots(mv_chan, desc);
	return 0;
}

static void __mv_xor_slot_cleanup(struct mv_xor_chan *mv_chan)
{
	struct mv_xor_desc_slot *iter, *_iter;
	dma_cookie_t cookie = 0;
	int busy = mv_chan_is_busy(mv_chan);
	u32 current_desc = mv_chan_get_current_desc(mv_chan);
	int seen_current = 0;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
	dev_dbg(mv_chan->device->common.dev, "%s %d\n", __func__, __LINE__);
#endif
	dev_dbg(mv_chan->device->common.dev, "current_desc %x\n", current_desc);
	mv_xor_clean_completed_slots(mv_chan);

	list_for_each_entry_safe(iter, _iter, &mv_chan->chain,
					chain_node) {
		prefetch(_iter);
		prefetch(&_iter->async_tx);

		if (seen_current)
			break;

		if (iter->async_tx.phys == current_desc) {
			seen_current = 1;
			if (busy)
				break;
		}

		cookie = mv_xor_run_tx_complete_actions(iter, mv_chan, cookie);

		if (mv_xor_clean_slot(iter, mv_chan))
			break;
	}

	if ((busy == 0) && !list_empty(&mv_chan->chain)) {
		struct mv_xor_desc_slot *chain_head;
		chain_head = list_entry(mv_chan->chain.next,
					struct mv_xor_desc_slot,
					chain_node);

		mv_xor_start_new_chain(mv_chan, chain_head);
	}

	if (cookie > 0)
		mv_chan->completed_cookie = cookie;
}

static void
mv_xor_slot_cleanup(struct mv_xor_chan *mv_chan)
{
	spin_lock_bh(&mv_chan->lock);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	dma_io_sync();
#endif
	__mv_xor_slot_cleanup(mv_chan);
	spin_unlock_bh(&mv_chan->lock);
}

static void mv_xor_tasklet(unsigned long data)
{
	struct mv_xor_chan *chan = (struct mv_xor_chan *) data;
	mv_xor_slot_cleanup(chan);
}

static struct mv_xor_desc_slot *
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
mv_xor_alloc_slots(struct mv_xor_chan *mv_chan)
#else
mv_xor_alloc_slots(struct mv_xor_chan *mv_chan, int num_slots,
		    int slots_per_op)
#endif
{
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	struct mv_xor_desc_slot *iter, *_iter;
	int retry = 0;
#else
	struct mv_xor_desc_slot *iter, *_iter, *alloc_start = NULL;
	LIST_HEAD(chain);
	int slots_found, retry = 0;
#endif

retry:
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
	slots_found = 0;
#endif
	if (retry == 0)
		iter = mv_chan->last_used;
	else
		iter = list_entry(&mv_chan->all_slots,
			struct mv_xor_desc_slot,
			slot_node);

	list_for_each_entry_safe_continue(
		iter, _iter, &mv_chan->all_slots, slot_node) {
		prefetch(_iter);
		prefetch(&_iter->async_tx);
		if (iter->slots_per_op) {
			 
			if (retry)
				break;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
			slots_found = 0;
#endif
			continue;
		}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		 
		async_tx_ack(&iter->async_tx);
		
		iter->async_tx.cookie = -EBUSY;
		iter->slots_per_op = 1;
		INIT_LIST_HEAD(&iter->chain_node);		
		mv_chan->last_used = iter;
		return iter;
#else
		 
		if (!slots_found++)
			alloc_start = iter;

		if (slots_found == num_slots) {
			struct mv_xor_desc_slot *alloc_tail = NULL;
			struct mv_xor_desc_slot *last_used = NULL;
			iter = alloc_start;
			while (num_slots) {
				int i;

				async_tx_ack(&iter->async_tx);

				list_add_tail(&iter->chain_node, &chain);
				alloc_tail = iter;
				iter->async_tx.cookie = 0;
				iter->slot_cnt = num_slots;
				iter->xor_check_result = NULL;
				for (i = 0; i < slots_per_op; i++) {
					iter->slots_per_op = slots_per_op - i;
					last_used = iter;
					iter = list_entry(iter->slot_node.next,
						struct mv_xor_desc_slot,
						slot_node);
				}
				num_slots -= slots_per_op;
			}
			alloc_tail->group_head = alloc_start;
			alloc_tail->async_tx.cookie = -EBUSY;
			list_splice(&chain, &alloc_tail->tx_list);
			mv_chan->last_used = last_used;
			mv_desc_clear_next_desc(alloc_start);
			mv_desc_clear_next_desc(alloc_tail);
			return alloc_tail;
		}
#endif
	}
	if (!retry++)
		goto retry;

	tasklet_schedule(&mv_chan->irq_tasklet);

	return NULL;
}

static dma_cookie_t
mv_desc_assign_cookie(struct mv_xor_chan *mv_chan,
		      struct mv_xor_desc_slot *desc)
{
	dma_cookie_t cookie = mv_chan->common.cookie;

	if (++cookie < 0)
		cookie = 1;
	mv_chan->common.cookie = desc->async_tx.cookie = cookie;
	return cookie;
}

static dma_cookie_t
mv_xor_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct mv_xor_desc_slot *sw_desc = to_mv_xor_slot(tx);
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(tx->chan);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	struct mv_xor_desc_slot *old_chain_tail;
#else
	struct mv_xor_desc_slot *grp_start, *old_chain_tail;
#endif
	dma_cookie_t cookie;
	int new_hw_chain = 1;

	dev_dbg(mv_chan->device->common.dev,
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		"%s sw_desc %p: async_tx %p, hw desc %x\n",
		__func__, sw_desc, &sw_desc->async_tx, sw_desc->async_tx.phys);
#else
		"%s sw_desc %p: async_tx %p\n",
		__func__, sw_desc, &sw_desc->async_tx);
#endif

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
	grp_start = sw_desc->group_head;
#endif

	spin_lock_bh(&mv_chan->lock);
	cookie = mv_desc_assign_cookie(mv_chan, sw_desc);

	if (list_empty(&mv_chan->chain))
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		list_add_tail(&sw_desc->chain_node, &mv_chan->chain);
#else
		list_splice_init(&sw_desc->tx_list, &mv_chan->chain);
#endif
	else {
		new_hw_chain = 0;

		old_chain_tail = list_entry(mv_chan->chain.prev,
					    struct mv_xor_desc_slot,
					    chain_node);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		list_add_tail(&sw_desc->chain_node, &mv_chan->chain);
#else
		list_splice_init(&grp_start->tx_list,
				 &old_chain_tail->chain_node);
#endif

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		if (!mv_can_chain(sw_desc))
#else
		if (!mv_can_chain(grp_start))
#endif
			goto submit_done;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		dev_dbg(mv_chan->device->common.dev, "Append to last desc %p hw %x\n",
			old_chain_tail, old_chain_tail->async_tx.phys);
#else
		dev_dbg(mv_chan->device->common.dev, "Append to last desc %x\n",
			old_chain_tail->async_tx.phys);
#endif

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		mv_desc_set_next_desc(old_chain_tail, sw_desc->async_tx.phys);
#else
		mv_desc_set_next_desc(old_chain_tail, grp_start->async_tx.phys);
#endif

		if (!mv_chan_is_busy(mv_chan)) {
			u32 current_desc = mv_chan_get_current_desc(mv_chan);
			 
			if (current_desc == old_chain_tail->async_tx.phys)
				new_hw_chain = 1;
		}
	}

	if (new_hw_chain)
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		mv_xor_start_new_chain(mv_chan, sw_desc);
#else
		mv_xor_start_new_chain(mv_chan, grp_start);
#endif

submit_done:
	spin_unlock_bh(&mv_chan->lock);

	return cookie;
}

static int mv_xor_alloc_chan_resources(struct dma_chan *chan)
{
	char *hw_desc;
	int idx;
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);
	struct mv_xor_desc_slot *slot = NULL;
	struct mv_xor_platform_data *plat_data =
		mv_chan->device->pdev->dev.platform_data;
	int num_descs_in_pool = plat_data->pool_size/MV_XOR_SLOT_SIZE;

	idx = mv_chan->slots_allocated;
	while (idx < num_descs_in_pool) {
		slot = kzalloc(sizeof(*slot), GFP_KERNEL);
		if (!slot) {
			printk(KERN_INFO "MV XOR Channel only initialized"
				" %d descriptor slots", idx);
			break;
		}
		hw_desc = (char *) mv_chan->device->dma_desc_pool_virt;
		slot->hw_desc = (void *) &hw_desc[idx * MV_XOR_SLOT_SIZE];

		dma_async_tx_descriptor_init(&slot->async_tx, chan);
		slot->async_tx.tx_submit = mv_xor_tx_submit;
		INIT_LIST_HEAD(&slot->chain_node);
		INIT_LIST_HEAD(&slot->slot_node);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#else
		INIT_LIST_HEAD(&slot->tx_list);
#endif
		hw_desc = (char *) mv_chan->device->dma_desc_pool;
		slot->async_tx.phys =
			(dma_addr_t) &hw_desc[idx * MV_XOR_SLOT_SIZE];
		slot->idx = idx++;

		spin_lock_bh(&mv_chan->lock);
		mv_chan->slots_allocated = idx;
		list_add_tail(&slot->slot_node, &mv_chan->all_slots);
		spin_unlock_bh(&mv_chan->lock);
	}

	if (mv_chan->slots_allocated && !mv_chan->last_used)
		mv_chan->last_used = list_entry(mv_chan->all_slots.next,
					struct mv_xor_desc_slot,
					slot_node);

	dev_dbg(mv_chan->device->common.dev,
		"allocated %d descriptor slots last_used: %p\n",
		mv_chan->slots_allocated, mv_chan->last_used);

	return mv_chan->slots_allocated ? : -ENOMEM;
}

static struct dma_async_tx_descriptor *
mv_xor_prep_dma_memcpy(struct dma_chan *chan, dma_addr_t dest, dma_addr_t src,
		size_t len, unsigned long flags)
{
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	struct mv_xor_desc_slot *sw_desc;
#else
	struct mv_xor_desc_slot *sw_desc, *grp_start;
	int slot_cnt;
#endif

	dev_dbg(mv_chan->device->common.dev,
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		"%s dest: %x src %x len: %u flags: %lx\n",
#else
		"%s dest: %x src %x len: %u flags: %ld\n",
#endif
		__func__, dest, src, len, flags);
	if (unlikely(len < MV_XOR_MIN_BYTE_COUNT))
		return NULL;

	BUG_ON(len > MV_XOR_MAX_BYTE_COUNT);

	spin_lock_bh(&mv_chan->lock);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	sw_desc = mv_xor_alloc_slots(mv_chan);
#else
	slot_cnt = mv_chan_memcpy_slot_count(len);
	sw_desc = mv_xor_alloc_slots(mv_chan, slot_cnt, 1);
#endif

	if (sw_desc) {
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		sw_desc->type = DMA_XOR;
#else
		sw_desc->type = DMA_MEMCPY;
#endif
		sw_desc->async_tx.flags = flags;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		mv_desc_init(sw_desc, 1, flags);
		mv_desc_set_byte_count(sw_desc, len);
		mv_desc_set_dest_addr(sw_desc, dest);
		mv_desc_set_src_addr(sw_desc, 0, src);
#else
		grp_start = sw_desc->group_head;
		mv_desc_init(grp_start, flags);
		mv_desc_set_byte_count(grp_start, len);
		mv_desc_set_dest_addr(sw_desc->group_head, dest);
		mv_desc_set_src_addr(grp_start, 0, src);
#endif
		sw_desc->unmap_src_cnt = 1;
		sw_desc->unmap_len = len;
	}
	spin_unlock_bh(&mv_chan->lock);

	dev_dbg(mv_chan->device->common.dev,
		"%s sw_desc %p async_tx %p\n",
		__func__, sw_desc, sw_desc ? &sw_desc->async_tx : 0);

	return sw_desc ? &sw_desc->async_tx : NULL;
}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
struct dma_async_tx_descriptor *
mv_xor_prep_dma_interrupt(struct dma_chan *chan, unsigned long flags)
{
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);
	struct mv_xor_desc_slot *sw_desc;

	dev_dbg(mv_chan->device->common.dev,
		"%s flags: %lx\n", __func__, flags);

	spin_lock_bh(&mv_chan->lock);

	sw_desc = mv_xor_alloc_slots(mv_chan);
	if (sw_desc) {
		sw_desc->type = DMA_XOR;
		sw_desc->async_tx.flags = flags;
		mv_desc_init(sw_desc, 1, DMA_PREP_INTERRUPT);
		mv_desc_set_byte_count(sw_desc, MV_XOR_MIN_BYTE_COUNT);
		mv_desc_set_dest_addr(sw_desc, dummy1_addr);
		mv_desc_set_src_addr(sw_desc, 0, dummy2_addr);
		sw_desc->unmap_len = 0;
	}
	spin_unlock_bh(&mv_chan->lock);
	dev_dbg(mv_chan->device->common.dev, "%s sw_desc %p async_tx %p\n",
		__func__, sw_desc, &sw_desc->async_tx);
	return sw_desc ? &sw_desc->async_tx : NULL;
}
#endif

static struct dma_async_tx_descriptor *
mv_xor_prep_dma_memset(struct dma_chan *chan, dma_addr_t dest, int value,
		       size_t len, unsigned long flags)
{
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	struct mv_xor_desc_slot *sw_desc;
#else
	struct mv_xor_desc_slot *sw_desc, *grp_start;
	int slot_cnt;
#endif

	dev_dbg(mv_chan->device->common.dev,
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		"%s dest: %x len: %u flags: %lx\n",
#else
		"%s dest: %x len: %u flags: %ld\n",
#endif
		__func__, dest, len, flags);
	if (unlikely(len < MV_XOR_MIN_BYTE_COUNT))
		return NULL;

	BUG_ON(len > MV_XOR_MAX_BYTE_COUNT);

	spin_lock_bh(&mv_chan->lock);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	sw_desc = mv_xor_alloc_slots(mv_chan);
#else
	slot_cnt = mv_chan_memset_slot_count(len);
	sw_desc = mv_xor_alloc_slots(mv_chan, slot_cnt, 1);
#endif
	if (sw_desc) {
		sw_desc->type = DMA_MEMSET;
		sw_desc->async_tx.flags = flags;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		mv_desc_init(sw_desc, 0, flags);
		mv_desc_set_byte_count(sw_desc, len);
		mv_desc_set_dest_addr(sw_desc, dest);
		mv_desc_set_block_fill_val(sw_desc, value);
#else
		grp_start = sw_desc->group_head;
		mv_desc_init(grp_start, flags);
		mv_desc_set_byte_count(grp_start, len);
		mv_desc_set_dest_addr(sw_desc->group_head, dest);
		mv_desc_set_block_fill_val(grp_start, value);
#endif
		sw_desc->unmap_src_cnt = 1;
		sw_desc->unmap_len = len;
	}
	spin_unlock_bh(&mv_chan->lock);
	dev_dbg(mv_chan->device->common.dev,
		"%s sw_desc %p async_tx %p \n",
		__func__, sw_desc, &sw_desc->async_tx);
	return sw_desc ? &sw_desc->async_tx : NULL;
}

static struct dma_async_tx_descriptor *
mv_xor_prep_dma_xor(struct dma_chan *chan, dma_addr_t dest, dma_addr_t *src,
		    unsigned int src_cnt, size_t len, unsigned long flags)
{
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	struct mv_xor_desc_slot *sw_desc;
#else
	struct mv_xor_desc_slot *sw_desc, *grp_start;
	int slot_cnt;
#endif

	if (unlikely(len < MV_XOR_MIN_BYTE_COUNT))
		return NULL;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	BUG_ON(unlikely(len > MV_XOR_MAX_BYTE_COUNT));
#else
	BUG_ON(len > MV_XOR_MAX_BYTE_COUNT);
#endif

	dev_dbg(mv_chan->device->common.dev,
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		"%s src_cnt: %d len: dest %x %u flags: %lx\n",
#else
		"%s src_cnt: %d len: dest %x %u flags: %ld\n",
#endif
		__func__, src_cnt, len, dest, flags);

	spin_lock_bh(&mv_chan->lock);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	sw_desc = mv_xor_alloc_slots(mv_chan);
#else
	slot_cnt = mv_chan_xor_slot_count(len, src_cnt);
	sw_desc = mv_xor_alloc_slots(mv_chan, slot_cnt, 1);
#endif
	if (sw_desc) {
		sw_desc->type = DMA_XOR;
		sw_desc->async_tx.flags = flags;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		mv_desc_init(sw_desc, src_cnt, flags);
#else
		grp_start = sw_desc->group_head;
		mv_desc_init(grp_start, flags);
#endif
		 
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		mv_desc_set_byte_count(sw_desc, len);
		mv_desc_set_dest_addr(sw_desc, dest);
#else
		mv_desc_set_byte_count(grp_start, len);
		mv_desc_set_dest_addr(sw_desc->group_head, dest);
#endif
		sw_desc->unmap_src_cnt = src_cnt;
		sw_desc->unmap_len = len;
		while (src_cnt--)
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
			mv_desc_set_src_addr(sw_desc, src_cnt, src[src_cnt]);
#else
			mv_desc_set_src_addr(grp_start, src_cnt, src[src_cnt]);
#endif
	}
	spin_unlock_bh(&mv_chan->lock);
	dev_dbg(mv_chan->device->common.dev,
		"%s sw_desc %p async_tx %p \n",
		__func__, sw_desc, &sw_desc->async_tx);
	return sw_desc ? &sw_desc->async_tx : NULL;
}

static void mv_xor_free_chan_resources(struct dma_chan *chan)
{
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);
	struct mv_xor_desc_slot *iter, *_iter;
	int in_use_descs = 0;

	mv_xor_slot_cleanup(mv_chan);

	spin_lock_bh(&mv_chan->lock);
	list_for_each_entry_safe(iter, _iter, &mv_chan->chain,
					chain_node) {
		in_use_descs++;
		list_del(&iter->chain_node);
	}
	list_for_each_entry_safe(iter, _iter, &mv_chan->completed_slots,
				 completed_node) {
		in_use_descs++;
		list_del(&iter->completed_node);
	}
	list_for_each_entry_safe_reverse(
		iter, _iter, &mv_chan->all_slots, slot_node) {
		list_del(&iter->slot_node);
		kfree(iter);
		mv_chan->slots_allocated--;
	}
	mv_chan->last_used = NULL;

	dev_dbg(mv_chan->device->common.dev, "%s slots_allocated %d\n",
		__func__, mv_chan->slots_allocated);
	spin_unlock_bh(&mv_chan->lock);

	if (in_use_descs)
		dev_err(mv_chan->device->common.dev,
			"freeing %d in use descriptors!\n", in_use_descs);
}

static enum dma_status mv_xor_status(struct dma_chan *chan,
					  dma_cookie_t cookie,
					  struct dma_tx_state *txstate)
{
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);
	dma_cookie_t last_used;
	dma_cookie_t last_complete;
	enum dma_status ret;

	last_used = chan->cookie;
	last_complete = mv_chan->completed_cookie;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	spin_lock_bh(&mv_chan->lock);
#endif
	mv_chan->is_complete_cookie = cookie;
	dma_set_tx_state(txstate, last_complete, last_used, 0);

	ret = dma_async_is_complete(cookie, last_complete, last_used);
	if (ret == DMA_SUCCESS) {
		mv_xor_clean_completed_slots(mv_chan);
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
		spin_unlock_bh(&mv_chan->lock);
#endif
		return ret;
	}
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	spin_unlock_bh(&mv_chan->lock);
#endif
	mv_xor_slot_cleanup(mv_chan);

	last_used = chan->cookie;
	last_complete = mv_chan->completed_cookie;

	dma_set_tx_state(txstate, last_complete, last_used, 0);
	return dma_async_is_complete(cookie, last_complete, last_used);
}

static void mv_dump_xor_regs(struct mv_xor_chan *chan)
{
	u32 val;

#ifdef MY_DEF_HERE
	val = readl_relaxed(XOR_CONFIG(chan));
#else
	val = __raw_readl(XOR_CONFIG(chan));
#endif
	dev_printk(KERN_ERR, chan->device->common.dev,
		   "config       0x%08x.\n", val);

#ifdef MY_DEF_HERE
	val = readl_relaxed(XOR_ACTIVATION(chan));
#else
	val = __raw_readl(XOR_ACTIVATION(chan));
#endif
	dev_printk(KERN_ERR, chan->device->common.dev,
		   "activation   0x%08x.\n", val);

#ifdef MY_DEF_HERE
	val = readl_relaxed(XOR_INTR_CAUSE(chan));
#else
	val = __raw_readl(XOR_INTR_CAUSE(chan));
#endif
	dev_printk(KERN_ERR, chan->device->common.dev,
		   "intr cause   0x%08x.\n", val);

#ifdef MY_DEF_HERE
	val = readl_relaxed(XOR_INTR_MASK(chan));
#else
	val = __raw_readl(XOR_INTR_MASK(chan));
#endif
	dev_printk(KERN_ERR, chan->device->common.dev,
		   "intr mask    0x%08x.\n", val);

#ifdef MY_DEF_HERE
	val = readl_relaxed(XOR_ERROR_CAUSE(chan));
#else
	val = __raw_readl(XOR_ERROR_CAUSE(chan));
#endif
	dev_printk(KERN_ERR, chan->device->common.dev,
		   "error cause  0x%08x.\n", val);

#ifdef MY_DEF_HERE
	val = readl_relaxed(XOR_ERROR_ADDR(chan));
#else
	val = __raw_readl(XOR_ERROR_ADDR(chan));
#endif
	dev_printk(KERN_ERR, chan->device->common.dev,
		   "error addr   0x%08x.\n", val);
}

static void mv_xor_err_interrupt_handler(struct mv_xor_chan *chan,
					 u32 intr_cause)
{
	if (intr_cause & (1 << 4)) {
	     dev_dbg(chan->device->common.dev,
		     "ignore this error\n");
	     return;
	}

	dev_printk(KERN_ERR, chan->device->common.dev,
		   "error on chan %d. intr cause 0x%08x.\n",
		   chan->idx, intr_cause);

	mv_dump_xor_regs(chan);
	BUG();
}

static irqreturn_t mv_xor_interrupt_handler(int irq, void *data)
{
	struct mv_xor_chan *chan = data;
	u32 intr_cause = mv_chan_get_intr_cause(chan);

	dev_dbg(chan->device->common.dev, "intr cause %x\n", intr_cause);

	if (mv_is_err_intr(intr_cause))
		mv_xor_err_interrupt_handler(chan, intr_cause);

	tasklet_schedule(&chan->irq_tasklet);

	mv_xor_device_clear_eoc_cause(chan);

	return IRQ_HANDLED;
}

static void mv_xor_issue_pending(struct dma_chan *chan)
{
	struct mv_xor_chan *mv_chan = to_mv_xor_chan(chan);

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	mv_xor_slot_cleanup(mv_chan);
#else
	if (mv_chan->pending >= MV_XOR_THRESHOLD) {
		mv_chan->pending = 0;
		mv_chan_activate(mv_chan);
	}
#endif
}

#define MV_XOR_TEST_SIZE 2000

static int __devinit mv_xor_memcpy_self_test(struct mv_xor_device *device)
{
	int i;
	void *src, *dest;
	dma_addr_t src_dma, dest_dma;
	struct dma_chan *dma_chan;
	dma_cookie_t cookie;
	struct dma_async_tx_descriptor *tx;
	int err = 0;
	struct mv_xor_chan *mv_chan;

	src = kmalloc(sizeof(u8) * MV_XOR_TEST_SIZE, GFP_KERNEL);
	if (!src)
		return -ENOMEM;

	dest = kzalloc(sizeof(u8) * MV_XOR_TEST_SIZE, GFP_KERNEL);
	if (!dest) {
		kfree(src);
		return -ENOMEM;
	}

	for (i = 0; i < MV_XOR_TEST_SIZE; i++)
		((u8 *) src)[i] = (u8)i;

	dma_chan = container_of(device->common.channels.next,
				struct dma_chan,
				device_node);
	if (mv_xor_alloc_chan_resources(dma_chan) < 1) {
		err = -ENODEV;
		goto out;
	}

	dest_dma = dma_map_single(dma_chan->device->dev, dest,
				  MV_XOR_TEST_SIZE, DMA_FROM_DEVICE);

	src_dma = dma_map_single(dma_chan->device->dev, src,
				 MV_XOR_TEST_SIZE, DMA_TO_DEVICE);

	tx = mv_xor_prep_dma_memcpy(dma_chan, dest_dma, src_dma,
				    MV_XOR_TEST_SIZE, 0);
	cookie = mv_xor_tx_submit(tx);
	mv_xor_issue_pending(dma_chan);
	async_tx_ack(tx);
	msleep(1);

	if (mv_xor_status(dma_chan, cookie, NULL) !=
	    DMA_SUCCESS) {
		dev_printk(KERN_ERR, dma_chan->device->dev,
			   "Self-test copy timed out, disabling\n");
		err = -ENODEV;
		goto free_resources;
	}

	mv_chan = to_mv_xor_chan(dma_chan);
	dma_sync_single_for_cpu(&mv_chan->device->pdev->dev, dest_dma,
				MV_XOR_TEST_SIZE, DMA_FROM_DEVICE);
	if (memcmp(src, dest, MV_XOR_TEST_SIZE)) {
		dev_printk(KERN_ERR, dma_chan->device->dev,
			   "Self-test copy failed compare, disabling\n");
		err = -ENODEV;
		goto free_resources;
	}

free_resources:
	mv_xor_free_chan_resources(dma_chan);
out:
	kfree(src);
	kfree(dest);
	return err;
}

#define MV_XOR_NUM_SRC_TEST 4  
static int __devinit
mv_xor_xor_self_test(struct mv_xor_device *device)
{
	int i, src_idx;
	struct page *dest;
	struct page *xor_srcs[MV_XOR_NUM_SRC_TEST];
	dma_addr_t dma_srcs[MV_XOR_NUM_SRC_TEST];
	dma_addr_t dest_dma;
	struct dma_async_tx_descriptor *tx;
	struct dma_chan *dma_chan;
	dma_cookie_t cookie;
	u8 cmp_byte = 0;
	u32 cmp_word;
	int err = 0;
	struct mv_xor_chan *mv_chan;

	for (src_idx = 0; src_idx < MV_XOR_NUM_SRC_TEST; src_idx++) {
		xor_srcs[src_idx] = alloc_page(GFP_KERNEL);
		if (!xor_srcs[src_idx]) {
			while (src_idx--)
				__free_page(xor_srcs[src_idx]);
			return -ENOMEM;
		}
	}

	dest = alloc_page(GFP_KERNEL);
	if (!dest) {
		while (src_idx--)
			__free_page(xor_srcs[src_idx]);
		return -ENOMEM;
	}

	for (src_idx = 0; src_idx < MV_XOR_NUM_SRC_TEST; src_idx++) {
		u8 *ptr = page_address(xor_srcs[src_idx]);
		for (i = 0; i < PAGE_SIZE; i++)
			ptr[i] = (1 << src_idx);
	}

	for (src_idx = 0; src_idx < MV_XOR_NUM_SRC_TEST; src_idx++)
		cmp_byte ^= (u8) (1 << src_idx);

	cmp_word = (cmp_byte << 24) | (cmp_byte << 16) |
		(cmp_byte << 8) | cmp_byte;

	memset(page_address(dest), 0, PAGE_SIZE);

	dma_chan = container_of(device->common.channels.next,
				struct dma_chan,
				device_node);
	if (mv_xor_alloc_chan_resources(dma_chan) < 1) {
		err = -ENODEV;
		goto out;
	}

	dest_dma = dma_map_page(dma_chan->device->dev, dest, 0, PAGE_SIZE,
				DMA_FROM_DEVICE);

	for (i = 0; i < MV_XOR_NUM_SRC_TEST; i++)
		dma_srcs[i] = dma_map_page(dma_chan->device->dev, xor_srcs[i],
					   0, PAGE_SIZE, DMA_TO_DEVICE);

	tx = mv_xor_prep_dma_xor(dma_chan, dest_dma, dma_srcs,
				 MV_XOR_NUM_SRC_TEST, PAGE_SIZE, 0);

	cookie = mv_xor_tx_submit(tx);
	mv_xor_issue_pending(dma_chan);
	async_tx_ack(tx);
	msleep(8);

	if (mv_xor_status(dma_chan, cookie, NULL) !=
	    DMA_SUCCESS) {
		dev_printk(KERN_ERR, dma_chan->device->dev,
			   "Self-test xor timed out, disabling\n");
		err = -ENODEV;
		goto free_resources;
	}

	mv_chan = to_mv_xor_chan(dma_chan);
	dma_sync_single_for_cpu(&mv_chan->device->pdev->dev, dest_dma,
				PAGE_SIZE, DMA_FROM_DEVICE);
	for (i = 0; i < (PAGE_SIZE / sizeof(u32)); i++) {
		u32 *ptr = page_address(dest);
		if (ptr[i] != cmp_word) {
			dev_printk(KERN_ERR, dma_chan->device->dev,
				   "Self-test xor failed compare, disabling."
				   " index %d, data %x, expected %x\n", i,
				   ptr[i], cmp_word);
			err = -ENODEV;
			goto free_resources;
		}
	}

free_resources:
	mv_xor_free_chan_resources(dma_chan);
out:
	src_idx = MV_XOR_NUM_SRC_TEST;
	while (src_idx--)
		__free_page(xor_srcs[src_idx]);
	__free_page(dest);
	return err;
}

static int __devexit mv_xor_remove(struct platform_device *dev)
{
	struct mv_xor_device *device = platform_get_drvdata(dev);
	struct dma_chan *chan, *_chan;
	struct mv_xor_chan *mv_chan;
	struct mv_xor_platform_data *plat_data = dev->dev.platform_data;

	dma_async_device_unregister(&device->common);

	dma_free_coherent(&dev->dev, plat_data->pool_size,
			device->dma_desc_pool_virt, device->dma_desc_pool);

	list_for_each_entry_safe(chan, _chan, &device->common.channels,
				device_node) {
		mv_chan = to_mv_xor_chan(chan);
		list_del(&chan->device_node);
	}

	return 0;
}

static int __devinit mv_xor_probe(struct platform_device *pdev)
{
	int ret = 0;
	int irq;
	struct mv_xor_device *adev;
	struct mv_xor_chan *mv_chan;
	struct dma_device *dma_dev;
	struct mv_xor_platform_data *plat_data = pdev->dev.platform_data;

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	dummy1_addr = dma_map_single(NULL, (void *)dummy1,
				     MV_XOR_MIN_BYTE_COUNT, DMA_FROM_DEVICE);
	dummy2_addr = dma_map_single(NULL, (void *)dummy1,
				     MV_XOR_MIN_BYTE_COUNT, DMA_TO_DEVICE);
#endif

	adev = devm_kzalloc(&pdev->dev, sizeof(*adev), GFP_KERNEL);
	if (!adev)
		return -ENOMEM;

	dma_dev = &adev->common;

	adev->dma_desc_pool_virt = dma_alloc_writecombine(&pdev->dev,
							  plat_data->pool_size,
							  &adev->dma_desc_pool,
							  GFP_KERNEL);
	if (!adev->dma_desc_pool_virt)
		return -ENOMEM;

	adev->id = plat_data->hw_id;

	dma_dev->cap_mask = plat_data->cap_mask;
	adev->pdev = pdev;
	platform_set_drvdata(pdev, adev);

	adev->shared = platform_get_drvdata(plat_data->shared);

	INIT_LIST_HEAD(&dma_dev->channels);

	dma_dev->device_alloc_chan_resources = mv_xor_alloc_chan_resources;
	dma_dev->device_free_chan_resources = mv_xor_free_chan_resources;
	dma_dev->device_tx_status = mv_xor_status;
	dma_dev->device_issue_pending = mv_xor_issue_pending;
	dma_dev->dev = &pdev->dev;

	if (dma_has_cap(DMA_MEMCPY, dma_dev->cap_mask))
		dma_dev->device_prep_dma_memcpy = mv_xor_prep_dma_memcpy;
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
	if (dma_has_cap(DMA_INTERRUPT, dma_dev->cap_mask))
		dma_dev->device_prep_dma_interrupt = mv_xor_prep_dma_interrupt;
#endif
	if (dma_has_cap(DMA_MEMSET, dma_dev->cap_mask))
		dma_dev->device_prep_dma_memset = mv_xor_prep_dma_memset;
	if (dma_has_cap(DMA_XOR, dma_dev->cap_mask)) {
		dma_dev->max_xor = 8;
		dma_dev->device_prep_dma_xor = mv_xor_prep_dma_xor;
	}

	mv_chan = devm_kzalloc(&pdev->dev, sizeof(*mv_chan), GFP_KERNEL);
	if (!mv_chan) {
		ret = -ENOMEM;
		goto err_free_dma;
	}
	mv_chan->device = adev;
	mv_chan->idx = plat_data->hw_id;
	mv_chan->mmr_base = adev->shared->xor_base;

	if (!mv_chan->mmr_base) {
		ret = -ENOMEM;
		goto err_free_dma;
	}
	tasklet_init(&mv_chan->irq_tasklet, mv_xor_tasklet, (unsigned long)
		     mv_chan);

	mv_xor_device_clear_err_status(mv_chan);

#ifdef MY_DEF_HERE
#ifdef CONFIG_ARCH_ARMADA38X
	 
	mv_chan_set_outstanding_reads_value(mv_chan, 2);
#endif
#endif

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		ret = irq;
		goto err_free_dma;
	}
	ret = devm_request_irq(&pdev->dev, irq,
			       mv_xor_interrupt_handler,
			       0, dev_name(&pdev->dev), mv_chan);
	if (ret)
		goto err_free_dma;

	mv_chan_unmask_interrupts(mv_chan);

	mv_set_mode(mv_chan, DMA_MEMCPY);

	spin_lock_init(&mv_chan->lock);
	INIT_LIST_HEAD(&mv_chan->chain);
	INIT_LIST_HEAD(&mv_chan->completed_slots);
	INIT_LIST_HEAD(&mv_chan->all_slots);
	mv_chan->common.device = dma_dev;

	list_add_tail(&mv_chan->common.device_node, &dma_dev->channels);

	if (dma_has_cap(DMA_MEMCPY, dma_dev->cap_mask)) {
		ret = mv_xor_memcpy_self_test(adev);
		dev_dbg(&pdev->dev, "memcpy self test returned %d\n", ret);
		if (ret)
			goto err_free_dma;
	}

	if (dma_has_cap(DMA_XOR, dma_dev->cap_mask)) {
		ret = mv_xor_xor_self_test(adev);
		dev_dbg(&pdev->dev, "xor self test returned %d\n", ret);
		if (ret)
			goto err_free_dma;
	}

	dev_printk(KERN_INFO, &pdev->dev, "Marvell XOR: "
	  "( %s%s%s%s)\n",
	  dma_has_cap(DMA_XOR, dma_dev->cap_mask) ? "xor " : "",
	  dma_has_cap(DMA_MEMSET, dma_dev->cap_mask)  ? "fill " : "",
	  dma_has_cap(DMA_MEMCPY, dma_dev->cap_mask) ? "cpy " : "",
	  dma_has_cap(DMA_INTERRUPT, dma_dev->cap_mask) ? "intr " : "");

	dma_async_device_register(dma_dev);
	goto out;

 err_free_dma:
	dma_free_coherent(&adev->pdev->dev, plat_data->pool_size,
			adev->dma_desc_pool_virt, adev->dma_desc_pool);
 out:
	return ret;
}

static void
mv_xor_conf_mbus_windows(struct mv_xor_shared_private *msp,
			 struct mbus_dram_target_info *dram)
{
	void __iomem *base = msp->xor_base;
	u32 win_enable = 0;
	int i;

	for (i = 0; i < 8; i++) {
		writel(0, base + WINDOW_BASE(i));
		writel(0, base + WINDOW_SIZE(i));
		if (i < 4)
			writel(0, base + WINDOW_REMAP_HIGH(i));
	}

	for (i = 0; i < dram->num_cs; i++) {
		struct mbus_dram_window *cs = dram->cs + i;

		writel((cs->base & 0xffff0000) |
		       (cs->mbus_attr << 8) |
		       dram->mbus_dram_target_id, base + WINDOW_BASE(i));
		writel((cs->size - 1) & 0xffff0000, base + WINDOW_SIZE(i));

		win_enable |= (1 << i);
		win_enable |= 3 << (16 + (2 * i));
	}

	writel(win_enable, base + WINDOW_BAR_ENABLE(0));
	writel(win_enable, base + WINDOW_BAR_ENABLE(1));
}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#ifdef CONFIG_PM
static int mv_xor_suspend(struct platform_device *dev, pm_message_t state)
{
	struct mv_xor_device *device = platform_get_drvdata(dev);
	struct dma_chan *dma_chan;
	struct mv_xor_chan *mv_chan;

	dma_chan = container_of(device->common.channels.next, struct dma_chan,
				device_node);

	mv_chan = to_mv_xor_chan(dma_chan);
	saved_regs.xor_config 	  = __raw_readl(XOR_CONFIG(mv_chan));
	saved_regs.interrupt_mask = __raw_readl(XOR_INTR_MASK(mv_chan));

	return 0;
}

static int mv_xor_resume(struct platform_device *dev)
{
	struct mv_xor_device *device = platform_get_drvdata(dev);
	struct dma_chan *dma_chan;
	struct mv_xor_chan *mv_chan;

	dma_chan = container_of(device->common.channels.next, struct dma_chan,
				device_node);

	mv_chan = to_mv_xor_chan(dma_chan);
	__raw_writel(saved_regs.xor_config, XOR_CONFIG(mv_chan));
	__raw_writel(saved_regs.interrupt_mask, XOR_INTR_MASK(mv_chan));

	return 0;
}
#endif  
#endif

static struct platform_driver mv_xor_driver = {
	.probe		= mv_xor_probe,
	.remove		= __devexit_p(mv_xor_remove),
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#ifdef CONFIG_PM
	.suspend	= mv_xor_suspend,
	.resume		= mv_xor_resume,
#endif
#endif
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= MV_XOR_NAME,
	},
};

static int mv_xor_shared_probe(struct platform_device *pdev)
{
	struct mv_xor_platform_shared_data *msd = pdev->dev.platform_data;
	struct mv_xor_shared_private *msp;
	struct resource *res;

	dev_printk(KERN_NOTICE, &pdev->dev, "Marvell shared XOR driver\n");

	msp = devm_kzalloc(&pdev->dev, sizeof(*msp), GFP_KERNEL);
	if (!msp)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	msp->xor_base = devm_ioremap(&pdev->dev, res->start,
				     resource_size(res));
	if (!msp->xor_base)
		return -EBUSY;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res)
		return -ENODEV;

	msp->xor_high_base = devm_ioremap(&pdev->dev, res->start,
					  resource_size(res));
	if (!msp->xor_high_base)
		return -EBUSY;

	platform_set_drvdata(pdev, msp);

	if (msd != NULL && msd->dram != NULL)
		mv_xor_conf_mbus_windows(msp, msd->dram);

	return 0;
}

static int mv_xor_shared_remove(struct platform_device *pdev)
{
	return 0;
}

#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#ifdef CONFIG_PM
static int mv_xor_shared_resume(struct platform_device *dev)
{
	struct mv_xor_platform_shared_data *msd = dev->dev.platform_data;
	struct mv_xor_shared_private *msp;

	msp = (struct mv_xor_shared_private *)platform_get_drvdata(dev);

	if (msd != NULL && msd->dram != NULL)
		mv_xor_conf_mbus_windows(msp, msd->dram);

	return 0;
}
#endif
#endif

static struct platform_driver mv_xor_shared_driver = {
	.probe		= mv_xor_shared_probe,
	.remove		= mv_xor_shared_remove,
#if defined(MY_DEF_HERE) || defined(MY_DEF_HERE)
#ifdef CONFIG_PM
	.resume		= mv_xor_shared_resume,
#endif
#endif
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= MV_XOR_SHARED_NAME,
	},
};

static int __init mv_xor_init(void)
{
	int rc;

	rc = platform_driver_register(&mv_xor_shared_driver);
	if (!rc) {
		rc = platform_driver_register(&mv_xor_driver);
		if (rc)
			platform_driver_unregister(&mv_xor_shared_driver);
	}
	return rc;
}
module_init(mv_xor_init);

#if 0
static void __exit mv_xor_exit(void)
{
	platform_driver_unregister(&mv_xor_driver);
	platform_driver_unregister(&mv_xor_shared_driver);
	return;
}

module_exit(mv_xor_exit);
#endif

MODULE_AUTHOR("Saeed Bishara <saeed@marvell.com>");
MODULE_DESCRIPTION("DMA engine driver for Marvell's XOR engine");
MODULE_LICENSE("GPL");
