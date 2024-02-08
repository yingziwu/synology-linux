 
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>

#include <linux/dmaengine.h>
#include "al_dma.h"
#include "al_dma_prep.h"
#include "al_dma_sysfs.h"
#include "al_hal_udma_iofic.h"
#include "al_hal_udma_config.h"
#ifdef CONFIG_SYNO_ALPINE_V2_5_3
#include "al_hal_ssm_crc_memcpy.h"
#include "al_hal_udma_fast.h"
#include "al_hal_udma_debug.h"
#include "al_hal_iomap.h"
#include "al_hal_plat_services.h"
#endif

#define OP_SUPPORT_INTERRUPT	1
#define OP_SUPPORT_MEMCPY	1
#define OP_SUPPORT_SG		1
#define OP_SUPPORT_MEMSET	1
#define OP_SUPPORT_XOR		1
#define OP_SUPPORT_XOR_VAL	1
#define OP_SUPPORT_PQ		1
#define OP_SUPPORT_PQ_VAL	1

static int max_channels = AL_DMA_MAX_CHANNELS;
module_param(max_channels, int, 0644);
MODULE_PARM_DESC(
	max_channels,
	"maximum number of channels (queues) to enable (default: 4)");

static int ring_alloc_order = 7;
module_param(ring_alloc_order, int, 0644);
MODULE_PARM_DESC(
	ring_alloc_order,
	 "allocate 2^n descriptors per channel"
	 " (default: 8 max: 16)");

static int tx_descs_order = 12;
module_param(tx_descs_order, int, 0644);
MODULE_PARM_DESC(
	tx_descs_order,
	"allocate 2^n of descriptors in Tx queue (default: 15)");

static int rx_descs_order = 12;
module_param(rx_descs_order, int, 0644);
MODULE_PARM_DESC(
	rx_descs_order,
	"allocate 2^n of descriptors in Rx queue (default: 15)");

static dma_cookie_t al_dma_tx_submit_unlock(
	struct dma_async_tx_descriptor *tx);

static void al_dma_free_chan_resources(
	struct dma_chan *c);

static int al_dma_alloc_chan_resources(
	struct dma_chan *c);

static enum dma_status al_dma_tx_status(
	struct dma_chan *c,
	dma_cookie_t cookie,
	struct dma_tx_state *txstate);

static void al_dma_issue_pending(
	struct dma_chan *c);

static int al_dma_control(
	struct dma_chan		*chan,
	enum dma_ctrl_cmd	cmd,
	unsigned long		arg);

static int al_dma_setup_interrupts(
	struct al_dma_device *device);

static irqreturn_t al_dma_do_interrupt(
	int	irq,
	void	*data);

static irqreturn_t al_dma_do_interrupt_msix(
	int	irq,
	void	*data);

static int al_dma_init_channels(
	struct al_dma_device	*device,
	int			max_channels);

static void al_dma_init_channel(
	struct al_dma_device	*device,
	struct al_dma_chan	*chan,
	int			idx);

static struct al_dma_sw_desc **al_dma_alloc_sw_ring(
	struct al_dma_chan	*chan,
	int			order,
	gfp_t			flags);

static struct al_dma_sw_desc *al_dma_alloc_ring_ent(
	struct al_dma_chan	*chan,
	gfp_t			flags);

static void al_dma_free_ring_ent(
	struct al_dma_sw_desc	*desc,
	struct al_dma_chan	*chan);

static void al_dma_cleanup_tasklet(unsigned long data);

int al_dma_core_init(
	struct al_dma_device	*device,
	void __iomem		*iobase_udma,
	void __iomem		*iobase_app)
{
	int32_t rc;

	struct dma_device *dma = &device->common;
	int err;
	struct al_udma_m2s_pkt_len_conf pkt_len_conf;
	struct al_udma *tx_udma;

	dev_dbg(
		dma->dev,
		"%s(%p, %p, %p)\n",
		__func__,
		device,
		iobase_udma,
		iobase_app);

	device->cache = kmem_cache_create(
		"al_dma",
		sizeof(struct al_dma_sw_desc),
		0,
		SLAB_HWCACHE_ALIGN,
		NULL);
	if (!device->cache)
		return -ENOMEM;

	device->max_channels = max_channels;

	device->udma_regs_base = iobase_udma;
	device->app_regs_base = iobase_app;

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
	memset(&device->ssm_dma_params, 0, sizeof(struct al_ssm_dma_params));
	device->ssm_dma_params.dev_id = device->dev_id;
	device->ssm_dma_params.rev_id = device->rev_id;
	device->ssm_dma_params.udma_regs_base = device->udma_regs_base;

	device->ssm_dma_params.name =
		kmalloc(strlen(dev_name(device->common.dev)) + 1, GFP_KERNEL);
	if (device->ssm_dma_params.name == NULL) {
		dev_err(device->common.dev, "kmalloc failed\n");
		return -1;
	}
#else
	memset(&device->raid_dma_params, 0, sizeof(struct al_raid_dma_params));
	device->raid_dma_params.dev_id = device->dev_id;
	device->raid_dma_params.rev_id = device->rev_id;
	device->raid_dma_params.udma_regs_base = device->udma_regs_base;
	device->raid_dma_params.app_regs_base = device->app_regs_base;

	device->raid_dma_params.name =
		kmalloc(strlen(dev_name(device->common.dev)) + 1, GFP_KERNEL);
	if (device->raid_dma_params.name == NULL) {
		dev_err(device->common.dev, "kmalloc failed\n");
		return -1;
	}
#endif

	memcpy(
#ifdef CONFIG_SYNO_ALPINE_V2_5_3
		device->ssm_dma_params.name,
#else
		device->raid_dma_params.name,
#endif
		dev_name(device->common.dev),
		strlen(dev_name(device->common.dev)) + 1);

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
	device->ssm_dma_params.num_of_queues = max_channels;

	rc = al_ssm_dma_init(&device->hal_raid, &device->ssm_dma_params);
#else
	device->raid_dma_params.num_of_queues = max_channels;
	device->raid_dma_params.init_gf_tables = 1;

	rc = al_raid_dma_init(&device->hal_raid, &device->raid_dma_params);
#endif
	if (rc) {
		dev_err(device->common.dev, "al_raid_dma_init failed\n");
		return rc;
	}

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
	al_raid_init(device->app_regs_base);
#endif

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
	rc = al_ssm_dma_handle_get(
		&device->hal_raid,
		UDMA_TX,
		&tx_udma);
#else
	rc = al_raid_dma_handle_get(
		&device->hal_raid,
		UDMA_TX,
		&tx_udma);
#endif
	if (rc) {
		dev_err(device->common.dev, "al_raid_dma_handle_get failed\n");
		return rc;
	}

	pkt_len_conf.encode_64k_as_zero = AL_FALSE;
	pkt_len_conf.max_pkt_size = SZ_512K;
	rc = al_udma_m2s_packet_size_cfg_set(tx_udma, &pkt_len_conf);
	if (rc) {
		dev_err(device->common.dev,
			"al_udma_m2s_packet_size_cfg_set failed\n");
		return rc;
	}

	al_dma_init_channels(device, max_channels);

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
	rc = al_ssm_dma_state_set(&device->hal_raid, UDMA_NORMAL);
#else
	rc = al_raid_dma_state_set(&device->hal_raid, UDMA_NORMAL);
#endif

	dma->dev = &device->pdev->dev;

	dma->device_alloc_chan_resources = al_dma_alloc_chan_resources;
	dma->device_free_chan_resources = al_dma_free_chan_resources;
	dma->device_tx_status = al_dma_tx_status;
	dma->device_issue_pending = al_dma_issue_pending;
	dma->device_control = al_dma_control;

#if OP_SUPPORT_INTERRUPT
	dma_cap_set(DMA_INTERRUPT, dma->cap_mask);
	dma->device_prep_dma_interrupt = al_dma_prep_interrupt_lock;
#endif

#if OP_SUPPORT_MEMCPY
	dma_cap_set(DMA_MEMCPY, dma->cap_mask);
	dma->device_prep_dma_memcpy = al_dma_prep_memcpy_lock;
#endif

#if OP_SUPPORT_SG
	dma_cap_set(DMA_SG, dma->cap_mask);
	dma->device_prep_dma_sg = al_dma_prep_sg_lock;
#endif

#if OP_SUPPORT_MEMSET
	dma_cap_set(DMA_MEMSET, dma->cap_mask);
	dma->device_prep_dma_memset = al_dma_prep_memset_lock;
#endif

#if OP_SUPPORT_XOR
	dma_cap_set(DMA_XOR, dma->cap_mask);
	dma->device_prep_dma_xor = al_dma_prep_xor_lock;
	dma->max_xor = AL_DMA_MAX_XOR;
#endif

#if OP_SUPPORT_PQ
	dma_cap_set(DMA_PQ, dma->cap_mask);
	dma->device_prep_dma_pq = al_dma_prep_pq_lock;
#endif

#if OP_SUPPORT_PQ_VAL
#ifndef CONFIG_ASYNC_TX_DISABLE_PQ_VAL_DMA
	dma_cap_set(DMA_PQ_VAL, dma->cap_mask);
	dma->device_prep_dma_pq_val = al_dma_prep_pq_val_lock;
#endif
#endif

#if (OP_SUPPORT_PQ || (OP_SUPPORT_PQ_VAL && !defined(CONFIG_ASYNC_TX_DISABLE_PQ_VAL_DMA)))
	dma_set_maxpq(dma, AL_DMA_MAX_XOR - 2, 0);
#endif

#if OP_SUPPORT_XOR_VAL
#ifndef CONFIG_ASYNC_TX_DISABLE_XOR_VAL_DMA
	dma_cap_set(DMA_XOR_VAL, dma->cap_mask);
	dma->device_prep_dma_xor_val = al_dma_prep_xor_val_lock;
#endif
#endif

#ifdef CONFIG_ALPINE_VP_WA
	dma->copy_align = AL_DMA_ALIGN_SHIFT;
	dma->xor_align = AL_DMA_ALIGN_SHIFT;
	dma->pq_align = AL_DMA_ALIGN_SHIFT;
	dma->fill_align = AL_DMA_ALIGN_SHIFT;
#endif

#ifdef CONFIG_DMATEST
	 
	dma_cap_set(DMA_PRIVATE, dma->cap_mask);
#endif

	err = al_dma_setup_interrupts(device);

	if (err) {
		dev_err(device->common.dev, "failed to setup interrupts\n");
		return err;
	}

	err = dma_async_device_register(&device->common);

	if (err)
		dev_err(device->common.dev, "failed to register dma device\n");

	return err;
}

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
 
#define FAST_DMA_NUM_OF_QUEUES		4
#define FAST_DMA_MEMCPY_TIMEOUT		1000  
#define FAST_DMA_DESCS_COUNT		8
#define FAST_DMA_TX_CDESCS_COUNT	8
#define FAST_DMA_RX_CDESCS_COUNT	8

DEFINE_PER_CPU(struct al_udma_q *, tx_udma_q_percpu);
DEFINE_PER_CPU(struct al_udma_q *, rx_udma_q_percpu);
DEFINE_PER_CPU(uint32_t *, temp_percpu);
DEFINE_PER_CPU(al_phys_addr_t, temp_phys_addr_percpu);

al_phys_addr_t tx_dma_desc_phys[FAST_DMA_NUM_OF_QUEUES];
al_phys_addr_t rx_dma_desc_phys[FAST_DMA_NUM_OF_QUEUES];
al_phys_addr_t rx_dma_cdesc_phys[FAST_DMA_NUM_OF_QUEUES];
void *tx_dma_desc_virt[FAST_DMA_NUM_OF_QUEUES];
void *rx_dma_desc_virt[FAST_DMA_NUM_OF_QUEUES];
void *rx_dma_cdesc_virt[FAST_DMA_NUM_OF_QUEUES];

uint64_t	al_pcie_read_addr_start[AL_SB_PCIE_NUM];
uint64_t	al_pcie_read_addr_end[AL_SB_PCIE_NUM];
uint64_t	al_pcie_write_addr_start[AL_SB_PCIE_NUM];
uint64_t	al_pcie_write_addr_end[AL_SB_PCIE_NUM];
bool		al_pcie_address_valid[AL_SB_PCIE_NUM] = {0};

bool		fast_dma_init = false;

static void ssm_udma_fast_init(struct al_ssm_dma *ssm_dma)
{
	struct al_memcpy_transaction xaction;
	struct al_udma_q *tx_udma_q, *rx_udma_q;
	uint32_t *temp;
	al_phys_addr_t temp_phys_addr;
	int cpu;

	for_each_possible_cpu(cpu) {
		tx_udma_q = al_ssm_dma_tx_queue_handle_get(ssm_dma, cpu);
		rx_udma_q = al_ssm_dma_rx_queue_handle_get(ssm_dma, cpu);

		memset(&xaction, 0, sizeof(struct al_memcpy_transaction));
		al_udma_fast_memcpy_q_prepare(tx_udma_q, rx_udma_q, &xaction);

		temp = dma_alloc_coherent(NULL,
							    sizeof(uint32_t),
							    &temp_phys_addr,
							    GFP_KERNEL);

		per_cpu(tx_udma_q_percpu, cpu) = tx_udma_q;
		per_cpu(rx_udma_q_percpu, cpu) = rx_udma_q;
		per_cpu(temp_percpu, cpu) = temp;
		per_cpu(temp_phys_addr_percpu, cpu) = temp_phys_addr;
	}
}

static void ssm_udma_fast_terminate(void)
{
	uint32_t *temp;
	al_phys_addr_t temp_phys_addr;
	int cpu;

	for_each_possible_cpu(cpu) {
		temp = per_cpu(temp_percpu, cpu);
		temp_phys_addr = per_cpu(temp_phys_addr_percpu, cpu);

		if (!temp)
			continue;

		dma_free_coherent(NULL,
				  sizeof(uint32_t),
				  temp,
				  temp_phys_addr);

	}
}

int al_dma_fast_init(
	struct al_dma_device	*device,
	void __iomem		*iobase_udma)
{
	int32_t rc;
	int i;

	struct dma_device *dma = &device->common;
	struct al_udma_m2s_pkt_len_conf pkt_len_conf;
	struct al_udma *tx_udma;

	struct al_udma_q_params tx_params;
	struct al_udma_q_params rx_params;

	dev_dbg(
		dma->dev,
		"%s(%p, %p)\n",
		__func__,
		device,
		iobase_udma);

	al_assert(FAST_DMA_NUM_OF_QUEUES >= NR_CPUS);

	device->max_channels = max_channels;

	device->udma_regs_base = iobase_udma;
	device->app_regs_base = NULL;

	memset(&device->ssm_dma_params, 0, sizeof(struct al_ssm_dma_params));
	device->ssm_dma_params.dev_id = device->dev_id;
	device->ssm_dma_params.rev_id = device->rev_id;
	device->ssm_dma_params.udma_regs_base = device->udma_regs_base;

	device->ssm_dma_params.name =
		kmalloc(strlen(dev_name(device->common.dev)) + 1, GFP_KERNEL);
	if (device->ssm_dma_params.name == NULL) {
		dev_err(device->common.dev, "kmalloc failed\n");
		return -1;
	}

	memcpy(
		device->ssm_dma_params.name,
		dev_name(device->common.dev),
		strlen(dev_name(device->common.dev)) + 1);

	device->ssm_dma_params.num_of_queues = max_channels;

	rc = al_ssm_dma_init(&device->hal_raid, &device->ssm_dma_params);
	if (rc) {
		dev_err(device->common.dev, "al_raid_dma_init failed\n");
		return rc;
	}

	rc = al_ssm_dma_handle_get(
		&device->hal_raid,
		UDMA_TX,
		&tx_udma);
	if (rc) {
		dev_err(device->common.dev, "al_raid_dma_handle_get failed\n");
		return rc;
	}

	pkt_len_conf.encode_64k_as_zero = AL_FALSE;
	pkt_len_conf.max_pkt_size = SZ_128;
	rc = al_udma_m2s_packet_size_cfg_set(tx_udma, &pkt_len_conf);
	if (rc) {
		dev_err(device->common.dev,
			"al_udma_m2s_packet_size_cfg_set failed\n");
		return rc;
	}

	rc = al_ssm_dma_state_set(&device->hal_raid, UDMA_NORMAL);

	dma->dev = &device->pdev->dev;

	for (i = 0; i < FAST_DMA_NUM_OF_QUEUES; i++) {
		 
		tx_dma_desc_virt[i] = dma_alloc_coherent(
			dma->dev,
			FAST_DMA_DESCS_COUNT * sizeof(union al_udma_desc),
			&tx_dma_desc_phys[i],
			GFP_KERNEL);

		rx_dma_desc_virt[i] = dma_alloc_coherent(
			dma->dev,
			FAST_DMA_DESCS_COUNT * sizeof(union al_udma_desc),
			&rx_dma_desc_phys[i],
			GFP_KERNEL);

		rx_dma_cdesc_virt[i] = dma_alloc_coherent(
			dma->dev,
			FAST_DMA_RX_CDESCS_COUNT * sizeof(union al_udma_cdesc),
			&rx_dma_cdesc_phys[i],
			GFP_KERNEL);

		tx_params.size = FAST_DMA_DESCS_COUNT;
		tx_params.desc_base = tx_dma_desc_virt[i];
		tx_params.desc_phy_base = tx_dma_desc_phys[i];
		tx_params.cdesc_base = NULL;  
		tx_params.cdesc_phy_base = 0;
		tx_params.cdesc_size = FAST_DMA_TX_CDESCS_COUNT;

		rx_params.size = FAST_DMA_DESCS_COUNT;
		rx_params.desc_base = rx_dma_desc_virt[i];
		rx_params.desc_phy_base = rx_dma_desc_phys[i];
		rx_params.cdesc_base = rx_dma_cdesc_virt[i];
		rx_params.cdesc_phy_base = rx_dma_cdesc_phys[i];
		rx_params.cdesc_size = FAST_DMA_RX_CDESCS_COUNT;

		rc += al_ssm_dma_q_init(&device->hal_raid, i,
				&tx_params, &rx_params, AL_MEM_CRC_MEMCPY_Q);
	}

	ssm_udma_fast_init(&device->hal_raid);

	fast_dma_init = true;

	return rc;
}
int al_dma_fast_terminate(struct al_dma_device	*device)
{
	int i;
	struct dma_device *dma = &device->common;

	dev_dbg(
		dma->dev,
		"%s(%p)\n",
		__func__,
		device);

	fast_dma_init = false;

	ssm_udma_fast_terminate();

	for (i=0; i < FAST_DMA_NUM_OF_QUEUES; i++) {
		dma_free_coherent(
			dma->dev,
			FAST_DMA_RX_CDESCS_COUNT * sizeof(union al_udma_cdesc),
			rx_dma_cdesc_virt[i],
			rx_dma_cdesc_phys[i]);

		dma_free_coherent(
			dma->dev,
			FAST_DMA_DESCS_COUNT * sizeof(union al_udma_desc),
			rx_dma_desc_virt[i],
			rx_dma_desc_phys[i]);

		dma_free_coherent(
			dma->dev,
			FAST_DMA_DESCS_COUNT * sizeof(union al_udma_desc),
			tx_dma_desc_virt[i],
			tx_dma_desc_phys[i]);
	}

	kfree(device->ssm_dma_params.name);

	return 0;
}
 
int udma_fast_memcpy(int len, al_phys_addr_t src, al_phys_addr_t dst)
{
	struct al_udma_q *tx_udma_q, *rx_udma_q;

	union al_udma_desc *tx_desc;
	union al_udma_desc *rx_desc;
	int completed = 0;
	int timeout = FAST_DMA_MEMCPY_TIMEOUT;
	uint32_t flags;
	 
	rx_udma_q = __get_cpu_var(rx_udma_q_percpu);
	tx_udma_q = __get_cpu_var(tx_udma_q_percpu);

	rx_desc = al_udma_desc_get(rx_udma_q);

	flags = al_udma_ring_id_get(rx_udma_q) <<
			AL_M2S_DESC_RING_ID_SHIFT;

	al_udma_fast_desc_flags_set(rx_desc, flags, AL_M2S_DESC_RING_ID_MASK);
	al_udma_fast_desc_len_set(rx_desc, len);
	al_udma_fast_desc_buf_set(rx_desc, dst, 0);

	al_udma_desc_action_add(rx_udma_q, 1);

	tx_desc = al_udma_desc_get(tx_udma_q);

	flags = al_udma_ring_id_get(tx_udma_q) <<
			AL_M2S_DESC_RING_ID_SHIFT;

	al_udma_fast_desc_flags_set(tx_desc, flags, AL_M2S_DESC_RING_ID_MASK);
	al_udma_fast_desc_len_set(tx_desc, len);
	al_udma_fast_desc_buf_set(tx_desc, src, 0);

	al_udma_desc_action_add(tx_udma_q, 1);

	while(1) {
		completed = al_udma_fast_completion(rx_udma_q, 1, 0);
		if ((completed > 0) || (timeout == 0))
			break;

		udelay(1);
		timeout--;
	}

	if (timeout == 0) {
		pr_err("%s: Didn't receive completion in %d uSec",
		       __func__, FAST_DMA_MEMCPY_TIMEOUT);

		return -ETIME;
	}

	return 0;
}
EXPORT_SYMBOL(udma_fast_memcpy);

static inline al_phys_addr_t virt_to_physical_address(const volatile void __iomem *address)
{
	al_phys_addr_t phys_addr;
	uint32_t phys_addr_h, phys_addr_l;

	asm volatile( "mcr p15, 0, %0, c7, c8, 0" :: "r"(address));

#ifdef CONFIG_CPU_BIG_ENDIAN
#error "virt_to_physical_address assumes LE!"
#endif
	asm volatile("mrrc p15, 0, %0, %1, c7" : "=r"(phys_addr_l), "=r"(phys_addr_h));

	phys_addr = phys_addr_l & ~(((uint32_t)1<<12) - 1UL);
	phys_addr |= (uintptr_t)address & AL_BIT_MASK(12);

	return phys_addr;
}

extern int hwcc;

#ifdef	CONFIG_AL_PCIE_DEADLOCK_WA_VALIDATE
#define _al_dma_dma_read_validate(type, val)			\
{								\
	type _cpu_val;						\
	switch (sizeof(type)) {						\
	case sizeof(uint8_t):					\
		_cpu_val = __raw_readb(address);		\
		break;						\
	case sizeof(uint16_t):					\
		_cpu_val = le16_to_cpu((__force __le16)__raw_readw(address)); \
		break;						\
	default:						\
	case sizeof(uint32_t):					\
		_cpu_val = le32_to_cpu((__force __le32)__raw_readl(address)); \
		break;						\
	}							\
								\
	if (memcmp(&_cpu_val, &val, sizeof(type))) {		\
		al_info("[%s] Potential Error: DMA read value isn't the same as CPU read addr: "	\
			"%p phys addr %x DMA read: %x cpu read: %x\n"					\
			"This register might be clear on read or status register so different values"	\
			"doesn't guarantee we have a problem, Please check the spec\n",			\
			__func__, address, phys_addr, val, _cpu_val);					\
			val = _cpu_val;				\
	}							\
}
#else
#define _al_dma_dma_read_validate(type, val)
#endif

static inline uint32_t _al_dma_read_reg(const volatile void __iomem *address, int size)
{
	unsigned long flags;
	al_phys_addr_t phys_addr;
	uint32_t val_32;
	uint16_t val_16;
	uint8_t val_8;
	int i;

	if (likely((hwcc) && (fast_dma_init))) {
		local_irq_save(flags);

		phys_addr = virt_to_physical_address(address);

		for (i = 0; i < AL_SB_PCIE_NUM; i++) {
			if (likely(al_pcie_address_valid[i] == false))
				continue;

			if (unlikely(phys_addr >= al_pcie_read_addr_start[i] &&
				     phys_addr <= al_pcie_read_addr_end[i]))
				goto pcie_mem_read;
		}

		local_irq_restore(flags);
	}

	switch (size) {
	case sizeof(uint8_t):
		val_8 = __raw_readb(address);
		return val_8;
	case sizeof(uint16_t):
		val_16 = le16_to_cpu((__force __le16)__raw_readw(address));
		return val_16;
	default:
	case sizeof(uint32_t):
		val_32 = le32_to_cpu((__force __le32)__raw_readl(address));
		return val_32;
	}

pcie_mem_read:
	udma_fast_memcpy(size,
			phys_addr,
			__get_cpu_var(temp_phys_addr_percpu));

	switch (size) {
	default:
	case sizeof(uint32_t):
		val_32 = *__get_cpu_var(temp_percpu);
		_al_dma_dma_read_validate(uint32_t, val_32);
		local_irq_restore(flags);
		return val_32;
	case sizeof(uint16_t):
		val_16 = *__get_cpu_var(temp_percpu);
		_al_dma_dma_read_validate(uint16_t, val_16);
		local_irq_restore(flags);
		return val_16;
	case sizeof(uint8_t):
		val_8 = *__get_cpu_var(temp_percpu);
		_al_dma_dma_read_validate(uint8_t, val_8);
		local_irq_restore(flags);
		return val_8;
	}
}

uint32_t al_dma_read_reg32(const volatile void __iomem *address)
{
	return _al_dma_read_reg(address, sizeof(uint32_t));
}
EXPORT_SYMBOL(al_dma_read_reg32);

uint16_t al_dma_read_reg16(const volatile void __iomem *address)
{
	return _al_dma_read_reg(address, sizeof(uint16_t));
}
EXPORT_SYMBOL(al_dma_read_reg16);

uint8_t al_dma_read_reg8(const volatile void __iomem *address)
{
	return _al_dma_read_reg(address, sizeof(uint8_t));
}
EXPORT_SYMBOL(al_dma_read_reg8);

void al_dma_write_reg32(volatile void __iomem *address, u32 val)
{
	unsigned long flags;
	al_phys_addr_t phys_addr;
	int i;

	if (likely((hwcc) && (fast_dma_init))) {
		local_irq_save(flags);

		phys_addr = virt_to_physical_address(address);

		for (i = 0; i < AL_SB_PCIE_NUM; i++) {
			if (likely(al_pcie_address_valid[i] == false))
				continue;

			if (unlikely(phys_addr >= al_pcie_write_addr_start[i] &&
				     phys_addr <= al_pcie_write_addr_end[i]))
				goto pcie_mem_write;
		}

		local_irq_restore(flags);
	}

	__raw_writel((__force u32) cpu_to_le32(val), address);

	return;

pcie_mem_write:
	*__get_cpu_var(temp_percpu) = val;

	udma_fast_memcpy(sizeof(uint32_t),
			__get_cpu_var(temp_phys_addr_percpu),
			phys_addr);

	local_irq_restore(flags);
}
EXPORT_SYMBOL(al_dma_write_reg32);
#endif

int al_dma_core_terminate(
	struct al_dma_device	*device)
{
	int status = 0;

	struct dma_device *dma = &device->common;

	dev_dbg(
		dma->dev,
		"%s(%p)\n",
		__func__,
		device);

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
	kfree(device->ssm_dma_params.name);
#else
	kfree(device->raid_dma_params.name);
#endif

	kmem_cache_destroy(device->cache);

	return status;
}

static int al_dma_init_channels(struct al_dma_device *device, int max_channels)
{
	int i;
	struct al_dma_chan *chan;
	struct device *dev = &device->pdev->dev;
	struct dma_device *dma = &device->common;

	INIT_LIST_HEAD(&dma->channels);
	dma->chancnt = max_channels;

	if (dma->chancnt > ARRAY_SIZE(device->channels)) {
		dev_warn(dev, "(%d) exceeds max supported channels (%zu)\n",
			 dma->chancnt, ARRAY_SIZE(device->channels));
		dma->chancnt = ARRAY_SIZE(device->channels);
	}

	for (i = 0; i < dma->chancnt; i++) {
		chan = devm_kzalloc(dev, sizeof(*chan), GFP_KERNEL);
		if (!chan)
			break;

		al_dma_init_channel(device, chan, i);

	}
	dma->chancnt = i;
	return i;
}

static void al_dma_init_channel(struct al_dma_device *device,
			 struct al_dma_chan *chan, int idx)
{
	struct dma_device *dma = &device->common;
	struct dma_chan *c = &chan->common;
	unsigned long data = (unsigned long) c;

	dev_dbg(
		dma->dev,
		"%s(%p, %p, %d): %p\n",
		__func__,
		device,
		chan,
		idx,
		c);

	chan->device = device;
	chan->idx = idx;
	chan->hal_raid = &device->hal_raid;

	spin_lock_init(&chan->prep_lock);

	spin_lock_init(&chan->cleanup_lock);
	chan->common.device = dma;
	list_add_tail(&chan->common.device_node, &dma->channels);
	device->channels[idx] = chan;

	tasklet_init(&chan->cleanup_task, al_dma_cleanup_tasklet, data);
}

static int al_dma_setup_interrupts(struct al_dma_device *device)
{
	struct al_dma_chan *chan;
	struct pci_dev *pdev = device->pdev;
	struct device *dev = &pdev->dev;
	struct msix_entry *msix;
	int i, j, msixcnt;
	int err = -EINVAL;

	msixcnt = device->common.chancnt;

	for (i = 0; i < msixcnt; i++)
		device->msix_entries[i].entry = 3 + i;

	err = pci_enable_msix(pdev, device->msix_entries, msixcnt);

	if (err < 0) {
		dev_err(dev, "pci_enable_msix failed! using intx instead.\n");
		goto intx;
	}

	if (err > 0) {
		dev_err(dev, "pci_enable_msix failed! msix_single_vector.\n");
		goto msix_single_vector;
	}

	for (i = 0; i < msixcnt; i++) {
		msix = &device->msix_entries[i];

		chan = al_dma_chan_by_index(device, i);

		dev_dbg(dev, "%s: requesting irq %d\n", __func__, msix->vector);

		snprintf(device->irq_tbl[i].name, AL_DMA_IRQNAME_SIZE,
			"al-dma-comp-%d@pci:%s", i,
			pci_name(pdev));

		err = devm_request_irq(
			dev,
			msix->vector,
			al_dma_do_interrupt_msix,
			0,
			device->irq_tbl[i].name,
			chan);

		if (err) {
			dev_err(dev, "devm_request_irq failed!.\n");

			for (j = 0; j < i; j++) {
				msix = &device->msix_entries[j];
				chan = al_dma_chan_by_index(device, j);
				devm_free_irq(dev, msix->vector, chan);
			}

			return -EIO;
		}

		if (cpu_online(chan->idx))
			cpumask_set_cpu(chan->idx, &chan->affinity_mask);
		else
			cpumask_copy(&chan->affinity_mask, cpu_online_mask);

		dev_dbg(
			dev,
			"Setting affinity of channel %d to %lx\n",
			chan->idx,
			chan->affinity_mask.bits[0]);

		err = irq_set_affinity_hint(msix->vector, &chan->affinity_mask);
		if (err) {
			dev_err(dev, "irq_set_affinity_hint failed!\n");
			return err;
		}

		err = irq_set_affinity(msix->vector, &chan->affinity_mask);
		if (err) {
			dev_err(dev, "irq_set_affinity failed!\n");
			return err;
		}
	}

	err = al_udma_iofic_config(
		(struct unit_regs *)device->udma_regs_base,
		AL_IOFIC_MODE_MSIX_PER_Q, 0x480, 0x480, 0x1E0, 0x1E0);
	if (err) {
		dev_err(dev, "al_udma_iofic_config failed!.\n");
		return err;
	}

	al_udma_iofic_unmask(
		(struct unit_regs *)device->udma_regs_base,
		AL_INT_GROUP_B,
		((1 << (device->common.chancnt)) - 1));

	goto done;

msix_single_vector:
	msix = &device->msix_entries[0];

	msix->entry = 0;

	err = pci_enable_msix(pdev, device->msix_entries, 1);

	if (err)
		goto intx;

	snprintf(device->irq_tbl[0].name, AL_DMA_IRQNAME_SIZE,
		"al-dma-msix-all@pci:%s", pci_name(pdev));

	err = devm_request_irq(
		dev,
		msix->vector,
		al_dma_do_interrupt,
		IRQF_TRIGGER_RISING,
		device->irq_tbl[0].name, device);

	if (err) {
		pci_disable_msix(pdev);
		goto intx;
	}

	goto done;

intx:
	snprintf(device->irq_tbl[0].name, AL_DMA_IRQNAME_SIZE,
		"al-dma-intx-all@pci:%s", pci_name(pdev));

	err = devm_request_irq(dev, pdev->irq, al_dma_do_interrupt,
			       IRQF_SHARED, device->irq_tbl[0].name, device);
	if (err)
		goto err_no_irq;

done:
	return 0;

err_no_irq:
	 
	dev_err(dev, "no usable interrupts\n");
	return err;
}

static int al_dma_alloc_chan_resources(struct dma_chan *c)
{
	struct al_dma_chan *chan = to_al_dma_chan(c);
	struct device *dev = chan->device->common.dev;
	struct al_dma_sw_desc **sw_ring;
	struct al_udma_q_params tx_params;
	struct al_udma_q_params rx_params;
	uint32_t rc = 0;

	dev_dbg(dev, "al_dma_alloc_chan_resources: channel %d\n",
		chan->idx);

	if (chan->sw_ring)
		return 1 << chan->alloc_order;

	chan->tx_descs_num = 1 << tx_descs_order;
	chan->rx_descs_num = 1 << rx_descs_order;

	chan->tx_dma_desc_virt = dma_alloc_coherent(dev,
						    chan->tx_descs_num *
						    sizeof(union al_udma_desc),
						    &chan->tx_dma_desc,
						    GFP_KERNEL);
	if (chan->tx_dma_desc_virt == NULL) {
		dev_err(dev, "failed to allocate %d bytes of coherent "
			"memory for Tx submission descriptors\n",
			chan->tx_descs_num * sizeof(union al_udma_desc));
		return -ENOMEM;
	}
	dev_dbg(dev, "allocted tx descriptor ring: virt 0x%p phys 0x%llx\n",
		chan->tx_dma_desc_virt, (u64)chan->tx_dma_desc);

	chan->rx_dma_desc_virt = dma_alloc_coherent(dev,
						    chan->rx_descs_num *
						    sizeof(union al_udma_desc),
						    &chan->rx_dma_desc,
						    GFP_KERNEL);
	if (chan->rx_dma_desc_virt == NULL) {
		dev_err(dev, "failed to allocate %d bytes of coherent "
			"memory for Rx submission descriptors\n",
			chan->rx_descs_num * sizeof(union al_udma_desc));

		al_dma_free_chan_resources(c);
		return -ENOMEM;
	}
	dev_dbg(dev, "allocted rx descriptor ring: virt 0x%p phys 0x%llx\n",
		chan->rx_dma_desc_virt, (u64)chan->rx_dma_desc);

	chan->rx_dma_cdesc_virt = dma_alloc_coherent(dev,
						     chan->rx_descs_num *
						     AL_DMA_RAID_RX_CDESC_SIZE,
						     &chan->rx_dma_cdesc,
						     GFP_KERNEL);
	if (chan->rx_dma_cdesc_virt == NULL) {
		dev_err(dev, "failed to allocate %d bytes of coherent "
			"memory for Rx completion descriptors\n",
			chan->rx_descs_num * AL_DMA_RAID_RX_CDESC_SIZE);

		al_dma_free_chan_resources(c);
		return -ENOMEM;
	}

	memset(
		chan->rx_dma_cdesc_virt,
		0,
		chan->rx_descs_num * AL_DMA_RAID_RX_CDESC_SIZE);

	dev_dbg(
		dev,
		"allocted rx completion desc ring: virt 0x%p phys 0x%llx\n",
		chan->rx_dma_cdesc_virt, (u64)chan->rx_dma_cdesc);

	tx_params.size = chan->tx_descs_num;
	tx_params.desc_base = chan->tx_dma_desc_virt;
	tx_params.desc_phy_base = chan->tx_dma_desc;
	tx_params.cdesc_base = NULL;  
	tx_params.cdesc_phy_base = 0;
	tx_params.cdesc_size = AL_DMA_RAID_TX_CDESC_SIZE;  

	rx_params.size = chan->rx_descs_num;
	rx_params.desc_base = chan->rx_dma_desc_virt;
	rx_params.desc_phy_base = chan->rx_dma_desc;
	rx_params.cdesc_base = chan->rx_dma_cdesc_virt;
	rx_params.cdesc_phy_base = chan->rx_dma_cdesc;
	rx_params.cdesc_size = AL_DMA_RAID_RX_CDESC_SIZE;

	if (ring_alloc_order < AL_DMA_SW_RING_MIN_ORDER) {
		dev_err(
			dev,
			"%s: ring_alloc_order = %d < %d!\n",
			__func__,
			ring_alloc_order,
			AL_DMA_SW_RING_MIN_ORDER);

		al_dma_free_chan_resources(c);
		return -EINVAL;
	} else if (ring_alloc_order > AL_DMA_SW_RING_MAX_ORDER) {
		dev_err(
			dev,
			"%s: ring_alloc_order = %d > %d!\n",
			__func__,
			ring_alloc_order,
			AL_DMA_SW_RING_MAX_ORDER);

		al_dma_free_chan_resources(c);
		return -EINVAL;
	} else if (ring_alloc_order > rx_descs_order) {
		dev_warn(
			dev,
			"%s: ring_alloc_order > rx_descs_order (%d>%d)!\n",
			__func__,
			ring_alloc_order,
			rx_descs_order);

	}

	sw_ring = al_dma_alloc_sw_ring(chan, ring_alloc_order, GFP_KERNEL);
	if (!sw_ring)
		return -ENOMEM;

	spin_lock_bh(&chan->cleanup_lock);
	spin_lock_bh(&chan->prep_lock);
	chan->sw_ring = sw_ring;
	chan->head = 0;
	chan->tail = 0;
	chan->alloc_order = ring_alloc_order;
	chan->tx_desc_produced = 0;
	spin_unlock_bh(&chan->prep_lock);
	spin_unlock_bh(&chan->cleanup_lock);

#ifdef CONFIG_SYNO_ALPINE_V2_5_3
	rc = al_ssm_dma_q_init(&chan->device->hal_raid, chan->idx,
				&tx_params, &rx_params, AL_RAID_Q);
#else
	rc = al_raid_dma_q_init(&chan->device->hal_raid, chan->idx,
				&tx_params, &rx_params);
#endif
	if (rc) {
		dev_err(dev, "failed to initialize hal q %d. rc %d\n",
			chan->idx, rc);
		al_dma_free_chan_resources(c);
		return rc;
	}

	return  1 << chan->alloc_order;
}

static void al_dma_free_chan_resources(struct dma_chan *c)
{
	struct al_dma_chan *chan = to_al_dma_chan(c);
	struct device *dev = chan->device->common.dev;

	dev_dbg(dev, "%s(%p): %p\n", __func__, c, chan);

	tasklet_disable(&chan->cleanup_task);

	al_dma_cleanup_fn(chan, 0);

	spin_lock_bh(&chan->cleanup_lock);

	if (chan->tx_dma_desc_virt != NULL) {
		dma_free_coherent(
			dev,
			chan->tx_descs_num * sizeof(union al_udma_desc),
			chan->tx_dma_desc_virt, chan->tx_dma_desc);
		chan->tx_dma_desc_virt = NULL;
	}

	if (chan->rx_dma_desc_virt != NULL) {
		dma_free_coherent(
			dev,
			chan->rx_descs_num * sizeof(union al_udma_desc),
			chan->rx_dma_desc_virt,
			chan->rx_dma_desc);
		chan->rx_dma_desc_virt = NULL;
	}

	if (chan->rx_dma_cdesc_virt != NULL) {
		dma_free_coherent(dev, chan->rx_descs_num *
				  AL_DMA_RAID_RX_CDESC_SIZE,
				  chan->rx_dma_cdesc_virt, chan->rx_dma_cdesc);
		chan->rx_dma_desc_virt = NULL;
	}

	spin_unlock_bh(&chan->cleanup_lock);

	return;
}

static struct al_dma_sw_desc **al_dma_alloc_sw_ring(
	struct al_dma_chan	*chan,
	int			order,
	gfp_t			flags)
{
	struct al_dma_sw_desc **ring;
	int descs = 1 << order;
	int i;

	ring = kcalloc(descs, sizeof(*ring), flags);
	if (!ring)
		return NULL;
	for (i = 0; i < descs; i++) {
		ring[i] = al_dma_alloc_ring_ent(chan, flags);
		if (!ring[i]) {
			while (i--)
				al_dma_free_ring_ent(ring[i], chan);
			kfree(ring);
			return NULL;
		}
		set_desc_id(ring[i], i);
	}

	return ring;
}

static struct al_dma_sw_desc *al_dma_alloc_ring_ent(
	struct al_dma_chan	*chan,
	gfp_t			flags)
{
	struct al_dma_sw_desc *desc;

	desc = kmem_cache_zalloc(chan->device->cache, flags);
	if (!desc)
		return NULL;

	dma_async_tx_descriptor_init(&desc->txd, &chan->common);
	desc->txd.tx_submit = al_dma_tx_submit_unlock;
	return desc;
}

static void al_dma_free_ring_ent(
	struct al_dma_sw_desc	*desc,
	struct al_dma_chan	*chan)
{
	kmem_cache_free(chan->device->cache, desc);
}

int al_dma_get_sw_desc_lock(struct al_dma_chan *chan, int num)
{
	spin_lock_bh(&chan->prep_lock);

	if (likely(al_dma_ring_space(chan) >= num)) {
		dev_dbg(to_dev(chan), "%s: (%x:%x)\n",
			__func__, chan->head, chan->tail);
		return 0;   
	}

	spin_unlock_bh(&chan->prep_lock);

	return -ENOMEM;
}

static irqreturn_t al_dma_do_interrupt(int irq, void *data)
{
	pr_debug("%s(%d, %p)\n", __func__, irq, data);

	return IRQ_HANDLED;
}

static irqreturn_t al_dma_do_interrupt_msix(int irq, void *data)
{
	struct al_dma_chan *chan = data;

	pr_debug("%s(%d, %p)\n", __func__, irq, data);

	tasklet_schedule(&chan->cleanup_task);

	return IRQ_HANDLED;
}

static enum dma_status al_dma_tx_status(
	struct dma_chan *c,
	dma_cookie_t cookie,
	struct dma_tx_state *txstate)
{
	struct al_dma_chan *chan = to_al_dma_chan(c);
	dma_cookie_t last_used;
	dma_cookie_t last_complete;

	enum dma_status dma_status;

	dev_dbg(
		to_dev(chan),
		"%s(%d)\n",
		__func__,
		cookie);

	al_dma_cleanup_fn(chan, 0);

	last_used = c->cookie;
	last_complete = chan->completed_cookie;

	dma_set_tx_state(txstate, last_complete, last_used, 0);

	dma_status = dma_async_is_complete(cookie, last_complete, last_used);

	dev_dbg(
		to_dev(chan),
		"%s: cookie=%d,last_complete=%d,last_used=%d,dma_status=%d\n",
		__func__,
		cookie,
		last_complete,
		last_used,
		dma_status);

	return dma_status;
}

static inline int al_dma_issue_pending_raw(struct al_dma_chan *chan)
{
	int err = 0;

	if (chan->tx_desc_produced) {
		dev_dbg(
			chan->device->common.dev,
			"%s(%p): issuing %u descriptors\n",
			__func__,
			chan,
			chan->tx_desc_produced);

		err = al_raid_dma_action(
				chan->hal_raid,
				chan->idx,
				chan->tx_desc_produced);
		if (err)
			dev_err(
				chan->device->common.dev,
				"al_raid_dma_action failed\n");

		chan->tx_desc_produced = 0;
	}

	return err;
}

static inline dma_cookie_t al_dma_cookie_assign(struct dma_async_tx_descriptor *tx)
{
	struct dma_chan *chan = tx->chan;
	dma_cookie_t cookie;

	cookie = chan->cookie + 1;
	if (cookie < DMA_MIN_COOKIE)
		cookie = DMA_MIN_COOKIE;
	tx->cookie = chan->cookie = cookie;

	return cookie;
}

void al_dma_tx_submit_sw_cond_unlock(
	struct al_dma_chan		*chan,
	struct dma_async_tx_descriptor	*tx)
{
	if (tx) {
		struct dma_chan *c = tx->chan;
		dma_cookie_t cookie = al_dma_cookie_assign(tx);

		c->cookie = cookie;

		dev_dbg(
			chan->device->common.dev,
			"%s: cookie = %d\n",
			__func__,
			cookie);

		chan->head += chan->sw_desc_num_locked;
		 
	}

#if !AL_DMA_ISSUE_PNDNG_UPON_SUBMIT
	spin_unlock_bh(&chan->prep_lock);
#endif
}

static dma_cookie_t al_dma_tx_submit_unlock(struct dma_async_tx_descriptor *tx)
{
#if AL_DMA_ISSUE_PNDNG_UPON_SUBMIT
	int err;

	struct dma_chan *c = tx->chan;
	struct al_dma_chan *chan = to_al_dma_chan(c);

	dev_dbg(
		chan->device->common.dev,
		"%s(%p): %p, %p\n",
		__func__,
		tx,
		chan,
		c);

	err = al_dma_issue_pending_raw(chan);
	if (err)
		dev_err(
			chan->device->common.dev,
			"%s: al_dma_issue_pending\n",
			__func__);

	spin_unlock_bh(&chan->prep_lock);
#endif

	return tx->cookie;
}

static void al_dma_issue_pending(struct dma_chan *c)
{
#if !AL_DMA_ISSUE_PNDNG_UPON_SUBMIT
	int err;

	struct al_dma_chan *chan = to_al_dma_chan(c);

	spin_lock_bh(&chan->prep_lock);

	dev_dbg(
		chan->device->common.dev,
		"%s(%p)\n",
		__func__,
		chan);

	err = al_dma_issue_pending_raw(chan);
	if (err)
		dev_err(
			chan->device->common.dev,
			"%s: al_dma_issue_pending\n",
			__func__);

	spin_unlock_bh(&chan->prep_lock);
#endif
}

static int al_dma_control(
	struct dma_chan		*c,
	enum dma_ctrl_cmd	cmd,
	unsigned long		arg)
{
	struct al_dma_chan *chan = to_al_dma_chan(c);
	int err;

	switch (cmd) {
	case DMA_SLAVE_CONFIG:
	case DMA_TERMINATE_ALL:
	case DMA_PAUSE:
	case DMA_RESUME:
	default:
		dev_err(
			chan->device->common.dev,
			"%s: Unexpected cmd (%d)!\n",
			__func__,
			cmd);
		err = -ENXIO;
		break;
	}

	return err;
}
static void al_dma_cleanup_tasklet(unsigned long data)
{
	struct al_dma_chan *chan = to_al_dma_chan((void *) data);
	int num_completed;

	num_completed = al_dma_cleanup_fn(chan, 1);

	if (unlikely(num_completed < 0))
		dev_err(
			chan->device->common.dev,
			"al_dma_cleanup_fn failed\n");

	al_udma_iofic_unmask(
		(struct unit_regs *)chan->device->udma_regs_base,
		AL_INT_GROUP_B,
		1 << chan->idx);
}
