#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/reset-helper.h>
#include <linux/reset.h>
#include <linux/suspend.h>
#include <linux/kthread.h>
#ifdef CONFIG_PCI_MSI
#include <linux/msi.h>
#include <asm/cacheflush.h>
#endif /* CONFIG_PCI_MSI */
#include <soc/realtek/rtd129x_cpu.h>
#include "pcie-rtd1295.h"

static void __iomem	*PCIE_CTRL_BASE;
static void __iomem	*PCIE_CFG_BASE;
static void __iomem	*SYSTEM_BASE1;
static void __iomem	*SYSTEM_BASE2;
static void __iomem	*EMMC_MUXPAD;
#ifdef CONFIG_PCI_MSI
static void __iomem	*DCSYS_BASE;
#endif /* CONFIG_PCI_MSI */

static u32 pcie_gpio_20 = 0;
static u32 speed_mode = 0;

static bool cfg_direct_access = true;

static int rtd129x_cpu_id;
static int rtd129x_cpu_revision;

static struct clk *pcie1_clk;
static struct reset_control *rstn_pcie1_stitch;
static struct reset_control *rstn_pcie1;
static struct reset_control *rstn_pcie1_core;
static struct reset_control *rstn_pcie1_power;
static struct reset_control *rstn_pcie1_nonstich;
static struct reset_control *rstn_pcie1_phy;
static struct reset_control *rstn_pcie1_phy_mdio;

static struct pci_bus *bus;

static spinlock_t rtk_pcie2_lock;

#ifdef CONFIG_PCI_MSI
#define MAX_RTK_MSI_IRQS 16
#define MAX_RTK_MSI_CTRLS	(MAX_RTK_MSI_IRQS / 16)

struct irq_domain *pcie2_irq_domain;
struct irq_domain *rtk_msi_domain;
struct mutex		msi_lock;

DECLARE_BITMAP(rtk_pcie_irq_bitmap, MAX_RTK_MSI_IRQS);
unsigned long *pcie2_msi_data;
dma_addr_t dma_handle;
bool no_msi = 0;
#endif /* CONFIG_PCI_MSI */

static inline u32 rtk_pcie2_read(u64 addr, u8 size)
{
	u32 rval = 0;
	u32 mask;
	u32 translate_val = 0;
	u64 tmp_addr = addr & 0xFFF;
	u32 pci_error_status = 0;
	int retry_cnt = 0;
	u8 retry = 5;
	unsigned long irqL;

	spin_lock_irqsave(&rtk_pcie2_lock, irqL);

	/* PCIE1.1 0x9804FCEC, PCIE2.0 0x9803CCEC & 0x9803CC68
	 * can't be used because of 1295 hardware issue.
	 */
	if (tmp_addr == 0xCEC || tmp_addr == 0xC68) {
		mask = PCIE_IO_2K_MASK;
		rtk_pci_ctrl_write(0xD00, PCIE_IO_2K_MASK);
		translate_val = rtk_pci_ctrl_read(0xD04);
		rtk_pci_ctrl_write(0xD04, translate_val | (addr & mask));
	} else if (addr >= 0x1000) {
		mask = PCIE_IO_4K_MASK;
		translate_val = rtk_pci_ctrl_read(0xD04);
		rtk_pci_ctrl_write(0xD04, translate_val | (addr & mask));
	} else
		mask = 0x0;

pci_read_129x_retry:

#ifdef CONFIG_RTK_SW_LOCK_API
	/* All RBUS1 driver need to have a workaround for emmc hardware error. */
	/* Need to protect 0xXXXX_X8XX~ 0xXXXX_X9XX. */
	if((tmp_addr > 0x7FF) && (tmp_addr < 0xA00))
		rtk_lockapi_lock(flags, __FUNCTION__);
#endif

	switch (size) {
	case 1:
		rval = rtk_pci_direct_read_byte((addr & ~mask));
		break;
	case 2:
		rval = rtk_pci_direct_read_word((addr & ~mask));
		break;
	case 4:
		rval = rtk_pci_direct_read((addr & ~mask));
		break;
	default:
		printk(KERN_INFO "RTD129X: %s: wrong size %d\n", __func__, size);
		break;
	}

#ifdef CONFIG_RTK_SW_LOCK_API
	if((tmp_addr>0x7FF) && (tmp_addr<0xA00))
		rtk_lockapi_unlock(flags, __FUNCTION__);
#endif

	//DLLP error patch
	pci_error_status = rtk_pci_ctrl_read(0xc7c);
	if (pci_error_status & 0x1F) {
		rtk_pci_ctrl_write(0xc7c, pci_error_status);
		printk(KERN_INFO "RTD129X: %s: DLLP(#%d) 0x%x reg=0x%llx val=0x%x\n", __func__, retry_cnt, pci_error_status, addr, rval);

		if (retry_cnt < retry) {
			retry_cnt++;
			goto pci_read_129x_retry;
		}
	}

	/* PCIE1.1 0x9804FCEC, PCIE2.0 0x9803CCEC & 0x9803CC68
	 * can't be used because of 1295 hardware issue.
	 */
	if (tmp_addr == 0xCEC || tmp_addr == 0xC68){
		rtk_pci_ctrl_write(0xD04, translate_val);
		rtk_pci_ctrl_write(0xD00, PCIE_IO_4K_MASK);
	}else if(addr >= 0x1000){
		rtk_pci_ctrl_write(0xD04, translate_val);
	}

	spin_unlock_irqrestore(&rtk_pcie2_lock, irqL);

	return rval;
}

static inline void rtk_pcie2_write(u64 addr, u8 size, u32 wval)
{
	u32 mask;
	u32 translate_val = 0;
	u64 tmp_addr = addr & 0xFFF;
	unsigned long irqL;

	spin_lock_irqsave(&rtk_pcie2_lock, irqL);

	/* PCIE1.1 0x9804FCEC, PCIE2.0 0x9803CCEC & 0x9803CC68
	 * can't be used because of 1295 hardware issue.
	 */
	if (tmp_addr == 0xCEC || tmp_addr == 0xC68) {
		mask = PCIE_IO_2K_MASK;
		rtk_pci_ctrl_write(0xD00, PCIE_IO_2K_MASK);
		translate_val = rtk_pci_ctrl_read(0xD04);
		rtk_pci_ctrl_write(0xD04, translate_val | (addr & mask));
	} else if (addr >= 0x1000) {
		mask = PCIE_IO_4K_MASK;
		translate_val = rtk_pci_ctrl_read(0xD04);
		rtk_pci_ctrl_write(0xD04, translate_val | (addr & mask));
	} else
		mask = 0x0;

#ifdef CONFIG_RTK_SW_LOCK_API
	/* All RBUS1 driver need to have a workaround for emmc hardware error. */
	/* Need to protect 0xXXXX_X8XX~ 0xXXXX_X9XX. */
	if((tmp_addr>0x7FF) && (tmp_addr < 0xA00))
		rtk_lockapi_lock(flags, __FUNCTION__);
#endif

	switch (size) {
	case 1:
		rtk_pci_direct_write_byte((addr&~mask), wval);
		break;
	case 2:
		rtk_pci_direct_write_word((addr&~mask), wval);
		break;
	case 4:
		rtk_pci_direct_write((addr&~mask), wval);
		break;
	default:
		printk(KERN_INFO "RTD129X: %s: wrong size %d\n", __func__, size);
		break;
	}

#ifdef CONFIG_RTK_SW_LOCK_API
	if((tmp_addr>0x7FF) && (tmp_addr<0xA00))
		rtk_lockapi_unlock(flags, __FUNCTION__);
#endif

	/* PCIE1.1 0x9804FCEC, PCIE2.0 0x9803CCEC & 0x9803CC68
	 * can't be used because of 1295 hardware issue.
	 */
	if (tmp_addr == 0xCEC || tmp_addr == 0xC68) {
		rtk_pci_ctrl_write(0xD04, translate_val);
		rtk_pci_ctrl_write(0xD00, PCIE_IO_4K_MASK);
	} else if (addr >= 0x1000) {
		rtk_pci_ctrl_write(0xD04, translate_val);
	}

	spin_unlock_irqrestore(&rtk_pcie2_lock, irqL);
}

u8 rtk_pcie2_readb(const volatile void __iomem *addr)
{
	return rtk_pcie2_read((u64)addr, 1);
}
EXPORT_SYMBOL(rtk_pcie2_readb);

u16 rtk_pcie2_readw(const volatile void __iomem *addr)
{
	return rtk_pcie2_read((u64)addr, 2);
}
EXPORT_SYMBOL(rtk_pcie2_readw);

u32 rtk_pcie2_readl(const volatile void __iomem *addr)
{
	return rtk_pcie2_read((u64)addr, 4);
}
EXPORT_SYMBOL(rtk_pcie2_readl);

u64 rtk_pcie2_readq(const volatile void __iomem *addr)
{
	const volatile u32 __iomem *p = addr;
	u32 low, high;

	low = rtk_pcie2_read((u64)p, 4);
	high = rtk_pcie2_read((u64)(p + 1), 4);

	return low + ((u64)high << 32);
}
EXPORT_SYMBOL(rtk_pcie2_readq);

void rtk_pcie2_writeb(u8 val, volatile void __iomem *addr)
{
	rtk_pcie2_write((u64)addr, 1, val);
	return;
}
EXPORT_SYMBOL(rtk_pcie2_writeb);

void rtk_pcie2_writew(u16 val, volatile void __iomem *addr)
{
	rtk_pcie2_write((u64)addr, 2, val);
	return;
}
EXPORT_SYMBOL(rtk_pcie2_writew);

void rtk_pcie2_writel(u32 val, volatile void __iomem *addr)
{
	rtk_pcie2_write((u64)addr, 4, val);
	return;
}
EXPORT_SYMBOL(rtk_pcie2_writel);

void rtk_pcie2_writeq(u64 val, volatile void __iomem *addr)
{
	rtk_pcie2_write((u64)addr, 4, val);
	rtk_pcie2_write((u64)addr + 4, 4, val >> 32);
	return;
}
EXPORT_SYMBOL(rtk_pcie2_writeq);

static int _indirect_cfg_write(unsigned long addr, unsigned long data, unsigned char size)
{

	unsigned long status;
	unsigned char mask;
	int try_count = 1000;

	if (ADDR_TO_DEVICE_NO(addr) != 0)
		return PCIBIOS_DEVICE_NOT_FOUND;

	mask = _pci_byte_mask(addr, size);

	if (!mask)
		return PCIBIOS_SET_FAILED;

	data = (data << _pci_bit_shift(addr)) & _pci_bit_mask(mask);

	rtk_pci_ctrl_write(PCIE_INDIR_CTR, 0x12);
	rtk_pci_ctrl_write(PCIE_CFG_ST, CFG_ST_ERROR|CFG_ST_DONE);
	rtk_pci_ctrl_write(PCIE_CFG_ADDR, addr);
	rtk_pci_ctrl_write(PCIE_CFG_WDATA, data);

	if (size == 4)
		rtk_pci_ctrl_write(PCIE_CFG_EN, 0x1);
	else
		rtk_pci_ctrl_write(PCIE_CFG_EN, BYTE_CNT(mask) | BYTE_EN | WRRD_EN(1));

	rtk_pci_ctrl_write(PCIE_CFG_CT, GO_CT);

	do {
		status = rtk_pci_ctrl_read(PCIE_CFG_ST);
		udelay(50);
	} while (!(status & CFG_ST_DONE) && try_count--);

	if (try_count < 0) {
		PCI_CFG_WARNING("Write config data (%p) failed - timeout\n",
				(void *) addr);
		goto error_occur;
	}

	if (rtk_pci_ctrl_read(PCIE_CFG_ST) & CFG_ST_ERROR) {
		if (status & CFG_ST_DETEC_PAR_ERROR)
			PCI_CFG_WARNING("Write config data failed - PAR error detected\n");
		if (status & CFG_ST_SIGNAL_SYS_ERROR)
			PCI_CFG_WARNING("Write config data failed - system error\n");
		if (status & CFG_ST_REC_MASTER_ABORT)
			PCI_CFG_WARNING("Write config data failed - master abort\n");
		if (status & CFG_ST_REC_TARGET_ABORT)
			PCI_CFG_WARNING("Write config data failed - target abort\n");
		if (status & CFG_ST_SIG_TAR_ABORT)
			PCI_CFG_WARNING("Write config data failed - tar abort\n");

		goto error_occur;
	}

	rtk_pci_ctrl_write(PCIE_CFG_ST, CFG_ST_ERROR|CFG_ST_DONE);

	return PCIBIOS_SUCCESSFUL;

error_occur:

	rtk_pci_ctrl_write(PCIE_CFG_ST, CFG_ST_ERROR|CFG_ST_DONE);

	return PCIBIOS_SET_FAILED;
}

static int _indirect_cfg_read(unsigned long addr, u32 *pdata, unsigned char size)
{
	unsigned long status;
	unsigned char mask;
	int try_count = 20000;

	if (ADDR_TO_DEVICE_NO(addr) != 0)
		return PCIBIOS_DEVICE_NOT_FOUND;

	mask = _pci_byte_mask(addr, size);

	if (!mask)
		return PCIBIOS_SET_FAILED;

	rtk_pci_ctrl_write(PCIE_INDIR_CTR, 0x10);
	rtk_pci_ctrl_write(PCIE_CFG_ST, 0x3);
	rtk_pci_ctrl_write(PCIE_CFG_ADDR, (addr & ~0x3));
	rtk_pci_ctrl_write(PCIE_CFG_EN, BYTE_CNT(mask) | BYTE_EN | WRRD_EN(0));
	rtk_pci_ctrl_write(PCIE_CFG_CT, GO_CT);

	do {
		status = rtk_pci_ctrl_read(PCIE_CFG_ST);
		udelay(50);
	} while (!(status & CFG_ST_DONE) && try_count--);

	if (try_count < 0) {
		PCI_CFG_WARNING("Read config data (%p) failed - timeout\n", (void *) addr);
		goto error_occur;
	}

	if (rtk_pci_ctrl_read(PCIE_CFG_ST) & CFG_ST_ERROR) {
		if (status & CFG_ST_DETEC_PAR_ERROR)
			PCI_CFG_WARNING("Read config data failed - PAR error detected\n");
		if (status & CFG_ST_SIGNAL_SYS_ERROR)
			PCI_CFG_WARNING("Read config data failed - system error\n");
		if (status & CFG_ST_REC_MASTER_ABORT)
			PCI_CFG_WARNING("Read config data failed - master abort\n");
		if (status & CFG_ST_REC_TARGET_ABORT)
			PCI_CFG_WARNING("Read config data failed - target abort\n");
		if (status & CFG_ST_SIG_TAR_ABORT)
			PCI_CFG_WARNING("Read config data failed - tar abort\n");
		goto error_occur;
	}

	rtk_pci_ctrl_write(PCIE_CFG_ST, 0x3);

	*pdata = (rtk_pci_ctrl_read(PCIE_CFG_RDATA) & _pci_bit_mask(mask)) >> _pci_bit_shift(addr);
	return PCIBIOS_SUCCESSFUL;

error_occur:
	rtk_pci_ctrl_write(PCIE_CFG_ST, 0x3);
	return PCIBIOS_SET_FAILED;
}

static int rtk_pcie2_rd_conf(struct pci_bus *bus, unsigned int devfn,
			     int reg, int size, u32 *pval)
{
	unsigned long address;
	int ret = PCIBIOS_DEVICE_NOT_FOUND;
	u32 val = 0;
	u8 retry = 5;
	unsigned long irqL;

	if (rtd129x_cpu_revision == RTD129x_CHIP_REVISION_A00)
		udelay(200);

	spin_lock_irqsave(&rtk_pcie2_lock, irqL);
again:
	if (bus->number == 1 && PCI_SLOT(devfn) == 0 && PCI_FUNC(devfn) == 0) {
		if (cfg_direct_access) {
			rtk_pci_ctrl_write(0xC00, 0x40012);

			if (size == 1)
				*pval = rtk_pci_direct_read_byte(reg);
			else if (size == 2)
				*pval = rtk_pci_direct_read_word(reg);
			else if (size == 4)
				*pval = rtk_pci_direct_read(reg);

			rtk_pci_ctrl_write(0xC00, 0x1E0002);
			ret = PCIBIOS_SUCCESSFUL;

		} else {
			address = _pci_address_conversion(bus, devfn, reg);
			ret = _indirect_cfg_read(address, pval, size);
		}
	}

	val = rtk_pci_ctrl_read(0xC7C);
	if ((val & 0x1f) && retry) {
		rtk_pci_ctrl_write(0xC7C, val);
		retry--;
		dev_err(&bus->dev, "pcie2 dllp error occur = 0x%x\n", val);
		goto again;
	}
	spin_unlock_irqrestore(&rtk_pcie2_lock, irqL);

	//dev_info(&bus->dev, "rtk_pcie2_rd_conf reg = 0x%x, *pval = 0x%x\n", reg, *pval);

	return ret;
}

static int rtk_pcie2_wr_conf(struct pci_bus *bus, unsigned int devfn,
			     int reg, int size, u32 val)
{
	unsigned long address;
	unsigned long irqL;
	int ret = PCIBIOS_DEVICE_NOT_FOUND;

	//dev_info(&bus->dev, "rtk_pcie2_wr_conf reg = 0x%x, val = 0x%x\n", reg, val);

	if (rtd129x_cpu_revision == RTD129x_CHIP_REVISION_A00)
		udelay(200);

	spin_lock_irqsave(&rtk_pcie2_lock, irqL);
	if (bus->number == 1 && PCI_SLOT(devfn) == 0 && PCI_FUNC(devfn) == 0) {
		if ((reg == 0x10) || (reg == 0x18) || (reg == 0x20) || (reg == 0x24)) {
			if ((val & 0xc1000000) == 0xc1000000)
				rtk_pci_ctrl_write(0xD04, (val&0xfffffff0));
		}

		if (cfg_direct_access) {
			rtk_pci_ctrl_write(0xC00, 0x40012);

			if (size == 1)
				rtk_pci_direct_write_byte(reg, val);
			else if (size == 2)
				rtk_pci_direct_write_word(reg, val);
			else if (size == 4)
				rtk_pci_direct_write(reg, val);

			rtk_pci_ctrl_write(0xC00, 0x1E0002);
			ret = PCIBIOS_SUCCESSFUL;

		} else {
			address = _pci_address_conversion(bus, devfn, reg);
			ret = _indirect_cfg_write(address, val, size);
		}
	}

	spin_unlock_irqrestore(&rtk_pcie2_lock, irqL);
	return ret;
}

static struct pci_ops rtk_pcie2_ops = {
	.read = rtk_pcie2_rd_conf,
	.write = rtk_pcie2_wr_conf,
};

static int rtk_pcie_mdio_chk(void){
#if 0
	int ret = 1;
	unsigned long timeout = 0;

	timeout = jiffies + msecs_to_jiffies(200);
	while(time_before(jiffies, timeout)){
		if((rtk_pci_ctrl_read(0xC1C) & 0x80) == 0x00000000){
			ret = 0;
			break;
		}
	}

	return ret;
#else

	mdelay(1);
	return 0;

#endif

}

static int rtk_pcie2_hw_initial(struct device *dev)
{
	bool pci_link_detected;
	int timeout = 0;
	int ret = 0;
	u32 val;

	if (rtd129x_cpu_revision == RTD129x_CHIP_REVISION_A00 ||
	   (rtd129x_cpu_id == RTK1296_CPU_ID && rtd129x_cpu_revision != RTD129x_CHIP_REVISION_B00)) {
		/* 0x9801C614[2:0] = 1 */
		val = readl(SYSTEM_BASE1 + 0x14);
		val &= (~0x7);
		val |= 0x1;
		writel(val, SYSTEM_BASE1 + 0x14);

		/* 0x9801C600[19:16] = 0  --PCIE2 */
		val = readl(SYSTEM_BASE1);
		val &= (~(0xf << 16));
		writel(val, SYSTEM_BASE1);

		/* 0x9801C608[7:0] = 8’b01010000 */
		writeb(0x51, SYSTEM_BASE1 + 0x8);
	}

	reset_control_deassert(rstn_pcie1_stitch);
	reset_control_deassert(rstn_pcie1);
	reset_control_deassert(rstn_pcie1_core);
	reset_control_deassert(rstn_pcie1_power);
	reset_control_deassert(rstn_pcie1_nonstich);
	reset_control_deassert(rstn_pcie1_phy);
	reset_control_deassert(rstn_pcie1_phy_mdio);
	ret = clk_prepare_enable(pcie1_clk);

	if (ret) {
		dev_err(dev, "unable to enable pcie1_clk clock\n");
		clk_disable_unprepare(pcie1_clk);
		return -EINVAL;
	}

	rtk_pci_ctrl_write(0xC00, 0x00140010);

	if(speed_mode == 0){
		rtk_pci_ctrl_write(0x0A0, (rtk_pci_ctrl_read(0x0A0)&0xFFFFFFF0)|0x00000001);
	}

	/* #Write soft reset */
	rtk_pci_ctrl_write(0xC1C, 0x00000003);
	if(rtk_pcie_mdio_chk())
		return -1;

	rtk_pci_ctrl_write(0xC1C, 0x27f10301);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #F code,close SSC */
	rtk_pci_ctrl_write(0xC1C, 0x52F50401);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify N code */
	rtk_pci_ctrl_write(0xC1C, 0xead70501);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify CMU ICP(TX jitter) */
	rtk_pci_ctrl_write(0xC1C, 0x000c0601);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify CMU RS(tx jitter) */
	rtk_pci_ctrl_write(0xC1C, 0xa6530a01);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify AMP */
	rtk_pci_ctrl_write(0xC1C, 0xd4662001);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify Rx parameter */
	rtk_pci_ctrl_write(0xC1C, 0xa84a0101);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #clk driving */
	rtk_pci_ctrl_write(0xC1C, 0xb8032b01);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #EQ */
	rtk_pci_ctrl_write(0xC1C, 0x27e94301);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #F code,close SSC */
	rtk_pci_ctrl_write(0xC1C, 0x52f54401);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify N code */
	rtk_pci_ctrl_write(0xC1C, 0xead74501);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify CMU ICP(TX jitter) */
	rtk_pci_ctrl_write(0xC1C, 0x000c4601);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify CMU RS(tx jitter) */
	rtk_pci_ctrl_write(0xC1C, 0xa6534a01);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify AMP */
	rtk_pci_ctrl_write(0xC1C, 0xd4776001);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #modify Rx parameter */
	rtk_pci_ctrl_write(0xC1C, 0xa84a4101);
	if(rtk_pcie_mdio_chk())
		return -1;

	/* #clk driving */
	rtk_pci_ctrl_write(0xC1C, 0xa8036b01);
	if(rtk_pcie_mdio_chk())
		return -1;

	rtk_pci_ctrl_write(0xC1C, 0x01225a01);
	if(rtk_pcie_mdio_chk())
		return -1;

	// after phy mdio set
	ret = gpio_direction_output(pcie_gpio_20, 0);
	mdelay(100);
	ret = gpio_direction_output(pcie_gpio_20, 1);

	/* set to MMIO */
	if (cfg_direct_access)
		rtk_pci_ctrl_write(0xC00, 0x00040012);
	else
		rtk_pci_ctrl_write(0xC00, 0x001E0022);

	msleep(50);

	/* #Link initial setting */
	rtk_pci_ctrl_write(0x710, 0x00010120);

	do {
		pci_link_detected = (rtk_pci_ctrl_read(0xCB4) & 0x800);
		if (!pci_link_detected) {
			mdelay(TIMEOUT_RESOLUTION);
			timeout += TIMEOUT_RESOLUTION;
		}
	} while (!pci_link_detected && timeout < PCIE_CONNECT_TIMEOUT);

	if (pci_link_detected) {
		dev_err(dev, "PCIE device has link up in slot 2\n");
	} else {
		reset_control_assert(rstn_pcie1_stitch);
		reset_control_assert(rstn_pcie1);
		reset_control_assert(rstn_pcie1_core);
		reset_control_assert(rstn_pcie1_power);
		reset_control_assert(rstn_pcie1_nonstich);
		reset_control_assert(rstn_pcie1_phy);
		reset_control_assert(rstn_pcie1_phy_mdio);
		clk_disable_unprepare(pcie1_clk);
		gpio_free(pcie_gpio_20);
		dev_err(dev, "PCIE device has link down in slot 2\n");
		return -ENODEV;
	}

	writel(readl(EMMC_MUXPAD + 0x61C) | 0x00000010, EMMC_MUXPAD + 0x61C);

	/* make sure DBI is working */
	rtk_pci_ctrl_write(0x04, 0x00000007);

	/* #Base */
	rtk_pci_ctrl_write(0xCFC, 0x9803C000);

	/* #Mask */
	rtk_pci_ctrl_write(0xD00, 0xFFFFF000);

	/* #translate for CFG R/W */
	rtk_pci_ctrl_write(0xD04, 0x50000000);

	/* prevent pcie hang if dllp error occur*/
	rtk_pci_ctrl_write(0xC78, 0x200001);

	/* set limit and base register */
	rtk_pci_ctrl_write(0x20, 0x0000FFF0);
	rtk_pci_ctrl_write(0x24, 0x0000FFF0);

#ifdef CONFIG_PCI_MSI
	if (!no_msi) {
		rtk_pci_ctrl_write(0xC04, 0x1C00);
	}
#endif /* CONFIG_PCI_MSI */

	return ret;
}

#ifdef CONFIG_PCI_MSI
/* MSI int handler */
irqreturn_t rtk_handle_msi_irq(int _irq, void *_data)
{
	unsigned long val = 0;
	int pos, irq;
	irqreturn_t ret = IRQ_NONE;
	u32 int_stat = 0;

	int_stat = readl(DCSYS_BASE + 0x240);
	if (int_stat & 0x2000){
		writel(0x5400, DCSYS_BASE + 0x240);/*interrupt clear*/
	} else {
		return IRQ_HANDLED;
	}
	while(1){
		val = *pcie2_msi_data;
		if(val != 0x0){
			*pcie2_msi_data = 0x0;
			break;
		}
	}

	ret = IRQ_HANDLED;
	pos = 0;
	while ((pos = find_next_bit(&val, MAX_RTK_MSI_IRQS, pos)) != MAX_RTK_MSI_IRQS) {
		irq = irq_find_mapping(pcie2_irq_domain, pos);
		generic_handle_irq(irq);
		pos++;
	}

	return ret;
}

static struct irq_chip rtk_msi_irq_chip = {
	.name = "RTK-PCIE2-MSI",
	.irq_enable = pci_msi_unmask_irq,
	.irq_disable = pci_msi_mask_irq,
	.irq_mask = pci_msi_mask_irq,
	.irq_unmask = pci_msi_unmask_irq,
};

void rtk_pcie_msi_init(void)
{
	pcie2_msi_data = (unsigned long *)__get_free_pages(GFP_KERNEL, 0);
	rtk_pci_ctrl_write(0xCD0, virt_to_phys((void *)pcie2_msi_data));
	*(volatile unsigned int *)pcie2_msi_data = 0;
}

static void rtk_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	msg->address_lo = dma_handle;
	msg->address_hi = 0x0;
	msg->data = 1 << data->hwirq;
}

static int rtk_msi_set_affinity(struct irq_data *irq_data,
				   const struct cpumask *mask, bool force)
{
	 return -EINVAL;
}

static struct irq_chip rtk_msi_bottom_irq_chip = {
	.name			= "Realtek MSI",
	.irq_compose_msi_msg	= rtk_compose_msi_msg,
	.irq_set_affinity	= rtk_msi_set_affinity,
};

static int rtk_irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
				   unsigned int nr_irqs, void *args)
{
	int pos0;

	WARN_ON(nr_irqs != 1);
	mutex_lock(&msi_lock);
	pos0 = find_first_zero_bit(rtk_pcie_irq_bitmap, MAX_RTK_MSI_IRQS);

	if (pos0 >= MAX_RTK_MSI_IRQS) {
		printk("[%s]ERROR: irq domain number(%d) > MAX_RTK_MSI_IRQS(%d)\n", __func__, pos0, MAX_RTK_MSI_IRQS);
		return -ENOSPC;
	}

	set_bit(pos0, rtk_pcie_irq_bitmap);
	mutex_unlock(&msi_lock);
	irq_domain_set_info(domain, virq, pos0, &rtk_msi_bottom_irq_chip,
			    domain->host_data, handle_simple_irq,
			    NULL, NULL);
	//set_irq_flags(virq, IRQF_VALID);

	return 0;
}

static void rtk_irq_domain_free(struct irq_domain *domain,
				   unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);

	mutex_lock(&msi_lock);
	if (!test_bit(d->hwirq, rtk_pcie_irq_bitmap)) {
		printk("[%s] PCIE: irq domain number(%lu) not in rtk_pcie_irq_bitmap\n", __func__, d->hwirq);
	} else {
		__clear_bit(d->hwirq, rtk_pcie_irq_bitmap);
	}
	mutex_unlock(&msi_lock);
}

static const struct irq_domain_ops rtk_msi_domain_ops = {
	.alloc = rtk_irq_domain_alloc,
	.free = rtk_irq_domain_free,
};

static struct msi_domain_info rtk_msi_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS | MSI_FLAG_MULTI_PCI_MSI),
	.chip	= &rtk_msi_irq_chip,
};

#endif /* CONFIG_PCI_MSI */

static int rtk_pcie2_probe(struct platform_device *pdev)
{
	int ret = 0;
	int size = 0;
	const u32 *prop;
#ifdef CONFIG_PCI_MSI
	int irq;
	struct fwnode_handle *fwnode = of_node_to_fwnode(pdev->dev.of_node);
	u32 tmp = 0;
#endif /* CONFIG_PCI_MSI */
	
	resource_size_t iobase = 0;
	LIST_HEAD(res);

	dev_info(&pdev->dev, "PCIE host driver initial begin.\n");

	prop = of_get_property(pdev->dev.of_node, "speed-mode", &size);
	if(prop){
		speed_mode = of_read_number(prop, 1);
		if(speed_mode == 0){
			dev_info(&pdev->dev, "Speed Mode: GEN1\n");
		}else if(speed_mode == 1){
			dev_info(&pdev->dev, "Speed Mode: GEN2\n");
		}
	}

	PCIE_CTRL_BASE = of_iomap(pdev->dev.of_node, 0);
	if (!PCIE_CTRL_BASE) {
		dev_err(&pdev->dev, "pcie no ctrl address\n");
		return -EINVAL;
	}

	PCIE_CFG_BASE = of_iomap(pdev->dev.of_node, 1);
	if (!PCIE_CFG_BASE) {
		dev_err(&pdev->dev, "pcie no cfg address\n");
		return -EINVAL;
	}

	SYSTEM_BASE1 = of_iomap(pdev->dev.of_node, 2);
	if (!SYSTEM_BASE1) {
		dev_err(&pdev->dev, "pcie no base1 address\n");
		return -EINVAL;
	}

	SYSTEM_BASE2 = of_iomap(pdev->dev.of_node, 3);
	if (!SYSTEM_BASE2) {
		dev_err(&pdev->dev, "pcie no base2 address\n");
		return -EINVAL;
	}

	EMMC_MUXPAD = of_iomap(pdev->dev.of_node, 4);
	if (!EMMC_MUXPAD) {
		dev_err(&pdev->dev, "can't request 'EMMC_MUXPAD' address\n");
		return -EINVAL;
	}

#ifdef CONFIG_PCI_MSI
	DCSYS_BASE = of_iomap(pdev->dev.of_node, 5);
	if (!DCSYS_BASE) {
		dev_err(&pdev->dev, "can't request 'DCSYS_BASE' address, no init msi\n");
		no_msi = 1;
	}
#endif /* CONFIG_PCI_MSI */

	pcie_gpio_20 = of_get_gpio_flags(pdev->dev.of_node, 0, NULL);
	if (gpio_is_valid(pcie_gpio_20)) {
		ret = gpio_request(pcie_gpio_20, "pcie_gpio(20)");
		if (ret < 0)
			printk(KERN_ERR "%s: can't request gpio %d\n", __func__, pcie_gpio_20);
	} else
		printk(KERN_ERR "%s: gpio %d is not valid\n", __func__, pcie_gpio_20);

	pcie1_clk = devm_clk_get(&pdev->dev, "clk_en_pcie1");
	if (IS_ERR(pcie1_clk)) {
		dev_err(&pdev->dev, "pcie 1 clock source missing or invalid\n");
		return PTR_ERR(pcie1_clk);
	}

	rstn_pcie1_stitch = rstc_get("rstn_pcie1_stitch");
	if(rstn_pcie1_stitch == NULL){
		dev_err(&pdev->dev, "rstn_pcie1_stitch source missing or invalid\n");
		return -EINVAL;
	}

	rstn_pcie1 = rstc_get("rstn_pcie1");
	if(rstn_pcie1 == NULL){
		dev_err(&pdev->dev, "rstn_pcie1 source missing or invalid\n");
		return -EINVAL;
	}

	rstn_pcie1_core = rstc_get("rstn_pcie1_core");
	if(rstn_pcie1_core == NULL){
		dev_err(&pdev->dev, "rstn_pcie1_core source missing or invalid\n");
		return -EINVAL;
	}

	rstn_pcie1_power = rstc_get("rstn_pcie1_power");
	if(rstn_pcie1_power == NULL){
		dev_err(&pdev->dev, "rstn_pcie1_power source missing or invalid\n");
		return -EINVAL;
	}

	rstn_pcie1_nonstich = rstc_get("rstn_pcie1_nonstich");
	if(rstn_pcie1_nonstich == NULL){
		dev_err(&pdev->dev, "rstn_pcie1_nonstich source missing or invalid\n");
		return -EINVAL;
	}

	rstn_pcie1_phy = rstc_get("rstn_pcie1_phy");
	if(rstn_pcie1_phy == NULL){
		dev_err(&pdev->dev, "rstn_pcie1_phy source missing or invalid\n");
		return -EINVAL;
	}

	rstn_pcie1_phy_mdio = rstc_get("rstn_pcie1_phy_mdio");
	if(rstn_pcie1_phy_mdio == NULL){
		dev_err(&pdev->dev, "rstn_pcie1_phy_mdio source missing or invalid\n");
		return -EINVAL;
	}

	rtd129x_cpu_id = get_rtd129x_cpu_id();
	rtd129x_cpu_revision = get_rtd129x_cpu_revision();

	if (rtk_pcie2_hw_initial(&pdev->dev) < 0) {
		dev_err(&pdev->dev, "rtk_pcie2_hw_initial fail\n");
		return -EINVAL;
	}

#ifdef CONFIG_PCI_MSI
	if (no_msi) {
		goto no_msi;
	}

	mutex_init(&msi_lock);

	/*MSI Init*/
	irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (irq < 0) {
		printk(KERN_ERR "PCIE2 request irq(%d) failed\n", irq);
		return -EINVAL;
	}

	ret = request_irq(irq, rtk_handle_msi_irq, IRQF_SHARED,
						"rtk-pcie2-msi", pdev);

	if (ret !=0)
		printk("[%s]request irq failed\n", __func__);

	pcie2_irq_domain = irq_domain_add_linear(pdev->dev.of_node,
					MAX_RTK_MSI_IRQS, &rtk_msi_domain_ops,
					NULL);
	if (!pcie2_irq_domain) {
		dev_err(&pdev->dev, "irq domain init failed\n");
		return -ENXIO;
	}

	rtk_msi_domain = pci_msi_create_irq_domain(fwnode, &rtk_msi_domain_info, pcie2_irq_domain);

	if (!rtk_msi_domain) {
		printk("[%s]failed to create MSI domain\n", __func__);
		irq_domain_remove(pcie2_irq_domain);
		return -ENOMEM;
	}
	pcie2_msi_data  = dma_alloc_coherent(&pdev->dev, PAGE_SIZE, &dma_handle, GFP_KERNEL);
	writel(1 << 30 | ((dma_handle >> 5) << 2), DCSYS_BASE + 0x200);/*write start address*/
	writel((((dma_handle + 0x4) >> 5) << 2), DCSYS_BASE + 0x220);/*write end address*/
	writel(0x56, DCSYS_BASE + 0x260); /*monitor pcie*/
	tmp = (0x1 << 2)| (0x1 << 0) | (0x1 << 23) | (0x2 << 21) | (0x2 << 19) | (0x2 << 17) | (0x2 << 15)
		| (0x1 << 8) | (0x1 << 3) | (0x1 << 4) | (0x1 << 5) | (0x0 << 6);
	writel(tmp, DCSYS_BASE + 0x240); /*set write access type & interrupt to cpu*/
	*pcie2_msi_data = 0x0;

no_msi:
#endif /* CONFIG_PCI_MSI */

	/*-------------------------------------------
	 * Register PCI-E host
	 *-------------------------------------------*/

	ret = of_pci_get_host_bridge_resources(pdev->dev.of_node, 0x1, 0xff, &res, &iobase);
	if (ret)
		return ret;

	bus = pci_create_root_bus(&pdev->dev, 1, &rtk_pcie2_ops, NULL, &res);

	if (!bus)
		return -ENOMEM;

	pci_scan_child_bus(bus);
	pci_assign_unassigned_bus_resources(bus);
	pci_bus_add_devices(bus);

	dev_info(&pdev->dev, "PCIE host driver initial done.\n");

	return ret;
}
#ifdef CONFIG_SUSPEND
static int rtk_pcie2_suspend(struct device *dev)
{
	dev_info(dev, "suspend enter ...\n");

	if(RTK_PM_STATE == PM_SUSPEND_STANDBY){
		rtk_pci_ctrl_write(0x178, 0xA3FF0001);
		rtk_pci_ctrl_write(0x098, 0x400);
		rtk_pci_ctrl_write(0xC6C, 0x00000031);
		dev_info(dev, "Idle mode\n");
	}else{
		dev_info(dev, "Suspend mode\n");
		reset_control_assert(rstn_pcie1_stitch);
		reset_control_assert(rstn_pcie1);
		reset_control_assert(rstn_pcie1_core);
		reset_control_assert(rstn_pcie1_power);
		reset_control_assert(rstn_pcie1_nonstich);
		reset_control_assert(rstn_pcie1_phy);
		reset_control_assert(rstn_pcie1_phy_mdio);
		clk_disable_unprepare(pcie1_clk);

		gpio_direction_output(pcie_gpio_20, 0);
		gpio_free(pcie_gpio_20);
	}

	dev_info(dev, "suspend exit ...\n");

	return 0;
}

static int rtk_pcie2_resume(struct device *dev)
{
	int ret = 0;

	dev_info(dev, "resume enter ...\n");

	if(RTK_PM_STATE == PM_SUSPEND_STANDBY){
		rtk_pci_ctrl_write(0xC6C, 0x00000032);
		dev_info(dev, "Idle mode\n");
	}else{
		dev_info(dev, "Suspend mode\n");
		if (gpio_is_valid(pcie_gpio_20)) {
			ret = gpio_request(pcie_gpio_20, "pcie_gpio(20)");
			if (ret < 0)
				printk(KERN_ERR "%s: can't request gpio %d\n", __func__, pcie_gpio_20);
		} else
			printk(KERN_ERR "%s: gpio %d is not valid\n", __func__, pcie_gpio_20);

		reset_control_deassert(rstn_pcie1_stitch);
		reset_control_deassert(rstn_pcie1);
		reset_control_deassert(rstn_pcie1_core);
		reset_control_deassert(rstn_pcie1_power);
		reset_control_deassert(rstn_pcie1_nonstich);
		reset_control_deassert(rstn_pcie1_phy);
		reset_control_deassert(rstn_pcie1_phy_mdio);
		ret = clk_prepare_enable(pcie1_clk);
		if (ret) {
			dev_err(dev, "unable to enable pcie1_clk clock\n");
			clk_disable_unprepare(pcie1_clk);
			return -EINVAL;
		}

		if (rtk_pcie2_hw_initial(dev) < 0) {
			dev_err(dev, "rtk_pcie2_hw_initial fail\n");
			return -EINVAL;
		}
	}

	dev_info(dev, "resume exit ...\n");

	return ret;
}

static struct dev_pm_ops rtk_pcie2_pm_ops = {
	.suspend_noirq = rtk_pcie2_suspend,
	.resume_noirq = rtk_pcie2_resume,
};
#endif //CONFIG_SUSPEND
static const struct of_device_id rtk_pcie2_match_table[] = {
	{.compatible = "realtek,rtd1295-pcie-slot2",},
	{},
};

static struct platform_driver rtk_pcie2_driver = {
	.driver = {
		   .name = "[RTD129x PCIE Slot2]",
		   .of_match_table = of_match_ptr(rtk_pcie2_match_table),
#ifdef CONFIG_SUSPEND
		   .pm = &rtk_pcie2_pm_ops,
#endif
	},
	.probe = rtk_pcie2_probe,
};
module_platform_driver(rtk_pcie2_driver);

MODULE_AUTHOR("James Tai <james.tai@realtek.com>");
MODULE_DESCRIPTION("Realtek PCIe slot2 host controller driver");
