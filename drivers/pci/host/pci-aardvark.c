#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined(MY_DEF_HERE)
/*
 * Driver for the Aardvark PCIe controller, used on Marvell Armada
 * 3700.
 *
 * Copyright (C) 2016 Marvell
 *
 */
#if defined(MY_DEF_HERE)
/*
 * Author: Hezi Shahmoon <hezi.shahmoon@marvell.com>
 */
#endif /* MY_DEF_HERE */
/*
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#if defined(MY_DEF_HERE)
#include <linux/phy/phy.h>
#include <linux/of_gpio.h>
#endif /* MY_DEF_HERE */

/* PCIe core registers */
#define PCIE_CORE_CMD_STATUS_REG				0x4
#define     PCIE_CORE_CMD_IO_ACCESS_EN				BIT(0)
#define     PCIE_CORE_CMD_MEM_ACCESS_EN				BIT(1)
#define     PCIE_CORE_CMD_MEM_IO_REQ_EN				BIT(2)
#define PCIE_CORE_DEV_CTRL_STATS_REG				0xc8
#define     PCIE_CORE_DEV_CTRL_STATS_RELAX_ORDER_DISABLE	(0 << 4)
#define     PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ_SHIFT	5
#if defined(MY_DEF_HERE)
#define     PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ		0x2
#endif /* MY_DEF_HERE */
#define     PCIE_CORE_DEV_CTRL_STATS_SNOOP_DISABLE		(0 << 11)
#define     PCIE_CORE_DEV_CTRL_STATS_MAX_RD_REQ_SIZE_SHIFT	12
#if defined(MY_DEF_HERE)
#define     PCIE_CORE_DEV_CTRL_STATS_MAX_RD_REQ_SZ		0x2
#define     PCIE_CORE_MPS_UNIT_BYTE				128
#endif /* MY_DEF_HERE */
#define PCIE_CORE_LINK_CTRL_STAT_REG				0xd0
#define     PCIE_CORE_LINK_L0S_ENTRY				BIT(0)
#define     PCIE_CORE_LINK_TRAINING				BIT(5)
#define     PCIE_CORE_LINK_WIDTH_SHIFT				20
#define PCIE_CORE_ERR_CAPCTL_REG				0x118
#define     PCIE_CORE_ERR_CAPCTL_ECRC_CHK_TX			BIT(5)
#define     PCIE_CORE_ERR_CAPCTL_ECRC_CHK_TX_EN			BIT(6)
#define     PCIE_CORE_ERR_CAPCTL_ECRC_CHCK			BIT(7)
#define     PCIE_CORE_ERR_CAPCTL_ECRC_CHCK_RCV			BIT(8)
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
#define PCIE_PHY_REF_CLOCK					0x4814
#define     PCIE_PHY_CTRL_OFF					16
#define     PCIE_PHY_BUF_CTRL_OFF				0
#define     PCIE_PHY_BUF_CTRL_INIT_VAL				0x1342
#endif /* MY_DEF_HERE */
#endif /* MY_DEF_HERE */

/* PIO registers base address and register offsets */
#define PIO_BASE_ADDR				0x4000
#define PIO_CTRL				(PIO_BASE_ADDR + 0x0)
#define   PIO_CTRL_TYPE_MASK			GENMASK(3, 0)
#define   PIO_CTRL_ADDR_WIN_DISABLE		BIT(24)
#define PIO_STAT				(PIO_BASE_ADDR + 0x4)
#define   PIO_COMPLETION_STATUS_SHIFT		7
#define   PIO_COMPLETION_STATUS_MASK		GENMASK(9, 7)
#define   PIO_COMPLETION_STATUS_OK		0
#define   PIO_COMPLETION_STATUS_UR		1
#define   PIO_COMPLETION_STATUS_CRS		2
#define   PIO_COMPLETION_STATUS_CA		4
#define   PIO_NON_POSTED_REQ			BIT(0)
#define PIO_ADDR_LS				(PIO_BASE_ADDR + 0x8)
#define PIO_ADDR_MS				(PIO_BASE_ADDR + 0xc)
#define PIO_WR_DATA				(PIO_BASE_ADDR + 0x10)
#define PIO_WR_DATA_STRB			(PIO_BASE_ADDR + 0x14)
#define PIO_RD_DATA				(PIO_BASE_ADDR + 0x18)
#define PIO_START				(PIO_BASE_ADDR + 0x1c)
#define PIO_ISR					(PIO_BASE_ADDR + 0x20)
#define PIO_ISRM				(PIO_BASE_ADDR + 0x24)

/* Aardvark Control registers */
#define CONTROL_BASE_ADDR			0x4800
#define PCIE_CORE_CTRL0_REG			(CONTROL_BASE_ADDR + 0x0)
#define     PCIE_GEN_SEL_MSK			0x3
#define     PCIE_GEN_SEL_SHIFT			0x0
#define     SPEED_GEN_1				0
#define     SPEED_GEN_2				1
#define     SPEED_GEN_3				2
#define     IS_RC_MSK				1
#define     IS_RC_SHIFT				2
#define     LANE_CNT_MSK			0x18
#define     LANE_CNT_SHIFT			0x3
#define     LANE_COUNT_1			(0 << LANE_CNT_SHIFT)
#define     LANE_COUNT_2			(1 << LANE_CNT_SHIFT)
#define     LANE_COUNT_4			(2 << LANE_CNT_SHIFT)
#define     LANE_COUNT_8			(3 << LANE_CNT_SHIFT)
#define     LINK_TRAINING_EN			BIT(6)
#define     LEGACY_INTA				BIT(28)
#define     LEGACY_INTB				BIT(29)
#define     LEGACY_INTC				BIT(30)
#define     LEGACY_INTD				BIT(31)
#define PCIE_CORE_CTRL1_REG			(CONTROL_BASE_ADDR + 0x4)
#define     HOT_RESET_GEN			BIT(0)
#define PCIE_CORE_CTRL2_REG			(CONTROL_BASE_ADDR + 0x8)
#define     PCIE_CORE_CTRL2_RESERVED		0x7
#define     PCIE_CORE_CTRL2_TD_ENABLE		BIT(4)
#define     PCIE_CORE_CTRL2_STRICT_ORDER_ENABLE	BIT(5)
#define     PCIE_CORE_CTRL2_OB_WIN_ENABLE	BIT(6)
#define     PCIE_CORE_CTRL2_MSI_ENABLE		BIT(10)
#if defined(MY_DEF_HERE)
#define PCIE_PHY_REF_CLOCK			(CONTROL_BASE_ADDR + 0x14)
#define     PCIE_PHY_CTRL_OFF			16
#define     PCIE_PHY_BUF_CTRL_OFF		0
#define     PCIE_PHY_BUF_CTRL_INIT_VAL		0x1342
#endif /* MY_DEF_HERE */
#define PCIE_ISR0_REG				(CONTROL_BASE_ADDR + 0x40)
#define PCIE_ISR0_MASK_REG			(CONTROL_BASE_ADDR + 0x44)
#define     PCIE_ISR0_MSI_INT_PENDING		BIT(24)
#define     PCIE_ISR0_INTX_ASSERT(val)		BIT(16 + (val))
#define     PCIE_ISR0_INTX_DEASSERT(val)	BIT(20 + (val))
#define	    PCIE_ISR0_ALL_MASK			GENMASK(26, 0)
#define PCIE_ISR1_REG				(CONTROL_BASE_ADDR + 0x48)
#define PCIE_ISR1_MASK_REG			(CONTROL_BASE_ADDR + 0x4C)
#define     PCIE_ISR1_POWER_STATE_CHANGE	BIT(4)
#define     PCIE_ISR1_FLUSH			BIT(5)
#if defined(MY_DEF_HERE)
#define     PCIE_ISR1_INTX_ASSERT(val)		BIT(8 + (val))
#define     PCIE_ISR1_ALL_MASK			GENMASK(11, 4)
#else /* MY_DEF_HERE */
#define     PCIE_ISR1_ALL_MASK			GENMASK(5, 4)
#endif /* MY_DEF_HERE */
#define PCIE_MSI_ADDR_LOW_REG			(CONTROL_BASE_ADDR + 0x50)
#define PCIE_MSI_ADDR_HIGH_REG			(CONTROL_BASE_ADDR + 0x54)
#define PCIE_MSI_STATUS_REG			(CONTROL_BASE_ADDR + 0x58)
#define PCIE_MSI_MASK_REG			(CONTROL_BASE_ADDR + 0x5C)
#define PCIE_MSI_PAYLOAD_REG			(CONTROL_BASE_ADDR + 0x9C)

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
/* PCIe window configuration */
#define OB_WIN_BASE_ADDR			0x4c00
#define OB_WIN_BLOCK_SIZE			0x20
#define OB_WIN_REG_ADDR(win, offset)		(OB_WIN_BASE_ADDR + \
						 OB_WIN_BLOCK_SIZE * (win) + \
						 (offset))
#define OB_WIN_MATCH_LS(win)			OB_WIN_REG_ADDR(win, 0x00)
#define OB_WIN_MATCH_MS(win)			OB_WIN_REG_ADDR(win, 0x04)
#define OB_WIN_REMAP_LS(win)			OB_WIN_REG_ADDR(win, 0x08)
#define OB_WIN_REMAP_MS(win)			OB_WIN_REG_ADDR(win, 0x0c)
#define OB_WIN_MASK_LS(win)			OB_WIN_REG_ADDR(win, 0x10)
#define OB_WIN_MASK_MS(win)			OB_WIN_REG_ADDR(win, 0x14)
#define OB_WIN_ACTIONS(win)			OB_WIN_REG_ADDR(win, 0x18)

/* PCIe window types */
#define OB_PCIE_MEM				0x0
#define OB_PCIE_IO				0x4

#endif /* MY_DEF_HERE */
/* LMI registers base address and register offsets */
#define LMI_BASE_ADDR				0x6000
#define CFG_REG					(LMI_BASE_ADDR + 0x0)
#define     LTSSM_SHIFT				24
#define     LTSSM_MASK				0x3f
#define     LTSSM_L0				0x10
#define     RC_BAR_CONFIG			0x300

/* PCIe core controller registers */
#define CTRL_CORE_BASE_ADDR			0x18000
#define CTRL_CONFIG_REG				(CTRL_CORE_BASE_ADDR + 0x0)
#define     CTRL_MODE_SHIFT			0x0
#define     CTRL_MODE_MASK			0x1
#define     PCIE_CORE_MODE_DIRECT		0x0
#define     PCIE_CORE_MODE_COMMAND		0x1

/* PCIe Central Interrupts Registers */
#define CENTRAL_INT_BASE_ADDR			0x1b000
#define HOST_CTRL_INT_STATUS_REG		(CENTRAL_INT_BASE_ADDR + 0x0)
#define HOST_CTRL_INT_MASK_REG			(CENTRAL_INT_BASE_ADDR + 0x4)
#if defined(MY_DEF_HERE)
#define     PCIE_IRQ_CMDQ_INT			BIT(0)
#endif /* MY_DEF_HERE */
#define     PCIE_IRQ_MSI_STATUS_INT		BIT(1)
#if defined(MY_DEF_HERE)
#define     PCIE_IRQ_CMD_SENT_DONE		BIT(3)
#endif /* MY_DEF_HERE */
#define     PCIE_IRQ_DMA_INT			BIT(4)
#if defined(MY_DEF_HERE)
#define     PCIE_IRQ_IB_DXFERDONE		BIT(5)
#endif /* MY_DEF_HERE */
#define     PCIE_IRQ_OB_DXFERDONE		BIT(6)
#define     PCIE_IRQ_OB_RXFERDONE		BIT(7)
#if defined(MY_DEF_HERE)
#define     PCIE_IRQ_COMPQ_INT			BIT(12)
#define     PCIE_IRQ_DIR_RD_DDR_DET		BIT(13)
#define     PCIE_IRQ_DIR_WR_DDR_DET		BIT(14)
#endif /* MY_DEF_HERE */
#define     PCIE_IRQ_CORE_INT			BIT(16)
#define     PCIE_IRQ_CORE_INT_PIO		BIT(17)
#define     PCIE_IRQ_DPMU_INT			BIT(18)
#define     PCIE_IRQ_PCIE_MIS_INT		BIT(19)
#if defined(MY_DEF_HERE)
#define     PCIE_IRQ_MSI_INT1_DET		BIT(20)
#define     PCIE_IRQ_MSI_INT2_DET		BIT(21)
#define     PCIE_IRQ_RC_DBELL_DET		BIT(22)
#define     PCIE_IRQ_EP_STATUS			BIT(23)
#endif /* MY_DEF_HERE */
#define     PCIE_IRQ_ALL_MASK			0xfff0fb
#define     PCIE_IRQ_ENABLE_INTS_MASK		PCIE_IRQ_CORE_INT

/* Transaction types */
#define PCIE_CONFIG_RD_TYPE0			0x8
#define PCIE_CONFIG_RD_TYPE1			0x9
#define PCIE_CONFIG_WR_TYPE0			0xa
#define PCIE_CONFIG_WR_TYPE1			0xb

/* PCI_BDF shifts 8bit, so we need extra 4bit shift */
#define PCIE_BDF(dev)				(dev << 4)
#define PCIE_CONF_BUS(bus)			(((bus) & 0xff) << 20)
#define PCIE_CONF_DEV(dev)			(((dev) & 0x1f) << 15)
#define PCIE_CONF_FUNC(fun)			(((fun) & 0x7)	<< 12)
#define PCIE_CONF_REG(reg)			((reg) & 0xffc)
#define PCIE_CONF_ADDR(bus, devfn, where)	\
	(PCIE_CONF_BUS(bus) | PCIE_CONF_DEV(PCI_SLOT(devfn))	| \
	 PCIE_CONF_FUNC(PCI_FUNC(devfn)) | PCIE_CONF_REG(where))

#define PIO_TIMEOUT_MS			1

#define LINK_WAIT_MAX_RETRIES		10
#define LINK_WAIT_USLEEP_MIN		90000
#define LINK_WAIT_USLEEP_MAX		100000

#define LEGACY_IRQ_NUM			4
#define MSI_IRQ_NUM			32

struct advk_pcie {
	struct platform_device *pdev;
#if defined(MY_DEF_HERE)
	struct pci_bus *bus;
#endif /* MY_DEF_HERE */
	void __iomem *base;
#if defined(MY_DEF_HERE)
	struct phy *phy;
#endif /* MY_DEF_HERE */
	struct list_head resources;
	struct irq_domain *irq_domain;
	struct irq_chip irq_chip;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	struct msi_controller msi;
#endif /* MY_DEF_HERE */
	struct irq_domain *msi_domain;
#if defined(MY_DEF_HERE)
	struct irq_domain *msi_inner_domain;
	struct irq_chip msi_bottom_irq_chip;
#endif /* MY_DEF_HERE */
	struct irq_chip msi_irq_chip;
#if defined(MY_DEF_HERE)
	struct msi_domain_info msi_domain_info;
	DECLARE_BITMAP(msi_used, MSI_IRQ_NUM);
#else /* MY_DEF_HERE */
	DECLARE_BITMAP(msi_irq_in_use, MSI_IRQ_NUM);
#endif /* MY_DEF_HERE */
	struct mutex msi_used_lock;
	u16 msi_msg;
	int root_bus_nr;
#if defined(MY_DEF_HERE)
	char *reset_name;
	struct gpio_desc *reset_gpio;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	enum of_gpio_flags flags;
	struct clk *clk;
#endif /* MY_DEF_HERE */
};

static inline void advk_writel(struct advk_pcie *pcie, u32 val, u64 reg)
{
	writel(val, pcie->base + reg);
}

static inline u32 advk_readl(struct advk_pcie *pcie, u64 reg)
{
	return readl(pcie->base + reg);
}

static int advk_pcie_link_up(struct advk_pcie *pcie)
{
	u32 val, ltssm_state;

	val = advk_readl(pcie, CFG_REG);
	ltssm_state = (val >> LTSSM_SHIFT) & LTSSM_MASK;
	return ltssm_state >= LTSSM_L0;
}

static int advk_pcie_wait_for_link(struct advk_pcie *pcie)
{
#if defined(MY_DEF_HERE)
	struct device *dev = &pcie->pdev->dev;
#endif /* MY_DEF_HERE */
	int retries;

	/* check if the link is up or not */
	for (retries = 0; retries < LINK_WAIT_MAX_RETRIES; retries++) {
		if (advk_pcie_link_up(pcie)) {
#if defined(MY_DEF_HERE)
			dev_info(dev, "link up\n");
#else /* MY_DEF_HERE */
			dev_info(&pcie->pdev->dev, "link up\n");
#endif /* MY_DEF_HERE */
			return 0;
		}

		usleep_range(LINK_WAIT_USLEEP_MIN, LINK_WAIT_USLEEP_MAX);
	}

#if defined(MY_DEF_HERE)
	dev_err(dev, "link never came up\n");
#else /* MY_DEF_HERE */
	dev_err(&pcie->pdev->dev, "link never came up\n");

#endif /* MY_DEF_HERE */
	return -ETIMEDOUT;
}

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
/*
 * Set PCIe address window register which could be used for memory
 * mapping.
 */
static void advk_pcie_set_ob_win(struct advk_pcie *pcie,
				 u32 win_num, u32 match_ms,
				 u32 match_ls, u32 mask_ms,
				 u32 mask_ls, u32 remap_ms,
				 u32 remap_ls, u32 action)
{
	advk_writel(pcie, match_ls, OB_WIN_MATCH_LS(win_num));
	advk_writel(pcie, match_ms, OB_WIN_MATCH_MS(win_num));
	advk_writel(pcie, mask_ms, OB_WIN_MASK_MS(win_num));
	advk_writel(pcie, mask_ls, OB_WIN_MASK_LS(win_num));
	advk_writel(pcie, remap_ms, OB_WIN_REMAP_MS(win_num));
	advk_writel(pcie, remap_ls, OB_WIN_REMAP_LS(win_num));
	advk_writel(pcie, action, OB_WIN_ACTIONS(win_num));
	advk_writel(pcie, match_ls | BIT(0), OB_WIN_MATCH_LS(win_num));
}

#endif /* MY_DEF_HERE */
static void advk_pcie_setup_hw(struct advk_pcie *pcie)
{
	u32 reg;
#if defined(MY_DEF_HERE)
	phys_addr_t msi_msg_phys;
#else /* MY_DEF_HERE */
	int i;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Set HW Reference Clock Buffer Control */
	advk_writel(pcie, PCIE_PHY_BUF_CTRL_INIT_VAL, PCIE_PHY_REF_CLOCK);
#else /* MY_DEF_HERE */
	/* Point PCIe unit MBUS decode windows to DRAM space */
	for (i = 0; i < 8; i++)
		advk_pcie_set_ob_win(pcie, i, 0, 0, 0, 0, 0, 0, 0);
#endif /* MY_DEF_HERE */

	/* Set to Direct mode */
	reg = advk_readl(pcie, CTRL_CONFIG_REG);
	reg &= ~(CTRL_MODE_MASK << CTRL_MODE_SHIFT);
	reg |= ((PCIE_CORE_MODE_DIRECT & CTRL_MODE_MASK) << CTRL_MODE_SHIFT);
	advk_writel(pcie, reg, CTRL_CONFIG_REG);

	/* Set PCI global control register to RC mode */
	reg = advk_readl(pcie, PCIE_CORE_CTRL0_REG);
	reg |= (IS_RC_MSK << IS_RC_SHIFT);
	advk_writel(pcie, reg, PCIE_CORE_CTRL0_REG);

	/* Set Advanced Error Capabilities and Control PF0 register */
	reg = PCIE_CORE_ERR_CAPCTL_ECRC_CHK_TX |
		PCIE_CORE_ERR_CAPCTL_ECRC_CHK_TX_EN |
		PCIE_CORE_ERR_CAPCTL_ECRC_CHCK |
		PCIE_CORE_ERR_CAPCTL_ECRC_CHCK_RCV;
	advk_writel(pcie, reg, PCIE_CORE_ERR_CAPCTL_REG);

	/* Set PCIe Device Control and Status 1 PF0 register */
	reg = PCIE_CORE_DEV_CTRL_STATS_RELAX_ORDER_DISABLE |
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		(PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ <<
		 PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ_SHIFT) |
#else /* MY_DEF_HERE */
		(PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ << PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ_SHIFT) |
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		(7 << PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ_SHIFT) |
#endif /* MY_DEF_HERE */
		PCIE_CORE_DEV_CTRL_STATS_SNOOP_DISABLE |
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
		(PCIE_CORE_DEV_CTRL_STATS_MAX_RD_REQ_SZ <<
		 PCIE_CORE_DEV_CTRL_STATS_MAX_RD_REQ_SIZE_SHIFT);
#else /* MY_DEF_HERE */
		(PCIE_CORE_DEV_CTRL_STATS_MAX_RD_REQ_SZ << PCIE_CORE_DEV_CTRL_STATS_MAX_RD_REQ_SIZE_SHIFT);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
		PCIE_CORE_DEV_CTRL_STATS_MAX_RD_REQ_SIZE_SHIFT;
#endif /* MY_DEF_HERE */
	advk_writel(pcie, reg, PCIE_CORE_DEV_CTRL_STATS_REG);

	/* Program PCIe Control 2 to disable strict ordering */
	reg = PCIE_CORE_CTRL2_RESERVED |
		PCIE_CORE_CTRL2_TD_ENABLE;
	advk_writel(pcie, reg, PCIE_CORE_CTRL2_REG);

	/* Set GEN2 */
	reg = advk_readl(pcie, PCIE_CORE_CTRL0_REG);
	reg &= ~PCIE_GEN_SEL_MSK;
	reg |= SPEED_GEN_2;
	advk_writel(pcie, reg, PCIE_CORE_CTRL0_REG);

	/* Set lane X1 */
	reg = advk_readl(pcie, PCIE_CORE_CTRL0_REG);
	reg &= ~LANE_CNT_MSK;
	reg |= LANE_COUNT_1;
	advk_writel(pcie, reg, PCIE_CORE_CTRL0_REG);

	/* Enable link training */
	reg = advk_readl(pcie, PCIE_CORE_CTRL0_REG);
	reg |= LINK_TRAINING_EN;
	advk_writel(pcie, reg, PCIE_CORE_CTRL0_REG);

#if defined(MY_DEF_HERE)
	/* Set MSI Address in RC mode */
	msi_msg_phys = virt_to_phys(&pcie->msi_msg);
	advk_writel(pcie, lower_32_bits(msi_msg_phys),
		    PCIE_MSI_ADDR_LOW_REG);
	advk_writel(pcie, upper_32_bits(msi_msg_phys),
		    PCIE_MSI_ADDR_HIGH_REG);

#endif /* MY_DEF_HERE */
	/* Enable MSI */
	reg = advk_readl(pcie, PCIE_CORE_CTRL2_REG);
	reg |= PCIE_CORE_CTRL2_MSI_ENABLE;
	advk_writel(pcie, reg, PCIE_CORE_CTRL2_REG);

	/* Clear all interrupts */
	advk_writel(pcie, PCIE_ISR0_ALL_MASK, PCIE_ISR0_REG);
	advk_writel(pcie, PCIE_ISR1_ALL_MASK, PCIE_ISR1_REG);
	advk_writel(pcie, PCIE_IRQ_ALL_MASK, HOST_CTRL_INT_STATUS_REG);

	/* Disable All ISR0/1 Sources */
	reg = PCIE_ISR0_ALL_MASK;
	reg &= ~PCIE_ISR0_MSI_INT_PENDING;
	advk_writel(pcie, reg, PCIE_ISR0_MASK_REG);

	advk_writel(pcie, PCIE_ISR1_ALL_MASK, PCIE_ISR1_MASK_REG);

	/* Unmask all MSI's */
	advk_writel(pcie, 0, PCIE_MSI_MASK_REG);

	/* Enable summary interrupt for GIC SPI source */
	reg = PCIE_IRQ_ALL_MASK & (~PCIE_IRQ_ENABLE_INTS_MASK);
	advk_writel(pcie, reg, HOST_CTRL_INT_MASK_REG);

	reg = advk_readl(pcie, PCIE_CORE_CTRL2_REG);
	reg |= PCIE_CORE_CTRL2_OB_WIN_ENABLE;
	advk_writel(pcie, reg, PCIE_CORE_CTRL2_REG);

	/* Bypass the address window mapping for PIO */
	reg = advk_readl(pcie, PIO_CTRL);
	reg |= PIO_CTRL_ADDR_WIN_DISABLE;
	advk_writel(pcie, reg, PIO_CTRL);

	/* Start link training */
	reg = advk_readl(pcie, PCIE_CORE_LINK_CTRL_STAT_REG);
	reg |= PCIE_CORE_LINK_TRAINING;
	advk_writel(pcie, reg, PCIE_CORE_LINK_CTRL_STAT_REG);

	advk_pcie_wait_for_link(pcie);

#if defined(MY_DEF_HERE)
	reg = (1 << PCIE_CORE_LINK_WIDTH_SHIFT);
#else /* MY_DEF_HERE */
	reg = PCIE_CORE_LINK_L0S_ENTRY |
		(1 << PCIE_CORE_LINK_WIDTH_SHIFT);
#endif /* MY_DEF_HERE */
	advk_writel(pcie, reg, PCIE_CORE_LINK_CTRL_STAT_REG);

	reg = advk_readl(pcie, PCIE_CORE_CMD_STATUS_REG);
	reg |= PCIE_CORE_CMD_MEM_ACCESS_EN |
		PCIE_CORE_CMD_IO_ACCESS_EN |
		PCIE_CORE_CMD_MEM_IO_REQ_EN;
	advk_writel(pcie, reg, PCIE_CORE_CMD_STATUS_REG);
}

static void advk_pcie_check_pio_status(struct advk_pcie *pcie)
{
#if defined(MY_DEF_HERE)
	struct device *dev = &pcie->pdev->dev;
#endif /* MY_DEF_HERE */
	u32 reg;
	unsigned int status;
	char *strcomp_status, *str_posted;

	reg = advk_readl(pcie, PIO_STAT);
	status = (reg & PIO_COMPLETION_STATUS_MASK) >>
		PIO_COMPLETION_STATUS_SHIFT;

	if (!status)
		return;

	switch (status) {
	case PIO_COMPLETION_STATUS_UR:
		strcomp_status = "UR";
		break;
	case PIO_COMPLETION_STATUS_CRS:
		strcomp_status = "CRS";
		break;
	case PIO_COMPLETION_STATUS_CA:
		strcomp_status = "CA";
		break;
	default:
		strcomp_status = "Unknown";
		break;
	}

	if (reg & PIO_NON_POSTED_REQ)
		str_posted = "Non-posted";
	else
		str_posted = "Posted";

#if defined(MY_DEF_HERE)
	dev_err(dev, "%s PIO Response Status: %s, %#x @ %#x\n",
#else /* MY_DEF_HERE */
	dev_err(&pcie->pdev->dev, "%s PIO Response Status: %s, %#x @ %#x\n",
#endif /* MY_DEF_HERE */
		str_posted, strcomp_status, reg, advk_readl(pcie, PIO_ADDR_LS));
}

static int advk_pcie_wait_pio(struct advk_pcie *pcie)
{
#if defined(MY_DEF_HERE)
	struct device *dev = &pcie->pdev->dev;
#endif /* MY_DEF_HERE */
	unsigned long timeout;

	timeout = jiffies + msecs_to_jiffies(PIO_TIMEOUT_MS);

	while (time_before(jiffies, timeout)) {
		u32 start, isr;

		start = advk_readl(pcie, PIO_START);
		isr = advk_readl(pcie, PIO_ISR);
		if (!start && isr)
			return 0;
	}

#if defined(MY_DEF_HERE)
	dev_err(dev, "config read/write timed out\n");
#else /* MY_DEF_HERE */
	dev_err(&pcie->pdev->dev, "config read/write timed out\n");
#endif /* MY_DEF_HERE */
	return -ETIMEDOUT;
}

static int advk_pcie_rd_conf(struct pci_bus *bus, u32 devfn,
			     int where, int size, u32 *val)
{
	struct advk_pcie *pcie = bus->sysdata;
	u32 reg;
	int ret;

	if ((bus->number == pcie->root_bus_nr) && (PCI_SLOT(devfn) != 0)) {
		*val = 0xffffffff;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	/* Start PIO */
	advk_writel(pcie, 0, PIO_START);
	advk_writel(pcie, 1, PIO_ISR);

	/* Program the control register */
	reg = advk_readl(pcie, PIO_CTRL);
	reg &= ~PIO_CTRL_TYPE_MASK;
	if (bus->number ==  pcie->root_bus_nr)
		reg |= PCIE_CONFIG_RD_TYPE0;
	else
		reg |= PCIE_CONFIG_RD_TYPE1;
	advk_writel(pcie, reg, PIO_CTRL);

	/* Program the address registers */
	reg = PCIE_CONF_ADDR(bus->number, devfn, where);
	advk_writel(pcie, reg, PIO_ADDR_LS);
	advk_writel(pcie, 0, PIO_ADDR_MS);

	/* Program the data strobe */
	advk_writel(pcie, 0xf, PIO_WR_DATA_STRB);

	/* Start the transfer */
	advk_writel(pcie, 1, PIO_START);

	ret = advk_pcie_wait_pio(pcie);
	if (ret < 0)
		return PCIBIOS_SET_FAILED;

	advk_pcie_check_pio_status(pcie);

	/* Get the read result */
	*val = advk_readl(pcie, PIO_RD_DATA);
	if (size == 1)
		*val = (*val >> (8 * (where & 3))) & 0xff;
	else if (size == 2)
		*val = (*val >> (8 * (where & 3))) & 0xffff;

	return PCIBIOS_SUCCESSFUL;
}

static int advk_pcie_wr_conf(struct pci_bus *bus, u32 devfn,
				int where, int size, u32 val)
{
	struct advk_pcie *pcie = bus->sysdata;
	u32 reg;
	u32 data_strobe = 0x0;
	int offset;
	int ret;

	if ((bus->number == pcie->root_bus_nr) && (PCI_SLOT(devfn) != 0))
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (where % size)
		return PCIBIOS_SET_FAILED;

	/* Start PIO */
	advk_writel(pcie, 0, PIO_START);
	advk_writel(pcie, 1, PIO_ISR);

	/* Program the control register */
	reg = advk_readl(pcie, PIO_CTRL);
	reg &= ~PIO_CTRL_TYPE_MASK;
	if (bus->number == pcie->root_bus_nr)
		reg |= PCIE_CONFIG_WR_TYPE0;
	else
		reg |= PCIE_CONFIG_WR_TYPE1;
	advk_writel(pcie, reg, PIO_CTRL);

	/* Program the address registers */
	reg = PCIE_CONF_ADDR(bus->number, devfn, where);
	advk_writel(pcie, reg, PIO_ADDR_LS);
	advk_writel(pcie, 0, PIO_ADDR_MS);

	/* Calculate the write strobe */
	offset      = where & 0x3;
	reg         = val << (8 * offset);
	data_strobe = GENMASK(size - 1, 0) << offset;

	/* Program the data register */
	advk_writel(pcie, reg, PIO_WR_DATA);

	/* Program the data strobe */
	advk_writel(pcie, data_strobe, PIO_WR_DATA_STRB);

	/* Start the transfer */
	advk_writel(pcie, 1, PIO_START);

	ret = advk_pcie_wait_pio(pcie);
	if (ret < 0)
		return PCIBIOS_SET_FAILED;

	advk_pcie_check_pio_status(pcie);

	return PCIBIOS_SUCCESSFUL;
}

static struct pci_ops advk_pcie_ops = {
	.read = advk_pcie_rd_conf,
	.write = advk_pcie_wr_conf,
};

#if defined(MY_DEF_HERE)
static void advk_msi_irq_compose_msi_msg(struct irq_data *data,
					 struct msi_msg *msg)
#else /* MY_DEF_HERE */
static int advk_pcie_alloc_msi(struct advk_pcie *pcie)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	struct advk_pcie *pcie = irq_data_get_irq_chip_data(data);
	phys_addr_t msi_msg = virt_to_phys(&pcie->msi_msg);
#else /* MY_DEF_HERE */
	int hwirq;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	msg->address_lo = lower_32_bits(msi_msg);
	msg->address_hi = upper_32_bits(msi_msg);
	msg->data = data->irq;
#else /* MY_DEF_HERE */
	mutex_lock(&pcie->msi_used_lock);
	hwirq = find_first_zero_bit(pcie->msi_irq_in_use, MSI_IRQ_NUM);
	if (hwirq >= MSI_IRQ_NUM)
		hwirq = -ENOSPC;
	else
		set_bit(hwirq, pcie->msi_irq_in_use);
	mutex_unlock(&pcie->msi_used_lock);

	return hwirq;
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static int advk_msi_set_affinity(struct irq_data *irq_data,
				 const struct cpumask *mask, bool force)
#else /* MY_DEF_HERE */
static void advk_pcie_free_msi(struct advk_pcie *pcie, int hwirq)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	return -EINVAL;
#else /* MY_DEF_HERE */
	mutex_lock(&pcie->msi_used_lock);
	if (!test_bit(hwirq, pcie->msi_irq_in_use))
		dev_err(&pcie->pdev->dev, "trying to free unused MSI#%d\n",
			hwirq);
	else
		clear_bit(hwirq, pcie->msi_irq_in_use);
	mutex_unlock(&pcie->msi_used_lock);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static int advk_msi_irq_domain_alloc(struct irq_domain *domain,
				     unsigned int virq,
				     unsigned int nr_irqs, void *args)
#else /* MY_DEF_HERE */
static int advk_pcie_setup_msi_irq(struct msi_controller *chip,
				   struct pci_dev *pdev,
				   struct msi_desc *desc)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	struct advk_pcie *pcie = domain->host_data;
	int hwirq, i;
#else /* MY_DEF_HERE */
	struct advk_pcie *pcie = pdev->bus->sysdata;
	struct msi_msg msg;
	int virq, hwirq;
	phys_addr_t msi_msg_phys;

	/* We support MSI, but not MSI-X */
	if (desc->msi_attrib.is_msix)
		return -EINVAL;

	hwirq = advk_pcie_alloc_msi(pcie);
	if (hwirq < 0)
		return hwirq;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	mutex_lock(&pcie->msi_used_lock);
	hwirq = bitmap_find_next_zero_area(pcie->msi_used, MSI_IRQ_NUM,
					   0, nr_irqs, 0);
	if (hwirq >= MSI_IRQ_NUM) {
		mutex_unlock(&pcie->msi_used_lock);
		return -ENOSPC;
#else /* MY_DEF_HERE */
	virq = irq_create_mapping(pcie->msi_domain, hwirq);
	if (!virq) {
		advk_pcie_free_msi(pcie, hwirq);
		return -EINVAL;
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	bitmap_set(pcie->msi_used, hwirq, nr_irqs);
	mutex_unlock(&pcie->msi_used_lock);
#else /* MY_DEF_HERE */
	irq_set_msi_desc(virq, desc);

	msi_msg_phys = virt_to_phys(&pcie->msi_msg);

	msg.address_lo = lower_32_bits(msi_msg_phys);
	msg.address_hi = upper_32_bits(msi_msg_phys);
	msg.data = virq;

	pci_write_msi_msg(virq, &msg);

	return 0;
}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	for (i = 0; i < nr_irqs; i++)
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &pcie->msi_bottom_irq_chip,
				    domain->host_data, handle_simple_irq,
				    NULL, NULL);
#else /* MY_DEF_HERE */
static void advk_pcie_teardown_msi_irq(struct msi_controller *chip,
				       unsigned int irq)
{
	struct irq_data *d = irq_get_irq_data(irq);
	struct msi_desc *msi = irq_data_get_msi_desc(d);
	struct advk_pcie *pcie = msi_desc_to_pci_sysdata(msi);
	unsigned long hwirq = d->hwirq;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	return hwirq;
#else /* MY_DEF_HERE */
	irq_dispose_mapping(irq);
	advk_pcie_free_msi(pcie, hwirq);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static void advk_msi_irq_domain_free(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs)
#else /* MY_DEF_HERE */
static int advk_pcie_msi_map(struct irq_domain *domain,
			     unsigned int virq, irq_hw_number_t hw)
#endif /* MY_DEF_HERE */
{
#if defined(MY_DEF_HERE)
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
#endif /* MY_DEF_HERE */
	struct advk_pcie *pcie = domain->host_data;

#if defined(MY_DEF_HERE)
	mutex_lock(&pcie->msi_used_lock);
	bitmap_clear(pcie->msi_used, d->hwirq, nr_irqs);
	mutex_unlock(&pcie->msi_used_lock);
#else /* MY_DEF_HERE */
	irq_set_chip_and_handler(virq, &pcie->msi_irq_chip,
				 handle_simple_irq);

	return 0;
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
static const struct irq_domain_ops advk_msi_domain_ops = {
	.alloc = advk_msi_irq_domain_alloc,
	.free = advk_msi_irq_domain_free,
#else /* MY_DEF_HERE */
static const struct irq_domain_ops advk_pcie_msi_irq_ops = {
	.map = advk_pcie_msi_map,
#endif /* MY_DEF_HERE */
};

static void advk_pcie_irq_mask(struct irq_data *d)
{
	struct advk_pcie *pcie = d->domain->host_data;
	irq_hw_number_t hwirq = irqd_to_hwirq(d);
	u32 mask;

#if defined(MY_DEF_HERE)
	mask = advk_readl(pcie, PCIE_ISR1_MASK_REG);
	mask |= PCIE_ISR1_INTX_ASSERT(hwirq);
	advk_writel(pcie, mask, PCIE_ISR1_MASK_REG);
#else /* MY_DEF_HERE */
	mask = advk_readl(pcie, PCIE_ISR0_MASK_REG);
	mask |= PCIE_ISR0_INTX_ASSERT(hwirq);
	advk_writel(pcie, mask, PCIE_ISR0_MASK_REG);
#endif /* MY_DEF_HERE */
}

static void advk_pcie_irq_unmask(struct irq_data *d)
{
	struct advk_pcie *pcie = d->domain->host_data;
	irq_hw_number_t hwirq = irqd_to_hwirq(d);
	u32 mask;

#if defined(MY_DEF_HERE)
	mask = advk_readl(pcie, PCIE_ISR1_MASK_REG);
	mask &= ~PCIE_ISR1_INTX_ASSERT(hwirq);
	advk_writel(pcie, mask, PCIE_ISR1_MASK_REG);
#else /* MY_DEF_HERE */
	mask = advk_readl(pcie, PCIE_ISR0_MASK_REG);
	mask &= ~PCIE_ISR0_INTX_ASSERT(hwirq);
	advk_writel(pcie, mask, PCIE_ISR0_MASK_REG);
#endif /* MY_DEF_HERE */
}

static int advk_pcie_irq_map(struct irq_domain *h,
			     unsigned int virq, irq_hw_number_t hwirq)
{
	struct advk_pcie *pcie = h->host_data;

	advk_pcie_irq_mask(irq_get_irq_data(virq));
	irq_set_status_flags(virq, IRQ_LEVEL);
	irq_set_chip_and_handler(virq, &pcie->irq_chip,
				 handle_level_irq);
	irq_set_chip_data(virq, pcie);

	return 0;
}

static const struct irq_domain_ops advk_pcie_irq_domain_ops = {
	.map = advk_pcie_irq_map,
	.xlate = irq_domain_xlate_onecell,
};

static int advk_pcie_init_msi_irq_domain(struct advk_pcie *pcie)
{
	struct device *dev = &pcie->pdev->dev;
	struct device_node *node = dev->of_node;
#if defined(MY_DEF_HERE)
	struct irq_chip *bottom_ic, *msi_ic;
	struct msi_domain_info *msi_di;
#else /* MY_DEF_HERE */
	struct irq_chip *msi_irq_chip;
	struct msi_controller *msi;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	phys_addr_t msi_msg_phys;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	phys_addr_t msi_msg_phys;
#else /* MY_DEF_HERE */
	int ret;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	mutex_init(&pcie->msi_used_lock);
#else /* MY_DEF_HERE */
	msi_irq_chip = &pcie->msi_irq_chip;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	bottom_ic = &pcie->msi_bottom_irq_chip;
#else /* MY_DEF_HERE */
	msi_irq_chip->name = devm_kasprintf(dev, GFP_KERNEL, "%s-msi",
					    dev_name(dev));
	if (!msi_irq_chip->name)
		return -ENOMEM;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	bottom_ic->name = "MSI";
	bottom_ic->irq_compose_msi_msg = advk_msi_irq_compose_msi_msg;
	bottom_ic->irq_set_affinity = advk_msi_set_affinity;
#else /* MY_DEF_HERE */
	msi_irq_chip->irq_enable = pci_msi_unmask_irq;
	msi_irq_chip->irq_disable = pci_msi_mask_irq;
	msi_irq_chip->irq_mask = pci_msi_mask_irq;
	msi_irq_chip->irq_unmask = pci_msi_unmask_irq;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	msi_ic = &pcie->msi_irq_chip;
	msi_ic->name = "advk-MSI";
#else /* MY_DEF_HERE */
	msi = &pcie->msi;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	msi_di = &pcie->msi_domain_info;
	msi_di->flags = MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		MSI_FLAG_MULTI_PCI_MSI;
	msi_di->chip = msi_ic;
#else /* MY_DEF_HERE */
	msi->setup_irq = advk_pcie_setup_msi_irq;
	msi->teardown_irq = advk_pcie_teardown_msi_irq;
	msi->of_node = node;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	msi_msg_phys = virt_to_phys(&pcie->msi_msg);

	advk_writel(pcie, lower_32_bits(msi_msg_phys),
		    PCIE_MSI_ADDR_LOW_REG);
	advk_writel(pcie, upper_32_bits(msi_msg_phys),
		    PCIE_MSI_ADDR_HIGH_REG);
#else /* MY_DEF_HERE */
	mutex_init(&pcie->msi_used_lock);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	msi_msg_phys = virt_to_phys(&pcie->msi_msg);

	advk_writel(pcie, lower_32_bits(msi_msg_phys),
		    PCIE_MSI_ADDR_LOW_REG);
	advk_writel(pcie, upper_32_bits(msi_msg_phys),
		    PCIE_MSI_ADDR_HIGH_REG);

#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	pcie->msi_inner_domain =
#else /* MY_DEF_HERE */
	pcie->msi_domain =
#endif /* MY_DEF_HERE */
		irq_domain_add_linear(NULL, MSI_IRQ_NUM,
#if defined(MY_DEF_HERE)
				      &advk_msi_domain_ops, pcie);
	if (!pcie->msi_inner_domain)
#else /* MY_DEF_HERE */
				      &advk_pcie_msi_irq_ops, pcie);
	if (!pcie->msi_domain)
#endif /* MY_DEF_HERE */
		return -ENOMEM;

#if defined(MY_DEF_HERE)
	pcie->msi_domain =
		pci_msi_create_irq_domain(of_node_to_fwnode(node),
					  msi_di, pcie->msi_inner_domain);
	if (!pcie->msi_domain) {
		irq_domain_remove(pcie->msi_inner_domain);
		return -ENOMEM;
#else /* MY_DEF_HERE */
	ret = of_pci_msi_chip_add(msi);
	if (ret < 0) {
		irq_domain_remove(pcie->msi_domain);
		return ret;
#endif /* MY_DEF_HERE */
	}

	return 0;
}

static void advk_pcie_remove_msi_irq_domain(struct advk_pcie *pcie)
{
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	of_pci_msi_chip_remove(&pcie->msi);
#endif /* MY_DEF_HERE */
	irq_domain_remove(pcie->msi_domain);
#if defined(MY_DEF_HERE)
	irq_domain_remove(pcie->msi_inner_domain);
#endif /* MY_DEF_HERE */
}

static int advk_pcie_init_irq_domain(struct advk_pcie *pcie)
{
	struct device *dev = &pcie->pdev->dev;
	struct device_node *node = dev->of_node;
	struct device_node *pcie_intc_node;
	struct irq_chip *irq_chip;

	pcie_intc_node =  of_get_next_child(node, NULL);
	if (!pcie_intc_node) {
		dev_err(dev, "No PCIe Intc node found\n");
		return -ENODEV;
	}

	irq_chip = &pcie->irq_chip;

	irq_chip->name = devm_kasprintf(dev, GFP_KERNEL, "%s-irq",
					dev_name(dev));
	if (!irq_chip->name) {
		of_node_put(pcie_intc_node);
		return -ENOMEM;
	}

	irq_chip->irq_mask = advk_pcie_irq_mask;
	irq_chip->irq_mask_ack = advk_pcie_irq_mask;
	irq_chip->irq_unmask = advk_pcie_irq_unmask;

	pcie->irq_domain =
		irq_domain_add_linear(pcie_intc_node, LEGACY_IRQ_NUM,
				      &advk_pcie_irq_domain_ops, pcie);
	if (!pcie->irq_domain) {
		dev_err(dev, "Failed to get a INTx IRQ domain\n");
		of_node_put(pcie_intc_node);
		return -ENOMEM;
	}

	return 0;
}

static void advk_pcie_remove_irq_domain(struct advk_pcie *pcie)
{
	irq_domain_remove(pcie->irq_domain);
}

static void advk_pcie_handle_msi(struct advk_pcie *pcie)
{
	u32 msi_val, msi_mask, msi_status, msi_idx;
	u16 msi_data;

	msi_mask = advk_readl(pcie, PCIE_MSI_MASK_REG);
	msi_val = advk_readl(pcie, PCIE_MSI_STATUS_REG);
	msi_status = msi_val & ~msi_mask;

	for (msi_idx = 0; msi_idx < MSI_IRQ_NUM; msi_idx++) {
		if (!(BIT(msi_idx) & msi_status))
			continue;

		advk_writel(pcie, BIT(msi_idx), PCIE_MSI_STATUS_REG);
		msi_data = advk_readl(pcie, PCIE_MSI_PAYLOAD_REG) & 0xFF;
		generic_handle_irq(msi_data);
	}

	advk_writel(pcie, PCIE_ISR0_MSI_INT_PENDING,
		    PCIE_ISR0_REG);
}

static void advk_pcie_handle_int(struct advk_pcie *pcie)
{
	u32 val, mask, status;
#if defined(MY_DEF_HERE)
	u32 val2, mask2, status2;
#endif /* MY_DEF_HERE */
	int i, virq;

	val = advk_readl(pcie, PCIE_ISR0_REG);
	mask = advk_readl(pcie, PCIE_ISR0_MASK_REG);
	status = val & ((~mask) & PCIE_ISR0_ALL_MASK);

#if defined(MY_DEF_HERE)
	val2 = advk_readl(pcie, PCIE_ISR1_REG);
	mask2 = advk_readl(pcie, PCIE_ISR1_MASK_REG);
	status2 = val2 & ((~mask2) & PCIE_ISR1_ALL_MASK);

	if (!status && !status2) {
#else /* MY_DEF_HERE */
	if (!status) {
#endif /* MY_DEF_HERE */
		advk_writel(pcie, val, PCIE_ISR0_REG);
#if defined(MY_DEF_HERE)
		advk_writel(pcie, val2, PCIE_ISR1_REG);
#endif /* MY_DEF_HERE */
		return;
	}

	/* Process MSI interrupts */
	if (status & PCIE_ISR0_MSI_INT_PENDING)
		advk_pcie_handle_msi(pcie);

	/* Process legacy interrupts */
	for (i = 0; i < LEGACY_IRQ_NUM; i++) {
#if defined(MY_DEF_HERE)
		if (!(status2 & PCIE_ISR1_INTX_ASSERT(i)))
#else /* MY_DEF_HERE */
		if (!(status & PCIE_ISR0_INTX_ASSERT(i)))
#endif /* MY_DEF_HERE */
			continue;

#if defined(MY_DEF_HERE)
		advk_writel(pcie, PCIE_ISR1_INTX_ASSERT(i),
			    PCIE_ISR1_REG);
#else /* MY_DEF_HERE */
		advk_writel(pcie, PCIE_ISR0_INTX_ASSERT(i),
			    PCIE_ISR0_REG);
#endif /* MY_DEF_HERE */

		virq = irq_find_mapping(pcie->irq_domain, i);
		generic_handle_irq(virq);
	}
}

static irqreturn_t advk_pcie_irq_handler(int irq, void *arg)
{
	struct advk_pcie *pcie = arg;
	u32 status;

	status = advk_readl(pcie, HOST_CTRL_INT_STATUS_REG);
	if (!(status & PCIE_IRQ_CORE_INT))
		return IRQ_NONE;

	advk_pcie_handle_int(pcie);

	/* Clear interrupt */
	advk_writel(pcie, PCIE_IRQ_CORE_INT, HOST_CTRL_INT_STATUS_REG);

	return IRQ_HANDLED;
}

static int advk_pcie_parse_request_of_pci_ranges(struct advk_pcie *pcie)
{
	int err, res_valid = 0;
	struct device *dev = &pcie->pdev->dev;
	struct device_node *np = dev->of_node;
#if defined(MY_DEF_HERE)
	struct resource_entry *win, *tmp;
#else /* MY_DEF_HERE */
	struct resource_entry *win;
#endif /* MY_DEF_HERE */
	resource_size_t iobase;

	INIT_LIST_HEAD(&pcie->resources);

	err = of_pci_get_host_bridge_resources(np, 0, 0xff, &pcie->resources,
					       &iobase);
	if (err)
		return err;

#if defined(MY_DEF_HERE)
	resource_list_for_each_entry_safe(win, tmp, &pcie->resources) {
#else /* MY_DEF_HERE */
	resource_list_for_each_entry(win, &pcie->resources) {
#endif /* MY_DEF_HERE */
		struct resource *parent = NULL;
		struct resource *res = win->res;

		switch (resource_type(res)) {
		case IORESOURCE_IO:
			parent = &ioport_resource;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
			advk_pcie_set_ob_win(pcie, 1,
					     upper_32_bits(res->start),
					     lower_32_bits(res->start),
					     0,	0xF8000000, 0,
					     lower_32_bits(res->start),
					     OB_PCIE_IO);
#endif /* MY_DEF_HERE */
			err = pci_remap_iospace(res, iobase);
			if (err) {
				dev_warn(dev, "error %d: failed to map resource %pR\n",
					 err, res);
#if defined(MY_DEF_HERE)
				resource_list_destroy_entry(win);
#endif /* MY_DEF_HERE */
				continue;
			}
			break;
		case IORESOURCE_MEM:
			parent = &iomem_resource;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
			advk_pcie_set_ob_win(pcie, 0,
					     upper_32_bits(res->start),
					     lower_32_bits(res->start),
					     0x0, 0xF8000000, 0,
					     lower_32_bits(res->start),
					     (2 << 20) | OB_PCIE_MEM);
#endif /* MY_DEF_HERE */
			res_valid |= !(res->flags & IORESOURCE_PREFETCH);
			break;
		case IORESOURCE_BUS:
			pcie->root_bus_nr = res->start;
			break;
		default:
			continue;
		}
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */

#endif /* MY_DEF_HERE */
		if (parent) {
			err = devm_request_resource(dev, parent, res);
			if (err)
				goto out_release_res;
		}
	}

	if (!res_valid) {
		dev_err(dev, "non-prefetchable memory resource required\n");
		err = -EINVAL;
		goto out_release_res;
	}

	return 0;

out_release_res:
	pci_free_resource_list(&pcie->resources);
	return err;
}

#if defined(MY_DEF_HERE)
static int advk_pcie_find_smpss(struct pci_dev *dev, void *data)
{
	u8 *smpss = data;

	if (!dev)
		return 0;

	if (!pci_is_pcie(dev))
		return 0;

	if (*smpss > dev->pcie_mpss)
		*smpss = dev->pcie_mpss;

	return 0;
}

static int advk_pcie_bus_configure_mps(struct pci_dev *dev, void *data)
{
	int mps;

	if (!dev)
		return 0;

	if (!pci_is_pcie(dev))
		return 0;

	mps = PCIE_CORE_MPS_UNIT_BYTE << *(u8 *)data;
	pcie_set_mps(dev, mps);

	return 0;
}

static void advk_pcie_configure_mps(struct pci_bus *bus, struct advk_pcie *pcie)
{
	u8 smpss = PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ;
	u32 reg;

	/* Find the minimal supported MAX payload size */
	advk_pcie_find_smpss(bus->self, &smpss);
	pci_walk_bus(bus, advk_pcie_find_smpss, &smpss);

	/* Configure RC MAX payload size */
	reg = advk_readl(pcie, PCIE_CORE_DEV_CTRL_STATS_REG);
	reg &= ~PCI_EXP_DEVCTL_PAYLOAD;
	reg |= smpss << PCIE_CORE_DEV_CTRL_STATS_MAX_PAYLOAD_SZ_SHIFT;
	advk_writel(pcie, reg, PCIE_CORE_DEV_CTRL_STATS_REG);

	/* Configure device MAX payload size */
	advk_pcie_bus_configure_mps(bus->self, &smpss);
	pci_walk_bus(bus, advk_pcie_bus_configure_mps, &smpss);
}

static int advk_pcie_clk_enable_then_reset(struct advk_pcie *pcie)
{
	int ret;

	/* WA: to avoid reset fail, set the reset gpio to low first */
	gpiod_direction_output(pcie->reset_gpio, 0);

	/* Enable pcie clock */
	ret = clk_prepare_enable(pcie->clk);
	if (ret) {
		dev_err(&pcie->pdev->dev, "Failed to enable clock\n");
		return ret;
	}

	/* After 200ms to reset pcie */
	mdelay(200);
	gpiod_direction_output(pcie->reset_gpio,
			       (pcie->flags & OF_GPIO_ACTIVE_LOW) ? 0 : 1);

	return ret;
}

#endif /* MY_DEF_HERE */
static int advk_pcie_probe(struct platform_device *pdev)
{
#if defined(MY_DEF_HERE)
	struct device *dev = &pdev->dev;
#endif /* MY_DEF_HERE */
	struct advk_pcie *pcie;
	struct resource *res;
	struct pci_bus *bus, *child;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	struct msi_controller *msi;
	struct device_node *msi_node;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	struct clk *clk;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	struct phy *comphy;
	struct device_node *dn = pdev->dev.of_node;
#endif /* MY_DEF_HERE */
	int ret, irq;
#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	enum of_gpio_flags flags;
#endif /* MY_DEF_HERE */
	int reset_gpio;
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	pcie = devm_kzalloc(dev, sizeof(struct advk_pcie), GFP_KERNEL);
#else /* MY_DEF_HERE */
	pcie = devm_kzalloc(&pdev->dev, sizeof(struct advk_pcie),
			    GFP_KERNEL);
#endif /* MY_DEF_HERE */
	if (!pcie)
		return -ENOMEM;

	pcie->pdev = pdev;
	platform_set_drvdata(pdev, pcie);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
#if defined(MY_DEF_HERE)
	pcie->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(pcie->base))
#else /* MY_DEF_HERE */
	pcie->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(pcie->base)) {
		dev_err(&pdev->dev, "Failed to map registers\n");
#endif /* MY_DEF_HERE */
		return PTR_ERR(pcie->base);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Get comphy and init if there is */
	comphy = devm_of_phy_get(&pdev->dev, dn, "comphy");
	if (!IS_ERR(comphy)) {
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
		/* Set HW Reference Clock Buffer Control */
		advk_writel(pcie, PCIE_PHY_BUF_CTRL_INIT_VAL, PCIE_PHY_REF_CLOCK);
#endif /* MY_DEF_HERE */
		pcie->phy = comphy;
		ret = phy_init(pcie->phy);
		if (ret)
			return ret;

		ret = phy_power_on(pcie->phy);
		if (ret) {
			phy_exit(pcie->phy);
			goto err_exit_phy;
		}
	}

#endif /* MY_DEF_HERE */
	irq = platform_get_irq(pdev, 0);
#if defined(MY_DEF_HERE)
	ret = devm_request_irq(dev, irq, advk_pcie_irq_handler,
#else /* MY_DEF_HERE */
	ret = devm_request_irq(&pdev->dev, irq, advk_pcie_irq_handler,
#endif /* MY_DEF_HERE */
			       IRQF_SHARED | IRQF_NO_THREAD, "advk-pcie",
			       pcie);
	if (ret) {
#if defined(MY_DEF_HERE)
		dev_err(dev, "Failed to register interrupt\n");
#else /* MY_DEF_HERE */
		dev_err(&pdev->dev, "Failed to register interrupt\n");
#endif /* MY_DEF_HERE */
		return ret;
	}

#if defined(MY_DEF_HERE)
	pcie->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(pcie->clk)) {
#else /* MY_DEF_HERE */
	clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(clk)) {
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
		dev_err(dev, "Failed to obtain clock from DT\n");
#else /* MY_DEF_HERE */
		dev_err(&pdev->dev, "Failed to obtain clock from DT\n");
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
		return PTR_ERR(pcie->clk);
#else /* MY_DEF_HERE */
		return PTR_ERR(clk);
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	/* Config reset gpio for pcie if there is valid gpio setting in DTS */
#else /* MY_DEF_HERE */
	/* Config reset gpio for pcie */
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	reset_gpio = of_get_named_gpio_flags(dn, "reset-gpios", 0, &pcie->flags);
#else /* MY_DEF_HERE */
	reset_gpio = of_get_named_gpio_flags(dn, "reset-gpios", 0, &flags);
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
		pcie->reset_gpio = gpio_to_desc(reset_gpio);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (gpio_is_valid(reset_gpio)) {
		pcie->reset_gpio = gpio_to_desc(reset_gpio);
		ret = advk_pcie_clk_enable_then_reset(pcie);
		if (ret)
			return ret;

		/* continue init flow after pcie reset */
		goto after_pcie_reset;
	} else if (reset_gpio == -EPROBE_DEFER) {
		return -EPROBE_DEFER;
#else /* MY_DEF_HERE */
		if (gpio_is_valid(reset_gpio)) {
#if defined(MY_DEF_HERE)
			pcie->reset_gpio = gpio_to_desc(reset_gpio);
			ret = advk_pcie_clk_enable_then_reset(pcie);
			if (ret)
#else /* MY_DEF_HERE */
			unsigned long gpio_flags;

			/* WA: to avoid reset fail, set the reset gpio to low first */
			gpiod_direction_output(pcie->reset_gpio, 0);

			/* Enable pcie clock and after 200ms to reset pcie */
			ret = clk_prepare_enable(clk);
			if (ret) {
				dev_err(&pdev->dev, "Failed to enable clock\n");
				return ret;
			}
			mdelay(200);

			/* Set GPIO for pcie reset */
			pcie->reset_name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "%s-reset",
							  pdev->name);
			if (!pcie->reset_name) {
				ret = -ENOMEM;
				dev_err(&pdev->dev, "devm_kasprintf failed\n");
#endif /* MY_DEF_HERE */
				return ret;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
			}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
			if (flags & OF_GPIO_ACTIVE_LOW) {
				dev_info(&pdev->dev, "%s: reset gpio is active low\n",
					 of_node_full_name(dn));
				gpio_flags = GPIOF_ACTIVE_LOW |
					     GPIOF_OUT_INIT_LOW;
			} else {
				gpio_flags = GPIOF_OUT_INIT_HIGH;
			}

			ret = devm_gpio_request_one(&pdev->dev, reset_gpio, gpio_flags,
						    pcie->reset_name);
			if (ret) {
				dev_err(&pdev->dev,
					"gpio_request for gpio failed, err = %d\n",
					ret);
				return ret;
			}
#endif /* MY_DEF_HERE */
			/* continue init flow after pcie reset */
			goto after_pcie_reset;
		}
#endif /* MY_DEF_HERE */
	}

#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	ret = clk_prepare_enable(pcie->clk);
#else /* MY_DEF_HERE */
	ret = clk_prepare_enable(clk);
#endif /* MY_DEF_HERE */
	if (ret) {
#if defined(MY_DEF_HERE)
		dev_err(dev, "Failed to enable clock\n");
#else /* MY_DEF_HERE */
		dev_err(&pdev->dev, "Failed to enable clock\n");
#endif /* MY_DEF_HERE */
		return ret;
	}
#if defined(MY_DEF_HERE)
after_pcie_reset:
#endif /* MY_DEF_HERE */
	ret = advk_pcie_parse_request_of_pci_ranges(pcie);
	if (ret) {
#if defined(MY_DEF_HERE)
		dev_err(dev, "Failed to parse resources\n");
#else /* MY_DEF_HERE */
		dev_err(&pdev->dev, "Failed to parse resources\n");
#endif /* MY_DEF_HERE */
		goto err_clk;
	}

	advk_pcie_setup_hw(pcie);

	ret = advk_pcie_init_irq_domain(pcie);
	if (ret) {
#if defined(MY_DEF_HERE)
		dev_err(dev, "Failed to initialize irq\n");
#else /* MY_DEF_HERE */
		dev_err(&pdev->dev, "Failed to initialize irq\n");
#endif /* MY_DEF_HERE */
		goto err_clk;
	}

	ret = advk_pcie_init_msi_irq_domain(pcie);
	if (ret) {
#if defined(MY_DEF_HERE)
		dev_err(dev, "Failed to initialize irq\n");
#else /* MY_DEF_HERE */
		dev_err(&pdev->dev, "Failed to initialize irq\n");
#endif /* MY_DEF_HERE */
		advk_pcie_remove_irq_domain(pcie);
		goto err_clk;
	}

#if defined(MY_DEF_HERE)
	bus = pci_scan_root_bus(dev, 0, &advk_pcie_ops,
				pcie, &pcie->resources);
#else /* MY_DEF_HERE */
	msi_node = of_parse_phandle(pdev->dev.of_node, "msi-parent", 0);
	if (msi_node)
		msi = of_pci_find_msi_chip_by_node(msi_node);
	else
		msi = NULL;

	bus = pci_scan_root_bus_msi(&pdev->dev, 0, &advk_pcie_ops,
				    pcie, &pcie->resources, &pcie->msi);
#endif /* MY_DEF_HERE */
	if (!bus) {
		advk_pcie_remove_msi_irq_domain(pcie);
		advk_pcie_remove_irq_domain(pcie);
		ret = -ENOMEM;
		goto err_clk;
	}

	pci_bus_assign_resources(bus);
#if defined(MY_DEF_HERE)
	pcie->bus = bus;
#endif /* MY_DEF_HERE */

	list_for_each_entry(child, &bus->children, node)
		pcie_bus_configure_settings(child);

#if defined(MY_DEF_HERE)
	/* Configure the MAX pay load size */
	advk_pcie_configure_mps(bus, pcie);

#endif /* MY_DEF_HERE */
	pci_bus_add_devices(bus);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */

#endif /* MY_DEF_HERE */
	return 0;

err_clk:
#if defined(MY_DEF_HERE)
	clk_disable_unprepare(pcie->clk);
#else /* MY_DEF_HERE */
	clk_disable_unprepare(clk);
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
err_exit_phy:
	if (pcie->phy)
		phy_exit(pcie->phy);

#endif /* MY_DEF_HERE */
	return ret;
}

#if defined(MY_DEF_HERE)
static int advk_pcie_suspend_noirq(struct device *dev)
{
	struct advk_pcie *pcie;

	pcie = dev_get_drvdata(dev);

	/* Gating clock */
	clk_disable_unprepare(pcie->clk);

	/* Power off PHY */
	if (!IS_ERR(pcie->phy)) {
		phy_power_off(pcie->phy);
		phy_exit(pcie->phy);
	}

	return 0;
}

static int advk_pcie_resume_noirq(struct device *dev)
{
	struct advk_pcie *pcie;
	int ret;

	pcie = dev_get_drvdata(dev);

	/* Power on PHY, it must be first, or pcie register access fail */
	if (!IS_ERR(pcie->phy)) {
		phy_init(pcie->phy);
		phy_power_on(pcie->phy);
	}

	if (pcie->reset_gpio)
		ret = advk_pcie_clk_enable_then_reset(pcie);
	else
		ret = clk_prepare_enable(pcie->clk);
	if (ret) {
		dev_err(dev, "Failed to enable clock\n");
		return ret;
	}

	advk_pcie_setup_hw(pcie);

#if defined(MY_DEF_HERE)
	/* Reconfigure the MAX pay load size */
	advk_pcie_configure_mps(pcie->bus, pcie);

#endif /* MY_DEF_HERE */
	return 0;
}

#endif /* MY_DEF_HERE */
static const struct of_device_id advk_pcie_of_match_table[] = {
	{ .compatible = "marvell,armada-3700-pcie", },
	{},
};

#if defined(MY_DEF_HERE)
static const struct dev_pm_ops advk_pcie_pm_ops = {
	.suspend_noirq = advk_pcie_suspend_noirq,
	.resume_noirq = advk_pcie_resume_noirq,
};

#endif /* MY_DEF_HERE */
static struct platform_driver advk_pcie_driver = {
	.driver = {
		.name = "advk-pcie",
		.of_match_table = advk_pcie_of_match_table,
		/* Driver unloading/unbinding currently not supported */
		.suppress_bind_attrs = true,
#if defined(MY_DEF_HERE)
		.pm = &advk_pcie_pm_ops,
#endif /* MY_DEF_HERE */
	},
	.probe = advk_pcie_probe,
};
module_platform_driver(advk_pcie_driver);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */

MODULE_AUTHOR("Hezi Shahmoon <hezi.shahmoon@marvell.com>");
MODULE_DESCRIPTION("Aardvark PCIe driver");
MODULE_LICENSE("GPL v2");
#endif /* MY_DEF_HERE */
#endif /* MY_DEF_HERE */
