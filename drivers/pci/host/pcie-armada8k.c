#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined(MY_DEF_HERE)
/*
 * PCIe host controller driver for Marvell Armada-8K SoCs
 *
 * Armada-8K PCIe Glue Layer Source Code
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#define pr_fmt(fmt) "armada-8k-pcie: " fmt

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/of_pci.h>
#include <linux/of_irq.h>
#if defined(MY_DEF_HERE)
#include <dt-bindings/phy/phy-comphy-mvebu.h>
#include <linux/of_gpio.h>
#endif /* MY_DEF_HERE */

#include "pcie-designware.h"

struct armada8k_pcie {
	void __iomem		*regs_base;
#if defined(MY_DEF_HERE)
	struct phy		**phys;
	int			phy_count;
#else /* MY_DEF_HERE */
	struct phy		*phy;
#endif /* MY_DEF_HERE */
	struct clk		*clk;
	struct pcie_port	pp;
#if defined(MY_DEF_HERE)
	struct gpio_desc	*reset_gpio;
	enum of_gpio_flags	flags;
#endif /* MY_DEF_HERE */
};

#define PCIE_GLOBAL_CONTROL             0x0
#define PCIE_APP_LTSSM_EN               (1 << 2)
#define PCIE_DEVICE_TYPE_OFFSET         (4)
#define PCIE_DEVICE_TYPE_MASK           (0xF)
#define PCIE_DEVICE_TYPE_EP             (0x0) /* Endpoint */
#define PCIE_DEVICE_TYPE_LEP            (0x1) /* Legacy endpoint */
#define PCIE_DEVICE_TYPE_RC             (0x4) /* Root complex */

#define PCIE_GLOBAL_STATUS              0x8
#define PCIE_GLB_STS_RDLH_LINK_UP       (1 << 1)
#define PCIE_GLB_STS_PHY_LINK_UP        (1 << 9)

#define PCIE_GLOBAL_INT_CAUSE1		0x1C
#define PCIE_GLOBAL_INT_MASK1		0x20
#define PCIE_INT_A_ASSERT_MASK		(1 << 9)
#define PCIE_INT_B_ASSERT_MASK		(1 << 10)
#define PCIE_INT_C_ASSERT_MASK		(1 << 11)
#define PCIE_INT_D_ASSERT_MASK		(1 << 12)

#define PCIE_ARCACHE_TRC                0x50
#define PCIE_AWCACHE_TRC                0x54
#define PCIE_ARUSER			0x5C
#define PCIE_AWUSER			0x60
/* AR/AW Cache defauls:
** - Normal memory
** - Write-Back
** - Read / Write allocate
*/
#define ARCACHE_DEFAULT_VALUE		0x3511
#define AWCACHE_DEFAULT_VALUE		0x5311

#define DOMAIN_OUTER_SHAREABLE		0x2
#define AX_USER_DOMAIN_MASK		0x3
#define AX_USER_DOMAIN_OFFSET		4

#define to_armada8k_pcie(x)	container_of(x, struct armada8k_pcie, pp)

static int armada8k_pcie_link_up(struct pcie_port *pp)
{
	u32 reg;
	struct armada8k_pcie *armada8k_pcie = to_armada8k_pcie(pp);
	u32 mask = PCIE_GLB_STS_RDLH_LINK_UP | PCIE_GLB_STS_PHY_LINK_UP;

	reg = readl(armada8k_pcie->regs_base + PCIE_GLOBAL_STATUS);

	if ((reg & mask) == mask)
		return 1;

	pr_debug("No link detected (Global-Status: 0x%08x).\n", reg);
	return 0;
}

static void armada8k_pcie_host_init(struct pcie_port *pp)
{
	struct armada8k_pcie *armada8k_pcie = to_armada8k_pcie(pp);
	void __iomem *regs_base = armada8k_pcie->regs_base;
	int timeout = 1000;
	u32 reg;

	if (!armada8k_pcie_link_up(pp)) {
		/* Disable LTSSM state machine to enable configuration */
		reg = readl(regs_base + PCIE_GLOBAL_CONTROL);
		reg &= ~(PCIE_APP_LTSSM_EN);
		writel(reg, regs_base + PCIE_GLOBAL_CONTROL);
	}

	/* Set the device to root complex mode */
	reg = readl(regs_base + PCIE_GLOBAL_CONTROL);
	reg &= ~(PCIE_DEVICE_TYPE_MASK << PCIE_DEVICE_TYPE_OFFSET);
	reg |= PCIE_DEVICE_TYPE_RC << PCIE_DEVICE_TYPE_OFFSET;
	writel(reg, regs_base + PCIE_GLOBAL_CONTROL);

	/* Set the PCIe master AxCache attributes */
	writel(ARCACHE_DEFAULT_VALUE, regs_base + PCIE_ARCACHE_TRC);
	writel(AWCACHE_DEFAULT_VALUE, regs_base + PCIE_AWCACHE_TRC);

	/* Set the PCIe master AxDomain attributes */
	reg = readl(regs_base + PCIE_ARUSER);
	reg &= ~(AX_USER_DOMAIN_MASK << AX_USER_DOMAIN_OFFSET);
	reg |= DOMAIN_OUTER_SHAREABLE << AX_USER_DOMAIN_OFFSET;
	writel(reg, regs_base + PCIE_ARUSER);

	reg = readl(regs_base + PCIE_AWUSER);
	reg &= ~(AX_USER_DOMAIN_MASK << AX_USER_DOMAIN_OFFSET);
	reg |= DOMAIN_OUTER_SHAREABLE << AX_USER_DOMAIN_OFFSET;
	writel(reg, regs_base + PCIE_AWUSER);

	dw_pcie_setup_rc(pp);

	/* Enable INT A-D interrupts */
	reg = readl(regs_base + PCIE_GLOBAL_INT_MASK1);
	reg |= PCIE_INT_A_ASSERT_MASK | PCIE_INT_B_ASSERT_MASK |
	       PCIE_INT_C_ASSERT_MASK | PCIE_INT_D_ASSERT_MASK;
	writel(reg, regs_base + PCIE_GLOBAL_INT_MASK1);

	if (!armada8k_pcie_link_up(pp)) {
		/* Configuration done. Start LTSSM */
		reg = readl(regs_base + PCIE_GLOBAL_CONTROL);
		reg |= PCIE_APP_LTSSM_EN;
		writel(reg, regs_base + PCIE_GLOBAL_CONTROL);
	}

	/* Wait until the link becomes active again */
	while (timeout) {
		if (armada8k_pcie_link_up(pp))
			break;
		udelay(1);
		timeout--;
	}

	if (timeout == 0)
		dev_err(pp->dev, "Link not up after reconfiguration\n");
}

#ifdef CONFIG_PCI_MSI
static int armada8k_pcie_msi_init(struct pcie_port *pp, struct msi_controller *chip)
{
	struct device_node *msi_node;
	struct msi_controller	*msi;

	msi_node = of_parse_phandle(pp->dev->of_node, "msi-parent", 0);
	if (!msi_node)
		return -ENXIO;

	/* Override the designware MSI chip. The designware registration
	 * method doesnt allow to supply a private msi chip so we resort
	 * to overriding it. should probably change the DW driver */
	msi = of_pci_find_msi_chip_by_node(msi_node);
	if (msi)
		*chip = *msi;

	return 0;
}
#endif

static void armada8k_pcie_clear_irq_pulse(struct pcie_port *pp)
{
	struct armada8k_pcie *armada8k_pcie = to_armada8k_pcie(pp);
	void __iomem *regs_base = armada8k_pcie->regs_base;
	u32 val;

	val = readl(regs_base + PCIE_GLOBAL_INT_CAUSE1);
	writel(val, regs_base + PCIE_GLOBAL_INT_CAUSE1);
}

static irqreturn_t armada8k_pcie_irq_handler(int irq, void *arg)
{
	struct pcie_port *pp = arg;

	armada8k_pcie_clear_irq_pulse(pp);
	return IRQ_HANDLED;
}

static struct pcie_host_ops armada8k_pcie_host_ops = {
	.link_up = armada8k_pcie_link_up,
	.host_init = armada8k_pcie_host_init,
#ifdef CONFIG_PCI_MSI
	.msi_host_init = armada8k_pcie_msi_init,
#endif
};

static int armada8k_add_pcie_port(struct pcie_port *pp,
					 struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	int ret;

	pp->root_bus_nr = -1;
	pp->ops = &armada8k_pcie_host_ops;

	pp->irq = platform_get_irq(pdev, 0);
	if (!pp->irq) {
		dev_err(dev, "failed to get irq for port\n");
		return -ENODEV;
	}

	ret = devm_request_irq(dev, pp->irq, armada8k_pcie_irq_handler,
				IRQF_SHARED, "armada8k-pcie", pp);
	if (ret) {
		dev_err(dev, "failed to request irq %d\n", pp->irq);
		return ret;
	}

	ret = dw_pcie_host_init(pp);
	if (ret) {
		dev_err(dev, "failed to initialize host\n");
		return ret;
	}

	return 0;
}

#if defined(MY_DEF_HERE)
/* armada8k_pcie_reset
 * The function implements the PCIe reset via GPIO.
 * First, pull down the GPIO used for PCIe reset, and wait 200ms;
 * Second, set the GPIO output value with setting from DTS, and wait
 * 200ms for taking effect.
 * Return: void, always success.
 */
static void armada8k_pcie_reset(struct armada8k_pcie *pcie)
{
	/* Set the reset gpio to low first */
	gpiod_direction_output(pcie->reset_gpio, 0);
	/* After 200ms to reset pcie */
	mdelay(200);
	gpiod_direction_output(pcie->reset_gpio,
			       (pcie->flags & OF_GPIO_ACTIVE_LOW) ? 0 : 1);
	mdelay(200);
}

#endif /* MY_DEF_HERE */
static int armada8k_pcie_probe(struct platform_device *pdev)
{
	struct armada8k_pcie *armada8k_pcie;
	struct pcie_port *pp;
#if defined(MY_DEF_HERE)
	struct phy **phys = NULL;
#endif /* MY_DEF_HERE */
	struct device *dev = &pdev->dev;
	struct resource *base;
#if defined(MY_DEF_HERE)
	int i, reset_gpio, phy_count = 0;
	u32 command;
	char phy_name[16];
#endif /* MY_DEF_HERE */
	int ret = 0;

	armada8k_pcie = devm_kzalloc(dev, sizeof(*armada8k_pcie), GFP_KERNEL);
	if (!armada8k_pcie)
		return -ENOMEM;

	armada8k_pcie->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(armada8k_pcie->clk))
		return PTR_ERR(armada8k_pcie->clk);

	clk_prepare_enable(armada8k_pcie->clk);

#if defined(MY_DEF_HERE)
	/* Get PHY count according to phy name */
	phy_count = of_property_count_strings(pdev->dev.of_node, "phy-names");
	if (phy_count > 0) {
		phys = devm_kzalloc(dev, sizeof(*phys) * phy_count, GFP_KERNEL);
		if (!phys)
			return -ENOMEM;

		for (i = 0; i < phy_count; i++) {
			snprintf(phy_name, sizeof(phy_name), "pcie-phy%d", i);
			phys[i] = devm_phy_get(dev, phy_name);
			if (IS_ERR(phys[i]))
				goto err_phy;

			/* Tell COMPHY the PCIE width based on phy command,
			 * and in PHY command callback, the width will be
			 * checked for its validation.
			 */
			switch (phy_count) {
			case PCIE_LNK_X1:
				command = COMPHY_COMMAND_PCIE_WIDTH_1;
				break;
			case PCIE_LNK_X2:
				command = COMPHY_COMMAND_PCIE_WIDTH_2;
				break;
			case PCIE_LNK_X4:
				command = COMPHY_COMMAND_PCIE_WIDTH_4;
				break;
			default:
				command = COMPHY_COMMAND_PCIE_WIDTH_UNSUPPORT;
			}
			phy_send_command(phys[i], command);

			ret = phy_init(phys[i]);
			if (ret < 0)
				goto err_phy;

			ret = phy_power_on(phys[i]);
			if (ret < 0) {
				phy_exit(phys[i]);
				goto err_phy;
			}
		}
#else /* MY_DEF_HERE */
#if 0
	/* Keep this code commented out till we write a PHY driver for
	** armada-8k PCIe PHY. */
	armada8k_pcie->phy = devm_phy_get(dev, "pcie-phy");
	if (IS_ERR(armada8k_pcie->phy)) {
		ret = PTR_ERR(armada8k_pcie->phy);
		if (ret == -EPROBE_DEFER)
			dev_info(dev, "probe deferred\n");
		else
			dev_err(dev, "couldn't get pcie-phy\n");

		goto fail_free;
	phy_init(armada8k_pcie->phy);
#endif
#endif /* MY_DEF_HERE */
	}

#if defined(MY_DEF_HERE)
	/* Config reset gpio for pcie if the reset connected to gpio */
	reset_gpio = of_get_named_gpio_flags(pdev->dev.of_node,
					     "reset-gpios", 0,
					     &armada8k_pcie->flags);
	if (gpio_is_valid(reset_gpio)) {
		armada8k_pcie->reset_gpio = gpio_to_desc(reset_gpio);
		armada8k_pcie_reset(armada8k_pcie);
	}
#endif /* MY_DEF_HERE */

	pp = &armada8k_pcie->pp;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */

#endif /* MY_DEF_HERE */
	pp->dev = dev;
#if defined(MY_DEF_HERE)
	armada8k_pcie->phys = phys;
	armada8k_pcie->phy_count = phy_count;
#endif /* MY_DEF_HERE */
	platform_set_drvdata(pdev, armada8k_pcie);

	/* Get the dw-pcie unit configuration/control registers base. */
	base = platform_get_resource_byname(pdev, IORESOURCE_MEM, "ctrl");
	pp->dbi_base = devm_ioremap_resource(dev, base);
	if (IS_ERR(pp->dbi_base)) {
		dev_err(dev, "couldn't remap regs base %p\n", base);
		ret = PTR_ERR(pp->dbi_base);
		goto fail_free;
	}
	armada8k_pcie->regs_base = pp->dbi_base + 0x8000;

	pci_add_flags(PCI_REASSIGN_ALL_RSRC | PCI_REASSIGN_ALL_BUS);

	ret = armada8k_add_pcie_port(pp, pdev);
	if (ret < 0)
		goto fail_free;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */

#endif /* MY_DEF_HERE */
	return 0;

#if defined(MY_DEF_HERE)
err_phy:
	while (--i >= 0) {
		phy_power_off(phys[i]);
		phy_exit(phys[i]);
	}

#endif /* MY_DEF_HERE */
fail_free:
	if (!IS_ERR(armada8k_pcie->clk))
		clk_disable_unprepare(armada8k_pcie->clk);

	return ret;
}

#if defined(MY_DEF_HERE)
static int armada8k_pcie_suspend_noirq(struct device *dev)
{
	int i;
	struct armada8k_pcie *pcie;

	pcie = dev_get_drvdata(dev);

	/* Gating clock */
	if (!IS_ERR(pcie->clk))
		clk_disable_unprepare(pcie->clk);

	/* Power off PHY */
	for (i = 0; i < pcie->phy_count; i++) {
		if (pcie->phys[i]) {
			phy_power_off(pcie->phys[i]);
			phy_exit(pcie->phys[i]);
		}
	}

	return 0;
}

static int armada8k_pcie_resume_noirq(struct device *dev)
{
	struct armada8k_pcie *pcie;
	int i, ret;

	pcie = dev_get_drvdata(dev);

	if (!IS_ERR(pcie->clk)) {
		ret = clk_prepare_enable(pcie->clk);
		if (ret) {
			dev_err(dev, "Failed to enable clock\n");
			return ret;
		}
	}

	/* Power on PHY */
	for (i = 0; i < pcie->phy_count; i++) {
		if (pcie->phys[i]) {
			u32 command;
			/* Tell COMPHY the PCIE width based on phy command,
			 * and in PHY command callback, the width will be
			 * checked for its validation.
			 */
			switch (pcie->phy_count) {
			case PCIE_LNK_X1:
				command = COMPHY_COMMAND_PCIE_WIDTH_1;
				break;
			case PCIE_LNK_X2:
				command = COMPHY_COMMAND_PCIE_WIDTH_2;
				break;
			case PCIE_LNK_X4:
				command = COMPHY_COMMAND_PCIE_WIDTH_4;
				break;
			default:
				command = COMPHY_COMMAND_PCIE_WIDTH_UNSUPPORT;
			}
			phy_send_command(pcie->phys[i], command);

			ret = phy_init(pcie->phys[i]);
			if (ret < 0)
				goto err_phy;
			ret = phy_power_on(pcie->phys[i]);
			if (ret < 0) {
				phy_exit(pcie->phys[i]);
				goto err_phy;
			}
		}
	}

	/* Reset PCIe if it is connected to GPIO */
	if (pcie->reset_gpio)
		armada8k_pcie_reset(pcie);

	/* Reinit PCIE host */
	armada8k_pcie_host_init(&pcie->pp);
	return 0;

err_phy:
	while (--i >= 0) {
		phy_power_off(pcie->phys[i]);
		phy_exit(pcie->phys[i]);
	}
	if (!IS_ERR(pcie->clk))
		clk_disable_unprepare(pcie->clk);

	return ret;
}

static const struct dev_pm_ops armada8k_pcie_pm_ops = {
	.suspend_noirq = armada8k_pcie_suspend_noirq,
	.resume_noirq = armada8k_pcie_resume_noirq,
};

#endif /* MY_DEF_HERE */
static const struct of_device_id armada8k_pcie_of_match[] = {
	{ .compatible = "marvell,armada8k-pcie", },
	{},
};
MODULE_DEVICE_TABLE(of, armada8k_pcie_of_match);

static struct platform_driver armada8k_pcie_driver = {
	.probe		= armada8k_pcie_probe,
	.driver = {
		.name	= "armada8k-pcie",
		.of_match_table = of_match_ptr(armada8k_pcie_of_match),
#if defined(MY_DEF_HERE)
		.pm	= &armada8k_pcie_pm_ops,
#endif /* MY_DEF_HERE */
	},
};

module_platform_driver(armada8k_pcie_driver);

MODULE_DESCRIPTION("Armada 8k PCIe host controller driver");
MODULE_AUTHOR("Yehuda Yitshak <yehuday@marvell.com>");
MODULE_AUTHOR("Shadi Ammouri <shadi@marvell.com>");
MODULE_LICENSE("GPL v2");
#endif /* MY_DEF_HERE */
