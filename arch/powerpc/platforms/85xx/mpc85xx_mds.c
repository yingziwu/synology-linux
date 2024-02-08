 
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/reboot.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/major.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/fsl_devices.h>
#include <linux/of_platform.h>
#include <linux/of_device.h>
#include <linux/phy.h>
#include <linux/lmb.h>

#include <asm/system.h>
#include <asm/atomic.h>
#include <asm/time.h>
#include <asm/io.h>
#include <asm/machdep.h>
#include <asm/pci-bridge.h>
#include <asm/irq.h>
#include <mm/mmu_decl.h>
#include <asm/prom.h>
#include <asm/udbg.h>
#include <sysdev/fsl_soc.h>
#include <sysdev/fsl_pci.h>
#include <sysdev/simple_gpio.h>
#include <asm/qe.h>
#include <asm/qe_ic.h>
#include <asm/mpic.h>
#include <asm/swiotlb.h>

#undef DEBUG
#ifdef DEBUG
#define DBG(fmt...) udbg_printf(fmt)
#else
#define DBG(fmt...)
#endif

#define MV88E1111_SCR	0x10
#define MV88E1111_SCR_125CLK	0x0010
static int mpc8568_fixup_125_clock(struct phy_device *phydev)
{
	int scr;
	int err;

	scr = phy_read(phydev, MV88E1111_SCR);

	if (scr < 0)
		return scr;

	err = phy_write(phydev, MV88E1111_SCR, scr & ~(MV88E1111_SCR_125CLK));

	if (err)
		return err;

	err = phy_write(phydev, MII_BMCR, BMCR_RESET);

	if (err)
		return err;

	scr = phy_read(phydev, MV88E1111_SCR);

	if (scr < 0)
		return err;

	err = phy_write(phydev, MV88E1111_SCR, scr | 0x0008);

	return err;
}

static int mpc8568_mds_phy_fixups(struct phy_device *phydev)
{
	int temp;
	int err;

	err = phy_write(phydev,29, 0x0006);

	if (err)
		return err;

	temp = phy_read(phydev, 30);

	if (temp < 0)
		return temp;

	temp = (temp & (~0x8000)) | 0x4000;
	err = phy_write(phydev,30, temp);

	if (err)
		return err;

	err = phy_write(phydev,29, 0x000a);

	if (err)
		return err;

	temp = phy_read(phydev, 30);

	if (temp < 0)
		return temp;

	temp = phy_read(phydev, 30);

	if (temp < 0)
		return temp;

	temp &= ~0x0020;

	err = phy_write(phydev,30,temp);

	if (err)
		return err;

	temp = phy_read(phydev, 16);

	if (temp < 0)
		return temp;

	temp &= ~0x0060;
	err = phy_write(phydev,16,temp);

	return err;
}

#ifdef CONFIG_SYNO_QORIQ
#ifdef CONFIG_PCI
 
static int get_p1021mds_host_agent(void)
{
	struct device_node *np;
	void __iomem *gur_regs;
	u32 host_agent;

	np = of_find_compatible_node(NULL, NULL, "fsl,p1021-guts");
	if (np == NULL) {
		printk(KERN_ERR "Could not find global-utilities node\n");
		return 0;
	}

	gur_regs = of_iomap(np, 0);
	of_node_put(np);
	if (!gur_regs) {
		printk(KERN_ERR "Failed to map global-utilities register space\n");
		return 0;
	}
	host_agent = (in_be32(gur_regs + 4) & 0x00070000) >> 16 ;

	iounmap(gur_regs);

	return host_agent;
}

static bool p1021mds_pci_is_host(u32 host_agent, resource_size_t res)
{
	switch (res & 0xfffff) {
	case 0xa000:     
		return host_agent & 0x2;
		break;
	case 0x9000:     
		return host_agent & 0x1;
		break;
	default:
		return true;
	}
}
#endif
#endif

#ifdef CONFIG_SYNO_QORIQ
#ifdef CONFIG_SMP
extern void __init mpc85xx_smp_init(void);
#endif
#endif

static void __init mpc85xx_mds_setup_arch(void)
{
	struct device_node *np;
	static u8 __iomem *bcsr_regs = NULL;
#ifdef CONFIG_PCI
	struct pci_controller *hose;
#ifdef CONFIG_SYNO_QORIQ
	u32 host_agent;
#endif
#endif
	dma_addr_t max = 0xffffffff;

	if (ppc_md.progress)
		ppc_md.progress("mpc85xx_mds_setup_arch()", 0);

	np = of_find_node_by_name(NULL, "bcsr");
	if (np != NULL) {
		struct resource res;

		of_address_to_resource(np, 0, &res);
		bcsr_regs = ioremap(res.start, res.end - res.start +1);
		of_node_put(np);
	}

#ifdef CONFIG_PCI
#ifdef CONFIG_SYNO_QORIQ
	host_agent = get_p1021mds_host_agent();
#endif
	for_each_node_by_type(np, "pci") {
		if (of_device_is_compatible(np, "fsl,mpc8540-pci") ||
		    of_device_is_compatible(np, "fsl,mpc8548-pcie")) {
			struct resource rsrc;
			of_address_to_resource(np, 0, &rsrc);
#ifdef CONFIG_SYNO_QORIQ
			if (!p1021mds_pci_is_host(host_agent, rsrc.start))
				continue;
#endif
			if ((rsrc.start & 0xfffff) == 0x8000)
				fsl_add_bridge(np, 1);
			else
				fsl_add_bridge(np, 0);

			hose = pci_find_hose_for_OF_device(np);
			max = min(max, hose->dma_window_base_cur +
					hose->dma_window_size);
		}
	}
#endif

#ifdef CONFIG_SYNO_QORIQ
#ifdef CONFIG_SMP
	mpc85xx_smp_init();
#endif
#endif

#ifdef CONFIG_QUICC_ENGINE
	np = of_find_compatible_node(NULL, NULL, "fsl,qe");
	if (!np) {
		np = of_find_node_by_name(NULL, "qe");
		if (!np)
			return;
	}

	qe_reset();
	of_node_put(np);

	np = of_find_node_by_name(NULL, "par_io");
	if (np) {
		struct device_node *ucc;

		par_io_init(np);
		of_node_put(np);

		for_each_node_by_name(ucc, "ucc")
			par_io_of_config(ucc);
	}

	if (bcsr_regs) {
		if (machine_is(mpc8568_mds)) {
#define BCSR_UCC1_GETH_EN	(0x1 << 7)
#define BCSR_UCC2_GETH_EN	(0x1 << 7)
#define BCSR_UCC1_MODE_MSK	(0x3 << 4)
#define BCSR_UCC2_MODE_MSK	(0x3 << 0)

			clrbits8(&bcsr_regs[8], BCSR_UCC1_GETH_EN);
			clrbits8(&bcsr_regs[9], BCSR_UCC2_GETH_EN);

			clrbits8(&bcsr_regs[11], BCSR_UCC1_MODE_MSK |
						 BCSR_UCC2_MODE_MSK);

			setbits8(&bcsr_regs[8], BCSR_UCC1_GETH_EN);
			setbits8(&bcsr_regs[9], BCSR_UCC2_GETH_EN);
		} else if (machine_is(mpc8569_mds)) {
#define BCSR7_UCC12_GETHnRST	(0x1 << 2)
#define BCSR8_UEM_MARVELL_RST	(0x1 << 1)
			 
			clrbits8(&bcsr_regs[7], BCSR7_UCC12_GETHnRST);
			setbits8(&bcsr_regs[8], BCSR8_UEM_MARVELL_RST);

			setbits8(&bcsr_regs[7], BCSR7_UCC12_GETHnRST);
			clrbits8(&bcsr_regs[8], BCSR8_UEM_MARVELL_RST);
		}
		iounmap(bcsr_regs);
	}
#endif	 

#ifdef CONFIG_SWIOTLB
	if (lmb_end_of_DRAM() > max) {
		ppc_swiotlb_enable = 1;
		set_pci_dma_ops(&swiotlb_dma_ops);
		ppc_md.pci_dma_dev_setup = pci_dma_dev_setup_swiotlb;
	}
#endif
}

static int __init board_fixups(void)
{
	char phy_id[20];
	char *compstrs[2] = {"fsl,gianfar-mdio", "fsl,ucc-mdio"};
	struct device_node *mdio;
	struct resource res;
	int i;

	for (i = 0; i < ARRAY_SIZE(compstrs); i++) {
		mdio = of_find_compatible_node(NULL, NULL, compstrs[i]);

		of_address_to_resource(mdio, 0, &res);
		snprintf(phy_id, sizeof(phy_id), "%llx:%02x",
			(unsigned long long)res.start, 1);

		phy_register_fixup_for_id(phy_id, mpc8568_fixup_125_clock);
		phy_register_fixup_for_id(phy_id, mpc8568_mds_phy_fixups);

		snprintf(phy_id, sizeof(phy_id), "%llx:%02x",
			(unsigned long long)res.start, 7);
		phy_register_fixup_for_id(phy_id, mpc8568_mds_phy_fixups);

		of_node_put(mdio);
	}

	return 0;
}
machine_arch_initcall(mpc8568_mds, board_fixups);
machine_arch_initcall(mpc8569_mds, board_fixups);

static struct of_device_id mpc85xx_ids[] = {
	{ .type = "soc", },
	{ .compatible = "soc", },
	{ .compatible = "simple-bus", },
	{ .type = "qe", },
	{ .compatible = "fsl,qe", },
	{ .compatible = "gianfar", },
	{ .compatible = "fsl,rapidio-delta", },
	{},
};

static int __init mpc85xx_publish_devices(void)
{
	if (machine_is(mpc8569_mds))
		simple_gpiochip_init("fsl,mpc8569mds-bcsr-gpio");

	of_platform_bus_probe(NULL, mpc85xx_ids, NULL);

	return 0;
}
machine_device_initcall(mpc8568_mds, mpc85xx_publish_devices);
machine_device_initcall(mpc8569_mds, mpc85xx_publish_devices);

#ifdef CONFIG_SYNO_QORIQ
static struct of_device_id p1021_ids[] = {
	{ .type = "soc", },
	{ .compatible = "soc", },
	{ .compatible = "simple-bus", },
	{ .type = "qe", },
	{ .compatible = "fsl,qe", },
	{ .compatible = "gianfar", },
	{},
};

static int __init p1021_publish_devices(void)
{
	 
	of_platform_bus_probe(NULL, p1021_ids, NULL);

	return 0;
}
machine_device_initcall(p1021_mds, p1021_publish_devices);
#endif

machine_arch_initcall(mpc8568_mds, swiotlb_setup_bus_notifier);
machine_arch_initcall(mpc8569_mds, swiotlb_setup_bus_notifier);
#ifdef CONFIG_SYNO_QORIQ
machine_arch_initcall(p1021_mds, swiotlb_setup_bus_notifier);
#endif

static void __init mpc85xx_mds_pic_init(void)
{
	struct mpic *mpic;
	struct resource r;
	struct device_node *np = NULL;

	np = of_find_node_by_type(NULL, "open-pic");
	if (!np)
		return;

	if (of_address_to_resource(np, 0, &r)) {
		printk(KERN_ERR "Failed to map mpic register space\n");
		of_node_put(np);
		return;
	}

	mpic = mpic_alloc(np, r.start,
#ifdef CONFIG_SYNO_QORIQ
			MPIC_PRIMARY | MPIC_WANTS_RESET | MPIC_BIG_ENDIAN |
			MPIC_BROKEN_FRR_NIRQS | MPIC_SINGLE_DEST_CPU,
#else
			MPIC_PRIMARY | MPIC_WANTS_RESET | MPIC_BIG_ENDIAN,
#endif
			0, 256, " OpenPIC  ");

	BUG_ON(mpic == NULL);
	of_node_put(np);

	mpic_init(mpic);

#ifdef CONFIG_QUICC_ENGINE
	np = of_find_compatible_node(NULL, NULL, "fsl,qe-ic");
	if (!np) {
		np = of_find_node_by_type(NULL, "qeic");
		if (!np)
			return;
	}
	qe_ic_init(np, 0, qe_ic_cascade_muxed_mpic, NULL);
	of_node_put(np);
#endif				 
}

static int __init mpc85xx_mds_probe(void)
{
        unsigned long root = of_get_flat_dt_root();

        return of_flat_dt_is_compatible(root, "MPC85xxMDS");
}

define_machine(mpc8568_mds) {
	.name		= "MPC8568 MDS",
	.probe		= mpc85xx_mds_probe,
	.setup_arch	= mpc85xx_mds_setup_arch,
	.init_IRQ	= mpc85xx_mds_pic_init,
	.get_irq	= mpic_get_irq,
	.restart	= fsl_rstcr_restart,
	.calibrate_decr	= generic_calibrate_decr,
	.progress	= udbg_progress,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
};

static int __init mpc8569_mds_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return of_flat_dt_is_compatible(root, "fsl,MPC8569EMDS");
}

define_machine(mpc8569_mds) {
	.name		= "MPC8569 MDS",
	.probe		= mpc8569_mds_probe,
	.setup_arch	= mpc85xx_mds_setup_arch,
	.init_IRQ	= mpc85xx_mds_pic_init,
	.get_irq	= mpic_get_irq,
	.restart	= fsl_rstcr_restart,
	.calibrate_decr	= generic_calibrate_decr,
	.progress	= udbg_progress,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
};

#ifdef CONFIG_SYNO_QORIQ
static int __init p1021_mds_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return of_flat_dt_is_compatible(root, "fsl,P1021MDS");

}

define_machine(p1021_mds) {
	.name		= "P1021 MDS",
	.probe		= p1021_mds_probe,
	.setup_arch	= mpc85xx_mds_setup_arch,
	.init_IRQ	= mpc85xx_mds_pic_init,
	.get_irq	= mpic_get_irq,
	.restart	= fsl_rstcr_restart,
	.calibrate_decr	= generic_calibrate_decr,
	.progress	= udbg_progress,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
};
#endif
