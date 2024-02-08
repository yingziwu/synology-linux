#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/marvell_phy.h>
#include <linux/of.h>

#include <linux/io.h>
#include <asm/irq.h>
#include <linux/uaccess.h>

#if defined(MY_DEF_HERE)
#define MII_MARVELL_REG_INIT_FIELDS	4
#endif  
#define MII_MARVELL_PHY_PAGE		22

#define MII_M1011_IEVENT		0x13
#define MII_M1011_IEVENT_CLEAR		0x0000

#define MII_M1011_IMASK			0x12
#define MII_M1011_IMASK_INIT		0x6400
#define MII_M1011_IMASK_CLEAR		0x0000

#define MII_M1011_PHY_SCR		0x10
#define MII_M1011_PHY_SCR_MDI		0x0000
#define MII_M1011_PHY_SCR_MDI_X		0x0020
#define MII_M1011_PHY_SCR_AUTO_CROSS	0x0060

#define MII_M1145_PHY_EXT_ADDR_PAGE	0x16
#define MII_M1145_PHY_EXT_SR		0x1b
#define MII_M1145_PHY_EXT_CR		0x14
#define MII_M1145_RGMII_RX_DELAY	0x0080
#define MII_M1145_RGMII_TX_DELAY	0x0002
#define MII_M1145_HWCFG_MODE_SGMII_NO_CLK	0x4
#define MII_M1145_HWCFG_MODE_MASK		0xf
#define MII_M1145_HWCFG_FIBER_COPPER_AUTO	0x8000

#define MII_M1145_HWCFG_MODE_SGMII_NO_CLK	0x4
#define MII_M1145_HWCFG_MODE_MASK		0xf
#define MII_M1145_HWCFG_FIBER_COPPER_AUTO	0x8000

#define MII_M1111_PHY_LED_CONTROL	0x18
#define MII_M1111_PHY_LED_DIRECT	0x4100
#define MII_M1111_PHY_LED_COMBINE	0x411c
#define MII_M1111_PHY_EXT_CR		0x14
#define MII_M1111_RX_DELAY		0x80
#define MII_M1111_TX_DELAY		0x2
#define MII_M1111_PHY_EXT_SR		0x1b

#define MII_M1111_HWCFG_MODE_MASK		0xf
#define MII_M1111_HWCFG_MODE_COPPER_RGMII	0xb
#define MII_M1111_HWCFG_MODE_FIBER_RGMII	0x3
#define MII_M1111_HWCFG_MODE_SGMII_NO_CLK	0x4
#define MII_M1111_HWCFG_MODE_COPPER_RTBI	0x9
#define MII_M1111_HWCFG_FIBER_COPPER_AUTO	0x8000
#define MII_M1111_HWCFG_FIBER_COPPER_RES	0x2000

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
#define MII_M1112_SPEC_STAT_REG		0x11
#define MII_M1112_FIBER_COPPER_RES	0x80
#else  
#define COPPER_BASE_T		1
#define FIBER_BASE_R		2
#define FIBER_BASE_X		3
#endif  

#define MII_M1112_PHY_ENERGY_STATE	0x10
#if defined(MY_DEF_HERE)
#define MII_M1112_PHY_COPPER_STATE	0x10

#define COPPER_PAGE		0
#define FIBER_PAGE		1

#define COPPER_BASE_T		BIT(1)
#define FIBER_BASE_R		BIT(2)
#define FIBER_BASE_X		BIT(3)
#endif  
#else  
#define MII_M1111_COPPER		0
#define MII_M1111_FIBER			1
#endif  

#define MII_88E1121_PHY_MSCR_PAGE	2
#define MII_88E1121_PHY_MSCR_REG	21
#define MII_88E1121_PHY_MSCR_RX_DELAY	BIT(5)
#define MII_88E1121_PHY_MSCR_TX_DELAY	BIT(4)
#define MII_88E1121_PHY_MSCR_DELAY_MASK	(~(0x3 << 4))

#define MII_88E1318S_PHY_MSCR1_REG	16
#define MII_88E1318S_PHY_MSCR1_PAD_ODD	BIT(6)

#define MII_88E1318S_PHY_CSIER                              0x12
 
#define MII_88E1318S_PHY_CSIER_WOL_EIE                      BIT(7)

#define MII_88E1318S_PHY_LED_PAGE                           0x03
#define MII_88E1318S_PHY_LED_TCR                            0x12
#define MII_88E1318S_PHY_LED_TCR_FORCE_INT                  BIT(15)
#if defined(MY_DEF_HERE)
#define MII_88E1318S_PHY_LED_TCR_INTN_ENABLE                BIT(7)
#else  
#define MII_88E1318S_PHY_LED_TCR_INTn_ENABLE                BIT(7)
#endif  
#define MII_88E1318S_PHY_LED_TCR_INT_ACTIVE_LOW             BIT(11)

#define MII_88E1318S_PHY_MAGIC_PACKET_WORD2                 0x17
#define MII_88E1318S_PHY_MAGIC_PACKET_WORD1                 0x18
#define MII_88E1318S_PHY_MAGIC_PACKET_WORD0                 0x19

#define MII_88E1318S_PHY_WOL_PAGE                           0x11
#define MII_88E1318S_PHY_WOL_CTRL                           0x10
#define MII_88E1318S_PHY_WOL_CTRL_CLEAR_WOL_STATUS          BIT(12)
#define MII_88E1318S_PHY_WOL_CTRL_MAGIC_PACKET_MATCH_ENABLE BIT(14)

#define MII_88E1121_PHY_LED_CTRL	16
#define MII_88E1121_PHY_LED_PAGE	3
#define MII_88E1121_PHY_LED_DEF		0x0030

#define MII_M1011_PHY_STATUS		0x11
#define MII_M1011_PHY_STATUS_1000	0x8000
#define MII_M1011_PHY_STATUS_100	0x4000
#define MII_M1011_PHY_STATUS_SPD_MASK	0xc000
#define MII_M1011_PHY_STATUS_FULLDUPLEX	0x2000
#define MII_M1011_PHY_STATUS_RESOLVED	0x0800
#define MII_M1011_PHY_STATUS_LINK	0x0400

#define MII_M1116R_CONTROL_REG_MAC	21

#define MII_88E3016_PHY_SPEC_CTRL	0x10
#define MII_88E3016_DISABLE_SCRAMBLER	0x0200
#define MII_88E3016_AUTO_MDIX_CROSSOVER	0x0030

#if defined(MY_DEF_HERE)
#define MII_88E1510_PHY_INTERNAL_REG_1	16
#define MII_88E1510_PHY_INTERNAL_REG_2	17
#define MII_88E1510_PHY_GENERAL_CTRL_1	20
#endif  

#if defined(MY_DEF_HERE)
#define MV_XMDIO(mmd, reg)					\
	((mmd << 16) | (reg & 0xffff))

#define MII_88E3310_10G_BASER_FIBER	0x1000
#define MII_88E3310_1G_BASEX_FIBER	0x2000

#define MII_88E3310_COPPER_IMASK	0x8010
#define MII_88E3310_COPPER_INT_ST	0x8011
#define MII_88E3310_COPPER_IMASK_INIT	0x6400

#define MII_88E3310_BASER_IMASK		0x9000
#define MII_88E3310_BASER_INT_ST	0x9001
#define MII_88E3310_BASER_IMASK_INIT	0x0004

#define MII_88E3310_BASEX_IMASK		0xA001
#define MII_88E3310_BASEX_INT_ST	0xA002
#define MII_88E3310_BASEX_IMASK_INIT	0x6600

#define MII_88E3310_BASEX_SPEC_SR	0xA003
#define MII_88E3310_COPPER_SPEC_SR	0x8008

#define MII_88E3310_COPPER_LP		0x0013
#define MII_88E3310_BASEX_LP		0x2005

#define MII_88E3310_COPPER_ADV		0x0010
#define MII_88E3310_BASEX_ADV		0x2004

#define MII_88E3310_CLEAR_INT		0x0000

#define MII_88E3310_PHY_STATUS_10000	0xc000
#define MII_88E3310_PHY_STATUS_5000	0xc008
#define MII_88E3310_PHY_STATUS_2500	0xc004
#define MII_88E3310_PHY_STATUS_1000	0x8000
#define MII_88E3310_PHY_STATUS_100	0x4000
#define MII_88E3310_PHY_STATUS_SPD_MASK	0xc00c

#define MII_88E3310_COPPER_SP_10000	0x2040
#define MII_88E3310_COPPER_SP_5000	0x205C
#define MII_88E3310_COPPER_SP_2500	0x2058
#define MII_88E3310_COPPER_SP_1000	0x0040
#define MII_88E3310_COPPER_SP_100	0x2000

#endif  
#if defined(MY_DEF_HERE)
#define MII_88E3310_AUT_NEG_CON		0x8000
#define MII_88E3310_AUT_NEG_ST		0x8001

#define MII_88E2110_IMASK		0x8010
#define MII_88E2110_IMASK_INIT		0x6400
#define MII_88E2110_IMASK_CLEAR		0x0000

#define MII_88E2110_ISTATUS		0x8011

#define MII_88E2110_PHY_STATUS		0x8008
#define MII_88E2110_PHY_STATUS_SPD_MASK	0xc00c
#define MII_88E2110_PHY_STATUS_5000	0xc008
#define MII_88E2110_PHY_STATUS_2500	0xc004
#define MII_88E2110_PHY_STATUS_1000	0x8000
#define MII_88E2110_PHY_STATUS_100	0x4000
#define MII_88E2110_PHY_STATUS_DUPLEX	0x2000
#define MII_88E2110_PHY_STATUS_SPDDONE	0x0800
#define MII_88E2110_PHY_STATUS_LINK	0x0400

#define MII_88E2110_NG_EXT_CTRL			0xc000
#define MII_88E2110_NG_EXT_CTRL_SWAP_ABCD	0x1

#define MII_88E2110_AN_CTRL		0x0
#define MII_88E2110_AN_CTRL_EXT_NP_CTRL 0x2000
#define MII_88E2110_AN_CTRL_AN_EN	0x1000
#define MII_88E2110_AN_CTRL_RESTART_AN	0x0200

#define MII_88E2110_ADVERTISE		0x10
#define MII_88E2110_LPA			0x13
#define MII_88E2110_STAT1000		0x8001

#define MII_88E2110_MGBASET_AN_CTRL1			0x20
#define MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_5000	0x01e1
#define MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_2500	0x00a1
#define MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_1000	0x0001

#endif  
MODULE_DESCRIPTION("Marvell PHY driver");
MODULE_AUTHOR("Andy Fleming");
MODULE_LICENSE("GPL");

#if defined(MY_DEF_HERE)
struct marvell_hw_stat {
	const char *string;
	u8 page;
	u8 reg;
	u8 bits;
};

static struct marvell_hw_stat marvell_hw_stats[] = {
	{ "phy_receive_errors", 0, 21, 16},
	{ "phy_idle_errors", 0, 10, 8 },
};

struct marvell_priv {
	u64 stats[ARRAY_SIZE(marvell_hw_stats)];
};
#endif  

static int marvell_ack_interrupt(struct phy_device *phydev)
{
	int err;

	err = phy_read(phydev, MII_M1011_IEVENT);

	if (err < 0)
		return err;

	return 0;
}

#if defined(MY_DEF_HERE)
static int m88e3310_ack_interrupt(struct phy_device *phydev)
{
	 
	if (phydev->dev_flags & COPPER_BASE_T)
		phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_COPPER_INT_ST));
	else if (phydev->dev_flags & FIBER_BASE_R)
		phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASER_INT_ST));
	else if (phydev->dev_flags & FIBER_BASE_X)
		phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_INT_ST));

	return 0;
}

#endif  
static int marvell_config_intr(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_write(phydev, MII_M1011_IMASK, MII_M1011_IMASK_INIT);
	else
		err = phy_write(phydev, MII_M1011_IMASK, MII_M1011_IMASK_CLEAR);

	return err;
}

#if defined(MY_DEF_HERE)
static int m88e3310_config_intr(struct phy_device *phydev)
{
	if (phydev->interrupts == PHY_INTERRUPT_ENABLED) {
		if (phydev->dev_flags & COPPER_BASE_T)
			phy_write(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_COPPER_INT_ST),
				  MII_88E3310_COPPER_IMASK_INIT);
		else if (phydev->dev_flags & FIBER_BASE_R)
			phy_write(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASER_INT_ST),
				  MII_88E3310_BASER_IMASK_INIT);
		else if (phydev->dev_flags & FIBER_BASE_X)
			phy_write(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_INT_ST),
				  MII_88E3310_BASEX_IMASK_INIT);
	} else {
		if (phydev->dev_flags & COPPER_BASE_T)
			phy_write(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_COPPER_INT_ST),
				  MII_88E3310_CLEAR_INT);
		else if (phydev->dev_flags & FIBER_BASE_R)
			phy_write(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASER_INT_ST),
				  MII_88E3310_CLEAR_INT);
		else if (phydev->dev_flags & FIBER_BASE_X)
			phy_write(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_INT_ST),
				  MII_88E3310_CLEAR_INT);
	}

	return 0;
}

#endif  
static int marvell_set_polarity(struct phy_device *phydev, int polarity)
{
	int reg;
	int err;
	int val;

	reg = phy_read(phydev, MII_M1011_PHY_SCR);
	if (reg < 0)
		return reg;

	val = reg;
	val &= ~MII_M1011_PHY_SCR_AUTO_CROSS;
	switch (polarity) {
	case ETH_TP_MDI:
		val |= MII_M1011_PHY_SCR_MDI;
		break;
	case ETH_TP_MDI_X:
		val |= MII_M1011_PHY_SCR_MDI_X;
		break;
	case ETH_TP_MDI_AUTO:
	case ETH_TP_MDI_INVALID:
	default:
		val |= MII_M1011_PHY_SCR_AUTO_CROSS;
		break;
	}

	if (val != reg) {
		 
		err = phy_write(phydev, MII_M1011_PHY_SCR, val);
		if (err)
			return err;
	}

	return 0;
}

static int marvell_config_aneg(struct phy_device *phydev)
{
	int err;

	err = phy_write(phydev, MII_BMCR, BMCR_RESET);

	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1d, 0x1f);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1e, 0x200c);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1d, 0x5);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1e, 0);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1e, 0x100);
	if (err < 0)
		return err;

	err = marvell_set_polarity(phydev, phydev->mdix);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_M1111_PHY_LED_CONTROL,
			MII_M1111_PHY_LED_DIRECT);
	if (err < 0)
		return err;

	err = genphy_config_aneg(phydev);
	if (err < 0)
		return err;

	if (phydev->autoneg != AUTONEG_ENABLE) {
		int bmcr;

		bmcr = phy_read(phydev, MII_BMCR);
		if (bmcr < 0)
			return bmcr;

		err = phy_write(phydev, MII_BMCR, bmcr | BMCR_RESET);
		if (err < 0)
			return err;
	}

	return 0;
}

#ifdef CONFIG_OF_MDIO
 
static int marvell_of_reg_init(struct phy_device *phydev)
{
	const __be32 *paddr;
	int len, i, saved_page, current_page, page_changed, ret;

#if defined(MY_DEF_HERE)
	if (!phydev->mdio.dev.of_node)
#else  
	if (!phydev->dev.of_node)
#endif  
		return 0;

#if defined(MY_DEF_HERE)
	paddr = of_get_property(phydev->mdio.dev.of_node,
				"marvell,reg-init", &len);
#else  
	paddr = of_get_property(phydev->dev.of_node, "marvell,reg-init", &len);
#endif  
	if (!paddr || len < (4 * sizeof(*paddr)))
		return 0;

	saved_page = phy_read(phydev, MII_MARVELL_PHY_PAGE);
	if (saved_page < 0)
		return saved_page;
	page_changed = 0;
	current_page = saved_page;

	ret = 0;
	len /= sizeof(*paddr);
	for (i = 0; i < len - 3; i += 4) {
		u16 reg_page = be32_to_cpup(paddr + i);
		u16 reg = be32_to_cpup(paddr + i + 1);
		u16 mask = be32_to_cpup(paddr + i + 2);
		u16 val_bits = be32_to_cpup(paddr + i + 3);
		int val;

		if (reg_page != current_page) {
			current_page = reg_page;
			page_changed = 1;
			ret = phy_write(phydev, MII_MARVELL_PHY_PAGE, reg_page);
			if (ret < 0)
				goto err;
		}

		val = 0;
		if (mask) {
			val = phy_read(phydev, reg);
			if (val < 0) {
				ret = val;
				goto err;
			}
			val &= mask;
		}
		val |= val_bits;

		ret = phy_write(phydev, reg, val);
		if (ret < 0)
			goto err;
	}
err:
	if (page_changed) {
		i = phy_write(phydev, MII_MARVELL_PHY_PAGE, saved_page);
		if (ret == 0)
			ret = i;
	}
	return ret;
}
#if defined(MY_DEF_HERE)

static int marvell_of_reg_c45_init(struct phy_device *phydev)
{
	const __be32 *paddr;
	int len, i, ret;

	if (!phydev->mdio.dev.of_node)
		return 0;

	paddr = of_get_property(phydev->mdio.dev.of_node,
				"marvell,c45-reg-init", &len);
	if (!paddr)
		return 0;

	ret = 0;
	len /= sizeof(*paddr);
	for (i = 0; i < len - (MII_MARVELL_REG_INIT_FIELDS - 1);
	     i += MII_MARVELL_REG_INIT_FIELDS) {
		u16 devid = be32_to_cpup(paddr + i);
		u16 reg = be32_to_cpup(paddr + i + 1);
		u16 mask = be32_to_cpup(paddr + i + 2);
		u16 val_bits = be32_to_cpup(paddr + i + 3);
		int val;

		val = 0;
		if (mask) {
			val = phy_read_mmd(phydev, devid, reg);
			if (val < 0) {
				ret = val;
				goto err;
			}
			val &= mask;
		}
		val |= val_bits;

		ret = phy_write_mmd(phydev, devid, reg, val);
		if (ret < 0)
			goto err;
	}
err:
	return ret;
}
#endif  
#else
static int marvell_of_reg_init(struct phy_device *phydev)
{
	return 0;
}
#if defined(MY_DEF_HERE)

static int marvell_of_reg_c45_init(struct phy_device *phydev)
{
	return 0;
}
#endif  
#endif  

static int m88e1121_config_aneg(struct phy_device *phydev)
{
	int err, oldpage, mscr;

	oldpage = phy_read(phydev, MII_MARVELL_PHY_PAGE);

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE,
			MII_88E1121_PHY_MSCR_PAGE);
	if (err < 0)
		return err;

	if (phy_interface_is_rgmii(phydev)) {
		mscr = phy_read(phydev, MII_88E1121_PHY_MSCR_REG) &
			MII_88E1121_PHY_MSCR_DELAY_MASK;

#if defined(MY_DEF_HERE)
		if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
#if defined(MY_DEF_HERE)
		    phydev->interface == PHY_INTERFACE_MODE_RGMII)
#else  
			phydev->interface == PHY_INTERFACE_MODE_RGMII)
#endif  
#else  
		if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID)
#endif  
			mscr |= (MII_88E1121_PHY_MSCR_RX_DELAY |
				 MII_88E1121_PHY_MSCR_TX_DELAY);
		else if (phydev->interface == PHY_INTERFACE_MODE_RGMII_RXID)
			mscr |= MII_88E1121_PHY_MSCR_RX_DELAY;
		else if (phydev->interface == PHY_INTERFACE_MODE_RGMII_TXID)
			mscr |= MII_88E1121_PHY_MSCR_TX_DELAY;

		err = phy_write(phydev, MII_88E1121_PHY_MSCR_REG, mscr);
		if (err < 0)
			return err;
	}

	phy_write(phydev, MII_MARVELL_PHY_PAGE, oldpage);

	err = phy_write(phydev, MII_BMCR, BMCR_RESET);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_M1011_PHY_SCR,
			MII_M1011_PHY_SCR_AUTO_CROSS);
	if (err < 0)
		return err;

	oldpage = phy_read(phydev, MII_MARVELL_PHY_PAGE);

	phy_write(phydev, MII_MARVELL_PHY_PAGE, MII_88E1121_PHY_LED_PAGE);
	phy_write(phydev, MII_88E1121_PHY_LED_CTRL, MII_88E1121_PHY_LED_DEF);
	phy_write(phydev, MII_MARVELL_PHY_PAGE, oldpage);

	err = genphy_config_aneg(phydev);

	return err;
}

static int m88e1318_config_aneg(struct phy_device *phydev)
{
	int err, oldpage, mscr;

	oldpage = phy_read(phydev, MII_MARVELL_PHY_PAGE);

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE,
			MII_88E1121_PHY_MSCR_PAGE);
	if (err < 0)
		return err;

	mscr = phy_read(phydev, MII_88E1318S_PHY_MSCR1_REG);
	mscr |= MII_88E1318S_PHY_MSCR1_PAD_ODD;

	err = phy_write(phydev, MII_88E1318S_PHY_MSCR1_REG, mscr);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, oldpage);
	if (err < 0)
		return err;

	return m88e1121_config_aneg(phydev);
}

static int m88e1510_config_aneg(struct phy_device *phydev)
{
	int err;

	err = m88e1318_config_aneg(phydev);
	if (err < 0)
		return err;

#if defined(MY_DEF_HERE)
	return 0;
#else  
	return marvell_of_reg_init(phydev);
#endif  
}

#if defined(MY_DEF_HERE)
static int marvell_config_init(struct phy_device *phydev)
{
	 
	return marvell_of_reg_init(phydev);
}
#endif  

#if defined(MY_DEF_HERE)
static int marvell_c45_config_init(struct phy_device *phydev)
{
	 
	return marvell_of_reg_c45_init(phydev);
}

#endif  
static int m88e1116r_config_init(struct phy_device *phydev)
{
	int temp;
	int err;

	temp = phy_read(phydev, MII_BMCR);
	temp |= BMCR_RESET;
	err = phy_write(phydev, MII_BMCR, temp);
	if (err < 0)
		return err;

	mdelay(500);

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0);
	if (err < 0)
		return err;

	temp = phy_read(phydev, MII_M1011_PHY_SCR);
	temp |= (7 << 12);	 
	temp |= (1 << 11);	 
	temp |= MII_M1011_PHY_SCR_AUTO_CROSS;
	err = phy_write(phydev, MII_M1011_PHY_SCR, temp);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 2);
	if (err < 0)
		return err;
	temp = phy_read(phydev, MII_M1116R_CONTROL_REG_MAC);
	temp |= (1 << 5);
	temp |= (1 << 4);
	err = phy_write(phydev, MII_M1116R_CONTROL_REG_MAC, temp);
	if (err < 0)
		return err;
	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0);
	if (err < 0)
		return err;

	temp = phy_read(phydev, MII_BMCR);
	temp |= BMCR_RESET;
	err = phy_write(phydev, MII_BMCR, temp);
	if (err < 0)
		return err;

	mdelay(500);

#if defined(MY_DEF_HERE)
	return marvell_config_init(phydev);
#else  
	return 0;
#endif  
}

static int m88e3016_config_init(struct phy_device *phydev)
{
	int reg;

	reg = phy_read(phydev, MII_88E3016_PHY_SPEC_CTRL);
	if (reg < 0)
		return reg;

	reg &= ~MII_88E3016_DISABLE_SCRAMBLER;
	reg |= MII_88E3016_AUTO_MDIX_CROSSOVER;

	reg = phy_write(phydev, MII_88E3016_PHY_SPEC_CTRL, reg);
	if (reg < 0)
		return reg;

#if defined(MY_DEF_HERE)
	return marvell_config_init(phydev);
#else  
	return 0;
#endif  
}

#if defined(MY_DEF_HERE)
int m88e3310_phy_update_link(struct phy_device *phydev)
{
	int status;

	phydev->dev_flags = 0;

	status = phy_read(phydev, MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMSR));

	if (status & BMSR_LSTATUS) {
		phydev->link = 1;
		phydev->dev_flags = COPPER_BASE_T;
		return 1;
	}

	status = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, (MII_BMSR + MII_88E3310_10G_BASER_FIBER)));
	if (status & BMSR_LSTATUS) {
		phydev->link = 1;
		phydev->dev_flags = FIBER_BASE_R;
		return 1;
	}

	status = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, (MII_BMSR + MII_88E3310_1G_BASEX_FIBER)));
	if (status & BMSR_LSTATUS) {
		phydev->link = 1;
		phydev->dev_flags = FIBER_BASE_X;
		return 1;
	}

	phydev->link = 0;
	phydev->speed = 0;

	return 0;
}

static int m88e3310_config_init(struct phy_device *phydev)
{
#if defined(MY_DEF_HERE)
	 
	phydev->supported |= SUPPORTED_1000baseT_Full;
#endif  
	m88e3310_phy_update_link(phydev);

	return 0;
}

#endif  
static int m88e1111_config_init(struct phy_device *phydev)
{
	int err;
	int temp;

	if (phy_interface_is_rgmii(phydev)) {
		temp = phy_read(phydev, MII_M1111_PHY_EXT_CR);
		if (temp < 0)
			return temp;

#if defined(MY_DEF_HERE)
		if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
#if defined(MY_DEF_HERE)
		    phydev->interface == PHY_INTERFACE_MODE_RGMII) {
#else  
			phydev->interface == PHY_INTERFACE_MODE_RGMII) {
#endif  
#else  
		if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID) {
#endif  
			temp |= (MII_M1111_RX_DELAY | MII_M1111_TX_DELAY);
		} else if (phydev->interface == PHY_INTERFACE_MODE_RGMII_RXID) {
			temp &= ~MII_M1111_TX_DELAY;
			temp |= MII_M1111_RX_DELAY;
		} else if (phydev->interface == PHY_INTERFACE_MODE_RGMII_TXID) {
			temp &= ~MII_M1111_RX_DELAY;
			temp |= MII_M1111_TX_DELAY;
		}

		err = phy_write(phydev, MII_M1111_PHY_EXT_CR, temp);
		if (err < 0)
			return err;

		temp = phy_read(phydev, MII_M1111_PHY_EXT_SR);
		if (temp < 0)
			return temp;

		temp &= ~(MII_M1111_HWCFG_MODE_MASK);

		if (temp & MII_M1111_HWCFG_FIBER_COPPER_RES)
			temp |= MII_M1111_HWCFG_MODE_FIBER_RGMII;
		else
			temp |= MII_M1111_HWCFG_MODE_COPPER_RGMII;

		err = phy_write(phydev, MII_M1111_PHY_EXT_SR, temp);
		if (err < 0)
			return err;
	}

	if (phydev->interface == PHY_INTERFACE_MODE_SGMII) {
		temp = phy_read(phydev, MII_M1111_PHY_EXT_SR);
		if (temp < 0)
			return temp;

		temp &= ~(MII_M1111_HWCFG_MODE_MASK);
		temp |= MII_M1111_HWCFG_MODE_SGMII_NO_CLK;
		temp |= MII_M1111_HWCFG_FIBER_COPPER_AUTO;

		err = phy_write(phydev, MII_M1111_PHY_EXT_SR, temp);
		if (err < 0)
			return err;

		err = phy_read(phydev, MII_M1145_PHY_EXT_ADDR_PAGE);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_M1145_PHY_EXT_ADDR_PAGE,
				err & (~0xff));
		if (err < 0)
			return err;
	}

	if (phydev->interface == PHY_INTERFACE_MODE_RTBI) {
		temp = phy_read(phydev, MII_M1111_PHY_EXT_CR);
		if (temp < 0)
			return temp;
		temp |= (MII_M1111_RX_DELAY | MII_M1111_TX_DELAY);
		err = phy_write(phydev, MII_M1111_PHY_EXT_CR, temp);
		if (err < 0)
			return err;

		temp = phy_read(phydev, MII_M1111_PHY_EXT_SR);
		if (temp < 0)
			return temp;
		temp &= ~(MII_M1111_HWCFG_MODE_MASK | MII_M1111_HWCFG_FIBER_COPPER_RES);
		temp |= 0x7 | MII_M1111_HWCFG_FIBER_COPPER_AUTO;
		err = phy_write(phydev, MII_M1111_PHY_EXT_SR, temp);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_BMCR, BMCR_RESET);
		if (err < 0)
			return err;
		do
			temp = phy_read(phydev, MII_BMCR);
		while (temp & BMCR_RESET);

		temp = phy_read(phydev, MII_M1111_PHY_EXT_SR);
		if (temp < 0)
			return temp;
		temp &= ~(MII_M1111_HWCFG_MODE_MASK | MII_M1111_HWCFG_FIBER_COPPER_RES);
		temp |= MII_M1111_HWCFG_MODE_COPPER_RTBI | MII_M1111_HWCFG_FIBER_COPPER_AUTO;
		err = phy_write(phydev, MII_M1111_PHY_EXT_SR, temp);
		if (err < 0)
			return err;
	}

	err = marvell_of_reg_init(phydev);
	if (err < 0)
		return err;

	return phy_write(phydev, MII_BMCR, BMCR_RESET);
}
#ifdef MY_DEF_HERE
int syno_m88e151X_led_init(struct phy_device *phydev)
{
	int err = -1;
	int status = 0;
	int page = 0;

	page = phy_read(phydev, MII_MARVELL_PHY_PAGE);
	if (page < 0) {
		goto END;
	}
	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0003);
	if (err < 0) {
		goto END;
	}

	status = phy_read(phydev, 0x10);
	if (status < 0) {
		goto END;
	}
	status &= 0xf000;
	status |= 0x0771;
	err = phy_write(phydev, 0x10, status);
	if (err < 0) {
		goto END;
	}

	status = phy_read(phydev, 0x12);
	status &= 0xf8ff;
	status |= 0x0200;
	status &= 0xff7f;
	err = phy_write(phydev, 0x12, status);
	if (err < 0) {
		goto END;
	}
	 
	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, page);
	if (err < 0) {
		goto END;
	}
	err = 0;

END:
	return err;
}
EXPORT_SYMBOL(syno_m88e151X_led_init);

int syno_m88e151X_init(struct phy_device *phydev)
{
	int err = -1;
	int status = 0;
	int page = 0;

	err = syno_m88e151X_led_init(phydev);
	if (err < 0) {
		goto END;
	}

	page = phy_read(phydev, MII_MARVELL_PHY_PAGE);
	if (page < 0) {
		goto END;
	}

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0002);
	if (err < 0) {
		goto END;
	}

	status = phy_read(phydev, 0x10);
	if (status < 0) {
		goto END;
	}
	status |= 0x0004;
	err = phy_write(phydev, 0x10, status);
	if (err < 0) {
		goto END;
	}

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0);
	if (err < 0) {
		goto END;
	}

	status = phy_read(phydev, 0x12);
	status &= 0xff7f;
	err = phy_write(phydev, 0x12, status);
	if (err < 0) {
		goto END;
	}

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, page);
	if (err < 0) {
		goto END;
	}
	err = 0;

END:
	return err;
}
#endif  

#if defined(MY_DEF_HERE)
static int m88e1510_phy_writebits(struct phy_device *phydev,
				  u8 reg_num, u16 offset, u16 len, u16 data)
{
	int err;
	int reg;
	u16 mask;

	if ((len + offset) >= 16)
		mask = 0 - (1 << offset);
	else
		mask = (1 << (len + offset)) - (1 << offset);

	reg = phy_read(phydev, reg_num);
	if (reg < 0)
		return reg;

	reg &= ~mask;
	reg |= data << offset;

	err = phy_write(phydev, reg_num, (u16)reg);

	return err;
}

static int m88e1510_config_init(struct phy_device *phydev)
{
	int err;

	if (phydev->interface == PHY_INTERFACE_MODE_SGMII) {
		err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x00ff);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_2, 0x214B);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_1, 0x2144);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_2, 0x0C28);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_1, 0x2146);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_2, 0xB233);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_1, 0x214D);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_2, 0xCC0C);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1510_PHY_INTERNAL_REG_1, 0x2159);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 18);
		if (err < 0)
			return err;

		err = m88e1510_phy_writebits(phydev,
					     MII_88E1510_PHY_GENERAL_CTRL_1,
					     0, 3, 1);
		if (err < 0)
			return err;

		err = m88e1510_phy_writebits(phydev,
					     MII_88E1510_PHY_GENERAL_CTRL_1,
					     15, 1, 1);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0);
		if (err < 0)
			return err;

		usleep_range(100, 200);
	}

#ifdef MY_DEF_HERE
	err = syno_m88e151X_init(phydev);
	if (err < 0)
		return err;
#endif  
	return m88e1111_config_init(phydev);
}
#endif  

static int m88e1118_config_aneg(struct phy_device *phydev)
{
	int err;

	err = phy_write(phydev, MII_BMCR, BMCR_RESET);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_M1011_PHY_SCR,
			MII_M1011_PHY_SCR_AUTO_CROSS);
	if (err < 0)
		return err;

	err = genphy_config_aneg(phydev);
	return 0;
}

static int m88e1118_config_init(struct phy_device *phydev)
{
	int err;

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0002);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x15, 0x1070);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0003);
	if (err < 0)
		return err;

	if (phydev->dev_flags & MARVELL_PHY_M1118_DNS323_LEDS)
		err = phy_write(phydev, 0x10, 0x1100);
	else
		err = phy_write(phydev, 0x10, 0x021e);
	if (err < 0)
		return err;

	err = marvell_of_reg_init(phydev);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0);
	if (err < 0)
		return err;

	return phy_write(phydev, MII_BMCR, BMCR_RESET);
}

static int m88e1149_config_init(struct phy_device *phydev)
{
	int err;

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0002);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x15, 0x1048);
	if (err < 0)
		return err;

	err = marvell_of_reg_init(phydev);
	if (err < 0)
		return err;

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x0);
	if (err < 0)
		return err;

	return phy_write(phydev, MII_BMCR, BMCR_RESET);
}

static int m88e1145_config_init(struct phy_device *phydev)
{
	int err;
	int temp;

	err = phy_write(phydev, 0x1d, 0x001b);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1e, 0x418f);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1d, 0x0016);
	if (err < 0)
		return err;

	err = phy_write(phydev, 0x1e, 0xa2da);
	if (err < 0)
		return err;

	if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID) {
		int temp = phy_read(phydev, MII_M1145_PHY_EXT_CR);

		if (temp < 0)
			return temp;

		temp |= (MII_M1145_RGMII_RX_DELAY | MII_M1145_RGMII_TX_DELAY);

		err = phy_write(phydev, MII_M1145_PHY_EXT_CR, temp);
		if (err < 0)
			return err;

		if (phydev->dev_flags & MARVELL_PHY_M1145_FLAGS_RESISTANCE) {
			err = phy_write(phydev, 0x1d, 0x0012);
			if (err < 0)
				return err;

			temp = phy_read(phydev, 0x1e);
			if (temp < 0)
				return temp;

			temp &= 0xf03f;
			temp |= 2 << 9;	 
			temp |= 2 << 6;	 

			err = phy_write(phydev, 0x1e, temp);
			if (err < 0)
				return err;

			err = phy_write(phydev, 0x1d, 0x3);
			if (err < 0)
				return err;

			err = phy_write(phydev, 0x1e, 0x8000);
			if (err < 0)
				return err;
		}
	}

	if (phydev->interface == PHY_INTERFACE_MODE_SGMII) {
		temp = phy_read(phydev, MII_M1145_PHY_EXT_SR);
		if (temp < 0)
			return temp;

		temp &= ~MII_M1145_HWCFG_MODE_MASK;
		temp |= MII_M1145_HWCFG_MODE_SGMII_NO_CLK;
		temp |= MII_M1145_HWCFG_FIBER_COPPER_AUTO;

		err = phy_write(phydev, MII_M1145_PHY_EXT_SR, temp);
		if (err < 0)
			return err;
	}

	err = marvell_of_reg_init(phydev);
	if (err < 0)
		return err;

	return 0;
}

#if defined(MY_DEF_HERE)
int m88e3310_restart_aneg(struct phy_device *phydev)
{
	int ctl = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_BMCR));

	if (ctl < 0)
		return ctl;

	ctl |= BMCR_ANENABLE | BMCR_ANRESTART;

	ctl &= ~BMCR_ISOLATE;

#if defined(MY_DEF_HERE)
	return phy_write(phydev, MV_XMDIO(MDIO_MMD_AN, MII_BMCR), ctl);
#else  
	return phy_write(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_BMCR), ctl);
#endif  
}

int m88e3310_setup_forced(struct phy_device *phydev)
{
	int ctl = 0;

	phydev->pause = 0;
	phydev->asym_pause = 0;

	if (phydev->speed == SPEED_10000)
		ctl |= MII_88E3310_COPPER_SP_10000;
	else if (phydev->speed == SPEED_5000)
		ctl |= MII_88E3310_COPPER_SP_5000;
	else if (phydev->speed == SPEED_2500)
		ctl |= MII_88E3310_COPPER_SP_2500;
	else if (phydev->speed == SPEED_1000)
		ctl |= MII_88E3310_COPPER_SP_1000;
	else if (phydev->speed == SPEED_100)
		ctl |= MII_88E3310_COPPER_SP_100;

	if (phydev->duplex == DUPLEX_FULL)
		ctl |= BMCR_FULLDPLX;

	return phy_write(phydev, MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMCR), ctl);
}

static int m88e3310_config_advert(struct phy_device *phydev)
{
	u32 advertise;
	int oldadv, adv, bmsr;
	int err, changed = 0;

	phydev->advertising &= phydev->supported;
	advertise = phydev->advertising;

	adv = phy_read(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_COPPER_ADV));

	oldadv = adv;
	adv &= ~(ADVERTISE_ALL | ADVERTISE_100BASE4 | ADVERTISE_PAUSE_CAP |
		 ADVERTISE_PAUSE_ASYM);
	adv |= ethtool_adv_to_mii_adv_t(advertise);

	if (adv != oldadv) {
		err = phy_write(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_COPPER_ADV), adv);

		changed = 1;
	}

#if defined(MY_DEF_HERE)
	bmsr = phy_read(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_AUT_NEG_ST));
#else  
	bmsr = phy_read(phydev, MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMSR));
#endif  

	if (!(bmsr & BMSR_ESTATEN))
		return changed;

	adv = phy_read(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_COPPER_ADV));

	oldadv = adv;
	adv &= ~(ADVERTISE_1000FULL | ADVERTISE_1000HALF);

	if (phydev->supported & (SUPPORTED_1000baseT_Half |
				 SUPPORTED_1000baseT_Full)) {
		adv |= ethtool_adv_to_mii_ctrl1000_t(advertise);
	}

	if (adv != oldadv)
		changed = 1;

#if defined(MY_DEF_HERE)
	phy_write(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_AUT_NEG_CON), adv);

#endif  
	return changed;
}

int m88e3310_config_aneg(struct phy_device *phydev)
{
	int result;

#if defined(MY_DEF_HERE)
	 
#else  
	 
#endif  
	if ((phydev->dev_flags & FIBER_BASE_X) || (phydev->dev_flags & FIBER_BASE_R))
		return 0;

#if defined(MY_DEF_HERE)
	 
	if (phydev->speed == SPEED_10000 || phydev->speed == SPEED_5000)
		return 0;

#endif  
	if (phydev->autoneg != AUTONEG_ENABLE)
		return m88e3310_setup_forced(phydev);

	result = m88e3310_config_advert(phydev);

	if (result == 0) {
		 
		int ctl = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_BMCR));

		if (ctl < 0)
			return ctl;

		if (!(ctl & BMCR_ANENABLE) || (ctl & BMCR_ISOLATE))
			result = 1;  
	}

	if (result > 0)
		result = m88e3310_restart_aneg(phydev);

	return result;
}

#endif  
 
static int marvell_read_status(struct phy_device *phydev)
{
	int adv;
	int err;
	int lpa;
	int lpagb;
	int status = 0;

	err = genphy_update_link(phydev);
	if (err)
		return err;

#if defined(MY_DEF_HERE)
	if (phydev->autoneg == AUTONEG_ENABLE) {
#else  
	if (AUTONEG_ENABLE == phydev->autoneg) {
#endif  
		status = phy_read(phydev, MII_M1011_PHY_STATUS);
		if (status < 0)
			return status;

		lpa = phy_read(phydev, MII_LPA);
		if (lpa < 0)
			return lpa;

		lpagb = phy_read(phydev, MII_STAT1000);
		if (lpagb < 0)
			return lpagb;

		adv = phy_read(phydev, MII_ADVERTISE);
		if (adv < 0)
			return adv;

		phydev->lp_advertising = mii_stat1000_to_ethtool_lpa_t(lpagb) |
					 mii_lpa_to_ethtool_lpa_t(lpa);

		lpa &= adv;

#if defined(MY_DEF_HERE)
		adv = phy_read(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_AUT_NEG_ST));

		phydev->lp_advertising |= mii_stat1000_to_ethtool_lpa_t(adv);

#endif  
		if (status & MII_M1011_PHY_STATUS_FULLDUPLEX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		status = status & MII_M1011_PHY_STATUS_SPD_MASK;
#if defined(MY_DEF_HERE)
		phydev->pause = 0;
		phydev->asym_pause = 0;
#else  
		phydev->pause = phydev->asym_pause = 0;
#endif  

		switch (status) {
		case MII_M1011_PHY_STATUS_1000:
			phydev->speed = SPEED_1000;
			break;

		case MII_M1011_PHY_STATUS_100:
			phydev->speed = SPEED_100;
			break;

		default:
			phydev->speed = SPEED_10;
			break;
		}

		if (phydev->duplex == DUPLEX_FULL) {
			phydev->pause = lpa & LPA_PAUSE_CAP ? 1 : 0;
			phydev->asym_pause = lpa & LPA_PAUSE_ASYM ? 1 : 0;
		}
	} else {
		int bmcr = phy_read(phydev, MII_BMCR);

		if (bmcr < 0)
			return bmcr;

		if (bmcr & BMCR_FULLDPLX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		if (bmcr & BMCR_SPEED1000)
			phydev->speed = SPEED_1000;
		else if (bmcr & BMCR_SPEED100)
			phydev->speed = SPEED_100;
		else
			phydev->speed = SPEED_10;

#if defined(MY_DEF_HERE)
		phydev->pause = 0;
		phydev->asym_pause = 0;
#else  
		phydev->pause = phydev->asym_pause = 0;
#endif  
		phydev->lp_advertising = 0;
	}
#if defined(MY_DEF_HERE)
	if (!phydev->link) {
		phydev->speed = SPEED_UNKNOWN;
		phydev->duplex = DUPLEX_UNKNOWN;
	}
#else  

#endif  
	return 0;
}

#if defined(MY_DEF_HERE)
static void m88e3310_copper_read_status(struct phy_device *phydev)
{
	int adv;
	int lpa;
	int status = 0;

	if (phydev->autoneg == AUTONEG_ENABLE) {
		status = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_COPPER_SPEC_SR));

		lpa = phy_read(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_COPPER_LP));

		adv = phy_read(phydev, MV_XMDIO(MDIO_MMD_AN, MII_88E3310_COPPER_ADV));

		phydev->lp_advertising = mii_lpa_to_ethtool_lpa_t(lpa);

		lpa &= adv;

		if (status & MII_M1011_PHY_STATUS_FULLDUPLEX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		status = status & MII_88E3310_PHY_STATUS_SPD_MASK;
		phydev->pause = 0;
		phydev->asym_pause = 0;

		switch (status) {
		case MII_88E3310_PHY_STATUS_10000:
			phydev->speed = SPEED_10000;
			break;

		case MII_88E3310_PHY_STATUS_5000:
			phydev->speed = SPEED_5000;
			break;

		case MII_88E3310_PHY_STATUS_2500:
			phydev->speed = SPEED_2500;
			break;

		case MII_88E3310_PHY_STATUS_1000:
			phydev->speed = SPEED_1000;
			break;

		case MII_88E3310_PHY_STATUS_100:
			phydev->speed = SPEED_100;
			break;

		default:
			phydev->speed = SPEED_10;
			break;
		}

		if (phydev->duplex == DUPLEX_FULL) {
			phydev->pause = lpa & LPA_PAUSE_CAP ? 1 : 0;
			phydev->asym_pause = lpa & LPA_PAUSE_ASYM ? 1 : 0;
		}
	} else {
		int bmcr = phy_read(phydev, MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMCR));

		if (bmcr & BMCR_FULLDPLX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		if (bmcr & BMCR_SPEED1000)
			phydev->speed = SPEED_1000;
		else if (bmcr & BMCR_SPEED100)
			phydev->speed = SPEED_100;
		else
			phydev->speed = SPEED_10;

		phydev->pause = 0;
		phydev->asym_pause = 0;
		phydev->lp_advertising = 0;
	}
}

static void m88e3310_basex_read_status(struct phy_device *phydev)
{
	int adv;
	int lpa;
	int status = 0;

	if (phydev->autoneg == AUTONEG_ENABLE) {
		status = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_SPEC_SR));

		lpa = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_LP));

		adv = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_ADV));

		phydev->lp_advertising = mii_lpa_to_ethtool_lpa_t(lpa);

		lpa &= adv;

		if (status & MII_M1011_PHY_STATUS_FULLDUPLEX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		status = status & MII_M1011_PHY_STATUS_SPD_MASK;
		phydev->pause = 0;
		phydev->asym_pause = 0;

		switch (status) {
		case MII_M1011_PHY_STATUS_1000:
			phydev->speed = SPEED_1000;
			break;

		case MII_M1011_PHY_STATUS_100:
			phydev->speed = SPEED_100;
			break;

		default:
			phydev->speed = SPEED_10;
			break;
		}

		if (phydev->duplex == DUPLEX_FULL) {
			phydev->pause = lpa & LPA_PAUSE_CAP ? 1 : 0;
			phydev->asym_pause = lpa & LPA_PAUSE_ASYM ? 1 : 0;
		}
	} else {
		int bmcr = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_1G_BASEX_FIBER));

		if (bmcr & BMCR_FULLDPLX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		if (bmcr & BMCR_SPEED1000)
			phydev->speed = SPEED_1000;
		else if (bmcr & BMCR_SPEED100)
			phydev->speed = SPEED_100;
		else
			phydev->speed = SPEED_10;

		phydev->pause = 0;
		phydev->asym_pause = 0;
		phydev->lp_advertising = 0;
	}
}

static void m88e3310_baser_read_status(struct phy_device *phydev)
{
	phydev->speed = SPEED_10000;
	phydev->duplex = DUPLEX_FULL;
	phydev->pause = 0;
	phydev->asym_pause = 0;
	phydev->lp_advertising = 0;
	phydev->autoneg = AUTONEG_DISABLE;
	phydev->supported = SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE;
	phydev->advertising = ADVERTISED_10000baseT_Full;
}

static int m88e3310_read_status(struct phy_device *phydev)
{
	int status = 0;

	status = m88e3310_phy_update_link(phydev);

	if (!status)
		return 0;

	if (phydev->dev_flags & COPPER_BASE_T)
		m88e3310_copper_read_status(phydev);
	else if (phydev->dev_flags & FIBER_BASE_R)
		m88e3310_baser_read_status(phydev);
	else if (phydev->dev_flags & FIBER_BASE_X)
		m88e3310_basex_read_status(phydev);

	return 0;
}

#endif  
static int marvell_aneg_done(struct phy_device *phydev)
{
	int retval = phy_read(phydev, MII_M1011_PHY_STATUS);
#if defined(MY_DEF_HERE)

	return (retval < 0) ? retval : (retval & MII_M1011_PHY_STATUS_RESOLVED);
}

static int m88e3310_aneg_done(struct phy_device *phydev)
{
	int retval = 0;

	if (phydev->dev_flags & COPPER_BASE_T)
		retval = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_COPPER_SPEC_SR));
	else if (phydev->dev_flags & FIBER_BASE_R)
		return 1;
	else if (phydev->dev_flags & FIBER_BASE_X)
		retval = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_SPEC_SR));

#endif  
	return (retval < 0) ? retval : (retval & MII_M1011_PHY_STATUS_RESOLVED);
}

static int m88e1121_did_interrupt(struct phy_device *phydev)
{
	int imask;

	imask = phy_read(phydev, MII_M1011_IEVENT);

	if (imask & MII_M1011_IMASK_INIT)
		return 1;

	return 0;
}

#if defined(MY_DEF_HERE)
static int m88e3310_did_interrupt(struct phy_device *phydev)
{
	int imask;

	if (phydev->dev_flags & COPPER_BASE_T) {
		imask = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_COPPER_INT_ST));

		if (imask & MII_88E3310_COPPER_IMASK_INIT)
			return 1;

	} else if (phydev->dev_flags & FIBER_BASE_R) {
		imask = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASER_INT_ST));

		if (imask & MII_88E3310_BASER_IMASK_INIT)
			return 1;

	} else if (phydev->dev_flags & FIBER_BASE_X) {
		imask = phy_read(phydev, MV_XMDIO(MDIO_MMD_PCS, MII_88E3310_BASEX_INT_ST));

		if (imask & MII_88E3310_BASEX_IMASK_INIT)
			return 1;
	}

	return 0;
}

#endif  
static void m88e1318_get_wol(struct phy_device *phydev, struct ethtool_wolinfo *wol)
{
	wol->supported = WAKE_MAGIC;
	wol->wolopts = 0;

	if (phy_write(phydev, MII_MARVELL_PHY_PAGE,
		      MII_88E1318S_PHY_WOL_PAGE) < 0)
		return;

	if (phy_read(phydev, MII_88E1318S_PHY_WOL_CTRL) &
	    MII_88E1318S_PHY_WOL_CTRL_MAGIC_PACKET_MATCH_ENABLE)
		wol->wolopts |= WAKE_MAGIC;

	if (phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x00) < 0)
		return;
}

static int m88e1318_set_wol(struct phy_device *phydev, struct ethtool_wolinfo *wol)
{
	int err, oldpage, temp;

	oldpage = phy_read(phydev, MII_MARVELL_PHY_PAGE);

	if (wol->wolopts & WAKE_MAGIC) {
		 
		err = phy_write(phydev, MII_MARVELL_PHY_PAGE, 0x00);
		if (err < 0)
			return err;

		temp = phy_read(phydev, MII_88E1318S_PHY_CSIER);
		temp |= MII_88E1318S_PHY_CSIER_WOL_EIE;
		err = phy_write(phydev, MII_88E1318S_PHY_CSIER, temp);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_MARVELL_PHY_PAGE,
				MII_88E1318S_PHY_LED_PAGE);
		if (err < 0)
			return err;

		temp = phy_read(phydev, MII_88E1318S_PHY_LED_TCR);
		temp &= ~MII_88E1318S_PHY_LED_TCR_FORCE_INT;
#if defined(MY_DEF_HERE)
		temp |= MII_88E1318S_PHY_LED_TCR_INTN_ENABLE;
#else  
		temp |= MII_88E1318S_PHY_LED_TCR_INTn_ENABLE;
#endif  
		temp |= MII_88E1318S_PHY_LED_TCR_INT_ACTIVE_LOW;
		err = phy_write(phydev, MII_88E1318S_PHY_LED_TCR, temp);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_MARVELL_PHY_PAGE,
				MII_88E1318S_PHY_WOL_PAGE);
		if (err < 0)
			return err;

		err = phy_write(phydev, MII_88E1318S_PHY_MAGIC_PACKET_WORD2,
				((phydev->attached_dev->dev_addr[5] << 8) |
				 phydev->attached_dev->dev_addr[4]));
		if (err < 0)
			return err;
		err = phy_write(phydev, MII_88E1318S_PHY_MAGIC_PACKET_WORD1,
				((phydev->attached_dev->dev_addr[3] << 8) |
				 phydev->attached_dev->dev_addr[2]));
		if (err < 0)
			return err;
		err = phy_write(phydev, MII_88E1318S_PHY_MAGIC_PACKET_WORD0,
				((phydev->attached_dev->dev_addr[1] << 8) |
				 phydev->attached_dev->dev_addr[0]));
		if (err < 0)
			return err;

		temp = phy_read(phydev, MII_88E1318S_PHY_WOL_CTRL);
		temp |= MII_88E1318S_PHY_WOL_CTRL_CLEAR_WOL_STATUS;
		temp |= MII_88E1318S_PHY_WOL_CTRL_MAGIC_PACKET_MATCH_ENABLE;
		err = phy_write(phydev, MII_88E1318S_PHY_WOL_CTRL, temp);
		if (err < 0)
			return err;
	} else {
		err = phy_write(phydev, MII_MARVELL_PHY_PAGE,
				MII_88E1318S_PHY_WOL_PAGE);
		if (err < 0)
			return err;

		temp = phy_read(phydev, MII_88E1318S_PHY_WOL_CTRL);
		temp |= MII_88E1318S_PHY_WOL_CTRL_CLEAR_WOL_STATUS;
		temp &= ~MII_88E1318S_PHY_WOL_CTRL_MAGIC_PACKET_MATCH_ENABLE;
		err = phy_write(phydev, MII_88E1318S_PHY_WOL_CTRL, temp);
		if (err < 0)
			return err;
	}

	err = phy_write(phydev, MII_MARVELL_PHY_PAGE, oldpage);
	if (err < 0)
		return err;

	return 0;
}

#if defined(MY_DEF_HERE)
static int marvell_get_sset_count(struct phy_device *phydev)
{
	return ARRAY_SIZE(marvell_hw_stats);
}

static void marvell_get_strings(struct phy_device *phydev, u8 *data)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(marvell_hw_stats); i++) {
		memcpy(data + i * ETH_GSTRING_LEN,
		       marvell_hw_stats[i].string, ETH_GSTRING_LEN);
	}
}

#if defined(MY_DEF_HERE)
int m88e3310_suspend(struct phy_device *phydev)
{
	int value;

	mutex_lock(&phydev->lock);

	if (phydev->dev_flags & COPPER_BASE_T) {
		value = phy_read(phydev,  MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMCR));
		phy_write(phydev,  MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMCR), value | BMCR_PDOWN);

	} else if (phydev->dev_flags & FIBER_BASE_R) {
		value = phy_read(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_10G_BASER_FIBER)));
		phy_write(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_10G_BASER_FIBER)),
			  value | BMCR_PDOWN);

	} else if (phydev->dev_flags & FIBER_BASE_X) {
		value = phy_read(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_1G_BASEX_FIBER)));
		phy_write(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_1G_BASEX_FIBER)),
			  value | BMCR_PDOWN);
	}

	mutex_unlock(&phydev->lock);

	return 0;
}

int m88e3310_resume(struct phy_device *phydev)
{
	int value;

	mutex_lock(&phydev->lock);

	if (phydev->dev_flags & COPPER_BASE_T) {
		value = phy_read(phydev,  MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMCR));
		phy_write(phydev,  MV_XMDIO(MDIO_MMD_PMAPMD, MII_BMCR), value & ~BMCR_PDOWN);

	} else if (phydev->dev_flags & FIBER_BASE_R) {
		value = phy_read(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_10G_BASER_FIBER)));
		phy_write(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_10G_BASER_FIBER)),
			  value & ~BMCR_PDOWN);

	} else if (phydev->dev_flags & FIBER_BASE_X) {
		value = phy_read(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_1G_BASEX_FIBER)));
		phy_write(phydev,  MV_XMDIO(MDIO_MMD_PCS, (MII_BMCR + MII_88E3310_1G_BASEX_FIBER)),
			  value & ~BMCR_PDOWN);
	}

	mutex_unlock(&phydev->lock);

	return 0;
}

int m88e3310_soft_reset(struct phy_device *phydev)
{
	 
	return 0;
}

#endif  
#if defined(MY_DEF_HERE)
static int m88e2110_ack_interrupt(struct phy_device *phydev)
{
	int err;

	err = phy_read_mmd(phydev, MDIO_MMD_PCS, MII_88E2110_ISTATUS);

	if (err < 0)
		return err;

	return 0;
}

static int m88e2110_config_aneg(struct phy_device *phydev)
{
	struct device_node *node = phydev->mdio.dev.of_node;
	u32 max_speed;
	int reg, change = 0;

	if (!of_property_read_u32(node, "max-speed", &max_speed)) {
		reg = phy_read_mmd(phydev, MDIO_MMD_AN,
				   MII_88E2110_MGBASET_AN_CTRL1);
		switch (max_speed) {
		case SPEED_5000:
			 
			if (reg != MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_5000) {
				phy_write_mmd(phydev, MDIO_MMD_AN,
					      MII_88E2110_MGBASET_AN_CTRL1,
					      MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_5000);
				change = 1;
			}
			break;
		case SPEED_2500:
			 
			if (reg != MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_2500) {
				phy_write_mmd(phydev, MDIO_MMD_AN,
					      MII_88E2110_MGBASET_AN_CTRL1,
					      MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_2500);
				change = 1;
			}
			break;
		default:
			 
			if (reg != MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_1000) {
				phy_write_mmd(phydev, MDIO_MMD_AN,
					      MII_88E2110_MGBASET_AN_CTRL1,
					      MII_88E2110_MGBASET_AN_CTRL1_ADVERTISE_1000);
				change = 1;
			}
			break;
		}
	}

	if (change)
		phy_write_mmd(phydev, MDIO_MMD_AN, MII_88E2110_AN_CTRL,
			      MII_88E2110_AN_CTRL_EXT_NP_CTRL |
			      MII_88E2110_AN_CTRL_AN_EN |
			      MII_88E2110_AN_CTRL_RESTART_AN);

	return 0;
}

static int m88e2110_config_init(struct phy_device *phydev)
{
	return marvell_c45_config_init(phydev);
}

static int m88e2110_config_intr(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_write_mmd(phydev, MDIO_MMD_PCS, MII_88E2110_IMASK,
				    MII_88E2110_IMASK_INIT);
	else
		err = phy_write_mmd(phydev, MDIO_MMD_PCS, MII_88E2110_IMASK,
				    MII_88E2110_IMASK_CLEAR);

	return err;
}

static int m88e2110_read_status(struct phy_device *phydev)
{
	int adv, lpa, lpagb, status;

	status = phy_read_mmd(phydev, MDIO_MMD_PCS, MII_88E2110_PHY_STATUS);
	if (status < 0)
		return status;

	if (!(status & MII_88E2110_PHY_STATUS_LINK)) {
		phydev->link = 0;
		return 0;
	}

	phydev->link = 1;
	if (status & MII_88E2110_PHY_STATUS_DUPLEX)
		phydev->duplex = DUPLEX_FULL;
	else
		phydev->duplex = DUPLEX_HALF;

	phydev->pause = 0;
	phydev->asym_pause = 0;

	switch (status & MII_88E2110_PHY_STATUS_SPD_MASK) {
	case MII_88E2110_PHY_STATUS_5000:
		phydev->speed = SPEED_5000;
		break;
	case MII_88E2110_PHY_STATUS_2500:
		phydev->speed = SPEED_2500;
		break;
	case MII_88E2110_PHY_STATUS_1000:
		phydev->speed = SPEED_1000;
		break;
	case MII_88E2110_PHY_STATUS_100:
		phydev->speed = SPEED_100;
		break;
	default:
		phydev->speed = SPEED_10;
		break;
	}

	if (phydev->autoneg == AUTONEG_ENABLE) {
		lpa = phy_read_mmd(phydev, MDIO_MMD_AN, MII_88E2110_LPA);
		if (lpa < 0)
			return lpa;

		lpagb = phy_read_mmd(phydev, MDIO_MMD_AN, MII_88E2110_STAT1000);
		if (lpagb < 0)
			return lpagb;

		adv = phy_read_mmd(phydev, MDIO_MMD_AN, MII_88E2110_ADVERTISE);
		if (adv < 0)
			return adv;

		phydev->lp_advertising = mii_stat1000_to_ethtool_lpa_t(lpagb) |
					 mii_lpa_to_ethtool_lpa_t(lpa);

		lpa &= adv;

		if (phydev->duplex == DUPLEX_FULL) {
			phydev->pause = lpa & LPA_PAUSE_CAP ? 1 : 0;
			phydev->asym_pause = lpa & LPA_PAUSE_ASYM ? 1 : 0;
		}
	} else {
		phydev->lp_advertising = 0;
	}

	return 0;
}

static int m88e2110_aneg_done(struct phy_device *phydev)
{
	int retval;

	retval = phy_read_mmd(phydev, MDIO_MMD_PCS, MII_88E2110_PHY_STATUS);

	return ((retval < 0) ? retval : (retval & MII_88E2110_PHY_STATUS_SPDDONE));
}

static int m88e2110_did_interrupt(struct phy_device *phydev)
{
	int imask;

	imask = phy_read_mmd(phydev, MDIO_MMD_PCS, MII_88E2110_ISTATUS);

	if (imask & MII_88E2110_IMASK_INIT)
		return 1;

	return 0;
}

static int m88e2110_soft_reset(struct phy_device *phydev)
{
	 
	return 0;
}

#endif  
#ifndef UINT64_MAX
#define UINT64_MAX              (u64)(~((u64)0))
#endif
static u64 marvell_get_stat(struct phy_device *phydev, int i)
{
	struct marvell_hw_stat stat = marvell_hw_stats[i];
	struct marvell_priv *priv = phydev->priv;
	int err, oldpage, val;
	u64 ret;

	oldpage = phy_read(phydev, MII_MARVELL_PHY_PAGE);
	err = phy_write(phydev, MII_MARVELL_PHY_PAGE,
			stat.page);
	if (err < 0)
		return UINT64_MAX;

	val = phy_read(phydev, stat.reg);
	if (val < 0) {
		ret = UINT64_MAX;
	} else {
		val = val & ((1 << stat.bits) - 1);
		priv->stats[i] += val;
		ret = priv->stats[i];
	}

	phy_write(phydev, MII_MARVELL_PHY_PAGE, oldpage);

	return ret;
}

static void marvell_get_stats(struct phy_device *phydev,
			      struct ethtool_stats *stats, u64 *data)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(marvell_hw_stats); i++)
		data[i] = marvell_get_stat(phydev, i);
}

static int marvell_probe(struct phy_device *phydev)
{
	struct marvell_priv *priv;

	priv = devm_kzalloc(&phydev->mdio.dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	phydev->priv = priv;

	return 0;
}
#endif  

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
static int m88e1112_config_advert(struct phy_device *phydev)
{
	u32 advertise;
	int oldadv, adv, bmsr;
	int err, changed = 0;

	phydev->advertising &= phydev->supported;
	advertise = phydev->advertising;

	adv = phy_read(phydev, MII_ADVERTISE);
	oldadv = adv;

	if (phydev->dev_flags & FIBER_BASE_R) {
		adv &= ~(ADVERTISE_1000XFULL | ADVERTISE_1000XHALF | ADVERTISE_1000XPAUSE | ADVERTISE_1000XPSE_ASYM);
		adv |= ethtool_adv_to_mii_adv_x(advertise);
	} else {
		adv &= ~(ADVERTISE_ALL | ADVERTISE_100BASE4 | ADVERTISE_PAUSE_CAP |
				 ADVERTISE_PAUSE_ASYM);
		adv |= ethtool_adv_to_mii_adv_t(advertise);
	}

	if (adv != oldadv) {
		phy_write(phydev, MII_ADVERTISE, adv);
		changed = 1;
	}

	if (!(phydev->dev_flags & FIBER_BASE_R)) {
		bmsr = phy_read(phydev, MII_BMSR);

		if (!(bmsr & BMSR_ESTATEN))
			return changed;

	    adv = phy_read(phydev, MII_CTRL1000);

	    oldadv = adv;
	    adv &= ~(ADVERTISE_1000FULL | ADVERTISE_1000HALF);

		if (phydev->supported & (SUPPORTED_1000baseT_Half | SUPPORTED_1000baseT_Full))
			adv |= ethtool_adv_to_mii_ctrl1000_t(advertise);

		if (adv != oldadv)
			changed = 1;

	    err = phy_write(phydev, MII_CTRL1000, adv);
	}

	return changed;
}

int m88e1112_control_aneg(struct phy_device *phydev)
{
	int result;

	if (phydev->autoneg != AUTONEG_ENABLE)
		return genphy_setup_forced(phydev);

	result = m88e1112_config_advert(phydev);

	if (result == 0) {
		 
		int ctl = phy_read(phydev, MII_BMCR);

		if (!(ctl & BMCR_ANENABLE) || (ctl & BMCR_ISOLATE))
			result = 1;  
	}

	if (result > 0)
		result = genphy_restart_aneg(phydev);

	return result;
}

static int m88e1112_config_aneg(struct phy_device *phydev)
{
	int err;

	if (phydev->dev_flags & FIBER_BASE_R)
		err = phy_write(phydev, MII_MARVELL_PHY_PAGE, FIBER_PAGE);
	else
		err = phy_write(phydev, MII_MARVELL_PHY_PAGE, COPPER_PAGE);

	err = phy_write(phydev, MII_BMCR, BMCR_RESET);

	if (!(phydev->dev_flags & FIBER_BASE_R)) {
		err = marvell_set_polarity(phydev, phydev->mdix);
		if (err < 0)
			return err;
	}

	m88e1112_control_aneg(phydev);

	if (phydev->autoneg != AUTONEG_ENABLE) {
		int bmcr;

		bmcr = phy_read(phydev, MII_BMCR);

		phy_write(phydev, MII_BMCR, bmcr | BMCR_RESET);
	}

	return 0;
}

#endif  
static int m88e1112_read_status(struct phy_device *phydev)
{
#if defined(MY_DEF_HERE)
	int adv;
	int err;
	int lpa;
	int lpagb = 0;
	int common_adv;
	int common_adv_gb = 0;
	int combo_mode, val;

	err = genphy_update_link(phydev);
	if (err)
		return err;

	combo_mode = phy_read(phydev, MII_M1112_SPEC_STAT_REG);

	if (phydev->dev_flags & FIBER_BASE_R) {
		if (!(combo_mode & MII_M1112_FIBER_COPPER_RES)) {
			phydev->dev_flags &= ~FIBER_BASE_R;
			m88e1112_config_aneg(phydev);
		}
	} else {
		if (combo_mode & MII_M1112_FIBER_COPPER_RES) {
			phydev->dev_flags |= FIBER_BASE_R;
			m88e1112_config_aneg(phydev);
#else  
	int val, bmcr;

	if ((phydev->autoneg != AUTONEG_ENABLE) & (phydev->speed == SPEED_10)) {
		val = phy_read(phydev, MII_M1011_IEVENT);
		 
		if (val & MII_M1112_PHY_ENERGY_STATE) {
			bmcr = phy_read(phydev, MII_BMCR);
			phy_write(phydev, MII_BMCR, bmcr | BMCR_RESET);
#endif  
		}
	}
#if defined(MY_DEF_HERE)
	phydev->lp_advertising = 0;

	if (phydev->autoneg == AUTONEG_ENABLE) {
		if (phydev->dev_flags & FIBER_BASE_R) {
			lpa = phy_read(phydev, MII_LPA);

			phydev->lp_advertising |= mii_lpa_to_ethtool_lpa_x(lpa);

			adv = phy_read(phydev, MII_ADVERTISE);

			common_adv = lpa & adv;

			phydev->speed = SPEED_10;
			phydev->duplex = DUPLEX_HALF;
			phydev->pause = 1;
			phydev->asym_pause = 1;

			if (common_adv & (LPA_1000FULL | LPA_1000HALF)) {
				phydev->speed = SPEED_1000;

				if (common_adv & LPA_1000FULL)
					phydev->duplex = DUPLEX_FULL;
		   }

			if (phydev->duplex == DUPLEX_FULL) {
				phydev->pause = lpa & LPA_1000XPAUSE ? 1 : 0;
				phydev->asym_pause = lpa & LPA_1000XPAUSE_ASYM ? 1 : 0;
			}
		} else {
			if (phydev->supported & (SUPPORTED_1000baseT_Half
					   | SUPPORTED_1000baseT_Full)) {
				lpagb = phy_read(phydev, MII_STAT1000);
#endif  

#if defined(MY_DEF_HERE)
				adv = phy_read(phydev, MII_CTRL1000);

				phydev->lp_advertising = mii_stat1000_to_ethtool_lpa_t(lpagb);
				common_adv_gb = lpagb & adv << 2;
			}

			lpa = phy_read(phydev, MII_LPA);
			phydev->lp_advertising |= mii_lpa_to_ethtool_lpa_t(lpa);
			adv = phy_read(phydev, MII_ADVERTISE);
			common_adv = lpa & adv;

			phydev->speed = SPEED_10;
			phydev->duplex = DUPLEX_HALF;
			phydev->pause = 0;
			phydev->asym_pause = 0;

			if (common_adv_gb & (LPA_1000FULL | LPA_1000HALF)) {
				phydev->speed = SPEED_1000;

				if (common_adv_gb & LPA_1000FULL)
					phydev->duplex = DUPLEX_FULL;
			} else if (common_adv & (LPA_100FULL | LPA_100HALF)) {
				phydev->speed = SPEED_100;

				if (common_adv & LPA_100FULL)
					phydev->duplex = DUPLEX_FULL;
			} else {
				if (common_adv & LPA_10FULL)
					phydev->duplex = DUPLEX_FULL;
			}

			if (phydev->duplex == DUPLEX_FULL) {
				phydev->pause = lpa & LPA_PAUSE_CAP ? 1 : 0;
				phydev->asym_pause = lpa & LPA_PAUSE_ASYM ? 1 : 0;
			}
		}
	} else {
		int bmcr = phy_read(phydev, MII_BMCR);

		if (bmcr & BMCR_FULLDPLX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		if (bmcr & BMCR_SPEED1000) {
			phydev->speed = SPEED_1000;
		} else if (bmcr & BMCR_SPEED100) {
			phydev->speed = SPEED_100;
		} else {
			phydev->speed = SPEED_10;
			val = phy_read(phydev, MII_M1011_IEVENT);
			if ((val & MII_M1112_PHY_ENERGY_STATE) || (val & MII_M1112_PHY_COPPER_STATE)) {
				bmcr = phy_read(phydev, MII_BMCR);
				phy_write(phydev, MII_BMCR, bmcr | BMCR_RESET);
			}
		}
		phydev->pause = 0;
		phydev->asym_pause = 0;
	}

	return 0;
#else  
	return genphy_read_status(phydev);
#endif  
}

#endif  
static struct phy_driver marvell_drivers[] = {
	{
		.phy_id = MARVELL_PHY_ID_88E1101,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1101",
		.features = PHY_GBIT_FEATURES,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.config_init = &marvell_config_init,
#endif  
		.config_aneg = &marvell_config_aneg,
		.read_status = &genphy_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1112,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1112",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_init = &m88e1111_config_init,
#if defined(MY_DEF_HERE)
		.config_aneg = &m88e1112_config_aneg,
		.aneg_done = &marvell_aneg_done,
#else  
		.config_aneg = &marvell_config_aneg,
#endif  
#if defined(MY_DEF_HERE)
		.read_status = &m88e1112_read_status,
#else  
		.read_status = &genphy_read_status,
#endif  
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1111,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1111",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_init = &m88e1111_config_init,
		.config_aneg = &marvell_config_aneg,
		.read_status = &marvell_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1118,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1118",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_init = &m88e1118_config_init,
		.config_aneg = &m88e1118_config_aneg,
		.read_status = &genphy_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = {.owner = THIS_MODULE,},
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1121R,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1121R",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
		.config_init = &marvell_config_init,
#endif  
		.config_aneg = &m88e1121_config_aneg,
		.read_status = &marvell_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.did_interrupt = &m88e1121_did_interrupt,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1318S,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1318S",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
		.config_init = &marvell_config_init,
#endif  
		.config_aneg = &m88e1318_config_aneg,
		.read_status = &marvell_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.did_interrupt = &m88e1121_did_interrupt,
		.get_wol = &m88e1318_get_wol,
		.set_wol = &m88e1318_set_wol,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1145,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1145",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_init = &m88e1145_config_init,
		.config_aneg = &marvell_config_aneg,
		.read_status = &genphy_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1149R,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1149R",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_init = &m88e1149_config_init,
		.config_aneg = &m88e1118_config_aneg,
		.read_status = &genphy_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1240,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1240",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_init = &m88e1111_config_init,
		.config_aneg = &marvell_config_aneg,
		.read_status = &genphy_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1116R,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1116R",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_init = &m88e1116r_config_init,
		.config_aneg = &genphy_config_aneg,
		.read_status = &genphy_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1510,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1510",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.config_init = &m88e1510_config_init,
#endif  
		.config_aneg = &m88e1510_config_aneg,
		.read_status = &marvell_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.did_interrupt = &m88e1121_did_interrupt,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
 
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E1540,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E1540",
		.features = PHY_GBIT_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
		.config_init = &marvell_config_init,
		.config_init = &marvell_config_init,
#endif  
		.config_aneg = &m88e1510_config_aneg,
		.read_status = &marvell_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.did_interrupt = &m88e1121_did_interrupt,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
	{
		.phy_id = MARVELL_PHY_ID_88E3016,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E3016",
		.features = PHY_BASIC_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
#if defined(MY_DEF_HERE)
		.probe = marvell_probe,
#endif  
		.config_aneg = &genphy_config_aneg,
		.config_init = &m88e3016_config_init,
		.aneg_done = &marvell_aneg_done,
		.read_status = &marvell_read_status,
		.ack_interrupt = &marvell_ack_interrupt,
		.config_intr = &marvell_config_intr,
		.did_interrupt = &m88e1121_did_interrupt,
		.resume = &genphy_resume,
		.suspend = &genphy_suspend,
#if defined(MY_DEF_HERE)
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
#else  
		.driver = { .owner = THIS_MODULE },
#endif  
	},
#if defined(MY_DEF_HERE)
	{
		.phy_id = MARVELL_PHY_ID_88E3310,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E3310",
		.features = PHY_BASIC_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
		.probe = marvell_probe,
		.config_aneg = &m88e3310_config_aneg,
		.soft_reset = &m88e3310_soft_reset,
		.config_init = &m88e3310_config_init,
		.aneg_done = &m88e3310_aneg_done,
		.read_status = &m88e3310_read_status,
		.ack_interrupt = &m88e3310_ack_interrupt,
		.config_intr = &m88e3310_config_intr,
		.did_interrupt = &m88e3310_did_interrupt,
		.resume = &m88e3310_resume,
		.suspend = &m88e3310_suspend,
		.get_sset_count = marvell_get_sset_count,
		.get_strings = marvell_get_strings,
		.get_stats = marvell_get_stats,
	},
#endif  
#if defined(MY_DEF_HERE)
	{
		.phy_id = MARVELL_PHY_ID_88E2110,
		.phy_id_mask = MARVELL_PHY_ID_MASK,
		.name = "Marvell 88E2110",
		.features = PHY_BASIC_FEATURES,
		.flags = PHY_HAS_INTERRUPT,
		.probe = marvell_probe,
		.config_aneg = &m88e2110_config_aneg,
		.config_init = &m88e2110_config_init,
		.aneg_done = &m88e2110_aneg_done,
		.read_status = &m88e2110_read_status,
		.ack_interrupt = &m88e2110_ack_interrupt,
		.config_intr = &m88e2110_config_intr,
		.did_interrupt = &m88e2110_did_interrupt,
		.soft_reset = &m88e2110_soft_reset,
	},
#endif  
};

module_phy_driver(marvell_drivers);

static struct mdio_device_id __maybe_unused marvell_tbl[] = {
	{ MARVELL_PHY_ID_88E1101, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1112, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1111, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1118, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1121R, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1145, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1149R, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1240, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1318S, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1116R, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1510, MARVELL_PHY_ID_MASK },
	{ MARVELL_PHY_ID_88E1540, MARVELL_PHY_ID_MASK },
#if defined(MY_DEF_HERE)
	{ MARVELL_PHY_ID_88E2110, MARVELL_PHY_ID_MASK },
#endif  
	{ MARVELL_PHY_ID_88E3016, MARVELL_PHY_ID_MASK },
#if defined(MY_DEF_HERE)
	{ MARVELL_PHY_ID_88E3310, MARVELL_PHY_ID_MASK },
#endif  
	{ }
};

MODULE_DEVICE_TABLE(mdio, marvell_tbl);
