 
#include <linux/phy.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#define AT803X_INTR_ENABLE			0x12
#define AT803X_INTR_STATUS			0x13
#define AT803X_WOL_ENABLE			0x01
#define AT803X_DEVICE_ADDR			0x03
#define AT803X_LOC_MAC_ADDR_0_15_OFFSET		0x804C
#define AT803X_LOC_MAC_ADDR_16_31_OFFSET	0x804B
#define AT803X_LOC_MAC_ADDR_32_47_OFFSET	0x804A
#define AT803X_MMD_ACCESS_CONTROL		0x0D
#define AT803X_MMD_ACCESS_CONTROL_DATA		0x0E
#define AT803X_FUNC_DATA			0x4003
#define AT803X_DEBUG_ADDR			0x1D
#define AT803X_DEBUG_DATA			0x1E
#define AT803X_DEBUG_SYSTEM_MODE_CTRL		0x05
#define AT803X_DEBUG_RGMII_TX_CLK_DLY		BIT(8)

MODULE_DESCRIPTION("Atheros 803x PHY driver");
MODULE_AUTHOR("Matus Ujhelyi");
MODULE_LICENSE("GPL");

static void at803x_set_wol_mac_addr(struct phy_device *phydev)
{
	struct net_device *ndev = phydev->attached_dev;
	const u8 *mac;
	unsigned int i, offsets[] = {
		AT803X_LOC_MAC_ADDR_32_47_OFFSET,
		AT803X_LOC_MAC_ADDR_16_31_OFFSET,
		AT803X_LOC_MAC_ADDR_0_15_OFFSET,
	};

	if (!ndev)
		return;

	mac = (const u8 *) ndev->dev_addr;

	if (!is_valid_ether_addr(mac))
		return;

	for (i = 0; i < 3; i++) {
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL,
				  AT803X_DEVICE_ADDR);
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL_DATA,
				  offsets[i]);
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL,
				  AT803X_FUNC_DATA);
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL_DATA,
				  mac[(i * 2) + 1] | (mac[(i * 2)] << 8));
	}
}

static int at803x_config_init(struct phy_device *phydev)
{
	int val;
	int ret;
	u32 features;
	int status;

	features = SUPPORTED_TP | SUPPORTED_MII | SUPPORTED_AUI |
		   SUPPORTED_FIBRE | SUPPORTED_BNC;

	val = phy_read(phydev, MII_BMSR);
	if (val < 0)
		return val;

	if (val & BMSR_ANEGCAPABLE)
		features |= SUPPORTED_Autoneg;
	if (val & BMSR_100FULL)
		features |= SUPPORTED_100baseT_Full;
	if (val & BMSR_100HALF)
		features |= SUPPORTED_100baseT_Half;
	if (val & BMSR_10FULL)
		features |= SUPPORTED_10baseT_Full;
	if (val & BMSR_10HALF)
		features |= SUPPORTED_10baseT_Half;

	if (val & BMSR_ESTATEN) {
		val = phy_read(phydev, MII_ESTATUS);
		if (val < 0)
			return val;

		if (val & ESTATUS_1000_TFULL)
			features |= SUPPORTED_1000baseT_Full;
		if (val & ESTATUS_1000_THALF)
			features |= SUPPORTED_1000baseT_Half;
	}

	phydev->supported = features;
	phydev->advertising = features;

#ifdef CONFIG_SYNO_ALPINE_A0
	if (phydev->interface == PHY_INTERFACE_MODE_RGMII_TXID) {
#endif
	ret = phy_write(phydev, AT803X_DEBUG_ADDR,
			AT803X_DEBUG_SYSTEM_MODE_CTRL);
	if (ret)
		return ret;
	ret = phy_write(phydev, AT803X_DEBUG_DATA,
			AT803X_DEBUG_RGMII_TX_CLK_DLY);
	if (ret)
		return ret;
#ifdef CONFIG_SYNO_ALPINE_A0
	}
#endif

	at803x_set_wol_mac_addr(phydev);
	status = phy_write(phydev, AT803X_INTR_ENABLE, AT803X_WOL_ENABLE);
	status = phy_read(phydev, AT803X_INTR_STATUS);

	return 0;
}

static struct phy_driver at803x_driver[] = {
{
	 
	.phy_id		= 0x004dd072,
	.name		= "Atheros 8035 ethernet",
	.phy_id_mask	= 0xffffffef,
	.config_init	= at803x_config_init,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.driver		= {
		.owner = THIS_MODULE,
	},
}, {
	 
	.phy_id		= 0x004dd076,
	.name		= "Atheros 8030 ethernet",
	.phy_id_mask	= 0xffffffef,
	.config_init	= at803x_config_init,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.driver		= {
		.owner = THIS_MODULE,
	},
}, {
	 
	.phy_id		= 0x004dd074,
	.name		= "Atheros 8031 ethernet",
	.phy_id_mask	= 0xffffffef,
	.config_init	= at803x_config_init,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.driver		= {
		.owner = THIS_MODULE,
	},
} };

static int __init atheros_init(void)
{
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(at803x_driver); i++) {
		ret = phy_driver_register(at803x_driver + i);
		if (ret) {
			while (i-- > 0)
				phy_driver_unregister(at803x_driver + i);
				break;
		}
	}

	return ret;
}

static void __exit atheros_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(at803x_driver); i++) {
		phy_driver_unregister(at803x_driver + i);
	}
}

module_init(atheros_init);
module_exit(atheros_exit);

static struct mdio_device_id __maybe_unused atheros_tbl[] = {
	{ 0x004dd076, 0xffffffef },
	{ 0x004dd074, 0xffffffef },
	{ 0x004dd072, 0xffffffef },
	{ }
};

MODULE_DEVICE_TABLE(mdio, atheros_tbl);
