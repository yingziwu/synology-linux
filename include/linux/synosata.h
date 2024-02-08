#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __SYNO_SATA_H_
#define __SYNO_SATA_H_

#include <linux/kernel.h>
#include <linux/synobios.h>

#if defined(MY_ABC_HERE) && defined(__KERNEL__)
extern long g_internal_hd_num;
extern long syno_boot_hd_count;

static inline void SleepForLatency(void)
{
	mdelay(3000);
}

static inline void SleepForHD(int i)
{
	if ((syno_boot_hd_count != g_internal_hd_num - 1) &&  
		(( g_internal_hd_num < 0 ) ||  
		  syno_boot_hd_count < g_internal_hd_num) ) {
		printk("Delay 10 seconds to wait for disk %d ready.\n", i);
		mdelay(10000);
	}
	syno_boot_hd_count++;
}

static inline void SleepForHDAdditional(void)
{
	if (g_internal_hd_num != 0){
		mdelay(5000);
	}
}

static inline void SleepForHW(int iDisk, int iIsDoLatency)
{
		 
	if (syno_boot_hd_count &&
		(( g_internal_hd_num < 0 ) ||  
		  syno_boot_hd_count < g_internal_hd_num) ) {
		if (iIsDoLatency) {
			printk("Delay 5 seconds to wait for disk %d ready.\n", iDisk);
			mdelay(5000);
		} else {
			printk("Delay 7 seconds to wait for disk %d ready.\n", iDisk);
			mdelay(7000);
		}
	}
	syno_boot_hd_count++;
}
#endif  

#ifdef MY_ABC_HERE
#include <linux/fs.h>

#define GPIO_3XXX_CMD_POWER_CTL 0x40
#define GPIO_3XXX_CMD_POWER_CLR 0x00

#define GPI_3XXX_PSU_OFF(x)		(0x2&x)
#define GPI_3XXX_HDD_PWR_OFF(x)		(0x10&x)

#define GPIO_3826_CMD_ENABLE_POWERBTN	(0 << 15)
 
static inline char
*DeviceNameGet(const int index, char *szBuf)
{	
	if (index < 26) {
		sprintf(szBuf, "sd%c", 'a' + index % 26);
	} else if (index < (26 + 1) * 26) {
		sprintf(szBuf, "sd%c%c",
			'a' + index / 26 - 1,'a' + index % 26);
	} else {
		const unsigned int m1 = (index / 26 - 1) / 26 - 1;
		const unsigned int m2 = (index / 26 - 1) % 26;
		const unsigned int m3 =  index % 26;
		sprintf(szBuf, "sd%c%c%c",
			'a' + m1, 'a' + m2, 'a' + m3);
	}

	return szBuf;
}

typedef struct _tag_SYNO_PM_PKG {
	 
	unsigned int	var;

	int	gpio_addr;

	void (*encode)(struct _tag_SYNO_PM_PKG *pm_pkg, int rw);

	void (*decode)(struct _tag_SYNO_PM_PKG *pm_pkg, int rw);
} SYNO_PM_PKG;

static inline void 
SIMG3xxx_gpio_decode(SYNO_PM_PKG *pPM_pkg, int rw)
{
#define GPI_3XXX_BIT1(GPIO)	(1&GPIO)
#define GPI_3XXX_BIT2(GPIO)	((1<<1)&GPIO)
#define GPI_3XXX_BIT3(GPIO)	((1<<13)&GPIO)>>11
#define GPI_3XXX_BIT4(GPIO)	((1<<26)&GPIO)>>23
#define GPI_3XXX_BIT5(GPIO)	((1<<28)&GPIO)>>24
#define GPI_3XXX_BIT6(GPIO)	((1<<29)&GPIO)>>24
#define GPI_3XXX_BIT7(GPIO)	((1<<31)&GPIO)>>25

	if (!rw) {
		pPM_pkg->var = 
			GPI_3XXX_BIT1(pPM_pkg->var)|
			GPI_3XXX_BIT2(pPM_pkg->var)|
			GPI_3XXX_BIT3(pPM_pkg->var)|
			GPI_3XXX_BIT4(pPM_pkg->var)|
			GPI_3XXX_BIT5(pPM_pkg->var)|
			GPI_3XXX_BIT6(pPM_pkg->var)|
			GPI_3XXX_BIT7(pPM_pkg->var);
	}
}
 
static inline void 
SIMG3xxx_gpio_encode(SYNO_PM_PKG *pPM_pkg, int rw)
{
#define GPIO_3XXX_BIT00(GPO)	(1&GPO)
#define GPIO_3XXX_BIT01(GPO)	((1<<1)&GPO)
#define GPIO_3XXX_BIT10(GPO)	((1<<2)&GPO)<<8
#define GPIO_3XXX_BIT11(GPO)	((1<<3)&GPO)<<8
#define GPIO_3XXX_BIT12(GPO)	((1<<4)&GPO)<<8
#define GPIO_3XXX_BIT13(GPO)	((1<<5)&GPO)<<8
#define GPIO_3XXX_BIT14(GPO)	((1<<6)&GPO)<<8
#define GPIO_3XXX_BIT15(GPO)	((1<<7)&GPO)<<8
#define GPIO_3XXX_BIT16(GPO)	((1<<8)&GPO)<<8
#define GPIO_3XXX_BIT17(GPO)	((1<<9)&GPO)<<8
#define GPIO_3XXX_BIT18(GPO)	((1<<10)&GPO)<<8
#define GPIO_3XXX_BIT19(GPO)	((1<<11)&GPO)<<8
#define GPIO_3XXX_BIT20(GPO)	((1<<12)&GPO)<<8
#define GPIO_3XXX_BIT21(GPO)	((1<<13)&GPO)<<8
#define GPIO_3XXX_BIT30(GPO)	((1<<14)&GPO)<<16
#define GPIO_3XXX_BIT31(GPO)	((1<<15)&GPO)<<16

	if (rw) {
		pPM_pkg->var = 
			GPIO_3XXX_BIT00(pPM_pkg->var)|
			GPIO_3XXX_BIT01(pPM_pkg->var)|
			GPIO_3XXX_BIT10(pPM_pkg->var)|
			GPIO_3XXX_BIT11(pPM_pkg->var)|
			GPIO_3XXX_BIT12(pPM_pkg->var)|
			GPIO_3XXX_BIT13(pPM_pkg->var)|
			GPIO_3XXX_BIT14(pPM_pkg->var)|
			GPIO_3XXX_BIT15(pPM_pkg->var)|
			GPIO_3XXX_BIT16(pPM_pkg->var)|
			GPIO_3XXX_BIT17(pPM_pkg->var)|
			GPIO_3XXX_BIT18(pPM_pkg->var)|
			GPIO_3XXX_BIT19(pPM_pkg->var)|
			GPIO_3XXX_BIT20(pPM_pkg->var)|
			GPIO_3XXX_BIT21(pPM_pkg->var)|
			GPIO_3XXX_BIT30(pPM_pkg->var)|
			GPIO_3XXX_BIT31(pPM_pkg->var);
	}
}

static inline unsigned char 
syno_pm_is_3726(unsigned short vendor, unsigned short devid)
{
	return (vendor == 0x1095 && devid == 0x3726);
}

static inline unsigned char 
syno_pm_is_3826(unsigned short vendor, unsigned short devid)
{
	return (vendor == 0x1095 && devid == 0x3826);
}

static inline unsigned char 
syno_pm_is_3xxx(unsigned short vendor, unsigned short devid)
{
	return (syno_pm_is_3726(vendor, devid) || syno_pm_is_3826(vendor, devid));
}

static inline void
syno_pm_systemstate_pkg_init(unsigned short vendor, unsigned short devid, SYNO_PM_PKG *pPKG)
{
	 
	memset(pPKG, 0, sizeof(*pPKG));
	if (syno_pm_is_3xxx(vendor, devid)) {
		pPKG->var = 0x200;
	}

}

static inline void 
syno_pm_unique_pkg_init(unsigned short vendor, unsigned short devid, SYNO_PM_PKG *pPKG)
{
	 
	memset(pPKG, 0, sizeof(*pPKG));
	if (syno_pm_is_3xxx(vendor, devid)) {
		pPKG->var = 0x100;
	}

}

static inline void 
syno_pm_raidledstate_pkg_init(unsigned short vendor, unsigned short devid, SYNO_PM_PKG *pPKG)
{
	 
	memset(pPKG, 0, sizeof(*pPKG));
	if (syno_pm_is_3xxx(vendor, devid)) {
		pPKG->var = 0x280;
	}

}

static inline void 
syno_pm_poweron_pkg_init(unsigned short vendor, unsigned short devid, SYNO_PM_PKG *pPKG, unsigned char blCLR)
{
	 
	memset(pPKG, 0, sizeof(*pPKG));
	if (syno_pm_is_3xxx(vendor, devid)) {
		if (blCLR) {
			pPKG->var = GPIO_3XXX_CMD_POWER_CLR;
		} else {
			pPKG->var = GPIO_3XXX_CMD_POWER_CTL;
		}		
	}

}

static inline void 
syno_pm_enable_powerbtn_pkg_init(unsigned short vendor, unsigned short devid, SYNO_PM_PKG *pPKG)
{
	 
	memset(pPKG, 0, sizeof(*pPKG));
	 
	if (syno_pm_is_3xxx(vendor, devid)) {
		pPKG->var = GPIO_3826_CMD_ENABLE_POWERBTN;
	}

}

static inline unsigned char
syno_pm_is_poweron(unsigned short vendor, unsigned short devid, SYNO_PM_PKG *pPKG)
{
	unsigned char ret = 0;

	if (!pPKG) {
		goto END;
	}

	if (syno_pm_is_3xxx(vendor, devid)) {
		if (GPI_3XXX_PSU_OFF(pPKG->var)) {
			goto END;
		}
	}

	ret = 1;
END:
	return ret;
}

static inline unsigned int
syno_support_disk_num(unsigned short vendor, 
					  unsigned short devid, 
					  unsigned int syno_uniq)
{
	unsigned int ret = 0;

	if (syno_pm_is_3xxx(vendor, devid)) {
		if (IS_SYNOLOGY_RX4(syno_uniq) || IS_SYNOLOGY_RX415(syno_uniq)) {
			ret = 4;
		} else if (IS_SYNOLOGY_DX5(syno_uniq) || IS_SYNOLOGY_DX513(syno_uniq)) {
			ret = 5;
		} else if (IS_SYNOLOGY_DXC(syno_uniq) || IS_SYNOLOGY_RXC(syno_uniq)) {
			ret = 3;
		} else if (IS_SYNOLOGY_DX213(syno_uniq)) {
			ret = 2;
		} else {
			printk("%s not RX4 or DX5", __FUNCTION__);
			ret = 5;
		}
		goto END;
	}

END:
	return ret;
}

#ifdef MY_ABC_HERE
extern EUNIT_PWRON_TYPE (*funcSynoEunitPowerctlType)(void);
#endif
extern char gszSynoHWVersion[16];
static inline unsigned char
is_ebox_support(void)
{
	unsigned char ret = 0;

#ifdef MY_ABC_HERE
	if (funcSynoEunitPowerctlType) {
		if (EUNIT_NOT_SUPPORT == funcSynoEunitPowerctlType()) {
			goto END;
		}
	}
#endif
	 
	ret = 1;
#ifdef MY_ABC_HERE
END:
#endif
	return ret;
}
#endif

#ifdef MY_ABC_HERE

#define SYNO_ATA_ID_MAJOR_VER	 80
#define SYNO_ATA_ID_MINOR_VER	 81
#define SYNO_ATA_ID_COMMAND_SET_1 82
#define SYNO_ATA_ID_COMMAND_SET_2 83
#define SYNO_ATA_ID_CFSSE		 84
#define SYNO_ATA_ID_ROT_SPEED	 217

static inline unsigned int
ata_major_version(const unsigned short *id)
{
	unsigned int mver;

	if (id[SYNO_ATA_ID_MAJOR_VER] == 0xFFFF)
		return 0;

	for (mver = 14; mver >= 1; mver--)
		if (id[SYNO_ATA_ID_MAJOR_VER] & (1 << mver))
			break;
	return mver;
}

static inline int 
syno_ata_id_is_ssd(const unsigned short *id)
{
	int res = 0;
	unsigned int major_id = ata_major_version(id);

	if (7 <= major_id){
		if (id[SYNO_ATA_ID_ROT_SPEED] == 0x01) {
			 
			res = 1;
			goto END;
		}
	}

	if ((id[SYNO_ATA_ID_COMMAND_SET_2]>>14) == 0x01 &&
		!(id[SYNO_ATA_ID_COMMAND_SET_1] & 0x0001)) {
		 
		res = 1;
		goto END;
	}

	if ((id[SYNO_ATA_ID_COMMAND_SET_2]>>14) == 0x01 &&
		(id[SYNO_ATA_ID_COMMAND_SET_1] & 0x0001) &&
		!(id[SYNO_ATA_ID_CFSSE] & 0x1)) {
		res = 1;
		goto END;
	}

END:
	return res;
}
#endif  

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define SZK_PMP_UEVENT "SYNO_PMP_EVENT"
#define SZV_PMP_CONNECT "CABLE_CONNECT"
#define SZV_PMP_DISCONNECT "CABLE_DISCONNECT"
#endif

#endif  
