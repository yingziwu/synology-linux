#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// Copyright (c) 2003-2015 Synology Inc. All rights reserved.
#include <linux/kernel.h>
#include <linux/synolib.h>

#ifdef MY_DEF_HERE
extern int setup_early_printk(char *);
extern char gszSynoTtyS0[50];
extern char gszSynoTtyS1[50];
extern char gszSynoTtyS2[50];
#endif /* MY_DEF_HERE */

#ifdef MY_ABC_HERE
#include <linux/syno.h>

extern int grgPwrCtlPin[];
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gszDiskIdxMap[16];
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gszSynoHWRevision[];
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gszSynoHWVersion[];
#endif /* MY_ABC_HERE */

#if defined(MY_ABC_HERE) && !defined(MY_DEF_HERE)
extern long g_syno_hdd_powerup_seq;
#endif /* MY_ABC_HERE && !MY_DEF_HERE*/

#ifdef MY_ABC_HERE
extern long g_hdd_hotplug;
#endif /* MY_ABC_HERE */

#ifdef MY_DEF_HERE
extern long g_smbus_hdd_powerctl;
extern char gSynoSmbusHddType[16];
extern int gSynoSmbusHddAdapter;
extern int gSynoSmbusHddAddress;
#endif /* MY_DEF_HERE */

#ifdef MY_ABC_HERE
extern unsigned char grgbLanMac[SYNO_MAC_MAX_NUMBER][16];
extern int giVenderFormatVersion;
extern char gszSkipVenderMacInterfaces[256];
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gszSerialNum[32];
extern char gszCustomSerialNum[32];
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern int g_syno_sata_remap[SATA_REMAP_MAX];
extern int g_use_sata_remap;
extern int g_syno_mv14xx_remap[SATA_REMAP_MAX];
extern int g_use_mv14xx_remap;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gszPciAddrList[PCI_ADDR_NUM_MAX][PCI_ADDR_LEN_MAX];
extern int gPciAddrNum;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern long g_internal_netif_num;
#endif /* MY_ABC_HERE*/

#ifdef MY_ABC_HERE
extern long g_sata_mv_led;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern int gSynoFactoryUSBFastReset;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern int gSynoFactoryUSB3Disable;
#endif /* MY_ABC_HERE */

#ifdef MY_DEF_HERE
extern long g_is_sas_model;
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
extern int gSynoDualHead;
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
extern int gSynoSASWriteConflictPanic;
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
extern char gSynoSASHBAAddr[CONFIG_SYNO_SAS_MAX_HBA_SLOT][13];
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
extern int gSynoBootSATADOM;
#endif /* MY_DEF_HERE */

#ifdef MY_ABC_HERE
extern char g_ahci_switch;
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gszSataPortMap[8];
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gSynoCastratedXhcAddr[CONFIG_SYNO_USB_NUM_CASTRATED_XHC][32];
extern unsigned int gSynoCastratedXhcPortBitmap[CONFIG_SYNO_USB_NUM_CASTRATED_XHC];
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern char gSynoUsbVbusHostAddr[CONFIG_SYNO_USB_VBUS_NUM_GPIO][20];
extern int gSynoUsbVbusPort[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
extern unsigned gSynoUsbVbusGpp[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
extern unsigned gSynoUsbVbusGppPol[CONFIG_SYNO_USB_VBUS_NUM_GPIO];
#include <linux/synobios.h>
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
extern int giSynoSpinupGroup[SYNO_SPINUP_GROUP_MAX];
extern int giSynoSpinupGroupNum;
extern int giSynoSpinupGroupDelay;
extern int giSynoSpinupGroupDebug;
#endif /* MY_ABC_HERE */

#ifdef MY_DEF_HERE
extern long gIsMultipathModel;
#endif /* MY_DEF_HERE */

#ifdef MY_ABC_HERE
/**
 * This function will parsing "pwrctl_pin" from uboot to get poweron pin
 * ex. "pwrctl_pin=N0910N1034"
 * N0910 means sata id 09 poweron pin is 10
 * N1034 means sata id 10 poweron pin is 34
 */
static int __init early_pwrctl_pin(char *p)
{
       int i = 0;
       int iLen = 0;
       int iCount = 0;
       int iSataID = 0;
       int iPin = 0;
       char szSataID[CONFIG_SYNO_PWRPIN_ENCODE_LEN + 1] = {'\0'};
       char szPin[CONFIG_SYNO_PWRPIN_ENCODE_LEN + 1] = {'\0'};


       // no pwr ctl pin
       if ((NULL == p) || (0 == (iLen = strlen(p)))) {
               goto END;
       }

       iCount = iLen / SYNO_PWRPIN_ITEM_LEN;
       for(i = 0; i < iCount; ++i) {
               if (CONFIG_SYNO_PORT_SIGN[0] != p[0]) {
                       goto END;
               }
               /* jump CONFIG_SYNO_PORT_SIGN */
               ++p;

               /* get port number */
               snprintf(szSataID, CONFIG_SYNO_PWRPIN_ENCODE_LEN + 1, "%s", p);
               iSataID = simple_strtol(szSataID, NULL, 10);
               if (0 > iSataID  || CONFIG_SYNO_MAX_SATA_ID < iSataID) {
                       printk("!!!!!!!!! wrong sata id %d, set pwrctl_pin fail\n",
                                       iSataID);
                       goto END;
               }
               /* jump port number */
               p+= CONFIG_SYNO_PWRPIN_ENCODE_LEN;

               /* get pwrctl_pin */
               snprintf(szPin, CONFIG_SYNO_PWRPIN_ENCODE_LEN + 1, "%s", p);
               if (0 > (iPin = simple_strtol(szPin, NULL, 10))) {
                       printk("!!!!!!!!! wrong iPin %d, set pwrctl_pin fail\n", iPin);
               }
               /* jump pin number */
               p+= CONFIG_SYNO_PWRPIN_ENCODE_LEN;

               /* set this item */
               printk("Get sata id %d pwrctl pin %d\n", iSataID, iPin);
               grgPwrCtlPin[iSataID] = iPin;
       }

END:
       return 1;
}

__setup("pwrctl_pin=", early_pwrctl_pin);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_disk_idx_map(char *p)
{
	snprintf(gszDiskIdxMap, sizeof(gszDiskIdxMap), "%s", p);

	if('\0' != gszDiskIdxMap[0]) {
		printk("Disk Index Map: %s\n", gszDiskIdxMap);
	}

	return 1;
}
__setup("DiskIdxMap=", early_disk_idx_map);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_hw_revision(char *p)
{
       snprintf(gszSynoHWRevision, 4, "%s", p);

       printk("Synology Hardware Revision: %s\n", gszSynoHWRevision);

       return 1;
}
__setup("rev=", early_hw_revision);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_hw_version(char *p)
{
	snprintf(gszSynoHWVersion, 16, "%s", p);

	printk("Synology Hardware Version: %s\n", gszSynoHWVersion);

	return 1;
}
__setup("syno_hw_version=", early_hw_version);
#endif /* MY_ABC_HERE */

#if defined(MY_ABC_HERE) && !defined(MY_DEF_HERE)
/* It is recommanded to use syno_hdd_powerup_seq instead of ihd_num.
 * Because the actual usage of the variable is represented the powerup seq,
 * the syno_hdd_powerup_seq is designed to replace ihd_num.
 * */
static int __init early_internal_hd_num(char *p)
{
        g_syno_hdd_powerup_seq = simple_strtol(p, NULL, 10);

        printk("Internal HD num: %d\n", (int)g_syno_hdd_powerup_seq);

        return 1;
}
__setup("ihd_num=", early_internal_hd_num);

static int __init syno_hdd_powerup_seq(char *p)
{
        g_syno_hdd_powerup_seq = simple_strtol(p, NULL, 10);

        printk("Power on seq num: %d\n", (int)g_syno_hdd_powerup_seq);

        return 1;
}
__setup("syno_hdd_powerup_seq=", syno_hdd_powerup_seq);
#endif /* MY_ABC_HERE && !MY_DEF_HERE */

#ifdef MY_ABC_HERE
/* It is recommanded to use enable_hdd_hotplug instead of HddHotplug.
 * Beacuse the bootarg is referred to a bool variable,
 * the enable_hdd_hotplug is designed to replace HddHotplug.
 * */
static int __init early_hdd_hotplug(char *p)
{
	g_hdd_hotplug = simple_strtol(p, NULL, 10);

	if ( g_hdd_hotplug > 0 ) {
		printk("Support HDD Hotplug.\n");
	}

	return 1;
}
__setup("HddHotplug=", early_hdd_hotplug);

static int __init early_hdd_enable_dynamic_power(char *p)
{
	g_hdd_hotplug = simple_strtol(p, NULL, 10);

	if ( g_hdd_hotplug > 0 ) {
		printk("Support HDD Dynamic Power.\n");
	}

	return 1;
}
__setup("HddEnableDynamicPower=", early_hdd_enable_dynamic_power);

static int __init enable_hdd_hotplug(char *p)
{
	g_hdd_hotplug = simple_strtol(p, NULL, 10);

	if ( g_hdd_hotplug > 0 ) {
		printk("Support HDD Hotplug.\n");
	}

	return 1;
}
__setup("enable_hdd_hotplug=", enable_hdd_hotplug);
#endif /* MY_ABC_HERE */

#ifdef MY_DEF_HERE
static int __init early_smbus_hdd_powerctl(char *p)
{
	g_smbus_hdd_powerctl = simple_strtol(p, NULL, 10);

	if ( g_smbus_hdd_powerctl > 0 ) {
		printk("Support SMBus HDD Dynamic Power Control.\n");
	}

	return 1;
}
__setup("SMBusHddDynamicPower=", early_smbus_hdd_powerctl);

static int __init early_smbus_hdd_type(char *p)
{
	snprintf(gSynoSmbusHddType, sizeof(gSynoSmbusHddType), "%s", p);

	printk("SYNO Smbus Hdd Type: %s\n", gSynoSmbusHddType);

	return 1;
}
__setup("syno_smbus_hdd_type=", early_smbus_hdd_type);

static int __init early_smbus_hdd_adapter(char *p)
{
	gSynoSmbusHddAdapter = simple_strtol(p, NULL, 10);

	printk("SYNO Smbus Hdd Adapter: %d\n", gSynoSmbusHddAdapter);

	return 1;
}
__setup("syno_smbus_hdd_adapter=", early_smbus_hdd_adapter);

static int __init early_smbus_hdd_address(char *p)
{
	gSynoSmbusHddAddress = simple_strtol(p, NULL, 16);

	printk("SYNO Smbus Hdd Address: 0x%02x\n", gSynoSmbusHddAddress);

	return 1;
}
__setup("syno_smbus_hdd_address=", early_smbus_hdd_address);
#endif /* MY_DEF_HERE */

#ifdef MY_ABC_HERE
static int __init early_mac1(char *p)
{
	snprintf(grgbLanMac[0], sizeof(grgbLanMac[0]), "%s", p);

	printk("Mac1: %s\n", grgbLanMac[0]);

	return 1;
}
__setup("mac1=", early_mac1);

static int __init early_mac2(char *p)
{
	snprintf(grgbLanMac[1], sizeof(grgbLanMac[1]), "%s", p);

	printk("Mac2: %s\n", grgbLanMac[1]);

	return 1;
}
__setup("mac2=", early_mac2);

static int __init early_mac3(char *p)
{
	snprintf(grgbLanMac[2], sizeof(grgbLanMac[2]), "%s", p);

	printk("Mac3: %s\n", grgbLanMac[2]);

	return 1;
}
__setup("mac3=", early_mac3);

static int __init early_mac4(char *p)
{
	snprintf(grgbLanMac[3], sizeof(grgbLanMac[3]), "%s", p);

	printk("Mac4: %s\n", grgbLanMac[3]);

	return 1;
}
__setup("mac4=", early_mac4);

static int __init early_macs(char *p)
{
	int iMacCount = 0;
	char *pBegin = p;
	char *pEnd = strstr(pBegin, ",");

	while (NULL != pEnd && SYNO_MAC_MAX_NUMBER > iMacCount) {
		*pEnd = '\0';
		snprintf(grgbLanMac[iMacCount], sizeof(grgbLanMac[iMacCount]), "%s", pBegin);
		pBegin = pEnd + 1;
		pEnd = strstr(pBegin, ",");
		iMacCount++;
	}

	if ('\0' != *pBegin && SYNO_MAC_MAX_NUMBER > iMacCount) {
		snprintf(grgbLanMac[iMacCount], sizeof(grgbLanMac[iMacCount]), "%s", pBegin);
	}

	return 1;
}
__setup("macs=", early_macs);

static int __init early_vender_format_version(char *p)
{
	giVenderFormatVersion = simple_strtol(p, NULL, 10);

	printk("Vender format version: %d\n", giVenderFormatVersion);

	return 1;
}
__setup("vender_format_version=", early_vender_format_version);

static int __init early_skip_vender_mac_interfaces(char *p)
{
	snprintf(gszSkipVenderMacInterfaces, sizeof(gszSkipVenderMacInterfaces), "%s", p);

	printk("Skip vender mac interfaces: %s\n", gszSkipVenderMacInterfaces);

	return 1;
}
__setup("skip_vender_mac_interfaces=", early_skip_vender_mac_interfaces);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_sn(char *p)
{
	snprintf(gszSerialNum, sizeof(gszSerialNum), "%s", p);
	printk("Serial Number: %s\n", gszSerialNum);
	return 1;
}
__setup("sn=", early_sn);

static int __init early_custom_sn(char *p)
{
	snprintf(gszCustomSerialNum, sizeof(gszCustomSerialNum), "%s", p);
	printk("Custom Serial Number: %s\n", gszCustomSerialNum);
	return 1;
}
__setup("custom_sn=", early_custom_sn);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_factory_usb_fast_reset(char *p)
{
	gSynoFactoryUSBFastReset = simple_strtol(p, NULL, 10);

	printk("Factory USB Fast Reset: %d\n", (int)gSynoFactoryUSBFastReset);

	return 1;
}
__setup("syno_usb_fast_reset=", early_factory_usb_fast_reset);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_factory_usb3_disable(char *p)
{
	gSynoFactoryUSB3Disable = simple_strtol(p, NULL, 10);

	printk("Factory USB3 Disable: %d\n", (int)gSynoFactoryUSB3Disable);

	return 1;
}
__setup("syno_disable_usb3=", early_factory_usb3_disable);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int remap_parser(char *p, int *rgRemapTable)
{
	int i;
	char *ptr = p;

	/* initialize basic mapping */
	for ( i = 0; i < SATA_REMAP_MAX; i++)
		rgRemapTable[i] = i;

	/* parse command line specified mapping */
	while (ptr && *ptr) {
		char *cp = ptr;
		char *sz_origin;
		char *sz_mapped;
		int origin_idx;
		int mapped_idx;

		sz_origin = cp;
		if ((cp = strchr(sz_origin, '>'))) {
			*cp++ = '\0';
		} else {
			goto FMT_ERR;
		}

		sz_mapped = cp;
		if ((cp = strchr(sz_mapped, ':'))) {
			*cp++ = '\0';
		}

		origin_idx = simple_strtol(sz_origin, NULL, 10);
		mapped_idx = simple_strtol(sz_mapped, NULL, 10);

		if (SATA_REMAP_MAX > origin_idx) {
			rgRemapTable[origin_idx] = mapped_idx;
		} else {
			goto FMT_ERR;
		}

		ptr = cp;
	}

	return 0;

FMT_ERR:
	/* format error */
	printk(KERN_ERR "SYNO: Parsing remap format error, ignore.\n");
	rgRemapTable[0] = SATA_REMAP_NOT_INIT;
	return -1;
}

/* Provide a simple way to remap data port sequence in boot cmdline
 * Not apply to port multiplier
 * ex:
 * 	1) ahci_remap=0>4:4>0
 * 	  In RS814, 7042 use 0~3, integrated sata uses 4~5. And we want
 * 	  to use 7042 1st port as sde(esata), integrated sata 1st port
 * 	  as sda (first internal port).
 * 	2) ahci_remap=4>5:5>8:12>16
 * 	  Port remap does not need to be symmetric
 * Note:
 * 	1) Not apply to port multipler
 */
static int __init early_ahci_remap(char *p)
{
	if (0 > remap_parser(p, g_syno_sata_remap)) {
		printk(KERN_INFO "SYNO: ahci remap initialized failed\n");
		g_use_sata_remap = 0;
		return -1;
	}

	printk(KERN_INFO "SYNO: ahci remap initialized\n");
	g_use_sata_remap = 1;
	return 0;
}
__setup("ahci_remap=", early_ahci_remap);

/*
 * Similar to sata_remap, however front number is represented for scsi port
 * instead of scsi host.
 * This could only be used by mv14xx driver.
 */
static int __init early_mv14xx_remap(char *p)
{
	if (0 > remap_parser(p, g_syno_mv14xx_remap)) {
		printk(KERN_INFO "SYNO: mv14xx remap initialized failed\n");
		g_use_mv14xx_remap = 0;
		return -1;
	}

	printk(KERN_INFO "SYNO: mv14xx remap initialized\n");
	g_use_mv14xx_remap = 1;
	return 0;
}
__setup("mv14xx_remap=", early_mv14xx_remap);

/* For legacy model only. We hope to phase this bootargs out.
 * mv1475 and ahci both use sata_remap, however they have diffiernet defintions
 * of the index it represented. The prefix index means SCSI host in ahci and SCSI
 * port in mv1475. This makes other feel confused easily, so we separated this bootargs
 * into ahci_remap and mv14xx_remap. PLEASE USE THOSE BOOTARGS.
 */
static int __init early_sata_remap_deprecated(char *p)
{
	if (0 > remap_parser(p, g_syno_sata_remap)) {
		printk(KERN_INFO "SYNO: sata remap initialized failed\n");
		g_use_sata_remap = 0;
		return -1;
	}

	printk(KERN_INFO "SYNO: sata remap initialized\n");
	g_use_sata_remap = 1;
	return 0;
}
__setup("sata_remap=", early_sata_remap_deprecated);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_opt_pci_slot(char *p)
{
	int index = 0;
	char *ptr = p;
	gPciAddrNum = 0;
	while(ptr && *ptr){
		if (',' ==  *ptr) {
			index = 0;
			gPciAddrNum ++;
			if (PCI_ADDR_NUM_MAX <= gPciAddrNum){
				goto FMT_ERR;
			}
		} else {
			if (PCI_ADDR_LEN_MAX <= index) {
				goto FMT_ERR;
			}
			gszPciAddrList[gPciAddrNum][index] = *ptr;
			index++;
		}
		ptr++;
	}
	gPciAddrNum ++;
	printk(KERN_ERR "Syno Bootargs : opt_pci_slot initialized\n");
	return 0;
FMT_ERR:
	gPciAddrNum = 0;
	printk(KERN_ERR "SYNO: opt_pci_slot format error, ignore.\n" );
	return 0;
}
__setup("opt_pci_slot=", early_opt_pci_slot);
#endif /* MY_ABC_HERE */

#ifdef  MY_ABC_HERE
static int __init early_internal_netif_num(char *p)
{
	g_internal_netif_num = simple_strtol(p, NULL, 10);

	if ( g_internal_netif_num >= 0 ) {
		printk("Internal netif num: %d\n", (int)g_internal_netif_num);
	}

	return 1;
}
__setup("netif_num=", early_internal_netif_num);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_sataled_special(char *p)
{
	g_sata_mv_led = simple_strtol(p, NULL, 10);

	if ( g_sata_mv_led >= 0 ) {
		printk("Special Sata LEDs.\n");
	}

	return 1;
}
__setup("SataLedSpecial=", early_sataled_special);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_sataport_map(char *p)
{
	snprintf(gszSataPortMap, sizeof(gszSataPortMap), "%s", p);

	if(0 != gszSataPortMap[0]) {
		printk("Sata Port Map: %s\n", gszSataPortMap);
	}

	return 1;
}
__setup("SataPortMap=", early_sataport_map);
#endif /* MY_ABC_HERE */

#if defined(MY_DEF_HERE) || (defined(MY_DEF_HERE) && defined(MY_DEF_HERE))
static int __init early_SASmodel(char *p)
{
	g_is_sas_model = simple_strtol(p, NULL, 10);

	if (1 == g_is_sas_model) {
		printk("SAS model: %d\n", (int)g_is_sas_model);
	}

	return 1;
}
__setup("SASmodel=", early_SASmodel);
#endif /* MY_DEF_HERE || (defined(MY_DEF_HERE) && defined(MY_DEF_HERE)) */

#ifdef MY_DEF_HERE
static int __init early_dual_head(char *p)
{
	gSynoDualHead = simple_strtol(p, NULL, 10);
#ifdef MY_DEF_HERE
	gSynoBootSATADOM = gSynoDualHead;
#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
	gSynoSASWriteConflictPanic = gSynoDualHead;
#endif

	printk("Synology Dual Head: %d\n", gSynoDualHead);

	return 1;
}
__setup("dual_head=", early_dual_head);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static int __init early_sas_reservation_write_conflict(char *p)
{
	gSynoSASWriteConflictPanic = simple_strtol(p, NULL, 10);

	printk("Let kernel panic if sas reservation write conflict: %d\n", gSynoSASWriteConflictPanic);

	return 1;
}
__setup("sas_reservation_write_conflict=", early_sas_reservation_write_conflict);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static int __init early_sas_hba_idx(char *p)
{
        int iCount = 0;
        char *pBegin = p;
        char *pEnd = NULL;

        do {
                pEnd = strstr(pBegin, ",");
                if (NULL != pEnd) {
                        *pEnd = '\0';
                }
                snprintf(gSynoSASHBAAddr[iCount],
                                sizeof(gSynoSASHBAAddr[iCount]), "%s", pBegin);
                pBegin = (NULL == pEnd) ? NULL : pEnd + 1;
                iCount ++;
        } while (NULL != pBegin && iCount < CONFIG_SYNO_SAS_MAX_HBA_SLOT);



        return 1;
}
__setup("sas_hba_idx_addr=", early_sas_hba_idx);
#endif /* MY_DEF_HERE */

#ifdef MY_DEF_HERE
static int __init early_synoboot_satadom(char *p)
{
	gSynoBootSATADOM = simple_strtol(p, NULL, 10);

	printk("Synology boot device SATADOM: %d\n", gSynoBootSATADOM);

	return 1;
}
__setup("synoboot_satadom=", early_synoboot_satadom);
#endif /* MY_DEF_HERE */

#ifdef  MY_ABC_HERE
static int __init early_ahci_switch(char *p)
{
	g_ahci_switch = p[0];
	if ('0' == g_ahci_switch) {
		printk("AHCI: 0\n");
	} else {
		printk("AHCI: 1\n");
	}

	return 1;
}
__setup("ahci=", early_ahci_switch);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
static int __init early_castrated_xhc(char *p)
{
	int iCount = 0;
	char *pBegin = p;
	char *pEnd = strstr(pBegin, ",");
	char *pPortSep = NULL;

	while (iCount < CONFIG_SYNO_USB_NUM_CASTRATED_XHC) {
		if(NULL != pEnd)
			*pEnd = '\0';
		pPortSep = strstr(pBegin, "@");
		if (pPortSep == NULL) {
			printk("Castrated xHC - Parameter format not correct\n");
			break;
		}
		*pPortSep = '\0';
		snprintf(gSynoCastratedXhcAddr[iCount],
				sizeof(gSynoCastratedXhcAddr[iCount]), "%s", pBegin);
		gSynoCastratedXhcPortBitmap[iCount] = simple_strtoul(pPortSep + 1, NULL,
				16);
		if (NULL == pEnd)
			break;
		pBegin = pEnd + 1;
		pEnd = strstr(pBegin, ",");
		iCount++;
	}

	return 1;
}
__setup("syno_castrated_xhc=", early_castrated_xhc);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#ifdef MY_DEF_HERE
#else
static int __init early_usb_vbus_gpio(char *p)
{
	int iCount = 0;
	char *pBegin = p;
	char *pEnd = NULL;
	char *pSeparator = NULL;
	int error = 0;

	printk("USB Vbus GPIO Control:\n");

#if defined(MY_ABC_HERE)
		if (syno_is_hw_version(HW_DS918p) || syno_is_hw_version(HW_DS418play)) {
			pBegin = "13@dev_name:usb2@1,13@dev_name:usb1@3,11@dev_name:usb2@2,11@dev_name:usb1@1";
		}
#endif
	pEnd = strstr(pBegin, ",");
	//initialize gsynousbvbusgpp array
	for (iCount = 0; iCount < CONFIG_SYNO_USB_VBUS_NUM_GPIO; iCount++) {
		gSynoUsbVbusGpp[iCount] = UINT_MAX;
	}
	iCount = 0;
	while (iCount < CONFIG_SYNO_USB_VBUS_NUM_GPIO) {
		if(NULL != pEnd)
			*pEnd = '\0';

		pSeparator = strstr(pBegin, "@");
		if (pSeparator == NULL) {
			printk("USB Vbus GPIO Control - Parameter format not correct\n");
			error = 1;
			break;
		}
		*pSeparator = '\0';
		gSynoUsbVbusGpp[iCount] = simple_strtoul(pBegin, NULL, 10);
		printk(" Gpp#%d", gSynoUsbVbusGpp[iCount]);

		pBegin = pSeparator + 1;
		pSeparator = strstr(pBegin, "@");
		if (pSeparator == NULL) {
			printk("\nUSB Vbus GPIO Control - Parameter format not correct\n");
			error = 1;
			break;
		}
		*pSeparator = '\0';
		snprintf(gSynoUsbVbusHostAddr[iCount],
				sizeof(gSynoUsbVbusHostAddr[iCount]), "%s", pBegin);
		printk(" - Host: %-20s", gSynoUsbVbusHostAddr[iCount]);

		gSynoUsbVbusPort[iCount] = simple_strtol(pSeparator + 1, NULL, 10);
#if defined(MY_DEF_HERE)
		if (syno_is_hw_version(HW_DS1618p) && -1 == gSynoUsbVbusPort[iCount]) {
			if ( 0 == (strcmp("0000:00:15.00", gSynoUsbVbusHostAddr[iCount]))) {
				snprintf(gSynoUsbVbusHostAddr[iCount],sizeof(gSynoUsbVbusHostAddr[iCount]), "%s","0000:00:15.0");
			}
			gSynoUsbVbusPort[iCount] = 2;
		}
#endif
#if defined(MY_DEF_HERE)
		//rtd129x misuse zoro-base index
		gSynoUsbVbusPort[iCount]++;
#endif /* MY_DEF_HERE */
		printk(" - Port:%d", gSynoUsbVbusPort[iCount]);

		pSeparator = strstr(pSeparator + 1, "@");
		if (NULL == pSeparator) {
			printk(" - Polarity: ACTIVE_HIGH\n");
			gSynoUsbVbusGppPol[iCount] = 1;
		} else {
			gSynoUsbVbusGppPol[iCount] = simple_strtoul(pSeparator + 1, NULL, 10);
			if (1 == gSynoUsbVbusGppPol[iCount])
				printk(" - Polarity: ACTIVE_HIGH\n");
			else if (0 == gSynoUsbVbusGppPol[iCount])
				printk(" - Polarity: ACTIVE_LOW\n");
			else {
				printk("\nUSB Vbus GPIO Control - Parameter format not correct\n");
				error = 1;
				break;
			}
		}
		if (NULL == pEnd)
			break;

		pBegin = pEnd + 1;
		pEnd = strstr(pBegin, ",");
		iCount++;
	}

	if (error) {
		iCount = 0;
		while (iCount < CONFIG_SYNO_USB_VBUS_NUM_GPIO) {
			gSynoUsbVbusHostAddr[iCount][0] = '\0';
			gSynoUsbVbusGpp[iCount] = UINT_MAX;
			gSynoUsbVbusPort[iCount] = 0;
			iCount++;
		}
	}

	return 1;
}
__setup("syno_usb_vbus_gpio=", early_usb_vbus_gpio);
#endif /* MY_DEF_HERE */
#endif /* MY_ABC_HERE */
#ifdef MY_DEF_HERE
static int __init early_syno_set_ttyS0(char *p)
{
	snprintf(gszSynoTtyS0, strlen(p) + 1, "%s", p);
	setup_early_printk(p);
	return 1;
}
__setup("syno_ttyS0=", early_syno_set_ttyS0);

static int __init early_syno_set_ttyS1(char *p)
{
	snprintf(gszSynoTtyS1, strlen(p) + 1, "%s", p);
	return 1;
}
__setup("syno_ttyS1=", early_syno_set_ttyS1);

static int __init early_syno_set_ttyS2(char *p)
{
	snprintf(gszSynoTtyS2, strlen(p) + 1, "%s", p);
	return 1;
}
__setup("syno_ttyS2=", early_syno_set_ttyS2);

#endif /* MY_DEF_HERE */
#ifdef MY_DEF_HERE
static int __init early_syno_m2_port(char *p)
{
	char *begin, *end;
	int i = 0, err;

	begin = p;
	end = strstr(begin, "#");
	if (NULL == end) {
		printk("%s: Parse sign '#' failed from %s\n", __func__, begin);
		goto ERR;
	}
	end[0] = 0;

	snprintf(gSynoM2HostName, M2_HOST_LEN_MAX, begin);

	begin = end+1;
	end = strstr(begin, "@");
	if (NULL == end) {
		printk("%s: Parse sign '@' failed from %s\n", __func__, begin);
		goto ERR;
	}
	end[0] = 0;

	err = kstrtoul(begin, 10, &gSynoM2PortNo);
	if (0 != err) {
		printk("%s: Parse the M.2 port number failed, err = %d\n", __func__, err);
		goto ERR;
	}

	for (i = 0; i < gSynoM2PortNo-1; ++i) {
		begin = end+1;
		end = strstr(begin, "@");
		if (NULL == end) {
			printk("%s: Parse sign '@' failed from %s\n", __func__, begin);
			goto ERR;
		}
		end[0] = 0;

		err = kstrtoul(begin, 10, &gSynoM2PortIndex[i]);
		if (0 != err) {
			printk("%s: Parse the M.2 port index %d failed, err = %d\n", __func__, i, err);
			goto ERR;
		}
	}
	err = kstrtoul(end+1, 10, &gSynoM2PortIndex[i]);
	if (0 != err) {
		printk("%s: Parse the M.2 port index %d failed, err = %d\n", __func__, i, err);
		goto ERR;
	}
	printk("%s: Onboard M2 host name is %s, port no is %lu, port index is", __func__, gSynoM2HostName, gSynoM2PortNo);
	for (i = 0; i < gSynoM2PortNo; ++i) {
		printk(" %lu", gSynoM2PortIndex[i]);
	}
	printk("\n");
	return 1;
ERR:
	gSynoM2PortNo = 0;
	gSynoM2HostName[0] = 0;
	return 1;
}
__setup("m2_port=", early_syno_m2_port);
#endif /* MY_DEF_HERE */
#ifdef MY_ABC_HERE
static int __init early_syno_spinup_group(char *p)
{
	int group_num = 0;
	char *endp;
	while (1) {
		if(SYNO_SPINUP_GROUP_MAX < group_num) {
			return -EMSGSIZE;
		}
		giSynoSpinupGroup[group_num] = simple_strtol(p, &endp, 10) & 0xFF;
		printk("SYNO Spinup Group %d: %d\n", group_num, giSynoSpinupGroup[group_num]);
		group_num++;
		// endp will point to a non digit position
		// Break if reach the end of string
		if (*endp == '\0') {
			break;
		}
		p = ++endp;
	}
	giSynoSpinupGroupNum = group_num;
#ifdef MY_DEF_HERE
	printk(KERN_ERR "ERROR !!! Kernel parameter for spinup group is only for HW tuning.\n");
	printk(KERN_ERR "ERROR !!! The spinup group should be read from dts.\n");
#endif /* MY_DEF_HERE */
	return 1;
}
__setup("syno_spinup_group=", early_syno_spinup_group);

static int __init early_syno_spinup_group_delay(char *p)
{
	giSynoSpinupGroupDelay = simple_strtol(p, NULL, 10);
	printk("SYNO Spinup Group Delay: %d\n", (int)giSynoSpinupGroupDelay);
#ifdef MY_DEF_HERE
	printk(KERN_ERR "ERROR !!! Kernel parameter for spinup group delay is only for HW tuning.\n");
	printk(KERN_ERR "ERROR !!! The spinup group delay should be read from dts.\n");
#endif /* MY_DEF_HERE */
	return 1;
}
__setup("syno_spinup_group_delay=", early_syno_spinup_group_delay);

static int __init early_syno_spinup_group_debug(char *p)
{
	giSynoSpinupGroupDebug = simple_strtol(p, NULL, 10);
	printk("SYNO Spinup Group Debug: %d\n", (int)giSynoSpinupGroupDebug);
	return 1;
}
__setup("syno_spinup_group_debug=", early_syno_spinup_group_debug);
#endif /* MY_ABC_HERE */

#ifdef MY_DEF_HERE
static int __init early_syno_multipath_model(char *p)
{
	gIsMultipathModel = simple_strtol(p, NULL, 10);

	printk("Is Multipath Model: %s\n", (int)gIsMultipathModel ? "Yes" : "No");
	return 1;
}
__setup("multipath_model=", early_syno_multipath_model);
#endif /* MY_DEF_HERE */
