#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __SYNOLIB_H_
#define __SYNOLIB_H_

#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/kobject.h>

#ifdef  MY_ABC_HERE
extern int gSynoDebugFlag;
extern int gSynoAtaDebug;
extern int gSynoHibernationLogLevel;
extern struct mm_struct *syno_get_task_mm(struct task_struct *task);
void syno_do_hibernation_fd_log(const int fd);
void syno_do_hibernation_filename_log(const char __user *filename);
void syno_do_hibernation_inode_log(struct inode *inode);
void syno_do_hibernation_bio_log(const char *DeviceName);
void syno_do_hibernation_scsi_log(const char *DeviceName);
#endif  

#ifdef MY_ABC_HERE
int SynoSCSIGetDeviceIndex(struct gendisk *disk);
#endif
#ifdef MY_ABC_HERE
int SynoNVMeGetDeviceIndex(struct gendisk *disk);
#endif  
#ifdef MY_ABC_HERE
int SynoDiskGetDeviceIndex(struct block_device *bdev);
#endif  

#ifdef MY_ABC_HERE
 
int syno_plugin_register(int plugin_magic, void *instance);
int syno_plugin_unregister(int plugin_magic);
 
int syno_plugin_handle_get(int plugin_magic, void **hnd);
void * syno_plugin_handle_instance(void *hnd);
void syno_plugin_handle_put(void *hnd);

#define EPIO_PLUGIN_MAGIC_NUMBER    0x20120815
#define RODSP_PLUGIN_MAGIC_NUMBER    0x20141111
#endif

#ifdef MY_ABC_HERE
 
#define SYNO_MAC_MAX_NUMBER 8
#endif  

#ifdef MY_ABC_HERE
#define SATA_REMAP_MAX  32
#define SATA_REMAP_NOT_INIT 0xff
extern int g_syno_sata_remap[SATA_REMAP_MAX];
extern int g_use_sata_remap;
int syno_get_remap_idx(int origin_idx);
extern int g_syno_mv14xx_remap[SATA_REMAP_MAX];
extern int g_use_mv14xx_remap;
int syno_get_mv_14xx_remap_idx(int origin_idx);
#endif  

#ifdef MY_DEF_HERE
#define DT_INTERNAL_SLOT "internal_slot"
#define DT_ESATA_SLOT "esata_port"
#define DT_CX4_SLOT "cx4_port"
#define DT_PCIE_SLOT "pcie_slot"
#define DT_USB_SLOT "usb_slot"
#define DT_HUB_SLOT "usb_hub"
#define DT_POWER_PIN_GPIO "power_pin_gpio"
#define DT_DETECT_PIN_GPIO "detect_pin_gpio"
#define DT_HDD_LED_TYPE "led_type"
#define DT_HDD_ORANGE_LED "led_orange"
#define DT_HDD_GREEN_LED "led_green"
#define DT_HDD_LED_NAME "led_name"
#define DT_HDD_ACT_LED "led_activity"
#define DT_SYNO_GPIO "syno_gpio"
#define DT_PCIE_ROOT "pcie_root"
#define DT_ATA_PORT "ata_port"
#define DT_AHCI "ahci"
#define DT_AHCI_RTK "ahci_rtk"
#define DT_AHCI_MVEBU "ahci_mvebu"
#define DT_MV14XX "mv14xx"
#define DT_PHY "phy"
#define DT_USB2 "usb2"
#define DT_USB3 "usb3"
#define DT_USB_PORT "usb_port"
#define DT_USB_HUB "usb_hub"
#define DT_VBUS "vbus"
#define DT_SHARED "shared"
#define DT_SYNO_SPINUP_GROUP "syno_spinup_group"
#define DT_SYNO_SPINUP_GROUP_DELAY "syno_spinup_group_delay"
#define DT_HDD_POWERUP_SEQ "syno_hdd_powerup_seq"
#define DT_PROPERTY_SW_ACTIVITY "sw_activity"
#define DT_DISK_LED_TYPE_GPIO "gpio"
#define DT_FORM_FACTOR "form_factor"
#define DT_EXPANDER "expander"
#define DT_MODEL_NAME "model_name"
#define DT_SWITCHTEC "switchtec"
#define DT_LED_OFF_GPIO "led_off_gpio"

#ifdef MY_DEF_HERE
#define DT_SYNO_HDD_SMBUS_TYPE "syno_smbus_hdd_type"
#define DT_SYNO_HDD_SMBUS_ADAPTER "syno_smbus_hdd_adapter"
#define DT_SYNO_HDD_SMBUS_ADDRESS "syno_smbus_hdd_address"
#endif  

#define DT_SYNO_PMBUS_ADAPTER "syno_pmbus_adapter"
#define DT_SYNO_PMBUS_ADDRESS "syno_pmbus_address"
#define DT_SYNO_PMBUS_PIN_REG "syno_pmbus_pin_register"
#define DT_SYNO_PMBUS_POUT_REG "syno_pmbus_pout_register"
#define DT_SYNO_PMBUS_TEMP1_REG "syno_pmbus_temp1_register"
#define DT_SYNO_PMBUS_TEMP2_REG "syno_pmbus_temp2_register"
#define DT_SYNO_PMBUS_TEMP3_REG "syno_pmbus_temp3_register"
#define DT_SYNO_PMBUS_FAN_REG "syno_pmbus_fan_register"
#define DT_SYNO_PMBUS_STATUS_REG "syno_pmbus_status_register"
#define DT_SYNO_PMBUS_PSU_OFF_BIT "syno_pmbus_psu_off_bit"
#define DT_SYNO_PMBUS_PSU_PRESENT_BIT "syno_pmbus_psu_present_bit"

#define SYNO_DTS_PROPERTY_CONTENT_LENGTH 128  
#define MAX_NODENAME_LEN 31

typedef enum _tag_DISK_PORT_TYPE{
	UNKNOWN_DEVICE = 0,
	INTERNAL_DEVICE,
	EXTERNAL_SATA_DEVICE,
	EUNIT_DEVICE,
	EXTERNAL_USB_DEVICE,
	SYNOBOOT_DEVICE,
	ISCSI_DEVICE,
	CACHE_DEVICE,
	USB_HUB_DEVICE,
	SDCARD_DEVICE,
	INVALID_DEVICE,
	SYSTEM_DEVICE,
	DISK_PORT_TYPE_END,
} DISK_PORT_TYPE;

#endif  

#ifdef MY_DEF_HERE
typedef struct _syno_smbus_hdd_powerctl {
        bool bl_init;
        int (*syno_smbus_hdd_enable_write)(int adapter, int address, int index, int val);
        int (*syno_smbus_hdd_enable_read)(int adapter, int address, int index);
        int (*syno_smbus_hdd_present_read)(int adapter, int address, int index);
        int (*syno_smbus_hdd_enable_write_all_once)(int adapter, int address);
} SYNO_SMBUS_HDD_POWERCTL;
#endif  

#ifdef MY_DEF_HERE
#define PCI_ADDR_LEN_MAX 9
#define PCI_ADDR_NUM_MAX CONFIG_SYNO_MAX_PCI_SLOT
extern char gszPciAddrList[PCI_ADDR_NUM_MAX][PCI_ADDR_LEN_MAX];
extern int gPciAddrNum;
extern int syno_check_on_option_pci_slot(struct pci_dev *pdev);
#endif  

#ifdef MY_DEF_HERE
 
#define M2SATA_START_IDX 800
extern int gPciDeferStart;
extern int g_nvc_map_index;
extern int g_syno_nvc_index_map[SATA_REMAP_MAX];
void syno_insert_sata_index_remap(unsigned int idx, unsigned int num, unsigned int id_start);
#endif  
#ifdef MY_DEF_HERE
#define M2_HOST_LEN_MAX 128
#define M2_PORT_NO_MAX 16
extern char gSynoM2HostName[M2_HOST_LEN_MAX];
extern unsigned long gSynoM2PortNo;
extern unsigned long gSynoM2PortIndex[M2_PORT_NO_MAX];
#endif  
#ifdef MY_DEF_HERE
#define SYNO_SPINUP_GROUP_MAX 16
#define SYNO_SPINUP_GROUP_PIN_MAX_NUM 8
extern int g_syno_rp_detect_no;
extern int g_syno_rp_detect_list[SYNO_SPINUP_GROUP_PIN_MAX_NUM];
extern int g_syno_hdd_detect_no;
extern int g_syno_hdd_detect_list[SYNO_SPINUP_GROUP_PIN_MAX_NUM];
extern int g_syno_hdd_enable_no;
extern int g_syno_hdd_enable_list[SYNO_SPINUP_GROUP_PIN_MAX_NUM];
#endif  

#ifdef MY_DEF_HERE
#define SYSTEM_DEVICE_START_IDX 900
#define SYSTEM_DEVICE_NUM_MAX 10
#endif  

#ifdef MY_DEF_HERE

typedef enum _tag_SYNO_MPATH_SYSFS_AGGR_METHOD {
	 
	MPATH_SYSFS_SHOW_AGGR_ARBITRARY,
	 
	MPATH_SYSFS_SHOW_AGGR_MIN_UL_DEC,
} SYNO_MPATH_SYSFS_SHOW_AGGR_METHOD;

typedef struct _syno_multipath_target_sysfs {
	struct kobject deviceKobj;
	struct kobj_type deviceKtype;
	struct kobject *parent;
	struct mapped_device *md;
	ssize_t (*funcTargetSysfsShow)(struct gendisk*, struct attribute*, char*);
	ssize_t (*funcTargetSysfsStore)(struct gendisk*, struct attribute*, const char*, size_t);
	SYNO_MPATH_SYSFS_SHOW_AGGR_METHOD (*funcTargetShowAggrMethod)(struct attribute*);
} SYNO_MPATH_TARGET_SYSFS;
#endif  

#endif  
