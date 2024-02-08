#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// Copyright (c) 2000-2008 Synology Inc. All rights reserved.
#ifndef __SYNOLIB_H_
#define __SYNOLIB_H_

#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/list.h>

#ifdef  MY_ABC_HERE
void syno_do_hibernation_fd_log(const int fd);
void syno_do_hibernation_filename_log(const char __user *filename);
void syno_do_hibernation_inode_log(struct inode *inode);
void syno_do_hibernation_bio_log(const char *DeviceName);
void syno_do_hibernation_scsi_log(const char *DeviceName);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
void syno_draw_auto_remap_buffer(char *buffer, int size);
#endif /* MY_ABC_HERE */

#ifdef MY_ABC_HERE
#include <linux/fs.h>
int SynoSCSIGetDeviceIndex(struct block_device *bdev); 
#endif

#ifdef MY_ABC_HERE
/**
 * How to use :
 * 1. module itself register the proprietary instance into the kernel
 *    by a predined MAGIC-key.
 * 2. Others can query the module registration by the same MAGIC-key
 *    and get the instance handle.
 * ********************************************************************
 * Beware of casting/handing "instance", you must know
 * what you are doing before accessing the instance.
 * ********************************************************************
 */
/* For plugin-instance registration */
int syno_plugin_register(int plugin_magic, void *instance);
int syno_plugin_unregister(int plugin_magic);
/* For getting the plugin-instance */
int syno_plugin_handle_get(int plugin_magic, void **hnd);
void * syno_plugin_handle_instance(void *hnd);
void syno_plugin_handle_put(void *hnd);

/* Magic definition */
#define EPIO_PLUGIN_MAGIC_NUMBER    0x20120815
#define RODSP_PLUGIN_MAGIC_NUMBER    0x20141111
#endif

/* Maximum number of MAC addresses */
#define SYNO_MAC_MAX_NUMBER 8

#ifdef MY_DEF_HERE
#define SATA_REMAP_MAX  32
#define SATA_REMAP_NOT_INIT 0xff
extern int g_syno_sata_remap[SATA_REMAP_MAX];
extern int g_use_sata_remap;
int syno_get_remap_idx(int origin_idx);
extern int g_syno_mv14xx_remap[SATA_REMAP_MAX];
extern int g_use_mv14xx_remap;
int syno_get_mv_14xx_remap_idx(int origin_idx);
#endif /* MY_DEF_HERE */

#ifdef MY_ABC_HERE
#define PCI_ADDR_LEN_MAX 9
#define PCI_ADDR_NUM_MAX CONFIG_SYNO_MAX_PCI_SLOT
extern char gszPciAddrList[PCI_ADDR_NUM_MAX][PCI_ADDR_LEN_MAX];
extern int gPciAddrNum;
extern int syno_check_on_option_pci_slot(struct pci_dev *pdev);
#endif /* MY_ABC_HERE */

#ifdef MY_DEF_HERE
/* Max 768 */
#define M2SATA_START_IDX 800
extern int gPciDeferStart;
extern int g_nvc_map_index;
extern int g_syno_nvc_index_map[SATA_REMAP_MAX];
void syno_insert_sata_index_remap(unsigned int idx, unsigned int num, unsigned int id_start);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE) || defined(MY_ABC_HERE)
#define SYNOBIOS_EVENTDATA_NUM_MAX 8
typedef struct _synobios_event_parm_tag {
	unsigned long long data[SYNOBIOS_EVENTDATA_NUM_MAX];
} SYNOBIOS_EVENT_PARM;

typedef int (*FUNC_SYNOBIOS_EVENT)(SYNOBIOS_EVENT_PARM parms);

typedef struct _synobios_evnet_action_tag {
	FUNC_SYNOBIOS_EVENT *funcSynobiosEvent;
	SYNOBIOS_EVENT_PARM parms;
	struct list_head list;
} SYNOBIOS_EVENT_ACTION_LIST;
#endif /* MY_DEF_HERE || MY_ABC_HERE */

#ifdef MY_ABC_HERE
/*
 * Notice
 * ------
 *  Before calling syno_kexec_test() or reading kexex_test_flags, please
 *  ensure that syno_kexec_test_init() has been called.
 */
#define KEXEC_TEST_DECOMPRESSION	0	/* Did we skip compressed/head_64.S ? */
#define KEXEC_TEST_BOOTLOADER		1	/* Is bootloader type 0xD ? */
#define KEXEC_TEST_E820_TABLE		2	/* Is the minimal start address of usable memory in e820 table 0x100 ? */
#define KEXEC_TEST_SETUP_DATA		3	/* Did we receive setup_data with type SETUP_NONE or SETUP_EFI ? */

extern unsigned long kexec_test_flags;

/*
 * Test whether the above KEXEC_TEST_* bits are set.
 */
static __always_inline bool syno_kexec_test(int test)
{
	return 0 != test_bit(test, &kexec_test_flags);
}
#endif /* MY_ABC_HERE */

#endif //__SYNOLIB_H_
