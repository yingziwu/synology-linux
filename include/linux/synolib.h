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
extern int syno_temperature_debug;
#endif

#ifdef MY_DEF_HERE
typedef struct _tag_SynoAsyncOperation{
	//struct timer_list	asyncStartTimer;

	/**
	 * worker info.
	 */
	struct workqueue_struct	*pwq;
	struct delayed_work sched_work;

	/*
	* period function, and his ownly data pointer.
	* period_in_sec is the periodly execution unit.
	* stopAsyncOperation will cause stop period execution
	*/
	void (*period_func)(void *data);
	void *period_func_data;
	unsigned long	period_in_sec;
	u8	stopAsyncOperation;

	spinlock_t	syno_async_lock;
}SYNOASYNCOPERATION;


int SynoAsyncOperationInit(SYNOASYNCOPERATION *pSynoAsyncOp, struct workqueue_struct *pWorkQueue,
							 void (*period_func)(void *data), void *user_data, unsigned long period_in_sec);
extern void SynoAsyncOperationCleanUp(SYNOASYNCOPERATION *pSynoAsyncOp);
extern void SynoAsyncOperationPause(SYNOASYNCOPERATION *pSynoAsyncOp);
extern void SynoAsyncOperationResume(SYNOASYNCOPERATION *pSynoAsyncOp);
extern void SynoAsyncOperationModifyPeriod(SYNOASYNCOPERATION *pSynoAsyncOp, unsigned long period_in_sec);

extern asmlinkage int SynoPrintk(u8 direct_print, const char *fmt, ...);

#define SYNO_AYNC_OP_INIT(pSynoAsyncOp, period_func, user_data, period_in_sec)	SynoAsyncOperationInit(pSynoAsyncOp, NULL, period_func, user_data, period_in_sec)
#define SYNO_SCHED_ASYNC_OP_INIT(pSynoAsyncOp, period_func, user_data, period_in_sec)	SynoAsyncOperationInit(pSynoAsyncOp, NULL, period_func, user_data, period_in_sec)
#define SYNO_SCHED_ASYNC_OP_INIT_WITH_WORKQUEUE(pSynoAsyncOp, pWorkQueue, period_func, user_data, period_in_sec)	SynoAsyncOperationInit(pSynoAsyncOp, pWorkQueue, period_func, user_data, period_in_sec)

struct workqueue_struct *SynoCreateWorkqueue(const char *name);
void SynoDestroyWorkqueue(struct workqueue_struct *wq);
#endif /* MY_DEF_HERE */

#ifdef MY_ABC_HERE
void syno_do_hibernation_fd_log(const int fd);
void syno_do_hibernation_filename_log(const char __user *filename);
void syno_do_hibernation_inode_log(struct inode *inode);
void syno_do_hibernation_bio_log(const char *DeviceName);
void syno_do_hibernation_scsi_log(const char *DeviceName);
#endif

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

#ifdef MY_ABC_HERE
typedef struct _synobios_event_parm_tag {
	unsigned long long data1;
	unsigned long long data2;
	unsigned long long data3;
	unsigned long long data4;
	unsigned long long data5;
} SYNOBIOS_EVENT_PARM;

typedef int (*FUNC_SYNOBIOS_EVENT)(SYNOBIOS_EVENT_PARM parms);

typedef struct _synobios_evnet_action_tag {
	FUNC_SYNOBIOS_EVENT *funcSynobiosEvent;
	SYNOBIOS_EVENT_PARM parms;
	struct list_head list;
} SYNOBIOS_EVENT_ACTION_LIST;
#endif /* MY_ABC_HERE */

#endif //__SYNOLIB_H_
