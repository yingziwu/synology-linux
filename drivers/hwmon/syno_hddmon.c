#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/syno.h>
#if !defined(MY_DEF_HERE)
#include <linux/gpio.h>
#endif

MODULE_LICENSE("Proprietary");

#define SYNO_MAX_HDD_PRZ 4
#define SYNO_HDDMON_POLL_SEC 1
#define SYNO_HDDMON_EN_WAIT_SEC 7
#define SYNO_HDDMON_STR "Syno_HDDMon"
#define SYNO_HDDMON_UPLG_STR "Syno_HDDMon_UPLGM"

#ifdef MY_ABC_HERE
extern long g_internal_hd_num;
#endif

#ifdef MY_ABC_HERE
extern long g_hdd_hotplug;
#endif

#if defined(CONFIG_SYNO_CEDARVIEW)
static int PrzPinMap[]   = {33, 35, 49, 18};
static int HddEnPinMap[] = {16, 20, 21, 32};
#elif defined(MY_ABC_HERE)
static int PrzPinMap[]   = {70, 71, 72, 84};
static int HddEnPinMap[] = {24, 25, 26, 27};
#else
static int *PrzPinMap = NULL;
static int *HddEnPinMap = NULL;
#endif

static u8 gblInversePresent = 0;

#if defined(MY_DEF_HERE)
extern u32 syno_pch_lpc_gpio_pin(int pin, int *pValue, int isWrite);
#endif

typedef struct __SynoHddMonData {
	int iProcessingIdx;
	int blHddHotPlugSupport;
	int iMaxHddNum;
	int blHddEnStat[SYNO_MAX_HDD_PRZ];
	int iHddPrzPinMap[SYNO_MAX_HDD_PRZ];
	int iHddEnPinMap[SYNO_MAX_HDD_PRZ];
} SynoHddMonData_t;

static struct task_struct *pHddPrzPolling;
static SynoHddMonData_t synoHddMonData;

static int syno_hddmon_pin_mapping(SynoHddMonData_t *pData)
{
	int iRet = -1;

	if (NULL == pData) {
		goto END;
	}

	if((NULL != PrzPinMap) && (NULL != HddEnPinMap)) {
		memcpy(pData->iHddPrzPinMap, PrzPinMap, sizeof(PrzPinMap));
		memcpy(pData->iHddEnPinMap, HddEnPinMap, sizeof(HddEnPinMap));
	}else{
		pData->blHddHotPlugSupport = 0;
		goto END;
	}

	iRet = 0;
END:
	return iRet;	
}

static int syno_hddmon_data_init(SynoHddMonData_t *pData)
{
	int iRet = -1;

	if (NULL == pData) {
		goto END;
	}

	memset(pData, 0, sizeof(SynoHddMonData_t));

#ifdef MY_ABC_HERE
	pData->blHddHotPlugSupport = g_hdd_hotplug;
#endif

#ifdef MY_ABC_HERE
	pData->iMaxHddNum = g_internal_hd_num;
#else
	pData->iMaxHddNum = SYNO_MAX_HDD_PRZ;
#endif

	if(SYNO_MAX_HDD_PRZ < pData->iMaxHddNum) {
		goto END;
	}

	syno_hddmon_pin_mapping (pData);

	if(0 == pData->blHddHotPlugSupport) {
		goto END;
	}

	iRet = 0;
END:
	return iRet;
}

static int syno_hddmon_unplug_monitor(void *args)
{
	int iRet = -1;
	int iIdx;
	int iPrzPinVal;
	SynoHddMonData_t *pData = NULL;
	unsigned int uiTimeout;

	if (NULL == args) {
		goto END;
	}

	pData = (SynoHddMonData_t *) args;

	while(1) {
		if (kthread_should_stop()) {
			break;
		}

		for(iIdx = 0; iIdx < pData->iMaxHddNum; iIdx++) {
			if(pData->iProcessingIdx == iIdx) {
				continue;
			}

#if defined(MY_DEF_HERE)
			syno_pch_lpc_gpio_pin(pData->iHddPrzPinMap[iIdx], &iPrzPinVal, 0);
#else
		if (gblInversePresent)
			iPrzPinVal = !gpio_get_value(pData->iHddPrzPinMap[iIdx]);
		else
			iPrzPinVal = gpio_get_value(pData->iHddPrzPinMap[iIdx]);
#endif

			if(iPrzPinVal) {
				continue;
			}

#if defined(MY_DEF_HERE)
			syno_pch_lpc_gpio_pin(pData->iHddEnPinMap[iIdx], &iPrzPinVal, 1);
#else
			gpio_set_value(pData->iHddEnPinMap[iIdx], iPrzPinVal);
#endif
			pData->blHddEnStat[iIdx] = iPrzPinVal;

		}

		uiTimeout = HZ / 2;
		do{
			set_current_state(TASK_INTERRUPTIBLE);
			uiTimeout = schedule_timeout(uiTimeout);
		}while(uiTimeout);
	}

	iRet = 0;
END:
	return iRet;
}

static void syno_hddmon_task(SynoHddMonData_t *pData)
{
	int iIdx;
	int iPrzPinVal;
	static struct task_struct *pUnplugMonitor;
	unsigned int uiTimeout;

	if (NULL == pData) {
		goto END;
	}

	for(iIdx = 0; iIdx < pData->iMaxHddNum; iIdx++) {
		pUnplugMonitor = NULL;
		pData->iProcessingIdx = iIdx;

#if defined(MY_DEF_HERE)
		syno_pch_lpc_gpio_pin(pData->iHddPrzPinMap[iIdx], &iPrzPinVal, 0);
#else
		if (gblInversePresent)
			iPrzPinVal = !gpio_get_value(pData->iHddPrzPinMap[iIdx]);
		else
			iPrzPinVal = gpio_get_value(pData->iHddPrzPinMap[iIdx]);
#endif

		if(pData->blHddEnStat[iIdx] != iPrzPinVal) {
			if(iPrzPinVal) {
				 
				pUnplugMonitor = kthread_run(syno_hddmon_unplug_monitor, pData, SYNO_HDDMON_UPLG_STR);
			}

#if defined(MY_DEF_HERE)
			syno_pch_lpc_gpio_pin(pData->iHddEnPinMap[iIdx], &iPrzPinVal, 1);
#else
			gpio_set_value(pData->iHddEnPinMap[iIdx], iPrzPinVal);
#endif
			pData->blHddEnStat[iIdx] = iPrzPinVal;

			if(iPrzPinVal) {
				uiTimeout = SYNO_HDDMON_EN_WAIT_SEC * HZ;
				do{
					set_current_state(TASK_INTERRUPTIBLE);
					uiTimeout = schedule_timeout(uiTimeout);
				}while(uiTimeout);
			}

			if(NULL != pUnplugMonitor) {
				kthread_stop(pUnplugMonitor);
			}
		}
	}

END:
	return;
}

static void syno_hddmon_sync(SynoHddMonData_t *pData)
{
	int iIdx;
	int iPrzPinVal;

	if (NULL == pData) {
		goto END;
	}

	for(iIdx = 0; iIdx < pData->iMaxHddNum; iIdx++) {
		pData->iProcessingIdx = iIdx;

#if defined(MY_DEF_HERE)
		syno_pch_lpc_gpio_pin(pData->iHddPrzPinMap[iIdx], &iPrzPinVal, 0);
#else
		if (gblInversePresent)
			iPrzPinVal = !gpio_get_value(pData->iHddPrzPinMap[iIdx]);
		else
			iPrzPinVal = gpio_get_value(pData->iHddPrzPinMap[iIdx]);
#endif
		 
		if(!iPrzPinVal) {
#if defined(MY_DEF_HERE)
			syno_pch_lpc_gpio_pin(pData->iHddEnPinMap[iIdx], &iPrzPinVal, 1);
#else
			gpio_set_value(pData->iHddEnPinMap[iIdx], iPrzPinVal);
#endif
		}

		pData->blHddEnStat[iIdx] = iPrzPinVal;

	}

END:
	return;
}
static int syno_hddmon_routine(void *args)
{
	int iRet = -1;
	SynoHddMonData_t *pData = NULL;
	unsigned int uiTimeout;

	if (NULL == args) {
		goto END;
	}

	pData = (SynoHddMonData_t *) args;

	while(1) {
		if (kthread_should_stop()) {
			break;
		}

		syno_hddmon_task(pData);

		uiTimeout = SYNO_HDDMON_POLL_SEC * HZ;
		do{
			set_current_state(TASK_INTERRUPTIBLE);
			uiTimeout = schedule_timeout(uiTimeout);
		}while(uiTimeout);
	}

	iRet = 0;
END:
	return iRet;
}

static int __init syno_hddmon_init(void)
{
	int iRet = -1;

#ifdef MY_ABC_HERE
	gblInversePresent = 1;
#endif

	iRet = syno_hddmon_data_init(&synoHddMonData);
	if( 0 > iRet) {
		goto END;
	}

	syno_hddmon_sync(&synoHddMonData);

	pHddPrzPolling = kthread_create(syno_hddmon_routine, &synoHddMonData, SYNO_HDDMON_STR);

	if (IS_ERR(pHddPrzPolling)) {
		iRet = PTR_ERR(pHddPrzPolling);
		pHddPrzPolling = NULL;
		goto END;
	}

	wake_up_process(pHddPrzPolling);

	iRet = 0;
END:
	return iRet;
}

static void __exit syno_hddman_exit(void)
{
	if(pHddPrzPolling) {
		kthread_stop(pHddPrzPolling);
	}
}

MODULE_AUTHOR("Yikai Peng");
MODULE_DESCRIPTION("Syno_HddMon\n");
MODULE_LICENSE("Synology Inc.");

module_init(syno_hddmon_init);
module_exit(syno_hddman_exit);
