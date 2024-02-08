#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// Copyright (c) 2000-2020 Synology Inc. All rights reserved.

#include <linux/synolib.h>
#include <linux/synobios.h>

#include "libsyno_report.h"

#if defined(MY_DEF_HERE)
FUNC_SYNOBIOS_EVENT funcSYNOSendScsiErrorEvent = NULL;
EXPORT_SYMBOL(funcSYNOSendScsiErrorEvent);

void SynoSendScsiErrorEvent(struct work_struct *work)
{
	struct scsi_device *psdev =
		container_of(work, struct scsi_device, sendScsiErrorEventTask);

	if (funcSYNOSendScsiErrorEvent && psdev) {
		funcSYNOSendScsiErrorEvent(psdev->scsiErrorEventParm);
	}
}

static inline unsigned int
SynoAssembleScsiSense(u8 sense_key, u8 asc, u8 ascq)
{
	return (((sense_key & 0xFF) << 16)
			| ((asc & 0xFF) << 8) | ((ascq & 0xFF)));
}

void SynoScsiErrorWithSenseReport(struct scsi_device *psdev,
		u8 sense_key, u8 asc, u8 ascq, sector_t lba)
{
	int index = -1;

#ifdef MY_ABC_HERE
	index = SynoScsiDeviceToDiskIndex(psdev);
#endif /* MY_ABC_HERE */
	if (0 <= index) {
		psdev->scsiErrorEventParm.data1 = SYNO_SCSI_ERROR_WITH_SENSE;
		psdev->scsiErrorEventParm.data2 = index;
		psdev->scsiErrorEventParm.data3 =
			SynoAssembleScsiSense(sense_key, asc, ascq);
		psdev->scsiErrorEventParm.data4 = lba;
		schedule_work(&(psdev->sendScsiErrorEventTask));
	}
}

void SynoScsiTimeoutReport(struct scsi_device *psdev,
		unsigned char op, int iRetries)
{
	int index = -1;

#ifdef MY_ABC_HERE
	index = SynoScsiDeviceToDiskIndex(psdev);
#endif /* MY_ABC_HERE */
	if (0 <= index) {
		psdev->scsiErrorEventParm.data1 = SYNO_SCSI_ERROR_TIMEOUT;
		psdev->scsiErrorEventParm.data2 = index;
		psdev->scsiErrorEventParm.data3 = op;
		psdev->scsiErrorEventParm.data4 = iRetries;
		schedule_work(&(psdev->sendScsiErrorEventTask));
	}
}
#endif /* MY_DEF_HERE */

