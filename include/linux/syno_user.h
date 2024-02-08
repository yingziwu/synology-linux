#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/* Copyright (c) 2010 Synology Inc. All rights reserved. */

#ifndef __SYNO_USER_H_
#define __SYNO_USER_H_

/**
 * Dsc: Synology multimedia server feature. For indexing video, photo,
 *      music.
 * Ref: libsynosdk, lnxnetatalk, lnxsdk, rsync, samba, smbftpd
 */
#define SYNO_INDEX_SHARES		"photo,video,music"

/**
 * Dsc: This definition is used to enhance samba's performance. 
 *      This modify should sync with samba
 */

/**
 * Dsc: This modify should sync with netatalk
 */
#define SYNO_EA

/**
 * Dsc: This modify should sync with samba
 */

#ifdef MY_ABC_HERE
#define SYNO_MAXPATH    4095
#define SYNO_MAXNAME    491
#endif

/**
 * Fix: DS20 bug #1405
 * Dsc: Avoid scan all inodes of ext3 while doing quotacheck
 */

#if defined(SYNOPLAT_F_X86_64)
#define SYNO_RESIZE_INODE_SIZE_EXTEND_USER
#endif

#endif /* __SYNO_USER_H_ */
