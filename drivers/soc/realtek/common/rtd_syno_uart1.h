#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/* Copyright (c) 2016 Synology Inc. All rights reserved. */
#ifndef _RTD_SYNO_UART1_H_
#define _RTD_SYNO_UART1_H_

// RTK connect with UART
#ifdef MY_DEF_HERE
#define RTK_RSTN_UR1_ADDR               0x98000004
#define RTK_CLK_EN_UR1_ADDR             0x98000010
#define RTK_UR1_BASE_ADDR               0x9801b200
#endif /* MY_DEF_HERE */
#ifdef CONFIG_SYNO_RTD1619
#define RTK_RSTN_UR1_ADDR               0x98000004
#define RTK_CLK_EN_UR1_ADDR             0x9800005c
#define RTK_UR1_BASE_ADDR               0x9801b200
#endif /* CONFIG_SYNO_RTD1619 */

// UART cmd
#define SET8N1							0x03 // set LCR 0x03, transfer mode is 8 bit data
#define SOFTWARE_POWER_LED_BLINK		0x35 // set TX 0x35, power LED blinking
#define SOFTWARE_STATUS_LED_OFF			0x37 // set TX 0x37, status gree LED off, orange LED off
#define SOFTWARE_SHUTDOWN				0x31 // set TX 0x31, poweroff
#define SOFTWARE_REBOOT					0x43 // set TX 0x43, reboot

/**
* Init rstn_ur1, clk_en_ur1, base_addr
* @param  None
*
* @return None
*
* @example
* <pre>
* syno_uart1_init();
* </pre>
*
* @see syno_uart1_init
*/
void syno_uart1_init(void);

/**
* Write UART1 on rtd platform
*
* @param[in] cmd Input command: SOFTWARE_SHUTDOWN, SOFTWARE_REBOOT
*
* @return None
*
* @example
* <pre>
* syno_uart1_write(SOFTWARE_SHUTDOWN);
* </pre>
*
* @see syno_uart1_write
*/
void syno_uart1_write(u32 cmd);

#endif /* _RTD_SYNO_UART1_H_ */
