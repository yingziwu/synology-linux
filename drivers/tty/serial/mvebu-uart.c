#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined(MY_DEF_HERE)
/*
* ***************************************************************************
* Copyright (C) 2015 Marvell International Ltd.
* ***************************************************************************
* This program is free software: you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the Free
* Software Foundation, either version 2 of the License, or any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ***************************************************************************
*/

#ifdef MY_DEF_HERE
#if defined(CONFIG_SERIAL_MVEBU_CONSOLE) && defined(CONFIG_MAGIC_SYSRQ)
#define SUPPORT_SYSRQ
#include <linux/sysrq.h>
#endif /* CONFIG_SERIAL_MVEBU_CONSOLE && CONFIG_MAGIC_SYSRQ */
#endif /* MY_DEF_HERE */

#include <linux/clk.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/serial.h>
#include <linux/serial_core.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>

#if defined(MY_DEF_HERE)
#ifdef MY_DEF_HERE
void __iomem *syno_uart1_base;
EXPORT_SYMBOL(syno_uart1_base);
#define PORT1_BASE 0xD0012200
#endif /* MY_DEF_HERE */

enum reg_uart_type {
	REG_UART_A3700,
	REG_UART_A3700_EXT,
};

struct uart_regs_layout {
	unsigned int uart_ctrl;
	unsigned int uart_ctrl2;
	unsigned int uart_rbr;
	unsigned int uart_tsh;
	unsigned int uart_brdv;
	unsigned int uart_stat;
	unsigned int uart_over_sample;
};
#endif /* MY_DEF_HERE */
/* Register Map */
#if defined(MY_DEF_HERE)

/* REG_UART_A3700 */
#endif /* MY_DEF_HERE */
#define UART_RBR		0x00
#define  RBR_BRK_DET		BIT(15)
#define  RBR_FRM_ERR_DET	BIT(14)
#define  RBR_PAR_ERR_DET	BIT(13)
#define  RBR_OVR_ERR_DET	BIT(12)

#define UART_TSH		0x04

#define UART_CTRL		0x08
#define  CTRL_SOFT_RST		BIT(31)
#define  CTRL_TXFIFO_RST	BIT(15)
#define  CTRL_RXFIFO_RST	BIT(14)
#define  CTRL_ST_MIRR_EN	BIT(13)
#define  CTRL_LPBK_EN		BIT(12)
#define  CTRL_SND_BRK_SEQ	BIT(11)
#define  CTRL_PAR_EN		BIT(10)
#define  CTRL_TWO_STOP		BIT(9)
#define  CTRL_TX_HFL_INT	BIT(8)
#define  CTRL_RX_HFL_INT	BIT(7)
#define  CTRL_TX_EMP_INT	BIT(6)
#define  CTRL_TX_RDY_INT	BIT(5)
#define  CTRL_RX_RDY_INT	BIT(4)
#define  CTRL_BRK_DET_INT	BIT(3)
#define  CTRL_FRM_ERR_INT	BIT(2)
#define  CTRL_PAR_ERR_INT	BIT(1)
#define  CTRL_OVR_ERR_INT	BIT(0)
#if defined(MY_DEF_HERE)
#define  CTRL_BRK_INT		(CTRL_BRK_DET_INT | CTRL_FRM_ERR_INT\
				 | CTRL_PAR_ERR_INT | CTRL_OVR_ERR_INT)
#else /* MY_DEF_HERE */
#define  CTRL_RX_INT			(CTRL_RX_RDY_INT | CTRL_BRK_DET_INT |\
	CTRL_FRM_ERR_INT | CTRL_PAR_ERR_INT | CTRL_OVR_ERR_INT)
#endif /* MY_DEF_HERE */

#define UART_STAT		0x0c
#define  STAT_TX_FIFO_EMP	BIT(13)
#define  STAT_RX_FIFO_EMP	BIT(12)
#define  STAT_TX_FIFO_FUL	BIT(11)
#define  STAT_TX_FIFO_HFL	BIT(10)
#define  STAT_RX_TOGL		BIT(9)
#define  STAT_RX_FIFO_FUL	BIT(8)
#define  STAT_RX_FIFO_HFL	BIT(7)
#define  STAT_TX_EMP		BIT(6)
#define  STAT_TX_RDY		BIT(5)
#define  STAT_RX_RDY		BIT(4)
#define  STAT_BRK_DET		BIT(3)
#define  STAT_FRM_ERR		BIT(2)
#define  STAT_PAR_ERR		BIT(1)
#define  STAT_OVR_ERR		BIT(0)
#define  STAT_BRK_ERR		(STAT_BRK_DET | STAT_FRM_ERR | STAT_FRM_ERR\
				 | STAT_PAR_ERR | STAT_OVR_ERR)

#define UART_BRDV		0x10
#if defined(MY_DEF_HERE)
#define  BAUD_MASK		0x000003ff
#define  BAUD_OFFSET		0

#define UART_OSAMP		0x14

/* REG_UART_A3700_EXT */
#define UART_EXT_CTRL		0x04

#define UART_EXT_STAT		0x0c
#define  EXT_STAT_TX_RDY_1B		BIT(15)
#define  EXT_STAT_RX_RDY_1B		BIT(14)

#define UART_EXT_BRDV		0x10

#define UART_EXT_OSAMP		0x14

#define UART_EXT_RBR_1BYTE	0x18
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
#define UART_EXT_TSH_1BYTE	0x1c

#define UART_EXT_CTRL2		0x20
#define EXT_CTRL2_TX_RDY_INT_1B	BIT(6)
#define EXT_CTRL2_RX_RDY_INT_1B	BIT(5)

/* REG_NORTH_BRIDGE_FOR_UART_A3700_EXT */
/* UART Interrupt Registers are not part of UART Register space.
 * It is in the common North Bridge Interrupt register space.
 *
 * UART Interrupt Select register:
 * The Uart interrupt could be either level triggered or pulse trigger.
 * By default, the interrupt mode is level triggered - '0'.
 * In order to enable the pulse interrupt select register, the UART
 * Interrupt Select register MUST be setted to '1'.
 */
#define NORTH_BRIDGE_UART_EXT_INT_SEL	0x1c
#define UART_EXT_TX_INT_SEL		BIT(27)
#define UART_EXT_RX_INT_SEL		BIT(26)

/* UART Interrupt State register*/
#define NORTH_BRIDGE_UART_EXT_INT_STAT	0x10
#define UART_EXT_STAT_TX_INT		BIT(27)
#define UART_EXT_STAT_RX_INT		BIT(26)

/* UART register layout definitions */
static struct uart_regs_layout uart_regs_layout[] = {
	[REG_UART_A3700] = {
		.uart_ctrl = UART_CTRL,
		.uart_rbr  = UART_RBR,
		.uart_tsh  = UART_TSH,
		.uart_brdv = UART_BRDV,
		.uart_stat = UART_STAT,
		.uart_over_sample = UART_OSAMP,
	},
	[REG_UART_A3700_EXT] = {
		.uart_ctrl  = UART_EXT_CTRL,
		.uart_ctrl2 = UART_EXT_CTRL2,
		.uart_rbr   = UART_EXT_RBR_1BYTE,
		.uart_tsh   = UART_EXT_TSH_1BYTE,
		.uart_brdv  = UART_EXT_BRDV,
		.uart_stat  = UART_EXT_STAT,
		.uart_over_sample = UART_EXT_OSAMP,
	},
};

#define MVEBU_NR_UARTS		2
#else /* MY_DEF_HERE */
#define MVEBU_NR_UARTS		1
#endif /* MY_DEF_HERE */

#define MVEBU_UART_TYPE		"mvebu-uart"
#define DRIVER_NAME		"mvebu-serial"

static struct uart_port mvebu_uart_ports[MVEBU_NR_UARTS];

struct mvebu_uart_data {
#if defined(MY_DEF_HERE)
	struct uart_port        *port;
	struct clk              *clk;
	struct uart_regs_layout *regs;
	enum reg_uart_type       reg_type;
#if defined(MY_DEF_HERE)
	spinlock_t               tx_lock;
#endif /* MY_DEF_HERE */

#ifdef CONFIG_PM
	/* Used to restore the uart registers status*/
	struct uart_regs_layout pm_reg_value;
	/* Used to restore the uart interrupt type */
	unsigned int		uart_ext_int_type;
#endif

	struct {
		unsigned int (*ctrl_rx_rdy_int)(struct mvebu_uart_data *data);
		unsigned int (*ctrl_tx_rdy_int)(struct mvebu_uart_data *data);
		unsigned int (*stat_rx_rdy)(struct mvebu_uart_data *data);
		unsigned int (*stat_tx_rdy)(struct mvebu_uart_data *data);
	} reg_bits;

	struct {
		unsigned int ctrl_reg;
		/* Uart summary interrupt includes the TX and RX interrupts
		 * if the uart port uses summary interrupt, TX/RX interrupts
		 * are not needed any more. Otherwise if the uart port doen't
		 * use summary irq, TX/RX interrupts need to be handled separately.
		 */
		int irq_sum;
		int irq_rx;
		int irq_tx;
		/* Uart_int_base is the North Bridge Interrupt Register base.
		 * It is necessary to fetch the Interrupt Status register and Interrupt
		 * Select register.
		 * It is used for setting Uart TX and RX interrupt trigger mode
		 * and clearing the TX/RX interrupt in the ISR.
		 */
		unsigned char __iomem *uart_int_base;
	} intr;
#else /* MY_DEF_HERE */
	struct uart_port *port;
	struct clk       *clk;
#endif /* MY_DEF_HERE */
};

#if defined(MY_DEF_HERE)
#define REG_CTRL(uart_data)	((uart_data)->regs->uart_ctrl)
#define REG_CTRL2(uart_data)	((uart_data)->regs->uart_ctrl2)
#define REG_RBR(uart_data)	((uart_data)->regs->uart_rbr)
#define REG_TSH(uart_data)	((uart_data)->regs->uart_tsh)
#define REG_BRDV(uart_data)	((uart_data)->regs->uart_brdv)
#define REG_STAT(uart_data)	((uart_data)->regs->uart_stat)
#define REG_OSAMP(uart_data)	((uart_data)->regs->uart_over_sample)

/* helper functions for 1-byte transfer */
static inline unsigned int get_ctrl_rx_1byte_rdy_int(struct mvebu_uart_data *data)
{
	switch (data->reg_type) {
	case REG_UART_A3700:
		return CTRL_RX_RDY_INT;
	case REG_UART_A3700_EXT:
		return EXT_CTRL2_RX_RDY_INT_1B;
	default:
		break;
	}
	return 0;
}

static inline unsigned int get_ctrl_tx_1byte_rdy_int(struct mvebu_uart_data *data)
{
	switch (data->reg_type) {
	case REG_UART_A3700:
		return CTRL_TX_RDY_INT;
	case REG_UART_A3700_EXT:
		return EXT_CTRL2_TX_RDY_INT_1B;
	default:
		break;
	}
	return 0;
}

static inline unsigned int get_stat_rx_1byte_rdy(struct mvebu_uart_data *data)
{
	switch (data->reg_type) {
	case REG_UART_A3700:
		return STAT_RX_RDY;
	case REG_UART_A3700_EXT:
		return EXT_STAT_RX_RDY_1B;
	default:
		break;
	}
	return 0;
}

static inline unsigned int get_stat_tx_1byte_rdy(struct mvebu_uart_data *data)
{
	switch (data->reg_type) {
	case REG_UART_A3700:
		return STAT_TX_RDY;
	case REG_UART_A3700_EXT:
		return EXT_STAT_TX_RDY_1B;
	default:
		break;
	}
	return 0;
}

#endif /* MY_DEF_HERE */
/* Core UART Driver Operations */
static unsigned int mvebu_uart_tx_empty(struct uart_port *port)
{
	unsigned long flags;
	unsigned int st;
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#endif /* MY_DEF_HERE */

	spin_lock_irqsave(&port->lock, flags);
#if defined(MY_DEF_HERE)
	st = readl(port->membase + REG_STAT(uart_data));
#else /* MY_DEF_HERE */
	st = readl(port->membase + UART_STAT);
#endif /* MY_DEF_HERE */
	spin_unlock_irqrestore(&port->lock, flags);

	return (st & STAT_TX_FIFO_EMP) ? TIOCSER_TEMT : 0;
}

static unsigned int mvebu_uart_get_mctrl(struct uart_port *port)
{
	return TIOCM_CTS | TIOCM_DSR | TIOCM_CAR;
}

static void mvebu_uart_set_mctrl(struct uart_port *port,
				 unsigned int mctrl)
{
/*
 * Even if we do not support configuring the modem control lines, this
 * function must be proided to the serial core
 */
}

static void mvebu_uart_stop_tx(struct uart_port *port)
{
#if defined(MY_DEF_HERE)
	unsigned int ctl;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#else /* MY_DEF_HERE */
	unsigned int ctl = readl(port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	ctl = readl(port->membase + uart_data->intr.ctrl_reg);
	ctl &= ~uart_data->reg_bits.ctrl_tx_rdy_int(uart_data);
	writel(ctl, port->membase + uart_data->intr.ctrl_reg);
#else /* MY_DEF_HERE */
	ctl &= ~CTRL_TX_RDY_INT;
	writel(ctl, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */
}

#if defined(MY_DEF_HERE)
/* mvebu_uart_tx_lock:
 * This lock is only used to lock the TX data when pulse interrupt is enabled.
 */
#define mvebu_uart_tx_lock(uart_data, flags)							\
do {												\
	if (!IS_ERR_OR_NULL(uart_data->intr.uart_int_base)) {					\
		spin_lock_irqsave(&uart_data->tx_lock, flags);					\
	}											\
} while (0)

/* mvebu_uart_tx_unlock:
 * This lock is only used to lock the TX data when pulse interrupt is enabled.
 */
#define mvebu_uart_tx_unlock(uart_data, flags)							\
do {												\
	if (!IS_ERR_OR_NULL(uart_data->intr.uart_int_base)) {					\
		spin_unlock_irqrestore(&uart_data->tx_lock, flags);				\
	}											\
} while (0)
#endif /* MY_DEF_HERE */

static void mvebu_uart_start_tx(struct uart_port *port)
{
#if defined(MY_DEF_HERE)
	unsigned int ctl;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
	struct circ_buf *xmit = &port->state->xmit;
#if defined(MY_DEF_HERE)
	unsigned long flags = 0;
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	unsigned int ctl = readl(port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
#if defined(MY_DEF_HERE)
	/* When Armada37x0 works with pulse interrupt, the TX interrupt
	 * is triggered only when TX FIFO state transmites in following
	 * two scenarios:
	 * - FIFO FULL => FIFO NON-FULL
	 * - FIFO EMPTY => FIFO NON-FULL
	 *
	 * In order to transmit the sequential data, the driver send out
	 * the first byte to toggle the FIFO state. And the rest bytes
	 * are supposed to be sent out until TX READY interrupt comes.
	 */
	ctl = readl(port->membase + uart_data->intr.ctrl_reg);
	ctl |= uart_data->reg_bits.ctrl_tx_rdy_int(uart_data);
	writel(ctl, port->membase + uart_data->intr.ctrl_reg);
	/* Use spin_lock to lock the action that write one character to tx fifo.
	 * This can prevent the tx interrupt from breaking the writing action.
	 */
	mvebu_uart_tx_lock(uart_data, flags);
#endif /* MY_DEF_HERE */
	if (!IS_ERR_OR_NULL(uart_data->intr.uart_int_base)) {
		if (!uart_circ_empty(xmit)) {
			writel(xmit->buf[xmit->tail], port->membase + REG_TSH(uart_data));
			xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
			port->icount.tx++;
		}
	}
#if defined(MY_DEF_HERE)
	mvebu_uart_tx_unlock(uart_data, flags);
#else /* MY_DEF_HERE */
	ctl = readl(port->membase + uart_data->intr.ctrl_reg);
	ctl |= uart_data->reg_bits.ctrl_tx_rdy_int(uart_data);
	writel(ctl, port->membase + uart_data->intr.ctrl_reg);
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	ctl |= CTRL_TX_RDY_INT;
	writel(ctl, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_stop_rx(struct uart_port *port)
{
#if defined(MY_DEF_HERE)
	unsigned int ctl;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#else /* MY_DEF_HERE */
	unsigned int ctl = readl(port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	ctl = readl(port->membase + REG_CTRL(uart_data));
	ctl &= ~CTRL_BRK_INT;
	writel(ctl, port->membase + REG_CTRL(uart_data));

	ctl = readl(port->membase + uart_data->intr.ctrl_reg);
	ctl &= ~uart_data->reg_bits.ctrl_rx_rdy_int(uart_data);
	writel(ctl, port->membase + uart_data->intr.ctrl_reg);
#else /* MY_DEF_HERE */
	ctl &= ~CTRL_RX_INT;
	writel(ctl, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_break_ctl(struct uart_port *port, int brk)
{
	unsigned int ctl;
	unsigned long flags;
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#else /* MY_DEF_HERE */

#endif /* MY_DEF_HERE */
	spin_lock_irqsave(&port->lock, flags);
#if defined(MY_DEF_HERE)
	ctl = readl(port->membase + REG_CTRL(uart_data));
#else /* MY_DEF_HERE */
	ctl = readl(port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */
	if (brk == -1)
		ctl |= CTRL_SND_BRK_SEQ;
	else
		ctl &= ~CTRL_SND_BRK_SEQ;
#if defined(MY_DEF_HERE)
	writel(ctl, port->membase + REG_CTRL(uart_data));
#else /* MY_DEF_HERE */
	writel(ctl, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */
	spin_unlock_irqrestore(&port->lock, flags);
}

static void mvebu_uart_rx_chars(struct uart_port *port, unsigned int status)
{
	struct tty_port *tport = &port->state->port;
	unsigned char ch = 0;
	char flag = 0;
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
	unsigned int stat_bit_rx_rdy = uart_data->reg_bits.stat_rx_rdy(uart_data);
#endif /* MY_DEF_HERE */

	do {
#if defined(MY_DEF_HERE)
		if (status & stat_bit_rx_rdy) {
			ch = readl(port->membase + REG_RBR(uart_data));
#else /* MY_DEF_HERE */
		if (status & STAT_RX_RDY) {
			ch = readl(port->membase + UART_RBR);
#endif /* MY_DEF_HERE */
			ch &= 0xff;
			flag = TTY_NORMAL;
			port->icount.rx++;

			if (status & STAT_PAR_ERR)
				port->icount.parity++;
		}

#ifdef MY_DEF_HERE
		/* This is a workaround to prevent from break
		 * cmd flushing.
		 */
		if ((status & STAT_BRK_DET) && !port->sysrq) {
#else /* MY_DEF_HERE */
		if (status & STAT_BRK_DET) {
#endif /* MY_DEF_HERE */
			port->icount.brk++;
			status &= ~(STAT_FRM_ERR | STAT_PAR_ERR);
			if (uart_handle_break(port))
				goto ignore_char;
		}

		if (status & STAT_OVR_ERR)
			port->icount.overrun++;

		if (status & STAT_FRM_ERR)
			port->icount.frame++;

		if (uart_handle_sysrq_char(port, ch))
			goto ignore_char;

		if (status & port->ignore_status_mask & STAT_PAR_ERR)
#if defined(MY_DEF_HERE)
			status &= ~stat_bit_rx_rdy;
#else /* MY_DEF_HERE */
			status &= ~STAT_RX_RDY;
#endif /* MY_DEF_HERE */

		status &= port->read_status_mask;

		if (status & STAT_PAR_ERR)
			flag = TTY_PARITY;

		status &= ~port->ignore_status_mask;

#if defined(MY_DEF_HERE)
		if (status & stat_bit_rx_rdy)
#else /* MY_DEF_HERE */
		if (status & STAT_RX_RDY)
#endif /* MY_DEF_HERE */
			tty_insert_flip_char(tport, ch, flag);

		if (status & STAT_BRK_DET)
			tty_insert_flip_char(tport, 0, TTY_BREAK);

		if (status & STAT_FRM_ERR)
			tty_insert_flip_char(tport, 0, TTY_FRAME);

		if (status & STAT_OVR_ERR)
			tty_insert_flip_char(tport, 0, TTY_OVERRUN);

ignore_char:
#if defined(MY_DEF_HERE)
		status = readl(port->membase + REG_STAT(uart_data));
	} while (status & (stat_bit_rx_rdy | STAT_BRK_DET));
#else /* MY_DEF_HERE */
		status = readl(port->membase + UART_STAT);
	} while (status & (STAT_RX_RDY | STAT_BRK_DET));
#endif /* MY_DEF_HERE */

	tty_flip_buffer_push(tport);
}

static void mvebu_uart_tx_chars(struct uart_port *port, unsigned int status)
{
	struct circ_buf *xmit = &port->state->xmit;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	unsigned int count;
#endif /* MY_DEF_HERE */
	unsigned int st;
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#endif /* MY_DEF_HERE */

	if (port->x_char) {
#if defined(MY_DEF_HERE)
		writel(port->x_char, port->membase + REG_TSH(uart_data));
#else /* MY_DEF_HERE */
		writel(port->x_char, port->membase + UART_TSH);
#endif /* MY_DEF_HERE */
		port->icount.tx++;
		port->x_char = 0;
		return;
	}

	if (uart_circ_empty(xmit) || uart_tx_stopped(port)) {
		mvebu_uart_stop_tx(port);
		return;
	}

#if defined(MY_DEF_HERE)
	for (;;) {
		writel(xmit->buf[xmit->tail], port->membase + REG_TSH(uart_data));
#else /* MY_DEF_HERE */
	for (count = 0; count < port->fifosize; count++) {
		writel(xmit->buf[xmit->tail], port->membase + UART_TSH);
#endif /* MY_DEF_HERE */
		xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
		port->icount.tx++;

		if (uart_circ_empty(xmit))
			break;

#if defined(MY_DEF_HERE)
		st = readl(port->membase + REG_STAT(uart_data));
#else /* MY_DEF_HERE */
		st = readl(port->membase + UART_STAT);
#endif /* MY_DEF_HERE */
		if (st & STAT_TX_FIFO_FUL)
			break;
	}

	if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
		uart_write_wakeup(port);

	if (uart_circ_empty(xmit))
		mvebu_uart_stop_tx(port);
}

static irqreturn_t mvebu_uart_isr(int irq, void *dev_id)
{
	struct uart_port *port = (struct uart_port *)dev_id;
#if defined(MY_DEF_HERE)
	unsigned int st;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#if defined(MY_DEF_HERE)
	unsigned long flags = 0;
#endif /* MY_DEF_HERE */

	st = readl(port->membase + REG_STAT(uart_data));
#else /* MY_DEF_HERE */
	unsigned int st = readl(port->membase + UART_STAT);
#endif /* MY_DEF_HERE */

	if (st & (STAT_RX_RDY | STAT_OVR_ERR | STAT_FRM_ERR | STAT_BRK_DET))
		mvebu_uart_rx_chars(port, st);

	if (st & STAT_TX_RDY)
#if defined(MY_DEF_HERE)
	{
		mvebu_uart_tx_lock(uart_data, flags);
#endif /* MY_DEF_HERE */
		mvebu_uart_tx_chars(port, st);
#if defined(MY_DEF_HERE)
		mvebu_uart_tx_unlock(uart_data, flags);
	}
#endif /* MY_DEF_HERE */

	return IRQ_HANDLED;
}

#if defined(MY_DEF_HERE)
static irqreturn_t mvebu_uart_rx_isr(int irq, void *dev_id)
{
	struct uart_port *port = (struct uart_port *)dev_id;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
	unsigned int st = readl(port->membase + REG_STAT(uart_data));
	unsigned int stat_bit_rx_rdy = uart_data->reg_bits.stat_rx_rdy(uart_data);

	if (st & (stat_bit_rx_rdy | STAT_OVR_ERR | STAT_FRM_ERR | STAT_BRK_DET))
		mvebu_uart_rx_chars(port, st);

	if (!IS_ERR_OR_NULL(uart_data->intr.uart_int_base)) {
		st = readl(uart_data->intr.uart_int_base + NORTH_BRIDGE_UART_EXT_INT_STAT);
		/* Clear the RX Interrupt State Register*/
		writel(st | UART_EXT_STAT_RX_INT, uart_data->intr.uart_int_base + NORTH_BRIDGE_UART_EXT_INT_STAT);
	}
	return IRQ_HANDLED;
}

static irqreturn_t mvebu_uart_tx_isr(int irq, void *dev_id)
{
	struct uart_port *port = (struct uart_port *)dev_id;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
	unsigned int st = readl(port->membase + REG_STAT(uart_data));
	unsigned int stat_bit_tx_rdy = uart_data->reg_bits.stat_tx_rdy(uart_data);
#if defined(MY_DEF_HERE)
	unsigned long flags = 0;
#endif /* MY_DEF_HERE */

	if (st & stat_bit_tx_rdy)
#if defined(MY_DEF_HERE)
	{
		mvebu_uart_tx_lock(uart_data, flags);
#endif /* MY_DEF_HERE */
		mvebu_uart_tx_chars(port, st);
#if defined(MY_DEF_HERE)
		mvebu_uart_tx_unlock(uart_data, flags);
	}
#endif /* MY_DEF_HERE */

	if (!IS_ERR_OR_NULL(uart_data->intr.uart_int_base)) {
		st = readl(uart_data->intr.uart_int_base + NORTH_BRIDGE_UART_EXT_INT_STAT);
		/* Clear the TX Interrupt State Register*/
		writel(st | UART_EXT_STAT_TX_INT, uart_data->intr.uart_int_base + NORTH_BRIDGE_UART_EXT_INT_STAT);
	}
	return IRQ_HANDLED;
}

static int mvebu_uart_irq_request(struct uart_port *port)
{
	int ret = 0;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;

	if (uart_data->intr.irq_sum > 0) {
		ret = request_irq(port->irq, mvebu_uart_isr, port->irqflags, DRIVER_NAME, port);
		if (ret) {
			dev_err(port->dev, "failed to request irq\n");
			return ret;
		}
	} else if ((uart_data->intr.irq_rx > 0) && (uart_data->intr.irq_tx > 0)) {
		ret = request_irq(uart_data->intr.irq_rx, mvebu_uart_rx_isr, IRQF_SHARED, DRIVER_NAME"-rx", port);
		if (ret) {
			dev_err(port->dev, "failed to request rx irq\n");
			return ret;
		}
		ret = request_irq(uart_data->intr.irq_tx, mvebu_uart_tx_isr, IRQF_SHARED, DRIVER_NAME"-tx", port);
		if (ret) {
			dev_err(port->dev, "failed to request tx irq\n");
			return ret;
		}
	}

	return ret;
}

#endif /* MY_DEF_HERE */
static int mvebu_uart_startup(struct uart_port *port)
{
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#if defined(MY_DEF_HERE)
	unsigned int ctl, ret;
#else /* MY_DEF_HERE */
	unsigned int ctl;
#endif /* MY_DEF_HERE */
#else /* MY_DEF_HERE */
	int ret;
#endif /* MY_DEF_HERE */

	writel(CTRL_TXFIFO_RST | CTRL_RXFIFO_RST,
#if defined(MY_DEF_HERE)
		port->membase + REG_CTRL(uart_data));
#else /* MY_DEF_HERE */
	       port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */
	udelay(1);
#if defined(MY_DEF_HERE)

	/* Clear the Error bits of state reg before irq request */
	ret = readl(port->membase + REG_STAT(uart_data));
	ret |= STAT_BRK_ERR;
	writel(ret, port->membase + REG_STAT(uart_data));

#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	writel(CTRL_BRK_INT, port->membase + REG_CTRL(uart_data));
	ctl = readl(port->membase + uart_data->intr.ctrl_reg);
	ctl |= uart_data->reg_bits.ctrl_rx_rdy_int(uart_data);
	writel(ctl, port->membase + uart_data->intr.ctrl_reg);
#else /* MY_DEF_HERE */
	writel(CTRL_RX_INT, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	/* Requset irq_sum, irq_tx, irq_rx separately for uart ports */
	return mvebu_uart_irq_request(port);
#else /* MY_DEF_HERE */
	ret = request_irq(port->irq, mvebu_uart_isr, port->irqflags, DRIVER_NAME,
			  port);
	if (ret) {
		dev_err(port->dev, "failed to request irq\n");
		return ret;
	}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	return 0;
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_shutdown(struct uart_port *port)
{
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;

	writel(0, port->membase + REG_CTRL(uart_data));
	writel(0, port->membase + uart_data->intr.ctrl_reg);

#if defined(MY_DEF_HERE)
	if (uart_data->intr.irq_sum > 0)
		free_irq(port->irq, port);
	else {
		free_irq(uart_data->intr.irq_tx, port);
		free_irq(uart_data->intr.irq_rx, port);
	}
#else /* MY_DEF_HERE */
	free_irq(port->irq, port);
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_baud_rate_set(struct uart_port *port, unsigned int baud)
{
	unsigned int value;
	unsigned int baud_rate_div;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;

	/* The Uart clock is divided by the value of divisor to generate
	 * UCLK_OUT clock, which is 16 times faster than the target baud rate:
	 * UCLK_OUT = 16 times the taregt baud rate.
	 * So the baudrate divisor can be calculated by:
	 * divisor = input_clock / (baudrate * 16).
	 * The divisor value is round up, and it works well with the baudrate 9600,
	 * 19200, 38400, 57600, 115200, 230400.
	 * But when working with baudrate 460800, the rounding up doesn't work,
	 * since the error per bit frame is 15.2%.
	 * (460800 - (25MHz / (0x4 * 16)))) / 460800 = 15.2%
	 * Theoretically, neither round-up nor round-down will work well. However,
	 * in this case, it needs to use Fractional Divisor when greater baud rate
	 * accuracy is required. UCLK_OUT is no longer fixed at 16 times faster than
	 * the desired baudrate but rather M times the desired baud rate. Where
	 * M = (3*m1 + 3*m2 + 2*m3 +2*m4)/10. (m1, m2, m3, m4) are set with RD0012214h
	 * (UART 2 Programmable Oversampling Stack).
	 * Fraction divisor feature should be supported in the future on demand.
	 */
	if (!IS_ERR(uart_data->clk)) {
		baud_rate_div = DIV_ROUND_UP(port->uartclk, (16 * baud));
		value = readl(port->membase + REG_BRDV(uart_data));
		value &= ~BAUD_MASK;
		value |= baud_rate_div << BAUD_OFFSET;
		writel(value, port->membase + REG_BRDV(uart_data));
	}
#else /* MY_DEF_HERE */
	writel(0, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_set_termios(struct uart_port *port,
				   struct ktermios *termios,
				   struct ktermios *old)
{
	unsigned long flags;
	unsigned int baud;
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
	unsigned int stat_bit_rx_rdy = uart_data->reg_bits.stat_rx_rdy(uart_data);
	unsigned int stat_bit_tx_rdy = uart_data->reg_bits.stat_tx_rdy(uart_data);
#endif /* MY_DEF_HERE */

	spin_lock_irqsave(&port->lock, flags);

#if defined(MY_DEF_HERE)
	port->read_status_mask = stat_bit_rx_rdy | STAT_OVR_ERR |
		stat_bit_tx_rdy | STAT_TX_FIFO_FUL;
#else /* MY_DEF_HERE */
	port->read_status_mask = STAT_RX_RDY | STAT_OVR_ERR |
		STAT_TX_RDY | STAT_TX_FIFO_FUL;
#endif /* MY_DEF_HERE */

	if (termios->c_iflag & INPCK)
		port->read_status_mask |= STAT_FRM_ERR | STAT_PAR_ERR;

	port->ignore_status_mask = 0;
	if (termios->c_iflag & IGNPAR)
		port->ignore_status_mask |=
			STAT_FRM_ERR | STAT_PAR_ERR | STAT_OVR_ERR;

	if ((termios->c_cflag & CREAD) == 0)
#if defined(MY_DEF_HERE)
		port->ignore_status_mask |= stat_bit_rx_rdy | STAT_BRK_ERR;
#else /* MY_DEF_HERE */
		port->ignore_status_mask |= STAT_RX_RDY | STAT_BRK_ERR;

	if (old)
		tty_termios_copy_hw(termios, old);
#endif /* MY_DEF_HERE */

	baud = uart_get_baud_rate(port, termios, old, 0, 460800);
	uart_update_timeout(port, termios->c_cflag, baud);
#if defined(MY_DEF_HERE)
	/* Baud-rate set*/
	mvebu_uart_baud_rate_set(port, baud);
#else /* MY_DEF_HERE */

#endif /* MY_DEF_HERE */
	spin_unlock_irqrestore(&port->lock, flags);
}

static const char *mvebu_uart_type(struct uart_port *port)
{
	return MVEBU_UART_TYPE;
}

static void mvebu_uart_release_port(struct uart_port *port)
{
	/* Nothing to do here */
}

static int mvebu_uart_request_port(struct uart_port *port)
{
	return 0;
}

#ifdef CONFIG_CONSOLE_POLL
static int mvebu_uart_get_poll_char(struct uart_port *port)
{
#if defined(MY_DEF_HERE)
	unsigned int st;
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;

	st = readl(port->membase + REG_STAT(uart_data));
#else /* MY_DEF_HERE */
	unsigned int st = readl(port->membase + UART_STAT);
#endif /* MY_DEF_HERE */

	if (!(st & STAT_RX_RDY))
		return NO_POLL_CHAR;

#if defined(MY_DEF_HERE)
	return readl(port->membase + REG_RBR(uart_data));
#else /* MY_DEF_HERE */
	return readl(port->membase + UART_RBR);
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_put_poll_char(struct uart_port *port, unsigned char c)
{
	unsigned int st;
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#endif /* MY_DEF_HERE */

	for (;;) {
#if defined(MY_DEF_HERE)
		st = readl(port->membase + REG_STAT(uart_data));
#else /* MY_DEF_HERE */
		st = readl(port->membase + UART_STAT);
#endif /* MY_DEF_HERE */

		if (!(st & STAT_TX_FIFO_FUL))
			break;

		udelay(1);
	}

#if defined(MY_DEF_HERE)
	writel(c, port->membase + REG_TSH(uart_data));
#else /* MY_DEF_HERE */
	writel(c, port->membase + UART_TSH);
#endif /* MY_DEF_HERE */
}
#endif

static const struct uart_ops mvebu_uart_ops = {
	.tx_empty	= mvebu_uart_tx_empty,
	.set_mctrl	= mvebu_uart_set_mctrl,
	.get_mctrl	= mvebu_uart_get_mctrl,
	.stop_tx	= mvebu_uart_stop_tx,
	.start_tx	= mvebu_uart_start_tx,
	.stop_rx	= mvebu_uart_stop_rx,
	.break_ctl	= mvebu_uart_break_ctl,
	.startup	= mvebu_uart_startup,
	.shutdown	= mvebu_uart_shutdown,
	.set_termios	= mvebu_uart_set_termios,
	.type		= mvebu_uart_type,
	.release_port	= mvebu_uart_release_port,
	.request_port	= mvebu_uart_request_port,
#ifdef CONFIG_CONSOLE_POLL
	.poll_get_char	= mvebu_uart_get_poll_char,
	.poll_put_char	= mvebu_uart_put_poll_char,
#endif
};

/* Console Driver Operations  */

#ifdef CONFIG_SERIAL_MVEBU_CONSOLE
/* Early Console */
static void mvebu_uart_putc(struct uart_port *port, int c)
{
	unsigned int st;

	for (;;) {
		st = readl(port->membase + UART_STAT);
		if (!(st & STAT_TX_FIFO_FUL))
			break;
	}

	writel(c, port->membase + UART_TSH);

	for (;;) {
		st = readl(port->membase + UART_STAT);
		if (st & STAT_TX_FIFO_EMP)
			break;
	}
}

static void mvebu_uart_putc_early_write(struct console *con,
					const char *s,
					unsigned n)
{
	struct earlycon_device *dev = con->data;

	uart_console_write(&dev->port, s, n, mvebu_uart_putc);
}

static int __init
mvebu_uart_early_console_setup(struct earlycon_device *device,
			       const char *opt)
{
	if (!device->port.membase)
		return -ENODEV;

	device->con->write = mvebu_uart_putc_early_write;

	return 0;
}

EARLYCON_DECLARE(ar3700_uart, mvebu_uart_early_console_setup);
OF_EARLYCON_DECLARE(ar3700_uart, "marvell,armada-3700-uart",
		    mvebu_uart_early_console_setup);

static void wait_for_xmitr(struct uart_port *port)
{
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#endif /* MY_DEF_HERE */
	u32 val;

#if defined(MY_DEF_HERE)
	readl_poll_timeout_atomic(port->membase + REG_STAT(uart_data),
				  val, (val & STAT_TX_EMP), 1, 10000);
#else /* MY_DEF_HERE */
	readl_poll_timeout_atomic(port->membase + UART_STAT, val,
				  (val & STAT_TX_EMP), 1, 10000);
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_console_putchar(struct uart_port *port, int ch)
{
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;

#endif /* MY_DEF_HERE */
	wait_for_xmitr(port);
#if defined(MY_DEF_HERE)
	writel(ch, port->membase + REG_TSH(uart_data));
#else /* MY_DEF_HERE */
	writel(ch, port->membase + UART_TSH);
#endif /* MY_DEF_HERE */
}

static void mvebu_uart_console_write(struct console *co, const char *s,
				     unsigned int count)
{
	struct uart_port *port = &mvebu_uart_ports[co->index];
#if defined(MY_DEF_HERE)
	struct mvebu_uart_data *uart_data = (struct mvebu_uart_data *)port->private_data;
#endif /* MY_DEF_HERE */
	unsigned long flags;
#if defined(MY_DEF_HERE)
	unsigned int ier, intr, ctl;
#else /* MY_DEF_HERE */
	unsigned int ier;
#endif /* MY_DEF_HERE */
	int locked = 1;

	if (oops_in_progress)
		locked = spin_trylock_irqsave(&port->lock, flags);
	else
		spin_lock_irqsave(&port->lock, flags);

#if defined(MY_DEF_HERE)
	ier = readl(port->membase + REG_CTRL(uart_data)) & CTRL_BRK_INT;
	intr = readl(port->membase + uart_data->intr.ctrl_reg);
	intr &= (uart_data->reg_bits.ctrl_rx_rdy_int(uart_data)
		| uart_data->reg_bits.ctrl_tx_rdy_int(uart_data));

	writel(0, port->membase + REG_CTRL(uart_data));
	writel(0, port->membase + uart_data->intr.ctrl_reg);
#else /* MY_DEF_HERE */
	ier = readl(port->membase + UART_CTRL) &
		(CTRL_RX_INT | CTRL_TX_RDY_INT);
	writel(0, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */

	uart_console_write(port, s, count, mvebu_uart_console_putchar);

	wait_for_xmitr(port);

	if (ier)
#if defined(MY_DEF_HERE)
		writel(ier, port->membase + REG_CTRL(uart_data));

	if (intr) {
		ctl = intr | readl(port->membase + uart_data->intr.ctrl_reg);
		writel(ctl, port->membase + uart_data->intr.ctrl_reg);
	}
#else /* MY_DEF_HERE */
		writel(ier, port->membase + UART_CTRL);
#endif /* MY_DEF_HERE */

	if (locked)
		spin_unlock_irqrestore(&port->lock, flags);
}

static int mvebu_uart_console_setup(struct console *co, char *options)
{
	struct uart_port *port;
	int baud = 9600;
	int bits = 8;
	int parity = 'n';
	int flow = 'n';

	if (co->index < 0 || co->index >= MVEBU_NR_UARTS)
		return -EINVAL;

	port = &mvebu_uart_ports[co->index];

	if (!port->mapbase || !port->membase) {
#ifdef MY_DEF_HERE /* MY_DEF_HERE */
		pr_debug("console on ttyS%i not present\n", co->index);
#else /* MY_DEF_HERE */
		pr_debug("console on ttyMV%i not present\n", co->index);
#endif /* MY_DEF_HERE */
		return -ENODEV;
	}

	if (options)
		uart_parse_options(options, &baud, &parity, &bits, &flow);

	return uart_set_options(port, co, baud, parity, bits, flow);
}

static struct uart_driver mvebu_uart_driver;

static struct console mvebu_uart_console = {
#ifdef MY_DEF_HERE /* MY_DEF_HERE */
	.name	= "ttyS",
#else /* MY_DEF_HERE */
	.name	= "ttyMV",
#endif /* MY_DEF_HERE */
	.write	= mvebu_uart_console_write,
	.device	= uart_console_device,
	.setup	= mvebu_uart_console_setup,
	.flags	= CON_PRINTBUFFER,
	.index	= -1,
	.data	= &mvebu_uart_driver,
};

static int __init mvebu_uart_console_init(void)
{
	register_console(&mvebu_uart_console);
	return 0;
}

console_initcall(mvebu_uart_console_init);

#endif /* CONFIG_SERIAL_MVEBU_CONSOLE */

static struct uart_driver mvebu_uart_driver = {
	.owner			= THIS_MODULE,
	.driver_name		= DRIVER_NAME,
#ifdef MY_DEF_HERE /* MY_DEF_HERE */
	.dev_name		= "ttyS",
#else /* MY_DEF_HERE */
	.dev_name		= "ttyMV",
#endif /* MY_DEF_HERE */
	.nr			= MVEBU_NR_UARTS,
#ifdef CONFIG_SERIAL_MVEBU_CONSOLE
	.cons			= &mvebu_uart_console,
#endif
};

#if defined(MY_DEF_HERE)
static const struct of_device_id mvebu_uart_of_match[];

#endif /* MY_DEF_HERE */
static int mvebu_uart_probe(struct platform_device *pdev)
{
	struct resource *reg = platform_get_resource(pdev, IORESOURCE_MEM, 0);
#if defined(MY_DEF_HERE)
	struct resource *uart_int_base = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	struct device_node *np = pdev->dev.of_node;

	int irq_sum = platform_get_irq_byname(pdev, "irq_sum");
	int irq_rx = platform_get_irq_byname(pdev, "irq_rx");
	int irq_tx = platform_get_irq_byname(pdev, "irq_tx");
	const struct of_device_id *match = of_match_device(mvebu_uart_of_match, &pdev->dev);
#else /* MY_DEF_HERE */
	struct resource *irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
#endif /* MY_DEF_HERE */
	struct uart_port *port;
	struct mvebu_uart_data *data;
	int ret;
#if defined(MY_DEF_HERE)
	u32 value;

	if (!reg) {
		dev_err(&pdev->dev, "no registers defined\n");
#else /* MY_DEF_HERE */
	if (!reg || !irq) {
		dev_err(&pdev->dev, "no registers/irq defined\n");
#endif /* MY_DEF_HERE */
		return -EINVAL;
	}

#if defined(MY_DEF_HERE)
	if ((irq_sum < 0) && ((irq_rx < 0) || (irq_tx < 0))) {
		dev_err(&pdev->dev, "no irq defined\n");
		return -EINVAL;
	}

	if (pdev->dev.of_node)
		pdev->id = of_alias_get_id(pdev->dev.of_node, "serial");
#else /* MY_DEF_HERE */
	port = &mvebu_uart_ports[0];
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	if (pdev->id >= MVEBU_NR_UARTS) {
		dev_err(&pdev->dev, "exceed max uart ports\n");
		return -EINVAL;
	}
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
	port = &mvebu_uart_ports[pdev->id];
#endif /* MY_DEF_HERE */

	spin_lock_init(&port->lock);

	port->dev        = &pdev->dev;
	port->type       = PORT_MVEBU;
	port->ops        = &mvebu_uart_ops;
	port->regshift   = 0;

	port->fifosize   = 32;
	port->iotype     = UPIO_MEM32;
	port->flags      = UPF_FIXED_PORT;
#if defined(MY_DEF_HERE)
	port->line       = pdev->id;
#else /* MY_DEF_HERE */
	port->line       = 0; /* single port: force line number to  0 */
#endif /* MY_DEF_HERE */

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	port->irq        = irq->start;
#endif /* MY_DEF_HERE */
	port->irqflags   = IRQF_SHARED;
	port->mapbase    = reg->start;

	port->membase = devm_ioremap_resource(&pdev->dev, reg);
	if (IS_ERR(port->membase))
		return -PTR_ERR(port->membase);

	data = devm_kzalloc(&pdev->dev, sizeof(struct mvebu_uart_data),
			    GFP_KERNEL);
	if (!data)
		return -ENOMEM;

#if defined(MY_DEF_HERE)
	data->reg_type = (enum reg_uart_type)match->data;
	data->regs     = &uart_regs_layout[data->reg_type];
	data->port     = port;

	/* First of all, if sum irq is legal, use sum irq. Otherwise, use tx irq and rx irq.*/
	if (irq_sum > 0) {
		port->irq = irq_sum;
		data->intr.irq_sum = irq_sum;
	} else if ((irq_rx > 0) && (irq_tx > 0)) {
		port->irq = irq_rx;
		data->intr.irq_rx = irq_rx;
		data->intr.irq_tx = irq_tx;
	}

	/* Get fixed-clock frequency*/
	data->clk = of_clk_get(np, 0);
	if (!IS_ERR(data->clk)) {
		ret = clk_prepare_enable(data->clk);
		if (ret) {
			clk_put(data->clk);
			dev_err(&pdev->dev, "failed to get the reference clock\n");
		}
		port->uartclk = clk_get_rate(data->clk);
	}

	/* Set interrupt register bits callbacks */
	/* Todo:
	 *     Set the callbacks according to the transfer mode.
	 *     Now, only 1-byte transfer is supported.
	 */
	data->reg_bits.ctrl_rx_rdy_int = get_ctrl_rx_1byte_rdy_int;
	data->reg_bits.ctrl_tx_rdy_int = get_ctrl_tx_1byte_rdy_int;
	data->reg_bits.stat_rx_rdy     = get_stat_rx_1byte_rdy;
	data->reg_bits.stat_tx_rdy     = get_stat_tx_1byte_rdy;

	/* Set interrupt registers */
	/* Todo:
	 * CTRL2 register is used for tx and rx interrupt control
	 * ONLY in 1-byte transfer mode with REG_A3700_EXT registers
	 * layout.
	 */
	if (data->reg_type == REG_UART_A3700_EXT)
		data->intr.ctrl_reg = REG_CTRL2(data);
	else
		data->intr.ctrl_reg = REG_CTRL(data);
#else /* MY_DEF_HERE */
	data->port = port;
#endif /* MY_DEF_HERE */
#if defined(MY_DEF_HERE)
	/* Initialize the tx spin_lock */
	spin_lock_init(&data->tx_lock);
#endif /* MY_DEF_HERE */

	port->private_data = data;
	platform_set_drvdata(pdev, data);

#if defined(MY_DEF_HERE)
	/* UART interrupt status selected */
	/* Select UART_EXT RX and TX as the interrupt status mode*/
	if (uart_int_base) {
		data->intr.uart_int_base = devm_ioremap_resource(&pdev->dev, uart_int_base);
		if (IS_ERR(data->intr.uart_int_base))
			return -PTR_ERR(data->intr.uart_int_base);
		value = readl(data->intr.uart_int_base + NORTH_BRIDGE_UART_EXT_INT_SEL);
		writel(value | UART_EXT_TX_INT_SEL | UART_EXT_RX_INT_SEL, data->intr.uart_int_base +
			   NORTH_BRIDGE_UART_EXT_INT_SEL);
	}

	/* UART Soft Reset*/
	writel(CTRL_SOFT_RST, port->membase + REG_CTRL(data));
	udelay(1);
	writel(0, port->membase + REG_CTRL(data));

#endif /* MY_DEF_HERE */
	ret = uart_add_one_port(&mvebu_uart_driver, port);
	if (ret)
		return ret;

	return 0;
}

static int mvebu_uart_remove(struct platform_device *pdev)
{
	struct mvebu_uart_data *data = platform_get_drvdata(pdev);

	uart_remove_one_port(&mvebu_uart_driver, data->port);
	data->port->private_data = NULL;
	data->port->mapbase      = 0;
	return 0;
}

#if defined(MY_DEF_HERE)
#ifdef CONFIG_PM

/* Uart registers status save in suspend process*/
static int mvebu_uart_reg_save(struct mvebu_uart_data *data)
{
	data->pm_reg_value.uart_ctrl = readl(data->port->membase + REG_CTRL(data));

	if (data->reg_type == REG_UART_A3700_EXT)
		data->pm_reg_value.uart_ctrl2 = readl(data->port->membase + REG_CTRL2(data));

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	data->pm_reg_value.uart_tsh = readl(data->port->membase + REG_TSH(data));
#endif /* MY_DEF_HERE */
	data->pm_reg_value.uart_brdv = readl(data->port->membase + REG_BRDV(data));
	data->pm_reg_value.uart_over_sample = readl(data->port->membase + REG_OSAMP(data));
	if (!IS_ERR_OR_NULL(data->intr.uart_int_base))
		data->uart_ext_int_type = readl(data->intr.uart_int_base + NORTH_BRIDGE_UART_EXT_INT_SEL);

	return 0;
}

/* Uart registers status restore in resume process*/
static int mvebu_uart_reg_restore(struct mvebu_uart_data *data)
{
	writel(data->pm_reg_value.uart_ctrl, data->port->membase + REG_CTRL(data));

	if (data->reg_type == REG_UART_A3700_EXT)
		writel(data->pm_reg_value.uart_ctrl2, data->port->membase + REG_CTRL2(data));

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	writel(data->pm_reg_value.uart_tsh, data->port->membase + REG_TSH(data));
#endif /* MY_DEF_HERE */
	writel(data->pm_reg_value.uart_brdv, data->port->membase + REG_BRDV(data));
	writel(data->pm_reg_value.uart_over_sample, data->port->membase + REG_OSAMP(data));
	if (!IS_ERR_OR_NULL(data->intr.uart_int_base))
		writel(data->uart_ext_int_type, data->intr.uart_int_base + NORTH_BRIDGE_UART_EXT_INT_SEL);

	return 0;
}

static int mvebu_uart_suspend(struct device *dev)
{
	struct mvebu_uart_data *data = dev_get_drvdata(dev);

	mvebu_uart_reg_save(data);

	if (data->port)
		uart_suspend_port(&mvebu_uart_driver, data->port);

	device_set_wakeup_enable(dev, true);

	return 0;
}

static int mvebu_uart_resume(struct device *dev)
{
	struct mvebu_uart_data *data = dev_get_drvdata(dev);

	mvebu_uart_reg_restore(data);

	if (data->port)
		uart_resume_port(&mvebu_uart_driver, data->port);

	device_set_wakeup_enable(dev, false);

	return 0;
}

static const struct dev_pm_ops mvebu_uart_pm_ops = {
	.suspend	= mvebu_uart_suspend,
	.resume		= mvebu_uart_resume,
};
#endif

#endif /* MY_DEF_HERE */
/* Match table for of_platform binding */
static const struct of_device_id mvebu_uart_of_match[] = {
#if defined(MY_DEF_HERE)
	{ .compatible = "marvell,armada-3700-uart",     .data = (void *)REG_UART_A3700     },
	{ .compatible = "marvell,armada-3700-uart-ext", .data = (void *)REG_UART_A3700_EXT },
#else /* MY_DEF_HERE */
	{ .compatible = "marvell,armada-3700-uart", },
#endif /* MY_DEF_HERE */
	{}
};
MODULE_DEVICE_TABLE(of, mvebu_uart_of_match);

static struct platform_driver mvebu_uart_platform_driver = {
	.probe	= mvebu_uart_probe,
	.remove	= mvebu_uart_remove,
	.driver	= {
		.owner	= THIS_MODULE,
		.name  = "mvebu-uart",
		.of_match_table = of_match_ptr(mvebu_uart_of_match),
#if defined(MY_DEF_HERE)
#ifdef CONFIG_PM
		.pm	= &mvebu_uart_pm_ops,
#endif
#endif /* MY_DEF_HERE */
	},
};

static int __init mvebu_uart_init(void)
{
	int ret;

#ifdef MY_DEF_HERE
	syno_uart1_base = ioremap(PORT1_BASE, 0x2C);
#endif /* MY_DEF_HERE */
	ret = uart_register_driver(&mvebu_uart_driver);
	if (ret)
		return ret;

	ret = platform_driver_register(&mvebu_uart_platform_driver);
	if (ret)
		uart_unregister_driver(&mvebu_uart_driver);

	return ret;
}

static void __exit mvebu_uart_exit(void)
{
	platform_driver_unregister(&mvebu_uart_platform_driver);
	uart_unregister_driver(&mvebu_uart_driver);
}

arch_initcall(mvebu_uart_init);
module_exit(mvebu_uart_exit);

MODULE_AUTHOR("Wilson Ding <dingwei@marvell.com>");
MODULE_DESCRIPTION("Marvell Armada-3700 Serial Driver");
MODULE_LICENSE("GPL");
#endif /* MY_DEF_HERE */
