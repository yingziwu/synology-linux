/*
 * Marvell Armada 8K Sample at Reset definitions.
 *
 * Copyright (C) 2017 Marvell Semiconductor
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef MVEBU_SAMPLE_AT_RESET_H
#define MVEBU_SAMPLE_AT_RESET_H

enum mvebu_bootsrc_type {
	BOOTSRC_NAND,
	BOOTSRC_SPI,
	BOOTSRC_AP_SPI,
	BOOTSRC_SD_EMMC,
	BOOTSRC_AP_SD_EMMC,
	BOOTSRC_NOR,
	BOOTSRC_MAX_IDX
};

/*
 * sample-at-reset information
 *  raw_sar_val: Raw value out of the sample-at-reset register.
 *		This is hw dependent and should not be used for comparison
 *		purposes (useful for debug, or verbose information).
 *  bootsrc (SAR_BOOT_SRC):
 *	type: Boot source interface type.
 *	index: When applicable, indicates the interface index (e.g. SPI #1,
 *		NAND #0).
 *	width: When applicable, indicates the interface bus width (e.g. NAND
 *	8-bit).
 *  freq: Frequency in Hz.
 */
struct sar_val {
	u32 raw_sar_val;
	union {
		struct {
			enum mvebu_bootsrc_type type;
			int index;
		} bootsrc;
		u32 freq;
		u32 clk_direction;
	};
};

/*
 * List of boot source options.
 * Return value for each of the options:
 *  - SAR_CPU_FREQ: Frequency (Hz)
 *  - SAR_DDR_FREQ: Frequency (Hz)
 *  - SAR_AP_FABRIC_FREQ: Frequency (Hz)
 *  - SAR_CP_FABRIC_FREQ: Frequency (Hz)
 *  - SAR_BOOT_SRC: Boot source type (see mvebu_bootsrc_type)
 */
enum mvebu_sar_opts {
	SAR_CPU_FREQ = 0,
	SAR_DDR_FREQ,
	SAR_AP_FABRIC_FREQ,
	SAR_CP_FABRIC_FREQ,
	SAR_CP_PCIE0_CLK,
	SAR_CP_PCIE1_CLK,
	SAR_BOOT_SRC,
	SAR_MAX_IDX
};

int mv_sar_value_get(struct device *dev,
			     enum mvebu_sar_opts sar_opt,
			     struct sar_val *val);
int mv_sar_dump(struct device *dev);

#endif /* MVEBU_SAMPLE_AT_RESET_H */
