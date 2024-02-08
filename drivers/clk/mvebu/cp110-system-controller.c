#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined(MY_DEF_HERE)
/*
 * Marvell Armada CP110 System Controller
 *
 * Copyright (C) 2016 Marvell
 *
 * Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

/*
#if defined(MY_DEF_HERE)
 * CP110 has 6 core clocks:
#else // MY_DEF_HERE
 * CP110 has 5 core clocks:
#endif // MY_DEF_HERE
 *
 *  - APLL		(1 Ghz)
 *    - PPv2 core	(1/3 APLL)
 *    - EIP		(1/2 APLL)
 *      - Core		(1/2 EIP)
#if defined(MY_DEF_HERE)
 *    - MMC		(2/5 APLL)
#endif // MY_DEF_HERE
 *
 *  - NAND clock, which is either:
#if defined(MY_DEF_HERE)
 *    - Equal to MMC clock
#else // MY_DEF_HERE
 *    - Equal to the core clock
#endif // MY_DEF_HERE
 *    - 2/5 APLL
 *
 * CP110 has 32 gatable clocks, for the various peripherals in the
 * IP. They have fairly complicated parent/child relationships.
 */

#define pr_fmt(fmt) "cp110-system-controller: " fmt

#include <linux/clk-provider.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/clk.h>

#define CP110_PM_CLOCK_GATING_REG	0x220
#define CP110_NAND_FLASH_CLK_CTRL_REG	0x700
#define    NF_CLOCK_SEL_400_MASK	BIT(0)

enum {
	CP110_CLK_TYPE_CORE,
	CP110_CLK_TYPE_GATABLE,
};

#if defined(MY_DEF_HERE)
#define CP110_MAX_CORE_CLOCKS		6
#else /* MY_DEF_HERE */
#define CP110_MAX_CORE_CLOCKS		5
#endif /* MY_DEF_HERE */
#define CP110_MAX_GATABLE_CLOCKS	32

#define CP110_CLK_NUM \
	(CP110_MAX_CORE_CLOCKS + CP110_MAX_GATABLE_CLOCKS)

#define CP110_CORE_APLL			0
#define CP110_CORE_PPV2			1
#define CP110_CORE_EIP			2
#define CP110_CORE_CORE			3
#define CP110_CORE_NAND			4
#if defined(MY_DEF_HERE)
#define CP110_CORE_MMC			5
#endif /* MY_DEF_HERE */

/* A number of gatable clocks need special handling */
#define CP110_GATE_AUDIO		0
#define CP110_GATE_COMM_UNIT		1
#define CP110_GATE_NAND			2
#define CP110_GATE_PPV2			3
#define CP110_GATE_SDIO			4
#if defined(MY_DEF_HERE)
#define CP110_GATE_MG			6
#endif /* MY_DEF_HERE */
#define CP110_GATE_XOR1			7
#define CP110_GATE_XOR0			8
#define CP110_GATE_PCIE_X1_0		11
#define CP110_GATE_PCIE_X1_1		12
#define CP110_GATE_PCIE_X4		13
#define CP110_GATE_PCIE_XOR		14
#define CP110_GATE_SATA			15
#define CP110_GATE_SATA_USB		16
#define CP110_GATE_MAIN			17
#define CP110_GATE_SDMMC		18
#define CP110_GATE_SLOW_IO		21
#define CP110_GATE_USB3H0		22
#define CP110_GATE_USB3H1		23
#define CP110_GATE_USB3DEV		24
#define CP110_GATE_EIP150		25
#define CP110_GATE_EIP197		26

struct cp110_gate_clk {
	struct clk_hw hw;
	struct regmap *regmap;
	u8 bit_idx;
};

#define to_cp110_gate_clk(clk) container_of(clk, struct cp110_gate_clk, hw)

static int cp110_gate_enable(struct clk_hw *hw)
{
	struct cp110_gate_clk *gate = to_cp110_gate_clk(hw);

	regmap_update_bits(gate->regmap, CP110_PM_CLOCK_GATING_REG,
			   BIT(gate->bit_idx), BIT(gate->bit_idx));

	return 0;
}

static void cp110_gate_disable(struct clk_hw *hw)
{
	struct cp110_gate_clk *gate = to_cp110_gate_clk(hw);

	regmap_update_bits(gate->regmap, CP110_PM_CLOCK_GATING_REG,
			   BIT(gate->bit_idx), 0);
}

static int cp110_gate_is_enabled(struct clk_hw *hw)
{
	struct cp110_gate_clk *gate = to_cp110_gate_clk(hw);
	u32 val;

	regmap_read(gate->regmap, CP110_PM_CLOCK_GATING_REG, &val);

	return val & BIT(gate->bit_idx);
}

static const struct clk_ops cp110_gate_ops = {
	.enable = cp110_gate_enable,
	.disable = cp110_gate_disable,
	.is_enabled = cp110_gate_is_enabled,
};

static struct clk *cp110_register_gate(const char *name,
				       const char *parent_name,
				       struct regmap *regmap, u8 bit_idx)
{
	struct cp110_gate_clk *gate;
	struct clk *clk;
	struct clk_init_data init;

	gate = kzalloc(sizeof(*gate), GFP_KERNEL);
	if (!gate)
		return ERR_PTR(-ENOMEM);

	memset(&init, 0, sizeof(init));

	init.name = name;
	init.ops = &cp110_gate_ops;
	init.flags = CLK_IS_BASIC;
	init.parent_names = &parent_name;
	init.num_parents = 1;

	gate->regmap = regmap;
	gate->bit_idx = bit_idx;
	gate->hw.init = &init;

	clk = clk_register(NULL, &gate->hw);
	if (IS_ERR(clk))
		kfree(gate);

	return clk;
}

static void cp110_unregister_gate(struct clk *clk)
{
	struct clk_hw *hw;

	hw = __clk_get_hw(clk);
	if (!hw)
		return;

	clk_unregister(clk);
	kfree(to_cp110_gate_clk(hw));
}

static struct clk *cp110_of_clk_get(struct of_phandle_args *clkspec, void *data)
{
	struct clk_onecell_data *clk_data = data;
	unsigned int type = clkspec->args[0];
	unsigned int idx = clkspec->args[1];

	if (type == CP110_CLK_TYPE_CORE) {
		if (idx > CP110_MAX_CORE_CLOCKS)
			return ERR_PTR(-EINVAL);
		return clk_data->clks[idx];
	} else if (type == CP110_CLK_TYPE_GATABLE) {
		if (idx > CP110_MAX_GATABLE_CLOCKS)
			return ERR_PTR(-EINVAL);
		return clk_data->clks[CP110_MAX_CORE_CLOCKS + idx];
	}

	return ERR_PTR(-EINVAL);
}

static int cp110_syscon_clk_probe(struct platform_device *pdev)
{
	struct regmap *regmap;
	struct device_node *np = pdev->dev.of_node;
#if defined(MY_DEF_HERE)
	const char *ppv2_name, *apll_name, *core_name, *eip_name, *nand_name, *mmc_name;
#else /* MY_DEF_HERE */
	const char *ppv2_name, *apll_name, *core_name, *eip_name, *nand_name;
#endif /* MY_DEF_HERE */
	struct clk_onecell_data *cp110_clk_data;
	struct clk *clk, **cp110_clks;
	u32 nand_clk_ctrl;
	int i, ret;

	regmap = syscon_node_to_regmap(np);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);

	ret = regmap_read(regmap, CP110_NAND_FLASH_CLK_CTRL_REG,
			  &nand_clk_ctrl);
	if (ret)
		return ret;

	cp110_clks = devm_kcalloc(&pdev->dev, sizeof(struct clk *),
				  CP110_CLK_NUM, GFP_KERNEL);
	if (IS_ERR(cp110_clks))
		return PTR_ERR(cp110_clks);

	cp110_clk_data = devm_kzalloc(&pdev->dev,
				      sizeof(struct clk_onecell_data),
				      GFP_KERNEL);
	if (IS_ERR(cp110_clk_data))
		return PTR_ERR(cp110_clk_data);

	cp110_clk_data->clks = cp110_clks;
	cp110_clk_data->clk_num = CP110_CLK_NUM;

	/* Register the APLL which is the root of the clk tree */
	of_property_read_string_index(np, "core-clock-output-names",
				      CP110_CORE_APLL, &apll_name);
	clk = clk_register_fixed_rate(NULL, apll_name, NULL, CLK_IS_ROOT,
				      1000 * 1000 * 1000);
	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		goto fail0;
	}

	cp110_clks[CP110_CORE_APLL] = clk;

	/* PPv2 is APLL/3 */
	of_property_read_string_index(np, "core-clock-output-names",
				      CP110_CORE_PPV2, &ppv2_name);
	clk = clk_register_fixed_factor(NULL, ppv2_name, apll_name, 0, 1, 3);
	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		goto fail1;
	}

	cp110_clks[CP110_CORE_PPV2] = clk;

	/* EIP clock is APLL/2 */
	of_property_read_string_index(np, "core-clock-output-names",
				      CP110_CORE_EIP, &eip_name);
	clk = clk_register_fixed_factor(NULL, eip_name, apll_name, 0, 1, 2);
	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		goto fail2;
	}

	cp110_clks[CP110_CORE_EIP] = clk;

	/* Core clock is EIP/2 */
	of_property_read_string_index(np, "core-clock-output-names",
				      CP110_CORE_CORE, &core_name);
	clk = clk_register_fixed_factor(NULL, core_name, eip_name, 0, 1, 2);
	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		goto fail3;
	}

	cp110_clks[CP110_CORE_CORE] = clk;

	/* NAND can be either APLL/2.5 or core clock */
	of_property_read_string_index(np, "core-clock-output-names",
				      CP110_CORE_NAND, &nand_name);
	if (nand_clk_ctrl & NF_CLOCK_SEL_400_MASK)
		clk = clk_register_fixed_factor(NULL, nand_name,
						apll_name, 0, 2, 5);
	else
		clk = clk_register_fixed_factor(NULL, nand_name,
						core_name, 0, 1, 1);
	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		goto fail4;
	}

	cp110_clks[CP110_CORE_NAND] = clk;

#if defined(MY_DEF_HERE)
	/* MMC clock is APLL/2.5 */
	of_property_read_string_index(np, "core-clock-output-names",
				      CP110_CORE_MMC, &mmc_name);

	clk = clk_register_fixed_factor(NULL, mmc_name,
					apll_name, 0, 2, 5);

	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		goto fail5;
	}

	cp110_clks[CP110_CORE_MMC] = clk;

#endif /* MY_DEF_HERE */
	for (i = 0; i < CP110_MAX_GATABLE_CLOCKS; i++) {
		const char *parent, *name;
		int ret;

		ret = of_property_read_string_index(np,
						    "gate-clock-output-names",
						    i, &name);
		/* Reached the end of the list? */
		if (ret < 0)
			break;

		if (!strcmp(name, "none"))
			continue;

		switch (i) {
		case CP110_GATE_AUDIO:
		case CP110_GATE_COMM_UNIT:
		case CP110_GATE_EIP150:
		case CP110_GATE_EIP197:
		case CP110_GATE_SLOW_IO:
			of_property_read_string_index(np,
						      "gate-clock-output-names",
						      CP110_GATE_MAIN, &parent);
			break;
		case CP110_GATE_NAND:
			parent = nand_name;
			break;
		case CP110_GATE_PPV2:
			parent = ppv2_name;
			break;
		case CP110_GATE_SDIO:
#if defined(MY_DEF_HERE)
			parent = mmc_name;
#else /* MY_DEF_HERE */
			of_property_read_string_index(np,
						      "gate-clock-output-names",
						      CP110_GATE_SDMMC, &parent);
#endif /* MY_DEF_HERE */
			break;
		case CP110_GATE_XOR1:
		case CP110_GATE_XOR0:
		case CP110_GATE_PCIE_X1_0:
		case CP110_GATE_PCIE_X1_1:
		case CP110_GATE_PCIE_X4:
			of_property_read_string_index(np,
						      "gate-clock-output-names",
						      CP110_GATE_PCIE_XOR, &parent);
			break;
		case CP110_GATE_SATA:
		case CP110_GATE_USB3H0:
		case CP110_GATE_USB3H1:
		case CP110_GATE_USB3DEV:
			of_property_read_string_index(np,
						      "gate-clock-output-names",
						      CP110_GATE_SATA_USB, &parent);
			break;
		default:
			parent = core_name;
			break;
		}

		clk = cp110_register_gate(name, parent, regmap, i);
		if (IS_ERR(clk)) {
			ret = PTR_ERR(clk);
			goto fail_gate;
		}

		cp110_clks[CP110_MAX_CORE_CLOCKS + i] = clk;
	}

#if defined(MY_DEF_HERE)
	/*
	 * Gated clocks 18 and 6 feeds many core clocks in CP110.
	 * Clock 18 feeds eMMC clock. eMMC driver supports only one clock - the core
	 * clock of eMMC) so we need to enable clock 18 in CP110 clock level
	 * and not the eMMC driver itself.
	 * Gated clock 6 feeds XSMI clock. If ppv2 ports on CP0 connected
	 * to XSMI on CP1 and there are no enabled ppv2 ports on CP1. XSMI won't be enabled.
	 * TODO:
	 * This is a workaround, the complete solution should be nesting all
	 * clock providers and consumers in the CP110 driver. One possible
	 * drawback of this WA is the fact that if we boot without IOs which
	 * use this clock, this clock will be still enabled.
	 */
	if (cp110_clks[CP110_MAX_CORE_CLOCKS + CP110_GATE_SDMMC]) {
		ret = clk_prepare_enable(cp110_clks[CP110_MAX_CORE_CLOCKS +
						    CP110_GATE_SDMMC]);
		if (ret)
			goto fail_clk_add;
	}

	if (cp110_clks[CP110_MAX_CORE_CLOCKS + CP110_GATE_MG]) {
		ret = clk_prepare_enable(cp110_clks[CP110_MAX_CORE_CLOCKS +
						    CP110_GATE_MG]);
		if (ret)
			goto fail_clk_add;
	}

#endif /* MY_DEF_HERE */
	ret = of_clk_add_provider(np, cp110_of_clk_get, cp110_clk_data);
	if (ret)
		goto fail_clk_add;

	platform_set_drvdata(pdev, cp110_clks);

	return 0;

fail_clk_add:
fail_gate:
	for (i = 0; i < CP110_MAX_GATABLE_CLOCKS; i++) {
		clk = cp110_clks[CP110_MAX_CORE_CLOCKS + i];

		if (clk)
			cp110_unregister_gate(clk);
	}

#if defined(MY_DEF_HERE)

	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_MMC]);
fail5:
#endif /* MY_DEF_HERE */
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_NAND]);
fail4:
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_CORE]);
fail3:
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_EIP]);
fail2:
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_PPV2]);
fail1:
	clk_unregister_fixed_rate(cp110_clks[CP110_CORE_APLL]);
fail0:
	return ret;
}

static int cp110_syscon_clk_remove(struct platform_device *pdev)
{
	struct clk **cp110_clks = platform_get_drvdata(pdev);
	int i;

	of_clk_del_provider(pdev->dev.of_node);

#if defined(MY_DEF_HERE)
	/*
	 * Disable gated clock 18 if it exists.
	 * (We enabled it in cp110_syscon_clk_probe).
	 */
	if (cp110_clks[CP110_MAX_CORE_CLOCKS + CP110_GATE_SDMMC])
		clk_disable_unprepare(cp110_clks[CP110_MAX_CORE_CLOCKS +
						 CP110_GATE_SDMMC]);

#endif /* MY_DEF_HERE */
	for (i = 0; i < CP110_MAX_GATABLE_CLOCKS; i++) {
		struct clk *clk = cp110_clks[CP110_MAX_CORE_CLOCKS + i];

		if (clk)
			cp110_unregister_gate(clk);
	}

#if defined(MY_DEF_HERE)
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_MMC]);
#endif /* MY_DEF_HERE */
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_NAND]);
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_CORE]);
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_EIP]);
	clk_unregister_fixed_factor(cp110_clks[CP110_CORE_PPV2]);
	clk_unregister_fixed_rate(cp110_clks[CP110_CORE_APLL]);

	return 0;
}

static const struct of_device_id cp110_syscon_of_match[] = {
	{ .compatible = "marvell,cp110-system-controller0", },
	{ }
};
MODULE_DEVICE_TABLE(of, armada8k_pcie_of_match);

static struct platform_driver cp110_syscon_driver = {
	.probe = cp110_syscon_clk_probe,
	.remove = cp110_syscon_clk_remove,
	.driver		= {
		.name	= "marvell-cp110-system-controller0",
		.of_match_table = cp110_syscon_of_match,
	},
};

module_platform_driver(cp110_syscon_driver);

MODULE_DESCRIPTION("Marvell CP110 System Controller 0 driver");
MODULE_AUTHOR("Thomas Petazzoni <thomas.petazzoni@free-electrons.com>");
MODULE_LICENSE("GPL");
#endif /* MY_DEF_HERE */
