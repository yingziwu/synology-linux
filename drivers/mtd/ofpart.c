#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/*
 * Flash partitions described by the OF (or flattened) device tree
 *
 * Copyright © 2006 MontaVista Software Inc.
 * Author: Vitaly Wool <vwool@ru.mvista.com>
 *
 * Revised to handle newer style flash binding by:
 *   Copyright © 2007 David Gibson, IBM Corporation.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/mtd/mtd.h>
#include <linux/slab.h>
#include <linux/mtd/partitions.h>

static bool node_has_compatible(struct device_node *pp)
{
	return of_get_property(pp, "compatible", NULL);
}

static int parse_ofpart_partitions(struct mtd_info *master,
#if defined(CONFIG_SYNO_RTD1619)
				   const struct mtd_partition **pparts,
#else /* CONFIG_SYNO_RTD1619 */
				   struct mtd_partition **pparts,
#endif /* CONFIG_SYNO_RTD1619 */
				   struct mtd_part_parser_data *data)
{
#if defined(CONFIG_SYNO_RTD1619)
	struct mtd_partition *parts;
#endif /* CONFIG_SYNO_RTD1619 */
	struct device_node *mtd_node;
	struct device_node *ofpart_node;
	const char *partname;
	struct device_node *pp;
	int nr_parts, i, ret = 0;
	bool dedicated = true;

#if defined(MY_DEF_HERE)
	/*
	 * of_node can be provided through auxiliary parser data or (preferred)
	 * by assigning the master device node
	 */
	mtd_node = data && data->of_node ? data->of_node : mtd_get_of_node(master);
#else /* MY_DEF_HERE */
	if (!data)
		return 0;

	mtd_node = data->of_node;
#endif /* MY_DEF_HERE */
	if (!mtd_node)
		return 0;

	ofpart_node = of_get_child_by_name(mtd_node, "partitions");
	if (!ofpart_node) {
		/*
		 * We might get here even when ofpart isn't used at all (e.g.,
		 * when using another parser), so don't be louder than
		 * KERN_DEBUG
		 */
		pr_debug("%s: 'partitions' subnode not found on %s. Trying to parse direct subnodes as partitions.\n",
			 master->name, mtd_node->full_name);
		ofpart_node = mtd_node;
		dedicated = false;
	} else if (!of_device_is_compatible(ofpart_node, "fixed-partitions")) {
		/* The 'partitions' subnode might be used by another parser */
		return 0;
	}

	/* First count the subnodes */
	nr_parts = 0;
	for_each_child_of_node(ofpart_node,  pp) {
		if (!dedicated && node_has_compatible(pp))
			continue;

		nr_parts++;
	}

	if (nr_parts == 0)
		return 0;

#if defined(CONFIG_SYNO_RTD1619)
	parts = kzalloc(nr_parts * sizeof(*parts), GFP_KERNEL);
	if (!parts)
#else /* CONFIG_SYNO_RTD1619 */
	*pparts = kzalloc(nr_parts * sizeof(**pparts), GFP_KERNEL);
	if (!*pparts)
#endif /* CONFIG_SYNO_RTD1619 */
		return -ENOMEM;

	i = 0;
	for_each_child_of_node(ofpart_node,  pp) {
		const __be32 *reg;
		int len;
		int a_cells, s_cells;

		if (!dedicated && node_has_compatible(pp))
			continue;

		reg = of_get_property(pp, "reg", &len);
		if (!reg) {
			if (dedicated) {
				pr_debug("%s: ofpart partition %s (%s) missing reg property.\n",
					 master->name, pp->full_name,
					 mtd_node->full_name);
				goto ofpart_fail;
			} else {
				nr_parts--;
				continue;
			}
		}

		a_cells = of_n_addr_cells(pp);
		s_cells = of_n_size_cells(pp);
		if (len / 4 != a_cells + s_cells) {
			pr_debug("%s: ofpart partition %s (%s) error parsing reg property.\n",
				 master->name, pp->full_name,
				 mtd_node->full_name);
			goto ofpart_fail;
		}

#if defined(CONFIG_SYNO_RTD1619)
		parts[i].offset = of_read_number(reg, a_cells);
		parts[i].size = of_read_number(reg + a_cells, s_cells);
#else /* CONFIG_SYNO_RTD1619 */
		(*pparts)[i].offset = of_read_number(reg, a_cells);
		(*pparts)[i].size = of_read_number(reg + a_cells, s_cells);
#endif /* CONFIG_SYNO_RTD1619 */

		partname = of_get_property(pp, "label", &len);
		if (!partname)
			partname = of_get_property(pp, "name", &len);
#if defined(CONFIG_SYNO_RTD1619)
		parts[i].name = partname;
#else /* CONFIG_SYNO_RTD1619 */
		(*pparts)[i].name = partname;
#endif /* CONFIG_SYNO_RTD1619 */

		if (of_get_property(pp, "read-only", &len))
#if defined(CONFIG_SYNO_RTD1619)
			parts[i].mask_flags |= MTD_WRITEABLE;
#else /* CONFIG_SYNO_RTD1619 */
			(*pparts)[i].mask_flags |= MTD_WRITEABLE;
#endif /* CONFIG_SYNO_RTD1619 */

		if (of_get_property(pp, "lock", &len))
#if defined(CONFIG_SYNO_RTD1619)
			parts[i].mask_flags |= MTD_POWERUP_LOCK;
#else /* CONFIG_SYNO_RTD1619 */
			(*pparts)[i].mask_flags |= MTD_POWERUP_LOCK;
#endif /* CONFIG_SYNO_RTD1619 */

		i++;
	}

	if (!nr_parts)
		goto ofpart_none;

#if defined(CONFIG_SYNO_RTD1619)
	*pparts = parts;
#endif /* CONFIG_SYNO_RTD1619 */
	return nr_parts;

ofpart_fail:
	pr_err("%s: error parsing ofpart partition %s (%s)\n",
	       master->name, pp->full_name, mtd_node->full_name);
	ret = -EINVAL;
ofpart_none:
	of_node_put(pp);
#if defined(CONFIG_SYNO_RTD1619)
	kfree(parts);
#else /* CONFIG_SYNO_RTD1619 */
	kfree(*pparts);
	*pparts = NULL;
#endif /* CONFIG_SYNO_RTD1619 */
	return ret;
}

static struct mtd_part_parser ofpart_parser = {
	.owner = THIS_MODULE,
	.parse_fn = parse_ofpart_partitions,
	.name = "ofpart",
};

static int parse_ofoldpart_partitions(struct mtd_info *master,
#if defined(CONFIG_SYNO_RTD1619)
				      const struct mtd_partition **pparts,
#else /* CONFIG_SYNO_RTD1619 */
				      struct mtd_partition **pparts,
#endif /* CONFIG_SYNO_RTD1619 */
				      struct mtd_part_parser_data *data)
{
#if defined(CONFIG_SYNO_RTD1619)
	struct mtd_partition *parts;
#endif /* CONFIG_SYNO_RTD1619 */
	struct device_node *dp;
	int i, plen, nr_parts;
	const struct {
		__be32 offset, len;
	} *part;
	const char *names;

#if defined(MY_DEF_HERE)
	/*
	 * of_node can be provided through auxiliary parser data or (preferred)
	 * by assigning the master device node
	 */
	dp = data && data->of_node ? data->of_node : mtd_get_of_node(master);
#else /* MY_DEF_HERE */
	if (!data)
		return 0;

	dp = data->of_node;
#endif /* MY_DEF_HERE */
	if (!dp)
		return 0;

	part = of_get_property(dp, "partitions", &plen);
	if (!part)
		return 0; /* No partitions found */

	pr_warning("Device tree uses obsolete partition map binding: %s\n",
			dp->full_name);

	nr_parts = plen / sizeof(part[0]);

#if defined(CONFIG_SYNO_RTD1619)
	parts = kzalloc(nr_parts * sizeof(*parts), GFP_KERNEL);
	if (!parts)
#else /* CONFIG_SYNO_RTD1619 */
	*pparts = kzalloc(nr_parts * sizeof(*(*pparts)), GFP_KERNEL);
	if (!*pparts)
#endif /* CONFIG_SYNO_RTD1619 */
		return -ENOMEM;

	names = of_get_property(dp, "partition-names", &plen);

	for (i = 0; i < nr_parts; i++) {
#if defined(CONFIG_SYNO_RTD1619)
		parts[i].offset = be32_to_cpu(part->offset);
		parts[i].size   = be32_to_cpu(part->len) & ~1;
#else /* CONFIG_SYNO_RTD1619 */
		(*pparts)[i].offset = be32_to_cpu(part->offset);
		(*pparts)[i].size   = be32_to_cpu(part->len) & ~1;
#endif /* CONFIG_SYNO_RTD1619 */
		/* bit 0 set signifies read only partition */
		if (be32_to_cpu(part->len) & 1)
#if defined(CONFIG_SYNO_RTD1619)
			parts[i].mask_flags = MTD_WRITEABLE;
#else /* CONFIG_SYNO_RTD1619 */
			(*pparts)[i].mask_flags = MTD_WRITEABLE;
#endif /* CONFIG_SYNO_RTD1619 */

		if (names && (plen > 0)) {
			int len = strlen(names) + 1;

#if defined(CONFIG_SYNO_RTD1619)
			parts[i].name = names;
#else /* CONFIG_SYNO_RTD1619 */
			(*pparts)[i].name = names;
#endif /* CONFIG_SYNO_RTD1619 */
			plen -= len;
			names += len;
		} else {
#if defined(CONFIG_SYNO_RTD1619)
			parts[i].name = "unnamed";
#else /* CONFIG_SYNO_RTD1619 */
			(*pparts)[i].name = "unnamed";
#endif /* CONFIG_SYNO_RTD1619 */
		}

		part++;
	}

#if defined(CONFIG_SYNO_RTD1619)
	*pparts = parts;
#endif /* CONFIG_SYNO_RTD1619 */
	return nr_parts;
}

static struct mtd_part_parser ofoldpart_parser = {
	.owner = THIS_MODULE,
	.parse_fn = parse_ofoldpart_partitions,
	.name = "ofoldpart",
};

static int __init ofpart_parser_init(void)
{
	register_mtd_parser(&ofpart_parser);
	register_mtd_parser(&ofoldpart_parser);
	return 0;
}

static void __exit ofpart_parser_exit(void)
{
	deregister_mtd_parser(&ofpart_parser);
	deregister_mtd_parser(&ofoldpart_parser);
}

module_init(ofpart_parser_init);
module_exit(ofpart_parser_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Parser for MTD partitioning information in device tree");
MODULE_AUTHOR("Vitaly Wool, David Gibson");
/*
 * When MTD core cannot find the requested parser, it tries to load the module
 * with the same name. Since we provide the ofoldpart parser, we should have
 * the corresponding alias.
 */
MODULE_ALIAS("ofoldpart");
