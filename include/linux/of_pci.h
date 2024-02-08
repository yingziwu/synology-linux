#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifndef __OF_PCI_H
#define __OF_PCI_H

#include <linux/pci.h>

struct pci_dev;
struct of_irq;
int of_irq_map_pci(struct pci_dev *pdev, struct of_irq *out_irq);

struct device_node;
struct device_node *of_pci_find_child_device(struct device_node *parent,
					     unsigned int devfn);
#ifdef MY_DEF_HERE
int of_pci_get_devfn(struct device_node *np);
int of_pci_parse_bus_range(struct device_node *node, struct resource *res);
#endif

#endif
