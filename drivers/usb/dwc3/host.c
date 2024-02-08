#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
/**
 * host.c - DesignWare USB3 DRD Controller Host Glue
 *
 * Copyright (C) 2011 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors: Felipe Balbi <balbi@ti.com>,
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the above-listed copyright holders may not be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2, as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/platform_device.h>
#if defined (MY_DEF_HERE)
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/usb/xhci_pdriver.h>
#include "../host/xhci.h"
#endif /* MY_DEF_HERE */

#include "core.h"

int dwc3_host_init(struct dwc3 *dwc)
{
	struct platform_device	*xhci;
#if defined (MY_DEF_HERE)
	struct usb_hcd *hcd;
	struct xhci_hcd *xhci_dev;
	struct usb_xhci_pdata	pdata;
#endif /* MY_DEF_HERE */
	int			ret;

	xhci = platform_device_alloc("xhci-hcd", PLATFORM_DEVID_AUTO);
	if (!xhci) {
		dev_err(dwc->dev, "couldn't allocate xHCI device\n");
		ret = -ENOMEM;
		goto err0;
	}

	dma_set_coherent_mask(&xhci->dev, dwc->dev->coherent_dma_mask);

	xhci->dev.parent	= dwc->dev;
	xhci->dev.dma_mask	= dwc->dev->dma_mask;
	xhci->dev.dma_parms	= dwc->dev->dma_parms;

	dwc->xhci = xhci;

	ret = platform_device_add_resources(xhci, dwc->xhci_resources,
						DWC3_XHCI_RESOURCES_NUM);
	if (ret) {
		dev_err(dwc->dev, "couldn't add resources to xHCI device\n");
		goto err1;
	}
#if defined (MY_DEF_HERE)

	memset(&pdata, 0, sizeof(pdata));

#ifdef CONFIG_DWC3_HOST_USB3_LPM_ENABLE
	pdata.usb3_lpm_capable = 1;
#endif

	ret = platform_device_add_data(xhci, &pdata, sizeof(pdata));
	if (ret) {
		dev_err(dwc->dev, "couldn't add platform data to xHCI device\n");
		goto err1;
	}

#endif /* MY_DEF_HERE */

	ret = platform_device_add(xhci);
	if (ret) {
		dev_err(dwc->dev, "failed to register xHCI device\n");
		goto err1;
	}
#if defined (MY_DEF_HERE)

	/*
	 * Attach the host controller phy to the shared_hcd struct of the
	 * initialized xhci-hcd.
	 * This will allow to inherit all the usb_phy callbacks, if any,
	 * used for example at phy connect/disconnect time.
	 */
	hcd = platform_get_drvdata(xhci);
	xhci_dev = hcd_to_xhci(hcd);
	xhci_dev->shared_hcd->phy = dwc->usb3_phy;
#endif /* MY_DEF_HERE */

	return 0;

err1:
	platform_device_put(xhci);

err0:
	return ret;
}

void dwc3_host_exit(struct dwc3 *dwc)
{
	platform_device_unregister(dwc->xhci);
}
