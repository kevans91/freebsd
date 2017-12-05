/*-
 * Copyright (c) 2016 Jared McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * Allwinner A83T HDMI transmitter
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <machine/bus.h>

#include <dev/extres/clk/clk.h>
#include <dev/extres/hwreset/hwreset.h>

#include <dev/videomode/videomode.h>
#include <dev/videomode/edidvar.h>

#include <dev/iicbus/iiconf.h>
#include <dev/iicbus/iicbus.h>

#include <dev/hdmi/dwc_hdmi.h>

#define	HDMI_READ_EN		0x10010
#define	 HDMI_READ_ENABLE	0x54524545	/* "TREE" */
#define	 HDMI_READ_DISABLE	0x57415452	/* "WATR" */
#define	HDMI_SCRAMBLE_EN	0x10014
#define	 HDMI_SCRAMBLE_ENABLE	0x0
#define	 HDMI_SCRAMBLE_DISABLE	0x42494e47	/* "BING" */

#include "hdmi_if.h"
#include "iicbus_if.h"

struct a83t_hdmi_softc {
	struct dwc_hdmi_softc	base;
	device_t		iicbus;
	clk_t			clk_bus;
	clk_t			clk_hdmi;
	clk_t			clk_hdmi_ddc;
	hwreset_t		rst_hdmi0;
	hwreset_t		rst_hdmi1;
};

static struct ofw_compat_data compat_data[] = {
	{ "allwinner,sun8i-a83t-hdmi",	1 },
	{ NULL,	            		0 }
};

static device_t
a83t_hdmi_get_i2c_dev(device_t dev)
{
	struct a83t_hdmi_softc *sc;

	sc = device_get_softc(dev);

	return (sc->iicbus);
}

static phandle_t
a83t_hdmi_get_node(device_t bus, device_t dev)
{
	return (ofw_bus_get_node(bus));
}

static int
a83t_hdmi_detach(device_t dev)
{
	struct a83t_hdmi_softc *sc;

	sc = device_get_softc(dev);

	if (sc->clk_hdmi_ddc != NULL)
		clk_release(sc->clk_hdmi_ddc);
	if (sc->clk_hdmi != NULL)
		clk_release(sc->clk_hdmi);
	if (sc->clk_bus != NULL)
		clk_release(sc->clk_bus);
	if (sc->rst_hdmi0 != NULL)
		hwreset_release(sc->rst_hdmi0);
	if (sc->rst_hdmi1 != NULL)
		hwreset_release(sc->rst_hdmi1);

	if (sc->base.sc_mem_res != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    sc->base.sc_mem_rid, sc->base.sc_mem_res);

	return (0);
}

static int
a83t_hdmi_attach(device_t dev)
{
	struct a83t_hdmi_softc *sc;
	int err;

	sc = device_get_softc(dev);
	sc->base.sc_dev = dev;
	sc->base.sc_get_i2c_dev = a83t_hdmi_get_i2c_dev;
	sc->base.sc_reg_shift = 0;
	err = 0;

	/* Allocate memory resources. */
	sc->base.sc_mem_rid = 0;
	sc->base.sc_mem_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &sc->base.sc_mem_rid, RF_ACTIVE);
	if (sc->base.sc_mem_res == NULL) {
		device_printf(dev, "Cannot allocate memory resources\n");
		err = ENXIO;
		goto out;
	}

	if (clk_get_by_ofw_name(dev, 0, "bus", &sc->clk_bus) != 0 ||
	    clk_get_by_ofw_name(dev, 0, "clock", &sc->clk_hdmi) != 0 ||
	    clk_get_by_ofw_name(dev, 0, "ddc-clock", &sc->clk_hdmi_ddc) != 0) {
		device_printf(dev, "Cannot get clocks\n");
		err = ENXIO;
		goto out;
	}
	if (hwreset_get_by_ofw_name(dev, 0, "hdmi0", &sc->rst_hdmi0) != 0 ||
	    hwreset_get_by_ofw_name(dev, 0, "hdmi1", &sc->rst_hdmi1) != 0) {
		device_printf(dev, "Cannot get resets\n");
		err = ENXIO;
		goto out;
	}

	if (clk_enable(sc->clk_hdmi_ddc) != 0) {
		device_printf(dev, "Cannot enable HDMI DDC clock\n");
		err = ENXIO;
		goto out;
	}
	if (clk_enable(sc->clk_hdmi) != 0) {
		device_printf(dev, "Cannot enable HDMI clock\n");
		err = ENXIO;
		goto out;
	}
	if (clk_enable(sc->clk_bus) != 0) {
		device_printf(dev, "Cannot enable AHB clock\n");
		err = ENXIO;
		goto out;
	}
	if (hwreset_deassert(sc->rst_hdmi0) != 0 ||
	    hwreset_deassert(sc->rst_hdmi1) != 0) {
		device_printf(dev, "Cannot de-assert resets\n");
		err = ENXIO;
		goto out;
	}

	/* Enable read access */
	bus_write_4(sc->base.sc_mem_res, HDMI_READ_EN, HDMI_READ_ENABLE);

	/* Disable register scrambling */
	bus_write_4(sc->base.sc_mem_res, HDMI_SCRAMBLE_EN,
	    HDMI_SCRAMBLE_DISABLE);

	sc->iicbus = device_add_child(dev, "iicbus", -1);

	bus_generic_attach(dev);

	return (dwc_hdmi_init(dev));

out:

	a83t_hdmi_detach(dev);

	return (err);
}

static int
a83t_hdmi_probe(device_t dev)
{

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Allwinner sun8i HDMI Controller");

	return (BUS_PROBE_DEFAULT);
}

static device_method_t a83t_hdmi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,  a83t_hdmi_probe),
	DEVMETHOD(device_attach, a83t_hdmi_attach),
	DEVMETHOD(device_detach, a83t_hdmi_detach),

	/* HDMI methods */
	DEVMETHOD(hdmi_get_edid,	dwc_hdmi_get_edid),
	DEVMETHOD(hdmi_set_videomode,	dwc_hdmi_set_videomode),

	/* OFW methods */
	DEVMETHOD(ofw_bus_get_node,	a83t_hdmi_get_node),

	/* iicbus methods */
	DEVMETHOD(iicbus_callback,	iicbus_null_callback),
	DEVMETHOD(iicbus_reset,		dwc_hdmi_i2cm_reset),
	DEVMETHOD(iicbus_transfer,	dwc_hdmi_i2cm_transfer),

	DEVMETHOD_END
};

static driver_t a83t_hdmi_driver = {
	"iichb",
	a83t_hdmi_methods,
	sizeof(struct a83t_hdmi_softc)
};

static devclass_t a83t_hdmi_devclass;

DRIVER_MODULE(iicbus, a83t_hdmi, iicbus_driver,
    iicbus_devclass, 0, 0);
DRIVER_MODULE(a83t_hdmi, simplebus, a83t_hdmi_driver,
    a83t_hdmi_devclass, 0, 0);
