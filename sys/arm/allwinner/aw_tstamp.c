/*-
 * Copyright (c) 2017 Kyle Evans <kevans@FreeBSD.org>
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

/*
 * Allwinner timestamp driver
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/sysctl.h>
#include <machine/bus.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

/* Control registers */
#define	TSTAMP_CTRL_REG		0x00
#define	 TSTAMP_CTRL_EN		(1 << 0)

#define	TSTAMP_CTRL_LOW		0x08
#define	TSTAMP_CTRL_HIGH	0x0c

#define	TSTAMP_CTRL_FREQ_REG	0x20
#define	 TSTAMP_CTRL_FREQ	0x16e3600	/* 24 MHz */

struct aw_tstamp_softc {
	device_t		dev;
	struct resource *	res[1];
};

static struct resource_spec aw_tstamp_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE }, /* CTRL */
	{ -1, 0 }
};


static struct ofw_compat_data compat_data[] = {
	{"allwinner,sun8i-a83t-timestamp", 1},
	{NULL,             0}
};

#define	READ(_sc, _r) bus_read_4((_sc)->res[0], (_r))
#define	WRITE(_sc, _r, _v) bus_write_4((_sc)->res[0], (_r), (_v))

static uint64_t aw_tstamp_read(struct aw_tstamp_softc *sc);
static int aw_tstamp_sysctl(SYSCTL_HANDLER_ARGS);

static uint64_t
aw_tstamp_read(struct aw_tstamp_softc *sc)
{
	uint32_t hi, lo;

	do {
		hi = READ(sc, TSTAMP_CTRL_HIGH);
		lo = READ(sc, TSTAMP_CTRL_LOW);
	} while (hi != READ(sc, TSTAMP_CTRL_HIGH));

	return ((uint64_t)hi << 32) | lo;
}

static int
aw_tstamp_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct aw_tstamp_softc *sc;
	device_t dev = arg1;
	uint64_t timestamp;

	sc = device_get_softc(dev);
	timestamp = aw_tstamp_read(sc);
	return (sysctl_handle_64(oidp, &timestamp, 0, req));
}

static int
aw_tstamp_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Allwinner timestamp module");
	return (BUS_PROBE_DEFAULT);
}

static int
aw_tstamp_attach(device_t dev)
{
	struct aw_tstamp_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, aw_tstamp_spec, sc->res) != 0) {
		device_printf(dev, "could not allocate memory resource\n");
		return (ENXIO);
	}

	/* Set frequency */
	WRITE(sc, TSTAMP_CTRL_FREQ_REG, TSTAMP_CTRL_FREQ);

	/* Enable it */
	WRITE(sc, TSTAMP_CTRL_REG, TSTAMP_CTRL_EN);

	device_printf(dev, "value = %llu\n", aw_tstamp_read(sc));

	/* Add sysctl */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "value", CTLTYPE_U64 | CTLFLAG_RD,
	    dev, 0, aw_tstamp_sysctl,
	    "LU", "Timestamp");

	return (0);
}

static device_method_t aw_tstamp_methods[] = {
	DEVMETHOD(device_probe, aw_tstamp_probe),
	DEVMETHOD(device_attach, aw_tstamp_attach),

	DEVMETHOD_END
};

static driver_t aw_tstamp_driver = {
	"aw_tstamp",
	aw_tstamp_methods,
	sizeof(struct aw_tstamp_softc),
};
static devclass_t aw_tstamp_devclass;

DRIVER_MODULE(aw_tstamp, simplebus, aw_tstamp_driver, aw_tstamp_devclass, 0, 0);
