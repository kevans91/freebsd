/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Michael J. Karels <karels@freebsd.org>
 * Copyright (c) 2012 Alexander Rybalko <ray@freebsd.org>
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

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/reboot.h>
#include <sys/rman.h>
#include <sys/systm.h>
#include <sys/watchdog.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/extres/clk/clk.h>

#include <machine/bus.h>
#include <machine/machdep.h>

#define	APLWD_WD0_TIMER		0x0000
#define	APLWD_WD0_RESET		0x0004
#define	APLWD_WD0_INTR		0x0008
#define	APLWD_WD0_CNTL		0x000c

#define	APLWD_WD1_TIMER		0x0010
#define	APLWD_WD1_RESET		0x0014
#define	APLWD_WD1_CNTL		0x001c

#define	APLWD_WD2_TIMER		0x0020
#define	APLWD_WD2_RESET		0x0024
#define	APLWD_WD2_CNTL		0x002c

#define	APLWD_CNTL_INTENABLE	0x0001
#define	APLWD_CNTL_INTSTAT	0x0002
#define	APLWD_CNTL_RSTENABLE	0x0004

#define	READ(_sc, _r) bus_space_read_4((_sc)->bst, (_sc)->bsh, (_r))
#define	WRITE(_sc, _r, _v) bus_space_write_4((_sc)->bst, (_sc)->bsh, (_r), (_v))

struct aplwd_softc {
	device_t		dev;
	struct resource *	res;
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	clk_t			clk;
	uint64_t		clk_freq;
	struct mtx		mtx;
};

static struct aplwd_softc *aplwd_lsc = NULL;

static struct ofw_compat_data compat_data[] = {
	{"apple,reboot-v0",	1},
	{"apple,wdt",		1},
	{NULL,			0}
};

static void aplwd_watchdog_fn(void *private, u_int cmd, int *error);
static void aplwd_reboot_system(void *, int);

static int
aplwd_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Apple Watchdog");

	return (BUS_PROBE_DEFAULT);
}

static int
aplwd_attach(device_t dev)
{
	struct aplwd_softc *sc;
	int error, rid;

	if (aplwd_lsc != NULL)
		return (ENXIO);

	sc = device_get_softc(dev);
	sc->dev = dev;

	rid = 0;
	sc->res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid, RF_ACTIVE);
	if (sc->res == NULL) {
		device_printf(dev, "could not allocate memory resource\n");
		return (ENXIO);
	}

	sc->bst = rman_get_bustag(sc->res);
	sc->bsh = rman_get_bushandle(sc->res);

	error = clk_get_by_ofw_index(dev, 0, 0, &sc->clk);
	if (error != 0) {
		device_printf(dev, "cannot get clock\n");
		goto fail;
	}
	error = clk_enable(sc->clk);
	if (error != 0) {
		device_printf(dev, "cannot enable clock\n");
		goto fail;
	}
	error = clk_get_freq(sc->clk, &sc->clk_freq);
	if (error != 0) {
		device_printf(dev, "cannot get base frequency\n");
		goto fail;
	}
// temp/debug:
device_printf(dev, "base frequency %jd\n", (intmax_t) sc->clk_freq);
sc->clk_freq = 24000000;

	aplwd_lsc = sc;
	mtx_init(&sc->mtx, "Apple Watchdog", "aplwd", MTX_DEF);
	EVENTHANDLER_REGISTER(watchdog_list, aplwd_watchdog_fn, sc, 0);
	EVENTHANDLER_REGISTER(shutdown_final, aplwd_reboot_system, sc,
	    SHUTDOWN_PRI_LAST);

	WRITE(sc, APLWD_WD0_CNTL, 0);
	WRITE(sc, APLWD_WD1_CNTL, 0);

	return (0);

fail:
	return (error);
}

static void
aplwd_watchdog_fn(void *private, u_int cmd, int *error)
{
	struct aplwd_softc *sc;
	uint64_t sec;
	uint32_t ticks;

	sc = private;
	mtx_lock(&sc->mtx);

	cmd &= WD_INTERVAL;

	if (cmd > 0) {
		sec = ((uint64_t)1 << (cmd & WD_INTERVAL)) / 1000000000;
#if 0
		if (sec == 0 || sec > 15) {
			/*
			 * Can't arm
			 * disable watchdog as watchdog(9) requires
			 */
			device_printf(sc->dev,
			    "Can't arm, timeout must be between 1-15 seconds\n");
			WRITE(sc, APLWD_WD1_CNTL, 0);
			mtx_unlock(&sc->mtx);
			*error = EINVAL;
			return;
		}
#endif

		ticks = sec * sc->clk_freq;
		WRITE(sc, APLWD_WD1_TIMER, 0);
		WRITE(sc, APLWD_WD1_RESET, ticks);
		WRITE(sc, APLWD_WD1_CNTL, APLWD_CNTL_RSTENABLE);

		*error = 0;
	} else
		WRITE(sc, APLWD_WD1_CNTL, 0);

	mtx_unlock(&sc->mtx);
}

#if 0	/* what is this for? */
void
aplwd_watchdog_reset(void)
{

	if (aplwd_lsc == NULL)
		return;

	WRITE(aplwd_lsc, APLWD_WD1_CNTL, 0);
}
#endif

static void
aplwd_reboot_system(void *private, int howto)
{
	struct aplwd_softc *sc = private;

	/* Only handle reset. */
	if (howto & RB_HALT || howto & RB_POWEROFF)
		return;

	printf("Resetting system ... ");

	WRITE(sc, APLWD_WD1_CNTL, APLWD_CNTL_RSTENABLE);
	WRITE(sc, APLWD_WD1_RESET, 1);
	WRITE(sc, APLWD_WD1_TIMER, 0);
#if 0	/* Linux does this read */
	(void) READ(sc, APLWD_WD1_TIMER);
#endif

	/* Wait for watchdog timeout; should take milliseconds. */
	DELAY(2000000);

	/* Not reached ... one hopes. */
	printf("failed to reset.\n");
}

static device_method_t aplwd_methods[] = {
	DEVMETHOD(device_probe, aplwd_probe),
	DEVMETHOD(device_attach, aplwd_attach),

	DEVMETHOD_END
};

static driver_t aplwd_driver = {
	"aplwd",
	aplwd_methods,
	sizeof(struct aplwd_softc),
};
static devclass_t aplwd_devclass;

DRIVER_MODULE(aplwd, simplebus, aplwd_driver, aplwd_devclass, 0, 0);
