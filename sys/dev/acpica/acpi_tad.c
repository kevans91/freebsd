/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 */

#include "opt_acpi.h"

#include <sys/param.h>
#include <sys/clock.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>

#include "clock_if.h"

/* Hooks for the ACPI CA debugging infrastructure */
#define _COMPONENT	ACPI_TAD
ACPI_MODULE_NAME("TAD")

struct acpi_tad_softc {
	device_t		tad_dev;
	ACPI_HANDLE		tad_handle;
	uint32_t		tad_cap;
};

#define	TADCAP_ACWAKE		0x0001	/* Supports AC wake */
#define	TADCAP_DCWAKE		0x0002	/* Supports DC wake */
#define	TADCAP_RTC		0x0004	/* Supports get/set real time */
#define	TADCAP_MSACC		0x0008	/* Accuracy in milliseconds */
#define	TADCAP_GWSOK		0x0010
#define	TADCAP_WAKES4AC		0x0020	/* Wake from S4 on AC */
#define	TADCAP_WAKES5AC		0x0040	/* Wake from S5 on AC */
#define	TADCAP_WAKES4DC		0x0080	/* Wake from S4 on DC */
#define	TADCAP_WAKES5DC		0x0100	/* Wake from S5 on DC */

#define	RTC_SEC_RES		1000000
#define	RTC_MSEC_RES		1000

#define	MSEC_IN_NS	1000000

static int	acpi_tad_probe(device_t dev);
static int	acpi_tad_attach(device_t dev);
static int	acpi_tad_detach(device_t dev);

static int	acpi_tad_gettime(device_t dev, struct timespec *ts);
static int	acpi_tad_settime(device_t dev, struct timespec *ts);

static char *tad_ids[] = {
	"ACPI000E",
	NULL
};

static device_method_t acpi_tad_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		acpi_tad_probe),
	DEVMETHOD(device_attach,	acpi_tad_attach),
	DEVMETHOD(device_detach,	acpi_tad_detach),

	/* Clock interface */
	DEVMETHOD(clock_gettime,	acpi_tad_gettime),
	DEVMETHOD(clock_settime,	acpi_tad_settime),

	DEVMETHOD_END
};

static driver_t acpi_tad_driver = {
	"acpi_tad",
	acpi_tad_methods,
	sizeof(struct acpi_tad_softc),
};

DRIVER_MODULE(acpi_tad, acpi, acpi_tad_driver, 0, 0);
MODULE_DEPEND(acpi_tad, acpi, 1, 1, 1);

/*
 * _SRT buffer is structurally identical, tm_valid is instead pad1.
 */
struct acpi_tad_tm {
	uint16_t	tm_year;	/* 1900 - 9999 */
	uint8_t		tm_mon;		/* 1-12 */
	uint8_t		tm_day;		/* 1-31 */
	uint8_t		tm_hour;	/* 0-59 */
	uint8_t		tm_min;		/* 0-59 */
	uint8_t		tm_sec;		/* 0-59 */
	uint8_t		tm_valid;	/* 0 invalid, 1 invalid */
	uint16_t	tm_msec;	/* 1-1000 */
	uint16_t	tm_tz;		/* -1440 - 1440 or 2047 (unspecified) */
	uint8_t		tm_dst;
	uint8_t		tm_pad2[3];	/* Must be zero */
};

static int
acpi_tad_probe(device_t dev)
{
	int rv;

	if (acpi_disabled("tad"))
		return (ENXIO);

	rv = ACPI_ID_PROBE(device_get_parent(dev), dev, tad_ids, NULL);
	if (rv > 0)
		return (ENXIO);

	device_set_desc(dev, "Time and Alarm Device (RTC)");
	return (rv);
}

static int
acpi_tad_attach(device_t dev)
{
	struct acpi_tad_softc *sc;
	ACPI_STATUS status;
	ACPI_BUFFER outbuf;
	ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

	sc = device_get_softc(dev);
	sc->tad_dev = dev;
	sc->tad_handle = acpi_get_handle(dev);

	outbuf.Pointer = &sc->tad_cap;
	outbuf.Length = sizeof(sc->tad_cap);
	status = AcpiEvaluateObject(sc->tad_handle, "_GCP", NULL, &outbuf);
	if (ACPI_FAILURE(status)) {
		device_printf(dev, "_GCP failed\n");
		return (ENXIO);
	}

	if ((sc->tad_cap & TADCAP_RTC) == 0) {
		device_printf(dev, "does not support RTC\n");
		return (ENXIO);
	}

	/* Resolution is either 1ms or 1s */
	if ((sc->tad_cap & TADCAP_MSACC) != 0)
		clock_register(dev, RTC_MSEC_RES);
	else
		clock_register(dev, RTC_SEC_RES);

	return (0);
}

static int
acpi_tad_detach(device_t dev)
{

	clock_unregister(dev);
	return (0);
}

static int
acpi_tad_gettime(device_t dev, struct timespec *ts)
{
	ACPI_BUFFER tmbuf;
	struct acpi_tad_softc *sc = device_get_softc(dev);
	struct clocktime ct;
	struct acpi_tad_tm tm = { 0 };
	ACPI_STATUS status;

	tmbuf.Pointer = (uint8_t *)&tm;
	tmbuf.Length = sizeof(tm);
	status = AcpiEvaluateObject(sc->tad_handle, "_GRT", NULL, &tmbuf);
	if (ACPI_FAILURE(status) || !tm.tm_valid) {
		device_printf(dev, "_GRT failed\n");
		return (EINVAL);
	}

	ct.sec = tm.tm_sec;
	ct.min = tm.tm_min;
	ct.hour = tm.tm_hour;
	ct.day = tm.tm_day;
	ct.mon = tm.tm_mon;
	ct.year = tm.tm_year;
	ct.nsec = tm.tm_msec * MSEC_IN_NS;

	clock_dbgprint_ct(dev, CLOCK_DBG_READ, &ct);
	return (clock_ct_to_ts(&ct, ts));
}

static int
acpi_tad_settime(device_t dev, struct timespec *ts)
{
	ACPI_OBJECT arg;
	ACPI_OBJECT_LIST arglist;
	struct acpi_tad_softc *sc = device_get_softc(dev);
	struct clocktime ct;
	struct acpi_tad_tm tm = { 0 };
	ACPI_STATUS status;

	clock_ts_to_ct(ts, &ct);
	clock_dbgprint_ct(dev, CLOCK_DBG_WRITE, &ct);

	tm.tm_sec = ct.sec;
	tm.tm_min = ct.min;
	tm.tm_hour = ct.hour;
	tm.tm_day = ct.day;
	tm.tm_mon = ct.mon;
	tm.tm_year = ct.year;
	tm.tm_msec = ct.nsec / MSEC_IN_NS;

	arglist.Pointer = &arg;
	arglist.Count = 1;
	arg.Type = ACPI_TYPE_BUFFER;
	arg.Buffer.Length = sizeof(tm);
	arg.Buffer.Pointer = (uint8_t *)&tm;

	status = AcpiEvaluateObject(sc->tad_handle, "_SRT", &arglist, NULL);
	if (ACPI_FAILURE(status)) {
		device_printf(dev, "_SRT failed\n");
		return (EINVAL);
	}

	return (0);
}
