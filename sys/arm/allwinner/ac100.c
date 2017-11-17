/*-
 * Copyright (c) 2014 Jared D. McNeill <jmcneill@invisible.ca>
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/clock.h>
#include <sys/rman.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include "clock_if.h"
#include "iicbus_if.h"

#define	AC100_CHIP_AUDIO_RST_REG	0x00
#define	AC100_PLL_CTRL1_REG		0x02
#define	AC100_PLL_CTRL2_REG		0x03
#define	AC100_SYSCLK_CTRL_REG		0x04
#define	AC100_MOD_RST_CTRL_REG		0x05
#define	AC100_ADDA_SR_CTRL_REG		0x06
#define	AC100_I2S1_LCK_CTRL_REG		0x10
#define	AC100_I2S1_SDIN_CTRL_REG	0x11
#define	AC100_I2S1_SDOUT_CTRL_REG	0x12
#define	AC100_I2S1_DIG_MIXER_REG	0x13
#define	AC100_I2S1_VOL_CTRL1_REG	0x14
#define	AC100_I2S1_VOL_CTRL2_REG	0x15
#define	AC100_I2S1_VOL_CTRL3_REG	0x16
#define	AC100_I2S1_VOL_CTRL4_REG	0x17
#define	AC100_I2S1_MXR_GAIN_REG		0x18
#define	AC100_I2S2_CLK_CTRL_REG		0x20
#define	AC100_I2S2_SDIN_CTRL_REG	0x21
#define	AC100_I2S2_SDOUT_CTRL_REG	0x22
#define	AC100_I2S2_DIG_MIXER_REG	0x23
#define	AC100_I2S2_VOL_CTRL1_REG	0x24
#define	AC100_I2S2_VOL_CTRL2_REG	0x26
#define	AC100_I2S2_MXR_GAIN_REG		0x28
#define	AC100_I2S3_CLK_CTRL_REG		0x30
#define	AC100_I2S3_SDIN_CTRL_REG	0x31
#define	AC100_I2S3_SDOUT_CTRL_REG	0x32
#define	AC100_I2S3_SGP_CTRL_REG		0x33
#define	AC100_ADC_DIG_CTRL_REG		0x40

#define	AC100_RTC_RESET_REG		0xc6
#define	AC100_RTC_CTRL_REG		0xc7
#define	AC100_RTC_SEC_REG		0xc8
#define	AC100_RTC_MIN_REG		0xc9
#define	AC100_RTC_HOU_REG		0xca
#define	AC100_RTC_WEE_REG		0xcb
#define	AC100_RTC_DAY_REG		0xcc
#define	AC100_RTC_MON_REG		0xcd
#define	AC100_RTC_YEA_REG		0xce
#define	AC100_RTC_UPD_TRIG_REG		0xcf

#define	AC100_RTC_GP_REG(n)		(0xe0 + (n))

#define	AC100_RTC_CTRL_12H_24H_MODE	(1 << 0)

#define	AC100_RTC_UPD_TRIG_WRITE	(1 << 15)

#define	HALF_OF_SEC_NS			500000000
#define	RTC_RES_US				1000000


static struct ofw_compat_data ac100_compat_data[] = {
	{ "x-powers,ac100", 1 },
	{ NULL, 0 }
};

static struct ofw_compat_data ac100_rtc_compat_data[] = {
	{ "x-powers,ac100-rtc", 1 },
	{ NULL, 0 }
};

struct ac100_softc {
	device_t		dev;
	struct resource	*res;

	uint16_t		addr;
	phandle_t		rtc;	/* RTC fdt node */
};


static int ac100_rtc_gettime(device_t, struct timespec *);
static int ac100_rtc_settime(device_t, struct timespec *);

static int ac100_read(device_t, uint8_t, uint8_t *, uint8_t);
static int ac100_write(device_t, uint8_t, uint8_t *, uint8_t);

static int ac100_read_word(device_t, uint8_t, uint16_t *);
static int ac100_write_word(device_t, uint8_t, uint16_t);
const struct ofw_compat_data * ofw_bus_node_search_compatible(phandle_t,
    const struct ofw_compat_data *);

const struct ofw_compat_data *
ofw_bus_node_search_compatible(phandle_t node,
    const struct ofw_compat_data *compat)
{

	if (compat == NULL)
		return NULL;

	for (; compat->ocd_str != NULL; ++compat) {
		if (ofw_bus_node_is_compatible(node, compat->ocd_str))
			break;
	}

	return (compat);
}

static int
ac100_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, ac100_compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "X-Powers AC100");
	return (BUS_PROBE_DEFAULT);
}

static int
ac100_rtc_attach(device_t dev)
{
	struct ac100_softc *sc;
	phandle_t rtc;
	int data;

	sc = device_get_softc(dev);
	rtc = ofw_bus_find_child(ofw_bus_get_node(dev), "rtc");
	if (rtc == 0)
		return (1);

	/* Check for compatibility */
	data = ofw_bus_node_search_compatible(rtc, ac100_rtc_compat_data)->ocd_data;
	if (data == 0)
		return (1);

	sc->rtc = rtc;

    ac100_write_word(dev, AC100_RTC_CTRL_REG, AC100_RTC_CTRL_12H_24H_MODE);
    clock_register(dev, RTC_RES_US);
	if (bootverbose)
		device_printf(dev, "RTC module initialized");
	return (0);
}


static int
ac100_attach(device_t dev)
{
	struct ac100_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->addr = iicbus_get_addr(dev);
	sc->rtc = 0;

	if (ac100_rtc_attach(dev) > 0 && bootverbose)
		device_printf(dev, "No RTC module");

	return (0);
}

static int
ac100_detach(device_t dev)
{
	struct ac100_softc *sc;

	sc = device_get_softc(dev);
	/* Cannot detach if we have an RTC */
	if (sc->rtc > 0)
			return (EBUSY);

	/* XXX TODO: Detach */
	return (EBUSY);
}

static int
ac100_read(device_t dev, uint8_t reg, uint8_t *data, uint8_t size)
{
	struct ac100_softc *sc;
	struct iic_msg msg[2];

	sc = device_get_softc(dev);

	msg[0].slave = sc->addr;
	msg[0].flags = IIC_M_WR;
	msg[0].len = 1;
	msg[0].buf = &reg;

	msg[1].slave = sc->addr;
	msg[1].flags = IIC_M_RD;
	msg[1].len = size;
	msg[1].buf = data;

	return (iicbus_transfer(dev, msg, 2));
}

static int
ac100_read_word(device_t dev, uint8_t reg, uint16_t *data)
{
	return (ac100_read(dev, reg, (uint8_t *)data, 2));
}

static int
ac100_write(device_t dev, uint8_t reg, uint8_t *data, uint8_t size)
{
	struct ac100_softc *sc;
	struct iic_msg msg[2];

	sc = device_get_softc(dev);

	msg[0].slave = sc->addr;
	msg[0].flags = IIC_M_WR;
	msg[0].len = 1;
	msg[0].buf = &reg;

	msg[1].slave = sc->addr;
	msg[1].flags = IIC_M_WR;
	msg[1].len = size;
	msg[1].buf = data;

	return (iicbus_transfer(dev, msg, 2));
}

static int
ac100_write_word(device_t dev, uint8_t reg, uint16_t val)
{
	uint8_t data[2];

	data[0] = val & 0xff;
	data[1] = (val >> 8) & 0xff;

	return (ac100_write(dev, reg, data, 2));
}

static int
ac100_rtc_gettime(device_t dev, struct timespec *dt)
{
	struct ac100_softc *sc;
	struct clocktime ct;
	uint16_t sec, min, hou, wee, day, mon, yea;

	sc = device_get_softc(dev);
	/* No supported RTC */
	if (sc->rtc == 0)
		return (1);
	ac100_read_word(dev, AC100_RTC_SEC_REG, &sec);
	ac100_read_word(dev, AC100_RTC_MIN_REG, &min);
	ac100_read_word(dev, AC100_RTC_HOU_REG, &hou);
	ac100_read_word(dev, AC100_RTC_WEE_REG, &wee);
	ac100_read_word(dev, AC100_RTC_DAY_REG, &day);
	ac100_read_word(dev, AC100_RTC_MON_REG, &mon);
	ac100_read_word(dev, AC100_RTC_YEA_REG, &yea);

	ct.year = POSIX_BASE_YEAR + bcd2bin(yea & 0xff);
	ct.mon = bcd2bin(mon & 0x1f);
	ct.day = bcd2bin(day & 0x3f);
	ct.hour = bcd2bin(hou & 0x3f);
	ct.min = bcd2bin(min & 0x7f);
	ct.sec = bcd2bin(sec & 0x7f);
	ct.dow = bcd2bin(wee & 0x7);
	ct.nsec = 0;

	return (clock_ct_to_ts(&ct, dt));
}

static int
ac100_rtc_settime(device_t dev, struct timespec *dt)
{
	struct ac100_softc *sc;
	struct clocktime ct;

	sc = device_get_softc(dev);
	/* No supported RTC */
	if (sc->rtc == 0)
		return (1);
	if (dt->tv_nsec >= HALF_OF_SEC_NS)
		dt->tv_sec++;
	dt->tv_nsec = 0;
	clock_ts_to_ct(dt, &ct);

	ac100_write_word(dev, AC100_RTC_WEE_REG, bin2bcd(ct.dow) & 0x7);
	ac100_write_word(dev, AC100_RTC_SEC_REG, bin2bcd(ct.sec) & 0x7f);
	ac100_write_word(dev, AC100_RTC_MIN_REG, bin2bcd(ct.min) & 0x7f);
	ac100_write_word(dev, AC100_RTC_HOU_REG, bin2bcd(ct.hour) & 0x3f);
	ac100_write_word(dev, AC100_RTC_DAY_REG, bin2bcd(ct.day) & 0x3f);
	ac100_write_word(dev, AC100_RTC_MON_REG, bin2bcd(ct.mon) & 0x1f);
	ac100_write_word(dev, AC100_RTC_YEA_REG,
	    bin2bcd(ct.year - POSIX_BASE_YEAR) & 0xff);
	ac100_write_word(dev, AC100_RTC_UPD_TRIG_REG,
	    AC100_RTC_UPD_TRIG_WRITE);

	return (0);
}

static device_method_t ac100_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		ac100_probe),
	DEVMETHOD(device_attach,	ac100_attach),
	DEVMETHOD(device_detach,	ac100_detach),

	/* Clock interface */
	DEVMETHOD(clock_gettime,	ac100_rtc_gettime),
	DEVMETHOD(clock_settime,	ac100_rtc_settime),

	DEVMETHOD_END
};

static driver_t ac100_driver = {
	"ac100",
	ac100_methods,
	sizeof(struct ac100_softc),
};

static devclass_t ac100_devclass;

EARLY_DRIVER_MODULE(ac100, iicbus, ac100_driver, ac100_devclass, 0, 0,
    BUS_PASS_RESOURCE + BUS_PASS_ORDER_LATE);
MODULE_VERSION(ac100, 1);
MODULE_DEPEND(ac100, iicbus, 1, 1, 1);
