/*-
 * Copyright (c) 2017 Jared McNeill <jmcneill@invisible.ca>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Allwinner Display Engine 2.0
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/fbio.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/bus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/videomode/videomode.h>
#include <dev/videomode/edidvar.h>

#include <dev/extres/clk/clk.h>
#include <dev/extres/hwreset/hwreset.h>

#include "fb_if.h"
#include "hdmi_if.h"

#define	FB_DEFAULT_W	800
#define	FB_DEFAULT_H	600
#define	FB_DEFAULT_REF	60
#define	FB_MAX_W	1920
#define	FB_MAX_H	1080
#define	FB_MAX_BW	(1920 * 1080 * 60)
#define	FB_BPP		32
#define	FB_ALIGN	0x1000

#define	HDMI_ENABLE_DELAY	20000

#define	DOT_CLOCK_TO_HZ(c)	((c) * 1000)
#define	FB_DIVIDE(x, y)		(((x) + ((y) / 2)) / (y))

/* Display backend */
#define	DE_MOD_REG		0x0000
#define	DE_GATE_REG		0x0004
#define	DE_RESET_REG		0x0008
#define	DE_DIV_REG		0x000c
#define	DE_SEL_REG		0x0010
#define	 DE_SEL_LCD_MASK	(1 << 0)
#define	 DE_SEL_LCD_0		0
#define	 DE_SEL_LCD_1		1

#define	DE_XY(x, y)		(((y) << 16) | (x))
#define	DE_WH(w, h)		((((h) - 1) << 16) | ((w) - 1))

#define	DE_MUX_BASE(_lcd)	(0x00100000 + ((_lcd) * 0x00100000))

/* Global control */
#define	DE_GLB_BASE(_lcd)	(DE_MUX_BASE(_lcd) + 0x0000)
#define	GLB_CTL			0x00
#define	 GLB_CTL_RTWB_PORT	(1 << 12)
#define	 GLB_CTL_RT_EN		(1 << 0)
#define	GLB_STATUS		0x04
#define	GLB_DBUFF		0x08
#define	GLB_SIZE		0x0c
	
/* Alpha blending */
#define	DE_BLD_BASE(_lcd)	(DE_MUX_BASE(_lcd) + 0x1000)
#define	BLD_FCOLOR_CTL		0x00
#define	BLD_FCOLOR_ATTR(n)	(0x04 + (n) * 0x10)
#define	BLD_INSIZE_ATTR(n)	(0x08 + (n) * 0x10)
#define	BLD_OFFSET_ATTR(n)	(0x0c + (n) * 0x10)
#define	BLD_ROUTE		0x80
#define	BLD_PREMULT		0x84
#define	BLD_BKCOLOR		0x88
#define	BLD_OUTPUT_SIZE		0x8c
#define	BLD_MODE(n)		(0x90 + (n) * 0x4)
#define	BLD_CK_CTL		0xb0
#define	BLD_CK_CFG		0xb4
#define	BLD_CK_MAX(n)		(0xc0 + (n) * 0x4)
#define	BLD_CK_MIN(n)		(0xe0 + (n) * 0x4)
#define	BLD_OUT_CTL		0xfc

/* Mixers (VI/UI) */
#define	DE_MIXER_BASE(_lcd, _ch)	(DE_MUX_BASE(_lcd) + 0x2000 + (_ch) * 0x1000)

/* VI channel */
#define	VI_SIZE			0x100

/* UI channel */
#define	UI_ATTR_CFG(n)		(0x00 + (n) * 0x20)
#define	 UI_ATTR_FMT		(0x1f << 8)
#define	 UI_ATTR_FMT_SHIFT	8
#define	  UI_ATTR_FMT_XRGB8888	(4 << UI_ATTR_FMT_SHIFT)
#define	 UI_ATTR_EN		(1 << 0)
#define	UI_SIZE_CFG(n)		(0x04 + (n) * 0x20)
#define	UI_COORD_CFG(n)		(0x08 + (n) * 0x20)
#define	UI_PITCH_CFG(n)		(0x0c + (n) * 0x20)
#define	UI_TOP_LADDR_CFG(n)	(0x10 + (n) * 0x20)
#define	UI_BOT_LADDR_CFG(n)	(0x14 + (n) * 0x20)
#define	UI_FCOLOR_CFG(n)	(0x18 + (n) * 0x20)
#define	UI_TOP_HADDR		0x80
#define	UI_BOT_HADDR		0x84
#define	UI_OVL_SIZE		0x88
#define	UI_SIZE			0x8c

/* Timing controller */
#define	TCON_GCTL		0x000
#define	 TCON_GCTL_EN		(1 << 31)
#define	TCON_GINT0		0x004
#define	TCON_GINT1		0x008
#define	TCON0_CTL		0x040
#define	 TCON0_CTL_EN		(1 << 31)
#define	TCON0_DCLK		0x044
#define	 DCLK_EN		0xf0000000
#define	TCON1_CTL		0x090
#define	 TCON1_CTL_EN		(1 << 31)
#define	 TCON1_CTL_INTERLACE	(1 << 20)
#define	 TCON1_CTL_START_DELAY	(0x1f << 4)
#define	 TCON1_CTL_START_DELAY_SHIFT	4
#define	 TCON1_CTL_SRC_SEL	(0x3 << 0)
#define	 TCON1_CTL_SRC_SEL_DE0	1
#define	 TCON1_CTL_SRC_SEL_BLUE	2
#define	TCON1_BASIC0		0x094
#define	TCON1_BASIC1		0x098
#define	TCON1_BASIC2		0x09c
#define	TCON1_BASIC3		0x0a0
#define	TCON1_BASIC4		0x0a4
#define	TCON1_BASIC5		0x0a8
#define	TCON1_PS_CTL		0x0b0
#define	TCON1_IO_POL		0x0f0
#define	 TCON1_IO_POL_IO2_INV	(1 << 26)
#define	 TCON1_IO_POL_IO1_INV	(1 << 25)
#define	 TCON1_IO_POL_IO0_INV	(1 << 24)
#define	TCON1_IO_TRI		0x0f4
#define	TCON_CEU_CTL		0x100
#define	 TCON_CEU_CTL_EN	(1 << 31)
#define	TCON_MUX_CTL		0x200
#define	 TCON_MUX_CTL_HDMI_SRC	(0x3 << 8)
#define	 TCON_MUX_CTL_HDMI_SRC_SHIFT	8
#define	TCON_FILL_CTL		0x300
#define	TCON_FILL_START0	0x304
#define	TCON_FILL_END0		0x308
#define	TCON_FILL_DATA0		0x30c

#define	TCON_XY(x, y)		(((x) << 16) | (y))

struct de2fb_softc {
	device_t		dev;
	device_t		fbdev;
	struct resource		*res[3];

	clk_t			gate_de, clock_de;
	clk_t			gate_tcon[2], clock_tcon[2];
	hwreset_t		rst_de;
	hwreset_t		rst_tcon[2];

	int			lcdno;
	int			mixerno;

	/* Framebuffer */
	struct fb_info		info;
	size_t			fbsize;
	bus_addr_t		paddr;
	vm_offset_t		vaddr;

	/* HDMI */
	eventhandler_tag	hdmi_evh;
};

static struct resource_spec de2fb_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },	/* DE */
	{ SYS_RES_MEMORY,	1,	RF_ACTIVE },	/* TCON0 */
	{ SYS_RES_MEMORY,	2,	RF_ACTIVE },	/* TCON1 */
	{ -1, 0 }
};

#define	DE_READ(sc, reg)		bus_read_4((sc)->res[0], (reg))
#define	DE_WRITE(sc, reg, val)		bus_write_4((sc)->res[0], (reg), (val))
#define	TCON_READ(sc, reg)		bus_read_4((sc)->res[1 + (sc)->lcdno], (reg))
#define	TCON_WRITE(sc, reg, val)	bus_write_4((sc)->res[1 + (sc)->lcdno], (reg), (val))
#define	TCON0_READ(sc, reg)		bus_read_4((sc)->res[1], (reg))
#define	TCON0_WRITE(sc, reg, val)	bus_write_4((sc)->res[1], (reg), (val))
#define	TCON1_READ(sc, reg)		bus_read_4((sc)->res[2], (reg))
#define	TCON1_WRITE(sc, reg, val)	bus_write_4((sc)->res[2], (reg), (val))

#define	GLB_READ(sc, reg)		DE_READ(sc, DE_GLB_BASE((sc)->mixerno) + (reg))
#define	GLB_WRITE(sc, reg, val)		DE_WRITE(sc, DE_GLB_BASE((sc)->mixerno) + (reg), val)
#define	BLD_READ(sc, reg)		DE_READ(sc, DE_BLD_BASE((sc)->mixerno) + (reg))
#define	BLD_WRITE(sc, reg, val)		DE_WRITE(sc, DE_BLD_BASE((sc)->mixerno) + (reg), val)
#define	VI_READ(sc, reg)		DE_READ(sc, DE_MIXER_BASE((sc)->mixerno, 0) + (reg))
#define	VI_WRITE(sc, reg, val)		DE_WRITE(sc, DE_MIXER_BASE((sc)->mixerno, 0) + (reg), val)
#define	UI_READ(sc, reg)		DE_READ(sc, DE_MIXER_BASE((sc)->mixerno, 1) + (reg))
#define	UI_WRITE(sc, reg, val)		DE_WRITE(sc, DE_MIXER_BASE((sc)->mixerno, 1) + (reg), val)

static int
de2fb_allocfb(struct de2fb_softc *sc)
{
	sc->vaddr = kmem_alloc_contig(kernel_arena, sc->fbsize,
	    M_NOWAIT | M_ZERO, 0, ~0, FB_ALIGN, 0, VM_MEMATTR_WRITE_COMBINING);
	if (sc->vaddr == 0) {
		device_printf(sc->dev, "failed to allocate FB memory\n");
		return (ENOMEM);
	}
	sc->paddr = pmap_kextract(sc->vaddr);

	return (0);
}

static void
de2fb_freefb(struct de2fb_softc *sc)
{
	kmem_free(kernel_arena, sc->vaddr, sc->fbsize);
}

static int
de2fb_enable_de_clocks(struct de2fb_softc *sc)
{
	int error;

	if (hwreset_get_by_ofw_name(sc->dev, 0, "de", &sc->rst_de) != 0) {
		device_printf(sc->dev, "cannot get hwreset resources\n");
		return (ENXIO);
	}

	if (clk_get_by_ofw_name(sc->dev, 0, "gate_de", &sc->gate_de) != 0 ||
	    clk_get_by_ofw_name(sc->dev, 0, "clock_de", &sc->clock_de) != 0) {
		device_printf(sc->dev, "cannot get clock resources\n");
		return (ENXIO);
	}

	/* Leave reset */
	error = hwreset_deassert(sc->rst_de);
	if (error != 0) {
		device_printf(sc->dev, "couldn't de-assert reset 'de'\n");
		return (error);
	}

	/* Gating clock */
	error = clk_enable(sc->gate_de);
	if (error != 0) {
		device_printf(sc->dev, "cannot enable clock 'gate_de'\n");
		return (error);
	}

	/* Core clock */
	error = clk_enable(sc->clock_de);
	if (error != 0) {
		device_printf(sc->dev, "cannot enable clock 'clock_de'\n");
		return (error);
	}

	return (0);
}

static int
de2fb_enable_tcon_clocks(struct de2fb_softc *sc)
{
	int error;

	if (hwreset_get_by_ofw_name(sc->dev, 0, "tcon0", &sc->rst_tcon[0]) != 0 ||
	    hwreset_get_by_ofw_name(sc->dev, 0, "tcon1", &sc->rst_tcon[1]) != 0) {
		device_printf(sc->dev, "cannot get hwreset resources\n");
		return (ENXIO);
	}

	if (clk_get_by_ofw_name(sc->dev, 0, "gate_tcon0", &sc->gate_tcon[0]) != 0 ||
	    clk_get_by_ofw_name(sc->dev, 0, "gate_tcon1", &sc->gate_tcon[1]) != 0) {
		device_printf(sc->dev, "cannot get gate clocks\n");
		return (ENXIO);
	}
	if (clk_get_by_ofw_name(sc->dev, 0, "clock_tcon0", &sc->clock_tcon[0]) != 0 ||
	    clk_get_by_ofw_name(sc->dev, 0, "clock_tcon1", &sc->clock_tcon[1]) != 0) {
		device_printf(sc->dev, "cannot get pixel clocks\n");
		return (ENXIO);
	}

	/* Leave reset */
	error = hwreset_deassert(sc->rst_tcon[0]);
	if (error != 0) {
		device_printf(sc->dev, "couldn't de-assert reset 0\n");
		return (error);
	}
	error = hwreset_deassert(sc->rst_tcon[1]);
	if (error != 0) {
		device_printf(sc->dev, "couldn't de-assert reset 1\n");
		return (error);
	}

	/* Gating clocks */
	error = clk_enable(sc->gate_tcon[0]);
	if (error != 0) {
		device_printf(sc->dev, "cannot enable gate clock 0\n");
		return (error);
	}
	error = clk_enable(sc->gate_tcon[1]);
	if (error != 0) {
		device_printf(sc->dev, "cannot enable gate clock 1\n");
		return (error);
	}

	/* Pixel clocks */
	error = clk_enable(sc->clock_tcon[0]);
	if (error != 0) {
		device_printf(sc->dev, "cannot enable pixel clock 0\n");
		return (error);
	}
	error = clk_enable(sc->clock_tcon[1]);
	if (error != 0) {
		device_printf(sc->dev, "cannot enable pixel clock 1\n");
		return (error);
	}

	return (0);
}

static void
de2fb_reset_de(struct de2fb_softc *sc)
{
	u_int off;

	/* Clear the VI/UI channels */
	for (off = 0x00; off < VI_SIZE; off += 4)
		VI_WRITE(sc, off, 0);
	for (off = 0x00; off < UI_SIZE; off += 4) {
		DE_WRITE(sc, DE_MIXER_BASE(sc->mixerno, 1) + off, 0);
		if (sc->mixerno == 0) {
			DE_WRITE(sc, DE_MIXER_BASE(sc->mixerno, 2) + off, 0);
			DE_WRITE(sc, DE_MIXER_BASE(sc->mixerno, 3) + off, 0);
		}
	}
		
	/* Setup alpha blending */
	BLD_WRITE(sc, BLD_FCOLOR_CTL, 0x00000101);
	BLD_WRITE(sc, BLD_ROUTE, 0x0021);
	BLD_WRITE(sc, BLD_PREMULT, 0);
	BLD_WRITE(sc, BLD_BKCOLOR, 0xff000000);
	BLD_WRITE(sc, BLD_MODE(0), 0x03010301);
	BLD_WRITE(sc, BLD_MODE(1), 0x03010301);
	BLD_WRITE(sc, BLD_MODE(2), 0x03010301);
}

static int
de2fb_setup_de(struct de2fb_softc *sc, const struct videomode *mode)
{
	uint32_t val, size;
	u_int enable;
	int interlace;

	size = DE_WH(mode->hdisplay, mode->vdisplay);
	interlace = !!(mode->flags & VID_INTERLACE);

/* XXX A83T */
	DE_WRITE(sc, DE_DIV_REG, 0x11);

	enable = sc->mixerno == 0 ? 1 : 4;
	DE_WRITE(sc, DE_RESET_REG, DE_READ(sc, DE_RESET_REG) | enable);
	enable = 1 << sc->mixerno;
	DE_WRITE(sc, DE_GATE_REG, DE_READ(sc, DE_GATE_REG) | enable);
	DE_WRITE(sc, DE_MOD_REG, DE_READ(sc, DE_MOD_REG) | enable);

	/* Select LCD output */
	val = DE_READ(sc, DE_SEL_REG);
	val &= ~DE_SEL_LCD_MASK;
	switch (sc->mixerno) {
	case 0:
		val |= DE_SEL_LCD_0;
		break;
	case 1:
		val |= DE_SEL_LCD_1;
		break;
	default:
		return (EINVAL);
	}
	DE_WRITE(sc, DE_SEL_REG, val);
	GLB_WRITE(sc, GLB_DBUFF, 1);

	/* Global init */
	GLB_WRITE(sc, GLB_CTL, GLB_CTL_RT_EN);
	GLB_WRITE(sc, GLB_STATUS, 0);
	GLB_WRITE(sc, GLB_SIZE, size);

	/* Initialize registers */
	de2fb_reset_de(sc);

	BLD_WRITE(sc, BLD_INSIZE_ATTR(0), size);
	BLD_WRITE(sc, BLD_INSIZE_ATTR(1), size);
	BLD_WRITE(sc, BLD_INSIZE_ATTR(2), size);
	BLD_WRITE(sc, BLD_INSIZE_ATTR(3), size);
	BLD_WRITE(sc, BLD_OUTPUT_SIZE, size);
	BLD_WRITE(sc, BLD_OUT_CTL, interlace ? 2 : 0);

	/* UI plane */
	UI_WRITE(sc, UI_ATTR_CFG(0), UI_ATTR_EN | UI_ATTR_FMT_XRGB8888);
	UI_WRITE(sc, UI_SIZE_CFG(0), size);
	UI_WRITE(sc, UI_COORD_CFG(0), DE_XY(0, 0));
	UI_WRITE(sc, UI_PITCH_CFG(0), mode->hdisplay * (FB_BPP / NBBY));
	UI_WRITE(sc, UI_TOP_LADDR_CFG(0), sc->paddr);
	UI_WRITE(sc, UI_OVL_SIZE, size);

	return (0);
}

static int
de2fb_setup_pll(struct de2fb_softc *sc, uint64_t freq)
{
	int error;

	error = clk_set_freq(sc->clock_tcon[sc->lcdno], freq, 0);
	if (error != 0) {
		device_printf(sc->dev, "cannot set %s frequency\n", clk_get_name(sc->clock_tcon[sc->lcdno]));
		return (error);
	}

	return (0);
}

static int
de2fb_setup_tcon(struct de2fb_softc *sc, const struct videomode *mode)
{
	int interlace, start_delay;
	uint32_t val;

	interlace = (mode->flags & VID_INTERLACE) ? 2 : 1;
	start_delay = MIN(31, (mode->vtotal - mode->vdisplay) / interlace - 5);

	val = TCON_XY(mode->hdisplay - 1, mode->vdisplay / interlace - 1);
	TCON_WRITE(sc, TCON1_BASIC0, val);
	TCON_WRITE(sc, TCON1_BASIC1, val);
	TCON_WRITE(sc, TCON1_BASIC2, val);
	val = TCON_XY(mode->htotal - 1, mode->htotal - mode->hsync_start - 1);
	TCON_WRITE(sc, TCON1_BASIC3, val);
	val = TCON_XY(mode->vtotal * (3 - interlace), mode->vtotal - mode->vsync_start - 1);
	TCON_WRITE(sc, TCON1_BASIC4, val);
	val = TCON_XY(mode->hsync_end - mode->hsync_start - 1,
	    mode->vsync_end - mode->vsync_start - 1);
	TCON_WRITE(sc, TCON1_BASIC5, val);

	TCON_WRITE(sc, TCON1_PS_CTL, TCON_XY(1, 1));

	val = TCON1_IO_POL_IO2_INV;
	if (mode->flags & VID_PVSYNC)
		val |= TCON1_IO_POL_IO0_INV;
	if (mode->flags & VID_PHSYNC)
		val |= TCON1_IO_POL_IO1_INV;
	TCON_WRITE(sc, TCON1_IO_POL, val);

	val = TCON_READ(sc, TCON_CEU_CTL);
	val &= ~TCON_CEU_CTL_EN;
	TCON_WRITE(sc, TCON_CEU_CTL, val);

	val = TCON_READ(sc, TCON1_CTL);
	if (interlace == 2)
		val |= TCON1_CTL_INTERLACE;
	else
		val &= ~TCON1_CTL_INTERLACE;
	TCON_WRITE(sc, TCON1_CTL, val);

	TCON_WRITE(sc, TCON_FILL_CTL, 0);
	TCON_WRITE(sc, TCON_FILL_START0, mode->vtotal + 1);
	TCON_WRITE(sc, TCON_FILL_END0, mode->vtotal);
	TCON_WRITE(sc, TCON_FILL_DATA0, 0);

	val = TCON_READ(sc, TCON1_CTL);
	val &= ~TCON1_CTL_START_DELAY;
	val |= (start_delay << TCON1_CTL_START_DELAY_SHIFT);
	val &= ~TCON1_CTL_SRC_SEL;
	val |= TCON1_CTL_SRC_SEL_DE0;
	val |= TCON1_CTL_EN;
	TCON_WRITE(sc, TCON1_CTL, val);

#if 0
	val = TCON_READ(sc, TCON1_CTL);
	val &= ~TCON1_CTL_SRC_SEL;
	val |= TCON1_CTL_SRC_SEL_BLUE;
	TCON_WRITE(sc, TCON1_CTL, val);
#endif

	return (0);
}

static void
de2fb_enable_tcon(struct de2fb_softc *sc, int onoff)
{
	uint32_t val;

	/* Enable TCON */
	val = TCON_READ(sc, TCON_GCTL);
	if (onoff)
		val |= TCON_GCTL_EN;
	else
		val &= ~TCON_GCTL_EN;
	TCON_WRITE(sc, TCON_GCTL, val);

	/* Enable TCON1 IO outputs */
	TCON_WRITE(sc, TCON1_IO_TRI, 0x0fffffff);
}

static int
de2fb_configure(struct de2fb_softc *sc, const struct videomode *mode)
{
	size_t fbsize;
	int error;

	fbsize = round_page(mode->hdisplay * mode->vdisplay * (FB_BPP / NBBY));

	/* Detach the old FB device */
	if (sc->fbdev != NULL) {
		device_delete_child(sc->dev, sc->fbdev);
		sc->fbdev = NULL;
	}

	/* If the FB size has changed, free the old FB memory */
	if (sc->fbsize > 0 && sc->fbsize != fbsize) {
		de2fb_freefb(sc);
		sc->vaddr = 0;
	}

	/* Allocate the FB if necessary */
	sc->fbsize = fbsize;
	if (sc->vaddr == 0) {
		error = de2fb_allocfb(sc);
		if (error != 0) {
			device_printf(sc->dev, "failed to allocate FB memory\n");
			return (ENXIO);
		}
	}

	/* Disable timing controller */
	de2fb_enable_tcon(sc, 0);
	TCON_WRITE(sc, TCON0_DCLK, DCLK_EN);

	/* Set pixel clock rate */
	error = de2fb_setup_pll(sc, DOT_CLOCK_TO_HZ(mode->dot_clock));
	if (error != 0)
		return (error);

	/* Setup display timing controller */
	error = de2fb_setup_tcon(sc, mode);
	if (error != 0)
		return (error);

	/* Enable timing controller */
	de2fb_enable_tcon(sc, 1);

	/* Setup display engine */
	error = de2fb_setup_de(sc, mode);
	if (error != 0)
		return (error);

	/* Attach framebuffer device */
	sc->info.fb_name = device_get_nameunit(sc->dev);
	sc->info.fb_vbase = (intptr_t)sc->vaddr;
	sc->info.fb_pbase = sc->paddr;
	sc->info.fb_size = sc->fbsize;
	sc->info.fb_bpp = sc->info.fb_depth = FB_BPP;
	sc->info.fb_stride = mode->hdisplay * (FB_BPP / NBBY);
	sc->info.fb_width = mode->hdisplay;
	sc->info.fb_height = mode->vdisplay;

	sc->fbdev = device_add_child(sc->dev, "fbd", device_get_unit(sc->dev));
	if (sc->fbdev == NULL) {
		device_printf(sc->dev, "failed to add fbd child\n");
		return (ENOENT);
	}

	error = device_probe_and_attach(sc->fbdev);
	if (error != 0) {
		device_printf(sc->dev, "failed to attach fbd device\n");
		return (error);
	}

	return (0);
}

static int
de2fb_get_bandwidth(const struct videomode *mode)
{
	int refresh;

	refresh = FB_DIVIDE(FB_DIVIDE(DOT_CLOCK_TO_HZ(mode->dot_clock),
	    mode->htotal), mode->vtotal);

	return mode->hdisplay * mode->vdisplay * refresh;
}

static int
de2fb_mode_supported(const struct videomode *mode)
{
	uint64_t freq;

	/* Check height and width restrictions */
	if (mode->hdisplay > FB_MAX_W || mode->vdisplay > FB_MAX_H)
		return (0);

	/* Bandwidth check */
	if (de2fb_get_bandwidth(mode) > FB_MAX_BW)
		return (0);

	/* Skip interlace modes */
	if ((mode->flags & VID_INTERLACE) != 0)
		return (0);

	/* XXX
	 * Driver only supports modes that can be derived from
	 * 297MHz or 270MHz reference clocks
	 */
	freq = DOT_CLOCK_TO_HZ(mode->dot_clock);
	if ((270000000 * 2) % freq != 0 &&
	    297000000 % freq != 0)
		return (0);

	return (1);
}

static const struct videomode *
de2fb_find_mode(struct edid_info *ei)
{
	const struct videomode *best;
	int n, bw, best_bw;

	/* If the preferred mode is OK, just use it */
	if (de2fb_mode_supported(ei->edid_preferred_mode) != 0)
		return ei->edid_preferred_mode;

	/* Pick the mode with the highest bandwidth requirements */
	best = NULL;
	best_bw = 0;
	for (n = 0; n < ei->edid_nmodes; n++) {
		if (de2fb_mode_supported(&ei->edid_modes[n]) == 0)
			continue;
		bw = de2fb_get_bandwidth(&ei->edid_modes[n]);
		if (best == NULL || bw > best_bw) {
			best = &ei->edid_modes[n];
			best_bw = bw;
		}
	}

	return best;
}

static void
de2fb_hdmi_event(void *arg, device_t hdmi_dev)
{
	const struct videomode *mode;
	struct videomode hdmi_mode;
	struct de2fb_softc *sc;
	struct edid_info ei;
	uint8_t *edid;
	uint32_t edid_len;
	int error;

	sc = arg;
	edid = NULL;
	edid_len = 0;
	mode = NULL;

	error = HDMI_GET_EDID(hdmi_dev, &edid, &edid_len);
	if (error != 0) {
		device_printf(sc->dev, "failed to get EDID: %d\n", error);
	} else {
		error = edid_parse(edid, &ei);
		if (error != 0) {
			device_printf(sc->dev, "failed to parse EDID: %d\n",
			    error);
		} else {
			if (bootverbose)
				edid_print(&ei);
			mode = de2fb_find_mode(&ei);
		}
	}

	/* If the preferred mode could not be determined, use the default */
	if (mode == NULL)
		mode = pick_mode_by_ref(FB_DEFAULT_W, FB_DEFAULT_H,
		    FB_DEFAULT_REF);

	if (mode == NULL) {
		device_printf(sc->dev, "failed to find usable video mode\n");
		return;
	}

	if (bootverbose)
		device_printf(sc->dev, "using %dx%d\n",
		    mode->hdisplay, mode->vdisplay);

	/* Configure DEBE and TCON */
	error = de2fb_configure(sc, mode);
	if (error != 0) {
		device_printf(sc->dev, "failed to configure FB: %d\n", error);
		return;
	}

	hdmi_mode = *mode;
	hdmi_mode.hskew = mode->hsync_end - mode->hsync_start;
	hdmi_mode.flags |= VID_HSKEW;
	HDMI_SET_VIDEOMODE(hdmi_dev, &hdmi_mode);
	
	/* XXX: ???? */
	DELAY(HDMI_ENABLE_DELAY);
	HDMI_ENABLE(hdmi_dev, 1);
}

static int
de2fb_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "allwinner,sun8i-a83t-fb"))
		return (ENXIO);

	device_set_desc(dev, "Allwinner DE2.0 Framebuffer");
	return (BUS_PROBE_DEFAULT);
}

static int
de2fb_attach(device_t dev)
{
	struct de2fb_softc *sc;

	sc = device_get_softc(dev);

	sc->dev = dev;
	sc->lcdno = 1;
	sc->mixerno = 0;

	if (bus_alloc_resources(dev, de2fb_spec, sc->res)) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	if (de2fb_enable_de_clocks(sc) != 0) {
		device_printf(dev, "cannot enable DE clocks\n");
		return (ENXIO);
	}

	if (de2fb_enable_tcon_clocks(sc) != 0) {
		device_printf(dev, "cannot enable TCON clocks\n");
		return (ENXIO);
	}

	/* Disable TCON */
	TCON_WRITE(sc, TCON0_CTL, TCON_READ(sc, TCON0_CTL) & ~TCON0_CTL_EN);
	TCON_WRITE(sc, TCON1_CTL, TCON_READ(sc, TCON1_CTL) & ~TCON1_CTL_EN);
	TCON_WRITE(sc, TCON_GCTL, TCON_READ(sc, TCON_GCTL) & ~TCON_GCTL_EN);
	TCON_WRITE(sc, TCON_GINT0, 0);

	sc->hdmi_evh = EVENTHANDLER_REGISTER(hdmi_event,
	    de2fb_hdmi_event, sc, 0);

	return (0);
}

static struct fb_info *
de2fb_fb_getinfo(device_t dev)
{
	struct de2fb_softc *sc;

	sc = device_get_softc(dev);

	return (&sc->info);
}

static device_method_t de2fb_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		de2fb_probe),
	DEVMETHOD(device_attach,	de2fb_attach),

	/* FB interface */
	DEVMETHOD(fb_getinfo,		de2fb_fb_getinfo),

	DEVMETHOD_END
};

static driver_t de2fb_driver = {
	"fb",
	de2fb_methods,
	sizeof(struct de2fb_softc),
};

static devclass_t de2fb_devclass;

DRIVER_MODULE(de2fb, simplebus, de2fb_driver, de2fb_devclass, 0, 0);
