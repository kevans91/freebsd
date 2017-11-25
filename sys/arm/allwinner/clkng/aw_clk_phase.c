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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>

#include <dev/extres/clk/clk.h>

#include <arm/allwinner/clkng/aw_clk.h>
#include <arm/allwinner/clkng/aw_clk_phase.h>

#include "clkdev_if.h"

struct aw_clk_phase_sc {
	uint32_t	offset;

	uint32_t		phase_shift;
	uint32_t		phase_mask;
};

#define	WRITE4(_clk, off, val)						\
	CLKDEV_WRITE_4(clknode_get_device(_clk), off, val)
#define	READ4(_clk, off, val)						\
	CLKDEV_READ_4(clknode_get_device(_clk), off, val)
#define	MODIFY4(_clk, off, clr, set )					\
	CLKDEV_MODIFY_4(clknode_get_device(_clk), off, clr, set)
#define	DEVICE_LOCK(_clk)							\
	CLKDEV_DEVICE_LOCK(clknode_get_device(_clk))
#define	DEVICE_UNLOCK(_clk)						\
	CLKDEV_DEVICE_UNLOCK(clknode_get_device(_clk))

static uint64_t aw_clk_phase_get_parent_rate(struct clknode *c_clk);
static uint64_t aw_clk_phase_div(uint64_t n, uint64_t d);

static uint64_t
aw_clk_phase_get_parent_rate(struct clknode *c_clk)
{
	struct clknode *p_clk;
	uint64_t p_rate;

	p_clk = clknode_get_parent(c_clk);
	if (p_clk == NULL)
		return (0);

	clknode_get_freq(p_clk, &p_rate);
	return (p_rate);
}

static uint64_t
aw_clk_phase_div(uint64_t n, uint64_t d)
{

	return ((n + (d / 2)) / d);
}

static int
aw_clk_phase_init(struct clknode *clk, device_t dev)
{
	clknode_init_parent_idx(clk, 0);
	return (0);
}

static int
aw_clk_phase_recalc(struct clknode *clk, uint64_t *freq)
{

	struct aw_clk_phase_sc *sc;
	uint64_t p_rate, gp_rate, p_div;
	uint32_t val;

	sc = clknode_get_softc(clk);

	p_rate = aw_clk_phase_get_parent_rate(clk);
	if (p_rate == 0)
		return (1);

	gp_rate = aw_clk_phase_get_parent_rate(clknode_get_parent(clk));
	if (gp_rate == 0)
		return (1);

	p_div = gp_rate / p_rate;
	DEVICE_LOCK(clk);
	READ4(clk, sc->offset, &val);
	DEVICE_UNLOCK(clk);

	val = (val & sc->phase_mask) >> sc->phase_shift;
	*freq = val * aw_clk_phase_div(360, p_div);
	return (0);
}

static int
aw_clk_phase_set_freq(struct clknode *clk, uint64_t fparent, uint64_t *fout,
    int flags, int *stop)
{
	struct aw_clk_phase_sc *sc;
	uint64_t p_rate, gp_rate, p_div, delay;
	uint32_t val;

	sc = clknode_get_softc(clk);

	p_rate = aw_clk_phase_get_parent_rate(clk);
	if (p_rate == 0)
		return (1);

	gp_rate = aw_clk_phase_get_parent_rate(clknode_get_parent(clk));
	if (gp_rate == 0)
		return (1);

	p_div = gp_rate / p_rate;
	delay = *fout == 180 ? 0 :
	    aw_clk_phase_div(*fout, aw_clk_phase_div(360, p_div));

	DEVICE_LOCK(clk);
	READ4(clk, sc->offset, &val);
	val &= ~sc->phase_mask;
	val |= (delay << sc->phase_shift);
	WRITE4(clk, sc->offset, val);
	DEVICE_UNLOCK(clk);

	return (0);
}

static clknode_method_t aw_phase_clknode_methods[] = {
	/* Device interface */
	CLKNODEMETHOD(clknode_init,		aw_clk_phase_init),
	CLKNODEMETHOD(clknode_recalc_freq,	aw_clk_phase_recalc),
	CLKNODEMETHOD(clknode_set_freq,		aw_clk_phase_set_freq),
	CLKNODEMETHOD_END
};

DEFINE_CLASS_1(aw_phase_clknode, aw_phase_clknode_class,
    aw_phase_clknode_methods, sizeof(struct aw_clk_phase_sc),
    clknode_class);

int
aw_clk_phase_register(struct clkdom *clkdom, struct aw_clk_phase_def *clkdef)
{
	struct clknode *clk;
	struct aw_clk_phase_sc *sc;

	clk = clknode_create(clkdom, &aw_phase_clknode_class, &clkdef->clkdef);
	if (clk == NULL)
		return (1);

	sc = clknode_get_softc(clk);

	sc->offset = clkdef->offset;

	sc->phase_shift = clkdef->phase_shift;
	sc->phase_mask = ((1 << clkdef->phase_width) - 1) << sc->phase_shift;

	clknode_register(clkdom, clk);

	return (0);
}
