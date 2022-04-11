/*-
 * Framework derived from sys/arm/broadcom/bcm2835//bcm2838_pci.c,
 * which bears the following copyright:
 *
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Dr Robert Harvey Crowston <crowston@protonmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * $FreeBSD$
 *
 */

/* Portions from the NetBSD driver: */
/* $NetBSD: apple_pcie.c,v 1.5 2021/09/14 01:33:19 jmcneill Exp $ */

/*-
 * Copyright (c) 2021 Jared McNeill <jmcneill@invisible.ca>
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
 */

#if 0
/*
 * BCM2838-compatible PCI-express controller.
 *
 * Broadcom likes to give the same chip lots of different names. The name of
 * this driver is taken from the Raspberry Pi 4 Broadcom 2838 chip.
 */
#endif

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/proc.h>
#include <sys/rman.h>
#include <sys/intr.h>
#include <sys/mutex.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/pci/pci_host_generic.h>
#include <dev/pci/pci_host_generic_fdt.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcib_private.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include "pcib_if.h"
#include "msi_if.h"
#include "pic_if.h"

#if 0
#define PCI_ID_VAL3		0x43c
#define CLASS_SHIFT		0x10
#define SUBCLASS_SHIFT		0x8

#define REG_CONTROLLER_HW_REV			0x406c
#define REG_BRIDGE_CTRL				0x9210
#define BRIDGE_DISABLE_FLAG	0x1
#define BRIDGE_RESET_FLAG	0x2
#define REG_BRIDGE_SERDES_MODE			0x4204
#define REG_DMA_CONFIG				0x4008
#define REG_DMA_WINDOW_LOW			0x4034
#define REG_DMA_WINDOW_HIGH			0x4038
#define REG_DMA_WINDOW_1			0x403c
#define REG_BRIDGE_GISB_WINDOW			0x402c
#define REG_BRIDGE_STATE			0x4068
#define REG_BRIDGE_LINK_STATE			0x00bc
#define REG_BUS_WINDOW_LOW			0x400c
#define REG_BUS_WINDOW_HIGH			0x4010
#define REG_CPU_WINDOW_LOW			0x4070
#define REG_CPU_WINDOW_START_HIGH		0x4080
#define REG_CPU_WINDOW_END_HIGH			0x4084

#define REG_MSI_ADDR_LOW			0x4044
#define REG_MSI_ADDR_HIGH			0x4048
#define REG_MSI_CONFIG				0x404c
#define REG_MSI_CLR				0x4508
#define REG_MSI_MASK_CLR			0x4514
#define REG_MSI_RAISED				0x4500
#define REG_MSI_EOI				0x4060
#define NUM_MSI			32

#define REG_EP_CONFIG_CHOICE			0x9000
#define REG_EP_CONFIG_DATA			0x8000
#endif

/* XXXTODO: find correct values for the below constants, which are from RPi4. */
/*
 * The system memory controller can address up to 16 GiB of physical memory
 * (although at time of writing the largest memory size available for purchase
 * is 8 GiB). However, the system DMA controller is capable of accessing only a
 * limited portion of the address space. Worse, the PCI-e controller has further
 * constraints for DMA, and those limitations are not wholly clear to the
 * author. NetBSD and Linux allow DMA on the lower 3 GiB of the physical memory,
 * but experimentation shows DMA performed above 960 MiB results in data
 * corruption with this driver. The limit of 960 MiB is taken from OpenBSD, but
 * apparently that value was chosen for satisfying a constraint of an unrelated
 * peripheral.
 *
 * Whatever the true maximum address, 960 MiB works.
 */
#define DMA_HIGH_LIMIT			0x3c000000
#if 0
#define MAX_MEMORY_LOG2			0x21
#define REG_VALUE_DMA_WINDOW_LOW	(MAX_MEMORY_LOG2 - 0xf)
#define REG_VALUE_DMA_WINDOW_HIGH	0x0
#define DMA_WINDOW_ENABLE		0x3000
#define REG_VALUE_DMA_WINDOW_CONFIG	\
    (((MAX_MEMORY_LOG2 - 0xf) << 0x1b) | DMA_WINDOW_ENABLE)

//#define REG_VALUE_MSI_CONFIG	0xffe06540
#endif

#define	PCIE_MSI_CTRL		0x0124
#define	 PCIE_MSI_CTRL_EN	(1U << 0)
#define	 PCIE_MSI_CTRL_32	(5U << 4)
#define	PCIE_MSI_REMAP		0x0128
#define	PCIE_MSI_DOORBELL	0x0168

#define PCIE_NPORTS		3

struct apple_pcie_irqsrc {
	struct intr_irqsrc	*isrc;
	u_int			irq;		/* XXX needed? */
	bool			allocated;
};

enum {
#if 0
	_RES_MEM,
#endif
	_RES_IRQ0,
	_RES_IRQ1,
	_RES_IRQ2,
	_RES_NITEMS
};
#define	PCIE_NIRQ	3
#define	FDT_INTR_NCELLS		3

struct apple_pcie_softc {
	struct generic_pcie_fdt_softc	base;
	device_t			dev;
	struct mtx			config_mtx;	/* XXX needed? */
	struct mtx			msi_mtx;
	struct resource 		*res[_RES_NITEMS];
	void				*ih[PCIE_NIRQ];
	device_t			aic_dev;
	struct intr_map_data_fdt	*msi_fdt_data;
	struct apple_pcie_irqsrc	*msi_isrcs;
	pci_addr_t			msi_addr;
	int				msi_start;
	int				nmsi;
};

static struct ofw_compat_data compat_data[] = {
	{"apple,t8103-pcie",		1},
	{"apple,pcie",			1},
	{NULL,				0}
};

static struct resource_spec pcie_spec[] = {
#if 0
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
#endif
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		1,	RF_ACTIVE },
	{ SYS_RES_IRQ,		2,	RF_ACTIVE },
	{ -1, 0 }
};

static int
apple_pcie_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_search_compatible(dev, compat_data)->ocd_data)
		return (ENXIO);

	device_set_desc(dev, "Apple PCIe controller");
	return (BUS_PROBE_DEFAULT);
}

#if 0
static void
apple_pcie_set_reg(struct apple_pcie_softc *sc, uint32_t reg, uint32_t val)
{

	bus_space_write_4(sc->base.base.bst, sc->base.base.bsh, reg,
	    htole32(val));
}

static uint32_t
apple_pcie_read_reg(struct bcm_pcib_softc *sc, uint32_t reg)
{

	return (le32toh(bus_space_read_4(sc->base.base.bst, sc->base.base.bsh,
	    reg)));
}
#endif

#if 0
static void
bcm_pcib_reset_controller(struct bcm_pcib_softc *sc)
{
	uint32_t val;

	val = bcm_pcib_read_reg(sc, REG_BRIDGE_CTRL);
	val = val | BRIDGE_RESET_FLAG | BRIDGE_DISABLE_FLAG;
	bcm_pcib_set_reg(sc, REG_BRIDGE_CTRL, val);

	DELAY(100);

	val = bcm_pcib_read_reg(sc, REG_BRIDGE_CTRL);
	val = val & ~BRIDGE_RESET_FLAG;
	bcm_pcib_set_reg(sc, REG_BRIDGE_CTRL, val);

	DELAY(100);

	bcm_pcib_set_reg(sc, REG_BRIDGE_SERDES_MODE, 0);

	DELAY(100);
}

static void
bcm_pcib_enable_controller(struct bcm_pcib_softc *sc)
{
	uint32_t val;

	val = bcm_pcib_read_reg(sc, REG_BRIDGE_CTRL);
	val = val & ~BRIDGE_DISABLE_FLAG;
	bcm_pcib_set_reg(sc, REG_BRIDGE_CTRL, val);

	DELAY(100);
}
#endif

static int
apple_pcie_check_ranges(device_t dev)
{
	struct apple_pcie_softc *sc;
	struct pcie_range *ranges;
	int error = 0, i;

	sc = device_get_softc(dev);
	ranges = &sc->base.base.ranges[0];

	/* XXX ??? keep for now... */
	/* The first range needs to be non-zero. */
	if (ranges[0].size == 0) {
		device_printf(dev, "error: first outbound memory range "
		    "(pci addr: 0x%jx, cpu addr: 0x%jx) has zero size.\n",
		    ranges[0].pci_base, ranges[0].phys_base);
		error = ENXIO;
	}
else
device_printf(dev, "first outbound memory range "
    "pci addr: 0x%jx, cpu addr: 0x%jx flags %lx\n",
    ranges[0].pci_base, ranges[0].phys_base, ranges[0].flags);
error = 1;

#if 0
	/*
	 * The controller can actually handle three distinct ranges, but we
	 * only implement support for one.
	 */
#endif
	for (i = 0; (bootverbose || error) && i < sc->base.base.nranges; ++i) {
		if (ranges[i].size > 0)
			device_printf(dev,
			    "note: outbound memory range %d (pci addr: 0x%jx, "
			    "cpu addr: 0x%jx, size: 0x%jx flags %lx).\n",
			    i, ranges[i].pci_base, ranges[i].phys_base,
			    ranges[i].size, ranges[i].flags);
	}

#if 0
	return (error);
#else
	return (0);
#endif
}

#if 0
static const char *
bcm_pcib_link_state_string(uint32_t mode)
{

	switch(mode & PCIEM_LINK_STA_SPEED) {
	case 0:
		return ("not up");
	case 1:
		return ("2.5 GT/s");
	case 2:
		return ("5.0 GT/s");
	case 4:
		return ("8.0 GT/s");
	default:
		return ("unknown");
	}
}

static bus_addr_t
bcm_get_offset_and_prepare_config(struct bcm_pcib_softc *sc, u_int bus,
    u_int slot, u_int func, u_int reg)
{
	/*
	 * Config for an end point is only available through a narrow window for
	 * one end point at a time. We first tell the controller which end point
	 * we want, then access it through the window.
	 */
	uint32_t func_index;

	if (bus == 0 && slot == 0 && func == 0)
		/*
		 * Special case for root device; its config is always available
		 * through the zero-offset.
		 */
		return (reg);

	/* Tell the controller to show us the config in question. */
	func_index = PCIE_ADDR_OFFSET(bus, slot, func, 0);
	bcm_pcib_set_reg(sc, REG_EP_CONFIG_CHOICE, func_index);

	return (REG_EP_CONFIG_DATA + reg);
}
#endif

#define	PCI_BAD_ADDR	((bus_addr_t)-1)

static bus_addr_t
apple_pcie_compose_quad(struct apple_pcie_softc *sc, u_int bus, u_int slot,
    u_int func, u_int reg)
{

	if ((bus < sc->base.base.bus_start) || (bus > sc->base.base.bus_end))
		return (PCI_BAD_ADDR);
	if ((slot > PCI_SLOTMAX) || (func > PCI_FUNCMAX) || (reg > PCIE_REGMAX))
		return (PCI_BAD_ADDR);

	/* shifts for ECAM */
	return ((bus << 20) | (slot << 15) | (func << 12) | reg);
}

static uint32_t
apple_pcie_read_config(device_t dev, u_int bus, u_int slot, u_int func,
    u_int reg, int bytes)
{
	struct apple_pcie_softc *sc;
	bus_space_handle_t h;
	bus_space_tag_t	t;
	bus_addr_t offset;
	uint32_t data;

	sc = device_get_softc(dev);
	offset = apple_pcie_compose_quad(sc, bus, slot, func, reg);
	if (offset == PCI_BAD_ADDR)
		return (~0U);

	t = sc->base.base.bst;
	h = sc->base.base.bsh;

	switch (bytes) {
	case 1:
		data = bus_space_read_1(t, h, offset);
		break;
	case 2:
		data = le16toh(bus_space_read_2(t, h, offset));
		break;
	case 4:
		data = le32toh(bus_space_read_4(t, h, offset));
		break;
	default:
		data = ~0U;
		break;
	}
	return (data);
}

static void
apple_pcie_write_config(device_t dev, u_int bus, u_int slot,
    u_int func, u_int reg, uint32_t val, int bytes)
{
	struct apple_pcie_softc *sc;
	bus_space_handle_t h;
	bus_space_tag_t	t;
	bus_addr_t offset;

	sc = device_get_softc(dev);
	offset = apple_pcie_compose_quad(sc, bus, slot, func, reg);
	if (offset == PCI_BAD_ADDR)
		return;

	t = sc->base.base.bst;
	h = sc->base.base.bsh;

	switch (bytes) {
	case 1:
		bus_space_write_1(t, h, offset, val);
		break;
	case 2:
		bus_space_write_2(t, h, offset, htole16(val));
		break;
	case 4:
		bus_space_write_4(t, h, offset, htole32(val));
		break;
	default:
		break;
	}
}

#if 0
static void
bcm_pcib_msi_intr_process(struct bcm_pcib_softc *sc, uint32_t interrupt_bitmap,
    struct trapframe *tf)
{
	struct bcm_pcib_irqsrc *irqsrc;
	uint32_t bit, irq;

	while ((bit = ffs(interrupt_bitmap))) {
		irq = bit - 1;

		/* Acknowledge interrupt. */
		bcm_pcib_set_reg(sc, REG_MSI_CLR, 1 << irq);

		/* Send EOI. */
		bcm_pcib_set_reg(sc, REG_MSI_EOI, 1);

		/* Despatch to handler. */
		irqsrc = &sc->msi_isrcs[irq];
		if (intr_isrc_dispatch(&irqsrc->isrc, tf))
			device_printf(sc->dev,
			    "note: unexpected interrupt (%d) triggered.\n",
			    irq);

		/* Done with this interrupt. */
		interrupt_bitmap = interrupt_bitmap & ~(1 << irq);
	}
}
#endif

#ifdef PCIE_INTR	/* probably unneeded */
static int
apple_pcie_msi_intr(void *arg)
{
	struct apple_pcie_softc *sc;
	struct trapframe *tf;
	//uint32_t interrupt_bitmap;

	sc = (struct apple_pcie_softc *) arg;
	tf = curthread->td_intr_frame;

#if 0
	while ((interrupt_bitmap = bcm_pcib_read_reg(sc, REG_MSI_RAISED)))
		bcm_pcib_msi_intr_process(sc, interrupt_bitmap, tf);

	return (FILTER_HANDLED);
#else
	device_printf(sc->dev, "%s %p\n", __func__, tf);
	return (FILTER_STRAY);
#endif
}
#endif

/* shared allocation code for MSI and MSIX */
static int
apple_pcie_alloc_intr(struct apple_pcie_softc *sc, int count,
    struct intr_irqsrc **srcs)
{
	int first_int, i, error;

	/* Find a contiguous region of free message-signalled interrupts. */
	for (first_int = 0; first_int + count < sc->nmsi; ) {
		for (i = first_int; i < first_int + count; ++i) {
			if (sc->msi_isrcs[i].allocated)
				goto next;
		}
		goto found;
next:
		first_int = i + 1;
	}

	/* No appropriate region available. */
	device_printf(sc->dev, "warning: failed to allocate %d MSI messages.\n",
	    count);
	return (-1);

found:
	/* Mark the messages as in use; map the interrupts. */
	for (i = first_int; i < first_int + count; ++i) {
		sc->msi_isrcs[i].allocated = true;
		sc->msi_isrcs[i].isrc = *srcs;
		sc->msi_fdt_data->cells[1] = sc->msi_start + i;
		error = PIC_MAP_INTR(sc->aic_dev,
		    (struct intr_map_data *)sc->msi_fdt_data, srcs);
		if (error) {
			device_printf(sc->dev, "PIC_MAP_INTR failed %d\n",
			    i + first_int);
			for (; i >= first_int; i--) {
				sc->msi_isrcs[i].allocated = false;
				sc->msi_isrcs[i].isrc = NULL;
			}
			break;
		}
		sc->msi_isrcs[i].isrc = *srcs;
		srcs++;
	}
	return (first_int);
}

static int
apple_pcie_alloc_msi(device_t dev, device_t child, int count, int maxcount,
    device_t *pic, struct intr_irqsrc **srcs)
{
	struct apple_pcie_softc *sc;
	int first_int, msicap, error;
	uint32_t val;

	if ((error = pci_find_cap(dev, PCIY_MSI, &msicap)) != 0) {
		device_printf(dev, "MSI capability not found?\n");
		return (error);
	}
device_printf(dev, "%s\n", __func__);
	if ((powerof2(count) == 0) || (count > 8))
		return (EINVAL);

	sc = device_get_softc(dev);

	mtx_lock(&sc->msi_mtx);
	if ((first_int = apple_pcie_alloc_intr(sc, count, srcs)) == -1) {
		mtx_unlock(&sc->msi_mtx);
		return (ENXIO);
	}

	//*pic = device_get_parent(dev);
	*pic = sc->aic_dev;

	val = pci_read_config(dev, msicap + PCIR_MSI_CTRL, 2);
	pci_write_config(dev, msicap + PCIR_MSI_CTRL,
	    val &~ PCIM_MSICTRL_MSI_ENABLE, 2);

	/* Update control register with actual count. */
	val = pci_read_config(dev, msicap + PCIR_MSI_CTRL, 2);
	val &= ~PCIM_MSICTRL_MME_MASK;
	val |= (ffs(count) - 1) << 4;
	pci_write_config(dev, msicap + PCIR_MSI_CTRL, val, 2);

	val = pci_read_config(dev, msicap + PCIR_MSI_CTRL, 2);
	pci_write_config(dev, msicap + PCIR_MSI_ADDR,
	    sc->msi_addr & 0xffffffff, 4);
	if (val & PCIM_MSICTRL_64BIT) {
		pci_write_config(dev, msicap + PCIR_MSI_ADDR_HIGH,
		    (sc->msi_addr >> 32) & 0xffffffff, 4);
		pci_write_config(dev, msicap + PCIR_MSI_DATA_64BIT,
		    first_int, 4);
	} else {
		pci_write_config(dev, msicap + PCIR_MSI_DATA, first_int, 4);
	}
	pci_write_config(dev, msicap + PCIR_MSI_CTRL,
	    val | PCIM_MSICTRL_MSI_ENABLE, 2);

	mtx_unlock(&sc->msi_mtx);

	if (bootverbose)
		device_printf(dev, "allocate MSI intr %d - %d\n",
		    first_int, first_int + count - 1);
	return (0);
}

static int
apple_pcie_alloc_msix(device_t dev, device_t child, device_t *pic,
    struct intr_irqsrc **srcs)
{
	struct apple_pcie_softc *sc;
	int first_int, msixcap, error;
	uint32_t val;

	if ((error = pci_find_cap(dev, PCIY_MSIX, &msixcap)) != 0) {
		device_printf(dev, "MSIX capability not found?\n");
		return (error);
	}

	sc = device_get_softc(dev);

device_printf(dev, "%s\n", __func__);
	mtx_lock(&sc->msi_mtx);
	if ((first_int = apple_pcie_alloc_intr(sc, 1, srcs)) == -1) {
		mtx_unlock(&sc->msi_mtx);
		return (ENXIO);
	}

	//*pic = device_get_parent(dev);
	*pic = sc->aic_dev;

	val = pci_read_config(dev, msixcap + PCIR_MSIX_CTRL, 2);
	pci_write_config(dev, msixcap + PCIR_MSIX_CTRL,
	    val &~ PCIM_MSIXCTRL_MSIX_ENABLE, 2);

	/* TODO: ??? */
	device_printf(dev, "TODO: msix vectors etc???\n");
#if 0	/* XXX NetBSD does this in apple_pcie_msi_msix_enable; do we need? */
	/* What would msix_vec be? */
	const uint64_t addr = sc->sc_msi_addr;
	const uint32_t data = msi;
	const uint64_t entry_base = PCI_MSIX_TABLE_ENTRY_SIZE * msix_vec;
	bus_space_write_4(bst, bsh, entry_base + PCI_MSIX_TABLE_ENTRY_ADDR_LO,
	    (uint32_t)addr);
	bus_space_write_4(bst, bsh, entry_base + PCI_MSIX_TABLE_ENTRY_ADDR_HI,
	    (uint32_t)(addr >> 32));
	bus_space_write_4(bst, bsh, entry_base + PCI_MSIX_TABLE_ENTRY_DATA,
	    data);
	val = bus_space_read_4(bst, bsh,
	    entry_base + PCI_MSIX_TABLE_ENTRY_VECTCTL);
	val &= ~PCI_MSIX_VECTCTL_MASK;
	bus_space_write_4(bst, bsh, entry_base + PCI_MSIX_TABLE_ENTRY_VECTCTL,
	    val);
#endif

	val = pci_read_config(dev, msixcap + PCIR_MSIX_CTRL, 2);
	pci_write_config(dev, msixcap + PCIR_MSIX_CTRL,
	    val | PCIM_MSIXCTRL_MSIX_ENABLE, 2);
	mtx_unlock(&sc->msi_mtx);

	if (bootverbose)
		device_printf(dev, "allocate MSIX intr %d\n", first_int);
	return (0);
}

static int
apple_pcie_find_intr(struct apple_pcie_softc *sc, struct intr_irqsrc *src)
{
	int i;

	for (i = 0; i < sc->nmsi; i++)
		if (sc->msi_isrcs[i].isrc == src)
			return (i);
	return (-1);
}

static int
apple_pcie_map_msi(device_t dev, device_t child, struct intr_irqsrc *isrc,
    uint64_t *addr, uint32_t *data)
{
	struct apple_pcie_softc *sc;
	struct apple_pcie_irqsrc *msi_msg;
	int i;

	sc = device_get_softc(dev);
	i = apple_pcie_find_intr(sc, isrc);
	if (i == -1)
		return (EINVAL);
device_printf(dev, "TODO: pcie map %d\n", i);

	msi_msg = &sc->msi_isrcs[i];

	*addr = sc->msi_addr;
#ifdef IMPL	/* XXX */
	*data = (REG_VALUE_MSI_CONFIG & 0xffff) | i;
#else
	*data =  msi_msg->irq;
#endif
	return (0);
}

static int
apple_pcie_release_msi(device_t dev, device_t child, int count,
    struct intr_irqsrc **isrc)
{
	struct apple_pcie_softc *sc;
	struct apple_pcie_irqsrc *msi_isrc;
	int i, first_int, msicap;
	uint32_t val;

	sc = device_get_softc(dev);
	/* Assume isrc's are in order, so we look up just the first. */
	first_int = apple_pcie_find_intr(sc, isrc[0]);
	if (first_int == -1)
		return (EINVAL);

	mtx_lock(&sc->msi_mtx);

	for (i = first_int; i < first_int + count; i++) {
		msi_isrc = &sc->msi_isrcs[i];
		msi_isrc->allocated = false;
		msi_isrc->isrc = NULL;
		/* XXX disable interrupt??? */
	}

	/* Disable MSI; XXX does this disable for all devices ??? */
	if (pci_find_cap(dev, PCIY_MSIX, &msicap) != 0)
		panic("%s: MSI not found???", __func__);
	val = pci_read_config(dev, msicap + PCIR_MSI_CTRL, 2);
	pci_write_config(dev, msicap + PCIR_MSI_CTRL,
	    val &~ PCIM_MSICTRL_MSI_ENABLE, 2);

	mtx_unlock(&sc->msi_mtx);
	return (0);
}

static int
apple_pcie_release_msix(device_t dev, device_t child,
    struct intr_irqsrc *srcs)
{

	return (apple_pcie_release_msi(dev, child, 1, &srcs));
}


static void
apple_pcie_setup_port(struct apple_pcie_softc *sc, u_int portno)
{
	char regname[sizeof("portX")];
	phandle_t node;
	struct resource *res;
	int rid;

	node = ofw_bus_get_node(sc->dev);
	snprintf(regname, sizeof(regname), "port%u", portno);
	if (ofw_bus_find_string_index(node, "reg-names", regname, &rid) != 0) {
		device_printf(sc->dev, "couldn't get %s regs\n", regname);
		return;
	}
	res = bus_alloc_resource_any(sc->dev, SYS_RES_MEMORY, &rid, RF_ACTIVE);
	if (res == NULL) {
		device_printf(sc->dev, "couldn't map %s regs\n", regname);
		return;
	}

	/* Doorbell address must be below 4GB */
	KASSERT((sc->msi_addr & ~0xffffffffUL) == 0, ("msi_addr > 4G"));

	/* Make MSI interrupts shareable across all ports. */
	bus_write_4(res, PCIE_MSI_CTRL, PCIE_MSI_CTRL_32 | PCIE_MSI_CTRL_EN);
	bus_write_4(res, PCIE_MSI_REMAP, 0);
	bus_write_4(res, PCIE_MSI_DOORBELL, (uint32_t)sc->msi_addr);

	bus_free_resource(sc->dev, SYS_RES_MEMORY, res);
}

static int
apple_pcie_msi_attach(device_t dev)
{
	struct apple_pcie_softc *sc = device_get_softc(dev);
	phandle_t node, xref;
	int i, error;
	cell_t *cells;
	ssize_t len;

	sc->msi_fdt_data = malloc(sizeof(*sc->msi_fdt_data) +
	    FDT_INTR_NCELLS * sizeof(*sc->msi_fdt_data->cells),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	sc->msi_fdt_data->hdr.type = INTR_MAP_DATA_FDT;
	sc->msi_fdt_data->ncells = FDT_INTR_NCELLS;

	node = ofw_bus_get_node(dev);
	len = OF_getencprop_alloc(node, "msi-ranges", (void **) &cells);
	if (len <= 0) {
		device_printf(dev,
		    "WARNING: bad msi-ranges property, MSI not enabled!\n");
		return (ENXIO);
	}
	error = 0;
	if (len != 20) {
		device_printf(dev,
		    "WARNING: bad msi-ranges property len, MSI not enabled!\n");
		error = ENXIO;
	} else {
		/* 5 cells: xref, specifier (3 cells), and count */
		sc->msi_start = cells[2];
		sc->nmsi = cells[4];
device_printf(dev, "msi_start %d nmsi %d\n", sc->msi_start, sc->nmsi);
		/* Save information to register IRQs. */
		sc->msi_fdt_data->cells[0] = cells[1];
		sc->msi_fdt_data->cells[1] = cells[2];
		sc->msi_fdt_data->cells[2] = cells[3];
		sc->aic_dev = OF_device_from_xref((phandle_t)cells[0]);
		if (sc->aic_dev == NULL) {
			device_printf(dev,
			    "WARNING: bad aic ref, MSI not enabled!\n");
			error = ENXIO;
		}
	}
	OF_prop_free(cells);
	if (error)
		return (error);

#if 0	/* XXX NetBSD uses getprop_uint64, do we have something? */
	if (of_getprop_uint64(phandle, "msi-doorbell", &sc->sc_msi_addr))
#endif
		sc->msi_addr = 0xffff000ULL;
#if 0
	sc->msi_addr = 0xffffffffc;
	

	/* Clear any pending interrupts. */
	bcm_pcib_set_reg(sc, REG_MSI_CLR, 0xffffffff);
#endif
	for (i = 0; i < PCIE_NPORTS; ++i)
		apple_pcie_setup_port(sc, i);

	sc->msi_isrcs = malloc(sizeof(*sc->msi_isrcs) * sc->nmsi, M_DEVBUF,
	    M_WAITOK | M_ZERO);
	for (i = 0; i < sc->nmsi; i++)
		sc->msi_isrcs[i].irq = i;

	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	error = intr_msi_register(dev, xref);
	if (error)
		return (ENXIO);

	mtx_init(&sc->msi_mtx, "apple_pcie: msi_mtx", NULL, MTX_DEF);

#if 0
	bcm_pcib_set_reg(sc, REG_MSI_MASK_CLR, 0xffffffff);
	bcm_pcib_set_reg(sc, REG_MSI_ADDR_LOW, (sc->msi_addr & 0xffffffff) | 1);
	bcm_pcib_set_reg(sc, REG_MSI_ADDR_HIGH, (sc->msi_addr >> 32));
	bcm_pcib_set_reg(sc, REG_MSI_CONFIG, REG_VALUE_MSI_CONFIG);
#endif

#define SELF_TEST
#ifdef SELF_TEST
	/* XXX TMP test; this may not work before attach is completed. */
	static struct intr_irqsrc *psrcs[2];
	device_t pic;
	device_printf(dev, "test alloc_msi\n");
	error = apple_pcie_alloc_msi(dev, NULL, 2, 2, &pic, psrcs);
	if (error)
		device_printf(dev, "test alloc_msi: err %d\n", error);
	else {
		error = apple_pcie_release_msi(dev, NULL, 2, psrcs);
		if (error)
			device_printf(dev, "test release_msi: err %d\n", error);
	}
	error = apple_pcie_alloc_msix(dev, NULL, &pic, psrcs);
	if (error)
		device_printf(dev, "test alloc_msix: err %d\n", error);
	else {
		error = apple_pcie_release_msix(dev, NULL, psrcs[0]);
		if (error)
		    device_printf(dev, "test release_msix: err %d\n", error);
	}
#endif

	return (0);
}

#if 0
static void
bcm_pcib_relocate_bridge_window(device_t dev)
{
	/*
	 * In principle an out-of-bounds bridge window could be automatically
	 * adjusted at resource-activation time to lie within the bus address
	 * space by pcib_grow_window(), but that is not possible because the
	 * out-of-bounds resource allocation fails at allocation time. Instead,
	 * we will just fix up the window on the controller here, before it is
	 * re-discovered by pcib_probe_windows().
	 */

	struct bcm_pcib_softc *sc;
	pci_addr_t base, size, new_base, new_limit;
	uint16_t val;

	sc = device_get_softc(dev);

	val = bcm_pcib_read_config(dev, 0, 0, 0, PCIR_MEMBASE_1, 2);
	base = PCI_PPBMEMBASE(0, val);

	val = bcm_pcib_read_config(dev, 0, 0, 0, PCIR_MEMLIMIT_1, 2);
	size = PCI_PPBMEMLIMIT(0, val) - base;

	new_base = sc->base.base.ranges[0].pci_base;
	val = (uint16_t) (new_base >> 16);
	bcm_pcib_write_config(dev, 0, 0, 0, PCIR_MEMBASE_1, val, 2);

	new_limit = new_base + size;
	val = (uint16_t) (new_limit >> 16);
	bcm_pcib_write_config(dev, 0, 0, 0, PCIR_MEMLIMIT_1, val, 2);
}

static uint32_t
encode_cpu_window_low(pci_addr_t phys_base, bus_size_t size)
{

	return (((phys_base >> 0x10) & 0xfff0) |
	    ((phys_base + size - 1) & 0xfff00000));
}

static uint32_t
encode_cpu_window_start_high(pci_addr_t phys_base)
{

	return ((phys_base >> 0x20) & 0xff);
}

static uint32_t
encode_cpu_window_end_high(pci_addr_t phys_base, bus_size_t size)
{

	return (((phys_base + size - 1) >> 0x20) & 0xff);
}
#endif

static void pcie_intr0(void *softc)
{
	struct apple_pcie_softc *sc = softc;

	device_printf(sc->dev, "pcie_intr0\n");
}

static void pcie_intr1(void *softc)
{
	struct apple_pcie_softc *sc = softc;

	device_printf(sc->dev, "pcie_intr1\n");
}

static void pcie_intr2(void *softc)
{
	struct apple_pcie_softc *sc = softc;

	device_printf(sc->dev, "pcie_intr2\n");
}

static int
apple_pcie_attach(device_t dev)
{
	struct apple_pcie_softc *sc;
#if 0
	pci_addr_t phys_base, pci_base;
	bus_size_t size;
	uint32_t hardware_rev, bridge_state, link_state;
	int error, tries;
#endif
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;

	error = pci_host_generic_setup_fdt(dev);
	if (error)
		return (error);

	error = apple_pcie_check_ranges(dev);
	if (error)
		return (error);

	mtx_init(&sc->config_mtx, "apple_pcie: config_mtx", NULL, MTX_DEF);

#if 0
	bcm_pcib_reset_controller(sc);

	hardware_rev = bcm_pcib_read_reg(sc, REG_CONTROLLER_HW_REV) & 0xffff;
	device_printf(dev, "hardware identifies as revision 0x%x.\n",
	    hardware_rev);

	/*
	 * Set PCI->CPU memory window. This encodes the inbound window showing
	 * the system memory to the controller.
	 */
	bcm_pcib_set_reg(sc, REG_DMA_WINDOW_LOW, REG_VALUE_DMA_WINDOW_LOW);
	bcm_pcib_set_reg(sc, REG_DMA_WINDOW_HIGH, REG_VALUE_DMA_WINDOW_HIGH);
	bcm_pcib_set_reg(sc, REG_DMA_CONFIG, REG_VALUE_DMA_WINDOW_CONFIG);

	bcm_pcib_set_reg(sc, REG_BRIDGE_GISB_WINDOW, 0);
	bcm_pcib_set_reg(sc, REG_DMA_WINDOW_1, 0);

	bcm_pcib_enable_controller(sc);

	/* Wait for controller to start. */
	for(tries = 0; ; ++tries) {
		bridge_state = bcm_pcib_read_reg(sc, REG_BRIDGE_STATE);

		if ((bridge_state & 0x30) == 0x30)
			/* Controller ready. */
			break;

		if (tries > 100) {
			device_printf(dev,
			    "error: controller failed to start.\n");
			return (ENXIO);
		}

		DELAY(1000);
	}

	link_state = bcm_pcib_read_reg(sc, REG_BRIDGE_LINK_STATE) >> 0x10;
	if (!link_state) {
		device_printf(dev, "error: controller started but link is not "
		    "up.\n");
		return (ENXIO);
	}
	if (bootverbose)
		device_printf(dev, "note: reported link speed is %s.\n",
		    bcm_pcib_link_state_string(link_state));

	/*
	 * Set the CPU->PCI memory window. The map in this direction is not 1:1.
	 * Addresses seen by the CPU need to be adjusted to make sense to the
	 * controller as they pass through the window.
	 */
	pci_base  = sc->base.base.ranges[0].pci_base;
	phys_base = sc->base.base.ranges[0].phys_base;
	size      = sc->base.base.ranges[0].size;

	bcm_pcib_set_reg(sc, REG_BUS_WINDOW_LOW, pci_base & 0xffffffff);
	bcm_pcib_set_reg(sc, REG_BUS_WINDOW_HIGH, pci_base >> 32);

	bcm_pcib_set_reg(sc, REG_CPU_WINDOW_LOW,
	    encode_cpu_window_low(phys_base, size));
	bcm_pcib_set_reg(sc, REG_CPU_WINDOW_START_HIGH,
	    encode_cpu_window_start_high(phys_base));
	bcm_pcib_set_reg(sc, REG_CPU_WINDOW_END_HIGH,
	    encode_cpu_window_end_high(phys_base, size));

	/*
	 * The controller starts up declaring itself an endpoint; readvertise it
	 * as a bridge.
	 */
	bcm_pcib_set_reg(sc, PCI_ID_VAL3,
	    PCIC_BRIDGE << CLASS_SHIFT | PCIS_BRIDGE_PCI << SUBCLASS_SHIFT);

	bcm_pcib_set_reg(sc, REG_BRIDGE_SERDES_MODE, 0x2);
	DELAY(100);

	bcm_pcib_relocate_bridge_window(dev);
#endif

	if (bus_alloc_resources(dev, pcie_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources\n");
		return (ENXIO);
	}

	/* Configure interrupt placeholders. */
	error = bus_setup_intr(dev, sc->res[_RES_IRQ0],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, pcie_intr0, sc, &sc->ih[0]);
	if (error != 0) {
		device_printf(dev, "cannot setup interrupt handler0\n");
		return (error);
	}
	error = bus_setup_intr(dev, sc->res[_RES_IRQ1],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, pcie_intr1, sc, &sc->ih[1]);
	if (error != 0) {
		device_printf(dev, "cannot setup interrupt handler1\n");
		return (error);
	}
	error = bus_setup_intr(dev, sc->res[_RES_IRQ2],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, pcie_intr2, sc, &sc->ih[2]);
	if (error != 0) {
		device_printf(dev, "cannot setup interrupt handler2\n");
		return (error);
	}

	/* Configure MSI interrupts. */
	error = apple_pcie_msi_attach(dev);
	if (error)
		return (error);

	/* Done. */
	device_add_child(dev, "pci", -1);
	return (bus_generic_attach(dev));
}

/*
 * Device method table.
 */
static device_method_t apple_pcie_methods[] = {
	/* Device interface. */
	DEVMETHOD(device_probe,			apple_pcie_probe),
	DEVMETHOD(device_attach,		apple_pcie_attach),

	/* PCIB interface. */
	DEVMETHOD(pcib_read_config,		apple_pcie_read_config),
	DEVMETHOD(pcib_write_config,		apple_pcie_write_config),

	/* MSI interface. */
	DEVMETHOD(msi_alloc_msi,		apple_pcie_alloc_msi),
	DEVMETHOD(msi_release_msi,		apple_pcie_release_msi),
	DEVMETHOD(msi_alloc_msix,		apple_pcie_alloc_msix),
	DEVMETHOD(msi_release_msix,		apple_pcie_release_msix),
	DEVMETHOD(msi_map_msi,			apple_pcie_map_msi),

	DEVMETHOD_END
};

DEFINE_CLASS_1(pcib, apple_pcie_driver, apple_pcie_methods,
    sizeof(struct apple_pcie_softc), generic_pcie_fdt_driver);

static devclass_t apple_pcie_devclass;
DRIVER_MODULE(apple_pcie, simplebus, apple_pcie_driver, apple_pcie_devclass,
    0, 0);
