/*-
 * Copyright (c) 2015 Landon Fuller <landon@landonf.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/systm.h>

#include <machine/bus.h>

#include <dev/bhnd/cores/bhnd_chipcreg.h>

#include "sibareg.h"
#include "sibavar.h"

/* The port/region/rid triplet used for all siba(4) cores. */
#define	SIBA_CORE_PORT		0	/**< fixed register block port. */
#define	SIBA_CORE_REGION	0	/**< fixed register block region. */
#define SIBA_CORE_RID		1	/**< fixed register resource-ID */

#define SIBA_IS_PORT_VALID(type, port, region)	\
	((type) == BHND_PORT_DEVICE &&		\
	 (port_num) == SIBA_CORE_PORT &&	\
	 region_num == SIBA_CORE_REGION)

int
siba_probe(device_t dev)
{
	device_set_desc(dev, "SIBA BHND bus");
	return (BUS_PROBE_DEFAULT);
}

int
siba_attach(device_t dev)
{
	/* Bus' generic attach will probe and attach any enumerated children */
	return (bus_generic_attach(dev));
}

int
siba_detach(device_t dev)
{
	return (bus_generic_detach(dev));
}

static int
siba_read_ivar(device_t dev, device_t child, int index, uintptr_t *result)
{
	const struct siba_devinfo *dinfo;
	const struct bhnd_core_info *cfg;
	
	dinfo = device_get_ivars(child);
	cfg = &dinfo->core_info;
	
	switch (index) {
	case BHND_IVAR_VENDOR:
		*result = cfg->vendor;
		return (0);
	case BHND_IVAR_DEVICE:
		*result = cfg->device;
		return (0);
	case BHND_IVAR_HWREV:
		*result = cfg->hwrev;
		return (0);
	case BHND_IVAR_DEVICE_CLASS:
		*result = bhnd_core_class(cfg);
		return (0);
	case BHND_IVAR_VENDOR_NAME:
		*result = (uintptr_t) bhnd_vendor_name(cfg->vendor);
		return (0);
	case BHND_IVAR_DEVICE_NAME:
		*result = (uintptr_t) bhnd_core_name(cfg);
		return (0);
	case BHND_IVAR_CORE_INDEX:
		*result = cfg->core_id;
		return (0);
	case BHND_IVAR_CORE_UNIT:
		*result = cfg->unit;
		return (0);
	default:
		return (ENOENT);
	}
}

static int
siba_write_ivar(device_t dev, device_t child, int index, uintptr_t value)
{
	switch (index) {
	case BHND_IVAR_VENDOR:
	case BHND_IVAR_DEVICE:
	case BHND_IVAR_HWREV:
	case BHND_IVAR_DEVICE_CLASS:
	case BHND_IVAR_VENDOR_NAME:
	case BHND_IVAR_DEVICE_NAME:
	case BHND_IVAR_CORE_INDEX:
	case BHND_IVAR_CORE_UNIT:
		return (EINVAL);
	default:
		return (ENOENT);
	}
}

static void
siba_child_deleted(device_t dev, device_t child)
{
	struct siba_devinfo *dinfo = device_get_ivars(child);
	if (dinfo != NULL)
		siba_free_dinfo(dinfo);
}

static struct resource_list *
siba_get_resource_list(device_t dev, device_t child)
{
	struct siba_devinfo *dinfo = device_get_ivars(child);
	return (&dinfo->resources);
}

static int
siba_get_port_rid(device_t dev, device_t child, bhnd_port_type port_type,
    u_int port_num, u_int region_num)
{
	/* delegate non-bus-attached devices to our parent */
	if (device_get_parent(child) != dev) {
		return (BHND_GET_PORT_RID(device_get_parent(dev), child,
		    port_type, port_num, region_num));
	}

	if (SIBA_IS_PORT_VALID(port_type, port_num, region_num))
		return (SIBA_CORE_RID);

	/* not found */
	return (-1);
}

static int
siba_decode_port_rid(device_t dev, device_t child, int type, int rid,
    bhnd_port_type *port_type, u_int *port_num, u_int *region_num)
{
	/* delegate non-bus-attached devices to our parent */
	if (device_get_parent(child) != dev) {
		return (BHND_DECODE_PORT_RID(device_get_parent(dev), child,
		    type, rid, port_type, port_num, region_num));
	}
	
	if (type != SYS_RES_MEMORY)
		return (EINVAL);

	/* siba(4) cores only support a single memory RID */
	if (rid != SIBA_CORE_RID)
		return (ENOENT);

	*port_type = BHND_PORT_DEVICE;
	*port_num = SIBA_CORE_PORT;
	*region_num = SIBA_CORE_REGION;
	return (0);
}

static int
siba_get_port_addr(device_t dev, device_t child, bhnd_port_type port_type,
    u_int port_num, u_int region_num, bhnd_addr_t *addr, bhnd_size_t *size)
{
	struct siba_devinfo		*dinfo;
	struct resource_list_entry	*rle;

	/* delegate non-bus-attached devices to our parent */
	if (device_get_parent(child) != dev) {
		return (BHND_GET_PORT_ADDR(device_get_parent(dev), child,
		    port_type, port_num, region_num, addr, size));
	}

	dinfo = device_get_ivars(child);

	/* siba(4) cores only support a single device port region */
	if (!SIBA_IS_PORT_VALID(port_type, port_num, region_num))
		return (ENOENT);

	/* fetch the port addr/size from the resource list */
	rle = resource_list_find(&dinfo->resources, SYS_RES_MEMORY,
	    SIBA_CORE_RID);
	if (rle == NULL)
		return (ENOENT);

	*addr = rle->start;
	*size = rle->count;
	return (0);
}

/**
 * Scan the core table and add all valid discovered cores to
 * the bus.
 * 
 * @param dev The siba bus device.
 * @param chipid The chip identifier, if known or if the device
 * does not provide a ChipCommon core. May be NULL otherwise.
 */
int
siba_add_children(device_t dev, const struct bhnd_chipid *chipid)
{
	struct bhnd_chipid	 ccid;
	struct bhnd_core_info	*cores;
	struct siba_devinfo	*dinfo;
	u_int			 ncores;
	int			 error;

	dinfo = NULL;
	cores = NULL;

	/* If not provided by our caller, read the chip ID now. */
	if (chipid == NULL) {
		struct resource_spec rs = {
			.rid = 0,
			.type = SYS_RES_MEMORY,
			.flags = RF_ACTIVE,
		};

		error = bhnd_read_chipid(dev, &rs, SIBA_ENUM_ADDR, &ccid);
		if (error) {
			device_printf(dev, "failed to read bus chipid\n");
			return (error);
		}

		chipid = &ccid;
	}
	
	/* Determine the core count */
	ncores = siba_get_ncores(chipid);
	if (ncores == 0) {
		device_printf(dev, "core count unknown for chip ID 0x%hx\n",
		    chipid->chip_id);
		return (ENXIO);
	}

	/* Allocate our temporary core table and enumerate all cores */
	cores = malloc(sizeof(*cores) * ncores, M_BHND, M_WAITOK);
	if (cores == NULL)
		return (ENOMEM);

	/* Add all cores. */
	for (u_int i = 0; i < ncores; i++) {
		struct resource	*r;
		device_t	 child;
		uint32_t	 idreg;
		u_long		 r_count, r_end, r_start;
		int		 rid;

		/* Map the core's register block */
		rid = 0;
		r_start = SIBA_CORE_ADDR(i);
		r_count = SIBA_CORE_SIZE;
		r_end = r_start + SIBA_CORE_SIZE - 1;
		r = bus_alloc_resource(dev, SYS_RES_MEMORY, &rid, r_start,
		    r_end, r_count, RF_ACTIVE);
		if (r == NULL) {
			error = ENXIO;
			goto cleanup;
		}

		/* Read the core info */
		idreg = bus_read_4(r, SIBA_IDHIGH);
		cores[i] = siba_parse_core_info(idreg, i, 0);

		/* Release our resource */
		bus_release_resource(dev, SYS_RES_MEMORY, rid, r);

		/* Determine unit number */
		for (u_int j = 0; j < i; j++) {
			if (cores[j].vendor == cores[i].vendor &&
			    cores[j].device == cores[i].device)
				cores[i].unit++;
		}

		/* Allocate per-device bus info */
		dinfo = siba_alloc_dinfo(dev, &cores[i]);
		if (dinfo == NULL) {
			error = ENXIO;
			goto cleanup;
		}

		/* Populate the resource list */
		resource_list_add(&dinfo->resources, SYS_RES_MEMORY,
		    SIBA_CORE_RID, SIBA_CORE_ADDR(i),
		    SIBA_CORE_ADDR(i) + SIBA_CORE_SIZE - 1, SIBA_CORE_SIZE);

		/* Add the child device */
		child = device_add_child(dev, NULL, -1);
		if (child == NULL) {
			error = ENXIO;
			goto cleanup;
		}

		/* The child device now owns the dinfo pointer */
		device_set_ivars(child, dinfo);
		dinfo = NULL;

		/* If pins are floating or the hardware is otherwise
		 * unpopulated, the device shouldn't be used. */
		if (bhnd_is_hw_disabled(child))
			device_disable(child);
	}
	
cleanup:
	if (cores != NULL)
		free(cores, M_BHND);

	if (dinfo != NULL)
		siba_free_dinfo(dinfo);

	return (error);
}

static device_method_t siba_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			siba_probe),
	DEVMETHOD(device_attach,		siba_attach),
	DEVMETHOD(device_detach,		siba_detach),
	
	/* Bus interface */
	DEVMETHOD(bus_child_deleted,		siba_child_deleted),
	DEVMETHOD(bus_read_ivar,		siba_read_ivar),
	DEVMETHOD(bus_write_ivar,		siba_write_ivar),
	DEVMETHOD(bus_get_resource_list,	siba_get_resource_list),

	/* BHND interface */
	DEVMETHOD(bhnd_get_port_rid,		siba_get_port_rid),
	DEVMETHOD(bhnd_decode_port_rid,		siba_decode_port_rid),
	DEVMETHOD(bhnd_get_port_addr,		siba_get_port_addr),

	DEVMETHOD_END
};

DEFINE_CLASS_1(bhnd, siba_driver, siba_methods, sizeof(struct siba_softc), bhnd_driver);

MODULE_VERSION(siba, 1);
MODULE_DEPEND(siba, bhnd, 1, 1, 1);
