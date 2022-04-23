/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2016 Michal Meloun <mmel@FreeBSD.org>
 * All rights reserved.
 *
 * Copyright (c) 2022 Kyle Evans <kevans@FreeBSD.org>
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include "opt_platform.h"
#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kobj.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#ifdef FDT
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/mbox/mbox.h>

#include "mbox_if.h"

MALLOC_DEFINE(M_MBOX, "mbox", "Mailbox Interface");

struct mbox {
	device_t	consumer_dev;		/* consumer device */
	device_t	provider_dev;		/* provider device */
	intptr_t	mbox_id;		/* mbox id */
};

int
mbox_get_by_id(device_t consumer_dev, device_t provider_dev, intptr_t id,
    mbox_t *mb_out)
{
	mbox_t mb;

	/* Create handle */
	mb = malloc(sizeof(struct mbox), M_MBOX,
	    M_WAITOK | M_ZERO);
	mb->consumer_dev = consumer_dev;
	mb->provider_dev = provider_dev;
	mb->mbox_id = id;
	*mb_out = mb;
	return (0);
}

void
mbox_release(mbox_t mb)
{

	free(mb, M_MBOX);
}

int
mbox_read(mbox_t mb, uint32_t *data)
{

	return (MBOX_READ(mb->provider_dev, mb->mbox_id, data));
}

int
mbox_write(mbox_t mb, uint32_t data)
{

	return (MBOX_WRITE(mb->provider_dev, mb->mbox_id, data));
}

#ifdef FDT
int
mbox_default_ofw_map(device_t provider_dev, phandle_t xref, int ncells,
    pcell_t *cells, intptr_t *id)
{
	if (ncells == 0)
		*id = 1;
	else if (ncells == 1)
		*id = cells[0];
	else
		return  (ERANGE);

	return (0);
}

int
mbox_get_by_ofw_idx(device_t consumer_dev, phandle_t cnode, int idx,
    mbox_t *mb)
{
	phandle_t xnode;
	pcell_t *cells;
	device_t mboxdev;
	int ncells, rv;
	intptr_t id;

	if (cnode <= 0)
		cnode = ofw_bus_get_node(consumer_dev);
	if (cnode <= 0) {
		device_printf(consumer_dev,
		    "%s called on not ofw based device\n", __func__);
		return (ENXIO);
	}

	rv = ofw_bus_parse_xref_list_alloc(cnode, "mboxes",
	    "#mbox-cells",
	    idx, &xnode, &ncells, &cells);
	if (rv != 0)
		return (rv);

	/* Tranlate provider to device */
	mboxdev = OF_device_from_xref(xnode);
	if (mboxdev == NULL) {
		OF_prop_free(cells);
		return (ENODEV);
	}
	/* Map power domain to number */
	rv = MBOX_MAP(mboxdev, xnode, ncells, cells, &id);
	OF_prop_free(cells);
	if (rv != 0)
		return (rv);

	return (mbox_get_by_id(consumer_dev, mboxdev, id, mb));
}

int
mbox_get_by_ofw_name(device_t consumer_dev, phandle_t cnode, char *name,
    mbox_t *mb)
{
	int rv, idx;

	if (cnode <= 0)
		cnode = ofw_bus_get_node(consumer_dev);
	if (cnode <= 0) {
		device_printf(consumer_dev,
		    "%s called on not ofw based device\n",  __func__);
		return (ENXIO);
	}
	rv = ofw_bus_find_string_index(cnode, "mbox-names", name, &idx);
	if (rv != 0)
		return (rv);
	return (mbox_get_by_ofw_idx(consumer_dev, cnode, idx, mb));
}

void
mbox_register_ofw_provider(device_t provider_dev)
{
	phandle_t xref, node;

	node = ofw_bus_get_node(provider_dev);
	if (node <= 0)
		panic("%s called on not ofw based device.\n", __func__);

	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, provider_dev);
}

void
mbox_unregister_ofw_provider(device_t provider_dev)
{
	phandle_t xref;

	xref = OF_xref_from_device(provider_dev);
	OF_device_register_xref(xref, NULL);
}
#endif
