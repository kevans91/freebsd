/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Kyle Evans <kevans@FreeBSD.org>
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
#include <sys/systm.h>

#include <net/vnet.h>

#ifdef KLD_MODULE
#error vnet_support.c may not be compiled into a module.
#endif

/*
 * vimage_configured is compiled into the kernel.  Untied modules will inspect
 * it in various vnet-related macros as well as in invocations of the below
 * vnet_dynamic_* functions that only get invoked from untied modules.
 */
#ifdef VIMAGE
const int vimage_configured = 1;
#else
const int vimage_configured = 0;
#endif

/*
 * Handlers for VNET_SYSINIT/VNET_SYSUNINIT in untied kmods that determine at
 * runtime if they are working with a VIMAGE kernel or not.  These either proxy
 * through to the undynamic version as necessary, or they invoke the underlying
 * callback at the correct time (as if directly specified SYSINIT/SYSUNINIT).
 */
void
vnet_dynamic_register_sysinit(void *arg)
{
	struct vnet_sysinit *vs;

	vs = arg;
	KASSERT(vs->subsystem > SI_SUB_VNET, ("vnet sysinit too early"));

	if (vimage_configured)
		vnet_register_sysinit(arg);
	else
		vs->func(vs->arg);
}

void
vnet_dynamic_deregister_sysinit(void *arg)
{

	if (vimage_configured)
		vnet_deregister_sysinit(arg);
}

void
vnet_dynamic_register_sysuninit(void *arg)
{

	if (vimage_configured)
		vnet_register_sysuninit(arg);
}

void
vnet_dynamic_deregister_sysuninit(void *arg)
{
	struct vnet_sysinit *vs;

	if (vimage_configured) {
		vnet_deregister_sysuninit(arg);
	} else {
		vs = arg;
		vs->func(vs->arg);
	}
}
