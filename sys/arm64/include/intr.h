/*-
 * Copyright (c) 2014 Andrew Turner <andrew@FreeBSD.org>
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

#ifndef _MACHINE_INTR_H_
#define	_MACHINE_INTR_H_

/*
 * We basically only want to expose some interrupt types that must be kept in
 * sync between assembly and C here.
 */
#ifndef LOCORE

#ifdef FDT
#include <dev/ofw/openfirm.h>
#endif

#include <sys/intr.h>

static inline void
arm_irq_memory_barrier(uintptr_t irq)
{
}

#ifdef SMP
void intr_ipi_dispatch(u_int);
#endif

#endif	/* LOCORE */

#ifndef NIRQ
#define	NIRQ		16384	/* XXX - It should be an option. */
#endif

#ifdef DEV_ACPI
#define	ACPI_INTR_XREF	1
#define	ACPI_MSI_XREF	2
#define	ACPI_GPIO_XREF	3
#endif

/* Platform interrupt types */
#define	INTR_TYPE_FIQ		0x0001

#endif	/* _MACHINE_INTR_H */
