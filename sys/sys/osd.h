/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2007 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_OSD_H_
#define _SYS_OSD_H_

#include <sys/queue.h>

/*
 * Lock key:
 *   (c) container lock (e.g. jail's pr_mtx) and/or osd_object_lock
 *   (l) osd_list_lock
 */
struct osd {
	u_int		  osd_nslots;	/* (c) */
	void		**osd_slots;	/* (c) */
	LIST_ENTRY(osd)	  osd_next;	/* (l) */
};

#ifdef _KERNEL

enum osd_type {
	OSD_THREAD,
	OSD_JAIL,
	OSD_KHELP,
	OSD_SESSION,
	OSD_PROC,

	OSD_LAST,	/* Keep this entry last. */
};

typedef void (*osd_destructor_t)(void *value);
typedef int (*osd_method_t)(void *obj, void *data);

int osd_register(enum osd_type type, osd_destructor_t destructor,
    osd_method_t *methods);
void osd_deregister(enum osd_type type, u_int slot);

int osd_set(enum osd_type type, struct osd *osd, u_int slot, void *value);
void **osd_reserve(u_int slot);
int osd_set_reserved(enum osd_type type, struct osd *osd, u_int slot,
    void **rsv, void *value);
void osd_free_reserved(void **rsv);
void *osd_get(enum osd_type type, struct osd *osd, u_int slot);
void *osd_get_unlocked(enum osd_type type, struct osd *osd, u_int slot);
void osd_del(enum osd_type type, struct osd *osd, u_int slot);
int osd_call(enum osd_type type, u_int method, void *obj, void *data);

void osd_exit(enum osd_type type, struct osd *osd);

#define	osd_thread_register(destructor)					\
	osd_register(OSD_THREAD, (destructor), NULL)
#define	osd_thread_deregister(slot)					\
	osd_deregister(OSD_THREAD, (slot))
#define	osd_thread_set(td, slot, value)					\
	osd_set(OSD_THREAD, &(td)->td_osd, (slot), (value))
#define	osd_thread_set_reserved(td, slot, rsv, value)			\
	osd_set_reserved(OSD_THREAD, &(td)->td_osd, (slot), (rsv), (value))
#define	osd_thread_get(td, slot)					\
	osd_get(OSD_THREAD, &(td)->td_osd, (slot))
#define	osd_thread_get_unlocked(td, slot)				\
	osd_get_unlocked(OSD_THREAD, &(td)->td_osd, (slot))
#define	osd_thread_del(td, slot)	do {				\
	KASSERT((td) == curthread, ("Not curthread."));			\
	osd_del(OSD_THREAD, &(td)->td_osd, (slot));			\
} while (0)
#define	osd_thread_call(td, method, data)				\
	osd_call(OSD_THREAD, (method), (td), (data))
#define	osd_thread_exit(td)						\
	osd_exit(OSD_THREAD, &(td)->td_osd)

#define	osd_jail_register(destructor, methods)				\
	osd_register(OSD_JAIL, (destructor), (methods))
#define	osd_jail_deregister(slot)					\
	osd_deregister(OSD_JAIL, (slot))
#define	osd_jail_set(pr, slot, value)					\
	osd_set(OSD_JAIL, &(pr)->pr_osd, (slot), (value))
#define	osd_jail_set_reserved(pr, slot, rsv, value)			\
	osd_set_reserved(OSD_JAIL, &(pr)->pr_osd, (slot), (rsv), (value))
#define	osd_jail_get(pr, slot)						\
	osd_get(OSD_JAIL, &(pr)->pr_osd, (slot))
#define	osd_jail_get_unlocked(pr, slot)					\
	osd_get_unlocked(OSD_JAIL, &(pr)->pr_osd, (slot))
#define	osd_jail_del(pr, slot)						\
	osd_del(OSD_JAIL, &(pr)->pr_osd, (slot))
#define	osd_jail_call(pr, method, data)					\
	osd_call(OSD_JAIL, (method), (pr), (data))
#define	osd_jail_exit(pr)						\
	osd_exit(OSD_JAIL, &(pr)->pr_osd)

#endif	/* _KERNEL */

#endif	/* !_SYS_OSD_H_ */
