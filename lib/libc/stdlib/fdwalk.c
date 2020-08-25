/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Justin Hibbits
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/filedesc.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define FD(slot, bit)	((slot * sizeof(NDSLOTTYPE) * NBBY) + bit)

int
fdwalk(int (*cb)(void *, int), void *cbd)
{
	int mib[4];
	size_t oldlen, newlen;
	int error, i, j, len;
	NDSLOTTYPE *buf, tmp;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_FDMAP;
	mib[3] = 0;

	oldlen = 0;
	for (;;) {
		error = sysctl(mib, nitems(mib), NULL, &newlen, NULL, 0);
		if (error == -1)
			return (0);
		if (oldlen < newlen) {
			oldlen = newlen;
			buf = alloca(newlen);
		}
		newlen = oldlen;
		error = sysctl(mib, nitems(mib), buf, &newlen, NULL, 0);
		if (error == 0)
			break;
		if (errno != ENOMEM)
			return (0);
	}

	/*
	 * Go through the full file list.  The fdmap is an integral multiple of
	 * sizeof(NDSLOTTYPE).
	 */
	len = howmany(newlen, sizeof(NDSLOTTYPE));

	for (i = 0; i < len; i++) {
		/*
		 * Iterate over each bit in the slot, short-circuting when there
		 * are no more file descriptors in use in this slot.
		 */
		for (j = 0, tmp = buf[i];
		    j < NBBY * sizeof(NDSLOTTYPE) && tmp != 0;
		    j++, tmp >>= 1) {
			if (tmp & 1) {
				error = cb(cbd, FD(i, j));
				if (error != 0)
					return (error);
			}
		}
	}
	return (0);
}
