/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Copyright (c) 2014 The FreeBSD Foundation
 *
 * Portions of this software were developed by Konstantin Belousov
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
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
#include <assert.h>

#include "stand.h"

/*
 * More or less extracted from sys/kern/subr_uio.c.
 */
int
uiomove(void *buf, int howmuch, struct uio *uiop)
{
	enum uio_rw rw = uiop->uio_rw;
	struct iovec *iov;
	size_t cnt;

	assert(rw == UIO_READ || rw == UIO_WRITE);
	while (howmuch > 0 && uiop->uio_resid > 0) {
		assert(uiop->uio_iovcnt > 0);

		/* Prune the first iov if it's now empty. */
		iov = uiop->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uiop->uio_iov++;
			uiop->uio_iovcnt--;
			continue;
		}

		/*
		 * Move it; we ripped segflg out of the uio in loader for
		 * obvious reasons, so this is somewhat simpler.
		 */
		cnt = MIN(cnt, howmuch);
		if (rw == UIO_READ)
			bcopy(buf, iov->iov_base, cnt);
		else
			bcopy(iov->iov_base, buf, cnt);

		iov->iov_base = (char *)iov->iov_base + cnt;
		iov->iov_len -= cnt;

		uiop->uio_resid -= cnt;
		uiop->uio_offset += cnt;
		buf = (char *)buf + cnt;
		howmuch -= cnt;
	}

	return (0);
}
