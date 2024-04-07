/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Raghav Sharma <raghav@freebsd.org>
 * Parts Copyright (c) 2014 Dave Vasilevsky <dave@vasilevsky.ca>
 * Obtained from the squashfuse project
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
 *
 */

#ifdef _KERNEL
#include "opt_gzio.h"
#include "opt_zstdio.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <squashfs.h>
#include <squashfs_mount.h>
#include <squashfs_decompressor.h>

#ifdef GZIO
#include <contrib/zlib/zlib.h>
#endif
#include <contrib/xz-embedded/linux/include/linux/xz.h>
#ifdef ZSTDIO
#define ZSTD_STATIC_LINKING_ONLY
#include <contrib/zstd/lib/zstd.h>
#endif

/* Support for zlib compressor */
#ifdef GZIO
static sqsh_err
zlib_decompressor(void *input, size_t input_size, void *output, size_t *output_size)
{
	uLongf zout;
	int zerr;

	zout = *output_size;
	zerr = uncompress((Bytef*)output, &zout, input, input_size);
	if (zerr != Z_OK)
		return (SQFS_ERR);
	*output_size = zout;
	return (SQFS_OK);
}
#endif	/* GZIO */

#ifdef _KERNEL
static sqsh_err
xz_decompressor(void *input, size_t input_size, void *output,
    size_t *output_size)
{
	static struct xz_dec *sqsh_xz_dec;
	struct xz_buf xzb;
	enum xz_ret ret;

	/* XXX FIXME: Need per-mount */
	if (sqsh_xz_dec == NULL) {
		sqsh_xz_dec = xz_dec_init(XZ_SINGLE, 0);
		if (sqsh_xz_dec == NULL)
			return (SQFS_ERR);
	}

	xzb.in = input;
	xzb.in_pos = 0;
	xzb.in_size = input_size;

	xzb.out = output;
	xzb.out_pos = 0;
	xzb.out_size = *output_size;

	ret = xz_dec_run(sqsh_xz_dec, &xzb);
	if (ret != XZ_STREAM_END)
		return (SQFS_ERR);

	*output_size = xzb.out_size;
	return (SQFS_OK);
}
#endif

#ifdef ZSTDIO
static sqsh_err
zstd_decompressor(void *input, size_t input_size, void *output, size_t *output_size)
{
	size_t zstdout;

	zstdout = ZSTD_decompress(output, *output_size, input, input_size);
	if (ZSTD_isError(zstdout))
		return (SQFS_ERR);
	*output_size = zstdout;
	return (SQFS_OK);
}
#endif	/* ZSTDIO */

static const struct sqsh_decompressor decompressors[] = {
	{
#ifdef GZIO
		.decompressor = zlib_decompressor,
#endif
		.id = ZLIB_COMPRESSION,
		.name = "zlib",
	},
	{
		.decompressor = NULL,
		.id = LZMA_COMPRESSION,
		.name = "lzma",
	},
	{
		.decompressor = NULL,
		.id = LZO_COMPRESSION,
		.name = "lzo",
	},
	{
#ifdef _KERNEL
		.decompressor = xz_decompressor,
#endif
		.id = XZ_COMPRESSION,
		.name = "xz",
	},
	{
		.decompressor = NULL,
		.id = LZ4_COMPRESSION,
		.name = "lz4",
	},
	{
#ifdef ZSTDIO
		.decompressor = zstd_decompressor,
#endif
		.id = ZSTD_COMPRESSION,
		.name = "zstd",
	},
};

const struct sqsh_decompressor *
sqsh_lookup_decompressor(int id)
{
	const struct sqsh_decompressor *decom;

	for (size_t i = 0; i < nitems(decompressors); i++) {
		decom = &decompressors[i];

		if (id == decom->id)
			return (decom);
	}

	return (NULL);
}
