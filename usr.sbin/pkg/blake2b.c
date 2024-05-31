/*- blake2b.c (from libmd:mdXhl.c)
 * SPDX-License-Identifier: Beerware
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

#include <blake2.h>
#include <stdlib.h>
#include <unistd.h>

#include "hash.h"

static char *
blake2b_end(blake2b_state *ctx, char *buf)
{
	unsigned char digest[BLAKE2B_OUTBYTES];
	static const char hex[] = "0123456789abcdef";
	int i;

	if (buf == NULL)
		buf = malloc(2 * sizeof(digest) + 1);
	if (buf == NULL)
		return (0);

	blake2b_final(ctx, digest, sizeof(digest));
	for (i = 0; i < BLAKE2B_OUTBYTES; i++) {
		buf[i + i] = hex[digest[i] >> 4];
		buf[i + i + 1] = hex[digest[i] & 0x0f];
	}

	buf[i + i] = '\0';
	return (buf);
}

char *
blake2b_buf(char *buf, size_t len)
{
	blake2b_state ctx;

	blake2b_init(&ctx, BLAKE2B_OUTBYTES);
	blake2b_update(&ctx, buf, len);

	return (blake2b_end(&ctx, buf));
}

char *
blake2b_fd(int fd)
{
	unsigned char buffer[16*1024];
	blake2b_state ctx;
	int readrv;

	blake2b_init(&ctx, BLAKE2B_OUTBYTES);

	readrv = 0;
	for (;;) {
		readrv = read(fd, buffer, sizeof(buffer));
		if (readrv <= 0)
			break;
		blake2b_update(&ctx, buffer, readrv);
	}

	if (readrv < 0)
		return NULL;
	return (blake2b_end(&ctx, NULL));
}
