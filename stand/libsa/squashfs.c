/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Kyle Evans <kevans@FreeBD.org>
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

#include <sys/param.h>
#include <sys/dirent.h>

#include "stand.h"

#include <fs/squashfs/squashfs.h>
#include <fs/squashfs/squashfs_mount.h>
#include <fs/squashfs/squashfs_inode.h>
#include <fs/squashfs/squashfs_block.h>
#include <fs/squashfs/squashfs_file.h>
#include <fs/squashfs/squashfs_dir.h>

#include <assert.h>

static int	squashfs_open(const char *, struct open_file *);
static int	squashfs_close(struct open_file *);
static int	squashfs_read(struct open_file *, void *, size_t, size_t *);
static off_t	squashfs_seek(struct open_file *, off_t, int);
static int	squashfs_stat(struct open_file *, struct stat *);
static int	squashfs_readdir(struct open_file *, struct dirent *);

static struct sqsh_inode *squashfs_lookup(struct sqsh_mount *, const char *);

#if 0
static int	squashfs_mount(const char *, const char *, void **);
static int	squashfs_unmount(const char *, void *);
#endif

typedef struct squashfs_file {
	struct sqsh_mount	 sqf_mount;
	struct open_file	*sqf_f;
	struct sqsh_inode	*sqf_inode;
	char			*sqf_iobuf;
	size_t			 sqf_iobufsz;
	struct devdesc		*sqf_dev;
	off_t			 sqf_off;
	off_t			 sqf_doff;
	int			 sqf_fd;
} squashfs_file_t;

#define	SQSH_MOUNT2FILE(ump)	((struct squashfs_file *)(ump))

struct fs_ops squashfs_fsops = {
	.fs_name = "squashfs",
	.fo_open = squashfs_open,
	.fo_close = squashfs_close,
	.fo_read = squashfs_read,
	.fo_write = null_write,
	.fo_seek = squashfs_seek,
	.fo_stat = squashfs_stat,
	.fo_readdir = squashfs_readdir,
#if 0
	.fo_mount = squashfs_mount,
	.fo_unmount = squashfs_unmount,
#endif
};

static int
squashfs_open(const char *path, struct open_file *f)
{
	squashfs_file_t *fp;
	int error;

	errno = 0;
	fp = calloc(1, sizeof(*fp));
	if (fp == NULL)
		return (errno);

	fp->sqf_f = f;
	fp->sqf_doff = -1;
	f->f_fsdata = fp;

	/* XXX Mounting? Don't do that yet. */
	twiddle(1);
	if (squashfs_init(&fp->sqf_mount) != SQFS_OK) {
		errno = ENXIO;
		goto out;
	}

	/* Read the inode */
	fp->sqf_inode = squashfs_lookup(&fp->sqf_mount, path);
	if (fp->sqf_inode == NULL)
		errno = ENXIO;
	else
		errno = 0;
out:
	error = errno;
	if (error != 0) {
		free(fp);
	}

	return (error);
}

static int
squashfs_close(struct open_file *f)
{

	return (ENXIO);
}

static int
squashfs_read(struct open_file *f, void *buf, size_t size, size_t *resid)
{
	squashfs_file_t *fp = f->f_fsdata;
	struct sqsh_inode *inode = fp->sqf_inode;
	struct iovec iov;
	struct uio uio;
	off_t len, off;
	int rc = 0;

	off = fp->sqf_off;
	len = size;
	if (off + len > inode->size)
		len = inode->size - off;

	iov.iov_base = buf;
	iov.iov_len = len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = off;
	uio.uio_resid = len;
	uio.uio_rw = UIO_READ;

	while (uio.uio_resid != 0) {
		if (inode->size <= uio.uio_offset)
			break;

		off = uio.uio_offset;

		len = MIN(inode->size - uio.uio_offset, uio.uio_resid);

		rc = sqsh_read_file(&fp->sqf_mount, inode, off, &len, &uio);
		if (rc != SQFS_OK) {
			rc = ENXIO;
			break;
		}
	}

	if (resid != NULL)
		*resid = size - (uio.uio_offset - fp->sqf_off);
	fp->sqf_off = uio.uio_offset;

	return (rc);
}

static off_t
squashfs_seek(struct open_file *f, off_t offset, int where)
{
	squashfs_file_t *fp = f->f_fsdata;
	struct sqsh_inode *inode = fp->sqf_inode;

	switch (where) {
	case SEEK_SET:
		fp->sqf_off = offset;
		break;
	case SEEK_CUR:
		fp->sqf_off += offset;
		break;
	case SEEK_END:
		fp->sqf_off = inode->size - offset;
		break;
	default:
		return -1;
	}

	return (fp->sqf_off);
}

static int
squashfs_stat(struct open_file *f, struct stat *sb)
{
	squashfs_file_t *fp = f->f_fsdata;
	struct sqsh_inode *inode = fp->sqf_inode;

	assert(inode != NULL);
	sb->st_mode = S_IRUSR | S_IRGRP | S_IROTH;
	if (inode->type == DT_DIR)
		sb->st_mode |= S_IFDIR;
	else
		sb->st_mode |= S_IFREG;
	sb->st_uid = sb->st_gid = 0;
	sb->st_size = inode->size;
	return (0);
}

static int
squashfs_readdir(struct open_file *f, struct dirent *d)
{
	squashfs_file_t *fp = f->f_fsdata;
	struct sqsh_inode *inode = fp->sqf_inode;
	sqsh_err err;
	bool reset;

	reset = fp->sqf_doff >= 0 && fp->sqf_off < fp->sqf_doff;
	if (reset) {
		sqsh_dir_init(&fp->sqf_mount, inode, &inode->xtra.dir.d);
		fp->sqf_doff = -1;
	}

	while (fp->sqf_off != fp->sqf_doff) {
		fp->sqf_doff++;
		err = sqsh_dir_getnext(&fp->sqf_mount, &inode->xtra.dir.d,
		    &inode->xtra.dir.entry);
		if (err == SQFS_END_OF_DIRECTORY)
			return (ENOENT);
	}

	fp->sqf_off++;

	d->d_fileno = inode->xtra.dir.entry.inode_id;
	d->d_reclen = sizeof(*d);
	d->d_type = sqsh_inode_type_from_id(&fp->sqf_mount, d->d_fileno);

	assert(inode->xtra.dir.entry.name_size < sizeof(d->d_name));
	d->d_namlen = inode->xtra.dir.entry.name_size;
	memcpy(d->d_name, inode->xtra.dir.entry.name, d->d_namlen);
	d->d_name[d->d_namlen] = '\0';

	return (0);
}

#ifdef NOTYET
static int
squashfs_mount(const char *dev, const char *path, void **data)
{
	squashfs_mnt_t *mnt;
	struct open_file *f;
	char *fs;
	int error;

	errno = 0;
	mnt = calloc(1, sizeof(*mnt));
	if (mnt == NULL)
		return (errno);

	mnt->sqfs_fd = -1;
	if (asprintf(&fs, "%s%s", dev, path) < 0)
		goto done;

	printf("%s: attempt to open %s\n", __func__, fs);
	mnt->sqfs_fd = open(fs, O_RDONLY);
	error = errno;
	free(fs);
	if (mnt->sqfs_fd == -1) {
		printf("%s: open failed, error %d\n", __func__, error);
		errno = error;
		goto done;
	}

	f = fd2open_file(mnt->sqfs_fd);
	if (strcmp(f->f_ops->fs_name, "squashfs") == 0) {
		mnt->sqfs_dev = f->f_devdata;
		STAILQ_INSERT_TAIL(&mnt_list, mnt, sqfs_link);
	} else {
		errno = ENXIO;
	}

	printf("%s: %s%s: errno %d\n", __func__, dev, path, errno);

done:
	error = errno;
	if (error != 0) {
		if (mnt->sqfs_fd != -1)
			close(mnt->sqfs_fd);
		free(mnt);
	} else {
		*data = mnt;
	}

	return (error);
}

static int
squashfs_unmount(const char *dev __unused, void *data)
{
#if 0
	squashfs_mnt_t *mnt = data;

	STAILQ_REMOVE(&mnt_list, mnt, squashfs_mnt, sqfs_link);
	close(mnt->sqfs_fd);
	free(mnt);
	return (0);
#endif
	return (ENXIO);
}
#endif	/* NOTYET */

/*
 * Reads data according to the provided uio.
 * This function reads directly from disk file
 * and all decompression reads are handled by seperate
 * functions in squashfs_block.h file.
 */
sqsh_err
sqsh_io_read(struct sqsh_mount *ump, struct uio *uiop)
{
	squashfs_file_t *fp = SQSH_MOUNT2FILE(ump);
	void *dev = fp->sqf_f->f_devdata;
	struct devsw *devsw = fp->sqf_f->f_dev;
	off_t off, trim;
	daddr_t lbn;
	size_t blksz, len, rlen;
	int error;
	bool shorted;

	if (fp->sqf_iobuf == NULL) {
		_Static_assert((SQUASHFS_METADATA_SIZE % DEV_BSIZE) == 0,
		    "iobuf must be multiple of block size");
		fp->sqf_iobufsz = SQUASHFS_METADATA_SIZE;
		fp->sqf_iobuf = malloc(fp->sqf_iobufsz);
		if (fp->sqf_iobuf == NULL)
			return (SQFS_ERR);
	}

	off = uiop->uio_offset;
	trim = off % DEV_BSIZE;
	off -= trim;

	do {
		assert((off % DEV_BSIZE) == 0);
		lbn = btodb(off);

		len = MIN(fp->sqf_iobufsz,
		    roundup2(uiop->uio_resid + trim, DEV_BSIZE));

		error = devsw->dv_strategy(dev, F_READ, lbn, len, fp->sqf_iobuf,
		    &rlen);
		if (error != 0)
			break;
		shorted = rlen < len;
		error = uiomove(fp->sqf_iobuf + trim, rlen - trim, uiop);
		if (shorted)
			break;

		off = uiop->uio_offset;
		trim = 0;
	} while (error == 0 && uiop->uio_resid > 0);

	return (error != 0 || uiop->uio_resid != 0 ? SQFS_ERR : SQFS_OK);
}

/*
 * Reads data into the provided buffer.
 * This function reads directly from disk file
 * and all decompression reads are handled by seperate
 * functions in squashfs_block.h file.
 * On succes it return number of bytes read else negative
 * value on failure.
 */
ssize_t
sqsh_io_read_buf(struct sqsh_mount *ump, void *buf, off_t off, size_t len)
{
	struct uio auio;
	struct iovec aiov;
	sqsh_err error;
	ssize_t res;

	/* return success and reading zero bytes of data */
	if (len == 0)
		return (0);

	/* initialize iovec */
	aiov.iov_base = buf;
	aiov.iov_len = len;

	/* initialize uio */
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = off;
	auio.uio_rw = UIO_READ;
	auio.uio_resid = len;

	error = sqsh_io_read(ump, &auio);

	/* return negative value on reading failure */
	if (error != SQFS_OK)
		return (-1);

	res = len - auio.uio_resid;

	return (res);
}

static struct sqsh_inode *
squashfs_lookup(struct sqsh_mount *ump, const char *upath)
{
	struct sqsh_inode *inode = NULL;
	struct sqsh_dir_entry *entry = NULL;
	uint64_t inum = ump->sb.root_inode;
	char *p, *q, *start;
	int error;
	bool found, leaf;

	error = 1;
	start = NULL;

	inode = calloc(1, sizeof(*inode));
	if (inode == NULL)
		return (NULL);

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		goto out;

	error = sqsh_get_inode(ump, inode, inum);
	if (error != SQFS_OK)
		goto out;

	p = q = start = strdup(upath);
	if (start == NULL)
		goto out;

	while (*p != '\0') {
		/* Remove extra separators */
		while (*p == '/')
			p++;
		if (*p == '\0')
			break;

		q = p;
		while (*p != '\0' && *p != '/')
			p++;

		leaf = *p == '\0';
		if (*p == '/')
			*p = '\0';

		/* q is now the next component. */
		error = sqsh_dir_lookup(ump, inode, q, p - q, entry, &found);
		if (error != SQFS_OK || !found) {
			error = ENOENT;
			goto out;
		}

		inum = entry->inode_id;
		error = sqsh_get_inode(ump, inode, inum);
		if (error != SQFS_OK) {
			error = ENOENT;
			goto out;
		}

		if (!leaf) {
			if (inode->type != DT_DIR) {
				error = ENOTDIR;
				goto out;
			}

			p++;
		} else {
			printf("Found entry for %s of type %d size %zu\n",
			    q, inode->type, inode->size);
		}
	}

	error = 0;
out:
	free(start);
	free(entry);
	if (error != 0) {
		free(inode);
		inode = NULL;
	}

	return (inode);
}

