/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Raghav Sharma <raghav@freebsd.org>
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

#include <vm/vm_param.h>

#include <geom/geom.h>
#include <geom/geom_vfs.h>

#include <squashfs.h>
#include <squashfs_io.h>
#include <squashfs_mount.h>
#include <squashfs_inode.h>
#include <squashfs_decompressor.h>
#include <squashfs_xattr.h>

static void
squashfs_swapendian_sb(struct sqsh_sb *sb)
{

	sb->s_magic					=	le32toh(sb->s_magic);
	sb->inodes					=	le32toh(sb->inodes);
	sb->mkfs_time				=	le32toh(sb->mkfs_time);
	sb->block_size				=	le32toh(sb->block_size);
	sb->fragments				=	le32toh(sb->fragments);
	sb->compression				=	le16toh(sb->compression);
	sb->block_log				=	le16toh(sb->block_log);
	sb->flags					=	le16toh(sb->flags);
	sb->no_ids					=	le16toh(sb->no_ids);
	sb->s_major					=	le16toh(sb->s_major);
	sb->s_minor					=	le16toh(sb->s_minor);
	sb->root_inode				=	le64toh(sb->root_inode);
	sb->bytes_used				=	le64toh(sb->bytes_used);
	sb->id_table_start			=	le64toh(sb->id_table_start);
	sb->xattr_id_table_start	=	le64toh(sb->xattr_id_table_start);
	sb->inode_table_start		=	le64toh(sb->inode_table_start);
	sb->directory_table_start	=	le64toh(sb->directory_table_start);
	sb->fragment_table_start	=	le64toh(sb->fragment_table_start);
	sb->lookup_table_start		=	le64toh(sb->lookup_table_start);
}

static sqsh_err
is_valid_superblock(struct sqsh_sb* sb)
{

	/* Check magic number */
	if (sb->s_magic != SQUASHFS_MAGIC && sb->s_magic != SQUASHFS_MAGIC_SWAP) {
#ifdef _KERNEL
		ERROR("Bad superblock magic number");
#endif
		return (SQFS_BADFORMAT);
	}

	/* Check for version of mounted fs */
	if (sb->s_major != SQUASHFS_MAJOR || sb->s_minor > SQUASHFS_MINOR) {
#ifdef _KERNEL
		ERROR("Unsupported version of squashfs is mounted");
#endif
		return (SQFS_BADVERSION);
	}

	/* Check if filesystem size is not negative for sanity */
	if (sb->bytes_used < 0) {
		ERROR("Filesystem size is negative!");
		return (SQFS_ERR);
	}

	/* Check block size for sanity */
	if (sb->block_size > SQUASHFS_FILE_MAX_SIZE) {
		ERROR("Invalid block size");
		return (SQFS_ERR);
	}

	/* Check block log for sanity */
	if (sb->block_log > SQUASHFS_FILE_MAX_LOG) {
		ERROR("Invalid block log");
		return (SQFS_ERR);
	}

	/* Check that block_size and block_log match */
	if (sb->block_size != (1 << sb->block_log)) {
		ERROR("Block size and log mismatch");
		return (SQFS_ERR);
	}

	/* Check the root inode for sanity */
	if (SQUASHFS_INODE_OFFSET(sb->root_inode) > SQUASHFS_METADATA_SIZE) {
		ERROR("Invalid root inode size");
		return (SQFS_ERR);
	}

	/* A valid superblock is detected */
	TRACE("A valid superblock is detected");
	return (SQFS_OK);
}

sqsh_err
squashfs_init(struct sqsh_mount* ump)
{
	sqsh_err error;

	/* squashfs superblock is at offset zero */
	if (sqsh_io_read_buf(ump, &ump->sb, 0, sizeof(struct sqsh_sb)) !=
			sizeof(struct sqsh_sb)) {
#ifdef _KERNEL
			ERROR("Failed to read superblock, I/O error");
#endif
			return (SQFS_ERR);
	}
	squashfs_swapendian_sb(&ump->sb);

	/* check superblock to see if everything is fine */
	error = is_valid_superblock(&ump->sb);
	if (error != SQFS_OK)
		return (error);

	/* Init decompressor for squashfs and check if it is unknown or supported? */
	ump->decompressor = sqsh_lookup_decompressor(ump->sb.compression);
	if (ump->decompressor == NULL) {
		ERROR("Filesystem compression type not found");
		return (SQFS_BADCOMP);
	} else if (ump->decompressor->decompressor == NULL) {
		ERROR("Filesystem uses \"%s\" compression, which is not included in this kernel.",
		       ump->decompressor->name);
		return (SQFS_BADCOMP);
	}

	error = sqsh_init_table(&ump->id_table, ump, ump->sb.id_table_start,
		sizeof(uint32_t), ump->sb.no_ids);
	if (error != SQFS_OK)
		goto id_table_fail;

	error = sqsh_init_table(&ump->frag_table, ump, ump->sb.fragment_table_start,
		sizeof(struct sqsh_fragment_entry), ump->sb.fragments);
	if (error != SQFS_OK)
		goto frag_table_fail;

	if (sqsh_export_ok(ump)) {
		error = sqsh_init_table(&ump->export_table, ump, ump->sb.lookup_table_start,
			sizeof(uint64_t), ump->sb.inodes);
		if (error != SQFS_OK)
			goto export_table_fail;
	}

	error = sqsh_init_xattr(ump);
	if (error != SQFS_OK)
		goto xattrs_fail;


	TRACE("Table init() passed!");

	/* Everything fine */
	return (SQFS_OK);

id_table_fail:
	sqsh_free_table(&ump->id_table);
	return (error);

frag_table_fail:
	sqsh_free_table(&ump->id_table);
	sqsh_free_table(&ump->frag_table);
	return (error);

export_table_fail:
	sqsh_free_table(&ump->id_table);
	sqsh_free_table(&ump->frag_table);
	sqsh_free_table(&ump->export_table);
	return (error);
xattrs_fail:
	sqsh_free_table(&ump->id_table);
	sqsh_free_table(&ump->frag_table);
	sqsh_free_table(&ump->export_table);
	sqsh_free_table(&ump->xattr_table);
	return (error);
}
