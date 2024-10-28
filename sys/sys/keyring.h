/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYS_KEYRING_H
#define	_SYS_KEYRING_H

struct keyring_obj;
struct keyring_payload;
struct keyring_store;

enum keyring_obj_type {
	KBLOB_KEYRING,
	KBLOB_USER,
};

typedef struct keyring_payload *(kstore_alloc)(struct keyring_store *,
    size_t, const void *);
typedef void (kstore_free)(struct keyring_store *, struct keyring_payload *);

struct keyring_store {
	kstore_alloc		*kstore_alloc;
	kstore_free		*kstore_free;
};

extern struct keyring_store keyring_store_phys;

struct keyring_obj *keyring_alloc(const char *, int);
struct keyring_obj *keyring_alloc_type(enum keyring_obj_type, const char *, int,
    size_t, const void *);
void keyring_release(struct keyring_obj *);

#endif	/* _SYS_KEYRING_H */
