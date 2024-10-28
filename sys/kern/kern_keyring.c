/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/blockcount.h>
#include <sys/kernel.h>
#include <sys/keyring.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_param.h>

static MALLOC_DEFINE(M_KEYRING, "keyring", "keyring metadata");

/* XXX Expiration, access rights */
struct keyring_obj {
	enum keyring_obj_type		 type;
	char				*desc;
	volatile u_int			 refcount;
	union {
		STAILQ_ENTRY(key)	 keys;
		struct {
			struct keyring_store	*store;
			struct keyring_payload	*payload;
		} data;
	};
};

static struct keyring_obj *
keyring_obj_alloc(enum keyring_obj_type type, const char *desc, int flags,
    size_t datasz, const void *data)
{
	struct keyring_obj *krobj;

	krobj = malloc(sizeof(*krobj), M_KEYRING, flags | M_ZERO);
	if (krobj == NULL)
		return (NULL);

	krobj->desc = strdup_flags(desc, M_KEYRING, flags & ~M_ZERO);
	if (krobj->desc == NULL)
		goto failed;

	if (datasz != 0) {
		struct keyring_store *store;

		MPASS(data != NULL);
		MPASS(type != KBLOB_KEYRING);

		/* XXX Configurable store? */
		store = &keyring_store_phys;

		krobj->data.store = store;
		krobj->data.payload = store->kstore_alloc(store, datasz, data);
		if (krobj->data.payload == NULL) {
			printf("kstore_alloc failed\n");	/* XXX */
			goto failed;
		}
	}

	krobj->type = type;
	refcount_init(&krobj->refcount, 1);
	return (krobj);

failed:
	free(krobj->desc, M_KEYRING);
	free(krobj, M_KEYRING);
	return (NULL);
}

struct keyring_obj *
keyring_alloc(const char *desc, int flags)
{

	return (keyring_obj_alloc(KBLOB_KEYRING, desc, flags, 0, NULL));
}

struct keyring_obj *
keyring_alloc_type(enum keyring_obj_type type, const char *desc, int flags,
    size_t datasz, const void *data)
{

	return (keyring_obj_alloc(type, desc, flags, datasz, data));
}

static void
keyring_free_payload(struct keyring_obj *krobj)
{

	if (krobj->data.store == NULL)
		return;

	krobj->data.store->kstore_free(krobj->data.store, krobj->data.payload);
}

void
keyring_release(struct keyring_obj *krobj)
{

	if (!refcount_release(&krobj->refcount))
		return;

	switch (krobj->type) {
	case KBLOB_KEYRING:
		/* Nothing to do here */
		break;
	case KBLOB_USER:
	default:
		/* Assume everything else may have a payload to free. */
		keyring_free_payload(krobj);
		break;
	}

	free(krobj->desc, M_KEYRING);
	free(krobj, M_KEYRING);
}
