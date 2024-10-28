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
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_param.h>

static kstore_alloc keyring_store_phys_alloc;
static kstore_free keyring_store_phys_free;

struct keyring_store keyring_store_phys = {
	.kstore_alloc = keyring_store_phys_alloc,
	.kstore_free = keyring_store_phys_free,
};

struct keyring_payload {
	vm_object_t			pobj;
	vm_size_t			ksize;
	size_t				datasz;

	/*
	 * We'll allow any kind of structured payload that consumers want to
	 * provide, so we potentially over-align it to be safe.
	 */
	_Alignas(__max_align_t) uint8_t	data[];
};

static struct keyring_payload *
keyring_store_phys_alloc(struct keyring_store *store, size_t datasz,
    const void *data)
{
	struct keyring_payload *payload;
	vm_size_t allocsz;
	vm_offset_t kva;
	vm_object_t pobj;
	size_t pages;
	int error;

	MPASS(store == &keyring_store_phys);

	/* Occupy only whole pages to be safe. */
	allocsz = roundup2(datasz + sizeof(*payload), PAGE_SIZE);
	if ((kva = kva_alloc(allocsz)) == 0)
		return (NULL);

	pobj = vm_pager_allocate(OBJT_PHYS, NULL, allocsz,
	    PROT_READ | PROT_WRITE, 0, NULL /* XXX */);
	if (pobj == NULL) {
		kva_free(kva, allocsz);
		return (NULL);
	}

	VM_OBJECT_WLOCK(pobj);
	pages = allocsz / PAGE_SIZE;
	for (size_t n = 0; n < pages; n++) {
		vm_page_t m;

		m = vm_page_grab(pobj, n, VM_ALLOC_WIRED | VM_ALLOC_NODUMP);
		vm_page_valid(m);
		vm_page_xunbusy(m);
		pmap_qenter(kva + n * PAGE_SIZE, &m, 1);
	}
	VM_OBJECT_WUNLOCK(pobj);

	printf("PAYLOAD KVA = %jx\n", kva);
	payload = (void *)(uintptr_t)kva;
	payload->pobj = pobj;
	payload->ksize = allocsz;
	payload->datasz = datasz;
	memcpy(&payload->data[0], data, datasz);

	/*
	 * Downgrade permissions; these should be read-only.  Any update of
	 * our payload must go through the proper measures to swap it out
	 * entirely.
	 */
	atomic_thread_fence_seq_cst();
	error = pmap_change_prot(kva, VM_PROT_READ, allocsz);
	MPASS(error == 0);

	return (payload);
}

static void
keyring_store_phys_free(struct keyring_store *store,
    struct keyring_payload *payload)
{
	vm_object_t pobj;
	vm_offset_t kva;
	vm_size_t ksize;
	int error;

	MPASS(store == &keyring_store_phys);

	kva = (vm_offset_t)payload;
	pobj = payload->pobj;
	ksize = payload->ksize;

	error = pmap_change_prot(kva, VM_PROT_READ | VM_PROT_WRITE, ksize);
	MPASS(error == KERN_SUCCESS);

	atomic_thread_fence_seq_cst();

	explicit_bzero(payload, ksize);
	vm_object_deallocate(pobj);
	kva_free(kva, ksize);
}
