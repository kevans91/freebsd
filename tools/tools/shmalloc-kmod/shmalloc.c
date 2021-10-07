/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Juniper Networks, Inc.
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

/*
 * A simple test kmod for enabling experimentation with boot-time-allocated SHM
 * regions.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/vmmeter.h>

#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#define	GiB				(1ULL << 30)
#define	MiB				(1ULL << 20)
#define	PAGE_SIZE_2M			(2 * MiB)
#define	PAGE_SIZE_1G			(1 * GiB)

#define	SHMALLOC_CONS_ALIGN_DEFAULT	0
#define	SHMALLOC_CONS_SIZE_DEFAULT	0
#define	SHMALLOC_MODE_DEFAULT		0600
#define	SHMALLOC_PAGESIZE_DEFAULT	PAGE_SIZE_2M
#define	SHMALLOC_PATH_DEFAULT		"/shmalloc"
#define	SHMALLOC_UNCONS_SIZE_DEFAULT	(1 * GiB)

#define	shmalloc_printf(fmt, ...)					\
    printf("shmalloc: " fmt, ## __VA_ARGS__)
#define	shmalloc_dprintf(fmt, ...)					\
    printf("shmalloc: %s:%d: " fmt, __func__, __LINE__, ## __VA_ARGS__)

struct shmalloc_default {
	long		memsize;
	u_long		cons_align;
	uint64_t	cons_size;
	uint64_t	uncons_early_size;
	uint64_t	uncons_late_size;
	u_long		pagesize;
};

static struct shmalloc_default shmalloc_defaults[] = {
	/*--------+---------------------+------------------------------------*/
	/* mem    |constrained region   |unconstrained          |page size   */
	/* size   |config               |region config          |            */
	/*        |                     |                       |            */
	/*        |align     |size      |early      |late       |            */
	/*        |          |          |size       |size       |            */
	/*--------+----------+----------+-----------+------------------------*/
	{4  * GiB, 512 * MiB, 512 * MiB, 0 *    GiB, 1.75 * GiB, PAGE_SIZE_2M},
	{8  * GiB, 1   * GiB, 2   * GiB, 0 *    GiB, 4    * GiB, PAGE_SIZE_1G},
	{16 * GiB, 1   * GiB, 4   * GiB, 0 *    GiB, 8    * GiB, PAGE_SIZE_1G},
	{32 * GiB, 1   * GiB, 8   * GiB, 0 *    GiB, 16   * GiB, PAGE_SIZE_1G},
};

static u_long		 shmalloc_cons_align = ULONG_MAX;
static uint64_t		 shmalloc_cons_size = UINT64_MAX;
static struct domainset	*shmalloc_domainset;
static bool		 shmalloc_is_alloced;
static vm_object_t	 shmalloc_memresrvobj;
static long		 shmalloc_mode = LONG_MAX;
static u_long		 shmalloc_pagesize;
static char		 shmalloc_path[MAXPATHLEN];
static struct sysctl_ctx_list shmalloc_sysctlctx;
static uint64_t		 shmalloc_uncons_early_size = UINT64_MAX;
static uint64_t		 shmalloc_uncons_late_size = UINT64_MAX;

static int		 shmalloc_create(void);
static int		 shmalloc_destroy(void);
static void		 shmalloc_init(void *arg __unused);
static void		 shmalloc_init_config(void);
static void		 shmalloc_init_mem_early(void);
static void		 shmalloc_init_mem_late(void);
static int		 shmalloc_modevent(module_t mod, int what, void *arg);

static SYSCTL_NODE(_hw, OID_AUTO, shmalloc, CTLFLAG_RD, 0, "shmalloc");
SYSCTL_ULONG(_hw_shmalloc, OID_AUTO, cons_align, CTLFLAG_RDTUN,
    &shmalloc_cons_align, 0, "shm allocation - constrained region - alignment");
SYSCTL_U64(_hw_shmalloc, OID_AUTO, cons_size, CTLFLAG_RDTUN,
    &shmalloc_cons_size, 0, "shm allocation - constrained region - size");
SYSCTL_LONG(_hw_shmalloc, OID_AUTO, mode, CTLFLAG_RDTUN, &shmalloc_mode, 0,
    "shm allocation - mode");
SYSCTL_ULONG(_hw_shmalloc, OID_AUTO, pagesize, CTLFLAG_RDTUN,
    &shmalloc_pagesize, 0, "shm allocation - page size");
SYSCTL_STRING(_hw_shmalloc, OID_AUTO, path, CTLFLAG_RDTUN, shmalloc_path,
    sizeof(shmalloc_path), "shm allocation - path");
SYSCTL_U64(_hw_shmalloc, OID_AUTO, uncons_early_size, CTLFLAG_RDTUN,
    &shmalloc_uncons_early_size, 0,
    "shm allocation - unconstrained region - early - size");
SYSCTL_U64(_hw_shmalloc, OID_AUTO, uncons_late_size, CTLFLAG_RDTUN,
    &shmalloc_uncons_late_size, 0,
    "shm allocation - unconstrained region - late - size");

static int
shmalloc_create(void)
{
	cap_rights_t rights;
	struct shm_largepage_conf conf;
	vm_pindex_t shmsize;
	struct file *fp;
	vm_page_t m;
	void *rl_cookie;
	struct shmfd *shmfd;
	vm_object_t resobj, shmobj;
	int err, fd, psind, ret;

	shmalloc_init_mem_late();

	if (shmalloc_memresrvobj == NULL)
		return (ENOMEM);

	shmsize = OFF_TO_IDX(shmalloc_cons_size) +
	    OFF_TO_IDX(shmalloc_uncons_early_size) +
	    OFF_TO_IDX(shmalloc_uncons_late_size);
	shmalloc_printf("creating shm region: mode %#4lo, pagesize %lu, path "
	    "\'%s\', size %ju (npages %ju)...\n", shmalloc_mode,
	    shmalloc_pagesize, shmalloc_path, IDX_TO_OFF(shmsize), shmsize);

	/* Create allocation: */
	/*     Create object: */
	err = shm_open2(shmalloc_path, O_RDWR | O_CREAT | O_EXCL, shmalloc_mode,
	    SHM_LARGEPAGE);
	if (err != 0) {
		shmalloc_dprintf("kern_shm_open2 failed: %d.\n", err);

		ret = err;
		goto leave_after_memresrvobj;
	}
	fd = (int)curthread->td_retval[0];
	shmalloc_is_alloced = true;

	/*
	 *     Configure object:
	 *         (Note: allow 'shm_ioctl()' to error-check the requested page
	 *         size).
	 */
	for (psind = 0; psind < MAXPAGESIZES; psind++)
		if (pagesizes[psind] == shmalloc_pagesize)
			break;
	KASSERT(psind < MAXPAGESIZES, ("shmalloc_pagesize %lu invalid",
	    shmalloc_pagesize));
	conf.psind = psind;
	conf.alloc_policy = SHM_LARGEPAGE_ALLOC_DEFAULT;
	err = kern_ioctl(curthread, fd, FIOSSHMLPGCNF, (caddr_t)&conf);
	if (err != 0) {
		shmalloc_dprintf("kern_ioctl for psind %d failed: %d.\n", psind,
		    err);

		ret = err;
		goto leave_after_shm_open;
	}

	CAP_ALL(&rights);
	err = fget(curthread, fd, &rights, &fp);
	if (err != 0) {
		shmalloc_dprintf("fget failed: %d.\n", err);

		ret = err;
		goto leave_after_shm_open;
	}
	shmfd = fp->f_data;
	shmfd->shm_object->domain.dr_policy = shmalloc_domainset;

	/*     Init object's memory with contents of 'shmalloc_memresrvobj': */
	resobj = shmalloc_memresrvobj;
	shmobj = shmfd->shm_object;

	rl_cookie = rangelock_wlock(&shmfd->shm_rl, 0, OFF_MAX,
	    &shmfd->shm_mtx);

	VM_OBJECT_WLOCK(resobj);
	VM_OBJECT_WLOCK(shmobj);

	KASSERT(resobj->resident_page_count == shmsize &&
	    shmobj->resident_page_count == 0, ("resobj and/or shmobj has wrong "
	    "npages before transfer: resobj %d (expected %ju), shmobj %d "
	    "(expected 0)", resobj->resident_page_count, shmsize,
	    shmobj->resident_page_count));
	KASSERT(shmfd->shm_size == 0, ("shmfd->shm_size is nonzero before "
	    "transfer: %ju", shmfd->shm_size));

	while ((m = vm_page_find_least(resobj, 0)) != NULL) {
		err = vm_page_rename(m, shmobj, m->pindex);
		if (err != 0) {
			shmalloc_dprintf("vmpage_rename failed at pindex %ju: "
			    "%d.\n", m->pindex, err);

			VM_OBJECT_WUNLOCK(shmobj);
			VM_OBJECT_WUNLOCK(resobj);

			rangelock_unlock(&shmfd->shm_rl, rl_cookie,
			    &shmfd->shm_mtx);

			ret = err;
			goto leave_after_fget;
		}
		resobj->size--;
		shmobj->size++;
		shmfd->shm_size += PAGE_SIZE;
		/*
		 * XXX: need to 'atomic_add_long(&count_largepages[psind], 1)'.
		 * Since this is just for stats/debug, for this PoC, just let
		 * this go for now; in a non-PoC version of this, there will
		 * probably need to be e.g. some addition to the 'shm_*()' API
		 * that accomplishes all of this within the SHM code rather than
		 * by sketchily reaching into it like this, and this API can
		 * update 'count_largepages'.
		 */
	}

	KASSERT(resobj->resident_page_count == 0 &&
	    shmobj->resident_page_count == shmsize, ("resobj and/or shmobj has "
	    "wrong npages after transfer: resobj %d (expected 0), shmobj %d "
	    "(expected %ju)", resobj->resident_page_count,
	    shmobj->resident_page_count, shmsize));
	KASSERT(shmfd->shm_size == IDX_TO_OFF(shmsize), ("shmfd->shm_size has "
	    "wrong value after transfer: %ju (expected %ju)", shmfd->shm_size,
	    IDX_TO_OFF(shmsize)));

	VM_OBJECT_WUNLOCK(shmobj);
	VM_OBJECT_WUNLOCK(resobj);

	rangelock_unlock(&shmfd->shm_rl, rl_cookie,
	    &shmfd->shm_mtx);

	ret = 0;

leave_after_fget:
	(void)fdrop(fp, curthread);

leave_after_shm_open:
	/*     Clean up the shm fd: */
	err = kern_close(curthread, fd);
	if (err != 0)
		shmalloc_dprintf("kern_close failed: %d.\n", err);

	if (ret != 0) {
		err = shmalloc_destroy();
		if (err != 0)
			shmalloc_dprintf("shmalloc_destroy failed: %d.\n", err);
	}

leave_after_memresrvobj:
	/*     Clean up 'shmalloc_memresrvobj': */
	vm_object_deallocate(shmalloc_memresrvobj);
	shmalloc_memresrvobj = NULL;

	return (ret);
}

static int
shmalloc_destroy(void)
{
	int err, ret;

	if (shmalloc_is_alloced) {
		shmalloc_printf("unlinking shm region \'%s\'...\n",
		    shmalloc_path);
		ret = shm_unlink(shmalloc_path);
		shmalloc_is_alloced = false;
	} else
		ret = 0;

	err = sysctl_ctx_free(&shmalloc_sysctlctx);
	if (err != 0)
		shmalloc_dprintf("sysctl_ctx_free failed: %d.\n", err);
	(void)sysctl_ctx_init(&shmalloc_sysctlctx);

	return (ret);
}

static void
shmalloc_init(void *arg __unused)
{
	shmalloc_init_config();
	shmalloc_init_mem_early();
}

static void
shmalloc_init_config(void)
{
	int i;

	if (shmalloc_cons_align == ULONG_MAX) {
		/* First, attempt to satisfy from shmalloc_defaults: */
		for (i = 0; i < nitems(shmalloc_defaults); i++)
			if (realmem << PAGE_SHIFT ==
			    shmalloc_defaults[i].memsize) {
				shmalloc_cons_align =
				    shmalloc_defaults[i].cons_align;
				break;
			}

		if (shmalloc_cons_align == ULONG_MAX)
			shmalloc_cons_align = SHMALLOC_CONS_SIZE_DEFAULT;
	}

	if (shmalloc_cons_size == UINT64_MAX) {
		/* First, attempt to satisfy from shmalloc_defaults: */
		for (i = 0; i < nitems(shmalloc_defaults); i++)
			if (realmem << PAGE_SHIFT ==
			    shmalloc_defaults[i].memsize) {
				shmalloc_cons_size =
				    shmalloc_defaults[i].cons_size;
				break;
			}

		if (shmalloc_cons_size == UINT64_MAX)
			shmalloc_cons_size = SHMALLOC_CONS_SIZE_DEFAULT;
	}

	(void)sysctl_ctx_init(&shmalloc_sysctlctx);
	(void)SYSCTL_ADD_PROC(&shmalloc_sysctlctx,
	    SYSCTL_STATIC_CHILDREN(_hw_shmalloc), OID_AUTO, "domainset",
	    CTLTYPE_STRING | CTLFLAG_MPSAFE | CTLFLAG_RDTUN,
	    &shmalloc_domainset, 0, sysctl_handle_domainset, "A",
	    "shm allocation NUMA policy");

	if (shmalloc_mode == LONG_MAX || (shmalloc_mode & ~0x1ff) != 0)
		shmalloc_mode = SHMALLOC_MODE_DEFAULT;

	if (shmalloc_pagesize == 0) {
		/* First, attempt to satisfy from shmalloc_defaults: */
		for (i = 0; i < nitems(shmalloc_defaults); i++)
			if (realmem << PAGE_SHIFT ==
			    shmalloc_defaults[i].memsize) {
				shmalloc_pagesize =
				    shmalloc_defaults[i].pagesize;
				break;
			}

		if (shmalloc_pagesize == 0)
			shmalloc_pagesize = SHMALLOC_PAGESIZE_DEFAULT;
	}

	if (shmalloc_path[0] == '\0')
		(void)strcpy(shmalloc_path, SHMALLOC_PATH_DEFAULT);

	if (shmalloc_uncons_early_size == UINT64_MAX) {
		/* First, attempt to satisfy from shmalloc_defaults: */
		for (i = 0; i < nitems(shmalloc_defaults); i++)
			if (realmem << PAGE_SHIFT ==
			    shmalloc_defaults[i].memsize) {
				shmalloc_uncons_early_size =
				    shmalloc_defaults[i].uncons_early_size;
				break;
			}

		if (shmalloc_uncons_early_size == UINT64_MAX)
			shmalloc_uncons_early_size = SHMALLOC_CONS_SIZE_DEFAULT;
	}

	if (shmalloc_uncons_late_size == UINT64_MAX) {
		/* First, attempt to satisfy from shmalloc_defaults: */
		for (i = 0; i < nitems(shmalloc_defaults); i++)
			if (realmem << PAGE_SHIFT ==
			    shmalloc_defaults[i].memsize) {
				shmalloc_uncons_late_size =
				    shmalloc_defaults[i].uncons_late_size;
				break;
			}

		if (shmalloc_uncons_late_size == UINT64_MAX)
			shmalloc_uncons_late_size = SHMALLOC_CONS_SIZE_DEFAULT;
	}
}

static void
shmalloc_init_mem_early(void)
{
	vm_object_t obj;
	vm_page_t m;
	vm_pindex_t finalsize;
	int aflags, i;

	shmalloc_printf("reserving memory: cons_align %lu, cons_size %ju, "
	    "uncons_early_size %ju, uncons_late_size %ju, pagesize %lu...\n",
	    shmalloc_cons_align, shmalloc_cons_size,
	    shmalloc_uncons_early_size, shmalloc_uncons_late_size,
	    shmalloc_pagesize);

	if (shmalloc_pagesize != PAGE_SIZE_2M && shmalloc_pagesize !=
	    PAGE_SIZE_1G) {
		shmalloc_dprintf("invalid largepage size %lu\n",
		    shmalloc_pagesize);
		return;
	}
	if (shmalloc_cons_size % shmalloc_pagesize != 0) {
		shmalloc_dprintf("cons_size %ju is not multiple of page size "
		    "%lu\n", shmalloc_cons_size, shmalloc_pagesize);
		return;
	}
	if (shmalloc_cons_align % shmalloc_pagesize != 0) {
		shmalloc_dprintf("cons_align %lu is not multiple of page size "
		    "%lu\n", shmalloc_cons_align, shmalloc_pagesize);
		return;
	}
	if (shmalloc_uncons_early_size % shmalloc_pagesize != 0) {
		shmalloc_dprintf("uncons_early_size %ju is not multiple of "
		    "page size %lu\n", shmalloc_uncons_early_size,
		    shmalloc_pagesize);
		return;
	}
	if (shmalloc_uncons_late_size % shmalloc_pagesize != 0) {
		shmalloc_dprintf("uncons_late_size %ju is not multiple of "
		    "page size %lu\n", shmalloc_uncons_late_size,
		    shmalloc_pagesize);
		return;
	}

	obj = vm_pager_allocate(OBJT_PHYS, NULL, 0, VM_PROT_DEFAULT, 0,
	    curthread->td_ucred);
	if (obj == NULL) {
		shmalloc_dprintf("vm_pager_allocate failed.\n");
		return;
	}

	aflags = VM_ALLOC_NORMAL | VM_ALLOC_ZERO | VM_ALLOC_NOWAIT;

	obj->pg_color = 0;
	obj->domain.dr_policy = shmalloc_domainset;

	VM_OBJECT_WLOCK(obj);
	vm_object_clear_flag(obj, OBJ_ONEMAPPING);
	vm_object_set_flag(obj, OBJ_COLORED | OBJ_NOSPLIT);

	/* Allocate constrained region, if applicable: */
	if (shmalloc_cons_size != 0) {
		m = vm_page_alloc_contig(obj, 0, aflags, shmalloc_cons_size /
		    PAGE_SIZE, 0, ~0, shmalloc_cons_align, 0,
		    VM_MEMATTR_DEFAULT);
		if (m == NULL) {
			shmalloc_dprintf("vm_page_alloc_contig failed for "
			    "constrained region allocation.\n");

			goto fail_after_obj_alloc;
		}
	}
	for (i = 0; i < shmalloc_cons_size / PAGE_SIZE; i++) {
		if ((m[i].flags & PG_ZERO) == 0)
			pmap_zero_page(&m[i]);
		m[i].valid = VM_PAGE_BITS_ALL;
		vm_page_xunbusy(&m[i]);
	}
	obj->size += OFF_TO_IDX(shmalloc_cons_size);
	vm_wire_add(atop(shmalloc_cons_size));

	/* Allocate early unconstrained region, if applicable: */
	finalsize = OFF_TO_IDX(shmalloc_cons_size) +
	    OFF_TO_IDX(shmalloc_uncons_early_size);
	while (obj->size < finalsize) {
		m = vm_page_alloc_contig(obj, obj->size, aflags,
		    shmalloc_pagesize / PAGE_SIZE, 0, ~0, shmalloc_pagesize, 0,
		    VM_MEMATTR_DEFAULT);
		if (m == NULL) {
			shmalloc_dprintf("vm_page_alloc_contig failed for "
			    "unconstrained early region allocation: pindex "
			    "%ju of %ju\n", obj->size, finalsize);

			goto fail_after_obj_alloc;
		}
		for (i = 0; i < shmalloc_pagesize / PAGE_SIZE; i++) {
			if ((m[i].flags & PG_ZERO) == 0)
				pmap_zero_page(&m[i]);
			m[i].valid = VM_PAGE_BITS_ALL;
			vm_page_xunbusy(&m[i]);
		}
		obj->size += OFF_TO_IDX(shmalloc_pagesize);
		vm_wire_add(atop(shmalloc_pagesize));
	}

	VM_OBJECT_WUNLOCK(obj);

	shmalloc_memresrvobj = obj;

	return;

fail_after_obj_alloc:
	vm_wire_sub(obj->size);
	VM_OBJECT_WUNLOCK(obj);
	vm_object_deallocate(obj);

	shmalloc_printf("failed to reserve cons and/or uncons_early memory "
	    "meeting specified criteria. SHM region will not be created.\n");
}

static void
shmalloc_init_mem_late(void)
{
	vm_object_t obj;
	vm_page_t m;
	vm_pindex_t finalsize;
	int aflags, i;

	obj = shmalloc_memresrvobj;
	if (obj == NULL)
		return;

	aflags = VM_ALLOC_NORMAL | VM_ALLOC_ZERO | VM_ALLOC_NOWAIT;

	VM_OBJECT_WLOCK(obj);

	/* Allocate late unconstrained region, if applicable: */
	KASSERT(obj->size == OFF_TO_IDX(shmalloc_cons_size) +
	    OFF_TO_IDX(shmalloc_uncons_early_size),
	    ("resobj size %ju not cons %ju + cons_early %ju", obj->size,
		OFF_TO_IDX(shmalloc_uncons_early_size),
		OFF_TO_IDX(shmalloc_uncons_late_size)));
	finalsize = OFF_TO_IDX(shmalloc_cons_size) +
	    OFF_TO_IDX(shmalloc_uncons_early_size) +
	    OFF_TO_IDX(shmalloc_uncons_late_size);
	while (obj->size < finalsize) {
		m = vm_page_alloc_contig(obj, obj->size, aflags,
		    shmalloc_pagesize / PAGE_SIZE, 0, ~0, shmalloc_pagesize, 0,
		    VM_MEMATTR_DEFAULT);
		if (m == NULL) {
			shmalloc_dprintf("vm_page_alloc_contig failed for "
			    "unconstrained late region allocation: pindex %ju "
			    "of %ju\n", obj->size, finalsize);
			shmalloc_printf("failed to reserve uncons_late memory "
			    "meeting specified criteria. SHM region will not "
			    "be created.\n");

			shmalloc_memresrvobj = NULL;
			vm_wire_sub(obj->size);
			VM_OBJECT_WUNLOCK(obj);
			vm_object_deallocate(obj);
			return;
		}
		for (i = 0; i < shmalloc_pagesize / PAGE_SIZE; i++) {
			if ((m[i].flags & PG_ZERO) == 0)
				pmap_zero_page(&m[i]);
			m[i].valid = VM_PAGE_BITS_ALL;
			vm_page_xunbusy(&m[i]);
		}
		obj->size += OFF_TO_IDX(shmalloc_pagesize);
		vm_wire_add(atop(shmalloc_pagesize));
	}

	VM_OBJECT_WUNLOCK(obj);
}

static int
shmalloc_modevent(module_t mod, int what, void *arg)
{
	int ret;

	switch (what) {
	case MOD_LOAD:
		ret = shmalloc_create();
		break;
	case MOD_UNLOAD:
		ret = shmalloc_destroy();
		break;
	default:
		ret = EOPNOTSUPP;
		break;
	}

	return (ret);
}

SYSINIT(shmalloc_init, SI_SUB_DRIVERS - 1, SI_ORDER_ANY, shmalloc_init, NULL);

static moduledata_t	shmalloc_mod = {
	"shmalloc",
	shmalloc_modevent,
	NULL
};

DECLARE_MODULE(shmalloc, shmalloc_mod, SI_SUB_SYSV_SHM + 1, SI_ORDER_FIRST);
MODULE_VERSION(shmalloc, 1);
