/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/queue.h>
#include <sys/smp.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/radix.h>
#include <net/bpf.h>
#include <net/mp_ring.h>

#include "wg_noise.h"
#include "crypto.h"
#include "if_wg.h"

static void wg_init(void *xsc);
static int wg_ioctl(struct ifnet *, u_long, caddr_t);
static int wg_transmit(struct ifnet *ifp, struct mbuf *m);
static void wg_qflush(struct ifnet *ifp);
static int wg_output(struct ifnet *ifp, struct mbuf *m,
    const struct sockaddr *sa, struct route *rt);

static int wg_up(struct wg_softc *sc);
static void wg_down(struct wg_softc *sc);

MALLOC_DEFINE(M_WG, "WG", "wireguard");

static const char wgname[] = "wg";

VNET_DEFINE_STATIC(struct if_clone *, wg_cloner);
#define	V_wg_cloner	VNET(wg_cloner)

#define	WG_CAPS		IFCAP_LINKSTATE | IFCAP_HWCSUM | IFCAP_HWCSUM_IPV6
#define	ph_family	PH_loc.eight[5]

/* TODO this is dumped in here from wg_module.h, so we can consolidate files.
 * It will need cleaning up. */
#define	MAX_PEERS_PER_IFACE	(1U << 20)

#define zfree(addr, type)						\
	do {										\
		explicit_bzero(addr, sizeof(*addr));	\
		free(addr, type);						\
	} while (0)

struct crypt_queue {
	union {
		struct {
			int last_cpu;
		};
	};
};

#define __ATOMIC_LOAD_SIZE						\
	({									\
	switch (size) {							\
	case 1: *(uint8_t *)res = *(volatile uint8_t *)p; break;		\
	case 2: *(uint16_t *)res = *(volatile uint16_t *)p; break;		\
	case 4: *(uint32_t *)res = *(volatile uint32_t *)p; break;		\
	case 8: *(uint64_t *)res = *(volatile uint64_t *)p; break;		\
	}								\
})

static inline void
__atomic_load_acq_size(volatile void *p, void *res, int size)
{
	__ATOMIC_LOAD_SIZE;
}

#define atomic_load_acq(x)						\
	({											\
	union { __typeof(x) __val; char __c[1]; } __u;			\
	__atomic_load_acq_size(&(x), __u.__c, sizeof(x));		\
	__u.__val;												\
})


int wg_ctx_init(void);
void wg_ctx_uninit(void);
/* end TODO */



TASKQGROUP_DECLARE(if_io_tqg);

struct wg_timespec64 {
	uint64_t	tv_sec;
	uint64_t	tv_nsec;
};

struct wg_peer_export {
	struct sockaddr_storage		endpoint;
	struct timespec			last_handshake;
	uint8_t				public_key[WG_KEY_SIZE];
	size_t				endpoint_sz;
	struct wg_allowedip		*aip;
	uint64_t			rx_bytes;
	uint64_t			tx_bytes;
	int				aip_count;
	uint16_t			persistent_keepalive;
};

static int clone_count;
uma_zone_t ratelimit_zone;

void
wg_encrypt_dispatch(struct wg_softc *sc)
{
	for (int i = 0; i < mp_ncpus; i++) {
		if (sc->sc_encrypt[i].gt_task.ta_flags & TASK_ENQUEUED)
			continue;
		GROUPTASK_ENQUEUE(&sc->sc_encrypt[i]);
	}
}

void
wg_decrypt_dispatch(struct wg_softc *sc)
{
	for (int i = 0; i < mp_ncpus; i++) {
		if (sc->sc_decrypt[i].gt_task.ta_flags & TASK_ENQUEUED)
			continue;
		GROUPTASK_ENQUEUE(&sc->sc_decrypt[i]);
	}
}

static void
crypto_taskq_setup(struct wg_softc *sc)
{

	sc->sc_encrypt = malloc(sizeof(struct grouptask)*mp_ncpus, M_WG, M_WAITOK);
	sc->sc_decrypt = malloc(sizeof(struct grouptask)*mp_ncpus, M_WG, M_WAITOK);

	for (int i = 0; i < mp_ncpus; i++) {
		GROUPTASK_INIT(&sc->sc_encrypt[i], 0,
		     (gtask_fn_t *)wg_softc_encrypt, sc);
		taskqgroup_attach_cpu(qgroup_if_io_tqg, &sc->sc_encrypt[i], sc, i, NULL, NULL, "wg encrypt");
		GROUPTASK_INIT(&sc->sc_decrypt[i], 0,
		    (gtask_fn_t *)wg_softc_decrypt, sc);
		taskqgroup_attach_cpu(qgroup_if_io_tqg, &sc->sc_decrypt[i], sc, i, NULL, NULL, "wg decrypt");
	}
}

static void
crypto_taskq_destroy(struct wg_softc *sc)
{
	for (int i = 0; i < mp_ncpus; i++) {
		taskqgroup_detach(qgroup_if_io_tqg, &sc->sc_encrypt[i]);
		taskqgroup_detach(qgroup_if_io_tqg, &sc->sc_decrypt[i]);
	}
	free(sc->sc_encrypt, M_WG);
	free(sc->sc_decrypt, M_WG);
}

static int
wg_clone_create(struct if_clone *ifc, int unit, caddr_t params)
{
	struct wg_softc *sc;
	struct iovec iov;
	struct ifnet *ifp;
	nvlist_t *nvl;
	void *packed;
	struct noise_local *local;
	uint8_t			 public[WG_KEY_SIZE];
	struct noise_upcall	 noise_upcall;
	int err;
	uint16_t listen_port;
	const void *key;
	size_t size;

	err = 0;
	packed = NULL;
	sc = malloc(sizeof(*sc), M_WG, M_WAITOK | M_ZERO);
	ifp = sc->sc_ifp = if_alloc(IFT_PPP);
	ifp->if_softc = sc;
	if_initname(ifp, wgname, unit);

	if (params == NULL) {
		key = NULL;
		listen_port = 0;
		nvl = NULL;
		packed = NULL;
		goto unpacked;
	}

	if (copyin(params, &iov, sizeof(iov))) {
		err = EFAULT;
		goto out;
	}

	/* check that this is reasonable */
	size = iov.iov_len;
	packed = malloc(size, M_TEMP, M_WAITOK);
	if (copyin(iov.iov_base, packed, size)) {
		err = EFAULT;
		goto out;
	}
	nvl = nvlist_unpack(packed, size, 0);
	if (nvl == NULL) {
		if_printf(ifp, "%s nvlist_unpack failed\n", __func__);
		err = EBADMSG;
		goto out;
	}

	/* wg_socket_bind() will update with the chosen port if omitted. */
	listen_port = 0;
	if (nvlist_exists_number(nvl, "listen-port"))
		listen_port = nvlist_get_number(nvl, "listen-port");
	if (!nvlist_exists_binary(nvl, "private-key")) {
		if_printf(ifp, "%s private-key not set\n", __func__);
		err = EBADMSG;
		goto nvl_out;
	}
	key = nvlist_get_binary(nvl, "private-key", &size);
	if (size != CURVE25519_KEY_SIZE) {
		if_printf(ifp, "%s bad length for private-key %zu\n", __func__, size);
		err = EBADMSG;
		goto nvl_out;
	}
unpacked:
	local = &sc->sc_local;
	noise_upcall.u_arg = sc;
	noise_upcall.u_remote_get =
		(struct noise_remote *(*)(void *, uint8_t *))wg_remote_get;
	noise_upcall.u_index_set =
		(uint32_t (*)(void *, struct noise_remote *))wg_index_set;
	noise_upcall.u_index_drop =
		(void (*)(void *, uint32_t))wg_index_drop;
	noise_local_init(local, &noise_upcall);
	cookie_checker_init(&sc->sc_cookie, ratelimit_zone);

	sc->sc_socket.so_port = listen_port;

	if (key != NULL) {
		/* TODO this is temp code, should not be released */
		if (!curve25519_generate_public(public, key)) {
			err = EBADMSG;
			goto nvl_out;
		}
		noise_local_lock_identity(local);
		noise_local_set_private(local, key);
		cookie_checker_update(&sc->sc_cookie, public);
		noise_local_unlock_identity(local);
	}
	atomic_add_int(&clone_count, 1);
	ifp->if_capabilities = ifp->if_capenable = WG_CAPS;
	ifp->if_hwassist = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;

	mbufq_init(&sc->sc_handshake_queue, MAX_QUEUED_INCOMING_HANDSHAKES);
	mtx_init(&sc->sc_mtx, NULL, "wg softc lock",  MTX_DEF);
	rw_init(&sc->sc_index_lock, "wg index lock");
	refcount_init(&sc->sc_peer_count, 0);
	sc->sc_encap_ring = buf_ring_alloc(MAX_QUEUED_PACKETS, M_WG, M_WAITOK, &sc->sc_mtx);
	sc->sc_decap_ring = buf_ring_alloc(MAX_QUEUED_PACKETS, M_WG, M_WAITOK, &sc->sc_mtx);
	GROUPTASK_INIT(&sc->sc_handshake, 0,
	    (gtask_fn_t *)wg_softc_handshake_receive, sc);
	taskqgroup_attach(qgroup_if_io_tqg, &sc->sc_handshake, sc, NULL, NULL, "wg tx initiation");
	crypto_taskq_setup(sc);

	wg_hashtable_init(&sc->sc_hashtable);
	sc->sc_index = hashinit(HASHTABLE_INDEX_SIZE, M_DEVBUF, &sc->sc_index_mask);
	wg_route_init(&sc->sc_routes);

	if_setmtu(ifp, ETHERMTU - 80);
	ifp->if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_NOARP;
	ifp->if_init = wg_init;
	ifp->if_qflush = wg_qflush;
	ifp->if_transmit = wg_transmit;
	ifp->if_output = wg_output;
	ifp->if_ioctl = wg_ioctl;

	if_attach(ifp);
	bpfattach(ifp, DLT_NULL, sizeof(uint32_t));
nvl_out:
	if (nvl != NULL)
		nvlist_destroy(nvl);
out:
	free(packed, M_TEMP);
	if (err != 0) {
		if_free(ifp);
		free(sc, M_WG);
	}
	return (err);
}

static void
wg_qflush(struct ifnet *ifp __unused)
{


}


static int
wg_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct wg_softc *sc;
	sa_family_t family;
	struct epoch_tracker et;
	struct wg_peer *peer;
	struct wg_tag *t;
	uint32_t af;
	int rc;

	/*
	 * Work around lifetime issue in the ipv6 mld code.
	 */
	if (__predict_false(ifp->if_flags & IFF_DYING))
		return (ENXIO);

	rc = 0;
	sc = ifp->if_softc;
	if ((t = wg_tag_get(m)) == NULL) {
		rc = ENOBUFS;
		goto early_out;
	}
	af = m->m_pkthdr.ph_family;
	BPF_MTAP2(ifp, &af, sizeof(af), m);

	NET_EPOCH_ENTER(et);
	peer = wg_route_lookup(&sc->sc_routes, m, OUT);
	if (__predict_false(peer == NULL)) {
		rc = ENOKEY;
		/* XXX log */
		goto err;
	}

	family = atomic_load_acq(peer->p_endpoint.e_remote.r_sa.sa_family);
	if (__predict_false(family != AF_INET && family != AF_INET6)) {
		rc = EHOSTUNREACH;
		/* XXX log */
		goto err;
	}
	t->t_peer = peer;
	t->t_mbuf = NULL;
	t->t_done = 0;
	t->t_mtu = ifp->if_mtu;

	rc = wg_queue_out(peer, m);
	if (rc == 0)
		wg_encrypt_dispatch(peer->p_sc);
	NET_EPOCH_EXIT(et);
	return (rc); 
err:
	NET_EPOCH_EXIT(et);
early_out:
	if_inc_counter(sc->sc_ifp, IFCOUNTER_OERRORS, 1);
	/* XXX send ICMP unreachable */
	m_free(m);
	return (rc);
}

static int
wg_output(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *sa, struct route *rt)
{
	m->m_pkthdr.ph_family =  sa->sa_family;
	return (wg_transmit(ifp, m));
}

static void
wg_clone_destroy(struct ifnet *ifp)
{
	struct wg_softc *sc = ifp->if_softc;

	if_link_state_change(sc->sc_ifp, LINK_STATE_DOWN);
	wg_socket_reinit(sc, NULL, NULL);

	/*
	 * No guarantees that all traffic have passed until the epoch has
	 * elapsed with the socket closed.
	 */
	NET_EPOCH_WAIT();

	taskqgroup_drain_all(qgroup_if_io_tqg);
	pause("link_down", hz/4);
	wg_peer_remove_all(sc, true);
	mtx_destroy(&sc->sc_mtx);
	rw_destroy(&sc->sc_index_lock);
	taskqgroup_detach(qgroup_if_io_tqg, &sc->sc_handshake);
	crypto_taskq_destroy(sc);
	buf_ring_free(sc->sc_encap_ring, M_WG);
	buf_ring_free(sc->sc_decap_ring, M_WG);

	wg_route_destroy(&sc->sc_routes);
	wg_hashtable_destroy(&sc->sc_hashtable);

	ether_ifdetach(sc->sc_ifp);
	if_free(sc->sc_ifp);
	free(sc, M_WG);

	atomic_add_int(&clone_count, -1);
}

static int
wg_peer_to_export(struct wg_peer *peer, struct wg_peer_export *exp)
{
	struct wg_endpoint *ep;
	struct wg_route *rt;
	int i;

	/* Non-sleepable context. */
	NET_EPOCH_ASSERT();

	bzero(&exp->endpoint, sizeof(exp->endpoint));
	ep = &peer->p_endpoint;
	if (ep->e_remote.r_sa.sa_family != 0) {
		exp->endpoint_sz = (ep->e_remote.r_sa.sa_family == AF_INET) ?
		    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

		memcpy(&exp->endpoint, &ep->e_remote, exp->endpoint_sz);
	}

	memcpy(exp->public_key, peer->p_remote.r_public,
	    sizeof(exp->public_key));

	exp->persistent_keepalive =
	    peer->p_timers.t_persistent_keepalive_interval;
	wg_timers_get_last_handshake(&peer->p_timers, &exp->last_handshake);
	exp->rx_bytes = counter_u64_fetch(peer->p_rx_bytes);
	exp->tx_bytes = counter_u64_fetch(peer->p_tx_bytes);

	exp->aip_count = 0;
	CK_LIST_FOREACH(rt, &peer->p_routes, r_entry) {
		exp->aip_count++;
	}

	/* Early success; no allowed-ips to copy out. */
	if (exp->aip_count == 0)
		return (0);

	exp->aip = malloc(exp->aip_count * sizeof(*exp->aip), M_TEMP, M_NOWAIT);
	if (exp->aip == NULL)
		return (ENOMEM);

	i = 0;
	CK_LIST_FOREACH(rt, &peer->p_routes, r_entry) {
		memcpy(&exp->aip[i++], &rt->r_cidr, sizeof(*exp->aip));
		if (i == exp->aip_count)
			break;
	}

	/* Again, AllowedIPs might have shrank; update it. */
	exp->aip_count = i;

	return (0);
}

static nvlist_t *
wg_peer_export_to_nvl(struct wg_peer_export *exp)
{
	struct wg_timespec64 ts64;
	nvlist_t *nvl;

	if ((nvl = nvlist_create(0)) == NULL)
		return (NULL);

	nvlist_add_binary(nvl, "public-key", exp->public_key, WG_KEY_SIZE);
	if (exp->endpoint_sz != 0)
		nvlist_add_binary(nvl, "endpoint", &exp->endpoint,
		    exp->endpoint_sz);

	nvlist_add_binary(nvl, "allowed-ips", exp->aip,
	    exp->aip_count * sizeof(*exp->aip));

	ts64.tv_sec = exp->last_handshake.tv_sec;
	ts64.tv_nsec = exp->last_handshake.tv_nsec;
	nvlist_add_binary(nvl, "last-handshake-time", &ts64, sizeof(ts64));

	if (exp->persistent_keepalive != 0)
		nvlist_add_number(nvl, "persistent-keepalive-interval",
		    exp->persistent_keepalive);

	if (exp->rx_bytes != 0)
		nvlist_add_number(nvl, "rx-bytes", exp->rx_bytes);
	if (exp->tx_bytes != 0)
		nvlist_add_number(nvl, "tx-bytes", exp->tx_bytes);

	return (nvl);
}

static int
wg_marshal_peers(struct wg_softc *sc, nvlist_t **nvlp, nvlist_t ***nvl_arrayp, int *peer_countp)
{
	struct wg_peer *peer;
	int err, i, peer_count;
	nvlist_t *nvl, **nvl_array;
	struct epoch_tracker et;
	struct wg_peer_export *wpe;

	nvl = NULL;
	nvl_array = NULL;
	if (nvl_arrayp)
		*nvl_arrayp = NULL;
	if (nvlp)
		*nvlp = NULL;
	if (peer_countp)
		*peer_countp = 0;
	peer_count = sc->sc_hashtable.h_num_peers;
	if (peer_count == 0) {
		printf("no peers found\n");
		return (ENOENT);
	}

	if (nvlp && (nvl = nvlist_create(0)) == NULL)
		return (ENOMEM);

	err = i = 0;
	nvl_array = malloc(peer_count*sizeof(void*), M_TEMP, M_WAITOK);
	wpe = malloc(peer_count*sizeof(*wpe), M_TEMP, M_WAITOK | M_ZERO);

	NET_EPOCH_ENTER(et);
	CK_LIST_FOREACH(peer, &sc->sc_hashtable.h_peers_list, p_entry) {
		if ((err = wg_peer_to_export(peer, &wpe[i])) != 0) {
			printf("wg_peer_to_export failed on %d peer, error %d\n",
			    i, err);
			break;
		}

		i++;
		if (i == peer_count)
			break;
	}
	NET_EPOCH_EXIT(et);

	if (err != 0)
		goto out;

	/* Update the peer count, in case we found fewer entries. */
	*peer_countp = peer_count = i;
	if (peer_count == 0) {
		printf("no peers found in list\n");
		err = ENOENT;
		goto out;
	}

	for (i = 0; i < peer_count; i++) {
		nvl_array[i] = wg_peer_export_to_nvl(&wpe[i]);
		if (nvl_array[i] == NULL) {
			printf("wg_peer_export_to_nvl failed on %d peer\n", i);
			break;
		}
	}

	if (nvl) {
		nvlist_add_nvlist_array(nvl, "peers",
		    (const nvlist_t * const *)nvl_array, peer_count);
		if ((err = nvlist_error(nvl))) {
			printf("nvlist_add_nvlist_array(%p, \"peers\", %p, %d) => %d\n",
			    nvl, nvl_array, peer_count, err);
			goto out;
		}
		*nvlp = nvl;
	}
	*nvl_arrayp = nvl_array;
	err = 0;
 out:
	if (err != 0) {
		for (i = 0; i < peer_count; i++) {
			nvlist_destroy(nvl_array[i]);
		}

		free(nvl_array, M_TEMP);
		if (nvl != NULL)
			nvlist_destroy(nvl);
	}

	for (i = 0; i < peer_count; i++)
		free(wpe[i].aip, M_TEMP);
	free(wpe, M_TEMP);
	return (err);
}

static int
wgc_get(struct wg_softc *sc, struct wg_data_io *wgd)
{
	nvlist_t *nvl, **nvl_array;
	void *packed;
	size_t size;
	int peer_count, err;

	nvl = nvlist_create(0);
	if (nvl == NULL)
		return (ENOMEM);

	err = 0;
	packed = NULL;
	if (sc->sc_socket.so_port != 0)
		nvlist_add_number(nvl, "listen-port", sc->sc_socket.so_port);
	if (sc->sc_local.l_has_identity) {
		nvlist_add_binary(nvl, "public-key", sc->sc_local.l_public, WG_KEY_SIZE);
		if (curthread->td_ucred->cr_uid == 0)
			nvlist_add_binary(nvl, "private-key", sc->sc_local.l_private, WG_KEY_SIZE);
	}
	if (sc->sc_hashtable.h_num_peers > 0) {
		err = wg_marshal_peers(sc, NULL, &nvl_array, &peer_count);
		if (err)
			goto out;
		nvlist_add_nvlist_array(nvl, "peers",
		    (const nvlist_t * const *)nvl_array, peer_count);
	}
	packed = nvlist_pack(nvl, &size);
	if (packed == NULL)
		return (ENOMEM);
	if (wgd->wgd_size == 0) {
		wgd->wgd_size = size;
		goto out;
	}
	if (wgd->wgd_size < size) {
		err = ENOSPC;
		goto out;
	}
	if (wgd->wgd_data == NULL) {
		err = EFAULT;
		goto out;
	}
	err = copyout(packed, wgd->wgd_data, size);
	wgd->wgd_size = size;
 out:
	nvlist_destroy(nvl);
	free(packed, M_NVLIST);
	return (err);
}

static bool
wg_allowedip_valid(const struct wg_allowedip *wip)
{

	return (true);
}

static int
wg_peer_add(struct wg_softc *sc, const nvlist_t *nvl)
{
	uint8_t			 public[WG_KEY_SIZE];
	const void *pub_key;
	struct ifnet *ifp;
	const struct sockaddr *endpoint;
	int err;
	size_t size;
	struct wg_peer *peer = NULL;
	bool need_insert = false;

	ifp = sc->sc_ifp;
	if (!nvlist_exists_binary(nvl, "public-key")) {
		if_printf(ifp, "peer has no public-key\n");
		return (EINVAL);
	}
	pub_key = nvlist_get_binary(nvl, "public-key", &size);
	if (size != CURVE25519_KEY_SIZE) {
		if_printf(ifp, "%s bad length for public-key %zu\n", __func__, size);
		return (EINVAL);
	}
	if (noise_local_keys(&sc->sc_local, public, NULL) == 0 &&
	    bcmp(public, pub_key, WG_KEY_SIZE) == 0) {
		if_printf(ifp, "public-key for peer already in use by host\n");
		return (EINVAL);
	}
	peer = wg_peer_lookup(sc, pub_key);
	if (nvlist_exists_bool(nvl, "remove") &&
		nvlist_get_bool(nvl, "remove")) {
		if (peer != NULL) {
			wg_hashtable_peer_remove(&sc->sc_hashtable, peer);
			wg_peer_destroy(peer);
			/* XXX free */
			printf("peer removed\n");
		}
		return (0);
	}
	if (nvlist_exists_bool(nvl, "replace-allowedips") &&
		nvlist_get_bool(nvl, "replace-allowedips") &&
	    peer != NULL) {

		wg_route_delete(&peer->p_sc->sc_routes, peer);
	}
	if (peer == NULL) {
		/*
		 * Serialize peer additions for a brief moment to do peer
		 * accounting.  Note that we don't bother locking on peer
		 * removal, and a peer isn't discounted until deferred-release.
		 */
		mtx_lock(&sc->sc_mtx);
		if (refcount_load(&sc->sc_peer_count) >= MAX_PEERS_PER_IFACE)
			return (E2BIG);
		refcount_acquire(&sc->sc_peer_count);
		mtx_unlock(&sc->sc_mtx);

		need_insert = true;
		peer = wg_peer_alloc(sc);
		MPASS(peer != NULL);
		noise_remote_init(&peer->p_remote, pub_key, &sc->sc_local);
		cookie_maker_init(&peer->p_cookie, pub_key);
	}
	if (nvlist_exists_binary(nvl, "endpoint")) {
		endpoint = nvlist_get_binary(nvl, "endpoint", &size);
		if (size > sizeof(peer->p_endpoint.e_remote)) {
			if_printf(ifp, "%s bad length for endpoint %zu\n", __func__, size);
			err = EBADMSG;
			goto out;
		}
		memcpy(&peer->p_endpoint.e_remote, endpoint, size);
	}
	if (nvlist_exists_binary(nvl, "preshared-key")) {
		const void *key;

		key = nvlist_get_binary(nvl, "preshared-key", &size);
		noise_remote_set_psk(&peer->p_remote, key);
	}
	if (nvlist_exists_number(nvl, "persistent-keepalive-interval")) {
		uint16_t pki;

		pki = nvlist_get_number(nvl, "persistent-keepalive-interval");
		wg_timers_set_persistent_keepalive(&peer->p_timers, pki);
	}
	if (nvlist_exists_nvlist_array(nvl, "allowed-ips")) {
		const void *binary;
		const nvlist_t * const * aipl;
		struct wg_allowedip aip;
		size_t allowedip_count;

		aipl = nvlist_get_nvlist_array(nvl, "allowed-ips",
		    &allowedip_count);
		for (size_t idx = 0; idx < allowedip_count; idx++) {
			if (!nvlist_exists_number(aipl[idx], "cidr"))
				continue;
			aip.cidr = nvlist_get_number(aipl[idx], "cidr");
			if (nvlist_exists_binary(aipl[idx], "ipv4")) {
				binary = nvlist_get_binary(aipl[idx], "ipv4", &size);
				if (binary == NULL || aip.cidr > 32 /* XXX */) {
					err = EINVAL;
					goto out;
				}

				aip.family = AF_INET;
				memcpy(&aip.ip4, binary, sizeof(aip.ip4));
			} else if (nvlist_exists_binary(aipl[idx], "ipv6")) {
				binary = nvlist_get_binary(aipl[idx], "ipv6", &size);
				if (binary == NULL || aip.cidr > 128 /* XXX */) {
					err = EINVAL;
					goto out;
				}

				aip.family = AF_INET6;
				memcpy(&aip.ip6, binary, sizeof(aip.ip6));
			} else {
				continue;
			}

			if (!wg_allowedip_valid(&aip)) {
				if_printf(ifp, "%s allowedip %ju not valid\n",
				    __func__, (uintmax_t)idx);
				err = EBADMSG;
				goto out;
			}

			if ((err = wg_route_add(&sc->sc_routes, peer, &aip)) != 0) {
				/* XXX */
				printf("route add %ju failed -> %d\n",
				    (uintmax_t)idx, err);
			}
		}
	}
	if (need_insert)
		wg_hashtable_peer_insert(&sc->sc_hashtable, peer);
	return (0);

out:
	wg_peer_destroy(peer);
	return (err);
}

static int
wgc_set(struct wg_softc *sc, struct wg_data_io *wgd)
{
	uint8_t			 public[WG_KEY_SIZE];
	struct ifnet *ifp;
	void *nvlpacked;
	nvlist_t *nvl;
	ssize_t size;
	int err;

	ifp = sc->sc_ifp;
	if (wgd->wgd_size == 0 || wgd->wgd_data == NULL)
		return (EFAULT);

	nvlpacked = malloc(wgd->wgd_size, M_TEMP, M_WAITOK);
	err = copyin(wgd->wgd_data, nvlpacked, wgd->wgd_size);
	if (err)
		goto out;
	nvl = nvlist_unpack(nvlpacked, wgd->wgd_size, 0);
	if (nvl == NULL) {
		if_printf(ifp, "%s nvlist_unpack failed\n", __func__);
		err = EBADMSG;
		goto out;
	}
	if (nvlist_exists_bool(nvl, "replace-peers") &&
		nvlist_get_bool(nvl, "replace-peers"))
		wg_peer_remove_all(sc, false);
	if (nvlist_exists_number(nvl, "listen-port")) {
		int listen_port __unused = nvlist_get_number(nvl, "listen-port");
			/*
			 * Set listen port
			 */
		if_link_state_change(sc->sc_ifp, LINK_STATE_DOWN);
		pause("link_down", hz/4);
		wg_socket_reinit(sc, NULL, NULL);
		sc->sc_socket.so_port = listen_port;
		if ((err = wg_socket_init(sc)) != 0)
			goto out;
		if_link_state_change(sc->sc_ifp, LINK_STATE_UP);
	}
	if (nvlist_exists_binary(nvl, "private-key")) {
		struct noise_local *local;
		const void *key = nvlist_get_binary(nvl, "private-key", &size);

		if (size != CURVE25519_KEY_SIZE) {
			if_printf(ifp, "%s bad length for private-key %zu\n", __func__, size);
			err = EBADMSG;
			goto nvl_out;
		}

		/* TODO this is temp code, should not be released */
		if (!curve25519_generate_public(public, key)) {
			err = EBADMSG;
			goto nvl_out;
		}
		/*
		 * set private key
		 */
		local = &sc->sc_local;
		noise_local_lock_identity(local);
		noise_local_set_private(local, key);
		cookie_checker_update(&sc->sc_cookie, public);
		noise_local_unlock_identity(local);
	}
	if (nvlist_exists_number(nvl, "user-cookie")) {
		sc->sc_user_cookie = nvlist_get_number(nvl, "user-cookie");
		/*
		 * setsockopt
		 */
	}
	if (nvlist_exists_nvlist_array(nvl, "peers")) {
		size_t peercount;
		const nvlist_t * const*nvl_peers;

		nvl_peers = nvlist_get_nvlist_array(nvl, "peers", &peercount);
		for (int i = 0; i < peercount; i++) {
			wg_peer_add(sc, nvl_peers[i]);
		}
	}
nvl_out:
	nvlist_destroy(nvl);
out:
	free(nvlpacked, M_TEMP);
	return (err);
}

static int
wg_up(struct wg_softc *sc)
{
	struct ifnet *ifp;
	int rc;

	mtx_lock(&sc->sc_mtx);
	ifp = sc->sc_ifp;
	rc = (ifp->if_drv_flags & IFF_DRV_RUNNING) != 0;
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	mtx_unlock(&sc->sc_mtx);
	if (rc != 0)
		return (0);

	if (sc->sc_socket.so_so4 != NULL)
		printf("XXX wg_init, socket non-NULL %p\n",
		    sc->sc_socket.so_so4);
	wg_socket_reinit(sc, NULL, NULL);
	rc = wg_socket_init(sc);
	if (rc != 0) {
		mtx_lock(&sc->sc_mtx);
		ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
		mtx_unlock(&sc->sc_mtx);
	}
	if_link_state_change(sc->sc_ifp, LINK_STATE_UP);

	return (rc);
}

static void
wg_down(struct wg_softc *sc)
{
	struct ifnet *ifp;

	ifp = sc->sc_ifp;
	mtx_lock(&sc->sc_mtx);
	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0) {
		mtx_unlock(&sc->sc_mtx);
		return;
	}
	mtx_unlock(&sc->sc_mtx);

	if_link_state_change(sc->sc_ifp, LINK_STATE_DOWN);
	wg_socket_reinit(sc, NULL, NULL);

	mtx_lock(&sc->sc_mtx);
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	mtx_unlock(&sc->sc_mtx);
}

static void
wg_init(void *xsc)
{
	struct wg_softc *sc;

	sc = xsc;
	wg_up(sc);
}

int
wg_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct wg_data_io *wgd = (struct wg_data_io *)data;
	struct ifreq *ifr = (struct ifreq *)data;
	struct wg_softc	*sc = ifp->if_softc;
	int		 ret = 0;

	switch (cmd) {
	case SIOCSWG:
		ret = wgc_set(sc, wgd);
		break;
	case SIOCGWG:
		ret = wgc_get(sc, wgd);
		break;
	/* Interface IOCTLs */
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		/* FALLTHROUGH */
	case SIOCSIFFLAGS:
		if ((ifp->if_flags & IFF_UP) != 0)
			ret = wg_up(sc);
		else
			wg_down(sc);
		break;
	case SIOCSIFMTU:
		/* Arbitrary limits */
		if (ifr->ifr_mtu <= 0 || ifr->ifr_mtu > 9000)
			ret = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	default:
		ret = ENOTTY;
	}

	return ret;
}

static void
vnet_wg_init(const void *unused __unused)
{

	V_wg_cloner = if_clone_simple(wgname, wg_clone_create, wg_clone_destroy,
	    0);
}
VNET_SYSINIT(vnet_wg_init, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY,
    vnet_wg_init, NULL);

static void
vnet_wg_uninit(const void *unused __unused)
{

	if_clone_detach(V_wg_cloner);
}
VNET_SYSUNINIT(vnet_wg_uninit, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY,
    vnet_wg_uninit, NULL);

static void
wg_module_init(void)
{

	ratelimit_zone = uma_zcreate("wg ratelimit", sizeof(struct ratelimit),
	     NULL, NULL, NULL, NULL, 0, 0);
}

static void
wg_module_deinit(void)
{

	uma_zdestroy(ratelimit_zone);
}

static int
wg_module_event_handler(module_t mod, int what, void *arg)
{

	switch (what) {
		case MOD_LOAD:
			wg_module_init();
			break;
		case MOD_UNLOAD:
			if (atomic_load_int(&clone_count) == 0)
				wg_module_deinit();
			else
				return (EBUSY);
			break;
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t wg_moduledata = {
	"wg",
	wg_module_event_handler,
	NULL
};

DECLARE_MODULE(wg, wg_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(wg, 1);
MODULE_DEPEND(wg, crypto, 1, 1, 1);
