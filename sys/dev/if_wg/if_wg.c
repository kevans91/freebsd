/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>
 * Copyright (c) 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* TODO audit imports */
#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <vm/uma.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/kernel.h>

#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/jail.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/rmlock.h>
#include <sys/protosw.h>
#include <sys/module.h>
#include <sys/endian.h>
#include <sys/kdb.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/gtaskqueue.h>
#include <sys/smp.h>
#include <sys/nv.h>

#include <net/bpf.h>

#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <net/radix.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#include <netinet/udp_var.h>

#include <machine/in_cksum.h>

#include "support.h"
#include "wg_noise.h"
#include "wg_cookie.h"
#include "if_wg.h"

/* TODO the following defines and structs are aligned to OpenBSD. */
#define DEFAULT_MTU		1420

#define MAX_STAGED_PKT		128
#define MAX_QUEUED_PKT		1024
#define MAX_QUEUED_PKT_MASK	(MAX_QUEUED_PKT - 1)

#define MAX_QUEUED_HANDSHAKES	4096

#define HASHTABLE_PEER_SIZE	(1 << 11)
#define HASHTABLE_INDEX_SIZE	(1 << 13)
#define MAX_PEERS_PER_IFACE	(1 << 20)

#define REKEY_TIMEOUT		5
#define REKEY_TIMEOUT_JITTER	334 /* 1/3 sec, round for arc4random_uniform */
#define KEEPALIVE_TIMEOUT	10
#define MAX_TIMER_HANDSHAKES	(90 / REKEY_TIMEOUT)
#define NEW_HANDSHAKE_TIMEOUT	(REKEY_TIMEOUT + KEEPALIVE_TIMEOUT)
#define UNDERLOAD_TIMEOUT	1

#define DPRINTF(sc,  ...) if (wireguard_debug) if_printf(sc->sc_ifp, ##__VA_ARGS__)

#define CONTAINER_OF(a, b, c) __containerof((a), b, c)

/* First byte indicating packet type on the wire */
#define WG_PKT_INITIATION htole32(1)
#define WG_PKT_RESPONSE htole32(2)
#define WG_PKT_COOKIE htole32(3)
#define WG_PKT_DATA htole32(4)

#define WG_PKT_WITH_PADDING(n)	(((n) + (16-1)) & (~(16-1)))
#define WG_KEY_SIZE		32

struct wg_pkt_initiation {
	uint32_t		t;
	uint32_t		s_idx;
	uint8_t			ue[NOISE_PUBLIC_KEY_LEN];
	uint8_t			es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN];
	uint8_t			ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN];
	struct cookie_macs	m;
};

struct wg_pkt_response {
	uint32_t		t;
	uint32_t		s_idx;
	uint32_t		r_idx;
	uint8_t			ue[NOISE_PUBLIC_KEY_LEN];
	uint8_t			en[0 + NOISE_AUTHTAG_LEN];
	struct cookie_macs	m;
};

struct wg_pkt_cookie {
	uint32_t		t;
	uint32_t		r_idx;
	uint8_t			nonce[COOKIE_NONCE_SIZE];
	uint8_t			ec[COOKIE_ENCRYPTED_SIZE];
};

struct wg_pkt_data {
	uint32_t		t;
	uint32_t		r_idx;
	uint8_t			nonce[sizeof(uint64_t)];
	uint8_t			buf[];
};

struct wg_endpoint {
	union {
		struct sockaddr		r_sa;
		struct sockaddr_in	r_sin;
#ifdef INET6
		struct sockaddr_in6	r_sin6;
#endif
	} e_remote;
	union {
		struct in_addr		l_in;
#ifdef INET6
		struct in6_pktinfo	l_pktinfo6;
#define l_in6 l_pktinfo6.ipi6_addr
#endif
	} e_local;
};

struct wg_index {
	LIST_ENTRY(wg_index)	 i_entry;
	SLIST_ENTRY(wg_index)	 i_unused_entry;
	uint32_t		 i_key;
	struct noise_remote	*i_value;
};

struct wg_queue {
	struct mtx	q_mtx;
	struct mbufq	q;
};

/* TODO the following structs are not aligned with OpenBSD and would require
 * code changes below to do so. Once aligned, move into the above section. */
struct wg_tag {
	struct m_tag		 t_tag;
	struct wg_endpoint	 t_endpoint;
	struct wg_peer		*t_peer;
	struct mbuf		*t_mbuf;
	sa_family_t		 t_family;
	int			 t_done;
	int			 t_mtu;
};

struct wg_timers {
	/* TODO the timers don't seem to be taking a read lock, they need a
	 * full audit. */
	/* t_lock is for blocking wg_timers_event_* when setting t_disabled. */
	struct rwlock		 t_lock;

	int			 t_disabled;
	int			 t_need_another_keepalive;
	uint16_t		 t_persistent_keepalive_interval;
	struct callout		 t_new_handshake;
	struct callout		 t_send_keepalive;
	struct callout		 t_retry_handshake;
	struct callout		 t_zero_key_material;
	struct callout		 t_persistent_keepalive;

	struct mtx		 t_handshake_mtx;
	struct timespec		 t_handshake_last_sent;
	struct timespec		 t_handshake_complete;
	volatile int		 t_handshake_retries;
};

struct wg_peer {
	CK_LIST_ENTRY(wg_peer)		 p_hash_entry;
	CK_LIST_ENTRY(wg_peer)		 p_entry;
	uint64_t			 p_id;
	struct wg_softc			*p_sc;

	struct noise_remote		 p_remote;
	struct cookie_maker		 p_cookie;
	struct wg_timers		 p_timers;

	struct rwlock			 p_endpoint_lock;
	struct wg_endpoint		 p_endpoint;

	SLIST_HEAD(,wg_index)		 p_unused_index;
	struct wg_index			 p_index[3];

	struct wg_queue	 		 p_stage_queue;
	struct wg_queue	 		 p_encap_queue;
	struct wg_queue	 		 p_decap_queue;

	struct grouptask		 p_clear_secrets;
	struct grouptask		 p_send_initiation;
	struct grouptask		 p_send_keepalive;
	struct grouptask		 p_send;
	struct grouptask		 p_recv;

	counter_u64_t			 p_tx_bytes;
	counter_u64_t			 p_rx_bytes;

	CK_LIST_HEAD(, wg_route)	 p_routes;
	struct mtx			 p_lock;
	struct epoch_context		 p_ctx;
};

/* TODO the following structs are not going to be aligned to OpenBSD due to
 * platform/implementation differences. */
enum route_direction {
	/* TODO OpenBSD doesn't use IN/OUT, instead passes the address buffer
	 * directly to route_lookup. */
	IN,
	OUT,
};

struct wg_route_table {
	size_t 			 t_count;
	struct radix_node_head	*t_ip;
	struct radix_node_head	*t_ip6;
};

struct wg_allowedip {
	uint16_t family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	};
	uint8_t cidr;
};

struct wg_route {
	struct radix_node	 r_nodes[2];
	CK_LIST_ENTRY(wg_route)	 r_entry;
	struct sockaddr_storage	 r_addr;
	struct sockaddr_storage	 r_mask;
	struct wg_peer		*r_peer;
};

struct wg_hashtable {
	/* TODO we can probably merge this into wg_softc. also on second
	 * viewing, i'm not sure why there are 3 different lists? I guess we'll
	 * never know... */
	struct mtx			 h_mtx;
	SIPHASH_KEY			 h_secret;
	CK_LIST_HEAD(, wg_peer)		 h_peers_list;
	CK_LIST_HEAD(, wg_peer)		*h_peers;
	u_long				 h_peers_mask;
	size_t				 h_num_peers;
	LIST_HEAD(, noise_keypair)	*h_keys;
	u_long				 h_keys_mask;
	size_t				 h_num_keys;
};

struct wg_socket {
	/* TODO openbsd doesn't use wg_socket, instead just has the elements in
	 * wg_softc. */
	struct mtx	 so_mtx;
	in_port_t	 so_port;
	struct socket	*so_so4;
	struct socket	*so_so6;
};

struct wg_softc {
	LIST_ENTRY(wg_softc)	 sc_entry;
	struct ifnet		*sc_ifp;
	uint16_t		 sc_incoming_port;
	uint32_t		 sc_user_cookie;
	int			 sc_flags;

	struct ucred		*sc_ucred;
	struct wg_socket	 sc_socket;
	struct wg_hashtable	 sc_hashtable;
	struct wg_route_table	 sc_routes;

	struct mbufq		 sc_handshake_queue;
	struct grouptask	 sc_handshake;

	struct noise_local	 sc_local;
	struct cookie_checker	 sc_cookie;

	struct buf_ring		*sc_encap_ring;
	struct buf_ring		*sc_decap_ring;

	struct grouptask	*sc_encrypt;
	struct grouptask	*sc_decrypt;

	struct rwlock		 sc_index_lock;
	LIST_HEAD(,wg_index)	*sc_index;
	u_long			 sc_index_mask;

	struct mtx		 sc_mtx;
	volatile u_int		 sc_peer_count;
};

#define	WGF_DYING	0x0001

/* TODO the following defines are freebsd specific, we should see what is
 * necessary and cleanup from there (i suspect a lot can be junked). */

#ifndef ENOKEY
#define	ENOKEY	ENOTCAPABLE
#endif

#if __FreeBSD_version > 1300000
typedef void timeout_t (void *);
#endif

#define	GROUPTASK_DRAIN(gtask)			\
	gtaskqueue_drain((gtask)->gt_taskqueue, &(gtask)->gt_task)

#define MTAG_WIREGUARD	0xBEAD
#define M_ENQUEUED	M_PROTO1

static int clone_count;
uma_zone_t ratelimit_zone;
static int wireguard_debug;
static volatile unsigned long peer_counter = 0;
static struct timeval	underload_interval = { UNDERLOAD_TIMEOUT, 0 };
static const char wgname[] = "wg";
static unsigned wg_osd_jail_slot;

static struct sx wg_sx;
SX_SYSINIT(wg_sx, &wg_sx, "wg_sx");

static LIST_HEAD(, wg_softc)	wg_list = LIST_HEAD_INITIALIZER(wg_list);

SYSCTL_NODE(_net, OID_AUTO, wg, CTLFLAG_RW, 0, "Wireguard");
SYSCTL_INT(_net_wg, OID_AUTO, debug, CTLFLAG_RWTUN, &wireguard_debug, 0,
	"enable debug logging");

TASKQGROUP_DECLARE(if_io_tqg);

MALLOC_DEFINE(M_WG, "WG", "wireguard");
VNET_DEFINE_STATIC(struct if_clone *, wg_cloner);


#define	V_wg_cloner	VNET(wg_cloner)
#define	WG_CAPS		IFCAP_LINKSTATE | IFCAP_HWCSUM | IFCAP_HWCSUM_IPV6
#define	ph_family	PH_loc.eight[5]

#define MAX_QUEUED_PACKETS		MAX_QUEUED_PKT
#define MAX_QUEUED_INCOMING_HANDSHAKES	MAX_QUEUED_HANDSHAKES

#define zfree(addr, type) do {			\
	explicit_bzero(addr, sizeof(*addr));	\
	free(addr, type);			\
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

struct wg_timespec64 {
	uint64_t	tv_sec;
	uint64_t	tv_nsec;
};

struct wg_peer_export {
	struct sockaddr_storage		endpoint;
	struct timespec			last_handshake;
	uint8_t				public_key[WG_KEY_SIZE];
	uint8_t				preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	size_t				endpoint_sz;
	struct wg_allowedip		*aip;
	uint64_t			rx_bytes;
	uint64_t			tx_bytes;
	int				aip_count;
	uint16_t			persistent_keepalive;
};

enum message_type {
	MESSAGE_INVALID = 0,
	MESSAGE_HANDSHAKE_INITIATION = 1,
	MESSAGE_HANDSHAKE_RESPONSE = 2,
	MESSAGE_HANDSHAKE_COOKIE = 3,
	MESSAGE_DATA = 4
};

/* TODO the next step for this section is to organise it as openbsd and then
 * audit side by side. Beyond here is the wild west. */

/* This is just a dump from `cproto -S -f2 if_wg.c` */
static void wg_m_freem(struct mbuf *);
static void m_calchdrlen(struct mbuf *);
static struct wg_tag *wg_tag_get(struct mbuf *);
static struct wg_endpoint *wg_mbuf_endpoint_get(struct mbuf *);
static void wg_peer_remove_all(struct wg_softc *, bool);
static int wg_socket_init(struct wg_softc *);
static void wg_socket_uninit(struct wg_softc *);
static int wg_socket_bind(struct wg_softc *, struct wg_socket *);
static int wg_send(struct wg_softc *, struct wg_endpoint *, struct mbuf *);
static void wg_timers_event_data_sent(struct wg_timers *);
static void wg_timers_event_data_received(struct wg_timers *);
static void wg_timers_event_any_authenticated_packet_sent(struct wg_timers *);
static void wg_timers_event_any_authenticated_packet_received(struct wg_timers *);
static void wg_timers_event_any_authenticated_packet_traversal(struct wg_timers *);
static void wg_timers_event_handshake_initiated(struct wg_timers *);
static void wg_timers_event_handshake_responded(struct wg_timers *);
static void wg_timers_event_handshake_complete(struct wg_timers *);
static void wg_timers_event_session_derived(struct wg_timers *);
static void wg_timers_event_want_initiation(struct wg_timers *);
static void wg_timers_event_reset_handshake_last_sent(struct wg_timers *);
static void wg_grouptask_enqueue(struct wg_peer *, struct grouptask *);
static void wg_timers_run_send_initiation(struct wg_timers *, int);
static void wg_timers_run_retry_handshake(struct wg_timers *);
static void wg_timers_run_send_keepalive(struct wg_timers *);
static void wg_timers_run_new_handshake(struct wg_timers *);
static void wg_timers_run_zero_key_material(struct wg_timers *);
static void wg_timers_run_persistent_keepalive(struct wg_timers *);
static void wg_peer_timers_init(struct wg_peer *);
static void wg_timers_disable(struct wg_timers *);
static void wg_timers_set_persistent_keepalive(struct wg_timers *, uint16_t);
static int wg_timers_get_persistent_keepalive(struct wg_timers *, uint16_t *);
static void wg_timers_get_last_handshake(struct wg_timers *, struct timespec *);
static int wg_timers_expired_handshake_last_sent(struct wg_timers *);
static int wg_timers_check_handshake_last_sent(struct wg_timers *);
static void wg_queue_init(struct wg_queue *, const char *);
static void wg_queue_deinit(struct wg_queue *);
static void wg_queue_purge(struct wg_queue *);
static struct mbuf *wg_queue_dequeue(struct wg_queue *, struct wg_tag **);
static int wg_queue_len(struct wg_queue *);
static int wg_queue_in(struct wg_peer *, struct mbuf *);
static void wg_queue_out(struct wg_peer *);
static void wg_queue_stage(struct wg_peer *, struct mbuf *);
static int wg_route_init(struct wg_route_table *);
static void wg_route_destroy(struct wg_route_table *);
static void wg_route_populate_aip4(struct wg_route *, const struct in_addr *, uint8_t);
static void wg_route_populate_aip6(struct wg_route *, const struct in6_addr *, uint8_t);
static int wg_route_add(struct wg_route_table *, struct wg_peer *, const struct wg_allowedip *);
static int wg_peer_remove(struct radix_node *, void *);
static int wg_route_delete(struct wg_route_table *, struct wg_peer *);
static struct wg_peer *wg_route_lookup(struct wg_route_table *, struct mbuf *, enum route_direction);
static void wg_hashtable_init(struct wg_hashtable *);
static void wg_hashtable_destroy(struct wg_hashtable *);
static void wg_hashtable_peer_insert(struct wg_hashtable *, struct wg_peer *);
static struct wg_peer *wg_peer_lookup(struct wg_softc *, const uint8_t [32]);
static void wg_hashtable_peer_remove(struct wg_hashtable *, struct wg_peer *);
static int wg_cookie_validate_packet(struct cookie_checker *, struct mbuf *, int);
static struct wg_peer *wg_peer_alloc(struct wg_softc *);
static void wg_peer_free_deferred(epoch_context_t);
static void wg_peer_destroy(struct wg_peer *);
static void wg_peer_send_buf(struct wg_peer *, uint8_t *, size_t);
static void wg_send_initiation(struct wg_peer *);
static void wg_send_response(struct wg_peer *);
static void wg_send_cookie(struct wg_softc *, struct cookie_macs *, uint32_t, struct mbuf *);
static void wg_peer_set_endpoint_from_tag(struct wg_peer *, struct wg_tag *);
static void wg_peer_clear_src(struct wg_peer *);
static void wg_peer_get_endpoint(struct wg_peer *, struct wg_endpoint *);
static void wg_deliver_out(struct wg_peer *);
static void wg_deliver_in(struct wg_peer *);
static void wg_send_buf(struct wg_softc *, struct wg_endpoint *, uint8_t *, size_t);
static void wg_send_keepalive(struct wg_peer *);
static void verify_endpoint(struct mbuf *);
static void wg_handshake(struct wg_softc *, struct mbuf *);
static void wg_encap(struct wg_softc *, struct mbuf *);
static void wg_decap(struct wg_softc *, struct mbuf *);
static void wg_softc_handshake_receive(struct wg_softc *);
static void wg_softc_decrypt(struct wg_softc *);
static void wg_softc_encrypt(struct wg_softc *);
static struct noise_remote *wg_remote_get(struct wg_softc *, uint8_t [CURVE25519_KEY_SIZE]);
static uint32_t wg_index_set(struct wg_softc *, struct noise_remote *);
static struct noise_remote *wg_index_get(struct wg_softc *, uint32_t);
static void wg_index_drop(struct wg_softc *, uint32_t);
static int wg_update_endpoint_addrs(struct wg_endpoint *, const struct sockaddr *, struct ifnet *);
static void wg_input(struct mbuf *, int, struct inpcb *, const struct sockaddr *, void *);
static void wg_encrypt_dispatch(struct wg_softc *);
static void wg_decrypt_dispatch(struct wg_softc *);
static void crypto_taskq_setup(struct wg_softc *);
static void crypto_taskq_destroy(struct wg_softc *);
static inline int callout_del(struct callout *);
static int wg_clone_create(struct if_clone *, int, caddr_t);
static void wg_qflush(struct ifnet *);
static int wg_transmit(struct ifnet *, struct mbuf *);
static int wg_output(struct ifnet *, struct mbuf *, const struct sockaddr *, struct route *);
static void wg_clone_destroy(struct ifnet *);
static int wg_peer_to_export(struct wg_peer *, struct wg_peer_export *);
static bool wgc_privileged(struct wg_softc *);
static int wgc_get(struct wg_softc *, struct wg_data_io *);
static int wgc_set(struct wg_softc *, struct wg_data_io *);
static int wg_up(struct wg_softc *);
static void wg_down(struct wg_softc *);
static void wg_reassign(struct ifnet *, struct vnet *, char *unused);
static void wg_init(void *);
static int wg_ioctl(struct ifnet *, u_long, caddr_t);
static void vnet_wg_init(const void *);
static void vnet_wg_uninit(const void *);
static void wg_module_init(void);
static void wg_module_deinit(void);

/* TODO Peer */
static struct wg_peer *
wg_peer_alloc(struct wg_softc *sc)
{
	struct wg_peer *peer;

	peer = malloc(sizeof(*peer), M_WG, M_WAITOK|M_ZERO);
	peer->p_sc = sc;
	peer->p_id = atomic_fetchadd_long(&peer_counter, 1);
	CK_LIST_INIT(&peer->p_routes);

	rw_init(&peer->p_endpoint_lock, "wg_peer_endpoint");
	wg_queue_init(&peer->p_stage_queue, "stageq");
	wg_queue_init(&peer->p_encap_queue, "txq");
	wg_queue_init(&peer->p_decap_queue, "rxq");

	GROUPTASK_INIT(&peer->p_send_initiation, 0, (gtask_fn_t *)wg_send_initiation, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_send_initiation, peer, NULL, NULL, "wg initiation");
	GROUPTASK_INIT(&peer->p_send_keepalive, 0, (gtask_fn_t *)wg_send_keepalive, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_send_keepalive, peer, NULL, NULL, "wg keepalive");
	GROUPTASK_INIT(&peer->p_clear_secrets, 0, (gtask_fn_t *)noise_remote_clear, &peer->p_remote);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_clear_secrets,
	    &peer->p_remote, NULL, NULL, "wg clear secrets");

	GROUPTASK_INIT(&peer->p_send, 0, (gtask_fn_t *)wg_deliver_out, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_send, peer, NULL, NULL, "wg send");
	GROUPTASK_INIT(&peer->p_recv, 0, (gtask_fn_t *)wg_deliver_in, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_recv, peer, NULL, NULL, "wg recv");

	wg_peer_timers_init(peer);

	peer->p_tx_bytes = counter_u64_alloc(M_WAITOK);
	peer->p_rx_bytes = counter_u64_alloc(M_WAITOK);

	SLIST_INIT(&peer->p_unused_index);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[0],
	    i_unused_entry);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[1],
	    i_unused_entry);
	SLIST_INSERT_HEAD(&peer->p_unused_index, &peer->p_index[2],
	    i_unused_entry);

	return (peer);
}

#define WG_HASHTABLE_PEER_FOREACH(peer, i, ht) \
	for (i = 0; i < HASHTABLE_PEER_SIZE; i++) \
		LIST_FOREACH(peer, &(ht)->h_peers[i], p_hash_entry)
#define WG_HASHTABLE_PEER_FOREACH_SAFE(peer, i, ht, tpeer) \
	for (i = 0; i < HASHTABLE_PEER_SIZE; i++) \
		CK_LIST_FOREACH_SAFE(peer, &(ht)->h_peers[i], p_hash_entry, tpeer)
static void
wg_hashtable_init(struct wg_hashtable *ht)
{
	mtx_init(&ht->h_mtx, "hash lock", NULL, MTX_DEF);
	arc4random_buf(&ht->h_secret, sizeof(ht->h_secret));
	ht->h_num_peers = 0;
	ht->h_num_keys = 0;
	ht->h_peers = hashinit(HASHTABLE_PEER_SIZE, M_DEVBUF,
			&ht->h_peers_mask);
	ht->h_keys = hashinit(HASHTABLE_INDEX_SIZE, M_DEVBUF,
			&ht->h_keys_mask);
}

static void
wg_hashtable_destroy(struct wg_hashtable *ht)
{
	MPASS(ht->h_num_peers == 0);
	MPASS(ht->h_num_keys == 0);
	mtx_destroy(&ht->h_mtx);
	hashdestroy(ht->h_peers, M_DEVBUF, ht->h_peers_mask);
	hashdestroy(ht->h_keys, M_DEVBUF, ht->h_keys_mask);
}

static void
wg_hashtable_peer_insert(struct wg_hashtable *ht, struct wg_peer *peer)
{
	uint64_t key;

	key = siphash24(&ht->h_secret, peer->p_remote.r_public,
			sizeof(peer->p_remote.r_public));

	mtx_lock(&ht->h_mtx);
	ht->h_num_peers++;
	CK_LIST_INSERT_HEAD(&ht->h_peers[key & ht->h_peers_mask], peer, p_hash_entry);
	CK_LIST_INSERT_HEAD(&ht->h_peers_list, peer, p_entry);
	mtx_unlock(&ht->h_mtx);
}

static struct wg_peer *
wg_peer_lookup(struct wg_softc *sc,
    const uint8_t pubkey[WG_KEY_SIZE])
{
	struct wg_hashtable *ht = &sc->sc_hashtable;
	uint64_t key;
	struct wg_peer *i = NULL;

	key = siphash24(&ht->h_secret, pubkey, WG_KEY_SIZE);

	mtx_lock(&ht->h_mtx);
	CK_LIST_FOREACH(i, &ht->h_peers[key & ht->h_peers_mask], p_hash_entry) {
		if (timingsafe_bcmp(i->p_remote.r_public, pubkey,
					WG_KEY_SIZE) == 0)
			break;
	}
	mtx_unlock(&ht->h_mtx);

	return i;
}

static void
wg_hashtable_peer_remove(struct wg_hashtable *ht, struct wg_peer *peer)
{
	mtx_lock(&ht->h_mtx);
	ht->h_num_peers--;
	CK_LIST_REMOVE(peer, p_hash_entry);
	CK_LIST_REMOVE(peer, p_entry);
	mtx_unlock(&ht->h_mtx);
}

static void
wg_peer_free_deferred(epoch_context_t ctx)
{
	struct wg_peer *peer;
	volatile u_int *peercnt;

	peer = __containerof(ctx, struct wg_peer, p_ctx);
	peercnt = &peer->p_sc->sc_peer_count;
	counter_u64_free(peer->p_tx_bytes);
	counter_u64_free(peer->p_rx_bytes);

	rw_destroy(&peer->p_timers.t_lock);
	rw_destroy(&peer->p_endpoint_lock);
	zfree(peer, M_WG);

	if (refcount_release(peercnt))
		wakeup(__DEVOLATILE(u_int *, peercnt));
}

static void
wg_peer_destroy(struct wg_peer *peer)
{

	/* We first remove the peer from the hash table and route table, so
	 * that it cannot be referenced again */
	wg_route_delete(&peer->p_sc->sc_routes, peer);
	MPASS(CK_LIST_EMPTY(&peer->p_routes));

	/* TODO currently, if there is a timer added after here, then the peer
	 * can hang around for longer than we want. */
	wg_timers_disable(&peer->p_timers);
	GROUPTASK_DRAIN(&peer->p_clear_secrets);
	GROUPTASK_DRAIN(&peer->p_send_initiation);
	GROUPTASK_DRAIN(&peer->p_send_keepalive);
	GROUPTASK_DRAIN(&peer->p_recv);
	GROUPTASK_DRAIN(&peer->p_send);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_clear_secrets);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_send_initiation);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_send_keepalive);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_recv);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_send);
	wg_queue_deinit(&peer->p_decap_queue);
	wg_queue_deinit(&peer->p_encap_queue);
	wg_queue_deinit(&peer->p_stage_queue);
	NET_EPOCH_CALL(wg_peer_free_deferred, &peer->p_ctx);
}

static void
wg_peer_set_endpoint_from_tag(struct wg_peer *peer, struct wg_tag *t)
{
	struct wg_endpoint *e = &t->t_endpoint;

	MPASS(e->e_remote.r_sa.sa_family != 0);
	if (memcmp(e, &peer->p_endpoint, sizeof(*e)) == 0)
		return;

	peer->p_endpoint = *e;
}

static void
wg_peer_clear_src(struct wg_peer *peer)
{
	rw_rlock(&peer->p_endpoint_lock);
	bzero(&peer->p_endpoint.e_local, sizeof(peer->p_endpoint.e_local));
	rw_runlock(&peer->p_endpoint_lock);
}

static void
wg_peer_get_endpoint(struct wg_peer *p, struct wg_endpoint *e)
{
	memcpy(e, &p->p_endpoint, sizeof(*e));
}

/* Allowed IP */
static int
wg_route_init(struct wg_route_table *tbl)
{
	int rc;

	tbl->t_count = 0;
	rc = rn_inithead((void **)&tbl->t_ip,
	    offsetof(struct sockaddr_in, sin_addr) * NBBY);

	if (rc == 0)
		return (ENOMEM);
	RADIX_NODE_HEAD_LOCK_INIT(tbl->t_ip);
#ifdef INET6
	rc = rn_inithead((void **)&tbl->t_ip6,
	    offsetof(struct sockaddr_in6, sin6_addr) * NBBY);
	if (rc == 0) {
		free(tbl->t_ip, M_RTABLE);
		return (ENOMEM);
	}
	RADIX_NODE_HEAD_LOCK_INIT(tbl->t_ip6);
#endif
	return (0);
}

static void
wg_route_destroy(struct wg_route_table *tbl)
{
	RADIX_NODE_HEAD_DESTROY(tbl->t_ip);
	free(tbl->t_ip, M_RTABLE);
#ifdef INET6
	RADIX_NODE_HEAD_DESTROY(tbl->t_ip6);
	free(tbl->t_ip6, M_RTABLE);
#endif
}

static void
wg_route_populate_aip4(struct wg_route *aip, const struct in_addr *addr,
    uint8_t mask)
{
	struct sockaddr_in *raddr, *rmask;
	uint8_t *p;
	unsigned int i;

	raddr = (struct sockaddr_in *)&aip->r_addr;
	rmask = (struct sockaddr_in *)&aip->r_mask;

	raddr->sin_len = sizeof(*raddr);
	raddr->sin_family = AF_INET;
	raddr->sin_addr = *addr;

	rmask->sin_len = sizeof(*rmask);
	p = (uint8_t *)&rmask->sin_addr.s_addr;
	for (i = 0; i < mask / NBBY; i++)
		p[i] = 0xff;
	if ((mask % NBBY) != 0)
		p[i] = (0xff00 >> (mask % NBBY)) & 0xff;
	raddr->sin_addr.s_addr &= rmask->sin_addr.s_addr;
}

static void
wg_route_populate_aip6(struct wg_route *aip, const struct in6_addr *addr,
    uint8_t mask)
{
	struct sockaddr_in6 *raddr, *rmask;

	raddr = (struct sockaddr_in6 *)&aip->r_addr;
	rmask = (struct sockaddr_in6 *)&aip->r_mask;

	raddr->sin6_len = sizeof(*raddr);
	raddr->sin6_family = AF_INET6;
	raddr->sin6_addr = *addr;

	rmask->sin6_len = sizeof(*rmask);
	in6_prefixlen2mask(&rmask->sin6_addr, mask);
	for (int i = 0; i < 4; ++i)
		raddr->sin6_addr.__u6_addr.__u6_addr32[i] &= rmask->sin6_addr.__u6_addr.__u6_addr32[i];
}

/* wg_route_take assumes that the caller guarantees the allowed-ip exists. */
static void
wg_route_take(struct radix_node_head *root, struct wg_peer *peer,
    struct wg_route *route)
{
	struct radix_node *node;
	struct wg_peer *ppeer;

	RADIX_NODE_HEAD_LOCK_ASSERT(root);

	node = root->rnh_lookup(&route->r_addr, &route->r_mask,
	    &root->rh);
	MPASS(node != NULL);

	route = (struct wg_route *)node;
	ppeer = route->r_peer;
	if (ppeer != peer) {
		route->r_peer = peer;

		CK_LIST_REMOVE(route, r_entry);
		CK_LIST_INSERT_HEAD(&peer->p_routes, route, r_entry);
	}
}

static int
wg_route_add(struct wg_route_table *tbl, struct wg_peer *peer,
			 const struct wg_allowedip *aip)
{
	struct radix_node	*node;
	struct radix_node_head	*root;
	struct wg_route *route;
	sa_family_t family;
	bool needfree = false;

	family = aip->family;
	if (family != AF_INET && family != AF_INET6) {
		printf("bad sa_family %d\n", aip->family);
		return (EINVAL);
	}

	route = malloc(sizeof(*route), M_WG, M_WAITOK|M_ZERO);
	switch (family) {
	case AF_INET:
		root = tbl->t_ip;

		wg_route_populate_aip4(route, &aip->ip4, aip->cidr);
		break;
	case AF_INET6:
		root = tbl->t_ip6;

		wg_route_populate_aip6(route, &aip->ip6, aip->cidr);
		break;
	}

	route->r_peer = peer;

	RADIX_NODE_HEAD_LOCK(root);
	node = root->rnh_addaddr(&route->r_addr, &route->r_mask, &root->rh,
							route->r_nodes);
	if (node == route->r_nodes) {
		tbl->t_count++;
		CK_LIST_INSERT_HEAD(&peer->p_routes, route, r_entry);
	} else {
		needfree = true;
		wg_route_take(root, peer, route);
	}
	RADIX_NODE_HEAD_UNLOCK(root);
	if (needfree) {
		free(route, M_WG);
	}
	return (0);
}

static struct wg_peer *
wg_route_lookup(struct wg_route_table *tbl, struct mbuf *m,
		enum route_direction dir)
{
	RADIX_NODE_HEAD_RLOCK_TRACKER;
	struct ip *iphdr;
	struct ip6_hdr *ip6hdr;
	struct radix_node_head *root;
	struct radix_node	*node;
	struct wg_peer	*peer = NULL;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	void *addr;
	int version;

	NET_EPOCH_ASSERT();
	iphdr = mtod(m, struct ip *);
	version = iphdr->ip_v;

	if (__predict_false(dir != IN && dir != OUT))
		panic("invalid route dir: %d\n", dir);

	if (version == 4) {
		root = tbl->t_ip;
		memset(&sin, 0, sizeof(sin));
		sin.sin_len = sizeof(struct sockaddr_in);
		if (dir == IN)
			sin.sin_addr = iphdr->ip_src;
		else
			sin.sin_addr = iphdr->ip_dst;
		addr = &sin;
	} else if (version == 6) {
		ip6hdr = mtod(m, struct ip6_hdr *);
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_len = sizeof(struct sockaddr_in6);

		root = tbl->t_ip6;
		if (dir == IN)
			addr = &ip6hdr->ip6_src;
		else
			addr = &ip6hdr->ip6_dst;
		memcpy(&sin6.sin6_addr, addr, sizeof(sin6.sin6_addr));
		addr = &sin6;
	} else  {
		log(LOG_WARNING, "%s bad version %d\n", __func__, version);
		return (NULL);
	}
	RADIX_NODE_HEAD_RLOCK(root);
	if ((node = root->rnh_matchaddr(addr, &root->rh)) != NULL) {
		peer = ((struct wg_route *) node)->r_peer;
	} else {
		log(LOG_WARNING, "matchaddr failed\n");
	}
	RADIX_NODE_HEAD_RUNLOCK(root);
	return (peer);
}

struct peer_del_arg {
	struct radix_node_head * pda_head;
	struct wg_peer *pda_peer;
	struct wg_route_table *pda_tbl;
};

static int
wg_peer_remove(struct radix_node *rn, void *arg)
{
	struct peer_del_arg *pda = arg;
	struct wg_peer *peer = pda->pda_peer;
	struct radix_node_head * rnh = pda->pda_head;
	struct wg_route_table *tbl = pda->pda_tbl;
	struct wg_route *route = (struct wg_route *)rn;
	struct radix_node *x;

	if (route->r_peer != peer)
		return (0);
	x = (struct radix_node *)rnh->rnh_deladdr(&route->r_addr,
	    &route->r_mask, &rnh->rh);
	if (x != NULL)	 {
		tbl->t_count--;
		CK_LIST_REMOVE(route, r_entry);
		free(route, M_WG);
	}
	return (0);
}

static int
wg_route_delete(struct wg_route_table *tbl, struct wg_peer *peer)
{
	struct peer_del_arg pda;

	pda.pda_peer = peer;
	pda.pda_tbl = tbl;
	RADIX_NODE_HEAD_LOCK(tbl->t_ip);
	pda.pda_head = tbl->t_ip;
	rn_walktree(&tbl->t_ip->rh, wg_peer_remove, &pda);
	RADIX_NODE_HEAD_UNLOCK(tbl->t_ip);

	RADIX_NODE_HEAD_LOCK(tbl->t_ip6);
	pda.pda_head = tbl->t_ip6;
	rn_walktree(&tbl->t_ip6->rh, wg_peer_remove, &pda);
	RADIX_NODE_HEAD_UNLOCK(tbl->t_ip6);
	return (0);
}

static int
wg_socket_init(struct wg_softc *sc)
{
	struct thread *td;
	struct wg_socket *so;
	struct ifnet *ifp;
	struct ucred *cred;
	struct socket *so4, *so6;
	int rc;

	so = &sc->sc_socket;
	td = curthread;
	ifp = sc->sc_ifp;
	mtx_lock(&sc->sc_mtx);
	if (sc->sc_ucred == NULL)
		return (EBUSY);
	cred = crhold(sc->sc_ucred);
	mtx_unlock(&sc->sc_mtx);

	/*
	 * For socket creation, we use the creds of the thread that created the
	 * tunnel rather than the current thread to maintain the semantics that
	 * WireGuard has on Linux with network namespaces -- that the sockets
	 * are created in their home vnet so that they can be configured and
	 * functionally attached to a foreign vnet as the jail's only interface
	 * to the network.
	 */
	rc = socreate(AF_INET, &so4, SOCK_DGRAM, IPPROTO_UDP, cred, td);
	if (rc) {
		crfree(cred);
		if_printf(ifp, "can't create AF_INET socket\n");
		return (rc);
	}

	rc = udp_set_kernel_tunneling(so4, wg_input, NULL, sc);
	/*
	 * udp_set_kernel_tunneling can only fail if there is already a tunneling function set.
	 * This should never happen with a new socket.
	 */
	MPASS(rc == 0);

	rc = socreate(AF_INET6, &so6, SOCK_DGRAM, IPPROTO_UDP, cred, td);
	if (rc) {
		if_printf(ifp, "can't create AF_INET6 socket\n");

		goto fail;
	}
	rc = udp_set_kernel_tunneling(so6, wg_input, NULL, sc);
	MPASS(rc == 0);

	mtx_lock(&sc->sc_mtx);
	/* If we started dying in the process, just drop these sockets. */
	if ((sc->sc_flags & WGF_DYING) != 0) {
		mtx_unlock(&sc->sc_mtx);

		SOCK_LOCK(so4);
		sofree(so4);

		SOCK_LOCK(so6);
		sofree(so6);

		crfree(cred);
		return (EBUSY);
	}

	so->so_so4 = so4;
	so->so_so6 = so6;

	mtx_unlock(&sc->sc_mtx);

	/*
	 * No lock; maybe the interface gets downed before we bind -- meh.
	 */
	rc = wg_socket_bind(sc, so);

	crfree(cred);
	return (rc);
fail:
	SOCK_LOCK(so4);
	sofree(so4);
	crfree(cred);
	return (rc);
}

static void
wg_socket_uninit(struct wg_softc *sc)
{
	struct wg_socket *so;

	so = &sc->sc_socket;

	if (so->so_so4)
		soclose(so->so_so4);
	so->so_so4 = NULL;
	if (so->so_so6)
		soclose(so->so_so6);
	so->so_so6 = NULL;
}

union wg_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

static int
wg_socket_bind(struct wg_softc *sc, struct wg_socket *so)
{
	int rc;
	struct thread *td;
	union wg_sockaddr laddr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct ifnet *ifp;

	td = curthread;
	bzero(&laddr, sizeof(laddr));
	ifp = sc->sc_ifp;
	sin = &laddr.in4;
	sin->sin_len = sizeof(laddr.in4);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(so->so_port);
	sin->sin_addr = (struct in_addr) { 0 };

	if ((rc = sobind(so->so_so4, &laddr.sa, td)) != 0) {
		if_printf(ifp, "can't bind AF_INET socket %d\n", rc);
		return (rc);
	}

	if (so->so_port == 0) {
		rc = sogetsockaddr(so->so_so4, (struct sockaddr **)&sin);
		if (rc != 0) {
			if_printf(ifp,
			    "can't fetch listening port from socket, error %d\n",
			    rc);
			return (rc);
		}

		so->so_port = ntohs(sin->sin_port);
		free(sin, M_SONAME);
	}

	sin6 = &laddr.in6;
	sin6->sin6_len = sizeof(laddr.in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(so->so_port);
	sin6->sin6_addr = (struct in6_addr) { .s6_addr = { 0 } };

	rc = sobind(so->so_so6, &laddr.sa, td);
	if (rc)
		if_printf(ifp, "can't bind AF_INET6 socket %d\n", rc);
	return (rc);
}

static int
wg_send(struct wg_softc *sc, struct wg_endpoint *e, struct mbuf *m)
{
	struct epoch_tracker et;
	struct sockaddr *sa;
	struct wg_socket *so = &sc->sc_socket;
	struct mbuf	 *control = NULL;
	int		 ret = 0;

	/* Get local control address before locking */
	if (e->e_remote.r_sa.sa_family == AF_INET) {
		if (e->e_local.l_in.s_addr != INADDR_ANY)
			control = sbcreatecontrol((caddr_t)&e->e_local.l_in,
			    sizeof(struct in_addr), IP_SENDSRCADDR,
			    IPPROTO_IP);
	} else if (e->e_remote.r_sa.sa_family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&e->e_local.l_in6))
			control = sbcreatecontrol((caddr_t)&e->e_local.l_pktinfo6,
			    sizeof(struct in6_pktinfo), IPV6_PKTINFO,
			    IPPROTO_IPV6);
	} else {
		return (EAFNOSUPPORT);
	}

	/* Get remote address */
	sa = &e->e_remote.r_sa;

	NET_EPOCH_ENTER(et);
	if (sc->sc_ifp->if_link_state == LINK_STATE_DOWN)
		goto done;
	if (e->e_remote.r_sa.sa_family == AF_INET && so->so_so4 != NULL)
		ret = sosend(so->so_so4, sa, NULL, m, control, 0, curthread);
	else if (e->e_remote.r_sa.sa_family == AF_INET6 && so->so_so6 != NULL)
		ret = sosend(so->so_so6, sa, NULL, m, control, 0, curthread);
	else {
		ret = ENOTCONN;
		wg_m_freem(control);
		wg_m_freem(m);
	}
done:
	NET_EPOCH_EXIT(et);
	return (ret);
}

static void
wg_send_buf(struct wg_softc *sc, struct wg_endpoint *e, uint8_t *buf,
    size_t len)
{
	struct mbuf	*m;
	int		 ret = 0;

retry:
	m = m_gethdr(M_WAITOK, MT_DATA);
	m->m_len = 0;
	m_copyback(m, 0, len, buf);

	if (ret == 0) {
		ret = wg_send(sc, e, m);
		/* Retry if we couldn't bind to e->e_local */
		if (ret == EADDRNOTAVAIL) {
			bzero(&e->e_local, sizeof(e->e_local));
			goto retry;
		}
	} else {
		wg_send(sc, e, m);
	}
}

/* TODO Tag */
static struct wg_tag *
wg_tag_get(struct mbuf *m)
{
	struct m_tag *tag;

	tag = m_tag_find(m, MTAG_WIREGUARD, NULL);
	if (tag == NULL) {
		tag = m_tag_get(MTAG_WIREGUARD, sizeof(struct wg_tag), M_NOWAIT|M_ZERO);
		m_tag_prepend(m, tag);
		MPASS(!SLIST_EMPTY(&m->m_pkthdr.tags));
		MPASS(m_tag_locate(m, MTAG_ABI_COMPAT, MTAG_WIREGUARD, NULL) == tag);
	}
	return (struct wg_tag *)tag;
}

/* TODO Timers */
static void
wg_peer_timers_init(struct wg_peer *peer)
{
	struct wg_timers *t = &peer->p_timers;

	bzero(t, sizeof(*t));

	rw_init(&peer->p_timers.t_lock, "wg_peer_timers");
	callout_init(&t->t_retry_handshake, true);
	callout_init(&t->t_send_keepalive, true);
	callout_init(&t->t_new_handshake, true);
	callout_init(&t->t_zero_key_material, true);
	callout_init(&t->t_persistent_keepalive, true);
}

static void
wg_timers_disable(struct wg_timers *t)
{
	rw_wlock(&t->t_lock);
	t->t_disabled = 1;
	t->t_need_another_keepalive = 0;
	rw_wunlock(&t->t_lock);

	callout_del(&t->t_retry_handshake);
	callout_del(&t->t_send_keepalive);
	callout_del(&t->t_new_handshake);
	callout_del(&t->t_zero_key_material);
	callout_del(&t->t_persistent_keepalive);
}

static void
wg_timers_set_persistent_keepalive(struct wg_timers *t, uint16_t interval)
{
	if (t->t_disabled)
		return;
	t->t_persistent_keepalive_interval = interval;
	wg_timers_run_persistent_keepalive(t);
}

static int
wg_timers_get_persistent_keepalive(struct wg_timers *t, uint16_t *interval)
{
	*interval = t->t_persistent_keepalive_interval;
	return *interval > 0 ? 0 : ENOENT;
}

static void
wg_timers_get_last_handshake(struct wg_timers *t, struct timespec *time)
{
	time->tv_sec = t->t_handshake_complete.tv_sec;
	time->tv_nsec = t->t_handshake_complete.tv_nsec;
}

static int
wg_timers_expired_handshake_last_sent(struct wg_timers *t)
{
	struct timespec uptime;
	struct timespec expire = { .tv_sec = REKEY_TIMEOUT, .tv_nsec = 0 };

	getnanouptime(&uptime);
	timespecadd(&t->t_handshake_last_sent, &expire, &expire);
	return timespeccmp(&uptime, &expire, >) ? ETIMEDOUT : 0;
}

static int
wg_timers_check_handshake_last_sent(struct wg_timers *t)
{
	int ret;

	if ((ret = wg_timers_expired_handshake_last_sent(t)) == ETIMEDOUT)
		getnanouptime(&t->t_handshake_last_sent);
	return (ret);
}

/* Should be called after an authenticated data packet is sent. */
static void
wg_timers_event_data_sent(struct wg_timers *t)
{
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);

	if (!t->t_disabled && !callout_pending(&t->t_new_handshake))
		callout_reset(&t->t_new_handshake,
		    NEW_HANDSHAKE_TIMEOUT * hz + (random() % REKEY_TIMEOUT_JITTER),
		    (timeout_t *)wg_timers_run_new_handshake, t);
	NET_EPOCH_EXIT(et);
}

/* Should be called after an authenticated data packet is received. */
static void
wg_timers_event_data_received(struct wg_timers *t)
{
	struct epoch_tracker et;

	if (t->t_disabled)
		return;
	NET_EPOCH_ENTER(et);
	if (!callout_pending(&t->t_send_keepalive)) {
		callout_reset(&t->t_send_keepalive, KEEPALIVE_TIMEOUT*hz,
		    (timeout_t *)wg_timers_run_send_keepalive, t);
	} else {
		t->t_need_another_keepalive = 1;
	}
	NET_EPOCH_EXIT(et);
}

/*
 * Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
static void
wg_timers_event_any_authenticated_packet_sent(struct wg_timers *t)
{
	callout_del(&t->t_send_keepalive);
}

/*
 * Should be called after any type of authenticated packet is received, whether
 * keepalive, data, or handshake.
 */
static void
wg_timers_event_any_authenticated_packet_received(struct wg_timers *t)
{
	callout_del(&t->t_new_handshake);
}

/*
 * Should be called before a packet with authentication, whether
 * keepalive, data, or handshake is sent, or after one is received.
 */
static void
wg_timers_event_any_authenticated_packet_traversal(struct wg_timers *t)
{
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	if (!t->t_disabled && t->t_persistent_keepalive_interval > 0)
		callout_reset(&t->t_persistent_keepalive,
		     t->t_persistent_keepalive_interval *hz,
		    (timeout_t *)wg_timers_run_persistent_keepalive, t);
	NET_EPOCH_EXIT(et);
}

/* Should be called after a handshake initiation message is sent. */
static void
wg_timers_event_handshake_initiated(struct wg_timers *t)
{

	if (t->t_disabled)
		return;
	callout_reset(&t->t_retry_handshake,
	    REKEY_TIMEOUT * hz + random() % REKEY_TIMEOUT_JITTER,
	    (timeout_t *)wg_timers_run_retry_handshake, t);
}

static void
wg_timers_event_handshake_responded(struct wg_timers *t)
{
	getnanouptime(&t->t_handshake_last_sent);
}

/*
 * Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
static void
wg_timers_event_handshake_complete(struct wg_timers *t)
{
	if (t->t_disabled)
		return;

	callout_del(&t->t_retry_handshake);
	t->t_handshake_retries = 0;
	getnanotime(&t->t_handshake_complete);
	wg_timers_run_send_keepalive(t);
}

/*
 * Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
static void
wg_timers_event_session_derived(struct wg_timers *t)
{
	if (t->t_disabled)
		return;

	callout_reset(&t->t_zero_key_material,
	    REJECT_AFTER_TIME * 3 * hz,
	    (timeout_t *)wg_timers_run_zero_key_material, t);
}

static void
wg_timers_event_want_initiation(struct wg_timers *t)
{
	if (t->t_disabled)
		return;

	wg_timers_run_send_initiation(t, 0);
}

static void
wg_timers_event_reset_handshake_last_sent(struct wg_timers *t)
{
	t->t_handshake_last_sent.tv_sec -= (REKEY_TIMEOUT + 1);
}

static void
wg_grouptask_enqueue(struct wg_peer *peer, struct grouptask *task)
{
	if (peer->p_sc->sc_ifp->if_link_state == LINK_STATE_UP)
		GROUPTASK_ENQUEUE(task);
}

static void
wg_timers_run_send_initiation(struct wg_timers *t, int is_retry)
{
	struct wg_peer	 *peer = CONTAINER_OF(t, struct wg_peer, p_timers);

	if (!is_retry)
		t->t_handshake_retries = 0;
	if (wg_timers_expired_handshake_last_sent(t) == ETIMEDOUT)
		wg_grouptask_enqueue(peer, &peer->p_send_initiation);
}

static void
wg_timers_run_retry_handshake(struct wg_timers *t)
{
	struct wg_peer	*peer = CONTAINER_OF(t, struct wg_peer, p_timers);
	int		 retries;

	retries = atomic_fetchadd_int(&t->t_handshake_retries, 1);

	if (retries <= MAX_TIMER_HANDSHAKES) {
		DPRINTF(peer->p_sc, "Handshake for peer %llu did not complete "
		    "after %d seconds, retrying (try %d)\n",
			(unsigned long long)peer->p_id,
		    REKEY_TIMEOUT, t->t_handshake_retries + 1);
		wg_peer_clear_src(peer);
		wg_timers_run_send_initiation(t, 1);
	} else {
		DPRINTF(peer->p_sc, "Handshake for peer %llu did not complete "
		    "after %d retries, giving up\n",
			(unsigned long long) peer->p_id, MAX_TIMER_HANDSHAKES + 2);

		callout_del(&t->t_send_keepalive);
		wg_queue_purge(&peer->p_stage_queue);
		if (!callout_pending(&t->t_zero_key_material))
			callout_reset(&t->t_zero_key_material, REJECT_AFTER_TIME * 3 * hz,
			    (timeout_t *)wg_timers_run_zero_key_material, t);
	}
}

static void
wg_timers_run_send_keepalive(struct wg_timers *t)
{
	struct wg_peer	*peer = CONTAINER_OF(t, struct wg_peer, p_timers);

	wg_grouptask_enqueue(peer, &peer->p_send_keepalive);
	if (t->t_need_another_keepalive) {
		t->t_need_another_keepalive = 0;
		callout_reset(&t->t_send_keepalive,
		    KEEPALIVE_TIMEOUT*hz,
		     (timeout_t *)wg_timers_run_send_keepalive, t);
	}
}

static void
wg_timers_run_new_handshake(struct wg_timers *t)
{
	struct wg_peer	*peer = CONTAINER_OF(t, struct wg_peer, p_timers);

	DPRINTF(peer->p_sc, "Retrying handshake with peer %llu because we "
	    "stopped hearing back after %d seconds\n",
		(unsigned long long)peer->p_id, NEW_HANDSHAKE_TIMEOUT);
	wg_peer_clear_src(peer);

	wg_timers_run_send_initiation(t, 0);
}

static void
wg_timers_run_zero_key_material(struct wg_timers *t)
{
	struct wg_peer *peer = CONTAINER_OF(t, struct wg_peer, p_timers);

	DPRINTF(peer->p_sc, "Zeroing out all keys for peer %llu, since we "
	    "haven't received a new one in %d seconds\n",
		(unsigned long long)peer->p_id, REJECT_AFTER_TIME * 3);
	GROUPTASK_ENQUEUE(&peer->p_clear_secrets);
}

static void
wg_timers_run_persistent_keepalive(struct wg_timers *t)
{
	struct wg_peer	 *peer = CONTAINER_OF(t, struct wg_peer, p_timers);

	if (t->t_persistent_keepalive_interval != 0)
		wg_grouptask_enqueue(peer, &peer->p_send_keepalive);
}

/* TODO Handshake */
static void
wg_peer_send_buf(struct wg_peer *peer, uint8_t *buf, size_t len)
{
	struct wg_endpoint	 endpoint;

	counter_u64_add(peer->p_tx_bytes, len);
	wg_timers_event_any_authenticated_packet_traversal(&peer->p_timers);
	wg_timers_event_any_authenticated_packet_sent(&peer->p_timers);
	wg_peer_get_endpoint(peer, &endpoint);
	wg_send_buf(peer->p_sc, &endpoint, buf, len);
}

static void
wg_send_initiation(struct wg_peer *peer)
{
	struct wg_pkt_initiation pkt;
	struct epoch_tracker et;

	if (wg_timers_check_handshake_last_sent(&peer->p_timers) != ETIMEDOUT)
		return;

	NET_EPOCH_ENTER(et);
	if (noise_create_initiation(&peer->p_remote, &pkt.s_idx, pkt.ue,
	    pkt.es, pkt.ets) != 0)
		goto out;
	pkt.t = le32toh(MESSAGE_HANDSHAKE_INITIATION);
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	    sizeof(pkt)-sizeof(pkt.m));
	wg_peer_send_buf(peer, (uint8_t *)&pkt, sizeof(pkt));
	wg_timers_event_handshake_initiated(&peer->p_timers);
out:
	NET_EPOCH_EXIT(et);
}

static void
wg_send_response(struct wg_peer *peer)
{
	struct wg_pkt_response pkt;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);

	DPRINTF(peer->p_sc, "Sending handshake response to peer %llu\n",
	    (unsigned long long)peer->p_id);

	if (noise_create_response(&peer->p_remote, &pkt.s_idx, &pkt.r_idx,
	    pkt.ue, pkt.en) != 0)
		goto out;
	if (noise_remote_begin_session(&peer->p_remote) != 0)
		goto out;

	wg_timers_event_session_derived(&peer->p_timers);
	pkt.t = MESSAGE_HANDSHAKE_RESPONSE;
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	     sizeof(pkt)-sizeof(pkt.m));
	wg_timers_event_handshake_responded(&peer->p_timers);
	wg_peer_send_buf(peer, (uint8_t*)&pkt, sizeof(pkt));
out:
	NET_EPOCH_EXIT(et);
}

static void
wg_send_cookie(struct wg_softc *sc, struct cookie_macs *cm, uint32_t idx,
    struct mbuf *m)
{
	struct wg_pkt_cookie	pkt;
	struct wg_endpoint *e;

	DPRINTF(sc, "Sending cookie response for denied handshake message\n");

	pkt.t = le32toh(MESSAGE_HANDSHAKE_COOKIE);
	pkt.r_idx = idx;

	e = wg_mbuf_endpoint_get(m);
	cookie_checker_create_payload(&sc->sc_cookie, cm, pkt.nonce,
	    pkt.ec, &e->e_remote.r_sa);
	wg_send_buf(sc, e, (uint8_t *)&pkt, sizeof(pkt));
}

static void
wg_send_keepalive(struct wg_peer *peer)
{
	struct mbuf *m = NULL;
	struct wg_tag *t;
	struct epoch_tracker et;

	if (wg_queue_len(&peer->p_stage_queue) != 0) {
		NET_EPOCH_ENTER(et);
		goto send;
	}
	if ((m = m_gethdr(M_NOWAIT, MT_DATA)) == NULL)
		return;
	if ((t = wg_tag_get(m)) == NULL) {
		wg_m_freem(m);
		return;
	}
	t->t_peer = peer;
	t->t_mbuf = NULL;
	t->t_done = 0;
	t->t_mtu = 0; /* MTU == 0 OK for keepalive */

	NET_EPOCH_ENTER(et);
	wg_queue_stage(peer, m);
send:
	wg_queue_out(peer);
	NET_EPOCH_EXIT(et);
}

static void
verify_endpoint(struct mbuf *m)
{
#ifdef INVARIANTS
	struct wg_endpoint *e = wg_mbuf_endpoint_get(m);

	MPASS(e->e_remote.r_sa.sa_family != 0);
#endif
}

static int
wg_cookie_validate_packet(struct cookie_checker *checker, struct mbuf *m,
    int under_load)
{
	struct wg_endpoint *e;
	void *data;
	struct wg_pkt_initiation	*init;
	struct wg_pkt_response	*resp;
	struct cookie_macs *macs;
	int type, size;

	type = le32toh(*mtod(m, uint32_t *));
	data = m->m_data;
	e = wg_mbuf_endpoint_get(m);
	if (type == MESSAGE_HANDSHAKE_INITIATION) {
		init = mtod(m, struct wg_pkt_initiation *);
		macs = &init->m;
		size = sizeof(*init) - sizeof(*macs);
	} else if (type == MESSAGE_HANDSHAKE_RESPONSE) {
		resp = mtod(m, struct wg_pkt_response *);
		macs = &resp->m;
		size = sizeof(*resp) - sizeof(*macs);
	} else
		return EINVAL;

	return (cookie_checker_validate_macs(checker, macs, data, size,
	    under_load, &e->e_remote.r_sa));
}


static void
wg_handshake(struct wg_softc *sc, struct mbuf *m)
{
	struct wg_pkt_initiation *init;
	struct wg_pkt_response *resp;
	struct noise_remote	*remote;
	struct wg_pkt_cookie		*cook;
	struct wg_peer	*peer;
	struct wg_tag *t;

	/* This is global, so that our load calculation applies to the whole
	 * system. We don't care about races with it at all.
	 */
	static struct timeval wg_last_underload;
	int packet_needs_cookie;
	int underload, res;

	underload = mbufq_len(&sc->sc_handshake_queue) >=
			MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	if (underload)
		getmicrouptime(&wg_last_underload);
	else if (wg_last_underload.tv_sec != 0) {
		if (!ratecheck(&wg_last_underload, &underload_interval))
			underload = 1;
		else
			bzero(&wg_last_underload, sizeof(wg_last_underload));
	}

    res = wg_cookie_validate_packet(&sc->sc_cookie, m,
	    underload);

	if (res && res != EAGAIN) {
		printf("validate_packet got %d\n", res);
		goto free;
	}
	packet_needs_cookie = (res == EAGAIN);

	t = wg_tag_get(m);
	switch (le32toh(*mtod(m, uint32_t *))) {
	case MESSAGE_HANDSHAKE_INITIATION:
		init = mtod(m, struct wg_pkt_initiation *);

		if (packet_needs_cookie) {
			wg_send_cookie(sc, &init->m, init->s_idx, m);
			return;
		}
		if (noise_consume_initiation(&sc->sc_local, &remote,
		    init->s_idx, init->ue, init->es, init->ets) != 0) {
			DPRINTF(sc, "Invalid handshake initiation");
			goto free;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);
		DPRINTF(sc, "Receiving handshake initiation from peer %llu\n",
		    (unsigned long long)peer->p_id);
		wg_peer_set_endpoint_from_tag(peer, t);
		wg_send_response(peer);
		break;
	case MESSAGE_HANDSHAKE_RESPONSE:
		resp = mtod(m, struct wg_pkt_response *);

		if (packet_needs_cookie) {
			wg_send_cookie(sc, &resp->m, resp->s_idx, m);
			return;
		}

		if ((remote = wg_index_get(sc, resp->r_idx)) == NULL) {
			DPRINTF(sc, "Unknown handshake response\n");
			goto free;
		}
		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);
		if (noise_consume_response(remote, resp->s_idx, resp->r_idx,
		    resp->ue, resp->en) != 0) {
			DPRINTF(sc, "Invalid handshake response\n");
			goto free;
		}

		DPRINTF(sc, "Receiving handshake response from peer %llu\n",
				(unsigned long long)peer->p_id);
		counter_u64_add(peer->p_rx_bytes, sizeof(*resp));
		wg_peer_set_endpoint_from_tag(peer, t);
		if (noise_remote_begin_session(&peer->p_remote) == 0) {
			wg_timers_event_session_derived(&peer->p_timers);
			wg_timers_event_handshake_complete(&peer->p_timers);
		}
		break;
	case MESSAGE_HANDSHAKE_COOKIE:
		cook = mtod(m, struct wg_pkt_cookie *);

		if ((remote = wg_index_get(sc, cook->r_idx)) == NULL) {
			DPRINTF(sc, "Unknown cookie index\n");
			goto free;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);

		if (cookie_maker_consume_payload(&peer->p_cookie,
		    cook->nonce, cook->ec) != 0) {
			DPRINTF(sc, "Could not decrypt cookie response\n");
			goto free;
		}

		DPRINTF(sc, "Receiving cookie response\n");
		goto free;
	default:
		goto free;
	}
	MPASS(peer != NULL);
	wg_timers_event_any_authenticated_packet_received(&peer->p_timers);
	wg_timers_event_any_authenticated_packet_traversal(&peer->p_timers);

free:
	wg_m_freem(m);
}

static void
wg_softc_handshake_receive(struct wg_softc *sc)
{
	struct mbuf *m;

	while ((m = mbufq_dequeue(&sc->sc_handshake_queue)) != NULL) {
		verify_endpoint(m);
		wg_handshake(sc, m);
	}
}

/* TODO Encrypt */
static void
wg_encap(struct wg_softc *sc, struct mbuf *m)
{
	struct wg_pkt_data *data;
	size_t padding_len, plaintext_len, out_len;
	struct mbuf *mc;
	struct wg_peer *peer;
	struct wg_tag *t;
	uint64_t nonce;
	int res;

	if (sc->sc_ifp->if_link_state == LINK_STATE_DOWN)
		return;

	NET_EPOCH_ASSERT();
	t = wg_tag_get(m);
	peer = t->t_peer;

	plaintext_len = MIN(WG_PKT_WITH_PADDING(m->m_pkthdr.len), t->t_mtu);
	padding_len = plaintext_len - m->m_pkthdr.len;
	out_len = sizeof(struct wg_pkt_data) + plaintext_len + NOISE_AUTHTAG_LEN;


	if ((mc = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES)) == NULL)
		goto error;

	data = mtod(mc, struct wg_pkt_data *);
	m_copydata(m, 0, m->m_pkthdr.len, data->buf);
	bzero(data->buf + m->m_pkthdr.len, padding_len);

	data->t = htole32(MESSAGE_DATA);

	res = noise_remote_encrypt(&peer->p_remote, &data->r_idx, &nonce,
	    data->buf, plaintext_len);
	nonce = htole64(nonce); /* Wire format is little endian. */
	memcpy(data->nonce, &nonce, sizeof(data->nonce));

	if (__predict_false(res)) {
		if (res == EINVAL) {
			wg_timers_event_want_initiation(&peer->p_timers);
			wg_m_freem(mc);
			goto error;
		} else if (res == ESTALE) {
			wg_timers_event_want_initiation(&peer->p_timers);
		} else
			panic("unexpected result: %d\n", res);
	}

	/* A packet with length 0 is a keepalive packet */
	if (m->m_pkthdr.len == 0)
		DPRINTF(sc, "Sending keepalive packet to peer %llu\n",
		    (unsigned long long)peer->p_id);
	/*
	 * Set the correct output value here since it will be copied
	 * when we move the pkthdr in send.
	 */
	m->m_pkthdr.len = out_len;
	mc->m_flags &= ~(M_MCAST | M_BCAST);
	mc->m_len = out_len;
	m_calchdrlen(mc);

	counter_u64_add(peer->p_tx_bytes, m->m_pkthdr.len);

	t->t_mbuf = mc;
 error:
	/* XXX membar ? */
	t->t_done = 1;
	GROUPTASK_ENQUEUE(&peer->p_send);
}

static void
wg_decap(struct wg_softc *sc, struct mbuf *m)
{
	struct wg_pkt_data *data;
	struct wg_peer *peer, *routed_peer;
	struct wg_tag *t;
	size_t plaintext_len;
	uint8_t version;
	uint64_t nonce;
	int res;

	if (sc->sc_ifp->if_link_state == LINK_STATE_DOWN)
		return;

	NET_EPOCH_ASSERT();
	data = mtod(m, struct wg_pkt_data *);
	plaintext_len = m->m_pkthdr.len - sizeof(struct wg_pkt_data);

	t = wg_tag_get(m);
	peer = t->t_peer;

	memcpy(&nonce, data->nonce, sizeof(nonce));
	nonce = le64toh(nonce); /* Wire format is little endian. */

	res = noise_remote_decrypt(&peer->p_remote, data->r_idx, nonce,
	    data->buf, plaintext_len);

	if (__predict_false(res)) {
		DPRINTF(sc, "noise_remote_decrypt fail %d \n", res);
		if (res == EINVAL) {
			goto error;
		} else if (res == ECONNRESET) {
			wg_timers_event_handshake_complete(&peer->p_timers);
		} else if (res == ESTALE) {
			wg_timers_event_want_initiation(&peer->p_timers);
		} else  {
			panic("unexpected response: %d\n", res);
		}
	}
	wg_peer_set_endpoint_from_tag(peer, t);
	counter_u64_add(peer->p_rx_bytes, m->m_pkthdr.len);

	/* Remove the data header, and crypto mac tail from the packet */
	m_adj(m, sizeof(struct wg_pkt_data));
	m_adj(m, -NOISE_AUTHTAG_LEN);

	/* A packet with length 0 is a keepalive packet */
	if (m->m_pkthdr.len == 0) {
		DPRINTF(peer->p_sc, "Receiving keepalive packet from peer "
		    "%llu\n", (unsigned long long)peer->p_id);
		goto done;
	}

	version = mtod(m, struct ip *)->ip_v;
	if (version != IPVERSION && version != 6) {
		DPRINTF(peer->p_sc, "Packet is neither ipv4 nor ipv6 from peer "
				"%llu\n", (unsigned long long)peer->p_id);
		goto error;
	}

	routed_peer = wg_route_lookup(&peer->p_sc->sc_routes, m, IN);
	if (routed_peer != peer) {
		DPRINTF(peer->p_sc, "Packet has unallowed src IP from peer "
		    "%llu\n", (unsigned long long)peer->p_id);
		goto error;
	}

done:
	t->t_mbuf = m;
error:
	t->t_done = 1;
	GROUPTASK_ENQUEUE(&peer->p_recv);
}

static void
wg_softc_decrypt(struct wg_softc *sc)
{
	struct epoch_tracker et;
	struct mbuf *m;

	NET_EPOCH_ENTER(et);
	while ((m = buf_ring_dequeue_mc(sc->sc_decap_ring)) != NULL)
		wg_decap(sc, m);
	NET_EPOCH_EXIT(et);
}

static void
wg_softc_encrypt(struct wg_softc *sc)
{
	struct mbuf *m;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	while ((m = buf_ring_dequeue_mc(sc->sc_encap_ring)) != NULL)
		wg_encap(sc, m);
	NET_EPOCH_EXIT(et);
}

static void
wg_encrypt_dispatch(struct wg_softc *sc)
{
	for (int i = 0; i < mp_ncpus; i++) {
		if (sc->sc_encrypt[i].gt_task.ta_flags & TASK_ENQUEUED)
			continue;
		GROUPTASK_ENQUEUE(&sc->sc_encrypt[i]);
	}
}

static void
wg_decrypt_dispatch(struct wg_softc *sc)
{
	for (int i = 0; i < mp_ncpus; i++) {
		if (sc->sc_decrypt[i].gt_task.ta_flags & TASK_ENQUEUED)
			continue;
		GROUPTASK_ENQUEUE(&sc->sc_decrypt[i]);
	}
}

static void
wg_deliver_out(struct wg_peer *peer)
{
	struct epoch_tracker et;
	struct wg_tag *t;
	struct mbuf *m;
	struct wg_endpoint endpoint;
	int ret;

	NET_EPOCH_ENTER(et);
	if (peer->p_sc->sc_ifp->if_link_state == LINK_STATE_DOWN)
		goto done;

	wg_peer_get_endpoint(peer, &endpoint);

	while ((m = wg_queue_dequeue(&peer->p_encap_queue, &t)) != NULL) {
		/* t_mbuf will contain the encrypted packet */
		if (t->t_mbuf == NULL){
			if_inc_counter(peer->p_sc->sc_ifp, IFCOUNTER_OERRORS, 1);
			wg_m_freem(m);
			continue;
		}
		M_MOVE_PKTHDR(t->t_mbuf, m);
		ret = wg_send(peer->p_sc, &endpoint, t->t_mbuf);

		if (ret == 0) {
			wg_timers_event_any_authenticated_packet_traversal(
			    &peer->p_timers);
			wg_timers_event_any_authenticated_packet_sent(
			    &peer->p_timers);

			if (m->m_pkthdr.len != 0)
				wg_timers_event_data_sent(&peer->p_timers);
		} else if (ret == EADDRNOTAVAIL) {
			wg_peer_clear_src(peer);
			wg_peer_get_endpoint(peer, &endpoint);
		}
		wg_m_freem(m);
	}
done:
	NET_EPOCH_EXIT(et);
}

static void
wg_deliver_in(struct wg_peer *peer)
{
	struct mbuf *m;
	struct wg_softc *sc;
	struct wg_socket *so;
	struct epoch_tracker et;
	struct wg_tag *t;
	uint32_t af;
	int version;


	NET_EPOCH_ENTER(et);
	sc = peer->p_sc;
	if (sc->sc_ifp->if_link_state == LINK_STATE_DOWN)
		goto done;

	so = &sc->sc_socket;

	while ((m = wg_queue_dequeue(&peer->p_decap_queue, &t)) != NULL) {
		/* t_mbuf will contain the encrypted packet */
		if (t->t_mbuf == NULL){
			if_inc_counter(peer->p_sc->sc_ifp, IFCOUNTER_IERRORS, 1);
			wg_m_freem(m);
			continue;
		}
		MPASS(m == t->t_mbuf);

		wg_timers_event_any_authenticated_packet_received(
		    &peer->p_timers);
		wg_timers_event_any_authenticated_packet_traversal(
		    &peer->p_timers);

		if (m->m_pkthdr.len == 0) {
			wg_m_freem(m);
			continue;
		}
		counter_u64_add(peer->p_rx_bytes, m->m_pkthdr.len);

		m->m_flags &= ~(M_MCAST | M_BCAST);
		m->m_pkthdr.rcvif = sc->sc_ifp;
		version = mtod(m, struct ip *)->ip_v;
		if (version == IPVERSION) {
			af = AF_INET;
			BPF_MTAP2(sc->sc_ifp, &af, sizeof(af), m);
			CURVNET_SET(so->so_so4->so_vnet);
			ip_input(m);
			CURVNET_RESTORE();
		} else if (version == 6) {
			af = AF_INET6;
			BPF_MTAP2(sc->sc_ifp, &af, sizeof(af), m);
			CURVNET_SET(so->so_so6->so_vnet);
			ip6_input(m);
			CURVNET_RESTORE();
		} else
			wg_m_freem(m);

		wg_timers_event_data_received(&peer->p_timers);
	}
done:
	NET_EPOCH_EXIT(et);
}

/* TODO Queue */
static int
wg_queue_in(struct wg_peer *peer, struct mbuf *m)
{
	struct buf_ring *parallel = peer->p_sc->sc_decap_ring;
	struct wg_queue		*serial = &peer->p_decap_queue;
	struct wg_tag		*t;
	int rc;

	MPASS(wg_tag_get(m) != NULL);

	mtx_lock(&serial->q_mtx);
	if ((rc = mbufq_enqueue(&serial->q, m)) == ENOBUFS) {
		wg_m_freem(m);
		if_inc_counter(peer->p_sc->sc_ifp, IFCOUNTER_OQDROPS, 1);
	} else {
		m->m_flags |= M_ENQUEUED;
		rc = buf_ring_enqueue(parallel, m);
		if (rc == ENOBUFS) {
			t = wg_tag_get(m);
			t->t_done = 1;
		}
	}
	mtx_unlock(&serial->q_mtx);
	return (rc);
}

static void
wg_queue_stage(struct wg_peer *peer, struct mbuf *m)
{
	struct wg_queue *q = &peer->p_stage_queue;
	mtx_lock(&q->q_mtx);
	STAILQ_INSERT_TAIL(&q->q.mq_head, m, m_stailqpkt);
	q->q.mq_len++;
	while (mbufq_full(&q->q)) {
		m = mbufq_dequeue(&q->q);
		if (m) {
			m_freem(m);
			if_inc_counter(peer->p_sc->sc_ifp, IFCOUNTER_OQDROPS, 1);
		}
	}
	mtx_unlock(&q->q_mtx);
}

static void
wg_queue_out(struct wg_peer *peer)
{
	struct buf_ring *parallel = peer->p_sc->sc_encap_ring;
	struct wg_queue		*serial = &peer->p_encap_queue;
	struct wg_tag		*t;
	struct mbufq		 staged;
	struct mbuf		*m;

	if (noise_remote_ready(&peer->p_remote) != 0) {
		wg_timers_event_want_initiation(&peer->p_timers);
		return;
	}

	/* We first "steal" the staged queue to a local queue, so that we can do these
	 * remaining operations without having to hold the staged queue mutex. */
	STAILQ_INIT(&staged.mq_head);
	mtx_lock(&peer->p_stage_queue.q_mtx);
	STAILQ_SWAP(&staged.mq_head, &peer->p_stage_queue.q.mq_head, mbuf);
	staged.mq_len = peer->p_stage_queue.q.mq_len;
	peer->p_stage_queue.q.mq_len = 0;
	staged.mq_maxlen = peer->p_stage_queue.q.mq_maxlen;
	mtx_unlock(&peer->p_stage_queue.q_mtx);

	while ((m = mbufq_dequeue(&staged)) != NULL) {
		if ((t = wg_tag_get(m)) == NULL) {
			wg_m_freem(m);
			continue;
		}
		t->t_peer = peer;
		mtx_lock(&serial->q_mtx);
		if (mbufq_enqueue(&serial->q, m) != 0) {
			wg_m_freem(m);
			if_inc_counter(peer->p_sc->sc_ifp, IFCOUNTER_OQDROPS, 1);
		} else {
			m->m_flags |= M_ENQUEUED;
			if (buf_ring_enqueue(parallel, m)) {
				t = wg_tag_get(m);
				t->t_done = 1;
			}
		}
		mtx_unlock(&serial->q_mtx);
	}
	wg_encrypt_dispatch(peer->p_sc);
}

static struct mbuf *
wg_queue_dequeue(struct wg_queue *q, struct wg_tag **t)
{
	struct mbuf *m_, *m;

	m = NULL;
	mtx_lock(&q->q_mtx);
	m_ = mbufq_first(&q->q);
	if (m_ != NULL && (*t = wg_tag_get(m_))->t_done) {
		m = mbufq_dequeue(&q->q);
		m->m_flags &= ~M_ENQUEUED;
	}
	mtx_unlock(&q->q_mtx);
	return (m);
}

static int
wg_queue_len(struct wg_queue *q)
{
	//TODO: do we care about locking on this or is it fine if it races?
	return (mbufq_len(&q->q));
}

static void
wg_queue_init(struct wg_queue *q, const char *name)
{
	mtx_init(&q->q_mtx, name, NULL, MTX_DEF);
	mbufq_init(&q->q, MAX_QUEUED_PKT);
}

static void
wg_queue_deinit(struct wg_queue *q)
{
	wg_queue_purge(q);
	mtx_destroy(&q->q_mtx);
}

static void
wg_queue_purge(struct wg_queue *q)
{
	mtx_lock(&q->q_mtx);
	mbufq_drain(&q->q);
	mtx_unlock(&q->q_mtx);
}

/* TODO Indexes */
static struct noise_remote *
wg_remote_get(struct wg_softc *sc, uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
	struct wg_peer *peer;

	if ((peer = wg_peer_lookup(sc, public)) == NULL)
		return (NULL);
	return (&peer->p_remote);
}

static uint32_t
wg_index_set(struct wg_softc *sc, struct noise_remote *remote)
{
	struct wg_index *index, *iter;
	struct wg_peer	*peer;
	uint32_t	 key;

	/* We can modify this without a lock as wg_index_set, wg_index_drop are
	 * guaranteed to be serialised (per remote). */
	peer = CONTAINER_OF(remote, struct wg_peer, p_remote);
	index = SLIST_FIRST(&peer->p_unused_index);
	MPASS(index != NULL);
	SLIST_REMOVE_HEAD(&peer->p_unused_index, i_unused_entry);

	index->i_value = remote;

	rw_wlock(&sc->sc_index_lock);
assign_id:
	key = index->i_key = arc4random();
	key &= sc->sc_index_mask;
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == index->i_key)
			goto assign_id;

	LIST_INSERT_HEAD(&sc->sc_index[key], index, i_entry);

	rw_wunlock(&sc->sc_index_lock);

	/* Likewise, no need to lock for index here. */
	return index->i_key;
}

static struct noise_remote *
wg_index_get(struct wg_softc *sc, uint32_t key0)
{
	struct wg_index		*iter;
	struct noise_remote	*remote = NULL;
	uint32_t		 key = key0 & sc->sc_index_mask;

	rw_enter_read(&sc->sc_index_lock);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			remote = iter->i_value;
			break;
		}
	rw_exit_read(&sc->sc_index_lock);
	return remote;
}

static void
wg_index_drop(struct wg_softc *sc, uint32_t key0)
{
	struct wg_index	*iter;
	struct wg_peer	*peer = NULL;
	uint32_t	 key = key0 & sc->sc_index_mask;

	rw_enter_write(&sc->sc_index_lock);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			LIST_REMOVE(iter, i_entry);
			break;
		}
	rw_exit_write(&sc->sc_index_lock);

	if (iter == NULL)
		return;

	/* We expect a peer */
	peer = CONTAINER_OF(iter->i_value, struct wg_peer, p_remote);
	MPASS(peer != NULL);
	SLIST_INSERT_HEAD(&peer->p_unused_index, iter, i_unused_entry);
}

/* TODO Interface IO */
static int
wg_update_endpoint_addrs(struct wg_endpoint *e, const struct sockaddr *srcsa,
    struct ifnet *rcvif)
{
	const struct sockaddr_in *sa4;
	const struct sockaddr_in6 *sa6;
	int ret = 0;

	/*
	 * UDP passes a 2-element sockaddr array: first element is the
	 * source addr/port, second the destination addr/port.
	 */
	if (srcsa->sa_family == AF_INET) {
		sa4 = (const struct sockaddr_in *)srcsa;
		e->e_remote.r_sin = sa4[0];
		/* Only update dest if not mcast/bcast */
		if (!(IN_MULTICAST(ntohl(sa4[1].sin_addr.s_addr)) ||
		      sa4[1].sin_addr.s_addr == INADDR_BROADCAST ||
		      in_broadcast(sa4[1].sin_addr, rcvif))) {
			e->e_local.l_in = sa4[1].sin_addr;
		}
	} else if (srcsa->sa_family == AF_INET6) {
		sa6 = (const struct sockaddr_in6 *)srcsa;
		e->e_remote.r_sin6 = sa6[0];
		/* Only update dest if not multicast */
		if (!IN6_IS_ADDR_MULTICAST(&sa6[1].sin6_addr))
			e->e_local.l_in6 = sa6[1].sin6_addr;
	} else {
		ret = EAFNOSUPPORT;
	}

	return (ret);
}

static void
wg_input(struct mbuf *m0, int offset, struct inpcb *inpcb,
		 const struct sockaddr *srcsa, void *_sc)
{
	struct wg_pkt_data *pkt_data;
	struct wg_endpoint *e;
	struct wg_softc *sc = _sc;
	struct mbuf *m;
	int pktlen, pkttype;
	struct noise_remote *remote;
	struct wg_tag *t;
	void *data;

	/* Caller provided us with srcsa, no need for this header. */
	m_adj(m0, offset + sizeof(struct udphdr));

	/*
	 * Ensure mbuf has at least enough contiguous data to peel off our
	 * headers at the beginning.
	 */
	if ((m = m_defrag(m0, M_NOWAIT)) == NULL) {
		DPRINTF(sc, "DEFRAG fail\n");
		m_freem(m0);
		return;
	}
	data = mtod(m, void *);
	pkttype = le32toh(*(uint32_t*)data);
	t = wg_tag_get(m);
	if (t == NULL) {
		DPRINTF(sc, "no tag\n");
		goto free;
	}
	e = wg_mbuf_endpoint_get(m);

	if (wg_update_endpoint_addrs(e, srcsa, m->m_pkthdr.rcvif)) {
		DPRINTF(sc, "unknown family\n");
		goto free;
	}
	verify_endpoint(m);

	if_inc_counter(sc->sc_ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(sc->sc_ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	pktlen = m->m_pkthdr.len;

	if ((pktlen == sizeof(struct wg_pkt_initiation) &&
		 pkttype == MESSAGE_HANDSHAKE_INITIATION) ||
		(pktlen == sizeof(struct wg_pkt_response) &&
		 pkttype == MESSAGE_HANDSHAKE_RESPONSE) ||
		(pktlen == sizeof(struct wg_pkt_cookie) &&
		 pkttype == MESSAGE_HANDSHAKE_COOKIE)) {
		verify_endpoint(m);
		if (mbufq_enqueue(&sc->sc_handshake_queue, m) == 0) {
			GROUPTASK_ENQUEUE(&sc->sc_handshake);
		} else {
			DPRINTF(sc, "Dropping handshake packet\n");
			wg_m_freem(m);
		}
	} else if (pktlen >= sizeof(struct wg_pkt_data) + NOISE_AUTHTAG_LEN
	    && pkttype == MESSAGE_DATA) {

		pkt_data = data;
		remote = wg_index_get(sc, pkt_data->r_idx);
		if (remote == NULL) {
			DPRINTF(sc, "no remote\n");
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IERRORS, 1);
			wg_m_freem(m);
		} else if (buf_ring_count(sc->sc_decap_ring) > MAX_QUEUED_PACKETS) {
			DPRINTF(sc, "freeing excess packet on input\n");
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IQDROPS, 1);
			wg_m_freem(m);
		} else {
			t->t_peer = CONTAINER_OF(remote, struct wg_peer,
			    p_remote);
			t->t_mbuf = NULL;
			t->t_done = 0;

			wg_queue_in(t->t_peer, m);
			wg_decrypt_dispatch(sc);
		}
	} else {
		DPRINTF(sc, "Invalid packet\n");
free:
		wg_m_freem(m);
	}
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

	wg_queue_stage(peer, m);
	wg_queue_out(peer);
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
	bool running;

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
		mtx_lock(&sc->sc_mtx);
		running = (sc->sc_ifp->if_drv_flags & IFF_DRV_RUNNING) != 0;
		mtx_unlock(&sc->sc_mtx);
		if (running)
			if_link_state_change(sc->sc_ifp, LINK_STATE_DOWN);
		pause("link_down", hz/4);
		wg_socket_uninit(sc);
		sc->sc_socket.so_port = listen_port;
		if (running) {
			if ((err = wg_socket_init(sc)) != 0)
				goto out;
			if_link_state_change(sc->sc_ifp, LINK_STATE_UP);
		}
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
		/* TODO: missing, but present in OpenBSD code.
		 TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
                        noise_remote_precompute(&peer->p_remote);
                        wg_timers_event_reset_handshake_last_sent(&peer->p_timers);
                        noise_remote_expire_current(&peer->p_remote);
                }
		*/
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

static unsigned int
in_mask2len(struct in_addr *mask)
{
	unsigned int x, y;
	uint8_t *p;

	p = (uint8_t *)mask;
	for (x = 0; x < sizeof(*mask); x++) {
		if (p[x] != 0xff)
			break;
	}
	y = 0;
	if (x < sizeof(*mask)) {
		for (y = 0; y < NBBY; y++) {
			if ((p[x] & (0x80 >> y)) == 0)
				break;
		}
	}
	return x * NBBY + y;
}

static int
wg_peer_to_export(struct wg_peer *peer, struct wg_peer_export *exp)
{
	struct wg_endpoint *ep;
	struct wg_route *rt;
	struct noise_remote *remote;
	int i;

	/* Non-sleepable context. */
	NET_EPOCH_ASSERT();

	bzero(&exp->endpoint, sizeof(exp->endpoint));
	remote = &peer->p_remote;
	ep = &peer->p_endpoint;
	if (ep->e_remote.r_sa.sa_family != 0) {
		exp->endpoint_sz = (ep->e_remote.r_sa.sa_family == AF_INET) ?
		    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

		memcpy(&exp->endpoint, &ep->e_remote, exp->endpoint_sz);
	}

	/* We always export it. */
	(void)noise_remote_keys(remote, exp->public_key, exp->preshared_key);
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
		exp->aip[i].family = rt->r_addr.ss_family;
		if (exp->aip[i].family == AF_INET) {
			struct sockaddr_in *sin =
			    (struct sockaddr_in *)&rt->r_addr;

			exp->aip[i].ip4 = sin->sin_addr;

			sin = (struct sockaddr_in *)&rt->r_mask;
			exp->aip[i].cidr = in_mask2len(&sin->sin_addr);
		} else if (exp->aip[i].family == AF_INET6) {
			struct sockaddr_in6 *sin6 =
			    (struct sockaddr_in6 *)&rt->r_addr;

			exp->aip[i].ip6 = sin6->sin6_addr;

			sin6 = (struct sockaddr_in6 *)&rt->r_mask;
			exp->aip[i].cidr = in6_mask2len(&sin6->sin6_addr, NULL);
		}
		i++;
		if (i == exp->aip_count)
			break;
	}

	/* Again, AllowedIPs might have shrank; update it. */
	exp->aip_count = i;

	return (0);
}

static nvlist_t *
wg_peer_export_to_nvl(struct wg_softc *sc, struct wg_peer_export *exp)
{
	struct wg_timespec64 ts64;
	nvlist_t *nvl, **nvl_aips;
	size_t i;
	uint16_t family;

	nvl_aips = NULL;
	if ((nvl = nvlist_create(0)) == NULL)
		return (NULL);

	nvlist_add_binary(nvl, "public-key", exp->public_key,
	    sizeof(exp->public_key));
	if (wgc_privileged(sc))
		nvlist_add_binary(nvl, "preshared-key", exp->preshared_key,
		    sizeof(exp->preshared_key));
	if (exp->endpoint_sz != 0)
		nvlist_add_binary(nvl, "endpoint", &exp->endpoint,
		    exp->endpoint_sz);

	if (exp->aip_count != 0) {
		nvl_aips = mallocarray(exp->aip_count, sizeof(*nvl_aips),
		    M_WG, M_WAITOK | M_ZERO);
	}

	for (i = 0; i < exp->aip_count; i++) {
		nvl_aips[i] = nvlist_create(0);
		if (nvl_aips[i] == NULL)
			goto err;
		family = exp->aip[i].family;
		nvlist_add_number(nvl_aips[i], "cidr", exp->aip[i].cidr);
		if (family == AF_INET)
			nvlist_add_binary(nvl_aips[i], "ipv4",
			    &exp->aip[i].ip4, sizeof(exp->aip[i].ip4));
		else if (family == AF_INET6)
			nvlist_add_binary(nvl_aips[i], "ipv6",
			    &exp->aip[i].ip6, sizeof(exp->aip[i].ip6));
	}

	if (i != 0) {
		nvlist_add_nvlist_array(nvl, "allowed-ips",
		    (const nvlist_t *const *)nvl_aips, i);
	}

	for (i = 0; i < exp->aip_count; ++i)
		nvlist_destroy(nvl_aips[i]);

	free(nvl_aips, M_WG);
	nvl_aips = NULL;

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
err:
	for (i = 0; i < exp->aip_count && nvl_aips[i] != NULL; i++) {
		nvlist_destroy(nvl_aips[i]);
	}

	free(nvl_aips, M_WG);
	nvlist_destroy(nvl);
	return (NULL);
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
	nvl_array = malloc(peer_count*sizeof(void*), M_TEMP, M_WAITOK | M_ZERO);
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
		nvl_array[i] = wg_peer_export_to_nvl(sc, &wpe[i]);
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
		if (wgc_privileged(sc))
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

static int
wg_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct wg_data_io *wgd = (struct wg_data_io *)data;
	struct ifreq *ifr = (struct ifreq *)data;
	struct wg_softc	*sc = ifp->if_softc;
	int ret = 0;

	switch (cmd) {
	case SIOCSWG:
		ret = priv_check(curthread, PRIV_NET_WG);
		if (ret == 0)
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

static int
wg_up(struct wg_softc *sc)
{
	struct ifnet *ifp;
	int rc;

	mtx_lock(&sc->sc_mtx);
	/* Jail's being removed, no more wg_up(). */
	if ((sc->sc_flags & WGF_DYING) != 0) {
		mtx_unlock(&sc->sc_mtx);
		return (EBUSY);
	}
	ifp = sc->sc_ifp;
	rc = (ifp->if_drv_flags & IFF_DRV_RUNNING) != 0;
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	mtx_unlock(&sc->sc_mtx);
	if (rc != 0)
		return (0);

	wg_socket_uninit(sc);
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

	/* TODO: missing, but present in OpenBSD:
        TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
                wg_queue_purge(&peer->p_stage_queue);
                wg_timers_disable(&peer->p_timers);
        }

        taskq_barrier(wg_handshake_taskq);
        TAILQ_FOREACH(peer, &sc->sc_peer_seq, p_seq_entry) {
                noise_remote_clear(&peer->p_remote);
                wg_timers_event_reset_handshake_last_sent(&peer->p_timers);
        }

	 */

	if_link_state_change(sc->sc_ifp, LINK_STATE_DOWN);
	wg_socket_uninit(sc);

	mtx_lock(&sc->sc_mtx);
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	mtx_unlock(&sc->sc_mtx);
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
	sc->sc_ucred = crhold(curthread->td_ucred);
	ifp = sc->sc_ifp = if_alloc(IFT_WIREGUARD);
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
	ifp->if_reassign = wg_reassign;
	ifp->if_qflush = wg_qflush;
	ifp->if_transmit = wg_transmit;
	ifp->if_output = wg_output;
	ifp->if_ioctl = wg_ioctl;

	if_attach(ifp);
	bpfattach(ifp, DLT_NULL, sizeof(uint32_t));

	sx_xlock(&wg_sx);
	LIST_INSERT_HEAD(&wg_list, sc, sc_entry);
	sx_xunlock(&wg_sx);
nvl_out:
	if (nvl != NULL)
		nvlist_destroy(nvl);
out:
	free(packed, M_TEMP);
	if (err != 0) {
		crfree(sc->sc_ucred);
		if_free(ifp);
		free(sc, M_WG);
	}
	return (err);
}

static void
wg_clone_destroy(struct ifnet *ifp)
{
	struct wg_softc *sc = ifp->if_softc;
	struct ucred *cred;

	sx_xlock(&wg_sx);
	mtx_lock(&sc->sc_mtx);
	sc->sc_flags |= WGF_DYING;
	cred = sc->sc_ucred;
	sc->sc_ucred = NULL;
	mtx_unlock(&sc->sc_mtx);

	LIST_REMOVE(sc, sc_entry);
	sx_xunlock(&wg_sx);

	if_link_state_change(sc->sc_ifp, LINK_STATE_DOWN);
	wg_socket_uninit(sc);

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

	if (cred != NULL)
		crfree(cred);
	if_detach(sc->sc_ifp);
	if_free(sc->sc_ifp);
	free(sc, M_WG);

	atomic_add_int(&clone_count, -1);
}





/* TODO Module things */
static void
wg_qflush(struct ifnet *ifp __unused)
{


}

/*
 * Privileged information (private-key, preshared-key) are only exported for
 * root and jailed root by default.
 */
static bool
wgc_privileged(struct wg_softc *sc)
{
	struct thread *td;

	td = curthread;
	return (priv_check(td, PRIV_NET_WG) == 0);
}

static void
wg_reassign(struct ifnet *ifp, struct vnet *new_vnet __unused,
    char *unused __unused)
{
	struct wg_softc *sc;

	sc = ifp->if_softc;
	wg_down(sc);
}

static void
wg_init(void *xsc)
{
	struct wg_softc *sc;

	sc = xsc;
	wg_up(sc);
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

static int
wg_prison_remove(void *obj, void *data __unused)
{
	const struct prison *pr = obj;
	struct wg_softc *sc;
	struct ucred *cred;

	/*
	 * Do a pass through all if_wg interfaces and release creds on any from
	 * the jail that are supposed to be going away.  This will, in turn, let
	 * the jail die so that we don't end up with Schrödinger's jail.
	 */
	sx_slock(&wg_sx);
	LIST_FOREACH(sc, &wg_list, sc_entry) {
		cred = NULL;

		mtx_lock(&sc->sc_mtx);
		if ((sc->sc_flags & WGF_DYING) == 0 && sc->sc_ucred != NULL &&
		    sc->sc_ucred->cr_prison == pr) {
			cred = sc->sc_ucred;
			sc->sc_ucred = NULL;

			sc->sc_flags |= WGF_DYING;
			if_link_state_change(sc->sc_ifp, LINK_STATE_DOWN);
			/* Have to kill the sockets, as they also hold refs. */
			wg_socket_uninit(sc);
		}
		mtx_unlock(&sc->sc_mtx);

		if (cred != NULL) {
			CURVNET_SET(sc->sc_ifp->if_vnet);
			if_purgeaddrs(sc->sc_ifp);
			CURVNET_RESTORE();
			crfree(cred);
		}
	}
	sx_sunlock(&wg_sx);

	return (0);
}

static void
wg_module_init(void)
{
	osd_method_t methods[PR_MAXMETHOD] = {
		[PR_METHOD_REMOVE] = wg_prison_remove,
	};

	ratelimit_zone = uma_zcreate("wg ratelimit", sizeof(struct ratelimit),
	     NULL, NULL, NULL, NULL, 0, 0);
	wg_osd_jail_slot = osd_jail_register(NULL, methods);
}

static void
wg_module_deinit(void)
{

	uma_zdestroy(ratelimit_zone);
	osd_jail_deregister(wg_osd_jail_slot);

	MPASS(LIST_EMPTY(&wg_list));
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

/* TODO Crap */
static inline int
callout_del(struct callout *c)
{
	/* TODO unwrap callout_stop (nobody checks return value) */
	return (callout_stop(c) > 0);
}

static void
wg_m_freem(struct mbuf *m)
{
	MPASS((m->m_flags & M_ENQUEUED) == 0);
	m_freem(m);
}

static void
m_calchdrlen(struct mbuf *m)
{
	struct mbuf *n;
	int plen = 0;

	MPASS(m->m_flags & M_PKTHDR);
	for (n = m; n; n = n->m_next)
		plen += n->m_len;
	m->m_pkthdr.len = plen;
}

static struct wg_endpoint *
wg_mbuf_endpoint_get(struct mbuf *m)
{
	struct wg_tag *hdr;

	if ((hdr = wg_tag_get(m)) == NULL)
		return (NULL);

	return (&hdr->t_endpoint);
}

static void
wg_peer_remove_all(struct wg_softc *sc, bool drain)
{
	struct wg_peer *peer, *tpeer;
	int error;

	CK_LIST_FOREACH_SAFE(peer, &sc->sc_hashtable.h_peers_list,
	    p_entry, tpeer) {
		wg_hashtable_peer_remove(&peer->p_sc->sc_hashtable, peer);
		/* FIXME -- needs to be deferred */
		wg_peer_destroy(peer);
	}

	if (drain) {
		error = EWOULDBLOCK;

		/*
		 * For drains, we wait until the peer count drops to 0.  Only
		 * safe to do in a context that we can guarantee no other peers
		 * will be created because we're running lockless right now.
		 */
		while (error != 0 && refcount_load(&sc->sc_peer_count) != 0) {
			error = tsleep_sbt(__DEVOLATILE(u_int *,
			    &sc->sc_peer_count), 0, "wgpeergo",
			    SBT_1S / 4, SBT_1MS, 0);
		}
	}
}
