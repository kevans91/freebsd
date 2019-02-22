/*	$OpenBSD: if_switch.c,v 1.25 2018/12/28 14:32:47 bluhm Exp $	*/

/*
 * Copyright (c) 2016 Kazuya GODA <goda@openbsd.org>
 * Copyright (c) 2016 Reyk Floeter <reyk@openbsd.org>
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

#ifndef __FreeBSD__
#include "bpfilter.h"
#include "pf.h"
#include "vlan.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ctype.h>
#ifdef __FreeBSD__
#include <sys/endian.h>
#endif
#include <sys/eventhandler.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#ifdef __FreeBSD__
#include <sys/sockio.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/rwlock.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#ifdef __FreeBSD__
#include <sys/priv.h>
#else
#include <sys/pool.h>
#endif
#include <sys/syslog.h>

#include <machine/_inttypes.h>

#include <net/if_types.h>
#include <net/netisr.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#ifndef __FreeBSD__
#include <net/ethertypes.h>
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#include <net/if_llc.h>
#include <net/if_bridgevar.h>
#include <net/bridgestp.h>
#include <net/if_clone.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#endif
#include <netinet6/nd6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#ifdef __FreeBSD__
#define	NPF 0
#endif

#if NPF > 0
#include <net/pfvar.h>
#endif

#include <net/bpf.h>

#include <net/ofp.h>
#ifndef __FreeBSD__
#include <net/if_bridge.h>
#endif
#include <net/if_switch.h>

#ifdef __FreeBSD__
#include <vm/uma.h>
#endif

#define	SWITCH_DEBUG

#ifdef	SWITCH_DEBUG
#define	DPRINTF(fmt, arg...)	printf("switch: " fmt, ##arg)
#else
#define	DPRINTF(fmt, arg...)	(void)0
#endif

#ifndef VIMAGE
#error NO VIMAGE
#endif

static int switchmodevent(module_t, int, void *);
static void vnet_switch_init(const void *);
static void vnet_switch_uninit(const void *);
static void switch_uninit(const void *);

extern int bridge_fragment(struct ifnet *ifp, struct mbuf **mp,
    struct ether_header *eh, int snap, struct llc *llc);

static int switchcreate(const char *name, struct cdev *dev);
static void switchclone(void *arg, struct ucred *cred, char *name, int namelen,
    struct cdev **dev);

static int switch_clone_match(struct if_clone *, const char *);
static int switch_clone_create(struct if_clone *ifc, char *name, size_t len,
    caddr_t params);
static int switch_destroy(struct switch_softc *sc);
static int switch_clone_destroy(struct if_clone *ifc, struct ifnet *ifp);
static bool	 switch_process(struct ifnet *, struct mbuf *);
int	 switch_port_set_local(struct switch_softc *, struct switch_port *);
int	 switch_port_unset_local(struct switch_softc *, struct switch_port *);
int	 switch_ioctl(struct ifnet *, unsigned long, caddr_t);
int	 switch_port_add(struct switch_softc *, struct ifbreq *);
void	 switch_port_detach(void *);
int	 switch_port_del(struct switch_softc *, struct ifbreq *);
int	 switch_port_list(struct switch_softc *, struct ifbifconf *);
struct mbuf *switch_input(struct ifnet *, struct mbuf *);
static void	switch_linkstate(struct ifnet *);

struct mbuf
	*switch_port_ingress(struct switch_softc *, struct ifnet *,
	    struct mbuf *);
int	 switch_ifenqueue(struct switch_softc *, struct ifnet *,
	    struct mbuf *, int);
void	 switch_port_ifb_start(struct ifnet *);
static bool switch_fragment(struct switch_softc *sc, struct ifnet *switch_if,
    struct ifnet *dst_if, struct ether_header *eh, struct mbuf *m);

struct mbuf
	*switch_flow_classifier_udp(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_tcp(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_icmpv4(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_nd6(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_icmpv6(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_ipv4(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_ipv6(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_arp(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_ether(struct mbuf *, int *,
	    struct switch_flow_classify *);
struct mbuf
	*switch_flow_classifier_tunnel(struct mbuf *, int *,
	    struct switch_flow_classify *);
void	 switch_flow_classifier_dump(struct switch_softc *,
	    struct switch_flow_classify *);
void	 switchattach(int);

static int	switch_ioctl_add(struct switch_softc *, void *);
static int	switch_ioctl_del(struct switch_softc *, void *);

struct rwlock switch_ifs_lk;

const char if_switchname[] = "switch";

static struct mtx	 switchmtx;
static struct clonedevs *switchclones;
static struct unrhdr	*switch_unrhdr;

static bool switchdclone = true;

SYSCTL_DECL(_net_link);
static SYSCTL_NODE(_net_link, OID_AUTO, switch, CTLFLAG_RW, 0,
    "OpenFlow Switch Interface.");
SYSCTL_BOOL(_net_link_switch, OID_AUTO, devfs_cloning, CTLFLAG_RWTUN,
    &switchdclone, false, "Enable legacy devfs interface creation.");

static eventhandler_tag	 eh_tag;
static LIST_HEAD(, switch_softc) switch_list = LIST_HEAD_INITIALIZER(switch_list);

VNET_DEFINE_STATIC(struct if_clone *, switch_cloner);
VNET_DEFINE(uma_zone_t, swfcl_zone);

#define	V_switch_cloner	VNET(switch_cloner)

struct switch_control {
	int	(*swc_func)(struct switch_softc *, void *);
	int	swc_argsize;
	int	swc_flags;
};

#define	SWC_F_COPYIN		0x01	/* copy arguments in */
#define	SWC_F_COPYOUT		0x02	/* copy arguments out */
#define	SWC_F_SUSER		0x04	/* do super-user check */

const struct switch_control switch_control_table[] = {
	{ switch_ioctl_add,		sizeof(struct ifbreq),
	  SWC_F_COPYIN|SWC_F_SUSER },
	{ switch_ioctl_del,		sizeof(struct ifbreq),
	  SWC_F_COPYIN|SWC_F_SUSER },
};

const int switch_control_table_size = nitems(switch_control_table);

static struct bstp_cb_ops switch_ops = {
	.bcb_state = NULL,
	.bcb_rtage = NULL
};

static int
switchmodevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		mtx_init(&switchmtx, "switchmtx", NULL, MTX_DEF);
		rw_init(&switch_ifs_lk, "switch_ifs_lk");

		DPRINTF("Setting up\n");
		clone_setup(&switchclones);
		eh_tag = EVENTHANDLER_REGISTER(dev_clone, switchclone, 0, 1000);
		if (eh_tag == NULL) {
			clone_cleanup(&switchclones);
			mtx_destroy(&switchmtx);
			rw_destroy(&switch_ifs_lk);
			return (ENOMEM);
		}
		switch_unrhdr = new_unrhdr(0, IF_MAXUNIT, &switchmtx);
		LIST_INIT(&switch_list);
		break;
	case MOD_UNLOAD:
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t switch_mod = {
        "if_switch",
        switchmodevent,
        0
};

DECLARE_MODULE(if_switch, switch_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_switch, 1);
MODULE_DEPEND(if_switch, bridgestp, 1, 1, 1);
MODULE_DEPEND(if_switch, if_bridge, 1, 1, 1);

static void
vnet_switch_init(const void *unused __unused)
{

	DPRINTF("Creating cloner\n");
	V_switch_cloner = if_clone_advanced(if_switchname, 0, switch_clone_match,
	    switch_clone_create, switch_clone_destroy);
	V_swfcl_zone = uma_zcreate("swfcl", sizeof(union switch_field),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	swofp_attach();
}
VNET_SYSINIT(vnet_switch_init, SI_SUB_PROTO_IF, SI_ORDER_ANY,
    vnet_switch_init, NULL);

static void
vnet_switch_uninit(const void *unused __unused)
{

	swofp_detach();
	uma_zdestroy(V_swfcl_zone);

	if_clone_detach(V_switch_cloner);
	V_switch_cloner = NULL;
}
VNET_SYSUNINIT(vnet_switch_uninit, SI_SUB_PROTO_IF, SI_ORDER_ANY,
    vnet_switch_uninit, NULL);

static void
switch_uninit(const void *unused __unused)
{
	struct switch_softc *sc;

	EVENTHANDLER_DEREGISTER(dev_clone, eh_tag);
	drain_dev_clone_events();

	/* grab switch_ifs_lk */
	rw_wlock(&switch_ifs_lk);
	while ((sc = LIST_FIRST(&switch_list)) != NULL) {
		LIST_REMOVE(sc, sc_switch_next);
		switch_destroy(sc);
	}
	rw_wunlock(&switch_ifs_lk);

	delete_unrhdr(switch_unrhdr);
	clone_cleanup(&switchclones);
	mtx_destroy(&switchmtx);
	rw_destroy(&switch_ifs_lk);
}
SYSUNINIT(switch_uninit, SI_SUB_PROTO_IF, SI_ORDER_ANY, switch_uninit, NULL);

struct switch_softc *
switch_lookup(int unit)
{
	struct switch_softc	*sc;

	DPRINTF("Looking for %u\n", unit);
	/* must hold switch_ifs_lk */
	LIST_FOREACH(sc, &switch_list, sc_switch_next) {
		if (sc->sc_unit == unit)
			return (sc);
	}

	return (NULL);
}

static void
switchclone(void *arg, struct ucred *cred, char *name, int namelen,
    struct cdev **dev)
{
	char devname[SPECNAMELEN + 1];
	int unit, i;
	bool append_unit;

	if (*dev != NULL)
		return;

	if (!switchdclone || priv_check_cred(cred, PRIV_NET_IFCREATE) != 0)
		return;

	append_unit = false;
	if (strcmp(name, if_switchname) == 0)
		unit = -1;
	else if (dev_stdclone(name, NULL, if_switchname, &unit) != 1)
		return;	/* Don't recognize */
	if (unit != -1 && unit > IF_MAXUNIT)
		return;

	/* Losing unit going into clone_create, if it's -1 */
	if (unit == -1)
		append_unit = true;

	CURVNET_SET(CRED_TO_VNET(cred));
	i = clone_create(&switchclones, &switch_cdevsw, &unit, dev, 0);
	if (i != 0) {
		if (append_unit) {
			/* Append a unit */
			namelen = snprintf(devname, sizeof(devname), "%s%d",
			    name, unit);
			name = devname;
		}

		*dev = make_dev_credf(MAKEDEV_REF, &switch_cdevsw, unit, cred,
		    UID_UUCP, GID_DIALER, 0600, "%s", name);
	}

	DPRINTF("%s:%u\n", name, namelen);
	if_clone_create(name, namelen, NULL);
	CURVNET_RESTORE();
}

static int
switchcreate(const char *name, struct cdev *dev)
{
	struct switch_softc *sc;
	struct ifnet *ifp;
	int unit;

	/* XXX Check out the rest of this (tuncreate) */
	unit = dev2unit(dev);
	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAITOK | M_ZERO);
	ifp = sc->sc_if = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		free(sc, M_DEVBUF);
		return (ENOSPC);
	}
	if_initname(ifp, name, unit);
	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "switch%d",
	    unit);
	ifp->if_softc = sc;
	ifp->if_mtu = ETHERMTU;
	ifp->if_ioctl = switch_ioctl;
	ifp->if_output = NULL;
	ifp->if_start = NULL;
	ifp->if_type = IFT_BRIDGE;
	ifp->if_hdrlen = ETHER_HDR_LEN;
	DPRINTF("Init'ing the swpo_list\n");
	/* XXX TODO: if_transmit? if_flags? if_qflush? */
	TAILQ_INIT(&sc->sc_swpo_list);

	sc->sc_cdev = dev;
	sc->sc_unit = unit;
	bstp_attach(&sc->sc_stp, &switch_ops);

	dev->si_drv1 = sc;
	if_attach(ifp);

	bpfattach(ifp, DLT_EN10MB, ETHER_HDR_LEN);

	swofp_create(sc);

	LIST_INSERT_HEAD(&switch_list, sc, sc_switch_next);
	return (0);
}

static int
switch_clone_match(struct if_clone *ifc, const char *name)
{
	char c;
	size_t len;

	len = sizeof(if_switchname) - 1;

	if (strncmp(if_switchname, name, len) == 0 &&
	    ((c = name[len]) == '\0' || isdigit(c))) {
		DPRINTF("Matched\n");
		return (1);
	}

	DPRINTF("Not matched\n");
	return (0);
}

static int
switch_clone_create(struct if_clone *ifc, char *name, size_t len,
    caddr_t params)
{
	struct cdev		*dev;
	int			i, err, unit;

	DPRINTF("clone create triggered against %s\n", name);
	err = ifc_name2unit(name, &unit);
	if (err != 0)
		return (err);

	if (unit != -1) {
		if (alloc_unr_specific(switch_unrhdr, unit) == -1)
			return (EEXIST);
	} else {
		unit = alloc_unr(switch_unrhdr);
	}

	snprintf(name, IFNAMSIZ, "%s%d", if_switchname, unit);

	i = clone_create(&switchclones, &switch_cdevsw, &unit, &dev, 0);
	if (i) {
		dev = make_dev(&switch_cdevsw, unit, UID_UUCP, GID_DIALER,
		    0600, "%s", name);
	}

	return (switchcreate(if_switchname, dev));
}

static int
switch_destroy(struct switch_softc *sc)
{
	struct switch_port	*swpo, *tp;
	struct ifnet		*ifp, *ifs;

	DPRINTF("Destroying!\n");
	ifp = sc->sc_if;
	CURVNET_SET(ifp->if_vnet);
	DPRINTF("Empty? %s\n", TAILQ_EMPTY(&sc->sc_swpo_list) ? "Yes" : "No");
	TAILQ_FOREACH_SAFE(swpo, &sc->sc_swpo_list, swpo_list_next, tp) {
		if ((ifs = ifnet_byindex_ref(swpo->swpo_ifindex)) != NULL) {
			DPRINTF("Detaching!\n");
			switch_port_detach(ifs);
			if_rele(ifs);
		} else {
			DPRINTF("Failed to locate...?\n");
			log(LOG_ERR, "failed to cleanup on ifindex(%d)\n",
			    swpo->swpo_ifindex);
		}
	}

	swofp_destroy(sc);
	switch_dev_destroy(sc);
	free_unr(switch_unrhdr, sc->sc_unit);
	destroy_dev(sc->sc_cdev);
	bstp_detach(&sc->sc_stp);
	if_detach(ifp);
	if_free(ifp);
	free(sc, M_DEVBUF);
	CURVNET_RESTORE();
	return (0);
}

static int
switch_clone_destroy(struct if_clone *ifc, struct ifnet *ifp)
{
	struct switch_softc	*sc = ifp->if_softc;

	rw_wlock(&switch_ifs_lk);
	LIST_REMOVE(sc, sc_switch_next);
	rw_wunlock(&switch_ifs_lk);

	switch_destroy(sc);
	return (0);
}

struct mbuf *
switch_input(struct ifnet *ifp, struct mbuf *m)
{
	M_ASSERTPKTHDR(m);
	if (m->m_flags & M_PROTO1) {
		m->m_flags &= ~M_PROTO1;
		return (m);
	}


	if (switch_process(ifp, m)) {
		m_freem(m);
		return (NULL);
	}
	return (m);
}

static void
switch_linkstate(struct ifnet *ifp)
{

	/* XXX TODO */
}

static bool
switch_process(struct ifnet *ifp, struct mbuf *m0)
{
	struct switch_softc		*sc = NULL;
	struct switch_port		*swpo;
	struct switch_flow_classify	 swfcl = { 0 };
	struct mbuf			*m = NULL;

	swpo = (struct switch_port *)ifp->if_switch;
	if (swpo == NULL)
		goto discard;
	sc = swpo->swpo_switch;
	if (!(sc->sc_if->if_flags & IFF_UP) ||
	    !(sc->sc_if->if_drv_flags & IFF_DRV_RUNNING))
		goto discard;

	m = m_copym(m0, 0, M_COPYALL, M_NOWAIT);
	if (m == NULL)
		goto discard;

	if (sc->sc_if->if_bpf)
		ETHER_BPF_MTAP(sc->sc_if, m);

	if (m->m_pkthdr.len < sizeof(struct ether_header))
		goto discard;

	if ((m = switch_port_ingress(sc, ifp, m)) == NULL)
		return (false); /* m was freed in switch_port_ingress */

	if ((m = switch_flow_classifier(m, swpo->swpo_port_no,
	    &swfcl)) == NULL) {
		switch_swfcl_free(&swfcl);
		return (false);  /* m was freed in switch_flow_classifier */
	}

	if (sc->sc_if->if_flags & IFF_DEBUG)
		switch_flow_classifier_dump(sc, &swfcl);

	if (!sc->switch_process_forward)
		goto discard;

	/* switch_process_forward finally consumes the mbuf */
	(sc->switch_process_forward)(sc, &swfcl, m);

	switch_swfcl_free(&swfcl);
	return (true);
discard:
	m_freem(m);
	switch_swfcl_free(&swfcl);
	if (sc)
		if_inc_counter(sc->sc_if, IFCOUNTER_OERRORS, 1);
	return (false);
}

int
switch_port_set_local(struct switch_softc *sc, struct switch_port *swpo)
{
	struct switch_port	*tswpo;
	struct ifreq		 ifreq;
	struct ifnet		*ifs;
	int			error = 0, re_up = 0;

	/*
	 * Only one local interface can exist per switch device.
	 */
	TAILQ_FOREACH(tswpo, &sc->sc_swpo_list, swpo_list_next) {
		if (tswpo->swpo_flags & IFBIF_LOCAL)
			return (EEXIST);
	}

	ifs = ifnet_byindex_ref(swpo->swpo_ifindex);
	if (ifs == NULL)
		return (ENOENT);

	if (ifs->if_flags & IFF_UP) {
		re_up = 1;
		memset(&ifreq, 0, sizeof(ifreq));
		strlcpy(ifreq.ifr_name, ifs->if_xname, IFNAMSIZ);
		ifs->if_flags &= ~IFF_UP;
		ifreq.ifr_flags = ifs->if_flags;
		error = (*ifs->if_ioctl)(ifs, SIOCSIFFLAGS, (caddr_t)&ifreq);
		if (error)
			goto error;
	}

	swpo->swpo_flags |= IFBIF_LOCAL;
	swpo->swpo_port_no = OFP_PORT_LOCAL;
	swpo->swop_bk_start = ifs->if_start;
	ifs->if_start = switch_port_ifb_start;

	if (re_up) {
		memset(&ifreq, 0, sizeof(ifreq));
		strlcpy(ifreq.ifr_name, ifs->if_xname, IFNAMSIZ);
		ifs->if_flags &= IFF_UP;
		ifreq.ifr_flags = ifs->if_flags;
		error = (*ifs->if_ioctl)(ifs, SIOCSIFFLAGS, (caddr_t)&ifreq);
		if (error)
			goto error;
	}

 error:
	if_rele(ifs);
	return (error);
}

int
switch_port_unset_local(struct switch_softc *sc, struct switch_port *swpo)
{
	struct ifreq	ifreq;
	struct ifnet	*ifs;
	int		error = 0, re_up = 0;

	ifs = ifnet_byindex_ref(swpo->swpo_ifindex);
	if (ifs == NULL)
		return (ENOENT);

	if (ifs->if_flags & IFF_UP) {
		re_up = 1;
		memset(&ifreq, 0, sizeof(ifreq));
		strlcpy(ifreq.ifr_name, ifs->if_xname, IFNAMSIZ);
		ifs->if_flags &= ~IFF_UP;
		ifreq.ifr_flags = ifs->if_flags;
		error = (*ifs->if_ioctl)(ifs, SIOCSIFFLAGS, (caddr_t)&ifreq);
		if (error)
			goto error;
	}

	swpo->swpo_flags &= ~IFBIF_LOCAL;
	swpo->swpo_port_no = swofp_assign_portno(sc, ifs->if_index);
	ifs->if_start = swpo->swop_bk_start;
	swpo->swop_bk_start = NULL;

	if (re_up) {
		memset(&ifreq, 0, sizeof(ifreq));
		strlcpy(ifreq.ifr_name, ifs->if_xname, IFNAMSIZ);
		ifs->if_flags &= IFF_UP;
		ifreq.ifr_flags = ifs->if_flags;
		error = (*ifs->if_ioctl)(ifs, SIOCSIFFLAGS, (caddr_t)&ifreq);
		if (error)
			goto error;
	}

 error:
	if_rele(ifs);
	return (error);
}

static int
switch_ioctl_add(struct switch_softc *sc, void *data)
{
	struct ifbreq *breq;
	struct ifnet *ifs;
	struct switch_port *swpo;
	int ret;

	breq = (struct ifbreq *)data;
	ret = switch_port_add(sc, breq);
	if (ret != 0 || !(breq->ifbr_ifsflags & IFBIF_LOCAL))
		return (ret);
	/* Local flag is set. */
	ifs = ifunit_ref(breq->ifbr_ifsname);
	if (ifs == NULL)
		return (ENOENT);

	swpo = (struct switch_port *)ifs->if_switch;
	if (swpo == NULL || swpo->swpo_switch != sc) {
		if_rele(ifs);
		return (ESRCH);
	}

	ret = switch_port_set_local(sc, swpo);
	if_rele(ifs);
	return (ret);
}

static int
switch_ioctl_del(struct switch_softc *sc, void *data)
{

	return (switch_port_del(sc, (struct ifbreq *)data));
}


int
switch_ioctl(struct ifnet *ifp, unsigned long cmd, caddr_t data)
{
#if 0
	struct ifbaconf		*baconf = (struct ifbaconf *)data;
	struct ifbropreq	*brop = (struct ifbropreq *)data;
	struct ifbrlconf	*bc = (struct ifbrlconf *)data;
	struct ifbreq		*breq = (struct ifbreq *)data;
	struct bstp_state	*bs = &sc->sc_stp;
	struct bstp_port	*bp;
	struct ifnet		*ifs;
	struct switch_port	*swpo;
#endif
	union {
		struct ifbreq ifbreq;
		struct ifbifconf ifbifconf;
		struct ifbareq ifbareq;
		struct ifbaconf ifbaconf;
		struct ifbrparam ifbrparam;
		struct ifbropreq ifbropreq;
	} args;
	struct switch_softc	*sc = (struct switch_softc *)ifp->if_softc;
	struct thread		*td = curthread;
	int			 error = 0;
	struct ifdrv *ifd = (struct ifdrv *) data;
	const struct switch_control	*swc;

	switch (cmd) {
	case SIOCGDRVSPEC:
	case SIOCSDRVSPEC:
		if (ifd->ifd_cmd >= switch_control_table_size) {
			error = EINVAL;
			break;
		}
		swc = &switch_control_table[ifd->ifd_cmd];

		if (cmd == SIOCGDRVSPEC &&
		    (swc->swc_flags & SWC_F_COPYOUT) == 0) {
			error = EINVAL;
			break;
		}
		else if (cmd == SIOCSDRVSPEC &&
		    (swc->swc_flags & SWC_F_COPYOUT) != 0) {
			error = EINVAL;
			break;
		}

		if (swc->swc_flags & SWC_F_SUSER) {
			error = priv_check(td, PRIV_NET_SWITCH);
			if (error)
				break;
		}

		if (ifd->ifd_len != swc->swc_argsize ||
		    ifd->ifd_len > sizeof(args)) {
			error = EINVAL;
			break;
		}

		bzero(&args, sizeof(args));
		if (swc->swc_flags & SWC_F_COPYIN) {
			error = copyin(ifd->ifd_data, &args, ifd->ifd_len);
			if (error)
				break;
		}

//		BRIDGE_LOCK(sc);
		error = (*swc->swc_func)(sc, &args);
//		BRIDGE_UNLOCK(sc);
		if (error)
			break;

		if (swc->swc_flags & SWC_F_COPYOUT)
			error = copyout(&args, ifd->ifd_data, ifd->ifd_len);

		break;
#if 0
	case SIOCBRDGIFS:
		error = switch_port_list(sc, (struct ifbifconf *)data);
		break;
	case SIOCBRDGGIFFLGS:
		ifs = ifunit(breq->ifbr_ifsname);
		if (ifs == NULL) {
			error = ENOENT;
			break;
		}
		swpo = (struct switch_port *)ifs->if_switch;
		if (swpo == NULL || swpo->swpo_switch != sc) {
			error = ESRCH;
			break;
		}
		breq->ifbr_ifsflags = swpo->swpo_flags;
		breq->ifbr_portno = swpo->swpo_port_no;
		break;
#endif
	case SIOCSIFFLAGS:
		if ((ifp->if_flags & IFF_UP) != 0) {
			ifp->if_drv_flags |= IFF_DRV_RUNNING;
			bstp_init(&sc->sc_stp);
		} else {
			bstp_stop(&sc->sc_stp);
			ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
		}

		break;
#if 0
	case SIOCBRDGRTS:
		baconf->ifbac_len = 0;
		break;
	case SIOCBRDGGRL:
		bc->ifbrl_len = 0;
		break;
	case SIOCBRDGGPARAM:
		if ((bp = bs->bs_root_port) == NULL)
			brop->ifbop_root_port = 0;
		else
			brop->ifbop_root_port = bp->bp_ifp->if_index;
		brop->ifbop_maxage = bs->bs_bridge_max_age >> 8;
		brop->ifbop_hellotime = bs->bs_bridge_htime >> 8;
		brop->ifbop_fwddelay = bs->bs_bridge_fdelay >> 8;
		brop->ifbop_holdcount = bs->bs_txholdcount;
		brop->ifbop_priority = bs->bs_bridge_priority;
		brop->ifbop_protocol = bs->bs_protover;
		brop->ifbop_root_bridge = bs->bs_root_pv.pv_root_id;
		brop->ifbop_root_path_cost = bs->bs_root_pv.pv_cost;
		brop->ifbop_root_port = bs->bs_root_pv.pv_port_id;
		brop->ifbop_desg_bridge = bs->bs_root_pv.pv_dbridge_id;
		brop->ifbop_last_tc_time.tv_sec = bs->bs_last_tc_time.tv_sec;
		brop->ifbop_last_tc_time.tv_usec = bs->bs_last_tc_time.tv_usec;
		break;
#endif
	case SIOCSWGDPID:
	case SIOCSWSDPID:
	case SIOCSWGMAXFLOW:
	case SIOCSWGMAXGROUP:
	case SIOCSWSPORTNO:
		error = swofp_ioctl(ifp, cmd, data);
		break;
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}

int
switch_port_add(struct switch_softc *sc, struct ifbreq *req)
{
	struct ifnet		*ifs;
	struct switch_port	*swpo;
	int			 error;

	DPRINTF("switch_port_add req\n");
	if ((ifs = ifunit(req->ifbr_ifsname)) == NULL)
		return (ENOENT);

	if (ifs->if_bridge != NULL)
		return (EBUSY);

	if (ifs->if_switch != NULL) {
		DPRINTF("if_switch != NULL... checking swpo_switch\n");
		swpo = (struct switch_port *)ifs->if_switch;
		if (swpo->swpo_switch == sc)
			return (EEXIST);
		else
			return (EBUSY);
	}

	DPRINTF("Good, not a member and not in another switch\n");

	if (ifs->if_type == IFT_ETHER) {
		DPRINTF("ifpromisc...\n");
		if ((error = ifpromisc(ifs, 1)) != 0)
			return (error);
	}

	DPRINTF("Allocating swpo!\n");
	swpo = malloc(sizeof(*swpo), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (swpo == NULL) {
		DPRINTF("Failed to alloc, switch back\n");
		if (ifs->if_type == IFT_ETHER)
			ifpromisc(ifs, 0);
		return (ENOMEM);
	}
	swpo->swpo_switch = sc;
	swpo->swpo_ifindex = ifs->if_index;
	ifs->if_switch = swpo;
	ifs->if_bridge_input = switch_input;
	ifs->if_bridge_linkstate = switch_linkstate;
	bstp_create(&sc->sc_stp, &swpo->swpo_stp, sc->sc_if);
	DPRINTF("swofp_assign_portno...\n");
	swpo->swpo_port_no = swofp_assign_portno(sc, ifs->if_index);

	DPRINTF("nanouptime..\n");
	nanouptime(&swpo->swpo_appended);

	DPRINTF("Insert to swpo_list...\n");
	TAILQ_INSERT_TAIL(&sc->sc_swpo_list, swpo, swpo_list_next);
	DPRINTF("Done!\n");

	return (0);
}

int
switch_port_list(struct switch_softc *sc, struct ifbifconf *bifc)
{
	struct switch_port	*swpo;
	struct ifnet		*ifs;
	struct ifbreq		 breq;
	int			 total = 0, n = 0, error = 0;

	TAILQ_FOREACH(swpo, &sc->sc_swpo_list, swpo_list_next)
		total++;

	if (bifc->ifbic_len == 0)
		goto done;

	TAILQ_FOREACH(swpo, &sc->sc_swpo_list, swpo_list_next) {
		memset(&breq, 0, sizeof(breq));

		if (bifc->ifbic_len < sizeof(breq))
			break;

		ifs = ifnet_byindex_ref(swpo->swpo_ifindex);
		if (ifs == NULL) {
			error = ENOENT;
			goto done;
		}
		strlcpy(breq.ifbr_ifsname, ifs->if_xname, IFNAMSIZ);
		if_rele(ifs);

		breq.ifbr_ifsflags = swpo->swpo_flags;
		breq.ifbr_portno = swpo->swpo_port_no;

		if ((error = copyout((caddr_t)&breq,
		    (caddr_t)(bifc->ifbic_req + n), sizeof(breq))) != 0)
			goto done;

		bifc->ifbic_len -= sizeof(breq);
		n++;
	}

done:
	bifc->ifbic_len = n * sizeof(breq);
	return (error);
}

void
switch_port_detach(void *arg)
{
	struct ifnet		*ifp = (struct ifnet *)arg;
	struct switch_softc	*sc;
	struct switch_port	*swpo;

	swpo = (struct switch_port *)ifp->if_switch;
	sc = swpo->swpo_switch;
	if (swpo->swpo_flags & IFBIF_LOCAL)
		switch_port_unset_local(sc, swpo);

	ifp->if_switch = NULL;
	ifp->if_bridge_input = NULL;
	ifp->if_bridge_linkstate = NULL;
	bstp_destroy(&swpo->swpo_stp);

	if (ifp->if_type == IFT_ETHER)
		ifpromisc(ifp, 0);
	TAILQ_REMOVE(&sc->sc_swpo_list, swpo, swpo_list_next);
	free(swpo, M_DEVBUF);
}

int
switch_port_del(struct switch_softc *sc, struct ifbreq *req)
{
	struct switch_port	*swpo;
	struct ifnet		*ifs;
	int			 error = 0;

	TAILQ_FOREACH(swpo, &sc->sc_swpo_list, swpo_list_next) {
		if ((ifs = ifnet_byindex_ref(swpo->swpo_ifindex)) == NULL)
			continue;
		if (strncmp(ifs->if_xname, req->ifbr_ifsname, IFNAMSIZ) == 0)
			break;
		if_rele(ifs);
	}

	if (swpo) {
		switch_port_detach(ifs);
		if_rele(ifs);
		error = 0;
	} else
		error = ENOENT;

	return (error);
}

struct mbuf *
switch_port_ingress(struct switch_softc *sc, struct ifnet *src_if,
    struct mbuf *m)
{
	struct switch_port	*swpo;
	struct ether_header	 eh;

	swpo = (struct switch_port *)src_if->if_switch;

	if_inc_counter(sc->sc_if, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(sc->sc_if, IFCOUNTER_IBYTES, m->m_pkthdr.len);

	m_copydata(m, 0, ETHER_HDR_LEN, (caddr_t)&eh);
#if 0
	/* It's the "#if 0" because it doesn't test switch(4) with pf(4)
	 * or with ipsec(4).
	 */
	if ((m = bridge_ip((struct bridge_softc *)sc,
	    PF_IN, src_if, &eh, m)) == NULL) {
		sc->sc_if->if_ierrors++;
		return (NULL);
	}
#endif /* NPF */

	return (m);
}

static bool
switch_fragment(struct switch_softc *sc, struct ifnet *switch_if,
    struct ifnet *dst_if, struct ether_header *eh, struct mbuf *m)
{
	struct llc *llc;
	int snap;
	uint16_t ether_type;

	llc = NULL;
	snap = 0;
	ether_type = ntohs(eh->ether_type);
	if (ether_type >= ETHERMTU)
		return (false);

	llc = (struct llc *)(eh + 1);
	if (m->m_len >= ETHER_HDR_LEN + 8 && llc->llc_dsap == LLC_SNAP_LSAP &&
	    llc->llc_ssap == LLC_SNAP_LSAP && llc->llc_control == LLC_UI)
		snap = 1;

	DPRINTF("Ready to fragment!\n");
	return (bridge_fragment(dst_if, &m, eh, snap, llc) == 0);
}

void
switch_port_egress(struct switch_softc *sc, struct switch_fwdp_queue *fwdp_q,
    struct mbuf *m)
{
	struct switch_port	*swpo;
	struct ifnet		*dst_if;
	struct mbuf		*mc;
	struct ether_header	 eh;
	int			 len, used = 0;

	if (sc->sc_if->if_bpf)
		ETHER_BPF_MTAP(sc->sc_if, m);

	DPRINTF("Ouuuuutttt!\n");
	m_copydata(m, 0, ETHER_HDR_LEN, (caddr_t)&eh);
	TAILQ_FOREACH(swpo, fwdp_q, swpo_fwdp_next) {

		DPRINTF("Check dst_if\n");
		if ((dst_if = ifnet_byindex_ref(swpo->swpo_ifindex)) == NULL)
			continue;

		DPRINTF("Check running\n");
		if ((dst_if->if_drv_flags & IFF_DRV_RUNNING) == 0)
			goto out;

		if (TAILQ_NEXT(swpo, swpo_fwdp_next) == NULL) {
			mc = m;
			used = 1;
		} else {
			mc = m_dup_pkt(m, ETHER_ALIGN, M_NOWAIT);
			DPRINTF("Aligned? %s\n", mc != NULL ? "Yes" : "No");
			if (mc == NULL)
				goto out;
		}

#if 0
		/* It's the "#if 0" because it doesn't test switch(4) with pf(4)
		 * or with ipsec(4).
		 */
		if ((mc = bridge_ip((struct bridge_softc *)sc,
		    PF_OUT, dst_if, &eh, mc)) == NULL) {
			sc->sc_if->if_ierrors++;
			goto out;
		}
#endif

		len = mc->m_pkthdr.len;
#if 0
#if NVLAN > 0
		if ((mc->m_flags & M_VLANTAG) &&
		    (dst_if->if_capabilities & IFCAP_VLAN_HWTAGGING) == 0)
			len += ETHER_VLAN_ENCAP_LEN;
#endif
#endif
		/*
		 * Only if egress port has local port capabilities, it doesn't
		 * need fragment because a frame sends up local network stack.
		 */
		if (!(swpo->swpo_flags & IFBIF_LOCAL) &&
		    ((len - ETHER_HDR_LEN) > dst_if->if_mtu)) {
			if (!switch_fragment(sc, sc->sc_if, dst_if, &eh, mc)) {
				DPRINTF("nope =(\n");
				goto out;
			}
		}

		switch_ifenqueue(sc, dst_if, mc,
		    (swpo->swpo_flags & IFBIF_LOCAL));
 out:

		if_rele(dst_if);
	}

	if (!used)
		m_freem(m);
}

int
switch_ifenqueue(struct switch_softc *sc, struct ifnet *ifp,
    struct mbuf *m, int local)
{
	struct ifnet		*ifs;
	int			 error;

	/* Loop prevention. */
	m->m_flags |= M_PROTO1;

	M_ASSERTPKTHDR(m);
	ifs = sc->sc_if;

	DPRINTF("Enqueue! local? %s\n", local ? "Yes" : "No");
	if (local) {
		m->m_pkthdr.rcvif = ifp;
		ifp->if_input(ifp, m);
	} else {
		IFQ_ENQUEUE(&ifp->if_snd, m, error);
		if (error) {
			if_inc_counter(ifs, IFCOUNTER_OERRORS, 1);
			return (error);
		}
		if_inc_counter(ifs, IFCOUNTER_OPACKETS, 1);
		if_inc_counter(ifs, IFCOUNTER_OBYTES, m->m_pkthdr.len);
	}

	return (0);
}

void
switch_port_ifb_start(struct ifnet *ifp)
{
	struct mbuf		*m;

	for (;;) {
		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			return;

		if (ifp->if_bpf)
			ETHER_BPF_MTAP(ifp, m);

		m->m_pkthdr.rcvif = ifp;
		ifp->if_input(ifp, m);
	}
}

/*
 * Flow Classifier
 */

int
switch_swfcl_dup(struct switch_flow_classify *from,
    struct switch_flow_classify *to)
{
	memset(to, 0, sizeof(*to));

	to->swfcl_flow_hash = from->swfcl_flow_hash;
	to->swfcl_metadata = from->swfcl_metadata;
	to->swfcl_cookie = from->swfcl_cookie;
	to->swfcl_table_id = from->swfcl_table_id;
	to->swfcl_in_port = from->swfcl_in_port;

	if (from->swfcl_tunnel) {
		to->swfcl_tunnel = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_tunnel == NULL)
			goto failed;
		memcpy(to->swfcl_tunnel, from->swfcl_tunnel,
		    sizeof(*from->swfcl_tunnel));
	}
	if (from->swfcl_ether) {
		to->swfcl_ether = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_ether == NULL)
			goto failed;
		memcpy(to->swfcl_ether, from->swfcl_ether,
		    sizeof(*from->swfcl_ether));
	}
	if (from->swfcl_vlan) {
		to->swfcl_vlan = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_vlan == NULL)
			goto failed;
		memcpy(to->swfcl_vlan, from->swfcl_vlan,
		    sizeof(*from->swfcl_vlan));
	}
	if (from->swfcl_ipv4) {
		to->swfcl_ipv4 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_ipv4 == NULL)
			goto failed;
		memcpy(to->swfcl_ipv4, from->swfcl_ipv4,
		    sizeof(*from->swfcl_ipv4));
	}
	if (from->swfcl_ipv6) {
		to->swfcl_ipv6 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_ipv6 == NULL)
			goto failed;
		memcpy(to->swfcl_ipv6, from->swfcl_ipv6,
		    sizeof(*from->swfcl_ipv6));
	}
	if (from->swfcl_arp) {
		to->swfcl_arp = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_arp == NULL)
			goto failed;
		memcpy(to->swfcl_arp, from->swfcl_arp,
		    sizeof(*from->swfcl_arp));

	}
	if (from->swfcl_nd6) {
		to->swfcl_nd6 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_nd6 == NULL)
			goto failed;
		memcpy(to->swfcl_nd6, from->swfcl_nd6,
		    sizeof(*from->swfcl_nd6));
	}
	if (from->swfcl_icmpv4) {
		to->swfcl_icmpv4 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_icmpv4 == NULL)
			goto failed;
		memcpy(to->swfcl_icmpv4, from->swfcl_icmpv4,
		    sizeof(*from->swfcl_icmpv4));
	}
	if (from->swfcl_icmpv6) {
		to->swfcl_icmpv6 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_icmpv6 == NULL)
			goto failed;
		memcpy(to->swfcl_icmpv6, from->swfcl_icmpv6,
		    sizeof(*from->swfcl_icmpv6));
	}
	if (from->swfcl_tcp) {
		to->swfcl_tcp = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_tcp == NULL)
			goto failed;
		memcpy(to->swfcl_tcp, from->swfcl_tcp,
		    sizeof(*from->swfcl_tcp));
	}
	if (from->swfcl_udp) {
		to->swfcl_udp = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_udp == NULL)
			goto failed;
		memcpy(to->swfcl_udp, from->swfcl_udp,
		    sizeof(*from->swfcl_udp));
	}
	if (from->swfcl_sctp) {
		to->swfcl_sctp = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (to->swfcl_sctp == NULL)
			goto failed;
		memcpy(to->swfcl_sctp, from->swfcl_sctp,
		    sizeof(*from->swfcl_sctp));
	}

	return (0);
 failed:
	switch_swfcl_free(to);
	return (ENOBUFS);
}

void
switch_swfcl_free(struct switch_flow_classify *swfcl)
{
	if (swfcl->swfcl_tunnel)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_tunnel);
	if (swfcl->swfcl_ether)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_ether);
	if (swfcl->swfcl_vlan)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_vlan);
	if (swfcl->swfcl_ipv4)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_ipv4);
	if (swfcl->swfcl_ipv6)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_ipv6);
	if (swfcl->swfcl_arp)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_arp);
	if (swfcl->swfcl_nd6)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_nd6);
	if (swfcl->swfcl_icmpv4)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_icmpv4);
	if (swfcl->swfcl_icmpv6)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_icmpv6);
	if (swfcl->swfcl_tcp)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_tcp);
	if (swfcl->swfcl_udp)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_udp);
	if (swfcl->swfcl_sctp)
		uma_zfree(V_swfcl_zone, swfcl->swfcl_sctp);

	memset(swfcl, 0, sizeof(*swfcl));
}

struct mbuf *
switch_flow_classifier_udp(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct udphdr	*uh;

	swfcl->swfcl_udp = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_udp == NULL) {
		m_freem(m);
		return (NULL);
	}

	if (m->m_len < (*offset + sizeof(*uh)) &&
	    (m = m_pullup(m, *offset + sizeof(*uh))) == NULL)
		return (NULL);

	uh = (struct udphdr *)((m)->m_data + *offset);

	swfcl->swfcl_udp->udp_src = uh->uh_sport;
	swfcl->swfcl_udp->udp_dst = uh->uh_dport;

	return (m);
}

struct mbuf *
switch_flow_classifier_tcp(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct tcphdr	*th;

	swfcl->swfcl_tcp = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_tcp == NULL) {
		m_freem(m);
		return (NULL);
	}

	if (m->m_len < (*offset + sizeof(*th)) &&
	    (m = m_pullup(m, *offset + sizeof(*th))) == NULL)
		return (NULL);

	th = (struct tcphdr *)((m)->m_data + *offset);

	swfcl->swfcl_tcp->tcp_src = th->th_sport;
	swfcl->swfcl_tcp->tcp_dst = th->th_dport;
	swfcl->swfcl_tcp->tcp_flags = th->th_flags;

	return (m);
}

struct mbuf *
switch_flow_classifier_icmpv4(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct icmp	*icmp;

	swfcl->swfcl_icmpv4 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_icmpv4 == NULL) {
		m_freem(m);
		return (NULL);
	}

	if (m->m_len < (*offset + ICMP_MINLEN) &&
	    (m = m_pullup(m, (*offset + ICMP_MINLEN))) == NULL)
		return (NULL);

	icmp = (struct icmp *)((m)->m_data + *offset);

	swfcl->swfcl_icmpv4->icmpv4_type = icmp->icmp_type;
	swfcl->swfcl_icmpv4->icmpv4_code = icmp->icmp_code;

	return (m);
}

#ifdef INET6
struct mbuf *
switch_flow_classifier_nd6(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct icmp6_hdr		*icmp6;
	struct nd_neighbor_advert	*nd_na;
	struct nd_neighbor_solicit	*nd_ns;
	union nd_opts			 ndopts;
	uint8_t				*lladdr;
	int				 lladdrlen;
	int				 icmp6len = m->m_pkthdr.len - *offset;

	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, *offset, sizeof(*icmp6));
	if (icmp6 == NULL)
		goto failed;

	switch (icmp6->icmp6_type) {
	case ND_NEIGHBOR_ADVERT:
		if (icmp6len < sizeof(struct nd_neighbor_advert))
			goto failed;
		break;
	case ND_NEIGHBOR_SOLICIT:
		if (icmp6len < sizeof(struct nd_neighbor_solicit))
			goto failed;
		break;
	}

	swfcl->swfcl_nd6 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_nd6 == NULL)
		goto failed;

	switch (icmp6->icmp6_type) {
	case ND_NEIGHBOR_ADVERT:
		IP6_EXTHDR_GET(nd_na, struct nd_neighbor_advert *, m,
		    *offset, icmp6len);

		if (nd_na == NULL)
			goto failed;

		swfcl->swfcl_nd6->nd6_target = nd_na->nd_na_target;
		icmp6len -= sizeof(*nd_na);
		nd6_option_init(nd_na + 1, icmp6len, &ndopts);
		if (nd6_options(&ndopts) < 0)
			goto failed;

		if (!ndopts.nd_opts_tgt_lladdr)
			goto failed;

		lladdr = (char *)(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = (ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3) - 2;

		/* switch(4) only supports Ethernet interfaces */
		if (lladdrlen != ETHER_ADDR_LEN)
			goto failed;
		memcpy(swfcl->swfcl_nd6->nd6_lladdr, lladdr, ETHER_ADDR_LEN);
		break;
	case ND_NEIGHBOR_SOLICIT:
		IP6_EXTHDR_GET(nd_ns, struct nd_neighbor_solicit *, m,
		    *offset, icmp6len);
		if (nd_ns == NULL)
			goto failed;
		swfcl->swfcl_nd6->nd6_target = nd_ns->nd_ns_target;
		icmp6len -= sizeof(*nd_ns);

		nd6_option_init(nd_ns + 1, icmp6len, &ndopts);
		if (nd6_options(&ndopts) < 0)
			goto failed;

		if (!ndopts.nd_opts_src_lladdr)
			goto failed;
		lladdr = (char *)(ndopts.nd_opts_src_lladdr + 1);
		lladdrlen = (ndopts.nd_opts_src_lladdr->nd_opt_len << 3) - 2;

		/* switch(4) only supports Ethernet interfaces */
		if (lladdrlen != ETHER_ADDR_LEN)
			goto failed;
		memcpy(swfcl->swfcl_nd6->nd6_lladdr, lladdr, ETHER_ADDR_LEN);

		break;
	}

	return (m);

 failed:
	m_freem(m);
	return (NULL);
}

struct mbuf *
switch_flow_classifier_icmpv6(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct icmp6_hdr	*icmp6;

	swfcl->swfcl_icmpv6 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_icmpv6 == NULL) {
		m_freem(m);
		return (NULL);
	}

	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, *offset, sizeof(*icmp6));
	if (icmp6 == NULL)
		return (NULL); /* m was already freed */

	swfcl->swfcl_icmpv6->icmpv6_type = icmp6->icmp6_type;
	swfcl->swfcl_icmpv6->icmpv6_code = icmp6->icmp6_code;

	switch (icmp6->icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
		return switch_flow_classifier_nd6(m, offset, swfcl);
	}

	return (m);
}
#endif /* INET6 */

struct mbuf *
switch_flow_classifier_ipv4(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct ip	*ip;

	swfcl->swfcl_ipv4 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_ipv4 == NULL) {
		m_freem(m);
		return (NULL);
	}

	if (m->m_len < (*offset + sizeof(*ip)) &&
	    (m = m_pullup(m, *offset + sizeof(*ip))) == NULL)
		return (NULL);

	ip = (struct ip *)((m)->m_data + *offset);

	swfcl->swfcl_ipv4->ipv4_tos = ip->ip_tos;
	swfcl->swfcl_ipv4->ipv4_ttl = ip->ip_ttl;
	swfcl->swfcl_ipv4->ipv4_proto = ip->ip_p;

	memcpy(&swfcl->swfcl_ipv4->ipv4_src, &ip->ip_src.s_addr,
	    sizeof(uint32_t));
	memcpy(&swfcl->swfcl_ipv4->ipv4_dst, &ip->ip_dst.s_addr,
	    sizeof(uint32_t));

	*offset += (ip->ip_hl << 2);

	switch (ip->ip_p) {
	case IPPROTO_UDP:
		return switch_flow_classifier_udp(m, offset, swfcl);
	case IPPROTO_TCP:
		return switch_flow_classifier_tcp(m, offset, swfcl);
	case IPPROTO_ICMP:
		return switch_flow_classifier_icmpv4(m, offset, swfcl);
	}

	return (m);
}

#ifdef INET6
struct mbuf *
switch_flow_classifier_ipv6(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct ip6_hdr	*ip6;

	swfcl->swfcl_ipv6 = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_ipv6 == NULL) {
		m_freem(m);
		return (NULL);
	}

	if (m->m_len < (*offset + sizeof(*ip6)) &&
	    (m = m_pullup(m, *offset + sizeof(*ip6))) == NULL)
		return (NULL);

	ip6 = (struct ip6_hdr *)((m)->m_data + *offset);

	swfcl->swfcl_ipv6->ipv6_src = ip6->ip6_src;
	swfcl->swfcl_ipv6->ipv6_dst = ip6->ip6_dst;
	swfcl->swfcl_ipv6->ipv6_flow_label =
	    (ip6->ip6_flow & IPV6_FLOWLABEL_MASK);
	swfcl->swfcl_ipv6->ipv6_tclass = (ntohl(ip6->ip6_flow) >> 20);
	swfcl->swfcl_ipv6->ipv6_hlimit = ip6->ip6_hlim;
	swfcl->swfcl_ipv6->ipv6_nxt = ip6->ip6_nxt;

	*offset += sizeof(*ip6);

	switch (ip6->ip6_nxt) {
	case IPPROTO_UDP:
		return switch_flow_classifier_udp(m, offset, swfcl);
	case IPPROTO_TCP:
		return switch_flow_classifier_tcp(m, offset, swfcl);
	case IPPROTO_ICMPV6:
		return switch_flow_classifier_icmpv6(m, offset, swfcl);
	}

	return (m);
}
#endif /* INET6 */

struct mbuf *
switch_flow_classifier_arp(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct ether_arp	*ea;

	swfcl->swfcl_arp = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_arp == NULL) {
		m_freem(m);
		return (NULL);
	}

	if (m->m_len < (*offset + sizeof(*ea)) &&
	    (m = m_pullup(m, *offset + sizeof(*ea))) == NULL)
		return (NULL);

	ea = (struct ether_arp *)((m)->m_data + *offset);

	swfcl->swfcl_arp->_arp_op = ea->arp_op;

	memcpy(swfcl->swfcl_arp->arp_sha, &ea->arp_sha, ETHER_ADDR_LEN);
	memcpy(swfcl->swfcl_arp->arp_tha, &ea->arp_tha, ETHER_ADDR_LEN);
	memcpy(&swfcl->swfcl_arp->arp_sip, &ea->arp_spa, sizeof(uint32_t));
	memcpy(&swfcl->swfcl_arp->arp_tip, &ea->arp_tpa, sizeof(uint32_t));

	return (m);
}

struct mbuf *
switch_flow_classifier_ether(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct ether_header		*eh;
	struct ether_vlan_header	*evl;
	uint16_t			 ether_type;

	swfcl->swfcl_ether = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_ether == NULL) {
		m_freem(m);
		return (NULL);
	}

	if (m->m_len < sizeof(*eh) && (m = m_pullup(m, sizeof(*eh))) == NULL)
		return (NULL);
	eh = mtod(m, struct ether_header *);

	memcpy(swfcl->swfcl_ether->eth_src, eh->ether_shost, ETHER_ADDR_LEN);
	memcpy(swfcl->swfcl_ether->eth_dst, eh->ether_dhost, ETHER_ADDR_LEN);

	if ((m->m_flags & M_VLANTAG) ||
	    (ntohs(eh->ether_type) == ETHERTYPE_VLAN) ||
	    (ntohs(eh->ether_type) == ETHERTYPE_QINQ)) {
		swfcl->swfcl_vlan = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
		if (swfcl->swfcl_vlan == NULL) {
			m_freem(m);
			return (NULL);
		}
	}

	if (m->m_flags & M_VLANTAG) {
		/*
		 * Hardware VLAN tagging is only supported for 801.1Q VLAN,
		 * but not for 802.1ad QinQ.
		 */
		swfcl->swfcl_vlan->vlan_tpid = htons(ETHERTYPE_VLAN);
		swfcl->swfcl_vlan->vlan_vid =
		    htons(EVL_VLANOFTAG(m->m_pkthdr.ether_vtag));
		swfcl->swfcl_vlan->vlan_pcp =
		    EVL_PRIOFTAG(m->m_pkthdr.ether_vtag);
		ether_type = eh->ether_type;
		*offset += sizeof(*eh);
	} else if (ntohs(eh->ether_type) == ETHERTYPE_VLAN) {
		if (m->m_len < sizeof(*evl) &&
		    (m = m_pullup(m, sizeof(*evl))) == NULL)
			return (NULL);
		evl = mtod(m, struct ether_vlan_header *);

		/*
		 * Software VLAN tagging is currently only supported for
		 * 801.1Q VLAN, but not for 802.1ad QinQ.
		 */
		swfcl->swfcl_vlan->vlan_tpid = htons(ETHERTYPE_VLAN);
		swfcl->swfcl_vlan->vlan_vid =
		    (evl->evl_tag & htons(EVL_VLID_MASK));
		swfcl->swfcl_vlan->vlan_pcp =
		    EVL_PRIOFTAG(ntohs(evl->evl_tag));
		ether_type = evl->evl_proto;
		*offset += sizeof(*evl);
	} else {
		ether_type = eh->ether_type;
		*offset += sizeof(*eh);
	}

	swfcl->swfcl_ether->eth_type = ether_type;

	ether_type = ntohs(ether_type);
	switch (ether_type) {
	case ETHERTYPE_ARP:
		return switch_flow_classifier_arp(m, offset, swfcl);
	case ETHERTYPE_IP:
		return switch_flow_classifier_ipv4(m, offset, swfcl);
#ifdef INET6
	case ETHERTYPE_IPV6:
		return switch_flow_classifier_ipv6(m, offset, swfcl);
#endif /* INET6 */
	case ETHERTYPE_MPLS:
		/* unsupported yet */
		break;
	}

	return (m);
}

#if 0
struct mbuf *
switch_flow_classifier_tunnel(struct mbuf *m, int *offset,
    struct switch_flow_classify *swfcl)
{
	struct bridge_tunneltag	*brtag;

	if ((brtag = bridge_tunnel(m)) == NULL)
		goto out;

	if ((brtag->brtag_peer.sa.sa_family != AF_INET) &&
	    (brtag->brtag_peer.sa.sa_family != AF_INET6))
		goto out;

	swfcl->swfcl_tunnel = uma_zalloc(V_swfcl_zone, M_NOWAIT|M_ZERO);
	if (swfcl->swfcl_tunnel == NULL) {
		m_freem(m);
		return (NULL);
	}

	swfcl->swfcl_tunnel->tun_af = brtag->brtag_peer.sa.sa_family;
	swfcl->swfcl_tunnel->tun_key = htobe64(brtag->brtag_id);
	if (swfcl->swfcl_tunnel->tun_af == AF_INET) {
		swfcl->swfcl_tunnel->tun_ipv4_src =
		    brtag->brtag_local.sin.sin_addr;
		swfcl->swfcl_tunnel->tun_ipv4_dst =
		    brtag->brtag_peer.sin.sin_addr;
	} else {
		swfcl->swfcl_tunnel->tun_ipv6_src =
		    brtag->brtag_local.sin6.sin6_addr;
		swfcl->swfcl_tunnel->tun_ipv6_dst =
		    brtag->brtag_peer.sin6.sin6_addr;
	}
	bridge_tunneluntag(m);
 out:
	return switch_flow_classifier_ether(m, offset, swfcl);
}
#endif

struct mbuf *
switch_flow_classifier(struct mbuf *m, uint32_t in_port,
    struct switch_flow_classify *swfcl)
{
	int	 offset = 0;

	memset(swfcl, 0, sizeof(*swfcl));
	swfcl->swfcl_in_port = in_port;

#if 0
	return switch_flow_classifier_tunnel(m, &offset, swfcl);
#else
	return switch_flow_classifier_ether(m, &offset, swfcl);
#endif
}

void
switch_flow_classifier_dump(struct switch_softc *sc,
    struct switch_flow_classify *swfcl)
{
	char	saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];

	log(LOG_DEBUG, "%s: ", sc->sc_if->if_xname);
	log(LOG_DEBUG, "in_port(%u),", swfcl->swfcl_in_port);

	if (swfcl->swfcl_tunnel) {
		if (swfcl->swfcl_tunnel->tun_af == AF_INET) {
			inet_ntop(AF_INET,
			    (void *)&swfcl->swfcl_tunnel->tun_ipv4_src,
			    saddr, sizeof(saddr));
			inet_ntop(AF_INET,
			    (void *)&swfcl->swfcl_tunnel->tun_ipv4_dst,
			    daddr, sizeof(daddr));
			log(LOG_DEBUG, "tun_ipv4_src(%s),tun_ipv4_dst(%s),"
			    "tun_id(%" PRIu64 "),", saddr, daddr,
			    be64toh(swfcl->swfcl_tunnel->tun_key));
		} else if (swfcl->swfcl_tunnel->tun_af == AF_INET6) {
			inet_ntop(AF_INET6,
			    (void *)&swfcl->swfcl_tunnel->tun_ipv6_src,
			    saddr, sizeof(saddr));
			inet_ntop(AF_INET6,
			    (void *)&swfcl->swfcl_tunnel->tun_ipv6_dst,
			    daddr, sizeof(daddr));
			log(LOG_DEBUG, "tun_ipv6_src(%s) tun_ipv6_dst(%s),"
			    "tun_id(%" PRIu64 "),", saddr, daddr,
			    be64toh(swfcl->swfcl_tunnel->tun_key));
		}
	}

	if (swfcl->swfcl_vlan) {
		log(LOG_DEBUG, "vlan_tpid(0x%0x4x),vlan_pcp(%u),vlan_vid(%u),",
		    ntohs(swfcl->swfcl_vlan->vlan_tpid),
		    swfcl->swfcl_vlan->vlan_pcp,
		    ntohs(swfcl->swfcl_vlan->vlan_vid));
	}

	if (swfcl->swfcl_ether) {
		log(LOG_DEBUG, "eth_dst(%s),eth_src(%s),eth_type(0x%04x)",
		    ether_sprintf(swfcl->swfcl_ether->eth_dst),
		    ether_sprintf(swfcl->swfcl_ether->eth_src),
		    ntohs(swfcl->swfcl_ether->eth_type));
	}

	if (swfcl->swfcl_arp) {
		inet_ntop(AF_INET, (void *)&swfcl->swfcl_arp->arp_sip,
		    saddr, sizeof(saddr));
		inet_ntop(AF_INET, (void *)&swfcl->swfcl_arp->arp_tip,
		    daddr, sizeof(daddr));
		log(LOG_DEBUG, "arp_op(%x),arp_tha(%s),arp_sha(%s),arp_sip(%s),"
		    "arp_tip(%s),", swfcl->swfcl_arp->_arp_op,
		    ether_sprintf(swfcl->swfcl_arp->arp_tha),
		    ether_sprintf(swfcl->swfcl_arp->arp_sha), saddr, daddr);
	}

	if (swfcl->swfcl_ipv4) {
		inet_ntop(AF_INET, (void *)&swfcl->swfcl_ipv4->ipv4_src,
		    saddr, sizeof(saddr));
		inet_ntop(AF_INET, (void *)&swfcl->swfcl_ipv4->ipv4_dst,
		    daddr, sizeof(daddr));
		log(LOG_DEBUG, "ip_proto(%u),ip_tos(%u),ip_ttl(%u),ip_src(%s),"
		    "ip_dst(%s),", swfcl->swfcl_ipv4->ipv4_proto,
		    swfcl->swfcl_ipv4->ipv4_tos, swfcl->swfcl_ipv4->ipv4_ttl,
		    saddr, daddr);
	}

	if (swfcl->swfcl_ipv6) {
		inet_ntop(AF_INET6, (void *)&swfcl->swfcl_ipv6->ipv6_src,
		    saddr, sizeof(saddr));
		inet_ntop(AF_INET6, (void *)&swfcl->swfcl_ipv6->ipv6_dst,
		    daddr, sizeof(daddr));
		log(LOG_DEBUG, "ip6_nxt(%u),ip6_flow_label(%u),ip6_tclass(%d),"
		    "ip6_hlimit(%u),ip6_src(%s),ip6_dst(%s),",
		    swfcl->swfcl_ipv6->ipv6_nxt,
		    ntohl(swfcl->swfcl_ipv6->ipv6_flow_label),
		    swfcl->swfcl_ipv6->ipv6_tclass,
		    swfcl->swfcl_ipv6->ipv6_hlimit, saddr, daddr);
	}

	if (swfcl->swfcl_icmpv4) {
		log(LOG_DEBUG, "icmp_type(%u),icmp_code(%u),",
		    swfcl->swfcl_icmpv4->icmpv4_type,
		    swfcl->swfcl_icmpv4->icmpv4_code);
	}

	if (swfcl->swfcl_icmpv6) {
		log(LOG_DEBUG, "icmp6_type(%u),icmp6_code(%u),",
		    swfcl->swfcl_icmpv6->icmpv6_type,
		    swfcl->swfcl_icmpv6->icmpv6_code);
	}

	if (swfcl->swfcl_nd6) {
		inet_ntop(AF_INET6, (void *)&swfcl->swfcl_nd6->nd6_target,
		    saddr, sizeof(saddr));
		log(LOG_DEBUG, "nd_target(%s),nd_lladdr(%s),", saddr,
		    ether_sprintf(swfcl->swfcl_nd6->nd6_lladdr));
	}

	if (swfcl->swfcl_tcp) {
		log(LOG_DEBUG, "tcp_src(%u),tcp_dst(%u),tcp_flags(%x),",
		    ntohs(swfcl->swfcl_tcp->tcp_src),
		    ntohs(swfcl->swfcl_tcp->tcp_dst),
		    swfcl->swfcl_tcp->tcp_flags);
	}

	if (swfcl->swfcl_udp) {
		log(LOG_DEBUG, "udp_src(%u),udp_dst(%u),",
		    ntohs(swfcl->swfcl_udp->udp_src),
		    ntohs(swfcl->swfcl_udp->udp_dst));
	}

	log(LOG_DEBUG, "\n");
}

void
switch_mtap(struct bpf_if *arg, struct mbuf *m, int dir, uint64_t datapath_id)
{
	struct dlt_openflow_hdr	 of;

	of.of_datapath_id = htobe64(datapath_id);
	of.of_direction = htonl(dir == BPF_D_IN ?
	    DLT_OPENFLOW_TO_SWITCH : DLT_OPENFLOW_TO_CONTROLLER);

	bpf_mtap2(arg, (void *)&of, sizeof(of), m);
}

int
ofp_split_mbuf(struct mbuf *m, struct mbuf **mtail)
{
	uint16_t		 ohlen;

	*mtail = NULL;

 again:
	/* We need more data. */
	M_ASSERTPKTHDR(m);
	if (m->m_pkthdr.len < sizeof(struct ofp_header))
		return (-1);

	m_copydata(m, offsetof(struct ofp_header, oh_length), sizeof(ohlen),
	    (caddr_t)&ohlen);
	ohlen = ntohs(ohlen);

	/* We got an invalid packet header, skip it. */
	if (ohlen < sizeof(struct ofp_header)) {
		m_adj(m, sizeof(struct ofp_header));
		goto again;
	}

	/* Nothing to split. */
	if (m->m_pkthdr.len == ohlen)
		return (0);
	else if (m->m_pkthdr.len < ohlen)
		return (-1);

	*mtail = m_split(m, ohlen, M_NOWAIT);
	/* No memory, try again later. */
	if (*mtail == NULL)
		return (-1);

	return (0);
}
