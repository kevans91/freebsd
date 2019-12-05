/*
 * Copyright (c) 2009 Theo de Raadt
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

/*
 * Copyright (c) 2018 Henning Matyschok
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_bridgevar.h>
#include <net/vnet.h>

/*
 * Virtual Ethernet interface, ported from OpenBSD. This interface
 * operates in conjunction with if_bridge(4).
 */

#define	vether_sdl(ifa) ((const struct sockaddr_dl *)(ifa)->ifa_addr)

#define	vether_lla(ifa) (vether_sdl(ifa)->sdl_data + vether_sdl(ifa)->sdl_nlen)

#define vether_lla_equal(ifa, lla) (	\
    (vether_sdl(ifa)->sdl_type == IFT_ETHER) && \
    (vether_sdl(ifa)->sdl_alen == sizeof(lla)) && \
    (bcmp(vether_lla(ifa), lla, sizeof(lla)) == 0))

struct vether_softc {
	struct ifmedia	sc_ifm;		/* fake media information */
	struct ifnet	*sc_ifp;	/* network interface. */
};
#define VETHER_IF_FLAGS		(IFF_SIMPLEX|IFF_BROADCAST|IFF_MULTICAST)
#define VETHER_IFCAP_FLAGS	(IFCAP_VLAN_MTU|IFCAP_JUMBO_MTU)
#define VETHER_IFM_FLAGS	(IFM_ETHER|IFM_AUTO)

static void	vether_init(void *);
static void	vether_stop(struct ifnet *, int);
static void	vether_start(struct ifnet *);

static int	vether_media_change(struct ifnet *);
static void	vether_media_status(struct ifnet *, struct ifmediareq *);
static int	vether_ioctl(struct ifnet *, u_long, caddr_t);

static int	vether_clone_create(struct if_clone *, int, caddr_t);
static void	vether_clone_destroy(struct ifnet *);

VNET_DEFINE(struct if_clone *, vether_cloner);
#define	V_vether_cloner	VNET(vether_cloner)

static const char vether_name[] = "vether";

static void
vnet_vether_init(const void *unused __unused)
{

	V_vether_cloner = if_clone_simple(vether_name,
	    vether_clone_create, vether_clone_destroy, 0);
}
VNET_SYSINIT(vnet_vether_init, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY,
    vnet_vether_init, NULL);

static void
vnet_vether_uninit(const void *unused __unused)
{

	if_clone_detach(V_vether_cloner);
}
VNET_SYSUNINIT(vnet_vether_uninit, SI_SUB_PSEUDO, SI_ORDER_ANY,
    vnet_vether_uninit, NULL);

static int
vether_mod_event(module_t mod, int event, void *data)
{
	int error;

	switch (event) {
	case MOD_LOAD:
	case MOD_UNLOAD:
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
	}

	return (error);
}

static moduledata_t vether_mod = {
	"if_vether",
	vether_mod_event,
	0
};
DECLARE_MODULE(if_vether, vether_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);

static int
vether_clone_create(struct if_clone *ifc, int unit, caddr_t data)
{
	struct vether_softc *sc;
	struct ifnet *ifp, *iter;
	/* XXX TODO: Use if_ethersubr to generate */
	uint8_t lla[ETHER_ADDR_LEN];

	/* Allocate software context. */
	sc = malloc(sizeof(struct vether_softc), M_DEVBUF,
	    M_WAITOK|M_ZERO);	/* can't fail */
	ifp = sc->sc_ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		free(sc, M_DEVBUF);
		return (ENOSPC);
	}
	if_initname(ifp, vether_name, unit);

	ifp->if_softc = sc;
	ifp->if_init = vether_init;
	ifp->if_ioctl = vether_ioctl;
	ifp->if_start = vether_start;

	ifp->if_flags = VETHER_IF_FLAGS;

	ifp->if_capabilities = VETHER_IFCAP_FLAGS;
	ifp->if_capenable = VETHER_IFCAP_FLAGS;

	ifmedia_init(&sc->sc_ifm, 0, vether_media_change,
	    vether_media_status);
	ifmedia_add(&sc->sc_ifm, VETHER_IFM_FLAGS, 0, NULL);
	ifmedia_set(&sc->sc_ifm, VETHER_IFM_FLAGS);

	/* create random LLA and initialize */
	lla[0] = 0x42;	/* 2nd bit denotes locally administered addr */
	lla[1] = 0x53;
again:

	/* map randomized postfix on LLA */
	arc4rand(&lla[2], sizeof(uint32_t), 0);
#if __FreeBSD_version >= 1300000
	IFNET_RLOCK();
#else
	IFNET_RLOCK_NOSLEEP();
#endif
#if __FreeBSD_version >= 1200064
	CK_STAILQ_FOREACH(iter, &V_ifnet, if_link) {
#else
	TAILQ_FOREACH(iter, &V_ifnet, if_link) {
#endif
		if (iter->if_type != IFT_ETHER)
			continue;

		if (vether_lla_equal(iter->if_addr, lla)) {
#if __FreeBSD_version >= 1300000
				IFNET_RLOCK();
#else
				IFNET_RLOCK_NOSLEEP();
#endif
			goto again;
		}
	}
#if __FreeBSD_version >= 1300000
	IFNET_RUNLOCK();
#else
	IFNET_RUNLOCK_NOSLEEP();
#endif


	ether_gen_addr(ifp, &hwaddr);
	ether_ifattach(ifp, hwaddr.octet);
	ifp->if_baudrate = 0;

	return (0);
}

static void
vether_clone_destroy(struct ifnet *ifp)
{
	struct vether_softc *sc;

	vether_stop(ifp, 1);

	ifp->if_flags &= ~IFF_UP;

	ether_ifdetach(ifp);

	if_free(ifp);

	sc = ifp->if_softc;
	free(sc, M_DEVBUF);
}

static int
vether_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct vether_softc *sc;
	struct ifreq *ifr;
	int error;

	sc = ifp->if_softc;
	ifr = (struct ifreq *)data;
	error = 0;
	switch (cmd) {
	case SIOCSIFMTU:
		if (ifr->ifr_mtu > ETHER_MAX_LEN_JUMBO)
			error = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCSIFMEDIA:	/* media types can't be changed */
	case SIOCGIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_ifm, cmd);
		break;
	case SIOCSIFFLAGS:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	case SIOCSIFPHYS:
		error = EOPNOTSUPP;
		break;
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}
	return (error);
}
static int
vether_media_change(struct ifnet *ifp)
{

	return (0);
}

static void
vether_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{

	ifmr->ifm_active = IFM_ETHER | IFM_AUTO;
	ifmr->ifm_status = IFM_AVALID | IFM_ACTIVE;
}

static void
vether_init(void *xsc)
{
	struct vether_softc *sc;
	struct ifnet *ifp;

	sc = (struct vether_softc *)xsc;
	ifp = sc->sc_ifp;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}

static void
vether_stop(struct ifnet *ifp, int disable)
{

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
}

/*
 * I/O.
 */

static void
vether_start(struct ifnet *ifp)
{
	struct mbuf *m;
	int error;

	if ((ifp->if_drv_flags & (IFF_DRV_RUNNING | IFF_DRV_OACTIVE)) !=
	    IFF_DRV_RUNNING)
		return;

	ifp->if_drv_flags |= IFF_DRV_OACTIVE;
	for (;;) {
		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			break;

		BPF_MTAP(ifp, m);

		/* do some statistics */
		if_inc_counter(ifp, IFCOUNTER_OBYTES, m->m_pkthdr.len);
		if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);

		/* discard, if not member of if_bridge(4) */
		if (ifp->if_bridge == NULL)
			m->m_pkthdr.rcvif = ifp;

		/*
		 * Three cases are considered here:
		 *
		 *  (a) Frame was tx'd by layer above.
		 *
		 *  (b) Frame was rx'd by link-layer.
		 *
		 *  (c) Data sink.
		 */
		if (m->m_pkthdr.rcvif == NULL) {
			/* broadcast frame by if_bridge(4) */

			m->m_pkthdr.rcvif = ifp;

			BRIDGE_OUTPUT(ifp, m, error);
			if (error != 0)
				m_freem(m);
		} else if (m->m_pkthdr.rcvif != ifp) {
			/* demultiplex any other frame */

			m->m_pkthdr.rcvif = ifp;

			(*ifp->if_input)(ifp, m);
		} else
			m_freem(m);
	}
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}
