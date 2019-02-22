/*	$OpenBSD: switchctl.c,v 1.14 2018/12/28 14:32:47 bluhm Exp $	*/

/*
 * Copyright (c) 2016 Kazuya GODA <goda@openbsd.org>
 * Copyright (c) 2015, 2016 YASUOKA Masahiko <yasuoka@openbsd.org>
 * Copyright (c) 2015, 2016 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#ifdef __FreeBSD__
#include <sys/filio.h>
#include <sys/sockio.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/selinfo.h>
#include <sys/rwlock.h>
#include <sys/proc.h>

#include <net/if.h>
#ifndef __FreeBSD__
#include <net/rtable.h>
#else
#include <net/if_var.h>
#endif

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/bridgestp.h>
#include <net/if_clone.h>
#include <net/if_switch.h>

extern struct rwlock	switch_ifs_lk;

/*
 * device part of switch(4)
 */
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/vnode.h>

struct switch_softc *switch_dev2sc(struct cdev *);
int	switchopen(struct cdev *, int, int, struct thread *);
int	switchread(struct cdev *, struct uio *, int);
int	switchwrite(struct cdev *, struct uio *, int);
int	switchioctl(struct cdev *, u_long, caddr_t, int, struct thread *);
int	switchclose(struct cdev *, int, int, struct thread *);
int	switchpoll(struct cdev *, int, struct thread *);
int	switchkqfilter(struct cdev *, struct knote *);
void	filt_switch_rdetach(struct knote *);
int	filt_switch_read(struct knote *, long);
void	filt_switch_wdetach(struct knote *);
int	filt_switch_write(struct knote *, long);
int	switch_dev_output(struct switch_softc *, struct mbuf *);
void	switch_dev_wakeup(struct switch_softc *);

struct filterops switch_rd_filtops = {
	.f_isfd = 1,
	.f_attach = NULL,
	.f_detach = filt_switch_rdetach,
	.f_event = filt_switch_read
};
struct filterops switch_wr_filtops = {
	.f_isfd = 1,
	.f_attach = NULL,
	.f_detach = filt_switch_wdetach,
	.f_event = filt_switch_write
};

struct cdevsw switch_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	D_NEEDMINOR,
	.d_open =	switchopen,
	.d_close =	switchclose,
	.d_read =	switchread,
	.d_write =	switchwrite,
	.d_ioctl =	switchioctl,
	.d_poll =	switchpoll,
	.d_kqfilter =	switchkqfilter,
	.d_name =	if_switchname,
};

struct switch_softc *
switch_dev2sc(struct cdev *dev)
{

	return (dev->si_drv1);
}

int
switchopen(struct cdev *dev, int flags, int mode, struct thread *td)
{
	struct switch_softc	*sc;
	struct mtx		*mtx;
	char			 name[IFNAMSIZ];
	int			 namelen, rv, s, error = 0;

	if ((sc = switch_dev2sc(dev)) == NULL) {
		namelen = snprintf(name, sizeof(name), "switch%d",
		    dev2unit(dev));
		rv = if_clone_create(name, namelen, NULL);
		if (rv != 0)
			return (rv);
		if ((sc = switch_dev2sc(dev)) == NULL)
			return (ENXIO);
	}

	rw_wlock(&switch_ifs_lk);
	if (sc->sc_swdev != NULL) {
		error = EBUSY;
		goto failed;
	}

	if ((sc->sc_swdev = malloc(sizeof(struct switch_dev), M_DEVBUF,
	    M_NOWAIT|M_ZERO)) == NULL ) {
		error = ENOBUFS;
		goto failed;
	}

	mtx = &sc->sc_swdev->swdev_mtx;
	mtx_init(mtx, "switchdev mtx", NULL, MTX_DEF);
	knlist_init_mtx(&sc->sc_swdev->swdev_rsel.si_note, mtx);
	knlist_init_mtx(&sc->sc_swdev->swdev_wsel.si_note, mtx);

	s = splnet();
	mbufq_init(&sc->sc_swdev->swdev_outq, 128);

	sc->sc_swdev->swdev_output = switch_dev_output;
	if (sc->sc_capabilities & SWITCH_CAP_OFP)
		swofp_init(sc);

	splx(s);

 failed:
	rw_wunlock(&switch_ifs_lk);
	return (error);

}

int
switchread(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct switch_softc	*sc;
	struct mbuf		*m;
	u_int			 len;
	int			 s, error = 0;

	sc = switch_dev2sc(dev);
	if (sc == NULL)
		return (ENXIO);

	if (sc->sc_swdev->swdev_lastm != NULL) {
		m = sc->sc_swdev->swdev_lastm;
		sc->sc_swdev->swdev_lastm = NULL;
		goto skip_dequeue;
	}

 dequeue_next:
	s = splnet();
	while ((m = mbufq_dequeue(&sc->sc_swdev->swdev_outq)) == NULL) {
		if ((ioflag & IO_NDELAY) != 0) {
			error = EWOULDBLOCK;
			goto failed;
		}
		sc->sc_swdev->swdev_waiting = 1;
		error = tsleep(sc, (PZERO + 1)|PCATCH, "switchread", 0);
		if (error != 0)
			goto failed;
		/* sc might be deleted while sleeping */
		sc = switch_dev2sc(dev);
		if (sc == NULL) {
			error = ENXIO;
			goto failed;
		}
	}
	splx(s);

 skip_dequeue:
	while (uio->uio_resid > 0) {
		len = ulmin(uio->uio_resid, m->m_len);
		if ((error = uiomove(mtod(m, caddr_t), len, uio)) != 0) {
			/* Save it so user can recover from EFAULT. */
			sc->sc_swdev->swdev_lastm = m;
			return (error);
		}

		/* Handle partial reads. */
		if (uio->uio_resid == 0) {
			if (len < m->m_len)
				m_adj(m, len);
			else
				m = m_free(m);
			sc->sc_swdev->swdev_lastm = m;
			break;
		}

		/*
		 * After consuming data from this mbuf test if we
		 * have to dequeue a new chain.
		 */
		m = m_free(m);
		if (m == NULL)
			goto dequeue_next;
	}

	return (0);
failed:
	splx(s);
	return (error);
}

int
switchwrite(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct switch_softc	*sc = NULL;
	struct mbuf		*m, *n, *mhead, *mtail = NULL;
	int			 s, error, trailing;
	size_t			 len;

	if (uio->uio_resid == 0)
		return (0);

	len = uio->uio_resid;

	sc = switch_dev2sc(dev);
	if (sc == NULL)
		return (ENXIO);

	if (sc->sc_swdev->swdev_inputm == NULL) {
		MGETHDR(m, M_NOWAIT, MT_DATA);
		if (m == NULL)
			return (ENOBUFS);
		if (len >= MHLEN) {
			MCLGETI(m, M_NOWAIT, NULL, len);
			if ((m->m_flags & M_EXT) == 0) {
				m_free(m);
				return (ENOBUFS);
			}
		}
		mhead = m;

		/* m_trailingspace() uses this to calculate space. */
		m->m_len = 0;
	} else {
		/* Recover the mbuf from the last write and get its tail. */
		mhead = sc->sc_swdev->swdev_inputm;
		for (m = mhead; m->m_next != NULL; m = m->m_next)
			/* NOTHING */;

		sc->sc_swdev->swdev_inputm = NULL;
	}
	M_ASSERTPKTHDR(mhead);

	while (len) {
		trailing = ulmin(M_TRAILINGSPACE(m), len);
		if ((error = uiomove(mtod(m, caddr_t) + m->m_len, trailing,
		    uio)) != 0)
			goto save_return;

		len -= trailing;
		mhead->m_pkthdr.len += trailing;
		m->m_len += trailing;
		if (len == 0)
			break;

		MGET(n, M_NOWAIT, MT_DATA);
		if (n == NULL) {
			error = ENOBUFS;
			goto save_return;
		}
		if (len >= MLEN) {
			MCLGETI(n, M_NOWAIT, NULL, len);
			if ((n->m_flags & M_EXT) == 0) {
				m_free(n);
				error = ENOBUFS;
				goto save_return;
			}
		}
		n->m_len = 0;

		m->m_next = n;
		m = n;
	}

	/* Loop until there is no more complete OFP packets. */
	while (ofp_split_mbuf(mhead, &mtail) == 0) {
		s = splnet();
		sc->sc_swdev->swdev_input(sc, mhead);
		splx(s);

		/* We wrote everything, just quit. */
		if (mtail == NULL)
			return (0);

		mhead = mtail;
	}

	/* Save the head, because ofp_split_mbuf failed. */
	sc->sc_swdev->swdev_inputm = mhead;

	return (0);

 save_return:
	/* Save it so user can recover from errors later. */
	sc->sc_swdev->swdev_inputm = mhead;
	return (error);
}

int
switchioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags, struct thread *td)
{
	int			 error;

	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
	case FIONREAD:
		return (0);
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}

int
switchclose(struct cdev *dev, int flags, int mode, struct thread *td)
{

	switch_dev_destroy(switch_dev2sc(dev));
	return (0);
}

void
switch_dev_destroy(struct switch_softc *sc)
{

	if (sc->sc_swdev == NULL)
		return;
	rw_wlock(&switch_ifs_lk);
	if (sc->sc_swdev != NULL) {
		switch_dev_wakeup(sc);

		seldrain(&sc->sc_swdev->swdev_rsel);
		knlist_clear(&sc->sc_swdev->swdev_rsel.si_note, 0);
		knlist_destroy(&sc->sc_swdev->swdev_rsel.si_note);

		seldrain(&sc->sc_swdev->swdev_wsel);
		knlist_clear(&sc->sc_swdev->swdev_wsel.si_note, 0);
		knlist_destroy(&sc->sc_swdev->swdev_wsel.si_note);

		m_freem(sc->sc_swdev->swdev_lastm);
		m_freem(sc->sc_swdev->swdev_inputm);
		mbufq_drain(&sc->sc_swdev->swdev_outq);
		free(sc->sc_swdev, M_DEVBUF);
		sc->sc_swdev = NULL;
	}
	rw_wunlock(&switch_ifs_lk);
}

int
switchpoll(struct cdev *dev, int events, struct thread *td)
{
	int			 revents = 0;
	struct switch_softc	*sc = switch_dev2sc(dev);

	if (sc == NULL)
		return (ENXIO);

	if (events & (POLLIN | POLLRDNORM)) {
		if (mbufq_len(&sc->sc_swdev->swdev_outq) == 0 ||
		    sc->sc_swdev->swdev_lastm != NULL)
			revents |= events & (POLLIN | POLLRDNORM);
	}
	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);
	if (revents == 0) {
		if (events & (POLLIN | POLLRDNORM))
			selrecord(td, &sc->sc_swdev->swdev_rsel);
	}

	return (revents);
}

int
switchkqfilter(struct cdev *dev, struct knote *kn)
{
	struct switch_softc	*sc = switch_dev2sc(dev);
	struct knlist		*knlist;

	if (sc == NULL)
		return (ENXIO);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		knlist = &sc->sc_swdev->swdev_rsel.si_note;
		kn->kn_fop = &switch_rd_filtops;
		break;
	case EVFILT_WRITE:
		knlist = &sc->sc_swdev->swdev_wsel.si_note;
		kn->kn_fop = &switch_wr_filtops;
		break;
	default:
		return (EINVAL);
	}

	kn->kn_hook = sc;
	knlist_add(knlist, kn, 0);

	return (0);
}

void
filt_switch_rdetach(struct knote *kn)
{
	struct switch_softc	*sc = (struct switch_softc *)kn->kn_hook;

	if ((kn->kn_status & KN_DETACHED) != 0)
		return;

	knlist_remove(&sc->sc_swdev->swdev_rsel.si_note, kn, 0);
}

int
filt_switch_read(struct knote *kn, long hint)
{
	struct switch_softc	*sc = (struct switch_softc *)kn->kn_hook;

	if ((kn->kn_status & KN_DETACHED) != 0) {
		kn->kn_data = 0;
		return (1);
	}

	if (mbufq_len(&sc->sc_swdev->swdev_outq) == 0 ||
	    sc->sc_swdev->swdev_lastm != NULL) {
		kn->kn_data = mbufq_len(&sc->sc_swdev->swdev_outq) +
		    (sc->sc_swdev->swdev_lastm != NULL);
		return (1);
	}

	return (0);
}

void
filt_switch_wdetach(struct knote *kn)
{
	struct switch_softc	*sc = (struct switch_softc *)kn->kn_hook;

	if ((kn->kn_status & KN_DETACHED) != 0)
		return;

	knlist_remove(&sc->sc_swdev->swdev_wsel.si_note, kn, 0);
}

int
filt_switch_write(struct knote *kn, long hint)
{
	/* Always writable */
	return (1);
}

int
switch_dev_output(struct switch_softc *sc, struct mbuf *m)
{
	if (mbufq_enqueue(&sc->sc_swdev->swdev_outq, m) != 0)
		return (-1);
	switch_dev_wakeup(sc);

	return (0);
}

void
switch_dev_wakeup(struct switch_softc *sc)
{
	if (sc->sc_swdev->swdev_waiting) {
		sc->sc_swdev->swdev_waiting = 0;
		wakeup((caddr_t)sc);
	}
	selwakeup(&sc->sc_swdev->swdev_rsel);
}
