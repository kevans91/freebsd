/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2008 Ed Schouten <ed@FreeBSD.org>
 * All rights reserved.
 *
 * Portions of this software were developed under sponsorship from Snow
 * B.V., the Netherlands.
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

#ifndef _SYS_TTY_H_
#define	_SYS_TTY_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/condvar.h>
#include <sys/selinfo.h>
#include <sys/_termios.h>
#include <sys/ttycom.h>
#include <sys/ttyqueue.h>

struct cdev;
struct file;
struct pgrp;
struct session;
struct ucred;

struct ttydevsw;

/*
 * Per-TTY structure, containing buffers, etc.
 *
 * Under the new locking model, the ttylock is mostly internal to ^/sys/kern.
 * It must be acquired when calling tty_rel_gone(), but for the most part
 * drivers will not touch it.  It is especially wrong for a driver to drop the
 * tty lock when entered via ttydevsw methods; it is sleepable so that drivers
 * do not need to drop it, keeping entry to tty methods from userland properly
 * blocked while the driver is operating.
 *
 * The lock that drivers may supply is now called the ttydisc lock, which
 * replaces most traditional usage of the ttylock in drivers.  As the name
 * implies, it must be held when calling ttydisc_* methods.  The exception is
 * when &Giant is passed to tty_alloc_mutex(); this is currently a special hack
 * put in place so that syscons can continue operating without the tty layer
 * attempting to acquire this sx before Giant.  syscons will become properly
 * locked in due time, but this is a more complicated feat.
 *
 * List of locks
 * (t)	locked by ttylock
 * (d)	locked by ttydisc lock
 * (l)	locked by tty_list_sx
 * (c)	const until freeing
 * (d+t) both locks must be held to write
 *
 * (d*) locking for tf_flags is more complex.  It is generally locked by the
 * ttydisc lock, but both locks must be held to mark some flags so that we
 * can do some unlocked reads safely with just one or the other.  Those flags
 * are annotated with a (t) to indicate that they require the ttylock as well.
*/
struct tty {
	struct mtx	*t_mtx;		/* Deprecated TTY lock (Giant). */
	struct sx	t_sxobj;	/* TTY lock (when not borrowing). */
	struct mtx	*t_discmtx;
	/* Per-TTY discipline lock (when not borrowing). */
	struct mtx	t_discmtxobj;
	TAILQ_ENTRY(tty) t_list;	/* (l) TTY list entry. */
	int		t_drainwait;	/* (d) TIOCDRAIN timeout seconds. */
	unsigned int	t_flags;	/* (d*) Terminal option flags. */
/* Keep flags in sync with db_show_tty and pstat(8). */
#define	TF_NOPREFIX	0x00001	/* Don't prepend "tty" to device name. */
#define	TF_INITLOCK	0x00002	/* Create init/lock state devices. */
#define	TF_CALLOUT	0x00004	/* Create "cua" devices. */
#define	TF_OPENED_IN	0x00008	/* (t) "tty" node is in use. */
#define	TF_OPENED_OUT	0x00010	/* (t) "cua" node is in use. */
#define	TF_OPENED_CONS	0x00020 /* (t) Device in use as console. */
#define	TF_OPENED	(TF_OPENED_IN|TF_OPENED_OUT|TF_OPENED_CONS)
#define	TF_GONE		0x00040	/* (t) Device node is gone. */
#define	TF_OPENCLOSE	0x00080	/* (t) Device is in open()/close(). */
#define	TF_ASYNC	0x00100	/* (t) Asynchronous I/O enabled. */
#define	TF_LITERAL	0x00200	/* Accept the next character literally. */
#define	TF_HIWAT_IN	0x00400	/* We've reached the input watermark. */
#define	TF_HIWAT_OUT	0x00800	/* We've reached the output watermark. */
#define	TF_HIWAT	(TF_HIWAT_IN|TF_HIWAT_OUT)
#define	TF_STOPPED	0x01000	/* Output flow control - stopped. */
#define	TF_EXCLUDE	0x02000	/* (t) Exclusive access. */
#define	TF_BYPASS	0x04000	/* Optimized input path. */
#define	TF_ZOMBIE	0x08000	/* Modem disconnect received. */
#define	TF_HOOK		0x10000	/* (t) TTY has hook attached. */
#define	TF_BUSY_IN	0x20000	/* (t) Process busy in read(); not supported. */
#define	TF_BUSY_OUT	0x40000	/* (Process busy in write(). */
#define	TF_BUSY		(TF_BUSY_IN|TF_BUSY_OUT)
	unsigned int	t_revokecnt;	/* (d+t) revoke() count. */

	/* Buffering mechanisms. */
	struct ttyinq	t_inq;		/* (d) Input queue. */
	size_t		t_inlow;	/* (d) Input low watermark. */
	struct ttyoutq	t_outq;		/* (d) Output queue. */
	size_t		t_outlow;	/* (d) Output low watermark. */

	/* Sleeping mechanisms. */
	struct cv	t_inwait;	/* (d) Input wait queue. */
	struct cv	t_outwait;	/* (d) Output wait queue. */
	struct cv	t_outserwait;	/* (d) Serial output wait queue. */
	struct cv	t_bgwait;	/* (d) Background wait queue. */
	struct cv	t_dcdwait;	/* (d) Carrier Detect wait queue. */

	/* Polling mechanisms. */
	struct selinfo	t_inpoll;	/* (t) Input poll queue. */
	struct selinfo	t_outpoll;	/* (t) Output poll queue. */
	struct sigio	*t_sigio;	/* (t) Asynchronous I/O. */

	struct termios	t_termios;	/* (d+t) I/O processing flags. */
	struct winsize	t_winsize;	/* (t) Window size. */
	unsigned int	t_column;	/* (d) Current cursor position. */
	unsigned int	t_writepos;	/* (d) Where input was interrupted. */
	int		t_compatflags;	/* (t) COMPAT_43TTY flags. */

	/* Init/lock-state devices. */
	struct termios	t_termios_init_in;	/* tty%s.init. */
	struct termios	t_termios_lock_in;	/* tty%s.lock. */
	struct termios	t_termios_init_out;	/* cua%s.init. */
	struct termios	t_termios_lock_out;	/* cua%s.lock. */

	struct ttydevsw	*t_devsw;	/* (c) Driver hooks. */
	struct ttyhook	*t_hook;	/* (t) Capture/inject hook. */

	/* Process signal delivery. */
	struct pgrp	*t_pgrp;	/* (d+t) Foreground process group. */
	struct session	*t_session;	/* (d+t) Associated session. */
	unsigned int	t_sessioncnt;	/* (d+t) Backpointing sessions. */

	void		*t_devswsoftc;	/* (c) Soft config, for drivers. */
	void		*t_hooksoftc;	/* (t) Soft config, for hooks. */
	struct cdev	*t_dev;		/* (c) Primary character device. */

	size_t		t_prbufsz;	/* (d) SIGINFO buffer size. */
	char		t_prbuf[];	/* (d) SIGINFO buffer. */
};

/*
 * Userland version of struct tty, for sysctl kern.ttys
 */
struct xtty {
	size_t	xt_size;	/* Structure size. */
	size_t	xt_insize;	/* Input queue size. */
	size_t	xt_incc;	/* Canonicalized characters. */
	size_t	xt_inlc;	/* Input line characters. */
	size_t	xt_inlow;	/* Input low watermark. */
	size_t	xt_outsize;	/* Output queue size. */
	size_t	xt_outcc;	/* Output queue usage. */
	size_t	xt_outlow;	/* Output low watermark. */
	unsigned int xt_column;	/* Current column position. */
	pid_t	xt_pgid;	/* Foreground process group. */
	pid_t	xt_sid;		/* Session. */
	unsigned int xt_flags;	/* Terminal option flags. */
	uint32_t xt_dev;	/* Userland device. XXXKIB truncated */
};

#ifdef _KERNEL

/* Used to distinguish between normal, callout, lock and init devices. */
#define	TTYUNIT_INIT		0x1
#define	TTYUNIT_LOCK		0x2
#define	TTYUNIT_CALLOUT		0x4

/* Allocation and deallocation. */
/*
 * - tty_alloc: allocate a TTY with internal TTY/discipline locks
 * - tty_alloc_mutex: allocate a TTY with a given mutex as the ttydisc lock.
 *       The exception is if the mutex specified is Giant, it will be used as
 *       the TTY lock instead and an internal discipline lock will be allocated.
 */
struct tty *tty_alloc(struct ttydevsw *tsw, void *softc);
struct tty *tty_alloc_mutex(struct ttydevsw *tsw, void *softc, struct mtx *mtx);
void	tty_rel_pgrp(struct tty *tp, struct pgrp *pgrp);
void	tty_rel_sess(struct tty *tp, struct session *sess);
void	tty_rel_gone(struct tty *tp);

/*
 * These will get turned back into macros after the syscons/Giant locking
 * situation is resolved.  For now, we have to support both kinds of tty lock
 * for this one case.
 */
static __inline void
_tty_lock(struct tty *tp)
{

	if (tp->t_mtx != NULL)
		mtx_lock(tp->t_mtx);
	else
		sx_xlock(&tp->t_sxobj);
}

static __inline void
_tty_unlock(struct tty *tp)
{

	if (tp->t_mtx != NULL)
		mtx_unlock(tp->t_mtx);
	else
		sx_xunlock(&tp->t_sxobj);
}

static __inline int
_tty_lock_owned(struct tty *tp)
{

	if (tp->t_mtx != NULL)
		return (mtx_owned(tp->t_mtx));
	else
		return (sx_xlocked(&tp->t_sxobj));
}

#if defined(INVARIANTS) || defined(INVARIANTS_SUPPORT)
/* XXX This should go away when the Giant special-case is removed. */
static __inline void
tty_assert_locked(struct tty *tp)
{

	if (tp->t_mtx != NULL)
		mtx_assert(tp->t_mtx, MA_OWNED);
	else
		sx_assert(&tp->t_sxobj, SA_XLOCKED);
}

#else

#define	tty_assert_locked(tp)

#endif /* defined(INVARIANTS) || defined(INVARIANTS_SUPPORT */

#define	tty_lock(tp)		_tty_lock(tp)
#define	tty_unlock(tp)		_tty_unlock(tp)
#define	tty_lock_owned(tp)	_tty_lock_owned(tp)

/*
 * XXX This one is technically wrong as long as syscons is still Giant-locked.
 * However, neither the internal tty infrastructure nor syscons will attempt to
 * tty_getlock, so we leave it as-is.
 */
#define	tty_getlock(tp)			(&(tp)->t_sxobj)

#define	ttydisc_lock(tp)		mtx_lock((tp)->t_discmtx)
#define	ttydisc_unlock(tp)		mtx_unlock((tp)->t_discmtx)
#define	ttydisc_lock_owned(tp)		mtx_owned((tp)->t_discmtx)
#define	ttydisc_assert_locked(tp)	mtx_assert((tp)->t_discmtx, MA_OWNED)
#define	ttydisc_assert_unlocked(tp)	mtx_assert((tp)->t_discmtx, MA_NOTOWNED)
#define	ttydisc_getlock(tp)		((tp)->t_discmtx)

/* Internal to tty, preferably... */
#define	ttydisc_lock_assert(tp, ma)	mtx_assert((tp)->t_discmtx, (ma))

/* Device node creation. */
int	tty_makedevf(struct tty *tp, struct ucred *cred, int flags,
    const char *fmt, ...) __printflike(4, 5);
#define	TTYMK_CLONING		0x1
#define	tty_makedev(tp, cred, fmt, ...) \
	(void )tty_makedevf((tp), (cred), 0, (fmt), ## __VA_ARGS__)
#define	tty_makealias(tp,fmt,...) \
	make_dev_alias((tp)->t_dev, fmt, ## __VA_ARGS__)

/* Signalling processes. */
void	tty_signal_sessleader(struct tty *tp, int signal);
void	tty_signal_pgrp(struct tty *tp, int signal);
/* Waking up readers/writers. */
int	tty_wait(struct tty *tp, struct cv *cv);
int	tty_wait_background(struct tty *tp, struct thread *td, int sig);
int	tty_timedwait(struct tty *tp, struct cv *cv, int timo);
void	tty_wakeup(struct tty *tp, int flags);

/* System messages. */
int	tty_checkoutq(struct tty *tp);
int	tty_putchar(struct tty *tp, char c);
int	tty_putstrn(struct tty *tp, const char *p, size_t n);

int	tty_ioctl(struct tty *tp, u_long cmd, void *data, int fflag,
    struct thread *td);
int	tty_ioctl_compat(struct tty *tp, u_long cmd, caddr_t data,
    int fflag, struct thread *td);
void	tty_set_winsize(struct tty *tp, const struct winsize *wsz);
void	tty_init_console(struct tty *tp, speed_t speed);
void	tty_flush(struct tty *tp, int flags);
void	tty_hiwat_in_block(struct tty *tp);
void	tty_hiwat_in_unblock(struct tty *tp);
dev_t	tty_udev(struct tty *tp);
#define	tty_opened(tp)		((tp)->t_flags & TF_OPENED)
#define	tty_gone(tp)		((tp)->t_flags & TF_GONE)
#define	tty_softc(tp)		((tp)->t_devswsoftc)
#define	tty_devname(tp)		devtoname((tp)->t_dev)

/* Status line printing. */
void	tty_info(struct tty *tp);

/* /dev/console selection. */
void	ttyconsdev_select(const char *name);

/* Pseudo-terminal hooks. */
int	pts_alloc(int fflags, struct thread *td, struct file *fp);
int	pts_alloc_external(int fd, struct thread *td, struct file *fp,
    struct cdev *dev, const char *name);

/* Drivers and line disciplines also need to call these. */
#include <sys/ttydisc.h>
#include <sys/ttydevsw.h>
#include <sys/ttyhook.h>
#endif /* _KERNEL */

#endif /* !_SYS_TTY_H_ */
