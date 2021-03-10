# $FreeBSD$


KMOD=   if_wg

INCDIR= ${SRCTOP}/sys/dev/if_wg/include

.PATH: ${SRCTOP}/sys/dev/if_wg/module

CFLAGS+= -I${INCDIR}

SRCS= opt_inet.h opt_inet6.h device_if.h bus_if.h ifdi_if.h

SRCS+= if_wg_session.c module.c
SRCS+= wg_noise.c wg_cookie.c
SRCS+= crypto.c

.include <bsd.kmod.mk>
