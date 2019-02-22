# $FreeBSD$

.PATH:	${SRCTOP}/sys/net
KMOD=	if_switch
SRCS=	if_switch.c switchctl.c switchofp.c opt_inet.h opt_inet6.h

SRCS+=	vnode_if.h

# XXX GROSS HACK PLEASE REMOVE
CFLAGS+=	-DVIMAGE

.include <bsd.kmod.mk>
