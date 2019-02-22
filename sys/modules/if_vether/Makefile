# $FreeBSD$

.PATH:	${SRCTOP}/sys/net
KMOD=	if_vether
SRCS=	if_vether.c opt_inet.h opt_inet6.h

#SRCS+=	vnode_if.h

# XXX GROSS HACK PLEASE REMOVE
CFLAGS+=	-DVIMAGE

.include <bsd.kmod.mk>
