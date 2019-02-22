# $OpenBSD: Makefile,v 1.8 2017/07/06 12:15:23 espie Exp $

PROG=		switchd
MAN=		switchd.8 switchd.conf.5
WARNS?=		1

SWITCHD=	${SRCTOP}/contrib/switchd

.PATH:		${SWITCHD}

SRCS=		imsg_util.c log.c packet.c proc.c switch.c timer.c util.c
SRCS+=		switchd.c control.c ofp.c ofp10.c ofp13.c ofp_common.c ofrelay.c
SRCS+=		${.OBJDIR}/ofp_map.c ${.OBJDIR}/ofp10_map.c
SRCS+=		parse.y ofcconn.c

LIBADD=		event openbsd util

CFLAGS+=	-Wall -I${SWITCHD}
CFLAGS+=	-I${SRCTOP}/lib/libopenbsd
CFLAGS+=	-I${SRCTOP}/contrib/pf/libevent
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare

GENERATED=	ofp_map.c ofp10_map.c
CLEANFILES+=	${GENERATED}
YFLAGS=

${.OBJDIR}/ofp_map.c: genmap.sh ${SWITCHD}/ofp_map.h ${SRCTOP}/sys/net/ofp.h
	/bin/sh ${SWITCHD}/genmap.sh -i ${SRCTOP}/sys/net/ofp.h -t ofp \
	    -m ${SWITCHD}/ofp_map.h -h '<net/ofp.h>' > $@
	@touch $@

${.OBJDIR}/ofp10_map.c: genmap.sh ${SWITCHD}/ofp_map.h ${SWITCHD}/ofp10.h
	/bin/sh ${SWITCHD}/genmap.sh -i ${SWITCHD}/ofp10.h -t ofp10 \
	    -m ${SWITCHD}/ofp_map.h -h '"ofp10.h"' > $@
	@touch $@

.include <bsd.prog.mk>
