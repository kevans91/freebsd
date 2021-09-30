# $FreeBSD$

WARNS?=		1

COMMONSRC=	${.CURDIR}/../common
.PATH:	${COMMONSRC}
CFLAGS+=	-I${COMMONSRC}

.include "../Makefile.inc"
