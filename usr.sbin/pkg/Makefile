
PACKAGE=	pkg-bootstrap

_BRANCH!=	${MAKE} -C ${SRCTOP}/release -V BRANCH
BRANCH?=	${_BRANCH}
.if ${BRANCH:MCURRENT} != ""
PKGCONFBRANCH?=	latest
.else
. if ${BRANCH:MBETA*} || ${BRANCH:MRC*} || ${BRANCH:MRELEASE*}
PKGCONFBRANCH?=	quarterly
. else
.  if ${MACHINE} != "amd64" && ${MACHINE} != "i386" && ${MACHINE} != "arm64"
PKGCONFBRANCH?=	quarterly
.  else
PKGCONFBRANCH?=	latest
.  endif
. endif
.endif
PKGCONF?=	FreeBSD.conf.${PKGCONFBRANCH}
CONFS=		${PKGCONF}
CONFSNAME_${PKGCONF}=	${PKGCONF:C/\.conf.+$/.conf/}
CONFSDIR=	/etc/pkg
CONFSMODE=	644
PROG=	pkg
SRCS=	pkg.c rsa.c dns_utils.c blake2b.c config.c hash.c
MAN=	pkg.7

.PATH: ${SRCTOP}/sys/contrib/libb2
SRCS+=	blake2b-ref.c
CFLAGS.blake2b-ref.c+=	-I${SRCTOP}/sys/crypto/blake2 -DSUFFIX=
CFLAGS.blake2b-ref.c+=	-Wno-cast-qual -Wno-implicit-function-declaration
CFLAGS.blake2b-ref.c+=	-Wno-unused-function
CFLAGS.blake2b.c+=	-I${SRCTOP}/sys/contrib/libb2

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive fetch ucl crypto ssl util md

.include <bsd.prog.mk>
