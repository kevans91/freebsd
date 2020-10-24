# $FreeBSD$

.include <src.opts.mk>
.include <bsd.init.mk>

ATF=		${SRCTOP}/contrib/atf
.PATH:		${ATF}/atf-lua

PROG_CXX=	atf-lua
SRCS=		atf-lua.c
SRCS+=		latf.c latf_tc.c
MAN=		atf-lua.1 atf-lua.3

CFLAGS+=	-DHAVE_CONFIG_H
CFLAGS+=	-DATF_LIBEXECDIR='"${LIBEXECDIR}"'
CFLAGS+=	-DATF_PKGDATADIR='"${SHAREDIR}/atf"'
CFLAGS+=	-DATF_LUA='"/usr/libexec/flua"'
CFLAGS+=	-I${ATF}
# For luaconf.h
CFLAGS+=	-I${SRCTOP}/lib/liblua
# For all other lua headers
CFLAGS+=	-I${SRCTOP}/contrib/lua/src

# Loadable modules
LDFLAGS+=	-Wl,-E
LIBADD=		lua

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "../../../lib/atf/common.mk"
.include <bsd.prog.mk>
