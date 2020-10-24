# $FreeBSD$

.include <src.opts.mk>

SHLIB_NAME=	jail.so
SHLIBDIR=	${LIBDIR}/flua

SRCS+=		lua_jail.c

CFLAGS+= \
	-I${SRCTOP}/contrib/lua/src \
	-I${SRCTOP}/lib/liblua \

LIBADD+=	jail

MAN=	jail.3lua

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
