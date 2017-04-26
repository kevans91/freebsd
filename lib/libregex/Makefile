# $FreeBSD$

.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	regex

CFLAGS+=	-DLIBREGEX_BUILD
SYMBOL_MAPS=	${SYM_MAPS}

.if ${MK_TESTS} != "no"
SUBDIR+=	tests
.endif

.include "${.CURDIR:H}/Makefile.inc"
.include "${SRCTOP}/lib/libc/regex/Makefile.inc"
.include <bsd.lib.mk>
