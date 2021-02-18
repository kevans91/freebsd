
.include <src.opts.mk>

PACKAGE=	runtime
PROG=	sed
SRCS=	compile.c main.c misc.c process.c

LIBADD=	regex

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
