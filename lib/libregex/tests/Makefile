# $FReeBSD$

PACKAGE=	tests
TESTSRC=	${SRCTOP}/contrib/netbsd-tests/lib/libc/regex

.PATH:		${SRCTOP}/tests

.include "${SRCTOP}/lib/libc/tests/regex/Makefile.inc"

ATF_TESTS_SH+=	libregex_test

${PACKAGE}DATA_FILES+=	gnuext.in

CFLAGS.h_regex+=-lregex
.for t in ${NETBSD_ATF_TESTS_C}
CFLAGS.$t+=	-lregex
.endfor

.include <netbsd-tests.test.mk>
.include <bsd.test.mk>
