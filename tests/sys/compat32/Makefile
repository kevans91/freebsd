PACKAGE=	tests

.if exists(${.CURDIR}/${MACHINE_ARCH})
.include "${MACHINE_ARCH}/Makefile.inc"
.endif

TESTSDIR=		${TESTSBASE}/sys/compat32

.include <bsd.test.mk>
