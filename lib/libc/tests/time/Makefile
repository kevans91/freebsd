
.include <bsd.own.mk>
.include <src.opts.mk>

ATF_TESTS_C=	localtime_test
.if ${MK_DETECT_TZ_CHANGES} != "no"
CFLAGS.localtime_test.c+=	-DDETECT_TZ_CHANGES
.endif

NETBSD_ATF_TESTS_C=	mktime_test
NETBSD_ATF_TESTS_C+=	strptime_test

.include "../Makefile.netbsd-tests"

.include <bsd.test.mk>
