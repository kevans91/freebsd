# $FreeBSD$

.include <bsd.init.mk>

ATF=		${SRCTOP}/contrib/atf
.PATH:		${ATF}/atf-lua

ATF_TESTS_LUA+=	latf_test

ATF_TESTS_SH+=	config_test
ATF_TESTS_SH+=	integration_test
ATF_TESTS_SH+=	tc_test

integration_test: Makefile
ATF_TESTS_SH_SED_integration_test= \
  -e 's,__ATF_LUA__,/usr/libexec/atf-lua,g'

SCRIPTS+=		misc_helpers
SCRIPTSDIR_misc_helpers=${TESTSDIR}
CLEANFILES+=		misc_helpers misc_helpers.tmp
misc_helpers: misc_helpers.lua
	echo '#! /usr/libexec/atf-lua' >${.TARGET}.tmp
	cat ${.ALLSRC} >>${.TARGET}.tmp
	chmod +x ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

.include <bsd.test.mk>
