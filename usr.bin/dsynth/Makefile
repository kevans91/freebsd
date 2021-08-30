#
#

PROG=	dsynth
SRCS=	dsynth.c subs.c pkglist.c config.c bulk.c build.c repo.c mount.c
SRCS+=	status.c
SRCS+=	runstats.c ncurses.c monitor.c html.c
SRCS+=	icrc32.c

SCRIPTS=mktemplate.sh
SCRIPTSDIR= ${SHAREDIR}/dsynth

# NOTE: The HTML support was directly transplanted from synth, written by
#       John R. Marino <draco@marino.st>.
#
FILESDIR= ${SCRIPTSDIR}
FILES= favicon.png progress.html progress.css progress.js dsynth.png

CFLAGS+=	-pthread
CFLAGS+=	-DSCRIPTDIR=${SHAREDIR}/dsynth
LIBADD+=	pthread util

# ncurses, md5, for DragonFlyBSD
#
CFLAGS+=        -I${_SHLIBDIRPREFIX}/usr/include/priv/ncurses
CFLAGS+=	${PRIVATELIB_CFLAGS}
LDFLAGS+=       ${PRIVATELIB_LDFLAGS}
LIBADD+=	ncursesw crypto

LIBADD+=	m

CWARNFLAGS.build.c+=	-Wno-thread-safety -Wno-\#warnings
CWARNFLAGS.icrc32.c+=	-Wno-cast-align

LOCALBASE?=	/usr/local
CFLAGS+=	-include paths.h -DDSYNTH_BUILD_BASE="_PATH_LOCALBASE"

CFLAGS+=	-DOPENSSL_API_COMPAT=0x10100000L

.include <bsd.prog.mk>
