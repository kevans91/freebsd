
PROG=	openrsync
MAN1=	openrsync.1
MAN5=	rsync.5 rsyncd.5

LIBADD=	m md

.PATH:	${SRCTOP}/contrib/openrsync
SRCS=	blocks.c	\
	client.c	\
	compats.c	\
	downloader.c	\
	fargs.c		\
	flist.c		\
	hash.c		\
	ids.c		\
	io.c		\
	log.c		\
	main.c		\
	misc.c		\
	mkpath.c	\
	mktemp.c	\
	receiver.c	\
	sender.c	\
	server.c	\
	session.c	\
	socket.c	\
	symlinks.c	\
	tests.c		\
	uploader.c

CFLAGS+=	-I${.CURDIR}
# Using md4 from libmd instead.
CFLAGS+=	-DMD4_Init=MD4Init -DMD4_Update=MD4Update -DMD4_Final=MD4Final
CFLAGS.socket.c=	-Wno-cast-align

.include <bsd.prog.mk>
