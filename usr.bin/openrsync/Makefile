
PROG=	openrsync
MAN1=	openrsync.1
MAN5=	rsync.5 rsyncd.5

WARNS=	0
LIBADD=	m
CFLAGS+=	-I${.CURDIR}

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
	md4.c		\
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

.include <bsd.prog.mk>
