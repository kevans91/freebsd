
.include <src.opts.mk>
.include "${SRCTOP}/secure/ssh.mk"

PROG=	scp
SRCS=	scp.c sftp-common.c sftp-client.c sftp-glob.c progressmeter.c
PACKAGE=	ssh

LIBADD=	ssh

.include <bsd.prog.mk>

.include "${SRCTOP}/secure/Makefile.openssh"
.PATH:	${SSHDIR}
