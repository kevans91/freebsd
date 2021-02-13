
LIB=	asignify
SRCS=	tweetnacl.c \
	chacha.c \
	sha2.c \
	pbkdf2.c \
	b64_pton.c \
	databuf.c \
	generate.c \
	pubkey.c \
	verify.c \
	sign.c \
	signature.c \
	encrypt.c \
	util.c

CFLAGS+=	-I${.CURDIR} -DHAVE_POSIX_MEMALIGN
WARNS=	2

.include <bsd.lib.mk>
