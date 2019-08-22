# $FreeBSD$

WARNS?=		0

.include <bsd.compiler.mk>

MK_PIE:=	no	# Explicit libXXX.a references

.if ${COMPILER_TYPE} == "clang"
DEBUG_FILES_CFLAGS= -gline-tables-only
.else
DEBUG_FILES_CFLAGS= -g1
.endif

.if ${MACHINE_ARCH} == "mips"
CFLAGS+= -mxgot
CXXFLAGS+= -mxgot
.endif

.include "../Makefile.inc"
