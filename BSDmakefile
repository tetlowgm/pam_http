.include <bsd.init.mk>

LIB=	pam_http
SRCS=	pam_http.c
NOMAN=

LDADD+=	-lcurl -lpam

CFLAGS+=	-I/usr/local/include
LDFLAGS+=	-L/usr/local/lib

SHLIBDIR?=	/lib
SHLIB_NAME?=	${LIB}.so
MK_DEBUG_FILES=	no
MK_INSTALLLIB=	no
MK_PROFILE=	no

.include <bsd.lib.mk>
