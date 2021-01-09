.include <bsd.init.mk>

LIB=	pam_http
SRCS=	pam_http.c
NOMAN=

WARNS?=	6

CFLAGS+=	-I/usr/local/include
LDFLAGS+=	-L/usr/local/lib
LDADD+=		-lcurl -lpam

SHLIBDIR=	/usr/local/lib
SHLIB_NAME=	${LIB}.so
MK_DEBUG_FILES=	no
MK_INSTALLLIB=	no
MK_PROFILE=	no

.include <bsd.lib.mk>
