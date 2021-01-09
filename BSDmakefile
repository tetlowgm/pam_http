.include <bsd.init.mk>

LIB=	pam_http
SRCS=	pam_http.c
NOMAN=

LIBADD+=	curl

CFLAGS+=	-I/usr/local/include
LDFLAGS+=	-D/usr/local/lib

.include <bsd.lib.mk>
