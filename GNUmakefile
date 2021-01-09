LIB = pam_http
OBJS = ${LIB}.o
SHLIBNAME ?= ${LIB}.so

PREFIX ?= /usr/local
LIBPATH ?= $(PREFIX)/lib

CFLAGS += -O2 -pipe -std=c99 -Wall -Werror -I/usr/local/include -fPIC
LDFLAGS += -L/usr/local/lib
LDLIBS += -lcurl -lpam

.PHONY: all clean install

all: $(SHLIBNAME)

$(SHLIBNAME): $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LDLIBS)

install:
	install -s -m 0444 $(SHLIBNAME) $(DESTDIR)$(LIBPATH)/
clean:
	rm -f $(SHLIBNAME) $(OBJS)
