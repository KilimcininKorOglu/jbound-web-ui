# Build and install the setuid PAM helper.
#
# This is the only privileged component of the panel, so it is compiled with
# the hardening flags on and installed 4750 root:jbound.

CC      ?= cc
CFLAGS  ?= -O2 -std=c11 -D_GNU_SOURCE \
           -Wall -Wextra -Werror \
           -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
           -fPIE
LDFLAGS ?= -Wl,-z,relro,-z,now -pie
LDLIBS  ?= -lpam

BINARY     := jbound-authhelper
PREFIX     ?= /usr/local
LIBEXECDIR ?= $(PREFIX)/libexec
OWNER      ?= root
GROUP      ?= jbound

.PHONY: all
all: $(BINARY)

$(BINARY): authhelper.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

# Mode 4750 is the point of the whole design: setuid root so PAM can read the
# shadow database, and group-only execution so no other local account can run
# it as an oracle.
.PHONY: install
install: $(BINARY)
	install -d -m 0755 $(DESTDIR)$(LIBEXECDIR)
	install -m 4750 -o $(OWNER) -g $(GROUP) $(BINARY) $(DESTDIR)$(LIBEXECDIR)/$(BINARY)

.PHONY: clean
clean:
	rm -f $(BINARY)
