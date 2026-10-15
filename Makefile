# Out-of-tree build of the psk-radius strongSwan plugin.
#
# strongSwan has no stable plugin ABI, and charon refuses plugins built for
# another version. Build against a configured and compiled source tree of
# exactly the strongSwan version (and configure options) that will load it:
#
#   make STRONGSWAN_SRC=/path/to/strongswan-6.0.6 LIBDIR=/usr/lib64/strongswan
#   sudo make install LIBDIR=/usr/lib64/strongswan
#
# LIBDIR is where libstrongswan.so.0, libcharon.so.0 and libradius.so.0 are
# installed: /usr/lib/ipsec upstream and on Debian/Ubuntu, /usr/lib64/strongswan
# on Fedora/RHEL/EPEL. Plugins go to $(LIBDIR)/plugins.

STRONGSWAN_SRC ?= $(error set STRONGSWAN_SRC to a configured and built strongSwan source tree)
LIBDIR ?= /usr/lib/ipsec
PLUGINDIR ?= $(LIBDIR)/plugins

TARGET = libstrongswan-psk-radius.so
SRCS = $(wildcard src/*.c)
HDRS = $(wildcard src/*.h)

CFLAGS ?= -O2 -g
# -Wno-format: gcc does not know strongSwan's printf extensions (%Y, %H, ...).
override CFLAGS += -fPIC -Wall -Wno-format -Werror=implicit-function-declaration
override CPPFLAGS += -include $(STRONGSWAN_SRC)/config.h \
	-I$(STRONGSWAN_SRC)/src/libstrongswan \
	-I$(STRONGSWAN_SRC)/src/libcharon \
	-I$(STRONGSWAN_SRC)/src/libradius
override LDFLAGS += -shared -Wl,-rpath,$(LIBDIR) \
	-L$(STRONGSWAN_SRC)/src/libradius/.libs \
	-L$(STRONGSWAN_SRC)/src/libcharon/.libs \
	-L$(STRONGSWAN_SRC)/src/libstrongswan/.libs
LDLIBS = -lradius -lcharon -lstrongswan

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS) $(LDLIBS)

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(PLUGINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install clean
