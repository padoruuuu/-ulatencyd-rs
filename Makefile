PREFIX    ?= /usr
DESTDIR   ?=
BINDIR     = $(DESTDIR)$(PREFIX)/sbin
USRBIN     = $(DESTDIR)$(PREFIX)/bin
RULESDIR   = $(DESTDIR)$(PREFIX)/lib/ulatencyd/rules
CONFDIR    = $(DESTDIR)/etc/ulatencyd
DBUSDIR    = $(DESTDIR)/etc/dbus-1/system.d
SYSTEMDDIR = $(DESTDIR)/lib/systemd/system

CARGO_FLAGS ?= --release
SRCDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: build install install-rules install-config install-dbus uninstall clean

build:
	cd $(SRCDIR) && cargo build $(CARGO_FLAGS)

install: install-rules install-config install-dbus
	install -Dm755 $(SRCDIR)target/release/ulatencyd   $(BINDIR)/ulatencyd
	install -Dm755 $(SRCDIR)target/release/ulatencyctl $(USRBIN)/ulatencyctl
	@INIT=$$(cat /proc/1/comm 2>/dev/null || echo unknown); \
	case "$$INIT" in \
	  systemd) \
	    install -Dm644 $(SRCDIR)contrib/systemd/ulatencyd.service $(SYSTEMDDIR)/ulatencyd.service; \
	    echo "Installed systemd unit. Run: systemctl daemon-reload && systemctl enable --now ulatencyd";; \
	  runit) \
	    install -dm755 $(DESTDIR)/etc/sv/ulatencyd/log; \
	    install -m755 $(SRCDIR)contrib/runit/run     $(DESTDIR)/etc/sv/ulatencyd/run; \
	    install -m755 $(SRCDIR)contrib/runit/log/run $(DESTDIR)/etc/sv/ulatencyd/log/run; \
	    echo "Installed runit service. Run: ln -s /etc/sv/ulatencyd /var/service/ulatencyd";; \
	  s6-svscan) \
	    echo "s6 detected. Copy $(SRCDIR)contrib/s6/ to your scan directory manually.";; \
	  openrc-init) \
	    install -Dm755 $(SRCDIR)contrib/openrc/ulatencyd $(DESTDIR)/etc/init.d/ulatencyd; \
	    echo "Installed OpenRC script. Run: rc-update add ulatencyd default";; \
	  *) \
	    echo "Unknown init ($$INIT). Install a service file from $(SRCDIR)contrib/ manually.";; \
	esac

install-rules:
	install -dm755 $(RULESDIR)
	install -m644  $(SRCDIR)rules/*.toml $(RULESDIR)/

install-config:
	install -dm755 $(CONFDIR)/rules
	test -f $(CONFDIR)/ulatencyd.toml || install -m644 $(SRCDIR)ulatencyd.toml $(CONFDIR)/ulatencyd.toml

install-dbus:
	install -Dm644 $(SRCDIR)contrib/dbus/org.ulatencyd.Ulatencyd1.conf \
	    $(DBUSDIR)/org.ulatencyd.Ulatencyd1.conf

uninstall:
	rm -f  $(BINDIR)/ulatencyd
	rm -f  $(USRBIN)/ulatencyctl
	rm -rf $(RULESDIR)
	rm -f  $(DBUSDIR)/org.ulatencyd.Ulatencyd1.conf
	rm -f  $(SYSTEMDDIR)/ulatencyd.service

clean:
	cd $(SRCDIR) && cargo clean
