PREFIX     ?= /usr
DESTDIR    ?=
BINDIR      = $(DESTDIR)$(PREFIX)/sbin
USRBIN      = $(DESTDIR)$(PREFIX)/bin
RULESDIR    = $(DESTDIR)$(PREFIX)/lib/ulatencyd/rules
CONFDIR     = $(DESTDIR)/etc/ulatencyd
DBUSDIR     = $(DESTDIR)/etc/dbus-1/system.d
POLKITACTS  = $(DESTDIR)$(PREFIX)/share/polkit-1/actions
POLKITRULES = $(DESTDIR)$(PREFIX)/share/polkit-1/rules.d
SYSTEMDDIR  = $(DESTDIR)/lib/systemd/system

RUNIT_SVDIR  ?= /etc/runit/sv
RUNIT_RUNDIR ?= /run/runit/service

CARGO_FLAGS ?= --release
SRCDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: build install install-rules install-config install-dbus install-polkit uninstall clean

build:
	cd $(SRCDIR) && cargo build $(CARGO_FLAGS)

install: install-rules install-config install-dbus install-polkit
	install -Dm755 $(SRCDIR)target/release/ulatencyd   $(BINDIR)/ulatencyd
	install -Dm755 $(SRCDIR)target/release/ulatencyctl $(USRBIN)/ulatencyctl
	@INIT=$$(cat /proc/1/comm 2>/dev/null || echo unknown); \
	case "$$INIT" in \
	  systemd) \
	    install -Dm644 $(SRCDIR)contrib/systemd/ulatencyd.service $(SYSTEMDDIR)/ulatencyd.service; \
	    echo "Run: systemctl daemon-reload && systemctl enable --now ulatencyd";; \
	  runit) \
	    install -dm755 $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/log; \
	    install -m755 $(SRCDIR)contrib/runit/run     $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/run; \
	    install -m755 $(SRCDIR)contrib/runit/log/run $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/log/run; \
	    mkdir -p /var/log/ulatencyd; \
	    ln -sf $(RUNIT_SVDIR)/ulatencyd $(DESTDIR)$(RUNIT_RUNDIR)/ulatencyd 2>/dev/null || true; \
	    echo "runit service installed. Run: sv up ulatencyd";; \
	  s6-svscan) \
	    echo "s6: copy $(SRCDIR)contrib/s6/ to your scan directory.";; \
	  openrc-init) \
	    install -Dm755 $(SRCDIR)contrib/openrc/ulatencyd $(DESTDIR)/etc/init.d/ulatencyd; \
	    echo "Run: rc-update add ulatencyd default";; \
	  *) \
	    echo "Unknown init ($$INIT) — install from $(SRCDIR)contrib/ manually.";; \
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
	@# Reload dbus-daemon so it picks up the new policy without a reboot.
	@if pidof dbus-daemon >/dev/null 2>&1; then \
	    kill -HUP $$(pidof dbus-daemon) && echo "reloaded dbus-daemon"; \
	elif pidof dbus-broker >/dev/null 2>&1; then \
	    echo "dbus-broker: reload via your init system if ulatencyctl fails"; \
	fi

install-polkit:
	install -Dm644 $(SRCDIR)contrib/polkit/rs.ulatencyd.policy \
	    $(POLKITACTS)/rs.ulatencyd.policy
	install -Dm644 $(SRCDIR)contrib/polkit/rs.ulatencyd.rules \
	    $(POLKITRULES)/rs.ulatencyd.rules

uninstall:
	rm -f  $(BINDIR)/ulatencyd
	rm -f  $(USRBIN)/ulatencyctl
	rm -rf $(RULESDIR)
	rm -f  $(DBUSDIR)/org.ulatencyd.Ulatencyd1.conf
	rm -f  $(POLKITACTS)/rs.ulatencyd.policy
	rm -f  $(POLKITRULES)/rs.ulatencyd.rules
	rm -f  $(SYSTEMDDIR)/ulatencyd.service
	rm -f  $(RUNIT_RUNDIR)/ulatencyd
	rm -rf $(RUNIT_SVDIR)/ulatencyd

clean:
	cd $(SRCDIR) && cargo clean
