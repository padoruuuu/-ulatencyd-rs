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

.PHONY: build install install-rules install-config install-dbus install-polkit uninstall clean pkg

build:
	cd $(SRCDIR) && cargo build $(CARGO_FLAGS)

# Universal install — all init-system service files are installed
# unconditionally.  Switching init systems later requires no reinstall.
install: install-rules install-config install-dbus install-polkit install-services
	install -Dm755 $(SRCDIR)target/release/ulatencyd   $(BINDIR)/ulatencyd
	install -Dm755 $(SRCDIR)target/release/ulatencyctl $(USRBIN)/ulatencyctl
	@echo ""
	@echo "=== ulatencyd-rs installed ==="
	@echo ""
	@echo "  Arch     : makepkg -si  (or make pkg)"
	@echo ""
	@INIT=$$(cat /proc/1/comm 2>/dev/null || echo unknown); \
	case "$$INIT" in \
	  systemd)     echo "  systemd  : systemctl daemon-reload && systemctl enable --now ulatencyd" ;; \
	  runit)       echo "  runit    : ln -s $(RUNIT_SVDIR)/ulatencyd $(RUNIT_RUNDIR)/ && sv up ulatencyd" ;; \
	  s6-svscan)   echo "  s6       : copy $(SRCDIR)contrib/s6/ to your scan directory" ;; \
	  openrc-init) echo "  OpenRC   : rc-update add ulatencyd default" ;; \
	  *)           echo "  Unknown init ($$INIT) — enable manually from $(SRCDIR)contrib/" ;; \
	esac
	@echo ""

# Install service definitions for ALL init systems so a future init
# switch does not require re-running 'make install'.
install-services:
	# systemd
	install -Dm644 $(SRCDIR)contrib/systemd/ulatencyd.service $(SYSTEMDDIR)/ulatencyd.service
	# runit
	install -dm755 $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/log
	install -m755 $(SRCDIR)contrib/runit/run     $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/run
	install -m755 $(SRCDIR)contrib/runit/log/run $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/log/run
	mkdir -p /var/log/ulatencyd 2>/dev/null || true
	# s6 — just stage the files; the admin copies them to the scan dir.
	install -dm755 $(DESTDIR)$(PREFIX)/lib/ulatencyd/s6
	cp -a $(SRCDIR)contrib/s6/. $(DESTDIR)$(PREFIX)/lib/ulatencyd/s6/ 2>/dev/null || true
	# OpenRC
	install -Dm755 $(SRCDIR)contrib/openrc/ulatencyd $(DESTDIR)/etc/init.d/ulatencyd

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

# Build and install via makepkg (Arch Linux)
pkg:
	@echo "pkgname=ulatencyd-rs" > PKGBUILD.tmp
	@echo "pkgver=0.1.0" >> PKGBUILD.tmp
	@echo "pkgrel=1" >> PKGBUILD.tmp
	@echo "arch=('x86_64')" >> PKGBUILD.tmp
	@echo "license=('GPL')" >> PKGBUILD.tmp
	@echo "depends=('cargo' 'systemd' 'dbus' 'polkit')" >> PKGBUILD.tmp
	@echo "makedepends=('rust')" >> PKGBUILD.tmp
	@echo "source=('local')" >> PKGBUILD.tmp
	@echo "build() {" >> PKGBUILD.tmp
	@echo "  cd \"\$$srcdir\"" >> PKGBUILD.tmp
	@echo "  cargo build --release" >> PKGBUILD.tmp
	@echo "}" >> PKGBUILD.tmp
	@echo "package() {" >> PKGBUILD.tmp
	@echo "  install -Dm755 target/release/ulatencyd   \"\$$pkgdir/usr/sbin/ulatencyd\"" >> PKGBUILD.tmp
	@echo "  install -Dm755 target/release/ulatencyctl \"\$$pkgdir/usr/bin/ulatencyctl\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 rules/*.toml -t \"\$$pkgdir/usr/lib/ulatencyd/rules\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 ulatencyd.toml \"\$$pkgdir/etc/ulatencyd/ulatencyd.toml\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 contrib/dbus/org.ulatencyd.Ulatencyd1.conf \"\$$pkgdir/etc/dbus-1/system.d/org.ulatencyd.Ulatencyd1.conf\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 contrib/polkit/rs.ulatencyd.policy \"\$$pkgdir/usr/share/polkit-1/actions/rs.ulatencyd.policy\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 contrib/polkit/rs.ulatencyd.rules \"\$$pkgdir/usr/share/polkit-1/rules.d/rs.ulatencyd.rules\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 contrib/systemd/ulatencyd.service \"\$$pkgdir/lib/systemd/system/ulatencyd.service\"" >> PKGBUILD.tmp
	@echo "}" >> PKGBUILD.tmp
	makepkg -si -p PKGBUILD.tmp
	rm -f PKGBUILD.tmp
