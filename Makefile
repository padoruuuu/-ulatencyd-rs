PREFIX     ?= /usr
DESTDIR    ?=
BINDIR      = $(DESTDIR)$(PREFIX)/sbin
USRBIN      = $(DESTDIR)$(PREFIX)/bin
LIBEXEC     = $(DESTDIR)$(PREFIX)/libexec
RULESDIR    = $(DESTDIR)$(PREFIX)/lib/ulatencyd/rules
CONFDIR     = $(DESTDIR)/etc/ulatencyd
DBUSDIR     = $(DESTDIR)/etc/dbus-1/system.d
SYSTEMDDIR  = $(DESTDIR)/lib/systemd/system

RUNIT_SVDIR  ?= /etc/runit/sv
RUNIT_RUNDIR ?= /run/runit/service

CARGO_FLAGS ?= --release
SRCDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: build build-shim install install-group enable-user install-rules \
        install-config install-services install-shim uninstall uninstall-shim \
        clean pkg

build:
	cd $(SRCDIR) && cargo build $(CARGO_FLAGS)

# Creates the system group referenced by ulatencyd.json's [control_socket]
# section (default: ulatencyd) and adds whoever ran `sudo make install` to
# it. Skipped entirely when DESTDIR is set — that means we're being
# packaged into a fakeroot (e.g. makepkg), where mutating the real system's
# group database would be wrong; see the `pkg` target's post_install()
# instead for that path.
install-group:
ifeq ($(DESTDIR),)
	@getent group ulatencyd >/dev/null 2>&1 || { \
	    groupadd --system ulatencyd && echo "created system group: ulatencyd"; \
	}
	@if [ -n "$$SUDO_USER" ]; then \
	    if id -nG "$$SUDO_USER" 2>/dev/null | tr ' ' '\n' | grep -qx ulatencyd; then \
	        echo "$$SUDO_USER is already in the ulatencyd group"; \
	    else \
	        usermod -aG ulatencyd "$$SUDO_USER" && \
	        echo ">>> added $$SUDO_USER to the ulatencyd group."; \
	        echo ">>> log out and back in (or run: newgrp ulatencyd) before using ulatencyctl —"; \
	        echo ">>> group membership doesn't apply to an already-running shell session."; \
	    fi; \
	else \
	    echo "SUDO_USER not set (did you run this as plain root, not via sudo?)."; \
	    echo "Add whichever user(s) should run ulatencyctl yourself:"; \
	    echo "  sudo usermod -aG ulatencyd <username>"; \
	fi
else
	@echo "DESTDIR is set — skipping group/user setup (packaging build)."
	@echo "See the 'pkg' target's post_install() for the packaged equivalent."
endif

# Add another user to the control-socket group after the fact, e.g.:
#   sudo make enable-user USER_TO_ADD=alice
enable-user:
	@test -n "$(USER_TO_ADD)" || { echo "usage: sudo make enable-user USER_TO_ADD=<username>"; exit 1; }
	usermod -aG ulatencyd "$(USER_TO_ADD)"
	@echo ">>> added $(USER_TO_ADD) to the ulatencyd group."
	@echo ">>> they need to log out and back in (or run: newgrp ulatencyd) for it to apply."

# The daemon and CLI need no D-Bus or polkit at all — control happens over a
# local varlink Unix socket, gated by Unix group membership (see
# install-group above).
install: install-group install-rules install-config install-services
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
	@echo "  Need com.system76.Scheduler D-Bus compat? See contrib/system76-compat-shim/"
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
	install -m644  $(SRCDIR)rules/*.json $(RULESDIR)/

install-config:
	install -dm755 $(CONFDIR)/rules
	test -f $(CONFDIR)/ulatencyd.json || install -m644 $(SRCDIR)ulatencyd.json $(CONFDIR)/ulatencyd.json

# Optional: com.system76.Scheduler D-Bus compatibility shim. This is a
# separate, standalone crate (its own Cargo.toml with an empty [workspace])
# and is NOT built by 'make build' or installed by 'make install'. See
# contrib/system76-compat-shim/README.md.
build-shim:
	cd $(SRCDIR)contrib/system76-compat-shim && cargo build --release

install-shim:
	install -Dm755 $(SRCDIR)contrib/system76-compat-shim/target/release/ulatencyd-system76-shim \
	    $(LIBEXEC)/ulatencyd-system76-shim
	install -Dm644 $(SRCDIR)contrib/system76-compat-shim/ulatencyd-system76-shim.service \
	    $(SYSTEMDDIR)/ulatencyd-system76-shim.service
	install -Dm644 $(SRCDIR)contrib/system76-compat-shim/com.system76.Scheduler.conf \
	    $(DBUSDIR)/com.system76.Scheduler.conf
	@if pidof dbus-daemon >/dev/null 2>&1; then \
	    kill -HUP $$(pidof dbus-daemon) && echo "reloaded dbus-daemon"; \
	elif pidof dbus-broker >/dev/null 2>&1; then \
	    echo "dbus-broker: reload via your init system if the shim fails to acquire its name"; \
	fi

uninstall:
	rm -f  $(BINDIR)/ulatencyd
	rm -f  $(USRBIN)/ulatencyctl
	rm -rf $(RULESDIR)
	rm -f  $(SYSTEMDDIR)/ulatencyd.service
	rm -f  $(RUNIT_RUNDIR)/ulatencyd
	rm -rf $(RUNIT_SVDIR)/ulatencyd

uninstall-shim:
	rm -f  $(LIBEXEC)/ulatencyd-system76-shim
	rm -f  $(SYSTEMDDIR)/ulatencyd-system76-shim.service
	rm -f  $(DBUSDIR)/com.system76.Scheduler.conf

clean:
	cd $(SRCDIR) && cargo clean

# Build and install via makepkg (Arch Linux) — core package only, no D-Bus
# or polkit dependency. Package contrib/system76-compat-shim separately if
# you need it.
pkg:
	@echo "pkgname=ulatencyd-rs" > PKGBUILD.tmp
	@echo "pkgver=0.1.0" >> PKGBUILD.tmp
	@echo "pkgrel=1" >> PKGBUILD.tmp
	@echo "arch=('x86_64')" >> PKGBUILD.tmp
	@echo "license=('GPL')" >> PKGBUILD.tmp
	@echo "depends=('systemd')" >> PKGBUILD.tmp
	@echo "makedepends=('rust' 'cargo')" >> PKGBUILD.tmp
	@echo "install=ulatencyd-rs.install" >> PKGBUILD.tmp
	@echo "source=('local')" >> PKGBUILD.tmp
	@echo "build() {" >> PKGBUILD.tmp
	@echo "  cd \"\$$srcdir\"" >> PKGBUILD.tmp
	@echo "  cargo build --release" >> PKGBUILD.tmp
	@echo "}" >> PKGBUILD.tmp
	@echo "package() {" >> PKGBUILD.tmp
	@echo "  install -Dm755 target/release/ulatencyd   \"\$$pkgdir/usr/sbin/ulatencyd\"" >> PKGBUILD.tmp
	@echo "  install -Dm755 target/release/ulatencyctl \"\$$pkgdir/usr/bin/ulatencyctl\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 rules/*.json -t \"\$$pkgdir/usr/lib/ulatencyd/rules\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 ulatencyd.json \"\$$pkgdir/etc/ulatencyd/ulatencyd.json\"" >> PKGBUILD.tmp
	@echo "  install -Dm644 contrib/systemd/ulatencyd.service \"\$$pkgdir/lib/systemd/system/ulatencyd.service\"" >> PKGBUILD.tmp
	@echo "}" >> PKGBUILD.tmp
	@echo "post_install() {" > ulatencyd-rs.install
	@echo "  getent group ulatencyd >/dev/null || groupadd --system ulatencyd" >> ulatencyd-rs.install
	@echo "  echo '==> ulatencyd-rs: add yourself to the ulatencyd group to use ulatencyctl:'" >> ulatencyd-rs.install
	@echo "  echo '    sudo usermod -aG ulatencyd <username>'" >> ulatencyd-rs.install
	@echo "  echo '    then log out and back in (or: newgrp ulatencyd)'" >> ulatencyd-rs.install
	@echo "}" >> ulatencyd-rs.install
	@echo "post_upgrade() {" >> ulatencyd-rs.install
	@echo "  post_install" >> ulatencyd-rs.install
	@echo "}" >> ulatencyd-rs.install
	makepkg -si -p PKGBUILD.tmp
	rm -f PKGBUILD.tmp ulatencyd-rs.install
