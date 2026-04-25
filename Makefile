PREFIX     ?= /usr
DESTDIR    ?=
BINDIR      = $(DESTDIR)$(PREFIX)/sbin
USRBIN      = $(DESTDIR)$(PREFIX)/bin
RULESDIR    = $(DESTDIR)$(PREFIX)/lib/ulatencyd/rules
CONFDIR     = $(DESTDIR)/etc/ulatencyd
POLKITACTS  = $(DESTDIR)$(PREFIX)/share/polkit-1/actions
POLKITRULES = $(DESTDIR)$(PREFIX)/share/polkit-1/rules.d
SYSTEMDDIR  = $(DESTDIR)/lib/systemd/system

CARGO_FLAGS ?= --release
SRCDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Detect runit service directory (varies by distro)
RUNIT_SERVICE ?= $(shell \
	if [ -d /run/runit/service ]; then echo /run/runit/service; \
	elif [ -d /var/service ]; then echo /var/service; \
	elif [ -d /etc/runit/runsvdir/default ]; then echo /etc/runit/runsvdir/default; \
	elif [ -d /etc/service ]; then echo /etc/service; \
	else echo /var/service; fi)

.PHONY: build install install-rules install-config install-polkit uninstall clean

build:
	cd $(SRCDIR) && cargo build $(CARGO_FLAGS)

install: install-rules install-config install-polkit
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
	    echo "Installed runit service. Run: ln -s /etc/sv/ulatencyd $(RUNIT_SERVICE)/ulatencyd";; \
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

install-polkit:
	install -Dm644 $(SRCDIR)contrib/polkit/rs.ulatencyd.policy \
	    $(POLKITACTS)/rs.ulatencyd.policy
	install -Dm644 $(SRCDIR)contrib/polkit/rs.ulatencyd.rules \
	    $(POLKITRULES)/rs.ulatencyd.rules

uninstall:
	rm -f  $(BINDIR)/ulatencyd
	rm -f  $(USRBIN)/ulatencyctl
	rm -rf $(RULESDIR)
	rm -f  $(POLKITACTS)/rs.ulatencyd.policy
	rm -f  $(POLKITRULES)/rs.ulatencyd.rules
	rm -f  $(SYSTEMDDIR)/ulatencyd.service

clean:
	cd $(SRCDIR) && cargo clean
