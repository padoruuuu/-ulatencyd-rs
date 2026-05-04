PREFIX     ?= /usr
DESTDIR    ?=
BINDIR      = $(DESTDIR)$(PREFIX)/sbin
USRBIN      = $(DESTDIR)$(PREFIX)/bin
RULESDIR    = $(DESTDIR)$(PREFIX)/lib/ulatencyd/rules
CONFDIR     = $(DESTDIR)/etc/ulatencyd
POLKITACTS  = $(DESTDIR)$(PREFIX)/share/polkit-1/actions
POLKITRULES = $(DESTDIR)$(PREFIX)/share/polkit-1/rules.d
SYSTEMDDIR  = $(DESTDIR)/lib/systemd/system

# runit: service definitions go in RUNIT_SVDIR, symlinks in RUNIT_RUNDIR.
# Artix Linux uses /etc/runit/sv + /run/runit/service.
# Void Linux uses /etc/sv + /var/service.
# Override on the command line if your distro uses different paths.
RUNIT_SVDIR  ?= /etc/runit/sv
RUNIT_RUNDIR ?= /run/runit/service

CARGO_FLAGS ?= --release
SRCDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

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
	    echo "Run: systemctl daemon-reload && systemctl enable --now ulatencyd";; \
	  runit) \
	    install -dm755 $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/log; \
	    install -m755 $(SRCDIR)contrib/runit/run     $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/run; \
	    install -m755 $(SRCDIR)contrib/runit/log/run $(DESTDIR)$(RUNIT_SVDIR)/ulatencyd/log/run; \
	    ln -sf $(RUNIT_SVDIR)/ulatencyd $(DESTDIR)$(RUNIT_RUNDIR)/ulatencyd; \
	    echo "runit service enabled in $(RUNIT_RUNDIR)";; \
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
	rm -f  $(RUNIT_RUNDIR)/ulatencyd
	rm -rf $(RUNIT_SVDIR)/ulatencyd

clean:
	cd $(SRCDIR) && cargo clean
