# ulatencyd-rs

A Rust rewrite of [ulatencyd](https://github.com/poelzi/ulatencyd) — a Linux daemon that
improves desktop responsiveness by managing cgroup v2 hierarchies and the CFS/EEVDF
scheduler in response to real-time process events.

Project: https://github.com/padoruuuu/-ulatencyd-rs

## What it does

| Feature | Details |
|---|---|
| **cgroup v2 tiers** | `rt`, `interactive`, `system`, `background`, `idle`, `swapstorm` |
| **Netlink proc connector** | Zero-overhead fork/exec/exit events — no polling |
| **Rule engine** | TOML rules with glob matching, priority, profile inheritance |
| **PSI monitoring** | `/proc/pressure/*` every 500 ms; classifies Normal/Low/High/Critical |
| **Fork-bomb detection** | Sliding-window rate limit per parent; throttles subtree to `swapstorm` |
| **Power-aware profiles** | Switches CFS latency knobs on AC ↔ battery via sysfs |
| **sched_ext aware** | Detects active BPF schedulers, skips `cpu.weight` writes |
| **Control socket** | `org.ulatencyd.Control` over a local varlink Unix socket — no D-Bus |
| **Init-agnostic** | systemd, runit, s6, OpenRC, SysV — one binary |
| **sd_notify** | `READY=1` / `STOPPING=1` / `STATUS=` for any supervisor with `NOTIFY_SOCKET` |

ulatencyd-rs does not use D-Bus at all. Its control interface is a local
varlink socket gated by Unix group membership (see [Control
socket](#control-socket)). If you need the historical
`com.system76.Scheduler` D-Bus interface for desktop-integration
compatibility, see the optional, standalone
[`contrib/system76-compat-shim`](contrib/system76-compat-shim/README.md).

## Requirements

- Linux kernel ≥ 5.14 (cgroup v2 unified hierarchy, `cgroup.kill`)
- Rust ≥ 1.82 (install via [rustup](https://rustup.rs), **not** distro packages)
- Root privileges (or appropriate capabilities: `CAP_SYS_NICE`, `CAP_NET_ADMIN`)

## Build

```bash
# Install Rust (skip if already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build
git clone <this-repo> ulatencyd-rs
cd ulatencyd-rs
cargo build --release

# Produces:
#   target/release/ulatencyd      ← daemon
#   target/release/ulatencyctl    ← CLI client
```

## Install

```bash
sudo make install
```

This automates the group setup below (creates the `ulatencyd` group and
adds whoever ran `sudo`); to add another user to it later:
`sudo make enable-user USER_TO_ADD=<username>`.

Or manually:

```bash
sudo groupadd --system ulatencyd            # controls who can use ulatencyctl
sudo usermod -aG ulatencyd <your user>

sudo install -m755 target/release/ulatencyd    /usr/sbin/ulatencyd
sudo install -m755 target/release/ulatencyctl  /usr/bin/ulatencyctl
sudo install -dm755 /etc/ulatencyd/rules /usr/lib/ulatencyd/rules
sudo install -m644 ulatencyd.json  /etc/ulatencyd/ulatencyd.json
sudo install -m644 rules/*.json    /usr/lib/ulatencyd/rules/
```

### systemd

```bash
sudo install -m644 contrib/systemd/ulatencyd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ulatencyd
sudo systemctl status ulatencyd
```

### runit (Void Linux, etc.)

```bash
sudo cp -r contrib/runit /etc/sv/ulatencyd
sudo chmod +x /etc/sv/ulatencyd/run /etc/sv/ulatencyd/log/run
sudo ln -s /etc/sv/ulatencyd /var/service/ulatencyd
```

### s6

Copy `contrib/s6/` to your scan directory. The `run` script uses
`s6-notifyoncheck` to forward `READY=1` readiness to s6.

### OpenRC (Alpine, Gentoo, etc.)

```bash
sudo install -m755 contrib/openrc/ulatencyd /etc/init.d/ulatencyd
sudo rc-update add ulatencyd default
sudo rc-service ulatencyd start
```

## Configuration

Edit `/etc/ulatencyd/ulatencyd.json`. All keys have sensible defaults:

```json
{
  "daemon": {
    "log_level": "info",
    "rescan_interval_secs": 30,
    "apply_to_existing_processes": true
  },
  "pressure": {
    "memory_low_threshold": 5.0,
    "memory_high_threshold": 40.0
  },
  "fork_bomb": {
    "threshold_per_second": 50
  },
  "sched": {
    "autogroup_enabled": false
  },
  "control_socket": {
    "enabled": true,
    "path": "/run/ulatencyd/control.sock",
    "group": "ulatencyd"
  }
}
```

- `pressure.memory_low_threshold` / `memory_high_threshold` — % PSI stall before "low" / "high" pressure
- `fork_bomb.threshold_per_second` — forks/sec from one parent → throttle
- `sched.autogroup_enabled` — disable kernel autogroup (recommended: `false`)
- `control_socket.group` — who can connect (see Control socket below)

JSON has no comment syntax; omit any section to use its defaults instead of copying the whole file.

## Control socket

ulatencyd-rs exposes a control/query interface over
[varlink](https://varlink.org) instead of D-Bus, on a local Unix socket
(default `/run/ulatencyd/control.sock`). The interface definition lives at
[`crates/control-proto/org.ulatencyd.Control.varlink`](crates/control-proto/org.ulatencyd.Control.varlink).

Access control is by Unix group membership rather than polkit: the socket
and its parent directory are owned `root:<control_socket.group>` with modes
`0660`/`0750`. Add yourself (or any client) to that group to use
`ulatencyctl`:

```bash
sudo groupadd --system ulatencyd   # if it doesn't already exist
sudo usermod -aG ulatencyd $USER
# log out/in (or `newgrp ulatencyd`) for the new group membership to apply
```

## Writing Rules

Rules live in `/etc/ulatencyd/rules/*.json` and `/usr/lib/ulatencyd/rules/*.json`.
Files are loaded in alphabetical order; `/etc/` takes precedence. Unknown
keys in a rule, `match`, or `action` object are a load-time error, not a
silently-ignored typo. Since JSON has no comment syntax, both `rule` and
`action` objects accept an optional `note` string field — purely
documentation, ignored by the daemon — as the place to put the "why" that
would otherwise be a TOML comment.

```json
{
  "rule": [
    {
      "name": "my-audio-server",
      "priority": 90,
      "note": "higher priority wins; first match stops evaluation",
      "match": {
        "comm": ["jackd"],
        "comm_prefix": ["my-"],
        "cmdline_contains": ["--realtime"],
        "exe_path": ["/usr/bin/jackd"],
        "uid": [1000],
        "env_set": ["JACK_DEFAULT_SERVER"],
        "min_threads": 4,
        "min_rss_mb": 100,
        "parent_comm": ["jackd"],
        "cgroup_path": "/user.slice/*"
      },
      "action": {
        "cgroup": "rt",
        "nice": -10,
        "sched_policy": "fifo",
        "sched_priority": 80,
        "oom_score_adj": -900,
        "io_weight": 9000,
        "recheck_secs": 60,
        "apply_to_children": true,
        "continue": false
      }
    }
  ]
}
```

Field notes: `comm` is an exact process name match, `comm_prefix` a prefix
match, `cmdline_contains` a substring of the joined cmdline, `exe_path` an
exact executable path, `uid` restricts to specific users, `env_set` requires
an environment variable to exist, `min_threads`/`min_rss_mb` are minimum
thresholds, `parent_comm` matches the parent process name, and `cgroup_path`
is a wildmatch on the v2 cgroup path. `action.cgroup` is one of
`rt|interactive|system|background|idle|swapstorm`, `nice` is `-20..19`,
`sched_policy` is `normal|batch|idle|fifo|rr`, `sched_priority` is `1..99`
(for `fifo`/`rr`), `oom_score_adj` is `-1000..1000`, `io_weight` is
`1..10000`, `recheck_secs` re-evaluates the rule after N seconds,
`apply_to_children` also applies the cgroup to all direct children, and
`continue: true` keeps matching lower-priority rules instead of stopping at
the first match.

Note: `env_set` matching reads `/proc/pid/environ`, which can be a few KB per
process — the daemon only pays for that read at all when at least one loaded
rule actually declares `env_set`.

### Cgroup tiers

| Tier | `cpu.weight` | `io.weight` | Notes |
|---|---|---|---|
| `rt` | 9000 | 9000 | Audio/RT. `oom.group=1` |
| `interactive` | 5000 | — | Compositor, focused app |
| `system` | 2000 | — | System services |
| `background` | 500 | 100 | Package managers, builds |
| `idle` | 100 | — | `memory.high=256M` |
| `swapstorm` | 50 | — | `memory.max=128M`, `swap.max=0`, `oom.group=1` |

## CLI (ulatencyctl)

```bash
ulatencyctl status              # daemon version, mode, process count
ulatencyctl list                # all managed processes with cgroup + rule
ulatencyctl info <pid>          # details for one PID
ulatencyctl pressure            # current PSI values
ulatencyctl reload              # hot-reload rules from disk
ulatencyctl set-cgroup <pid> background   # manually move a PID
ulatencyctl set-foreground <pid>          # hint: window manager focus change
ulatencyctl run background -- make -j8    # run a command under a tier
```

(There is no `watch-signals` — varlink has no D-Bus-signal equivalent to
subscribe to. Poll `status`/`list` instead.)

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │              ulatencyd                  │
                    │                                         │
  /proc/pid/stat ──►│  ProcessTable   ◄── netlink proc events │
  /proc/pressure ──►│  PSI Monitor                            │
  /sys/power_supply►│  Power Monitor   ──► sysctl knobs       │
                    │                                         │
                    │  RuleEngine ──► Applier ──► cgroupv2    │
                    │     │                       │           │
                    │     └── ExceptionList        └── /sys/  │
                    │                                 fs/cgroup│
                    │  ForkBombDetector                        │
                    │  Control socket (varlink) ◄─────────────►│ ulatencyctl
                    └─────────────────────────────────────────┘
```

Need `com.system76.Scheduler` on D-Bus for desktop-integration
compatibility? That's a separate, optional process
(`contrib/system76-compat-shim`) sitting entirely outside this diagram,
translating D-Bus calls onto the control socket above like any other client.

## Crate structure

| Crate | Purpose |
|---|---|
| `procmon` | `/proc` parser, netlink proc connector, full + incremental scan |
| `cgroupv2` | cgroup v2 hierarchy manager |
| `psi` | PSI pressure reader and classifier |
| `rules` | TOML rule engine with wildmatch and profile inheritance |
| `control-proto` | Shared `org.ulatencyd.Control` varlink schema (not a crate — see its README) |
| `core` (`ulatencyd`) | Main daemon binary: event loop, applier, fork-bomb, power, signals, control socket |
| `cli` (`ulatencyctl`) | Control-socket client CLI (sync varlink) |

`contrib/system76-compat-shim` is a separate, standalone crate (own
`Cargo.toml`, own workspace) — see its own README for why it's not listed
here as a workspace member.

## License

GPLv3
