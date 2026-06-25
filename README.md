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
| **Power-aware profiles** | Switches CFS latency knobs on AC ↔ battery via UPower or sysfs |
| **sched_ext aware** | Detects active BPF schedulers, skips `cpu.weight` writes |
| **D-Bus API** | `org.ulatencyd.Ulatencyd1` on the system bus |
| **Init-agnostic** | systemd, runit, s6, OpenRC, SysV — one binary |
| **sd_notify** | `READY=1` / `STOPPING=1` / `STATUS=` for any supervisor with `NOTIFY_SOCKET` |

## Requirements

- Linux kernel ≥ 5.14 (cgroup v2 unified hierarchy, `cgroup.kill`)
- Rust ≥ 1.82 (install via [rustup](https://rustup.rs), **not** distro packages)
- D-Bus system daemon
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
sudo bash install.sh
```

Or manually:

```bash
sudo install -m755 target/release/ulatencyd    /usr/sbin/ulatencyd
sudo install -m755 target/release/ulatencyctl  /usr/bin/ulatencyctl
sudo install -dm755 /etc/ulatencyd/rules /usr/lib/ulatencyd/rules
sudo install -m644 ulatencyd.toml  /etc/ulatencyd/ulatencyd.toml
sudo install -m644 rules/*.toml    /usr/lib/ulatencyd/rules/
sudo install -m644 contrib/dbus/org.ulatencyd.Ulatencyd1.conf \
    /etc/dbus-1/system.d/org.ulatencyd.Ulatencyd1.conf
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

Edit `/etc/ulatencyd/ulatencyd.toml`. All keys have sensible defaults:

```toml
[daemon]
log_level = "info"
rescan_interval_secs = 30
apply_to_existing_processes = true

[pressure]
memory_low_threshold  = 5.0   # % PSI stall before "low" pressure
memory_high_threshold = 40.0  # % PSI stall before "high" pressure

[fork_bomb]
threshold_per_second = 50     # forks/sec from one parent → throttle

[sched]
autogroup_enabled = false     # disable kernel autogroup (recommended)
```

## Writing Rules

Rules live in `/etc/ulatencyd/rules/*.toml` and `/usr/lib/ulatencyd/rules/*.toml`.
Files are loaded in alphabetical order; `/etc/` takes precedence.

```toml
[[rule]]
name     = "my-audio-server"
priority = 90          # higher wins; first match stops evaluation

[rule.match]
comm           = ["jackd"]          # exact process name
comm_prefix    = ["my-"]            # prefix match
cmdline_contains = ["--realtime"]   # substring in joined cmdline
exe_path       = ["/usr/bin/jackd"] # exact executable path
uid            = [1000]             # only for this user
env_set        = ["JACK_DEFAULT_SERVER"]  # env var must exist
min_threads    = 4                  # at least 4 threads
min_rss_mb     = 100                # at least 100 MB RSS
parent_comm    = ["jackd"]          # parent process name
cgroup_path    = "/user.slice/*"    # wildmatch on v2 cgroup path

[rule.action]
cgroup          = "rt"         # rt|interactive|system|background|idle|swapstorm
nice            = -10          # -20..19
sched_policy    = "fifo"       # normal|batch|idle|fifo|rr
sched_priority  = 80           # 1..99 (for fifo/rr)
oom_score_adj   = -900         # -1000..1000
io_weight       = 9000         # 1..10000
recheck_secs    = 60           # re-evaluate after N seconds
apply_to_children = true       # also apply to all direct children
continue        = false        # set true to keep matching lower-priority rules
```

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
ulatencyctl watch-signals       # stream D-Bus signals to stdout
```

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
                    │  D-Bus Interface ◄──────────────────────►│ ulatencyctl
                    └─────────────────────────────────────────┘
```

## Crate structure

| Crate | Purpose |
|---|---|
| `procmon` | `/proc` parser, netlink proc connector, full scan |
| `cgroupv2` | cgroup v2 hierarchy manager |
| `psi` | PSI pressure reader and classifier |
| `rules` | TOML rule engine with wildmatch and profile inheritance |
| `dbus-api` | zbus 4 D-Bus interface + signal emitters |
| `core` (`ulatencyd`) | Main daemon binary: event loop, applier, fork-bomb, power, signals |
| `cli` (`ulatencyctl`) | D-Bus client CLI |

## License

GPLv3
