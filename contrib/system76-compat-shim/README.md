# system76-compat-shim

An **optional**, **standalone** companion binary that exposes the historical
`com.system76.Scheduler` D-Bus interface by translating calls onto
ulatencyd-rs's own control socket (`org.ulatencyd.Control`, over varlink).

## Why this exists

ulatencyd-rs itself no longer speaks D-Bus at all — its control interface is
a local varlink Unix socket (see `crates/core/src/control.rs`). Some desktop
components predating that change (e.g. certain GNOME Shell process-priority
integrations) still call `com.system76.Scheduler` directly over D-Bus. This
shim exists solely so those components keep working, without pulling D-Bus
(or `zbus`, or anything in its dependency tree) into the main daemon or its
workspace.

**Most systems do not need this.** Only build/install it if something on
your system specifically requires `com.system76.Scheduler`.

## Why it's not a workspace member

This directory has its own `Cargo.toml` with an **empty `[workspace]`
table**, which tells Cargo this crate is its own workspace root — it is
never pulled into `../../Cargo.toml`'s workspace. That means:

- `cargo build --workspace` from the repo root never touches this directory.
- `cargo tree` from the repo root never shows `zbus` or anything the shim
  depends on.
- The daemon and CLI's dependency resolution is completely unaffected by
  whatever this shim needs.

## Building

```sh
cd contrib/system76-compat-shim
cargo build --release
```

This produces `target/release/ulatencyd-system76-shim`, a standalone
binary depending on `ulatencyd` already running and listening on
`/run/ulatencyd/control.sock`.

## Installing (systemd)

```sh
sudo install -m 755 target/release/ulatencyd-system76-shim /usr/libexec/ulatencyd-system76-shim
sudo install -m 644 ulatencyd-system76-shim.service /etc/systemd/system/
sudo install -m 644 com.system76.Scheduler.conf /etc/dbus-1/system.d/
sudo systemctl daemon-reload
sudo systemctl reload dbus  # or reboot — needed to pick up the new D-Bus policy
sudo systemctl enable --now ulatencyd-system76-shim.service
```

## Coverage

This shim implements the subset of the historical interface that's actually
load-bearing for desktop integration:

| D-Bus method                        | Translates to                                    |
|--------------------------------------|---------------------------------------------------|
| `SetForegroundProcess(pid)`          | `org.ulatencyd.Control.SetForegroundProcess`       |
| `SetBackgroundProcess(pid)`          | `org.ulatencyd.Control.SetProcessCgroup(pid, "background")` |

It is not a full reproduction of every method the original
`system76-scheduler` package ever shipped. If you rely on a method not
listed here, please open an issue describing the use case.
