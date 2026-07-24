# crates/control-proto

This directory is **not** a Cargo crate — it has no `Cargo.toml` and is not a
member of the workspace. It exists purely to hold the single shared
`.varlink` interface definition file consumed by three independent
binaries:

- `crates/core` (the `ulatencyd` daemon) — sync server, via
  `../control-proto/org.ulatencyd.Control.varlink` from its `build.rs`.
- `crates/cli` (`ulatencyctl`) — sync client, via
  `../control-proto/org.ulatencyd.Control.varlink` from its `build.rs`.
- `contrib/system76-compat-shim` — async client, via
  `../../crates/control-proto/org.ulatencyd.Control.varlink` from its
  `build.rs`.

Each of the three consumers runs `varlink_generator::cargo_build_options`
against this same file with **different** `GeneratorOptions`
(`generate_async: true` only for the shim; the daemon and the CLI both use
`GeneratorOptions::default()` — sync — now that the daemon's control socket
runs a blocking `varlink::listen()` server on its own OS thread instead of
an async server on a tokio runtime), and each writes its generated `*.rs`
into its own crate's `OUT_DIR`. Because generation happens per-consumer
against a filesystem path rather than through a shared Rust dependency, the
standalone `system76-compat-shim`'s Cargo dependency graph never touches
the main workspace, and `cargo tree` run from the repo root never shows the
shim or anything it depends on (including `zbus`).

If you edit the interface (add a method, add a field, etc.), all three
consumers need to be rebuilt — `cargo build --workspace` from the repo
root plus a separate `cargo build` inside `contrib/system76-compat-shim`.
