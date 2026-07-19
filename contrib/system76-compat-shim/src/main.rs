//! ulatencyd-system76-shim
//!
//! Optional, standalone companion binary providing D-Bus compatibility for
//! desktop components that still expect the historical
//! `com.system76.Scheduler` interface (e.g. GNOME Shell's process-priority
//! integration on some distros). It is a thin translation layer only:
//!
//!     D-Bus (`com.system76.Scheduler`, polkit-gated)
//!         │
//!         ▼  translates each call 1:1
//!     varlink (`org.ulatencyd.Control`, over the daemon's Unix socket)
//!
//! This binary is NOT part of the main ulatencyd-rs workspace (see its
//! standalone Cargo.toml) and is not required for the daemon to function —
//! it exists purely for backward compatibility with software that hasn't
//! been updated to talk to ulatencyd-rs's own varlink interface directly.
//! Most desktop environments have no need for it; only enable/install it if
//! something on your system specifically requires `com.system76.Scheduler`.
//!
//! Coverage note: this shim implements the subset of the historical
//! interface that's actually load-bearing for desktop integration —
//! foreground/background process hints — not a full reproduction of every
//! method system76-scheduler ever shipped.

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{info, warn};
use zbus::{interface, ConnectionBuilder};

const CONTROL_SOCKET: &str = "unix:/run/ulatencyd/control.sock";

#[allow(non_camel_case_types, dead_code, non_snake_case)]
mod control_proto {
    include!(concat!(env!("OUT_DIR"), "/org.ulatencyd.Control.rs"));
}

use control_proto::VarlinkClientInterface;

struct Scheduler {
    varlink: Arc<control_proto::VarlinkClient>,
}

#[interface(name = "com.system76.Scheduler")]
impl Scheduler {
    /// Hint that `pid` is the current foreground/focused process and should
    /// receive interactive scheduling priority.
    async fn set_foreground_process(&self, pid: u32) -> zbus::fdo::Result<()> {
        self.varlink
            .set_foreground_process(pid as i64)
            .call()
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("control call failed: {}", e)))?;
        Ok(())
    }

    /// Hint that `pid` should be treated as a background process. Historical
    /// system76-scheduler exposed this as a distinct call; ulatencyd-rs's
    /// own model is rule-driven, so the closest equivalent is moving the
    /// pid to the `background` cgroup tier directly.
    async fn set_background_process(&self, pid: u32) -> zbus::fdo::Result<()> {
        self.varlink
            .set_process_cgroup(pid as i64, "background".to_string())
            .call()
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("control call failed: {}", e)))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("ulatencyd-system76-shim starting");

    let connection = varlink::AsyncConnection::with_address(CONTROL_SOCKET)
        .await
        .with_context(|| format!("cannot connect to {} — is ulatencyd running?", CONTROL_SOCKET))?;

    let varlink = Arc::new(control_proto::VarlinkClient::new(connection));

    let scheduler = Scheduler { varlink };

    let _dbus_conn = ConnectionBuilder::system()
        .context("connect to system D-Bus")?
        .name("com.system76.Scheduler")
        .context("acquire com.system76.Scheduler name (is another instance already running, \
                  or is this shim not installed/authorized to own that name?)")?
        .serve_at("/com/system76/Scheduler", scheduler)
        .context("register /com/system76/Scheduler object")?
        .build()
        .await
        .context("build D-Bus connection")?;

    info!("serving com.system76.Scheduler on the system bus (polkit-gated — see contrib/system76-compat-shim/)");

    // Run until terminated.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    warn!("shutting down");
    Ok(())
}
