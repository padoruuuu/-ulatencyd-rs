//! ulatencyd-rs — cgroup v2 + scheduler latency daemon
//!
//! Usage:
//!   ulatencyd [--config PATH] [--log-level LEVEL]

mod applier;
mod config;
mod daemon;
mod forkbomb;
mod init;
mod process_table;
mod sched;
mod signal;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use cgroupv2::{CgroupManager, setup_direct_root};
use dbus_api::{SharedState, start_dbus_service};
use procmon::ProcMonitor;

use config::Config;
use daemon::Daemon;
use init::{InitSystem, SupervisorNotify};
use signal::init_signals;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name    = "ulatencyd",
    version,
    about   = "cgroup v2 + scheduler latency daemon (Rust rewrite)",
)]
struct Args {
    /// Path to configuration file.
    #[arg(short, long, default_value = "/etc/ulatencyd/ulatencyd.toml")]
    config: PathBuf,

    /// Override log level (trace|debug|info|warn|error).
    #[arg(long)]
    log_level: Option<String>,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load config (defaults if missing).
    let config = Config::load_or_default(&args.config);

    // Initialise tracing.
    let log_level = args.log_level
        .as_deref()
        .unwrap_or(&config.daemon.log_level);

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level))
        )
        .with_target(false)
        .init();

    info!("ulatencyd-rs {} starting", env!("CARGO_PKG_VERSION"));

    // Detect init system.
    let init = InitSystem::detect();
    let notify = SupervisorNotify::new(init.clone());

    // Set up cgroup hierarchy.
    let cgroup_root = if init.uses_systemd_cgroups() {
        // For systemd, we use the current process's delegated slice
        // (see contrib/systemd/ulatencyd.service which sets Delegate=yes).
        // The cgroup root is already delegated to us; just use our own
        // /proc/self/cgroup to find it.
        get_systemd_delegate_root().await
            .unwrap_or_else(|e| {
                tracing::warn!("could not get systemd delegate root ({}), falling back to direct", e);
                PathBuf::from("/sys/fs/cgroup/ulatencyd")
            })
    } else {
        setup_direct_root()
            .await
            .context("failed to set up cgroup root")?
    };

    let cgmgr = CgroupManager::new(cgroup_root)
        .await
        .context("failed to initialise cgroup hierarchy")?;

    info!("cgroup hierarchy ready at {}", cgmgr.root.display());

    // Shared state (D-Bus + main loop).
    let state = Arc::new(Mutex::new(SharedState::new()));

    // D-Bus service.
    let (dbus_conn, dbus_rx) = if config.dbus.enabled {
        match start_dbus_service(Arc::clone(&state)).await {
            Ok((conn, rx)) => (Some(conn), rx),
            Err(e) => {
                tracing::warn!("D-Bus service failed to start: {} (continuing without)", e);
                let (_, rx) = tokio::sync::mpsc::channel(1);
                (None, rx)
            }
        }
    } else {
        let (_, rx) = tokio::sync::mpsc::channel(1);
        (None, rx)
    };

    // Netlink proc monitor.
    let proc_monitor = ProcMonitor::spawn()
        .context("failed to open netlink proc connector")?;

    // Signals.
    let (shutdown, mut sighup_rx) = init_signals();

    // Wire SIGHUP → rule reload (the daemon's dbus_rx also accepts ReloadRules).
    tokio::spawn(async move {
        while sighup_rx.recv().await.is_some() {
            tracing::info!("SIGHUP received: send 'ulatencyctl reload' or wait for next rule check");
        }
    });

    // Write PID file.
    write_pid_file(&config.daemon.pid_file);

    // Notify supervisor.
    notify.status("initialising");

    // Build and run the daemon.
    let daemon = Daemon::new(config, cgmgr, Arc::clone(&state))
        .await
        .context("failed to initialise daemon")?;

    notify.ready();
    notify.status("running");

    daemon.run(proc_monitor, dbus_rx, dbus_conn, shutdown).await?;

    notify.stopping();
    info!("exiting cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the systemd-delegated cgroup root from /proc/self/cgroup.
async fn get_systemd_delegate_root() -> Result<PathBuf> {
    let content = tokio::fs::read_to_string("/proc/self/cgroup")
        .await
        .context("read /proc/self/cgroup")?;

    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            let full = PathBuf::from(format!("/sys/fs/cgroup{}", path.trim()));
            if full.exists() {
                return Ok(full);
            }
        }
    }
    anyhow::bail!("could not determine delegated cgroup root from /proc/self/cgroup")
}

fn write_pid_file(path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(path, format!("{}\n", std::process::id())) {
        Ok(_)  => tracing::debug!("PID file written to {}", path.display()),
        Err(e) => tracing::warn!("could not write PID file {}: {}", path.display(), e),
    }
}
