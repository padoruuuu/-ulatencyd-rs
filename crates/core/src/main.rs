//! ulatencyd-rs — cgroup v2 + scheduler latency daemon
//!
//! Usage:
//!   ulatencyd [--config PATH] [--log-level LEVEL]

mod applier;
mod config;
mod daemon;
mod diag;
mod focus;
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

use cgroupv2::CgroupManager;
use dbus_api::{SharedState, start_dbus_service};
use procmon::ProcMonitor;

use config::Config;
use daemon::Daemon;
use diag::flush_diagnostic_log;
use init::{Supervisor, SupervisorNotify};
use signal::init_signals;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name    = "ulatencyd",
    version,
    about   = "ulatencyd-rs — cgroup v2 + scheduler latency daemon",
)]
struct Args {
    /// Path to configuration file.
    #[arg(short, long, default_value = "/etc/ulatencyd/ulatencyd.toml")]
    config: PathBuf,

    /// Override log level (trace|debug|info|warn|error).
    #[arg(long)]
    log_level: Option<String>,

    /// Write a detailed diagnostic log to ~/ulatencyd-diagnostic.txt.
    /// Records every classification decision, cgroup write, proc event,
    /// PSI reading, and rule match. Has overhead — use only for debugging.
    #[arg(long, default_value_t = false)]
    diagnostic: bool,
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

    // Diagnostic log (optional).
    if args.diagnostic {
        match diag::init_diagnostic_log().await {
            Ok(path) => {
                info!("diagnostic log: {}", path.display());
                diag::diag_section("STARTUP");
                diag::write_diag("config", format!("version={} log_level={}", env!("CARGO_PKG_VERSION"), log_level));
            }
            Err(e) => tracing::warn!("could not open diagnostic log: {}", e),
        }
    } else {
        diag::disable_diagnostic_log();
    }

    // Detect init system (used for supervisor notification and for
    // init-specific tuning such as the startup grace period).
    let notify = SupervisorNotify::detect();
    let init_system = notify.init();

    // Announce our PID so the supervisor can track us (systemd MAINPID=).
    notify.mainpid(std::process::id());

    // Extend the startup timeout — cgroup setup and D-Bus initialisation
    // can take a few seconds on busy systems.
    notify.extend_timeout(15_000_000); // 15 s

    // Set up cgroup hierarchy — init-system agnostic.
    //
    // On systemd with Delegate=yes we use the private subtree handed to us via
    // /proc/self/cgroup.  On runit, s6, OpenRC, or when run as root manually,
    // the daemon starts in the cgroupv2 root ("/"); in that case we fall back
    // to creating /sys/fs/cgroup/ulatencyd directly so we never touch the root
    // cgroup that belongs to the session manager (elogind/systemd-logind).
    //
    // Same binary, same code path, works on all init systems.
    let cgroup_root = setup_cgroup_root().await
        .context("failed to set up cgroup root")?;

    let cgmgr = CgroupManager::new(cgroup_root)
        .await
        .context("failed to initialise cgroup hierarchy")?;

    info!("cgroup hierarchy ready at {}", cgmgr.root.display());

    // Shared state (D-Bus + main loop).
    let state = Arc::new(Mutex::new(SharedState::new()));

    // D-Bus service.
    let (dbus_conn, dbus_rx) = if config.dbus.enabled {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            start_dbus_service(Arc::clone(&state)),
        )
        .await
        {
            Ok(Ok((conn, rx))) => (Some(conn), rx),
            Ok(Err(e)) => {
                tracing::warn!("D-Bus service failed to start: {} (continuing without)", e);
                let (_, rx) = tokio::sync::mpsc::channel(1);
                (None, rx)
            }
            Err(_) => {
                tracing::warn!("D-Bus service start timed out (continuing without)");
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
    let daemon = Daemon::new(config, cgmgr, Arc::clone(&state), init_system)
        .await
        .context("failed to initialise daemon")?;

    notify.ready();
    notify.status("running");

    daemon.run(proc_monitor, dbus_rx, dbus_conn, shutdown).await?;

    notify.stopping();
    flush_diagnostic_log().await;
    info!("exiting cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse /proc/self/cgroup and return the delegated cgroupv2 path if one
/// is present and exists on the filesystem.  Returns `None` if no `0::`
/// line is found or the resolved path does not exist.
fn read_delegated_cgroup() -> Option<PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;

    // Strip any tier-suffix left over from a previous daemon run so that
    // re-use of an already-configured subtree works correctly.
    const TIER_SUFFIXES: &[&str] = &[
        "/rt", "/interactive", "/system", "/background", "/idle", "/swapstorm",
    ];

    for line in content.lines() {
        if let Some(raw) = line.strip_prefix("0::") {
            let raw = raw.trim();
            let clean = TIER_SUFFIXES.iter()
                .fold(raw.to_string(), |s, t| {
                    s.strip_suffix(t).map(|x| x.to_string()).unwrap_or(s)
                });
            let full = PathBuf::from(format!("/sys/fs/cgroup{}", clean));
            if full.exists() {
                return Some(full);
            }
        }
    }
    None
}

/// Init-system-agnostic cgroup root setup.
///
/// **Systemd with `Delegate=yes`**: `/proc/self/cgroup` yields something like
/// `0::/system.slice/ulatencyd.service`, so `full` =
/// `/sys/fs/cgroup/system.slice/ulatencyd.service` → we use it directly.
///
/// **runit / s6 / OpenRC / manual root**: the daemon starts in the root
/// cgroup (`0::/`), so `full` = `/sys/fs/cgroup` — the cgroupv2 filesystem
/// root itself, which is owned by the session manager (elogind/systemd-logind).
/// Writing our tier hierarchy there would interfere with their delegation.
/// We fall back to creating `/sys/fs/cgroup/ulatencyd` directly instead.
async fn setup_cgroup_root() -> Result<PathBuf> {
    // 1. Try the delegated cgroup from /proc/self/cgroup.
    if let Some(delegated) = read_delegated_cgroup() {
        if delegated != PathBuf::from("/sys/fs/cgroup") {
            info!("cgroup root (delegated): {}", delegated.display());
            return Ok(delegated);
        }
        // Delegated to the cgroupv2 root — fall through to direct creation.
        tracing::info!(
            "cgroup delegated to root (/sys/fs/cgroup); \
             using /sys/fs/cgroup/ulatencyd instead"
        );
    }

    // 2. Fallback: create /sys/fs/cgroup/ulatencyd directly.
    //    Works on runit, s6, OpenRC, and when run manually as root.
    cgroupv2::setup_direct_root().await
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
