//! ulatencyd-rs — cgroup v2 + scheduler latency daemon
//!
//! Usage:
//!   ulatencyd [--config PATH] [--log-level LEVEL]

mod applier;
mod config;
mod control;
mod daemon;
mod diag;
mod event;
mod focus;
mod forkbomb;
mod init;
mod process_table;
mod sched;
mod signal;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use cgroupv2::CgroupManager;
use procmon::ProcMonitor;

use config::Config;
use control::{SharedState, start_control_service};
use daemon::Daemon;
use diag::flush_diagnostic_log;
use event::Event;
use init::{Supervisor, SupervisorNotify};

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
    #[arg(short, long, default_value = "/etc/ulatencyd/ulatencyd.json")]
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

// No async runtime: every event source below is a plain OS thread pushing
// into one std::sync::mpsc::channel(), and main() itself just does startup
// wiring and then hands off to Daemon::run()'s blocking receive loop.
fn main() -> Result<()> {
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
        match diag::init_diagnostic_log() {
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

    // Extend the startup timeout — cgroup setup and control socket
    // initialisation can take a few seconds on busy systems.
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
    let cgroup_root = setup_cgroup_root()
        .context("failed to set up cgroup root")?;

    let cgmgr = CgroupManager::new(cgroup_root)
        .context("failed to initialise cgroup hierarchy")?;

    info!("cgroup hierarchy ready at {}", cgmgr.root.display());

    // Shared state (control socket + main loop).
    let state = Arc::new(Mutex::new(SharedState::new()));

    // The single fan-in event channel. Every producer below gets its own
    // cloned Sender<Event> and pushes into it from its own dedicated OS
    // thread; Daemon::run() is a single blocking receive loop over the
    // Receiver.
    let (event_tx, event_rx) = mpsc::channel::<Event>();

    // Control socket service — runs a blocking varlink server on its own
    // thread and forwards commands as Event::Control(cmd).
    if config.control_socket.enabled {
        if let Err(e) = start_control_service(
            Arc::clone(&state),
            &config.control_socket.path,
            &config.control_socket.group,
            event_tx.clone(),
        ) {
            tracing::warn!("control socket failed to start: {} (continuing without)", e);
        }
    }

    // Netlink proc monitor + a thread that forwards its events onto the
    // shared channel as Event::Proc(e).
    let mut proc_monitor = ProcMonitor::spawn()
        .context("failed to open netlink proc connector")?;
    {
        let tx = event_tx.clone();
        std::thread::Builder::new()
            .name("procmon-forward".into())
            .spawn(move || {
                while let Some(e) = proc_monitor.next_event() {
                    if tx.send(Event::Proc(e)).is_err() {
                        return; // daemon shutting down
                    }
                }
                tracing::warn!("netlink proc monitor closed — requesting shutdown");
                let _ = tx.send(Event::Shutdown);
            })
            .context("failed to spawn procmon-forward thread")?;
    }

    // Signals: SIGHUP → Event::ReloadRules, SIGTERM/SIGINT → Event::Shutdown.
    // Wired directly onto the same channel — no extra forwarding hop needed
    // (the old tokio version routed SIGHUP through the control channel via
    // an intermediate task; that indirection is gone).
    signal::init_signals(event_tx.clone())
        .context("failed to install signal handlers")?;

    // Timers — three trivial always-sleeping threads (rescan/recheck/gc).
    // Matches the existing philosophy of many cheap, mostly-blocked threads
    // rather than one clever multiplexed one.
    spawn_ticker("rescan-timer", std::time::Duration::from_secs(config.daemon.rescan_interval_secs), event_tx.clone(), || Event::RescanTick);
    spawn_ticker("recheck-timer", std::time::Duration::from_secs(5), event_tx.clone(), || Event::RecheckTick);
    spawn_ticker("gc-timer", std::time::Duration::from_secs(10), event_tx.clone(), || Event::GcTick);

    // PSI monitor — kernel-native reactive triggers on /proc/pressure/memory,
    // with a timeout-driven fallback tick. psi has no dependency on this
    // crate's Event type (core depends on psi, not the other way around),
    // so it takes a plain callback instead. The returned Arc<Mutex<..>> is
    // psi's own always-fresh copy for on-demand reads; unused here because
    // on-demand queries (control socket / ulatencyctl pressure) already go
    // through SharedState.pressure, which the daemon keeps in sync from
    // every Event::Pressure it processes.
    {
        let tx = event_tx.clone();
        let _pressure_state = psi::spawn_psi_monitor(config.pressure, move |p| {
            tx.send(Event::Pressure(p)).is_ok()
        });
    }

    // Power state monitor — sysfs polling on its own thread. The returned
    // Arc<Mutex<PowerState>> already holds the value read synchronously at
    // spawn time, so we can apply the correct scheduling profile immediately
    // without waiting for the first Event::Power.
    let power_state = sched::spawn_power_monitor(event_tx.clone());
    let initial_power = *power_state.lock().unwrap();

    // Write PID file.
    write_pid_file(&config.daemon.pid_file);

    // Notify supervisor.
    notify.status("initialising");

    // Build and run the daemon.
    let daemon = Daemon::new(config, cgmgr, Arc::clone(&state), init_system)
        .context("failed to initialise daemon")?;

    notify.ready();
    notify.status("running");

    daemon.run(event_rx, initial_power)?;

    notify.stopping();
    flush_diagnostic_log();
    info!("exiting cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn a dedicated sleep-loop thread that pushes `make_event()` into `tx`
/// every `interval`: `loop { sleep(interval); if tx.send(make_event()).is_err() { return } }`.
/// Replaces `tokio::time::interval` — the equivalent of
/// `MissedTickBehavior::Skip` falls out naturally here since a plain
/// `sleep()` loop never queues up missed ticks the way a wall-clock-aligned
/// interval can.
fn spawn_ticker<F>(name: &'static str, interval: std::time::Duration, tx: mpsc::Sender<Event>, make_event: F)
where
    F: Fn() -> Event + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                if tx.send(make_event()).is_err() {
                    return; // daemon shutting down
                }
            }
        })
        .expect("failed to spawn ticker thread");
}

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
fn setup_cgroup_root() -> Result<PathBuf> {
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
    cgroupv2::setup_direct_root()
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
