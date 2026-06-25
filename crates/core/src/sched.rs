//! CFS/EEVDF scheduler tuning and power-aware profile switching.
//!
//! Two scheduling profiles:
//!   RESPONSIVE — AC power, desktop use (lower latency knobs)
//!   CONSERVATIVE — battery, server (kernel defaults)
//!
//! Autogroup disabling is the single highest-impact change (Learning 1).

use anyhow::Result;
use tracing::{debug, info, warn};
use zbus;

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SchedProfile {
    /// CFS/EEVDF scheduling period (ns). Lower = more responsive.
    pub latency_ns:            u64,
    /// Min time a task runs before preemption (ns).
    pub min_granularity_ns:    u64,
    /// How far ahead a waking task must be to preempt the current task (ns).
    pub wakeup_granularity_ns: u64,
    /// CFS bandwidth slice size (µs).
    pub bandwidth_slice_us:    u64,
    /// Kernel preemption model written to /sys/kernel/debug/sched/preempt
    /// (optional, requires debugfs).
    pub preempt: Option<&'static str>,
}

pub const RESPONSIVE: SchedProfile = SchedProfile {
    latency_ns:             4_000_000,  // CFS: lower latency on AC (more responsive)
    min_granularity_ns:     750_000,    // EEVDF: kernel default (AC)
    wakeup_granularity_ns:  1_000_000,  // EEVDF: kernel default (AC)
    bandwidth_slice_us:     3_000,
    preempt: Some("full"),
};

pub const CONSERVATIVE: SchedProfile = SchedProfile {
    latency_ns:             6_000_000,  // CFS: longer period on battery (more efficient)
    min_granularity_ns:     500_000,    // EEVDF: reduced on battery
    wakeup_granularity_ns:  750_000,    // EEVDF: reduced on battery
    bandwidth_slice_us:     5_000,
    preempt: Some("voluntary"),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState { AC, Battery }

// ---------------------------------------------------------------------------
// Autogroup
// ---------------------------------------------------------------------------

/// Saved autogroup state so we can restore it on shutdown.
pub struct AutogroupGuard {
    original_value: String,
}

impl AutogroupGuard {
    /// Read the current autogroup setting, then disable it.
    pub fn disable() -> Result<Self> {
        let path = "/proc/sys/kernel/sched_autogroup_enabled";
        let orig = std::fs::read_to_string(path)
            .unwrap_or_else(|_| "1\n".to_string());

        // Write 0 to disable.
        match std::fs::write(path, "0\n") {
            Ok(_) => info!("autogroup disabled (was: {})", orig.trim()),
            Err(e) => warn!("could not disable autogroup: {} (continuing)", e),
        }

        Ok(Self { original_value: orig })
    }

    /// Restore the original autogroup value on drop.
    pub fn restore(&self) {
        let path = "/proc/sys/kernel/sched_autogroup_enabled";
        match std::fs::write(path, &self.original_value) {
            Ok(_) => info!("autogroup restored to {}", self.original_value.trim()),
            Err(e) => warn!("could not restore autogroup: {}", e),
        }
    }
}

impl Drop for AutogroupGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

// ---------------------------------------------------------------------------
// Startup probes — computed once in Daemon::new()
// ---------------------------------------------------------------------------

/// Returns `true` if `/proc/sys/kernel/sched_latency_ns` exists (CFS, kernels
/// < 6.6). On EEVDF kernels (≥ 6.6) the file is absent and we fall back to
/// `sched_min_granularity_ns` + `sched_wakeup_granularity_ns` instead.
pub fn probe_sched_latency_ns() -> bool {
    std::path::Path::new("/proc/sys/kernel/sched_latency_ns").exists()
}

/// Finds the debugfs preempt-model control file (path differs by kernel).
fn preempt_model_path() -> Option<std::path::PathBuf> {
    for candidate in &[
        "/sys/kernel/debug/sched/preempt",
        "/sys/kernel/debug/preempt",
    ] {
        let p = std::path::Path::new(candidate);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Returns `true` if the kernel supports runtime preempt-model switching.
///
/// The probe writes the current model value back unchanged — a no-op when
/// `CONFIG_PREEMPT_DYNAMIC` is enabled, `EINVAL` when the model is fixed or
/// a `sched_ext` BPF scheduler is active.
pub fn probe_preempt_model_switchable() -> bool {
    let Some(path) = preempt_model_path() else {
        return false;
    };
    let Ok(current) = std::fs::read_to_string(&path) else {
        return false;
    };
    std::fs::write(&path, current.trim()).is_ok()
}

// ---------------------------------------------------------------------------
// Sysctl profile application
// ---------------------------------------------------------------------------

/// Apply a scheduling profile by writing sysctl/debugfs knobs.
///
/// `sched_latency_ns_available` should be the result of `probe_sched_latency_ns()`
/// computed once at daemon startup. `preempt_switchable` should be the result
/// of `probe_preempt_model_switchable()`.
///
/// Silently skips knobs that are not writable. Logs a warning (not an error)
/// for unexpected write failures so the daemon continues running even if
/// individual sysctl writes fail.
pub fn apply_sched_profile(
    profile: &SchedProfile,
    sched_latency_ns_available: bool,
    preempt_switchable: bool,
) {
    // sched_cfs_bandwidth_slice_us exists on all supported kernel versions.
    if let Err(e) = write_sysctl("kernel/sched_cfs_bandwidth_slice_us", profile.bandwidth_slice_us) {
        warn!("sysctl kernel/sched_cfs_bandwidth_slice_us: {} (skipping)", e);
    } else {
        debug!("sysctl kernel/sched_cfs_bandwidth_slice_us = {}", profile.bandwidth_slice_us);
    }

    if sched_latency_ns_available {
        // CFS kernel (< 6.6): write the original latency tunable.
        if let Err(e) = write_sysctl("kernel/sched_latency_ns", profile.latency_ns) {
            warn!("sysctl kernel/sched_latency_ns: {} (skipping)", e);
        } else {
            debug!("sysctl kernel/sched_latency_ns = {}", profile.latency_ns);
        }
    } else {
        // EEVDF kernel (≥ 6.6): use the equivalent granularity knobs.
        if let Err(e) = write_sysctl("kernel/sched_min_granularity_ns", profile.min_granularity_ns) {
            warn!("sysctl kernel/sched_min_granularity_ns: {} (skipping)", e);
        } else {
            debug!("sysctl kernel/sched_min_granularity_ns = {}", profile.min_granularity_ns);
        }
        if let Err(e) = write_sysctl("kernel/sched_wakeup_granularity_ns", profile.wakeup_granularity_ns) {
            warn!("sysctl kernel/sched_wakeup_granularity_ns: {} (skipping)", e);
        } else {
            debug!("sysctl kernel/sched_wakeup_granularity_ns = {}", profile.wakeup_granularity_ns);
        }
    }

    if let Some(preempt) = profile.preempt {
        if preempt_switchable {
            if let Some(path) = preempt_model_path() {
                if let Err(e) = std::fs::write(&path, preempt) {
                    // Warn: file existed and was writable at probe time but
                    // the write now fails — sched_ext may have been loaded.
                    warn!("write preempt model {:?}: {}", preempt, e);
                } else {
                    info!("preempt model set to {}", preempt);
                }
            }
        } else {
            debug!("preempt model switching unavailable; skipping ({:?})", preempt);
        }
    }
}

fn write_sysctl(key: &str, value: u64) -> Result<()> {
    let path = format!("/proc/sys/{}", key);
    std::fs::write(&path, format!("{}\n", value))
        .map_err(|e| anyhow::anyhow!("{}: {}", path, e))
}

// ---------------------------------------------------------------------------
// Power state detection (fallback for systems without UPower)
// ---------------------------------------------------------------------------

/// Detect current power source from `/sys/class/power_supply/`.
///
/// A machine is considered on battery **only** when:
///   - A battery entry reports `status = Discharging`, AND
///   - No mains (AC) adapter reports `online = 1`.
///
/// On a desktop with no battery at all, both conditions are false → AC.
/// USB hubs and UPS entries (type ≠ Mains / Battery) are ignored.
/// Used when UPower D-Bus is unavailable (runit/minimal systems).
pub fn detect_power_state_sysfs() -> PowerState {
    let ps_dir = std::path::Path::new("/sys/class/power_supply");
    let Ok(entries) = std::fs::read_dir(ps_dir) else {
        // Cannot read power supply directory — assume AC on a desktop.
        return PowerState::AC;
    };

    let mut any_ac_online      = false;
    let mut any_bat_discharging = false;

    for entry in entries.flatten() {
        let path = entry.path();
        let type_str = std::fs::read_to_string(path.join("type"))
            .unwrap_or_default();

        match type_str.trim() {
            "Mains" => {
                let online = std::fs::read_to_string(path.join("online"))
                    .unwrap_or_default();
                if online.trim() == "1" {
                    any_ac_online = true;
                }
            }
            "Battery" => {
                let status = std::fs::read_to_string(path.join("status"))
                    .unwrap_or_default();
                if status.trim().eq_ignore_ascii_case("discharging") {
                    any_bat_discharging = true;
                }
            }
            _ => {} // USB, UPS, etc. — ignored
        }
    }

    // Return Battery only when a battery is actively discharging and no
    // mains adapter is online.  Desktops with no battery at all have both
    // flags false, correctly returning AC.
    if any_bat_discharging && !any_ac_online {
        PowerState::Battery
    } else {
        PowerState::AC
    }
}

/// Monitor power state changes using UPower D-Bus.
/// Falls back to sysfs polling if UPower is not available.
/// Returns a watch receiver of PowerState.
pub async fn monitor_power_state() -> tokio::sync::watch::Receiver<PowerState> {
    let initial = detect_power_state_sysfs();
    let (tx, rx) = tokio::sync::watch::channel(initial);

    tokio::spawn(async move {
        // Try to subscribe to UPower via D-Bus.
        match subscribe_upower(tx.clone()).await {
            Ok(_) => {} // UPower task took over
            Err(e) => {
                tracing::info!("UPower not available ({}), polling sysfs every 30s", e);
                // Fall back to polling sysfs.
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    let new_state = detect_power_state_sysfs();
                    // Only send when the state actually changed; sending the
                    // same value every tick would mark the watch as modified
                    // and cause the daemon's power handler to fire spuriously.
                    if *tx.borrow() != new_state {
                        if tx.send(new_state).is_err() { break; }
                    }
                }
            }
        }
    });

    rx
}

async fn subscribe_upower(tx: tokio::sync::watch::Sender<PowerState>) -> anyhow::Result<()> {
    use futures_util::StreamExt as _;

    let conn = zbus::Connection::system().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.UPower",
        "/org/freedesktop/UPower",
        "org.freedesktop.UPower",
    ).await?;

    // Read initial value.
    let on_battery: bool = proxy.get_property("OnBattery").await?;
    let _ = tx.send(if on_battery { PowerState::Battery } else { PowerState::AC });

    // Subscribe to PropertiesChanged via fdo::PropertiesProxy.
    let props = zbus::fdo::PropertiesProxy::builder(&conn)
        .destination("org.freedesktop.UPower")?
        .path("/org/freedesktop/UPower")?
        .build()
        .await?;

    let mut stream = props.receive_properties_changed().await?;

    while let Some(signal) = stream.next().await {
        let args = signal.args()?;
        if args.interface_name().as_str() == "org.freedesktop.UPower" {
            if let Some(val) = args.changed_properties().get("OnBattery") {
                // val is &zvariant::Value<'_>
                if let Ok(on_bat) = bool::try_from(val) {
                    let state = if on_bat { PowerState::Battery } else { PowerState::AC };
                    info!("power state changed: {:?}", state);
                    if tx.send(state).is_err() { break; }
                }
            }
        }
    }

    Ok(())
}
