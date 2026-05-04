//! CFS/EEVDF scheduler tuning and power-aware profile switching.
//!
//! Two scheduling profiles:
//!   RESPONSIVE — AC power, desktop use (lower latency knobs)
//!   CONSERVATIVE — battery, server (kernel defaults)
//!
//! Autogroup disabling is the single highest-impact change (Learning 1).

use anyhow::Result;
use tracing::{info, warn};
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
    latency_ns:             4_000_000,
    min_granularity_ns:     0,         // removed in kernel 6.6 (EEVDF)
    wakeup_granularity_ns:  0,         // removed in kernel 6.6 (EEVDF)
    bandwidth_slice_us:     3_000,
    preempt: Some("full"),
};

pub const CONSERVATIVE: SchedProfile = SchedProfile {
    latency_ns:             6_000_000,
    min_granularity_ns:     0,         // removed in kernel 6.6 (EEVDF)
    wakeup_granularity_ns:  0,         // removed in kernel 6.6 (EEVDF)
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
// Sysctl profile application
// ---------------------------------------------------------------------------

/// Apply a scheduling profile by writing sysctl knobs.
/// Silently skips knobs that are not writable (some hardened kernels make
/// them read-only). Logs a warning but does not return an error so that
/// cgroup management continues to work independently.
pub fn apply_sched_profile(profile: &SchedProfile) {
    let knobs: &[(&str, u64)] = &[
        ("kernel/sched_latency_ns",             profile.latency_ns),
        ("kernel/sched_min_granularity_ns",     profile.min_granularity_ns),
        ("kernel/sched_wakeup_granularity_ns",  profile.wakeup_granularity_ns),
        ("kernel/sched_cfs_bandwidth_slice_us", profile.bandwidth_slice_us),
    ];

    for (key, value) in knobs {
        if *value == 0 {
            continue; // 0 means "not applicable on this kernel version", skip silently
        }
        if let Err(e) = write_sysctl(key, *value) {
            warn!("sysctl {}: {} (skipping)", key, e);
        } else {
            tracing::debug!("sysctl {} = {}", key, value);
        }
    }

    if let Some(preempt) = profile.preempt {
        // debugfs path (not always mounted).
        let p = "/sys/kernel/debug/sched/preempt";
        if std::path::Path::new(p).exists() {
            if let Err(e) = std::fs::write(p, preempt) {
                warn!("write preempt model {:?}: {}", preempt, e);
            } else {
                info!("preempt model set to {}", preempt);
            }
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

/// Check /sys/class/power_supply/*/status for "Discharging".
/// Returns Battery if any supply is discharging; AC otherwise.
/// Used when UPower D-Bus is unavailable (runit/minimal systems).
pub fn detect_power_state_sysfs() -> PowerState {
    for entry in glob_status_files() {
        if let Ok(status) = std::fs::read_to_string(&entry) {
            if status.trim().eq_ignore_ascii_case("discharging") {
                return PowerState::Battery;
            }
        }
    }
    PowerState::AC
}

fn glob_status_files() -> Vec<std::path::PathBuf> {
    let dir = std::path::Path::new("/sys/class/power_supply");
    if !dir.exists() {
        return Vec::new();
    }
    std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().join("status"))
        .collect()
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
                    let state = detect_power_state_sysfs();
                    if tx.send(state).is_err() { break; }
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
