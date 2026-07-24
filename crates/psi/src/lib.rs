//! PSI (Pressure Stall Information) monitor.
//!
//! Kernel-native reactive design: arms threshold triggers on
//! `/proc/pressure/memory` (kernel 5.2+) and blocks in `poll()` for
//! `POLLPRI`, instead of polling on a fixed interval. The kernel wakes us
//! only when accumulated stall time crosses a threshold within the
//! trailing window (rate-limited to once per window), so CPU usage is
//! zero while the system is calm.
//!
//! `poll()`'s timeout argument doubles as a fallback tick: the kernel has
//! no "pressure resolved" notification (only "crossed into a stall
//! state"), and cpu/io numbers need to stay fresh for on-demand queries
//! even when nothing is triggering. A few seconds is plenty for that,
//! since this no longer needs to be the primary polling loop the way it
//! was before triggers existed.
//!
//! Deliberately avoids `tokio::io::unix::AsyncFd` even where tokio is
//! otherwise in use elsewhere, because of a still-open tokio issue
//! (#6632) about `AsyncFd` mishandling priority-readiness on some fd
//! types — but since this crate has no tokio dependency at all, that's
//! moot here; the real reason is just architectural consistency with
//! procmon's netlink thread, which also drives a raw fd with
//! `libc::poll()` on its own dedicated OS thread.

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Metrics for a single PSI resource (cpu, memory, or io).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct PsiMetrics {
    pub some_avg10:  f32,
    pub some_avg60:  f32,
    pub some_avg300: f32,
    pub full_avg10:  f32,
    pub full_avg60:  f32,
    pub full_avg300: f32,
}

/// Snapshot of all three PSI subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct SystemPressure {
    pub cpu:    PsiMetrics,
    pub memory: PsiMetrics,
    pub io:     PsiMetrics,
}

/// Discrete pressure level derived from memory.some_avg10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PressureLevel {
    Normal   = 0,
    Low      = 1,
    High     = 2,
    Critical = 3,
}

impl PressureLevel {
    pub fn from_memory(metrics: &PsiMetrics, low_thresh: f32, high_thresh: f32) -> Self {
        if metrics.some_avg10 >= high_thresh * 1.5 {
            Self::Critical
        } else if metrics.some_avg10 >= high_thresh {
            Self::High
        } else if metrics.some_avg10 >= low_thresh {
            Self::Low
        } else {
            Self::Normal
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration thresholds for pressure classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PsiConfig {
    pub memory_low_threshold:  f32,   // default 5.0  (%)
    pub memory_high_threshold: f32,   // default 40.0 (%)
    /// Fallback poll() timeout in milliseconds. Doubles as the interval at
    /// which cpu/io numbers are refreshed and "pressure resolved"
    /// transitions are caught (the kernel only notifies on crossing *into*
    /// a stall state, never back out of one). This used to be the primary
    /// polling interval before kernel-native triggers existed, so it no
    /// longer needs to be aggressive — default 3000ms vs. the old 500ms.
    pub check_interval_ms:     u64,
}

impl Default for PsiConfig {
    fn default() -> Self {
        Self {
            memory_low_threshold:  5.0,
            memory_high_threshold: 40.0,
            check_interval_ms:     3000,
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel-native trigger (poll() on /proc/pressure/memory)
// ---------------------------------------------------------------------------

/// A single armed PSI threshold trigger. Holds its own fd — a separate
/// `open()` is required per trigger, even against the same file. Dropping
/// this closes the fd, which de-registers the trigger with the kernel.
struct Trigger {
    fd:    RawFd,
    label: &'static str,
}

impl Trigger {
    /// Open `path`, write a `"some <stall_us> <window_us>"` trigger string,
    /// and return the armed trigger. `window_us` must be 500ms–10s on
    /// kernels older than 6.5 (unbounded above on newer kernels).
    fn arm(path: &str, stall_us: u64, window_us: u64, label: &'static str) -> Result<Self> {
        let cpath = CString::new(path).context("path contains a NUL byte")?;

        // SAFETY: cpath is a valid, NUL-terminated C string.
        let fd = unsafe {
            libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC)
        };
        if fd < 0 {
            bail!("open {} failed: errno {}", path, errno());
        }

        let trigger = format!("some {} {}\0", stall_us, window_us);
        // SAFETY: fd is freshly opened and valid; trigger is a valid buffer
        // for its own length.
        let rc = unsafe {
            libc::write(fd, trigger.as_ptr() as *const libc::c_void, trigger.len())
        };
        if rc < 0 {
            let e = errno();
            // SAFETY: fd was opened above and hasn't been closed yet.
            unsafe { libc::close(fd); }
            bail!("write trigger {:?} to {} failed: errno {}", trigger.trim_end_matches('\0'), path, e);
        }

        Ok(Self { fd, label })
    }
}

impl Drop for Trigger {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this Trigger and only closed once.
        unsafe { libc::close(self.fd); }
    }
}

/// Convert a percentage threshold (e.g. 40.0 meaning 40%) into a stall_us
/// value for the given window, clamped to a sane range. This makes a PSI
/// kernel trigger fire at roughly the same point that `some_avg10 >= pct`
/// would have crossed under the old polling design.
fn pct_to_stall_us(pct: f32, window_us: u64) -> u64 {
    let clamped = pct.clamp(0.1, 99.0) as f64 / 100.0;
    ((window_us as f64) * clamped).round().max(1.0) as u64
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

/// Spawn the PSI monitor on a dedicated OS thread.
///
/// Returns an `Arc<Mutex<SystemPressure>>` holding the latest reading,
/// readable at any time (used to answer on-demand queries like
/// `ulatencyctl pressure` / `GetSystemPressure` without waiting for a
/// wake). On every wake — kernel trigger or fallback timeout — the fresh
/// reading is stored there *and* passed to `on_update`.
///
/// `on_update` returns `false` to ask the thread to exit (e.g. because the
/// receiving end of whatever channel it forwards into has closed, meaning
/// the daemon is shutting down). This crate has no dependency on the
/// daemon's `Event` type, so the caller (`crates/core`, which already
/// depends on `psi`) is expected to pass a closure that does something
/// like `move |p| event_tx.send(Event::Pressure(p)).is_ok()`.
pub fn spawn_psi_monitor<F>(config: PsiConfig, on_update: F) -> Arc<Mutex<SystemPressure>>
where
    F: FnMut(SystemPressure) -> bool + Send + 'static,
{
    let latest = Arc::new(Mutex::new(SystemPressure::default()));
    let latest_for_thread = latest.clone();

    std::thread::Builder::new()
        .name("psi-monitor".into())
        .spawn(move || run_monitor(config, latest_for_thread, on_update))
        .expect("failed to spawn psi-monitor thread");

    latest
}

fn run_monitor<F>(config: PsiConfig, latest: Arc<Mutex<SystemPressure>>, mut on_update: F)
where
    F: FnMut(SystemPressure) -> bool,
{
    const WINDOW_US: u64 = 1_000_000; // 1s — a good uniform choice per kernel docs.

    // Only memory.some_avg10 currently drives reactive behaviour
    // (handle_pressure_change), so only memory gets real kernel triggers.
    // cpu/io are read on every wake (trigger or fallback) purely for
    // on-demand display — nothing currently reacts to them.
    let levels: [(&'static str, f32); 3] = [
        ("low",      config.memory_low_threshold),
        ("high",     config.memory_high_threshold),
        ("critical", (config.memory_high_threshold * 1.5).min(99.0)),
    ];

    let mut triggers: Vec<Trigger> = Vec::new();
    for (label, pct) in levels {
        let stall_us = pct_to_stall_us(pct, WINDOW_US);
        match Trigger::arm("/proc/pressure/memory", stall_us, WINDOW_US, label) {
            Ok(t)  => {
                debug!("psi: armed memory/{} trigger (stall_us={} window_us={})", label, stall_us, WINDOW_US);
                triggers.push(t);
            }
            Err(e) => {
                // Graceful degradation: old kernel, psi=0, or a container
                // without /proc/pressure. Just don't add this fd to the
                // poll set — poll() with fewer/zero fds simply blocks for
                // the timeout and returns 0, which degrades to plain
                // timer-only behaviour automatically. Never crashes the
                // daemon on systems without working PSI.
                warn!("psi: could not arm memory/{} trigger: {} (degrading to timer-only)", label, e);
            }
        }
    }
    if triggers.is_empty() {
        warn!("psi: no kernel triggers armed; falling back to timer-only polling every {}ms", config.check_interval_ms);
    }

    let timeout_ms = config.check_interval_ms.clamp(1, i32::MAX as u64) as i32;
    let mut buf = String::with_capacity(256);

    loop {
        let mut pollfds: Vec<libc::pollfd> = triggers
            .iter()
            .map(|t| libc::pollfd { fd: t.fd, events: libc::POLLPRI, revents: 0 })
            .collect();

        // SAFETY: pollfds is a valid array of the given length (possibly
        // empty, which is valid — poll() then just sleeps for the timeout).
        let n = unsafe {
            libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms)
        };

        if n < 0 {
            let e = errno();
            if e == libc::EINTR {
                continue; // interrupted by a signal — just re-poll.
            }
            error!("psi: poll() failed: errno {} — falling back to a plain sleep", e);
            std::thread::sleep(Duration::from_millis(timeout_ms as u64));
        } else if n > 0 {
            for (pfd, trigger) in pollfds.iter().zip(triggers.iter()) {
                if pfd.revents & libc::POLLPRI != 0 {
                    debug!("psi: memory/{} trigger fired", trigger.label);
                }
                if pfd.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                    warn!("psi: memory/{} trigger fd reported an error (revents={:#x})", trigger.label, pfd.revents);
                }
            }
        }
        // n == 0: fallback timeout elapsed — read fresh values anyway, both
        // to keep cpu/io numbers current and to catch "pressure resolved"
        // transitions the kernel never explicitly signals.

        let pressure = SystemPressure {
            cpu:    read_psi_into("/proc/pressure/cpu", &mut buf).unwrap_or_default(),
            memory: read_psi_into("/proc/pressure/memory", &mut buf).unwrap_or_default(),
            io:     read_psi_into("/proc/pressure/io", &mut buf).unwrap_or_default(),
        };

        debug!(
            "psi: mem.some_avg10={:.1} io.some_avg10={:.1}",
            pressure.memory.some_avg10,
            pressure.io.some_avg10
        );

        *latest.lock().unwrap() = pressure;

        if !on_update(pressure) {
            debug!("psi: on_update signalled shutdown, exiting monitor thread");
            return; // dropping `triggers` here closes the fds.
        }
    }
}

// Parse a PSI file into a buffer, reusing the buffer's capacity.
fn read_psi_into(path: &str, buf: &mut String) -> Result<PsiMetrics> {
    buf.clear();
    std::fs::read_to_string(path)
        .with_context(|| format!("read PSI {}", path))
        .map(|s| buf.push_str(&s))?;

    let content = buf.as_str();
    let mut m = PsiMetrics::default();
    for line in content.lines() {
        let mut iter = line.split_ascii_whitespace();
        let kind = iter.next().unwrap_or("");
        let mut avg10 = 0f32;
        let mut avg60 = 0f32;
        let mut avg300 = 0f32;
        for field in iter {
            if let Some(v) = field.strip_prefix("avg10=") {
                avg10 = v.parse().unwrap_or(0.0);
            } else if let Some(v) = field.strip_prefix("avg60=") {
                avg60 = v.parse().unwrap_or(0.0);
            } else if let Some(v) = field.strip_prefix("avg300=") {
                avg300 = v.parse().unwrap_or(0.0);
            }
        }
        match kind {
            "some" => { m.some_avg10 = avg10; m.some_avg60 = avg60; m.some_avg300 = avg300; }
            "full" => { m.full_avg10 = avg10; m.full_avg60 = avg60; m.full_avg300 = avg300; }
            _ => {}
        }
    }
    Ok(m)
}

fn errno() -> i32 {
    // SAFETY: no invariants; just reads thread-local errno.
    unsafe { *libc::__errno_location() }
}
