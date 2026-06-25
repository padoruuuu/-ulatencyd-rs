//! PSI (Pressure Stall Information) monitor.
//!
//! Polls /proc/pressure/{memory,cpu,io} every 500 ms and classifies the
//! system into Normal / Low / High / Critical pressure states.

use std::time::Duration;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::debug;

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
// Monitor
// ---------------------------------------------------------------------------

/// Configuration thresholds for pressure classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PsiConfig {
    pub memory_low_threshold:  f32,   // default 5.0
    pub memory_high_threshold: f32,   // default 40.0
    pub io_high_threshold:     f32,   // default 60.0
    pub check_interval_ms:     u64,   // default 500
}

impl Default for PsiConfig {
    fn default() -> Self {
        Self {
            memory_low_threshold:  5.0,
            memory_high_threshold: 40.0,
            io_high_threshold:     60.0,
            check_interval_ms:     500,
        }
    }
}

/// Spawns a background task polling /proc/pressure/*.
/// Returns a watch receiver updated every `check_interval_ms`.
pub fn spawn_psi_monitor(config: PsiConfig) -> watch::Receiver<SystemPressure> {
let (tx, rx) = watch::channel(SystemPressure::default());

tokio::spawn(async move {
let interval = Duration::from_millis(config.check_interval_ms);
// Reuse a single buffer across reads to reduce allocations.
let mut buf = String::with_capacity(256);
loop {
let pressure = SystemPressure {
cpu: read_psi_into("/proc/pressure/cpu", &mut buf).unwrap_or_default(),
memory: read_psi_into("/proc/pressure/memory", &mut buf).unwrap_or_default(),
io: read_psi_into("/proc/pressure/io", &mut buf).unwrap_or_default(),
};

debug!(
"psi: mem.some_avg10={:.1} io.some_avg10={:.1}",
pressure.memory.some_avg10,
pressure.io.some_avg10
);

if tx.send(pressure).is_err() {
break; // receiver dropped
}

tokio::time::sleep(interval).await;
}
});

rx
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

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------


