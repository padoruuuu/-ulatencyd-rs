//! Configuration loaded from /etc/ulatencyd/ulatencyd.json

use std::path::PathBuf;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use psi::PsiConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub cgroups: CgroupsConfig,
    #[serde(default)]
    pub pressure: PsiConfig,
    #[serde(default)]
    pub fork_bomb: ForkBombConfig,
    #[serde(default)]
    pub sched: SchedConfig,
    #[serde(default)]
    pub control_socket: ControlSocketConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            daemon:         DaemonConfig::default(),
            cgroups:        CgroupsConfig::default(),
            pressure:       PsiConfig::default(),
            fork_bomb:      ForkBombConfig::default(),
            sched:          SchedConfig::default(),
            control_socket: ControlSocketConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    pub log_level:                    String,
    pub pid_file:                     PathBuf,
    pub rules_dir:                    Vec<PathBuf>,
    pub rescan_interval_secs:         u64,
    pub apply_to_existing_processes:  bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            log_level:                   "info".into(),
            pid_file:                    PathBuf::from("/run/ulatencyd.pid"),
            rules_dir:                   vec![
                PathBuf::from("/etc/ulatencyd/rules"),
                PathBuf::from("/usr/lib/ulatencyd/rules"),
            ],
            rescan_interval_secs:        30,
            apply_to_existing_processes: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CgroupsConfig {
    /// Override the cgroup root path on non-systemd systems.
    #[serde(default)]
    pub cgroup_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ForkBombConfig {
    pub threshold_per_second: u32,
    pub lineage_depth:        u32,
}

impl Default for ForkBombConfig {
    fn default() -> Self {
        Self { threshold_per_second: 50, lineage_depth: 5 }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SchedConfig {
    /// Disable kernel autogroup on startup (default: true).
    pub autogroup_enabled:   bool,
    /// sched_ext: detect and skip CPU weight management if active.
    pub detect_and_defer:    bool,
}

impl Default for SchedConfig {
    fn default() -> Self {
        Self { autogroup_enabled: false, detect_and_defer: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlSocketConfig {
    pub enabled: bool,
    pub path:    PathBuf,
    /// Group that owns the socket and its parent directory. Only members of
    /// this group can connect — see crates/core/src/control.rs §5.
    pub group:   String,
}

impl Default for ControlSocketConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path:    PathBuf::from("/run/ulatencyd/control.sock"),
            group:   "ulatencyd".into(),
        }
    }
}

// ---------------------------------------------------------------------------

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("parse config {}", path.display()))
    }

    pub fn load_or_default(path: &std::path::Path) -> Self {
        match Self::load(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("config load failed ({}), using defaults", e);
                Self::default()
            }
        }
    }
}
