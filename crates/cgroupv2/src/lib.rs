//! Cgroup v2 manager — creates/manages the ulatencyd cgroup hierarchy.
//!
//! Hierarchy (flat, ≤2 levels per kernel 7.1 cgroup sub-scheduler guidance):
//!
//! ```text
//! /sys/fs/cgroup/ulatencyd/      (or ulatencyd.slice/ on systemd)
//! ├── rt/           cpu.weight=9000  io.weight=9000
//! ├── interactive/  cpu.weight=5000
//! ├── system/       cpu.weight=2000
//! ├── background/   cpu.weight=500   io.weight=100
//! ├── idle/         cpu.weight=100   memory.high=256M
//! └── swapstorm/    cpu.weight=50    memory.max=128M  memory.swap.max=0
//! ```

use std::path::PathBuf;
use std::sync::OnceLock;
use anyhow::{Context, Result};
use tokio::fs;
use tracing::{debug, info, warn};

/// Inode of /proc/self/ns/cgroup, cached at first call.
static SELF_CGROUP_NS: OnceLock<u64> = OnceLock::new();



/// Returns true if `pid` is in the same cgroup namespace as this process.
/// Processes in a different namespace (bwrap, containers) are skipped.
pub fn same_cgroup_ns(pid: u32) -> bool {
    let self_ino = SELF_CGROUP_NS.get_or_init(|| {
        std::fs::metadata("/proc/self/ns/cgroup")
            .map(|m| { use std::os::unix::fs::MetadataExt; m.ino() })
            .unwrap_or(0)
    });

    let proc_ino = std::fs::metadata(format!("/proc/{}/ns/cgroup", pid))
        .map(|m| { use std::os::unix::fs::MetadataExt; m.ino() })
        .unwrap_or(0);

    // If we can't read either, assume same namespace (will fail gracefully on write).
    if *self_ino == 0 || proc_ino == 0 { return true; }
    *self_ino == proc_ino
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A handle to a single cgroup directory.
#[derive(Debug, Clone)]
pub struct Cgroup {
    pub path: PathBuf,
}

impl Cgroup {
    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    async fn write(&self, name: &str, value: &str) -> Result<()> {
        let path = self.file(name);
        fs::write(&path, value)
            .await
            .with_context(|| format!("write {} = {:?}", path.display(), value))
    }

    /// Write PID to cgroup.procs (assigns the process to this cgroup).
    pub async fn assign_pid(&self, pid: u32) -> Result<()> {
        self.write("cgroup.procs", &format!("{}\n", pid)).await
    }

    /// List all PIDs currently in this cgroup.
    pub async fn pids(&self) -> Result<Vec<u32>> {
        let content = fs::read_to_string(self.file("cgroup.procs"))
            .await
            .with_context(|| format!("read {}/cgroup.procs", self.path.display()))?;
        Ok(content
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect())
    }

    /// Kill all processes in this cgroup atomically (requires kernel 5.14+).
    pub async fn kill_all(&self) -> Result<()> {
        self.write("cgroup.kill", "1").await
    }

    // --- resource knobs ---

    pub async fn set_cpu_weight(&self, weight: u32) -> Result<()> {
        self.write("cpu.weight", &format!("{}\n", weight.clamp(1, 10_000))).await
    }

    pub async fn set_cpu_max(&self, quota_us: u64, period_us: u64) -> Result<()> {
        self.write("cpu.max", &format!("{} {}\n", quota_us, period_us)).await
    }

    pub async fn set_memory_high(&self, bytes: u64) -> Result<()> {
        self.write("memory.high", &format!("{}\n", bytes)).await
    }

    pub async fn set_memory_max(&self, bytes: u64) -> Result<()> {
        self.write("memory.max", &format!("{}\n", bytes)).await
    }

    pub async fn set_memory_swap_max(&self, bytes: u64) -> Result<()> {
        // "0" disables swap for this cgroup.
        self.write("memory.swap.max", &format!("{}\n", bytes)).await
    }

    pub async fn set_io_weight(&self, weight: u32) -> Result<()> {
        self.write("io.weight", &format!("{}\n", weight.clamp(1, 10_000))).await
    }

    pub async fn set_oom_group(&self, enable: bool) -> Result<()> {
        self.write("memory.oom.group", if enable { "1\n" } else { "0\n" }).await
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Well-known cgroup tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CgroupTier {
    Rt,
    Interactive,
    System,
    Background,
    Idle,
    Swapstorm,
}

impl CgroupTier {
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Rt          => "rt",
            Self::Interactive => "interactive",
            Self::System      => "system",
            Self::Background  => "background",
            Self::Idle        => "idle",
            Self::Swapstorm   => "swapstorm",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "rt"          => Some(Self::Rt),
            "interactive" => Some(Self::Interactive),
            "system"      => Some(Self::System),
            "background"  => Some(Self::Background),
            "idle"        => Some(Self::Idle),
            "swapstorm"   => Some(Self::Swapstorm),
            _             => None,
        }
    }
}

/// Manages the ulatencyd cgroup subtree.
pub struct CgroupManager {
    /// Absolute path to our delegated root (e.g. /sys/fs/cgroup/ulatencyd).
    pub root: PathBuf,
    /// Available controllers detected at runtime.
    pub controllers: Vec<String>,
    /// sched_ext active? If so, skip cpu.weight changes.
    pub sched_ext_active: bool,
}

impl CgroupManager {
    /// Initialise the manager, creating the cgroup hierarchy from scratch.
    /// Call after init-system-specific root setup.
    pub async fn new(root: PathBuf) -> Result<Self> {
        let mut mgr = Self {
            root,
            controllers: Vec::new(),
            sched_ext_active: detect_sched_ext(),
        };
        mgr.setup_hierarchy().await?;
        Ok(mgr)
    }

    /// Return the Cgroup handle for a named tier.
    pub fn tier_cgroup(&self, tier: CgroupTier) -> Cgroup {
        Cgroup {
            path: self.root.join(tier.dir_name()),
        }
    }

    /// Return the root cgroup (used to move PIDs back on shutdown).
    pub fn root_cgroup(&self) -> Cgroup {
        Cgroup { path: self.root.clone() }
    }

    /// Assign a PID to a named tier (or root cgroup).
    /// Silently skips processes that are in a different cgroup namespace
    /// (e.g. inside a bwrap/container sandbox) — moving them would either
    /// fail with EINVAL or break their sandbox.
    pub async fn assign_pid(&self, tier: Option<CgroupTier>, pid: u32) -> Result<()> {
        if !same_cgroup_ns(pid) {
            debug!("skipping pid {} — different cgroup namespace (sandboxed)", pid);
            return Ok(());
        }
        let cgroup = match tier {
            Some(t) => self.tier_cgroup(t),
            None    => self.root_cgroup(),
        };
        cgroup.assign_pid(pid).await
    }

    /// Garbage-collect empty child cgroups (non-blocking, spawns a task).
    /// A tier cgroup is only removable when it has no member processes.
    /// We leave occupied tiers alone — they are rebuilt on the next setup_hierarchy().
    pub fn gc_empty_cgroups(&self) {
        let root = self.root.clone();
        tokio::spawn(async move {
            for tier in all_tiers() {
                let cg = Cgroup { path: root.join(tier.dir_name()) };
                match cg.pids().await {
                    Ok(pids) if pids.is_empty() => {
                        // Bug 4 fix: actually remove the empty directory instead
                        // of only logging it.  remove_dir() is a no-op if the
                        // cgroup doesn't exist or isn't empty.
                        match fs::remove_dir(&cg.path).await {
                            Ok(_)  => debug!("gc: removed empty cgroup {}", cg.path.display()),
                            Err(e) => debug!("gc: could not remove {}: {}", cg.path.display(), e),
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    /// Shutdown cleanup.
    ///
    /// Managed processes are not killed when the daemon stops; they continue
    /// running in whichever tier they were last placed.  We only try to remove
    /// now-empty tier directories.
    ///
    /// Each rmdir is capped at 100 ms; occupied cgroups are silently left in
    /// place — the kernel removes them automatically once the last process exits.
    pub async fn teardown(&self) {
        for tier in all_tiers() {
            let path = self.root.join(tier.dir_name());
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                fs::remove_dir(&path),
            ).await {
                Ok(Ok(_))  => debug!("teardown: removed {}", path.display()),
                Ok(Err(e)) => debug!("teardown: {} occupied or missing: {}", path.display(), e),
                Err(_)     => debug!("teardown: {} timed out", path.display()),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    async fn setup_hierarchy(&mut self) -> Result<()> {
        // Detect available controllers.
        let avail = self.read_available_controllers().await;
        self.controllers = avail;

        // Enable controllers in our root's subtree_control.
        let wanted: Vec<&str> = ["cpu", "memory", "io", "cpuset"]
            .iter()
            .filter(|&&c| self.controllers.iter().any(|a| a == c))
            .copied()
            .collect();

        if !wanted.is_empty() {
            let value = wanted.iter().map(|c| format!("+{}", c)).collect::<Vec<_>>().join(" ");
            let sc_path = self.root.join("cgroup.subtree_control");
            if let Err(e) = fs::write(&sc_path, &value).await {
                warn!("set subtree_control {:?}: {}", value, e);
            } else {
                info!("enabled controllers: {}", value);
            }
        }

        // Create tier directories and configure them.
        self.create_and_configure_tiers().await?;

        Ok(())
    }

    async fn create_and_configure_tiers(&self) -> Result<()> {
        // TODO(cgroupv2-future): Upcoming kernel interfaces worth adopting:
        //
        // 1. cpu.idle (kernel 6.4+, stable): Writing `1` makes an entire cgroup
        //    run at SCHED_IDLE priority — strictly below all non-idle CFS work.
        //    The `idle` and `swapstorm` tiers currently use cpu.weight=100/50.
        //    Switching them to cpu.idle=1 is more semantically correct and more
        //    aggressive about deprioritisation.  Gated on kernel version detection.
        //
        // 2. memory.reclaim (kernel 6.4+, stable): A write-only file that triggers
        //    synchronous memory reclaim on a cgroup.  In handle_pressure_change(High),
        //    instead of/before moving processes to `swapstorm`, proactively writing to
        //    idle/memory.reclaim and background/memory.reclaim could free memory without
        //    a disruptive cgroup move.
        //
        // 3. cgroup.pressure (modern kernels): A per-cgroup PSI roll-up.  Can be read
        //    to see which of our own tiers is under pressure — more granular than
        //    /proc/pressure/memory which is system-wide.
        //
        // 4. PSI threshold notifications via poll() (kernel 5.2+): /proc/pressure/memory
        //    accepts writes of the form `some 500 1000000` to register a threshold
        //    trigger; the fd becomes readable when the threshold is crossed.  This would
        //    let psi/src/lib.rs switch from 500 ms polling to event-driven wakeups —
        //    better latency, zero CPU when idle.
        //
        // 5. sched_ext cgroup weight callbacks (kernel 6.12+, maturing in 6.14/6.15):
        //    When a BPF scheduler implements `cgroup_set_weight`, our cpu.weight writes
        //    *do* have effect under sched_ext.  Detection should be refined: check
        //    whether the active scheduler has the callback rather than skipping all
        //    weight writes unconditionally via sched_ext_active.
        //
        // 6. memory.zswap.max / memory.zswap.writeback (kernel 6.x, stable): For the
        //    `swapstorm` tier, in addition to memory.swap.max=0, consider setting
        //    memory.zswap.max=0 to also block zswap usage, or conversely allow
        //    zswap-only (no disk swap) as a softer limit.
        for tier in all_tiers() {
            let dir = self.root.join(tier.dir_name());
            if !dir.exists() {
                fs::create_dir(&dir)
                    .await
                    .with_context(|| format!("create cgroup dir {}", dir.display()))?;
            }
            let cg = Cgroup { path: dir };

            // Configure each tier's resource limits.
            match tier {
                CgroupTier::Rt => {
                    if !self.sched_ext_active {
                        let _ = cg.set_cpu_weight(9000).await;
                    }
                    let _ = cg.set_io_weight(9000).await;
                    let _ = cg.set_oom_group(true).await;
                }
                CgroupTier::Interactive => {
                    if !self.sched_ext_active {
                        let _ = cg.set_cpu_weight(5000).await;
                    }
                }
                CgroupTier::System => {
                    if !self.sched_ext_active {
                        let _ = cg.set_cpu_weight(2000).await;
                    }
                }
                CgroupTier::Background => {
                    if !self.sched_ext_active {
                        let _ = cg.set_cpu_weight(500).await;
                    }
                    let _ = cg.set_io_weight(100).await;
                }
                CgroupTier::Idle => {
                    if !self.sched_ext_active {
                        let _ = cg.set_cpu_weight(100).await;
                    }
                    let _ = cg.set_memory_high(256 * 1024 * 1024).await;
                }
                CgroupTier::Swapstorm => {
                    if !self.sched_ext_active {
                        let _ = cg.set_cpu_weight(50).await;
                    }
                    let _ = cg.set_memory_max(128 * 1024 * 1024).await;
                    let _ = cg.set_memory_swap_max(0).await;
                    let _ = cg.set_oom_group(true).await;
                }
            }
        }
        Ok(())
    }

    async fn read_available_controllers(&self) -> Vec<String> {
        let path = self.root.join("cgroup.controllers");
        fs::read_to_string(&path)
            .await
            .unwrap_or_default()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Init-system-aware root setup (called before CgroupManager::new)
// ---------------------------------------------------------------------------

/// Initialise the cgroup root at /sys/fs/cgroup/ulatencyd.
/// Does NOT write to the root cgroup.subtree_control — that is owned by the
/// system's session manager (elogind/systemd-logind). Writing to it disrupts
/// their cgroup delegation and causes elogind to crash on runit systems.
/// Controllers are enabled in our own subtree by CgroupManager::setup_hierarchy.
pub async fn setup_direct_root() -> Result<PathBuf> {
    let root = PathBuf::from("/sys/fs/cgroup/ulatencyd");
    fs::create_dir_all(&root)
        .await
        .with_context(|| format!("create {}", root.display()))?;
    Ok(root)
}

// ---------------------------------------------------------------------------
// sched_ext detection
// ---------------------------------------------------------------------------

pub fn detect_sched_ext() -> bool {
    std::fs::read_to_string("/sys/kernel/sched_ext/state")
        .map(|s| s.trim() == "enabled")
        .unwrap_or(false)
}

fn all_tiers() -> &'static [CgroupTier] {
    use CgroupTier::*;
    &[Rt, Interactive, System, Background, Idle, Swapstorm]
}
