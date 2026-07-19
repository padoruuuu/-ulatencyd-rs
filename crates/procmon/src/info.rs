use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedPolicy {
    Normal, Batch, Idle,
    Fifo(u8), RoundRobin(u8), Deadline,
    Unknown(i32),
}

/// Where a process lives according to the cgroup v2 hierarchy.
/// Derived from /proc/pid/cgroup without knowing any app names.
/// Works on all init systems — runit/s6/OpenRC processes all appear
/// under "/" or flat paths; systemd provides richer paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOrigin {
    /// User process in an interactive login session
    UserInteractive,
    /// User process launched as an app or service
    UserService,
    /// System-level service or uid=0 process
    SystemService,
    /// Kernel thread (uid=0, no exe in /proc/pid/exe)
    KernelThread,
    /// Unclassified — treat conservatively
    Unknown,
}

impl SessionOrigin {
    /// Derive origin from the raw cgroup v2 path.
    /// `our_mark` is a substring that identifies our own cgroup root
    /// (e.g. "ulatencyd" or "ulatencyd.service").
    pub fn from_cgroup_path(path: &str, uid: u32, our_mark: &str) -> Self {
        // Check our marker first.
        if path.contains(our_mark) {
            // Even inside our hierarchy, use uid to distinguish system vs user
            // so default_cgroup_for can make the right decision.
            if uid == 0 {
                return Self::SystemService;
            }
            return Self::UserInteractive;
        }
        if path.contains("/user.slice/") {
            if path.contains("/session-") {
                return Self::UserInteractive;
            }
            return Self::UserService;
        }
        if path.contains("/system.slice/") || path.starts_with("/init.scope") {
            return Self::SystemService;
        }
        // Non-systemd fallback: use uid.
        if path == "/" || path.is_empty() {
            if uid == 0 { return Self::SystemService; }
            return Self::UserInteractive;
        }
        Self::Unknown
    }

    /// True if this process is a kernel thread (never should be moved).
    pub fn is_kernel() -> bool { false } // checked separately via exe
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid:            u32,
    pub ppid:           u32,
    pub uid:            u32,
    pub gid:            u32,
    pub comm:           String,
    pub cmdline:        Vec<String>,
    pub exe:            Option<PathBuf>,
    pub threads:        u32,
    pub vm_rss_kb:      u64,
    pub sched_policy:   SchedPolicy,
    pub nice:           i8,
    pub cgroup_path:    Option<String>,
    /// Derived classification — stable without app-name knowledge.
    pub session_origin: SessionOrigin,
    /// True when uid=0 and /proc/pid/exe is empty (kernel thread).
    pub is_kernel_thread: bool,
    pub environ:        HashMap<String, String>,
}

impl ProcessInfo {
    pub fn from_pid(pid: u32) -> Result<Self> {
        let proc = format!("/proc/{}", pid);

        let stat_raw = std::fs::read(format!("{}/stat", proc))
            .with_context(|| format!("read /proc/{}/stat", pid))?;
        let (ppid, comm, nice, threads) = parse_stat(&stat_raw)?;

        let status_raw = std::fs::read_to_string(format!("{}/status", proc))
            .with_context(|| format!("read /proc/{}/status", pid))?;
        let (uid, gid, vm_rss_kb) = parse_status(&status_raw);

        let cmdline: Vec<String> = std::fs::read(format!("{}/cmdline", proc))
            .map(|b| {
                b.split(|&c| c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect()
            })
            .unwrap_or_default();

        let exe = std::fs::read_link(format!("{}/exe", proc)).ok();
        // Kernel threads have uid=0 and no exe symlink target.
        let is_kernel_thread = uid == 0 && exe.is_none() && cmdline.is_empty();

        let cgroup_path = read_cgroup_v2(pid);
        let session_origin = cgroup_path.as_deref()
            .map(|p| SessionOrigin::from_cgroup_path(p, uid, "ulatencyd"))
            .unwrap_or(SessionOrigin::Unknown);

        let sched_policy = get_sched_policy(pid as i32);

        Ok(ProcessInfo {
            pid, ppid, uid, gid, comm, cmdline, exe,
            threads, vm_rss_kb,
            sched_policy, nice, cgroup_path, session_origin,
            is_kernel_thread, environ: HashMap::new(),
        })
    }

    pub fn load_environ(&mut self) -> Result<()> {
        let raw = std::fs::read(format!("/proc/{}/environ", self.pid))
            .with_context(|| format!("read /proc/{}/environ", self.pid))?;
        self.environ = raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|entry| {
                let s = std::str::from_utf8(entry).ok()?;
                let mut parts = s.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next().unwrap_or("").to_string()))
            })
            .collect();
        Ok(())
    }
}

fn parse_stat(raw: &[u8]) -> Result<(u32, String, i8, u32)> {
    let paren_open  = raw.iter().position(|&b| b == b'(')
        .ok_or_else(|| anyhow::anyhow!("malformed stat: no '('"))?;
    let paren_close = raw.iter().rposition(|&b| b == b')')
        .ok_or_else(|| anyhow::anyhow!("malformed stat: no ')'"))?;
    let comm = String::from_utf8_lossy(&raw[paren_open+1..paren_close]).into_owned();
    let rest = std::str::from_utf8(&raw[paren_close+2..])?;
    let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
    let ppid: u32        = fields.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let num_threads: u32 = fields.get(17).and_then(|s| s.parse().ok()).unwrap_or(1);
    let nice: i8         = fields.get(18).and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok((ppid, comm, nice, num_threads))
}

fn parse_status(status: &str) -> (u32, u32, u64) {
    let (mut uid, mut gid, mut vm_rss_kb) = (0u32, 0u32, 0u64);
    for line in status.lines() {
        if let Some(r) = line.strip_prefix("Uid:") {
            uid = r.split_ascii_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(r) = line.strip_prefix("Gid:") {
            gid = r.split_ascii_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(r) = line.strip_prefix("VmRSS:") {
            vm_rss_kb = r.split_ascii_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }
    (uid, gid, vm_rss_kb)
}

fn read_cgroup_v2(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Some(path.trim().to_string());
        }
    }
    None
}

fn get_sched_policy(pid: i32) -> SchedPolicy {
    let policy = unsafe { libc::sched_getscheduler(pid) };
    match policy {
        libc::SCHED_NORMAL   => SchedPolicy::Normal,
        libc::SCHED_BATCH    => SchedPolicy::Batch,
        libc::SCHED_IDLE     => SchedPolicy::Idle,
        libc::SCHED_DEADLINE => SchedPolicy::Deadline,
        libc::SCHED_FIFO => {
            let mut p = libc::sched_param { sched_priority: 0 };
            unsafe { libc::sched_getparam(pid, &mut p); }
            SchedPolicy::Fifo(p.sched_priority.clamp(0,99) as u8)
        }
        libc::SCHED_RR => {
            let mut p = libc::sched_param { sched_priority: 0 };
            unsafe { libc::sched_getparam(pid, &mut p); }
            SchedPolicy::RoundRobin(p.sched_priority.clamp(0,99) as u8)
        }
        other => SchedPolicy::Unknown(other),
    }
}
