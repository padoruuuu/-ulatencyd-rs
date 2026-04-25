use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Kernel scheduling policy for a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedPolicy {
    Normal,
    Batch,
    Idle,
    Fifo(u8),
    RoundRobin(u8),
    Deadline,
    Unknown(i32),
}

/// Snapshot of a process read from /proc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid:            u32,
    pub ppid:           u32,
    pub uid:            u32,
    pub gid:            u32,
    /// /proc/pid/comm (truncated to 16 chars by kernel)
    pub comm:           String,
    pub cmdline:        Vec<String>,
    pub exe:            Option<PathBuf>,
    pub oom_score:      i32,
    pub threads:        u32,
    pub vm_rss_kb:      u64,
    pub io_read_bytes:  u64,
    pub io_write_bytes: u64,
    pub sched_policy:   SchedPolicy,
    pub nice:           i8,
    /// v2 cgroup path from /proc/pid/cgroup (e.g. "/user.slice/...")
    pub cgroup_path:    Option<String>,
    /// Lazily populated; empty until load_environ() is called.
    pub environ:        HashMap<String, String>,
}

impl ProcessInfo {
    /// Read all available information for `pid` from /proc.
    /// Returns Err if the process has already exited.
    pub fn from_pid(pid: u32) -> Result<Self> {
        let proc = format!("/proc/{}", pid);

        // stat ---------------------------------------------------------------
        let stat_raw = std::fs::read(format!("{}/stat", proc))
            .with_context(|| format!("read /proc/{}/stat", pid))?;
        let (ppid, comm, nice, threads) = parse_stat(&stat_raw)?;

        // status -------------------------------------------------------------
        let status_raw = std::fs::read_to_string(format!("{}/status", proc))
            .with_context(|| format!("read /proc/{}/status", pid))?;
        let (uid, gid, vm_rss_kb) = parse_status(&status_raw);

        // cmdline ------------------------------------------------------------
        let cmdline = std::fs::read(format!("{}/cmdline", proc))
            .map(|b| {
                b.split(|&c| c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect()
            })
            .unwrap_or_default();

        // exe ----------------------------------------------------------------
        let exe = std::fs::read_link(format!("{}/exe", proc)).ok();

        // oom_score ----------------------------------------------------------
        let oom_score = std::fs::read_to_string(format!("{}/oom_score", proc))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // cgroup (v2 only) ---------------------------------------------------
        let cgroup_path = read_cgroup_v2(pid);

        // io -----------------------------------------------------------------
        let (io_read_bytes, io_write_bytes) = read_io(pid).unwrap_or((0, 0));

        // sched --------------------------------------------------------------
        let sched_policy = get_sched_policy(pid as i32);

        Ok(ProcessInfo {
            pid,
            ppid,
            uid,
            gid,
            comm,
            cmdline,
            exe,
            oom_score,
            threads,
            vm_rss_kb,
            io_read_bytes,
            io_write_bytes,
            sched_policy,
            nice,
            cgroup_path,
            environ: HashMap::new(),
        })
    }

    /// Lazily populate environ from /proc/pid/environ.
    pub fn load_environ(&mut self) -> Result<()> {
        let raw = std::fs::read(format!("/proc/{}/environ", self.pid))
            .with_context(|| format!("read /proc/{}/environ", self.pid))?;
        self.environ = raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|entry| {
                let s = std::str::from_utf8(entry).ok()?;
                let mut parts = s.splitn(2, '=');
                Some((
                    parts.next()?.to_string(),
                    parts.next().unwrap_or("").to_string(),
                ))
            })
            .collect();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// /proc parsers
// ---------------------------------------------------------------------------

/// Parse /proc/pid/stat (raw bytes to avoid UTF-8 cost in hot path).
/// Returns (ppid, comm, nice, num_threads).
fn parse_stat(raw: &[u8]) -> Result<(u32, String, i8, u32)> {
    // Format:  pid (comm) state ppid pgrp … nice … num_threads …
    // comm may contain spaces, find the enclosing parens.
    let paren_open = raw
        .iter()
        .position(|&b| b == b'(')
        .ok_or_else(|| anyhow::anyhow!("malformed stat: no '('"))?;
    let paren_close = raw
        .iter()
        .rposition(|&b| b == b')')
        .ok_or_else(|| anyhow::anyhow!("malformed stat: no ')'"))?;

    let comm = String::from_utf8_lossy(&raw[paren_open + 1..paren_close]).into_owned();

    // Fields after ')': state(0) ppid(1) pgrp(2) … num_threads(17) … nice(18)
    let rest = std::str::from_utf8(&raw[paren_close + 2..])?;
    let fields: Vec<&str> = rest.split_ascii_whitespace().collect();

    let ppid: u32 = fields.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let num_threads: u32 = fields.get(17).and_then(|s| s.parse().ok()).unwrap_or(1);
    let nice: i8 = fields.get(18).and_then(|s| s.parse().ok()).unwrap_or(0);

    Ok((ppid, comm, nice, num_threads))
}

/// Parse /proc/pid/status for UID, GID, VmRSS.
fn parse_status(status: &str) -> (u32, u32, u64) {
    let mut uid = 0u32;
    let mut gid = 0u32;
    let mut vm_rss_kb = 0u64;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_ascii_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest.split_ascii_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            vm_rss_kb = rest.split_ascii_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }

    (uid, gid, vm_rss_kb)
}

/// Extract cgroup v2 path from /proc/pid/cgroup.
/// v2 line format: "0::<path>"
fn read_cgroup_v2(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Some(path.to_string());
        }
    }
    None
}

/// Parse /proc/pid/io for read_bytes / write_bytes.
fn read_io(pid: u32) -> Result<(u64, u64)> {
    let content = std::fs::read_to_string(format!("/proc/{}/io", pid))
        .with_context(|| format!("read /proc/{}/io", pid))?;
    let mut rb = 0u64;
    let mut wb = 0u64;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("read_bytes: ") {
            rb = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("write_bytes: ") {
            wb = v.trim().parse().unwrap_or(0);
        }
    }
    Ok((rb, wb))
}

/// Query the kernel for the scheduling policy of `pid` via libc.
fn get_sched_policy(pid: i32) -> SchedPolicy {
    // SAFETY: sched_getscheduler is a pure read syscall; worst case returns -1.
    let policy = unsafe { libc::sched_getscheduler(pid) };
    match policy {
        libc::SCHED_NORMAL => SchedPolicy::Normal,
        libc::SCHED_BATCH  => SchedPolicy::Batch,
        libc::SCHED_IDLE   => SchedPolicy::Idle,
        libc::SCHED_FIFO   => {
            let mut param = libc::sched_param { sched_priority: 0 };
            // SAFETY: param is a valid stack-allocated sched_param.
            unsafe { libc::sched_getparam(pid, &mut param); }
            SchedPolicy::Fifo(param.sched_priority.clamp(0, 99) as u8)
        }
        libc::SCHED_RR => {
            let mut param = libc::sched_param { sched_priority: 0 };
            // SAFETY: same as above.
            unsafe { libc::sched_getparam(pid, &mut param); }
            SchedPolicy::RoundRobin(param.sched_priority.clamp(0, 99) as u8)
        }
        libc::SCHED_DEADLINE => SchedPolicy::Deadline,
        other => SchedPolicy::Unknown(other),
    }
}
