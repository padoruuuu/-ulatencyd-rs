//! Full /proc directory scan — used on startup and periodic GC sweeps.

use tracing::{debug, warn};

use crate::info::ProcessInfo;

/// Scan /proc and return ProcessInfo for every live PID (excluding PID 1 threads).
/// Errors per-process are silently skipped (process may have exited).
pub fn scan_proc() -> Vec<ProcessInfo> {
    let mut result = Vec::with_capacity(256);

    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!("scan_proc: failed to open /proc: {}", e);
            return result;
        }
    };

    for entry in dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric entries are PIDs.
        let pid: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        match ProcessInfo::from_pid(pid) {
            Ok(info) => result.push(info),
            Err(e) => debug!("scan_proc: pid {} vanished: {}", pid, e),
        }
    }

    debug!("scan_proc: found {} processes", result.len());
    result
}

/// Check if a PID is still alive without reading its full info.
/// Faster than ProcessInfo::from_pid for GC sweeps.
pub fn pid_exists(pid: u32) -> bool {
// Use itoa for stack-allocated integer formatting, avoiding allocation.
let mut buf = itoa::Buffer::new();
let pid_str = buf.format(pid);
let mut path_buf = std::path::PathBuf::with_capacity(16);
path_buf.push("/proc");
path_buf.push(pid_str);
path_buf.exists()
}

// ---------------------------------------------------------------------------
// Incremental scan
// ---------------------------------------------------------------------------

/// Result of an incremental /proc scan.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Full ProcessInfo only for PIDs not already in `known_pids` — the
    /// (relatively expensive) handful of /proc/pid/* reads per process is
    /// skipped entirely for processes the caller already knows about.
    pub new_processes: Vec<ProcessInfo>,
    /// Every PID that exists in /proc right now (from the directory listing
    /// alone — no per-process reads), so the caller can still detect exits
    /// even though `new_processes` only covers new arrivals.
    pub live_pids: std::collections::HashSet<u32>,
}

/// Incremental version of `scan_proc`: the /proc directory listing itself
/// is cheap (a single readdir), but calling `ProcessInfo::from_pid` for
/// every PID on every periodic rescan re-reads stat/status/cmdline/exe/
/// cgroup for processes that haven't changed at all since the last scan.
/// On a system with a few thousand processes this adds up on every
/// `rescan_interval_secs` tick. Only PIDs absent from `known_pids` get the
/// full read; everything else is just confirmed still-alive via the
/// directory listing.
pub fn scan_proc_incremental(known_pids: &std::collections::HashSet<u32>) -> ScanResult {
    let mut result = ScanResult {
        new_processes: Vec::with_capacity(64),
        live_pids: std::collections::HashSet::with_capacity(256),
    };

    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!("scan_proc_incremental: failed to open /proc: {}", e);
            return result;
        }
    };

    for entry in dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric entries are PIDs.
        let pid: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        result.live_pids.insert(pid);

        if known_pids.contains(&pid) {
            continue; // already known — nothing to (re-)read
        }

        match ProcessInfo::from_pid(pid) {
            Ok(info) => result.new_processes.push(info),
            Err(e) => debug!("scan_proc_incremental: pid {} vanished: {}", pid, e),
        }
    }

    debug!(
        "scan_proc_incremental: {} live, {} new",
        result.live_pids.len(), result.new_processes.len()
    );
    result
}
