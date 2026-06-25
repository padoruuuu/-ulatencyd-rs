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
