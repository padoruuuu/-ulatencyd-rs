//! Applies Rule actions to live processes.
//!
//! All writes are non-fatal — a process may vanish between classification
//! and application. Each error is logged at debug level and skipped.

use anyhow::Result;
use tracing::{debug, warn};
use libc;

use cgroupv2::{CgroupManager, CgroupTier};
use rules::Action;

// ---------------------------------------------------------------------------
// Public entry-point
// ---------------------------------------------------------------------------

/// Apply `action` to `pid`. Returns true if all requested operations succeeded.
/// Partial success is tolerated — the return value is informational.
pub async fn apply_action(
    pid:     u32,
    action:  &Action,
    cgmgr:   &CgroupManager,
) -> bool {
    let mut ok = true;

    // 1. cgroup assignment
    if let Some(ref cgroup_name) = action.cgroup {
        if let Some(tier) = CgroupTier::from_str(cgroup_name) {
            if let Err(e) = cgmgr.assign_pid(Some(tier), pid).await {
                debug!("assign pid {} to cgroup {}: {}", pid, cgroup_name, e);
                ok = false;
            } else {
                debug!("pid {} → cgroup/{}", pid, cgroup_name);
            }
        } else {
            warn!("unknown cgroup tier {:?} for pid {}", cgroup_name, pid);
            ok = false;
        }
    }

    // 2. nice
    if let Some(nice) = action.nice {
        if let Err(e) = set_nice(pid, nice) {
            debug!("set nice {} for pid {}: {}", nice, pid, e);
            ok = false;
        } else {
            debug!("pid {} nice={}", pid, nice);
        }
    }

    // 3. scheduling policy
    if let Some(ref policy) = action.sched_policy {
        let priority = action.sched_priority.unwrap_or(0);
        if let Err(e) = set_sched_policy(pid, policy, priority) {
            debug!("set sched policy {:?}/{} for pid {}: {}", policy, priority, pid, e);
            ok = false;
        } else {
            debug!("pid {} sched={}/{}", pid, policy, priority);
        }
    }

    // 4. OOM score adjustment
    if let Some(adj) = action.oom_score_adj {
        if let Err(e) = set_oom_score_adj(pid, adj) {
            debug!("set oom_score_adj {} for pid {}: {}", adj, pid, e);
            ok = false;
        } else {
            debug!("pid {} oom_score_adj={}", pid, adj);
        }
    }

    ok
}

// ---------------------------------------------------------------------------
// nice
// ---------------------------------------------------------------------------

fn set_nice(pid: u32, nice: i8) -> Result<()> {
    // SAFETY: setpriority is a standard POSIX syscall.
    let rc = unsafe {
        libc::setpriority(
            libc::PRIO_PROCESS,
            pid as libc::id_t,
            nice as libc::c_int,
        )
    };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "setpriority(pid={}, nice={}) errno={}",
            pid, nice, errno()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scheduling policy
// ---------------------------------------------------------------------------

fn set_sched_policy(pid: u32, policy: &str, priority: u8) -> Result<()> {
    let (sched_policy, param) = match policy {
        "normal" | "other" => (
            libc::SCHED_NORMAL,
            libc::sched_param { sched_priority: 0 },
        ),
        "batch" => (
            libc::SCHED_BATCH,
            libc::sched_param { sched_priority: 0 },
        ),
        "idle" => (
            libc::SCHED_IDLE,
            libc::sched_param { sched_priority: 0 },
        ),
        "fifo" => (
            libc::SCHED_FIFO,
            libc::sched_param {
                sched_priority: priority.clamp(1, 99) as i32,
            },
        ),
        "rr" | "round_robin" => (
            libc::SCHED_RR,
            libc::sched_param {
                sched_priority: priority.clamp(1, 99) as i32,
            },
        ),
        other => {
            return Err(anyhow::anyhow!("unknown sched policy {:?}", other));
        }
    };

    // SAFETY: param is a valid sched_param on the stack.
    let rc = unsafe {
        libc::sched_setscheduler(pid as i32, sched_policy, &param as *const _)
    };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "sched_setscheduler(pid={}, policy={}, prio={}) errno={}",
            pid, policy, priority, errno()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OOM score adjustment
// ---------------------------------------------------------------------------

fn set_oom_score_adj(pid: u32, adj: i32) -> Result<()> {
    let clamped = adj.clamp(-1000, 1000);
    let path = format!("/proc/{}/oom_score_adj", pid);
    std::fs::write(&path, format!("{}\n", clamped))
        .map_err(|e| anyhow::anyhow!("write {}: {}", path, e))
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn errno() -> i32 {
    // SAFETY: reads thread-local errno.
    unsafe { *libc::__errno_location() }
}
