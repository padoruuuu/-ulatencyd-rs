//! Applies Rule actions to live processes.
//!
//! apply_action      — full action, only when a rule directly matches.
//! apply_cgroup_only — cgroup tier only, safe for children/focus inheritance.

use anyhow::Result;
use tracing::{debug, warn};
use libc;

use cgroupv2::{CgroupManager, CgroupTier};
use rules::Action;

pub async fn apply_action(pid: u32, action: &Action, cgmgr: &CgroupManager) -> bool {
    let mut ok = true;

    ok &= apply_cgroup_inner(pid, action, cgmgr).await;

    // set_nice / set_sched_policy / set_oom_score_adj are all synchronous
    // syscalls/file writes. On the multi-thread runtime this was merely
    // wasteful; on the current_thread runtime main.rs now uses, blocking the
    // single worker thread here would stall the entire event loop (netlink
    // events, PSI updates, control-socket requests) for the duration of all
    // three calls. Bundle them into one spawn_blocking so the async task
    // yields instead of blocking in place.
    let nice          = action.nice;
    let sched_policy  = action.sched_policy.clone();
    let sched_priority = action.sched_priority;
    let oom_score_adj = action.oom_score_adj;

    if nice.is_some() || sched_policy.is_some() || oom_score_adj.is_some() {
        let applied = tokio::task::spawn_blocking(move || {
            let mut ok = true;

            if let Some(nice) = nice {
                match set_nice(pid, nice) {
                    Ok(_)  => debug!("pid {} nice={}", pid, nice),
                    Err(e) => { debug!("pid {} nice={}: {}", pid, nice, e); ok = false; }
                }
            }

            if let Some(ref policy) = sched_policy {
                let prio = sched_priority.unwrap_or(0);
                match set_sched_policy(pid, policy, prio) {
                    Ok(_)  => debug!("pid {} sched={}/{}", pid, policy, prio),
                    Err(e) => { debug!("pid {} sched={}: {}", pid, policy, e); ok = false; }
                }
            }

            if let Some(adj) = oom_score_adj {
                match set_oom_score_adj(pid, adj) {
                    Ok(_)  => debug!("pid {} oom_score_adj={}", pid, adj),
                    Err(e) => { debug!("pid {} oom={}: {}", pid, adj, e); ok = false; }
                }
            }

            ok
        })
        .await
        .unwrap_or(false);

        ok &= applied;
    }

    ok
}

pub async fn apply_cgroup_only(pid: u32, action: &Action, cgmgr: &CgroupManager) -> bool {
    apply_cgroup_inner(pid, action, cgmgr).await
}

/// Read the current cgroup v2 path for pid from /proc/pid/cgroup.
/// Returns the path without /sys/fs/cgroup prefix (e.g. "/user.slice/...").
pub fn read_current_cgroup(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Some(path.trim().to_string());
        }
    }
    None
}

async fn apply_cgroup_inner(pid: u32, action: &Action, cgmgr: &CgroupManager) -> bool {
    let Some(ref name) = action.cgroup else { return true; };
    let Some(tier) = CgroupTier::from_str(name) else {
        warn!("unknown cgroup tier {:?} for pid {}", name, pid);
        return false;
    };
    match cgmgr.assign_pid(Some(tier), pid).await {
        Ok(_)  => { debug!("pid {} → cgroup/{}", pid, name); true }
        Err(e) => { debug!("pid {} → cgroup/{}: {}", pid, name, e); false }
    }
}

/// Move a PID back to an arbitrary cgroup path (used in teardown).
pub async fn restore_cgroup(pid: u32, cgroup_path: &str) {
    let procs_path = format!("/sys/fs/cgroup{}/cgroup.procs", cgroup_path);
    if let Err(e) = tokio::fs::write(&procs_path, format!("{}\n", pid)).await {
        debug!("restore pid {} to {}: {}", pid, cgroup_path, e);
    }
}

pub fn set_nice(pid: u32, nice: i8) -> Result<()> {
    let rc = unsafe {
        libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice as libc::c_int)
    };
    if rc != 0 { Err(anyhow::anyhow!("errno={}", errno())) } else { Ok(()) }
}

fn set_sched_policy(pid: u32, policy: &str, priority: u8) -> Result<()> {
    let (pol, param) = match policy {
        "normal"|"other" => (libc::SCHED_NORMAL, libc::sched_param { sched_priority: 0 }),
        "batch"          => (libc::SCHED_BATCH,  libc::sched_param { sched_priority: 0 }),
        "idle"           => (libc::SCHED_IDLE,   libc::sched_param { sched_priority: 0 }),
        "fifo"           => (libc::SCHED_FIFO,   libc::sched_param { sched_priority: priority.clamp(1, 99) as i32 }),
        "rr"|"round_robin" => (libc::SCHED_RR,  libc::sched_param { sched_priority: priority.clamp(1, 99) as i32 }),
        other => return Err(anyhow::anyhow!("unknown policy {:?}", other)),
    };
    let rc = unsafe { libc::sched_setscheduler(pid as i32, pol, &param as *const _) };
    if rc != 0 { Err(anyhow::anyhow!("errno={}", errno())) } else { Ok(()) }
}

fn set_oom_score_adj(pid: u32, adj: i32) -> Result<()> {
    let path = format!("/proc/{}/oom_score_adj", pid);
    std::fs::write(&path, format!("{}\n", adj.clamp(-1000, 1000)))
        .map_err(|e| anyhow::anyhow!("{}: {}", path, e))
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
