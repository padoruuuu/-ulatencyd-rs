//! Foreground process tree management.
//!
//! When a compositor calls SetForegroundProcess(pid), we:
//!   1. Walk up the tree to find the topmost non-system ancestor
//!      (stops at init, login session boundary, or a known launcher)
//!   2. Collect the entire descendant subtree from that root
//!   3. Move all PIDs to the `interactive` cgroup
//!   4. Move the previous foreground group back to `system`
//!   5. Tag all PIDs as "foreground" so new forks inherit the tier
//!
//! This gives equivalent or better behaviour to system76-scheduler's
//! foreground tracking without needing a separate daemon.

use std::collections::HashSet;
use tracing::{debug, info};

use cgroupv2::{CgroupManager, CgroupTier};

use crate::process_table::ProcessTable;

// ---------------------------------------------------------------------------
// Session boundary detection
// ---------------------------------------------------------------------------

/// Process names that are session/login boundaries — we stop walking up
/// when we hit one of these, since they are not part of the app's tree.
const SESSION_ROOTS: &[&str] = &[
    "systemd",
    "systemd --user",
    "init",
    "login",
    "sddm",
    "gdm",
    "lightdm",
    "greetd",
    "sway",
    "kwin_wayland",
    "mutter",
    "Hyprland",
    "weston",
    "gamescope",
    "river",
    "wayfire",
    "labwc",
    "Xorg",
    "X",
];

fn is_session_root(comm: &str) -> bool {
    SESSION_ROOTS.iter().any(|&s| s == comm)
}

// ---------------------------------------------------------------------------
// ForegroundTracker
// ---------------------------------------------------------------------------

pub struct ForegroundTracker {
    /// PIDs currently in the foreground group.
    current_pids: HashSet<u32>,
    /// The root pid of the current foreground app (for logging).
    current_root: Option<u32>,
}

impl ForegroundTracker {
    pub fn new() -> Self {
        Self {
            current_pids: HashSet::new(),
            current_root: None,
        }
    }

    /// Called when the compositor reports a new foreground PID.
    /// Moves the new foreground tree to `interactive` and the old one to `system`.
    pub async fn set_foreground(
        &mut self,
        hint_pid:  u32,
        table:     &ProcessTable,
        cgmgr:     &CgroupManager,
    ) {
        // 1. Find the application root (walk up until session boundary or PID 1).
        let app_root = find_app_root(hint_pid, table);
        debug!("foreground hint pid={} → app_root={}", hint_pid, app_root);

        // 2. Collect the full descendant tree from the root.
        let new_pids = collect_tree(app_root, table);
        info!(
            "foreground: {} ({} pids, root={})",
            table.get(app_root)
                .map(|e| e.info.comm.as_str())
                .unwrap_or("?"),
            new_pids.len(),
            app_root,
        );

        // 3. Move old foreground pids that are NOT in the new set back to system.
        let to_demote: Vec<u32> = self.current_pids
            .difference(&new_pids)
            .copied()
            .collect();

        for pid in &to_demote {
            if let Err(e) = cgmgr.assign_pid(Some(CgroupTier::System), *pid).await {
                debug!("demote pid {} to system: {}", pid, e);
            }
        }
        if !to_demote.is_empty() {
            debug!("demoted {} pids from interactive → system", to_demote.len());
        }

        // 4. Move new foreground pids to interactive.
        for pid in &new_pids {
            if let Err(e) = cgmgr.assign_pid(Some(CgroupTier::Interactive), *pid).await {
                debug!("promote pid {} to interactive: {}", pid, e);
            }
        }

        self.current_pids = new_pids;
        self.current_root = Some(app_root);
    }

    /// Called on every Fork event — if the parent is in the foreground group,
    /// automatically promote the child too.
    pub async fn on_fork(
        &mut self,
        parent_pid: u32,
        child_pid:  u32,
        cgmgr:      &CgroupManager,
    ) {
        if self.current_pids.contains(&parent_pid) {
            debug!(
                "foreground fork: child {} inherits interactive from parent {}",
                child_pid, parent_pid
            );
            self.current_pids.insert(child_pid);
            if let Err(e) = cgmgr.assign_pid(Some(CgroupTier::Interactive), child_pid).await {
                debug!("foreground fork promote {}: {}", child_pid, e);
            }
        }
    }

    /// Called on Exit — remove from tracking set.
    pub fn on_exit(&mut self, pid: u32) {
        self.current_pids.remove(&pid);
    }

    /// Returns true if `pid` is currently in the foreground group.
    pub fn is_foreground(&self, pid: u32) -> bool {
        self.current_pids.contains(&pid)
    }

    /// Current foreground PIDs (for D-Bus status reporting).
    pub fn current_pids(&self) -> &HashSet<u32> {
        &self.current_pids
    }
}

// ---------------------------------------------------------------------------
// Tree walking
// ---------------------------------------------------------------------------

/// Walk up the process tree from `pid` to find the topmost ancestor that is
/// still part of the application (not a session root or PID 1).
fn find_app_root(pid: u32, table: &ProcessTable) -> u32 {
    let mut current = pid;

    loop {
        let entry = match table.get(current) {
            Some(e) => e,
            None    => return current,
        };

        let ppid = entry.info.ppid;

        // Stop at PID 1 or init boundary.
        if ppid == 0 || ppid == 1 || ppid == current {
            return current;
        }

        let parent = match table.get(ppid) {
            Some(p) => p,
            None    => return current,
        };

        // Stop if the parent is a session/compositor root.
        if is_session_root(&parent.info.comm) {
            return current;
        }

        // Stop if the parent is in the rt cgroup (audio server etc.) —
        // don't pull real-time processes into the foreground group.
        if let Some(ref cg) = parent.info.cgroup_path {
            if cg.ends_with("/rt") {
                return current;
            }
        }

        current = ppid;
    }
}

/// Collect the full descendant subtree of `root` (BFS).
/// Returns a HashSet of all PIDs including root.
fn collect_tree(root: u32, table: &ProcessTable) -> HashSet<u32> {
    let mut result = HashSet::new();
    let mut queue  = vec![root];

    while let Some(pid) = queue.pop() {
        if result.insert(pid) {
            for child in table.children_of(pid) {
                queue.push(child);
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_root_detection() {
        assert!(is_session_root("sway"));
        assert!(is_session_root("Xorg"));
        assert!(!is_session_root("firefox"));
        assert!(!is_session_root("alacritty"));
    }
}
