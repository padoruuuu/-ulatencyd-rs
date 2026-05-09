//! Foreground process tree management.
//!
//! When a compositor calls SetForegroundProcess(pid), we:
//!   1. Find the topmost non-session-root ancestor of hint_pid
//!   2. Collect the entire descendant subtree from that root
//!   3. Move all PIDs (filtered to exclude session roots) to `interactive`
//!   4. Move the previous foreground group back to `system`
//!
//! Key invariant: SESSION_ROOTS (compositors, display managers, session
//! launchers) are NEVER moved — their cgroup placement is owned by logind.
//! The walk stops when the CURRENT node is a session root (not just the parent).

use std::collections::HashSet;
use tracing::{debug, info};
use libc;

use cgroupv2::{CgroupManager, CgroupTier};

use crate::process_table::ProcessTable;

// ---------------------------------------------------------------------------
// Session boundary set
// ---------------------------------------------------------------------------

/// Process comm names that mark a session/launcher boundary.
/// The walk stops when the current node IS one of these, or its parent is.
/// Deliberately broad — better to be conservative than to accidentally move
/// a compositor into our cgroup.
const SESSION_ROOTS: &[&str] = &[
    // Wayland compositors
    "sway", "kwin_wayland", "kwin_x11", "mutter", "weston",
    "gamescope", "Hyprland", "river", "wayfire", "labwc",
    // X11 window managers
    "openbox", "i3", "bspwm", "herbstluftwm", "qtile",
    "awesome", "xmonad", "dwm", "spectrwm", "fluxbox",
    "jwm", "icewm", "matchbox-window-manager",
    // X server
    "Xorg", "X", "Xwayland",
    // Session launchers and wrappers that are parents of compositors
    "dbus-run-session", "dbus-launch", "dbus-daemon",
    "startx", "xinit", "sx",
    // Desktop session managers
    "gnome-session", "gnome-session-binary",
    "plasma_session", "startplasma-wayland", "startplasma-x11",
    "xfce4-session", "lxsession", "mate-session",
    "openbox-session", "i3-session",
    // Display managers (shouldn't be hint pids, but just in case)
    "sddm", "gdm", "gdm3", "lightdm", "greetd", "lxdm", "slim",
    // Init / systemd
    "systemd", "init",
];

pub fn is_session_root(comm: &str) -> bool {
    SESSION_ROOTS.iter().any(|&s| s == comm)
}

// ---------------------------------------------------------------------------
// ForegroundTracker
// ---------------------------------------------------------------------------

pub struct ForegroundTracker {
    current_pids: HashSet<u32>,
    current_root: Option<u32>,
}

impl ForegroundTracker {
    pub fn new() -> Self {
        Self { current_pids: HashSet::new(), current_root: None }
    }

    pub async fn set_foreground(
        &mut self,
        hint_pid: u32,
        table:    &ProcessTable,
        cgmgr:   &CgroupManager,
    ) {
        // Guard: if hint_pid is itself a session root, ignore.
        if let Some(e) = table.get(hint_pid) {
            if is_session_root(&e.info.comm) {
                debug!("set_foreground: hint {} is session root, ignoring", hint_pid);
                return;
            }
        }

        // find_app_root returns None if the walk hits a session root,
        // meaning hint_pid is already a direct child of a compositor.
        let app_root = match find_app_root(hint_pid, table) {
            Some(r) => r,
            None    => hint_pid, // hint_pid is the app root itself
        };

        debug!("set_foreground hint={} app_root={}", hint_pid, app_root);

        // Collect the full tree, then filter out any session roots.
        let new_pids: HashSet<u32> = collect_tree(app_root, table)
            .into_iter()
            .filter(|&pid| {
                table.get(pid)
                    .map(|e| !is_session_root(&e.info.comm))
                    .unwrap_or(false)
            })
            .collect();

        if new_pids.is_empty() {
            debug!("set_foreground: no movable pids in tree of {}", app_root);
            return;
        }

        info!(
            "foreground: {} ({} pids, root={})",
            table.get(app_root).map(|e| e.info.comm.as_str()).unwrap_or("?"),
            new_pids.len(),
            app_root,
        );

        // Demote previous foreground pids not in the new set.
        // Nice is restored to 0 (CFS normal). Cgroup move to System only
        // applies to processes we originally moved (not session-scoped ones).
        let to_demote: Vec<u32> = self.current_pids
            .difference(&new_pids)
            .copied()
            .collect();
        for &pid in &to_demote {
            // Restore nice to 0 unconditionally — this is safe for any process.
            set_nice(pid, 0);
            if let Err(e) = cgmgr.assign_pid(Some(CgroupTier::System), pid).await {
                debug!("demote pid {}: {}", pid, e);
            }
        }
        if !to_demote.is_empty() {
            debug!("demoted {} pids → system (nice=0)", to_demote.len());
        }

        // Promote new foreground pids.
        // Apply nice=-5 (same as system76-scheduler) regardless of whether
        // the cgroup move succeeds — session-scoped processes stay in their
        // session cgroup but still get the scheduling boost.
        for &pid in &new_pids {
            set_nice(pid, -5);
            if let Err(e) = cgmgr.assign_pid(Some(CgroupTier::Interactive), pid).await {
                debug!("promote pid {}: {}", pid, e);
            }
        }
        debug!("boosted {} pids (nice=-5)", new_pids.len());

        self.current_pids = new_pids;
        self.current_root = Some(app_root);
    }

    pub fn on_exit(&mut self, pid: u32) {
        if self.current_pids.remove(&pid) {
            // Best-effort nice restore — process may already be gone.
            set_nice(pid, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Tree walking
// ---------------------------------------------------------------------------

/// Walk up from pid, stopping when:
///   - the current node IS a session root (return None — caller uses hint_pid)
///   - the parent IS a session root (return current — it's the app root)
///   - we reach PID 1 or a cycle
fn find_app_root(pid: u32, table: &ProcessTable) -> Option<u32> {
    let mut current = pid;

    loop {
        let entry = match table.get(current) {
            Some(e) => e,
            None    => return Some(current),
        };

        // If the current node itself is a session root, we've walked too far.
        if is_session_root(&entry.info.comm) {
            return None;
        }

        let ppid = entry.info.ppid;

        // PID 1 / cycle boundary.
        if ppid == 0 || ppid == 1 || ppid == current {
            return Some(current);
        }

        let parent = match table.get(ppid) {
            Some(p) => p,
            None    => return Some(current),
        };

        // Parent is a session root — current is the app root.
        if is_session_root(&parent.info.comm) {
            return Some(current);
        }

        // Don't walk into the RT tier.
        if let Some(ref cg) = parent.info.cgroup_path {
            if cg.ends_with("/rt") {
                return Some(current);
            }
        }

        current = ppid;
    }
}

/// Set the nice level for a pid. Safe to call on any pid including
/// session-scoped processes — nice adjustments don't require cgroup membership.
fn set_nice(pid: u32, nice: i8) {
    unsafe {
        libc::setpriority(
            libc::PRIO_PROCESS,
            pid as libc::id_t,
            nice as libc::c_int,
        );
    }
}
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
        assert!(is_session_root("dbus-run-session"));
        assert!(is_session_root("Xorg"));
        assert!(!is_session_root("firefox"));
        assert!(!is_session_root("alacritty"));
    }
}
