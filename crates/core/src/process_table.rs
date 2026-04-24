//! In-memory process table — maps PIDs to ProcessInfo and parent→child edges.
//!
//! Maintained incrementally via netlink events, with periodic full rescans
//! to correct any missed events (netlink is unreliable for burst forks).

use std::collections::{HashMap, HashSet};
use tracing::debug;

use procmon::ProcessInfo;
use rules::Action;

// ---------------------------------------------------------------------------
// ProcessTable
// ---------------------------------------------------------------------------

/// Entry in the process table.
pub struct ProcessEntry {
    pub info:       ProcessInfo,
    /// Last applied rule action (if any).
    pub applied:    Option<Action>,
    /// When to re-evaluate this process (monotonic seconds).
    pub recheck_at: Option<std::time::Instant>,
}

/// In-memory process tree.
pub struct ProcessTable {
    entries:  HashMap<u32, ProcessEntry>,
    /// parent → set of children
    children: HashMap<u32, HashSet<u32>>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            entries:  HashMap::with_capacity(512),
            children: HashMap::with_capacity(512),
        }
    }

    // -----------------------------------------------------------------------
    // Mutation
    // -----------------------------------------------------------------------

    /// Insert or replace a process. Updates the parent→child index.
    pub fn insert(&mut self, info: ProcessInfo) {
        let pid  = info.pid;
        let ppid = info.ppid;

        // Remove from old parent if re-inserting.
        if let Some(old) = self.entries.get(&pid) {
            if old.info.ppid != ppid {
                self.children.entry(old.info.ppid).and_modify(|s| { s.remove(&pid); });
            }
        }

        self.children.entry(ppid).or_default().insert(pid);
        self.entries.insert(pid, ProcessEntry {
            info,
            applied:    None,
            recheck_at: None,
        });
    }

    /// Remove a process, cleaning up the parent→child index.
    pub fn remove(&mut self, pid: u32) {
        if let Some(entry) = self.entries.remove(&pid) {
            self.children
                .entry(entry.info.ppid)
                .and_modify(|s| { s.remove(&pid); });
            self.children.remove(&pid);
        }
    }

    /// Mark the applied action for a PID and set an optional recheck timer.
    pub fn set_applied(&mut self, pid: u32, action: Action) {
        if let Some(e) = self.entries.get_mut(&pid) {
            let recheck_at = action.recheck_secs.map(|s| {
                std::time::Instant::now() + std::time::Duration::from_secs(s)
            });
            e.recheck_at = recheck_at;
            e.applied = Some(action);
        }
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.entries.get(&pid)
    }

    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessEntry> {
        self.entries.get_mut(&pid)
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.entries.contains_key(&pid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// All children of `ppid`.
    pub fn children_of(&self, ppid: u32) -> impl Iterator<Item = u32> + '_ {
        self.children
            .get(&ppid)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    /// Walk ancestor chain of `pid` (excluding pid itself), up to `max_depth`.
    /// Returns a Vec<String> of ancestor comm names, oldest last.
    pub fn ancestor_comms(&self, pid: u32, max_depth: usize) -> Vec<String> {
        let mut comms = Vec::new();
        let mut current = pid;
        for _ in 0..max_depth {
            let entry = match self.entries.get(&current) {
                Some(e) => e,
                None    => break,
            };
            let ppid = entry.info.ppid;
            if ppid == 0 || ppid == current { break; }
            match self.entries.get(&ppid) {
                Some(p) => {
                    comms.push(p.info.comm.clone());
                    current = ppid;
                }
                None => break,
            }
        }
        comms
    }

    /// All PIDs whose recheck timer has expired.
    pub fn expired_rechecks(&self) -> Vec<u32> {
        let now = std::time::Instant::now();
        self.entries
            .iter()
            .filter(|(_, e)| e.recheck_at.map_or(false, |t| now >= t))
            .map(|(&pid, _)| pid)
            .collect()
    }

    /// All PID → ProcessInfo pairs (for initial scan / GC).
    pub fn iter_infos(&self) -> impl Iterator<Item = (u32, &ProcessInfo)> {
        self.entries.iter().map(|(&pid, e)| (pid, &e.info))
    }

    /// PIDs present in the table but not in `live_pids` (for GC).
    pub fn stale_pids(&self, live_pids: &HashSet<u32>) -> Vec<u32> {
        self.entries
            .keys()
            .filter(|pid| !live_pids.contains(pid))
            .copied()
            .collect()
    }

    // -----------------------------------------------------------------------
    // Bulk operations
    // -----------------------------------------------------------------------

    /// Merge a fresh full scan into the table.
    /// Processes no longer in `fresh` are removed.
    pub fn merge_scan(&mut self, fresh: Vec<ProcessInfo>) {
        let live: HashSet<u32> = fresh.iter().map(|p| p.pid).collect();

        // Insert/update.
        for info in fresh {
            self.insert(info);
        }

        // Evict stale.
        let stale = self.stale_pids(&live);
        let count = stale.len();
        for pid in stale {
            self.remove(pid);
        }
        if count > 0 {
            debug!("gc: removed {} stale pids", count);
        }
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}
