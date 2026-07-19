//! In-memory process table — maps PIDs to ProcessInfo and parent→child edges.

use std::collections::{HashMap, HashSet};
use tracing::debug;

use procmon::ProcessInfo;
use rules::Action;

pub struct ProcessEntry {
    pub info:            ProcessInfo,
    pub applied:         Option<Action>,
    pub recheck_at:      Option<std::time::Instant>,
    /// Set after first classify_and_apply attempt — prevents rescans from
    /// re-running the rule engine on every kernel thread that will never match.
    pub classified:      bool,
    /// The cgroup v2 path this process was in BEFORE we moved it.
    /// Restored on teardown so compositors etc. end up in their original
    /// session cgroup rather than wherever our teardown leaves them.
    pub original_cgroup: Option<String>,
}

pub struct ProcessTable {
    entries:  HashMap<u32, ProcessEntry>,
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

    pub fn insert(&mut self, info: ProcessInfo) {
        let pid  = info.pid;
        let ppid = info.ppid;

        // Preserve original_cgroup across re-inserts (exec events).
        let original_cgroup = self.entries.get(&pid)
            .and_then(|e| e.original_cgroup.clone());

        if let Some(old) = self.entries.get(&pid) {
            if old.info.ppid != ppid {
                self.children.entry(old.info.ppid).and_modify(|s| { s.remove(&pid); });
            }
        }

        self.children.entry(ppid).or_default().insert(pid);
        self.entries.insert(pid, ProcessEntry {
            info,
            applied:         None,
            recheck_at:      None,
            classified:      false,
            original_cgroup,
        });
    }

    pub fn remove(&mut self, pid: u32) {
        if let Some(entry) = self.entries.remove(&pid) {
            self.children
                .entry(entry.info.ppid)
                .and_modify(|s| { s.remove(&pid); });
            self.children.remove(&pid);
        }
    }

    pub fn mark_classified(&mut self, pid: u32) {
        if let Some(e) = self.entries.get_mut(&pid) {
            e.classified = true;
        }
    }

    /// Reset classified flag so the next rescan re-evaluates this process.
    pub fn mark_classified_false(&mut self, pid: u32) {
        if let Some(e) = self.entries.get_mut(&pid) {
            e.classified  = false;
            e.applied      = None;
        }
    }

    /// Record the process's original cgroup before we move it.
    pub fn set_original_cgroup(&mut self, pid: u32, path: String) {
        if let Some(e) = self.entries.get_mut(&pid) {
            if e.original_cgroup.is_none() {
                e.original_cgroup = Some(path);
            }
        }
    }

    pub fn set_applied(&mut self, pid: u32, action: Action) {
        if let Some(e) = self.entries.get_mut(&pid) {
            let recheck_at = action.recheck_secs.map(|s| {
                std::time::Instant::now() + std::time::Duration::from_secs(s)
            });
            e.recheck_at = recheck_at;
            e.applied    = Some(action);
            e.classified = true;
        }
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.entries.get(&pid)
    }

    pub fn children_of(&self, ppid: u32) -> impl Iterator<Item = u32> + '_ {
        self.children
            .get(&ppid)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

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
                Some(p) => { comms.push(p.info.comm.clone()); current = ppid; }
                None    => break,
            }
        }
        comms
    }

    pub fn expired_rechecks(&self) -> Vec<u32> {
        let now = std::time::Instant::now();
        self.entries
            .iter()
            .filter(|(_, e)| e.recheck_at.map_or(false, |t| now >= t))
            .map(|(&pid, _)| pid)
            .collect()
    }

    /// Merge the results of an incremental scan.
    ///
    /// `fresh` contains only *new* processes discovered this scan (see
    /// `procmon::scan_proc_incremental`) — NOT the full /proc listing, so
    /// staleness can no longer be derived from `fresh` alone. `live_pids` is
    /// the authoritative set of every PID that exists in /proc right now;
    /// anything in the table but not in `live_pids` has exited.
    pub fn merge_scan(&mut self, fresh: Vec<ProcessInfo>, live_pids: &HashSet<u32>) {
        for info in fresh {
            // Only insert if not already known — preserves classified flag
            // and original_cgroup for existing entries.
            if !self.entries.contains_key(&info.pid) {
                let pid  = info.pid;
                let ppid = info.ppid;
                self.children.entry(ppid).or_default().insert(pid);
                self.entries.insert(pid, ProcessEntry {
                    info,
                    applied:         None,
                    recheck_at:      None,
                    classified:      false,
                    original_cgroup: None,
                });
            }
        }
        let stale: Vec<u32> = self.entries.keys()
            .filter(|pid| !live_pids.contains(pid))
            .copied()
            .collect();
        let count = stale.len();
        for pid in stale { self.remove(pid); }
        if count > 0 { debug!("gc: removed {} stale pids", count); }
    }

    /// Every PID currently tracked by the table — passed to
    /// `procmon::scan_proc_incremental` so it can skip the (relatively
    /// expensive) /proc/pid/* reads for processes we already know about.
    pub fn known_pids(&self) -> HashSet<u32> {
        self.entries.keys().copied().collect()
    }

    /// PIDs with `classified == false` — new this scan, or reset by e.g.
    /// swapstorm-recovery reclassification.
    pub fn unclassified_pids(&self) -> Vec<u32> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.classified)
            .map(|(&pid, _)| pid)
            .collect()
    }

    /// All (pid, original_cgroup) pairs where we have moved the process.
    pub fn moved_pids(&self) -> Vec<(u32, Option<String>)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.applied.as_ref().and_then(|a| a.cgroup.as_ref()).is_some())
            .map(|(&pid, e)| (pid, e.original_cgroup.clone()))
            .collect()
    }
}

impl Default for ProcessTable {
    fn default() -> Self { Self::new() }
}
