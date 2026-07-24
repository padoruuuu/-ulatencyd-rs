//! Fork-bomb detector.
//!
//! Tracks per-parent fork rates in a sliding 1-second window.
//! When a parent exceeds `threshold` forks/sec, its entire subtree is
//! moved to the `swapstorm` cgroup (heavily restricted).

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use cgroupv2::{CgroupManager, CgroupTier};
use crate::process_table::ProcessTable;

// ---------------------------------------------------------------------------
// ForkEvent ring buffer per parent
// ---------------------------------------------------------------------------

/// A ring buffer of fork timestamps for a single parent PID.
struct ForkWindow {
    timestamps: std::collections::VecDeque<Instant>,
    threshold:  u32,
}

impl ForkWindow {
    fn new(threshold: u32) -> Self {
        Self {
            timestamps: std::collections::VecDeque::with_capacity(threshold as usize * 2),
            threshold,
        }
    }

    /// Record a fork event, evict events older than 1 second.
    /// Returns true if the rate has exceeded the threshold.
    fn record(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(1);

        // Evict stale entries.
        while self.timestamps.front().map_or(false, |&t| t < cutoff) {
            self.timestamps.pop_front();
        }

        self.timestamps.push_back(now);
        self.timestamps.len() as u32 >= self.threshold
    }

    /// Count forks in the last second.
    fn rate(&self) -> u32 {
        let cutoff = Instant::now() - Duration::from_secs(1);
        self.timestamps.iter().filter(|&&t| t >= cutoff).count() as u32
    }
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

pub struct ForkBombDetector {
    /// fork rate tracker per parent pid
    windows:            HashMap<u32, ForkWindow>,
    threshold:          u32,
    lineage_depth:      u32,
    /// PIDs already throttled (avoid repeated cgroup moves).
    throttled:          std::collections::HashSet<u32>,
}

impl ForkBombDetector {
    pub fn new(threshold: u32, lineage_depth: u32) -> Self {
        Self {
            windows: HashMap::new(),
            threshold,
            lineage_depth,
            throttled: Default::default(),
        }
    }

    /// Called for every PROC_EVENT_FORK.
    /// Returns Some(parent_pid) if a fork bomb is detected for this parent.
    pub fn record_fork(&mut self, parent_pid: u32) -> Option<u32> {
        if self.throttled.contains(&parent_pid) {
            return None; // already handled
        }

        let threshold = self.threshold;
        let window = self
            .windows
            .entry(parent_pid)
            .or_insert_with(|| ForkWindow::new(threshold));

        if window.record() {
            let rate = window.rate();
            warn!(
                "fork bomb detected: ppid={} forks/sec={}",
                parent_pid, rate
            );
            self.throttled.insert(parent_pid);
            Some(parent_pid)
        } else {
            None
        }
    }

    /// Collect all PIDs in the subtree of `root_pid` up to `depth` levels.
    pub fn collect_subtree(
        &self,
        root_pid: u32,
        table: &ProcessTable,
        depth: u32,
    ) -> Vec<u32> {
        let mut result = vec![root_pid];
        let mut frontier = vec![root_pid];
        for _ in 0..depth {
            let mut next = Vec::new();
            for pid in &frontier {
                for child in table.children_of(*pid) {
                    result.push(child);
                    next.push(child);
                }
            }
            if next.is_empty() { break; }
            frontier = next;
        }
        result
    }

    /// Throttle a subtree rooted at `ppid` by moving all PIDs to swapstorm.
    /// A plain sequential loop — these are cheap per-PID cgroup.procs
    /// writes, and concurrency was never buying much here even during an
    /// active fork bomb with hundreds of PIDs to move.
    pub fn throttle_subtree(
        &self,
        ppid: u32,
        table: &ProcessTable,
        cgmgr: &CgroupManager,
    ) -> u32 {
        let pids = self.collect_subtree(ppid, table, self.lineage_depth);
        let count = pids.len() as u32;
        info!(
            "throttling {} pids in subtree of ppid={} → swapstorm",
            count, ppid
        );
        for &pid in &pids {
            if let Err(e) = cgmgr.assign_pid(Some(CgroupTier::Swapstorm), pid) {
                warn!("throttle pid {}: {}", pid, e);
            }
        }
        count
    }

    /// Evict stale entries from the window map (call on GC timer).
    /// Also clears the throttled set for any PID whose fork window has gone
    /// cold — prevents monotonic growth and allows PID-reuse correctness.
    pub fn gc(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(10);
        // Collect PIDs whose windows are stale before mutably borrowing windows.
        let stale: Vec<u32> = self.windows
            .iter()
            .filter(|(_, w)| w.timestamps.back().map_or(true, |&t| t < cutoff))
            .map(|(&pid, _)| pid)
            .collect();
        for pid in &stale {
            self.windows.remove(pid);
            // Bug 2 fix: remove from throttled so PID reuse works correctly
            // and the set doesn't grow without bound.
            self.throttled.remove(pid);
        }
    }
}
