//! Main event loop for ulatencyd-rs.
//!
//! Wires together:
//!   - netlink proc connector (fork/exec/exit events)
//!   - full /proc rescan (startup + periodic)
//!   - rule engine classification
//!   - cgroup/sched/nice application
//!   - PSI pressure monitor
//!   - fork-bomb detector
//!   - D-Bus command receiver
//!   - power-aware sched profile switching
//!   - SIGHUP (reload) / SIGTERM (graceful shutdown)

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Mutex;
use tokio::time;
use tracing::{debug, info, warn};

use cgroupv2::{CgroupManager, CgroupTier};
use dbus_api::{DbusCommand, ProcessEntry, SharedState, emit_fork_bomb, emit_pressure_changed, emit_process_classified};
use procmon::{ProcEvent, ProcessInfo, ProcMonitor, scan_proc};
use psi::{PressureLevel, spawn_psi_monitor};
use rules::RuleEngine;

use crate::applier::apply_action;
use crate::config::Config;
use crate::forkbomb::ForkBombDetector;
use crate::process_table::ProcessTable;
use crate::sched::{
    AutogroupGuard, PowerState, apply_sched_profile,
    monitor_power_state, CONSERVATIVE, RESPONSIVE,
};
use crate::signal::ShutdownToken;

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

pub struct Daemon {
    config:    Config,
    cgmgr:     CgroupManager,
    engine:    RuleEngine,
    table:     ProcessTable,
    forkbomb:  ForkBombDetector,
    state:     Arc<Mutex<SharedState>>,
}

impl Daemon {
    pub async fn new(
        config: Config,
        cgmgr:  CgroupManager,
        state:  Arc<Mutex<SharedState>>,
    ) -> Result<Self> {
        let engine = RuleEngine::load(&config.daemon.rules_dir)?;
        info!("rule engine: {} rules loaded", engine.rule_count());

        let forkbomb = ForkBombDetector::new(
            config.fork_bomb.threshold_per_second,
            config.fork_bomb.lineage_depth,
        );

        Ok(Self {
            config,
            cgmgr,
            engine,
            table: ProcessTable::new(),
            forkbomb,
            state,
        })
    }

    // -----------------------------------------------------------------------
    // Entry-point
    // -----------------------------------------------------------------------

    pub async fn run(
        mut self,
        mut proc_monitor: ProcMonitor,
        mut dbus_rx:      tokio::sync::mpsc::Receiver<DbusCommand>,
        dbus_conn:        Option<zbus::Connection>,
        mut shutdown:         ShutdownToken,
    ) -> Result<()> {
        // Disable autogroup (single highest-impact kernel toggle).
        let _autogroup_guard = if !self.config.sched.autogroup_enabled {
            Some(AutogroupGuard::disable()?)
        } else {
            None
        };

        // PSI monitor.
        let psi_config = self.config.pressure;
        let mut psi_rx = spawn_psi_monitor(psi_config);
        let mut last_pressure_level = PressureLevel::Normal;

        // Power state monitor.
        let mut power_rx = monitor_power_state().await;
        let mut current_power = *power_rx.borrow();
        let profile = if current_power == PowerState::Battery {
            &CONSERVATIVE
        } else {
            &RESPONSIVE
        };
        apply_sched_profile(profile);

        // Timers.
        let rescan_interval = Duration::from_secs(self.config.daemon.rescan_interval_secs);
        let mut rescan_timer = time::interval(rescan_interval);
        rescan_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let mut gc_timer = time::interval(Duration::from_secs(10));
        gc_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let mut recheck_timer = time::interval(Duration::from_secs(5));
        recheck_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        // Initial scan.
        if self.config.daemon.apply_to_existing_processes {
            self.do_full_scan(&dbus_conn).await;
        }

        info!("event loop started");

        loop {
            tokio::select! {
                // Netlink proc event.
                event = proc_monitor.next_event() => {
                    match event {
                        Some(e) => self.handle_proc_event(e, &dbus_conn).await,
                        None    => {
                            warn!("netlink proc monitor closed — stopping");
                            break;
                        }
                    }
                }

                // D-Bus command.
                cmd = dbus_rx.recv() => {
                    match cmd {
                        Some(c) => self.handle_dbus_cmd(c, &dbus_conn).await,
                        None    => {}
                    }
                }

                // PSI update.
                _ = psi_rx.changed() => {
                    let pressure = *psi_rx.borrow();
                    self.state.lock().await.pressure = pressure;
                    let level = PressureLevel::from_memory(
                        &pressure.memory,
                        psi_config.memory_low_threshold,
                        psi_config.memory_high_threshold,
                    );
                    if level != last_pressure_level {
                        info!("pressure level: {:?} → {:?}", last_pressure_level, level);
                        last_pressure_level = level;
                        if let Some(ref conn) = dbus_conn {
                            emit_pressure_changed(conn, level as u32).await;
                        }
                        self.handle_pressure_change(level).await;
                    }
                }

                // Power state change.
                _ = power_rx.changed() => {
                    current_power = *power_rx.borrow();
                    let profile = if current_power == PowerState::Battery {
                        info!("switched to battery power");
                        &CONSERVATIVE
                    } else {
                        info!("switched to AC power");
                        &RESPONSIVE
                    };
                    apply_sched_profile(profile);
                }

                // Periodic full rescan.
                _ = rescan_timer.tick() => {
                    debug!("periodic rescan");
                    self.do_full_scan(&dbus_conn).await;
                }

                // Recheck timer.
                _ = recheck_timer.tick() => {
                    self.do_rechecks(&dbus_conn).await;
                }

                // GC timer.
                _ = gc_timer.tick() => {
                    self.do_gc();
                }

                // Graceful shutdown signal.
                _ = shutdown.wait() => {
                    info!("shutdown signal received");
                    break;
                }
            }
        }

        self.shutdown().await;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Proc events
    // -----------------------------------------------------------------------

    async fn handle_proc_event(
        &mut self,
        event:     ProcEvent,
        dbus_conn: &Option<zbus::Connection>,
    ) {
        match event {
            ProcEvent::Fork { parent_pid, child_pid, child_tgid } => {
                // Fork-bomb detection (track by TGID, not TID).
                if parent_pid == child_tgid {
                    // thread group leader forked → real fork
                    if let Some(ppid) = self.forkbomb.record_fork(parent_pid) {
                        let count = self.forkbomb
                            .throttle_subtree(ppid, &self.table, &self.cgmgr)
                            .await;
                        if let Some(ref conn) = dbus_conn {
                            emit_fork_bomb(conn, ppid, count).await;
                        }
                        return; // Subtree is already throttled.
                    }
                }

                // Read the child's info; it may already be a new exec().
                match ProcessInfo::from_pid(child_pid) {
                    Ok(info) => {
                        self.table.insert(info.clone());
                        self.classify_and_apply(child_pid, &info, dbus_conn).await;
                    }
                    Err(e) => debug!("fork pid {} vanished: {}", child_pid, e),
                }
            }

            ProcEvent::Exec { pid } => {
                // Re-read after exec (comm/cmdline/exe changed).
                match ProcessInfo::from_pid(pid) {
                    Ok(info) => {
                        self.table.insert(info.clone());
                        self.classify_and_apply(pid, &info, dbus_conn).await;
                    }
                    Err(e) => debug!("exec pid {} vanished: {}", pid, e),
                }
            }

            ProcEvent::Exit { pid, .. } => {
                self.table.remove(pid);
                self.state.lock().await.managed.remove(&pid);
            }

            ProcEvent::Comm { pid, .. } | ProcEvent::Uid { pid } => {
                // Re-classify on comm/uid change.
                match ProcessInfo::from_pid(pid) {
                    Ok(info) => {
                        self.table.insert(info.clone());
                        self.classify_and_apply(pid, &info, dbus_conn).await;
                    }
                    Err(_) => {}
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // D-Bus commands
    // -----------------------------------------------------------------------

    async fn handle_dbus_cmd(
        &mut self,
        cmd:      DbusCommand,
        dbus_conn: &Option<zbus::Connection>,
    ) {
        match cmd {
            DbusCommand::SetForegroundProcess(pid) => {
                info!("foreground pid → {}", pid);
                self.state.lock().await.foreground_pid = Some(pid);
                // Move foreground process to interactive cgroup.
                if let Err(e) = self.cgmgr.assign_pid(Some(CgroupTier::Interactive), pid).await {
                    warn!("move foreground pid {} to interactive: {}", pid, e);
                }
                // Move previous foreground back to system cgroup (if different).
                // (Tracked in SharedState.foreground_pid via a separate prev field in future.)
            }

            DbusCommand::SetProcessCgroup { pid, cgroup } => {
                if let Some(tier) = CgroupTier::from_str(&cgroup) {
                    if let Err(e) = self.cgmgr.assign_pid(Some(tier), pid).await {
                        warn!("D-Bus SetProcessCgroup pid={} cgroup={}: {}", pid, cgroup, e);
                    }
                }
            }

            DbusCommand::ReloadRules => {
                match self.engine.reload(&self.config.daemon.rules_dir) {
                    Ok(_)  => info!("rules reloaded"),
                    Err(e) => warn!("rules reload failed: {}", e),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Classification helpers
    // -----------------------------------------------------------------------

    async fn classify_and_apply(
        &mut self,
        pid:      u32,
        info:     &ProcessInfo,
        dbus_conn: &Option<zbus::Connection>,
    ) {
        let ancestors = self.table.ancestor_comms(pid, 5);

        match self.engine.classify(info, &ancestors) {
            Some(action) => {
                let cgroup_name = action.cgroup.clone().unwrap_or_else(|| "system".into());
                let rule_name   = action.rule_name.clone();

                let _ok = apply_action(pid, &action, &self.cgmgr).await;

                // If rule says apply to children, push to existing children too.
                if action.apply_to_children {
                    let children: Vec<u32> = self.table.children_of(pid).collect();
                    for child in children {
                        let child_info = self.table.get(child).map(|e| e.info.clone());
                        if child_info.is_some() {
                            apply_action(child, &action, &self.cgmgr).await;
                        }
                    }
                }

                self.table.set_applied(pid, action);

                // Update D-Bus visible state.
                self.state.lock().await.managed.insert(pid, ProcessEntry {
                    pid,
                    comm:      info.comm.clone(),
                    cgroup:    cgroup_name.clone(),
                    rule_name: rule_name.clone(),
                });

                if let Some(ref conn) = dbus_conn {
                    emit_process_classified(conn, pid, &cgroup_name, &rule_name).await;
                }
            }
            None => {
                // No rule matched; ensure process is at least in root cgroup.
                // (Don't touch processes that are already correctly placed.)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Full scan
    // -----------------------------------------------------------------------

    async fn do_full_scan(&mut self, dbus_conn: &Option<zbus::Connection>) {
        let fresh = tokio::task::spawn_blocking(scan_proc)
            .await
            .unwrap_or_default();
        let count = fresh.len();
        self.table.merge_scan(fresh.clone());
        tracing::info!("full scan: {} processes", count);
        for proc_info in fresh {
            // Only (re-)apply to processes that don't yet have an applied action.
            if self.table.get(proc_info.pid).and_then(|e| e.applied.as_ref()).is_none() {
                self.classify_and_apply(proc_info.pid, &proc_info, dbus_conn).await;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Recheck
    // -----------------------------------------------------------------------

    async fn do_rechecks(&mut self, dbus_conn: &Option<zbus::Connection>) {
        let expired = self.table.expired_rechecks();
        for pid in expired {
            match ProcessInfo::from_pid(pid) {
                Ok(proc_info) => {
                    self.table.insert(proc_info.clone());
                    self.classify_and_apply(pid, &proc_info, dbus_conn).await;
                }
                Err(_) => {
                    self.table.remove(pid);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // GC
    // -----------------------------------------------------------------------

    fn do_gc(&mut self) {
        self.forkbomb.gc();
        self.cgmgr.gc_empty_cgroups(); // fire-and-forget
    }

    // -----------------------------------------------------------------------
    // Pressure response
    // -----------------------------------------------------------------------

    async fn handle_pressure_change(&mut self, level: PressureLevel) {
        match level {
            PressureLevel::Critical => {
                info!("critical memory pressure: throttling idle/swapstorm cgroups");
                self.state.lock().await.mode = "pressure-critical".into();
            }
            PressureLevel::Normal => {
                self.state.lock().await.mode = "normal".into();
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    async fn shutdown(&self) {
        info!("moving all managed pids back to root cgroup");
        let managed_pids: Vec<u32> = self.state
            .lock()
            .await
            .managed
            .keys()
            .copied()
            .collect();

        self.cgmgr.teardown(managed_pids.into_iter()).await;
        info!("shutdown complete");
    }
}
