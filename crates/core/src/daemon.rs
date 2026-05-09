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

use crate::applier::{apply_action, apply_cgroup_only};
use crate::config::Config;
use crate::diag::{diag, diag_section};
use crate::focus::ForegroundTracker;
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
    config:   Config,
    cgmgr:    CgroupManager,
    engine:   RuleEngine,
    table:    ProcessTable,
    forkbomb: ForkBombDetector,
    focus:    ForegroundTracker,
    state:    Arc<Mutex<SharedState>>,
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
            focus: ForegroundTracker::new(),
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
                        diag!("PSI",
                            "level={:?} mem_avg10={:.2} io_avg10={:.2} cpu_avg10={:.2}",
                            level, pressure.memory.some_avg10,
                            pressure.io.some_avg10, pressure.cpu.some_avg10
                        );
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
                diag!("FORK", "parent={} child={} tgid={}", parent_pid, child_pid, child_tgid);
                if child_pid == child_tgid {
                    if let Some(ppid) = self.forkbomb.record_fork(parent_pid) {
                        let count = self.forkbomb
                            .throttle_subtree(ppid, &self.table, &self.cgmgr)
                            .await;
                        if let Some(ref conn) = dbus_conn {
                            emit_fork_bomb(conn, ppid, count).await;
                        }
                        return;
                    }
                }

                match ProcessInfo::from_pid(child_pid) {
                    Ok(info) => {
                        self.table.insert(info.clone());
                        // classify_and_apply checks ancestor chain — bwrap/sandbox
                        // children are automatically exempt via ExceptionList.
                        self.classify_and_apply(child_pid, &info, dbus_conn).await;
                    }
                    Err(e) => debug!("fork pid {} vanished: {}", child_pid, e),
                }
            }

            ProcEvent::Exec { pid } => {
                diag!("EXEC", "pid={}", pid);
                match ProcessInfo::from_pid(pid) {
                    Ok(info) => {
                        // Insert resets classified=false, so the new comm/exe
                        // goes through the rule engine fresh.
                        self.table.insert(info.clone());
                        self.classify_and_apply(pid, &info, dbus_conn).await;
                    }
                    Err(e) => debug!("exec pid {} vanished: {}", pid, e),
                }
            }

            ProcEvent::Exit { pid, .. } => {
                diag!("EXIT", "pid={}", pid);
                self.focus.on_exit(pid);
                self.table.remove(pid);
                self.state.lock().await.managed.remove(&pid);
            }

            ProcEvent::Comm { pid, .. } | ProcEvent::Uid { pid } => {
                // Only re-classify if the comm actually changed (exec happened)
                // or this process was never classified. A bare Comm event from
                // thread renaming should not trigger full re-evaluation.
                let already_classified = self.table.get(pid)
                    .map(|e| e.classified)
                    .unwrap_or(false);
                if !already_classified {
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
                self.focus.set_foreground(pid, &self.table, &self.cgmgr).await;
                if let Some(ref conn) = dbus_conn {
                    emit_process_classified(conn, pid, "interactive", "foreground-boost").await;
                }
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

    async fn classify_and_apply(
        &mut self,
        pid:        u32,
        info:       &ProcessInfo,
        dbus_conn:  &Option<zbus::Connection>,
    ) {
        // Never classify our own process or its threads — we'd be moving
        // ourselves, which changes our own scheduling in undefined ways.
        let own_pid = std::process::id();
        if pid == own_pid || info.ppid == own_pid as u32
            || info.comm == "tokio-rt-worker"
            || info.comm == "procmon-netlink"
            || info.comm == "ulatencyd"
        {
            self.table.mark_classified(pid);
            return;
        }

        // Kernel threads — no exe, never touch.
        if info.is_kernel_thread {
            self.table.mark_classified(pid);
            return;
        }

        let ancestors = self.table.ancestor_comms(pid, 10);

        match self.engine.classify(info, &ancestors) {
            Some(action) => {
                let cgroup_name = action.cgroup.clone().unwrap_or_else(|| "system".into());
                let rule_name   = action.rule_name.clone();

                // Record where this process was BEFORE we move it so teardown
                // can restore it to its original session/system cgroup.
                if action.cgroup.is_some() {
                    if let Some(orig) = crate::applier::read_current_cgroup(pid) {
                        self.table.set_original_cgroup(pid, orig);
                    }
                }

                diag!("CLASSIFY",
                    "pid={} comm={:?} rule={:?} cgroup={:?} nice={:?} sched={:?} oom={:?}",
                    pid, info.comm, rule_name, action.cgroup,
                    action.nice, action.sched_policy, action.oom_score_adj
                );

                let _ok = apply_action(pid, &action, &self.cgmgr).await;

                if action.apply_to_children {
                    let children: Vec<u32> = self.table.children_of(pid).collect();
                    diag!("CHILDREN", "pid={} comm={:?} propagating cgroup to {} children",
                        pid, info.comm, children.len());
                    for child in children {
                        if self.table.get(child).is_some() {
                            apply_cgroup_only(child, &action, &self.cgmgr).await;
                        }
                    }
                }

                self.table.set_applied(pid, action);

                {
                    let mut state = self.state.lock().await;
                    state.managed.insert(pid, ProcessEntry {
                        pid,
                        comm:      info.comm.clone(),
                        cgroup:    cgroup_name.clone(),
                        rule_name: rule_name.clone(),
                    });
                }

                if let Some(ref conn) = dbus_conn {
                    emit_process_classified(conn, pid, &cgroup_name, &rule_name).await;
                }
            }
            None => {
                // Only log NO_RULE for user processes — uid=0 system/init
                // helpers are never moved so they add no actionable information
                // and flood the log (runsv, svlogd, tput, etc. on runit).
                if !info.is_kernel_thread && info.uid >= 1000 {
                    diag!("NO_RULE", "pid={} comm={:?} uid={} origin={:?}",
                        pid, info.comm, info.uid, info.session_origin);
                }
                self.table.mark_classified(pid);
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

        let unclassified: Vec<u32> = fresh
            .iter()
            .filter(|p| {
                self.table
                    .get(p.pid)
                    .map(|e| !e.classified)
                    .unwrap_or(true)
            })
            .map(|p| p.pid)
            .collect();

        self.table.merge_scan(fresh);
        tracing::info!(
            "full scan: {} processes ({} new to classify)",
            count, unclassified.len()
        );
        diag_section(&format!("SCAN {} procs {} new", count, unclassified.len()));

        // Suppress D-Bus signals during bulk classification — emitting hundreds
        // of signals at boot floods the bus and slows startup significantly.
        // Signals are still emitted for individual process events after startup.
        let bulk = unclassified.len() > 10;
        for pid in unclassified {
            if let Some(proc_info) = self.table.get(pid).map(|e| e.info.clone()) {
                self.classify_and_apply(
                    pid,
                    &proc_info,
                    if bulk { &None } else { dbus_conn },
                ).await;
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
                info!("critical memory pressure: throttling background/idle → swapstorm");
                self.state.lock().await.mode = "pressure-critical".into();
                // Move idle and background tier contents to swapstorm tier
                // which has memory.max=128M and memory.swap.max=0 — prevents
                // OOM cascade from swap exhaustion.
                let idle_pids = self.cgmgr.tier_cgroup(cgroupv2::CgroupTier::Idle).pids().await.unwrap_or_default();
                let bg_pids   = self.cgmgr.tier_cgroup(cgroupv2::CgroupTier::Background).pids().await.unwrap_or_default();
                for pid in idle_pids.into_iter().chain(bg_pids) {
                    let _ = self.cgmgr.assign_pid(Some(cgroupv2::CgroupTier::Swapstorm), pid).await;
                }
            }
            PressureLevel::High => {
                self.state.lock().await.mode = "pressure-high".into();
                info!("high memory pressure: background processes may be throttled");
            }
            PressureLevel::Low => {
                self.state.lock().await.mode = "pressure-low".into();
            }
            PressureLevel::Normal => {
                let was_critical = self.state.lock().await.mode == "pressure-critical";
                self.state.lock().await.mode = "normal".into();
                if was_critical {
                    // Pressure resolved — trigger rescan to restore processes
                    // to their correct tiers based on current rules.
                    info!("memory pressure resolved: restoring process tiers");
                    // Reset classified flags on swapstorm pids so next rescan reclassifies them.
                    let swapstorm_pids = self.cgmgr
                        .tier_cgroup(cgroupv2::CgroupTier::Swapstorm)
                        .pids().await.unwrap_or_default();
                    for pid in swapstorm_pids {
                        self.table.mark_classified_false(pid);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    async fn shutdown(&self) {
        info!("shutdown: restoring process cgroups");
        crate::diag::diag_section("SHUTDOWN");

        let moved = self.table.moved_pids();

        let restore_result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            async {
                let mut n = 0usize;
                for (pid, original) in &moved {
                    let Some(ref orig_path) = original else { continue; };
                    if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                        continue;
                    }
                    let procs = format!("/sys/fs/cgroup{}/cgroup.procs", orig_path);
                    if !std::path::Path::new(&procs).exists() {
                        debug!("teardown: original cgroup gone for pid {}: {}", pid, orig_path);
                        continue;
                    }
                    crate::applier::restore_cgroup(*pid, orig_path).await;
                    n += 1;
                }
                n
            }
        ).await;

        let restored = restore_result.unwrap_or_else(|_| {
            info!("teardown: restore timed out");
            0
        });

        if !moved.is_empty() {
            info!("teardown: restored {}/{} pids", restored, moved.len());
        }

        self.cgmgr.teardown().await;
        crate::diag::flush_diagnostic_log().await;
        info!("shutdown complete");
    }
}
