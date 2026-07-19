//! Main event loop for ulatencyd-rs.
//!
//! Wires together:
//!   - netlink proc connector (fork/exec/exit events)
//!   - full /proc rescan (startup + periodic)
//!   - rule engine classification
//!   - cgroup/sched/nice application
//!   - PSI pressure monitor
//!   - fork-bomb detector
//!   - control socket command receiver
//!   - power-aware sched profile switching
//!   - SIGHUP (reload) / SIGTERM (graceful shutdown)

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Mutex;
use tokio::time;
use tracing::{debug, info, warn};

use cgroupv2::{CgroupManager, CgroupTier};
use procmon::{ProcEvent, ProcessInfo, ProcMonitor};
use psi::{PressureLevel, spawn_psi_monitor};
use rules::RuleEngine;

use crate::applier::{apply_action, apply_cgroup_only};
use crate::config::Config;
use crate::control::{ControlCommand, ProcessEntry, SharedState};
use crate::diag::{diag, diag_section};
use crate::focus::ForegroundTracker;
use crate::forkbomb::ForkBombDetector;
use crate::init::InitSystem;
use crate::process_table::ProcessTable;
use crate::sched::{
    AutogroupGuard, PowerState, apply_sched_profile,
    monitor_power_state, probe_preempt_model_switchable, probe_sched_latency_ns,
    CONSERVATIVE, RESPONSIVE,
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
    startup_deadline: tokio::time::Instant,
    startup_phase:    bool,
    /// Probed once at startup: true on CFS kernels (< 6.6), false on EEVDF.
    sched_latency_ns_available: bool,
    /// Probed once at startup: true when the kernel supports runtime preempt
    /// model switching (CONFIG_PREEMPT_DYNAMIC and no sched_ext active).
    preempt_switchable: bool,
    /// Last observed power source; used to detect real AC↔battery transitions
    /// and suppress spurious handler invocations when the polled value is
    /// unchanged.
    last_power_source: Option<PowerState>,
}

impl Daemon {
    pub async fn new(
        config:     Config,
        cgmgr:      CgroupManager,
        state:      Arc<Mutex<SharedState>>,
        init_system: InitSystem,
    ) -> Result<Self> {
        let engine = RuleEngine::load(&config.daemon.rules_dir)?;
        info!("rule engine: {} rules loaded", engine.rule_count());

        let forkbomb = ForkBombDetector::new(
            config.fork_bomb.threshold_per_second,
            config.fork_bomb.lineage_depth,
        );

        // Startup grace period: during the first N seconds after launch,
        // no process classification or cgroup moves are applied. This
        // prevents interfering with session startup on non-systemd init
        // systems (runit, s6, OpenRC) where the daemon may start before
        // the graphical session is fully initialised.
        //
        // The grace period is tuned per init system — systemd services
        // typically start after the session is ready, so a shorter window
        // is safe.
        let grace_secs = init_system.startup_grace_secs();
        let startup_deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(grace_secs);

        info!(
            "startup grace period: {} s (init={:?})",
            grace_secs, init_system
        );

        // Probe once: sched_latency_ns availability (CFS vs EEVDF kernel).
        let sched_latency_ns_available = probe_sched_latency_ns();
        if !sched_latency_ns_available {
            info!(
                "sched_latency_ns absent (kernel ≥ 6.6, EEVDF); \
                 using sched_min_granularity_ns + sched_wakeup_granularity_ns instead"
            );
        }

        // Probe once: preempt model switchability.
        let preempt_switchable = probe_preempt_model_switchable();
        if !preempt_switchable {
            info!("preempt model switching unavailable (fixed kernel or sched_ext active); skipping");
        }

        Ok(Self {
            config,
            cgmgr,
            engine,
            table: ProcessTable::new(),
            forkbomb,
            focus: ForegroundTracker::new(),
            state,
            startup_deadline,
            startup_phase: true,
            sched_latency_ns_available,
            preempt_switchable,
            last_power_source: None,
        })
    }

    // -----------------------------------------------------------------------
    // Entry-point
    // -----------------------------------------------------------------------

    pub async fn run(
        mut self,
        mut proc_monitor: ProcMonitor,
        mut control_rx:   tokio::sync::mpsc::Receiver<ControlCommand>,
        mut shutdown:     ShutdownToken,
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
        let initial_power = *power_rx.borrow();
        self.last_power_source = Some(initial_power);
        let profile = if initial_power == PowerState::Battery {
            &CONSERVATIVE
        } else {
            &RESPONSIVE
        };
        apply_sched_profile(profile, self.sched_latency_ns_available, self.preempt_switchable);

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
            self.do_full_scan().await;
        }

        // Startup grace period is already configured in Daemon::new()
        // based on the detected init system.  We re-assert it here so
        // that a future restart/reset path can re-enter the grace period
        // without duplicating the init-system logic.
        self.startup_phase = true;

        info!("event loop started");

        loop {
            // End of startup grace period — enable classification.
            if self.startup_phase && tokio::time::Instant::now() >= self.startup_deadline {
                info!("startup grace period ended; enabling full classification");
                self.startup_phase = false;
                self.do_full_scan().await;
            }
            tokio::select! {
                // Netlink proc event.
                event = proc_monitor.next_event() => {
                    match event {
                        Some(e) => {
                            if self.startup_phase {
                                // During the grace period we still drain the
                                // channel so the 4096-slot buffer never fills
                                // and stalls the listener thread (which causes
                                // the kernel to drop events, including future
                                // Exits).  Process Exits for bookkeeping only;
                                // full classification happens after the grace
                                // period via do_full_scan().
                                self.handle_proc_event_startup(e).await;
                            } else {
                                self.handle_proc_event(e).await;
                            }
                        }
                        None    => {
                            warn!("netlink proc monitor closed — stopping");
                            break;
                        }
                    }
                }

                // Control socket command.
                cmd = control_rx.recv() => {
                    match cmd {
                        Some(c) => self.handle_control_cmd(c).await,
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
                        self.handle_pressure_change(level).await;
                    }
                }

                // Power state change.
                _ = power_rx.changed() => {
                    let new_source = *power_rx.borrow_and_update();
                    if self.last_power_source != Some(new_source) {
                        let prev = self.last_power_source.replace(new_source);
                        if let Some(p) = prev {
                            info!("power source: {:?} → {:?}", p, new_source);
                        }
                        let profile = if new_source == PowerState::Battery {
                            &CONSERVATIVE
                        } else {
                            &RESPONSIVE
                        };
                        apply_sched_profile(
                            profile,
                            self.sched_latency_ns_available,
                            self.preempt_switchable,
                        );
                    }
                }

                // Periodic full rescan.
                _ = rescan_timer.tick() => {
                    debug!("periodic rescan");
                    self.do_full_scan().await;
                }

                // Recheck timer.
                _ = recheck_timer.tick() => {
                    self.do_rechecks().await;
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
    // Proc events (startup-phase — bookkeeping only, no classification)
    // -----------------------------------------------------------------------

    /// Lightweight event handler used during the startup grace period.
    /// Keeps the netlink channel drained to prevent buffer saturation and
    /// dropped Exit events.  Only Exit events need real processing — Fork
    /// events are ignored (the subsequent full scan will pick up survivors)
    /// and Exec/Comm/Uid events are deferred to post-grace classification.
    async fn handle_proc_event_startup(&mut self, event: ProcEvent) {
        match event {
            ProcEvent::Fork { parent_pid, child_pid, child_tgid } => {
                diag!("FORK(startup)", "parent={} child={} tgid={}", parent_pid, child_pid, child_tgid);
                // Still track forks for fork-bomb detection even during startup.
                if child_pid == child_tgid {
                    if let Some(ppid) = self.forkbomb.record_fork(parent_pid) {
                        let count = self.forkbomb
                            .throttle_subtree(ppid, &self.table, &self.cgmgr)
                            .await;
                        debug!("startup fork-bomb: ppid={} throttled {} pids", ppid, count);
                    }
                }
                // Insert into table so children_of() works correctly once
                // the grace period ends and classify_and_apply() runs.
                if let Ok(info) = ProcessInfo::from_pid(child_pid) {
                    self.table.insert(info);
                    self.table.mark_classified(child_pid); // defer classification
                }
            }

            ProcEvent::Exit { pid, .. } => {
                diag!("EXIT(startup)", "pid={}", pid);
                self.focus.on_exit(pid);
                self.table.remove(pid);
                // Remove from managed even though classification is deferred —
                // a previous daemon instance or a pre-existing classified entry
                // could be in the map.
                self.state.lock().await.managed.remove(&pid);
            }

            // Exec/Comm/Uid during startup: just insert into the table so we
            // have current process info, but defer classification.
            ProcEvent::Exec { pid } => {
                if let Ok(info) = ProcessInfo::from_pid(pid) {
                    self.table.insert(info);
                    // insert() resets classified=false; re-mark as classified
                    // so the startup-phase guard below doesn't re-attempt.
                    // After grace period, do_full_scan will reclassify properly.
                    self.table.mark_classified(pid);
                }
            }

            ProcEvent::Comm { .. } | ProcEvent::Uid { .. } => {
                // Ignore during startup — do_full_scan handles these.
            }
        }
    }

    // -----------------------------------------------------------------------
    // Proc events
    // -----------------------------------------------------------------------

    async fn handle_proc_event(&mut self, event: ProcEvent) {
        match event {
            ProcEvent::Fork { parent_pid, child_pid, child_tgid } => {
                diag!("FORK", "parent={} child={} tgid={}", parent_pid, child_pid, child_tgid);
                if child_pid == child_tgid {
                    if let Some(ppid) = self.forkbomb.record_fork(parent_pid) {
                        let count = self.forkbomb
                            .throttle_subtree(ppid, &self.table, &self.cgmgr)
                            .await;
                        warn!("fork bomb: ppid={} throttled {} pids", ppid, count);
                        return;
                    }
                }

                match ProcessInfo::from_pid(child_pid) {
                    Ok(info) => {
                        self.table.insert(info);
                        // Do NOT classify at fork time. The child still has
                        // the parent's comm and hasn't exec'd its real binary
                        // yet. Classifying here applies the parent's rules to
                        // the child — e.g. sway forks a child that becomes
                        // xfce4-taskmand, but we'd apply compositor oom=-1000
                        // to it before it execs, and oom_score_adj persists
                        // across exec, potentially breaking the service.
                        // Classification happens correctly at EXEC instead.
                        self.table.mark_classified(child_pid);
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
                        if !self.startup_phase {
                            self.classify_and_apply(pid, info).await;
                        } else {
                            debug!("startup phase: defer classification for pid {}", pid);
                        }
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
                            if !self.startup_phase {
                                self.classify_and_apply(pid, info).await;
                            } else {
                                debug!("startup phase: defer classification for pid {}", pid);
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Control socket commands
    // -----------------------------------------------------------------------

    async fn handle_control_cmd(&mut self, cmd: ControlCommand) {
        match cmd {
            ControlCommand::SetForegroundProcess(pid) => {
                if self.startup_phase {
                    info!("ignoring SetForegroundProcess during startup (pid={})", pid);
                    return;
                }
                info!("foreground pid → {}", pid);
                self.state.lock().await.foreground_pid = Some(pid);
                self.focus.set_foreground(pid, &self.table, &self.cgmgr).await;
            }

            ControlCommand::SetProcessCgroup { pid, cgroup } => {
                if let Some(tier) = CgroupTier::from_str(&cgroup) {
                    if let Err(e) = self.cgmgr.assign_pid(Some(tier), pid).await {
                        warn!("control SetProcessCgroup pid={} cgroup={}: {}", pid, cgroup, e);
                    }
                }
            }

            ControlCommand::ReloadRules => {
                match self.engine.reload(&self.config.daemon.rules_dir) {
                    Ok(_)  => info!("rules reloaded"),
                    Err(e) => warn!("rules reload failed: {}", e),
                }
            }
        }
    }

    async fn classify_and_apply(&mut self, pid: u32, mut info: ProcessInfo) {
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

        // Do not demote a process that the focus tracker has boosted to interactive.
        // The foreground tracker owns these PIDs; classify_and_apply must not override
        // their cgroup/nice placement.  Without this guard, do_rechecks() → table.insert()
        // resets classified=false on browser PIDs, triggering a full rule-engine
        // re-evaluation that demotes them from interactive back to system, causing
        // a visible freeze until the focus tracker re-promotes them.
        if self.focus.is_foreground(pid) {
            self.table.mark_classified(pid);
            return;
        }

        // Lazily load /proc/pid/environ only when a loaded rule actually
        // declares env_set — /proc/pid/environ can be several KB, so this
        // must not run unconditionally on every classify.
        if self.engine.wants_environ() && info.environ.is_empty() {
            let _ = info.load_environ();
        }

        let ancestors = self.table.ancestor_comms(pid, 10);

        match self.engine.classify(&info, &ancestors) {
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

    async fn do_full_scan(&mut self) {
        let known_pids = self.table.known_pids();
        let scan_result = tokio::task::spawn_blocking(move || {
            procmon::scan_proc_incremental(&known_pids)
        })
            .await
            .unwrap_or_else(|_| procmon::ScanResult::default());

        let new_count = scan_result.new_processes.len();
        let live_pids = scan_result.live_pids.clone();

        self.table.merge_scan(scan_result.new_processes, &live_pids);

        // Any process whose `classified` flag is false — whether brand new
        // this scan or an existing entry reset by e.g. swapstorm-recovery
        // reclassification — needs (re)classification.  Querying the table
        // directly post-merge (rather than re-deriving from the scan's own
        // transient new-processes list) correctly picks up both cases.
        let unclassified: Vec<u32> = self.table.unclassified_pids();

        tracing::info!(
            "full scan: {} live processes ({} new, {} to classify)",
            live_pids.len(), new_count, unclassified.len()
        );
        diag_section(&format!("SCAN {} procs {} new {} to classify", live_pids.len(), new_count, unclassified.len()));

        // GC the managed map against the live PID set.  merge_scan() already
        // prunes ProcessTable, but SharedState::managed is a separate map
        // that only gets cleaned on Exit events.  If an Exit event was
        // dropped (netlink backpressure, kernel buffer overflow) the entry
        // would leak forever without this sweep.
        {
            let mut state = self.state.lock().await;
            let before = state.managed.len();
            state.managed.retain(|pid, _| live_pids.contains(pid));
            let removed = before - state.managed.len();
            if removed > 0 {
                debug!("gc: removed {} stale managed entries", removed);
            }
        }

        if !self.startup_phase {
            for pid in unclassified {
                if let Some(proc_info) = self.table.get(pid).map(|e| e.info.clone()) {
                    self.classify_and_apply(pid, proc_info).await;
                }
            }
        } else {
            tracing::info!(
                "startup phase: deferring classification of {} processes",
                unclassified.len()
            );
        }
    }

    // -----------------------------------------------------------------------
    // Recheck
    // -----------------------------------------------------------------------

    async fn do_rechecks(&mut self) {
        let expired = self.table.expired_rechecks();
        for pid in expired {
            // Do not re-insert or re-classify processes that the focus tracker
            // has boosted to interactive.  table.insert() resets classified=false,
            // which would trigger a full rule-engine re-evaluation on the next
            // classify_and_apply call and demote the foreground process from
            // interactive to whichever system rule matches — exactly the freeze
            // bug this guard is meant to prevent.  The foreground guard inside
            // classify_and_apply() also catches this, but skipping re-insertion
            // here avoids the unnecessary /proc read entirely.
            if self.focus.is_foreground(pid) {
                continue;
            }
            match ProcessInfo::from_pid(pid) {
                Ok(proc_info) => {
                    self.table.insert(proc_info.clone());
                    self.classify_and_apply(pid, proc_info).await;
                }
                Err(_) => {
                    // Remove from both stores so the managed map doesn't
                    // accumulate ghost entries for dead processes.
                    self.table.remove(pid);
                    self.state.lock().await.managed.remove(&pid);
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
