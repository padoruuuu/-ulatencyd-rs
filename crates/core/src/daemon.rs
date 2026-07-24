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
//!
//! Every source above runs on its own dedicated OS thread and pushes an
//! `Event` into one shared `std::sync::mpsc::Sender<Event>` (all spawned by
//! `main.rs`). This function's `run()` loop is a single blocking
//! `for event in event_rx.iter()`, replacing the old `tokio::select!` loop.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::{debug, info, warn};

use cgroupv2::{CgroupManager, CgroupTier};
use procmon::{ProcEvent, ProcessInfo};
use psi::PressureLevel;
use rules::RuleEngine;

use crate::applier::{apply_action, apply_cgroup_only};
use crate::config::Config;
use crate::control::{ControlCommand, ProcessEntry, SharedState};
use crate::diag::{diag, diag_section};
use crate::event::Event;
use crate::focus::ForegroundTracker;
use crate::forkbomb::ForkBombDetector;
use crate::init::InitSystem;
use crate::process_table::ProcessTable;
use crate::sched::{
    AutogroupGuard, PowerState, apply_sched_profile,
    probe_preempt_model_switchable, probe_sched_latency_ns,
    CONSERVATIVE, RESPONSIVE,
};

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
    startup_deadline: Instant,
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
    /// Last classified system-wide pressure level.
    last_pressure_level: PressureLevel,
}

impl Daemon {
    pub fn new(
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
        let startup_deadline = Instant::now() + Duration::from_secs(grace_secs);

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
            last_pressure_level: PressureLevel::Normal,
        })
    }

    // -----------------------------------------------------------------------
    // Entry-point
    // -----------------------------------------------------------------------

    /// Run the main event loop until `Event::Shutdown` is received.
    ///
    /// `initial_power` is the power state read synchronously at spawn time
    /// by `sched::spawn_power_monitor` (before this call), so the correct
    /// scheduling profile can be applied immediately at startup rather than
    /// waiting for the first `Event::Power`.
    pub fn run(
        mut self,
        event_rx: std::sync::mpsc::Receiver<Event>,
        initial_power: PowerState,
    ) -> Result<()> {
        // Disable autogroup (single highest-impact kernel toggle).
        let _autogroup_guard = if !self.config.sched.autogroup_enabled {
            Some(AutogroupGuard::disable()?)
        } else {
            None
        };

        // Apply the scheduling profile matching the power state observed at
        // startup.
        self.last_power_source = Some(initial_power);
        let profile = if initial_power == PowerState::Battery {
            &CONSERVATIVE
        } else {
            &RESPONSIVE
        };
        apply_sched_profile(profile, self.sched_latency_ns_available, self.preempt_switchable);

        // Initial scan.
        if self.config.daemon.apply_to_existing_processes {
            self.do_full_scan();
        }

        // Startup grace period is already configured in Daemon::new()
        // based on the detected init system.  We re-assert it here so
        // that a future restart/reset path can re-enter the grace period
        // without duplicating the init-system logic.
        self.startup_phase = true;

        info!("event loop started");

        for event in event_rx.iter() {
            // End of startup grace period — enable classification.
            if self.startup_phase && Instant::now() >= self.startup_deadline {
                info!("startup grace period ended; enabling full classification");
                self.startup_phase = false;
                self.do_full_scan();
            }

            match event {
                Event::Proc(e) => {
                    if self.startup_phase {
                        // During the grace period we still drain proc
                        // events so classification stays deferred but
                        // bookkeeping (fork-bomb tracking, table inserts,
                        // Exit cleanup) doesn't fall behind.
                        self.handle_proc_event_startup(e);
                    } else {
                        self.handle_proc_event(e);
                    }
                }

                Event::Control(cmd) => self.handle_control_cmd(cmd),

                Event::Pressure(pressure) => {
                    self.state.lock().unwrap().pressure = pressure;
                    let level = PressureLevel::from_memory(
                        &pressure.memory,
                        self.config.pressure.memory_low_threshold,
                        self.config.pressure.memory_high_threshold,
                    );
                    if level != self.last_pressure_level {
                        info!("pressure level: {:?} → {:?}", self.last_pressure_level, level);
                        diag!("PSI",
                            "level={:?} mem_avg10={:.2} io_avg10={:.2} cpu_avg10={:.2}",
                            level, pressure.memory.some_avg10,
                            pressure.io.some_avg10, pressure.cpu.some_avg10
                        );
                        self.last_pressure_level = level;
                        self.handle_pressure_change(level);
                    }
                }

                Event::Power(new_source) => {
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

                Event::RescanTick => {
                    debug!("periodic rescan");
                    self.do_full_scan();
                }

                Event::RecheckTick => self.do_rechecks(),

                Event::GcTick => self.do_gc(),

                Event::ReloadRules => self.reload_rules(),

                Event::Shutdown => {
                    info!("shutdown signal received");
                    break;
                }
            }
        }

        self.shutdown();
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
    fn handle_proc_event_startup(&mut self, event: ProcEvent) {
        match event {
            ProcEvent::Fork { parent_pid, child_pid, child_tgid } => {
                diag!("FORK(startup)", "parent={} child={} tgid={}", parent_pid, child_pid, child_tgid);
                // Still track forks for fork-bomb detection even during startup.
                if child_pid == child_tgid {
                    if let Some(ppid) = self.forkbomb.record_fork(parent_pid) {
                        let count = self.forkbomb
                            .throttle_subtree(ppid, &self.table, &self.cgmgr);
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
                self.state.lock().unwrap().managed.remove(&pid);
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

    fn handle_proc_event(&mut self, event: ProcEvent) {
        match event {
            ProcEvent::Fork { parent_pid, child_pid, child_tgid } => {
                diag!("FORK", "parent={} child={} tgid={}", parent_pid, child_pid, child_tgid);
                if child_pid == child_tgid {
                    if let Some(ppid) = self.forkbomb.record_fork(parent_pid) {
                        let count = self.forkbomb
                            .throttle_subtree(ppid, &self.table, &self.cgmgr);
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
                            self.classify_and_apply(pid, info);
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
                self.state.lock().unwrap().managed.remove(&pid);
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
                                self.classify_and_apply(pid, info);
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

    fn handle_control_cmd(&mut self, cmd: ControlCommand) {
        match cmd {
            ControlCommand::SetForegroundProcess(pid) => {
                if self.startup_phase {
                    info!("ignoring SetForegroundProcess during startup (pid={})", pid);
                    return;
                }
                info!("foreground pid → {}", pid);
                self.state.lock().unwrap().foreground_pid = Some(pid);
                self.focus.set_foreground(pid, &self.table, &self.cgmgr);
            }

            ControlCommand::SetProcessCgroup { pid, cgroup } => {
                if let Some(tier) = CgroupTier::from_str(&cgroup) {
                    if let Err(e) = self.cgmgr.assign_pid(Some(tier), pid) {
                        warn!("control SetProcessCgroup pid={} cgroup={}: {}", pid, cgroup, e);
                    }
                }
            }

            ControlCommand::ReloadRules => self.reload_rules(),
        }
    }

    fn reload_rules(&mut self) {
        match self.engine.reload(&self.config.daemon.rules_dir) {
            Ok(_)  => info!("rules reloaded"),
            Err(e) => warn!("rules reload failed: {}", e),
        }
    }

    fn classify_and_apply(&mut self, pid: u32, mut info: ProcessInfo) {
        // Never classify our own process or its threads — we'd be moving
        // ourselves, which changes our own scheduling in undefined ways.
        // Netlink fork events fire for plain std::thread spawns too (they're
        // clone() under the hood), so every dedicated OS thread name this
        // daemon uses needs to be listed here, not just the process's own
        // comm. (Previously just "tokio-rt-worker" + "procmon-netlink" — the
        // tokio worker thread is gone, but this migration added several more
        // named threads that need the same guard.)
        let own_pid = std::process::id();
        const OWN_THREAD_NAMES: &[&str] = &[
            "ulatencyd", "procmon-netlink", "psi-monitor", "power-monitor",
            "signals", "control-socket", "control-sock-perm", "diag-log",
            "cgroup-gc", "cgroup-teardown", "shutdown-restore",
        ];
        if pid == own_pid || info.ppid == own_pid as u32
            || OWN_THREAD_NAMES.contains(&info.comm.as_str())
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

                let _ok = apply_action(pid, &action, &self.cgmgr);

                if action.apply_to_children {
                    let children: Vec<u32> = self.table.children_of(pid).collect();
                    diag!("CHILDREN", "pid={} comm={:?} propagating cgroup to {} children",
                        pid, info.comm, children.len());
                    for child in children {
                        if self.table.get(child).is_some() {
                            apply_cgroup_only(child, &action, &self.cgmgr);
                        }
                    }
                }

                self.table.set_applied(pid, action);

                {
                    let mut state = self.state.lock().unwrap();
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

    fn do_full_scan(&mut self) {
        // Previously offloaded to tokio::task::spawn_blocking to avoid
        // stalling the single-threaded async runtime's other select! arms
        // while the /proc walk ran. With no async runtime, this is just a
        // plain synchronous call — other event producers (procmon, control
        // socket, PSI, timers) keep queuing into event_rx regardless of how
        // long this takes, so nothing is lost, only delayed.
        let known_pids = self.table.known_pids();
        let scan_result = procmon::scan_proc_incremental(&known_pids);

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
            let mut state = self.state.lock().unwrap();
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
                    self.classify_and_apply(pid, proc_info);
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

    fn do_rechecks(&mut self) {
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
                    self.classify_and_apply(pid, proc_info);
                }
                Err(_) => {
                    // Remove from both stores so the managed map doesn't
                    // accumulate ghost entries for dead processes.
                    self.table.remove(pid);
                    self.state.lock().unwrap().managed.remove(&pid);
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

    fn handle_pressure_change(&mut self, level: PressureLevel) {
        match level {
            PressureLevel::Critical => {
                info!("critical memory pressure: throttling background/idle → swapstorm");
                self.state.lock().unwrap().mode = "pressure-critical".into();
                // Move idle and background tier contents to swapstorm tier
                // which has memory.max=128M and memory.swap.max=0 — prevents
                // OOM cascade from swap exhaustion.
                let idle_pids = self.cgmgr.tier_cgroup(cgroupv2::CgroupTier::Idle).pids().unwrap_or_default();
                let bg_pids   = self.cgmgr.tier_cgroup(cgroupv2::CgroupTier::Background).pids().unwrap_or_default();
                for pid in idle_pids.into_iter().chain(bg_pids) {
                    let _ = self.cgmgr.assign_pid(Some(cgroupv2::CgroupTier::Swapstorm), pid);
                }
            }
            PressureLevel::High => {
                self.state.lock().unwrap().mode = "pressure-high".into();
                info!("high memory pressure: background processes may be throttled");
            }
            PressureLevel::Low => {
                self.state.lock().unwrap().mode = "pressure-low".into();
            }
            PressureLevel::Normal => {
                let was_critical = self.state.lock().unwrap().mode == "pressure-critical";
                self.state.lock().unwrap().mode = "normal".into();
                if was_critical {
                    // Pressure resolved — trigger rescan to restore processes
                    // to their correct tiers based on current rules.
                    info!("memory pressure resolved: restoring process tiers");
                    // Reset classified flags on swapstorm pids so next rescan reclassifies them.
                    let swapstorm_pids = self.cgmgr
                        .tier_cgroup(cgroupv2::CgroupTier::Swapstorm)
                        .pids().unwrap_or_default();
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

    fn shutdown(&self) {
        info!("shutdown: restoring process cgroups");
        crate::diag::diag_section("SHUTDOWN");

        let moved = self.table.moved_pids();

        // Cap the whole restore pass at 2s, same as before. There's no
        // async runtime to hand a future to tokio::time::timeout anymore,
        // so run the restore loop on its own thread and wait for it with
        // recv_timeout — the same pattern cgroupv2::teardown uses.
        let (tx, rx) = std::sync::mpsc::channel();
        let restore_thread = std::thread::Builder::new()
            .name("shutdown-restore".into())
            .spawn(move || {
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
                    crate::applier::restore_cgroup(*pid, orig_path);
                    n += 1;
                }
                let _ = tx.send((n, moved.len()));
            });

        let restored = if restore_thread.is_ok() {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok((n, total)) => Some((n, total)),
                Err(_) => {
                    info!("teardown: restore timed out");
                    None
                }
            }
        } else {
            None
        };

        if let Some((restored, total)) = restored {
            if total > 0 {
                info!("teardown: restored {}/{} pids", restored, total);
            }
        }

        self.cgmgr.teardown();
        crate::diag::flush_diagnostic_log();
        info!("shutdown complete");
    }
}
