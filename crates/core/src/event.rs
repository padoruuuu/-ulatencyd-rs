//! Fan-in event type for the daemon's synchronous main loop.
//!
//! Every event source — the netlink proc monitor, the control socket, the
//! PSI monitor, the power monitor, the periodic timers, and signal handling
//! — runs on its own dedicated OS thread. Each thread holds a clone of a
//! single `std::sync::mpsc::Sender<Event>` created once in `main.rs`, and
//! pushes into it as things happen. The main loop is a single blocking
//! `for event in event_rx.iter() { ... }`, replacing the old
//! `tokio::select!` loop in `daemon.rs`.

use procmon::ProcEvent;
use psi::SystemPressure;

use crate::control::ControlCommand;
use crate::sched::PowerState;

pub enum Event {
    /// Fork/exec/exit/comm/uid event from procmon's netlink thread.
    Proc(ProcEvent),
    /// A command received over the varlink control socket.
    Control(ControlCommand),
    /// Fresh PSI reading from the psi-monitor thread (kernel trigger or
    /// fallback tick).
    Pressure(SystemPressure),
    /// AC/battery transition from the power-monitor thread.
    Power(PowerState),
    /// Periodic full /proc rescan.
    RescanTick,
    /// Periodic recheck of processes with a recheck_secs action.
    RecheckTick,
    /// Periodic empty-cgroup / stale-window garbage collection.
    GcTick,
    /// SIGHUP — reload rule files from disk.
    ReloadRules,
    /// SIGTERM/SIGINT — begin graceful shutdown.
    Shutdown,
}
