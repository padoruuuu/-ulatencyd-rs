//! Unix signal handling via signal-hook, on a dedicated OS thread.
//!
//! SIGTERM/SIGINT map to `Event::Shutdown`; SIGHUP maps to `Event::ReloadRules`.
//! There is no separate forwarding step: the signal thread pushes directly
//! onto the daemon's single fan-in event channel.

use std::sync::mpsc::Sender;

use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use tracing::info;

use crate::event::Event;

/// Spawn a background thread that listens for SIGTERM, SIGINT, and SIGHUP
/// and pushes the corresponding `Event` onto `tx`.
pub fn init_signals(tx: Sender<Event>) -> anyhow::Result<()> {
    let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP])?;

    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            for sig in signals.forever() {
                let ev = match sig {
                    SIGHUP => {
                        info!("received SIGHUP — reloading rules");
                        Event::ReloadRules
                    }
                    SIGTERM => {
                        info!("received SIGTERM");
                        Event::Shutdown
                    }
                    _ /* SIGINT */ => {
                        info!("received SIGINT");
                        Event::Shutdown
                    }
                };
                if tx.send(ev).is_err() {
                    return; // main loop has exited
                }
            }
        })?;

    Ok(())
}
