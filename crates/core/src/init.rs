//! Init system detection and supervisor readiness notification.
//!
//! Detection is purely runtime — the same binary works on any init system.
//! No compile-time flags are used.
//!
//! ## Universal supervisor protocol
//!
//! All init systems converge on two primitives:
//!   * readiness  — "I am ready to serve"
//!   * stopping   — "I am about to exit"
//!
//! | Init system | Readiness mechanism                                    | Stopping     |
//! |-------------|-------------------------------------------------------|--------------|
//! | systemd     | sd_notify("READY=1\\n") + MAINPID=...                 | STOPPING=1   |
//! | s6          | NOTIFY_SOCKET (s6-notifyoncheck) or $READY_FD        | (same)       |
//! | runit       | ./check script (external); daemon just stays alive    | (n/a)        |
//! | OpenRC      | start-stop-daemon --waitpid; daemon just stays alive   | (n/a)        |
//!
//! By writing to the same `Supervisor` trait, a fix for one init system
//! automatically benefits all others.

use std::os::unix::net::UnixDatagram;
use std::path::Path;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// InitSystem
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    Runit,
    S6,
    OpenRC,
    Unknown,
}

impl InitSystem {
    /// Detect the running init system by inspecting /proc/1/comm and
    /// well-known indicator paths.
    pub fn detect() -> Self {
        let comm = std::fs::read_to_string("/proc/1/comm")
            .unwrap_or_default()
            .trim()
            .to_string();

        match comm.as_str() {
            "systemd" => {
                info!("detected init: systemd");
                Self::Systemd
            }
            "runit" => {
                info!("detected init: runit");
                Self::Runit
            }
            "s6-svscan" => {
                info!("detected init: s6");
                Self::S6
            }
            "openrc-init" => {
                info!("detected init: OpenRC");
                Self::OpenRC
            }
            other => {
                // Some containers / WSL don't have the canonical PID-1 comm.
                if Path::new("/run/systemd/system").exists() {
                    info!("detected init: systemd (via /run/systemd/system)");
                    return Self::Systemd;
                }
                if Path::new("/run/runit").exists() {
                    info!("detected init: runit (via /run/runit)");
                    return Self::Runit;
                }
                if Path::new("/run/s6").exists() || Path::new("/run/s6-rc").exists() {
                    info!("detected init: s6 (via /run/s6)");
                    return Self::S6;
                }
                if Path::new("/run/openrc").exists() {
                    info!("detected init: OpenRC (via /run/openrc)");
                    return Self::OpenRC;
                }
                debug!("unknown init (PID 1 comm = {:?})", other);
                Self::Unknown
            }
        }
    }



    /// Whether sd_notify-style readiness is meaningful.
    /// True for systemd AND for any supervisor that sets NOTIFY_SOCKET
    /// (e.g. s6 with s6-notifyoncheck also sets it).
    pub fn supports_notify_socket(&self) -> bool {
        std::env::var("NOTIFY_SOCKET").is_ok()
    }

    /// Recommended startup grace period in seconds.
    ///
    /// Non-systemd init systems often start the daemon before the
    /// graphical session is fully initialised.  A longer grace period
    /// prevents premature classification of session components.
    pub fn startup_grace_secs(&self) -> u64 {
        match self {
            Self::Systemd  => 10,
            Self::Runit    => 30,
            Self::S6       => 30,
            Self::OpenRC   => 30,
            Self::Unknown  => 30,
        }
    }
}

// ---------------------------------------------------------------------------
// Supervisor trait — write once, work everywhere
// ---------------------------------------------------------------------------

/// Universal interface for notifying the service supervisor.
///
/// Each method has a default no-op implementation, so adding a new
/// init system only requires overriding the methods it supports.
pub trait Supervisor: Send + Sync {
    /// The daemon has finished initialisation and is ready for work.
    fn ready(&self) {
        debug!("supervisor ready: no-op (init={:?})", self.init_system());
    }

    /// The daemon is about to shut down.
    fn stopping(&self) {
        debug!("supervisor stopping: no-op (init={:?})", self.init_system());
    }

    /// Update the human-readable status string.
    fn status(&self, _msg: &str) {}

    /// Announce our main PID (systemd MAINPID=).
    fn mainpid(&self, _pid: u32) {}



    /// Return the init system this supervisor wraps.
    fn init_system(&self) -> InitSystem;

    /// Extend the startup timeout.
    ///
    /// On systemd this sends `EXTEND_TIMEOUT_USEC=<usec>` to the service
    /// manager, delaying the watchdog deadline.  On all other init systems
    /// (runit, s6, OpenRC, Unknown) this is a **no-op** — none of them
    /// implement an equivalent mechanism.  The implementation in
    /// `SupervisorNotify` already handles this correctly: it gates the
    /// `sd_notify` call on `NOTIFY_SOCKET` being set, which only happens on
    /// systemd (and on s6 with `s6-notifyoncheck`).
    fn extend_timeout(&self, _usec: u64) {}
}

// ---------------------------------------------------------------------------
// SupervisorNotify — universal implementation
// ---------------------------------------------------------------------------

/// Concrete supervisor that auto-detects the init system and dispatches
/// to the correct notification mechanism.
pub struct SupervisorNotify {
    init: InitSystem,
}

impl SupervisorNotify {
    /// Auto-detect and construct — no need to pass InitSystem explicitly.
    pub fn detect() -> Self {
        Self {
            init: InitSystem::detect(),
        }
    }

    /// Access the underlying init system for init-specific tuning
    /// (e.g. startup grace period, cgroup setup strategy).
    pub fn init(&self) -> InitSystem {
        self.init
    }
}

impl Supervisor for SupervisorNotify {
    fn init_system(&self) -> InitSystem {
        self.init
    }

    fn ready(&self) {
        // 1. sd_notify READY=1 (systemd, s6-notifyoncheck, and any
        //    supervisor that sets NOTIFY_SOCKET).
        if self.init.supports_notify_socket() {
            match sd_notify("READY=1\n") {
                Ok(()) => {
                    debug!("notified supervisor: READY=1");
                    return;
                }
                Err(e) => warn!("sd_notify READY=1 failed: {}", e),
            }
        }

        // 2. s6 READY_FD fallback — write '\n' to the fd in $READY_FD.
        if let Ok(fd_str) = std::env::var("READY_FD") {
            if let Ok(fd) = fd_str.parse::<i32>() {
                // SAFETY: fd is an integer from the environment;
                //         a single-byte write to a pipe is atomic.
                let rc = unsafe { libc::write(fd, b"\n".as_ptr() as *const _, 1) };
                if rc == 1 {
                    debug!("notified supervisor: READY_FD={}", fd);
                    return;
                }
                warn!("READY_FD={} write returned {} (errno check)", fd, rc);
            }
        }

        // 3. runit / OpenRC / Unknown: the daemon is considered ready
        //    the moment it daemonizes and the ./run or start-stop-daemon
        //    wrapper returns.  No explicit notification is required.
        debug!(
            "supervisor ready: implicit (init={:?}, no NOTIFY_SOCKET / READY_FD)",
            self.init
        );
    }

    fn stopping(&self) {
        if self.init.supports_notify_socket() {
            let _ = sd_notify("STOPPING=1\n");
        }
    }

    fn status(&self, msg: &str) {
        if self.init.supports_notify_socket() {
            let _ = sd_notify(&format!("STATUS={}\n", msg));
        }
    }

    fn mainpid(&self, pid: u32) {
        if self.init.supports_notify_socket() {
            let _ = sd_notify(&format!("MAINPID={}\n", pid));
        }
    }



    fn extend_timeout(&self, usec: u64) {
        if self.init.supports_notify_socket() {
            let _ = sd_notify(&format!("EXTEND_TIMEOUT_USEC={}\n", usec));
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level sd_notify helper
// ---------------------------------------------------------------------------

/// Write a datagram to $NOTIFY_SOCKET.
/// Implements the sd_notify protocol without linking libsystemd.
fn sd_notify(msg: &str) -> std::io::Result<()> {
    let socket_path = std::env::var("NOTIFY_SOCKET")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;

    // NOTIFY_SOCKET may start with '@' for abstract namespace sockets.
    let sock = UnixDatagram::unbound()?;
    let path = if let Some(stripped) = socket_path.strip_prefix('@') {
        format!("\0{}", stripped)
    } else {
        socket_path
    };
    sock.send_to(msg.as_bytes(), path)?;
    Ok(())
}
