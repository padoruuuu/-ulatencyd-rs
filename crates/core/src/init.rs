//! Init system detection and supervisor readiness notification.
//!
//! Detection is purely runtime — the same binary works on any init system.
//! No compile-time flags are used.

use std::os::unix::net::UnixDatagram;
use std::path::Path;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// InitSystem
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
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
            .unwrap_or_default();
        match comm.trim() {
            "systemd"     => {
                info!("detected init: systemd");
                Self::Systemd
            }
            "runit"       => {
                info!("detected init: runit");
                Self::Runit
            }
            "s6-svscan"   => {
                info!("detected init: s6");
                Self::S6
            }
            "openrc-init" => {
                info!("detected init: OpenRC");
                Self::OpenRC
            }
            _ => {
                if Path::new("/run/openrc").exists() {
                    info!("detected init: OpenRC (via /run/openrc)");
                    return Self::OpenRC;
                }
                debug!("unknown init (PID 1 comm = {:?})", comm.trim());
                Self::Unknown
            }
        }
    }

    /// Whether to request a delegated cgroup slice via systemd D-Bus.
    #[allow(dead_code)]
    pub fn uses_systemd_cgroups(&self) -> bool {
        matches!(self, Self::Systemd)
    }

    /// Whether sd_notify-style readiness is meaningful.
    /// True for systemd AND for any supervisor that sets NOTIFY_SOCKET
    /// (e.g. s6 with s6-notifyoncheck also sets it).
    pub fn supports_notify_socket(&self) -> bool {
        std::env::var("NOTIFY_SOCKET").is_ok()
    }
}

// ---------------------------------------------------------------------------
// SupervisorNotify
// ---------------------------------------------------------------------------

/// Abstracts supervisor readiness/stopping/status notifications.
pub struct SupervisorNotify {
    init: InitSystem,
}

impl SupervisorNotify {
    pub fn new(init: InitSystem) -> Self {
        Self { init }
    }

    /// Auto-detect and construct — no need to pass InitSystem explicitly.
    pub fn detect() -> Self {
        Self { init: InitSystem::detect() }
    }

    /// Notify the supervisor that the daemon is ready to handle requests.
    pub fn ready(&self) {
        // Try sd_notify READY=1 (works for systemd and any supervisor with
        // NOTIFY_SOCKET set, e.g. s6-notifyoncheck).
        if self.init.supports_notify_socket() {
            if let Err(e) = sd_notify("READY=1\n") {
                tracing::warn!("sd_notify READY=1 failed: {}", e);
            } else {
                debug!("notified supervisor: READY=1");
                return;
            }
        }

        // s6 READY_FD fallback: write '\n' to fd $READY_FD.
        if let Ok(fd_str) = std::env::var("READY_FD") {
            if let Ok(fd) = fd_str.parse::<i32>() {
                // SAFETY: fd is an integer from the environment; write is atomic.
                let rc = unsafe { libc::write(fd, b"\n".as_ptr() as *const _, 1) };
                if rc == 1 {
                    debug!("notified supervisor: READY_FD={}", fd);
                    return;
                }
            }
        }

        // runit and others: no-op (daemon is considered ready when running).
        debug!("no supervisor notification needed for {:?}", self.init);
    }

    /// Notify the supervisor that we are stopping (sd_notify STOPPING=1).
    pub fn stopping(&self) {
        if self.init.supports_notify_socket() {
            let _ = sd_notify("STOPPING=1\n");
        }
    }

    /// Send a status string (sd_notify STATUS=...).
    pub fn status(&self, msg: &str) {
        if self.init.supports_notify_socket() {
            let _ = sd_notify(&format!("STATUS={}\n", msg));
        }
    }
}

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
