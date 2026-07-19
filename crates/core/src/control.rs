//! Control socket for ulatencyd-rs, served over a local varlink Unix socket
//! instead of D-Bus.
//!
//! Interface: org.ulatencyd.Control  (see crates/control-proto/)
//! Socket:    /run/ulatencyd/control.sock (configurable)
//!
//! Access control is via Unix group membership on the socket and its parent
//! directory (see `start_control_service` / §5 of the design notes), not
//! polkit — polkit-gated D-Bus access lives only in the optional
//! `contrib/system76-compat-shim` companion binary now.

use std::collections::HashMap;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use psi::SystemPressure;

// ---------------------------------------------------------------------------
// Generated varlink bindings (async server mode)
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types, dead_code, non_snake_case)]
pub mod control_proto {
    include!(concat!(env!("OUT_DIR"), "/org.ulatencyd.Control.rs"));
}

use control_proto::{
    Call_GetProcessInfo, Call_GetSystemPressure, Call_ListManagedProcesses, Call_ReloadRules,
    Call_SetForegroundProcess, Call_SetProcessCgroup, Call_Status, PressureMetrics,
    ProcessRecord, VarlinkInterface,
};

// ---------------------------------------------------------------------------
// Shared daemon state visible to the control layer
// ---------------------------------------------------------------------------

/// Control-socket-visible snapshot of a managed process.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub comm: String,
    pub cgroup: String,
    pub rule_name: String,
}

/// Commands the control layer sends to the main event loop.
/// (Renamed from `DbusCommand`.)
#[derive(Debug)]
pub enum ControlCommand {
    SetForegroundProcess(u32),
    SetProcessCgroup { pid: u32, cgroup: String },
    ReloadRules,
}

/// Shared state between the control interface and the main loop.
pub struct SharedState {
    pub managed: HashMap<u32, ProcessEntry>,
    pub pressure: SystemPressure,
    pub mode: String,
    pub uptime: std::time::Instant,
    pub version: String,
    pub foreground_pid: Option<u32>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            managed: HashMap::new(),
            pressure: SystemPressure::default(),
            mode: "normal".into(),
            uptime: std::time::Instant::now(),
            version: format!("ulatencyd-rs {}", env!("CARGO_PKG_VERSION")),
            foreground_pid: None,
        }
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// varlink interface implementation
// ---------------------------------------------------------------------------

struct ControlInterface {
    state:  Arc<Mutex<SharedState>>,
    cmd_tx: mpsc::Sender<ControlCommand>,
}

fn to_pressure_metrics(m: &psi::PsiMetrics) -> PressureMetrics {
    PressureMetrics {
        some_avg10:  m.some_avg10  as f64,
        some_avg60:  m.some_avg60  as f64,
        some_avg300: m.some_avg300 as f64,
        full_avg10:  m.full_avg10  as f64,
        full_avg60:  m.full_avg60  as f64,
        full_avg300: m.full_avg300 as f64,
    }
}

#[async_trait::async_trait]
impl VarlinkInterface for ControlInterface {
    async fn status(&self, call: &mut dyn Call_Status) -> varlink::Result<()> {
        let s = self.state.lock().await;
        call.reply(
            s.version.clone(),
            s.mode.clone(),
            s.managed.len() as i64,
            s.uptime.elapsed().as_secs() as i64,
        )
    }

    async fn list_managed_processes(
        &self,
        call: &mut dyn Call_ListManagedProcesses,
    ) -> varlink::Result<()> {
        let s = self.state.lock().await;
        let processes = s
            .managed
            .values()
            .map(|e| ProcessRecord {
                pid:    e.pid as i64,
                comm:   e.comm.clone(),
                cgroup: e.cgroup.clone(),
                rule:   e.rule_name.clone(),
            })
            .collect();
        call.reply(processes)
    }

    async fn get_process_info(
        &self,
        call: &mut dyn Call_GetProcessInfo,
        pid: i64,
    ) -> varlink::Result<()> {
        let s = self.state.lock().await;
        match s.managed.get(&(pid as u32)) {
            Some(e) => call.reply(ProcessRecord {
                pid:    e.pid as i64,
                comm:   e.comm.clone(),
                cgroup: e.cgroup.clone(),
                rule:   e.rule_name.clone(),
            }),
            None => call.reply_unknown_pid(pid),
        }
    }

    async fn get_system_pressure(
        &self,
        call: &mut dyn Call_GetSystemPressure,
    ) -> varlink::Result<()> {
        let p = self.state.lock().await.pressure;
        call.reply(
            to_pressure_metrics(&p.memory),
            to_pressure_metrics(&p.io),
            p.cpu.some_avg10 as f64,
        )
    }

    async fn reload_rules(&self, call: &mut dyn Call_ReloadRules) -> varlink::Result<()> {
        // A successful reply means "accepted onto the channel" — matching
        // prior D-Bus semantics exactly, not "operation completed". The
        // main event loop's tokio::select! consumes this unchanged.
        let _ = self.cmd_tx.send(ControlCommand::ReloadRules).await;
        call.reply()
    }

    async fn set_process_cgroup(
        &self,
        call: &mut dyn Call_SetProcessCgroup,
        pid: i64,
        cgroup: String,
    ) -> varlink::Result<()> {
        let _ = self
            .cmd_tx
            .send(ControlCommand::SetProcessCgroup { pid: pid as u32, cgroup })
            .await;
        call.reply()
    }

    async fn set_foreground_process(
        &self,
        call: &mut dyn Call_SetForegroundProcess,
        pid: i64,
    ) -> varlink::Result<()> {
        let _ = self
            .cmd_tx
            .send(ControlCommand::SetForegroundProcess(pid as u32))
            .await;
        call.reply()
    }
}

// ---------------------------------------------------------------------------
// Socket permissions (§5)
// ---------------------------------------------------------------------------

/// Resolve a group name to a gid via the reentrant `getgrnam_r` (plain
/// `getgrnam` is not guaranteed thread-safe), matching the project's
/// existing style of reaching for raw libc for this kind of thing.
fn resolve_gid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0i8; 4096];
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();

    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };

    if rc == 0 && !result.is_null() {
        Some(grp.gr_gid)
    } else {
        None
    }
}

fn chown_path(path: &Path, gid: u32) {
    use std::os::unix::ffi::OsStrExt;
    let cpath = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        Ok(c)  => c,
        Err(_) => return,
    };
    // uid unchanged (-1), gid set to the control group.
    let rc = unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        warn!("chown {} to gid {}: errno {}", path.display(), gid, unsafe {
            *libc::__errno_location()
        });
    }
}

fn chmod_path(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!("chmod {} to {:o}: {}", path.display(), mode, e);
    }
}

/// Remove a stale socket file left over from a previous crashed run.
/// Only unlinks it if it's actually a socket — never blindly unlinks
/// whatever happens to be at that path.
fn remove_stale_socket(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?;
            debug!("removed stale control socket {}", path.display());
            Ok(())
        }
        Ok(_) => {
            anyhow::bail!(
                "{} exists and is not a socket — refusing to remove it",
                path.display()
            );
        }
        Err(_) => Ok(()), // nothing there
    }
}

/// Set up the parent directory (root:<group> 0750) and, once the listener
/// has bound the socket, fix its ownership/mode (root:<group> 0660) too.
/// The directory-level restriction is the primary defense — only members of
/// `group` can even traverse the directory to reach the socket — so the
/// short polling window for the socket file itself is not a real gap.
fn prepare_socket_dir(socket_path: &Path, group: &str) -> Result<u32> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("control socket path has no parent directory"))?;

    std::fs::create_dir_all(parent)
        .with_context(|| format!("create {}", parent.display()))?;

    let gid = resolve_gid(group).unwrap_or_else(|| {
        warn!(
            "control_socket.group {:?} not found; leaving parent dir group unchanged",
            group
        );
        // Fall back to the process's own gid so chmod still succeeds even
        // when the configured group doesn't exist on this system.
        unsafe { libc::getgid() }
    });

    chown_path(parent, gid);
    chmod_path(parent, 0o750);

    remove_stale_socket(socket_path)?;

    Ok(gid)
}

/// Poll for the socket file to appear on disk (varlink's listener creates it
/// synchronously right after bind, but we don't get a callback), then
/// chown/chmod it. Budget: ~1s at 20ms intervals.
fn spawn_socket_permission_fixup(socket_path: PathBuf, gid: u32) {
    tokio::spawn(async move {
        for _ in 0..50 {
            if socket_path.exists() {
                chown_path(&socket_path, gid);
                chmod_path(&socket_path, 0o660);
                debug!("control socket permissions set: {}", socket_path.display());
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        warn!(
            "control socket {} did not appear within 1s; permissions not set",
            socket_path.display()
        );
    });
}

// ---------------------------------------------------------------------------
// Service startup
// ---------------------------------------------------------------------------

/// Start the control service on a Unix socket.
///
/// Returns a command receiver for the main event loop to consume, plus a
/// clone of the sender — used by `main.rs` to wire SIGHUP directly onto the
/// same channel (`ControlCommand::ReloadRules`), in-process, with no socket
/// round trip.
pub async fn start_control_service(
    state:       Arc<Mutex<SharedState>>,
    socket_path: &Path,
    group:       &str,
) -> Result<(mpsc::Receiver<ControlCommand>, mpsc::Sender<ControlCommand>)> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<ControlCommand>(64);

    let gid = prepare_socket_dir(socket_path, group)?;
    spawn_socket_permission_fixup(socket_path.to_path_buf(), gid);

    let iface = ControlInterface {
        state: Arc::clone(&state),
        cmd_tx: cmd_tx.clone(),
    };

    let handler = control_proto::new(Arc::new(iface));
    let address = format!("unix:{}", socket_path.display());

    tokio::spawn(async move {
        if let Err(e) = varlink::listen_async(
            Arc::new(handler),
            &address,
            &varlink::ListenAsyncConfig::default(),
        )
        .await
        {
            tracing::error!("control socket listener exited: {}", e);
        }
    });

    info!("control socket listening on {}", socket_path.display());
    Ok((cmd_rx, cmd_tx))
}
