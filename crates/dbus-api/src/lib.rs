//! D-Bus service for ulatencyd-rs.
//!
//! Interface: org.ulatencyd.Ulatencyd1
//! Object:    /org/ulatencyd/Ulatencyd1
//!
//! Also exposes com.system76.Scheduler.SetForegroundProcess for compositor compat.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use zbus::{interface, SignalContext};

use psi::SystemPressure;

// ---------------------------------------------------------------------------
// Polkit helper
// ---------------------------------------------------------------------------

/// Check a polkit action for the caller identified by `sender`.
/// Returns Ok(true) if authorized, Ok(false) if denied, Err on comms failure.
async fn polkit_check(
    conn:      &zbus::Connection,
    sender:    &str,
    action_id: &str,
) -> Result<bool, zbus::Error> {
    // org.freedesktop.PolicyKit1.Authority.CheckAuthorization
    let proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    ).await?;

    // Subject: ("system-bus-name", {"name": sender})
    let mut subject_details: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
    subject_details.insert("name", zbus::zvariant::Value::new(sender));
    let subject = ("system-bus-name", subject_details);

    // flags=0 (no interaction), cancellation_id=""
    let result: (bool, bool, HashMap<String, String>) = proxy
        .call("CheckAuthorization", &(subject, action_id, HashMap::<&str, &str>::new(), 0u32, ""))
        .await?;

    // result.0 = is_authorized
    Ok(result.0)
}

// ---------------------------------------------------------------------------
// Shared daemon state visible to the D-Bus layer
// ---------------------------------------------------------------------------

/// D-Bus-visible snapshot of a managed process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessEntry {
    pub pid:       u32,
    pub comm:      String,
    pub cgroup:    String,
    pub rule_name: String,
}

/// Commands the D-Bus layer sends to the main event loop.
#[derive(Debug)]
pub enum DbusCommand {
    SetForegroundProcess(u32),
    SetProcessCgroup { pid: u32, cgroup: String },
    ReloadRules,
}

/// Shared state between the D-Bus interface and the main loop.
pub struct SharedState {
    pub managed:  HashMap<u32, ProcessEntry>,
    pub pressure: SystemPressure,
    pub mode:     String,
    pub uptime:   std::time::Instant,
    pub version:  String,
    pub foreground_pid: Option<u32>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            managed:        HashMap::new(),
            pressure:       SystemPressure::default(),
            mode:           "normal".into(),
            uptime:         std::time::Instant::now(),
            version:        format!("ulatencyd-rs {}", env!("CARGO_PKG_VERSION")),
            foreground_pid: None,
        }
    }
}

// ---------------------------------------------------------------------------
// zbus interface implementation
// ---------------------------------------------------------------------------

pub struct UlatencydInterface {
    pub state: Arc<Mutex<SharedState>>,
    pub cmd_tx: mpsc::Sender<DbusCommand>,
}

#[interface(name = "org.ulatencyd.Ulatencyd1")]
impl UlatencydInterface {
    // --- Methods ---

    async fn get_daemon_status(&self) -> HashMap<String, String> {
        let s = self.state.lock().await;
        let mut map = HashMap::new();
        map.insert("version".into(), s.version.clone());
        map.insert("mode".into(), s.mode.clone());
        map.insert("process_count".into(), s.managed.len().to_string());
        map.insert(
            "uptime_secs".into(),
            s.uptime.elapsed().as_secs().to_string(),
        );
        map
    }

    async fn list_managed_processes(&self) -> Vec<(u32, String, String)> {
        self.state.lock().await
            .managed.values()
            .map(|e| (e.pid, e.cgroup.clone(), e.rule_name.clone()))
            .collect()
    }

    async fn get_process_info(&self, pid: u32) -> HashMap<String, String> {
        let s = self.state.lock().await;
        let mut map = HashMap::new();
        if let Some(e) = s.managed.get(&pid) {
            map.insert("pid".into(), pid.to_string());
            map.insert("comm".into(), e.comm.clone());
            map.insert("cgroup".into(), e.cgroup.clone());
            map.insert("rule".into(), e.rule_name.clone());
        }
        map
    }

    async fn get_system_pressure(&self) -> HashMap<String, f64> {
        let p = self.state.lock().await.pressure;
        let mut m = HashMap::new();
        // Memory — some and full
        m.insert("memory_some_avg10".into(),  p.memory.some_avg10  as f64);
        m.insert("memory_some_avg60".into(),  p.memory.some_avg60  as f64);
        m.insert("memory_some_avg300".into(), p.memory.some_avg300 as f64);
        m.insert("memory_full_avg10".into(),  p.memory.full_avg10  as f64);
        m.insert("memory_full_avg60".into(),  p.memory.full_avg60  as f64);
        m.insert("memory_full_avg300".into(), p.memory.full_avg300 as f64);
        // I/O — some and full
        m.insert("io_some_avg10".into(),      p.io.some_avg10  as f64);
        m.insert("io_some_avg60".into(),      p.io.some_avg60  as f64);
        m.insert("io_some_avg300".into(),     p.io.some_avg300 as f64);
        m.insert("io_full_avg10".into(),      p.io.full_avg10  as f64);
        m.insert("io_full_avg60".into(),      p.io.full_avg60  as f64);
        m.insert("io_full_avg300".into(),     p.io.full_avg300 as f64);
        // CPU — some only.
        // NOTE: /proc/pressure/cpu does not have a 'full' line on most kernels
        // by design — CPU full stalls are not well-defined because there is
        // always at least one runnable task.  cpu.full_avg10 from the PSI
        // parser is 0.0; we omit it here to avoid misleading callers.
        m.insert("cpu_some_avg10".into(),     p.cpu.some_avg10 as f64);
        m
    }

    async fn reload_rules(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> bool {
        let sender = hdr.sender().map(|s| s.to_string()).unwrap_or_default();
        match polkit_check(conn, &sender, "rs.ulatencyd.reload-rules").await {
            Ok(true) => {}
            Ok(false) => { warn!("polkit denied reload-rules for {}", sender); return false; }
            Err(e)   => { warn!("polkit error: {}", e); return false; }
        }
        match self.cmd_tx.send(DbusCommand::ReloadRules).await {
            Ok(_) => true,
            Err(e) => { warn!("reload_rules: send error: {}", e); false }
        }
    }

    async fn set_process_cgroup(
        &self,
        pid: u32,
        cgroup: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> bool {
        let sender = hdr.sender().map(|s| s.to_string()).unwrap_or_default();
        match polkit_check(conn, &sender, "rs.ulatencyd.set-cgroup").await {
            Ok(true) => {}
            Ok(false) => { warn!("polkit denied set-cgroup for {}", sender); return false; }
            Err(e)   => { warn!("polkit error: {}", e); return false; }
        }
        match self.cmd_tx.send(DbusCommand::SetProcessCgroup { pid, cgroup }).await {
            Ok(_) => true,
            Err(e) => { warn!("set_process_cgroup: send error: {}", e); false }
        }
    }

    /// Called by compositors/WMs when focus changes (system76-scheduler compat).
    async fn set_foreground_process(
        &self,
        pid: u32,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) {
        let sender = hdr.sender().map(|s| s.to_string()).unwrap_or_default();
        match polkit_check(conn, &sender, "rs.ulatencyd.set-foreground").await {
            Ok(true) => {}
            Ok(false) => { warn!("polkit denied set-foreground for {}", sender); return; }
            Err(e)   => { warn!("polkit error (allowing anyway): {}", e); }
        }
        info!("D-Bus: SetForegroundProcess({})", pid);
        let _ = self.cmd_tx.send(DbusCommand::SetForegroundProcess(pid)).await;
    }

    // --- Signals ---

    #[zbus(signal)]
    async fn process_classified(
        ctx: &SignalContext<'_>,
        pid:    u32,
        cgroup: &str,
        rule:   &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn memory_pressure_changed(
        ctx:   &SignalContext<'_>,
        level: u32,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn fork_bomb_detected(
        ctx:   &SignalContext<'_>,
        ppid:  u32,
        count: u32,
    ) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Service startup
// ---------------------------------------------------------------------------

/// Start the D-Bus service on the system bus.
/// Returns the connection (must be kept alive) and a command receiver.
pub async fn start_dbus_service(
    state: Arc<Mutex<SharedState>>,
) -> anyhow::Result<(zbus::Connection, mpsc::Receiver<DbusCommand>)> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<DbusCommand>(64);

    let iface = UlatencydInterface {
        state: Arc::clone(&state),
        cmd_tx,
    };

    let conn = zbus::connection::Builder::system()?
        .name("org.ulatencyd.Ulatencyd1")?
        .serve_at("/org/ulatencyd/Ulatencyd1", iface)?
        .build()
        .await?;

    info!("D-Bus service registered on system bus");
    Ok((conn, cmd_rx))
}

/// Emit a ProcessClassified signal on an existing connection.
pub async fn emit_process_classified(
    conn:   &zbus::Connection,
    pid:    u32,
    cgroup: &str,
    rule:   &str,
) {
    let obj = conn.object_server();
    if let Ok(iface_ref) = obj
        .interface::<_, UlatencydInterface>("/org/ulatencyd/Ulatencyd1")
        .await
    {
        let ctx = iface_ref.signal_context();
        let _ = UlatencydInterface::process_classified(ctx, pid, cgroup, rule).await;
    }
}

/// Emit MemoryPressureChanged signal.
pub async fn emit_pressure_changed(conn: &zbus::Connection, level: u32) {
    let obj = conn.object_server();
    if let Ok(iface_ref) = obj
        .interface::<_, UlatencydInterface>("/org/ulatencyd/Ulatencyd1")
        .await
    {
        let ctx = iface_ref.signal_context();
        let _ = UlatencydInterface::memory_pressure_changed(ctx, level).await;
    }
}

/// Emit ForkBombDetected signal.
pub async fn emit_fork_bomb(conn: &zbus::Connection, ppid: u32, count: u32) {
    let obj = conn.object_server();
    if let Ok(iface_ref) = obj
        .interface::<_, UlatencydInterface>("/org/ulatencyd/Ulatencyd1")
        .await
    {
        let ctx = iface_ref.signal_context();
        let _ = UlatencydInterface::fork_bomb_detected(ctx, ppid, count).await;
    }
}
