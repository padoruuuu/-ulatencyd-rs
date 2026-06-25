//! ulatencyctl — command-line client for ulatencyd-rs.
//!
//! Communicates with the daemon over D-Bus (system bus).
//!
//! Usage:
//!   ulatencyctl status
//!   ulatencyctl list
//!   ulatencyctl info <pid>
//!   ulatencyctl pressure
//!   ulatencyctl reload
//!   ulatencyctl set-cgroup <pid> <cgroup>
//!   ulatencyctl set-foreground <pid>
//!   ulatencyctl watch-signals

use std::collections::HashMap;
use anyhow::Result;
use clap::{Parser, Subcommand};
use libc;

const DBUS_DEST: &str  = "org.ulatencyd.Ulatencyd1";
const DBUS_PATH: &str  = "/org/ulatencyd/Ulatencyd1";
const DBUS_IFACE: &str = "org.ulatencyd.Ulatencyd1";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name    = "ulatencyctl",
    version,
    about   = "Control and query ulatencyd-rs",
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show daemon status summary.
    Status,
    /// List all managed processes.
    List,
    /// Show details for a specific PID.
    Info { pid: u32 },
    /// Show current system pressure (PSI).
    Pressure,
    /// Reload rules from disk.
    Reload,
    /// Move a PID to a cgroup tier (rt|interactive|system|background|idle|swapstorm).
    SetCgroup { pid: u32, cgroup: String },
    /// Notify the daemon of the current foreground process.
    SetForeground { pid: u32 },
    /// Subscribe to D-Bus signals and print them.
    WatchSignals,
    /// Run a command under a specific cgroup tier and optional scheduling policy.
    /// Example: ulatencyctl run background -- make -j8
    Run {
        /// Cgroup tier: rt|interactive|system|background|idle|swapstorm
        tier: String,
        /// Optional nice level (-20..19)
        #[arg(long)]
        nice: Option<i8>,
        /// Optional scheduling policy: normal|batch|idle|fifo|rr
        #[arg(long)]
        sched: Option<String>,
        /// Command and arguments to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .with_target(false)
        .init();

    let args = Args::parse();

    let conn = zbus::Connection::system().await
        .map_err(|e| anyhow::anyhow!("Cannot connect to system D-Bus: {}\nIs ulatencyd running?", e))?;

    let proxy = zbus::Proxy::new(
        &conn,
        DBUS_DEST,
        DBUS_PATH,
        DBUS_IFACE,
    ).await?;

    match args.cmd {
        Cmd::Status        => cmd_status(&proxy).await?,
        Cmd::List          => cmd_list(&proxy).await?,
        Cmd::Info { pid }  => cmd_info(&proxy, pid).await?,
        Cmd::Pressure      => cmd_pressure(&proxy).await?,
        Cmd::Reload        => cmd_reload(&proxy).await?,
        Cmd::SetCgroup { pid, cgroup } => cmd_set_cgroup(&proxy, pid, &cgroup).await?,
        Cmd::SetForeground { pid }     => cmd_set_foreground(&proxy, pid).await?,
        Cmd::WatchSignals  => cmd_watch_signals(&conn).await?,
        Cmd::Run { tier, nice, sched, command } => cmd_run(&conn, &tier, nice, sched, command).await?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

async fn cmd_status(proxy: &zbus::Proxy<'_>) -> Result<()> {
    let status: HashMap<String, String> = proxy
        .call("GetDaemonStatus", &())
        .await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;

    println!("ulatencyd status");
    println!("  version:       {}", status.get("version").map_or("?", |s| s));
    println!("  mode:          {}", status.get("mode").map_or("?", |s| s));
    println!("  processes:     {}", status.get("process_count").map_or("?", |s| s));
    println!("  uptime (secs): {}", status.get("uptime_secs").map_or("?", |s| s));
    Ok(())
}

async fn cmd_list(proxy: &zbus::Proxy<'_>) -> Result<()> {
    let procs: Vec<(u32, String, String)> = proxy
        .call("ListManagedProcesses", &())
        .await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;

    if procs.is_empty() {
        println!("No managed processes.");
        return Ok(());
    }

    println!("{:<8}  {:<20}  {}", "PID", "CGROUP", "RULE");
    for (pid, cgroup, rule) in &procs {
        println!("{:<8}  {:<20}  {}", pid, cgroup, rule);
    }
    println!("\n{} process(es) total", procs.len());
    Ok(())
}

async fn cmd_info(proxy: &zbus::Proxy<'_>, pid: u32) -> Result<()> {
    let info: HashMap<String, String> = proxy
        .call("GetProcessInfo", &(pid,))
        .await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;

    if info.is_empty() {
        eprintln!("pid {} is not managed (or does not exist)", pid);
        std::process::exit(1);
    }

    for (k, v) in &info {
        println!("  {}: {}", k, v);
    }
    Ok(())
}

async fn cmd_pressure(proxy: &zbus::Proxy<'_>) -> Result<()> {
    let metrics: HashMap<String, f64> = proxy
        .call("GetSystemPressure", &())
        .await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;

    println!("PSI pressure metrics (10-second avg):");
    println!("  memory.some:  {:.2}%", metrics.get("memory_some_avg10").copied().unwrap_or(0.0));
    println!("  memory.full:  {:.2}%", metrics.get("memory_full_avg10").copied().unwrap_or(0.0));
    println!("  io.some:      {:.2}%", metrics.get("io_some_avg10").copied().unwrap_or(0.0));
    println!("  io.full:      {:.2}%", metrics.get("io_full_avg10").copied().unwrap_or(0.0));
    println!("  cpu.some:     {:.2}%", metrics.get("cpu_some_avg10").copied().unwrap_or(0.0));
    Ok(())
}

async fn cmd_reload(proxy: &zbus::Proxy<'_>) -> Result<()> {
    let ok: bool = proxy
        .call("ReloadRules", &())
        .await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;

    if ok {
        println!("Rules reloaded successfully.");
    } else {
        eprintln!("Reload failed (check daemon logs).");
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_set_cgroup(proxy: &zbus::Proxy<'_>, pid: u32, cgroup: &str) -> Result<()> {
    let ok: bool = proxy
        .call("SetProcessCgroup", &(pid, cgroup))
        .await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;

    if ok {
        println!("pid {} moved to cgroup/{}", pid, cgroup);
    } else {
        eprintln!("Failed to move pid {} to cgroup/{}", pid, cgroup);
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_set_foreground(proxy: &zbus::Proxy<'_>, pid: u32) -> Result<()> {
    proxy
        .call::<_, (u32,), ()>("SetForegroundProcess", &(pid,))
        .await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;
    println!("foreground process set to pid {}", pid);
    Ok(())
}

async fn cmd_run(
    conn:    &zbus::Connection,
    tier:    &str,
    nice:    Option<i8>,
    sched:   Option<String>,
    command: Vec<String>,
) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let valid_tiers = ["rt","interactive","system","background","idle","swapstorm"];
    if !valid_tiers.contains(&tier) {
        anyhow::bail!("unknown tier {:?}. Valid: {}", tier, valid_tiers.join("|"));
    }
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    // Ask the daemon to move OUR pid into the target tier first, then exec.
    // The child inherits our cgroup membership.
    let our_pid = std::process::id();
    let proxy = zbus::Proxy::new(conn, DBUS_DEST, DBUS_PATH, DBUS_IFACE).await?;
    let _: bool = proxy.call("SetProcessCgroup", &(our_pid, tier)).await
        .map_err(|e| anyhow::anyhow!("D-Bus call failed: {}", e))?;

    // Apply nice if requested.
    if let Some(n) = nice {
        let rc = unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, n as libc::c_int)
        };
        if rc != 0 { eprintln!("warning: could not set nice={}", n); }
    }

    // Apply sched policy if requested.
    if let Some(ref policy) = sched {
        let (pol, prio) = match policy.as_str() {
            "normal" | "other" => (libc::SCHED_NORMAL, 0i32),
            "batch"            => (libc::SCHED_BATCH,  0),
            "idle"             => (libc::SCHED_IDLE,   0),
            "fifo"             => (libc::SCHED_FIFO,   1),
            "rr"               => (libc::SCHED_RR,     1),
            other => anyhow::bail!("unknown sched policy {:?}", other),
        };
        let param = libc::sched_param { sched_priority: prio };
        let rc = unsafe { libc::sched_setscheduler(0, pol, &param) };
        if rc != 0 { eprintln!("warning: could not set sched policy={}", policy); }
    }

    // exec into the command — replaces this process.
    let err = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();

    anyhow::bail!("exec failed: {}", err)
}

async fn cmd_watch_signals(conn: &zbus::Connection) -> Result<()> {
    use zbus::MessageStream;
    use futures_util::StreamExt as _;

    println!("Watching D-Bus signals (Ctrl-C to exit)...");

    let rule = format!(
        "type='signal',sender='{}',path='{}'",
        DBUS_DEST, DBUS_PATH
    );

    let dbus_proxy = zbus::fdo::DBusProxy::new(conn).await?;
    dbus_proxy.add_match_rule(rule.as_str().try_into()?).await?;

    let mut stream = MessageStream::from(conn);
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(m) => {
                if m.message_type() == zbus::message::Type::Signal {
                    let member = m.header()
                        .member()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "<unknown>".into());
                    println!("[signal] {}", member);
                }
            }
            Err(e) => eprintln!("stream error: {}", e),
        }
    }
    Ok(())
}
