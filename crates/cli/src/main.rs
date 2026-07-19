//! ulatencyctl — command-line client for ulatencyd-rs.
//!
//! Communicates with the daemon over a local varlink Unix socket
//! (org.ulatencyd.Control — see crates/control-proto/) instead of D-Bus.
//!
//! Usage:
//!   ulatencyctl status
//!   ulatencyctl list
//!   ulatencyctl info <pid>
//!   ulatencyctl pressure
//!   ulatencyctl reload
//!   ulatencyctl set-cgroup <pid> <cgroup>
//!   ulatencyctl set-foreground <pid>
//!   ulatencyctl run <tier> [--nice N] [--sched POLICY] -- <command>...
//!
//! Note: the old `watch-signals` subcommand is gone — varlink has no
//! broadcast-signal equivalent to D-Bus signals, so there is nothing to
//! subscribe to. `ulatencyctl status`/`list` can be polled instead.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

const DEFAULT_SOCKET: &str = "unix:/run/ulatencyd/control.sock";

#[allow(non_camel_case_types, dead_code, non_snake_case)]
mod control_proto {
    include!(concat!(env!("OUT_DIR"), "/org.ulatencyd.Control.rs"));
}

use control_proto::VarlinkClientInterface;

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
    /// varlink address of the control socket.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: String,

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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .with_target(false)
        .init();

    let args = Args::parse();

    let connection = varlink::Connection::with_address(&args.socket)
        .map_err(|_| diagnose_connect_failure(&args.socket))?;

    let mut client = control_proto::VarlinkClient::new(connection);

    match args.cmd {
        Cmd::Status                     => cmd_status(&mut client)?,
        Cmd::List                       => cmd_list(&mut client)?,
        Cmd::Info { pid }               => cmd_info(&mut client, pid)?,
        Cmd::Pressure                   => cmd_pressure(&mut client)?,
        Cmd::Reload                     => cmd_reload(&mut client)?,
        Cmd::SetCgroup { pid, cgroup }  => cmd_set_cgroup(&mut client, pid, &cgroup)?,
        Cmd::SetForeground { pid }      => cmd_set_foreground(&mut client, pid)?,
        Cmd::Run { tier, nice, sched, command } => {
            cmd_run(&mut client, &tier, nice, sched, command)?
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Connection diagnostics
// ---------------------------------------------------------------------------

/// varlink's own `ErrorKind::Io(_)` `Display` impl just prints the literal
/// string `"IO error"` — it doesn't forward the underlying `io::Error`'s
/// message, so `Connection::with_address`'s error alone can't tell a user
/// whether the socket is missing, they lack permission, or it's a stale
/// socket from a crashed daemon. This re-diagnoses the failure directly
/// against the filesystem/socket to give an actionable message.
fn diagnose_connect_failure(socket_addr: &str) -> anyhow::Error {
    let path = socket_addr.strip_prefix("unix:").unwrap_or(socket_addr);

    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::anyhow!(
            "control socket {} does not exist.\n\n\
             Is ulatencyd running? Check with e.g.:\n  \
             systemctl status ulatencyd\n\
             (or the runit/s6/OpenRC equivalent).\n\n\
             If it's not running, start it and check its logs for a startup \
             error, e.g.:\n  journalctl -u ulatencyd -e",
            path
        ),
        // EACCES here means we couldn't even stat() the path — i.e. we lack
        // search (x) permission on its *parent* directory. The socket file
        // itself might be fine; ls -l on the socket path won't work either
        // (same traversal problem), so point at the parent dir instead.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let parent = std::path::Path::new(path)
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| ".".to_string());
            anyhow::anyhow!(
                "permission denied reaching {path}.\n\n\
                 You don't have search access to {parent} — you're likely not \
                 a member of the group that owns it. Check:\n  \
                 ls -ld {parent}\n\
                 against your own groups:\n  \
                 groups\n\n\
                 If you need to be added:\n  \
                 sudo usermod -aG <group> $USER\n\
                 then log out and back in (or run `newgrp <group>`) — group \
                 membership changes don't apply to an already-running shell \
                 session.",
                path = path, parent = parent
            )
        }
        Err(e) => anyhow::anyhow!("cannot stat control socket {}: {}", path, e),
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                return anyhow::anyhow!(
                    "{} exists but is not a socket — something else is using that path.",
                    path
                );
            }
            // It IS a socket on disk. Try a raw connect to surface the real
            // errno instead of varlink's swallowed one.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => anyhow::anyhow!(
                    "connected to {} at the raw socket level, but the varlink \
                     handshake failed. Is something other than ulatencyd \
                     listening on this path?",
                    path
                ),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                        "permission denied connecting to {p}.\n\n\
                         You're likely not a member of the socket's group. Check:\n  \
                         ls -l {p}\n\
                         against your own groups:\n  \
                         groups\n\n\
                         If you need to be added:\n  \
                         sudo usermod -aG <group> $USER\n\
                         then log out and back in (or run `newgrp <group>`) — \
                         group membership changes don't apply to an \
                         already-running shell session.",
                        p = path
                    ),
                    std::io::ErrorKind::ConnectionRefused => anyhow::anyhow!(
                        "connection refused at {}.\n\n\
                         This usually means a stale socket file was left behind \
                         by a crashed ulatencyd instance — nothing is listening \
                         on it anymore. Restart ulatencyd (it removes and \
                         recreates the socket on startup); if the file is still \
                         there afterwards, check its logs for why it isn't \
                         reaching that point.",
                        path
                    ),
                    _ => anyhow::anyhow!("cannot connect to {}: {}", path, e),
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn cmd_status(client: &mut control_proto::VarlinkClient) -> Result<()> {
    let reply = client
        .status()
        .call()
        .map_err(|e| anyhow::anyhow!("control call failed: {}", e))?;

    println!("ulatencyd status");
    println!("  version:       {}", reply.version);
    println!("  mode:          {}", reply.mode);
    println!("  processes:     {}", reply.process_count);
    println!("  uptime (secs): {}", reply.uptime_secs);
    Ok(())
}

fn cmd_list(client: &mut control_proto::VarlinkClient) -> Result<()> {
    let reply = client
        .list_managed_processes()
        .call()
        .map_err(|e| anyhow::anyhow!("control call failed: {}", e))?;

    if reply.processes.is_empty() {
        println!("No managed processes.");
        return Ok(());
    }

    println!("{:<8}  {:<20}  {}", "PID", "CGROUP", "RULE");
    for p in &reply.processes {
        println!("{:<8}  {:<20}  {}", p.pid, p.cgroup, p.rule);
    }
    println!("\n{} process(es) total", reply.processes.len());
    Ok(())
}

fn cmd_info(client: &mut control_proto::VarlinkClient, pid: u32) -> Result<()> {
    match client.get_process_info(pid as i64).call() {
        Ok(reply) => {
            let p = reply.process;
            println!("  pid:    {}", p.pid);
            println!("  comm:   {}", p.comm);
            println!("  cgroup: {}", p.cgroup);
            println!("  rule:   {}", p.rule);
            Ok(())
        }
        Err(control_proto::Error(control_proto::ErrorKind::UnknownPid(_), ..)) => {
            eprintln!("pid {} is not managed (or does not exist)", pid);
            std::process::exit(1);
        }
        Err(e) => Err(anyhow::anyhow!("control call failed: {}", e)),
    }
}

fn cmd_pressure(client: &mut control_proto::VarlinkClient) -> Result<()> {
    let reply = client
        .get_system_pressure()
        .call()
        .map_err(|e| anyhow::anyhow!("control call failed: {}", e))?;

    println!("PSI pressure metrics (10-second avg):");
    println!("  memory.some:  {:.2}%", reply.memory.some_avg10);
    println!("  memory.full:  {:.2}%", reply.memory.full_avg10);
    println!("  io.some:      {:.2}%", reply.io.some_avg10);
    println!("  io.full:      {:.2}%", reply.io.full_avg10);
    println!("  cpu.some:     {:.2}%", reply.cpu_some_avg10);
    Ok(())
}

fn cmd_reload(client: &mut control_proto::VarlinkClient) -> Result<()> {
    client
        .reload_rules()
        .call()
        .map_err(|e| anyhow::anyhow!("control call failed: {}", e))?;
    println!("Rules reloaded successfully.");
    Ok(())
}

fn cmd_set_cgroup(client: &mut control_proto::VarlinkClient, pid: u32, cgroup: &str) -> Result<()> {
    client
        .set_process_cgroup(pid as i64, cgroup.to_string())
        .call()
        .map_err(|e| anyhow::anyhow!("control call failed: {}", e))?;
    println!("pid {} moved to cgroup/{}", pid, cgroup);
    Ok(())
}

fn cmd_set_foreground(client: &mut control_proto::VarlinkClient, pid: u32) -> Result<()> {
    client
        .set_foreground_process(pid as i64)
        .call()
        .map_err(|e| anyhow::anyhow!("control call failed: {}", e))?;
    println!("foreground process set to pid {}", pid);
    Ok(())
}

fn cmd_run(
    client:  &mut control_proto::VarlinkClient,
    tier:    &str,
    nice:    Option<i8>,
    sched:   Option<String>,
    command: Vec<String>,
) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let valid_tiers = ["rt", "interactive", "system", "background", "idle", "swapstorm"];
    if !valid_tiers.contains(&tier) {
        anyhow::bail!("unknown tier {:?}. Valid: {}", tier, valid_tiers.join("|"));
    }
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    // Ask the daemon to move OUR pid into the target tier first, then exec.
    // The child inherits our cgroup membership.
    let our_pid = std::process::id();
    client
        .set_process_cgroup(our_pid as i64, tier.to_string())
        .call()
        .map_err(|e| anyhow::anyhow!("control call failed: {}", e))?;

    // Apply nice if requested.
    if let Some(n) = nice {
        let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, n as libc::c_int) };
        if rc != 0 {
            eprintln!("warning: could not set nice={}", n);
        }
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
        if rc != 0 {
            eprintln!("warning: could not set sched policy={}", policy);
        }
    }

    // exec into the command — replaces this process.
    let err = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();

    Err(err).context("exec failed")
}
