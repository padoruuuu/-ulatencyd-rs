//! Diagnostic logging to ~/ulatencyd-diagnostic.txt.
//!
//! Enable with: ulatencyd --diagnostic
//!
//! Every classification decision, cgroup write, proc event, PSI reading,
//! and rule match is recorded with microsecond timestamps.
//! Use for bug reports and development only — has I/O overhead.

use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{mpsc, oneshot};

// Channel carries either a log line (Some) or a flush request (None = shutdown).
static DIAG_TX: OnceLock<Option<mpsc::UnboundedSender<DiagMsg>>> = OnceLock::new();

enum DiagMsg {
    Line(String),
    Flush(oneshot::Sender<()>),
}

/// Initialise the diagnostic log. Call once at startup when --diagnostic is set.
pub async fn init_diagnostic_log() -> std::io::Result<PathBuf> {
    // When running as root (systemd service), use the real user's home
    // via SUDO_USER or DBUS_SESSION_BUS_ADDRESS owner, falling back to /tmp.
    let home = std::env::var("SUDO_USER")
        .ok()
        .and_then(|u| {
            // Look up the user's home from /etc/passwd.
            std::fs::read_to_string("/etc/passwd").ok().and_then(|pw| {
                pw.lines()
                    .find(|l| l.starts_with(&format!("{}:", u)))
                    .and_then(|l| l.split(':').nth(5))
                    .map(|h| h.to_string())
            })
        })
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_else(|| "/tmp".to_string());
    let path = PathBuf::from(&home).join("ulatencyd-diagnostic.txt");

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await?;

    let (tx, mut rx) = mpsc::unbounded_channel::<DiagMsg>();

    let header = format!(
        "ulatencyd-rs diagnostic log\nStarted: {:?}\n{}\n\n",
        std::time::SystemTime::now(),
        "=".repeat(60),
    );
    file.write_all(header.as_bytes()).await?;

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                DiagMsg::Line(line) => {
                    let _ = file.write_all(line.as_bytes()).await;
                }
                DiagMsg::Flush(reply) => {
                    let _ = file.flush().await;
                    let _ = reply.send(());
                }
            }
        }
        let _ = file.flush().await;
    });

    let _ = DIAG_TX.set(Some(tx));
    Ok(path)
}

/// Call at clean shutdown to flush all buffered lines to disk before exit.
pub async fn flush_diagnostic_log() {
    let Some(Some(tx)) = DIAG_TX.get() else { return; };
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = tx.send(DiagMsg::Flush(reply_tx));
    // Wait up to 2s for the flush to complete.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reply_rx,
    ).await;
}

/// Call when --diagnostic is NOT set.
pub fn disable_diagnostic_log() {
    let _ = DIAG_TX.set(None);
}

/// Write a single diagnostic entry. No-op when diagnostics are disabled.
pub fn write_diag(category: &str, detail: String) {
    let Some(Some(tx)) = DIAG_TX.get() else { return; };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let line = format!(
        "[{:>10}.{:06}] {:<12} {}\n",
        now.as_secs(),
        now.subsec_micros(),
        category,
        detail,
    );
    let _ = tx.send(DiagMsg::Line(line));
}

/// Write a section separator.
pub fn diag_section(title: &str) {
    write_diag("---", format!("=== {} ===", title));
}

/// Convenience macro — write_diag with format args.
macro_rules! diag {
    ($cat:expr, $($arg:tt)*) => {
        $crate::diag::write_diag($cat, format!($($arg)*))
    };
}
pub(crate) use diag;
