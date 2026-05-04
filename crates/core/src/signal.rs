//! Unix signal handling via tokio.
//!
//! Provides a ShutdownToken (SIGTERM/SIGINT) and a SIGHUP reload channel.

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use tracing::info;

// ---------------------------------------------------------------------------
// ShutdownToken
// ---------------------------------------------------------------------------

/// A cloneable token that becomes ready when SIGTERM or SIGINT is received.
#[derive(Clone)]
pub struct ShutdownToken {
    rx: watch::Receiver<bool>,
}

impl ShutdownToken {
    /// Wait until shutdown is signalled.
    pub async fn wait(&mut self) {
        let _ = self.rx.wait_for(|&v| v).await;
    }
}

// ---------------------------------------------------------------------------
// Public initialiser
// ---------------------------------------------------------------------------

/// Spawn background tasks for SIGTERM, SIGINT, and SIGHUP.
///
/// Returns:
///   - `ShutdownToken` — becomes ready on SIGTERM or SIGINT
///   - `mpsc::Receiver<()>` — fires on SIGHUP (reload requests)
pub fn init_signals() -> (ShutdownToken, mpsc::Receiver<()>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (sighup_tx,   sighup_rx)   = mpsc::channel::<()>(4);

    // SIGTERM
    tokio::spawn({
        let tx = shutdown_tx.clone();
        async move {
            let mut sig = signal(SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
            sig.recv().await;
            info!("received SIGTERM");
            let _ = tx.send(true);
        }
    });

    // SIGINT
    tokio::spawn({
        let tx = shutdown_tx;
        async move {
            let mut sig = signal(SignalKind::interrupt())
                .expect("failed to register SIGINT handler");
            sig.recv().await;
            info!("received SIGINT");
            let _ = tx.send(true);
        }
    });

    // SIGHUP (reload)
    tokio::spawn(async move {
        let mut sig = signal(SignalKind::hangup())
            .expect("failed to register SIGHUP handler");
        loop {
            sig.recv().await;
            info!("received SIGHUP — reloading rules");
            if sighup_tx.send(()).await.is_err() {
                break;
            }
        }
    });

    (ShutdownToken { rx: shutdown_rx }, sighup_rx)
}
