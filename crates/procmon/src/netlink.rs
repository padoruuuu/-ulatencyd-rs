//! Linux netlink proc connector (CN_IDX_PROC) listener.
//!
//! Opens a NETLINK_CONNECTOR socket, subscribes to proc events, and streams
//! them through a std::sync::mpsc channel. The socket is owned by a
//! blocking background thread; a `ProcMonitor` is the receiving handle.
//!
//! Kernel headers referenced:
//!   <linux/netlink.h>, <linux/connector.h>, <linux/cn_proc.h>

use std::os::unix::io::RawFd;
use std::sync::mpsc;
use anyhow::{bail, Result};
use tracing::{debug, error};



// ---------------------------------------------------------------------------
// Protocol constants (linux/connector.h, linux/cn_proc.h)
// ---------------------------------------------------------------------------

const NETLINK_CONNECTOR: libc::c_int = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;

// proc_event::what values
const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_UID:  u32 = 0x0000_0004;
const PROC_EVENT_COMM: u32 = 0x0000_0200;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// Wire structs (repr(C), packed to match kernel ABI)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct CbId {
    idx: u32,
    val: u32,
}

/// cn_msg header preceding every connector message.
#[repr(C)]
#[derive(Clone, Copy)]
struct CnMsg {
    id:    CbId,
    seq:   u32,
    ack:   u32,
    len:   u16,
    flags: u16,
}

/// Minimal proc_event header (what + cpu + timestamp_ns).
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcEventHdr {
    what:         u32,
    cpu:          u32,
    timestamp_ns: u64,
}

/// fork event data (child_pid / child_tgid)
#[repr(C)]
#[derive(Clone, Copy)]
struct ForkData {
    parent_pid:  u32,
    parent_tgid: u32,
    child_pid:   u32,
    child_tgid:  u32,
}

/// exec event data
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecData {
    process_pid:  u32,
    process_tgid: u32,
}

/// exit event data
#[repr(C)]
#[derive(Clone, Copy)]
struct ExitData {
    process_pid:    u32,
    process_tgid:   u32,
    exit_code:      u32,
    exit_signal:    u32,
    parent_pid:     u32,
    parent_tgid:    u32,
}

/// comm event data
#[repr(C)]
#[derive(Clone, Copy)]
struct CommData {
    process_pid:  u32,
    process_tgid: u32,
    comm:         [u8; 16],
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// An event received from the kernel proc connector.
#[derive(Debug)]
pub enum ProcEvent {
    Fork { parent_pid: u32, child_pid: u32, child_tgid: u32 },
    Exec { pid: u32 },
    Exit { pid: u32, exit_code: u32 },
    Comm { pid: u32, comm: String },
    Uid  { pid: u32 },
}

/// Handle to the background netlink listener thread.
pub struct ProcMonitor {
    rx: mpsc::Receiver<ProcEvent>,
}

impl ProcMonitor {
    /// Spawn the background listener and return a handle.
    pub fn spawn() -> Result<Self> {
        let fd = open_connector_socket()?;
        subscribe_to_proc_events(fd)?;

        // Bounded, matching the old tokio channel's capacity — the sender
        // (the netlink listener thread) blocks on send() if the receiver
        // falls behind, which is the same backpressure behaviour as before.
        let (tx, rx) = mpsc::sync_channel::<ProcEvent>(4096);

        std::thread::Builder::new()
            .name("procmon-netlink".into())
            .spawn(move || run_listener(fd, tx))?;

        Ok(Self { rx })
    }

    /// Block until the next proc event arrives, or `None` if the listener
    /// thread has exited (socket closed / error).
    pub fn next_event(&mut self) -> Option<ProcEvent> {
        self.rx.recv().ok()
    }
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

fn open_connector_socket() -> Result<RawFd> {
    // SAFETY: standard POSIX socket creation.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_CONNECTOR,
        )
    };
    if fd < 0 {
        bail!("socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR) failed: errno {}", errno());
    }

    // SAFETY: sockaddr_nl is a plain C struct; zeroing all bytes is valid.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid    = 0;
    addr.nl_groups = CN_IDX_PROC;

    // SAFETY: addr is a valid sockaddr_nl.
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd); }
        bail!("bind(NETLINK_CONNECTOR) failed: errno {}", errno());
    }

    Ok(fd)
}

fn subscribe_to_proc_events(fd: RawFd) -> Result<()> {
    // Build: nlmsghdr + cn_msg + u32 (PROC_CN_MCAST_LISTEN)
    const NL_HDR_LEN:  usize = std::mem::size_of::<libc::nlmsghdr>();
    const CN_HDR_LEN:  usize = std::mem::size_of::<CnMsg>();
    const OP_LEN:      usize = std::mem::size_of::<u32>();
    const TOTAL:       usize = NL_HDR_LEN + CN_HDR_LEN + OP_LEN;

    let mut buf = [0u8; TOTAL];

    // nlmsghdr
    let nlh = buf.as_mut_ptr() as *mut libc::nlmsghdr;
    // SAFETY: buf is properly sized and aligned.
    unsafe {
        (*nlh).nlmsg_len   = TOTAL as u32;
        (*nlh).nlmsg_type  = libc::NLMSG_DONE as u16;
        (*nlh).nlmsg_flags = 0;
        (*nlh).nlmsg_seq   = 0;
        (*nlh).nlmsg_pid   = libc::getpid() as u32;
    }

    // cn_msg
    let cn = unsafe { nlh.add(1) as *mut CnMsg };
    // SAFETY: buffer large enough.
    unsafe {
        (*cn).id    = CbId { idx: CN_IDX_PROC, val: CN_VAL_PROC };
        (*cn).seq   = 0;
        (*cn).ack   = 0;
        (*cn).len   = OP_LEN as u16;
        (*cn).flags = 0;
    }

    // op (PROC_CN_MCAST_LISTEN)
    let op_ptr = unsafe { cn.add(1) as *mut u32 };
    // SAFETY: buffer large enough.
    unsafe { *op_ptr = PROC_CN_MCAST_LISTEN; }

    // SAFETY: sockaddr_nl is a plain C struct; zeroing all bytes is valid.
    let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dst.nl_family = libc::AF_NETLINK as u16;
    dst.nl_pid    = 0;
    dst.nl_groups = 0;

    // SAFETY: buf, dst are valid.
    let rc = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            TOTAL,
            0,
            &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };

    if rc < 0 {
        // Bug 3 fix: close the socket before returning so the fd is never
        // leaked when the caller (ProcMonitor::spawn) gets this error.
        unsafe { libc::close(fd); }
        bail!("sendto(PROC_CN_MCAST_LISTEN) failed: errno {}", errno());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listener loop (runs in a background OS thread)
// ---------------------------------------------------------------------------

fn run_listener(fd: RawFd, tx: mpsc::SyncSender<ProcEvent>) {
    let mut buf = vec![0u8; 8192];

    loop {
        // SAFETY: buf is valid, fd is a netlink socket.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n <= 0 {
            if n < 0 {
                error!("procmon netlink recv error: errno {}", errno());
            }
            break;
        }

        let data = &buf[..n as usize];

        // Walk nlmsghdr messages in the datagram.
        let mut offset = 0usize;
        while offset + std::mem::size_of::<libc::nlmsghdr>() <= data.len() {
            // SAFETY: bounds checked above.
            let nlh = unsafe { &*(data[offset..].as_ptr() as *const libc::nlmsghdr) };
            let msg_len = nlh.nlmsg_len as usize;
            if msg_len < std::mem::size_of::<libc::nlmsghdr>() || offset + msg_len > data.len() {
                break;
            }

            if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                let cn_off = offset + std::mem::size_of::<libc::nlmsghdr>();
                if let Some(event) = parse_cn_msg(&data[cn_off..]) {
                    if tx.send(event).is_err() {
                        debug!("procmon: receiver dropped, exiting listener");
                        unsafe { libc::close(fd); }
                        return;
                    }
                }
            }

            // Align to NLMSG_ALIGNTO (4 bytes)
            offset += (msg_len + 3) & !3;
        }
    }

    // SAFETY: fd was opened in open_connector_socket.
    unsafe { libc::close(fd); }
}

fn parse_cn_msg(buf: &[u8]) -> Option<ProcEvent> {
    const CN_LEN: usize = std::mem::size_of::<CnMsg>();
    const HDR_LEN: usize = std::mem::size_of::<ProcEventHdr>();

    if buf.len() < CN_LEN + HDR_LEN {
        return None;
    }

    // SAFETY: size checked above.
    let cn = unsafe { &*(buf.as_ptr() as *const CnMsg) };
    if cn.id.idx != CN_IDX_PROC || cn.id.val != CN_VAL_PROC {
        return None;
    }

    let event_buf = &buf[CN_LEN..];
    if event_buf.len() < HDR_LEN {
        return None;
    }

    // SAFETY: event_buf is large enough.
    let hdr = unsafe { &*(event_buf.as_ptr() as *const ProcEventHdr) };

    match hdr.what {
        PROC_EVENT_FORK => {
            if event_buf.len() < HDR_LEN + std::mem::size_of::<ForkData>() {
                return None;
            }
            // SAFETY: size checked.
            let d = unsafe { &*(event_buf[HDR_LEN..].as_ptr() as *const ForkData) };
            Some(ProcEvent::Fork {
                parent_pid: d.parent_pid,
                child_pid:  d.child_pid,
                child_tgid: d.child_tgid,
            })
        }
        PROC_EVENT_EXEC => {
            if event_buf.len() < HDR_LEN + std::mem::size_of::<ExecData>() {
                return None;
            }
            // SAFETY: size checked.
            let d = unsafe { &*(event_buf[HDR_LEN..].as_ptr() as *const ExecData) };
            Some(ProcEvent::Exec { pid: d.process_pid })
        }
        PROC_EVENT_EXIT => {
            if event_buf.len() < HDR_LEN + std::mem::size_of::<ExitData>() {
                return None;
            }
            // SAFETY: size checked.
            let d = unsafe { &*(event_buf[HDR_LEN..].as_ptr() as *const ExitData) };
            Some(ProcEvent::Exit { pid: d.process_pid, exit_code: d.exit_code })
        }
        PROC_EVENT_COMM => {
            if event_buf.len() < HDR_LEN + std::mem::size_of::<CommData>() {
                return None;
            }
            // SAFETY: size checked.
            let d = unsafe { &*(event_buf[HDR_LEN..].as_ptr() as *const CommData) };
            let comm = std::str::from_utf8(&d.comm)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            Some(ProcEvent::Comm { pid: d.process_pid, comm })
        }
        PROC_EVENT_UID => {
            if event_buf.len() < HDR_LEN + 16 { return None; }
            // SAFETY: size checked, first two u32 are process_pid/process_tgid.
            let pid = unsafe { *(event_buf[HDR_LEN..].as_ptr() as *const u32) };
            Some(ProcEvent::Uid { pid })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn errno() -> i32 {
    // SAFETY: no invariants; just reads thread-local errno.
    unsafe { *libc::__errno_location() }
}
