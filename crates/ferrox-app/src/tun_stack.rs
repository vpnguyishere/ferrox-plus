//! The TUN inbound: `tun-rs` carries the kernel device, batching a queue's
//! packets with GSO/GRO, and the `WireGuard` server stack owns the TCP state
//! machine and the per-flow proxy dial. Every queue is one stack, one reader
//! and one writer, so a multi-queue device spreads flows across cores without a
//! lock between them. The `system` and `hybrid` names hand TCP to the kernel
//! stack through a NAT loop on Linux instead; hybrid falls back to this stack
//! for a flow the kernel cannot take.

use std::io;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use tun_rs::{DeviceBuilder, SyncDevice};

#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use crate::proxy::Outbound;
use crate::tun::Spec;
use crate::wg_stack::{Packet, TxPool};
use crate::wireguard::DeviceConfig;

pub(crate) const RX_QUEUE: usize = 1024;
pub(crate) const TX_QUEUE: usize = 1024;
/// The most packets one write batches; 32 packets fill one 64 KiB aggregate.
#[cfg(target_os = "linux")]
const WRITE_BATCH: usize = 64;

#[cfg(unix)]
pub(crate) type WakeWriter = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
pub(crate) type WakeWriter = ();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Userspace,
    System,
    Hybrid,
}

/// Open the device and start the configured TCP stack.
pub(crate) fn serve(spec: &Spec, out: &Outbound, mode: Mode) -> io::Result<()> {
    match mode {
        Mode::Userspace => serve_userspace(spec, out),
        #[cfg(target_os = "linux")]
        Mode::System => crate::tun_system::serve(spec, out, false),
        #[cfg(target_os = "linux")]
        Mode::Hybrid => match crate::tun_system::serve(spec, out, true) {
            Ok(()) => Ok(()),
            Err(error) => {
                eprintln!(
                    "tun inbound: the hybrid stack is unavailable ({error}), using the userspace stack"
                );
                serve_userspace(spec, out)
            }
        },
        #[cfg(not(target_os = "linux"))]
        Mode::System => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the system tun stack is Linux-only",
        )),
        #[cfg(not(target_os = "linux"))]
        Mode::Hybrid => {
            eprintln!("tun inbound: the hybrid stack is Linux-only, using the userspace stack");
            serve_userspace(spec, out)
        }
    }
}

fn serve_userspace(spec: &Spec, out: &Outbound) -> io::Result<()> {
    let (first, offload, queues) = open(spec)?;
    let first = Arc::new(first);
    spawn_queue(Arc::clone(&first), spec, offload, out.clone());
    #[cfg(target_os = "linux")]
    for _ in 1..queues {
        let device = Arc::new(first.try_clone()?);
        spawn_queue(device, spec, offload, out.clone());
    }
    #[cfg(not(target_os = "linux"))]
    let _ = queues;
    Ok(())
}

fn open(spec: &Spec) -> io::Result<(SyncDevice, bool, usize)> {
    #[cfg(target_os = "linux")]
    {
        let multi = spec.queues() > 1;
        match build(spec, multi, true) {
            Ok((device, offload, multi)) => {
                Ok((device, offload, if multi { spec.queues() } else { 1 }))
            }
            Err(error) => {
                if let Ok((device, offload, multi)) = build(spec, multi, false) {
                    return Ok((device, offload, if multi { spec.queues() } else { 1 }));
                }
                if multi {
                    if let Ok((device, offload, _)) = build(spec, false, true) {
                        return Ok((device, offload, 1));
                    }
                }
                if let Ok((device, offload, _)) = build(spec, false, false) {
                    return Ok((device, offload, 1));
                }
                Err(error)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (device, _, _) = build(spec, false, false)?;
        Ok((device, false, 1))
    }
}

pub(crate) fn build(
    spec: &Spec,
    multi: bool,
    offload: bool,
) -> io::Result<(SyncDevice, bool, bool)> {
    spec.validate()?;
    let mtu = u16::try_from(spec.mtu()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tun mtu {} exceeds 65535", spec.mtu()),
        )
    })?;
    let mut builder = DeviceBuilder::new().name(spec.name()).mtu(mtu);
    builder = match spec.address() {
        IpAddr::V4(address) => builder.ipv4(address, spec.prefix(), None),
        IpAddr::V6(address) => builder.ipv6(address, spec.prefix()),
    };
    #[cfg(target_os = "linux")]
    let builder = builder.offload(offload).multi_queue(multi);
    #[cfg(not(target_os = "linux"))]
    let builder = builder;
    let device = builder.build_sync()?;
    #[cfg(target_os = "linux")]
    let offload = device.tcp_gso();
    #[cfg(not(target_os = "linux"))]
    let _ = (multi, offload);
    Ok((device, offload, multi))
}

#[allow(clippy::needless_pass_by_value)]
fn spawn_queue(device: Arc<SyncDevice>, spec: &Spec, offload: bool, out: Outbound) {
    #[cfg(target_os = "linux")]
    let headroom = VIRTIO_NET_HDR_LEN;
    #[cfg(not(target_os = "linux"))]
    let headroom = 0;
    #[cfg(target_os = "linux")]
    let (tx_pool, tx_free) = if headroom == VIRTIO_NET_HDR_LEN {
        let (pool, free) = TxPool::new(WRITE_BATCH, headroom + 65_535);
        (Some(pool), Some(free))
    } else {
        (None, None)
    };
    #[cfg(not(target_os = "linux"))]
    let (tx_pool, tx_free): (Option<TxPool>, Option<SyncSender<Vec<u8>>>) = (None, None);
    let (packets, incoming) = mpsc::sync_channel(RX_QUEUE);
    let (outgoing, writes) = mpsc::sync_channel(TX_QUEUE);
    let (recycle, reused) = mpsc::sync_channel(RX_QUEUE);
    #[cfg(unix)]
    let (wake_read, wake_write) = std::os::unix::net::UnixStream::pair().expect("tun wake pair");
    #[cfg(unix)]
    let _ = wake_write.set_nonblocking(true);
    #[cfg(not(unix))]
    let wake_write = ();
    let config = device_config(spec);
    let stack_out = out.clone();
    let failed = Arc::new(AtomicBool::new(false));
    let stack_failed = Arc::clone(&failed);
    thread::spawn(move || {
        #[cfg(unix)]
        crate::wg_stack::serve_tun_device(
            config,
            incoming,
            outgoing,
            stack_out,
            Some(recycle),
            headroom,
            tx_pool,
            wake_read,
            stack_failed,
        );
        #[cfg(not(unix))]
        crate::wg_stack::serve_tun_device(
            config,
            incoming,
            outgoing,
            stack_out,
            Some(recycle),
            headroom,
            tx_pool,
            stack_failed,
        );
    });
    let send_device = Arc::clone(&device);
    thread::spawn(move || {
        send_loop(send_device, writes, offload, headroom, tx_free.as_ref(), &failed);
    });
    let mtu = spec.mtu();
    thread::spawn(move || recv_loop(device, packets, reused, mtu, headroom, wake_write));
}

pub(crate) fn device_config(spec: &Spec) -> DeviceConfig {
    DeviceConfig {
        secret: [0; 32],
        addresses: vec![spec.address()],
        peers: Vec::new(),
        mtu: spec.mtu(),
        reserved: [0; 3],
        is_client: Some(false),
        no_kernel_tun: true,
        large_segments: true,
        dns: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn recv_loop(
    device: Arc<SyncDevice>,
    packets: SyncSender<Packet>,
    reuse: Receiver<Vec<u8>>,
    mtu: usize,
    headroom: usize,
    wake: WakeWriter,
) {
    let mut original = vec![0u8; VIRTIO_NET_HDR_LEN + 65_535];
    let mut bufs: Vec<Vec<u8>> = (0..IDEAL_BATCH_SIZE)
        .map(|_| vec![0u8; VIRTIO_NET_HDR_LEN + mtu])
        .collect();
    let mut sizes = vec![0usize; IDEAL_BATCH_SIZE];
    loop {
        let count =
            match device.recv_multiple(&mut original, &mut bufs, &mut sizes, VIRTIO_NET_HDR_LEN) {
                Ok(0) => continue,
                Ok(count) => count,
                Err(error) => {
                    eprintln!("tun read: {error}");
                    return;
                }
            };
        for index in 0..count {
            let end = VIRTIO_NET_HDR_LEN.saturating_add(sizes[index]);
            if sizes[index] == 0 || end > bufs[index].len() {
                continue;
            }
            let bytes = if headroom == VIRTIO_NET_HDR_LEN {
                let mut replacement = reuse.try_recv().unwrap_or_default();
                replacement.clear();
                replacement.resize(VIRTIO_NET_HDR_LEN + mtu, 0);
                let mut bytes = std::mem::replace(&mut bufs[index], replacement);
                bytes.truncate(end);
                bytes
            } else {
                packet_bytes(&reuse, &bufs[index][VIRTIO_NET_HDR_LEN..end])
            };
            let packet = Packet {
                peer: [0; 32],
                bytes,
                at: headroom,
            };
            if packets.send(packet).is_err() {
                return;
            }
        }
        if count > 0 {
            wake_signal(&wake);
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn recv_loop(
    device: Arc<SyncDevice>,
    packets: SyncSender<Packet>,
    reuse: Receiver<Vec<u8>>,
    mtu: usize,
    _headroom: usize,
    wake: WakeWriter,
) {
    let mut buffer = vec![0u8; mtu.max(1500) + 64];
    loop {
        let size = match device.recv(&mut buffer) {
            Ok(0) => continue,
            Ok(size) if size <= buffer.len() => size,
            Ok(_) => continue,
            Err(error) => {
                eprintln!("tun read: {error}");
                return;
            }
        };
        let bytes = packet_bytes(&reuse, &buffer[..size]);
        let packet = Packet {
            peer: [0; 32],
            bytes,
            at: 0,
        };
        if packets.send(packet).is_err() {
            return;
        }
        wake_signal(&wake);
    }
}

#[cfg(target_os = "linux")]
fn send_loop(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    offload: bool,
    headroom: usize,
    tx_free: Option<&SyncSender<Vec<u8>>>,
    failed: &AtomicBool,
) {
    if !offload {
        send_packets_offset(device, packets, failed, headroom, tx_free);
        return;
    }
    let mut gro = GROTable::default();
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(WRITE_BATCH);
    loop {
        let Ok(packet) = packets.recv() else {
            return;
        };
        batch.clear();
        batch.push(packet);
        while batch.len() < WRITE_BATCH {
            match packets.try_recv() {
                Ok(packet) => batch.push(packet),
                Err(_) => break,
            }
        }
        let written = device.send_multiple(&mut gro, &mut batch, headroom);
        for buffer in batch.drain(..) {
            if let Some(free) = tx_free {
                let _ = free.try_send(buffer);
            }
        }
        if let Err(error) = written {
            if refused(&error) {
                continue;
            }
            eprintln!("tun write: {error}");
            failed.store(true, Ordering::Relaxed);
            return;
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn send_loop(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    _offload: bool,
    _headroom: usize,
    _tx_free: Option<&SyncSender<Vec<u8>>>,
    failed: &AtomicBool,
) {
    send_plain(device, packets, failed, None);
}

#[cfg(unix)]
pub(crate) fn wake_signal(wake: &WakeWriter) {
    let _ = unsafe { libc::write(wake.as_raw_fd(), c"".as_ptr().cast(), 1) };
}

#[cfg(not(unix))]
pub(crate) fn wake_signal(_: &WakeWriter) {}

#[cfg(target_os = "linux")]
#[allow(clippy::needless_pass_by_value)]
fn send_packets_offset(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    failed: &AtomicBool,
    offset: usize,
    recycle: Option<&SyncSender<Vec<u8>>>,
) {
    send_packets(&packets, failed, recycle, |packet| {
        let body = packet
            .get(offset..)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        device.send(body).map(|_| ())
    });
}

fn packet_bytes(reuse: &Receiver<Vec<u8>>, source: &[u8]) -> Vec<u8> {
    let mut bytes = reuse.try_recv().unwrap_or_default();
    bytes.clear();
    bytes.extend_from_slice(source);
    bytes
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn send_plain(
    device: Arc<SyncDevice>,
    packets: Receiver<Vec<u8>>,
    failed: &AtomicBool,
    recycle: Option<SyncSender<Vec<u8>>>,
) {
    send_packets(&packets, failed, recycle.as_ref(), |packet| {
        device.send(packet).map(|_| ())
    });
}

/// One packet the kernel refuses is the packet that is lost, not the device: `EINVAL` and
/// `EMSGSIZE` mean this send was bad, while every other error means the descriptor is gone.
#[cfg(unix)]
const REFUSED_WRITES: [i32; 2] = [libc::EINVAL, libc::EMSGSIZE];
#[cfg(windows)]
const REFUSED_WRITES: [i32; 2] = [10022, 10040];
#[cfg(not(any(unix, windows)))]
const REFUSED_WRITES: [i32; 0] = [];

pub(crate) fn refused(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::InvalidInput
        || error
            .raw_os_error()
            .is_some_and(|code| REFUSED_WRITES.contains(&code))
}

fn send_packets<W>(
    packets: &Receiver<Vec<u8>>,
    failed: &AtomicBool,
    recycle: Option<&SyncSender<Vec<u8>>>,
    mut write: W,
) where
    W: FnMut(&[u8]) -> io::Result<()>,
{
    while let Ok(packet) = packets.recv() {
        let written = write(&packet);
        if let Some(recycle) = recycle {
            let _ = recycle.try_send(packet);
        }
        if let Err(error) = written {
            if refused(&error) {
                continue;
            }
            eprintln!("tun write: {error}");
            failed.store(true, Ordering::Relaxed);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const REFUSED: i32 = libc::EINVAL;
    #[cfg(windows)]
    const REFUSED: i32 = 10022;
    #[cfg(unix)]
    const DEAD: i32 = libc::EBADF;
    #[cfg(windows)]
    const DEAD: i32 = 10009;

    #[test]
    #[cfg(any(unix, windows))]
    fn a_refused_packet_is_dropped_and_the_next_still_goes_out() {
        let (tx, rx) = mpsc::channel();
        tx.send(b"first".to_vec()).expect("queues");
        tx.send(b"second".to_vec()).expect("queues");
        drop(tx);
        let failed = AtomicBool::new(false);
        let mut seen = Vec::new();
        let mut first = true;
        let mut writes = 0;
        send_packets(&rx, &failed, None, |packet| {
            writes += 1;
            if first {
                first = false;
                return Err(io::Error::from_raw_os_error(REFUSED));
            }
            seen.push(packet.to_vec());
            Ok(())
        });
        assert_eq!(writes, 2, "the loop kept writing after the refusal");
        assert_eq!(seen, vec![b"second".to_vec()]);
        assert!(!failed.load(Ordering::Relaxed), "a refusal is not fatal");
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn a_dead_descriptor_still_stops_the_send_loop() {
        let (tx, rx) = mpsc::channel();
        tx.send(b"first".to_vec()).expect("queues");
        tx.send(b"second".to_vec()).expect("queues");
        drop(tx);
        let failed = AtomicBool::new(false);
        let mut writes = 0;
        send_packets(&rx, &failed, None, |_| {
            writes += 1;
            Err(io::Error::from_raw_os_error(DEAD))
        });
        assert_eq!(writes, 1, "a dead descriptor stops before the next packet");
        assert!(failed.load(Ordering::Relaxed));
    }
}
