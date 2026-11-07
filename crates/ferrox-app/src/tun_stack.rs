//! The userspace TUN inbound: `tun-rs` carries the kernel device, batching a
//! queue's packets with GSO/GRO, and the `WireGuard` server stack owns the TCP
//! state machine and the per-flow proxy dial. Every queue is one stack, one
//! reader and one writer, so a multi-queue device spreads flows across cores
//! without a lock between them.

use std::io;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use tun_rs::{DeviceBuilder, SyncDevice};

#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use crate::proxy::Outbound;
use crate::tun::Spec;
use crate::wg_stack::Packet;
use crate::wireguard::DeviceConfig;

const RX_QUEUE: usize = 1024;
const TX_QUEUE: usize = 1024;

#[cfg(unix)]
type WakeWriter = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
type WakeWriter = ();

/// Open the device and start one stack per queue.
pub(crate) fn serve(spec: &Spec, out: &Outbound) -> io::Result<()> {
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
                return Ok((device, offload, if multi { spec.queues() } else { 1 }));
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
                return Err(error);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (device, _, _) = build(spec, false, false)?;
        Ok((device, false, 1))
    }
}

fn build(spec: &Spec, multi: bool, offload: bool) -> io::Result<(SyncDevice, bool, bool)> {
    let mut builder = DeviceBuilder::new()
        .name(spec.name())
        .mtu(u16::try_from(spec.mtu()).unwrap_or(1500));
    builder = match spec.address() {
        IpAddr::V4(address) => builder.ipv4(address, spec.prefix().min(32), None),
        IpAddr::V6(address) => builder.ipv6(address, spec.prefix().min(128)),
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

fn spawn_queue(device: Arc<SyncDevice>, spec: &Spec, offload: bool, out: Outbound) {
    let (packets, incoming) = mpsc::sync_channel(RX_QUEUE);
    let (outgoing, writes) = mpsc::sync_channel(TX_QUEUE);
    let (recycle, reused) = mpsc::channel();
    #[cfg(unix)]
    let (wake_read, wake_write) = std::os::unix::net::UnixStream::pair().expect("tun wake pair");
    #[cfg(unix)]
    let _ = wake_write.set_nonblocking(true);
    #[cfg(not(unix))]
    let wake_write = ();
    let config = device_config(spec);
    let stack_out = out.clone();
    thread::spawn(move || {
        #[cfg(unix)]
        crate::wg_stack::serve_tun_device(
            config,
            incoming,
            outgoing,
            stack_out,
            Some(recycle),
            wake_read,
        );
        #[cfg(not(unix))]
        crate::wg_stack::serve_tun_device(config, incoming, outgoing, stack_out, Some(recycle));
    });
    let writer = Arc::clone(&device);
    thread::spawn(move || send_loop(writer, writes, offload));
    let mtu = spec.mtu();
    thread::spawn(move || recv_loop(device, packets, reused, mtu, wake_write));
}

fn device_config(spec: &Spec) -> DeviceConfig {
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
fn recv_loop(
    device: Arc<SyncDevice>,
    packets: SyncSender<Packet>,
    reuse: Receiver<Vec<u8>>,
    mtu: usize,
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
            let bytes = packet_bytes(&reuse, &bufs[index][VIRTIO_NET_HDR_LEN..end]);
            let packet = Packet {
                peer: [0; 32],
                bytes,
                at: 0,
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
fn recv_loop(
    device: Arc<SyncDevice>,
    packets: SyncSender<Packet>,
    reuse: Receiver<Vec<u8>>,
    mtu: usize,
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
fn send_loop(device: Arc<SyncDevice>, packets: Receiver<Vec<u8>>, offload: bool) {
    if !offload {
        send_plain(device, packets);
        return;
    }
    let mut gro = GROTable::default();
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(IDEAL_BATCH_SIZE);
    loop {
        let Ok(packet) = packets.recv() else {
            return;
        };
        batch.clear();
        batch.push(packet);
        while batch.len() < IDEAL_BATCH_SIZE {
            match packets.try_recv() {
                Ok(packet) => batch.push(packet),
                Err(_) => break,
            }
        }
        if let Err(error) = device.send_multiple(&mut gro, &mut batch, VIRTIO_NET_HDR_LEN) {
            eprintln!("tun write: {error}");
            return;
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn send_loop(device: Arc<SyncDevice>, packets: Receiver<Vec<u8>>, _offload: bool) {
    send_plain(device, packets);
}

#[cfg(unix)]
fn wake_signal(wake: &WakeWriter) {
    let _ = unsafe { libc::write(wake.as_raw_fd(), b"\0".as_ptr().cast(), 1) };
}

#[cfg(not(unix))]
fn wake_signal(_: &WakeWriter) {}

fn packet_bytes(reuse: &Receiver<Vec<u8>>, source: &[u8]) -> Vec<u8> {
    let mut bytes = reuse.try_recv().unwrap_or_default();
    bytes.clear();
    bytes.extend_from_slice(source);
    bytes
}

fn send_plain(device: Arc<SyncDevice>, packets: Receiver<Vec<u8>>) {
    while let Ok(packet) = packets.recv() {
        #[cfg(target_os = "linux")]
        let packet = &packet[VIRTIO_NET_HDR_LEN..];
        #[cfg(not(target_os = "linux"))]
        let packet = &packet[..];
        if let Err(error) = device.send(packet) {
            eprintln!("tun write: {error}");
            return;
        }
    }
}
