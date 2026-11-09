//! The kernel-backed TUN TCP stack: incoming TCP packets are rewritten onto a
//! peer address and a loopback listener, so the kernel owns the handshake,
//! windows and retransmits while one relay dials the proxy for each accepted
//! flow. UDP and ICMP stay on the userspace stack. Hybrid passes a TCP flow the
//! kernel cannot take to that stack instead of dropping it.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use ferrox_core::foxy::connectip::{
    checksum_update, ipv4_head, ipv6_head, IPV4_HEADER, IPV6_HEADER,
};

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_ACK: u8 = 0x10;
const NAT_PORT_BASE: u16 = 20_000;
const NAT_PORT_LIMIT: u16 = 65_000;
const NAT_MAX: usize = 4_096;
const NAT_IDLE: Duration = Duration::from_secs(120);
const NAT_LINGER: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
}

impl FlowKey {
    fn of(view: &TcpView) -> Self {
        Self {
            source: view.source,
            source_port: view.source_port,
            destination: view.destination,
            destination_port: view.destination_port,
        }
    }

    fn reversed(self) -> Self {
        Self {
            source: self.destination,
            source_port: self.destination_port,
            destination: self.source,
            destination_port: self.source_port,
        }
    }
}

struct Mapping {
    key: FlowKey,
    accepted: bool,
    closed: bool,
    generation: u64,
    last: Instant,
}

struct Nat {
    local: IpAddr,
    peer: IpAddr,
    listener_port: u16,
    forward: HashMap<FlowKey, u16>,
    ports: HashMap<u16, Mapping>,
    next: u16,
    created: u64,
    hybrid: bool,
    fallback: HashMap<FlowKey, Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Handled,
    UnhandledTcp,
    Other,
}

struct TcpView {
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    flags: u8,
    l4: usize,
}

impl Nat {
    fn new(local: IpAddr, peer: IpAddr, listener_port: u16, hybrid: bool) -> Self {
        Self {
            local,
            peer,
            listener_port,
            forward: HashMap::new(),
            ports: HashMap::new(),
            next: NAT_PORT_BASE,
            created: 0,
            hybrid,
            fallback: HashMap::new(),
        }
    }

    fn rewrite(&mut self, packet: &mut [u8]) -> Outcome {
        let Some(view) = tcp_view(packet) else {
            return Outcome::Other;
        };
        let local = self.local;
        let peer = self.peer;
        let listener_port = self.listener_port;
        if view.source.is_ipv4() != local.is_ipv4() {
            return Outcome::Other;
        }
        let now = Instant::now();
        let key = FlowKey::of(&view);
        let fallback = if view.source == local {
            Some(key)
        } else if view.destination == local {
            Some(key.reversed())
        } else {
            None
        };
        if let Some(fallback) = fallback {
            if let Some(last) = self.fallback.get_mut(&fallback) {
                *last = now;
                if view.flags & (FLAG_FIN | FLAG_RST) != 0 {
                    self.fallback.remove(&fallback);
                }
                return Outcome::UnhandledTcp;
            }
        }
        if view.source == local && view.destination == peer && view.source_port == listener_port {
            let Some(mapping) = self.ports.get_mut(&view.destination_port) else {
                return Outcome::UnhandledTcp;
            };
            if !mapping.closed {
                mapping.last = now;
            }
            let key = mapping.key;
            return mapped(
                packet,
                &view,
                key.destination,
                key.source,
                key.destination_port,
                key.source_port,
            );
        }

        if let Some(port) = self.forward.get(&key).copied() {
            if let Some(mapping) = self.ports.get_mut(&port) {
                if !mapping.closed {
                    mapping.last = now;
                    return mapped(packet, &view, peer, local, port, listener_port);
                }
                if view.flags & FLAG_SYN == 0 || view.flags & FLAG_ACK != 0 {
                    return mapped(packet, &view, peer, local, port, listener_port);
                }
            }
            self.remove(port);
        }

        if view.flags & FLAG_SYN == 0 || view.flags & FLAG_ACK != 0 {
            self.remember_fallback(&view, now);
            return Outcome::UnhandledTcp;
        }
        let Some(port) = self.allocate(now) else {
            self.remember_fallback(&view, now);
            return Outcome::UnhandledTcp;
        };
        let generation = self.created;
        self.forward.insert(key, port);
        self.ports.insert(
            port,
            Mapping {
                key,
                accepted: false,
                closed: false,
                generation,
                last: now,
            },
        );
        mapped(packet, &view, peer, local, port, listener_port)
    }

    fn remember_fallback(&mut self, view: &TcpView, now: Instant) {
        if !self.hybrid || view.source != self.local {
            return;
        }
        let key = FlowKey::of(view);
        if !self.fallback.contains_key(&key) && self.fallback.len() >= NAT_MAX {
            if let Some(oldest) = self
                .fallback
                .iter()
                .min_by_key(|(_, last)| **last)
                .map(|(key, _)| *key)
            {
                self.fallback.remove(&oldest);
            }
        }
        self.fallback.insert(key, now);
    }

    fn allocate(&mut self, now: Instant) -> Option<u16> {
        self.created = self.created.wrapping_add(1);
        if self.ports.len() >= NAT_MAX || self.created.is_multiple_of(256) {
            self.sweep(now);
        }
        if self.ports.len() >= NAT_MAX {
            return None;
        }
        for _ in NAT_PORT_BASE..NAT_PORT_LIMIT {
            let port = self.next;
            self.next = if port + 1 >= NAT_PORT_LIMIT {
                NAT_PORT_BASE
            } else {
                port + 1
            };
            if !self.ports.contains_key(&port) {
                return Some(port);
            }
        }
        None
    }

    fn sweep(&mut self, now: Instant) {
        let stale: Vec<u16> = self
            .ports
            .iter()
            .filter_map(|(&port, mapping)| {
                let age = now.saturating_duration_since(mapping.last);
                ((mapping.closed && age > NAT_LINGER) || (!mapping.accepted && age > NAT_IDLE))
                    .then_some(port)
            })
            .collect();
        for port in stale {
            self.remove(port);
        }
    }

    fn remove(&mut self, port: u16) {
        if let Some(mapping) = self.ports.remove(&port) {
            self.forward.remove(&mapping.key);
        }
    }

    fn accepted(&mut self, peer: SocketAddr) -> Option<(SocketAddr, u64)> {
        if peer.ip() != self.peer {
            return None;
        }
        let mapping = self.ports.get_mut(&peer.port())?;
        if mapping.accepted {
            return None;
        }
        mapping.accepted = true;
        mapping.last = Instant::now();
        Some((
            SocketAddr::new(mapping.key.destination, mapping.key.destination_port),
            mapping.generation,
        ))
    }

    fn closed(&mut self, port: u16, generation: u64) {
        if let Some(mapping) = self.ports.get_mut(&port) {
            if mapping.generation == generation {
                mapping.closed = true;
                mapping.last = Instant::now();
            }
        }
    }
}

fn mapped(
    packet: &mut [u8],
    view: &TcpView,
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
) -> Outcome {
    if rewrite_tcp(
        packet,
        view,
        source,
        destination,
        source_port,
        destination_port,
    ) {
        Outcome::Handled
    } else {
        Outcome::Other
    }
}

fn tcp_view(packet: &[u8]) -> Option<TcpView> {
    let first = *packet.first()?;
    let (source, destination, l4, total, protocol) = match first >> 4 {
        4 => {
            let (head, _) = ipv4_head(packet)?;
            if *packet.get(6)? & 0x3f != 0 || *packet.get(7)? != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::from(head.source)),
                IpAddr::V4(Ipv4Addr::from(head.destination)),
                IPV4_HEADER,
                usize::from(head.length),
                head.protocol,
            )
        }
        6 => {
            let (head, body) = ipv6_head(packet)?;
            (
                IpAddr::V6(Ipv6Addr::from(head.source)),
                IpAddr::V6(Ipv6Addr::from(head.destination)),
                IPV6_HEADER,
                IPV6_HEADER + body.len(),
                head.next_header,
            )
        }
        _ => return None,
    };
    if protocol != 6 || total < l4 + 20 {
        return None;
    }
    let source_port = u16::from_be_bytes([*packet.get(l4)?, *packet.get(l4 + 1)?]);
    let destination_port = u16::from_be_bytes([*packet.get(l4 + 2)?, *packet.get(l4 + 3)?]);
    Some(TcpView {
        source,
        destination,
        source_port,
        destination_port,
        flags: *packet.get(l4 + 13)?,
        l4,
    })
}

fn rewrite_tcp(
    packet: &mut [u8],
    view: &TcpView,
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
) -> bool {
    // `tcp_view` returns `l4` as 20 or 40 only after the IP length fits the packet.
    let Some(l4_end) = view.l4.checked_add(20) else {
        return false;
    };
    let Some(tcp) = packet.get(view.l4..l4_end) else {
        return false;
    };
    let mut checksum = u16::from_be_bytes([tcp[16], tcp[17]]);
    // One's-complement addition is linear: one delta over the changed words equals the sequential deltas.
    let mut old = [0u8; 36];
    let mut new = [0u8; 36];
    // The view and the NAT peer share a family; a mismatch stays with the userspace stack.
    match (view.source, view.destination, source, destination) {
        (
            IpAddr::V4(old_source),
            IpAddr::V4(old_destination),
            IpAddr::V4(source),
            IpAddr::V4(destination),
        ) => {
            old[..4].copy_from_slice(&old_source.octets());
            old[4..8].copy_from_slice(&old_destination.octets());
            old[8..10].copy_from_slice(&view.source_port.to_be_bytes());
            old[10..12].copy_from_slice(&view.destination_port.to_be_bytes());
            new[..4].copy_from_slice(&source.octets());
            new[4..8].copy_from_slice(&destination.octets());
            new[8..10].copy_from_slice(&source_port.to_be_bytes());
            new[10..12].copy_from_slice(&destination_port.to_be_bytes());
            let Some(header) = packet.get(10..12) else {
                return false;
            };
            let header = checksum_update(
                u16::from_be_bytes([header[0], header[1]]),
                &old[..8],
                &new[..8],
            );
            checksum = checksum_update(checksum, &old[..12], &new[..12]);
            let Some(ip) = packet.get_mut(10..20) else {
                return false;
            };
            ip[2..6].copy_from_slice(&source.octets());
            ip[6..10].copy_from_slice(&destination.octets());
            ip[0..2].copy_from_slice(&header.to_be_bytes());
        }
        (
            IpAddr::V6(old_source),
            IpAddr::V6(old_destination),
            IpAddr::V6(source),
            IpAddr::V6(destination),
        ) => {
            old[..16].copy_from_slice(&old_source.octets());
            old[16..32].copy_from_slice(&old_destination.octets());
            old[32..34].copy_from_slice(&view.source_port.to_be_bytes());
            old[34..36].copy_from_slice(&view.destination_port.to_be_bytes());
            new[..16].copy_from_slice(&source.octets());
            new[16..32].copy_from_slice(&destination.octets());
            new[32..34].copy_from_slice(&source_port.to_be_bytes());
            new[34..36].copy_from_slice(&destination_port.to_be_bytes());
            checksum = checksum_update(checksum, &old[..36], &new[..36]);
            let Some(ip) = packet.get_mut(8..40) else {
                return false;
            };
            ip[..16].copy_from_slice(&source.octets());
            ip[16..].copy_from_slice(&destination.octets());
        }
        _ => return false,
    }
    let Some(tcp) = packet.get_mut(view.l4..l4_end) else {
        return false;
    };
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    true
}

fn nat_peer(address: IpAddr, prefix: u8) -> Option<IpAddr> {
    match address {
        IpAddr::V4(address) => {
            if prefix > 30 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            let network = u32::from(address) & mask;
            let local = u32::from(address);
            [network + 1, network + 2]
                .into_iter()
                .find(|candidate| *candidate != local)
                .map(|candidate| IpAddr::V4(Ipv4Addr::from(candidate)))
        }
        IpAddr::V6(address) => {
            if prefix > 126 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            let network = u128::from(address) & mask;
            let local = u128::from(address);
            [network + 1, network + 2]
                .into_iter()
                .find(|candidate| *candidate != local)
                .map(|candidate| IpAddr::V6(Ipv6Addr::from(candidate)))
        }
    }
}

#[cfg(target_os = "linux")]
fn listener_address(local: IpAddr, name: &str) -> io::Result<SocketAddr> {
    let IpAddr::V6(address) = local else {
        return Ok(SocketAddr::new(local, 0));
    };
    if !address.is_unicast_link_local() {
        return Ok(SocketAddr::new(local, 0));
    }
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::other("interface name contains a NUL"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
        address, 0, 0, index,
    )))
}

#[cfg(target_os = "linux")]
pub(crate) fn serve(
    spec: &crate::tun::Spec,
    out: &crate::proxy::Outbound,
    hybrid: bool,
) -> io::Result<()> {
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use crate::tun_stack::{self, RX_QUEUE, TX_QUEUE};

    spec.validate()?;
    let local = spec.address();
    let peer = nat_peer(local, spec.prefix()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the system stack needs a second address inside tun prefix {local}/{}",
                spec.prefix()
            ),
        )
    })?;
    let device = Arc::new(tun_stack::build(spec, false, false)?.0);
    let listener = std::net::TcpListener::bind(listener_address(local, &device.name()?)?)?;
    listener.set_nonblocking(true)?;
    let listener_port = listener.local_addr()?.port();
    if spec.queues() > 1 {
        let stack = if hybrid { "hybrid" } else { "system" };
        eprintln!("tun inbound: the {stack} stack uses one queue");
    }
    let (packets, incoming) = mpsc::sync_channel(RX_QUEUE);
    let (outgoing, writes) = mpsc::sync_channel(TX_QUEUE);
    let (to_stack, stack_rx) = mpsc::sync_channel(RX_QUEUE);
    let (recycle, reused) = mpsc::sync_channel(RX_QUEUE);
    let failed = Arc::new(AtomicBool::new(false));
    let nat = Arc::new(Mutex::new(Nat::new(local, peer, listener_port, hybrid)));

    let (wake_read, wake_write) = UnixStream::pair()?;
    wake_write.set_nonblocking(true)?;
    let stack_wake = wake_write.try_clone()?;
    let config = tun_stack::device_config(spec);
    let stack_out = out.clone();
    let stack_failed = Arc::clone(&failed);
    let stack_recycle = recycle.clone();
    let stack_outgoing = outgoing.clone();
    thread::spawn(move || {
        crate::wg_stack::serve_tun_device(
            config,
            stack_rx,
            stack_outgoing,
            stack_out,
            Some(stack_recycle),
            wake_read,
            stack_failed,
        );
    });

    let accept_nat = Arc::clone(&nat);
    let accept_out = out.clone();
    let accept_failed = Arc::clone(&failed);
    thread::spawn(move || accept_loop(listener, accept_nat, accept_out, accept_failed));

    let loop_nat = Arc::clone(&nat);
    let loop_failed = Arc::clone(&failed);
    let loop_recycle = recycle.clone();
    thread::spawn(move || {
        packet_loop(
            incoming,
            to_stack,
            outgoing,
            loop_nat,
            loop_recycle,
            stack_wake,
            loop_failed,
            hybrid,
        );
    });

    let write_device = Arc::clone(&device);
    let write_failed = Arc::clone(&failed);
    thread::spawn(move || {
        tun_stack::send_plain(write_device, writes, &write_failed, Some(recycle));
    });

    let mtu = spec.mtu();
    thread::spawn(move || tun_stack::recv_loop(device, packets, reused, mtu, wake_write));
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn packet_loop(
    incoming: std::sync::mpsc::Receiver<crate::wg_stack::Packet>,
    to_stack: std::sync::mpsc::SyncSender<crate::wg_stack::Packet>,
    outgoing: std::sync::mpsc::SyncSender<Vec<u8>>,
    nat: std::sync::Arc<std::sync::Mutex<Nat>>,
    recycle: std::sync::mpsc::SyncSender<Vec<u8>>,
    wake: crate::tun_stack::WakeWriter,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    hybrid: bool,
) {
    use std::sync::atomic::Ordering;

    while !failed.load(Ordering::Relaxed) {
        let Ok(mut packet) = incoming.recv() else {
            return;
        };
        let outcome = match nat.lock() {
            Ok(mut nat) => nat.rewrite(&mut packet.bytes),
            Err(_) => return,
        };
        match outcome {
            Outcome::Handled => {
                if outgoing.send(packet.bytes).is_err() {
                    return;
                }
            }
            Outcome::Other => {
                if to_stack.send(packet).is_err() {
                    return;
                }
                crate::tun_stack::wake_signal(&wake);
            }
            Outcome::UnhandledTcp if hybrid => {
                if to_stack.send(packet).is_err() {
                    return;
                }
                crate::tun_stack::wake_signal(&wake);
            }
            Outcome::UnhandledTcp => {
                let _ = recycle.try_send(packet.bytes);
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::needless_pass_by_value)]
fn accept_loop(
    listener: std::net::TcpListener,
    nat: std::sync::Arc<std::sync::Mutex<Nat>>,
    out: crate::proxy::Outbound,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    while !failed.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let destination = match nat.lock() {
                    Ok(mut nat) => nat.accepted(peer),
                    Err(_) => return,
                };
                let Some((destination, generation)) = destination else {
                    continue;
                };
                let out = out.clone();
                let nat = std::sync::Arc::clone(&nat);
                let port = peer.port();
                thread::spawn(move || {
                    let conn = crate::conn::Connection::Tcp(stream);
                    let destination = crate::proxy::Destination::Address(destination);
                    let _ = crate::proxy::serve_device_flow(conn, &out, &destination);
                    if let Ok(mut nat) = nat.lock() {
                        nat.closed(port, generation);
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                eprintln!("tun system accept: {error}");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrox_core::foxy::connectip::{ipv4_checksum, tcp_checksum};

    fn ipv4_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        ipv4_packet_with_payload(
            source,
            destination,
            source_port,
            destination_port,
            flags,
            &[],
        )
    }

    fn ipv4_packet_with_payload(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        let total = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet[34..36].copy_from_slice(&65_535u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        let checksum = ipv4_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        let checksum = tcp_checksum(&source.octets(), &destination.octets(), &packet[20..]);
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv6_packet(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        ipv6_packet_with_payload(
            source,
            destination,
            source_port,
            destination_port,
            flags,
            &[],
        )
    }

    fn ipv6_packet_with_payload(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 60 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(20u16 + payload.len() as u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = flags;
        packet[54..56].copy_from_slice(&65_535u16.to_be_bytes());
        packet[60..].copy_from_slice(payload);
        let checksum = tcp_checksum(&source.octets(), &destination.octets(), &packet[40..]);
        packet[56..58].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn fields(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16) {
        (
            Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            u16::from_be_bytes([packet[20], packet[21]]),
            u16::from_be_bytes([packet[22], packet[23]]),
        )
    }

    #[test]
    fn a_forwarded_syn_becomes_a_packet_to_the_local_listener() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let peer = Ipv4Addr::new(198, 18, 0, 2);
        let mut nat = Nat::new(local.into(), peer.into(), 40_000, false);
        let mut packet = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_SYN);

        assert!(nat.rewrite(&mut packet) == Outcome::Handled);
        let (source, destination, source_port, destination_port) = fields(&packet);
        assert_eq!(source, peer);
        assert_eq!(destination, local);
        assert!((NAT_PORT_BASE..NAT_PORT_LIMIT).contains(&source_port));
        assert_eq!(destination_port, 40_000);
        assert_eq!(ipv4_checksum(&packet[..20]), 0);
        assert_eq!(
            tcp_checksum(&source.octets(), &destination.octets(), &packet[20..]),
            0
        );

        let mut reverse = ipv4_packet(local, peer, 40_000, source_port, FLAG_SYN | FLAG_ACK);
        assert!(nat.rewrite(&mut reverse) == Outcome::Handled);
        assert_eq!(
            fields(&reverse),
            (Ipv4Addr::new(203, 0, 113, 7), local, 443, 1234,)
        );
        let (source, destination, _, _) = fields(&reverse);
        assert_eq!(ipv4_checksum(&reverse[..20]), 0);
        assert_eq!(
            tcp_checksum(&source.octets(), &destination.octets(), &reverse[20..]),
            0
        );
    }

    #[test]
    fn an_accepted_flow_names_its_original_destination() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let peer = Ipv4Addr::new(198, 18, 0, 2);
        let mut nat = Nat::new(local.into(), peer.into(), 40_000, false);
        let mut packet = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut packet) == Outcome::Handled);
        let port = fields(&packet).2;
        assert_eq!(
            nat.accepted(SocketAddr::new(Ipv4Addr::new(198, 18, 0, 9).into(), port)),
            None
        );
        let (destination, generation) = nat
            .accepted(SocketAddr::new(peer.into(), port))
            .expect("the peer's connection is accepted");
        assert_eq!(
            destination,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 443)
        );
        assert_eq!(nat.accepted(SocketAddr::new(peer.into(), port)), None);
        nat.closed(port, generation);
        assert!(nat.ports.get(&port).is_some_and(|mapping| mapping.closed));
    }

    #[test]
    fn an_ipv6_flow_is_rewritten_with_its_checksum() {
        let local = "fdfe:dcba:9876::1".parse::<Ipv6Addr>().unwrap();
        let peer = "fdfe:dcba:9876::2".parse::<Ipv6Addr>().unwrap();
        let remote = "2001:db8::7".parse::<Ipv6Addr>().unwrap();
        let mut nat = Nat::new(local.into(), peer.into(), 40_000, false);
        let mut packet = ipv6_packet(local, remote, 1234, 443, FLAG_SYN);

        assert!(nat.rewrite(&mut packet) == Outcome::Handled);
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
        let source_port = u16::from_be_bytes([packet[40], packet[41]]);
        let destination_port = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(source, peer);
        assert_eq!(destination, local);
        assert!((NAT_PORT_BASE..NAT_PORT_LIMIT).contains(&source_port));
        assert_eq!(destination_port, 40_000);
        assert_eq!(
            tcp_checksum(&source.octets(), &destination.octets(), &packet[40..]),
            0
        );

        let mut reverse = ipv6_packet(local, peer, 40_000, source_port, FLAG_SYN | FLAG_ACK);
        assert!(nat.rewrite(&mut reverse) == Outcome::Handled);
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&reverse[8..24]).unwrap());
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&reverse[24..40]).unwrap());
        assert_eq!(source, remote);
        assert_eq!(destination, local);
        assert_eq!(u16::from_be_bytes([reverse[40], reverse[41]]), 443);
        assert_eq!(u16::from_be_bytes([reverse[42], reverse[43]]), 1234);
        assert_eq!(
            tcp_checksum(&source.octets(), &destination.octets(), &reverse[40..]),
            0
        );
    }

    #[test]
    fn a_rewrite_keeps_the_checksum_of_every_payload_length() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let peer = Ipv4Addr::new(198, 18, 0, 2);
        let remote = Ipv4Addr::new(203, 0, 113, 7);
        let local6 = "fdfe:dcba:9876::1".parse::<Ipv6Addr>().unwrap();
        let peer6 = "fdfe:dcba:9876::2".parse::<Ipv6Addr>().unwrap();
        let remote6 = "2001:db8::7".parse::<Ipv6Addr>().unwrap();
        for len in [0usize, 1, 2, 3, 17, 64, 1_460, 4_096, 65_475] {
            let payload: Vec<u8> = (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect();
            let mut nat = Nat::new(local.into(), peer.into(), 40_000, false);
            let mut packet = ipv4_packet_with_payload(local, remote, 1234, 443, FLAG_SYN, &payload);
            assert!(nat.rewrite(&mut packet) == Outcome::Handled);
            assert_eq!(ipv4_checksum(&packet[..20]), 0, "ipv4 header len {len}");
            let mut expected_header = packet[..20].to_vec();
            expected_header[10..12].fill(0);
            assert_eq!(
                u16::from_be_bytes([packet[10], packet[11]]),
                ipv4_checksum(&expected_header),
                "ipv4 header bytes len {len}"
            );
            assert_eq!(
                tcp_checksum(&peer.octets(), &local.octets(), &packet[20..]),
                0,
                "ipv4 tcp len {len}"
            );
            let mut expected = packet.clone();
            expected[36..38].fill(0);
            let want = tcp_checksum(&peer.octets(), &local.octets(), &expected[20..]);
            assert_eq!(
                u16::from_be_bytes([packet[36], packet[37]]),
                want,
                "ipv4 tcp bytes len {len}"
            );
            let mut nat = Nat::new(local6.into(), peer6.into(), 40_000, false);
            let mut packet =
                ipv6_packet_with_payload(local6, remote6, 1234, 443, FLAG_SYN, &payload);
            assert!(nat.rewrite(&mut packet) == Outcome::Handled);
            assert_eq!(
                tcp_checksum(&peer6.octets(), &local6.octets(), &packet[40..]),
                0,
                "ipv6 tcp len {len}"
            );
            let mut expected = packet.clone();
            expected[56..58].fill(0);
            let want = tcp_checksum(&peer6.octets(), &local6.octets(), &expected[40..]);
            assert_eq!(
                u16::from_be_bytes([packet[56], packet[57]]),
                want,
                "ipv6 tcp bytes len {len}"
            );
        }
    }

    #[test]
    fn a_reverse_rewrite_keeps_the_checksum_of_every_payload_length() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let peer = Ipv4Addr::new(198, 18, 0, 2);
        let remote = Ipv4Addr::new(203, 0, 113, 7);
        let local6 = "fdfe:dcba:9876::1".parse::<Ipv6Addr>().unwrap();
        let peer6 = "fdfe:dcba:9876::2".parse::<Ipv6Addr>().unwrap();
        let remote6 = "2001:db8::7".parse::<Ipv6Addr>().unwrap();
        for len in [0usize, 1, 2, 3, 17, 64, 1_460, 4_096, 65_475] {
            let payload: Vec<u8> = (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect();
            let mut nat = Nat::new(local.into(), peer.into(), 40_000, false);
            let mut forward =
                ipv4_packet_with_payload(local, remote, 1234, 443, FLAG_SYN, &payload);
            assert!(nat.rewrite(&mut forward) == Outcome::Handled);
            let nat_port = u16::from_be_bytes([forward[20], forward[21]]);
            let mut reverse = ipv4_packet_with_payload(
                local,
                peer,
                40_000,
                nat_port,
                FLAG_SYN | FLAG_ACK,
                &payload,
            );
            assert!(nat.rewrite(&mut reverse) == Outcome::Handled);
            assert_eq!(
                fields(&reverse),
                (remote, local, 443, 1234),
                "ipv4 reverse fields len {len}"
            );
            assert_eq!(
                ipv4_checksum(&reverse[..20]),
                0,
                "ipv4 reverse header len {len}"
            );
            let mut expected_header = reverse[..20].to_vec();
            expected_header[10..12].fill(0);
            assert_eq!(
                u16::from_be_bytes([reverse[10], reverse[11]]),
                ipv4_checksum(&expected_header),
                "ipv4 reverse header bytes len {len}"
            );
            assert_eq!(
                tcp_checksum(&remote.octets(), &local.octets(), &reverse[20..]),
                0,
                "ipv4 reverse tcp len {len}"
            );
            let mut expected = reverse.clone();
            expected[36..38].fill(0);
            assert_eq!(
                u16::from_be_bytes([reverse[36], reverse[37]]),
                tcp_checksum(&remote.octets(), &local.octets(), &expected[20..]),
                "ipv4 reverse tcp bytes len {len}"
            );

            let mut nat = Nat::new(local6.into(), peer6.into(), 40_000, false);
            let mut forward =
                ipv6_packet_with_payload(local6, remote6, 1234, 443, FLAG_SYN, &payload);
            assert!(nat.rewrite(&mut forward) == Outcome::Handled);
            let nat_port = u16::from_be_bytes([forward[40], forward[41]]);
            let mut reverse = ipv6_packet_with_payload(
                local6,
                peer6,
                40_000,
                nat_port,
                FLAG_SYN | FLAG_ACK,
                &payload,
            );
            assert!(nat.rewrite(&mut reverse) == Outcome::Handled);
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&reverse[8..24]).unwrap());
            let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&reverse[24..40]).unwrap());
            assert_eq!(source, remote6, "ipv6 reverse source len {len}");
            assert_eq!(destination, local6, "ipv6 reverse destination len {len}");
            assert_eq!(
                u16::from_be_bytes([reverse[40], reverse[41]]),
                443,
                "ipv6 reverse source port len {len}"
            );
            assert_eq!(
                u16::from_be_bytes([reverse[42], reverse[43]]),
                1234,
                "ipv6 reverse destination port len {len}"
            );
            assert_eq!(
                tcp_checksum(&remote6.octets(), &local6.octets(), &reverse[40..]),
                0,
                "ipv6 reverse tcp len {len}"
            );
            let mut expected = reverse.clone();
            expected[56..58].fill(0);
            assert_eq!(
                u16::from_be_bytes([reverse[56], reverse[57]]),
                tcp_checksum(&remote6.octets(), &local6.octets(), &expected[40..]),
                "ipv6 reverse tcp bytes len {len}"
            );
        }
    }

    #[test]
    fn a_fragment_stays_for_the_userspace_stack() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let mut nat = Nat::new(
            local.into(),
            Ipv4Addr::new(198, 18, 0, 2).into(),
            40_000,
            false,
        );
        let mut packet = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_SYN);
        packet[6] |= 0x20;
        let original = packet.clone();
        assert!(nat.rewrite(&mut packet) == Outcome::Other);
        assert_eq!(packet, original);
    }

    #[test]
    fn a_second_flow_gets_its_own_port_and_a_closed_one_is_replaced() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let nat_ip = Ipv4Addr::new(198, 18, 0, 2);
        let mut nat = Nat::new(local.into(), nat_ip.into(), 40_000, false);
        let mut first = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut first) == Outcome::Handled);
        let first_port = fields(&first).2;

        let mut second = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1235, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut second) == Outcome::Handled);
        assert_ne!(fields(&second).2, first_port);

        let (_, generation) = nat
            .accepted(SocketAddr::new(nat_ip.into(), first_port))
            .expect("the flow is accepted");
        nat.closed(first_port, generation);
        let mut late = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_ACK);
        assert!(nat.rewrite(&mut late) == Outcome::Handled);
        assert_eq!(fields(&late).2, first_port);
        let mut again = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut again) == Outcome::Handled);
        assert_ne!(fields(&again).2, first_port);
    }

    #[test]
    fn a_foreign_family_segment_stays_for_the_userspace_stack() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let mut nat = Nat::new(
            local.into(),
            Ipv4Addr::new(198, 18, 0, 2).into(),
            40_000,
            false,
        );
        let mut packet = ipv6_packet(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            1234,
            443,
            FLAG_SYN,
        );
        assert!(nat.rewrite(&mut packet) == Outcome::Other);
        assert!(nat.forward.is_empty());
        assert!(nat.ports.is_empty());
    }

    #[test]
    fn a_stale_close_keeps_a_reused_port_open() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let peer = Ipv4Addr::new(198, 18, 0, 2);
        let mut nat = Nat::new(local.into(), peer.into(), 40_000, false);
        let mut packet = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut packet) == Outcome::Handled);
        let port = fields(&packet).2;
        let (_, generation) = nat
            .accepted(SocketAddr::new(peer.into(), port))
            .expect("the flow is accepted");
        nat.closed(port, generation.wrapping_add(1));
        assert!(!nat.ports.get(&port).expect("the mapping").closed);
        nat.closed(port, generation);
        assert!(nat.ports.get(&port).expect("the mapping").closed);
    }

    #[test]
    fn an_open_accepted_mapping_survives_the_idle_timeout() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let peer = Ipv4Addr::new(198, 18, 0, 2);
        let mut nat = Nat::new(local.into(), peer.into(), 40_000, false);
        let mut packet = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut packet) == Outcome::Handled);
        let port = fields(&packet).2;
        let (_, generation) = nat
            .accepted(SocketAddr::new(peer.into(), port))
            .expect("the flow is accepted");
        nat.ports.get_mut(&port).expect("the mapping").last = Instant::now()
            .checked_sub(NAT_IDLE + Duration::from_secs(1))
            .unwrap();
        nat.sweep(Instant::now());
        assert!(nat.ports.contains_key(&port));
        nat.closed(port, generation);
        nat.ports.get_mut(&port).expect("the mapping").last = Instant::now()
            .checked_sub(NAT_LINGER + Duration::from_secs(1))
            .unwrap();
        nat.sweep(Instant::now());
        assert!(!nat.ports.contains_key(&port));
        assert!(nat.forward.is_empty());
    }

    #[test]
    fn a_hybrid_fallback_flow_keeps_the_userspace_stack() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let peer = Ipv4Addr::new(198, 18, 0, 2);
        let remote = Ipv4Addr::new(203, 0, 113, 7);
        let mut nat = Nat::new(local.into(), peer.into(), 40_000, true);
        let now = Instant::now();
        for offset in 0..NAT_MAX {
            let port = NAT_PORT_BASE + offset as u16;
            nat.ports.insert(
                port,
                Mapping {
                    key: FlowKey {
                        source: local.into(),
                        source_port: offset as u16,
                        destination: remote.into(),
                        destination_port: 443,
                    },
                    accepted: false,
                    closed: false,
                    generation: 0,
                    last: now,
                },
            );
        }
        let mut syn = ipv4_packet(local, remote, 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut syn) == Outcome::UnhandledTcp);
        nat.ports.remove(&NAT_PORT_BASE);
        let mut again = ipv4_packet(local, remote, 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut again) == Outcome::UnhandledTcp);
        let mut reverse = ipv4_packet(remote, local, 443, 1234, FLAG_ACK);
        assert!(nat.rewrite(&mut reverse) == Outcome::UnhandledTcp);
        let mut fin = ipv4_packet(local, remote, 1234, 443, FLAG_FIN | FLAG_ACK);
        assert!(nat.rewrite(&mut fin) == Outcome::UnhandledTcp);
        let mut replacement = ipv4_packet(local, remote, 1234, 443, FLAG_SYN);
        assert!(nat.rewrite(&mut replacement) == Outcome::Handled);
    }

    #[test]
    fn an_unmatched_segment_stays_for_the_userspace_fallback() {
        let local = Ipv4Addr::new(198, 18, 0, 1);
        let mut nat = Nat::new(
            local.into(),
            Ipv4Addr::new(198, 18, 0, 2).into(),
            40_000,
            false,
        );
        let mut packet = ipv4_packet(local, Ipv4Addr::new(203, 0, 113, 7), 1234, 443, FLAG_ACK);
        assert!(nat.rewrite(&mut packet) == Outcome::UnhandledTcp);
    }

    #[test]
    fn a_peer_address_is_inside_the_prefix_and_not_the_local_one() {
        assert_eq!(
            nat_peer(Ipv4Addr::new(198, 18, 0, 1).into(), 15),
            Some(Ipv4Addr::new(198, 18, 0, 2).into())
        );
        assert_eq!(
            nat_peer(Ipv4Addr::new(198, 18, 0, 2).into(), 30),
            Some(Ipv4Addr::new(198, 18, 0, 1).into())
        );
        assert_eq!(
            nat_peer("fdfe:dcba:9876::1".parse().unwrap(), 64),
            Some("fdfe:dcba:9876::2".parse().unwrap())
        );
        assert_eq!(
            nat_peer(Ipv4Addr::new(198, 18, 0, 1).into(), 0),
            Some(Ipv4Addr::new(0, 0, 0, 1).into())
        );
        assert_eq!(nat_peer(Ipv4Addr::new(198, 18, 0, 1).into(), 31), None);
        assert_eq!(nat_peer(Ipv4Addr::new(198, 18, 0, 1).into(), 32), None);
    }
}
