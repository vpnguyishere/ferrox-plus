//! The userspace IP stack a `WireGuard` tunnel carries: `smoltcp` owns the TCP
//! state machine, its windows and retransmits, while this file owns only the
//! bridge between a tunnel's inner packets and the local streams.
//!
//! A client connects a local flow to the destination it asked for; a server
//! listens on every destination address and port at once (`any_ip`, and a
//! wildcard listener raised per SYN), so a packet addressed to 192.0.2.1:7 is
//! accepted even though no interface owns that address. Datagrams do not need
//! the state machine: the tunnel carries them as UDP, and the tree's own
//! datagram lane dials them, so this file builds and parses their packets
//! directly and leaves their routing to the caller.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, UdpSocket};
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use ferrox_core::foxy::connectip::{
    icmp_echo_reply, ipv4_checksum, tcp_checksum, udp_datagram, udp_from_packet, UdpDatagram,
    IPV4_HEADER, IPV6_HEADER, PROTOCOL_UDP,
};
#[cfg(test)]
use ferrox_core::wireguard::transport::HEADER_SIZE as WG_HEADER_SIZE;
use ferrox_core::wireguard::transport::TAG_SIZE as WG_TAG_SIZE;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    CongestionControl, RecvError, SendError, Socket as TcpSocket, SocketBuffer, State,
};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};

use crate::conn::Connection;
use crate::proxy::{serve_device_flow, serve_udp_lane, Destination, Outbound};
use crate::wireguard::{DeviceConfig, PeerConfig};

/// The receive side of one flow: a peer may have this much in flight before a
/// window update, which is the reference's order of magnitude.
const TCP_RECV_BUFFER: usize = 1024 * 1024;
/// The send side of one flow: a stream moves this queue per round trip, and a
/// tunnel's round trip is milliseconds, so the queue bounds a fast link.
const TCP_SEND_BUFFER: usize = 1024 * 1024;
/// One turn drains at most this many local reads into a flow, so a download
/// does not wait a whole tick for each buffer when the peer is far ahead.
const UP_BURST: usize = 64;
/// The most answers a client races for one target.
const RACES: usize = 8;
/// A pinned lane re-races its answers after this long without a reply.
const LANE_RACE_AGAIN: Duration = Duration::from_secs(2);
/// The most names one lane gives their own tunnel source port.
const LANE_PORTS: usize = 256;
static NEXT_LANE_PORT: AtomicU16 = AtomicU16::new(0);
/// How long a name waits for its answer inside the tunnel before the caller
/// falls back to the host resolver.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);
/// The tunnel source ports a DNS query may take, above every lane port.
const DNS_PORT_BASE: u16 = 60000;
const DNS_PORT_SPAN: u16 = 5535;
static NEXT_DNS_PORT: AtomicU16 = AtomicU16::new(0);
/// One racing candidate's two socket buffers.
const RACE_BYTES: usize = TCP_RECV_BUFFER + TCP_SEND_BUFFER;
/// The most memory every flow's extra candidates may reserve together.
const RACE_BUDGET: usize = 256 * 1024 * 1024;
/// The most listeners one inbound may hold across every destination port. Each
/// listener owns both TCP buffers, so a spoofed SYN stream must not grow the
/// set past a fixed share of memory.
const LISTENERS: usize = 64;
/// The most listeners one destination port may hold, so concurrent SYNs to one
/// service do not wait for a retransmit while the total stays bounded.
const LISTENERS_PER_PORT: usize = 8;
/// How long a listener may wait for a handshake before it is reclaimed, so a
/// spoofed SYN cannot hold a slot for the life of the inbound.
const LISTENER_TTL: Duration = Duration::from_secs(60);
/// The stack's poll interval when no packet arrived: a target's answer can be
/// ready with no tunnel packet to wake the stack, so the wait bounds a request's
/// round trip and stays short.
const TICK: Duration = Duration::from_millis(1);
/// A TUN carries no tunnel reader to wake the stack, so an idle wait is also
/// the bound on a target's answer; keep it below a request's round trip.
const TUN_TICK: Duration = Duration::from_micros(100);
/// Datagram lanes are idle most of their life; a ten millisecond wake is a
/// poll of their own, not a bound on a request.
const LANE_TICK: Duration = Duration::from_millis(10);
/// The most inner packets the tunnel reader may queue before the stack drains
/// them; past it the oldest is dropped, as a full device would drop.
const RX_PACKETS: usize = 4096;
/// The most datagrams one stack turn consumes before it polls: a turn that
/// drained a long ACK backlog would answer with a burst the peer's socket
/// cannot hold, and a TCP retransmit costs more than the poll saves.
const RX_BURST: usize = 256;
/// The most datagrams one stack turn emits: a peer's default UDP socket holds
/// about 212 KiB, so a 128-datagram chunk per flow stays under it and does not
/// lose tail segments, whose retransmit costs a whole RTO.
const TX_BURST: usize = 128;
/// Segment buffers the stack keeps for the TUN writer to refill; a reused
/// buffer costs no allocation on the transmit path.
pub(crate) const TX_POOL: usize = 256;
/// The most server datagram lanes one inbound may hold.
const UDP_FLOWS: usize = 4096;
/// The largest inner packet the server's TCP may build, so a read becomes one
/// segment the peer reassembles instead of dozens it must acknowledge.
const INNER_MTU: usize = 65_535;
/// The largest inner packet one tunnel datagram carries.
const TUNNEL_FRAGMENT: usize = 1_344;
/// The most bytes one stack holds while it reassembles inner fragments.
const REASSEMBLY_BYTES: usize = 8 * 1024 * 1024;
/// The most incomplete sets one stack holds, so a flood of first fragments is
/// bounded by count as well as bytes.
const REASSEMBLY_SETS: usize = 1_024;
/// The most incomplete sets one peer may hold, so its flood cannot evict
/// another peer's work.
const REASSEMBLY_PEER_SETS: usize = 64;
/// The most bytes one peer may reserve, so two peers cannot fill the shared
/// budget and refuse every other peer.
const REASSEMBLY_PEER_BYTES: usize = REASSEMBLY_BYTES / 16;
/// The most ranges one set may track; adjacent fragments merge, so a normal
/// split stays far below this.
const REASSEMBLY_RANGES: usize = 256;
/// How long an incomplete fragment set waits for the rest.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_FRAGMENT_ID: AtomicU32 = AtomicU32::new(1);

/// One decrypted inner packet and the peer that authenticated it.
pub(crate) struct Packet {
    pub(crate) peer: [u8; 32],
    pub(crate) bytes: Vec<u8>,
    pub(crate) at: usize,
}

/// One local stream the client asks the stack to connect.
pub(crate) struct ClientFlow {
    pub(crate) client: Connection,
    pub(crate) destinations: Vec<SocketAddr>,
    pub(crate) prefix: Vec<u8>,
}

/// The route table of live client datagram lanes, keyed by the loopback relay
/// port each lane bound: an inner reply names that port, so the reader hands it
/// to the lane that asked.
pub(crate) type UdpRoutes = Arc<Mutex<HashMap<u16, Sender<Vec<u8>>>>>;

/// An in-memory IP device: the reader pushes inner packets into `rx`, and every
/// packet `smoltcp` emits is left in `tx` for the tunnel writer.
struct QueueDevice {
    rx: VecDeque<(Vec<u8>, usize)>,
    tx: VecDeque<Vec<u8>>,
    tx_pool: Vec<Vec<u8>>,
    tx_reuse: Option<Receiver<Vec<u8>>>,
    mtu: usize,
    headroom: usize,
    recycle: Option<Sender<Vec<u8>>>,
}

impl QueueDevice {
    /// A device whose transmit tokens leave `headroom` bytes for the tunnel's record header.
    fn new(mtu: usize, headroom: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            tx_pool: Vec::new(),
            tx_reuse: None,
            mtu,
            headroom,
            recycle: None,
        }
    }

    /// Queue an inner packet, recycling the oldest slot when the queue is full.
    fn push(&mut self, packet: Vec<u8>, at: usize) {
        if self.rx.len() >= RX_PACKETS {
            if let Some((buffer, at)) = self.rx.pop_front() {
                self.recycle(buffer, at);
            }
        }
        self.rx.push_back((packet, at));
    }

    /// Refill the segment pool from the writer, which returns every buffer it
    /// has copied into its aggregate.
    fn refill_tx(&mut self) {
        let Some(reuse) = self.tx_reuse.as_ref() else {
            return;
        };
        while self.tx_pool.len() < TX_POOL {
            match reuse.try_recv() {
                Ok(buffer) => self.tx_pool.push(buffer),
                Err(_) => break,
            }
        }
    }

    /// Return a receive slot to the batch, leaving copied payloads alone.
    fn recycle(&self, buffer: Vec<u8>, at: usize) {
        if at != self.headroom {
            return;
        }
        if let Some(recycle) = &self.recycle {
            let _ = recycle.send(buffer);
        }
    }

    /// A path MTU an ICMP Packet Too Big names narrows every later segment; a packet that names no usable MTU leaves it alone.
    fn absorb(&mut self, packet: &[u8]) -> bool {
        let Some(mtu) = icmp_mtu(packet) else {
            return false;
        };
        if mtu >= self.mtu {
            return false;
        }
        self.mtu = mtu;
        true
    }
}

/// The receive token that reads past a transport header and returns the slot.
struct QueueRx {
    buffer: Vec<u8>,
    at: usize,
    recycle: Option<Sender<Vec<u8>>>,
}

impl RxToken for QueueRx {
    /// Read the packet after its transport header.
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer[self.at..])
    }
}

/// Return the consumed slot after smoltcp has read its bytes.
impl Drop for QueueRx {
    /// Return the slot to the batch once smoltcp has consumed it.
    fn drop(&mut self) {
        if let Some(recycle) = self.recycle.take() {
            let _ = recycle.send(std::mem::take(&mut self.buffer));
        }
    }
}

/// The transmit token that prepends tunnel headroom and a tag to one segment.
struct QueueTx<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
    pool: &'a mut Vec<Vec<u8>>,
    headroom: usize,
}

/// Build an outgoing segment in one buffer with its tunnel headroom reserved.
impl TxToken for QueueTx<'_> {
    /// Reserve headroom, build the segment, and queue it for the tunnel.
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self.pool.pop().unwrap_or_default();
        buffer.clear();
        buffer.reserve(self.headroom + len + WG_TAG_SIZE);
        buffer.resize(self.headroom + len, 0);
        let answer = f(&mut buffer[self.headroom..]);
        self.tx.push_back(buffer);
        answer
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = QueueRx
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTx<'a>
    where
        Self: 'a;

    /// Pop one queued packet and offer its slot to smoltcp.
    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (buffer, at) = self.rx.pop_front()?;
        Some((
            QueueRx {
                buffer,
                at,
                recycle: if at == self.headroom {
                    self.recycle.clone()
                } else {
                    None
                },
            },
            QueueTx {
                tx: &mut self.tx,
                pool: &mut self.tx_pool,
                headroom: self.headroom,
            },
        ))
    }

    /// Offer a token that appends one segment to the transmit queue.
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx {
            tx: &mut self.tx,
            pool: &mut self.tx_pool,
            headroom: self.headroom,
        })
    }

    /// Report the current path MTU and an IP medium to smoltcp.
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Which local streams have bytes to read: one `poll` over every flow, so an
/// idle flow costs no read syscall per stack turn.
#[cfg(unix)]
struct Readiness {
    fds: Vec<libc::pollfd>,
    ready: Vec<bool>,
}

#[cfg(unix)]
impl Readiness {
    fn new() -> Self {
        Self {
            fds: Vec::new(),
            ready: Vec::new(),
        }
    }

    fn sync(&mut self, flows: &[Flow]) -> &[bool] {
        self.sync_locals(flows.iter().map(|flow| &flow.local))
    }

    fn sync_locals<'a>(&mut self, locals: impl Iterator<Item = &'a Connection>) -> &[bool] {
        self.fds.clear();
        for local in locals {
            self.fds.push(libc::pollfd {
                fd: local.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let answered =
            unsafe { libc::poll(self.fds.as_mut_ptr(), self.fds.len() as libc::nfds_t, 0) };
        self.ready.clear();
        for entry in &self.fds {
            self.ready.push(
                answered < 0
                    || (answered > 0
                        && entry.revents
                            & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                            != 0),
            );
        }
        &self.ready
    }
}

#[cfg(not(unix))]
struct Readiness {
    ready: Vec<bool>,
}

#[cfg(not(unix))]
impl Readiness {
    fn new() -> Self {
        Self { ready: Vec::new() }
    }

    fn sync(&mut self, flows: &[Flow]) -> &[bool] {
        self.ready.clear();
        self.ready.resize(flows.len(), true);
        &self.ready
    }
}

/// One TCP flow and the local stream on the other side of it. `pending_down`
/// holds bytes the local socket refused because its send buffer was full;
/// `pending_up` holds bytes read locally that the TCP window has not accepted.
#[allow(clippy::struct_excessive_bools)]
struct Flow {
    handle: SocketHandle,
    local: Connection,
    local_port: u16,
    races: Vec<(SocketHandle, u16)>,
    pending_down: Vec<u8>,
    pending_down_at: usize,
    pending_up: Vec<u8>,
    pending_up_at: usize,
    up_eof: bool,
    sent_fin: bool,
    down_eof: bool,
    down_shutdown: bool,
    established: bool,
    done: bool,
}

impl Flow {
    fn new(handle: SocketHandle, local: Connection, local_port: u16) -> Self {
        Self {
            handle,
            local,
            local_port,
            races: Vec::new(),
            pending_down: Vec::new(),
            pending_down_at: 0,
            pending_up: Vec::new(),
            pending_up_at: 0,
            up_eof: false,
            sent_fin: false,
            down_eof: false,
            down_shutdown: false,
            established: false,
            done: false,
        }
    }

    fn down_pending(&self) -> bool {
        self.pending_down_at < self.pending_down.len()
    }

    fn up_pending(&self) -> bool {
        self.pending_up_at < self.pending_up.len()
    }

    fn stage_down(&mut self, bytes: &[u8]) {
        self.pending_down.clear();
        self.pending_down.extend_from_slice(bytes);
        self.pending_down_at = 0;
    }

    fn stage_up(&mut self, bytes: &[u8]) {
        self.pending_up.clear();
        self.pending_up.extend_from_slice(bytes);
        self.pending_up_at = 0;
    }

    fn adopt(
        &mut self,
        sockets: &mut SocketSet<'_>,
        ports: &mut HashSet<u16>,
        retiring: &mut Vec<(SocketHandle, u16, bool)>,
        race_bytes: &mut usize,
    ) {
        if self.races.is_empty() {
            if !self.established && sockets.get::<TcpSocket>(self.handle).state() == State::Closed {
                self.done = true;
            }
            return;
        }
        loop {
            let primary = sockets.get::<TcpSocket>(self.handle).state();
            if matches!(primary, State::Established | State::CloseWait) {
                for (handle, port) in self.races.drain(..) {
                    sockets.get_mut::<TcpSocket>(handle).abort();
                    retiring.push((handle, port, true));
                }
                return;
            }
            let winner = self.races.iter().position(|(handle, _)| {
                matches!(
                    sockets.get::<TcpSocket>(*handle).state(),
                    State::Established | State::CloseWait
                )
            });
            if let Some(winner) = winner {
                let (handle, port) = self.races.remove(winner);
                sockets.get_mut::<TcpSocket>(self.handle).abort();
                retiring.push((self.handle, self.local_port, false));
                for (handle, port) in self.races.drain(..) {
                    sockets.get_mut::<TcpSocket>(handle).abort();
                    retiring.push((handle, port, true));
                }
                self.handle = handle;
                self.local_port = port;
                *race_bytes -= RACE_BYTES;
                return;
            }
            if primary != State::Closed {
                break;
            }
            let next = self
                .races
                .iter()
                .position(|(handle, _)| sockets.get::<TcpSocket>(*handle).state() != State::Closed);
            let Some(next) = next else {
                for (handle, port) in self.races.drain(..) {
                    sockets.remove(handle);
                    ports.remove(&port);
                    *race_bytes -= RACE_BYTES;
                }
                self.done = true;
                return;
            };
            sockets.remove(self.handle);
            ports.remove(&self.local_port);
            let (handle, port) = self.races.remove(next);
            self.handle = handle;
            self.local_port = port;
            *race_bytes -= RACE_BYTES;
        }
        let closed: Vec<usize> = self
            .races
            .iter()
            .enumerate()
            .filter_map(|(index, (handle, _))| {
                (sockets.get::<TcpSocket>(*handle).state() == State::Closed).then_some(index)
            })
            .collect();
        for index in closed.into_iter().rev() {
            let (handle, port) = self.races.swap_remove(index);
            sockets.remove(handle);
            ports.remove(&port);
            *race_bytes -= RACE_BYTES;
        }
    }
}

/// What a stack loop sends the tunnel writer. The bound is the caller's: a
/// carrier whose writer can fall behind uses `sync_channel`, so a fast inner
/// producer stalls instead of growing the queue without limit.
#[derive(Clone, Debug)]
pub(crate) enum ToTunnel {
    Unbounded(Sender<Vec<u8>>),
    Bounded(SyncSender<Vec<u8>>),
}

impl ToTunnel {
    pub(crate) fn send(&self, packet: Vec<u8>) -> Result<(), mpsc::SendError<Vec<u8>>> {
        match self {
            Self::Unbounded(sender) => sender.send(packet),
            Self::Bounded(sender) => sender.send(packet),
        }
    }
}

impl From<Sender<Vec<u8>>> for ToTunnel {
    fn from(sender: Sender<Vec<u8>>) -> Self {
        Self::Unbounded(sender)
    }
}

impl From<SyncSender<Vec<u8>>> for ToTunnel {
    fn from(sender: SyncSender<Vec<u8>>) -> Self {
        Self::Bounded(sender)
    }
}
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum FragmentKey {
    V4 {
        peer: [u8; 32],
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        id: u16,
    },
    V6 {
        peer: [u8; 32],
        source: [u8; 16],
        destination: [u8; 16],
        protocol: u8,
        id: u32,
    },
}

type FragmentParts = (FragmentKey, usize, usize, usize, usize, bool, Option<usize>);

impl FragmentKey {
    fn peer(&self) -> [u8; 32] {
        match *self {
            Self::V4 { peer, .. } | Self::V6 { peer, .. } => peer,
        }
    }
}

struct FragmentSet {
    at: usize,
    header: Vec<u8>,
    next_header: u8,
    payload: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    last: Option<usize>,
    started: StdInstant,
}

impl FragmentSet {
    fn assemble(&self, total: usize) -> Vec<u8> {
        let header_len = self.header.len();
        let mut packet = Vec::with_capacity(self.at + header_len + total);
        packet.resize(self.at, 0);
        packet.extend_from_slice(&self.header);
        packet.extend_from_slice(&self.payload[..total]);
        if packet[self.at] >> 4 == 4 {
            let length = (header_len + total) as u16;
            packet[self.at + 2..self.at + 4].copy_from_slice(&length.to_be_bytes());
            packet[self.at + 4..self.at + 6].copy_from_slice(&0u16.to_be_bytes());
            packet[self.at + 6..self.at + 8].copy_from_slice(&0u16.to_be_bytes());
            packet[self.at + 10..self.at + 12].copy_from_slice(&0u16.to_be_bytes());
            let checksum = ipv4_checksum(&packet[self.at..self.at + header_len]);
            packet[self.at + 10..self.at + 12].copy_from_slice(&checksum.to_be_bytes());
        } else {
            packet[self.at + 4..self.at + 6].copy_from_slice(&(total as u16).to_be_bytes());
            packet[self.at + 6] = self.next_header;
        }
        packet
    }
}

fn merge_ranges(ranges: &mut Vec<(usize, usize)>) {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, finish) in ranges.drain(..) {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(finish),
            _ => merged.push((start, finish)),
        }
    }
    *ranges = merged;
}

/// One inner packet, the fragments it may be split into, and the sets waiting
/// for the rest. A set is bounded in time and memory, and a completed one is
/// handed back as the packet the sender wrote.
#[derive(Default)]
struct Reassembly {
    parts: HashMap<FragmentKey, FragmentSet>,
    bytes: usize,
}

enum Reassembled {
    Pass,
    Held,
    Complete(Vec<u8>),
}

impl Reassembly {
    fn accept(&mut self, peer: [u8; 32], packet: &[u8], at: usize) -> Reassembled {
        let Some((key, header_len, offset, payload_at, end, _more, total)) = fragment(peer, packet)
        else {
            return Reassembled::Pass;
        };
        self.expire();
        if end > INNER_MTU || (packet[0] >> 4 == 4 && header_len + end > 65_535) {
            return Reassembled::Held;
        }
        if offset == end {
            return Reassembled::Held;
        }
        if !self.parts.contains_key(&key) {
            if !self.make_room(end, key) {
                return Reassembled::Held;
            }
            self.parts.insert(
                key,
                FragmentSet {
                    at,
                    header: Vec::new(),
                    next_header: 0,
                    payload: Vec::new(),
                    ranges: Vec::new(),
                    last: None,
                    started: StdInstant::now(),
                },
            );
        }
        if self.parts.get(&key).is_some_and(|part| part.at != at) {
            if let Some(part) = self.parts.remove(&key) {
                self.bytes -= part.payload.len();
            }
            return Reassembled::Held;
        }
        let len = self.parts.get(&key).map_or(0, |part| part.payload.len());
        if end > len {
            let grow = end - len;
            if !self.make_growth_room(grow, &key) {
                self.drop(&key);
                return Reassembled::Held;
            }
            self.bytes += grow;
            self.parts
                .get_mut(&key)
                .expect("the set was just admitted")
                .payload
                .resize(end, 0);
        }
        let part = self.parts.get_mut(&key).expect("the set was just admitted");
        if offset == 0 && part.header.is_empty() {
            part.header.extend_from_slice(&packet[..header_len]);
            part.next_header = if packet[0] >> 4 == 6 { packet[40] } else { 0 };
        }
        if part
            .ranges
            .iter()
            .any(|&(start, finish)| offset < finish && start < end)
        {
            if let Some(part) = self.parts.remove(&key) {
                self.bytes -= part.payload.len();
            }
            return Reassembled::Held;
        }
        if part
            .last
            .is_some_and(|last| end > last || total.is_some_and(|next| next != last))
            || total.is_some_and(|last| part.ranges.iter().any(|&(_, finish)| finish > last))
        {
            if let Some(part) = self.parts.remove(&key) {
                self.bytes -= part.payload.len();
            }
            return Reassembled::Held;
        }
        part.payload[offset..end].copy_from_slice(&packet[payload_at..payload_at + (end - offset)]);
        part.ranges.push((offset, end));
        part.ranges.sort_unstable();
        merge_ranges(&mut part.ranges);
        if part.ranges.len() > REASSEMBLY_RANGES {
            self.drop(&key);
            return Reassembled::Held;
        }
        if let Some(total) = total {
            part.last = Some(total);
        }
        let Some(total) = part.last else {
            return Reassembled::Held;
        };
        let mut covered = 0;
        for &(start, finish) in &part.ranges {
            if start > covered {
                break;
            }
            covered = covered.max(finish);
        }
        if covered < total || part.header.is_empty() {
            return Reassembled::Held;
        }
        let part = self.parts.remove(&key).expect("a complete set");
        self.bytes -= part.payload.len();
        Reassembled::Complete(part.assemble(total))
    }

    fn make_room(&mut self, need: usize, key: FragmentKey) -> bool {
        let peer = key.peer();
        loop {
            let (sets, bytes) = self.peer_usage(peer);
            if sets < REASSEMBLY_PEER_SETS && bytes + need <= REASSEMBLY_PEER_BYTES {
                break;
            }
            let Some(oldest) = self.oldest(peer) else {
                return false;
            };
            self.drop(&oldest);
        }
        while self.bytes + need > REASSEMBLY_BYTES || self.parts.len() >= REASSEMBLY_SETS {
            let Some(victim) = self.fair_victim(None) else {
                return false;
            };
            self.drop(&victim);
        }
        true
    }

    fn make_growth_room(&mut self, grow: usize, key: &FragmentKey) -> bool {
        let peer = key.peer();
        loop {
            let (_, bytes) = self.peer_usage(peer);
            if bytes + grow <= REASSEMBLY_PEER_BYTES {
                break;
            }
            let Some(oldest) = self.oldest_except(peer, Some(key)) else {
                return false;
            };
            self.drop(&oldest);
        }
        while self.bytes + grow > REASSEMBLY_BYTES {
            let Some(victim) = self.fair_victim(Some(key)) else {
                return false;
            };
            self.drop(&victim);
        }
        true
    }

    fn peer_usage(&self, peer: [u8; 32]) -> (usize, usize) {
        self.parts
            .iter()
            .filter(|(key, _)| key.peer() == peer)
            .fold((0, 0), |(sets, bytes), (_, part)| {
                (sets + 1, bytes + part.payload.len())
            })
    }

    fn fair_victim(&self, keep: Option<&FragmentKey>) -> Option<FragmentKey> {
        let mut peers: HashMap<[u8; 32], (usize, usize)> = HashMap::new();
        for (key, part) in &self.parts {
            if Some(key) == keep {
                continue;
            }
            let entry = peers.entry(key.peer()).or_default();
            entry.0 += 1;
            entry.1 += part.payload.len();
        }
        let (peer, usage) = peers
            .iter()
            .max_by_key(|(_, (sets, bytes))| (*sets, *bytes))?;
        if usage.0 <= 1 {
            return None;
        }
        self.oldest_except(*peer, keep)
    }

    fn oldest(&self, peer: [u8; 32]) -> Option<FragmentKey> {
        self.oldest_except(peer, None)
    }

    fn oldest_except(&self, peer: [u8; 32], keep: Option<&FragmentKey>) -> Option<FragmentKey> {
        self.parts
            .iter()
            .filter(|(key, _)| key.peer() == peer && !keep.is_some_and(|keep| *key == keep))
            .min_by_key(|(_, part)| part.started)
            .map(|(key, _)| *key)
    }

    fn drop(&mut self, key: &FragmentKey) {
        if let Some(part) = self.parts.remove(key) {
            self.bytes -= part.payload.len();
        }
    }

    fn expire(&mut self) {
        let now = StdInstant::now();
        let stale: Vec<_> = self
            .parts
            .iter()
            .filter(|(_, part)| now.duration_since(part.started) > REASSEMBLY_TIMEOUT)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            if let Some(part) = self.parts.remove(&key) {
                self.bytes -= part.payload.len();
            }
        }
    }
}

/// The key, header length, fragment offset, payload start, declared payload end,
/// more-fragments flag and original payload length of an IPv4 or IPv6 fragment.
fn fragment(peer: [u8; 32], packet: &[u8]) -> Option<FragmentParts> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < IPV4_HEADER {
                return None;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            if header < IPV4_HEADER || total < header || total > packet.len() {
                return None;
            }
            let fields = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
            let offset = usize::from(fields & 0x1fff) * 8;
            let more = fields & 0x2000 != 0;
            if offset == 0 && !more {
                return None;
            }
            let source = <[u8; 4]>::try_from(packet.get(12..16)?).ok()?;
            let destination = <[u8; 4]>::try_from(packet.get(16..20)?).ok()?;
            let key = FragmentKey::V4 {
                peer,
                source,
                destination,
                protocol: *packet.get(9)?,
                id: u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]),
            };
            let end = offset + total - header;
            Some((
                key,
                header,
                offset,
                header,
                end,
                more,
                (!more).then_some(end),
            ))
        }
        6 => {
            if packet.len() < IPV6_HEADER + 8 || packet.get(6) != Some(&44) {
                return None;
            }
            let end =
                IPV6_HEADER + usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
            if end > packet.len() || end < IPV6_HEADER + 8 {
                return None;
            }
            let fields = u16::from_be_bytes([*packet.get(42)?, *packet.get(43)?]);
            let offset = usize::from(fields >> 3) * 8;
            let more = fields & 1 != 0;
            let payload_at = IPV6_HEADER + 8;
            let source = <[u8; 16]>::try_from(packet.get(8..24)?).ok()?;
            let destination = <[u8; 16]>::try_from(packet.get(24..40)?).ok()?;
            let key = FragmentKey::V6 {
                peer,
                source,
                destination,
                protocol: *packet.get(40)?,
                id: u32::from_be_bytes([
                    *packet.get(44)?,
                    *packet.get(45)?,
                    *packet.get(46)?,
                    *packet.get(47)?,
                ]),
            };
            let total = offset + end - payload_at;
            Some((
                key,
                IPV6_HEADER,
                offset,
                payload_at,
                total,
                more,
                (!more).then_some(total),
            ))
        }
        _ => None,
    }
}

/// The IP header length, TCP header length and packet length of a TCP segment.
fn tcp_view(packet: &[u8]) -> Option<(usize, usize, usize)> {
    let (ip_header, total) = match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            if header < IPV4_HEADER || total < header + 20 || total > packet.len() {
                return None;
            }
            (header, total)
        }
        6 => {
            if packet.len() < IPV6_HEADER || packet.get(6) != Some(&PROTOCOL_TCP) {
                return None;
            }
            let total =
                IPV6_HEADER + usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
            if total < IPV6_HEADER + 20 || total > packet.len() {
                return None;
            }
            (IPV6_HEADER, total)
        }
        _ => return None,
    };
    let tcp_header = usize::from(*packet.get(ip_header + 12)? >> 4) * 4;
    if tcp_header < 20 || ip_header + tcp_header > total {
        return None;
    }
    Some((ip_header, tcp_header, total))
}

/// The offset of the MSS value within a TCP segment, when it carries one.
fn tcp_mss_option(segment: &[u8]) -> Option<usize> {
    let header = usize::from(*segment.get(12)? >> 4) * 4;
    if header < 20 || header > segment.len() {
        return None;
    }
    let mut at = 20;
    while at < header {
        match segment[at] {
            0 => break,
            1 => at += 1,
            kind => {
                let length = usize::from(*segment.get(at + 1)?);
                if length < 2 || at + length > header {
                    break;
                }
                if kind == 2 && length == 4 {
                    return Some(at + 2);
                }
                at += length;
            }
        }
    }
    None
}

/// Set a TCP segment's advertised MSS and its checksum, when it carries one.
fn set_tcp_mss(packet: &mut [u8], at: usize, mss: u16) -> bool {
    let Some((ip_header, _, total)) = tcp_view(&packet[at..]) else {
        return false;
    };
    let tcp_at = at + ip_header;
    let Some(option) = tcp_mss_option(&packet[tcp_at..at + total]) else {
        return false;
    };
    let (source, destination, length) = match packet[at] >> 4 {
        4 => {
            let mut source = [0u8; 16];
            let mut destination = [0u8; 16];
            source[..4].copy_from_slice(&packet[at + 12..at + 16]);
            destination[..4].copy_from_slice(&packet[at + 16..at + 20]);
            (source, destination, 4)
        }
        6 => {
            let mut source = [0u8; 16];
            let mut destination = [0u8; 16];
            source.copy_from_slice(&packet[at + 8..at + 24]);
            destination.copy_from_slice(&packet[at + 24..at + 40]);
            (source, destination, 16)
        }
        _ => return false,
    };
    let segment = &mut packet[tcp_at..at + total];
    segment[option..option + 2].copy_from_slice(&mss.to_be_bytes());
    segment[16..18].copy_from_slice(&0u16.to_be_bytes());
    let checksum = tcp_checksum(&source[..length], &destination[..length], segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    true
}

fn lower_syn_ack_mss(packet: &mut [u8], at: usize, mtu: usize) {
    let Some((ip_header, _, _)) = tcp_view(&packet[at..]) else {
        return;
    };
    let flags = packet[at + ip_header + 13];
    if flags & 0x12 == 0x12 {
        let mss = mtu.saturating_sub(ip_header + 20).max(536);
        if let Ok(mss) = u16::try_from(mss) {
            let _ = set_tcp_mss(packet, at, mss);
        }
    }
}

/// Send one inner packet, split to the tunnel's datagram size when it is wider.
fn send_packet(to_tunnel: &ToTunnel, packet: Vec<u8>, headroom: usize, limit: usize) -> bool {
    if packet.len().saturating_sub(headroom) <= limit {
        return to_tunnel.send(packet).is_ok();
    }
    let Some(fragments) = fragment_packet(&packet, headroom, limit) else {
        return to_tunnel.send(packet).is_ok();
    };
    fragments
        .into_iter()
        .all(|fragment| to_tunnel.send(fragment).is_ok())
}

fn fragment_packet(packet: &[u8], headroom: usize, limit: usize) -> Option<Vec<Vec<u8>>> {
    let ip = packet.get(headroom..)?;
    match ip.first()? >> 4 {
        4 => {
            let header = usize::from(ip[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
            if header < IPV4_HEADER || total < header || headroom + total > packet.len() {
                return None;
            }
            let payload = &ip[header..total];
            if payload.is_empty() {
                return None;
            }
            let piece = (limit.saturating_sub(header) & !7).max(8);
            let id = NEXT_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed) as u16;
            let mut fragments = Vec::with_capacity(payload.len().div_ceil(piece));
            let mut at = 0;
            while at < payload.len() {
                let length = piece.min(payload.len() - at);
                let more = at + length < payload.len();
                let mut fragment = Vec::with_capacity(headroom + header + length + WG_TAG_SIZE);
                fragment.resize(headroom, 0);
                fragment.extend_from_slice(&ip[..header]);
                let total = (header + length) as u16;
                fragment[headroom + 2..headroom + 4].copy_from_slice(&total.to_be_bytes());
                fragment[headroom + 4..headroom + 6].copy_from_slice(&id.to_be_bytes());
                let offset = (at / 8) as u16;
                let flags = (if more { 0x2000 } else { 0 }) | offset;
                fragment[headroom + 6..headroom + 8].copy_from_slice(&flags.to_be_bytes());
                fragment[headroom + 10..headroom + 12].copy_from_slice(&0u16.to_be_bytes());
                fragment.extend_from_slice(&payload[at..at + length]);
                let checksum = ipv4_checksum(&fragment[headroom..headroom + header]);
                fragment[headroom + 10..headroom + 12].copy_from_slice(&checksum.to_be_bytes());
                fragments.push(fragment);
                at += length;
            }
            Some(fragments)
        }
        6 => {
            let total = IPV6_HEADER + usize::from(u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?]));
            if total < IPV6_HEADER || total > ip.len() {
                return None;
            }
            let payload = &ip[IPV6_HEADER..total];
            if payload.is_empty() {
                return None;
            }
            let piece = (limit.saturating_sub(IPV6_HEADER + 8) & !7).max(8);
            let id = NEXT_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed);
            let mut fragments = Vec::with_capacity(payload.len().div_ceil(piece));
            let mut at = 0;
            while at < payload.len() {
                let body = piece.min(payload.len() - at);
                let more = at + body < payload.len();
                let mut fragment =
                    Vec::with_capacity(headroom + IPV6_HEADER + 8 + body + WG_TAG_SIZE);
                fragment.resize(headroom, 0);
                fragment.extend_from_slice(&ip[..IPV6_HEADER]);
                let length = (8 + body) as u16;
                fragment[headroom + 4..headroom + 6].copy_from_slice(&length.to_be_bytes());
                fragment[headroom + 6] = 44;
                let fields = ((at / 8) as u16) << 3 | u16::from(more);
                fragment.extend_from_slice(&[ip[6], 0, (fields >> 8) as u8, fields as u8]);
                fragment.extend_from_slice(&id.to_be_bytes());
                fragment.extend_from_slice(&payload[at..at + body]);
                fragments.push(fragment);
                at += body;
            }
            Some(fragments)
        }
        _ => None,
    }
}

/// What the tunnel reader sends the stack.
type Packets = Receiver<Packet>;

/// One packet the reader decrypted into the client stack.
fn receive_client(stack: &mut ClientStack, packet: Packet) {
    let at = packet.at;
    let bytes = match stack
        .reassembly
        .accept(packet.peer, &packet.bytes[at..], at)
    {
        Reassembled::Pass => packet.bytes,
        Reassembled::Held => {
            stack.device.recycle(packet.bytes, at);
            return;
        }
        Reassembled::Complete(bytes) => {
            stack.device.recycle(packet.bytes, at);
            bytes
        }
    };
    if inner_protocol(&bytes[at..]) == Some(PROTOCOL_TCP) {
        stack.device.push(bytes, at);
        return;
    }
    if stack.deliver_udp(&bytes[at..]) {
        stack.device.recycle(bytes, at);
        return;
    }
    if !stack.answer_echo(&bytes[at..]) {
        stack.absorb(packet.peer, &bytes[at..]);
    }
    stack.device.recycle(bytes, at);
}

/// Run the client stack until the outbound is dropped.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn client(
    config: DeviceConfig,
    to_tunnel: impl Into<ToTunnel>,
    packets: Packets,
    flows: Receiver<ClientFlow>,
    headroom: usize,
    routes: UdpRoutes,
    recycle: Option<Sender<Vec<u8>>>,
) {
    let mut stack = ClientStack::new(&config, to_tunnel, headroom);
    stack.routes = routes;
    stack.device.recycle = recycle;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        while let Ok(flow) = flows.try_recv() {
            if let Err(error) = stack.connect(flow) {
                eprintln!("wireguard client: {error}");
            }
        }
        if client_turn(&mut stack, &packets, &mut buf) {
            return;
        }
    }
}

/// One client turn, or true once the tunnel is closed.
fn client_turn(stack: &mut ClientStack, packets: &Packets, buf: &mut [u8]) -> bool {
    let mut closed = false;
    for _ in 0..RX_BURST {
        match packets.try_recv() {
            Ok(packet) => receive_client(stack, packet),
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                closed = true;
                break;
            }
        }
    }
    let progressed = stack.poll(buf);
    if closed {
        return true;
    }
    if progressed {
        return false;
    }
    match packets.recv_timeout(TICK) {
        Ok(packet) => receive_client(stack, packet),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return true,
    }
    false
}

/// Abort was already called; remove each socket once its poll has emitted the RST.
fn retire(
    sockets: &mut SocketSet<'_>,
    ports: &mut HashSet<u16>,
    retiring: &mut Vec<(SocketHandle, u16, bool)>,
    race_bytes: &mut usize,
) {
    retiring.retain(|(handle, port, charged)| {
        if sockets.get::<TcpSocket>(*handle).state() != State::Closed {
            return true;
        }
        sockets.remove(*handle);
        ports.remove(port);
        if *charged {
            *race_bytes -= RACE_BYTES;
        }
        false
    });
}

/// Run the server stack until its inbound is dropped.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn server(
    config: DeviceConfig,
    to_tunnel: impl Into<ToTunnel>,
    packets: Packets,
    out: Outbound,
    headroom: usize,
    recycle: Option<Sender<Vec<u8>>>,
) {
    let mut stack = ServerStack::new(&config, to_tunnel, out, headroom);
    stack.device.recycle = recycle;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if server_turn(&mut stack, &packets, &mut buf, TICK) {
            return;
        }
    }
}

/// Run the server stack over a TUN until its reader is dropped.
#[cfg(unix)]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn serve_tun_device(
    config: DeviceConfig,
    packets: Receiver<Packet>,
    to_tunnel: SyncSender<Vec<u8>>,
    out: Outbound,
    recycle: Option<Sender<Vec<u8>>>,
    tx_reuse: Receiver<Vec<u8>>,
    wake: std::os::unix::net::UnixStream,
) {
    let mut stack = ServerStack::new_tun(&config, to_tunnel, out, tx_reuse);
    stack.device.recycle = recycle;
    let _ = wake.set_nonblocking(true);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut closed = false;
        for _ in 0..RX_BURST {
            match packets.try_recv() {
                Ok(packet) => stack.receive(packet),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    closed = true;
                    break;
                }
            }
        }
        let progressed = stack.poll(&mut buf);
        if closed {
            return;
        }
        if progressed {
            continue;
        }
        if wait_for_tun(&stack, &wake) {
            return;
        }
    }
}

/// Run the server stack over a TUN until its reader is dropped.
#[cfg(not(unix))]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn serve_tun_device(
    config: DeviceConfig,
    packets: Receiver<Packet>,
    to_tunnel: SyncSender<Vec<u8>>,
    out: Outbound,
    recycle: Option<Sender<Vec<u8>>>,
    tx_reuse: Receiver<Vec<u8>>,
) {
    let mut stack = ServerStack::new_tun(&config, to_tunnel, out, tx_reuse);
    stack.device.recycle = recycle;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let tick = if stack.flows.is_empty() {
            TICK
        } else {
            TUN_TICK
        };
        if server_turn(&mut stack, &packets, &mut buf, tick) {
            return;
        }
    }
}

/// Wait until the TUN reader signals a packet or a local stream has bytes; the
/// timeout services smoltcp's retransmit timers.
#[cfg(unix)]
fn wait_for_tun(stack: &ServerStack, wake: &std::os::unix::net::UnixStream) -> bool {
    let mut fds = Vec::with_capacity(stack.flows.len() + 1);
    fds.push(libc::pollfd {
        fd: wake.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    });
    for flow in &stack.flows {
        if flow.up_pending() || flow.up_eof {
            continue;
        }
        fds.push(libc::pollfd {
            fd: flow.local.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    let timeout = TICK.as_millis() as libc::c_int;
    let answered = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
    if answered <= 0 {
        return answered < 0;
    }
    if fds[0].revents & libc::POLLIN != 0 {
        let mut sink = [0u8; 256];
        let _ = unsafe { libc::read(wake.as_raw_fd(), sink.as_mut_ptr().cast(), sink.len()) };
    }
    fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

/// One server turn, or true once the inbound is closed.
fn server_turn(stack: &mut ServerStack, packets: &Packets, buf: &mut [u8], tick: Duration) -> bool {
    let mut closed = false;
    for _ in 0..RX_BURST {
        match packets.try_recv() {
            Ok(packet) => stack.receive(packet),
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                closed = true;
                break;
            }
        }
    }
    let progressed = stack.poll(buf);
    if closed {
        return true;
    }
    if progressed {
        return false;
    }
    match packets.recv_timeout(tick) {
        Ok(packet) => stack.receive(packet),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return true,
    }
    false
}

struct ClientStack {
    device: QueueDevice,
    headroom: usize,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: Vec<Flow>,
    readiness: Readiness,
    ports: HashSet<u16>,
    next_port: u16,
    race_bytes: usize,
    retiring: Vec<(SocketHandle, u16, bool)>,
    to_tunnel: ToTunnel,
    addresses: Vec<IpAddr>,
    peers: Vec<PeerConfig>,
    reassembly: Reassembly,
    fragment: usize,
    routes: UdpRoutes,
    started: StdInstant,
}

impl ClientStack {
    /// Build the client's interface, sockets and routes over a device that reserves its headroom.
    fn new(config: &DeviceConfig, to_tunnel: impl Into<ToTunnel>, headroom: usize) -> Self {
        let mtu = if config.large_segments {
            INNER_MTU
        } else {
            config.mtu
        };
        let mut device = QueueDevice::new(mtu, headroom);
        let mut iface = Interface::new(
            iface_config(0x5eed_1234),
            &mut device,
            Instant::from_millis(0),
        );
        add_addresses(&mut iface, &config.addresses);
        add_default_routes(&mut iface, &config.addresses);
        Self {
            device,
            headroom,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows: Vec::new(),
            readiness: Readiness::new(),
            ports: HashSet::new(),
            next_port: 49_152,
            race_bytes: 0,
            retiring: Vec::new(),
            to_tunnel: to_tunnel.into(),
            addresses: config.addresses.clone(),
            peers: config.peers.clone(),
            reassembly: Reassembly::default(),
            fragment: if headroom == 0 {
                TUNNEL_FRAGMENT
            } else {
                config.mtu
            },
            routes: Arc::default(),
            started: StdInstant::now(),
        }
    }

    /// Hand a complete UDP packet to the lane waiting on its destination port.
    fn deliver_udp(&self, packet: &[u8]) -> bool {
        let Some(datagram) = udp_from_packet(packet) else {
            return false;
        };
        if !datagram.verified {
            return false;
        }
        let Ok(table) = self.routes.lock() else {
            return false;
        };
        let Some(lane) = table.get(&datagram.destination_port) else {
            return false;
        };
        lane.send(packet.to_vec()).is_ok()
    }

    /// Answer an echo aimed at one of the client's own tunnel addresses.
    fn answer_echo(&self, packet: &[u8]) -> bool {
        answer_echo(packet, &self.addresses, &self.to_tunnel, self.headroom)
    }

    /// A Packet Too Big narrows the shared MTU only on a single-peer client, when
    /// it quotes a flow that peer routes and this client sent.
    fn absorb(&mut self, peer: [u8; 32], packet: &[u8]) {
        if self.peers.len() > 1 {
            return;
        }
        let Some((source, destination)) = icmp_quoted(packet) else {
            return;
        };
        let routed = self.peers.is_empty()
            || self
                .peers
                .iter()
                .any(|known| known.public == peer && known.routes(destination));
        if !self.addresses.contains(&source) || !routed {
            return;
        }
        if self.device.absorb(packet) {
            self.reset_iface();
        }
    }

    /// Rebuild the interface so smoltcp's cached capabilities carry the learned MTU.
    fn reset_iface(&mut self) {
        let now = self.now();
        self.iface = Interface::new(iface_config(0x5eed_1234), &mut self.device, now);
        add_addresses(&mut self.iface, &self.addresses);
        add_default_routes(&mut self.iface, &self.addresses);
    }

    /// Race a client flow's destinations and keep the first connected socket.
    fn connect(&mut self, flow: ClientFlow) -> std::io::Result<()> {
        flow.client.set_nonblocking(true)?;
        let mut candidates = Vec::new();
        let mut refused = None;
        for destination in &flow.destinations {
            if candidates.len() == RACES {
                break;
            }
            if destination.port() == 0 || destination.ip().is_unspecified() {
                refused = Some(format!("destination {destination} is not a TCP endpoint"));
                continue;
            }
            if !self
                .addresses
                .iter()
                .any(|address| address.is_ipv4() == destination.ip().is_ipv4())
            {
                continue;
            }
            if !candidates.is_empty() && self.race_bytes + RACE_BYTES > RACE_BUDGET {
                break;
            }
            let Some(local_port) = self.free_port() else {
                break;
            };
            let mut socket = TcpSocket::new(
                SocketBuffer::new(vec![0u8; TCP_RECV_BUFFER]),
                SocketBuffer::new(vec![0u8; TCP_SEND_BUFFER]),
            );
            socket.set_nagle_enabled(false);
            socket.set_ack_delay(None);
            socket.set_congestion_control(CongestionControl::Cubic);
            if let Err(error) = socket.connect(
                self.iface.context(),
                IpEndpoint::from(*destination),
                IpListenEndpoint::from(local_port),
            ) {
                refused = Some(format!("cannot connect {destination}: {error:?}"));
                continue;
            }
            let handle = self.sockets.add(socket);
            self.ports.insert(local_port);
            if !candidates.is_empty() {
                self.race_bytes += RACE_BYTES;
            }
            candidates.push((handle, local_port));
        }
        let Some((handle, local_port)) = candidates.first().copied() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                refused.unwrap_or_else(|| "wireguard has no routable destination".to_owned()),
            ));
        };
        candidates.remove(0);
        let mut routed = Flow::new(handle, flow.client, local_port);
        routed.races = candidates;
        routed.pending_up = flow.prefix;
        self.flows.push(routed);
        Ok(())
    }

    /// Find the next unused local port for a datagram lane.
    fn free_port(&mut self) -> Option<u16> {
        let span = usize::from(u16::MAX) - 49_152 + 1;
        for _ in 0..span {
            let port = self.next_port.max(49_152);
            self.next_port = if port == u16::MAX { 49_152 } else { port + 1 };
            if !self.ports.contains(&port) {
                return Some(port);
            }
        }
        None
    }

    /// Drive the interface, every flow, and the queued transmits one turn.
    fn poll(&mut self, buf: &mut [u8]) -> bool {
        self.device.refill_tx();
        let now = self.now();
        self.reassembly.expire();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        let ready = self.readiness.sync(&self.flows);
        let mut retiring = std::mem::take(&mut self.retiring);
        let mut moved = false;
        for (flow, &up_ready) in self.flows.iter_mut().zip(ready) {
            flow.adopt(
                &mut self.sockets,
                &mut self.ports,
                &mut retiring,
                &mut self.race_bytes,
            );
            moved |= pump(flow, &mut self.sockets, buf, up_ready);
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        retire(
            &mut self.sockets,
            &mut self.ports,
            &mut retiring,
            &mut self.race_bytes,
        );
        self.retiring = retiring;
        for _ in 0..TX_BURST {
            let Some(packet) = self.device.tx.pop_front() else {
                break;
            };
            if !send_packet(&self.to_tunnel, packet, self.headroom, self.fragment) {
                return moved;
            }
        }
        let mut retiring = std::mem::take(&mut self.retiring);
        self.flows.retain_mut(|flow| {
            if flow.done {
                let _ = flow.local.shutdown(Shutdown::Both);
                self.sockets.remove(flow.handle);
                self.ports.remove(&flow.local_port);
                for (handle, port) in flow.races.drain(..) {
                    self.sockets.get_mut::<TcpSocket>(handle).abort();
                    retiring.push((handle, port, true));
                }
                false
            } else {
                true
            }
        });
        self.retiring = retiring;
        moved || !self.device.tx.is_empty()
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.started.elapsed().as_millis() as i64)
    }
}

struct Listener {
    handle: SocketHandle,
    since: StdInstant,
}

struct UdpLane {
    uplink: UdpSocket,
    head: Vec<u8>,
    stop: Arc<AtomicBool>,
    last_used: Arc<AtomicU64>,
}

#[cfg(test)]
thread_local! {
    static LAST_SERVER_DATAGRAM: std::cell::Cell<Option<(usize, usize)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn remember_server_datagram(head: &[u8], payload: &[u8]) {
    LAST_SERVER_DATAGRAM.with(|sent| {
        sent.set(Some((head.as_ptr() as usize, payload.as_ptr() as usize)));
    });
}

fn elapsed_ms(started: StdInstant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct ServerStack {
    device: QueueDevice,
    headroom: usize,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: Vec<Flow>,
    readiness: Readiness,
    listeners: HashMap<u16, Vec<Listener>>,
    syn_ports: Vec<u16>,
    udp: HashMap<([u8; 32], SocketAddr, SocketAddr), UdpLane>,
    to_tunnel: ToTunnel,
    out: Outbound,
    addresses: Vec<IpAddr>,
    mtu: usize,
    reassembly: Reassembly,
    fragment: usize,
    started: StdInstant,
}

impl ServerStack {
    /// Build the server's interface, sockets and routes over a device that reserves its headroom.
    fn new(
        config: &DeviceConfig,
        to_tunnel: impl Into<ToTunnel>,
        out: Outbound,
        headroom: usize,
    ) -> Self {
        let fragment = if headroom == 0 {
            TUNNEL_FRAGMENT
        } else {
            config.mtu
        };
        Self::with_mtu(config, to_tunnel, out, headroom, INNER_MTU, fragment)
    }

    /// Build the same interface over a TUN whose packets already carry their IP header.
    fn new_tun(
        config: &DeviceConfig,
        to_tunnel: impl Into<ToTunnel>,
        out: Outbound,
        tx_reuse: Receiver<Vec<u8>>,
    ) -> Self {
        let mut stack = Self::with_mtu(config, to_tunnel, out, 0, config.mtu, config.mtu);
        stack.device.tx_reuse = Some(tx_reuse);
        stack
    }

    fn with_mtu(
        config: &DeviceConfig,
        to_tunnel: impl Into<ToTunnel>,
        out: Outbound,
        headroom: usize,
        device_mtu: usize,
        fragment: usize,
    ) -> Self {
        let mut device = QueueDevice::new(device_mtu, headroom);
        let mut iface = Interface::new(
            iface_config(0x5eed_5678),
            &mut device,
            Instant::from_millis(0),
        );
        add_addresses(&mut iface, &config.addresses);
        add_default_routes(&mut iface, &config.addresses);
        iface.set_any_ip(true);
        Self {
            device,
            headroom,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows: Vec::new(),
            readiness: Readiness::new(),
            listeners: HashMap::new(),
            syn_ports: Vec::new(),
            udp: HashMap::new(),
            to_tunnel: to_tunnel.into(),
            out,
            addresses: config.addresses.clone(),
            mtu: config.mtu,
            reassembly: Reassembly::default(),
            fragment,
            started: StdInstant::now(),
        }
    }

    /// Route one packet to TCP, a UDP lane, or the server echo path.
    fn receive(&mut self, packet: Packet) {
        let at = packet.at;
        let bytes = match self.reassembly.accept(packet.peer, &packet.bytes[at..], at) {
            Reassembled::Pass => packet.bytes,
            Reassembled::Held => {
                self.device.recycle(packet.bytes, at);
                return;
            }
            Reassembled::Complete(bytes) => {
                self.device.recycle(packet.bytes, at);
                bytes
            }
        };
        let protocol = inner_protocol(&bytes[at..]);
        match protocol {
            Some(PROTOCOL_TCP) => self.device.push(bytes, at),
            Some(PROTOCOL_UDP) => {
                self.datagram(packet.peer, &bytes[at..]);
                self.device.recycle(bytes, at);
            }
            _ => {
                // A client's ICMP must not narrow the MTU every tunnel shares.
                self.answer_echo(&bytes[at..]);
                self.device.recycle(bytes, at);
            }
        }
    }

    /// Answer an echo aimed at one of the server's own tunnel addresses.
    fn answer_echo(&self, packet: &[u8]) -> bool {
        answer_echo(packet, &self.addresses, &self.to_tunnel, self.headroom)
    }

    /// Open or reuse the lane a client's inner datagram names.
    fn datagram(&mut self, peer: [u8; 32], bytes: &[u8]) {
        let Some(datagram) = udp_from_packet(bytes) else {
            return;
        };
        let Some(source) = socket_addr(datagram.source, datagram.source_port) else {
            return;
        };
        let Some(target) = socket_addr(datagram.destination, datagram.destination_port) else {
            return;
        };
        let key = (peer, source, target);
        let now = elapsed_ms(self.started);
        let lane = if let Some(lane) = self.udp.get_mut(&key) {
            lane
        } else {
            if self.udp.len() >= UDP_FLOWS {
                return;
            }
            let last_used = Arc::new(AtomicU64::new(elapsed_ms(self.started)));
            let Some((uplink, stop)) = server_udp(
                key,
                self.started,
                &last_used,
                &self.out,
                &self.to_tunnel,
                self.headroom,
            ) else {
                return;
            };
            self.udp.insert(
                key,
                UdpLane {
                    uplink,
                    head: Vec::new(),
                    stop,
                    last_used,
                },
            );
            let Some(lane) = self.udp.get_mut(&key) else {
                return;
            };
            lane
        };
        lane.last_used.store(now, Ordering::Relaxed);
        let (head, payload) =
            crate::proxy::socks_udp_parts(&mut lane.head, &target, datagram.payload);
        #[cfg(test)]
        remember_server_datagram(head, payload);
        let _ = crate::proxy::send_two(&lane.uplink, head, payload);
    }

    /// Drive the server interface and hand off every completed flow.
    fn poll(&mut self, buf: &mut [u8]) -> bool {
        self.syn_ports.clear();
        self.reassembly.expire();
        for (packet, at) in &self.device.rx {
            if let Some(port) = tcp_syn_port(&packet[*at..]) {
                self.syn_ports.push(port);
            }
        }
        for i in 0..self.syn_ports.len() {
            let port = self.syn_ports[i];
            self.listen(port);
        }
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.handoff();
        let ready = self.readiness.sync(&self.flows);
        let mut moved = false;
        for (flow, &up_ready) in self.flows.iter_mut().zip(ready) {
            moved |= pump(flow, &mut self.sockets, buf, up_ready);
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        for _ in 0..TX_BURST {
            let Some(mut packet) = self.device.tx.pop_front() else {
                break;
            };
            lower_syn_ack_mss(&mut packet, self.headroom, self.mtu);
            if !send_packet(&self.to_tunnel, packet, self.headroom, self.fragment) {
                return moved;
            }
        }
        self.flows.retain(|flow| {
            if flow.done {
                let _ = flow.local.shutdown(Shutdown::Both);
                self.sockets.remove(flow.handle);
                false
            } else {
                true
            }
        });
        let dead: Vec<(u16, SocketHandle)> = self
            .listeners
            .iter()
            .flat_map(|(port, listeners)| {
                listeners.iter().filter_map(|listener| {
                    let state = self.sockets.get::<TcpSocket>(listener.handle).state();
                    let live = matches!(state, State::Listen | State::SynReceived)
                        && listener.since.elapsed() < LISTENER_TTL;
                    (!live).then_some((*port, listener.handle))
                })
            })
            .collect();
        for (port, handle) in dead {
            self.sockets.remove(handle);
            if let Some(listeners) = self.listeners.get_mut(&port) {
                listeners.retain(|listener| listener.handle != handle);
                if listeners.is_empty() {
                    self.listeners.remove(&port);
                }
            }
        }
        let idle = u64::try_from(crate::budgets::udp_idle().as_millis()).unwrap_or(u64::MAX);
        let now = elapsed_ms(self.started);
        let stale: Vec<_> = self
            .udp
            .iter()
            .filter(|(_, lane)| now.saturating_sub(lane.last_used.load(Ordering::Relaxed)) >= idle)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            if let Some(lane) = self.udp.remove(&key) {
                lane.stop.store(true, Ordering::Relaxed);
            }
        }
        moved || !self.device.tx.is_empty()
    }

    fn listen(&mut self, port: u16) {
        let total = self.listeners.values().map(Vec::len).sum::<usize>();
        if total >= LISTENERS {
            return;
        }
        let listeners = self.listeners.entry(port).or_default();
        if listeners.len() >= LISTENERS_PER_PORT {
            return;
        }
        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0u8; TCP_RECV_BUFFER]),
            SocketBuffer::new(vec![0u8; TCP_SEND_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        socket.set_congestion_control(CongestionControl::Cubic);
        if socket.listen(IpListenEndpoint { addr: None, port }).is_ok() {
            let handle = self.sockets.add(socket);
            listeners.push(Listener {
                handle,
                since: StdInstant::now(),
            });
        }
    }

    /// Hands each established listener to a flow that carries the device's address as its peer.
    fn handoff(&mut self) {
        let mut ready = Vec::new();
        for (port, listeners) in &self.listeners {
            for listener in listeners {
                let socket = self.sockets.get::<TcpSocket>(listener.handle);
                if socket.state() == State::Established {
                    if let (Some(local), Some(remote)) =
                        (socket.local_endpoint(), socket.remote_endpoint())
                    {
                        ready.push((*port, listener.handle, local, remote));
                    }
                }
            }
        }
        for (port, handle, local, remote) in ready {
            if let Some(listeners) = self.listeners.get_mut(&port) {
                listeners.retain(|listener| listener.handle != handle);
                if listeners.is_empty() {
                    self.listeners.remove(&port);
                }
            }
            let destination = match local.addr {
                IpAddress::Ipv4(address) => SocketAddr::new(IpAddr::V4(address), local.port),
                IpAddress::Ipv6(address) => SocketAddr::new(IpAddr::V6(address), local.port),
            };
            let peer = match remote.addr {
                IpAddress::Ipv4(address) => SocketAddr::new(IpAddr::V4(address), remote.port),
                IpAddress::Ipv6(address) => SocketAddr::new(IpAddr::V6(address), remote.port),
            };
            let Ok((tun, proxy)) = loopback() else {
                self.sockets.remove(handle);
                continue;
            };
            let out = self.out.clone();
            std::thread::spawn(move || {
                let _ = serve_device_flow(
                    proxy.with_peer(peer),
                    &out,
                    &Destination::Address(destination),
                );
            });
            if tun.set_nonblocking(true).is_err() {
                self.sockets.remove(handle);
                continue;
            }
            self.flows.push(Flow::new(handle, tun, 0));
        }
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.started.elapsed().as_millis() as i64)
    }
}

/// Move bytes between one flow's local stream and its TCP socket. Every read and
/// write is nonblocking, so a slow local peer parks only its own buffers.
#[allow(clippy::too_many_lines)]
fn pump(flow: &mut Flow, sockets: &mut SocketSet<'_>, buf: &mut [u8], up_ready: bool) -> bool {
    let mut moved = false;
    let socket = sockets.get_mut::<TcpSocket>(flow.handle);
    if matches!(socket.state(), State::Established | State::CloseWait) {
        flow.established = true;
    }
    if socket.state() == State::Closed && !flow.established {
        flow.done = true;
    }

    while flow.down_pending() {
        let at = flow.pending_down_at;
        match flow.local.write(&flow.pending_down[at..]) {
            Ok(0) => {
                flow.down_eof = true;
                break;
            }
            Ok(n) => {
                flow.pending_down_at += n;
                moved = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                flow.done = true;
                socket.abort();
                break;
            }
        }
    }
    if !flow.down_pending() {
        flow.pending_down.clear();
        flow.pending_down_at = 0;
    }

    while !flow.down_pending() {
        match socket.recv_slice(buf) {
            Ok(0) | Err(RecvError::InvalidState) => break,
            Ok(n) => {
                moved = true;
                let mut at = 0;
                while at < n {
                    match flow.local.write(&buf[at..n]) {
                        Ok(0) => {
                            flow.down_eof = true;
                            at = n;
                        }
                        Ok(written) => at += written,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            flow.stage_down(&buf[at..n]);
                            at = n;
                        }
                        Err(_) => {
                            flow.done = true;
                            socket.abort();
                            at = n;
                        }
                    }
                }
            }
            Err(RecvError::Finished) => {
                flow.down_eof = true;
                break;
            }
        }
    }

    let mut bursts = 0;
    while bursts < UP_BURST && !flow.up_eof && socket.can_send() {
        if flow.up_pending() {
            let at = flow.pending_up_at;
            match socket.send_slice(&flow.pending_up[at..]) {
                Ok(0) => break,
                Ok(n) => {
                    flow.pending_up_at += n;
                    moved = true;
                    bursts += 1;
                    if !flow.up_pending() {
                        flow.pending_up.clear();
                        flow.pending_up_at = 0;
                    }
                }
                Err(SendError::InvalidState) => {
                    flow.done = true;
                    socket.abort();
                    break;
                }
            }
        } else if up_ready {
            match flow.local.read(buf) {
                Ok(0) => {
                    flow.up_eof = true;
                    break;
                }
                Ok(n) => {
                    moved = true;
                    bursts += 1;
                    match socket.send_slice(&buf[..n]) {
                        Ok(sent) if sent < n => flow.stage_up(&buf[sent..n]),
                        Ok(_) => {}
                        Err(SendError::InvalidState) => {
                            flow.done = true;
                            socket.abort();
                            break;
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    flow.done = true;
                    socket.abort();
                    break;
                }
            }
        } else {
            break;
        }
    }
    if flow.up_eof && !flow.up_pending() && socket.is_open() && !flow.sent_fin {
        socket.close();
        flow.sent_fin = true;
    }
    if flow.down_eof && !flow.down_shutdown && !flow.down_pending() {
        let _ = flow.local.shutdown(Shutdown::Write);
        flow.down_shutdown = true;
    }
    if socket.state() == State::Closed && flow.established && !flow.down_pending() {
        flow.down_eof = true;
        flow.done = true;
    }
    if flow.sent_fin && flow.down_eof && socket.state() == State::Closed {
        flow.done = true;
    }
    moved
}

#[cfg(unix)]
fn loopback() -> std::io::Result<(Connection, Connection)> {
    let (tun, proxy) = std::os::unix::net::UnixStream::pair()?;
    Ok((Connection::from(tun), Connection::from(proxy)))
}

#[cfg(not(unix))]
fn loopback() -> std::io::Result<(Connection, Connection)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let tun = std::net::TcpStream::connect(address)?;
    let (proxy, _) = listener.accept()?;
    Ok((Connection::from(tun), Connection::from(proxy)))
}

fn iface_config(seed: u64) -> IfaceConfig {
    let mut config = IfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = seed;
    config
}

fn add_addresses(iface: &mut Interface, addresses: &[IpAddr]) {
    iface.update_ip_addrs(|slots| {
        for address in addresses {
            let prefix = if address.is_ipv4() { 24 } else { 64 };
            let cidr = IpCidr::new(IpAddress::from(*address), prefix);
            let _ = slots.push(cidr);
        }
    });
}

/// A default route via the first configured address of each family. The bridge
/// is `Medium::Ip`, so the gateway is only a route-table choice; the packet
/// keeps the destination the flow asked for.
fn add_default_routes(iface: &mut Interface, addresses: &[IpAddr]) {
    if let Some(IpAddr::V4(address)) = addresses.iter().find(|address| address.is_ipv4()) {
        let _ = iface.routes_mut().add_default_ipv4_route(*address);
    }
    if let Some(IpAddr::V6(address)) = addresses.iter().find(|address| address.is_ipv6()) {
        let _ = iface.routes_mut().add_default_ipv6_route(*address);
    }
}

/// The destination port of an unfragmented TCP SYN, the packet that raises a
/// listener on a server that owns none of the addresses it receives.
fn tcp_syn_port(packet: &[u8]) -> Option<u16> {
    let tcp = match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet.first()? & 0x0f) * 4;
            if *packet.get(9)? != PROTOCOL_TCP || header < IPV4_HEADER {
                return None;
            }
            packet.get(header..)?
        }
        6 => {
            if *packet.get(6)? != PROTOCOL_TCP {
                return None;
            }
            packet.get(IPV6_HEADER..)?
        }
        _ => return None,
    };
    let flags = *tcp.get(13)?;
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None;
    }
    Some(u16::from_be_bytes([*tcp.get(2)?, *tcp.get(3)?]))
}

/// Whether an inner packet carries TCP, which the stack takes, or UDP, which
/// the datagram lane takes.
pub(crate) fn inner_protocol(packet: &[u8]) -> Option<u8> {
    match packet.first()? >> 4 {
        4 => packet.get(9).copied(),
        6 => packet.get(6).copied(),
        _ => None,
    }
}

/// Whether an inner packet belongs to the stack, including an IPv6 fragment
/// whose transport header is not visible until reassembly.
pub(crate) fn stack_packet(packet: &[u8]) -> bool {
    match inner_protocol(packet) {
        Some(PROTOCOL_TCP) => true,
        Some(PROTOCOL_UDP) => ipv4_fragment(packet),
        Some(44) => packet.first().is_some_and(|byte| byte >> 4 == 6),
        _ => false,
    }
}

/// Whether the packet is an IPv4 fragment rather than a complete datagram.
pub(crate) fn ipv4_fragment(packet: &[u8]) -> bool {
    if packet.first().is_none_or(|byte| byte >> 4 != 4) {
        return false;
    }
    let Some(fields) = packet.get(6..8) else {
        return false;
    };
    let fields = u16::from_be_bytes([fields[0], fields[1]]);
    fields & 0x3fff != 0
}

/// The inner source and destination addresses of an IPv4 or IPv6 packet.
pub(crate) fn inner_addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 => {
            let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let destination: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some((IpAddr::from(source), IpAddr::from(destination)))
        }
        6 => {
            let source: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let destination: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some((IpAddr::from(source), IpAddr::from(destination)))
        }
        _ => None,
    }
}

/// A replied lane sends only to its winner; an unanswered one races the answers
/// its configured source addresses can reach.
fn lane_targets(
    destination: Destination,
    resolve: &dyn Fn(&str, u16) -> Vec<SocketAddr>,
    addresses: &[IpAddr],
    winner: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    if let Some(won) = winner {
        return vec![won];
    }
    let raced = match destination {
        Destination::Address(address) => vec![address],
        Destination::Name(host, port) => resolve(&host, port),
    };
    raced
        .into_iter()
        .filter(|target| {
            addresses
                .iter()
                .any(|address| address.is_ipv4() == target.ip().is_ipv4())
        })
        .take(RACES)
        .collect()
}

/// Build and send one datagram to a target; false means the tunnel is gone.
fn lane_send(
    config: &DeviceConfig,
    source_port: u16,
    target: SocketAddr,
    payload: &[u8],
    to_tunnel: &ToTunnel,
    headroom: usize,
) -> bool {
    let Some(inner_source) = config
        .addresses
        .iter()
        .find(|address| address.is_ipv4() == target.is_ipv4())
    else {
        return true;
    };
    let mut source_room = [0u8; 16];
    let mut destination_room = [0u8; 16];
    let source = ip_bytes_into(*inner_source, &mut source_room);
    let destination = ip_bytes_into(target.ip(), &mut destination_room);
    let header = if source.len() == 4 {
        IPV4_HEADER
    } else {
        IPV6_HEADER
    };
    let mut packet = Vec::with_capacity(headroom + header + 8 + payload.len() + WG_TAG_SIZE);
    packet.resize(headroom, 0);
    let datagram = UdpDatagram {
        source,
        destination,
        source_port,
        destination_port: target.port(),
        payload,
    };
    udp_datagram(&datagram, &mut packet) && to_tunnel.send(packet).is_ok()
}

/// Resolve a name through the tunnel against the configured DNS servers: the
/// query rides the same datagram path as the caller's flows, so a name resolves
/// where the tunnel can reach, not where the host can. A literal is returned
/// unchanged, and an answer this lane cannot use is `None` so the caller keeps
/// its own resolver as the fallback.
pub(crate) fn resolve_over_tunnel(
    config: &DeviceConfig,
    to_tunnel: &ToTunnel,
    routes: &UdpRoutes,
    servers: &[IpAddr],
    host: &str,
    port: u16,
) -> Option<SocketAddr> {
    if host.parse::<IpAddr>().is_ok() {
        return crate::proxy::resolve_endpoint(host, port);
    }
    let mut name = Vec::with_capacity(host.len() + 1);
    name.extend_from_slice(host.as_bytes());
    if !host.ends_with('.') {
        name.push(b'.');
    }
    for server in servers {
        let Some(source) = config
            .addresses
            .iter()
            .find(|address| address.is_ipv4() == server.is_ipv4())
            .copied()
        else {
            continue;
        };
        for qtype in [1u16, 28] {
            let family = qtype == 1;
            if !config
                .addresses
                .iter()
                .any(|address| address.is_ipv4() == family)
            {
                continue;
            }
            if let Some(ip) = query_tunnel(to_tunnel, routes, source, *server, &name, qtype) {
                if family == ip.is_ipv4() {
                    return Some(SocketAddr::new(ip, port));
                }
            }
        }
    }
    None
}

/// One question over the tunnel, answered by the first record of its own type:
/// the route is owned for the whole exchange and removed whether it answered or
/// timed out, so a lost query leaves no port behind.
fn query_tunnel(
    to_tunnel: &ToTunnel,
    routes: &UdpRoutes,
    source: IpAddr,
    server: IpAddr,
    name: &[u8],
    qtype: u16,
) -> Option<IpAddr> {
    let id = NEXT_DNS_PORT.fetch_add(1, Ordering::Relaxed);
    let query = ferrox_core::dns::build_query(id, name, qtype, None)?;
    let mut source_room = [0u8; 16];
    let mut destination_room = [0u8; 16];
    let source = ip_bytes_into(source, &mut source_room);
    let destination = ip_bytes_into(server, &mut destination_room);
    let (reply_tx, reply_rx) = mpsc::channel();
    let source_port = reserve_dns_port(routes, &reply_tx)?;
    let mut packet = Vec::with_capacity(source.len() + 8 + query.len());
    let datagram = UdpDatagram {
        source,
        destination,
        source_port,
        destination_port: 53,
        payload: &query,
    };
    let sent = udp_datagram(&datagram, &mut packet) && to_tunnel.send(packet).is_ok();
    let answer = if sent {
        let deadline = StdInstant::now() + DNS_TIMEOUT;
        loop {
            let Some(left) = deadline.checked_duration_since(StdInstant::now()) else {
                break None;
            };
            let Ok(reply) = reply_rx.recv_timeout(left) else {
                break None;
            };
            let Some(datagram) = udp_from_packet(&reply) else {
                continue;
            };
            let Some(answer) = ferrox_core::dns::parse_answer(datagram.payload) else {
                continue;
            };
            if answer.id != id {
                continue;
            }
            if answer.rcode != 0 {
                break None;
            }
            break answer.records.iter().find_map(|record| {
                if record.kind != qtype {
                    return None;
                }
                match record.rdata.len() {
                    4 => Some(IpAddr::from(
                        <[u8; 4]>::try_from(record.rdata.as_slice()).ok()?,
                    )),
                    16 => Some(IpAddr::from(
                        <[u8; 16]>::try_from(record.rdata.as_slice()).ok()?,
                    )),
                    _ => None,
                }
            });
        }
    } else {
        None
    };
    if let Ok(mut table) = routes.lock() {
        table.remove(&source_port);
    }
    answer
}

/// Reserve the port the answer will be addressed to; a lane that already owns it
/// is skipped so the query never steals a reply from a live call.
fn reserve_dns_port(routes: &UdpRoutes, sender: &Sender<Vec<u8>>) -> Option<u16> {
    let mut table = routes.lock().ok()?;
    for _ in 0..DNS_PORT_SPAN {
        let port = DNS_PORT_BASE + (NEXT_DNS_PORT.fetch_add(1, Ordering::Relaxed) % DNS_PORT_SPAN);
        if let std::collections::hash_map::Entry::Vacant(entry) = table.entry(port) {
            entry.insert(sender.clone());
            return Some(port);
        }
    }
    None
}

/// Record the reply's source as this name's winner; false means the name had
/// already pinned a different target.
fn lane_reply(
    winners: &mut HashMap<(String, u16), (SocketAddr, StdInstant)>,
    key: &(String, u16),
    remote: SocketAddr,
) -> bool {
    match winners.get(key) {
        Some((won, _)) if *won != remote => false,
        Some(_) => true,
        None => {
            winners.insert(key.clone(), (remote, StdInstant::now()));
            true
        }
    }
}

/// Reserve a tunnel source port for one name on this lane.
fn lane_port(routes: &UdpRoutes, sender: &Sender<Vec<u8>>, lane: u16) -> Option<u16> {
    let mut table = routes.lock().ok()?;
    for _ in 0..LANE_PORTS {
        let port = 20000 + (NEXT_LANE_PORT.fetch_add(1, Ordering::Relaxed) % 40000);
        if port != lane && !table.contains_key(&port) {
            table.insert(port, sender.clone());
            return Some(port);
        }
    }
    None
}

/// The name's unexpired winner, dropping a pin that has gone quiet.
fn lane_winner(
    winners: &mut HashMap<(String, u16), (SocketAddr, StdInstant)>,
    key: Option<&(String, u16)>,
) -> Option<SocketAddr> {
    let key = key?;
    match winners.get(key) {
        Some((won, at)) if at.elapsed() < LANE_RACE_AGAIN => Some(*won),
        Some(_) => {
            winners.remove(key);
            None
        }
        None => None,
    }
}

/// Give a name its own tunnel source port so its reply pins only its own race.
fn lane_source_port(
    key: Option<&(String, u16)>,
    sources: &mut HashMap<(String, u16), u16>,
    replies: &mut HashMap<u16, (String, u16)>,
    owned: &mut Vec<u16>,
    routes: &UdpRoutes,
    sender: &Sender<Vec<u8>>,
    lane: u16,
) -> Option<u16> {
    let Some(key) = key else {
        return Some(lane);
    };
    if let Some(port) = sources.get(key) {
        return Some(*port);
    }
    if owned.len() >= LANE_PORTS {
        return None;
    }
    let port = lane_port(routes, sender, lane)?;
    owned.push(port);
    sources.insert(key.clone(), port);
    replies.insert(port, key.clone());
    Some(port)
}

/// Whether a lane has outlived its peer or its idle budget.
fn lane_over(associate: Option<&Connection>, quiet: StdInstant) -> bool {
    associate.is_some_and(crate::proxy::peer_left) || quiet.elapsed() >= crate::budgets::udp_idle()
}

/// A client datagram lane: every frame the local SOCKS5 front writes becomes an
/// inner UDP packet, and the reply the tunnel returns is framed back to the last
/// app that spoke. Each name gets its own inner source port, so a reply pins
/// only the name that raced it, and the relay port serves a literal address.
#[allow(clippy::too_many_lines)]
pub(crate) fn client_udp<T: Clone + Into<ToTunnel>>(
    relay: &UdpSocket,
    config: &DeviceConfig,
    to_tunnel: &T,
    routes: &UdpRoutes,
    associate: Option<&Connection>,
    resolve: &dyn Fn(&str, u16) -> Vec<SocketAddr>,
    headroom: usize,
) {
    let to_tunnel: ToTunnel = to_tunnel.clone().into();
    let Ok(local) = relay.local_addr() else {
        return;
    };
    let port = local.port();
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    if let Ok(mut table) = routes.lock() {
        table.insert(port, reply_tx.clone());
    }
    let _ = relay.set_read_timeout(Some(LANE_TICK));
    if let Some(associate) = associate {
        let _ = associate.set_read_timeout(Some(crate::budgets::SESSION_POLL));
    }
    let mut buf = crate::proxy::udp_buffer();
    let mut frame = Vec::new();
    let mut app: Option<SocketAddr> = None;
    let mut winners: HashMap<(String, u16), (SocketAddr, StdInstant)> = HashMap::new();
    let mut sources: HashMap<(String, u16), u16> = HashMap::new();
    let mut replies: HashMap<u16, (String, u16)> = HashMap::new();
    let mut owned = vec![port];
    let mut quiet = StdInstant::now();
    'lane: loop {
        while let Ok(inner) = reply_rx.try_recv() {
            let Some(datagram) = udp_from_packet(&inner) else {
                continue;
            };
            let Some(app) = app else {
                continue;
            };
            let Some(remote) = socket_addr(datagram.source, datagram.source_port) else {
                continue;
            };
            if let Some(key) = replies.get(&datagram.destination_port) {
                if !lane_reply(&mut winners, key, remote) {
                    continue;
                }
            } else if datagram.destination_port != port {
                continue;
            }
            let out = crate::proxy::socks_udp_frame(&mut frame, None, &remote, datagram.payload);
            let _ = relay.send_to(out, app);
            quiet = StdInstant::now();
        }
        match relay.recv_from(&mut buf) {
            Ok((n, sender)) => {
                quiet = StdInstant::now();
                let Some((destination, payload)) = crate::proxy::parse_socks_udp_dest(&buf[..n])
                else {
                    continue;
                };
                if app.is_some_and(|bound| bound != sender) {
                    continue;
                }
                app = Some(sender);
                let key = match &destination {
                    Destination::Name(host, port) => Some((host.clone(), *port)),
                    Destination::Address(_) => None,
                };
                let winner = lane_winner(&mut winners, key.as_ref());
                let Some(source_port) = lane_source_port(
                    key.as_ref(),
                    &mut sources,
                    &mut replies,
                    &mut owned,
                    routes,
                    &reply_tx,
                    port,
                ) else {
                    break 'lane;
                };
                let targets = lane_targets(destination, resolve, &config.addresses, winner);
                for target in targets {
                    if !lane_send(config, source_port, target, payload, &to_tunnel, headroom) {
                        break 'lane;
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if lane_over(associate, quiet) {
                    break;
                }
            }
            Err(error) if crate::proxy::is_udp_gone(&error) => {
                if lane_over(associate, quiet) {
                    break;
                }
                std::thread::sleep(LANE_TICK);
            }
            Err(_) => break,
        }
    }
    if let Ok(mut table) = routes.lock() {
        for port in owned {
            table.remove(&port);
        }
    }
}

/// A server datagram lane: the inner flow is one client source and one target,
/// so its loopback relay carries only that pair. The tree's own UDP dispatcher
/// dials the outbound, and a reader wraps every answer as the packet the client
/// expects back.
pub(crate) fn server_udp<T: Clone + Into<ToTunnel>>(
    flow: ([u8; 32], SocketAddr, SocketAddr),
    started: StdInstant,
    last_used: &Arc<AtomicU64>,
    out: &Outbound,
    to_tunnel: &T,
    headroom: usize,
) -> Option<(UdpSocket, Arc<AtomicBool>)> {
    let relay = UdpSocket::bind("127.0.0.1:0").ok()?;
    let relay_address = relay.local_addr().ok()?;
    let uplink = UdpSocket::bind("127.0.0.1:0").ok()?;
    uplink.connect(relay_address).ok()?;
    let reader = uplink.try_clone().ok()?;
    let (_, source, target) = flow;
    let outbound = match out {
        Outbound::Route(plan) => plan
            .pick(
                &Destination::Address(target),
                crate::router::Network::Udp,
                None,
                None,
            )
            .into_owned(),
        other => other.clone(),
    };
    let _ = relay.set_read_timeout(Some(crate::budgets::udp_idle()));
    std::thread::spawn(move || serve_udp_lane(&relay, &outbound, None));

    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop);
    let reader_activity = Arc::clone(last_used);
    let tunnel = to_tunnel.clone().into();
    std::thread::spawn(move || {
        let mut buf = crate::proxy::udp_buffer();
        let _ = reader.set_read_timeout(Some(LANE_TICK));
        loop {
            if reader_stop.load(Ordering::Relaxed) {
                break;
            }
            match reader.recv(&mut buf) {
                Ok(n) => {
                    let Some((_, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
                        continue;
                    };
                    let mut source_bytes = [0u8; 16];
                    let mut destination_bytes = [0u8; 16];
                    let source_bytes = ip_bytes_into(target.ip(), &mut source_bytes);
                    let destination_bytes = ip_bytes_into(source.ip(), &mut destination_bytes);
                    let header = if source_bytes.len() == 4 {
                        IPV4_HEADER
                    } else {
                        IPV6_HEADER
                    };
                    let mut packet =
                        Vec::with_capacity(headroom + header + 8 + payload.len() + WG_TAG_SIZE);
                    packet.resize(headroom, 0);
                    let datagram = UdpDatagram {
                        source: source_bytes,
                        destination: destination_bytes,
                        source_port: target.port(),
                        destination_port: source.port(),
                        payload,
                    };
                    if !udp_datagram(&datagram, &mut packet) {
                        continue;
                    }
                    reader_activity.store(elapsed_ms(started), Ordering::Relaxed);
                    if tunnel.send(packet).is_err() {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    });
    Some((uplink, stop))
}

fn socket_addr(bytes: &[u8], port: u16) -> Option<SocketAddr> {
    match bytes.len() {
        4 => Some(SocketAddr::new(
            IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
            port,
        )),
        16 => Some(SocketAddr::new(
            IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
            port,
        )),
        _ => None,
    }
}

pub(crate) fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

/// The same octets in the caller's stack room, so a datagram lane builds a packet without a heap buffer per address.
fn ip_bytes_into(address: IpAddr, out: &mut [u8; 16]) -> &[u8] {
    match address {
        IpAddr::V4(address) => {
            out[..4].copy_from_slice(&address.octets());
            &out[..4]
        }
        IpAddr::V6(address) => {
            out.copy_from_slice(&address.octets());
            &out[..]
        }
    }
}

/// The IP protocol number a TCP segment carries.
pub(crate) const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_ICMPV6: u8 = 58;

/// Answer an echo request the tunnel sent to one of this device's own addresses; the reply
/// rides the same tunnel back, so a ping to the tunnel address returns instead of vanishing.
fn answer_echo(packet: &[u8], addresses: &[IpAddr], to_tunnel: &ToTunnel, headroom: usize) -> bool {
    let Some((source, destination)) = inner_addresses(packet) else {
        return false;
    };
    if !addresses.contains(&destination) {
        return false;
    }
    let Some(message) = icmp_message(packet) else {
        return false;
    };
    let mut reply = Vec::with_capacity(headroom + packet.len() + WG_TAG_SIZE);
    reply.resize(headroom, 0);
    if !icmp_echo_reply(source, destination, message, &mut reply) {
        return false;
    }
    to_tunnel.send(reply).is_ok()
}

/// The ICMP message an inner packet carries, cut at its IP header's length so trailing
/// padding is not read as part of the message.
fn icmp_message(packet: &[u8]) -> Option<&[u8]> {
    match packet.first()? >> 4 {
        4 => {
            let header = usize::from(*packet.first()? & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            (packet.get(9) == Some(&PROTOCOL_ICMP)
                && header >= IPV4_HEADER
                && header + 8 <= total
                && total <= packet.len())
            .then(|| &packet[header..total])
        }
        6 => {
            let payload = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
            let total = IPV6_HEADER + payload;
            (packet.get(6) == Some(&PROTOCOL_ICMPV6) && total <= packet.len())
                .then(|| &packet[IPV6_HEADER..total])
        }
        _ => None,
    }
}

/// The source and destination the ICMP error quotes, when the quoted header is
/// long enough to carry them.
fn icmp_quoted(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if packet.len() >= 48
        && packet[0] >> 4 == 4
        && packet[9] == PROTOCOL_ICMP
        && packet[20] == 3
        && packet[21] == 4
    {
        let quoted = 28;
        if packet.len() >= quoted + 20 && packet[quoted] >> 4 == 4 {
            let source = <[u8; 4]>::try_from(&packet[quoted + 12..quoted + 16]).ok()?;
            let destination = <[u8; 4]>::try_from(&packet[quoted + 16..quoted + 20]).ok()?;
            return Some((IpAddr::from(source), IpAddr::from(destination)));
        }
    }
    if packet.len() >= 88
        && packet[0] >> 4 == 6
        && packet[6] == PROTOCOL_ICMPV6
        && packet[40] == 2
        && packet[41] == 0
    {
        let quoted = 48;
        if packet[quoted] >> 4 == 6 {
            let source = <[u8; 16]>::try_from(&packet[quoted + 8..quoted + 24]).ok()?;
            let destination = <[u8; 16]>::try_from(&packet[quoted + 24..quoted + 40]).ok()?;
            return Some((IpAddr::from(source), IpAddr::from(destination)));
        }
    }
    None
}

/// The MTU an ICMP Packet Too Big names, when the packet is one at all: a v4 destination-unreachable with code 4, or a v6 packet-too-big, both at or above their family's floor.
fn icmp_mtu(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 28
            && packet[9] == PROTOCOL_ICMP
            && packet[20] == 3
            && packet[21] == 4 =>
        {
            let mtu = usize::from(u16::from_be_bytes([packet[26], packet[27]]));
            (mtu >= 68).then_some(mtu)
        }
        6 if packet.len() >= 48
            && packet[6] == PROTOCOL_ICMPV6
            && packet[40] == 2
            && packet[41] == 0 =>
        {
            let mtu = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]);
            if mtu >= 1280 {
                usize::try_from(mtu).ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_resolves_through_the_tunnel() {
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().expect("an inner address")],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, queries): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = std::sync::mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let responder_routes = Arc::clone(&routes);
        let responder = std::thread::spawn(move || {
            let query = queries.recv().expect("a query");
            let datagram = udp_from_packet(&query).expect("an inner datagram");
            assert_eq!(datagram.destination_port, 53);
            let question = ferrox_core::dns::parse_query(datagram.payload).expect("a question");
            let answer = ferrox_core::dns::ip_answer(&question, 0, 60, &[vec![192, 0, 2, 7]])
                .expect("an answer");
            let reply = UdpDatagram {
                source: &[1, 1, 1, 1],
                destination: &[10, 0, 0, 2],
                source_port: 53,
                destination_port: datagram.source_port,
                payload: &answer,
            };
            let mut packet = Vec::new();
            assert!(udp_datagram(&reply, &mut packet), "the reply is built");
            responder_routes
                .lock()
                .expect("routes")
                .get(&datagram.source_port)
                .cloned()
                .expect("the query's route")
                .send(packet)
                .expect("the answer reaches the waiter");
        });
        let answer = resolve_over_tunnel(
            &config,
            &ToTunnel::from(to_tunnel),
            &routes,
            &["192.0.2.53".parse().expect("a resolver")],
            "example.com",
            443,
        );
        responder.join().expect("the responder");
        assert_eq!(answer, Some("192.0.2.7:443".parse().expect("an answer")));
        assert!(
            routes.lock().expect("routes").is_empty(),
            "the query left its route behind"
        );
    }

    #[test]
    fn listeners_share_one_total_budget_and_expire() {
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&config, to_tunnel, out, 0);
        for port in 0..(LISTENERS as u16 + 10) {
            stack.listen(10_000 + port);
        }
        assert_eq!(stack.listeners.len(), LISTENERS);
        let expired = 10_000;
        stack.listeners.get_mut(&expired).expect("listener")[0].since = StdInstant::now()
            .checked_sub(LISTENER_TTL)
            .expect("instant");
        let mut buf = [0u8; 1024];
        stack.poll(&mut buf);
        assert!(!stack.listeners.contains_key(&expired));
        stack.listen(10_000 + LISTENERS as u16 + 20);
        assert_eq!(stack.listeners.len(), LISTENERS);
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += if pair.len() == 2 {
                u32::from(u16::from_be_bytes([pair[0], pair[1]]))
            } else {
                u32::from(pair[0]) << 8
            };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// The SYN-ACK a peer would answer a client's SYN with, so the upload path runs on an established socket without a second stack.
    fn syn_ack(syn: &[u8]) -> Vec<u8> {
        let ihl = usize::from(syn[0] & 0x0f) * 4;
        let source: [u8; 4] = syn[12..16].try_into().expect("source");
        let destination: [u8; 4] = syn[16..20].try_into().expect("destination");
        let source_port = u16::from_be_bytes([syn[ihl], syn[ihl + 1]]);
        let destination_port = u16::from_be_bytes([syn[ihl + 2], syn[ihl + 3]]);
        let sequence = u32::from_be_bytes(
            syn[ihl + 4..ihl + 8]
                .try_into()
                .expect("the client's sequence"),
        );
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&destination);
        packet[16..20].copy_from_slice(&source);
        let header_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&destination_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&source_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x1234u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&(sequence + 1).to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x12;
        tcp[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        let tcp_sum = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
        packet
    }

    /// A TCP segment a device would send to the server at `destination`, with `flags` and no payload.
    #[allow(clippy::too_many_arguments)]
    fn tcp_segment(
        source: [u8; 4],
        source_port: u16,
        destination: [u8; 4],
        destination_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTOCOL_TCP;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        let header_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&[0, PROTOCOL_TCP]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        let tcp_sum = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
        packet
    }

    /// The TCP payload of an inner IPv4 packet, which is where an upload's bytes ride.
    fn tcp_payload(packet: &[u8]) -> &[u8] {
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        let offset = ihl + usize::from(packet[ihl + 12] >> 4) * 4;
        let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        &packet[offset..total.min(packet.len())]
    }

    /// The TCP sequence number of an inner packet, so a test can put a download
    /// back in order even when segments arrive out of order or twice.
    fn tcp_sequence(packet: &[u8]) -> Option<u32> {
        let (ip_header, _, _) = tcp_view(packet)?;
        Some(u32::from_be_bytes(
            packet.get(ip_header + 4..ip_header + 8)?.try_into().ok()?,
        ))
    }

    /// Every byte the stack handed the tunnel since the last drain, with the TCP headers removed.
    fn tunnel_payload(packets: &std::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Ok(packet) = packets.try_recv() {
            if packet.get(9) == Some(&PROTOCOL_TCP) {
                bytes.extend_from_slice(tcp_payload(&packet));
            }
        }
        bytes
    }

    /// Poll the stack until the tunnel has carried `want` payload bytes, which may take a turn beyond the one that drained the staging buffer.
    fn tunnel_bytes(
        stack: &mut ClientStack,
        packets: &std::sync::mpsc::Receiver<Vec<u8>>,
        buf: &mut [u8],
        want: usize,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..50 {
            stack.poll(buf);
            bytes.extend_from_slice(&tunnel_payload(packets));
            if bytes.len() >= want {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        bytes
    }

    /// A client stack whose first flow is established, its handshake packets drained, and the local end of the flow kept alive by the returned handle.
    fn established_client() -> (ClientStack, std::sync::mpsc::Receiver<Vec<u8>>, Connection) {
        let (app, proxy) = loopback().expect("pair");
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&config, to_tunnel, 0);
        stack
            .connect(ClientFlow {
                client: proxy,
                destinations: vec!["192.0.2.1:80".parse().expect("destination")],
                prefix: Vec::new(),
            })
            .expect("connect");
        let mut buf = [0u8; 2048];
        stack.poll(&mut buf);
        let syn = packets
            .recv_timeout(Duration::from_secs(5))
            .expect("the client's SYN");
        assert_eq!(syn[9], 6, "the inner packet is TCP");
        stack.device.push(syn_ack(&syn), 0);
        stack.poll(&mut buf);
        assert_eq!(
            stack
                .sockets
                .get::<TcpSocket>(stack.flows[0].handle)
                .state(),
            State::Established,
            "the SYN-ACK establishes the flow"
        );
        while packets.try_recv().is_ok() {}
        (stack, packets, app)
    }

    /// The bytes a refused write leaves staged are written where they lie, and the same buffer takes the next stage instead of a fresh allocation.
    #[test]
    fn a_staged_direction_reuses_its_buffer_across_a_drain() {
        let (mut stack, packets, mut app) = established_client();
        app.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a read timeout, so a lost download fails rather than hangs");
        let mut buf = [0u8; 2048];

        let upload = [b'u'; 512];
        stack.flows[0].stage_up(&upload);
        let cap = stack.flows[0].pending_up.capacity();
        let base = stack.flows[0].pending_up.as_ptr();
        assert!(cap >= upload.len(), "the upload landed in a buffer");
        stack.poll(&mut buf);
        assert!(
            !stack.flows[0].up_pending(),
            "the socket takes the staged upload"
        );
        assert_eq!(
            tunnel_bytes(&mut stack, &packets, &mut buf, upload.len()),
            upload,
            "the staged upload leaves unchanged"
        );
        assert_eq!(
            stack.flows[0].pending_up.capacity(),
            cap,
            "a drained upload released its buffer"
        );
        assert_eq!(
            stack.flows[0].pending_up.as_ptr(),
            base,
            "a drained upload moved its buffer"
        );
        stack.flows[0].stage_up(&upload);
        assert_eq!(
            stack.flows[0].pending_up.capacity(),
            cap,
            "a same-sized upload reallocated"
        );
        assert_eq!(
            stack.flows[0].pending_up.as_ptr(),
            base,
            "a same-sized upload moved its buffer"
        );
        stack.poll(&mut buf);
        assert!(!stack.flows[0].up_pending());
        assert_eq!(
            tunnel_bytes(&mut stack, &packets, &mut buf, upload.len()),
            upload,
            "a reused upload leaves unchanged"
        );

        let download = [b'd'; 512];
        stack.flows[0].stage_down(&download);
        let cap = stack.flows[0].pending_down.capacity();
        let base = stack.flows[0].pending_down.as_ptr();
        assert!(cap >= download.len(), "the download landed in a buffer");
        stack.poll(&mut buf);
        assert!(
            !stack.flows[0].down_pending(),
            "the local socket takes the staged download"
        );
        let mut got = [0u8; 512];
        app.read_exact(&mut got)
            .expect("the local peer reads the download");
        assert_eq!(got, download, "the staged download arrives unchanged");
        assert_eq!(
            stack.flows[0].pending_down.capacity(),
            cap,
            "a drained download released its buffer"
        );
        assert_eq!(
            stack.flows[0].pending_down.as_ptr(),
            base,
            "a drained download moved its buffer"
        );
        stack.flows[0].stage_down(&download);
        assert_eq!(
            stack.flows[0].pending_down.capacity(),
            cap,
            "a same-sized download reallocated"
        );
        assert_eq!(
            stack.flows[0].pending_down.as_ptr(),
            base,
            "a same-sized download moved its buffer"
        );
        stack.poll(&mut buf);
        assert!(!stack.flows[0].down_pending());
        app.read_exact(&mut got)
            .expect("the local peer reads the reused download");
        assert_eq!(got, download, "a reused download arrives unchanged");
    }

    #[test]
    fn a_ready_upload_keeps_the_stack_turning_until_it_is_drained() {
        let (mut stack, _packets, mut app) = established_client();
        app.set_nonblocking(true).expect("a nonblocking local peer");
        let chunk = [b'u'; 4096];
        let mut written = 0;
        loop {
            match app.write(&chunk) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("the local peer writes: {error}"),
            }
        }
        assert!(written > 0, "the local window holds an upload");
        let mut buf = [0u8; 2048];
        let mut turns = 0;
        while stack.poll(&mut buf) {
            turns += 1;
            assert!(turns < 1024, "a ready upload drains");
        }
        assert!(turns > 0, "a ready upload kept the stack from parking");
        assert_eq!(
            stack
                .sockets
                .get::<TcpSocket>(stack.flows[0].handle)
                .send_queue(),
            written,
            "the stack read every byte the local peer wrote"
        );
    }

    /// A turn that reports progress still takes the packets the tunnel queued.
    #[test]
    fn a_turn_takes_the_tunnel_packets_even_when_a_flow_progresses() {
        let (_app, proxy) = loopback().expect("pair");
        let config = device(&["10.0.0.2"], true);
        let (to_tunnel, tunnel) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&config, to_tunnel, 0);
        stack
            .connect(ClientFlow {
                client: proxy,
                destinations: vec!["192.0.2.1:80".parse().expect("destination")],
                prefix: Vec::new(),
            })
            .expect("connect");
        let mut buf = [0u8; 2048];
        stack.poll(&mut buf);
        let syn = tunnel
            .recv_timeout(Duration::from_secs(5))
            .expect("the client's SYN");
        stack.device.push(syn_ack(&syn), 0);
        stack.poll(&mut buf);
        assert_eq!(
            stack
                .sockets
                .get::<TcpSocket>(stack.flows[0].handle)
                .state(),
            State::Established,
            "the SYN-ACK establishes the flow"
        );
        while tunnel.try_recv().is_ok() {}

        let (packets_tx, packets) = std::sync::mpsc::channel();
        packets_tx
            .send(Packet {
                peer: [0u8; 32],
                bytes: echo_v4([10, 0, 0, 1], [10, 0, 0, 2], b"ping"),
                at: 0,
            })
            .expect("a queued echo");
        stack.flows[0].stage_up(&[b'u'; 512]);
        assert!(
            !client_turn(&mut stack, &packets, &mut buf),
            "a live tunnel keeps the client turning"
        );
        assert!(
            !stack.flows[0].up_pending(),
            "this turn's poll took the staged upload"
        );
        let mut answered = false;
        while let Ok(packet) = tunnel.try_recv() {
            answered |=
                packet.get(9) == Some(&PROTOCOL_ICMP) && packet.get(IPV4_HEADER) == Some(&0);
        }
        assert!(answered, "progress on a flow left the tunnel's echo unread");
    }

    #[test]
    fn a_direct_upload_never_builds_the_staging_buffer() {
        let (mut stack, packets, mut app) = established_client();
        let mut buf = [0u8; 2048];

        app.write_all(b"hello").expect("write");
        let mut seen = false;
        for _ in 0..50 {
            stack.poll(&mut buf);
            while let Ok(packet) = packets.try_recv() {
                if packet
                    .windows(b"hello".len())
                    .any(|window| window == b"hello")
                {
                    seen = true;
                }
            }
            if seen {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            stack.flows[0].pending_up.capacity(),
            0,
            "an accepted upload is never copied into pending_up"
        );
        assert!(seen, "the accepted bytes leave on the tunnel");
    }

    #[test]
    fn a_datagram_address_is_written_in_stack_room_and_the_bytes_are_the_allocated_ones() {
        let source: IpAddr = "2001:db8::2".parse().unwrap();
        let destination: IpAddr = "2001:db8::7".parse().unwrap();
        let payload = b"addresses";
        let mut packet = Vec::with_capacity(IPV6_HEADER + 8 + payload.len());

        let ((), new) = ferrox_core::alloc_count::measure(|| {
            let mut source_room = [0u8; 16];
            let mut destination_room = [0u8; 16];
            let source_bytes = ip_bytes_into(source, &mut source_room);
            let destination_bytes = ip_bytes_into(destination, &mut destination_room);
            let datagram = UdpDatagram {
                source: source_bytes,
                destination: destination_bytes,
                source_port: 1234,
                destination_port: 53,
                payload,
            };
            assert!(udp_datagram(&datagram, &mut packet));
        });
        assert_eq!(new.allocs, 0, "the address build takes no heap: {new:?}");

        let mut reference = Vec::with_capacity(IPV6_HEADER + 8 + payload.len());
        let ((), old) = ferrox_core::alloc_count::measure(|| {
            let source_bytes = ip_bytes(source);
            let destination_bytes = ip_bytes(destination);
            let datagram = UdpDatagram {
                source: &source_bytes,
                destination: &destination_bytes,
                source_port: 1234,
                destination_port: 53,
                payload,
            };
            assert!(udp_datagram(&datagram, &mut reference));
        });
        assert_eq!(
            old.allocs, 2,
            "the old build allocated each address: {old:?}"
        );
        assert_eq!(packet, reference, "the stack room writes the same packet");
    }

    /// A server datagram lane carries its payload through the freedom outbound.
    #[test]
    fn a_server_datagram_lane_echoes_through_freedom() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let target = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (to_tunnel, replies) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let source: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let started = StdInstant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("instant");
        let last_used = Arc::new(AtomicU64::new(0));
        let (uplink, _) = server_udp(
            ([0x11; 32], source, target),
            started,
            &last_used,
            &out,
            &to_tunnel,
            0,
        )
        .expect("lane");
        let mut buf = Vec::new();
        let frame = crate::proxy::socks_udp_frame(&mut buf, None, &target, b"hi");
        uplink.send(frame).expect("send");
        let packet = replies.recv_timeout(Duration::from_secs(5)).expect("reply");
        assert!(
            last_used.load(Ordering::Relaxed) > 0,
            "a reply refreshes the lane's activity"
        );
        let datagram = udp_from_packet(&packet).expect("inner datagram");
        assert_eq!(datagram.payload, b"hi");
        assert_eq!(datagram.source, ip_bytes(target.ip()));
        assert_eq!(datagram.source_port, target.port());
        assert_eq!(datagram.destination, ip_bytes(source.ip()));
        assert_eq!(datagram.destination_port, source.port());
    }

    /// A server datagram reuses the per-lane frame head across a drain.
    #[test]
    fn a_server_stack_datagram_reuses_its_frame_head() {
        crate::budgets::clear();
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let target = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, replies) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&config, to_tunnel.clone(), out, 0);
        let source: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let send = |stack: &mut ServerStack, payload: &[u8]| {
            let mut inner = Vec::new();
            assert!(udp_datagram(
                &UdpDatagram {
                    source: &[10, 0, 0, 2],
                    destination: &[127, 0, 0, 1],
                    source_port: source.port(),
                    destination_port: target.port(),
                    payload,
                },
                &mut inner,
            ));
            let parsed = udp_from_packet(&inner).expect("inner datagram");
            let base = inner.as_ptr() as usize;
            let end = base + inner.len();
            let parsed_payload = parsed.payload.as_ptr() as usize;
            assert!((base..end).contains(&parsed_payload));
            LAST_SERVER_DATAGRAM.with(|sent| sent.set(None));
            stack.receive(Packet {
                peer: [0x11; 32],
                bytes: inner,
                at: 0,
            });
            let (head, sent) = LAST_SERVER_DATAGRAM
                .with(std::cell::Cell::get)
                .expect("the server datagram sent");
            let lane = stack.udp.values().next().expect("lane");
            assert_eq!(
                head,
                lane.head.as_ptr() as usize,
                "the head is the lane buffer"
            );
            assert_eq!(
                sent, parsed_payload,
                "the second iovec is the parsed payload, not a frame copy"
            );
            let packet = replies.recv_timeout(Duration::from_secs(5)).expect("reply");
            let datagram = udp_from_packet(&packet).expect("inner datagram");
            assert_eq!(datagram.payload, payload);
        };
        send(&mut stack, b"hi");
        let lane = stack.udp.values().next().expect("lane");
        let first_head = lane.head.as_ptr();
        let first = lane.head.capacity();
        assert!(first > 0, "the head is built once");
        send(&mut stack, b"again");
        let lane = stack.udp.values().next().expect("lane");
        assert_eq!(
            lane.head.as_ptr(),
            first_head,
            "the head allocation does not move"
        );
        assert_eq!(
            lane.head.capacity(),
            first,
            "the head buffer does not grow per datagram"
        );
        crate::budgets::clear();
    }

    #[test]
    fn a_server_datagram_lane_is_reclaimed_when_idle() {
        crate::budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_millis(100)),
            ..Default::default()
        });
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&config, to_tunnel.clone(), out.clone(), 0);
        let source: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let target: SocketAddr = "192.0.2.1:7".parse().unwrap();
        let key = ([0x11; 32], source, target);
        let started = StdInstant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("instant");
        stack.started = started;
        let last_used = Arc::new(AtomicU64::new(0));
        let (uplink, stop) =
            server_udp(key, started, &last_used, &out, &to_tunnel, 0).expect("lane");
        stack.udp.insert(
            key,
            UdpLane {
                uplink,
                head: Vec::new(),
                stop: Arc::clone(&stop),
                last_used,
            },
        );
        let mut buf = [0u8; 1024];
        stack.poll(&mut buf);
        assert!(stack.udp.is_empty(), "an idle lane leaves the table");
        assert!(stop.load(Ordering::Relaxed), "its reader is told to stop");
        crate::budgets::clear();
    }

    fn echo_v4(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let length = IPV4_HEADER + 8 + payload.len();
        let mut packet = vec![0u8; length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTOCOL_ICMP;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[IPV4_HEADER] = 8;
        packet[IPV4_HEADER + 8..].copy_from_slice(payload);
        packet
    }

    fn echo_v6(source: [u8; 16], destination: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let length = 8 + payload.len();
        let mut packet = vec![0u8; IPV6_HEADER + length];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        packet[6] = PROTOCOL_ICMPV6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet[IPV6_HEADER] = 128;
        packet[IPV6_HEADER + 8..].copy_from_slice(payload);
        packet
    }

    fn device(addresses: &[&str], is_client: bool) -> DeviceConfig {
        DeviceConfig {
            secret: [0u8; 32],
            addresses: addresses
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(is_client),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        }
    }

    /// An echo to the client's own address is answered on the tunnel.
    #[test]
    fn an_echo_to_the_devices_own_address_is_answered_on_the_tunnel() {
        let (to_tunnel, replies) = std::sync::mpsc::channel();
        let stack = ClientStack::new(
            &device(&["10.0.0.2", "fd00::2"], true),
            to_tunnel,
            WG_HEADER_SIZE,
        );

        assert!(stack.answer_echo(&echo_v4([10, 0, 0, 1], [10, 0, 0, 2], b"ping")));
        let reply = replies.try_recv().expect("a v4 reply");
        assert!(reply[..WG_HEADER_SIZE].iter().all(|&byte| byte == 0));
        assert_eq!(reply[WG_HEADER_SIZE], 0x45);
        assert_eq!(
            &reply[WG_HEADER_SIZE + 12..WG_HEADER_SIZE + 16],
            &[10, 0, 0, 2],
            "source is this device"
        );
        assert_eq!(
            &reply[WG_HEADER_SIZE + 16..WG_HEADER_SIZE + 20],
            &[10, 0, 0, 1],
            "target is the pinger"
        );
        assert_eq!(reply[WG_HEADER_SIZE + IPV4_HEADER], 0, "an echo reply");
        assert_eq!(&reply[WG_HEADER_SIZE + IPV4_HEADER + 8..], b"ping");

        assert!(stack.answer_echo(&echo_v6(
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            b"ping",
        )));
        let reply = replies.try_recv().expect("a v6 reply");
        assert!(reply[..WG_HEADER_SIZE].iter().all(|&byte| byte == 0));
        assert_eq!(reply[WG_HEADER_SIZE], 0x60);
        assert_eq!(reply[WG_HEADER_SIZE + IPV6_HEADER], 129, "an echo reply");
        assert_eq!(
            &reply[WG_HEADER_SIZE + IPV6_HEADER + 8..],
            b"ping",
            "the message comes back"
        );

        assert!(
            !stack.answer_echo(&echo_v4([10, 0, 0, 1], [10, 0, 0, 9], b"ping")),
            "not this device's address"
        );
        assert!(replies.try_recv().is_err(), "and no reply was sent");
    }

    /// An echo to the server's own tunnel address is answered locally.
    #[test]
    fn a_server_answers_an_echo_to_its_own_address() {
        let (to_tunnel, replies) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(
            &device(&["10.13.0.1"], false),
            to_tunnel,
            out,
            WG_HEADER_SIZE,
        );

        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: echo_v4([10, 13, 0, 2], [10, 13, 0, 1], b"ping"),
            at: 0,
        });
        let reply = replies.try_recv().expect("a reply");
        assert!(reply[..WG_HEADER_SIZE].iter().all(|&byte| byte == 0));
        assert_eq!(
            &reply[WG_HEADER_SIZE + 12..WG_HEADER_SIZE + 16],
            &[10, 13, 0, 1],
            "source is this server"
        );
        assert_eq!(
            &reply[WG_HEADER_SIZE + 16..WG_HEADER_SIZE + 20],
            &[10, 13, 0, 2],
            "target is the pinger"
        );
        assert_eq!(reply[WG_HEADER_SIZE + IPV4_HEADER], 0);

        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: echo_v4([10, 13, 0, 2], [10, 13, 0, 9], b"ping"),
            at: 0,
        });
        assert!(replies.try_recv().is_err(), "an address it does not own");
    }

    /// A handed-off flow carries the device peer in its PROXY header.
    #[test]
    fn the_handoff_names_the_device_peer_in_the_proxy_header() {
        let sink = std::net::TcpListener::bind("127.0.0.1:0").expect("sink");
        let sink_port = sink.local_addr().expect("addr").port();
        let (header, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = sink.accept().expect("accepts");
            let mut line = Vec::new();
            while line.len() < 1024 {
                let mut byte = [0u8; 1];
                if stream.read_exact(&mut byte).is_err() {
                    break;
                }
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    break;
                }
            }
            let _ = header.send(line);
        });

        let freedom = crate::json::parse(&format!(
            r#"{{"protocol":"freedom","tag":"f","settings":{{"redirect":"127.0.0.1:{sink_port}","proxyProtocol":1}}}}"#
        ))
        .expect("parses");
        let out = crate::proxy::build_outbound(&freedom, "f").expect("builds");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let mut stack = ServerStack::new(&device(&["10.13.0.1"], false), to_tunnel, out, 0);
        let source = [10, 13, 0, 2];
        let destination = [192, 0, 2, 1];
        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: tcp_segment(source, 1234, destination, 80, 1000, 0, 0x02),
            at: 0,
        });
        let mut buf = [0u8; 2048];
        stack.poll(&mut buf);
        let syn_ack = packets
            .recv_timeout(Duration::from_secs(5))
            .expect("the server's SYN-ACK");
        let ihl = usize::from(syn_ack[0] & 0x0f) * 4;
        let server_sequence = u32::from_be_bytes(
            syn_ack[ihl + 4..ihl + 8]
                .try_into()
                .expect("the server's sequence"),
        );
        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: tcp_segment(
                source,
                1234,
                destination,
                80,
                1001,
                server_sequence + 1,
                0x10,
            ),
            at: 0,
        });
        stack.poll(&mut buf);

        let line = received
            .recv_timeout(Duration::from_secs(5))
            .expect("the proxy header reached the redirect");
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        assert_eq!(fields.first(), Some(&b"PROXY".as_slice()), "{line:?}");
        assert_eq!(fields.get(1), Some(&b"TCP4".as_slice()), "{line:?}");
        assert_eq!(fields.get(2), Some(&b"10.13.0.2".as_slice()), "{line:?}");
        assert_eq!(fields.get(4), Some(&b"1234".as_slice()), "{line:?}");
    }

    #[test]
    fn a_server_download_leaves_as_fragments_the_client_reassembles() {
        let payload: Vec<u8> = (0..16 * 1024).map(|byte| (byte % 251) as u8).collect();
        let sink = std::net::TcpListener::bind("127.0.0.1:0").expect("sink");
        let sink_port = sink.local_addr().expect("addr").port();
        let served = payload.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = sink.accept().expect("accepts");
            let _ = stream.write_all(&served);
        });

        let freedom = crate::json::parse(&format!(
            r#"{{"protocol":"freedom","tag":"f","settings":{{"redirect":"127.0.0.1:{sink_port}"}}}}"#
        ))
        .expect("parses");
        let out = crate::proxy::build_outbound(&freedom, "f").expect("builds");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let mut stack = ServerStack::new(&device(&["10.13.0.1"], false), to_tunnel, out, 0);
        let source = [10, 0, 0, 2];
        let destination = [192, 0, 2, 1];
        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: syn_with_mss(65_495, 0x02),
            at: 0,
        });
        let mut buf = vec![0u8; 64 * 1024];
        stack.poll(&mut buf);
        let syn_ack = packets
            .recv_timeout(Duration::from_secs(5))
            .expect("the server's SYN-ACK");
        let ihl = usize::from(syn_ack[0] & 0x0f) * 4;
        let server_sequence = u32::from_be_bytes(
            syn_ack[ihl + 4..ihl + 8]
                .try_into()
                .expect("the server's sequence"),
        );
        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: tcp_segment(
                source,
                1234,
                destination,
                80,
                1001,
                server_sequence + 1,
                0x10,
            ),
            at: 0,
        });

        let mut reassembly = Reassembly::default();
        let mut chunks = std::collections::BTreeMap::new();
        let mut got = Vec::new();
        let mut want = server_sequence + 1;
        let mut saw_fragment = false;
        for _ in 0..1_000 {
            stack.poll(&mut buf);
            while let Ok(packet) = packets.try_recv() {
                saw_fragment |= fragment([0u8; 32], &packet).is_some();
                let packet = match reassembly.accept([0u8; 32], &packet, 0) {
                    Reassembled::Complete(packet) => packet,
                    Reassembled::Pass => packet,
                    Reassembled::Held => continue,
                };
                if packet.get(9) == Some(&PROTOCOL_TCP) {
                    let sequence = tcp_sequence(&packet).expect("the server's sequence");
                    let data = tcp_payload(&packet);
                    if !data.is_empty() {
                        chunks.insert(sequence, data.to_vec());
                    }
                }
            }
            while let Some(data) = chunks.remove(&want) {
                want = want.wrapping_add(data.len() as u32);
                got.extend_from_slice(&data);
                stack.receive(Packet {
                    peer: [0u8; 32],
                    bytes: tcp_segment(source, 1234, destination, 80, 1001, want, 0x10),
                    at: 0,
                });
            }
            if got.len() >= payload.len() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(saw_fragment, "the 16 KiB segment was not fragmented");
        assert_eq!(
            got.get(..payload.len()),
            Some(payload.as_slice()),
            "the client reassembled the download"
        );
    }

    fn tcp_data(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTOCOL_TCP;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        let header = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&1u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        tcp[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
        tcp[20..].copy_from_slice(payload);
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&[0, PROTOCOL_TCP]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        let sum = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn tcp6_data(source: [u8; 16], destination: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let total = 40 + 20 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[6] = PROTOCOL_TCP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        let tcp = &mut packet[40..];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&1u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        tcp[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
        tcp[20..].copy_from_slice(payload);
        let mut pseudo = Vec::with_capacity(40 + tcp.len());
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, PROTOCOL_TCP]);
        pseudo.extend_from_slice(tcp);
        let sum = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn syn_with_mss(mss: u16, flags: u8) -> Vec<u8> {
        let total = 44;
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTOCOL_TCP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        let header = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[12] = 0x60;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
        tcp[20..22].copy_from_slice(&[2, 4]);
        tcp[22..24].copy_from_slice(&mss.to_be_bytes());
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&[10, 0, 0, 2]);
        pseudo.extend_from_slice(&[192, 0, 2, 1]);
        pseudo.extend_from_slice(&[0, PROTOCOL_TCP]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        let sum = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    fn tcp_mss(packet: &[u8]) -> u16 {
        let (ip_header, _, _) = tcp_view(&packet[0..]).expect("a TCP packet");
        let option = tcp_mss_option(&packet[ip_header..]).expect("an MSS option");
        u16::from_be_bytes([packet[ip_header + option], packet[ip_header + option + 1]])
    }

    fn tcp_checksum_verifies(packet: &[u8]) -> bool {
        let Some((ip_header, _, total)) = tcp_view(packet) else {
            return false;
        };
        let mut segment = packet[ip_header..total].to_vec();
        let expected = u16::from_be_bytes([segment[16], segment[17]]);
        segment[16..18].copy_from_slice(&0u16.to_be_bytes());
        let (source, destination) = match packet[0] >> 4 {
            4 => (packet[12..16].to_vec(), packet[16..20].to_vec()),
            6 => (packet[8..24].to_vec(), packet[24..40].to_vec()),
            _ => return false,
        };
        tcp_checksum(&source, &destination, &segment) == expected
    }

    #[test]
    fn a_large_inner_packet_fragments_to_the_tunnel_and_reassembles() {
        let original = tcp_data([10, 0, 0, 2], [192, 0, 2, 1], &[0x5a; 5000]);
        let fragments = fragment_packet(&original, 0, TUNNEL_FRAGMENT).expect("fragments");
        assert_eq!(TUNNEL_FRAGMENT, 1_344);
        assert_eq!(fragments.len(), 4, "a 5 KiB segment takes four fragments");
        let id = u16::from_be_bytes([fragments[0][4], fragments[0][5]]);
        for fragment in &fragments {
            assert!(
                fragment.len() <= TUNNEL_FRAGMENT,
                "a fragment fits the tunnel"
            );
            assert_eq!(
                u16::from_be_bytes([fragment[4], fragment[5]]),
                id,
                "one packet's fragments share an identification"
            );
        }
        let other = fragment_packet(&original, 0, TUNNEL_FRAGMENT).expect("fragments");
        assert_ne!(
            u16::from_be_bytes([other[0][4], other[0][5]]),
            id,
            "a later packet gets its own identification"
        );
        let mut padded = fragments.clone();
        padded
            .last_mut()
            .expect("the last fragment")
            .extend_from_slice(b"trailing");
        let mut reassembly = Reassembly::default();
        let mut complete = None;
        for fragment in padded.iter().rev() {
            if let Reassembled::Complete(packet) = reassembly.accept([0u8; 32], fragment, 0) {
                complete = Some(packet);
            }
        }
        assert_eq!(complete.as_deref(), Some(original.as_slice()));
    }

    #[test]
    fn an_ipv6_packet_fragments_and_reassembles_without_its_fragment_header() {
        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let original = tcp6_data(source, destination, &[0x6b; 5000]);
        let fragments = fragment_packet(&original, 0, TUNNEL_FRAGMENT).expect("fragments");
        assert_eq!(fragments.len(), 4, "a 5 KiB segment takes four fragments");
        for fragment in &fragments {
            assert_eq!(fragment[6], 44, "the fragment header is present");
            assert!(fragment.len() <= TUNNEL_FRAGMENT);
        }
        let mut padded = fragments.clone();
        padded
            .last_mut()
            .expect("the last fragment")
            .extend_from_slice(b"trailing");
        let mut reassembly = Reassembly::default();
        let mut complete = None;
        for fragment in &padded {
            if let Reassembled::Complete(packet) = reassembly.accept([0u8; 32], fragment, 0) {
                complete = Some(packet);
            }
        }
        assert_eq!(complete.as_deref(), Some(original.as_slice()));
    }

    #[test]
    fn the_client_advertises_the_inner_mss() {
        let (app, proxy) = loopback().expect("pair");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let mut config = device(&["10.0.0.2"], true);
        config.large_segments = true;
        let mut stack = ClientStack::new(&config, to_tunnel, 0);
        stack
            .connect(ClientFlow {
                client: proxy,
                destinations: vec!["192.0.2.1:80".parse().expect("destination")],
                prefix: Vec::new(),
            })
            .expect("connect");
        let mut buf = [0u8; 2048];
        stack.poll(&mut buf);
        let syn = packets
            .recv_timeout(Duration::from_secs(5))
            .expect("the client's SYN");
        assert_eq!(tcp_mss(&syn), 65_495);
        drop(app);
    }

    /// Without the opt-in the client advertises the configured tunnel MSS.
    #[test]
    fn the_client_keeps_the_tunnel_mss_without_large_segments() {
        let (app, proxy) = loopback().expect("pair");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&device(&["10.0.0.2"], true), to_tunnel, 0);
        stack
            .connect(ClientFlow {
                client: proxy,
                destinations: vec!["192.0.2.1:80".parse().expect("destination")],
                prefix: Vec::new(),
            })
            .expect("connect");
        let mut buf = [0u8; 2048];
        stack.poll(&mut buf);
        let syn = packets
            .recv_timeout(Duration::from_secs(5))
            .expect("the client's SYN");
        assert_eq!(tcp_mss(&syn), 1_380);
        drop(app);
    }

    #[test]
    fn the_server_keeps_the_syn_mss_and_lowers_its_answer() {
        let (to_tunnel, tunneled) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&device(&["10.13.0.1"], false), to_tunnel, out, 0);
        stack.receive(Packet {
            peer: [0x11; 32],
            bytes: syn_with_mss(1240, 0x02),
            at: 0,
        });
        let (queued, at) = stack.device.rx.front().expect("the SYN reaches the stack");
        assert_eq!(
            tcp_mss(&queued[*at..]),
            1240,
            "the peer's advertised segment size is kept"
        );
        assert!(tcp_checksum_verifies(&queued[*at..]));
        let mut buf = [0u8; 1024];
        stack.poll(&mut buf);
        let answer = tunneled
            .recv_timeout(Duration::from_secs(5))
            .expect("the SYN-ACK");
        assert_eq!(tcp_mss(&answer), 1380);
        assert!(tcp_checksum_verifies(&answer));
    }

    /// A completed fragment is handed to the lane that asked for the datagram.
    #[test]
    fn a_fragmented_udp_reply_reaches_its_lane() {
        let payload = vec![0x5a; 3000];
        for ipv6 in [false, true] {
            let (to_tunnel, _) = std::sync::mpsc::channel();
            let addresses: &[&str] = if ipv6 {
                &["10.0.0.2", "fd00::2"]
            } else {
                &["10.0.0.2"]
            };
            let mut stack = ClientStack::new(&device(addresses, true), to_tunnel, 0);
            let (lane, replies) = std::sync::mpsc::channel();
            stack.routes.lock().expect("routes").insert(4321, lane);
            let (source, destination): (&[u8], &[u8]) = if ipv6 {
                (
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                )
            } else {
                (&[10, 0, 0, 2], &[192, 0, 2, 1])
            };
            let mut packet = Vec::new();
            let datagram = UdpDatagram {
                source,
                destination,
                source_port: 53,
                destination_port: 4321,
                payload: &payload,
            };
            assert!(udp_datagram(&datagram, &mut packet));
            let fragments =
                fragment_packet(&packet, 0, TUNNEL_FRAGMENT).expect("a fragmented datagram");
            assert!(fragments.len() > 1);
            for fragment in fragments {
                receive_client(
                    &mut stack,
                    Packet {
                        peer: [0u8; 32],
                        bytes: fragment,
                        at: 0,
                    },
                );
            }
            let reply = replies
                .recv_timeout(Duration::from_secs(5))
                .expect("the completed datagram reaches its lane");
            assert_eq!(reply, packet);
        }
    }

    #[test]
    fn the_fragment_limit_follows_the_carrier() {
        let out = || Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let (wireguard, _) = std::sync::mpsc::channel();
        let stack = ServerStack::new(
            &device(&["10.13.0.1"], false),
            wireguard,
            out(),
            WG_HEADER_SIZE,
        );
        assert_eq!(stack.fragment, 1420);
        let (masque, _) = std::sync::mpsc::sync_channel(1);
        let stack = ServerStack::new(&device(&["10.13.0.1"], false), masque, out(), 0);
        assert_eq!(stack.fragment, TUNNEL_FRAGMENT);
    }

    fn first_fragment(source: [u8; 4], id: u16) -> Vec<u8> {
        let mut packet = tcp_data(source, [192, 0, 2, 1], &[0x5a; 3000]);
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut fragment = fragment_packet(&packet, 0, TUNNEL_FRAGMENT)
            .and_then(|fragments| fragments.into_iter().next())
            .expect("a first fragment");
        fragment[4..6].copy_from_slice(&id.to_be_bytes());
        fragment
    }

    fn fragment_at(source: [u8; 4], id: u16, offset: u16, payload: &[u8], more: bool) -> Vec<u8> {
        let mut packet = tcp_data(source, [192, 0, 2, 1], payload);
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        let flags = (offset / 8) | if more { 0x2000 } else { 0 };
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        packet
    }

    fn far_fragment(source: [u8; 4], id: u16) -> Vec<u8> {
        fragment_at(source, id, 60_000, &[0x5a; 1_000], true)
    }

    fn empty_fragment(source: [u8; 4], id: u16, offset: u16) -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_HEADER];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(IPV4_HEADER as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&((offset / 8) | 0x2000).to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTOCOL_TCP;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        let checksum = ipv4_checksum(&packet[..IPV4_HEADER]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn a_flood_of_first_fragments_is_bounded_by_count() {
        let mut reassembly = Reassembly::default();
        for peer in 0..16u8 {
            for id in 0..REASSEMBLY_PEER_SETS as u16 {
                reassembly.accept([peer; 32], &first_fragment([10, 0, 0, peer + 2], id), 0);
            }
        }
        assert_eq!(reassembly.parts.len(), REASSEMBLY_SETS);
        reassembly.accept([16u8; 32], &first_fragment([10, 0, 0, 18], 0), 0);
        assert_eq!(
            reassembly.parts.len(),
            REASSEMBLY_SETS,
            "the set count was not bounded at the cap"
        );
        assert!(
            reassembly.parts.keys().any(|key| key.peer() == [16u8; 32]),
            "a new peer can still admit a fragment under set pressure"
        );
    }

    #[test]
    fn one_peers_fragments_do_not_evict_anothers() {
        let mut reassembly = Reassembly::default();
        for id in 0..REASSEMBLY_PEER_SETS as u16 {
            reassembly.accept([0u8; 32], &first_fragment([10, 0, 0, 2], id), 0);
        }
        reassembly.accept([1u8; 32], &first_fragment([10, 0, 0, 3], 0), 0);
        reassembly.accept([0u8; 32], &first_fragment([10, 0, 0, 2], 64), 0);
        assert!(
            reassembly.parts.keys().any(|key| key.peer() == [1u8; 32]),
            "one peer's flood evicted another peer's set"
        );
        assert_eq!(
            reassembly
                .parts
                .keys()
                .filter(|key| key.peer() == [0u8; 32])
                .count(),
            REASSEMBLY_PEER_SETS,
            "the flooding peer exceeded its own cap"
        );
    }

    #[test]
    fn a_peer_cannot_take_the_whole_reassembly_byte_budget() {
        let mut reassembly = Reassembly::default();
        for id in 0..10 {
            reassembly.accept([0u8; 32], &far_fragment([10, 0, 0, 2], id), 0);
        }
        assert!(
            reassembly.peer_usage([0u8; 32]).1 <= REASSEMBLY_PEER_BYTES,
            "one peer reserved more than its share"
        );
        reassembly.accept([1u8; 32], &first_fragment([10, 0, 0, 3], 0), 0);
        assert!(
            reassembly.parts.keys().any(|key| key.peer() == [1u8; 32]),
            "another peer could not admit a fragment"
        );
    }

    #[test]
    fn a_new_peer_can_admit_a_fragment_under_byte_pressure() {
        let mut reassembly = Reassembly::default();
        for peer in 0..24u8 {
            for id in 0..8 {
                reassembly.accept([peer; 32], &far_fragment([10, 0, 0, peer + 2], id), 0);
            }
        }
        assert!(reassembly.bytes <= REASSEMBLY_BYTES);
        reassembly.accept([99u8; 32], &first_fragment([10, 0, 0, 2], 0), 0);
        assert!(
            reassembly.parts.keys().any(|key| key.peer() == [99u8; 32]),
            "the byte budget was held by the existing peers"
        );
        assert!(reassembly.bytes <= REASSEMBLY_BYTES);
    }

    #[test]
    fn a_growing_set_evicts_another_set_of_its_peer() {
        let peer = [0u8; 32];
        let old = FragmentKey::V4 {
            peer,
            source: [10, 0, 0, 2],
            destination: [192, 0, 2, 1],
            protocol: PROTOCOL_TCP,
            id: 0,
        };
        let key = FragmentKey::V4 {
            peer,
            source: [10, 0, 0, 2],
            destination: [192, 0, 2, 1],
            protocol: PROTOCOL_TCP,
            id: 1,
        };
        let now = StdInstant::now();
        let mut reassembly = Reassembly::default();
        reassembly.parts.insert(
            old,
            FragmentSet {
                at: 0,
                header: Vec::new(),
                next_header: 0,
                payload: vec![0; 510_000],
                ranges: Vec::new(),
                last: None,
                started: now,
            },
        );
        reassembly.parts.insert(
            key,
            FragmentSet {
                at: 0,
                header: Vec::new(),
                next_header: 0,
                payload: vec![0; 128],
                ranges: Vec::new(),
                last: None,
                started: now + Duration::from_millis(1),
            },
        );
        reassembly.bytes = 510_128;
        let payload = vec![0x5a; 20_000];
        let packet = fragment_at([10, 0, 0, 2], 1, 0, &payload, true);
        reassembly.accept(peer, &packet, 0);
        assert!(
            reassembly.parts.contains_key(&key),
            "the growing set was dropped instead of evicting its peer's old set"
        );
        assert!(
            !reassembly.parts.contains_key(&old),
            "the peer's own old set was not evicted"
        );
        assert!(reassembly.peer_usage(peer).1 <= REASSEMBLY_PEER_BYTES);
    }

    #[test]
    fn empty_fragments_do_not_grow_range_metadata() {
        let mut reassembly = Reassembly::default();
        let peer = [0u8; 32];
        let first = first_fragment([10, 0, 0, 2], 0);
        reassembly.accept(peer, &first, 0);
        let key = FragmentKey::V4 {
            peer,
            source: [10, 0, 0, 2],
            destination: [192, 0, 2, 1],
            protocol: PROTOCOL_TCP,
            id: 0,
        };
        let before = reassembly
            .parts
            .get(&key)
            .expect("the first fragment")
            .ranges
            .len();
        let bytes = reassembly.bytes;
        for _ in 0..1_000 {
            reassembly.accept(peer, &empty_fragment([10, 0, 0, 2], 0, 0), 0);
        }
        let part = reassembly
            .parts
            .get(&key)
            .expect("the set is still pending");
        assert_eq!(part.ranges.len(), before, "empty fragments added ranges");
        assert_eq!(reassembly.bytes, bytes, "empty fragments reserved bytes");
    }

    #[test]
    fn range_metadata_is_bounded() {
        let mut reassembly = Reassembly::default();
        let peer = [0u8; 32];
        reassembly.accept(peer, &first_fragment([10, 0, 0, 2], 0), 0);
        for index in 0..REASSEMBLY_RANGES + 8 {
            let offset = 2_000 + index as u16 * 16;
            let packet = fragment_at([10, 0, 0, 2], 0, offset, &[0x5a; 8], true);
            reassembly.accept(peer, &packet, 0);
        }
        assert!(
            reassembly.parts.is_empty(),
            "range metadata grew past its cap"
        );
    }

    #[test]
    fn inconsistent_final_fragment_lengths_drop_the_set() {
        let peer = [0u8; 32];
        let short = tcp_data([10, 0, 0, 2], [192, 0, 2, 1], &[0x5a; 3_000]);
        let long = tcp_data([10, 0, 0, 2], [192, 0, 2, 1], &[0x5b; 4_000]);
        let mut short = fragment_packet(&short, 0, TUNNEL_FRAGMENT).expect("fragments");
        let mut long = fragment_packet(&long, 0, TUNNEL_FRAGMENT).expect("fragments");
        for fragment in short.iter_mut().chain(long.iter_mut()) {
            fragment[4..6].copy_from_slice(&7u16.to_be_bytes());
        }
        let mut reassembly = Reassembly::default();
        reassembly.accept(peer, &short[0], 0);
        reassembly.accept(peer, short.last().expect("a final fragment"), 0);
        assert_eq!(reassembly.parts.len(), 1, "the set is incomplete");
        reassembly.accept(peer, long.last().expect("a final fragment"), 0);
        assert!(
            reassembly.parts.is_empty(),
            "a second final fragment with another total was kept"
        );
    }

    #[test]
    fn a_growing_set_cannot_exceed_the_reassembly_byte_cap() {
        let mut fragment = tcp_data([10, 0, 0, 2], [192, 0, 2, 1], &[0x5a; 2_797]);
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut reassembly = Reassembly::default();
        for id in 0..128 {
            reassembly.parts.insert(
                FragmentKey::V4 {
                    peer: [id as u8; 32],
                    source: [10, 0, 0, 2],
                    destination: [192, 0, 2, 1],
                    protocol: PROTOCOL_TCP,
                    id,
                },
                FragmentSet {
                    at: 0,
                    header: fragment[..20].to_vec(),
                    next_header: 0,
                    payload: vec![0; 65_514],
                    ranges: Vec::new(),
                    last: None,
                    started: StdInstant::now(),
                },
            );
            reassembly.bytes += 65_514;
        }
        let key = FragmentKey::V4 {
            peer: [200u8; 32],
            source: [10, 0, 0, 2],
            destination: [192, 0, 2, 1],
            protocol: PROTOCOL_TCP,
            id: 128,
        };
        reassembly.parts.insert(
            key,
            FragmentSet {
                at: 0,
                header: fragment[..20].to_vec(),
                next_header: 0,
                payload: vec![0; 2_816],
                ranges: Vec::new(),
                last: None,
                started: StdInstant::now(),
            },
        );
        reassembly.bytes = REASSEMBLY_BYTES;
        fragment[4..6].copy_from_slice(&128u16.to_be_bytes());
        let _ = reassembly.accept([200u8; 32], &fragment, 0);
        assert!(!reassembly.parts.contains_key(&key));
        assert!(reassembly.bytes <= REASSEMBLY_BYTES);
    }

    /// A client packet cannot lower the server's MTU.
    #[test]
    fn a_client_cannot_narrow_the_server_mtu() {
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let mut stack = ServerStack::new(&device(&["10.13.0.1"], false), to_tunnel, out, 0);
        let before = stack.device.capabilities().max_transmission_unit;
        assert_eq!(before, 65_535, "the server stack builds a 64 KiB segment");
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[8] = 64;
        inner[9] = PROTOCOL_UDP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 2]);
        inner[16..20].copy_from_slice(&[198, 51, 100, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 1170).expect("a v4 answer");
        stack.receive(Packet {
            peer: [0u8; 32],
            bytes: too_big,
            at: 0,
        });
        assert_eq!(
            stack.device.capabilities().max_transmission_unit,
            before,
            "a client narrowed the MTU every tunnel shares"
        );
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use std::time::Duration;

    /// How long a lane's thread gets to hand back a packet it was told to tunnel: the suite runs its 1 722 tests over four cores, so a starved lane is not a lost packet.
    const LANE_WAIT: Duration = Duration::from_secs(30);

    fn resolve_one(host: &str, port: u16) -> Vec<SocketAddr> {
        crate::proxy::resolve_endpoint(host, port)
            .into_iter()
            .collect()
    }

    fn config() -> DeviceConfig {
        DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        }
    }

    #[test]
    fn a_client_datagram_lane_returns_when_its_client_leaves() {
        crate::budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let port = relay.local_addr().expect("address").port();
        let (associate, remote) = loopback().expect("pair");
        drop(remote);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let routes: UdpRoutes = Arc::default();
        let thread_routes = Arc::clone(&routes);
        crate::budgets::spawn(move || {
            let (to_tunnel, _) = std::sync::mpsc::channel();
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                Some(&associate),
                &resolve_one,
                0,
            );
            let _ = done_tx.send(());
        });
        let returned = done_rx.recv_timeout(Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("a closed control socket ends the lane");
        assert!(!routes.lock().expect("routes").contains_key(&port));
    }

    #[test]
    fn a_quiet_client_datagram_lane_returns_on_the_idle_budget() {
        crate::budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let port = relay.local_addr().expect("address").port();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let routes: UdpRoutes = Arc::default();
        let thread_routes = Arc::clone(&routes);
        crate::budgets::spawn(move || {
            let (to_tunnel, _) = std::sync::mpsc::channel();
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                None,
                &resolve_one,
                0,
            );
            let _ = done_tx.send(());
        });
        let returned = done_rx.recv_timeout(Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("a quiet lane ends on its idle budget");
        assert!(!routes.lock().expect("routes").contains_key(&port));
    }

    #[test]
    fn a_client_datagram_lane_frames_and_unframes() {
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("address");
        let app = UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let thread_routes = Arc::clone(&routes);
        std::thread::spawn(move || {
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                None,
                &resolve_one,
                0,
            );
        });
        let port = relay_address.port();
        for _ in 0..100 {
            if routes.lock().expect("routes").contains_key(&port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(routes.lock().expect("routes").contains_key(&port));

        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let mut buf = Vec::new();
        let frame = crate::proxy::socks_udp_frame(&mut buf, None, &target, b"query");
        app.send_to(frame, relay_address).expect("send");
        let inner = packets.recv_timeout(LANE_WAIT).expect("inner");
        let datagram = udp_from_packet(&inner).expect("packet");
        assert_eq!(datagram.source_port, port);
        assert_eq!(datagram.destination_port, 53);
        assert_eq!(datagram.payload, b"query");

        let source = ip_bytes(target.ip());
        let destination = ip_bytes("10.0.0.2".parse().unwrap());
        let mut reply = Vec::new();
        let answer = UdpDatagram {
            source: &source,
            destination: &destination,
            source_port: 53,
            destination_port: port,
            payload: b"answer",
        };
        assert!(udp_datagram(&answer, &mut reply));
        routes
            .lock()
            .expect("routes")
            .get(&port)
            .expect("lane")
            .send(reply)
            .expect("reply");
        let mut received = [0u8; 2048];
        let (n, _) = app.recv_from(&mut received).expect("framed reply");
        let (remote, payload) = crate::proxy::parse_socks_udp(&received[..n]).expect("frame");
        assert_eq!(remote, target);
        assert_eq!(payload, b"answer");
    }

    /// A client datagram name races every answer it was given.
    #[test]
    fn a_client_datagram_name_races_every_supplied_answer() {
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("address");
        let app = UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let thread_routes = Arc::clone(&routes);
        let targets: Vec<SocketAddr> = vec![
            "192.0.2.7:53".parse().unwrap(),
            "192.0.2.8:53".parse().unwrap(),
        ];
        let wanted = targets.clone();
        std::thread::spawn(move || {
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                None,
                &|host, port| {
                    if host == "other.test" {
                        assert_eq!(port, 54);
                        return vec![
                            "192.0.2.9:54".parse().unwrap(),
                            "192.0.2.10:54".parse().unwrap(),
                        ];
                    }
                    assert_eq!(host, "example.test");
                    assert_eq!(port, 53);
                    wanted.clone()
                },
                0,
            );
        });
        let port = relay_address.port();
        for _ in 0..100 {
            if routes.lock().expect("routes").contains_key(&port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(routes.lock().expect("routes").contains_key(&port));

        let name = b"example.test";
        let mut frame = vec![0, 0, 0, 3, name.len() as u8];
        frame.extend_from_slice(name);
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(b"query");
        app.send_to(&frame, relay_address).expect("send");
        let mut sent = Vec::new();
        for _ in 0..targets.len() {
            let inner = packets.recv_timeout(LANE_WAIT).expect("inner");
            let datagram = udp_from_packet(&inner).expect("packet");
            assert_eq!(datagram.destination_port, 53);
            assert_eq!(datagram.payload, b"query");
            sent.push(socket_addr(datagram.destination, 53).expect("target"));
        }
        sent.sort();
        let mut expected = targets;
        expected.sort();
        assert_eq!(sent, expected);
    }

    /// A replied datagram lane sends the next datagram only to the winner.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_replied_client_datagram_lane_sends_the_next_datagram_only_to_the_winner() {
        crate::budgets::apply(&crate::config::Budgets {
            udp_idle: Some(Duration::from_secs(300)),
            ..Default::default()
        });
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("address");
        let app = UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let thread_relay = relay.try_clone().expect("clone");
        let thread_config = config();
        let thread_routes = Arc::clone(&routes);
        let targets: Vec<SocketAddr> = vec![
            "192.0.2.7:53".parse().unwrap(),
            "192.0.2.8:53".parse().unwrap(),
        ];
        let wanted = targets.clone();
        crate::budgets::spawn(move || {
            client_udp(
                &thread_relay,
                &thread_config,
                &to_tunnel,
                &thread_routes,
                None,
                &|host, port| {
                    if host == "other.test" {
                        assert_eq!(port, 54);
                        return vec![
                            "192.0.2.9:54".parse().unwrap(),
                            "192.0.2.10:54".parse().unwrap(),
                        ];
                    }
                    assert_eq!(host, "example.test");
                    assert_eq!(port, 53);
                    wanted.clone()
                },
                0,
            );
        });
        let port = relay_address.port();
        for _ in 0..100 {
            if routes.lock().expect("routes").contains_key(&port) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(routes.lock().expect("routes").contains_key(&port));

        let name = b"example.test";
        let mut frame = vec![0, 0, 0, 3, name.len() as u8];
        frame.extend_from_slice(name);
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(b"query");
        app.send_to(&frame, relay_address).expect("send");
        let mut raced = Vec::new();
        let mut source_port = 0;
        for _ in 0..targets.len() {
            let inner = packets.recv_timeout(LANE_WAIT).expect("inner");
            let datagram = udp_from_packet(&inner).expect("packet");
            if source_port == 0 {
                source_port = datagram.source_port;
            }
            assert_eq!(datagram.source_port, source_port, "one port per name");
            raced.push(socket_addr(datagram.destination, 53).expect("target"));
        }
        assert_eq!(raced, targets, "the first datagram races every answer");
        assert_ne!(source_port, port, "a name gets its own tunnel source port");

        let winner = targets[0];
        let mut source_room = [0u8; 16];
        let source = ip_bytes_into(winner.ip(), &mut source_room);
        let mut reply = Vec::new();
        assert!(udp_datagram(
            &UdpDatagram {
                source,
                destination: &[10, 0, 0, 2],
                source_port: winner.port(),
                destination_port: source_port,
                payload: b"answer",
            },
            &mut reply,
        ));
        routes
            .lock()
            .expect("routes")
            .get(&source_port)
            .expect("lane")
            .send(reply)
            .expect("reply");

        let mut received = [0u8; 2048];
        let (n, _) = app.recv_from(&mut received).expect("framed reply");
        let (remote, payload) = crate::proxy::parse_socks_udp(&received[..n]).expect("frame");
        assert_eq!(remote, winner);
        assert_eq!(payload, b"answer");

        let loser = targets[1];
        let mut source_room = [0u8; 16];
        let source = ip_bytes_into(loser.ip(), &mut source_room);
        let mut reply = Vec::new();
        assert!(udp_datagram(
            &UdpDatagram {
                source,
                destination: &[10, 0, 0, 2],
                source_port: loser.port(),
                destination_port: source_port,
                payload: b"loser",
            },
            &mut reply,
        ));
        routes
            .lock()
            .expect("routes")
            .get(&port)
            .expect("lane")
            .send(reply)
            .expect("reply");
        app.set_read_timeout(Some(Duration::from_millis(150)))
            .expect("timeout");
        assert!(
            app.recv_from(&mut received).is_err(),
            "a reply from outside the pinned target is dropped"
        );
        app.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");

        app.send_to(&frame, relay_address).expect("send again");
        let inner = packets.recv_timeout(LANE_WAIT).expect("inner");
        let datagram = udp_from_packet(&inner).expect("packet");
        assert_eq!(
            socket_addr(datagram.destination, 53).expect("target"),
            winner
        );
        assert!(
            packets.recv_timeout(Duration::from_millis(150)).is_err(),
            "a replied lane must not fan the next datagram out"
        );

        let name = b"other.test";
        let mut other = vec![0, 0, 0, 3, name.len() as u8];
        other.extend_from_slice(name);
        other.extend_from_slice(&54u16.to_be_bytes());
        other.extend_from_slice(b"other");
        app.send_to(&other, relay_address).expect("send other");
        let mut raced = Vec::new();
        let mut other_port = 0;
        for _ in 0..2 {
            let inner = packets.recv_timeout(LANE_WAIT).unwrap_or_else(|error| {
                let alive = routes
                    .lock()
                    .is_ok_and(|table| table.contains_key(&source_port));
                panic!("inner: {error} (lane alive: {alive})");
            });
            let datagram = udp_from_packet(&inner).expect("packet");
            assert_eq!(datagram.destination_port, 54);
            other_port = datagram.source_port;
            raced.push(socket_addr(datagram.destination, 54).expect("target"));
        }
        assert_ne!(other_port, source_port, "each name races on its own port");
        assert_eq!(
            raced,
            vec![
                "192.0.2.9:54".parse::<SocketAddr>().unwrap(),
                "192.0.2.10:54".parse::<SocketAddr>().unwrap()
            ],
            "another destination on the same lane still races"
        );
        crate::budgets::clear();
    }

    /// A consumed device token returns its slot with the same allocation and capacity.
    #[test]
    fn a_queue_token_returns_the_received_buffer() {
        let (recycle, recycled) = mpsc::channel();
        let mut device = QueueDevice::new(1500, 16);
        device.recycle = Some(recycle);
        let mut buffer = vec![0u8; 1500];
        buffer[16..19].copy_from_slice(b"tcp");
        let base = buffer.as_ptr();
        let capacity = buffer.capacity();
        device.push(buffer, 16);
        let (token, _) = device.receive(Instant::from_millis(0)).expect("a token");
        token.consume(|bytes| assert_eq!(&bytes[..3], b"tcp"));
        let back = recycled.try_recv().expect("the slot comes back");
        assert_eq!(back.as_ptr(), base);
        assert_eq!(back.capacity(), capacity);
    }

    /// A Packet Too Big lowers the device MTU once and never widens it.
    #[test]
    fn a_packet_too_big_narrows_the_device_mtu() {
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[8] = 64;
        inner[9] = PROTOCOL_UDP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 2]);
        inner[16..20].copy_from_slice(&[198, 51, 100, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 1170).expect("a v4 answer");
        let mut device = QueueDevice::new(1420, 0);
        assert!(device.absorb(&too_big));
        assert_eq!(device.capabilities().max_transmission_unit, 1170);
        assert!(!device.absorb(&too_big), "never wider again");

        let mut inner = vec![0u8; 48];
        inner[0] = 0x60;
        inner[4..6].copy_from_slice(&8u16.to_be_bytes());
        inner[6] = PROTOCOL_UDP;
        inner[7] = 64;
        inner[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 1280).expect("a v6 answer");
        let mut device = QueueDevice::new(1420, 0);
        assert!(device.absorb(&too_big));
        assert_eq!(device.capabilities().max_transmission_unit, 1280);

        let mut forged = too_big;
        forged[40] = 3;
        assert!(!device.absorb(&forged), "not a packet too big");
    }
    /// A learned MTU reaches the SYN's advertised segment size.
    #[test]
    fn a_learned_mtu_reaches_the_client_segment_size() {
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![crate::wireguard::PeerConfig {
                public: [0u8; 32],
                preshared: [0; 32],
                endpoint: None,
                endpoints: Vec::new(),
                keepalive: 0,
                allowed: vec![("0.0.0.0".parse().unwrap(), 0)],
            }],
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, packets) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&config, to_tunnel, 0);
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[8] = 64;
        inner[9] = PROTOCOL_UDP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 2]);
        inner[16..20].copy_from_slice(&[198, 51, 100, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 600).expect("a v4 answer");
        receive_client(
            &mut stack,
            Packet {
                peer: [0u8; 32],
                bytes: too_big,
                at: 0,
            },
        );

        let (app, proxy) = loopback().expect("pair");
        stack
            .connect(ClientFlow {
                client: proxy,
                destinations: vec!["192.0.2.1:80".parse().expect("destination")],
                prefix: Vec::new(),
            })
            .expect("connect");
        let mut buf = [0u8; 2048];
        stack.poll(&mut buf);
        let syn = packets.recv_timeout(LANE_WAIT).expect("SYN");
        let header = usize::from(syn[0] & 0x0f) * 4;
        let options = header + 20..header + usize::from(syn[header + 12] >> 4) * 4;
        let mut at = options.start;
        let mut mss = None;
        while at < options.end {
            match syn[at] {
                0 => break,
                1 => at += 1,
                kind => {
                    let len = usize::from(syn[at + 1]);
                    if kind == 2 && len == 4 {
                        mss = Some(u16::from_be_bytes([syn[at + 2], syn[at + 3]]));
                    }
                    at += len;
                }
            }
        }
        assert!(
            usize::from(mss.expect("a SYN advertises MSS")) <= 600 - 20 - 20,
            "the SYN advertises the learned MTU's segment size"
        );
        drop(app);
    }

    /// A MASQUE client has no peer table, so its own Packet Too Big still narrows the path.
    #[test]
    fn a_packet_too_big_narrows_a_client_without_peers() {
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&config, to_tunnel, 0);
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[8] = 64;
        inner[9] = PROTOCOL_UDP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 2]);
        inner[16..20].copy_from_slice(&[198, 51, 100, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 1200).expect("a v4 answer");
        receive_client(
            &mut stack,
            Packet {
                peer: [0u8; 32],
                bytes: too_big,
                at: 0,
            },
        );
        assert_eq!(
            stack.device.capabilities().max_transmission_unit,
            1200,
            "the client without peers ignored its own Packet Too Big"
        );
    }

    /// One peer's Packet Too Big does not narrow another peer's path.
    #[test]
    fn a_peer_cannot_narrow_another_peers_path() {
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![
                crate::wireguard::PeerConfig {
                    public: [0x11; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    endpoints: Vec::new(),
                    keepalive: 0,
                    allowed: vec![("198.51.100.0".parse().unwrap(), 24)],
                },
                crate::wireguard::PeerConfig {
                    public: [0x22; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    endpoints: Vec::new(),
                    keepalive: 0,
                    allowed: vec![("203.0.113.0".parse().unwrap(), 24)],
                },
            ],
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: true,
            dns: Vec::new(),
        };
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&config, to_tunnel, 0);
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[8] = 64;
        inner[9] = PROTOCOL_UDP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 2]);
        inner[16..20].copy_from_slice(&[203, 0, 113, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 1000).expect("a v4 answer");
        receive_client(
            &mut stack,
            Packet {
                peer: [0x11; 32],
                bytes: too_big,
                at: 0,
            },
        );
        assert_eq!(
            stack.device.capabilities().max_transmission_unit,
            INNER_MTU,
            "one peer narrowed another peer's path"
        );
    }

    /// One peer's Packet Too Big does not narrow the MTU another peer uses.
    #[test]
    fn a_peer_cannot_narrow_the_mtu_another_peer_uses() {
        let config = DeviceConfig {
            secret: [0u8; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![
                crate::wireguard::PeerConfig {
                    public: [0x11; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    endpoints: Vec::new(),
                    keepalive: 0,
                    allowed: vec![("0.0.0.0".parse().unwrap(), 0)],
                },
                crate::wireguard::PeerConfig {
                    public: [0x22; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    endpoints: Vec::new(),
                    keepalive: 0,
                    allowed: vec![("0.0.0.0".parse().unwrap(), 0)],
                },
            ],
            mtu: 1420,
            reserved: [0u8; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: true,
            dns: Vec::new(),
        };
        let (to_tunnel, _) = std::sync::mpsc::channel();
        let mut stack = ClientStack::new(&config, to_tunnel, 0);
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[8] = 64;
        inner[9] = PROTOCOL_UDP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 2]);
        inner[16..20].copy_from_slice(&[198, 51, 100, 7]);
        let too_big =
            ferrox_core::foxy::connectip::icmp_too_large(&inner, 600).expect("a v4 answer");
        receive_client(
            &mut stack,
            Packet {
                peer: [0x11; 32],
                bytes: too_big,
                at: 0,
            },
        );
        assert_eq!(
            stack.device.capabilities().max_transmission_unit,
            INNER_MTU,
            "one peer narrowed the MTU every peer shares"
        );
    }
}

#[cfg(all(test, unix))]
mod readiness_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn readiness_names_only_the_stream_with_bytes() {
        let (first, mut first_peer) = UnixStream::pair().expect("first pair");
        let (second, _second_peer) = UnixStream::pair().expect("second pair");
        let locals = [Connection::from(first), Connection::from(second)];
        let mut readiness = Readiness::new();
        assert_eq!(readiness.sync_locals(locals.iter()), &[false, false]);
        first_peer.write_all(b"x").expect("write");
        assert_eq!(readiness.sync_locals(locals.iter()), &[true, false]);
    }
}
