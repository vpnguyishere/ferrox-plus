//! The native TUN device inbound: opens a virtual interface, reads IP packets, turns each TCP
//! flow into a proxy dial through `serve_connect` and each UDP flow into a datagram dial through
//! a SOCKS5 UDP association — the same two entries every other front reaches, no second dialer.
//!
//! Byte-identity: a TUN carries no wire byte-stream to diff, so this row's identity claim is
//! the (target, payload) dial-set differential — the set of (destination, payload) pairs the
//! inbound produces from a given packet stream must match the pinned reference. Proven by
//! the loopback test set; the oracle lives in `scripts/tun-oracle`.
//!
//! Platform opens: Linux `/dev/net/tun` + `TUNSETIFF`, macOS utun, and an inherited
//! descriptor (`FERROX_TUN_FD`). The privileged opens are compile-checked only — no CI
//! runner holds `CAP_NET_ADMIN` — while the inherited-fd path runs fully in tests.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::sync::{mpsc, Arc};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::budgets;
use crate::conn::Connection;
use ferrox_core::foxy::connectip::{
    icmp_echo_reply, ipv4_checksum, ipv4_head, tcp_checksum, udp_datagram, udp_head, Ipv4Head,
    UdpDatagram, IPV4_HEADER, PROTOCOL_UDP, UDP_HEADER,
};

const DEFAULT_MTU: usize = 1500;
/// The head of a framed datagram: the RSV/FRAG prefix and the widest address (IPv6 plus its port). The payload stays the device's buffer and is handed to the socket by pointer.
const FRAME_CAP: usize = 3 + 1 + 16 + 2;
const TCP_PROTO: u8 = 6;
const ICMP_PROTO: u8 = 1;
/// An ICMP echo request is type 8; its answer flips that to type 0 and carries the message back.
const ICMP_ECHO_REQUEST: u8 = 8;
#[cfg(all(test, unix))]
const ICMP_ECHO_REPLY: u8 = 0;
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

pub(crate) fn is_device(protocol: &str) -> bool {
    matches!(protocol, "tun" | "utun" | "wintun" | "tun2socks")
}

const DEFAULT_ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 1));
const DEFAULT_PREFIX: u8 = 15;

pub(crate) struct Spec {
    name: String,
    mtu: usize,
    address: IpAddr,
    prefix: u8,
    queues: usize,
}

impl Spec {
    pub(crate) fn new(name: Option<&str>, mtu: Option<usize>) -> Self {
        Self::with(name, mtu, None, None, None)
    }

    pub(crate) fn with(
        name: Option<&str>,
        mtu: Option<usize>,
        address: Option<IpAddr>,
        prefix: Option<u8>,
        queues: Option<usize>,
    ) -> Self {
        Self {
            name: name
                .filter(|n| !n.is_empty())
                .unwrap_or("ferrox0")
                .to_owned(),
            mtu: mtu.filter(|m| *m > 0).unwrap_or(DEFAULT_MTU),
            address: address.unwrap_or(DEFAULT_ADDRESS),
            prefix: prefix.filter(|p| *p > 0).unwrap_or(DEFAULT_PREFIX),
            queues: queues.filter(|q| *q > 0).unwrap_or_else(default_queues),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn mtu(&self) -> usize {
        self.mtu
    }

    pub(crate) fn address(&self) -> IpAddr {
        self.address
    }

    pub(crate) fn prefix(&self) -> u8 {
        self.prefix
    }

    pub(crate) fn queues(&self) -> usize {
        self.queues
    }
}

pub(crate) fn default_queues() -> usize {
    if cfg!(target_os = "linux") {
        std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
    } else {
        1
    }
}

/// Split `address[/prefix]` and let an explicit `prefix` fill a missing CIDR.
pub(crate) fn parse_address(
    value: Option<&str>,
    prefix: Option<u32>,
) -> (Option<IpAddr>, Option<u8>) {
    let explicit = prefix.and_then(|p| u8::try_from(p).ok());
    let Some(value) = value else {
        return (None, explicit);
    };
    let (address, cidr) = match value.split_once('/') {
        Some((address, prefix)) => (address, prefix.parse::<u8>().ok()),
        None => (value, None),
    };
    (address.parse::<IpAddr>().ok(), cidr.or(explicit))
}

#[derive(Debug, Clone, Copy)]
struct TcpHead {
    source_port: u16,
    destination_port: u16,
    seq: u32,
    flags: u8,
}

fn tcp_head(body: &[u8]) -> Option<(TcpHead, &[u8])> {
    if body.len() < 20 {
        return None;
    }
    let source_port = u16::from_be_bytes([body[0], body[1]]);
    let destination_port = u16::from_be_bytes([body[2], body[3]]);
    let seq = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let data_offset = usize::from(body[12] >> 4) * 4;
    if data_offset < 20 || data_offset > body.len() {
        return None;
    }
    let flags = body[13];
    Some((
        TcpHead {
            source_port,
            destination_port,
            seq,
            flags,
        },
        &body[data_offset..],
    ))
}

/// Whether an ICMP body is an IPv4 echo request worth answering: type 8, code 0, and at
/// least the eight-byte header. A reply, another code or a truncated message is refused.
fn is_echo_request(body: &[u8]) -> bool {
    body.len() >= 8 && body[0] == ICMP_ECHO_REQUEST && body[1] == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
}

/// One datagram flow, keyed the same way as a stream flow: the device's own address is implied by the packet's destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
}

/// A flow a thread has left: its entry goes at the next packet, so the packet path pays nothing for the reap.
enum Ended {
    Stream(FlowKey),
    Datagram(UdpKey),
}

/// A TUN device: a file descriptor carrying raw IP packets (`IFF_TUN` | `IFF_NO_PI` on Linux).
pub(crate) struct Device {
    handle: std::fs::File,
    mtu: usize,
}

impl Device {
    pub(crate) fn open(spec: &Spec) -> io::Result<Self> {
        if let Some(handle) = inherited_handle() {
            return Ok(Self {
                handle,
                mtu: spec.mtu,
            });
        }
        #[cfg(target_os = "linux")]
        return Self::open_linux(spec);
        #[cfg(target_os = "macos")]
        return Self::open_macos(spec);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no TUN platform open; set FERROX_TUN_FD for an inherited descriptor",
        ))
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = buf.len().min(self.mtu + 4);
        self.handle.read(&mut buf[..limit])
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.handle.write_all(packet)
    }

    fn clone_writer(&self) -> io::Result<std::fs::File> {
        self.handle.try_clone()
    }

    #[cfg(all(test, unix))]
    fn from_handle(handle: std::fs::File, mtu: usize) -> Self {
        Self { handle, mtu }
    }
}

#[cfg(unix)]
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_raw_fd()
    }
}

fn inherited_handle() -> Option<std::fs::File> {
    let fd_str = std::env::var_os("FERROX_TUN_FD")?;
    let fd: i64 = fd_str.to_str()?.parse().ok()?;
    if fd < 0 {
        return None;
    }
    #[cfg(unix)]
    return Some(unsafe { std::fs::File::from_raw_fd(fd as RawFd) });
    #[cfg(not(unix))]
    {
        let _ = fd;
        None
    }
}

#[cfg(target_os = "linux")]
impl Device {
    fn open_linux(spec: &Spec) -> io::Result<Self> {
        use std::ffi::CString;
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; 16],
            ifr_flags: libc::c_short,
            _pad: [u8; 22],
        }
        let path = CString::new("/dev/net/tun").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut req = IfReq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let n = spec.name.as_bytes();
        let l = n.len().min(15);
        req.ifr_name[..l].copy_from_slice(&n[..l]);
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &req) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Self {
            handle: unsafe { std::fs::File::from_raw_fd(fd) },
            mtu: spec.mtu,
        })
    }
}

#[cfg(target_os = "macos")]
impl Device {
    fn open_macos(spec: &Spec) -> io::Result<Self> {
        const SYSPROTO_CONTROL: libc::c_int = 2;
        const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
        const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
        #[repr(C)]
        struct CtlInfo {
            ci_id: u32,
            ci_name: [u8; 128],
            ci_rcvbuf: libc::c_int,
            ci_sndbuf: libc::c_int,
            ci_flags: u16,
            _p: [u8; 6],
            ci_maxunits: libc::c_int,
            _r: [u8; 2],
        }
        #[repr(C)]
        struct SockaddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            _r: [u8; 8],
        }
        let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut info = CtlInfo {
            ci_id: 0,
            ci_name: [0; 128],
            ci_rcvbuf: 0,
            ci_sndbuf: 0,
            ci_flags: 0,
            _p: [0; 6],
            ci_maxunits: 0,
            _r: [0; 2],
        };
        let nl = UTUN_CONTROL_NAME.len();
        info.ci_name[..nl].copy_from_slice(UTUN_CONTROL_NAME);
        if unsafe { libc::ioctl(fd, CTLIOCGINFO as _, &mut info) } < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: 2,
            sc_id: info.ci_id,
            sc_unit: 0,
            _r: [0; 8],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Self {
            handle: unsafe { std::fs::File::from_raw_fd(fd) },
            mtu: spec.mtu,
        })
    }
}

/// Render one IPv4/TCP packet into `out` — the caller's reused buffer — so a steady stream of SYN-ACKs, pure ACKs and response packets allocates and zero-fills nothing per packet. The IPv4 and TCP headers are built on the stack and extended, the payload is extended once, and both checksums are computed in place, the twelve-byte pseudo-header summed as words and never written. The bytes are what a freshly zero-filled buffer would hold for the same arguments: every header byte is named explicitly and the checksum field is read as zero until it is computed.
#[allow(clippy::too_many_arguments)] // the fields of one IPv4/TCP header, plus the caller's reused out buffer
fn render_tcp_packet(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    let (src, src_port) = src;
    let (dst, dst_port) = dst;
    let tcp_len = 20 + payload.len();
    let ip_len = IPV4_HEADER + tcp_len;
    out.clear();
    out.reserve(ip_len);
    let mut ip = [0u8; IPV4_HEADER];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = TCP_PROTO;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    let c = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack_num.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    out.extend_from_slice(&ip);
    out.extend_from_slice(&tcp);
    out.extend_from_slice(payload);
    let tc = tcp_checksum(&src, &dst, &out[IPV4_HEADER..]);
    out[IPV4_HEADER + 16..IPV4_HEADER + 18].copy_from_slice(&tc.to_be_bytes());
}

/// An ICMP echo request answered as the device's own destination would: the shared renderer
/// flips the type, swaps the addresses and recomputes both checksums into the caller's reused
/// `out`, so a ping storm allocates nothing per reply. `src` and `dst` are the reply's, the
/// request's the other way round.
fn render_icmp_reply(src: [u8; 4], dst: [u8; 4], request: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let _ = icmp_echo_reply(IpAddr::from(dst), IpAddr::from(src), request, out);
}

/// Test-only: the render pair behind a fresh vector, so a caller that only wants to inspect one packet need not thread a buffer. Production emits reach the device through `render_*_packet` into a reused buffer.
#[cfg(test)]
fn build_tcp_packet(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    render_tcp_packet(src, dst, seq, ack_num, flags, window, payload, &mut out);
    out
}

#[cfg(test)]
fn build_icmp_reply(src: [u8; 4], dst: [u8; 4], request: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    render_icmp_reply(src, dst, request, &mut out);
    out
}

/// One active TCP flow's state. The two cursors are shared with the response
/// thread: `rcv_nxt` advances as the handler delivers payload to the proxy, and
/// `snd_nxt` advances as the response thread sends payload out, so a pure ACK
/// carries both numbers truthfully.
struct Flow {
    write_half: TcpStream,
    rcv_nxt: Arc<AtomicU32>,
    snd_nxt: Arc<AtomicU32>,
    /// Payload reached the proxy since the response thread's last idle expiry: a flow is alive when either direction spoke inside the budget.
    busy: Arc<AtomicBool>,
    last_acked: u32,
    local: ([u8; 4], u16),
    remote: ([u8; 4], u16),
    /// One close packet — `FIN` or `RST` — leaves per flow, whichever thread sees the end first.
    signaled: Arc<AtomicBool>,
}

/// The relay function the TUN handler calls per TCP flow: takes the proxied Connection and
/// the destination extracted from the packet headers. An error means the proxy leg was
/// refused, so the device's established flow is reset rather than left silent.
pub(crate) type Relay =
    Arc<dyn Fn(Connection, crate::proxy::Destination) -> io::Result<()> + Send + Sync>;

/// The datagram entry the TUN handler rides per UDP flow: handed the client half of an association, it runs the same SOCKS5 UDP server the SOCKS inbound reaches, `serve_socks_udp`.
pub(crate) type Associate = Arc<dyn Fn(Connection) + Send + Sync>;

/// The device's one association: the control leg stays open for its life, as every other SOCKS front's does, and `relay` is where every flow's framed datagram is sent.
struct Association {
    control: Connection,
    relay: SocketAddr,
}

impl Association {
    /// Associate over a loopback pair and read the relay address off the reply: the
    /// reply is the ten bytes a SOCKS5 server writes for a `UDP ASSOCIATE`, so the
    /// outbound's UDP arms cannot tell a device from a proxy client.
    fn open(associate: &Associate) -> io::Result<Self> {
        let associate = Arc::clone(associate);
        let association =
            crate::proxy::udp_association(move |conn| associate(conn)).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the association refused its address type",
                )
            })?;
        Ok(Self {
            control: association.control,
            relay: association.relay,
        })
    }
}

/// The TUN handler: reads packets, relays each TCP flow and each UDP flow through the proxy outbound.
pub(crate) struct Handler {
    device: Device,
    relay: Relay,
    associate: Associate,
    flows: HashMap<FlowKey, Flow>,
    legs: HashMap<UdpKey, UdpSocket>,
    frame: Vec<u8>,
    /// Reused render buffer for every device-bound packet this thread emits (SYN-ACK, pure ACK, ICMP reply), so the emit path allocates nothing in steady state.
    emit: Vec<u8>,
    association: Option<Association>,
    ended_tx: mpsc::Sender<Ended>,
    ended_rx: mpsc::Receiver<Ended>,
}

impl Handler {
    pub(crate) fn new(device: Device, relay: Relay, associate: Associate) -> Self {
        let (ended_tx, ended_rx) = mpsc::channel();
        let emit = Vec::with_capacity(device.mtu + 64);
        Self {
            device,
            relay,
            associate,
            flows: HashMap::new(),
            legs: HashMap::new(),
            frame: Vec::with_capacity(FRAME_CAP),
            emit,
            association: None,
            ended_tx,
            ended_rx,
        }
    }

    pub(crate) fn serve(&mut self) -> io::Result<()> {
        let mut buf = vec![0u8; self.device.mtu + 64];
        loop {
            let n = self.device.read_packet(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            if let Err(e) = self.dispatch(&buf[..n]) {
                eprintln!("tun dispatch: {e}");
            }
        }
    }

    fn dispatch(&mut self, packet: &[u8]) -> io::Result<()> {
        // Threads that left their flow report here, so neither table keeps a dead entry or the socket inside it.
        while let Ok(ended) = self.ended_rx.try_recv() {
            match ended {
                Ended::Stream(key) => {
                    self.flows.remove(&key);
                }
                Ended::Datagram(key) => {
                    self.legs.remove(&key);
                }
            }
        }
        let Some((ip, body)) = ipv4_head(packet) else {
            return Ok(());
        };
        match ip.protocol {
            TCP_PROTO => self.handle_tcp(&ip, body),
            PROTOCOL_UDP => self.handle_udp(&ip, body),
            ICMP_PROTO => self.handle_icmp(&ip, body),
            _ => Ok(()),
        }
    }

    /// Relay one datagram: the flow's leg is raised on the association's relay address and every packet afterwards rides it, framed with the destination the device asked for. A packet whose association or leg cannot be raised is lost, as an unroutable datagram is at every other front.
    fn handle_udp(&mut self, ip: &Ipv4Head, body: &[u8]) -> io::Result<()> {
        let Some((udp, payload)) = udp_head(body) else {
            return Ok(());
        };
        if self.association.is_none() {
            if let Ok(association) = Association::open(&self.associate) {
                self.association = Some(association);
            }
        }
        let Some(association) = &self.association else {
            return Ok(());
        };
        let relay = association.relay;
        let target = SocketAddr::from((ip.destination, udp.destination_port));
        let key = UdpKey {
            source_port: udp.source_port,
            destination: ip.destination,
            destination_port: udp.destination_port,
        };
        let leg = match self.legs.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(vacant) => vacant.insert(open_leg(
                &self.device,
                relay,
                (ip.destination, udp.destination_port),
                (ip.source, udp.source_port),
                key,
                &self.ended_tx,
            )?),
        };
        let mut frame = std::mem::take(&mut self.frame);
        let (front, tail) = crate::proxy::socks_udp_parts(&mut frame, &target, payload);
        let sent = crate::proxy::send_two(leg, front, tail);
        self.frame = frame;
        if sent.is_err() {
            self.legs.remove(&key);
        }
        Ok(())
    }

    fn handle_tcp(&mut self, ip: &Ipv4Head, body: &[u8]) -> io::Result<()> {
        let Some((tcp, payload)) = tcp_head(body) else {
            return Ok(());
        };
        let key = FlowKey {
            source_port: tcp.source_port,
            destination: ip.destination,
            destination_port: tcp.destination_port,
        };
        if tcp.flags & FLAG_SYN != 0 && tcp.flags & FLAG_ACK == 0 {
            return self.accept_flow(ip, &tcp, key);
        }
        if tcp.flags & FLAG_RST != 0 {
            self.close_flow(key, None);
            return Ok(());
        }
        let mut dead = false;
        if let Some(flow) = self.flows.get_mut(&key) {
            let end = tcp.seq.wrapping_add(payload.len() as u32);
            let fin = tcp.flags & FLAG_FIN != 0;
            if !payload.is_empty() {
                flow.busy.store(true, Relaxed);
                dead = flow.write_half.write_all(payload).is_err();
                flow.rcv_nxt.store(end, Relaxed);
            }
            if fin {
                flow.rcv_nxt.store(end.wrapping_add(1), Relaxed);
                let _ = flow.write_half.shutdown(Shutdown::Write);
            }
            // Delayed like the references: answer at a push, at a finish, or at a full MTU unacked.
            let unacked = flow.rcv_nxt.load(Relaxed).wrapping_sub(flow.last_acked);
            if fin
                || (tcp.flags & FLAG_PSH != 0 && !payload.is_empty())
                || unacked >= self.device.mtu as u32
            {
                let snd = flow.snd_nxt.load(Relaxed);
                let rcv = flow.rcv_nxt.load(Relaxed);
                let mut emit = std::mem::take(&mut self.emit);
                render_tcp_packet(
                    (ip.destination, tcp.destination_port),
                    (ip.source, tcp.source_port),
                    snd,
                    rcv,
                    FLAG_ACK,
                    65535,
                    &[],
                    &mut emit,
                );
                let _ = self.device.write_packet(&emit);
                self.emit = emit;
                flow.last_acked = rcv;
            }
        }
        // The proxy half is gone: an upload into a closed lane has no flow to finish, and keeping the entry would keep its socket and its cursors. The device still believes it is established, so it gets a reset.
        if dead {
            self.close_flow(key, Some(FLAG_RST | FLAG_ACK));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn accept_flow(&mut self, ip: &Ipv4Head, tcp: &TcpHead, key: FlowKey) -> io::Result<()> {
        let local_ip = ip.destination;
        let remote_ip = ip.source;
        let local_port = tcp.destination_port;
        let remote_port = tcp.source_port;
        let syn_seq = tcp.seq;

        let mut emit = std::mem::take(&mut self.emit);
        render_tcp_packet(
            (local_ip, local_port),
            (remote_ip, remote_port),
            syn_seq.wrapping_add(1),
            syn_seq.wrapping_add(1),
            FLAG_SYN | FLAG_ACK,
            65535,
            &[],
            &mut emit,
        );
        let wrote = self.device.write_packet(&emit);
        self.emit = emit;
        wrote?;

        let target = SocketAddr::from((ip.destination, tcp.destination_port));
        let destination = crate::proxy::Destination::from(target);
        let relay = Arc::clone(&self.relay);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let pair_addr = listener.local_addr()?;
        let tun_half = TcpStream::connect(pair_addr)?;
        let (proxy_half, _) = listener.accept()?;
        drop(listener);
        let proxy_hold = proxy_half.try_clone()?;

        let write_half = tun_half.try_clone()?;
        let rcv_nxt = Arc::new(AtomicU32::new(syn_seq.wrapping_add(1)));
        let snd_nxt = Arc::new(AtomicU32::new(syn_seq.wrapping_add(2)));
        let busy = Arc::new(AtomicBool::new(false));
        let signaled = Arc::new(AtomicBool::new(false));
        self.flows.insert(
            key,
            Flow {
                write_half,
                rcv_nxt: Arc::clone(&rcv_nxt),
                snd_nxt: Arc::clone(&snd_nxt),
                busy: Arc::clone(&busy),
                last_acked: syn_seq.wrapping_add(1),
                local: (local_ip, local_port),
                remote: (remote_ip, remote_port),
                signaled: Arc::clone(&signaled),
            },
        );

        let mut read_half = tun_half;
        // Silence past the idle budget is death: an untimed read parks a thread, and with it the flow's relay leg and its lane, for the life of the process.
        read_half.set_read_timeout(Some(budgets::udp_idle()))?;
        let mut dev_writer = self.device.clone_writer()?;
        let ended_tx = self.ended_tx.clone();
        let (outcome_tx, outcome_rx) = mpsc::channel();

        std::thread::spawn(move || {
            let conn = Connection::from(proxy_half);
            let _ = outcome_tx.send(relay(conn, destination).is_ok());
            // The duplicate holds the pair's far end open until the verdict is queued, so an EOF before it is a clean remote close, not a refusal.
            drop(proxy_hold);
        });

        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let mut pkt = Vec::with_capacity(4096 + 40);
            let end = loop {
                match read_half.read(&mut buf) {
                    Ok(0) => {
                        // A clean close ends with FIN, a refused leg with RST; a relay that never reports is dead.
                        let clean = match outcome_rx.try_recv() {
                            Ok(clean) => clean,
                            Err(mpsc::TryRecvError::Empty) => true,
                            Err(mpsc::TryRecvError::Disconnected) => false,
                        };
                        break if clean {
                            FLAG_FIN | FLAG_ACK
                        } else {
                            FLAG_RST | FLAG_ACK
                        };
                    }
                    Ok(n) => {
                        let seq = snd_nxt.fetch_add(n as u32, Relaxed);
                        render_tcp_packet(
                            (local_ip, local_port),
                            (remote_ip, remote_port),
                            seq,
                            rcv_nxt.load(Relaxed),
                            FLAG_PSH | FLAG_ACK,
                            65535,
                            &buf[..n],
                            &mut pkt,
                        );
                        if dev_writer.write_all(&pkt).is_err() {
                            break FLAG_RST | FLAG_ACK;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    // The budget expired with nothing to carry: the upload leg gets one more budget to speak, and a silent one ends the flow.
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if !busy.swap(false, Relaxed) {
                            break FLAG_RST | FLAG_ACK;
                        }
                    }
                    Err(_) => break FLAG_RST | FLAG_ACK,
                }
            };
            if !signaled.swap(true, Relaxed) {
                render_tcp_packet(
                    (local_ip, local_port),
                    (remote_ip, remote_port),
                    snd_nxt.load(Relaxed),
                    rcv_nxt.load(Relaxed),
                    end,
                    65535,
                    &[],
                    &mut pkt,
                );
                let _ = dev_writer.write_all(&pkt);
            }
            // Both halves, because the handler's write half is a clone of this descriptor and only a shutdown tells it the flow is over.
            let _ = read_half.shutdown(Shutdown::Both);
            let _ = ended_tx.send(Ended::Stream(key));
        });

        Ok(())
    }

    /// Answer an ICMP echo request as the device's own address would, so a ping off the
    /// interface returns instead of vanishing; a message that is not a well-formed echo
    /// request is left unanswered, exactly as the reference's handler returns.
    fn handle_icmp(&mut self, ip: &Ipv4Head, body: &[u8]) -> io::Result<()> {
        if !is_echo_request(body) {
            return Ok(());
        }
        let mut emit = std::mem::take(&mut self.emit);
        render_icmp_reply(ip.destination, ip.source, body, &mut emit);
        let wrote = self.device.write_packet(&emit);
        self.emit = emit;
        wrote
    }

    fn close_flow(&mut self, key: FlowKey, signal: Option<u8>) {
        if let Some(flow) = self.flows.remove(&key) {
            match signal {
                Some(flags) if !flow.signaled.swap(true, Relaxed) => {
                    let mut emit = std::mem::take(&mut self.emit);
                    render_tcp_packet(
                        flow.local,
                        flow.remote,
                        flow.snd_nxt.load(Relaxed),
                        flow.rcv_nxt.load(Relaxed),
                        flags,
                        65535,
                        &[],
                        &mut emit,
                    );
                    let _ = self.device.write_packet(&emit);
                    self.emit = emit;
                }
                // The device reset the flow itself: nothing has to travel back.
                _ => flow.signaled.store(true, Relaxed),
            }
            let _ = flow.write_half.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for Handler {
    /// The device is gone: closing the control leg ends the association, whose relay socket and reader threads would otherwise outlive the inbound that opened them.
    fn drop(&mut self) {
        if let Some(association) = self.association.take() {
            let _ = association.control.shutdown(Shutdown::Both);
        }
    }
}

/// Raise one flow's leg: a socket on the association's own address that the handler sends framed datagrams through, answered by a reader that re-wraps each reply as a packet back to the flow's source. Silence past the idle budget ends the flow, so neither its thread nor its leg outlives a target that stopped answering.
fn open_leg(
    device: &Device,
    relay: SocketAddr,
    endpoint: ([u8; 4], u16),
    client: ([u8; 4], u16),
    key: UdpKey,
    ended: &mpsc::Sender<Ended>,
) -> io::Result<UdpSocket> {
    let leg = crate::proxy::relay_leg(relay)?;
    let target = SocketAddr::from(endpoint);
    let reader = leg.try_clone()?;
    let mut dev_writer = device.clone_writer()?;
    let mtu = device.mtu;
    let ended = ended.clone();
    std::thread::spawn(move || {
        let mut buf = crate::proxy::udp_buffer();
        let mut out: Vec<u8> = Vec::with_capacity(IPV4_HEADER + UDP_HEADER + mtu);
        while let Ok(n) = reader.recv(&mut buf) {
            let Some((source, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
                continue;
            };
            if source != target {
                continue;
            }
            let datagram = UdpDatagram {
                source: endpoint.0.as_slice(),
                destination: client.0.as_slice(),
                source_port: endpoint.1,
                destination_port: client.1,
                payload,
            };
            out.clear();
            if !udp_datagram(&datagram, &mut out) {
                continue;
            }
            if dev_writer.write_all(&out).is_err() {
                break;
            }
        }
        let _ = ended.send(Ended::Datagram(key));
    });
    Ok(leg)
}

pub(crate) fn refusal_reason(spec: &Spec) -> String {
    format!(
        "`{}` (mtu {} B) cannot open a TUN: no ioctl and no FERROX_TUN_FD",
        spec.name, spec.mtu
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use ferrox_core::foxy::connectip::checksum;

    #[test]
    fn device_protocols_recognized() {
        for p in ["tun", "utun", "wintun", "tun2socks"] {
            assert!(is_device(p));
        }
        assert!(!is_device("vless"));
    }

    #[test]
    fn tcp_head_parses_syn() {
        let pkt = build_tcp_packet(
            ([10, 0, 0, 2], 12345),
            ([10, 0, 0, 1], 80),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.protocol, TCP_PROTO);
        let (tcp, pl) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(tcp.destination_port, 80);
        assert_eq!(tcp.seq, 1000);
        assert_eq!(tcp.flags, FLAG_SYN);
        assert_eq!(pl, []);
    }

    #[test]
    fn tcp_head_parses_payload() {
        let pkt = build_tcp_packet(
            ([1, 2, 3, 4], 999),
            ([5, 6, 7, 8], 1000),
            50,
            10,
            FLAG_ACK,
            4096,
            b"hello tun",
        );
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(payload, b"hello tun");
    }

    #[test]
    fn tcp_head_refuses_short_segment() {
        assert!(tcp_head(&[0u8; 10]).is_none());
    }

    #[test]
    fn the_payload_is_borrowed_from_the_read_buffer() {
        // Pointer identity, not bytes: a parsing copy returns the same bytes from a moved base.
        let pkt = build_tcp_packet(
            ([10, 0, 0, 2], 5),
            ([10, 0, 0, 1], 6),
            100,
            0,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"borrow me",
        );
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_tcp, payload) = tcp_head(body).unwrap();
        let base = pkt.as_ptr() as usize;
        assert_eq!(payload.as_ptr() as usize, base + IPV4_HEADER + 20);
        assert!(payload.as_ptr() as usize + payload.len() <= base + pkt.len());
    }

    #[test]
    fn build_tcp_packet_roundtrips() {
        let pkt = build_tcp_packet(
            ([10, 0, 0, 1], 443),
            ([10, 0, 0, 2], 55555),
            100,
            200,
            FLAG_SYN | FLAG_ACK,
            65535,
            b"x",
        );
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.source, [10, 0, 0, 1]);
        assert_eq!(ip.destination, [10, 0, 0, 2]);
        let (_tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(payload, b"x");
    }

    /// The emit path reallocates nothing under steady traffic: warm one render, then require the reused buffer's base pointer and capacity to survive every later TCP and ICMP render, and each render's bytes to equal a fresh build — the witness that buffer reuse leaks no stale byte a throwaway vector would not have carried.
    #[test]
    fn an_emitted_packet_reuses_its_render_buffer() {
        let src = ([10, 0, 0, 1], 443);
        let dst = ([10, 0, 0, 2], 55555);
        let mut out = Vec::new();
        render_tcp_packet(
            src,
            dst,
            100,
            200,
            FLAG_PSH | FLAG_ACK,
            65535,
            b"0123456789",
            &mut out,
        );
        let warm_ptr = out.as_ptr() as usize;
        let warm_cap = out.capacity();
        for payload in [&[][..], &b"hi"[..], &b"borrow me"[..], &b"0123456789"[..]] {
            render_tcp_packet(
                src,
                dst,
                100,
                200,
                FLAG_PSH | FLAG_ACK,
                65535,
                payload,
                &mut out,
            );
            assert_eq!(
                out.as_ptr() as usize,
                warm_ptr,
                "no reallocation across the emit cycle"
            );
            assert_eq!(out.capacity(), warm_cap, "capacity held steady");
            assert_eq!(out.len(), IPV4_HEADER + 20 + payload.len());
            assert_eq!(
                out,
                build_tcp_packet(src, dst, 100, 200, FLAG_PSH | FLAG_ACK, 65535, payload),
                "a reused render is byte-identical to a fresh one"
            );
        }
        let request = [8u8, 0, 0, 0, 0, 1, 0, 1, b'p', b'i', b'n', b'g'];
        render_icmp_reply([10, 0, 0, 1], [10, 0, 0, 2], &request, &mut out);
        assert_eq!(
            out.as_ptr() as usize,
            warm_ptr,
            "the icmp reply rides the same buffer"
        );
        assert_eq!(
            out,
            build_icmp_reply([10, 0, 0, 1], [10, 0, 0, 2], &request),
            "a reused icmp render is byte-identical to a fresh one"
        );
    }

    /// One reply packet, built the way the lane builds it.
    fn datagram(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(udp_datagram(
            &UdpDatagram {
                source: source.as_slice(),
                destination: destination.as_slice(),
                source_port,
                destination_port,
                payload,
            },
            &mut out,
        ));
        out
    }

    /// The device's datagram leaves as a head this handler builds and the device's own payload:
    /// the payload pointer is the tail, and the head's capacity is held over a push/drain cycle.
    #[test]
    fn a_device_datagram_hands_the_payload_over_by_pointer() {
        let target: SocketAddr = "[2001:db8::7]:53".parse().expect("addr");
        let payload = b"query";
        let mut head = Vec::with_capacity(FRAME_CAP);
        let base = head.as_ptr() as usize;
        let capacity = head.capacity();
        for _ in 0..2 {
            let (front, tail) = crate::proxy::socks_udp_parts(&mut head, &target, payload);
            assert_eq!(tail.as_ptr(), payload.as_ptr(), "no payload copy");
            assert_eq!(front.len(), 22, "the widest head is an IPv6 address");
            assert_eq!(head.as_ptr() as usize, base, "the head does not move");
            assert_eq!(head.capacity(), capacity, "the head does not grow");
        }
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            let (front, tail) = crate::proxy::socks_udp_parts(&mut head, &target, payload);
            assert_eq!(front.len(), 22);
            assert_eq!(tail.len(), payload.len());
        });
        assert_eq!(counts.allocs, 0, "the warm head costs no heap buffer");
    }

    #[test]
    fn udp_head_parses_a_datagram() {
        let pkt = datagram([10, 0, 0, 2], [10, 0, 0, 1], 51500, 53, b"query");
        let (ip, body) = ipv4_head(&pkt).unwrap();
        assert_eq!(ip.protocol, PROTOCOL_UDP);
        let (udp, payload) = udp_head(body).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (51500, 53));
        assert_eq!(payload, b"query");
    }

    #[test]
    fn udp_head_refuses_a_forged_length() {
        // A length field that disagrees with the body is refused, never read past.
        let mut pkt = datagram([10, 0, 0, 2], [10, 0, 0, 1], 5, 6, b"ab");
        let forged = ((UDP_HEADER + 400) as u16).to_be_bytes();
        pkt[IPV4_HEADER + 4..IPV4_HEADER + 6].copy_from_slice(&forged);
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        assert!(udp_head(body).is_none());
        assert!(udp_head(&[0u8; 4]).is_none());
    }

    #[test]
    fn the_datagram_is_borrowed_from_the_read_buffer() {
        // Pointer identity, not bytes: the parse returns the packet's own storage.
        let pkt = datagram([10, 0, 0, 2], [10, 0, 0, 1], 5, 6, b"borrow me");
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (_udp, payload) = udp_head(body).unwrap();
        let base = pkt.as_ptr() as usize;
        assert_eq!(payload.as_ptr() as usize, base + IPV4_HEADER + UDP_HEADER);
        assert!(payload.as_ptr() as usize + payload.len() <= base + pkt.len());
    }

    #[test]
    fn the_reply_packet_verifies_at_the_reference_reader() {
        // Built here, verified by the core's own checksumming walk: the same bytes a peer's stack reads.
        let pkt = datagram([198, 51, 100, 7], [10, 0, 0, 2], 53, 51500, b"an answer");
        let read =
            ferrox_core::foxy::connectip::udp_from_packet(&pkt).expect("a readable datagram");
        assert!(read.verified, "both checksums hold");
        assert_eq!(read.payload, b"an answer");
        assert_eq!((read.source_port, read.destination_port), (53, 51500));
    }

    #[cfg(unix)]
    #[test]
    fn a_syn_flow_replies_syn_ack_over_a_socketpair() {
        let (a, b) = unix_socketpair().unwrap();
        let device = Device::from_handle(a, DEFAULT_MTU);
        let mut peer = b;

        let relay: Relay = Arc::new(|_conn, _dest| Ok(()));
        let mut handler = Handler::new(device, relay, no_associate());

        let syn = build_tcp_packet(
            ([10, 0, 0, 2], 44444),
            ([10, 0, 0, 1], 8080),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], &syn[..]);
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = vec![0u8; 64];
        let rn = peer.read(&mut reply).unwrap();
        assert!(rn > 0);
        let (_rip, rbody) = ipv4_head(&reply[..rn]).unwrap();
        let (rtcp, _) = tcp_head(rbody).unwrap();
        assert_eq!(rtcp.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(rtcp.source_port, 8080);
        assert_eq!(rtcp.destination_port, 44444);
        assert_eq!(rtcp.seq, 1001);
    }

    #[test]
    fn a_non_echo_icmp_message_is_refused() {
        // The three shapes that are not an IPv4 echo request the handler would answer.
        assert!(!is_echo_request(&[0, 0, 0, 0, 0, 0, 0, 0]), "an echo reply");
        assert!(
            !is_echo_request(&[8, 3, 0, 0, 0, 0, 0, 0]),
            "a non-zero code"
        );
        assert!(
            !is_echo_request(&[8, 0, 0, 0]),
            "shorter than the eight-byte header"
        );
        assert!(
            is_echo_request(&[8, 0, 0, 0, 0, 0, 0, 0]),
            "a well-formed request"
        );
    }

    /// One IPv4 ICMP echo request, rendered independently of the reply so the round trip
    /// is not self-consistent: type 8, code 0, a carried identifier, sequence and data.
    #[cfg(unix)]
    fn icmp_echo(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let ip_len = IPV4_HEADER + 8 + data.len();
        let mut pkt = vec![0u8; ip_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = ICMP_PROTO;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let c = ipv4_checksum(&pkt[..IPV4_HEADER]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        let m = &mut pkt[IPV4_HEADER..];
        m[0] = ICMP_ECHO_REQUEST;
        m[4..6].copy_from_slice(&id.to_be_bytes());
        m[6..8].copy_from_slice(&seq.to_be_bytes());
        m[8..].copy_from_slice(data);
        let ic = checksum(m);
        m[2..4].copy_from_slice(&ic.to_be_bytes());
        pkt
    }

    #[cfg(unix)]
    #[test]
    fn an_icmp_echo_request_is_answered_as_a_reply() {
        let (a, b) = unix_socketpair().unwrap();
        let device = Device::from_handle(a, DEFAULT_MTU);
        let mut peer = b;
        let relay: Relay = Arc::new(|_conn, _dest| Ok(()));
        let mut handler = Handler::new(device, relay, no_associate());

        let request = icmp_echo([10, 0, 0, 2], [10, 0, 0, 1], 0x1234, 0x0007, b"ping data");
        peer.write_all(&request).unwrap();

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = vec![0u8; DEFAULT_MTU + 64];
        let rn = peer.read(&mut reply).unwrap();
        let (rip, rbody) = ipv4_head(&reply[..rn]).unwrap();
        assert_eq!(rip.protocol, ICMP_PROTO);
        // answered as the address the request asked, back to the pinger
        assert_eq!(rip.source, [10, 0, 0, 1]);
        assert_eq!(rip.destination, [10, 0, 0, 2]);
        assert_eq!(
            ipv4_checksum(&reply[..IPV4_HEADER]),
            0,
            "the header verifies"
        );
        // an echo reply whose own checksum holds, carrying the message back unchanged
        assert_eq!(rbody[0], ICMP_ECHO_REPLY);
        assert_eq!(rbody[1], 0);
        assert_eq!(
            checksum(rbody),
            0,
            "the reply carries a valid ICMP checksum"
        );
        assert_eq!(&rbody[4..8], &[0x12, 0x34, 0x00, 0x07]);
        assert_eq!(&rbody[8..], b"ping data");
    }

    #[cfg(unix)]
    fn unix_socketpair() -> io::Result<(std::fs::File, std::fs::File)> {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((unsafe { std::fs::File::from_raw_fd(fds[0]) }, unsafe {
            std::fs::File::from_raw_fd(fds[1])
        }))
    }

    #[cfg(unix)]
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// One `FLOW` line of `scripts/tun-oracle/script.txt`: the destination the packet
    /// names, the client port, the SYN sequence, and the payload chunks as separate
    /// segments — the same rendering rules the Go oracle reads from that file.
    #[cfg(unix)]
    struct FlowSpec {
        destination: SocketAddr,
        source_port: u16,
        syn_seq: u32,
        chunks: Vec<Vec<u8>>,
    }

    /// One `UFLOW` line of the same script: a client source port, a destination, and
    /// each datagram body, rendered by the oracle as one independent IPv4 UDP packet.
    #[cfg(unix)]
    struct DatagramSpec {
        destination: SocketAddr,
        source_port: u16,
        datagrams: Vec<Vec<u8>>,
    }

    #[cfg(unix)]
    const SCRIPT_CLIENT: [u8; 4] = [10, 0, 0, 2];

    #[cfg(unix)]
    fn parse_script(text: &str) -> Vec<FlowSpec> {
        let mut flows = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("FLOW") => {}
                Some("UFLOW") => continue,
                other => panic!("the script holds only FLOW and UFLOW lines, found {other:?}"),
            }
            let destination = fields.next().unwrap().parse().unwrap();
            let source_port = fields.next().unwrap().parse().unwrap();
            let syn_seq = fields.next().unwrap().parse().unwrap();
            let chunks = fields.map(hex_decode).collect();
            flows.push(FlowSpec {
                destination,
                source_port,
                syn_seq,
                chunks,
            });
        }
        flows
    }

    #[cfg(unix)]
    fn parse_datagram_script(text: &str) -> Vec<DatagramSpec> {
        let mut flows = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("UFLOW") => {}
                Some("FLOW") => continue,
                other => panic!("the script holds only FLOW and UFLOW lines, found {other:?}"),
            }
            let destination = fields.next().unwrap().parse().unwrap();
            let source_port = fields.next().unwrap().parse().unwrap();
            let datagrams = fields.map(hex_decode).collect();
            flows.push(DatagramSpec {
                destination,
                source_port,
                datagrams,
            });
        }
        flows
    }

    /// The dial set the golden records for one transport: every `<keyword> <target>
    /// <hex>` line, sorted. `DIAL` is the TCP half and `UDIAL` the datagram half, so
    /// one file carries both and each differential reads its own kind.
    #[cfg(unix)]
    fn parse_dials(text: &str, keyword: &str) -> Vec<(String, Vec<u8>)> {
        let mut dials = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            if fields.next() != Some(keyword) {
                continue;
            }
            dials.push((
                fields.next().unwrap().to_owned(),
                hex_decode(fields.next().unwrap()),
            ));
        }
        dials.sort();
        dials
    }

    /// The recorded dial set: every (target, payload) pair a relay saw, shared
    /// between the recorder and the tests that wait on it.
    #[cfg(unix)]
    type Dials = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    /// An association that answers nothing: the stream tests never frame a datagram, and a leg closed at once is what a datagram they did send would deserve.
    #[cfg(unix)]
    fn no_associate() -> Associate {
        Arc::new(|_conn| {})
    }

    /// A dial recorder behind the same `Relay` seam the app installs: it reads each
    /// flow to EOF, exactly as `serve_connect` does, and keeps (target, payload).
    #[cfg(unix)]
    fn recording_relay(results: Dials) -> Relay {
        Arc::new(
            move |mut conn: Connection, dest: crate::proxy::Destination| {
                let mut payload = Vec::new();
                let _ = conn.read_to_end(&mut payload);
                let target = match dest {
                    crate::proxy::Destination::Address(a) => a.to_string(),
                    crate::proxy::Destination::Name(host, port) => format!("{host}:{port}"),
                };
                results.lock().unwrap().push((target, payload));
                Ok(())
            },
        )
    }

    #[cfg(unix)]
    fn wait_for(results: &Dials, count: usize) {
        for _ in 0..2_500 {
            if results.lock().unwrap().len() == count {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!(
            "{count} dials did not arrive; got {:?}",
            results.lock().unwrap().len()
        );
    }

    /// One client-side flow rendered by the script's rules: SYN, then the ACK whose
    /// acknowledgement number is read off this stack's own SYN-ACK (a reference picks
    /// its initial sequence itself — `tcp_lightweight.go` `rand.Uint32()` — so the
    /// golden cannot pin it), then each payload chunk as one PSH, then FIN.
    #[cfg(unix)]
    fn run_flow(handler: &mut Handler, peer: &mut std::fs::File, flow: &FlowSpec, buf: &mut [u8]) {
        let SocketAddr::V4(destination) = flow.destination else {
            panic!("the script names IPv4 destinations only");
        };
        let dst = destination.ip().octets();
        let dst_port = destination.port();
        let endpoint = (dst, dst_port);
        let client = (SCRIPT_CLIENT, flow.source_port);
        let syn = build_tcp_packet(client, endpoint, flow.syn_seq, 0, FLAG_SYN, 65535, &[]);
        peer.write_all(&syn).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let syn_ack = next_syn_ack(peer);
        assert_eq!(
            syn_ack.flags,
            FLAG_SYN | FLAG_ACK,
            "the handshake opens with a SYN-ACK"
        );
        let peer_ack = syn_ack.seq.wrapping_add(1);

        let ack = build_tcp_packet(
            client,
            endpoint,
            flow.syn_seq.wrapping_add(1),
            peer_ack,
            FLAG_ACK,
            65535,
            &[],
        );
        peer.write_all(&ack).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut seq = flow.syn_seq.wrapping_add(1);
        for chunk in &flow.chunks {
            let psh = build_tcp_packet(
                client,
                endpoint,
                seq,
                peer_ack,
                FLAG_PSH | FLAG_ACK,
                65535,
                chunk,
            );
            peer.write_all(&psh).unwrap();
            let n = handler.device.read_packet(buf).unwrap();
            handler.dispatch(&buf[..n]).unwrap();
            seq = seq.wrapping_add(chunk.len() as u32);
        }
        let fin = build_tcp_packet(
            client,
            endpoint,
            seq,
            peer_ack,
            FLAG_FIN | FLAG_ACK,
            65535,
            &[],
        );
        peer.write_all(&fin).unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
    }

    /// The row's identity claim, checked: the set of (target, payload) dials the
    /// inbound produces from the pinned packet stream equals the golden recorded
    /// from the reference stack by `scripts/tun-oracle`.
    #[cfg(unix)]
    #[test]
    fn the_dial_set_matches_the_pinned_stream() {
        let flows = parse_script(include_str!("../../../scripts/tun-oracle/script.txt"));
        let expected = parse_dials(
            include_str!("../../../scripts/tun-oracle/expected.txt"),
            "DIAL",
        );
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, mut peer) = peer_with_deadline().unwrap();
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            recording_relay(results.clone()),
            no_associate(),
        );

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for flow in &flows {
            run_flow(&mut handler, &mut peer, flow, &mut buf);
        }
        wait_for(&results, flows.len());

        let mut got: Vec<(String, Vec<u8>)> = results.lock().unwrap().clone();
        got.sort();
        assert_eq!(got, expected, "the dial set is the reference's own");
    }

    #[cfg(unix)]
    type Frames = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

    /// The association a test answers with: a SOCKS5 UDP server on loopback that keeps every frame it is handed and echoes each one back, so the device's datagram lane is walked end to end without dialing a target.
    #[cfg(unix)]
    fn echo_associate(frames: Frames) -> Associate {
        Arc::new(move |mut client: Connection| {
            let mut greeting = [0u8; 3];
            if client.read_exact(&mut greeting).is_err() || client.write_all(&[5, 0]).is_err() {
                return;
            }
            let mut request = [0u8; 10];
            if client.read_exact(&mut request).is_err() {
                return;
            }
            let Ok(relay) = UdpSocket::bind("127.0.0.1:0") else {
                return;
            };
            let Ok(addr) = relay.local_addr() else {
                return;
            };
            let mut reply = vec![5, 0, 0];
            crate::proxy::push_socks_addr(&mut reply, &addr);
            if client.write_all(&reply).is_err() {
                return;
            }
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, src)) = relay.recv_from(&mut buf) else {
                    return;
                };
                let frame = buf[..n].to_vec();
                let Some((target, payload)) = crate::proxy::parse_socks_udp(&frame) else {
                    continue;
                };
                let mut back = vec![0u8, 0, 0];
                crate::proxy::push_socks_addr(&mut back, &target);
                back.extend_from_slice(payload);
                frames.lock().unwrap().push(frame);
                if relay.send_to(&back, src).is_err() {
                    return;
                }
            }
        })
    }

    #[cfg(unix)]
    fn wait_for_frames(frames: &Frames, count: usize) {
        for _ in 0..2_500 {
            if frames.lock().unwrap().len() == count {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!("{count} frames did not arrive");
    }

    /// The next packet the device wrote, with the same bounded wait the stream tests use: a lane that answers nothing fails rather than parking the suite.
    #[cfg(unix)]
    fn next_datagram(peer: &mut std::fs::File, buf: &mut [u8]) -> usize {
        for _ in 0..2_500 {
            match peer.read(buf) {
                Ok(n) if n > 0 => return n,
                Ok(_) => {}
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        panic!("no datagram answer came back to the device");
    }

    /// The row's datagram claim, checked: a packet off the device becomes the RFC 1928 request the association names, and the answer comes back re-wrapped for the flow that asked.
    #[cfg(unix)]
    #[test]
    fn a_datagram_flow_frames_the_association_and_returns_the_echo() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let frames: Frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay: Relay = Arc::new(|_conn, _dest| Ok(()));
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            echo_associate(frames.clone()),
        );
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let query = datagram(SCRIPT_CLIENT, [198, 51, 100, 7], 51500, 53, b"who-is");
        peer.write_all(&query).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        // Reserved, fragment, address type, the destination the packet named, then the datagram itself.
        let mut want = vec![0u8, 0, 0, 1, 198, 51, 100, 7, 0, 53];
        want.extend_from_slice(b"who-is");
        wait_for_frames(&frames, 1);
        assert_eq!(
            frames.lock().unwrap().first().map(Vec::as_slice),
            Some(want.as_slice()),
            "the association carries the request the spec writes"
        );

        let n = next_datagram(&mut peer, &mut buf);
        let (ip, body) = ipv4_head(&buf[..n]).unwrap();
        assert_eq!(ip.protocol, PROTOCOL_UDP);
        assert_eq!(
            (ip.source, ip.destination),
            ([198, 51, 100, 7], SCRIPT_CLIENT)
        );
        let (udp, payload) = udp_head(body).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (53, 51500));
        assert_eq!(payload, b"who-is");
    }

    /// A recording association: the SOCKS5 UDP server the device's leg reaches, but
    /// it keeps each frame's (target, datagram) instead of echoing, so the outbound
    /// half of the datagram lane is witnessed without dialing a real target.
    #[cfg(unix)]
    fn recording_associate(dials: Dials) -> Associate {
        use std::io::Write;
        Arc::new(move |mut client: Connection| {
            let mut greeting = [0u8; 3];
            if client.read_exact(&mut greeting).is_err() || client.write_all(&[5, 0]).is_err() {
                return;
            }
            let mut request = [0u8; 10];
            if client.read_exact(&mut request).is_err() {
                return;
            }
            let Ok(relay) = UdpSocket::bind("127.0.0.1:0") else {
                return;
            };
            let Ok(addr) = relay.local_addr() else {
                return;
            };
            let mut reply = vec![5, 0, 0];
            crate::proxy::push_socks_addr(&mut reply, &addr);
            if client.write_all(&reply).is_err() {
                return;
            }
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, _src)) = relay.recv_from(&mut buf) else {
                    return;
                };
                if let Some((target, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) {
                    dials
                        .lock()
                        .unwrap()
                        .push((target.to_string(), payload.to_vec()));
                }
            }
        })
    }

    /// The row's datagram identity claim, checked against the reference stack rather
    /// than the spec's own frame: the set of (target, datagram) the inbound hands to
    /// its association equals the golden `scripts/tun-oracle` recorded by running
    /// smoltcp's UDP socket over the same pinned stream. Where it bites and the
    /// frame test does not: two bodies to one port stay two dials (a datagram is
    /// never coalesced the way a TCP stream is), a body shaped like a frame header
    /// survives verbatim, and an odd length is delivered whole.
    #[cfg(unix)]
    #[test]
    fn the_datagram_dial_set_matches_the_pinned_stream() {
        let flows = parse_datagram_script(include_str!("../../../scripts/tun-oracle/script.txt"));
        let expected = parse_dials(
            include_str!("../../../scripts/tun-oracle/expected.txt"),
            "UDIAL",
        );
        let wanted: usize = flows.iter().map(|flow| flow.datagrams.len()).sum();
        let dials: Dials = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|_conn, _dest| Ok(()));
        let mut handler = Handler::new(
            Device::from_handle(a, DEFAULT_MTU),
            relay,
            recording_associate(dials.clone()),
        );

        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        for flow in &flows {
            let SocketAddr::V4(destination) = flow.destination else {
                panic!("the script names IPv4 destinations only");
            };
            let dst = destination.ip().octets();
            for body in &flow.datagrams {
                let packet = datagram(
                    SCRIPT_CLIENT,
                    dst,
                    flow.source_port,
                    destination.port(),
                    body,
                );
                peer.write_all(&packet).unwrap();
                let n = handler.device.read_packet(&mut buf).unwrap();
                handler.dispatch(&buf[..n]).unwrap();
            }
        }
        wait_for(&dials, wanted);

        let mut got: Vec<(String, Vec<u8>)> = dials.lock().unwrap().clone();
        got.sort();
        assert_eq!(
            got, expected,
            "the datagram dial set is the reference's own"
        );
    }

    /// A nonblocking peer: a frame that never arrives fails the assertions instead
    /// of parking the suite until the job timeout names nothing.
    #[cfg(unix)]
    fn peer_with_deadline() -> io::Result<(std::fs::File, std::fs::File)> {
        let (a, peer) = unix_socketpair()?;
        let rc = unsafe { libc::fcntl(peer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((a, peer))
    }

    /// Read frames off the peer until the SYN-ACK: a flow that ran earlier leaves
    /// its delayed ACKs queued ahead of it on the shared descriptor.
    #[cfg(unix)]
    fn next_syn_ack(peer: &mut std::fs::File) -> TcpHead {
        let mut reply = [0u8; 64];
        for _ in 0..1_000 {
            match peer.read(&mut reply) {
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((tcp, _)) = tcp_head(body) {
                            if tcp.flags == FLAG_SYN | FLAG_ACK {
                                return tcp;
                            }
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        panic!("no SYN-ACK arrived on the device");
    }

    /// The next TCP packet the handler wrote to the device, waited for with a bound
    /// so a silent lane fails the test instead of parking it.
    #[cfg(unix)]
    fn next_tcp_packet(peer: &mut std::fs::File, buf: &mut [u8]) -> (TcpHead, Vec<u8>) {
        for _ in 0..2_500 {
            match peer.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&buf[..n]) {
                        if let Some((tcp, payload)) = tcp_head(body) {
                            return (tcp, payload.to_vec());
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        panic!("no packet arrived on the device");
    }

    /// The reverse role, checked: bytes the outbound writes back leave the handler as
    /// IP packets carrying exactly those bytes on the same descriptor.
    #[cfg(unix)]
    #[test]
    fn the_response_bytes_come_back_as_ip_packets() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|mut conn: Connection, _dest| {
            use std::io::Write;
            let _ = conn.write_all(b"pong\n");
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let flow = FlowSpec {
            destination: "203.0.113.53:53".parse().unwrap(),
            source_port: 51001,
            syn_seq: 7000,
            chunks: vec![vec![0xde, 0xad, 0xbe, 0xef]],
        };
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        run_flow(&mut handler, &mut peer, &flow, &mut buf);

        let mut reply = vec![0u8; DEFAULT_MTU + 64];
        let mut payload = Vec::new();
        for _ in 0..250 {
            match peer.read(&mut reply) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((_, pl)) = tcp_head(body) {
                            payload.extend_from_slice(pl);
                        }
                    }
                    if payload.windows(5).any(|w| w == b"pong\n") {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        assert!(
            payload.windows(5).any(|w| w == b"pong\n"),
            "the response bytes ride back as a payload"
        );
    }

    /// The tun2socks shape: a device's TCP flow leaves through the SOCKS5 client
    /// lane, and the echo comes back as IP packets on the same descriptor.
    ///
    /// The SOCKS5 server here answers the greeting, the `CONNECT` request and the
    /// reply the way a SOCKS5 client writes them, and relays to the destination the
    /// request named — so the lane cannot tell a device from a proxy client.
    #[cfg(unix)]
    #[test]
    fn a_device_flow_leaves_through_the_socks_client_lane() {
        let echo = echo_server();
        let (asked, port) = socks_server();
        let out = crate::proxy::Outbound::Socks(crate::proxy::SocksOut::new(
            "127.0.0.1",
            port,
            "",
            "",
            crate::socks::Version::V5,
        ));
        let relay: Relay =
            Arc::new(move |conn, dest| crate::proxy::serve_device_flow(conn, &out, &dest));
        let (a, mut peer) = peer_with_deadline().unwrap();
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let flow = FlowSpec {
            destination: format!("127.0.0.1:{echo}").parse().unwrap(),
            source_port: 51002,
            syn_seq: 8000,
            chunks: vec![b"ping".to_vec()],
        };
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        run_flow(&mut handler, &mut peer, &flow, &mut buf);

        // The SOCKS5 server received the CONNECT for the destination the device named; the dial runs on the flow's own thread, so the record is waited for.
        let record = Arc::clone(&asked);
        let mut seen = Vec::new();
        for _ in 0..2_500 {
            seen = record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if !seen.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            seen.as_slice(),
            &[format!("127.0.0.1:{echo}").parse().expect("an address")],
            "the device's destination is the one the request names"
        );

        // And the echo rides back as IP packets on the device's own descriptor.
        let mut reply = vec![0u8; DEFAULT_MTU + 64];
        let mut payload = Vec::new();
        for _ in 0..500 {
            match peer.read(&mut reply) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some((_ip, body)) = ipv4_head(&reply[..n]) {
                        if let Some((_, pl)) = tcp_head(body) {
                            payload.extend_from_slice(pl);
                        }
                    }
                    if payload.windows(4).any(|w| w == b"ping") {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        assert!(
            payload.windows(4).any(|w| w == b"ping"),
            "the echo rides back as a payload"
        );
    }

    /// A TCP echo server on loopback: the destination the device's flow names.
    #[cfg(unix)]
    fn echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = stream.read(&mut buf) {
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// A SOCKS5 server on loopback: the greeting, the `CONNECT` request and the reply,
    /// and then a relay to the destination the request named. The destination is kept
    /// so a test can see what the client asked for.
    #[cfg(unix)]
    fn socks_server() -> (Arc<std::sync::Mutex<Vec<SocketAddr>>>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let asked: Arc<std::sync::Mutex<Vec<SocketAddr>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&asked);
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut greeting = [0u8; 3];
            if stream.read_exact(&mut greeting).is_err() || stream.write_all(&[5, 0]).is_err() {
                return;
            }
            let mut head = [0u8; 4];
            if stream.read_exact(&mut head).is_err() {
                return;
            }
            let mut body = [0u8; 6];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            let target = SocketAddr::from((
                [body[0], body[1], body[2], body[3]],
                u16::from_be_bytes([body[4], body[5]]),
            ));
            record.lock().expect("the record").push(target);
            if stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
                return;
            }
            let Ok(mut upstream) = TcpStream::connect(target) else {
                return;
            };
            let Ok(mut down) = stream.try_clone() else {
                return;
            };
            let Ok(mut up) = upstream.try_clone() else {
                return;
            };
            let mut back = stream;
            let forward = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = up.read(&mut buf) {
                    if n == 0 || back.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
            let mut buf = [0u8; 4096];
            while let Ok(n) = down.read(&mut buf) {
                if n == 0 || upstream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = forward.join();
        });
        (asked, port)
    }

    /// One flow opened and then silent: SYN, the ACK read off this stack's own SYN-ACK, and nothing after.
    #[cfg(unix)]
    fn open_flow(
        handler: &mut Handler,
        peer: &mut std::fs::File,
        destination: SocketAddr,
        source_port: u16,
        syn_seq: u32,
        buf: &mut [u8],
    ) -> FlowKey {
        let SocketAddr::V4(destination) = destination else {
            panic!("the flow names an IPv4 destination");
        };
        let endpoint = (destination.ip().octets(), destination.port());
        let client = (SCRIPT_CLIENT, source_port);
        peer.write_all(&build_tcp_packet(
            client,
            endpoint,
            syn_seq,
            0,
            FLAG_SYN,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let syn_ack = next_syn_ack(peer);
        peer.write_all(&build_tcp_packet(
            client,
            endpoint,
            syn_seq.wrapping_add(1),
            syn_ack.seq.wrapping_add(1),
            FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        FlowKey {
            source_port,
            destination: endpoint.0,
            destination_port: endpoint.1,
        }
    }

    /// Silence past the idle budget is death, not a leak: a flow that stops speaking on both sides hands its relay leg back at the budget, and its entry goes at the next dial.
    #[cfg(unix)]
    #[test]
    fn a_quiet_tun_flow_hands_its_threads_back() {
        let idle = std::time::Duration::from_millis(250);
        budgets::apply(&crate::config::Budgets {
            udp_idle: Some(idle),
            ..Default::default()
        });
        let (a, mut peer) = peer_with_deadline().unwrap();
        let (gone_tx, gone_rx) = std::sync::mpsc::channel::<()>();
        let relay: Relay = Arc::new(move |mut conn: Connection, _dest| {
            let mut sink = Vec::new();
            let _ = conn.read_to_end(&mut sink);
            let _ = gone_tx.send(());
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let destination: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let key = open_flow(&mut handler, &mut peer, destination, 51500, 9000, &mut buf);
        assert!(
            handler.flows.contains_key(&key),
            "the dial opens before its budget runs"
        );
        let back = gone_rx.recv_timeout(idle + std::time::Duration::from_secs(5));
        budgets::clear();
        assert!(
            back.is_ok(),
            "a flow silent past its idle budget still holds its relay leg"
        );

        // The entry goes at the next dial, so the packet path pays nothing for the reap.
        let second = open_flow(&mut handler, &mut peer, destination, 51501, 9500, &mut buf);
        assert!(
            handler.flows.contains_key(&second) && !handler.flows.contains_key(&key),
            "the quiet flow's entry is gone at the next dial"
        );
        assert_eq!(handler.flows.len(), 1, "only the live flow is left");

        // The client's goodbye outranks the budget: a reset flow hands its leg back at once.
        peer.write_all(&build_tcp_packet(
            (SCRIPT_CLIENT, second.source_port),
            (second.destination, second.destination_port),
            9501,
            0,
            FLAG_RST | FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
        let second_back = gone_rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(
            second_back.is_ok(),
            "a reset flow is still holding its relay leg"
        );
        assert!(handler.flows.is_empty(), "the reset flow's entry is gone");
    }

    /// A proxy leg that closes after its bytes finishes the device's flow: the
    /// response payload arrives first, then `FIN | ACK`, and a device `FIN` is
    /// still accepted instead of being answered with a reset.
    #[cfg(unix)]
    #[test]
    fn a_closed_proxy_leg_sends_fin_after_its_bytes() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|mut conn: Connection, _dest| {
            use std::io::Write;
            let _ = conn.write_all(b"reply");
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let destination: SocketAddr = "203.0.113.61:80".parse().unwrap();
        let destination_ip = match destination {
            SocketAddr::V4(address) => address.ip().octets(),
            SocketAddr::V6(_) => panic!("the flow names IPv4"),
        };
        let source_port = 52000;
        let syn_seq = 3000;
        open_flow(
            &mut handler,
            &mut peer,
            destination,
            source_port,
            syn_seq,
            &mut buf,
        );

        let mut payload = Vec::new();
        let mut fin = None;
        for _ in 0..4 {
            let (tcp, body) = next_tcp_packet(&mut peer, &mut buf);
            if tcp.flags & FLAG_FIN != 0 {
                fin = Some(tcp);
                break;
            }
            payload.extend_from_slice(&body);
        }
        assert_eq!(payload, b"reply", "the proxy bytes reach the device first");
        let fin = fin.expect("a proxy close must finish the device flow");
        assert_eq!(fin.flags, FLAG_FIN | FLAG_ACK);
        assert_eq!(fin.source_port, destination.port());
        assert_eq!(fin.destination_port, source_port);

        // The device's own goodbye still lands after the proxy's.
        peer.write_all(&build_tcp_packet(
            (SCRIPT_CLIENT, source_port),
            (destination_ip, destination.port()),
            syn_seq.wrapping_add(1),
            fin.seq.wrapping_add(1),
            FLAG_FIN | FLAG_ACK,
            65535,
            &[],
        ))
        .unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();
    }

    /// A proxy leg that refuses before carrying a byte cannot leave the device
    /// waiting on an established socket: the flow is reset instead.
    #[cfg(unix)]
    #[test]
    fn a_refused_proxy_leg_resets_the_device_flow() {
        let (a, mut peer) = peer_with_deadline().unwrap();
        let relay: Relay = Arc::new(|_conn: Connection, _dest| {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let destination: SocketAddr = "203.0.113.62:443".parse().unwrap();
        let source_port = 52001;
        open_flow(
            &mut handler,
            &mut peer,
            destination,
            source_port,
            4000,
            &mut buf,
        );

        let (tcp, _) = next_tcp_packet(&mut peer, &mut buf);
        assert_eq!(
            tcp.flags,
            FLAG_RST | FLAG_ACK,
            "a refused dial resets the device's established flow"
        );
        assert_eq!(tcp.source_port, destination.port());
        assert_eq!(tcp.destination_port, source_port);
    }

    #[test]
    fn a_forged_packet_is_refused_not_repaired() {
        // A forged IP length and a short TCP body must leave the parse silent, not reading past.
        let mut pkt = build_tcp_packet(
            ([10, 0, 0, 2], 1),
            ([10, 0, 0, 1], 2),
            1000,
            0,
            FLAG_SYN,
            65535,
            b"x",
        );
        let forged_len = (pkt.len() + 8) as u16;
        pkt[2..4].copy_from_slice(&forged_len.to_be_bytes());
        assert!(ipv4_head(&pkt).is_none());
        let short = build_tcp_packet(
            ([10, 0, 0, 2], 1),
            ([10, 0, 0, 1], 2),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        assert!(tcp_head(&short[IPV4_HEADER..IPV4_HEADER + 19]).is_none());
    }

    #[test]
    fn a_syn_with_options_leaves_the_payload_where_the_header_ends() {
        let mut pkt = build_tcp_packet(
            ([10, 0, 0, 2], 12345),
            ([10, 0, 0, 1], 80),
            1000,
            0,
            FLAG_SYN,
            65535,
            b"ab",
        );
        // Insert a 4-byte MSS option and bump the data offset to six words.
        let head = pkt[..IPV4_HEADER + 20].to_vec();
        let tail = pkt[IPV4_HEADER + 20..].to_vec();
        pkt = head;
        pkt[IPV4_HEADER + 12] = 0x60;
        pkt.extend_from_slice(&[2, 4, 0, 140]);
        pkt.extend_from_slice(&tail);
        let l = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&l.to_be_bytes());
        let (_ip, body) = ipv4_head(&pkt).unwrap();
        let (tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(payload, b"ab", "the payload starts after the options");
    }

    #[cfg(unix)]
    #[test]
    fn the_syn_ack_numbers_wrap_at_the_sequence_space_boundary() {
        let (a, mut peer) = unix_socketpair().unwrap();
        let relay: Relay = Arc::new(|_conn, _dest| Ok(()));
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let syn = build_tcp_packet(
            ([10, 0, 0, 2], 44444),
            ([10, 0, 0, 1], 80),
            u32::MAX - 1,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut reply = [0u8; 64];
        let rn = peer.read(&mut reply).unwrap();
        let (_ip, body) = ipv4_head(&reply[..rn]).unwrap();
        let (syn_ack, _) = tcp_head(body).unwrap();
        assert_eq!(
            syn_ack.seq,
            u32::MAX,
            "the reply sequence wraps instead of saturating"
        );
    }
}
