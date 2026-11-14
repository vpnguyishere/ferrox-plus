//! The native TUN device inbound: opens a virtual interface, reads IP packets, turns each TCP
//! flow into a proxy dial through `serve_connect` and each UDP flow into a datagram dial through
//! a SOCKS5 UDP association — the same two entries every other front reaches, no second dialer.
//!
//! Byte-identity: a TUN carries no wire byte-stream to diff, so this row's identity claim is
//! the (target, payload) dial-set differential — the set of (destination, payload) pairs the
//! inbound produces from a given packet stream must match the pinned reference. Proven by
//! the loopback test set; the oracle lives in `scripts/tun-oracle`.
//!
//! Platform opens: the `tun-rs` builder on Linux and macOS, or an inherited descriptor
//! (`FERROX_TUN_FD`). The privileged opens are compile-checked only — no CI runner holds
//! `CAP_NET_ADMIN` — while the inherited-fd path runs fully in tests.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed, Ordering::SeqCst};
use std::sync::{mpsc, Arc};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::budgets;
use crate::conn::Connection;
use ferrox_core::foxy::connectip::{
    checksum, icmp_echo_reply, ipv4_checksum, ipv4_head, ipv6_head, tcp_checksum, udp_datagram,
    udp_head, UdpDatagram, IPV4_HEADER, IPV6_HEADER, PROTOCOL_UDP, UDP_HEADER,
};

const DEFAULT_MTU: usize = 1500;
/// The largest IP packet a device can carry.
const MAX_PACKET: usize = u16::MAX as usize;
/// The head of a framed datagram: the RSV/FRAG prefix and the widest address (IPv6 plus its port). The payload stays the device's buffer and is handed to the socket by pointer.
const FRAME_CAP: usize = 3 + 1 + 16 + 2;
const TCP_PROTO: u8 = 6;
const ICMP_PROTO: u8 = 1;
const ICMPV6_PROTO: u8 = 58;
/// An ICMP echo request is type 8 (128 over IPv6); its answer flips that to 0 (129) and carries the message back.
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// A path-MTU report carries no usable MTU below the version's smallest link, and no TCP segment is worth less than this.
const IPV4_SMALLEST_MTU: u32 = 576;
const IPV6_SMALLEST_MTU: u32 = 1280;
const SMALLEST_MSS: u32 = 48;
#[cfg(all(test, unix))]
const ICMP_ECHO_REPLY: u8 = 0;
#[cfg(test)]
const ICMPV6_ECHO_REPLY: u8 = 129;
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

const VIRTIO_NET_HDR_LEN: usize = 10;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
const UTUN_HEADER_LEN: usize = 4;
const UTUN_AF_INET: u8 = 2;
const UTUN_AF_INET6: u8 = 30;

/// How a descriptor frames a packet: raw IP, the macOS utun family word, or the Linux virtio header that carries GSO and checksum offload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // the variants are platform-specific; each build constructs only its own
enum Framing {
    Raw,
    Utun,
    Virtio,
}

impl Framing {
    const fn header_len(self) -> usize {
        match self {
            Self::Raw => 0,
            Self::Utun => UTUN_HEADER_LEN,
            Self::Virtio => VIRTIO_NET_HDR_LEN,
        }
    }
}

pub(crate) fn is_device(protocol: &str) -> bool {
    matches!(protocol, "tun" | "utun" | "wintun" | "tun2socks")
}

const DEFAULT_ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 1));
const DEFAULT_PREFIX: u8 = 15;
const DEFAULT_PREFIX_V6: u8 = 64;
const MAX_QUEUES: usize = 4;

pub(crate) struct Spec {
    name: String,
    mtu: usize,
    address: IpAddr,
    prefix: u8,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
        let address = address.unwrap_or(DEFAULT_ADDRESS);
        let prefix = prefix.unwrap_or(if address.is_ipv6() {
            DEFAULT_PREFIX_V6
        } else {
            DEFAULT_PREFIX
        });
        // macOS only accepts `utunN`, and the reference lets the system name its own device; elsewhere the stable name keeps a restart on the same interface.
        let name = name.filter(|n| !n.is_empty()).map_or_else(
            || {
                if cfg!(target_os = "macos") {
                    String::new()
                } else {
                    "ferrox0".to_owned()
                }
            },
            str::to_owned,
        );
        Self {
            name,
            mtu: mtu.filter(|m| *m > 0).unwrap_or(DEFAULT_MTU),
            address,
            prefix,
            queues: queues.unwrap_or_else(default_queues),
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

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn queues(&self) -> usize {
        self.queues
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.mtu > usize::from(u16::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tun mtu {} exceeds 65535", self.mtu),
            ));
        }
        let max_prefix = if self.address.is_ipv6() { 128 } else { 32 };
        if self.prefix > max_prefix {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tun prefix /{} is outside /0../{max_prefix} for {}",
                    self.prefix, self.address
                ),
            ));
        }
        let max_queues = if cfg!(target_os = "linux") {
            MAX_QUEUES
        } else {
            1
        };
        if self.queues == 0 || self.queues > max_queues {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tun queues {} is outside 1..={max_queues} on this platform",
                    self.queues
                ),
            ));
        }
        Ok(())
    }
}

pub(crate) fn default_queues() -> usize {
    if cfg!(target_os = "linux") {
        std::thread::available_parallelism().map_or(1, |n| n.get().min(MAX_QUEUES))
    } else {
        1
    }
}

/// Split `address[/prefix]` and let an explicit `prefix` fill a missing CIDR.
pub(crate) fn parse_address(
    value: Option<&str>,
    prefix: Option<u32>,
) -> Result<(Option<IpAddr>, Option<u8>), String> {
    let explicit = match prefix {
        Some(prefix) => Some(
            u8::try_from(prefix)
                .map_err(|_| format!("tun prefix /{prefix} is outside /0../128"))?,
        ),
        None => None,
    };
    let Some(value) = value else {
        if let Some(prefix) = explicit {
            if prefix > 32 {
                return Err(format!(
                    "tun prefix /{prefix} is outside /0../32 for the default IPv4 address"
                ));
            }
        }
        return Ok((None, explicit));
    };
    let (address, cidr) = match value.split_once('/') {
        Some((address, prefix)) => (
            address,
            Some(
                prefix
                    .parse::<u8>()
                    .map_err(|_| format!("tun address `{value}` has an invalid prefix"))?,
            ),
        ),
        None => (value, None),
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("tun address `{value}` is not an IP address"))?;
    let prefix = cidr.or(explicit);
    if let Some(prefix) = prefix {
        let max_prefix = if address.is_ipv6() { 128 } else { 32 };
        if prefix > max_prefix {
            return Err(format!(
                "tun prefix /{prefix} is outside /0../{max_prefix} for {address}"
            ));
        }
    }
    Ok((Some(address), prefix))
}

#[derive(Debug, Clone, Copy)]
struct TcpHead {
    source_port: u16,
    destination_port: u16,
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
}

fn tcp_head(body: &[u8]) -> Option<(TcpHead, &[u8])> {
    if body.len() < 20 {
        return None;
    }
    let source_port = u16::from_be_bytes([body[0], body[1]]);
    let destination_port = u16::from_be_bytes([body[2], body[3]]);
    let seq = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let ack_num = u32::from_be_bytes(body[8..12].try_into().unwrap());
    let window = u16::from_be_bytes([body[14], body[15]]);
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
            ack_num,
            flags,
            window,
        },
        &body[data_offset..],
    ))
}

/// Whether an ICMP body is an echo request the handler answers: the version's request type, code 0, and at least the eight-byte header. A reply, another code or a truncated message is refused.
fn is_echo_request(protocol: u8, body: &[u8]) -> bool {
    let request = match protocol {
        ICMP_PROTO => ICMP_ECHO_REQUEST,
        ICMPV6_PROTO => ICMPV6_ECHO_REQUEST,
        _ => return false,
    };
    body.len() >= 8 && body[0] == request && body[1] == 0
}

/// One IP packet read in place, whichever version carried it.
#[derive(Debug, Clone, Copy)]
struct IpHead {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
}

/// Walk an IPv4 or IPv6 packet, including the IPv6 extension headers this handler can skip, and hand back the transport body borrowed from the read buffer.
fn ip_head(packet: &[u8]) -> Option<(IpHead, &[u8])> {
    if let Some((ip, body)) = ipv4_head(packet) {
        return Some((
            IpHead {
                source: IpAddr::V4(Ipv4Addr::from(ip.source)),
                destination: IpAddr::V4(Ipv4Addr::from(ip.destination)),
                protocol: ip.protocol,
            },
            body,
        ));
    }
    let (ip, body) = ipv6_head(packet)?;
    let (protocol, body) = walk_extensions(ip.next_header, body)?;
    Some((
        IpHead {
            source: IpAddr::V6(Ipv6Addr::from(ip.source)),
            destination: IpAddr::V6(Ipv6Addr::from(ip.destination)),
            protocol,
        },
        body,
    ))
}

/// Skip the IPv6 extension headers this handler can walk, handing back the transport protocol and its slice.
fn walk_extensions(mut protocol: u8, mut body: &[u8]) -> Option<(u8, &[u8])> {
    loop {
        match protocol {
            0 | 43 | 60 => {
                if body.len() < 8 {
                    return None;
                }
                let size = (usize::from(body[1]) + 1) * 8;
                if size > body.len() {
                    return None;
                }
                protocol = body[0];
                body = &body[size..];
            }
            51 => {
                if body.len() < 2 {
                    return None;
                }
                let size = (usize::from(body[1]) + 2) * 4;
                if size < 12 || size > body.len() {
                    return None;
                }
                protocol = body[0];
                body = &body[size..];
            }
            // A fragment is not reassembled here, and an encrypted payload is not this handler's.
            44 | 50 | 59 => return None,
            _ => return Some((protocol, body)),
        }
    }
}

/// The flow a quoted packet names, read from the header plus the eight transport bytes an ICMP error carries. The quote is the packet this handler wrote to the device — remote to client — so its source is the flow's destination, its destination the flow's source, and its two ports reversed. The quoted total length is usually larger than what arrived, so this does not ask the full-packet walk to accept it.
fn quoted_flow(quoted: &[u8]) -> Option<(FlowKey, u32)> {
    let first = *quoted.first()?;
    let (protocol, remote, client, transport) = if first >> 4 == 4 {
        let header = usize::from(first & 0x0f) * 4;
        if header < IPV4_HEADER || header > quoted.len() {
            return None;
        }
        let remote = *quoted.get(12..16)?.first_chunk::<4>()?;
        let client = *quoted.get(16..20)?.first_chunk::<4>()?;
        (
            *quoted.get(9)?,
            IpAddr::V4(Ipv4Addr::from(remote)),
            IpAddr::V4(Ipv4Addr::from(client)),
            quoted.get(header..)?,
        )
    } else if first >> 4 == 6 {
        if quoted.len() < IPV6_HEADER {
            return None;
        }
        let remote = *quoted.get(8..24)?.first_chunk::<16>()?;
        let client = *quoted.get(24..40)?.first_chunk::<16>()?;
        let (protocol, transport) = walk_extensions(*quoted.get(6)?, quoted.get(IPV6_HEADER..)?)?;
        (
            protocol,
            IpAddr::V6(Ipv6Addr::from(remote)),
            IpAddr::V6(Ipv6Addr::from(client)),
            transport,
        )
    } else {
        return None;
    };
    if protocol != TCP_PROTO || transport.len() < 8 {
        return None;
    }
    let seq = u32::from_be_bytes(transport[4..8].try_into().ok()?);
    Some((
        FlowKey {
            source: client,
            source_port: u16::from_be_bytes([transport[2], transport[3]]),
            destination: remote,
            destination_port: u16::from_be_bytes([transport[0], transport[1]]),
        },
        seq,
    ))
}

/// The flow a v4 or v6 ICMP error quotes, when the quoted segment is TCP this handler carried: type 3 over v4, type 1 and packet-too-big type 2 over v6.
fn icmp_error_flow(protocol: u8, body: &[u8]) -> Option<(FlowKey, u32)> {
    let quoted = match (protocol, body.first().copied()) {
        (ICMP_PROTO, Some(3)) | (ICMPV6_PROTO, Some(1 | 2)) => body.get(8..)?,
        _ => return None,
    };
    quoted_flow(quoted)
}

/// The path MTU a packet-too-big message reports: v4 fragmentation-needed (type 3 code 4) or v6 type 2, clamped to the smallest link each version allows.
fn reported_mtu(protocol: u8, body: &[u8]) -> Option<u32> {
    match (protocol, body.first().copied()) {
        (ICMP_PROTO, Some(3)) if body.get(1) == Some(&4) => {
            let mtu = u32::from(u16::from_be_bytes(body.get(6..8)?.try_into().ok()?));
            Some(mtu.max(IPV4_SMALLEST_MTU))
        }
        (ICMPV6_PROTO, Some(2)) => {
            let mtu = u32::from_be_bytes(body.get(4..8)?.try_into().ok()?);
            Some(mtu.max(IPV6_SMALLEST_MTU))
        }
        _ => None,
    }
}

/// The segment size a path MTU leaves after the IP and TCP headers, never below the floor the references believe.
fn path_mss(mtu: u32, ipv6: bool) -> u32 {
    let header = if ipv6 {
        (IPV6_HEADER + 20) as u32
    } else {
        (IPV4_HEADER + 20) as u32
    };
    mtu.saturating_sub(header).max(SMALLEST_MSS)
}

/// How much a response read may take: one segment without offload, the whole buffer when the descriptor can split a GSO packet.
fn read_limit(gso: bool, mss: usize, room: usize) -> usize {
    if gso {
        room
    } else {
        mss.min(room)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
}

/// One datagram flow, keyed the same way as a stream flow: both endpoints, because two clients can pick the same source port towards the same target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
}

/// A flow a thread has left: its entry goes at the next packet, so the packet path pays nothing for the reap.
enum Ended {
    Stream(FlowKey, u64),
    Datagram(UdpKey, u64),
}

/// A TUN device: a file descriptor carrying IP packets, with the framing its platform puts in front of each one.
pub(crate) struct Device {
    handle: std::fs::File,
    mtu: usize,
    framing: Framing,
    /// The builder enabled `TUN_F_TSO4|TUN_F_TSO6`; an inherited descriptor's `IFF_VNET_HDR` says nothing about that.
    gso: bool,
}

impl Device {
    pub(crate) fn open(spec: &Spec) -> io::Result<Self> {
        if let Some(handle) = inherited_handle() {
            let framing = inherited_framing(&handle);
            return Ok(Self {
                handle,
                mtu: spec.mtu,
                framing,
                gso: false,
            });
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::io::IntoRawFd;
            #[cfg(target_os = "linux")]
            let (device, offload, _) = match crate::tun_stack::build(spec, false, true) {
                Ok((device, true, multi)) => {
                    // The kernel enabled UDP segment offload with the TCP ones; the handler does not split an aggregate, so the device is narrowed before its name is released for the plain rebuild.
                    if crate::tun_stack::tcp_only_offload(&device) {
                        (device, true, multi)
                    } else {
                        drop(device);
                        let (device, _, multi) = crate::tun_stack::build(spec, false, false)?;
                        (device, false, multi)
                    }
                }
                Ok((device, false, multi)) => (device, false, multi),
                Err(error) if offload_refused(&error) => {
                    crate::tun_stack::build(spec, false, false)?
                }
                Err(error) => return Err(error),
            };
            #[cfg(target_os = "macos")]
            let (device, _, _) = crate::tun_stack::build(spec, false, true)?;
            #[cfg(target_os = "linux")]
            let framing = if offload {
                Framing::Virtio
            } else {
                Framing::Raw
            };
            #[cfg(target_os = "macos")]
            let framing = Framing::Utun;
            let handle = unsafe { std::fs::File::from_raw_fd(device.into_raw_fd()) };
            Ok(Self {
                handle,
                mtu: spec.mtu,
                framing,
                #[cfg(target_os = "linux")]
                gso: offload,
                #[cfg(target_os = "macos")]
                gso: false,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no TUN platform open; set FERROX_TUN_FD for an inherited descriptor",
        ))
    }

    pub(crate) fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let head = self.framing.header_len();
        if head == 0 {
            return self.handle.read(buf);
        }
        #[cfg(unix)]
        {
            let mut header = [0u8; VIRTIO_NET_HDR_LEN];
            let mut iov = [
                libc::iovec {
                    iov_base: header.as_mut_ptr().cast(),
                    iov_len: head,
                },
                libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: buf.len(),
                },
            ];
            loop {
                let n = unsafe { libc::readv(self.handle.as_raw_fd(), iov.as_mut_ptr(), 2) };
                if n < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                return Ok((n as usize).saturating_sub(head));
            }
        }
        #[cfg(not(unix))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "framed TUN reads need a unix descriptor",
        ))
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        write_framed(&mut self.handle, self.framing, None, packet).map(|_| ())
    }

    pub(crate) fn clone_writer(&self) -> io::Result<PacketWriter> {
        Ok(PacketWriter {
            handle: self.handle.try_clone()?,
            framing: self.framing,
            gso: self.gso,
        })
    }

    /// A packet tunnel's descriptor: the reference dups it, closes it on exec, and makes it nonblocking.
    pub(crate) fn from_inherited(fd: i32, mtu: usize) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let duplicated = unsafe { libc::dup(fd) };
            if duplicated < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { libc::fcntl(duplicated, libc::F_SETFD, libc::FD_CLOEXEC) };
            let flags = unsafe { libc::fcntl(duplicated, libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(duplicated, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }
            let handle = unsafe { std::fs::File::from_raw_fd(duplicated) };
            Ok(Self {
                framing: inherited_framing(&handle),
                handle,
                mtu,
                gso: false,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (fd, mtu);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "packet tunnel needs a Unix descriptor",
            ))
        }
    }

    #[cfg(unix)]
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.handle.as_raw_fd()
    }

    #[cfg(not(unix))]
    pub(crate) fn raw_fd(&self) -> i32 {
        -1
    }

    fn mss(&self, remote: IpAddr) -> u32 {
        let header = if remote.is_ipv6() {
            IPV6_HEADER + 20
        } else {
            IPV4_HEADER + 20
        };
        self.mtu.saturating_sub(header).max(1) as u32
    }

    #[cfg(all(test, unix))]
    fn from_handle(handle: std::fs::File, mtu: usize) -> Self {
        Self {
            handle,
            mtu,
            framing: Framing::Raw,
            gso: false,
        }
    }
}

/// A flow's writer: the descriptor clone plus the framing an emit owes it.
pub(crate) struct PacketWriter {
    handle: std::fs::File,
    framing: Framing,
    gso: bool,
}

impl PacketWriter {
    pub(crate) fn write_packet(&mut self, packet: &[u8]) -> io::Result<bool> {
        write_framed(&mut self.handle, self.framing, None, packet)
    }

    fn write_gso(&mut self, packet: &[u8], mss: u16) -> io::Result<bool> {
        write_framed(&mut self.handle, self.framing, Some(mss), packet)
    }

    fn gso(&self) -> bool {
        self.gso
    }
}

/// The virtio header a GSO packet needs: native-endian fields, checksum offload from the TCP header, and the segment size the kernel splits at.
fn virtio_header(packet: &[u8], gso: Option<u16>) -> [u8; VIRTIO_NET_HDR_LEN] {
    let mut header = [0u8; VIRTIO_NET_HDR_LEN];
    let Some(mss) = gso else {
        return header;
    };
    let ip_header = if packet.first().is_some_and(|byte| byte >> 4 == 6) {
        IPV6_HEADER
    } else {
        IPV4_HEADER
    };
    header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header[1] = if ip_header == IPV6_HEADER {
        VIRTIO_NET_HDR_GSO_TCPV6
    } else {
        VIRTIO_NET_HDR_GSO_TCPV4
    };
    header[2..4].copy_from_slice(&(ip_header as u16 + 20).to_ne_bytes());
    header[4..6].copy_from_slice(&mss.to_ne_bytes());
    header[6..8].copy_from_slice(&(ip_header as u16).to_ne_bytes());
    header[8..10].copy_from_slice(&16u16.to_ne_bytes());
    header
}

/// One packet write with the descriptor's framing in front of it, all-or-nothing: a full write is carried, a short or refused write is dropped.
fn write_framed(
    handle: &mut std::fs::File,
    framing: Framing,
    gso: Option<u16>,
    packet: &[u8],
) -> io::Result<bool> {
    match framing {
        Framing::Raw => write_packet_to(handle, packet),
        Framing::Utun => {
            let family = if packet.first().is_some_and(|byte| byte >> 4 == 6) {
                UTUN_AF_INET6
            } else {
                UTUN_AF_INET
            };
            write_pair(handle, &[0, 0, 0, family], packet)
        }
        Framing::Virtio => write_pair(handle, &virtio_header(packet, gso), packet),
    }
}

/// One framed packet in one writev, so the header and payload reach the device as one packet. A short write drops the packet rather than sending its tail as another.
fn write_pair<W: Write>(writer: &mut W, header: &[u8], packet: &[u8]) -> io::Result<bool> {
    let total = header.len() + packet.len();
    let parts = [std::io::IoSlice::new(header), std::io::IoSlice::new(packet)];
    loop {
        match writer.write_vectored(&parts) {
            Ok(written) if written == total => return Ok(true),
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if crate::tun_stack::refused(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

/// One packet write, all-or-nothing: a full write is carried, a short or refused write is dropped.
fn write_packet_to<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<bool> {
    loop {
        match writer.write(packet) {
            Ok(written) if written == packet.len() => return Ok(true),
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if crate::tun_stack::refused(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_raw_fd()
    }
}

/// The framing an inherited descriptor already carries, read from the descriptor rather than the environment: a Linux TUN reports its virtio header, and a macOS utun always has its family word.
#[cfg(target_os = "linux")]
fn inherited_framing(handle: &std::fs::File) -> Framing {
    const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
    const IFF_VNET_HDR: libc::c_short = 0x4000;
    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req = IfReq {
        ifr_name: [0; 16],
        ifr_flags: 0,
        _pad: [0; 22],
    };
    if unsafe { libc::ioctl(handle.as_raw_fd(), TUNGETIFF as _, &mut req) } < 0 {
        return Framing::Raw;
    }
    if req.ifr_flags & IFF_VNET_HDR != 0 {
        Framing::Virtio
    } else {
        Framing::Raw
    }
}

#[cfg(target_os = "macos")]
fn inherited_framing(_handle: &std::fs::File) -> Framing {
    Framing::Utun
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn inherited_framing(_handle: &std::fs::File) -> Framing {
    Framing::Raw
}

fn inherited_handle() -> Option<std::fs::File> {
    let fd_str = std::env::var_os("FERROX_TUN_FD")?;
    let fd: i64 = fd_str.to_str()?.parse().ok()?;
    if fd < 3 {
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

/// A Linux open refused the optional offload, so the same spec is retried without it.
#[cfg(target_os = "linux")]
fn offload_refused(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
    ) || matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EOPNOTSUPP || code == libc::ENOTSUP
    )
}

/// The pseudo-header checksum a GSO segment carries into the kernel: the field holds the folded sum before the segment, and the kernel folds the payload onto it.
fn partial_tcp_checksum(source: IpAddr, destination: IpAddr, tcp_len: usize) -> u16 {
    let mut pseudo = [0u8; IPV6_HEADER + 8];
    let len = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            pseudo[..4].copy_from_slice(&source.octets());
            pseudo[4..8].copy_from_slice(&destination.octets());
            pseudo[9] = TCP_PROTO;
            pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            12
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            pseudo[..16].copy_from_slice(&source.octets());
            pseudo[16..32].copy_from_slice(&destination.octets());
            pseudo[32..36].copy_from_slice(&(tcp_len as u32).to_be_bytes());
            pseudo[39] = TCP_PROTO;
            40
        }
        _ => return 0,
    };
    !checksum(&pseudo[..len])
}

fn write_tcp_checksum(source: IpAddr, destination: IpAddr, partial: bool, out: &mut [u8]) {
    let ip_header = if source.is_ipv6() {
        IPV6_HEADER
    } else {
        IPV4_HEADER
    };
    let tcp_len = out.len() - ip_header;
    let field = ip_header + 16;
    // Both fields hold the pseudo-header sum in network order; the offload one leaves the segment for the kernel to add and complete.
    let value = if partial {
        partial_tcp_checksum(source, destination, tcp_len)
    } else {
        let (source, destination) = octets(source, destination);
        tcp_checksum(&source, &destination, &out[ip_header..])
    };
    out[field..field + 2].copy_from_slice(&value.to_be_bytes());
}

fn octets(source: IpAddr, destination: IpAddr) -> ([u8; 16], [u8; 16]) {
    let mut from = [0u8; 16];
    let mut to = [0u8; 16];
    match source {
        IpAddr::V4(address) => from[..4].copy_from_slice(&address.octets()),
        IpAddr::V6(address) => from.copy_from_slice(&address.octets()),
    }
    match destination {
        IpAddr::V4(address) => to[..4].copy_from_slice(&address.octets()),
        IpAddr::V6(address) => to.copy_from_slice(&address.octets()),
    }
    (from, to)
}

/// Render one IP/TCP packet into `out` — the caller's reused buffer. The headers are built on the stack and extended, the payload is extended once, and both checksums are computed in place. A GSO render leaves the TCP field as the pseudo-header sum the kernel completes.
#[allow(clippy::too_many_arguments)]
fn render_tcp_packet_ip(
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    partial: bool,
    out: &mut Vec<u8>,
) {
    let (src_ip, src_port) = src;
    let (dst_ip, dst_port) = dst;
    let tcp_len = 20 + payload.len();
    out.clear();
    let ip_len = if src_ip.is_ipv6() {
        IPV6_HEADER + tcp_len
    } else {
        IPV4_HEADER + tcp_len
    };
    out.reserve(ip_len);
    if let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (src_ip, dst_ip) {
        let mut ip = [0u8; IPV4_HEADER];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = TCP_PROTO;
        ip[12..16].copy_from_slice(&src_ip.octets());
        ip[16..20].copy_from_slice(&dst_ip.octets());
        let c = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        out.extend_from_slice(&ip);
    } else if let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (src_ip, dst_ip) {
        let mut ip = [0u8; IPV6_HEADER];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        ip[6] = TCP_PROTO;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&src_ip.octets());
        ip[24..40].copy_from_slice(&dst_ip.octets());
        out.extend_from_slice(&ip);
    } else {
        return;
    }
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack_num.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    out.extend_from_slice(&tcp);
    out.extend_from_slice(payload);
    write_tcp_checksum(src_ip, dst_ip, partial, out);
}

/// Render one IPv4/TCP packet with no offload, the shape the caller's tests and the v4-only path already exercised.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
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
    render_tcp_packet_ip(
        (IpAddr::from(src.0), src.1),
        (IpAddr::from(dst.0), dst.1),
        seq,
        ack_num,
        flags,
        window,
        payload,
        false,
        out,
    );
}

/// An ICMP echo request answered as the device's own destination would: the shared renderer
/// flips the type, swaps the addresses and recomputes both checksums into the caller's reused
/// `out`, so a ping storm allocates nothing per reply. `src` and `dst` are the reply's, the
/// request's the other way round.
fn render_icmp_reply_ip(src: IpAddr, dst: IpAddr, request: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let _ = icmp_echo_reply(dst, src, request, out);
}

#[cfg(test)]
fn render_icmp_reply(src: [u8; 4], dst: [u8; 4], request: &[u8], out: &mut Vec<u8>) {
    render_icmp_reply_ip(IpAddr::from(src), IpAddr::from(dst), request, out);
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

#[cfg(test)]
fn build_ipv6_tcp_packet(
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    seq: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    render_tcp_packet_ip(
        src, dst, seq, ack_num, flags, window, payload, false, &mut out,
    );
    out
}

/// The peer's send window for one flow: the highest sequence it acknowledged and the room it advertises, so the response thread stalls instead of overrunning a receive buffer and losing segments this handler cannot retransmit.
struct SendWindow {
    una: AtomicU32,
    window: AtomicU32,
    closed: AtomicBool,
    parked: AtomicBool,
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl SendWindow {
    fn new(una: u32, window: u16) -> Self {
        Self {
            una: AtomicU32::new(una),
            window: AtomicU32::new(u32::from(window)),
            closed: AtomicBool::new(false),
            parked: AtomicBool::new(false),
            thread: std::sync::OnceLock::new(),
        }
    }

    /// Fold one device ACK into the window; a stale number never moves either field, and a zero-window probe still opens the window.
    fn acked(&self, ack: u32, window: u16, sent: u32) {
        let current = self.una.load(SeqCst);
        let advance = ack.wrapping_sub(current);
        if advance < 1u32 << 31 {
            if advance != 0 && ack.wrapping_sub(sent) >= 1u32 << 31 {
                self.una.store(ack, SeqCst);
            }
            self.window.store(u32::from(window), SeqCst);
        }
        self.wake();
    }

    fn close(&self) {
        self.closed.store(true, SeqCst);
        self.wake();
    }

    fn wake(&self) {
        if self.parked.swap(false, SeqCst) {
            if let Some(thread) = self.thread.get() {
                thread.unpark();
            }
        }
    }

    /// Room the peer's window leaves right now; `None` when the flow ended or a silent peer kept the window shut past the idle budget.
    fn room(&self, sent: &AtomicU32) -> Option<u32> {
        let deadline = std::time::Instant::now() + budgets::udp_idle();
        loop {
            if self.closed.load(SeqCst) {
                return None;
            }
            let una = self.una.load(SeqCst);
            let window = self.window.load(SeqCst);
            let inflight = sent.load(SeqCst).wrapping_sub(una);
            if inflight < window {
                return Some(window - inflight);
            }
            self.parked.store(true, SeqCst);
            // Re-read after publishing the park flag so an ACK that lands in between is not lost.
            let una = self.una.load(SeqCst);
            let window = self.window.load(SeqCst);
            let inflight = sent.load(SeqCst).wrapping_sub(una);
            if self.closed.load(SeqCst) {
                self.parked.store(false, SeqCst);
                return None;
            }
            if inflight < window {
                self.parked.store(false, SeqCst);
                continue;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                self.parked.store(false, SeqCst);
                return None;
            }
            if self.thread.get().is_some() {
                std::thread::park_timeout(deadline - now);
            }
            self.parked.store(false, SeqCst);
        }
    }
}

/// One active TCP flow's state. The two cursors are shared with the response
/// thread: `rcv_nxt` advances as the handler delivers payload to the proxy, and
/// `snd_nxt` advances as the response thread sends payload out, so a pure ACK
/// carries both numbers truthfully.
struct Flow {
    /// The generation this entry was inserted at, so a late reaper cannot remove a replacement with the same tuple.
    id: u64,
    /// The client's initial sequence, so a retransmitted SYN replays the handshake instead of minting a second flow.
    isn: u32,
    write_half: TcpStream,
    rcv_nxt: Arc<AtomicU32>,
    snd_nxt: Arc<AtomicU32>,
    /// Payload reached the proxy since the response thread's last idle expiry: a flow is alive when either direction spoke inside the budget.
    busy: Arc<AtomicBool>,
    last_acked: u32,
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
    /// The largest payload the response thread may put in one segment; a path-MTU report lowers it.
    mss: Arc<AtomicU32>,
    /// The peer's advertised window, updated from every ACK, so a download stalls at the receive buffer instead of flooding past it.
    send: Arc<SendWindow>,
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
    legs: HashMap<UdpKey, (u64, UdpSocket)>,
    frame: Vec<u8>,
    /// Reused render buffer for every device-bound packet this thread emits (SYN-ACK, pure ACK, ICMP reply), so the emit path allocates nothing in steady state.
    emit: Vec<u8>,
    association: Option<Association>,
    ended_tx: mpsc::Sender<Ended>,
    ended_rx: mpsc::Receiver<Ended>,
    next_flow_id: u64,
    next_leg_id: u64,
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
            next_flow_id: 0,
            next_leg_id: 0,
        }
    }

    pub(crate) fn serve(&mut self) -> io::Result<()> {
        let mut buf = vec![0u8; MAX_PACKET + 64];
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
                Ended::Stream(key, id) => {
                    if self.flows.get(&key).is_some_and(|flow| flow.id == id) {
                        self.flows.remove(&key);
                    }
                }
                Ended::Datagram(key, id) => {
                    if self.legs.get(&key).is_some_and(|leg| leg.0 == id) {
                        self.legs.remove(&key);
                    }
                }
            }
        }
        let Some((ip, body)) = ip_head(packet) else {
            return Ok(());
        };
        match ip.protocol {
            TCP_PROTO => self.handle_tcp(&ip, body),
            PROTOCOL_UDP => self.handle_udp(&ip, body),
            ICMP_PROTO | ICMPV6_PROTO => self.handle_icmp(&ip, body),
            _ => Ok(()),
        }
    }

    /// Relay one datagram: the flow's leg is raised on the association's relay address and every packet afterwards rides it, framed with the destination the device asked for. A packet whose association or leg cannot be raised is lost, as an unroutable datagram is at every other front.
    fn handle_udp(&mut self, ip: &IpHead, body: &[u8]) -> io::Result<()> {
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
        let target = SocketAddr::new(ip.destination, udp.destination_port);
        let key = UdpKey {
            source: ip.source,
            source_port: udp.source_port,
            destination: ip.destination,
            destination_port: udp.destination_port,
        };
        let leg = match self.legs.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => &mut entry.into_mut().1,
            std::collections::hash_map::Entry::Vacant(vacant) => {
                let id = self.next_leg_id;
                self.next_leg_id = self.next_leg_id.wrapping_add(1);
                &mut vacant
                    .insert((
                        id,
                        open_leg(
                            &self.device,
                            relay,
                            (ip.destination, udp.destination_port),
                            (ip.source, udp.source_port),
                            key,
                            id,
                            &self.ended_tx,
                        )?,
                    ))
                    .1
            }
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

    fn handle_tcp(&mut self, ip: &IpHead, body: &[u8]) -> io::Result<()> {
        let Some((tcp, payload)) = tcp_head(body) else {
            return Ok(());
        };
        let key = FlowKey {
            source: ip.source,
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
            if tcp.flags & FLAG_ACK != 0 {
                let sent = flow.snd_nxt.load(Relaxed);
                flow.send.acked(tcp.ack_num, tcp.window, sent);
            }
            let fin = tcp.flags & FLAG_FIN != 0;
            // A device retransmits and can reorder, so only the bytes past `rcv_nxt` reach the proxy: a duplicate is dropped and an overlapping segment is trimmed, never written twice.
            let rcv = flow.rcv_nxt.load(Relaxed);
            let len = payload.len() as u32;
            let gap = rcv.wrapping_sub(tcp.seq);
            let skip = if i32::try_from(gap).is_ok() {
                gap as usize
            } else {
                usize::MAX
            };
            let mut end = rcv;
            if skip < payload.len() {
                flow.busy.store(true, Relaxed);
                dead = flow.write_half.write_all(&payload[skip..]).is_err();
                end = rcv.wrapping_add(len - skip as u32);
                flow.rcv_nxt.store(end, Relaxed);
            }
            if fin && tcp.seq.wrapping_add(len) == flow.rcv_nxt.load(Relaxed) {
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
                render_tcp_packet_ip(
                    (ip.destination, tcp.destination_port),
                    (ip.source, tcp.source_port),
                    snd,
                    rcv,
                    FLAG_ACK,
                    65535,
                    &[],
                    false,
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
    fn accept_flow(&mut self, ip: &IpHead, tcp: &TcpHead, key: FlowKey) -> io::Result<()> {
        if let Some(flow) = self.flows.get(&key) {
            // A retransmitted SYN keeps its flow and only needs the SYN-ACK again; a new SYN on a live tuple ends the old flow first, so its threads and lane cannot outlive it.
            if flow.isn == tcp.seq {
                let mut emit = std::mem::take(&mut self.emit);
                render_tcp_packet_ip(
                    flow.local,
                    flow.remote,
                    flow.isn.wrapping_add(1),
                    flow.isn.wrapping_add(1),
                    FLAG_SYN | FLAG_ACK,
                    65535,
                    &[],
                    false,
                    &mut emit,
                );
                let wrote = self.device.write_packet(&emit);
                self.emit = emit;
                return wrote;
            }
            self.close_flow(key, Some(FLAG_RST | FLAG_ACK));
        }
        let local_ip = ip.destination;
        let remote_ip = ip.source;
        let local_port = tcp.destination_port;
        let remote_port = tcp.source_port;
        let syn_seq = tcp.seq;
        let mss = Arc::new(AtomicU32::new(self.device.mss(remote_ip)));

        let mut emit = std::mem::take(&mut self.emit);
        render_tcp_packet_ip(
            (local_ip, local_port),
            (remote_ip, remote_port),
            syn_seq.wrapping_add(1),
            syn_seq.wrapping_add(1),
            FLAG_SYN | FLAG_ACK,
            65535,
            &[],
            false,
            &mut emit,
        );
        let wrote = self.device.write_packet(&emit);
        self.emit = emit;
        wrote?;

        let target = SocketAddr::new(ip.destination, tcp.destination_port);
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
        let send = Arc::new(SendWindow::new(syn_seq.wrapping_add(2), tcp.window));
        let id = self.next_flow_id;
        self.next_flow_id = self.next_flow_id.wrapping_add(1);
        self.flows.insert(
            key,
            Flow {
                id,
                isn: syn_seq,
                write_half,
                rcv_nxt: Arc::clone(&rcv_nxt),
                snd_nxt: Arc::clone(&snd_nxt),
                busy: Arc::clone(&busy),
                last_acked: syn_seq.wrapping_add(1),
                local: (local_ip, local_port),
                remote: (remote_ip, remote_port),
                mss: Arc::clone(&mss),
                send: Arc::clone(&send),
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
            let _ = send.thread.set(std::thread::current());
            let gso_capable = dev_writer.gso();
            let initial = (mss.load(Relaxed) as usize).max(1);
            let mut buf = vec![
                0u8;
                if gso_capable {
                    MAX_PACKET - IPV6_HEADER - 20
                } else {
                    initial
                }
            ];
            let mut pkt = Vec::with_capacity(if gso_capable {
                MAX_PACKET
            } else {
                IPV6_HEADER + 20 + initial
            });
            let end = loop {
                let max = (mss.load(Relaxed) as usize).max(1);
                let limit = read_limit(gso_capable, max, buf.len());
                match read_half.read(&mut buf[..limit]) {
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
                        let mut at = 0;
                        while at < n {
                            let Some(room) = send.room(&snd_nxt) else {
                                break;
                            };
                            let max = (mss.load(Relaxed) as usize).max(1);
                            let take = (n - at).min(room as usize);
                            let seq = snd_nxt.load(Relaxed);
                            let gso = gso_capable && take > max;
                            render_tcp_packet_ip(
                                (local_ip, local_port),
                                (remote_ip, remote_port),
                                seq,
                                rcv_nxt.load(Relaxed),
                                FLAG_PSH | FLAG_ACK,
                                65535,
                                &buf[at..at + take],
                                gso,
                                &mut pkt,
                            );
                            let wrote = if gso {
                                dev_writer.write_gso(&pkt, max as u16)
                            } else {
                                dev_writer.write_packet(&pkt)
                            };
                            match wrote {
                                Ok(true) => {
                                    snd_nxt.fetch_add(take as u32, Relaxed);
                                    at += take;
                                }
                                Ok(false) => break,
                                Err(_) => break,
                            }
                        }
                        if at < n {
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
                render_tcp_packet_ip(
                    (local_ip, local_port),
                    (remote_ip, remote_port),
                    snd_nxt.load(Relaxed),
                    rcv_nxt.load(Relaxed),
                    end,
                    65535,
                    &[],
                    false,
                    &mut pkt,
                );
                let _ = dev_writer.write_packet(&pkt);
            }
            // Queue the entry's removal before the shutdown that wakes the relay leg, so a caller that sees the leg end can reap the entry at its next dispatch.
            let _ = ended_tx.send(Ended::Stream(key, id));
            // Both halves, because the handler's write half is a clone of this descriptor and only a shutdown tells it the flow is over.
            let _ = read_half.shutdown(Shutdown::Both);
        });

        Ok(())
    }

    /// Answer an ICMP echo request as the device's own address would, so a ping off the
    /// interface returns instead of vanishing; a message that is not a well-formed echo
    /// request is left unanswered, exactly as the reference's handler returns.
    fn handle_icmp(&mut self, ip: &IpHead, body: &[u8]) -> io::Result<()> {
        if is_echo_request(ip.protocol, body) {
            let mut emit = std::mem::take(&mut self.emit);
            render_icmp_reply_ip(ip.destination, ip.source, body, &mut emit);
            let wrote = self.device.write_packet(&emit);
            self.emit = emit;
            return wrote;
        }
        if let Some((key, seq)) = icmp_error_flow(ip.protocol, body) {
            let Some(flow) = self.flows.get(&key) else {
                return Ok(());
            };
            // A forged report names a segment this handler never sent; the quote's sequence has to sit inside what has already gone out.
            let sent = flow.snd_nxt.load(Relaxed);
            if seq == sent || sent.wrapping_sub(seq) > u32::MAX / 2 {
                return Ok(());
            }
            if let Some(mtu) = reported_mtu(ip.protocol, body) {
                self.shrink_flow(key, mtu);
            } else {
                self.close_flow(key, Some(FLAG_RST | FLAG_ACK));
            }
        }
        Ok(())
    }

    /// Take a path-MTU report for the rest of a flow: only a smaller segment size is believed, and the floor keeps a forged report from stopping the flow.
    fn shrink_flow(&mut self, key: FlowKey, mtu: u32) {
        if let Some(flow) = self.flows.get(&key) {
            let mss = path_mss(mtu, flow.remote.0.is_ipv6());
            let current = flow.mss.load(Relaxed);
            flow.mss.store(current.min(mss), Relaxed);
        }
    }

    fn close_flow(&mut self, key: FlowKey, signal: Option<u8>) {
        if let Some(flow) = self.flows.remove(&key) {
            match signal {
                Some(flags) if !flow.signaled.swap(true, Relaxed) => {
                    let mut emit = std::mem::take(&mut self.emit);
                    render_tcp_packet_ip(
                        flow.local,
                        flow.remote,
                        flow.snd_nxt.load(Relaxed),
                        flow.rcv_nxt.load(Relaxed),
                        flags,
                        65535,
                        &[],
                        false,
                        &mut emit,
                    );
                    let _ = self.device.write_packet(&emit);
                    self.emit = emit;
                }
                // The device reset the flow itself: nothing has to travel back.
                _ => flow.signaled.store(true, Relaxed),
            }
            flow.send.close();
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
    endpoint: (IpAddr, u16),
    client: (IpAddr, u16),
    key: UdpKey,
    id: u64,
    ended: &mpsc::Sender<Ended>,
) -> io::Result<UdpSocket> {
    let leg = crate::proxy::relay_leg(relay)?;
    let target = SocketAddr::new(endpoint.0, endpoint.1);
    let reader = leg.try_clone()?;
    let mut dev_writer = device.clone_writer()?;
    let mtu = device.mtu;
    let ended = ended.clone();
    let (endpoint_bytes, client_bytes) = octets(endpoint.0, client.0);
    let endpoint_len = if endpoint.0.is_ipv6() { 16 } else { 4 };
    let client_len = if client.0.is_ipv6() { 16 } else { 4 };
    std::thread::spawn(move || {
        let mut buf = crate::proxy::udp_buffer();
        let mut out: Vec<u8> = Vec::with_capacity(IPV6_HEADER + UDP_HEADER + mtu);
        while let Ok(n) = reader.recv(&mut buf) {
            let Some((source, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
                continue;
            };
            if source != target {
                continue;
            }
            let datagram = UdpDatagram {
                source: &endpoint_bytes[..endpoint_len],
                destination: &client_bytes[..client_len],
                source_port: endpoint.1,
                destination_port: client.1,
                payload,
            };
            out.clear();
            if !udp_datagram(&datagram, &mut out) {
                continue;
            }
            if dev_writer.write_packet(&out).is_err() {
                break;
            }
        }
        let _ = ended.send(Ended::Datagram(key, id));
    });
    Ok(leg)
}

pub(crate) fn refusal_reason(spec: &Spec) -> String {
    format!(
        "`{}` (mtu {} B) cannot open a TUN: no ioctl and no FERROX_TUN_FD",
        if spec.name.is_empty() {
            "default"
        } else {
            spec.name.as_str()
        },
        spec.mtu
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
    fn a_tun_prefix_is_kept_or_refused_by_family() {
        let (address, prefix) = parse_address(Some("198.18.0.1/0"), None).unwrap();
        assert_eq!(address, Some("198.18.0.1".parse().unwrap()));
        assert_eq!(prefix, Some(0));
        assert!(parse_address(Some("198.18.0.1/33"), None).is_err());
        assert!(parse_address(Some("2001:db8::1/129"), None).is_err());
        assert!(parse_address(Some("not-an-ip"), None).is_err());
        let (_, prefix) = parse_address(Some("2001:db8::1"), None).unwrap();
        assert_eq!(prefix, None);
    }

    #[test]
    fn the_tun_spec_defaults_ipv6_and_bounds_its_values() {
        let spec = Spec::with(None, None, Some("2001:db8::1".parse().unwrap()), None, None);
        assert_eq!(spec.prefix(), 64);
        assert!(Spec::with(None, Some(65_536), None, None, None)
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, Some(33), None)
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, None, Some(0))
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, None, Some(5))
            .validate()
            .is_err());
        assert!(Spec::with(None, None, None, Some(0), None)
            .validate()
            .is_ok());
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
    fn a_gso_read_can_take_more_than_one_mss() {
        assert_eq!(read_limit(true, 1400, 65_515), 65_515);
        assert_eq!(read_limit(false, 1400, 65_515), 1400);
        assert_eq!(read_limit(false, 1400, 700), 700);
    }

    #[test]
    fn a_virtio_gso_header_names_the_tcp_segment() {
        assert_eq!(Framing::Virtio.header_len(), VIRTIO_NET_HDR_LEN);
        assert_eq!(Framing::Utun.header_len(), UTUN_HEADER_LEN);
        let packet = build_ipv6_tcp_packet(
            ("2001:db8::2".parse().unwrap(), 1),
            ("2001:db8::1".parse().unwrap(), 2),
            0,
            0,
            FLAG_ACK,
            4096,
            b"",
        );
        let header = virtio_header(&packet, Some(1400));
        assert_eq!(header[0], VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(header[1], VIRTIO_NET_HDR_GSO_TCPV6);
        assert_eq!(u16::from_ne_bytes([header[2], header[3]]), 60);
        assert_eq!(u16::from_ne_bytes([header[4], header[5]]), 1400);
        assert_eq!(u16::from_ne_bytes([header[6], header[7]]), 40);
        assert_eq!(u16::from_ne_bytes([header[8], header[9]]), 16);
    }

    /// A response read larger than one segment leaves as one GSO frame: the end-to-end gate the header-only test cannot be, because it drives the response thread rather than calling the header builder.
    #[cfg(unix)]
    #[test]
    fn a_large_response_read_leaves_as_one_gso_frame() {
        use std::io::Write;
        let (a, mut peer) = peer_with_deadline().unwrap();
        let payload: Vec<u8> = (0..4_000u32).map(|i| (i % 251) as u8).collect();
        let sent = payload.clone();
        let relay: Relay = Arc::new(move |mut conn: Connection, _dest| {
            conn.write_all(&sent)?;
            Ok(())
        });
        let device = Device {
            handle: a,
            mtu: 100,
            framing: Framing::Virtio,
            gso: true,
        };
        let mut handler = Handler::new(device, relay, no_associate());
        let client = (SCRIPT_CLIENT, 51001);
        let endpoint = ([203, 0, 113, 53], 53);
        let mut buf = vec![0u8; MAX_PACKET + 64];

        // A virtio-framed SYN: the device read strips the ten-byte header as a Linux descriptor's does, and the response thread is spawned off the flow.
        let syn = build_tcp_packet(client, endpoint, 7000, 0, FLAG_SYN, 65535, &[]);
        let mut frame = vec![0u8; VIRTIO_NET_HDR_LEN];
        frame.extend_from_slice(&syn);
        peer.write_all(&frame).unwrap();
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let mut gso = None;
        for _ in 0..2_500 {
            match peer.read(&mut buf) {
                Ok(n) if n > VIRTIO_NET_HDR_LEN => {
                    let header: [u8; VIRTIO_NET_HDR_LEN] =
                        buf[..VIRTIO_NET_HDR_LEN].try_into().unwrap();
                    if header[1] == VIRTIO_NET_HDR_GSO_TCPV4 {
                        gso = Some((header, n));
                        break;
                    }
                    // The SYN-ACK carries no GSO header; answer it so the flow's receive cursor moves, then wait for the response.
                    if header == [0u8; VIRTIO_NET_HDR_LEN] {
                        if let Some((_ip, body)) = ipv4_head(&buf[VIRTIO_NET_HDR_LEN..n]) {
                            if let Some((tcp, _)) = tcp_head(body) {
                                if tcp.flags == FLAG_SYN | FLAG_ACK {
                                    let ack = build_tcp_packet(
                                        client,
                                        endpoint,
                                        7001,
                                        tcp.seq.wrapping_add(1),
                                        FLAG_ACK,
                                        65535,
                                        &[],
                                    );
                                    let mut frame = vec![0u8; VIRTIO_NET_HDR_LEN];
                                    frame.extend_from_slice(&ack);
                                    peer.write_all(&frame).unwrap();
                                    let m = handler.device.read_packet(&mut buf).unwrap();
                                    handler.dispatch(&buf[..m]).unwrap();
                                }
                            }
                        }
                    }
                }
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
        let (header, total) = gso.expect("a read larger than the MSS leaves as one GSO frame");
        assert_eq!(
            header[0] & VIRTIO_NET_HDR_F_NEEDS_CSUM,
            VIRTIO_NET_HDR_F_NEEDS_CSUM,
            "the kernel completes the checksum"
        );
        assert_eq!(header[1], VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(
            usize::from(u16::from_ne_bytes([header[4], header[5]])),
            60,
            "the split size is the flow's MSS"
        );
        let (ip, body) = ipv4_head(&buf[VIRTIO_NET_HDR_LEN..total]).unwrap();
        let (_tcp, carried) = tcp_head(body).unwrap();
        assert_eq!(
            carried,
            payload.as_slice(),
            "one GSO frame carries the whole read"
        );
        // The offload field is the pseudo-header sum in network order, the same value the header-only test pins without the segment the kernel adds.
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&ip.source);
        pseudo.extend_from_slice(&ip.destination);
        pseudo.extend_from_slice(&[0, TCP_PROTO]);
        pseudo.extend_from_slice(&(body.len() as u16).to_be_bytes());
        let mut sum = 0u32;
        for word in pseudo.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        assert_eq!(
            u16::from_be_bytes([body[16], body[17]]),
            (sum & 0xffff) as u16,
            "the partial checksum is the pseudo-header sum in the network order the kernel folds"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_offload_refusal_is_retried_without_it() {
        assert!(offload_refused(&io::Error::from_raw_os_error(libc::EINVAL)));
        assert!(offload_refused(&io::Error::new(
            io::ErrorKind::Unsupported,
            "offload"
        )));
        assert!(!offload_refused(&io::Error::from_raw_os_error(libc::EPERM)));
    }

    #[cfg(unix)]
    #[test]
    fn an_inherited_descriptor_does_not_claim_gso() {
        let (handle, _peer) = unix_socketpair().unwrap();
        let device = Device::from_handle(handle, 1500);
        assert!(!device.clone_writer().unwrap().gso());
    }

    #[cfg(unix)]
    #[test]
    fn a_framed_packet_takes_one_write() {
        let (mut writer, mut reader) = unix_socketpair().unwrap();
        let packet = [0x45u8; 20];
        for framing in [Framing::Raw, Framing::Utun, Framing::Virtio] {
            let mut expected = match framing {
                Framing::Raw => Vec::new(),
                Framing::Utun => vec![0, 0, 0, UTUN_AF_INET],
                Framing::Virtio => virtio_header(&packet, None).to_vec(),
            };
            expected.extend_from_slice(&packet);
            assert!(write_framed(&mut writer, framing, None, &packet).unwrap());
            let mut got = [0u8; 64];
            let n = reader.read(&mut got).unwrap();
            assert_eq!(&got[..n], expected, "{framing:?} split its frame");
        }
    }

    #[test]
    fn a_quoted_v6_flow_is_read_through_an_extension_header() {
        let mut quoted = vec![0u8; IPV6_HEADER + 16];
        quoted[0] = 0x60;
        quoted[6] = 0;
        quoted[7] = 64;
        quoted[8..24].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        quoted[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        quoted[40] = TCP_PROTO;
        quoted[48..50].copy_from_slice(&443u16.to_be_bytes());
        quoted[50..52].copy_from_slice(&12345u16.to_be_bytes());
        let (flow, seq) = quoted_flow(&quoted).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(flow.source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.source_port, 12345);
        assert_eq!(flow.destination_port, 443);
        assert_eq!(flow.destination, "2001:db8::2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn an_ipv6_tcp_packet_parses_and_renders_with_its_checksum() {
        let source: IpAddr = "2001:db8::2".parse().unwrap();
        let destination: IpAddr = "2001:db8::1".parse().unwrap();
        let pkt = build_ipv6_tcp_packet(
            (source, 12345),
            (destination, 443),
            1000,
            1001,
            FLAG_SYN | FLAG_ACK,
            65535,
            b"v6",
        );
        assert_eq!(pkt[0] >> 4, 6);
        let (ip, body) = ip_head(&pkt).unwrap();
        assert_eq!(ip.source, source);
        assert_eq!(ip.destination, destination);
        assert_eq!(ip.protocol, TCP_PROTO);
        let (tcp, payload) = tcp_head(body).unwrap();
        assert_eq!(tcp.source_port, 12345);
        assert_eq!(tcp.destination_port, 443);
        assert_eq!(payload, b"v6");
        let (from, to) = octets(source, destination);
        assert_eq!(tcp_checksum(&from, &to, body), 0);
    }

    #[test]
    fn an_ipv6_extension_header_is_walked_to_the_transport() {
        let source: IpAddr = "2001:db8::2".parse().unwrap();
        let destination: IpAddr = "2001:db8::1".parse().unwrap();
        let tcp = build_ipv6_tcp_packet((source, 7), (destination, 8), 1, 2, FLAG_ACK, 4096, b"x");
        let mut pkt = Vec::with_capacity(tcp.len() + 8);
        pkt.extend_from_slice(&tcp[..IPV6_HEADER]);
        pkt[6] = 60;
        pkt[4..6].copy_from_slice(&((tcp.len() - IPV6_HEADER + 8) as u16).to_be_bytes());
        pkt.extend_from_slice(&[TCP_PROTO, 0, 1, 4, 0, 0, 0, 0]);
        pkt.extend_from_slice(&tcp[IPV6_HEADER..]);
        let (ip, body) = ip_head(&pkt).unwrap();
        assert_eq!(ip.protocol, TCP_PROTO);
        assert_eq!(tcp_head(body).unwrap().1, b"x");
    }

    #[test]
    fn an_icmp_error_quotes_the_flow_it_ends() {
        let remote: IpAddr = "2001:db8::2".parse().unwrap();
        let client: IpAddr = "2001:db8::1".parse().unwrap();
        let quoted =
            build_ipv6_tcp_packet((remote, 443), (client, 5555), 9, 10, FLAG_ACK, 4096, b"");
        let mut body = vec![2, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&quoted[..IPV6_HEADER + 8]);
        let (key, seq) = icmp_error_flow(ICMPV6_PROTO, &body).unwrap();
        assert_eq!(seq, 9);
        assert_eq!(key.source_port, 5555);
        assert_eq!(key.source, client);
        assert_eq!(key.destination, remote);
        assert_eq!(key.destination_port, 443);
    }

    #[test]
    fn a_v4_icmp_error_quotes_the_flow_it_ends() {
        let quoted = build_tcp_packet(
            ([203, 0, 113, 7], 443),
            ([10, 0, 0, 2], 5555),
            9,
            10,
            FLAG_ACK,
            4096,
            b"",
        );
        let mut body = vec![3, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&quoted[..IPV4_HEADER + 8]);
        let (key, seq) = icmp_error_flow(ICMP_PROTO, &body).unwrap();
        assert_eq!(seq, 9);
        assert_eq!(key.source_port, 5555);
        assert_eq!(key.source, IpAddr::V4([10, 0, 0, 2].into()));
        assert_eq!(key.destination, IpAddr::V4([203, 0, 113, 7].into()));
        assert_eq!(key.destination_port, 443);
    }

    #[test]
    fn a_path_mtu_report_names_the_segment_size_left_for_the_path() {
        let v4 = [3, 4, 0, 0, 0, 0, 0x04, 0xb0];
        assert_eq!(reported_mtu(ICMP_PROTO, &v4), Some(1200));
        assert_eq!(
            reported_mtu(ICMP_PROTO, &[3, 3, 0, 0, 0, 0, 0x04, 0xb0]),
            None
        );
        let v6 = [2, 0, 0, 0, 0, 0, 0x04, 0xb0];
        assert_eq!(reported_mtu(ICMPV6_PROTO, &v6), Some(1280));
        assert_eq!(reported_mtu(ICMPV6_PROTO, &[1, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(path_mss(1200, false), 1160);
        assert_eq!(path_mss(1200, true), 1140);
        assert_eq!(path_mss(40, true), SMALLEST_MSS);
    }

    #[test]
    fn a_v6_echo_request_flips_to_a_v6_reply() {
        let request = [128u8, 0, 0, 0, 0, 1, 0, 1, b'p', b'i', b'n', b'g'];
        let mut out = Vec::new();
        render_icmp_reply_ip(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            &request,
            &mut out,
        );
        assert_eq!(out[0] >> 4, 6);
        assert_eq!(out[IPV6_HEADER], ICMPV6_ECHO_REPLY);
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

    struct RefuseOnce {
        writes: usize,
        accepted: Vec<u8>,
    }

    impl Write for RefuseOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "one packet refused",
                ));
            }
            self.accepted.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_refused_packet_does_not_end_the_flow() {
        let mut writer = RefuseOnce {
            writes: 0,
            accepted: Vec::new(),
        };
        assert!(
            !write_packet_to(&mut writer, b"refused").expect("the refusal is reported"),
            "a refused packet is dropped"
        );
        assert!(
            write_packet_to(&mut writer, b"carried").expect("the next packet is written"),
            "the next packet is carried"
        );
        assert_eq!(
            writer.accepted, b"carried",
            "the packet after a refusal still reaches the device"
        );
    }

    struct InterruptOnce {
        writes: usize,
        accepted: Vec<u8>,
    }

    impl Write for InterruptOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes == 1 {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.accepted.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_interrupted_packet_write_is_retried() {
        let mut writer = InterruptOnce {
            writes: 0,
            accepted: Vec::new(),
        };
        assert!(
            write_packet_to(&mut writer, b"retried").expect("the retry carries the packet"),
            "a transient signal is retried, not treated as a refusal"
        );
        assert_eq!(writer.accepted, b"retried");
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
        assert!(
            !is_echo_request(ICMP_PROTO, &[0, 0, 0, 0, 0, 0, 0, 0]),
            "an echo reply"
        );
        assert!(
            !is_echo_request(ICMP_PROTO, &[8, 3, 0, 0, 0, 0, 0, 0]),
            "a non-zero code"
        );
        assert!(
            !is_echo_request(ICMP_PROTO, &[8, 0, 0, 0]),
            "shorter than the eight-byte header"
        );
        assert!(
            is_echo_request(ICMP_PROTO, &[8, 0, 0, 0, 0, 0, 0, 0]),
            "a well-formed request"
        );
        assert!(
            is_echo_request(ICMPV6_PROTO, &[128, 0, 0, 0, 0, 0, 0, 0]),
            "a well-formed v6 request"
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
    #[test]
    fn a_packet_too_big_shrinks_the_response_segment() {
        let (a, b) = unix_socketpair().unwrap();
        let (_release, hold) = std::sync::mpsc::channel::<()>();
        let hold = Arc::new(std::sync::Mutex::new(hold));
        let relay: Relay = Arc::new(move |_conn, _dest| {
            let _ = hold.lock().unwrap().recv();
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut peer = b;
        let client = ([10, 0, 0, 2], 44444);
        let endpoint = ([10, 0, 0, 1], 8080);
        let syn = build_tcp_packet(client, endpoint, 1000, 0, FLAG_SYN, 65535, &[]);
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let key = FlowKey {
            source: IpAddr::V4(client.0.into()),
            source_port: 44444,
            destination: IpAddr::V4(endpoint.0.into()),
            destination_port: 8080,
        };
        assert_eq!(
            handler.flows.get(&key).unwrap().mss.load(Relaxed),
            (DEFAULT_MTU - IPV4_HEADER - 20) as u32
        );

        let quoted = build_tcp_packet(
            (endpoint.0, 8080),
            (client.0, 44444),
            1001,
            1001,
            FLAG_ACK,
            65535,
            &[],
        );
        let mut pkt = vec![0u8; IPV4_HEADER + 8 + IPV4_HEADER + 8];
        let len = pkt.len() as u16;
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&len.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = ICMP_PROTO;
        pkt[12..16].copy_from_slice(&endpoint.0);
        pkt[16..20].copy_from_slice(&client.0);
        let body = &mut pkt[IPV4_HEADER..];
        body[0] = 3;
        body[1] = 4;
        body[6..8].copy_from_slice(&1200u16.to_be_bytes());
        body[8..8 + IPV4_HEADER + 8].copy_from_slice(&quoted[..IPV4_HEADER + 8]);
        handler.dispatch(&pkt).unwrap();

        assert_eq!(handler.flows.get(&key).unwrap().mss.load(Relaxed), 1160);
    }

    #[cfg(unix)]
    #[test]
    fn a_v6_packet_too_big_shrinks_the_response_segment() {
        let (a, b) = unix_socketpair().unwrap();
        let (_release, hold) = std::sync::mpsc::channel::<()>();
        let hold = Arc::new(std::sync::Mutex::new(hold));
        let relay: Relay = Arc::new(move |_conn, _dest| {
            let _ = hold.lock().unwrap().recv();
            Ok(())
        });
        let mut handler = Handler::new(Device::from_handle(a, DEFAULT_MTU), relay, no_associate());
        let mut peer = b;
        let client: IpAddr = "2001:db8::2".parse().unwrap();
        let endpoint: IpAddr = "2001:db8::1".parse().unwrap();
        let syn = build_ipv6_tcp_packet(
            (client, 44444),
            (endpoint, 8080),
            1000,
            0,
            FLAG_SYN,
            65535,
            &[],
        );
        peer.write_all(&syn).unwrap();
        let mut buf = vec![0u8; DEFAULT_MTU + 64];
        let n = handler.device.read_packet(&mut buf).unwrap();
        handler.dispatch(&buf[..n]).unwrap();

        let key = FlowKey {
            source: client,
            source_port: 44444,
            destination: endpoint,
            destination_port: 8080,
        };
        assert_eq!(
            handler.flows.get(&key).unwrap().mss.load(Relaxed),
            (DEFAULT_MTU - IPV6_HEADER - 20) as u32
        );

        let quoted = build_ipv6_tcp_packet(
            (endpoint, 8080),
            (client, 44444),
            1001,
            1001,
            FLAG_ACK,
            65535,
            &[],
        );
        let mut pkt = vec![0u8; IPV6_HEADER + 8 + IPV6_HEADER + 8];
        let payload = (pkt.len() - IPV6_HEADER) as u16;
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&payload.to_be_bytes());
        pkt[6] = ICMPV6_PROTO;
        pkt[7] = 64;
        let (from, to) = octets(endpoint, client);
        pkt[8..24].copy_from_slice(&from);
        pkt[24..40].copy_from_slice(&to);
        let body = &mut pkt[IPV6_HEADER..];
        body[0] = 2;
        body[4..8].copy_from_slice(&1200u32.to_be_bytes());
        body[8..8 + IPV6_HEADER + 8].copy_from_slice(&quoted[..IPV6_HEADER + 8]);
        handler.dispatch(&pkt).unwrap();

        assert_eq!(handler.flows.get(&key).unwrap().mss.load(Relaxed), 1220);
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
            source: IpAddr::V4(Ipv4Addr::from(SCRIPT_CLIENT)),
            source_port,
            destination: IpAddr::V4(*destination.ip()),
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
        let IpAddr::V4(second_ip) = second.destination else {
            panic!("the test flow names an IPv4 destination");
        };
        peer.write_all(&build_tcp_packet(
            (SCRIPT_CLIENT, second.source_port),
            (second_ip.octets(), second.destination_port),
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
