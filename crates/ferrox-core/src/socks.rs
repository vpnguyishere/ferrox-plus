//! The SOCKS5 **client** half: the greeting, the RFC 1929 user/password exchange, the
//! request, and the datagram framing a UDP association carries.
//!
//! The tree serves SOCKS5 (the `socks` front) but never *dials* one. This module is the
//! other half: the bytes a SOCKS5 client writes, which is what a tun2socks tunnel needs
//! on the far side of a device.
//!
//! Byte-identity: the bytes here are the ones the pinned references write.
//! `xray-core/proxy/socks/protocol.go`'s `ClientHandshake` writes the greeting
//! `[5, 1, method]`, the RFC 1929 block `[1, ulen, user, plen, pass]`, and the request
//! `[5, cmd, 0, atyp, addr, port]`; `hev-socks5-core`'s `hev_socks5_client_write_request`
//! writes the same request shape with `cmd` in the second byte and `rsv` in the third.
//!
//! The datagram frame is RFC 1928's: two reserved bytes, a fragment byte, then the
//! destination address and port, then the payload.
//!
//! The SOCKS4 half is here too: the reply a front writes (`[0, 90, 0, 0, 0, 0, 0, 0]`
//! granted, `[0, 91, ...]` refused — the pinned Go server's own bytes) and the request a
//! client sends (the version, the command, the port, the address, the user id and, for
//! `SOCKS4a`, the name).

/// The protocol version every byte of this module carries.
pub const VERSION: u8 = 5;

/// The command byte: connect a TCP stream to the named destination.
pub const CMD_CONNECT: u8 = 0x01;
/// The command byte: bind a UDP relay to receive datagrams for the client.
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// The address type byte: a four-byte IPv4 address.
pub const ATYP_IPV4: u8 = 0x01;
/// The address type byte: a domain name, length-prefixed.
pub const ATYP_DOMAIN: u8 = 0x03;
/// The address type byte: a sixteen-byte IPv6 address.
pub const ATYP_IPV6: u8 = 0x04;

/// The authentication method byte: no authentication.
pub const METHOD_NONE: u8 = 0x00;
/// The authentication method byte: the RFC 1929 user/password exchange.
pub const METHOD_USER: u8 = 0x02;

/// The RFC 1929 sub-negotiation version byte.
pub const AUTH_VERSION: u8 = 0x01;

/// The SOCKS4 version byte.
pub const VERSION4: u8 = 4;

/// The SOCKS4 command byte: connect a TCP stream to the named destination.
pub const CMD4_CONNECT: u8 = 0x01;

/// The SOCKS4 reply code: the request was granted.
pub const REPLY4_GRANTED: u8 = 90;

/// The SOCKS4 reply code: the request was rejected.
pub const REPLY4_REJECTED: u8 = 91;

/// The longest name a SOCKS4 request may carry: the user id, or the domain of a
/// `SOCKS4a` request.
///
/// The bound is the pinned Go reader's: a name that does not end inside it is a
/// refused request, not a longer one.
pub const NAME4_MAX: usize = 255;

/// The address a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// A four-byte IPv4 address and a port.
    V4([u8; 4], u16),
    /// A sixteen-byte IPv6 address and a port.
    V6([u8; 16], u16),
    /// A domain name and a port. The name is length-prefixed on the wire.
    Name(&'a [u8], u16),
}

impl Target<'_> {
    /// The address type byte this target writes.
    #[must_use]
    pub const fn atyp(&self) -> u8 {
        match self {
            Self::V4(..) => ATYP_IPV4,
            Self::V6(..) => ATYP_IPV6,
            Self::Name(..) => ATYP_DOMAIN,
        }
    }

    /// The octets this target occupies on the wire: the type byte, the address, and the
    /// port. A name's length byte is counted, so a caller can reserve exactly.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        match self {
            Self::V4(..) => 1 + 4 + 2,
            Self::V6(..) => 1 + 16 + 2,
            Self::Name(name, _) => 1 + 1 + name.len() + 2,
        }
    }

    /// Write this target into `out`, which must hold `wire_len()` octets.
    pub fn encode_into(&self, out: &mut [u8]) {
        match self {
            Self::V4(octets, port) => {
                assert!(out.len() >= 7, "socks5 address buffer too short");
                out[0] = ATYP_IPV4;
                out[1..5].copy_from_slice(octets);
                out[5..7].copy_from_slice(&port.to_be_bytes());
            }
            Self::V6(octets, port) => {
                assert!(out.len() >= 19, "socks5 address buffer too short");
                out[0] = ATYP_IPV6;
                out[1..17].copy_from_slice(octets);
                out[17..19].copy_from_slice(&port.to_be_bytes());
            }
            Self::Name(name, port) => {
                let len = 4 + name.len();
                assert!(out.len() >= len, "socks5 address buffer too short");
                out[0] = ATYP_DOMAIN;
                out[1] = name.len() as u8;
                out[2..2 + name.len()].copy_from_slice(name);
                out[2 + name.len()..len].copy_from_slice(&port.to_be_bytes());
            }
        }
    }
}

/// The greeting a client opens with: the version, the number of methods, and the methods.
///
/// The pinned writers offer exactly the one method they will use — `[5, 1, 0]` without a
/// credential and `[5, 1, 2]` with one, which is what `xray-core`'s `ClientHandshake` and
/// `hev-socks5-core`'s `hev_socks5_client_write_auth_methods` each write. Offering both
/// (`[5, 2, 0, 2]`, as `zeronet`'s `connect_socks5` does) reaches one more server: this
/// tree's own front answers `[5, 2]` when it is configured with accounts and `[5, 0]`
/// when it is not, so a client that offers `USER` first and `NONE` second is answered
/// with whichever the front wants, and a client that offers only the method the front
/// does not want is refused. One method is what the references write.
#[must_use]
pub fn greeting(with_credential: bool) -> [u8; 3] {
    if with_credential {
        [VERSION, 1, METHOD_USER]
    } else {
        [VERSION, 1, METHOD_NONE]
    }
}

/// The RFC 1929 user/password block: the version, the user name, the password.
#[must_use]
pub fn user_pass(user: &[u8], pass: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + user.len() + pass.len());
    out.push(AUTH_VERSION);
    out.push(user.len() as u8);
    out.extend_from_slice(user);
    out.push(pass.len() as u8);
    out.extend_from_slice(pass);
    out
}

/// The request a client sends after the greeting: the version, the command, the reserved
/// byte, and the destination.
#[allow(
    clippy::uninit_vec,
    reason = "the address is written into the room below before the vector is read"
)]
#[must_use]
pub fn request(cmd: u8, target: &Target<'_>) -> Vec<u8> {
    let len = target.wire_len();
    let mut out = Vec::with_capacity(3 + len);
    out.push(VERSION);
    out.push(cmd);
    out.push(0);
    // SAFETY: the address is written into the room below before the vector is read, and `encode_into` fills every byte of it.
    unsafe { out.set_len(3 + len) };
    target.encode_into(&mut out[3..]);
    out
}

/// The address a server bound a session to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound<'a> {
    /// A four-byte IPv4 address and a port.
    V4([u8; 4], u16),
    /// A sixteen-byte IPv6 address and a port.
    V6([u8; 16], u16),
    /// A domain name and a port.
    Name(&'a [u8], u16),
}

impl Bound<'_> {
    /// The address type byte this bound address was sent as.
    #[must_use]
    pub const fn atyp(&self) -> u8 {
        match self {
            Self::V4(..) => ATYP_IPV4,
            Self::V6(..) => ATYP_IPV6,
            Self::Name(..) => ATYP_DOMAIN,
        }
    }

    /// The octets this address occupies on the wire, so a reader knows how many to consume.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        match self {
            Self::V4(..) => 1 + 4 + 2,
            Self::V6(..) => 1 + 16 + 2,
            Self::Name(name, _) => 1 + 1 + name.len() + 2,
        }
    }

    /// Write this address into `out`, which must hold `wire_len()` octets.
    pub fn encode_into(&self, out: &mut [u8]) {
        match self {
            Self::V4(octets, port) => {
                assert!(out.len() >= 7, "socks5 address buffer too short");
                out[0] = ATYP_IPV4;
                out[1..5].copy_from_slice(octets);
                out[5..7].copy_from_slice(&port.to_be_bytes());
            }
            Self::V6(octets, port) => {
                assert!(out.len() >= 19, "socks5 address buffer too short");
                out[0] = ATYP_IPV6;
                out[1..17].copy_from_slice(octets);
                out[17..19].copy_from_slice(&port.to_be_bytes());
            }
            Self::Name(name, port) => {
                let len = 4 + name.len();
                assert!(out.len() >= len, "socks5 address buffer too short");
                out[0] = ATYP_DOMAIN;
                out[1] = name.len() as u8;
                out[2..2 + name.len()].copy_from_slice(name);
                out[2 + name.len()..len].copy_from_slice(&port.to_be_bytes());
            }
        }
    }
}

/// The reply a SOCKS4 front writes when it grants the request: the version byte is
/// zero, the code, then the port and the address — both zero, the way the pinned Go
/// server writes them (`net.AnyIP` and port 0).
#[must_use]
pub fn grant4() -> &'static [u8] {
    &[0, REPLY4_GRANTED, 0, 0, 0, 0, 0, 0]
}

/// The reply a SOCKS4 front writes when it refuses the request.
#[must_use]
pub fn refuse4() -> &'static [u8] {
    &[0, REPLY4_REJECTED, 0, 0, 0, 0, 0, 0]
}

/// The request a SOCKS4 client sends: the version, the command, the port, the address,
/// the user id and its NUL — and, for `SOCKS4a`, the name and its NUL.
///
/// The address of a `SOCKS4a` request is the marker `0.0.0.1`: the first byte zero is
/// what tells the server a name follows. One buffer carries the whole request.
#[must_use]
pub fn request4(cmd: u8, port: u16, address: [u8; 4], user: &[u8], name: Option<&[u8]>) -> Vec<u8> {
    let total = 9 + user.len() + name.map_or(0, |name| name.len() + 1);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[VERSION4, cmd]);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&address);
    out.extend_from_slice(user);
    out.push(0);
    if let Some(name) = name {
        out.extend_from_slice(name);
        out.push(0);
    }
    debug_assert_eq!(out.len(), total);
    out
}

/// Write the SOCKS4 request into `out` and return its length, so a dial can use one
/// stack block instead of a heap `Vec`.
pub fn request4_into(
    cmd: u8,
    port: u16,
    address: [u8; 4],
    user: &[u8],
    name: Option<&[u8]>,
    out: &mut [u8],
) -> Option<usize> {
    let total = 9 + user.len() + name.map_or(0, |name| name.len() + 1);
    if out.len() < total {
        return None;
    }
    out[0] = VERSION4;
    out[1] = cmd;
    out[2..4].copy_from_slice(&port.to_be_bytes());
    out[4..8].copy_from_slice(&address);
    out[8..8 + user.len()].copy_from_slice(user);
    out[8 + user.len()] = 0;
    let mut at = 9 + user.len();
    if let Some(name) = name {
        out[at..at + name.len()].copy_from_slice(name);
        at += name.len();
        out[at] = 0;
        at += 1;
    }
    Some(at)
}

/// The RFC 1928 reply: the version, the status, the reserved byte, and the bound address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply<'a> {
    /// The status byte. Zero is success.
    pub status: u8,
    /// The address the server bound.
    pub bound: Bound<'a>,
}

impl Reply<'_> {
    /// Whether the server granted the request.
    #[must_use]
    pub const fn granted(&self) -> bool {
        self.status == 0
    }
}

/// Read a reply off the front of `buf`, which must hold the whole reply.
///
/// The reply is the version, the status, the reserved byte, and the bound address. A
/// version that is not five is refused, as is an address type that is not one of the
/// three RFC 1928 defines.
#[must_use]
pub fn parse_reply(buf: &[u8]) -> Option<Reply<'_>> {
    if buf.len() < 4 || buf[0] != VERSION {
        return None;
    }
    let atyp = buf[3];
    let (bound, len) = match atyp {
        ATYP_IPV4 => {
            let octets: [u8; 4] = buf.get(4..8)?.try_into().ok()?;
            let port = u16::from_be_bytes(buf.get(8..10)?.try_into().ok()?);
            (Bound::V4(octets, port), 10)
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = buf.get(4..20)?.try_into().ok()?;
            let port = u16::from_be_bytes(buf.get(20..22)?.try_into().ok()?);
            (Bound::V6(octets, port), 22)
        }
        ATYP_DOMAIN => {
            let name_len = usize::from(*buf.get(4)?);
            let name = buf.get(5..5 + name_len)?;
            let port = u16::from_be_bytes(buf.get(5 + name_len..7 + name_len)?.try_into().ok()?);
            (Bound::Name(name, port), 7 + name_len)
        }
        _ => return None,
    };
    if buf.len() < len {
        return None;
    }
    Some(Reply {
        status: buf[1],
        bound,
    })
}

/// The octets a UDP datagram frame occupies before its payload: the two reserved bytes, the
/// fragment byte, the address, and the port.
#[must_use]
pub fn datagram_header_len(target: &Target<'_>) -> usize {
    3 + target.wire_len()
}

/// Write a datagram frame: the reserved bytes, the fragment byte, the destination, and the
/// payload.
///
/// The fragment byte is zero: a fragmented datagram is dropped by every server that
/// implements RFC 1928 strictly, and the pinned Go reader drops one too
/// (`DecodeUDPPacket` refuses `packet.Byte(2) != 0`).
pub fn datagram(target: &Target<'_>, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(datagram_header_len(target) + payload.len());
    out.push(0);
    out.push(0);
    out.push(0);
    let at = out.len();
    out.resize(at + target.wire_len(), 0);
    target.encode_into(&mut out[at..]);
    out.extend_from_slice(payload);
}

/// Read a datagram frame off the front of `packet`, returning the source address and the
/// payload.
///
/// A frame whose fragment byte is not zero is refused: RFC 1928 says a server must not
/// reassemble fragments, and the pinned Go reader drops one.
#[must_use]
pub fn parse_datagram(packet: &[u8]) -> Option<(Bound<'_>, &[u8])> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let atyp = packet[3];
    let (bound, used) = match atyp {
        ATYP_IPV4 => {
            let octets: [u8; 4] = packet.get(4..8)?.try_into().ok()?;
            let port = u16::from_be_bytes(packet.get(8..10)?.try_into().ok()?);
            (Bound::V4(octets, port), 10)
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = packet.get(4..20)?.try_into().ok()?;
            let port = u16::from_be_bytes(packet.get(20..22)?.try_into().ok()?);
            (Bound::V6(octets, port), 22)
        }
        ATYP_DOMAIN => {
            let name_len = usize::from(*packet.get(4)?);
            let name = packet.get(5..5 + name_len)?;
            let port = u16::from_be_bytes(packet.get(5 + name_len..7 + name_len)?.try_into().ok()?);
            (Bound::Name(name, port), 7 + name_len)
        }
        _ => return None,
    };
    if packet.len() < used {
        return None;
    }
    Some((bound, &packet[used..]))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// The octets in hex, the way the oracle prints them.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// The octets behind a hex run.
    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    /// The target a script line names. The name lives in the embedded script, so it
    /// outlives the borrow.
    fn script_target(atyp: &str, addr: &'static str, port: &str) -> Target<'static> {
        let port: u16 = port.parse().expect("a port");
        match atyp {
            "ipv4" => Target::V4(addr.parse::<Ipv4Addr>().expect("an address").octets(), port),
            "ipv6" => Target::V6(addr.parse::<Ipv6Addr>().expect("an address").octets(), port),
            _ => Target::Name(addr.as_bytes(), port),
        }
    }

    /// The bytes this module writes are the bytes the pinned reference writes.
    ///
    /// The oracle (`scripts/socks5-oracle`) drives the pinned `xray-core`'s own
    /// `ClientHandshake` and `EncodeUDPPacket` and prints every octet they write.
    /// This replays the same script through this module's writers and compares the two
    /// runs octet for octet.
    #[test]
    fn the_client_writes_the_bytes_the_pinned_go_writes() {
        let script = include_str!("../../../scripts/socks5-oracle/script.txt");
        let expected = include_str!("../../../scripts/socks5-oracle/expected.txt");

        let mut lines = Vec::new();
        for line in script.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts[0] {
                "handshake" => {
                    let method = parts[1];
                    let target = script_target(parts[2], parts[3], parts[4]);
                    let mut bytes = greeting(method == "user").to_vec();
                    if method == "user" {
                        bytes.extend_from_slice(&user_pass(
                            parts[5].as_bytes(),
                            parts[6].as_bytes(),
                        ));
                    }
                    bytes.extend_from_slice(&request(CMD_CONNECT, &target));
                    lines.push(format!("BYTES {}", hex(&bytes)));
                }
                "udp" => {
                    let target = script_target(parts[1], parts[2], parts[3]);
                    let mut out = Vec::new();
                    datagram(&target, &unhex(parts[4]), &mut out);
                    lines.push(format!("BYTES {}", hex(&out)));
                }
                other => panic!("unknown script command {other}"),
            }
        }
        assert_eq!(lines.join("\n") + "\n", expected);
    }

    #[test]
    fn the_socks4_request_is_the_bytes_the_pinned_writer_writes() {
        // `xray-core`'s SOCKS4 server reads the version, the command, the port, the address and the user id; `SOCKS4a` adds the name after the user id.
        let request = request4(CMD4_CONNECT, 80, [127, 0, 0, 1], b"", None);
        assert_eq!(
            request,
            vec![4, 1, 0, 80, 127, 0, 0, 1, 0],
            "the version, the command, the port, the address and the user id's NUL"
        );
        let with_name = request4(
            CMD4_CONNECT,
            80,
            [0, 0, 0, 1],
            b"user",
            Some(b"example.com"),
        );
        assert_eq!(
            &with_name[..8],
            &[4, 1, 0, 80, 0, 0, 0, 1],
            "the address of a SOCKS4a request is the 0.0.0.1 marker"
        );
        assert_eq!(&with_name[8..], b"user\0example.com\0");
    }

    #[test]
    fn the_socks4_request_is_one_unzeroed_buffer() {
        let (request, counts) = crate::alloc_count::measure(|| {
            request4(
                CMD4_CONNECT,
                80,
                [0, 0, 0, 1],
                b"user",
                Some(b"example.com"),
            )
        });
        assert_eq!(&request[..8], &[4, 1, 0, 80, 0, 0, 0, 1]);
        assert_eq!(counts.allocs, 1, "the request is one buffer");
        assert_eq!(
            counts.zeroed, 0,
            "the request is written, not zero-filled before the write"
        );
    }

    #[test]
    fn the_socks4_reply_is_the_bytes_the_pinned_server_writes() {
        // `writeSocks4Response` writes the version byte zero, the code, the port and the address — `net.AnyIP` and port 0, both zero.
        assert_eq!(grant4(), &[0, 90, 0, 0, 0, 0, 0, 0]);
        assert_eq!(refuse4(), &[0, 91, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn the_greeting_is_the_bytes_the_pinned_writer_writes() {
        // `xray-core/proxy/socks/protocol.go` writes `[]byte{socks5Version, 0x01, authByte}`.
        assert_eq!(greeting(false), [5, 1, 0]);
        // With a credential the same writer writes `authPassword` alone, and `hev-socks5-core`'s `hev_socks5_client_write_auth_methods` writes the one method it will use — so does this.
        assert_eq!(greeting(true), [5, 1, 2]);
    }

    #[test]
    fn the_user_pass_block_is_rfc_1929() {
        assert_eq!(user_pass(b"u", b"p"), vec![1, 1, b'u', 1, b'p']);
        let block = user_pass(b"Test Account", b"Test Password");
        assert_eq!(block[0], 1);
        assert_eq!(usize::from(block[1]), b"Test Account".len());
        assert_eq!(&block[2..2 + b"Test Account".len()], b"Test Account");
        assert_eq!(
            usize::from(block[2 + b"Test Account".len()]),
            b"Test Password".len()
        );
        assert_eq!(
            &block[3 + b"Test Account".len()..],
            b"Test Password",
            "the password follows the name with its own length byte"
        );
    }

    #[test]
    fn the_request_is_the_bytes_the_pinned_writer_writes() {
        // `hev_socks5_client_write_request` writes ver, cmd, rsv, then the address.
        assert_eq!(
            request(CMD_CONNECT, &Target::V4([192, 0, 2, 1], 443)),
            vec![5, 1, 0, 1, 192, 0, 2, 1, 1, 187]
        );
        assert_eq!(
            request(CMD_CONNECT, &Target::Name(b"example.com", 443)),
            vec![
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                1, 187
            ]
        );
        // RFC 1928's UDP ASSOCIATE names no destination: the address is 0.0.0.0:0.
        assert_eq!(
            request(CMD_UDP_ASSOCIATE, &Target::V4([0, 0, 0, 0], 0)),
            vec![5, 3, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_target_encodes_to_the_octets_the_field_defines() {
        let mut buf = [0u8; 1 + 1 + 256 + 2];

        let v4 = Target::V4([192, 0, 2, 1], 443);
        assert_eq!(v4.wire_len(), 7);
        v4.encode_into(&mut buf);
        assert_eq!(&buf[..7], &[1, 192, 0, 2, 1, 1, 187]);

        let v6 = Target::V6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            443,
        );
        assert_eq!(v6.wire_len(), 19);
        v6.encode_into(&mut buf);
        assert_eq!(v6.atyp(), ATYP_IPV6);
        assert_eq!(
            &buf[1..17],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&buf[17..19], &[1, 187]);

        let name = Target::Name(b"example.com", 443);
        assert_eq!(name.wire_len(), 15);
        name.encode_into(&mut buf);
        assert_eq!(&buf[..15], b"\x03\x0bexample.com\x01\xbb");
    }

    #[test]
    fn the_datagram_frame_is_rfc_1928() {
        let mut out = Vec::new();
        datagram(&Target::V4([198, 51, 100, 7], 53), b"who-is", &mut out);
        assert_eq!(
            out,
            vec![0, 0, 0, 1, 198, 51, 100, 7, 0, 53, b'w', b'h', b'o', b'-', b'i', b's']
        );

        let (source, payload) = parse_datagram(&out).expect("the frame round trips");
        assert_eq!(source, Bound::V4([198, 51, 100, 7], 53));
        assert_eq!(payload, b"who-is");
    }

    #[test]
    fn a_datagram_frame_encodes_every_address_form() {
        let mut out = Vec::new();
        datagram(
            &Target::V6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
                53,
            ),
            b"p",
            &mut out,
        );
        assert_eq!(
            out,
            vec![
                0, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 53, b'p'
            ]
        );
        datagram(&Target::Name(b"a", 53), b"p", &mut out);
        assert_eq!(out, vec![0, 0, 0, 3, 1, b'a', 0, 53, b'p']);
    }

    #[test]
    fn a_fragmented_datagram_is_refused() {
        let mut out = Vec::new();
        datagram(&Target::V4([198, 51, 100, 7], 53), b"x", &mut out);
        out[2] = 1;
        assert!(parse_datagram(&out).is_none());
    }

    #[test]
    fn a_reply_reads_the_bound_address() {
        let reply = parse_reply(&[5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]).expect("a reply");
        assert!(reply.granted());
        assert_eq!(reply.bound, Bound::V4([127, 0, 0, 1], 8080));
    }

    #[test]
    fn a_refused_reply_is_read_and_carries_its_status() {
        let reply = parse_reply(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).expect("a reply");
        assert!(!reply.granted());
        assert_eq!(reply.status, 5);
    }

    #[test]
    fn a_reply_of_another_version_is_refused() {
        assert!(parse_reply(&[4, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_reply_of_an_unknown_address_type_is_refused() {
        assert!(parse_reply(&[5, 0, 0, 9, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_bound_address_round_trips_through_its_own_bytes() {
        let mut buf = [0u8; 1 + 1 + 256 + 2];
        for bound in [
            Bound::V4([192, 0, 2, 1], 443),
            Bound::V6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                443,
            ),
            Bound::Name(b"example.com", 443),
        ] {
            let len = bound.wire_len();
            bound.encode_into(&mut buf[..len]);
            assert_eq!(buf[0], bound.atyp());
        }
    }
}
