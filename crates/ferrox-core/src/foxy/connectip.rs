//! MASQUE CONNECT-IP (RFC 9484) over CONNECT-UDP's two carriers: one `connect-ip` request with `capsule-protocol: ?1`, then `ADDRESS_ASSIGN` 1, `ADDRESS_REQUEST` 2 and `ROUTE_ADVERTISEMENT` 3 capsules decide what the stream carries, IP packets for every destination riding the type-0 DATAGRAM capsule with a zero context byte — arithmetic only, no socket, clock or heap.

use super::frames::{quic_read, quic_varint, quic_varint_len};
use super::hpack::{integer, integer_into};
use std::net::IpAddr;

/// The default URI template, RFC 9484 §3.2, up to the host the tunnel reaches.
const PREFIX: &[u8] = b"/.well-known/masque/ip/";
/// The scheme the pass is presented with, the shape the edge answers on both carriers.
const BEARER: &[u8] = b"Bearer ";

/// The capsule type numbers, RFC 9484 §4.
const ADDRESS_ASSIGN: u64 = 1;
const ADDRESS_REQUEST: u64 = 2;
const ROUTE_ADVERTISEMENT: u64 = 3;

/// What a proxy grants when it refuses an address request (RFC 9484 §4.2): the all-zeros address at its full prefix length, rather than an error.
const REFUSED_V4: [u8; 4] = [0, 0, 0, 0];
const REFUSED_V6: [u8; 16] = [0; 16];

/// One address a proxy granted, with the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assigned {
    /// Which request this answers, so an answer can name it back.
    pub request_id: u64,
    /// Version 4 or 6, the address and the prefix length — the RFC's own order, which is also an `ADDRESS_REQUEST`'s write order.
    pub version: u8,
    pub address: [u8; 16],
    pub prefix: u8,
}

impl Assigned {
    /// Whether this is the proxy refusing, which the RFC names as the all-zeros prefix at full length rather than as an error.
    #[must_use]
    pub fn refused(&self) -> bool {
        match self.version {
            4 => self.prefix == 32 && self.address[..4] == REFUSED_V4,
            6 => self.prefix == 128 && self.address == REFUSED_V6,
            _ => true,
        }
    }

    /// The granted address, truncated to the width its version names.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.address[..self.width()]
    }

    /// The bytes one address of this version occupies on the wire.
    #[must_use]
    pub const fn width(&self) -> usize {
        if self.version == 4 {
            4
        } else {
            16
        }
    }
}

/// One route a proxy advertised (RFC 9484 §4.3): the first and last address it carries and the IP protocol that range is limited to, where zero carries every protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub first: [u8; 16],
    pub last: [u8; 16],
    pub version: u8,
    pub protocol: u8,
}

impl Route {
    #[must_use]
    pub const fn width(&self) -> usize {
        if self.version == 4 {
            4
        } else {
            16
        }
    }
}

/// The default URI template's path for one target (RFC 9484 §3.2): only a colon is encoded, since of a DNS name, an IPv4 literal and an IPv6 literal only the last uses one.
pub fn ip_path(host: &str, port: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(PREFIX);
    for byte in host.bytes() {
        if byte == b':' {
            out.extend_from_slice(b"%3A");
        } else {
            out.push(byte);
        }
    }
    out.push(b'/');
    push_port(out, port);
    out.push(b'/');
}

/// The path's length, which a field line names before writing it: HTTP/2 and QPACK write a field's length ahead of its bytes, so staging the path first would spend a buffer per connection.
fn ip_path_len(host: &str, port: u16) -> usize {
    PREFIX.len()
        + host.len()
        + 2 * host.bytes().filter(|byte| *byte == b':').count()
        + 1
        + decimal_len(port)
        + 1
}

/// The port's digits, written lowest first into the end of the buffer: a division per digit is the whole cost, where a `format!` here is an allocation per path.
fn push_port(out: &mut Vec<u8>, port: u16) {
    let mut port = port;
    let mut digits = [0u8; 5];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (port % 10) as u8;
        port /= 10;
        if port == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
}

/// The digits a decimal number has, so its length can be known before it is written.
fn decimal_len(mut value: u16) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// One HTTP/2 literal field line: the new-name pattern, the name with a 7-bit prefix, then the value the same way.
fn field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x00);
    integer(out, 7, 0x00, name.len());
    out.extend_from_slice(name);
    integer(out, 7, 0x00, value.len());
    out.extend_from_slice(value);
}

/// The same field line under QPACK's `001` pattern: the never-indexed bit set and a three-bit name prefix continuing into the following bytes.
fn qpack_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x20);
    integer_into(out, 3, name.len());
    out.extend_from_slice(name);
    integer(out, 7, 0x00, value.len());
    out.extend_from_slice(value);
}

/// The `:path` field line for one target, in either codec's own spelling: its length is known before the path is written, so the path never sits in a buffer of its own.
fn path_field(out: &mut Vec<u8>, host: &str, port: u16, qpack: bool) {
    if qpack {
        out.push(0x20);
        integer_into(out, 3, 5);
    } else {
        out.push(0x00);
        integer(out, 7, 0x00, 5);
    }
    out.extend_from_slice(b":path");
    integer(out, 7, 0x00, ip_path_len(host, port));
    ip_path(host, port, out);
}

/// The authorization field line, whose value is the pass behind the scheme: one length covers both halves and the bytes follow in place, because a `Bearer ` and a token are never more than a concatenation.
fn bearer_field(out: &mut Vec<u8>, bearer: &str, qpack: bool) {
    if qpack {
        out.push(0x20);
        integer_into(out, 3, b"proxy-authorization".len());
    } else {
        out.push(0x00);
        integer(out, 7, 0x00, b"proxy-authorization".len());
    }
    out.extend_from_slice(b"proxy-authorization");
    integer(out, 7, 0x00, BEARER.len() + bearer.len());
    out.extend_from_slice(BEARER);
    out.extend_from_slice(bearer.as_bytes());
}

/// One CONNECT-IP request over HTTP/2 (RFC 9484 §3.2): the `:protocol` naming the IP proxy rather than the UDP one, the template, the pass, and the capsule protocol the rest of the stream is written in.
pub fn connect_ip(edge_authority: &str, host: &str, port: u16, bearer: &str, out: &mut Vec<u8>) {
    field(out, b":method", b"CONNECT");
    field(out, b":protocol", b"connect-ip");
    field(out, b":scheme", b"https");
    field(out, b":authority", edge_authority.as_bytes());
    path_field(out, host, port, false);
    bearer_field(out, bearer, false);
    field(out, b"capsule-protocol", b"?1");
}

/// The same request as a QPACK block, which is how it rides HTTP/3.
pub fn connect_ip_qpack(
    edge_authority: &str,
    host: &str,
    port: u16,
    bearer: &str,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&[0x00, 0x00]);
    qpack_field(out, b":method", b"CONNECT");
    qpack_field(out, b":protocol", b"connect-ip");
    qpack_field(out, b":scheme", b"https");
    qpack_field(out, b":authority", edge_authority.as_bytes());
    path_field(out, host, port, true);
    bearer_field(out, bearer, true);
    qpack_field(out, b"capsule-protocol", b"?1");
}

/// The same request as a QPACK block with the path, authority and headers a config named, which is how MASQUE's transport writes it: the path is a literal rather than the RFC 9484 template, and every header rides in the order the config gave.
pub fn connect_ip_qpack_named(
    authority: &str,
    path: &str,
    headers: &[(String, String)],
    out: &mut Vec<u8>,
) {
    connect_ip_qpack_named_protocol(authority, path, b"connect-ip", headers, out);
}

/// The same named request under the extended-CONNECT protocol a transport
/// asks for: Cloudflare's WARP endpoint answers `cf-connect-ip`, and the rest
/// of the block is unchanged.
pub fn connect_ip_qpack_named_protocol(
    authority: &str,
    path: &str,
    protocol: &[u8],
    headers: &[(String, String)],
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&[0x00, 0x00]);
    qpack_field(out, b":method", b"CONNECT");
    qpack_field(out, b":protocol", protocol);
    qpack_field(out, b":scheme", b"https");
    qpack_field(out, b":authority", authority.as_bytes());
    qpack_field(out, b":path", path.as_bytes());
    for (name, value) in headers {
        qpack_field(out, name.as_bytes(), value.as_bytes());
    }
    qpack_field(out, b"capsule-protocol", b"?1");
}

/// The prefix one IP packet carries inside a QUIC DATAGRAM on a CONNECT-IP stream (RFC 9484 §5): the stream id divided by four as a varint, then context zero. The datagram's length comes from the QUIC frame, so none is written here.
pub fn datagram_prefix(stream: u64, out: &mut Vec<u8>) {
    quic_varint(out, stream / 4);
    out.push(0);
}

/// Splits one QUIC DATAGRAM on a CONNECT-IP stream into its stream id and packet, refusing a context this lane does not read; the inverse of [`datagram_prefix`].
#[must_use]
pub fn datagram_split(datagram: &[u8]) -> Option<(u64, &[u8])> {
    let mut at = 0usize;
    let quarter = quic_read(datagram, &mut at)?;
    let context = quic_read(datagram, &mut at)?;
    if context != 0 {
        return None;
    }
    Some((quarter.checked_mul(4)?, &datagram[at..]))
}

/// One `ADDRESS_REQUEST` capsule (RFC 9484 §4.1): a request id that must not be zero, then the address wanted; a client with no preference asks for `0.0.0.0` or `::` and the proxy answers with what it picks.
pub fn address_request(id: u64, version: u8, address: &[u8], out: &mut Vec<u8>) {
    address_requests(&[(id, version, address)], out);
}

/// One `ADDRESS_REQUEST` capsule naming every address a client wants, which is how the reference asks for both families at once: a proxy replaces the peer's allowed sources with each answer, so a second request would leave the first family unroutable.
pub fn address_requests(entries: &[(u64, u8, &[u8])], out: &mut Vec<u8>) {
    let length: usize = entries
        .iter()
        .map(|(id, _, address)| quic_varint_len(*id) + 1 + address.len() + 1)
        .sum();
    quic_varint(out, ADDRESS_REQUEST);
    quic_varint(out, length as u64);
    for (id, version, address) in entries {
        quic_varint(out, *id);
        out.push(*version);
        out.extend_from_slice(address);
        out.push((address.len() as u8) * 8);
    }
}

/// Bytes one DATAGRAM capsule takes for an IP packet of this length, so a caller frames it before building it: HTTP/3 writes its frame length ahead, and the capsule's own varint sits inside it.
pub fn packet_len(packet: usize) -> usize {
    1 + quic_varint_len(1 + packet as u64) + 1 + packet
}

/// One IP packet as one DATAGRAM capsule: type zero, the context byte zero, then the packet unchanged.
pub fn packet_encode(packet: &[u8], out: &mut Vec<u8>) {
    out.push(0x00);
    quic_varint(out, 1 + packet.len() as u64);
    out.push(0x00);
    out.extend_from_slice(packet);
}

/// The same capsule without a context: the shape Cloudflare's WARP carries
/// over HTTP/2, where the request stream is the only context there is.
pub fn packet_encode_bare(packet: &[u8], out: &mut Vec<u8>) {
    out.push(0x00);
    quic_varint(out, packet.len() as u64);
    out.extend_from_slice(packet);
}

/// What one capsule was, as far as this lane reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capsule<'a> {
    /// A DATAGRAM capsule with context zero, whose packet follows the context.
    Datagram(&'a [u8]),
    /// The proxy answering an address request, or refusing it.
    AddressAssign(&'a [u8]),
    /// A proxy asking the client for an address.
    AddressRequest(&'a [u8]),
    /// The proxy naming the ranges it will carry.
    RouteAdvert(&'a [u8]),
    /// A capsule number this lane does not read.
    Other(u64),
}

/// The first complete capsule in a stream buffer: bytes consumed and what it was, or `None` while the capsule is not whole; a capsule this lane does not read is *answered* and stepping over it is the caller's, because an advertised extension must not cost the tunnel its packets.
#[must_use]
pub fn capsule_split(buf: &[u8]) -> Option<(usize, Capsule<'_>)> {
    let mut at = 0usize;
    if at >= buf.len() {
        return None;
    }
    let kind = quic_read(buf, &mut at)?;
    let length = quic_read(buf, &mut at)? as usize;
    let end = at.checked_add(length)?;
    let value = buf.get(at..end)?;
    Some((
        end,
        match kind {
            0 => {
                let mut at_context = 0usize;
                if quic_read(value, &mut at_context) == Some(0) {
                    Capsule::Datagram(&value[at_context..])
                } else {
                    Capsule::Other(0)
                }
            }
            ADDRESS_ASSIGN => Capsule::AddressAssign(value),
            ADDRESS_REQUEST => Capsule::AddressRequest(value),
            ROUTE_ADVERTISEMENT => Capsule::RouteAdvert(value),
            other => Capsule::Other(other),
        },
    ))
}

/// The first complete capsule in a WARP HTTP/2 body: a type-zero capsule is a
/// bare packet with no context byte, and every other type reads as it does on
/// the RFC 9484 stream.
#[must_use]
pub fn capsule_split_bare(buf: &[u8]) -> Option<(usize, Capsule<'_>)> {
    let mut at = 0usize;
    if at >= buf.len() {
        return None;
    }
    let kind = quic_read(buf, &mut at)?;
    let length = quic_read(buf, &mut at)? as usize;
    let end = at.checked_add(length)?;
    let value = buf.get(at..end)?;
    Some((
        end,
        match kind {
            0 => Capsule::Datagram(value),
            ADDRESS_ASSIGN => Capsule::AddressAssign(value),
            ADDRESS_REQUEST => Capsule::AddressRequest(value),
            ROUTE_ADVERTISEMENT => Capsule::RouteAdvert(value),
            other => Capsule::Other(other),
        },
    ))
}

/// The addresses one `ADDRESS_ASSIGN` capsule grants (RFC 9484 §4.2): host bits above the prefix are *not* required to be zero — a proxy hands out a `/64` and `2001:db8::1` inside it is the tunnel's address — while a request must zero them, which this lane's all-zeros-at-full-length request does by construction.
pub fn address_assign(body: &[u8], into: &mut Vec<Assigned>) -> Option<()> {
    into.clear();
    let mut at = 0usize;
    while at < body.len() {
        let request_id = quic_read(body, &mut at)?;
        let version = *body.get(at)?;
        at += 1;
        let width = match version {
            4 => 4usize,
            6 => 16,
            _ => return None,
        };
        let mut address = [0u8; 16];
        address[..width].copy_from_slice(body.get(at..at + width)?);
        at += width;
        let prefix = *body.get(at)?;
        at += 1;
        if usize::from(prefix) > width * 8 {
            return None;
        }
        into.push(Assigned {
            request_id,
            version,
            address,
            prefix,
        });
    }
    Some(())
}

/// The routes one `ROUTE_ADVERTISEMENT` capsule names, RFC 9484 §4.3.
pub fn route_advert(body: &[u8], into: &mut Vec<Route>) -> Option<()> {
    into.clear();
    let mut at = 0usize;
    while at < body.len() {
        let version = *body.get(at)?;
        at += 1;
        let width = match version {
            4 => 4usize,
            6 => 16,
            _ => return None,
        };
        let mut first = [0u8; 16];
        let mut last = [0u8; 16];
        first[..width].copy_from_slice(body.get(at..at + width)?);
        at += width;
        last[..width].copy_from_slice(body.get(at..at + width)?);
        at += width;
        let protocol = *body.get(at)?;
        at += 1;
        into.push(Route {
            first,
            last,
            version,
            protocol,
        });
    }
    Some(())
}

/// The `ADDRESS_ASSIGN` capsule a proxy answers requests with (RFC 9484 §4.2): one whole capsule — type, the body's length, then each grant as request id, version, address and prefix — the exact inverse of [`address_assign`], framed like [`address_request`] so both directions share one wire shape. A refusal is its own entry: the all-zeros address at full length.
pub fn address_assign_encode(assignments: &[Assigned], out: &mut Vec<u8>) {
    let body_len = assignments.iter().fold(0usize, |acc, a| {
        acc + quic_varint_len(a.request_id) + 1 + a.width() + 1
    });
    quic_varint(out, ADDRESS_ASSIGN);
    quic_varint(out, body_len as u64);
    for a in assignments {
        quic_varint(out, a.request_id);
        out.push(a.version);
        out.extend_from_slice(&a.address[..a.width()]);
        out.push(a.prefix);
    }
}

/// The `ROUTE_ADVERTISEMENT` capsule a proxy names its carried ranges with (RFC 9484 §4.3): the exact inverse of [`route_advert`], one whole capsule of first, last and protocol per route.
pub fn route_advert_encode(routes: &[Route], out: &mut Vec<u8>) {
    let body_len = routes.iter().fold(0usize, |acc, r| acc + 2 + 2 * r.width());
    quic_varint(out, ROUTE_ADVERTISEMENT);
    quic_varint(out, body_len as u64);
    for r in routes {
        let width = r.width();
        out.push(r.version);
        out.extend_from_slice(&r.first[..width]);
        out.extend_from_slice(&r.last[..width]);
        out.push(r.protocol);
    }
}

/// One IPv4 header read in place: this lane walks only the fields it needs, so a header it cannot walk is refused rather than repaired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Head {
    /// Total length, which includes this header.
    pub length: u16,
    /// The protocol this packet carries, where 17 is UDP.
    pub protocol: u8,
    /// Time to live, which a hop decrements and a zero refuses.
    pub hop: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

/// One IPv6 header, read in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Head {
    /// Payload length, which excludes this header.
    pub length: u16,
    /// The next header this packet carries, where 17 is UDP.
    pub next_header: u8,
    pub hop: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

/// The fixed header sizes, RFC 791 §3 and RFC 8200 §3.
pub const IPV4_HEADER: usize = 20;
pub const IPV6_HEADER: usize = 40;
/// The UDP header size, RFC 768.
pub const UDP_HEADER: usize = 8;
/// The protocol number UDP carries in both versions.
pub const PROTOCOL_UDP: u8 = 17;
/// The hop limit this lane writes, a reasonable default rather than a value a proxy asks for.
pub const HOP_LIMIT: u8 = 64;
/// The largest datagram this lane will build: a UDP length field is sixteen bits, so a longer one cannot be named in a header.
pub const MAX_DATAGRAM: usize = u16::MAX as usize - UDP_HEADER;

/// Walks an IPv4 header, or `None` when it is not one: the first nibble is the version, the second the header length in 32-bit words, and a header needing options or a total length past what arrived is refused because the payload would be read out of something else.
pub fn ipv4_head(packet: &[u8]) -> Option<(Ipv4Head, &[u8])> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header = usize::from(first & 0x0f) * 4;
    if header != IPV4_HEADER {
        return None;
    }
    let length = u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]);
    let total = usize::from(length);
    if total < header || total > packet.len() {
        return None;
    }
    let mut source = [0u8; 4];
    let mut destination = [0u8; 4];
    source.copy_from_slice(packet.get(12..16)?);
    destination.copy_from_slice(packet.get(16..20)?);
    Some((
        Ipv4Head {
            length,
            protocol: *packet.get(9)?,
            hop: *packet.get(8)?,
            source,
            destination,
        },
        &packet[header..total],
    ))
}

/// Walks an IPv6 header, or `None` when it is not one.
pub fn ipv6_head(packet: &[u8]) -> Option<(Ipv6Head, &[u8])> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let length = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]);
    if IPV6_HEADER + usize::from(length) > packet.len() {
        return None;
    }
    let mut source = [0u8; 16];
    let mut destination = [0u8; 16];
    source.copy_from_slice(packet.get(8..24)?);
    destination.copy_from_slice(packet.get(24..40)?);
    Some((
        Ipv6Head {
            length,
            next_header: *packet.get(6)?,
            hop: *packet.get(7)?,
            source,
            destination,
        },
        &packet[IPV6_HEADER..IPV6_HEADER + usize::from(length)],
    ))
}

/// One UDP header and its payload, read in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHead {
    pub source_port: u16,
    pub destination_port: u16,
    /// The UDP length, which includes this header and must match the body.
    pub length: u16,
}

/// Walks a UDP header, or `None` when it is not one: the length field names the header plus the payload, so a body that disagrees with it is refused.
pub fn udp_head(body: &[u8]) -> Option<(UdpHead, &[u8])> {
    let source_port = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
    let destination_port = u16::from_be_bytes([*body.get(2)?, *body.get(3)?]);
    let length = u16::from_be_bytes([*body.get(4)?, *body.get(5)?]);
    if usize::from(length) != body.len() {
        return None;
    }
    Some((
        UdpHead {
            source_port,
            destination_port,
            length,
        },
        body.get(UDP_HEADER..)?,
    ))
}

/// The octets one block holds: two octets per word, sixteen words, and a multiple of two so every octet keeps the parity of its own offset.
const BLOCK: usize = 32;

/// The one's-complement sum of bytes read as 16-bit big-endian words, the last zero-padded on an odd run.
///
/// A big-endian word is `high * 256 + low`, so the sum over a whole run is `256 * (even octets) + (odd octets)`: two byte sums and no per-word arithmetic at all. `vpsadbw` is exactly a byte sum — eight octets into one 64-bit lane, sixteen lanes a block — so a block costs one load, one shift that moves the odd octets into lanes a sum can see, two sums and two accumulating adds, and the whole run ends in the one subtraction `256 * all - 255 * odd`. Every term is an exact integer, so no octet is rounded away and the folded number this returns is the definition's own residue: an octet at an odd offset is the high half of its word and nothing else moves. The kernel's unwrapped accumulator is the word sum itself, while an aligned eight-octet lane folds to `hi32 + lo32`, which is congruent to its four words and about twenty-eight thousand times larger, so the fold and not the accumulator is what both sides share — `the_vector_block_sum_is_the_walk_sum` pins the kernel's magnitude against sixteen-bit words and its residue against the walk. Witnessed by `the_word_sum_costs_the_words_it_reads` against `the_serial_word_sum_costs_the_same_answer` over the same buffer, and by `the_parallel_accumulators_hold_the_single_accumulator_word_sum`, `word_sum_is_the_word_at_a_time_sum_at_every_tail` and `the_word_fold_is_the_byte_at_a_time_sum` at every length and tail.
fn word_sum(bytes: &[u8]) -> u32 {
    // The split is on a block boundary, so the octets the tail reads are at the offsets they held in the whole run.
    let wide = bytes.len() & !(BLOCK - 1);
    let acc = block_sum(&bytes[..wide]) + lane_sum(&bytes[wide..]);
    // Fold the 64-bit residue into a 32-bit one (`2^32` is again congruent to `1`), then drain the carries twice: two steps bound any run past `0xffff` and callers fold once more.
    let mut sum = (acc >> 32) + (acc & 0xffff_ffff);
    sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    sum as u32
}

/// The words of a run of whole blocks, as an exact integer: the vector kernel where AVX2 answers, the baseline vector width everywhere else.
fn block_sum(bytes: &[u8]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: the probe above is the guard, and the kernel reads only whole blocks of a run that is a whole number of them.
            return unsafe { avx2_block_sum(bytes) };
        }
        // SAFETY: SSE2 is part of the x86_64 baseline, and the kernel reads only whole sixteen-byte lanes of a run that is a whole number of them.
        return unsafe { sse2_block_sum(bytes) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is part of the aarch64 baseline, and the kernel reads only whole sixteen-byte lanes of a run that is a whole number of them.
        return unsafe { neon_block_sum(bytes) };
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    lane_sum(bytes)
}

/// The same run as two byte sums: `256 * every octet - 255 * the odd octets` is the word sum, because an odd octet is its word's high half.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_block_sum(bytes: &[u8]) -> u64 {
    use core::arch::x86_64::{
        __m256i, _mm256_add_epi64, _mm256_loadu_si256, _mm256_sad_epu8, _mm256_setzero_si256,
        _mm256_srli_epi16, _mm256_storeu_si256,
    };
    let zero = _mm256_setzero_si256();
    let (mut every, mut odd) = (_mm256_setzero_si256(), _mm256_setzero_si256());
    let mut at = 0usize;
    while at + BLOCK <= bytes.len() {
        let block: __m256i = unsafe { _mm256_loadu_si256(bytes.as_ptr().add(at).cast()) };
        every = _mm256_add_epi64(every, _mm256_sad_epu8(block, zero));
        // Byte `2k + 1` of each word moves into byte `2k`, so the same sum now answers the odd octets.
        let high = _mm256_srli_epi16(block, 8);
        odd = _mm256_add_epi64(odd, _mm256_sad_epu8(high, zero));
        at += BLOCK;
    }
    let mut every_lanes = [0u64; 4];
    let mut odd_lanes = [0u64; 4];
    unsafe { _mm256_storeu_si256(every_lanes.as_mut_ptr().cast(), every) };
    unsafe { _mm256_storeu_si256(odd_lanes.as_mut_ptr().cast(), odd) };
    let sum: u64 = every_lanes.iter().sum();
    let high: u64 = odd_lanes.iter().sum();
    sum * 256 - high * 255
}

/// The same two byte sums in the x86_64 baseline: `psadbw` on a sixteen-byte lane, two lanes accumulated, so a block costs the same one load, shift, two sums and two adds as the wide kernel over half the span.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn sse2_block_sum(bytes: &[u8]) -> u64 {
    use core::arch::x86_64::{
        __m128i, _mm_add_epi64, _mm_loadu_si128, _mm_sad_epu8, _mm_setzero_si128, _mm_srli_epi16,
        _mm_storeu_si128,
    };
    let zero = _mm_setzero_si128();
    let (mut every, mut odd) = (_mm_setzero_si128(), _mm_setzero_si128());
    let mut at = 0usize;
    while at + 16 <= bytes.len() {
        let block: __m128i = unsafe { _mm_loadu_si128(bytes.as_ptr().add(at).cast()) };
        every = _mm_add_epi64(every, _mm_sad_epu8(block, zero));
        let high = _mm_srli_epi16(block, 8);
        odd = _mm_add_epi64(odd, _mm_sad_epu8(high, zero));
        at += 16;
    }
    let mut every_lanes = [0u64; 2];
    let mut odd_lanes = [0u64; 2];
    unsafe { _mm_storeu_si128(every_lanes.as_mut_ptr().cast(), every) };
    unsafe { _mm_storeu_si128(odd_lanes.as_mut_ptr().cast(), odd) };
    let sum: u64 = every_lanes.iter().sum();
    let high: u64 = odd_lanes.iter().sum();
    sum * 256 - high * 255
}

/// The same two byte sums in NEON, which is mandatory on aarch64: `vpadal` folds the sixteen octets to two 64-bit lanes in three widening adds, and the shift moves each odd octet into its own lane for the second sum.
#[cfg(target_arch = "aarch64")]
unsafe fn neon_block_sum(bytes: &[u8]) -> u64 {
    use core::arch::aarch64::{
        uint64x2_t, vaddvq_u64, vdupq_n_u64, vld1q_u8, vpadalq_u32, vpaddlq_u16, vpaddlq_u8,
        vreinterpretq_u8_u16, vshrq_n_u16,
    };
    let (mut every, mut odd): (uint64x2_t, uint64x2_t) = (vdupq_n_u64(0), vdupq_n_u64(0));
    let mut at = 0usize;
    while at + 16 <= bytes.len() {
        let block = unsafe { vld1q_u8(bytes.as_ptr().add(at)) };
        every = vpadalq_u32(every, vpaddlq_u16(vpaddlq_u8(block)));
        let high = vreinterpretq_u8_u16(vshrq_n_u16::<8>(block));
        odd = vpadalq_u32(odd, vpaddlq_u16(vpaddlq_u8(high)));
        at += 16;
    }
    vaddvq_u64(every) * 256 - vaddvq_u64(odd) * 255
}

/// The same sum eight octets a lane, which answers both the run past the last whole block and the whole run where no kernel does: an eight-octet lane folded the way `2^32 = 1 mod 0xffff` allows, then the last three, two or one octets as words.
fn lane_sum(bytes: &[u8]) -> u64 {
    let (lanes, rem) = bytes.as_chunks::<8>();
    let mut acc = 0u64;
    for lane in lanes {
        let word = u64::from_be_bytes(*lane);
        acc += (word >> 32) + (word & 0xffff_ffff);
    }
    // Every group taken here is even so pairs still begin on an even byte, and a lone trailing byte is the high half of a zero-padded word.
    let mut at = 0usize;
    if rem.len() >= 4 {
        acc += u64::from(u32::from_be_bytes(rem[..4].try_into().expect("four bytes")));
        at = 4;
    }
    if rem.len() - at >= 2 {
        acc += u64::from(u16::from_be_bytes(
            rem[at..at + 2].try_into().expect("two bytes"),
        ));
        at += 2;
    }
    if rem.len() - at == 1 {
        acc += u64::from(rem[at]) << 8;
    }
    acc
}

/// The fold a checksum ends with: add the halves until nothing is left to carry, at most two steps for a 32-bit accumulator.
fn fold(sum: u32) -> u16 {
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The one's complement of a byte run, which is what a checksum field holds.
pub fn checksum(bytes: &[u8]) -> u16 {
    !fold(word_sum(bytes))
}

/// The IPv4 header checksum of a header this lane builds: the complement of the sum over the header itself, which a receiver adds its own copy of the header into to read all ones.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    !fold(word_sum(header))
}

/// The TCP checksum of a segment this lane builds (RFC 793), summed without materialising the twelve-byte pseudo-header: the addresses contribute their word runs, the protocol (6) and the segment length their own words, and the segment — header with its checksum field read as zero plus payload — is summed where it already lies. The same one's-complement sum the materialised pseudo-header and a copy of the whole segment reached, so the bytes on the device are unchanged and the throwaway vector and its copy are gone.
pub fn tcp_checksum(source: &[u8], destination: &[u8], segment: &[u8]) -> u16 {
    const TCP_PROTOCOL: u32 = 6;
    let sum = word_sum(source) + word_sum(destination) + (segment.len() as u32) + TCP_PROTOCOL;
    let sum = (sum & 0xffff) + (sum >> 16);
    !fold(sum + word_sum(segment))
}

/// The pseudo-header a UDP checksum covers (RFC 768, RFC 8200 §8.1) summed without writing it: a one's-complement sum is position-independent, so the addresses contribute their word runs, the length its value (sixteen bits by construction, IPv6's wider field adding an unchanged zero word) and the protocol a lone word whose high half is zero — the same words the materialised header held, so both versions agree with no branch.
fn pseudo_sum(source: &[u8], destination: &[u8], payload: usize) -> u32 {
    let length = (UDP_HEADER + payload) as u32;
    let sum = word_sum(source) + word_sum(destination) + length + u32::from(PROTOCOL_UDP);
    (sum & 0xffff) + (sum >> 16)
}

/// The UDP checksum of a datagram this lane builds: header fields, pseudo-header and payload summed with the checksum field read as zero, complemented — and a zero answer is never written, because a receiver reads it as "not computed", so the protocol's illegal value goes instead and verifies at either version.
pub fn udp_checksum(
    source: &[u8],
    destination: &[u8],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> u16 {
    let mut sum =
        u32::from(source_port) + u32::from(destination_port) + (UDP_HEADER + payload.len()) as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum += pseudo_sum(source, destination, payload.len());
    sum = (sum & 0xffff) + (sum >> 16);
    sum += word_sum(payload);
    let answer = !fold(sum);
    if answer == 0 {
        0xffff
    } else {
        answer
    }
}

/// The smallest MTU each family may name, RFC 791 and RFC 8200 §5.
const IPV4_MIN_MTU: usize = 68;
const IPV6_MIN_MTU: usize = 1280;
const ICMP_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;
const ICMP_DESTINATION_UNREACHABLE: u8 = 3;
const ICMP_FRAGMENTATION_NEEDED: u8 = 4;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;

/// The ICMP Packet Too Big a narrow tunnel answers a packet too wide to carry: the version's error, this tunnel's MTU, and the start of the packet that did not fit, addressed back from where it came. `None` when the packet is not a whole IP header or the MTU is below the family's floor, which is a tunnel the reference refuses too.
#[must_use]
pub fn icmp_too_large(packet: &[u8], mtu: usize) -> Option<Vec<u8>> {
    let mut answer = Vec::new();
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < IPV4_HEADER || mtu < IPV4_MIN_MTU {
                return None;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            let data = &packet[..packet.len().min(header.max(IPV4_HEADER) + 8)];
            let mtu = u16::try_from(mtu).ok()?;
            let mut message = vec![
                ICMP_DESTINATION_UNREACHABLE,
                ICMP_FRAGMENTATION_NEEDED,
                0,
                0,
                0,
                0,
                (mtu >> 8) as u8,
                mtu as u8,
            ];
            message.extend_from_slice(data);
            let sum = checksum(&message);
            message[2..4].copy_from_slice(&sum.to_be_bytes());
            let mut head = [0u8; IPV4_HEADER];
            head[0] = 0x45;
            let total = u16::try_from(IPV4_HEADER + message.len()).ok()?;
            head[2..4].copy_from_slice(&total.to_be_bytes());
            head[8] = HOP_LIMIT;
            head[9] = ICMP_PROTOCOL;
            head[12..16].copy_from_slice(&packet[16..20]);
            head[16..20].copy_from_slice(&packet[12..16]);
            let sum = ipv4_checksum(&head);
            head[10..12].copy_from_slice(&sum.to_be_bytes());
            answer.extend_from_slice(&head);
            answer.extend_from_slice(&message);
        }
        6 => {
            if packet.len() < IPV6_HEADER || mtu < IPV6_MIN_MTU {
                return None;
            }
            let data = &packet[..packet.len().min(1232)];
            let mtu = u32::try_from(mtu).ok()?;
            let mut message = vec![ICMPV6_PACKET_TOO_BIG, 0, 0, 0];
            message.extend_from_slice(&mtu.to_be_bytes());
            message.extend_from_slice(data);
            let sum = pseudo_checksum(&packet[24..40], &packet[8..24], ICMPV6_PROTOCOL, &message);
            message[2..4].copy_from_slice(&sum.to_be_bytes());
            let mut head = [0u8; IPV6_HEADER];
            head[0] = 0x60;
            let payload = u16::try_from(message.len()).ok()?;
            head[4..6].copy_from_slice(&payload.to_be_bytes());
            head[6] = ICMPV6_PROTOCOL;
            head[7] = HOP_LIMIT;
            head[8..24].copy_from_slice(&packet[24..40]);
            head[24..40].copy_from_slice(&packet[8..24]);
            answer.extend_from_slice(&head);
            answer.extend_from_slice(&message);
        }
        _ => return None,
    }
    Some(answer)
}

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Answer an ICMP echo request that reached a device's own address: its message with the
/// type flipped and the checksum recomputed, wrapped in an IP header whose addresses are
/// the request's swapped, appended to the caller's reused `out` so a reserved `WireGuard`
/// header survives and a ping storm allocates nothing per reply. A message that is not a
/// well-formed echo request is refused and `out` is left untouched.
pub fn icmp_echo_reply(
    source: IpAddr,
    destination: IpAddr,
    message: &[u8],
    out: &mut Vec<u8>,
) -> bool {
    if message.len() < 8 || message[1] != 0 {
        return false;
    }
    let echo = match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => message[0] == ICMP_ECHO_REQUEST,
        (IpAddr::V6(_), IpAddr::V6(_)) => message[0] == ICMPV6_ECHO_REQUEST,
        _ => false,
    };
    if !echo {
        return false;
    }
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let Ok(total) = u16::try_from(IPV4_HEADER + message.len()) else {
                return false;
            };
            let at = out.len();
            out.reserve(usize::from(total));
            let mut head = [0u8; IPV4_HEADER];
            head[0] = 0x45;
            head[2..4].copy_from_slice(&total.to_be_bytes());
            head[6] = 0x40;
            head[8] = HOP_LIMIT;
            head[9] = ICMP_PROTOCOL;
            head[12..16].copy_from_slice(&destination.octets());
            head[16..20].copy_from_slice(&source.octets());
            let sum = ipv4_checksum(&head);
            head[10..12].copy_from_slice(&sum.to_be_bytes());
            out.extend_from_slice(&head);
            out.extend_from_slice(message);
            out[at + IPV4_HEADER] = ICMP_ECHO_REPLY;
            out[at + IPV4_HEADER + 2..at + IPV4_HEADER + 4].fill(0);
            let sum = checksum(&out[at + IPV4_HEADER..]);
            out[at + IPV4_HEADER + 2..at + IPV4_HEADER + 4].copy_from_slice(&sum.to_be_bytes());
            true
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let Ok(payload) = u16::try_from(message.len()) else {
                return false;
            };
            let at = out.len();
            out.reserve(IPV6_HEADER + message.len());
            let mut head = [0u8; IPV6_HEADER];
            head[0] = 0x60;
            head[4..6].copy_from_slice(&payload.to_be_bytes());
            head[6] = ICMPV6_PROTOCOL;
            head[7] = HOP_LIMIT;
            head[8..24].copy_from_slice(&destination.octets());
            head[24..40].copy_from_slice(&source.octets());
            out.extend_from_slice(&head);
            out.extend_from_slice(message);
            out[at + IPV6_HEADER] = ICMPV6_ECHO_REPLY;
            out[at + IPV6_HEADER + 2..at + IPV6_HEADER + 4].fill(0);
            let sum = pseudo_checksum(
                &destination.octets(),
                &source.octets(),
                ICMPV6_PROTOCOL,
                &out[at + IPV6_HEADER..],
            );
            out[at + IPV6_HEADER + 2..at + IPV6_HEADER + 4].copy_from_slice(&sum.to_be_bytes());
            true
        }
        _ => false,
    }
}

/// A checksum over a pseudo-header plus a payload, summed without writing the pseudo-header down.
fn pseudo_checksum(source: &[u8], destination: &[u8], protocol: u8, payload: &[u8]) -> u16 {
    let sum = word_sum(source) + word_sum(destination) + payload.len() as u32 + u32::from(protocol);
    let sum = (sum & 0xffff) + (sum >> 16);
    !fold(sum + word_sum(payload))
}

/// Whether an incoming datagram's checksum verifies: pseudo-header, the whole UDP header including its checksum field, and payload must sum to all ones; over IPv4 a zero field means "not computed" and is accepted, over IPv6 the field is mandatory and a zero is refused.
fn checksum_holds(
    source: &[u8],
    destination: &[u8],
    datagram: &[u8],
    optional: bool,
) -> Option<bool> {
    let field = u16::from_be_bytes([*datagram.get(6)?, *datagram.get(7)?]);
    if field == 0 && optional {
        return Some(true);
    }
    let mut sum = pseudo_sum(source, destination, datagram.len() - UDP_HEADER);
    sum = (sum & 0xffff) + (sum >> 16);
    sum += word_sum(datagram);
    Some(fold(sum) == 0xffff)
}

/// The headers one outgoing UDP datagram needs, in the order they are written: a reply shape — source the assigned tunnel address, destination the target, payload the caller's bytes — so everything else is derived and this is all a caller names.
#[derive(Debug, Clone, Copy)]
pub struct UdpDatagram<'a> {
    /// The tunnel's own address, as the proxy assigned it.
    pub source: &'a [u8],
    pub destination: &'a [u8],
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

/// Whether a datagram of this payload can be named at all: a UDP length field is sixteen bits, so one past it cannot be written into a header.
#[must_use]
pub fn datagram_fits(payload: usize) -> bool {
    payload <= MAX_DATAGRAM
}

/// Writes one UDP datagram into `out` — IP header, UDP header, payload — taking the version from the tunnel address's width, so a v4-assigned lane writes v4 packets and a v6-assigned one v6, never mixed.
pub fn udp_datagram(datagram: &UdpDatagram<'_>, out: &mut Vec<u8>) -> bool {
    if !datagram_fits(datagram.payload.len()) {
        return false;
    }
    let payload = UDP_HEADER + datagram.payload.len();
    if datagram.source.len() == 4 {
        let mut header = [0u8; IPV4_HEADER];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&((IPV4_HEADER + payload) as u16).to_be_bytes());
        header[8] = HOP_LIMIT;
        header[9] = PROTOCOL_UDP;
        header[12..16].copy_from_slice(datagram.source);
        header[16..20].copy_from_slice(datagram.destination);
        let sum = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(&header);
    } else {
        let mut header = [0u8; IPV6_HEADER];
        header[0] = 0x60;
        header[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        header[6] = PROTOCOL_UDP;
        header[7] = HOP_LIMIT;
        header[8..24].copy_from_slice(datagram.source);
        header[24..40].copy_from_slice(datagram.destination);
        out.extend_from_slice(&header);
    }
    let sum = udp_checksum(
        datagram.source,
        datagram.destination,
        datagram.source_port,
        datagram.destination_port,
        datagram.payload,
    );
    let mut udp = [0u8; UDP_HEADER];
    udp[0..2].copy_from_slice(&datagram.source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&datagram.destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    out.extend_from_slice(&udp);
    out.extend_from_slice(datagram.payload);
    true
}

/// One UDP datagram read out of an IP packet with both of its ends borrowed from the packet: the header fields sit at fixed offsets, so walking a datagram costs no copy at all.
#[derive(Debug, Clone, Copy)]
pub struct Datagram<'a> {
    pub source: &'a [u8],
    pub destination: &'a [u8],
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
    /// Whether the packet's checksum held, which an IPv4 peer is allowed to have left out and an IPv6 peer is not.
    pub verified: bool,
}

/// Walks a UDP datagram out of an IP packet, or `None` when the packet is not a UDP datagram this lane can read.
pub fn udp_from_packet(packet: &[u8]) -> Option<Datagram<'_>> {
    let (source, destination, body, optional) = match packet.first()? >> 4 {
        4 => {
            let (head, body) = ipv4_head(packet)?;
            if head.protocol != PROTOCOL_UDP {
                return None;
            }
            (&packet[12..16], &packet[16..20], body, true)
        }
        6 => {
            let (head, body) = ipv6_head(packet)?;
            if head.next_header != PROTOCOL_UDP {
                return None;
            }
            (&packet[8..24], &packet[24..40], body, false)
        }
        _ => return None,
    };
    let (udp, payload) = udp_head(body)?;
    let verified = checksum_holds(source, destination, body, optional)?;
    Some(Datagram {
        source,
        destination,
        source_port: udp.source_port,
        destination_port: udp.destination_port,
        payload,
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A datagram this lane builds, or the panic a bool answer owes.
    trait DatagramBuilt {
        fn expect_datagram(self);
        fn expect_refused(self);
    }
    impl DatagramBuilt for bool {
        fn expect_datagram(self) {
            assert!(self, "the datagram was built");
        }
        fn expect_refused(self) {
            assert!(!self, "the datagram was refused");
        }
    }

    /// One assignment, byte for byte the way a proxy writes it: request id, a version, an address, a prefix length.
    fn assign(request_id: u64, version: u8, address: &[u8], prefix: u8) -> Option<Vec<Assigned>> {
        let mut body = Vec::new();
        quic_varint(&mut body, request_id);
        body.push(version);
        body.extend_from_slice(address);
        body.push(prefix);
        let mut into = Vec::new();
        address_assign(&body, &mut into).map(|()| into)
    }

    /// One request, byte for byte the way a client writes it.
    fn request(id: u64, version: u8, address: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        address_request(id, version, address, &mut out);
        out
    }

    const V4: [u8; 4] = [0, 0, 0, 0];
    const V6: [u8; 16] = [0; 16];

    /// A client asks for both families in one capsule: a proxy replaces the peer's allowed sources with each answer, so two capsules would leave the first family's replies refused.
    #[test]
    fn one_request_capsule_names_every_family_a_client_wants() {
        let mut out = Vec::new();
        address_requests(&[(1, 4, &V4), (2, 6, &V6)], &mut out);
        let (end, capsule) = capsule_split(&out).expect("a capsule");
        assert_eq!(end, out.len(), "both families are in one capsule");
        let Capsule::AddressRequest(body) = capsule else {
            panic!("a request");
        };
        assert_eq!(body.len(), 7 + 19);
        assert_eq!(request(1, 4, &V4).len(), 9, "one family keeps its bytes");
    }

    /// The all-zeros prefix at full length is how a proxy refuses, and the reader has to say so rather than hand the lane a tunnel address of zero.
    #[test]
    fn a_refused_assignment_is_named_and_a_granted_one_is_not() {
        assert!(assign(1, 4, &V4, 32).expect("a refusal parses")[0].refused());
        assert!(assign(2, 6, &V6, 128).expect("a refusal parses")[0].refused());
        let granted = assign(1, 4, &[192, 0, 2, 7], 32).expect("a grant parses");
        assert!(!granted[0].refused(), "a real address is a grant");
        assert_eq!(granted[0].bytes(), &[192, 0, 2, 7]);
        assert_eq!(
            granted[0].request_id, 1,
            "it answers the request it was asked with"
        );
    }

    /// Host bits above an assignment's prefix are the tunnel's own address, so they read as granted: a proxy hands out a `/64` with an address inside it, and refusing that would leave the lane with no address; a prefix past the address is still refused at either version.
    #[test]
    fn the_host_bits_of_an_assignment_are_the_tunnels_own_address() {
        let granted = assign(
            1,
            6,
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        )
        .expect("a /64 grant parses");
        assert_eq!(granted.len(), 1);
        assert!(
            !granted[0].refused(),
            "an address inside its prefix is a grant"
        );
        assert_eq!(granted[0].prefix, 64);
        assert_eq!(granted[0].bytes().last(), Some(&1));
        assert!(assign(1, 4, &[10, 0, 0, 1], 33).is_none(), "33 bits of v4");
        assert!(
            assign(
                1,
                6,
                &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                129
            )
            .is_none(),
            "129 bits of v6"
        );
        assert!(
            assign(1, 5, &[0; 16], 64).is_none(),
            "version 5 does not exist"
        );
    }

    /// This lane's request carries zeroed host bits by construction — the all-zeros address at full length means "any address you like" — and is written in the shape an assignment is read in, so both directions agree without a second codec.
    #[test]
    fn a_request_is_the_shape_an_assignment_is_read_in() {
        assert_eq!(request(1, 4, &V4), [2, 7, 1, 4, 0, 0, 0, 0, 32]);
        let mut wide = vec![2, 19, 2, 6];
        wide.extend_from_slice(&V6);
        wide.push(128);
        assert_eq!(request(2, 6, &V6), wide);
    }

    /// The routes a proxy advertises read back as first, last and protocol, and a protocol of zero means every protocol.
    #[test]
    fn an_advertised_route_names_its_range_and_its_protocol() {
        let mut body = Vec::new();
        body.push(4);
        body.extend_from_slice(&[192, 0, 2, 0]);
        body.extend_from_slice(&[192, 0, 2, 255]);
        body.push(0);
        let mut routes = Vec::new();
        route_advert(&body, &mut routes).expect("parses");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].first[..4], [192, 0, 2, 0]);
        assert_eq!(routes[0].last[..4], [192, 0, 2, 255]);
        assert_eq!(routes[0].protocol, 0, "zero is every protocol");
        assert_eq!(
            route_advert(&[5, 0, 0], &mut routes),
            None,
            "a version with no address width is refused"
        );
    }

    /// One grant as a proxy would build it, its address padded to sixteen bytes with only the version's width significant.
    fn assigned(request_id: u64, version: u8, address: &[u8], prefix: u8) -> Assigned {
        let mut bytes = [0u8; 16];
        bytes[..address.len()].copy_from_slice(address);
        Assigned {
            request_id,
            version,
            address: bytes,
            prefix,
        }
    }

    /// One route as a proxy would build it.
    fn route(version: u8, first: &[u8], last: &[u8], protocol: u8) -> Route {
        let mut f = [0u8; 16];
        let mut l = [0u8; 16];
        f[..first.len()].copy_from_slice(first);
        l[..last.len()].copy_from_slice(last);
        Route {
            first: f,
            last: l,
            version,
            protocol,
        }
    }

    /// The assign a proxy writes is the assign the lane reads: encode one whole capsule, split it, read the body — the same fields come back at every boundary the proxy answers with, and the bytes match the shape the reader already accepts, so the writer is proven inverse to it and not merely round-trippable against itself.
    #[test]
    fn the_assign_a_proxy_writes_is_the_assign_the_lane_reads() {
        let read_back = |entries: &[Assigned]| -> Vec<Assigned> {
            let mut capsule = Vec::new();
            address_assign_encode(entries, &mut capsule);
            let (used, kind) = capsule_split(&capsule).expect("a whole capsule");
            assert_eq!(used, capsule.len(), "the capsule is exactly whole");
            let Capsule::AddressAssign(body) = kind else {
                panic!("an assignment capsule")
            };
            let mut into = Vec::new();
            address_assign(body, &mut into).expect("reads back");
            into
        };
        let one = [assigned(1, 4, &[198, 51, 100, 9], 32)];
        assert_eq!(read_back(&one), one.to_vec());
        let mut wire = Vec::new();
        address_assign_encode(&one, &mut wire);
        assert_eq!(
            wire,
            [0x01, 0x07, 0x01, 0x04, 198, 51, 100, 9, 32],
            "byte-for-byte the assignment the CONNECT-IP edge hand-rolled"
        );
        let wide64 = [assigned(
            2,
            6,
            &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            64,
        )];
        assert_eq!(read_back(&wide64), wide64.to_vec(), "host bits above a /64");
        let refused = [assigned(3, 4, &[0, 0, 0, 0], 32)];
        assert!(
            read_back(&refused)[0].refused(),
            "the all-zeros grant still reads as a refusal"
        );
        let big_id = [assigned(
            1_000_000,
            6,
            &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            128,
        )];
        assert_eq!(read_back(&big_id), big_id.to_vec(), "a two-byte request id");
        let both = [
            assigned(1, 4, &[10, 0, 0, 1], 24),
            assigned(
                2,
                6,
                &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
                64,
            ),
        ];
        assert_eq!(read_back(&both), both.to_vec(), "two grants in one capsule");
        let mut empty = Vec::new();
        address_assign_encode(&[], &mut empty);
        assert_eq!(empty, [0x01, 0x00], "an empty capsule names a zero body");
        assert_eq!(read_back(&[]), [] as [Assigned; 0]);
    }

    /// The route advert a proxy writes is the route advert the lane reads, at both versions, on UDP and every-protocol limits, and with the bytes the reader already parses.
    #[test]
    fn the_route_advert_a_proxy_writes_is_the_route_advert_the_lane_reads() {
        let read_back = |routes: &[Route]| -> Vec<Route> {
            let mut capsule = Vec::new();
            route_advert_encode(routes, &mut capsule);
            let (used, kind) = capsule_split(&capsule).expect("a whole capsule");
            assert_eq!(used, capsule.len(), "the capsule is exactly whole");
            let Capsule::RouteAdvert(body) = kind else {
                panic!("a route capsule")
            };
            let mut into = Vec::new();
            route_advert(body, &mut into).expect("reads back");
            into
        };
        let v4 = [route(4, &[192, 0, 2, 0], &[192, 0, 2, 255], 0)];
        assert_eq!(read_back(&v4), v4.to_vec());
        let mut wire = Vec::new();
        route_advert_encode(&v4, &mut wire);
        assert_eq!(
            wire,
            [0x03, 0x0a, 4, 192, 0, 2, 0, 192, 0, 2, 255, 0],
            "byte-for-byte the route the reader already walks"
        );
        let v6 = [route(
            6,
            &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255],
            17,
        )];
        assert_eq!(read_back(&v6), v6.to_vec(), "a UDP-only v6 range");
        let both = [
            route(4, &[10, 0, 0, 0], &[10, 0, 0, 255], 0),
            route(
                6,
                &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                17,
            ),
        ];
        assert_eq!(
            read_back(&both),
            both.to_vec(),
            "a v4 and a v6 in one capsule"
        );
        let mut empty = Vec::new();
        route_advert_encode(&[], &mut empty);
        assert_eq!(empty, [0x03, 0x00], "an empty advert names a zero body");
        assert_eq!(read_back(&[]), [] as [Route; 0]);
    }

    /// A capsule this lane does not read is answered whole and stepping over it is the caller's, so a proxy advertising an extension must not cost the tunnel its packets.
    #[test]
    fn a_capsule_this_lane_does_not_read_is_answered_whole() {
        let mut buf = Vec::new();
        quic_varint(&mut buf, 0x1c);
        quic_varint(&mut buf, 3);
        buf.extend_from_slice(b"abc");
        packet_encode(b"\x45\x00", &mut buf);
        let (used, capsule) = capsule_split(&buf).expect("a capsule");
        assert_eq!(used, 5, "the first capsule is the answer");
        assert_eq!(capsule, Capsule::Other(0x1c));
        let (used, capsule) = capsule_split(&buf[used..]).expect("then the datagram");
        // The context byte is stripped, so what the caller reads is the packet.
        assert_eq!(capsule, Capsule::Datagram(&buf[8..]));
        assert_eq!(used, buf.len() - 5);
        assert_eq!(capsule_split(&buf[..2]), None, "half a capsule");
        assert_eq!(capsule_split(b""), None);
    }

    /// WARP's HTTP/2 carrier drops the context byte, so a bare capsule is the
    /// packet behind a type and length and nothing else.
    #[test]
    fn a_bare_datagram_has_no_context() {
        let mut buf = Vec::new();
        packet_encode_bare(b"\x45\x00\x00\x14", &mut buf);
        assert_eq!(buf, [0x00, 0x04, 0x45, 0x00, 0x00, 0x14]);
        let (used, capsule) = capsule_split_bare(&buf).expect("a capsule");
        assert_eq!(used, buf.len());
        assert_eq!(capsule, Capsule::Datagram(b"\x45\x00\x00\x14"));
    }

    /// The IP/UDP header walk reads a datagram this lane builds without a copy, at both versions, and verifies what it read.
    #[test]
    fn a_datagram_built_is_a_datagram_walked() {
        let v6 = |head: &[u8]| {
            let mut wide = vec![0u8; 16];
            wide[..head.len()].copy_from_slice(head);
            wide
        };
        for (source, destination) in [
            (vec![192, 0, 2, 7], vec![203, 0, 113, 9]),
            (v6(&[0x20, 1]), v6(&[0x20, 2])),
        ] {
            let mut packet = Vec::new();
            udp_datagram(
                &UdpDatagram {
                    source: &source,
                    destination: &destination,
                    source_port: 1_000,
                    destination_port: 2_000,
                    payload: b"hello ip",
                },
                &mut packet,
            )
            .expect_datagram();
            let read = udp_from_packet(&packet).expect("walks");
            assert_eq!(read.source, source.as_slice());
            assert_eq!(read.destination, destination.as_slice());
            assert_eq!(read.source_port, 1_000);
            assert_eq!(read.destination_port, 2_000);
            assert_eq!(read.payload, b"hello ip");
            assert!(read.verified, "and its checksum holds");
        }
    }

    /// A datagram past the length field is refused rather than truncated.
    #[test]
    fn a_datagram_past_the_length_field_is_refused() {
        assert!(!datagram_fits(MAX_DATAGRAM + 1));
        let long = vec![0u8; MAX_DATAGRAM + 1];
        let mut out = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[10, 0, 0, 1],
                destination: &[10, 0, 0, 2],
                source_port: 1,
                destination_port: 2,
                payload: &long,
            },
            &mut out,
        )
        .expect_refused();
        assert!(out.is_empty(), "and nothing was written");
    }

    /// The IPv4 header checksum is the complement of the sum over the header, which a receiver adds its own copy of the header into to read all ones.
    #[test]
    fn an_ipv4_header_checksum_verifies_against_itself() {
        let mut header = [0u8; IPV4_HEADER];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&28u16.to_be_bytes());
        header[8] = HOP_LIMIT;
        header[9] = PROTOCOL_UDP;
        header[12..16].copy_from_slice(&[192, 0, 2, 7]);
        header[16..20].copy_from_slice(&[203, 0, 113, 9]);
        let written = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&written.to_be_bytes());
        assert_eq!(fold(word_sum(&header)), 0xffff);
    }

    /// The word sum as it stood: four accumulators over eight-octet lanes, a word at a time. Kept verbatim as the second side of the probe pair, so one `ops.yml` run prices both over the same buffer and the two folds cannot differ.
    fn word_sum_serial(bytes: &[u8]) -> u32 {
        let (lanes, rem) = bytes.as_chunks::<8>();
        let (quads, singles) = lanes.as_chunks::<4>();
        let (mut a0, mut a1, mut a2, mut a3) = (0u64, 0u64, 0u64, 0u64);
        for quad in quads {
            let w0 = u64::from_be_bytes(quad[0]);
            let w1 = u64::from_be_bytes(quad[1]);
            let w2 = u64::from_be_bytes(quad[2]);
            let w3 = u64::from_be_bytes(quad[3]);
            a0 += (w0 >> 32) + (w0 & 0xffff_ffff);
            a1 += (w1 >> 32) + (w1 & 0xffff_ffff);
            a2 += (w2 >> 32) + (w2 & 0xffff_ffff);
            a3 += (w3 >> 32) + (w3 & 0xffff_ffff);
        }
        for lane in singles {
            let word = u64::from_be_bytes(*lane);
            a0 += (word >> 32) + (word & 0xffff_ffff);
        }
        let mut acc = (a0 + a1) + (a2 + a3);
        let mut at = 0usize;
        if rem.len() - at >= 4 {
            acc += u64::from(u32::from_be_bytes(
                rem[at..at + 4].try_into().expect("four bytes"),
            ));
            at += 4;
        }
        if rem.len() - at >= 2 {
            acc += u64::from(u16::from_be_bytes(
                rem[at..at + 2].try_into().expect("two bytes"),
            ));
            at += 2;
        }
        if rem.len() - at == 1 {
            acc += u64::from(rem[at]) << 8;
        }
        let mut sum = (acc >> 32) + (acc & 0xffff_ffff);
        sum = (sum >> 16) + (sum & 0xffff);
        sum = (sum >> 16) + (sum & 0xffff);
        sum as u32
    }

    /// One datagram's worth of payload, the width a CONNECT-IP packet's own checksum covers: the same bytes both probes below sum.
    fn a_datagram_worth() -> Vec<u8> {
        (0..1342usize)
            .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
            .collect()
    }

    /// The vector kernel against the three forms of the same sum, whole blocks at a time, wherever the kernel exists: the masked byte sums the kernel is written in against the sixteen-bit words the definition names, those words against the lane walk the dispatcher falls back to over their folded residue (an aligned eight-octet lane folds to `hi32 + lo32` — congruent to its four words mod `0xffff`, larger than them, so only the fold is shared), and the kernel's own magnitude against the words.
    #[test]
    fn the_vector_block_sum_is_the_walk_sum() {
        // The definition, at its plainest: a big-endian word at a time, the last zero-padded on an odd run.
        fn by_words(bytes: &[u8]) -> u64 {
            let mut sum: u64 = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|word| u64::from(u16::from_be_bytes(*word)))
                .sum();
            if let [last] = bytes.as_chunks::<2>().1 {
                sum += u64::from(*last) << 8;
            }
            sum
        }
        // The fold `word_sum` ends with, on whichever accumulator it was handed.
        fn folded(sum: u64) -> u32 {
            let sum = (sum >> 32) + (sum & 0xffff_ffff);
            let sum = (sum >> 16) + (sum & 0xffff);
            let sum = (sum >> 16) + (sum & 0xffff);
            sum as u32
        }
        // The equation the kernel is written in, in scalar form, so the arithmetic is gated on every platform and the intrinsic only has to be shown to compute the same thing.
        fn by_masks(bytes: &[u8]) -> u64 {
            let (mut all, mut odd) = (0u64, 0u64);
            for (at, byte) in bytes.iter().enumerate() {
                all += u64::from(*byte);
                if at % 2 == 1 {
                    odd += u64::from(*byte);
                }
            }
            all * 256 - odd * 255
        }
        let bytes = a_datagram_worth();
        for blocks in 0..=bytes.len() / BLOCK {
            let run = &bytes[..blocks * BLOCK];
            assert_eq!(by_masks(run), by_words(run), "{blocks} blocks, as masks");
            assert_eq!(
                folded(by_words(run)),
                folded(lane_sum(run)),
                "{blocks} blocks, as a residue"
            );
        }
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                for blocks in 0..=bytes.len() / BLOCK {
                    let run = &bytes[..blocks * BLOCK];
                    // SAFETY: the probe above is the guard.
                    let kernel = unsafe { avx2_block_sum(run) };
                    assert_eq!(kernel, by_words(run), "{blocks} blocks, as words");
                }
            }
            for blocks in 0..=bytes.len() / BLOCK {
                let run = &bytes[..blocks * BLOCK];
                // SAFETY: SSE2 is the x86_64 baseline.
                let kernel = unsafe { sse2_block_sum(run) };
                assert_eq!(kernel, by_words(run), "{blocks} blocks, as sse2 words");
            }
        }
        #[cfg(target_arch = "aarch64")]
        for blocks in 0..=bytes.len() / BLOCK {
            let run = &bytes[..blocks * BLOCK];
            // SAFETY: NEON is the aarch64 baseline.
            let kernel = unsafe { neon_block_sum(run) };
            assert_eq!(kernel, by_words(run), "{blocks} blocks, as neon words");
        }
    }

    /// The sum the vector kernel returns: sixty-four sums of the same 1342-octet buffer, folded so neither can be folded away, pinned so a run reads the same answer every time.
    #[test]
    fn the_word_sum_costs_the_words_it_reads() {
        let payload = a_datagram_worth();
        let mut fold: u32 = 0;
        for _ in 0..64 {
            fold = fold.wrapping_mul(31).wrapping_add(word_sum(&payload));
        }
        std::hint::black_box(fold);
        assert_eq!(fold, 3_545_888_768, "sixty-four parity sums");
    }

    /// The same sixty-four sums of the same buffer through the word-at-a-time walk, which is the price this slice traded away.
    #[test]
    fn the_serial_word_sum_costs_the_same_answer() {
        let payload = a_datagram_worth();
        let mut fold: u32 = 0;
        for _ in 0..64 {
            fold = fold
                .wrapping_mul(31)
                .wrapping_add(word_sum_serial(&payload));
        }
        std::hint::black_box(fold);
        assert_eq!(fold, 3_545_888_768, "the same sixty-four sums");
    }

    /// The word-at-a-time fold is the byte-at-a-time sum it replaces, at every length that has a boundary inside it and past the point an accumulator wraps.
    #[test]
    fn the_word_fold_is_the_byte_at_a_time_sum() {
        // The definition: one's complement, complemented at the end.
        fn oracle(bytes: &[u8]) -> u16 {
            let mut sum = 0u32;
            let mut high = true;
            for byte in bytes {
                sum = sum.wrapping_add(if high {
                    u32::from(*byte) << 8
                } else {
                    u32::from(*byte)
                });
                high = !high;
            }
            let mut total = sum;
            while total >> 16 != 0 {
                total = (total & 0xffff) + (total >> 16);
            }
            !total as u16
        }
        for len in 0..=40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            assert_eq!(checksum(&bytes), oracle(&bytes), "len {len}");
        }
        let wide: Vec<u8> = (0..=200usize)
            .map(|i| (i as u8).wrapping_mul(101))
            .collect();
        assert_eq!(checksum(&wide), oracle(&wide));
        // The block fold must agree with the byte sum across a block boundary: one fold per 8192 words loses no carry, so sweep both sides of 16 KiB and several blocks deep, on even and odd runs.
        for len in [
            16_382, 16_383, 16_384, 16_385, 16_386, 32_767, 32_768, 32_769, 49_152, 49_153,
        ] {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect();
            assert_eq!(checksum(&bytes), oracle(&bytes), "block boundary len {len}");
        }
    }

    /// The eight-byte lane is the two-byte word walk it replaces, folded to the same residue at every length through several lanes and every remainder modulo eight — the sweep that catches a lost tail byte, a misaligned pair or a carry the lane swallowed.
    #[test]
    fn word_sum_is_the_word_at_a_time_sum_at_every_tail() {
        fn by_words(bytes: &[u8]) -> u32 {
            let (pairs, odd) = bytes.as_chunks::<2>();
            let mut sum = 0u32;
            for pair in pairs {
                sum += u32::from(u16::from_be_bytes(*pair));
            }
            if let [last] = odd {
                sum += u32::from(*last) << 8;
            }
            sum
        }
        let residue = |mut sum: u32| {
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum
        };
        for len in 0..=260usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect();
            assert_eq!(
                residue(word_sum(&bytes)),
                residue(by_words(&bytes)),
                "len {len}"
            );
        }
        // All-ones lanes stress the carry a folded lane could hide: eight `ff` bytes fold to `0xfffe`, and a run of them must still agree with words.
        for len in [8usize, 16, 24, 1000] {
            let bytes = vec![0xffu8; len];
            assert_eq!(
                residue(word_sum(&bytes)),
                residue(by_words(&bytes)),
                "all-ones len {len}"
            );
        }
    }

    /// The parallel lane accumulators hold the exact u32 a single accumulator returns — every length through several quads, every lane remainder, all-ones carries — because `pseudo_sum` folds only once and reads that magnitude, a contract the residue-only sweeps above cannot see.
    #[test]
    fn the_parallel_accumulators_hold_the_single_accumulator_word_sum() {
        // The pre-rewrite walk, one accumulator, as the second source the parallel one is checked against.
        fn by_one_accumulator(bytes: &[u8]) -> u32 {
            let (lanes, rem) = bytes.as_chunks::<8>();
            let mut acc = 0u64;
            for lane in lanes {
                let word = u64::from_be_bytes(*lane);
                acc += (word >> 32) + (word & 0xffff_ffff);
            }
            let mut at = 0usize;
            if rem.len() - at >= 4 {
                acc += u64::from(u32::from_be_bytes(
                    rem[at..at + 4].try_into().expect("four bytes"),
                ));
                at += 4;
            }
            if rem.len() - at >= 2 {
                acc += u64::from(u16::from_be_bytes(
                    rem[at..at + 2].try_into().expect("two bytes"),
                ));
                at += 2;
            }
            if rem.len() - at == 1 {
                acc += u64::from(rem[at]) << 8;
            }
            let mut sum = (acc >> 32) + (acc & 0xffff_ffff);
            sum = (sum >> 16) + (sum & 0xffff);
            sum = (sum >> 16) + (sum & 0xffff);
            sum as u32
        }
        let pattern = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
                .collect()
        };
        // Every lane count through sixteen quads, and the remainder mod four each one leaves.
        for len in 0..=130usize {
            let bytes = pattern(len);
            assert_eq!(word_sum(&bytes), by_one_accumulator(&bytes), "len {len}");
        }
        // Deep runs and all-ones lanes, where a dropped or mis-folded quad moves the exact magnitude, not just its residue.
        for len in [1_000usize, 4_096, 16_384, 65_535] {
            let bytes = pattern(len);
            assert_eq!(
                word_sum(&bytes),
                by_one_accumulator(&bytes),
                "deep len {len}"
            );
        }
        for len in [8usize, 16, 32, 40, 1_000, 65_536] {
            let bytes = vec![0xffu8; len];
            assert_eq!(
                word_sum(&bytes),
                by_one_accumulator(&bytes),
                "all-ones len {len}"
            );
        }
    }

    /// The closed-form pseudo-header sum is the residue that materialising the twelve- or forty-byte header produced, at every address width and datagram length the codec can name; the comparison is at the canonical fold, since `word_sum` lands its residue in a lane as wide as it likes and only the folded number defines a checksum.
    #[test]
    fn the_pseudo_sum_is_the_materialised_header_words() {
        let materialised = |source: &[u8], destination: &[u8], payload: usize| -> u32 {
            let length = (UDP_HEADER + payload) as u32;
            if source.len() == 4 {
                let mut header = [0u8; 12];
                header[..4].copy_from_slice(source);
                header[4..8].copy_from_slice(destination);
                header[9] = PROTOCOL_UDP;
                header[10..12].copy_from_slice(&(length as u16).to_be_bytes());
                word_sum(&header)
            } else {
                let mut header = [0u8; 40];
                header[..16].copy_from_slice(source);
                header[16..32].copy_from_slice(destination);
                header[32..36].copy_from_slice(&length.to_be_bytes());
                header[39] = PROTOCOL_UDP;
                word_sum(&header)
            }
        };
        let v4 = || ([198u8, 51, 100, 7], [203u8, 0, 113, 9]);
        let v6 = || {
            (
                [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            )
        };
        for payload in [
            0,
            1,
            2,
            3,
            7,
            8,
            511,
            512,
            1000,
            MAX_DATAGRAM - 1,
            MAX_DATAGRAM,
        ] {
            let (src, dst) = v4();
            assert_eq!(
                fold(pseudo_sum(&src, &dst, payload)),
                fold(materialised(&src, &dst, payload)),
                "v4 payload {payload}"
            );
            let (src, dst) = v6();
            assert_eq!(
                fold(pseudo_sum(&src, &dst, payload)),
                fold(materialised(&src, &dst, payload)),
                "v6 payload {payload}"
            );
        }
    }

    /// The streaming TCP checksum is the one's-complement sum of the materialised twelve-byte IPv4 pseudo-header followed by the whole segment — the exact byte run the TUN builder used to copy into a throwaway vector — at every segment length the builder can emit, including the odd tail, the empty header-only packet, and an all-ones segment that maximises the carry chain.
    #[test]
    fn the_tcp_checksum_is_the_materialised_pseudo_header_words() {
        let materialised = |source: &[u8], destination: &[u8], segment: &[u8]| -> u16 {
            let tcp_len = segment.len() as u16;
            let mut pseudo: Vec<u8> = Vec::with_capacity(12 + segment.len());
            pseudo.extend_from_slice(source);
            pseudo.extend_from_slice(destination);
            pseudo.push(0);
            pseudo.push(6);
            pseudo.extend_from_slice(&tcp_len.to_be_bytes());
            pseudo.extend_from_slice(segment);
            checksum(&pseudo)
        };
        let src = [198u8, 51, 100, 7];
        let dst = [203u8, 0, 113, 9];
        for len in [0usize, 1, 2, 3, 20, 21, 1332, 1333] {
            // A segment that is 20 bytes of header plus `len` payload bytes, the checksum field left zero as the builder leaves it.
            let mut segment = vec![0u8; 20 + len];
            for (i, b) in segment.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            segment[16] = 0;
            segment[17] = 0;
            assert_eq!(
                tcp_checksum(&src, &dst, &segment),
                materialised(&src, &dst, &segment),
                "segment len {len}"
            );
        }
        // The all-ones worst case: a maximum carry chain folded twice.
        let ones = [0xffu8; 20 + 512];
        assert_eq!(
            tcp_checksum(&src, &dst, &ones),
            materialised(&src, &dst, &ones),
            "all-ones segment"
        );
    }

    /// A receiver of a datagram this lane builds sums the pseudo-header, the UDP header with the checksum in it, and the payload, and gets all ones — and a zero answer never goes on the wire.
    #[test]
    fn a_written_checksum_verifies_at_both_versions() {
        for (source, destination) in [
            (vec![192u8, 0, 2, 7], vec![203, 0, 113, 9]),
            (
                vec![0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                vec![0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            ),
        ] {
            let payload = b"a longer payload that spans words";
            let written = udp_checksum(&source, &destination, 1_000, 2_000, payload);
            assert_ne!(written, 0, "a zero answer is not written");
            let mut datagram = [0u8; UDP_HEADER];
            datagram[0..2].copy_from_slice(&1_000u16.to_be_bytes());
            datagram[2..4].copy_from_slice(&2_000u16.to_be_bytes());
            datagram[4..6].copy_from_slice(&((UDP_HEADER + payload.len()) as u16).to_be_bytes());
            datagram[6..8].copy_from_slice(&written.to_be_bytes());
            let mut sum = pseudo_sum(&source, &destination, payload.len());
            sum = (sum & 0xffff) + (sum >> 16);
            sum += word_sum(&datagram);
            sum = (sum & 0xffff) + (sum >> 16);
            sum += word_sum(payload);
            assert_eq!(fold(sum), 0xffff, "the written checksum verifies");
        }
    }

    /// A tampered datagram is refused rather than relayed, and a peer that left its checksum out is accepted wherever the protocol allows it.
    #[test]
    fn a_tampered_datagram_is_refused_and_an_unchecked_ipv4_one_is_not() {
        let mut packet = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[192, 0, 2, 7],
                destination: &[203, 0, 113, 9],
                source_port: 1_000,
                destination_port: 2_000,
                payload: b"hello ip",
            },
            &mut packet,
        )
        .expect_datagram();
        let flipped = packet.len() - 1;
        packet[flipped] ^= 0x01;
        assert!(
            !udp_from_packet(&packet).expect("still parses").verified,
            "a flipped byte must not verify"
        );
        packet[flipped] ^= 0x01;
        packet[26..28].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            udp_from_packet(&packet).expect("parses").verified,
            "an IPv4 peer may leave the checksum out"
        );

        let mut v6 = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                destination: &[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                source_port: 53,
                destination_port: 53,
                payload: b"\x12\x34",
            },
            &mut v6,
        )
        .expect_datagram();
        v6[46..48].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            !udp_from_packet(&v6).expect("parses").verified,
            "an IPv6 checksum is not optional"
        );
    }

    /// A packet that is not UDP, or not a packet, is refused.
    #[test]
    fn a_packet_that_is_not_udp_is_refused() {
        let mut packet = Vec::new();
        udp_datagram(
            &UdpDatagram {
                source: &[192, 0, 2, 7],
                destination: &[203, 0, 113, 9],
                source_port: 1,
                destination_port: 2,
                payload: b"hi",
            },
            &mut packet,
        )
        .expect_datagram();
        packet[9] = 6;
        assert!(
            udp_from_packet(&packet).is_none(),
            "a TCP packet is not a datagram"
        );
        assert!(udp_from_packet(b"").is_none());
        assert!(
            udp_from_packet(b"\x45").is_none(),
            "a header with no header"
        );
    }

    /// The two carriers write the same request: a HPACK block and a QPACK block whose fields a reader walking literals either way sees as one, so a carrier is a spelling and not a second codec.
    #[test]
    fn both_carriers_carry_the_same_connect_ip_request() {
        let mut h2 = Vec::new();
        connect_ip("edge.example:2499", "example.com", 443, "the-pass", &mut h2);
        let mut q3 = Vec::new();
        connect_ip_qpack("edge.example:2499", "example.com", 443, "the-pass", &mut q3);
        let text = String::from_utf8_lossy(&h2);
        for field in [
            "CONNECT",
            "connect-ip",
            "https",
            "edge.example:2499",
            "/.well-known/masque/ip/example.com/443/",
            "Bearer the-pass",
            "capsule-protocol",
            "?1",
        ] {
            assert!(text.contains(field), "h2 is missing {field}");
        }
        let text = String::from_utf8_lossy(&q3);
        for field in [
            "CONNECT",
            "connect-ip",
            "/.well-known/masque/ip/example.com/443/",
            "Bearer the-pass",
        ] {
            assert!(text.contains(field), "qp3 is missing {field}");
        }
        assert_eq!(super::super::hpack::hpack_status(&h2), None);
        assert_eq!(
            super::super::hpack::qpack_status(&q3),
            None,
            "a request carries no status"
        );
    }

    /// A v4 packet whose payload is eight bytes, so a too-big answer copies the header and the eight bytes the reference copies.
    fn v4_packet(source: [u8; 4], destination: [u8; 4], options: bool) -> Vec<u8> {
        let header = if options { 24 } else { 20 };
        let mut packet = vec![0u8; header + 8];
        packet[0] = 0x40 | ((header / 4) as u8);
        let total = u16::try_from(packet.len()).expect("a short packet");
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = PROTOCOL_UDP;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn v6_packet(source: [u8; 16], destination: [u8; 16]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV6_HEADER + 8];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = PROTOCOL_UDP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn a_packet_too_big_swaps_the_addresses_and_verifies_at_both_versions() {
        let source = [10, 13, 0, 2];
        let destination = [198, 51, 100, 7];
        let packet = v4_packet(source, destination, false);
        let answer = icmp_too_large(&packet, 1170).expect("a v4 answer");
        assert_eq!(answer.len(), 20 + 8 + 28, "v4 header, ICMP, copied packet");
        assert_eq!(answer[0], 0x45);
        assert_eq!(answer[8], HOP_LIMIT);
        assert_eq!(answer[9], ICMP_PROTOCOL);
        assert_eq!(&answer[12..16], &destination, "source is the old target");
        assert_eq!(&answer[16..20], &source, "target is the old source");
        assert_eq!(
            u16::from_be_bytes([answer[2], answer[3]]) as usize,
            answer.len()
        );
        assert_eq!(
            &answer[20..22],
            &[ICMP_DESTINATION_UNREACHABLE, ICMP_FRAGMENTATION_NEEDED]
        );
        assert_eq!(u16::from_be_bytes([answer[26], answer[27]]), 1170);
        assert_eq!(
            &answer[28..],
            &packet[..28],
            "the header and eight bytes follow"
        );
        assert_eq!(fold(word_sum(&answer[..20])), 0xffff, "v4 header checksum");
        assert_eq!(fold(word_sum(&answer[20..])), 0xffff, "v4 ICMP checksum");

        let source6 = [0xfd, 0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let destination6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        let packet = v6_packet(source6, destination6);
        let answer = icmp_too_large(&packet, IPV6_MIN_MTU).expect("a v6 answer");
        assert_eq!(answer.len(), IPV6_HEADER + 8 + 48);
        assert_eq!(answer[0], 0x60);
        assert_eq!(answer[6], ICMPV6_PROTOCOL);
        assert_eq!(answer[7], HOP_LIMIT);
        assert_eq!(&answer[8..24], &destination6, "source is the old target");
        assert_eq!(&answer[24..40], &source6, "target is the old source");
        assert_eq!(
            u16::from_be_bytes([answer[4], answer[5]]) as usize,
            answer.len() - IPV6_HEADER
        );
        assert_eq!(&answer[40..42], &[ICMPV6_PACKET_TOO_BIG, 0]);
        assert_eq!(
            u32::from_be_bytes([answer[44], answer[45], answer[46], answer[47]]),
            u32::try_from(IPV6_MIN_MTU).expect("an mtu")
        );
        assert_eq!(&answer[48..], &packet[..48]);
        let sum = word_sum(&answer[8..24])
            + word_sum(&answer[24..40])
            + (answer.len() - IPV6_HEADER) as u32
            + u32::from(ICMPV6_PROTOCOL);
        let sum = (sum & 0xffff) + (sum >> 16);
        assert_eq!(
            fold(sum + word_sum(&answer[IPV6_HEADER..])),
            0xffff,
            "v6 ICMP checksum covers the pseudo-header"
        );
    }

    #[test]
    fn a_packet_too_big_copies_options_and_refuses_a_narrow_mtu() {
        let packet = v4_packet([10, 13, 0, 2], [198, 51, 100, 7], true);
        let answer = icmp_too_large(&packet, 1170).expect("a v4 answer");
        assert_eq!(answer.len(), 20 + 8 + 32, "24-byte header and eight bytes");
        assert_eq!(&answer[28..], &packet[..32]);
        assert!(icmp_too_large(&packet, 67).is_none(), "below the v4 floor");
        assert!(
            icmp_too_large(&v6_packet([0; 16], [0; 16]), 1279).is_none(),
            "below the v6 floor"
        );
        assert!(
            icmp_too_large(&[0x45, 0, 0], 1280).is_none(),
            "not a header"
        );
        assert!(
            icmp_too_large(&[0x55; 40], 1280).is_none(),
            "not an IP version"
        );
    }

    #[test]
    fn an_echo_request_is_answered_at_both_families() {
        let request = [
            ICMP_ECHO_REQUEST,
            0,
            0,
            0,
            0x12,
            0x34,
            0,
            7,
            b'p',
            b'i',
            b'n',
            b'g',
        ];
        let mut answer = Vec::new();
        assert!(icmp_echo_reply(
            "10.13.0.2".parse().expect("a v4 source"),
            "10.13.0.1".parse().expect("a v4 destination"),
            &request,
            &mut answer
        ));
        assert_eq!(answer.len(), IPV4_HEADER + request.len());
        assert_eq!(answer[0], 0x45);
        assert_eq!(answer[8], HOP_LIMIT);
        assert_eq!(answer[9], ICMP_PROTOCOL);
        assert_eq!(&answer[12..16], &[10, 13, 0, 1], "source is the old target");
        assert_eq!(&answer[16..20], &[10, 13, 0, 2], "target is the old source");
        assert_eq!(&answer[IPV4_HEADER..IPV4_HEADER + 2], &[ICMP_ECHO_REPLY, 0]);
        assert_eq!(&answer[IPV4_HEADER + 4..], &request[4..]);
        assert_eq!(fold(word_sum(&answer[..IPV4_HEADER])), 0xffff, "v4 header");
        assert_eq!(fold(word_sum(&answer[IPV4_HEADER..])), 0xffff, "v4 ICMP");

        let source6 = [0xfd, 0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let destination6 = [0xfd, 0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut request = vec![ICMPV6_ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0, 7];
        request.extend_from_slice(b"ping");
        let mut answer = Vec::new();
        assert!(icmp_echo_reply(
            source6.into(),
            destination6.into(),
            &request,
            &mut answer
        ));
        assert_eq!(answer.len(), IPV6_HEADER + request.len());
        assert_eq!(answer[0], 0x60);
        assert_eq!(answer[6], ICMPV6_PROTOCOL);
        assert_eq!(answer[7], HOP_LIMIT);
        assert_eq!(&answer[8..24], &destination6, "source is the old target");
        assert_eq!(&answer[24..40], &source6, "target is the old source");
        assert_eq!(
            &answer[IPV6_HEADER..IPV6_HEADER + 2],
            &[ICMPV6_ECHO_REPLY, 0]
        );
        assert_eq!(&answer[IPV6_HEADER + 4..], &request[4..]);
        let sum = word_sum(&answer[8..24])
            + word_sum(&answer[24..40])
            + request.len() as u32
            + u32::from(ICMPV6_PROTOCOL);
        let sum = (sum & 0xffff) + (sum >> 16);
        assert_eq!(
            fold(sum + word_sum(&answer[IPV6_HEADER..])),
            0xffff,
            "v6 ICMP covers the pseudo-header"
        );
    }

    #[test]
    fn a_message_that_is_not_an_echo_request_leaves_the_buffer_alone() {
        let mut answer = b"kept".to_vec();
        let base = answer.as_ptr();
        let refused: [(&[u8], &str); 3] = [
            (&[ICMP_ECHO_REPLY, 0, 0, 0, 0, 0, 0, 0], "10.13.0.1"),
            (&[ICMP_ECHO_REQUEST, 3, 0, 0, 0, 0, 0, 0], "10.13.0.1"),
            (&[ICMP_ECHO_REQUEST, 0, 0, 0], "10.13.0.1"),
        ];
        for (message, destination) in refused {
            assert!(!icmp_echo_reply(
                "10.13.0.2".parse().expect("a v4 source"),
                destination.parse().expect("a v4 destination"),
                message,
                &mut answer
            ));
            assert_eq!(answer, b"kept", "a refusal writes nothing");
            assert_eq!(answer.as_ptr(), base, "and moves no buffer");
        }
        let v6 = [ICMPV6_ECHO_REQUEST, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            !icmp_echo_reply(
                "10.13.0.2".parse().expect("a v4 source"),
                "fd13::1".parse().expect("a v6 destination"),
                &v6,
                &mut answer
            ),
            "a family the request does not share"
        );
        assert_eq!(answer, b"kept");
    }
}
