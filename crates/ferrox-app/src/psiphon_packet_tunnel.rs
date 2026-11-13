//! Packet tunnel framing and transparent DNS rewriting, matching the reference client's
//! `common/tun` packet path: two-byte length frames on the `tun@psiphon.ca` SSH channel,
//! IPv4/IPv6 TCP and UDP only, and the two-step DNS translation.

use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const MTU: usize = 1500;
pub(crate) const CHANNEL: &[u8] = b"tun@psiphon.ca";
pub(crate) const DNS_PORT: u16 = 53;

const RESOLVER_V4: [u8; 4] = [10, 0, 0, 2];
const RESOLVER_V6: [u8; 16] = [
    0xfd, 0x19, 0xca, 0x83, 0xe6, 0xd5, 0x1c, 0x44, 0, 0, 0, 0, 0, 0, 0, 2,
];

const TCP: u8 = 6;
const UDP: u8 = 17;

/// The VPN DNS addresses a packet tunnel is configured with, absent when the field is empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Dns {
    v4: Option<[u8; 4]>,
    v6: Option<[u8; 16]>,
}

impl Dns {
    pub(crate) fn parse(v4: &str, v6: &str) -> Result<Self, String> {
        let v4 = if v4.is_empty() {
            None
        } else {
            let address = v4
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("invalid IPv4 address {v4:?}"))?;
            Some(address.octets())
        };
        let v6 = if v6.is_empty() {
            None
        } else {
            let address = v6
                .parse::<Ipv6Addr>()
                .map_err(|_| format!("invalid IPv6 address {v6:?}"))?;
            if address.to_ipv4_mapped().is_some() {
                return Err(format!("invalid IPv6 address {v6:?}"));
            }
            Some(address.octets())
        };
        Ok(Self { v4, v6 })
    }

    #[cfg(test)]
    pub(crate) fn addresses(&self) -> (Option<[u8; 4]>, Option<[u8; 16]>) {
        (self.v4, self.v6)
    }
}

/// The offsets in one parsed IP packet that the two rewrites touch.
struct View {
    version: u8,
    source: std::ops::Range<usize>,
    destination: std::ops::Range<usize>,
    ip_checksum: Option<std::ops::Range<usize>>,
    transport_checksum: std::ops::Range<usize>,
    source_port: u16,
    destination_port: u16,
}

fn port(packet: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

fn parse(packet: &[u8]) -> Option<View> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet[0] & 0x0f != 5 || packet.len() < 20 {
                return None;
            }
            let protocol = packet[9];
            let transport_checksum = match protocol {
                TCP => {
                    if packet.len() < 38 {
                        return None;
                    }
                    let offset = 20 + 4 * usize::from(packet[32] >> 4);
                    if packet.len() < offset {
                        return None;
                    }
                    36..38
                }
                UDP => {
                    if packet.len() < 28 {
                        return None;
                    }
                    26..28
                }
                _ => return None,
            };
            Some(View {
                version: 4,
                source: 12..16,
                destination: 16..20,
                ip_checksum: Some(10..12),
                transport_checksum,
                source_port: port(packet, 20),
                destination_port: port(packet, 22),
            })
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let protocol = packet[6];
            let transport_checksum = match protocol {
                TCP => {
                    if packet.len() < 58 {
                        return None;
                    }
                    let offset = 40 + 4 * usize::from(packet[52] >> 4);
                    if packet.len() < offset {
                        return None;
                    }
                    56..58
                }
                UDP => {
                    if packet.len() < 48 {
                        return None;
                    }
                    46..48
                }
                _ => return None,
            };
            Some(View {
                version: 6,
                source: 8..24,
                destination: 24..40,
                ip_checksum: None,
                transport_checksum,
                source_port: port(packet, 40),
                destination_port: port(packet, 42),
            })
        }
        _ => None,
    }
}

fn global_unicast(address: &[u8]) -> bool {
    match address.len() {
        4 => {
            let first = address[0];
            !(address == [0, 0, 0, 0]
                || first == 127
                || (first == 169 && address[1] == 254)
                || address == [255, 255, 255, 255]
                || first & 0xf0 == 0xe0)
        }
        16 => {
            if address[..10].iter().all(|byte| *byte == 0)
                && address[10] == 0xff
                && address[11] == 0xff
            {
                return global_unicast(&address[12..]);
            }
            !(address.iter().all(|byte| *byte == 0)
                || address == Ipv6Addr::LOCALHOST.octets()
                || address[0] == 0xff
                || (address[0] == 0xfe && address[1] & 0xc0 == 0x80))
        }
        _ => false,
    }
}

fn checked_address(packet: &[u8], address: std::ops::Range<usize>, wanted: [u8; 4]) -> bool {
    packet.get(address) == Some(wanted.as_slice())
}

fn checked_address6(packet: &[u8], address: std::ops::Range<usize>, wanted: [u8; 16]) -> bool {
    packet.get(address) == Some(wanted.as_slice())
}

fn checksum_accumulate(data: &[u8], adding: bool, accumulator: &mut i32) {
    for word in data.as_chunks::<4>().0 {
        let [high, low] = [
            u16::from_be_bytes([word[0], word[1]]),
            u16::from_be_bytes([word[2], word[3]]),
        ];
        let (high, low) = (i32::from(high), i32::from(low));
        if adding {
            *accumulator -= low;
            *accumulator -= high;
        } else {
            *accumulator += low;
            *accumulator += high;
        }
    }
}

fn checksum_adjust(field: &mut [u8], accumulator: i32) {
    let mut accumulator = i32::from(u16::from_be_bytes([field[0], field[1]])) + accumulator;
    if accumulator < 0 {
        accumulator = -accumulator;
        accumulator = (accumulator >> 16) + (accumulator & 0xffff);
        accumulator += accumulator >> 16;
        let checksum = !(accumulator as u16);
        field.copy_from_slice(&checksum.to_be_bytes());
    } else {
        accumulator = (accumulator >> 16) + (accumulator & 0xffff);
        accumulator += accumulator >> 16;
        field.copy_from_slice(&(accumulator as u16).to_be_bytes());
    }
}

fn rewrite(packet: &mut [u8], view: &View, source: Option<&[u8]>, destination: Option<&[u8]>) {
    let mut accumulator = 0i32;
    if let Some(address) = source {
        checksum_accumulate(&packet[view.source.clone()], false, &mut accumulator);
        packet[view.source.clone()].copy_from_slice(address);
        checksum_accumulate(&packet[view.source.clone()], true, &mut accumulator);
    }
    if let Some(address) = destination {
        checksum_accumulate(&packet[view.destination.clone()], false, &mut accumulator);
        packet[view.destination.clone()].copy_from_slice(address);
        checksum_accumulate(&packet[view.destination.clone()], true, &mut accumulator);
    }
    if source.is_none() && destination.is_none() {
        return;
    }
    if let Some(field) = view.ip_checksum.clone() {
        checksum_adjust(&mut packet[field], accumulator);
    }
    let field = view.transport_checksum.clone();
    checksum_adjust(&mut packet[field], accumulator);
}

/// Validate and rewrite one packet from the device toward the tunnel.
#[must_use]
pub(crate) fn upstream(packet: &mut [u8], dns: &Dns) -> bool {
    let Some(view) = parse(packet) else {
        return false;
    };
    let transparent = view.destination_port == DNS_PORT
        && match view.version {
            4 => dns
                .v4
                .is_some_and(|address| checked_address(packet, view.destination.clone(), address)),
            6 => dns
                .v6
                .is_some_and(|address| checked_address6(packet, view.destination.clone(), address)),
            _ => false,
        };
    if !transparent
        && (view.destination_port == 0 || !global_unicast(&packet[view.destination.clone()]))
    {
        return false;
    }
    if transparent {
        match view.version {
            4 => rewrite(packet, &view, None, Some(&RESOLVER_V4)),
            _ => rewrite(packet, &view, None, Some(&RESOLVER_V6)),
        }
    }
    true
}

/// Validate and rewrite one packet from the tunnel toward the device.
#[must_use]
pub(crate) fn downstream(packet: &mut [u8], dns: &Dns) -> bool {
    let Some(view) = parse(packet) else {
        return false;
    };
    let transparent = view.source_port == DNS_PORT
        && match view.version {
            4 => checked_address(packet, view.source.clone(), RESOLVER_V4),
            6 => checked_address6(packet, view.source.clone(), RESOLVER_V6),
            _ => false,
        };
    if !transparent && (view.source_port == 0 || !global_unicast(&packet[view.destination.clone()]))
    {
        return false;
    }
    if transparent {
        match (view.version, dns.v4, dns.v6) {
            (4, Some(address), _) => rewrite(packet, &view, Some(&address), None),
            (6, _, Some(address)) => rewrite(packet, &view, Some(&address), None),
            _ => {}
        }
    }
    true
}

/// Append one length-prefixed packet to the channel's batch.
pub(crate) fn append_frame(out: &mut Vec<u8>, packet: &[u8]) -> Result<(), ()> {
    let length = u16::try_from(packet.len()).map_err(|_| ())?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(packet);
    Ok(())
}

/// Read one length-prefixed packet into the reused buffer.
pub(crate) fn read_frame<R: Read>(reader: &mut R, packet: &mut Vec<u8>) -> io::Result<usize> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header)?;
    let length = usize::from(u16::from_be_bytes(header));
    if length > MTU {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet exceeds MTU",
        ));
    }
    packet.resize(length, 0);
    reader.read_exact(packet)?;
    Ok(length)
}

/// Wait for the device to have one packet, without blocking shutdown indefinitely.
#[cfg(unix)]
pub(crate) fn wait_readable(fd: std::os::fd::RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout_ms) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(ready > 0)
}

#[cfg(not(unix))]
pub(crate) fn wait_readable(_fd: i32, _timeout_ms: i32) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "packet tunnel needs a Unix descriptor",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns() -> Dns {
        Dns::parse("192.168.0.1", "fd00::1").expect("dns")
    }

    fn udp4(destination: [u8; 4], destination_port: u16, source_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + 8];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = UDP;
        packet[12..16].copy_from_slice(&[192, 168, 0, 2]);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    fn udp6(destination: [u8; 16], destination_port: u16, source_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + 8];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = UDP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40].copy_from_slice(&destination);
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    fn sum(data: &[u8]) -> u32 {
        let mut total = 0u32;
        let (chunks, remainder) = data.as_chunks::<2>();
        for word in chunks {
            total += u32::from(u16::from_be_bytes(*word));
        }
        if let Some(last) = remainder.first() {
            total += u32::from(*last) << 8;
        }
        total
    }

    fn fold(mut total: u32) -> u16 {
        while total >> 16 != 0 {
            total = (total & 0xffff) + (total >> 16);
        }
        !(total as u16)
    }

    fn seal4(packet: &mut [u8]) {
        packet[10..12].copy_from_slice(&[0, 0]);
        let checksum = fold(sum(&packet[..20]));
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet[26..28].copy_from_slice(&[0, 0]);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[12..20]);
        pseudo.push(0);
        pseudo.push(UDP);
        pseudo.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
        pseudo.extend_from_slice(&packet[20..]);
        let checksum = fold(sum(&pseudo));
        packet[26..28].copy_from_slice(&checksum.to_be_bytes());
    }

    fn seal6(packet: &mut [u8]) {
        packet[46..48].copy_from_slice(&[0, 0]);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[8..40]);
        pseudo.extend_from_slice(&((packet.len() - 40) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, UDP]);
        pseudo.extend_from_slice(&packet[40..]);
        let checksum = fold(sum(&pseudo));
        packet[46..48].copy_from_slice(&checksum.to_be_bytes());
    }

    fn ip_checksum_ok(packet: &[u8]) -> bool {
        fold(sum(&packet[..20])) == 0
    }

    fn udp4_checksum_ok(packet: &[u8]) -> bool {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[12..20]);
        pseudo.push(0);
        pseudo.push(UDP);
        let length = (packet.len() - 20) as u16;
        pseudo.extend_from_slice(&length.to_be_bytes());
        pseudo.extend_from_slice(&packet[20..]);
        fold(sum(&pseudo)) == 0
    }

    fn udp6_checksum_ok(packet: &[u8]) -> bool {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[8..40]);
        let length = (packet.len() - 40) as u32;
        pseudo.extend_from_slice(&length.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, UDP]);
        pseudo.extend_from_slice(&packet[40..]);
        fold(sum(&pseudo)) == 0
    }

    #[test]
    fn a_vpn_dns_query_is_rewritten_to_the_transparent_resolver() {
        let mut packet = udp4([192, 168, 0, 1], 53, 5555);
        seal4(&mut packet);
        assert!(upstream(&mut packet, &dns()));
        assert_eq!(&packet[16..20], &RESOLVER_V4);
        assert!(ip_checksum_ok(&packet));
        assert!(udp4_checksum_ok(&packet));
        assert_eq!(&packet[22..24], &53u16.to_be_bytes());
    }

    #[test]
    fn a_vpn_dns_response_is_rewritten_back_to_the_configured_server() {
        let mut packet = udp4([10, 0, 0, 1], 5555, 53);
        packet[16..20].copy_from_slice(&[192, 168, 0, 9]);
        packet[12..16].copy_from_slice(&RESOLVER_V4);
        seal4(&mut packet);
        assert!(downstream(&mut packet, &dns()));
        assert_eq!(&packet[12..16], &[192, 168, 0, 1]);
        assert!(ip_checksum_ok(&packet));
        assert!(udp4_checksum_ok(&packet));
    }

    #[test]
    fn an_unrelated_dns_query_keeps_its_destination() {
        let mut packet = udp4([1, 1, 1, 1], 53, 5555);
        assert!(upstream(&mut packet, &dns()));
        assert_eq!(&packet[16..20], &[1, 1, 1, 1]);
    }

    #[test]
    fn an_ipv6_vpn_dns_query_is_rewritten_to_the_transparent_resolver() {
        let mut packet = udp6(
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            53,
            5555,
        );
        seal6(&mut packet);
        assert!(upstream(&mut packet, &dns()));
        assert_eq!(&packet[24..40], &RESOLVER_V6);
        assert!(udp6_checksum_ok(&packet));
    }

    #[test]
    fn an_ipv6_vpn_dns_response_is_rewritten_back() {
        let mut packet = udp6(
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            5555,
            53,
        );
        packet[8..24].copy_from_slice(&RESOLVER_V6);
        seal6(&mut packet);
        assert!(downstream(&mut packet, &dns()));
        assert_eq!(
            &packet[8..24],
            &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert!(udp6_checksum_ok(&packet));
    }

    #[test]
    fn a_loopback_destination_is_refused() {
        let mut packet = udp4([127, 0, 0, 1], 443, 5555);
        assert!(!upstream(&mut packet, &dns()));
    }

    #[test]
    fn a_private_unicast_destination_is_carried() {
        let mut packet = udp4([10, 9, 8, 7], 443, 5555);
        assert!(upstream(&mut packet, &dns()));
        assert_eq!(&packet[16..20], &[10, 9, 8, 7]);
    }

    #[test]
    fn a_packet_with_ipv4_options_is_refused() {
        let mut packet = udp4([1, 1, 1, 1], 53, 5555);
        packet[0] = 0x46;
        assert!(!upstream(&mut packet, &dns()));
    }

    #[test]
    fn a_non_tcp_or_udp_packet_is_refused() {
        let mut packet = udp4([1, 1, 1, 1], 53, 5555);
        packet[9] = 1;
        assert!(!upstream(&mut packet, &dns()));
    }

    #[test]
    fn a_truncated_packet_is_refused() {
        let mut packet = udp4([1, 1, 1, 1], 53, 5555);
        packet.truncate(19);
        assert!(!upstream(&mut packet, &dns()));
    }

    #[test]
    fn a_zero_port_is_refused() {
        let mut packet = udp4([1, 1, 1, 1], 0, 5555);
        assert!(!upstream(&mut packet, &dns()));
    }

    #[test]
    fn a_frame_round_trips_through_the_reused_buffer() {
        let packet = udp4([1, 1, 1, 1], 53, 5555);
        let mut framed = Vec::new();
        append_frame(&mut framed, &packet).expect("frame");
        assert_eq!(&framed[..2], &(packet.len() as u16).to_be_bytes());
        let mut buffer = Vec::new();
        let length = read_frame(&mut &framed[..], &mut buffer).expect("read");
        assert_eq!(length, packet.len());
        assert_eq!(buffer, packet);
    }

    #[test]
    fn a_frame_over_the_mtu_is_refused() {
        let framed = [0x05, 0xdd];
        let mut buffer = Vec::new();
        assert!(read_frame(&mut &framed[..], &mut buffer).is_err());
    }

    #[test]
    fn the_dns_addresses_are_validated() {
        assert!(Dns::parse("", "").is_ok());
        assert!(Dns::parse("not-an-address", "").is_err());
        assert!(Dns::parse("", "not-an-address").is_err());
        assert!(Dns::parse("", "::ffff:192.0.2.1").is_err());
    }
}
