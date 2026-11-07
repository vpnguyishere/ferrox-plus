//! The SOCKS5 **client** session: the handshake a client writes to a SOCKS5 server, and
//! the two tunnels it opens there.
//!
//! The tree already *serves* SOCKS5 (the `socks` front in `proxy.rs`). This module is the
//! other half — the side `hev-socks5-tunnel` is on: a TUN device's flows are tunnelled
//! into a SOCKS5 server, the Go core's local SOCKS inbound in `PattNG`'s deployment.
//!
//! Byte-identity: every byte this module writes is the byte the pinned references write.
//! `xray-core/proxy/socks/protocol.go`'s `ClientHandshake` writes the greeting
//! `[5, 1, method]`, the RFC 1929 block `[1, ulen, user, plen, pass]` and the request
//! `[5, cmd, 0, atyp, addr, port]`; `hev-socks5-core`'s
//! `hev_socks5_client_write_auth_methods` and `hev_socks5_client_write_request` write the
//! same shapes. The codec that builds those bytes is `ferrox_core::socks`; this module
//! only moves them.
//!
//! The reference offers the one method it will use, so this does too: a session with no
//! credential writes `[5, 1, 0]` and one with a credential writes `[5, 1, 2]` and then
//! the RFC 1929 block.
//!
//! The session is strict about the method: a server that answers one the session did
//! not offer is refused, the way the pinned Go client refuses it (`auth method not
//! supported.`), so a credentialed session never tunnels through a server that answered
//! no authentication.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Instant;

#[cfg(test)]
use crate::conn::Connection;
use ferrox_core::socks;

/// The credential a SOCKS5 server may ask for.
#[derive(Debug, Clone, Default)]
pub(crate) struct Credential {
    /// The user name the RFC 1929 exchange carries.
    pub(crate) user: String,
    /// The password the RFC 1929 exchange carries.
    pub(crate) pass: String,
}

/// The SOCKS version a session speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    /// RFC 1928, with RFC 1929's credential exchange.
    V5,
    /// SOCKS4 and `SOCKS4a`: one request, no negotiation, a user id and no password.
    V4,
}

impl Credential {
    /// The method this credential makes the session offer, or nothing when the
    /// credential cannot be spelled on the wire.
    ///
    /// A credential that is half-written is refused rather than downgraded to no
    /// authentication: the pinned Go client offers the one method it will use and
    /// fails when the server picks another, and a session that quietly offered no
    /// authentication would hand the server a tunnel the operator asked to be
    /// authenticated.
    fn method(&self) -> Option<u8> {
        if self.user.is_empty() && self.pass.is_empty() {
            return Some(socks::METHOD_NONE);
        }
        if self.user.is_empty() || self.pass.is_empty() {
            return None;
        }
        if self.user.len() > 255 || self.pass.len() > 255 {
            return None;
        }
        Some(socks::METHOD_USER)
    }
}

/// The destination a SOCKS5 request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Destination<'a> {
    /// A four-byte IPv4 address and a port.
    V4([u8; 4], u16),
    /// A sixteen-byte IPv6 address and a port.
    V6([u8; 16], u16),
    /// A domain name and a port.
    Name(&'a [u8], u16),
}

impl<'a> Destination<'a> {
    /// The target the codec writes.
    fn target(&self) -> socks::Target<'a> {
        match self {
            Self::V4(octets, port) => socks::Target::V4(*octets, *port),
            Self::V6(octets, port) => socks::Target::V6(*octets, *port),
            Self::Name(name, port) => socks::Target::Name(name, *port),
        }
    }
}

const REQUEST_HEAD: usize = 3;
const INLINE_ADDRESS: usize = 1 + 16 + 2;
const MAX_ADDRESS: usize = 1 + 1 + 255 + 2;
const INLINE_REQUEST: usize = REQUEST_HEAD + INLINE_ADDRESS;
const MAX_REQUEST: usize = REQUEST_HEAD + MAX_ADDRESS;
const INLINE_AUTH: usize = 3 + 64;
const MAX_AUTH: usize = 3 + 255 + 255;

/// The request's octets into the caller's room: the version, the command, the reserved
/// byte and the destination. The destination's own encoder is the writer the oracle
/// compares, so this only places it after the head.
fn encode_request(cmd: u8, destination: &Destination<'_>, out: &mut [u8]) -> Option<usize> {
    let target = destination.target();
    let total = REQUEST_HEAD + target.wire_len();
    if out.len() < total {
        return None;
    }
    out[0] = socks::VERSION;
    out[1] = cmd;
    out[2] = 0;
    target.encode_into(&mut out[REQUEST_HEAD..total]);
    Some(total)
}

/// One request on the wire without a heap buffer: a literal or a short name fits the
/// inline room, and the RFC's longest name takes the block beside it. Both are written
/// where they are read, so a dial allocates nothing for its request.
fn write_request<W: Write>(stream: &mut W, cmd: u8, destination: &Destination<'_>) -> Option<()> {
    let total = REQUEST_HEAD + destination.target().wire_len();
    if total <= INLINE_REQUEST {
        let mut inline = [0u8; INLINE_REQUEST];
        encode_request(cmd, destination, &mut inline)?;
        stream.write_all(&inline[..total]).ok()?;
    } else {
        let mut long = [0u8; MAX_REQUEST];
        encode_request(cmd, destination, &mut long)?;
        stream.write_all(&long[..total]).ok()?;
    }
    Some(())
}

fn encode_user_pass(user: &[u8], pass: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 3 + user.len() + pass.len();
    if out.len() < total || user.len() > 255 || pass.len() > 255 {
        return None;
    }
    out[0] = socks::AUTH_VERSION;
    out[1] = user.len() as u8;
    out[2..2 + user.len()].copy_from_slice(user);
    out[2 + user.len()] = pass.len() as u8;
    out[3 + user.len()..total].copy_from_slice(pass);
    Some(total)
}

fn write_user_pass<W: Write>(stream: &mut W, user: &[u8], pass: &[u8]) -> Option<()> {
    let total = 3 + user.len() + pass.len();
    if total <= INLINE_AUTH {
        let mut inline = [0u8; INLINE_AUTH];
        encode_user_pass(user, pass, &mut inline)?;
        stream.write_all(&inline[..total]).ok()?;
    } else {
        let mut long = [0u8; MAX_AUTH];
        encode_user_pass(user, pass, &mut long)?;
        stream.write_all(&long[..total]).ok()?;
    }
    Some(())
}

/// A handshake read over a session that polls its transport: a timeout is another round, not the end of the exchange.
fn read_exact_within(stream: &mut impl Read, buf: &mut [u8], until: Instant) -> Option<()> {
    use std::io::ErrorKind;
    let mut at = 0;
    while at < buf.len() {
        if Instant::now() >= until {
            return None;
        }
        match stream.read(&mut buf[at..]) {
            Ok(0) => return None,
            Ok(n) => {
                at += n;
                if Instant::now() >= until {
                    return None;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {
                if Instant::now() >= until {
                    return None;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if Instant::now() >= until {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    if Instant::now() >= until {
        return None;
    }
    Some(())
}

/// Consume the bound address a granted reply carries, without owning it: a TCP tunnel
/// uses nothing the server bound, so the bytes are read to put the stream at the first
/// tunnel octet and no `Vec` or `String` is built for a name that is then dropped.
fn skip_bound<R: Read>(stream: &mut R, atyp: u8, until: Instant) -> Option<()> {
    match atyp {
        socks::ATYP_IPV4 => {
            let mut body = [0u8; 6];
            read_exact_within(stream, &mut body, until)?;
        }
        socks::ATYP_IPV6 => {
            let mut body = [0u8; 18];
            read_exact_within(stream, &mut body, until)?;
        }
        socks::ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact_within(stream, &mut len, until)?;
            let mut body = [0u8; 257];
            read_exact_within(stream, &mut body[..usize::from(len[0]) + 2], until)?;
        }
        _ => return None,
    }
    Some(())
}

/// The address a reply's type byte named: one edge the RFC gives the bound address.
enum Bound {
    /// An IP address and port, read as the server sent them.
    Ip(SocketAddr),
    /// A domain name and port; the association dials the name the way the
    /// reference's dialer does, the TCP tunnel uses nothing it named.
    Name(String, u16),
}

/// A SOCKS5 client session over one connection.
pub(crate) struct Session<S> {
    stream: S,
    until: Instant,
}

impl<S: Read + Write> Session<S> {
    /// Open the handshake on an already-connected socket: the greeting, the credential
    /// exchange when the server asks for one, and nothing else. The request comes after,
    /// because the reply to the greeting is what says whether a credential is needed.
    ///
    /// A server that answers a method this session cannot serve is refused: the pinned Go
    /// client refuses it too (`"auth method not supported."`).
    pub(crate) fn open(mut stream: S, credential: &Credential) -> Option<Self> {
        let until = Instant::now() + crate::budgets::handshake();
        let offered = credential.method()?;
        stream
            .write_all(&socks::greeting(offered == socks::METHOD_USER))
            .ok()?;
        let mut method = [0u8; 2];
        read_exact_within(&mut stream, &mut method, until)?;
        if method[0] != socks::VERSION || method[1] != offered {
            return None;
        }
        if offered == socks::METHOD_USER {
            write_user_pass(
                &mut stream,
                credential.user.as_bytes(),
                credential.pass.as_bytes(),
            )?;
            let mut status = [0u8; 2];
            read_exact_within(&mut stream, &mut status, until)?;
            if status[0] != socks::AUTH_VERSION || status[1] != 0 {
                return None;
            }
        }
        Some(Self { stream, until })
    }

    /// Send a request and wait for the reply's head, returning the address type byte.
    ///
    /// The reply is the version, the status, the reserved byte and the bound address's
    /// type byte. The status decides whether the address is read at all: a refusal
    /// carries an address too, but the pinned writer stops at the status
    /// (`"server rejects request: "`).
    fn send(&mut self, cmd: u8, destination: &Destination<'_>) -> Option<u8> {
        write_request(&mut self.stream, cmd, destination)?;
        let mut head = [0u8; 4];
        read_exact_within(&mut self.stream, &mut head, self.until)?;
        if head[0] != socks::VERSION || head[1] != 0 {
            return None;
        }
        Some(head[3])
    }

    /// Read the address the server bound, which the reply's type byte names.
    ///
    /// RFC 1928 gives the bound address three forms and the reference reads all
    /// three: `addrParser.ReadAddressPort` is the reader the request used, so the
    /// reply accepts every type the request can carry a destination in. What the
    /// caller makes of it differs: a TCP tunnel uses nothing the reply bound
    /// (`proxy/socks/client.go` substitutes an address for UDP only), a UDP
    /// association dials the relay — through the name, where the server bound one.
    fn read_bound(&mut self, atyp: u8) -> Option<Bound> {
        match atyp {
            socks::ATYP_IPV4 => {
                let mut body = [0u8; 6];
                read_exact_within(&mut self.stream, &mut body, self.until)?;
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&body[..4]);
                Some(Bound::Ip(SocketAddr::from((
                    octets,
                    u16::from_be_bytes([body[4], body[5]]),
                ))))
            }
            socks::ATYP_IPV6 => {
                let mut body = [0u8; 18];
                read_exact_within(&mut self.stream, &mut body, self.until)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&body[..16]);
                Some(Bound::Ip(SocketAddr::from((
                    octets,
                    u16::from_be_bytes([body[16], body[17]]),
                ))))
            }
            socks::ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                read_exact_within(&mut self.stream, &mut len, self.until)?;
                let name_len = usize::from(len[0]);
                let mut body = vec![0u8; name_len + 2];
                read_exact_within(&mut self.stream, &mut body, self.until)?;
                let name = String::from_utf8_lossy(&body[..name_len]).into_owned();
                let port = u16::from_be_bytes([body[name_len], body[name_len + 1]]);
                Some(Bound::Name(name, port))
            }
            _ => None,
        }
    }

    /// Ask for a TCP tunnel to one destination.
    ///
    /// The address the server bound is not what the caller asked for and is not needed,
    /// but its octets are read so the stream sits where the tunnel begins.
    fn connect(&mut self, destination: &Destination<'_>) -> Option<()> {
        let atyp = self.send(socks::CMD_CONNECT, destination)?;
        skip_bound(&mut self.stream, atyp, self.until)?;
        Some(())
    }

    /// Ask for a UDP association and read the relay the datagrams go to.
    pub(crate) fn associate(&mut self) -> Option<SocketAddr> {
        // RFC 1928's associate request names no destination: the address is `0.0.0.0:0` — `hev-socks5-core` sends the same all-zero IPv4 address, and `xray-core`'s `ClientHandshake` writes `{1, 0, 0, 0, 0, 0, 0}` for a UDP request.
        let atyp = self.send(socks::CMD_UDP_ASSOCIATE, &Destination::V4([0, 0, 0, 0], 0))?;
        match self.read_bound(atyp)? {
            Bound::Ip(relay) => Some(relay),
            // The server's relay is dialled, not refused: the reference resolves the name its dialer is handed.
            Bound::Name(name, port) => crate::proxy::resolve_endpoint(name.as_str(), port),
        }
    }

    /// The socket the session runs on, once the request has been granted.
    pub(crate) fn into_stream(self) -> S {
        self.stream
    }

    /// Open a SOCKS4 session: there is no greeting and no method to negotiate, so the
    /// request is the first thing on the wire.
    pub(crate) fn open4(stream: S) -> Self {
        Self {
            stream,
            until: Instant::now() + crate::budgets::handshake(),
        }
    }

    /// The SOCKS4 request: the version, the command, the port, the address, the user
    /// id, and — for a name — the name itself.
    ///
    /// A name rides the `SOCKS4a` form, with the `0.0.0.1` marker in the address
    /// field, so the server resolves it and this tree's resolver never sees it. An
    /// IPv6 address has no SOCKS4 form and is refused.
    fn connect4(&mut self, destination: &Destination<'_>, credential: &Credential) -> Option<()> {
        let (port, address, name) = match destination {
            Destination::V4(octets, port) => (*port, *octets, None),
            Destination::V6(..) => return None,
            Destination::Name(name, port) => (*port, [0, 0, 0, 1], Some(*name)),
        };
        let user = credential.user.as_bytes();
        if user.len() > socks::NAME4_MAX || name.is_some_and(|name| name.len() > socks::NAME4_MAX) {
            return None;
        }
        if user.is_empty() && name.is_none() {
            let mut request = [0u8; 9];
            let total =
                socks::request4_into(socks::CMD4_CONNECT, port, address, user, name, &mut request)?;
            self.stream.write_all(&request[..total]).ok()?;
        } else {
            let mut request = [0u8; 520];
            let total =
                socks::request4_into(socks::CMD4_CONNECT, port, address, user, name, &mut request)?;
            self.stream.write_all(&request[..total]).ok()?;
        }
        let mut reply = [0u8; 8];
        read_exact_within(&mut self.stream, &mut reply, self.until)?;
        if reply[1] != socks::REPLY4_GRANTED {
            return None;
        }
        Some(())
    }
}

/// The relay a UDP association names: the address datagrams go to, and the control
/// connection that keeps the association alive.
pub(crate) struct Association<S> {
    /// The address the datagrams are sent to.
    pub(crate) relay: SocketAddr,
    /// The control connection. It stays open for the association's life: dropping it
    /// ends the association, which is what the reference does too.
    pub(crate) control: S,
}

/// Open a UDP association with a SOCKS5 server.
pub(crate) fn associate<S: Read + Write>(
    stream: S,
    credential: &Credential,
) -> Option<Association<S>> {
    let mut session = Session::open(stream, credential)?;
    let relay = session.associate()?;
    Some(Association {
        relay,
        control: session.into_stream(),
    })
}

/// Open a TCP tunnel to one destination through a SOCKS5 server.
pub(crate) fn connect<S: Read + Write>(
    stream: S,
    credential: &Credential,
    destination: &Destination<'_>,
    version: Version,
) -> Option<S> {
    match version {
        Version::V5 => {
            let mut session = Session::open(stream, credential)?;
            session.connect(destination)?;
            Some(session.into_stream())
        }
        Version::V4 => {
            let mut session = Session::open4(stream);
            session.connect4(destination, credential)?;
            Some(session.into_stream())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    /// The octets the client wrote, collected by the server end as it reads them.
    type Written = Arc<Mutex<Vec<u8>>>;

    /// An in-memory server end: the reply is already there, and every read and write is
    /// counted, so a handshake's syscall shape is exact rather than the scheduler's.
    struct Script {
        reply: Vec<u8>,
        at: usize,
        writes: Vec<u8>,
        write_calls: usize,
        read_calls: usize,
    }

    impl Script {
        fn new(reply: Vec<u8>) -> Self {
            Self {
                reply,
                at: 0,
                writes: Vec::with_capacity(512),
                write_calls: 0,
                read_calls: 0,
            }
        }
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read_calls += 1;
            let take = buf.len().min(self.reply.len() - self.at);
            buf[..take].copy_from_slice(&self.reply[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_calls += 1;
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A socket pair whose server end answers a scripted SOCKS5 handshake. The octets
    /// the client writes land in the slot, so a test can wait for them.
    fn pair(handler: impl Fn(&mut Connection, &Written) + Send + 'static) -> (Connection, Written) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let address = listener.local_addr().expect("an address");
        let client = std::net::TcpStream::connect(address).expect("a connection");
        let (server_end, _) = listener.accept().expect("an accept");
        let mut server = Connection::from(server_end);
        let written: Written = Arc::new(Mutex::new(Vec::new()));
        let slot = Arc::clone(&written);
        std::thread::spawn(move || {
            handler(&mut server, &slot);
            // Drain what the client still owes before the socket closes: a close with unread data in the queue answers the peer with a reset, and the bytes already sent would go with it.
            let mut sink = [0u8; 64];
            while let Ok(n) = server.read(&mut sink) {
                if n == 0 {
                    break;
                }
            }
        });
        (Connection::from(client), written)
    }

    /// The first `len` octets the client wrote, waiting for them to land.
    fn octets(slot: &Written, len: usize) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            {
                let seen = slot.lock().expect("the slot");
                if seen.len() >= len {
                    return seen[..len].to_vec();
                }
            }
            assert!(
                Instant::now() < deadline,
                "the client wrote fewer than {len} octets"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// A transport that polls: the first reads answer `WouldBlock` and the script is not consumed until they stop.
    struct Polled {
        inner: Script,
        polls: usize,
    }

    impl Read for Polled {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.polls > 0 {
                self.polls -= 1;
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.inner.read(buf)
        }
    }

    impl Write for Polled {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    /// A polled transport's timeout is another round: a handshake that reads once would fail here.
    #[test]
    fn a_handshake_read_waits_out_a_polled_transport() {
        let reply = vec![5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 0];
        let mut stream = Polled {
            inner: Script::new(reply),
            polls: 3,
        };
        assert!(connect(
            &mut stream,
            &Credential::default(),
            &Destination::V4([127, 0, 0, 1], 80),
            Version::V5,
        )
        .is_some());
    }

    #[test]
    fn the_greeting_is_the_byte_the_pinned_writer_writes() {
        let (client, written) = pair(|server, seen| {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).expect("the greeting");
            seen.lock().expect("the slot").extend_from_slice(&greeting);
            server.write_all(&[5, 0]).expect("the method reply");
            let mut request = [0u8; 10];
            server.read_exact(&mut request).expect("the request");
            seen.lock().expect("the slot").extend_from_slice(&request);
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .expect("the reply");
        });
        let mut session = Session::open(client, &Credential::default()).expect("a session");
        assert_eq!(octets(&written, 3), vec![5, 1, 0]);
        session
            .connect(&Destination::V4([10, 0, 0, 1], 80))
            .expect("a granted request");
        // The request follows the greeting: the version, the command, the reserved byte and the destination.
        assert_eq!(
            octets(&written, 13),
            vec![5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 1, 0, 80]
        );
    }

    #[test]
    fn a_credentialed_session_offers_the_user_method_and_sends_the_credential() {
        let credential = Credential {
            user: "u".to_owned(),
            pass: "p".to_owned(),
        };
        let (client, written) = pair(|server, seen| {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).expect("the greeting");
            seen.lock().expect("the slot").extend_from_slice(&greeting);
            server.write_all(&[5, 2]).expect("the method reply");
            let mut block = [0u8; 5];
            server.read_exact(&mut block).expect("the credential");
            seen.lock().expect("the slot").extend_from_slice(&block);
            server.write_all(&[1, 0]).expect("the credential reply");
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .expect("the reply");
        });
        let mut session = Session::open(client, &credential).expect("a session");
        assert_eq!(octets(&written, 3), vec![5, 1, 2]);
        // The RFC 1929 block rides next: the version, the name's length, the name, the password's length, the password.
        assert_eq!(octets(&written, 8), vec![5, 1, 2, 1, 1, b'u', 1, b'p']);
        session
            .connect(&Destination::V4([10, 0, 0, 1], 80))
            .expect("a granted request");
    }

    #[test]
    fn a_no_auth_connect_writes_the_greeting_then_the_request() {
        let reply = vec![5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 80];
        let script = Script::new(reply);
        let (stream, counts) = ferrox_core::alloc_count::measure(|| {
            crate::socks::connect(
                script,
                &Credential::default(),
                &Destination::V4([10, 0, 0, 1], 80),
                Version::V5,
            )
        });
        let stream = stream.expect("a granted tunnel");
        assert_eq!(stream.write_calls, 2, "the greeting, then the request");
        assert_eq!(stream.read_calls, 3, "method, reply head, bound address");
        assert_eq!(stream.writes, vec![5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 1, 0, 80]);
        assert_eq!(counts.allocs, 0, "the handshake takes no heap buffer");
    }

    #[test]
    fn a_credentialed_connect_writes_the_greeting_credential_and_request() {
        let reply = vec![5, 2, 1, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 80];
        let script = Script::new(reply);
        let credential = Credential {
            user: "u".to_owned(),
            pass: "p".to_owned(),
        };
        let (stream, counts) = ferrox_core::alloc_count::measure(|| {
            crate::socks::connect(
                script,
                &credential,
                &Destination::V4([10, 0, 0, 1], 80),
                Version::V5,
            )
        });
        let stream = stream.expect("a granted tunnel");
        assert_eq!(stream.write_calls, 3, "greeting, credential, then request");
        assert_eq!(
            stream.read_calls, 4,
            "method, status, reply head, bound address"
        );
        assert_eq!(
            stream.writes,
            vec![5, 1, 2, 1, 1, b'u', 1, b'p', 5, 1, 0, 1, 10, 0, 0, 1, 0, 80]
        );
        assert_eq!(counts.allocs, 0, "the handshake takes no heap buffer");
    }

    #[test]
    fn a_long_destination_and_a_long_bound_name_take_no_heap_buffer() {
        let name = vec![b'a'; 200];
        let mut reply = vec![5, 0, 5, 0, 0, 3, 200];
        reply.extend_from_slice(&name);
        reply.extend_from_slice(&80u16.to_be_bytes());
        let script = Script::new(reply);
        let (stream, counts) = ferrox_core::alloc_count::measure(|| {
            crate::socks::connect(
                script,
                &Credential::default(),
                &Destination::Name(&name, 443),
                Version::V5,
            )
        });
        let stream = stream.expect("a granted tunnel");
        assert_eq!(stream.write_calls, 2);
        assert_eq!(
            stream.read_calls, 4,
            "method, reply head, length, name+port"
        );
        assert_eq!(stream.writes[..3], [5, 1, 0]);
        assert_eq!(stream.writes[3..6], [5, 1, 0]);
        assert_eq!(stream.writes[6], 3);
        assert_eq!(stream.writes[7], 200);
        assert_eq!(&stream.writes[8..8 + 200], name.as_slice());
        assert_eq!(stream.writes[8 + 200..], [1, 187]);
        assert_eq!(counts.allocs, 0, "both slow-path rooms are on the stack");
    }

    #[test]
    fn a_socks4_session_writes_the_request_and_reads_the_reply() {
        let credential = Credential {
            user: "u".to_owned(),
            pass: "p".to_owned(),
        };
        let (client, written) = pair(|server, seen| {
            let mut request = [0u8; 10];
            server.read_exact(&mut request).expect("the request");
            seen.lock().expect("the slot").extend_from_slice(&request);
            server
                .write_all(&[0, 90, 0, 0, 0, 0, 0, 0])
                .expect("the reply");
        });
        let mut session = Session::open4(client);
        session
            .connect4(&Destination::V4([10, 0, 0, 1], 80), &credential)
            .expect("a granted request");
        // The request is one buffer: the version, the command, the port, the address, the user id and its NUL. SOCKS4 has no password.
        assert_eq!(
            octets(&written, 10),
            vec![4, 1, 0, 80, 10, 0, 0, 1, b'u', 0],
            "the user id is the credential's name and the password is not sent"
        );
    }

    #[test]
    fn a_socks4a_session_names_its_destination() {
        let (client, written) = pair(|server, seen| {
            let mut request = [0u8; 21];
            server.read_exact(&mut request).expect("the request");
            seen.lock().expect("the slot").extend_from_slice(&request);
            server
                .write_all(&[0, 90, 0, 0, 0, 0, 0, 0])
                .expect("the reply");
        });
        let mut session = Session::open4(client);
        session
            .connect4(
                &Destination::Name(b"example.com", 443),
                &Credential::default(),
            )
            .expect("a granted request");
        // The address is the 0.0.0.1 marker and the name follows the user id.
        assert_eq!(
            octets(&written, 21),
            vec![
                4, 1, 1, 187, 0, 0, 0, 1, 0, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0
            ],
            "the name rides the request instead of being resolved here"
        );
    }

    #[test]
    fn a_socks4_connect_takes_no_heap_buffer() {
        let script = Script::new(vec![0, 90, 0, 0, 0, 0, 0, 0]);
        let (stream, counts) = ferrox_core::alloc_count::measure(|| {
            crate::socks::connect(
                script,
                &Credential::default(),
                &Destination::V4([10, 0, 0, 1], 80),
                Version::V4,
            )
        });
        let stream = stream.expect("a granted tunnel");
        assert_eq!(stream.write_calls, 1);
        assert_eq!(stream.read_calls, 1);
        assert_eq!(stream.writes, vec![4, 1, 0, 80, 10, 0, 0, 1, 0]);
        assert_eq!(counts.allocs, 0, "the request is a stack block");
    }

    #[test]
    fn a_socks4a_connect_takes_no_heap_buffer() {
        let name = vec![b'a'; 200];
        let script = Script::new(vec![0, 90, 0, 0, 0, 0, 0, 0]);
        let (stream, counts) = ferrox_core::alloc_count::measure(|| {
            crate::socks::connect(
                script,
                &Credential::default(),
                &Destination::Name(&name, 443),
                Version::V4,
            )
        });
        let stream = stream.expect("a granted tunnel");
        assert_eq!(stream.write_calls, 1);
        assert_eq!(stream.read_calls, 1);
        assert_eq!(&stream.writes[..9], [4, 1, 1, 187, 0, 0, 0, 1, 0]);
        assert_eq!(&stream.writes[9..9 + 200], name.as_slice());
        assert_eq!(stream.writes[9 + 200], 0);
        assert_eq!(counts.allocs, 0, "the name rides the stack block");
    }

    #[test]
    fn a_socks4_session_refuses_a_refused_request() {
        let (client, _written) = pair(|server, _seen| {
            let mut request = [0u8; 9];
            server.read_exact(&mut request).expect("the request");
            server
                .write_all(&[0, 91, 0, 0, 0, 0, 0, 0])
                .expect("the refusal");
        });
        let mut session = Session::open4(client);
        assert!(session
            .connect4(&Destination::V4([10, 0, 0, 1], 80), &Credential::default())
            .is_none());
    }

    #[test]
    fn a_socks4_session_refuses_an_address_it_cannot_carry() {
        let (client, _written) = pair(|server, _seen| {
            // The client refuses an IPv6 address before it writes, so the server has nothing to read.
            let mut sink = [0u8; 1];
            let _ = server.read(&mut sink);
        });
        let mut session = Session::open4(client);
        assert!(session
            .connect4(&Destination::V6([0; 16], 80), &Credential::default())
            .is_none());
    }

    #[test]
    fn a_server_that_asks_for_a_method_this_session_cannot_serve_is_refused() {
        let (client, written) = pair(|server, seen| {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).expect("the greeting");
            seen.lock().expect("the slot").extend_from_slice(&greeting);
            server.write_all(&[5, 2]).expect("the method reply");
        });
        assert!(Session::open(client, &Credential::default()).is_none());
        assert_eq!(octets(&written, 3), vec![5, 1, 0]);
    }

    #[test]
    fn a_credentialed_session_refuses_a_server_that_answers_no_auth() {
        // The pinned Go client fails when the server picks a method it did not offer (`"auth method not supported."`), so a credentialed session refuses a server that answers `[5, 0]` rather than tunnel without the credential.
        let credential = Credential {
            user: "u".to_owned(),
            pass: "p".to_owned(),
        };
        let (client, written) = pair(|server, seen| {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).expect("the greeting");
            seen.lock().expect("the slot").extend_from_slice(&greeting);
            server.write_all(&[5, 0]).expect("the method reply");
        });
        assert!(Session::open(client, &credential).is_none());
        assert_eq!(octets(&written, 3), vec![5, 1, 2]);
    }

    #[test]
    fn a_half_written_credential_refuses_the_session() {
        // A credential that names no password must not be downgraded to no authentication: the session is refused instead.
        let credential = Credential {
            user: "u".to_owned(),
            pass: String::new(),
        };
        let (client, written) = pair(|server, _seen| {
            server.write_all(&[5, 0]).expect("the method reply");
            // The session refuses the credential before it writes anything, so the server has no greeting to read.
            let mut sink = [0u8; 3];
            let _ = server.read(&mut sink);
        });
        assert!(Session::open(client, &credential).is_none());
        assert!(
            octets(&written, 0).is_empty(),
            "the session writes no greeting at all"
        );
    }

    #[test]
    fn a_refused_request_is_refused() {
        let (client, _written) = pair(|server, _seen| {
            server.write_all(&[5, 0]).expect("the method reply");
            server
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("the refusal");
        });
        let mut session = Session::open(client, &Credential::default()).expect("a session");
        assert!(session
            .connect(&Destination::V4([10, 0, 0, 1], 80))
            .is_none());
    }

    #[test]
    fn the_associate_request_names_no_destination() {
        let (client, written) = pair(|server, seen| {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).expect("the greeting");
            seen.lock().expect("the slot").extend_from_slice(&greeting);
            server.write_all(&[5, 0]).expect("the method reply");
            let mut request = [0u8; 10];
            server.read_exact(&mut request).expect("the request");
            seen.lock().expect("the slot").extend_from_slice(&request);
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90])
                .expect("the reply");
        });
        let mut session = Session::open(client, &Credential::default()).expect("a session");
        let relay = session.associate().expect("an association");
        assert_eq!(relay, "127.0.0.1:8080".parse().expect("an address"));
        // The greeting, then the request: ten bytes of version, command, reserved and the all-zero IPv4 address.
        assert_eq!(
            octets(&written, 13),
            vec![5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    /// A server may name the relay a UDP association uses; that name must take the bounded resolver, not a lookup that can park the flow forever.
    #[test]
    fn an_association_reply_name_takes_the_bounded_resolver() {
        crate::proxy::forget_lookup("localhost", 53);
        let (client, _written) = pair(|server, _seen| {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).expect("the greeting");
            server.write_all(&[5, 0]).expect("the method reply");
            let mut request = [0u8; 10];
            server.read_exact(&mut request).expect("the request");
            let name = b"localhost";
            let mut reply = vec![5, 0, 0, 3, name.len() as u8];
            reply.extend_from_slice(name);
            reply.extend_from_slice(&53u16.to_be_bytes());
            server.write_all(&reply).expect("the reply");
        });
        let mut session = Session::open(client, &Credential::default()).expect("a session");
        let relay = session.associate().expect("localhost has a relay");
        assert_eq!(relay.port(), 53, "the reply's port rides the lookup");
        assert!(
            crate::proxy::lookup_is_remembered("localhost", 53),
            "the association took the bounded resolver"
        );
    }

    /// The three address types RFC 1928 gives the reply's bound address, read from one
    /// server that grants the tunnel with each: IPv4 and IPv6 stay the addresses they
    /// came as, and a name is read as a name — the reply is granted, the tunnel
    /// carries on, no refusal after a grant.
    #[test]
    fn a_tunnel_carries_a_reply_that_binds_any_rfc_edge() {
        let probe = |reply: Vec<u8>| {
            let (client, written) = pair(move |server, seen| {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).expect("the greeting");
                server.write_all(&[5, 0]).expect("the method reply");
                let mut request = [0u8; 10];
                server.read_exact(&mut request).expect("the request");
                server.write_all(&reply).expect("the reply");
                // The reply is the grant, so the client's next write is the tunnel's first bytes.
                let mut after = [0u8; 4];
                server.read_exact(&mut after).expect("the tunnel's bytes");
                seen.lock().expect("the slot").extend_from_slice(&after);
            });
            let mut session = Session::open(client, &Credential::default()).expect("a session");
            session
                .connect(&Destination::Name(b"a.b", 80))
                .expect("a granted tunnel");
            session.stream.write_all(b"PING").expect("writes");
            octets(&written, 4)
        };
        assert_eq!(probe(vec![5, 0, 0, 1, 1, 2, 3, 4, 0, 80]), b"PING");
        assert_eq!(probe(vec![5, 0, 0, 3, 3, b'a', b'.', b'b', 0, 80]), b"PING");
        assert_eq!(
            probe(vec![
                5, 0, 0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80
            ]),
            b"PING"
        );
    }

    /// The relay a server binds with a name is dialled, not refused: the reference
    /// hands the bound address to its dialer, which resolves the name — `localhost`
    /// answers here without a wire, so the association carries the loopback relay.
    #[test]
    fn an_association_dials_the_relay_the_server_bound_by_name() {
        let (client, _written) = pair(|server, _seen| {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).expect("the greeting");
            server.write_all(&[5, 0]).expect("the method reply");
            let mut request = [0u8; 10];
            server.read_exact(&mut request).expect("the request");
            server
                .write_all(&[
                    5, 0, 0, 3, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x1f, 0x90,
                ])
                .expect("the reply");
        });
        let mut session = Session::open(client, &Credential::default()).expect("a session");
        let relay = session.associate().expect("an association");
        assert!(
            relay.ip().is_loopback(),
            "the name dialled a loopback relay: {relay}"
        );
        assert_eq!(relay.port(), 8080);
    }
}
