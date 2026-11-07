//! HTTP/3 over QUIC for the CDN-fronted meek entries that carry QUIC.

use crate::psiphon_webrtc::WebRtcStream;
use quiche::h3::NameValue as _;
use std::io;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAX_DATAGRAM: usize = 1350;
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// One HTTP/3 response.
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

/// A datagram path for QUIC: a UDP socket or an in-proxy WebRTC channel.
enum Link {
    Udp(UdpSocket),
    WebRtc(WebRtcStream),
}

impl Link {
    fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.send(buffer),
            Self::WebRtc(stream) => stream.write(buffer),
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.recv(buffer),
            Self::WebRtc(stream) => stream.read(buffer),
        }
    }

    fn set_read_timeout(&mut self, wait: Duration) -> io::Result<()> {
        match self {
            Self::Udp(socket) => socket.set_read_timeout(Some(wait)),
            Self::WebRtc(stream) => {
                stream.set_read_timeout(Some(wait));
                Ok(())
            }
        }
    }

    fn addresses(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        match self {
            Self::Udp(socket) => Ok((socket.local_addr()?, socket.peer_addr()?)),
            Self::WebRtc(_) => Ok((
                SocketAddr::from(([0, 0, 0, 0], 0)),
                SocketAddr::from(([0, 0, 0, 0], 0)),
            )),
        }
    }
}

/// A persistent HTTP/3 connection to one front.
pub(crate) struct H3 {
    link: Link,
    peer: SocketAddr,
    local: SocketAddr,
    conn: quiche::Connection,
    http3: quiche::h3::Connection,
    stream: Option<u64>,
    response: Response,
    finished: bool,
    read_chunk: usize,
}

impl H3 {
    /// Open a QUIC connection carrying HTTP/3 to one front.
    pub(crate) fn connect(
        dial: &str,
        port: u16,
        sni: &str,
        timeout: Duration,
        dns: &crate::psiphon_dns::Config,
    ) -> Result<Self, String> {
        let peer = crate::psiphon_dns::resolve_with(dns, dial, port)
            .map_err(|error| format!("psiphon h3 resolve {dial}: {error}"))?
            .into_iter()
            .next()
            .ok_or_else(|| format!("psiphon h3 resolve {dial}: no address"))?;
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).map_err(|error| format!("psiphon h3 bind: {error}"))?;
        socket
            .connect(peer)
            .map_err(|error| format!("psiphon h3 connect {dial}: {error}"))?;
        socket
            .set_read_timeout(Some(timeout))
            .and_then(|()| socket.set_write_timeout(Some(timeout)))
            .map_err(|error| format!("psiphon h3 socket: {error}"))?;
        Self::connect_link(Link::Udp(socket), dial, sni, timeout)
    }

    /// Open HTTP/3 over an in-proxy WebRTC datagram channel.
    pub(crate) fn connect_over(
        stream: WebRtcStream,
        dial: &str,
        sni: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        Self::connect_link(Link::WebRtc(stream), dial, sni, timeout)
    }

    /// Open HTTP/3 over one datagram path.
    #[allow(clippy::too_many_lines)]
    fn connect_link(
        mut link: Link,
        dial: &str,
        sni: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        let (local, peer) = link
            .addresses()
            .map_err(|error| format!("psiphon h3 local address: {error}"))?;
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|error| format!("psiphon h3 config: {error}"))?;
        // The front certificate is cover; the inner SSH host key authenticates the server.
        config.verify_peer(false);
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|error| format!("psiphon h3 protocol: {error}"))?;
        config.set_max_idle_timeout(millis(timeout));
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM);
        config.set_initial_max_data(16 * 1024 * 1024);
        config.set_initial_max_stream_data_bidi_local(4 * 1024 * 1024);
        config.set_initial_max_stream_data_bidi_remote(4 * 1024 * 1024);
        config.set_initial_max_stream_data_uni(4 * 1024 * 1024);
        config.set_initial_max_streams_bidi(16);
        config.set_initial_max_streams_uni(16);
        config.set_disable_active_migration(true);
        let scid = crate::psiphon_ssh::random::<{ quiche::MAX_CONN_ID_LEN }>();
        let scid = quiche::ConnectionId::from_ref(&scid);
        let sni = (!sni.is_empty()).then_some(sni);
        let mut conn = quiche::connect(sni, &scid, local, peer, &mut config)
            .map_err(|error| format!("psiphon h3 start {dial}: {error}"))?;
        let deadline = Instant::now() + timeout;
        let mut buffer = vec![0u8; 65535];
        let mut out = [0u8; MAX_DATAGRAM];
        while !conn.is_established() {
            loop {
                match conn.send(&mut out) {
                    Ok((write, _)) => {
                        link.send(&out[..write])
                            .map_err(|error| format!("psiphon h3 send: {error}"))?;
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => return Err(format!("psiphon h3 send: {error}")),
                }
            }
            let now = Instant::now();
            if now >= deadline || conn.is_closed() {
                return Err(format!("psiphon h3 handshake {dial} timed out"));
            }
            let wait = deadline
                .saturating_duration_since(now)
                .min(conn.timeout().unwrap_or(Duration::ZERO))
                .max(Duration::from_millis(1));
            link.set_read_timeout(wait)
                .map_err(|error| format!("psiphon h3 socket: {error}"))?;
            match link.receive(&mut buffer) {
                Ok(read) => {
                    let info = quiche::RecvInfo {
                        from: peer,
                        to: local,
                    };
                    conn.recv(&mut buffer[..read], info)
                        .map_err(|error| format!("psiphon h3 receive: {error}"))?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    conn.on_timeout();
                }
                Err(error) => return Err(format!("psiphon h3 receive: {error}")),
            }
        }
        let http3_config =
            quiche::h3::Config::new().map_err(|error| format!("psiphon h3 settings: {error}"))?;
        let http3 = quiche::h3::Connection::with_transport(&mut conn, &http3_config)
            .map_err(|error| format!("psiphon h3 transport: {error}"))?;
        Ok(Self {
            link,
            peer,
            local,
            conn,
            http3,
            stream: None,
            response: Response {
                status: 0,
                headers: Vec::new(),
                body: Vec::new(),
            },
            finished: false,
            read_chunk: 16 * 1024,
        })
    }

    /// Whether the peer closed the QUIC connection.
    pub(crate) fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Send one request and collect its response.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn round_trip(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
        read_chunk: usize,
    ) -> Result<Response, String> {
        self.read_chunk = read_chunk.max(1);
        let mut list = vec![
            quiche::h3::Header::new(b":method", b"POST"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", host.as_bytes()),
            quiche::h3::Header::new(b":path", path.as_bytes()),
        ];
        for (name, value) in headers {
            list.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
        }
        self.response = Response {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
        };
        self.finished = false;
        let stream = self
            .http3
            .send_request(&mut self.conn, &list, body.is_empty())
            .map_err(|error| format!("psiphon h3 request: {error}"))?;
        self.stream = Some(stream);
        let deadline = Instant::now() + timeout;
        let mut buffer = vec![0u8; 65535];
        let mut out = [0u8; MAX_DATAGRAM];
        if !body.is_empty() {
            let mut sent = 0;
            while sent < body.len() {
                match self
                    .http3
                    .send_body(&mut self.conn, stream, &body[sent..], true)
                {
                    Ok(0) => return Err("psiphon h3 body was not sent".to_owned()),
                    Ok(wrote) => sent += wrote,
                    Err(quiche::h3::Error::Done) => {
                        self.flush(&mut out)?;
                        self.receive(&mut buffer, deadline)?;
                    }
                    Err(error) => return Err(format!("psiphon h3 body: {error}")),
                }
            }
        }
        self.flush(&mut out)?;
        while !self.finished {
            self.receive(&mut buffer, deadline)?;
            self.flush(&mut out)?;
        }
        if self.response.status == 0 {
            return Err("psiphon h3 response had no status".to_owned());
        }
        Ok(std::mem::replace(
            &mut self.response,
            Response {
                status: 0,
                headers: Vec::new(),
                body: Vec::new(),
            },
        ))
    }

    fn receive(&mut self, buffer: &mut [u8], deadline: Instant) -> Result<(), String> {
        let now = Instant::now();
        if now >= deadline || self.conn.is_closed() {
            return Err("psiphon h3 response timed out".to_owned());
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(self.conn.timeout().unwrap_or(Duration::ZERO))
            .max(Duration::from_millis(1));
        self.link
            .set_read_timeout(wait)
            .map_err(|error| format!("psiphon h3 socket: {error}"))?;
        match self.link.receive(buffer) {
            Ok(read) => {
                let info = quiche::RecvInfo {
                    from: self.peer,
                    to: self.local,
                };
                self.conn
                    .recv(&mut buffer[..read], info)
                    .map_err(|error| format!("psiphon h3 receive: {error}"))?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                self.conn.on_timeout();
            }
            Err(error) => return Err(format!("psiphon h3 receive: {error}")),
        }
        self.poll()
    }

    /// Write every queued QUIC packet to the peer.
    fn flush(&mut self, out: &mut [u8]) -> Result<(), String> {
        loop {
            match self.conn.send(out) {
                Ok((write, _)) => {
                    self.link
                        .send(&out[..write])
                        .map_err(|error| format!("psiphon h3 send: {error}"))?;
                }
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(format!("psiphon h3 send: {error}")),
            }
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        let Some(stream) = self.stream else {
            return Ok(());
        };
        loop {
            match self.http3.poll(&mut self.conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) if id == stream => {
                    for header in list {
                        let name = String::from_utf8_lossy(header.name()).to_string();
                        let value = String::from_utf8_lossy(header.value()).to_string();
                        if name == ":status" {
                            self.response.status = value.parse().unwrap_or(0);
                        } else if !name.starts_with(':') {
                            self.response.headers.push((name, value));
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Data)) if id == stream => {
                    let mut chunk = [0u8; 16 * 1024];
                    let limit = self.read_chunk.min(chunk.len()).max(1);
                    let chunk = &mut chunk[..limit];
                    loop {
                        match self.http3.recv_body(&mut self.conn, stream, chunk) {
                            Ok(0) | Err(quiche::h3::Error::Done) => break,
                            Ok(read) => {
                                if self.response.body.len() + read > MAX_RESPONSE {
                                    return Err("psiphon h3 response is too large".to_owned());
                                }
                                self.response.body.extend_from_slice(&chunk[..read]);
                            }
                            Err(error) => {
                                return Err(format!("psiphon h3 response body: {error}"));
                            }
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) if id == stream => {
                    self.finished = true;
                    self.stream = None;
                    break;
                }
                Ok((id, quiche::h3::Event::Reset(code))) if id == stream => {
                    return Err(format!("psiphon h3 response reset {code}"));
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => return Err(format!("psiphon h3 response: {error}")),
            }
        }
        Ok(())
    }
}

/// Clamp a duration to the millisecond field a QUIC setting takes.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
