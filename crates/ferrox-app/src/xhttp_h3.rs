// xHTTP over HTTP/3: one QUIC connection carries the same request streams the H2 lane does, so stream-one, stream-up and packet-up keep their shapes and only the framing under them changes.

use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::frames;
use ferrox_core::foxy::hpack;

use crate::quic::{self, Activity, Datagram};
use crate::xhttp::{XhttpMode, XhttpSettings};

const TICK: Duration = Duration::from_millis(20);
const POLL: Duration = Duration::from_millis(5);
const READ_ROOM: usize = 16 * 1024;

/// One request stream's byte transport: a served stream on the QUIC driver, or one the client
/// opened on its own connection. Both clones share the connection, never the buffered bytes.
#[derive(Clone)]
pub(crate) enum Wire {
    Server(quic::QuicStream),
    Client(ClientStream),
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Server(stream) => stream.read(buf),
            Self::Client(stream) => stream.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Server(stream) => stream.write(buf),
            Self::Client(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Server(stream) => stream.flush(),
            Self::Client(stream) => stream.flush(),
        }
    }
}

impl Wire {
    fn activity(&self) -> Arc<Activity> {
        match self {
            Self::Server(stream) => stream.activity(),
            Self::Client(stream) => Arc::clone(&stream.activity),
        }
    }

    fn fin(&self) {
        match self {
            Self::Server(stream) => {
                stream.fin();
            }
            Self::Client(stream) => stream.fin(),
        }
    }

    fn close(&self) {
        match self {
            Self::Server(stream) => stream.close(),
            Self::Client(stream) => stream.close(),
        }
    }
}

/// The request stream as the shared dispatch reads it: HEADERS becomes the H1 head `accept_core`
/// parses, and every DATA frame after it is body.
pub(crate) struct H3Reader {
    wire: Wire,
    buf: Vec<u8>,
    room: Vec<u8>,
    payload: Vec<u8>,
    at: usize,
    head: Option<Vec<u8>>,
    status: Option<u16>,
    frame_left: usize,
    ended: bool,
    head_seen: bool,
    expect_request: bool,
    idle_since: Option<Instant>,
    activity: Arc<Activity>,
    deadline: Option<Instant>,
}

impl H3Reader {
    fn new(wire: Wire) -> Self {
        let activity = wire.activity();
        let expect_request = matches!(&wire, Wire::Server(_));
        Self {
            wire,
            buf: Vec::new(),
            room: vec![0; READ_ROOM],
            payload: Vec::new(),
            at: 0,
            head: None,
            status: None,
            frame_left: 0,
            ended: false,
            head_seen: false,
            expect_request,
            idle_since: None,
            activity,
            deadline: None,
        }
    }

    pub(crate) fn status(&self) -> Option<u16> {
        self.status
    }

    /// Whether this POST's own response deadline has passed.
    fn expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Bounds this POST's response wait, independently of the connection's activity clock.
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }

    /// Drops this request's stream in both directions.
    fn reset(&self) {
        self.wire.close();
    }

    fn idle_expired(&self, since: Instant) -> bool {
        if self.expired() {
            return true;
        }
        let idle = if self.head_seen {
            self.activity.age()
        } else {
            since.elapsed()
        };
        idle >= crate::budgets::relay_stall()
    }

    /// The H1 head the request's HEADERS frame names, with the connection framing the reference's
    /// hub never writes: an H3 stream ends by itself, so the head says chunked and nothing parses it.
    pub(crate) fn read_head(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        while self.head.is_none() && !self.ended {
            self.step()?;
            if self.head_seen && self.head.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "h3 request head is missing",
                ));
            }
        }
        Ok(self.head.take())
    }

    /// Parse the frames already buffered, then take one datagram's worth when nothing completes.
    fn step(&mut self) -> std::io::Result<()> {
        loop {
            if self.frame_left > 0 {
                self.fill_data()?;
                if !self.payload.is_empty() {
                    self.idle_since = None;
                    return Ok(());
                }
                if self.ended {
                    return Ok(());
                }
                continue;
            }
            self.parse()?;
            if self.expect_request && self.head.is_some() {
                return Ok(());
            }
            if self.frame_left > 0 {
                self.fill_data()?;
                if !self.payload.is_empty() {
                    self.idle_since = None;
                    return Ok(());
                }
                if self.ended {
                    return Ok(());
                }
                continue;
            }
            if self.ended || self.head.is_some() {
                return Ok(());
            }
            match self.wire.read(&mut self.room) {
                Ok(0) => {
                    self.ended = true;
                    return Ok(());
                }
                Ok(n) => {
                    self.buf.extend_from_slice(&self.room[..n]);
                    self.idle_since = None;
                }
                Err(error) if crate::proxy::is_timeout(&error) => {
                    if crate::proxy::body_deadline().is_some_and(|until| Instant::now() >= until) {
                        return Err(error);
                    }
                    let since = *self.idle_since.get_or_insert_with(Instant::now);
                    if self.idle_expired(since) {
                        return Err(std::io::Error::other("h3 request stalled"));
                    }
                    if crate::proxy::relay_step_owns_poll()
                        && since.elapsed() >= crate::budgets::RELAY_POLL
                    {
                        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                    }
                    std::thread::sleep(POLL);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Consume every complete frame in the buffer, leaving an incomplete one's header in place.
    fn parse(&mut self) -> std::io::Result<()> {
        let mut at = 0usize;
        let mut took = false;
        loop {
            let start = at;
            let Some(frame) = frames::h3_frame(&self.buf, &mut at) else {
                at = start;
                break;
            };
            let Ok(length) = usize::try_from(frame.length) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "h3 frame too long",
                ));
            };
            if frame.kind != frames::H3_DATA && length > crate::xhttp::HEAD_LIMIT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "h3 frame too large",
                ));
            }
            if frame.kind == frames::H3_DATA {
                if !self.head_seen {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "h3 data before headers",
                    ));
                }
                self.buf.drain(..at);
                self.frame_left = length;
                if length == 0 {
                    at = 0;
                    took = false;
                    continue;
                }
                return Ok(());
            }
            let Some(end) = at.checked_add(length) else {
                at = start;
                break;
            };
            if end > self.buf.len() {
                at = start;
                break;
            }
            let payload = &self.buf[at..end];
            at = end;
            match frame.kind {
                frames::H3_HEADERS => {
                    self.head_seen = true;
                    if self.head.is_none() && self.status.is_none() {
                        self.head =
                            hpack::qpack_fields(payload).and_then(|fields| synth_head(&fields));
                        self.status = hpack::qpack_status(payload);
                        if self.expect_request && self.head.is_none() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "h3 request head is missing",
                            ));
                        }
                    }
                }
                frames::H3_RESET => self.ended = true,
                _ => {}
            }
            took = true;
        }
        if took {
            self.buf.drain(..at);
        }
        Ok(())
    }

    /// Take the next piece of the DATA frame now open, reading only that frame's remaining bytes.
    fn fill_data(&mut self) -> std::io::Result<()> {
        loop {
            if self.frame_left == 0 {
                return Ok(());
            }
            if !self.buf.is_empty() {
                let take = self.frame_left.min(self.buf.len());
                self.payload.extend_from_slice(&self.buf[..take]);
                self.buf.drain(..take);
                self.frame_left -= take;
                return Ok(());
            }
            match self.wire.read(&mut self.room) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "h3 data frame ended early",
                    ));
                }
                Ok(n) => {
                    let take = n.min(self.frame_left);
                    self.payload.extend_from_slice(&self.room[..take]);
                    if n > take {
                        self.buf.extend_from_slice(&self.room[take..n]);
                    }
                    self.frame_left -= take;
                    self.idle_since = None;
                    return Ok(());
                }
                Err(error) if crate::proxy::is_timeout(&error) => {
                    if crate::proxy::body_deadline().is_some_and(|until| Instant::now() >= until) {
                        return Err(error);
                    }
                    let since = *self.idle_since.get_or_insert_with(Instant::now);
                    if self.idle_expired(since) {
                        return Err(std::io::Error::other("h3 request stalled"));
                    }
                    if crate::proxy::relay_step_owns_poll()
                        && since.elapsed() >= crate::budgets::RELAY_POLL
                    {
                        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                    }
                    std::thread::sleep(POLL);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn advance(&mut self) -> std::io::Result<bool> {
        if self.expired() {
            return Err(std::io::Error::other("h3 request stalled"));
        }
        if self.at < self.payload.len() {
            return Ok(true);
        }
        self.payload.clear();
        self.at = 0;
        if self.ended {
            return Ok(false);
        }
        if self.frame_left > 0 {
            self.fill_data()?;
            return Ok(!self.payload.is_empty());
        }
        self.step()?;
        Ok(self.at < self.payload.len())
    }
}

fn status_ok(status: Option<u16>) -> std::io::Result<()> {
    if status.is_some_and(|code| !(200..300).contains(&code)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "h3 response is not 2xx",
        ));
    }
    Ok(())
}

impl Read for H3Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let more = self.advance()?;
        status_ok(self.status)?;
        if !more {
            return Ok(0);
        }
        let n = (self.payload.len() - self.at).min(buf.len());
        buf[..n].copy_from_slice(&self.payload[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

impl crate::proxy::WindowRead for H3Reader {
    fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
        let more = self.advance()?;
        status_ok(self.status)?;
        if !more {
            return Ok(crate::proxy::Window::empty());
        }
        let start = self.at;
        self.at = self.payload.len();
        Ok(crate::proxy::Window::one(&self.payload[start..]))
    }
}

/// The write half: the dispatch's H1 response head becomes HEADERS, everything after it DATA.
struct H3Writer {
    wire: Wire,
    head: Vec<u8>,
    headed: bool,
}

impl H3Writer {
    fn new(wire: Wire) -> Self {
        Self {
            wire,
            head: Vec::new(),
            headed: false,
        }
    }
}

impl Write for H3Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.headed {
            self.head.extend_from_slice(buf);
            let Some(at) = head_end(&self.head) else {
                return Ok(buf.len());
            };
            let head = std::mem::take(&mut self.head);
            let text = std::str::from_utf8(&head[..at]).unwrap_or_default();
            if !send_fields(&self.wire, frames::H3_HEADERS, &response_fields(text)) {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            self.headed = true;
            let body = &head[at + 4..];
            if !body.is_empty() && !send_data(&self.wire, body) {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            return Ok(buf.len());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if !send_data(&self.wire, buf) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::proxy::FrameWrite for H3Writer {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        parts.iter().all(|part| self.write_all(part).is_ok())
    }
}

/// The stream a session writes through once its head is out; the dispatch keys on this instead of
/// the H2 stream out, so the body stays raw on both HTTP/2 and HTTP/3.
#[derive(Clone)]
pub(crate) struct H3StreamOut {
    wire: Wire,
}

impl std::fmt::Debug for H3StreamOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("H3StreamOut")
    }
}

impl H3StreamOut {
    pub(crate) fn data(&self, payload: &[u8]) -> bool {
        payload.is_empty() || send_data(&self.wire, payload)
    }

    pub(crate) fn bind_session(_sid: &str) {}

    pub(crate) fn bind_upload(_sid: &str) {}

    pub(crate) fn end(&self) {
        self.wire.fin();
    }

    pub(crate) fn reset(&self) {
        self.wire.close();
    }
}

fn send_data(wire: &Wire, payload: &[u8]) -> bool {
    let mut frame = Vec::with_capacity(payload.len() + 9);
    frames::quic_varint(&mut frame, frames::H3_DATA);
    frames::quic_varint(&mut frame, payload.len() as u64);
    frame.extend_from_slice(payload);
    wire_ready(wire, &frame)
}

fn send_fields(wire: &Wire, kind: u64, fields: &[(String, String)]) -> bool {
    let refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut block = Vec::new();
    hpack::qpack_literal_many(&refs, &mut block);
    let mut frame = Vec::with_capacity(block.len() + 9);
    frames::quic_varint(&mut frame, kind);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    wire_ready(wire, &frame)
}

/// A frame's bytes go down one clone, and the connection keeps pumping the other direction.
fn wire_ready(wire: &Wire, bytes: &[u8]) -> bool {
    let mut wire = wire.clone();
    wire.write_all(bytes).is_ok()
}

fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn response_fields(head: &str) -> Vec<(String, String)> {
    let mut fields = Vec::with_capacity(2 + head.matches("\r\n").count());
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .unwrap_or("200");
    fields.push((":status".to_owned(), status.to_owned()));
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        fields.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    fields
}

/// The head `accept_core` parses from a request's fields: the same shape the H2 lane synthesises.
fn synth_head(fields: &[(Vec<u8>, Vec<u8>)]) -> Option<Vec<u8>> {
    let field = |name: &[u8]| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_slice())
    };
    let method = field(b":method")?;
    let target = field(b":path")?;
    let mut head = Vec::with_capacity(method.len() + target.len() + 64);
    head.extend_from_slice(method);
    head.push(b' ');
    head.extend_from_slice(target);
    head.extend_from_slice(b" HTTP/3\r\n");
    if let Some(authority) = field(b":authority") {
        head.extend_from_slice(b"Host: ");
        head.extend_from_slice(authority);
        head.extend_from_slice(b"\r\n");
    }
    for (name, value) in fields {
        if name.starts_with(b":") {
            continue;
        }
        head.extend_from_slice(name);
        head.extend_from_slice(b": ");
        head.extend_from_slice(value);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
    Some(head)
}

/// The dial head as request fields: the pseudo-headers the H2 lane's block carries, with this
/// connection's own framing dropped.
fn block_from_text(head: &str, host: &str, scheme: &str) -> Vec<u8> {
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split_ascii_whitespace();
    let method = request.next().unwrap_or("POST");
    let target = request.next().unwrap_or("/");
    let mut fields = vec![
        (":method".to_owned(), method.to_owned()),
        (":path".to_owned(), target.to_owned()),
        (":scheme".to_owned(), scheme.to_owned()),
        (":authority".to_owned(), host.to_owned()),
    ];
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("te")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        fields.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    let refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut block = Vec::new();
    hpack::qpack_literal_many(&refs, &mut block);
    block
}

pub(crate) trait H3Service: Send + Sync {
    fn serve(
        &self,
        reader: Box<dyn crate::proxy::WindowRead + Send>,
        writer: crate::xhttp::XhttpWriter,
    );
}

/// Bind the H3 listener and run its shared QUIC driver; the returned port is the bound one.
pub(crate) fn serve_inbound(
    address: &str,
    identity: &ferrox_core::tls::TlsServerConfig,
    settings: &XhttpSettings,
    service: Arc<dyn H3Service>,
    stop: Option<Arc<crate::proxy::Stop>>,
) -> Result<u16, String> {
    let config = quic::serve_config(identity).ok_or("unreadable xhttp h3 identity")?;
    let sock = quic::bind_datagram_plain(address)
        .map_err(|error| format!("cannot bind xhttp h3 `{address}`: {error}"))?;
    let port = sock
        .local_addr()
        .map_err(|error| format!("xhttp h3 `{address}` has no local address: {error}"))?
        .port();
    let settings = settings.clone();
    let serve: quic::Serve = Arc::new(move |stream| {
        stream.preface_h3();
        serve_one(&stream, &settings, &service);
    });
    let stop_flag = stop
        .as_ref()
        .map_or_else(|| Arc::new(AtomicBool::new(false)), |stop| stop.shared());
    std::thread::Builder::new()
        .name("xhttp-h3".to_owned())
        .spawn(move || {
            quic::serve_loop(
                Datagram::plain(sock),
                &Arc::new(Mutex::new(config)),
                &serve,
                &stop_flag,
            );
            if let Some(stop) = stop {
                stop.mark_closed();
            }
        })
        .map_err(|error| format!("xhttp h3 listener: {error}"))?;
    Ok(port)
}

fn serve_one(stream: &quic::QuicStream, settings: &XhttpSettings, service: &Arc<dyn H3Service>) {
    let mut reader = H3Reader::new(Wire::Server(stream.clone()));
    let Ok(Some(head)) = reader.read_head() else {
        stream.close();
        return;
    };
    let writer = H3Writer::new(Wire::Server(stream.clone()));
    let out = H3StreamOut {
        wire: Wire::Server(stream.clone()),
    };
    let upload: crate::xhttp::Upload<H3Reader> = crate::xhttp::Upload::Window(Box::new(reader));
    match crate::xhttp::accept_core(
        &head,
        Vec::new(),
        upload,
        writer,
        settings,
        Some(crate::xhttp::StreamOut::H3(out.clone())),
        None,
    ) {
        crate::xhttp::Served::Session(reader, writer) => {
            service.serve(reader, writer);
        }
        _ => {
            out.end();
        }
    }
}

/// One client request stream on the connection the session dialled.
#[derive(Clone)]
pub(crate) struct ClientStream {
    _owner: Arc<H3Client>,
    conn: Arc<Mutex<quiche::Connection>>,
    sock: Arc<Datagram>,
    id: u64,
    peer_fin: Arc<AtomicBool>,
    activity: Arc<Activity>,
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.peer_fin.load(Ordering::Relaxed) {
            return Ok(0);
        }
        let deadline = Instant::now() + crate::budgets::RELAY_POLL;
        loop {
            let Ok(mut conn) = self.conn.lock() else {
                return Err(std::io::Error::other("h3 connection lock poisoned"));
            };
            match conn.stream_recv(self.id, buf) {
                Ok((0, true)) => {
                    self.peer_fin.store(true, Ordering::Relaxed);
                    return Ok(0);
                }
                Ok((n, fin)) => {
                    if n > 0 {
                        self.peer_fin.store(fin, Ordering::Relaxed);
                        self.activity.touch();
                        quic::flush_egress(&mut conn, &self.sock);
                        return Ok(n);
                    }
                }
                Err(quiche::Error::Done) => {}
                Err(error) => {
                    return Err(std::io::Error::other(format!("h3 stream read: {error:?}")));
                }
            }
            if conn.is_closed() {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            drop(conn);
            if Instant::now() >= deadline {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            std::thread::sleep(POLL);
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + crate::budgets::relay_stall();
        let mut rest = buf;
        while !rest.is_empty() {
            let Ok(mut conn) = self.conn.lock() else {
                return Err(std::io::Error::other("h3 connection lock poisoned"));
            };
            match conn.stream_send(self.id, rest, false) {
                Ok(0) | Err(quiche::Error::Done) => {
                    drop(conn);
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("h3 stream send timed out"));
                    }
                    std::thread::sleep(POLL);
                }
                Ok(n) => {
                    self.activity.touch();
                    quic::flush_egress(&mut conn, &self.sock);
                    rest = &rest[n..];
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!("h3 stream send: {error:?}")));
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("h3 connection lock poisoned"));
        };
        quic::flush_egress(&mut conn, &self.sock);
        Ok(())
    }
}

impl ClientStream {
    fn fin(&self) {
        let Ok(mut conn) = self.conn.lock() else {
            return;
        };
        let _ = conn.stream_send(self.id, &[], true);
        quic::flush_egress(&mut conn, &self.sock);
    }

    fn close(&self) {
        let Ok(mut conn) = self.conn.lock() else {
            return;
        };
        let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Read, 0);
        let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Write, 0);
        quic::flush_egress(&mut conn, &self.sock);
    }
}

/// The client side of one H3 connection: streams open on the shared connection and one pump reads
/// its socket, so an upload waits on credit without stopping the downlink's datagrams.
pub(crate) struct H3Client {
    conn: Arc<Mutex<quiche::Connection>>,
    sock: Arc<Datagram>,
    next: AtomicU64,
    dead: Arc<AtomicBool>,
}

impl Drop for H3Client {
    fn drop(&mut self) {
        self.dead.store(true, Ordering::Relaxed);
        if let Ok(mut conn) = self.conn.lock() {
            let _ = conn.close(false, 0, b"");
            quic::flush_egress(&mut conn, &self.sock);
        }
    }
}

impl H3Client {
    pub(crate) fn connect(
        address: &str,
        port: u16,
        server_name: &str,
        tls: &ferrox_core::tls::TlsConfig,
    ) -> Option<Arc<Self>> {
        let peers: Vec<SocketAddr> = format!("{address}:{port}")
            .to_socket_addrs()
            .ok()?
            .collect();
        let peer = *peers.first()?;
        let mut config = if tls.insecure || !tls.cert_pins.is_empty() {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
            config.verify_peer(false);
            if !quic::tune(&mut config, quic::ALPN) {
                return None;
            }
            config
        } else {
            quic::quiche_config(&tls.roots, None)?
        };
        config.set_initial_max_data(16 * 1024 * 1024);
        let sock = if peer.is_ipv6() {
            UdpSocket::bind("[::]:0").ok()?
        } else {
            UdpSocket::bind("0.0.0.0:0").ok()?
        };
        let local = sock.local_addr().ok()?;
        let sock = Arc::new(Datagram::plain(sock));
        let mut scid = [0u8; 16];
        getrandom::fill(&mut scid).ok()?;
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect(Some(server_name), &cid, local, peer, &mut config).ok()?;
        quic::drive_handshake_by(&mut conn, &sock, local, crate::budgets::handshake())?;
        if !tls.cert_pins.is_empty() {
            let chain: Vec<Vec<u8>> = match conn.peer_cert_chain() {
                Some(chain) => chain.iter().map(|cert| cert.to_vec()).collect(),
                None => conn
                    .peer_cert()
                    .map(|cert| vec![cert.to_vec()])
                    .unwrap_or_default(),
            };
            if !ferrox_core::tls::verify_cert_pinned(&chain, &tls.cert_pins, server_name) {
                return None;
            }
        }
        quic::send_h3_opening(&mut conn, &sock);
        let conn = Arc::new(Mutex::new(conn));
        let dead = Arc::new(AtomicBool::new(false));
        let pump = Arc::clone(&conn);
        let pump_sock = Arc::clone(&sock);
        let pump_dead = Arc::clone(&dead);
        std::thread::Builder::new()
            .name("xhttp-h3-pump".to_owned())
            .spawn(move || pump_connection(&pump, &pump_sock, local, &pump_dead))
            .ok()?;
        Some(Arc::new(Self {
            conn,
            sock,
            next: AtomicU64::new(0),
            dead,
        }))
    }

    fn open(self: &Arc<Self>, block: &[u8], end_request: bool) -> Option<(H3Reader, H3StreamOut)> {
        self.open_with(block, end_request, Arc::new(Activity::new()))
    }

    fn open_with(
        self: &Arc<Self>,
        block: &[u8],
        end_request: bool,
        activity: Arc<Activity>,
    ) -> Option<(H3Reader, H3StreamOut)> {
        if self.dead.load(Ordering::Relaxed) {
            return None;
        }
        let id = self.next.fetch_add(4, Ordering::SeqCst);
        let wire = Wire::Client(ClientStream {
            _owner: Arc::clone(self),
            conn: Arc::clone(&self.conn),
            sock: Arc::clone(&self.sock),
            id,
            peer_fin: Arc::new(AtomicBool::new(false)),
            activity,
        });
        let mut frame = Vec::with_capacity(block.len() + 9);
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(block);
        let mut writer = wire.clone();
        if writer.write_all(&frame).is_err() {
            return None;
        }
        if end_request {
            wire.fin();
        }
        Some((H3Reader::new(wire.clone()), H3StreamOut { wire }))
    }

    fn packet(
        self: &Arc<Self>,
        host: &str,
        settings: &XhttpSettings,
        session: &str,
        seq: u64,
        piece: &[u8],
    ) -> bool {
        let (head, body) = crate::xhttp::packet_head(host, settings, session, seq, piece);
        let block = block_from_text(&head, host, "https");
        let deadline = Instant::now() + crate::budgets::relay_stall();
        let Some((mut reader, out)) = self.open(&block, false) else {
            return false;
        };
        reader.set_deadline(deadline);
        if let Some(body) = body {
            if !out.data(body) {
                out.reset();
                return false;
            }
        }
        out.end();
        let mut sink = [0u8; 64];
        loop {
            match reader.read(&mut sink) {
                Ok(0) => {
                    return reader
                        .status()
                        .is_some_and(|code| (200..300).contains(&code));
                }
                Ok(_) => {}
                Err(error) if crate::proxy::is_timeout(&error) => {}
                Err(_) => {
                    reader.reset();
                    return false;
                }
            }
        }
    }
}

fn pump_connection(
    conn: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<Datagram>,
    local: SocketAddr,
    dead: &Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let wait = conn
            .lock()
            .ok()
            .and_then(|conn| conn.timeout())
            .map_or(TICK, |left| left.min(TICK));
        let _ = sock.set_read_timeout(Some(wait.max(Duration::from_millis(1))));
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Ok(mut conn) = conn.lock() {
                    let _ = conn.recv(&mut buf[..n], quiche::RecvInfo { from, to: local });
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
        let Ok(mut conn) = conn.lock() else {
            break;
        };
        if conn.is_closed() {
            break;
        }
        conn.on_timeout();
        quic::flush_egress(&mut conn, sock);
    }
    dead.store(true, Ordering::Relaxed);
}

struct H3Post {
    client: Arc<H3Client>,
    host: String,
    settings: XhttpSettings,
    session: String,
}

impl crate::xhttp::PacketPost for H3Post {
    fn post(&mut self, seq: u64, piece: &[u8]) -> bool {
        self.client
            .packet(&self.host, &self.settings, &self.session, seq, piece)
    }
}

struct NullWrite;

impl Write for NullWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::proxy::FrameWrite for NullWrite {
    fn write_slices(&mut self, _parts: &[&[u8]]) -> bool {
        true
    }
}

pub(crate) fn is_h3(alpn: &[Vec<u8>]) -> bool {
    alpn.len() == 1 && alpn[0].eq_ignore_ascii_case(b"h3")
}

pub(crate) fn connect_split(
    address: &str,
    port: u16,
    host: &str,
    settings: &XhttpSettings,
    tls: &ferrox_core::tls::TlsConfig,
) -> Option<(H3Reader, crate::xhttp::XhttpWriter)> {
    let name = if tls.server_name.is_empty() {
        host
    } else {
        &tls.server_name
    };
    let client = H3Client::connect(address, port, name, tls)?;
    let head = crate::xhttp::dial_head(host, settings, "", None);
    let block = block_from_text(&head, host, "https");
    let (reader, out) = client.open(&block, false)?;
    let writer = crate::xhttp::XhttpWriter::new(NullWrite);
    writer.set_stream(crate::xhttp::StreamOut::H3(out));
    Some((reader, writer))
}

pub(crate) fn connect_dual_split(
    address: &str,
    port: u16,
    host: &str,
    settings: &XhttpSettings,
    tls: &ferrox_core::tls::TlsConfig,
) -> Option<(H3Reader, crate::xhttp::XhttpWriter)> {
    let name = if tls.server_name.is_empty() {
        host
    } else {
        &tls.server_name
    };
    let client = H3Client::connect(address, port, name, tls)?;
    let session = settings.session_id();
    let down = crate::xhttp::downlink_head(host, settings, &session);
    let block = block_from_text(&down, host, "https");
    let activity = Arc::new(Activity::new());
    let (reader, _) = client.open_with(&block, true, Arc::clone(&activity))?;
    let writer = if settings.mode == XhttpMode::PacketUp {
        crate::xhttp::XhttpWriter::packets_h3(Arc::clone(&client), host, settings, session)
    } else {
        let up = crate::xhttp::dial_head(host, settings, &session, None);
        let block = block_from_text(&up, host, "https");
        let (_, out) = client.open_with(&block, false, activity)?;
        let writer = crate::xhttp::XhttpWriter::new(NullWrite);
        writer.set_stream(crate::xhttp::StreamOut::H3(out));
        writer
    };
    Some((reader, writer))
}

pub(crate) fn packets(
    client: Arc<H3Client>,
    host: &str,
    settings: &XhttpSettings,
    session: String,
) -> crate::xhttp::XhttpWriter {
    let post = H3Post {
        client,
        host: host.to_owned(),
        settings: settings.clone(),
        session,
    };
    crate::xhttp::XhttpWriter::packets_with(Box::new(post), settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::WindowRead;

    struct Recorder(Arc<std::sync::Mutex<Option<std::io::ErrorKind>>>);

    impl H3Service for Recorder {
        fn serve(
            &self,
            mut reader: Box<dyn WindowRead + Send>,
            _writer: crate::xhttp::XhttpWriter,
        ) {
            let mut buf = [0u8; 16];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) => {
                        *self.0.lock().expect("recorder lock") = Some(error.kind());
                        break;
                    }
                }
            }
        }
    }

    struct Echo;

    impl H3Service for Echo {
        fn serve(&self, mut reader: Box<dyn WindowRead + Send>, writer: crate::xhttp::XhttpWriter) {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if !writer.send(&buf[..n]) {
                            break;
                        }
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || crate::proxy::is_timeout(&error) => {}
                    Err(_) => break,
                }
            }
            writer.finish();
        }
    }

    fn minted_identity(name: &str) -> (ferrox_core::tls::TlsServerConfig, Vec<Vec<u8>>) {
        let minted = rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("mints");
        let roots = quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let identity = ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: roots.clone(),
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: vec![b"h3".to_vec()],
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            send_tickets: true,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
        };
        (identity, roots)
    }

    fn settings() -> XhttpSettings {
        XhttpSettings {
            path: "/x".to_owned(),
            mode: XhttpMode::StreamOne,
            mode_source: crate::xhttp::ModeSource::Stated,
            ..XhttpSettings::stream_one()
        }
    }

    fn dual_settings(mode: XhttpMode) -> XhttpSettings {
        XhttpSettings {
            mode,
            mode_source: crate::xhttp::ModeSource::Stated,
            ..settings()
        }
    }

    fn dial(
        port: u16,
        settings: &XhttpSettings,
        roots: Vec<Vec<u8>>,
    ) -> (H3Reader, crate::xhttp::XhttpWriter) {
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            ..Default::default()
        };
        connect_dual_split("127.0.0.1", port, "localhost", settings, &tls)
            .expect("the h3 streams open")
    }

    fn client(port: u16, roots: Vec<Vec<u8>>) -> Arc<H3Client> {
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            ..Default::default()
        };
        H3Client::connect("127.0.0.1", port, "localhost", &tls).expect("the h3 client connects")
    }

    fn raw_stream(client: &Arc<H3Client>) -> Wire {
        let id = client.next.fetch_add(4, Ordering::SeqCst);
        Wire::Client(ClientStream {
            _owner: Arc::clone(client),
            conn: Arc::clone(&client.conn),
            sock: Arc::clone(&client.sock),
            id,
            peer_fin: Arc::new(AtomicBool::new(false)),
            activity: Arc::new(Activity::new()),
        })
    }

    fn send_frame(wire: &Wire, kind: u64, payload: &[u8]) {
        let mut frame = Vec::with_capacity(payload.len() + 9);
        frames::quic_varint(&mut frame, kind);
        frames::quic_varint(&mut frame, payload.len() as u64);
        frame.extend_from_slice(payload);
        wire.clone().write_all(&frame).expect("the frame sends");
    }

    fn refused(reader: &mut H3Reader, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut buf = [0u8; 1];
            match reader.read(&mut buf) {
                Ok(0) => panic!("{what} ended as a clean EOF"),
                Ok(_) => panic!("{what} was answered"),
                Err(error) if crate::proxy::is_timeout(&error) => {
                    assert!(Instant::now() < deadline, "{what} never refused");
                }
                Err(_) => return,
            }
        }
    }

    #[test]
    fn a_stream_up_upload_reaches_the_downlink_over_h3() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        assert!(writer.send(b"hello"));
        writer.finish();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, b"hello");
    }

    #[test]
    fn a_read_reuses_one_scratch_buffer() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        reader.room.fill(0xAA);
        assert!(writer.send(b"hello"));
        writer.finish();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, b"hello");
        assert_eq!(
            reader.room[READ_ROOM - 1],
            0xAA,
            "the scratch buffer is reused, not zeroed"
        );
    }

    #[test]
    fn a_bulk_upload_crosses_h3_in_one_data_frame() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::StreamUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        let payload: Vec<u8> = (0..96 * 1024).map(|byte| (byte % 251) as u8).collect();
        assert!(writer.send(&payload));
        writer.finish();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, payload);
    }

    #[test]
    fn an_h3_packet_up_post_gets_a_2xx_and_carries_the_body() {
        let (identity, roots) = minted_identity("localhost");
        let settings = dual_settings(XhttpMode::PacketUp);
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let (mut reader, writer) = dial(port, &settings, roots);
        assert!(writer.send(b"hello"));
        writer.finish();
        let mut got = [0u8; 5];
        let mut at = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while at < got.len() {
            match reader.read(&mut got[at..]) {
                Ok(0) => panic!("the downlink ended after {at} bytes"),
                Ok(n) => at += n,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || crate::proxy::is_timeout(&error) => {}
                Err(error) => panic!("the answer reads: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the answer stalls after {at} bytes"
            );
        }
        assert_eq!(&got, b"hello");
    }

    #[test]
    fn a_data_frame_before_headers_is_refused() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let client = client(port, roots);
        let wire = raw_stream(&client);
        send_data(&wire, b"too early");
        let mut reader = H3Reader::new(wire);
        refused(&mut reader, "early DATA");
    }

    #[test]
    fn a_request_head_without_a_method_is_refused() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let client = client(port, roots);
        let wire = raw_stream(&client);
        let mut block = Vec::new();
        hpack::qpack_literal_many(&[(":path", "/x")], &mut block);
        send_frame(&wire, frames::H3_HEADERS, &block);
        let mut reader = H3Reader::new(wire);
        refused(&mut reader, "a head without :method");
    }

    #[test]
    fn a_truncated_data_frame_is_an_error() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let seen = Arc::new(std::sync::Mutex::new(None));
        let port = serve_inbound(
            "127.0.0.1:0",
            &identity,
            &settings,
            Arc::new(Recorder(Arc::clone(&seen))),
            None,
        )
        .expect("the h3 listener binds");
        let client = client(port, roots);
        let wire = raw_stream(&client);
        let mut block = Vec::new();
        let padding = "x".repeat(100);
        let target = format!("/x?x_padding={padding}");
        hpack::qpack_literal_many(
            &[
                (":method", "POST"),
                (":path", target.as_str()),
                (":scheme", "https"),
                (":authority", "localhost"),
            ],
            &mut block,
        );
        let mut frame = Vec::new();
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        frames::quic_varint(&mut frame, frames::H3_DATA);
        frames::quic_varint(&mut frame, 16);
        frame.extend_from_slice(b"cut");
        wire.clone().write_all(&frame).expect("the frame sends");
        wire.fin();
        let deadline = Instant::now() + Duration::from_secs(5);
        while seen.lock().expect("recorder lock").is_none() {
            assert!(Instant::now() < deadline, "the truncation was never seen");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            *seen.lock().expect("recorder lock"),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn a_non_2xx_status_is_an_error() {
        assert!(status_ok(Some(403)).is_err());
        assert!(status_ok(Some(204)).is_ok());
        assert!(status_ok(None).is_ok());
    }

    #[test]
    fn a_stream_one_session_crosses_h3_both_ways() {
        let (identity, roots) = minted_identity("localhost");
        let settings = settings();
        let port = serve_inbound("127.0.0.1:0", &identity, &settings, Arc::new(Echo), None)
            .expect("the h3 listener binds");
        let tls = ferrox_core::tls::TlsConfig {
            server_name: "localhost".to_owned(),
            roots: roots.into(),
            ..Default::default()
        };
        let (mut reader, writer) = connect_split("127.0.0.1", port, "localhost", &settings, &tls)
            .expect("the h3 stream opens");
        assert!(writer.send(b"hello"), "the request body rides DATA");
        writer.finish();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("the answer reads");
        assert_eq!(got, b"hello");
    }
}
