use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;

use crate::conn::Connection;
use crate::json::{self, Json};
use crate::ws::{WsReader, WsWriter};

const PAGE: &str = include_str!("browser_dialer.html");
const POOL: usize = 256;
const TASK: Duration = Duration::from_secs(8);
const TASK_TOTAL: Duration = Duration::from_secs(16);
const CONNECTIONS: usize = 512;
const HEAD_LIMIT: usize = 16 * 1024;

static BRIDGE: OnceLock<Option<Arc<Bridge>>> = OnceLock::new();

pub(crate) fn active() -> bool {
    bridge().is_some()
}

fn bridge() -> Option<&'static Arc<Bridge>> {
    BRIDGE.get_or_init(start_from_env).as_ref()
}

fn start_from_env() -> Option<Arc<Bridge>> {
    let addr = std::env::var("xray.browser.dialer")
        .ok()
        .or_else(|| std::env::var("XRAY_BROWSER_DIALER").ok())?;
    if addr.trim().is_empty() {
        return None;
    }
    if let Some(bridge) = Bridge::start(addr.trim()) {
        Some(bridge)
    } else {
        eprintln!("browser dialer: cannot listen on {addr}");
        None
    }
}

struct Slot {
    reader: WsReader<Connection>,
    writer: WsWriter,
}

struct Live(Arc<Bridge>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct Bridge {
    #[cfg_attr(not(test), allow(dead_code, reason = "the page port is a test hook"))]
    addr: SocketAddr,
    token: String,
    page: String,
    queue: Mutex<VecDeque<Slot>>,
    ready: Condvar,
    live: AtomicUsize,
}

impl Bridge {
    pub(crate) fn start(addr: &str) -> Option<Arc<Self>> {
        let listener = TcpListener::bind(addr).ok()?;
        let local = listener.local_addr().ok()?;
        let token = uuid_v4()?;
        let bridge = Arc::new(Self {
            addr: local,
            page: PAGE.replace("csrfToken", &token),
            token,
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            live: AtomicUsize::new(0),
        });
        let worker = Arc::clone(&bridge);
        std::thread::Builder::new()
            .name("browser-dialer".to_owned())
            .spawn(move || worker.accept(&listener))
            .ok()?;
        Some(bridge)
    }

    #[cfg_attr(not(test), allow(dead_code, reason = "the page port is a test hook"))]
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn accept(self: Arc<Self>, listener: &TcpListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            if self
                .live
                .try_update(Ordering::AcqRel, Ordering::Relaxed, |live| {
                    (live < CONNECTIONS).then_some(live + 1)
                })
                .is_err()
            {
                continue;
            }
            let this = Arc::clone(&self);
            if std::thread::Builder::new()
                .name("browser-page".to_owned())
                .spawn(move || {
                    let live = Live(this);
                    live.0.serve(Connection::Tcp(stream));
                })
                .is_err()
            {
                self.live.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn serve(&self, mut stream: Connection) {
        let Some((head, at)) = crate::proxy::read_http_head_kept(
            &mut stream,
            HEAD_LIMIT,
            crate::budgets::head_arrival(),
        ) else {
            return;
        };
        let Some(target) = request_target(&head[..at]) else {
            return;
        };
        if self.addr.ip().is_loopback() {
            let allowed = request_host(&head[..at]).is_some_and(host_is_loopback);
            if !allowed {
                let _ = stream.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.shutdown(Shutdown::Both);
                return;
            }
        }
        if target.split('?').next() == Some("/websocket") {
            if !has_token(target, &self.token) {
                let _ = stream.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.shutdown(Shutdown::Both);
                return;
            }
            let Some((reader, writer)) = crate::ws::accept_head(stream, head, at, "/websocket")
            else {
                return;
            };
            self.push(reader, writer);
            return;
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src http: https: ws: wss:\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.page.len(),
            self.page
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.shutdown(Shutdown::Both);
    }

    fn push(&self, reader: WsReader<Connection>, writer: WsWriter) {
        let Ok(mut queue) = self.queue.lock() else {
            writer.close();
            return;
        };
        if queue.len() >= POOL {
            writer.close();
            return;
        }
        queue.push_back(Slot { reader, writer });
        self.ready.notify_one();
    }

    fn take(&self, deadline: Instant) -> Option<Slot> {
        let mut queue = self.queue.lock().ok()?;
        loop {
            if let Some(slot) = queue.pop_front() {
                return Some(slot);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (next, waited) = self.ready.wait_timeout(queue, deadline - now).ok()?;
            queue = next;
            if waited.timed_out() && queue.is_empty() {
                return None;
            }
        }
    }

    fn task(&self, task: &Json) -> Option<Slot> {
        let mut text = String::new();
        json::write(task, &mut text);
        let deadline = Instant::now() + TASK_TOTAL;
        loop {
            let mut slot = self.take(deadline)?;
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                slot.writer.close();
                return None;
            }
            slot.reader.set_poll(Some(left.min(TASK)));
            slot.reader.set_handshake_budget(Some(deadline));
            slot.writer.set_write_timeout(Some(left.min(TASK)));
            if !slot.writer.send_text(text.as_bytes()) {
                slot.writer.set_write_timeout(None);
                slot.writer.close();
                continue;
            }
            let ack = read_ack(&mut slot.reader);
            slot.writer.set_write_timeout(None);
            slot.reader.set_poll(None);
            slot.reader.set_handshake_budget(None);
            match ack {
                Ack::Ok => return Some(slot),
                Ack::Fail => {
                    slot.writer.close();
                    return None;
                }
                Ack::Closed => slot.writer.close(),
            }
        }
    }
}

fn task(method: &str, url: String, extra: Option<Json>, stream: bool) -> Json {
    let mut fields = vec![
        ("method".to_owned(), Json::Str(method.to_owned())),
        ("url".to_owned(), Json::Str(url)),
    ];
    if let Some(extra) = extra {
        fields.push(("extra".to_owned(), extra));
    }
    fields.push(("streamResponse".to_owned(), Json::Bool(stream)));
    Json::Obj(fields)
}

fn http_extra(parts: &HeadParts) -> Option<Json> {
    let mut fields = Vec::new();
    if let Some(referrer) = &parts.referrer {
        fields.push(("referrer".to_owned(), Json::Str(referrer.clone())));
    }
    if !parts.headers.is_empty() {
        fields.push((
            "headers".to_owned(),
            Json::Obj(
                parts
                    .headers
                    .iter()
                    .map(|(name, value)| (name.clone(), Json::Str(value.clone())))
                    .collect(),
            ),
        ));
    }
    if !parts.cookies.is_empty() {
        fields.push((
            "cookies".to_owned(),
            Json::Obj(
                parts
                    .cookies
                    .iter()
                    .map(|(name, value)| (name.clone(), Json::Str(value.clone())))
                    .collect(),
            ),
        ));
    }
    if fields.is_empty() {
        None
    } else {
        Some(Json::Obj(fields))
    }
}

enum Ack {
    Ok,
    Fail,
    Closed,
}

fn read_ack(reader: &mut WsReader<Connection>) -> Ack {
    let mut buf = [0u8; 2];
    let mut at = 0;
    while at < buf.len() {
        match reader.read(&mut buf[at..]) {
            Ok(0) | Err(_) => return Ack::Closed,
            Ok(n) => at += n,
        }
    }
    if buf == *b"ok" {
        Ack::Ok
    } else {
        Ack::Fail
    }
}

pub(crate) struct WsTarget<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) tls: bool,
    pub(crate) path: &'a str,
    pub(crate) ed: u32,
    pub(crate) first: &'a [u8],
}

pub(crate) fn dial_ws(target: &WsTarget<'_>) -> Option<(WsReader<Connection>, WsWriter)> {
    dial_ws_on(bridge()?, target)
}

fn dial_ws_on(bridge: &Bridge, target: &WsTarget<'_>) -> Option<(WsReader<Connection>, WsWriter)> {
    let early = !target.first.is_empty() && target.first.len() as u64 <= u64::from(target.ed);
    let extra = if early {
        Some(Json::Obj(vec![(
            "protocol".to_owned(),
            Json::Str(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(target.first)),
        )]))
    } else {
        None
    };
    let scheme = if target.tls { "wss" } else { "ws" };
    let path = if target.path.is_empty() {
        "/".to_owned()
    } else if target.path.starts_with('/') {
        target.path.to_owned()
    } else {
        format!("/{}", target.path)
    };
    let url = format!(
        "{scheme}://{}{path}",
        authority(target.host, target.port, target.tls)
    );
    let slot = bridge.task(&task("WS", url, extra, true))?;
    if !early && !target.first.is_empty() {
        slot.writer.set_write_timeout(Some(TASK));
        let sent = slot.writer.send(target.first);
        slot.writer.set_write_timeout(None);
        if !sent {
            return None;
        }
    }
    Some((slot.reader, slot.writer))
}

pub(crate) fn dial_get(url: String, parts: &HeadParts) -> Option<WsReader<Connection>> {
    let bridge = bridge()?;
    let slot = bridge.task(&task("GET", url, http_extra(parts), true))?;
    Some(slot.reader)
}

pub(crate) fn dial_packet(method: &str, url: String, parts: &HeadParts, payload: &[u8]) -> bool {
    let Some(bridge) = bridge() else {
        return false;
    };
    let Some(mut slot) = bridge.task(&task(method, url, http_extra(parts), false)) else {
        return false;
    };
    slot.reader.set_poll(Some(TASK));
    slot.reader
        .set_handshake_budget(Some(Instant::now() + TASK_TOTAL));
    slot.writer.set_write_timeout(Some(TASK));
    let sent = slot.writer.send(payload);
    slot.writer.set_write_timeout(None);
    if !sent || !matches!(read_ack(&mut slot.reader), Ack::Ok) {
        return false;
    }
    slot.reader.set_handshake_budget(None);
    slot.writer.close();
    true
}

pub(crate) struct HeadParts {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) referrer: Option<String>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) cookies: Vec<(String, String)>,
}

pub(crate) fn head_parts(head: &str) -> Option<HeadParts> {
    let (first, rest) = head.split_once("\r\n")?;
    let mut line = first.split(' ');
    let method = line.next()?.to_owned();
    let target = line.next()?.to_owned();
    let mut referrer = None;
    let mut headers = Vec::new();
    let mut cookies = Vec::new();
    for header in rest.split("\r\n") {
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        let name = name.trim();
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "host" | "connection" | "content-length" | "transfer-encoding" => {}
            "referer" => referrer = Some(value.to_owned()),
            "cookie" => {
                for cookie in value.split(';') {
                    if let Some((key, value)) = cookie.trim().split_once('=') {
                        cookies.push((key.to_owned(), value.to_owned()));
                    }
                }
            }
            _ => headers.push((name.to_owned(), value.to_owned())),
        }
    }
    Some(HeadParts {
        method,
        target,
        referrer,
        headers,
        cookies,
    })
}

pub(crate) fn authority(host: &str, port: u16, tls: bool) -> String {
    let host = host.trim();
    if host.is_empty() {
        return format!("127.0.0.1:{port}");
    }
    let bracketed = host.starts_with('[');
    let has_port = if bracketed {
        host.split_once("]:")
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    } else {
        host.matches(':').count() == 1
            && host
                .rsplit_once(':')
                .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    };
    let default = if tls { 443 } else { 80 };
    if has_port {
        return host.to_owned();
    }
    let bare = if bracketed {
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
    } else {
        host
    };
    if port == default {
        return if bare.contains(':') && !bracketed {
            format!("[{bare}]:{port}")
        } else {
            host.to_owned()
        };
    }
    if bare.contains(':') {
        format!("[{bare}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn http_url(authority: &str, tls: bool, target: &str) -> String {
    format!("http{}://{authority}{target}", if tls { "s" } else { "" })
}

fn request_target(head: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").next()?.split(' ').nth(1)
}

fn request_host(head: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host").then_some(value.trim())
    })
}

fn host_is_loopback(host: &str) -> bool {
    let name = host
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(host, |(name, _)| name);
    let name = name
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
        .unwrap_or(name);
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn has_token(target: &str, token: &str) -> bool {
    let Some((_, query)) = target.split_once('?') else {
        return false;
    };
    let mut found = 0u8;
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if name == "token" {
            found |= u8::from(constant_time_eq(value.as_bytes(), token.as_bytes()));
        }
    }
    found != 0
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn uuid_v4() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut out = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(b"0123456789abcdef"[usize::from(byte >> 4)] as char);
        out.push(b"0123456789abcdef"[usize::from(byte & 0xf)] as char);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn connect_page(bridge: &Bridge, token: &str) -> (WsReader<Connection>, WsWriter) {
        let stream = std::net::TcpStream::connect(bridge.addr()).expect("connects");
        crate::ws::connect(
            Connection::Tcp(stream),
            "127.0.0.1",
            &format!("/websocket?token={token}"),
            0,
            &[],
            &[],
            0,
        )
        .expect("upgrades")
    }

    #[test]
    fn authority_keeps_the_reference_shape() {
        assert_eq!(authority("example.com", 443, true), "example.com");
        assert_eq!(authority("example.com", 8443, true), "example.com:8443");
        assert_eq!(authority("2001:db8::1", 443, true), "[2001:db8::1]:443");
        assert_eq!(authority("[::1]", 80, false), "[::1]");
    }

    #[test]
    fn only_loopback_hosts_reach_a_loopback_bridge() {
        assert!(host_is_loopback("localhost:8080"));
        assert!(host_is_loopback("127.0.0.1:8080"));
        assert!(host_is_loopback("[::1]:8080"));
        assert!(!host_is_loopback("evil.example:8080"));
    }

    #[test]
    fn head_parts_move_the_referrer_and_cookies_out_of_headers() {
        let parts = head_parts(
            "POST /a?b=c HTTP/1.1\r\nHost: example.com\r\nReferer: https://example.com/x\r\nCookie: a=1; b=2\r\nX-Test: yes\r\n\r\n",
        )
        .expect("parts");
        assert_eq!(parts.method, "POST");
        assert_eq!(parts.target, "/a?b=c");
        assert_eq!(parts.referrer.as_deref(), Some("https://example.com/x"));
        assert_eq!(
            parts.cookies,
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
        assert_eq!(parts.headers, vec![("X-Test".into(), "yes".into())]);
    }

    #[test]
    fn the_page_carries_the_token_and_the_socket_refuses_another() {
        let bridge = Bridge::start("127.0.0.1:0").expect("starts");
        let page = std::net::TcpStream::connect(bridge.addr()).expect("connects");
        let mut page = Connection::Tcp(page);
        page.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .expect("writes");
        let mut response = String::new();
        page.read_to_string(&mut response).expect("reads");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(bridge.token.as_str()));

        let mut wrong = std::net::TcpStream::connect(bridge.addr()).expect("connects");
        wrong
            .write_all(b"GET /websocket?token=nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .expect("writes");
        let mut status = [0u8; 12];
        wrong.read_exact(&mut status).expect("reads");
        assert_eq!(&status, b"HTTP/1.1 403");
    }

    #[test]
    fn dial_ws_crosses_the_browser_bridge() {
        let target = std::net::TcpListener::bind("127.0.0.1:0").expect("binds target");
        let target_addr = target.local_addr().expect("target addr");
        thread::spawn(move || {
            let (stream, _) = target.accept().expect("accepts target");
            let (mut reader, writer) = crate::ws::accept(Connection::Tcp(stream), "/").expect("ws");
            let mut buf = [0u8; 64];
            let n = reader.read(&mut buf).expect("reads");
            writer.send(&buf[..n]);
        });

        let bridge = Bridge::start("127.0.0.1:0").expect("starts");
        let token = bridge.token.clone();
        let (mut browser, browser_writer) = connect_page(&bridge, &token);
        let worker = thread::spawn(move || {
            let mut task = [0u8; 1024];
            let n = browser.read(&mut task).expect("task");
            let task = std::str::from_utf8(&task[..n]).expect("text");
            assert!(task.contains("\"method\":\"WS\""));
            assert!(task.contains(&format!(":{}", target_addr.port())));
            browser_writer.send_text(b"ok");

            let mut buf = [0u8; 64];
            let n = browser.read(&mut buf).expect("payload");
            let target = std::net::TcpStream::connect(target_addr).expect("target dial");
            let (mut target_reader, target_writer) =
                crate::ws::connect(Connection::Tcp(target), "127.0.0.1", "/", 0, &[], &[], 0)
                    .expect("target ws");
            target_writer.send(&buf[..n]);
            let n = target_reader.read(&mut buf).expect("echo");
            browser_writer.send(&buf[..n]);
        });

        let (mut reader, writer) = dial_ws_on(
            &bridge,
            &WsTarget {
                host: "127.0.0.1",
                port: target_addr.port(),
                tls: false,
                path: "/",
                ed: 0,
                first: &[][..],
            },
        )
        .expect("browser dial");
        writer.send(b"hello");
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).expect("echo");
        assert_eq!(&buf, b"hello");
        worker.join().expect("worker");
    }
}
