use std::collections::HashMap;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::net::{Shutdown, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use ferrox_core::failure::Kind;
use ferrox_core::shadowsocks::{
    rc4_md5_key, Cipher, MasterKey, Method, Rc4, LENGTH_LEN, MAX_CHUNK, TAG_LEN,
};

use crate::budgets::RELAY_POLL;
use crate::conn::Connection;
use crate::proxy::{read_exact, under_handshake, write_all_runs, Destination, RelayPoll, UDP_BUF};

const SALT_LEN: usize = 32;
// Chunks one relay read takes and one write carries. A batch never waits for the chunk that has not arrived, so this is a syscall count rather than a latency budget: four costs the same one read and the same one write as one.
const CHUNKS_PER_BATCH: usize = 4;
// One relay read of a stream is exactly one chunk: a 16384 B read would seal as 16383 + 1, a second length seal and tag for a single tail byte, and a batch read of CHUNKS_PER_BATCH of them tiles into whole chunks for the same reason. A stream has no chunks to batch, so its granularity — and every carrier frame size that follows from it — is unchanged.
const READ_CHUNK: usize = MAX_CHUNK;
const IV_LEN: usize = 16;

/// The mux request's own name and port, which the reference compares by domain alone.
pub(crate) const MUX_HOST: &str = "v1.mux.cool";
pub(crate) const MUX_PORT: u16 = 9527;

/// What the uplink thread seals with: the AEAD chunk cipher, or the stream state whose crypt writes into the read buffer itself.
#[allow(
    clippy::large_enum_variant,
    reason = "the 258-byte schedule is built once per handshake; boxing it would add a heap allocation and a pointer chase to a state that lives in the thread that uses it"
)]
pub(crate) enum Uplink {
    Aead(Cipher),
    Stream(Rc4),
}

/// One client a shadowsocks listener serves: the cipher its password derives, as xray builds one account per `users` entry.
#[derive(Clone)]
pub(crate) struct SsUser {
    pub(crate) method: Method,
    pub(crate) master: MasterKey,
    /// The account's name and policy level, applied once the cipher names it.
    pub(crate) email: String,
    pub(crate) level: u32,
}

pub(crate) type SsUsers = std::sync::Arc<[SsUser]>;

/// An inbound's clients, plus the single password a 2022 inbound's PSK list is read from.
pub(crate) struct SsAccounts {
    pub(crate) users: SsUsers,
    pub(crate) password: String,
    pub(crate) method: String,
    pub(crate) is_2022: bool,
    /// One (email, level) per client PSK a 2022 multi-user password names after the master; empty for a legacy or single-password inbound.
    pub(crate) identities: Vec<(String, u32)>,
}

impl std::fmt::Debug for SsAccounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsAccounts")
            .field("users", &self.users.len())
            .field("method", &self.method)
            .field("is_2022", &self.is_2022)
            .finish_non_exhaustive()
    }
}

/// A stream method authenticates nothing, so its account is the whole inbound, the way the reference returns the first non-AEAD user without probing.
fn stream_user(users: &[SsUser]) -> Option<&SsUser> {
    users.iter().find(|user| user.method.is_stream())
}

/// The one client an inbound without a `users` list serves, or none when the method is one this tree cannot open.
pub(crate) fn account(password: &str, method: &str) -> SsUsers {
    match Method::parse(method) {
        Some(method) => std::sync::Arc::from([SsUser {
            method,
            master: MasterKey::new(password, method.key_len()),
            email: String::new(),
            level: 0,
        }]),
        None => SsUsers::default(),
    }
}

pub(crate) fn serve(mut stream: Connection, users: &[SsUser], freedom: bool) {
    if !freedom || users.is_empty() {
        return;
    }
    if let Some(user) = stream_user(users) {
        return serve_stream(stream, user);
    }
    let mut head = wire_buffer();
    // Bound the salt and first-chunk reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: &mut stream,
            until: std::time::Instant::now() + budget,
        };
        match accept_cipher(&mut bounded, users) {
            Some((user, mut recv, size)) => {
                open_chunk_after(&mut bounded, &mut recv, &mut head, size)
                    .map(|chunk| (user, recv, chunk))
            }
            None => None,
        }
    };
    let _ = stream.set_read_timeout(None);
    let Some((user, recv, chunk)) = opened else {
        return;
    };
    stream = stream
        .with_meter(authenticate(user))
        .with_policy(Some(crate::policy::flow(user.level)));
    let Some(request) = parse_request(chunk) else {
        return;
    };
    let (target, header_len) = match request {
        Request::Mux(header_len) => {
            crate::accesslog::record_current(&format_args!("{MUX_HOST}:{MUX_PORT}"));
            let carried = chunk[header_len..].to_vec();
            drop(head);
            let Some(accepted) = mux_after_handshake(user, &mut stream, Recv::Ready(recv), carried)
            else {
                return;
            };
            serve_mux_connection(&stream, accepted);
            return;
        }
        Request::Target(target, header_len) => (target, header_len),
    };
    crate::accesslog::record_current(&target);
    let Ok(mut uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if uplink.write_all(&chunk[header_len..]).is_err() {
        return;
    }
    // The relay allocates its own chunk buffer, so this one stops costing 16 KiB.
    drop(head);
    let salt_len = user.method.key_len();
    let mut salt = [0u8; SALT_LEN];
    if getrandom::fill(&mut salt[..salt_len]).is_err() {
        return;
    }
    let Some(send) = Cipher::from_master_key(user.method, &user.master, &salt[..salt_len]) else {
        return;
    };
    if stream.write_all(&salt[..salt_len]).is_err() {
        return;
    }
    pump_relay(&uplink, &stream, Uplink::Aead(send), Recv::Ready(recv));
}

/// The first chunk's length frame opened against every client: the salts are tried smallest first, so a match never reads past the salt that matched.
fn accept_cipher<'u>(
    reader: &mut dyn Read,
    users: &'u [SsUser],
) -> Option<(&'u SsUser, Cipher, usize)> {
    let mut probe = [0u8; SALT_LEN + LENGTH_LEN + TAG_LEN];
    let mut have = 0usize;
    // The two salt lengths the methods use: AES-128's 16 bytes, every other method 32.
    for salt_len in [16, SALT_LEN] {
        if !users
            .iter()
            .any(|user| user.method.key_len() == salt_len && !user.method.is_stream())
        {
            continue;
        }
        let need = salt_len + LENGTH_LEN + TAG_LEN;
        if have < need {
            read_exact(reader, &mut probe[have..need]).ok()?;
            have = need;
        }
        for user in users
            .iter()
            .filter(|user| !user.method.is_stream() && user.method.key_len() == salt_len)
        {
            let mut recv = Cipher::from_master_key(user.method, &user.master, &probe[..salt_len])?;
            let mut length = [0u8; LENGTH_LEN + TAG_LEN];
            length.copy_from_slice(&probe[salt_len..need]);
            if let Some(size) = open_length(&mut recv, &mut length) {
                return Some((user, recv, size));
            }
        }
    }
    None
}

/// The account whose cipher opened the request: from here its email, level and counters are the flow's.
fn authenticate(user: &SsUser) -> crate::stats::Meter {
    crate::accesslog::reidentify(&user.email, user.level);
    crate::stats::user_traffic(&user.email, user.level)
}

/// The stream handshake: a 16-byte IV in the clear, then the address header rides the RC4 stream itself, so the first read already carries payload and whatever arrived with the header is forwarded, not re-read.
fn serve_stream(mut stream: Connection, user: &SsUser) {
    let master = user.master.clone();
    let mut head = [0u8; 512];
    // Bound the IV and address-header reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: &mut stream,
            until: std::time::Instant::now() + budget,
        };
        let mut iv = [0u8; IV_LEN];
        read_exact(&mut bounded, &mut iv)
            .ok()
            .and_then(|()| rc4_md5_key(master.as_bytes(), &iv))
            .and_then(|key| Rc4::new(&key))
            .and_then(|mut recv| {
                let mut len = 0usize;
                while len < head.len() {
                    match bounded.read(&mut head[len..]) {
                        Ok(0) => return None,
                        Ok(n) => {
                            recv.crypt(&mut head[len..len + n]);
                            len += n;
                            if let Some(request) = parse_request(&head[..len]) {
                                return Some((recv, request, len));
                            }
                        }
                        Err(error) if crate::proxy::is_timeout(&error) => {}
                        Err(_) => return None,
                    }
                }
                None
            })
    };
    let _ = stream.set_read_timeout(None);
    let Some((recv, request, len)) = opened else {
        return;
    };
    stream = stream
        .with_meter(authenticate(user))
        .with_policy(Some(crate::policy::flow(user.level)));
    let (target, consumed) = match request {
        Request::Mux(consumed) => {
            crate::accesslog::record_current(&format_args!("{MUX_HOST}:{MUX_PORT}"));
            let Some(accepted) = stream_mux(&mut stream, &master, recv, &head[consumed..len])
            else {
                return;
            };
            serve_mux_connection(&stream, accepted);
            return;
        }
        Request::Target(target, consumed) => (target, consumed),
    };
    crate::accesslog::record_current(&target);
    let Ok(mut uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if consumed < len && uplink.write_all(&head[consumed..len]).is_err() {
        return;
    }
    let mut iv = [0u8; IV_LEN];
    if getrandom::fill(&mut iv).is_err() {
        return;
    }
    let Some(key) = rc4_md5_key(master.as_bytes(), &iv) else {
        return;
    };
    let Some(send) = Rc4::new(&key) else {
        return;
    };
    if stream.write_all(&iv).is_err() {
        return;
    }
    pump_relay(
        &uplink,
        &stream,
        Uplink::Stream(send),
        Recv::StreamReady(recv),
    );
}

pub(crate) fn serve_ws(stream: Connection, users: &[SsUser], path: &str, freedom: bool) {
    let Some((mut reader, mut writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((accepted, meter)) = accept_on(&mut reader, &mut writer, users, freedom) else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    serve_accepted(accepted, reader, writer, close, meter);
}

pub(crate) fn serve_httpupgrade(
    stream: Connection,
    users: &[SsUser],
    path: &str,
    host: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::httpupgrade::accept(stream, path, host) else {
        return;
    };
    let Some((accepted, meter)) = accept_on(&mut reader, &mut writer, users, freedom) else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    serve_accepted(accepted, reader, writer, close, meter);
}

#[cfg(test)]
pub(crate) fn serve_grpc(stream: Connection, users: &[SsUser], path: &str, freedom: bool) {
    serve_grpc_with(
        stream,
        users,
        &crate::config::GrpcSettings::path(path),
        freedom,
    );
}

pub(crate) fn serve_grpc_with(
    stream: Connection,
    users: &[SsUser],
    settings: &crate::config::GrpcSettings,
    freedom: bool,
) {
    let Ok(write) = stream.try_clone() else {
        return;
    };
    let _ = stream.set_read_timeout(Some(crate::budgets::RELAY_POLL));
    crate::grpc::serve_muxed_ss_conn(
        stream,
        crate::grpc::Tail::new(Box::new(write)),
        settings,
        &std::sync::Arc::from(users),
        freedom,
    );
}

/// The shadowsocks handler for one stream of a multiplexed gRPC connection: the demux has already
/// answered the HTTP/2 head, so only the cipher handshake and the relay remain.
pub(crate) fn serve_grpc_muxed(
    mut reader: crate::grpc::GrpcReader<crate::grpc::BodyFrames>,
    mut writer: crate::grpc::GrpcWriter,
    users: &[SsUser],
    freedom: bool,
    opened: &std::sync::atomic::AtomicBool,
) {
    reader.arm_mux_poll();
    let Some((accepted, meter)) = under_handshake(&mut reader, |read| {
        accept_on(read, &mut writer, users, freedom)
    }) else {
        reader.abort();
        return;
    };
    opened.store(true, std::sync::atomic::Ordering::Relaxed);
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    serve_accepted(accepted, reader, writer, close, meter);
}

pub(crate) fn serve_xhttp(
    stream: Connection,
    users: &[SsUser],
    settings: &crate::xhttp::XhttpSettings,
    freedom: bool,
) {
    let Ok(read) = stream.try_clone() else {
        return;
    };
    let Some((reader, writer)) =
        crate::xhttp::accept_split_with_settings(read, stream, settings, None)
    else {
        return;
    };
    // A packet-up GET waits on its reader for a POST queued behind this lane; the wait belongs to the flow.
    let users = users.to_vec();
    crate::proxy::spawn_carried(move || {
        serve_xhttp_accepted(reader, writer, &users, freedom);
    });
}

fn serve_xhttp_accepted(
    reader: Box<dyn crate::proxy::WindowRead + Send>,
    mut writer: crate::xhttp::XhttpWriter,
    users: &[SsUser],
    freedom: bool,
) {
    // The handshake clock: a carrier that answers its head and then goes silent ends the slot at its budget instead of holding it.
    let mut reader = crate::proxy::HandshakeRead::new(reader, crate::budgets::handshake());
    let Some((accepted, meter)) = accept_on(&mut reader, &mut writer, users, freedom) else {
        writer.abort();
        return;
    };
    reader.disarm();
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    serve_accepted(accepted, reader, writer, close, meter);
}

/// The stream-one handshake the in-memory test dials still speak: one chunked POST, no mode metadata.
#[cfg(test)]
pub(crate) fn serve_xhttp_legacy(stream: Connection, users: &[SsUser], path: &str, freedom: bool) {
    let Some((mut reader, mut writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let Some((accepted, meter)) = accept_on(&mut reader, &mut writer, users, freedom) else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    serve_accepted(accepted, reader, writer, close, meter);
}

pub(crate) fn serve_httpheader(stream: Connection, users: &[SsUser], path: &str, freedom: bool) {
    let Some((mut reader, mut writer)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((accepted, meter)) = accept_on(&mut reader, &mut writer, users, freedom) else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    serve_accepted(accepted, reader, writer, close, meter);
}

pub(crate) fn serve_session<R, W>(
    mut reader: R,
    mut writer: W,
    users: &[SsUser],
    freedom: bool,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Some((accepted, meter)) = accept_on(
        &mut reader as &mut dyn Read,
        &mut writer as &mut dyn Write,
        users,
        freedom,
    ) else {
        close();
        return;
    };
    serve_accepted(
        accepted,
        reader,
        writer,
        std::sync::Arc::clone(close),
        meter,
    );
}

pub(crate) fn serve_kcp<R, W>(
    mut reader: R,
    mut writer: W,
    users: &[SsUser],
    freedom: bool,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Some((accepted, meter)) = accept_on(
        &mut reader as &mut dyn Read,
        &mut writer as &mut dyn Write,
        users,
        freedom,
    ) else {
        return;
    };
    serve_accepted(
        accepted,
        reader,
        writer,
        std::sync::Arc::clone(close),
        meter,
    );
}

fn accept_stream(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    user: &SsUser,
) -> Option<(Accepted, crate::stats::Meter)> {
    let meter = authenticate(user);
    let master = &user.master;
    let mut iv = [0u8; IV_LEN];
    read_exact(reader, &mut iv).ok()?;
    let key = rc4_md5_key(master.as_bytes(), &iv)?;
    let mut recv = Rc4::new(&key)?;
    let mut head = [0u8; 512];
    let mut len = 0usize;
    let request = loop {
        if len >= 512 {
            return None;
        }
        let n = match reader.read(&mut head[len..]) {
            Ok(0) => return None,
            Ok(n) => n,
            Err(error) if crate::proxy::is_timeout(&error) => continue,
            Err(_) => return None,
        };
        recv.crypt(&mut head[len..len + n]);
        len += n;
        if let Some(request) = parse_request(&head[..len]) {
            break request;
        }
    };
    let (target, consumed) = match request {
        Request::Mux(consumed) => {
            crate::accesslog::record_current(&format_args!("{MUX_HOST}:{MUX_PORT}"));
            return stream_mux(writer, master, recv, &head[consumed..len])
                .map(|accepted| (accepted, meter));
        }
        Request::Target(target, consumed) => (target, consumed),
    };
    crate::accesslog::record_current(&target);
    let mut iv = [0u8; IV_LEN];
    getrandom::fill(&mut iv).ok()?;
    let key = rc4_md5_key(master.as_bytes(), &iv)?;
    let send = Rc4::new(&key)?;
    let mut uplink = crate::conn::dial_tcp(&target, Duration::from_secs(8)).ok()?;
    uplink.write_all(&head[consumed..len]).ok()?;
    writer.write_all(&iv).ok()?;
    Some((
        Accepted::Direct {
            uplink,
            send: Uplink::Stream(send),
            recv: Recv::StreamReady(recv),
        },
        meter,
    ))
}

fn accept_on(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    users: &[SsUser],
    freedom: bool,
) -> Option<(Accepted, crate::stats::Meter)> {
    if !freedom {
        return None;
    }
    if let Some(user) = stream_user(users) {
        return accept_stream(reader, writer, user);
    }
    let mut head = wire_buffer();
    let (user, mut recv, size) = accept_cipher(reader, users)?;
    let meter = authenticate(user);
    let chunk = open_chunk_after(reader, &mut recv, &mut head, size)?;
    let request = parse_request(chunk)?;
    let (target, header_len) = match request {
        Request::Mux(header_len) => {
            crate::accesslog::record_current(&format_args!("{MUX_HOST}:{MUX_PORT}"));
            let carried = chunk[header_len..].to_vec();
            return mux_after_handshake(user, writer, Recv::Ready(recv), carried)
                .map(|accepted| (accepted, meter));
        }
        Request::Target(target, header_len) => (target, header_len),
    };
    crate::accesslog::record_current(&target);
    let mut uplink = crate::conn::dial_tcp(&target, Duration::from_secs(8)).ok()?;
    uplink.write_all(&chunk[header_len..]).ok()?;
    drop(head);
    let salt_len = user.method.key_len();
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt[..salt_len]).ok()?;
    let send = Cipher::from_master_key(user.method, &user.master, &salt[..salt_len])?;
    writer.write_all(&salt[..salt_len]).ok()?;
    Some((
        Accepted::Direct {
            uplink,
            send: Uplink::Aead(send),
            recv: Recv::Ready(recv),
        },
        meter,
    ))
}

/// The first request's destination: the mux name is one no resolver answers, so it is recognised
/// from the raw header before resolution and never dialed.
enum Request {
    Mux(usize),
    Target(SocketAddr, usize),
}

fn parse_request(buf: &[u8]) -> Option<Request> {
    if let Some(used) = mux_header_len(buf) {
        return Some(Request::Mux(used));
    }
    parse_addr_header(buf).map(|(target, used)| Request::Target(target, used))
}

/// The reference compares the mux domain alone, so the port a client chose never gates the session.
fn mux_header_len(buf: &[u8]) -> Option<usize> {
    if buf.first() != Some(&3) {
        return None;
    }
    let (crate::proxy::AddrBody::Domain(host), at) =
        crate::proxy::parse_addr_body(buf, crate::proxy::AddrKind::Domain)?
    else {
        return None;
    };
    if host != MUX_HOST || buf.len() < at + 2 {
        return None;
    }
    Some(at + 2)
}

fn mux_after_handshake(
    user: &SsUser,
    writer: &mut dyn Write,
    recv: Recv,
    carried: Vec<u8>,
) -> Option<Accepted> {
    let salt_len = user.method.key_len();
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt[..salt_len]).ok()?;
    let send = Cipher::from_master_key(user.method, &user.master, &salt[..salt_len])?;
    writer.write_all(&salt[..salt_len]).ok()?;
    Some(Accepted::Mux {
        send: Uplink::Aead(send),
        recv,
        carried,
    })
}

/// The stream rung's mux answer: the reply IV goes out in the clear and whatever rode the header enters the session.
fn stream_mux(
    writer: &mut dyn Write,
    master: &MasterKey,
    recv: Rc4,
    carried: &[u8],
) -> Option<Accepted> {
    let mut iv = [0u8; IV_LEN];
    getrandom::fill(&mut iv).ok()?;
    let key = rc4_md5_key(master.as_bytes(), &iv)?;
    let send = Rc4::new(&key)?;
    writer.write_all(&iv).ok()?;
    Some(Accepted::Mux {
        send: Uplink::Stream(send),
        recv: Recv::StreamReady(recv),
        carried: carried.to_vec(),
    })
}

/// A mux session on a socket this thread owns: the reader, writer and close are the socket's own clones.
fn serve_mux_connection(stream: &Connection, accepted: Accepted) {
    let Ok(stream) = stream.try_clone() else {
        return;
    };
    crate::proxy::spawn_carried(move || serve_mux_connection_owned(&stream, accepted));
}

fn serve_mux_connection_owned(stream: &Connection, accepted: Accepted) {
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let Ok(writer) = stream.try_clone() else {
        return;
    };
    let Ok(closer) = stream.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    serve_accepted(
        accepted,
        reader,
        writer,
        close,
        crate::stats::Meter::default(),
    );
}

fn serve_accepted<R, W>(
    accepted: Accepted,
    reader: R,
    writer: W,
    close: std::sync::Arc<dyn Fn() + Send + Sync>,
    meter: crate::stats::Meter,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    match accepted {
        Accepted::Direct { uplink, send, recv } => {
            pump_relay_carried(&uplink, reader, writer, &close, send, recv);
        }
        Accepted::Mux {
            send,
            recv,
            carried,
        } => {
            let mut reader = reader;
            reader.arm_relay_poll();
            let reader = SsMuxReader::new(reader, recv);
            let writer = SsMuxWriter::new(writer, send);
            crate::proxy::serve_mux_tunnel(Box::new(reader), Box::new(writer), close, &carried);
        }
    }
}

pub(crate) struct SsMuxReader<R> {
    downlink: Downlink<R>,
    pending: Vec<u8>,
    at: usize,
    done: bool,
}

impl<R: Read> SsMuxReader<R> {
    pub(crate) fn new(reader: R, recv: Recv) -> Self {
        Self {
            downlink: Downlink::new(reader, recv),
            pending: Vec::new(),
            at: 0,
            done: false,
        }
    }
}

impl<R: Read> Read for SsMuxReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.at < self.pending.len() {
                let n = (self.pending.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
                self.at += n;
                if self.at == self.pending.len() {
                    self.pending.clear();
                    self.at = 0;
                }
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            let mut sink = VecSink(&mut self.pending);
            let next = self.downlink.step(&mut sink, None);
            if self.pending.is_empty() {
                match next {
                    crate::proxy::lane_pool::Next::Done => {
                        self.done = true;
                        return Ok(0);
                    }
                    crate::proxy::lane_pool::Next::Idle => {
                        return Err(std::io::ErrorKind::WouldBlock.into());
                    }
                    crate::proxy::lane_pool::Next::More | crate::proxy::lane_pool::Next::Retry => {}
                }
            } else if matches!(next, crate::proxy::lane_pool::Next::Done) {
                self.done = true;
            }
        }
    }
}

pub(crate) struct SsMuxWriter<W> {
    send: Uplink,
    writer: W,
    buf: Vec<u8>,
}

impl<W: Write> SsMuxWriter<W> {
    pub(crate) fn new(writer: W, send: Uplink) -> Self {
        Self {
            send,
            writer,
            buf: crate::proxy::unfilled(BATCH),
        }
    }
}

impl<W: Write> Write for SsMuxWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut offset = 0;
        while offset < buf.len() {
            let take = (buf.len() - offset).min(MAX_CHUNK);
            self.buf[SEAL_HEAD..SEAL_HEAD + take].copy_from_slice(&buf[offset..offset + take]);
            seal_all(&mut self.send, &mut self.buf, take, &mut self.writer)?;
            offset += take;
        }
        Ok(buf.len())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }
            self.write(buf)?;
            total += buf.len();
        }
        Ok(total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

struct VecSink<'a>(&'a mut Vec<u8>);

impl Write for VecSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            self.0.extend_from_slice(buf);
            total += buf.len();
        }
        Ok(total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn client_send_handshake(
    uplink: &mut dyn Write,
    password: &str,
    method: &str,
    target: &Destination,
) -> Result<(Uplink, Recv), Kind> {
    let method = Method::parse(method).ok_or(Kind::Local)?;
    let master = MasterKey::new(password, method.key_len());
    if method.is_stream() {
        let mut iv = [0u8; IV_LEN];
        getrandom::fill(&mut iv).map_err(|_| Kind::Local)?;
        uplink.write_all(&iv).map_err(|error| Kind::of(&error))?;
        let key = rc4_md5_key(master.as_bytes(), &iv).ok_or(Kind::Local)?;
        let mut send = Rc4::new(&key).ok_or(Kind::Local)?;
        let mut addr = Vec::with_capacity(2 + target.addr_len());
        target.push_addr(&mut addr, 4, 3);
        addr.extend_from_slice(&target.port().to_be_bytes());
        send.crypt(&mut addr);
        uplink.write_all(&addr).map_err(|error| Kind::of(&error))?;
        return Ok((Uplink::Stream(send), Recv::StreamWaiting(master)));
    }
    let salt_len = method.key_len();
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt[..salt_len]).map_err(|_| Kind::Local)?;
    uplink
        .write_all(&salt[..salt_len])
        .map_err(|error| Kind::of(&error))?;
    let mut send = Uplink::Aead(
        Cipher::from_master_key(method, &master, &salt[..salt_len]).ok_or(Kind::Local)?,
    );
    let mut addr = Vec::with_capacity(2 + target.addr_len());
    target.push_addr(&mut addr, 4, 3);
    addr.extend_from_slice(&target.port().to_be_bytes());
    let n = addr.len();
    let mut buf = crate::proxy::unfilled(SEAL_HEAD + n + TAG_LEN);
    buf[SEAL_HEAD..SEAL_HEAD + n].copy_from_slice(&addr);
    seal_all(&mut send, &mut buf, n, uplink).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            Kind::Local
        } else {
            Kind::of(&error)
        }
    })?;
    Ok((send, Recv::Waiting(method, master)))
}

#[allow(
    clippy::large_enum_variant,
    reason = "the 258-byte schedule is built once per handshake; boxing it would add a heap allocation and a pointer chase to a state that lives in the thread that uses it"
)]
pub(crate) enum Recv {
    Ready(Cipher),
    Waiting(Method, MasterKey),
    StreamReady(Rc4),
    StreamWaiting(MasterKey),
}

pub(crate) enum Accepted {
    Direct {
        uplink: Connection,
        send: Uplink,
        recv: Recv,
    },
    Mux {
        send: Uplink,
        recv: Recv,
        carried: Vec<u8>,
    },
}

pub(crate) fn pump_relay(plain: &Connection, sealed: &Connection, send: Uplink, recv: Recv) {
    let Ok(sealed_read) = sealed.try_clone() else {
        return;
    };
    let Ok(sealed_write) = sealed.try_clone() else {
        return;
    };
    let Ok(closer) = sealed.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(plain, sealed_read, sealed_write, &close, send, recv);
}

pub(crate) fn pump_relay_carried<R, W>(
    plain: &Connection,
    reader: R,
    writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    send: Uplink,
    recv: Recv,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut plain_write = plain_write;
    let _ = plain_read.set_read_timeout(Some(RELAY_POLL));
    let flow = crate::proxy::RelayFinish::new(true, std::sync::Arc::clone(close), None);
    let mut send = send;
    let mut writer = writer;
    let mut buf = crate::proxy::unfilled(uplink_buffer_len(&send));
    let up_flow = std::sync::Arc::clone(&flow);
    crate::proxy::lane_pool::submit(
        Box::new(move || uplink_step(&mut plain_read, &mut buf, &mut send, &mut writer, &up_flow)),
        Box::new(crate::proxy::stream_lane_done(&flow)),
    );
    let mut reader = reader;
    reader.arm_relay_poll();
    let mut link = Downlink::new(reader, recv);
    let down_flow = std::sync::Arc::clone(&flow);
    crate::proxy::lane_pool::submit(
        Box::new(move || link.step(&mut plain_write, Some(&down_flow))),
        Box::new(crate::proxy::stream_lane_done(&flow)),
    );
}

/// One step of the sealing leg: read what the client sent, seal it into the carrier, and hand the
/// lane back when the socket has nothing yet rather than waiting inside the read.
fn uplink_step(
    plain_read: &mut Connection,
    buf: &mut [u8],
    send: &mut Uplink,
    writer: &mut dyn Write,
    flow: &crate::proxy::RelayFinish,
) -> crate::proxy::lane_pool::Next {
    let read = match send {
        Uplink::Aead(_) => read_slots(plain_read, buf),
        Uplink::Stream(_) => plain_read.read(&mut buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]),
    };
    match read {
        Ok(0) => crate::proxy::lane_pool::Next::Done,
        Ok(n) if seal_all(send, buf, n, writer).is_ok() => crate::proxy::lane_pool::Next::More,
        Err(error)
            if crate::proxy::is_timeout(&error)
                && !flow.ended_and_idle(crate::budgets::RELAY_RESPONSE_IDLE) =>
        {
            crate::proxy::lane_pool::Next::Idle
        }
        Ok(_) | Err(_) => crate::proxy::lane_pool::Next::Done,
    }
}

/// The downlink the dials build: the carrier's octets opened into the codec's own window, so the
/// widest ask the carrier ever hears is a window and a payload byte crosses user space once.
/// `false` is the handshake never opening, which is the pump's own early exit: the carrier is not
/// finished and the uplink is not joined, because the dial dropping the sockets is what ends it.
#[cfg(test)]
fn relay_downlink<R: Read>(reader: R, recv: Recv, out: &mut dyn Write) -> bool {
    let mut link = Downlink::new(reader, recv);
    loop {
        let handshaking = matches!(link, Downlink::Handshake { .. });
        match link.step(out, None) {
            crate::proxy::lane_pool::Next::Done => return !handshaking,
            crate::proxy::lane_pool::Next::Idle
            | crate::proxy::lane_pool::Next::More
            | crate::proxy::lane_pool::Next::Retry => {}
        }
    }
}

/// The carrier's direction of a sealed relay as lane steps: the handshake's salt or stream IV, then
/// the codec's own window. A step that finds nothing yet hands the lane back instead of waiting on
/// the socket, and the blocking dial wrappers just loop on that wait.
enum Downlink<R> {
    Handshake {
        read: R,
        pending: Recv,
        head: [u8; SALT_LEN],
        at: usize,
    },
    Aead {
        window: ChunkReader<R>,
        cipher: Cipher,
    },
    Stream {
        read: R,
        rc4: Rc4,
        buf: Vec<u8>,
    },
    /// Holds the value a step swaps out while it runs; never observed or stepped twice.
    Running,
}

#[cfg(test)]
impl<R: Read> Downlink<R> {
    fn window(&mut self) -> Option<&mut ChunkReader<R>> {
        match self {
            Self::Aead { window, .. } => Some(window),
            _ => None,
        }
    }
}

impl<R: Read> Downlink<R> {
    fn new(read: R, recv: Recv) -> Self {
        match recv {
            Recv::Ready(cipher) => Self::Aead {
                window: ChunkReader::new(read),
                cipher,
            },
            Recv::StreamReady(rc4) => Self::Stream {
                read,
                rc4,
                buf: crate::proxy::unfilled(READ_CHUNK),
            },
            Recv::Waiting(..) | Recv::StreamWaiting(..) => Self::Handshake {
                read,
                pending: recv,
                head: [0u8; SALT_LEN],
                at: 0,
            },
        }
    }

    fn step(
        &mut self,
        out: &mut dyn Write,
        flow: Option<&crate::proxy::RelayFinish>,
    ) -> crate::proxy::lane_pool::Next {
        let next = std::mem::replace(self, Self::Running);
        let (next, state) = next.advance(out, flow);
        *self = state;
        next
    }

    fn advance(
        self,
        out: &mut dyn Write,
        flow: Option<&crate::proxy::RelayFinish>,
    ) -> (crate::proxy::lane_pool::Next, Self) {
        match self {
            Self::Handshake {
                read,
                pending,
                head,
                at,
            } => handshake_step(read, pending, head, at, flow),
            Self::Aead { window, cipher } => aead_step(window, cipher, out, flow),
            Self::Stream { read, rc4, buf } => stream_step(read, rc4, buf, out, flow),
            Self::Running => unreachable!("a step that is running is never stepped again"),
        }
    }
}

/// The handshake's step: one read of the salt or IV, then the state that reads the window.
fn handshake_step<R: Read>(
    mut read: R,
    pending: Recv,
    mut head: [u8; SALT_LEN],
    mut at: usize,
    flow: Option<&crate::proxy::RelayFinish>,
) -> (crate::proxy::lane_pool::Next, Downlink<R>) {
    let need = match &pending {
        Recv::Waiting(method, _) => method.key_len(),
        _ => IV_LEN,
    };
    let next = match read.read(&mut head[at..need]) {
        Ok(0) => return (crate::proxy::lane_pool::Next::Done, Downlink::Running),
        Ok(n) => {
            at += n;
            if at < need {
                return (
                    crate::proxy::lane_pool::Next::More,
                    Downlink::Handshake {
                        read,
                        pending,
                        head,
                        at,
                    },
                );
            }
            match pending {
                Recv::Waiting(method, master) => {
                    let Some(cipher) = Cipher::from_master_key(method, &master, &head[..need])
                    else {
                        return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
                    };
                    Downlink::Aead {
                        window: ChunkReader::new(read),
                        cipher,
                    }
                }
                Recv::StreamWaiting(master) => {
                    let mut iv = [0u8; IV_LEN];
                    iv.copy_from_slice(&head[..IV_LEN]);
                    let Some(key) = rc4_md5_key(master.as_bytes(), &iv) else {
                        return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
                    };
                    let Some(rc4) = Rc4::new(&key) else {
                        return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
                    };
                    Downlink::Stream {
                        read,
                        rc4,
                        buf: crate::proxy::unfilled(READ_CHUNK),
                    }
                }
                _ => unreachable!("only a waiting handshake reads a head"),
            }
        }
        Err(error) if crate::proxy::is_timeout(&error) => {
            return (
                waited(flow),
                Downlink::Handshake {
                    read,
                    pending,
                    head,
                    at,
                },
            );
        }
        Err(_) => return (crate::proxy::lane_pool::Next::Done, Downlink::Running),
    };
    (crate::proxy::lane_pool::Next::More, next)
}

/// The window's step: hand the target every chunk that has arrived, and ask once for more when none
/// has — a batch that has not finished arriving is a wait, not a chunk to hold the worker for.
fn aead_step<R: Read>(
    mut window: ChunkReader<R>,
    mut cipher: Cipher,
    out: &mut dyn Write,
    flow: Option<&crate::proxy::RelayFinish>,
) -> (crate::proxy::lane_pool::Next, Downlink<R>) {
    let mut batch = [(0usize, 0usize); CHUNKS_PER_BATCH];
    let opened = window.open_ready(&mut cipher, &mut batch);
    if opened.chunks > 0
        && write_all_runs::<CHUNKS_PER_BATCH>(out, &window.buf, &batch[..opened.chunks]).is_err()
    {
        return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
    }
    if opened.forged {
        return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
    }
    let next = if opened.chunks > 0 {
        crate::proxy::lane_pool::Next::More
    } else {
        match window.try_fill() {
            Fill::Ready => crate::proxy::lane_pool::Next::More,
            Fill::Idle => waited(flow),
            Fill::End => {
                return (
                    crate::proxy::lane_pool::Next::Done,
                    Downlink::Aead { window, cipher },
                );
            }
        }
    };
    (next, Downlink::Aead { window, cipher })
}

/// The stream rung's step: one read is one payload, decrypted where it lies and handed on.
fn stream_step<R: Read>(
    mut read: R,
    mut rc4: Rc4,
    mut buf: Vec<u8>,
    out: &mut dyn Write,
    flow: Option<&crate::proxy::RelayFinish>,
) -> (crate::proxy::lane_pool::Next, Downlink<R>) {
    let next = match read.read(&mut buf[..READ_CHUNK]) {
        Ok(0) => return (crate::proxy::lane_pool::Next::Done, Downlink::Running),
        Ok(n) => {
            rc4.crypt(&mut buf[..n]);
            if out.write_all(&buf[..n]).is_err() {
                return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
            }
            crate::proxy::lane_pool::Next::More
        }
        Err(error) if crate::proxy::is_timeout(&error) => waited(flow),
        Err(_) => return (crate::proxy::lane_pool::Next::Done, Downlink::Running),
    };
    (next, Downlink::Stream { read, rc4, buf })
}

/// A quiet socket is a wait for the lane unless the sibling has ended: then there is nothing left
/// to read on either side.
fn waited(flow: Option<&crate::proxy::RelayFinish>) -> crate::proxy::lane_pool::Next {
    if flow.is_some_and(crate::proxy::RelayFinish::ended) {
        crate::proxy::lane_pool::Next::Done
    } else {
        crate::proxy::lane_pool::Next::Idle
    }
}

pub(crate) fn serve_udp(address: &str, users: &[SsUser], freedom: bool) {
    let Ok(clients) = UdpSocket::bind(address) else {
        return;
    };
    serve_udp_on(&clients, users, freedom);
}

/// The most client sources one AEAD listener carries: each source owns an upstream socket pair, and only a datagram whose tag verifies creates one.
pub(crate) const SS_UDP_SOURCES: usize = 4096;

/// The most destinations one stream-cipher listener routes replies for: that account seals no tag, so a reply goes to the last client whose datagram named it.
const SS_UDP_DESTS: usize = 4096;

/// Datagrams one ready socket drains in a pass: a flooder cannot keep the front from its other sockets, and a level-triggered `poll` names what is left next pass.
const UDP_DRAIN: usize = 64;

/// One client source's UDP association: the account its first datagram named, its own upstream sockets, and the reply cipher that account seals with.
struct UdpSource {
    user: usize,
    v4: UdpSocket,
    v6: Option<UdpSocket>,
    hop: Option<Cipher>,
    last: Instant,
}

/// One readiness wait over the front's client socket and every association's sockets, so a pass
/// reads only what has data instead of trying each socket in turn.
#[cfg(unix)]
mod poll_set {
    use std::io;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    pub(crate) type Row = libc::pollfd;

    pub(crate) fn socket_row(socket: &UdpSocket) -> Row {
        libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }
    }

    pub(crate) fn wait(rows: &mut [Row], timeout: i32) -> io::Result<usize> {
        let count = libc::nfds_t::try_from(rows.len()).unwrap_or(libc::nfds_t::MAX);
        loop {
            // SAFETY: `rows` is this call's array, `count` its length, and the call writes only `revents`.
            let answered = unsafe { libc::poll(rows.as_mut_ptr(), count, timeout) };
            if answered >= 0 {
                return Ok(usize::try_from(answered).unwrap_or(0));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    pub(crate) fn is_ready(row: Row) -> bool {
        row.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
    }
}

/// The Windows spelling of the same wait: `WSAPoll`, whose error code comes from `WSAGetLastError`.
#[cfg(windows)]
mod poll_set {
    use std::io;
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        WSAGetLastError, WSAPoll, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLRDNORM, SOCKET, WSAPOLLFD,
    };

    pub(crate) type Row = WSAPOLLFD;

    pub(crate) fn socket_row(socket: &UdpSocket) -> Row {
        WSAPOLLFD {
            fd: socket.as_raw_socket() as SOCKET,
            events: POLLIN | POLLRDNORM,
            revents: 0,
        }
    }

    pub(crate) fn wait(rows: &mut [Row], timeout: i32) -> io::Result<usize> {
        let count = u32::try_from(rows.len()).unwrap_or(u32::MAX);
        // SAFETY: `rows` is this call's array, `count` its length, and the call writes only `revents`.
        let answered = unsafe { WSAPoll(rows.as_mut_ptr(), count, timeout) };
        if answered < 0 {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        Ok(usize::try_from(answered).unwrap_or(0))
    }

    pub(crate) fn is_ready(row: Row) -> bool {
        row.revents & (POLLIN | POLLRDNORM | POLLERR | POLLHUP | POLLNVAL) != 0
    }
}

pub(crate) fn serve_udp_on(clients: &UdpSocket, users: &[SsUser], freedom: bool) {
    if !freedom || users.is_empty() {
        return;
    }
    if clients.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    match users.iter().position(|user| user.method.is_stream()) {
        // Nothing in a stream datagram proves which client sent it, so the first stream account owns the front's udp side.
        Some(which) => serve_udp_stream(clients, &users[which]),
        None => serve_udp_aead(clients, users),
    }
}

/// One socket pair and one destination table serve a stream account: a reply is addressed to the last client that named its destination, and the table is capped rather than grown, so a stream front admits no descriptor for traffic it cannot prove.
fn serve_udp_stream(clients: &UdpSocket, user: &SsUser) {
    let Ok(v4) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    let v6 = UdpSocket::bind("[::]:0").ok();
    if v4.set_nonblocking(true).is_err() {
        return;
    }
    if v6
        .as_ref()
        .is_some_and(|sock| sock.set_nonblocking(true).is_err())
    {
        return;
    }
    let mut by_dest: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let mut hop = None;
    let mut buf = crate::proxy::unfilled(DATAGRAM_MAX);
    let mut reply = crate::proxy::unfilled(DATAGRAM_MAX);
    loop {
        match clients.recv_from(&mut buf[SEAL_ROOM..SEAL_ROOM + UDP_BUF]) {
            Ok((n, src)) => {
                let datagram = &mut buf[SEAL_ROOM..SEAL_ROOM + n];
                if let Some((dest, payload)) =
                    open_datagram(&user.master, user.method, datagram, &mut hop)
                {
                    if by_dest.len() >= SS_UDP_DESTS {
                        by_dest.clear();
                    }
                    by_dest.insert(dest, src);
                    if dest.is_ipv6() {
                        if let Some(sock) = v6.as_ref() {
                            let _ = sock.send_to(payload, dest);
                        }
                    } else {
                        let _ = v4.send_to(payload, dest);
                    }
                }
            }
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => break,
        }
        for sock in std::iter::once(&v4).chain(v6.as_ref()) {
            for _ in 0..UDP_DRAIN {
                let Ok((n, from)) = sock.recv_from(&mut reply[SEAL_ROOM..SEAL_ROOM + UDP_BUF])
                else {
                    break;
                };
                let Some(&client) = by_dest.get(&from) else {
                    continue;
                };
                if let Some(packet) = seal_datagram(
                    &user.master,
                    user.method,
                    &from,
                    &mut reply,
                    SEAL_ROOM,
                    n,
                    &mut hop,
                ) {
                    let _ = clients.send_to(packet, client);
                }
            }
        }
    }
}

/// One association per client source, created only by a datagram whose tag verifies: a reply can only name a source the tag proved.
#[allow(clippy::too_many_lines)]
/// Serve an AEAD front: one upstream association per client source, each with its own sockets, so a
/// reply reaches the one account that opened it. The pass parks in `poll` until a socket is ready or
/// the earliest association goes idle, so a quiet front costs no wakeups.
fn serve_udp_aead(clients: &UdpSocket, users: &[SsUser]) {
    if clients.set_nonblocking(true).is_err() {
        return;
    }
    let mut sources: HashMap<SocketAddr, UdpSource> = HashMap::new();
    let mut probes: Vec<Option<Cipher>> = users.iter().map(|_| None).collect();
    let mut buf = crate::proxy::unfilled(DATAGRAM_MAX);
    let mut reply = crate::proxy::unfilled(DATAGRAM_MAX);
    let mut rows: Vec<poll_set::Row> = Vec::new();
    let mut owners: Vec<Option<(SocketAddr, bool)>> = Vec::new();
    let idle = crate::budgets::udp_idle();
    loop {
        rows.clear();
        owners.clear();
        rows.push(poll_set::socket_row(clients));
        owners.push(None);
        for (address, source) in &sources {
            rows.push(poll_set::socket_row(&source.v4));
            owners.push(Some((*address, false)));
            if let Some(v6) = source.v6.as_ref() {
                rows.push(poll_set::socket_row(v6));
                owners.push(Some((*address, true)));
            }
        }
        let now = Instant::now();
        let timeout = sources
            .values()
            .map(|source| (source.last + idle).saturating_duration_since(now))
            .min()
            .map_or(-1, |left| {
                i32::try_from(left.as_millis()).unwrap_or(i32::MAX)
            });
        let Ok(ready) = poll_set::wait(&mut rows, timeout) else {
            break;
        };
        if ready > 0 {
            for (row, owner) in rows.iter().zip(owners.iter()) {
                if !poll_set::is_ready(*row) {
                    continue;
                }
                let Some((src, is_v6)) = *owner else {
                    for _ in 0..UDP_DRAIN {
                        let Ok((n, src)) =
                            clients.recv_from(&mut buf[SEAL_ROOM..SEAL_ROOM + UDP_BUF])
                        else {
                            break;
                        };
                        let now = Instant::now();
                        let datagram = &mut buf[SEAL_ROOM..SEAL_ROOM + n];
                        let mut bound = false;
                        if let Some(source) = sources.get_mut(&src) {
                            let user = &users[source.user];
                            if let Some((dest, payload)) =
                                open_datagram(&user.master, user.method, datagram, &mut source.hop)
                            {
                                source.last = now;
                                let uplink = if dest.is_ipv6() {
                                    source.v6.as_ref()
                                } else {
                                    Some(&source.v4)
                                };
                                if let Some(uplink) = uplink {
                                    let _ = uplink.send_to(payload, dest);
                                }
                                bound = true;
                            }
                        }
                        if bound {
                            continue;
                        }
                        let Some((which, dest, payload)) =
                            open_datagram_any(users, datagram, &mut probes)
                        else {
                            continue;
                        };
                        if sources.len() >= SS_UDP_SOURCES {
                            sources.retain(|_, source| now.duration_since(source.last) < idle);
                            if sources.len() >= SS_UDP_SOURCES {
                                continue;
                            }
                        }
                        let Ok(v4) = UdpSocket::bind("0.0.0.0:0") else {
                            continue;
                        };
                        if v4.set_nonblocking(true).is_err() {
                            continue;
                        }
                        let v6 = UdpSocket::bind("[::]:0")
                            .ok()
                            .filter(|sock| sock.set_nonblocking(true).is_ok());
                        let payload = &buf[SEAL_ROOM + payload.start..SEAL_ROOM + payload.end];
                        let uplink = if dest.is_ipv6() {
                            v6.as_ref()
                        } else {
                            Some(&v4)
                        };
                        if let Some(uplink) = uplink {
                            let _ = uplink.send_to(payload, dest);
                        }
                        let hop = probes[which].take();
                        sources.insert(
                            src,
                            UdpSource {
                                user: which,
                                v4,
                                v6,
                                hop,
                                last: now,
                            },
                        );
                    }
                    continue;
                };
                let Some(source) = sources.get_mut(&src) else {
                    continue;
                };
                let socket = if is_v6 {
                    match source.v6.as_ref() {
                        Some(socket) => socket,
                        None => continue,
                    }
                } else {
                    &source.v4
                };
                let mut dropped = false;
                for _ in 0..UDP_DRAIN {
                    match socket.recv_from(&mut reply[SEAL_ROOM..SEAL_ROOM + UDP_BUF]) {
                        Ok((n, from)) => {
                            source.last = Instant::now();
                            let user = &users[source.user];
                            if let Some(packet) = seal_datagram(
                                &user.master,
                                user.method,
                                &from,
                                &mut reply,
                                SEAL_ROOM,
                                n,
                                &mut source.hop,
                            ) {
                                let _ = clients.send_to(packet, src);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                        Err(_) => {
                            dropped = true;
                            break;
                        }
                    }
                }
                if dropped {
                    sources.remove(&src);
                }
            }
        }
        let now = Instant::now();
        sources.retain(|_, source| now.duration_since(source.last) < idle);
    }
}

/// Bytes one wire chunk can never exceed: `MAX_CHUNK` of payload plus its tag.
pub(crate) const WIRE_MAX: usize = MAX_CHUNK + TAG_LEN;

/// Room around one chunk's payload inside the caller's buffer: a sealed length before it and its tag after it, so both seals land beside the payload instead of the payload moving to them.
pub(crate) const SEAL_HEAD: usize = LENGTH_LEN + TAG_LEN;

/// One batch slot: its own headroom, a full chunk of payload, its own tailroom. A stride this wide is what lets a chunk's tag land beside its own payload rather than on the next chunk's plaintext, which is the one reason a batch cannot simply be a wider read.
const SLOT: usize = SEAL_HEAD + MAX_CHUNK + TAG_LEN;

/// The relay's read buffer: one slot per chunk of a batch.
const BATCH: usize = CHUNKS_PER_BATCH * SLOT;

/// The uplink's read buffer, sized by what the rung can fill: an AEAD leg reads four chunks at a
/// time, a stream crypt reads one — four slots would be buffers for a batch that leg never makes.
fn uplink_buffer_len(send: &Uplink) -> usize {
    match send {
        Uplink::Aead(_) => BATCH,
        Uplink::Stream(_) => SLOT,
    }
}

/// A chunk buffer sized once: `open_chunk` writes into a prefix of it, so no read ever grows or re-zeroes it.
pub(crate) fn wire_buffer() -> Vec<u8> {
    crate::proxy::unfilled(WIRE_MAX)
}

/// Seal what one relay read filled: every chunk of it seals inside its own slot — length into that slot's headroom, tag into its tailroom — and the batch leaves as one vectored write whose slices are exactly the wire bytes a chunk at a time used to be, so a carrier with no `writev` still sees one write per chunk. A payload byte is never copied in user space, and more chunks than the buffer has slots is refused loudly rather than corrupted quietly.
fn seal_all(
    send: &mut Uplink,
    buf: &mut [u8],
    n: usize,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    match send {
        Uplink::Aead(cipher) => {
            let mut sealed = [(0usize, 0usize); CHUNKS_PER_BATCH];
            let mut chunks = 0usize;
            let mut got = 0usize;
            while got < n {
                let take = (n - got).min(MAX_CHUNK);
                let head = chunks * SLOT;
                let end = head + SEAL_HEAD + take;
                let slot = sealed.get_mut(chunks).ok_or_else(invalid)?;
                if end + TAG_LEN > buf.len() {
                    return Err(invalid());
                }
                let mut length = (take as u16).to_be_bytes();
                let length_tag = cipher
                    .seal_piece_in_place(&mut length)
                    .ok_or_else(invalid)?;
                let tag = {
                    let chunk = &mut buf[head + SEAL_HEAD..end];
                    cipher.seal_piece_in_place(chunk).ok_or_else(invalid)?
                };
                buf[head..head + LENGTH_LEN].copy_from_slice(&length);
                buf[head + LENGTH_LEN..head + SEAL_HEAD].copy_from_slice(&length_tag);
                buf[end..end + TAG_LEN].copy_from_slice(&tag);
                *slot = (head, end + TAG_LEN - head);
                chunks += 1;
                got += take;
            }
            write_all_runs::<CHUNKS_PER_BATCH>(out, buf, &sealed[..chunks])
        }
        Uplink::Stream(rc4) => {
            let payload = &mut buf[SEAL_HEAD..SEAL_HEAD + n];
            rc4.crypt(payload);
            out.write_all(payload)
        }
    }
}

/// Fill a batch's payload slots with one vectored read. The kernel takes iovecs in order, so a short slot is always the last one and every sealed chunk still sits in its own slot.
fn read_slots(read: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut slots: [IoSliceMut; CHUNKS_PER_BATCH] =
        std::array::from_fn(|_| IoSliceMut::new(&mut []));
    let mut room = buf[..BATCH].chunks_mut(SLOT);
    for slot in &mut slots {
        let filled = room
            .next()
            .expect("the batch buffer holds one slot per chunk of a batch");
        *slot = IoSliceMut::new(&mut filled[SEAL_HEAD..SEAL_HEAD + MAX_CHUNK]);
    }
    read.read_vectored(&mut slots)
}

/// Read one wire chunk out of `chunk`'s prefix: `chunk` is the caller's, sized [`WIRE_MAX`] once and opened in place — no allocation, no zero-fill — and the handshake opens exactly one chunk because whatever the peer pipelined after it belongs to the relay.
#[cfg(test)]
fn open_chunk<'a>(
    stream: &mut dyn Read,
    recv: &mut Cipher,
    chunk: &'a mut [u8],
) -> Option<&'a [u8]> {
    let mut length = [0u8; LENGTH_LEN + TAG_LEN];
    read_exact(stream, &mut length).ok()?;
    let size = open_length(recv, &mut length)?;
    open_chunk_after(stream, recv, chunk, size)
}

/// The body of a chunk whose length a probe already opened: reads `size` bytes and their tag into the caller's buffer and opens them where they lie, so the cipher that matched a salt carries on from the length's block.
fn open_chunk_after<'a>(
    stream: &mut dyn Read,
    recv: &mut Cipher,
    chunk: &'a mut [u8],
    size: usize,
) -> Option<&'a [u8]> {
    if size + TAG_LEN > chunk.len() {
        return None;
    }
    let wire = &mut chunk[..size + TAG_LEN];
    read_exact(stream, wire).ok()?;
    let plain = open_into(recv, wire)?;
    Some(&wire[..plain])
}

/// Open an 18 B sealed length in place: the payload size it names, or `None` on a forged tag or an impossible size; both chunk readers share this so the framing lives in one place.
fn open_length(recv: &mut Cipher, length: &mut [u8]) -> Option<usize> {
    if open_into(recv, length)? != LENGTH_LEN {
        return None;
    }
    let size = usize::from(u16::from_be_bytes([length[0], length[1]]));
    (size <= MAX_CHUNK).then_some(size)
}

/// What one chunk's framing found: a plaintext that opened, more bytes still to arrive, or a tag that will not open.
enum Open {
    Chunk(usize, usize),
    Incomplete,
    Forged,
}

/// What the window's ready chunks came to: how many opened, and whether a forged tag stopped the batch.
struct Opened {
    chunks: usize,
    forged: bool,
}

/// One relay connection's downlink window: wire bytes land here once and chunks open where they lie — a length never costs its own read and the payload decrypts in the caller's buffer with no copy; sized for a whole batch of full chunks so one bulk read serves the length, the payloads and usually the next length too.
struct ChunkReader<R> {
    read: R,
    buf: Vec<u8>,
    at: usize,
    end: usize,
    /// A chunk whose length is drawn but whose bytes have not all arrived.
    held: Option<usize>,
}

impl<R: Read> ChunkReader<R> {
    fn new(read: R) -> Self {
        Self {
            read,
            buf: crate::proxy::unfilled(BATCH),
            at: 0,
            end: 0,
            held: None,
        }
    }

    /// One read's worth of filling for a lane: the window compacts only when it is full, so
    /// leftovers move once, and a quiet socket hands the worker back instead of parking it.
    fn try_fill(&mut self) -> Fill {
        if self.end == self.buf.len() {
            self.buf.copy_within(self.at..self.end, 0);
            self.end -= self.at;
            self.at = 0;
        }
        match self.read.read(&mut self.buf[self.end..]) {
            Ok(0) => Fill::End,
            Ok(n) => {
                self.end += n;
                Fill::Ready
            }
            Err(error) if crate::proxy::is_timeout(&error) => Fill::Idle,
            Err(_) => Fill::End,
        }
    }

    /// Open one chunk where it lies and say where its plaintext ended up. Incomplete input waits
    /// for more bytes, while a length or body tag that will not open is forged and ends the relay.
    fn open_chunk(&mut self, recv: &mut Cipher) -> Open {
        let head = LENGTH_LEN + TAG_LEN;
        let size = if let Some(size) = self.held {
            size
        } else {
            if self.end - self.at < head {
                return Open::Incomplete;
            }
            let length = &mut self.buf[self.at..self.at + head];
            let Some(size) = open_length(recv, length) else {
                return Open::Forged;
            };
            self.held = Some(size);
            size
        };
        let body = size + TAG_LEN;
        if self.end - self.at < head + body {
            return Open::Incomplete;
        }
        self.held = None;
        let start = self.at + head;
        let Some(plain) = open_into(recv, &mut self.buf[start..start + body]) else {
            return Open::Forged;
        };
        self.at = start + body;
        Open::Chunk(start, plain)
    }

    /// Open every chunk the window already holds: a peer that stops to hear back from its own
    /// target must never find the chunk it is waiting on held for a batch that has not arrived.
    /// The plaintexts are disjoint runs of one buffer, so they leave together in one vectored write;
    /// a forged tag stops the batch, and the chunks opened before it still reach the target.
    fn open_ready(&mut self, recv: &mut Cipher, out: &mut [(usize, usize)]) -> Opened {
        let mut chunks = 0usize;
        while chunks < out.len() {
            match self.open_chunk(recv) {
                Open::Chunk(start, plain) => {
                    out[chunks] = (start, plain);
                    chunks += 1;
                }
                Open::Incomplete => break,
                Open::Forged => {
                    return Opened {
                        chunks,
                        forged: true,
                    }
                }
            }
        }
        Opened {
            chunks,
            forged: false,
        }
    }
}

/// What one lane step's filling found: bytes arrived, the socket has none yet, or the stream ended.
enum Fill {
    Ready,
    Idle,
    End,
}

fn open_into(recv: &mut Cipher, chunk: &mut [u8]) -> Option<usize> {
    recv.open_in_place(chunk)
}

/// Room a sealed datagram's salt and address header take before its payload: the widest header is an IPv6 one at 19 bytes.
pub(crate) const SEAL_ROOM: usize = SALT_LEN + 19;

/// One UDP datagram's whole wire room: the headroom a seal needs, the payload, and one AEAD tag.
pub(crate) const DATAGRAM_MAX: usize = SEAL_ROOM + UDP_BUF + TAG_LEN;

/// One SOCKS-style address header — kind, octets, port — written where a datagram's buffer has room for it, so a per-datagram `Vec` is not needed to build the head.
pub(crate) fn write_addr(out: &mut [u8], dest: &SocketAddr) -> usize {
    match dest {
        SocketAddr::V4(v4) => {
            out[0] = 1;
            out[1..5].copy_from_slice(&v4.ip().octets());
            out[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        SocketAddr::V6(v6) => {
            out[0] = 4;
            out[1..17].copy_from_slice(&v6.ip().octets());
            out[17..19].copy_from_slice(&v6.port().to_be_bytes());
            19
        }
    }
}

/// Seal `n` payload bytes already at `buf[at..at + n]`, writing the salt or stream IV and the address header into the headroom before it and the tag after it: a datagram is sealed where the socket put it, with no per-datagram buffer and no second pass over the payload.
pub(crate) fn seal_datagram<'a>(
    master: &MasterKey,
    method: Method,
    dest: &SocketAddr,
    buf: &'a mut [u8],
    at: usize,
    n: usize,
    hop: &mut Option<Cipher>,
) -> Option<&'a [u8]> {
    let addr_bytes = if dest.is_ipv6() { 19 } else { 7 };
    if method.is_stream() {
        let head = IV_LEN + addr_bytes;
        if at < head || at + n > buf.len() {
            return None;
        }
        let mut iv = [0u8; IV_LEN];
        getrandom::fill(&mut iv).ok()?;
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut rc4 = Rc4::new(&key)?;
        let clear_at = at - head;
        buf[clear_at..clear_at + IV_LEN].copy_from_slice(&iv);
        write_addr(&mut buf[clear_at + IV_LEN..at], dest);
        rc4.crypt(&mut buf[at - addr_bytes..at + n]);
        return Some(&buf[clear_at..at + n]);
    }
    let salt_len = method.key_len();
    let head = salt_len + addr_bytes;
    if at < head || at + n + TAG_LEN > buf.len() {
        return None;
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt[..salt_len]).ok()?;
    // The first datagram on the chain builds the engine; every one after rekeys it: the salt is the key, so the HKDF and the schedule run again and the heap holds still.
    let cipher: &mut Cipher = match hop {
        Some(cipher) => {
            cipher.rekey(master, &salt[..salt_len])?;
            cipher
        }
        None => hop.insert(Cipher::from_master_key(method, master, &salt[..salt_len])?),
    };
    let clear_at = at - head;
    buf[clear_at..clear_at + salt_len].copy_from_slice(&salt[..salt_len]);
    write_addr(&mut buf[clear_at + salt_len..at], dest);
    let tag = cipher.seal_piece_in_place(&mut buf[at - addr_bytes..at + n])?;
    buf[at + n..at + n + TAG_LEN].copy_from_slice(&tag);
    Some(&buf[clear_at..at + n + TAG_LEN])
}

/// Open one wire datagram in place in the caller's buffer: the salt and the address header precede the payload and the payload comes back where the datagram put it, so a datagram costs no allocation, no second buffer and no `memmove`.
pub(crate) fn open_datagram<'a>(
    master: &MasterKey,
    method: Method,
    packet: &'a mut [u8],
    hop: &mut Option<Cipher>,
) -> Option<(SocketAddr, &'a [u8])> {
    if method.is_stream() {
        if packet.len() < IV_LEN + 1 {
            return None;
        }
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&packet[..IV_LEN]);
        let key = rc4_md5_key(master.as_bytes(), &iv)?;
        let mut rc4 = Rc4::new(&key)?;
        rc4.crypt(&mut packet[IV_LEN..]);
        let (target, used) = parse_addr_header(&packet[IV_LEN..])?;
        return Some((target, &packet[IV_LEN + used..]));
    }
    let salt_len = method.key_len();
    if packet.len() < salt_len + TAG_LEN + 1 {
        return None;
    }
    // The first datagram on the chain builds the engine; every one after rekeys it: the salt is the key, so the HKDF and the schedule run again and the heap holds still.
    let cipher: &mut Cipher = match hop {
        Some(cipher) => {
            cipher.rekey(master, &packet[..salt_len])?;
            cipher
        }
        None => hop.insert(Cipher::from_master_key(
            method,
            master,
            &packet[..salt_len],
        )?),
    };
    let body = &mut packet[salt_len..];
    let len = cipher.open_in_place(body)?;
    let (target, used) = parse_addr_header(&body[..len])?;
    Some((target, &body[used..len]))
}

/// Open one wire datagram against every client: the first whose tag verifies names the flow and seals its replies, and a failed probe leaves the buffer untouched because the tag is checked before the body opens.
pub(crate) fn open_datagram_any(
    users: &[SsUser],
    packet: &mut [u8],
    hops: &mut [Option<Cipher>],
) -> Option<(usize, SocketAddr, std::ops::Range<usize>)> {
    let base = packet.as_ptr() as usize;
    for (which, user) in users.iter().enumerate() {
        if let Some((target, payload)) =
            open_datagram(&user.master, user.method, &mut *packet, &mut hops[which])
        {
            let start = payload.as_ptr() as usize - base;
            return Some((which, target, start..start + payload.len()));
        }
    }
    None
}

fn parse_addr_header(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let kind = match buf.first()? {
        1 => crate::proxy::AddrKind::V4,
        4 => crate::proxy::AddrKind::V6,
        3 => crate::proxy::AddrKind::Domain,
        _ => return None,
    };
    let (body, mut used) = crate::proxy::parse_addr_body(buf, kind)?;
    let port = u16::from_be_bytes(buf.get(used..used + 2)?.try_into().ok()?);
    used += 2;
    let target = match body {
        crate::proxy::AddrBody::V4(ip) => SocketAddr::new(std::net::IpAddr::V4(ip.into()), port),
        crate::proxy::AddrBody::V6(ip) => SocketAddr::new(std::net::IpAddr::V6(ip.into()), port),
        crate::proxy::AddrBody::Domain(host) => crate::proxy::resolve_endpoint(host, port)?,
    };
    Some((target, used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IoSlice;
    use std::thread;

    /// A datagram's address literal parses straight to an address, with no
    /// `host:port` string and no resolver iterator: the counting allocator is the witness.
    #[test]
    fn a_datagram_target_is_resolved_without_a_host_port_string() {
        let mut header = vec![3u8, 3];
        header.extend_from_slice(b"::1");
        header.extend_from_slice(&443u16.to_be_bytes());
        let ((target, used), counts) =
            ferrox_core::alloc_count::measure(|| parse_addr_header(&header).expect("resolves"));
        assert_eq!(used, header.len(), "the whole header was read");
        assert_eq!(target, SocketAddr::new("::1".parse().expect("ip"), 443));
        assert_eq!(
            counts.allocs, 0,
            "an address literal is parsed, not walked through an allocating resolver iterator"
        );
    }

    /// Silence past the budget is death, not scheduling: a peer that opens the connection and never sends must not pin the raw Shadowsocks handshake thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_a_raw_shadowsocks_handshake() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(
                stream,
                &account("an-example-shared-password", "aes-256-gcm"),
                true,
            );
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// Silence past the budget is death, not scheduling: the stream handshake reads a clear IV then scans the encrypted header, and a peer that opens the connection and never sends must not pin that thread forever either.
    #[test]
    fn a_silent_peer_cannot_pin_a_stream_shadowsocks_handshake() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(
                stream,
                &account("an-example-shared-password", "rc4-md5"),
                true,
            );
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    fn methods() -> [(&'static str, Method); 10] {
        [
            ("aes-128-gcm", Method::Aes128Gcm),
            ("aead_aes_128_gcm", Method::Aes128Gcm),
            ("aes-256-gcm", Method::Aes256Gcm),
            ("aead_aes_256_gcm", Method::Aes256Gcm),
            ("chacha20-ietf-poly1305", Method::Chacha20Poly1305),
            ("aead_chacha20_poly1305", Method::Chacha20Poly1305),
            ("chacha20-poly1305", Method::Chacha20Poly1305),
            ("xchacha20-ietf-poly1305", Method::XChacha20Poly1305),
            ("aead_xchacha20_poly1305", Method::XChacha20Poly1305),
            ("AES-256-GCM", Method::Aes256Gcm),
        ]
    }

    #[test]
    fn every_named_method_and_spelling_relays_an_echo() {
        for (name, method) in methods() {
            let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let echo_port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                let (mut stream, _) = echo.accept().expect("accepts");
                let mut buf = [0u8; 1024];
                while let Ok(read) = stream.read(&mut buf) {
                    if read == 0 || stream.write_all(&buf[..read]).is_err() {
                        return;
                    }
                }
            });
            let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            let announced = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let announced = announced.clone();
                    thread::spawn(move || {
                        serve(
                            stream,
                            &account("an-example-shared-password", &announced),
                            true,
                        );
                    });
                }
            });
            let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
            let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("timeout");
            let Ok((mut send, recv)) = client_send_handshake(
                &mut uplink,
                "an-example-shared-password",
                name,
                &Destination::from(target),
            ) else {
                panic!("{name}: handshake refused");
            };
            assert!(
                matches!(send, Uplink::Aead(_)),
                "{name}: and it is the named one"
            );
            let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
            seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(_, master) => {
                    let salt_len = method.key_len();
                    let mut peer = [0u8; SALT_LEN];
                    read_exact(&mut uplink, &mut peer[..salt_len]).expect("salt");
                    Cipher::from_master_key(method, &master, &peer[..salt_len]).expect("derives")
                }
                Recv::StreamReady(_) | Recv::StreamWaiting(_) => {
                    panic!("{name}: an AEAD method never answers with stream state");
                }
            };
            let mut buf = wire_buffer();
            let back = open_chunk(&mut uplink, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"ping"[..], "{name}");
        }
    }

    #[test]
    fn a_method_outside_the_rung_is_refused() {
        for name in [
            "aes-192-gcm",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
            "none",
            "",
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "chacha20-ietf",
            "xchacha20",
        ] {
            let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            let refused = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let refused = refused.clone();
                    thread::spawn(move || {
                        serve(
                            stream,
                            &account("an-example-shared-password", &refused),
                            true,
                        );
                    });
                }
            });
            let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("timeout");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            assert!(
                client_send_handshake(
                    &mut uplink,
                    "an-example-shared-password",
                    name,
                    &Destination::from(target)
                )
                .is_err(),
                "{name}: refused"
            );
        }
    }

    #[test]
    fn stream_relays_an_echo() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(1) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || {
                    serve(
                        stream,
                        &account("an-example-shared-password", "rc4-md5"),
                        true,
                    );
                });
            }
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        uplink
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .expect("timeout");
        let Ok((mut send, recv)) = client_send_handshake(
            &mut uplink,
            "an-example-shared-password",
            "rc4-md5",
            &Destination::from(target),
        ) else {
            panic!("handshake refused");
        };
        assert!(matches!(send, Uplink::Stream(_)), "and it is the named one");
        let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
        ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
        seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
        let mut recv = match recv {
            Recv::StreamWaiting(master) => {
                let mut peer = [0u8; IV_LEN];
                read_exact(&mut uplink, &mut peer).expect("iv");
                let key = rc4_md5_key(master.as_bytes(), &peer).expect("derives");
                Rc4::new(&key).expect("schedules")
            }
            Recv::Ready(_) | Recv::Waiting(..) | Recv::StreamReady(_) => {
                panic!("a stream handshake never answers with AEAD state");
            }
        };
        let mut back = [0u8; 4];
        read_exact(&mut uplink, &mut back).expect("echo");
        recv.crypt(&mut back);
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn stream_rides_the_ws_carrier() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_ws(
                stream,
                &account("an-example-shared-password", "rc4-md5"),
                "/ss-ws",
                true,
            );
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::ws::connect(stream, "127.0.0.1", "/ss-ws", 0, &[], &[], 0).expect("carries");
        let Ok((mut send, recv)) = client_send_handshake(
            &mut writer,
            "an-example-shared-password",
            "rc4-md5",
            &Destination::from(target),
        ) else {
            panic!("handshake refused");
        };
        let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
        ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
        seal_all(&mut send, &mut ping, 4, &mut writer).expect("seals");
        let recv = match recv {
            Recv::StreamWaiting(master) => {
                let mut peer = [0u8; IV_LEN];
                read_exact(&mut reader, &mut peer).expect("iv");
                let key = rc4_md5_key(master.as_bytes(), &peer).expect("derives");
                Rc4::new(&key).expect("schedules")
            }
            Recv::Ready(_) | Recv::Waiting(..) | Recv::StreamReady(_) => {
                panic!("a stream handshake never answers with AEAD state");
            }
        };
        let mut back = Vec::new();
        let mut link = Downlink::new(&mut reader, Recv::StreamReady(recv));
        while back.is_empty() {
            match link.step(&mut back, None) {
                crate::proxy::lane_pool::Next::More | crate::proxy::lane_pool::Next::Retry => {}
                crate::proxy::lane_pool::Next::Done | crate::proxy::lane_pool::Next::Idle => break,
            }
        }
        assert_eq!(back, b"ping");
    }

    #[test]
    fn stream_relay_read_becomes_one_write() {
        struct Counting<'a> {
            seen: &'a mut Vec<u8>,
            writes: usize,
        }
        impl Write for Counting<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                self.seen.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let master = MasterKey::new("an-example-shared-password", 16);
        let key = rc4_md5_key(master.as_bytes(), &[9u8; IV_LEN]).expect("derives");
        let mut send = Uplink::Stream(Rc4::new(&key).expect("schedules"));
        let mut buf = vec![0u8; SEAL_HEAD + READ_CHUNK + TAG_LEN];
        for (i, b) in buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 251) as u8;
        }
        let want = buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK].to_vec();
        let mut seen = Vec::new();
        let writes = {
            let mut out = Counting {
                seen: &mut seen,
                writes: 0,
            };
            seal_all(&mut send, &mut buf, READ_CHUNK, &mut out).expect("seals");
            out.writes
        };
        assert_eq!(writes, 1, "a relay read is crypted and written once");
        let mut back = seen.clone();
        Rc4::new(&key).expect("schedules").crypt(&mut back);
        assert_eq!(back, want, "every byte came back");
    }

    /// What each rung is given for its read buffer, asserted rather than left to the loop above it.
    #[test]
    fn a_stream_uplink_buffers_one_slot_and_an_aead_uplink_a_batch() {
        let salt = [7u8; SALT_LEN];
        let master = MasterKey::new("an-example-shared-password", 16);
        let key = rc4_md5_key(master.as_bytes(), &[9u8; IV_LEN]).expect("derives");
        assert_eq!(
            uplink_buffer_len(&Uplink::Stream(Rc4::new(&key).expect("schedules"))),
            SLOT,
            "a stream read fills one chunk, so three more slots are memory that leg never touches"
        );
        assert_eq!(
            uplink_buffer_len(&Uplink::Aead(
                Cipher::new(Method::Aes256Gcm, "an-example-shared-password", &salt)
                    .expect("derives")
            )),
            BATCH,
            "an AEAD read fills the batch"
        );
    }

    /// Seal one datagram into a buffer of its own, the way a socket thread hands its payload to the sealer.
    fn seal_to_wire(
        master: &MasterKey,
        method: Method,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; DATAGRAM_MAX];
        buf[SEAL_ROOM..SEAL_ROOM + payload.len()].copy_from_slice(payload);
        let mut hop = None;
        seal_datagram(
            master,
            method,
            dest,
            &mut buf,
            SEAL_ROOM,
            payload.len(),
            &mut hop,
        )
        .expect("seals")
        .to_vec()
    }

    /// Open one wire datagram and copy out what it carried, for the tests that compare bytes rather than pointers.
    fn open_from_wire(
        master: &MasterKey,
        method: Method,
        packet: &[u8],
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let mut wire = packet.to_vec();
        let mut hop = None;
        let (target, payload) = open_datagram(master, method, &mut wire, &mut hop)?;
        Some((target, payload.to_vec()))
    }

    /// One listener on a list of ciphers: a datagram opens under the client whose key sealed it and the reply takes that client's salt length, while a password none lists opens nothing.
    #[test]
    fn a_datagram_opens_under_each_clients_own_cipher() {
        let target: SocketAddr = "203.0.113.9:53".parse().expect("addr");
        let users: Vec<SsUser> = [
            ("first-password", Method::Aes256Gcm),
            ("second-password", Method::Aes128Gcm),
        ]
        .into_iter()
        .map(|(password, method)| SsUser {
            method,
            master: MasterKey::new(password, method.key_len()),
            email: String::new(),
            level: 0,
        })
        .collect();
        let mut hops: Vec<Option<Cipher>> = users.iter().map(|_| None).collect();
        let mut wire = seal_to_wire(&users[1].master, users[1].method, &target, b"ping");
        let (which, got, payload) = open_datagram_any(&users, &mut wire, &mut hops)
            .expect("the second client's datagram opens");
        assert_eq!(which, 1, "the matched client names the flow");
        assert_eq!(got, target);
        assert_eq!(&wire[payload], b"ping");
        let mut reply = vec![0u8; DATAGRAM_MAX];
        reply[SEAL_ROOM..SEAL_ROOM + 4].copy_from_slice(b"pong");
        let sealed = seal_datagram(
            &users[1].master,
            users[1].method,
            &target,
            &mut reply,
            SEAL_ROOM,
            4,
            &mut hops[1],
        )
        .expect("seals");
        assert_eq!(
            sealed.len(),
            16 + 7 + 4 + TAG_LEN,
            "the reply carries aes-128's sixteen-byte salt"
        );
        let (_, back) = open_from_wire(&users[1].master, users[1].method, sealed)
            .expect("the client opens its reply");
        assert_eq!(back, b"pong");
        let stranger = seal_to_wire(
            &MasterKey::new("nobody-lists-this", 32),
            Method::Aes256Gcm,
            &target,
            b"ping",
        );
        let mut wire = stranger;
        assert!(open_datagram_any(&users, &mut wire, &mut hops).is_none());
    }

    /// Each source answers on its own association: two clients naming one destination reach the
    /// destination from two upstream sockets, and each hears only the answer to its own datagram.
    #[test]
    fn an_aead_front_answers_each_source_on_its_own_association() {
        fn echo_and_report() -> (SocketAddr, std::sync::mpsc::Receiver<bool>) {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
            let addr = sock.local_addr().expect("addr");
            let (reported, seen) = std::sync::mpsc::channel();
            thread::spawn(move || {
                let mut buf = vec![0u8; UDP_BUF];
                let mut first = None;
                let mut shared = true;
                for _ in 0..2 {
                    if let Ok((n, from)) = sock.recv_from(&mut buf) {
                        shared &= first.is_none_or(|source| source == from);
                        first.get_or_insert(from);
                        let _ = sock.send_to(&buf[..n], from);
                    }
                }
                let _ = reported.send(shared);
            });
            (addr, seen)
        }
        let (dest, upstream) = echo_and_report();
        let users: Vec<SsUser> = [
            ("first-password", Method::Aes256Gcm),
            ("second-password", Method::Aes128Gcm),
        ]
        .into_iter()
        .map(|(password, method)| SsUser {
            method,
            master: MasterKey::new(password, method.key_len()),
            email: String::new(),
            level: 0,
        })
        .collect();
        let front = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let front_addr = front.local_addr().expect("addr");
        let serving = users.clone();
        thread::spawn(move || serve_udp_on(&front, &serving, true));
        let first = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let second = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let mut wire = vec![0u8; DATAGRAM_MAX];
        for (client, user, marker) in [
            (&first, &users[0], b"first".as_slice()),
            (&second, &users[1], b"second".as_slice()),
        ] {
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let packet = seal_to_wire(&user.master, user.method, &dest, marker);
            client.send_to(&packet, front_addr).expect("sends");
            let (n, _) = client
                .recv_from(&mut wire)
                .expect("the source hears its answer");
            let (from, payload) = open_from_wire(&user.master, user.method, &wire[..n])
                .expect("the answer opens under that source's own account");
            assert_eq!((from, payload.as_slice()), (dest, marker));
        }
        assert!(
            !upstream.recv().expect("the destination reports"),
            "each client source owns its upstream association"
        );
        for client in [&first, &second] {
            client
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("timeout");
            assert!(
                client.recv_from(&mut wire).is_err(),
                "an answer is never fanned across sources"
            );
        }
    }

    /// A source whose stored account no longer opens its datagram is re-probed across the users, so an address another client now sends from is rebound instead of dropped.
    #[test]
    fn a_rebound_source_replaces_its_association() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let dest = echo.local_addr().expect("addr");
        let (reported, seen) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = reported.send(from);
                if echo.send_to(&buf[..n], from).is_err() {
                    return;
                }
            }
        });
        let users: Vec<SsUser> = [
            ("first-password", Method::Aes256Gcm),
            ("second-password", Method::Aes128Gcm),
        ]
        .into_iter()
        .map(|(password, method)| SsUser {
            method,
            master: MasterKey::new(password, method.key_len()),
            email: String::new(),
            level: 0,
        })
        .collect();
        let front = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let front_addr = front.local_addr().expect("addr");
        let serving = users.clone();
        thread::spawn(move || serve_udp_on(&front, &serving, true));
        let client = UdpSocket::bind("127.0.0.1:0").expect("binds");
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut wire = vec![0u8; DATAGRAM_MAX];
        for (user, marker) in [
            (&users[0], b"first".as_slice()),
            (&users[1], b"second".as_slice()),
        ] {
            let packet = seal_to_wire(&user.master, user.method, &dest, marker);
            client.send_to(&packet, front_addr).expect("sends");
            let (n, _) = client
                .recv_from(&mut wire)
                .expect("the rebound source hears its answer");
            let (from, payload) = open_from_wire(&user.master, user.method, &wire[..n])
                .expect("the answer opens under the account that now proves the source");
            assert_eq!((from, payload.as_slice()), (dest, marker));
        }
        let first = seen.recv().expect("the first association's source");
        let second = seen.recv().expect("the second association's source");
        assert_ne!(first, second, "the rebound association is new");
    }

    #[test]
    fn stream_udp_round_trips_and_rejects_damage() {
        let method = Method::Rc4Md5;
        let master = MasterKey::new("an-example-shared-password", 16);
        for target in [
            "127.0.0.1:53".parse().expect("v4"),
            "[2001:db8::1]:443".parse().expect("v6"),
        ] {
            let packet = seal_to_wire(&master, method, &target, b"ping");
            let header = if target.is_ipv6() { 19 } else { 7 };
            assert_eq!(
                packet.len(),
                IV_LEN + header + b"ping".len(),
                "a datagram is the IV, the header and the payload, with no tag"
            );
            let (got, payload) = open_from_wire(&master, method, &packet).expect("opens");
            assert_eq!(got, target);
            assert_eq!(payload, b"ping");
        }
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let packet = seal_to_wire(&master, method, &target, b"ping");
        let mut cut = packet.clone();
        cut.pop();
        let (_, short) = open_from_wire(&master, method, &cut).expect("opens");
        assert_eq!(
            short, b"pin",
            "a stream has no tag: truncation truncates, it does not refuse"
        );
        assert!(open_from_wire(&master, method, &packet[..10]).is_none());
        assert!(open_from_wire(&master, method, &[]).is_none());
        let wrong = MasterKey::new("a-different-password", 16);
        if let Some((_, payload)) = open_from_wire(&wrong, method, &packet) {
            assert_ne!(payload, b"ping", "a wrong password opens only noise");
        }
    }

    /// A shadowsocks inbound over gRPC whose peer answers the head and never sends its IV releases the serve thread: the carrier puts its clock away with the head, so the handshake reads under its own.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_shadowsocks_request() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(
                stream,
                &account("an-example-shared-password", "aes-256-gcm"),
                "/p",
                true,
            );
            let _ = done_tx.send(());
        });
        let stream = Connection::connect(addr).expect("connects");
        let (_reader, _writer) = crate::grpc::connect(stream, "127.0.0.1", "/p").expect("dials");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A listener that answers every connection with whatever it reads.
    fn echo() -> u16 {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else { continue };
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    while let Ok(read) = stream.read(&mut buf) {
                        if read == 0 || stream.write_all(&buf[..read]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    /// The seal now lands on the socket after the carrier's switch, so a write that fails there is the transport's, not the caller's: it must let the ladder climb instead of holding the rung.
    #[test]
    fn a_handshake_write_that_fails_after_the_switch_is_a_transport_kind() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let target = Destination::from("127.0.0.1:1".parse::<SocketAddr>().expect("addr"));
        assert!(matches!(
            client_send_handshake(
                &mut Broken,
                "an-example-shared-password",
                "aes-256-gcm",
                &target
            ),
            Err(Kind::Dropped)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn carried_transports_relay_an_echo() {
        const PASSWORD: &str = "an-example-shared-password";
        const METHOD: &str = "aes-256-gcm";
        fn answers(reader: &mut dyn Read, writer: &mut dyn Write, mut send: Uplink, recv: Recv) {
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(_, master) => {
                    let mut peer = [0u8; SALT_LEN];
                    read_exact(reader, &mut peer).expect("salt");
                    Cipher::from_master_key(Method::Aes256Gcm, &master, &peer).expect("derives")
                }
                Recv::StreamReady(_) | Recv::StreamWaiting(_) => {
                    panic!("an AEAD method never answers with stream state");
                }
            };
            let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
            seal_all(&mut send, &mut ping, 4, writer).expect("seals");
            let mut buf = wire_buffer();
            let back = open_chunk(reader, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"ping"[..]);
        }
        fn round_trip(reader: &mut dyn Read, writer: &mut dyn Write, target: &Destination) {
            let Ok((send, recv)) = client_send_handshake(writer, PASSWORD, METHOD, target) else {
                panic!("handshake refused");
            };
            answers(reader, writer, send, recv);
        }
        fn tunnel(serve: fn(Connection, &[SsUser], &str, bool), path: &'static str) -> Connection {
            let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            thread::spawn(move || {
                let (stream, _) = server.accept().expect("accepts");
                serve(stream, &account(PASSWORD, METHOD), path, true);
            });
            Connection::connect(("127.0.0.1", port)).expect("connects")
        }
        fn serve_httpupgrade_without_host(
            stream: Connection,
            users: &[SsUser],
            path: &str,
            freedom: bool,
        ) {
            serve_httpupgrade(stream, users, path, "", freedom);
        }
        fn sealed(target: &Destination) -> (Vec<u8>, Uplink, Recv) {
            let mut packet = Vec::new();
            let Ok((send, recv)) = client_send_handshake(&mut packet, PASSWORD, METHOD, target)
            else {
                panic!("handshake refused");
            };
            (packet, send, recv)
        }
        let echo_port = echo();
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let target = Destination::from(target);
        let (mut reader, mut writer) = crate::ws::connect(
            tunnel(serve_ws, "/ss-ws"),
            "127.0.0.1",
            "/ss-ws",
            0,
            &[],
            &[],
            0,
        )
        .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        // What the dial does on this carrier: the request packet is sealed before the connect, so it leaves whole after the answer.
        let (packet, send, recv) = sealed(&target);
        let (mut reader, mut writer) = crate::httpupgrade::connect(
            tunnel(serve_httpupgrade_without_host, "/ss-upgrade"),
            "127.0.0.1",
            "/ss-upgrade",
            &packet,
            &[],
        )
        .expect("carries");
        answers(&mut reader, &mut writer, send, recv);
        let (mut reader, mut writer) = crate::grpc::connect(
            tunnel(serve_grpc, "/TunnelService/Tun"),
            "127.0.0.1",
            "/TunnelService/Tun",
        )
        .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let (mut reader, mut writer) = crate::xhttp::connect(
            tunnel(serve_xhttp_legacy, "/ss-xhttp"),
            "127.0.0.1",
            "/ss-xhttp",
            &[],
            &"X".repeat(500),
        )
        .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let (mut reader, mut writer) = crate::httpheader::connect(
            tunnel(serve_httpheader, "/ss-camouflage"),
            "127.0.0.1",
            "/ss-camouflage",
            &[],
        )
        .expect("carries");
        round_trip(&mut reader, &mut writer, &target);
    }

    /// A carrier that answers the xHTTP head and then goes silent ends at the handshake budget instead of holding the slot forever.
    #[test]
    fn a_silent_xhttp_handshake_ends_at_its_budget() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(std::time::Duration::from_millis(100)),
            ..Default::default()
        });
        let settings = crate::xhttp::XhttpSettings::stream_one();
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        let users = account("an-example-shared-password", "aes-256-gcm");
        crate::budgets::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_xhttp(stream, &users, &settings, true);
        });
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("timeout");
        let referer = "http://127.0.0.1?x_padding=".to_owned() + &"X".repeat(500);
        client
            .write_all(
                format!(
                    "POST / HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("writes the head");
        let began = std::time::Instant::now();
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => seen.extend_from_slice(&buf[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("the slot held the handshake past its budget: {error}"),
            }
        }
        assert!(
            String::from_utf8_lossy(&seen[..seen.len().min(12)]).starts_with("HTTP/1.1 2"),
            "the carrier answered {seen:?}"
        );
        assert!(
            began.elapsed() < std::time::Duration::from_secs(5),
            "the handshake waited {:?}",
            began.elapsed()
        );
    }

    /// A writer that has `writev`, which is what the relay's own socket is: it counts vectored
    /// calls, so a batch that leaves in one of them is one syscall by the same account the kernel
    /// keeps, and a carrier without `writev` is the other writer below.
    struct Vectored<'a> {
        seen: &'a mut Vec<u8>,
        writes: usize,
        bases: Vec<usize>,
    }
    impl Write for Vectored<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bases.push(buf.as_ptr() as usize);
            self.seen.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
            self.writes += 1;
            let mut taken = 0usize;
            for piece in bufs {
                self.bases.push(piece.as_ptr() as usize);
                self.seen.extend_from_slice(piece);
                taken += piece.len();
            }
            Ok(taken)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Bytes of a batch, each in the slot the kernel would have filled it with.
    fn slot_fill(total: usize) -> Vec<u8> {
        let mut buf = vec![0u8; CHUNKS_PER_BATCH * SLOT];
        for (i, byte) in (0..total).map(|i| (i % 251) as u8).enumerate() {
            buf[SEAL_HEAD + (i / MAX_CHUNK) * SLOT + (i % MAX_CHUNK)] = byte;
        }
        buf
    }

    #[test]
    fn one_relay_read_becomes_one_write_and_reads_back_whole() {
        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let total = MAX_CHUNK * CHUNKS_PER_BATCH;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let mut buf = slot_fill(total);
        let plain: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let base = buf.as_ptr() as usize;
        let capacity = buf.capacity();
        let room = base + buf.len();
        let mut seen = Vec::new();
        let (writes, bases) = {
            let mut out = Vectored {
                seen: &mut seen,
                writes: 0,
                bases: Vec::new(),
            };
            seal_all(&mut send, &mut buf, total, &mut out).expect("seals");
            (out.writes, out.bases)
        };
        assert_eq!(writes, 1, "four sealed chunks leave in one vectored write");
        assert_eq!(bases.len(), CHUNKS_PER_BATCH);
        for at in &bases {
            assert!(
                (base..room).contains(at),
                "a chunk leaves from the caller's buffer"
            );
        }
        assert_eq!(buf.as_ptr() as usize, base, "the read buffer never moves");
        assert_eq!(buf.capacity(), capacity, "the read buffer never grows");

        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&seen);
        let mut wire = wire_buffer();
        let mut got = 0usize;
        let mut chunks = 0usize;
        while got < plain.len() {
            let back = open_chunk(&mut cursor, &mut recv, &mut wire).expect("opens");
            assert_eq!(back, &plain[got..got + back.len()]);
            got += back.len();
            chunks += 1;
        }
        assert_eq!(got, plain.len(), "every byte came back");
        assert_eq!(
            chunks, CHUNKS_PER_BATCH,
            "one relay read of {total} B seals as four chunks"
        );

        // The batch is the same stream the same chunks sealed one at a time are: same lengths, same order, same tags, because every nonce and every byte position is unchanged by batching.
        let mut one_by_one = Vec::new();
        let mut again = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        for part in plain.chunks(MAX_CHUNK) {
            let mut slot = vec![0u8; SLOT];
            slot[SEAL_HEAD..SEAL_HEAD + part.len()].copy_from_slice(part);
            seal_all(&mut again, &mut slot, part.len(), &mut one_by_one).expect("seals");
        }
        assert_eq!(
            seen, one_by_one,
            "a batch is the chunks written one at a time"
        );
    }

    /// The read half of the batch, counted where the count is exact: one vectored read asks for
    /// [`CHUNKS_PER_BATCH`] slots of [`MAX_CHUNK`], and a fill that stops short lands only in the
    /// last slot, which is the one layout [`seal_all`] can tile without moving a byte.
    #[test]
    fn one_relay_read_asks_for_every_slot_of_a_batch() {
        struct Slots {
            rest: Vec<u8>,
            given: Vec<usize>,
            reads: usize,
        }
        impl Read for Slots {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let take = self.rest.len().min(buf.len());
                buf[..take].copy_from_slice(&self.rest[..take]);
                self.rest.drain(..take);
                Ok(take)
            }
            fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
                self.reads += 1;
                self.given = bufs.iter().map(|slot| slot.len()).collect();
                let mut filled = 0usize;
                for slot in bufs {
                    let take = self.rest.len().min(slot.len());
                    slot[..take].copy_from_slice(&self.rest[..take]);
                    self.rest.drain(..take);
                    filled += take;
                }
                Ok(filled)
            }
        }

        let plain: Vec<u8> = (0..MAX_CHUNK * CHUNKS_PER_BATCH - 7)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut read = Slots {
            rest: plain.clone(),
            given: Vec::new(),
            reads: 0,
        };
        let mut buf = vec![0u8; BATCH];
        let got = read_slots(&mut read, &mut buf).expect("reads");
        assert_eq!(got, plain.len(), "one read takes the whole fill");
        assert_eq!(read.reads, 1, "a batch is one read syscall");
        assert_eq!(
            read.given,
            vec![MAX_CHUNK; CHUNKS_PER_BATCH],
            "every slot of the batch is offered at once"
        );
        for (i, byte) in plain.iter().enumerate() {
            assert_eq!(
                buf[SEAL_HEAD + (i / MAX_CHUNK) * SLOT + (i % MAX_CHUNK)],
                *byte,
                "byte {i} of the fill sits in the slot seal_all reads it from"
            );
        }
    }

    /// The downlink's batch path end to end, counted where the count is exact: a source that
    /// answers the whole window in one read, a target that counts vectored writes, and two chunks
    /// that open and leave without one byte copied out of the window.
    #[test]
    fn a_bulk_read_serves_every_buffered_chunk() {
        struct CountingReads<R> {
            read: R,
            reads: usize,
        }
        impl<R: Read> Read for CountingReads<R> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                self.read.read(buf)
            }
        }

        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let n1 = MAX_CHUNK;
        let n2 = 100usize;
        let plain: Vec<u8> = (0..n1 + n2).map(|i| (i % 251) as u8).collect();
        let mut wire = Vec::new();
        for (off, n) in [(0, n1), (n1, n2)] {
            let mut buf = vec![0u8; SEAL_HEAD + n + TAG_LEN];
            buf[SEAL_HEAD..SEAL_HEAD + n].copy_from_slice(&plain[off..off + n]);
            seal_all(&mut send, &mut buf, n, &mut wire).expect("seals");
        }
        let recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut link = Downlink::new(
            CountingReads {
                read: std::io::Cursor::new(wire),
                reads: 0,
            },
            Recv::Ready(recv),
        );
        let mut got = Vec::new();
        let (writes, bases) = {
            let mut out = Vectored {
                seen: &mut got,
                writes: 0,
                bases: Vec::new(),
            };
            while !matches!(
                link.step(&mut out, None),
                crate::proxy::lane_pool::Next::Done
            ) {}
            (out.writes, out.bases)
        };
        let window = link.window().expect("an opened batch keeps its window");
        assert_eq!(
            window.read.reads, 2,
            "one bulk read serves both chunks, the next one finds the end"
        );
        assert_eq!(writes, 1, "the opened batch leaves in one write");
        assert_eq!(bases.len(), 2, "one piece per opened chunk");
        assert!(
            bases[0] < bases[1],
            "the chunks open where they lie, in wire order"
        );
        let base = window.buf.as_ptr() as usize;
        let room = base + window.buf.len();
        for at in &bases {
            assert!(
                (base..room).contains(at),
                "a plaintext leaves from the window's own buffer"
            );
        }
        assert_eq!(got, plain, "the batch is the stream the seals made");
        let mut oversize = vec![0u8; SEAL_HEAD + MAX_CHUNK + 1 + TAG_LEN];
        assert!(
            seal_all(&mut send, &mut oversize, MAX_CHUNK + 1, &mut Vec::new()).is_err(),
            "a second chunk has no slot of its own in a one-slot buffer"
        );
    }

    /// A batch is the chunks the window already holds, and nothing more: a peer that stops to hear
    /// back from its own target must find the chunk it sent already at the target, so only the
    /// first chunk of a batch is ever waited for. One read, two opened, no third byte asked for.
    #[test]
    fn a_batch_never_waits_for_a_chunk_that_has_not_arrived() {
        struct Staged {
            parts: Vec<Vec<u8>>,
            at: usize,
            reads: usize,
        }
        impl Read for Staged {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                let Some(part) = self.parts.get(self.at) else {
                    return Ok(0);
                };
                self.at += 1;
                let take = part.len().min(buf.len());
                buf[..take].copy_from_slice(&part[..take]);
                Ok(take)
            }
        }

        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let first: Vec<u8> = (0..MAX_CHUNK).map(|i| (i % 251) as u8).collect();
        let second: Vec<u8> = (0..MAX_CHUNK).map(|i| (i % 197) as u8).collect();
        let seal = |send: &mut Uplink, plain: &[u8]| {
            let mut buf = vec![0u8; SLOT];
            buf[SEAL_HEAD..SEAL_HEAD + plain.len()].copy_from_slice(plain);
            let mut wire = Vec::new();
            seal_all(send, &mut buf, plain.len(), &mut wire).expect("seals");
            wire
        };
        let whole = seal(&mut send, &first);
        let rest = seal(&mut send, &second);
        // Chunk one whole, then the second chunk's sealed length and part of its payload; the rest of that payload is what the pump must not wait for.
        let split = LENGTH_LEN + TAG_LEN + 8;
        let mut staged = Staged {
            parts: vec![
                [whole.as_slice(), &rest[..split]].concat(),
                rest[split..].to_vec(),
            ],
            at: 0,
            reads: 0,
        };
        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut window = ChunkReader::new(&mut staged);
        let mut batch = [(0usize, 0usize); CHUNKS_PER_BATCH];
        assert!(matches!(window.try_fill(), Fill::Ready));
        assert_eq!(
            window.open_ready(&mut recv, &mut batch).chunks,
            1,
            "the second chunk is still arriving"
        );
        assert_eq!(window.read.reads, 1, "no read is spent waiting for it");
        assert_eq!(&window.buf[batch[0].0..batch[0].0 + batch[0].1], &first[..]);
        assert!(matches!(window.try_fill(), Fill::Ready));
        assert_eq!(
            window.open_ready(&mut recv, &mut batch).chunks,
            1,
            "the held length opens against its own nonce once the payload lands"
        );
        assert_eq!(
            &window.buf[batch[0].0..batch[0].0 + batch[0].1],
            &second[..]
        );
    }

    #[test]
    fn chunks_open_that_seal_sealed_and_reject_damage() {
        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let mut wire = Vec::new();
        let mut msg = [0u8; SEAL_HEAD + 17 + TAG_LEN];
        msg[SEAL_HEAD..SEAL_HEAD + 17].copy_from_slice(b"length-is-framing");
        seal_all(&mut send, &mut msg, 17, &mut wire).expect("seals");
        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&wire);
        let mut buf = wire_buffer();
        let base = buf.as_ptr() as usize;
        let room = buf.capacity();
        let back_at = {
            let back = open_chunk(&mut cursor, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"length-is-framing"[..]);
            back.as_ptr() as usize
        };
        assert!(
            (base..base + room).contains(&back_at),
            "the opened payload is a separate buffer, so a chunk read copies it out"
        );
        assert_eq!(buf.as_ptr() as usize, base, "the read buffer never moves");
        assert_eq!(buf.capacity(), room, "the read buffer never grows");

        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut damaged = std::io::Cursor::new(&tampered);
        let mut fresh = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        assert!(open_chunk(&mut damaged, &mut fresh, &mut wire_buffer()).is_none());
    }

    #[test]
    fn a_forged_tag_closes_the_downlink_and_an_incomplete_chunk_waits() {
        struct Quiet<'a> {
            data: &'a [u8],
            at: usize,
        }
        impl Read for Quiet<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.at == self.data.len() {
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                let take = (self.data.len() - self.at).min(buf.len());
                buf[..take].copy_from_slice(&self.data[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }

        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let mut msg = [0u8; SEAL_HEAD + 17 + TAG_LEN];
        msg[SEAL_HEAD..SEAL_HEAD + 17].copy_from_slice(b"length-is-framing");
        let mut wire = Vec::new();
        seal_all(&mut send, &mut msg, 17, &mut wire).expect("seals");

        for at in [SEAL_HEAD - 1, wire.len() - 1] {
            let mut tampered = wire.clone();
            tampered[at] ^= 1;
            let mut reader = Quiet {
                data: &tampered,
                at: 0,
            };
            let mut window = ChunkReader::new(&mut reader);
            assert!(matches!(window.try_fill(), Fill::Ready));
            let recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
            let mut out = Vec::new();
            let (next, _) = aead_step(window, recv, &mut out, None);
            assert_eq!(
                next,
                crate::proxy::lane_pool::Next::Done,
                "a forged tag at byte {at} closes the relay"
            );
            assert!(
                out.is_empty(),
                "a forged or incomplete chunk writes nothing"
            );
        }

        let mut incomplete = wire;
        incomplete.truncate(incomplete.len() - 1);
        let mut reader = Quiet {
            data: &incomplete,
            at: 0,
        };
        let mut window = ChunkReader::new(&mut reader);
        assert!(matches!(window.try_fill(), Fill::Ready));
        let recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut out = Vec::new();
        let (next, _) = aead_step(window, recv, &mut out, None);
        assert_eq!(
            next,
            crate::proxy::lane_pool::Next::Idle,
            "a chunk that has not finished arriving still waits"
        );
        assert!(
            out.is_empty(),
            "a forged or incomplete chunk writes nothing"
        );
    }

    #[test]
    fn an_authenticated_chunk_before_a_forged_one_still_reaches_the_target() {
        struct Quiet<'a> {
            data: &'a [u8],
            at: usize,
        }
        impl Read for Quiet<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.at == self.data.len() {
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                let take = (self.data.len() - self.at).min(buf.len());
                buf[..take].copy_from_slice(&self.data[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }

        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let first: Vec<u8> = (0..17).map(|i| (i % 251) as u8).collect();
        let second: Vec<u8> = (0..17).map(|i| (i % 197) as u8).collect();
        let mut wire = Vec::new();
        for plain in [&first, &second] {
            let mut msg = vec![0u8; SEAL_HEAD + plain.len() + TAG_LEN];
            msg[SEAL_HEAD..SEAL_HEAD + plain.len()].copy_from_slice(plain);
            seal_all(&mut send, &mut msg, plain.len(), &mut wire).expect("seals");
        }
        let last = wire.len() - 1;
        wire[last] ^= 1;

        let mut reader = Quiet { data: &wire, at: 0 };
        let mut window = ChunkReader::new(&mut reader);
        assert!(matches!(window.try_fill(), Fill::Ready));
        let recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut out = Vec::new();
        let (next, _) = aead_step(window, recv, &mut out, None);
        assert_eq!(next, crate::proxy::lane_pool::Next::Done);
        assert_eq!(
            out, first,
            "the chunk opened before the forged tag still lands"
        );
    }

    #[test]
    fn udp_salts_follow_the_method() {
        for (name, salt_len) in [
            ("aes-128-gcm", 16),
            ("aes-256-gcm", 32),
            ("chacha20-ietf-poly1305", 32),
        ] {
            let method = Method::parse(name).expect("names");
            assert_eq!(method.key_len(), salt_len, "{name}");
            let master = MasterKey::new("an-example-shared-password", salt_len);
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let packet = seal_to_wire(&master, method, &target, b"ping");
            assert_eq!(packet.len(), salt_len + 7 + 4 + TAG_LEN, "{name}");
            let (got, payload) = open_from_wire(&master, method, &packet).expect("opens");
            assert_eq!(got, target, "{name}");
            assert_eq!(payload, b"ping", "{name}");
        }
    }

    #[test]
    fn every_payload_length_and_address_survives_the_round_trip() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let mut checked = 0usize;
        for addr in [
            "127.0.0.1:53".parse().expect("v4"),
            "[2001:db8::1]:443".parse().expect("v6"),
            "0.0.0.0:65535".parse().expect("v4 edge"),
        ] {
            for len in (0..=300usize).chain([511, 512, 513, 1024, 1500, 4096]) {
                let payload: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(9))
                    .collect();
                let packet = seal_to_wire(&master, method, &addr, &payload);
                let (got, back) = open_from_wire(&master, method, &packet).expect("opens");
                assert_eq!(got, addr, "{addr} len {len}");
                assert_eq!(back, payload, "{addr} len {len}");
                checked += 1;
            }
        }
        assert!(checked > 900, "the sweep should be dense, not a sample");
    }

    /// The sealed packet and the opened payload must both be slices of the caller's own datagram buffer: one buffer per datagram, no second pass, and the buffer must not move or grow while datagrams flow through it.
    #[test]
    fn an_opened_payload_is_the_callers_own_bytes() {
        for (method, key_len) in [(Method::Aes256Gcm, 32), (Method::Rc4Md5, 16)] {
            let master = MasterKey::new("an-example-shared-password", key_len);
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let payload = b"a payload worth keeping";
            let mut wire = vec![0u8; DATAGRAM_MAX];
            let base = wire.as_ptr() as usize;
            let room = wire.capacity();
            let mut hop = None;
            for round in 0..8 {
                wire[SEAL_ROOM..SEAL_ROOM + payload.len()].copy_from_slice(payload);
                let (sealed_at, sealed) = {
                    let packet = seal_datagram(
                        &master,
                        method,
                        &target,
                        &mut wire,
                        SEAL_ROOM,
                        payload.len(),
                        &mut hop,
                    )
                    .expect("seals");
                    let at = packet.as_ptr() as usize;
                    assert!(
                        (base..base + room).contains(&at),
                        "round {round}: the sealed datagram is outside the caller's buffer"
                    );
                    (at - base, packet.len())
                };
                assert_eq!(
                    wire.as_ptr() as usize,
                    base,
                    "round {round}: the seal buffer moved, so a datagram reallocates"
                );
                assert_eq!(
                    wire.capacity(),
                    room,
                    "round {round}: the seal buffer grew, so a datagram reallocates"
                );
                let opened_at = {
                    let (got, opened) = open_datagram(
                        &master,
                        method,
                        &mut wire[sealed_at..sealed_at + sealed],
                        &mut hop,
                    )
                    .expect("opens");
                    assert_eq!(got, target, "round {round}");
                    assert_eq!(opened, payload, "round {round}");
                    opened.as_ptr() as usize
                };
                assert!(
                    (base..base + room).contains(&opened_at),
                    "round {round}: the payload is a separate buffer, so the datagram paid a \
                     second pass to reach it"
                );
                assert_eq!(
                    wire.as_ptr() as usize,
                    base,
                    "round {round}: the open buffer moved, so a datagram reallocates"
                );
                assert_eq!(
                    wire.capacity(),
                    room,
                    "round {round}: the open buffer grew, so a datagram reallocates"
                );
            }
        }
    }

    #[test]
    fn udp_datagrams_reject_damage() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let packet = seal_to_wire(&master, method, &target, b"ping");
        let wrong = MasterKey::new("a-different-password", 32);
        assert!(open_from_wire(&wrong, method, &packet).is_none());
        let mut cut = packet.clone();
        cut.pop();
        assert!(open_from_wire(&master, method, &cut).is_none());
        let mut flipped = packet.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        let as_sent = flipped.clone();
        let mut hop = None;
        assert!(open_datagram(&master, method, &mut flipped, &mut hop).is_none());
        assert_eq!(
            flipped, as_sent,
            "a refused datagram is left exactly as it arrived"
        );
        assert!(open_from_wire(&master, method, &packet[..10]).is_none());
        assert!(open_from_wire(&master, method, &[]).is_none());
    }

    /// A stream account seals no tag, so each destination's reply goes to the client whose datagram last named it rather than to whichever source spoke last.
    #[test]
    fn a_stream_front_routes_each_destination_back_to_its_client() {
        fn answer(word: u8) -> (SocketAddr, thread::JoinHandle<()>) {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
            let addr = sock.local_addr().expect("addr");
            let handle = thread::spawn(move || {
                let mut buf = vec![0u8; UDP_BUF];
                while let Ok((n, src)) = sock.recv_from(&mut buf) {
                    if sock.send_to(&vec![word; n], src).is_err() {
                        return;
                    }
                }
            });
            (addr, handle)
        }
        let (a_dest, _a) = answer(b'a');
        let (b_dest, _b) = answer(b'b');
        let method = Method::Rc4Md5;
        let master = MasterKey::new("an-example-shared-password", 16);
        let users = [SsUser {
            method,
            master: master.clone(),
            email: String::new(),
            level: 0,
        }];
        let front = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let front_addr = front.local_addr().expect("addr");
        thread::spawn(move || serve_udp_on(&front, &users, true));
        let (a, b) = (
            UdpSocket::bind("127.0.0.1:0").expect("binds"),
            UdpSocket::bind("127.0.0.1:0").expect("binds"),
        );
        a.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        b.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        a.send_to(&seal_to_wire(&master, method, &a_dest, b"one"), front_addr)
            .expect("sends");
        b.send_to(&seal_to_wire(&master, method, &b_dest, b"two"), front_addr)
            .expect("sends");
        let mut wire = vec![0u8; DATAGRAM_MAX];
        let (n, _) = a.recv_from(&mut wire).expect("the first client hears back");
        let (from, payload) = open_from_wire(&master, method, &wire[..n]).expect("opens");
        assert_eq!((from, payload.as_slice()), (a_dest, b"aaa".as_slice()));
        let (n, _) = b
            .recv_from(&mut wire)
            .expect("the second client hears back");
        let (from, payload) = open_from_wire(&master, method, &wire[..n]).expect("opens");
        assert_eq!((from, payload.as_slice()), (b_dest, b"bbb".as_slice()));
    }

    /// What a stage between the carrier and the codec asks for: its own capacity.
    const STAGE: usize = 32 * 1024;

    /// The record size this tree's own xhttp writer frames a body in.
    const FRAME: usize = 16 * 1024;

    /// The carrier side of a carried downlink: every width the codec reaches the carrier with, which
    /// is where a stage's capacity would stand in for the codec's own ask.
    struct Asks<R> {
        read: R,
        widths: std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
    }

    impl<R: Read> Read for Asks<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.widths.borrow_mut().push(buf.len());
            self.read.read(buf)
        }
    }

    impl crate::proxy::FrameWrite for std::io::Cursor<Vec<u8>> {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            parts.iter().all(|part| self.write_all(part).is_ok())
        }
    }

    /// A carrier's answer: the head, the body framed in records the way this tree's writer frames
    /// them, and the terminator, so the codec below the carrier hears the wire as a dial hands it.
    fn carrier_answer(body: &[u8]) -> Vec<u8> {
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut wire = Vec::from(HEAD);
        for frame in body.chunks(FRAME) {
            let len = frame.len();
            wire.extend_from_slice(format!("{len:x}\r\n").as_bytes());
            wire.extend_from_slice(frame);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        wire
    }

    /// The chain the xhttp arm composes, driven from memory: an AEAD batch arrives through the real
    /// carrier framing into the window that opens it, and the carrier hears the window's own room —
    /// a `BufReader` between them would have swallowed the ask below its capacity and answered the
    /// window from its stage, so the capacity itself is what the carrier would hear.
    #[test]
    fn the_carrier_and_the_window_ask_the_socket_as_one() {
        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Uplink::Aead(
            Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
        );
        let plain: Vec<u8> = (0..MAX_CHUNK * 8).map(|i| (i % 251) as u8).collect();
        let mut body = Vec::new();
        for piece in plain.chunks(MAX_CHUNK) {
            let len = piece.len();
            let mut buf = vec![0u8; SEAL_HEAD + len + TAG_LEN];
            buf[SEAL_HEAD..SEAL_HEAD + len].copy_from_slice(piece);
            seal_all(&mut send, &mut buf, len, &mut body).expect("seals");
        }
        let (carrier, _writer) = crate::xhttp::connect_split(
            std::io::Cursor::new(carrier_answer(&body)),
            std::io::Cursor::new(Vec::new()),
            "h",
            "/share",
            &[],
            &"X".repeat(500),
        )
        .expect("dials the head");
        let widths = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut out = Vec::new();
        assert!(
            relay_downlink(
                Asks {
                    read: carrier,
                    widths: std::rc::Rc::clone(&widths),
                },
                Recv::Ready(recv),
                &mut out,
            ),
            "the batch opens"
        );
        assert_eq!(out, plain, "a downlink byte crosses user space once");
        let seen = widths.borrow();
        assert!(
            seen.contains(&BATCH),
            "the whole window is asked of the carrier: {seen:?}"
        );
        assert!(
            seen.contains(&(BATCH - 4 * FRAME)),
            "the window's sub-capacity remainder reaches the carrier as the window asked it: {seen:?}"
        );
    }

    /// The stream rung's downlink: it asks one chunk at a time and the carrier hears that chunk, not
    /// a stage's capacity — the shape the `rc4-md5` page claims, witnessed below the carrier.
    #[test]
    fn the_stream_downlink_asks_its_own_chunk_of_the_socket() {
        let master = MasterKey::new("an-example-shared-password", 16);
        let iv = [9u8; IV_LEN];
        let key = rc4_md5_key(master.as_bytes(), &iv).expect("derives");
        let mut send = Rc4::new(&key).expect("cipher");
        let mut body = vec![0u8; READ_CHUNK * 2 + 10];
        for (i, byte) in body.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        send.crypt(&mut body);
        let widths = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let recv = Rc4::new(&key).expect("cipher");
        let (carrier, _writer) = crate::xhttp::connect_split(
            std::io::Cursor::new(carrier_answer(&body)),
            std::io::Cursor::new(Vec::new()),
            "h",
            "/share",
            &[],
            &"X".repeat(500),
        )
        .expect("dials the head");
        let plain: Vec<u8> = (0..READ_CHUNK * 2 + 10).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        assert!(
            relay_downlink(
                Asks {
                    read: carrier,
                    widths: std::rc::Rc::clone(&widths),
                },
                Recv::StreamReady(recv),
                &mut out,
            ),
            "the stream opens"
        );
        assert_eq!(out, plain, "the keystream writes where the carrier read");
        let seen = widths.borrow();
        assert!(
            seen.contains(&READ_CHUNK),
            "the relay read is asked of the carrier whole: {seen:?}"
        );
        assert!(
            !seen.contains(&STAGE),
            "a stage would ask its capacity here: {seen:?}"
        );
    }
    /// Eight sessions that never send a byte add no thread: both directions are lane steps, and a
    /// step with nothing to read hands its worker back instead of parking on the socket.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_session_costs_no_thread() {
        fn pair() -> (Connection, Connection) {
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let dialled = Connection::connect(("127.0.0.1", port)).expect("connects");
            let (accepted, _) = listener.accept().expect("accepts");
            (dialled, accepted)
        }
        if !crate::conn::in_a_quiet_process("shadowsocks::tests::a_live_session_costs_no_thread") {
            return;
        }
        let method = Method::Aes256Gcm;
        let salt = [7u8; SALT_LEN];
        let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(|| {});
        let held_first = {
            let (plain, peer) = pair();
            let (sealed, client) = pair();
            let writer = sealed.try_clone().expect("clones the carrier");
            pump_relay_carried(
                &plain,
                sealed,
                writer,
                &close,
                Uplink::Aead(
                    Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
                ),
                Recv::Ready(
                    Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
                ),
            );
            (peer, client)
        };
        let before = crate::conn::live_threads();
        let mut held = Vec::new();
        for _ in 0..8 {
            let (plain, peer) = pair();
            let (sealed, client) = pair();
            let writer = sealed.try_clone().expect("clones the carrier");
            pump_relay_carried(
                &plain,
                sealed,
                writer,
                &close,
                Uplink::Aead(
                    Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
                ),
                Recv::Ready(
                    Cipher::new(method, "an-example-shared-password", &salt).expect("derives"),
                ),
            );
            held.push((peer, client));
        }
        let after = crate::conn::live_threads();
        assert!(
            after < before + 8,
            "eight live sessions added {} threads",
            after.saturating_sub(before)
        );
        drop(held);
        drop(held_first);
    }
}
