use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrox_core::failure::Kind;
use ferrox_core::shadowsocks2022::{self, Cipher, Method, BLOCK_LEN, MAX_CHUNK, TAG_LEN};

use crate::budgets::RELAY_POLL;
use crate::conn::Connection;
use crate::proxy::{push_addr, read_exact, under_handshake, write_all_runs};

const READ_CHUNK: usize = 0x4000;
const SKEW: u64 = 30;
const LENGTH_LEN: usize = 2;
/// Room around one chunk's payload inside the caller's buffer: a sealed length before it and its tag after it, so both seals land beside the payload instead of the payload moving to them.
const SEAL_HEAD: usize = LENGTH_LEN + TAG_LEN;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn salt_seen(salt: &[u8]) -> bool {
    static WINDOW: OnceLock<Mutex<crate::proxy::Replay>> = OnceLock::new();
    let mut key = [0u8; 32];
    key[..salt.len()].copy_from_slice(salt);
    let mut guard = WINDOW
        .get_or_init(|| Mutex::new(crate::proxy::Replay::new(SKEW)))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.seen(&key, now_secs())
}

fn psks(password: &str, method: Method) -> Option<Vec<Vec<u8>>> {
    shadowsocks2022::parse_psk_list(password, method.key_len())
}

fn fresh_salt(key_len: usize) -> Option<Vec<u8>> {
    let mut salt = vec![0u8; key_len];
    getrandom::fill(&mut salt).ok()?;
    Some(salt)
}

fn padding_for(payload_len: usize) -> usize {
    if payload_len > 0 {
        0
    } else {
        16
    }
}

pub(crate) fn serve(
    mut stream: Connection,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    freedom: bool,
) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    let Some(list) = psks(password, method) else {
        return;
    };
    if list.len() == 1 {
        serve_single(&mut stream, method, &list[0], freedom);
    } else if !method.is_chacha() {
        serve_multi(stream, method, &list, identities, freedom);
    }
}

/// Read and open the fixed+variable header of an already-salted request, returning the target and any early data; the single- and multi-psk handshakes share this so the framing lives in one place.
fn read_request_header(stream: &mut dyn Read, recv: &mut Cipher) -> Option<(SocketAddr, Vec<u8>)> {
    let mut fixed = [0u8; 11 + TAG_LEN];
    if read_exact(stream, &mut fixed).is_err() {
        return None;
    }
    let len = recv.open_in_place(&mut fixed)?;
    if len != 11 || fixed[0] != 0 {
        return None;
    }
    let stamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap_or([0u8; 8]));
    if now_secs().abs_diff(stamp) > SKEW {
        return None;
    }
    let var_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
    if var_len == 0 {
        return None;
    }
    let mut variable = vec![0u8; var_len + TAG_LEN];
    if read_exact(stream, &mut variable).is_err() {
        return None;
    }
    recv.open_in_place(&mut variable)?;
    variable.truncate(var_len);
    let (target, used) = parse_addr_header(&variable)?;
    if variable.len() < used + 2 {
        return None;
    }
    let pad = usize::from(u16::from_be_bytes([variable[used], variable[used + 1]]));
    let at = used + 2 + pad;
    if at > variable.len() || (pad == 0 && at == variable.len()) {
        return None;
    }
    variable.drain(..at);
    Some((target, variable))
}

fn serve_single(stream: &mut Connection, method: Method, psk: &[u8], freedom: bool) {
    if !freedom {
        return;
    }
    let key_len = method.key_len();
    // Bound the salt/fixed/variable request reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: stream,
            until: std::time::Instant::now() + budget,
        };
        'req: {
            let mut salt = vec![0u8; key_len];
            if read_exact(&mut bounded, &mut salt).is_err() {
                break 'req None;
            }
            if salt_seen(&salt) {
                break 'req None;
            }
            let Some(mut recv) = Cipher::from_psk(method, psk, &salt) else {
                break 'req None;
            };
            let Some((target, early)) = read_request_header(&mut bounded, &mut recv) else {
                break 'req None;
            };
            Some((recv, salt, target, early))
        }
    };
    let _ = stream.set_read_timeout(None);
    let Some((recv, salt, target, early)) = opened else {
        return;
    };
    crate::accesslog::record_current(&target);
    let Ok(mut uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if !early.is_empty() && uplink.write_all(&early).is_err() {
        return;
    }
    let Some(server_salt) = fresh_salt(key_len) else {
        return;
    };
    let Some(send) = Cipher::from_psk(method, psk, &server_salt) else {
        return;
    };
    let response = Response::new(send, server_salt, salt);
    pump_relay_with_response(&uplink, stream, response, Recv::Ready(recv));
}

fn serve_multi(
    mut stream: Connection,
    method: Method,
    list: &[Vec<u8>],
    identities: &[(String, u32)],
    freedom: bool,
) {
    if !freedom || list.len() < 2 {
        return;
    }
    let key_len = method.key_len();
    let master = &list[0];
    // Bound the salt/eih/fixed/variable request reads to a wall-clock budget, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let opened = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: &mut stream,
            until: std::time::Instant::now() + budget,
        };
        'req: {
            let mut salt = vec![0u8; key_len];
            if read_exact(&mut bounded, &mut salt).is_err() {
                break 'req None;
            }
            if salt_seen(&salt) {
                break 'req None;
            }
            let mut eih = [0u8; BLOCK_LEN];
            if read_exact(&mut bounded, &mut eih).is_err() {
                break 'req None;
            }
            let Some(hash) = shadowsocks2022::decrypt_eih(method, master, &salt, &eih) else {
                break 'req None;
            };
            let Some(idx) = list[1..]
                .iter()
                .position(|p| shadowsocks2022::user_hash(p) == hash)
            else {
                break 'req None;
            };
            let psk = list[1 + idx].clone();
            let Some(mut recv) = Cipher::from_psk(method, &psk, &salt) else {
                break 'req None;
            };
            let Some((target, early)) = read_request_header(&mut bounded, &mut recv) else {
                break 'req None;
            };
            Some((recv, psk, salt, target, early, idx))
        }
    };
    let _ = stream.set_read_timeout(None);
    let Some((recv, psk, salt, target, early, idx)) = opened else {
        return;
    };
    // The identity header names one account, so the flow line and the byte counters read that user, not the inbound's default.
    if let Some((email, level)) = identities.get(idx) {
        stream = stream.with_meter(authenticate(email, *level));
    }
    crate::accesslog::record_current(&target);
    let Ok(mut uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    if !early.is_empty() && uplink.write_all(&early).is_err() {
        return;
    }
    let Some(server_salt) = fresh_salt(key_len) else {
        return;
    };
    let Some(send) = Cipher::from_psk(method, &psk, &server_salt) else {
        return;
    };
    let response = Response::new(send, server_salt, salt);
    pump_relay_with_response(&uplink, &stream, response, Recv::Ready(recv));
}

/// The account whose identity header opened the request: from here its email and level are the flow's, and the counters ride the stream.
fn authenticate(email: &str, level: u32) -> crate::stats::Meter {
    crate::accesslog::reidentify(email, level);
    crate::stats::user_traffic(email, level)
}

pub(crate) fn serve_relay(
    stream: Connection,
    method: &str,
    relay_psk: &[u8],
    dests: &[(Vec<u8>, SocketAddr)],
) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if method.is_chacha() {
        return;
    }
    serve_relay_on(stream, method, relay_psk, dests);
}

fn serve_relay_on(
    mut stream: Connection,
    method: Method,
    relay_psk: &[u8],
    dests: &[(Vec<u8>, SocketAddr)],
) {
    let key_len = method.key_len();
    if relay_psk.len() != key_len {
        return;
    }
    let mut salt = vec![0u8; key_len];
    if read_exact(&mut stream, &mut salt).is_err() {
        return;
    }
    let mut eih = [0u8; BLOCK_LEN];
    if read_exact(&mut stream, &mut eih).is_err() {
        return;
    }
    let Some(hash) = shadowsocks2022::decrypt_eih(method, relay_psk, &salt, &eih) else {
        return;
    };
    let Some((_, target)) = dests
        .iter()
        .find(|(k, _)| shadowsocks2022::user_hash(k) == hash)
    else {
        return;
    };
    let target = *target;
    let Ok(mut next) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let mut rest = crate::proxy::RelayBuf::new();
    let mut head = Vec::with_capacity(salt.len() + READ_CHUNK);
    head.extend_from_slice(&salt);
    match stream.read(rest.as_mut()) {
        Ok(0) | Err(_) => {}
        Ok(n) => head.extend_from_slice(&rest.as_mut()[..n]),
    }
    let _ = stream.set_read_timeout(None);
    if next.write_all(&head).is_err() {
        return;
    }
    relay_raw(&mut stream, &mut next);
}

fn relay_raw(a: &mut Connection, b: &mut Connection) {
    let Ok(a_read) = a.try_clone() else { return };
    let Ok(mut b_write) = b.try_clone() else {
        return;
    };
    let t = thread::spawn(move || {
        let mut buf = crate::proxy::RelayBuf::new();
        let mut src = a_read;
        loop {
            match src.read(buf.as_mut()) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if b_write.write_all(&buf.as_mut()[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut buf = crate::proxy::RelayBuf::new();
    loop {
        match b.read(buf.as_mut()) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if a.write_all(&buf.as_mut()[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = t.join();
}

fn accept_on(
    reader: &mut dyn Read,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    freedom: bool,
) -> Option<(Connection, Response, Recv, crate::stats::Meter)> {
    let method = Method::parse(method)?;
    if !freedom {
        return None;
    }
    let list = psks(password, method)?;
    let (psk, eih_len) = if list.len() == 1 {
        (list[0].clone(), 0)
    } else {
        if method.is_chacha() {
            return None;
        }
        let mut salt_probe = vec![0u8; method.key_len()];
        read_exact(reader, &mut salt_probe).ok()?;
        if salt_seen(&salt_probe) {
            return None;
        }
        let mut eih = [0u8; BLOCK_LEN];
        read_exact(reader, &mut eih).ok()?;
        let hash = shadowsocks2022::decrypt_eih(method, &list[0], &salt_probe, &eih)?;
        let idx = list[1..]
            .iter()
            .position(|p| shadowsocks2022::user_hash(p) == hash)?;
        let user = list[1 + idx].clone();
        // The identity header names one account: the flow line reads that user and the counters ride both legs.
        let meter = identities
            .get(idx)
            .map(|(email, level)| authenticate(email, *level))
            .unwrap_or_default();
        let mut recv = Cipher::from_psk(method, &user, &salt_probe)?;
        let target = read_request_header(reader, &mut recv)?;
        crate::accesslog::record_current(&target.0);
        let mut uplink = crate::conn::dial_tcp(&target.0, Duration::from_secs(8)).ok()?;
        uplink.write_all(&target.1).ok()?;
        let server_salt = fresh_salt(method.key_len())?;
        let send = Cipher::from_psk(method, &user, &server_salt)?;
        let response = Response::new(send, server_salt, salt_probe);
        return Some((uplink, response, Recv::Ready(recv), meter));
    };
    let _ = eih_len;
    let key_len = method.key_len();
    let mut salt = vec![0u8; key_len];
    read_exact(reader, &mut salt).ok()?;
    if salt_seen(&salt) {
        return None;
    }
    let mut recv = Cipher::from_psk(method, &psk, &salt)?;
    let (target, early) = read_request_header(reader, &mut recv)?;
    crate::accesslog::record_current(&target);
    let mut uplink = crate::conn::dial_tcp(&target, Duration::from_secs(8)).ok()?;
    uplink.write_all(&early).ok()?;
    let server_salt = fresh_salt(key_len)?;
    let send = Cipher::from_psk(method, &psk, &server_salt)?;
    let response = Response::new(send, server_salt, salt);
    // A single-PSK inbound names no user, so the flow keeps the inbound's default attribution and no per-user counters ride.
    Some((
        uplink,
        response,
        Recv::Ready(recv),
        crate::stats::Meter::default(),
    ))
}

pub(crate) fn serve_ws(
    stream: Connection,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((uplink, response, recv, meter)) =
        accept_on(&mut reader, password, method, identities, freedom)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    pump_relay_carried_with_response(&uplink, reader, writer, &close, response, recv);
}

pub(crate) fn serve_httpupgrade(
    stream: Connection,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    path: &str,
    host: &str,
    freedom: bool,
) {
    let Some((mut reader, writer)) = crate::httpupgrade::accept(stream, path, host) else {
        return;
    };
    let Some((uplink, response, recv, meter)) =
        accept_on(&mut reader, password, method, identities, freedom)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(std::net::Shutdown::Both);
    });
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    pump_relay_carried_with_response(&uplink, reader, writer, &close, response, recv);
}

#[cfg(test)]
pub(crate) fn serve_grpc(
    stream: Connection,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    path: &str,
    freedom: bool,
) {
    serve_grpc_with(
        stream,
        password,
        method,
        identities,
        &crate::config::GrpcSettings::path(path),
        freedom,
    );
}

pub(crate) fn serve_grpc_with(
    stream: Connection,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    settings: &crate::config::GrpcSettings,
    freedom: bool,
) {
    let Some((mut reader, writer)) = crate::grpc::accept_with(stream, settings) else {
        return;
    };
    let Some((uplink, response, recv, meter)) = under_handshake(&mut reader, |read| {
        accept_on(read, password, method, identities, freedom)
    }) else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    pump_relay_carried_with_response(&uplink, reader, writer, &close, response, recv);
}

pub(crate) fn serve_xhttp(
    stream: Connection,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
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
    let password = password.to_owned();
    let method = method.to_owned();
    let identities = identities.to_vec();
    crate::proxy::spawn_carried(move || {
        serve_xhttp_accepted(reader, writer, &password, &method, &identities, freedom);
    });
}

fn serve_xhttp_accepted(
    reader: Box<dyn crate::proxy::WindowRead + Send>,
    writer: crate::xhttp::XhttpWriter,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    freedom: bool,
) {
    // The handshake clock: a carrier that answers its head and then goes silent ends the slot at its budget instead of holding it.
    let mut reader = crate::proxy::HandshakeRead::new(reader, crate::budgets::handshake());
    let Some((uplink, response, recv, meter)) =
        accept_on(&mut reader, password, method, identities, freedom)
    else {
        writer.abort();
        return;
    };
    reader.disarm();
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    pump_relay_carried_with_response(&uplink, reader, writer, &close, response, recv);
}

pub(crate) fn serve_httpheader(
    stream: Connection,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, writer)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((uplink, response, recv, meter)) =
        accept_on(&mut reader, password, method, identities, freedom)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(std::net::Shutdown::Both);
    });
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    pump_relay_carried_with_response(&uplink, reader, writer, &close, response, recv);
}

pub(crate) fn serve_session<R, W>(
    mut reader: R,
    writer: W,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    freedom: bool,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Some((uplink, response, recv, meter)) = accept_on(
        &mut reader as &mut dyn Read,
        password,
        method,
        identities,
        freedom,
    ) else {
        close();
        return;
    };
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    pump_relay_carried_with_response(&uplink, reader, writer, close, response, recv);
}

pub(crate) fn serve_kcp<R, W>(
    mut reader: R,
    writer: W,
    password: &str,
    method: &str,
    identities: &[(String, u32)],
    freedom: bool,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Some((uplink, response, recv, meter)) = accept_on(
        &mut reader as &mut dyn Read,
        password,
        method,
        identities,
        freedom,
    ) else {
        return;
    };
    let reader = crate::proxy::metered(reader, meter.clone());
    let writer = crate::proxy::metered(writer, meter);
    pump_relay_carried_with_response(&uplink, reader, writer, close, response, recv);
}

pub(crate) fn client_send_handshake(
    uplink: &mut dyn Write,
    password: &str,
    method: &str,
    target: &crate::proxy::Destination,
) -> Result<(Cipher, Recv), Kind> {
    let method = Method::parse(method).ok_or(Kind::Local)?;
    let list = psks(password, method).ok_or(Kind::Local)?;
    let final_psk = list.last().ok_or(Kind::Local)?.clone();
    let key_len = method.key_len();
    let salt = fresh_salt(key_len).ok_or(Kind::Local)?;
    let pad_len = padding_for(0);
    let variable_len = target.addr_len() + 2 + 2 + pad_len;
    let eih_count = list.len().saturating_sub(1);
    let mut staging =
        Vec::with_capacity(salt.len() + eih_count * BLOCK_LEN + 11 + variable_len + 2 * TAG_LEN);
    staging.extend_from_slice(&salt);
    if list.len() > 1 {
        if method.is_chacha() {
            return Err(Kind::Local);
        }
        for i in 0..list.len() - 1 {
            let eih = shadowsocks2022::encrypt_eih(method, &list[i], &salt, &list[i + 1])
                .ok_or(Kind::Local)?;
            staging.extend_from_slice(&eih);
        }
    }
    let mut send = Cipher::from_psk(method, &final_psk, &salt).ok_or(Kind::Local)?;
    let at = staging.len();
    staging.push(0);
    staging.extend_from_slice(&now_secs().to_be_bytes());
    staging.extend_from_slice(&(variable_len as u16).to_be_bytes());
    send.seal_tail_in_place(&mut staging, at)
        .ok_or(Kind::Local)?;
    let at = staging.len();
    target.push_addr(&mut staging, 4, 3);
    staging.extend_from_slice(&target.port().to_be_bytes());
    staging.extend_from_slice(&(pad_len as u16).to_be_bytes());
    staging.resize(staging.len() + pad_len, 0);
    send.seal_tail_in_place(&mut staging, at)
        .ok_or(Kind::Local)?;
    uplink
        .write_all(&staging)
        .map_err(|error| Kind::of(&error))?;
    Ok((send, Recv::Waiting(method, final_psk, salt)))
}

pub(crate) enum Recv {
    Ready(Cipher),
    Waiting(Method, Vec<u8>, Vec<u8>),
}

struct Response {
    send: Cipher,
    server_salt: Vec<u8>,
    request_salt: Vec<u8>,
    first_owed: bool,
}

impl Response {
    fn new(send: Cipher, server_salt: Vec<u8>, request_salt: Vec<u8>) -> Self {
        Self {
            send,
            server_salt,
            request_salt,
            first_owed: true,
        }
    }

    fn seal_first(&mut self, buf: &mut [u8], n: usize, out: &mut dyn Write) -> std::io::Result<()> {
        let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
        let first = u16::try_from(n).map_err(|_| invalid())?;
        let key_len = self.request_salt.len();
        // xray reads salt and the fixed header in one read, so they leave as one segment: a carrier that frames per write left that read one record short.
        let mut head = [0u8; 32 + 11 + 32 + TAG_LEN];
        head[..key_len].copy_from_slice(&self.server_salt);
        head[key_len] = 1;
        head[key_len + 1..key_len + 9].copy_from_slice(&now_secs().to_be_bytes());
        head[key_len + 9..key_len + 9 + key_len].copy_from_slice(&self.request_salt);
        head[key_len + 9 + key_len..key_len + 11 + key_len].copy_from_slice(&first.to_be_bytes());
        let tag = self
            .send
            .seal_piece_in_place(&mut head[key_len..key_len + 11 + key_len])
            .ok_or_else(invalid)?;
        head[key_len + 11 + key_len..key_len + 11 + key_len + TAG_LEN].copy_from_slice(&tag);
        let head = &head[..key_len + 11 + key_len + TAG_LEN];
        let payload_wire = if n == 0 {
            &[][..]
        } else {
            let end = SEAL_HEAD + n;
            let tag = self
                .send
                .seal_piece_in_place(&mut buf[SEAL_HEAD..end])
                .ok_or_else(invalid)?;
            buf[end..end + TAG_LEN].copy_from_slice(&tag);
            &buf[SEAL_HEAD..end + TAG_LEN]
        };
        self.first_owed = false;
        crate::proxy::write_all_parts::<2>(out, &[head, payload_wire])
    }
}

enum Outbound {
    Client(Cipher),
    Server(Response),
}

pub(crate) fn pump_relay(plain: &Connection, sealed: &Connection, send: Cipher, recv: Recv) {
    pump_relay_outbound(plain, sealed, Outbound::Client(send), recv);
}

fn pump_relay_with_response(
    plain: &Connection,
    sealed: &Connection,
    response: Response,
    recv: Recv,
) {
    pump_relay_outbound(plain, sealed, Outbound::Server(response), recv);
}

fn pump_relay_outbound(plain: &Connection, sealed: &Connection, outbound: Outbound, recv: Recv) {
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
        let _ = closer.shutdown(std::net::Shutdown::Both);
    });
    pump_relay_carried_inner(plain, sealed_read, sealed_write, &close, outbound, recv);
}

pub(crate) fn pump_relay_carried<R, W>(
    plain: &Connection,
    reader: R,
    writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    send: Cipher,
    recv: Recv,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    pump_relay_carried_inner(plain, reader, writer, close, Outbound::Client(send), recv);
}

fn pump_relay_carried_with_response<R, W>(
    plain: &Connection,
    reader: R,
    writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    response: Response,
    recv: Recv,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    pump_relay_carried_inner(
        plain,
        reader,
        writer,
        close,
        Outbound::Server(response),
        recv,
    );
}

fn pump_relay_carried_inner<R, W>(
    plain: &Connection,
    reader: R,
    writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    outbound: Outbound,
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
    let mut outbound = outbound;
    let mut writer = writer;
    let mut buf = crate::proxy::RelayBuf::with_len(SEAL_HEAD + READ_CHUNK + TAG_LEN);
    let up_flow = std::sync::Arc::clone(&flow);
    crate::proxy::lane_pool::submit(
        Box::new(move || {
            let next = uplink_step(
                &mut plain_read,
                buf.as_mut(),
                &mut outbound,
                &mut writer,
                &up_flow,
            );
            if next == crate::proxy::lane_pool::Next::Idle {
                crate::proxy::note_wait_finish(&up_flow);
            }
            next
        }),
        Box::new(crate::proxy::stream_lane_done(&flow)),
    );
    let mut reader = reader;
    reader.arm_relay_poll();
    let mut link = Downlink::new(reader, recv);
    let down_flow = std::sync::Arc::clone(&flow);
    crate::proxy::lane_pool::submit(
        Box::new(move || {
            let next = link.step(&mut plain_write, Some(&down_flow));
            if next == crate::proxy::lane_pool::Next::Idle {
                crate::proxy::note_wait_finish(&down_flow);
            }
            next
        }),
        Box::new(crate::proxy::stream_lane_done(&flow)),
    );
}

/// One step of the sealing leg: read what the client sent, seal it into the carrier, and hand the
/// lane back when the socket has nothing yet rather than waiting inside the read.
fn uplink_step(
    plain_read: &mut Connection,
    buf: &mut [u8],
    outbound: &mut Outbound,
    writer: &mut dyn Write,
    flow: &crate::proxy::RelayFinish,
) -> crate::proxy::lane_pool::Next {
    let read = plain_read.read(&mut buf[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]);
    let sealed = match read {
        Ok(0) => {
            if let Outbound::Server(response) = outbound {
                if response.first_owed {
                    let _ = response.seal_first(buf, 0, writer);
                }
            }
            return crate::proxy::lane_pool::Next::Done;
        }
        Ok(n) => match outbound {
            Outbound::Client(send) => seal_all(send, buf, n, writer),
            Outbound::Server(response) => {
                if response.first_owed {
                    response.seal_first(buf, n, writer)
                } else {
                    seal_all(&mut response.send, buf, n, writer)
                }
            }
        },
        Err(error)
            if crate::proxy::is_timeout(&error)
                && !flow.ended_and_idle(crate::budgets::RELAY_RESPONSE_IDLE) =>
        {
            return crate::proxy::lane_pool::Next::Idle;
        }
        Err(_) => return crate::proxy::lane_pool::Next::Done,
    };
    if sealed.is_ok() {
        crate::proxy::lane_pool::Next::More
    } else {
        crate::proxy::lane_pool::Next::Done
    }
}

/// The downlink the dials build: the carrier's octets opened into the codec's own window, so the
/// widest ask the carrier ever hears is a window, a sealed length never costs its own ask, and a
/// payload byte crosses user space once. `false` is the handshake never opening, which is the
/// blocking dial's own early exit: the carrier is not finished and the uplink is not joined.
#[cfg(test)]
fn relay_downlink<R: Read>(reader: R, recv: Recv, out: &mut dyn Write) -> bool {
    let mut link = Downlink::new(reader, recv);
    loop {
        let handshaking = !matches!(link, Downlink::Aead { .. });
        match link.step(out, None) {
            crate::proxy::lane_pool::Next::Done => return !handshaking,
            crate::proxy::lane_pool::Next::Idle
            | crate::proxy::lane_pool::Next::More
            | crate::proxy::lane_pool::Next::Retry => {}
        }
    }
}

/// The carrier's direction of a sealed relay as lane steps: the server's salt, the fixed header a
/// 2022 server answers with, its first payload, then the codec's own window. A step that finds
/// nothing yet hands the lane back instead of waiting on the socket.
enum Downlink<R> {
    Salt {
        read: R,
        method: Method,
        psk: Vec<u8>,
        client_salt: Vec<u8>,
        server_salt: Vec<u8>,
        at: usize,
    },
    Fixed {
        read: R,
        cipher: Cipher,
        fixed: Vec<u8>,
        client_salt: Vec<u8>,
        at: usize,
    },
    First {
        read: R,
        cipher: Cipher,
        chunk: Vec<u8>,
        at: usize,
    },
    Aead {
        window: ChunkReader<R>,
        cipher: Cipher,
    },
    /// Holds the value a step swaps out while it runs; never observed or stepped twice.
    Running,
}

impl<R: Read> Downlink<R> {
    fn new(read: R, recv: Recv) -> Self {
        match recv {
            Recv::Ready(cipher) => Self::Aead {
                window: ChunkReader::new(read),
                cipher,
            },
            Recv::Waiting(method, psk, client_salt) => {
                let key_len = method.key_len();
                Self::Salt {
                    read,
                    method,
                    psk,
                    client_salt,
                    server_salt: vec![0u8; key_len],
                    at: 0,
                }
            }
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
            Self::Salt {
                read,
                method,
                psk,
                client_salt,
                server_salt,
                at,
            } => salt_step(read, method, psk, client_salt, server_salt, at, flow),
            Self::Fixed {
                read,
                cipher,
                fixed,
                client_salt,
                at,
            } => fixed_step(read, cipher, fixed, client_salt, at, flow),
            Self::First {
                read,
                cipher,
                chunk,
                at,
            } => first_step(read, cipher, chunk, at, out, flow),
            Self::Aead { window, cipher } => aead_step(window, cipher, out, flow),
            Self::Running => unreachable!("a step that is running is never stepped again"),
        }
    }
}

/// The server's salt, one read at a time: the key that opens everything behind it derives from it.
#[allow(clippy::too_many_arguments)]
fn salt_step<R: Read>(
    mut read: R,
    method: Method,
    psk: Vec<u8>,
    client_salt: Vec<u8>,
    mut server_salt: Vec<u8>,
    mut at: usize,
    flow: Option<&crate::proxy::RelayFinish>,
) -> (crate::proxy::lane_pool::Next, Downlink<R>) {
    let key_len = method.key_len();
    match read.read(&mut server_salt[at..key_len]) {
        Ok(0) => (crate::proxy::lane_pool::Next::Done, Downlink::Running),
        Ok(n) => {
            at += n;
            if at < key_len {
                return (
                    crate::proxy::lane_pool::Next::More,
                    Downlink::Salt {
                        read,
                        method,
                        psk,
                        client_salt,
                        server_salt,
                        at,
                    },
                );
            }
            let Some(cipher) = Cipher::from_psk(method, &psk, &server_salt) else {
                return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
            };
            let fixed_len = 1 + 8 + key_len + 2 + TAG_LEN;
            (
                crate::proxy::lane_pool::Next::More,
                Downlink::Fixed {
                    read,
                    cipher,
                    fixed: vec![0u8; fixed_len],
                    client_salt,
                    at: 0,
                },
            )
        }
        Err(error) if crate::proxy::is_timeout(&error) => (
            waited(flow),
            Downlink::Salt {
                read,
                method,
                psk,
                client_salt,
                server_salt,
                at,
            },
        ),
        Err(_) => (crate::proxy::lane_pool::Next::Done, Downlink::Running),
    }
}

/// The fixed header a 2022 server answers with, then the first payload chunk its length names.
fn fixed_step<R: Read>(
    mut read: R,
    mut cipher: Cipher,
    mut fixed: Vec<u8>,
    client_salt: Vec<u8>,
    mut at: usize,
    flow: Option<&crate::proxy::RelayFinish>,
) -> (crate::proxy::lane_pool::Next, Downlink<R>) {
    match read.read(&mut fixed[at..]) {
        Ok(0) => (crate::proxy::lane_pool::Next::Done, Downlink::Running),
        Ok(n) => {
            at += n;
            if at < fixed.len() {
                return (
                    crate::proxy::lane_pool::Next::More,
                    Downlink::Fixed {
                        read,
                        cipher,
                        fixed,
                        client_salt,
                        at,
                    },
                );
            }
            let key_len = client_salt.len();
            let Some(len) = cipher.open_in_place(&mut fixed) else {
                return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
            };
            if len != 1 + 8 + key_len + 2 || fixed[0] != 1 {
                return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
            }
            let stamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap_or([0u8; 8]));
            if now_secs().abs_diff(stamp) > SKEW || fixed[9..9 + key_len] != client_salt[..] {
                return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
            }
            let first = usize::from(u16::from_be_bytes([
                fixed[9 + key_len],
                fixed[10 + key_len],
            ]));
            if first == 0 {
                (
                    crate::proxy::lane_pool::Next::More,
                    Downlink::Aead {
                        window: ChunkReader::new(read),
                        cipher,
                    },
                )
            } else {
                (
                    crate::proxy::lane_pool::Next::More,
                    Downlink::First {
                        read,
                        cipher,
                        chunk: vec![0u8; first + TAG_LEN],
                        at: 0,
                    },
                )
            }
        }
        Err(error) if crate::proxy::is_timeout(&error) => (
            waited(flow),
            Downlink::Fixed {
                read,
                cipher,
                fixed,
                client_salt,
                at,
            },
        ),
        Err(_) => (crate::proxy::lane_pool::Next::Done, Downlink::Running),
    }
}

/// The chunk the fixed header named, opened where the carrier put it and handed straight on.
fn first_step<R: Read>(
    mut read: R,
    mut cipher: Cipher,
    mut chunk: Vec<u8>,
    mut at: usize,
    out: &mut dyn Write,
    flow: Option<&crate::proxy::RelayFinish>,
) -> (crate::proxy::lane_pool::Next, Downlink<R>) {
    match read.read(&mut chunk[at..]) {
        Ok(0) => (crate::proxy::lane_pool::Next::Done, Downlink::Running),
        Ok(n) => {
            at += n;
            if at < chunk.len() {
                return (
                    crate::proxy::lane_pool::Next::More,
                    Downlink::First {
                        read,
                        cipher,
                        chunk,
                        at,
                    },
                );
            }
            let Some(got) = cipher.open_in_place(&mut chunk) else {
                return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
            };
            if out.write_all(&chunk[..got]).is_err() {
                return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
            }
            (
                crate::proxy::lane_pool::Next::More,
                Downlink::Aead {
                    window: ChunkReader::new(read),
                    cipher,
                },
            )
        }
        Err(error) if crate::proxy::is_timeout(&error) => (
            waited(flow),
            Downlink::First {
                read,
                cipher,
                chunk,
                at,
            },
        ),
        Err(_) => (crate::proxy::lane_pool::Next::Done, Downlink::Running),
    }
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
    let next = if opened > 0 {
        if write_all_runs::<CHUNKS_PER_BATCH>(out, &window.buf, &batch[..opened]).is_err() {
            return (crate::proxy::lane_pool::Next::Done, Downlink::Running);
        }
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

/// A quiet socket is a wait for the lane unless the sibling has ended: then there is nothing left
/// to read on either side.
fn waited(flow: Option<&crate::proxy::RelayFinish>) -> crate::proxy::lane_pool::Next {
    if flow.is_some_and(crate::proxy::RelayFinish::ended) {
        crate::proxy::lane_pool::Next::Done
    } else {
        crate::proxy::lane_pool::Next::Idle
    }
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

/// Chunks one window batch opens and hands to the target at once: a peer that frames 8 KiB chunks
/// fills a window with eight of them, so one opened batch is one target write.
const CHUNKS_PER_BATCH: usize = 8;

/// The relay's read window: one slot per chunk of the batch above, each slot a half-size chunk's whole wire cost — sealed length, payload, payload tag — so eight of the framing a peer actually uses fill it to the last byte, and the widest chunk a peer can name, `MAX_CHUNK` with its length and both tags, still lands in it whole.
const WINDOW: usize = CHUNKS_PER_BATCH * (SEAL_HEAD + READ_CHUNK / 2 + TAG_LEN);

/// One relay connection's downlink window: wire bytes land here once and chunks open where they lie,
/// so a sealed length never costs its own carrier ask and a payload byte crosses user space once.
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
            buf: crate::proxy::RelayBuf::with_len(WINDOW).into_vec(),
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

    /// Open one chunk where it lies and say where its plaintext ended up. `None` is the stream
    /// ending, a tag that will not open, or a chunk that has not finished arriving — which is why
    /// its length is drawn once and held rather than drawn again against the next chunk's nonce.
    fn open_chunk(&mut self, recv: &mut Cipher) -> Option<(usize, usize)> {
        let head = LENGTH_LEN + TAG_LEN;
        let size = if let Some(size) = self.held {
            size
        } else {
            if self.end - self.at < head {
                return None;
            }
            let length = &mut self.buf[self.at..self.at + head];
            let size = open_length(recv, length)?;
            self.held = Some(size);
            size
        };
        let body = size + TAG_LEN;
        if self.end - self.at < head + body {
            return None;
        }
        self.held = None;
        let start = self.at + head;
        let plain = recv.open_in_place(&mut self.buf[start..start + body])?;
        self.at = start + body;
        Some((start, plain))
    }

    /// Open every chunk the window already holds: a peer that stops to hear back from its own
    /// target must never find the chunk it is waiting on held for a batch that has not arrived.
    fn open_ready(&mut self, recv: &mut Cipher, out: &mut [(usize, usize)]) -> usize {
        let mut opened = 0usize;
        while opened < out.len() {
            let Some(chunk) = self.open_chunk(recv) else {
                break;
            };
            out[opened] = chunk;
            opened += 1;
        }
        opened
    }
}

/// What one lane step's filling found: bytes arrived, the socket has none yet, or the stream ended.
enum Fill {
    Ready,
    Idle,
    End,
}

/// Open an 18 B sealed length in place: the payload size it names, or `None` on a forged tag or a
/// size the rung does not accept — 2022 has no empty chunk, so a zero length ends the stream.
fn open_length(recv: &mut Cipher, length: &mut [u8]) -> Option<usize> {
    if recv.open_in_place(length)? != LENGTH_LEN {
        return None;
    }
    let size = usize::from(u16::from_be_bytes([length[0], length[1]]));
    (size > 0 && size <= MAX_CHUNK).then_some(size)
}

/// Seal `n` payload bytes at `buf[SEAL_HEAD..]` and hand seals and payload to `out` in one write: a payload byte is never copied in user space, and one call seals one chunk because `READ_CHUNK` is a quarter of `MAX_CHUNK` — a relay read is already one chunk, and oversize input is refused loudly rather than corrupted.
fn seal_all(
    send: &mut Cipher,
    buf: &mut [u8],
    n: usize,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    if n > MAX_CHUNK {
        return Err(invalid());
    }
    debug_assert!(buf.len() >= SEAL_HEAD + n + TAG_LEN);
    let end = SEAL_HEAD + n;
    let mut length = (n as u16).to_be_bytes();
    let length_tag = send.seal_piece_in_place(&mut length).ok_or_else(invalid)?;
    let tag = send
        .seal_piece_in_place(&mut buf[SEAL_HEAD..end])
        .ok_or_else(invalid)?;
    buf[..LENGTH_LEN].copy_from_slice(&length);
    buf[LENGTH_LEN..SEAL_HEAD].copy_from_slice(&length_tag);
    buf[end..end + TAG_LEN].copy_from_slice(&tag);
    out.write_all(&buf[..end + TAG_LEN])
}

struct ServerUdp {
    window: shadowsocks2022::SlidingWindow,
    cipher: Option<Cipher>,
    user: Option<usize>,
    server_session: u64,
    server_packet: u64,
    server_cipher: Option<Cipher>,
}

struct PeerServer {
    window: shadowsocks2022::SlidingWindow,
    cipher: Option<Cipher>,
    last_seen: u64,
}

pub(crate) struct Datagrams {
    sealed: Vec<u8>,
    session: u64,
    packet: u64,
    sessions: HashMap<u64, ServerUdp>,
    peers: HashMap<u64, PeerServer>,
    client_body: Option<Cipher>,
    client_psk: Vec<u8>,
    client_session: [u8; 8],
}

impl Datagrams {
    pub(crate) fn new() -> Self {
        let mut session = [0u8; 8];
        let _ = getrandom::fill(&mut session);
        Self::with_client_session(u64::from_be_bytes(session))
    }
    /// The client's identity session: `seal` puts it on every request and the server echoes it back, so a reply reader must know it.
    pub(crate) fn client_session(&self) -> u64 {
        self.session
    }
    /// A reply reader seeded with the request writer's session, which is what `open_server` checks a reply carries.
    pub(crate) fn with_client_session(session: u64) -> Self {
        Self {
            sealed: Vec::new(),
            session,
            packet: 0,
            sessions: HashMap::new(),
            peers: HashMap::new(),
            client_body: None,
            client_psk: Vec::new(),
            client_session: [0u8; 8],
        }
    }
    pub(crate) fn seal(
        &mut self,
        psk: &[u8],
        method: Method,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        let key_len = method.key_len();
        if psk.len() != key_len {
            return None;
        }
        if method.is_chacha() {
            let mut nonce = [0u8; 24];
            getrandom::fill(&mut nonce).ok()?;
            let out = &mut self.sealed;
            out.clear();
            out.reserve(24 + 16 + 11 + payload.len() + TAG_LEN);
            out.extend_from_slice(&nonce);
            let at = out.len();
            out.extend_from_slice(&self.session.to_be_bytes());
            out.extend_from_slice(&self.packet.to_be_bytes());
            self.packet = self.packet.wrapping_add(1);
            out.push(0);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            shadowsocks2022::x_seal_tail(psk, &nonce, out, at)?;
            Some(out)
        } else {
            let mut raw = [0u8; BLOCK_LEN];
            raw[..8].copy_from_slice(&self.session.to_be_bytes());
            raw[8..].copy_from_slice(&self.packet.to_be_bytes());
            self.packet = self.packet.wrapping_add(1);
            let enc = shadowsocks2022::block_encrypt(psk, &raw)?;
            let session = self.session.to_be_bytes();
            let fresh = self.client_body.is_none()
                || self.client_psk != psk
                || self.client_session != session;
            if fresh {
                let sub = shadowsocks2022::session_subkey(psk, &session)?;
                let cipher = Cipher::from_subkey(method, &sub[..key_len])?;
                self.client_body = Some(cipher);
                self.client_psk = psk.to_vec();
                self.client_session = session;
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            let (out, body_key) = (&mut self.sealed, self.client_body.as_ref()?);
            out.clear();
            out.reserve(16 + 11 + payload.len() + TAG_LEN);
            out.extend_from_slice(&enc);
            let at = out.len();
            out.push(0);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            body_key.seal_tail_with_nonce(&nonce, out, at)?;
            Some(out)
        }
    }
    pub(crate) fn seal_list(
        &mut self,
        method: Method,
        psks: &[Vec<u8>],
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        let final_psk = psks.last()?;
        if method.is_chacha() || psks.len() < 2 {
            return None;
        }
        let key_len = method.key_len();
        if psks.iter().any(|p| p.len() != key_len) {
            return None;
        }
        let mut raw = [0u8; BLOCK_LEN];
        raw[..8].copy_from_slice(&self.session.to_be_bytes());
        raw[8..].copy_from_slice(&self.packet.to_be_bytes());
        self.packet = self.packet.wrapping_add(1);
        let session = self.session.to_be_bytes();
        let fresh = self.client_body.is_none()
            || self.client_psk != final_psk.as_slice()
            || self.client_session != session;
        if fresh {
            let sub = shadowsocks2022::session_subkey(final_psk, &session)?;
            let cipher = Cipher::from_subkey(method, &sub[..key_len])?;
            self.client_body = Some(cipher);
            self.client_psk.clone_from(final_psk);
            self.client_session = session;
        }
        let enc = shadowsocks2022::block_encrypt(&psks[0], &raw)?;
        let (out, body_key) = (&mut self.sealed, self.client_body.as_ref()?);
        out.clear();
        out.reserve((1 + psks.len()) * BLOCK_LEN + 11 + payload.len() + TAG_LEN);
        out.extend_from_slice(&enc);
        for pair in psks.windows(2) {
            let hash = shadowsocks2022::user_hash(&pair[1]);
            let eih = shadowsocks2022::encrypt_udp_eih(&pair[0], &raw, &hash)?;
            out.extend_from_slice(&eih);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&raw[4..16]);
        let at = out.len();
        out.push(0);
        out.extend_from_slice(&now_secs().to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        push_addr(out, dest, 4);
        out.extend_from_slice(&dest.port().to_be_bytes());
        out.extend_from_slice(payload);
        body_key.seal_tail_with_nonce(&nonce, out, at)?;
        Some(out)
    }
    pub(crate) fn open<'a>(
        &mut self,
        psk: &[u8],
        method: Method,
        packet: &'a mut [u8],
    ) -> Option<(SocketAddr, &'a [u8], u64)> {
        if method.is_chacha() {
            if psk.len() != 32 || packet.len() < 24 + TAG_LEN {
                return None;
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&packet[..24]);
            let len = shadowsocks2022::x_open(psk, &nonce, &mut packet[24..])?;
            if len > packet.len() - 24 {
                return None;
            }
            let body = &packet[24..24 + len];
            if body.len() < 16 + 11 {
                return None;
            }
            let session = u64::from_be_bytes(body[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(body[8..16].try_into().ok()?);
            let entry = self.sessions.entry(session).or_insert_with(|| ServerUdp {
                window: shadowsocks2022::SlidingWindow::new(),
                cipher: None,
                user: None,
                server_session: 0,
                server_packet: 0,
                server_cipher: None,
            });
            if !entry.window.check_and_add(packet_id) {
                return None;
            }
            let body = &body[16..];
            if body[0] != 0 {
                return None;
            }
            let stamp = u64::from_be_bytes(body[1..9].try_into().ok()?);
            if now_secs().abs_diff(stamp) > SKEW {
                return None;
            }
            let pad = usize::from(u16::from_be_bytes([body[9], body[10]]));
            if body.len() < 11 + pad {
                return None;
            }
            let (target, used) = parse_addr_header(&body[11 + pad..])?;
            if body.len() < 11 + pad + used {
                return None;
            }
            Some((
                target,
                &packet[24 + 16 + 11 + pad + used..24 + len],
                session,
            ))
        } else {
            let key_len = method.key_len();
            if psk.len() != key_len || packet.len() < 16 + TAG_LEN {
                return None;
            }
            let mut enc = [0u8; BLOCK_LEN];
            enc.copy_from_slice(&packet[..16]);
            let raw = shadowsocks2022::block_decrypt(psk, &enc)?;
            let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(raw[8..].try_into().ok()?);
            let entry = self.sessions.entry(session).or_insert_with(|| ServerUdp {
                window: shadowsocks2022::SlidingWindow::new(),
                cipher: None,
                user: None,
                server_session: 0,
                server_packet: 0,
                server_cipher: None,
            });
            if !entry.window.check_and_add(packet_id) {
                return None;
            }
            if entry.cipher.is_none() {
                let sub = shadowsocks2022::session_subkey(psk, &raw[..8])?;
                entry.cipher = Cipher::from_subkey(method, &sub[..key_len]);
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            let cipher = self.sessions.get(&session)?.cipher.as_ref()?;
            let (target, total, len) =
                open_body_in_place(cipher, &nonce, &mut packet[16..], 11, 0)?;
            Some((target, &packet[16 + total..16 + len], session))
        }
    }
    pub(crate) fn open_multi<'a>(
        &mut self,
        method: Method,
        psks: &[Vec<u8>],
        packet: &'a mut [u8],
    ) -> Option<(SocketAddr, &'a [u8], usize, u64)> {
        if method.is_chacha() || psks.len() < 2 {
            return None;
        }
        let key_len = method.key_len();
        if psks.iter().any(|p| p.len() != key_len) || packet.len() < 32 + TAG_LEN {
            return None;
        }
        let mut enc = [0u8; BLOCK_LEN];
        enc.copy_from_slice(&packet[..16]);
        let raw = shadowsocks2022::block_decrypt(&psks[0], &enc)?;
        let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
        let packet_id = u64::from_be_bytes(raw[8..].try_into().ok()?);
        let entry = self.sessions.entry(session).or_insert_with(|| ServerUdp {
            window: shadowsocks2022::SlidingWindow::new(),
            cipher: None,
            user: None,
            server_session: 0,
            server_packet: 0,
            server_cipher: None,
        });
        if !entry.window.check_and_add(packet_id) {
            return None;
        }
        if entry.user.is_none() {
            let mut eih = [0u8; BLOCK_LEN];
            eih.copy_from_slice(&packet[16..32]);
            let hash = shadowsocks2022::decrypt_udp_eih(&psks[0], &raw, &eih)?;
            let idx = psks[1..]
                .iter()
                .position(|p| shadowsocks2022::user_hash(p) == hash)?
                + 1;
            let sub = shadowsocks2022::session_subkey(&psks[idx], &raw[..8])?;
            entry.cipher = Cipher::from_subkey(method, &sub[..key_len]);
            entry.user = Some(idx);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&raw[4..16]);
        let idx = self.sessions.get(&session)?.user?;
        let cipher = self.sessions.get(&session)?.cipher.as_ref()?;
        let (target, total, len) = open_body_in_place(cipher, &nonce, &mut packet[32..], 11, 0)?;
        Some((target, &packet[32 + total..32 + len], idx, session))
    }
    pub(crate) fn seal_server(
        &mut self,
        method: Method,
        user_psk: &[u8],
        client_session: u64,
        dest: &SocketAddr,
        payload: &[u8],
    ) -> Option<&[u8]> {
        if user_psk.len() != method.key_len() {
            return None;
        }
        let fresh = self.sessions.get(&client_session).is_none_or(|e| {
            e.server_session == 0 || (!method.is_chacha() && e.server_cipher.is_none())
        });
        if fresh {
            let mut sid = [0u8; 8];
            getrandom::fill(&mut sid).ok()?;
            let sid = u64::from_be_bytes(sid);
            if sid == 0 {
                return None;
            }
            let entry = self
                .sessions
                .entry(client_session)
                .or_insert_with(|| ServerUdp {
                    window: shadowsocks2022::SlidingWindow::new(),
                    cipher: None,
                    user: None,
                    server_session: 0,
                    server_packet: 0,
                    server_cipher: None,
                });
            entry.server_session = sid;
            if !method.is_chacha() {
                let sub = shadowsocks2022::session_subkey(user_psk, &sid.to_be_bytes())?;
                entry.server_cipher = Cipher::from_subkey(method, &sub[..method.key_len()]);
            }
        }
        if method.is_chacha() {
            let (server_session, server_packet) = {
                let entry = self.sessions.get_mut(&client_session)?;
                let id = entry.server_packet;
                entry.server_packet = entry.server_packet.wrapping_add(1);
                (entry.server_session, id)
            };
            let mut nonce = [0u8; 24];
            getrandom::fill(&mut nonce).ok()?;
            let out = &mut self.sealed;
            out.clear();
            out.reserve(24 + 16 + 19 + payload.len() + TAG_LEN);
            out.extend_from_slice(&nonce);
            let at = out.len();
            out.extend_from_slice(&server_session.to_be_bytes());
            out.extend_from_slice(&server_packet.to_be_bytes());
            out.push(1);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&client_session.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            shadowsocks2022::x_seal_tail(user_psk, &nonce, out, at)?;
            Some(out)
        } else {
            let (server_session, server_packet) = {
                let entry = self.sessions.get_mut(&client_session)?;
                let id = entry.server_packet;
                entry.server_packet = entry.server_packet.wrapping_add(1);
                (entry.server_session, id)
            };
            let mut raw = [0u8; BLOCK_LEN];
            raw[..8].copy_from_slice(&server_session.to_be_bytes());
            raw[8..].copy_from_slice(&server_packet.to_be_bytes());
            let enc = shadowsocks2022::block_encrypt(user_psk, &raw)?;
            let (out, sessions) = (&mut self.sealed, &self.sessions);
            let cipher = sessions.get(&client_session)?.server_cipher.as_ref()?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            out.clear();
            out.reserve(16 + 19 + payload.len() + TAG_LEN);
            out.extend_from_slice(&enc);
            let at = out.len();
            out.push(1);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&client_session.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            push_addr(out, dest, 4);
            out.extend_from_slice(&dest.port().to_be_bytes());
            out.extend_from_slice(payload);
            cipher.seal_tail_with_nonce(&nonce, out, at)?;
            Some(out)
        }
    }
    pub(crate) fn open_server<'a>(
        &mut self,
        psk: &[u8],
        method: Method,
        packet: &'a mut [u8],
    ) -> Option<(SocketAddr, &'a [u8])> {
        let now = now_secs();
        if method.is_chacha() {
            if psk.len() != 32 || packet.len() < 24 + TAG_LEN {
                return None;
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&packet[..24]);
            let len = shadowsocks2022::x_open(psk, &nonce, &mut packet[24..])?;
            if len > packet.len() - 24 {
                return None;
            }
            let body = &packet[24..24 + len];
            if body.len() < 16 + 19 {
                return None;
            }
            let session = u64::from_be_bytes(body[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(body[8..16].try_into().ok()?);
            if !peer_check(&mut self.peers, session, packet_id, now) {
                return None;
            }
            let body = &body[16..];
            if body[0] != 1 {
                return None;
            }
            if now.abs_diff(u64::from_be_bytes(body[1..9].try_into().ok()?)) > SKEW {
                return None;
            }
            if u64::from_be_bytes(body[9..17].try_into().ok()?) != self.session {
                return None;
            }
            let pad = usize::from(u16::from_be_bytes([body[17], body[18]]));
            if body.len() < 19 + pad {
                return None;
            }
            let (target, used) = parse_addr_header(&body[19 + pad..])?;
            if body.len() < 19 + pad + used {
                return None;
            }
            Some((target, &packet[24 + 16 + 19 + pad + used..24 + len]))
        } else {
            let key_len = method.key_len();
            if psk.len() != key_len || packet.len() < 16 + TAG_LEN {
                return None;
            }
            let mut enc = [0u8; BLOCK_LEN];
            enc.copy_from_slice(&packet[..16]);
            let raw = shadowsocks2022::block_decrypt(psk, &enc)?;
            let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
            let packet_id = u64::from_be_bytes(raw[8..].try_into().ok()?);
            if !peer_check(&mut self.peers, session, packet_id, now) {
                return None;
            }
            if self
                .peers
                .get(&session)
                .is_none_or(|peer| peer.cipher.is_none())
            {
                let sub = shadowsocks2022::session_subkey(psk, &raw[..8])?;
                let cipher = Cipher::from_subkey(method, &sub[..key_len])?;
                self.peers.get_mut(&session)?.cipher = Some(cipher);
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&raw[4..16]);
            let cipher = self.peers.get(&session)?.cipher.as_ref()?;
            let len = cipher.open_with_nonce(&nonce, &mut packet[16..])?;
            if len > packet.len() - 16 {
                return None;
            }
            let body = &packet[16..16 + len];
            if body.len() < 19 || body[0] != 1 {
                return None;
            }
            if now.abs_diff(u64::from_be_bytes(body[1..9].try_into().ok()?)) > SKEW {
                return None;
            }
            if u64::from_be_bytes(body[9..17].try_into().ok()?) != self.session {
                return None;
            }
            let pad = usize::from(u16::from_be_bytes([body[17], body[18]]));
            if body.len() < 19 + pad {
                return None;
            }
            let (target, used) = parse_addr_header(&body[19 + pad..])?;
            if body.len() < 19 + pad + used {
                return None;
            }
            Some((target, &packet[16 + 19 + pad + used..16 + len]))
        }
    }
}

fn peer_check(
    peers: &mut HashMap<u64, PeerServer>,
    session: u64,
    packet_id: u64,
    now: u64,
) -> bool {
    if let Some(peer) = peers.get_mut(&session) {
        peer.last_seen = now;
        return peer.window.check_and_add(packet_id);
    }
    peers.retain(|_, peer: &mut PeerServer| now.wrapping_sub(peer.last_seen) < 60);
    if peers
        .values()
        .any(|peer| now.wrapping_sub(peer.last_seen) < 60)
    {
        return false;
    }
    if peers.len() >= 8 {
        return false;
    }
    let mut peer = PeerServer {
        window: shadowsocks2022::SlidingWindow::new(),
        cipher: None,
        last_seen: now,
    };
    if !peer.window.check_and_add(packet_id) {
        return false;
    }
    peers.insert(session, peer);
    true
}

fn open_body_in_place(
    cipher: &Cipher,
    nonce: &[u8; 12],
    body: &mut [u8],
    header: usize,
    kind: u8,
) -> Option<(SocketAddr, usize, usize)> {
    let len = cipher.open_with_nonce(nonce, body)?;
    if len > body.len() {
        return None;
    }
    let body = &body[..len];
    if body.len() < header || body[0] != kind {
        return None;
    }
    let stamp = u64::from_be_bytes(body[1..9].try_into().ok()?);
    if now_secs().abs_diff(stamp) > SKEW {
        return None;
    }
    let pad = usize::from(u16::from_be_bytes([body[9], body[10]]));
    if body.len() < header + pad {
        return None;
    }
    let (target, used) = parse_addr_header(&body[header + pad..])?;
    let total = header + pad + used;
    if body.len() < total {
        return None;
    }
    Some((target, total, len))
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

pub(crate) fn serve_udp(address: &str, password: &str, method: &str, freedom: bool) {
    let Ok(clients) = UdpSocket::bind(address) else {
        return;
    };
    serve_udp_on(&clients, password, method, freedom);
}

pub(crate) fn relay_udp_forward(
    relay_psk: &[u8],
    dests: &[RelayDest<'_>],
    packet: &[u8],
    out: &mut Vec<u8>,
) -> Option<(SocketAddr, u64)> {
    if packet.len() < 32 + TAG_LEN {
        return None;
    }
    let mut enc = [0u8; BLOCK_LEN];
    enc.copy_from_slice(&packet[..16]);
    let raw = shadowsocks2022::block_decrypt(relay_psk, &enc)?;
    let session = u64::from_be_bytes(raw[..8].try_into().ok()?);
    let mut eih = [0u8; BLOCK_LEN];
    eih.copy_from_slice(&packet[16..32]);
    let hash = shadowsocks2022::decrypt_udp_eih(relay_psk, &raw, &eih)?;
    let dest = dests.iter().find(|dest| dest.hash == hash)?;
    let re_enc = shadowsocks2022::block_encrypt(dest.psk, &raw)?;
    out.clear();
    out.reserve(16 + packet.len() - 32);
    out.extend_from_slice(&re_enc);
    out.extend_from_slice(&packet[32..]);
    Some((dest.addr, session))
}

/// One relay destination carrying the hash its key is matched by: `user_hash` reads only that key, so a forwarded datagram compares hashes it already has instead of deriving one per destination it might yet reach.
pub(crate) struct RelayDest<'a> {
    hash: [u8; BLOCK_LEN],
    psk: &'a [u8],
    addr: SocketAddr,
}

/// The destinations as one relay sees them, hashed once for its whole life.
pub(crate) fn relay_dests(dests: &[(Vec<u8>, SocketAddr)]) -> Vec<RelayDest<'_>> {
    dests
        .iter()
        .map(|(psk, addr)| RelayDest {
            hash: shadowsocks2022::user_hash(psk),
            psk,
            addr: *addr,
        })
        .collect()
}

pub(crate) fn relay_udp_client_of(
    dest_psk: &[u8],
    body: &mut Vec<u8>,
    packet: &[u8],
) -> Option<u64> {
    if packet.len() < 16 + 19 + TAG_LEN {
        return None;
    }
    let mut enc = [0u8; BLOCK_LEN];
    enc.copy_from_slice(&packet[..16]);
    let raw = shadowsocks2022::block_decrypt(dest_psk, &enc)?;
    let sub = shadowsocks2022::session_subkey(dest_psk, &raw[..8])?;
    let cipher = Cipher::from_subkey(
        if dest_psk.len() == 16 {
            Method::Aes128Gcm
        } else {
            Method::Aes256Gcm
        },
        &sub[..dest_psk.len()],
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw[4..16]);
    body.clear();
    body.extend_from_slice(&packet[16..]);
    let len = cipher.open_with_nonce(&nonce, body)?;
    body.truncate(len);
    if body.len() < 19 || body[0] != 1 {
        return None;
    }
    if now_secs().abs_diff(u64::from_be_bytes(body[1..9].try_into().ok()?)) > SKEW {
        return None;
    }
    Some(u64::from_be_bytes(body[9..17].try_into().ok()?))
}

pub(crate) fn serve_udp_relay(
    clients: &UdpSocket,
    method: Method,
    relay_psk: &[u8],
    dests: &[(Vec<u8>, SocketAddr)],
) {
    if method.is_chacha() || relay_psk.len() != method.key_len() {
        return;
    }
    let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    if upstream.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    if clients.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    let mut by_addr: HashMap<SocketAddr, usize> = HashMap::new();
    for (idx, (_, addr)) in dests.iter().enumerate() {
        by_addr.insert(*addr, idx);
    }
    let hashed = relay_dests(dests);
    let mut client_of: HashMap<u64, SocketAddr> = HashMap::new();
    let mut forwarded: Vec<u8> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let mut buf = crate::proxy::udp_buffer();
    loop {
        match clients.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some((dest, session)) =
                    relay_udp_forward(relay_psk, &hashed, &buf[..n], &mut forwarded)
                {
                    if client_of.len() >= 4096 {
                        client_of.clear();
                    }
                    client_of.insert(session, src);
                    let _ = upstream.send_to(&forwarded, dest);
                }
            }
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => break,
        }
        while let Ok((n, from)) = upstream.recv_from(&mut buf) {
            let Some(idx) = by_addr.get(&from).copied() else {
                continue;
            };
            let Some((dest_psk, _)) = dests.get(idx) else {
                continue;
            };
            if let Some(session) = relay_udp_client_of(dest_psk, &mut body, &buf[..n]) {
                if let Some(client) = client_of.get(&session) {
                    let _ = clients.send_to(&buf[..n], client);
                }
            }
        }
    }
}

pub(crate) fn serve_udp_on(clients: &UdpSocket, password: &str, method: &str, freedom: bool) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    let Some(list) = psks(password, method) else {
        return;
    };
    if list.is_empty() {
        return;
    }
    if method.is_chacha() && list.len() > 1 {
        return;
    }
    let multi = !method.is_chacha() && list.len() > 1;
    let psk = list.last().expect("non-empty").clone();
    let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    let upstream6 = UdpSocket::bind("[::]:0").ok();
    for sock in [clients, &upstream].into_iter().chain(upstream6.as_ref()) {
        if sock.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
    }
    let mut table: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let mut users: HashMap<SocketAddr, usize> = HashMap::new();
    let mut sessions: HashMap<SocketAddr, u64> = HashMap::new();
    let mut buf = crate::proxy::udp_buffer();
    let mut reply = crate::proxy::udp_buffer();
    let mut datagrams = Datagrams::new();
    loop {
        match clients.recv_from(&mut buf) {
            Ok((n, src)) => {
                if multi {
                    if let Some((dest, payload, idx, session)) =
                        datagrams.open_multi(method, &list, &mut buf[..n])
                    {
                        if table.len() >= 4096 {
                            table.clear();
                            users.clear();
                            sessions.clear();
                        }
                        table.insert(dest, src);
                        users.insert(src, idx);
                        sessions.insert(src, session);
                        if dest.is_ipv6() {
                            if let Some(sock) = &upstream6 {
                                let _ = sock.send_to(payload, dest);
                            }
                        } else {
                            let _ = upstream.send_to(payload, dest);
                        }
                    }
                } else if let Some((dest, payload, session)) =
                    datagrams.open(&psk, method, &mut buf[..n])
                {
                    if table.len() >= 4096 {
                        table.clear();
                        sessions.clear();
                    }
                    table.insert(dest, src);
                    sessions.insert(src, session);
                    if dest.is_ipv6() {
                        if let Some(sock) = &upstream6 {
                            let _ = sock.send_to(payload, dest);
                        }
                    } else {
                        let _ = upstream.send_to(payload, dest);
                    }
                }
            }
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => break,
        }
        for sock in [&upstream].into_iter().chain(upstream6.as_ref()) {
            while let Ok((n, src)) = sock.recv_from(&mut reply) {
                let state = UdpAnswer {
                    method,
                    list: &list,
                    psk: &psk,
                    multi,
                    table: &table,
                    users: &users,
                    sessions: &sessions,
                };
                answer_udp(clients, &mut datagrams, &state, &reply[..n], src);
            }
        }
    }
}

struct UdpAnswer<'a> {
    method: Method,
    list: &'a [Vec<u8>],
    psk: &'a [u8],
    multi: bool,
    table: &'a HashMap<SocketAddr, SocketAddr>,
    users: &'a HashMap<SocketAddr, usize>,
    sessions: &'a HashMap<SocketAddr, u64>,
}

fn answer_udp(
    clients: &UdpSocket,
    datagrams: &mut Datagrams,
    state: &UdpAnswer<'_>,
    reply: &[u8],
    src: SocketAddr,
) {
    let Some(client) = state.table.get(&src).copied() else {
        return;
    };
    let Some(session) = state.sessions.get(&client).copied() else {
        return;
    };
    let user = if state.multi {
        let idx = state
            .users
            .get(&client)
            .copied()
            .unwrap_or(state.list.len() - 1);
        state.list.get(idx).map(Vec::as_slice)
    } else {
        Some(state.psk)
    };
    let Some(user) = user else {
        return;
    };
    if user.len() != state.method.key_len() {
        return;
    }
    if let Some(packet) = datagrams.seal_server(state.method, user, session, &src, reply) {
        let _ = clients.send_to(packet, client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes one wire chunk can never exceed: what a single-chunk open is given room for.
    const WIRE_MAX: usize = MAX_CHUNK + TAG_LEN;

    fn wire_buffer() -> Vec<u8> {
        crate::proxy::RelayBuf::with_len(WIRE_MAX).into_vec()
    }

    /// One chunk opened out of a buffer of its own, which is how a gate reaches a codec primitive
    /// without the relay's window standing between them.
    fn open_chunk<'a>(
        stream: &mut dyn Read,
        recv: &mut Cipher,
        chunk: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let mut length = [0u8; LENGTH_LEN + TAG_LEN];
        read_exact(stream, &mut length).ok()?;
        let size = open_length(recv, &mut length)?;
        if size + TAG_LEN > chunk.len() {
            return None;
        }
        let wire = &mut chunk[..size + TAG_LEN];
        read_exact(stream, wire).ok()?;
        let plain = recv.open_in_place(wire)?;
        Some(&wire[..plain])
    }

    /// A writer that has `writev`, which is what the relay's own socket is: it counts calls and
    /// remembers every base it was handed, so a batch that leaves in one vectored write is one
    /// syscall by the same account the kernel keeps, and a plaintext that left the window where it
    /// lies is witnessed by its base sitting inside that window.
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
        fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
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

    /// A source that answers a whole read at once, counting them, so a fill's read count is exact.
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

    /// A source that hands back one staged part per read and nothing after the last, so a chunk that
    /// has not arrived is a chunk the pump can be seen not to wait for.
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

    /// A chunk of `plain` on the wire, sealed by `send` into a buffer of its slot's width.
    fn seal_one(send: &mut Cipher, plain: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; SEAL_HEAD + plain.len() + TAG_LEN];
        buf[SEAL_HEAD..SEAL_HEAD + plain.len()].copy_from_slice(plain);
        let mut wire = Vec::new();
        seal_all(send, &mut buf, plain.len(), &mut wire).expect("seals");
        wire
    }

    fn psk_b64(key_len: usize) -> String {
        ferrox_core::b64::encode(&vec![0x42u8; key_len])
    }

    #[test]
    fn a_silent_peer_cannot_pin_a_single_psk_shadowsocks2022_handshake() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let psk = psk_b64(32);
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, &psk, "2022-blake3-aes-256-gcm", &[], true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    /// A 2022-blake3 inbound over gRPC whose peer answers the head and never sends its salt releases the serve thread: the carrier puts its clock away with the head, so the handshake reads under its own.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_shadowsocks2022_request() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let psk = psk_b64(32);
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(stream, &psk, "2022-blake3-aes-256-gcm", &[], "/p", true);
            let _ = done_tx.send(());
        });
        let stream = Connection::connect(addr).expect("connects");
        let (_reader, _writer) = crate::grpc::connect(stream, "127.0.0.1", "/p").expect("dials");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn a_silent_peer_cannot_pin_a_multi_psk_shadowsocks2022_handshake() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let password = format!("{}:{}", psk_b64(32), psk_b64(32));
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, &password, "2022-blake3-aes-256-gcm", &[], true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn the_response_head_folds_the_first_downlink_chunk() {
        let method = Method::Aes256Gcm;
        let name = "2022-blake3-aes-256-gcm";
        let psk = psk_b64(method.key_len());
        let target = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let target_port = target.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = target.accept().expect("accepts");
            stream.write_all(b"first").expect("writes");
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        let announced = psk.clone();
        let named = name.to_owned();
        thread::spawn(move || {
            for stream in server.incoming().take(1) {
                let Ok(stream) = stream else { continue };
                let announced = announced.clone();
                let named = named.clone();
                thread::spawn(move || {
                    serve(stream, &announced, &named, &[], true);
                });
            }
        });
        let target_addr: SocketAddr = format!("127.0.0.1:{target_port}").parse().expect("addr");
        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let Ok((_send, recv)) = client_send_handshake(
            &mut uplink,
            &psk,
            name,
            &crate::proxy::Destination::from(target_addr),
        ) else {
            panic!("handshake refused");
        };
        let Recv::Waiting(m, p, s) = recv else {
            panic!("the client waits for a server salt");
        };
        let mut peer = vec![0u8; m.key_len()];
        read_exact(&mut uplink, &mut peer).expect("salt");
        let mut cipher = Cipher::from_psk(m, &p, &peer).expect("derives");
        let fixed_len = 1 + 8 + m.key_len() + 2 + TAG_LEN;
        let mut fixed = vec![0u8; fixed_len];
        read_exact(&mut uplink, &mut fixed).expect("fixed");
        cipher.open_in_place(&mut fixed).expect("opens");
        let first = usize::from(u16::from_be_bytes([
            fixed[9 + m.key_len()],
            fixed[10 + m.key_len()],
        ]));
        assert!(
            first > 0,
            "the server head carries the first downlink chunk"
        );
        let mut chunk = vec![0u8; first + TAG_LEN];
        read_exact(&mut uplink, &mut chunk).expect("first");
        let got = cipher.open_in_place(&mut chunk).expect("opens first");
        assert_eq!(&chunk[..got], b"first");
        let _ = s;
    }

    /// A carrier that frames per write: TLS seals one record and a WebSocket one frame per call, so
    /// the default vectored write — the first non-empty segment only — is its whole contract.
    struct Framed(Vec<Vec<u8>>);
    impl Write for Framed {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.push(buf.to_vec());
            Ok(buf.len())
        }
        fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
            let Some(first) = bufs.iter().find(|piece| !piece.is_empty()) else {
                return Ok(0);
            };
            self.0.push(first.to_vec());
            Ok(first.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_response_salt_and_fixed_header_leave_in_one_write() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let key_len = method.key_len();
            let psk = vec![0x33u8; key_len];
            let request_salt = vec![0x44u8; key_len];
            let server_salt = vec![0x55u8; key_len];
            let send = Cipher::from_psk(method, &psk, &server_salt).expect("derives");
            let mut response = Response::new(send, server_salt.clone(), request_salt);
            let mut buf = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            buf[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"data");
            let mut out = Framed(Vec::new());
            response.seal_first(&mut buf, 4, &mut out).expect("seals");
            let head_len = key_len + 11 + key_len + TAG_LEN;
            assert_eq!(
                out.0.first().map(Vec::len),
                Some(head_len),
                "xray reads salt and the fixed header in one read; a split record leaves it short"
            );
            assert_eq!(&out.0[0][..key_len], &server_salt[..]);
        }
    }

    #[test]
    fn a_large_variable_header_is_a_request_not_a_refusal() {
        let method = Method::Aes128Gcm;
        let psk = vec![0x42u8; method.key_len()];
        let salt = vec![0x11u8; method.key_len()];
        let target: SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let early = vec![0x5au8; 8192];
        let padding = 0usize;
        let mut cipher = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut variable = Vec::new();
        crate::proxy::Destination::from(target).push_addr(&mut variable, 4, 3);
        variable.extend_from_slice(&target.port().to_be_bytes());
        variable.extend_from_slice(&(padding as u16).to_be_bytes());
        variable.resize(variable.len() + padding, 0);
        variable.extend_from_slice(&early);
        let mut fixed = vec![0u8; 11];
        fixed[1..9].copy_from_slice(&now_secs().to_be_bytes());
        fixed[9..11].copy_from_slice(&(variable.len() as u16).to_be_bytes());
        let var_len = variable.len();
        let mut wire = Vec::new();
        let tag = cipher.seal_piece_in_place(&mut fixed).expect("seals");
        wire.extend_from_slice(&fixed);
        wire.extend_from_slice(&tag);
        let at = wire.len();
        wire.extend_from_slice(&variable);
        let tag = cipher.seal_piece_in_place(&mut wire[at..]).expect("seals");
        wire.extend_from_slice(&tag);

        let mut recv = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let (parsed, counts) = ferrox_core::alloc_count::measure(|| {
            read_request_header(&mut std::io::Cursor::new(&wire), &mut recv)
        });
        let (got, data) = parsed.expect("an 8 KiB first write is a request, not a refusal");
        assert_eq!(got, target);
        assert_eq!(data, early);
        assert_eq!(
            counts.allocs, 1,
            "the header costs the sealed variable buffer and nothing else"
        );
        // The buffer is born inside `read_request_header`, so no caller address can be recorded beside it; what reaches from outside is the size of the one allocation and the capacity the returned vector still reports.
        assert_eq!(
            counts.bytes,
            var_len + TAG_LEN,
            "the single allocation is the sealed variable header, neither shorter nor larger"
        );
        assert_eq!(
            data.capacity(),
            var_len + TAG_LEN,
            "and the returned bytes are that buffer: opened in place, truncated and drained, never reallocated"
        );
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
        let method = Method::Aes256Gcm;
        let psk = psk_b64(method.key_len());
        let target =
            crate::proxy::Destination::from("127.0.0.1:1".parse::<SocketAddr>().expect("addr"));
        assert!(matches!(
            client_send_handshake(&mut Broken, &psk, "2022-blake3-aes-256-gcm", &target),
            Err(Kind::Dropped)
        ));
    }

    #[test]
    fn a_client_handshake_leaves_in_one_write() {
        let method = Method::Aes256Gcm;
        let name = "2022-blake3-aes-256-gcm";
        let password = psk_b64(method.key_len());
        let target: SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let mut seen = Vec::new();
        let (send, recv) = {
            let mut out = Vectored {
                seen: &mut seen,
                writes: 0,
                bases: Vec::new(),
            };
            let got = client_send_handshake(
                &mut out,
                &password,
                name,
                &crate::proxy::Destination::from(target),
            )
            .expect("handshake builds");
            assert_eq!(out.writes, 1, "the whole handshake leaves in one write");
            assert_eq!(out.bases.len(), 1, "one write means one base");
            got
        };
        assert_eq!(send.method(), method);
        let Recv::Waiting(m, p, s) = recv else {
            panic!("the client waits for a server salt");
        };
        assert_eq!(m, method);
        let mut cipher = Cipher::from_psk(m, &p, &s).expect("derives");
        let (got, early) =
            read_request_header(&mut std::io::Cursor::new(&seen[s.len()..]), &mut cipher)
                .expect("the one-write handshake parses");
        assert_eq!(got, target);
        assert_eq!(early, Vec::<u8>::new());
    }

    #[test]
    fn a_multi_psk_handshake_leaves_in_one_write() {
        let method = Method::Aes256Gcm;
        let name = "2022-blake3-aes-256-gcm";
        let password = format!(
            "{}:{}",
            psk_b64(method.key_len()),
            psk_b64(method.key_len())
        );
        let target: SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let mut seen = Vec::new();
        let mut out = Vectored {
            seen: &mut seen,
            writes: 0,
            bases: Vec::new(),
        };
        let _ = client_send_handshake(
            &mut out,
            &password,
            name,
            &crate::proxy::Destination::from(target),
        )
        .expect("handshake builds");
        assert_eq!(out.writes, 1, "the EIH chain rides the same write");
        assert_eq!(out.bases.len(), 1);
        assert!(seen.len() > method.key_len() + BLOCK_LEN);
    }

    #[test]
    fn every_named_method_relays_an_echo() {
        for (name, method) in [
            ("2022-blake3-aes-128-gcm", Method::Aes128Gcm),
            ("2022-blake3-aes-256-gcm", Method::Aes256Gcm),
            ("2022-blake3-chacha20-poly1305", Method::Chacha20Poly1305),
        ] {
            let psk = psk_b64(method.key_len());
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
            let announced = psk.clone();
            let named = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let announced = announced.clone();
                    let named = named.clone();
                    thread::spawn(move || {
                        serve(stream, &announced, &named, &[], true);
                    });
                }
            });
            let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
            let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            let Ok((mut send, recv)) = client_send_handshake(
                &mut uplink,
                &psk,
                name,
                &crate::proxy::Destination::from(target),
            ) else {
                panic!("{name}: handshake refused");
            };
            assert_eq!(send.method(), method, "{name}");
            let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
            seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(m, p, s) => {
                    let mut peer = vec![0u8; m.key_len()];
                    read_exact(&mut uplink, &mut peer).expect("salt");
                    let mut cipher = Cipher::from_psk(m, &p, &peer).expect("derives");
                    let fixed_len = 1 + 8 + m.key_len() + 2 + TAG_LEN;
                    let mut fixed = vec![0u8; fixed_len];
                    read_exact(&mut uplink, &mut fixed).expect("fixed");
                    cipher.open_in_place(&mut fixed).expect("opens");
                    let first = usize::from(u16::from_be_bytes([
                        fixed[9 + m.key_len()],
                        fixed[10 + m.key_len()],
                    ]));
                    assert_eq!(first, 4, "{name}: the head carries the first payload");
                    let mut chunk = vec![0u8; first + TAG_LEN];
                    read_exact(&mut uplink, &mut chunk).expect("first");
                    let got = cipher.open_in_place(&mut chunk).expect("opens first");
                    assert_eq!(&chunk[..got], b"ping", "{name}");
                    let _ = s;
                    cipher
                }
            };
            let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
            ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
            seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
            let mut buf = wire_buffer();
            let back = open_chunk(&mut uplink, &mut recv, &mut buf).expect("opens body");
            assert_eq!(back, &b"ping"[..], "{name}");
        }
    }

    /// One ping through a freshly served connection, with the identity the password names.
    fn echo_through(port: u16, password: &str, method: &str, target: SocketAddr) {
        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let (mut send, recv) = client_send_handshake(
            &mut uplink,
            password,
            method,
            &crate::proxy::Destination::from(target),
        )
        .expect("handshake");
        let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
        ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
        seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
        let (mut recv, folded) = match recv {
            Recv::Ready(cipher) => (cipher, None),
            Recv::Waiting(m, p, s) => {
                let mut peer = vec![0u8; m.key_len()];
                read_exact(&mut uplink, &mut peer).expect("salt");
                let mut cipher = Cipher::from_psk(m, &p, &peer).expect("derives");
                let fixed_len = 1 + 8 + m.key_len() + 2 + TAG_LEN;
                let mut fixed = vec![0u8; fixed_len];
                read_exact(&mut uplink, &mut fixed).expect("fixed");
                cipher.open_in_place(&mut fixed).expect("opens");
                let first = usize::from(u16::from_be_bytes([
                    fixed[9 + m.key_len()],
                    fixed[10 + m.key_len()],
                ]));
                let head = (first > 0).then(|| {
                    let mut chunk = vec![0u8; first + TAG_LEN];
                    read_exact(&mut uplink, &mut chunk).expect("first");
                    let got = cipher.open_in_place(&mut chunk).expect("opens first");
                    chunk[..got].to_vec()
                });
                let _ = s;
                (cipher, head)
            }
        };
        let mut buf = wire_buffer();
        let back = match folded {
            Some(head) => head,
            None => open_chunk(&mut uplink, &mut recv, &mut buf)
                .expect("opens body")
                .to_vec(),
        };
        assert_eq!(back, b"ping"[..]);
    }

    /// Served traffic meters the generated and configured identities apart, even when a foreign inbound reserves the name the generated one would have taken.
    #[test]
    fn served_multi_user_traffic_counts_the_generated_and_configured_identities_apart() {
        use base64::Engine as _;
        let _guard = crate::stats::test_lock();
        crate::stats::clear();
        let stats = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&stats).expect("policy installs");
        crate::stats::install(&stats).expect("stats installs");

        let key = |b: u8| base64::engine::general_purpose::STANDARD.encode(vec![b; 32]);
        let password = format!("{}:{}:{}", key(1), key(2), key(3));
        let method = "2022-blake3-aes-256-gcm";
        let root = crate::json::parse(&format!(
            r#"{{"inbounds":[
                {{"protocol":"shadowsocks","tag":"ss-in","settings":{{"method":"{method}","password":"{password}","users":[{{"email":"alice@example"}}]}}}},
                {{"protocol":"trojan","settings":{{"email":"ss-in#1"}}}}]}}"#
        ))
        .expect("parses");
        let inbound = crate::json::parse(&format!(
            r#"{{"protocol":"shadowsocks","tag":"ss-in","settings":{{"method":"{method}","password":"{password}","users":[{{"email":"alice@example"}}]}}}}"#
        ))
        .expect("parses");
        let reserved = crate::proxy::configured_emails(&root);
        let accounts = crate::proxy::ss_accounts(
            &inbound,
            "127.0.0.1:0",
            password.clone(),
            method.to_owned(),
            &reserved,
        );
        assert_eq!(
            accounts.identities,
            vec![("alice@example".to_owned(), 0), ("ss-in#1#".to_owned(), 0),]
        );

        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let target: SocketAddr = echo.local_addr().expect("addr");
        thread::spawn(move || {
            for stream in echo.incoming().take(2) {
                let Ok(mut stream) = stream else { continue };
                thread::spawn(move || {
                    let mut buf = [0u8; 64];
                    while let Ok(read) = stream.read(&mut buf) {
                        if read == 0 || stream.write_all(&buf[..read]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        let identities = accounts.identities.clone();
        let announced = password.clone();
        thread::spawn(move || {
            for stream in server.incoming().take(2) {
                let Ok(stream) = stream else { continue };
                let announced = announced.clone();
                let identities = identities.clone();
                thread::spawn(move || serve(stream, &announced, method, &identities, true));
            }
        });

        for psk in [key(2), key(3)] {
            echo_through(port, &format!("{}:{psk}", key(1)), method, target);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let snapshot = loop {
            let snapshot = crate::stats::snapshot();
            let counted = ["alice@example", "ss-in#1#"].iter().all(|user| {
                snapshot
                    .user
                    .get(*user)
                    .is_some_and(|traffic| traffic.uplink == 38 && traffic.downlink >= 4)
            });
            if counted || std::time::Instant::now() >= deadline {
                break snapshot;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(snapshot.user["alice@example"].uplink, 38);
        assert_eq!(snapshot.user["ss-in#1#"].uplink, 38);
        assert!(snapshot.user["alice@example"].downlink >= 4);
        assert!(snapshot.user["ss-in#1#"].downlink >= 4);
        assert!(
            !snapshot.user.contains_key("ss-in#1"),
            "the configured email of another inbound received no traffic"
        );
        crate::stats::clear();
    }

    #[test]
    fn one_relay_read_becomes_one_write_and_reads_back_whole() {
        struct Counting<'a> {
            seen: &'a mut Vec<u8>,
            writes: usize,
            base: usize,
        }
        impl Write for Counting<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                self.base = buf.as_ptr() as usize;
                self.seen.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
        let mut send = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut buf = crate::proxy::RelayBuf::with_len(SEAL_HEAD + READ_CHUNK + TAG_LEN);
        for (i, b) in buf.as_mut()[SEAL_HEAD..SEAL_HEAD + READ_CHUNK]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 251) as u8;
        }
        let plain = buf.as_mut()[SEAL_HEAD..SEAL_HEAD + READ_CHUNK].to_vec();
        let base = buf.as_mut().as_ptr() as usize;
        let capacity = buf.capacity();
        let mut seen = Vec::new();
        let (writes, wrote_base) = {
            let mut out = Counting {
                seen: &mut seen,
                writes: 0,
                base: 0,
            };
            seal_all(&mut send, buf.as_mut(), READ_CHUNK, &mut out).expect("seals");
            (out.writes, out.base)
        };
        assert_eq!(writes, 1, "a relay read is sealed and written once");
        assert_eq!(
            wrote_base, base,
            "the write leaves from the caller's buffer, so no payload byte is copied"
        );
        assert_eq!(
            buf.as_mut().as_ptr() as usize,
            base,
            "the read buffer never moves"
        );
        assert_eq!(buf.capacity(), capacity, "the read buffer never grows");
        let mut cursor = std::io::Cursor::new(&seen);
        let mut wire = wire_buffer();
        let mut got = 0usize;
        let mut chunks = 0usize;
        let mut recv2 = Cipher::from_psk(method, &psk, &salt).expect("derives");
        while got < plain.len() {
            let back = open_chunk(&mut cursor, &mut recv2, &mut wire).expect("opens");
            assert_eq!(back, &plain[got..got + back.len()]);
            got += back.len();
            chunks += 1;
        }
        assert_eq!(got, plain.len());
        assert_eq!(chunks, 1, "a 16 KiB read is one 2022 chunk, not two");
    }

    #[test]
    fn chunks_open_that_seal_sealed_and_reject_damage() {
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
        let mut send = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut wire = Vec::new();
        let msg = b"length-is-framing";
        let mut plain_buf = vec![0u8; SEAL_HEAD + msg.len() + TAG_LEN];
        plain_buf[SEAL_HEAD..SEAL_HEAD + msg.len()].copy_from_slice(msg);
        seal_all(&mut send, &mut plain_buf, msg.len(), &mut wire).expect("seals");
        let mut recv = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&wire);
        let mut buf = wire_buffer();
        let back = open_chunk(&mut cursor, &mut recv, &mut buf).expect("opens");
        assert_eq!(back, &b"length-is-framing"[..]);
        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut damaged = std::io::Cursor::new(&tampered);
        let mut fresh = Cipher::from_psk(method, &psk, &salt).expect("derives");
        assert!(open_chunk(&mut damaged, &mut fresh, &mut wire_buffer()).is_none());
    }

    #[test]
    fn an_opened_payload_is_the_datagrams_own_bytes() {
        let method = Method::Aes256Gcm;
        let psk = vec![0x11u8; 32];
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut datagrams = Datagrams::new();
        datagrams.session = 0x0102_0304_0506_0708;
        datagrams.packet = 0;
        let mut warm = datagrams
            .seal(&psk, method, &target, b"a payload worth keeping")
            .expect("seals")
            .to_vec();
        datagrams
            .open(&psk, method, &mut warm)
            .expect("warms the session");
        for round in 0..8 {
            let mut packet = datagrams
                .seal(&psk, method, &target, b"a payload worth keeping")
                .expect("seals")
                .to_vec();
            let start = packet.as_ptr() as usize;
            let end = start + packet.len();
            let (got, payload, _) = datagrams.open(&psk, method, &mut packet).expect("opens");
            let _ = got;
            assert_eq!(payload, b"a payload worth keeping", "round {round}");
            assert!(
                (start..end).contains(&(payload.as_ptr() as usize)),
                "round {round}: payload is a separate buffer"
            );
        }
    }

    #[test]
    fn eih_multi_user_hands_the_right_psk_to_the_session() {
        let method = Method::Aes128Gcm;
        let master = ferrox_core::b64::encode(&[0x11u8; 16]);
        let user = ferrox_core::b64::encode(&[0x22u8; 16]);
        let password = format!("{master}:{user}");
        let list = psks(&password, method).expect("lists");
        assert_eq!(list.len(), 2);
        let salt = vec![0x33u8; 16];
        let eih = shadowsocks2022::encrypt_eih(method, &list[0], &salt, &list[1]).expect("seals");
        let hash = shadowsocks2022::decrypt_eih(method, &list[0], &salt, &eih).expect("opens");
        assert_eq!(hash, shadowsocks2022::user_hash(&list[1]));
    }

    #[test]
    fn udp_multi_user_packs_one_eih_and_opens_with_the_pinned_psk() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let key_len = method.key_len();
            let master = vec![0x11u8; key_len];
            let user = vec![0x22u8; key_len];
            let list = vec![master, user];
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let mut client = Datagrams::new();
            client.session = 0x0a0b_0c0d_0e0f_1011;
            client.packet = 0;
            let mut packet = client
                .seal_list(method, &list, &target, b"multi-payload")
                .expect("seals")
                .to_vec();
            let single = client
                .seal(&list[1], method, &target, b"multi-payload")
                .expect("seals")
                .to_vec();
            assert_eq!(
                packet.len(),
                single.len() + BLOCK_LEN,
                "{method}: one EIH block rides beside the header"
            );
            let mut server = Datagrams::new();
            let mut opened = packet.clone();
            let (got, payload, idx, _) = server
                .open_multi(method, &list, &mut opened)
                .expect("opens");
            assert_eq!(got, target);
            assert_eq!(idx, 1);
            assert_eq!(payload, b"multi-payload");
            assert!(server.open_multi(method, &list, &mut packet).is_none());
            assert!(client
                .seal_list(method, &list[..1], &target, b"x")
                .is_none());
            assert!(Datagrams::new()
                .open_multi(Method::Chacha20Poly1305, &list, &mut packet)
                .is_none());
        }
        assert!(
            Datagrams::new()
                .seal_list(
                    Method::Chacha20Poly1305,
                    &[vec![0u8; 32], vec![1u8; 32]],
                    &"127.0.0.1:53".parse().expect("addr"),
                    b"x",
                )
                .is_none(),
            "chacha multi-user stays refused"
        );
    }

    #[test]
    fn udp_server_replies_are_server_typed_and_stay_with_their_session() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let key_len = method.key_len();
            let psk = vec![0x33u8; key_len];
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let mut server = Datagrams::new();
            let client_session = 0x7172_7374_7576_7778;
            let mut packet = server
                .seal_server(method, &psk, client_session, &target, b"reply-payload")
                .expect("seals")
                .to_vec();
            let mut client = Datagrams::new();
            client.session = client_session;
            let mut opened = packet.clone();
            let start = opened.as_ptr() as usize;
            let end = start + opened.len();
            let (got, payload) = client
                .open_server(&psk, method, &mut opened)
                .expect("opens");
            assert_eq!(got, target, "{method}");
            assert_eq!(payload, b"reply-payload", "{method}");
            assert!(
                (start..end).contains(&(payload.as_ptr() as usize)),
                "{method}: the reply is opened in the datagram"
            );
            let mut stranger = Datagrams::new();
            stranger.session = client_session ^ 1;
            assert!(
                stranger.open_server(&psk, method, &mut packet).is_none(),
                "{method}: a forged client session is refused"
            );
            let mut tampered = packet.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert!(
                Datagrams::new()
                    .open_server(&psk, method, &mut tampered)
                    .is_none(),
                "{method}: damage is refused"
            );
        }
    }

    /// The assembled client seals requests on one codec and opens replies on another in a reader thread: the reply codec must be seeded with the request codec's session, or every reply drops as forged.
    #[test]
    fn a_reply_reader_seeded_with_the_request_session_opens_the_server_reply() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let psk = vec![0x5au8; method.key_len()];
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let mut writer = Datagrams::new();
            let packet = writer
                .seal(&psk, method, &target, b"udp-ping")
                .expect("seals")
                .to_vec();
            let mut server = Datagrams::new();
            let mut opened = packet.clone();
            let (_, request, session) = server.open(&psk, method, &mut opened).expect("opens");
            assert_eq!(request, b"udp-ping");
            assert_eq!(
                session,
                writer.client_session(),
                "the request carries the writer's session"
            );
            let reply = server
                .seal_server(method, &psk, session, &target, b"udp-pong")
                .expect("seals")
                .to_vec();
            let mut reader = Datagrams::with_client_session(writer.client_session());
            let mut buf = reply.clone();
            let (got, payload) = reader
                .open_server(&psk, method, &mut buf)
                .expect("opens the reply");
            assert_eq!(got, target, "{method}");
            assert_eq!(payload, b"udp-pong", "{method}");
            let mut stranger = Datagrams::new();
            stranger.session = writer.client_session() ^ 1;
            let mut buf = reply.clone();
            assert!(
                stranger.open_server(&psk, method, &mut buf).is_none(),
                "{method}: an unseeded reader drops the reply, as the split client used to"
            );
        }
    }

    #[test]
    fn udp_relay_strips_one_header_and_still_opens() {
        let method = Method::Aes256Gcm;
        let relay_psk = vec![0x44u8; 32];
        let dest_psk = vec![0x55u8; 32];
        let dest: SocketAddr = "127.0.0.1:8388".parse().expect("addr");
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let list = vec![relay_psk.clone(), dest_psk.clone()];
        let mut client = Datagrams::new();
        client.session = 0x1a1b_1c1d_1e1f_2021;
        client.packet = 0;
        let packet = client
            .seal_list(method, &list, &target, b"relay-payload")
            .expect("seals")
            .to_vec();
        let mut out: Vec<u8> = Vec::new();
        let dests = [(dest_psk.clone(), dest)];
        let (got, session) =
            relay_udp_forward(&relay_psk, &relay_dests(&dests), &packet, &mut out).expect("relays");
        assert_eq!(got, dest);
        assert_eq!(out.len(), packet.len() - BLOCK_LEN);
        let forwarded = out.clone();
        let mut server = Datagrams::new();
        let mut opened = forwarded.clone();
        let (target_back, payload, _) = server.open(&dest_psk, method, &mut opened).expect("opens");
        assert_eq!(target_back, target);
        assert_eq!(payload, b"relay-payload");
        assert_eq!(session, 0x1a1b_1c1d_1e1f_2021);
        assert!(
            relay_udp_forward(&relay_psk, &relay_dests(&dests), &forwarded, &mut out).is_none(),
            "a header already stripped is not a client packet"
        );
        let reply = server
            .seal_server(method, &dest_psk, session, &target, b"relay-reply")
            .expect("seals")
            .to_vec();
        assert_eq!(
            relay_udp_client_of(&dest_psk, &mut Vec::new(), &reply),
            Some(session),
            "the relay reads the client session out of the response"
        );
    }

    /// The reply body opens into the caller's buffer: two replies of one size write where the first did, so a relay that answers a thousand requests of one size allocates for the first of them.
    #[test]
    fn a_reply_body_is_opened_into_a_buffer_that_stops_growing() {
        let method = Method::Aes256Gcm;
        let dest_psk = vec![0x55u8; 32];
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut server = Datagrams::new();
        let reply = server
            .seal_server(
                method,
                &dest_psk,
                0x1111_2222_3333_4444,
                &target,
                b"relay-reply",
            )
            .expect("seals")
            .to_vec();
        let mut body: Vec<u8> = Vec::new();
        assert_eq!(
            relay_udp_client_of(&dest_psk, &mut body, &reply),
            Some(0x1111_2222_3333_4444)
        );
        let pointer = body.as_ptr();
        let room = body.capacity();
        assert_eq!(
            relay_udp_client_of(&dest_psk, &mut body, &reply),
            Some(0x1111_2222_3333_4444),
            "the same reply opens again on the reused buffer"
        );
        assert!(
            std::ptr::eq(pointer, body.as_ptr()),
            "a repeat reply size allocated no new buffer"
        );
        assert_eq!(
            body.capacity(),
            room,
            "a repeat reply size reallocated nothing"
        );
    }

    /// The forwarded datagram is written into the caller's buffer: forwarding a size the buffer has already held moves neither its pointer nor its capacity, so a relay that carries a thousand datagrams of one size allocates for the first of them.
    #[test]
    fn a_forwarded_datagram_is_written_into_a_buffer_that_stops_growing() {
        let method = Method::Aes256Gcm;
        let relay_psk = vec![0x44u8; 32];
        let dest_psk = vec![0x55u8; 32];
        let dest: SocketAddr = "127.0.0.1:8388".parse().expect("addr");
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let list = vec![relay_psk.clone(), dest_psk.clone()];
        let dests = [(dest_psk.clone(), dest)];
        let hashed = relay_dests(&dests);
        let mut client = Datagrams::new();
        client.session = 0x2b2b_2b2b_2b2b_2b2b;
        let packet = client
            .seal_list(method, &list, &target, b"a-relayed-datagram")
            .expect("seals")
            .to_vec();
        let mut out: Vec<u8> = Vec::new();
        let (got, session) =
            relay_udp_forward(&relay_psk, &hashed, &packet, &mut out).expect("relays");
        assert_eq!(got, dest);
        assert_eq!(session, 0x2b2b_2b2b_2b2b_2b2b);
        assert_eq!(out.len(), packet.len() - BLOCK_LEN);
        let written = out.clone();
        let pointer = out.as_ptr();
        let room = out.capacity();
        // The same size again: the write lands where the last one did, and the bytes are the ones a fresh buffer would have held.
        relay_udp_forward(&relay_psk, &hashed, &packet, &mut out).expect("relays");
        assert_eq!(
            out, written,
            "the reused buffer holds what a fresh one held"
        );
        assert!(
            std::ptr::eq(pointer, out.as_ptr()),
            "a repeat size allocated no new buffer"
        );
        assert_eq!(out.capacity(), room, "a repeat size reallocated nothing");
    }

    #[test]
    fn udp_relay_carries_an_echo_end_to_end() {
        let method = Method::Aes256Gcm;
        let relay_psk = vec![0x71u8; 32];
        let dest_psk = vec![0x72u8; 32];
        let dest_b64 = ferrox_core::b64::encode(&dest_psk);
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_addr = echo.local_addr().expect("addr");
        echo.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let dest_addr = dest_sock.local_addr().expect("addr");
        let relay_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let relay_addr = relay_sock.local_addr().expect("addr");
        let client_relay = relay_psk.clone();
        let client_dest = dest_psk.clone();
        thread::spawn(move || {
            let mut buf = vec![0u8; crate::proxy::UDP_BUF];
            while let Ok((n, src)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], src);
            }
        });
        thread::spawn(move || {
            serve_udp_on(&dest_sock, &dest_b64, "2022-blake3-aes-256-gcm", true);
        });
        thread::spawn(move || {
            serve_udp_relay(&relay_sock, method, &relay_psk, &[(dest_psk, dest_addr)]);
        });
        let client = UdpSocket::bind("127.0.0.1:0").expect("binds");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut datagrams = Datagrams::new();
        let list = vec![client_relay, client_dest.clone()];
        let packet = datagrams
            .seal_list(method, &list, &echo_addr, b"udp-relay-ping")
            .expect("seals")
            .to_vec();
        client.send_to(&packet, relay_addr).expect("sends");
        let mut buf = vec![0u8; crate::proxy::UDP_BUF];
        let (n, _) = client.recv_from(&mut buf).expect("receives");
        let (_, payload) = datagrams
            .open_server(&client_dest, method, &mut buf[..n])
            .expect("opens");
        assert_eq!(payload, b"udp-relay-ping");
    }

    #[test]
    fn tcp_relay_carries_an_echo_behind_one_eih() {
        let relay_psk = psk_b64(32);
        let dest_psk = ferrox_core::b64::encode(&[0x66u8; 32]);
        let password = format!("{relay_psk}:{dest_psk}");
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
        let dest = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let dest_port = dest.local_addr().expect("addr").port();
        let dest_psk_thread = dest_psk.clone();
        thread::spawn(move || {
            let (stream, _) = dest.accept().expect("accepts");
            serve(
                stream,
                &dest_psk_thread,
                "2022-blake3-aes-256-gcm",
                &[],
                true,
            );
        });
        let relay = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let relay_port = relay.local_addr().expect("addr").port();
        let relay_psk_thread = relay_psk.clone();
        let dest_addr: SocketAddr = format!("127.0.0.1:{dest_port}").parse().expect("addr");
        let dest_psk_raw = ferrox_core::b64::decode(dest_psk.as_bytes()).expect("decodes");
        thread::spawn(move || {
            let (stream, _) = relay.accept().expect("accepts");
            serve_relay(
                stream,
                "2022-blake3-aes-256-gcm",
                &ferrox_core::b64::decode(relay_psk_thread.as_bytes()).expect("decodes"),
                &[(dest_psk_raw, dest_addr)],
            );
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = Connection::connect(("127.0.0.1", relay_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let Ok((mut send, recv)) = client_send_handshake(
            &mut uplink,
            &password,
            "2022-blake3-aes-256-gcm",
            &crate::proxy::Destination::from(target),
        ) else {
            panic!("relay handshake refused");
        };
        let mut ping = [0u8; SEAL_HEAD + 4 + TAG_LEN];
        ping[SEAL_HEAD..SEAL_HEAD + 4].copy_from_slice(b"ping");
        seal_all(&mut send, &mut ping, 4, &mut uplink).expect("seals");
        let _cipher = match recv {
            Recv::Ready(cipher) => cipher,
            Recv::Waiting(m, p, s) => {
                let mut peer = vec![0u8; m.key_len()];
                read_exact(&mut uplink, &mut peer).expect("salt");
                let mut cipher = Cipher::from_psk(m, &p, &peer).expect("derives");
                let fixed_len = 1 + 8 + m.key_len() + 2 + TAG_LEN;
                let mut fixed = vec![0u8; fixed_len];
                read_exact(&mut uplink, &mut fixed).expect("fixed");
                cipher.open_in_place(&mut fixed).expect("opens");
                let first = usize::from(u16::from_be_bytes([
                    fixed[9 + m.key_len()],
                    fixed[10 + m.key_len()],
                ]));
                assert_eq!(first, 4, "the head carries the first payload");
                let mut chunk = vec![0u8; first + TAG_LEN];
                read_exact(&mut uplink, &mut chunk).expect("first");
                let got = cipher.open_in_place(&mut chunk).expect("opens first");
                assert_eq!(&chunk[..got], b"ping");
                let _ = s;
                cipher
            }
        };
    }

    /// What a stage between the carrier and the codec asks for: its own capacity.
    const STAGE: usize = 32 * 1024;

    /// The record size this tree's own xhttp writer frames a body in.
    const FRAME: usize = 16 * 1024;

    /// The carrier side of a carried downlink: every width the codec reaches the carrier with, which
    /// is where a stage's capacity would stand in for the codec's own chunk asks.
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

    impl crate::proxy::FrameWrite for Vec<u8> {
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

    /// The chain the xhttp arm composes, driven from memory: two sealed chunks arrive through the
    /// real carrier framing, and the carrier hears the window's own ask. A sealed length and the
    /// chunk it names used to be two asks of the carrier each, which is what a `BufReader` between
    /// them made worse by asking its capacity for the first byte of either.
    #[test]
    fn the_carrier_and_the_window_ask_the_socket_as_one() {
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
        let mut send = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let plain: Vec<u8> = (0..1000 + 4000).map(|i| (i % 251) as u8).collect();
        let mut body = Vec::new();
        for piece in [&plain[..1000], &plain[1000..]] {
            let len = piece.len();
            let mut buf = vec![0u8; SEAL_HEAD + len + TAG_LEN];
            buf[SEAL_HEAD..SEAL_HEAD + len].copy_from_slice(piece);
            seal_all(&mut send, &mut buf, len, &mut body).expect("seals");
        }
        let (carrier, _writer) = crate::xhttp::connect_split(
            std::io::Cursor::new(carrier_answer(&body)),
            Vec::new(),
            "h",
            "/share",
            &[],
            &"X".repeat(500),
        )
        .expect("dials the head");
        let widths = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let recv = Cipher::from_psk(method, &psk, &salt).expect("derives");
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
            "the chunks open"
        );
        assert_eq!(out, plain, "a downlink byte crosses user space once");
        let seen = widths.borrow();
        assert!(
            seen.contains(&WINDOW),
            "the whole window is asked of the carrier: {seen:?}"
        );
        assert!(
            !seen.contains(&(LENGTH_LEN + TAG_LEN)),
            "a sealed length no longer costs its own ask: {seen:?}"
        );
        assert!(
            !seen.contains(&(1000 + TAG_LEN)),
            "nor does the chunk it names: {seen:?}"
        );
        assert!(
            !seen.contains(&STAGE),
            "a stage would ask its capacity here: {seen:?}"
        );
        // The ask count is no gate here: `connect_split` hands the carrier's pipelined tail to its reader's prefix, so a window ask is answered at that boundary first.
        assert_eq!(
            seen[0], WINDOW,
            "the batch opens inside one window ask, not a length ask and a payload ask"
        );
    }

    /// The downlink's batch path end to end, counted where the count is exact: a source that answers
    /// the whole window in one read, a target that counts vectored writes, and eight 8 KiB chunks —
    /// the framing the window is sized to, filling it to its last byte — opening and leaving whole.
    #[test]
    fn a_bulk_read_serves_every_buffered_chunk() {
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
        let mut send = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let sizes = [8192; CHUNKS_PER_BATCH];
        let mut plain = Vec::new();
        let mut wire = Vec::new();
        for (part, size) in sizes.iter().enumerate() {
            let piece: Vec<u8> = (0..*size).map(|i| ((i + part * 7) % 251) as u8).collect();
            plain.extend_from_slice(&piece);
            wire.extend_from_slice(&seal_one(&mut send, &piece));
        }
        let recv = Cipher::from_psk(method, &psk, &salt).expect("derives");
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
            "one bulk read serves the whole batch, the next one finds the end"
        );
        assert_eq!(writes, 1, "the opened batch leaves in one write");
        assert_eq!(bases.len(), sizes.len(), "one piece per opened chunk");
        assert!(
            bases.windows(2).all(|pair| pair[0] < pair[1]),
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
    }

    /// A batch is the chunks the window already holds, and nothing more: a peer that stops to hear
    /// back from its own target must find the chunk it sent already at the target, so only the first
    /// chunk of a batch is ever waited for. One read, one opened, no second read spent.
    #[test]
    fn a_batch_never_waits_for_a_chunk_that_has_not_arrived() {
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
        let mut send = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let first: Vec<u8> = (0..READ_CHUNK).map(|i| (i % 251) as u8).collect();
        let second: Vec<u8> = (0..100).map(|i| (i % 197) as u8).collect();
        let whole = seal_one(&mut send, &first);
        let rest = seal_one(&mut send, &second);
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
        let mut recv = Cipher::from_psk(method, &psk, &salt).expect("derives");
        let mut window = ChunkReader::new(&mut staged);
        let mut batch = [(0usize, 0usize); CHUNKS_PER_BATCH];
        assert!(matches!(window.try_fill(), Fill::Ready));
        assert_eq!(
            window.open_ready(&mut recv, &mut batch),
            1,
            "the second chunk is still arriving"
        );
        assert_eq!(window.read.reads, 1, "no read is spent waiting for it");
        assert_eq!(&window.buf[batch[0].0..batch[0].0 + batch[0].1], &first[..]);
        assert!(matches!(window.try_fill(), Fill::Ready));
        assert_eq!(
            window.open_ready(&mut recv, &mut batch),
            1,
            "the held length opens against its own nonce once the payload lands"
        );
        assert_eq!(
            &window.buf[batch[0].0..batch[0].0 + batch[0].1],
            &second[..]
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
        if !crate::conn::in_a_quiet_process(
            "shadowsocks2022::tests::a_live_session_costs_no_thread",
        ) {
            return;
        }
        let method = Method::Aes256Gcm;
        let psk = vec![7u8; 32];
        let salt = vec![7u8; 32];
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
                Cipher::from_psk(method, &psk, &salt).expect("derives"),
                Recv::Ready(Cipher::from_psk(method, &psk, &salt).expect("derives")),
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
                Cipher::from_psk(method, &psk, &salt).expect("derives"),
                Recv::Ready(Cipher::from_psk(method, &psk, &salt).expect("derives")),
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
