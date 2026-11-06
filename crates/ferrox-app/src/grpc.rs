use crate::config::GrpcSettings;
use crate::conn::Connection;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::proxy::{Accepted, FrameWrite, Settle};

use crate::h2::{
    block_encode, frame_head, write_frame, Decoder, E_REFUSED, FRAME_CAP, F_ACK, F_END,
    F_END_HEADERS, F_PADDED, F_PRIORITY, HEAD_CAP, MAGIC, S_MAX_CONCURRENT, S_MAX_FRAME, S_WINDOW,
    T_CONT, T_DATA, T_HEADERS, T_PING, T_RST, T_SETTINGS, T_WINDOW, WINDOW, WINDOW_MAX,
};

const MSG_CAP: usize = 16 * 1024 * 1024;

/// The control frames a post-`END_STREAM` read pumps before it yields: a peer that never stops sending them must not pin the lane past the half-close the relay owes the target.
const POST_END_BURST: usize = 16;

/// The bodies one credit pays for, half the window the preface advertises: a peer that has sent this much is owed a credit, and one that has not still has the other half to send into, so no grant is ever the thing a stalled writer waits for.
const CREDIT_AT: u32 = WINDOW / 2;

/// The two `WINDOW_UPDATE` frames a credit grants differ only by stream id, so their eighteen header bytes are constant and each call fills the two increment slots left zero here: the pair leaves in one write.
const CREDIT_PAIR: [u8; 26] = {
    let mut out = [0u8; 26];
    out[2] = 4;
    out[3] = T_WINDOW;
    out[15] = 4;
    out[16] = T_WINDOW;
    out
};

/// What this lane advertises before any body arrives: the stream window is the setting, and the connection window is the RFC's `65_535` plus this top-up, so both equal `WINDOW` and a peer can send a whole window before it needs a credit.
const PREFACE: [u8; 34] = {
    let mut out = [0u8; 34];
    out[2] = 12;
    out[3] = T_SETTINGS;
    let window_setting = S_WINDOW.to_be_bytes();
    out[9] = window_setting[0];
    out[10] = window_setting[1];
    let window = WINDOW.to_be_bytes();
    out[11] = window[0];
    out[12] = window[1];
    out[13] = window[2];
    out[14] = window[3];
    let concurrent = S_MAX_CONCURRENT.to_be_bytes();
    out[15] = concurrent[0];
    out[16] = concurrent[1];
    out[20] = 1;
    out[23] = 4;
    out[24] = T_WINDOW;
    let top_up = (WINDOW - 65_535).to_be_bytes();
    out[30] = top_up[0];
    out[31] = top_up[1];
    out[32] = top_up[2];
    out[33] = top_up[3];
    out
};

#[derive(Debug, Default)]
struct SendWindow {
    conn: u64,
    stream: u64,
    /// The transport gates the bytes itself (the multiplexed server), so this layer must not take a
    /// window it never receives a `WINDOW_UPDATE` for.
    unlimited: bool,
}

struct Shared {
    stream: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    send: Mutex<SendWindow>,
    wake: Condvar,
    max_frame: Mutex<usize>,
    init: Mutex<u64>,
    ended: AtomicBool,
    upload_ended: AtomicBool,
    upload_gate: Mutex<()>,
    dead: AtomicBool,
    pong: AtomicU64,
    /// The transport is the multiplexed sender, whose own windows are the only gate.
    muxed: bool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("send", &self.send)
            .field("max_frame", &self.max_frame)
            .field("init", &self.init)
            .field("ended", &self.ended)
            .field("upload_ended", &self.upload_ended)
            .field("dead", &self.dead)
            .field("pong", &self.pong)
            .finish_non_exhaustive()
    }
}

/// Take `need` from both windows, waiting for the peer's credit only when `wait` says to: a gathered
/// batch flushes before it parks, since a peer grants for bytes it has seen and not for ones still
/// sitting in the batch.
fn take_window(shared: &Shared, need: u64, wait: bool) -> bool {
    let deadline = wait.then(|| Instant::now() + crate::budgets::relay_stall());
    take_window_until(shared, need, deadline)
}

/// The same take under a deadline: a relay write waits only the quantum its lane can spare, while a
/// blocking caller waits the relay stall, and the wake is the peer's `WINDOW_UPDATE` rather than a
/// poll that has to re-ask for credit it could already have.
fn take_window_until(shared: &Shared, need: u64, deadline: Option<Instant>) -> bool {
    let mut send = shared.send.lock().unwrap_or_else(PoisonError::into_inner);
    if send.unlimited {
        return true;
    }
    while send.conn < need || send.stream < need {
        if shared.dead.load(Ordering::SeqCst) {
            return false;
        }
        let Some(deadline) = deadline else {
            return false;
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let (guard, waited) = shared
            .wake
            .wait_timeout(send, left)
            .unwrap_or_else(PoisonError::into_inner);
        send = guard;
        if waited.timed_out() {
            return false;
        }
    }
    send.conn -= need;
    send.stream -= need;
    true
}

/// A batch the transport refused gives its window back: the bytes never left, so the peer will
/// never grant for them, and the caller's retry must find the credit it took.
fn refund(shared: &Shared, need: u64) {
    if need == 0 {
        return;
    }
    let mut send = shared.send.lock().unwrap_or_else(PoisonError::into_inner);
    if send.unlimited {
        return;
    }
    send.conn += need;
    send.stream += need;
    drop(send);
    shared.wake.notify_all();
}

/// Which of the service's two methods a call used, and so what shape its messages have.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Method {
    /// `rpc Tun`: one `Hunk` per message, one payload in each.
    Hunk,
    /// `rpc TunMulti`: one `MultiHunk` per message, a batch of elements in each.
    MultiHunk,
}

/// What a header block answers, read while it decodes: each name the gates use is judged at its first field, so a head costs no allocation and no buffer outlives the block.
#[derive(Debug, Default)]
struct Gate {
    /// The first `:status` was `200`; `None` when the block carries no status at all.
    status: Option<bool>,
    /// The first `:path` names one of the two served methods.
    served: Option<bool>,
    /// and which of them, so the reply is read as a `MultiHunk` rather than silently truncated to the last element of every message.
    multi: Option<bool>,
    /// The first `:method` was `POST`.
    posted: Option<bool>,
    /// The first `content-type` is a gRPC one.
    typed: Option<bool>,
}

impl Gate {
    fn take(&mut self, name: &[u8], value: &[u8], path: &str, multi_path: &str) {
        if self.status.is_none() && name.eq_ignore_ascii_case(b":status") {
            self.status = Some(value == b"200");
        } else if self.served.is_none() && name.eq_ignore_ascii_case(b":path") {
            let multi = multi_path != path && value == multi_path.as_bytes();
            self.multi = Some(multi);
            self.served = Some(multi || value == path.as_bytes());
        } else if self.posted.is_none() && name.eq_ignore_ascii_case(b":method") {
            self.posted = Some(value == b"POST");
        } else if self.typed.is_none() && name.eq_ignore_ascii_case(b"content-type") {
            self.typed = Some(value.starts_with(b"application/grpc"));
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub(crate) struct GrpcReader<R: Read = Connection> {
    read: R,
    shared: Arc<Shared>,
    decoder: Decoder,
    stream: u32,
    server: bool,
    path: String,
    /// The same call with the multi-mode stream name: one listener serves both methods, the way Xray's hub registers `Tun` and `TunMulti` from one config.
    multi_path: String,
    /// The method this call used, read off its `:path`, because the two shapes cannot share a decoder.
    method: Method,
    answered: bool,
    head: Vec<u8>,
    head_id: u32,
    /// The flags of the `HEADERS` frame that opened an incomplete block: `END_STREAM` arrives there, not on the final `CONTINUATION`.
    head_flags: u8,
    /// The one buffer a body uses: DATA frames are read onto its end and decoded there.
    msg: Vec<u8>,
    msg_at: usize,
    /// One past the last byte of the last decoded message, so fields this lane does not read are skipped where they lie.
    msg_end: usize,
    /// One past the payload the caller has not taken yet, from `msg_at`.
    pay_end: usize,
    /// Bytes the reader moved for itself — the reclaim move and the part of a message a pad byte cuts into: these and nothing else are what the staging gate counts.
    #[cfg_attr(not(test), allow(dead_code, reason = "read by the staging gate"))]
    staged: usize,
    /// The reclaim moves that copied live bytes: a drained buffer cleared rather than moved is a call fewer here, which the byte counter cannot see.
    #[cfg_attr(not(test), allow(dead_code, reason = "read by the reclaim gate"))]
    reclaims: usize,
    /// Scratch for the frames that are not a body: headers, settings, ping.
    frame: Vec<u8>,
    /// The nine bytes that open the next frame, and how many are in hand: a poll timeout hands the
    /// lane back with the partial head kept, so the next read resumes on the same bytes.
    frame_head: [u8; 9],
    frame_have: usize,
    /// The frame whose body has not landed whole: what arrived is kept and the next read continues it.
    pending: Option<Pending>,
    /// Bodies read since the last credit, and the stream they belong to: a credit pays for a window's worth of frames, not for one.
    owed: u32,
    owed_id: u32,
    /// The clock this head must be decoded by, armed only while the preface, the request headers and the opening request arrive: past it a silence is an error rather than a wait, so a peer that stops speaking releases the thread.
    handshake: Option<std::time::Instant>,
    eof: bool,
    /// The peer sent `END_STREAM`: the read half finished normally, so the write half may still be used.
    remote_end: bool,
    /// The socket answers a poll instead of blocking, so a read past `END_STREAM` can pump control frames and hand the turn back.
    poll: bool,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    len: usize,
    kind: u8,
    flags: u8,
    id: u32,
    from: usize,
    filled: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct GrpcWriter {
    shared: Arc<Shared>,
    stream: u32,
    multi: bool,
}

impl GrpcReader<Connection> {
    /// Arm or clear the poll quantum on the socket this reader reads through, so a peer that opens then stalls mid-header cannot pin the serve thread past the header read; as the `ws`, `httpupgrade` and `httpheader` readers do, and a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        self.poll = every.is_some();
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R: Read + crate::proxy::RelayPoll> crate::proxy::RelayPoll for GrpcReader<R> {
    fn arm_relay_poll(&mut self) {
        self.read.arm_relay_poll();
    }
}

impl<R: Read> GrpcReader<R> {
    /// Arm or clear the clock the opening head is decoded under; only that head runs armed, a relay waits blocking again, as the `ws` reader's budget does.
    pub(crate) fn set_handshake_budget(&mut self, until: Option<std::time::Instant>) {
        self.handshake = until;
    }

    fn emit(&self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut **stream, kind, flags, id, body)
    }

    fn settings(&self, flags: u8, body: &[u8]) {
        if flags & F_ACK != 0 {
            return;
        }
        let mut at = 0;
        while at + 6 <= body.len() {
            let id = u16::from_be_bytes([body[at], body[at + 1]]);
            let value =
                u32::from_be_bytes([body[at + 2], body[at + 3], body[at + 4], body[at + 5]]);
            if id == S_WINDOW {
                let mut init = self
                    .shared
                    .init
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let mut send = self
                    .shared
                    .send
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                send.stream = send
                    .stream
                    .saturating_add(u64::from(value))
                    .saturating_sub(*init);
                send.stream = send.stream.min(WINDOW_MAX);
                *init = u64::from(value);
                self.shared.wake.notify_all();
            } else if id == S_MAX_FRAME {
                let mut max = self
                    .shared
                    .max_frame
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *max = usize::try_from(value).unwrap_or(FRAME_CAP).min(FRAME_CAP);
            }
            at += 6;
        }
        self.emit(T_SETTINGS, F_ACK, 0, &[]);
    }

    fn ping(&self, flags: u8, body: &[u8]) {
        if body.len() != 8 {
            return;
        }
        if flags & F_ACK == 0 {
            self.emit(T_PING, F_ACK, 0, body);
        } else {
            let seq = u64::from_be_bytes(body.try_into().unwrap());
            self.shared.pong.fetch_max(seq, Ordering::SeqCst);
        }
    }

    /// The window this lane grants back as it reads: a body adds to what is owed and nothing leaves the socket, until a credit's worth has landed and one write pays for all of it.
    fn replenish(&mut self, id: u32, len: usize) {
        if self.owed > 0 && id != self.owed_id {
            self.grant();
        }
        self.owed_id = id;
        self.owed += len as u32;
        if self.owed >= CREDIT_AT {
            self.grant();
        }
    }

    /// The connection update and the stream update are the two halves of a constant pair, and the increment is the window they both owe: one credit, one write, one lock.
    fn grant(&mut self) {
        let owed = std::mem::take(&mut self.owed);
        if owed == 0 {
            return;
        }
        let inc = owed.to_be_bytes();
        let mut pair = CREDIT_PAIR;
        pair[9..13].copy_from_slice(&inc);
        let out: &[u8] = if self.owed_id == 0 {
            &pair[..13]
        } else {
            pair[18..22].copy_from_slice(&self.owed_id.to_be_bytes());
            pair[22..26].copy_from_slice(&inc);
            &pair
        };
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        stream.write_slices(&[out]);
    }

    fn refuse(&self, id: u32) {
        self.emit(T_RST, 0, id, &E_REFUSED.to_be_bytes());
    }

    fn headers(&mut self, id: u32, flags: u8, block: &[u8]) -> Option<()> {
        let (path, multi_path) = (&self.path[..], &self.multi_path[..]);
        let mut gate = Gate::default();
        self.decoder.decode(block, &mut |name, value| {
            gate.take(name, value, path, multi_path);
        })?;
        if self.server {
            return self.serve_headers(id, flags, &gate);
        }
        if id != self.stream {
            return Some(());
        }
        if !self.answered {
            if gate.status != Some(true) {
                return None;
            }
            self.answered = true;
        }
        if flags & F_END != 0 {
            self.eof = true;
            self.remote_end = true;
        }
        Some(())
    }

    fn serve_headers(&mut self, id: u32, flags: u8, gate: &Gate) -> Option<()> {
        if self.answered {
            if flags & F_END != 0 {
                self.eof = true;
                self.remote_end = true;
            }
            return Some(());
        }
        if gate.served != Some(true) || gate.posted != Some(true) || gate.typed != Some(true) {
            self.refuse(id);
            return None;
        }
        self.method = if gate.multi == Some(true) {
            Method::MultiHunk
        } else {
            Method::Hunk
        };
        let block = block_encode(&[
            (":status", "200"),
            ("content-type", "application/grpc"),
            ("grpc-encoding", "identity"),
        ]);
        if !self.emit(T_HEADERS, F_END_HEADERS, id, &block) {
            return None;
        }
        self.stream = id;
        self.answered = true;
        if flags & F_END != 0 {
            self.eof = true;
            self.remote_end = true;
        }
        Some(())
    }

    /// Where this DATA body lands: the reclaim a drained buffer gets before a frame is read onto its end.
    fn begin_data(&mut self) -> usize {
        // A fully drained buffer has nothing live to keep, so the reclaim is a clear, not a move of an empty run.
        if self.msg_at == self.msg.len() {
            self.msg.clear();
            self.msg_at = 0;
            self.msg_end = 0;
            self.pay_end = 0;
        } else if self.msg_at * 2 >= self.msg.len() {
            // The bytes the caller already had go first, and only when they outweigh what is still live: a move that costs more than it frees is a copy.
            let at = self.msg_at;
            self.staged += self.msg.len() - at;
            self.reclaims += 1;
            self.msg.copy_within(at.., 0);
            self.msg.truncate(self.msg.len() - at);
            self.msg_at = 0;
            self.msg_end = self.msg_end.saturating_sub(at);
            self.pay_end = self.pay_end.saturating_sub(at);
        }
        self.msg.len()
    }

    /// A DATA body lands at the end of the buffer the decoder reads and the caller takes from, so a payload moves twice at most: out of the socket, and into the caller; `staged` counts every other move.
    fn finish_data(&mut self, id: u32, flags: u8, from: usize, len: usize) -> Option<()> {
        if id != self.stream || !self.answered {
            self.msg.truncate(from);
            return Some(());
        }
        // DATA after END_STREAM is a protocol violation: discard it rather than buffer a body the read half can no longer consume.
        if self.remote_end {
            self.msg.truncate(from);
            return None;
        }
        let (first, pad) = if flags & F_PADDED != 0 {
            let Some(&one) = self.msg.get(from) else {
                self.msg.truncate(from);
                return None;
            };
            let pad = usize::from(one);
            if pad + 1 > len {
                self.msg.truncate(from);
                return None;
            }
            (1usize, pad)
        } else {
            (0usize, 0usize)
        };
        // RFC 7540 6.9: the whole DATA payload is subject to flow control, so the credit is the wire length and not what the cut left.
        self.replenish(id, len);
        if first != 0 || pad != 0 {
            // A pad byte and pad tail sit inside the body the parser reads: when they open a message region a cursor step skips the byte and the frame's length drops the tail, and only a message that already crossed into this frame moves.
            if self.msg_at == from && self.pay_end == from && self.msg_end == from {
                self.msg.truncate(from + len - pad);
                self.msg_at = from + first;
                self.msg_end = from + first;
                self.pay_end = from + first;
            } else {
                self.staged += len - first - pad;
                let end = from + len - pad;
                self.msg.copy_within(from + first..end, from);
                self.msg.truncate(end - first);
            }
        }
        let out = self.decode();
        if flags & F_END != 0 {
            if !self.whole() {
                return None;
            }
            self.eof = true;
            if out.is_some() {
                self.remote_end = true;
            }
        }
        out
    }

    /// The body read, resumed where the last one stopped: a poll timeout leaves what arrived on the
    /// buffer and hands the lane back, and the next call fills the rest.
    fn fill_msg(&mut self, from: usize, len: usize, filled: &mut usize) -> std::io::Result<bool> {
        let end = from + len;
        crate::proxy::grow_scratch(&mut self.msg, end);
        while *filled < len {
            match self.read.read(&mut self.msg[from + *filled..end]) {
                Ok(0) => {
                    self.msg.truncate(from + *filled);
                    return Ok(false);
                }
                Ok(n) => *filled += n,
                Err(error) if crate::proxy::is_timeout(&error) => {
                    self.msg.truncate(from + *filled);
                    match self.handshake {
                        Some(until) if std::time::Instant::now() < until => {
                            crate::proxy::grow_scratch(&mut self.msg, end);
                        }
                        // The head's clock is spent: a hard end, so `read_exact` stops retrying.
                        Some(_) => return Ok(false),
                        // A lane's poll resumes from the bytes in hand; a plain wait keeps waiting.
                        None if crate::proxy::relay_step_owns_poll() => return Err(error),
                        None => {
                            std::thread::sleep(crate::budgets::RELAY_POLL);
                            crate::proxy::grow_scratch(&mut self.msg, end);
                        }
                    }
                }
                Err(_) => {
                    self.msg.truncate(from + *filled);
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The same resume for the frames that are not a body: the scratch holds what arrived.
    fn fill_frame(&mut self, len: usize, filled: &mut usize) -> std::io::Result<bool> {
        crate::proxy::grow_scratch(&mut self.frame, len);
        while *filled < len {
            match self.read.read(&mut self.frame[*filled..len]) {
                Ok(0) => {
                    self.frame.truncate(*filled);
                    return Ok(false);
                }
                Ok(n) => *filled += n,
                Err(error) if crate::proxy::is_timeout(&error) => match self.handshake {
                    Some(until) if std::time::Instant::now() < until => {}
                    Some(_) => {
                        self.frame.truncate(*filled);
                        return Ok(false);
                    }
                    None if crate::proxy::relay_step_owns_poll() => {
                        self.frame.truncate(*filled);
                        return Err(error);
                    }
                    None => std::thread::sleep(crate::budgets::RELAY_POLL),
                },
                Err(_) => {
                    self.frame.truncate(*filled);
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The nine bytes that open a frame, resumed on a poll timeout: nothing of a partial head is lost.
    fn read_frame_head(&mut self) -> std::io::Result<bool> {
        while self.frame_have < 9 {
            match self.read.read(&mut self.frame_head[self.frame_have..]) {
                Ok(0) => return Ok(false),
                Ok(n) => self.frame_have += n,
                Err(error) if crate::proxy::is_timeout(&error) => match self.handshake {
                    Some(until) if std::time::Instant::now() < until => {}
                    // The head's clock is spent: a hard end, so `read_exact` stops retrying.
                    Some(_) => return Ok(false),
                    // A lane's poll: the partial head stays in hand for the next read.
                    None if crate::proxy::relay_step_owns_poll() => return Err(error),
                    None => std::thread::sleep(crate::budgets::RELAY_POLL),
                },
                Err(_) => return Ok(false),
            }
        }
        Ok(true)
    }

    /// True when every byte past the last decoded message belongs to a whole message: `END_STREAM` over a partial head or a short body is a refusal, not a delivery of a truncated payload.
    fn whole(&self) -> bool {
        let mut at = self.msg_end;
        loop {
            let live = &self.msg[at..];
            if live.len() < 5 {
                return live.is_empty();
            }
            if live[0] != 0 {
                return false;
            }
            let len = u32::from_be_bytes(live[1..5].try_into().unwrap()) as usize;
            if len > MSG_CAP || live.len() < 5 + len {
                return false;
            }
            if hunk_decode(&live[5..5 + len]).is_none() {
                return false;
            }
            at += 5 + len;
        }
    }

    /// Messages are decoded where they landed: the payload stays in `msg` and `msg_at`..`pay_end` is what the caller has not taken, so nothing is copied to wait for it.
    fn decode(&mut self) -> Option<()> {
        loop {
            if self.msg_at < self.pay_end {
                return Some(());
            }
            if self.msg_at < self.msg_end {
                if self.method == Method::MultiHunk {
                    self.next_element()?;
                    continue;
                }
                self.msg_at = self.msg_end;
            }
            let live = &self.msg[self.msg_at..];
            if live.len() < 5 {
                return Some(());
            }
            if live[0] != 0 {
                return None;
            }
            let len = u32::from_be_bytes(live[1..5].try_into().unwrap()) as usize;
            if len > MSG_CAP {
                return None;
            }
            if live.len() < 5 + len {
                return Some(());
            }
            let body = self.msg_at + 5;
            self.msg_end = body + len;
            if self.method == Method::MultiHunk {
                self.msg_at = body;
                self.next_element()?;
                continue;
            }
            let (at, payload) = hunk_decode(&live[5..5 + len])?;
            self.msg_at = body + at;
            self.pay_end = self.msg_at + payload.len();
        }
    }

    /// The next element of the `MultiHunk` the cursor sits in: `repeated bytes` means an element's own bytes end exactly where the next element's key begins, so a batch is handed out where it lies and the cursor only leaves the message when it has no element left.
    fn next_element(&mut self) -> Option<()> {
        let end = self.msg_end;
        let mut at = self.msg_at;
        loop {
            if at >= end {
                self.msg_at = end;
                return Some(());
            }
            let key = read_varint(&self.msg, &mut at)?;
            let field = (key >> 3) as u32;
            let wire = (key & 0x07) as u8;
            if field == 0 {
                return None;
            }
            if field != 1 || wire != 2 {
                skip_field(&self.msg, &mut at, wire)?;
                continue;
            }
            let len = usize::try_from(read_varint(&self.msg, &mut at)?).ok()?;
            let start = at;
            let stop = start.checked_add(len)?;
            if stop > end {
                return None;
            }
            self.msg_at = start;
            self.pay_end = stop;
            return Some(());
        }
    }

    fn pump(&mut self) -> std::io::Result<Option<()>> {
        let (len, kind, flags, id, from) = if let Some(pending) = self.pending {
            (
                pending.len,
                pending.kind,
                pending.flags,
                pending.id,
                pending.from,
            )
        } else {
            if !self.read_frame_head()? {
                return Ok(None);
            }
            let head = self.frame_head;
            self.frame_have = 0;
            let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
            if len > FRAME_CAP {
                return Ok(None);
            }
            let kind = head[3];
            let flags = head[4];
            let id = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7FFF_FFFF;
            let from = if kind == T_DATA { self.begin_data() } else { 0 };
            self.pending = Some(Pending {
                len,
                kind,
                flags,
                id,
                from,
                filled: 0,
            });
            (len, kind, flags, id, from)
        };
        let mut filled = self.pending.map_or(0, |pending| pending.filled);
        let outcome = if kind == T_DATA {
            self.fill_msg(from, len, &mut filled)
        } else {
            self.fill_frame(len, &mut filled)
        };
        // A lane's poll hands back what arrived, so the resume starts where this read stopped.
        if let Some(pending) = self.pending.as_mut() {
            pending.filled = filled;
        }
        if !outcome? {
            return Ok(None);
        }
        self.pending = None;
        Ok(if kind == T_DATA {
            self.finish_data(id, flags, from, len)
        } else {
            self.dispatch(kind, flags, id, len)
        })
    }

    /// After a normal `END_STREAM` the read half is done, but the connection still carries the control frames the write half needs: pump them, and let the lane's poll timeout hand the turn back.
    fn pump_after_end(&mut self) -> std::io::Result<usize> {
        for _ in 0..POST_END_BURST {
            match self.pump() {
                Ok(Some(())) => {}
                Ok(None) => return Ok(0),
                Err(error) => return Err(error),
            }
        }
        // A peer that keeps the control frames coming must not pin this read: the timeout hands the lane back so it can close the target write half, and the next turn pumps the rest.
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }

    /// One complete frame that is not a body: the scratch holds its bytes and the match is the same one `pump` ran inline.
    fn dispatch(&mut self, kind: u8, flags: u8, id: u32, len: usize) -> Option<()> {
        let mut frame = std::mem::take(&mut self.frame);
        frame.truncate(len);
        let out = match kind {
            T_HEADERS => self.head_block(id, flags, &frame),
            T_CONT => self.continue_block(id, flags, &frame),
            T_RST => {
                if id == self.stream {
                    self.eof = true;
                }
                Some(())
            }
            T_SETTINGS => {
                if id == 0 {
                    self.settings(flags, &frame);
                }
                Some(())
            }
            T_PING => {
                if id == 0 {
                    self.ping(flags, &frame);
                }
                Some(())
            }
            T_WINDOW => {
                self.window(id, frame.get(..4).unwrap_or(&[]));
                Some(())
            }
            // A GOAWAY still carries this stream's body; END_STREAM ends it.
            _ => Some(()),
        };
        self.frame = frame;
        out
    }

    fn head_block(&mut self, id: u32, flags: u8, body: &[u8]) -> Option<()> {
        let mut body = body;
        if flags & F_PADDED != 0 {
            let pad = usize::from(*body.first()?);
            if pad + 1 > body.len() {
                return None;
            }
            body = &body[1..body.len() - pad];
        }
        if flags & F_PRIORITY != 0 {
            if body.len() < 5 {
                return None;
            }
            body = &body[5..];
        }
        if flags & F_END_HEADERS != 0 {
            self.head_flags = 0;
            return self.headers(id, flags, body);
        }
        if self.head.len() + body.len() > HEAD_CAP {
            return None;
        }
        self.head.extend_from_slice(body);
        self.head_id = id;
        self.head_flags = flags;
        Some(())
    }

    fn continue_block(&mut self, id: u32, flags: u8, body: &[u8]) -> Option<()> {
        if id != self.head_id || self.head.len() + body.len() > HEAD_CAP {
            return None;
        }
        if flags & F_END_HEADERS != 0 {
            let mut block = std::mem::take(&mut self.head);
            block.extend_from_slice(body);
            let flags = flags | (self.head_flags & F_END);
            self.head_flags = 0;
            return self.headers(id, flags, &block);
        }
        self.head.extend_from_slice(body);
        Some(())
    }

    fn window(&self, id: u32, body: &[u8]) {
        if body.len() != 4 {
            return;
        }
        let inc = u64::from(u32::from_be_bytes(body[..4].try_into().unwrap()) & 0x7FFF_FFFF);
        if inc == 0 {
            return;
        }
        let mut send = self
            .shared
            .send
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if id == 0 {
            send.conn = send.conn.saturating_add(inc).min(WINDOW_MAX);
        } else if id == self.stream {
            send.stream = send.stream.saturating_add(inc).min(WINDOW_MAX);
        } else {
            return;
        }
        self.shared.wake.notify_all();
    }
}

impl<R: Read> GrpcReader<R> {
    /// Settles on the payload in hand, on the end, or on the lane's timeout: the range the caller may
    /// take from the message buffer, so a window hands it on where it lies instead of staging it.
    fn ready(&mut self) -> std::io::Result<Option<(usize, usize)>> {
        loop {
            if self.msg_at < self.pay_end {
                return Ok(Some((self.msg_at, self.pay_end)));
            }
            // The next message may already be in the buffer behind the one just taken, and reading the socket first would block on it; that holds at END_STREAM too — the flag ends the frames, not the bytes.
            if self.decode().is_none() {
                self.eof = true;
                if self.remote_end && self.poll {
                    self.pump_after_end()?;
                }
                return Ok(None);
            }
            if self.msg_at < self.pay_end {
                continue;
            }
            if self.eof {
                if self.remote_end && self.poll {
                    self.pump_after_end()?;
                }
                return Ok(None);
            }
            if self.pump()?.is_none() {
                self.eof = true;
                if self.remote_end && self.poll {
                    self.pump_after_end()?;
                }
                return Ok(None);
            }
        }
    }
}

impl<R: Read> Read for GrpcReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let Some((at, end)) = self.ready()? else {
            return Ok(0);
        };
        let n = (end - at).min(buf.len());
        buf[..n].copy_from_slice(&self.msg[at..at + n]);
        self.msg_at = at + n;
        Ok(n)
    }
}

impl<R: Read> crate::proxy::WindowRead for GrpcReader<R> {
    /// The payload the one message buffer already holds, handed on where it lies: the relay writes it
    /// to the peer socket as the reader's own slices, so no relay buffer stages it a second time.
    fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
        let Some((at, end)) = self.ready()? else {
            return Ok(crate::proxy::Window::one(&[]));
        };
        self.msg_at = end;
        Ok(crate::proxy::Window::one(&self.msg[at..end]))
    }
}

/// The frames one write carries: a promoted relay read is `64 KiB`, five DATA frames, one whole
/// Hunk in each, so one read of the relay's own buffer is one batch and one socket call. A wider
/// caller flushes mid-write when the batch fills; a narrower one pays the call it was asked for and
/// no other.
const FRAMES_PER_WRITE: usize = 8;

/// A gathered frame's own bytes: its nine-byte head and the envelope prefix it carries, at most the
/// `16` bytes `frame_prefix` can fill.
const SLOT: usize = 9 + 16;

/// The frame that has not been added to a batch yet, and the part slot of a list still empty.
const NO_FRAME: &[u8] = &[];

/// A caller write's frames held apart rather than staged together: every head and envelope prefix in
/// a slot of its own, every payload still the caller's own slice, so one flush is one vectored write
/// whose body parts point into the buffer the relay handed over.
struct Gather<'a> {
    slots: [[u8; SLOT]; FRAMES_PER_WRITE],
    held: [(&'a [u8], usize); FRAMES_PER_WRITE],
    used: usize,
    /// The window this batch took and the transport has not confirmed: a refused flush gives it back.
    credit: u64,
}

impl<'a> Gather<'a> {
    fn new() -> Self {
        Self {
            slots: [[0u8; SLOT]; FRAMES_PER_WRITE],
            held: [(NO_FRAME, 0); FRAMES_PER_WRITE],
            used: 0,
            credit: 0,
        }
    }

    fn full(&self) -> bool {
        self.used == FRAMES_PER_WRITE
    }

    /// One DATA frame into the batch: its head built where it will be read from, the envelope bytes it
    /// carries copied in beside it, and its payload left as the caller's slice.
    fn add(&mut self, id: u32, flags: u8, prefix: &[u8], payload: &'a [u8]) {
        let at = self.used;
        self.used += 1;
        let load = prefix.len() + payload.len();
        self.credit += load as u64;
        let head = frame_head(load, T_DATA, flags, id);
        self.slots[at][..9].copy_from_slice(&head);
        self.slots[at][9..9 + prefix.len()].copy_from_slice(prefix);
        self.held[at] = (payload, prefix.len());
    }

    /// The batch as one offer, in the order the frames go out: a head slot and then the payload run
    /// it opens, for every frame held. A refused batch keeps its frames and gives its window back, so
    /// the caller's retry re-takes exactly what it took; an accepted batch is emptied.
    fn flush(&mut self, shared: &Arc<Shared>) -> Accepted {
        if self.used == 0 {
            return Accepted::All;
        }
        let mut parts: [&[u8]; 2 * FRAMES_PER_WRITE] = [NO_FRAME; 2 * FRAMES_PER_WRITE];
        let mut pieces = 0;
        for (slot, held) in self.slots[..self.used]
            .iter()
            .zip(self.held[..self.used].iter().copied())
        {
            let (payload, prefix) = held;
            parts[pieces] = &slot[..9 + prefix];
            pieces += 1;
            if !payload.is_empty() {
                parts[pieces] = payload;
                pieces += 1;
            }
        }
        let took = match shared.stream.lock() {
            Ok(mut stream) => stream.offer_slices(&parts[..pieces]),
            Err(_) => Accepted::Lost,
        };
        match took {
            Accepted::All => {
                self.used = 0;
                self.credit = 0;
                Accepted::All
            }
            Accepted::Full => {
                refund(shared, self.credit);
                Accepted::Full
            }
            Accepted::Lost => Accepted::Lost,
        }
    }

    /// Waits out a paced tail for the blocking writer: the framed relay never takes this path, so the
    /// wait costs a lane only when a caller asked for every byte before it returned.
    fn settle_blocking(shared: &Shared) -> bool {
        let deadline = Instant::now() + crate::budgets::relay_stall();
        loop {
            let settled = match shared.stream.lock() {
                Ok(mut stream) => stream.settle(),
                Err(_) => Settle::Lost,
            };
            match settled {
                Settle::Clear => return true,
                Settle::Lost => return false,
                Settle::Parked => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(crate::budgets::RELAY_POLL);
                }
            }
        }
    }

    /// The same offer for a caller that may wait: a refused batch drains the paced tail and takes
    /// its window again before the next try.
    fn flush_blocking(&mut self, shared: &Arc<Shared>) -> bool {
        let deadline = Instant::now() + crate::budgets::relay_stall();
        loop {
            match self.flush(shared) {
                Accepted::All => return true,
                Accepted::Lost => return false,
                Accepted::Full => {
                    if Instant::now() >= deadline || !Self::settle_blocking(shared) {
                        return false;
                    }
                    if !take_window(shared, self.credit, true) {
                        return false;
                    }
                    if let Ok(stream) = shared.stream.lock() {
                        stream.wait_room(crate::budgets::RELAY_POLL);
                    }
                }
            }
        }
    }
}

impl GrpcWriter {
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        let max = self.max_frame();
        // Four frames of the 16 KiB the peer advertises are one byte over the default 65_535-byte stream window, so the fourth waits for a credit; a body one byte under the frame fits all four.
        let payload = message_payload(max.saturating_sub(1)).max(1);
        if self.multi {
            return self.send_multi(data, payload);
        }
        let mut batch = Gather::new();
        for piece in data.chunks(payload) {
            if !self.message(piece, max, false, &mut batch) {
                return false;
            }
        }
        batch.flush_blocking(&self.shared)
    }

    /// The blocking writer's `MultiHunk` path: each group is sized from the room the transport has
    /// when it is formed, and a transport with no usable room is waited out rather than frozen into
    /// a one-byte element for the rest of the write.
    fn send_multi(&self, data: &[u8], element: usize) -> bool {
        let mut batch = Gather::new();
        let mut lengths = [0usize; FRAMES_PER_WRITE];
        let mut at = 0usize;
        let mut target = 0usize;
        let deadline = Instant::now() + crate::budgets::relay_stall();
        while at < data.len() {
            let cap = self.multi_cap();
            if cap < 8 {
                if Instant::now() >= deadline {
                    return false;
                }
                if !batch.flush_blocking(&self.shared) {
                    return false;
                }
                self.wait_for_room(crate::budgets::RELAY_POLL);
                continue;
            }
            let fits = multi_payload(cap);
            if target > 0 && fits < target && data.len() - at > fits {
                if !batch.flush_blocking(&self.shared) {
                    return false;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                self.wait_for_room(crate::budgets::RELAY_POLL);
                continue;
            }
            let element = element.min(fits).max(1);
            target = target.max(element);
            let (payload_len, count) = multi_group(data, at, element, cap, &mut lengths);
            if !self.send_multi_group(&data[at..at + payload_len], &lengths[..count], &mut batch) {
                return false;
            }
            at += payload_len;
        }
        batch.flush_blocking(&self.shared)
    }

    /// Adds one `MultiHunk` message to a blocking batch: its window is taken whole before its first
    /// frame, and a batch the transport refuses is drained and paid for again by `flush_blocking`.
    fn send_multi_group<'a>(
        &self,
        payload: &'a [u8],
        lengths: &[usize],
        batch: &mut Gather<'a>,
    ) -> bool {
        let inner: usize = lengths
            .iter()
            .map(|&len| 1 + varint_len(len as u64) + len)
            .sum();
        let total = 5 + inner;
        if batch.used + lengths.len() > FRAMES_PER_WRITE && !batch.flush_blocking(&self.shared) {
            return false;
        }
        if !self.credit(batch, total as u64) {
            return false;
        }
        let mut prefix = [0u8; 16];
        let mut offset = 0;
        for (at, &len) in lengths.iter().enumerate() {
            let mut end = 0;
            if at == 0 {
                prefix[0] = 0;
                prefix[1..5].copy_from_slice(&(inner as u32).to_be_bytes());
                end = 5;
            }
            prefix[end] = 0x0A;
            end += 1;
            end += write_varint(&mut prefix[end..], len as u64);
            batch.add(
                self.stream,
                0,
                &prefix[..end],
                &payload[offset..offset + len],
            );
            offset += len;
        }
        true
    }

    /// The same frames as `send`, but a window the peer has not granted parks the bytes instead of
    /// holding the worker the lane that reads the credit needs. A message is the unit a window
    /// pays for, so it is taken whole: a half-sent one cannot be offered again without duplicating
    /// the half the peer already has.
    fn try_send(&self, data: &[u8]) -> crate::proxy::Push {
        if self.shared.dead.load(Ordering::SeqCst) {
            return crate::proxy::Push::Lost;
        }
        let max = self.max_frame().max(1);
        // A frame width below two cannot keep one message in one batch, so a peer that asks for it gets the blocking writer.
        if max < 2 {
            return if self.send(data) {
                crate::proxy::Push::Took(data.len())
            } else {
                crate::proxy::Push::Lost
            };
        }
        let payload = message_payload(max.saturating_sub(1)).max(1);
        if self.multi {
            return self.try_send_multi(data, payload);
        }
        let mut batch = Gather::new();
        let mut flushed = 0usize;
        let mut held = 0usize;
        let mut room = self.send_room();
        for piece in data.chunks(payload) {
            let mut prefix = [0u8; 16];
            let plen = frame_prefix(piece.len(), &mut prefix);
            let total = plen + piece.len();
            let frames = total.div_ceil(max);
            if batch.used + frames > FRAMES_PER_WRITE
                || (batch.used > 0 && batch.credit + total as u64 > room)
            {
                if let Some(stop) =
                    Self::flush_held(&self.shared, &mut batch, &mut flushed, &mut held)
                {
                    return stop;
                }
                room = self.send_room();
            }
            if !take_window(&self.shared, total as u64, false) {
                if let Some(stop) =
                    Self::flush_held(&self.shared, &mut batch, &mut flushed, &mut held)
                {
                    return stop;
                }
                return Self::took_or_parked(flushed);
            }
            if total <= max {
                batch.add(self.stream, 0, &prefix[..plen], piece);
            } else {
                let mut at = 0;
                while at < total {
                    let n = (total - at).min(max);
                    if at + n <= plen {
                        batch.add(self.stream, 0, &prefix[at..at + n], &[]);
                    } else if at >= plen {
                        batch.add(self.stream, 0, &[], &piece[at - plen..at - plen + n]);
                    } else {
                        batch.add(self.stream, 0, &prefix[at..plen], &piece[..n - (plen - at)]);
                    }
                    at += n;
                }
            }
            held += piece.len();
        }
        match batch.flush(&self.shared) {
            Accepted::All => Self::took_or_parked(flushed + held),
            Accepted::Full => Self::took_or_parked(flushed),
            Accepted::Lost => crate::proxy::Push::Lost,
        }
    }

    /// The most bytes one relay read should hand this writer: a multi-mode write reads no more than
    /// the credit the peer has left, so the read leaves as one `MultiHunk` the peer can pay for
    /// rather than one it parks on. The envelope and tags of a four-element `64 KiB` read cost at
    /// most `64` bytes; a read that fits one element costs at most `16`.
    pub(crate) fn read_window(&self) -> Option<usize> {
        if !self.multi {
            return None;
        }
        let init = self
            .shared
            .init
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let send = self
            .shared
            .send
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let available = (*init).min(send.conn).min(send.stream);
        let margin = if available > 16_375 { 64 } else { 16 };
        let limit = usize::try_from(available).unwrap_or(usize::MAX);
        Some(
            limit
                .saturating_sub(margin)
                .clamp(1, crate::proxy::RELAY_BUFFER),
        )
    }

    /// The same offer as `try_send`, but a `MultiHunk` batch: consecutive elements are gathered
    /// into one gRPC message, and a message is never split across a retry — a group is only added
    /// to a batch that has room for all its frames, and the window for the whole message is taken
    /// before its first frame.
    fn try_send_multi(&self, data: &[u8], element: usize) -> crate::proxy::Push {
        let mut batch = Gather::new();
        let mut flushed = 0usize;
        let mut held = 0usize;
        let mut lengths = [0usize; FRAMES_PER_WRITE];
        let mut at = 0usize;
        let mut target = 0usize;
        while at < data.len() {
            let cap = self.multi_cap();
            if cap < 8 {
                if let Some(stop) =
                    Self::flush_held(&self.shared, &mut batch, &mut flushed, &mut held)
                {
                    return stop;
                }
                return Self::took_or_parked(flushed);
            }
            let fits = multi_payload(cap);
            if target > 0 && fits < target && data.len() - at > fits {
                if let Some(stop) =
                    Self::flush_held(&self.shared, &mut batch, &mut flushed, &mut held)
                {
                    return stop;
                }
                return Self::took_or_parked(flushed);
            }
            let element = element.min(fits).max(1);
            target = target.max(element);
            let (payload_len, count) = multi_group(data, at, element, cap, &mut lengths);
            if let Some(stop) = self.try_multi_group(
                &data[at..at + payload_len],
                &lengths[..count],
                &mut batch,
                &mut flushed,
                &mut held,
            ) {
                return stop;
            }
            at += payload_len;
        }
        match batch.flush(&self.shared) {
            Accepted::All => Self::took_or_parked(flushed + held),
            Accepted::Full => Self::took_or_parked(flushed),
            Accepted::Lost => crate::proxy::Push::Lost,
        }
    }

    /// The largest `MultiHunk` the peer can pay for in one take right now: its starting stream
    /// window, the connection's own 65_535-byte opening window, and the transport's live room.
    fn multi_cap(&self) -> u64 {
        let room = self.send_room();
        let init = *self
            .shared
            .init
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let send = self
            .shared
            .send
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        init.min(65_535).min(send.conn).min(send.stream).min(room)
    }

    /// Adds one `MultiHunk` message to the batch, flushing first when the batch cannot hold all its
    /// frames; the window for the whole message is taken before its first frame, so a message is
    /// never half-sent and retried.
    fn try_multi_group<'a>(
        &self,
        payload: &'a [u8],
        lengths: &[usize],
        batch: &mut Gather<'a>,
        flushed: &mut usize,
        held: &mut usize,
    ) -> Option<crate::proxy::Push> {
        let inner: usize = lengths
            .iter()
            .map(|&len| 1 + varint_len(len as u64) + len)
            .sum();
        let total = 5 + inner;
        if batch.used + lengths.len() > FRAMES_PER_WRITE
            || (batch.used > 0 && batch.credit + total as u64 > self.send_room())
        {
            if let Some(stop) = Self::flush_held(&self.shared, batch, flushed, held) {
                return Some(stop);
            }
        }
        if !take_window(&self.shared, total as u64, false) {
            if let Some(stop) = Self::flush_held(&self.shared, batch, flushed, held) {
                return Some(stop);
            }
            return Some(Self::took_or_parked(*flushed));
        }
        let mut prefix = [0u8; 16];
        let mut offset = 0;
        for (at, &len) in lengths.iter().enumerate() {
            let mut end = 0;
            if at == 0 {
                prefix[0] = 0;
                prefix[1..5].copy_from_slice(&(inner as u32).to_be_bytes());
                end = 5;
            }
            prefix[end] = 0x0A;
            end += 1;
            end += write_varint(&mut prefix[end..], len as u64);
            batch.add(
                self.stream,
                0,
                &prefix[..end],
                &payload[offset..offset + len],
            );
            offset += len;
        }
        *held += payload.len();
        None
    }

    fn flush_held(
        shared: &Arc<Shared>,
        batch: &mut Gather<'_>,
        flushed: &mut usize,
        held: &mut usize,
    ) -> Option<crate::proxy::Push> {
        match batch.flush(shared) {
            Accepted::All => {
                *flushed += *held;
                *held = 0;
                None
            }
            Accepted::Full => Some(Self::took_or_parked(*flushed)),
            Accepted::Lost => Some(crate::proxy::Push::Lost),
        }
    }

    fn took_or_parked(sent: usize) -> crate::proxy::Push {
        if sent == 0 {
            crate::proxy::Push::Parked
        } else {
            crate::proxy::Push::Took(sent)
        }
    }

    pub(crate) fn settle(&self) -> Settle {
        match self.shared.stream.lock() {
            Ok(mut stream) => stream.settle(),
            Err(_) => Settle::Lost,
        }
    }

    /// A parked relay turn ends on the peer's `WINDOW_UPDATE`; a wake that raced the park leaves the
    /// full turn, which is the poll it would have paid anyway.
    pub(crate) fn wait_for_room(&self, turn: Duration) {
        let send = self
            .shared
            .send
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if send.unlimited {
            drop(send);
            if let Ok(stream) = self.shared.stream.lock() {
                stream.wait_room(turn);
            }
            return;
        }
        let _ = self.shared.wake.wait_timeout(send, turn);
    }

    pub(crate) fn upload_done(&self) {
        let _gate = self
            .shared
            .upload_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.shared.dead.load(Ordering::SeqCst)
            || self.shared.ended.load(Ordering::SeqCst)
            || self.shared.upload_ended.load(Ordering::SeqCst)
        {
            return;
        }
        self.shared.upload_ended.store(true, Ordering::SeqCst);
        let mut batch = Gather::new();
        if !self.message(&[], self.max_frame(), true, &mut batch)
            || !batch.flush_blocking(&self.shared)
        {
            self.shared.upload_ended.store(false, Ordering::SeqCst);
            return;
        }
        let _ = Gather::settle_blocking(&self.shared);
    }

    pub(crate) fn close(&self) {
        let _gate = self
            .shared
            .upload_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.shared.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        if self.shared.upload_ended.load(Ordering::SeqCst) {
            return;
        }
        let mut batch = Gather::new();
        if !self.message(&[], self.max_frame(), true, &mut batch)
            || !batch.flush_blocking(&self.shared)
        {
            self.shared.ended.store(false, Ordering::SeqCst);
            return;
        }
        self.shared.upload_ended.store(true, Ordering::SeqCst);
        let _ = Gather::settle_blocking(&self.shared);
    }

    fn max_frame(&self) -> usize {
        *self
            .shared
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// What the transport's window takes now: a batch is cut to this so a lane's offer is the batch
    /// that fits, and one that still does not parks instead of holding a worker.
    fn send_room(&self) -> u64 {
        if !self.shared.muxed {
            return u64::MAX;
        }
        self.shared.stream.lock().map_or(0, |stream| stream.room())
    }

    /// Window for one more frame, or the batch out to the peer first: a credit the peer has not given
    /// cannot be waited for while its own bytes sit unwritten.
    fn credit(&self, batch: &mut Gather<'_>, need: u64) -> bool {
        if take_window(&self.shared, need, false) {
            return true;
        }
        if !batch.flush_blocking(&self.shared) {
            return false;
        }
        take_window(&self.shared, need, true)
    }

    /// Writes one message, splitting it only when it exceeds `max` bytes.
    fn message<'a>(&self, data: &'a [u8], max: usize, end: bool, batch: &mut Gather<'a>) -> bool {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(data.len(), &mut prefix);
        let total = plen + data.len();
        let max = max.max(1);
        // The empty end marker is retried by `close` if this wait fails: take its whole window first, so a retry never replays a prefix already on the wire.
        let reserved = end && data.is_empty();
        if reserved && !self.credit(batch, total as u64) {
            return false;
        }
        if total <= max {
            if !reserved && !self.credit(batch, total as u64) {
                return false;
            }
            if batch.full() && !batch.flush_blocking(&self.shared) {
                return false;
            }
            batch.add(
                self.stream,
                if end { F_END } else { 0 },
                &prefix[..plen],
                data,
            );
            return true;
        }
        let mut at = 0;
        while at < total {
            let n = (total - at).min(max);
            let last = at + n == total;
            if !reserved && !self.credit(batch, n as u64) {
                return false;
            }
            if batch.full() && !batch.flush_blocking(&self.shared) {
                return false;
            }
            let flags = if last && end { F_END } else { 0 };
            if at + n <= plen {
                batch.add(self.stream, flags, &prefix[at..at + n], &[]);
            } else if at >= plen {
                batch.add(self.stream, flags, &[], &data[at - plen..at - plen + n]);
            } else {
                batch.add(
                    self.stream,
                    flags,
                    &prefix[at..plen],
                    &data[..n - (plen - at)],
                );
            }
            at += n;
        }
        true
    }
}

impl std::io::Write for GrpcWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.send(data) {
            Ok(data.len())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The most payload whose gRPC envelope and `Hunk` tag still fit one DATA frame, so a message is
/// never cut across two: the envelope's varint grows with the payload, so the fixed point is
/// reached from above in a couple of steps.
fn message_payload(max_frame: usize) -> usize {
    let max = max_frame.min(FRAME_CAP);
    let mut payload = max.saturating_sub(6);
    loop {
        let plen = 6 + varint_len(payload as u64);
        let next = max.saturating_sub(plen);
        if next >= payload {
            return payload;
        }
        payload = next;
    }
}

/// The largest `MultiHunk` element whose complete envelope — the gRPC prefix, the field tag and
/// its length — fits `cap` bytes, so one element is never split for a margin it does not owe.
fn multi_payload(cap: u64) -> usize {
    let max = usize::try_from(cap).unwrap_or(usize::MAX);
    if max < 8 {
        return 1;
    }
    let mut payload = max - 6;
    loop {
        let total = 6 + varint_len(payload as u64) + payload;
        if total <= max {
            return payload;
        }
        payload = payload.saturating_sub(1);
        if payload == 0 {
            return 1;
        }
    }
}

/// One `MultiHunk` group from `data[at..]`: whole `element`-sized pieces until the frame count or
/// the actual envelope cost would cross `cap`, so only a group that cannot fit is split.
fn multi_group(
    data: &[u8],
    at: usize,
    element: usize,
    cap: u64,
    lengths: &mut [usize; FRAMES_PER_WRITE],
) -> (usize, usize) {
    let mut end = at;
    let mut count = 0usize;
    let mut payload_len = 0usize;
    let mut prefix_len = 5usize;
    while end < data.len() && count < FRAMES_PER_WRITE {
        let len = element.min(data.len() - end);
        let add = 1 + varint_len(len as u64);
        let total = prefix_len + add + payload_len + len;
        if count > 0 && total as u64 > cap {
            break;
        }
        lengths[count] = len;
        count += 1;
        payload_len += len;
        prefix_len += add;
        end += len;
    }
    (payload_len, count)
}

/// The number of bytes a protobuf varint takes for `value`: seven bits per byte, never fewer than one.
fn varint_len(value: u64) -> usize {
    (64 - value.leading_zeros() as usize).div_ceil(7).max(1)
}

/// Writes the envelope and `Hunk` tag for `data_len` into `out`, returning the prefix length.
#[inline]
fn frame_prefix(data_len: usize, out: &mut [u8; 16]) -> usize {
    let (at, inner) = if data_len < 0x80 {
        out[6] = data_len as u8;
        (7, (2 + data_len) as u32)
    } else if data_len < 0x4000 {
        out[6] = (data_len as u8 & 0x7F) | 0x80;
        out[7] = (data_len >> 7) as u8;
        (8, (3 + data_len) as u32)
    } else {
        let mut value = data_len as u64;
        let mut at = 6;
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out[at] = byte;
                at += 1;
                break;
            }
            out[at] = byte | 0x80;
            at += 1;
        }
        (at, (at - 5 + data_len) as u32)
    };
    out[0] = 0;
    out[1..5].copy_from_slice(&inner.to_be_bytes());
    out[5] = 0x0A;
    at
}

/// Writes `value` as a protobuf varint into `out`, returning its length.
fn write_varint(out: &mut [u8], mut value: u64) -> usize {
    let mut at = 0;
    while value >= 0x80 {
        out[at] = (value as u8 & 0x7F) | 0x80;
        value >>= 7;
        at += 1;
    }
    out[at] = value as u8;
    at + 1
}

#[cfg(test)]
fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 & 0x7F | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Reads one protobuf varint at `at`, advancing the cursor.
#[inline]
fn read_varint(msg: &[u8], at: &mut usize) -> Option<u64> {
    let first = *msg.get(*at)?;
    *at += 1;
    if first & 0x80 == 0 {
        return Some(u64::from(first));
    }
    let mut value = u64::from(first & 0x7F);
    for shift in (7..70).step_by(7) {
        let byte = *msg.get(*at)?;
        *at += 1;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The `Data` field of a `Hunk`, and where it sits inside the message: the reader hands over the bytes where they lie, so the offset is part of the answer rather than something the caller finds again.
#[inline]
fn hunk_decode(msg: &[u8]) -> Option<(usize, &[u8])> {
    let mut at = 0;
    let mut data: &[u8] = &[];
    let mut off = 0usize;
    while at < msg.len() {
        let key = read_varint(msg, &mut at)?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return None;
        }
        if field == 1 {
            if wire != 2 {
                return None;
            }
            let len = usize::try_from(read_varint(msg, &mut at)?).ok()?;
            let end = at.checked_add(len)?;
            data = msg.get(at..end)?;
            off = at;
            at = end;
        } else {
            skip_field(msg, &mut at, wire)?;
        }
    }
    Some((off, data))
}

fn skip_field(msg: &[u8], at: &mut usize, wire: u8) -> Option<()> {
    let fixed = match wire {
        0 => {
            read_varint(msg, at)?;
            return Some(());
        }
        1 => 8,
        2 => usize::try_from(read_varint(msg, at)?).ok()?,
        5 => 4,
        _ => return None,
    };
    *at = at.checked_add(fixed)?;
    if *at > msg.len() {
        return None;
    }
    Some(())
}

/// A frame sink that drops what it is given: the multiplexed reader's credits belong to the demux,
/// which already granted the peer the window its body arrived under.
struct NullSink;

impl Write for NullSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl FrameWrite for NullSink {
    fn write_slices(&mut self, _parts: &[&[u8]]) -> bool {
        true
    }
}

/// Turns the already framed gRPC DATA frames back into bodies for the shared HTTP/2 sender, which
/// owns framing and flow control on the multiplexed connection.
struct MuxSink {
    out: crate::xhttp_h2::H2StreamOut,
}

impl Write for MuxSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One batch of framed DATA bodies apart from their frame heads: each group is one frame's parts.
struct Batched<'a> {
    groups: [[&'a [u8]; 2]; 16],
    sizes: [usize; 16],
    count: usize,
    end: bool,
}

impl MuxSink {
    /// The framed DATA bodies apart from the frame heads, and whether the batch carries `END_STREAM`.
    fn split<'a>(parts: &[&'a [u8]]) -> Option<Batched<'a>> {
        let mut batched = Batched {
            groups: [[&[]; 2]; 16],
            sizes: [0usize; 16],
            count: 0,
            end: false,
        };
        let mut at = 0;
        while at < parts.len() {
            let frame = parts[at];
            if frame.len() < 9 {
                return None;
            }
            let len =
                usize::from(frame[0]) << 16 | usize::from(frame[1]) << 8 | usize::from(frame[2]);
            let kind = frame[3];
            let flags = frame[4];
            let prefix = &frame[9..];
            let body = if prefix.len() < len {
                at += 2;
                parts.get(at - 1).copied().unwrap_or(&[])
            } else {
                at += 1;
                &[]
            };
            if kind == T_DATA && batched.count < batched.groups.len() {
                let mut size = 0;
                if !prefix.is_empty() {
                    batched.groups[batched.count][size] = prefix;
                    size += 1;
                }
                if !body.is_empty() {
                    batched.groups[batched.count][size] = body;
                    size += 1;
                }
                if size > 0 {
                    batched.sizes[batched.count] = size;
                    batched.count += 1;
                }
            }
            if flags & F_END != 0 {
                batched.end = true;
            }
        }
        Some(batched)
    }
}

impl Batched<'_> {
    fn slices(&self) -> [&[&[u8]]; 16] {
        let mut slices: [&[&[u8]]; 16] = [&[]; 16];
        for (at, slice) in slices.iter_mut().enumerate().take(self.count) {
            *slice = &self.groups[at][..self.sizes[at]];
        }
        slices
    }
}

impl FrameWrite for MuxSink {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        let Some(batched) = Self::split(parts) else {
            return false;
        };
        let slices = batched.slices();
        if batched.count > 0 && !self.out.batch_parts(&slices[..batched.count]) {
            return false;
        }
        if batched.end {
            self.out.end();
        }
        true
    }

    fn offer_slices(&mut self, parts: &[&[u8]]) -> crate::proxy::Accepted {
        use crate::proxy::Accepted;
        let Some(batched) = Self::split(parts) else {
            return Accepted::Lost;
        };
        let slices = batched.slices();
        match self.out.try_batch_parts(&slices[..batched.count]) {
            Some(true) => {
                if batched.end {
                    self.out.end();
                }
                Accepted::All
            }
            Some(false) => Accepted::Lost,
            None => Accepted::Full,
        }
    }

    fn room(&self) -> u64 {
        self.out.room()
    }

    fn wait_room(&self, turn: Duration) {
        self.out.wait_room(turn);
    }

    fn settle(&mut self) -> Settle {
        self.out.settle()
    }
}

/// The request body as the DATA frames the shared parser expects, built from the demux's de-framed
/// bytes: one synthetic frame per read, and one empty `END_STREAM` frame when the body ends.
pub(crate) struct BodyFrames {
    body: crate::xhttp_h2::H2StreamReader,
    id: u32,
    buf: Vec<u8>,
    at: usize,
    len: usize,
    head: [u8; 9],
    head_at: usize,
    ended: bool,
}

impl BodyFrames {
    /// The request is given up with its body still open: the stream's table entry and the chunks
    /// already queued have to go, or a peer that never ends the request holds both for the
    /// connection's life.
    pub(crate) fn abort(&self) {
        self.body.abort();
    }

    pub(crate) fn reset_handle(&self) -> impl FnOnce() + Send + 'static {
        self.body.reset_handle()
    }

    fn new(body: crate::xhttp_h2::H2StreamReader, id: u32) -> Self {
        Self {
            body,
            id,
            buf: vec![0; 16 * 1024],
            at: 0,
            len: 0,
            head: [0; 9],
            head_at: 9,
            ended: false,
        }
    }
}

impl Read for BodyFrames {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.head_at < 9 {
                let n = (9 - self.head_at).min(out.len());
                out[..n].copy_from_slice(&self.head[self.head_at..self.head_at + n]);
                self.head_at += n;
                return Ok(n);
            }
            if self.at < self.len {
                let n = (self.len - self.at).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.ended {
                return Ok(0);
            }
            let n = self.body.read(&mut self.buf)?;
            if n == 0 {
                self.ended = true;
                self.head = frame_head(0, T_DATA, F_END, self.id);
                self.head_at = 0;
                continue;
            }
            self.at = 0;
            self.len = n;
            self.head = frame_head(n, T_DATA, 0, self.id);
            self.head_at = 0;
        }
    }
}

impl crate::proxy::RelayPoll for BodyFrames {
    fn arm_relay_poll(&mut self) {}
}

impl GrpcReader<BodyFrames> {
    /// The relay lane polls the demuxed body at its own grain; the reader's timeout is the
    /// carrier's `WINDOW_UPDATE` arriving, not the request falling silent.
    pub(crate) fn arm_mux_poll(&mut self) {
        self.poll = true;
        crate::proxy::RelayPoll::arm_relay_poll(&mut self.read);
    }
}

impl crate::proxy::Carried for GrpcReader<BodyFrames> {
    fn arm(&mut self, _every: Duration, until: Instant) {
        self.set_handshake_budget(Some(until));
    }
    fn disarm(&mut self) {
        self.set_handshake_budget(None);
    }
}

fn mux_shared(write: Box<dyn FrameWrite + Send>, max: usize, window: u64) -> Arc<Shared> {
    Arc::new(Shared {
        stream: Mutex::new(write),
        send: Mutex::new(SendWindow {
            conn: window,
            stream: window,
            unlimited: true,
        }),
        wake: Condvar::new(),
        max_frame: Mutex::new(max),
        init: Mutex::new(window),
        ended: AtomicBool::new(false),
        upload_ended: AtomicBool::new(false),
        upload_gate: Mutex::new(()),
        dead: AtomicBool::new(false),
        pong: AtomicU64::new(0),
        muxed: true,
    })
}

fn mux_stream(
    conn: &Arc<crate::xhttp_h2::H2Conn>,
    body: crate::xhttp_h2::H2StreamReader,
    out: crate::xhttp_h2::H2StreamOut,
    sid: u32,
    method: Method,
) -> (GrpcReader<BodyFrames>, GrpcWriter) {
    let max = conn.max_frame_now();
    let window = conn.peer_window();
    let read = mux_shared(Box::new(NullSink), max, window);
    let write = mux_shared(Box::new(MuxSink { out }), max, window);
    let mut reader = new_reader(BodyFrames::new(body, sid), read, true, "", "", sid);
    reader.answered = true;
    reader.stream = sid;
    reader.method = method;
    let writer = GrpcWriter {
        shared: write,
        stream: sid,
        multi: method == Method::MultiHunk,
    };
    (reader, writer)
}

/// One connection, many gRPC streams: the shared HTTP/2 demux hands each request block here, and
/// every accepted stream runs the VLESS handler on its own reader and writer pair.
pub(crate) struct GrpcService {
    path: String,
    multi_path: String,
    users: crate::proxy::VlessUsers,
    freedom: bool,
    /// Set when the first stream's opening request has been decoded (or refused), so the demux's
    /// handshake clock stops bounding the connection.
    opened: Arc<std::sync::atomic::AtomicBool>,
}

impl GrpcService {
    pub(crate) fn new(
        settings: &GrpcSettings,
        users: &[crate::proxy::VlessUser],
        freedom: bool,
        opened: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            path: settings.path.clone(),
            multi_path: settings.multi_path.clone(),
            users: Arc::from(users),
            freedom,
            opened,
        }
    }
}

impl crate::xhttp_h2::H2Service for GrpcService {
    fn open(
        &self,
        conn: &Arc<crate::xhttp_h2::H2Conn>,
        sid: u32,
        block: &[u8],
        end_stream: bool,
    ) -> bool {
        let mut gate = Gate::default();
        if !conn.decode_block(block, |name, value| {
            gate.take(name, value, &self.path, &self.multi_path);
        }) || gate.served != Some(true)
            || gate.posted != Some(true)
            || gate.typed != Some(true)
        {
            conn.reset(sid);
            return false;
        }
        let method = if gate.multi == Some(true) {
            Method::MultiHunk
        } else {
            Method::Hunk
        };
        let Some((body, _head, out)) = conn.open(sid, end_stream) else {
            return false;
        };
        if !conn.respond(
            sid,
            &[
                (":status", "200"),
                ("content-type", "application/grpc"),
                ("grpc-encoding", "identity"),
            ],
        ) {
            conn.reset(sid);
            return false;
        }
        let (reader, writer) = mux_stream(conn, body, out, sid, method);
        let users = Arc::clone(&self.users);
        let freedom = self.freedom;
        let opened = Arc::clone(&self.opened);
        crate::proxy::lane_pool::submit_stream_setup(move || {
            crate::proxy::serve_grpc_muxed(reader, writer, &users, freedom, &opened);
        });
        // The head is not a request until the VLESS body decodes: `serve_grpc_muxed` puts the clock away then.
        false
    }
}

pub(crate) fn serve_muxed<R: Read + Send + 'static, W: FrameWrite + Send + 'static>(
    read: R,
    write: W,
    settings: &GrpcSettings,
    users: &[crate::proxy::VlessUser],
    freedom: bool,
) {
    let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let service = GrpcService::new(settings, users, freedom, Arc::clone(&opened));
    let until = std::time::Instant::now() + crate::budgets::handshake();
    let mut step = crate::xhttp_h2::h2_lane(read, write, service, None, Some((until, opened)));
    let sniffing = crate::sniff::current();
    let access = crate::accesslog::snapshot();
    crate::proxy::lane_pool::submit_demux(
        Box::new(move || {
            crate::sniff::install_current(sniffing.clone());
            let _flow = crate::accesslog::install_snapshot(access.clone());
            step()
        }),
        Box::new(|| {}),
    );
}

/// A plaintext muxed connection's demux as a relay lane: a connection waiting for its peer's next
/// frame parks on the socket's readiness, so eight of them add lanes, not threads.
pub(crate) fn serve_muxed_conn(
    read: Connection,
    write: Tail,
    settings: &GrpcSettings,
    users: &[crate::proxy::VlessUser],
    freedom: bool,
) {
    let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let service = GrpcService::new(settings, users, freedom, Arc::clone(&opened));
    let until = std::time::Instant::now() + crate::budgets::handshake();
    let mut step = crate::xhttp_h2::h2_lane(read, write, service, None, Some((until, opened)));
    // A lane runs on whichever worker is free, so the accept thread's sniffing and access-log target are installed into each step.
    let sniffing = crate::sniff::current();
    let access = crate::accesslog::snapshot();
    crate::proxy::lane_pool::submit_demux(
        Box::new(move || {
            crate::sniff::install_current(sniffing.clone());
            let _flow = crate::accesslog::install_snapshot(access.clone());
            step()
        }),
        Box::new(|| {}),
    );
}

#[cfg(test)]
pub(crate) fn accept(stream: Connection, path: &str) -> Option<(GrpcReader, GrpcWriter)> {
    accept_with(stream, &GrpcSettings::path(path))
}

pub(crate) fn accept_with(
    stream: Connection,
    settings: &GrpcSettings,
) -> Option<(GrpcReader, GrpcWriter)> {
    let read = stream;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    // A head's clock only bites when a read answers it, so the preface and the request headers are polled at the relay's grain and ended by the deadline; the relay behind them waits blocking again.
    read.set_read_timeout(Some(crate::budgets::RELAY_POLL))
        .ok()?;
    let write = Tail::new(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>);
    let mut accepted = accept_split_with(read, write, settings)?;
    accepted.0.set_poll(None);
    Some(accepted)
}

/// The plaintext a bare socket cannot hold itself: an offer is taken whole into this tail and the
/// socket drains it at its own pace, so a lane never parks in a full send buffer and the bytes an
/// offer acknowledged are still owed a write.
pub(crate) struct Tail {
    inner: Box<dyn crate::proxy::FrameWrite + Send>,
    bytes: Vec<u8>,
    at: usize,
    lost: bool,
}

impl Tail {
    pub(crate) fn new(mut inner: Box<dyn crate::proxy::FrameWrite + Send>) -> Self {
        inner.arm_write(crate::budgets::RELAY_POLL);
        Self {
            inner,
            bytes: Vec::new(),
            at: 0,
            lost: false,
        }
    }

    /// The most this tail keeps ahead of a socket that has no pacing of its own.
    const MOST: usize = 256 * 1024;

    /// The caller's parts straight at the socket; only the suffix it would not take is copied.
    fn put(&mut self, parts: &[&[u8]]) -> Accepted {
        let total = parts.iter().map(|part| part.len()).sum::<usize>();
        let mut wrote = 0;
        while wrote < total {
            let mut bufs: [std::io::IoSlice<'_>; 2 * FRAMES_PER_WRITE] =
                std::array::from_fn(|_| std::io::IoSlice::new(NO_FRAME));
            let mut skip = wrote;
            let mut pieces = 0;
            for part in parts {
                if skip >= part.len() {
                    skip -= part.len();
                    continue;
                }
                bufs[pieces] = std::io::IoSlice::new(&part[skip..]);
                pieces += 1;
                skip = 0;
                if pieces == bufs.len() {
                    break;
                }
            }
            match self.inner.write_vectored(&bufs[..pieces]) {
                Ok(0) => {
                    self.lost = true;
                    return Accepted::Lost;
                }
                Ok(n) => wrote += n,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || crate::proxy::is_timeout(&error) =>
                {
                    break;
                }
                Err(_) => {
                    self.lost = true;
                    return Accepted::Lost;
                }
            }
        }
        if wrote < total {
            self.keep(parts, wrote);
        }
        Accepted::All
    }

    /// The bytes the socket did not take, kept until a settle writes them. What the socket already
    /// took is dropped here, so the buffer holds the pending suffix and not the whole transfer.
    fn keep(&mut self, parts: &[&[u8]], mut skip: usize) {
        if self.at > 0 {
            self.bytes.drain(..self.at);
            self.at = 0;
        }
        for part in parts {
            if skip >= part.len() {
                skip -= part.len();
                continue;
            }
            self.bytes.extend_from_slice(&part[skip..]);
            skip = 0;
        }
    }

    fn drain(&mut self) -> Settle {
        if self.lost {
            return Settle::Lost;
        }
        while self.at < self.bytes.len() {
            match self.inner.write(&self.bytes[self.at..]) {
                Ok(0) => {
                    self.lost = true;
                    return Settle::Lost;
                }
                Ok(n) => self.at += n,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || crate::proxy::is_timeout(&error) =>
                {
                    return Settle::Parked;
                }
                Err(_) => {
                    self.lost = true;
                    return Settle::Lost;
                }
            }
        }
        self.bytes.clear();
        self.at = 0;
        Settle::Clear
    }
}

impl std::io::Write for Tail {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match self.offer_slices(&[data]) {
            Accepted::All => Ok(data.len()),
            Accepted::Full => Err(std::io::ErrorKind::WouldBlock.into()),
            Accepted::Lost => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.drain() {
            Settle::Lost => Err(std::io::ErrorKind::BrokenPipe.into()),
            _ => Ok(()),
        }
    }
}

impl crate::proxy::FrameWrite for Tail {
    /// A control frame ordered behind bytes the peer has not read still has to be accepted: the
    /// demux writes it while no lane may wait, so it appends past the cap instead of being refused.
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        if self.lost {
            return false;
        }
        if matches!(self.drain(), Settle::Lost) {
            return false;
        }
        if self.at < self.bytes.len() {
            self.keep(parts, 0);
            return true;
        }
        matches!(self.put(parts), Accepted::All)
    }

    /// The caller's parts go straight to the socket when it has room; only the suffix a timed-out
    /// write left behind is copied, because the relay buffer behind it is overwritten next read.
    fn offer_slices(&mut self, parts: &[&[u8]]) -> Accepted {
        if self.lost {
            return Accepted::Lost;
        }
        if self.at < self.bytes.len() {
            match self.drain() {
                Settle::Lost => return Accepted::Lost,
                Settle::Clear | Settle::Parked => {}
            }
        }
        if self.at < self.bytes.len() {
            let pending = self.bytes.len() - self.at;
            let offered: usize = parts.iter().map(|part| part.len()).sum();
            if pending >= Self::MOST || offered > Self::MOST - pending {
                return Accepted::Full;
            }
            self.keep(parts, 0);
            return Accepted::All;
        }
        self.put(parts)
    }

    fn settle(&mut self) -> Settle {
        self.drain()
    }

    fn arm_write(&mut self, timeout: Duration) {
        self.inner.arm_write(timeout);
    }
}

fn new_shared(write: Box<dyn crate::proxy::FrameWrite + Send>) -> Arc<Shared> {
    Arc::new(Shared {
        stream: Mutex::new(write),
        send: Mutex::new(SendWindow {
            conn: 65_535,
            stream: 65_535,
            unlimited: false,
        }),
        wake: Condvar::new(),
        max_frame: Mutex::new(16_384),
        init: Mutex::new(65_535),
        ended: AtomicBool::new(false),
        upload_ended: AtomicBool::new(false),
        upload_gate: Mutex::new(()),
        dead: AtomicBool::new(false),
        pong: AtomicU64::new(0),
        muxed: false,
    })
}

fn new_reader<R: Read>(
    read: R,
    shared: Arc<Shared>,
    server: bool,
    path: &str,
    multi_path: &str,
    stream: u32,
) -> GrpcReader<R> {
    GrpcReader {
        read,
        shared,
        decoder: Decoder::default(),
        stream,
        server,
        path: path.to_owned(),
        multi_path: multi_path.to_owned(),
        method: Method::Hunk,
        answered: false,
        head: Vec::new(),
        head_id: 0,
        head_flags: 0,
        msg: Vec::new(),
        msg_at: 0,
        msg_end: 0,
        pay_end: 0,
        staged: 0,
        reclaims: 0,
        frame: Vec::new(),
        frame_head: [0; 9],
        frame_have: 0,
        pending: None,
        owed: 0,
        owed_id: 0,
        handshake: None,
        eof: false,
        remote_end: false,
        poll: false,
    }
}

// The same accept over halves that cannot clone: the preface is read, not peeked.
#[cfg(test)]
pub(crate) fn accept_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    path: &str,
) -> Option<(GrpcReader<R>, GrpcWriter)> {
    accept_split_with(read, write, &GrpcSettings::path(path))
}

pub(crate) fn accept_split_with<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    settings: &GrpcSettings,
) -> Option<(GrpcReader<R>, GrpcWriter)> {
    write.arm_write(crate::budgets::RELAY_POLL);
    let until = std::time::Instant::now() + crate::budgets::handshake();
    let mut magic = [0u8; 24];
    crate::proxy::read_exact(
        &mut crate::proxy::HandshakeDeadline {
            inner: &mut read,
            until,
        },
        &mut magic,
    )
    .ok()?;
    if magic != *MAGIC {
        return None;
    }
    let shared = new_shared(Box::new(write));
    {
        let Ok(mut socket) = shared.stream.lock() else {
            return None;
        };
        if socket
            .write_all(&preface(settings.initial_window_size))
            .is_err()
        {
            return None;
        }
    }
    let mut reader = new_reader(
        read,
        Arc::clone(&shared),
        true,
        &settings.path,
        &settings.multi_path,
        0,
    );
    // The clock the preface was read under covers the request headers too, and ends where the head ends: past it the pump is a give-up rather than a wait, and a reader handed to a caller is unarmed again.
    reader.set_handshake_budget(Some(until));
    while !reader.answered && !reader.eof {
        if !matches!(reader.pump(), Ok(Some(()))) {
            reader.eof = true;
        }
    }
    if !reader.answered {
        return None;
    }
    reader.set_handshake_budget(None);
    let writer = GrpcWriter {
        shared,
        stream: reader.stream,
        multi: reader.method == Method::MultiHunk,
    };
    start_keepalive(Arc::clone(&writer.shared), settings);
    Some((reader, writer))
}

#[cfg(test)]
pub(crate) fn connect(
    stream: Connection,
    host: &str,
    path: &str,
) -> Option<(GrpcReader, GrpcWriter)> {
    connect_with(stream, host, &GrpcSettings::path(path))
}

pub(crate) fn connect_with(
    stream: Connection,
    host: &str,
    settings: &GrpcSettings,
) -> Option<(GrpcReader, GrpcWriter)> {
    let read = stream;
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let write = Tail::new(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>);
    connect_split_with(read, write, host, settings)
}

// The same connect over halves that cannot clone: the preface is written, not peeked.
#[cfg(test)]
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    host: &str,
    path: &str,
) -> Option<(GrpcReader<R>, GrpcWriter)> {
    connect_split_with(read, write, host, &GrpcSettings::path(path))
}

pub(crate) fn connect_split_with<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    mut write: W,
    host: &str,
    settings: &GrpcSettings,
) -> Option<(GrpcReader<R>, GrpcWriter)> {
    write.arm_write(crate::budgets::RELAY_POLL);
    if !write.write_slices(&[MAGIC, &preface(settings.initial_window_size)]) {
        return None;
    }
    let authority = if settings.authority.is_empty() {
        host
    } else {
        &settings.authority
    };
    let path = if settings.multi_mode {
        &settings.multi_path
    } else {
        &settings.path
    };
    let mut headers = vec![
        (":method", "POST"),
        (":scheme", "http"),
        (":path", path),
        (":authority", authority),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("grpc-encoding", "identity"),
        ("grpc-accept-encoding", "gzip,identity"),
    ];
    let agent = user_agent(&settings.user_agent);
    if !agent.is_empty() {
        headers.push(("user-agent", agent));
    }
    let block = block_encode(&headers);
    if !write_frame(&mut write, T_HEADERS, F_END_HEADERS, 1, &block) {
        return None;
    }
    let shared = new_shared(Box::new(write));
    let mut reader = new_reader(
        read,
        Arc::clone(&shared),
        false,
        &settings.path,
        &settings.multi_path,
        1,
    );
    if settings.multi_mode {
        reader.method = Method::MultiHunk;
    }
    start_keepalive(Arc::clone(&shared), settings);
    Some((
        reader,
        GrpcWriter {
            shared,
            stream: 1,
            multi: settings.multi_mode,
        },
    ))
}

fn preface(initial_window: u32) -> Vec<u8> {
    let mut out = PREFACE.to_vec();
    if initial_window > 0 {
        let value = initial_window.min(i32::MAX as u32);
        out[11..15].copy_from_slice(&value.to_be_bytes());
    }
    out
}

const CHROME_UA: &str = concat!(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/",
    "144",
    ".0.0.0 Safari/537.36"
);
const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
const EDGE_UA: &str = concat!(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/",
    "144",
    ".0.0.0 Safari/537.36 Edg/",
    "144",
    ".0.0.0"
);

fn user_agent(name: &str) -> &str {
    match name {
        "" | "chrome" => CHROME_UA,
        "firefox" => FIREFOX_UA,
        "edge" => EDGE_UA,
        "golang" => "",
        other => other,
    }
}

fn start_keepalive(shared: Arc<Shared>, settings: &GrpcSettings) {
    // One stream per connection, so there is no idle connection for this flag to keep alive.
    let _ = settings.permit_without_stream;
    if settings.idle_timeout == 0 {
        return;
    }
    let every = u64::from(settings.idle_timeout);
    let health = settings.health_check_timeout;
    std::thread::spawn(move || {
        let mut seq = 0u64;
        loop {
            std::thread::sleep(Duration::from_secs(every));
            if shared.dead.load(Ordering::SeqCst) || shared.ended.load(Ordering::SeqCst) {
                return;
            }
            seq += 1;
            let body = seq.to_be_bytes();
            let head = frame_head(8, T_PING, 0, 0);
            let sent = shared
                .stream
                .lock()
                .is_ok_and(|mut socket| socket.write_slices(&[&head, &body]));
            if !sent {
                shared.dead.store(true, Ordering::SeqCst);
                return;
            }
            if health > 0 {
                let until = Instant::now() + Duration::from_secs(u64::from(health));
                while Instant::now() < until && shared.pong.load(Ordering::SeqCst) < seq {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if shared.pong.load(Ordering::SeqCst) < seq {
                    shared.dead.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }
    });
}

impl crate::proxy::CarrierSink for GrpcWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn push(&self, bytes: &[u8]) -> crate::proxy::Push {
        self.try_send(bytes)
    }
    #[inline]
    fn read_window(&self) -> Option<usize> {
        GrpcWriter::read_window(self)
    }
    #[inline]
    fn settle(&self) -> Settle {
        self.settle()
    }
    #[inline]
    fn wait_for_room(&self, turn: Duration) {
        self.wait_for_room(turn);
    }
    #[inline]
    fn close(&self) {
        self.close();
    }
    #[inline]
    fn upload_done(&self) {
        self.upload_done();
    }
}

impl GrpcReader<BodyFrames> {
    pub(crate) fn abort(&self) {
        self.read.abort();
    }

    pub(crate) fn reset_handle(&self) -> impl FnOnce() + Send + 'static {
        self.read.reset_handle()
    }
}

pub(crate) fn mark_reader_dead<R: Read>(reader: &mut GrpcReader<R>) {
    if reader.remote_end {
        return;
    }
    reader.shared.dead.store(true, Ordering::SeqCst);
    reader.shared.wake.notify_all();
}

pub(crate) fn request_ended<R: Read>(reader: &GrpcReader<R>) -> bool {
    reader.remote_end && reader.msg_at >= reader.pay_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::WindowRead;
    use std::io::Write;

    const HUNK: usize = 16 * 1024;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn varint_len_matches_the_written_length_at_every_boundary() {
        for bits in 0..64 {
            for value in [(1u64 << bits) - 1, 1u64 << bits] {
                let mut bytes = [0u8; 10];
                assert_eq!(
                    varint_len(value),
                    write_varint(&mut bytes, value),
                    "{value}"
                );
            }
        }
        for value in [0, u64::MAX] {
            let mut bytes = [0u8; 10];
            assert_eq!(
                varint_len(value),
                write_varint(&mut bytes, value),
                "{value}"
            );
        }
    }

    #[test]
    fn the_varint_length_over_every_boundary() {
        let mut acc = 0usize;
        for _ in 0..1024 {
            for bits in 0..64 {
                acc += varint_len(std::hint::black_box((1u64 << bits) - 1))
                    + varint_len(std::hint::black_box(1u64 << bits));
            }
        }
        std::hint::black_box(acc);
    }

    #[test]
    fn the_varint_shift_loop_over_every_boundary() {
        fn shift_len(mut value: u64) -> usize {
            let mut len = 1;
            while value >= 0x80 {
                value >>= 7;
                len += 1;
            }
            len
        }
        let mut acc = 0usize;
        for _ in 0..1024 {
            for bits in 0..64 {
                acc += shift_len(std::hint::black_box((1u64 << bits) - 1))
                    + shift_len(std::hint::black_box(1u64 << bits));
            }
        }
        std::hint::black_box(acc);
    }

    #[test]
    fn huffman_matches_the_rfc_example() {
        let coded = [
            0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF,
        ];
        let mut plain = Vec::new();
        ferrox_core::foxy::hpack::huffman_decode(&coded, &mut plain).expect("decodes");
        assert_eq!(plain, b"www.example.com");
        assert!(ferrox_core::foxy::hpack::huffman_decode(b"\xff", &mut Vec::new()).is_none());
    }

    #[test]
    fn headers_decode_the_rfc_request_example() {
        let first = [
            0x82, 0x86, 0x84, 0x41, 0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB,
            0x90, 0xF4, 0xFF,
        ];
        let mut decoder = Decoder::default();
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        decoder
            .decode(&first, &mut |name, value| {
                headers.push((name.to_vec(), value.to_vec()));
            })
            .expect("decodes");
        let get = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name.as_bytes())
                .map(|(_, value)| value.clone())
        };
        assert_eq!(get(":method").expect("method"), b"GET");
        assert_eq!(get(":scheme").expect("scheme"), b"http");
        assert_eq!(get(":path").expect("path"), b"/");
        assert_eq!(get(":authority").expect("authority"), b"www.example.com");
    }

    #[test]
    fn headers_round_trip_without_indexing() {
        let block = block_encode(&[(":method", "POST"), (":path", "/TunnelService/Tun")]);
        let mut decoder = Decoder::default();
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        decoder
            .decode(&block, &mut |name, value| {
                headers.push((name.to_vec(), value.to_vec()));
            })
            .expect("decodes");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].1, b"/TunnelService/Tun");
    }

    #[test]
    fn grpc_settings_reach_the_preface_and_head() {
        let calls = Calls::default();
        let seen = Arc::clone(&calls.0);
        let settings = GrpcSettings {
            path: "/svc/tun".to_owned(),
            multi_path: "/svc/tunmulti".to_owned(),
            authority: "edge.example".to_owned(),
            user_agent: "agent/1".to_owned(),
            multi_mode: true,
            initial_window_size: 1_000_000,
            ..GrpcSettings::default()
        };
        let (reader, writer) = connect_split_with(
            std::io::Cursor::new(Vec::new()),
            calls,
            "ignored",
            &settings,
        )
        .expect("dials");
        drop(reader);
        drop(writer);
        let chunks = seen.lock().expect("writes");
        assert_eq!(&chunks[0][..MAGIC.len()], &MAGIC[..]);
        let window = u32::from_be_bytes(
            chunks[0][MAGIC.len() + 11..MAGIC.len() + 15]
                .try_into()
                .unwrap(),
        );
        assert_eq!(window, 1_000_000, "initialWindowsSize is the stream window");
        let mut decoder = Decoder::default();
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        decoder
            .decode(&chunks[1][9..], &mut |name, value| {
                headers.push((name.to_vec(), value.to_vec()));
            })
            .expect("decodes");
        let get = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name.as_bytes())
                .map(|(_, value)| value.as_slice())
        };
        assert_eq!(get(":path"), Some(b"/svc/tunmulti".as_slice()));
        assert_eq!(get(":authority"), Some(b"edge.example".as_slice()));
        assert_eq!(get("user-agent"), Some(b"agent/1".as_slice()));
    }

    #[test]
    fn a_multi_mode_dial_reads_the_batch_it_asked_for() {
        let settings = GrpcSettings {
            path: "/svc/tun".to_owned(),
            multi_path: "/svc/tunmulti".to_owned(),
            multi_mode: true,
            ..GrpcSettings::default()
        };
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        wire.extend_from_slice(&frame(T_DATA, F_END, 1, &multi_message(&[b"pi", b"n"])));
        let (mut reader, writer) = connect_split_with(
            std::io::Cursor::new(wire),
            Sink::default(),
            "127.0.0.1",
            &settings,
        )
        .expect("dials");
        drop(writer);
        let mut got = [0u8; 3];
        reader.read_exact(&mut got).expect("reads the batch");
        assert_eq!(&got, b"pin");
    }

    #[test]
    fn hunks_carry_the_xray_schema_bytes() {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(4, &mut prefix);
        let mut frame = prefix[..plen].to_vec();
        frame.extend_from_slice(b"ping");
        assert_eq!(frame, b"\0\0\0\0\x06\x0a\x04ping");
        assert_eq!(
            hunk_decode(&[0x0A, 0x04, b'p', b'i', b'n', b'g']).expect("decodes"),
            (2, b"ping".as_slice())
        );
        // A field the lane does not read still carries its payload's offset.
        assert_eq!(
            hunk_decode(&[0x12, 0x02, 0x01, 0x02, 0x0A, 0x02, b'p', b'g']).expect("decodes"),
            (6, b"pg".as_slice())
        );
        assert!(hunk_decode(b"raw payload").is_none());
        assert!(hunk_decode(&[0x0A, 0x80]).is_none());
    }

    /// A server that answers whole frames at its own pace, in memory: the place where a copy count is exact rather than a function of the scheduler.
    #[derive(Default)]
    struct Sink(Vec<u8>);

    impl std::io::Write for Sink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Sink {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            parts.iter().all(|part| self.write_all(part).is_ok())
        }
    }

    /// A peer socket that keeps every write it was given as its own entry, so a test can count the writes and read their bytes.
    #[derive(Default)]
    struct Calls(Arc<Mutex<Vec<Vec<u8>>>>);

    impl std::io::Write for Calls {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().push(data.to_vec());
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Calls {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            self.0.lock().unwrap().push(parts.concat());
            true
        }
    }

    /// What a peer was given: every write whole, and every part of one by address and length.
    #[derive(Default)]
    struct Peer {
        writes: Vec<Vec<u8>>,
        parts: Vec<(usize, usize)>,
    }

    /// A peer socket that records both, so a batch is witnessed by what it carries and by what it
    /// points at — the second is the only way a gather's zero-copy is ever seen.
    struct Recorder(Arc<Mutex<Peer>>);

    impl Recorder {
        fn record(&mut self, parts: &[&[u8]]) -> bool {
            let mut peer = self.0.lock().unwrap();
            for part in parts {
                peer.parts.push((part.as_ptr() as usize, part.len()));
            }
            peer.writes.push(parts.concat());
            true
        }
    }

    impl std::io::Write for Recorder {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.record(&[data]);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Recorder {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            self.record(parts)
        }
    }

    fn frame(kind: u8, flags: u8, id: u32, body: &[u8]) -> Vec<u8> {
        let mut sink = Sink::default();
        assert!(write_frame(&mut sink, kind, flags, id, body));
        sink.0
    }

    /// A writer over the test's own sink, at the frame size it asks for and with the window it owes.
    fn writer_over<W: crate::proxy::FrameWrite + 'static>(
        write: W,
        max_frame: usize,
        window: u64,
    ) -> GrpcWriter {
        let shared = new_shared(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>);
        *shared.max_frame.lock().unwrap() = max_frame;
        *shared.init.lock().unwrap() = window;
        let mut send = shared.send.lock().unwrap();
        send.conn = window;
        send.stream = window;
        drop(send);
        GrpcWriter {
            shared,
            stream: 1,
            multi: false,
        }
    }

    /// The same writer over the same sink, but sending a `MultiHunk` batch rather than one `Hunk`;
    /// `cap` is the window the peer started with, which a group may not exceed even when later
    /// grants have made the live window larger.
    fn multi_writer_over<W: crate::proxy::FrameWrite + 'static>(
        write: W,
        max_frame: usize,
        window: u64,
        cap: u64,
    ) -> GrpcWriter {
        let mut writer = writer_over(write, max_frame, window);
        writer.multi = true;
        *writer.shared.init.lock().unwrap() = cap;
        writer
    }

    /// The frames a write leaves as at the frame size this lane advertises: one whole message in
    /// every frame — the reference a gathered batch is compared frame by frame against.
    fn frames(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for piece in payload.chunks(message_payload(HUNK - 1)) {
            out.extend_from_slice(&frame(T_DATA, 0, 1, &message(piece)));
        }
        out
    }

    /// One gRPC message: the 5-byte envelope and a `Hunk` whose `Data` is `payload`.
    fn message(payload: &[u8]) -> Vec<u8> {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(payload.len(), &mut prefix);
        let mut body = prefix[..plen].to_vec();
        body.extend_from_slice(payload);
        body
    }

    /// One gRPC message carrying a `MultiHunk`: field 1 is `repeated bytes`, so each element is a tag, its own varint length and its bytes, in order.
    fn multi_message(elements: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for element in elements {
            body.push(0x0A);
            push_varint(&mut body, element.len() as u64);
            body.extend_from_slice(element);
        }
        let mut out = vec![0u8];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// The number of gRPC messages in a concatenation of them.
    fn message_count(mut body: &[u8]) -> usize {
        let mut count = 0;
        while !body.is_empty() {
            let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
            body = &body[5 + len..];
            count += 1;
        }
        count
    }

    /// The served side of a call over a scripted wire: the preface, the HEADERS that open it, then its DATA frames.
    fn served(
        path: &str,
        frames: &[(u8, Vec<u8>)],
    ) -> Option<GrpcReader<std::io::Cursor<Vec<u8>>>> {
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[
                (":method", "POST"),
                (":path", path),
                ("content-type", "application/grpc"),
            ]),
        ));
        for (flags, body) in frames {
            wire.extend_from_slice(&frame(T_DATA, *flags, 1, body));
        }
        let (reader, writer) = accept_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "/TunnelService/Tun",
        )?;
        drop(writer);
        Some(reader)
    }

    /// Everything the caller is handed, and the bytes the reader moved for itself to hand it.
    fn drain_all(reader: &mut GrpcReader<std::io::Cursor<Vec<u8>>>) -> (Vec<u8>, usize) {
        let mut got = Vec::new();
        let mut buf = [0u8; 3000];
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        (got, reader.staged)
    }

    /// The two methods cannot share a decoder: a `MultiHunk` read as a `Hunk` hands the caller only the last element of every message, which is the silent truncation the served mode exists to refuse.
    #[test]
    fn a_multi_message_hands_every_element_in_order() {
        let batch = multi_message(&[b"ab", b"cdef", b"", b"g"]);
        for (name, frames, want) in [
            (
                "one message, four elements",
                vec![(F_END, batch.clone())],
                b"abcdefg".to_vec(),
            ),
            (
                "two messages, two elements each",
                vec![
                    (0, multi_message(&[b"ab", b"c"])),
                    (F_END, multi_message(&[b"d", b"ef"])),
                ],
                b"abcdef".to_vec(),
            ),
            (
                "one element cut across frames",
                vec![(0, batch[..11].to_vec()), (F_END, batch[11..].to_vec())],
                b"abcdefg".to_vec(),
            ),
        ] {
            let mut multi = served("/TunnelService/TunMulti", &frames).expect("serves");
            let (got, staged) = drain_all(&mut multi);
            assert_eq!(got, want, "{name}");
            assert_eq!(staged, 0, "{name} staged bytes for itself");
        }
        let mut blind = served("/TunnelService/Tun", &[(F_END, batch)]).expect("serves");
        assert_eq!(
            drain_all(&mut blind).0,
            b"g".to_vec(),
            "single mode takes the last element and drops the batch"
        );
        assert!(
            served("/other/TunMulti", &[]).is_none(),
            "a multi call on another service is refused"
        );
    }

    /// The batch the reference server writes: eight `readv` buffers is its ceiling, so one message carries the set and the caller still gets every byte in order, unstaged.
    #[test]
    fn a_batched_downlink_arrives_element_by_element() {
        let parts: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'a' + i; 8 * 1024]).collect();
        let batch: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let mut reader = served(
            "/TunnelService/TunMulti",
            &[
                (0, multi_message(&batch[..4])),
                (F_END, multi_message(&batch[4..])),
            ],
        )
        .expect("serves");
        let (got, staged) = drain_all(&mut reader);
        assert_eq!(got, parts.concat(), "eight elements of 8 KiB, in order");
        assert_eq!(staged, 0, "a batch is delivered where it lies");
    }

    /// The single-mode call is untouched by the second method, and a path that is neither is refused.
    #[test]
    fn one_listener_serves_both_methods() {
        for (path, want) in [
            ("/TunnelService/Tun", b"ping".to_vec()),
            ("/TunnelService/TunMulti", b"pin".to_vec()),
        ] {
            let frames = if path.ends_with("Multi") {
                vec![(F_END, multi_message(&[b"pi", b"n"]))]
            } else {
                vec![(F_END, message(b"ping"))]
            };
            let mut reader = served(path, &frames).expect("serves");
            assert_eq!(drain_all(&mut reader).0, want, "{path}");
        }
        assert!(served("/TunnelService/TunExtra", &[]).is_none());
    }

    fn dial(frames: &[(u8, Vec<u8>)]) -> GrpcReader<std::io::Cursor<Vec<u8>>> {
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        for (flags, body) in frames {
            wire.extend_from_slice(&frame(T_DATA, *flags, 1, body));
        }
        let (reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        reader
    }

    /// The witness for `carrier-grpc payload-staging-copies-per-byte-read 0`: a body is read onto the end of the buffer the caller is served from, over the three shapes a body can arrive in.
    #[test]
    fn a_body_never_lands_in_a_second_buffer() {
        for (name, frames, want) in [
            (
                "one message per frame",
                vec![
                    (0, message(b"ping")),
                    (0, message(b"pong")),
                    (F_END, message(b"last")),
                ],
                b"pingponglast".to_vec(),
            ),
            (
                "two messages in one frame",
                vec![(F_END, [message(b"ab"), message(b"cd")].concat())],
                b"abcd".to_vec(),
            ),
            (
                "one message split over frames",
                vec![
                    (0, message(b"ping")[..6].to_vec()),
                    (F_END, message(b"ping")[6..].to_vec()),
                ],
                b"ping".to_vec(),
            ),
        ] {
            let mut reader = dial(&frames);
            let mut got = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = reader.read(&mut buf).expect("reads");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, want, "{name}");
            assert_eq!(reader.staged, 0, "{name} staged bytes for itself");
        }
    }

    /// Records the base and length of every slice the relay's own write hands the sink, so a copy
    /// into a staging buffer would show as a base outside the reader's message buffer.
    #[derive(Default)]
    struct RecordingSink {
        runs: Vec<(usize, usize)>,
    }

    impl std::io::Write for RecordingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.runs.push((buf.as_ptr() as usize, buf.len()));
            Ok(buf.len())
        }

        fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
            for buf in bufs {
                self.runs.push((buf.as_ptr() as usize, buf.len()));
            }
            Ok(bufs.iter().map(|buf| buf.len()).sum())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The witness for `carrier-grpc relay-window-copies-per-byte 0`: the window a carrier read gives
    /// the relay is one run of the message buffer the reader already holds, and the relay's own write
    /// path hands the sink that same run, so the downloaded body reaches the peer socket from the
    /// reader's buffer instead of being staged a second time.
    #[test]
    fn a_relay_window_hands_the_payload_it_read_by_pointer() {
        let bodies: [&[u8]; 3] = [b"ping", b"pong", b"last"];
        let mut reader = dial(
            &bodies
                .iter()
                .enumerate()
                .map(|(i, body)| (if i + 1 == bodies.len() { F_END } else { 0 }, message(body)))
                .collect::<Vec<_>>(),
        );
        let (mut steady_base, mut steady_capacity) = (0usize, 0usize);
        let mut sink = RecordingSink::default();
        for (i, body) in bodies.iter().enumerate() {
            let base = {
                let window = reader.read_window().expect("reads a window");
                assert_eq!(window.bytes(), *body, "payload {i}");
                assert_eq!(
                    window.parts(),
                    [(0, body.len())].as_slice(),
                    "payload {i} is one run"
                );
                sink.runs.clear();
                crate::proxy::write_all_runs::<{ crate::proxy::WINDOW_PARTS }>(
                    &mut sink,
                    window.bytes(),
                    window.parts(),
                )
                .expect("the relay's write carries the window");
                assert_eq!(
                    sink.runs.len(),
                    1,
                    "payload {i} reached the sink as one run"
                );
                window.bytes().as_ptr() as usize
            };
            let buffer = reader.msg.as_ptr() as usize;
            assert!(
                base >= buffer && base + body.len() <= buffer + reader.msg.capacity(),
                "payload {i} was staged outside the message buffer"
            );
            assert_eq!(
                sink.runs[0],
                (base, body.len()),
                "payload {i} reached the sink as the window's own run"
            );
            if i == 0 {
                steady_base = buffer;
                steady_capacity = reader.msg.capacity();
            } else {
                assert_eq!(buffer, steady_base, "the message buffer moved");
                assert_eq!(
                    reader.msg.capacity(),
                    steady_capacity,
                    "the message buffer grew"
                );
            }
        }
        assert!(reader.read_window().expect("ends").is_empty());
        assert_eq!(
            reader.msg.as_ptr() as usize,
            steady_base,
            "the message buffer moved at the end"
        );
        assert_eq!(
            reader.msg.capacity(),
            steady_capacity,
            "the message buffer grew at the end"
        );
    }

    /// The witness for `carrier-grpc user-space-copies-per-byte-written 0`: the uplink hands the payload to the frame writer as one slice whose base is the caller's buffer, so a `writev` carries it unstaged — a round trip cannot see this, so pointer identity is the only witness.
    #[test]
    fn the_uplink_hands_the_payload_to_the_writer_by_pointer() {
        let payload: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let base = payload.as_ptr() as usize;
        let capacity = payload.capacity();
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), usize::MAX, u64::MAX);
        assert!(writer.send(&payload));
        // The payload reached the frame writer as a slice whose base is the caller's own buffer, so a `writev` carries it and no byte is staged through a second `Vec`.
        assert!(
            peer.lock()
                .unwrap()
                .parts
                .iter()
                .any(|&(at, len)| at == base && len == payload.len()),
            "the payload was handed by pointer, not staged through a buffer"
        );
        assert_eq!(payload.as_ptr() as usize, base, "the caller's buffer moved");
        assert_eq!(payload.capacity(), capacity, "the caller's buffer grew");
    }

    /// A writer the peer never credits gives up at the relay stall, so a relay leg cannot park its thread on a window that never arrives.
    #[test]
    fn a_writer_with_no_credit_gives_up_at_the_stall() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(500)),
            ..Default::default()
        });
        let writer = writer_over(Recorder(Arc::new(Mutex::new(Peer::default()))), HUNK, 0);
        let shared = Arc::clone(&writer.shared);
        let (sent, got) = std::sync::mpsc::channel();
        let running = crate::budgets::spawn(move || {
            let _ = sent.send(writer.send(b"ping"));
        });
        let verdict = got.recv_timeout(Duration::from_secs(3));
        shared.dead.store(true, Ordering::SeqCst);
        shared.wake.notify_all();
        running.join().expect("writer thread");
        crate::budgets::clear();
        assert_eq!(verdict, Ok(false), "a writer with no credit returned");
    }

    /// A parked relay turn ends on the update its own flush earns: a peer that grants nothing still
    /// costs the turn it already cost, and a peer that grants for the bytes it just read wakes the
    /// lane instead of pacing it at one window per quantum.
    #[test]
    fn a_window_update_ends_a_parked_room_wait() {
        let writer = writer_over(Recorder(Arc::new(Mutex::new(Peer::default()))), HUNK, 0);
        let shared = Arc::clone(&writer.shared);
        let done = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&done);
        let grant = std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                {
                    let mut send = shared.send.lock().unwrap_or_else(PoisonError::into_inner);
                    send.conn = u64::MAX;
                    send.stream = u64::MAX;
                }
                shared.wake.notify_all();
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let began = Instant::now();
        writer.wait_for_room(Duration::from_secs(2));
        done.store(true, Ordering::SeqCst);
        grant.join().expect("the granter ran");
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "the update woke the parked relay turn before its deadline"
        );
    }

    /// The update that pays for a parked take wakes it before its deadline, so a relay re-offers
    /// the same bytes on the notification rather than polling for them.
    #[test]
    fn a_window_update_wakes_a_parked_take() {
        let writer = writer_over(Recorder(Arc::new(Mutex::new(Peer::default()))), HUNK, 0);
        let shared = Arc::clone(&writer.shared);
        let done = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&done);
        let grant = std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                {
                    let mut send = shared.send.lock().unwrap_or_else(PoisonError::into_inner);
                    send.conn = u64::MAX;
                    send.stream = u64::MAX;
                }
                shared.wake.notify_all();
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let began = Instant::now();
        let took = take_window_until(
            &writer.shared,
            HUNK as u64 - 1,
            Some(began + Duration::from_secs(2)),
        );
        done.store(true, Ordering::SeqCst);
        grant.join().expect("the granter ran");
        assert!(took, "the parked take saw the window update");
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "the update woke the take before its deadline"
        );
    }

    /// The witnesses for `carrier-grpc writes-per-relay-read 1`, `carrier-grpc segments-per-socket-write 10` and `carrier-grpc payload-runs-per-socket-write 5`: a relay read of four `HUNK`s is five DATA frames, one whole message each, and leaves as one write of ten segments whose bytes are those frames in order, with five of them still runs of the caller's own buffer — a gather holds heads and envelopes apart, it does not stage a byte of payload.
    #[test]
    fn a_relay_read_gathers_its_frames_into_one_write() {
        let data: Vec<u8> = (0..FRAMES_PER_WRITE / 2 * HUNK)
            .map(|i| (i % 251) as u8)
            .collect();
        let hunks = data.len().div_ceil(message_payload(HUNK - 1));
        assert_eq!(hunks, 5, "five Hunk messages for this relay read");
        let base = data.as_ptr() as usize;
        let capacity = data.capacity();
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, u64::MAX);
        assert!(writer.send(&data));
        let peer = peer.lock().unwrap();
        assert_eq!(peer.writes.len(), 1, "one write for a relay read");
        assert_eq!(peer.writes[0], frames(&data), "the same frames, in order");
        assert_eq!(
            peer.parts.len(),
            2 * hunks,
            "a head slot and a payload run for every frame"
        );
        // The parts that lie in the caller's buffer are its payload, edge to edge: the batch skipped no byte and copied none.
        let end = base + data.len();
        let runs = peer
            .parts
            .iter()
            .filter(|&&(start, _)| (base..end).contains(&start))
            .count();
        assert_eq!(runs, hunks, "one payload run per frame");
        let mut at = base;
        for &(start, len) in &peer.parts {
            if start < base || start >= end {
                continue;
            }
            assert_eq!(start, at, "a payload run starts where the last one ended");
            assert!(start + len <= end, "a run leaves the caller's buffer");
            at = start + len;
        }
        assert_eq!(at, end, "every byte reached the writer");
        assert_eq!(data.capacity(), capacity, "the caller's buffer grew");
    }

    /// The regression witness: a multi-mode writer over the dial path leaves one message for a
    /// 32 KiB relay read, not one `Hunk` per element. A `Hunk` can carry at most `16_375` bytes,
    /// so two messages here mean the writer did not gather the batch; the test is red on the
    /// one-`Hunk`-per-element writer.
    #[test]
    fn a_multi_mode_dial_writer_gathers_the_read_into_one_message() {
        let settings = GrpcSettings {
            multi_mode: true,
            ..GrpcSettings::default()
        };
        let calls = Calls::default();
        let seen = Arc::clone(&calls.0);
        let (_, mut writer) = connect_split_with(
            std::io::Cursor::new(Vec::new()),
            calls,
            "127.0.0.1",
            &settings,
        )
        .expect("dials");
        let data: Vec<u8> = (0..2 * HUNK).map(|i| (i % 251) as u8).collect();
        writer.write_all(&data).expect("writes the read");
        drop(writer);
        let recorded = seen.lock().expect("writes");
        let bytes: Vec<u8> = recorded
            .iter()
            .flat_map(|write| write.iter().copied())
            .collect();
        let bytes = bytes.strip_prefix(MAGIC).unwrap_or(bytes.as_slice());
        let body = data_body(bytes);
        assert_eq!(
            message_count(&body),
            1,
            "one MultiHunk message for a 32 KiB read"
        );
        assert!(
            body.len() > HUNK,
            "the message carries more than one element"
        );
    }

    /// A transport whose first offer is refused because its paced tail is full: the blocking writer
    /// must settle that tail and retry the same group, not wait for a peer credit it already has.
    #[test]
    fn a_multi_mode_dial_writer_drains_a_full_tail_before_retrying() {
        struct Paced {
            refused: bool,
            got: Arc<Mutex<Vec<u8>>>,
        }
        impl std::io::Write for Paced {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.got.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::proxy::FrameWrite for Paced {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                matches!(self.offer_slices(parts), Accepted::All)
            }
            fn offer_slices(&mut self, parts: &[&[u8]]) -> Accepted {
                if self.refused {
                    self.refused = false;
                    return Accepted::Full;
                }
                let mut got = self.got.lock().unwrap();
                for part in parts {
                    got.extend_from_slice(part);
                }
                Accepted::All
            }
            fn settle(&mut self) -> Settle {
                Settle::Clear
            }
        }
        let got = Arc::new(Mutex::new(Vec::new()));
        let writer = multi_writer_over(
            Paced {
                refused: true,
                got: Arc::clone(&got),
            },
            HUNK,
            65_535,
            65_535,
        );
        let data: Vec<u8> = (0..2 * HUNK).map(|i| (i % 251) as u8).collect();
        assert!(writer.send(&data), "the drain leaves the retry its group");
        let body = data_body(&got.lock().unwrap());
        let elements: Vec<&[u8]> = data.chunks(message_payload(HUNK - 1)).collect();
        assert_eq!(
            body,
            multi_message(&elements),
            "the retry repeats no element"
        );
    }

    /// The DATA bodies in a concatenation of HTTP/2 frames, with the client preface already gone.
    fn data_body(mut wire: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        while wire.len() >= 9 {
            let len = ((wire[0] as usize) << 16) | ((wire[1] as usize) << 8) | wire[2] as usize;
            let kind = wire[3];
            let rest = &wire[9..];
            if rest.len() < len {
                break;
            }
            if kind == T_DATA {
                body.extend_from_slice(&rest[..len]);
            }
            wire = &rest[len..];
        }
        body
    }

    /// The multi-mode witness: one relay read leaves as the batch the peer's default window can
    /// pay for — two `MultiHunk` messages, four elements and the remainder, instead of five
    /// `Hunk`s — split into DATA frames at the peer's frame size, and every payload run is still
    /// the caller's own bytes.
    #[test]
    fn a_multi_relay_read_batches_the_window_it_can_pay_for() {
        let data: Vec<u8> = (0..FRAMES_PER_WRITE / 2 * HUNK)
            .map(|i| (i % 251) as u8)
            .collect();
        let base = data.as_ptr() as usize;
        let capacity = data.capacity();
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = multi_writer_over(Recorder(Arc::clone(&peer)), HUNK, 65_560, 65_535);
        assert!(matches!(
            writer.try_send(&data),
            crate::proxy::Push::Took(n) if n == data.len()
        ));
        let peer = peer.lock().unwrap();
        assert_eq!(peer.writes.len(), 1, "one write for a relay read");
        let elements: Vec<&[u8]> = data.chunks(message_payload(HUNK - 1)).collect();
        let split = 4;
        let want = [
            multi_message(&elements[..split]),
            multi_message(&elements[split..]),
        ]
        .concat();
        let mut body = Vec::new();
        let mut at = 0;
        while at < peer.writes[0].len() {
            let head = &peer.writes[0][at..at + 9];
            let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
            assert_eq!(head[3], T_DATA);
            assert_eq!(u32::from_be_bytes(head[5..9].try_into().unwrap()), 1);
            at += 9;
            body.extend_from_slice(&peer.writes[0][at..at + len]);
            at += len;
        }
        assert_eq!(body, want, "two MultiHunk messages at the default window");
        assert_eq!(message_count(&body), 2, "two messages, not five");
        let end = base + data.len();
        let mut seen = base;
        for &(start, len) in &peer.parts {
            if start < base || start >= end {
                continue;
            }
            assert_eq!(start, seen, "a payload run starts where the last one ended");
            assert!(start + len <= end, "a run leaves the caller's buffer");
            seen = start + len;
        }
        assert_eq!(seen, end, "every byte reached the writer");
        assert_eq!(data.capacity(), capacity, "the caller's buffer grew");
    }

    /// A read at the peer's own starting window is one message: the relay asks the writer for the
    /// most it can frame, so the last bytes of a `64 KiB` read are not a second message that has to
    /// wait for a credit after the first one emptied the window.
    #[test]
    fn a_multi_relay_read_at_the_peer_window_is_one_message() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = multi_writer_over(Recorder(Arc::clone(&peer)), HUNK, 65_535, 65_535);
        let len = writer
            .read_window()
            .expect("multi mode limits the relay read");
        assert_eq!(len, 65_471, "the window less the envelope and tags");
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let base = data.as_ptr() as usize;
        let capacity = data.capacity();
        assert!(matches!(
            writer.try_send(&data),
            crate::proxy::Push::Took(n) if n == data.len()
        ));
        let peer = peer.lock().unwrap();
        assert_eq!(peer.writes.len(), 1, "one write for a relay read");
        let elements: Vec<&[u8]> = data.chunks(message_payload(HUNK - 1)).collect();
        let want = multi_message(&elements);
        let mut body = Vec::new();
        let mut at = 0;
        while at < peer.writes[0].len() {
            let head = &peer.writes[0][at..at + 9];
            let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
            assert_eq!(head[3], T_DATA);
            at += 9;
            body.extend_from_slice(&peer.writes[0][at..at + len]);
            at += len;
        }
        assert_eq!(body, want, "the read is one MultiHunk message");
        assert_eq!(message_count(&body), 1, "one message, not two");
        let end = base + data.len();
        let mut seen = base;
        for &(start, len) in &peer.parts {
            if start < base || start >= end {
                continue;
            }
            assert_eq!(start, seen, "a payload run starts where the last one ended");
            assert!(start + len <= end, "a run leaves the caller's buffer");
            seen = start + len;
        }
        assert_eq!(seen, end, "every byte reached the writer");
        assert_eq!(data.capacity(), capacity, "the caller's buffer grew");
    }

    /// A peer may advertise a stream window above the connection window it starts with. The relay
    /// must read at the smaller grant, or every write parks on a message the peer never pays for.
    #[test]
    fn a_multi_relay_read_never_asks_past_the_connection_window() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = multi_writer_over(Recorder(Arc::clone(&peer)), HUNK, 65_535, 1_000_000);
        assert_eq!(writer.read_window(), Some(65_471));
    }

    /// A small peer window is still usable: the relay's read fits one message, and the next read
    /// follows the credit the first write left instead of asking for a window it has not granted.
    #[test]
    fn a_multi_read_fits_a_small_window_and_follows_credit() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = multi_writer_over(Recorder(Arc::clone(&peer)), HUNK, 10_000, 1_000_000);
        let len = writer
            .read_window()
            .expect("multi mode limits the relay read");
        assert_eq!(len, 9_984);
        assert!(matches!(
            writer.try_send(&vec![0u8; len]),
            crate::proxy::Push::Took(n) if n == len
        ));
        let peer = peer.lock().unwrap();
        assert_eq!(peer.writes.len(), 1, "one write for a relay read");
        assert_eq!(
            message_count(&peer.writes[0][9..]),
            1,
            "one message, not two"
        );
        drop(peer);

        let next = multi_writer_over(
            Recorder(Arc::new(Mutex::new(Peer::default()))),
            HUNK,
            10_000,
            1_000_000,
        );
        assert!(matches!(
            next.try_send(&vec![0u8; 8_000]),
            crate::proxy::Push::Took(8_000)
        ));
        assert_eq!(next.read_window(), Some(1_976));
    }

    /// A multi write splits at the connection window even when the stream starts larger, so the
    /// first group leaves and the rest parks instead of waiting on credit the peer never grants.
    #[test]
    fn a_multi_write_splits_at_the_connection_window() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = multi_writer_over(Recorder(Arc::clone(&peer)), HUNK, 65_535, 1_000_000);
        let data = vec![0u8; 65_536];
        assert!(matches!(
            writer.try_send(&data),
            crate::proxy::Push::Took(65_500)
        ));
    }

    /// A muxed sink whose `room()` is the body capacity and whose offers are checked against it;
    /// `grant` lets a blocking test hand the first `wait_room` a fresh window.
    struct Roomed {
        limit: std::sync::atomic::AtomicU64,
        grant: std::sync::atomic::AtomicU64,
        got: Arc<Mutex<Vec<u8>>>,
        offered: Arc<Mutex<Vec<usize>>>,
    }

    impl std::io::Write for Roomed {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.got.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Roomed {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            matches!(self.offer_slices(parts), Accepted::All)
        }
        fn offer_slices(&mut self, parts: &[&[u8]]) -> Accepted {
            let frames = parts.len().div_ceil(2);
            let total: usize = parts.iter().map(|part| part.len()).sum();
            let body = total - frames * 9;
            self.offered.lock().unwrap().push(body);
            if body as u64 > self.limit.load(Ordering::Relaxed) {
                return Accepted::Full;
            }
            for part in parts {
                self.got.lock().unwrap().extend_from_slice(part);
            }
            Accepted::All
        }
        fn room(&self) -> u64 {
            self.limit.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn wait_room(&self, _turn: Duration) {
            let limit = self.grant.swap(u64::MAX, Ordering::Relaxed);
            if limit != u64::MAX {
                self.limit.store(limit, Ordering::Relaxed);
            }
        }
    }

    fn mux_writer_over<W: crate::proxy::FrameWrite + 'static>(
        write: W,
        max_frame: usize,
        window: u64,
    ) -> GrpcWriter {
        GrpcWriter {
            shared: mux_shared(Box::new(write), max_frame, window),
            stream: 1,
            multi: true,
        }
    }

    fn roomed(limit: u64, grant: Option<u64>) -> (Roomed, Arc<Mutex<Vec<usize>>>) {
        let offered = Arc::new(Mutex::new(Vec::new()));
        (
            Roomed {
                limit: std::sync::atomic::AtomicU64::new(limit),
                grant: std::sync::atomic::AtomicU64::new(grant.unwrap_or(u64::MAX)),
                got: Arc::new(Mutex::new(Vec::new())),
                offered: Arc::clone(&offered),
            },
            offered,
        )
    }

    /// The multiplexed transport owns the live window, so a group is cut to its `room()` before
    /// it is offered: a group sized only by the opening window parks forever when the peer has
    /// already spent the credit on the response it is reading.
    #[test]
    fn a_multi_mode_muxed_writer_cuts_each_group_to_the_live_room() {
        let (sink, offered) = roomed(40_000, None);
        let writer = mux_writer_over(sink, HUNK, 65_535);
        let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        assert!(matches!(
            writer.try_send(&data),
            crate::proxy::Push::Took(n) if n == data.len()
        ));
        assert!(
            offered.lock().unwrap().iter().all(|&total| total <= 40_000),
            "every offered group fits the live room"
        );
    }

    /// A whole element whose complete envelope fits the live room stays one message; only a margin
    /// inferred from the frame width would split it.
    #[test]
    fn a_multi_mode_muxed_writer_keeps_a_message_that_fits_the_room() {
        let (sink, offered) = roomed(16_370, None);
        let writer = mux_writer_over(sink, HUNK, 65_535);
        let data: Vec<u8> = (0..16_360).map(|i| (i % 251) as u8).collect();
        assert!(matches!(
            writer.try_send(&data),
            crate::proxy::Push::Took(n) if n == data.len()
        ));
        assert_eq!(
            offered.lock().unwrap().len(),
            1,
            "one message for one element"
        );
    }

    /// A blocking write starts with no room: it waits for the transport instead of freezing the
    /// first group's one-byte element into the chunk size for the rest of the write.
    #[test]
    fn a_multi_mode_muxed_writer_waits_for_room_before_sizing_the_write() {
        let (sink, offered) = roomed(0, Some(40_000));
        let writer = mux_writer_over(sink, HUNK, 65_535);
        let data: Vec<u8> = (0..100).map(|i| (i % 251) as u8).collect();
        assert!(writer.send(&data));
        assert_eq!(
            offered.lock().unwrap().len(),
            1,
            "one message once room arrives"
        );
    }

    /// Every element leaves in the largest envelope the room pays for, and one byte more does not
    /// fit; a fixed frame-width margin would leave room unused.
    #[test]
    fn a_multi_element_uses_the_envelope_the_peer_pays_for() {
        for cap in [
            8u64, 9, 127, 128, 134, 16_383, 16_384, 16_390, 40_000, 65_535,
        ] {
            let payload = multi_payload(cap);
            let fits = 6 + varint_len(payload as u64) + payload;
            assert!(
                fits as u64 <= cap,
                "cap {cap} leaves payload {payload} at {fits}"
            );
            if payload > 1 {
                let next = payload + 1;
                let over = 6 + varint_len(next as u64) + next;
                assert!(over as u64 > cap, "cap {cap} still fits payload {next}");
            }
        }
    }

    /// A peer whose starting window is smaller than one frame: the writer cuts its elements to
    /// fit that window instead of forming a message the peer can never pay for.
    #[test]
    fn a_multi_writer_fits_an_element_to_the_starting_window() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = multi_writer_over(Recorder(Arc::clone(&peer)), HUNK, 64, 64);
        let data: Vec<u8> = (0..200).map(|i| (i % 251) as u8).collect();
        assert!(matches!(
            writer.try_send(&data),
            crate::proxy::Push::Took(n) if n > 0
        ));
        let peer = peer.lock().unwrap();
        let body = data_body(&peer.writes[0]);
        let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
        assert!(5 + len <= 64, "the message fits the peer's window");
    }

    /// The same batch driven over a real socket, where the only thing a loopback test can assert is
    /// its bytes: ten segments is the widest list this carrier hands `writev` or `WSASend`, so a
    /// platform that split the list or refused its width would answer with missing or reordered
    /// frames rather than with a count.
    #[test]
    fn a_wide_batch_reaches_a_real_socket_whole() {
        let data: Vec<u8> = (0..FRAMES_PER_WRITE / 2 * HUNK)
            .map(|i| (i % 251) as u8)
            .collect();
        let want = frames(&data);
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let writer = writer_over(stream, HUNK, u64::MAX);
            assert!(writer.send(&data), "the socket took the batch");
        });
        let mut read = Connection::connect(("127.0.0.1", port)).expect("connects");
        let mut wire = Vec::new();
        read.read_to_end(&mut wire).expect("reads");
        handle.join().expect("joins");
        assert_eq!(wire, want, "the same frames, in the same order, whole");
    }

    /// The plaintext tail hands the socket the caller's own slice, not a copy of it: the relay
    /// buffer behind a payload is overwritten by the next read, so a copy here would be invisible to
    /// a byte test and paid on every byte of a plaintext gRPC flow.
    #[test]
    fn the_tail_hands_the_payload_to_the_socket_by_pointer() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let mut tail = Tail::new(Box::new(Recorder(Arc::clone(&peer))));
        let payload = vec![0x5au8; 4096];
        let base = payload.as_ptr() as usize;
        let capacity = payload.capacity();
        assert!(matches!(tail.offer_slices(&[&payload]), Accepted::All));
        let seen = peer.lock().unwrap();
        assert_eq!(
            seen.parts,
            vec![(base, payload.len())],
            "the socket saw a copy, not the caller's bytes"
        );
        assert_eq!(payload.capacity(), capacity, "the caller's buffer grew");
    }

    /// A socket that takes a hundred bytes a call: the tail keeps the suffix the first write did not,
    /// and settle puts it all on the wire in the same order.
    #[test]
    fn the_tail_keeps_what_a_timed_out_socket_did_not_take() {
        struct Short(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Short {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                let take = data.len().min(100);
                self.0.lock().unwrap().extend_from_slice(&data[..take]);
                Ok(take)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::proxy::FrameWrite for Short {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                for part in parts {
                    let _ = self.write(part);
                }
                true
            }
        }
        let got = Arc::new(Mutex::new(Vec::new()));
        let mut tail = Tail::new(Box::new(Short(Arc::clone(&got))));
        let payload: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        assert!(matches!(tail.offer_slices(&[&payload]), Accepted::All));
        assert!(matches!(tail.settle(), Settle::Clear));
        assert_eq!(*got.lock().unwrap(), payload);
    }

    /// A pending suffix already at the cap, or one an offer would push past it, is refused rather
    /// than accepted and copied: a tail that counted only what was already kept would let each
    /// accepted window grow the buffer by another window past `MOST`.
    #[test]
    fn the_tail_refuses_an_offer_the_pending_suffix_cannot_hold() {
        struct Trickle {
            taken: usize,
            cap: usize,
        }
        impl std::io::Write for Trickle {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if self.taken >= self.cap {
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                let n = data.len().min(self.cap - self.taken);
                self.taken += n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::proxy::FrameWrite for Trickle {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                for part in parts {
                    if self.write(part).is_err() {
                        return false;
                    }
                }
                true
            }
        }
        let half = Tail::MOST / 2;
        let mut tail = Tail::new(Box::new(Trickle {
            taken: 0,
            cap: half,
        }));
        let first = vec![0x11u8; Tail::MOST];
        assert!(matches!(tail.offer_slices(&[&first]), Accepted::All));
        assert!(
            matches!(tail.settle(), Settle::Parked),
            "a full socket parks"
        );
        let over = vec![0x22u8; half + 1];
        assert!(matches!(tail.offer_slices(&[&over]), Accepted::Full));
        let fits = vec![0x33u8; 1];
        assert!(matches!(tail.offer_slices(&[&fits]), Accepted::All));
    }

    /// A peer that advertises a one-byte frame cannot overflow the eight batch slots: `try_send`
    /// hands the message to the blocking writer, whose frame-by-frame shape
    /// `messages_frame_identically_at_every_chunk_size` already holds.
    #[test]
    fn a_one_byte_frame_does_not_overflow_the_batch() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), 1, u64::MAX);
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        assert!(matches!(
            writer.try_send(&data),
            crate::proxy::Push::Took(64)
        ));
        assert_ne!(peer.lock().unwrap().writes.len(), 0);
    }

    /// A reader that has already ended loses the next push instead of parking the forward lane on a
    /// window the dead peer will never raise.
    #[test]
    fn a_dead_reader_loses_the_forward_push() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, u64::MAX);
        writer.shared.dead.store(true, Ordering::SeqCst);
        assert!(matches!(writer.try_send(b"ping"), crate::proxy::Push::Lost));
        assert!(
            peer.lock().unwrap().writes.is_empty(),
            "a dead reader took bytes"
        );
    }

    /// The client half-close sends the gRPC end marker once; the later full close does not repeat it.
    #[test]
    fn upload_done_ends_the_request_once() {
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, u64::MAX);
        writer.upload_done();
        writer.close();
        let peer = peer.lock().unwrap();
        assert_eq!(peer.writes.concat(), frame(T_DATA, F_END, 1, &message(b"")));
    }

    /// A response that ends at `END_STREAM` closes the read half, not the connection: the upload
    /// lane can still send bytes the peer has not taken.
    #[test]
    fn a_normal_end_stream_keeps_the_writer_alive() {
        let mut reader = dial(&[(F_END, message(b"ping"))]);
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 4);
        assert_eq!(reader.read(&mut got).expect("reads"), 0);
        assert!(reader.eof);
        mark_reader_dead(&mut reader);
        assert!(
            !reader.shared.dead.load(Ordering::SeqCst),
            "a normal END_STREAM was treated as a dead connection"
        );
    }

    /// An end-marked `HEADERS` that needs a continuation still ends the read half: the final
    /// `CONTINUATION` does not carry the flag, so the opening frame's `END_STREAM` must survive.
    #[test]
    fn an_end_stream_survives_a_continuation() {
        let block = block_encode(&[(":status", "200"), ("content-type", "application/grpc")]);
        let cut = block.len() / 2;
        let mut wire = frame(T_HEADERS, F_END, 1, &block[..cut]);
        wire.extend_from_slice(&frame(T_CONT, F_END_HEADERS, 1, &block[cut..]));
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 0);
        assert!(
            reader.remote_end && reader.eof,
            "END_STREAM was lost across the continuation"
        );
    }

    /// A half-close that cannot take the end marker leaves the completion retryable: the full close
    /// sends `F_END` once the peer grants the seven bytes the empty message needs.
    #[test]
    fn a_half_close_that_cannot_send_the_end_marker_is_retried() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(100)),
            ..Default::default()
        });
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, 0);
        let shared = Arc::clone(&writer.shared);
        writer.upload_done();
        {
            let mut send = shared.send.lock().unwrap();
            send.conn = u64::MAX;
            send.stream = u64::MAX;
        }
        shared.wake.notify_all();
        writer.close();
        crate::budgets::clear();
        let peer = peer.lock().unwrap();
        assert_eq!(
            peer.writes.concat(),
            frame(T_DATA, F_END, 1, &message(b"")),
            "the end marker was lost after a stalled half-close"
        );
    }

    /// A message that fails to decode is not a normal end: the read half is closed, but the writer must
    /// still see the failure and wake.
    #[test]
    fn an_undecodable_end_stream_is_not_a_normal_end() {
        let mut body = vec![0u8];
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(0xFF);
        let mut reader = dial(&[(F_END, body)]);
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 0);
        assert!(reader.eof);
        mark_reader_dead(&mut reader);
        assert!(
            reader.shared.dead.load(Ordering::SeqCst),
            "an undecodable END_STREAM was recorded as a normal end"
        );
    }

    /// The control frames the write half needs still arrive after the read half ends: a `WINDOW_UPDATE`
    /// behind `END_STREAM` raises the writer's window instead of waiting on a reader that returned.
    #[test]
    fn a_window_update_after_end_stream_still_reaches_the_writer() {
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        wire.extend_from_slice(&frame(T_DATA, F_END, 1, &message(b"ping")));
        let inc = 100u32.to_be_bytes();
        wire.extend_from_slice(&frame(T_WINDOW, 0, 0, &inc));
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        reader.poll = true;
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 4);
        assert_eq!(reader.read(&mut got).expect("reads"), 0);
        assert_eq!(
            reader.shared.send.lock().unwrap().conn,
            65_535 + 100,
            "a WINDOW_UPDATE after END_STREAM did not reach the writer"
        );
    }

    /// A stalled end marker takes its whole window before the first byte, so the retry in `close` cannot
    /// replay a prefix the peer already saw.
    #[test]
    fn a_stalled_end_marker_is_not_replayed() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(100)),
            ..Default::default()
        });
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), 1, 5);
        let shared = Arc::clone(&writer.shared);
        writer.upload_done();
        {
            let mut send = shared.send.lock().unwrap();
            send.conn = u64::MAX;
            send.stream = u64::MAX;
        }
        shared.wake.notify_all();
        writer.close();
        crate::budgets::clear();
        let prefix = message(b"");
        let mut want = Vec::new();
        for (i, byte) in prefix.iter().enumerate() {
            let flags = if i + 1 == prefix.len() { F_END } else { 0 };
            want.extend_from_slice(&frame(T_DATA, flags, 1, &[*byte]));
        }
        assert_eq!(
            peer.lock().unwrap().writes.concat(),
            want,
            "a stalled end marker was replayed from the start"
        );
    }

    /// DATA after a normal `END_STREAM` is refused rather than buffered: the read half cannot consume
    /// it, so keeping it would grow the reader without a bound.
    #[test]
    fn data_after_end_stream_is_not_buffered() {
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        wire.extend_from_slice(&frame(T_DATA, F_END, 1, &message(b"ping")));
        for _ in 0..3 {
            wire.extend_from_slice(&frame(T_DATA, 0, 1, &message(b"pong")));
        }
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        reader.poll = true;
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 4);
        assert_eq!(&got[..4], b"ping");
        let before = reader.msg.len();
        assert_eq!(reader.read(&mut got).expect("reads"), 0);
        assert!(
            reader.msg.len() <= before,
            "DATA after END_STREAM grew the read buffer"
        );
    }

    /// A peer that keeps sending control frames after `END_STREAM` must not pin the read: a burst
    /// yields so the relay can half-close, and the next turn pumps the rest.
    #[test]
    fn post_end_pumping_yields_after_a_burst() {
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        wire.extend_from_slice(&frame(T_DATA, F_END, 1, &message(b"ping")));
        let total = 64u64;
        for seq in 1..=total {
            wire.extend_from_slice(&frame(T_PING, F_ACK, 0, &seq.to_be_bytes()));
        }
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Sink::default(),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        reader.poll = true;
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 4);
        let error = reader.read(&mut got).expect_err("pumping must yield");
        assert!(crate::proxy::is_timeout(&error), "{error:?}");
        let pumped = reader.shared.pong.load(Ordering::SeqCst);
        assert!(pumped > 0 && pumped < total, "pumped {pumped} of {total}");
        assert!(request_ended(&reader));
    }

    /// `END_STREAM` is only a normal request end once the body it closed has been handed out: a
    /// half-close on the flag alone would cut off bytes still buffered behind the last read.
    #[test]
    fn request_ended_waits_for_the_buffered_body() {
        let body = vec![7u8; 64];
        let mut reader = dial(&[(F_END, message(&body))]);
        let mut one = [0u8; 1];
        assert_eq!(reader.read(&mut one).expect("reads"), 1);
        assert!(
            !request_ended(&reader),
            "reported the request ended with the body still buffered"
        );
        let mut rest = vec![0u8; body.len() - 1];
        assert_eq!(reader.read(&mut rest).expect("reads"), rest.len());
        assert!(request_ended(&reader));
    }

    /// An empty end marker reserves its whole window once: the per-frame loop must not charge it again,
    /// or a marker that fits the window exactly is refused and leaks the reservation.
    #[test]
    fn an_empty_end_marker_charges_its_window_once() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(100)),
            ..Default::default()
        });
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), 1, 7);
        let shared = Arc::clone(&writer.shared);
        writer.upload_done();
        {
            let send = shared.send.lock().unwrap();
            assert_eq!(
                send.conn, 0,
                "the end marker charged the connection window twice"
            );
            assert_eq!(
                send.stream, 0,
                "the end marker charged the stream window twice"
            );
        }
        let prefix = message(b"");
        let mut want = Vec::new();
        for (i, byte) in prefix.iter().enumerate() {
            let flags = if i + 1 == prefix.len() { F_END } else { 0 };
            want.extend_from_slice(&frame(T_DATA, flags, 1, &[*byte]));
        }
        crate::budgets::clear();
        assert_eq!(
            peer.lock().unwrap().writes.concat(),
            want,
            "the end marker did not reach the peer"
        );
    }

    /// The gathered batch reaches the peer before its own credit parks the writer: a peer grants for
    /// bytes it has seen, so frames held in a batch cannot wait behind the window they are the thing
    /// that would raise. The witness is a write seen while the thread is still inside `send` — with the
    /// flush taken away the loop below runs out its bound instead — and the run joins only once the
    /// credit arrives.
    #[test]
    fn a_gathered_batch_flushes_before_a_window_that_has_not_arrived() {
        let one_hunk = HUNK as u64;
        let data: Vec<u8> = (0..4 * HUNK).map(|i| (i % 251) as u8).collect();
        let want = frames(&data);
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, one_hunk);
        let shared = Arc::clone(&writer.shared);
        let handle = thread::spawn(move || writer.send(&data));
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while peer.lock().unwrap().writes.is_empty() {
            assert!(
                std::time::Instant::now() < until,
                "the writer parked with its own batch unwritten"
            );
            thread::yield_now();
        }
        assert!(
            !handle.is_finished(),
            "one frame of window cannot carry the read"
        );
        {
            let mut send = shared.send.lock().unwrap();
            send.conn = u64::MAX;
            send.stream = u64::MAX;
        }
        shared.wake.notify_all();
        assert!(handle.join().expect("joins"));
        let peer = peer.lock().unwrap();
        assert_eq!(
            peer.writes.concat(),
            want,
            "the same frames, in the same order"
        );
    }

    /// The same buffer answers every frame: a body the size of the one before it is appended in place, so no message pays a reallocation of the bytes still live in it, and a caller that drains each hunk before the next arrives never pays a reclaim move either.
    #[test]
    fn the_message_buffer_is_reused_not_reallocated() {
        let hunk = [b'x'; HUNK];
        let mut reader = dial(&[
            (0, message(&hunk)),
            (0, message(&hunk)),
            (F_END, message(&hunk)),
        ]);
        let mut got = [0u8; HUNK];
        reader.read_exact(&mut got).expect("reads a hunk");
        assert_eq!(got, hunk);
        let cap = reader.msg.capacity();
        assert!(cap > 0, "the body landed somewhere");
        for _ in 1..3 {
            reader.read_exact(&mut got).expect("reads a hunk");
            assert_eq!(got, hunk);
            assert_eq!(reader.msg.capacity(), cap, "a same-sized body reallocated");
        }
        assert_eq!(reader.staged, 0, "a drained buffer staged nothing");
        assert_eq!(reader.reclaims, 0, "a drained buffer took a reclaim move");
    }

    /// The witnesses for `carrier-grpc credit-bytes 2097152`, `window-update-writes-per-credit 1` and `window-update-frames-per-credit 2`: a credit is still the peer's two frames, byte for byte, in one write — granted once for a whole half-window of bodies, not once per frame, and never so late that the peer has spent its window waiting for it.
    #[test]
    fn a_credit_grants_the_window_it_owes_in_one_write() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let hunk = [b'x'; HUNK];
        let body = message(&hunk);
        // The first frame that reaches a credit's worth, and two credits of frames, so the run sees both sides of the threshold twice.
        let per_credit = (CREDIT_AT as usize - 1) / body.len() + 1;
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        for _ in 0..per_credit * 2 {
            wire.extend_from_slice(&frame(T_DATA, 0, 1, &body));
        }
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Calls(Arc::clone(&calls)),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        calls.lock().unwrap().clear();
        let owed = (per_credit * body.len()) as u32;
        assert!(owed >= CREDIT_AT, "a credit is owed at the threshold");
        assert!(
            owed < WINDOW,
            "the credit lands while the peer still has window to send into"
        );
        let mut got = [0u8; HUNK];
        let mut want = Vec::new();
        for credit in 0..2 {
            for _ in 1..per_credit {
                reader.read_exact(&mut got).expect("reads a hunk");
                assert_eq!(got, hunk);
            }
            assert_eq!(
                calls.lock().unwrap().len(),
                credit,
                "a body short of a credit's worth grants nothing"
            );
            reader.read_exact(&mut got).expect("reads the last hunk");
            assert_eq!(got, hunk);
            let inc = owed.to_be_bytes();
            let mut pair = frame(T_WINDOW, 0, 0, &inc);
            pair.extend_from_slice(&frame(T_WINDOW, 0, 1, &inc));
            want.push(pair);
            assert_eq!(
                *calls.lock().unwrap(),
                want,
                "one write per credit carries the connection and the stream update, and their increments are every body that landed since the last one"
            );
        }
    }

    /// The witness for `carrier-grpc connection-window-credit-at-preface 4128769`: the grant a batched credit rests on, because a peer that started at the RFC's connection window would have to wait for the first credit to send a second window's worth.
    #[test]
    fn the_preface_grants_the_peer_a_whole_window() {
        let mut settings = Vec::with_capacity(14);
        settings.extend_from_slice(&S_WINDOW.to_be_bytes());
        settings.extend_from_slice(&WINDOW.to_be_bytes());
        settings.extend_from_slice(&S_MAX_CONCURRENT.to_be_bytes());
        settings.extend_from_slice(&1u32.to_be_bytes());
        let mut want = frame(T_SETTINGS, 0, 0, &settings);
        want.extend_from_slice(&frame(T_WINDOW, 0, 0, &(WINDOW - 65_535).to_be_bytes()));

        let dialed = Arc::new(Mutex::new(Vec::new()));
        let (reader, writer) = connect_split(
            std::io::Cursor::new(Vec::new()),
            Calls(Arc::clone(&dialed)),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop((reader, writer));

        let served = Arc::new(Mutex::new(Vec::new()));
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[
                (":method", "POST"),
                (":path", "/x"),
                ("content-type", "application/grpc"),
            ]),
        ));
        let (reader, writer) =
            accept_split(std::io::Cursor::new(wire), Calls(Arc::clone(&served)), "/x")
                .expect("serves");
        drop((reader, writer));

        let mut head = MAGIC.to_vec();
        head.extend_from_slice(&want);
        assert_eq!(
            dialed.lock().unwrap()[0],
            head,
            "the client's preface, settings and top-up leave as one write"
        );
        assert_eq!(
            served.lock().unwrap()[0],
            want,
            "the server grants the same window before it reads a body"
        );
    }

    /// The witness that the peer is asked for one stream per connection: its next flow opens a
    /// fresh connection instead of hanging on this one, and a body sent after the headers still has
    /// a stream to land on.
    #[test]
    fn an_accepted_connection_advertises_one_stream_at_a_time() {
        use crate::h2::T_GOAWAY;
        let served = Arc::new(Mutex::new(Vec::new()));
        let mut wire = MAGIC.to_vec();
        wire.extend_from_slice(&frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[
                (":method", "POST"),
                (":path", "/x"),
                ("content-type", "application/grpc"),
            ]),
        ));
        let (reader, writer) =
            accept_split(std::io::Cursor::new(wire), Calls(Arc::clone(&served)), "/x")
                .expect("serves");
        drop((reader, writer));
        let text = served.lock().unwrap().concat();
        let mut setting = S_MAX_CONCURRENT.to_be_bytes().to_vec();
        setting.extend_from_slice(&1u32.to_be_bytes());
        assert!(
            text.windows(setting.len())
                .any(|part| part == setting.as_slice()),
            "the server asks the peer for one stream at a time"
        );
        let mut last = [0u8; 8];
        last[..4].copy_from_slice(&1u32.to_be_bytes());
        assert!(
            !text.windows(17)
                .any(|part| part == frame(T_GOAWAY, 0, 0, &last)),
            "the stream must outlive the headers for a peer that buffers its first body"
        );
    }

    /// The witness for `carrier-grpc message-bytes-moved-per-padded-frame 0`: the pad byte opens a message region, so the parser steps over it and the frame's length drops the tail, and the message between them stays where it landed.
    #[test]
    fn a_padded_frame_opens_a_message_without_moving() {
        let mut body = vec![3u8];
        body.extend_from_slice(&message(b"ping"));
        body.extend_from_slice(&[0xA5; 3]);
        let mut reader = dial(&[(F_PADDED | F_END, body)]);
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"ping");
        assert_eq!(reader.staged, 0, "the pad byte and tail cost no move");
    }

    /// The witness for `carrier-grpc padded-frame-credit-octets`: RFC 7540 6.9 puts the
    /// whole DATA payload — the Pad Length octet and the Padding included — into the
    /// flow-control window, so a padded frame gives the peer its wire length back and a
    /// peer with a strict window does not lose an octet per frame.
    #[test]
    fn a_padded_frame_credits_its_whole_wire_payload() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let hunk = [b'x'; HUNK];
        // A padded frame: the pad byte, the message, the pad tail.
        let mut padded = vec![3u8];
        padded.extend_from_slice(&message(&hunk));
        padded.extend_from_slice(&[0xA5; 3]);
        let wire_len = padded.len();
        let per_credit = (CREDIT_AT as usize - 1) / wire_len + 1;
        let mut wire = frame(
            T_HEADERS,
            F_END_HEADERS,
            1,
            &block_encode(&[(":status", "200"), ("content-type", "application/grpc")]),
        );
        for _ in 0..per_credit {
            wire.extend_from_slice(&frame(T_DATA, F_PADDED, 1, &padded));
        }
        let (mut reader, writer) = connect_split(
            std::io::Cursor::new(wire),
            Calls(Arc::clone(&calls)),
            "127.0.0.1",
            "/x",
        )
        .expect("dials");
        drop(writer);
        calls.lock().unwrap().clear();
        let mut got = [0u8; HUNK];
        for _ in 0..per_credit {
            reader.read_exact(&mut got).expect("reads a hunk");
            assert_eq!(got, hunk);
        }
        // The grant: one write carrying the connection's and the stream's update.
        let inc = (per_credit * wire_len) as u32;
        let mut want = frame(T_WINDOW, 0, 0, &inc.to_be_bytes());
        want.extend_from_slice(&frame(T_WINDOW, 0, 1, &inc.to_be_bytes()));
        let sent = calls.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "one credit, one write");
        assert_eq!(
            sent[0], want,
            "the increment is every frame's wire length, the pad byte and the pad tail included"
        );
        assert!(
            inc > (per_credit * (wire_len - 4)) as u32,
            "and not what the cut left"
        );
    }

    /// The move a padded frame still pays, and the witness that the staging counter counts: here the pad byte cuts into a message the frame before had started, so only what follows it moves down.
    #[test]
    fn a_padded_frame_that_cuts_into_a_message_moves_only_what_follows_the_pad() {
        let split = message(b"ping");
        let mut body = vec![1u8];
        body.extend_from_slice(&split[6..]);
        body.push(0xA5);
        let mut reader = dial(&[(0, split[..6].to_vec()), (F_PADDED | F_END, body)]);
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"ping");
        assert_eq!(
            reader.staged,
            split.len() - 6,
            "only the bytes after the pad byte move"
        );
    }

    /// `END_STREAM` in the middle of a message is a refusal, not a short delivery: the envelope promised bytes the stream did not carry.
    #[test]
    fn an_end_stream_mid_message_delivers_nothing() {
        let mut body = message(b"ping");
        body.truncate(body.len() - 2);
        let mut reader = dial(&[(F_END, body)]);
        let mut got = [0u8; 8];
        assert_eq!(reader.read(&mut got).expect("reads"), 0);
        assert!(reader.eof);
    }

    #[test]
    fn messages_frame_identically_at_every_chunk_size() {
        for max in [1usize, 2, 5, 6, 7, 8, 11, 16, 100, 16_384] {
            for len in [0usize, 1, 4, 127, 300] {
                let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut want = vec![0u8; 5];
                want.push(0x0A);
                push_varint(&mut want, len as u64);
                want.extend_from_slice(&data);
                let hunk_len = (want.len() - 5) as u32;
                want[1..5].copy_from_slice(&hunk_len.to_be_bytes());

                let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
                let port = listener.local_addr().expect("addr").port();
                let handle = thread::spawn(move || {
                    let (stream, _) = listener.accept().expect("accepts");
                    let shared = Arc::new(Shared {
                        stream: Mutex::new(
                            Box::new(stream) as Box<dyn crate::proxy::FrameWrite + Send>
                        ),
                        send: Mutex::new(SendWindow {
                            conn: u64::MAX,
                            stream: u64::MAX,
                            unlimited: false,
                        }),
                        wake: Condvar::new(),
                        max_frame: Mutex::new(max),
                        init: Mutex::new(u64::from(WINDOW)),
                        ended: AtomicBool::new(false),
                        upload_ended: AtomicBool::new(false),
                        upload_gate: Mutex::new(()),
                        dead: AtomicBool::new(false),
                        pong: AtomicU64::new(0),
                        muxed: false,
                    });
                    let writer = GrpcWriter {
                        shared,
                        stream: 1,
                        multi: false,
                    };
                    let mut batch = Gather::new();
                    assert!(
                        writer.message(&data, max, true, &mut batch),
                        "max {max} len {len}"
                    );
                    assert!(
                        matches!(batch.flush(&writer.shared), Accepted::All),
                        "max {max} len {len}"
                    );
                });
                let mut read = Connection::connect(("127.0.0.1", port)).expect("connects");
                let mut wire = Vec::new();
                read.read_to_end(&mut wire).expect("reads");
                handle.join().expect("joins");
                let mut body = Vec::new();
                let mut at = 0;
                while at < wire.len() {
                    let head = &wire[at..at + 9];
                    let len = usize::from(head[0]) << 16
                        | usize::from(head[1]) << 8
                        | usize::from(head[2]);
                    assert_eq!(head[3], T_DATA, "max {max} len {len}");
                    assert_eq!(u32::from_be_bytes(head[5..9].try_into().unwrap()), 1);
                    at += 9;
                    body.extend_from_slice(&wire[at..at + len]);
                    at += len;
                }
                assert_eq!(body, want, "max {max} len {len}");
            }
        }
    }

    /// The ops probe the page's `ops-retired-instructions` row names: the two per-message math steps, a gRPC envelope assembled and a `Hunk` parsed, over buffers the compiler cannot fold — no I/O, so the frame is the loops and the methods.
    #[test]
    fn the_envelope_and_the_hunk_cost_their_loops_and_nothing_else() {
        let messages = std::hint::black_box([
            &[0x0A, 0x04, b'p', b'i', b'n', b'g'][..],
            &[0x12, 0x02, 0x01, 0x02, 0x0A, 0x02, b'p', b'g'][..],
        ]);
        let mut prefix = [0u8; 16];
        let mut acc = 0usize;
        for _ in 0..512 {
            for msg in messages {
                let (off, data) = hunk_decode(msg).expect("decodes");
                acc += off + data.len() + frame_prefix(data.len(), &mut prefix);
            }
        }
        assert!(acc > 0);
        std::hint::black_box(&prefix);
    }

    #[test]
    fn frame_prefix_matches_the_vec_form_at_varint_edges() {
        for len in [0usize, 1, 127, 128, 300, 16383, 16384, 1 << 21, 1 << 28] {
            let mut varint = Vec::new();
            push_varint(&mut varint, len as u64);
            let inner = (1 + varint.len() + len) as u32;
            let mut want = vec![0u8];
            want.extend_from_slice(&inner.to_be_bytes());
            want.push(0x0A);
            want.extend_from_slice(&varint);
            let mut prefix = [0u8; 16];
            let plen = frame_prefix(len, &mut prefix);
            assert_eq!(&prefix[..plen], &want[..], "len {len}");
        }
    }

    #[test]
    fn tunnel_carries_an_echo_over_loopback() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/TunnelService/Tun").expect("serves");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
            drain(&mut reader);
            writer.close();
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) =
            connect(stream, "127.0.0.1", "/TunnelService/Tun").expect("dials");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        writer.close();
        drain(&mut reader);
        server.join().expect("joins");
    }

    fn drain(reader: &mut GrpcReader) {
        let mut buf = [0u8; 1024];
        while reader.read(&mut buf).unwrap_or(0) != 0 {}
    }

    /// A hunk is one frame: the envelope and the payload its length announces fit the DATA frame
    /// the peer advertised, so a peer parses the message where it landed instead of reassembling it
    /// from a frame of its own. The reference's client reassembles every message that crosses one.
    #[test]
    fn a_hunk_fits_the_frame_that_carries_it() {
        const _: () = assert!(4 * (HUNK - 1) <= 65_535);
        const _: () = assert!(4 * HUNK > 65_535);
        let fit = message_payload(HUNK - 1);
        assert_eq!(
            fit, 16_375,
            "the envelope and the tag leave this much of a frame one byte under the width the window packs"
        );
        assert_eq!(fit + 8, HUNK - 1);
        let data: Vec<u8> = (0..4 * HUNK).map(|i| (i % 251) as u8).collect();
        let peer = Arc::new(Mutex::new(Peer::default()));
        let writer = writer_over(Recorder(Arc::clone(&peer)), HUNK, u64::MAX);
        assert!(writer.send(&data));
        let wire = peer.lock().unwrap().writes.concat();
        let mut at = 0;
        let mut frames = 0;
        let mut got = Vec::new();
        while at < wire.len() {
            assert!(wire.len() - at >= 9, "a frame head was cut short");
            let len = usize::from(wire[at]) << 16
                | usize::from(wire[at + 1]) << 8
                | usize::from(wire[at + 2]);
            assert_eq!(wire[at + 3], T_DATA, "only DATA frames carry a hunk");
            assert!(wire.len() - at - 9 >= len, "a frame body was cut short");
            let body = &wire[at + 9..at + 9 + len];
            assert!(body.len() >= 5, "a DATA frame opens no message");
            assert!(body.len() < HUNK, "a hunk is wider than the window packs");
            let announced = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
            assert_eq!(announced + 5, body.len(), "a hunk crossed a frame boundary");
            let (_, payload) = hunk_decode(&body[5..]).expect("the hunk decodes");
            got.extend_from_slice(payload);
            frames += 1;
            at += 9 + len;
        }
        assert_eq!(at, wire.len(), "a frame was cut short");
        assert_eq!(got, data, "the payload is unchanged");
        assert_eq!(frames, 5, "64 KiB at 16 KiB frames is five hunks");
    }

    #[test]
    fn tunnel_rejects_a_wrong_path() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/TunnelService/Tun").is_none());
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (_, writer) = connect(stream, "127.0.0.1", "/other/Tun").expect("dials");
        drop(writer);
        server.join().expect("joins");
    }

    struct EchoService;

    impl crate::xhttp_h2::H2Service for EchoService {
        fn open(
            &self,
            conn: &Arc<crate::xhttp_h2::H2Conn>,
            sid: u32,
            _block: &[u8],
            end_stream: bool,
        ) -> bool {
            let Some((body, _head, out)) = conn.open(sid, end_stream) else {
                return false;
            };
            if !conn.respond(
                sid,
                &[(":status", "200"), ("content-type", "application/grpc")],
            ) {
                return false;
            }
            let (mut reader, writer) = mux_stream(conn, body, out, sid, Method::Hunk);
            crate::budgets::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if !writer.send(&buf[..n]) {
                                break;
                            }
                        }
                    }
                }
                writer.close();
            });
            true
        }
    }

    #[test]
    fn one_connection_serves_two_streams_at_once() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let write = stream.try_clone().expect("clones");
            crate::xhttp_h2::serve_h2_service(stream, write, &EchoService, None);
        });
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(MAGIC).expect("preface");
        assert!(write_frame(&mut client, T_SETTINGS, 0, 0, &[]));
        let head = block_encode(&[
            (":method", "POST"),
            (":path", "/TunnelService/Tun"),
            ("content-type", "application/grpc"),
        ]);
        for id in [1, 3] {
            assert!(write_frame(
                &mut client,
                T_HEADERS,
                F_END_HEADERS,
                id,
                &head
            ));
        }
        assert!(write_frame(&mut client, T_DATA, 0, 1, &message(b"one")));
        assert!(write_frame(&mut client, T_DATA, F_END, 3, &message(b"two")));
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("arms");
        let mut got: Vec<(u32, Vec<u8>)> = Vec::new();
        while got.len() < 2 {
            let (len, kind, _flags, id) = crate::h2::read_head(&mut client).expect("a frame");
            let mut body = vec![0u8; len];
            client.read_exact(&mut body).expect("body");
            if kind == T_DATA && !body.is_empty() {
                let (_, payload) = hunk_decode(&body[5..]).expect("a hunk");
                if !payload.is_empty() {
                    got.push((id, payload.to_vec()));
                }
            }
        }
        got.sort();
        assert_eq!(got, vec![(1, b"one".to_vec()), (3, b"two".to_vec())]);
        drop(client);
        server.join().expect("joins");
    }

    #[test]
    fn a_refused_reverse_request_resets_its_stream() {
        let id = [7u8; 16];
        let users = [crate::proxy::VlessUser {
            id,
            flow: ferrox_core::vless::Flow::None,
            email: String::new(),
            level: 0,
            reverse: None,
        }];
        let settings = GrpcSettings::path("/TunnelService/Tun");
        let opened = Arc::new(AtomicBool::new(false));
        let service = GrpcService::new(&settings, &users, true, opened);
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let write = stream.try_clone().expect("clones");
            crate::xhttp_h2::serve_h2_service(stream, write, &service, None);
        });
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(MAGIC).expect("preface");
        assert!(write_frame(&mut client, T_SETTINGS, 0, 0, &[]));
        let head = block_encode(&[
            (":method", "POST"),
            (":path", "/TunnelService/Tun"),
            ("content-type", "application/grpc"),
        ]);
        assert!(write_frame(&mut client, T_HEADERS, F_END_HEADERS, 1, &head));
        assert!(write_frame(
            &mut client,
            T_DATA,
            0,
            1,
            &message(&crate::proxy::vless_reverse_header(&id))
        ));
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("arms");
        let mut refused = false;
        while !refused {
            let (len, kind, _flags, sid) = crate::h2::read_head_bounded(&mut client)
                .expect("the refused stream was never reset");
            let mut body = vec![0u8; len];
            client.read_exact(&mut body).expect("body");
            if kind == T_RST {
                assert_eq!(sid, 1);
                assert_eq!(body[..4], E_REFUSED.to_be_bytes());
                refused = true;
            }
        }
        drop(client);
        server.join().expect("joins");
    }

    /// A sealed connection's demux is a lane, not a thread: sixteen silent connections cost the demux pool's cap.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_sealed_demux_rides_the_lane_pool() {
        struct Silent;
        impl Read for Silent {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
        }
        if !crate::conn::in_a_quiet_process("grpc::tests::a_sealed_demux_rides_the_lane_pool") {
            return;
        }
        let settings = GrpcSettings::path("/p");
        let before = crate::conn::live_threads();
        for _ in 0..16 {
            serve_muxed(Silent, NullSink, &settings, &[], true);
        }
        let until = Instant::now() + Duration::from_secs(5);
        while crate::proxy::lane_pool::demux_workers() == 0 && Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        let lanes = crate::proxy::lane_pool::demux_workers();
        assert!(lanes >= 1, "the sealed demux never reached the lane pool");
        let grown = crate::conn::live_threads().saturating_sub(before);
        assert!(
            grown <= crate::proxy::lane_pool::demux_lanes() + 1,
            "sixteen sealed demuxes grew the process by {grown} threads past the demux pool's {} lanes and its reaper",
            crate::proxy::lane_pool::demux_lanes()
        );
    }
}
