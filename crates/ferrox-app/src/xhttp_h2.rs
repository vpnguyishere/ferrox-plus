// xHTTP over HTTP/2: one connection multiplexes many requests the way many TCP connections would — each stream is one GET, POST or packet — and the H1 dispatch is reused byte for byte, headers re-serialized into the H1-style head the same validators read and the response head parsed back into H2 HEADERS.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::h2::{
    block_encode, frame_head, write_frame, Decoder, E_FRAME_SIZE, E_PROTOCOL, E_REFUSED, F_ACK,
    F_END, F_END_HEADERS, F_PADDED, F_PRIORITY, HEAD_CAP, MAGIC, S_MAX_FRAME, S_WINDOW, T_CONT,
    T_DATA, T_GOAWAY, T_HEADERS, T_PING, T_RST, T_SETTINGS, T_WINDOW, WINDOW,
};
use crate::proxy::{VlessUser, VlessUsers};
use crate::xhttp::XhttpSettings;

const CONN_WINDOW_TOP_UP: u32 = 16 * 1024 * 1024 - 65_535;
const MAX_STREAMS: u32 = 100;
/// The default `SETTINGS_MAX_FRAME_SIZE` (RFC 7540 6.5.2): the largest inbound frame we accept because we never advertise a larger one.
const MAX_RECV_FRAME: usize = 16_384;
/// The two `WINDOW_UPDATE` frames one credit grants differ only by stream id, so twenty of their twenty-six bytes are constant; the connection frame keeps the first slot because that is the order it was written in.
const CREDIT_TEMPLATE: [u8; 26] = {
    let mut out = [0u8; 26];
    // length 4, WINDOW_UPDATE, no flags, stream 0 at [0..13], stream id at [13..26].
    out[2] = 4;
    out[3] = T_WINDOW;
    out[15] = 4;
    out[16] = T_WINDOW;
    out
};

/// The DATA frames one downlink write carries: a promoted relay window is `64 KiB`, four frames of the default `SETTINGS_MAX_FRAME_SIZE`, so one window reaches the peer as one vectored write.
const DATA_FRAMES_PER_WRITE: usize = 8;

const NO_PART: &[u8] = &[];

/// One credit is one 26-byte write holding both `WINDOW_UPDATE` frames, the largest control frame queued, and a batch is one write.
const CREDIT_FRAME: usize = 26;
const CONTROL_MAX: usize = CREDIT_FRAME;
const CONTROL_BATCH: usize = 8;

/// A window's DATA frames held apart rather than staged together: each nine-byte head in its own
/// slot and every payload still the caller's own slice, so one flush is one write whose bytes are
/// the same frames written one at a time.
struct DataBatch<'a> {
    heads: [[u8; 9]; DATA_FRAMES_PER_WRITE],
    bodies: [[&'a [u8]; 4]; DATA_FRAMES_PER_WRITE],
    counts: [u8; DATA_FRAMES_PER_WRITE],
    used: usize,
}

impl<'a> DataBatch<'a> {
    fn new() -> Self {
        Self {
            heads: [[0u8; 9]; DATA_FRAMES_PER_WRITE],
            bodies: [[NO_PART; 4]; DATA_FRAMES_PER_WRITE],
            counts: [0; DATA_FRAMES_PER_WRITE],
            used: 0,
        }
    }

    fn full(&self) -> bool {
        self.used == DATA_FRAMES_PER_WRITE
    }

    fn add(&mut self, stream: u32, payload: &'a [u8]) {
        self.add_parts(stream, &[payload]);
    }

    fn add_parts(&mut self, stream: u32, parts: &[&'a [u8]]) {
        if parts.is_empty() || parts.len() > self.bodies[self.used].len() {
            return;
        }
        let len: usize = parts.iter().map(|part| part.len()).sum();
        self.heads[self.used] = frame_head(len, T_DATA, 0, stream);
        self.bodies[self.used][..parts.len()].copy_from_slice(parts);
        self.counts[self.used] = parts.len() as u8;
        self.used += 1;
    }

    fn flush(&mut self, conn: &H2Conn) -> bool {
        let Ok(mut write) = conn.write.lock() else {
            return false;
        };
        self.flush_locked(conn, &mut **write)
    }

    /// The same bytes into a write half the caller already holds: a lane takes the lock without
    /// waiting, so a busy writer parks the lane instead of stacking workers behind the mutex.
    fn flush_locked(
        &mut self,
        conn: &H2Conn,
        write: &mut (dyn crate::proxy::FrameWrite + Send),
    ) -> bool {
        if self.used == 0 {
            return true;
        }
        let mut parts: [&[u8]; 5 * DATA_FRAMES_PER_WRITE] = [NO_PART; 5 * DATA_FRAMES_PER_WRITE];
        let mut pieces = 0;
        for at in 0..self.used {
            parts[pieces] = &self.heads[at];
            pieces += 1;
            for body in &self.bodies[at][..self.counts[at] as usize] {
                if !body.is_empty() {
                    parts[pieces] = body;
                    pieces += 1;
                }
            }
        }
        self.used = 0;
        if !write.write_slices(&parts[..pieces]) {
            conn.dead.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub(crate) struct H2StreamOut {
    conn: Arc<H2Conn>,
    stream: u32,
    _owner: Option<Arc<ClientOwner>>,
    client: bool,
}

/// The last writer clone out closes the dialed connection: a clone dropped by the relay must not.
pub(crate) struct ClientOwner {
    conn: Arc<H2Conn>,
}

impl std::fmt::Debug for ClientOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientOwner")
    }
}

impl Drop for ClientOwner {
    fn drop(&mut self) {
        self.conn.close_client();
    }
}

impl H2StreamOut {
    pub(crate) fn data(&self, payload: &[u8]) -> bool {
        self.conn.send_data(self.stream, payload)
    }

    /// The same offer for bodies built from several slices: each group is one frame, its parts
    /// written side by side, so a gRPC envelope and its payload stay one message in one frame.
    pub(crate) fn batch_parts(&self, groups: &[&[&[u8]]]) -> bool {
        self.conn.send_grouped(self.stream, groups)
    }

    /// The non-blocking offer: the whole batch or nothing, so a lane that finds no window parks
    /// instead of holding the worker the peer's credit is read on.
    pub(crate) fn try_batch_parts(&self, groups: &[&[&[u8]]]) -> Option<bool> {
        self.conn.try_send_grouped(self.stream, groups)
    }

    pub(crate) fn room(&self) -> u64 {
        self.conn.room(self.stream)
    }

    pub(crate) fn wait_room(&self, turn: std::time::Duration) {
        self.conn.wait_room(self.stream, turn);
    }

    pub(crate) fn settle(&self) -> crate::proxy::Settle {
        self.conn.settle()
    }

    pub(crate) fn bind_session(&self, sid: &str) {
        self.conn.bind_session(sid, self.stream, true);
    }

    pub(crate) fn bind_upload(&self, sid: &str) {
        self.conn.bind_session(sid, self.stream, false);
    }

    pub(crate) fn end(&self) {
        if self.client {
            self.conn.finish_stream(self.stream);
        } else {
            self.conn.end_stream(self.stream);
        }
        self.conn.end_session_of(self.stream);
    }

    /// The request is refused with its body unread: an `RST_STREAM` frees the stream and the credit
    /// it would otherwise keep granting a body nobody drains.
    pub(crate) fn reset(&self) {
        self.conn.reset(self.stream);
    }
}

pub(crate) struct H2Stream {
    state: Mutex<StreamState>,
    cv: Condvar,
    send_window: Mutex<u64>,
    responded: AtomicBool,
}

#[allow(clippy::struct_excessive_bools)]
struct StreamState {
    body: VecDeque<Vec<u8>>,
    ended: bool,
    /// The response `END_STREAM` has gone out: a stream retires once both halves are done.
    finished: bool,
    /// The request half ended locally: the peer still owes the response, so it does not end the read.
    request_ended: bool,
    /// The upload reader left at a finished response while the client still holds the request open.
    abandoned: bool,
    /// The session ended under the reader, so later DATA is discarded instead of queued for an answer already owed.
    stopped: bool,
    /// The response status a client decoded, so a packet POST can refuse a non-2xx answer.
    status: Option<u16>,
    dead: bool,
}

impl StreamState {
    /// Whether the reader has nothing left to take: the peer's `END_STREAM`, or our own half
    /// ending on the side that reads requests. A client's request half ending still expects an
    /// answer on the same stream.
    fn read_ended(&self) -> bool {
        self.ended || (self.finished && !self.request_ended)
    }

    /// Both halves are done, so the stream can retire: the peer's `END_STREAM` and the half this
    /// side sent, whichever end it was.
    fn both_ended(&self) -> bool {
        self.ended && (self.finished || self.request_ended)
    }
}

impl H2Stream {
    /// The stream is gone from the connection, not merely done reading: a sender waiting for
    /// credit on it has nothing left to write, while an ended request still has a response to send.
    fn gone(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dead
    }
}

/// Control frames are written by their own thread: a `WINDOW_UPDATE` or ACK produced while
/// reading must never wait on a data write the peer has not drained, or two bulk directions
/// hold each other's reader.
enum Control {
    Inline,
    Threaded(Arc<ControlQueue>),
}

/// The most control frames an unread peer may park before the connection ends: a peer that
/// sends PINGs or empty SETTINGS while withholding reads put one element on the queue per
/// inbound frame, so the backlog has to be bounded rather than grown.
const CONTROL_QUEUE_MAX: usize = 1024;

type SharedWriter = Arc<Mutex<Box<dyn crate::proxy::FrameWrite + Send>>>;

struct ControlQueue {
    frames: Mutex<VecDeque<(u8, [u8; CONTROL_MAX])>>,
    go: Condvar,
    stop: AtomicBool,
    /// Frames queued or taken into a batch and not yet written: the shutdown grace starts from zero
    /// here, so it begins after the last refusal is on the wire rather than before it.
    pending: AtomicUsize,
    /// The instant the queue last reached empty, so a waiter that wakes after the deadline can
    /// still tell an in-deadline drain from a late one.
    done: Mutex<Option<std::time::Instant>>,
    /// Set by the worker when its own write fails, so the connection it serves ends with it
    /// instead of admitting frames no one will ever drain.
    dead: Arc<AtomicBool>,
}

impl Control {
    fn threaded(write: SharedWriter, dead: Arc<AtomicBool>) -> Self {
        let queue = Arc::new(ControlQueue {
            frames: Mutex::new(VecDeque::new()),
            go: Condvar::new(),
            stop: AtomicBool::new(false),
            pending: AtomicUsize::new(0),
            done: Mutex::new(None),
            dead,
        });
        let worker = Arc::clone(&queue);
        let spawned = std::thread::Builder::new()
            .name("ferrox-h2-control".into())
            .spawn(move || {
                let mut batch = [0u8; CONTROL_MAX * CONTROL_BATCH];
                loop {
                    let (total, used) = {
                        let mut queue =
                            worker.frames.lock().unwrap_or_else(PoisonError::into_inner);
                        loop {
                            if !queue.is_empty() {
                                break;
                            }
                            if worker.stop.load(Ordering::SeqCst) {
                                return;
                            }
                            queue = worker
                                .go
                                .wait(queue)
                                .unwrap_or_else(PoisonError::into_inner);
                        }
                        let mut used = 0;
                        let mut total = 0;
                        while used < CONTROL_BATCH {
                            let Some((len, frame)) = queue.pop_front() else {
                                break;
                            };
                            let at = total;
                            batch[at..at + len as usize].copy_from_slice(&frame[..len as usize]);
                            total += len as usize;
                            used += 1;
                        }
                        (total, used)
                    };
                    let Ok(mut out) = write.lock() else {
                        worker.dead.store(true, Ordering::SeqCst);
                        return;
                    };
                    if !out.write_slices(&[&batch[..total]]) {
                        worker.dead.store(true, Ordering::SeqCst);
                        return;
                    }
                    let completed = std::time::Instant::now();
                    worker.pending.fetch_sub(used, Ordering::SeqCst);
                    if worker.pending.load(Ordering::SeqCst) == 0 {
                        *worker.done.lock().unwrap_or_else(PoisonError::into_inner) =
                            Some(completed);
                    }
                }
            });
        if spawned.is_ok() {
            Control::Threaded(queue)
        } else {
            Control::Inline
        }
    }

    /// Queue one frame, or answer `false` when the connection can no longer carry it: the
    /// worker is gone, or the peer has let `CONTROL_QUEUE_MAX` frames sit unread. A caller
    /// that gets `false` ends the connection rather than drop a credit on a live one.
    fn send(&self, len: usize, frame: [u8; CONTROL_MAX]) -> bool {
        match self {
            Control::Inline => true,
            Control::Threaded(queue) => {
                if queue.dead.load(Ordering::SeqCst) || queue.stop.load(Ordering::SeqCst) {
                    return false;
                }
                let mut frames = queue.frames.lock().unwrap_or_else(PoisonError::into_inner);
                if frames.len() >= CONTROL_QUEUE_MAX {
                    return false;
                }
                frames.push_back((len as u8, frame));
                queue.pending.fetch_add(1, Ordering::SeqCst);
                *queue.done.lock().unwrap_or_else(PoisonError::into_inner) = None;
                drop(frames);
                queue.go.notify_one();
                true
            }
        }
    }

    /// Waits for the queue and every batch already taken from it to be written before `grace`; `true`
    /// is a drain that completed inside that window, even when observed after it, and `false` is a
    /// peer that is not reading or a queue that died, so the shutdown has the deadline, not the write.
    fn drained(&self, grace: Duration) -> bool {
        let Control::Threaded(queue) = self else {
            return true;
        };
        let until = std::time::Instant::now() + grace;
        loop {
            if queue.dead.load(Ordering::SeqCst) {
                return false;
            }
            if queue.pending.load(Ordering::SeqCst) == 0 {
                let done = *queue.done.lock().unwrap_or_else(PoisonError::into_inner);
                return done.map_or_else(|| std::time::Instant::now() <= until, |at| at <= until);
            }
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn stop(&self) {
        match self {
            Control::Inline => {}
            Control::Threaded(queue) => {
                // The worker checks `stop` under `frames`, so it is stored under that guard and the notify follows: a bare store can land between the check and the wait.
                {
                    let _frames = queue.frames.lock().unwrap_or_else(PoisonError::into_inner);
                    queue.stop.store(true, Ordering::SeqCst);
                }
                queue.go.notify_all();
            }
        }
    }
}

pub(crate) struct H2Conn {
    write: SharedWriter,
    control: Control,
    streams: Mutex<HashMap<u32, Arc<H2Stream>>>,
    sessions: Mutex<HashSet<String>>,
    session_of: Mutex<HashMap<u32, String>>,
    upload_of: Mutex<HashMap<u32, String>>,
    send_conn: Mutex<u64>,
    wake: Condvar,
    decoder: Mutex<Decoder>,
    max_frame: Mutex<usize>,
    peer_initial: Mutex<u64>,
    dead: Arc<AtomicBool>,
    goaway: AtomicBool,
    refused: AtomicBool,
    /// The client half's transport: a client pumps frames on demand from its reader or a writer
    /// waiting for credit, so one thread owns the session and no parser thread outlives it.
    client_read: Option<Mutex<Box<dyn Read + Send>>>,
    /// The client frame a previous lane turn left half-read: a poll boundary hands the lane back,
    /// so bytes already taken from the transport are kept here instead of being read again.
    client_partial: Mutex<PartialFrame>,
    /// A response head split across `HEADERS` and `CONTINUATION` frames, gathered until
    /// `END_HEADERS` before `:status` is decoded.
    client_head: Mutex<Option<(u32, Vec<u8>, bool)>>,
    raw: Option<Arc<crate::conn::Connection>>,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
}

impl std::fmt::Debug for H2Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Conn").finish_non_exhaustive()
    }
}

impl Drop for H2Conn {
    fn drop(&mut self) {
        self.control.stop();
    }
}

pub(crate) struct H2StreamReader {
    conn: Arc<H2Conn>,
    stream: Arc<H2Stream>,
    id: u32,
    /// The frame the reader owns: the queue hands it over, so a window is a span of the loop's own
    /// allocation and a short read leaves the tail at the offset it already had.
    cur: Vec<u8>,
    at: usize,
    /// The start of the current idle stretch, so a lane's polls still end a body at the stall.
    idle_since: Option<std::time::Instant>,
}

impl H2StreamReader {
    /// The request is abandoned with its body still open: an `RST_STREAM` frees the table entry and
    /// the queued chunks, where dropping the handles would leave both for the connection's life.
    pub(crate) fn abort(&self) {
        self.reset_handle()();
    }

    /// The same reset carried past a handoff: a relay that fails to start has already taken the
    /// reader, so only this holds the stream it has to free.
    pub(crate) fn reset_handle(&self) -> impl FnOnce() + Send + 'static {
        let conn = Arc::clone(&self.conn);
        let id = self.id;
        move || conn.reset(id)
    }

    /// The response status decoded for a client stream, once its head has arrived.
    pub(crate) fn status(&self) -> Option<u16> {
        self.stream
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .status
    }
}

impl Read for H2StreamReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.at < self.cur.len() {
                let n = (self.cur.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.cur[self.at..self.at + n]);
                self.at += n;
                if self.at == self.cur.len() {
                    self.cur.clear();
                    self.at = 0;
                }
                self.idle_since = None;
                self.conn.replenish(self.id, n);
                return Ok(n);
            }
            let mut st = self
                .stream
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(front) = st.body.pop_front() {
                drop(st);
                self.cur = front;
                self.at = 0;
                continue;
            }
            if st.read_ended() {
                st.abandoned = !st.ended;
                drop(st);
                self.conn.forget_upload(self.id);
                return Ok(0);
            }
            if st.dead || self.conn.dead.load(Ordering::SeqCst) {
                drop(st);
                self.conn.forget_upload(self.id);
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            if self.conn.client_read.is_some() {
                drop(st);
                match self.conn.pump_read(
                    || {
                        let st = self
                            .stream
                            .state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        !st.body.is_empty() || st.read_ended() || st.dead
                    },
                    crate::proxy::relay_step_owns_poll(),
                ) {
                    Pumped::Alive => {}
                    Pumped::Yield => {
                        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                    }
                    Pumped::Dead => {
                        self.conn.forget_upload(self.id);
                        return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
                    }
                }
                continue;
            }
            // A lane step owns its thread for one poll; a body idle for the whole stall still ends.
            if crate::proxy::relay_step_owns_poll() {
                let since = *self.idle_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() >= crate::budgets::relay_stall() {
                    drop(st);
                    self.conn.forget_upload(self.id);
                    return Err(std::io::Error::other("h2 body stalled"));
                }
                let (_guard, wait) = self
                    .stream
                    .cv
                    .wait_timeout(st, crate::budgets::RELAY_POLL)
                    .unwrap_or_else(PoisonError::into_inner);
                if wait.timed_out() {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                continue;
            }
            let (next, wait) = self
                .stream
                .cv
                .wait_timeout(st, crate::budgets::relay_stall())
                .unwrap_or_else(PoisonError::into_inner);
            st = next;
            if wait.timed_out() {
                drop(st);
                self.conn.forget_upload(self.id);
                return Err(std::io::Error::other("h2 body stalled"));
            }
        }
    }
}

impl crate::proxy::WindowRead for H2StreamReader {
    fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
        loop {
            if self.at < self.cur.len() {
                let start = self.at;
                self.at = self.cur.len();
                self.idle_since = None;
                self.conn.replenish(self.id, self.cur.len() - start);
                return Ok(crate::proxy::Window::one(&self.cur[start..]));
            }
            let mut st = self
                .stream
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(front) = st.body.pop_front() {
                drop(st);
                self.cur = front;
                self.at = 0;
                continue;
            }
            if st.read_ended() {
                st.abandoned = !st.ended;
                drop(st);
                self.conn.forget_upload(self.id);
                return Ok(crate::proxy::Window::empty());
            }
            if st.dead || self.conn.dead.load(Ordering::SeqCst) {
                drop(st);
                self.conn.forget_upload(self.id);
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            if self.conn.client_read.is_some() {
                drop(st);
                match self.conn.pump_read(
                    || {
                        let st = self
                            .stream
                            .state
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        !st.body.is_empty() || st.read_ended() || st.dead
                    },
                    crate::proxy::relay_step_owns_poll(),
                ) {
                    Pumped::Alive => {}
                    Pumped::Yield => {
                        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                    }
                    Pumped::Dead => {
                        self.conn.forget_upload(self.id);
                        return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
                    }
                }
                continue;
            }
            if crate::proxy::relay_step_owns_poll() {
                let since = *self.idle_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() >= crate::budgets::relay_stall() {
                    drop(st);
                    self.conn.forget_upload(self.id);
                    return Err(std::io::Error::other("h2 body stalled"));
                }
                let (_guard, wait) = self
                    .stream
                    .cv
                    .wait_timeout(st, crate::budgets::RELAY_POLL)
                    .unwrap_or_else(PoisonError::into_inner);
                if wait.timed_out() {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                continue;
            }
            let (next, wait) = self
                .stream
                .cv
                .wait_timeout(st, crate::budgets::relay_stall())
                .unwrap_or_else(PoisonError::into_inner);
            st = next;
            if wait.timed_out() {
                drop(st);
                self.conn.forget_upload(self.id);
                return Err(std::io::Error::other("h2 body stalled"));
            }
        }
    }
}

pub(crate) struct H2StreamWriter {
    conn: Arc<H2Conn>,
    stream: u32,
    head: Vec<u8>,
    headed: bool,
}

/// The h1 fields a stream never forwards: the connection owns them.
fn hop_by_hop(name: &str) -> bool {
    [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
    ]
    .into_iter()
    .any(|hop| hop.eq_ignore_ascii_case(name))
}

/// HTTP/2 field names are lowercase (RFC 9113 8.2.1), so the canonical spelling is lowered in place.
fn lower_field_names(head: &mut [u8]) {
    let mut at = match head.windows(2).position(|w| w == b"\r\n") {
        Some(end) => end + 2,
        None => return,
    };
    while at < head.len() && !head[at..].starts_with(b"\r\n") {
        let Some(colon) = head[at..].iter().position(|&b| b == b':') else {
            return;
        };
        head[at..at + colon].make_ascii_lowercase();
        at = match head[at + colon..].windows(2).position(|w| w == b"\r\n") {
            Some(end) => at + colon + end + 2,
            None => return,
        };
    }
}

/// A response head's fields, status first: one pass and one list, and a hop-by-hop name is
/// recognised in place where the lowercase form it replaces allocated a `String` per line.
fn response_fields(head: &str) -> Vec<(&str, &str)> {
    let mut fields = Vec::with_capacity(1 + head.matches("\r\n").count());
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap_or("200");
    fields.push((":status", status));
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if hop_by_hop(name) {
            continue;
        }
        fields.push((name, value.trim()));
    }
    fields
}

impl H2StreamWriter {
    fn emit_headers(&mut self, head: &mut [u8]) -> bool {
        lower_field_names(head);
        let text = std::str::from_utf8(head).unwrap_or_default();
        let headers = response_fields(text);
        let block = block_encode(&headers);
        let max = *self
            .conn
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut at = 0;
        loop {
            let end = (at + max).min(block.len());
            let flags = if end == block.len() { F_END_HEADERS } else { 0 };
            let kind = if at == 0 { T_HEADERS } else { T_CONT };
            if !self.conn.frame(kind, flags, self.stream, &block[at..end]) {
                return false;
            }
            at = end;
            if at >= block.len() {
                break;
            }
        }
        self.headed = true;
        if let Some(s) = self
            .conn
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.stream)
        {
            s.responded.store(true, Ordering::SeqCst);
        }
        true
    }
}

impl Write for H2StreamWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.headed {
            let prior = self.head.len();
            self.head.extend_from_slice(buf);
            let mut scanned = prior;
            if let Some(at) = ferrox_core::foxy::head_end_grown(&self.head, &mut scanned) {
                let mut head = std::mem::take(&mut self.head);
                if !self.emit_headers(&mut head[..at + 4]) {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                }
                let body = &head[at + 4..];
                if !body.is_empty() && !self.conn.send_data(self.stream, body) {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                }
            }
            return Ok(buf.len());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.conn.send_data(self.stream, buf) {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::proxy::FrameWrite for H2StreamWriter {
    fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
        parts.iter().all(|part| self.write_all(part).is_ok())
    }
}

impl H2Conn {
    fn frame(&self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let Ok(mut write) = self.write.lock() else {
            return false;
        };
        if !write_frame(&mut **write, kind, flags, id, body) {
            self.dead.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// An ACK the read path owes the peer: queued, so a blocked data write cannot park the reader.
    fn send_control(&self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        if body.len() + 9 > CONTROL_MAX {
            return false;
        }
        let mut frame = [0u8; CONTROL_MAX];
        frame[..9].copy_from_slice(&frame_head(body.len(), kind, flags, id));
        frame[9..9 + body.len()].copy_from_slice(body);
        match &self.control {
            Control::Inline => self.frame(kind, flags, id, body),
            Control::Threaded(_) => {
                if self.control.send(9 + body.len(), frame) {
                    true
                } else {
                    self.dead.store(true, Ordering::SeqCst);
                    false
                }
            }
        }
    }

    /// Refuse the connection: the GOAWAY goes out now, and `refused` remembers that the peer still has to be given the window to read it.
    fn refuse(&self, code: u32) {
        self.refused.store(true, Ordering::SeqCst);
        let mut goaway = [0u8; 8];
        goaway[4..].copy_from_slice(&code.to_be_bytes());
        // Queued: the GOAWAY is the demux's answer, so it must not wait on a write the peer has not read.
        let _ = self.send_control(T_GOAWAY, 0, 0, &goaway);
    }

    fn send_data(&self, stream: u32, mut payload: &[u8]) -> bool {
        if payload.is_empty() {
            return true;
        }
        let Some(state) = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .cloned()
        else {
            return false;
        };
        let max = *self
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut batch = DataBatch::new();
        while !payload.is_empty() {
            let fit = payload.len().min(max);
            let Some(chunk) = self.credit(&state, fit as u64, &mut batch) else {
                return false;
            };
            if batch.full() && !batch.flush(self) {
                return false;
            }
            batch.add(stream, &payload[..chunk]);
            payload = &payload[chunk..];
        }
        batch.flush(self)
    }

    fn send_grouped(&self, stream: u32, groups: &[&[&[u8]]]) -> bool {
        let Some(state) = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .cloned()
        else {
            return false;
        };
        let max = *self
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut batch = DataBatch::new();
        for group in groups {
            let mut need: usize = group.iter().map(|part| part.len()).sum();
            if need == 0 || group.len() > 4 {
                continue;
            }
            let mut index = 0;
            let mut offset = 0;
            while need > 0 {
                let want = need.min(max);
                let Some(chunk) = self.credit(&state, want as u64, &mut batch) else {
                    return false;
                };
                if batch.full() && !batch.flush(self) {
                    return false;
                }
                let mut parts: [&[u8]; 4] = [&[]; 4];
                let mut used = 0;
                let mut left = chunk;
                while left > 0 && index < group.len() {
                    let part = &group[index][offset..];
                    if part.len() <= left {
                        parts[used] = part;
                        used += 1;
                        left -= part.len();
                        index += 1;
                        offset = 0;
                    } else {
                        parts[used] = &part[..left];
                        used += 1;
                        offset += left;
                        left = 0;
                    }
                }
                batch.add_parts(stream, &parts[..used]);
                need -= chunk;
            }
        }
        batch.flush(self)
    }

    /// The whole batch off the two windows or none of it: a lane that offered bytes no window
    /// covers parks and retries, so a blocked sender never holds the worker its peer's credit runs on.
    fn try_send_grouped(&self, stream: u32, groups: &[&[&[u8]]]) -> Option<bool> {
        let Some(state) = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .cloned()
        else {
            return Some(false);
        };
        let total: u64 = groups
            .iter()
            .filter(|group| group.len() <= 4)
            .map(|group| group.iter().map(|part| part.len() as u64).sum::<u64>())
            .sum();
        if total == 0 {
            return Some(true);
        }
        let Ok(mut write) = self.write.try_lock() else {
            return None;
        };
        let (Ok(mut conn), Ok(mut window)) =
            (self.send_conn.try_lock(), state.send_window.try_lock())
        else {
            return None;
        };
        if *conn < total || *window < total {
            if stream > 1 {
                static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                if N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 40 {
                    eprintln!(
                        "PROBE wide str={stream} total={total} conn={} win={}",
                        *conn, *window
                    );
                }
            }
            return None;
        }
        *conn -= total;
        *window -= total;
        let max = *self
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut batch = DataBatch::new();
        for group in groups {
            let mut need: usize = group.iter().map(|part| part.len()).sum();
            if need == 0 || group.len() > 4 {
                continue;
            }
            let mut index = 0;
            let mut offset = 0;
            while need > 0 {
                let chunk = need.min(max);
                if batch.full() && !batch.flush_locked(self, &mut **write) {
                    return Some(false);
                }
                let mut parts: [&[u8]; 4] = [&[]; 4];
                let mut used = 0;
                let mut left = chunk;
                while left > 0 && index < group.len() {
                    let part = &group[index][offset..];
                    if part.len() <= left {
                        parts[used] = part;
                        used += 1;
                        left -= part.len();
                        index += 1;
                        offset = 0;
                    } else {
                        parts[used] = &part[..left];
                        used += 1;
                        offset += left;
                        left = 0;
                    }
                }
                batch.add_parts(stream, &parts[..used]);
                need -= chunk;
            }
        }
        Some(batch.flush_locked(self, &mut **write))
    }

    /// Drains a writer that kept a paced tail for a peer that had not read: the lane settles it,
    /// so an `END_STREAM` behind that tail is not left waiting for a write nobody offers.
    fn settle(&self) -> crate::proxy::Settle {
        let Ok(mut write) = self.write.lock() else {
            return crate::proxy::Settle::Lost;
        };
        write.settle()
    }

    fn room(&self, stream: u32) -> u64 {
        let conn = *self
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let state = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .cloned();
        let Some(state) = state else {
            return 0;
        };
        let window = *state
            .send_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        conn.min(window)
    }

    /// The caller already knows its batch does not fit, so any wait here is the poll it would pay
    /// anyway; holding the connection window across the recheck is what keeps a grant that landed
    /// between the caller's look and this wait from being slept out as a whole poll.
    fn wait_room(&self, stream: u32, turn: std::time::Duration) {
        let conn = self
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let state = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .cloned();
        let Some(state) = state else {
            return;
        };
        {
            let window = *state
                .send_window
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *conn > 0 && window > 0 {
                return;
            }
        }
        let _ = self.wake.wait_timeout(conn, turn);
    }

    /// Take what the two windows allow, waiting only after the frames already reserved have reached the peer.
    fn credit(&self, state: &H2Stream, need: u64, batch: &mut DataBatch<'_>) -> Option<usize> {
        if let Some(take) = self.take_send_window(state, need, false) {
            return Some(take);
        }
        if !batch.flush(self) {
            return None;
        }
        self.take_send_window(state, need, true)
    }

    fn take_send_window(&self, stream: &H2Stream, need: u64, blocking: bool) -> Option<usize> {
        let mut conn = self
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            if self.dead.load(Ordering::SeqCst) {
                return None;
            }
            let take = {
                let mut window = stream
                    .send_window
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let take = need.min(*conn).min(*window);
                if take > 0 {
                    *conn -= take;
                    *window -= take;
                }
                take
            };
            if take > 0 {
                return Some(take as usize);
            }
            if !blocking || stream.gone() {
                return None;
            }
            if self.client_read.is_some() {
                // A client's credit arrives on its reader's transport, so a parked writer pumps it itself.
                drop(conn);
                if !matches!(
                    self.pump_read(
                        || {
                            if self.dead.load(Ordering::SeqCst) || stream.gone() {
                                return true;
                            }
                            let conn = self
                                .send_conn
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner);
                            let window = stream
                                .send_window
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner);
                            *conn > 0 && *window > 0
                        },
                        false,
                    ),
                    Pumped::Alive
                ) {
                    return None;
                }
                conn = self
                    .send_conn
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let (guard, waited) = self
                .wake
                .wait_timeout(conn, crate::budgets::relay_stall())
                .unwrap_or_else(PoisonError::into_inner);
            conn = guard;
            if waited.timed_out() || stream.gone() {
                return None;
            }
        }
    }

    fn replenish(&self, stream: u32, n: usize) {
        if n == 0 || n > u32::MAX as usize {
            return;
        }
        let increment = (n as u32).to_be_bytes();
        let mut out = CREDIT_TEMPLATE;
        out[9..13].copy_from_slice(&increment);
        out[18..22].copy_from_slice(&stream.to_be_bytes());
        out[22..26].copy_from_slice(&increment);
        // Consuming inbound bytes grants the peer more credit; our own send windows rise only from the peer's WINDOW_UPDATE, so crediting them here would let a bulk send outrun the window the peer gave and trip its flow control.
        match &self.control {
            Control::Inline => {
                let Ok(mut write) = self.write.lock() else {
                    return;
                };
                if !write.write_slices(&[&out]) {
                    self.dead.store(true, Ordering::SeqCst);
                }
            }
            Control::Threaded(_) => {
                if !self.control.send(CREDIT_FRAME, out) {
                    self.dead.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    /// Connection credit for bytes discarded on an abandoned stream: the shared window must rise or
    /// the peer's later uploads on other streams stall, while the abandoned stream's own window
    /// stays spent so its upload cannot grow.
    fn replenish_connection(&self, n: usize) -> bool {
        if n == 0 || n > u32::MAX as usize {
            return true;
        }
        let mut out = CREDIT_TEMPLATE;
        out[9..13].copy_from_slice(&(n as u32).to_be_bytes());
        match &self.control {
            Control::Inline => {
                let Ok(mut write) = self.write.lock() else {
                    return false;
                };
                if !write.write_slices(&[&out[..13]]) {
                    self.dead.store(true, Ordering::SeqCst);
                    return false;
                }
                true
            }
            Control::Threaded(_) => {
                if !self.control.send(13, out) {
                    self.dead.store(true, Ordering::SeqCst);
                    return false;
                }
                true
            }
        }
    }

    /// A bodyless request ended with its HEADERS (`END_STREAM`), so the peer still owes the answer.
    fn mark_request_ended(&self, stream: u32) {
        let ended = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .map(|state| {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                st.request_ended = true;
                st.ended
            });
        if ended == Some(true) {
            self.retire(stream);
        }
    }

    /// The status a response HEADERS block carries: decoded on the client's reader so the table stays
    /// in wire order, and `None` when the block does not decode.
    fn response_status(&self, block: &[u8]) -> Option<u16> {
        let mut status = None;
        let mut decoder = self.decoder.lock().ok()?;
        decoder.decode(block, &mut |name, value| {
            if name == b":status" {
                status = std::str::from_utf8(value).ok().and_then(|s| s.parse().ok());
            }
        })?;
        status
    }

    /// The client's request body ends on its own stream while the response keeps reading: an RST
    /// here would discard the answer the peer has not written yet.
    fn finish_stream(&self, stream: u32) {
        let _ = self.frame(T_DATA, F_END, stream, &[]);
        let ended = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .map(|state| {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                st.request_ended = true;
                st.ended
            });
        if ended == Some(true) {
            self.retire(stream);
        }
    }

    pub(crate) fn close_client(&self) {
        self.dead.store(true, Ordering::SeqCst);
        if let Some(raw) = &self.raw {
            let _ = raw.shutdown(std::net::Shutdown::Both);
        }
        self.kill();
    }

    /// A reset from the peer kills only its stream: the connection may still serve the others.
    fn fail_stream(&self, stream: u32) {
        let state = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&stream);
        if let Some(state) = state {
            let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            st.dead = true;
            state.cv.notify_all();
        }
        self.wake.notify_all();
    }

    fn end_stream(&self, stream: u32) {
        let (responded, ended) = {
            let streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(state) = streams.get(&stream) else {
                drop(streams);
                self.reset_stream(stream);
                return;
            };
            let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            st.finished = true;
            state.cv.notify_all();
            (state.responded.load(Ordering::SeqCst), st.ended)
        };
        if responded {
            let _ = self.frame(T_DATA, F_END, stream, &[]);
            if ended {
                self.retire(stream);
            }
        } else {
            self.reset_stream(stream);
        }
    }

    /// Both halves have ended, so the table frees the id: keeping it would refuse every call past
    /// `MAX_STREAMS` on a connection that is otherwise healthy.
    fn retire(&self, stream: u32) {
        let removed = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&stream)
            .is_some();
        if removed {
            self.forget_upload(stream);
            self.end_session_of(stream);
        }
    }

    fn reset_stream(&self, stream: u32) {
        self.forget_upload(stream);
        {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(state) = streams.remove(&stream) {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                st.dead = true;
                state.cv.notify_all();
            }
        }
        self.wake.notify_all();
        self.end_session_of(stream);
        // Queued: a refusal is the demux's answer, so it must not wait on a write the peer has not read.
        let _ = self.send_control(T_RST, 0, stream, &E_REFUSED.to_be_bytes());
    }

    fn kill(&self) {
        self.dead.store(true, Ordering::SeqCst);
        self.wake.notify_all();
        let streams: Vec<_> = {
            self.streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .cloned()
                .collect()
        };
        for state in streams {
            let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            st.dead = true;
            state.cv.notify_all();
        }
        let sessions: Vec<String> = self
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for session in sessions {
            crate::xhttp::end_session(&session);
        }
    }

    /// The session a stream of this connection waits on dies with the connection: past `dead` there is no frame left to post, so a waiter would park on a sequence no peer can ever send.
    fn bind_session(&self, sid: &str, stream: u32, downlink: bool) {
        {
            let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
            // Every packet-up POST repeats its session's id, so the owned key is only made for a first bind.
            if !sessions.contains(sid) {
                sessions.insert(sid.to_owned());
            }
        }
        let owner = if downlink {
            &self.session_of
        } else {
            &self.upload_of
        };
        owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(stream, sid.to_owned());
        // `kill` sets `dead` before it drains this set, so a bind that raced the drain ends its own session.
        if self.dead.load(Ordering::SeqCst) {
            crate::xhttp::end_session(sid);
        }
    }

    fn forget_upload(&self, stream: u32) {
        self.upload_of
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&stream);
    }

    /// The session is over, so the uploads that shared it wake, but the stream stays in the table: a
    /// stream-up POST still owes its deferred 200, and a reset here would discard it.
    fn end_uploads(&self, sid: &str) {
        let streams: Vec<u32> = {
            let mut uploads = self
                .upload_of
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let owned: Vec<u32> = uploads
                .iter()
                .filter(|(_, owner)| owner.as_str() == sid)
                .map(|(stream, _)| *stream)
                .collect();
            for stream in &owned {
                uploads.remove(stream);
            }
            owned
        };
        for stream in streams {
            let state = self
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&stream)
                .cloned();
            if let Some(state) = state {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                st.ended = true;
                st.stopped = true;
                state.cv.notify_all();
            }
        }
    }

    /// A finished downlink ends the session its uploads wait on, so a packet-up POST parked in `wait_ended` is not left for the connection's death.
    fn end_session_of(&self, stream: u32) {
        let sid = self
            .session_of
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&stream);
        if let Some(sid) = sid {
            self.end_uploads(&sid);
            self.sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&sid);
            crate::xhttp::end_session(&sid);
        }
    }
}

impl H2Conn {
    fn apply_settings(&self, body: &[u8]) -> bool {
        let mut at = 0;
        while at + 6 <= body.len() {
            let id = u16::from_be_bytes([body[at], body[at + 1]]);
            let value =
                u32::from_be_bytes([body[at + 2], body[at + 3], body[at + 4], body[at + 5]]);
            at += 6;
            if id == S_MAX_FRAME {
                let mut max = self
                    .max_frame
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *max = usize::try_from(value)
                    .unwrap_or(crate::h2::FRAME_CAP)
                    .clamp(16_384, 16_777_215);
            } else if id == S_WINDOW {
                let value = u64::from(value.min((1 << 31) - 1));
                // The stream table gates the snapshot and the delta so neither misses nor doubles the other.
                let streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
                let mut previous = self
                    .peer_initial
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let delta = value.saturating_sub(*previous);
                *previous = value;
                drop(previous);
                for state in streams.values() {
                    let mut window = state
                        .send_window
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    *window = window.saturating_add(delta).min((1 << 31) - 1);
                }
                drop(streams);
                self.wake.notify_all();
            }
        }
        self.send_control(T_SETTINGS, F_ACK, 0, &[])
    }

    /// Insert a stream with the initial window the peer has published so far. The stream table is
    /// held across the snapshot and the insertion so a concurrent `S_WINDOW` update can neither
    /// miss the new stream nor apply its delta to it twice.
    fn attach_stream(&self, sid: u32, end_stream: bool) -> Option<Arc<H2Stream>> {
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        if streams.len() >= MAX_STREAMS as usize || streams.contains_key(&sid) {
            return None;
        }
        let initial = *self
            .peer_initial
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: end_stream,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(initial),
            responded: AtomicBool::new(false),
        });
        streams.insert(sid, Arc::clone(&state));
        Some(state)
    }
}

/// What one client-frame read did: dispatched a whole frame, reached a poll boundary with the
/// frame still arriving, or found the connection dead.
enum Pumped {
    Alive,
    Yield,
    Dead,
}

/// The frame a client read is assembling: a lane yields at a poll boundary, so its head and the
/// body already taken stay here until the next turn completes them.
#[derive(Default)]
struct PartialFrame {
    head: [u8; 9],
    head_len: usize,
    frame: Option<(u8, u8, u32)>,
    body: Vec<u8>,
    body_len: usize,
    since: Option<std::time::Instant>,
}

/// Fills `buf` from `stream`, keeping what arrived across a lane's poll boundary: `Some(true)`
/// when the buffer is whole, `Some(false)` when a yieldable poll reached its boundary, `None`
/// when the stream died or the frame outlived the relay stall.
fn fill_frame(
    stream: &mut dyn Read,
    buf: &mut [u8],
    at: &mut usize,
    since: std::time::Instant,
    yieldable: bool,
) -> Option<bool> {
    while *at < buf.len() {
        match stream.read(&mut buf[*at..]) {
            Ok(0) => return None,
            Ok(n) => *at += n,
            Err(error) if crate::proxy::is_timeout(&error) => {
                if since.elapsed() >= crate::budgets::relay_stall() {
                    return None;
                }
                if yieldable {
                    return Some(false);
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(crate::budgets::RELAY_POLL);
                }
            }
            Err(_) => return None,
        }
    }
    Some(true)
}

impl H2Conn {
    /// A client's frames arrive on the same transport its reader consumes: one frame is parsed on
    /// demand, so a read and a credit-starved write both make progress without a parser thread.
    /// A lane step that cannot finish the frame yields the poll instead of sleeping in it.
    fn pump_read(&self, ready: impl FnOnce() -> bool, yieldable: bool) -> Pumped {
        let Some(read) = self.client_read.as_ref() else {
            return Pumped::Dead;
        };
        let mut read = read.lock().unwrap_or_else(PoisonError::into_inner);
        if ready() {
            return Pumped::Alive;
        }
        let mut partial = self
            .client_partial
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let since = *partial.since.get_or_insert_with(std::time::Instant::now);
        let frame = {
            let partial = &mut *partial;
            if partial.frame.is_none() {
                match fill_frame(
                    &mut **read,
                    &mut partial.head,
                    &mut partial.head_len,
                    since,
                    yieldable,
                ) {
                    Some(true) => {}
                    Some(false) => return Pumped::Yield,
                    None => {
                        self.dead.store(true, Ordering::SeqCst);
                        return Pumped::Dead;
                    }
                }
                let head = partial.head;
                let len =
                    usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
                if len > MAX_RECV_FRAME {
                    self.dead.store(true, Ordering::SeqCst);
                    return Pumped::Dead;
                }
                let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7FFF_FFFF;
                partial.frame = Some((head[3], head[4], sid));
                partial.body = crate::proxy::unfilled(len);
            }
            let Some((kind, flags, sid)) = partial.frame else {
                return Pumped::Dead;
            };
            match fill_frame(
                &mut **read,
                &mut partial.body,
                &mut partial.body_len,
                since,
                yieldable,
            ) {
                Some(true) => {}
                Some(false) => return Pumped::Yield,
                None => {
                    self.dead.store(true, Ordering::SeqCst);
                    return Pumped::Dead;
                }
            }
            let body = std::mem::take(&mut partial.body);
            partial.head_len = 0;
            partial.frame = None;
            partial.body_len = 0;
            partial.since = None;
            (kind, flags, sid, body)
        };
        drop(partial);
        let (kind, flags, sid, body) = frame;
        // Dispatch under the read lock so a later frame cannot overtake an earlier one on the wire.
        let alive = client_frame(self, kind, flags, sid, body);
        if !alive {
            self.dead.store(true, Ordering::SeqCst);
        }
        if alive {
            Pumped::Alive
        } else {
            Pumped::Dead
        }
    }
}

/// The client's frame dispatch: settings and credit are shared with the server, while a response
/// head ends the stream and a reset fails only that stream.
fn client_frame(conn: &H2Conn, kind: u8, flags: u8, sid: u32, body: Vec<u8>) -> bool {
    if let Some(alive) = control_frame(conn, kind, flags, sid, &body) {
        return alive;
    }
    match kind {
        T_HEADERS => {
            let mut block = body;
            let mut start = 0;
            let mut end = block.len();
            if flags & F_PADDED != 0 {
                let Some(&pad) = block.first() else {
                    return true;
                };
                start = 1;
                end = match block.len().checked_sub(pad as usize) {
                    Some(end) if end >= start => end,
                    _ => return true,
                };
            }
            if flags & F_PRIORITY != 0 {
                start += 5;
                if start > end {
                    return true;
                }
            }
            block.truncate(end);
            block.drain(..start);
            let end_stream = flags & F_END != 0;
            if flags & F_END_HEADERS != 0 {
                *conn
                    .client_head
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = None;
                client_headers(conn, sid, &block, end_stream);
            } else {
                *conn
                    .client_head
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some((sid, block, end_stream));
            }
            true
        }
        T_CONT => {
            let pending = conn
                .client_head
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let Some((pending_sid, mut gathered, end_stream)) = pending else {
                return true;
            };
            if pending_sid != sid {
                *conn
                    .client_head
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) =
                    Some((pending_sid, gathered, end_stream));
                return true;
            }
            if gathered.len() + body.len() > HEAD_CAP {
                conn.refuse(E_PROTOCOL);
                return false;
            }
            gathered.extend_from_slice(&body);
            if flags & F_END_HEADERS != 0 {
                client_headers(conn, sid, &gathered, end_stream);
            } else {
                *conn
                    .client_head
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some((sid, gathered, end_stream));
            }
            true
        }
        T_DATA => queue_data(conn, flags, sid, body),
        T_RST => {
            conn.fail_stream(sid);
            true
        }
        T_GOAWAY => {
            conn.goaway.store(true, Ordering::SeqCst);
            true
        }
        _ => true,
    }
}

/// A complete response head: decode its `:status`, retire the stream when the peer's `END_STREAM`
/// already rode the head, and wake a reader parked on the answer.
fn client_headers(conn: &H2Conn, sid: u32, block: &[u8], end_stream: bool) {
    let status = conn.response_status(block);
    let state = conn
        .streams
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&sid)
        .cloned();
    if let Some(state) = state {
        state.responded.store(true, Ordering::SeqCst);
        let done = {
            let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            if status.is_some() {
                st.status = status;
            }
            if end_stream {
                st.ended = true;
            }
            state.cv.notify_all();
            st.both_ended()
        };
        if done {
            conn.retire(sid);
        }
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

/// One client connection, one stream: the reference opens a stream per session and keeps the
/// connection for the pool, so a stream ending must not close what a later session can reuse.
/// One client connection: the reference opens a stream per session and keeps the connection for
/// the pool (`mux.go`), so a stream ending must not close what a later session can reuse.
pub(crate) struct H2Client {
    conn: Arc<H2Conn>,
    next: AtomicU32,
}

impl H2Client {
    pub(crate) fn new<R: Read + Send + 'static, W: crate::proxy::FrameWrite + Send + 'static>(
        read: R,
        write: W,
        raw: Option<Arc<crate::conn::Connection>>,
    ) -> Option<Arc<Self>> {
        let dead = Arc::new(AtomicBool::new(false));
        let write: SharedWriter = Arc::new(Mutex::new(Box::new(write)));
        let conn = Arc::new(H2Conn {
            control: Control::threaded(Arc::clone(&write), Arc::clone(&dead)),
            write,
            streams: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashSet::new()),
            session_of: Mutex::new(HashMap::new()),
            upload_of: Mutex::new(HashMap::new()),
            send_conn: Mutex::new(65_535),
            wake: Condvar::new(),
            decoder: Mutex::new(Decoder::default()),
            max_frame: Mutex::new(16_384),
            peer_initial: Mutex::new(65_535),
            dead,
            goaway: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            client_read: Some(Mutex::new(Box::new(read))),
            client_partial: Mutex::new(PartialFrame::default()),
            client_head: Mutex::new(None),
            raw,
            decryption: None,
        });
        {
            let mut write = conn.write.lock().unwrap_or_else(PoisonError::into_inner);
            if write.write_all(MAGIC).is_err() {
                return None;
            }
        }
        let mut initial = Vec::with_capacity(12);
        initial.extend_from_slice(&S_WINDOW.to_be_bytes());
        initial.extend_from_slice(&WINDOW.to_be_bytes());
        if !conn.frame(T_SETTINGS, 0, 0, &initial) {
            return None;
        }
        if !conn.frame(T_WINDOW, 0, 0, &CONN_WINDOW_TOP_UP.to_be_bytes()) {
            return None;
        }
        Some(Arc::new(Self {
            conn,
            next: AtomicU32::new(1),
        }))
    }

    /// The pool closes the connection when its last entry goes; a stream that still holds it keeps
    /// the sockets alive until it ends.
    pub(crate) fn close(&self) {
        self.conn.close_client();
    }

    /// The pool may hand this connection to another session only while both halves are alive and
    /// the peer has not asked for the connection to end.
    pub(crate) fn reusable(&self) -> bool {
        !self.conn.dead.load(Ordering::SeqCst) && !self.conn.goaway.load(Ordering::SeqCst)
    }

    /// A session that does not pool the connection holds one of these: the last clone closes it.
    pub(crate) fn owner(&self) -> Arc<ClientOwner> {
        Arc::new(ClientOwner {
            conn: Arc::clone(&self.conn),
        })
    }

    /// `owned` closes the connection when the session's last writer drops; a pooled connection is
    /// the pool's to close, not the session's.
    pub(crate) fn open(
        &self,
        host: &str,
        settings: &XhttpSettings,
        scheme: &str,
        owned: bool,
    ) -> Option<(H2StreamReader, crate::xhttp::XhttpWriter)> {
        let block = request_block(host, settings, scheme);
        let closer = owned.then(|| self.owner());
        let (reader, out) = self.open_headers(&block, closer, false)?;
        let writer = crate::xhttp::XhttpWriter::new(NullWrite);
        writer.set_h2(out);
        Some((reader, writer))
    }

    /// Sends one request head on a fresh stream. `end_request` marks a bodyless request (the GET
    /// downlink) so the response's own `END_STREAM` retires the stream.
    fn open_headers(
        &self,
        block: &[u8],
        owner: Option<Arc<ClientOwner>>,
        end_request: bool,
    ) -> Option<(H2StreamReader, H2StreamOut)> {
        let sid = self.next.fetch_add(2, Ordering::SeqCst);
        let state = self.conn.attach_stream(sid, false)?;
        let flags = if end_request {
            F_END_HEADERS | F_END
        } else {
            F_END_HEADERS
        };
        if !self.conn.frame(T_HEADERS, flags, sid, block) {
            self.conn.fail_stream(sid);
            return None;
        }
        if end_request {
            self.conn.mark_request_ended(sid);
        }
        let reader = H2StreamReader {
            conn: Arc::clone(&self.conn),
            stream: state,
            id: sid,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let out = H2StreamOut {
            conn: Arc::clone(&self.conn),
            stream: sid,
            _owner: owner,
            client: true,
        };
        Some((reader, out))
    }

    /// One packet-up POST: its own stream, the packet in the body, the answer drained before the
    /// next shares the connection. A refused packet would stall the download, so the answer is read
    /// to its end and a non-2xx status fails the upload.
    pub(crate) fn packet(
        &self,
        host: &str,
        settings: &XhttpSettings,
        session: &str,
        seq: u64,
        piece: &[u8],
    ) -> bool {
        let (head, body) = crate::xhttp::packet_head(host, settings, session, seq, piece);
        let block = block_from_head(&head, host, "https");
        let Some((mut reader, out)) = self.open_headers(&block, None, false) else {
            return false;
        };
        if let Some(body) = body {
            if !out.data(body) {
                self.conn.fail_stream(reader.id);
                return false;
            }
        }
        self.conn.finish_stream(reader.id);
        let mut sink = [0u8; 64];
        loop {
            match reader.read(&mut sink) {
                Ok(0) => {
                    return reader
                        .status()
                        .is_some_and(|code| (200..300).contains(&code))
                }
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }
}

fn request_block(host: &str, settings: &XhttpSettings, scheme: &str) -> Vec<u8> {
    let path = crate::xhttp::dial_path(settings);
    let mut fields: Vec<(String, String)> = vec![
        (":method".to_owned(), "POST".to_owned()),
        (":path".to_owned(), path),
        (":scheme".to_owned(), scheme.to_owned()),
        (":authority".to_owned(), host.to_owned()),
    ];
    for (mut name, value) in crate::xhttp::dial_fields(host, settings) {
        if name.starts_with(':')
            || hop_by_hop(&name)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("te")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        name.make_ascii_lowercase();
        fields.push((name, value));
    }
    let refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    block_encode(&refs)
}

pub(crate) fn connect_split<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    read: R,
    write: W,
    raw: Arc<crate::conn::Connection>,
    host: &str,
    settings: &XhttpSettings,
    scheme: &str,
) -> Option<(H2StreamReader, crate::xhttp::XhttpWriter)> {
    H2Client::new(read, write, Some(raw))?.open(host, settings, scheme, true)
}

/// A dual-session dial on one h2 connection: the GET downlink and the POST upload are two streams,
/// exactly as the reference's `http2.Transport` muxes them on the one connection it pooled.
pub(crate) fn connect_dual_split<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    read: R,
    write: W,
    raw: Arc<crate::conn::Connection>,
    host: &str,
    settings: &XhttpSettings,
    scheme: &str,
) -> Option<(H2StreamReader, crate::xhttp::XhttpWriter)> {
    let client = H2Client::new(read, write, Some(raw))?;
    let owner = client.owner();
    let session = settings.session_id();
    let down = crate::xhttp::downlink_head(host, settings, &session);
    let block = block_from_head(&down, host, scheme);
    let Some((reader, _)) = client.open_headers(&block, None, true) else {
        client.close();
        return None;
    };
    let writer = if settings.mode == crate::xhttp::XhttpMode::PacketUp {
        crate::xhttp::XhttpWriter::packets_h2(Arc::clone(&client), host, settings, session, owner)
    } else {
        let up = crate::xhttp::dial_head(host, settings, &session, None);
        let block = block_from_head(&up, host, scheme);
        let Some((_, out)) = client.open_headers(&block, Some(owner), false) else {
            client.close();
            return None;
        };
        let writer = crate::xhttp::XhttpWriter::new(NullWrite);
        writer.set_h2(out);
        writer
    };
    Some((reader, writer))
}

/// The h2 fields an H1 dial head already decided: its request line becomes the pseudo-headers and
/// the framing the connection owns is dropped, while `content-length` stays so a packet's body is
/// bounded.
fn block_from_head(head: &str, host: &str, scheme: &str) -> Vec<u8> {
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or_default().split_ascii_whitespace();
    let method = request.next().unwrap_or("POST");
    let target = request.next().unwrap_or("/");
    let mut fields: Vec<(String, String)> = Vec::with_capacity(8);
    fields.push((":method".to_owned(), method.to_owned()));
    fields.push((":path".to_owned(), target.to_owned()));
    fields.push((":scheme".to_owned(), scheme.to_owned()));
    fields.push((":authority".to_owned(), host.to_owned()));
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
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
    block_encode(&refs)
}

/// What a connection does with a request stream: xHTTP synthesises its H1 head and reuses the H1
/// dispatch, gRPC opens the message reader and writer over the same demux.
pub(crate) trait H2Service: Send + Sync {
    /// True when the frame opened a request; a rejected head resets its stream and answers false.
    fn open(&self, conn: &Arc<H2Conn>, sid: u32, block: &[u8], end_stream: bool) -> bool;
}

impl H2Conn {
    pub(crate) fn decode_block(&self, block: &[u8], mut field: impl FnMut(&[u8], &[u8])) -> bool {
        self.decoder
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .decode(block, &mut field)
            .is_some()
    }

    pub(crate) fn open(
        self: &Arc<Self>,
        sid: u32,
        end_stream: bool,
    ) -> Option<(H2StreamReader, H2StreamWriter, H2StreamOut)> {
        if self.goaway.load(Ordering::SeqCst) {
            self.reset_stream(sid);
            return None;
        }
        let Some(state) = self.attach_stream(sid, end_stream) else {
            self.reset_stream(sid);
            return None;
        };
        Some((
            H2StreamReader {
                conn: Arc::clone(self),
                stream: Arc::clone(&state),
                id: sid,
                at: 0,
                cur: Vec::new(),
                idle_since: None,
            },
            H2StreamWriter {
                conn: Arc::clone(self),
                stream: sid,
                head: Vec::new(),
                headed: false,
            },
            H2StreamOut {
                conn: Arc::clone(self),
                stream: sid,
                _owner: None,
                client: false,
            },
        ))
    }

    pub(crate) fn respond(&self, sid: u32, fields: &[(&str, &str)]) -> bool {
        let block = block_encode(fields);
        let max = *self
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut at = 0;
        loop {
            let end = (at + max).min(block.len());
            let flags = if end == block.len() { F_END_HEADERS } else { 0 };
            let kind = if at == 0 { T_HEADERS } else { T_CONT };
            if !self.frame(kind, flags, sid, &block[at..end]) {
                return false;
            }
            at = end;
            if at >= block.len() {
                break;
            }
        }
        if let Some(state) = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&sid)
        {
            state.responded.store(true, Ordering::SeqCst);
        }
        true
    }

    pub(crate) fn max_frame_now(&self) -> usize {
        *self
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn peer_window(&self) -> u64 {
        *self
            .peer_initial
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn reset(&self, sid: u32) {
        self.reset_stream(sid);
    }
}

/// What a served h2 stream hands the protocol above the carrier once `accept_core` split it.
pub(crate) type SessionServe = dyn Fn(
        Box<dyn crate::proxy::WindowRead + Send>,
        crate::xhttp::XhttpWriter,
        Option<Arc<ferrox_core::vless_encryption::Server>>,
    ) + Send
    + Sync;

struct XhttpService {
    settings: XhttpSettings,
    serve: Arc<SessionServe>,
}

impl H2Service for XhttpService {
    fn open(&self, conn: &Arc<H2Conn>, sid: u32, block: &[u8], end_stream: bool) -> bool {
        open_stream(
            conn,
            &self.settings,
            Arc::clone(&self.serve),
            sid,
            block,
            end_stream,
        )
    }
}

/// The same demux for a carrier whose protocol above xHTTP is not VLESS: the accept still splits the
/// stream into the carrier reader and writer, and the caller's closure runs the protocol handler.
pub(crate) struct XhttpSessionService {
    settings: XhttpSettings,
    serve: Arc<SessionServe>,
}

impl XhttpSessionService {
    pub(crate) fn new(settings: XhttpSettings, serve: Arc<SessionServe>) -> Self {
        Self { settings, serve }
    }
}

impl H2Service for XhttpSessionService {
    fn open(&self, conn: &Arc<H2Conn>, sid: u32, block: &[u8], end_stream: bool) -> bool {
        open_stream(
            conn,
            &self.settings,
            Arc::clone(&self.serve),
            sid,
            block,
            end_stream,
        )
    }
}

fn synth_head(method: &[u8], target: &[u8], lines: &[u8], end_stream: bool) -> Vec<u8> {
    // " " and " HTTP/2\r\n" and the closing "\r\n", plus the chunked line a stream still open carries.
    let framing = if end_stream { 12 } else { 40 };
    let mut head = Vec::with_capacity(method.len() + target.len() + lines.len() + framing);
    head.extend_from_slice(method);
    head.push(b' ');
    head.extend_from_slice(target);
    head.extend_from_slice(b" HTTP/2\r\n");
    head.extend_from_slice(lines);
    if !end_stream {
        head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// A served stream carries the sealed session in its body when the inbound names an engine: the
/// engine handshake runs above the carrier framing, exactly as it does over H1.
fn serve_stream(
    reader: Box<dyn crate::proxy::WindowRead + Send>,
    writer: crate::xhttp::XhttpWriter,
    users: &VlessUsers,
    freedom: bool,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
) {
    let Some(decryption) = decryption else {
        crate::proxy::serve_session_xhttp_with(reader, &writer, users, freedom);
        return;
    };
    let close = writer.clone();
    let close: Arc<dyn Fn() + Send + Sync> = Arc::new(move || close.finish());
    // The engine handshake reads the request body under the handshake clock: a silent peer cannot park a worker for the stall, and a poll-sized read is retried rather than failed.
    let reader = crate::proxy::HandshakeRead::new(reader, crate::budgets::handshake());
    crate::proxy::serve_sealed_carried_with(
        reader,
        writer,
        users,
        freedom,
        &decryption,
        close,
        |_| {},
        |reader| reader.rearm(crate::budgets::handshake()),
        crate::proxy::HandshakeRead::disarm,
    );
}

fn open_stream(
    conn: &Arc<H2Conn>,
    settings: &XhttpSettings,
    serve: Arc<SessionServe>,
    sid: u32,
    block: &[u8],
    end_stream: bool,
) -> bool {
    let (method, target, lines) = {
        let mut decoder = conn.decoder.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut method, mut target, mut lines) = (Vec::new(), Vec::new(), Vec::new());
        let (mut have_method, mut have_target) = (false, false);
        let ok = decoder
            .decode(block, &mut |name, value| {
                if name.first() == Some(&b':') {
                    if name.eq_ignore_ascii_case(b":method") && !have_method {
                        have_method = true;
                        method.extend_from_slice(value);
                    } else if name.eq_ignore_ascii_case(b":path") && !have_target {
                        have_target = true;
                        target.extend_from_slice(value);
                    }
                } else {
                    lines.extend_from_slice(name);
                    lines.extend_from_slice(b": ");
                    lines.extend_from_slice(value);
                    lines.extend_from_slice(b"\r\n");
                }
            })
            .is_some();
        drop(decoder);
        if !ok || !have_method || !have_target {
            conn.reset_stream(sid);
            return false;
        }
        (method, target, lines)
    };
    if conn.goaway.load(Ordering::SeqCst) {
        conn.reset_stream(sid);
        return false;
    }
    let Some(state) = conn.attach_stream(sid, end_stream) else {
        conn.reset_stream(sid);
        return false;
    };
    let head = synth_head(&method, &target, &lines, end_stream);
    let reader = H2StreamReader {
        conn: Arc::clone(conn),
        stream: Arc::clone(&state),
        id: sid,
        at: 0,
        cur: Vec::new(),
        idle_since: None,
    };
    let h2out = H2StreamOut {
        conn: Arc::clone(conn),
        stream: sid,
        _owner: None,
        client: false,
    };
    let writer = H2StreamWriter {
        conn: Arc::clone(conn),
        stream: sid,
        head: Vec::new(),
        headed: false,
    };
    let settings = settings.clone();
    let decryption = conn.decryption.clone();
    crate::budgets::spawn(move || {
        match crate::xhttp::accept_core(
            &head,
            Vec::new(),
            reader,
            writer,
            &settings,
            Some(h2out.clone()),
            None,
        ) {
            crate::xhttp::Served::Session(ureader, xwriter) => {
                serve(ureader, xwriter, decryption);
            }
            _ => h2out.end(),
        }
    });
    true
}

pub(crate) fn serve_h2<R: Read + Send + 'static, W: crate::proxy::FrameWrite + Send + 'static>(
    read: R,
    write: W,
    settings: &XhttpSettings,
    users: &[VlessUser],
    freedom: bool,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
) {
    let users: VlessUsers = Arc::from(users);
    let service = XhttpService {
        settings: settings.clone(),
        serve: Arc::new(move |reader, writer, decryption| {
            serve_stream(reader, writer, &users, freedom, decryption);
        }),
    };
    serve_h2_service(read, write, &service, decryption);
}

/// The plaintext xHTTP/2 demux as a lane step: a connection waiting for its peer's next frame
/// parks its socket with the pool, so it does not hold the worker that accepted it.
pub(crate) fn h2_xhttp_lane<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    read: R,
    write: W,
    settings: &XhttpSettings,
    users: &[VlessUser],
    freedom: bool,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
) -> impl FnMut() -> crate::proxy::lane_pool::Next + Send + 'static {
    let users: VlessUsers = Arc::from(users);
    let service = XhttpService {
        settings: settings.clone(),
        serve: Arc::new(move |reader, writer, decryption| {
            serve_stream(reader, writer, &users, freedom, decryption);
        }),
    };
    h2_lane(read, write, service, decryption, None)
}

pub(crate) fn serve_h2_service<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
    S: H2Service,
>(
    read: R,
    write: W,
    service: &S,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
) {
    // A peer that offers the preface and no request ends at the handshake clock; the first HEADERS puts it away.
    let until = std::time::Instant::now() + crate::budgets::handshake();
    let opened = Arc::new(AtomicBool::new(false));
    serve_h2_service_until(read, write, service, decryption, Some((until, opened)));
}

/// What one call of `Frames::step` settled on: another frame is ready, the socket is quiet until the
/// peer speaks again, or the connection is over.
enum Stepped {
    More,
    Idle,
    Done,
}

/// How one buffer fill ended.
enum Filled {
    Full,
    Idle,
    End,
    /// One bounded read moved bytes but the buffer is not full; a lane hands the worker back.
    Partial,
}

#[derive(Clone, Copy)]
enum Phase {
    Magic,
    Head,
    Body,
}

/// The preface, frame heads and bodies with their own buffers, so the demux can be handed back to a
/// lane between frames instead of holding a thread until the peer ends the connection. `block` keeps
/// the accept path's sleeping read; the lane path returns `Idle` and lets the pool park on the socket.
struct Frames<R, W> {
    read: R,
    until: Option<std::time::Instant>,
    opened: Option<Arc<std::sync::atomic::AtomicBool>>,
    write: Option<W>,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
    conn: Option<Arc<H2Conn>>,
    magic: [u8; MAGIC.len()],
    magic_have: usize,
    head: [u8; 9],
    head_have: usize,
    body: Vec<u8>,
    body_have: usize,
    frame: (u8, u8, u32),
    phase: Phase,
    frag: Option<(u32, Vec<u8>, bool)>,
    bounded: bool,
}

impl<R: Read, W: crate::proxy::FrameWrite + Send + 'static> Frames<R, W> {
    fn new(
        read: R,
        write: W,
        decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
        until: Option<(std::time::Instant, Arc<std::sync::atomic::AtomicBool>)>,
        bounded: bool,
    ) -> Self {
        let (until, opened) =
            until.map_or((None, None), |(until, opened)| (Some(until), Some(opened)));
        Self {
            read,
            until,
            opened,
            write: Some(write),
            decryption,
            conn: None,
            magic: [0u8; MAGIC.len()],
            magic_have: 0,
            head: [0u8; 9],
            head_have: 0,
            body: Vec::new(),
            body_have: 0,
            frame: (0, 0, 0),
            phase: Phase::Magic,
            frag: None,
            bounded,
        }
    }

    /// The handshake clock: silence before the first request is decoded ends at `until`, and the
    /// first decoded request puts the clock away for the life of the connection.
    fn expired(
        until: &mut Option<std::time::Instant>,
        opened: &mut Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> bool {
        if opened
            .as_ref()
            .is_some_and(|opened| opened.load(Ordering::Relaxed))
        {
            *until = None;
            *opened = None;
            return false;
        }
        until.is_some_and(|until| std::time::Instant::now() >= until)
    }

    fn fill(
        read: &mut R,
        until: &mut Option<std::time::Instant>,
        opened: &mut Option<Arc<std::sync::atomic::AtomicBool>>,
        buf: &mut [u8],
        have: &mut usize,
        block: bool,
        bounded: bool,
    ) -> Filled {
        while *have < buf.len() {
            if Self::expired(until, opened) {
                return Filled::End;
            }
            match read.read(&mut buf[*have..]) {
                Ok(0) => return Filled::End,
                Ok(filled) => {
                    *have += filled;
                    if bounded && !block && *have < buf.len() {
                        // A lane's turn is one read: a peer that keeps the bytes coming cannot hold the worker.
                        return Filled::Partial;
                    }
                }
                Err(error) if crate::proxy::is_timeout(&error) => {
                    if !block {
                        return Filled::Idle;
                    }
                    // No deadline means an established connection: poll in a quantum instead of spinning a worker.
                    let wait = until.map_or(crate::budgets::RELAY_POLL, |until| {
                        until
                            .saturating_duration_since(std::time::Instant::now())
                            .min(crate::budgets::RELAY_POLL)
                    });
                    std::thread::sleep(wait);
                }
                Err(_) => return Filled::End,
            }
        }
        Filled::Full
    }

    fn step(&mut self, service: &dyn H2Service, block: bool) -> Stepped {
        let filled = match self.phase {
            Phase::Magic => Self::fill(
                &mut self.read,
                &mut self.until,
                &mut self.opened,
                &mut self.magic,
                &mut self.magic_have,
                block,
                self.bounded,
            ),
            Phase::Head => Self::fill(
                &mut self.read,
                &mut self.until,
                &mut self.opened,
                &mut self.head,
                &mut self.head_have,
                block,
                self.bounded,
            ),
            Phase::Body => Self::fill(
                &mut self.read,
                &mut self.until,
                &mut self.opened,
                &mut self.body,
                &mut self.body_have,
                block,
                self.bounded,
            ),
        };
        match filled {
            Filled::Idle => Stepped::Idle,
            Filled::End => self.end(),
            Filled::Partial => Stepped::More,
            Filled::Full => self.advance(service),
        }
    }

    /// The frame whose buffers are full: answer a preface, size the body a head names, or hand a body
    /// to the service and go back to the next head.
    fn advance(&mut self, service: &dyn H2Service) -> Stepped {
        match self.phase {
            Phase::Magic => {
                if self.magic[..] != MAGIC[..] {
                    return self.end();
                }
                let Some(write) = self.write.take() else {
                    return self.end();
                };
                let dead = Arc::new(AtomicBool::new(false));
                let write: SharedWriter = Arc::new(Mutex::new(Box::new(write)));
                let conn = Arc::new(H2Conn {
                    control: Control::threaded(Arc::clone(&write), Arc::clone(&dead)),
                    write,
                    streams: Mutex::new(HashMap::new()),
                    sessions: Mutex::new(HashSet::new()),
                    session_of: Mutex::new(HashMap::new()),
                    upload_of: Mutex::new(HashMap::new()),
                    send_conn: Mutex::new(65_535),
                    wake: Condvar::new(),
                    decoder: Mutex::new(Decoder::default()),
                    max_frame: Mutex::new(16_384),
                    peer_initial: Mutex::new(65_535),
                    dead,
                    goaway: AtomicBool::new(false),
                    refused: AtomicBool::new(false),
                    client_read: None,
                    client_partial: Mutex::new(PartialFrame::default()),
                    client_head: Mutex::new(None),
                    raw: None,
                    decryption: self.decryption.take(),
                });
                let mut initial = Vec::with_capacity(12);
                initial.extend_from_slice(&S_WINDOW.to_be_bytes());
                initial.extend_from_slice(&WINDOW.to_be_bytes());
                if !conn.frame(T_SETTINGS, 0, 0, &initial) {
                    self.conn = Some(conn);
                    return self.end();
                }
                conn.frame(T_WINDOW, 0, 0, &CONN_WINDOW_TOP_UP.to_be_bytes());
                self.conn = Some(conn);
                self.head_have = 0;
                self.phase = Phase::Head;
            }
            Phase::Head => {
                let len = usize::from(self.head[0]) << 16
                    | usize::from(self.head[1]) << 8
                    | usize::from(self.head[2]);
                let (kind, flags) = (self.head[3], self.head[4]);
                let sid =
                    u32::from_be_bytes([self.head[5], self.head[6], self.head[7], self.head[8]])
                        & 0x7FFF_FFFF;
                if len > MAX_RECV_FRAME {
                    // A frame past the default SETTINGS_MAX_FRAME_SIZE is a connection error (RFC 7540 6.9.1): refuse it before reserving its length or blocking on a body that may never arrive.
                    if let Some(conn) = &self.conn {
                        conn.refuse(E_FRAME_SIZE);
                    }
                    return self.end();
                }
                self.body = crate::proxy::unfilled(len);
                self.body_have = 0;
                self.frame = (kind, flags, sid);
                self.phase = Phase::Body;
            }
            Phase::Body => {
                let (kind, flags, sid) = self.frame;
                let Some(conn) = &self.conn else {
                    return self.end();
                };
                let body = std::mem::take(&mut self.body);
                if !pump_frame(
                    conn,
                    service,
                    kind,
                    flags,
                    sid,
                    body,
                    &mut self.frag,
                    self.opened.as_ref(),
                ) {
                    return self.end();
                }
                self.head_have = 0;
                self.phase = Phase::Head;
            }
        }
        Stepped::More
    }

    fn end(&mut self) -> Stepped {
        if let Some(conn) = self.conn.take() {
            if conn.refused.load(Ordering::SeqCst) {
                // Closing while the peer's bytes sit unread aborts the connection, and the RST can swallow the GOAWAY a moment earlier; the grace is held after the last write drains, so the peer has the window to read it, and spent off the lane.
                let closing = Arc::clone(&conn);
                let spawned = std::thread::Builder::new().spawn(move || finish_refusal(&closing));
                if spawned.is_err() {
                    // No thread can wait out the grace, so release the parked streams and sessions now.
                    conn.kill();
                }
            } else {
                conn.kill();
            }
            conn.wake.notify_all();
        }
        Stepped::Done
    }
}

fn finish_refusal(conn: &Arc<H2Conn>) {
    let grace = crate::budgets::goaway_grace();
    if conn.control.drained(grace) && !conn.dead.load(Ordering::SeqCst) {
        std::thread::sleep(grace);
    }
    conn.kill();
}

pub(crate) fn serve_h2_service_until<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
    S: H2Service,
>(
    read: R,
    write: W,
    service: &S,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
    until: Option<(std::time::Instant, Arc<std::sync::atomic::AtomicBool>)>,
) {
    let mut frames = Frames::new(read, write, decryption, until, false);
    while !matches!(frames.step(service, true), Stepped::Done) {}
}

/// The same demux as a lane step: a quiet socket costs a parked readiness slot, not a thread for the
/// connection's life. The caller submits it and carries its own per-thread context into each step.
pub(crate) fn h2_lane<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
    S: H2Service + 'static,
>(
    read: R,
    write: W,
    service: S,
    decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
    until: Option<(std::time::Instant, Arc<std::sync::atomic::AtomicBool>)>,
) -> impl FnMut() -> crate::proxy::lane_pool::Next + Send + 'static {
    let mut frames = Frames::new(read, write, decryption, until, true);
    move || match frames.step(&service, false) {
        Stepped::More => crate::proxy::lane_pool::Next::More,
        Stepped::Idle => crate::proxy::lane_pool::Next::Idle,
        Stepped::Done => crate::proxy::lane_pool::Next::Done,
    }
}

/// Cuts a padded DATA frame's own buffer to `[payload]` in place — the pad-length byte skipped, the padding tail dropped — and returns the payload length, `0` when the pad swallows the payload. The allocation survives truncated, where a slice-to-`Vec` would have copied the payload out; the saturation matches the borrow-checked reference at every pad length.
#[inline]
fn cut_padded_data(body: &mut Vec<u8>, pad: usize) -> usize {
    let inner = body.len().saturating_sub(1 + pad);
    body.copy_within(1..=inner, 0);
    body.truncate(inner);
    inner
}

/// The frames both roles answer the same way: settings, pings and flow-control credit. `None`
/// leaves the frame to the role that owns the stream lifecycle.
fn control_frame(conn: &H2Conn, kind: u8, flags: u8, sid: u32, body: &[u8]) -> Option<bool> {
    match kind {
        T_SETTINGS => {
            // A payload that is not a whole number of six-byte settings is a connection error, and the peer owes the reason before the close.
            if flags & F_ACK == 0 && !body.len().is_multiple_of(6) {
                conn.refuse(E_FRAME_SIZE);
                return Some(false);
            }
            if flags & F_ACK == 0 && !conn.apply_settings(body) {
                return Some(false);
            }
            Some(true)
        }
        T_PING => {
            if flags & F_ACK == 0 && body.len() == 8 {
                return Some(conn.send_control(T_PING, F_ACK, 0, body));
            }
            Some(true)
        }
        T_WINDOW => {
            if body.len() != 4 {
                return Some(true);
            }
            let inc =
                u64::from(u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7FFF_FFFF);
            if inc == 0 {
                return Some(true);
            }
            let mut conn_window = conn
                .send_conn
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if sid == 0 {
                *conn_window = conn_window.saturating_add(inc).min((1 << 31) - 1);
            } else if let Some(state) = conn
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&sid)
            {
                let mut window = state
                    .send_window
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *window = window.saturating_add(inc).min((1 << 31) - 1);
            }
            conn.wake.notify_all();
            Some(true)
        }
        _ => None,
    }
}

/// A DATA frame's credit is its wire length, taken before the in-place cut that makes the frame's
/// own buffer the queued chunk: flow control counts the whole payload, the Pad Length octet and the
/// padding included (RFC 7540 6.9), as the reference's take of `f.Length` does.
fn queue_data(conn: &H2Conn, flags: u8, sid: u32, mut body: Vec<u8>) -> bool {
    let wire_len = body.len();
    if flags & F_PADDED != 0 {
        let Some(&pad) = body.first() else {
            return true;
        };
        cut_padded_data(&mut body, pad as usize);
    }
    let streams = conn.streams.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(state) = streams.get(&sid).cloned() else {
        drop(streams);
        conn.replenish(sid, wire_len);
        return true;
    };
    drop(streams);
    let done = {
        let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !st.dead {
            st.body.push_back(body);
            if flags & F_END != 0 {
                st.ended = true;
            }
        }
        state.cv.notify_all();
        st.both_ended()
    };
    conn.replenish(sid, wire_len);
    if done {
        conn.retire(sid);
    }
    true
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one arm per frame kind; splitting the dispatcher would scatter the protocol"
)]
fn pump_frame(
    conn: &Arc<H2Conn>,
    service: &dyn H2Service,
    kind: u8,
    flags: u8,
    sid: u32,
    mut body: Vec<u8>,
    frag: &mut Option<(u32, Vec<u8>, bool)>,
    opened: Option<&Arc<AtomicBool>>,
) -> bool {
    if let Some(alive) = control_frame(conn, kind, flags, sid, &body) {
        return alive;
    }
    match kind {
        T_HEADERS => {
            if sid == 0 || sid.is_multiple_of(2) {
                return true;
            }
            let mut block = body;
            let mut pos = 0;
            if flags & F_PADDED != 0 {
                let Some(&len) = block.first() else {
                    return true;
                };
                pos = 1 + len as usize;
                if pos > block.len() {
                    return true;
                }
            }
            if flags & F_PRIORITY != 0 {
                pos += 5;
                if pos > block.len() {
                    return true;
                }
            }
            block.drain(..pos);
            let end_headers = flags & F_END_HEADERS != 0;
            let end_stream = flags & F_END != 0;
            if end_headers {
                // A HEADERS for another stream while one is still assembling is a connection error; drop the stale assembly, serve this.
                let _ = frag.take();
                if conn
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .contains_key(&sid)
                {
                    return true;
                }
                if service.open(conn, sid, &block, end_stream) {
                    if let Some(opened) = opened {
                        opened.store(true, Ordering::Relaxed);
                    }
                }
            } else {
                *frag = Some((sid, block, end_stream));
            }
            true
        }
        T_CONT => {
            if let Some((pending, mut gathered, end_stream)) = frag.take() {
                if pending != sid {
                    *frag = Some((pending, gathered, end_stream));
                    return true;
                }
                // A header block reassembled past the implementation limit is a connection error (RFC 7540 4.3): refuse before growing it, so endless CONTINUATION frames cannot accumulate without bound.
                if gathered.len() + body.len() > HEAD_CAP {
                    conn.refuse(E_PROTOCOL);
                    return false;
                }
                gathered.extend_from_slice(&body);
                if flags & F_END_HEADERS != 0 {
                    if service.open(conn, sid, &gathered, end_stream) {
                        if let Some(opened) = opened {
                            opened.store(true, Ordering::Relaxed);
                        }
                    }
                } else {
                    *frag = Some((sid, gathered, end_stream));
                }
            }
            true
        }
        T_DATA => {
            // The credit is the frame's wire length, taken before the in-place cut that makes the frame's own buffer the queued chunk: flow control counts the whole DATA payload, the Pad Length octet and the Padding included (RFC 7540 6.9), as the reference's take of `f.Length` does.
            let wire_len = body.len();
            if flags & F_PADDED != 0 {
                let Some(&pad) = body.first() else {
                    return true;
                };
                cut_padded_data(&mut body, pad as usize);
            }
            let streams = conn.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(state) = streams.get(&sid).cloned() else {
                drop(streams);
                conn.replenish(sid, wire_len);
                return true;
            };
            drop(streams);
            let (finished, abandoned, stopped) = {
                let mut st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
                let finished = st.finished || st.request_ended;
                let abandoned = st.abandoned;
                let stopped = st.stopped;
                if !abandoned && !st.dead && !stopped {
                    st.body.push_back(body);
                    if flags & F_END != 0 {
                        st.ended = true;
                    }
                }
                state.cv.notify_all();
                (finished, abandoned, stopped)
            };
            if abandoned || stopped {
                if !conn.replenish_connection(wire_len) {
                    return false;
                }
                if abandoned && flags & F_END != 0 {
                    conn.retire(sid);
                }
                return true;
            }
            if finished && flags & F_END != 0 {
                conn.retire(sid);
            }
            conn.replenish(sid, wire_len);
            true
        }
        T_RST => {
            conn.reset_stream(sid);
            true
        }
        T_GOAWAY => {
            conn.goaway.store(true, Ordering::SeqCst);
            true
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{test_bind, Connection};
    use crate::h2::{read_head, read_head_bounded, MAGIC};
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::Duration;

    /// The production pump with no demux clock: a unit test drives frames, not a connection's handshake.
    fn pump_frame(
        conn: &Arc<H2Conn>,
        service: &dyn H2Service,
        kind: u8,
        flags: u8,
        sid: u32,
        body: Vec<u8>,
        frag: &mut Option<(u32, Vec<u8>, bool)>,
    ) -> bool {
        super::pump_frame(conn, service, kind, flags, sid, body, frag, None)
    }

    fn test_service(settings: &XhttpSettings) -> XhttpService {
        let users = crate::proxy::one_user([0u8; 16]);
        XhttpService {
            settings: settings.clone(),
            serve: Arc::new(move |reader, writer, decryption| {
                serve_stream(reader, writer, &users, true, decryption);
            }),
        }
    }

    struct H2Client {
        stream: Connection,
        next: u32,
        decoder: Decoder,
        held: VecDeque<(u8, u8, u32, Vec<u8>)>,
    }

    impl H2Client {
        /// Opens the test peer and reads the server's opening frames under the socket deadline, so a
        /// demux that never answers fails the test instead of parking it.
        fn connect(addr: SocketAddr) -> Self {
            let mut stream = Connection::connect(addr).expect("connects");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("timeout");
            stream.write_all(MAGIC).expect("preface");
            let mut initial = Vec::with_capacity(12);
            initial.extend_from_slice(&S_WINDOW.to_be_bytes());
            initial.extend_from_slice(&WINDOW.to_be_bytes());
            write_frame(&mut stream, T_SETTINGS, 0, 0, &initial);
            let mut conn = Self {
                stream,
                next: 1,
                decoder: Decoder::default(),
                held: VecDeque::new(),
            };
            for _ in 0..3 {
                let (len, kind, flags, _) = read_head_bounded(&mut conn.stream).expect("frame");
                let mut body = crate::proxy::unfilled(len);
                conn.stream.read_exact(&mut body).expect("body");
                if kind == T_SETTINGS && flags & F_ACK == 0 {
                    write_frame(&mut conn.stream, T_SETTINGS, F_ACK, 0, &[]);
                }
            }
            conn
        }

        fn headers(
            &mut self,
            method: &str,
            target: &str,
            extra: &[(&str, &str)],
            end_stream: bool,
        ) -> u32 {
            let id = self.next;
            self.next += 2;
            let mut fields = vec![
                (":method", method),
                (":path", target),
                (":scheme", "http"),
                (":authority", "127.0.0.1"),
            ];
            fields.extend_from_slice(extra);
            let block = block_encode(&fields);
            let flags = if end_stream {
                F_END | F_END_HEADERS
            } else {
                F_END_HEADERS
            };
            write_frame(&mut self.stream, T_HEADERS, flags, id, &block);
            self.stream.flush().expect("flushes");
            id
        }

        fn data(&mut self, id: u32, payload: &[u8], end: bool) {
            let mut at = 0;
            while at < payload.len() {
                let end_at = (at + 16384).min(payload.len());
                let last = end && end_at == payload.len();
                write_frame(
                    &mut self.stream,
                    T_DATA,
                    if last { F_END } else { 0 },
                    id,
                    &payload[at..end_at],
                );
                at = end_at;
            }
            if end && payload.is_empty() {
                write_frame(&mut self.stream, T_DATA, F_END, id, &[]);
            }
            self.stream.flush().expect("flushes");
        }

        /// Every DATA frame is padded: a pad-length byte in front of the payload, `pad` bytes after it, the last frame ending the stream. Chunk sizing leaves room for both pad halves inside one frame.
        fn padded_data(&mut self, id: u32, payload: &[u8], pad: u8, end: bool) {
            let room = MAX_RECV_FRAME - 1 - pad as usize;
            let mut at = 0;
            loop {
                let end_at = (at + room).min(payload.len());
                let chunk = &payload[at..end_at];
                let last = end && end_at == payload.len();
                let mut frame = Vec::with_capacity(1 + chunk.len() + pad as usize);
                frame.push(pad);
                frame.extend_from_slice(chunk);
                frame.extend(std::iter::repeat_n(pad, pad as usize));
                write_frame(
                    &mut self.stream,
                    T_DATA,
                    if last { F_PADDED | F_END } else { F_PADDED },
                    id,
                    &frame,
                );
                at = end_at;
                if last || at == payload.len() {
                    break;
                }
            }
            self.stream.flush().expect("flushes");
        }

        /// The next frame this reader has a use for: a wanted frame for `id` comes off what an
        /// earlier reader set aside before the socket is read at all, and a frame that arrived for
        /// another stream is set aside instead of dropped. A PING is answered here, once, so no
        /// reader has to remember to.
        fn next_frame(&mut self, id: u32, want: impl Fn(u8) -> bool) -> (u8, u8, u32, Vec<u8>) {
            loop {
                if let Some(at) = self.held.iter().position(|f| f.2 == id && want(f.0)) {
                    return self.held.remove(at).expect("the position just found");
                }
                let (len, kind, flags, got) = read_head_bounded(&mut self.stream).expect("frame");
                let mut body = crate::proxy::unfilled(len);
                self.stream.read_exact(&mut body).expect("body");
                if kind == T_PING && flags & F_ACK == 0 && body.len() == 8 {
                    write_frame(&mut self.stream, T_PING, F_ACK, 0, &body);
                    continue;
                }
                if got == id && want(kind) {
                    return (kind, flags, got, body);
                }
                self.hold(kind, flags, got, body);
            }
        }

        /// A frame belonging to a stream this reader is not waiting on. Dropping one is how a
        /// multiplexed response arrives short: the bytes were read and then thrown away.
        fn hold(&mut self, kind: u8, flags: u8, id: u32, body: Vec<u8>) {
            if !body.is_empty() && matches!(kind, T_DATA | T_HEADERS | T_CONT) {
                self.held.push_back((kind, flags, id, body));
            }
        }

        fn response_head(&mut self, id: u32) -> u16 {
            let mut block = Vec::new();
            loop {
                let (_, flags, _, frame) =
                    self.next_frame(id, |kind| matches!(kind, T_HEADERS | T_CONT));
                block.extend_from_slice(&frame);
                if flags & F_END_HEADERS != 0 {
                    let mut status = 0u16;
                    let mut seen = false;
                    self.decoder
                        .decode(&block, &mut |name, value| {
                            if seen || name != &b":status"[..] {
                                return;
                            }
                            seen = true;
                            status = std::str::from_utf8(value)
                                .unwrap_or_default()
                                .parse()
                                .unwrap_or(0);
                        })
                        .expect("decodes");
                    return status;
                }
            }
        }

        fn response_data(&mut self, id: u32, n: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                let (kind, flags, _, frame) =
                    self.next_frame(id, |kind| matches!(kind, T_DATA | T_RST));
                assert!(kind != T_RST, "stream reset");
                let take = (n - out.len()).min(frame.len());
                out.extend_from_slice(&frame[..take]);
                self.hold(kind, flags, id, frame[take..].to_vec());
            }
            out
        }

        /// Read the server's DATA the way a strict peer's flow control does: never grant more window, and fail the moment a frame outruns what was granted. A `grant`-byte connection window, no `WINDOW_UPDATE` ever sent, so a server that honours flow control stops at `grant` (returned as `false`), while one that outran it yields `true` past the boundary.
        fn outruns_the_granted_window(&mut self, id: u32, grant: u64) -> bool {
            // The ceiling only ends the correct run, where the peer's send window is exhausted and it blocks; the verdict is the byte count, never the clock.
            let _ = self.stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut left = grant;
            loop {
                let mut head = [0u8; 9];
                if fill(&mut self.stream, &mut head).is_none() {
                    return false;
                }
                let len =
                    usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
                let kind = head[3];
                let flags = head[4];
                let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7FFF_FFFF;
                let mut body = crate::proxy::unfilled(len);
                if len > 0 && fill(&mut self.stream, &mut body).is_none() {
                    return false;
                }
                match kind {
                    T_DATA if sid == id => {
                        let taken = len as u64;
                        if taken > left {
                            return true;
                        }
                        left -= taken;
                    }
                    T_PING if flags & F_ACK == 0 && len == 8 => {
                        write_frame(&mut self.stream, T_PING, F_ACK, 0, &body);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Fill `buf` from the socket, returning `None` on EOF or a read error (including the timeout that means a window-exhausted peer has stopped) so a drain can distinguish "no more to observe" from a frame count.
    fn fill(stream: &mut Connection, buf: &mut [u8]) -> Option<usize> {
        let mut at = 0;
        while at < buf.len() {
            match stream.read(&mut buf[at..]) {
                Ok(0) => return None,
                Ok(n) => at += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        Some(at)
    }

    fn echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
        let echo = test_bind("127.0.0.1:0").expect("binds");
        let addr = echo.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        (addr, handle)
    }

    fn vless_header(port: u16) -> Vec<u8> {
        ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses")
        .encode_request_header("127.0.0.1", port)
    }

    fn test_settings(mode: &str) -> XhttpSettings {
        let node = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"xhttpSettings": {{"path": "/up/", "mode": "{mode}"}}}}}}"#
        ))
        .expect("parses");
        XhttpSettings::from_json(node.get("streamSettings")).expect("settings")
    }

    fn serve_one(
        settings: XhttpSettings,
        id: [u8; 16],
        takes: usize,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        serve_one_with(settings, id, takes, None)
    }

    fn serve_one_with(
        settings: XhttpSettings,
        id: [u8; 16],
        takes: usize,
        decryption: Option<Arc<ferrox_core::vless_encryption::Server>>,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let front = test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let handle = crate::budgets::spawn(move || {
            for stream in front.incoming().take(takes) {
                let Ok(stream) = stream else { continue };
                let Ok(read) = stream.try_clone() else {
                    continue;
                };
                let settings = settings.clone();
                let decryption = decryption.clone();
                crate::budgets::spawn(move || {
                    serve_h2(
                        read,
                        stream,
                        &settings,
                        &crate::proxy::one_user(id),
                        true,
                        decryption,
                    );
                });
            }
        });
        (addr, handle)
    }

    fn padding() -> String {
        format!("http://127.0.0.1/up/?x_padding={}", "X".repeat(128))
    }

    /// The in-place padded-DATA cut equals the borrow-checked reference at every pad length: a partially padded frame keeps exactly `body[1..len - pad]`, a pad that swallows the payload leaves the empty chunk `get(..).unwrap_or_default()` produced, and the length the caller replenishes by is the same in both.
    #[test]
    fn a_padded_data_cut_matches_the_reference_at_every_pad_length() {
        for len in 1..=8usize {
            let frame: Vec<u8> = (0..len as u8)
                .map(|b| b.wrapping_mul(37).wrapping_add(5))
                .collect();
            for pad in 0..=10usize {
                let mut mine = frame.clone();
                let cut = cut_padded_data(&mut mine, pad);
                let want = frame
                    .get(1..frame.len().saturating_sub(pad))
                    .unwrap_or_default()
                    .to_vec();
                assert_eq!(mine, want, "len {len} pad {pad}: cut bytes differ");
                assert_eq!(cut, want.len(), "len {len} pad {pad}: cut length differs");
            }
        }
    }

    /// The received frame is queued as itself. The DATA chunk and the unterminated header block keep the buffer the loop read the body into, so nothing copies between the frame and the queue: a `to_vec` on that path moves the base pointer and grows or shrinks the allocation, and the assertions carry both.
    /// The frame's body is not zeroed: the read fills every byte of it, so the zero pass
    /// in front of the read was work generated and thrown away, once a frame, over the
    /// whole frame's length. The counting allocator's `zeroed` counter is the witness.
    #[test]
    fn a_received_frames_body_is_not_zero_filled() {
        let mut bytes = crate::h2::MAGIC.to_vec();
        let body = vec![7u8; 4096];
        bytes.extend_from_slice(&crate::h2::frame_head(body.len(), T_DATA, 0, 1));
        bytes.extend_from_slice(&body);
        let reader = std::io::Cursor::new(bytes);
        let written = Arc::new(Mutex::new(Vec::new()));
        let slices = Arc::new(AtomicUsize::new(0));
        let writer = Counted { written, slices };
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            serve_h2(
                reader,
                writer,
                &XhttpSettings::stream_one(),
                &crate::proxy::one_user([0u8; 16]),
                true,
                None,
            );
        });
        assert_eq!(counts.zeroed, 0, "no frame body is zeroed");
    }

    #[test]
    fn a_received_frame_is_queued_as_the_buffer_the_loop_read_it_into() {
        let (conn, _, _) = bare_conn();
        let settings = XhttpSettings::stream_one();
        let mut frag: Option<(u32, Vec<u8>, bool)> = None;

        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let body = vec![9u8; 5];
        let base = body.as_ptr();
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_DATA,
            0,
            1,
            body,
            &mut frag
        ));
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            let queued = st.body.front().expect("queued");
            assert_eq!(queued.as_ptr(), base, "DATA queued the frame's own buffer");
            assert_eq!(
                queued.capacity(),
                5,
                "the queue did not grow or shrink the allocation"
            );
        }

        // Padded: the cut happens in place, so the payload's base is still the frame's base and the capacity still fits the whole frame.
        let frame = vec![2u8, b'a', b'b', b'c', b'd', b'e', b'f', 2, 2];
        let base = frame.as_ptr();
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_DATA,
            F_PADDED,
            1,
            frame,
            &mut frag
        ));
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            let queued = st.body.back().expect("queued");
            assert_eq!(
                queued.as_ptr(),
                base,
                "padded DATA cut in the frame's buffer"
            );
            assert_eq!(
                queued.capacity(),
                9,
                "the padded payload kept the frame's allocation"
            );
            assert_eq!(queued.as_slice(), b"abcdef");
        }

        // A header block that does not end is stored owned in the assembly, not copied in front of it.
        let block = vec![0x88u8, 0x86, 0x40, 0x01, 0x02];
        let base = block.as_ptr();
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_HEADERS,
            0,
            3,
            block,
            &mut frag
        ));
        let stored = frag.as_ref().expect("stored").1.as_ptr();
        assert_eq!(stored, base, "the header block is the assembly's buffer");
        drop(frag);
    }

    /// A short read leaves the frame's tail where the loop put it: the reader carries a cursor
    /// instead of draining its head, and the assertions read the address, which the drain moved.
    #[test]
    fn a_partly_read_frame_is_not_moved() {
        let (conn, _, _) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let frame: Vec<u8> = (0u8..64).collect();
        let base = frame.as_ptr();
        state
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .body
            .push_back(frame);
        let mut reader = H2StreamReader {
            conn,
            stream: Arc::clone(&state),
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let mut first = [0u8; 16];
        assert_eq!(reader.read(&mut first).unwrap(), 16);
        assert!(first.iter().copied().eq(0u8..16), "the head of the frame");
        assert_eq!(reader.cur.as_ptr(), base, "the frame is its own allocation");
        assert_eq!(
            reader.cur.len(),
            64,
            "the frame was not shortened by the read"
        );
        assert_eq!(reader.cur[16], 16, "the tail sits at its own offset");
        assert!(
            state
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .body
                .is_empty(),
            "the queue handed the frame over"
        );
        let mut rest = [0u8; 48];
        assert_eq!(reader.read(&mut rest).unwrap(), 48);
        assert!(rest.iter().copied().eq(16u8..64), "the tail of the frame");
        assert!(reader.cur.is_empty(), "the spent frame is released");
    }

    #[test]
    fn a_frame_window_is_the_readers_own_allocation() {
        let (conn, _, _) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let frame: Vec<u8> = (0u8..64).collect();
        let base = frame.as_ptr();
        state
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .body
            .push_back(frame);
        let mut reader = H2StreamReader {
            conn,
            stream: Arc::clone(&state),
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let window = crate::proxy::WindowRead::read_window(&mut reader).unwrap();
        assert_eq!(
            window.bytes().as_ptr(),
            base,
            "the window is the frame's own allocation"
        );
        assert_eq!(window.bytes().len(), 64, "the whole frame is the window");
        assert_eq!(window.parts(), &[(0, 64)]);
    }

    /// The window path drives a client connection's demux the way `Read` does: without the pump
    /// the frame stays on the transport and the reader waits out the stall budget.
    #[test]
    fn a_client_frame_window_pumps_the_demux() {
        let mut wire = Vec::new();
        write_frame(&mut wire, T_DATA, 0, 1, b"answer");
        let (conn, state, _) = reading_conn(Box::new(std::io::Cursor::new(wire)));
        let mut reader = H2StreamReader {
            conn,
            stream: state,
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let window = crate::proxy::WindowRead::read_window(&mut reader)
            .expect("the window pumps the client demux");
        assert_eq!(window.bytes(), b"answer");
    }

    /// The response head's fields come out of one list and one pass: a hop-by-hop name is
    /// recognised in place, where the lowercase form it replaces allocated a `String` per line,
    /// and the list is opened for the lines it will hold rather than grown into.
    #[test]
    fn a_response_head_is_split_without_allocating() {
        let head = "HTTP/1.1 200 OK\r\n\
                    Content-Length: 12\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Connection: close\r\n\
                    Keep-Alive: timeout=5\r\n\
                    Content-Lengths: 12\r\n\
                    Connectio: x\r\n\
                    Content-Type: text/plain\r\n\
                    Server: x\r\n\r\n";
        let (fields, counts) = ferrox_core::alloc_count::measure(|| response_fields(head));
        assert_eq!(
            counts.allocs, 1,
            "the field list, nothing per line: {counts:?}"
        );
        assert_eq!(
            fields,
            vec![
                (":status", "200"),
                ("Content-Lengths", "12"),
                ("Connectio", "x"),
                ("Content-Type", "text/plain"),
                ("Server", "x"),
            ],
            "the connection's own fields are skipped in any spelling, and a near miss is kept"
        );
        assert_eq!(
            block_encode(&fields),
            block_encode(&[
                (":status", "200"),
                ("Content-Lengths", "12"),
                ("Connectio", "x"),
                ("Content-Type", "text/plain"),
                ("Server", "x"),
            ]),
            "the block is the fields' own bytes"
        );
    }

    #[test]
    fn a_response_head_reaches_h2_with_lowercase_field_names() {
        let mut head =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Padding: ab\r\n\r\n".to_vec();
        let capacity = head.capacity();
        let base = head.as_ptr();
        lower_field_names(&mut head);
        assert_eq!(
            &head[..],
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nx-padding: ab\r\n\r\n"
        );
        assert_eq!(head.capacity(), capacity, "the head keeps its allocation");
        assert_eq!(head.as_ptr(), base, "the head is lowered where it lies");
    }

    #[test]
    fn h2_stream_up_carries_bulk_both_ways() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers("GET", "/up/sess-h2-01", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(down), 200);
        let up = client.headers(
            "POST",
            "/up/sess-h2-01",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..32768u32).map(|i| (i % 251) as u8).collect();
        let mut body = header;
        body.extend_from_slice(&payload);
        client.data(up, &body, true);
        assert_eq!(client.response_head(up), 200);
        assert_eq!(client.response_data(down, 2), [0, 0]);
        assert_eq!(client.response_data(down, payload.len()), payload);
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A carrier whose protocol above xHTTP is not VLESS hands the demux a closure instead of the engine session: the split request reaches it with the upload body as its first bytes and its reply lands on the downlink stream.
    #[test]
    fn a_carried_session_runs_above_the_demux() {
        let front = test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let ran = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&ran);
        let server = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            let read = stream.try_clone().expect("clone");
            let service = XhttpSessionService::new(
                test_settings("stream-up"),
                Arc::new(move |mut reader, mut writer, _decryption| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    let mut body = Vec::new();
                    let mut chunk = [0u8; 8];
                    while body.len() < 8 {
                        match reader.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => body.extend_from_slice(&chunk[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(e) if crate::proxy::is_timeout(&e) => {}
                            Err(_) => break,
                        }
                    }
                    let _ = writer.write_all(&body);
                    writer.finish();
                }),
            );
            serve_h2_service(read, stream, &service, None);
        });
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers("GET", "/up/carried-1", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(down), 200);
        let up = client.headers(
            "POST",
            "/up/carried-1",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        client.data(up, b"carried!", true);
        assert_eq!(client.response_head(up), 200);
        assert_eq!(client.response_data(down, 8), b"carried!");
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "the carried session ran once"
        );
        drop(client);
        server.join().expect("joins");
    }

    /// A padded DATA frame is queued as exactly its payload: the pad-length byte and the pad tail are gone before the chunk reaches the session, so an echo over the padded uplink round-trips the payload untouched.
    #[test]
    fn a_padded_data_frame_is_its_payload_between_pad_byte_and_pad_tail() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers("GET", "/up/sess-h2-pad", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(down), 200);
        let up = client.headers(
            "POST",
            "/up/sess-h2-pad",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..50000u32).map(|i| (i % 251) as u8).collect();
        let mut body = header;
        body.extend_from_slice(&payload);
        client.padded_data(up, &body, 7, true);
        assert_eq!(client.response_head(up), 200);
        assert_eq!(client.response_data(down, 2), [0, 0]);
        assert_eq!(client.response_data(down, payload.len()), payload);
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A session that refuses the dial still owns the downlink stream its carrier opened: leaving that stream open parks the client's next read on a reply that can no longer arrive.
    #[test]
    fn a_refused_session_ends_the_stream_it_parked() {
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers(
            "GET",
            "/up/sess-h2-refused",
            &[("referer", pad.as_str())],
            true,
        );
        assert_eq!(client.response_head(down), 200);
        let up = client.headers(
            "POST",
            "/up/sess-h2-refused",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        // A uuid the served id does not carry, so the session refuses before it dials.
        let header = ferrox_core::vless::VlessLink::parse(
            "vless://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses")
        .encode_request_header("127.0.0.1", 9);
        client.data(up, &header, true);
        // The witness is the frame that lifts the park, so the clock bounds only the failure: 3 s of silence is a read that would never return.
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let (kind, flags, _, _) = client.next_frame(down, |kind| matches!(kind, T_DATA | T_RST));
        assert!(
            kind == T_RST || flags & F_END != 0,
            "the refused session left stream {down} open: frame {kind} flags {flags:#04x}"
        );
        drop(client);
        server.join().expect("joins");
    }

    /// A peer that opens a downlink and then dies without ever posting leaves the server's stream thread parked on a sequence that can no longer arrive — the connection, not that thread, owns the session, so its death has to end it and free the thread with it.
    #[test]
    fn a_dead_carrier_ends_the_session_it_parked() {
        let (addr, server) = serve_one(test_settings("stream-up"), [0xbbu8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers(
            "GET",
            "/up/sess-h2-dead",
            &[("referer", pad.as_str())],
            true,
        );
        assert_eq!(client.response_head(down), 200);
        assert!(
            crate::xhttp::session_is_carried("sess-h2-dead"),
            "the downlink holds its session while its carrier lives"
        );
        drop(client);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while crate::xhttp::session_is_carried("sess-h2-dead")
            && std::time::Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            !crate::xhttp::session_is_carried("sess-h2-dead"),
            "the carrier died and left its session parked: nothing will ever wake that thread"
        );
        server.join().expect("joins");
    }

    /// A peer that announces a frame larger than the default `SETTINGS_MAX_FRAME_SIZE` must be refused with `FRAME_SIZE_ERROR`, not have its length reserved and its phantom body awaited — the read is unbounded, so a parked oversized head would pin the thread.
    #[test]
    fn a_frame_beyond_the_max_size_is_refused_not_reserved_or_read() {
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let oversized = MAX_RECV_FRAME + 1;
        let mut head = [0u8; 9];
        head[0..3].copy_from_slice(&(oversized as u32).to_be_bytes()[1..]);
        head[3] = T_HEADERS;
        head[4] = F_END_HEADERS;
        head[5..9].copy_from_slice(&1u32.to_be_bytes());
        client.stream.write_all(&head).expect("head");
        client.stream.flush().expect("flushes");
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut got = [0u8; 9];
        assert!(
            fill(&mut client.stream, &mut got).is_some(),
            "the server neither answered nor refused the oversized frame"
        );
        assert_eq!(got[3], T_GOAWAY, "expected a GOAWAY");
        let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
        let mut body = crate::proxy::unfilled(len);
        assert!(fill(&mut client.stream, &mut body).is_some(), "goaway body");
        assert_eq!(
            u32::from_be_bytes(body[4..8].try_into().unwrap()),
            E_FRAME_SIZE,
            "the GOAWAY must carry FRAME_SIZE_ERROR"
        );
        drop(client);
        let _ = server;
    }

    /// Endless CONTINUATION frames for one stream must not grow a header block past `HEAD_CAP`: the reassembly is refused with a GOAWAY rather than accumulated without bound. Repeated because one round only sees the race on a busy machine — the refusal used to lose its GOAWAY to our own abortive close.
    #[test]
    fn a_header_block_reassembled_past_the_cap_refuses_the_connection() {
        for round in 0..24 {
            let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
            let mut client = H2Client::connect(addr);
            // Open a header block that never ends: HEADERS without END_HEADERS.
            write_frame(&mut client.stream, T_HEADERS, 0, 1, &[0x88]);
            // Feed CONTINUATION frames of one max-size payload each; a compliant endpoint refuses at HEAD_CAP, so none is ever answered by an opened stream.
            let chunk = [0u8; MAX_RECV_FRAME];
            for _ in 0..(HEAD_CAP / MAX_RECV_FRAME + 2) {
                write_frame(&mut client.stream, T_CONT, 0, 1, &chunk);
            }
            client.stream.flush().expect("flushes");
            client
                .stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut got = [0u8; 9];
            assert!(
                fill(&mut client.stream, &mut got).is_some(),
                "round {round}: the server neither opened the stream nor refused the over-long block"
            );
            assert_eq!(got[3], T_GOAWAY, "round {round}: expected a GOAWAY");
            let len = usize::from(got[0]) << 16 | usize::from(got[1]) << 8 | usize::from(got[2]);
            let mut body = crate::proxy::unfilled(len);
            assert!(
                fill(&mut client.stream, &mut body).is_some(),
                "round {round}: goaway body"
            );
            assert_eq!(
                u32::from_be_bytes(body[4..8].try_into().unwrap()),
                E_PROTOCOL,
                "round {round}: the GOAWAY must carry PROTOCOL_ERROR"
            );
            drop(client);
            let _ = server;
        }
    }

    #[test]
    fn h2_packet_up_reassembles_out_of_order_posts() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("packet-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let down = client.headers("GET", "/up/sess-h2-02", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(down), 200);
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let one = client.headers(
            "POST",
            "/up/sess-h2-02/1",
            &[("referer", pad.as_str()), ("content-length", "4096")],
            false,
        );
        client.data(one, &payload[4096..], true);
        assert_eq!(client.response_head(one), 200);
        let mut body0 = header.clone();
        body0.extend_from_slice(&payload[..4096]);
        let zero = client.headers(
            "POST",
            "/up/sess-h2-02/0",
            &[
                ("referer", pad.as_str()),
                ("content-length", &body0.len().to_string()),
            ],
            false,
        );
        client.data(zero, &body0, true);
        assert_eq!(client.response_head(zero), 200);
        assert_eq!(client.response_data(down, 2), [0, 0]);
        assert_eq!(client.response_data(down, payload.len()), payload);
        drop(client);
        server.join().expect("joins");
        let _ = echo;
    }

    /// The dual dial's downlink GET and upload POST share the one h2 connection the REALITY
    /// handshake already carried: the stream-up writer is a DATA stream, and the echo comes back on
    /// the GET the same client opened.
    #[test]
    fn h2_dual_split_stream_up_carries_both_directions_on_one_connection() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-up"), [0xaau8; 16], 1);
        let conn = Connection::connect(addr).expect("connects");
        let raw = Arc::new(conn.try_clone().expect("clones"));
        let settings = test_settings("stream-up");
        let (mut reader, writer) = connect_dual_split(
            conn.try_clone().expect("clones"),
            conn,
            raw,
            "127.0.0.1",
            &settings,
            "http",
        )
        .expect("dials both directions");
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..32768u32).map(|i| (i % 251) as u8).collect();
        let mut body = header;
        body.extend_from_slice(&payload);
        assert!(writer.send(&body), "the upload takes the request");
        writer.finish();
        let mut status = [0u8; 2];
        reader.read_exact(&mut status).expect("the response head");
        assert_eq!(status, [0, 0]);
        let mut got = vec![0u8; payload.len()];
        reader.read_exact(&mut got).expect("the echo");
        assert_eq!(got, payload);
        drop(reader);
        drop(writer);
        server.join().expect("joins");
        let _ = echo;
    }

    /// Packet-up on the dual dial opens one POST stream per batch beside the GET, and the answer is
    /// drained before the next batch shares the connection.
    #[test]
    fn h2_dual_split_packet_up_posts_beside_the_downlink() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("packet-up"), [0xaau8; 16], 1);
        let conn = Connection::connect(addr).expect("connects");
        let raw = Arc::new(conn.try_clone().expect("clones"));
        let settings = test_settings("packet-up");
        let (mut reader, writer) = connect_dual_split(
            conn.try_clone().expect("clones"),
            conn,
            raw,
            "127.0.0.1",
            &settings,
            "http",
        )
        .expect("dials both directions");
        let header = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let mut body = header;
        body.extend_from_slice(&payload);
        assert!(writer.send(&body), "the upload takes the request");
        writer.finish();
        let mut status = [0u8; 2];
        reader.read_exact(&mut status).expect("the response head");
        assert_eq!(status, [0, 0]);
        let mut got = vec![0u8; payload.len()];
        reader.read_exact(&mut got).expect("the echo");
        assert_eq!(got, payload);
        drop(reader);
        drop(writer);
        server.join().expect("joins");
        let _ = echo;
    }

    /// The scripted peer answers two streams at once and puts the other stream's frames in front of
    /// each reader, so a reader that throws away what it did not ask for returns the wrong bytes
    /// rather than only losing them when the scheduler lets two responses interleave.
    #[test]
    fn an_early_frame_waits_for_the_reader_that_asked_for_it() {
        let listener = test_bind("127.0.0.1:0").expect("binds a scripted peer");
        let addr = listener.local_addr().expect("addr");
        let scripted = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("the client connects");
            for _ in 0..3 {
                write_frame(&mut peer, T_SETTINGS, 0, 0, &[]);
            }
            let ok = block_encode(&[(":status", "200")]);
            let late = block_encode(&[(":status", "500")]);
            write_frame(&mut peer, T_HEADERS, F_END_HEADERS, 3, &ok);
            write_frame(&mut peer, T_HEADERS, F_END_HEADERS, 1, &ok);
            write_frame(&mut peer, T_DATA, 0, 3, b"held-first-");
            write_frame(&mut peer, T_DATA, 0, 1, b"head-then-tail");
            write_frame(&mut peer, T_DATA, 0, 1, b"-continued");
            write_frame(&mut peer, T_DATA, 0, 3, b"late-second!");
            write_frame(&mut peer, T_HEADERS, F_END_HEADERS, 3, &late);
            peer.flush().expect("flushes");
            let mut drain = [0u8; 64];
            while peer.read(&mut drain).is_ok_and(|n| n > 0) {}
        });
        let mut client = H2Client::connect(addr);
        assert_eq!(client.response_head(1), 200);
        assert_eq!(client.response_data(1, 4), b"head");
        assert_eq!(
            client.response_data(1, 10),
            b"-then-tail",
            "a frame longer than the read asked for has to keep its remainder"
        );
        assert_eq!(client.response_data(1, 10), b"-continued");
        assert_eq!(
            client.response_data(3, 11),
            b"held-first-",
            "another stream's reader must not spend the bytes this one is waiting for"
        );
        assert_eq!(
            client.response_head(3),
            200,
            "a status read while waiting on another stream is not noise to drop"
        );
        drop(client);
        scripted.join().expect("the peer ends");
    }

    #[test]
    fn h2_stream_one_carries_a_duplex_echo() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-one"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let only = client.headers(
            "POST",
            "/up/",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let mut body = vless_header(echo_addr.port());
        body.extend_from_slice(b"ping");
        client.data(only, &body, true);
        assert_eq!(client.response_head(only), 200);
        assert_eq!(client.response_data(only, 2), [0, 0]);
        assert_eq!(client.response_data(only, 4), b"ping");
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A bulk duplex echo whose response outruns the initial connection window: the server must not send DATA past the `65_535` it was granted when the client never sends a `WINDOW_UPDATE`. Crediting the server's own send window for the bytes it consumed on the way in (the bug) lets the echo outrun that grant, which a strict peer answers with a flow-control reset — the `early eof` and `Connection reset by peer` the upstream suites report.
    #[test]
    fn h2_bulk_echo_never_outruns_the_granted_connection_window() {
        let (echo_addr, echo) = echo_server();
        let (addr, server) = serve_one(test_settings("stream-one"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let only = client.headers(
            "POST",
            "/up/",
            &[
                ("referer", pad.as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        let mut body = vless_header(echo_addr.port());
        let payload: Vec<u8> = (0..131_072u32).map(|i| (i % 251) as u8).collect();
        body.extend_from_slice(&payload);
        client.data(only, &body, true);
        assert_eq!(client.response_head(only), 200);
        assert!(
            !client.outruns_the_granted_window(only, 65_535),
            "server sent DATA beyond the window it was granted"
        );
        drop(client);
        echo.join().expect("joins");
        server.join().expect("joins");
    }

    /// A downlink that finishes ends its session: the packet-up upload's `wait_ended` is parked on that session, not on the stream.
    #[test]
    fn a_finished_downlink_ends_its_session() {
        let sid = "h2-downlink-finish";
        crate::xhttp::start_session_for_probe(sid);
        assert!(
            crate::xhttp::session_is_carried(sid),
            "the session starts carried"
        );
        let (conn, _written, _slices) = bare_conn();
        let out = H2StreamOut {
            conn,
            stream: 1,
            _owner: None,
            client: false,
        };
        out.bind_session(sid);
        out.end();
        assert!(
            !crate::xhttp::session_is_carried(sid),
            "the finished downlink leaves no session parked"
        );
    }

    /// An ended session wakes the upload it was relaying: a stream-up POST parked in `H2StreamReader::read` must not hold its worker until the connection dies.
    #[test]
    fn an_ended_session_wakes_its_upload_reader() {
        let sid = "h2-ended-upload";
        crate::xhttp::start_session_for_probe(sid);
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .expect("streams")
            .insert(2, Arc::clone(&state));
        let downlink = H2StreamOut {
            conn: Arc::clone(&conn),
            stream: 1,
            _owner: None,
            client: false,
        };
        downlink.bind_session(sid);
        let upload = H2StreamOut {
            conn: Arc::clone(&conn),
            stream: 2,
            _owner: None,
            client: false,
        };
        upload.bind_upload(sid);
        let mut reader = H2StreamReader {
            conn,
            stream: state,
            id: 2,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = sender.send(reader.read(&mut byte).map_err(|error| error.kind()));
        });
        downlink.end();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)),
            Ok(Ok(0)),
            "the ended session ends its parked upload"
        );
    }

    /// A downlink that ends before its upload's body still owes the POST a 200: the upload's stream
    /// stays in the table, so the deferred head is not answered by a reset.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_finished_downlink_leaves_its_upload_for_the_response() {
        struct Discard;
        impl H2Service for Discard {
            fn open(
                &self,
                _conn: &Arc<H2Conn>,
                _sid: u32,
                _block: &[u8],
                _end_stream: bool,
            ) -> bool {
                true
            }
        }
        let sid = "h2-deferred-upload-answer";
        crate::xhttp::start_session_for_probe(sid);
        let (conn, written, _slices) = bare_conn();
        let upload_state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(2, Arc::clone(&upload_state));
        let downlink = H2StreamOut {
            conn: Arc::clone(&conn),
            stream: 1,
            _owner: None,
            client: false,
        };
        downlink.bind_session(sid);
        let upload = H2StreamOut {
            conn: Arc::clone(&conn),
            stream: 2,
            _owner: None,
            client: false,
        };
        upload.bind_upload(sid);
        downlink.end();
        assert!(
            !crate::xhttp::session_is_carried(sid),
            "the finished downlink ends its session"
        );
        assert!(
            conn.streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(&2),
            "the upload stays for its deferred 200"
        );
        assert!(
            pump_frame(&conn, &Discard, T_DATA, 0, 2, vec![0xa5; 4096], &mut None),
            "a late upload frame is discarded instead of ending the connection"
        );
        assert!(
            upload_state
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .body
                .is_empty(),
            "the stopped upload queues nothing for an answer already owed"
        );
        let mut writer = H2StreamWriter {
            conn: Arc::clone(&conn),
            stream: 2,
            head: Vec::new(),
            headed: false,
        };
        writer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .expect("the deferred 200 goes out");
        upload.end();
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut headers, mut end) = (false, false);
        let mut at = 0;
        while at + 9 <= bytes.len() {
            let len = usize::from(bytes[at]) << 16
                | usize::from(bytes[at + 1]) << 8
                | usize::from(bytes[at + 2]);
            let kind = bytes[at + 3];
            let flags = bytes[at + 4];
            let id =
                u32::from_be_bytes([bytes[at + 5], bytes[at + 6], bytes[at + 7], bytes[at + 8]])
                    & 0x7FFF_FFFF;
            assert!(kind != T_RST || id != 2, "the upload was reset");
            headers |= id == 2 && kind == T_HEADERS;
            end |= id == 2 && kind == T_DATA && flags & F_END != 0;
            at += 9 + len;
        }
        assert!(headers, "the POST receives its 200");
        assert!(end, "the response ends the stream instead of a reset");
        assert!(
            !conn
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(&2),
            "the answered upload retires"
        );
    }

    #[test]
    fn h2_refusals_carry_their_statuses() {
        let (addr, server) = serve_one(test_settings("packet-up"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let pad = padding();
        let wrong = client.headers("GET", "/elsewhere", &[("referer", pad.as_str())], true);
        assert_eq!(client.response_head(wrong), 404);
        let bare = client.headers("POST", "/up/nopad", &[], true);
        assert_eq!(client.response_head(bare), 400);
        let bad_seq = client.headers("POST", "/up/abc/xyz", &[("referer", pad.as_str())], true);
        client.data(bad_seq, b"junk", true);
        assert_eq!(client.response_head(bad_seq), 500);
        drop(client);
        server.join().expect("joins");
    }

    /// A client's request half ending is not its response ending: the connection is pooled and the
    /// peer still owes an answer, so `finish` must not turn the read into EOF.
    #[test]
    fn a_finished_request_half_still_reads_the_response() {
        let (conn, _written, _slices) = bare_conn();
        let client = super::H2Client {
            conn: Arc::clone(&conn),
            next: AtomicU32::new(1),
        };
        let (mut reader, mut writer) = client
            .open("example.org", &test_settings("stream-one"), "https", false)
            .expect("the stream opens");
        writer.write_all(b"request").expect("the request goes out");
        writer.finish();
        let answering = {
            let conn = Arc::clone(&conn);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                let head = block_encode(&[(":status", "200")]);
                client_frame(&conn, T_HEADERS, F_END_HEADERS, 1, head);
                queue_data(&conn, F_END, 1, b"answer".to_vec());
            })
        };
        let mut got = [0u8; 6];
        let n = reader.read(&mut got).expect("the response reads");
        answering.join().expect("the peer answers");
        assert_eq!(
            n, 6,
            "the answer must not be lost when the request half ends"
        );
        assert_eq!(&got, b"answer");
    }

    /// A read that owns a poll must not sleep in it: a lane that cannot finish a client frame hands
    /// the thread back, and the bytes it did take are kept for the next turn.
    #[test]
    fn a_lane_step_hands_back_a_client_frame_it_cannot_finish() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(300)),
            ..Default::default()
        });
        let (conn, state, _written) = reading_conn(Box::new(Silent));
        let mut reader = H2StreamReader {
            conn: Arc::clone(&conn),
            stream: state,
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let _step = crate::proxy::RelayStep::enter();
        let began = std::time::Instant::now();
        let mut buf = [0u8; 8];
        let error = reader
            .read(&mut buf)
            .expect_err("the lane cannot finish the frame");
        let took = began.elapsed();
        crate::budgets::clear();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::WouldBlock,
            "a lane step yields the poll instead of reporting the stream dead"
        );
        assert!(
            took < Duration::from_millis(150),
            "the lane step slept {} ms waiting for the frame",
            took.as_millis()
        );
    }

    /// The frame the previous turn left half-read still completes, and its body arrives once: the
    /// lane's yields must not lose the head or the bytes already taken.
    #[test]
    fn a_frame_split_across_lane_turns_arrives_whole() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(300)),
            ..Default::default()
        });
        let mut frame = Vec::new();
        write_frame(&mut frame, T_DATA, F_END, 1, b"answer");
        let (conn, state, _written) = reading_conn(Box::new(Trickle {
            bytes: frame,
            at: 0,
            tick: 0,
            chunk: 3,
        }));
        let mut reader = H2StreamReader {
            conn: Arc::clone(&conn),
            stream: state,
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let _step = crate::proxy::RelayStep::enter();
        let mut got = Vec::new();
        let mut turns = 0;
        while got.is_empty() {
            turns += 1;
            assert!(turns < 64, "the frame never completed across lane turns");
            let mut buf = [0u8; 16];
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(error) if crate::proxy::is_timeout(&error) => {}
                Err(error) => panic!("the frame failed: {error}"),
            }
        }
        crate::budgets::clear();
        assert_eq!(
            got, b"answer",
            "the body the previous turns took is dropped"
        );
    }

    /// A reader that times out on every call: nothing ever arrives on the peer's transport.
    struct Silent;

    impl Read for Silent {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }
    }

    /// Bytes that arrive a few at a time, with a timeout between every delivery, the way a TLS
    /// record lands on a socket armed with the relay poll.
    struct Trickle {
        bytes: Vec<u8>,
        at: usize,
        tick: usize,
        chunk: usize,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.at >= self.bytes.len() {
                return Ok(0);
            }
            self.tick += 1;
            if self.tick % 2 == 1 {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let n = self.chunk.min(buf.len()).min(self.bytes.len() - self.at);
            buf[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    /// A connection whose client transport is a script, with stream 1 in its table.
    fn reading_conn(
        read: Box<dyn Read + Send>,
    ) -> (Arc<H2Conn>, Arc<H2Stream>, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let slices = Arc::new(AtomicUsize::new(0));
        let write: SharedWriter = Arc::new(Mutex::new(Box::new(Counted {
            written: Arc::clone(&written),
            slices,
        })
            as Box<dyn crate::proxy::FrameWrite + Send>));
        let dead = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(H2Conn {
            write,
            control: Control::Inline,
            streams: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashSet::new()),
            session_of: Mutex::new(HashMap::new()),
            upload_of: Mutex::new(HashMap::new()),
            send_conn: Mutex::new(65_535),
            wake: Condvar::new(),
            decoder: Mutex::new(Decoder::default()),
            max_frame: Mutex::new(16_384),
            peer_initial: Mutex::new(65_535),
            dead,
            goaway: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            client_read: Some(Mutex::new(read)),
            client_partial: Mutex::new(PartialFrame::default()),
            client_head: Mutex::new(None),
            raw: None,
            decryption: None,
        });
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(true),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        (conn, state, written)
    }

    /// A response head split across `HEADERS` and `CONTINUATION` decodes its `:status` once the
    /// block completes; dropping the continuation left it `None` and the packet path read that as
    /// success.
    #[test]
    fn a_fragmented_response_head_decodes_its_status() {
        let (conn, state, _) = reading_conn(Box::new(Silent));
        assert!(client_frame(&conn, T_HEADERS, 0, 1, Vec::new()));
        assert!(client_frame(&conn, T_CONT, F_END_HEADERS, 1, vec![0x8d]));
        assert_eq!(
            state
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .status,
            Some(404)
        );
    }

    /// Padding sits at the end of a `HEADERS` frame, behind the priority fields: only the pad length
    /// octet and the priority are skipped from the front, and the padding is cut from the tail.
    #[test]
    fn a_padded_response_head_keeps_its_status() {
        let (conn, state, _) = reading_conn(Box::new(Silent));
        assert!(client_frame(
            &conn,
            T_HEADERS,
            F_END_HEADERS | F_PADDED,
            1,
            vec![3, 0x88, 0, 0, 0]
        ));
        assert_eq!(
            state
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .status,
            Some(200)
        );
        assert!(client_frame(
            &conn,
            T_HEADERS,
            F_END_HEADERS | F_PADDED | F_PRIORITY,
            1,
            vec![2, 0, 0, 0, 0, 0x10, 0x8d, 0, 0]
        ));
        assert_eq!(
            state
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .status,
            Some(404)
        );
    }

    /// A downlink that finishes leaves no body to deliver: the upload reader parked on the same
    /// stream must end with it, not hold its worker until the relay stall expires.
    #[test]
    fn a_finished_downlink_wakes_its_upload_reader() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(true),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let mut reader = H2StreamReader {
            conn: Arc::clone(&conn),
            stream: state,
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        let parked = crate::budgets::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = sender.send(reader.read(&mut byte).map_err(|error| error.kind()));
        });
        thread::sleep(Duration::from_millis(50));
        conn.end_stream(1);
        let verdict = receiver.recv_timeout(Duration::from_secs(2));
        crate::budgets::clear();
        assert_eq!(
            verdict,
            Ok(Ok(0)),
            "a finished downlink left its upload reader parked for the stall"
        );
        parked.join().expect("the reader returns");
    }

    /// The reader leaving at a finished response must stop the queue and the stream's credit with
    /// it: the stream stays open in the client's eyes, so what it sends after that is bounded by
    /// the stream window, while the shared connection window keeps flowing for every other stream.
    #[test]
    fn a_data_after_the_upload_reader_left_is_dropped_and_uncredited() {
        let (conn, written, slices) = bare_conn();
        let settings = XhttpSettings::stream_one();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: true,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(true),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let mut reader = H2StreamReader {
            conn: Arc::clone(&conn),
            stream: Arc::clone(&state),
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        assert_eq!(reader.read(&mut [0u8; 8]).expect("eof"), 0);
        let mut frag: Option<(u32, Vec<u8>, bool)> = None;
        for _ in 0..3 {
            assert!(pump_frame(
                &conn,
                &test_service(&settings),
                T_DATA,
                0,
                1,
                vec![b'x'; 16],
                &mut frag
            ));
        }
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(
                st.body.is_empty(),
                "no chunk is queued for a reader that left"
            );
        }
        let out = written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(
            slices.load(Ordering::SeqCst),
            3,
            "each dropped frame returns the connection's credit"
        );
        let (frames, _) = out.as_chunks::<13>();
        let connection: Vec<u32> = frames
            .iter()
            .map(|frame| {
                assert_eq!(
                    frame[3], T_WINDOW,
                    "only a window update answers a dropped frame"
                );
                assert_eq!(
                    u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]),
                    0,
                    "the stream's own window stays spent"
                );
                u32::from_be_bytes([frame[9], frame[10], frame[11], frame[12]])
            })
            .collect();
        assert_eq!(
            connection,
            vec![16, 16, 16],
            "the shared window rises by every dropped frame"
        );
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_DATA,
            F_END,
            1,
            Vec::new(),
            &mut frag
        ));
        assert!(
            conn.streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&1)
                .is_none(),
            "the request ending retires the stream"
        );
    }

    /// A sealed handshake reads a body no peer has to finish: it runs under the handshake clock,
    /// so a silent peer cannot hold the stream for the relay stall.
    #[test]
    fn a_sealed_handshake_is_bounded_by_its_clock() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(200)),
            relay_stall: Some(Duration::from_secs(2)),
            ..Default::default()
        });
        let (_encryption, decryption) =
            ferrox_core::vless_encryption::generate_pair(false, "native", "1rtt", "600s");
        let server = ferrox_core::vless_encryption::Server::new(
            ferrox_core::vless_encryption::ServerConfig::parse(&decryption).expect("server config"),
        );
        let (addr, handle) =
            serve_one_with(test_settings("stream-one"), [0xaau8; 16], 1, Some(server));
        let mut client = H2Client::connect(addr);
        let only = client.headers(
            "POST",
            "/up/",
            &[
                ("referer", padding().as_str()),
                ("content-type", "application/grpc"),
            ],
            false,
        );
        assert_eq!(client.response_head(only), 200, "the stream is accepted");
        let began = std::time::Instant::now();
        let (kind, flags, _, _) = client.next_frame(only, |kind| matches!(kind, T_DATA | T_RST));
        let took = began.elapsed();
        crate::budgets::clear();
        assert!(
            kind == T_RST || (kind == T_DATA && flags & F_END != 0),
            "the stalled handshake must end its stream, got kind {kind} flags {flags}"
        );
        assert!(
            took < Duration::from_secs(1),
            "the handshake clock did not end the stream: {took:?}"
        );
        drop(client);
        let _ = handle;
    }

    /// A peer that offers the h2 preface and no request is ended at the handshake clock: the demux
    /// does not hold its worker for a connection that never opened a stream.
    #[test]
    fn a_preface_without_a_request_ends_at_the_handshake_budget() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(200)),
            ..Default::default()
        });
        let front = test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let opened = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&opened);
        let server = thread::spawn(crate::budgets::carrying(move || {
            let (stream, _) = front.accept().expect("accepts");
            let read = stream.try_clone().expect("clone");
            read.set_read_timeout(Some(crate::budgets::RELAY_POLL))
                .expect("arms the poll");
            let service = XhttpSessionService::new(
                test_settings("stream-up"),
                Arc::new(move |_, _, _| {
                    seen.store(true, Ordering::SeqCst);
                }),
            );
            let began = std::time::Instant::now();
            serve_h2_service(read, stream, &service, None);
            began.elapsed()
        }));
        let mut client = Connection::connect(addr).expect("connects");
        client.write_all(MAGIC).expect("writes the preface");
        let took = server.join().expect("joins");
        crate::budgets::clear();
        assert!(!opened.load(Ordering::SeqCst), "no stream opened");
        assert!(
            took < Duration::from_secs(2),
            "the demux did not end at its clock: {took:?}"
        );
        drop(client);
    }

    /// A gRPC head is not a request either: the VLESS body decodes later, so the connection clock
    /// stays until then and a head-only peer cannot hold the demux.
    #[test]
    fn a_grpc_head_does_not_clear_the_connection_clock() {
        let (conn, _, _) = bare_conn();
        let settings = crate::config::GrpcSettings::path("/p");
        let service =
            crate::grpc::GrpcService::new(&settings, &[], true, Arc::new(AtomicBool::new(false)));
        let block = block_encode(&[
            (":path", "/p"),
            (":method", "POST"),
            ("content-type", "application/grpc"),
        ]);
        let opened = Arc::new(AtomicBool::new(false));
        let mut frag = None;
        assert!(super::pump_frame(
            &conn,
            &service,
            T_HEADERS,
            F_END_HEADERS,
            3,
            block,
            &mut frag,
            Some(&opened),
        ));
        assert!(!opened.load(Ordering::SeqCst), "a gRPC head opened");
    }

    /// A refused request must not clear the clock: the reply is the last thing the peer sends, then
    /// it goes silent, and the stream never opened.
    #[test]
    fn a_refused_head_does_not_open_the_connection() {
        struct Reject;
        impl H2Service for Reject {
            fn open(&self, _: &Arc<H2Conn>, _: u32, _: &[u8], _: bool) -> bool {
                false
            }
        }
        let (conn, _, _) = bare_conn();
        let opened = Arc::new(AtomicBool::new(false));
        let mut frag = None;
        assert!(super::pump_frame(
            &conn,
            &Reject,
            T_HEADERS,
            F_END_HEADERS,
            3,
            vec![0x82],
            &mut frag,
            Some(&opened),
        ));
        assert!(!opened.load(Ordering::SeqCst), "a refused head opened");
    }

    /// A refused session frees its request stream with an `RST_STREAM`: leaving it open would credit
    /// a body nobody reads for the connection's life.
    #[test]
    fn an_aborted_writer_resets_its_stream() {
        let (conn, written, _) = bare_conn();
        let Some((_reader, _writer, out)) = conn.open(3, false) else {
            panic!("the stream opens");
        };
        let writer = crate::xhttp::XhttpWriter::new(Vec::<u8>::new());
        writer.set_h2(out);
        writer.abort();
        let bytes = written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert!(
            bytes
                .as_chunks::<9>()
                .0
                .iter()
                .any(|f| { f[3] == T_RST && u32::from_be_bytes([f[5], f[6], f[7], f[8]]) == 3 }),
            "no RST_STREAM went out"
        );
    }

    /// A HEADERS on stream 0 is not a request: it must not clear the clock, or a silent peer keeps
    /// the demux worker without ever opening a stream.
    #[test]
    fn a_headers_on_stream_zero_keeps_the_handshake_clock() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(200)),
            ..Default::default()
        });
        let front = test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let opened = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&opened);
        let server = thread::spawn(crate::budgets::carrying(move || {
            let (stream, _) = front.accept().expect("accepts");
            let read = stream.try_clone().expect("clone");
            read.set_read_timeout(Some(crate::budgets::RELAY_POLL))
                .expect("arms the poll");
            let service = XhttpSessionService::new(
                test_settings("stream-up"),
                Arc::new(move |_, _, _| {
                    seen.store(true, Ordering::SeqCst);
                }),
            );
            let began = std::time::Instant::now();
            serve_h2_service(read, stream, &service, None);
            began.elapsed()
        }));
        let mut client = Connection::connect(addr).expect("connects");
        client.write_all(MAGIC).expect("writes the preface");
        // HEADERS, END_STREAM|END_HEADERS, stream 0: ignored by the demux.
        client
            .write_all(&[0, 0, 1, T_HEADERS, F_END | F_END_HEADERS, 0, 0, 0, 0, 0x82])
            .expect("writes the ignored head");
        let took = server.join().expect("joins");
        crate::budgets::clear();
        assert!(!opened.load(Ordering::SeqCst), "no stream opened");
        assert!(
            took < Duration::from_secs(2),
            "the ignored head cleared the clock: {took:?}"
        );
        drop(client);
    }

    /// The writer a credit is read by: it answers with the bytes it was handed, so the number of writes it took is exact — over a loopback socket the same shape moves with the scheduler.
    struct Counted {
        written: Arc<Mutex<Vec<u8>>>,
        slices: Arc<AtomicUsize>,
    }

    impl Write for Counted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Counted {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            self.slices.fetch_add(1, Ordering::SeqCst);
            parts.iter().all(|part| self.write_all(part).is_ok())
        }
    }

    /// A connection with no streams and no peer: only what a call writes can be seen.
    fn conn_with(write: Box<dyn crate::proxy::FrameWrite + Send>, threaded: bool) -> Arc<H2Conn> {
        let write: SharedWriter = Arc::new(Mutex::new(write));
        let dead = Arc::new(AtomicBool::new(false));
        let control = if threaded {
            Control::threaded(Arc::clone(&write), Arc::clone(&dead))
        } else {
            Control::Inline
        };
        Arc::new(H2Conn {
            write,
            control,
            streams: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashSet::new()),
            session_of: Mutex::new(HashMap::new()),
            upload_of: Mutex::new(HashMap::new()),
            send_conn: Mutex::new(65_535),
            wake: Condvar::new(),
            decoder: Mutex::new(Decoder::default()),
            max_frame: Mutex::new(16_384),
            peer_initial: Mutex::new(65_535),
            dead,
            goaway: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            client_read: None,
            client_partial: Mutex::new(PartialFrame::default()),
            client_head: Mutex::new(None),
            raw: None,
            decryption: None,
        })
    }

    fn bare_conn() -> (Arc<H2Conn>, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let slices = Arc::new(AtomicUsize::new(0));
        let conn = conn_with(
            Box::new(Counted {
                written: Arc::clone(&written),
                slices: Arc::clone(&slices),
            }),
            false,
        );
        (conn, written, slices)
    }

    /// A SETTINGS payload whose length is not a multiple of six is a connection error
    /// (RFC 9113 6.5), so the demux answers a `FRAME_SIZE_ERROR` GOAWAY instead of closing silently.
    #[test]
    fn a_settings_length_outside_sixes_is_refused_as_a_frame_size_error() {
        struct Silent;
        impl H2Service for Silent {
            fn open(
                &self,
                _conn: &Arc<H2Conn>,
                _sid: u32,
                _block: &[u8],
                _end_stream: bool,
            ) -> bool {
                true
            }
        }
        let (conn, written, _slices) = bare_conn();
        let mut frag = None;
        assert!(
            !pump_frame(&conn, &Silent, T_SETTINGS, 0, 0, vec![0u8; 5], &mut frag),
            "a malformed SETTINGS ends the read loop"
        );
        let out = written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let at = out
            .windows(9)
            .position(|frame| frame[3] == T_GOAWAY)
            .expect("the connection answers with a GOAWAY");
        assert_eq!(
            &out[at + 4..at + 13],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0],
            "a GOAWAY with an eight-byte body and no last stream id"
        );
        assert_eq!(
            u32::from_be_bytes([out[at + 13], out[at + 14], out[at + 15], out[at + 16]]),
            E_FRAME_SIZE,
            "the refusal names FRAME_SIZE_ERROR"
        );
    }

    /// A SETTINGS window update must take the stream table before it publishes the new window:
    /// a stream inserted in between would take the new initial and then the delta again.
    #[test]
    fn a_settings_window_update_publishes_only_with_the_stream_table() {
        let (conn, _written, _slices) = bare_conn();
        let peer = conn
            .peer_initial
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let update = {
            let conn = Arc::clone(&conn);
            std::thread::spawn(move || {
                let mut body = Vec::with_capacity(6);
                body.extend_from_slice(&S_WINDOW.to_be_bytes());
                body.extend_from_slice(&100_000u32.to_be_bytes());
                conn.apply_settings(&body)
            })
        };
        let mut took_streams = false;
        for _ in 0..2_000 {
            if conn.streams.try_lock().is_err() {
                took_streams = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(peer);
        assert!(
            update.join().expect("the settings thread"),
            "the update is acked"
        );
        assert!(
            took_streams,
            "the window update did not take the stream table before publishing"
        );
        assert_eq!(conn.peer_window(), 100_000);
    }

    /// `END_STREAM` arrives on the `HEADERS` frame that opens a block, not on the last
    /// `CONTINUATION` that completes it: the flag has to ride the assembly, or a header-only
    /// request opens with a body it never has and its entry is never retired.
    #[test]
    fn an_end_stream_header_block_keeps_its_flag_across_a_continuation() {
        struct Record(Arc<Mutex<Vec<(u32, bool)>>>);
        impl H2Service for Record {
            fn open(&self, _conn: &Arc<H2Conn>, sid: u32, _block: &[u8], end_stream: bool) -> bool {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((sid, end_stream));
                true
            }
        }
        let (conn, _, _) = bare_conn();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let service = Record(Arc::clone(&seen));
        let mut frag = None;
        assert!(pump_frame(
            &conn,
            &service,
            T_HEADERS,
            F_END,
            1,
            b"\x88".to_vec(),
            &mut frag
        ));
        assert!(pump_frame(
            &conn,
            &service,
            T_CONT,
            F_END_HEADERS,
            1,
            b"\x84".to_vec(),
            &mut frag
        ));
        assert_eq!(
            *seen.lock().unwrap_or_else(PoisonError::into_inner),
            vec![(1, true)]
        );
    }

    /// A request given up before its body ends resets the stream: the table entry and the chunks
    /// queued on it go, and the peer is told with an `RST_STREAM` instead of a half-closed call that
    /// would hold the entry for the connection's life.
    #[test]
    fn aborting_an_open_stream_resets_it_and_frees_its_entry() {
        let (conn, written, _) = bare_conn();
        let (reader, _writer, _out) = conn.open(3, false).expect("opens");
        assert!(conn
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&3));
        reader.abort();
        assert!(!conn
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&3));
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            bytes[3], T_RST,
            "the peer is not told the stream is refused"
        );
        assert_eq!(
            u32::from_be_bytes(bytes[5..9].try_into().unwrap()),
            3,
            "the reset names another stream"
        );
    }

    /// A finished call gives its id back: two hundred sequential calls on one connection must not
    /// hit the table's cap, which is what a completed stream left behind would do.
    #[test]
    fn a_completed_stream_frees_its_id() {
        let (conn, _, _) = bare_conn();
        for round in 0..2u32 {
            for sid in 1..=MAX_STREAMS {
                let sid = sid + round * MAX_STREAMS;
                let Some((_reader, _writer, out)) = conn.open(sid, true) else {
                    panic!("stream {sid} was refused after {} completed", sid - 1);
                };
                assert!(conn.respond(sid, &[(":status", "200")]));
                out.end();
            }
        }
        assert!(
            conn.streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty(),
            "every completed stream left the table"
        );
    }

    /// One credit is both `WINDOW_UPDATE`s: the pair differs only by stream id, so it goes out as one 26-byte write under one lock, where two `frame()` calls were two locks and two records on the wire for the same bytes.
    #[test]
    fn a_credit_grants_both_windows_in_one_write() {
        let (conn, written, slices) = bare_conn();
        let increment = 0x1234_5678u32;
        conn.replenish(7, 0);
        conn.replenish(7, usize::MAX);
        assert_eq!(
            slices.load(Ordering::SeqCst),
            0,
            "a credit of nothing, or of more than a frame can say, writes nothing"
        );
        conn.replenish(7, increment as usize);
        assert_eq!(
            slices.load(Ordering::SeqCst),
            1,
            "one credit, one write, whatever the pair costs the old shape"
        );
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes.len(), 26, "the pair is 26 bytes and nothing else");
        let mut at = 0usize;
        for id in [0, 7] {
            let (len, kind, flags, sid) = read_head(&mut &bytes[at..at + 9]).expect("head");
            assert_eq!(
                (len, kind, flags, sid),
                (4, T_WINDOW, 0, id),
                "the frame at {at} is the credit for stream {id}"
            );
            assert_eq!(
                bytes[at + 9..at + 13],
                increment.to_be_bytes(),
                "both windows rise by the bytes consumed"
            );
            at += 13;
        }
    }

    /// A writer whose first `write_slices` holds the lock until the test releases it, so a second
    /// credit proves it queued instead of waiting behind a data write the peer has not drained.
    struct Blocked {
        written: Arc<Mutex<Vec<u8>>>,
        entered: Arc<(Mutex<bool>, Condvar)>,
        release: Arc<(Mutex<bool>, Condvar)>,
        first: AtomicBool,
    }

    impl Write for Blocked {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Blocked {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            if !self.first.swap(true, Ordering::SeqCst) {
                *self
                    .entered
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = true;
                self.entered.1.notify_all();
                let mut released = self
                    .release
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                while !*released {
                    released = self
                        .release
                        .1
                        .wait(released)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            }
            parts.iter().all(|part| self.write_all(part).is_ok())
        }
    }

    #[test]
    fn a_credit_never_waits_on_a_blocked_data_write() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let conn = conn_with(
            Box::new(Blocked {
                written: Arc::clone(&written),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                first: AtomicBool::new(false),
            }),
            true,
        );
        conn.replenish(1, 16);
        let mut in_write = entered.0.lock().unwrap_or_else(PoisonError::into_inner);
        while !*in_write {
            in_write = entered
                .1
                .wait(in_write)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(in_write);
        let (sender, receiver) = std::sync::mpsc::channel();
        let sender_conn = Arc::clone(&conn);
        thread::spawn(move || {
            sender_conn.replenish(2, 16);
            let _ = sender.send(());
        });
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)),
            Ok(()),
            "a credit queued behind a data write instead of waiting for its lock"
        );
        *release.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
        release.1.notify_all();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let len = written.lock().unwrap_or_else(PoisonError::into_inner).len();
            if len == 52 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the queued credit is written once the data write drains"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    type BlockedConn = (
        Arc<H2Conn>,
        Arc<Mutex<Vec<u8>>>,
        Arc<(Mutex<bool>, Condvar)>,
    );

    /// A connection whose one write is parked mid-frame, with the credit already queued, so a
    /// connection-level frame proves whether it queues or waits for the peer to drain.
    fn blocked_conn() -> BlockedConn {
        let written = Arc::new(Mutex::new(Vec::new()));
        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let conn = conn_with(
            Box::new(Blocked {
                written: Arc::clone(&written),
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                first: AtomicBool::new(false),
            }),
            true,
        );
        conn.replenish(1, 16);
        let mut in_write = entered.0.lock().unwrap_or_else(PoisonError::into_inner);
        while !*in_write {
            in_write = entered
                .1
                .wait(in_write)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(in_write);
        (conn, written, release)
    }

    /// The demux answers a frame batch only after the peer's write drains: a refused stream's reset
    /// and a refused connection's GOAWAY are queued, so neither waits behind the parked write.
    #[test]
    fn a_refusal_leaves_the_demux_without_a_write() {
        let (conn, written, release) = blocked_conn();
        let (reset, reset_ran) = std::sync::mpsc::channel();
        let resetter = Arc::clone(&conn);
        thread::spawn(move || {
            resetter.reset_stream(2);
            let _ = reset.send(());
        });
        let (refuse, refuse_ran) = std::sync::mpsc::channel();
        let refuser = Arc::clone(&conn);
        thread::spawn(move || {
            refuser.refuse(E_PROTOCOL);
            let _ = refuse.send(());
        });
        assert_eq!(
            reset_ran.recv_timeout(Duration::from_secs(2)),
            Ok(()),
            "a refused stream waited for the peer to drain the write it already owed"
        );
        assert_eq!(
            refuse_ran.recv_timeout(Duration::from_secs(2)),
            Ok(()),
            "a refused connection waited for the peer to drain the write it already owed"
        );
        *release.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
        release.1.notify_all();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let len = written.lock().unwrap_or_else(PoisonError::into_inner).len();
            if len == 56 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the queued refusals are written once the parked write drains"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// A shutdown that stops the control worker still writes the GOAWAY queued before it: the peer
    /// receives the refusal instead of a bare close when the block lifts after the grace.
    #[test]
    fn a_queued_goaway_survives_the_worker_stopping() {
        let (conn, written, release) = blocked_conn();
        conn.refuse(E_PROTOCOL);
        conn.control.stop();
        *release.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
        release.1.notify_all();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let len = written.lock().unwrap_or_else(PoisonError::into_inner).len();
            if len == 43 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the worker stopped with the GOAWAY still queued, so the peer never saw it"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// A dead connection has no GOAWAY left to protect, so its refusal does not wait for the grace.
    #[test]
    fn a_dead_refusal_does_not_wait_for_the_grace() {
        let (conn, _written, _slices) = bare_conn();
        conn.dead.store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();
        finish_refusal(&conn);
        assert!(
            started.elapsed() < crate::budgets::goaway_grace(),
            "a dead connection waited for the GOAWAY grace"
        );
    }

    /// A drained refusal keeps the socket for the grace, so unread request bytes cannot reset the
    /// connection before the peer reads the GOAWAY.
    #[test]
    fn a_drained_refusal_keeps_the_socket_for_the_grace() {
        let (conn, _written, _slices) = bare_conn();
        let started = std::time::Instant::now();
        finish_refusal(&conn);
        assert!(
            started.elapsed() >= crate::budgets::goaway_grace(),
            "the socket closed before the peer had the grace to read the GOAWAY"
        );
        assert!(
            conn.dead.load(Ordering::SeqCst),
            "the refusal left the connection live"
        );
    }

    /// The refusal grace is counted from the last write, not before it: a parked peer does not count
    /// as drained, and the queue reads empty once its block lifts.
    #[test]
    fn the_goaway_grace_starts_when_the_queue_drains() {
        let (conn, _written, release) = blocked_conn();
        conn.refuse(E_PROTOCOL);
        assert!(
            !conn.control.drained(Duration::from_millis(20)),
            "a parked write is not a drained queue"
        );
        *release.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
        release.1.notify_all();
        assert!(
            conn.control.drained(Duration::from_secs(2)),
            "the queue drains once the peer takes the writes"
        );
        assert!(
            conn.control.drained(Duration::ZERO),
            "a drain that completed before the call is still a live drain"
        );
    }

    /// A writer that cannot carry a byte: the control worker's first batch fails.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for Broken {
        fn write_slices(&mut self, _parts: &[&[u8]]) -> bool {
            false
        }
    }

    /// A peer that answers every inbound frame with a control frame and stops reading parks one
    /// queue element per frame in the process; the backlog is capped and the connection ends, so
    /// the memory a peer can hold is a constant rather than the length of its stream.
    #[test]
    fn a_control_flood_ends_the_connection_at_the_cap() {
        const CAP: usize = 1024;
        let written = Arc::new(Mutex::new(Vec::new()));
        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let conn = conn_with(
            Box::new(Blocked {
                written,
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                first: AtomicBool::new(false),
            }),
            true,
        );
        conn.replenish(1, 16);
        let mut in_write = entered.0.lock().unwrap_or_else(PoisonError::into_inner);
        while !*in_write {
            in_write = entered
                .1
                .wait(in_write)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(in_write);
        let mut queued = 0;
        while !conn.dead.load(Ordering::SeqCst) && queued <= CAP + CONTROL_BATCH + 2 {
            conn.replenish(2, 16);
            queued += 1;
        }
        assert!(
            conn.dead.load(Ordering::SeqCst),
            "a flooded control queue ended the connection instead of growing without a bound; {queued} frames were attempted"
        );
        assert!(
            queued >= CAP,
            "the queue admitted its cap before refusing: {queued}"
        );
        assert!(
            queued <= CAP + CONTROL_BATCH + 2,
            "the queue refuses within one batch of its cap: {queued}"
        );
        *release.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
        release.1.notify_all();
    }

    /// A worker whose own write fails ends the connection with it: before the change it exited
    /// alone and `replenish` kept queueing frames nobody would drain.
    #[test]
    fn a_failed_control_write_ends_the_connection() {
        let conn = conn_with(Box::new(Broken), true);
        conn.replenish(1, 16);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !conn.dead.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "a failed control write marks the connection dead"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// A control send that fails ends the read loop: its caller sees `false`, kills the
    /// connection and wakes the parked streams, instead of dispatching frames nothing can answer.
    #[test]
    fn a_failed_control_send_ends_the_read_loop() {
        struct Silent;
        impl H2Service for Silent {
            fn open(
                &self,
                _conn: &Arc<H2Conn>,
                _sid: u32,
                _block: &[u8],
                _end_stream: bool,
            ) -> bool {
                true
            }
        }
        let conn = conn_with(Box::new(NullWrite), true);
        conn.dead.store(true, Ordering::SeqCst);
        let mut frag = None;
        assert!(
            !pump_frame(&conn, &Silent, T_PING, 0, 0, vec![0u8; 8], &mut frag),
            "a PING whose ACK cannot be sent ends the read loop"
        );
        assert!(
            !pump_frame(&conn, &Silent, T_SETTINGS, 0, 0, Vec::new(), &mut frag),
            "a SETTINGS whose ACK cannot be sent ends the read loop"
        );
    }

    /// DATA the demux discards for an abandoned request still spends the shared receive window:
    /// the connection credit must come back or later uploads on other streams stall, while the
    /// stream's own window stays spent so the abandoned upload cannot grow.
    #[test]
    fn a_discarded_frame_returns_the_connection_window() {
        let (conn, written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: true,
                request_ended: false,
                stopped: false,
                abandoned: true,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(true),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        let mut frag = None;
        assert!(pump_frame(
            &conn,
            &test_service(&test_settings("stream-up")),
            T_DATA,
            0,
            1,
            vec![0u8; 5],
            &mut frag
        ));
        let out = written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let updates = |stream: u32| {
            out.windows(13)
                .filter(|frame| {
                    frame[3] == T_WINDOW
                        && u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]) == stream
                })
                .map(|frame| u32::from_be_bytes([frame[9], frame[10], frame[11], frame[12]]))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            updates(0),
            vec![5],
            "the shared window rises by the bytes the demux discarded"
        );
        assert!(
            updates(1).is_empty(),
            "the abandoned stream keeps its own window spent"
        );
        let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(st.body.is_empty(), "an abandoned request queues nothing");
    }

    /// A connection with one stream and all the credit it needs: the frame writer is the only
    /// observer of how many calls a downlink window costs.
    fn streaming_conn(total: usize) -> (Arc<H2Conn>, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
        let (conn, written, slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(total as u64),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        *conn
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = total as u64;
        (conn, written, slices)
    }

    /// The frames the pre-batch loop sent one call at a time, kept as the oracle.
    fn one_call_per_frame(
        payload: &[u8],
        max: usize,
        mut conn: usize,
        mut stream: usize,
    ) -> Vec<u8> {
        let mut wire = Vec::new();
        let mut left = payload;
        while !left.is_empty() {
            let take = left.len().min(max).min(conn).min(stream);
            let (head, body) = (&left[..take], &left[..take]);
            wire.extend_from_slice(&frame_head(body.len(), T_DATA, 0, 1));
            wire.extend_from_slice(head);
            conn -= take;
            stream -= take;
            left = &left[take..];
        }
        wire
    }

    /// A promoted relay window is four DATA frames of the default frame size and one write, where
    /// the per-frame shape paid four; both shapes put the same bytes in the same order.
    #[test]
    fn a_data_window_leaves_as_one_write() {
        let payload: Vec<u8> = (0..4 * 16_384u32).map(|i| (i % 251) as u8).collect();
        let (conn, written, slices) = streaming_conn(payload.len());
        assert!(conn.send_data(1, &payload), "the whole window is sent");
        assert_eq!(
            slices.load(Ordering::SeqCst),
            1,
            "one window, one write, whatever the four frames cost the old shape"
        );
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            *bytes,
            one_call_per_frame(&payload, 16_384, payload.len(), payload.len()),
            "the batch is the frames the per-frame loop wrote, byte for byte"
        );
    }

    /// A frame the window cuts short is still its own frame: batching only the writes never
    /// widens a frame past the credit that admitted it.
    #[test]
    fn a_data_batch_writes_the_frames_the_old_loop_did() {
        for len in [1, 16_383, 16_384, 16_385, 20_000, 65_535, 65_536] {
            let payload: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
            let (conn, written, slices) = streaming_conn(len);
            assert!(conn.send_data(1, &payload), "the window is sent");
            let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(
                *bytes,
                one_call_per_frame(&payload, 16_384, len, len),
                "the frames of a {len}-byte window are the old loop's frames"
            );
            let frames = len.div_ceil(16_384);
            assert!(slices.load(Ordering::SeqCst) <= frames);
        }
    }

    /// A lane step hands its thread back at the poll; only a wait outside a lane takes the stall.
    #[test]
    fn a_lane_read_hands_the_poll_back() {
        let (conn, _written, _slices) = streaming_conn(0);
        let stream = conn
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&1)
            .cloned()
            .expect("the stream");
        let mut reader = H2StreamReader {
            conn,
            stream,
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let mut buf = [0u8; 8];
        let started = std::time::Instant::now();
        let error = {
            let _step = crate::proxy::RelayStep::enter();
            reader.read(&mut buf).expect_err("no body arrived")
        };
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a lane waits the poll, not the stall"
        );
        assert!(crate::proxy::is_timeout(&error), "{error:?}");
    }

    /// A lane's polls hand the thread back, but an idle body still ends at the stall.
    #[test]
    fn a_lane_read_still_ends_at_the_stall() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(40)),
            ..Default::default()
        });
        let (conn, _written, _slices) = streaming_conn(0);
        let stream = conn
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&1)
            .cloned()
            .expect("the stream");
        let mut reader = H2StreamReader {
            conn,
            stream,
            id: 1,
            at: 0,
            cur: Vec::new(),
            idle_since: None,
        };
        let mut buf = [0u8; 8];
        let error = {
            let _step = crate::proxy::RelayStep::enter();
            let mut polls = 0u32;
            loop {
                polls += 1;
                assert!(polls < 500, "a lane read never ended at the stall");
                match reader.read(&mut buf) {
                    Err(error) if crate::proxy::is_timeout(&error) => {}
                    other => break other.expect_err("no body arrived"),
                }
            }
        };
        crate::budgets::clear();
        assert!(!crate::proxy::is_timeout(&error), "{error:?}");
    }

    /// A sender the peer never credits gives up at the relay stall, so a downlink cannot park its thread on a window that never arrives.
    #[test]
    fn a_sender_with_no_credit_gives_up_at_the_stall() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(500)),
            ..Default::default()
        });
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(0),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, state);
        *conn
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = 0;
        let (sent, got) = std::sync::mpsc::channel();
        let sender = Arc::clone(&conn);
        let running = crate::budgets::spawn(move || {
            let _ = sent.send(sender.send_data(1, b"ping"));
        });
        let verdict = got.recv_timeout(Duration::from_secs(3));
        conn.dead.store(true, Ordering::SeqCst);
        conn.wake.notify_all();
        running.join().expect("sender thread");
        crate::budgets::clear();
        assert_eq!(verdict, Ok(false), "a sender with no credit returned");
    }

    /// A request that ended its own body still has a response to send: waiting for credit must not
    /// read the inbound `END_STREAM` as a dead stream and drop the downlink.
    #[test]
    fn an_ended_request_still_sends_its_response() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: true,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(0),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        let held = state
            .send_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let sender = Arc::clone(&conn);
        let running = crate::budgets::spawn(move || sender.send_data(1, b"ping"));
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while conn.send_conn.try_lock().is_ok() {
            assert!(
                std::time::Instant::now() < until,
                "the sender never took the connection window"
            );
            thread::yield_now();
        }
        drop(held);
        {
            let mut conn_window = conn
                .send_conn
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let mut stream_window = state
                .send_window
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *conn_window += 4;
            *stream_window += 4;
        }
        conn.wake.notify_all();
        assert!(
            running.join().expect("sender thread"),
            "the ended request's response is still sent"
        );
        crate::budgets::clear();
    }

    /// A credit that landed between the caller's look at the room and its wait is already paid for:
    /// sleeping the whole poll would cap a peer that grants one window at a time, which is what a
    /// small initial window does.
    #[test]
    fn a_credit_that_landed_before_the_wait_is_not_slept_out() {
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(4),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        *conn
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = 4;
        let began = std::time::Instant::now();
        conn.wait_room(1, Duration::from_millis(250));
        assert!(
            began.elapsed() < Duration::from_millis(100),
            "the paid window was slept out"
        );
    }

    /// A reset stream has no window left to grant, so its writer must be woken by the reset, not
    /// left to discover the stream is gone when the relay stall expires.
    #[test]
    fn a_reset_stream_wakes_a_sender_waiting_on_its_window() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let (conn, _written, _slices) = bare_conn();
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(0),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));
        *conn
            .send_conn
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = 0;
        let held = state
            .send_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (sent, got) = std::sync::mpsc::channel();
        let sender = Arc::clone(&conn);
        let running = crate::budgets::spawn(move || {
            let _ = sent.send(sender.send_data(1, b"ping"));
        });
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while conn.send_conn.try_lock().is_ok() {
            assert!(
                std::time::Instant::now() < until,
                "the sender never took the connection window"
            );
            thread::yield_now();
        }
        drop(held);
        let until = std::time::Instant::now() + Duration::from_secs(2);
        while conn.send_conn.try_lock().is_err() {
            assert!(
                std::time::Instant::now() < until,
                "the sender never parked on its stream window"
            );
            thread::yield_now();
        }
        let began = std::time::Instant::now();
        conn.reset_stream(1);
        let verdict = got.recv_timeout(Duration::from_secs(2));
        let took = began.elapsed();
        conn.dead.store(true, Ordering::SeqCst);
        conn.wake.notify_all();
        running.join().expect("sender thread");
        crate::budgets::clear();
        assert_eq!(verdict, Ok(false), "the reset sender returned");
        assert!(
            took < Duration::from_secs(1),
            "the reset stream kept its writer parked for {took:?}"
        );
    }

    /// A POST that never sends its body leaves the stream's reader parked on a request no peer will finish; the relay stall ends it, and the stream is reset instead of holding its thread for the life of the connection.
    #[test]
    fn a_post_with_no_body_ends_at_the_stall() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(Duration::from_millis(200)),
            ..Default::default()
        });
        let (addr, server) = serve_one(test_settings("stream-one"), [0xaau8; 16], 1);
        let mut client = H2Client::connect(addr);
        let id = client.headers("POST", "/up/", &[("referer", padding().as_str())], false);
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        assert_eq!(client.response_head(id), 200, "the request is accepted");
        let (kind, flags, _, _) = client.next_frame(id, |kind| matches!(kind, T_DATA | T_RST));
        crate::budgets::clear();
        assert!(
            kind == T_DATA && flags & F_END != 0,
            "a body that never arrives must end the stream at the stall, got kind {kind} flags {flags}"
        );
        drop(client);
        server.join().expect("joins");
    }

    /// The last bytes the connection wrote are one credit for `sid` of `inc`: the pair of
    /// four-octet `WINDOW_UPDATE` frames, connection-level then stream-level, both saying `inc`.
    fn expect_one_credit(
        written: &Arc<Mutex<Vec<u8>>>,
        slices: &Arc<AtomicUsize>,
        sid: u32,
        inc: u32,
    ) {
        assert_eq!(
            slices.load(Ordering::SeqCst),
            1,
            "one credit, one write for stream {sid}"
        );
        let bytes = written.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(bytes.len(), 26, "the credit is the pair and nothing else");
        let mut at = 0usize;
        for id in [0, sid] {
            let (len, kind, flags, got) = read_head(&mut &bytes[at..at + 9]).expect("head");
            assert_eq!(
                (len, kind, flags, got),
                (4, T_WINDOW, 0, id),
                "the frame at {at} is the credit for stream {id}"
            );
            assert_eq!(
                bytes[at + 9..at + 13],
                inc.to_be_bytes(),
                "both windows rise by the frame's wire length"
            );
            at += 13;
        }
    }

    /// A DATA frame's credit is what the frame cost the peer's window — the whole wire payload, Pad Length octet and Padding counted (RFC 7540 6.9, where the reference takes `f.Length`) — so both `WINDOW_UPDATE` halves carry `1 + payload + pad`. Crediting the post-cut payload under-credits every padded frame by `1 + pad`; crediting a swallowed payload nothing starves the peer outright.
    #[test]
    fn a_padded_data_credit_counts_the_whole_wire_payload() {
        let (conn, written, slices) = bare_conn();
        let settings = XhttpSettings::stream_one();
        let mut frag: Option<(u32, Vec<u8>, bool)> = None;
        let state = Arc::new(H2Stream {
            state: Mutex::new(StreamState {
                body: VecDeque::new(),
                ended: false,
                finished: false,
                request_ended: false,
                stopped: false,
                abandoned: false,
                status: None,
                dead: false,
            }),
            cv: Condvar::new(),
            send_window: Mutex::new(65_535),
            responded: AtomicBool::new(false),
        });
        conn.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(1, Arc::clone(&state));

        // A live stream: pad byte 2, payload 6, pad tail 2 — nine octets on the wire, six into the queue.
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_DATA,
            F_PADDED,
            1,
            vec![2u8, b'a', b'b', b'c', b'd', b'e', b'f', 2, 2],
            &mut frag
        ));
        {
            let st = state.state.lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(
                st.body.front().expect("queued").as_slice(),
                b"abcdef",
                "the queued chunk is still the cut payload"
            );
        }
        expect_one_credit(&written, &slices, 1, 9);

        // A pad that swallows the payload: the cut returns nothing, the frame still cost the peer its wire length.
        written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        slices.store(0, Ordering::SeqCst);
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_DATA,
            F_PADDED,
            1,
            vec![200u8, b'x'],
            &mut frag
        ));
        expect_one_credit(&written, &slices, 1, 2);

        // DATA for a stream that is not there is credited at the wire length on its way out, too.
        written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        slices.store(0, Ordering::SeqCst);
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_DATA,
            F_PADDED,
            9,
            vec![3u8, b'p', 3, 3, 3],
            &mut frag
        ));
        expect_one_credit(&written, &slices, 9, 5);

        // Unpadded: the payload is the wire, and that arm does not move.
        written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        slices.store(0, Ordering::SeqCst);
        assert!(pump_frame(
            &conn,
            &test_service(&settings),
            T_DATA,
            0,
            1,
            vec![7u8; 5],
            &mut frag
        ));
        expect_one_credit(&written, &slices, 1, 5);
    }

    #[test]
    fn the_synthesized_head_is_sized_for_its_bytes() {
        for end_stream in [true, false] {
            let head = synth_head(b"GET", b"/path", b"host: x\r\n", end_stream);
            assert_eq!(head.capacity(), head.len(), "one allocation, no growth");
            assert!(head.starts_with(b"GET /path HTTP/2\r\nhost: x\r\n"));
            assert_eq!(
                head.ends_with(b"Transfer-Encoding: chunked\r\n\r\n"),
                !end_stream,
                "only a stream still open is declared chunked"
            );
        }
    }

    #[test]
    fn a_bounded_demux_turn_stops_at_one_read() {
        struct Trickle(Arc<AtomicUsize>);
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::SeqCst);
                if buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = 0;
                Ok(1)
            }
        }
        let reads = Arc::new(AtomicUsize::new(0));
        let settings = XhttpSettings::stream_one();
        let mut frames = Frames::new(Trickle(Arc::clone(&reads)), NullWrite, None, None, true);
        assert!(matches!(
            frames.step(&test_service(&settings), false),
            Stepped::More
        ));
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "a lane turn must return after one read"
        );
    }
}
