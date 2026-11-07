use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use super::config::Config;
use super::roundtrip::RoundTripInfo;
#[cfg(test)]
use super::segment::DataSegment;
use super::segment::{AckSegment, CmdOnlySegment, Command, Segment, SegmentOption};
use super::worker::{ReceivingWorker, SendingWorker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Active,
    ReadyToClose,
    PeerClosed,
    Terminating,
    PeerTerminating,
    Terminated,
}

impl State {
    fn from_int(v: i32) -> Self {
        match v {
            0 => Self::Active,
            1 => Self::ReadyToClose,
            2 => Self::PeerClosed,
            3 => Self::Terminating,
            4 => Self::PeerTerminating,
            _ => Self::Terminated,
        }
    }
}

type Writer = Box<dyn FnMut(&[u8]) -> io::Result<()> + Send>;

#[cfg(test)]
type LockGate = dyn Fn(&'static str) + Send + Sync;

struct OutputSink {
    buf: Vec<u8>,
    write: Writer,
}

type Closer = dyn FnOnce() + Send;

#[derive(Debug, Clone, Copy)]
pub struct ConnMetadata {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub conversation: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    IoTimeout,
    Closed,
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoTimeout => write!(f, "read/write timeout"),
            Self::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for ConnError {}

#[derive(Default)]
struct Notifier {
    generation: Mutex<u64>,
    condvar: Condvar,
}

impl Notifier {
    fn new() -> Self {
        Self::default()
    }

    fn gen(&self) -> u64 {
        *self.generation.lock().unwrap()
    }

    fn signal(&self) {
        *self.generation.lock().unwrap() += 1;
        self.condvar.notify_all();
    }

    fn wait_since(&self, snapshot: u64, timeout: Duration) -> bool {
        let mut g = self.generation.lock().unwrap();
        loop {
            if *g != snapshot {
                return true;
            }
            let (guard, r) = self.condvar.wait_timeout(g, timeout).unwrap();
            g = guard;
            if r.timed_out() && *g == snapshot {
                return false;
            }
        }
    }
}

/// One thread drives every live KCP connection's flush clock: a write wakes it at once, a
/// quiet connection waits its tick, and a connection that drops is pruned on the next pass.
struct Scheduler {
    conns: Mutex<Vec<Weak<Connection>>>,
    wake: Notifier,
}

static SCHEDULER: OnceLock<Arc<Scheduler>> = OnceLock::new();

fn scheduler() -> &'static Arc<Scheduler> {
    SCHEDULER.get_or_init(|| {
        let scheduler = Arc::new(Scheduler {
            conns: Mutex::new(Vec::new()),
            wake: Notifier::new(),
        });
        #[cfg(not(miri))]
        {
            let weak = Arc::downgrade(&scheduler);
            std::thread::Builder::new()
                .name("kcp-flush".to_owned())
                .spawn(move || scheduler_loop(&weak))
                .expect("spawns the flush thread");
        }
        scheduler
    })
}

#[cfg(not(miri))]
fn scheduler_loop(weak: &Weak<Scheduler>) {
    let mut seen = 0;
    loop {
        let Some(scheduler) = weak.upgrade() else {
            break;
        };
        let now = Instant::now();
        let conns: Vec<Arc<Connection>> = {
            let mut conns = scheduler.conns.lock().unwrap();
            conns.retain(|conn| conn.strong_count() > 0);
            conns.iter().filter_map(Weak::upgrade).collect()
        };
        let mut wait = Duration::from_secs(1);
        for conn in conns {
            let next = conn.poll(now);
            wait = wait.min(
                next.saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1)),
            );
        }
        let generation = scheduler.wake.gen();
        if generation != seen {
            seen = generation;
            continue;
        }
        scheduler.wake.wait_since(generation, wait);
        seen = scheduler.wake.gen();
    }
}

impl Scheduler {
    fn register(&self, conn: Weak<Connection>) {
        if let Ok(mut conns) = self.conns.lock() {
            conns.push(conn);
        }
        self.wake.signal();
    }
}

pub(crate) struct Ctx {
    pub meta: ConnMetadata,
    pub config: Config,
    pub state: AtomicI32,
    pub round_trip: Mutex<RoundTripInfo>,
    output: Mutex<OutputSink>,
}

const WRITE_ATTEMPTS: u32 = 5;

/// A send that failed because the socket was momentarily unavailable is worth another write; a
/// refused or unreachable one is the peer's answer, and retrying it only holds the flush.
fn transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
    )
}

impl Ctx {
    fn emit(&self, mut enc: impl FnMut(&mut Vec<u8>)) -> io::Result<()> {
        let mut last = None;
        for _ in 0..WRITE_ATTEMPTS {
            let outcome = {
                let mut sink = self.output.lock().unwrap();
                let OutputSink { buf, write } = &mut *sink;
                buf.clear();
                enc(buf);
                write(buf)
            };
            match outcome {
                Ok(()) => return Ok(()),
                Err(e) if transient(&e) => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("segment write")))
    }

    /// Sender path: the segment is already contiguous in the sending window's arena (an 18-byte header gap and the payload), so the writer gets those bytes directly and the payload never enters a staging buffer.
    pub(crate) fn emit_slice(&self, data: &[u8]) -> io::Result<()> {
        let mut last = None;
        for _ in 0..WRITE_ATTEMPTS {
            let outcome = {
                let mut sink = self.output.lock().unwrap();
                (sink.write)(data)
            };
            match outcome {
                Ok(()) => return Ok(()),
                Err(e) if transient(&e) => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("segment write")))
    }

    pub(crate) fn emit_ack(&self, a: &AckSegment) -> io::Result<()> {
        self.emit(|buf| a.serialize(buf))
    }

    pub(crate) fn emit_cmd(&self, c: &CmdOnlySegment) -> io::Result<()> {
        self.emit(|buf| c.serialize(buf))
    }
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx").finish_non_exhaustive()
    }
}

pub struct Connection {
    ctx: Arc<Ctx>,
    state_begin_time: AtomicU32,
    last_incoming_time: AtomicU32,
    last_ping_time: AtomicU32,
    since: Instant,
    data_input: Notifier,
    data_output: Notifier,
    rd: Mutex<Option<Instant>>,
    wd: Mutex<Option<Instant>>,
    mss: u32,
    receiving: Mutex<ReceivingWorker>,
    sending: Mutex<SendingWorker>,
    closer: Mutex<Option<Box<Closer>>>,
    terminated: AtomicBool,
    started: AtomicBool,
    write_pending: AtomicBool,
    #[cfg(any(test, not(miri)))]
    last_flush: Mutex<Instant>,
    #[cfg(any(test, not(miri)))]
    last_uncond: Mutex<Instant>,
    #[cfg(test)]
    flush_calls: AtomicU32,
    #[cfg(test)]
    lock_gate: Mutex<Option<Arc<LockGate>>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(closer) = self.closer.lock().unwrap().take() {
            closer();
        }
    }
}

impl Connection {
    #[must_use]
    pub fn new(
        meta: ConnMetadata,
        writer: Writer,
        closer: Box<dyn FnOnce() + Send>,
        config: Config,
    ) -> Arc<Self> {
        let conn = Self::build(meta, writer, closer, config);
        conn.start();
        conn
    }

    /// A connection whose scheduler registration is deferred until its session is in the
    /// socket's table, so a datagram cannot arrive before there is a session to feed.
    pub(crate) fn new_unstarted(
        meta: ConnMetadata,
        writer: Writer,
        closer: Box<dyn FnOnce() + Send>,
        config: Config,
    ) -> Arc<Self> {
        Self::build(meta, writer, closer, config)
    }

    fn build(
        meta: ConnMetadata,
        writer: Writer,
        closer: Box<dyn FnOnce() + Send>,
        config: Config,
    ) -> Arc<Self> {
        let mss = config.payload_size();
        let tti = config.tti;
        let ctx = Arc::new(Ctx {
            meta,
            config,
            state: AtomicI32::new(0),
            round_trip: Mutex::new(RoundTripInfo::new(tti)),
            output: Mutex::new(OutputSink {
                buf: Vec::new(),
                write: writer,
            }),
        });
        let now = Instant::now();
        #[cfg(any(test, not(miri)))]
        let tick = Duration::from_millis(u64::from(tti));
        Arc::new(Self {
            ctx: Arc::clone(&ctx),
            state_begin_time: AtomicU32::new(0),
            last_incoming_time: AtomicU32::new(0),
            last_ping_time: AtomicU32::new(0),
            since: now,
            data_input: Notifier::new(),
            data_output: Notifier::new(),
            rd: Mutex::new(None),
            wd: Mutex::new(None),
            mss,
            receiving: Mutex::new(ReceivingWorker::new(&ctx.config, Arc::clone(&ctx))),
            sending: Mutex::new(SendingWorker::new(&ctx.config, Arc::clone(&ctx))),
            closer: Mutex::new(Some(closer)),
            terminated: AtomicBool::new(false),
            started: AtomicBool::new(false),
            write_pending: AtomicBool::new(false),
            #[cfg(any(test, not(miri)))]
            last_flush: Mutex::new(now.checked_sub(tick).unwrap_or(now)),
            #[cfg(any(test, not(miri)))]
            last_uncond: Mutex::new(now),
            #[cfg(test)]
            flush_calls: AtomicU32::new(0),
            #[cfg(test)]
            lock_gate: Mutex::new(None),
        })
    }

    pub(crate) fn start(self: &Arc<Self>) {
        if !self.started.swap(true, Ordering::SeqCst) {
            scheduler().register(Arc::downgrade(self));
        }
    }

    #[cfg(any(test, not(miri)))]
    fn poll(&self, now: Instant) -> Instant {
        let tick = Duration::from_millis(u64::from(self.ctx.config.tti));
        if self.terminated.load(Ordering::SeqCst) {
            return now + Duration::from_secs(1);
        }
        let state = self.state();
        let draining = state == State::Terminating || state == State::PeerTerminating;
        let necessary = self.sending.lock().unwrap().update_necessary();
        #[cfg(test)]
        self.pass_lock_gate("poll");
        let necessary = necessary || self.receiving.lock().unwrap().update_necessary();
        let last_flush = *self.last_flush.lock().unwrap();
        let last_uncond = *self.last_uncond.lock().unwrap();
        let due = draining
            || self.write_pending.swap(false, Ordering::SeqCst)
            || now.saturating_duration_since(last_flush) >= tick;
        if due
            && (draining
                || necessary
                || now.saturating_duration_since(last_uncond) >= Duration::from_secs(5))
        {
            self.flush();
            *self.last_flush.lock().unwrap() = now;
            *self.last_uncond.lock().unwrap() = now;
            return now + tick;
        }
        if draining {
            now + Duration::from_secs(1)
        } else {
            // A pass that flushed nothing must still park for a tick: adding the tick to a stale `last_flush` returns an instant already past and spins the one scheduler thread every millisecond.
            let next = last_flush + tick;
            if next > now {
                next
            } else {
                now + tick
            }
        }
    }

    #[must_use]
    pub fn state(&self) -> State {
        State::from_int(self.ctx.state.load(Ordering::SeqCst))
    }

    fn set_state(&self, state: State) {
        let current = self.elapsed();
        self.ctx.state.store(state as i32, Ordering::SeqCst);
        self.state_begin_time.store(current, Ordering::SeqCst);
        match state {
            State::ReadyToClose => {
                self.receiving.lock().unwrap().close_read();
            }
            State::PeerClosed | State::PeerTerminating => {
                self.sending.lock().unwrap().close_write();
            }
            State::Terminating => {
                self.receiving.lock().unwrap().close_read();
                self.sending.lock().unwrap().close_write();
            }
            State::Terminated => {
                self.receiving.lock().unwrap().close_read();
                self.sending.lock().unwrap().close_write();
                self.data_input.signal();
                self.data_output.signal();
                Self::wake_update();
                self.terminated.store(true, Ordering::SeqCst);
                self.terminate();
            }
            State::Active => {}
        }
    }

    fn elapsed(&self) -> u32 {
        self.since.elapsed().as_millis() as u32
    }

    #[must_use]
    pub fn round_trip_timeout(&self) -> u32 {
        self.ctx.round_trip.lock().unwrap().timeout()
    }

    /// Hands the socket thread one payload buffer to fill for the next inbound data segment; spent buffers return through `ReceivingWorker::read`, so a connection busy once allocates no more per segment.
    pub fn take_payload(&self) -> Vec<u8> {
        self.receiving.lock().unwrap().take_payload()
    }

    /// Takes the caller's datagram buffer by `drain`, so the socket thread parses into one vector and hands it over with its capacity intact: a datagram allocates nothing for its segment list.
    pub fn input(&self, segments: &mut Vec<Segment>) {
        let current = self.elapsed();
        self.last_incoming_time.store(current, Ordering::SeqCst);
        let mut woke = false;
        for seg in segments.drain(..) {
            if seg.conversation() != self.ctx.meta.conversation {
                break;
            }
            if seg.option().is_close() {
                self.on_peer_closed();
            }
            match seg {
                Segment::Data(d) => {
                    let mut receiving = self.receiving.lock().unwrap();
                    receiving.process_segment(d);
                    woke |= receiving.is_data_available();
                }
                Segment::Ack(a) => {
                    let rto = self.ctx.round_trip.lock().unwrap().timeout();
                    self.sending
                        .lock()
                        .unwrap()
                        .process_segment(current, &a, rto);
                    self.data_output.signal();
                    // The socket thread that parsed this ack is the thread that reaches here, so its number list returns to that thread's pool.
                    super::segment::reclaim_ack_numbers(a.numbers);
                }
                Segment::CmdOnly(c) => {
                    if c.kind() == Some(Command::Terminate) {
                        match self.state() {
                            State::Active | State::PeerClosed => {
                                self.set_state(State::PeerTerminating);
                            }
                            State::ReadyToClose => self.set_state(State::Terminating),
                            State::Terminating => self.set_state(State::Terminated),
                            _ => {}
                        }
                    }
                    if c.option.is_close() || c.kind() == Some(Command::Terminate) {
                        self.data_input.signal();
                        self.data_output.signal();
                    }
                    let mut receiving = self.receiving.lock().unwrap();
                    #[cfg(test)]
                    self.pass_lock_gate("receiving");
                    receiving.process_sending_next(c.sending_next);
                    drop(receiving);
                    let mut sending = self.sending.lock().unwrap();
                    #[cfg(test)]
                    self.pass_lock_gate("sending");
                    sending.process_receiving_next(c.receiving_next);
                    drop(sending);
                    self.ctx
                        .round_trip
                        .lock()
                        .unwrap()
                        .update_peer_rto(c.peer_rto, current);
                }
            }
        }
        // One wake for the datagram: a reader parked on the generation counter needs it to change once, not once per segment.
        if woke {
            self.data_input.signal();
        }
    }
}

const PING_INTERVAL_MS: u32 = 3000;

// A ping resets `last_ping_time`, so a worker ping already satisfies the interval.
fn ping_due(current: u32, last_ping: u32, worker_pinged: bool) -> bool {
    worker_pinged || current.wrapping_sub(last_ping) >= PING_INTERVAL_MS
}

impl Connection {
    pub fn flush(&self) {
        #[cfg(test)]
        self.flush_calls.fetch_add(1, Ordering::SeqCst);
        let current = self.elapsed();
        if self.state() == State::Terminated {
            return;
        }
        if self.state() == State::Active
            && current.wrapping_sub(self.last_incoming_time.load(Ordering::SeqCst)) >= 30000
        {
            self.close();
        }
        if self.state() == State::ReadyToClose && self.sending.lock().unwrap().is_empty() {
            self.set_state(State::Terminating);
        }
        if self.state() == State::Terminating {
            self.ping(current, Command::Terminate);
            if current.wrapping_sub(self.state_begin_time.load(Ordering::SeqCst)) > 8000 {
                self.set_state(State::Terminated);
            }
            return;
        }
        if self.state() == State::PeerTerminating
            && current.wrapping_sub(self.state_begin_time.load(Ordering::SeqCst)) > 4000
        {
            self.set_state(State::Terminating);
        }
        if self.state() == State::ReadyToClose
            && current.wrapping_sub(self.state_begin_time.load(Ordering::SeqCst)) > 15000
        {
            self.set_state(State::Terminating);
        }
        self.receiving.lock().unwrap().flush(current);
        let worker_pinged = self.sending.lock().unwrap().flush(current);
        if ping_due(
            current,
            self.last_ping_time.load(Ordering::SeqCst),
            worker_pinged,
        ) {
            self.ping(current, Command::Ping);
        }
    }

    pub fn ping(&self, current: u32, cmd: Command) {
        let receiving_next = self.receiving.lock().unwrap().next_number();
        #[cfg(test)]
        self.pass_lock_gate("ping");
        let sending_next = self.sending.lock().unwrap().first_unacknowledged();
        let seg = CmdOnlySegment {
            conv: self.ctx.meta.conversation,
            cmd: cmd.to_byte(),
            option: if self.state() == State::ReadyToClose {
                SegmentOption::CLOSE
            } else {
                SegmentOption::NONE
            },
            receiving_next,
            sending_next,
            peer_rto: self.ctx.round_trip.lock().unwrap().timeout(),
        };
        let _ = self.ctx.emit_cmd(&seg);
        self.last_ping_time.store(current, Ordering::SeqCst);
    }

    pub fn on_peer_closed(&self) {
        match self.state() {
            State::ReadyToClose => self.set_state(State::Terminating),
            State::Active => self.set_state(State::PeerClosed),
            _ => {}
        }
    }

    pub fn close(&self) {
        self.data_input.signal();
        self.data_output.signal();
        match self.state() {
            State::ReadyToClose | State::Terminating | State::Terminated => {}
            State::Active => self.set_state(State::ReadyToClose),
            State::PeerClosed => self.set_state(State::Terminating),
            State::PeerTerminating => self.set_state(State::Terminated),
        }
        if matches!(self.state(), State::ReadyToClose | State::Terminating) {
            self.flush();
        }
    }

    pub fn terminate(&self) {
        self.data_input.signal();
        self.data_output.signal();
        if let Some(closer) = self.closer.lock().unwrap().take() {
            closer();
        }
        self.sending.lock().unwrap().release();
        self.receiving.lock().unwrap().release();
    }

    pub fn read(&self, b: &mut [u8]) -> Result<usize, ConnError> {
        loop {
            if self.state() == State::ReadyToClose
                || self.state() == State::Terminating
                || self.state() == State::Terminated
            {
                return Err(ConnError::Closed);
            }
            let snap = self.data_input.gen();
            let n = self.receiving.lock().unwrap().read(b);
            if n > 0 {
                return Ok(n);
            }
            if self.state() == State::PeerTerminating {
                return Err(ConnError::Closed);
            }
            self.wait_for_data_input(snap)?;
        }
    }

    fn wait_for_data_input(&self, snap: u64) -> Result<(), ConnError> {
        // One acquisition: the deadline is Copy, and taking it twice let a concurrent set_rd_deadline land between the two reads.
        let deadline = *self.rd.lock().unwrap();
        if deadline.is_some_and(|t| t <= Instant::now()) {
            return Err(ConnError::IoTimeout);
        }
        let duration = deadline.map_or(Duration::from_secs(16), |t| {
            t.saturating_duration_since(Instant::now())
        });
        if !self.data_input.wait_since(snap, duration)
            && deadline.is_some_and(|t| t <= Instant::now())
        {
            return Err(ConnError::IoTimeout);
        }
        Ok(())
    }

    fn wait_for_data_output(&self, snap: u64) -> Result<(), ConnError> {
        // One acquisition: the deadline is Copy, and taking it twice let a concurrent set_wd_deadline land between the two reads.
        let deadline = *self.wd.lock().unwrap();
        if deadline.is_some_and(|t| t <= Instant::now()) {
            return Err(ConnError::IoTimeout);
        }
        let duration = deadline.map_or(Duration::from_secs(16), |t| {
            t.saturating_duration_since(Instant::now())
        });
        if !self.data_output.wait_since(snap, duration)
            && deadline.is_some_and(|t| t <= Instant::now())
        {
            return Err(ConnError::IoTimeout);
        }
        Ok(())
    }

    pub fn write(&self, b: &[u8]) -> Result<usize, ConnError> {
        let mut offset = 0;
        let mut pushed = false;
        while offset < b.len() {
            if self.state() != State::Active {
                return Err(ConnError::Closed);
            }
            let snap = self.data_output.gen();
            let n = (b.len() - offset).min(self.mss as usize);
            if !self.sending.lock().unwrap().push(&b[offset..offset + n]) {
                if pushed {
                    Self::wake_update();
                    pushed = false;
                }
                self.wait_for_data_output(snap)?;
                continue;
            }
            pushed = true;
            offset += n;
        }
        if pushed {
            self.write_pending.store(true, Ordering::SeqCst);
            Self::wake_update();
        }
        Ok(b.len())
    }

    pub fn set_read_deadline(&self, t: Instant) {
        *self.rd.lock().unwrap() = Some(t);
    }

    pub fn set_write_deadline(&self, t: Instant) {
        *self.wd.lock().unwrap() = Some(t);
    }

    #[cfg(test)]
    pub(crate) fn flush_calls(&self) -> u32 {
        self.flush_calls.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn set_lock_gate(&self, gate: Option<Arc<LockGate>>) {
        *self.lock_gate.lock().unwrap() = gate;
    }

    #[cfg(test)]
    fn pass_lock_gate(&self, site: &'static str) {
        let gate = self.lock_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate(site);
        }
    }

    #[must_use]
    pub fn conversation(&self) -> u16 {
        self.ctx.meta.conversation
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.ctx.meta.local
    }

    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.ctx.meta.remote
    }

    fn wake_update() {
        scheduler().wake.signal();
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use std::time::{Duration, Instant};

    use super::{
        ping_due, CmdOnlySegment, Command, Config, ConnMetadata, Connection, Segment,
        PING_INTERVAL_MS, WRITE_ATTEMPTS,
    };

    struct Recorder {
        attempts: AtomicU32,
        seen: Mutex<Vec<Vec<u8>>>,
        fail_times: u32,
    }

    impl Recorder {
        fn new(fail_times: u32) -> Arc<Self> {
            Arc::new(Self {
                attempts: AtomicU32::new(0),
                seen: Mutex::new(Vec::new()),
                fail_times,
            })
        }

        fn write(&self, data: &[u8]) -> io::Result<()> {
            let n = self.attempts.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(data.to_vec());
            if n < self.fail_times {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok(())
            }
        }
    }

    fn recording_connection(fail_times: u32) -> (Arc<Recorder>, Arc<Connection>) {
        let recorder = Recorder::new(fail_times);
        let sink = Arc::clone(&recorder);
        let local = ([127, 0, 0, 1], 1).into();
        let conn = Connection::new(
            ConnMetadata {
                local,
                remote: local,
                conversation: 4,
            },
            Box::new(move |data: &[u8]| sink.write(data)),
            Box::new(|| {}),
            Config::default(),
        );
        (recorder, conn)
    }

    #[test]
    fn a_failed_write_is_retried_with_the_same_bytes() {
        let (recorder, conn) = recording_connection(2);
        conn.ping(1, Command::Terminate);
        let seen = recorder.seen.lock().unwrap();
        assert_eq!(recorder.attempts.load(Ordering::SeqCst), 3);
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], seen[1]);
        assert_eq!(seen[1], seen[2]);
        assert_eq!(seen[0].len(), CmdOnlySegment::byte_size());
    }

    #[test]
    fn a_write_that_never_succeeds_stops_at_the_attempt_limit() {
        let (recorder, conn) = recording_connection(u32::MAX);
        #[cfg(not(miri))]
        let started = Instant::now();
        conn.ping(1, Command::Ping);
        assert_eq!(recorder.attempts.load(Ordering::SeqCst), WRITE_ATTEMPTS);
        #[cfg(not(miri))]
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a dead sink held the flush for {:?}; the scheduler drives every connection",
            started.elapsed()
        );
    }

    /// An idle connection must park the scheduler for a tick rather than return an instant that already passed.
    #[test]
    fn an_idle_connection_parks_for_a_tick() {
        let (_, conn) = recording_connection(0);
        let now = Instant::now();
        let tick = Duration::from_millis(u64::from(Config::default().tti));
        let next = conn.poll(now);
        assert!(
            next.saturating_duration_since(now) >= tick,
            "idle poll returned {:?}, not a tick",
            next.saturating_duration_since(now)
        );
    }

    #[test]
    fn a_command_takes_the_receiving_lock_before_the_sending_lock() {
        let local = ([127, 0, 0, 1], 1).into();
        let conn = Connection::new_unstarted(
            ConnMetadata {
                local,
                remote: local,
                conversation: 4,
            },
            Box::new(|_| Ok(())),
            Box::new(|| {}),
            Config::default(),
        );
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&events);
        let weak = Arc::downgrade(&conn);
        conn.set_lock_gate(Some(Arc::new(move |site: &'static str| {
            let conn = weak.upgrade().expect("the connection is alive");
            match site {
                "receiving" => {
                    assert!(
                        conn.sending.try_lock().is_ok(),
                        "input held the sending lock while taking the receiving lock"
                    );
                }
                "sending" => {
                    assert!(
                        conn.receiving.try_lock().is_ok(),
                        "input held the receiving lock while taking the sending lock"
                    );
                }
                _ => unreachable!("unknown lock site"),
            }
            recorded.lock().unwrap().push(site);
        })));
        let mut command = CmdOnlySegment::new();
        command.conv = 4;
        conn.input(&mut vec![Segment::CmdOnly(command)]);
        assert_eq!(*events.lock().unwrap(), ["receiving", "sending"]);
    }

    #[test]
    fn poll_and_ping_do_not_hold_worker_locks_across_each_other() {
        let local = ([127, 0, 0, 1], 1).into();
        let conn = Connection::new_unstarted(
            ConnMetadata {
                local,
                remote: local,
                conversation: 4,
            },
            Box::new(|_| Ok(())),
            Box::new(|| {}),
            Config::default(),
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let weak = Arc::downgrade(&conn);
        let gate_barrier = Arc::clone(&barrier);
        conn.set_lock_gate(Some(Arc::new(move |site: &'static str| {
            gate_barrier.wait();
            let conn = weak.upgrade().expect("the connection is alive");
            match site {
                "poll" => assert!(
                    conn.receiving.try_lock().is_ok(),
                    "poll held the receiving lock while ping held it"
                ),
                "ping" => assert!(
                    conn.sending.try_lock().is_ok(),
                    "ping held the sending lock while poll held it"
                ),
                _ => unreachable!("unknown lock site"),
            }
        })));
        let poller = {
            let conn = Arc::clone(&conn);
            std::thread::spawn(move || conn.poll(conn.since))
        };
        let pinger = {
            let conn = Arc::clone(&conn);
            std::thread::spawn(move || conn.ping(1, Command::Ping))
        };
        poller
            .join()
            .expect("poll must not wait on a lock ping holds");
        pinger
            .join()
            .expect("ping must not wait on a lock poll holds");
    }

    fn data(number: u32, sending_next: u32, payload: &[u8]) -> Segment {
        Segment::Data(super::DataSegment {
            conv: 4,
            option: super::SegmentOption::NONE,
            timestamp: 0,
            number,
            sending_next,
            payload: payload.to_vec(),
            timeout: 0,
            transmit: 0,
        })
    }

    fn echoing_connection() -> Arc<Connection> {
        let local = ([127, 0, 0, 1], 1).into();
        Connection::new(
            ConnMetadata {
                local,
                remote: local,
                conversation: 4,
            },
            Box::new(|_| Ok(())),
            Box::new(|| {}),
            Config::default(),
        )
    }

    fn read_once(conn: &Connection, b: &mut [u8]) -> Result<usize, super::ConnError> {
        conn.set_read_deadline(std::time::Instant::now() + Duration::from_millis(200));
        conn.read(b)
    }

    #[test]
    fn an_in_order_segment_is_delivered_once() {
        let conn = echoing_connection();
        conn.input(&mut vec![data(0, 0, b"first"), data(1, 0, b"second")]);
        let mut buf = [0u8; 32];
        assert_eq!(read_once(&conn, &mut buf), Ok(11));
        assert_eq!(&buf[..11], b"firstsecond");
        assert_eq!(read_once(&conn, &mut buf), Err(super::ConnError::IoTimeout));
    }

    #[test]
    fn a_peer_close_waits_for_the_data_it_still_owes() {
        let conn = echoing_connection();
        let mut last = data(0, 0, b"last");
        if let Segment::Data(segment) = &mut last {
            segment.option = super::SegmentOption::CLOSE;
        }
        conn.input(&mut vec![last]);
        let mut buf = [0u8; 8];
        assert_eq!(read_once(&conn, &mut buf), Ok(4));
        assert_eq!(
            &buf[..4],
            b"last",
            "the close did not drop the data before it"
        );
        assert_eq!(
            read_once(&conn, &mut buf),
            Err(super::ConnError::IoTimeout),
            "the peer's close ended the read before the rest of its data arrived"
        );
        conn.input(&mut vec![data(1, 0, b"tail")]);
        assert_eq!(read_once(&conn, &mut buf), Ok(4));
        assert_eq!(&buf[..4], b"tail");
        let mut terminate = CmdOnlySegment::new();
        terminate.conv = 4;
        terminate.cmd = Command::Terminate.to_byte();
        conn.input(&mut vec![Segment::CmdOnly(terminate)]);
        assert_eq!(read_once(&conn, &mut buf), Err(super::ConnError::Closed));
    }

    #[test]
    fn a_segment_beyond_the_receiving_window_is_dropped() {
        let conn = echoing_connection();
        let beyond = Config::default().receiving_in_flight_size();
        conn.input(&mut vec![data(beyond, 0, b"too far")]);
        let mut buf = [0u8; 32];
        assert_eq!(read_once(&conn, &mut buf), Err(super::ConnError::IoTimeout));
    }

    #[test]
    fn a_retransmitted_segment_is_delivered_once() {
        let conn = echoing_connection();
        conn.input(&mut vec![data(0, 0, b"payload"), data(0, 0, b"payload")]);
        let mut buf = [0u8; 32];
        assert_eq!(read_once(&conn, &mut buf), Ok(7));
        assert_eq!(read_once(&conn, &mut buf), Err(super::ConnError::IoTimeout));
    }

    #[test]
    fn a_segment_arriving_out_of_order_waits_for_its_turn() {
        let conn = echoing_connection();
        conn.input(&mut vec![data(1, 0, b"second"), data(0, 0, b"first")]);
        let mut buf = [0u8; 32];
        assert_eq!(read_once(&conn, &mut buf), Ok(11));
        assert_eq!(&buf[..11], b"firstsecond");
    }

    /// Spent payload buffers go back to `spare` for the socket thread to fill, so after the window has been full once no received segment allocates; held capacity is the witness, since a fill that allocated or a drain that stopped returning buffers could not hold it steady.
    #[cfg_attr(
        miri,
        ignore = "the worker closes a link silent for 30 s of wall clock"
    )]
    #[test]
    fn the_receive_pool_serves_every_segment_without_growing() {
        let conn = echoing_connection();
        let mut out = vec![0u8; 8 * 1332];
        let mut settled = 0usize;
        for round in 0..64u32 {
            let base = round * 8;
            let mut segs = Vec::new();
            for n in base..base + 8 {
                let mut payload = conn.take_payload();
                payload.extend_from_slice(&[n as u8; 1332]);
                segs.push(Segment::Data(super::DataSegment {
                    conv: 4,
                    option: super::SegmentOption::NONE,
                    timestamp: 0,
                    number: n,
                    sending_next: base + 8,
                    payload,
                    timeout: 0,
                    transmit: 0,
                }));
            }
            conn.input(&mut segs);
            assert_eq!(read_once(&conn, &mut out), Ok(8 * 1332), "round {round}");
            for (i, n) in (base..base + 8).enumerate() {
                let body = &out[i * 1332..(i + 1) * 1332];
                assert!(
                    body.iter().all(|&b| b == n as u8),
                    "round {round}: segment {n} came back as another's bytes"
                );
            }
            let receiving = conn.receiving.lock().unwrap();
            if round == 2 {
                settled = receiving.spare_capacity();
            } else if round > 2 {
                assert_eq!(
                    receiving.spare_capacity(),
                    settled,
                    "round {round}: the pool grew, so a segment allocated"
                );
            }
        }
        assert!(
            settled >= 8 * 1332,
            "the pool must hold the window's worth: {settled}"
        );
        assert_eq!(
            conn.receiving.lock().unwrap().spare_buffers(),
            8,
            "every drained buffer comes back"
        );
    }

    /// The segment list is the socket thread's and `input` drains rather than takes, so one capacity serves every datagram; a second allocation would mean the buffer was dropped instead of borrowed.
    #[test]
    fn a_datagram_leaves_the_callers_segment_buffer_ready_for_the_next() {
        let conn = echoing_connection();
        let mut segs: Vec<Segment> = Vec::new();
        let mut room = 0usize;
        for round in 0..8 {
            segs.extend([data(0, 0, b"a"), data(1, 0, b"bb"), data(2, 0, b"ccc")]);
            conn.input(&mut segs);
            assert!(
                segs.is_empty(),
                "round {round}: input must drain the buffer"
            );
            if round == 0 {
                room = segs.capacity();
                assert!(room >= 3, "a three-segment datagram has to fit: {room}");
            }
            assert_eq!(
                segs.capacity(),
                room,
                "round {round}: the capacity {room} was dropped, so a datagram reallocates"
            );
        }
    }

    /// `Notifier::gen` is the counter `read` snapshots and `wait_since` compares, so its delta is the number of wakeups: this is the gate for one wakeup per datagram rather than a reading of it.
    #[test]
    fn a_datagram_wakes_the_reader_once_however_many_segments_it_carries() {
        for width in [1usize, 2, 3, 8] {
            let conn = echoing_connection();
            let mut segs: Vec<Segment> = Vec::new();
            for number in 0..width {
                segs.push(data(number as u32, 0, b"payload"));
            }
            let before = conn.data_input.gen();
            conn.input(&mut segs);
            assert_eq!(
                conn.data_input.gen() - before,
                1,
                "width {width}: a {width}-segment datagram woke the reader more than once"
            );
        }
        let conn = echoing_connection();
        let before = conn.data_input.gen();
        conn.input(&mut vec![data(9, 0, b"far away")]);
        assert_eq!(
            conn.data_input.gen(),
            before,
            "a segment outside the receiving window is not a wakeup"
        );
    }

    /// A burst of inbound segments is one flush per tick, not one per segment: the worker's clock is the `tti`, and an ack that is already pending when a tick opens joins that tick's flush.
    #[cfg_attr(miri, ignore = "waits on the worker's wall-clock tick")]
    #[test]
    fn a_burst_of_inbound_segments_does_not_flush_once_per_segment() {
        let local = ([127, 0, 0, 1], 1).into();
        let config = Config {
            tti: 5000,
            ..Config::default()
        };
        let conn = Connection::new(
            ConnMetadata {
                local,
                remote: local,
                conversation: 4,
            },
            Box::new(|_| Ok(())),
            Box::new(|| {}),
            config,
        );
        for number in 0..40 {
            conn.input(&mut vec![data(number, 0, b"payload")]);
            std::thread::sleep(Duration::from_millis(10));
        }
        let flushes = conn.flush_calls();
        assert!(
            flushes <= 2,
            "40 segments over 400 ms flushed {flushes} times; a five-second tick allows one"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "drains on 20ms wall-clock deadlines behind a worker thread"
    )]
    #[test]
    fn every_read_size_delivers_the_same_stream() {
        let stream: Vec<u8> = (0..776).map(|i| (i as u8).wrapping_mul(29)).collect();
        let segments: Vec<Vec<u8>> = (0..8)
            .map(|k| stream[k * 97..(k + 1) * 97].to_vec())
            .collect();
        let mut want = Vec::new();
        for window in [1usize, 2, 3, 7, 31, 64, 96, 97, 128, 389, 776, 1024, 4096] {
            let conn = echoing_connection();
            let mut segs: Vec<Segment> = Vec::new();
            let mut number = 0u32;
            for chunk in &segments {
                let mut at = 0;
                while at < chunk.len() {
                    let take = window.min(chunk.len() - at);
                    segs.push(data(number, 0, &chunk[at..at + take]));
                    number += 1;
                    at += take;
                }
            }
            conn.input(&mut segs);
            let mut got = Vec::new();
            let mut buf = vec![0u8; window];
            loop {
                conn.set_read_deadline(std::time::Instant::now() + Duration::from_millis(20));
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            if want.is_empty() {
                want = got.clone();
            }
            assert_eq!(got, want, "window {window}");
            assert_eq!(got.len(), stream.len(), "window {window}");
        }
        assert_eq!(
            want, stream,
            "the reassembled stream is the one that went in"
        );
    }

    #[test]
    fn one_tick_pings_at_most_once() {
        for last in [0, 1, 500, 12_500] {
            for gap in [0, 1, 42, PING_INTERVAL_MS - 1, PING_INTERVAL_MS, 90_000] {
                assert!(ping_due(last + gap, last, true));
                assert_eq!(ping_due(last + gap, last, false), gap >= PING_INTERVAL_MS);
            }
        }
    }

    #[test]
    fn the_interval_wraps_instead_of_underflowing() {
        let before = u32::MAX - (PING_INTERVAL_MS - 2);
        assert!(!ping_due(
            before.wrapping_add(PING_INTERVAL_MS - 1),
            before,
            false
        ));
        assert!(ping_due(
            before.wrapping_add(PING_INTERVAL_MS),
            before,
            false
        ));
    }
}
