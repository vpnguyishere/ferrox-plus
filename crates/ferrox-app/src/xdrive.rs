//! The xdrive carrier: one proxy stream carried by an object store both ends poll, so a lane survives addresses, restarts and rebindings by naming its segments in send order.

use crate::budgets::RELAY_POLL;
use crate::conn::Connection;
use crate::json::Json;
use ferrox_core::tls::{RealityClientConfig, RustlsProvider, TlsConfig, TlsProvider as _};
use sha2::Digest as _;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::io::{self, ErrorKind, Read, Write};
use std::net::ToSocketAddrs as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SESSIONS_DIR: &str = "sessions";
const STREAMS_DIR: &str = "streams";
const UPLINK_DIR: &str = "c2s";
const DOWNLINK_DIR: &str = "s2c";
const SEG_SUFFIX: &str = ".seg";
const END_SUFFIX: &str = ".end";
const ERR_SUFFIX: &str = ".err";
const TEMP_PREFIX: &str = ".xdrive-tmp-";

const DEFAULT_SEGMENT_BYTES: usize = 512 * 1024;
const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_FLUSH: Duration = Duration::from_millis(20);
const DEFAULT_MIN_POLL: Duration = Duration::from_millis(50);
const DEFAULT_MAX_POLL: Duration = Duration::from_millis(500);
const DEFAULT_EAGER: Duration = Duration::from_millis(2000);
const DEFAULT_HOLE: Duration = Duration::from_secs(30);
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CONCURRENCY: usize = 8;
const MAX_CONCURRENCY: usize = 256;
const MAX_COALESCED_TICKS: usize = 8;
const WORKER_STACK: usize = 256 * 1024;
const DRAIN_WAIT: Duration = Duration::from_millis(500);
const DRAIN_TRIES: u32 = 120;

/// One object a listing names, with the payload the listing carried alongside it where the service can hand both at once; an inline entry costs the reader no second request.
pub(crate) struct Entry {
    name: String,
    inline: Option<Vec<u8>>,
}

/// The object store a session runs over. `get` answers `NotFound` for an absent name, the one error a polling reader reads as "not yet" rather than as a lane failure.
pub(crate) trait Storage: Send + Sync {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()>;
    fn get(&self, name: &str) -> io::Result<Vec<u8>>;
    fn delete(&self, name: &str) -> io::Result<()>;
    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>>;

    /// Whether a batch of gets is worth a thread each: a store read from the local filesystem answers one in less time than a thread takes to start, so the pump reads it in order.
    fn threaded(&self) -> bool {
        true
    }
}

/// The tuned budgets of one carrier instance, with the reference's defaults and caps applied to whatever the config left out.
#[derive(Debug, Clone)]
pub(crate) struct Params {
    segment_bytes: usize,
    flush: Duration,
    min_poll: Duration,
    max_poll: Duration,
    eager: Duration,
    hole: Duration,
    ttl: Duration,
    concurrency: usize,
}

/// `xdriveSettings` as the reference spells its fields: where the objects live, which service holds them, and the budgets, with the `snake_case` fallback every resolver in this tree accepts.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub remote_folder: String,
    pub service: String,
    pub secrets: Vec<String>,
    pub template: Option<Json>,
    pub s3: Option<S3Settings>,
    pub params: Params,
    /// The transport's `security`, which the reference counts in the identity of a shared store.
    pub security: String,
    /// The transport's own TLS, applied to the lanes the store dials; `None` speaks the url's scheme with system roots.
    pub tls: Option<Arc<TlsConfig>>,
    /// The transport's REALITY identity, applied instead of TLS when `security` names it.
    pub reality: Option<Arc<RealityClientConfig>>,
    /// Whether the identity named its decoy; otherwise the lane's own host is the name.
    pub reality_named: bool,
}

/// The `s3` object: where the bucket is, which region signs it, and whether the bucket rides in the path or the host.
#[derive(Debug, Clone)]
pub(crate) struct S3Settings {
    endpoint: String,
    region: String,
    bucket: String,
    path_style: bool,
}

/// The two mutually exclusive `xmux` bounds; their ranges steer the pool once the HTTP/2 lanes land.
#[derive(Debug, Clone, Default)]
struct XmuxSettings {
    max_concurrency: u32,
    max_connections: u32,
}

impl XmuxSettings {
    /// The upper bound of an `Int32Range`: an integer or the `"1-4"` range string the reference also accepts.
    fn set(value: &Json) -> Option<u32> {
        let (left, right) = crate::xhttp::i32_range(value)?;
        u32::try_from(left.max(right).max(0)).ok()
    }
}

impl Settings {
    /// An empty folder or an unknown service is a refusal by the caller, not a silent default: a carrier pointed at nowhere must not start polling.
    pub(crate) fn from_json(stream: Option<&Json>) -> Option<Self> {
        let stream = stream?;
        let drive = stream.get("xdriveSettings")?;
        let text = |name: &str| {
            drive
                .get(name)
                .or_else(|| drive.get(&snake_case(name)))
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let number = |name: &str| {
            drive
                .get(name)
                .or_else(|| drive.get(&snake_case(name)))
                .and_then(Json::as_u32)
                .unwrap_or(0)
        };
        let remote_folder = text("remoteFolder");
        let service = match text("service").as_str() {
            "Google Drive" | "google-drive" => "google-drive".to_owned(),
            other => other.to_owned(),
        };
        if remote_folder.is_empty()
            || !matches!(
                service.as_str(),
                "local" | "template" | "google-drive" | "s3"
            )
        {
            return None;
        }
        let s3 = s3_of(drive);
        if service == "s3" && s3.is_none() {
            return None;
        }
        let xmux = xmux_of(drive)?;
        if xmux.max_connections > 0 && xmux.max_concurrency > 0 {
            return None;
        }
        let security = stream
            .get("security")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let (reality, reality_named) = transport_reality(stream);
        if security == "reality" && reality.is_none() {
            return None;
        }
        let secrets = drive
            .get("secrets")
            .and_then(Json::as_arr)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Json::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let params = Params {
            segment_bytes: bytes_of(
                number("segmentBytes"),
                DEFAULT_SEGMENT_BYTES,
                MAX_SEGMENT_BYTES,
            ),
            flush: millis(number("flushIntervalMs"), DEFAULT_FLUSH),
            min_poll: millis(number("pollIntervalMs"), DEFAULT_MIN_POLL),
            max_poll: millis(number("maxPollIntervalMs"), DEFAULT_MAX_POLL),
            eager: millis(number("eagerWindowMs"), DEFAULT_EAGER),
            hole: millis(number("holeTimeoutMs"), DEFAULT_HOLE),
            ttl: seconds(number("sessionTtlSeconds"), DEFAULT_TTL),
            concurrency: count(number("concurrency"), DEFAULT_CONCURRENCY, MAX_CONCURRENCY),
        }
        .clamped();
        Some(Self {
            params,
            template: template_of(drive),
            s3,
            remote_folder,
            service,
            secrets,
            tls: transport_tls(stream, &security),
            reality,
            reality_named,
            security,
        })
    }

    /// The store this config names: one per folder for the services that carry a lane pool and an id cache, a fresh one for a folder on disk.
    ///
    /// # Errors
    /// A folder that cannot be created, a template that does not describe four operations, or a Drive set without three secrets.
    pub(crate) fn store(&self, front: Option<(&str, u16)>) -> io::Result<Arc<dyn Storage>> {
        match self.service.as_str() {
            "local" => Ok(Arc::new(Local::new(&self.remote_folder)?)),
            "template" => {
                let cap = self
                    .template
                    .as_ref()
                    .and_then(|root| root.get("concurrency"))
                    .and_then(Json::as_u32)
                    .unwrap_or(0);
                shared(
                    self,
                    front,
                    count(cap, DEFAULT_INFLIGHT, MAX_INFLIGHT),
                    |settings, http| Ok(Arc::new(Template::build(settings, http)?)),
                )
            }
            "google-drive" => shared(self, front, DEFAULT_INFLIGHT, |settings, http| {
                Ok(Arc::new(Drive::build(settings, http)?))
            }),
            "s3" => shared(self, front, DEFAULT_INFLIGHT, |settings, http| {
                Ok(Arc::new(S3::build(settings, http)?))
            }),
            other => Err(carrier_error(format!(
                "the {other} service is not built here"
            ))),
        }
    }

    /// The store this config names, opened as a client: the session announcement first, then both logs on it.
    pub(crate) fn dial(&self, front: Option<(&str, u16)>) -> io::Result<Conn> {
        dial(self.store(front)?, &Arc::new(self.params.clone()))
    }

    /// The store this config names, watched as a listener: every accepted session goes to `accept` on a thread of its own.
    pub(crate) fn listen(
        &self,
        front: Option<(&str, u16)>,
        accept: Accept,
    ) -> io::Result<Arc<Server>> {
        Server::serve(self.store(front)?, Arc::new(self.params.clone()), accept)
    }

    /// The template as one text, which is what makes two configs the same store.
    fn template_text(&self) -> String {
        let mut text = String::new();
        if let Some(root) = &self.template {
            crate::json::write(root, &mut text);
        }
        text
    }
}

/// The `template` field either as the object it describes or as the JSON text the reference ships it in.
fn template_of(drive: &Json) -> Option<Json> {
    match drive
        .get("template")
        .or_else(|| drive.get("template_json"))?
    {
        Json::Str(text) => crate::json::parse(text).ok(),
        Json::Obj(items) => Some(Json::Obj(items.clone())),
        _ => None,
    }
}

/// The `s3` object; a missing one is only legal for another service.
fn s3_of(drive: &Json) -> Option<S3Settings> {
    let node = drive.get("s3")?;
    let text = |name: &str| {
        node.get(name)
            .or_else(|| node.get(&snake_case(name)))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned()
    };
    Some(S3Settings {
        endpoint: text("endpoint"),
        region: text("region"),
        bucket: text("bucket"),
        path_style: node
            .get("pathStyle")
            .or_else(|| node.get("path_style"))
            .and_then(Json::as_bool)
            .unwrap_or(true),
    })
}

/// The `xmux` object as the reference reads it, with the same `snake_case` fallback as every other field.
fn xmux_of(drive: &Json) -> Option<XmuxSettings> {
    let Some(node) = drive.get("xmux") else {
        return Some(XmuxSettings::default());
    };
    if !matches!(node, Json::Obj(_) | Json::Null) {
        return None;
    }
    let field = |name: &str| -> Option<u32> {
        match node.get(name).or_else(|| node.get(&snake_case(name))) {
            Some(value) => XmuxSettings::set(value),
            None => Some(0),
        }
    };
    Some(XmuxSettings {
        max_concurrency: field("maxConcurrency")?,
        max_connections: field("maxConnections")?,
    })
}

/// The transport's REALITY identity, and whether it named its own decoy rather than borrowing the lane's host.
fn transport_reality(stream: &Json) -> (Option<Arc<RealityClientConfig>>, bool) {
    let named = stream
        .get("realitySettings")
        .and_then(|reality| reality.get("serverName"))
        .and_then(Json::as_str)
        .is_some_and(|name| !name.is_empty());
    (
        crate::config::stream_reality(stream, "xdrive.invalid"),
        named,
    )
}

/// The transport's TLS as the store dials it: the config's server name or the url's host, its roots or the system's, and no `ALPN` because the store speaks `HTTP/1.1`.
fn transport_tls(stream: &Json, security: &str) -> Option<Arc<TlsConfig>> {
    (security == "tls").then(|| {
        let tls = stream.get("tlsSettings").unwrap_or(&Json::Null);
        Arc::new(TlsConfig {
            server_name: tls
                .get("serverName")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
            alpn: Vec::new().into(),
            roots: tls
                .get("caCertFile")
                .and_then(Json::as_str)
                .and_then(crate::config::read_cert_file)
                .map(|pem| ferrox_core::tls::Anchors::from(crate::quic::parse_ca_pem(&pem)))
                .unwrap_or_default(),
            pins: ferrox_core::foxy::pin::Pins::default(),
            cert_pins: std::sync::Arc::from(Vec::new()),
            verify_names: std::sync::Arc::default(),
            cipher_suites: std::sync::Arc::default(),
            curves: std::sync::Arc::default(),
            insecure: tls.get("allowInsecure").and_then(Json::as_bool) == Some(true),
            resumption: true,
            fingerprint: None,
            ech_config_list: None,
            websocket: false,
            master_key_log: None,
            client_cert: None,
            client_random: None,
            padding: None,
            ..Default::default()
        })
    })
}

/// The `snake_case` spelling of a `camelCase` config name, so either form reaches one field.
fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for ch in name.chars() {
        if ch.is_uppercase() {
            out.push('_');
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// A budget left at zero is unset; any other value is taken as configured.
fn millis(value: u32, fallback: Duration) -> Duration {
    if value == 0 {
        fallback
    } else {
        Duration::from_millis(u64::from(value))
    }
}

fn seconds(value: u32, fallback: Duration) -> Duration {
    if value == 0 {
        fallback
    } else {
        Duration::from_secs(u64::from(value))
    }
}

/// A byte budget capped at the ceiling the reference enforces, never rounded down to zero.
fn bytes_of(value: u32, fallback: usize, limit: usize) -> usize {
    if value == 0 {
        return fallback;
    }
    usize::try_from(value).unwrap_or(limit).clamp(1, limit)
}

fn count(value: u32, fallback: usize, limit: usize) -> usize {
    if value == 0 {
        return fallback;
    }
    usize::try_from(value).unwrap_or(limit).clamp(1, limit)
}

impl Params {
    /// A `maxPollIntervalMs` configured below its own `pollIntervalMs` is raised to it, so the backoff never inverts.
    fn clamped(mut self) -> Self {
        if self.max_poll < self.min_poll {
            self.max_poll = self.min_poll;
        }
        self
    }
}

/// `sessions/<unixnano>-<session>`: the stamp is part of the name because the listener ages announcements out of the name alone, with no metadata to read.
fn announce_name(session: &str, nanos: i64) -> String {
    format!("{SESSIONS_DIR}/{nanos}-{session}")
}

/// The name split back apart: a digit-only nanosecond stamp and the session after the first dash.
fn parse_announce(entry: &str) -> Option<(&str, i64)> {
    let (stamp, session) = entry.split_once('-')?;
    if session.is_empty() {
        return None;
    }
    Some((session, digits(stamp)?.parse().ok()?))
}

/// Only ASCII digits, so a forged listing that carries a sign, a space or a non-decimal digit names nothing.
fn digits(text: &str) -> Option<&str> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then_some(text)
}

fn uplink_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}/{UPLINK_DIR}")
}

fn downlink_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}/{DOWNLINK_DIR}")
}

/// The nine-digit sequence and the suffix: a listing sorts into send order by this width, so the padding is wire format.
fn object_name(prefix: &str, seq: u64, suffix: &str) -> String {
    format!("{prefix}/{seq:09}{suffix}")
}

/// The sequence and suffix a listed name carries, or nothing for a name this carrier did not write.
fn parse_entry(name: &str) -> Option<(u64, &str)> {
    let dot = name.rfind('.')?;
    let suffix = &name[dot..];
    if suffix != SEG_SUFFIX && suffix != END_SUFFIX && suffix != ERR_SUFFIX {
        return None;
    }
    digits(&name[..dot])?.parse().ok().map(|seq| (seq, suffix))
}

fn unix_nanos(now: SystemTime) -> i64 {
    i64::try_from(
        now.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    )
    .unwrap_or(i64::MAX)
}

/// The 32 lowercase hex characters that name one session.
fn session_id() -> io::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|error| io::Error::other(error.to_string()))?;
    let mut hex = String::with_capacity(32);
    for byte in raw {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// A failure the lane reports as its own end: an object the store refused to hold, a segment that never arrived while later ones did, or a peer that marked one lost.
fn carrier_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Why a loop's wait ended, since a loop woken by the peer polls at once while one woken by a halt returns.
enum Woke {
    Stopped,
    Rung,
    Waited,
}

/// The wait every xdrive loop parks on: a poll interval, a ring from the peer's write, or the lane's halt, all on one condvar so closing a stream ends every loop without a join.
struct Wake {
    stopped: AtomicBool,
    rung: AtomicBool,
    lock: Mutex<()>,
    cv: Condvar,
}

impl Wake {
    fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            rung: AtomicBool::new(false),
            lock: Mutex::new(()),
            cv: Condvar::new(),
        }
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Shorten the next wait: the peer's write means an object the reader would otherwise learn of only when its backoff expires.
    fn ring(&self) {
        self.rung.store(true, Ordering::Release);
        self.cv.notify_one();
    }

    fn halt(&self) {
        self.stopped.store(true, Ordering::Release);
        self.cv.notify_all();
    }

    /// Wait out `longest`, or until rung, or until halted; a flag set while nobody waited is read here, so a wake is never lost between two polls.
    fn wait(&self, longest: Duration) -> Woke {
        if self.stopped() {
            return Woke::Stopped;
        }
        if self.rung.swap(false, Ordering::AcqRel) {
            return Woke::Rung;
        }
        census!("xdrive-wait", crate::census::NO_FD, Some(longest));
        let guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (guard, timed_out) = self
            .cv
            .wait_timeout(guard, longest)
            .unwrap_or_else(PoisonError::into_inner);
        drop(guard);
        if self.stopped() {
            return Woke::Stopped;
        }
        if self.rung.swap(false, Ordering::AcqRel) || !timed_out.timed_out() {
            return Woke::Rung;
        }
        Woke::Waited
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

/// The jobs a `Pool` drains, with those handed to a worker counted beside those still waiting so a closer can wait for its last upload to land.
struct Queue {
    jobs: VecDeque<Job>,
    left: usize,
    shut: bool,
}

/// Bounded concurrent work against the store — uploads, deletes — whose threads exist only while jobs wait: a lane idle for an hour costs no thread, and a burst of segments gets as many as the config allows and no more.
struct Pool {
    queue: Mutex<Queue>,
    run: Condvar,
    settled: Condvar,
    live: AtomicUsize,
    cap: usize,
}

impl Pool {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(Queue {
                jobs: VecDeque::new(),
                left: 0,
                shut: false,
            }),
            run: Condvar::new(),
            settled: Condvar::new(),
            live: AtomicUsize::new(0),
            cap,
        })
    }

    /// Hand a job over, starting a worker when every one it has may already be busy. The count and the queue move under one lock, so a job never sits waiting with no worker awake for it.
    fn push(self: &Arc<Self>, job: Job) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.shut {
            return false;
        }
        queue.jobs.push_back(job);
        queue.left += 1;
        let live = self.live.load(Ordering::Acquire);
        let spawn = queue.jobs.len() >= live && live < self.cap;
        self.run.notify_one();
        if !spawn {
            return true;
        }
        self.live.fetch_add(1, Ordering::AcqRel);
        let pool = Arc::clone(self);
        if std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || Self::drain(&pool))
            .is_ok()
        {
            return true;
        }
        self.live.fetch_sub(1, Ordering::AcqRel);
        if let Some(job) = queue.jobs.pop_front() {
            drop(queue);
            job();
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.left -= 1;
            if queue.left == 0 {
                self.settled.notify_all();
            }
        }
        true
    }

    /// A worker's life: wait for a job, run it outside the lock, and retire only when the queue holds nothing and no more can arrive.
    fn drain(self: &Arc<Self>) {
        loop {
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            while queue.jobs.is_empty() {
                if queue.shut {
                    drop(queue);
                    self.live.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                census!("xdrive-worker", crate::census::NO_FD, None);
                queue = self.run.wait(queue).unwrap_or_else(PoisonError::into_inner);
            }
            let Some(job) = queue.jobs.pop_front() else {
                continue;
            };
            drop(queue);
            job();
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.left -= 1;
            if queue.left == 0 {
                self.settled.notify_all();
            }
        }
    }

    /// No further jobs, but every one already promised still runs: the `.end` marker a writer puts after this must not overtake the segments queued before it.
    fn shut(&self) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .shut = true;
        self.run.notify_all();
    }

    /// Wait for every promised job, giving up if the lane ends underneath: a relay tearing down has no reader left to wait for.
    fn wait_settled(&self, wake: &Wake) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        for _ in 0..DRAIN_TRIES {
            if queue.left == 0 {
                return true;
            }
            if wake.stopped() {
                return false;
            }
            census!("xdrive-drain", crate::census::NO_FD, Some(DRAIN_WAIT));
            let (guard, _timeout) = self
                .settled
                .wait_timeout(queue, DRAIN_WAIT)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
        }
        queue.left == 0
    }

    /// End the queue and throw away what never started: the lane is already dying and nothing left can read it.
    fn abort(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        queue.shut = true;
        queue.left -= queue.jobs.len();
        queue.jobs.clear();
        if queue.left == 0 {
            self.settled.notify_all();
        }
        drop(queue);
        self.run.notify_all();
    }
}

/// One writer's place in the shared ticker.
struct Ticker {
    sink: Arc<Sink>,
    pending: Arc<Mutex<Pending>>,
    uploads: Arc<Pool>,
    every: Duration,
    due: AtomicU64,
    done: AtomicBool,
}

/// The clock every writer registers with: the interval is the same for every session, so one thread pacing all of them replaces one timer per stream.
struct Clock {
    list: Mutex<Vec<Arc<Ticker>>>,
    cv: Condvar,
}

/// Milliseconds since the first mark, so one monotonic clock numbers every writer's deadline.
fn mark() -> u64 {
    static ZERO: OnceLock<Instant> = OnceLock::new();
    Instant::now()
        .duration_since(*ZERO.get_or_init(Instant::now))
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

impl Clock {
    fn global() -> Arc<Self> {
        static CLOCK: OnceLock<Arc<Clock>> = OnceLock::new();
        Arc::clone(CLOCK.get_or_init(|| {
            let clock = Arc::new(Self {
                list: Mutex::new(Vec::new()),
                cv: Condvar::new(),
            });
            let runner = Arc::clone(&clock);
            std::thread::Builder::new()
                .stack_size(WORKER_STACK)
                .spawn(move || runner.run())
                .expect("the xdrive ticker always starts");
            clock
        }))
    }

    /// Wake the runner so it recomputes its deadline the moment a writer joins or leaves.
    fn wakeup(&self) {
        let _guard = self.list.lock().unwrap_or_else(PoisonError::into_inner);
        self.cv.notify_one();
    }

    fn add(&self, ticker: Arc<Ticker>) {
        self.list
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(ticker);
        self.wakeup();
    }

    /// Drop writers that ended, arm the ones now due, fire them off the lock, then sleep until the next deadline.
    fn run(&self) {
        loop {
            let mut due: Vec<Arc<Ticker>> = Vec::new();
            let mut next = u64::MAX;
            {
                let mut list = self.list.lock().unwrap_or_else(PoisonError::into_inner);
                let now = mark();
                list.retain(|ticker| {
                    if ticker.done.load(Ordering::Acquire) {
                        return false;
                    }
                    let at = ticker.due.load(Ordering::Acquire);
                    if at > now {
                        next = next.min(at);
                        return true;
                    }
                    let again = now.saturating_add(ticker.every.as_millis().max(1) as u64);
                    ticker.due.store(again, Ordering::Release);
                    next = next.min(again);
                    due.push(Arc::clone(ticker));
                    true
                });
            }
            for ticker in &due {
                tick(ticker);
            }
            let sleep = if next == u64::MAX {
                DEFAULT_FLUSH
            } else {
                Duration::from_millis(next.saturating_sub(mark()).max(1))
            };
            census!("xdrive-ticker", crate::census::NO_FD, Some(sleep));
            let guard = self.list.lock().unwrap_or_else(PoisonError::into_inner);
            let (guard, _timeout) = self
                .cv
                .wait_timeout(guard, sleep)
                .unwrap_or_else(PoisonError::into_inner);
            drop(guard);
        }
    }
}

/// The parts of a writer an upload worker needs, held apart from the buffer state so a worker's closure never points back at the stream that owns it.
struct Sink {
    storage: Arc<dyn Storage>,
    prefix: String,
    wake: Arc<Wake>,
    segment: usize,
    err: Mutex<Option<String>>,
    spare: Mutex<Vec<Vec<u8>>>,
}

impl Sink {
    /// A failed put is the lane's last word: the writer reports it and stops writing, as the reference latches its first error, and names the object so the peer ends instead of waiting out the hole timeout.
    fn note(&self, message: String) {
        let mut err = self.err.lock().unwrap_or_else(PoisonError::into_inner);
        if err.is_none() {
            *err = Some(message);
        }
        drop(err);
        self.wake.ring();
    }

    fn failure(&self) -> Option<String> {
        self.err
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// An empty buffer with the capacity a finished upload left behind, so steady traffic writes into the same allocation instead of paying for a fresh one per segment.
    fn adopt(&self) -> Vec<u8> {
        self.spare
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_default()
    }

    /// A buffer that reached the store is worth keeping only for its capacity, and only a couple of them.
    fn reclaim(&self, mut data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        data.clear();
        let mut spare = self.spare.lock().unwrap_or_else(PoisonError::into_inner);
        if spare.len() < 2 {
            spare.push(data);
        }
    }

    /// One segment's upload: the store's refusal latches the failure and marks the sequence, and the buffer comes back either way.
    fn send(&self, name: &str, marker: &str, buf: Vec<u8>, len: usize) {
        if let Err(error) = self.storage.put(name, &buf[..len]) {
            self.note(format!("the store refused {name}: {error}"));
            let _ = self.storage.put(marker, &[]);
        }
        self.reclaim(buf);
    }
}

/// The bytes not yet sent, with the coalescing state beside them: `held` counts the ticks a still-growing buffer was left alone and `last` is the size the tick before saw.
struct Pending {
    buf: Vec<u8>,
    seq: u64,
    last: usize,
    held: usize,
    closed: bool,
    err: Option<String>,
}

impl Pending {
    /// The reference's rule: while the buffer keeps growing hold the cut for a bounded number of ticks so a burst coalesces, and flush the moment growth stops.
    fn ready(&mut self) -> bool {
        let grew = self.buf.len() > self.last;
        self.last = self.buf.len();
        if grew && self.held < MAX_COALESCED_TICKS {
            self.held += 1;
            return false;
        }
        self.held = 0;
        true
    }
}

/// The write half of a session: coalesce into segments, hand each to the store, and close with the `.end` marker at the sequence the peer reads to know the stream is over.
struct Writer {
    sink: Arc<Sink>,
    uploads: Arc<Pool>,
    pending: Arc<Mutex<Pending>>,
    ticker: Arc<Ticker>,
    ended: AtomicBool,
}

impl Writer {
    fn new(storage: Arc<dyn Storage>, prefix: String, params: &Params, wake: Arc<Wake>) -> Self {
        let sink = Arc::new(Sink {
            segment: params.segment_bytes,
            storage,
            prefix,
            wake,
            err: Mutex::new(None),
            spare: Mutex::new(Vec::new()),
        });
        let uploads = Pool::new(params.concurrency);
        let pending = Arc::new(Mutex::new(Pending {
            buf: Vec::new(),
            seq: 0,
            last: 0,
            held: 0,
            closed: false,
            err: None,
        }));
        let ticker = Arc::new(Ticker {
            sink: Arc::clone(&sink),
            pending: Arc::clone(&pending),
            uploads: Arc::clone(&uploads),
            every: params.flush,
            due: AtomicU64::new(mark().saturating_add(params.flush.as_millis() as u64)),
            done: AtomicBool::new(false),
        });
        Clock::global().add(Arc::clone(&ticker));
        Self {
            sink,
            uploads,
            pending,
            ticker,
            ended: AtomicBool::new(false),
        }
    }

    /// Append and cut whole segments as the buffer fills, so a bulk write never parks bytes in memory waiting for the clock.
    fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.err.is_none() {
            pending.err = self.sink.failure();
        }
        if let Some(message) = &pending.err {
            return Err(carrier_error(message.clone()));
        }
        if pending.closed {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        }
        pending.buf.extend_from_slice(data);
        while pending.buf.len() >= self.sink.segment {
            if !Self::cut(&self.sink, &self.uploads, &mut pending) {
                let message = pending
                    .err
                    .clone()
                    .unwrap_or_else(|| "the store stopped answering".to_owned());
                return Err(carrier_error(message));
            }
        }
        Ok(data.len())
    }

    /// Move one segment out of the buffer and onto the store. The buffer goes whole and only the bytes past this sequence are copied into a recycled continuation, so a flush that empties the tail costs no copy and one that does not costs the remainder once, against the reference's segment-plus-remainder pair.
    fn cut(sink: &Arc<Sink>, uploads: &Arc<Pool>, pending: &mut Pending) -> bool {
        if pending.buf.is_empty() {
            return true;
        }
        if let Some(message) = sink.failure() {
            pending.err.get_or_insert(message);
            return false;
        }
        let len = pending.buf.len().min(sink.segment);
        let rest = pending.buf.len() - len;
        let mut next = sink.adopt();
        if next.capacity() < rest {
            next = Vec::with_capacity(rest.max(sink.segment));
        }
        next.extend_from_slice(&pending.buf[len..]);
        let buf = std::mem::replace(&mut pending.buf, next);
        let seq = pending.seq;
        pending.seq += 1;
        pending.last = pending.buf.len();
        pending.held = 0;
        let name = object_name(&sink.prefix, seq, SEG_SUFFIX);
        let marker = object_name(&sink.prefix, seq, ERR_SUFFIX);
        let job_sink = Arc::clone(sink);
        if !uploads.push(Box::new(move || job_sink.send(&name, &marker, buf, len))) {
            pending
                .err
                .get_or_insert("the writer closed with a segment unsent".to_owned());
            return false;
        }
        true
    }

    /// Drain what the stream still holds, wait for every segment to land, then name the end: a peer reads the `.end` at the next sequence and closes its own side.
    fn close(&self) -> io::Result<()> {
        if self.ended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let seq = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            pending.closed = true;
            while !pending.buf.is_empty() && Self::cut(&self.sink, &self.uploads, &mut pending) {}
            pending.seq
        };
        self.ticker.done.store(true, Ordering::Release);
        Clock::global().wakeup();
        self.uploads.shut();
        if !self.uploads.wait_settled(&self.sink.wake) {
            self.uploads.abort();
            return Err(carrier_error(
                "the store stopped answering the last segments".to_owned(),
            ));
        }
        if let Some(message) = self.sink.failure() {
            return Err(carrier_error(message));
        }
        self.sink
            .storage
            .put(&object_name(&self.sink.prefix, seq, END_SUFFIX), &[])
    }
}

impl Drop for Writer {
    /// A write log left open by a relay that dropped its handle gets its `.end` here; `close` is idempotent, so the leg that closed in prose costs one atomic swap.
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// A writer's tick: decide whether the buffer is ripe and, if it is, hand over a segment.
fn tick(ticker: &Ticker) {
    let mut pending = ticker
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if pending.closed || pending.err.is_some() || pending.buf.is_empty() || !pending.ready() {
        return;
    }
    Writer::cut(&ticker.sink, &ticker.uploads, &mut pending);
}

/// What the relay's read asks the inbox for next.
enum Piece {
    Chunk(Vec<u8>),
    Ended(Option<String>),
    Waited,
}

/// The read half's mailbox: the chunks the poll delivered, bounded by the same concurrency the store is read with so a fast store cannot outrun a slow relay leg.
struct Inbox {
    chunks: Mutex<VecDeque<Vec<u8>>>,
    got: Condvar,
    room: Condvar,
    ended: AtomicBool,
    err: Mutex<Option<String>>,
}

impl Inbox {
    fn new() -> Self {
        Self {
            chunks: Mutex::new(VecDeque::new()),
            got: Condvar::new(),
            room: Condvar::new(),
            ended: AtomicBool::new(false),
            err: Mutex::new(None),
        }
    }

    /// The poll's hand-off: wait for room, and give up if the lane ends underneath.
    fn push(&self, chunk: Vec<u8>, cap: usize, wake: &Wake) -> bool {
        let mut queue = self.chunks.lock().unwrap_or_else(PoisonError::into_inner);
        while queue.len() >= cap {
            if wake.stopped() {
                return false;
            }
            census!("xdrive-inbox-room", crate::census::NO_FD, Some(DRAIN_WAIT));
            let (guard, _timeout) = self
                .room
                .wait_timeout(queue, DRAIN_WAIT)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
        }
        queue.push_back(chunk);
        drop(queue);
        self.got.notify_one();
        true
    }

    /// End the stream for the reader, once: no reason is a clean `.end`, a reason is a refusal, which is how the reference splits `io.EOF` from a latched error.
    fn end(&self, reason: Option<String>) {
        if self.ended.swap(true, Ordering::AcqRel) {
            return;
        }
        *self.err.lock().unwrap_or_else(PoisonError::into_inner) = reason;
        self.got.notify_all();
        self.room.notify_all();
    }

    /// The next chunk, the stream's end, or nothing within `longest`.
    fn take(&self, longest: Duration) -> Piece {
        let mut queue = self.chunks.lock().unwrap_or_else(PoisonError::into_inner);
        let until = Instant::now() + longest;
        loop {
            if let Some(chunk) = queue.pop_front() {
                drop(queue);
                self.room.notify_one();
                return Piece::Chunk(chunk);
            }
            if self.ended.load(Ordering::Acquire) {
                let reason = self
                    .err
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                return Piece::Ended(reason);
            }
            let now = Instant::now();
            if now >= until {
                return Piece::Waited;
            }
            census!("xdrive-read", crate::census::NO_FD, Some(until - now));
            let (guard, timeout) = self
                .got
                .wait_timeout(queue, until - now)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
            if timeout.timed_out() {
                return Piece::Waited;
            }
        }
    }
}

/// What the polling half of a stream needs of the store, held apart from the mailbox so the pump thread can reach both.
struct Rd {
    storage: Arc<dyn Storage>,
    prefix: String,
    params: Arc<Params>,
    wake: Arc<Wake>,
    discards: Arc<Pool>,
}

impl Rd {
    /// Forget one object once it has been read: a store holds a live stream only as long as its objects do.
    fn discard(&self, full: String) {
        let storage = Arc::clone(&self.storage);
        let _ = self.discards.push(Box::new(move || {
            let _ = storage.delete(&full);
        }));
    }

    /// One pass at the store: list, work out what comes next, fetch it, hand the bytes over. The answer says whether the sequence moved and whether the peer ended the stream.
    fn poll(
        &self,
        seq: &mut u64,
        hole: &mut Option<Instant>,
        inbox: &Inbox,
    ) -> io::Result<(bool, bool)> {
        let mut listed = self.storage.list(&self.prefix)?;
        if listed.is_empty() {
            return Ok((false, false));
        }
        let mut pending: HashMap<u64, usize> = HashMap::new();
        let mut ahead = false;
        for (index, entry) in listed.iter().enumerate() {
            if let Some((number, _)) = parse_entry(&entry.name) {
                pending.insert(number, index);
                if number > *seq {
                    ahead = true;
                }
            }
        }
        if !pending.contains_key(seq) && ahead {
            match hole {
                empty @ None => *empty = Some(Instant::now()),
                Some(since) if since.elapsed() >= self.params.hole => {
                    return Err(carrier_error(format!(
                        "segment {seq} never arrived while later ones did, the peer lost it"
                    )));
                }
                Some(_) => {}
            }
        } else {
            *hole = None;
        }

        let mut advanced = false;
        loop {
            if let Some(&index) = pending.get(seq) {
                if listed[index].name.ends_with(ERR_SUFFIX) {
                    let full = format!("{}/{}", self.prefix, listed[index].name);
                    self.discard(full);
                    return Err(carrier_error(format!(
                        "the peer could not store segment {seq}"
                    )));
                }
            }
            let mut batch: Vec<usize> = Vec::with_capacity(self.params.concurrency);
            let mut done = false;
            for offset in 0..self.params.concurrency as u64 {
                let Some(&index) = pending.get(&(*seq + offset)) else {
                    break;
                };
                let name = &listed[index].name;
                if !name.ends_with(SEG_SUFFIX) {
                    if offset == 0 && name.ends_with(END_SUFFIX) {
                        let full = format!("{}/{}", self.prefix, name);
                        self.discard(full);
                        done = true;
                    }
                    break;
                }
                batch.push(index);
            }
            if done {
                return Ok((advanced, true));
            }
            let chunks = match self.fetch(&mut listed, &batch) {
                Ok(chunks) => chunks,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok((advanced, false)),
                Err(error) => return Err(error),
            };
            if chunks.is_empty() {
                return Ok((advanced, false));
            }
            for (offset, chunk) in chunks.into_iter().enumerate() {
                if !inbox.push(chunk, self.params.concurrency, &self.wake) {
                    return Ok((advanced, true));
                }
                let full = format!("{}/{}", self.prefix, listed[batch[offset]].name);
                self.discard(full);
                *seq += 1;
                advanced = true;
            }
        }
    }

    /// Pull a batch down: an inline entry costs nothing, one object costs no thread, and a remote store is read with a whole batch of requests in flight.
    fn fetch(&self, listed: &mut [Entry], batch: &[usize]) -> io::Result<Vec<Vec<u8>>> {
        let mut got: Vec<Option<Vec<u8>>> = batch.iter().map(|_| None).collect();
        let mut need: Vec<(usize, String)> = Vec::with_capacity(batch.len());
        for (slot, &index) in batch.iter().enumerate() {
            if let Some(data) = listed[index].inline.take() {
                got[slot] = Some(data);
                continue;
            }
            need.push((slot, format!("{}/{}", self.prefix, listed[index].name)));
        }
        if need.is_empty() {
            return Ok(got.into_iter().flatten().collect());
        }
        if need.len() == 1 || !self.storage.threaded() {
            for (slot, name) in need {
                got[slot] = Some(self.storage.get(&name)?);
            }
            return Ok(got.into_iter().flatten().collect());
        }
        let answers: Mutex<HashMap<usize, io::Result<Vec<u8>>>> = Mutex::new(HashMap::new());
        std::thread::scope(|scope| {
            for (slot, name) in need {
                let storage = &self.storage;
                let filled = &answers;
                let _ = std::thread::Builder::new()
                    .stack_size(WORKER_STACK)
                    .spawn_scoped(scope, move || {
                        let answer = storage.get(&name);
                        filled
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(slot, answer);
                    });
            }
        });
        let mut answers = answers.into_inner().unwrap_or_else(PoisonError::into_inner);
        for (slot, place) in got.iter_mut().enumerate() {
            if place.is_some() {
                continue;
            }
            match answers.remove(&slot) {
                Some(Ok(data)) => *place = Some(data),
                Some(Err(error)) => return Err(error),
                None => {
                    return Err(carrier_error(format!(
                        "the store answered nothing for segment {}",
                        listed[batch[slot]].name
                    )));
                }
            }
        }
        Ok(got.into_iter().flatten().collect())
    }

    /// The pump's own loop: poll, then wait out a backoff the peer's write can cut short; the mailbox ends with the reason the loop stopped.
    fn run(&self, inbox: &Inbox) {
        let mut seq = 0u64;
        let mut hole: Option<Instant> = None;
        let mut delay = self.params.min_poll;
        let mut active = Instant::now();
        loop {
            let polled = Instant::now();
            match self.poll(&mut seq, &mut hole, inbox) {
                Ok((advanced, eof)) => {
                    if eof {
                        return;
                    }
                    if advanced {
                        active = Instant::now();
                    }
                    delay = backoff(advanced, active, delay, &self.params);
                }
                Err(error) => {
                    inbox.end(Some(error.to_string()));
                    return;
                }
            }
            match self.wake.wait(delay) {
                Woke::Stopped => return,
                Woke::Waited => {}
                Woke::Rung => {
                    active = Instant::now();
                    delay = self.params.min_poll;
                    if let Some(rest) = self.params.min_poll.checked_sub(polled.elapsed()) {
                        if matches!(self.wake.wait(rest), Woke::Stopped) {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// The wait the next poll of a lane gets: the interval while it advances or is still fresh, then doubling to the cap.
fn backoff(advanced: bool, active: Instant, delay: Duration, params: &Params) -> Duration {
    if advanced || active.elapsed() < params.eager {
        return params.min_poll;
    }
    delay
        .checked_mul(2)
        .unwrap_or(params.max_poll)
        .min(params.max_poll)
}

/// The read half: a pump thread polling the store, and the mailbox the relay reads.
struct Reader {
    rd: Arc<Rd>,
    inbox: Arc<Inbox>,
    rest: Mutex<(Vec<u8>, usize)>,
}

impl Reader {
    fn new(
        storage: Arc<dyn Storage>,
        prefix: String,
        params: Arc<Params>,
        wake: Arc<Wake>,
    ) -> Self {
        let rd = Arc::new(Rd {
            discards: Pool::new(params.concurrency),
            storage,
            prefix,
            params,
            wake,
        });
        let inbox = Arc::new(Inbox::new());
        let pump = Arc::clone(&rd);
        let mailbox = Arc::clone(&inbox);
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || {
                pump.run(&mailbox);
                mailbox.end(None);
            })
            .expect("a reader always gets its pump");
        Self {
            rd,
            inbox,
            rest: Mutex::new((Vec::new(), 0)),
        }
    }

    /// Fill from the mailbox and keep the unread tail of a chunk the caller could not take, so a chunk is delivered once and never copied back.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut rest = self.rest.lock().unwrap_or_else(PoisonError::into_inner);
        if rest.1 < rest.0.len() {
            let n = (rest.0.len() - rest.1).min(buf.len());
            buf[..n].copy_from_slice(&rest.0[rest.1..rest.1 + n]);
            rest.1 += n;
            if rest.1 == rest.0.len() {
                rest.0.clear();
                rest.1 = 0;
            }
            return Ok(n);
        }
        drop(rest);
        match self.inbox.take(RELAY_POLL) {
            Piece::Waited => Err(io::Error::from(ErrorKind::WouldBlock)),
            Piece::Ended(None) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Piece::Ended(Some(reason)) => Err(carrier_error(reason)),
            Piece::Chunk(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                let mut rest = self.rest.lock().unwrap_or_else(PoisonError::into_inner);
                rest.0 = data;
                rest.1 = n;
                Ok(n)
            }
        }
    }
}

impl Drop for Reader {
    /// The last handle dropping ends the pump and closes the discard queue, but the deletes already promised still land: a session outlives the relay that read it only in the sense that nothing new is handed over.
    fn drop(&mut self) {
        self.rd.wake.halt();
        self.rd.discards.shut();
    }
}

/// One xdrive stream: the two write-ahead logs one session names, with the object store the peer reads and writes beside them.
#[derive(Clone)]
pub(crate) struct Conn {
    writer: Arc<Writer>,
    reader: Arc<Reader>,
    wake: Arc<Wake>,
    meter: crate::stats::Meter,
}

impl Conn {
    fn pair(storage: Arc<dyn Storage>, params: &Arc<Params>, write: String, read: String) -> Self {
        let wake = Arc::new(Wake::new());
        Self {
            writer: Arc::new(Writer::new(
                Arc::clone(&storage),
                write,
                params,
                Arc::clone(&wake),
            )),
            reader: Arc::new(Reader::new(
                storage,
                read,
                Arc::clone(params),
                Arc::clone(&wake),
            )),
            wake,
            meter: crate::stats::Meter::default(),
        }
    }

    /// Adds counters to the session while keeping the ones it already carries.
    pub(crate) fn with_meter(mut self, meter: crate::stats::Meter) -> Self {
        self.meter = self.meter.merged(meter);
        self
    }

    /// End only the write log, so a relay whose source went quiet lets the peer read its `.end` while our own reader keeps serving the reply.
    pub(crate) fn end_write(&self) -> io::Result<()> {
        self.writer.close()
    }

    /// End the read mailbox too, for a caller that is done with both directions and must not leave its reader parked.
    pub(crate) fn end_read(&self) {
        self.reader.inbox.end(None);
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.meter.read(n);
        Ok(n)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.meter.write(n);
        self.wake.ring();
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The client's half of a session: name the session where the listener looks, then open both logs on it.
pub(crate) fn dial(storage: Arc<dyn Storage>, params: &Arc<Params>) -> io::Result<Conn> {
    let session = session_id()?;
    storage.put(&announce_name(&session, unix_nanos(SystemTime::now())), &[])?;
    Ok(Conn::pair(
        storage,
        params,
        uplink_prefix(&session),
        downlink_prefix(&session),
    ))
}

/// What a listener hands each accepted session to: the caller's relay, on a thread of its own.
pub(crate) type Accept = Arc<dyn Fn(Conn) + Send + Sync>;

/// The sessions one listener has already seen, so a second listing of the same announcement cannot open it twice.
#[derive(Default)]
struct Claims {
    active: HashSet<String>,
    handled: HashMap<String, Instant>,
    idle: HashMap<String, Instant>,
}

/// The server's half: a poll for announcements, a sweep for abandoned sessions, and the claims that keep each session opening once.
pub(crate) struct Server {
    wake: Arc<Wake>,
    claims: Mutex<Claims>,
}

impl Server {
    /// Watch the store for sessions and hand each one over, then keep the folder clean of what nobody closed.
    pub(crate) fn serve(
        storage: Arc<dyn Storage>,
        params: Arc<Params>,
        accept: Accept,
    ) -> io::Result<Arc<Self>> {
        let server = Arc::new(Self {
            wake: Arc::new(Wake::new()),
            claims: Mutex::new(Claims::default()),
        });
        let rd = Arc::new(Rd {
            discards: Pool::new(params.concurrency),
            storage,
            prefix: String::new(),
            params,
            wake: Arc::clone(&server.wake),
        });
        let accept_loop = Arc::clone(&server);
        let accept_rd = Arc::clone(&rd);
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || accept_loop.accept(&accept_rd, &accept))
            .map_err(|error| io::Error::other(error.to_string()))?;
        let collect_loop = Arc::clone(&server);
        let collect_rd = Arc::clone(&rd);
        std::thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || collect_loop.collect_loop(&collect_rd))
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(server)
    }

    /// Claim a session once: a name already active or already handed over is not opened again.
    fn claim(&self, session: &str) -> bool {
        let mut claims = self.claims.lock().unwrap_or_else(PoisonError::into_inner);
        if claims.active.contains(session) || claims.handled.contains_key(session) {
            return false;
        }
        claims.active.insert(session.to_owned());
        claims.handled.insert(session.to_owned(), Instant::now());
        true
    }

    fn release(&self, session: &str) {
        self.claims
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active
            .remove(session);
    }

    /// Poll the announcement folder on the same backoff as a stream: a busy listener stays at the fast interval, a quiet one sleeps out to the cap.
    fn accept(self: &Arc<Self>, rd: &Rd, accept: &Accept) {
        let mut delay = rd.params.min_poll;
        let mut active = Instant::now();
        loop {
            let accepted = self.accept_pending(rd, accept);
            if accepted {
                active = Instant::now();
            }
            delay = backoff(accepted, active, delay, &rd.params);
            match rd.wake.wait(delay) {
                Woke::Stopped => return,
                Woke::Rung => {
                    active = Instant::now();
                    delay = rd.params.min_poll;
                }
                Woke::Waited => {}
            }
        }
    }

    /// One listing of `sessions`: drop what is not an announcement or older than the ttl, and open what is fresh and unclaimed.
    fn accept_pending(self: &Arc<Self>, rd: &Rd, accept: &Accept) -> bool {
        let Ok(listed) = rd.storage.list(SESSIONS_DIR) else {
            return false;
        };
        let mut accepted = false;
        for entry in listed {
            let full = format!("{SESSIONS_DIR}/{}", entry.name);
            let Some((session, at)) = parse_announce(&entry.name) else {
                rd.discard(full);
                continue;
            };
            if unix_nanos(SystemTime::now()) - at
                > i64::try_from(rd.params.ttl.as_nanos()).unwrap_or(i64::MAX)
            {
                rd.discard(full);
                rd.discard(format!("{STREAMS_DIR}/{session}"));
                continue;
            }
            if !self.claim(session) {
                continue;
            }
            rd.discard(full);
            accepted = true;
            let conn = Conn::pair(
                Arc::clone(&rd.storage),
                &rd.params,
                downlink_prefix(session),
                uplink_prefix(session),
            );
            let server = Arc::clone(self);
            let handler = Arc::clone(accept);
            let session = session.to_owned();
            let handed = session.clone();
            if std::thread::Builder::new()
                .stack_size(WORKER_STACK)
                .spawn(move || {
                    handler(conn);
                    server.release(&handed);
                })
                .is_err()
            {
                self.release(&session);
            }
        }
        accepted
    }

    /// Sweep the streams folder twice a ttl: a session nobody has touched for a ttl is bytes no peer will read again.
    fn collect_loop(&self, rd: &Rd) {
        let interval = rd.params.ttl / 2;
        loop {
            if matches!(rd.wake.wait(interval), Woke::Stopped) {
                return;
            }
            let _ = self.collect(rd);
        }
    }

    fn collect(&self, rd: &Rd) -> io::Result<()> {
        let listed = rd.storage.list(STREAMS_DIR)?;
        let now = Instant::now();
        let mut expired: Vec<String> = Vec::new();
        {
            let mut claims = self.claims.lock().unwrap_or_else(PoisonError::into_inner);
            let mut present: HashSet<String> = HashSet::new();
            for entry in &listed {
                let session = &entry.name;
                present.insert(session.clone());
                if claims.active.contains(session.as_str()) {
                    claims.idle.remove(session.as_str());
                    continue;
                }
                match claims.idle.get(session.as_str()).copied() {
                    None => {
                        claims.idle.insert(session.clone(), now);
                    }
                    Some(since) if now.duration_since(since) >= rd.params.ttl => {
                        expired.push(session.clone());
                        claims.idle.remove(session.as_str());
                    }
                    Some(_) => {}
                }
            }
            claims.idle.retain(|session, _| present.contains(session));
            let ttl = rd.params.ttl;
            let active = claims.active.clone();
            claims.handled.retain(|session, at| {
                !active.contains(session.as_str()) && now.duration_since(*at) < ttl
            });
        }
        for session in expired {
            rd.storage.delete(&format!("{STREAMS_DIR}/{session}"))?;
        }
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.wake.halt();
    }
}

/// The store both ends can reach on one filesystem: the same folder an `xray` process would poll, with every object committed by a temp-name move so a reader never sees half a segment.
pub(crate) struct Local {
    root: PathBuf,
}

static TEMP_MARK: AtomicU64 = AtomicU64::new(0);

impl Local {
    pub(crate) fn new(root: &str) -> io::Result<Self> {
        let path = PathBuf::from(root);
        create_dir(&path)?;
        Ok(Self { root: path })
    }

    /// An absolute clean of an object name: empty and `.` segments drop, a `..` pops what it can, and the result can never name its way out of the folder.
    fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        let mut parts: Vec<&str> = Vec::new();
        for part in name.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        let Some(last) = parts.last() else {
            return Err(carrier_error(format!("invalid object name: {name}")));
        };
        if last.starts_with(TEMP_PREFIX) {
            return Err(carrier_error(format!("reserved object name: {name}")));
        }
        let mut path = self.root.clone();
        for part in parts {
            path.push(part);
        }
        Ok(path)
    }
}

/// A folder with the reference's permissions: readable by nobody but the process that polls it.
fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

impl Storage for Local {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let full = self.resolve(name)?;
        let dir = full
            .parent()
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        create_dir(&dir)?;
        let temp = dir.join(format!(
            "{TEMP_PREFIX}{}-{}",
            std::process::id(),
            TEMP_MARK.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        file.write_all(data)?;
        let committed = std::fs::rename(&temp, &full);
        if committed.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        committed
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.resolve(name)?)
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let path = self.resolve(name)?;
        let result = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match result {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let Ok(readable) = std::fs::read_dir(self.resolve(prefix)?) else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for name in readable
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
        {
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            found.push(Entry { name, inline: None });
        }
        Ok(found)
    }

    fn threaded(&self) -> bool {
        false
    }
}

/// The separator a flattened name uses where the folder step would be a slash.
const FLAT_SEP: &str = "~";
const DRIVE_INLINE_LIMIT: usize = 12_000;
const DRIVE_BOUNDARY: &str = "xdrive-boundary";
const DRIVE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DRIVE_FILES_URL: &str = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD_URL: &str =
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name";
const MAX_ATTEMPTS: usize = 8;
const DEFAULT_INFLIGHT: usize = 64;
const MAX_INFLIGHT: usize = 256;
const SERVICE_TIMEOUT: Duration = Duration::from_secs(60);
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(8);
const LINE_CAP: usize = 8 * 1024;
const HEAD_CAP: usize = 16 * 1024;
const ERROR_BODY_CAP: usize = 64 * 1024;
const TOKEN_CAP: usize = 1 << 20;
const TOKEN_SKEW: Duration = Duration::from_secs(60);
const TOKEN_LIFE: Duration = Duration::from_secs(3600);
const DRIVE_PAGE_SIZE: usize = 1000;

/// The folder steps an object name carries, replaced by `~` for a service that keeps names in one flat listing.
fn flatten(name: &str) -> String {
    name.replace('/', FLAT_SEP)
}

/// Whether one name sits under the folder prefix a listing was asked for.
fn under<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    name.strip_prefix(prefix)
        .and_then(|rest| (!rest.is_empty()).then_some(rest))
}

/// The first step of a flattened name, which is what a listing of one folder level reports.
fn first_step(rest: &str) -> &str {
    rest.split(FLAT_SEP).next().unwrap_or(rest)
}

/// A bound on how many requests one service answers at once, which is also its connection cap: a lane is held for exactly as long as its holder lives.
struct Gate {
    left: Mutex<usize>,
    room: Condvar,
}

/// The borrowed slot; dropping it is the release.
struct Hold<'a> {
    gate: &'a Gate,
}

impl Gate {
    fn new(cap: usize) -> Self {
        Self {
            left: Mutex::new(cap),
            room: Condvar::new(),
        }
    }

    /// Wait for a slot, re-checking on a timer so a stuck holder still names itself in the census.
    fn hold(&self) -> Hold<'_> {
        let mut left = self.left.lock().unwrap_or_else(PoisonError::into_inner);
        while *left == 0 {
            census!("xdrive-gate", crate::census::NO_FD, Some(DRAIN_WAIT));
            let (guard, _timeout) = self
                .room
                .wait_timeout(left, DRAIN_WAIT)
                .unwrap_or_else(PoisonError::into_inner);
            left = guard;
        }
        *left -= 1;
        Hold { gate: self }
    }
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        let mut left = self
            .gate
            .left
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *left += 1;
        self.gate.room.notify_one();
    }
}

/// The stream one service lane rides: plain to a loopback fake, TLS to a real origin.
enum Kind {
    Plain(Connection),
    Secure(Box<RustlsProvider<Connection>>),
    Reality(
        Box<
            ferrox_core::tls::RealityClientSession<
                ferrox_core::tls::reality::RecordLimiter<Connection>,
            >,
        >,
    ),
}

impl Read for Kind {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Secure(tls) => tls.read(buf),
            Self::Reality(tls) => tls.read(buf),
        }
    }
}

impl Write for Kind {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Secure(tls) => tls.write(buf),
            Self::Reality(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Secure(tls) => tls.flush(),
            Self::Reality(tls) => tls.flush(),
        }
    }
}

/// One kept-alive exchange, with the read buffer the lane keeps warm so the next reply costs no allocation and bytes that arrive past an answer are still there for it.
struct Lane {
    kind: Kind,
    buf: Vec<u8>,
    at: usize,
}

/// A reply and whether its lane can be kept: a peer that said `close`, or that ended the body at EOF, has nothing left to answer.
struct Answer {
    status: u16,
    body: Vec<u8>,
    kept: bool,
}

impl Lane {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            buf: Vec::with_capacity(crate::proxy::READ_SLICE),
            at: 0,
        }
    }

    /// At least one unread byte in the buffer, or zero once the peer has said it is done.
    fn ready(&mut self) -> io::Result<usize> {
        while self.at >= self.buf.len() {
            self.settle();
            if crate::proxy::read_into_tail(&mut self.kind, &mut self.buf)? == 0 {
                return Ok(0);
            }
        }
        Ok(self.buf.len() - self.at)
    }

    /// Move the consumed prefix out of the way without moving the unread tail.
    fn settle(&mut self) {
        if self.at >= self.buf.len() {
            self.buf.clear();
            self.at = 0;
        }
    }

    /// One `CRLF`-terminated line as a slice of the lane's own buffer: a head is read out of the buffer it arrived in, and the bytes past the line stay there for the next one.
    fn line(&mut self) -> io::Result<&[u8]> {
        loop {
            if let Some(step) = self.buf[self.at..].iter().position(|byte| *byte == b'\n') {
                let start = self.at;
                let stop = start + step;
                let end = (stop > start && self.buf[stop - 1] == b'\r').then_some(stop - 1);
                self.at = stop + 1;
                return Ok(&self.buf[start..end.unwrap_or(stop)]);
            }
            if self.ready()? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "the service ended the head",
                ));
            }
            if self.buf.len() - self.at > LINE_CAP {
                return Err(carrier_error("a service head line is too long"));
            }
        }
    }

    /// Exactly `want` body bytes appended to `out`, the chunked framing of a service that has none left being the only thing that ends the read early.
    fn append_body(&mut self, want: usize, out: &mut Vec<u8>) -> io::Result<()> {
        let stop = out.len() + want;
        while out.len() < stop {
            if self.ready()? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "the service ended the body early",
                ));
            }
            let take = (stop - out.len()).min(self.buf.len() - self.at);
            out.extend_from_slice(&self.buf[self.at..self.at + take]);
            self.at += take;
            self.settle();
        }
        Ok(())
    }

    /// Everything the peer has left to say, which is a reply only a `close`ing service can give, under the caller's cap.
    fn read_to_eof(&mut self, out: &mut Vec<u8>, limit: Option<usize>) -> io::Result<()> {
        while self.ready()? > 0 {
            guard(out.len() + self.buf.len() - self.at, limit)?;
            out.extend_from_slice(&self.buf[self.at..]);
            self.at = self.buf.len();
        }
        Ok(())
    }

    /// The request, then the answer; `header_only` is a `HEAD`, whose declared length never arrives as bytes.
    fn exchange(
        &mut self,
        head: &[u8],
        body: Option<&[u8]>,
        header_only: bool,
        limit: Option<usize>,
    ) -> io::Result<Answer> {
        self.buf.clear();
        self.at = 0;
        self.kind.write_all(head)?;
        if let Some(payload) = body {
            self.kind.write_all(payload)?;
        }
        self.kind.flush()?;
        self.reply(header_only, limit)
    }

    fn reply(&mut self, header_only: bool, limit: Option<usize>) -> io::Result<Answer> {
        let first = self.line()?;
        let mut counted = first.len();
        let status =
            status_of(first).ok_or_else(|| carrier_error("a service head has no status"))?;
        let mut transfer = false;
        let mut length = None;
        let mut closing = false;
        loop {
            let line = self.line()?;
            counted += line.len();
            if counted > HEAD_CAP {
                return Err(carrier_error("the service head is too long"));
            }
            if line.is_empty() {
                break;
            }
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            // The name and the value are read where they lie: a head the service does not read costs no buffer, and the three names it does read are compared in place rather than built.
            let name = &line[..colon];
            let value = String::from_utf8_lossy(&line[colon + 1..]);
            let value = value.trim();
            if name.eq_ignore_ascii_case(b"content-length") && !transfer {
                length = value.parse::<usize>().ok().or(length);
            } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
                transfer |= contains_ascii_case(value, "chunked");
            } else if name.eq_ignore_ascii_case(b"connection") {
                closing |= contains_ascii_case(value, "close");
            }
        }
        if header_only || matches!(status, 204 | 304) {
            return Ok(Answer {
                status,
                body: Vec::new(),
                kept: !closing,
            });
        }
        let limit = limit.map(|cap| {
            if (200..300).contains(&status) {
                cap
            } else {
                cap.min(ERROR_BODY_CAP)
            }
        });
        let mut body = Vec::new();
        let kept = if transfer {
            self.chunks(&mut body, limit)?;
            !closing
        } else if let Some(want) = length {
            guard(want, limit)?;
            self.append_body(want, &mut body)?;
            !closing
        } else {
            self.read_to_eof(&mut body, limit)?;
            false
        };
        Ok(Answer { status, body, kept })
    }

    /// A chunked body: the framing read one chunk at a time, so a chunk boundary is never a copy boundary.
    fn chunks(&mut self, out: &mut Vec<u8>, limit: Option<usize>) -> io::Result<()> {
        loop {
            let line = self.line()?;
            let Some(want) = chunk_size(line) else {
                return Err(carrier_error("the service framed a chunk badly"));
            };
            if want == 0 {
                while !self.line()?.is_empty() {}
                return Ok(());
            }
            guard(out.len() + want, limit)?;
            self.append_body(want, out)?;
            self.line()?;
        }
    }
}

/// A body length the caller will not let the store spend.
fn guard(want: usize, limit: Option<usize>) -> io::Result<()> {
    if limit.is_some_and(|cap| want > cap) {
        return Err(carrier_error(format!(
            "the service body reaches {want} bytes past its limit"
        )));
    }
    Ok(())
}

/// Whether a header value holds a word, compared without a copy of the value.
fn contains_ascii_case(haystack: &str, needle: &str) -> bool {
    let hay = haystack.as_bytes();
    let pin = needle.as_bytes();
    hay.windows(pin.len())
        .any(|window| window.eq_ignore_ascii_case(pin))
}

/// The status out of `HTTP/1.1 200 OK`.
fn status_of(line: &[u8]) -> Option<u16> {
    let mut parts = line.split(|byte| *byte == b' ');
    let version = parts.next()?;
    if !version.starts_with(b"HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    let text = String::from_utf8_lossy(code);
    (text.len() == 3)
        .then(|| text.parse::<u16>().ok())
        .flatten()
}

/// A chunk's hex length, with its extension dropped.
fn chunk_size(line: &[u8]) -> Option<usize> {
    let hex = line
        .split(|byte| *byte == b';')
        .next()
        .map_or("", |part| std::str::from_utf8(part).unwrap_or(""));
    usize::from_str_radix(hex.trim(), 16).ok()
}

/// Where one service url says to go: the authority for the `Host` header, the path and query for the request line.
#[derive(Debug)]
struct Target {
    secure: bool,
    host: String,
    port: u16,
    named_port: bool,
    path: String,
}

impl Target {
    fn parse(url: &str) -> Option<Self> {
        let (secure, rest) = url
            .strip_prefix("https://")
            .map(|rest| (true, rest))
            .or_else(|| url.strip_prefix("http://").map(|rest| (false, rest)))?;
        let cut = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = (&rest[..cut], &rest[cut..]);
        let host = match authority.strip_prefix('[') {
            Some(bracketed) => bracketed.split(']').next()?,
            None => authority
                .rsplit_once(':')
                .map_or(authority, |(host, _)| host),
        };
        let named_port = authority.strip_prefix('[').map_or_else(
            || authority.contains(':'),
            |bracketed| bracketed.contains("]:"),
        );
        let port = match authority.strip_prefix('[') {
            Some(bracketed) => bracketed
                .split(']')
                .nth(1)
                .and_then(|rest| rest.strip_prefix(':'))
                .and_then(|digits| digits.parse().ok()),
            None if authority.contains(':') => authority
                .rsplit_once(':')
                .and_then(|(_, digits)| digits.parse().ok()),
            None => None,
        }
        .unwrap_or(if secure { 443 } else { 80 });
        if host.is_empty() {
            return None;
        }
        Some(Self {
            secure,
            host: host.to_owned(),
            port,
            named_port,
            path: if tail.is_empty() {
                "/".to_owned()
            } else {
                tail.to_owned()
            },
        })
    }

    /// The bucket this lane belongs to: a scheme, a host and a port, with the fronting the transport arms kept out of it because a lane to a front speaks for the origin.
    fn origin(&self) -> String {
        format!(
            "{}:{}:{}",
            if self.secure { "https" } else { "http" },
            self.host,
            self.port
        )
    }

    /// The `Host` header, whose port only shows when it is not the scheme's own.
    fn authority(&self) -> String {
        let default = !self.named_port && self.port == if self.secure { 443 } else { 80 };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// The request head, with the payload deliberately left out of it: a segment is written behind the head instead of copied into it, which is the one thing a Go `bytes.Reader` gets for free and a merged buffer would not.
fn request_head(
    method: &str,
    authority: &str,
    path: &str,
    headers: &[(&str, &str)],
    length: Option<usize>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + path.len());
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(authority.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some(want) = declared_length(method, length) {
        let _ = write!(out, "Content-Length: {want}\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The length line the service's own http library would write: a body always declares, and a bodyless `POST`, `PUT` or `PATCH` declares zero while a `GET`, `HEAD` or `DELETE` says nothing at all.
fn declared_length(method: &str, length: Option<usize>) -> Option<usize> {
    length.or(match method {
        "POST" | "PUT" | "PATCH" => Some(0),
        _ => None,
    })
}

/// The pooled `HTTP/1.1` lanes one object service shares: a lane per in-flight request, kept for the next rather than handshaken again.
pub(crate) struct Http {
    tls: Option<Arc<TlsConfig>>,
    reality: Option<Arc<RealityClientConfig>>,
    reality_named: bool,
    front: Option<(String, u16)>,
    gate: Gate,
    lanes: Mutex<HashMap<String, VecDeque<Lane>>>,
}

impl Http {
    fn new(
        tls: Option<Arc<TlsConfig>>,
        reality: Option<Arc<RealityClientConfig>>,
        reality_named: bool,
        front: Option<(String, u16)>,
        cap: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            tls,
            reality,
            reality_named,
            front,
            gate: Gate::new(cap),
            lanes: Mutex::new(HashMap::new()),
        })
    }

    /// One request and its answer, retried by the caller's ladder: a lane taken from the pool gets one second try on a fresh one, because a server that timed out an idle connection is the ordinary reason a first try fails.
    pub(crate) fn ask(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        limit: Option<usize>,
    ) -> io::Result<(u16, Vec<u8>)> {
        let target = Target::parse(url)
            .ok_or_else(|| carrier_error(format!("the service url {url} names no origin")))?;
        let head = request_head(
            method,
            &target.authority(),
            &target.path,
            headers,
            body.map(<[u8]>::len),
        );
        let key = target.origin();
        let _hold = self.gate.hold();
        let header_only = method.eq_ignore_ascii_case("HEAD");
        let pooled = self.borrow(&key);
        if let Some(mut lane) = pooled {
            return match lane.exchange(&head, body, header_only, limit) {
                Ok(answer) => {
                    self.finish(&key, lane, &answer);
                    Ok((answer.status, answer.body))
                }
                Err(first) => {
                    let mut again = self.dial(&target)?;
                    let answer =
                        again
                            .exchange(&head, body, header_only, limit)
                            .map_err(|why| {
                                carrier_error(format!(
                                    "the service lane failed twice: {why}; first {first}"
                                ))
                            })?;
                    self.finish(&key, again, &answer);
                    Ok((answer.status, answer.body))
                }
            };
        }
        let mut lane = self.dial(&target)?;
        let answer = lane.exchange(&head, body, header_only, limit)?;
        self.finish(&key, lane, &answer);
        Ok((answer.status, answer.body))
    }

    fn borrow(&self, key: &str) -> Option<Lane> {
        let mut lanes = self.lanes.lock().unwrap_or_else(PoisonError::into_inner);
        let queue = lanes.get_mut(key)?;
        let lane = queue.pop_front();
        if queue.is_empty() {
            lanes.remove(key);
        }
        lane
    }

    fn finish(&self, key: &str, lane: Lane, answer: &Answer) {
        if !answer.kept {
            return;
        }
        self.lanes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.to_owned())
            .or_default()
            .push_back(lane);
    }

    /// Dial the fronting the outbound names, or the url's own origin, and put TLS on it when the url asks for that scheme.
    fn dial(&self, target: &Target) -> io::Result<Lane> {
        let (host, port) = match &self.front {
            Some((front, 0)) => (front.clone(), target.port),
            Some((front, at)) => (front.clone(), *at),
            None => (target.host.clone(), target.port),
        };
        let peer = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|why| carrier_error(format!("resolve {host}: {why}")))?
            .next()
            .ok_or_else(|| carrier_error(format!("{host} resolves to nothing")))?;
        let stream = crate::conn::dial_tcp(&peer, SERVICE_TIMEOUT)
            .map_err(|why| carrier_error(format!("connect {peer}: {why}")))?;
        let _ = stream.set_read_timeout(Some(SERVICE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SERVICE_TIMEOUT));
        if let Some(reality) = &self.reality {
            let mut cfg = reality.as_ref().clone();
            if !self.reality_named {
                cfg.server_name.clone_from(&target.host);
            }
            let now = u32::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
            .unwrap_or(u32::MAX);
            let limiter = ferrox_core::tls::reality::RecordLimiter::new(stream);
            let session = ferrox_core::tls::RealityClientSession::connect(&cfg, now, limiter)
                .map_err(|why| carrier_error(format!("reality {}: {why}", target.host)))?;
            return Ok(Lane::new(Kind::Reality(Box::new(session))));
        }
        if !target.secure {
            return Ok(Lane::new(Kind::Plain(stream)));
        }
        let mut cfg = self.tls.as_deref().cloned().unwrap_or_default();
        if cfg.server_name.is_empty() {
            cfg.server_name.clone_from(&target.host);
        }
        if cfg.roots.is_empty() {
            cfg.roots = crate::quic::system_roots();
        }
        let mut tls = RustlsProvider::connect(&cfg, stream)
            .map_err(|why| carrier_error(format!("tls {}: {why}", target.host)))?;
        tls.handshake()
            .map_err(|why| carrier_error(format!("handshake {}: {why}", target.host)))?;
        Ok(Lane::new(Kind::Secure(Box::new(tls))))
    }
}

/// The bearer both `HTTP` services carry, with the moment it stops being worth sending.
struct Token {
    value: String,
    until: Instant,
}

impl Default for Token {
    fn default() -> Self {
        Self {
            value: String::new(),
            until: Instant::now(),
        }
    }
}

impl Token {
    fn fresh(&self, now: Instant) -> Option<&str> {
        (!self.value.is_empty() && now < self.until).then_some(self.value.as_str())
    }

    /// The lifetime the service stated, less the minute it may be wrong by, and never less than zero.
    fn set(&mut self, value: String, life: Duration) {
        let kept = if life > TOKEN_SKEW {
            life.saturating_sub(TOKEN_SKEW)
        } else {
            Duration::ZERO
        };
        self.value = value;
        self.until = Instant::now() + kept;
    }
}

/// A byte below `top`, the way the reference jitters a backoff: no entropy is a roll of zero, which is the smallest wait rather than a failure.
fn roll(top: u64) -> u64 {
    if top == 0 {
        return 0;
    }
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).map_or(0, |()| u64::from_le_bytes(raw) % top)
}

/// Half the wait kept, half of it rolled, so a whole fleet of sessions does not poll one store in lockstep.
fn jitter(backoff: Duration) -> Duration {
    let half = backoff / 2;
    let room = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
    if room == 0 {
        return backoff;
    }
    half + Duration::from_nanos(roll(room))
}

/// One ask, either answered or worth another attempt with the reason it was not.
enum Control {
    Done(io::Result<(u16, Vec<u8>)>),
    Again(String),
}

/// The reference's attempt ladder: eight tries, the wait doubling from 200 ms to 8 s with half of each rung jittered.
fn retried(mut ask: impl FnMut() -> Control) -> io::Result<(u16, Vec<u8>)> {
    let mut backoff = INITIAL_BACKOFF;
    let mut last = String::from("the service never answered");
    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(jitter(backoff));
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        match ask() {
            Control::Done(answer) => return answer,
            Control::Again(why) => last = why,
        }
    }
    Err(carrier_error(last))
}

/// A value byte that needs quoting in a query: the unreserved set and nothing else.
fn reserved(byte: u8) -> bool {
    !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// One byte as the percent-escape the services' url library writes: uppercase, two digits.
fn pct(out: &mut String, byte: u8) {
    out.push('%');
    out.push(UPPER_HEX[(byte >> 4) as usize] as char);
    out.push(UPPER_HEX[(byte & 0x0f) as usize] as char);
}

/// `url.Values.Encode` of a list of pairs: keys sorted, every value percent-quoted with a space as `+`.
fn query(pairs: &[(&str, &str)]) -> String {
    let mut sorted = pairs.to_vec();
    sorted.sort_unstable();
    let mut out = String::new();
    for (index, (key, value)) in sorted.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        for byte in value.as_bytes() {
            match byte {
                b' ' => out.push('+'),
                other if reserved(*other) => pct(&mut out, *other),
                other => out.push(*other as char),
            }
        }
    }
    out
}

/// A `'`-quoted value inside a Drive query, with its own quotes and backslashes escaped.
fn quoted(value: &str) -> String {
    value.replace('\\', r"\\").replace('\'', r"\'")
}

/// One step of a dotted answer path.
fn walk<'a>(node: &'a Json, path: &str) -> Option<&'a Json> {
    let mut at = node;
    for key in path.split('.') {
        at = at.get(key)?;
    }
    Some(at)
}

fn text_of(node: &Json, name: &str) -> String {
    node.get(name)
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

fn flag_of(node: &Json, name: &str) -> bool {
    node.get(name).and_then(Json::as_bool).unwrap_or(false)
}

/// A `map[string]string` config field, in the order the config wrote it.
fn pairs_of(node: &Json, name: &str) -> Vec<(String, String)> {
    let Some(Json::Obj(items)) = node.get(name) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_owned()))
        .collect()
}

fn numbers_of(node: &Json, name: &str) -> Vec<u32> {
    let Some(items) = node.get(name).and_then(Json::as_arr) else {
        return Vec::new();
    };
    items.iter().filter_map(Json::as_u32).collect()
}

/// The variables a template name, in one pass over it instead of one pass per variable.
#[derive(Clone)]
struct Vars(Vec<(String, String)>);

impl Vars {
    fn new(folder: &str, secrets: &[String]) -> Self {
        let mut out = vec![("folder".to_owned(), folder.to_owned())];
        for (index, secret) in secrets.iter().enumerate() {
            out.push((format!("secret{index}"), secret.clone()));
        }
        Self(out)
    }

    fn set(&mut self, key: &str, value: String) {
        if let Some(found) = self.0.iter_mut().find(|(name, _)| name == key) {
            found.1 = value;
            return;
        }
        self.0.push((key.to_owned(), value));
    }

    /// Every `{name}` this holds, and nothing else: an unknown brace is left as the config wrote it, which is what the reference's per-key replace leaves.
    fn sub(&self, text: &str) -> String {
        if !text.contains('{') {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find('{') {
            out.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            let Some(cut) = after.find(['{', '}']) else {
                out.push('{');
                rest = after;
                continue;
            };
            if after.as_bytes()[cut] == b'{' {
                out.push('{');
                out.push_str(&after[..cut]);
                rest = &after[cut..];
                continue;
            }
            let name = &after[..cut];
            if let Some((_, value)) = self.0.iter().find(|(key, _)| key == name) {
                out.push_str(value);
            } else {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
            rest = &after[cut + 1..];
        }
        out.push_str(rest);
        out
    }
}

/// One templated operation: `GET` when it names no method, and no body until it writes one.
struct Op {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
    names: String,
    /// The JSON path a two-step operation answers with the URL to call next.
    href_path: String,
    href_method: String,
    /// A presigned URL is called as given, with neither the service's auth nor a second substitution.
    presigned: bool,
}

fn op_of(node: &Json, name: &str) -> Op {
    let empty = Json::Null;
    let at = node.get(name).unwrap_or(&empty);
    Op {
        method: text_of(at, "method"),
        url: text_of(at, "url"),
        headers: pairs_of(at, "headers"),
        body: text_of(at, "body"),
        names: text_of(at, "namesRegex"),
        href_path: text_of(at, "hrefPath"),
        href_method: text_of(at, "hrefMethod"),
        presigned: false,
    }
}

/// Which answers the templated service wants asked again.
struct Retry {
    status: Vec<u32>,
    reason: String,
}

/// How a templated service is proved: nothing, a header the config writes, a `Basic` pair, or an `OAuth2` token it fetches first.
struct Auth {
    kind: String,
    headers: Vec<(String, String)>,
    username: String,
    password: String,
    token_url: String,
    form: Vec<(String, String)>,
    token_path: String,
    expiry_path: String,
}

/// A JSON-described object service: four operations spelled as templates over `{folder}`, `{secret0}`, `{name}`, `{prefix}` and `{data}`, so any store that speaks `HTTP` can carry a session.
pub(crate) struct Template {
    http: Arc<Http>,
    folder: String,
    secrets: Vec<String>,
    flatten: bool,
    names: regex::Regex,
    auth: Auth,
    put: Op,
    get: Op,
    drop: Op,
    list: Op,
    retry: Retry,
    token: Mutex<Token>,
}

impl Template {
    fn build(settings: &Settings, http: Arc<Http>) -> io::Result<Self> {
        let root = settings
            .template
            .as_ref()
            .ok_or_else(|| carrier_error("the template service has no template"))?;
        let put = op_of(root, "put");
        let get = op_of(root, "get");
        let drop = op_of(root, "delete");
        let list = op_of(root, "list");
        if put.url.is_empty() || get.url.is_empty() || drop.url.is_empty() || list.url.is_empty() {
            return Err(carrier_error(
                "the template needs put, get, list and delete operations",
            ));
        }
        if list.names.is_empty() {
            return Err(carrier_error("the template list needs a namesRegex"));
        }
        let names = regex::Regex::new(&list.names)
            .map_err(|why| carrier_error(format!("bad namesRegex: {why}")))?;
        if names.captures_len() < 2 {
            return Err(carrier_error("namesRegex needs one capture group"));
        }
        let retry = root.get("retry").unwrap_or(&Json::Null);
        let auth = root.get("auth").unwrap_or(&Json::Null);
        Ok(Self {
            http,
            folder: settings.remote_folder.clone(),
            secrets: settings.secrets.clone(),
            flatten: flag_of(root, "flatten"),
            names,
            auth: Auth {
                kind: text_of(auth, "type"),
                headers: pairs_of(auth, "header"),
                username: text_of(auth, "username"),
                password: text_of(auth, "password"),
                token_url: text_of(auth, "tokenUrl"),
                form: pairs_of(auth, "form"),
                token_path: text_of(auth, "tokenPath"),
                expiry_path: text_of(auth, "expiryPath"),
            },
            put,
            get,
            drop,
            list,
            retry: Retry {
                status: numbers_of(retry, "status"),
                reason: text_of(retry, "rateReason"),
            },
            token: Mutex::new(Token::default()),
        })
    }

    fn stored(&self, name: &str) -> String {
        if self.flatten {
            flatten(name)
        } else {
            name.to_owned()
        }
    }

    fn base(&self) -> Vars {
        Vars::new(&self.folder, &self.secrets)
    }

    /// The answer's status against the config's list, and the `403` whose body says the reason the config named.
    fn retryable(&self, status: u16, payload: &[u8]) -> bool {
        if self.retry.status.contains(&u32::from(status)) {
            return true;
        }
        if status != 403 || self.retry.reason.is_empty() {
            return false;
        }
        let Ok(answer) = crate::json::parse(&String::from_utf8_lossy(payload)) else {
            return false;
        };
        answer
            .get(&self.retry.reason)
            .and_then(Json::as_str)
            .is_some_and(|reason| !reason.is_empty())
    }

    fn access(&self, vars: &mut Vars) -> io::Result<String> {
        let now = Instant::now();
        if let Some(found) = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fresh(now)
            .map(str::to_owned)
        {
            return Ok(found);
        }
        let mut form = String::new();
        for (index, (key, value)) in self.auth.form.iter().enumerate() {
            if index > 0 {
                form.push('&');
            }
            let _ = write!(form, "{key}={}", vars.sub(value));
        }
        let (status, payload) = self.http.ask(
            "POST",
            &self.auth.token_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(form.as_bytes()),
            Some(TOKEN_CAP),
        )?;
        if status != 200 {
            return Err(carrier_error(format!(
                "the token endpoint answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the token answer is not json: {why}")))?;
        let path = if self.auth.token_path.is_empty() {
            "access_token"
        } else {
            &self.auth.token_path
        };
        let value = walk(&answer, path)
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| carrier_error(format!("the token answer has no token at {path}")))?
            .to_owned();
        let life = (!self.auth.expiry_path.is_empty())
            .then(|| walk(&answer, &self.auth.expiry_path).and_then(Json::as_u32))
            .flatten()
            .filter(|seconds| *seconds > 0)
            .map_or(TOKEN_LIFE, |seconds| {
                Duration::from_secs(u64::from(seconds))
            });
        let mut token = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        token.set(value.clone(), life);
        Ok(value)
    }

    /// The headers the credential needs, with the `oauth2` token put where its template can reach it.
    fn headers(&self, vars: &mut Vars) -> io::Result<Vec<(String, String)>> {
        match self.auth.kind.as_str() {
            "" | "none" => Ok(Vec::new()),
            "static" => Ok(self
                .auth
                .headers
                .iter()
                .map(|(key, value)| (key.clone(), vars.sub(value)))
                .collect()),
            "oauth2" => {
                let token = self.access(vars)?;
                vars.set("token", token);
                Ok(self
                    .auth
                    .headers
                    .iter()
                    .map(|(key, value)| (key.clone(), vars.sub(value)))
                    .collect())
            }
            "basic" => {
                let pair = format!(
                    "{}:{}",
                    vars.sub(&self.auth.username),
                    vars.sub(&self.auth.password)
                );
                Ok(vec![(
                    "Authorization".to_owned(),
                    format!("Basic {}", ferrox_core::b64::encode(pair.as_bytes())),
                )])
            }
            other => Err(carrier_error(format!("unsupported auth type: {other}"))),
        }
    }

    fn do_op(&self, op: &Op, vars: &mut Vars, body: Option<&[u8]>) -> io::Result<(u16, Vec<u8>)> {
        let method = if op.method.is_empty() {
            "GET"
        } else {
            &op.method
        };
        retried(|| {
            let mut slots = vars.clone();
            let mut owned: Vec<(String, String)> = if op.presigned {
                Vec::new()
            } else {
                match self.headers(&mut slots) {
                    Ok(headers) => headers,
                    Err(why) => return Control::Again(why.to_string()),
                }
            };
            owned.extend(
                op.headers
                    .iter()
                    .map(|(key, value)| (key.clone(), slots.sub(value))),
            );
            let url = if op.presigned {
                op.url.clone()
            } else {
                slots.sub(&op.url)
            };
            let sent: Vec<(&str, &str)> = owned
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            let answer = self.http.ask(method, &url, &sent, body, None);
            let (status, payload) = match answer {
                Ok(answer) => answer,
                Err(why) => return Control::Again(format!("request failed: {why}")),
            };
            if status == 401 && self.auth.kind == "oauth2" && !op.presigned {
                self.token
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .value
                    .clear();
                return Control::Again("the service rejected the token".to_owned());
            }
            if self.retryable(status, &payload) {
                return Control::Again(format!("the service answered {status}"));
            }
            Control::Done(Ok((status, payload)))
        })
    }

    /// One operation, following the href a two-step service answers on the first leg.
    fn run(&self, op: &Op, vars: &mut Vars, body: Option<&[u8]>) -> io::Result<(u16, Vec<u8>)> {
        if op.href_path.is_empty() {
            return self.do_op(op, vars, body);
        }
        let (status, payload) = self.do_op(op, vars, None)?;
        if !(200..300).contains(&status) {
            return Ok((status, payload));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the href answer is not json: {why}")))?;
        let href = walk(&answer, &op.href_path)
            .and_then(Json::as_str)
            .filter(|href| !href.is_empty())
            .ok_or_else(|| {
                carrier_error(format!("the response has no href at {}", op.href_path))
            })?;
        let follow = Op {
            method: op.href_method.clone(),
            url: href.to_owned(),
            headers: Vec::new(),
            body: String::new(),
            names: String::new(),
            href_path: String::new(),
            href_method: String::new(),
            presigned: true,
        };
        self.do_op(&follow, vars, body)
    }
}

impl Storage for Template {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let mut vars = self.base();
        vars.set("name", self.stored(name));
        let encoded: Vec<u8>;
        let payload: Option<&[u8]> = if self.put.body.is_empty() {
            (!data.is_empty()).then_some(data)
        } else {
            vars.set("data", ferrox_core::b64::encode(data));
            encoded = vars.sub(&self.put.body).into_bytes();
            Some(&encoded)
        };
        let (status, payload) = self.run(&self.put, &mut vars, payload)?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        Err(carrier_error(format!(
            "put of {name} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut vars = self.base();
        vars.set("name", self.stored(name));
        let (status, payload) = self.run(&self.get, &mut vars, None)?;
        if (200..300).contains(&status) {
            return Ok(payload);
        }
        if status == 404 {
            return Err(io::Error::from(ErrorKind::NotFound));
        }
        Err(carrier_error(format!(
            "get of {name} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let mut vars = self.base();
        vars.set("name", self.stored(name));
        let (status, payload) = self.run(&self.drop, &mut vars, None)?;
        if status == 404 || (200..300).contains(&status) {
            return Ok(());
        }
        Err(carrier_error(format!(
            "delete of {name} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let mut vars = self.base();
        let flat = self.stored(prefix);
        vars.set("prefix", flat.clone());
        let (status, payload) = self.run(&self.list, &mut vars, None)?;
        if status == 404 {
            return Ok(Vec::new());
        }
        if !(200..300).contains(&status) {
            return Err(carrier_error(format!(
                "list of {prefix} answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let text = String::from_utf8_lossy(&payload);
        if !self.flatten {
            return Ok(self
                .names
                .captures_iter(text.as_ref())
                .filter_map(|found| {
                    found.get(1).map(|at| Entry {
                        name: at.as_str().to_owned(),
                        inline: None,
                    })
                })
                .collect());
        }
        let mut out = Vec::new();
        let want = format!("{flat}{FLAT_SEP}");
        let mut seen: HashSet<String> = HashSet::new();
        for found in self.names.captures_iter(text.as_ref()) {
            let Some(at) = found.get(1).map(|at| at.as_str()) else {
                continue;
            };
            let Some(name) = under(at, &want) else {
                continue;
            };
            let step = first_step(name).to_owned();
            if seen.insert(step.clone()) {
                out.push(Entry {
                    name: step,
                    inline: None,
                });
            }
        }
        Ok(out)
    }
}

/// A file a Drive listing named, with the payload it carried alongside when the object was small enough to ride in the description.
struct Found {
    id: String,
    description: Option<Vec<u8>>,
}

/// S3 as an object store: every name is a key under the configured folder, signed with `SigV4` and listed a page at a time.
pub(crate) struct S3 {
    http: Arc<Http>,
    scheme: &'static str,
    authority: String,
    base_path: String,
    prefix: String,
    region: String,
    access: String,
    secret: String,
    token: String,
}

impl S3 {
    fn build(settings: &Settings, http: Arc<Http>) -> io::Result<Self> {
        let s3 = settings
            .s3
            .as_ref()
            .ok_or_else(|| carrier_error(r#"service "s3" needs an "s3" object"#))?;
        validate_s3(
            &s3.endpoint,
            &s3.region,
            &s3.bucket,
            s3.path_style,
            &settings.remote_folder,
        )?;
        if !(2..=3).contains(&settings.secrets.len())
            || settings.secrets[0].is_empty()
            || settings.secrets[1].is_empty()
        {
            return Err(carrier_error(
                "S3 needs AccessKeyID, SecretAccessKey and optionally SessionToken in secrets",
            ));
        }
        for secret in &settings.secrets {
            if !header_value(secret) {
                return Err(carrier_error("invalid S3 secret"));
            }
        }
        if settings.secrets[0].contains(['/', ',', ' ', '\t']) {
            return Err(carrier_error("invalid S3 AccessKeyID"));
        }
        let target = Target::parse(&s3.endpoint)
            .ok_or_else(|| carrier_error("S3 endpoint must be an http(s) URL"))?;
        let mut base_path = escape_endpoint_path(&target.path);
        if !base_path.ends_with('/') {
            base_path.push('/');
        }
        let (authority, path) = if s3.path_style {
            let path = format!("{base_path}{}/", s3_escape(&s3.bucket));
            (target.authority(), path)
        } else {
            let host = format!("{}.{}", s3.bucket, target.host);
            let authority = if target.named_port {
                format!("{host}:{}", target.port)
            } else {
                host
            };
            (authority, base_path)
        };
        Ok(Self {
            http,
            scheme: if target.secure { "https" } else { "http" },
            authority,
            base_path: path,
            prefix: format!(
                "{}/",
                settings
                    .remote_folder
                    .strip_suffix('/')
                    .unwrap_or(&settings.remote_folder)
            ),
            region: if s3.region.is_empty() {
                "us-east-1".to_owned()
            } else {
                s3.region.clone()
            },
            access: settings.secrets[0].clone(),
            secret: settings.secrets[1].clone(),
            token: settings.secrets.get(2).cloned().unwrap_or_default(),
        })
    }

    fn key(&self, name: &str) -> io::Result<String> {
        if !valid_s3_name(name) {
            return Err(carrier_error("invalid relative S3 object name"));
        }
        let key = format!("{}{name}", self.prefix);
        if key.len() > 1024 {
            return Err(carrier_error("S3 object key exceeds 1024 bytes"));
        }
        Ok(key)
    }

    fn target(&self, key: &str, query: &str) -> (String, String) {
        let path = format!("{}{}", self.base_path, s3_escape(key));
        let mut url = format!("{}://{}{}", self.scheme, self.authority, path);
        if !query.is_empty() {
            let _ = write!(url, "?{query}");
        }
        (url, path)
    }

    fn sign(
        &self,
        method: &str,
        path: &str,
        query: &str,
        content_type: Option<&str>,
        payload_hash: &str,
        headers: &mut Vec<(String, String)>,
    ) {
        let (stamp, date) = utc_stamp();
        headers.push(("X-Amz-Date".to_owned(), stamp.clone()));
        headers.push(("X-Amz-Content-Sha256".to_owned(), payload_hash.to_owned()));
        let mut signed = String::new();
        let mut canonical_headers = String::new();
        if let Some(content_type) = content_type {
            headers.push(("Content-Type".to_owned(), content_type.to_owned()));
            canonical_headers.push_str("content-type:");
            canonical_headers.push_str(content_type);
            canonical_headers.push('\n');
            signed.push_str("content-type;");
        }
        canonical_headers.push_str("host:");
        canonical_headers.push_str(&self.authority);
        canonical_headers.push_str("\nx-amz-content-sha256:");
        canonical_headers.push_str(payload_hash);
        canonical_headers.push_str("\nx-amz-date:");
        canonical_headers.push_str(&stamp);
        canonical_headers.push('\n');
        signed.push_str("host;x-amz-content-sha256;x-amz-date");
        if !self.token.is_empty() {
            let token = self.token.split_whitespace().collect::<Vec<_>>().join(" ");
            headers.push(("X-Amz-Security-Token".to_owned(), self.token.clone()));
            canonical_headers.push_str("x-amz-security-token:");
            canonical_headers.push_str(&token);
            canonical_headers.push('\n');
            signed.push_str(";x-amz-security-token");
        }
        let canonical =
            format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}");
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            sha_hex(canonical.as_bytes())
        );
        let mut key = hmac(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes());
        key = hmac(&key, self.region.as_bytes());
        key = hmac(&key, b"s3");
        key = hmac(&key, b"aws4_request");
        headers.push((
            "Authorization".to_owned(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
                self.access,
                ferrox_core::foxy::account::hex_encode(&hmac(&key, to_sign.as_bytes()))
            ),
        ));
    }

    /// One request through the retry ladder: a fresh signature each try, a retryable answer worth another, and a body read before the slot is released.
    fn ask(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<&[u8]>,
    ) -> io::Result<(u16, Vec<u8>)> {
        let payload_hash = sha_hex(body.unwrap_or_default());
        let content_type = (method == "PUT").then_some("application/octet-stream");
        retried(|| {
            let (url, path) = self.target(key, query);
            let mut owned = Vec::new();
            self.sign(
                method,
                &path,
                query,
                content_type,
                &payload_hash,
                &mut owned,
            );
            let sent: Vec<(&str, &str)> = owned
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            match self
                .http
                .ask(method, &url, &sent, body, Some(MAX_SEGMENT_BYTES))
            {
                Ok((status, payload)) if retryable_status(status) => Control::Again(format!(
                    "S3 {method} answered {status}: {}",
                    String::from_utf8_lossy(&payload)
                )),
                Ok(answer) => Control::Done(Ok(answer)),
                Err(why) => Control::Again(format!("S3 request failed: {why}")),
            }
        })
    }

    fn delete_object(&self, key: &str) -> io::Result<()> {
        let (status, payload) = self.ask("DELETE", key, "", None)?;
        if matches!(status, 200 | 204) || s3_missing(status, &payload) {
            return Ok(());
        }
        Err(s3_response_error("DELETE", status, &payload))
    }

    fn pages(
        &self,
        prefix: &str,
        delimiter: &str,
        mut visit: impl FnMut(&S3Page) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut pairs = vec![("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")];
        if !delimiter.is_empty() {
            pairs.push(("delimiter", delimiter));
        }
        let mut query = s3_query(&pairs);
        let mut seen = HashSet::new();
        loop {
            let (status, payload) = self.ask("GET", "", &query, None)?;
            if status != 200 {
                return Err(s3_response_error("LIST", status, &payload));
            }
            let page =
                S3Page::parse(&payload).ok_or_else(|| carrier_error("invalid S3 list response"))?;
            for key in &page.keys {
                if !key.starts_with(prefix) {
                    return Err(carrier_error(
                        "S3 returned an object outside the requested prefix",
                    ));
                }
            }
            for prefix_len in &page.prefixes {
                if !prefix_len.starts_with(prefix) {
                    return Err(carrier_error(
                        "S3 returned a directory outside the requested prefix",
                    ));
                }
            }
            if page.truncated && (page.next.is_empty() || !seen.insert(page.next.clone())) {
                return Err(carrier_error("S3 list pagination did not advance"));
            }
            visit(&page)?;
            if !page.truncated {
                return Ok(());
            }
            let mut pairs = vec![("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")];
            if !delimiter.is_empty() {
                pairs.push(("delimiter", delimiter));
            }
            pairs.push(("continuation-token", &page.next));
            query = s3_query(&pairs);
        }
    }
}

impl Storage for S3 {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let key = self.key(name)?;
        let (status, payload) = self.ask("PUT", &key, "", Some(data))?;
        if status == 200 {
            return Ok(());
        }
        Err(s3_response_error("PUT", status, &payload))
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let key = self.key(name)?;
        let (status, payload) = self.ask("GET", &key, "", None)?;
        if s3_missing(status, &payload) {
            return Err(io::Error::from(ErrorKind::NotFound));
        }
        if status == 200 {
            return Ok(payload);
        }
        Err(s3_response_error("GET", status, &payload))
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let key = self.key(name)?;
        self.delete_object(&key)?;
        let prefix = format!("{key}/");
        self.pages(&prefix, "", |page| {
            for item in &page.keys {
                self.delete_object(item)?;
            }
            Ok(())
        })
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let key = format!("{}/", self.key(prefix)?);
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        self.pages(&key, "/", |page| {
            for full in page.keys.iter().chain(&page.prefixes) {
                let rest = full.strip_prefix(key.as_str()).unwrap_or(full);
                let name = rest.split('/').next().unwrap_or(rest);
                if !name.is_empty() && valid_s3_name(name) && seen.insert(name.to_owned()) {
                    entries.push(Entry {
                        name: name.to_owned(),
                        inline: None,
                    });
                }
            }
            Ok(())
        })?;
        Ok(entries)
    }
}

/// One listing page: the keys under the prefix, the directories at the delimiter, and the token that reaches the next page.
struct S3Page {
    truncated: bool,
    next: String,
    keys: Vec<String>,
    prefixes: Vec<String>,
}

impl S3Page {
    fn parse(payload: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(payload).ok()?;
        let root = xml_values(text, "ListBucketResult")?.into_iter().next()?;
        let mut keys = Vec::new();
        for item in xml_values(root, "Contents")? {
            keys.push(xml_text(item, "Key")?);
        }
        let mut prefixes = Vec::new();
        for item in xml_values(root, "CommonPrefixes")? {
            prefixes.push(xml_text(item, "Prefix")?);
        }
        Some(Self {
            truncated: xml_text(root, "IsTruncated")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            next: xml_text(root, "NextContinuationToken").unwrap_or_default(),
            keys,
            prefixes,
        })
    }
}

/// The raw inner text of every `<tag>` element, left encoded so a container keeps its child markup for the next parse.
fn xml_values<'a>(text: &'a str, tag: &str) -> Option<Vec<&'a str>> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(offset) = text[at..].find(&open) {
        let start = at + offset;
        let after = &text[start + open.len()..];
        if !after
            .chars()
            .next()
            .is_some_and(|byte| byte == '>' || byte.is_ascii_whitespace())
        {
            at = start + open.len();
            continue;
        }
        let body = start + open.len() + after.find('>')? + 1;
        let end = text[body..].find(&close)?;
        found.push(&text[body..body + end]);
        at = body + end + close.len();
    }
    Some(found)
}

/// The decoded text of the first `<tag>` element, which is the only place an `&amp;` in a key is decoded.
fn xml_text(text: &str, tag: &str) -> Option<String> {
    xml_values(text, tag)?.into_iter().next().map(xml_decode)
}

fn xml_decode(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(amp) = text[at..].find('&') {
        let amp = at + amp;
        out.push_str(&text[at..amp]);
        let Some(end) = text[amp..].find(';') else {
            out.push_str(&text[amp..]);
            return out;
        };
        let end = amp + end;
        let entity = &text[amp + 1..end];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let code = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()));
                match code.and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => out.push_str(&text[amp..=end]),
                }
            }
        }
        at = end + 1;
    }
    out.push_str(&text[at..]);
    out
}

fn s3_error_code(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    xml_text(text, "Code")
}

fn s3_missing(status: u16, payload: &[u8]) -> bool {
    status == 404
        && matches!(
            s3_error_code(payload).as_deref(),
            Some("NoSuchKey" | "NotFound")
        )
}

fn s3_response_error(method: &str, status: u16, payload: &[u8]) -> io::Error {
    match s3_error_code(payload) {
        Some(code) => carrier_error(format!("S3 {method} answered {status} ({code:?})")),
        None => carrier_error(format!("S3 {method} answered {status}")),
    }
}

fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

fn header_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
}

fn valid_s3_name(name: &str) -> bool {
    if name
        .chars()
        .any(|ch| ch < '\u{20}' || ch == '\u{7f}' || ch == '\\')
    {
        return false;
    }
    name.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn validate_s3(
    endpoint: &str,
    region: &str,
    bucket: &str,
    path_style: bool,
    folder: &str,
) -> io::Result<()> {
    let target = Target::parse(endpoint)
        .filter(|_| !endpoint.contains(['?', '#']) && !endpoint_has_user(endpoint))
        .ok_or_else(|| {
            carrier_error(
                "S3 endpoint must be an http(s) URL without credentials, query or fragment",
            )
        })?;
    if !header_value(region) || region.contains(['/', ',', ' ', '\t']) {
        return Err(carrier_error("invalid S3 signing region"));
    }
    if !valid_s3_name(bucket) || bucket.contains('/') {
        return Err(carrier_error(
            "S3 needs a bucket name without path separators",
        ));
    }
    if !path_style {
        if target.host.parse::<std::net::IpAddr>().is_ok() {
            return Err(carrier_error(
                "S3 virtual-hosted addressing requires a DNS endpoint",
            ));
        }
        if !bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        }) || bucket.contains("..")
            || bucket.starts_with('.')
            || bucket.ends_with('.')
        {
            return Err(carrier_error(
                "S3 virtual-hosted addressing requires a DNS-compatible bucket name",
            ));
        }
    }
    if !valid_s3_name(folder.strip_suffix('/').unwrap_or(folder)) {
        return Err(carrier_error(
            "S3 remoteFolder must be a nonempty relative prefix without empty, '.' or '..' components",
        ));
    }
    Ok(())
}

fn endpoint_has_user(endpoint: &str) -> bool {
    endpoint
        .split_once("://")
        .map(|(_, rest)| rest.split('/').next().unwrap_or(rest))
        .is_some_and(|authority| authority.contains('@'))
}

fn escape_endpoint_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        out.push_str(&s3_escape_bytes(&percent_decode(segment), true));
    }
    out
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_digit(bytes[at + 1]), hex_digit(bytes[at + 2])) {
                out.push(high << 4 | low);
                at += 3;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    out
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn s3_escape(value: &str) -> String {
    s3_escape_with(value, false)
}

fn s3_escape_with(value: &str, slash: bool) -> String {
    s3_escape_bytes(value.as_bytes(), slash)
}

fn s3_escape_bytes(value: &[u8], slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (byte == b'/' && !slash)
        {
            out.push(byte as char);
        } else {
            pct(&mut out, byte);
        }
    }
    out
}

fn s3_query(pairs: &[(&str, &str)]) -> String {
    query(pairs).replace('+', "%20")
}

fn sha_hex(data: &[u8]) -> String {
    ferrox_core::foxy::account::hex_encode(&sha2::Sha256::digest(data))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::hmac::sign(&key, data).as_ref());
    out
}

fn utc_stamp() -> (String, String) {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or_default();
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    (
        format!(
            "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        ),
        format!("{year:04}{month:02}{day:02}"),
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

/// Google Drive as an object store: a name becomes a file id, a small object rides base64 in the file's description, and a larger one its media.
pub(crate) struct Drive {
    http: Arc<Http>,
    folder: String,
    client_id: String,
    client_secret: String,
    refresh: String,
    token_url: String,
    files_url: String,
    upload_url: String,
    token: Mutex<Token>,
    ids: Mutex<HashMap<String, String>>,
}

impl Drive {
    fn build(settings: &Settings, http: Arc<Http>) -> io::Result<Self> {
        let [client_id, client_secret, refresh] = settings.secrets.as_slice() else {
            return Err(carrier_error(
                "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken",
            ));
        };
        if client_id.is_empty() || client_secret.is_empty() || refresh.is_empty() {
            return Err(carrier_error("a Google Drive secret is empty"));
        }
        Ok(Self {
            http,
            folder: settings.remote_folder.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            refresh: refresh.clone(),
            token_url: DRIVE_TOKEN_URL.to_owned(),
            files_url: DRIVE_FILES_URL.to_owned(),
            upload_url: DRIVE_UPLOAD_URL.to_owned(),
            token: Mutex::new(Token::default()),
            ids: Mutex::new(HashMap::new()),
        })
    }

    fn access(&self) -> io::Result<String> {
        let now = Instant::now();
        if let Some(found) = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fresh(now)
            .map(str::to_owned)
        {
            return Ok(found);
        }
        let form = query(&[
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("grant_type", "refresh_token"),
            ("refresh_token", &self.refresh),
        ]);
        let (status, payload) = self.http.ask(
            "POST",
            &self.token_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(form.as_bytes()),
            Some(TOKEN_CAP),
        )?;
        if status != 200 {
            return Err(carrier_error(format!(
                "the token endpoint answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the token answer is not json: {why}")))?;
        let value = answer
            .get("access_token")
            .and_then(Json::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| carrier_error("the token endpoint returned no access token"))?
            .to_owned();
        let life = answer
            .get("expires_in")
            .and_then(Json::as_u32)
            .map_or(Duration::ZERO, |seconds| {
                Duration::from_secs(u64::from(seconds))
            });
        let mut token = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        token.set(value.clone(), life);
        Ok(value)
    }

    fn forget(&self, name: &str) {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
    }

    fn remember(&self, name: &str, id: &str) {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), id.to_owned());
    }

    fn cached(&self, name: &str) -> Option<String> {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    /// The `403` that is a rate limit rather than a refusal, which is the one a retry can outlast.
    fn rate_limited(payload: &[u8]) -> bool {
        let Ok(answer) = crate::json::parse(&String::from_utf8_lossy(payload)) else {
            return false;
        };
        let Some(error) = answer.get("error") else {
            return false;
        };
        if error
            .get("errors")
            .and_then(Json::as_arr)
            .unwrap_or(&[])
            .iter()
            .filter_map(|item| item.get("reason").and_then(Json::as_str))
            .any(|reason| {
                matches!(
                    reason,
                    "rateLimitExceeded" | "userRateLimitExceeded" | "sharingRateLimitExceeded"
                )
            })
        {
            return true;
        }
        error
            .get("status")
            .and_then(Json::as_str)
            .is_some_and(|status| status == "RESOURCE_EXHAUSTED")
    }

    fn ask(
        &self,
        method: &str,
        target: &str,
        content: &str,
        body: Option<&[u8]>,
    ) -> io::Result<(u16, Vec<u8>)> {
        retried(|| {
            let token = match self.access() {
                Ok(token) => token,
                Err(why) => return Control::Again(why.to_string()),
            };
            let headers = [("Authorization", format!("Bearer {token}"))];
            let mut sent: Vec<(&str, &str)> = headers
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect();
            if !content.is_empty() {
                sent.push(("Content-Type", content));
            }
            let answer = self.http.ask(method, target, &sent, body, None);
            let (status, payload) = match answer {
                Ok(answer) => answer,
                Err(why) => return Control::Again(format!("Drive request failed: {why}")),
            };
            if status == 401 {
                self.token
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .value
                    .clear();
                return Control::Again("Drive rejected the access token".to_owned());
            }
            if status == 403 && Self::rate_limited(&payload) {
                return Control::Again(format!(
                    "Drive is rate limiting: {}",
                    String::from_utf8_lossy(&payload)
                ));
            }
            if matches!(status, 429 | 500 | 502 | 503 | 504) {
                return Control::Again(format!(
                    "Drive answered {status}: {}",
                    String::from_utf8_lossy(&payload)
                ));
            }
            Control::Done(Ok((status, payload)))
        })
    }

    /// One page of a Drive listing, and every page after it, keeping the last answer for a name as the reference does.
    fn query(&self, condition: &str) -> io::Result<HashMap<String, Found>> {
        let mut found: HashMap<String, Found> = HashMap::new();
        let mut page = String::new();
        loop {
            let mut pairs = vec![
                (
                    "fields",
                    "nextPageToken,files(id,name,description)".to_owned(),
                ),
                ("includeItemsFromAllDrives", "true".to_owned()),
                ("pageSize", DRIVE_PAGE_SIZE.to_string()),
                (
                    "q",
                    format!(
                        "'{}' in parents and trashed = false and {condition}",
                        quoted(&self.folder)
                    ),
                ),
                ("supportsAllDrives", "true".to_owned()),
            ];
            if !page.is_empty() {
                pairs.push(("pageToken", page.clone()));
            }
            let owned: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect();
            let target = format!("{}?{}", self.files_url, query(&owned));
            let (status, payload) = self.ask("GET", &target, "", None)?;
            if status != 200 {
                return Err(carrier_error(format!(
                    "Drive listing answered {status}: {}",
                    String::from_utf8_lossy(&payload)
                )));
            }
            let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
                .map_err(|why| carrier_error(format!("the Drive listing is not json: {why}")))?;
            for file in answer.get("files").and_then(Json::as_arr).unwrap_or(&[]) {
                let name = file.get("name").and_then(Json::as_str).unwrap_or("");
                let id = file.get("id").and_then(Json::as_str).unwrap_or("");
                if name.is_empty() || id.is_empty() {
                    continue;
                }
                let description = file
                    .get("description")
                    .and_then(Json::as_str)
                    .filter(|text| !text.is_empty())
                    .and_then(|text| ferrox_core::b64::decode(text.as_bytes()));
                self.remember(name, id);
                found.insert(
                    name.to_owned(),
                    Found {
                        id: id.to_owned(),
                        description,
                    },
                );
            }
            let next = answer
                .get("nextPageToken")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned();
            if next.is_empty() {
                return Ok(found);
            }
            page = next;
        }
    }

    fn resolve(&self, flat: &str) -> io::Result<String> {
        if let Some(id) = self.cached(flat) {
            return Ok(id);
        }
        let found = self.query(&format!("name = '{}'", quoted(flat)))?;
        found
            .get(flat)
            .map(|file| file.id.clone())
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))
    }

    /// The object as Drive stores it: small enough it rides base64 in the metadata, otherwise the metadata and the payload go out as one multipart body.
    fn write(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let flat = flatten(name);
        let inline = data.len() <= DRIVE_INLINE_LIMIT;
        // The keys in the order the reference's map marshaller writes them, so the metadata body is byte for byte the same.
        let mut pairs = Vec::with_capacity(3);
        if inline {
            pairs.push((
                "description".to_owned(),
                Json::Str(ferrox_core::b64::encode(data)),
            ));
        }
        pairs.push(("name".to_owned(), Json::Str(flat.clone())));
        pairs.push((
            "parents".to_owned(),
            Json::Arr(vec![Json::Str(self.folder.clone())]),
        ));
        let mut text = String::new();
        crate::json::write(&Json::Obj(pairs), &mut text);
        let (target, content, body) = if inline {
            (
                format!("{}?fields=id", self.files_url),
                "application/json; charset=UTF-8".to_owned(),
                text.into_bytes(),
            )
        } else {
            let mut body = Vec::with_capacity(text.len() + data.len() + 128);
            let _ = write!(
                body,
                "--{DRIVE_BOUNDARY}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
            );
            body.extend_from_slice(text.as_bytes());
            let _ = write!(
                body,
                "\r\n--{DRIVE_BOUNDARY}\r\nContent-Type: application/octet-stream\r\n\r\n"
            );
            body.extend_from_slice(data);
            let _ = write!(body, "\r\n--{DRIVE_BOUNDARY}--\r\n");
            (
                self.upload_url.clone(),
                format!("multipart/related; boundary={DRIVE_BOUNDARY}"),
                body,
            )
        };
        let (status, payload) = self.ask("POST", &target, &content, Some(&body))?;
        if status != 200 {
            return Err(carrier_error(format!(
                "Drive upload of {name} answered {status}: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the Drive upload answer is not json: {why}")))?;
        if let Some(id) = answer
            .get("id")
            .and_then(Json::as_str)
            .filter(|id| !id.is_empty())
        {
            self.remember(&flat, id);
        }
        Ok(())
    }

    fn remove(&self, flat: &str, id: &str) -> io::Result<()> {
        let target = format!(
            "{}/{id}?supportsAllDrives=true",
            self.files_url,
            id = path_escape(id)
        );
        let (status, payload) = self.ask("DELETE", &target, "", None)?;
        self.forget(flat);
        if matches!(status, 200 | 204 | 404) {
            return Ok(());
        }
        Err(carrier_error(format!(
            "Drive deletion of {flat} answered {status}: {}",
            String::from_utf8_lossy(&payload)
        )))
    }

    /// The base64 a small object rode in, which is what a `0`-length media read means.
    fn inline(&self, id: &str) -> io::Result<Vec<u8>> {
        let target = format!(
            "{}/{id}?fields=description&supportsAllDrives=true",
            self.files_url,
            id = path_escape(id)
        );
        let (status, payload) = self.ask("GET", &target, "", None)?;
        if status != 200 {
            return Err(carrier_error(format!(
                "Drive answered {status} for inline data: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let answer = crate::json::parse(&String::from_utf8_lossy(&payload))
            .map_err(|why| carrier_error(format!("the inline data is not json: {why}")))?;
        let description = answer
            .get("description")
            .and_then(Json::as_str)
            .unwrap_or("");
        if description.is_empty() {
            return Ok(Vec::new());
        }
        ferrox_core::b64::decode(description.as_bytes())
            .ok_or_else(|| carrier_error("the inline data is not valid base64"))
    }
}

/// The way a path segment quotes an id: every byte outside the unreserved set, uppercase.
fn path_escape(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for byte in id.as_bytes() {
        if reserved(*byte) {
            pct(&mut out, *byte);
        } else {
            out.push(*byte as char);
        }
    }
    out
}

impl Storage for Drive {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        self.write(name, data)
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let flat = flatten(name);
        let id = self.resolve(&flat)?;
        let target = format!(
            "{}/{id}?alt=media&supportsAllDrives=true",
            self.files_url,
            id = path_escape(&id)
        );
        let (status, payload) = self.ask("GET", &target, "", None)?;
        match status {
            200 if !payload.is_empty() => Ok(payload),
            200 => self.inline(&id),
            404 => {
                self.forget(&flat);
                Err(io::Error::from(ErrorKind::NotFound))
            }
            other => Err(carrier_error(format!(
                "Drive download of {name} answered {other}: {}",
                String::from_utf8_lossy(&payload)
            ))),
        }
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let flat = flatten(name);
        match self.resolve(&flat) {
            Ok(id) => self.remove(&flat, &id)?,
            Err(why) if why.kind() == ErrorKind::NotFound => {}
            Err(why) => return Err(why),
        }
        let children = self.query(&format!(
            "name contains '{}'",
            quoted(&format!("{flat}{FLAT_SEP}"))
        ))?;
        for (child, file) in children {
            self.remove(&child, &file.id)?;
        }
        Ok(())
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let flat = format!("{}{FLAT_SEP}", flatten(prefix));
        let found = self.query(&format!("name contains '{}'", quoted(&flat)))?;
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for (name, file) in found {
            let Some(rest) = under(&name, &flat) else {
                continue;
            };
            let direct = !rest.contains(FLAT_SEP);
            let step = first_step(rest).to_owned();
            if !seen.insert(step.clone()) {
                continue;
            }
            out.push(Entry {
                inline: direct.then_some(file.description).flatten(),
                name: step,
            });
        }
        Ok(out)
    }
}

/// One store per folder, shared by every session that names it: a token cache and a file-id map are worth one per service, not one per stream.
static SHARED: LazyLock<Mutex<HashMap<String, Arc<dyn Storage>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The identity of one service's store, the way the reference keys it: the service, the folder, every secret, the transport's security, and the address it fronts through.
fn share_key(settings: &Settings, front: Option<(&str, u16)>) -> String {
    use sha2::Digest as _;
    let mut joined = vec![settings.service.clone(), settings.remote_folder.clone()];
    if let Some(s3) = &settings.s3 {
        joined.push(s3.endpoint.clone());
        joined.push(if s3.region.is_empty() {
            "us-east-1".to_owned()
        } else {
            s3.region.clone()
        });
        joined.push(s3.bucket.clone());
        joined.push(if s3.path_style {
            "path-style".to_owned()
        } else {
            "virtual-hosted-style".to_owned()
        });
    }
    joined.extend_from_slice(&settings.secrets);
    joined.push(settings.security.clone());
    if let Some(reality) = &settings.reality {
        joined.push("reality".to_owned());
        joined.push(reality.server_name.clone());
        joined.push(ferrox_core::foxy::account::hex_encode(&reality.public_key));
        joined.push(ferrox_core::foxy::account::hex_encode(&reality.short_id));
        joined.push(reality.fingerprint.clone());
        joined.push(if settings.reality_named {
            "named".to_owned()
        } else {
            "lane-host".to_owned()
        });
    }
    if let Some((host, port)) = front {
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        joined.push(if port == 0 {
            format!("tcp:{host}")
        } else {
            format!("tcp:{host}:{port}")
        });
    }
    joined.push(settings.template_text());
    let digest = sha2::Sha256::digest(joined.join("\0").as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The store the settings name, or the one an earlier session with the same settings already opened.
fn shared(
    settings: &Settings,
    front: Option<(&str, u16)>,
    cap: usize,
    build: impl FnOnce(&Settings, Arc<Http>) -> io::Result<Arc<dyn Storage>>,
) -> io::Result<Arc<dyn Storage>> {
    let key = share_key(settings, front);
    let mut pool = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(found) = pool.get(&key) {
        return Ok(Arc::clone(found));
    }
    let http = Http::new(
        settings.tls.clone(),
        settings.reality.clone(),
        settings.reality_named,
        front.map(|(host, port)| (host.to_owned(), port)),
        cap,
    );
    let made = build(settings, http)?;
    pool.insert(key, Arc::clone(&made));
    Ok(made)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder of its own per test, named with the process and the clock so two parallel runs never share one.
    fn scratch(tag: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ferrox-xdrive-{tag}-{}-{stamp}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    /// The store of a folder that test owns.
    fn local(tag: &str) -> (PathBuf, Arc<dyn Storage>) {
        let dir = scratch(tag);
        let text = dir.to_str().expect("utf-8 folder").to_owned();
        (dir, Arc::new(Local::new(&text).expect("opens")))
    }

    /// Budgets tuned for a test: a segment small enough to cut twice in one write, a poll small enough to finish long before the deadline.
    fn quick() -> Params {
        Params {
            segment_bytes: 512,
            flush: Duration::from_millis(2),
            min_poll: Duration::from_millis(2),
            max_poll: Duration::from_millis(8),
            eager: Duration::from_secs(1),
            hole: Duration::from_secs(30),
            ttl: Duration::from_secs(60),
            concurrency: 4,
        }
    }

    /// Read until `want` bytes arrive or the deadline passes, so a parked carrier fails the test instead of the run.
    fn read_up_to(stream: &mut Conn, want: usize, budget: Duration) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buf = vec![0u8; 1024];
        let until = Instant::now() + budget;
        while got.len() < want && Instant::now() < until {
            match stream.read(&mut buf) {
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        got
    }

    /// The head's names and values are read where they lie: a reply with headers the
    /// service does not read costs no buffer for them.
    #[test]
    fn a_reply_head_costs_no_buffer_for_its_headers() {
        let origin = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = origin.local_addr().expect("addr").port();
        let (done, wait) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = origin.accept().expect("accepts");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\nX-Extra-One: a\r\nX-Extra-Two: b\r\nX-Extra-Three: c\r\n\r\n")
                .expect("answers");
            stream.flush().expect("flushes");
            let _ = wait.recv();
        });
        let mut lane = Lane::new(Kind::Plain(
            Connection::connect(("127.0.0.1", port)).expect("connects"),
        ));
        let (answer, counts) =
            ferrox_core::alloc_count::measure(|| lane.reply(false, None).expect("the answer"));
        assert_eq!(answer.status, 200, "the head was read");
        assert_eq!(
            counts.allocs, 0,
            "the head's names and values are read where they lie, so none of them costs a buffer"
        );
        drop(done);
        server.join().expect("the service finishes");
    }

    #[test]
    fn names_are_the_shape_the_reference_reads() {
        assert_eq!(
            announce_name("ab12", 1_700_000_000_123_456_789),
            "sessions/1700000000123456789-ab12"
        );
        assert_eq!(uplink_prefix("ab12"), "streams/ab12/c2s");
        assert_eq!(downlink_prefix("ab12"), "streams/ab12/s2c");
        assert_eq!(
            object_name("streams/ab12/c2s", 7, SEG_SUFFIX),
            "streams/ab12/c2s/000000007.seg"
        );
        assert_eq!(
            object_name("streams/ab12/s2c", 0, END_SUFFIX),
            "streams/ab12/s2c/000000000.end"
        );
        assert_eq!(
            object_name("streams/ab12/s2c", 12, ERR_SUFFIX),
            "streams/ab12/s2c/000000012.err"
        );
        assert!(
            object_name("p", 9, SEG_SUFFIX) < object_name("p", 10, SEG_SUFFIX),
            "the padded sequence sorts into send order, which is what the padding is for"
        );
    }

    #[test]
    fn an_announcement_parses_only_its_own_shape() {
        assert_eq!(
            parse_announce("1700000000123456789-abcd"),
            Some(("abcd", 1_700_000_000_123_456_789))
        );
        assert_eq!(parse_announce("12-a-b"), Some(("a-b", 12)));
        for forged in ["-abcd", "1234-", "+12-ab", " 12-ab", "12ab-cd", "12_ab", ""] {
            assert_eq!(
                parse_announce(forged),
                None,
                "{forged} is not an announcement this carrier wrote"
            );
        }
    }

    #[test]
    fn a_listed_name_parses_only_what_the_carrier_wrote() {
        assert_eq!(parse_entry("000000042.seg"), Some((42, SEG_SUFFIX)));
        assert_eq!(parse_entry("000000000.end"), Some((0, END_SUFFIX)));
        assert_eq!(parse_entry("000000001.err"), Some((1, ERR_SUFFIX)));
        for forged in [
            "000000000.tmp",
            "x000000000.seg",
            "00000 0000.seg",
            "-1.seg",
            ".seg",
            "000000000",
        ] {
            assert_eq!(
                parse_entry(forged),
                None,
                "{forged} names no segment, end or error"
            );
        }
    }

    #[test]
    fn budgets_take_the_reference_defaults_and_caps() {
        let named = |text: &str| {
            Settings::from_json(Some(&crate::json::parse(text).expect("parses"))).expect("names")
        };
        let bare = named(r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/x"}}"#);
        assert_eq!(bare.params.segment_bytes, 512 * 1024);
        assert_eq!(bare.params.flush, Duration::from_millis(20));
        assert_eq!(bare.params.min_poll, Duration::from_millis(50));
        assert_eq!(bare.params.max_poll, Duration::from_millis(500));
        assert_eq!(bare.params.eager, Duration::from_millis(2000));
        assert_eq!(bare.params.hole, Duration::from_secs(30));
        assert_eq!(bare.params.ttl, Duration::from_secs(300));
        assert_eq!(bare.params.concurrency, 8);
        assert_eq!(bare.service, "local");
        assert_eq!(bare.remote_folder, "/tmp/x");

        let snake = named(
            r#"{"xdriveSettings":{"service":"local","remote_folder":"/tmp/y","poll_interval_ms":11}}"#,
        );
        assert_eq!(snake.remote_folder, "/tmp/y");
        assert_eq!(snake.params.min_poll, Duration::from_millis(11));

        let capped = named(
            r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/z","segmentBytes":4000000000,"concurrency":1000,"segmentBytesBelow":0}}"#,
        );
        assert_eq!(capped.params.segment_bytes, 16 * 1024 * 1024);
        assert_eq!(capped.params.concurrency, 256);

        let raised = named(
            r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/w","pollIntervalMs":100,"maxPollIntervalMs":10}}"#,
        );
        assert_eq!(
            raised.params.max_poll, raised.params.min_poll,
            "a cap configured under its own floor is raised to it"
        );

        for refused in [
            "{}",
            r#"{"xdriveSettings":{}}"#,
            r#"{"xdriveSettings":{"service":"local"}}"#,
            r#"{"xdriveSettings":{"remoteFolder":"/tmp/x"}}"#,
            r#"{"xdriveSettings":{"service":"dropbox","remoteFolder":"/tmp/x"}}"#,
        ] {
            assert!(
                Settings::from_json(Some(&crate::json::parse(refused).expect("parses"))).is_none(),
                "{refused} names no reachable store"
            );
        }
    }

    #[test]
    fn coalescing_holds_a_growing_buffer_for_a_bounded_run_of_ticks() {
        let mut held = Pending {
            buf: Vec::new(),
            seq: 0,
            last: 0,
            held: 0,
            closed: false,
            err: None,
        };
        for tick in 1..=MAX_COALESCED_TICKS {
            held.buf.push(b'a');
            assert!(
                !held.ready(),
                "a buffer that grew on tick {tick} of {MAX_COALESCED_TICKS} is left alone"
            );
        }
        assert_eq!(held.held, MAX_COALESCED_TICKS);
        held.buf.push(b'a');
        assert!(held.ready(), "the hold is bounded: the next growth cuts");
        assert_eq!(held.held, 0, "and the count starts over");
        assert!(held.ready(), "a buffer that stopped growing cuts at once");
    }

    #[test]
    fn backoff_doubles_to_the_cap_and_resets_on_progress() {
        let params = Params {
            min_poll: Duration::from_millis(50),
            max_poll: Duration::from_millis(400),
            eager: Duration::from_millis(2000),
            ..quick()
        };
        let stale = Instant::now()
            .checked_sub(Duration::from_secs(3))
            .expect("a clock three seconds back");
        let fresh = Instant::now();
        assert_eq!(
            backoff(true, stale, Duration::from_millis(300), &params),
            params.min_poll
        );
        assert_eq!(
            backoff(false, fresh, Duration::from_millis(300), &params),
            params.min_poll
        );
        assert_eq!(
            backoff(false, stale, Duration::from_millis(50), &params),
            Duration::from_millis(100)
        );
        assert_eq!(
            backoff(false, stale, Duration::from_millis(300), &params),
            Duration::from_millis(400)
        );
        assert_eq!(
            backoff(false, stale, Duration::from_millis(400), &params),
            Duration::from_millis(400),
            "the cap is a ceiling, not a step past it"
        );
    }

    #[test]
    fn a_template_name_substitutes_only_what_it_holds() {
        let secrets = vec!["k0".to_owned(), "k1".to_owned()];
        let vars = Vars::new("inbox", &secrets);
        assert_eq!(vars.sub("{folder}/{secret1}/{name}"), "inbox/k1/{name}");
        assert_eq!(vars.sub("no braces"), "no braces");
        assert_eq!(vars.sub("{unbalanced"), "{unbalanced");
        assert_eq!(
            vars.sub(r#"{"at":"{folder}"}"#),
            r#"{"at":"inbox"}"#,
            "a structural brace is left alone and the placeholder inside it still reads"
        );
        let mut grown = vars.clone();
        grown.set("name", "a/b.seg".to_owned());
        assert_eq!(grown.sub("{folder}/{name}"), "inbox/a/b.seg");
        grown.set("name", "c.seg".to_owned());
        assert_eq!(
            grown.sub("{name}"),
            "c.seg",
            "a variable is replaced, not appended"
        );
    }

    /// Waits for a prefix to be left holding nothing, because the reader hands its deletes to a pool of its own.
    fn emptied(store: &Arc<dyn Storage>, prefix: &str, budget: Duration) -> usize {
        let until = Instant::now() + budget;
        loop {
            let left = store.list(prefix).map_or(1, |found| found.len());
            if left == 0 || Instant::now() >= until {
                return left;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_local_store_commits_escapes_and_lists_like_the_reference() {
        let (dir, store) = local("clamp");
        store
            .put("streams/a/c2s/000000000.seg", b"hello")
            .expect("puts");
        assert_eq!(
            store.get("streams/a/c2s/000000000.seg").expect("gets"),
            b"hello"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let object = std::fs::metadata(dir.join("streams/a/c2s/000000000.seg")).expect("stats");
            assert_eq!(
                object.permissions().mode() & 0o777,
                0o600,
                "an object is readable by the process that wrote it"
            );
            let folder = std::fs::metadata(&dir).expect("stats");
            assert_eq!(
                folder.permissions().mode() & 0o777,
                0o700,
                "and so is the folder that holds the session"
            );
        }
        store
            .put("../evil", b"out")
            .expect("a clamp, not a refusal");
        assert!(dir.join("evil").is_file(), "a dot-dot pops what it can");
        assert!(
            !dir.parent().expect("parent").join("evil").is_file(),
            "and never names its way out of the folder"
        );
        assert!(
            store.put("x/.xdrive-tmp-7", b"").is_err(),
            "the temp prefix is reserved for a commit in flight"
        );
        assert!(
            store.put("", b"x").is_err(),
            "an object with no last step is refused, not written at the root"
        );
        let absent = store
            .get("streams/a/c2s/000000001.seg")
            .expect_err("absent");
        assert_eq!(
            absent.kind(),
            ErrorKind::NotFound,
            "an absent object answers the one error a polling reader reads as not yet"
        );
        store
            .delete("streams/a/c2s/000000000.seg")
            .expect("deletes");
        store
            .delete("streams/a/c2s/000000000.seg")
            .expect("an absent delete is already done");
        std::fs::write(dir.join("streams/a/c2s/.xdrive-tmp-1"), b"half a segment")
            .expect("writes an uncommitted object");
        store
            .put("streams/a/c2s/000000002.seg", b"b")
            .expect("puts");
        let listed = store.list("streams/a/c2s").expect("lists");
        assert_eq!(
            listed.len(),
            1,
            "a reader is never handed a half-written object"
        );
        assert_eq!(listed[0].name, "000000002.seg");
        assert!(
            store
                .list("no/such/prefix")
                .expect("lists nothing")
                .is_empty(),
            "an absent folder lists empty rather than failing the poll"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_segment_stream_is_the_input_cut_at_the_segment_size() {
        #[derive(Default)]
        struct Held {
            puts: Mutex<Vec<(String, Vec<u8>)>>,
        }

        impl Storage for Held {
            fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
                self.puts
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((name.to_owned(), data.to_vec()));
                Ok(())
            }

            fn get(&self, _name: &str) -> io::Result<Vec<u8>> {
                Err(io::Error::from(ErrorKind::NotFound))
            }

            fn delete(&self, _name: &str) -> io::Result<()> {
                Ok(())
            }

            fn list(&self, _prefix: &str) -> io::Result<Vec<Entry>> {
                Ok(Vec::new())
            }
        }

        let held = Arc::new(Held::default());
        let params = Arc::new(Params {
            segment_bytes: 512,
            ..quick()
        });
        let writer = Writer::new(
            Arc::clone(&held) as Arc<dyn Storage>,
            "streams/w/c2s".to_owned(),
            &params,
            Arc::new(Wake::new()),
        );
        let payload: Vec<u8> = (0..1_200usize).map(|at| (at % 253) as u8).collect();
        assert_eq!(writer.write(&payload).expect("buffers"), payload.len());
        drop(writer);

        let mut puts = held
            .puts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        puts.sort_by(|(left, _), (right, _)| left.cmp(right));
        let names: Vec<&str> = puts.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "streams/w/c2s/000000000.seg",
                "streams/w/c2s/000000001.seg",
                "streams/w/c2s/000000002.seg",
                "streams/w/c2s/000000003.end",
            ],
            "three segments and the end marker at the sequence the peer reads"
        );
        let mut back = Vec::new();
        for (name, data) in &puts {
            if name.ends_with(SEG_SUFFIX) {
                assert!(
                    data.len() <= params.segment_bytes,
                    "{name} overran its segment"
                );
                back.extend_from_slice(data);
            } else {
                assert!(data.is_empty(), "the end marker carries no payload");
            }
        }
        assert_eq!(
            back, payload,
            "the stream cut up and put back is the stream"
        );
    }

    #[test]
    fn a_session_carries_every_byte_both_ways_over_one_folder() {
        let (dir, store) = local("pair");
        let params = Arc::new(Params {
            segment_bytes: 512,
            ..quick()
        });
        let payload: Vec<u8> = (0..5_000usize).map(|at| (at % 251) as u8).collect();
        let accept: Accept = Arc::new(move |mut session: Conn| {
            let mut buf = [0u8; 512];
            loop {
                match session.read(&mut buf) {
                    Ok(n) => {
                        if session.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
        });
        let server =
            Server::serve(Arc::clone(&store), Arc::clone(&params), accept).expect("serves");
        let mut client = dial(Arc::clone(&store), &params).expect("dials");
        client.write_all(&payload).expect("writes");
        let got = read_up_to(&mut client, payload.len(), Duration::from_secs(30));
        assert_eq!(
            got, payload,
            "the echo is the input, across every segment boundary"
        );
        client.end_write().expect("ends the uplink");
        let mut ended = None;
        let until = Instant::now() + Duration::from_secs(30);
        while Instant::now() < until {
            let mut buf = [0u8; 16];
            match client.read(&mut buf) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => {
                    ended = Some(error.kind());
                    break;
                }
            }
        }
        assert_eq!(
            ended,
            Some(ErrorKind::UnexpectedEof),
            "the peer's own handle dropping is what puts its .end and closes our read"
        );
        let sessions = store.list("streams").expect("lists");
        assert_eq!(sessions.len(), 1, "one announcement opened one session");
        let session = &sessions[0].name;
        assert_eq!(
            emptied(&store, &uplink_prefix(session), Duration::from_secs(10)),
            0,
            "every uplink object was discarded once it was read"
        );
        assert_eq!(
            emptied(&store, &downlink_prefix(session), Duration::from_secs(10)),
            0,
            "and every downlink object too"
        );
        assert_eq!(
            emptied(&store, SESSIONS_DIR, Duration::from_secs(10)),
            0,
            "the announcement went to the listener that claimed it"
        );
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the reader promised to discard before its handle went away is still discarded: the queue closes, it does not forget.
    #[test]
    fn a_session_ends_with_every_uplink_object_deleted() {
        struct Held {
            inner: Arc<dyn Storage>,
            hold: AtomicBool,
            entered: AtomicBool,
        }

        impl Storage for Held {
            fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
                self.inner.put(name, data)
            }

            fn get(&self, name: &str) -> io::Result<Vec<u8>> {
                self.inner.get(name)
            }

            // The hold is bounded, so a latch the test never drops fails the run instead of parking it.
            fn delete(&self, name: &str) -> io::Result<()> {
                self.entered.store(true, Ordering::Release);
                let until = Instant::now() + Duration::from_secs(5);
                while self.hold.load(Ordering::Acquire) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(2));
                }
                self.inner.delete(name)
            }

            fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
                self.inner.list(prefix)
            }
        }

        let (dir, inner) = local("discard");
        let held = Arc::new(Held {
            inner,
            hold: AtomicBool::new(true),
            entered: AtomicBool::new(false),
        });
        let store: Arc<dyn Storage> = Arc::clone(&held) as Arc<dyn Storage>;
        // One worker for the whole queue: the first discard is what the gate holds, so every one after it is provably still queued when the session ends.
        let params = Arc::new(Params {
            concurrency: 1,
            ..quick()
        });
        let closed = Arc::new(AtomicBool::new(false));
        let gone = Arc::clone(&closed);
        let accept: Accept = Arc::new(move |mut session: Conn| {
            let mut buf = [0u8; 512];
            loop {
                match session.read(&mut buf) {
                    Ok(n) => {
                        if session.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
            drop(session);
            gone.store(true, Ordering::Release);
        });
        let server = Server::serve(Arc::clone(&store), Arc::clone(&params), Arc::clone(&accept))
            .expect("serves");
        let mut client = dial(Arc::clone(&store), &params).expect("dials");
        let payload: Vec<u8> = (0..1_600usize).map(|at| (at % 251) as u8).collect();
        client.write_all(&payload).expect("writes");
        assert_eq!(
            read_up_to(&mut client, payload.len(), Duration::from_secs(30)),
            payload,
            "the echo carries every byte before the uplink ends"
        );
        client.end_write().expect("ends the uplink");
        let until = Instant::now() + Duration::from_secs(30);
        while !closed.load(Ordering::Acquire) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            closed.load(Ordering::Acquire),
            "the session's own handle is what ended it"
        );
        assert!(
            held.entered.load(Ordering::Acquire),
            "a discard reached the gate, so the rest of that queue never left it"
        );
        held.hold.store(false, Ordering::Release);
        let sessions = store.list(STREAMS_DIR).expect("lists");
        assert_eq!(sessions.len(), 1, "one announcement opened one session");
        let session = &sessions[0].name;
        assert_eq!(
            emptied(&store, &uplink_prefix(session), Duration::from_secs(10)),
            0,
            "the uplink objects the reader read are gone once its handle dropped"
        );
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refused_put_marks_the_segment_and_the_peer_names_it() {
        struct Full {
            inner: Arc<dyn Storage>,
        }

        impl Storage for Full {
            fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
                if name.ends_with(SEG_SUFFIX) {
                    return Err(carrier_error("the bucket is full"));
                }
                self.inner.put(name, data)
            }

            fn get(&self, name: &str) -> io::Result<Vec<u8>> {
                self.inner.get(name)
            }

            fn delete(&self, name: &str) -> io::Result<()> {
                self.inner.delete(name)
            }

            fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
                self.inner.list(prefix)
            }
        }

        let (dir, store) = local("err");
        let params = Arc::new(quick());
        let writer = Writer::new(
            Arc::new(Full {
                inner: Arc::clone(&store),
            }),
            "streams/a/c2s".to_owned(),
            &params,
            Arc::new(Wake::new()),
        );
        writer
            .write(b"hello")
            .expect("a buffered write is not yet a failure");
        let refused = writer
            .close()
            .expect_err("the close reports the latched failure");
        assert!(
            refused.to_string().contains("the bucket is full"),
            "{refused}"
        );
        assert!(
            dir.join("streams/a/c2s/000000000.err").is_file(),
            "the sequence that could not be stored is marked for the peer to read"
        );
        let rd = Rd {
            discards: Pool::new(1),
            storage: Arc::clone(&store),
            prefix: "streams/a/c2s".to_owned(),
            params,
            wake: Arc::new(Wake::new()),
        };
        let inbox = Inbox::new();
        let mut seq = 0u64;
        let mut hole = None;
        let why = rd
            .poll(&mut seq, &mut hole, &inbox)
            .expect_err("a mark is an end with a reason");
        assert!(
            why.to_string()
                .contains("the peer could not store segment 0"),
            "{why}"
        );
        assert_eq!(
            emptied(&store, "streams/a/c2s", Duration::from_secs(10)),
            0,
            "the mark is read once and then cleared out of the store"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_segment_that_never_arrives_while_later_ones_did_times_out() {
        let (dir, store) = local("hole");
        store
            .put("streams/h/c2s/000000001.seg", b"later")
            .expect("puts");
        let params = Arc::new(Params {
            hole: Duration::ZERO,
            ..quick()
        });
        let rd = Rd {
            discards: Pool::new(1),
            storage: Arc::clone(&store),
            prefix: "streams/h/c2s".to_owned(),
            params,
            wake: Arc::new(Wake::new()),
        };
        let inbox = Inbox::new();
        let mut seq = 0u64;
        let mut hole = None;
        let (advanced, eof) = rd.poll(&mut seq, &mut hole, &inbox).expect("marks");
        assert!(
            !advanced && !eof && hole.is_some(),
            "the first pass only starts the wait: a gap is not yet a lost segment"
        );
        let why = rd
            .poll(&mut seq, &mut hole, &inbox)
            .expect_err("the second pass runs out");
        assert!(
            why.to_string()
                .contains("segment 0 never arrived while later ones did"),
            "{why}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_announcement_and_an_idle_session_are_swept_out_of_the_folder() {
        let (dir, store) = local("sweep");
        let server = Arc::new(Server {
            wake: Arc::new(Wake::new()),
            claims: Mutex::new(Claims::default()),
        });
        let rd = Arc::new(Rd {
            discards: Pool::new(2),
            storage: Arc::clone(&store),
            prefix: String::new(),
            params: Arc::new(quick()),
            wake: Arc::clone(&server.wake),
        });
        store
            .put("sessions/1000-gone", &[])
            .expect("an ancient announce");
        store
            .put("streams/gone/c2s/000000000.seg", b"orphan")
            .expect("its bytes");
        let opened = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&opened);
        let accept: Accept = Arc::new(move |_: Conn| {
            counted.fetch_add(1, Ordering::AcqRel);
        });
        assert!(
            !server.accept_pending(&rd, &accept),
            "nothing in the folder is a session waiting to be opened"
        );
        assert_eq!(opened.load(Ordering::Acquire), 0);
        assert_eq!(
            emptied(&store, SESSIONS_DIR, Duration::from_secs(10)),
            0,
            "a stamp older than the ttl is dropped without a handler"
        );
        assert_eq!(
            emptied(&store, STREAMS_DIR, Duration::from_secs(10)),
            0,
            "and so are the streams of the session it announced, on the pool that deletes"
        );

        store
            .put("streams/idle/c2s/000000000.seg", b"x")
            .expect("puts");
        let short = Arc::new(Rd {
            discards: Pool::new(2),
            storage: Arc::clone(&store),
            prefix: String::new(),
            params: Arc::new(Params {
                ttl: Duration::ZERO,
                ..quick()
            }),
            wake: Arc::clone(&server.wake),
        });
        server.collect(&short).expect("first sweep notes it idle");
        assert!(dir.join("streams/idle").exists(), "one pass never deletes");
        server.collect(&short).expect("second sweep expires it");
        assert!(
            !dir.join("streams/idle").exists(),
            "a session idle for a ttl is bytes no peer will read again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_finished_upload_hands_its_buffer_back_empty_and_whole() {
        let (_dir, store) = local("sink");
        let sink = Sink {
            storage: Arc::clone(&store),
            prefix: String::new(),
            wake: Arc::new(Wake::new()),
            segment: 64,
            err: Mutex::new(None),
            spare: Mutex::new(Vec::new()),
        };
        let cold = sink.adopt();
        assert!(
            cold.is_empty() && cold.capacity() == 0,
            "before any upload has finished, a write's buffer is its own first allocation"
        );
        let mut used = Vec::with_capacity(64);
        used.extend_from_slice(b"a segment that reached the store");
        let ptr = used.as_ptr();
        let cap = used.capacity();
        sink.reclaim(used);
        let again = sink.adopt();
        assert_eq!(
            again.as_ptr(),
            ptr,
            "the continuation is written into the very allocation the upload left behind"
        );
        assert_eq!(again.capacity(), cap, "and it was not grown to hold it");
        assert!(
            again.is_empty(),
            "what comes back is the capacity alone: a recycled buffer never carries the last segment into the next"
        );
        drop(again);

        let mut keep = Vec::with_capacity(32);
        keep.extend_from_slice(b"one");
        let first = keep.as_ptr();
        sink.reclaim(keep);
        let mut second = Vec::with_capacity(32);
        second.extend_from_slice(b"two");
        let next = second.as_ptr();
        sink.reclaim(second);
        let mut third = Vec::with_capacity(32);
        third.extend_from_slice(b"three");
        sink.reclaim(third);
        let newest = sink.adopt();
        assert_eq!(newest.as_ptr(), next, "two buffers is the whole pool");
        let oldest = sink.adopt();
        assert_eq!(oldest.as_ptr(), first, "and they come back newest first");
        assert_eq!(
            sink.adopt().capacity(),
            0,
            "and a third ask costs the writer one fresh allocation, no more"
        );
    }

    /// The bytes after `\r\n\r\n` of a head, or none until the whole delimiter has arrived.
    fn head_end(bytes: &[u8]) -> Option<usize> {
        bytes
            .windows(4)
            .position(|at| at == b"\r\n\r\n")
            .map(|at| at + 4)
    }

    /// The length a request declared, which is what tells the fake where its body stops.
    fn declared(head: &[u8]) -> usize {
        let text = String::from_utf8_lossy(head).to_lowercase();
        text.lines()
            .find(|line| line.starts_with("content-length:"))
            .and_then(|line| line[15..].trim().parse::<usize>().ok())
            .unwrap_or(0)
    }

    /// The first line of a request, split into method and target.
    fn request_line(head: &[u8]) -> (String, String) {
        let text = String::from_utf8_lossy(head).into_owned();
        let mut parts = text.split(' ');
        (
            parts.next().unwrap_or("").to_owned(),
            parts.next().unwrap_or("").to_owned(),
        )
    }

    /// One canned answer: the status the test wants and the body that rides with it.
    type Canned = VecDeque<(u16, Vec<u8>)>;

    /// The state one fake origin shares with every lane it serves.
    #[derive(Clone)]
    struct Held {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        answers: Arc<Mutex<Canned>>,
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        lanes: Arc<AtomicUsize>,
    }

    /// An origin that keeps its connections alive, answers from an in-memory folder or from the queue the test filled, and hands every request byte back to the test that sent it.
    struct Fake {
        port: u16,
        held: Held,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Fake {
        fn start() -> Self {
            let origin = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = origin.local_addr().expect("addr").port();
            let held = Held {
                requests: Arc::new(Mutex::new(Vec::new())),
                answers: Arc::new(Mutex::new(Canned::new())),
                objects: Arc::new(Mutex::new(HashMap::new())),
                lanes: Arc::new(AtomicUsize::new(0)),
            };
            let stop = Arc::new(AtomicBool::new(false));
            let runner_state = held.clone();
            let runner_stop = Arc::clone(&stop);
            let runner = std::thread::spawn(move || {
                while !runner_stop.load(Ordering::Acquire) {
                    let Ok((stream, _)) = origin.accept() else {
                        return;
                    };
                    if runner_stop.load(Ordering::Acquire) {
                        return;
                    }
                    runner_state.lanes.fetch_add(1, Ordering::AcqRel);
                    let served = runner_state.clone();
                    std::thread::spawn(move || {
                        let _ = served.connection(stream);
                    });
                }
            });
            Self {
                port,
                held,
                stop,
                thread: Some(runner),
            }
        }

        /// The origin, with `path` behind it.
        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}/{}", self.port, path)
        }

        /// Queue one canned answer, consumed in order before the folder is read.
        fn push(&self, status: u16, body: &str) {
            self.held
                .answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back((status, body.as_bytes().to_vec()));
        }

        /// Every request the origin read, head and body, in the order it read them.
        fn taken(&self) -> Vec<Vec<u8>> {
            self.held
                .requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn text(&self, index: usize) -> String {
            String::from_utf8_lossy(&self.taken()[index]).into_owned()
        }

        fn asks(&self) -> usize {
            self.taken().len()
        }

        /// How many connections the origin has been handed: one per lane, which is the whole point of keeping them.
        fn lanes(&self) -> usize {
            self.held.lanes.load(Ordering::Acquire)
        }
    }

    impl Held {
        /// Serve one connection until the client stops sending: a kept-alive origin that answers the next request on the same lane.
        fn connection(&self, mut stream: Connection) -> io::Result<()> {
            let mut got: Vec<u8> = Vec::new();
            let mut buf = vec![0u8; 8192];
            loop {
                let Some(head) = Self::read_head(&mut got, &mut stream, &mut buf)? else {
                    return Ok(());
                };
                let stop = head + declared(&got[..head]);
                while got.len() < stop {
                    match stream.read(&mut buf) {
                        Ok(0) => return Ok(()),
                        Ok(read) => got.extend_from_slice(&buf[..read]),
                        Err(why) if why.kind() == ErrorKind::Interrupted => {}
                        Err(why) => return Err(why),
                    }
                }
                let request = got[..stop].to_vec();
                got.drain(..stop);
                self.requests
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(request.clone());
                let (status, payload) = self.route(&request[..head], &request[head..]);
                let answer = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\r\n",
                    payload.len()
                );
                stream.write_all(answer.as_bytes())?;
                stream.write_all(&payload)?;
                stream.flush()?;
            }
        }

        /// The offset past the next request head, or none once the client has said it is done.
        fn read_head(
            got: &mut Vec<u8>,
            stream: &mut Connection,
            buf: &mut [u8],
        ) -> io::Result<Option<usize>> {
            loop {
                if let Some(at) = head_end(got) {
                    return Ok(Some(at));
                }
                match stream.read(buf) {
                    Ok(0) => return Ok(None),
                    Ok(read) => got.extend_from_slice(&buf[..read]),
                    Err(why) if why.kind() == ErrorKind::Interrupted => {}
                    Err(why) => return Err(why),
                }
            }
        }

        /// The folder's own answer, unless the test queued one for this ask.
        fn route(&self, head: &[u8], body: &[u8]) -> (u16, Vec<u8>) {
            if let Some(found) = self
                .answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
            {
                return found;
            }
            let (method, target) = request_line(head);
            let path = target.split('?').next().unwrap_or("").to_owned();
            let mut objects = self.objects.lock().unwrap_or_else(PoisonError::into_inner);
            let stored = path.strip_prefix("/o/");
            let listed = path.strip_prefix("/l/");
            let listing = match (method.as_str(), stored, listed) {
                ("PUT", Some(name), _) => {
                    objects.insert(name.to_owned(), body.to_vec());
                    return (200, Vec::new());
                }
                ("GET", Some(name), _) => {
                    return objects
                        .get(name)
                        .map_or((404, Vec::new()), |data| (200, data.clone()));
                }
                ("DELETE", Some(name), _) => {
                    objects.remove(name);
                    return (200, Vec::new());
                }
                ("GET", None, Some(prefix)) => {
                    let under = format!("{prefix}/");
                    let mut names: Vec<&String> = objects
                        .keys()
                        .filter(|name| name.starts_with(under.as_str()))
                        .collect();
                    names.sort();
                    let mut text = String::new();
                    for name in names {
                        text.push_str(name);
                        text.push('\n');
                    }
                    text
                }
                _ => return (404, Vec::new()),
            };
            (200, listing.into_bytes())
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _wake = Connection::connect(("127.0.0.1", self.port));
            if let Some(runner) = self.thread.take() {
                let _ = runner.join();
            }
        }
    }

    /// The `xdriveSettings` of a templated store aimed at the test's own origin, with `<p>` standing for its port.
    fn templated(text: &str, port: u16) -> Settings {
        Settings {
            remote_folder: "folder".to_owned(),
            service: "template".to_owned(),
            secrets: vec!["s0".to_owned()],
            template: Some(
                crate::json::parse(&text.replace("<p>", &port.to_string())).expect("a template"),
            ),
            s3: None,
            params: quick(),
            security: String::new(),
            tls: None,
            reality: None,
            reality_named: false,
        }
    }

    /// The head of an answer is walked in the lane's own buffer, and what arrived past it stays there for the next answer: no line is staged into a copy, and the walk moves no allocation.
    #[test]
    fn a_lane_keeps_what_arrives_past_the_answer_it_read() {
        const FIRST: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst";
        const SECOND: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond";
        const THIRD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext";
        let origin = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = origin.local_addr().expect("addr").port();
        let (hold, wait) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = origin.accept().expect("accepts");
            stream
                .write_all(&[FIRST, SECOND, THIRD].concat())
                .expect("answers three");
            stream.flush().expect("flushes");
            let _ = wait.recv();
        });
        let mut lane = Lane::new(Kind::Plain(
            Connection::connect(("127.0.0.1", port)).expect("connects"),
        ));
        lane.kind
            .write_all(
                b"GET /o/a HTTP/1.1\r\nHost: h\r\n\r\nGET /o/b HTTP/1.1\r\nHost: h\r\n\r\nGET /o/c HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .expect("asks three");
        lane.kind.flush().expect("flushes");
        let total = FIRST.len() + SECOND.len() + THIRD.len();
        while lane.buf.len() < total {
            let read = crate::proxy::read_into_tail(&mut lane.kind, &mut lane.buf)
                .expect("the origin answers");
            assert_ne!(
                read,
                0,
                "the origin closed after {} of {total} bytes",
                lane.buf.len()
            );
        }
        let base = lane.buf.as_ptr();
        let room = lane.buf.capacity();
        let first = lane.reply(false, None).expect("the first answer");
        assert_eq!(first.body, b"first");
        assert!(
            first.kept,
            "an answer that says nothing about closing leaves its lane for the next request"
        );
        assert_eq!(
            lane.reply(false, None).expect("the second answer").body,
            b"second"
        );
        assert_eq!(
            &lane.buf[lane.at..],
            THIRD,
            "the bytes that rode in past the answer it read were never handed to a second owner"
        );
        let status = lane.line().expect("the third status");
        assert_eq!(status, b"HTTP/1.1 200 OK");
        let offset = status.as_ptr() as usize - base as usize;
        assert!(
            offset < room,
            "the head is read out of the buffer it arrived in"
        );
        assert_eq!(lane.buf.as_ptr(), base, "and the walk never moved it");
        assert_eq!(
            lane.buf.capacity(),
            room,
            "nor grew it across one push and three drains"
        );
        drop(hold);
        server.join().expect("stops");
    }

    /// Every request the templated store makes, read back as the exact bytes it put on the wire.
    #[test]
    fn the_templated_store_sends_the_reference_bytes() {
        const WIRE: &str = r#"{"auth":{"type":"static","header":{"X-Folder":"{folder}/{secret0}"}},"put":{"method":"PUT","url":"http://127.0.0.1:<p>/o/{name}","headers":{"X-Magic":"keep"}},"get":{"url":"http://127.0.0.1:<p>/o/{name}"},"delete":{"method":"DELETE","url":"http://127.0.0.1:<p>/o/{name}"},"list":{"url":"http://127.0.0.1:<p>/l/{prefix}","namesRegex":"streams/a/([a-z0-9./~-]+)"}}"#;
        let fake = Fake::start();
        let store = Template::build(
            &templated(WIRE, fake.port),
            Http::new(None, None, false, None, 8),
        )
        .expect("builds");
        let host = format!("127.0.0.1:{}", fake.port);
        let segment = "streams/a/c2s/000000000.seg";
        let marker = "streams/a/c2s/000000003.end";
        store.put(segment, b"hello").expect("stores");
        store.put(marker, &[]).expect("marks the end");
        assert_eq!(store.get(segment).expect("reads"), b"hello");
        let listed = store.list("streams/a").expect("lists");
        store.delete(segment).expect("drops");
        assert_eq!(
            fake.text(0),
            format!(
                "PUT /o/{segment} HTTP/1.1\r\nHost: {host}\r\nX-Folder: folder/s0\r\nX-Magic: keep\r\nContent-Length: 5\r\n\r\nhello"
            )
        );
        assert_eq!(
            fake.text(1),
            format!(
                "PUT /o/{marker} HTTP/1.1\r\nHost: {host}\r\nX-Folder: folder/s0\r\nX-Magic: keep\r\nContent-Length: 0\r\n\r\n"
            ),
            "a bodyless put declares zero, the way the service's own http library writes it"
        );
        assert_eq!(
            fake.text(2),
            format!("GET /o/{segment} HTTP/1.1\r\nHost: {host}\r\nX-Folder: folder/s0\r\n\r\n"),
            "and a get declares no length at all"
        );
        assert_eq!(
            fake.text(3),
            format!("GET /l/streams/a HTTP/1.1\r\nHost: {host}\r\nX-Folder: folder/s0\r\n\r\n")
        );
        assert_eq!(
            fake.text(4),
            format!("DELETE /o/{segment} HTTP/1.1\r\nHost: {host}\r\nX-Folder: folder/s0\r\n\r\n")
        );
        assert_eq!(
            listed.iter().map(|at| at.name.as_str()).collect::<Vec<_>>(),
            vec!["c2s/000000000.seg", "c2s/000000003.end"],
            "the listing hands back exactly what its regex captured, in the order the service wrote it"
        );
        assert_eq!(fake.lanes(), 1, "five asks, one kept-alive lane");
    }

    /// The base64 of a payload reaches the `{data}` slot of a body template, and a `basic` credential is the pair the service's own http library would have sent.
    #[test]
    fn a_templated_body_carries_the_data_and_the_credential() {
        const ENVELOPE: &str = r#"{"auth":{"type":"basic","username":"a","password":"{secret0}"},"put":{"method":"PUT","url":"http://127.0.0.1:<p>/o/{name}","body":"{\"raw\":\"{data}\"}"},"get":{"url":"http://127.0.0.1:<p>/o/{name}"},"delete":{"method":"DELETE","url":"http://127.0.0.1:<p>/o/{name}"},"list":{"url":"http://127.0.0.1:<p>/l/{prefix}","namesRegex":"([a-z0-9./~-]+)"}}"#;
        let fake = Fake::start();
        let store = Template::build(
            &templated(ENVELOPE, fake.port),
            Http::new(None, None, false, None, 8),
        )
        .expect("builds");
        store.put("a.seg", b"hello").expect("stores");
        assert_eq!(
            fake.text(0),
            format!(
                "PUT /o/a.seg HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Basic YTpzMA==\r\nContent-Length: 18\r\n\r\n{{\"raw\":\"aGVsbG8=\"}}",
                fake.port
            )
        );
    }

    /// An `oauth2` template fetches its token once, rides it through the header template, and asks for another when the service says the old one is dead.
    #[test]
    fn an_oauth2_template_fetches_its_token_once_and_again_after_a_401() {
        const OAUTH: &str = r#"{"auth":{"type":"oauth2","tokenUrl":"http://127.0.0.1:<p>/token","form":{"client_id":"cid","refresh_token":"rtok"},"header":{"Authorization":"Bearer {token}"},"tokenPath":"data.access","expiryPath":"exp"},"put":{"method":"PUT","url":"http://127.0.0.1:<p>/o/{name}"},"get":{"url":"http://127.0.0.1:<p>/o/{name}"},"delete":{"method":"DELETE","url":"http://127.0.0.1:<p>/o/{name}"},"list":{"url":"http://127.0.0.1:<p>/l/{prefix}","namesRegex":"([a-z0-9./~-]+)"}}"#;
        let fake = Fake::start();
        let store = Template::build(
            &templated(OAUTH, fake.port),
            Http::new(None, None, false, None, 8),
        )
        .expect("builds");
        let host = format!("127.0.0.1:{}", fake.port);
        fake.push(200, r#"{"data":{"access":"atok"},"exp":3600}"#);
        store.put("a.seg", b"one").expect("stores");
        store.put("b.seg", b"two").expect("stores again");
        assert_eq!(fake.asks(), 3, "one token for two segments");
        assert_eq!(
            fake.text(0),
            format!(
                "POST /token HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 32\r\n\r\nclient_id=cid&refresh_token=rtok",
                fake.port
            )
        );
        assert_eq!(
            fake.text(1),
            format!(
                "PUT /o/a.seg HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\nContent-Length: 3\r\n\r\none"
            ),
            "the token lands where the header template points it"
        );
        fake.push(401, "gone");
        fake.push(200, r#"{"data":{"access":"atok2"},"exp":3600}"#);
        store.put("c.seg", b"three").expect("retries the refusal");
        assert_eq!(
            fake.asks(),
            6,
            "the refused ask, a fresh token, and the ask again"
        );
        assert_eq!(
            fake.text(3),
            format!(
                "PUT /o/c.seg HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\nContent-Length: 5\r\n\r\nthree"
            ),
            "the refused try still carried the old token"
        );
        assert_eq!(
            fake.text(5),
            format!(
                "PUT /o/c.seg HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok2\r\nContent-Length: 5\r\n\r\nthree"
            ),
            "and the retry carried the new one"
        );
        assert_eq!(fake.lanes(), 1, "six asks, one kept-alive lane");
    }

    /// A status the config named is asked again, and a `403` is only one when its body says the reason the config named.
    #[test]
    fn a_configured_answer_is_asked_again() {
        const LADDER: &str = r#"{"retry":{"status":[503],"rateReason":"slow"},"get":{"url":"http://127.0.0.1:<p>/o/{name}"},"put":{"method":"PUT","url":"http://127.0.0.1:<p>/o/{name}"},"delete":{"method":"DELETE","url":"http://127.0.0.1:<p>/o/{name}"},"list":{"url":"http://127.0.0.1:<p>/l/{prefix}","namesRegex":"([a-z0-9./~-]+)"}}"#;
        let fake = Fake::start();
        let store = Template::build(
            &templated(LADDER, fake.port),
            Http::new(None, None, false, None, 8),
        )
        .expect("builds");
        fake.push(503, "busy");
        fake.push(200, "body");
        assert_eq!(
            store.get("streams/a/c2s.seg").expect("asked again"),
            b"body",
            "the second answer is the one the reader gets"
        );
        assert_eq!(
            fake.asks(),
            2,
            "one rung the ladder waits out, one it takes"
        );
        assert!(
            store.retryable(403, br#"{"slow":"yes"}"#),
            "a 403 whose body names the configured reason is a rate limit"
        );
        assert!(
            !store.retryable(403, br#"{"other":"yes"}"#),
            "and a 403 that does not is a refusal"
        );
        assert!(
            !store.retryable(404, r#"{"slow":"yes"}"#.as_bytes()),
            "a status the list does not name is neither"
        );
    }

    /// The four operations a templated store must name, aimed at the fake's in-memory folder.
    const SIDES: &str = r#"{"put":{"method":"PUT","url":"http://127.0.0.1:<p>/o/{name}"},"get":{"url":"http://127.0.0.1:<p>/o/{name}"},"delete":{"method":"DELETE","url":"http://127.0.0.1:<p>/o/{name}"},"list":{"url":"http://127.0.0.1:<p>/l/{prefix}","namesRegex":"([a-z0-9./~-]+)"}}"#;

    /// A Drive store built over the test's own origin, with the three secrets the reference asks for.
    fn drive_over(fake: &Fake) -> Drive {
        let settings = Settings {
            remote_folder: "root".to_owned(),
            service: "Google Drive".to_owned(),
            secrets: vec!["cid".to_owned(), "csecret".to_owned(), "rtok".to_owned()],
            template: None,
            s3: None,
            params: quick(),
            security: String::new(),
            tls: None,
            reality: None,
            reality_named: false,
        };
        let mut drive =
            Drive::build(&settings, Http::new(None, None, false, None, 8)).expect("builds");
        drive.token_url = fake.url("token");
        drive.files_url = fake.url("drive/files");
        drive.upload_url = fake.url("upload/files?uploadType=multipart");
        drive
    }

    /// The Drive calls the carrier makes, read back as the exact bytes the reference's own client would have written.
    #[test]
    fn the_drive_service_asks_in_the_reference_shape() {
        const FORM: &str =
            "client_id=cid&client_secret=csecret&grant_type=refresh_token&refresh_token=rtok";
        const INLINE: &str =
            r#"{"description":"aGVsbG8=","name":"streams~a~c2s~000000000.seg","parents":["root"]}"#;
        let fake = Fake::start();
        let host = format!("127.0.0.1:{}", fake.port);
        let drive = drive_over(&fake);
        fake.push(200, r#"{"access_token":"atok","expires_in":3600}"#);
        fake.push(200, r#"{"id":"f0"}"#);
        let segment = "streams/a/c2s/000000000.seg";
        drive.put(segment, b"hello").expect("rides the metadata");
        assert_eq!(
            fake.text(0),
            format!(
                "POST /token HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{FORM}",
                FORM.len()
            )
        );
        assert_eq!(
            fake.text(1),
            format!(
                "POST /drive/files?fields=id HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: {}\r\n\r\n{INLINE}",
                INLINE.len()
            )
        );
        fake.push(200, "payload");
        assert_eq!(
            drive.get(segment).expect("reads the media"),
            b"payload",
            "the id the upload answered is the id the read uses, so no listing stands between them"
        );
        assert_eq!(
            fake.text(2),
            format!(
                "GET /drive/files/f0?alt=media&supportsAllDrives=true HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\n\r\n"
            ),
            "and a get declares no length at all"
        );
        drive.remember("streams~a~s2c~000000001.seg", "f%1");
        fake.push(200, "");
        fake.push(200, r#"{"description":"aGVsbG8="}"#);
        assert_eq!(
            drive
                .get("streams/a/s2c/000000001.seg")
                .expect("reads the description"),
            b"hello",
            "a media read of nothing is the payload that rode in the description"
        );
        assert_eq!(
            fake.text(3),
            format!(
                "GET /drive/files/f%251?alt=media&supportsAllDrives=true HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\n\r\n"
            ),
            "an id is quoted as a path segment is"
        );
        assert_eq!(
            fake.text(4),
            format!(
                "GET /drive/files/f%251?fields=description&supportsAllDrives=true HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\n\r\n"
            )
        );
        assert_eq!(fake.lanes(), 1, "five asks, one kept-alive lane");
    }

    /// An object too large for the description rides one multipart body: the metadata part, then the payload, then the closing boundary.
    #[test]
    fn a_large_drive_object_rides_the_multipart_body() {
        let fake = Fake::start();
        let drive = drive_over(&fake);
        let data: Vec<u8> = (0..=DRIVE_INLINE_LIMIT)
            .map(|at| b'a' + (at % 26) as u8)
            .collect();
        let metadata = r#"{"name":"streams~a~c2s~000000000.seg","parents":["root"]}"#;
        let mut want = format!(
            "--{DRIVE_BOUNDARY}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{DRIVE_BOUNDARY}\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .into_bytes();
        want.extend_from_slice(&data);
        want.extend_from_slice(b"\r\n--");
        want.extend_from_slice(DRIVE_BOUNDARY.as_bytes());
        want.extend_from_slice(b"--\r\n");
        fake.push(200, r#"{"access_token":"atok","expires_in":3600}"#);
        fake.push(200, r#"{"id":"big"}"#);
        drive
            .put("streams/a/c2s/000000000.seg", &data)
            .expect("uploads");
        let request = fake.taken()[1].clone();
        let head = head_end(&request).expect("a head");
        assert_eq!(
            &request[..head],
            format!(
                "POST /upload/files?uploadType=multipart HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer atok\r\nContent-Type: multipart/related; boundary={DRIVE_BOUNDARY}\r\nContent-Length: {}\r\n\r\n",
                fake.port,
                want.len()
            )
            .as_bytes(),
            "the metadata part carries no description, because the payload did not fit in one"
        );
        assert_eq!(
            &request[head..],
            want.as_slice(),
            "the whole object in one body"
        );
    }

    /// The listing and the tree a Drive delete walks, in the reference's query form: sorted keys, uppercase escapes, a space as `+`.
    #[test]
    fn a_drive_listing_is_the_reference_query() {
        let fake = Fake::start();
        let host = format!("127.0.0.1:{}", fake.port);
        let drive = drive_over(&fake);
        fake.push(200, r#"{"access_token":"atok","expires_in":3600}"#);
        fake.push(
            200,
            r#"{"files":[{"id":"f1","name":"streams~a~c2s~000000000.seg","description":"aGVsbG8="}]}"#,
        );
        let listed = drive.list("streams/a").expect("lists");
        assert_eq!(
            fake.text(1),
            format!(
                "GET /drive/files?fields=nextPageToken%2Cfiles%28id%2Cname%2Cdescription%29&includeItemsFromAllDrives=true&pageSize=1000&q=%27root%27+in+parents+and+trashed+%3D+false+and+name+contains+%27streams~a~%27&supportsAllDrives=true HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\n\r\n"
            )
        );
        assert_eq!(
            listed.iter().map(|at| at.name.as_str()).collect::<Vec<_>>(),
            vec!["c2s"],
            "one step of the tree, not the whole name"
        );
        assert!(
            listed[0].inline.is_none(),
            "a child one level down is not the object a read could take from the listing"
        );
        fake.push(
            200,
            r#"{"files":[{"id":"fold","name":"streams~a"},{"id":"f1","name":"streams~a~c2s~000000000.seg"}]}"#,
        );
        fake.push(200, "");
        fake.push(
            200,
            r#"{"files":[{"id":"f1","name":"streams~a~c2s~000000000.seg"}]}"#,
        );
        fake.push(200, "");
        drive.delete("streams/a").expect("empties the prefix");
        assert_eq!(
            fake.text(2),
            format!(
                "GET /drive/files?fields=nextPageToken%2Cfiles%28id%2Cname%2Cdescription%29&includeItemsFromAllDrives=true&pageSize=1000&q=%27root%27+in+parents+and+trashed+%3D+false+and+name+%3D+%27streams~a%27&supportsAllDrives=true HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\n\r\n"
            ),
            "the prefix itself is looked up before its children"
        );
        assert_eq!(
            fake.text(3),
            format!(
                "DELETE /drive/files/fold?supportsAllDrives=true HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\n\r\n"
            )
        );
        assert_eq!(
            fake.text(5),
            format!(
                "DELETE /drive/files/f1?supportsAllDrives=true HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atok\r\n\r\n"
            )
        );
        assert_eq!(fake.asks(), 6, "one token for the whole walk");
    }

    /// A Drive `403` is a rate limit only when its body says one of the reasons Google writes.
    #[test]
    fn a_drive_refusal_is_only_worth_waiting_out_when_it_names_a_limit() {
        for answer in [
            r#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#,
            r#"{"error":{"errors":[{"reason":"rateLimitExceeded"},{"reason":"other"}]}}"#,
            r#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#,
        ] {
            assert!(
                Drive::rate_limited(answer.as_bytes()),
                "{answer} is a limit the ladder can outlast"
            );
        }
        for refusal in [
            r#"{"error":{"errors":[{"reason":"accessNotConfigured"}]}}"#,
            r#"{"error":{"status":"PERMISSION_DENIED"}}"#,
            "not json",
        ] {
            assert!(
                !Drive::rate_limited(refusal.as_bytes()),
                "{refusal} is a refusal, and asking again would only cost"
            );
        }
    }

    /// One store per service and folder, shared by every session that names it, and a refusal by name for what this tree does not build.
    #[test]
    fn a_store_is_shared_by_the_settings_that_name_it() {
        let settings = templated(SIDES, 9);
        let first = settings.store(None).expect("opens");
        let second = settings.store(None).expect("opens again");
        assert!(
            Arc::ptr_eq(&first, &second),
            "two sessions on one folder share one lane pool"
        );
        let fronted = settings.store(Some(("127.0.0.1", 9))).expect("fronts");
        assert!(
            !Arc::ptr_eq(&first, &fronted),
            "and the address a session fronts through is part of the identity"
        );
        let mut secured = settings.clone();
        secured.security = "tls".to_owned();
        assert!(
            !Arc::ptr_eq(&first, &secured.store(None).expect("reopens")),
            "so does the transport's security"
        );
        let mut named = settings.clone();
        named.secrets = vec!["other".to_owned()];
        assert!(
            !Arc::ptr_eq(&first, &named.store(None).expect("reopens again")),
            "and so does every secret"
        );
        let mut reality = settings.clone();
        reality.reality = Some(Arc::new(RealityClientConfig {
            server_name: "a.example".to_owned(),
            public_key: [1; 32],
            short_id: [0; 8],
            fingerprint: "chrome".to_owned(),
            key_log: None,
        }));
        let mut rotated = reality.clone();
        rotated.reality = Some(Arc::new(RealityClientConfig {
            server_name: "a.example".to_owned(),
            public_key: [2; 32],
            short_id: [0; 8],
            fingerprint: "chrome".to_owned(),
            key_log: None,
        }));
        assert_ne!(
            share_key(&reality, None),
            share_key(&rotated, None),
            "a rotated REALITY key is a different store"
        );
        let mut other_name = reality.clone();
        other_name.reality_named = true;
        assert_ne!(
            share_key(&reality, None),
            share_key(&other_name, None),
            "and so is a named decoy"
        );
        let mut disk = settings.clone();
        disk.service = "local".to_owned();
        let folder = scratch("shared-local");
        disk.remote_folder = folder.display().to_string();
        disk.template = None;
        let opened = disk.store(None).expect("a folder");
        assert!(
            !Arc::ptr_eq(&opened, &disk.store(None).expect("the same folder")),
            "but a folder on disk is opened fresh each time, never pooled"
        );
        let mut unbuilt = settings.clone();
        unbuilt.service = "webdav".to_owned();
        assert!(
            unbuilt.store(None).is_err(),
            "and an unknown service is refused by name"
        );
        let mut short = settings.clone();
        short.service = "Google Drive".to_owned();
        short.secrets = vec!["cid".to_owned(), "csecret".to_owned()];
        assert!(
            Drive::build(&short, Http::new(None, None, false, None, 8)).is_err(),
            "Drive refuses a set without three secrets"
        );
        let mut blind = templated(SIDES, 9);
        blind.template = Some(
            crate::json::parse(
                r#"{"put":{"method":"PUT","url":"u"},"get":{"url":"u"},"delete":{"method":"DELETE","url":"u"},"list":{"url":"u","namesRegex":"no group"}}"#,
            )
            .expect("a template"),
        );
        assert!(
            Template::build(&blind, Http::new(None, None, false, None, 8)).is_err(),
            "and a template whose list names no capture group, because there would be nothing to read back"
        );
    }
    /// An S3 store aimed at the fake origin, with the two secrets the reference's minimum asks for.
    fn s3_over(fake: &Fake, bucket: &str) -> Settings {
        Settings {
            remote_folder: "root".to_owned(),
            service: "s3".to_owned(),
            secrets: vec!["AKID".to_owned(), "SECRET".to_owned()],
            template: None,
            s3: Some(S3Settings {
                endpoint: format!("http://127.0.0.1:{}", fake.port),
                region: "us-east-1".to_owned(),
                bucket: bucket.to_owned(),
                path_style: true,
            }),
            params: quick(),
            security: String::new(),
            tls: None,
            reality: None,
            reality_named: false,
        }
    }

    /// S3 is a path-style signed GET, and a directory page becomes the names under the prefix.
    #[test]
    fn s3_lists_a_path_style_bucket_and_signs_every_request() {
        let fake = Fake::start();
        fake.push(
            200,
            "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>root/streams/a/000.seg</Key></Contents><CommonPrefixes><Prefix>root/streams/a/sub/</Prefix></CommonPrefixes></ListBucketResult>",
        );
        let store = S3::build(
            &s3_over(&fake, "bucket"),
            Http::new(None, None, false, None, 8),
        )
        .expect("builds");
        let listed = store.list("streams/a").expect("lists");
        assert_eq!(
            listed
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["000.seg", "sub"]
        );
        let request = fake.text(0);
        assert!(
            request.starts_with(
                "GET /bucket/?delimiter=%2F&list-type=2&max-keys=1000&prefix=root%2Fstreams%2Fa%2F HTTP/1.1"
            ),
            "{request}"
        );
        assert!(
            request.contains("Authorization: AWS4-HMAC-SHA256 Credential=AKID/"),
            "{request}"
        );
        assert!(
            request.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
            "{request}"
        );
    }

    /// XML is decoded at the leaf, and a body that is not one complete `ListBucketResult` is no page at all.
    #[test]
    fn an_s3_page_decodes_leaf_entities_once_and_refuses_malformed_xml() {
        let page = S3Page::parse(
            br#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated><Contents><Key>root/a&amp;b/000.seg</Key></Contents><CommonPrefixes><Prefix>root/a&amp;b/sub/</Prefix></CommonPrefixes></ListBucketResult>"#,
        )
        .expect("one page");
        assert_eq!(page.keys, ["root/a&b/000.seg"]);
        assert_eq!(page.prefixes, ["root/a&b/sub/"]);
        for body in [
            &b""[..],
            b"<Error><Code>NoSuchKey</Code></Error>",
            b"<ListBucketResult><Contents><Key>a</Key>",
            b"<ListBucketResult><Contents></Contents></ListBucketResult>",
        ] {
            assert!(
                S3Page::parse(body).is_none(),
                "not a complete listing: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// A missing S3 key is the polling reader's `NotFound`, not a lane failure.
    #[test]
    fn s3_maps_a_missing_key_to_not_found() {
        let fake = Fake::start();
        fake.push(404, "<Error><Code>NoSuchKey</Code></Error>");
        let store = S3::build(
            &s3_over(&fake, "bucket"),
            Http::new(None, None, false, None, 8),
        )
        .expect("builds");
        assert_eq!(
            store.get("streams/a/000.seg").expect_err("absent").kind(),
            ErrorKind::NotFound
        );
    }

    /// The reference's S3 object is required, its service alias is canonical, and mutually exclusive XMUX bounds are refused.
    #[test]
    fn s3_and_xmux_are_read_with_the_reference_defaults() {
        let named =
            |text: &str| Settings::from_json(Some(&crate::json::parse(text).expect("parses")));
        assert!(
            named(r#"{"xdriveSettings":{"service":"s3","remoteFolder":"root"}}"#).is_none(),
            "s3 without an s3 object is not a store"
        );
        let drive = named(
            r#"{"xdriveSettings":{"service":"Google Drive","remoteFolder":"root","secrets":["a","b","c"]}}"#,
        )
        .expect("the deprecated spelling");
        assert_eq!(drive.service, "google-drive");
        for body in [
            r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/x","xmux":{"maxConnections":2,"maxConcurrency":"1-4"}}}"#,
            r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/x","xmux":{"maxConnections":"1-4","maxConcurrency":2}}}"#,
            r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/x","xmux":{"maxConnections":{"from":1,"to":2},"maxConcurrency":2}}}"#,
        ] {
            assert!(
                named(body).is_none(),
                "the reference refuses both connection bounds at once: {body}"
            );
        }
        assert!(
            named(r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/x","xmux":{"maxConnections":"1-4"}}}"#).is_some(),
            "one range bound is accepted"
        );
        assert!(
            named(r#"{"xdriveSettings":{"service":"local","remoteFolder":"/tmp/x","xmux":{"maxConnections":3,"maxConcurrency":"-2"}}}"#).is_some(),
            "a negative bound is a sentinel, not a second bound"
        );
        let s3 = named(
            r#"{"xdriveSettings":{"service":"s3","remoteFolder":"root","secrets":["ak","sk"],"s3":{"endpoint":"https://s3.example","bucket":"store"}}}"#,
        )
        .expect("path style is the default");
        assert!(s3.s3.as_ref().expect("s3").path_style);
        let built = S3::build(&s3, Http::new(None, None, false, None, 8)).expect("builds");
        assert_eq!(built.authority, "s3.example");
        assert_eq!(built.base_path, "/store/");
        let virtual_hosted = named(
            r#"{"xdriveSettings":{"service":"s3","remoteFolder":"root","secrets":["ak","sk"],"s3":{"endpoint":"https://s3.example","bucket":"store","pathStyle":false}}}"#,
        )
        .expect("virtual-hosted addressing is read");
        assert!(!virtual_hosted.s3.as_ref().expect("s3").path_style);
        let built =
            S3::build(&virtual_hosted, Http::new(None, None, false, None, 8)).expect("builds");
        assert_eq!(built.authority, "store.s3.example");
        assert_eq!(built.base_path, "/");
    }

    /// REALITY is the store lane's handshake, and an unnamed decoy takes the host the endpoint names.
    #[test]
    fn a_reality_store_lane_keeps_its_identity() {
        let settings = Settings::from_json(Some(&crate::json::parse(
            r#"{"security":"reality","realitySettings":{"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":""},"xdriveSettings":{"service":"template","remoteFolder":"folder","template":{"put":{"method":"PUT","url":"u"},"get":{"url":"u"},"delete":{"method":"DELETE","url":"u"},"list":{"url":"u","namesRegex":"(a)"}}}}"#,
        ).expect("parses"))).expect("names a store");
        assert_eq!(settings.security, "reality");
        assert!(settings.reality.is_some());
        assert!(!settings.reality_named);
        assert!(settings.store(None).is_ok());
    }

    /// A two-step template calls the href the first answer names, with the payload and without the service's auth.
    #[test]
    fn a_template_href_carries_the_second_leg() {
        let fake = Fake::start();
        let text = format!(
            r#"{{"put":{{"method":"PUT","url":"http://127.0.0.1:{p}/start/{{name}}","hrefPath":"meta.href","hrefMethod":"PUT"}},"get":{{"url":"http://127.0.0.1:{p}/o/{{name}}"}},"delete":{{"method":"DELETE","url":"http://127.0.0.1:{p}/o/{{name}}"}},"list":{{"url":"http://127.0.0.1:{p}/l/{{prefix}}","namesRegex":"([a-z0-9./~-]+)"}}}}"#,
            p = fake.port
        );
        let store = Template::build(
            &templated(&text, fake.port),
            Http::new(None, None, false, None, 8),
        )
        .expect("builds");
        fake.push(
            200,
            &format!(
                r#"{{"meta":{{"href":"http://127.0.0.1:{}/o/abc"}}}}"#,
                fake.port
            ),
        );
        fake.push(200, "");
        store.put("abc", b"x").expect("puts through the href");
        assert_eq!(fake.asks(), 2);
        assert!(
            fake.text(0).starts_with("PUT /start/abc HTTP/1.1"),
            "{}",
            fake.text(0)
        );
        let second = fake.text(1);
        assert!(second.starts_with("PUT /o/abc HTTP/1.1"), "{second}");
        assert!(second.ends_with("\r\n\r\nx"), "{second}");
    }
}
