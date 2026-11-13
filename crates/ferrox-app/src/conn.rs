//! The transport-agnostic stream a proxy connection rides, and the two roles that produce
//! one: a listener that accepts it and a dialer that connects it.
//!
//! Until now the app spoke `std::net::TcpStream` end to end, so a config naming a Unix
//! domain socket had nowhere to bind or dial. `Connection` is the seam that lets an `AF_UNIX`
//! stream stand in for a TCP one wherever a connection is carried: it forwards the reads,
//! writes and half-closes the relay needs, keeps the same read and write timeouts the engine
//! arms a leg with, and — because `TCP_NODELAY` has no socket analogue — makes the no-delay
//! request a documented no-op on a Unix stream rather than a silent failure.
//!
//! The Unix arm is built on both host families that name a socket path in a config. On a Unix
//! host it is `std`'s `UnixStream`; on Windows `std` has the type but keeps it behind the
//! unstable `windows_unix_domain_sockets` feature, which a stable build cannot name, so there the
//! same arm is a `SOCK_STREAM` socket in the `AF_UNIX` family, opened and driven through
//! `WinSock` (`winunix` below) the way `std` drives its own sockets. What neither host gives for
//! free is carried by the seam: `std` has no timeout setter for a Unix stream at all, and
//! `WinSock` spells the wait bound in milliseconds rather than a `timeval`. The `SOCK_STREAM`
//! shape and the Windows 10 build 17063 floor are the ones `std`'s own Windows unix module names.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[cfg(unix)]
use libc::{SO_RCVTIMEO, SO_SNDTIMEO};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(any(unix, windows))]
use std::path::PathBuf;
#[cfg(windows)]
use winunix::{
    get_socket_timeout, set_socket_timeout, unix_peek, UnixListener, UnixStream, SO_RCVTIMEO,
    SO_SNDTIMEO,
};

/// A live proxy connection: a TCP stream, that stream under a post-TLS write mask, or an
/// `AF_UNIX` stream on either host family, carried the same way. Every method forwards to
/// whichever it holds, so the relay, the carriers and the handshake never learn which family they
/// were handed.
#[derive(Debug)]
pub(crate) enum Connection {
    Tcp(TcpStream),
    Masked(Masked),
    /// The same stream with a flow's counters and policy above it; every read and write reaches
    /// the socket through the meter, and a clone shares the counters rather than starting new ones.
    Metered(Metered),
    /// A stream whose peer is the one a PROXY protocol header reported rather than the socket's
    /// own peer: reads and writes still reach the socket, but routing sees the reported source.
    Proxied {
        inner: Box<Connection>,
        peer: SocketAddr,
    },
    /// The level policy a flow's account names, above a stream that counts no bytes itself.
    Policied {
        inner: Box<Connection>,
        flow: crate::policy::Flow,
    },
    #[cfg(any(unix, windows))]
    Unix(UnixStream),
}

/// A connection under the stats manager: the inner stream keeps its family and mask, while the
/// meter counts each direction and carries the policy the flow's level names.
#[derive(Debug)]
pub(crate) struct Metered {
    inner: Box<Connection>,
    meter: crate::stats::Meter,
}

/// A TCP stream with the `finalmask` chain under it, which is what the reference's wrapped conn
/// is: timeouts, addresses and teardown reach the socket itself, while writes pass through the
/// chain and, when a codec stage is armed, reads decode through a second chain opened for the same
/// side. Both chains are shared behind a lock because a cloned handle must share the same stream
/// state, and because a relay leg holds its stream by shared reference.
#[derive(Debug)]
pub(crate) struct Masked {
    stream: TcpStream,
    chain: std::sync::Arc<std::sync::Mutex<ferrox_core::finalmask::Chain>>,
    read_chain: Option<std::sync::Arc<std::sync::Mutex<ferrox_core::finalmask::Chain>>>,
    header: Option<std::sync::Arc<std::sync::Mutex<ferrox_core::finalmask::HeaderRun>>>,
    xmc: Option<std::sync::Arc<XmcState>>,
}

#[derive(Debug)]
struct XmcState {
    config: ferrox_core::finalmask::xmc::Config,
    role: ferrox_core::finalmask::MaskRole,
    session: XmcSlot,
}

type XmcSession<R, W> = ferrox_core::finalmask::xmc::Session<R, W>;
type Xmc = std::sync::Arc<XmcSession<DeadlineReader<TcpStream>, XmcWriter>>;
type XmcSlot = std::sync::OnceLock<Result<Xmc, String>>;

#[derive(Debug)]
struct XmcWriter {
    stream: TcpStream,
    chain: std::sync::Arc<std::sync::Mutex<ferrox_core::finalmask::Chain>>,
}

/// A handshake that outlives a peer's interest is a stalled connection, not a slow one; the
/// reference's own bound is two minutes, and an admission shortens it to what the lane has left.
const XMC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// The reference's two minutes, unless an admission has less of its budget left to spend.
fn xmc_deadline(left: Option<Duration>) -> Duration {
    left.map_or(XMC_HANDSHAKE_TIMEOUT, |left| {
        left.min(XMC_HANDSHAKE_TIMEOUT)
    })
}

/// A read source whose clock can be re-armed for one read, so a handshake can hold a single
/// deadline across every read it makes instead of restarting a per-read timeout.
trait ReadClock: std::io::Read {
    fn arm(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl ReadClock for TcpStream {
    fn arm(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

/// One absolute deadline shared by the reader a handshake reads through.
#[derive(Debug, Clone, Default)]
struct HandshakeDeadline(std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>);

impl HandshakeDeadline {
    fn begin(budget: Duration) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(Some(
            std::time::Instant::now() + budget,
        ))))
    }

    fn gate(&self) -> std::sync::MutexGuard<'_, Option<std::time::Instant>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn end(&self) {
        *self.gate() = None;
    }
}

/// Reads never wait past the shared deadline: each read is clocked to the time that is left,
/// and a deadline that has passed fails the read instead of arming another clock.
#[derive(Debug)]
struct DeadlineReader<R> {
    reader: R,
    deadline: HandshakeDeadline,
}

impl<R: ReadClock> DeadlineReader<R> {
    fn new(reader: R, deadline: HandshakeDeadline) -> Self {
        Self { reader, deadline }
    }
}

impl<R: ReadClock> std::io::Read for DeadlineReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(at) = *self.deadline.gate() {
            let left = at.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "xmc: handshake deadline passed",
                ));
            }
            self.reader.arm(Some(left.max(Duration::from_millis(1))))?;
        }
        self.reader.read(output)
    }
}

impl std::io::Write for XmcWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Ok(mut chain) = self.chain.lock() else {
            return Err(std::io::Error::other("the mask chain is gone"));
        };
        chain.write(&mut &self.stream, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&self.stream).flush()
    }
}

impl XmcState {
    fn session(
        &self,
        stream: &TcpStream,
        chain: &std::sync::Arc<std::sync::Mutex<ferrox_core::finalmask::Chain>>,
    ) -> io::Result<Xmc> {
        let result = self.session.get_or_init(|| {
            let saved_read = stream.read_timeout().ok().flatten();
            let saved_write = stream.write_timeout().ok().flatten();
            let _ = stream.set_read_timeout(Some(XMC_HANDSHAKE_TIMEOUT));
            let _ = stream.set_write_timeout(Some(XMC_HANDSHAKE_TIMEOUT));
            let result = (|| {
                let deadline =
                    HandshakeDeadline::begin(xmc_deadline(crate::budgets::handshake_cap()));
                let reader = DeadlineReader::new(stream.try_clone()?, deadline.clone());
                let writer = XmcWriter {
                    stream: stream.try_clone()?,
                    chain: std::sync::Arc::clone(chain),
                };
                let session = match self.role {
                    ferrox_core::finalmask::MaskRole::Client => {
                        XmcSession::client(reader, writer, &self.config, stream.peer_addr().ok())?
                    }
                    ferrox_core::finalmask::MaskRole::Server => {
                        XmcSession::server(reader, writer, &self.config)?
                    }
                };
                deadline.end();
                Ok::<_, io::Error>(std::sync::Arc::new(session))
            })();
            let _ = stream.set_read_timeout(saved_read);
            let _ = stream.set_write_timeout(saved_write);
            result.map_err(|error| error.to_string())
        });
        result
            .as_ref()
            .map(std::sync::Arc::clone)
            .map_err(|error| io::Error::other(error.clone()))
    }
}

impl Masked {
    /// Finish the xmc handshake before a relay lane can read; the blocking path owns it.
    pub(crate) fn complete_xmc(&self) -> io::Result<()> {
        self.xmc_session().map(|_| ())
    }

    fn xmc_session(&self) -> io::Result<Option<Xmc>> {
        self.ensure_header()?;
        match &self.xmc {
            Some(state) => state.session(&self.stream, &self.chain).map(Some),
            None => Ok(None),
        }
    }
}

/// The clock the captured-variable store stamps and expires with; the core takes it as a value so
/// that a library read stays deterministic.
fn mask_clock() -> Duration {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed()
}

impl Masked {
    /// Run the configured handshake before the first byte of the session moves.
    fn ensure_header(&self) -> io::Result<()> {
        let Some(header) = &self.header else {
            return Ok(());
        };
        let Ok(mut run) = header.lock() else {
            return Err(io::Error::other("the header handshake is gone"));
        };
        if run.is_done() {
            return Ok(());
        }
        // The relay arms a one-millisecond poll clock; the handshake's reads run to one absolute deadline instead, so a dribbled byte cannot restart the budget, and the clock comes back.
        let prior = self.stream.read_timeout().ok();
        let mut source = HeaderWire {
            chain: &self.chain,
            read_chain: self.read_chain.as_deref(),
            stream: &self.stream,
            until: Instant::now() + crate::budgets::handshake(),
        };
        let result = run.handshake(&mut source, mask_clock());
        if let Some(prior) = prior {
            let _ = self.stream.set_read_timeout(prior);
        }
        result
    }

    /// The chain's write over a shared handle: the socket side is `&TcpStream`, which `std` also
    /// makes a writer, so a leg drained by reference masks exactly as one moved by value.
    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(session) = self.xmc_session()? {
            return (&*session).write(buf);
        }
        // A stage never panics while held, so a poisoned lock is a broken process, not a wire state.
        let Ok(mut chain) = self.chain.lock() else {
            return Err(io::Error::other("the mask chain is gone"));
        };
        chain.write(&mut &self.stream, buf)
    }

    // A chain is a byte writer, so a gathered write answers its first run and the caller's loop hands the rest over as the write it would have been.
    fn send_vectored(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        bufs.iter()
            .find(|part| !part.is_empty())
            .map_or(Ok(0), |first| self.send(first))
    }

    /// Encode a whole frame and put it on the wire in one call, the shape a blocking relay write has.
    #[cfg(unix)]
    fn send_ready(&self, parts: &[&[u8]]) -> io::Result<usize> {
        let Ok(mut chain) = self.chain.lock() else {
            return Err(io::Error::other("the mask chain is gone"));
        };
        let mut total = 0usize;
        for part in parts {
            total += chain.write(&mut &self.stream, part)?;
        }
        Ok(total)
    }

    /// A read through the codec chain, or the socket itself when no stage transforms bytes.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(session) = self.xmc_session()? {
            return (&*session).read(buf);
        }
        self.ensure_header()?;
        let Some(chain) = &self.read_chain else {
            return (&self.stream).read(buf);
        };
        let Ok(mut chain) = chain.lock() else {
            return Err(io::Error::other("the mask chain is gone"));
        };
        let mut source = &self.stream;
        chain.read(&mut source, buf)
    }

    fn recv_vectored(&self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match bufs.iter_mut().find(|part| !part.is_empty()) {
            Some(first) => self.recv(&mut first[..]),
            None => Ok(0),
        }
    }

    /// One nonblocking read through the codec chain. The handshake is the blocking path's: a
    /// pending header answers `WouldBlock` instead of running it, so a readiness lane never waits.
    #[cfg(unix)]
    fn recv_ready(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(state) = &self.xmc {
            if state.session.get().is_none() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            return self.recv(buf);
        }
        if let Some(header) = &self.header {
            let Ok(run) = header.lock() else {
                return Err(io::Error::other("the header handshake is gone"));
            };
            if !run.is_done() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let Some(chain) = &self.read_chain else {
            return recv_ready(&self.stream, buf);
        };
        let Ok(mut chain) = chain.lock() else {
            return Err(io::Error::other("the mask chain is gone"));
        };
        chain.read(&mut ReadySource(&self.stream), buf)
    }

    /// Look ahead through the codec's pending plaintext without consuming it.
    fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.xmc.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "an xmc stream cannot be peeked",
            ));
        }
        self.ensure_header()?;
        let Some(chain) = &self.read_chain else {
            return self.stream.peek(buf);
        };
        let Ok(mut chain) = chain.lock() else {
            return Err(io::Error::other("the mask chain is gone"));
        };
        let mut source = &self.stream;
        chain.peek(&mut source, buf)
    }
}

/// A read that never waits, for the codec decoder's inner source.
#[cfg(unix)]
struct ReadySource<'a>(&'a TcpStream);

#[cfg(unix)]
impl Read for ReadySource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        recv_ready(self.0, buf)
    }
}

/// The handshake writes through the stages beneath its mask, as the reference's wrapped conn does,
/// while a read stays the socket's own because a fragment writes and never decodes.
struct HeaderWire<'a> {
    chain: &'a std::sync::Mutex<ferrox_core::finalmask::Chain>,
    read_chain: Option<&'a std::sync::Mutex<ferrox_core::finalmask::Chain>>,
    stream: &'a TcpStream,
    until: Instant,
}

impl std::io::Write for HeaderWire<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Ok(mut chain) = self.chain.lock() else {
            return Err(std::io::Error::other("the mask chain is gone"));
        };
        let mut source = self.stream;
        chain.write(&mut source, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl std::io::Read for HeaderWire<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the header handshake deadline passed",
            ));
        }
        self.stream
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))?;
        let Some(chain) = self.read_chain else {
            return (&*self.stream).read(buf);
        };
        let Ok(mut chain) = chain.lock() else {
            return Err(std::io::Error::other("the mask chain is gone"));
        };
        let mut source = self.stream;
        chain.read(&mut source, buf)
    }
}

impl Connection {
    /// The same socket with this chain's clone beneath it, armed for a dialling client; `None`, or a
    /// chain with no stage, leaves the stream exactly as it came, which is the ordinary case.
    pub(crate) fn with_mask(self, mask: Option<&ferrox_core::finalmask::Chain>) -> Self {
        self.with_mask_role(mask, ferrox_core::finalmask::MaskRole::Client)
    }

    /// The same socket with the chain armed for the side this connection plays. A codec's directions
    /// are asymmetric and a header handshake expects the other side's sequences, so the role matters.
    pub(crate) fn with_mask_role(
        self,
        mask: Option<&ferrox_core::finalmask::Chain>,
        role: ferrox_core::finalmask::MaskRole,
    ) -> Self {
        match (self, mask.filter(|chain| !chain.is_empty())) {
            (Connection::Tcp(stream), Some(chain)) => {
                let local = stream.local_addr().ok();
                let remote = stream.peer_addr().ok();
                let header = chain.header().cloned().map(|header| {
                    std::sync::Arc::new(std::sync::Mutex::new(header.open(
                        role,
                        local,
                        remote,
                        mask_clock(),
                    )))
                });
                let opened = chain.open(role);
                let xmc = chain.xmc().map(|config| {
                    std::sync::Arc::new(XmcState {
                        config: config.clone(),
                        role,
                        session: std::sync::OnceLock::new(),
                    })
                });
                Connection::Masked(Masked {
                    stream,
                    chain: std::sync::Arc::new(std::sync::Mutex::new(opened.write)),
                    read_chain: opened
                        .read
                        .map(|read| std::sync::Arc::new(std::sync::Mutex::new(read))),
                    header,
                    xmc,
                })
            }
            (Connection::Metered(metered), mask) => Connection::Metered(Metered {
                inner: Box::new(metered.inner.with_mask_role(mask, role)),
                meter: metered.meter,
            }),
            (Connection::Proxied { inner, peer }, mask) => Connection::Proxied {
                inner: Box::new(inner.with_mask_role(mask, role)),
                peer,
            },
            (Connection::Policied { inner, flow }, mask) => Connection::Policied {
                inner: Box::new(inner.with_mask_role(mask, role)),
                flow,
            },
            (this, _) => this,
        }
    }

    /// The same stream with the peer a PROXY protocol header reported, which routing reads in
    /// place of the socket's own peer.
    pub(crate) fn with_peer(self, peer: SocketAddr) -> Self {
        Connection::Proxied {
            inner: Box::new(self),
            peer,
        }
    }

    /// Complete a pending header handshake on the blocking path, before a readiness lane asks.
    /// A readiness read never runs it, so admission must finish it first.
    pub(crate) fn complete_header(&self) -> io::Result<()> {
        match self {
            Connection::Masked(masked) => masked.ensure_header(),
            Connection::Metered(metered) => metered.inner.complete_header(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.complete_header()
            }
            Connection::Tcp(_) => Ok(()),
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Ok(()),
        }
    }

    /// Whether a write to this stream must pass the chain, which a descriptor-level fast path
    /// addressing the socket would skip. Reads, teardown and the census are unaffected by it.
    pub(crate) fn masked(&self) -> bool {
        match self {
            Connection::Masked(_) => true,
            Connection::Metered(metered) => metered.inner.masked(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.masked()
            }
            Connection::Tcp(_) => false,
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => false,
        }
    }

    /// Finish an xmc handshake on the masking layer, whichever wrapper holds it.
    pub(crate) fn complete_xmc(&self) -> io::Result<()> {
        match self {
            Connection::Masked(masked) => masked.complete_xmc(),
            Connection::Metered(metered) => metered.inner.complete_xmc(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.complete_xmc()
            }
            Connection::Tcp(_) => Ok(()),
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Ok(()),
        }
    }

    /// Whether a descriptor-level fast path would skip the meter above this stream.
    pub(crate) fn metered(&self) -> bool {
        match self {
            Connection::Metered(metered) => metered.meter.counts(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.metered()
            }
            Connection::Masked(_) => false,
            Connection::Tcp(_) => false,
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => false,
        }
    }

    /// Put this flow's counters above the stream. A stream that already carries a meter keeps
    /// every counter and adds the newer one's, so the inbound and the account both count.
    pub(crate) fn with_meter(self, meter: crate::stats::Meter) -> Self {
        if meter.is_empty() {
            return self;
        }
        match self {
            Connection::Metered(metered) => Connection::Metered(Metered {
                inner: metered.inner,
                meter: metered.meter.merged(meter),
            }),
            inner => Connection::Metered(Metered {
                inner: Box::new(inner),
                meter,
            }),
        }
    }

    /// Put this flow's level policy above the stream without counting its bytes.
    pub(crate) fn with_policy(self, flow: Option<crate::policy::Flow>) -> Self {
        let Some(flow) = flow else {
            return self;
        };
        match self {
            Connection::Policied { inner, .. } => Connection::Policied { inner, flow },
            Connection::Proxied { inner, peer } => Connection::Proxied {
                inner: Box::new(inner.with_policy(Some(flow))),
                peer,
            },
            inner => Connection::Policied {
                inner: Box::new(inner),
                flow,
            },
        }
    }

    /// The policy a flow's level names, if one is above this stream.
    pub(crate) fn policy(&self) -> Option<crate::policy::Flow> {
        match self {
            Connection::Metered(metered) => metered.inner.policy(),
            Connection::Proxied { inner, .. } => inner.policy(),
            Connection::Policied { flow, .. } => Some(*flow),
            Connection::Masked(_) | Connection::Tcp(_) => None,
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => None,
        }
    }
}

impl From<TcpStream> for Connection {
    fn from(stream: TcpStream) -> Self {
        Connection::Tcp(stream)
    }
}

#[cfg(any(unix, windows))]
impl From<UnixStream> for Connection {
    fn from(stream: UnixStream) -> Self {
        Connection::Unix(stream)
    }
}

/// The raw descriptor the vectored-write and splice fast paths address. Every arm is a socket, so
/// `writev`/`splice` reach the queue identically and a masked stream answers with the socket its
/// chain writes through; those paths are `#[cfg(target_os = "linux")]`, `AsRawFd` is their Unix
/// spelling, and the `AF_UNIX` arm answers with the same descriptor its reads and writes go to.
#[cfg(unix)]
impl std::os::fd::AsRawFd for Connection {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        match self {
            Connection::Tcp(stream) => stream.as_raw_fd(),
            Connection::Masked(masked) => masked.stream.as_raw_fd(),
            Connection::Metered(metered) => metered.inner.as_raw_fd(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.as_raw_fd()
            }
            Connection::Unix(stream) => stream.as_raw_fd(),
        }
    }
}

/// The same descriptor under the Windows spelling, so `census::handle` reads a `Connection` the
/// way it reads a `TcpStream` there. Every Windows arm is a `WinSock` socket — a `SOCK_STREAM` in
/// the `AF_UNIX` family is still a `SOCKET` — so this forwards whichever handle the leg holds. The
/// census only names it, so no TCP-only query is ever issued against the unix arm.
#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for Connection {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        match self {
            Connection::Tcp(stream) => stream.as_raw_socket(),
            Connection::Masked(masked) => masked.stream.as_raw_socket(),
            Connection::Metered(metered) => metered.inner.as_raw_socket(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.as_raw_socket()
            }
            Connection::Unix(stream) => stream.as_raw_socket(),
        }
    }
}

/// The record-boundary marker the TLS layer needs of a stream it seals records onto. `TcpStream`
/// impls it in `ferrox-core`; a `Connection` forwards to whichever family it holds, so a TLS
/// session over either arm keeps the same record alignment the TCP path had.
impl ferrox_core::tls::RecordAlignment for Connection {}

impl Connection {
    /// Finish a masked handshake where the lane can spend the handshake budget, so a readiness
    /// read never runs one and a split header is not read under the relay's poll clock.
    pub(crate) fn start_mask(&self) -> io::Result<()> {
        match self {
            Connection::Masked(masked) => masked.ensure_header(),
            Connection::Metered(metered) => metered.inner.start_mask(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.start_mask()
            }
            Connection::Tcp(_) => Ok(()),
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Ok(()),
        }
    }

    /// One relay read that never waits: an empty socket answers `WouldBlock` at once, and the lane
    /// parks on the descriptor its timeout names instead of spending the poll quantum in a worker.
    pub(crate) fn read_ready(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            let result = match self {
                Connection::Tcp(stream) => recv_ready(stream, buf),
                Connection::Masked(masked) => masked.recv_ready(buf),
                Connection::Metered(metered) => match metered.inner.read_ready(buf) {
                    Ok(n) => {
                        metered.meter.read(n);
                        Ok(n)
                    }
                    Err(error) => Err(error),
                },
                Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                    inner.read_ready(buf)
                }
                Connection::Unix(stream) => recv_ready(stream, buf),
            };
            if result.as_ref().is_err_and(crate::proxy::is_descriptor_wait) {
                crate::proxy::note_wait_fd(std::os::fd::AsRawFd::as_raw_fd(&*self));
            }
            result
        }
        #[cfg(not(unix))]
        {
            self.read(buf)
        }
    }
}

impl Connection {
    /// One relay write that never waits: a socket with no room answers `WouldBlock` at once, and the
    /// lane parks on the descriptor's writability instead of spending the send clock in a worker.
    #[cfg(unix)]
    pub(crate) fn write_ready(&mut self, parts: &[&[u8]]) -> io::Result<usize> {
        let result = match self {
            Connection::Tcp(stream) => sendmsg_ready(stream, parts),
            Connection::Masked(masked) if masked.xmc.is_some() => parts
                .iter()
                .copied()
                .find(|part| !part.is_empty())
                .map_or(Ok(0), |first| masked.send(first)),
            Connection::Masked(masked) => masked.send_ready(parts),
            Connection::Metered(metered) => match metered.inner.write_ready(parts) {
                Ok(n) => {
                    metered.meter.write(n);
                    Ok(n)
                }
                Err(error) => Err(error),
            },
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.write_ready(parts)
            }
            Connection::Unix(stream) => sendmsg_ready(stream, parts),
        };
        if result.as_ref().is_err_and(crate::proxy::is_descriptor_wait) {
            crate::proxy::note_wait_fd_write(std::os::fd::AsRawFd::as_raw_fd(&*self));
        }
        result
    }
}

/// `sendmsg` with `MSG_DONTWAIT`, the per-call form of a non-blocking write: the descriptor keeps the
/// blocking shape every other arm writes through.
#[cfg(unix)]
fn sendmsg_ready<S: std::os::fd::AsRawFd>(stream: &S, parts: &[&[u8]]) -> io::Result<usize> {
    const CAP: usize = 16;
    if parts.len() > CAP {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let mut made = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; CAP];
    let mut count = 0usize;
    for part in parts.iter().copied().filter(|part| !part.is_empty()) {
        made[count] = libc::iovec {
            iov_base: part.as_ptr().cast_mut().cast(),
            iov_len: part.len(),
        };
        count += 1;
    }
    // SAFETY: a zeroed `msghdr` names no address, control or segment, and the caller's slices outlive the call.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = made.as_mut_ptr();
    #[cfg(target_os = "linux")]
    {
        message.msg_iovlen = count;
    }
    #[cfg(not(target_os = "linux"))]
    {
        message.msg_iovlen = i32::try_from(count).unwrap_or(i32::MAX);
    }
    let fd = stream.as_raw_fd();
    #[cfg(target_os = "linux")]
    let sent = unsafe {
        libc::sendmsg(
            fd,
            std::ptr::from_ref(&message),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    #[cfg(target_os = "linux")]
    let error = (sent < 0).then(io::Error::last_os_error);
    // Darwin ignores `MSG_DONTWAIT` on a full send buffer, so the descriptor flag is restored before the borrow ends.
    #[cfg(not(target_os = "linux"))]
    let (sent, error) = {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let armed =
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0;
        if armed {
            let sent = unsafe { libc::sendmsg(fd, std::ptr::from_ref(&message), 0) };
            let error = (sent < 0).then(io::Error::last_os_error);
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
            (sent, error)
        } else {
            (-1, Some(io::Error::last_os_error()))
        }
    };
    match error {
        Some(error) => Err(error),
        None => Ok(sent as usize),
    }
}

/// `recv` with `MSG_DONTWAIT`, the per-call form of a non-blocking read: the descriptor keeps the
/// blocking shape and read timeout the rest of the relay arms on it.
#[cfg(unix)]
fn recv_ready<S: std::os::fd::AsRawFd>(stream: &S, buf: &mut [u8]) -> io::Result<usize> {
    let count = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = match self {
            Connection::Tcp(stream) => stream.read(buf),
            Connection::Masked(masked) => masked.recv(buf),
            Connection::Metered(metered) => match metered.inner.read(buf) {
                Ok(n) => {
                    metered.meter.read(n);
                    Ok(n)
                }
                Err(error) => Err(error),
            },
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.read(buf)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.read(buf),
        };
        // A relay step's timed-out read names the socket the lane can wait on instead of polling the clock.
        if result.as_ref().is_err_and(crate::proxy::is_descriptor_wait) {
            crate::proxy::note_wait_fd(crate::proxy::wait_key(&*self));
        }
        result
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        let result = match self {
            Connection::Tcp(stream) => stream.read_vectored(bufs),
            Connection::Masked(masked) => masked.recv_vectored(bufs),
            Connection::Metered(metered) => match metered.inner.read_vectored(bufs) {
                Ok(n) => {
                    metered.meter.read(n);
                    Ok(n)
                }
                Err(error) => Err(error),
            },
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.read_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.read_vectored(bufs),
        };
        if result.as_ref().is_err_and(crate::proxy::is_descriptor_wait) {
            crate::proxy::note_wait_fd(crate::proxy::wait_key(&*self));
        }
        result
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.write(buf),
            Connection::Masked(masked) => masked.send(buf),
            Connection::Metered(metered) => {
                let n = metered.inner.write(buf)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.write(buf)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.write(buf),
        }
    }

    // One `writev` for a frame's parts on either family; `write_vectored` is `writev` on a socket, so the TCP coalescing is the same call, not a relocation.
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.write_vectored(bufs),
            Connection::Masked(masked) => masked.send_vectored(bufs),
            Connection::Metered(metered) => {
                let n = metered.inner.write_vectored(bufs)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.write_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.write_vectored(bufs),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.flush(),
            Connection::Masked(masked) => match masked.xmc_session() {
                Ok(Some(session)) => (&*session).flush(),
                Ok(None) => masked.stream.flush(),
                Err(error) => Err(error),
            },
            Connection::Metered(metered) => metered.inner.flush(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => inner.flush(),
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.flush(),
        }
    }
}

// A socket answers on a shared descriptor, so `std` impls `Read`/`Write` for `&TcpStream` and the relay drains each leg by shared reference; `&Connection` does the same for whichever arm it holds, and a masked leg's writes reach its chain the same way.
impl Read for &Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.read(buf)
            }
            Connection::Masked(masked) => masked.recv(buf),
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                match inner.read(buf) {
                    Ok(n) => {
                        metered.meter.read(n);
                        Ok(n)
                    }
                    Err(error) => Err(error),
                }
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.read(buf)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.read(buf)
            }
        };
        if result.as_ref().is_err_and(crate::proxy::is_descriptor_wait) {
            crate::proxy::note_wait_fd(crate::proxy::wait_key(*self));
        }
        result
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        let result = match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.read_vectored(bufs)
            }
            Connection::Masked(masked) => masked.recv_vectored(bufs),
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                match inner.read_vectored(bufs) {
                    Ok(n) => {
                        metered.meter.read(n);
                        Ok(n)
                    }
                    Err(error) => Err(error),
                }
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.read_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.read_vectored(bufs)
            }
        };
        if result.as_ref().is_err_and(crate::proxy::is_descriptor_wait) {
            crate::proxy::note_wait_fd(crate::proxy::wait_key(*self));
        }
        result
    }
}

impl Write for &Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.write(buf)
            }
            Connection::Masked(masked) => masked.send(buf),
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                let n = inner.write(buf)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.write(buf)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.write(buf)
            }
        }
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.write_vectored(bufs)
            }
            Connection::Masked(masked) => masked.send_vectored(bufs),
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                let n = inner.write_vectored(bufs)?;
                metered.meter.write(n);
                Ok(n)
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.write_vectored(bufs)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.write_vectored(bufs)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            Connection::Tcp(stream) => {
                let mut inner = stream;
                inner.flush()
            }
            Connection::Masked(masked) => {
                let mut inner = &masked.stream;
                inner.flush()
            }
            Connection::Metered(ref metered) => {
                let mut inner = &*metered.inner;
                inner.flush()
            }
            Connection::Proxied { ref inner, .. } | Connection::Policied { ref inner, .. } => {
                let mut inner = &**inner;
                inner.flush()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => {
                let mut inner = stream;
                inner.flush()
            }
        }
    }
}

impl Connection {
    /// Whether a codec lies between this connection and the socket. A masked frame cannot report a
    /// partial plaintext take — its encoded length is not the caller's — so the relay keeps the blocking
    /// `write_slices` for it instead of the nonblocking shortcut.
    #[cfg(unix)]
    pub(crate) fn has_mask(&self) -> bool {
        match self {
            Connection::Masked(_) => true,
            Connection::Metered(metered) => metered.inner.has_mask(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.has_mask()
            }
            Connection::Tcp(_) => false,
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => false,
        }
    }

    /// A second handle to the same socket, so a relay reads on one leg and writes on the other. A
    /// masked handle shares its chain rather than starting a fresh one, because the reference's
    /// wrapped conn counts writes once per connection, not once per handle.
    pub(crate) fn try_clone(&self) -> io::Result<Connection> {
        match self {
            Connection::Tcp(stream) => stream.try_clone().map(Connection::Tcp),
            Connection::Masked(masked) => masked.stream.try_clone().map(|stream| {
                Connection::Masked(Masked {
                    stream,
                    chain: std::sync::Arc::clone(&masked.chain),
                    read_chain: masked.read_chain.as_ref().map(std::sync::Arc::clone),
                    header: masked.header.as_ref().map(std::sync::Arc::clone),
                    xmc: masked.xmc.as_ref().map(std::sync::Arc::clone),
                })
            }),
            Connection::Metered(metered) => metered.inner.try_clone().map(|inner| {
                Connection::Metered(Metered {
                    inner: Box::new(inner),
                    meter: metered.meter.clone(),
                })
            }),
            Connection::Proxied { inner, peer } => {
                inner.try_clone().map(|inner| Connection::Proxied {
                    inner: Box::new(inner),
                    peer: *peer,
                })
            }
            Connection::Policied { inner, flow } => {
                inner.try_clone().map(|inner| Connection::Policied {
                    inner: Box::new(inner),
                    flow: *flow,
                })
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.try_clone().map(Connection::Unix),
        }
    }

    /// Which direction of the full-duplex connection to tear down: the relay's half-close edge.
    pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.shutdown(how),
            Connection::Masked(masked) => {
                if let Some(state) = &masked.xmc {
                    if let Some(Ok(session)) = state.session.get() {
                        session.stop();
                    }
                }
                masked.stream.shutdown(how)
            }
            Connection::Metered(metered) => metered.inner.shutdown(how),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.shutdown(how)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.shutdown(how),
        }
    }

    /// Look ahead without consuming, the way the HTTP-head readers prove a head before taking
    /// it. TCP has `peek`; `std`'s `UnixStream::peek` is unstable, so the Unix arm issues the
    /// same `recv(MSG_PEEK)` the kernel serves under the hood.
    pub(crate) fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Connection::Tcp(stream) => stream.peek(buf),
            Connection::Masked(masked) => masked.peek(buf),
            Connection::Metered(metered) => metered.inner.peek(buf),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.peek(buf)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => unix_peek(stream, buf),
        }
    }

    /// The peer's address. `std` answers `io::Result` for a TCP stream and an `AF_UNIX` one
    /// has no IP tuple, so the Unix arm yields the same error a caller asking a never-bound TCP
    /// stream gets — matching the std signature keeps every `peer_addr()?`/`.ok()` call-site
    /// unchanged across the transport swap.
    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Connection::Tcp(stream) => stream.peer_addr(),
            Connection::Masked(masked) => masked.stream.peer_addr(),
            Connection::Metered(metered) => metered.inner.peer_addr(),
            Connection::Proxied { peer, .. } => Ok(*peer),
            Connection::Policied { inner, .. } => inner.peer_addr(),
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream reports no peer address",
            )),
        }
    }

    /// The socket's own peer, without a PROXY header's reported address: process ownership names a
    /// socket on this host, which a remote-reported peer cannot.
    pub(crate) fn socket_peer(&self) -> io::Result<SocketAddr> {
        match self {
            Connection::Tcp(stream) => stream.peer_addr(),
            Connection::Masked(masked) => masked.stream.peer_addr(),
            Connection::Metered(metered) => metered.inner.socket_peer(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.socket_peer()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream reports no peer address",
            )),
        }
    }

    /// The local address, `std`'s `io::Result` shape; `Unsupported` for a Unix stream, which
    /// reports no port.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Connection::Tcp(stream) => stream.local_addr(),
            Connection::Masked(masked) => masked.stream.local_addr(),
            Connection::Metered(metered) => metered.inner.local_addr(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.local_addr()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream reports no local address",
            )),
        }
    }

    /// Switch the socket's blocking mode, the readiness seam's one socket-shape change: a
    /// duplicate shares the descriptor's status flags, so the relay restores it when the flow ends.
    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_nonblocking(nonblocking),
            Connection::Masked(masked) => masked.stream.set_nonblocking(nonblocking),
            Connection::Metered(metered) => metered.inner.set_nonblocking(nonblocking),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_nonblocking(nonblocking)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => stream.set_nonblocking(nonblocking),
        }
    }

    /// Whether a write can take at least one byte now. Windows keeps no byte count on a timed-out
    /// send, so a paced carrier asks this first and only writes when the socket has room.
    #[cfg(windows)]
    pub(crate) fn writable(&self, timeout: Duration) -> io::Result<bool> {
        use std::os::windows::io::AsRawSocket as _;
        use windows_sys::Win32::Networking::WinSock::{
            select, FD_SET, FD_SETSIZE, SOCKET_ERROR, TIMEVAL,
        };
        let socket = match self {
            Connection::Tcp(stream) => stream.as_raw_socket(),
            Connection::Masked(masked) => masked.stream.as_raw_socket(),
            Connection::Metered(metered) => return metered.inner.writable(timeout),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                return inner.writable(timeout);
            }
            Connection::Unix(stream) => stream.as_raw_socket(),
        };
        let mut set = FD_SET {
            fd_count: 1,
            fd_array: [0; FD_SETSIZE as usize],
        };
        set.fd_array[0] = socket as usize;
        let wait = TIMEVAL {
            tv_sec: i32::try_from(timeout.as_secs()).unwrap_or(i32::MAX),
            tv_usec: i32::try_from(timeout.subsec_micros()).unwrap_or(999_999),
        };
        // SAFETY: `set` holds this socket and lives for the call; no read or exception set is asked for.
        let ready = unsafe {
            select(
                0,
                std::ptr::null_mut(),
                &mut set,
                std::ptr::null_mut(),
                &wait,
            )
        };
        if ready == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        Ok(ready > 0)
    }

    /// Arm the read side's wait bound. TCP uses `SO_RCVTIMEO`; on a Unix stream `std` omits the
    /// setter, so the same `timeval` goes through `setsockopt` at `SOL_SOCKET`, the level that
    /// carries it for `AF_UNIX` too. `None` clears the bound and lets the read block.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_read_timeout(timeout),
            Connection::Masked(masked) => masked.stream.set_read_timeout(timeout),
            Connection::Metered(metered) => metered.inner.set_read_timeout(timeout),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_read_timeout(timeout)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => set_socket_timeout(stream, SO_RCVTIMEO, timeout),
        }
    }

    /// Arm the write side's wait bound, mirroring `set_read_timeout` on `SO_SNDTIMEO`.
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_write_timeout(timeout),
            Connection::Masked(masked) => masked.stream.set_write_timeout(timeout),
            Connection::Metered(metered) => metered.inner.set_write_timeout(timeout),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_write_timeout(timeout)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => set_socket_timeout(stream, SO_SNDTIMEO, timeout),
        }
    }

    /// Read back the armed wait bound, so a caller can save and restore it around a stage that
    /// tightens it. TCP asks `std`; a Unix stream reads the same `SO_RCVTIMEO`/`SO_SNDTIMEO`
    /// `timeval` back through `getsockopt`, so the save/restore is as exact as the set was.
    pub(crate) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            Connection::Tcp(stream) => stream.read_timeout(),
            Connection::Masked(masked) => masked.stream.read_timeout(),
            Connection::Metered(metered) => metered.inner.read_timeout(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.read_timeout()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(stream) => get_socket_timeout(stream, SO_RCVTIMEO),
        }
    }

    /// Turn Nagle off, matching `TcpStream::set_nodelay(bool)` so the `no_delay` wrapper's call
    /// is unchanged. Meaningful only on TCP; a Unix stream needs no analogue — there is no
    /// internetwork to delay on — so the request is accepted and does nothing rather than
    /// failing, which is why a caller keeps calling it uniformly on either family.
    pub(crate) fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Connection::Tcp(stream) => stream.set_nodelay(nodelay),
            Connection::Masked(masked) => masked.stream.set_nodelay(nodelay),
            Connection::Metered(metered) => metered.inner.set_nodelay(nodelay),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.set_nodelay(nodelay)
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Ok(()),
        }
    }

    /// Wait for this socket to have something to read, without taking a byte or blocking the
    /// caller's own reads: a relay leg parks here so it can hold nothing while it waits. `Ok(true)`
    /// is readiness, the peer's end included, which the next read then reports; `Ok(false)` is the
    /// wait expiring. `#[cfg(unix)]` spelling: one `poll` row.
    #[cfg(unix)]
    pub(crate) fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut row = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one descriptor this leg holds, one element in the array, and the call writes only `revents`.
            let ready = unsafe { libc::poll(&raw mut row, 1, millis) };
            if ready > 0 {
                return Ok(row.revents != 0);
            }
            if ready == 0 {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// The Windows spelling of the same wait: one `WSAPoll` row, whose error code comes from
    /// `WSAGetLastError` rather than the process error slot.
    #[cfg(windows)]
    pub(crate) fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            WSAGetLastError, WSAPoll, POLLERR, POLLHUP, POLLIN, POLLRDNORM, SOCKET, WSAPOLLFD,
        };
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut row = WSAPOLLFD {
            fd: self.as_raw_socket() as SOCKET,
            events: POLLIN | POLLRDNORM,
            revents: 0,
        };
        // SAFETY: one handle this leg holds and one element the call writes `revents` into.
        let ready = unsafe { WSAPoll(&raw mut row, 1, millis) };
        if ready < 0 {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        let readable = POLLIN | POLLRDNORM | POLLHUP | POLLERR;
        Ok(ready > 0 && row.revents & readable != 0)
    }
}

/// Read the PROXY protocol header a listener's `acceptProxyProtocol` promised. A v1 text line or
/// a v2 binary header is consumed in full and the source address it reports is returned; `None`
/// means the header is valid but names no IP source (`UNKNOWN`, `LOCAL`, or a Unix/unspecified
/// family), so the socket's own peer stays the source. A malformed or truncated header is an
/// error, and the caller closes the connection rather than letting carrier bytes stand in for it.
pub(crate) fn read_proxy_header(stream: &mut Connection) -> io::Result<Option<SocketAddr>> {
    const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
    let mut first = [0u8; 12];
    stream.read_exact(&mut first)?;
    if &first[..6] == b"PROXY " {
        let mut line = [0u8; 108];
        line[..12].copy_from_slice(&first);
        let mut len = 12;
        while len < line.len() {
            if len >= 2 && &line[len - 2..len] == b"\r\n" {
                break;
            }
            stream.read_exact(&mut line[len..=len])?;
            len += 1;
        }
        if len < 2 || &line[len - 2..len] != b"\r\n" {
            return Err(bad_proxy(
                "the PROXY v1 line is longer than the protocol allows",
            ));
        }
        return parse_proxy_v1(&line[..len]);
    }
    if first != V2_SIGNATURE {
        return Err(bad_proxy(
            "the connection does not start with a PROXY header",
        ));
    }
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] >> 4 != 2 {
        return Err(bad_proxy("the PROXY v2 header names another version"));
    }
    let command = head[0] & 0x0f;
    let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    if command == 0 {
        return Ok(None);
    }
    if command != 1 {
        return Err(bad_proxy("the PROXY v2 header names an unknown command"));
    }
    let family = head[1] >> 4;
    match family {
        0 | 3 => Ok(None),
        1 if body.len() >= 12 => {
            let source = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(Some(SocketAddr::from((source, port))))
        }
        2 if body.len() >= 36 => {
            let mut source = [0u8; 16];
            source.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(Some(SocketAddr::from((
                std::net::Ipv6Addr::from(source),
                port,
            ))))
        }
        _ => Err(bad_proxy(
            "the PROXY v2 header is shorter than its family needs",
        )),
    }
}

fn parse_proxy_v1(line: &[u8]) -> io::Result<Option<SocketAddr>> {
    let text = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|_| bad_proxy("the PROXY v1 line is not UTF-8"))?;
    let mut fields = text.split(' ');
    if fields.next() != Some("PROXY") {
        return Err(bad_proxy("the PROXY v1 line has no PROXY prefix"));
    }
    let family = fields
        .next()
        .ok_or_else(|| bad_proxy("the PROXY v1 line names no family"))?;
    if family == "UNKNOWN" {
        return Ok(None);
    }
    if family != "TCP4" && family != "TCP6" {
        return Err(bad_proxy("the PROXY v1 line names an unknown family"));
    }
    let source = fields
        .next()
        .and_then(|field| field.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| bad_proxy("the PROXY v1 line has no source address"))?;
    let destination = fields
        .next()
        .and_then(|field| field.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| bad_proxy("the PROXY v1 line has no destination address"))?;
    let source_port = fields
        .next()
        .and_then(|field| field.parse::<u16>().ok())
        .ok_or_else(|| bad_proxy("the PROXY v1 line has no source port"))?;
    if fields
        .next()
        .and_then(|field| field.parse::<u16>().ok())
        .is_none()
    {
        return Err(bad_proxy("the PROXY v1 line has no destination port"));
    }
    if fields.next().is_some() {
        return Err(bad_proxy("the PROXY v1 line carries extra fields"));
    }
    if (family == "TCP4") != source.is_ipv4() || (family == "TCP4") != destination.is_ipv4() {
        return Err(bad_proxy(
            "the PROXY v1 line's family does not match its addresses",
        ));
    }
    Ok(Some(SocketAddr::new(source, source_port)))
}

fn bad_proxy(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Set `SO_RCVTIMEO`/`SO_SNDTIMEO` the way `std` does for TCP but not Unix: one `timeval`
/// through `setsockopt` at `SOL_SOCKET`, the level carrying the timeout for `AF_UNIX`. A zero
/// `timeval` clears the bound and the call blocks, matching `None`.
#[cfg(unix)]
fn set_socket_timeout(
    stream: &UnixStream,
    option: libc::c_int,
    timeout: Option<Duration>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    if let Some(timeout) = timeout {
        // Whole microseconds; the sub-microsecond remainder would only round the bound down.
        value.tv_sec = timeout.as_secs().try_into().unwrap_or(i64::MAX);
        // `suseconds_t` is `i32` on macOS, where this conversion can fail, and `i64` on Linux, where it cannot.
        #[allow(clippy::unnecessary_fallible_conversions)]
        let usec: libc::suseconds_t = timeout.subsec_micros().try_into().unwrap_or(0);
        value.tv_usec = usec;
    }
    // SAFETY: `value` is a live `timeval`, sized as the kernel reads the option, on the stream's own descriptor.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw const value).cast::<libc::c_void>(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read `SO_RCVTIMEO`/`SO_SNDTIMEO` back as the `Duration` `std` would report for TCP: a zero
/// `timeval` is no bound (`None`), otherwise seconds plus microseconds. This keeps a save/restore
/// of the budget exact on a Unix stream, where `std` gives no getter.
#[cfg(unix)]
fn get_socket_timeout(stream: &UnixStream, option: libc::c_int) -> io::Result<Option<Duration>> {
    use std::os::fd::AsRawFd;
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: `value` and `len` are writable and sized as the kernel writes the option, on the stream's own descriptor.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let secs = u64::try_from(value.tv_sec).unwrap_or(0);
    let micros = u32::try_from(value.tv_usec).unwrap_or(0);
    if secs == 0 && micros == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::new(secs, micros * 1_000)))
}

/// A Unix `peek`: `recv` with `MSG_PEEK` reads the head of the queue without consuming it,
/// which is exactly the `TcpStream::peek` the head readers rely on. A zero-length buffer is
/// refused by the kernel as `EINVAL`, so an empty peek answers `Ok(0)` before the call.
#[cfg(unix)]
fn unix_peek(stream: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        // SAFETY: `buf` is a live slice of `buf.len()` readable bytes on the stream's own descriptor; `MSG_PEEK` leaves the queue unchanged.
        let read = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if read >= 0 {
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Where a proxy connection goes: an IP address and port, or the path of an `AF_UNIX` socket,
/// which either host family serves. The dial role needs both because a config naming
/// `unix:/path/sock` is not a `SocketAddr`, and the address is what picks the family before
/// anything is dialed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Ip(SocketAddr),
    #[cfg(any(unix, windows))]
    Unix(PathBuf),
}

/// Parse a listen or dial address into a `Target`. A leading `unix:` (the spelling the
/// references use for a socket path) names an `AF_UNIX` stream, on either host; anything else
/// resolves as an address, so every `ip:port` caller keeps its behavior untouched. An empty
/// path after the prefix is refused rather than dialed at the filesystem root.
pub(crate) fn parse_target(address: &str) -> io::Result<Target> {
    #[cfg(any(unix, windows))]
    if let Some(rest) = address.strip_prefix("unix:") {
        if rest.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a unix address names no path",
            ));
        }
        return Ok(Target::Unix(PathBuf::from(rest)));
    }
    let mut addrs = address.to_socket_addrs()?;
    addrs
        .next()
        .map(Target::Ip)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address resolved to nothing"))
}

/// One `http`/`https` URL taken apart for a dial: the scheme's TLS need, the host and port to reach,
/// the authority a `Host` line repeats, and the path with its query.
#[derive(Debug, Clone)]
pub(crate) struct HttpUrl {
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) authority: String,
    pub(crate) path: String,
    pub(crate) userinfo: Option<Vec<u8>>,
}

/// The `username:password` bytes a URL's userinfo names, percent-decoded per component and with
/// the colon Go's Basic auth always writes, even when the password is absent.
fn decode_userinfo(raw: &str) -> Result<Vec<u8>, String> {
    let (user, password) = raw.split_once(':').unwrap_or((raw, ""));
    let mut out = decode_userinfo_component(user)?;
    out.push(b':');
    out.extend_from_slice(&decode_userinfo_component(password)?);
    Ok(out)
}

fn decode_userinfo_component(raw: &str) -> Result<Vec<u8>, String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let high = userinfo_hex(
                *bytes
                    .get(at + 1)
                    .ok_or("URL userinfo has a short percent escape")?,
            )?;
            let low = userinfo_hex(
                *bytes
                    .get(at + 2)
                    .ok_or("URL userinfo has a short percent escape")?,
            )?;
            out.push(high << 4 | low);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    Ok(out)
}

fn userinfo_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("URL userinfo has an invalid percent escape".to_owned()),
    }
}

impl HttpUrl {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let (tls, rest) = match text.split_once("://") {
            Some(("http", rest)) => (false, rest),
            Some(("https", rest)) => (true, rest),
            Some(_) => return Err("URL scheme is not http or https".to_owned()),
            None => return Err("URL names no scheme".to_owned()),
        };
        let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let target = &rest[..split];
        let (userinfo, authority) = match target.rsplit_once('@') {
            Some((userinfo, authority)) => (Some(decode_userinfo(userinfo)?), authority),
            None => (None, target),
        };
        if authority.is_empty() {
            return Err("URL names no host".to_owned());
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| "URL has an unclosed IPv6 host".to_owned())?;
            let port = tail
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(if tls { 443 } else { 80 });
            (host.to_owned(), port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if port.chars().all(|ch| ch.is_ascii_digit()) {
                (
                    host.to_owned(),
                    port.parse()
                        .map_err(|_| "URL has an invalid port".to_owned())?,
                )
            } else {
                (authority.to_owned(), if tls { 443 } else { 80 })
            }
        } else {
            (authority.to_owned(), if tls { 443 } else { 80 })
        };
        if authority.starts_with('[') {
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err("URL host is not valid".to_owned());
            }
        } else if host.contains(':') {
            return Err("URL host is not valid".to_owned());
        }
        if host.is_empty() {
            return Err("URL names no host".to_owned());
        }
        let mut path = &rest[split..];
        if let Some(fragment) = path.find('#') {
            path = &path[..fragment];
        }
        let path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        Ok(Self {
            tls,
            host,
            port,
            authority: authority.to_owned(),
            path,
            userinfo,
        })
    }
}

/// One bound socket yielding `Connection`s, whichever family it was opened in, so the accept
/// loop keeps the same shape whichever the config named.
pub(crate) enum Listener {
    Tcp(std::net::TcpListener),
    #[cfg(any(unix, windows))]
    Unix(UnixListener),
}

impl Listener {
    /// Bind a listener for the target's family. A unix target is read the way the reference's
    /// listener reads it: an `@` name is Linux's abstract namespace, a second `@` pads it across
    /// the kernel's whole `sun_path`, and a path may carry one comma-separated octal mode applied
    /// after binding. A comma followed by anything but an octal mode is part of the name. A stale
    /// socket left from a previous run is unlinked first, the same recovery the references do; a
    /// file that is not a socket is refused rather than removed.
    pub(crate) fn bind(target: &Target) -> io::Result<Listener> {
        match target {
            Target::Ip(addr) => std::net::TcpListener::bind(addr).map(Listener::Tcp),
            #[cfg(any(unix, windows))]
            Target::Unix(path) => bind_unix(path).map(Listener::Unix),
        }
    }

    /// Bind the listener a transparent inbound accepts on: the socket may receive
    /// another host's traffic in either transparent mode.
    pub(crate) fn bind_transparent(target: &Target) -> io::Result<Listener> {
        use socket2::{Domain, Protocol, Socket, Type};
        let Target::Ip(address) = target else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a transparent listener needs an IP address",
            ));
        };
        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        crate::transparent::set_transparent(&socket, address.is_ipv6())?;
        socket.bind(&(*address).into())?;
        socket.listen(1024)?;
        Ok(Listener::Tcp(std::net::TcpListener::from(socket)))
    }

    /// The socket address a TCP listener holds. A Unix listener has no port to report, so it
    /// answers the error a caller expecting an ephemeral TCP port would get from no bind.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Listener::Tcp(listener) => listener.local_addr(),
            #[cfg(any(unix, windows))]
            Listener::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix listener reports no socket address",
            )),
        }
    }

    pub(crate) fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }
}

/// The accepted connections of a `Listener`, one family or the other.
pub(crate) struct Incoming<'a> {
    listener: &'a Listener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<Connection>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.listener {
            Listener::Tcp(listener) => listener
                .incoming()
                .map(|stream| stream.map(Connection::Tcp))
                .next(),
            #[cfg(any(unix, windows))]
            Listener::Unix(listener) => listener
                .incoming()
                .map(|stream| stream.map(Connection::Unix))
                .next(),
        }
    }
}

/// Dial a resolved TCP address with a budget, yielding a `Connection`. This is the one dial
/// primitive the edge/uplink producers use; it forwards to `TcpStream::connect_timeout` with the
/// same arguments, so the dial it issues (and its budget) is byte-for-byte what the TCP path
/// did before the transport seam — the transport type changed, the syscall did not.
pub(crate) fn dial_tcp(addr: &SocketAddr, timeout: Duration) -> io::Result<Connection> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    connect_bounded(&socket, &SockAddr::from(*addr), timeout)?;
    Ok(Connection::Tcp(TcpStream::from(socket)))
}

#[cfg(test)]
impl Connection {
    /// A TCP connection to an address, for the suites that dial their own echo servers before
    /// handing the stream to a carrier. They once wrote `TcpStream::connect`; the transport type
    /// on both sides of such a test is now `Connection`, and this keeps that one call the same.
    pub(crate) fn connect(addr: impl std::net::ToSocketAddrs) -> io::Result<Connection> {
        TcpStream::connect(addr).map(Connection::Tcp)
    }

    /// Read the `TCP_NODELAY` flag back, for the one test that proves a dial and an accept both
    /// turn Nagle off. A Unix stream has no such flag, so it answers as a never-set query would.
    pub(crate) fn nodelay(&self) -> io::Result<bool> {
        match self {
            Connection::Tcp(stream) => stream.nodelay(),
            Connection::Masked(masked) => masked.stream.nodelay(),
            Connection::Metered(metered) => metered.inner.nodelay(),
            Connection::Proxied { inner, .. } | Connection::Policied { inner, .. } => {
                inner.nodelay()
            }
            #[cfg(any(unix, windows))]
            Connection::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a unix stream has no TCP_NODELAY flag",
            )),
        }
    }
}

/// Bind a TCP listener for the suites that stand up their own echo servers. They once wrote
/// `TcpListener::bind`; a listener now yields `Connection`s on both roles, so a fixture binds
/// through the same seam and gets the matching type back.
#[cfg(test)]
pub(crate) fn test_bind(addr: impl std::net::ToSocketAddrs) -> io::Result<Listener> {
    std::net::TcpListener::bind(addr).map(Listener::Tcp)
}

/// A census or a budget the suite arms is process-wide state a parallel test can move under a
/// reader: run the test in a child that carries only it, so the number is the test's.
#[cfg(test)]
pub(crate) fn in_a_quiet_process(name: &str) -> bool {
    if std::env::var_os("FERROX_QUIET_PROCESS").is_some() {
        return true;
    }
    let exe = std::env::current_exe().expect("the test binary");
    let output = std::process::Command::new(exe)
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env("FERROX_QUIET_PROCESS", "1")
        .output()
        .expect("re-runs the test in a quiet process");
    let ran = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{name} failed in its quiet process:\n{}\n{}",
        ran,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        ran.contains("1 passed"),
        "{name} ran no test in its quiet process, so the name is wrong and the gate is a no-op:\n{ran}"
    );
    false
}

/// The tasks `/proc/self/task` lists, for a caller already inside a quiet process.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn live_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("reads the task table")
        .count()
}

#[cfg(test)]
impl Listener {
    /// The single accept a fixture that dials one client needs; the std `accept` shape, mapped
    /// onto the seam so a bound listener hands back a `Connection` and the peer address.
    pub(crate) fn accept(&self) -> io::Result<(Connection, SocketAddr)> {
        match self {
            Listener::Tcp(listener) => listener
                .accept()
                .map(|(stream, addr)| (Connection::Tcp(stream), addr)),
            #[cfg(any(unix, windows))]
            Listener::Unix(listener) => listener.accept().map(|(stream, _addr)| {
                (
                    Connection::Unix(stream),
                    SocketAddr::from(([0, 0, 0, 0], 0)),
                )
            }),
        }
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Listener::Tcp(listener) => listener.set_nonblocking(nonblocking),
            #[cfg(any(unix, windows))]
            Listener::Unix(listener) => listener.set_nonblocking(nonblocking),
        }
    }
}

/// Connect to a target, whichever family it names. The IP arm is the TCP dial with its budget
/// unchanged; the Unix arm spends the same budget, because Linux parks `connect` on a socket path
/// until the listener's backlog has room, where macOS refuses it at once.
pub(crate) fn connect(target: &Target, timeout: Duration) -> io::Result<Connection> {
    match target {
        Target::Ip(addr) => dial_tcp(addr, timeout),
        #[cfg(unix)]
        Target::Unix(path) => unix_connect(path, timeout),
        #[cfg(windows)]
        Target::Unix(path) => UnixStream::connect(path).map(Connection::Unix),
    }
}

/// The abstract-namespace name a unix target text names, on the hosts whose kernel serves one: a
/// leading `@` marks it, and a second `@` asks for the name padded across the kernel's whole
/// `sun_path` — the spelling haproxy's sockets use, which the reference's listener reads the same
/// way. Any other text, and any text on a host with no abstract namespace, is a filesystem path.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn abstract_name(path: &std::path::Path) -> Option<(&[u8], bool)> {
    use std::os::unix::ffi::OsStrExt as _;
    let rest = path.as_os_str().as_bytes().strip_prefix(b"@")?;
    Some(match rest.strip_prefix(b"@") {
        Some(name) => (name, true),
        None => (rest, false),
    })
}

/// The one comma-separated octal permission the reference's listener takes after a socket path,
/// split before anything touches the filesystem. Exactly one comma followed by octal digits is
/// the spelling; another count, or a suffix that is not octal, stays part of the path, so a name
/// like `app,v2.sock` binds and dials the same literal text a peer outside this tree can name.
#[cfg(unix)]
fn split_permission(path: &std::path::Path) -> (&std::path::Path, Option<u32>) {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_os_str().as_bytes();
    let Some(comma) = bytes.iter().position(|byte| *byte == b',') else {
        return (path, None);
    };
    if bytes[comma + 1..].contains(&b',') {
        return (path, None);
    }
    let Ok(text) = std::str::from_utf8(&bytes[comma + 1..]) else {
        return (path, None);
    };
    let Ok(mode) = u32::from_str_radix(text, 8) else {
        return (path, None);
    };
    let head = std::path::Path::new(std::ffi::OsStr::from_bytes(&bytes[..comma]));
    (head, Some(mode))
}

/// Bind a unix listener from the text a config names: an abstract name on the hosts that serve
/// one, else a filesystem path after the permission the reference accepts is split off. A stale
/// socket is replaced and a file that is not a socket is refused, so a typo cannot delete data; a
/// requested mode is applied inside a private staging directory beside the socket and then
/// hard-linked into place, so nothing but our own socket ever takes the permission — or, when the
/// directory leaves no room for a staged name, to the path itself.
#[cfg(unix)]
fn bind_unix(path: &std::path::Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some((name, padded)) = abstract_name(path) {
        return abstract_listener(name, padded);
    }
    let (path, perm) = split_permission(path);
    let stale = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => Some((meta.dev(), meta.ino())),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "a unix listen path names a file that is not a socket",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let Some(mode) = perm else {
        take_stale(path, stale)?;
        return UnixListener::bind(path);
    };
    if let Some(listener) = bind_staged(path, mode, stale)? {
        return Ok(listener);
    }
    // The directory leaves no room for a staged name, so the mode goes on the path itself.
    take_stale(path, stale)?;
    let listener = UnixListener::bind(path)?;
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

/// Remove the socket the initial check saw, only while the same inode is still at the path, so two
/// starts racing for one path leave the winner's listener alone and the loser refuses.
#[cfg(unix)]
fn take_stale(path: &std::path::Path, stale: Option<(u64, u64)>) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let Some((dev, ino)) = stale else {
        return Ok(());
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if (meta.dev(), meta.ino()) == (dev, ino) => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "a unix listen path was replaced while binding",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Bind the socket inside a private `0700` directory beside the configured path, so no other writer
/// can create or swap the entry the mode is applied to, then hard-link it into place, which refuses
/// to replace whatever another writer left at the path. `None` when the staged name would not fit
/// the address field, where the caller binds the path itself.
#[cfg(unix)]
fn bind_staged(
    path: &std::path::Path,
    mode: u32,
    stale: Option<(u64, u64)>,
) -> io::Result<Option<UnixListener>> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    for _ in 0..8 {
        let dir = staged_name(path);
        let inner = dir.join("s");
        if inner.as_os_str().len() > std::mem::size_of::<libc::sockaddr_un>() - 3 {
            return Ok(None);
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
        let published = (|| {
            let listener = UnixListener::bind(&inner)?;
            std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(mode))?;
            take_stale(path, stale)?;
            std::fs::hard_link(&inner, path)?;
            Ok(listener)
        })();
        let _ = std::fs::remove_file(&inner);
        let _ = std::fs::remove_dir(&dir);
        return published.map(Some);
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "a unix listen path left no staged name free",
    ))
}

/// A staging directory name in the socket's own directory — same filesystem, so the hard link into
/// place is atomic — that no configured path can name.
#[cfg(unix)]
fn staged_name(path: &std::path::Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!(".ferrox-{}-{id}", std::process::id());
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => std::path::PathBuf::from(name),
    }
}

#[cfg(windows)]
fn bind_unix(path: &std::path::Path) -> io::Result<UnixListener> {
    if std::fs::symlink_metadata(path).is_ok() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    Ok(listener)
}

/// One nonblocking `connect` waited out with `poll`, so a full backlog costs the budget and not the
/// flow's thread, and a listener that answers at once still does.
#[cfg(unix)]
fn unix_connect(path: &std::path::Path, timeout: Duration) -> io::Result<Connection> {
    use socket2::{Domain, SockAddr, Socket, Type};
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some((name, padded)) = abstract_name(path) {
        return abstract_connect(name, padded, timeout);
    }
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    connect_bounded(&socket, &SockAddr::unix(unix_dial_path(path))?, timeout)?;
    Ok(unix_connection(socket))
}

/// The path a dial reads from the same text a listener takes: an octal mode suffix belongs to the
/// listener, not the name, so it is split off here too. A suffix that is not octal names a file
/// literally, which is the only such text a peer outside this tree could have bound.
#[cfg(unix)]
fn unix_dial_path(path: &std::path::Path) -> &std::path::Path {
    match split_permission(path) {
        (head, Some(_)) => head,
        (_, None) => path,
    }
}

/// `connect_timeout`, with a peer that accepts and closes at once taken as connected: the kernel wakes the connect's poll with a hangup and no error set, which socket2 reports as `Other`. Linux's full `AF_UNIX` queue is named here too — the same hangup with no error set, which is a refusal rather than a connection.
pub(crate) fn connect_bounded(
    socket: &socket2::Socket,
    address: &socket2::SockAddr,
    timeout: Duration,
) -> io::Result<()> {
    let bounded = socket.connect_timeout(address, timeout);
    if bounded.is_err() && socket.peer_addr().is_ok() {
        return Ok(());
    }
    bounded.map_err(|error| {
        if cfg!(unix) && error.kind() == io::ErrorKind::Other {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "the socket's queue did not take the connection",
            )
        } else {
            error
        }
    })
}

#[cfg(unix)]
fn unix_connection(socket: socket2::Socket) -> Connection {
    Connection::Unix(UnixStream::from(std::os::fd::OwnedFd::from(socket)))
}

/// The `sockaddr_un` an abstract name fills: the leading zero is the namespace's marker, as
/// `from_abstract_name` writes it, and a padded name declares itself through the kernel's whole
/// `sun_path` so it meets a peer that spelled it the haproxy way. The tail past a short name
/// stays zero, which `try_init` hands over.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn abstract_address(name: &[u8], padded: bool) -> io::Result<socket2::SockAddr> {
    use socket2::SockAddr;
    // SAFETY: `try_init` hands over zeroed storage sized for any address, and the family, marker and length written into it describe the `sockaddr_un` filled here; no byte past `sun_path` is addressed.
    unsafe {
        SockAddr::try_init(|storage, length| {
            let address = storage.cast::<libc::sockaddr_un>();
            let field = (*address).sun_path.len();
            if name.is_empty() || name.len() >= field {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an abstract name does not fit a socket address",
                ));
            }
            (*address).sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path = std::ptr::addr_of_mut!((*address).sun_path).cast::<u8>();
            for (at, byte) in name.iter().enumerate() {
                *path.add(at + 1) = *byte;
            }
            let base = std::mem::offset_of!(libc::sockaddr_un, sun_path);
            *length = if padded {
                base + field
            } else {
                base + 1 + name.len()
            } as libc::socklen_t;
            Ok(())
        })
        .map(|((), address)| address)
    }
}

/// Bind the abstract name and listen on it. Nothing on disk names it, so there is no stale entry
/// to unlink, and the name leaves with the socket's last descriptor.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn abstract_listener(name: &[u8], padded: bool) -> io::Result<UnixListener> {
    use socket2::{Domain, Socket, Type};
    let address = abstract_address(name, padded)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.bind(&address)?;
    socket.listen(128)?;
    Ok(UnixListener::from(std::os::fd::OwnedFd::from(socket)))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn abstract_connect(name: &[u8], padded: bool, timeout: Duration) -> io::Result<Connection> {
    use socket2::{Domain, Socket, Type};
    let address = abstract_address(name, padded)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    connect_bounded(&socket, &address, timeout)?;
    Ok(unix_connection(socket))
}

/// Connect Linux's abstract namespace, whose address is bytes rather than a path, under the same
/// budget the named arm spends. This is the route a webhook's `@name` URL takes, which names the
/// namespace without the `unix:` spelling the config reader takes.
#[cfg(target_os = "linux")]
pub(crate) fn connect_abstract(name: &[u8], timeout: Duration) -> io::Result<Connection> {
    abstract_connect(name, false, timeout)
}

/// The seam's `AF_UNIX` arm on the host whose `std` keeps `UnixStream` behind the unstable
/// `windows_unix_domain_sockets` feature, so a stable build cannot name the type. Windows serves
/// the family from build 17063 as a `SOCK_STREAM` socket through `WinSock` — the shape and the
/// floor `std`'s own Windows unix module names — and this module is the part `std` would be
/// writing for itself: open, dial, bind, accept, the four `Read`/`Write` shapes, and the wait
/// bounds `std` has setters for on TCP and none for a unix stream.
///
/// What the seam refuses it refuses rather than papers over: an address query answers
/// `Unsupported` because a socket path has no port to name, on either host, and `try_clone` shares
/// the one handle behind an `Arc` instead of calling `WSADuplicateSocket`, so no leg depends on
/// what the provider serves for this family. That is the same lifetime a `dup`ed descriptor pair
/// has on Unix — the relay's two legs reach one socket, and the last drop closes it.
#[cfg(windows)]
mod winunix {
    use std::io::{self, IoSlice, IoSliceMut, Read, Write};
    use std::net::Shutdown;
    #[cfg(test)]
    use std::net::SocketAddr;
    use std::os::windows::io::{AsRawSocket, RawSocket};
    use std::path::Path;
    use std::ptr::null_mut;
    use std::sync::{Arc, Once};
    use std::time::Duration;
    use windows_sys::Win32::Networking::WinSock::{
        accept, bind, closesocket, connect, getsockopt, listen, recv, send, setsockopt, shutdown,
        socket, WSAGetLastError, WSARecv, WSASend, WSAStartup, AF_UNIX, INVALID_SOCKET, MSG_PEEK,
        SD_BOTH, SD_RECEIVE, SD_SEND, SOCKADDR, SOCKADDR_UN, SOCKET, SOCKET_ERROR, SOCK_STREAM,
        SOL_SOCKET, WSABUF, WSADATA, WSAESHUTDOWN,
    };
    use windows_sys::Win32::Networking::WinSock::{ioctlsocket, FIONBIO};

    pub(crate) use windows_sys::Win32::Networking::WinSock::{SO_RCVTIMEO, SO_SNDTIMEO};

    /// The run of buffers one `WSASend`/`WSARecv` is offered. The frame writer's part cap is wider,
    /// and parts past this go out on the next turn of its loop, so nothing is dropped by the clamp.
    const VECTORS: usize = 16;

    /// One `WinSock` socket, closed when the last leg holding it drops.
    #[derive(Debug)]
    struct Handle(SOCKET);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: this is the handle's own socket and `closesocket` is its free.
            unsafe { closesocket(self.0) };
        }
    }

    // A socket handle names a kernel object every thread can reach, and WinSock serializes the calls made on it — which is what a relay's two legs do with one connection.
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}

    /// `WinSock` has to be opened before a call reaches it, and `std` does that only for its own
    /// sockets, so this arm asks for itself once. The version is the one `std` requests, and no
    /// `WSACleanup` follows: the process that owns a leg outlives it.
    fn startup() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // SAFETY: `data` is a live `WSADATA`, sized as the library writes it.
            let mut data: WSADATA = unsafe { std::mem::zeroed() };
            let code = unsafe { WSAStartup(0x0202, &raw mut data) };
            assert_eq!(code, 0, "winsock will not start");
        });
    }

    /// A refused call as the `io::Error` `std` gives for the same code: `WSAGetLastError` is the
    /// provider's answer, and `from_raw_os_error` maps the WSA codes onto the kinds the relay reads.
    fn last_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    /// The socket address a path names: `AF_UNIX` then the path's bytes, NUL-terminated inside the
    /// field, with the length the provider reads being the family plus those bytes. An address here
    /// is always a named path — the arm has no autobind or abstract-namespace spelling — so an empty
    /// one is refused rather than bound at nothing.
    fn address(path: &Path) -> io::Result<(SOCKADDR_UN, i32)> {
        let text = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a unix path is not utf-8 on windows",
            )
        })?;
        let bytes = text.as_bytes();
        let field = std::mem::offset_of!(SOCKADDR_UN, sun_path);
        if bytes.is_empty() || bytes.len() + 1 > std::mem::size_of::<SOCKADDR_UN>() - field {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a unix path does not fit a socket address",
            ));
        }
        // SAFETY: an all-zero `SOCKADDR_UN` is a valid address with an empty path and a zero length.
        let mut addr: SOCKADDR_UN = unsafe { std::mem::zeroed() };
        addr.sun_family = AF_UNIX;
        for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as i8;
        }
        Ok((
            addr,
            i32::try_from(field + bytes.len() + 1).unwrap_or(i32::MAX),
        ))
    }

    /// A `SOCK_STREAM` socket in the `AF_UNIX` family — the shape `std`'s own Windows unix
    /// module opens, and the only one this seam needs.
    fn open() -> io::Result<Handle> {
        startup();
        // SAFETY: the family and type are WinSock's own constants and no buffer is touched.
        let handle = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        if handle == INVALID_SOCKET {
            return Err(last_error());
        }
        Ok(Handle(handle))
    }

    /// One `recv`, peeking or not: a zero return is the peer's EOF, an interrupted call is retried,
    /// and `WSAESHUTDOWN` — the code for a socket this side already shut down for reading — answers
    /// that same clean end, so a leg reading past its own shutdown stops instead of erroring.
    fn receive(socket: SOCKET, buf: &mut [u8], flags: i32) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // A run wider than the count the call names is clamped to it, never wrapped around.
            let asked = i32::try_from(buf.len()).unwrap_or(i32::MAX);
            // SAFETY: `buf` is a live slice of `asked` writable bytes on this socket.
            let read = unsafe { recv(socket, buf.as_mut_ptr(), asked, flags) };
            if read >= 0 {
                return Ok(read as usize);
            }
            let error = last_error();
            if error.raw_os_error() == Some(WSAESHUTDOWN) {
                return Ok(0);
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// One `send`, returning how much of the buffer the queue took; the caller's loop writes the rest.
    fn transmit(socket: SOCKET, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // A run wider than the count the call names is clamped to it, never wrapped around.
            let asked = i32::try_from(buf.len()).unwrap_or(i32::MAX);
            // SAFETY: `buf` is a live slice of readable bytes; `send` only reads `asked` of them.
            let sent = unsafe { send(socket, buf.as_ptr(), asked, 0) };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = last_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// The gathered half of a vectored call: the runs the caller handed, as the `WSABUF` array
    /// `WinSock` reads, clamped to `VECTORS` so the provider is never offered more buffers than the
    /// loop is prepared to retry.
    fn gather(bufs: &[IoSlice<'_>]) -> ([WSABUF; VECTORS], u32) {
        let mut array = [WSABUF {
            len: 0,
            buf: null_mut(),
        }; VECTORS];
        for (slot, part) in array.iter_mut().zip(bufs) {
            slot.len = part.len().min(u32::MAX as usize) as u32;
            // WinSock declares a `WSABUF`'s buffer mutable for a send too; the call only reads it.
            slot.buf = part.as_ptr().cast_mut();
        }
        (array, bufs.len().min(VECTORS) as u32)
    }

    /// The same array for a receive, whose runs the caller owns mutably.
    fn gather_mut(bufs: &mut [IoSliceMut<'_>]) -> ([WSABUF; VECTORS], u32) {
        let mut array = [WSABUF {
            len: 0,
            buf: null_mut(),
        }; VECTORS];
        let count = bufs.len().min(VECTORS) as u32;
        for (slot, part) in array.iter_mut().zip(bufs) {
            slot.len = part.len().min(u32::MAX as usize) as u32;
            slot.buf = part.as_mut_ptr();
        }
        (array, count)
    }

    /// A connected `AF_UNIX` stream.
    #[derive(Debug)]
    pub(crate) struct UnixStream {
        socket: Arc<Handle>,
    }

    impl UnixStream {
        /// Dial a socket path. A local connect answers at once — `ENOENT` for no listener, a refused
        /// code for one that will not take it — so there is no retransmission to bound with a timeout.
        pub(crate) fn connect(path: &Path) -> io::Result<UnixStream> {
            let (addr, len) = address(path)?;
            let handle = open()?;
            // SAFETY: `addr` is a live socket address of `len` bytes; `connect` neither keeps nor writes it.
            if unsafe { connect(handle.0, (&raw const addr).cast::<SOCKADDR>(), len) }
                == SOCKET_ERROR
            {
                return Err(last_error());
            }
            Ok(UnixStream {
                socket: Arc::new(handle),
            })
        }

        /// The other leg of the same socket: the handle is shared behind the `Arc`, not
        /// duplicated, so the last leg to drop closes it — the lifetime a `dup`ed unix
        /// descriptor has.
        #[allow(
            clippy::unnecessary_wraps,
            reason = "the seam matches one fallible clone signature"
        )]
        pub(crate) fn try_clone(&self) -> io::Result<UnixStream> {
            Ok(UnixStream {
                socket: Arc::clone(&self.socket),
            })
        }

        /// Which direction of the full-duplex stream to tear down.
        pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            let how = match how {
                Shutdown::Write => SD_SEND,
                Shutdown::Read => SD_RECEIVE,
                Shutdown::Both => SD_BOTH,
            };
            // SAFETY: this is the stream's own socket and `how` is one of WinSock's three directions.
            if unsafe { shutdown(self.socket.0, how) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(())
        }

        /// Switch the socket's blocking mode; every leg shares the one handle, so the flags
        /// change for the relay's duplicates together and are restored together.
        pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            // SAFETY: `mode` is the one `u32` flag `FIONBIO` reads, on this socket.
            let mut mode = u32::from(nonblocking);
            if unsafe { ioctlsocket(self.socket.0, FIONBIO, &raw mut mode) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(())
        }
    }

    impl AsRawSocket for UnixStream {
        fn as_raw_socket(&self) -> RawSocket {
            self.socket.0 as RawSocket
        }
    }

    impl Read for &UnixStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            receive(self.socket.0, buf, 0)
        }

        // One `WSARecv` for the whole run, the call that stands in for `readv` here.
        fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
            if bufs.is_empty() {
                return Ok(0);
            }
            let (array, count) = gather_mut(bufs);
            loop {
                let mut received = 0u32;
                let mut flags = 0u32;
                // SAFETY: `array` describes the caller's runs, live for the call; a blocking socket takes no overlapped or completion routine, and `flags` is the reserved zero WinSock requires.
                let code = unsafe {
                    WSARecv(
                        self.socket.0,
                        array.as_ptr(),
                        count,
                        &raw mut received,
                        &raw mut flags,
                        null_mut(),
                        None,
                    )
                };
                if code == SOCKET_ERROR {
                    let error = last_error();
                    if error.raw_os_error() == Some(WSAESHUTDOWN) {
                        return Ok(0);
                    }
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                    continue;
                }
                return Ok(received as usize);
            }
        }
    }

    impl Write for &UnixStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            transmit(self.socket.0, buf)
        }

        // One `WSASend` for a frame's parts, so the coalescing the TCP path does with `writev` is the same single call here, not a relocation into one buffer per part.
        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            if bufs.is_empty() {
                return Ok(0);
            }
            let (array, count) = gather(bufs);
            loop {
                let mut sent = 0u32;
                // SAFETY: `array` describes the caller's buffers, live and read-only for the call; a blocking socket takes no overlapped or completion routine.
                let code = unsafe {
                    WSASend(
                        self.socket.0,
                        array.as_ptr(),
                        count,
                        &raw mut sent,
                        0,
                        null_mut(),
                        None,
                    )
                };
                if code == SOCKET_ERROR {
                    let error = last_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                    continue;
                }
                return Ok(sent as usize);
            }
        }

        // A socket queue has no user-space buffer to push.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for UnixStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.read(buf)
        }

        fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.read_vectored(bufs)
        }
    }

    impl Write for UnixStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.write(buf)
        }

        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            let mut inner = &*self;
            inner.write_vectored(bufs)
        }

        fn flush(&mut self) -> io::Result<()> {
            let mut inner = &*self;
            inner.flush()
        }
    }

    /// A bound `AF_UNIX` socket file. The file outlives the descriptor that made it, which is why
    /// `Listener::bind` unlinks before binding instead of trusting the path to be free.
    #[derive(Debug)]
    pub(crate) struct UnixListener {
        socket: Arc<Handle>,
    }

    impl UnixListener {
        /// Bind a path and queue for it. `windows-sys` names `SOMAXCONN` as `5`, not the
        /// `0x7fffffff` that `WinSock` means by it, so the deepest queue the provider will read is
        /// asked for by number.
        pub(crate) fn bind(path: &Path) -> io::Result<UnixListener> {
            let (addr, len) = address(path)?;
            let handle = open()?;
            // SAFETY: `addr` is a live socket address of `len` bytes; `bind` neither keeps nor writes it.
            if unsafe { bind(handle.0, (&raw const addr).cast::<SOCKADDR>(), len) } == SOCKET_ERROR
            {
                return Err(last_error());
            }
            // SAFETY: this is the socket the bind above just took.
            if unsafe { listen(handle.0, 0x7fff_ffff) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(UnixListener {
                socket: Arc::new(handle),
            })
        }

        /// The next peer. The seam reports no address for a unix leg on either host, so the tuple's
        /// second half is the zero address `std`'s unix accept hands back for a path that names no
        /// port.
        #[cfg(test)]
        pub(crate) fn accept(&self) -> io::Result<(UnixStream, SocketAddr)> {
            self.accept_one()
                .map(|stream| (stream, SocketAddr::from(([0, 0, 0, 0], 0))))
        }

        /// One accepted socket, with an interrupted accept retried the way `std` retries it.
        fn accept_one(&self) -> io::Result<UnixStream> {
            loop {
                // SAFETY: no peer address is asked for — the seam has no use for one — so both out-params are null.
                let handle = unsafe { accept(self.socket.0, null_mut(), null_mut()) };
                if handle == INVALID_SOCKET {
                    let error = last_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                    continue;
                }
                return Ok(UnixStream {
                    socket: Arc::new(Handle(handle)),
                });
            }
        }

        pub(crate) fn incoming(&self) -> Incoming<'_> {
            Incoming { listener: self }
        }

        #[cfg(test)]
        pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            // SAFETY: `mode` is the one `u32` flag `FIONBIO` reads, on this socket.
            let mut mode = u32::from(nonblocking);
            if unsafe { ioctlsocket(self.socket.0, FIONBIO, &raw mut mode) } == SOCKET_ERROR {
                return Err(last_error());
            }
            Ok(())
        }
    }

    /// The accepted connections of a `UnixListener`.
    pub(crate) struct Incoming<'a> {
        listener: &'a UnixListener,
    }

    impl Iterator for Incoming<'_> {
        type Item = io::Result<UnixStream>;

        fn next(&mut self) -> Option<Self::Item> {
            Some(self.listener.accept_one())
        }
    }

    /// Arm the wait bound the way `WinSock` spells it: one `DWORD` of milliseconds, where `None` is no
    /// bound and a zero `Duration` is the invalid value `std` refuses on TCP too.
    pub(crate) fn set_socket_timeout(
        stream: &UnixStream,
        option: i32,
        timeout: Option<Duration>,
    ) -> io::Result<()> {
        let millis = match timeout {
            None => 0,
            Some(timeout) => {
                let millis = u32::try_from(timeout.as_millis())
                    .map_err(|_| invalid("a unix timeout is past its bounds"))?;
                if millis == 0 {
                    return Err(invalid("a unix timeout is zero"));
                }
                millis
            }
        };
        let bytes = i32::try_from(std::mem::size_of::<u32>()).unwrap_or(i32::MAX);
        // SAFETY: `millis` is a live `DWORD`, sized as WinSock reads the option, on the stream's own socket.
        let code = unsafe {
            setsockopt(
                stream.socket.0,
                SOL_SOCKET,
                option,
                (&raw const millis).cast::<u8>(),
                bytes,
            )
        };
        if code == SOCKET_ERROR {
            return Err(last_error());
        }
        Ok(())
    }

    /// The bound read back: zero is no bound, exactly as `std` reports for a TCP socket on Windows,
    /// so a save/restore of the budget is as exact here as the set was.
    pub(crate) fn get_socket_timeout(
        stream: &UnixStream,
        option: i32,
    ) -> io::Result<Option<Duration>> {
        let mut millis: u32 = 0;
        let mut len = i32::try_from(std::mem::size_of::<u32>()).unwrap_or(i32::MAX);
        // SAFETY: `millis` and `len` are writable and sized as WinSock writes the option, on the stream's own socket.
        let code = unsafe {
            getsockopt(
                stream.socket.0,
                SOL_SOCKET,
                option,
                (&raw mut millis).cast::<u8>(),
                &raw mut len,
            )
        };
        if code == SOCKET_ERROR {
            return Err(last_error());
        }
        if millis == 0 {
            return Ok(None);
        }
        Ok(Some(Duration::from_millis(u64::from(millis))))
    }

    /// A unix `peek`: the same `recv` a `TcpStream::peek` is built on, with `MSG_PEEK` leaving the
    /// queue whole.
    pub(crate) fn unix_peek(stream: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
        receive(stream.socket.0, buf, MSG_PEEK)
    }

    fn invalid(reason: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, reason)
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    #[test]
    fn an_http_url_keeps_the_authority_and_makes_the_path() {
        let url = HttpUrl::parse("https://example.test:8443/check?q=1#frag").expect("parses");
        assert!(url.tls);
        assert_eq!(url.host, "example.test");
        assert_eq!(url.port, 8443);
        assert_eq!(url.authority, "example.test:8443");
        assert_eq!(url.path, "/check?q=1");
        let bare = HttpUrl::parse("http://example.test?q=1").expect("parses");
        assert_eq!(bare.path, "/?q=1");
    }

    #[test]
    fn a_url_error_does_not_echo_the_credential() {
        for raw in [
            "user:secret@host/hook",
            "ftp://user:secret@host/hook",
            "http://[user:secret",
        ] {
            let error = HttpUrl::parse(raw).expect_err("refused");
            assert!(!error.contains("secret"), "{raw}: {error}");
        }
    }

    /// A relay read on an empty socket answers instead of waiting out the read clock, which is what
    /// lets the lane park on the descriptor with the worker free.
    #[cfg(unix)]
    #[test]
    fn a_relay_read_never_waits_out_the_clock() {
        let (side, _peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut stream = Connection::Unix(side);
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("arms the read clock");
        let began = std::time::Instant::now();
        let error = stream
            .read_ready(&mut [0u8; 8])
            .expect_err("nothing was sent");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "an empty socket is a wait, not an end: {error:?}"
        );
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "the read waited out its clock instead of handing the lane a park"
        );
    }

    /// A masked server's handshake reads the peer's first bytes: it takes the handshake budget, not
    /// the relay's poll clock, and it puts the clock back when the header is done.
    #[test]
    fn a_masked_handshake_reads_past_the_poll_clock_and_restores_it() {
        use ferrox_core::finalmask::{Chain, HeaderCustom, Item, MaskRole, Sequence};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let peer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connects");
            std::thread::sleep(Duration::from_millis(25));
            stream.write_all(b"abcd").expect("sends the header");
        });
        let (side, _) = listener.accept().expect("accepts");
        side.set_read_timeout(Some(Duration::from_millis(1)))
            .expect("arms the poll clock");
        let clients = Item {
            packet: Some(b"abcd".to_vec()),
            ..Item::default()
        };
        let header = HeaderCustom::new(
            vec![Sequence {
                items: vec![clients],
            }],
            Vec::new(),
            Vec::new(),
        )
        .expect("a mask the config can drive");
        let mut chain = Chain::default();
        chain.push_header_custom(header);
        let connection = Connection::Tcp(side).with_mask_role(Some(&chain), MaskRole::Server);
        connection
            .start_mask()
            .expect("the header handshake reads past the poll clock");
        match &connection {
            Connection::Masked(masked) => assert_eq!(
                masked.stream.read_timeout().expect("reads the clock"),
                Some(Duration::from_millis(1)),
                "the relay's clock comes back after the handshake"
            ),
            other => panic!("a masked connection is expected: {other:?}"),
        }
        peer.join().expect("the peer joins");
    }

    /// A readiness read never runs the header handshake, so a pending header is left whole for the
    /// blocking path instead of being read part way and failed on the readiness lane.
    #[cfg(unix)]
    #[test]
    fn a_readiness_read_leaves_a_pending_header_to_the_blocking_path() {
        use ferrox_core::finalmask::{Chain, HeaderCustom, Item, MaskRole, Sequence};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).expect("connects");
        let (mut server, _) = listener.accept().expect("accepts");
        let header = Item {
            packet: Some(vec![7]),
            save: "tx".to_owned(),
            ..Item::default()
        };
        let answer = Item {
            reuse: "tx".to_owned(),
            ..Item::default()
        };
        let mask = HeaderCustom::new(
            vec![Sequence {
                items: vec![header],
            }],
            vec![Sequence {
                items: vec![answer],
            }],
            Vec::new(),
        )
        .expect("config is valid");
        let mut chain = Chain::default();
        chain.push_header_custom(mask);
        let mut client = Connection::Tcp(client).with_mask_role(Some(&chain), MaskRole::Client);

        server.set_nonblocking(true).expect("nonblocking");
        let mut probe = [0u8; 8];
        let error = client
            .read_ready(&mut probe)
            .expect_err("the header is pending");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let unseen = server.peek(&mut probe).expect_err("nothing was sent");
        assert_eq!(
            unseen.kind(),
            io::ErrorKind::WouldBlock,
            "the readiness lane did not start the handshake"
        );

        server.set_nonblocking(false).expect("blocking");
        let server = std::thread::spawn(move || {
            let mut sent = [0u8; 1];
            server.read_exact(&mut sent).expect("reads the header");
            assert_eq!(sent, [7]);
            server.write_all(&[7]).expect("answers the header");
            server.write_all(&[42]).expect("writes the session");
        });
        let mut session = [0u8; 1];
        client
            .read_exact(&mut session)
            .expect("the blocking read finishes the handshake and reads the session");
        assert_eq!(session, [42]);
        server.join().expect("server finishes");
    }

    /// A full socket answers the relay's offer at once instead of spending a worker in the send
    /// clock, and the lane learns which descriptor the reactor must watch for a write.
    #[cfg(unix)]
    #[test]
    fn a_full_socket_write_never_waits_out_the_clock() {
        use std::os::unix::io::AsRawFd;

        fn small_buffer(fd: std::os::unix::io::RawFd, name: libc::c_int) {
            let want: libc::c_int = 4096;
            // SAFETY: `want` outlives the call, and the size is its own.
            let set = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    name,
                    std::ptr::addr_of!(want).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            assert_eq!(set, 0, "a small socket buffer is refused");
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let peer = TcpStream::connect(listener.local_addr().expect("addr")).expect("connects");
        let (side, _) = listener.accept().expect("accepts");
        small_buffer(side.as_raw_fd(), libc::SO_SNDBUF);
        small_buffer(peer.as_raw_fd(), libc::SO_RCVBUF);
        let mut stream = Connection::Tcp(side);
        let step = crate::proxy::RelayStep::enter();
        let mut filled = 0usize;
        let (began, error) = loop {
            let began = std::time::Instant::now();
            match stream.write_ready(&[&[0u8; 64][..]]) {
                Ok(n) => {
                    filled += n;
                    assert!(filled < 64 * 1024 * 1024, "the socket never filled");
                }
                Err(error) if crate::proxy::is_descriptor_wait(&error) => break (began, error),
                Err(error) => panic!("the fill ended: {error:?}"),
            }
        };
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "a full socket is a wait, not an end: {error:?}"
        );
        assert!(
            began.elapsed() < Duration::from_millis(100),
            "the write waited out the send clock instead of handing the lane a park"
        );
        assert!(
            crate::proxy::write_wait_pending(),
            "the lane was not told to wait on writability"
        );
        drop(step);
    }

    #[test]
    fn a_policy_without_counters_does_not_forbid_the_splice_path() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connects");
        let (server, _) = listener.accept().expect("accepts");
        let stream = Connection::Tcp(server).with_policy(Some(crate::policy::flow(0)));
        assert!(stream.policy().is_some());
        assert!(!stream.metered());
        drop(client);
    }

    /// The row's identity claim is transparency: a Unix stream carries the exact bytes the same
    /// round trip over TCP carries, in both directions, with no re-framing. A differential over
    /// a real `AF_UNIX` socket witnesses it and runs with no root and no `CAP_NET_ADMIN`.
    #[test]
    fn a_unix_connection_carries_the_same_bytes_the_tcp_round_trip_does() {
        let sent: Vec<u8> = (0..64 * 1024u32).map(|i| (i % 253) as u8).collect();
        let over_unix = round_trip_unix(&sent);
        let over_tcp = round_trip_tcp(&sent);
        assert_eq!(
            over_unix, over_tcp,
            "a unix round trip must be byte-identical to the tcp one"
        );
        assert_eq!(
            over_unix, sent,
            "the payload is delivered whole and unchanged"
        );
    }

    /// A head that is not a multiple of any vector width, and a big bulk write the kernel buffer
    /// cannot take at once — the inputs a round number hides — must still arrive whole.
    #[test]
    fn a_unix_round_trip_survives_lengths_a_vector_would_split() {
        for len in [1usize, 3, 1501, 65535] {
            let sent: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                round_trip_unix(&sent),
                sent,
                "{len} bytes round-trip whole over a unix stream"
            );
        }
    }

    /// The timeout setter must arm a Unix read the way it arms a TCP one, or a leg the engine
    /// bounds would park forever on unix while failing on tcp — the budget-parity claim. The bound
    /// read back is what either family can witness; that it then stops the block is proven where a
    /// refusal fails fast instead of parking the suite: a provider that ignored the option would
    /// hang this test, not fail it.
    #[test]
    fn a_unix_read_timeout_arms_the_way_the_tcp_one_does() {
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a TCP listener");
        let tcp = TcpStream::connect(tcp_listener.local_addr().expect("the TCP address"))
            .expect("a native TCP reference");
        tcp.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("arms the native TCP timeout");
        let bound = tcp
            .read_timeout()
            .expect("reads the native TCP bound")
            .expect("TCP has a timeout");
        let (_client, listener) = unix_pair();
        let server = listener.incoming().next().unwrap().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("arms a read timeout on a unix stream");
        assert_eq!(
            server.read_timeout().expect("reads the bound back"),
            Some(bound),
            "a unix stream reports the same kernel bound as TCP"
        );
        #[cfg(unix)]
        match server {
            Connection::Unix(mut reader) => {
                let mut buf = [0u8; 4];
                let error = reader
                    .read(&mut buf)
                    .expect_err("an empty armed unix read times out");
                assert!(
                    matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ),
                    "the bound fired, not a block: {:?}",
                    error.kind()
                );
            }
            Connection::Tcp(_)
            | Connection::Masked(_)
            | Connection::Metered(_)
            | Connection::Proxied { .. }
            | Connection::Policied { .. } => {
                unreachable!("a unix pair yields a unix stream")
            }
        }
    }

    /// The `unix:` spelling is what selects the family before anything is dialed; an empty path
    /// is refused rather than bound at the root.
    #[test]
    fn a_unix_address_parses_to_a_path_and_an_empty_one_is_refused() {
        let target = parse_target("unix:/run/ferrox/sock").expect("parses");
        assert_eq!(target, Target::Unix(PathBuf::from("/run/ferrox/sock")));
        assert!(parse_target("unix:").is_err(), "an empty path is refused");
        assert!(
            matches!(
                parse_target("127.0.0.1:1").expect("ip parses"),
                Target::Ip(_)
            ),
            "an ip:port stays an ip target"
        );
    }

    /// The path field of a socket address is a fixed array on every host — 108 bytes on Linux and
    /// Windows, 104 on macOS — so a name past it is refused, never truncated into a prefix of
    /// itself. The same directory holds the short path that does bind, so the refusal is about the
    /// length and not about where it lives.
    #[test]
    fn a_unix_path_past_the_socket_field_is_refused() {
        let dir = std::env::temp_dir();
        let short = dir.join(format!("ferrox-unix-len-{}", std::process::id()));
        let listener = Listener::bind(&Target::Unix(short.clone()))
            .expect("a path inside the field binds in the same directory");
        drop(listener);
        std::fs::remove_file(&short).ok();
        let long = dir.join("a".repeat(200));
        assert!(
            Listener::bind(&Target::Unix(long)).is_err(),
            "a path past the socket address field is refused, not truncated and bound"
        );
    }

    /// A config naming `unix:@name` names Linux's abstract namespace, not a file called `@name`:
    /// a raw client that spells the name the kernel's own way must reach the listener, and the
    /// seam's own dial must land on it too.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_unix_abstract_name_is_bound_and_dialed() {
        use std::os::linux::net::SocketAddrExt;

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("ferrox-abstract-{:07}-{:03}", std::process::id(), id);
        assert_eq!(name.len(), 27, "the witness spells a 27-byte abstract name");
        let target = parse_target(&format!("unix:@{name}")).expect("the spelling parses");
        let listener = Listener::bind(&target).expect("binds the abstract name");
        std::fs::remove_file(format!("@{name}")).ok();
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
            .expect("an abstract address");
        let mut raw = std::os::unix::net::UnixStream::connect_addr(&address)
            .expect("a raw abstract client reaches the listener");
        let (mut server, _) = listener.accept().expect("accepts the raw client");
        server.write_all(b"r").expect("writes");
        let mut byte = [0u8; 1];
        raw.read_exact(&mut byte).expect("reads");
        assert_eq!(&byte, b"r", "the abstract listener answers the raw client");

        let mut seam =
            connect(&target, Duration::from_secs(5)).expect("the seam dials the abstract name");
        let (mut server, _) = listener.accept().expect("accepts the seam's dial");
        server.write_all(b"s").expect("writes");
        seam.read_exact(&mut byte).expect("reads the second answer");
        assert_eq!(&byte, b"s", "the seam's dial lands on the same listener");
    }

    /// A second `@` asks for the name padded across the kernel's whole `sun_path`, the spelling
    /// haproxy's sockets use: a peer that fills the field — as the reference's dialer does — must
    /// find it, where the short spelling would name a different address.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_doubled_unix_at_names_the_padded_abstract_name() {
        use socket2::{Domain, Socket, Type};

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("ferrox-padded-{:07}-{:03}", std::process::id(), id);
        let target = parse_target(&format!("unix:@@{name}")).expect("the spelling parses");
        let listener = Listener::bind(&target).expect("binds the padded abstract name");
        std::fs::remove_file(format!("@@{name}")).ok();
        // SAFETY: the storage `try_init` hands over is zeroed and sized for any address; the family, marker, name and length written here describe the `sockaddr_un`.
        let ((), address) = unsafe {
            socket2::SockAddr::try_init(|storage, length| {
                let address = storage.cast::<libc::sockaddr_un>();
                let field = (*address).sun_path.len();
                (*address).sun_family = libc::AF_UNIX as libc::sa_family_t;
                let path = std::ptr::addr_of_mut!((*address).sun_path).cast::<u8>();
                for (at, byte) in name.as_bytes().iter().enumerate() {
                    *path.add(at + 1) = *byte;
                }
                *length =
                    (std::mem::offset_of!(libc::sockaddr_un, sun_path) + field) as libc::socklen_t;
                Ok(())
            })
        }
        .expect("the padded address");
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).expect("a unix socket");
        socket
            .connect(&address)
            .expect("a padded abstract client reaches the listener");
        let mut raw = UnixStream::from(std::os::fd::OwnedFd::from(socket));
        let (mut server, _) = listener.accept().expect("accepts the padded client");
        server.write_all(b"p").expect("writes");
        let mut byte = [0u8; 1];
        raw.read_exact(&mut byte).expect("reads");
        assert_eq!(&byte, b"p", "the padded listener answers the padded client");
    }

    /// The comma-separated octal mode the references take after a socket path is applied to the
    /// socket file the listener creates, so a peer that names only the path reaches it under the
    /// mode the config asked for.
    #[cfg(unix)]
    #[test]
    fn a_unix_listener_takes_the_permission_it_names() {
        use std::os::unix::fs::PermissionsExt as _;

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-unix-perm-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("sock");
        let target = parse_target(&format!("unix:{},0770", path.display())).expect("parses");
        let listener = Listener::bind(&target).expect("binds the named path with its mode");
        let mode = std::fs::metadata(&path)
            .expect("the socket file the listener created")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o770,
            "the listener applies the mode the address names"
        );
        let plain =
            parse_target(&format!("unix:{}", path.display())).expect("the bare path parses");
        let mut client = connect(&plain, Duration::from_secs(5))
            .expect("a client that names only the path reaches the listener");
        let (mut server, _) = listener.accept().expect("accepts");
        server.write_all(b"m").expect("writes");
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).expect("reads");
        assert_eq!(
            &byte, b"m",
            "the mode never changed the address the client names"
        );
        let mut spelled = connect(&target, Duration::from_secs(5))
            .expect("the seam dials the same mode-suffixed text the listener took");
        let (mut server, _) = listener.accept().expect("accepts the spelled dial");
        server.write_all(b"s").expect("writes");
        spelled
            .read_exact(&mut byte)
            .expect("reads the second answer");
        assert_eq!(
            &byte, b"s",
            "the mode is a listener spelling, never part of the dialed name"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A single comma whose suffix is not octal is part of the name, not a mode: the text binds
    /// and dials the same literal path a peer outside this tree can name, where a hard error on
    /// that suffix would refuse a path that bound before the mode spelling existed.
    #[cfg(unix)]
    #[test]
    fn a_unix_comma_path_that_is_not_a_mode_stays_literal() {
        use std::os::unix::fs::FileTypeExt as _;

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-unix-comma-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("app,v2.sock");
        assert_eq!(
            b"v2.sock".len(),
            7,
            "the witness spells a 7-byte non-octal suffix"
        );
        let target = parse_target(&format!("unix:{}", path.display())).expect("parses");
        let listener = Listener::bind(&target).expect("the literal comma path binds");
        let mut client =
            connect(&target, Duration::from_secs(5)).expect("the same text dials the literal path");
        let (mut server, _) = listener.accept().expect("accepts");
        server.write_all(b"c").expect("writes");
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).expect("reads");
        assert_eq!(
            &byte, b"c",
            "the literal path serves the text it was bound from"
        );
        let file = std::fs::symlink_metadata(&path).expect("the socket file the listener created");
        assert!(
            file.file_type().is_socket(),
            "the comma stays in the name the listener creates"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A unix listen path that already names a regular file is refused, never removed: a typo in a
    /// config must not delete data on the way to a failed bind.
    #[cfg(unix)]
    #[test]
    fn a_unix_listener_never_removes_a_regular_file() {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-unix-file-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("sock");
        let kept = [b'k'; 16];
        std::fs::write(&path, kept).expect("writes a regular file at the socket path");
        let result = Listener::bind(&Target::Unix(path.clone()));
        assert!(result.is_err(), "binding over a regular file is refused");
        assert_eq!(
            std::fs::read(&path).expect("the file survives the refused bind"),
            kept,
            "the file is untouched"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A mode must not narrow a path that already fills the address field: applying it to a
    /// longer sibling name would make a config that binds without a mode fail with one.
    #[cfg(unix)]
    #[test]
    fn a_unix_mode_on_a_path_at_the_address_field_limit() {
        use std::os::unix::fs::PermissionsExt as _;

        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // The longest path text a socket address holds, less the family field and the trailing NUL.
        let limit = std::mem::size_of::<libc::sockaddr_un>() - 3;
        let root =
            std::env::temp_dir().join(format!("ferrox-unix-limit-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&root).expect("scratch dir");
        let fill = limit - 3 - root.as_os_str().len();
        assert!(fill > 8, "the temp dir leaves room for a deep name");
        let dir = root.join("d".repeat(fill));
        std::fs::create_dir_all(&dir).expect("the deep dir");
        let path = dir.join("s");
        assert_eq!(
            path.as_os_str().len(),
            limit,
            "the witness fills the address field exactly"
        );
        let target = parse_target(&format!("unix:{},0750", path.display())).expect("parses");
        let listener = Listener::bind(&target)
            .expect("a path at the field limit still binds when a mode follows it");
        let mode = std::fs::metadata(&path)
            .expect("the socket file at the field limit")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o750, "the mode reaches the path at the field limit");
        drop(listener);
        std::fs::remove_dir_all(&root).ok();
    }

    /// The staging directory the mode is applied in leaves nothing behind: after a bind with a
    /// mode, the socket's directory holds the socket and no `.ferrox-*` entry.
    #[cfg(unix)]
    #[test]
    fn a_unix_mode_staging_leaves_only_the_socket() {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-unix-stage-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("sock");
        let target = parse_target(&format!("unix:{},0750", path.display())).expect("parses");
        let listener = Listener::bind(&target).expect("binds under the staged mode");
        let left: Vec<_> = std::fs::read_dir(&dir)
            .expect("the socket directory")
            .map(|entry| entry.expect("a directory entry").file_name())
            .collect();
        assert_eq!(
            left,
            vec![std::ffi::OsString::from("sock")],
            "the staging directory is removed, so 0 entries are left behind"
        );
        drop(listener);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A mode on a path whose directory is missing reports the missing directory, not a made-up
    /// "no staged name free": only a name collision is retried, every other error is the caller's.
    #[cfg(unix)]
    #[test]
    fn a_unix_mode_reports_a_missing_directory() {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-unix-missing-{}-{id}", std::process::id()));
        let target =
            parse_target(&format!("unix:{},0750", dir.join("sock").display())).expect("parses");
        let error = Listener::bind(&target)
            .err()
            .expect("a missing directory is refused");
        assert_eq!(
            error.kind(),
            io::ErrorKind::NotFound,
            "the directory's own error, not a staging one"
        );
    }

    /// Linux parks `connect` on a socket path once the listener's backlog is full, so a dial that
    /// is not waited out holds its caller past the budget; the seam spends the budget instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_full_unix_backlog_ends_the_dial_at_its_budget() {
        use socket2::{Domain, SockAddr, Socket, Type};
        use std::sync::mpsc;
        use std::time::Instant;

        let dir = std::env::temp_dir().join(format!("ferrox-unix-full-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("sock");
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None).expect("a unix socket");
        listener
            .bind(&SockAddr::unix(&path).expect("a unix address"))
            .expect("binds");
        listener.listen(1).expect("listens");

        // Queue connections until a blocking dial stops answering: the next dial then has no room.
        let filler_path = path.clone();
        let (progress, filled) = mpsc::channel();
        std::thread::spawn(move || loop {
            match UnixStream::connect(&filler_path) {
                // A queued connection keeps its slot; dropping it would free the room the dial needs to find full.
                Ok(stream) => std::mem::forget(stream),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
            let _ = progress.send(());
        });
        let started = Instant::now();
        while filled.recv_timeout(Duration::from_millis(150)).is_ok() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the backlog never fills"
            );
        }

        let (done, result) = mpsc::channel();
        let dial_path = path.clone();
        std::thread::spawn(move || {
            let _ = done.send(connect(
                &Target::Unix(dial_path),
                Duration::from_millis(200),
            ));
        });
        let attempt = result
            .recv_timeout(Duration::from_secs(5))
            .expect("a full backlog must not hold the dial past its budget");
        let error = attempt.expect_err("a dial with no room must end in the budget's error");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "the budget's error, not another: {:?}",
            error.kind()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn round_trip_unix(sent: &[u8]) -> Vec<u8> {
        let (mut client, listener) = unix_pair();
        let handle = std::thread::spawn(move || {
            let mut server = listener.incoming().next().unwrap().unwrap();
            let mut got = Vec::new();
            server.read_to_end(&mut got).expect("reads the request");
            server.write_all(&got).expect("echoes it");
            server.flush().expect("flushes");
            server.shutdown(Shutdown::Write).expect("half-closes");
        });
        echo_round_trip(&mut client, sent, handle)
    }

    fn round_trip_tcp(sent: &[u8]) -> Vec<u8> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let (mut server, _) = listener.accept().expect("accepts");
            let mut got = Vec::new();
            server.read_to_end(&mut got).expect("reads the request");
            server.write_all(&got).expect("echoes it");
            server.flush().expect("flushes");
            let _ = server.shutdown(Shutdown::Write);
        });
        let mut client: Connection = TcpStream::connect(addr).expect("connects").into();
        echo_round_trip(&mut client, sent, handle)
    }

    fn echo_round_trip(
        client: &mut Connection,
        sent: &[u8],
        handle: std::thread::JoinHandle<()>,
    ) -> Vec<u8> {
        client.write_all(sent).expect("writes the request");
        client.flush().expect("flushes");
        client
            .shutdown(Shutdown::Write)
            .expect("half-closes the write side");
        let mut back = Vec::new();
        client.read_to_end(&mut back).expect("reads the echo");
        handle.join().expect("the echo thread finishes");
        back
    }

    /// A connected unix client and its still-bound listener, in a per-test directory that is
    /// removed so no two runs collide on one socket path.
    fn unix_pair() -> (Connection, Listener) {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ferrox-unix-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("sock");
        let listener = Listener::bind(&Target::Unix(path.clone())).expect("binds a unix socket");
        let client = connect(&Target::Unix(path.clone()), Duration::from_secs(5))
            .expect("connects a unix socket");
        // The socket file lives on by the listener's descriptor; drop the directory entry now so an interrupted run leaves nothing to unlink.
        std::fs::remove_dir_all(&dir).ok();
        (client, listener)
    }

    /// A socket the kernel already connected answers `connect` with an error and no refusal: the dial reports connected, and the read that follows is what reports a peer that left.
    #[test]
    fn an_error_reported_on_a_connected_socket_is_not_a_refusal() {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = SockAddr::from(listener.local_addr().expect("addr"));
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let accept = crate::budgets::spawn(move || {
            let _ = listener.accept();
            let _ = accepted_tx.send(());
        });
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("socket");
        socket.connect(&address).expect("the dial connects");
        accepted_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the peer accepts");
        // The peer has already left. The repeated connect is the branch's own witness: it has to fail, or the dial below never reaches the recovery.
        assert!(
            socket.connect(&address).is_err(),
            "a repeated connect on a connected socket fails"
        );
        connect_bounded(&socket, &address, Duration::from_secs(5)).expect(
            "a second connect reports an error, and the socket it already had is the answer",
        );
        accept.join().expect("joins");
    }

    struct StalledReader {
        armed: std::sync::Arc<std::sync::Mutex<Option<Duration>>>,
    }

    impl std::io::Read for StalledReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl ReadClock for StalledReader {
        fn arm(&self, timeout: Option<Duration>) -> io::Result<()> {
            *self.armed.lock().expect("the clock") = timeout;
            Ok(())
        }
    }

    /// A peer cannot hold a worker by dribbling a byte per clock: every handshake read is clocked
    /// to what is left of one deadline, and a read past it fails instead of arming another.
    #[test]
    fn a_read_past_the_handshake_deadline_never_arms_another_clock() {
        let armed = std::sync::Arc::new(std::sync::Mutex::new(None));
        let deadline = HandshakeDeadline::begin(Duration::from_millis(30));
        let mut reader = DeadlineReader::new(
            StalledReader {
                armed: std::sync::Arc::clone(&armed),
            },
            deadline.clone(),
        );
        let mut byte = [0u8; 1];
        let first = reader.read(&mut byte).expect_err("nothing arrives");
        assert_eq!(first.kind(), io::ErrorKind::WouldBlock);
        let clock = armed.lock().expect("the clock").expect("a clock is armed");
        assert!(!clock.is_zero() && clock <= Duration::from_millis(30));

        std::thread::sleep(Duration::from_millis(40));
        let past = reader.read(&mut byte).expect_err("the deadline passed");
        assert_eq!(past.kind(), io::ErrorKind::TimedOut);
        assert!(
            armed.lock().expect("the clock").is_some(),
            "the clock is left alone once the deadline has passed"
        );

        deadline.end();
        let after = reader.read(&mut byte).expect_err("nothing arrives");
        assert_eq!(after.kind(), io::ErrorKind::WouldBlock);
    }

    /// A peer that dribbles a byte before each clock cannot hold a handshake open: the reads run to
    /// one absolute deadline, not a budget each read restarts.
    #[test]
    fn a_trickled_header_ends_at_the_handshake_deadline() {
        use ferrox_core::finalmask::{Chain, HeaderCustom, Item, MaskRole, Sequence};
        let _cap = crate::budgets::cap_handshake(Duration::from_millis(40));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let peer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connects");
            for byte in b"abcd" {
                std::thread::sleep(Duration::from_millis(30));
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let (side, _) = listener.accept().expect("accepts");
        let clients = Item {
            packet: Some(b"abcd".to_vec()),
            ..Item::default()
        };
        let header = HeaderCustom::new(
            vec![Sequence {
                items: vec![clients],
            }],
            Vec::new(),
            Vec::new(),
        )
        .expect("a mask the config can drive");
        let mut chain = Chain::default();
        chain.push_header_custom(header);
        let connection = Connection::Tcp(side).with_mask_role(Some(&chain), MaskRole::Server);
        let began = std::time::Instant::now();
        connection
            .start_mask()
            .expect_err("the trickle runs out the deadline");
        assert!(
            began.elapsed() < Duration::from_millis(120),
            "the handshake outlived its one deadline"
        );
        peer.join().expect("joins");
    }

    /// The login keeps the reference's two minutes on a dial, and an admission shortens it to the
    /// budget the lane still has.
    #[test]
    fn the_xmc_deadline_is_the_smaller_of_two_minutes_and_what_admission_left() {
        assert_eq!(xmc_deadline(None), XMC_HANDSHAKE_TIMEOUT);
        assert_eq!(
            xmc_deadline(Some(Duration::from_secs(5))),
            Duration::from_secs(5)
        );
        assert_eq!(
            xmc_deadline(Some(Duration::from_secs(300))),
            XMC_HANDSHAKE_TIMEOUT
        );
    }
}
