//! DPI-resistant TCP fragmentation, the synchronous shape of the reference's
//! `fragmentor.Conn`: the first bytes of a dial leave in several small writes
//! with random pauses, then the stream resumes its ordinary width.
//!
//! The bytes and their order are unchanged. Only the size and timing of the
//! initial TCP writes move, which is what a middlebox that reassembles an
//! application message across segments observes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::psiphon_ssh::random;

/// The reference's largest default fragment.
const DEFAULT_MAX_WRITE: usize = 1500;

/// The `Fragmentor*` parameters one dial may use.
#[derive(Clone, Debug)]
pub(crate) struct Fragmentor {
    probability: f64,
    protocols: Vec<String>,
    min_total: usize,
    max_total: usize,
    min_write: usize,
    max_write: usize,
    min_delay: Duration,
    max_delay: Duration,
    allow_with_prefix: bool,
}

impl Default for Fragmentor {
    /// The reference defaults: half the dials, no protocol limit, 1500-byte writes, 10 ms pauses.
    fn default() -> Self {
        Self {
            probability: 0.5,
            protocols: Vec::new(),
            min_total: 0,
            max_total: 0,
            min_write: 1,
            max_write: DEFAULT_MAX_WRITE,
            min_delay: Duration::ZERO,
            max_delay: Duration::from_millis(10),
            allow_with_prefix: false,
        }
    }
}

impl Fragmentor {
    /// Store the reference parameters, clamping each to its valid range.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        probability: f64,
        protocols: Vec<String>,
        min_total: usize,
        max_total: usize,
        min_write: usize,
        max_write: usize,
        min_delay: Duration,
        max_delay: Duration,
        allow_with_prefix: bool,
    ) -> Self {
        Self {
            probability: probability.clamp(0.0, 1.0),
            protocols,
            min_total: min_total.min(max_total),
            max_total,
            min_write: min_write.max(1).min(max_write.max(1)),
            max_write: max_write.max(1),
            min_delay: min_delay.min(max_delay),
            max_delay,
            allow_with_prefix,
        }
    }

    /// Whether this dial may fragment. An OSSH prefix suppresses the fragmentor
    /// unless `OSSHPrefixEnableFragmentor` turns it back on, as the reference does.
    pub(crate) fn may_fragment(&self, protocol: &str, prefixed: bool) -> bool {
        if self.max_total == 0 || (prefixed && !self.allow_with_prefix) {
            return false;
        }
        self.protocols.is_empty()
            || self
                .protocols
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
    }

    /// How many leading bytes this dial fragments, zero when the coin fails.
    fn plan(&self) -> usize {
        if !coin(self.probability) {
            return 0;
        }
        random_range(self.min_total, self.max_total)
    }

    /// One fragment size, never wider than what remains.
    fn write_size(&self, remaining: usize) -> usize {
        let low = self.min_write.min(remaining).max(1);
        let high = self.max_write.min(remaining).max(low);
        random_range(low, high)
    }

    /// A random pause between this dial's bounds.
    fn delay(&self) -> Duration {
        let low = duration_nanos(self.min_delay);
        let high = duration_nanos(self.max_delay).max(low);
        if high == low {
            return Duration::from_nanos(low);
        }
        Duration::from_nanos(low + random_below(high - low + 1))
    }
}

/// A duration in nanoseconds, saturating at the type limit.
fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// A random value in `0..bound`.
fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    u64::from_be_bytes(random::<8>()) % bound
}

/// A random value in the inclusive range.
fn random_range(low: usize, high: usize) -> usize {
    if high <= low {
        return low;
    }
    low + usize::try_from(random_below(
        u64::try_from(high - low).unwrap_or(u64::MAX) + 1,
    ))
    .unwrap_or(0)
}

/// One random coin with the given probability.
fn coin(probability: f64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    f64::from(u16::from_be_bytes(random::<2>())) / 65_536.0 < probability
}

struct State {
    bytes_to_fragment: i64,
    fragmented: usize,
}

/// A TCP stream whose initial writes are split and paced.
pub(crate) struct FragmentStream {
    socket: TcpStream,
    config: Arc<Fragmentor>,
    state: Arc<Mutex<State>>,
}

impl FragmentStream {
    /// Wrap a dial in the fragmentor's first-write plan.
    pub(crate) fn new(socket: TcpStream, config: Fragmentor) -> Self {
        Self {
            socket,
            config: Arc::new(config),
            state: Arc::new(Mutex::new(State {
                bytes_to_fragment: -1,
                fragmented: 0,
            })),
        }
    }

    /// Clone the socket and its remaining fragment plan.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
            config: Arc::clone(&self.config),
            state: Arc::clone(&self.state),
        })
    }

    /// The socket beneath the fragment writes.
    pub(crate) fn get_ref(&self) -> &TcpStream {
        &self.socket
    }

    /// Forward the read timeout to the socket.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Forward the write timeout to the socket.
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    /// Forward the shutdown to the socket.
    pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }
}

impl ferrox_core::tls::RecordAlignment for FragmentStream {}

impl Read for FragmentStream {
    /// Reads pass straight through; only writes are fragmented.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.read(buffer)
    }
}

impl Write for FragmentStream {
    /// Write the planned leading bytes in fragments, then the rest ordinarily.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("psiphon fragmentor lock"))?;
        if state.bytes_to_fragment < 0 {
            state.bytes_to_fragment = i64::try_from(self.config.plan()).unwrap_or(i64::MAX);
        }
        if state.fragmented >= usize::try_from(state.bytes_to_fragment).unwrap_or(usize::MAX) {
            return self.socket.write(buffer);
        }
        let mut written = 0;
        while written < buffer.len() {
            std::thread::sleep(self.config.delay());
            let size = self.config.write_size(buffer.len() - written);
            let end = written + size;
            match self.socket.write(&buffer[written..end]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "psiphon fragmentor wrote zero bytes",
                    ));
                }
                Ok(count) => {
                    written += count;
                    state.fragmented += count;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) if written > 0 => return Ok(written),
                Err(error) => return Err(error),
            }
            let target = usize::try_from(state.bytes_to_fragment).unwrap_or(usize::MAX);
            if state.fragmented >= target {
                break;
            }
        }
        Ok(written)
    }

    /// Flatten the slices once, then use the ordinary write path.
    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if buffers.len() == 1 {
            return self.write(&buffers[0]);
        }
        let mut all = Vec::new();
        for buffer in buffers {
            all.extend_from_slice(buffer);
        }
        self.write(&all)
    }

    /// Flush the underlying socket.
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A connected loopback pair for fragment tests.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).expect("client");
        let (server, _) = listener.accept().expect("server");
        (client, server)
    }

    #[test]
    /// A zero total disables fragmentation.
    fn a_zero_total_never_fragments() {
        let config = Fragmentor::default();
        assert!(!config.may_fragment("OSSH", false));
    }

    #[test]
    /// A prefixed dial fragments only when the switch allows it.
    fn a_prefixed_dial_needs_the_switch() {
        let mut config = Fragmentor::new(
            1.0,
            Vec::new(),
            4,
            8,
            1,
            2,
            Duration::ZERO,
            Duration::ZERO,
            false,
        );
        assert!(!config.may_fragment("OSSH", true));
        config.allow_with_prefix = true;
        assert!(config.may_fragment("OSSH", true));
        assert!(config.may_fragment("SSH", false));
    }

    #[test]
    /// A protocol list fragments only the protocols it names.
    fn a_protocol_limit_names_only_its_protocols() {
        let config = Fragmentor::new(
            1.0,
            vec!["OSSH".to_owned()],
            4,
            8,
            1,
            2,
            Duration::ZERO,
            Duration::ZERO,
            true,
        );
        assert!(config.may_fragment("ossh", false));
        assert!(!config.may_fragment("TLS-OSSH", false));
    }

    #[test]
    /// Fragmentation changes the writes, not the bytes or their order.
    fn the_bytes_and_their_order_are_unchanged() {
        let (mut client, mut server) = pair();
        let config = Fragmentor::new(
            1.0,
            Vec::new(),
            64,
            64,
            1,
            3,
            Duration::ZERO,
            Duration::ZERO,
            true,
        );
        let mut stream = FragmentStream::new(client.try_clone().expect("clone"), config);
        let payload: Vec<u8> = (0..200u8).collect();
        stream.write_all(&payload).expect("write");
        drop(stream);
        let mut received = vec![0u8; payload.len()];
        server.read_exact(&mut received).expect("read");
        assert_eq!(received, payload);
        client.write_all(b"x").ok();
    }

    #[test]
    /// A failed coin leaves the dial as one ordinary write.
    fn a_failed_coin_is_a_plain_write() {
        let config = Fragmentor::new(
            0.0,
            Vec::new(),
            64,
            64,
            1,
            1,
            Duration::ZERO,
            Duration::ZERO,
            true,
        );
        assert_eq!(config.plan(), 0);
    }
}
