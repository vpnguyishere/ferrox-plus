use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// Every wait cadence in the app: the dial, the handshake read, the relay polls, the head arrival, the carrier probe, the payload grace, the idle timeouts. A hang hunt starts here; anything that can wait and how long is named on this page, and which of them holds a thread right now is the census' dump.

pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

// Bound the raw opening request read: a peer that connects and stays silent must not pin its per-connection thread forever.
pub(crate) const HANDSHAKE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const RELAY_POLL: Duration = Duration::from_millis(1);

/// A shaped handshake's read quantum: the core gives a hello 1500 polls, so 20 ms here is its 30 s budget.
pub(crate) const HANDSHAKE_POLL: Duration = Duration::from_millis(20);

/// How long a lane keeps reading after its sibling ended: a peer may answer after the FIN, and xray-core's own `UplinkOnly` default is one second. Past it the lane hands its thread back, so a peer that never answers cannot park it.
pub(crate) const RELAY_RESPONSE_IDLE: Duration = Duration::from_secs(1);

/// How long a connection we refused stays open after its GOAWAY: closing with the peer's bytes still unread makes the stack abort with RST, and that can swallow the refusal itself.
pub(crate) const GOAWAY_GRACE: Duration = Duration::from_millis(100);

/// How long the blackhole sink holds a flow open after its answer: the peer's bytes are read in that window, so the close is a finish and not the reset an unread request earns. Half the reference's own second, so the flow the sink holds is never longer than the one it replaces.
pub(crate) const SINK_GRACE: Duration = Duration::from_millis(500);

/// How long a shared read holds the lock while its flow is moving: under one grain on purpose, so a writer never waits out the wait.
pub(crate) const SESSION_POLL: Duration = Duration::from_millis(1);

/// Empty shared reads a flow may keep the short grain for: a pause between two writes must not cost the second the long grain.
pub(crate) const RELAY_MOVING_READS: u32 = 64;

pub(crate) const RELAY_HANDOFF_SPINS: u32 = 64;

/// One leg's wait for its partner after the flow has ended: a partner still missing past the relay's own idle bound is starved rather than draining, and a thread that waits forever turns one stalled peer into a pile-up of held sessions.
pub(crate) const RELAY_JOIN: Duration = Duration::from_secs(120);

/// One relay leg's patience: how long a copy may sit against a socket that moves neither way before the flow is given up. A peer that stops reading and never closes otherwise parks a worker, its duplicated descriptors and a copy buffer for the life of the process.
pub(crate) const RELAY_STALL: Duration = Duration::from_secs(120);

pub(crate) const RELAY_LOCK_TRIES: u32 = 64;

/// How long a relay worker may sit unclaimed before it hands its thread back: long enough for the next flow to reuse it, short enough that a burst of finished flows leaves no residue.
pub(crate) const RELAY_WORKER_LIFE: Duration = Duration::from_secs(30);

/// A head's arrival budget: without one a quiet peer keeps a task waking once per poll, burning a core.
pub(crate) const HEAD_DEADLINE: Duration = Duration::from_secs(20);

/// The bound on one backward read's lock hold: without it the first idle read wedges every upload.
pub(crate) const RELAY_QUANTUM: Duration = Duration::from_millis(100);

/// How long an `auto` carrier the user did not ask for is proven for; a configured one gets the full budget.
pub(crate) const CARRIER_PROBE: Duration = Duration::from_millis(2_500);

/// A silent edge's quarantine: long enough to skip a per-flow probe, short enough to find it answering again.
pub(crate) const CARRIER_DEAD_SECS: u64 = 60;

/// Sign-in attempts and the first pause: a refused credential is the only answer that is not worth asking again.
pub(crate) const ACCOUNT_ATTEMPTS: usize = 4;
pub(crate) const ACCOUNT_BACKOFF_SECS: u64 = 5;

/// The ceiling on a guessed retry pause: a plane that says nothing is still asked again on a clock, never more rarely than this.
pub(crate) const ACCOUNT_RETRY_CAP: u64 = 900;

/// The ceiling on a wait the plane named: past this, a `Retry-After` is a number a renewal should not sleep on.
pub(crate) const ACCOUNT_NAMED_WAIT_MAX: u64 = 12 * 3_600;

/// A quiet poll's sleep: long enough not to spin, short enough that traffic never feels it.
pub(crate) const RELAY_IDLE: Duration = Duration::from_millis(10);

pub(crate) const UDP_IDLE: Duration = Duration::from_secs(120);

/// How long a carrier may stay open and silent before the app's payload goes out ahead of the answer: a carrier that refuses inside the window leaves the bytes for the ladder's next rung.
pub(crate) const PAYLOAD_GRACE: Duration = Duration::from_millis(100);

/// One wait a config can restate, in the order `CONSTANTS`, `SLOTS` and `as_table` carry it.
#[derive(Clone, Copy)]
enum Named {
    Dial,
    Handshake,
    HeadArrival,
    RelayJoin,
    RelayQuantum,
    RelayStall,
    UdpIdle,
    PayloadGrace,
    GoawayGrace,
    SinkGrace,
    CarrierProbe,
}

/// The constant beside each name, read when nothing has restated it.
const CONSTANTS: [Duration; 11] = [
    DIAL_TIMEOUT,
    HANDSHAKE_REQUEST_TIMEOUT,
    HEAD_DEADLINE,
    RELAY_JOIN,
    RELAY_QUANTUM,
    RELAY_STALL,
    UDP_IDLE,
    PAYLOAD_GRACE,
    GOAWAY_GRACE,
    SINK_GRACE,
    CARRIER_PROBE,
];

// The same waits restated by a config, in milliseconds, where zero means the name was never written. Each getter is read once per flow — at a dial, a handshake arm, a relay teardown, an idle arming — and never inside a byte loop, so naming a budget adds no operation to a measured path. Cadences that pace a loop (`RELAY_POLL`, `SESSION_POLL`, `RELAY_IDLE`, the spin and try counts) stay constants on purpose: a runtime cadence is a load per iteration in the hottest loop this file describes.
static SLOTS: [AtomicU64; 11] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// A config's waits in `Named` order: the one place the eleven names are spelled out.
fn as_table(overrides: &crate::config::Budgets) -> [Option<Duration>; 11] {
    [
        overrides.dial,
        overrides.handshake,
        overrides.head_arrival,
        overrides.relay_join,
        overrides.relay_quantum,
        overrides.relay_stall,
        overrides.udp_idle,
        overrides.payload_grace,
        overrides.goaway_grace,
        overrides.sink_grace,
        overrides.carrier_probe,
    ]
}

/// The wait one site reads: the value a test armed for this thread, else the one the config named, else the constant.
fn wait(named: Named) -> Duration {
    #[cfg(test)]
    if let Some(armed) = MINE.with(|cell| cell.get()[named as usize]) {
        return armed;
    }
    match SLOTS[named as usize].load(Ordering::Relaxed) {
        0 => CONSTANTS[named as usize],
        millis => Duration::from_millis(millis),
    }
}

pub(crate) fn dial() -> Duration {
    wait(Named::Dial)
}

thread_local! {
    static HANDSHAKE_CAP: Cell<Option<std::time::Instant>> = const { Cell::new(None) };
}

pub(crate) struct HandshakeCap(Option<std::time::Instant>);

pub(crate) fn cap_handshake(remaining: Duration) -> HandshakeCap {
    let until = std::time::Instant::now() + remaining;
    let previous = HANDSHAKE_CAP.with(|cell| cell.replace(Some(until)));
    HandshakeCap(previous)
}

impl Drop for HandshakeCap {
    fn drop(&mut self) {
        let previous = self.0;
        HANDSHAKE_CAP.with(|cell| cell.set(previous));
    }
}

pub(crate) fn handshake() -> Duration {
    let configured = wait(Named::Handshake);
    handshake_cap().map_or(configured, |cap| configured.min(cap))
}

pub(crate) fn handshake_cap() -> Option<Duration> {
    HANDSHAKE_CAP.with(|cell| {
        cell.get()
            .map(|until| until.saturating_duration_since(std::time::Instant::now()))
    })
}

pub(crate) fn head_arrival() -> Duration {
    wait(Named::HeadArrival)
}

pub(crate) fn relay_join() -> Duration {
    wait(Named::RelayJoin)
}

pub(crate) fn relay_quantum() -> Duration {
    wait(Named::RelayQuantum)
}

pub(crate) fn relay_stall() -> Duration {
    wait(Named::RelayStall)
}

pub(crate) fn udp_idle() -> Duration {
    wait(Named::UdpIdle)
}

pub(crate) fn payload_grace() -> Duration {
    wait(Named::PayloadGrace)
}

pub(crate) fn goaway_grace() -> Duration {
    wait(Named::GoawayGrace)
}

pub(crate) fn sink_grace() -> Duration {
    wait(Named::SinkGrace)
}

pub(crate) fn carrier_probe() -> Duration {
    wait(Named::CarrierProbe)
}

/// Write every budget the config named; a name it did not write stays the constant above.
pub(crate) fn apply_config(overrides: &crate::config::Budgets) {
    for (slot, value) in SLOTS.iter().zip(as_table(overrides)) {
        if let Some(value) = value {
            slot.store(
                u64::try_from(value.as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The waits a test armed for its own flows: this thread reads them, and every thread it starts carries them. A concurrent test reads the constants, so an arm is measured against the budgets the suite is not racing.
    static MINE: std::cell::Cell<[Option<Duration>; 11]> = const { std::cell::Cell::new([None; 11]) };
}

/// Arm the waits this test's own flows read; a name it leaves out keeps the constant.
#[cfg(test)]
pub(crate) fn apply(overrides: &crate::config::Budgets) {
    let named = as_table(overrides);
    MINE.with(|cell| {
        let mut armed = cell.get();
        for (slot, value) in armed.iter_mut().zip(named) {
            if value.is_some() {
                *slot = value;
            }
        }
        cell.set(armed);
    });
}

/// Hand the table back, so a test that named nothing reads the constants again.
#[cfg(test)]
pub(crate) fn clear() {
    MINE.with(|cell| cell.set([None; 11]));
    for slot in &SLOTS {
        slot.store(0, Ordering::Relaxed);
    }
}

/// A body for a thread this one starts: it reads the waits this thread armed, not the constants.
#[cfg(test)]
pub(crate) fn carrying<F: FnOnce() -> T + Send, T: Send>(body: F) -> impl FnOnce() -> T + Send {
    let armed = MINE.with(std::cell::Cell::get);
    move || {
        MINE.with(|cell| cell.set(armed));
        body()
    }
}

/// A thread a test starts, for the flow the test drives off its own thread: `thread::spawn` drops the arm.
#[cfg(test)]
pub(crate) fn spawn<F: FnOnce() -> T + Send + 'static, T: Send + 'static>(
    body: F,
) -> std::thread::JoinHandle<T> {
    std::thread::spawn(carrying(body))
}

/// The same thread in a shipped binary, where the table is the process's and every thread already reads it.
#[cfg(not(test))]
pub(crate) fn spawn<F: FnOnce() -> T + Send + 'static, T: Send + 'static>(
    body: F,
) -> std::thread::JoinHandle<T> {
    std::thread::spawn(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An arm is this thread's, so the constants are read before it and after it by the same test and by every other test at any thread count.
    #[test]
    fn a_budget_the_config_names_is_the_value_a_site_reads() {
        // Nothing has armed the table, so each site reads the constant beside its name.
        assert_eq!(dial(), DIAL_TIMEOUT);
        assert_eq!(handshake(), HANDSHAKE_REQUEST_TIMEOUT);
        assert_eq!(head_arrival(), HEAD_DEADLINE);
        assert_eq!(relay_join(), RELAY_JOIN);
        assert_eq!(relay_quantum(), RELAY_QUANTUM);
        assert_eq!(relay_stall(), RELAY_STALL);
        assert_eq!(udp_idle(), UDP_IDLE);
        assert_eq!(payload_grace(), PAYLOAD_GRACE);
        assert_eq!(goaway_grace(), GOAWAY_GRACE);
        assert_eq!(sink_grace(), SINK_GRACE);
        assert_eq!(carrier_probe(), CARRIER_PROBE);

        let root = crate::json::parse(
            r#"{"budgets": {"dial": "20s", "handshake": "30s", "headArrival": "40s",
                            "relayJoin": "5mn", "relayQuantum": "250ms", "relayStall": "180s",
                            "udpIdle": "300s", "sinkGrace": "750ms",
                            "payloadGrace": "400ms", "goawayGrace": "200ms", "carrierProbe": "3s"}}"#,
        )
        .expect("parses");
        // A name spelled past the units the engine reads is refused with its own name, not silently the default.
        let error = crate::config::budgets(&root).expect_err("`5mn` names no wait");
        assert!(error.contains("relayJoin"), "{error}");

        let root = crate::json::parse(
            r#"{"budgets": {"dial": "20s", "handshake": "30s", "headArrival": "40s",
                            "relayJoin": "300s", "relayQuantum": "250ms", "relayStall": "180s",
                            "udpIdle": "300s", "sinkGrace": "750ms",
                            "payloadGrace": "400ms", "goawayGrace": "200ms", "carrierProbe": "3s"}}"#,
        )
        .expect("parses");
        apply(&crate::config::budgets(&root).expect("every name is one the engine acts on"));
        assert_eq!(dial(), Duration::from_secs(20));
        assert_eq!(handshake(), Duration::from_secs(30));
        assert_eq!(head_arrival(), Duration::from_secs(40));
        assert_eq!(relay_join(), Duration::from_secs(300));
        assert_eq!(relay_quantum(), Duration::from_millis(250));
        assert_eq!(relay_stall(), Duration::from_secs(180));
        assert_eq!(udp_idle(), Duration::from_secs(300));
        assert_eq!(sink_grace(), Duration::from_millis(750));
        assert_eq!(payload_grace(), Duration::from_millis(400));
        assert_eq!(goaway_grace(), Duration::from_millis(200));
        assert_eq!(carrier_probe(), Duration::from_secs(3));
        clear();
        assert_eq!(
            carrier_probe(),
            CARRIER_PROBE,
            "an unnamed wait is its constant"
        );
    }

    /// A setup lane that waited in the queue spends that wait from the handshake budget it has left.
    #[test]
    fn a_setup_lane_spends_its_queue_time_from_the_handshake_budget() {
        let full = handshake();
        let cap = cap_handshake(Duration::from_millis(1));
        assert!(handshake() <= Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(handshake(), Duration::ZERO);
        drop(cap);
        assert_eq!(handshake(), full);
    }

    /// A thread a test starts reads the table it armed, so a flow that runs off the test's own thread is still measured against the named wait.
    #[test]
    fn a_spawned_thread_reads_the_table_its_starter_armed() {
        apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let seen = spawn(handshake).join().expect("joins");
        clear();
        assert_eq!(seen, Duration::from_millis(250));
        assert_eq!(handshake(), HANDSHAKE_REQUEST_TIMEOUT);
    }
}
