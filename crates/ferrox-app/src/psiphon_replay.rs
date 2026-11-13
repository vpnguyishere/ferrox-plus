//! The reference's dial-parameter replay: a successful dial's chosen server and
//! shape seed are remembered per host, then reused while the entry, config state
//! and TTL still match.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::psiphon_ssh::{random, Server, Session};

/// The `Replay*` fields, with the reference defaults.
#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub(crate) disable: bool,
    pub(crate) candidate_count: i64,
    pub(crate) ttl: Duration,
    pub(crate) target_upstream: u64,
    pub(crate) target_downstream: u64,
    pub(crate) target_duration: Duration,
    pub(crate) later_round_move_to_front: f64,
    pub(crate) retain_failed: f64,
    pub(crate) ignore_changed_config_state: f64,
    pub(crate) fronted_ttl: Duration,
    pub(crate) fronted_update_frequency: Duration,
    pub(crate) fronted_probability: f64,
    pub(crate) fronted_retain_failed: f64,
    pub(crate) inproxy_broker_ttl: Duration,
    pub(crate) inproxy_broker_update_frequency: Duration,
    pub(crate) inproxy_broker_probability: f64,
    pub(crate) inproxy_broker_retain_failed: f64,
    pub(crate) inproxy_retain_failed: f64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            disable: false,
            candidate_count: 10,
            ttl: Duration::from_hours(24),
            target_upstream: 0,
            target_downstream: 0,
            target_duration: Duration::from_secs(1),
            later_round_move_to_front: 0.0,
            retain_failed: 0.5,
            ignore_changed_config_state: 0.0,
            fronted_ttl: Duration::from_hours(24),
            fronted_update_frequency: Duration::from_mins(5),
            fronted_probability: 1.0,
            fronted_retain_failed: 0.5,
            inproxy_broker_ttl: Duration::from_hours(24),
            inproxy_broker_update_frequency: Duration::from_mins(5),
            inproxy_broker_probability: 1.0,
            inproxy_broker_retain_failed: 0.5,
            inproxy_retain_failed: 1.0,
        }
    }
}

/// One class's replay window and failure policy.
struct Profile {
    ttl: Duration,
    update_frequency: Duration,
    probability: f64,
    retain_failed: f64,
}

pub(crate) struct Cache {
    settings: Settings,
    state: Mutex<State>,
}

struct State {
    entries: HashMap<String, Entry>,
    candidates: i64,
    round: u64,
}

struct Entry {
    server: Server,
    seed: [u8; 32],
    config_state: u64,
    server_hash: u64,
    last_used: Instant,
    created: Instant,
    session_id: usize,
    established: bool,
    succeeded: bool,
}

/// A dial attempt's replay decision, held for its success or failure outcome.
pub(crate) struct Lease {
    cache: Arc<Cache>,
    key: String,
    server: Server,
    seed: [u8; 32],
    config_state: u64,
    server_hash: u64,
    is_replay: bool,
}

impl Cache {
    /// Build a cache that applies `settings` to every round.
    pub(crate) fn new(settings: Settings) -> Self {
        Self {
            settings,
            state: Mutex::new(State {
                entries: HashMap::new(),
                candidates: 0,
                round: 0,
            }),
        }
    }

    /// Start an establishment pass, resetting the candidate budget.
    pub(crate) fn start_pass(&self) {
        let mut state = lock(&self.state);
        state.round = 0;
        state.candidates = 0;
    }

    /// Start a later pass over the entries without refilling the candidate budget.
    pub(crate) fn next_round(&self) {
        let mut state = lock(&self.state);
        state.round = state.round.saturating_add(1);
    }

    /// Whether this round moves stored dial parameters to the front of the list.
    pub(crate) fn wants_move_to_front(&self) -> bool {
        if self.settings.disable || self.settings.candidate_count == 0 {
            return false;
        }
        let state = lock(&self.state);
        if state.round == 0 {
            return true;
        }
        coin(self.settings.later_round_move_to_front)
    }

    /// Move entries that have stored dial parameters ahead of the rest, preserving order.
    pub(crate) fn move_to_front(&self, entries: &mut Vec<Server>) {
        let state = lock(&self.state);
        let mut replay = Vec::with_capacity(entries.len());
        let mut rest = Vec::with_capacity(entries.len());
        for server in entries.drain(..) {
            let replayable = state.entries.get(&server.host).is_some_and(|entry| {
                entry.succeeded
                    && entry.server_hash == hash_server(&server)
                    && entry.last_used.elapsed() <= self.settings.profile(&server).ttl
            });
            if replayable {
                replay.push(server);
            } else {
                rest.push(server);
            }
        }
        for index in (1..replay.len()).rev() {
            let bound = u64::try_from(index).unwrap_or(0).saturating_add(1);
            let pick = usize::try_from(u64::from_be_bytes(random::<8>()) % bound).unwrap_or(0);
            replay.swap(index, pick);
        }
        replay.extend(rest);
        *entries = replay;
    }

    /// Choose the server and shape seed for one attempt.
    pub(crate) fn begin(self: &Arc<Self>, server: &Server, config_state: u64) -> Lease {
        let key = server.host.clone();
        let server_hash = hash_server(server);
        let profile = self.settings.profile(server);
        let mut state = lock(&self.state);
        let candidates_left =
            self.settings.candidate_count < 0 || state.candidates < self.settings.candidate_count;
        let mut selected = server.clone();
        let mut seed = random::<32>();
        let mut is_replay = false;
        if !self.settings.disable
            && profile.ttl > Duration::ZERO
            && candidates_left
            && coin(profile.probability)
        {
            if let Some(entry) = state.entries.get(&key) {
                let config_ok = entry.config_state == config_state
                    || coin(self.settings.ignore_changed_config_state);
                if entry.succeeded
                    && entry.server_hash == server_hash
                    && entry.last_used.elapsed() <= profile.ttl
                    && config_ok
                {
                    selected = entry.server.clone();
                    seed = entry.seed;
                    is_replay = true;
                }
            }
        }
        state.candidates = state.candidates.saturating_add(1);
        Lease {
            cache: Arc::clone(self),
            key,
            server: selected,
            seed,
            config_state,
            server_hash,
            is_replay,
        }
    }

    #[cfg(test)]
    /// Mark a stored entry as having met its transfer targets.
    pub(crate) fn mark_succeeded(&self, host: &str) {
        let mut state = lock(&self.state);
        if let Some(entry) = state.entries.get_mut(host) {
            entry.succeeded = true;
            entry.last_used = Instant::now();
        }
    }

    /// Promote established sessions that reached the configured transfer targets.
    pub(crate) fn promote(&self, sessions: &[Arc<Session>]) {
        let mut state = lock(&self.state);
        let mut drop = Vec::new();
        for session in sessions {
            let key = session_key(session.server());
            let Some(entry) = state.entries.get_mut(key) else {
                continue;
            };
            if entry.session_id != session.id() {
                continue;
            }
            if entry.succeeded {
                continue;
            }
            if entry.established
                && session.bytes_up() >= self.settings.target_upstream
                && session.bytes_down() >= self.settings.target_downstream
                && session.age() >= self.settings.target_duration
            {
                entry.succeeded = true;
                entry.last_used = Instant::now();
            } else if session.is_closed() {
                drop.push(key.to_owned());
            }
        }
        for key in drop {
            state.entries.remove(&key);
        }
    }
}

impl Lease {
    /// The server this attempt must dial.
    pub(crate) fn server(&self) -> &Server {
        &self.server
    }

    /// The seed that makes this attempt's dial shape replayable.
    pub(crate) fn seed(&self) -> [u8; 32] {
        self.seed
    }

    #[cfg(test)]
    /// Whether this attempt reused stored dial parameters.
    pub(crate) fn is_replay(&self) -> bool {
        self.is_replay
    }

    /// Record that the dial established a session.
    pub(crate) fn succeeded(&self, session_id: usize) {
        let profile = self.cache.settings.profile(&self.server);
        let now = Instant::now();
        let mut state = lock(&self.cache.state);
        let entry = state
            .entries
            .entry(self.key.clone())
            .or_insert_with(|| Entry {
                server: self.server.clone(),
                seed: self.seed,
                config_state: self.config_state,
                server_hash: self.server_hash,
                last_used: now,
                created: now,
                session_id,
                established: false,
                succeeded: false,
            });
        let replay_matches = entry.server_hash == self.server_hash && entry.seed == self.seed;
        entry.server = self.server.clone();
        entry.config_state = self.config_state;
        entry.server_hash = self.server_hash;
        entry.last_used = now;
        entry.session_id = session_id;
        entry.established = true;
        if !self.is_replay || !replay_matches {
            entry.succeeded = false;
            entry.seed = self.seed;
            entry.created = now;
        } else if profile.update_frequency > Duration::ZERO
            && entry.created.elapsed() >= profile.update_frequency
        {
            entry.seed = random::<32>();
            entry.created = now;
        }
    }

    /// Drop stored parameters after a failed replay, subject to the retain coin.
    pub(crate) fn failed(&self) {
        if !self.is_replay {
            return;
        }
        let profile = self.cache.settings.profile(&self.server);
        let retain = coin(profile.retain_failed)
            || (self.server.inproxy.is_some() || self.server.tls_inproxy.is_some())
                && (coin(self.cache.settings.retain_failed)
                    || coin(self.cache.settings.inproxy_retain_failed));
        if retain {
            return;
        }
        let mut state = lock(&self.cache.state);
        let Some(entry) = state.entries.get(&self.key) else {
            return;
        };
        if entry.server_hash != self.server_hash
            || entry.config_state != self.config_state
            || entry.seed != self.seed
        {
            return;
        }
        state.entries.remove(&self.key);
    }
}

impl Settings {
    /// The replay window and failure policy for this server's transport class.
    fn profile(&self, server: &Server) -> Profile {
        if server.inproxy.is_some() || server.tls_inproxy.is_some() {
            return Profile {
                ttl: self.inproxy_broker_ttl,
                update_frequency: self.inproxy_broker_update_frequency,
                probability: self.inproxy_broker_probability,
                retain_failed: self.inproxy_broker_retain_failed,
            };
        }
        if server.meek.as_ref().is_some_and(|meek| meek.fronted)
            || server.fronting_provider_id.is_some()
        {
            return Profile {
                ttl: self.fronted_ttl,
                update_frequency: self.fronted_update_frequency,
                probability: self.fronted_probability,
                retain_failed: self.fronted_retain_failed,
            };
        }
        Profile {
            ttl: self.ttl,
            update_frequency: Duration::ZERO,
            probability: 1.0,
            retain_failed: self.retain_failed,
        }
    }
}

/// Take a cache lock, ignoring a poisoned guard.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The host part of a `host:port` session name.
fn session_key(server: &str) -> &str {
    server.rsplit_once(':').map_or(server, |(host, _)| host)
}

/// Hash the selected entry so a changed server does not replay.
fn hash_server(server: &Server) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{server:?}").hash(&mut hasher);
    hasher.finish()
}

/// One weighted coin, with the reference's inclusive endpoints.
fn coin(probability: f64) -> bool {
    if probability >= 1.0 {
        return true;
    }
    if probability <= 0.0 {
        return false;
    }
    f64::from(u16::from_be_bytes(random::<2>())) / 65_536.0 < probability
}

#[cfg(test)]
mod tests {
    use super::{lock, Cache, Settings};
    use crate::psiphon_ssh::{dial_random, dial_seed_scope, Server};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn server(host: &str, port: u16) -> Server {
        Server {
            host: host.to_owned(),
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port,
            ssh_port: None,
            quic: false,
            quic_port: None,
            quic_versions: Vec::new(),
            quic_noise: None,
            user: "user".to_owned(),
            password: "pass".to_owned(),
            host_key: vec![1, 2, 3],
            obfuscation_key: None,
            tls_obfuscation_key: None,
            meek_obfuscated_key: None,
            region: None,
            provider_id: None,
            fronting_provider_id: None,
            tag: String::new(),
            web_server_secret: String::new(),
            configuration_version: 0,
            scan_cdn: true,
            ssh_api: true,
            direct: true,
            tls: false,
            tls_port: None,
            ss: false,
            shadowsocks: None,
            meek: None,
            unfronted_meek: None,
            inproxy_meek: None,
            tactics: None,
            inproxy: None,
            tls_inproxy: None,
            inproxy_shadowsocks_key: None,
            channel_window: 2 * 1024 * 1024,
            packet_tunnel_channel_window: crate::psiphon_ssh::packet_tunnel_channel_window(None),
        }
    }

    fn new_cache(settings: Settings) -> Arc<Cache> {
        Arc::new(Cache::new(settings))
    }

    #[test]
    fn a_stored_lease_replays_its_server_and_seed() {
        let cache = new_cache(Settings::default());
        let entry = server("example.test", 443);
        let first = cache.begin(&entry, 7);
        first.succeeded(1);
        cache.mark_succeeded("example.test");
        let replay = cache.begin(&entry, 7);
        assert!(replay.is_replay());
        assert_eq!(replay.server().host, entry.host);
        assert_eq!(replay.seed(), first.seed());
    }

    #[test]
    fn a_changed_server_entry_does_not_replay() {
        let cache = new_cache(Settings::default());
        let entry = server("example.test", 443);
        cache.begin(&entry, 7).succeeded(1);
        cache.mark_succeeded("example.test");
        let changed = server("example.test", 8443);
        assert!(!cache.begin(&changed, 7).is_replay());
    }

    #[test]
    fn a_changed_config_state_is_ignored_only_by_its_coin() {
        let cache = new_cache(Settings::default());
        let entry = server("example.test", 443);
        cache.begin(&entry, 7).succeeded(1);
        cache.mark_succeeded("example.test");
        assert!(!cache.begin(&entry, 8).is_replay());

        let cache = new_cache(Settings {
            ignore_changed_config_state: 1.0,
            ..Settings::default()
        });
        cache.begin(&entry, 7).succeeded(1);
        cache.mark_succeeded("example.test");
        assert!(cache.begin(&entry, 8).is_replay());
    }

    #[test]
    fn the_candidate_count_bounds_replay() {
        let cache = new_cache(Settings {
            candidate_count: 1,
            ..Settings::default()
        });
        let entry = server("example.test", 443);
        cache.begin(&entry, 7).succeeded(1);
        cache.mark_succeeded("example.test");
        assert!(!cache.begin(&entry, 7).is_replay());
    }

    #[test]
    fn a_failed_replay_is_dropped_when_the_retain_coin_fails() {
        let cache = new_cache(Settings {
            retain_failed: 0.0,
            ..Settings::default()
        });
        let entry = server("example.test", 443);
        cache.begin(&entry, 7).succeeded(1);
        cache.mark_succeeded("example.test");
        let replay = cache.begin(&entry, 7);
        assert!(replay.is_replay());
        replay.failed();
        assert!(!cache.begin(&entry, 7).is_replay());
    }

    #[test]
    fn a_replay_lease_that_no_longer_matches_is_a_new_dial() {
        let cache = new_cache(Settings::default());
        let entry = server("example.test", 443);
        cache.begin(&entry, 7).succeeded(1);
        cache.mark_succeeded("example.test");
        let replay = cache.begin(&entry, 7);
        assert!(replay.is_replay());
        {
            let mut state = lock(&cache.state);
            state.entries.get_mut("example.test").expect("entry").seed = [9; 32];
        }
        replay.succeeded(2);
        assert!(!cache.begin(&entry, 7).is_replay());
    }

    #[test]
    fn a_failed_replay_leaves_a_newer_entry() {
        let cache = new_cache(Settings {
            retain_failed: 0.0,
            ..Settings::default()
        });
        let entry = server("example.test", 443);
        cache.begin(&entry, 7).succeeded(1);
        cache.mark_succeeded("example.test");
        let failed = cache.begin(&entry, 7);
        assert!(failed.is_replay());
        {
            let mut state = lock(&cache.state);
            state.entries.get_mut("example.test").expect("entry").seed = [9; 32];
        }
        failed.failed();
        assert!(cache.begin(&entry, 7).is_replay());
    }

    #[test]
    fn move_to_front_skips_entries_that_cannot_replay() {
        let cache = new_cache(Settings::default());
        let ready = server("ready.test", 443);
        cache.begin(&ready, 7).succeeded(1);
        cache.mark_succeeded("ready.test");
        let pending = server("pending.test", 443);
        cache.begin(&pending, 7).succeeded(1);
        let mut entries = vec![pending.clone(), server("unseen.test", 443), ready.clone()];
        cache.move_to_front(&mut entries);
        assert_eq!(entries[0].host, "ready.test");
        assert_eq!(entries[1].host, "pending.test");
        assert_eq!(entries[2].host, "unseen.test");
    }

    #[test]
    fn move_to_front_skips_a_changed_server_variant() {
        let cache = new_cache(Settings::default());
        let ready = server("ready.test", 443);
        cache.begin(&ready, 7).succeeded(1);
        cache.mark_succeeded("ready.test");
        let changed = server("ready.test", 8443);
        let mut entries = vec![changed.clone(), ready.clone()];
        cache.move_to_front(&mut entries);
        assert_eq!(entries[0].port, 443);
        assert_eq!(entries[1].port, 8443);
    }

    #[test]
    fn a_new_pass_gets_first_round_move_to_front() {
        let cache = new_cache(Settings::default());
        assert!(cache.wants_move_to_front());
        cache.next_round();
        assert!(!cache.wants_move_to_front());
        cache.start_pass();
        assert!(cache.wants_move_to_front());
    }

    #[test]
    fn the_dial_stream_matches_chacha20_blocks() {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let seed = [3u8; 32];
        let mut expected = [0u8; 192];
        let mut cipher = chacha20::ChaCha20::new_from_slices(&seed, &[0u8; 12])
            .expect("fixed ChaCha20 key and nonce lengths");
        cipher.apply_keystream(&mut expected);
        let _scope = dial_seed_scope(seed);
        assert_eq!(dial_random::<192>(), expected);
    }

    #[test]
    fn the_dial_seed_repeats_the_same_shape_draws() {
        let seed = [9u8; 32];
        let first = {
            let _scope = dial_seed_scope(seed);
            dial_random::<32>()
        };
        let second = {
            let _scope = dial_seed_scope(seed);
            dial_random::<32>()
        };
        assert_eq!(first, second);
        let other = {
            let _scope = dial_seed_scope([10u8; 32]);
            dial_random::<32>()
        };
        assert_ne!(first, other);
    }
}
