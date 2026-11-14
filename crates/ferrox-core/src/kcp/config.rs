use super::mask::Mask;
use super::segment::DATA_SEGMENT_OVERHEAD;

/// The sessions one listener admits before it drops a new conversation.
pub const DEFAULT_MAX_SESSIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub cwnd_multiplier: u32,
    pub max_sending_window: u32,
    /// The mkcp legacy mask stacked under the framing, empty for raw KCP.
    pub mask: Mask,
    /// The source-address allow/deny lists applied to received datagrams.
    pub filters: Vec<crate::finalmask::SourceFilter>,
    /// The sessions one listener admits before it drops a new conversation.
    pub max_sessions: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            cwnd_multiplier: 1,
            max_sending_window: 2 * 1024 * 1024,
            mask: Mask::default(),
            filters: Vec::new(),
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

impl Config {
    #[must_use]
    pub fn sending_in_flight_size(&self) -> u32 {
        let size = self.uplink_capacity.wrapping_mul(1024 * 1024)
            / self.mtu.max(1)
            / (1000 / self.tti.max(1)).max(1);
        size.max(8)
    }

    #[must_use]
    pub fn sending_buffer_size(&self) -> u32 {
        self.max_sending_window / self.mtu.max(1)
    }

    #[must_use]
    pub fn receiving_in_flight_size(&self) -> u32 {
        let size = self.downlink_capacity.wrapping_mul(1024 * 1024)
            / self.mtu.max(1)
            / (1000 / self.tti.max(1)).max(1);
        size.max(8)
    }

    #[must_use]
    pub fn payload_size(&self) -> u32 {
        self.mtu.saturating_sub(DATA_SEGMENT_OVERHEAD)
    }

    #[must_use]
    pub fn ack_limit(&self) -> usize {
        (self.mtu.saturating_sub(17) / 4) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upstream_defaults_are_these() {
        let c = Config::default();
        assert_eq!(c.mtu, 1350);
        assert_eq!(c.tti, 50);
        assert_eq!(c.uplink_capacity, 5);
        assert_eq!(c.downlink_capacity, 20);
        assert_eq!(c.cwnd_multiplier, 1);
        assert_eq!(c.max_sending_window, 2 * 1024 * 1024);
        assert_eq!(c.max_sessions, DEFAULT_MAX_SESSIONS);
    }

    #[test]
    fn derived_sizes_match_the_formula() {
        let c = Config::default();
        assert_eq!(c.sending_in_flight_size(), 194);
        assert_eq!(c.sending_buffer_size(), 1553);
        assert_eq!(c.receiving_in_flight_size(), 776);
        assert_eq!(c.payload_size(), 1350 - 18);
        assert_eq!(c.ack_limit(), ((1350 - 17) / 4) as usize);
    }

    #[test]
    fn no_derived_size_panics_and_the_floors_hold() {
        for mtu in [0, 1, 10, 17, 18, 21, 1350, u32::MAX] {
            for tti in [0, 1, 10, 1000, u32::MAX] {
                let c = Config {
                    mtu,
                    tti,
                    ..Config::default()
                };
                assert!(c.sending_in_flight_size() >= 8);
                assert!(c.receiving_in_flight_size() >= 8);
                assert!(c.payload_size() <= mtu);
                let _ = c.ack_limit();
            }
        }
    }

    #[test]
    fn capacities_at_and_above_the_wrapping_point_match_the_reference() {
        let c = Config {
            uplink_capacity: 4096,
            downlink_capacity: 4096,
            ..Config::default()
        };
        assert_eq!(c.sending_in_flight_size(), 8);
        assert_eq!(c.receiving_in_flight_size(), 8);

        let c = Config {
            uplink_capacity: 4097,
            downlink_capacity: 4097,
            ..Config::default()
        };
        assert_eq!(c.sending_in_flight_size(), 38);
        assert_eq!(c.receiving_in_flight_size(), 38);
    }

    #[test]
    fn the_reference_bounds_leave_the_formula_alone() {
        // Miri interprets every pair, so it walks the boundaries where the floor binds; the dense sweep runs natively.
        let mtus: Vec<u32> = if cfg!(miri) {
            vec![
                21, 22, 23, 24, 25, 100, 1349, 1350, 1351, 4096, 6553, 6554, 32768, 32769, 65534,
                65535,
            ]
        } else {
            (21..=u16::MAX as u32).collect()
        };
        for mtu in mtus {
            for tti in 10..=1000 {
                let c = Config {
                    mtu,
                    tti,
                    ..Config::default()
                };
                let reference = c.uplink_capacity * 1024 * 1024 / mtu / (1000 / tti);
                assert_eq!(c.sending_in_flight_size(), reference.max(8));
                assert_eq!(c.payload_size(), mtu - 18);
                assert_eq!(c.ack_limit(), ((mtu - 17) / 4) as usize);
            }
        }
    }
}
