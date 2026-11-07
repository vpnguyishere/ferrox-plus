//! Token-bucket throttling for the tunnel, the synchronous shape of the
//! reference's `common.ThrottledConn`. A rate of zero disables throttling for
//! that direction, which is the reference default and the unchanged fast path.
//! `CloseAfterExhausted` still closes a direction once its free allowance is used.

use std::time::{Duration, Instant};

/// One direction's bucket: `unthrottled` bytes pass free, then `rate` bytes a
/// second, with a one-second burst.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    rate: u64,
    unthrottled: u64,
    seen: u64,
    tokens: u64,
    last: Instant,
}

impl Bucket {
    /// A full one-second burst bucket.
    fn new(rate: u64, unthrottled: u64) -> Self {
        Self {
            rate,
            unthrottled,
            seen: 0,
            tokens: rate,
            last: Instant::now(),
        }
    }

    /// Account `bytes` and return how long the caller must wait before them.
    fn account(&mut self, bytes: u64) -> Duration {
        let free = self.unthrottled.saturating_sub(self.seen);
        self.seen = self.seen.saturating_add(bytes);
        if self.rate == 0 || free >= bytes {
            return Duration::ZERO;
        }
        let throttled = bytes - free;
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last);
        let refill = elapsed.as_nanos().saturating_mul(u128::from(self.rate)) / 1_000_000_000;
        let refill = u64::try_from(refill).unwrap_or(u64::MAX);
        self.tokens = self.tokens.saturating_add(refill).min(self.rate);
        self.last = now;
        if self.tokens >= throttled {
            self.tokens -= throttled;
            return Duration::ZERO;
        }
        let deficit = throttled.saturating_sub(self.tokens);
        self.tokens = 0;
        let nanos = (u128::from(deficit) * 1_000_000_000) / u128::from(self.rate.max(1));
        let delay = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
        self.last = now + delay;
        delay
    }

    /// Whether the free allowance has been consumed.
    fn exhausted(&self) -> bool {
        self.seen >= self.unthrottled
    }
}

/// The `RateLimits` object the reference accepts.
#[derive(Clone, Debug)]
pub(crate) struct Rate {
    read: Bucket,
    write: Bucket,
    close_after_exhausted: bool,
}

/// The verdict one accounting call returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Account {
    /// Wait this long, then let the bytes through.
    Wait(Duration),
    /// `CloseAfterExhausted` fired; the flow is done.
    Close,
}

impl Rate {
    /// Build the read and write buckets and the exhaustion policy.
    pub(crate) fn new(
        read_rate: u64,
        read_unthrottled: u64,
        write_rate: u64,
        write_unthrottled: u64,
        close_after_exhausted: bool,
    ) -> Self {
        Self {
            read: Bucket::new(read_rate, read_unthrottled),
            write: Bucket::new(write_rate, write_unthrottled),
            close_after_exhausted,
        }
    }

    /// Whether either direction can ever throttle; a false keeps the relay on
    /// its ordinary path with no lock and no clock read.
    pub(crate) fn active(&self) -> bool {
        self.read.rate > 0 || self.write.rate > 0 || self.close_after_exhausted
    }

    /// Account bytes received from the tunnel.
    pub(crate) fn read(&mut self, bytes: usize) -> Account {
        self.account(true, bytes)
    }

    /// Account bytes sent into the tunnel.
    pub(crate) fn write(&mut self, bytes: usize) -> Account {
        self.account(false, bytes)
    }

    /// Account one direction, honouring `CloseAfterExhausted`.
    fn account(&mut self, is_read: bool, bytes: usize) -> Account {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let bucket = if is_read {
            &mut self.read
        } else {
            &mut self.write
        };
        if self.close_after_exhausted && bucket.exhausted() {
            return Account::Close;
        }
        Account::Wait(bucket.account(bytes))
    }
}

/// Apply one verdict: sleep the wait, or report that the flow is done.
pub(crate) fn settle(account: Account) -> bool {
    match account {
        Account::Wait(delay) => {
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            true
        }
        Account::Close => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Zero rates mean no throttling and no extra work.
    fn zero_rates_are_unlimited() {
        let mut rate = Rate::new(0, 0, 0, 0, false);
        assert!(!rate.active());
        assert_eq!(rate.read(1_000_000), Account::Wait(Duration::ZERO));
        assert_eq!(rate.write(1_000_000), Account::Wait(Duration::ZERO));
    }

    #[test]
    /// The free allowance passes before the token bucket applies.
    fn unthrottled_bytes_pass_before_the_bucket() {
        let mut rate = Rate::new(1000, 1000, 0, 0, false);
        assert_eq!(rate.read(1000), Account::Wait(Duration::ZERO));
        let account = rate.read(2000);
        assert!(matches!(account, Account::Wait(delay) if delay >= Duration::from_millis(900)));
    }

    #[test]
    /// Tokens refill as time passes.
    fn the_bucket_refills_over_time() {
        let mut rate = Rate::new(1_000_000, 0, 0, 0, false);
        assert_eq!(rate.read(1_000_000), Account::Wait(Duration::ZERO));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(rate.read(10_000), Account::Wait(Duration::ZERO));
    }

    #[test]
    /// `CloseAfterExhausted` closes a flow once the allowance is gone.
    fn close_after_exhausted_closes_instead_of_throttling() {
        let mut rate = Rate::new(1000, 100, 0, 0, true);
        assert_eq!(rate.read(100), Account::Wait(Duration::ZERO));
        assert_eq!(rate.read(1), Account::Close);
        assert_eq!(rate.write(1), Account::Close);
    }
}
