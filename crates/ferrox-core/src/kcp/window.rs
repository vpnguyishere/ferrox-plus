use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

use super::segment::{
    write_data_header, AckSegment, DataSegment, OutgoingHeader, SegmentOption,
    DATA_SEGMENT_OVERHEAD,
};

/// The data-segment header the arena keeps in front of every payload.
const DATA_HEADER: usize = DATA_SEGMENT_OVERHEAD as usize;

/// One segment the sender still owes the wire. The payload is a half-open range
/// into `SendingWindow::arena` rather than an owned buffer: at the default
/// 1 332-byte MSS that was one `malloc` and one `free` per 1 332 bytes sent,
/// which at 100 Mbps is about 9 400 pairs a second per direction.
#[derive(Debug, Clone, Copy)]
struct Outgoing {
    header: OutgoingHeader,
    transmit: u32,
    timeout: u32,
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
pub struct SendingWindow {
    cache: VecDeque<Outgoing>,
    arena: Vec<u8>,
    total_in_flight: u32,
}

impl SendingWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> u32 {
        self.cache.len() as u32
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn push(&mut self, number: u32, payload: &[u8]) {
        // The payload keeps an 18-byte header gap before it, so the segment is contiguous in the arena and can be sent without copying the payload.
        let start = self.arena.len();
        self.arena.resize(start + DATA_HEADER, 0);
        self.arena.extend_from_slice(payload);
        self.cache.push_back(Outgoing {
            header: OutgoingHeader {
                conv: 0,
                option: SegmentOption::default(),
                timestamp: 0,
                number,
                sending_next: 0,
            },
            transmit: 0,
            timeout: 0,
            start,
            end: self.arena.len(),
        });
    }

    /// Drops the arena prefix no cached segment points into, once it is at least
    /// half the arena, so trimming is amortised rather than per segment.
    fn trim(&mut self) {
        // The oldest live range ends the dead prefix, whether or not the cache reached empty between bursts.
        let Some(front) = self.cache.front() else {
            self.arena.clear();
            return;
        };
        let base = front.start;
        if base == 0 || base * 2 < self.arena.len() {
            return;
        }
        self.arena.drain(..base);
        for seg in &mut self.cache {
            seg.start -= base;
            seg.end -= base;
        }
    }

    #[must_use]
    pub fn arena_capacity(&self) -> usize {
        self.arena.capacity()
    }

    #[must_use]
    pub fn first_number(&self) -> u32 {
        self.cache.front().map_or(0, |s| s.header.number)
    }

    pub fn clear(&mut self, una: u32) {
        while let Some(seg) = self.cache.front() {
            if seg.header.number >= una {
                break;
            }
            if seg.transmit > 0 {
                self.total_in_flight = self.total_in_flight.saturating_sub(1);
            }
            self.cache.pop_front();
        }
        self.trim();
    }

    pub fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        let third = rto / 3;
        for seg in &mut self.cache {
            if seg.header.number == number || number.wrapping_sub(seg.header.number) > 0x7FFF_FFFF {
                return;
            }
            if seg.transmit > 0 && seg.timeout > third {
                seg.timeout -= third;
            }
        }
    }

    pub fn remove(&mut self, number: u32) -> bool {
        let Some(index) = self.cache.iter().position(|s| s.header.number >= number) else {
            return false;
        };
        if self.cache[index].header.number != number {
            return false;
        }
        if self.cache[index].transmit > 0 {
            self.total_in_flight = self.total_in_flight.saturating_sub(1);
        }
        self.cache.remove(index);
        self.trim();
        true
    }

    pub fn release(&mut self) {
        self.cache.clear();
        self.arena.clear();
        self.total_in_flight = 0;
    }

    // The clock, the window bound, the four header fields the wire needs, and the writer — every one is read per segment and none is derivable there.
    #[allow(
        clippy::too_many_arguments,
        reason = "one header build per segment, not an API surface"
    )]
    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        max_in_flight: u32,
        conv: u16,
        sending_next: u32,
        option: SegmentOption,
        write: &mut dyn FnMut(&[u8]),
    ) -> Option<u32> {
        let mut lost = 0u32;
        let mut in_flight = 0u32;
        // `self.cache` and `self.arena` are disjoint fields, so a segment's header is written into the arena and the whole range handed out while the entry it came from is still borrowed from the cache.
        for seg in &mut self.cache {
            if current.wrapping_sub(seg.timeout) >= 0x7FFF_FFFF {
                continue;
            }
            if seg.transmit == 0 {
                self.total_in_flight += 1;
            } else {
                lost += 1;
            }
            seg.timeout = current + rto;
            seg.transmit += 1;
            let start = seg.start;
            let end = seg.end;
            // Drop the fresh header into the gap, then hand the writer the whole arena range: the payload goes to the socket without a second copy.
            write_data_header(
                OutgoingHeader {
                    conv,
                    option,
                    timestamp: current,
                    number: seg.header.number,
                    sending_next,
                },
                (end - start - DATA_HEADER) as u16,
                &mut self.arena[start..start + DATA_HEADER],
            );
            write(&self.arena[start..end]);
            in_flight += 1;
            if in_flight >= max_in_flight {
                break;
            }
        }
        if in_flight > 0 && self.total_in_flight != 0 {
            Some(lost * 100 / self.total_in_flight)
        } else {
            None
        }
    }
}

/// A receive window of at most this many segments is a fixed ring; a larger
/// window keeps the map, because its ring would be a multi-megabyte allocation
/// per connection that a sparse window never fills.
const RING_MAX: u32 = 1 << 16;

/// Out-of-order receive slots in a power-of-two ring; the power of two divides
/// `2^32`, so a window that crosses `u32::MAX` still gives every live number a
/// slot of its own. A window larger than `RING_MAX` keeps the map instead.
#[derive(Debug)]
pub struct ReceivingWindow {
    slots: Vec<Option<DataSegment>>,
    mask: u32,
    map: Option<HashMap<u32, DataSegment>>,
}

impl ReceivingWindow {
    #[must_use]
    pub fn new(size: u32) -> Self {
        if size > RING_MAX {
            return Self {
                slots: Vec::new(),
                mask: 0,
                map: Some(HashMap::new()),
            };
        }
        let capacity = size.max(1).next_power_of_two();
        Self {
            slots: Vec::new(),
            mask: capacity - 1,
            map: None,
        }
    }

    fn index(&self, id: u32) -> usize {
        (id & self.mask) as usize
    }

    fn ensure_allocated(&mut self) {
        if self.slots.is_empty() {
            self.slots.resize_with(self.mask as usize + 1, || None);
        }
    }

    pub fn set(&mut self, id: u32, value: DataSegment) -> bool {
        self.insert(id, value).is_none()
    }

    /// Stores `value` unless the slot is taken, in which case the caller gets it
    /// back: the payload is a lent buffer, and a rejected segment would drop it
    /// instead of returning it to the pool.
    pub fn insert(&mut self, id: u32, value: DataSegment) -> Option<DataSegment> {
        if let Some(map) = &mut self.map {
            return match map.entry(id) {
                Entry::Occupied(_) => Some(value),
                Entry::Vacant(slot) => {
                    slot.insert(value);
                    None
                }
            };
        }
        self.ensure_allocated();
        let index = self.index(id);
        let slot = &mut self.slots[index];
        if slot.is_some() {
            return Some(value);
        }
        *slot = Some(value);
        None
    }

    #[must_use]
    pub fn has(&self, id: u32) -> bool {
        if let Some(map) = &self.map {
            return map.contains_key(&id);
        }
        !self.slots.is_empty() && self.slots[self.index(id)].is_some()
    }

    pub fn remove(&mut self, id: u32) -> Option<DataSegment> {
        if let Some(map) = &mut self.map {
            return map.remove(&id);
        }
        if self.slots.is_empty() {
            return None;
        }
        let index = self.index(id);
        self.slots[index].take()
    }

    pub fn release(&mut self) {
        if let Some(map) = &mut self.map {
            *map = HashMap::new();
        } else {
            self.slots = Vec::new();
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AckEntry {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

// Upstream bounds an ack's number list and the deferred-candidate buffer separately, and they are separate limits that happen to share a value.
const FLUSH_CANDIDATES: usize = 128;
const ACK_ENTRY_LIMIT: usize = 1024;
const ACK_DUPLICATE_ALLOWANCE: usize = 128;

#[derive(Debug)]
pub struct AckList {
    entries: Vec<AckEntry>,
    candidates: Vec<u32>,
    /// The ack segment this list is filling. Reused across the whole run of
    /// flushes and across every ack one flush emits, so its `numbers` list
    /// keeps one allocation instead of a fresh `Vec<u32>` per emitted ack.
    scratch: AckSegment,
    dirty: bool,
    limit: usize,
}

impl Default for AckList {
    fn default() -> Self {
        Self::with_limit(ACK_ENTRY_LIMIT)
    }
}

impl AckList {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub(crate) fn for_window(window_size: u32) -> Self {
        Self::with_limit(window_size as usize + ACK_DUPLICATE_ALLOWANCE)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            candidates: Vec::new(),
            scratch: AckSegment::default(),
            dirty: false,
            limit: limit.max(1),
        }
    }

    pub fn add(&mut self, number: u32, timestamp: u32) {
        if self.entries.len() >= self.limit {
            // A full list must still carry a new number inside the window: evict a duplicate of a segment already listed (a retransmission), and let a distinct one grow the list, which the receive window already bounds.
            let evict = self
                .entries
                .iter()
                .position(|entry| entry.number == number)
                .or_else(|| {
                    self.entries
                        .windows(2)
                        .position(|pair| pair[0].number == pair[1].number)
                        .map(|at| at + 1)
                });
            if let Some(at) = evict {
                self.entries.remove(at);
            }
        }
        self.entries.push(AckEntry {
            number,
            timestamp,
            next_flush: 0,
        });
        self.dirty = true;
    }

    pub fn clear(&mut self, una: u32) {
        let mut kept = 0;
        for i in 0..self.entries.len() {
            if self.entries[i].number < una {
                continue;
            }
            if i != kept {
                self.entries[kept] = self.entries[i];
            }
            kept += 1;
        }
        if kept < self.entries.len() {
            self.entries.truncate(kept);
            self.dirty = true;
        }
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        limit: usize,
        write: &mut impl FnMut(&mut AckSegment),
    ) {
        // `entries`, `candidates`, `scratch` and `dirty` are disjoint fields, so the segment can be handed to the writer while its source entries are still borrowed from the same list.
        let AckList {
            entries,
            candidates,
            scratch,
            dirty,
            ..
        } = self;
        scratch.begin(limit);
        let timeout = (rto / 2).max(20);
        candidates.clear();
        for entry in entries {
            if entry.next_flush > current {
                if candidates.len() < FLUSH_CANDIDATES {
                    candidates.push(entry.number);
                }
                continue;
            }
            scratch.put_number(entry.number);
            scratch.put_timestamp(entry.timestamp);
            entry.next_flush = current + timeout;
            if scratch.is_full() {
                write(scratch);
                scratch.begin(limit);
                *dirty = false;
            }
        }
        if *dirty || !scratch.is_empty() {
            for number in &*candidates {
                if scratch.is_full() {
                    break;
                }
                scratch.put_number(*number);
            }
            write(scratch);
            *dirty = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_is_not_due_until_current_reaches_timeout() {
        let mut w = SendingWindow::new();
        w.push(1, b"hello");
        let mut emitted = Vec::new();
        w.flush(0, 100, 16, 0, 0, SegmentOption::NONE, &mut |s| {
            emitted.push(s.to_vec());
        });
        assert_eq!(emitted.len(), 1);
        emitted.clear();
        w.flush(50, 100, 16, 0, 0, SegmentOption::NONE, &mut |s| {
            emitted.push(s.to_vec());
        });
        assert_eq!(emitted.len(), 0);
        w.flush(100, 100, 16, 0, 0, SegmentOption::NONE, &mut |s| {
            emitted.push(s.to_vec());
        });
        assert_eq!(emitted.len(), 1);
    }

    fn seg_number(segment: &[u8]) -> u32 {
        u32::from_be_bytes(segment[8..12].try_into().unwrap())
    }

    fn seg_payload(segment: &[u8]) -> &[u8] {
        &segment[DATA_HEADER..]
    }

    #[test]
    fn fast_ack_cuts_the_timeout_of_earlier_segments() {
        let mut w = SendingWindow::new();
        w.push(1, b"a");
        w.push(2, b"b");
        let before = {
            let mut out = Vec::new();
            w.flush(0, 300, 16, 0, 0, SegmentOption::NONE, &mut |segment| {
                out.push(seg_number(segment));
            });
            w.cache.front().unwrap().timeout
        };
        w.handle_fast_ack(2, 300);
        assert_eq!(w.cache.front().unwrap().timeout, before - 100);
    }
    /// The claim this window makes: one buffer serves every segment, so a send
    /// costs no allocation per segment. Capacity is the witness — a per-segment
    /// `Vec` would need a fresh allocation every 1 332 bytes, and this never
    /// exceeds the high-water mark of its first few rounds.
    #[test]
    fn the_arena_serves_every_segment_without_growing() {
        let mut w = SendingWindow::new();
        let mut high = 0usize;
        for round in 0..64u32 {
            let base = round * 8;
            for n in base..base + 8 {
                w.push(n, &[n as u8; 1332]);
            }
            high = high.max(w.arena_capacity());
            assert_eq!(w.len(), 8, "round {round}");
            w.flush(100 + round, 200, 64, 0, 0, SegmentOption::NONE, &mut |_| {});
            w.clear(base + 8);
        }
        assert!(
            high <= 8 * 1332 * 3,
            "the arena reached {high} bytes for 8 live segments of 1332"
        );
        assert_eq!(w.len(), 0, "every round acknowledged its eight");
        // one buffer, reused: not one per segment, and not one that grows forever
        assert!(high >= 8 * 1332);

        // A live window never drains between reads: the next eight arrive while the last eight are still owed.
        let mut w = SendingWindow::new();
        let mut high = 0usize;
        for round in 0..64u32 {
            let base = round * 8;
            for n in base..base + 8 {
                w.push(n, &[n as u8; 1332]);
            }
            high = high.max(w.arena_capacity());
            w.flush(100 + round, 200, 64, 0, 0, SegmentOption::NONE, &mut |_| {});
            if round > 0 {
                w.clear(base);
            }
        }
        assert_eq!(w.len(), 8, "the live tail is the last round's eight");
        assert!(
            high <= 8 * 1332 * 3,
            "the live window's arena reached {high} bytes for 8 live segments of 1332"
        );
    }

    /// Trimming shifts every live range down by the trimmed prefix. If that
    /// arithmetic is wrong, a segment goes out carrying another segment's bytes,
    /// so every emitted payload must still be its own — at every offset.
    #[test]
    fn trimming_never_moves_a_live_payload() {
        for trim in [0u32, 1, 7, 8, 15, 16, 31] {
            let mut w = SendingWindow::new();
            for n in 0..32u32 {
                w.push(n, &[n as u8; 64]);
            }
            w.clear(trim);
            let mut live = Vec::new();
            w.flush(100, 200, 64, 0, 0, SegmentOption::NONE, &mut |segment| {
                live.push((seg_number(segment), seg_payload(segment).to_vec()));
            });
            assert_eq!(live.len(), (32 - trim) as usize, "trim {trim}");
            for (number, payload) in &live {
                assert_eq!(payload.len(), 64, "trim {trim}: segment {number}");
                assert!(
                    payload.iter().all(|&b| b == *number as u8),
                    "trim {trim}: segment {number} carries {:?}",
                    &payload[..8]
                );
            }
            if let Some((first, _)) = live.first() {
                assert_eq!(*first, trim, "trim {trim}: wrong first segment");
            }
        }
    }

    /// The wrapped case: numbers near `u32::MAX` must not collide in the arena.
    #[test]
    fn the_arena_does_not_confuse_wrapped_segment_numbers() {
        let mut w = SendingWindow::new();
        w.push(u32::MAX, &[0xAA; 16]);
        w.push(0, &[0xBB; 16]);
        w.clear(u32::MAX);
        let mut live = Vec::new();
        w.flush(10, 20, 8, 0, 0, SegmentOption::NONE, &mut |segment| {
            live.push((seg_number(segment), seg_payload(segment)[0]));
        });
        assert_eq!(live, vec![(u32::MAX, 0xAA), (0, 0xBB)]);
    }

    /// The emit path's copy claim, proved by pointer identity rather than by
    /// bytes: a byte test passes whether or not the payload was staged, because
    /// the staged bytes are identical. So the writer must see a slice whose base
    /// *is* the arena plus the segment's start, with the payload contiguous
    /// behind the header — no arena → staging → socket second copy.
    #[test]
    fn the_writer_gets_the_arena_range_and_not_a_copy_of_it() {
        let mut w = SendingWindow::new();
        w.push(7, &[0xA5u8; 900]);
        w.push(8, &[0x5A; 40]);
        // No push happens between here and the flush, so the base captured now is the allocation the writer's slices must live inside.
        let arena = w.arena.as_ptr();
        let mut seen = Vec::new();
        w.flush(100, 200, 16, 0x0102, 9, SegmentOption::NONE, &mut |s| {
            seen.push((s.as_ptr() as usize, s.as_ptr() as usize + s.len(), s.len()));
        });
        assert_eq!(seen.len(), 2);
        let live: Vec<(usize, usize)> = w.cache.iter().map(|seg| (seg.start, seg.end)).collect();
        for (slot, (start, end)) in seen.iter().zip(&live) {
            assert_eq!(
                slot.0,
                arena as usize + start,
                "the writer was handed a copy, not the arena range"
            );
            assert_eq!(slot.1, arena as usize + end, "the slice is not the range");
            assert!(
                slot.0 + slot.2 - DATA_HEADER >= arena as usize + start + DATA_HEADER,
                "the payload half must sit behind the header gap, inside the arena"
            );
        }
        // The gap is filled before the range goes out, or a zero-padded header would reach the wire at the arena's own address and pass a bytes test.
        assert_eq!(&w.arena[live[0].0..live[0].0 + 2], &[0x01, 0x02]);
        assert_eq!(w.cache.len(), 2);
    }

    #[test]
    fn release_empties_the_window_where_clear_at_the_wrap_would_not() {
        let mut w = SendingWindow::new();
        w.push(u32::MAX, b"last");
        w.push(0, b"first");
        w.clear(u32::MAX);
        assert_eq!(w.len(), 2);

        let mut w = SendingWindow::new();
        w.push(u32::MAX, b"last");
        w.push(0, b"first");
        w.release();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn clear_forgets_the_in_flight_count_of_acknowledged_segments() {
        let mut w = SendingWindow::new();
        w.push(1, b"one");
        w.push(2, b"two");
        w.flush(0, 100, 1, 0, 0, SegmentOption::NONE, &mut |_| {});
        assert_eq!(w.total_in_flight, 1);
        w.clear(2);
        assert_eq!(w.len(), 1);
        assert_eq!(
            w.total_in_flight, 0,
            "an acknowledged segment stayed in flight"
        );
    }

    #[test]
    fn removing_an_untransmitted_segment_keeps_the_in_flight_count() {
        let mut w = SendingWindow::new();
        w.push(1, b"one");
        w.push(2, b"two");
        w.flush(0, 100, 1, 0, 0, SegmentOption::NONE, &mut |_| {});
        assert_eq!(w.total_in_flight, 1);
        assert!(w.remove(2));
        assert_eq!(
            w.total_in_flight, 1,
            "an unsent segment left the in-flight count"
        );
    }

    #[test]
    fn removing_beyond_the_window_is_not_a_removal() {
        let mut w = SendingWindow::new();
        w.push(4, b"a");
        w.push(5, b"b");
        assert!(!w.remove(3));
        assert!(!w.remove(6));
        assert!(w.remove(5));
        assert!(!w.remove(5));
        assert!(w.remove(4));
        assert!(w.is_empty());
    }

    #[test]
    fn ack_list_clear_drops_the_acknowledged_prefix() {
        let mut l = AckList::new();
        l.add(5, 10);
        l.add(7, 20);
        l.clear(7);
        assert_eq!(
            l.entries.iter().map(|e| e.number).collect::<Vec<_>>(),
            vec![7]
        );
        assert_eq!(l.entries[0].timestamp, 20);
    }

    #[test]
    fn a_duplicate_segment_is_acknowledged_again_like_the_reference() {
        use std::fmt::Write as _;

        let mut l = AckList::new();
        l.add(7, 100);
        l.add(7, 200);
        assert_eq!(
            l.entries.len(),
            2,
            "the reference appends a repeated segment"
        );
        assert_eq!(l.entries[0].timestamp, 100);
        assert_eq!(l.entries[1].timestamp, 200);
        let mut numbers = Vec::new();
        let mut wire = Vec::new();
        l.flush(0, 100, 300, &mut |seg: &mut AckSegment| {
            numbers.push(seg.numbers.clone());
            seg.serialize(&mut wire);
        });
        assert_eq!(numbers, vec![vec![7, 7]]);
        let mut wire_hex = String::new();
        for byte in &wire {
            write!(wire_hex, "{byte:02x}").unwrap();
        }
        assert_eq!(
            wire_hex,
            "000000000000000000000000000000c8020000000700000007"
        );
    }

    #[test]
    fn a_duplicate_flood_evicts_a_duplicate_before_a_new_number() {
        let mut l = AckList::for_window(1);
        for timestamp in 0..=ACK_DUPLICATE_ALLOWANCE as u32 + 1 {
            l.add(7, timestamp);
        }
        assert_eq!(l.entries.len(), 1 + ACK_DUPLICATE_ALLOWANCE);
        assert_eq!(
            l.entries.last().unwrap().timestamp,
            ACK_DUPLICATE_ALLOWANCE as u32 + 1
        );
        // A full list of duplicates must still take a new number inside the window; refusing it left that segment unacked.
        l.add(8, 500);
        let mut acked = Vec::new();
        l.flush(0, 100, 1024, &mut |seg: &mut AckSegment| {
            acked.extend_from_slice(&seg.numbers);
        });
        assert!(acked.contains(&8), "the new number was dropped");
    }

    #[test]
    fn the_ack_list_reuses_its_scratch_across_flushes() {
        let mut l = AckList::new();
        l.add(1, 100);
        l.add(2, 110);
        l.flush(0, 100, 300, &mut |_: &mut AckSegment| {});
        for current in 1..50u32 {
            l.flush(current, 100, 300, &mut |_: &mut AckSegment| {});
            assert_eq!(l.candidates, vec![1, 2]);
        }
        l.flush(50, 100, 300, &mut |_: &mut AckSegment| {});
        let scratch = l.candidates.as_ptr();
        for current in 51..100u32 {
            l.flush(current, 100, 300, &mut |_: &mut AckSegment| {});
            assert_eq!(l.candidates, vec![1, 2]);
        }
        assert_eq!(l.candidates.as_ptr(), scratch);
        assert_eq!(l.entries.len(), 2);

        // The ack segment's own number list is reused too: once a flush has filled it past one segment, flushing again must not hand back a freshly allocated `Vec`. A byte test on the emitted ack cannot see this — the numbers are identical either way — so the witness is the allocation's identity: same base pointer, same capacity.
        let mut heavy = AckList::new();
        for n in 0..200u32 {
            heavy.add(n, n);
        }
        let mut emitted = 0usize;
        heavy.flush(0, 100, 128, &mut |a: &mut AckSegment| {
            assert!(!a.numbers.is_empty(), "a full ack carries numbers");
            emitted += 1;
        });
        assert!(emitted >= 2, "200 numbers over a limit of 128 is two acks");
        let numbers_ptr = heavy.scratch.numbers.as_ptr();
        let numbers_cap = heavy.scratch.numbers.capacity();
        assert!(!numbers_ptr.is_null(), "the scratch allocated its list");
        for current in 1..10u32 {
            heavy.flush(current, 100, 128, &mut |_: &mut AckSegment| {});
        }
        assert_eq!(
            heavy.scratch.numbers.as_ptr(),
            numbers_ptr,
            "a flush reallocated the ack segment's number list"
        );
        assert_eq!(heavy.scratch.numbers.capacity(), numbers_cap);
    }

    #[test]
    fn ack_list_flush_emits_every_known_number_on_the_first_round() {
        let mut l = AckList::new();
        l.add(1, 100);
        l.add(2, 110);
        let mut emitted = Vec::new();
        l.flush(0, 100, 300, &mut |seg: &mut AckSegment| {
            emitted.push(seg.clone());
        });
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].numbers, vec![1, 2]);
        assert_eq!(emitted[0].timestamp, 110);
    }

    fn receive_segment(number: u32) -> DataSegment {
        DataSegment {
            conv: 0,
            option: SegmentOption::NONE,
            timestamp: 0,
            number,
            sending_next: 0,
            payload: Vec::new(),
            timeout: 0,
            transmit: 0,
        }
    }

    /// A receive window within the ring bound is a fixed ring, not a growable
    /// map: one allocation on the first segment, then the same base and
    /// capacity through a full window and the next lap. A map would grow its
    /// bucket array, and a per-segment buffer would move the base, so identity
    /// is the witness.
    #[test]
    fn the_receive_window_indexes_a_fixed_ring() {
        let mut w = ReceivingWindow::new(8);
        assert!(w.slots.is_empty(), "the ring is allocated on first use");
        assert!(w.set(0, receive_segment(0)));
        let base = w.slots.as_ptr();
        let capacity = w.slots.capacity();
        assert_eq!(w.slots.len(), 8);
        for number in 1..8 {
            assert!(w.set(number, receive_segment(number)));
        }
        assert_eq!(w.slots.as_ptr(), base, "a full window moved the ring");
        assert_eq!(w.slots.capacity(), capacity);
        assert!(!w.set(3, receive_segment(3)), "a duplicate must be refused");
        for number in 0..8 {
            assert!(w.has(number));
            assert_eq!(w.remove(number).map(|seg| seg.number), Some(number));
        }
        for number in 8..16 {
            assert!(w.set(number, receive_segment(number)));
        }
        assert_eq!(
            w.slots.as_ptr(),
            base,
            "the second lap reallocated the ring"
        );
        assert_eq!(w.slots.capacity(), capacity);
    }

    /// Three does not divide `2^32`; a modulo index aliased `u32::MAX` and `0`
    /// into one slot. The power-of-two ring must keep all three numbers apart.
    #[test]
    fn the_ring_keeps_wrapped_numbers_in_their_slot() {
        let mut w = ReceivingWindow::new(3);
        let start = u32::MAX - 1;
        for offset in 0..3 {
            let number = start.wrapping_add(offset);
            assert!(w.set(number, receive_segment(number)));
        }
        assert!(!w.set(start, receive_segment(start)));
        for offset in 0..3 {
            let number = start.wrapping_add(offset);
            assert!(w.has(number));
            assert_eq!(w.remove(number).map(|seg| seg.number), Some(number));
        }
        assert!(w.slots.iter().all(Option::is_none));
    }

    /// A window above the ring bound must not preallocate its slots: it keeps
    /// the map, and the map still refuses a duplicate and returns its segment.
    #[test]
    fn a_window_above_the_ring_keeps_the_map() {
        let mut w = ReceivingWindow::new(RING_MAX + 1);
        assert!(w.map.is_some(), "a large window must keep the map");
        assert!(
            w.slots.is_empty(),
            "the map path must not allocate the ring"
        );
        assert!(w.set(0, receive_segment(0)));
        assert!(w.has(0));
        assert!(!w.set(0, receive_segment(0)));
        assert_eq!(w.remove(0).map(|seg| seg.number), Some(0));
        assert!(!w.has(0));

        let w = ReceivingWindow::new(u32::MAX);
        assert!(w.map.is_some(), "the largest window must not round up");
        assert!(
            w.slots.is_empty(),
            "the largest window must not allocate the ring"
        );
    }

    /// The ring's set/remove path is the hot receive path: after the one-time
    /// slot allocation it must not allocate at all, which is what keeps a
    /// datagram's segment from paying a bucket insert and a probe.
    #[test]
    fn the_receive_window_does_not_allocate_per_segment() {
        let mut w = ReceivingWindow::new(8);
        w.set(0, receive_segment(0));
        w.remove(0);
        let ((), counts) = crate::alloc_count::measure(|| {
            for number in 0..64 {
                assert!(w.set(number, receive_segment(number)));
                assert!(w.remove(number).is_some());
            }
        });
        assert_eq!(counts.allocs, 0, "a segment allocated in the ring");
    }
}
