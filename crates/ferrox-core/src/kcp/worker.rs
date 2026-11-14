use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::config::Config;
use super::connection::{Ctx, State};
use super::segment::{AckSegment, DataSegment, SegmentOption};
use super::window::{AckList, ReceivingWindow, SendingWindow};

pub struct SendingWorker {
    ctx: Arc<Ctx>,
    window: SendingWindow,
    first_unacknowledged: u32,
    next_number: u32,
    remote_next_number: u32,
    control_window: u32,
    in_flight_size: u32,
    window_size: u32,
    first_unacknowledged_updated: bool,
    closed: bool,
}

impl std::fmt::Debug for SendingWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendingWorker").finish_non_exhaustive()
    }
}

impl SendingWorker {
    pub(crate) fn new(config: &Config, ctx: Arc<Ctx>) -> Self {
        Self {
            ctx,
            window: SendingWindow::new(),
            first_unacknowledged: 0,
            next_number: 0,
            remote_next_number: 32,
            control_window: config.sending_in_flight_size(),
            in_flight_size: config.sending_in_flight_size(),
            window_size: config.sending_buffer_size(),
            first_unacknowledged_updated: false,
            closed: false,
        }
    }

    #[must_use]
    pub fn update_necessary(&self) -> bool {
        !self.window.is_empty()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    #[must_use]
    pub fn first_unacknowledged(&self) -> u32 {
        self.first_unacknowledged
    }

    pub fn process_receiving_next(&mut self, next_number: u32) {
        self.window.clear(next_number);
        self.find_first_unacknowledged();
    }

    fn find_first_unacknowledged(&mut self) {
        let first = self.first_unacknowledged;
        self.first_unacknowledged = if self.window.is_empty() {
            self.next_number
        } else {
            self.window.first_number()
        };
        if first != self.first_unacknowledged {
            self.first_unacknowledged_updated = true;
        }
    }

    fn process_ack(&mut self, number: u32) -> bool {
        if number.wrapping_sub(self.first_unacknowledged) > 0x7FFF_FFFF
            || number.wrapping_sub(self.next_number) < 0x7FFF_FFFF
        {
            return false;
        }
        let removed = self.window.remove(number);
        if removed {
            self.find_first_unacknowledged();
        }
        removed
    }

    pub fn process_segment(&mut self, current: u32, seg: &AckSegment, rto: u32) {
        if self.closed {
            return;
        }
        if self.remote_next_number < seg.receiving_window {
            self.remote_next_number = seg.receiving_window;
        }
        self.window.clear(seg.receiving_next);
        self.find_first_unacknowledged();
        if seg.numbers.is_empty() {
            return;
        }
        let mut maxack = 0u32;
        let mut maxack_removed = false;
        for &number in &seg.numbers {
            let removed = self.process_ack(number);
            if maxack < number {
                maxack = number;
                maxack_removed = removed;
            }
        }
        if maxack_removed {
            self.window.handle_fast_ack(maxack, rto);
            if current.wrapping_sub(seg.timestamp) < 10000 {
                self.ctx
                    .round_trip
                    .lock()
                    .unwrap()
                    .update(current.wrapping_sub(seg.timestamp), current);
            }
        }
    }

    pub fn push(&mut self, payload: &[u8]) -> bool {
        if self.closed {
            return false;
        }
        if self.window.len() > self.window_size {
            return false;
        }
        self.window.push(self.next_number, payload);
        self.next_number += 1;
        true
    }

    pub fn on_packet_loss(&mut self, loss_rate: u32) {
        if self.ctx.round_trip.lock().unwrap().timeout() == 0 {
            return;
        }
        if loss_rate >= 15 {
            self.control_window = 3 * self.control_window / 4;
        }
        if loss_rate <= 5 {
            self.control_window += self.control_window / 4;
        }
        if self.control_window < 16 {
            self.control_window = 16;
        }
        if self.control_window > self.in_flight_size {
            self.control_window = self.in_flight_size;
        }
    }

    pub fn flush(&mut self, current: u32) -> bool {
        if self.closed {
            return false;
        }
        let mut cwnd = self.in_flight_size;
        let rest = self
            .remote_next_number
            .wrapping_sub(self.first_unacknowledged);
        if cwnd > rest {
            cwnd = rest;
        }
        if cwnd > self.control_window {
            cwnd = self.control_window;
        }
        cwnd *= self.ctx.config.cwnd_multiplier;
        if !self.window.is_empty() {
            let rto = self.ctx.round_trip.lock().unwrap().timeout();
            let first_unack = self.first_unacknowledged;
            let ctx = Arc::clone(&self.ctx);
            // The three wire-header fields that are not the segment's own are identical for every segment in this flush, so they are computed once.
            let conv = ctx.meta.conversation;
            let option = if ctx.state.load(Ordering::SeqCst) == State::ReadyToClose as i32 {
                SegmentOption::CLOSE
            } else {
                SegmentOption::NONE
            };
            let rate = self.window.flush(
                current,
                rto,
                cwnd,
                conv,
                first_unack,
                option,
                &mut |segment| {
                    let _ = ctx.emit_slice(segment);
                },
            );
            if let Some(rate) = rate {
                self.on_packet_loss(rate);
            }
            self.first_unacknowledged_updated = false;
        }
        let updated = self.first_unacknowledged_updated;
        self.first_unacknowledged_updated = false;
        updated
    }

    pub fn close_write(&mut self) {
        self.window.clear(u32::MAX);
    }

    pub fn release(&mut self) {
        self.window.release();
        self.closed = true;
    }
}

pub struct ReceivingWorker {
    ctx: Arc<Ctx>,
    /// Spent payload buffers, ready to be filled by the next inbound segment.
    spare: Vec<Vec<u8>>,
    left_over: VecDeque<Vec<u8>>,
    left_over_off: usize,
    window: ReceivingWindow,
    acklist: AckList,
    next_number: u32,
    window_size: u32,
    ack_limit: usize,
}

impl std::fmt::Debug for ReceivingWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivingWorker").finish_non_exhaustive()
    }
}

impl ReceivingWorker {
    pub(crate) fn new(config: &Config, ctx: Arc<Ctx>) -> Self {
        let window_size = config.receiving_in_flight_size();
        Self {
            ctx,
            spare: Vec::new(),
            left_over: VecDeque::new(),
            left_over_off: 0,
            window: ReceivingWindow::new(window_size),
            acklist: AckList::for_window(window_size),
            next_number: 0,
            window_size,
            ack_limit: config.ack_limit(),
        }
    }

    #[must_use]
    pub fn update_necessary(&self) -> bool {
        self.acklist.is_pending()
    }

    #[must_use]
    pub fn next_number(&self) -> u32 {
        self.next_number
    }

    #[must_use]
    pub fn is_data_available(&self) -> bool {
        self.window.has(self.next_number)
    }

    pub fn process_sending_next(&mut self, next_number: u32) {
        self.acklist.clear(next_number);
    }

    pub fn process_segment(&mut self, seg: DataSegment) {
        let number = seg.number;
        if number.wrapping_sub(self.next_number) >= self.window_size {
            self.spare.push(seg.payload);
            return;
        }
        self.acklist.clear(seg.sending_next);
        self.acklist.add(number, seg.timestamp);
        if let Some(rejected) = self.window.insert(number, seg) {
            self.spare.push(rejected.payload);
        }
    }

    /// Drains every segment the window holds so `next_number` reaches the end of what arrived before `read` gets the caller's buffer: lazily it lags by whatever one read did not consume, and `process_segment` refuses anything `window_size` ahead, so a lazy pull drops segments an eager drain accepts.
    fn drain_window(&mut self) {
        while let Some(mut seg) = self.window.remove(self.next_number) {
            self.next_number += 1;
            self.left_over.push_back(std::mem::take(&mut seg.payload));
        }
    }

    /// One payload buffer for the socket thread to fill; drained buffers go back to `spare`, so the count settles at the deepest the window ever held.
    pub fn take_payload(&mut self) -> Vec<u8> {
        let mut buf = self.spare.pop().unwrap_or_default();
        buf.clear();
        buf
    }

    #[must_use]
    pub fn spare_buffers(&self) -> usize {
        self.spare.len()
    }

    #[must_use]
    pub fn spare_capacity(&self) -> usize {
        self.spare.iter().map(Vec::capacity).sum()
    }

    pub fn read(&mut self, b: &mut [u8]) -> usize {
        if self.left_over.is_empty() {
            self.drain_window();
            if self.left_over.is_empty() {
                return 0;
            }
        }
        let mut n = 0;
        while n < b.len() && !self.left_over.is_empty() {
            let start = self.left_over_off;
            let head = &self.left_over[0];
            let take = (b.len() - n).min(head.len() - start);
            b[n..n + take].copy_from_slice(&head[start..start + take]);
            n += take;
            self.left_over_off += take;
            if self.left_over_off == self.left_over[0].len() {
                let spent = self.left_over.pop_front().expect("a drained segment");
                self.left_over_off = 0;
                self.spare.push(spent);
            }
        }
        n
    }

    pub fn flush(&mut self, current: u32) {
        let rto = self.ctx.round_trip.lock().unwrap().timeout();
        let limit = self.ack_limit;
        let ctx = Arc::clone(&self.ctx);
        let window_size = self.window_size;
        let next_number = self.next_number;
        self.acklist
            .flush(current, rto, limit, &mut |a: &mut AckSegment| {
                a.conv = ctx.meta.conversation;
                a.receiving_next = next_number;
                a.receiving_window = next_number + window_size;
                a.option = if ctx.state.load(Ordering::SeqCst) == State::ReadyToClose as i32 {
                    SegmentOption::CLOSE
                } else {
                    SegmentOption::NONE
                };
                let _ = ctx.emit_ack(a);
            });
    }

    pub fn close_read(&mut self) {}

    pub fn release(&mut self) {
        self.left_over.clear();
        self.left_over_off = 0;
        self.spare.clear();
        self.window.release();
    }
}
