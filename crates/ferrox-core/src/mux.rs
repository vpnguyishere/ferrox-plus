use std::fmt;

use crate::addr::{self, Addr};

pub const DATA: u8 = 0x01;
pub const ERROR: u8 = 0x02;

pub const FIXED: usize = 4;

pub const GLOBAL_ID: usize = 8;

pub const META_MAX: usize = FIXED + 3 * (1 + 2 + 1 + addr::MAX_DOMAIN);

pub const CHUNK_MAX: usize = 8192;

pub const ID_SPACE: usize = 1 << 16;

pub const DEFAULT_CAP: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    New,
    Keep,
    End,
    KeepAlive,
}

impl Status {
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::New),
            0x02 => Some(Self::Keep),
            0x03 => Some(Self::End),
            0x04 => Some(Self::KeepAlive),
            _ => None,
        }
    }

    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::New => 0x01,
            Self::Keep => 0x02,
            Self::End => 0x03,
            Self::KeepAlive => 0x04,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            _ => None,
        }
    }

    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x02,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
    pub network: Network,
    pub port: u16,
    pub addr: Addr<'a>,
}

impl<'a> Target<'a> {
    #[must_use]
    pub fn of(network: Network, host: &'a str, port: u16) -> Self {
        Self {
            network,
            port,
            addr: Addr::of(host),
        }
    }

    #[must_use]
    pub const fn wire_len(self) -> usize {
        1 + 2 + self.addr.wire_len()
    }

    #[inline]
    pub fn encode_into(&self, out: &mut [u8]) -> usize {
        assert!(out.len() >= self.wire_len(), "mux target buffer too short");
        let mut o = 0;
        out[o] = self.network.byte();
        o += 1;
        out[o..o + 2].copy_from_slice(&self.port.to_be_bytes());
        o += 2;
        o + self.addr.encode_into(&mut out[o..])
    }

    #[inline]
    pub fn take(buf: &'a [u8]) -> Result<(Self, usize), Error> {
        let Some((&network, rest)) = buf.split_first() else {
            return Err(Error::Truncated);
        };
        let Some(network) = Network::from_byte(network) else {
            return Err(Error::Network(network));
        };
        let Some((&[hi, lo], after)) = rest.split_first_chunk::<2>() else {
            return Err(Error::Truncated);
        };
        let (addr, used) = Addr::take(after).map_err(|e| match e {
            addr::FamilyError::Unknown(byte) => Error::Family(byte),
            addr::FamilyError::Short => Error::Truncated,
        })?;
        Ok((
            Self {
                network,
                port: u16::from_be_bytes([hi, lo]),
                addr,
            },
            1 + 2 + used,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outgoing<'a> {
    pub id: u16,
    pub status: Status,
    pub options: u8,
    pub target: Option<Target<'a>>,
    pub global_id: Option<[u8; GLOBAL_ID]>,
}

impl Outgoing<'_> {
    #[must_use]
    pub const fn bare(id: u16, status: Status, options: u8) -> Self {
        Self {
            id,
            status,
            options,
            target: None,
            global_id: None,
        }
    }

    #[must_use]
    pub const fn has_data(&self) -> bool {
        self.options & DATA != 0
    }

    #[must_use]
    #[inline]
    pub fn meta_len(&self) -> usize {
        let identity = if self.global_id.is_some() {
            GLOBAL_ID
        } else {
            0
        };
        FIXED + self.target.map_or(0, Target::wire_len) + identity
    }

    #[must_use]
    pub fn frame_len(&self, data_len: usize) -> usize {
        let chunk = if self.has_data() { 2 + data_len } else { 0 };
        2 + self.meta_len() + chunk
    }

    #[must_use]
    pub const fn carries_target(&self) -> bool {
        match self.status {
            Status::New => true,
            Status::Keep => self.target.is_some(),
            Status::End | Status::KeepAlive => false,
        }
    }

    #[inline]
    /// The three invariants every encoding of this frame has to satisfy, and the
    /// metadata length they agree on. Split out of `encode_into` so the
    /// header-only path below cannot drift from the full one.
    fn check_meta(&self) -> usize {
        assert!(
            self.carries_target() == self.target.is_some(),
            "the status decides whether a target follows, and this frame disagrees with itself"
        );
        assert!(
            self.status != Status::Keep || self.target.is_none_or(|t| t.network == Network::Udp),
            "only a datagram carries its own destination"
        );
        assert!(
            self.global_id.is_none()
                || (self.status == Status::New
                    && self.target.is_some_and(|t| t.network == Network::Udp)),
            "the NAT identity rides a new UDP frame and nowhere else"
        );
        let meta = self.meta_len();
        assert!(
            meta <= META_MAX,
            "mux metadata longer than the format allows"
        );
        meta
    }

    /// Writes `[meta length][metadata]` and returns the offset the payload
    /// length goes at. `out` must already be at least `2 + meta` long.
    fn write_meta(&self, out: &mut [u8], meta: usize) -> usize {
        let mut o = 2;
        out[o..o + 2].copy_from_slice(&self.id.to_be_bytes());
        o += 2;
        out[o] = self.status.byte();
        o += 1;
        out[o] = self.options;
        o += 1;
        if let Some(target) = self.target {
            o += target.encode_into(&mut out[o..]);
        }
        if let Some(identity) = self.global_id {
            out[o..o + GLOBAL_ID].copy_from_slice(&identity);
            o += GLOBAL_ID;
        }
        debug_assert_eq!(
            o - 2,
            meta,
            "the length came from one function and the writes agree"
        );
        out[..2].copy_from_slice(&(meta as u16).to_be_bytes());
        o
    }

    /// Everything a frame puts on the wire except its payload: the metadata
    /// length, the metadata, and a **zeroed** payload length for the caller to
    /// patch once it knows how many bytes it has.
    ///
    /// This is for a relay that can hand the payload to the socket without
    /// moving it — the payload is not sealed, it is framed — so a `writev` of
    /// header and read buffer is the whole frame and no relay read is copied.
    /// `encode_into` is this plus the copy; the two must not drift, which
    /// `a_header_plus_a_patched_length_is_the_whole_frame` holds.
    #[must_use]
    pub fn encode_header_into(&self, out: &mut Vec<u8>) -> usize {
        let meta = self.check_meta();
        let len = 2 + meta + usize::from(self.has_data()) * 2;
        out.clear();
        out.reserve_exact(len);
        // SAFETY: `write_meta` fills `[0 .. 2 + meta]` in full and the two payload-length bytes are written below, so no grown byte is read uninitialized; the `resize` this replaces zero-filled the metadata region only for `write_meta` to overwrite every byte of it.
        unsafe { out.set_len(len) };
        let at = self.write_meta(out, meta);
        if self.has_data() {
            out[at..at + 2].copy_from_slice(&0u16.to_be_bytes());
        }
        debug_assert_eq!(at, 2 + meta, "the payload length follows the metadata");
        at
    }

    /// Rewrites the payload length `encode_header_into` left at zero.
    pub fn patch_payload_len(&self, out: &mut [u8], at: usize, len: usize) {
        debug_assert!(self.has_data(), "only a frame with a payload has a length");
        out[at..at + 2].copy_from_slice(&(len as u16).to_be_bytes());
    }

    pub fn encode_into(&self, data: Option<&[u8]>, out: &mut [u8]) -> usize {
        assert_eq!(
            self.has_data(),
            data.is_some(),
            "the data option and the payload have to agree"
        );
        let payload = data.unwrap_or(&[]);
        assert!(
            payload.len() <= CHUNK_MAX,
            "mux chunk longer than a length field"
        );
        let meta = self.check_meta();
        let chunk = if self.has_data() {
            2 + payload.len()
        } else {
            0
        };
        assert!(out.len() >= 2 + meta + chunk, "mux frame buffer too short");

        let mut o = self.write_meta(out, meta);

        if self.has_data() {
            out[o..o + 2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            o += 2;
            out[o..o + payload.len()].copy_from_slice(payload);
            o += payload.len();
        }
        o
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewTail {
    Forward,
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reflection<'a> {
    pub source: Target<'a>,
    pub local: Option<Target<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incoming<'a> {
    pub id: u16,
    pub status: Status,
    pub options: u8,
    pub target: Option<Target<'a>>,
    pub global_id: Option<[u8; GLOBAL_ID]>,
    pub reflection: Option<Reflection<'a>>,
    pub data: Option<&'a [u8]>,
}

impl<'a> Incoming<'a> {
    #[must_use]
    pub const fn has_data(&self) -> bool {
        self.options & DATA != 0
    }

    #[must_use]
    pub fn to_outgoing(&self) -> Option<Outgoing<'a>> {
        if self.reflection.is_some() {
            return None;
        }
        Some(Outgoing {
            id: self.id,
            status: self.status,
            options: self.options,
            target: self.target,
            global_id: self.global_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Short { need: usize, have: usize },
    MetaLen(u16),
    Status(u8),
    Network(u8),
    Family(u8),
    Truncated,
}

impl Error {
    const fn short(need: usize, have: usize) -> Self {
        Self::Short { need, have }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short { need, have } => write!(f, "short: {have} of {need} bytes"),
            Self::MetaLen(len) => write!(f, "meta length {len} is outside {FIXED}..={META_MAX}"),
            Self::Status(byte) => write!(f, "status {byte:#04x} is not a frame status"),
            Self::Network(byte) => write!(f, "network {byte:#04x} is not a transport"),
            Self::Family(byte) => write!(f, "address family {byte:#04x} is not one"),
            Self::Truncated => write!(f, "metadata ends inside a field it promised"),
        }
    }
}

impl std::error::Error for Error {}

pub fn decode(buf: &[u8], tail: NewTail) -> Result<(Incoming<'_>, usize), Error> {
    let Some((&head, after)) = buf.split_first_chunk::<2>() else {
        return Err(Error::short(2, buf.len()));
    };
    let declared = u16::from_be_bytes(head);
    if !(FIXED..=META_MAX).contains(&usize::from(declared)) {
        return Err(Error::MetaLen(declared));
    }
    let meta_len = usize::from(declared);
    let Some(meta) = after.get(..meta_len) else {
        return Err(Error::short(2 + meta_len, buf.len()));
    };

    // One bounded load of the fixed head: four indexed reads would each carry their own length check although `meta_len >= FIXED` proved the bytes are here.
    let Some((&fixed, rest)) = meta.split_first_chunk::<FIXED>() else {
        return Err(Error::Truncated);
    };
    let id = u16::from_be_bytes([fixed[0], fixed[1]]);
    let status = Status::from_byte(fixed[2]).ok_or(Error::Status(fixed[2]))?;
    let options = fixed[3];

    let mut at = FIXED;
    let mut target = None;
    // Only `New`, or a `Keep` whose metadata reaches past the fixed head and names UDP, carries a target; `rest` is already cut at that boundary, so the bulk TCP `Keep` sees it empty and pays neither the byte compare nor the option it used to build to ask.
    let carries = match status {
        Status::New => true,
        Status::Keep => matches!(rest.first(), Some(&byte) if byte == Network::Udp.byte()),
        Status::End | Status::KeepAlive => false,
    };
    if carries {
        let (found, used) = Target::take(&meta[at..])?;
        at += used;
        target = Some(found);
    }

    let mut global_id = None;
    let mut reflection = None;
    if status == Status::New {
        match tail {
            NewTail::Reverse => reflection = read_reflection(&meta[at..])?,
            NewTail::Forward => {
                if options & DATA != 0
                    && target.is_some_and(|t| t.network == Network::Udp)
                    && meta.len() - at >= GLOBAL_ID
                {
                    let mut identity = [0u8; GLOBAL_ID];
                    identity.copy_from_slice(&meta[at..at + GLOBAL_ID]);
                    global_id = Some(identity);
                }
            }
        }
    }

    let mut consumed = 2 + meta_len;
    let mut data = None;
    if options & DATA != 0 {
        debug_assert!(
            buf.len() >= consumed,
            "the metadata slice was proven present"
        );
        let (&len, payload) = buf[consumed..]
            .split_first_chunk::<2>()
            .ok_or_else(|| Error::short(consumed + 2, buf.len()))?;
        let len = usize::from(u16::from_be_bytes(len));
        let body = payload
            .get(..len)
            .ok_or_else(|| Error::short(consumed + 2 + len, buf.len()))?;
        consumed += 2 + len;
        data = Some(body);
    }

    Ok((
        Incoming {
            id,
            status,
            options,
            target,
            global_id,
            reflection,
            data,
        },
        consumed,
    ))
}

#[inline]
fn read_reflection(rest: &[u8]) -> Result<Option<Reflection<'_>>, Error> {
    let Some((&network, _)) = rest.split_first() else {
        return Ok(None);
    };
    if network == 0 {
        return Ok(None);
    }
    let (source, used) = Target::take(rest)?;
    let local = match Target::take(&rest[used..]) {
        Ok((found, _)) => Some(found),
        Err(Error::Network(0) | Error::Truncated) => None,
        Err(other) => return Err(other),
    };
    Ok(Some(Reflection { source, local }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    Full,
    Exhausted,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("the session cap is reached"),
            Self::Exhausted => f.write_str("every session id is spent"),
        }
    }
}

impl std::error::Error for IdError {}

#[derive(Debug, Clone)]
pub struct Ids {
    next: u32,
    live: usize,
    cap: usize,
}

impl Ids {
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            next: 1,
            live: 0,
            cap,
        }
    }

    pub fn take(&mut self) -> Result<u16, IdError> {
        if self.cap != 0 && self.live >= self.cap {
            return Err(IdError::Full);
        }
        let id = u16::try_from(self.next).map_err(|_| IdError::Exhausted)?;
        self.next += 1;
        self.live += 1;
        Ok(id)
    }

    pub fn give_back(&mut self) {
        self.live = self.live.saturating_sub(1);
    }

    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    #[must_use]
    pub const fn opened(&self) -> u32 {
        self.next - 1
    }

    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }
}

#[derive(Debug)]
enum Slot<T> {
    Empty,
    Live(u16, T),
    Closed(u16),
}

#[derive(Debug)]
pub struct Sessions<T> {
    slots: Vec<Slot<T>>,
    mask: usize,
    live: usize,
    cap: usize,
}

impl<T> Sessions<T> {
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_CAP)
    }

    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        let cap = cap.max(1);
        let len = cap.saturating_mul(2).max(4).next_power_of_two();
        let slots = (0..len).map(|_| Slot::Empty).collect();
        Self {
            slots,
            mask: len - 1,
            live: 0,
            cap,
        }
    }

    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }

    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.slots.len()
    }

    fn probe(&self, id: u16) -> (Option<usize>, Option<usize>) {
        let mut at = self.mask & usize::from(id);
        let mut free = None;
        for _ in 0..=self.mask {
            match &self.slots[at] {
                Slot::Empty => {
                    if free.is_none() {
                        free = Some(at);
                    }
                    return (None, free);
                }
                Slot::Live(key, _) | Slot::Closed(key) if *key == id => return (Some(at), free),
                Slot::Closed(_) => {
                    if free.is_none() {
                        free = Some(at);
                    }
                }
                Slot::Live(..) => {}
            }
            at = (at + 1) & self.mask;
        }
        (None, free)
    }

    pub fn open(&mut self, id: u16, value: T) -> Option<Option<T>> {
        let (found, free) = self.probe(id);
        if let Some(at) = found {
            if let Slot::Live(_, old) = &mut self.slots[at] {
                return Some(Some(std::mem::replace(old, value)));
            }
            if self.live >= self.cap {
                return None;
            }
            self.slots[at] = Slot::Live(id, value);
            self.live += 1;
            return Some(None);
        }
        if self.live >= self.cap {
            return None;
        }
        let at = free?;
        self.live += 1;
        self.slots[at] = Slot::Live(id, value);
        Some(None)
    }

    #[must_use]
    pub fn get(&self, id: u16) -> Option<&T> {
        let at = self.probe(id).0?;
        match &self.slots[at] {
            Slot::Live(_, value) => Some(value),
            Slot::Empty | Slot::Closed(_) => None,
        }
    }

    pub fn get_mut(&mut self, id: u16) -> Option<&mut T> {
        let at = self.probe(id).0?;
        match &mut self.slots[at] {
            Slot::Live(_, value) => Some(value),
            Slot::Empty | Slot::Closed(_) => None,
        }
    }

    pub fn close(&mut self, id: u16) -> Option<T> {
        let at = self.probe(id).0?;
        match std::mem::replace(&mut self.slots[at], Slot::Closed(id)) {
            Slot::Live(_, value) => {
                self.live -= 1;
                Some(value)
            }
            _ => None,
        }
    }
}

impl<T> Default for Sessions<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: [u8; 2] = [0x00, 0x14];
    const ID: [u8; 2] = [0x00, 0x01];

    const NEW_DOMAIN: [u8; 28] =
        *b"\x00\x14\x00\x01\x01\x01\x01\x00\x50\x02\x0bexample.com\x00\x04abcd";

    /// The relay writes a header it built once and a payload it never copied.
    /// Those two have to be the same bytes as the single-buffer encoder at
    /// every status, option and length — the header-only path is the one on the
    /// wire for every relayed byte, and it shares `write_meta` with the other
    /// so the only thing left to pin is the length field.
    #[test]
    fn a_header_plus_a_patched_length_is_the_whole_frame() {
        let addrs = [
            Target::of(Network::Tcp, "192.0.2.1", 443),
            Target::of(Network::Udp, "example.com", 53),
        ];
        let mut frames: Vec<Outgoing> = Vec::new();
        for status in [Status::New, Status::Keep, Status::End, Status::KeepAlive] {
            for options in [0u8, DATA, DATA | ERROR, ERROR] {
                for target in [None, Some(addrs[0]), Some(addrs[1])] {
                    for global_id in [None, Some([7u8; GLOBAL_ID])] {
                        let f = Outgoing {
                            id: 513,
                            status,
                            options,
                            target,
                            global_id,
                        };
                        // skip the shapes this type already refuses to encode
                        if f.carries_target() != target.is_some()
                            || (status == Status::Keep
                                && target.is_some_and(|t| t.network != Network::Udp))
                            || (global_id.is_some()
                                && !(status == Status::New
                                    && target.is_some_and(|t| t.network == Network::Udp)))
                            || f.has_data() != (options & DATA != 0)
                        {
                            continue;
                        }
                        frames.push(f);
                    }
                }
            }
        }
        assert!(frames.len() > 20, "the sweep should cover many shapes");

        let mut checked = 0usize;
        for f in &frames {
            for len in [0usize, 1, 2, 15, 16, 17, 255, 256, 1400, 8192] {
                if !f.has_data() && len != 0 {
                    continue;
                }
                if len > CHUNK_MAX {
                    continue;
                }
                let payload: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x3C).collect();
                let data = f.has_data().then_some(payload.as_slice());

                let mut whole = vec![0u8; f.frame_len(len)];
                let n = f.encode_into(data, &mut whole);
                assert_eq!(n, whole.len(), "frame_len and the encoder disagree");

                let mut header = Vec::new();
                let at = f.encode_header_into(&mut header);
                if f.has_data() {
                    f.patch_payload_len(&mut header, at, len);
                }
                let mut split = header.clone();
                split.extend_from_slice(data.unwrap_or(&[]));

                assert_eq!(
                    split,
                    whole,
                    "{:?} len {len}: header plus payload is not the frame",
                    (f.status, f.options)
                );
                assert_eq!(
                    header.len(),
                    2 + f.meta_len() + usize::from(f.has_data()) * 2,
                    "{:?}: the header length must not carry the payload",
                    (f.status, f.options)
                );
                checked += 1;
            }
        }
        assert!(
            checked > 100,
            "the sweep should be dense, not a sample: {checked}"
        );
    }

    /// The header grows into the buffer it is handed rather than reallocating or
    /// re-zeroing it. A byte test cannot witness this — the wire bytes are
    /// identical either way — so the assertion is pointer identity: the base does
    /// not move and the capacity does not grow across every shape.
    #[test]
    fn the_header_grows_into_its_own_capacity_and_never_reallocates() {
        let frames = [
            Outgoing {
                id: 1,
                status: Status::New,
                options: DATA,
                target: Some(Target::of(Network::Tcp, "192.0.2.1", 443)),
                global_id: None,
            },
            Outgoing {
                id: 2,
                status: Status::New,
                options: DATA,
                target: Some(Target::of(Network::Udp, "example.com", 53)),
                global_id: Some([7u8; GLOBAL_ID]),
            },
            Outgoing::bare(3, Status::KeepAlive, 0),
        ];
        let mut out = Vec::new();
        for f in &frames {
            let _ = f.encode_header_into(&mut out);
        }
        let warm = out.capacity();
        assert!(warm > 0, "the warm-up pass must have taken a buffer");
        for f in &frames {
            let base = out.as_ptr();
            let at = f.encode_header_into(&mut out);
            assert_eq!(
                out.as_ptr(),
                base,
                "the header reallocated instead of growing into its own tail"
            );
            assert_eq!(
                out.capacity(),
                warm,
                "reserve_exact over-grew: capacity moved across shapes"
            );
            assert_eq!(at, 2 + f.meta_len(), "the payload length offset");
            assert_eq!(
                out.len(),
                2 + f.meta_len() + usize::from(f.has_data()) * 2,
                "the header length must not carry the payload"
            );
        }
    }

    #[test]
    fn a_new_frame_is_the_bytes_the_fields_add_up_to() {
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "example.com", 80)),
            global_id: None,
        };
        let mut buf = [0u8; 64];
        let n = out.encode_into(Some(b"abcd"), &mut buf);
        assert_eq!(&buf[..n], &NEW_DOMAIN);
        assert_eq!(
            n, 28,
            "two of length, twenty of metadata, two of chunk, four of payload"
        );
        assert_eq!(
            &buf[..2],
            &LEN,
            "the length counts the metadata and neither chunk nor itself"
        );
        assert_eq!(&buf[2..4], &ID);
        assert_eq!(out.meta_len(), 20);
        assert_eq!(out.frame_len(4), 28);
    }

    #[test]
    fn a_new_frame_decodes_back_into_what_encoded_it() {
        let (frame, used) = decode(&NEW_DOMAIN, NewTail::Forward).expect("it decodes");
        assert_eq!(used, NEW_DOMAIN.len(), "the whole frame, chunk included");
        assert_eq!(frame.id, 1);
        assert_eq!(frame.status, Status::New);
        assert_eq!(frame.options, DATA);
        assert_eq!(
            frame.target,
            Some(Target::of(Network::Tcp, "example.com", 80))
        );
        assert_eq!(frame.global_id, None);
        assert_eq!(frame.reflection, None);
        assert_eq!(frame.data, Some(&b"abcd"[..]));
        let (again, _) = decode(&NEW_DOMAIN, NewTail::Forward).expect("and again");
        assert_eq!(frame, again, "decoding is a function of the bytes");
    }

    /// `decode` driven over one fixed frame, again and again, so a callgrind
    /// frame prices the decoder and nothing else: no socket, no allocation, no
    /// fixture — the fold is the only other work in the loop. This is the probe
    /// the `mux-cool` decode row in `scripts/method-ops.txt` points at.
    #[test]
    fn the_decode_probe_costs_the_frame_walk_and_nothing_else() {
        let mut sink = 0usize;
        for _ in 0..4096 {
            let (frame, used) = decode(&NEW_DOMAIN, NewTail::Forward).expect("decodes");
            sink += used + frame.data.map_or(0, <[u8]>::len) + usize::from(frame.id);
        }
        assert_eq!(sink, 4096 * (NEW_DOMAIN.len() + 4 + 1), "the loop ran");
    }

    /// `encode_into` driven over one fixed frame, again and again, so a callgrind
    /// frame prices the metadata and payload write and nothing else.
    #[test]
    fn the_frame_probe_costs_the_metadata_and_payload_write_and_nothing_else() {
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "example.com", 80)),
            global_id: None,
        };
        let mut buf = [0u8; 64];
        let mut sink = 0usize;
        for _ in 0..4096 {
            sink += out.encode_into(Some(b"abcd"), &mut buf);
        }
        assert_eq!(sink, 4096 * NEW_DOMAIN.len(), "the loop ran");
    }

    /// `encode_header_into` driven over one fixed Keep, again and again, so a
    /// callgrind frame prices the header write and nothing else.
    #[test]
    fn the_header_probe_costs_the_metadata_write_and_nothing_else() {
        let out = Outgoing::bare(1, Status::Keep, DATA);
        let mut header = Vec::with_capacity(8);
        let mut sink = 0usize;
        for _ in 0..4096 {
            let at = out.encode_header_into(&mut header);
            out.patch_payload_len(&mut header, at, CHUNK_MAX);
            sink += header.len();
        }
        assert_eq!(sink, 4096 * 8, "the loop ran");
    }

    #[test]
    fn the_ipv4_and_ipv6_families_sit_where_the_field_says() {
        let v4 = Outgoing {
            id: 7,
            status: Status::New,
            options: 0,
            target: Some(Target::of(Network::Tcp, "192.0.2.53", 443)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = v4.encode_into(None, &mut buf);
        assert_eq!(v4.meta_len(), 12);
        assert_eq!(n, 14);
        assert_eq!(
            &buf[..n],
            &[0, 12, 0, 7, 1, 0, 1, 0x01, 0xbb, 1, 192, 0, 2, 53]
        );

        let v6 = Outgoing {
            id: 7,
            status: Status::New,
            options: 0,
            target: Some(Target::of(Network::Tcp, "2001:db8::1", 443)),
            global_id: None,
        };
        let n = v6.encode_into(None, &mut buf);
        assert_eq!(v6.meta_len(), 24, "four octets become sixteen");
        assert_eq!(n, 26);
        let frame = decode(&buf[..n], NewTail::Forward).expect("v6 decodes").0;
        assert_eq!(
            frame.target,
            Some(Target::of(Network::Tcp, "2001:db8::1", 443))
        );
        assert_eq!(frame.data, None);
    }

    #[test]
    fn a_new_udp_frame_carries_eight_bytes_of_nat_identity() {
        let identity = [0xa1u8; GLOBAL_ID];
        let out = Outgoing {
            id: 3,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Udp, "example.com", 53)),
            global_id: Some(identity),
        };
        let mut buf = [0u8; 64];
        let n = out.encode_into(Some(b"q"), &mut buf);
        assert_eq!(out.meta_len(), 28);
        assert_eq!(n, 33);
        assert_eq!(&buf[2..4], &[0, 3]);
        assert_eq!(
            &buf[22..30],
            &identity,
            "the identity sits after the target address"
        );
        assert_eq!(
            &buf[30..n],
            &[0, 1, b'q'],
            "the chunk is length then payload"
        );

        let frame = decode(&buf[..n], NewTail::Forward)
            .expect("udp new decodes")
            .0;
        assert_eq!(frame.global_id, Some(identity));
        assert_eq!(frame.data, Some(&b"q"[..]));
    }

    #[test]
    fn keep_and_end_carry_only_the_four_fixed_bytes() {
        for status in [Status::Keep, Status::End, Status::KeepAlive] {
            let out = Outgoing::bare(9, status, 0);
            let mut buf = [0u8; 16];
            let n = out.encode_into(None, &mut buf);
            assert_eq!(n, 6, "{status:?}: two of length and four of metadata");
            assert_eq!(buf[..n], [0, 4, 0, 9, status.byte(), 0]);
            assert_eq!(out.meta_len(), 4);
            let frame = decode(&buf[..n], NewTail::Forward).expect("decodes");
            assert_eq!(frame.0.status, status);
            assert_eq!(frame.0.target, None);
            assert_eq!(frame.0.data, None);
        }
    }

    #[test]
    fn an_end_frame_says_why_with_one_bit() {
        let out = Outgoing::bare(4, Status::End, ERROR);
        let mut buf = [0u8; 16];
        let n = out.encode_into(None, &mut buf);
        assert_eq!(buf[5], ERROR);
        assert_eq!(
            decode(&buf[..n], NewTail::Forward)
                .expect("decodes")
                .0
                .options,
            ERROR
        );
    }

    #[test]
    fn a_keep_frame_may_bring_its_own_datagram_destination() {
        let out = Outgoing {
            id: 2,
            status: Status::Keep,
            options: DATA,
            target: Some(Target::of(Network::Udp, "192.0.2.9", 5353)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = out.encode_into(Some(b"ping"), &mut buf);
        assert_eq!(
            buf[6], 0x02,
            "the network byte is what marks this as a datagram"
        );
        let frame = decode(&buf[..n], NewTail::Forward).expect("decodes").0;
        assert_eq!(
            frame.target,
            Some(Target::of(Network::Udp, "192.0.2.9", 5353))
        );
        assert_eq!(frame.data, Some(&b"ping"[..]));

        let bare = Outgoing::bare(2, Status::Keep, DATA);
        let n = bare.encode_into(Some(b"hi"), &mut buf);
        let frame = decode(&buf[..n], NewTail::Forward).expect("decodes").0;
        assert_eq!(frame.target, None, "no network byte, no address");
        assert_eq!(frame.data, Some(&b"hi"[..]));
    }
    /// The head split cut the metadata at the fixed boundary once for all four
    /// statuses, and which shapes still carry a target plus how many bytes a
    /// frame consumes is the only thing that decision had to preserve. This walks
    /// every status against a bare head, a head naming UDP, and a head naming
    /// TCP — the last a `Keep` forging a destination the encoder itself refuses —
    /// and pins the target/no-target answer and the consumed length, so the
    /// per-frame probe that used to ask cannot be missed.
    #[test]
    fn every_status_decides_its_target_from_the_bytes_a_head_split_reveals() {
        let shapes: [(Option<Network>, &[u8]); 3] = [
            (None, &[]),
            (
                Some(Network::Udp),
                &[Network::Udp.byte(), 0, 53, 1, 192, 0, 2, 9],
            ),
            (
                Some(Network::Tcp),
                &[Network::Tcp.byte(), 1, 187, 1, 192, 0, 2, 9],
            ),
        ];
        for status in [Status::New, Status::Keep, Status::End, Status::KeepAlive] {
            for (net, trailing) in shapes {
                let mut meta = vec![0, 5, status.byte(), 0];
                meta.extend_from_slice(trailing);
                let mut frame = vec![(meta.len() >> 8) as u8, (meta.len() & 0xff) as u8];
                frame.extend_from_slice(&meta);
                // a New with no trailing metadata promises a target it cannot find: the probe and the match both reach the same Truncated
                if status == Status::New && trailing.is_empty() {
                    assert_eq!(
                        decode(&frame, NewTail::Forward),
                        Err(Error::Truncated),
                        "{status:?}: a New with nowhere to read its target"
                    );
                    continue;
                }
                let (decoded, used) = decode(&frame, NewTail::Forward)
                    .unwrap_or_else(|e| panic!("{status:?} net {net:?}: {e}"));
                let want = match status {
                    Status::New => true,
                    Status::Keep => net == Some(Network::Udp),
                    Status::End | Status::KeepAlive => false,
                };
                assert_eq!(
                    decoded.target.is_some(),
                    want,
                    "{status:?} net {net:?}: the target decision moved"
                );
                if want {
                    assert_eq!(
                        decoded.target.unwrap().network,
                        net.expect("a decided target names a transport"),
                        "{status:?}: the wrong transport was read"
                    );
                }
                assert_eq!(
                    used,
                    2 + meta.len(),
                    "{status:?} net {net:?}: the consumed length moved"
                );
            }
        }
    }

    #[test]
    fn a_reverse_mux_frame_is_read_but_never_written() {
        let mut addresses = [0u8; 64];
        let mut at = 0;
        for (network, port, host) in [
            (Network::Udp, 53u16, "example.com"),
            (Network::Tcp, 443, "192.0.2.1"),
            (Network::Tcp, 8443, "198.51.100.7"),
        ] {
            addresses[at] = network.byte();
            at += 1;
            addresses[at..at + 2].copy_from_slice(&port.to_be_bytes());
            at += 2;
            at += Addr::of(host).encode_into(&mut addresses[at..]);
        }
        let mut buf = [0u8; 64];
        buf[..2].copy_from_slice(&((4 + at) as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&[0x00, 0x05]);
        buf[4] = Status::New.byte();
        buf[6..6 + at].copy_from_slice(&addresses[..at]);
        let total = 6 + at;

        let frame = decode(&buf[..total], NewTail::Reverse)
            .expect("a bridge's frame is framed, not dropped")
            .0;
        assert_eq!(frame.id, 5);
        let reflection = frame.reflection.expect("the tail is reflection");
        assert_eq!(
            reflection.source,
            Target::of(Network::Tcp, "192.0.2.1", 443)
        );
        assert_eq!(
            reflection.local,
            Some(Target::of(Network::Tcp, "198.51.100.7", 8443))
        );
        assert_eq!(
            frame.to_outgoing(),
            None,
            "which is why it is not written back"
        );
    }

    #[test]
    fn a_zero_network_byte_ends_a_reflection() {
        let target = Target::of(Network::Tcp, "192.0.2.53", 443);
        let source = Target::of(Network::Tcp, "192.0.2.1", 443);
        let mut tail = [0u8; 64];
        let mut at = 0;
        at += target.encode_into(&mut tail[at..]);
        at += source.encode_into(&mut tail[at..]);
        tail[at] = 0;

        let mut buf = [0u8; 64];
        buf[..2].copy_from_slice(&((4 + at + 1) as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&[0, 1]);
        buf[4] = Status::New.byte();
        let tail_len = at + 1;
        buf[6..6 + tail_len].copy_from_slice(&tail[..tail_len]);
        let total = 7 + at;

        let frame = decode(&buf[..total], NewTail::Reverse).expect("decodes").0;
        assert_eq!(frame.target, Some(target));
        let reflection = frame.reflection.expect("a source is enough");
        assert_eq!(reflection.source, source);
        assert_eq!(
            reflection.local, None,
            "zero means no local address, not a broken one"
        );
    }

    #[test]
    fn every_domain_length_survives_a_round_trip() {
        for len in 0..=addr::MAX_DOMAIN {
            let host = "d".repeat(len);
            let out = Outgoing {
                id: u16::MAX - len as u16,
                status: Status::New,
                options: DATA,
                target: Some(Target::of(Network::Tcp, &host, len as u16)),
                global_id: None,
            };
            let payload = [0x5au8; 3];
            let mut buf = vec![0u8; out.frame_len(payload.len())];
            let n = out.encode_into(Some(&payload), &mut buf);
            assert_eq!(
                n,
                buf.len(),
                "len {len}: the frame is exactly as long as it said"
            );
            let (frame, used) =
                decode(&buf, NewTail::Forward).unwrap_or_else(|e| panic!("len {len}: {e}"));
            assert_eq!(used, n, "len {len}");
            assert_eq!(frame.id, u16::MAX - len as u16, "len {len}");
            assert_eq!(frame.data, Some(&payload[..]), "len {len}");
            let target = frame.target.expect("a new frame names its target");
            assert_eq!(target.port, len as u16, "len {len}");
            assert_eq!(target.addr.body(), host.as_bytes(), "len {len}");
        }
    }

    #[test]
    fn a_zero_length_payload_is_a_frame_and_not_an_error() {
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "192.0.2.1", 443)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = out.encode_into(Some(&[]), &mut buf);
        assert_eq!(&buf[n - 2..n], &[0, 0], "an empty chunk is two zero bytes");
        assert_eq!(
            decode(&buf[..n], NewTail::Forward).expect("decodes").0.data,
            Some(&[][..])
        );
    }

    #[test]
    fn trailing_bytes_are_the_next_frames_and_not_ours() {
        let mut buf = [0u8; 64];
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "192.0.2.1", 443)),
            global_id: None,
        };
        let n = out.encode_into(Some(b"one"), &mut buf);
        buf[n] = 0xde;
        buf[n + 1] = 0xad;
        let (frame, used) = decode(&buf[..n + 2], NewTail::Forward).expect("decodes");
        assert_eq!(used, n, "one frame is one frame");
        assert_eq!(frame.data, Some(&b"one"[..]));
    }

    #[test]
    fn the_decoder_refuses_only_what_it_cannot_frame() {
        let cases: [(&[u8], Error, &str); 7] = [
            (&[], Error::Short { need: 2, have: 0 }, "no length"),
            (&[0], Error::Short { need: 2, have: 1 }, "half a length"),
            (
                &[0, 3, 0, 1, 1, 0],
                Error::MetaLen(3),
                "shorter than the fixed four",
            ),
            (
                &[0, 200, 0, 1],
                Error::Short { need: 202, have: 4 },
                "a length the buffer has not caught up to",
            ),
            (
                &[0, 4, 0, 1, 9, 0],
                Error::Status(9),
                "a status nobody names",
            ),
            (
                &[0, 9, 0, 1, 1, 0, 5, 0, 80, 1, 192],
                Error::Network(5),
                "a transport nobody names",
            ),
            (
                &[0, 9, 0, 1, 1, 0, 1, 0, 80, 9, 192],
                Error::Family(9),
                "an address family nobody names",
            ),
        ];
        for (input, want, why) in cases {
            assert_eq!(decode(input, NewTail::Forward), Err(want), "{why}");
        }
    }

    #[test]
    fn metadata_that_ends_inside_a_field_is_refused_not_guessed() {
        assert_eq!(
            decode(&[0, 4, 0, 1, 1, 0], NewTail::Forward),
            Err(Error::Truncated),
            "not even a network byte"
        );
        assert_eq!(
            decode(&[0, 8, 0, 1, 1, 0, 1, 0, 80, 1], NewTail::Forward),
            Err(Error::Truncated),
            "a network and a port but no address"
        );
    }

    #[test]
    fn a_frame_that_claims_more_than_the_format_holds_is_refused() {
        let over = (META_MAX + 1) as u16;
        assert_eq!(
            decode(&over.to_be_bytes(), NewTail::Forward),
            Err(Error::MetaLen(over)),
            "781 is the whole format's ceiling and 782 is not"
        );
        let mut buf = vec![0u8; 2 + META_MAX];
        buf[..2].copy_from_slice(&(META_MAX as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&[0, 1]);
        buf[4] = Status::New.byte();
        buf[6] = Network::Tcp.byte();
        buf[7..9].copy_from_slice(&443u16.to_be_bytes());
        buf[9] = crate::addr::IPV4;
        buf[10..14].copy_from_slice(&[192, 0, 2, 1]);
        let frame = decode(&buf, NewTail::Forward).expect("781 is accepted");
        assert_eq!(frame.1, 2 + META_MAX);
        assert_eq!(
            frame.0.target,
            Some(Target::of(Network::Tcp, "192.0.2.1", 443))
        );
        assert_eq!(
            frame.0.global_id, None,
            "options are clear, so no identity is read"
        );
    }

    #[test]
    fn a_payload_the_buffer_has_not_caught_up_to_is_short_not_wrong() {
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "192.0.2.1", 443)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = out.encode_into(Some(b"abcdefgh"), &mut buf);
        assert_eq!(
            decode(&buf[..n - 1], NewTail::Forward),
            Err(Error::Short {
                need: n,
                have: n - 1
            })
        );
    }

    #[test]
    fn the_decoder_reads_a_superset_of_what_the_encoder_writes() {
        for len in [0usize, 1, 7, 63, 255] {
            let host = "h".repeat(len);
            for options in [0u8, DATA, DATA | ERROR] {
                let payload: Option<&[u8]> = if options & DATA != 0 {
                    Some(b"payload")
                } else {
                    None
                };
                let out = Outgoing {
                    id: 42,
                    status: Status::New,
                    options,
                    target: Some(Target::of(Network::Tcp, &host, 8080)),
                    global_id: None,
                };
                let mut buf = vec![0u8; out.frame_len(payload.map_or(0, <[u8]>::len))];
                let n = out.encode_into(payload, &mut buf);
                let frame = decode(&buf[..n], NewTail::Forward).expect("decodes").0;
                let label = format!("len {len} options {options:#04x}");
                assert_eq!(frame.to_outgoing(), Some(out), "{label}");
                assert_eq!(frame.data, payload, "{label}");
            }
        }
    }

    #[test]
    fn ids_are_handed_out_once_each_and_refused_rather_than_wrapped() {
        let mut ids = Ids::new(0);
        assert_eq!(
            ids.take(),
            Ok(1),
            "the first id is one, as upstream's pre-increment makes it"
        );
        assert_eq!(ids.take(), Ok(2));
        assert_eq!(ids.live(), 2);
        assert_eq!(ids.opened(), 2);
        ids.give_back();
        assert_eq!(ids.live(), 1);
        assert_eq!(ids.take(), Ok(3), "a returned id is not reissued");

        let mut capped = Ids::new(2);
        assert_eq!(capped.take(), Ok(1));
        assert_eq!(capped.take(), Ok(2));
        assert_eq!(
            capped.take(),
            Err(IdError::Full),
            "another connection is the answer here"
        );
        assert_eq!(capped.live(), 2);
        assert_eq!(capped.cap(), 2);
        capped.give_back();
        assert_eq!(capped.take(), Ok(3), "and the id space moves on regardless");

        let mut all = Ids::new(0);
        for expected in 1..=u32::from(u16::MAX) {
            assert_eq!(all.take(), Ok(expected as u16), "session {expected}");
        }
        assert_eq!(all.take(), Err(IdError::Exhausted));
        assert_eq!(all.opened(), u32::from(u16::MAX));
    }

    #[test]
    fn sessions_are_indexed_by_id_and_handed_back_on_close() {
        let mut sessions = Sessions::new();
        assert_eq!(sessions.cap(), DEFAULT_CAP);
        assert_eq!(sessions.open(1, "one"), Some(None));
        assert_eq!(sessions.open(3, "three"), Some(None));
        assert_eq!(sessions.live(), 2);
        assert_eq!(sessions.get(1), Some(&"one"));
        assert_eq!(sessions.get(2), None);
        assert_eq!(sessions.close(1), Some("one"));
        assert_eq!(sessions.live(), 1);
        assert_eq!(sessions.get(1), None);
        if let Some(slot) = sessions.get_mut(3) {
            *slot = "THREE";
        }
        assert_eq!(sessions.get(3), Some(&"THREE"));
        assert_eq!(sessions.close(1), None, "a tombstone is not a session");
        assert_eq!(sessions.live(), 1, "and closing one does not count twice");
    }

    #[test]
    fn reopening_a_live_id_hands_the_old_session_back() {
        let mut sessions = Sessions::with_cap(8);
        assert_eq!(sessions.open(4, "first"), Some(None));
        assert_eq!(sessions.open(4, "second"), Some(Some("first")));
        assert_eq!(sessions.live(), 1, "one session, not two");
        assert_eq!(sessions.get(4), Some(&"second"));
    }

    #[test]
    fn an_id_a_peer_invents_costs_a_slot_it_already_paid_for() {
        let mut sessions = Sessions::<u32>::with_cap(2);
        assert_eq!(sessions.slot_count(), 4, "twice the cap, a power of two");
        assert_eq!(sessions.open(u16::MAX, 1), Some(None));
        assert_eq!(sessions.slot_count(), 4, "no growth, whatever the id");
        assert_eq!(sessions.get(u16::MAX), Some(&1));
        assert_eq!(sessions.live(), 1);
        assert_eq!(sessions.open(0, 2), Some(None));
        assert_eq!(sessions.get(0), Some(&2));
        assert_eq!(sessions.live(), 2);
        assert_eq!(sessions.open(7, 3), None, "the cap is two, not three");
    }

    #[test]
    fn a_closed_slot_is_reused_rather_than_left_to_pile_up() {
        let mut sessions = Sessions::<u32>::with_cap(2);
        let slots = sessions.slot_count();
        for round in 0..1_000u32 {
            let id = u16::try_from(round % 2).expect("two ids");
            assert_eq!(sessions.open(id, round), Some(None), "round {round}");
            assert_eq!(sessions.close(id), Some(round), "round {round}");
            assert_eq!(sessions.live(), 0, "round {round}");
        }
        assert_eq!(sessions.slot_count(), slots, "1000 rounds and no growth");
    }

    #[test]
    fn a_tombstone_is_reused_for_a_new_id() {
        let mut sessions = Sessions::<u32>::with_cap(2);
        for id in 1..=4u16 {
            assert_eq!(sessions.open(id, u32::from(id)), Some(None), "id {id}");
            assert_eq!(sessions.close(id), Some(u32::from(id)), "id {id}");
        }
        assert_eq!(sessions.live(), 0);
        assert_eq!(
            sessions.open(5, 5),
            Some(None),
            "a closed slot is free for a new id"
        );
        assert_eq!(sessions.get(5), Some(&5));
    }

    #[test]
    fn a_tombstone_does_not_open_past_the_cap() {
        let mut sessions = Sessions::with_cap(2);
        assert_eq!(sessions.open(1, 'a'), Some(None));
        assert_eq!(sessions.open(2, 'b'), Some(None));
        assert_eq!(sessions.close(1), Some('a'));
        assert_eq!(
            sessions.open(3, 'c'),
            Some(None),
            "a free slot, not the tombstone"
        );
        assert_eq!(sessions.live(), 2);
        assert_eq!(
            sessions.open(1, 'd'),
            None,
            "reusing a tombstone is a third live session"
        );
        assert_eq!(sessions.live(), 2);
        assert_eq!(
            sessions.get(1),
            None,
            "and the refused session left no slot"
        );
    }

    #[test]
    fn the_concurrency_cap_counts_live_sessions_and_not_the_ids_used() {
        let mut sessions = Sessions::with_cap(2);
        assert_eq!(sessions.open(1, 'a'), Some(None));
        assert_eq!(sessions.open(2, 'b'), Some(None));
        assert_eq!(
            sessions.open(3, 'c'),
            None,
            "a third is over the cap whatever its id"
        );
        assert_eq!(sessions.close(2), Some('b'));
        assert_eq!(
            sessions.open(u16::MAX, 'z'),
            Some(None),
            "the id is a key, so a big one opens like a small one"
        );
        assert_eq!(sessions.live(), 2);
        assert_eq!(sessions.open(9, 'c'), None, "and the cap still counts");
        assert_eq!(sessions.close(u16::MAX), Some('z'));
        assert_eq!(
            sessions.open(9, 'c'),
            Some(None),
            "the freed slot takes a small id"
        );
    }
}
