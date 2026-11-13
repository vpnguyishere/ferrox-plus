//! The `sudoku` TCP mask: every plaintext byte becomes four disguised hint bytes, drawn from a
//! per-password table of 4x4 grids, and the packed direction carries three plaintext bytes in four.
//! The two directions are asymmetric in the reference: a client writes the pure stream and reads the
//! packed one, a server the reverse, so the mask needs a reader where `fragment` needed only a writer.
//!
//! The table is derived, not stored: 288 grids in deterministic DFS order, 1820 four-cell clue sets,
//! and a Go `math/rand` v1 shuffle seeded by the password's first eight SHA-256 octets put grid `b`
//! at table slot `b`. That shuffle is the wire contract — a peer running the pinned reference derives
//! the same table only if the draw is byte-identical — so [`go_rand`](super::go_rand) reproduces it.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::mem;
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};

use super::go_rand::GoRand;
use super::MaskRole;

/// One read asks for this many wire octets at a time; the reference's own reader buffer.
const READ_CHUNK: usize = 32 * 1024;

/// The 24 orderings of four hint bytes, in the reference's order.
const PERM4: [[u8; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Entropy,
    Ascii,
    Custom,
}

/// One layout's byte arithmetic: how a six-bit group becomes a wire octet, which octets are hints,
/// and which padding octets never decode as one.
struct Layout {
    mode: Mode,
    hint_mask: u8,
    hint_value: u8,
    pad_marker: u8,
    padding: Vec<u8>,
    x_mask: u8,
    p_bits: [u8; 2],
    v_bits: [u8; 4],
}

impl fmt::Debug for Layout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Layout")
            .field("mode", &self.mode)
            .field("pad_marker", &self.pad_marker)
            .field("padding", &self.padding.len())
            .finish_non_exhaustive()
    }
}

impl Layout {
    fn entropy() -> Self {
        let mut padding = Vec::with_capacity(16);
        for i in 0..8u8 {
            padding.push(0x80 + i);
            padding.push(0x10 + i);
        }
        Self {
            mode: Mode::Entropy,
            hint_mask: 0x90,
            hint_value: 0,
            pad_marker: 0x80,
            padding,
            x_mask: 0,
            p_bits: [0; 2],
            v_bits: [0; 4],
        }
    }

    fn ascii() -> Self {
        Self {
            mode: Mode::Ascii,
            hint_mask: 0x40,
            hint_value: 0x40,
            pad_marker: 0x3f,
            padding: (0x20..0x40).collect(),
            x_mask: 0,
            p_bits: [0; 2],
            v_bits: [0; 4],
        }
    }

    fn custom(pattern: &str) -> Option<Self> {
        let mut x_bits = [0u8; 2];
        let mut p_bits = [0u8; 2];
        let mut v_bits = [0u8; 4];
        let (mut x, mut p, mut v) = (0usize, 0usize, 0usize);
        for (index, byte) in pattern.bytes().enumerate() {
            let bit = 7 - index as u8;
            match byte {
                b'x' => {
                    *x_bits.get_mut(x)? = bit;
                    x += 1;
                }
                b'p' => {
                    *p_bits.get_mut(p)? = bit;
                    p += 1;
                }
                b'v' => {
                    *v_bits.get_mut(v)? = bit;
                    v += 1;
                }
                _ => return None,
            }
        }
        if (x, p, v) != (2, 2, 4) {
            return None;
        }
        let x_mask: u8 = (1 << x_bits[0]) | (1 << x_bits[1]);
        let mut padding = [0u8; 128];
        let mut len = 0usize;
        for &drop_bit in &x_bits {
            for val in 0..4u8 {
                for pos in 0..16u8 {
                    let mut out = x_mask;
                    out &= !(1 << drop_bit);
                    out |= if val & 0x02 != 0 { 1 << p_bits[0] } else { 0 };
                    out |= if val & 0x01 != 0 { 1 << p_bits[1] } else { 0 };
                    for (i, bit) in v_bits.iter().enumerate() {
                        if (pos >> (3 - i as u8)) & 1 == 1 {
                            out |= 1 << bit;
                        }
                    }
                    if out.count_ones() >= 5 && !padding[..len].contains(&out) {
                        padding[len] = out;
                        len += 1;
                    }
                }
            }
        }
        let mut padding = padding[..len].to_vec();
        padding.sort_unstable();
        let pad_marker = *padding.first()?;
        Some(Self {
            mode: Mode::Custom,
            hint_mask: x_mask,
            hint_value: x_mask,
            pad_marker,
            padding,
            x_mask,
            p_bits,
            v_bits,
        })
    }

    fn is_hint(&self, byte: u8) -> bool {
        (byte & self.hint_mask) == self.hint_value || (self.mode == Mode::Ascii && byte == b'\n')
    }

    fn encode_group(&self, group: u8) -> u8 {
        match self.mode {
            Mode::Entropy => {
                let value = group & 0x3f;
                ((value & 0x30) << 1) | (value & 0x0f)
            }
            Mode::Ascii => {
                let byte = 0x40 | (group & 0x3f);
                if byte == 0x7f {
                    b'\n'
                } else {
                    byte
                }
            }
            Mode::Custom => {
                let mut out = self.x_mask;
                let value = (group >> 4) & 0x03;
                let pos = group & 0x0f;
                if value & 0x02 != 0 {
                    out |= 1 << self.p_bits[0];
                }
                if value & 0x01 != 0 {
                    out |= 1 << self.p_bits[1];
                }
                for (i, bit) in self.v_bits.iter().enumerate() {
                    if (pos >> (3 - i as u8)) & 1 == 1 {
                        out |= 1 << bit;
                    }
                }
                out
            }
        }
    }

    fn decode_group(&self, byte: u8) -> Option<u8> {
        match self.mode {
            Mode::Entropy => ((byte & 0x90) == 0).then_some(((byte >> 1) & 0x30) | (byte & 0x0f)),
            Mode::Ascii => {
                if byte == b'\n' {
                    Some(0x3f)
                } else if byte & 0x40 == 0 {
                    None
                } else {
                    Some(byte & 0x3f)
                }
            }
            Mode::Custom => {
                if byte & self.x_mask != self.x_mask {
                    return None;
                }
                let mut value = 0u8;
                if byte & (1 << self.p_bits[0]) != 0 {
                    value |= 0x02;
                }
                if byte & (1 << self.p_bits[1]) != 0 {
                    value |= 0x01;
                }
                let mut pos = 0u8;
                for (i, bit) in self.v_bits.iter().enumerate() {
                    if byte & (1 << bit) != 0 {
                        pos |= 1 << (3 - i as u8);
                    }
                }
                Some((value << 4) | (pos & 0x0f))
            }
        }
    }

    /// A pure-direction padding octet: any pool byte, the marker included, because the pure decoder
    /// drops every octet that is not a hint and a marker is never one.
    fn pure_padding(&self, rng: &mut SudokuRng) -> io::Result<u8> {
        let index = rng.int_n(self.padding.len())?;
        Ok(self.padding[index])
    }

    /// A packed-direction padding octet: never the marker, because the marker resets the bit stream
    /// and spreading one through a payload would cut it.
    fn packed_padding(&self, rng: &mut SudokuRng) -> io::Result<u8> {
        if let [only] = self.padding.as_slice() {
            return Ok(*only);
        }
        loop {
            let index = rng.int_n(self.padding.len())?;
            let byte = self.padding[index];
            if byte != self.pad_marker {
                return Ok(byte);
            }
        }
    }
}

/// The table slot `byte` carries: the four hint values for that plaintext octet in every accepted
/// clue set of the grid, and the reverse key -> octet map.
struct Table {
    encode: Vec<Vec<[u8; 4]>>,
    decode: Vec<(u32, u8)>,
    layout: Layout,
}

impl fmt::Debug for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Table")
            .field("entries", &self.encode.len())
            .field("keys", &self.decode.len())
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl Table {
    fn decode_byte(&self, key: u32) -> Option<u8> {
        self.decode
            .binary_search_by_key(&key, |(k, _)| *k)
            .ok()
            .map(|at| self.decode[at].1)
    }
}

/// A seeded `getrandom` supply shaped like the reference's `rand/v2` draws: a pool of 64-bit words
/// and Lemire's multiply-and-reject for the bounded draw.
struct SudokuRng {
    cache: [u64; 4],
    at: usize,
}

impl SudokuRng {
    fn new() -> Self {
        Self {
            cache: [0; 4],
            at: 4,
        }
    }

    fn draw(&mut self) -> io::Result<u64> {
        if self.at == 4 {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).map_err(|_| io::Error::other("sudoku entropy"))?;
            let words = raw.as_chunks::<8>().0;
            self.cache = [
                u64::from_le_bytes(words[0]),
                u64::from_le_bytes(words[1]),
                u64::from_le_bytes(words[2]),
                u64::from_le_bytes(words[3]),
            ];
            self.at = 0;
        }
        let draw = self.cache[self.at];
        self.at += 1;
        Ok(draw)
    }

    fn int_n(&mut self, n: usize) -> io::Result<usize> {
        let n = n as u64;
        let mut value = self.draw()?;
        let mut product = u128::from(value) * u128::from(n);
        let mut low = product as u64;
        if low < n {
            let threshold = n.wrapping_neg() % n;
            while low < threshold {
                value = self.draw()?;
                product = u128::from(value) * u128::from(n);
                low = product as u64;
            }
        }
        Ok((product >> 64) as usize)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterKind {
    Pure,
    Packed,
}

struct Encoder {
    tables: Arc<[Table]>,
    kind: WriterKind,
    rng: SudokuRng,
    padding_min: u32,
    padding_max: u32,
    chance: Option<u32>,
    table_index: usize,
    group_index: usize,
    out: Vec<u8>,
}

impl Encoder {
    fn new(tables: Arc<[Table]>, padding_min: u32, padding_max: u32, kind: WriterKind) -> Self {
        Self {
            tables,
            kind,
            rng: SudokuRng::new(),
            padding_min,
            padding_max,
            chance: None,
            table_index: 0,
            group_index: 0,
            out: Vec::new(),
        }
    }

    fn encode(&mut self, p: &[u8]) -> io::Result<&[u8]> {
        self.out.clear();
        if p.is_empty() {
            return Ok(&self.out);
        }
        match self.kind {
            WriterKind::Pure => self.encode_pure(p)?,
            WriterKind::Packed => self.encode_packed(p)?,
        }
        Ok(&self.out)
    }

    fn encode_pure(&mut self, p: &[u8]) -> io::Result<()> {
        self.out
            .reserve(p.len().saturating_mul(10).saturating_add(8));
        let mut out = mem::take(&mut self.out);
        let tables = &self.tables;
        let len = tables.len();
        let (padding_min, padding_max) = (self.padding_min, self.padding_max);
        let rng = &mut self.rng;
        let chance = &mut self.chance;
        for &byte in p {
            let table = &tables[self.table_index];
            if should_pad(rng, chance, padding_min, padding_max)? {
                push_pure_pad(rng, &mut out, &table.layout)?;
            }
            let choices = table
                .encode
                .get(byte as usize)
                .filter(|list| !list.is_empty());
            let Some(choices) = choices else {
                self.out = out;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sudoku table missing an entry",
                ));
            };
            let hints = choices[rng.int_n(choices.len())?];
            let perm = PERM4[rng.int_n(PERM4.len())?];
            for index in perm {
                if should_pad(rng, chance, padding_min, padding_max)? {
                    push_pure_pad(rng, &mut out, &table.layout)?;
                }
                out.push(hints[index as usize]);
            }
            self.table_index = next_slot(self.table_index, len);
        }
        let table = &tables[self.table_index];
        if should_pad(rng, chance, padding_min, padding_max)? {
            push_pure_pad(rng, &mut out, &table.layout)?;
        }
        self.out = out;
        Ok(())
    }

    fn encode_packed(&mut self, p: &[u8]) -> io::Result<()> {
        self.out
            .reserve(p.len().saturating_mul(3).saturating_add(8));
        let mut out = mem::take(&mut self.out);
        let tables = &self.tables;
        let len = tables.len();
        let (padding_min, padding_max) = (self.padding_min, self.padding_max);
        let rng = &mut self.rng;
        let chance = &mut self.chance;
        let mut bit_buf = 0u64;
        let mut bit_count = 0u32;
        for &byte in p {
            bit_buf = (bit_buf << 8) | u64::from(byte);
            bit_count += 8;
            while bit_count >= 6 {
                bit_count -= 6;
                let layout = &tables[self.group_index].layout;
                if should_pad(rng, chance, padding_min, padding_max)? {
                    push_packed_pad(rng, &mut out, layout)?;
                }
                out.push(layout.encode_group((bit_buf >> bit_count) as u8 & 0x3f));
                self.group_index = next_slot(self.group_index, len);
                bit_buf = if bit_count > 0 {
                    bit_buf & ((1u64 << bit_count) - 1)
                } else {
                    0
                };
            }
        }
        if bit_count > 0 {
            let layout = &tables[self.group_index].layout;
            if should_pad(rng, chance, padding_min, padding_max)? {
                push_packed_pad(rng, &mut out, layout)?;
            }
            let group = ((bit_buf << (6 - bit_count)) & 0x3f) as u8;
            out.push(layout.encode_group(group));
            self.group_index = next_slot(self.group_index, len);
            let next = &tables[self.group_index].layout;
            out.push(next.pad_marker);
        }
        let layout = &tables[self.group_index].layout;
        if should_pad(rng, chance, padding_min, padding_max)? {
            push_packed_pad(rng, &mut out, layout)?;
        }
        self.out = out;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReaderKind {
    Pure,
    Packed,
}

struct Reader {
    tables: Arc<[Table]>,
    kind: ReaderKind,
    table_index: usize,
    hint: [u8; 4],
    hint_len: usize,
    group_index: usize,
    bit_buf: u64,
    bit_count: u32,
    raw: Vec<u8>,
    pending: Vec<u8>,
    at: usize,
}

impl Reader {
    fn new(tables: Arc<[Table]>, kind: ReaderKind) -> Self {
        Self {
            tables,
            kind,
            table_index: 0,
            hint: [0; 4],
            hint_len: 0,
            group_index: 0,
            bit_buf: 0,
            bit_count: 0,
            raw: Vec::new(),
            pending: Vec::with_capacity(READ_CHUNK),
            at: 0,
        }
    }

    fn read<R: Read>(&mut self, inner: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(n) = self.take(buf) {
                return Ok(n);
            }
            if !self.fill(inner)? {
                return Ok(0);
            }
        }
    }

    fn peek<R: Read>(&mut self, inner: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending.len() > self.at {
                let n = (self.pending.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
                return Ok(n);
            }
            self.pending.clear();
            self.at = 0;
            if !self.fill(inner)? {
                return Ok(0);
            }
        }
    }

    fn take(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.pending.len() <= self.at {
            self.pending.clear();
            self.at = 0;
            return None;
        }
        let n = (self.pending.len() - self.at).min(buf.len());
        buf[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
        self.at += n;
        if self.at == self.pending.len() {
            self.pending.clear();
            self.at = 0;
        }
        Some(n)
    }

    fn fill<R: Read>(&mut self, inner: &mut R) -> io::Result<bool> {
        if self.raw.is_empty() {
            self.raw.resize(READ_CHUNK, 0);
        }
        let mut raw = mem::take(&mut self.raw);
        let read = inner.read(&mut raw);
        let decoded = match read {
            Ok(0) => Ok(false),
            Ok(n) => self.decode_chunk(&raw[..n]).map(|()| true),
            Err(error) => Err(error),
        };
        self.raw = raw;
        decoded
    }

    fn decode_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        match self.kind {
            ReaderKind::Pure => self.decode_pure(chunk),
            ReaderKind::Packed => self.decode_packed(chunk),
        }
    }

    fn decode_pure(&mut self, chunk: &[u8]) -> io::Result<()> {
        for &byte in chunk {
            let table = &self.tables[self.table_index];
            if !table.layout.is_hint(byte) {
                continue;
            }
            self.hint[self.hint_len] = byte;
            self.hint_len += 1;
            if self.hint_len < self.hint.len() {
                continue;
            }
            let key = pack_key(sort4(self.hint));
            let Some(plain) = table.decode_byte(key) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid sudoku hint tuple",
                ));
            };
            self.pending.push(plain);
            self.hint_len = 0;
            self.table_index = next_slot(self.table_index, self.tables.len());
        }
        Ok(())
    }

    fn decode_packed(&mut self, chunk: &[u8]) -> io::Result<()> {
        for &byte in chunk {
            let layout = &self.tables[self.group_index].layout;
            if !layout.is_hint(byte) {
                if byte == layout.pad_marker {
                    self.bit_buf = 0;
                    self.bit_count = 0;
                }
                continue;
            }
            let Some(group) = layout.decode_group(byte) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid packed sudoku byte",
                ));
            };
            self.group_index = next_slot(self.group_index, self.tables.len());
            self.bit_buf = (self.bit_buf << 6) | u64::from(group);
            self.bit_count += 6;
            while self.bit_count >= 8 {
                self.bit_count -= 8;
                self.pending.push((self.bit_buf >> self.bit_count) as u8);
                self.bit_buf = if self.bit_count > 0 {
                    self.bit_buf & ((1u64 << self.bit_count) - 1)
                } else {
                    0
                };
            }
        }
        Ok(())
    }
}

/// The configured `sudoku` stage. One instance is the config's template; every connection opens a
/// writer, a reader, or both from it, so the derived table is shared and the stream state is not.
pub struct Sudoku {
    tables: Arc<[Table]>,
    padding_min: u32,
    padding_max: u32,
    role: MaskRole,
    writer: Option<Encoder>,
    reader: Option<Reader>,
}

impl fmt::Debug for Sudoku {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sudoku")
            .field("tables", &self.tables.len())
            .field("padding_min", &self.padding_min)
            .field("padding_max", &self.padding_max)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl Clone for Sudoku {
    fn clone(&self) -> Self {
        self.template()
    }
}

impl Sudoku {
    /// A stage the config can drive: the mode and every custom pattern must normalise, and every
    /// derived table must be collision-free. `None` refuses the carrier rather than arming a stage
    /// whose bytes no peer derives.
    pub fn new(
        password: &str,
        ascii: &str,
        custom_table: &str,
        custom_tables: &[String],
        padding_min: u32,
        padding_max: u32,
    ) -> Option<Self> {
        let mode = normalize_ascii(ascii)?;
        let patterns = patterns(mode, custom_table, custom_tables)?;
        let mut tables = Vec::with_capacity(patterns.len());
        for pattern in &patterns {
            let layout = match mode {
                Mode::Ascii => Layout::ascii(),
                Mode::Entropy if pattern.is_empty() => Layout::entropy(),
                Mode::Custom | Mode::Entropy => Layout::custom(pattern)?,
            };
            tables.push(build_table(password, layout)?);
        }
        if tables.is_empty() {
            return None;
        }
        let templates = Self {
            tables: tables.into(),
            padding_min: padding_min.min(100),
            padding_max: padding_max.min(100),
            role: MaskRole::Client,
            writer: None,
            reader: None,
        };
        Some(Self {
            padding_max: templates.padding_max.max(templates.padding_min),
            ..templates
        })
    }

    fn template(&self) -> Self {
        Self {
            tables: Arc::clone(&self.tables),
            padding_min: self.padding_min,
            padding_max: self.padding_max,
            role: MaskRole::Client,
            writer: None,
            reader: None,
        }
    }

    /// The writer this connection needs: a client writes the pure direction and a server the packed
    /// one.
    #[must_use]
    pub fn open_write(&self, role: MaskRole) -> Self {
        let kind = match role {
            MaskRole::Client => WriterKind::Pure,
            MaskRole::Server => WriterKind::Packed,
        };
        Self {
            writer: Some(Encoder::new(
                Arc::clone(&self.tables),
                self.padding_min,
                self.padding_max,
                kind,
            )),
            ..self.template()
        }
    }

    /// The reader this connection needs: it reads the direction the peer wrote, the reverse of its
    /// own writer.
    #[must_use]
    pub fn open_read(&self, role: MaskRole) -> Self {
        let kind = match role {
            MaskRole::Client => ReaderKind::Packed,
            MaskRole::Server => ReaderKind::Pure,
        };
        Self {
            reader: Some(Reader::new(Arc::clone(&self.tables), kind)),
            ..self.template()
        }
    }

    /// Encode one plaintext write and put all of it on the wire. The answer is the plaintext length;
    /// an encoded stream has no partial-write count the caller could advance by.
    pub fn write<W: Write>(&mut self, raw: &mut W, p: &[u8]) -> io::Result<usize> {
        let Some(writer) = self.writer.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sudoku stage is not open for writing",
            ));
        };
        let encoded = writer.encode(p)?;
        write_wire(raw, encoded)?;
        Ok(p.len())
    }

    pub fn read_from<R: Read>(&mut self, inner: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        match self.reader.as_mut() {
            Some(reader) => reader.read(inner, buf),
            None => inner.read(buf),
        }
    }

    pub fn peek_from<R: Read>(&mut self, inner: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        match self.reader.as_mut() {
            Some(reader) => reader.peek(inner, buf),
            None => inner.read(buf),
        }
    }
}

#[inline]
fn next_slot(slot: usize, len: usize) -> usize {
    debug_assert!(slot < len);
    if slot + 1 == len {
        0
    } else {
        slot + 1
    }
}

fn should_pad(
    rng: &mut SudokuRng,
    chance: &mut Option<u32>,
    padding_min: u32,
    padding_max: u32,
) -> io::Result<bool> {
    let drawn = if let Some(drawn) = *chance {
        drawn
    } else {
        let drawn = if padding_min == padding_max {
            padding_min
        } else {
            let span = (padding_max - padding_min + 1) as usize;
            padding_min + rng.int_n(span)? as u32
        };
        *chance = Some(drawn);
        drawn
    };
    if drawn == 0 {
        return Ok(false);
    }
    if drawn >= 100 {
        return Ok(true);
    }
    Ok((rng.int_n(100)? as u32) < drawn)
}

fn push_pure_pad(rng: &mut SudokuRng, out: &mut Vec<u8>, layout: &Layout) -> io::Result<()> {
    out.push(layout.pure_padding(rng)?);
    Ok(())
}

fn push_packed_pad(rng: &mut SudokuRng, out: &mut Vec<u8>, layout: &Layout) -> io::Result<()> {
    out.push(layout.packed_padding(rng)?);
    Ok(())
}

fn write_wire<W: Write>(raw: &mut W, mut p: &[u8]) -> io::Result<()> {
    while !p.is_empty() {
        match raw.write(p) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => p = &p[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn normalize_ascii(mode: &str) -> Option<Mode> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "entropy" | "prefer_entropy" => Some(Mode::Entropy),
        "ascii" | "prefer_ascii" => Some(Mode::Ascii),
        _ => None,
    }
}

fn normalize_custom(pattern: &str) -> Option<String> {
    let cleaned: String = pattern
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| *c != ' ')
        .collect();
    if cleaned.len() != 8 || !cleaned.is_ascii() {
        return None;
    }
    let (mut x, mut p, mut v) = (0usize, 0usize, 0usize);
    for byte in cleaned.bytes() {
        match byte {
            b'x' => x += 1,
            b'p' => p += 1,
            b'v' => v += 1,
            _ => return None,
        }
    }
    ((x, p, v) == (2, 2, 4)).then_some(cleaned)
}

fn patterns(mode: Mode, custom_table: &str, custom_tables: &[String]) -> Option<Vec<String>> {
    if mode == Mode::Ascii {
        return Some(vec![String::new()]);
    }
    let raw: Vec<&str> = if custom_tables.is_empty() {
        vec![custom_table]
    } else {
        custom_tables.iter().map(String::as_str).collect()
    };
    let mut patterns: Vec<String> = Vec::with_capacity(raw.len());
    for raw in raw {
        let trimmed = raw.trim();
        let pattern = if trimmed.is_empty() {
            String::new()
        } else {
            normalize_custom(trimmed)?
        };
        if !patterns.contains(&pattern) {
            patterns.push(pattern);
        }
    }
    if patterns.is_empty() {
        patterns.push(String::new());
    }
    Some(patterns)
}

fn build_table(password: &str, layout: Layout) -> Option<Table> {
    let patterns = base_patterns();
    if patterns.len() < 256 {
        return None;
    }
    let mut order: Vec<usize> = (0..patterns.len()).collect();
    let digest = Sha256::digest(password.as_bytes());
    let seed = i64::from_be_bytes(digest[..8].try_into().ok()?);
    GoRand::new(seed).shuffle(&mut order);

    let mut decode: HashMap<u32, u8> = HashMap::with_capacity(1 << 12);
    let mut encode: Vec<Vec<[u8; 4]>> = vec![Vec::new(); 256];
    for byte in 0..256usize {
        let list = &patterns[order[byte]];
        if list.is_empty() {
            return None;
        }
        let mut choices = Vec::with_capacity(list.len());
        for groups in list {
            let hints = [
                layout.encode_group(groups[0]),
                layout.encode_group(groups[1]),
                layout.encode_group(groups[2]),
                layout.encode_group(groups[3]),
            ];
            let key = pack_key(sort4(hints));
            if let Some(&old) = decode.get(&key) {
                if old != byte as u8 {
                    return None;
                }
            }
            decode.insert(key, byte as u8);
            choices.push(hints);
        }
        encode[byte] = choices;
    }
    let mut decode: Vec<(u32, u8)> = decode.into_iter().collect();
    decode.sort_unstable_by_key(|(key, _)| *key);
    Some(Table {
        encode,
        decode,
        layout,
    })
}

fn base_patterns() -> &'static [Vec<[u8; 4]>] {
    static PATTERNS: OnceLock<Vec<Vec<[u8; 4]>>> = OnceLock::new();
    PATTERNS.get_or_init(build_base_patterns)
}

fn build_base_patterns() -> Vec<Vec<[u8; 4]>> {
    let grids = all_grids();
    let positions = hint_positions();
    let mut patterns: Vec<Vec<[u8; 4]>> = vec![Vec::new(); grids.len()];
    for position in positions {
        let mut counts: HashMap<u32, u16> = HashMap::with_capacity(grids.len());
        let mut keys = Vec::with_capacity(grids.len());
        let mut groups = Vec::with_capacity(grids.len());
        for grid in grids {
            let clue = [
                clue_group(grid, position[0]),
                clue_group(grid, position[1]),
                clue_group(grid, position[2]),
                clue_group(grid, position[3]),
            ];
            let clue = sort4(clue);
            let key = pack_key(clue);
            keys.push(key);
            groups.push(clue);
            *counts.entry(key).or_insert(0) += 1;
        }
        for (index, key) in keys.into_iter().enumerate() {
            if counts[&key] == 1 {
                patterns[index].push(groups[index]);
            }
        }
    }
    patterns
}

fn all_grids() -> &'static [[u8; 16]] {
    static GRIDS: OnceLock<Vec<[u8; 16]>> = OnceLock::new();
    GRIDS.get_or_init(generate_grids)
}

fn generate_grids() -> Vec<[u8; 16]> {
    fn dfs(index: usize, grid: &mut [u8; 16], out: &mut Vec<[u8; 16]>) {
        if index == 16 {
            out.push(*grid);
            return;
        }
        let row = index / 4;
        let col = index % 4;
        let box_row = (row / 2) * 2;
        let box_col = (col / 2) * 2;
        for num in 1u8..=4 {
            let mut valid = (0..4).all(|i| grid[row * 4 + i] != num && grid[i * 4 + col] != num);
            if valid {
                'boxes: for r in 0..2 {
                    for c in 0..2 {
                        if grid[(box_row + r) * 4 + box_col + c] == num {
                            valid = false;
                            break 'boxes;
                        }
                    }
                }
            }
            if !valid {
                continue;
            }
            grid[index] = num;
            dfs(index + 1, grid, out);
            grid[index] = 0;
        }
    }
    let mut grids = Vec::with_capacity(288);
    let mut grid = [0u8; 16];
    dfs(0, &mut grid, &mut grids);
    grids
}

fn hint_positions() -> Vec<[u8; 4]> {
    let mut positions = Vec::with_capacity(1820);
    for a in 0..13u8 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    positions.push([a, b, c, d]);
                }
            }
        }
    }
    positions
}

fn clue_group(grid: &[u8; 16], pos: u8) -> u8 {
    ((grid[pos as usize] - 1) << 4) | (pos & 0x0f)
}

fn sort4(mut v: [u8; 4]) -> [u8; 4] {
    v.sort_unstable();
    v
}

fn pack_key(v: [u8; 4]) -> u32 {
    u32::from_be_bytes(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(password: &str, ascii: &str, custom: &[&str]) -> Sudoku {
        let custom: Vec<String> = custom.iter().map(|s| (*s).to_owned()).collect();
        Sudoku::new(password, ascii, "", &custom, 0, 0).expect("a driveable stage")
    }

    fn round_trip(role: MaskRole, config: &Sudoku, plain: &[u8]) {
        let reader_role = match role {
            MaskRole::Client => MaskRole::Server,
            MaskRole::Server => MaskRole::Client,
        };
        let mut writer = config.open_write(role);
        let mut reader = config.open_read(reader_role);
        let mut wire = Vec::new();
        writer.write(&mut wire, plain).expect("encodes");
        assert_ne!(wire, plain, "the mask changes the bytes on the wire");
        let mut input = wire.as_slice();
        let mut decoded = vec![0u8; plain.len()];
        let mut got = 0usize;
        while got < decoded.len() {
            let n = reader
                .read_from(&mut input, &mut decoded[got..])
                .expect("decodes");
            assert_ne!(n, 0, "the wire carries every plaintext octet");
            got += n;
        }
        assert_eq!(decoded, plain);
    }

    #[test]
    fn the_grids_and_positions_are_the_reference_sets() {
        assert_eq!(all_grids().len(), 288);
        assert_eq!(hint_positions().len(), 1820);
        assert_eq!(
            all_grids()[0],
            [1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1]
        );
        assert_eq!(
            all_grids()[287],
            [4, 3, 2, 1, 2, 1, 4, 3, 3, 4, 1, 2, 1, 2, 3, 4]
        );
    }

    #[test]
    fn every_grid_has_a_unique_clue_set() {
        for (index, list) in base_patterns().iter().enumerate() {
            assert!(!list.is_empty(), "grid {index} has no clue set");
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn the_reference_wire_decodes_to_its_plaintext() {
        let fixture = include_str!("../../../../scripts/sudoku-oracle/wire.txt");
        let mut cases = 0;
        for line in fixture.lines() {
            let mut fields = line.split_whitespace();
            match fields.next().expect("a fixture line") {
                "GRIDS" => {
                    assert_eq!(fields.next(), Some("288"));
                    assert_eq!(
                        hex(fields.next().expect("first grid")).as_slice(),
                        all_grids()[0]
                    );
                    assert_eq!(
                        hex(fields.next().expect("last grid")).as_slice(),
                        all_grids()[287]
                    );
                }
                direction @ ("PURE" | "PACKED") => {
                    let name = fields.next().expect("a case name");
                    let plain = hex(fields.next().expect("plaintext"));
                    let wire = hex(fields.next().expect("wire"));
                    let config = match name {
                        "entropy" | "all-bytes" => stage("hunter2", "", &[]),
                        "ascii" => stage("hunter2", "ascii", &[]),
                        "custom" | "padded" => stage("hunter2", "", &["xpxpvvvv"]),
                        "multi" => stage("hunter2", "", &["xpxpvvvv", "vxpvxpvv"]),
                        other => panic!("unknown fixture {other}"),
                    };
                    let role = if direction == "PURE" {
                        MaskRole::Server
                    } else {
                        MaskRole::Client
                    };
                    let mut reader = config.open_read(role);
                    let mut decoded = vec![0u8; plain.len()];
                    let mut input = wire.as_slice();
                    let mut got = 0usize;
                    while got < decoded.len() {
                        let n = reader
                            .read_from(&mut input, &mut decoded[got..])
                            .unwrap_or_else(|error| panic!("{direction} {name}: {error}"));
                        assert_ne!(n, 0, "the wire carries every plaintext octet");
                        got += n;
                    }
                    assert_eq!(decoded, plain, "{direction} {name}");
                    cases += 1;
                }
                other => panic!("unknown fixture record {other}"),
            }
        }
        assert_eq!(cases, 12, "every reference direction ran");
    }

    #[test]
    fn a_plain_stream_round_trips_in_both_directions() {
        let plain: Vec<u8> = (0..=255u8).collect();
        for role in [MaskRole::Client, MaskRole::Server] {
            round_trip(role, &stage("hunter2", "", &[]), &plain);
        }
    }

    #[test]
    fn ascii_and_custom_layouts_round_trip() {
        let plain: Vec<u8> = (0..=255u8).collect();
        round_trip(MaskRole::Client, &stage("x", "ascii", &[]), &plain);
        round_trip(MaskRole::Server, &stage("x", "prefer_ascii", &[]), &plain);
        round_trip(MaskRole::Client, &stage("x", "", &["xpxpvvvv"]), &plain);
        round_trip(MaskRole::Server, &stage("x", "", &["vvvvppxx"]), &plain);
        round_trip(
            MaskRole::Client,
            &stage("x", "", &["xpxpvvvv", "vxpvxpvv"]),
            &plain,
        );
    }

    #[test]
    fn every_padding_level_round_trips() {
        let plain: Vec<u8> = (0..=255u8).collect();
        for (min, max) in [(0, 0), (0, 100), (100, 100), (40, 40)] {
            for role in [MaskRole::Client, MaskRole::Server] {
                let custom: Vec<String> = Vec::new();
                let config =
                    Sudoku::new("pad", "", "", &custom, min, max).expect("a driveable stage");
                round_trip(role, &config, &plain);
            }
        }
    }

    #[test]
    fn a_decoder_keeps_its_state_across_short_reads() {
        struct Dribble<'a> {
            wire: &'a [u8],
            at: usize,
        }
        impl Read for Dribble<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let take = (self.wire.len() - self.at).min(buf.len().min(3));
                buf[..take].copy_from_slice(&self.wire[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }
        let config = stage("hunter2", "", &["xpxpvvvv"]);
        let plain: Vec<u8> = (0..=255u8).collect();
        let mut writer = config.open_write(MaskRole::Client);
        let mut wire = Vec::new();
        writer.write(&mut wire, &plain).expect("encodes");
        let mut reader = config.open_read(MaskRole::Server);
        let mut source = Dribble { wire: &wire, at: 0 };
        let mut decoded = vec![0u8; plain.len()];
        let mut got = 0usize;
        while got < decoded.len() {
            let n = reader
                .read_from(&mut source, &mut decoded[got..])
                .expect("decodes");
            assert_ne!(n, 0);
            got += n;
        }
        assert_eq!(decoded, plain);
    }

    #[test]
    fn a_peek_does_not_consume_the_plaintext() {
        let config = stage("hunter2", "", &[]);
        let plain: Vec<u8> = (0..32).collect();
        let mut writer = config.open_write(MaskRole::Client);
        let mut wire = Vec::new();
        writer.write(&mut wire, &plain).expect("encodes");
        let mut source = wire.as_slice();
        let mut reader = config.open_read(MaskRole::Server);
        let mut ahead = [0u8; 16];
        assert_eq!(
            reader.peek_from(&mut source, &mut ahead).expect("peeks"),
            16
        );
        assert_eq!(ahead, plain[..16]);
        let mut whole = vec![0u8; plain.len()];
        let mut got = 0usize;
        while got < whole.len() {
            got += reader
                .read_from(&mut source, &mut whole[got..])
                .expect("reads");
        }
        assert_eq!(whole, plain, "the peek left every octet for the read");
    }

    #[test]
    fn an_invalid_custom_table_is_refused() {
        let none: Vec<String> = Vec::new();
        assert!(Sudoku::new("x", "", "xpxpvvv", &none, 0, 0).is_none());
        assert!(Sudoku::new("x", "", "xxxxvvvv", &none, 0, 0).is_none());
        assert!(Sudoku::new("x", "", "xpxpvvvz", &none, 0, 0).is_none());
        assert!(Sudoku::new("x", "", "xpxpvvvv", &none, 0, 0).is_some());
        assert!(
            Sudoku::new("x", "unknown", "", &none, 0, 0).is_none(),
            "an unknown ascii mode is refused"
        );
    }

    #[test]
    fn padding_is_clamped_like_the_reference() {
        let none: Vec<String> = Vec::new();
        let config = Sudoku::new("x", "", "", &none, 200, 20).expect("a driveable stage");
        assert_eq!(config.padding_min, 100);
        assert_eq!(config.padding_max, 100);
    }

    #[test]
    fn the_wire_ratio_is_the_reference_shape() {
        let config = stage("hunter2", "", &[]);
        let plain = vec![7u8; 300];
        let mut pure = Vec::new();
        config
            .open_write(MaskRole::Client)
            .write(&mut pure, &plain)
            .expect("encodes the pure direction");
        assert_eq!(
            pure.len(),
            plain.len() * 4,
            "a pure write is four hints per octet"
        );
        let mut packed = Vec::new();
        config
            .open_write(MaskRole::Server)
            .write(&mut packed, &plain)
            .expect("encodes the packed direction");
        assert_eq!(
            packed.len(),
            plain.len() * 4 / 3,
            "a packed write is four octets per three plaintext octets"
        );
    }

    const PROBE_PLAINTEXT: usize = 4096;
    const PROBE_ROUNDS: usize = 16;

    #[inline(never)]
    fn encode_probe() -> usize {
        let config = stage("probe", "", &[]);
        let mut writer = config.open_write(MaskRole::Client);
        let plain: Vec<u8> = (0..PROBE_PLAINTEXT).map(|at| at as u8).collect();
        let mut sink = std::io::sink();
        let mut total = 0;
        for _ in 0..PROBE_ROUNDS {
            total += writer.write(&mut sink, &plain).expect("encodes");
        }
        std::hint::black_box(total)
    }

    #[inline(never)]
    fn decode_probe() -> usize {
        let config = stage("probe", "", &[]);
        let plain: Vec<u8> = (0..PROBE_PLAINTEXT).map(|at| at as u8).collect();
        let mut wire = Vec::new();
        let mut writer = config.open_write(MaskRole::Client);
        for _ in 0..PROBE_ROUNDS {
            writer.write(&mut wire, &plain).expect("encodes");
        }
        let mut reader = config.open_read(MaskRole::Server);
        let mut input = wire.as_slice();
        let mut decoded = vec![0u8; PROBE_PLAINTEXT];
        let mut total = 0;
        loop {
            let got = reader.read_from(&mut input, &mut decoded).expect("decodes");
            if got == 0 {
                break;
            }
            total += got;
        }
        std::hint::black_box(total)
    }

    #[test]
    fn the_sudoku_wire_costs_the_bytes_and_nothing_else() {
        assert_eq!(encode_probe(), PROBE_PLAINTEXT * PROBE_ROUNDS);
        assert_eq!(decode_probe(), PROBE_PLAINTEXT * PROBE_ROUNDS);
    }

    #[test]
    fn the_encoder_buffer_holds_its_capacity() {
        let config = stage("hunter2", "", &[]);
        let mut writer = config.open_write(MaskRole::Client);
        let mut sink = Vec::new();
        writer.write(&mut sink, &[0u8; 4096]).expect("encodes");
        let capacity = writer.writer.as_ref().expect("open").out.capacity();
        for len in [0usize, 1, 4096, 64, 2048] {
            writer.write(&mut sink, &vec![7u8; len]).expect("encodes");
            assert_eq!(
                writer.writer.as_ref().expect("open").out.capacity(),
                capacity,
                "the encode buffer does not grow again"
            );
        }
    }
}
