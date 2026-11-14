//! HPACK for HTTP/2 and QPACK for HTTP/3, both answering one question — the status — and refusing any representation needing a table the lane never fills, while both encoders write literals only: one request per stream, no table state, no Huffman. Integers share one prefix scheme: below `2^n - 1` the low `n` bits of one byte, else that maximum plus a base-128 remainder.

use std::sync::OnceLock;

/// The HPACK Huffman code is canonical — consecutive codes per length, each starting where the previous ended shifted left — so one byte per symbol rebuilds every code and a code maps back by its offset within its length.
const HUFFMAN_BITS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, //
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, //
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, //
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, //
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, //
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, //
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, //
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, //
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, //
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, //
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, //
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, //
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, //
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, //
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, //
    30,
];

const SHORTEST: usize = 5;
const MAX_BITS: usize = 30;
const PEEK: usize = 12;

/// The pair table's bit above the second symbol's length, set when a `PEEK`-bit window holds two codes.
const TWO_CODES: u32 = 1 << 26;

/// The symbols a `len`-octet Huffman window can hold: `SHORTEST` is the code's shortest symbol, so this is the ceiling the decode can reach and a buffer of it never grows.
const fn decoded_bound(len: usize) -> usize {
    8 * len / SHORTEST
}

struct Huffman {
    /// One load per probed length: the first code of that length in the high half and how many codes share it in the low half. A length with no codes reads `(0, 0)`, so the range test below already rejects it and no separate empty-length check is needed.
    probe: [u64; MAX_BITS + 1],
    /// Where each length's symbols begin in `symbols`, ordered by length then symbol, so a code is `first[length] + offset`; read only on the rare match.
    base: [u16; MAX_BITS + 1],
    symbols: [u16; 257],
    /// Each symbol's canonical code, built by the same walk the decode ranges come from, so encode and decode can never disagree.
    codes: [u32; 257],
    /// One load resolves one or two symbols whose codes fit the `PEEK`-bit window: low byte is the first symbol, the next five bits its length, then the second symbol and length with `TWO_CODES`; zero means no code prefixes the window and the serial probe takes over. Prefix-freeness makes each hit unique.
    pair: [u32; 1 << PEEK],
}

fn huffman() -> &'static Huffman {
    static TABLE: OnceLock<Huffman> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Huffman {
            probe: [0; MAX_BITS + 1],
            base: [0; MAX_BITS + 1],
            symbols: [0; 257],
            codes: [0; 257],
            pair: [0; 1 << PEEK],
        };
        let mut next = 0u32;
        let mut placed = 0usize;
        let mut previous = 0usize;
        for bits in SHORTEST..=MAX_BITS {
            if !HUFFMAN_BITS.contains(&(bits as u8)) {
                continue;
            }
            next <<= bits - previous;
            previous = bits;
            let first = next;
            table.base[bits] = placed as u16;
            let mut count = 0u32;
            for (symbol, length) in HUFFMAN_BITS.iter().enumerate() {
                if usize::from(*length) != bits {
                    continue;
                }
                table.symbols[placed] = symbol as u16;
                table.codes[symbol] = first + count;
                count += 1;
                placed += 1;
                next += 1;
            }
            table.probe[bits] = (u64::from(first) << 32) | u64::from(count);
            if bits <= PEEK {
                let spread = 1usize << (PEEK - bits);
                let base = placed - count as usize;
                for slot in 0..count as usize {
                    let entry = table.symbols[base + slot] as u32 | ((bits as u32) << 8);
                    let at = ((first as usize) << (PEEK - bits)) + (slot << (PEEK - bits));
                    table.pair[at..at + spread].fill(entry);
                }
            }
        }
        for window in 0..(1u32 << PEEK) {
            let entry = table.pair[window as usize];
            let first_len = ((entry >> 8) & 0x1f) as usize;
            if first_len == 0 {
                continue;
            }
            let remaining = PEEK - first_len;
            let rest = ((window << first_len) & ((1u32 << PEEK) - 1)) as usize;
            let second = table.pair[rest];
            let second_len = ((second >> 8) & 0x1f) as usize;
            if second_len != 0 && second_len <= remaining {
                table.pair[window as usize] =
                    entry | ((second & 0xff) << 13) | ((second_len as u32) << 21) | TWO_CODES;
            }
        }
        table
    })
}

/// Decodes one Huffman-coded string: the 257th entry is the EOS code rather than a symbol, so a block decoding one is malformed, and only the all-ones prefix under eight bits may follow the last symbol. The unread bits sit in one register, refilled a byte at a time, so a load of the 4096-entry pair table `huffman()` builds once beside the probe rows resolves one or two codes of `PEEK` bits or fewer — the whole ASCII range — and a miss hands the register's high bits to the same serial probe the pre-table decoder ran, for the 13..30-bit codes, without reading a byte for it.
pub fn huffman_decode(code: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let table = huffman();
    // The register is left-justified at the next unread bit, so consuming a symbol is one shift, and `held + 8 * (code.len() - cursor)` is the string's remaining bit count at every point of the walk.
    let mut held = 0u64;
    let mut bits = 0usize;
    let mut cursor = 0usize;
    'symbol: loop {
        while bits <= 56 && cursor < code.len() {
            held |= u64::from(code[cursor]) << (56 - bits);
            bits += 8;
            cursor += 1;
        }
        if bits < PEEK {
            break;
        }
        let entry = table.pair[(held >> (64 - PEEK)) as usize];
        let first = ((entry >> 8) & 0x1f) as usize;
        if first != 0 {
            out.push((entry & 0xff) as u8);
            let used = if entry & TWO_CODES != 0 {
                out.push(((entry >> 13) & 0xff) as u8);
                first + ((entry >> 21) & 0x1f) as usize
            } else {
                first
            };
            held <<= used;
            bits -= used;
            continue;
        }
        let mut length = PEEK;
        while length < bits && length < MAX_BITS {
            length += 1;
            let probe = table.probe[length];
            let acc = (held >> (64 - length)) as u32;
            let offset = acc.wrapping_sub((probe >> 32) as u32);
            if offset >= probe as u32 {
                continue;
            }
            let symbol = table.symbols[table.base[length] as usize + offset as usize];
            if symbol == 256 {
                return None;
            }
            out.push(symbol as u8);
            held <<= length;
            bits -= length;
            continue 'symbol;
        }
        return None;
    }
    let mut acc = 0u32;
    let mut length = 0usize;
    while bits > 0 {
        acc = (acc << 1) | (held >> 63) as u32;
        held <<= 1;
        bits -= 1;
        length += 1;
        let probe = table.probe[length];
        let offset = acc.wrapping_sub((probe >> 32) as u32);
        if offset < probe as u32 {
            let symbol = table.symbols[table.base[length] as usize + offset as usize];
            if symbol == 256 {
                return None;
            }
            out.push(symbol as u8);
            acc = 0;
            length = 0;
        }
    }
    if length != 0 && (length >= 8 || acc != (1 << length) - 1) {
        return None;
    }
    Some(())
}

/// Encodes one Huffman-coded string: each symbol's canonical code from the same table the decoder derives, written MSB-first, the last byte padded with the EOS prefix.
pub fn huffman_encode(bytes: &[u8], out: &mut Vec<u8>) {
    let table = huffman();
    let mut acc = 0u64;
    let mut bits = 0u32;
    for byte in bytes {
        let length = u32::from(HUFFMAN_BITS[usize::from(*byte)]);
        acc = (acc << length) | u64::from(table.codes[usize::from(*byte)]);
        bits += length;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits != 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
}

/// The octets one string's codes need, so an encoder can refuse Huffman without writing it first.
pub fn huffman_len(bytes: &[u8]) -> usize {
    let bits: usize = bytes
        .iter()
        .map(|byte| usize::from(HUFFMAN_BITS[usize::from(*byte)]))
        .sum();
    bits.div_ceil(8)
}

/// An integer in one byte carrying `prefix` low bits, continued in base-128.
pub fn integer(out: &mut Vec<u8>, prefix: u8, mask: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(mask | value as u8);
        return;
    }
    out.push(mask | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// The same integer as `integer`, continued into the byte the pattern already occupies — QPACK's one form for a field name, where that byte's low bits are the length prefix.
pub(crate) fn integer_into(out: &mut Vec<u8>, prefix: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    let slot = out.len() - 1;
    if value < max {
        out[slot] |= value as u8;
        return;
    }
    out[slot] |= max as u8;
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

fn read_integer(block: &[u8], at: &mut usize, prefix: u8) -> Option<usize> {
    let first = *block.get(*at)?;
    *at += 1;
    let max = (1usize << prefix) - 1;
    let mut value = usize::from(first & max as u8);
    if value < max {
        return Some(value);
    }
    let mut shift = 0u32;
    loop {
        let byte = *block.get(*at)?;
        *at += 1;
        if shift > 56 {
            return None;
        }
        value = value.checked_add(usize::from(byte & 0x7f).checked_shl(shift)?)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

/// One string literal, borrowed when stored as-is and owned when Huffman coded; that path allocates because a status is three digits and a name this lane reads is one short literal.
enum Literal<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Literal<'_> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    fn is_status(&self) -> bool {
        self.as_bytes() == b":status"
    }
}

fn string_literal<'a>(block: &'a [u8], at: &mut usize) -> Option<Literal<'a>> {
    let coded = *block.get(*at)? & 0x80 != 0;
    let len = read_integer(block, at, 7)?;
    let raw = block.get(*at..at.checked_add(len)?)?;
    *at += len;
    if !coded {
        return Some(Literal::Borrowed(raw));
    }
    let mut out = Vec::with_capacity(decoded_bound(len));
    huffman_decode(raw, &mut out)?;
    Some(Literal::Owned(out))
}

/// The HPACK static table's names, index-addressed from one: the request encoder names its field lines from here, so a line the edge's decoder expects lands as one byte of prefix.
const HPACK_NAME: [(&str, u16); 48] = [
    (":authority", 1),
    (":method", 2),
    (":path", 4),
    (":scheme", 6),
    ("accept", 19),
    ("accept-charset", 15),
    ("accept-encoding", 16),
    ("accept-language", 17),
    ("accept-ranges", 18),
    ("access-control-allow-origin", 20),
    ("age", 21),
    ("allow", 22),
    ("authorization", 23),
    ("cache-control", 24),
    ("content-disposition", 25),
    ("content-encoding", 26),
    ("content-language", 27),
    ("content-length", 28),
    ("content-location", 29),
    ("content-range", 30),
    ("content-type", 31),
    ("cookie", 32),
    ("date", 33),
    ("etag", 34),
    ("expect", 35),
    ("expires", 36),
    ("from", 37),
    ("host", 38),
    ("if-match", 39),
    ("if-modified-since", 40),
    ("if-none-match", 41),
    ("if-range", 42),
    ("if-unmodified-since", 43),
    ("last-modified", 44),
    ("link", 45),
    ("location", 46),
    ("max-forwards", 47),
    ("proxy-authenticate", 48),
    ("proxy-authorization", 49),
    ("range", 50),
    ("referer", 51),
    ("refresh", 52),
    ("retry-after", 53),
    ("server", 54),
    ("set-cookie", 55),
    ("strict-transport-security", 56),
    ("transfer-encoding", 57),
    ("user-agent", 58),
];

/// The static index of one field name, `None` when the name sits outside the table and a literal name is the honest encoding.
pub fn hpack_name(name: &str) -> Option<u16> {
    HPACK_NAME
        .binary_search_by(|(known, _)| (*known).cmp(name))
        .ok()
        .and_then(|slot| HPACK_NAME.get(slot).map(|(_, index)| *index))
}

/// The QPACK static table, index-addressed: the 99 name/value pairs every endpoint knows without dynamic state, so an indexed field line is two bytes.
const QPACK_STATIC: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

/// The `:status` entries of a static table, HPACK's from index 8 and QPACK's from the table above: an indexed entry is one integer with nothing following, so a field this lane never reads costs nothing to walk past.
fn static_status(index: usize, h2: bool) -> Option<u16> {
    if h2 {
        const H2: [u16; 7] = [200, 204, 206, 304, 400, 404, 500];
        return H2.get(index.checked_sub(8)?).copied();
    }
    let (name, value) = QPACK_STATIC.get(index)?;
    if *name != b":status" {
        return None;
    }
    status_of(value)
}

/// A three-digit decimal status, read in place rather than copied out.
fn status_of(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        u16::from(bytes[0] - b'0') * 100
            + u16::from(bytes[1] - b'0') * 10
            + u16::from(bytes[2] - b'0'),
    )
}

/// Reads an HPACK block's `:status`: an indexed entry is one integer, so any index outside the `:status` range is skipped; a literal is read only under a `:status` name; a dynamic size update carries no entry and is skipped, the lane keeping no dynamic table.
pub fn hpack_status(block: &[u8]) -> Option<u16> {
    let mut at = 0usize;
    let mut status = None;
    while at < block.len() {
        let first = block[at];
        if first & 0x80 != 0 {
            let index = read_integer(block, &mut at, 7)?;
            if let Some(code) = static_status(index, true) {
                status = Some(code);
            }
            continue;
        }
        if first & 0xC0 == 0x40 {
            let index = read_integer(block, &mut at, 6)?;
            let name_is_status = if index == 0 {
                string_literal(block, &mut at)?.is_status()
            } else {
                static_status(index, true).is_some()
            };
            let value = string_literal(block, &mut at)?;
            if name_is_status {
                status = Some(status_of(value.as_bytes())?);
            }
            continue;
        }
        if first & 0xE0 == 0x20 {
            read_integer(block, &mut at, 5)?;
            continue;
        }
        let index = read_integer(block, &mut at, 4)?;
        let name_is_status = if index == 0 {
            string_literal(block, &mut at)?.is_status()
        } else {
            static_status(index, true).is_some()
        };
        let value = string_literal(block, &mut at)?;
        if name_is_status {
            status = Some(status_of(value.as_bytes())?);
        }
    }
    status
}

/// Reads a QPACK block's `:status`: QPACK prefixes it with a required insert count and a delta base, and a block not prefixed by two zero bytes names a dynamic table this lane does not have.
pub fn qpack_status(block: &[u8]) -> Option<u16> {
    if *block.first()? != 0 || *block.get(1)? != 0 {
        return None;
    }
    let mut at = 2usize;
    let mut status = None;
    while at < block.len() {
        let first = block[at];
        let name_is_status = if first & 0x80 != 0 {
            let index = read_integer(block, &mut at, 6)?;
            // A field the lane does not read is walked past, the way the `h2` reader does: the status is what the block has, not the first line it met.
            if let Some(code) = static_status(index, false) {
                status = Some(code);
            }
            continue;
        } else if first & 0xC0 == 0x40 {
            // The `01` pattern, a literal line naming a field the static table holds: the edge's own answer names `:status` this way, and a reader that does not know the pattern cannot read a status the edge sent.
            if first & 0x10 == 0 {
                // The T bit clear names the dynamic table, which this lane never fills.
                return None;
            }
            let index = read_integer(block, &mut at, 4)?;
            static_name(index) == Some(b":status".as_slice())
        } else if first & 0xE0 == 0x20 {
            qpack_name(block, &mut at)?.is_status()
        } else {
            return None;
        };
        let value = string_literal(block, &mut at)?;
        if name_is_status {
            status = Some(status_of(value.as_bytes())?);
        }
    }
    status
}

/// A static table entry's name, which the `01` pattern names instead of spelling out: the entry's value is not read, only its name.
fn static_name(index: usize) -> Option<&'static [u8]> {
    QPACK_STATIC.get(index).map(|(name, _)| *name)
}

/// QPACK's literal field line packs the `001` pattern, the never-indexed bit, the name's Huffman bit and a three-bit name length into one byte, so the name is a prefixed integer read from that byte.
fn qpack_name<'a>(block: &'a [u8], at: &mut usize) -> Option<Literal<'a>> {
    let coded = *block.get(*at)? & 0x08 != 0;
    let len = read_integer(block, at, 3)?;
    let raw = block.get(*at..at.checked_add(len)?)?;
    *at += len;
    if !coded {
        return Some(Literal::Borrowed(raw));
    }
    let mut out = Vec::with_capacity(decoded_bound(len));
    huffman_decode(raw, &mut out)?;
    Some(Literal::Owned(out))
}

/// One QPACK literal field line: the `001` pattern, the name's three-bit length, the value's seven-bit length and nothing Huffman-coded. A value handed over in runs goes on the wire as one field with nothing joined first.
fn qpack_line(out: &mut Vec<u8>, name: &str, value: &[&[u8]]) {
    out.push(0x20);
    integer_into(out, 3, name.len());
    out.extend_from_slice(name.as_bytes());
    integer(out, 7, 0x00, value.iter().map(|run| run.len()).sum());
    for run in value {
        out.extend_from_slice(run);
    }
}

/// The bytes a prefixed integer costs: one for the octet holding what fits the prefix, then one per seven bits left over.
fn integer_len(prefix: u8, value: usize) -> usize {
    let max = (1usize << prefix) - 1;
    if value < max {
        return 1;
    }
    let mut rest = value - max;
    let mut len = 2;
    while rest >= 128 {
        rest >>= 7;
        len += 1;
    }
    len
}

/// The bytes a literal field line costs, so a block can be sized before it is written: the pattern octet shared with the name's length integer, the name, the value's length integer, the value.
#[must_use]
pub fn qpack_field_len(name: usize, value: usize) -> usize {
    integer_len(3, name) + name + integer_len(7, value) + value
}

/// The two zero bytes that open a QPACK field block: no dynamic state, no indexed name.
pub fn qpack_open(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00]);
}

/// One field of an open block, its value taken as bytes: a code written into a stack buffer needs no `String`, and a value that already is bytes needs no join.
pub fn qpack_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    qpack_line(out, name, &[value]);
}

/// Any request as literal field lines: two zero prefix bytes name no dynamic state, and each field is a `001` name length, name, value length and value run with no Huffman to compute.
pub fn qpack_literal_many(fields: &[(&str, &str)], out: &mut Vec<u8>) {
    qpack_open(out);
    for (name, value) in fields {
        qpack_field(out, name, value.as_bytes());
    }
}

/// Reads every field of a QPACK block whose references stay inside the static table — indexed lines, static name references, literal names Huffman-coded or not — and refuses anything naming dynamic state.
#[must_use]
pub fn qpack_fields(block: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    if *block.first()? != 0 || *block.get(1)? != 0 {
        return None;
    }
    let mut at = 2usize;
    let mut fields = Vec::new();
    while at < block.len() {
        let first = block[at];
        if first & 0x80 != 0 {
            let index = read_integer(block, &mut at, 6)?;
            let (name, value) = QPACK_STATIC.get(index)?;
            fields.push((name.to_vec(), value.to_vec()));
        } else if first & 0xC0 == 0x40 {
            if first & 0x10 == 0 {
                // The T bit clear names the dynamic table, which this lane never fills. The N bit beside it is a hint about a later hop's table and says nothing about this one.
                return None;
            }
            let index = read_integer(block, &mut at, 4)?;
            let (name, _) = QPACK_STATIC.get(index)?;
            let value = string_literal(block, &mut at)?;
            fields.push((name.to_vec(), value.as_bytes().to_vec()));
        } else if first & 0xE0 == 0x20 {
            let name = qpack_name(block, &mut at)?;
            let value = string_literal(block, &mut at)?;
            fields.push((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        } else {
            return None;
        }
    }
    Some(fields)
}

/// One CONNECT request, three fields, literal names and values: the smallest header block a CONNECT can be written in, with the `Bearer` scheme the edge answers — a bare token is a 400.
pub fn hpack_connect(target: &str, bearer: &str, out: &mut Vec<u8>) {
    for (name, value) in [(":method", "CONNECT"), (":authority", target)] {
        out.push(0x00);
        integer(out, 7, 0x00, name.len());
        out.extend_from_slice(name.as_bytes());
        integer(out, 7, 0x00, value.len());
        out.extend_from_slice(value.as_bytes());
    }
    let name = "proxy-authorization";
    out.push(0x00);
    integer(out, 7, 0x00, name.len());
    out.extend_from_slice(name.as_bytes());
    integer(out, 7, 0x00, "Bearer ".len() + bearer.len());
    out.extend_from_slice(b"Bearer ");
    out.extend_from_slice(bearer.as_bytes());
}

/// The same three fields under QPACK: a required insert count of zero, fields named with the `001` literal pattern, and the scheme the edge answers written ahead of the token rather than joined onto it, since a bare token is a 400.
pub fn qpack_connect(target: &str, bearer: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00]);
    qpack_line(out, ":method", &[b"CONNECT"]);
    qpack_line(out, ":authority", &[target.as_bytes()]);
    qpack_line(out, "proxy-authorization", &[b"Bearer ", bearer.as_bytes()]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One QPACK literal field line, written the way a peer would write it.
    fn qpack_literal_coded(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        if block.is_empty() {
            block.extend_from_slice(&[0x00, 0x00]);
        }
        block.push(0x20);
        integer_into(block, 3, name.len());
        block.extend_from_slice(name.as_bytes());
        block.push(0x80 | value.len() as u8);
        block.extend_from_slice(value);
    }

    fn qpack_literal(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        if block.is_empty() {
            block.extend_from_slice(&[0x00, 0x00]);
        }
        block.push(0x20);
        integer_into(block, 3, name.len());
        block.extend_from_slice(name.as_bytes());
        integer(block, 7, 0x00, value.len());
        block.extend_from_slice(value);
    }

    /// One HPACK literal field line with a literal name, the form this lane writes.
    fn hpack_literal(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        block.push(0x00);
        integer(block, 7, 0x00, name.len());
        block.extend_from_slice(name.as_bytes());
        integer(block, 7, 0x00, value.len());
        block.extend_from_slice(value);
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|byte| (byte as char).to_digit(16).expect("hex") as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    #[test]
    fn the_rfc7541_huffman_examples_decode_to_their_plain_text() {
        for (encoded, plain) in [
            ("f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"),
            ("a8eb10649cbf", "no-cache"),
            ("25a849e95ba97d7f", "custom-key"),
            ("25a849e95bb8e8b4bf", "custom-value"),
            ("90692f", "date"),
        ] {
            let raw = hex(encoded);
            let mut out = Vec::new();
            huffman_decode(&raw, &mut out).expect("decodes");
            assert_eq!(out, plain.as_bytes(), "{encoded}");
        }
    }

    /// The decode's own cost, with no socket, allocation or fixture in the frame: one coded host string, decoded 64 times into a buffer that is allocated once and cleared each turn, folded after every pass so the probe cannot pass by having stopped running. `scripts/method-ops.txt` points the `huffman_decode` row at it.
    #[test]
    fn the_huffman_probe_costs_the_decode_and_nothing_else() {
        let coded = hex("f1e3c2e5f23a6ba0ab90f4ff");
        let mut out = Vec::with_capacity(coded.len());
        let mut fold: u32 = 0;
        for _ in 0..64 {
            out.clear();
            huffman_decode(&coded, &mut out).expect("decodes");
            for &byte in &out {
                fold = fold.wrapping_mul(31).wrapping_add(u32::from(byte));
            }
        }
        assert_eq!(out, b"www.example.com".as_slice());
        assert_eq!(
            fold, 0xff9c_e800,
            "64 decodes of one coded host string, folded after each"
        );
    }

    #[test]
    fn encoding_huffman_reproduces_the_rfc7541_appendix_c_bit_strings() {
        for (plain, encoded) in [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-key", "25a849e95ba97d7f"),
            ("custom-value", "25a849e95bb8e8b4bf"),
            ("date", "90692f"),
            ("", ""),
        ] {
            let mut out = Vec::new();
            huffman_encode(plain.as_bytes(), &mut out);
            assert_eq!(out, hex(encoded), "{plain}");
        }
    }

    #[test]
    fn every_symbol_round_trips_through_the_canonical_table() {
        let all: Vec<u8> = (0..=255u8).collect();
        let mut coded = Vec::new();
        huffman_encode(&all, &mut coded);
        let mut back = Vec::new();
        huffman_decode(&coded, &mut back).expect("decodes");
        assert_eq!(back, all);
        assert_eq!(huffman_decode(&[], &mut Vec::new()), Some(()));
    }

    #[test]
    fn every_symbol_decodes_to_itself_one_at_a_time() {
        for symbol in 0..=255usize {
            let mut coded = Vec::new();
            let byte = symbol as u8;
            huffman_encode(&[byte], &mut coded);
            let mut out = Vec::new();
            huffman_decode(&coded, &mut out).expect("decodes");
            assert_eq!(out, vec![byte], "symbol {symbol}");
        }
    }

    /// The bit-serial decode exactly as it stood, kept as the oracle the table decoder must answer with the same verdict and the same partial output on every case.
    fn huffman_decode_serial(code: &[u8], out: &mut Vec<u8>) -> Option<()> {
        let table = huffman();
        let mut acc = 0u32;
        let mut bits = 0usize;
        for byte in code {
            for shift in (0..8).rev() {
                acc = (acc << 1) | u32::from(byte >> shift & 1);
                bits += 1;
                if bits > MAX_BITS {
                    return None;
                }
                let probe = table.probe[bits];
                let offset = acc.wrapping_sub((probe >> 32) as u32);
                if offset >= probe as u32 {
                    continue;
                }
                let symbol = table.symbols[table.base[bits] as usize + offset as usize];
                if symbol == 256 {
                    return None;
                }
                out.push(symbol as u8);
                acc = 0;
                bits = 0;
            }
        }
        if bits != 0 && (bits >= 8 || acc != (1 << bits) - 1) {
            return None;
        }
        Some(())
    }

    #[test]
    fn the_pair_window_resolves_one_or_two_short_codes() {
        let table = huffman();
        for window in 0..(1u32 << PEEK) {
            let mut expected = Vec::new();
            let mut at = 0usize;
            while PEEK - at >= SHORTEST {
                let remaining = PEEK - at;
                let mut hit = None;
                for bits in SHORTEST..=remaining {
                    let probe = table.probe[bits];
                    let acc = ((window >> (PEEK - at - bits)) & ((1u32 << bits) - 1)) as u32;
                    let offset = acc.wrapping_sub((probe >> 32) as u32);
                    if offset < probe as u32 {
                        let symbol =
                            table.symbols[table.base[bits] as usize + offset as usize] as u32;
                        hit = Some((symbol, bits));
                        break;
                    }
                }
                let Some((symbol, bits)) = hit else { break };
                expected.push((symbol, bits));
                at += bits;
            }
            let entry = table.pair[window as usize];
            let mut got = Vec::new();
            let first = ((entry >> 8) & 0x1f) as usize;
            if first != 0 {
                got.push((entry & 0xff, first));
                if entry & TWO_CODES != 0 {
                    got.push(((entry >> 13) & 0xff, ((entry >> 21) & 0x1f) as usize));
                }
            }
            assert_eq!(got, expected, "window {window}");
        }
    }

    #[test]
    fn the_table_decode_matches_the_serial_probe_on_every_case() {
        let mut cases: Vec<Vec<u8>> = vec![vec![]];
        for a in 0..=255u8 {
            cases.push(vec![a]);
            for b in 0..=255u8 {
                cases.push(vec![a, b]);
            }
        }
        let all: Vec<u8> = (0..=255u8).collect();
        let mut coded = Vec::new();
        huffman_encode(&all, &mut coded);
        for cut in 0..=coded.len() {
            cases.push(coded[..cut].to_vec());
        }
        let mut base = Vec::new();
        huffman_encode(b"200", &mut base);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let mut case = base.clone();
                case.extend_from_slice(&[a, b]);
                cases.push(case);
            }
        }
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        };
        for _ in 0..20_000 {
            let len = 1 + usize::from(next()) % 20;
            cases.push((0..len).map(|_| next()).collect());
        }
        let high = [0u8, 10, 14, 255, b'a', b'z', b'0', b'.', b'%'];
        for _ in 0..10_000 {
            let len = 1 + usize::from(next()) % 12;
            let text: Vec<u8> = (0..len)
                .map(|_| high[usize::from(next()) % high.len()])
                .collect();
            let mut enc = Vec::new();
            huffman_encode(&text, &mut enc);
            cases.push(enc);
        }
        for case in &cases {
            let mut fast = Vec::new();
            let mut serial = Vec::new();
            let got = huffman_decode(case, &mut fast);
            let was = huffman_decode_serial(case, &mut serial);
            assert_eq!(got.is_some(), was.is_some(), "verdict for {case:?}");
            assert_eq!(fast, serial, "output for {case:?}");
        }
    }

    #[test]
    fn the_fused_probe_holds_the_canonical_first_and_count_of_every_length() {
        // An independent canonical walk off the code lengths is the second source the fused probe is checked against, not itself.
        let table = huffman();
        let mut histogram = [0u32; MAX_BITS + 1];
        for &length in &HUFFMAN_BITS {
            histogram[usize::from(length)] += 1;
        }
        let mut code = 0i64;
        let mut previous = 0usize;
        let walked = table
            .probe
            .iter()
            .zip(&histogram)
            .enumerate()
            .skip(SHORTEST);
        for (bits, (&probe, &count)) in walked {
            code <<= bits - previous;
            previous = bits;
            // A length with no codes keeps the table's zero default, as the build skips it; only a populated length is checked.
            if count == 0 {
                continue;
            }
            assert_eq!(
                probe >> 32,
                u64::from(code as u32),
                "first of length {bits}"
            );
            assert_eq!(probe as u32, count, "count of length {bits}");
            code += i64::from(count);
        }
    }

    #[test]
    fn the_rebuilt_table_is_the_rfc_table_code_for_code() {
        for (symbol, expected) in [
            (0usize, (8184, 13)),
            (32, (20, 6)),
            (37, (21, 6)),
            (46, (23, 6)),
            (48, (0, 5)),
            (49, (1, 5)),
            (50, (2, 5)),
            (58, (92, 7)),
            (63, (1020, 10)),
            (97, (3, 5)),
            (98, (35, 6)),
            (124, (2044, 11)),
            (255, (67_108_846, 26)),
            (256, (1_073_741_823, 30)),
        ] {
            assert_eq!(
                (huffman().codes[symbol], usize::from(HUFFMAN_BITS[symbol])),
                expected,
                "symbol {symbol}"
            );
        }
    }

    #[test]
    fn an_eos_code_inside_a_string_is_refused_and_padding_is_not() {
        let mut coded = Vec::new();
        huffman_encode(b"200", &mut coded);
        assert!(huffman_decode(&coded, &mut Vec::new()).is_some());
        assert!(
            huffman_decode(&[0xff], &mut Vec::new()).is_none(),
            "eight bits of padding"
        );
        let eos = [0xff, 0xff, 0xff, 0xff];
        assert!(
            huffman_decode(&eos, &mut Vec::new()).is_none(),
            "an EOS symbol"
        );
        assert!(
            huffman_decode(&[0x90], &mut Vec::new()).is_none(),
            "half a symbol"
        );
        let padded = [0x90, 0x69];
        let mut out = Vec::new();
        assert!(
            huffman_decode(&padded, &mut out).is_some(),
            "padding is allowed"
        );
        assert_eq!(out, b"dat");
    }

    /// A coded literal is a `len`-byte window holding at most `8 * len / SHORTEST` symbols, so a buffer sized to `len` overflows on any literal denser than eight bits a symbol and pays a reallocation plus a copy of what it already wrote.
    #[test]
    fn a_coded_literal_is_decoded_into_one_allocation() {
        let decode = |value: &str| {
            let mut coded = Vec::new();
            huffman_encode(value.as_bytes(), &mut coded);
            let mut block = vec![0x80 | coded.len() as u8];
            block.extend_from_slice(&coded);
            let mut at = 0usize;
            let literal = string_literal(&block, &mut at).expect("a coded literal");
            assert_eq!(literal.as_bytes(), value.as_bytes());
            assert_eq!(at, block.len(), "the whole literal is spent");
            match literal {
                Literal::Owned(bytes) => (bytes.capacity(), coded.len()),
                Literal::Borrowed(_) => unreachable!("the H bit named a coded literal"),
            }
        };
        // The table's one-time build allocates, so the window opens only after a decode has already run.
        decode("200");
        for value in ["200", "12345678", "gzip", "a", "www.cloudflare.com"] {
            let (capacity, coded) = decode(value);
            assert_eq!(
                capacity,
                8 * coded / SHORTEST,
                "{value}: the buffer is the symbol bound of its {coded} bytes"
            );
            assert!(
                capacity >= value.len(),
                "{value}: the bound still holds the string it decodes to"
            );
        }
        let mut coded = Vec::new();
        huffman_encode(b"200", &mut coded);
        let mut block = vec![0x80 | coded.len() as u8];
        block.extend_from_slice(&coded);
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..4096 {
                let mut at = 0usize;
                std::hint::black_box(string_literal(std::hint::black_box(&block), &mut at));
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (4096, 4096 * 3, 0),
            "4096 coded statuses take one buffer each and no growth"
        );
    }

    #[test]
    fn the_integer_prefix_spans_its_own_boundary() {
        for prefix in [4u8, 5, 6, 7] {
            for value in [
                0usize, 1, 14, 15, 16, 30, 31, 32, 126, 127, 128, 129, 1_000, 70_000,
            ] {
                let mut out = Vec::new();
                integer(&mut out, prefix, 0x00, value);
                let mut at = 0;
                assert_eq!(
                    read_integer(&out, &mut at, prefix),
                    Some(value),
                    "{prefix}/{value}"
                );
                assert_eq!(at, out.len());
            }
        }
    }

    #[test]
    fn a_truncated_or_oversized_integer_is_refused() {
        assert_eq!(read_integer(&[0x7e], &mut 0, 7), Some(126));
        assert_eq!(read_integer(&[0x7f, 0x00], &mut 0, 7), Some(127));
        assert_eq!(read_integer(&[0xff], &mut 0, 7), None);
        assert_eq!(read_integer(&[0xff, 0x80], &mut 0, 7), None);
        assert_eq!(read_integer(&[0xff; 12], &mut 0, 7), None);
        assert_eq!(read_integer(&[0x7f, 0xff], &mut 0, 7), None);
    }

    #[test]
    fn a_literal_status_of_three_digits_is_read_in_both_codecs() {
        let mut h2 = Vec::new();
        hpack_literal(&mut h2, ":status", b"200");
        assert_eq!(hpack_status(&h2), Some(200));
        let mut q3 = Vec::new();
        qpack_literal(&mut q3, ":status", b"200");
        assert_eq!(qpack_status(&q3), Some(200));
    }

    #[test]
    fn an_indexed_status_is_read_from_both_static_tables() {
        for (index, want) in [
            (8usize, 200u16),
            (9, 204),
            (10, 206),
            (11, 304),
            (12, 400),
            (13, 404),
            (14, 500),
        ] {
            let mut h2 = Vec::new();
            integer(&mut h2, 7, 0x80, index);
            assert_eq!(hpack_status(&h2), Some(want), "hpack {index}");
            if index == 8 {
                let mut literal = vec![0x40];
                integer_into(&mut literal, 6, index);
                integer(&mut literal, 7, 0x00, 3);
                literal.extend_from_slice(b"200");
                assert_eq!(hpack_status(&literal), Some(200), "a literal status");
            }
        }
        for (index, want) in [
            (24usize, 103u16),
            (25, 200),
            (26, 304),
            (27, 404),
            (28, 503),
            (63, 100),
            (64, 204),
            (71, 500),
        ] {
            let mut q3 = vec![0x00, 0x00];
            integer(&mut q3, 6, 0xC0, index);
            assert_eq!(qpack_status(&q3), Some(want), "qpack {index}");
        }
        for index in [15usize, 20, 22, 23, 29, 62, 72, 98, 99, 200] {
            let mut q3 = vec![0x00, 0x00];
            integer(&mut q3, 6, 0xC0, index);
            assert_eq!(qpack_status(&q3), None, "not a status: {index}");
        }
    }

    #[test]
    fn a_huffman_coded_status_is_read() {
        let mut value = Vec::new();
        huffman_encode(b"200", &mut value);
        let mut block = vec![0x40];
        integer_into(&mut block, 6, 8);
        block.push(0x80 | value.len() as u8);
        block.extend_from_slice(&value);
        assert_eq!(hpack_status(&block), Some(200));
        let mut q3_coded = Vec::new();
        qpack_literal_coded(&mut q3_coded, ":status", &value);
        assert_eq!(qpack_status(&q3_coded), Some(200), "a huffman status");
        let mut q3_raw = Vec::new();
        qpack_literal(&mut q3_raw, ":status", b"200");
        assert_eq!(qpack_status(&q3_raw), Some(200), "a literal status");
    }

    #[test]
    fn a_status_that_is_not_three_digits_is_refused() {
        for text in ["", "2", "20", "2000", "abc", "2 0", "++"] {
            let mut block = Vec::new();
            hpack_literal(&mut block, ":status", text.as_bytes());
            assert_eq!(hpack_status(&block), None, "{text:?}");
        }
    }

    #[test]
    fn a_block_with_no_status_in_it_yields_none() {
        assert_eq!(hpack_status(&[0x3f, 0xe1, 0x1f]), None, "a size update");
        assert_eq!(
            hpack_status(&[0x0f, 0x61, 0x62, 0x63]),
            None,
            "an unindexed name"
        );
        assert_eq!(
            hpack_status(&[0xff, 0x02, 0x00, 0x40]),
            None,
            "a table index"
        );
        assert_eq!(
            hpack_status(&[0x3f, 0xe1, 0x1f, 0x82]),
            None,
            "a size update first"
        );
        assert_eq!(
            qpack_status(&[0x01, 0x00, 0xC0, 0x01]),
            None,
            "a dynamic insert count"
        );
        assert_eq!(qpack_status(&[0x00]), None, "a truncated prefix");
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x40, 0x01]),
            None,
            "a name reference"
        );
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x30, 0x00]),
            None,
            "a post-base index"
        );
    }

    #[test]
    fn an_encoder_beyond_the_minimal_one_still_yields_its_status() {
        // A size update, an unread indexed field, a literal with incremental indexing naming one, then the indexed status.
        let mut block = vec![0x3f, 0xe1, 0x1f, 0x80 | 0x21];
        block.push(0x40);
        integer_into(&mut block, 6, 33);
        integer(&mut block, 7, 0x00, 1);
        block.extend_from_slice(b"x");
        block.push(0x88);
        assert_eq!(hpack_status(&block), Some(200));
        // The same status as a literal under its indexed name, with a literal date first: the name decides, not the representation.
        let mut named = vec![0x00];
        integer(&mut named, 7, 0x00, 4);
        named.extend_from_slice(b"date");
        integer(&mut named, 7, 0x00, 1);
        named.extend_from_slice(b"x");
        named.push(0x40);
        integer_into(&mut named, 6, 13);
        integer(&mut named, 7, 0x00, 3);
        named.extend_from_slice(b"404");
        assert_eq!(hpack_status(&named), Some(404));
    }

    #[test]
    fn a_field_this_lane_does_not_read_is_skipped_not_refused() {
        let mut block = Vec::new();
        for (name, value) in [("date", "x"), (":status", "200"), ("server", "edge")] {
            hpack_literal(&mut block, name, value.as_bytes());
        }
        assert_eq!(hpack_status(&block), Some(200));
        let mut q3 = Vec::new();
        for (name, value) in [("date", "x"), (":status", "404"), ("server", "edge")] {
            qpack_literal(&mut q3, name, value.as_bytes());
        }
        assert_eq!(qpack_status(&q3), Some(404));
    }

    #[test]
    fn the_qpack_static_table_holds_99_indexed_entries() {
        assert_eq!(QPACK_STATIC.len(), 99);
        for (index, name, value) in [
            (0usize, ":authority", ""),
            (1, ":path", "/"),
            (15, ":method", "CONNECT"),
            (20, ":method", "POST"),
            (22, ":scheme", "http"),
            (23, ":scheme", "https"),
            (24, ":status", "103"),
            (25, ":status", "200"),
            (28, ":status", "503"),
            (63, ":status", "100"),
            (71, ":status", "500"),
            (84, "authorization", ""),
            (98, "x-frame-options", "sameorigin"),
        ] {
            assert_eq!(
                QPACK_STATIC[index],
                (name.as_bytes(), value.as_bytes()),
                "index {index}"
            );
        }
    }

    #[test]
    fn qpack_fields_reads_indexed_named_and_coded_lines() {
        let mut block = Vec::new();
        qpack_literal_many(
            &[(":method", "POST"), ("hysteria-auth", "s3cret")],
            &mut block,
        );
        block.push(0x80 | 0x17);
        // A static name reference to `:status` (index 24), which the four-bit prefix does not hold, so the index continues in the byte after it.
        block.extend_from_slice(&[0x5F, 0x09, 0x03, b'2', b'3', b'3']);
        assert_eq!(
            qpack_fields(&block),
            Some(vec![
                (b":method".to_vec(), b"POST".to_vec()),
                (b"hysteria-auth".to_vec(), b"s3cret".to_vec()),
                (b":scheme".to_vec(), b"https".to_vec()),
                (b":status".to_vec(), b"233".to_vec()),
            ])
        );
        let mut coded = Vec::new();
        huffman_encode(b"gzip", &mut coded);
        let mut huffed = vec![0x00, 0x00, 0x20];
        integer_into(&mut huffed, 3, 7);
        huffed.extend_from_slice(b":status");
        huffed.push(0x80 | coded.len() as u8);
        huffed.extend_from_slice(&coded);
        assert_eq!(
            qpack_fields(&huffed),
            Some(vec![(b":status".to_vec(), b"gzip".to_vec())])
        );
    }

    #[test]
    fn qpack_fields_refuses_anything_naming_dynamic_state() {
        assert_eq!(qpack_fields(&[]), None);
        assert_eq!(qpack_fields(&[0x01, 0x00]), None);
        assert_eq!(qpack_fields(&[0x00, 0x00, 0x60, 0x00]), None);
        // `0x10` is the `0001` form, an indexed field line with a post-base index; the `0000N` form is a block whose prefix byte is `0x00`.
        assert_eq!(qpack_fields(&[0x00, 0x00, 0x10]), None);
        assert_eq!(qpack_fields(&[0x00, 0x00, 0x00]), None);
    }

    /// An indexed line the lane does not read is walked past, not refused: a response that names its status and then `date` (`static` index 6) has a readable status, and the reader keeps whichever status the block carried.
    #[test]
    fn a_field_the_h3_lane_does_not_read_is_skipped_not_refused() {
        assert_eq!(qpack_status(&[0x00, 0x00, 0x99]), Some(200));
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x99, 0x86]),
            Some(200),
            "the status survives an indexed `date` behind it"
        );
    }

    /// The edge's own answer, taken off a live h3 lane: it names its status with the `01` pattern and a static name index, so a reader that does not know the pattern cannot read a status the edge sent. The block is the one the live lane refused, byte for byte.
    #[test]
    fn the_status_the_edge_sent_with_a_static_name_reference_is_read() {
        let block = hex(
            "0000 5f09 826c 0254 0232 352f 02ae c3f9 f4b2 1234 da8f 9cc2 3426 8f5f 6a16 cb0f 6412\
             1509 3543 498f 5446 ae2a ec3c e68c c92c 9f5f 1d92 497c a58a e819 aafb 5093 8ec4 1530\
             5a99 567b 2f02 f2b2 0b67 72c8 b47e bf8f 20c9 3956 2f8b 16ea 5f16 05d6 8006 d9",
        );
        assert_eq!(
            qpack_status(&block),
            Some(502),
            "the status the edge sent, read out of a name reference"
        );
        let fields = qpack_fields(&block).expect("the block reads");
        assert_eq!(fields[0], (b":status".to_vec(), b"502".to_vec()));
    }

    /// A name reference into the static table, with the never-indexed bit set, is the same line: the bit beside the T bit is a hint about a later hop's table and says nothing about this one.
    #[test]
    fn a_static_name_reference_reads_whether_or_not_the_never_indexed_bit_is_set() {
        for never in [0x00u8, 0x20] {
            let mut block = vec![0x00, 0x00];
            // The `01` pattern with the T bit set: the name index is a four-bit integer, and `:status` sits past what four bits hold, so the index continues in the byte after it.
            integer(&mut block, 4, 0x40 | 0x10 | never, 24);
            block.extend_from_slice(&[0x03, b'2', b'0', b'0']);
            assert_eq!(
                qpack_status(&block),
                Some(200),
                "a static name reference with the never-indexed bit at {never:#04x}"
            );
        }
    }

    /// How many of RFC 9204 §4.5's five field-line forms the status reader understands, one
    /// block per form: three read, the two post-base forms refused by their own names —
    /// a block that names a dynamic table this lane never fills. The row in
    /// `scripts/method-counts.txt` is this number, read here rather than written down.
    #[test]
    fn the_status_reader_understands_every_pattern_the_edge_may_send() {
        // The `1T` pattern, an indexed line: the status is the table entry's own value.
        let mut indexed = vec![0x00, 0x00];
        integer(&mut indexed, 6, 0x80, 25);
        // The `01NT` pattern, a literal line naming the field in the static table.
        let mut named = vec![0x00, 0x00];
        integer(&mut named, 4, 0x40 | 0x10, 24);
        named.extend_from_slice(&[0x03, b'2', b'0', b'0']);
        // The `001NH` pattern, a literal line spelling the name out.
        let mut spelled = vec![0x00, 0x00, 0x20];
        integer_into(&mut spelled, 3, 7);
        spelled.extend_from_slice(b":status");
        spelled.push(0x03);
        spelled.extend_from_slice(b"200");
        for (name, block) in [
            ("the indexed pattern", indexed),
            ("the static name reference", named),
            ("the literal name", spelled),
        ] {
            assert_eq!(qpack_status(&block), Some(200), "{name}");
        }
        // The `0001` form, an indexed field line with a post-base index, and the `0000N` form, a literal with a post-base name reference: both name the dynamic table this lane never fills, so they are refused, a status it cannot know is not a status it should guess.
        assert_eq!(qpack_status(&[0x00, 0x00, 0x10]), None, "a post-base index");
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x00, 0x03, b'2', b'0', b'0']),
            None,
            "a post-base name reference"
        );
    }

    #[test]
    fn a_literal_request_encodes_the_connect_form() {
        let mut many = Vec::new();
        qpack_literal_many(
            &[
                (":method", "CONNECT"),
                (":authority", "example.com:443"),
                ("proxy-authorization", "Bearer p"),
            ],
            &mut many,
        );
        let mut one = Vec::new();
        qpack_connect("example.com:443", "p", &mut one);
        assert_eq!(many, one);
        assert_eq!(
            qpack_fields(&many).expect("reads").len(),
            3,
            "three literal fields"
        );
    }
    #[test]
    fn a_connect_block_is_the_smallest_literal_form_and_holds_the_bearer() {
        let mut h2 = Vec::new();
        hpack_connect("example.com:443", "p", &mut h2);
        let mut q3 = Vec::new();
        qpack_connect("example.com:443", "p", &mut q3);
        assert_eq!(h2, hex("00073a6d 6574686f 6407434f 4e4e4543 54000a3a 61757468 6f726974 790f6578 616d706c 652e636f 6d3a3434 33001370 726f7879 2d617574 686f7269 7a617469 6f6e0842 65617265 722070"));
        assert_eq!(q3, hex("00002700 3a6d6574 686f6407 434f4e4e 45435427 033a6175 74686f72 6974790f 6578616d 706c652e 636f6d3a 34343327 0c70726f 78792d61 7574686f 72697a61 74696f6e 08426561 72657220 70"));
        assert_eq!((h2.len(), q3.len()), (75, 77));
    }

    /// A CONNECT block used to `format!` the bearer scheme onto the token before writing it, so every h3 lane open paid a `String` and a copy of the token to write one field the encoder can put on the wire in two runs.
    #[test]
    fn a_connect_block_is_written_without_touching_the_heap() {
        let mid = "t".repeat(120);
        let over = "t".repeat(121);
        let long = "t".repeat(300);
        for token in ["", "p", mid.as_str(), over.as_str(), long.as_str()] {
            let joined_value = format!("Bearer {token}");
            let mut joined = Vec::new();
            qpack_literal_many(
                &[
                    (":method", "CONNECT"),
                    (":authority", "example.com:443"),
                    ("proxy-authorization", joined_value.as_str()),
                ],
                &mut joined,
            );
            let mut split = Vec::new();
            qpack_connect("example.com:443", token, &mut split);
            assert_eq!(joined, split, "two runs write what one joined value wrote");
        }
        let mut out = Vec::with_capacity(192);
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..4096 {
                out.clear();
                qpack_connect(
                    std::hint::black_box("example.com:443"),
                    std::hint::black_box("the-pass-which-is-long-enough"),
                    &mut out,
                );
                std::hint::black_box(&out);
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 CONNECT blocks take no heap: the caller's buffer holds the block and nothing is joined first"
        );
        assert_eq!(out.capacity(), 192, "the caller's buffer never grew");
    }

    #[test]
    fn a_long_name_length_spans_the_three_bit_qpack_prefix() {
        let name = "x".repeat(40);
        let mut q3 = Vec::new();
        qpack_literal(&mut q3, &name, b"");
        assert_eq!(qpack_status(&q3), None, "not a status field");
        let mut h2 = Vec::new();
        hpack_literal(&mut h2, &name, b"");
        assert_eq!(hpack_status(&h2), None, "not a status field");
    }
}
