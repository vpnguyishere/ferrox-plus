use std::fmt::Write as _;

use ferrox_core::b64;

use crate::framing::{timed_row_at, Row};

/// The row's claim: the shipped coder is no slower than the loop it replaced, so a first reading under parity is re-measured before it can fail.
pub(crate) const PARITY: f64 = 1.0;

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn digit_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut byte = b'A';
    while byte <= b'Z' {
        table[byte as usize] = byte - b'A';
        byte += 1;
    }
    byte = b'a';
    while byte <= b'z' {
        table[byte as usize] = byte - b'a' + 26;
        byte += 1;
    }
    byte = b'0';
    while byte <= b'9' {
        table[byte as usize] = byte - b'0' + 52;
        byte += 1;
    }
    table[b'+' as usize] = 62;
    table[b'-' as usize] = 62;
    table[b'/' as usize] = 63;
    table[b'_' as usize] = 63;
    table
}

const DIGITS: [u8; 256] = digit_table();

fn group_word(group: [u8; 4]) -> Option<[u8; 3]> {
    let t0 = u32::from(DIGITS[usize::from(group[0])]);
    let t1 = u32::from(DIGITS[usize::from(group[1])]);
    let t2 = u32::from(DIGITS[usize::from(group[2])]);
    let t3 = u32::from(DIGITS[usize::from(group[3])]);
    if (t0 | t1 | t2 | t3) & 0xc0 != 0 {
        return None;
    }
    let word = (t0 << 18) | (t1 << 12) | (t2 << 6) | t3;
    let bytes = word.to_be_bytes();
    Some([bytes[1], bytes[2], bytes[3]])
}

fn group_tail(rest: &[u8]) -> Option<[u8; 3]> {
    let mut word = 0u32;
    for &byte in rest {
        let digit = DIGITS[usize::from(byte)];
        if digit == 255 {
            return None;
        }
        word = (word << 6) | u32::from(digit);
    }
    word <<= 6 * (4 - rest.len());
    let bytes = word.to_be_bytes();
    Some([bytes[1], bytes[2], bytes[3]])
}

fn encode_reference(bytes: &[u8]) -> String {
    let len = b64::encoded_len(bytes.len());
    let mut out = Vec::<u8>::with_capacity(len);
    let ptr = out.as_mut_ptr();
    let (whole, rest) = bytes.as_chunks::<3>();
    let mut at = 0usize;
    for [a, b, c] in whole {
        let word = u32::from_be_bytes([0, *a, *b, *c]);
        unsafe {
            ptr.add(at).write(STD[(word >> 18 & 63) as usize]);
            ptr.add(at + 1).write(STD[(word >> 12 & 63) as usize]);
            ptr.add(at + 2).write(STD[(word >> 6 & 63) as usize]);
            ptr.add(at + 3).write(STD[(word & 63) as usize]);
        }
        at += 4;
    }
    if !rest.is_empty() {
        let mut word = 0u32;
        for byte in rest {
            word = (word << 8) | u32::from(*byte);
        }
        word <<= 8 * (3 - rest.len());
        unsafe {
            ptr.add(at).write(STD[(word >> 18 & 63) as usize]);
            ptr.add(at + 1).write(STD[(word >> 12 & 63) as usize]);
            ptr.add(at + 2).write(if rest.len() > 1 {
                STD[(word >> 6 & 63) as usize]
            } else {
                b'='
            });
            ptr.add(at + 3).write(b'=');
        }
        at += 4;
    }
    debug_assert_eq!(at, len);
    unsafe {
        out.set_len(len);
        String::from_utf8_unchecked(out)
    }
}

fn decode_reference(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut at = 0usize;
    while at + 4 <= text.len() {
        let Some(bytes) = group_word([text[at], text[at + 1], text[at + 2], text[at + 3]]) else {
            break;
        };
        out.extend_from_slice(&bytes);
        at += 4;
    }
    if at == text.len() {
        return (!out.is_empty()).then_some(out);
    }
    let mut group = [0u8; 4];
    let mut held = 0usize;
    let mut saw = false;
    for &byte in &text[at..] {
        if byte == b'=' {
            break;
        }
        if byte.is_ascii_whitespace() {
            continue;
        }
        group[held] = byte;
        held += 1;
        saw = true;
        if held == 4 {
            out.extend_from_slice(&group_word(group)?);
            held = 0;
        }
    }
    if held == 1 {
        return None;
    }
    if held != 0 {
        out.extend_from_slice(&group_tail(&group[..held])?[..held - 1]);
    }
    if out.is_empty() && !saw {
        return None;
    }
    Some(out)
}

fn iters_for(len: usize) -> u64 {
    (64 * 1024 * 1024 / len.max(1) as u64).clamp(256, 2_000_000)
}

pub(crate) fn gate_b64() -> Vec<Row> {
    let mut rows = Vec::new();
    for len in [12usize, 64, 256, 1024, 8192] {
        let raw: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
        let coded = b64::encode(&raw);
        assert_eq!(coded, encode_reference(&raw), "encode {len}");
        assert_eq!(
            b64::decode(coded.as_bytes()),
            decode_reference(coded.as_bytes()),
            "decode {len}"
        );
        let iters = iters_for(len);
        rows.push(timed_row_at(
            format!("b64 encode, {len}B"),
            len,
            iters,
            PARITY,
            &mut || b64::encode(std::hint::black_box(&raw)).len(),
            &mut || encode_reference(std::hint::black_box(&raw)).len(),
        ));
        let text = coded.as_bytes();
        rows.push(timed_row_at(
            format!("b64 decode, {len}B"),
            len,
            iters,
            PARITY,
            &mut || {
                b64::decode(std::hint::black_box(text))
                    .expect("decodes")
                    .len()
            },
            &mut || {
                decode_reference(std::hint::black_box(text))
                    .expect("decodes")
                    .len()
            },
        ));
    }
    rows
}

pub(crate) fn report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n## Gate 11 — the base64 coder, new against the form it replaced\n"
    );
    let _ = writeln!(
        out,
        "Each row runs the shipped coder and the exact loop it replaced on the same bytes, in\n\
         the same process, and asserts the two produce the same text and the same decode before\n\
         either is timed. The reference is the four-shift, four-store group walk; the shipped\n\
         form reads one twelve-bit group as two table probes and two stores, and decodes a\n\
         pair of groups with eight table probes and one eight-byte store. The gate below\n\
         requires every row to be no slower than its own reference; a row read under\n\
         parity is re-measured at four times the budget first, so one loaded round at\n\
         twelve bytes cannot fail it.\n"
    );
    let _ = writeln!(
        out,
        "| coder | bytes | reference ns/call | ferrox ns/call | speedup |\n\
         | --- | ---: | ---: | ---: | ---: |"
    );
    for row in rows {
        let _ = writeln!(
            out,
            "| `{}` | {} | {:.1} | {:.1} | {:.2}x |",
            row.name,
            row.bytes,
            row.base * 1e9,
            row.ours * 1e9,
            row.ratio()
        );
    }
    out
}
