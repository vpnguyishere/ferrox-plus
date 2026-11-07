use std::mem::MaybeUninit;

use crate::poly1305::Poly1305;
use crate::record::{fill_exact, fill_exact_with_head};

/// Thirty-two bytes of block zero's keystream, requested at that length so the block's second half is never staged.
fn poly_key(chacha_key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut key = [0u8; 32];
    fill_exact(chacha_key, nonce, 0, &mut key);
    key
}

#[must_use]
pub fn chacha20_poly1305_seal_in_place_unfused(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    fill_exact(key, nonce, 1, buf);
    let mut state = Poly1305::new(&poly_key(key, nonce));
    mac(&mut state, aad, buf);
    state.finish()
}

fn mac(state: &mut Poly1305, aad: &[u8], ciphertext: &[u8]) {
    for section in [aad, ciphertext] {
        state.update(section);
        state.pad_to_block();
    }
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    state.update(&lengths);
}

#[must_use]
pub fn chacha20_poly1305_seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let mut one_time = [0u8; 32];
    fill_exact_with_head(key, nonce, 0, &mut one_time, buf);

    let mut state = Poly1305::new(&one_time);
    mac(&mut state, aad, buf);
    state.finish()
}

#[must_use]
pub fn chacha20_poly1305_seal_from(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    src: &[u8],
    dst: &mut [u8],
) -> [u8; 16] {
    assert_eq!(
        src.len(),
        dst.len(),
        "the source and the wire are the same message"
    );
    let mut one_time = [0u8; 32];
    crate::record::fill_exact_with_head_from(key, nonce, 0, &mut one_time, src, dst);

    let mut state = Poly1305::new(&one_time);
    mac(&mut state, aad, dst);
    state.finish()
}

/// Seal `src` into `dst`, which may be uninitialized: every byte is written before this returns, so a caller holding spare capacity pays no zeroing pass beside the fill, and no staging copy of the plaintext — the payload register file is read through `xor_chunk_from`, which never writes `src`.
#[must_use]
pub fn chacha20_poly1305_seal_from_uninit(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    src: &[u8],
    dst: &mut [MaybeUninit<u8>],
) -> [u8; 16] {
    assert_eq!(
        src.len(),
        dst.len(),
        "the source and the wire are the same message"
    );
    let mut one_time = [0u8; 32];
    // `fill_exact_with_head_from` writes every wrapped byte through `xor_chunk_from`, so every byte is initialized before this slice is formed.
    let dst_initialized =
        unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), dst.len()) };
    crate::record::fill_exact_with_head_from(key, nonce, 0, &mut one_time, src, dst_initialized);

    let mut state = Poly1305::new(&one_time);
    mac(&mut state, aad, dst_initialized);
    state.finish()
}

#[must_use]
pub fn chacha20_poly1305_decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Option<usize> {
    // Poly1305 authenticates the ciphertext, so the tag is checked before the one keystream xor into the caller's buffer.
    let mut state = Poly1305::new(&poly_key(key, nonce));
    mac(&mut state, aad, buf);
    let want = state.finish();

    let mut diff = 0u8;
    for (a, b) in want.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }

    fill_exact(key, nonce, 1, buf);
    Some(buf.len())
}

#[must_use]
pub fn chacha20_poly1305_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let mut state = Poly1305::new(&poly_key(key, nonce));
    mac(&mut state, aad, ciphertext);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::AeadInOut as _;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

    /// Sweep lengths: each natively, the same boundaries as a Miri sample that interprets every byte.
    fn sweep_lengths() -> Vec<usize> {
        if cfg!(miri) {
            vec![
                0, 1, 15, 16, 17, 63, 64, 65, 111, 112, 113, 300, 511, 512, 513,
            ]
        } else {
            (0..=300)
                .chain([511, 512, 513, 1024, 4095, 4096, 8192])
                .collect()
        }
    }

    #[test]
    fn sealing_from_a_source_is_the_in_place_seal_and_leaves_the_source_alone() {
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        let aad = b"a header";
        for &len in &sweep_lengths() {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(251).wrapping_add(11))
                .collect();
            let original = plain.clone();
            let mut in_place = plain.clone();
            let want = chacha20_poly1305_seal_in_place(&key, &nonce, aad, &mut in_place);
            let mut dst = vec![0u8; len];
            let got = chacha20_poly1305_seal_from(&key, &nonce, aad, &plain, &mut dst);
            assert_eq!(got, want, "tag at length {len}");
            assert_eq!(dst, in_place, "ciphertext at length {len}");
            let mut uninit = vec![std::mem::MaybeUninit::new(0xa5u8); len];
            let got = chacha20_poly1305_seal_from_uninit(&key, &nonce, aad, &plain, &mut uninit);
            assert_eq!(got, want, "uninit tag at length {len}");
            // SAFETY: seal_from_uninit wrote every byte of the destination.
            let uninit =
                unsafe { std::slice::from_raw_parts(uninit.as_ptr().cast::<u8>(), uninit.len()) };
            assert_eq!(uninit, in_place, "uninit ciphertext at length {len}");
            assert_eq!(plain, original, "source at length {len}");
        }
    }

    #[test]
    fn the_rfc_8439_vector_is_the_framing() {
        let key: [u8; 32] = std::array::from_fn(|i| 0x80u8.wrapping_add(i as u8));
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plain: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you \
            only one tip for the future, sunscreen would be it.";
        assert_eq!(plain.len(), 114, "the RFC's plaintext is 114 bytes");
        let mut buf = plain.to_vec();
        let tag = chacha20_poly1305_seal_in_place(&key, &nonce, &aad, &mut buf);
        assert_eq!(
            &buf[..16],
            &[
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2
            ],
            "RFC 8439 section 2.8.2 ciphertext"
        );
        assert_eq!(
            tag,
            [
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
                0x06, 0x91
            ],
            "RFC 8439 section 2.8.2 tag"
        );
        assert_eq!(
            chacha20_poly1305_tag(&key, &nonce, &aad, &buf),
            tag,
            "the tag-only entry point, on the RFC's own ciphertext"
        );
        let mut opened = buf.clone();
        assert_eq!(
            chacha20_poly1305_decrypt_in_place(&key, &nonce, &aad, &mut opened, &tag),
            Some(plain.len()),
            "the RFC's ciphertext opens"
        );
        assert_eq!(
            opened, plain,
            "the RFC's ciphertext opens to the RFC's plaintext"
        );
    }

    #[test]
    fn is_byte_identical_to_the_crate_it_replaces() {
        let keys = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let lengths = sweep_lengths();
        let mut checked = 0usize;
        for key in &keys {
            for nonce in [[0u8; 12], [0xa7u8; 12], [0xffu8; 12]] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                    for &len in &lengths {
                        let plain: Vec<u8> = (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect();
                        let mut buf = plain.clone();
                        let tag = chacha20_poly1305_seal_in_place(key, &nonce, &aad, &mut buf);
                        let want_ct = {
                            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key");
                            let mut ct = plain.clone();
                            let want_tag = cipher
                                .encrypt_inout_detached(
                                    &Nonce::try_from(&nonce[..]).expect("length"),
                                    &aad,
                                    (&mut ct[..]).into(),
                                )
                                .expect("seals");
                            let want_tag: [u8; 16] = want_tag.into();
                            assert_eq!(
                                tag, want_tag,
                                "tag: key {key:02x?} nonce {nonce:02x?} aad {aad_len} len {len}"
                            );
                            ct
                        };
                        assert_eq!(
                            buf, want_ct,
                            "ciphertext: key {key:02x?} nonce {nonce:02x?} aad {aad_len} len {len}"
                        );
                        assert_eq!(
                            chacha20_poly1305_tag(key, &nonce, &aad, &buf),
                            tag,
                            "the tag-only entry point disagrees at len {len}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(
            checked,
            keys.len() * 3 * 6 * lengths.len(),
            "every case the sweep configures ran"
        );
        if cfg!(not(miri)) {
            assert!(checked > 5_000, "the native sweep is dense, not a sample");
        }
    }

    #[test]
    fn every_decrypt_matches_the_crate_it_replaces() {
        let keys = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let lengths = sweep_lengths();
        let mut checked = 0usize;
        for key in &keys {
            for nonce in [[0u8; 12], [0xa7u8; 12], [0xffu8; 12]] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                    for &len in &lengths {
                        let plain: Vec<u8> = (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect();
                        let mut sealed = plain.clone();
                        let tag = chacha20_poly1305_seal_in_place(key, &nonce, &aad, &mut sealed);

                        let want = {
                            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key");
                            let mut ct = sealed.clone();
                            cipher
                                .decrypt_inout_detached(
                                    &Nonce::try_from(&nonce[..]).expect("length"),
                                    &aad,
                                    (&mut ct[..]).into(),
                                    &chacha20poly1305::Tag::try_from(&tag[..]).expect("length"),
                                )
                                .expect("the crate opens what it sealed");
                            ct
                        };

                        let mut opened = sealed.clone();
                        assert_eq!(
                            chacha20_poly1305_decrypt_in_place(
                                key,
                                &nonce,
                                &aad,
                                &mut opened,
                                &tag
                            ),
                            Some(len),
                            "aad {aad_len} len {len}"
                        );
                        assert_eq!(opened, want, "plaintext: aad {aad_len} len {len}");
                        assert_eq!(opened, plain, "round trip: aad {aad_len} len {len}");

                        let mut bad = tag;
                        bad[len % 16] ^= 0x80;
                        let mut refused = sealed.clone();
                        assert_eq!(
                            chacha20_poly1305_decrypt_in_place(
                                key,
                                &nonce,
                                &aad,
                                &mut refused,
                                &bad
                            ),
                            None,
                            "a forged tag at aad {aad_len} len {len}"
                        );
                        assert_eq!(refused, sealed, "a refused tag must not decrypt");
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(
            checked,
            keys.len() * 3 * 6 * lengths.len(),
            "every case the sweep configures ran"
        );
        if cfg!(not(miri)) {
            assert!(checked > 6_000, "the native sweep is dense, not a sample");
        }
    }

    #[test]
    fn opens_what_seal_made_and_refuses_a_forged_tag() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut buf = plain.clone();
            let tag = chacha20_poly1305_seal_in_place(&key, &nonce, b"", &mut buf);
            assert_eq!(
                chacha20_poly1305_decrypt_in_place(&key, &nonce, b"", &mut buf, &tag),
                Some(len),
                "length {len}"
            );
            assert_eq!(buf, plain, "length {len} round trips");

            let mut bad = tag;
            bad[0] ^= 1;
            assert_eq!(
                chacha20_poly1305_decrypt_in_place(&key, &nonce, b"", &mut buf, &bad),
                None,
                "length {len} refuses a changed tag"
            );
        }
    }

    #[test]
    fn a_refused_message_is_left_encrypted() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let plain = b"do not decrypt me before you check the tag".to_vec();
        let mut buf = plain.clone();
        let _tag = chacha20_poly1305_seal_in_place(&key, &nonce, b"", &mut buf);
        let ciphertext = buf.clone();
        assert_eq!(
            chacha20_poly1305_decrypt_in_place(&key, &nonce, b"", &mut buf, &[0u8; 16]),
            None
        );
        assert_eq!(buf, ciphertext, "a wrong tag must not decrypt");
    }

    #[test]
    fn aad_is_authenticated() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 12];
        let mut buf = b"payload".to_vec();
        let tag = chacha20_poly1305_seal_in_place(&key, &nonce, b"one", &mut buf);
        assert_eq!(
            chacha20_poly1305_decrypt_in_place(&key, &nonce, b"two", &mut buf, &tag),
            None,
            "the tag must not verify under a different aad"
        );
    }
}
