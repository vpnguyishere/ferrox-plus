use super::Lanes;
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::aarch64::*;

const SHORT_SEAL_BYTES: usize = 512;

pub(crate) struct Engine {
    rk: [uint8x16_t; 11],
    h: [(uint8x16_t, uint8x16_t); 4],
    hp: [(P, P); 4],
}

trait GhashTables {
    fn h(&self) -> &[(uint8x16_t, uint8x16_t); 4];
    fn hp(&self) -> &[(P, P); 4];
}

#[derive(Clone, Copy)]
pub(crate) struct P {
    lo: uint8x16_t,
    hi: uint8x16_t,
}

#[inline(always)]
fn bswap_p(p: P) -> P {
    P {
        lo: <uint8x16_t as Lanes>::bswap(p.lo),
        hi: <uint8x16_t as Lanes>::bswap(p.hi),
    }
}

#[inline(always)]
fn mul_add_p(acc: &mut [[uint8x16_t; 4]; 2], a: P, h: P, hxs: P) {
    <uint8x16_t as Lanes>::mul_add(&mut acc[0], a.lo, h.lo, hxs.lo);
    <uint8x16_t as Lanes>::mul_add(&mut acc[1], a.hi, h.hi, hxs.hi);
}

#[inline(always)]
fn combine_p(acc: [[uint8x16_t; 4]; 2]) -> [uint8x16_t; 4] {
    [
        <uint8x16_t as Lanes>::xor(acc[0][0], acc[1][0]),
        <uint8x16_t as Lanes>::xor(acc[0][1], acc[1][1]),
        <uint8x16_t as Lanes>::xor(acc[0][2], acc[1][2]),
        <uint8x16_t as Lanes>::xor(acc[0][3], acc[1][3]),
    ]
}

#[inline(always)]
fn ghash_group8(hp: &[(P, P); 4], state: uint8x16_t, pairs: [P; 4]) -> uint8x16_t {
    unsafe {
        let mut acc = [[vdupq_n_u8(0); 4]; 2];
        let ypair = P {
            lo: state,
            hi: vdupq_n_u8(0),
        };
        mul_add_p(
            &mut acc,
            P {
                lo: <uint8x16_t as Lanes>::xor(pairs[0].lo, ypair.lo),
                hi: <uint8x16_t as Lanes>::xor(pairs[0].hi, ypair.hi), // pairs[0].hi ^ 0
            },
            hp[3].0,
            hp[3].1,
        );
        mul_add_p(&mut acc, pairs[1], hp[2].0, hp[2].1);
        mul_add_p(&mut acc, pairs[2], hp[1].0, hp[1].1);
        mul_add_p(&mut acc, pairs[3], hp[0].0, hp[0].1);
        <uint8x16_t as Lanes>::reduce(combine_p(acc))
    }
}

#[inline(always)]
fn ctr_lane(template: uint8x16_t, be: u32) -> uint8x16_t {
    unsafe { vreinterpretq_u8_u32(vsetq_lane_u32::<3>(be, vreinterpretq_u32_u8(template))) }
}

#[inline(always)]
fn ctr8v_p(template: uint8x16_t, ctr: u32) -> [[uint8x16_t; 4]; 2] {
    if ctr & 0xff <= 0xf8 {
        let b = ctr.to_be();
        [
            [
                ctr_lane(template, b),
                ctr_lane(template, b.wrapping_add(0x0100_0000)),
                ctr_lane(template, b.wrapping_add(0x0200_0000)),
                ctr_lane(template, b.wrapping_add(0x0300_0000)),
            ],
            [
                ctr_lane(template, b.wrapping_add(0x0400_0000)),
                ctr_lane(template, b.wrapping_add(0x0500_0000)),
                ctr_lane(template, b.wrapping_add(0x0600_0000)),
                ctr_lane(template, b.wrapping_add(0x0700_0000)),
            ],
        ]
    } else {
        [
            [
                template.ctr_be(ctr),
                template.ctr_be(ctr + 1),
                template.ctr_be(ctr + 2),
                template.ctr_be(ctr + 3),
            ],
            [
                template.ctr_be(ctr + 4),
                template.ctr_be(ctr + 5),
                template.ctr_be(ctr + 6),
                template.ctr_be(ctr + 7),
            ],
        ]
    }
}

#[inline(always)]
fn load_pairs(g: &[[u8; 16]; 8]) -> [P; 4] {
    [
        P {
            lo: <uint8x16_t as Lanes>::load(&g[0]),
            hi: <uint8x16_t as Lanes>::load(&g[1]),
        },
        P {
            lo: <uint8x16_t as Lanes>::load(&g[2]),
            hi: <uint8x16_t as Lanes>::load(&g[3]),
        },
        P {
            lo: <uint8x16_t as Lanes>::load(&g[4]),
            hi: <uint8x16_t as Lanes>::load(&g[5]),
        },
        P {
            lo: <uint8x16_t as Lanes>::load(&g[6]),
            hi: <uint8x16_t as Lanes>::load(&g[7]),
        },
    ]
}

#[inline(always)]
fn store_pairs(g: &mut [[u8; 16]; 8], pairs: [P; 4]) {
    pairs[0].lo.store(&mut g[0]);
    pairs[0].hi.store(&mut g[1]);
    pairs[1].lo.store(&mut g[2]);
    pairs[1].hi.store(&mut g[3]);
    pairs[2].lo.store(&mut g[4]);
    pairs[2].hi.store(&mut g[5]);
    pairs[3].lo.store(&mut g[6]);
    pairs[3].hi.store(&mut g[7]);
}

#[inline(always)]
fn pmull(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe {
        core::mem::transmute::<u128, uint8x16_t>(vmull_p64(
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(a)),
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(b)),
        ))
    }
}

#[inline(always)]
fn pmull2(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe {
        core::mem::transmute::<u128, uint8x16_t>(vmull_p64(
            vgetq_lane_u64::<1>(vreinterpretq_u64_u8(a)),
            vgetq_lane_u64::<1>(vreinterpretq_u64_u8(b)),
        ))
    }
}

#[inline(always)]
fn karatsuba2(h: uint8x16_t, m: uint8x16_t, l: uint8x16_t) -> (uint8x16_t, uint8x16_t) {
    unsafe {
        let t = {
            let t0 = veorq_u8(m, vextq_u8::<8>(l, h));
            let t1 = veorq_u8(h, l);
            veorq_u8(t0, t1)
        };
        let x01 = vextq_u8::<8>(vextq_u8::<8>(l, l), t);
        let x23 = vextq_u8::<8>(t, vextq_u8::<8>(h, h));
        (x23, x01)
    }
}

impl Lanes for uint8x16_t {
    #[inline(always)]
    fn load(b: &[u8; 16]) -> Self {
        unsafe { vld1q_u8(b.as_ptr()) }
    }

    #[inline(always)]
    fn store(self, b: &mut [u8; 16]) {
        unsafe { vst1q_u8(b.as_mut_ptr(), self) }
    }

    #[inline(always)]
    unsafe fn store_ptr(self, dst: *mut u8) {
        unsafe { vst1q_u8(dst, self) }
    }

    #[inline(always)]
    fn xor(self, o: Self) -> Self {
        unsafe { veorq_u8(self, o) }
    }

    #[inline(always)]
    fn bswap(self) -> Self {
        unsafe {
            let r = vrev64q_u8(self);
            vextq_u8::<8>(r, r)
        }
    }

    #[inline(always)]
    fn swap_halves(self) -> Self {
        unsafe { vextq_u8::<8>(self, self) }
    }

    #[inline(always)]
    fn mul_add(acc: &mut [Self; 4], a: Self, h: Self, hxs: Self) {
        unsafe {
            let m = pmull(veorq_u8(a, vextq_u8::<8>(a, a)), hxs);
            let hh = pmull2(a, h);
            let ll = pmull(a, h);
            let (x23, x01) = karatsuba2(hh, m, ll);
            acc[0] = veorq_u8(acc[0], x01);
            acc[1] = veorq_u8(acc[1], x23);
        }
    }

    #[inline(always)]
    fn reduce(acc: [Self; 4]) -> Self {
        unsafe {
            let poly = vreinterpretq_u8_p128(
                (1u128 << 127)
                    | (1u128 << 126)
                    | (1u128 << 121)
                    | (1u128 << 63)
                    | (1u128 << 62)
                    | (1u128 << 57),
            );
            let x01 = acc[0];
            let x23 = acc[1];
            let a = pmull(x01, poly);
            let b = veorq_u8(x01, vextq_u8::<8>(a, a));
            let c = pmull2(b, poly);
            veorq_u8(x23, veorq_u8(c, b))
        }
    }

    #[inline(always)]
    fn ctr_add(self, n: u32) -> Self {
        unsafe {
            vreinterpretq_u8_u32(vaddq_u32(
                vreinterpretq_u32_u8(self),
                vsetq_lane_u32::<3>(n, vdupq_n_u32(0)),
            ))
        }
    }

    #[inline(always)]
    fn ctr_swap(self) -> Self {
        const MASK: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12];
        unsafe { vqtbl1q_u8(self, vld1q_u8(MASK.as_ptr())) }
    }

    #[inline(always)]
    fn ctr_be(self, n: u32) -> Self {
        ctr_lane(self, n.to_be())
    }

    #[inline(always)]
    fn encrypt4(rk: &[Self; 11], s: &mut [Self; 4]) {
        unsafe {
            for k in &rk[..9] {
                for lane in s.iter_mut() {
                    *lane = vaesmcq_u8(vaeseq_u8(*lane, *k));
                }
            }
            for lane in s.iter_mut() {
                *lane = veorq_u8(vaeseq_u8(*lane, rk[9]), rk[10]);
            }
        }
    }

    #[inline(always)]
    fn encrypt1v(rk: &[Self; 11], mut s: Self) -> Self {
        unsafe {
            for k in &rk[..9] {
                s = vaesmcq_u8(vaeseq_u8(s, *k));
            }
            veorq_u8(vaeseq_u8(s, rk[9]), rk[10])
        }
    }

    #[inline(always)]
    fn encrypt4_256(rk: &[Self; 15], s: &mut [Self; 4]) {
        unsafe {
            for k in &rk[..13] {
                for lane in s.iter_mut() {
                    *lane = vaesmcq_u8(vaeseq_u8(*lane, *k));
                }
            }
            for lane in s.iter_mut() {
                *lane = veorq_u8(vaeseq_u8(*lane, rk[13]), rk[14]);
            }
        }
    }

    #[inline(always)]
    fn encrypt1v_256(rk: &[Self; 15], mut s: Self) -> Self {
        unsafe {
            for k in &rk[..13] {
                s = vaesmcq_u8(vaeseq_u8(s, *k));
            }
            veorq_u8(vaeseq_u8(s, rk[13]), rk[14])
        }
    }
}

#[inline(always)]
fn ctr_ghash8(
    rk: &[uint8x16_t; 11],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    buf: &mut [u8],
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    if buf.len() <= SHORT_SEAL_BYTES {
        ctr_only8(rk, template, buf, ctr);
        return ghash8(ghash, state, buf, tailq);
    }
    let (blocks, _rest_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        store_pairs(g, ct);
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    super::ctr_ghash(rk, h, template, state, &mut buf[done * 16..], tailq, ctr)
}

#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the key schedule, both directions and the deferred tail are the pass, not a bundle"
)]
fn ctr_ghash8_from(
    rk: &[uint8x16_t; 11],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    src: &[u8],
    dst: &mut [u8],
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (sblocks, _rest_bytes) = src.as_chunks::<16>();
    let (dblocks, _rest_bytes) = dst.as_chunks_mut::<16>();
    let (sgroups, _rest_blocks) = sblocks.as_chunks::<8>();
    let (dgroups, _rest_blocks) = dblocks.as_chunks_mut::<8>();
    let done = dgroups.len() * 8;
    for (sg, dg) in sgroups.iter().zip(dgroups.iter_mut()) {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[1]);
        let mut ct = load_pairs(sg);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        store_pairs(dg, ct);
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    super::ctr_ghash_from(
        rk,
        h,
        template,
        state,
        &src[done * 16..],
        &mut dst[done * 16..],
        tailq,
        ctr,
    )
}

#[inline(always)]
fn ghash8(
    ghash: &impl GhashTables,
    mut state: uint8x16_t,
    data: &[u8],
    tail: &mut super::Tail<uint8x16_t>,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (blocks, _rest_bytes) = data.as_chunks::<16>();
    let (groups, _rest) = blocks.as_chunks::<8>();
    let done = groups.len() * 8;
    for g in groups {
        let mut pairs = load_pairs(g);
        for p in &mut pairs {
            *p = bswap_p(*p);
        }
        state = ghash_group8(hp, state, pairs);
    }
    super::ghash(h, state, &data[done * 16..], tail)
}

#[inline(always)]
fn ctr_only8(rk: &[uint8x16_t; 11], template: uint8x16_t, buf: &mut [u8], mut ctr: u32) {
    let (blocks, _tail_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(pair.lo, ks[i / 2][i % 2 * 2]);
            pair.hi = <uint8x16_t as Lanes>::xor(pair.hi, ks[i / 2][i % 2 * 2 + 1]);
        }
        store_pairs(g, ct);
        ctr += 8;
    }
    super::ctr_only(rk, template, &mut buf[done * 16..], ctr);
}

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    unsafe {
        let v = vreinterpretq_u8_u32(vdupq_n_u32(w));
        let s = vaeseq_u8(v, vdupq_n_u8(0));
        vgetq_lane_u32::<0>(vreinterpretq_u32_u8(s))
    }
}

#[inline(always)]
fn ctr_ghash8_256(
    rk: &[uint8x16_t; 15],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    buf: &mut [u8],
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    if buf.len() <= SHORT_SEAL_BYTES {
        ctr_only8_256(rk, template, buf, ctr);
        return ghash8(ghash, state, buf, tailq);
    }
    let (blocks, _rest_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        store_pairs(g, ct);
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    super::ctr_ghash_256(rk, h, template, state, &mut buf[done * 16..], tailq, ctr)
}

#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the cipher state, both directions and the deferred tail are the pass, not a bundle"
)]
/// CTR and GHASH reading `src` and writing `dst`, returning the chained GHASH state.
fn ctr_ghash8_from_256(
    rk: &[uint8x16_t; 15],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    src: &[u8],
    dst: &mut [u8],
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (sblocks, _) = src.as_chunks::<16>();
    let (dblocks, _) = dst.as_chunks_mut::<16>();
    let (sgroups, _) = sblocks.as_chunks::<8>();
    let (dgroups, _) = dblocks.as_chunks_mut::<8>();
    debug_assert_eq!(sgroups.len(), dgroups.len(), "equal lengths group alike");
    let done = sgroups.len() * 8;
    for (sg, dg) in sgroups.iter().zip(dgroups.iter_mut()) {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[1]);
        let mut ct = load_pairs(sg);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        store_pairs(dg, ct);
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    super::ctr_ghash_from_256(
        rk,
        h,
        template,
        state,
        &src[done * 16..],
        &mut dst[done * 16..],
        tailq,
        ctr,
    )
}

#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the cipher state, both directions and the deferred tail are the pass, not a bundle"
)]
/// CTR and GHASH writing `src.len()` bytes into uninitialized `dst`.
unsafe fn ctr_ghash8_from_256_uninit(
    rk: &[uint8x16_t; 15],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    src: &[u8],
    dst: *mut u8,
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (sblocks, _) = src.as_chunks::<16>();
    let (sgroups, _) = sblocks.as_chunks::<8>();
    let done = sgroups.len() * 8;
    for (group, sg) in sgroups.iter().enumerate() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[1]);
        let mut ct = load_pairs(sg);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        let at = group * 128;
        for (i, pair) in ct.iter().enumerate() {
            // SAFETY: each pair lands inside the caller's `src.len()`-byte destination.
            unsafe {
                <uint8x16_t as Lanes>::store_ptr(pair.lo, dst.add(at + i * 32));
                <uint8x16_t as Lanes>::store_ptr(pair.hi, dst.add(at + i * 32 + 16));
            }
        }
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    // SAFETY: the tail starts after the full groups and stays inside the destination.
    unsafe {
        super::ctr_ghash_from_256_uninit(
            rk,
            h,
            template,
            state,
            &src[done * 16..],
            dst.add(done * 16),
            tailq,
            ctr,
        )
    }
}

#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the cipher state, both directions and the deferred tail are the pass, not a bundle"
)]
/// CTR and GHASH writing `src.len()` bytes into uninitialized `dst`.
unsafe fn ctr_ghash8_from_uninit(
    rk: &[uint8x16_t; 11],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    src: &[u8],
    dst: *mut u8,
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (sblocks, _) = src.as_chunks::<16>();
    let (sgroups, _) = sblocks.as_chunks::<8>();
    let done = sgroups.len() * 8;
    for (group, sg) in sgroups.iter().enumerate() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[1]);
        let mut ct = load_pairs(sg);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        let at = group * 128;
        for (i, pair) in ct.iter().enumerate() {
            // SAFETY: each pair lands inside the caller's `src.len()`-byte destination.
            unsafe {
                <uint8x16_t as Lanes>::store_ptr(pair.lo, dst.add(at + i * 32));
                <uint8x16_t as Lanes>::store_ptr(pair.hi, dst.add(at + i * 32 + 16));
            }
        }
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    // SAFETY: the tail starts after the full groups and stays inside the destination.
    unsafe {
        super::ctr_ghash_from_uninit(
            rk,
            h,
            template,
            state,
            &src[done * 16..],
            dst.add(done * 16),
            tailq,
            ctr,
        )
    }
}

#[inline(always)]
fn ctr_only8_256(rk: &[uint8x16_t; 15], template: uint8x16_t, buf: &mut [u8], mut ctr: u32) {
    let (blocks, _tail_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(pair.lo, ks[i / 2][i % 2 * 2]);
            pair.hi = <uint8x16_t as Lanes>::xor(pair.hi, ks[i / 2][i % 2 * 2 + 1]);
        }
        store_pairs(g, ct);
        ctr += 8;
    }
    super::ctr_only_256(rk, template, &mut buf[done * 16..], ctr);
}

impl Engine {
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn rekey(&mut self, key: &[u8; 16]) {
        unsafe { *self = Self::new(key) };
    }

    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn new(key: &[u8; 16]) -> Self {
        const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
        let mut words = [0u32; 44];
        for (i, w) in words[..4].iter_mut().enumerate() {
            *w = u32::from_ne_bytes(key[4 * i..4 * i + 4].try_into().expect("a word is 4 bytes"));
        }
        for i in 4..44 {
            let mut w = words[i - 1];
            if i % 4 == 0 {
                w = sub_word(w).rotate_right(8) ^ RCON[i / 4 - 1];
            }
            words[i] = words[i - 4] ^ w;
        }
        let rk: [uint8x16_t; 11] = core::array::from_fn(|r| {
            let mut b = [0u8; 16];
            for (wb, w) in b
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(words[4 * r..4 * r + 4].iter())
            {
                wb.copy_from_slice(&w.to_ne_bytes());
            }
            unsafe { vld1q_u8(b.as_ptr()) }
        });
        let h = super::powers(&rk);
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let h5 = (h5, <uint8x16_t as Lanes>::xor(h5, h5.swap_halves()));
        let h6 = (h6, <uint8x16_t as Lanes>::xor(h6, h6.swap_halves()));
        let h7 = (h7, <uint8x16_t as Lanes>::xor(h7, h7.swap_halves()));
        let h8 = (h8, <uint8x16_t as Lanes>::xor(h8, h8.swap_halves()));
        let pair = |early: (uint8x16_t, uint8x16_t), late: (uint8x16_t, uint8x16_t)| -> (P, P) {
            (
                P {
                    lo: early.0,
                    hi: late.0,
                },
                P {
                    lo: early.1,
                    hi: late.1,
                },
            )
        };
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, h, hp }
    }

    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ctr_ghash8(&self.rk, self, template, state, buf, &mut tailq, 2);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn seal_from(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; 16] {
        debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ctr_ghash8_from(&self.rk, self, template, state, src, dst, &mut tailq, 2);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            dst.len() as u64,
            mask,
        )
    }

    /// Seal `src` into uninitialized `dst` and return the tag.
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: *mut u8,
    ) -> [u8; 16] {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = unsafe {
            ctr_ghash8_from_uninit(&self.rk, self, template, state, src, dst, &mut tailq, 2)
        };
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            src.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ghash8(self, state, buf, &mut tailq);
        let want = super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        );

        if !super::tag_eq(&want, tag) {
            return None;
        }

        ctr_only8(&self.rk, template, buf, 2);
        Some(buf.len())
    }
}

pub(crate) struct Engine256 {
    rk: [uint8x16_t; 15],
    h: [(uint8x16_t, uint8x16_t); 4],
    hp: [(P, P); 4],
}

impl GhashTables for Engine {
    fn h(&self) -> &[(uint8x16_t, uint8x16_t); 4] {
        &self.h
    }
    fn hp(&self) -> &[(P, P); 4] {
        &self.hp
    }
}

impl GhashTables for Engine256 {
    fn h(&self) -> &[(uint8x16_t, uint8x16_t); 4] {
        &self.h
    }
    fn hp(&self) -> &[(P, P); 4] {
        &self.hp
    }
}

impl Engine256 {
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn rekey(&mut self, key: &[u8; 32]) {
        unsafe { *self = Self::new(key) };
    }

    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn new(key: &[u8; 32]) -> Self {
        const RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
        let mut words = [0u32; 60];
        for (i, w) in words[..8].iter_mut().enumerate() {
            *w = u32::from_ne_bytes(key[4 * i..4 * i + 4].try_into().expect("a word is 4 bytes"));
        }
        for i in 8..60 {
            let mut w = words[i - 1];
            if i % 8 == 0 {
                w = sub_word(w).rotate_right(8) ^ RCON[i / 8 - 1];
            } else if i % 8 == 4 {
                w = sub_word(w);
            }
            words[i] = words[i - 8] ^ w;
        }
        let rk: [uint8x16_t; 15] = core::array::from_fn(|r| {
            let mut b = [0u8; 16];
            for (wb, w) in b
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(words[4 * r..4 * r + 4].iter())
            {
                wb.copy_from_slice(&w.to_ne_bytes());
            }
            unsafe { vld1q_u8(b.as_ptr()) }
        });
        let h = super::powers_256(&rk);
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let h5 = (h5, <uint8x16_t as Lanes>::xor(h5, h5.swap_halves()));
        let h6 = (h6, <uint8x16_t as Lanes>::xor(h6, h6.swap_halves()));
        let h7 = (h7, <uint8x16_t as Lanes>::xor(h7, h7.swap_halves()));
        let h8 = (h8, <uint8x16_t as Lanes>::xor(h8, h8.swap_halves()));
        let pair = |early: (uint8x16_t, uint8x16_t), late: (uint8x16_t, uint8x16_t)| -> (P, P) {
            (
                P {
                    lo: early.0,
                    hi: late.0,
                },
                P {
                    lo: early.1,
                    hi: late.1,
                },
            )
        };
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, h, hp }
    }

    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ctr_ghash8_256(&self.rk, self, template, state, buf, &mut tailq, 2);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "aes,neon")]
    /// Seal `src` into `dst` without staging the plaintext, returning the authentication tag.
    pub(crate) unsafe fn seal_from(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; 16] {
        debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ctr_ghash8_from_256(&self.rk, self, template, state, src, dst, &mut tailq, 2);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            dst.len() as u64,
            mask,
        )
    }

    /// Seal `src` into uninitialized `dst` and return the tag.
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: *mut u8,
    ) -> [u8; 16] {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = unsafe {
            ctr_ghash8_from_256_uninit(&self.rk, self, template, state, src, dst, &mut tailq, 2)
        };
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            src.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ghash8(self, state, buf, &mut tailq);
        let want = super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        );
        if !super::tag_eq(&want, tag) {
            return None;
        }
        ctr_only8_256(&self.rk, template, buf, 2);
        Some(buf.len())
    }
}
