use super::Lanes;
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::x86_64::*;

pub(crate) struct Engine {
    rk: [__m128i; 11],
    rk2: [__m256i; 11],
    h: [(__m128i, __m128i); 4],
    hp: [(__m256i, __m256i); 4],
}

const BSWAP2: [u8; 32] = [
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, //
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
];

const CTRMASK2: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12, //
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12,
];

#[inline(always)]
fn loadu2(b: &[u8; 32]) -> __m256i {
    unsafe { _mm256_loadu_si256(b.as_ptr().cast()) }
}

#[inline(always)]
fn bswap2(x: __m256i) -> __m256i {
    unsafe { _mm256_shuffle_epi8(x, loadu2(&BSWAP2)) }
}

#[inline(always)]
fn cswap2(x: __m256i) -> __m256i {
    unsafe { _mm256_shuffle_epi8(x, loadu2(&CTRMASK2)) }
}

#[inline(always)]
fn mul_add2(acc: &mut [__m256i; 4], a: __m256i, h: __m256i, hxs: __m256i) {
    unsafe {
        let a1 = _mm256_shuffle_epi32::<0x0E>(a);
        let a2 = _mm256_xor_si256(a, a1);
        let t0 = _mm256_clmulepi64_epi128::<0x00>(a, h);
        let t1 = _mm256_clmulepi64_epi128::<0x11>(a, h);
        let t2 = _mm256_clmulepi64_epi128::<0x00>(a2, hxs);
        let t2 = _mm256_xor_si256(t2, _mm256_xor_si256(t0, t1));
        acc[0] = _mm256_xor_si256(acc[0], t0);
        acc[1] = _mm256_xor_si256(
            acc[1],
            _mm256_xor_si256(_mm256_shuffle_epi32::<0x0E>(t0), t2),
        );
        acc[2] = _mm256_xor_si256(
            acc[2],
            _mm256_xor_si256(t1, _mm256_shuffle_epi32::<0x0E>(t2)),
        );
        acc[3] = _mm256_xor_si256(acc[3], _mm256_shuffle_epi32::<0x0E>(t1));
    }
}

#[inline(always)]
fn combine(acc: [__m256i; 4]) -> [__m128i; 4] {
    unsafe {
        acc.map(|r| _mm_xor_si128(_mm256_castsi256_si128(r), _mm256_extracti128_si256::<1>(r)))
    }
}

#[inline(always)]
fn ctr8v(template: __m256i, ctr: u32) -> [__m256i; 4] {
    unsafe {
        let a0 = _mm256_add_epi32(
            template,
            _mm256_set_epi32((ctr + 1).cast_signed(), 0, 0, 0, ctr.cast_signed(), 0, 0, 0),
        );
        let two = _mm256_set_epi32(2, 0, 0, 0, 2, 0, 0, 0);
        let a1 = _mm256_add_epi32(a0, two);
        let a2 = _mm256_add_epi32(a1, two);
        let a3 = _mm256_add_epi32(a2, two);
        [cswap2(a0), cswap2(a1), cswap2(a2), cswap2(a3)]
    }
}

#[inline(always)]
fn encrypt8(rk: &[__m256i; 11], s: &mut [__m256i; 4]) {
    unsafe {
        for lane in s.iter_mut() {
            *lane = _mm256_xor_si256(*lane, rk[0]);
        }
        for k in &rk[1..10] {
            for lane in s.iter_mut() {
                *lane = _mm256_aesenc_epi128(*lane, *k);
            }
        }
        for lane in s.iter_mut() {
            *lane = _mm256_aesenclast_epi128(*lane, rk[10]);
        }
    }
}

#[inline(always)]
fn encrypt8_256(rk: &[__m256i; 15], s: &mut [__m256i; 4]) {
    unsafe {
        for lane in s.iter_mut() {
            *lane = _mm256_xor_si256(*lane, rk[0]);
        }
        for k in &rk[1..14] {
            for lane in s.iter_mut() {
                *lane = _mm256_aesenc_epi128(*lane, *k);
            }
        }
        for lane in s.iter_mut() {
            *lane = _mm256_aesenclast_epi128(*lane, rk[14]);
        }
    }
}

#[inline(always)]
fn ghash_group8(hp: &[(__m256i, __m256i); 4], state: __m128i, pairs: [__m256i; 4]) -> __m128i {
    unsafe {
        let ypair = _mm256_set_m128i(_mm_setzero_si128(), state);
        let mut acc = [_mm256_setzero_si256(); 4];
        mul_add2(
            &mut acc,
            _mm256_xor_si256(pairs[0], ypair),
            hp[3].0,
            hp[3].1,
        );
        mul_add2(&mut acc, pairs[1], hp[2].0, hp[2].1);
        mul_add2(&mut acc, pairs[2], hp[1].0, hp[1].1);
        mul_add2(&mut acc, pairs[3], hp[0].0, hp[0].1);
        <__m128i as Lanes>::reduce(combine(acc))
    }
}

#[inline(always)]
fn load_pairs(g: &[[u8; 16]; 8]) -> [__m256i; 4] {
    unsafe {
        [
            _mm256_loadu_si256(g[0..].as_ptr().cast()),
            _mm256_loadu_si256(g[2..].as_ptr().cast()),
            _mm256_loadu_si256(g[4..].as_ptr().cast()),
            _mm256_loadu_si256(g[6..].as_ptr().cast()),
        ]
    }
}

#[inline(always)]
fn store_pairs(g: &mut [[u8; 16]; 8], pairs: [__m256i; 4]) {
    unsafe {
        for (pair, g2) in pairs.iter().zip(g.as_chunks_mut::<2>().0.iter_mut()) {
            _mm256_storeu_si256(g2.as_mut_ptr().cast(), *pair);
        }
    }
}

#[inline(always)]
fn grouped(blocks: &[[u8; 16]]) -> usize {
    blocks.len() / 8 * 128
}

impl Engine {
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn rekey(&mut self, key: &[u8; 16]) {
        unsafe { *self = Self::new(key) };
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn new(key: &[u8; 16]) -> Self {
        let rk = super::x86::expand(key);
        let rk2 = rk.map(|k| _mm256_broadcastsi128_si256(k));
        let h = super::powers(&rk);
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let pair = |early: (__m128i, __m128i), late: (__m128i, __m128i)| {
            (
                _mm256_set_m128i(late.0, early.0),
                _mm256_set_m128i(late.1, early.1),
            )
        };
        let h5 = (h5, h5.xor(h5.swap_halves()));
        let h6 = (h6, h6.xor(h6.swap_halves()));
        let h7 = (h7, h7.xor(h7.swap_halves()));
        let h8 = (h8, h8.xor(h8.swap_halves()));
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, rk2, h, hp }
    }

    #[inline(always)]
    fn ctr_ghash8(
        &self,
        template: __m128i,
        mut state: __m128i,
        buf: &mut [u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (blocks, _) = buf.as_chunks_mut::<16>();
            let done = grouped(blocks);
            let (groups, _) = blocks.as_chunks_mut::<8>();
            let mut ctr = 2u32;
            for g in groups {
                let mut ks = ctr8v(template2, ctr);
                encrypt8(&self.rk2, &mut ks);
                let pt = load_pairs(g);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                store_pairs(g, pairs);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            super::ctr_ghash(
                &self.rk,
                &self.h,
                template,
                state,
                &mut buf[done..],
                tailq,
                ctr,
            )
        }
    }

    #[inline(always)]
    fn ctr_ghash8_from(
        &self,
        template: __m128i,
        mut state: __m128i,
        src: &[u8],
        dst: &mut [u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (sblocks, _) = src.as_chunks::<16>();
            let (dblocks, _) = dst.as_chunks_mut::<16>();
            let done = grouped(dblocks);
            let (sgroups, _) = sblocks.as_chunks::<8>();
            let (dgroups, _) = dblocks.as_chunks_mut::<8>();
            let mut ctr = 2u32;
            for (sg, dg) in sgroups.iter().zip(dgroups.iter_mut()) {
                let mut ks = ctr8v(template2, ctr);
                encrypt8(&self.rk2, &mut ks);
                let pt = load_pairs(sg);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                store_pairs(dg, pairs);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            super::ctr_ghash_from(
                &self.rk,
                &self.h,
                template,
                state,
                &src[done..],
                &mut dst[done..],
                tailq,
                ctr,
            )
        }
    }

    #[inline(always)]
    fn ghash8(&self, mut state: __m128i, data: &[u8], tailq: &mut super::Tail<__m128i>) -> __m128i {
        let (blocks, _) = data.as_chunks::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks::<8>();
        for g in groups {
            let pt = load_pairs(g);
            state = ghash_group8(
                &self.hp,
                state,
                [bswap2(pt[0]), bswap2(pt[1]), bswap2(pt[2]), bswap2(pt[3])],
            );
        }
        super::ghash(&self.h, state, &data[done..], tailq)
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ctr_ghash8(template, state, buf, &mut tailq);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal_from(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; 16] {
        debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ctr_ghash8_from(template, state, src, dst, &mut tailq);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            dst.len() as u64,
            mask,
        )
    }

    #[inline(always)]
    /// CTR and GHASH writing `src.len()` bytes into uninitialized `dst`.
    unsafe fn ctr_ghash8_from_uninit(
        &self,
        template: __m128i,
        mut state: __m128i,
        src: &[u8],
        dst: *mut u8,
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (sblocks, _) = src.as_chunks::<16>();
            let (sgroups, _) = sblocks.as_chunks::<8>();
            let done = grouped(sblocks);
            let mut ctr = 2u32;
            for (group, sg) in sgroups.iter().enumerate() {
                let mut ks = ctr8v(template2, ctr);
                encrypt8(&self.rk2, &mut ks);
                let pt = load_pairs(sg);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                let at = group * 128;
                _mm256_storeu_si256(dst.add(at).cast(), pairs[0]);
                _mm256_storeu_si256(dst.add(at + 32).cast(), pairs[1]);
                _mm256_storeu_si256(dst.add(at + 64).cast(), pairs[2]);
                _mm256_storeu_si256(dst.add(at + 96).cast(), pairs[3]);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            super::ctr_ghash_from_uninit(
                &self.rk,
                &self.h,
                template,
                state,
                &src[done..],
                dst.add(done),
                tailq,
                ctr,
            )
        }
    }

    /// Seal `src` into uninitialized `dst` and return the tag.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: *mut u8,
    ) -> [u8; 16] {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = unsafe { self.ctr_ghash8_from_uninit(template, state, src, dst, &mut tailq) };
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            src.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ghash8(state, buf, &mut tailq);
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

        let template2 = _mm256_broadcastsi128_si256(template);
        let (blocks, _) = buf.as_chunks_mut::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks_mut::<8>();
        let mut ctr = 2u32;
        for g in groups {
            let mut ks = ctr8v(template2, ctr);
            encrypt8(&self.rk2, &mut ks);
            let pt = load_pairs(g);
            let pairs = [
                _mm256_xor_si256(ks[0], pt[0]),
                _mm256_xor_si256(ks[1], pt[1]),
                _mm256_xor_si256(ks[2], pt[2]),
                _mm256_xor_si256(ks[3], pt[3]),
            ];
            store_pairs(g, pairs);
            ctr += 8;
        }
        super::ctr_only(&self.rk, template, &mut buf[done..], ctr);
        Some(buf.len())
    }
}

pub(crate) struct Engine256 {
    rk: [__m128i; 15],
    rk2: [__m256i; 15],
    h: [(__m128i, __m128i); 4],
    hp: [(__m256i, __m256i); 4],
}

impl Engine256 {
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn rekey(&mut self, key: &[u8; 32]) {
        unsafe { *self = Self::new(key) };
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn new(key: &[u8; 32]) -> Self {
        let rk = super::x86::expand256(key);
        let rk2 = rk.map(|k| _mm256_broadcastsi128_si256(k));
        let h = super::powers_256(&rk);
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let pair = |early: (__m128i, __m128i), late: (__m128i, __m128i)| {
            (
                _mm256_set_m128i(late.0, early.0),
                _mm256_set_m128i(late.1, early.1),
            )
        };
        let h5 = (h5, h5.xor(h5.swap_halves()));
        let h6 = (h6, h6.xor(h6.swap_halves()));
        let h7 = (h7, h7.xor(h7.swap_halves()));
        let h8 = (h8, h8.xor(h8.swap_halves()));
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, rk2, h, hp }
    }

    #[inline(always)]
    fn ctr_ghash8_256(
        &self,
        template: __m128i,
        mut state: __m128i,
        buf: &mut [u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (blocks, _) = buf.as_chunks_mut::<16>();
            let done = grouped(blocks);
            let (groups, _) = blocks.as_chunks_mut::<8>();
            let mut ctr = 2u32;
            for g in groups {
                let mut ks = ctr8v(template2, ctr);
                encrypt8_256(&self.rk2, &mut ks);
                let pt = load_pairs(g);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                store_pairs(g, pairs);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            super::ctr_ghash_256(
                &self.rk,
                &self.h,
                template,
                state,
                &mut buf[done..],
                tailq,
                ctr,
            )
        }
    }

    #[inline(always)]
    /// CTR and GHASH reading `src` and writing `dst`, returning the chained GHASH state.
    fn ctr_ghash8_from_256(
        &self,
        template: __m128i,
        mut state: __m128i,
        src: &[u8],
        dst: &mut [u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (sblocks, _) = src.as_chunks::<16>();
            let (dblocks, _) = dst.as_chunks_mut::<16>();
            let done = grouped(sblocks);
            let (sgroups, _) = sblocks.as_chunks::<8>();
            let (dgroups, _) = dblocks.as_chunks_mut::<8>();
            debug_assert_eq!(sgroups.len(), dgroups.len(), "equal lengths group alike");
            let mut ctr = 2u32;
            for (sg, dg) in sgroups.iter().zip(dgroups.iter_mut()) {
                let mut ks = ctr8v(template2, ctr);
                encrypt8_256(&self.rk2, &mut ks);
                let pt = load_pairs(sg);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                store_pairs(dg, pairs);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            super::ctr_ghash_from_256(
                &self.rk,
                &self.h,
                template,
                state,
                &src[done..],
                &mut dst[done..],
                tailq,
                ctr,
            )
        }
    }

    #[inline(always)]
    /// CTR and GHASH writing `src.len()` bytes into uninitialized `dst`.
    unsafe fn ctr_ghash8_from_256_uninit(
        &self,
        template: __m128i,
        mut state: __m128i,
        src: &[u8],
        dst: *mut u8,
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (sblocks, _) = src.as_chunks::<16>();
            let (sgroups, _) = sblocks.as_chunks::<8>();
            let done = grouped(sblocks);
            let mut ctr = 2u32;
            for (group, sg) in sgroups.iter().enumerate() {
                let mut ks = ctr8v(template2, ctr);
                encrypt8_256(&self.rk2, &mut ks);
                let pt = load_pairs(sg);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                let at = group * 128;
                _mm256_storeu_si256(dst.add(at).cast(), pairs[0]);
                _mm256_storeu_si256(dst.add(at + 32).cast(), pairs[1]);
                _mm256_storeu_si256(dst.add(at + 64).cast(), pairs[2]);
                _mm256_storeu_si256(dst.add(at + 96).cast(), pairs[3]);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            super::ctr_ghash_from_256_uninit(
                &self.rk,
                &self.h,
                template,
                state,
                &src[done..],
                dst.add(done),
                tailq,
                ctr,
            )
        }
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ctr_ghash8_256(template, state, buf, &mut tailq);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    /// Seal `src` into `dst` without staging the plaintext, returning the authentication tag.
    pub(crate) unsafe fn seal_from(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; 16] {
        debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ctr_ghash8_from_256(template, state, src, dst, &mut tailq);
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
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: *mut u8,
    ) -> [u8; 16] {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state =
            unsafe { self.ctr_ghash8_from_256_uninit(template, state, src, dst, &mut tailq) };
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            src.len() as u64,
            mask,
        )
    }

    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v_256(&self.rk, template.ctr_be(1));
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ghash8_256(state, buf, &mut tailq);
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
        let template2 = _mm256_broadcastsi128_si256(template);
        let (blocks, _) = buf.as_chunks_mut::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks_mut::<8>();
        let mut ctr = 2u32;
        for g in groups {
            let mut ks = ctr8v(template2, ctr);
            encrypt8_256(&self.rk2, &mut ks);
            let pt = load_pairs(g);
            let pairs = [
                _mm256_xor_si256(ks[0], pt[0]),
                _mm256_xor_si256(ks[1], pt[1]),
                _mm256_xor_si256(ks[2], pt[2]),
                _mm256_xor_si256(ks[3], pt[3]),
            ];
            store_pairs(g, pairs);
            ctr += 8;
        }
        super::ctr_only_256(&self.rk, template, &mut buf[done..], ctr);
        Some(buf.len())
    }

    #[inline(always)]
    fn ghash8_256(
        &self,
        mut state: __m128i,
        data: &[u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        let (blocks, _) = data.as_chunks::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks::<8>();
        for g in groups {
            let pt = load_pairs(g);
            state = ghash_group8(
                &self.hp,
                state,
                [bswap2(pt[0]), bswap2(pt[1]), bswap2(pt[2]), bswap2(pt[3])],
            );
        }
        super::ghash(&self.h, state, &data[done..], tailq)
    }
}
