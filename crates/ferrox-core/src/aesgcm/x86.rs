use super::Lanes;
#[allow(
    clippy::wildcard_imports,
    reason = "arch intrinsics: the module's whole API is register operations"
)]
use core::arch::x86_64::*;

pub(crate) struct Engine {
    rk: [__m128i; 11],
    h: [(__m128i, __m128i); 4],
}

const HALVES: i32 = 0x0E;

const BSWAP: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

const CTRMASK: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12];

#[inline(always)]
fn loadu(b: &[u8; 16]) -> __m128i {
    unsafe { _mm_loadu_si128(b.as_ptr().cast()) }
}

#[inline(always)]
fn xor4(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(_mm_xor_si128(a, b), _mm_xor_si128(c, d)) }
}

#[inline(always)]
fn xor5(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i, v4: __m128i) -> __m128i {
    unsafe {
        _mm_xor_si128(
            v0,
            _mm_xor_si128(_mm_xor_si128(v1, v2), _mm_xor_si128(v3, v4)),
        )
    }
}

impl Lanes for __m128i {
    #[inline(always)]
    fn load(b: &[u8; 16]) -> Self {
        loadu(b)
    }

    #[inline(always)]
    fn store(self, b: &mut [u8; 16]) {
        unsafe { _mm_storeu_si128(b.as_mut_ptr().cast(), self) }
    }

    #[inline(always)]
    unsafe fn store_ptr(self, dst: *mut u8) {
        unsafe { _mm_storeu_si128(dst.cast(), self) }
    }

    #[inline(always)]
    fn xor(self, o: Self) -> Self {
        unsafe { _mm_xor_si128(self, o) }
    }

    #[inline(always)]
    fn bswap(self) -> Self {
        unsafe { _mm_shuffle_epi8(self, loadu(&BSWAP)) }
    }

    #[inline(always)]
    fn swap_halves(self) -> Self {
        unsafe { _mm_shuffle_epi32::<HALVES>(self) }
    }

    #[inline(always)]
    fn mul_add(acc: &mut [Self; 4], a: Self, h: Self, hxs: Self) {
        unsafe {
            let a1 = _mm_shuffle_epi32::<HALVES>(a);
            let a2 = _mm_xor_si128(a, a1);
            let t0 = _mm_clmulepi64_si128::<0x00>(a, h);
            let t1 = _mm_clmulepi64_si128::<0x11>(a, h);
            let t2 = _mm_clmulepi64_si128::<0x00>(a2, hxs);
            let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
            acc[0] = _mm_xor_si128(acc[0], t0);
            acc[1] = _mm_xor_si128(acc[1], _mm_xor_si128(_mm_shuffle_epi32::<HALVES>(t0), t2));
            acc[2] = _mm_xor_si128(acc[2], _mm_xor_si128(t1, _mm_shuffle_epi32::<HALVES>(t2)));
            acc[3] = _mm_xor_si128(acc[3], _mm_shuffle_epi32::<HALVES>(t1));
        }
    }

    #[inline(always)]
    fn reduce(acc: [Self; 4]) -> Self {
        unsafe {
            let [v0, v1, v2, v3] = acc;
            let v2 = xor5(
                v2,
                v0,
                _mm_srli_epi64::<1>(v0),
                _mm_srli_epi64::<2>(v0),
                _mm_srli_epi64::<7>(v0),
            );
            let v1 = xor4(
                v1,
                _mm_slli_epi64::<63>(v0),
                _mm_slli_epi64::<62>(v0),
                _mm_slli_epi64::<57>(v0),
            );
            let v3 = xor5(
                v3,
                v1,
                _mm_srli_epi64::<1>(v1),
                _mm_srli_epi64::<2>(v1),
                _mm_srli_epi64::<7>(v1),
            );
            let v2 = xor4(
                v2,
                _mm_slli_epi64::<63>(v1),
                _mm_slli_epi64::<62>(v1),
                _mm_slli_epi64::<57>(v1),
            );
            _mm_unpacklo_epi64(v2, v3)
        }
    }

    #[inline(always)]
    fn ctr_add(self, n: u32) -> Self {
        unsafe { _mm_add_epi32(self, _mm_set_epi32(n.cast_signed(), 0, 0, 0)) }
    }

    #[inline(always)]
    fn ctr_swap(self) -> Self {
        unsafe { _mm_shuffle_epi8(self, loadu(&CTRMASK)) }
    }

    #[inline(always)]
    fn encrypt4(rk: &[Self; 11], s: &mut [Self; 4]) {
        unsafe {
            for lane in s.iter_mut() {
                *lane = _mm_xor_si128(*lane, rk[0]);
            }
            for k in &rk[1..10] {
                for lane in s.iter_mut() {
                    *lane = _mm_aesenc_si128(*lane, *k);
                }
            }
            for lane in s.iter_mut() {
                *lane = _mm_aesenclast_si128(*lane, rk[10]);
            }
        }
    }

    #[inline(always)]
    fn encrypt1v(rk: &[Self; 11], mut s: Self) -> Self {
        unsafe {
            s = _mm_xor_si128(s, rk[0]);
            for k in &rk[1..10] {
                s = _mm_aesenc_si128(s, *k);
            }
            _mm_aesenclast_si128(s, rk[10])
        }
    }

    #[inline(always)]
    fn encrypt4_256(rk: &[Self; 15], s: &mut [Self; 4]) {
        unsafe {
            for lane in s.iter_mut() {
                *lane = _mm_xor_si128(*lane, rk[0]);
            }
            for k in &rk[1..14] {
                for lane in s.iter_mut() {
                    *lane = _mm_aesenc_si128(*lane, *k);
                }
            }
            for lane in s.iter_mut() {
                *lane = _mm_aesenclast_si128(*lane, rk[14]);
            }
        }
    }

    #[inline(always)]
    fn encrypt1v_256(rk: &[Self; 15], mut s: Self) -> Self {
        unsafe {
            s = _mm_xor_si128(s, rk[0]);
            for k in &rk[1..14] {
                s = _mm_aesenc_si128(s, *k);
            }
            _mm_aesenclast_si128(s, rk[14])
        }
    }
}

#[inline(always)]
fn assist<const RCON: i32>(k: __m128i) -> __m128i {
    unsafe {
        let t = _mm_shuffle_epi32::<0xff>(_mm_aeskeygenassist_si128::<RCON>(k));
        let k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
        let k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
        let k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
        _mm_xor_si128(k, t)
    }
}

#[inline(always)]
pub(crate) fn expand(key: &[u8; 16]) -> [__m128i; 11] {
    let mut rk = [loadu(key); 11];
    rk[1] = assist::<0x01>(rk[0]);
    rk[2] = assist::<0x02>(rk[1]);
    rk[3] = assist::<0x04>(rk[2]);
    rk[4] = assist::<0x08>(rk[3]);
    rk[5] = assist::<0x10>(rk[4]);
    rk[6] = assist::<0x20>(rk[5]);
    rk[7] = assist::<0x40>(rk[6]);
    rk[8] = assist::<0x80>(rk[7]);
    rk[9] = assist::<0x1b>(rk[8]);
    rk[10] = assist::<0x36>(rk[9]);
    rk
}

impl Engine {
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn rekey(&mut self, key: &[u8; 16]) {
        unsafe { *self = Self::new(key) };
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn new(key: &[u8; 16]) -> Self {
        let rk = expand(key);
        let h = super::powers(&rk);
        Self { rk, h }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        super::seal_impl(&self.rk, &self.h, nonce, aad, buf)
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal_from(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; 16] {
        super::seal_impl_from(&self.rk, &self.h, nonce, aad, src, dst)
    }

    /// Seal `src` into uninitialized `dst` and return the tag.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: *mut u8,
    ) -> [u8; 16] {
        unsafe { super::seal_impl_from_uninit(&self.rk, &self.h, nonce, aad, src, dst) }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        super::open_impl(&self.rk, &self.h, nonce, aad, buf, tag)
    }
}

#[inline(always)]
fn sub_word256(w: u32) -> u32 {
    unsafe {
        let k = _mm_set_epi32(w.rotate_left(8).cast_signed(), 0, 0, 0);
        _mm_extract_epi32::<3>(_mm_aeskeygenassist_si128::<0x00>(k)).cast_unsigned()
    }
}

#[inline(always)]
pub(crate) fn expand256(key: &[u8; 32]) -> [__m128i; 15] {
    const RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    let mut words = [0u32; 60];
    for (i, w) in words[..8].iter_mut().enumerate() {
        *w = u32::from_ne_bytes(key[4 * i..4 * i + 4].try_into().expect("a word is 4 bytes"));
    }
    for i in 8..60 {
        let mut w = words[i - 1];
        if i % 8 == 0 {
            w = sub_word256(w).rotate_right(8) ^ RCON[i / 8 - 1];
        } else if i % 8 == 4 {
            w = sub_word256(w);
        }
        words[i] = words[i - 8] ^ w;
    }
    core::array::from_fn(|r| {
        let mut b = [0u8; 16];
        for (wb, w) in b
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(words[4 * r..4 * r + 4].iter())
        {
            wb.copy_from_slice(&w.to_ne_bytes());
        }
        loadu(&b)
    })
}

pub(crate) struct Engine256 {
    rk: [__m128i; 15],
    h: [(__m128i, __m128i); 4],
}

impl Engine256 {
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn rekey(&mut self, key: &[u8; 32]) {
        unsafe { *self = Self::new(key) };
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn new(key: &[u8; 32]) -> Self {
        let rk = expand256(key);
        let h = super::powers_256(&rk);
        Self { rk, h }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        super::seal_impl_256(&self.rk, &self.h, nonce, aad, buf)
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    /// Seal `src` into `dst` without staging the plaintext, returning the authentication tag.
    pub(crate) unsafe fn seal_from(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> [u8; 16] {
        super::seal_impl_from_256(&self.rk, &self.h, nonce, aad, src, dst)
    }

    /// Seal `src` into uninitialized `dst` and return the tag.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: *mut u8,
    ) -> [u8; 16] {
        unsafe { super::seal_impl_from_256_uninit(&self.rk, &self.h, nonce, aad, src, dst) }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        super::open_impl_256(&self.rk, &self.h, nonce, aad, buf, tag)
    }
}
