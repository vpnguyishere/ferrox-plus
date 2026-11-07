#![allow(
    clippy::inline_always,
    reason = "lane primitives are only sound inside the caller's target_feature function"
)]

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
mod x86v;

use aes_gcm::aead::AeadInOut as _;

#[cfg(target_arch = "aarch64")]
const SHORT_MIN: usize = 256;
#[cfg(target_arch = "aarch64")]
const SHORT_MAX: usize = 512;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn in_short_band(len: usize) -> bool {
    (SHORT_MIN..=SHORT_MAX).contains(&len)
}

pub(crate) trait Lanes: Copy {
    fn load(b: &[u8; 16]) -> Self;
    fn store(self, b: &mut [u8; 16]);
    unsafe fn store_ptr(self, dst: *mut u8);
    fn xor(self, o: Self) -> Self;
    fn bswap(self) -> Self;
    fn swap_halves(self) -> Self;
    fn mul_add(acc: &mut [Self; 4], a: Self, h: Self, hxs: Self);
    fn reduce(acc: [Self; 4]) -> Self;
    fn ctr_add(self, n: u32) -> Self;
    fn ctr_swap(self) -> Self;
    #[inline(always)]
    fn ctr_be(self, n: u32) -> Self {
        self.ctr_add(n).ctr_swap()
    }
    #[inline(always)]
    fn ctr4(self, n: u32) -> [Self; 4] {
        [
            self.ctr_be(n),
            self.ctr_be(n + 1),
            self.ctr_be(n + 2),
            self.ctr_be(n + 3),
        ]
    }
    fn encrypt4(rk: &[Self; 11], s: &mut [Self; 4]);
    fn encrypt1v(rk: &[Self; 11], s: Self) -> Self;
    #[inline(always)]
    fn encrypt1(rk: &[Self; 11], b: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        Self::encrypt1v(rk, Self::load(b)).store(&mut out);
        out
    }
    fn encrypt4_256(rk: &[Self; 15], s: &mut [Self; 4]);
    fn encrypt1v_256(rk: &[Self; 15], s: Self) -> Self;
    #[inline(always)]
    fn encrypt1_256(rk: &[Self; 15], b: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        Self::encrypt1v_256(rk, Self::load(b)).store(&mut out);
        out
    }
}

pub(crate) struct Tail<V> {
    blocks: [V; 4],
    len: usize,
}

impl<V: Lanes> Tail<V> {
    #[inline(always)]
    pub(crate) fn new() -> Self {
        Self {
            blocks: [V::load(&[0u8; 16]); 4],
            len: 0,
        }
    }

    #[inline(always)]
    pub(crate) fn push(&mut self, x: V) {
        self.blocks[self.len] = x;
        self.len += 1;
    }
}

fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;
    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

#[inline(always)]
fn ctr4v<V: Lanes>(template: V, ctr: u32) -> [V; 4] {
    template.ctr4(ctr)
}

#[inline(always)]
pub(crate) fn mul1<V: Lanes>(x: V, h: (V, V)) -> V {
    let mut acc = [V::load(&[0u8; 16]); 4];
    V::mul_add(&mut acc, x, h.0, h.1);
    V::reduce(acc)
}

#[inline(always)]
fn ghash_group<V: Lanes>(h: &[(V, V); 4], x: [V; 4]) -> V {
    let mut acc = [V::load(&[0u8; 16]); 4];
    V::mul_add(&mut acc, x[0], h[3].0, h[3].1);
    V::mul_add(&mut acc, x[1], h[2].0, h[2].1);
    V::mul_add(&mut acc, x[2], h[1].0, h[1].1);
    V::mul_add(&mut acc, x[3], h[0].0, h[0].1);
    V::reduce(acc)
}

#[inline(always)]
pub(crate) fn ghash<V: Lanes>(
    hp: &[(V, V); 4],
    mut state: V,
    data: &[u8],
    tail: &mut Tail<V>,
) -> V {
    let (blocks, rest_bytes) = data.as_chunks::<16>();
    let (groups, rest) = blocks.as_chunks::<4>();
    for quad in groups {
        state = ghash_group(
            hp,
            [
                state.xor(V::load(&quad[0]).bswap()),
                V::load(&quad[1]).bswap(),
                V::load(&quad[2]).bswap(),
                V::load(&quad[3]).bswap(),
            ],
        );
    }
    for blk in rest {
        tail.push(V::load(blk).bswap());
    }
    if !rest_bytes.is_empty() {
        let mut padded = [0u8; 16];
        padded[..rest_bytes.len()].copy_from_slice(rest_bytes);
        tail.push(V::load(&padded).bswap());
    }
    state
}

#[inline(always)]
pub(crate) fn flush<V: Lanes>(hp: &[(V, V); 4], state: V, tail: &mut Tail<V>) -> V {
    if tail.len == 0 {
        return state;
    }
    let qlen = tail.len;
    tail.len = 0;
    let mut acc = [V::load(&[0u8; 16]); 4];
    for (i, blk) in tail.blocks[..qlen].iter().enumerate() {
        let blk = if i == 0 { state.xor(*blk) } else { *blk };
        V::mul_add(&mut acc, blk, hp[qlen - 1 - i].0, hp[qlen - 1 - i].1);
    }
    V::reduce(acc)
}

#[inline(always)]
pub(crate) fn ctr_ghash<V: Lanes>(
    rk: &[V; 11],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    buf: &mut [u8],
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&quad[0])),
            ksv[1].xor(V::load(&quad[1])),
            ksv[2].xor(V::load(&quad[2])),
            ksv[3].xor(V::load(&quad[3])),
        ];
        ct4[0].store(&mut quad[0]);
        ct4[1].store(&mut quad[1]);
        ct4[2].store(&mut quad[2]);
        ct4[3].store(&mut quad[3]);
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        let ct1 = ks1.xor(V::load(blk));
        ct1.store(blk);
        tailq.push(ct1.bswap());
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for ((xb, kb), pb) in tail.iter_mut().zip(ksb.iter()).zip(padded.iter_mut()) {
            let v = *xb ^ kb;
            *xb = v;
            *pb = v;
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

#[inline(always)]
pub(crate) fn ctr_only<V: Lanes>(rk: &[V; 11], template: V, buf: &mut [u8], mut ctr: u32) {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4(rk, &mut ksv);
        for (ks, gi) in ksv.iter().zip(quad.iter_mut()) {
            let ct1 = ks.xor(V::load(gi));
            ct1.store(gi);
        }
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        ks1.xor(V::load(blk)).store(blk);
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        for (xb, kb) in tail.iter_mut().zip(ksb.iter()) {
            *xb ^= kb;
        }
    }
}

#[inline(always)]
pub(crate) fn finish<V: Lanes>(
    hp: &[(V, V); 4],
    mut state: V,
    tailq: &mut Tail<V>,
    aad: u64,
    ct: u64,
    mask: V,
) -> [u8; 16] {
    if tailq.len == 4 {
        state = mul1(state.xor(tailq.blocks[0]), hp[0]);
        tailq.blocks.copy_within(1.., 0);
        tailq.len = 3;
    }
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad * 8).to_be_bytes());
    lens[8..].copy_from_slice(&(ct * 8).to_be_bytes());
    tailq.push(V::load(&lens).bswap());
    let state = flush(hp, state, tailq);
    let mut tag = [0u8; 16];
    state.bswap().xor(mask).store(&mut tag);
    tag
}

#[inline(always)]
fn tag_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    u128::from_ne_bytes(*a) ^ u128::from_ne_bytes(*b) == 0
}

#[inline(always)]
pub(crate) fn counter_template<V: Lanes>(nonce: &[u8; 12]) -> V {
    let mut bytes = [0u8; 16];
    bytes[..12].copy_from_slice(nonce);
    V::load(&bytes)
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn seal_impl<V: Lanes>(
    rk: &[V; 11],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ctr_ghash(rk, h, template, state, buf, &mut tailq, 2);
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        buf.len() as u64,
        mask,
    )
}

/// CTR and GHASH reading `src` and writing `dst`, so a caller that holds plaintext in one buffer and the wire in another never copies between them. `src` and `dst` must not overlap; their lengths are equal.
#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the cipher state, both directions and the deferred tail are the pass, not a bundle"
)]
pub(crate) fn ctr_ghash_from<V: Lanes>(
    rk: &[V; 11],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    src: &[u8],
    dst: &mut [u8],
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
    let (sblocks, stail) = src.as_chunks::<16>();
    let (dblocks, dtail) = dst.as_chunks_mut::<16>();
    let (sgroups, srest) = sblocks.as_chunks::<4>();
    let (dgroups, drest) = dblocks.as_chunks_mut::<4>();
    debug_assert_eq!(sgroups.len(), dgroups.len(), "equal lengths group alike");
    for (sq, dq) in sgroups.iter().zip(dgroups.iter_mut()) {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&sq[0])),
            ksv[1].xor(V::load(&sq[1])),
            ksv[2].xor(V::load(&sq[2])),
            ksv[3].xor(V::load(&sq[3])),
        ];
        ct4[0].store(&mut dq[0]);
        ct4[1].store(&mut dq[1]);
        ct4[2].store(&mut dq[2]);
        ct4[3].store(&mut dq[3]);
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    for (sb, db) in srest.iter().zip(drest.iter_mut()) {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        let ct1 = ks1.xor(V::load(sb));
        ct1.store(db);
        tailq.push(ct1.bswap());
        ctr += 1;
    }
    if !stail.is_empty() {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for (((xb, kb), pb), db) in stail
            .iter()
            .zip(ksb.iter())
            .zip(padded.iter_mut())
            .zip(dtail.iter_mut())
        {
            let v = *xb ^ kb;
            *pb = v;
            *db = v;
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

/// CTR and GHASH reading `src` and writing `len` bytes to `dst`, which may be uninitialized. Every byte is written before this returns.
#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the cipher state, both directions and the deferred tail are the pass, not a bundle"
)]
pub(crate) unsafe fn ctr_ghash_from_uninit<V: Lanes>(
    rk: &[V; 11],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    src: &[u8],
    dst: *mut u8,
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    let (sblocks, stail) = src.as_chunks::<16>();
    let (sgroups, srest) = sblocks.as_chunks::<4>();
    for (group, sq) in sgroups.iter().enumerate() {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&sq[0])),
            ksv[1].xor(V::load(&sq[1])),
            ksv[2].xor(V::load(&sq[2])),
            ksv[3].xor(V::load(&sq[3])),
        ];
        let at = group * 64;
        // SAFETY: the caller guarantees `dst` has room for every byte stored here.
        unsafe {
            V::store_ptr(ct4[0], dst.add(at));
            V::store_ptr(ct4[1], dst.add(at + 16));
            V::store_ptr(ct4[2], dst.add(at + 32));
            V::store_ptr(ct4[3], dst.add(at + 48));
        }
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    let mut at = sgroups.len() * 64;
    for sb in srest {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        let ct1 = ks1.xor(V::load(sb));
        // SAFETY: `at` is inside the `src.len()`-byte destination.
        unsafe { V::store_ptr(ct1, dst.add(at)) };
        tailq.push(ct1.bswap());
        ctr += 1;
        at += 16;
    }
    if !stail.is_empty() {
        let ks1 = V::encrypt1v(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for (i, ((xb, kb), pb)) in stail
            .iter()
            .zip(ksb.iter())
            .zip(padded.iter_mut())
            .enumerate()
        {
            let v = *xb ^ kb;
            *pb = v;
            // SAFETY: the tail starts at `at` and has fewer than 16 bytes left.
            unsafe { std::ptr::write(dst.add(at + i), v) };
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn seal_impl_from<V: Lanes>(
    rk: &[V; 11],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    src: &[u8],
    dst: &mut [u8],
) -> [u8; 16] {
    debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ctr_ghash_from(rk, h, template, state, src, dst, &mut tailq, 2);
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        dst.len() as u64,
        mask,
    )
}

/// Seal `src` into initialization-free `dst` with the fused pass, returning the tag.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn seal_impl_from_uninit<V: Lanes>(
    rk: &[V; 11],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    src: &[u8],
    dst: *mut u8,
) -> [u8; 16] {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    // SAFETY: the caller guarantees `dst` has room for every plaintext byte.
    let state = unsafe { ctr_ghash_from_uninit(rk, h, template, state, src, dst, &mut tailq, 2) };
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        src.len() as u64,
        mask,
    )
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn open_impl<V: Lanes>(
    rk: &[V; 11],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Option<usize> {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ghash(h, state, buf, &mut tailq);
    let want = finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        buf.len() as u64,
        mask,
    );

    if !tag_eq(&want, tag) {
        return None;
    }

    ctr_only(rk, template, buf, 2);
    Some(buf.len())
}

#[inline(always)]
pub(crate) fn powers<V: Lanes>(rk: &[V; 11]) -> [(V, V); 4] {
    let h0 = {
        let mut reversed = V::encrypt1(rk, &[0u8; 16]);
        reversed.reverse();
        V::load(&mulx(&reversed))
    };
    let pair = |h: V| (h, h.xor(h.swap_halves()));
    let h1 = mul1(h0, pair(h0));
    let h2 = mul1(h1, pair(h0));
    let h3 = mul1(h1, pair(h1));
    [pair(h0), pair(h1), pair(h2), pair(h3)]
}

pub struct Aes128Gcm {
    inner: Inner,
}

#[cfg(target_arch = "aarch64")]
struct ArmState {
    engine: arm::Engine,
    short: aes_gcm::Aes128Gcm,
}

enum Inner {
    #[cfg(target_arch = "x86_64")]
    X86V(Box<x86v::Engine>),
    #[cfg(target_arch = "x86_64")]
    X86(Box<x86::Engine>),
    #[cfg(target_arch = "aarch64")]
    Arm(Box<ArmState>),
    Crate(Box<aes_gcm::Aes128Gcm>),
}

impl core::fmt::Debug for Aes128Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes128Gcm")
            .field("backend", &self.backend())
            .finish()
    }
}

/// Whether this machine has a hardware AES-GCM backend; `new` gates on the same predicate and picks which one.
#[must_use]
pub fn has_hardware_support() -> bool {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("aes")
        && std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("ssse3")
    {
        return true;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
        && std::arch::is_aarch64_feature_detected!("neon")
    {
        return true;
    }
    false
}

impl Aes128Gcm {
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        #[cfg(target_arch = "x86_64")]
        if has_hardware_support() {
            if std::is_x86_feature_detected!("avx2")
                && std::is_x86_feature_detected!("vaes")
                && std::is_x86_feature_detected!("vpclmulqdq")
            {
                let engine = unsafe { Box::new(x86v::Engine::new(key)) };
                return Self {
                    inner: Inner::X86V(engine),
                };
            }
            let engine = unsafe { Box::new(x86::Engine::new(key)) };
            return Self {
                inner: Inner::X86(engine),
            };
        }
        #[cfg(target_arch = "aarch64")]
        if has_hardware_support() {
            let engine = unsafe { arm::Engine::new(key) };
            let short =
                aes_gcm::KeyInit::new_from_slice(key).expect("a 16-byte key is valid AES-128");
            return Self {
                inner: Inner::Arm(Box::new(ArmState { engine, short })),
            };
        }
        Self {
            inner: Inner::Crate(Box::new(
                aes_gcm::KeyInit::new_from_slice(key).expect("a 16-byte key is valid AES-128"),
            )),
        }
    }

    /// Rekey in place: the box and the backend pick survive, the schedule and the GHASH powers rebuild, and a caller that rekeys per datagram stops paying an allocation per datagram. The power table depends on the key, so it rebuilds too; what leaves is the `Box` and the probe, not the crypto.
    pub fn rekey(&mut self, key: &[u8; 16]) {
        match &mut self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(e) => unsafe { e.rekey(key) },
            #[cfg(target_arch = "x86_64")]
            Inner::X86(e) => unsafe { e.rekey(key) },
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(e) => {
                unsafe { e.engine.rekey(key) };
                e.short =
                    aes_gcm::KeyInit::new_from_slice(key).expect("a 16-byte key is valid AES-128");
            }
            Inner::Crate(c) => {
                **c =
                    aes_gcm::KeyInit::new_from_slice(key).expect("a 16-byte key is valid AES-128");
            }
        }
    }

    #[must_use]
    pub const fn backend(&self) -> &'static str {
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(_) => "vaes-256 + vpclmulqdq, fused 8-block, deferred reduction",
            #[cfg(target_arch = "x86_64")]
            Inner::X86(_) => "aes-ni + pclmulqdq, fused 4-block, deferred reduction",
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(..) => "armv8 aes + pmull, fused outside the 256..=512 B band, crate in it",
            Inner::Crate(_) => "aes-gcm 0.10 (crate fallback)",
        }
    }

    #[cfg_attr(target_arch = "aarch64", inline)]
    #[must_use]
    pub fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(e) => unsafe { e.seal(nonce, aad, buf) },
            #[cfg(target_arch = "x86_64")]
            Inner::X86(e) => unsafe { e.seal(nonce, aad, buf) },
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(e) => {
                if in_short_band(buf.len()) {
                    e.short
                        .encrypt_inout_detached(
                            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                            aad,
                            (&mut buf[..]).into(),
                        )
                        .expect("the length limits above are the crate's own refusal conditions")
                        .into()
                } else {
                    unsafe { e.engine.seal(nonce, aad, buf) }
                }
            }
            Inner::Crate(c) => c
                .encrypt_inout_detached(
                    &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                    aad,
                    (&mut buf[..]).into(),
                )
                .expect("the length limits above are the crate's own refusal conditions")
                .into(),
        }
    }

    /// Seal `src` into `dst` without a staging copy: the CTR pass reads plaintext and writes ciphertext where the caller wants it, and GHASH authenticates the bytes it just wrote. `src` and `dst` must be equal-length and must not overlap.
    #[must_use]
    pub fn seal_from(&self, nonce: &[u8; 12], aad: &[u8], src: &[u8], dst: &mut [u8]) -> [u8; 16] {
        assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        assert!(
            (dst.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(e) => unsafe { e.seal_from(nonce, aad, src, dst) },
            #[cfg(target_arch = "x86_64")]
            Inner::X86(e) => unsafe { e.seal_from(nonce, aad, src, dst) },
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(e) => {
                if in_short_band(src.len()) {
                    dst.copy_from_slice(src);
                    e.short
                        .encrypt_inout_detached(
                            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                            aad,
                            (&mut dst[..]).into(),
                        )
                        .expect("the length limits above are the crate's own refusal conditions")
                        .into()
                } else {
                    unsafe { e.engine.seal_from(nonce, aad, src, dst) }
                }
            }
            Inner::Crate(_) => {
                dst.copy_from_slice(src);
                self.seal_in_place(nonce, aad, dst)
            }
        }
    }

    /// Seal `src` into `dst`, which may be uninitialized, returning the tag. Every byte of `dst` is written before this returns.
    #[cfg_attr(target_arch = "aarch64", inline)]
    #[must_use]
    pub fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [std::mem::MaybeUninit<u8>],
    ) -> [u8; 16] {
        assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        assert!(
            (dst.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(e) => unsafe {
                e.seal_from_uninit(nonce, aad, src, dst.as_mut_ptr().cast())
            },
            #[cfg(target_arch = "x86_64")]
            Inner::X86(e) => unsafe {
                e.seal_from_uninit(nonce, aad, src, dst.as_mut_ptr().cast())
            },
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(e) => unsafe {
                e.engine
                    .seal_from_uninit(nonce, aad, src, dst.as_mut_ptr().cast())
            },
            Inner::Crate(_) => {
                for (d, s) in dst.iter_mut().zip(src) {
                    d.write(*s);
                }
                // SAFETY: every byte was initialized by writing the plaintext above.
                let dst = unsafe {
                    std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), dst.len())
                };
                self.seal_in_place(nonce, aad, dst)
            }
        }
    }

    #[must_use]
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM ciphertext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(e) => unsafe { e.open(nonce, aad, buf, tag) },
            #[cfg(target_arch = "x86_64")]
            Inner::X86(e) => unsafe { e.open(nonce, aad, buf, tag) },
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(e) => {
                if in_short_band(buf.len()) {
                    e.short
                        .decrypt_inout_detached(
                            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                            aad,
                            (&mut buf[..]).into(),
                            &aes_gcm::Tag::try_from(&tag[..]).expect("length"),
                        )
                        .ok()?;
                    Some(buf.len())
                } else {
                    unsafe { e.engine.open(nonce, aad, buf, tag) }
                }
            }
            Inner::Crate(c) => {
                c.decrypt_inout_detached(
                    &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                    aad,
                    (&mut buf[..]).into(),
                    &aes_gcm::Tag::try_from(&tag[..]).expect("length"),
                )
                .ok()?;
                Some(buf.len())
            }
        }
    }
}

#[inline(always)]
pub(crate) fn powers_256<V: Lanes>(rk: &[V; 15]) -> [(V, V); 4] {
    let h0 = {
        let mut reversed = V::encrypt1_256(rk, &[0u8; 16]);
        reversed.reverse();
        V::load(&mulx(&reversed))
    };
    let pair = |h: V| (h, h.xor(h.swap_halves()));
    let h1 = mul1(h0, pair(h0));
    let h2 = mul1(h1, pair(h0));
    let h3 = mul1(h1, pair(h1));
    [pair(h0), pair(h1), pair(h2), pair(h3)]
}

#[inline(always)]
pub(crate) fn ctr_ghash_256<V: Lanes>(
    rk: &[V; 15],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    buf: &mut [u8],
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4_256(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&quad[0])),
            ksv[1].xor(V::load(&quad[1])),
            ksv[2].xor(V::load(&quad[2])),
            ksv[3].xor(V::load(&quad[3])),
        ];
        ct4[0].store(&mut quad[0]);
        ct4[1].store(&mut quad[1]);
        ct4[2].store(&mut quad[2]);
        ct4[3].store(&mut quad[3]);
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        let ct1 = ks1.xor(V::load(blk));
        ct1.store(blk);
        tailq.push(ct1.bswap());
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for ((xb, kb), pb) in tail.iter_mut().zip(ksb.iter()).zip(padded.iter_mut()) {
            let v = *xb ^ kb;
            *xb = v;
            *pb = v;
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

/// CTR and GHASH reading `src` and writing `dst`, so a caller that holds plaintext in one buffer and the wire in another never copies between them. `src` and `dst` must not overlap; their lengths are equal.
#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the cipher state, both directions and the deferred tail are the pass, not a bundle"
)]
pub(crate) fn ctr_ghash_from_256<V: Lanes>(
    rk: &[V; 15],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    src: &[u8],
    dst: &mut [u8],
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
    let (sblocks, stail) = src.as_chunks::<16>();
    let (dblocks, dtail) = dst.as_chunks_mut::<16>();
    let (sgroups, srest) = sblocks.as_chunks::<4>();
    let (dgroups, drest) = dblocks.as_chunks_mut::<4>();
    debug_assert_eq!(sgroups.len(), dgroups.len(), "equal lengths group alike");
    for (sq, dq) in sgroups.iter().zip(dgroups.iter_mut()) {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4_256(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&sq[0])),
            ksv[1].xor(V::load(&sq[1])),
            ksv[2].xor(V::load(&sq[2])),
            ksv[3].xor(V::load(&sq[3])),
        ];
        ct4[0].store(&mut dq[0]);
        ct4[1].store(&mut dq[1]);
        ct4[2].store(&mut dq[2]);
        ct4[3].store(&mut dq[3]);
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    for (sb, db) in srest.iter().zip(drest.iter_mut()) {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        let ct1 = ks1.xor(V::load(sb));
        ct1.store(db);
        tailq.push(ct1.bswap());
        ctr += 1;
    }
    if !stail.is_empty() {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for (((xb, kb), pb), db) in stail
            .iter()
            .zip(ksb.iter())
            .zip(padded.iter_mut())
            .zip(dtail.iter_mut())
        {
            let v = *xb ^ kb;
            *pb = v;
            *db = v;
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

/// CTR and GHASH reading `src` and writing `len` bytes to `dst`, which may be uninitialized. Every byte is written before this returns.
#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the cipher state, both directions and the deferred tail are the pass, not a bundle"
)]
pub(crate) unsafe fn ctr_ghash_from_256_uninit<V: Lanes>(
    rk: &[V; 15],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    src: &[u8],
    dst: *mut u8,
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    let (sblocks, stail) = src.as_chunks::<16>();
    let (sgroups, srest) = sblocks.as_chunks::<4>();
    for (group, sq) in sgroups.iter().enumerate() {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4_256(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&sq[0])),
            ksv[1].xor(V::load(&sq[1])),
            ksv[2].xor(V::load(&sq[2])),
            ksv[3].xor(V::load(&sq[3])),
        ];
        let at = group * 64;
        // SAFETY: the caller guarantees `dst` has room for every byte stored here.
        unsafe {
            V::store_ptr(ct4[0], dst.add(at));
            V::store_ptr(ct4[1], dst.add(at + 16));
            V::store_ptr(ct4[2], dst.add(at + 32));
            V::store_ptr(ct4[3], dst.add(at + 48));
        }
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    let mut at = sgroups.len() * 64;
    for sb in srest {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        let ct1 = ks1.xor(V::load(sb));
        // SAFETY: `at` is inside the `src.len()`-byte destination.
        unsafe { V::store_ptr(ct1, dst.add(at)) };
        tailq.push(ct1.bswap());
        ctr += 1;
        at += 16;
    }
    if !stail.is_empty() {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for (i, ((xb, kb), pb)) in stail
            .iter()
            .zip(ksb.iter())
            .zip(padded.iter_mut())
            .enumerate()
        {
            let v = *xb ^ kb;
            *pb = v;
            // SAFETY: the tail starts at `at` and has fewer than 16 bytes left.
            unsafe { std::ptr::write(dst.add(at + i), v) };
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

#[inline(always)]
pub(crate) fn ctr_only_256<V: Lanes>(rk: &[V; 15], template: V, buf: &mut [u8], mut ctr: u32) {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4_256(rk, &mut ksv);
        for (ks, gi) in ksv.iter().zip(quad.iter_mut()) {
            let ct1 = ks.xor(V::load(gi));
            ct1.store(gi);
        }
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        ks1.xor(V::load(blk)).store(blk);
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v_256(rk, template.ctr_be(ctr));
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        for (xb, kb) in tail.iter_mut().zip(ksb.iter()) {
            *xb ^= kb;
        }
    }
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn seal_impl_256<V: Lanes>(
    rk: &[V; 15],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v_256(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ctr_ghash_256(rk, h, template, state, buf, &mut tailq, 2);
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        buf.len() as u64,
        mask,
    )
}

/// Seal `src` into `dst` with the fused CTR/GHASH pass, returning the authentication tag.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn seal_impl_from_256<V: Lanes>(
    rk: &[V; 15],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    src: &[u8],
    dst: &mut [u8],
) -> [u8; 16] {
    debug_assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v_256(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ctr_ghash_from_256(rk, h, template, state, src, dst, &mut tailq, 2);
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        dst.len() as u64,
        mask,
    )
}

/// Seal `src` into initialization-free `dst` with the fused pass, returning the tag.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn seal_impl_from_256_uninit<V: Lanes>(
    rk: &[V; 15],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    src: &[u8],
    dst: *mut u8,
) -> [u8; 16] {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v_256(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    // SAFETY: the caller guarantees `dst` has room for every plaintext byte.
    let state =
        unsafe { ctr_ghash_from_256_uninit(rk, h, template, state, src, dst, &mut tailq, 2) };
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        src.len() as u64,
        mask,
    )
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn open_impl_256<V: Lanes>(
    rk: &[V; 15],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Option<usize> {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v_256(rk, template.ctr_be(1));
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ghash(h, state, buf, &mut tailq);
    let want = finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        buf.len() as u64,
        mask,
    );
    if !tag_eq(&want, tag) {
        return None;
    }
    ctr_only_256(rk, template, buf, 2);
    Some(buf.len())
}

pub struct Aes256Gcm {
    inner: Inner256,
}

#[cfg(target_arch = "aarch64")]
struct ArmState256 {
    engine: arm::Engine256,
    short: aes_gcm::Aes256Gcm,
}

enum Inner256 {
    #[cfg(target_arch = "x86_64")]
    X86V(Box<x86v::Engine256>),
    #[cfg(target_arch = "x86_64")]
    X86(Box<x86::Engine256>),
    #[cfg(target_arch = "aarch64")]
    Arm(Box<ArmState256>),
    Crate(Box<aes_gcm::Aes256Gcm>),
}

impl core::fmt::Debug for Aes256Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes256Gcm")
            .field("backend", &self.backend())
            .finish()
    }
}

impl Aes256Gcm {
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("avx2")
            && std::is_x86_feature_detected!("vaes")
            && std::is_x86_feature_detected!("vpclmulqdq")
            && std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            let engine = unsafe { Box::new(x86v::Engine256::new(key)) };
            return Self {
                inner: Inner256::X86V(engine),
            };
        }
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            let engine = unsafe { Box::new(x86::Engine256::new(key)) };
            return Self {
                inner: Inner256::X86(engine),
            };
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
            && std::arch::is_aarch64_feature_detected!("neon")
        {
            let engine = unsafe { arm::Engine256::new(key) };
            let short =
                aes_gcm::KeyInit::new_from_slice(key).expect("a 32-byte key is valid AES-256");
            return Self {
                inner: Inner256::Arm(Box::new(ArmState256 { engine, short })),
            };
        }
        Self {
            inner: Inner256::Crate(Box::new(
                aes_gcm::KeyInit::new_from_slice(key).expect("a 32-byte key is valid AES-256"),
            )),
        }
    }

    /// Rekey in place: the box and the backend pick survive, the schedule and the GHASH powers rebuild, and a caller that rekeys per datagram stops paying an allocation per datagram. The power table depends on the key, so it rebuilds too; what leaves is the `Box` and the probe, not the crypto.
    pub fn rekey(&mut self, key: &[u8; 32]) {
        match &mut self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(e) => unsafe { e.rekey(key) },
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(e) => unsafe { e.rekey(key) },
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(e) => {
                unsafe { e.engine.rekey(key) };
                e.short =
                    aes_gcm::KeyInit::new_from_slice(key).expect("a 32-byte key is valid AES-256");
            }
            Inner256::Crate(c) => {
                **c =
                    aes_gcm::KeyInit::new_from_slice(key).expect("a 32-byte key is valid AES-256");
            }
        }
    }

    #[must_use]
    pub const fn backend(&self) -> &'static str {
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(_) => "vaes-256 + vpclmulqdq, fused 8-block, deferred reduction",
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(_) => "aes-ni + pclmulqdq, fused 4-block, deferred reduction",
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(..) => {
                "armv8 aes + pmull, fused outside the 256..=512 B band, crate in it"
            }
            Inner256::Crate(_) => "aes-gcm 0.10 (crate fallback)",
        }
    }

    #[cfg_attr(target_arch = "aarch64", inline)]
    #[must_use]
    pub fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(e) => unsafe { e.seal(nonce, aad, buf) },
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(e) => unsafe { e.seal(nonce, aad, buf) },
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(e) => {
                if in_short_band(buf.len()) {
                    e.short
                        .encrypt_inout_detached(
                            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                            aad,
                            (&mut buf[..]).into(),
                        )
                        .expect("the length limits above are the crate's own refusal conditions")
                        .into()
                } else {
                    unsafe { e.engine.seal(nonce, aad, buf) }
                }
            }
            Inner256::Crate(c) => c
                .encrypt_inout_detached(
                    &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                    aad,
                    (&mut buf[..]).into(),
                )
                .expect("the length limits above are the crate's own refusal conditions")
                .into(),
        }
    }

    /// Seal `src` into `dst` without a staging copy: the CTR pass reads plaintext and writes ciphertext where the caller wants it, and GHASH authenticates the bytes it just wrote. `src` and `dst` must be equal-length and must not overlap.
    #[must_use]
    pub fn seal_from(&self, nonce: &[u8; 12], aad: &[u8], src: &[u8], dst: &mut [u8]) -> [u8; 16] {
        assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        assert!(
            (dst.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(e) => unsafe { e.seal_from(nonce, aad, src, dst) },
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(e) => unsafe { e.seal_from(nonce, aad, src, dst) },
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(e) => {
                if in_short_band(src.len()) {
                    dst.copy_from_slice(src);
                    e.short
                        .encrypt_inout_detached(
                            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                            aad,
                            (&mut dst[..]).into(),
                        )
                        .expect("the length limits above are the crate's own refusal conditions")
                        .into()
                } else {
                    unsafe { e.engine.seal_from(nonce, aad, src, dst) }
                }
            }
            Inner256::Crate(_) => {
                dst.copy_from_slice(src);
                self.seal_in_place(nonce, aad, dst)
            }
        }
    }

    /// Seal `src` into `dst`, which may be uninitialized, returning the tag. Every byte of `dst` is written before this returns.
    #[must_use]
    pub fn seal_from_uninit(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        src: &[u8],
        dst: &mut [std::mem::MaybeUninit<u8>],
    ) -> [u8; 16] {
        assert_eq!(src.len(), dst.len(), "one ciphertext for one plaintext");
        assert!(
            (dst.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(e) => unsafe {
                e.seal_from_uninit(nonce, aad, src, dst.as_mut_ptr().cast())
            },
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(e) => unsafe {
                e.seal_from_uninit(nonce, aad, src, dst.as_mut_ptr().cast())
            },
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(e) => {
                if in_short_band(src.len()) {
                    for (d, s) in dst.iter_mut().zip(src) {
                        d.write(*s);
                    }
                    // SAFETY: every byte was initialized by writing the plaintext above.
                    let dst = unsafe {
                        std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), dst.len())
                    };
                    e.short
                        .encrypt_inout_detached(
                            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                            aad,
                            (&mut dst[..]).into(),
                        )
                        .expect("the length limits above are the crate's own refusal conditions")
                        .into()
                } else {
                    unsafe {
                        e.engine
                            .seal_from_uninit(nonce, aad, src, dst.as_mut_ptr().cast())
                    }
                }
            }
            Inner256::Crate(_) => {
                for (d, s) in dst.iter_mut().zip(src) {
                    d.write(*s);
                }
                // SAFETY: every byte was initialized by writing the plaintext above.
                let dst = unsafe {
                    std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), dst.len())
                };
                self.seal_in_place(nonce, aad, dst)
            }
        }
    }

    #[cfg_attr(target_arch = "aarch64", inline)]
    #[must_use]
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM ciphertext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(e) => unsafe { e.open(nonce, aad, buf, tag) },
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(e) => unsafe { e.open(nonce, aad, buf, tag) },
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(e) => {
                if in_short_band(buf.len()) {
                    e.short
                        .decrypt_inout_detached(
                            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                            aad,
                            (&mut buf[..]).into(),
                            &aes_gcm::Tag::try_from(&tag[..]).expect("length"),
                        )
                        .ok()?;
                    Some(buf.len())
                } else {
                    unsafe { e.engine.open(nonce, aad, buf, tag) }
                }
            }
            Inner256::Crate(c) => {
                c.decrypt_inout_detached(
                    &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                    aad,
                    (&mut buf[..]).into(),
                    &aes_gcm::Tag::try_from(&tag[..]).expect("length"),
                )
                .ok()?;
                Some(buf.len())
            }
        }
    }
}

/// The length set the differential sweeps walk: dense natively, a representative subset under Miri, whose interpretive AES-GCM rounds cannot finish the full sweep inside the shard's budget.
#[cfg(test)]
fn sweep_lengths() -> Vec<usize> {
    if cfg!(miri) {
        vec![
            0, 1, 15, 16, 17, 63, 64, 65, 111, 112, 113, 300, 511, 512, 513,
        ]
    } else {
        (0..=300)
            .chain([511, 512, 513, 1024, 1400, 4096, 8171, 16383])
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::KeyInit as _;

    fn crate_seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .expect("key")
            .encrypt_inout_detached(
                &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                aad,
                (&mut buf[..]).into(),
            )
            .expect("seals")
            .into()
    }

    #[test]
    fn the_gcm_spec_vectors() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let engine = Aes128Gcm::new(&key);

        let tag = engine.seal_in_place(&nonce, &[], &mut []);
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ],
            "test case 1: the empty message's tag"
        );

        let mut buf = [0u8; 16];
        let tag = engine.seal_in_place(&nonce, &[], &mut buf);
        assert_eq!(
            buf,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78
            ],
            "test case 2: one zero block's ciphertext"
        );
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf
            ],
            "test case 2: one zero block's tag"
        );
    }

    #[test]
    fn the_gcm_spec_vector_with_aad() {
        let key: [u8; 16] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let plain: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let want_ct: [u8; 60] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91,
        ];
        let want_tag = [
            0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12,
            0x1a, 0x47,
        ];
        let engine = Aes128Gcm::new(&key);
        let mut buf = plain;
        let tag = engine.seal_in_place(&nonce, &aad, &mut buf);
        assert_eq!(buf, want_ct, "the spec vector's ciphertext");
        assert_eq!(tag, want_tag, "the spec vector's tag");
        assert_eq!(
            engine.open_in_place(&nonce, &aad, &mut buf, &tag),
            Some(60),
            "the spec vector opens"
        );
        assert_eq!(buf, plain, "and opens to the spec's plaintext");
    }

    #[test]
    fn is_byte_identical_to_the_crate_it_replaces() {
        let keys: [[u8; 16]; 2] = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let mut checked = 0usize;
        for key in &keys {
            let engine = Aes128Gcm::new(key);
            for nonce in [[0u8; 12], [0xa7u8; 12], [0xffu8; 12]] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                    for len in sweep_lengths() {
                        let plain: Vec<u8> = (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect();
                        let mut buf = plain.clone();
                        let tag = engine.seal_in_place(&nonce, &aad, &mut buf);

                        let mut want = plain.clone();
                        let want_tag = crate_seal(key, &nonce, &aad, &mut want);
                        assert_eq!(
                            buf, want,
                            "ciphertext: key {key:02x?} nonce {nonce:02x?} aad {aad_len} len {len}"
                        );
                        assert_eq!(tag, want_tag, "tag: aad {aad_len} len {len}");

                        let mut opened = want.clone();
                        assert_eq!(
                            engine.open_in_place(&nonce, &aad, &mut opened, &want_tag),
                            Some(len),
                            "ours opens the crate's seal at len {len}"
                        );
                        assert_eq!(opened, plain, "len {len} round trips");
                        let mut crate_opened = buf.clone();
                        assert!(
                            aes_gcm::Aes128Gcm::new_from_slice(key)
                                .expect("key")
                                .decrypt_inout_detached(
                                    &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                                    &aad,
                                    (&mut crate_opened[..]).into(),
                                    &aes_gcm::Tag::try_from(&tag[..]).expect("length"),
                                )
                                .is_ok(),
                            "the crate opens ours at len {len}"
                        );
                        assert_eq!(crate_opened, plain, "len {len} round trips the crate");
                        checked += 1;
                    }
                }
            }
        }
        if cfg!(not(miri)) {
            assert!(checked > 5_000, "the native sweep is dense, not a sample");
        }
    }

    #[test]
    fn sealing_from_a_source_writes_the_same_bytes_and_leaves_the_source_alone() {
        let keys: [[u8; 16]; 2] = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let nonce = [0x5au8; 12];
        let mut checked = 0usize;
        for key in &keys {
            let engine = Aes128Gcm::new(key);
            for aad_len in [0usize, 16] {
                let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                for len in sweep_lengths() {
                    let plain: Vec<u8> = (0..len)
                        .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                        .collect();
                    let mut in_place = plain.clone();
                    let want = engine.seal_in_place(&nonce, &aad, &mut in_place);
                    let mut dst = vec![0xa5u8; len];
                    let tag = engine.seal_from(&nonce, &aad, &plain, &mut dst);
                    assert_eq!(tag, want, "tag: aad {aad_len} len {len}");
                    assert_eq!(dst, in_place, "ciphertext: aad {aad_len} len {len}");
                    let mut uninit = vec![std::mem::MaybeUninit::new(0xa5u8); len];
                    let tag = engine.seal_from_uninit(&nonce, &aad, &plain, &mut uninit);
                    assert_eq!(tag, want, "uninit tag: aad {aad_len} len {len}");
                    // SAFETY: seal_from_uninit wrote every byte of the destination.
                    let uninit = unsafe {
                        std::slice::from_raw_parts(uninit.as_ptr().cast::<u8>(), uninit.len())
                    };
                    assert_eq!(
                        uninit, in_place,
                        "uninit ciphertext: aad {aad_len} len {len}"
                    );
                    assert_eq!(
                        plain,
                        (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect::<Vec<u8>>(),
                        "seal_from must not touch the plaintext: aad {aad_len} len {len}"
                    );
                    checked += 1;
                }
            }
        }
        if cfg!(not(miri)) {
            assert!(checked > 900, "the native sweep is dense, not a sample");
        }
    }

    #[test]
    fn a_forged_tag_is_refused_and_nothing_is_decrypted() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let engine = Aes128Gcm::new(&key);
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut buf = plain.clone();
            let tag = engine.seal_in_place(&nonce, b"", &mut buf);
            let ciphertext = buf.clone();
            let mut bad = tag;
            bad[0] ^= 1;
            assert_eq!(
                engine.open_in_place(&nonce, b"", &mut buf, &bad),
                None,
                "length {len} refuses a changed tag"
            );
            assert_eq!(
                buf, ciphertext,
                "length {len}: a wrong tag must not decrypt"
            );
        }
    }

    #[test]
    fn aad_is_authenticated() {
        let key = [0x55u8; 16];
        let nonce = [0x66u8; 12];
        let engine = Aes128Gcm::new(&key);
        let mut buf = b"payload".to_vec();
        let tag = engine.seal_in_place(&nonce, b"one", &mut buf);
        assert_eq!(
            engine.open_in_place(&nonce, b"two", &mut buf, &tag),
            None,
            "the tag must not verify under a different aad"
        );
    }

    #[test]
    fn the_crate_fallback_agrees_with_the_dispatch() {
        let key = [0x77u8; 16];
        let nonce = [0x88u8; 12];
        let dispatched = Aes128Gcm::new(&key);
        let fallback = Aes128Gcm {
            inner: Inner::Crate(Box::new(
                aes_gcm::KeyInit::new_from_slice(&key).expect("key"),
            )),
        };
        for len in [0usize, 1, 64, 65, 512] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut a = plain.clone();
            let mut b = plain;
            let ta = dispatched.seal_in_place(&nonce, b"ad", &mut a);
            let tb = fallback.seal_in_place(&nonce, b"ad", &mut b);
            assert_eq!((a, ta), (b, tb), "len {len}: dispatch and fallback agree");
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn both_x86_engines_agree_with_the_crate() {
        if !(std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3"))
        {
            return;
        }
        let key: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(61).wrapping_add(9));
        let nonce = [0xc3u8; 12];
        let narrow = unsafe { x86::Engine::new(&key) };
        let wide = if std::is_x86_feature_detected!("avx2")
            && std::is_x86_feature_detected!("vaes")
            && std::is_x86_feature_detected!("vpclmulqdq")
        {
            Some(unsafe { x86v::Engine::new(&key) })
        } else {
            None
        };

        for len in (0..=260usize).chain([511, 512, 513, 1024, 4096]) {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(29)).collect();
            let aad: Vec<u8> = (0..len % 40).map(|i| (i as u8).wrapping_mul(3)).collect();
            let mut want = plain.clone();
            let want_tag = crate_seal(&key, &nonce, &aad, &mut want);

            let mut got = plain.clone();
            let got_tag = unsafe { narrow.seal(&nonce, &aad, &mut got) };
            assert_eq!(got, want, "128-bit engine, len {len}");
            assert_eq!(got_tag, want_tag, "128-bit engine tag, len {len}");

            if let Some(wide) = &wide {
                let mut got = plain;
                let got_tag = unsafe { wide.seal(&nonce, &aad, &mut got) };
                assert_eq!(got, want, "256-bit engine, len {len}");
                assert_eq!(got_tag, want_tag, "256-bit engine tag, len {len}");
            }
        }
    }
}

#[cfg(test)]
mod tests_aes256 {
    use super::*;
    use aes_gcm::KeyInit as _;

    fn crate_seal256(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .expect("key")
            .encrypt_inout_detached(
                &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                aad,
                (&mut buf[..]).into(),
            )
            .expect("seals")
            .into()
    }

    /// The source seal writes the same bytes as the in-place seal and leaves its input alone.
    #[test]
    fn sealing_256_from_a_source_writes_the_same_bytes_and_leaves_the_source_alone() {
        let keys: [[u8; 32]; 2] = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let nonce = [0x5au8; 12];
        let mut checked = 0usize;
        for key in &keys {
            let engine = Aes256Gcm::new(key);
            for aad_len in [0usize, 16] {
                let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                for len in sweep_lengths() {
                    let plain: Vec<u8> = (0..len)
                        .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                        .collect();
                    let mut in_place = plain.clone();
                    let want = engine.seal_in_place(&nonce, &aad, &mut in_place);
                    let mut dst = vec![0xa5u8; len];
                    let tag = engine.seal_from(&nonce, &aad, &plain, &mut dst);
                    assert_eq!(tag, want, "tag: aad {aad_len} len {len}");
                    assert_eq!(dst, in_place, "ciphertext: aad {aad_len} len {len}");
                    let mut uninit = vec![std::mem::MaybeUninit::new(0xa5u8); len];
                    let tag = engine.seal_from_uninit(&nonce, &aad, &plain, &mut uninit);
                    assert_eq!(tag, want, "uninit tag: aad {aad_len} len {len}");
                    // SAFETY: seal_from_uninit wrote every byte of the destination.
                    let uninit = unsafe {
                        std::slice::from_raw_parts(uninit.as_ptr().cast::<u8>(), uninit.len())
                    };
                    assert_eq!(
                        uninit, in_place,
                        "uninit ciphertext: aad {aad_len} len {len}"
                    );
                    assert_eq!(
                        plain,
                        (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect::<Vec<u8>>(),
                        "seal_from must not touch the plaintext: aad {aad_len} len {len}"
                    );
                    checked += 1;
                }
            }
        }
        if cfg!(not(miri)) {
            assert!(checked > 900, "the native sweep is dense, not a sample");
        }
    }

    #[test]
    fn the_gcm_spec_vector_for_256() {
        let engine = Aes256Gcm::new(&[0u8; 32]);
        let tag = engine.seal_in_place(&[0u8; 12], &[], &mut []);
        assert_eq!(
            tag,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b
            ],
            "all-zero key and nonce, empty message"
        );
    }

    #[test]
    fn is_byte_identical_to_the_crate_it_replaces() {
        let keys: [[u8; 32]; 2] = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let mut checked = 0usize;
        for key in &keys {
            let engine = Aes256Gcm::new(key);
            for nonce in [[0u8; 12], [0xa7u8; 12], [0xffu8; 12]] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                    for len in sweep_lengths() {
                        let plain: Vec<u8> = (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect();
                        let mut buf = plain.clone();
                        let tag = engine.seal_in_place(&nonce, &aad, &mut buf);

                        let mut want = plain.clone();
                        let want_tag = crate_seal256(key, &nonce, &aad, &mut want);
                        assert_eq!(buf, want, "ciphertext: aad {aad_len} len {len}");
                        assert_eq!(tag, want_tag, "tag: aad {aad_len} len {len}");

                        let mut opened = want.clone();
                        assert_eq!(
                            engine.open_in_place(&nonce, &aad, &mut opened, &want_tag),
                            Some(len),
                            "ours opens the crate's seal at len {len}"
                        );
                        assert_eq!(opened, plain, "len {len} round trips");
                        let mut crate_opened = buf.clone();
                        assert!(
                            aes_gcm::Aes256Gcm::new_from_slice(key)
                                .expect("key")
                                .decrypt_inout_detached(
                                    &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
                                    &aad,
                                    (&mut crate_opened[..]).into(),
                                    &aes_gcm::Tag::try_from(&tag[..]).expect("length"),
                                )
                                .is_ok(),
                            "the crate opens ours at len {len}"
                        );
                        assert_eq!(crate_opened, plain, "len {len} round trips the crate");
                        checked += 1;
                    }
                }
            }
        }
        if cfg!(not(miri)) {
            assert!(checked > 5_000, "the native sweep is dense, not a sample");
        }
    }
}
