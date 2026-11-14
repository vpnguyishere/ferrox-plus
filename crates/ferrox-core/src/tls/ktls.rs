//! Linux kTLS: hand the record layer to the kernel after a TLS 1.3 handshake.

use crate::tls::shaped::kdf::{self, Hash};
use std::io;

use crate::tls::RawFd;

/// A cipher the kernel can drive. TLS 1.2 suites never reach here: kTLS needs 1.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Cipher {
    #[cfg(target_os = "linux")]
    const fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 51,
            Self::Aes256Gcm => 52,
            Self::ChaCha20Poly1305 => 54,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    #[cfg(target_os = "linux")]
    const fn salt_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 4,
            Self::ChaCha20Poly1305 => 0,
        }
    }

    #[cfg(target_os = "linux")]
    const fn iv_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 8,
            Self::ChaCha20Poly1305 => 12,
        }
    }
}

/// One direction's current traffic secret and record counter.
#[derive(Clone)]
pub(crate) struct Material {
    pub(crate) cipher: Cipher,
    pub(crate) hash: Hash,
    pub(crate) secret: Vec<u8>,
    pub(crate) seq: u64,
}

impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Material")
            .field("cipher", &self.cipher)
            .field("hash", &self.hash)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// The `key`/`iv` pair of a TLS 1.3 traffic secret.
#[cfg(target_os = "linux")]
struct Keys {
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

/// `HKDF-Expand-Label(secret, "key"/"iv", "", ...)` for one direction.
#[cfg(target_os = "linux")]
fn keys(material: &Material) -> Keys {
    let mut key = vec![0u8; material.cipher.key_len()];
    kdf::expand_label(material.hash, &material.secret, b"key", b"", &mut key);
    let mut iv = [0u8; 12];
    kdf::expand_label(material.hash, &material.secret, b"iv", b"", &mut iv);
    Keys {
        key,
        iv,
        seq: material.seq,
    }
}

/// The next traffic secret a `KeyUpdate` installs.
pub(crate) fn next_secret(material: &Material) -> Material {
    let mut secret = vec![0u8; material.hash.len()];
    kdf::expand_label(
        material.hash,
        &material.secret,
        b"traffic upd",
        b"",
        &mut secret,
    );
    Material {
        cipher: material.cipher,
        hash: material.hash,
        secret,
        seq: 0,
    }
}

/// The kernel record layer a session owns once TX or RX is offloaded.
#[derive(Debug)]
pub(crate) struct Ktls {
    #[cfg(target_os = "linux")]
    fd: RawFd,
    tx: Option<Material>,
    rx: Option<Material>,
    stage: Vec<u8>,
}

impl Ktls {
    /// Installs the offload on a socket that has finished its TLS 1.3 handshake.
    ///
    /// On a host without the Linux kernel interface this fails: a config that asks
    /// for kernel encryption has no user-space fallback, and pretending otherwise
    /// would send bytes the reference never sends.
    pub(crate) fn install(
        fd: RawFd,
        tx: Option<Material>,
        rx: Option<Material>,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut ktls = Self {
                fd,
                tx: None,
                rx: None,
                stage: vec![0u8; 16384 + 256],
            };
            set_ulp(fd)?;
            if let Some(material) = tx {
                install_key(fd, TLS_TX, &material)?;
                ktls.tx = Some(material);
            }
            if let Some(material) = rx {
                install_key(fd, TLS_RX, &material)?;
                ktls.rx = Some(material);
                let one: libc::c_int = 1;
                // An optimisation, not a correctness switch: an older kernel still decrypts.
                unsafe {
                    libc::setsockopt(
                        fd,
                        SOL_TLS,
                        TLS_RX_EXPECT_NO_PAD,
                        (&raw const one).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
            Ok(ktls)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (fd, tx, rx);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// Whether TX records are encrypted by the kernel.
    pub(crate) fn tx_offloaded(&self) -> bool {
        self.tx.is_some()
    }

    /// Whether RX records are decrypted by the kernel.
    pub(crate) fn rx_offloaded(&self) -> bool {
        self.rx.is_some()
    }

    /// The next RX traffic secret, installed as the new RX key.
    pub(crate) fn rekey_rx(&mut self) -> io::Result<()> {
        let Some(material) = self.rx.as_mut() else {
            return Err(io::Error::other("ktls: no RX key to update"));
        };
        *material = next_secret(material);
        #[cfg(target_os = "linux")]
        install_key(self.fd, TLS_RX, material)?;
        Ok(())
    }

    /// The next TX traffic secret, installed as the new TX key.
    pub(crate) fn rekey_tx(&mut self) -> io::Result<()> {
        let Some(material) = self.tx.as_mut() else {
            return Err(io::Error::other("ktls: no TX key to update"));
        };
        *material = next_secret(material);
        #[cfg(target_os = "linux")]
        install_key(self.fd, TLS_TX, material)?;
        Ok(())
    }

    /// Sends one control record (a handshake message or an alert) through the
    /// kernel's record-type channel, so it stays unencrypted on the wire while
    /// the payload itself is plaintext to the caller.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_self))]
    pub(crate) fn send_control(&self, kind: u8, body: &[u8]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let mut control = [0u8; 64];
            let header = std::mem::size_of::<libc::cmsghdr>();
            let space = cmsg_space(1);
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: body.as_ptr().cast_mut().cast(),
                iov_len: body.len(),
            };
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            unsafe {
                let cmsg = control.as_mut_ptr().cast::<libc::cmsghdr>();
                (*cmsg).cmsg_len = cmsg_len(1) as _;
                (*cmsg).cmsg_level = SOL_TLS;
                (*cmsg).cmsg_type = TLS_SET_RECORD_TYPE;
                *control.as_mut_ptr().add(header) = kind;
                let wrote = libc::sendmsg(self.fd, &raw const msg, 0);
                if wrote < 0 {
                    return Err(io::Error::last_os_error());
                }
                if wrote as usize != body.len() {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (kind, body);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// Reads one record through the kernel, leaving its payload in `stage`.
    ///
    /// The returned byte is the TLS record type: `23` for application data,
    /// `22` for a handshake message such as a `KeyUpdate`, `21` for an alert.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_self))]
    pub(crate) fn recv(&mut self) -> io::Result<(u8, usize)> {
        #[cfg(target_os = "linux")]
        {
            let mut control = [0u8; 64];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: self.stage.as_mut_ptr().cast(),
                iov_len: self.stage.len(),
            };
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = control.len() as _;
            let got = unsafe { libc::recvmsg(self.fd, &raw mut msg, 0) };
            if got < 0 {
                return Err(io::Error::last_os_error());
            }
            let len = got as usize;
            let kind = unsafe {
                let cmsg = control.as_ptr().cast::<libc::cmsghdr>();
                if msg.msg_controllen >= cmsg_len(0) as _
                    && (*cmsg).cmsg_len >= cmsg_len(1) as _
                    && (*cmsg).cmsg_level == SOL_TLS
                    && (*cmsg).cmsg_type == TLS_GET_RECORD_TYPE
                {
                    *control.as_ptr().add(std::mem::size_of::<libc::cmsghdr>())
                } else {
                    23
                }
            };
            Ok((kind, len))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// The record `recv` last read.
    pub(crate) fn stage(&self, len: usize) -> &[u8] {
        &self.stage[..len]
    }
}

#[cfg(target_os = "linux")]
const SOL_TLS: libc::c_int = 282;
#[cfg(target_os = "linux")]
const TCP_ULP: libc::c_int = 31;
#[cfg(target_os = "linux")]
const TLS_TX: libc::c_int = 1;
#[cfg(target_os = "linux")]
const TLS_RX: libc::c_int = 2;
#[cfg(target_os = "linux")]
const TLS_RX_EXPECT_NO_PAD: libc::c_int = 4;
#[cfg(target_os = "linux")]
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
#[cfg(target_os = "linux")]
const TLS_GET_RECORD_TYPE: libc::c_int = 2;
#[cfg(target_os = "linux")]
const TLS_1_3_VERSION: u16 = 0x0304;

#[cfg(target_os = "linux")]
const fn cmsg_align(len: usize) -> usize {
    let width = std::mem::size_of::<usize>();
    (len + width - 1) & !(width - 1)
}

#[cfg(target_os = "linux")]
const fn cmsg_len(len: usize) -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>()) + len
}

#[cfg(target_os = "linux")]
const fn cmsg_space(len: usize) -> usize {
    cmsg_align(cmsg_len(len))
}

#[cfg(target_os = "linux")]
fn set_ulp(fd: RawFd) -> io::Result<()> {
    let ulp = *b"tls\0";
    let set = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_ULP,
            ulp.as_ptr().cast(),
            ulp.len() as libc::socklen_t,
        )
    };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_key(fd: RawFd, direction: libc::c_int, material: &Material) -> io::Result<()> {
    let keys = keys(material);
    let mut info = [0u8; 64];
    info[0..2].copy_from_slice(&TLS_1_3_VERSION.to_ne_bytes());
    info[2..4].copy_from_slice(&material.cipher.id().to_ne_bytes());
    let cipher = material.cipher;
    let mut at = 4;
    let salt = cipher.salt_len();
    let iv = cipher.iv_len();
    info[at..at + iv].copy_from_slice(&keys.iv[salt..salt + iv]);
    at += iv;
    info[at..at + keys.key.len()].copy_from_slice(&keys.key);
    at += keys.key.len();
    info[at..at + salt].copy_from_slice(&keys.iv[..salt]);
    at += salt;
    info[at..at + 8].copy_from_slice(&keys.seq.to_be_bytes());
    at += 8;
    let set = unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            direction,
            info.as_ptr().cast(),
            at as libc::socklen_t,
        )
    };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

use crate::tls::shaped::record::{self, Direction, Suite};
use crate::tls::shaped::seal_chunks;
use std::io::{Read, Write};

const APPLICATION: u8 = 23;
const HANDSHAKE: u8 = 22;
const ALERT: u8 = 21;
const MAX_PLAINTEXT: usize = 16384;

/// The handshake message a peer's `update_requested` asks this side to send.
const KEY_UPDATE: [u8; 5] = [24, 0, 0, 1, 0];

fn suite_of(cipher: Cipher, hash: Hash) -> Option<Suite> {
    match (cipher, hash) {
        (Cipher::Aes128Gcm, Hash::Sha256) => Some(Suite::Aes128GcmSha256),
        (Cipher::Aes256Gcm, Hash::Sha384) => Some(Suite::Aes256GcmSha384),
        (Cipher::ChaCha20Poly1305, Hash::Sha256) => Some(Suite::ChaCha20Sha256),
        _ => None,
    }
}

/// The record layer after a kTLS request: the kernel takes an offloaded direction, and
/// the other direction stays here under the same traffic-secret epoch so a `KeyUpdate`
/// advances both in lockstep.
pub(crate) struct Layer {
    ktls: Ktls,
    tx: Option<Direction>,
    rx: Option<Direction>,
    pending_tx_update: bool,
    hs: Vec<u8>,
    plain: Vec<u8>,
    plain_at: usize,
    plain_end: usize,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    eof: bool,
}

impl std::fmt::Debug for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layer")
            .field("tx_offloaded", &self.ktls.tx_offloaded())
            .field("rx_offloaded", &self.ktls.rx_offloaded())
            .field("eof", &self.eof)
            .finish_non_exhaustive()
    }
}

impl Layer {
    /// Takes over a finished TLS 1.3 session. At least one direction must be offloaded.
    pub(crate) fn new(
        fd: RawFd,
        tx_offload: bool,
        rx_offload: bool,
        tx: Material,
        rx: Material,
    ) -> io::Result<Self> {
        if !tx_offload && !rx_offload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ktls: neither direction offloaded",
            ));
        }
        let tx_suite = suite_of(tx.cipher, tx.hash).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "ktls: TX cipher is not 1.3")
        })?;
        let rx_suite = suite_of(rx.cipher, rx.hash).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "ktls: RX cipher is not 1.3")
        })?;
        let tx_user = (!tx_offload).then(|| Direction::tls13_at(tx_suite, &tx.secret, tx.seq));
        let rx_user = (!rx_offload).then(|| Direction::tls13_at(rx_suite, &rx.secret, rx.seq));
        let ktls = Ktls::install(fd, tx_offload.then_some(tx), rx_offload.then_some(rx))?;
        Ok(Self {
            ktls,
            tx: tx_user,
            rx: rx_user,
            pending_tx_update: false,
            hs: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            plain_end: 0,
            inbuf: Vec::new(),
            out: Vec::new(),
            eof: false,
        })
    }

    pub(crate) fn rx_offloaded(&self) -> bool {
        self.ktls.rx_offloaded()
    }

    pub(crate) fn tx_offloaded(&self) -> bool {
        self.ktls.tx_offloaded()
    }

    pub(crate) fn eof(&self) -> bool {
        self.eof
    }

    fn deliver(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.plain_end - self.plain_at).min(buf.len());
        buf[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain_at += n;
        if self.plain_at == self.plain_end {
            self.plain_at = 0;
            self.plain_end = 0;
        }
        n
    }

    /// The response a peer's `KeyUpdate` asked for, sent under the current TX key before
    /// that key advances: the peer will read it with the epoch it still holds.
    fn flush_control_into(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if !self.pending_tx_update {
            return Ok(());
        }
        if self.tx_offloaded() {
            self.ktls.send_control(HANDSHAKE, &KEY_UPDATE)?;
            self.ktls.rekey_tx()?;
        } else {
            let tx = self
                .tx
                .as_mut()
                .ok_or_else(|| io::Error::other("ktls: no TX keys"))?;
            record::seal13(tx, HANDSHAKE, &KEY_UPDATE, out).map_err(io::Error::other)?;
            tx.update();
        }
        self.pending_tx_update = false;
        Ok(())
    }

    fn flush_control_direct<W: Write + ?Sized>(&mut self, io: &mut W) -> io::Result<()> {
        if !self.pending_tx_update {
            return Ok(());
        }
        if self.tx_offloaded() {
            self.ktls.send_control(HANDSHAKE, &KEY_UPDATE)?;
            self.ktls.rekey_tx()?;
            self.pending_tx_update = false;
            return Ok(());
        }
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        let result = self.flush_control_into(&mut out);
        self.out = out;
        result?;
        io.write_all(&self.out)
    }

    fn handle_handshake(&mut self, body: &[u8]) -> io::Result<()> {
        self.hs.extend_from_slice(body);
        loop {
            if self.hs.len() < 4 {
                return Ok(());
            }
            let len = u32::from_be_bytes([0, self.hs[1], self.hs[2], self.hs[3]]) as usize;
            if len > 1 << 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ktls: handshake message too long",
                ));
            }
            if self.hs.len() < 4 + len {
                return Ok(());
            }
            let kind = self.hs[0];
            let request = self.hs.get(4).copied() == Some(1);
            self.hs.drain(..4 + len);
            match kind {
                // NewSessionTicket: a kernel-offloaded session does not resume, so the ticket is dropped unread.
                4 => {}
                24 => {
                    if self.rx_offloaded() {
                        self.ktls.rekey_rx()?;
                    } else {
                        self.rx
                            .as_mut()
                            .ok_or_else(|| io::Error::other("ktls: no RX keys"))?
                            .update();
                    }
                    self.pending_tx_update |= request;
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ktls: unexpected handshake message {other}"),
                    ));
                }
            }
        }
    }

    fn handle_alert(&mut self, body: &[u8]) -> io::Result<()> {
        if body.get(1).copied() == Some(0) {
            self.eof = true;
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("ktls: peer alert {:?}", body.get(1)),
        ))
    }

    fn read_offloaded(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let (kind, len) = self.ktls.recv()?;
            match kind {
                APPLICATION => {
                    let n = len.min(buf.len());
                    buf[..n].copy_from_slice(self.ktls.stage(n));
                    if n < len {
                        let rest = self.ktls.stage(len)[n..].to_vec();
                        self.plain.clear();
                        self.plain.extend_from_slice(&rest);
                        self.plain_at = 0;
                        self.plain_end = rest.len();
                    }
                    return Ok(n);
                }
                HANDSHAKE => {
                    let body = self.ktls.stage(len).to_vec();
                    self.handle_handshake(&body)?;
                }
                ALERT => {
                    let body = self.ktls.stage(len).to_vec();
                    self.handle_alert(&body)?;
                }
                // A compatibility change_cipher_spec is part of the old version's shape.
                20 => {}
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ktls: unexpected record type {other}"),
                    ));
                }
            }
        }
    }

    fn fill_record<R: Read + ?Sized>(&mut self, io: &mut R) -> io::Result<bool> {
        while self.inbuf.len() < 5 {
            let want = 5 - self.inbuf.len();
            let mut head = [0u8; 5];
            match io.read(&mut head[..want]) {
                Ok(0) => return Ok(false),
                Ok(n) => self.inbuf.extend_from_slice(&head[..n]),
                Err(error) => return Err(error),
            }
        }
        let len = usize::from(u16::from_be_bytes([self.inbuf[3], self.inbuf[4]]));
        if len > MAX_PLAINTEXT + 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ktls: record too long",
            ));
        }
        let total = 5 + len;
        while self.inbuf.len() < total {
            let want = (total - self.inbuf.len()).min(4096);
            let mut chunk = [0u8; 4096];
            match io.read(&mut chunk[..want]) {
                Ok(0) => return Ok(false),
                Ok(n) => self.inbuf.extend_from_slice(&chunk[..n]),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    fn read_userspace<R: Read + ?Sized>(
        &mut self,
        io: &mut R,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        loop {
            if self.plain_at < self.plain_end {
                return Ok(self.deliver(buf));
            }
            if self.eof {
                return Ok(0);
            }
            if !self.fill_record(io)? {
                self.eof = true;
                return Ok(0);
            }
            let header = [
                self.inbuf[0],
                self.inbuf[1],
                self.inbuf[2],
                self.inbuf[3],
                self.inbuf[4],
            ];
            let (kind, len) = {
                let rx = self
                    .rx
                    .as_mut()
                    .ok_or_else(|| io::Error::other("ktls: no RX keys"))?;
                record::open13(rx, header, &mut self.inbuf[5..]).map_err(io::Error::other)?
            };
            match kind {
                APPLICATION => {
                    let n = len.min(buf.len());
                    let at = 5;
                    buf[..n].copy_from_slice(&self.inbuf[at..at + n]);
                    if n < len {
                        let rest = self.inbuf[at + n..at + len].to_vec();
                        self.plain.clear();
                        self.plain.extend_from_slice(&rest);
                        self.plain_at = 0;
                        self.plain_end = rest.len();
                    }
                    self.inbuf.clear();
                    return Ok(n);
                }
                HANDSHAKE => {
                    let body = self.inbuf[5..5 + len].to_vec();
                    self.inbuf.clear();
                    self.handle_handshake(&body)?;
                }
                ALERT => {
                    let body = self.inbuf[5..5 + len].to_vec();
                    self.inbuf.clear();
                    self.handle_alert(&body)?;
                }
                20 => self.inbuf.clear(),
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ktls: unexpected record type {other}"),
                    ));
                }
            }
        }
    }

    pub(crate) fn read<R: Read + ?Sized>(
        &mut self,
        io: &mut R,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.plain_at < self.plain_end {
            return Ok(self.deliver(buf));
        }
        if self.rx_offloaded() {
            self.read_offloaded(buf)
        } else {
            self.read_userspace(io, buf)
        }
    }

    /// Processes ciphertext the relay read itself, for a session that keeps RX in user space.
    pub(crate) fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> io::Result<(usize, usize)> {
        if self.rx_offloaded() {
            return Err(io::Error::other("ktls: the kernel decrypts this direction"));
        }
        if self.plain_at < self.plain_end {
            return Ok((self.deliver(buf), 0));
        }
        if ciphertext.is_empty() {
            return Ok((0, 0));
        }
        self.inbuf.extend_from_slice(ciphertext);
        let mut at = 0usize;
        let mut filled = 0usize;
        loop {
            if self.inbuf.len() - at < 5 {
                break;
            }
            let len = usize::from(u16::from_be_bytes([self.inbuf[at + 3], self.inbuf[at + 4]]));
            if len > MAX_PLAINTEXT + 256 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ktls: record too long",
                ));
            }
            if self.inbuf.len() - at - 5 < len {
                break;
            }
            let header = [
                self.inbuf[at],
                self.inbuf[at + 1],
                self.inbuf[at + 2],
                self.inbuf[at + 3],
                self.inbuf[at + 4],
            ];
            let (kind, plen) = {
                let rx = self
                    .rx
                    .as_mut()
                    .ok_or_else(|| io::Error::other("ktls: no RX keys"))?;
                record::open13(rx, header, &mut self.inbuf[at + 5..at + 5 + len])
                    .map_err(io::Error::other)?
            };
            let begin = at + 5;
            match kind {
                APPLICATION => {
                    let room = buf.len() - filled;
                    let take = plen.min(room);
                    buf[filled..filled + take].copy_from_slice(&self.inbuf[begin..begin + take]);
                    filled += take;
                    if take < plen {
                        let rest = self.inbuf[begin + take..begin + plen].to_vec();
                        if self.plain_at == self.plain_end {
                            self.plain.clear();
                            self.plain_at = 0;
                            self.plain_end = 0;
                        }
                        let end = self.plain_end + rest.len();
                        if self.plain.len() < end {
                            self.plain.resize(end, 0);
                        }
                        self.plain[self.plain_end..end].copy_from_slice(&rest);
                        self.plain_end = end;
                    }
                }
                HANDSHAKE => {
                    let body = self.inbuf[begin..begin + plen].to_vec();
                    self.handle_handshake(&body)?;
                }
                ALERT => {
                    let body = self.inbuf[begin..begin + plen].to_vec();
                    self.handle_alert(&body)?;
                }
                20 => {}
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ktls: unexpected record type {other}"),
                    ));
                }
            }
            at += 5 + len;
        }
        if at > 0 {
            self.inbuf.drain(..at);
        }
        Ok((filled, ciphertext.len()))
    }

    pub(crate) fn seal_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> io::Result<usize> {
        // A kernel TX control record must wait for a caller whose buffer holds plaintext.
        if !self.tx_offloaded() || out.is_empty() {
            self.flush_control_into(out)?;
        }
        let total = parts.iter().map(|part| part.len()).sum();
        if self.tx_offloaded() {
            for part in parts {
                out.extend_from_slice(part);
            }
            return Ok(total);
        }
        let tx = self
            .tx
            .as_mut()
            .ok_or_else(|| io::Error::other("ktls: no TX keys"))?;
        seal_chunks(parts, out, |chunk, out| {
            record::seal13_parts(tx, APPLICATION, chunk, out)
        })
        .map_err(io::Error::other)?;
        Ok(total)
    }

    pub(crate) fn write<W: Write + ?Sized>(&mut self, io: &mut W, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.flush_control_direct(io)?;
        if self.tx_offloaded() {
            io.write_all(buf)?;
        } else {
            self.out.clear();
            let tx = self
                .tx
                .as_mut()
                .ok_or_else(|| io::Error::other("ktls: no TX keys"))?;
            record::seal13(tx, APPLICATION, buf, &mut self.out).map_err(io::Error::other)?;
            io.write_all(&self.out)?;
        }
        Ok(buf.len())
    }

    pub(crate) fn write_all<W: Write + ?Sized>(
        &mut self,
        io: &mut W,
        parts: &[&[u8]],
    ) -> io::Result<()> {
        self.flush_control_direct(io)?;
        if self.tx_offloaded() {
            for part in parts {
                io.write_all(part)?;
            }
            return Ok(());
        }
        self.out.clear();
        let tx = self
            .tx
            .as_mut()
            .ok_or_else(|| io::Error::other("ktls: no TX keys"))?;
        seal_chunks(parts, &mut self.out, |chunk, out| {
            record::seal13_parts(tx, APPLICATION, chunk, out)
        })
        .map_err(io::Error::other)?;
        io.write_all(&self.out)
    }

    pub(crate) fn flush<W: Write + ?Sized>(&mut self, io: &mut W) -> io::Result<()> {
        self.flush_control_direct(io)?;
        io.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn userspace(secret: &[u8]) -> Layer {
        let suite = Suite::Aes128GcmSha256;
        Layer {
            ktls: Ktls {
                #[cfg(target_os = "linux")]
                fd: -1,
                tx: None,
                rx: None,
                stage: Vec::new(),
            },
            tx: None,
            rx: Some(Direction::tls13_at(suite, secret, 0)),
            pending_tx_update: false,
            hs: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            plain_end: 0,
            inbuf: Vec::new(),
            out: Vec::new(),
            eof: false,
        }
    }

    #[test]
    fn a_window_smaller_than_two_records_keeps_the_second() {
        let secret = [9u8; 32];
        let mut tx = Direction::tls13_at(Suite::Aes128GcmSha256, &secret, 0);
        let mut wire = Vec::new();
        record::seal13(&mut tx, APPLICATION, b"aa", &mut wire).expect("seals");
        record::seal13(&mut tx, APPLICATION, b"bb", &mut wire).expect("seals");
        let mut layer = userspace(&secret);
        let mut window = [0u8; 2];
        assert_eq!(
            layer.open(&wire, &mut window).expect("opens"),
            (2, wire.len())
        );
        assert_eq!(&window, b"aa");
        assert_eq!(layer.open(&[], &mut window).expect("opens"), (2, 0));
        assert_eq!(&window, b"bb");
    }
}
