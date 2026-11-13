use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;

const BLOCK_SIZE: usize = 16;

pub struct Cfb8 {
    cipher: Aes128,
    iv: [u8; BLOCK_SIZE],
    decrypt: bool,
}

impl Cfb8 {
    pub fn encrypt(secret: &[u8; 16]) -> Self {
        Self::new(secret, secret, false)
    }

    pub fn decrypt(secret: &[u8; 16]) -> Self {
        Self::new(secret, secret, true)
    }

    pub fn with_iv(key: &[u8; 16], iv: &[u8; 16], decrypt: bool) -> Self {
        Self::new(key, iv, decrypt)
    }

    fn new(key: &[u8; 16], iv: &[u8; 16], decrypt: bool) -> Self {
        Self {
            cipher: Aes128::new_from_slice(key).expect("AES-128 accepts a 16-byte key"),
            iv: *iv,
            decrypt,
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            let mut block = self.iv.into();
            self.cipher.encrypt_block(&mut block);
            let ciphertext = *byte;
            *byte ^= block[0];
            self.iv.rotate_left(1);
            self.iv[BLOCK_SIZE - 1] = if self.decrypt { ciphertext } else { *byte };
        }
    }
}

impl std::fmt::Debug for Cfb8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cfb8")
            .field("decrypt", &self.decrypt)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_and_iv() -> [u8; 16] {
        let mut value = [0; 16];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = index as u8;
        }
        value
    }

    #[test]
    fn known_answer_matches_standard_cfb8() {
        let secret = key_and_iv();
        let mut data = *b"hello world";
        let mut encrypt = Cfb8::encrypt(&secret);
        encrypt.apply(&mut data);
        assert_eq!(
            data,
            [0x62, 0xbf, 0xe8, 0xa3, 0x2e, 0x18, 0xb0, 0x65, 0x2c, 0x21, 0x49]
        );

        let mut decrypt = Cfb8::decrypt(&secret);
        decrypt.apply(&mut data);
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn a_round_trip_holds_across_block_boundaries() {
        let secret = key_and_iv();
        let plaintext: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let mut wire = plaintext.clone();

        let mut encrypt = Cfb8::encrypt(&secret);
        encrypt.apply(&mut wire);
        assert_ne!(wire, plaintext);

        let mut decrypt = Cfb8::decrypt(&secret);
        decrypt.apply(&mut wire);
        assert_eq!(wire, plaintext);
    }

    #[test]
    fn both_directions_share_the_secret_as_their_iv() {
        let secret = key_and_iv();
        let mut left = *b"the same stream";
        let mut right = left;
        Cfb8::encrypt(&secret).apply(&mut left);
        Cfb8::with_iv(&secret, &secret, false).apply(&mut right);
        assert_eq!(left, right);
    }
}
