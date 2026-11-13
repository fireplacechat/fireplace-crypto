//! AES-256-GCM with a caller-supplied 12-byte nonce.
//!
//! `aes-gcm`'s `getrandom` feature is off, so the cipher never draws a nonce
//! itself. Dart's `SecretBox` splits the box into nonce, ciphertext and a
//! 16-byte tag; this module does the same split.

use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};

const TAG: usize = 16;

pub fn seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG])> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Invalid("aes key"))?;
    let nonce = nonce_of(nonce)?;
    let boxed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("aes seal"))?;
    split_box(&boxed)
}

pub fn open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    if tag.len() != TAG {
        return Err(Error::Crypto("authentication failed"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Invalid("aes key"))?;
    let nonce = nonce_of(nonce)?;
    let mut boxed = Vec::with_capacity(ciphertext.len() + TAG);
    boxed.extend_from_slice(ciphertext);
    boxed.extend_from_slice(tag);
    cipher
        .decrypt(&nonce, Payload { msg: &boxed, aad })
        .map_err(|_| Error::Crypto("authentication failed"))
}

fn nonce_of(bytes: &[u8]) -> Result<aes_gcm::aead::Nonce<Aes256Gcm>> {
    aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(bytes).map_err(|_| Error::Invalid("nonce"))
}

fn split_box(boxed: &[u8]) -> Result<(Vec<u8>, [u8; TAG])> {
    if boxed.len() < TAG {
        return Err(Error::Crypto("aes seal"));
    }
    let split = boxed.len() - TAG;
    let mut tag = [0u8; TAG];
    tag.copy_from_slice(&boxed[split..]);
    Ok((boxed[..split].to_vec(), tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejects_a_flipped_bit() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let (ct, tag) = seal(&key, &nonce, b"aad", b"hello").unwrap();
        assert_eq!(open(&key, &nonce, b"aad", &ct, &tag).unwrap(), b"hello");
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(open(&key, &nonce, b"aad", &ct, &bad).is_err());
    }
}
