//! The 160-bit recovery key and the encrypted identity backup.
//!
//! Display form is RFC 4648 base32 with no padding (32 characters) plus a
//! 4-character checksum, shown as 9 groups of 4. The backup plaintext is the
//! UTF-8 of `jsonEncode(identity.toJson())`, which is why identity JSON keeps
//! Dart's field order.

use crate::aead;
use crate::codec::{b64_decode, b64_encode, lp};
use crate::error::{Error, Result};
use crate::identity::AccountIdentity;
use crate::kdf::{hkdf_sha256, sha256};
use crate::rng::Rng;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BACKUP_INFO: &[u8] = b"fireplace/v1/backup";

pub struct RecoveryKey {
    bytes: [u8; 20],
}

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryKey")
    }
}

impl RecoveryKey {
    pub fn generate(rng: &mut Rng) -> Result<Self> {
        Ok(Self {
            bytes: rng.array::<20>()?,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 20] = bytes
            .try_into()
            .map_err(|_| Error::Invalid("recovery key"))?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.bytes
    }

    pub fn display(&self) -> Result<String> {
        let body = base32(&self.bytes);
        let check = checksum(&self.bytes)?;
        let grouped = format!("{body}{check}");
        Ok(grouped
            .as_bytes()
            .chunks(4)
            .map(|c| core::str::from_utf8(c).expect("base32 is ascii"))
            .collect::<Vec<_>>()
            .join("-"))
    }

    /// Any case, and spaces or dashes, are accepted. A typo returns `None`.
    pub fn parse(input: &str) -> Result<Option<Self>> {
        let folded: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .flat_map(|c| c.to_uppercase())
            .collect();
        if folded.len() != 36 {
            return Ok(None);
        }
        let Some(data) = unbase32(&folded[..32]) else {
            return Ok(None);
        };
        if data.len() < 20 {
            return Ok(None);
        }
        let mut key = [0u8; 20];
        key.copy_from_slice(&data[..20]);
        if checksum(&key)? != folded[32..] {
            return Ok(None);
        }
        Ok(Some(Self { bytes: key }))
    }

    fn aead_key(&self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        hkdf_sha256(&self.bytes, b"", BACKUP_INFO, &mut out)?;
        Ok(out)
    }
}

pub fn encrypt(identity: &AccountIdentity, key: &RecoveryKey, rng: &mut Rng) -> Result<String> {
    let plain = identity.to_json().into_bytes();
    let nonce = rng.array::<12>()?;
    let (ciphertext, tag) = aead::seal(&key.aead_key()?, &nonce, BACKUP_INFO, &plain)?;
    let mut boxed = Vec::with_capacity(12 + ciphertext.len() + 16);
    boxed.extend_from_slice(&nonce);
    boxed.extend_from_slice(&ciphertext);
    boxed.extend_from_slice(&tag);
    Ok(b64_encode(&boxed))
}

pub fn decrypt(blob: &str, key: &RecoveryKey) -> Result<AccountIdentity> {
    let boxed = b64_decode(blob)
        .map_err(|_| Error::Crypto("Wrong recovery key, or the backup is damaged."))?;
    if boxed.len() < 12 + 16 {
        return Err(Error::Crypto(
            "Wrong recovery key, or the backup is damaged.",
        ));
    }
    let (nonce, rest) = boxed.split_at(12);
    let (ciphertext, tag) = rest.split_at(rest.len() - 16);
    let plain = aead::open(&key.aead_key()?, nonce, BACKUP_INFO, ciphertext, tag)
        .map_err(|_| Error::Crypto("Wrong recovery key, or the backup is damaged."))?;
    let text = core::str::from_utf8(&plain)
        .map_err(|_| Error::Crypto("Wrong recovery key, or the backup is damaged."))?;
    AccountIdentity::from_json(text)
        .map_err(|_| Error::Crypto("Wrong recovery key, or the backup is damaged."))
}

fn checksum(key: &[u8]) -> Result<String> {
    let hash = sha256(&lp(&[b"fireplace/v1/rk-check", key])?);
    Ok(base32(&hash[..3])[..4].to_string())
}

fn base32(data: &[u8]) -> String {
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = String::new();
    for byte in data {
        value = (value << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((value >> (bits - 5)) & 31) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
        if bits == 0 {
            value = 0;
        } else {
            value &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        let index = ((value << (5 - bits)) & 31) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for ch in text.chars() {
        let index = ALPHABET.iter().position(|c| *c as char == ch)? as u32;
        value = (value << 5) | index;
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 255) as u8);
            bits -= 8;
            value &= if bits == 0 { 0 } else { (1 << bits) - 1 };
        }
    }
    Some(out)
}
