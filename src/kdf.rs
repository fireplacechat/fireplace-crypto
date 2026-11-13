//! HKDF-SHA256 and the ratchet's HMAC-SHA256 chain.
//!
//! The chain is HMAC, not HKDF. `hmac` is not an approved direct dependency,
//! so the HMAC is computed with `sha2`. Empty salt matches the Dart `Hkdf`
//! call, which passes an empty nonce as the salt: for SHA-256 that is the
//! same key schedule as the RFC 5869 HashLen-zero salt.

use crate::error::{Error, Result};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::Sha512;
    let digest = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// HMAC-SHA256. The key pad is wiped before return.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut keyed = [0u8; BLOCK];
    if key.len() > BLOCK {
        keyed[..32].copy_from_slice(&sha256(key));
    } else {
        keyed[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= keyed[i];
        opad[i] ^= keyed[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    keyed.zeroize();
    ipad.zeroize();
    opad.zeroize();
    out
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .map_err(|_| Error::Crypto("hkdf"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc_4231_hmac_sha256_case_1() {
        let key = vec![0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode_like(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc_5869_case_1_and_empty_salt() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let mut out = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut out).unwrap();
        assert_eq!(
            hex::encode_like(&out),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // RFC 5869 test case 3: zero-length salt and info.
        let ikm3 = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let mut out3 = [0u8; 42];
        hkdf_sha256(&ikm3, b"", b"", &mut out3).unwrap();
        assert_eq!(
            hex::encode_like(&out3),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    mod hex {
        pub fn encode_like(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    }
}
