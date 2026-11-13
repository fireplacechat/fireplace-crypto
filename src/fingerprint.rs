//! Fingerprints and the safety number. Both are hashes of length-prefixed
//! inputs, so a changed label changes the value people compare in person.

use crate::codec::lp;
use crate::error::Result;
use crate::kdf::{sha256, sha512};

pub fn identity_fingerprint(identity_pub: &[u8]) -> Result<String> {
    let hash = sha256(&lp(&[b"fireplace/v1/fp", identity_pub])?);
    let hex: String = hash[..15]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(hex
        .as_bytes()
        .chunks(5)
        .map(|chunk| core::str::from_utf8(chunk).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn safety_number(identity_a: &[u8], identity_b: &[u8]) -> Result<String> {
    let (first, second) = if cmp_bytes(identity_a, identity_b) <= 0 {
        (identity_a, identity_b)
    } else {
        (identity_b, identity_a)
    };
    let hash = sha512(&lp(&[b"fireplace/v1/safety", first, second])?);
    let mut groups = Vec::with_capacity(12);
    for chunk in hash[..60].chunks(5) {
        let mut value = 0u64;
        for byte in chunk {
            value = (value << 8) | u64::from(*byte);
        }
        groups.push(format!("{:05}", value % 100_000));
    }
    Ok(groups.join(" "))
}

fn cmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    for i in 0..a.len().min(b.len()) {
        if a[i] != b[i] {
            return i32::from(a[i]) - i32::from(b[i]);
        }
    }
    a.len() as i32 - b.len() as i32
}
