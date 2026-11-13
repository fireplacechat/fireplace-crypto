//! Moving an account identity onto a new device of the same account.
//!
//! The new device's public keys are compared out of band (a short fingerprint
//! and a 6-digit code). The seal is hybrid X25519 plus ML-KEM-768. A
//! non-contributory X25519 shared secret is refused.

use crate::aead;
use crate::codec::{self, Json, b64_encode, b64url_encode, concat, lp, parse_json};
use crate::device::DeviceKeys;
use crate::error::{Error, Result};
use crate::identity::AccountIdentity;
use crate::kdf::{hkdf_sha256, sha256};
use crate::prim::{self, MLKEM_CT, MLKEM_EK};
use crate::rng::Rng;

#[derive(Clone, Debug)]
pub struct SealedIdentity {
    pub ek: Vec<u8>,
    pub kem_ct: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ct: Vec<u8>,
    pub mac: Vec<u8>,
}

impl SealedIdentity {
    pub fn to_json(&self) -> String {
        codec::to_json(&Json::object(vec![
            ("ek".to_string(), Json::Str(b64_encode(&self.ek))),
            ("kemCt".to_string(), Json::Str(b64_encode(&self.kem_ct))),
            ("nonce".to_string(), Json::Str(b64_encode(&self.nonce))),
            ("ct".to_string(), Json::Str(b64_encode(&self.ct))),
            ("mac".to_string(), Json::Str(b64_encode(&self.mac))),
        ]))
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let value = parse_json(text)?;
        let obj = value.as_object()?;
        Ok(Self {
            ek: codec::b64_field(codec::obj_get(obj, "ek")?, Some(32), 32, "ek")?,
            kem_ct: codec::b64_field(
                codec::obj_get(obj, "kemCt")?,
                Some(MLKEM_CT),
                MLKEM_CT,
                "kemCt",
            )?,
            nonce: codec::b64_field(codec::obj_get(obj, "nonce")?, Some(12), 12, "nonce")?,
            ct: codec::b64_field(codec::obj_get(obj, "ct")?, None, 1024 * 1024, "ct")?,
            mac: codec::b64_field(codec::obj_get(obj, "mac")?, Some(16), 16, "mac")?,
        })
    }
}

pub fn request_fingerprint(x25519_pub: &[u8], kem_pub: &[u8]) -> Result<String> {
    let hash = sha256(&lp(&[b"fireplace/v1/link-fp", x25519_pub, kem_pub])?);
    Ok(b64url_encode(&hash[..16]))
}

pub fn confirmation_code(identity_pub: &[u8], x25519_pub: &[u8], kem_pub: &[u8]) -> Result<String> {
    let hash = sha256(&lp(&[
        b"fireplace/v1/link-sas",
        identity_pub,
        x25519_pub,
        kem_pub,
    ])?);
    let n = u32::from_be_bytes(hash[..4].try_into().expect("4 bytes")) % 1_000_000;
    Ok(format!("{n:06}"))
}

fn info(
    uid: &str,
    device_id: &str,
    ek: &[u8],
    kem_ct: &[u8],
    x25519_pub: &[u8],
    kem_pub: &[u8],
) -> Result<Vec<u8>> {
    lp(&[
        b"fireplace/v1/link",
        uid.as_bytes(),
        device_id.as_bytes(),
        ek,
        kem_ct,
        x25519_pub,
        kem_pub,
    ])
}

fn key(dh: &[u8], shared: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    if !prim::contributory(dh) {
        return Err(Error::Crypto("Invalid device linking key."));
    }
    let mut out = [0u8; 32];
    hkdf_sha256(&concat(&[dh, shared]), b"", info, &mut out)?;
    Ok(out)
}

/// 32-byte ephemeral X25519 seed, 32 encapsulation coins, then a 12-byte nonce.
pub fn seal(
    identity: &AccountIdentity,
    uid: &str,
    device_id: &str,
    x25519_pub: &[u8],
    kem_pub: &[u8],
    rng: &mut Rng,
) -> Result<SealedIdentity> {
    if kem_pub.len() != MLKEM_EK || x25519_pub.len() != 32 {
        return Err(Error::Invalid("link key"));
    }
    let mut seed = rng.array::<32>()?;
    let ek = prim::x25519_public(&seed)?.to_vec();
    let dh = prim::x25519_shared(&seed, x25519_pub)?;
    seed.zeroize();
    let coins = rng.array::<32>()?;
    let (kem_ct, shared) = prim::mlkem_encapsulate(kem_pub, &coins)?;
    let info = info(uid, device_id, &ek, &kem_ct, x25519_pub, kem_pub)?;
    let plain = identity.to_json().into_bytes();
    let nonce = rng.array::<12>()?;
    let (ct, mac) = aead::seal(&key(&dh, &shared, &info)?, &nonce, &info, &plain)
        .map_err(|_| Error::Crypto("Invalid device linking key."))?;
    Ok(SealedIdentity {
        ek,
        kem_ct,
        nonce: nonce.to_vec(),
        ct,
        mac: mac.to_vec(),
    })
}

pub fn open(sealed: &SealedIdentity, uid: &str, keys: &DeviceKeys) -> Result<AccountIdentity> {
    let opened = (|| {
        let dh = prim::x25519_shared(&keys.x25519_seed, &sealed.ek)?;
        let shared = prim::mlkem_decapsulate(&keys.kem_secret, &sealed.kem_ct)?;
        let info = info(
            uid,
            &keys.device_id,
            &sealed.ek,
            &sealed.kem_ct,
            &keys.x25519_pub,
            &keys.kem_pub,
        )?;
        let plain = aead::open(
            &key(&dh, &shared, &info)?,
            &sealed.nonce,
            &info,
            &sealed.ct,
            &sealed.mac,
        )?;
        let text = core::str::from_utf8(&plain).map_err(|_| Error::Invalid("link"))?;
        AccountIdentity::from_json(text)
    })();
    opened.map_err(|_| Error::Crypto("Could not decrypt the transferred identity."))
}

use zeroize::Zeroize;
