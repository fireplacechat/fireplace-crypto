//! Moving an account identity onto a new device of the same account.
//!
//! The new device shows a QR code that holds a fingerprint of its public keys
//! and a random secret. The fingerprint tells the approving device which keys
//! to seal to. The secret never leaves the two screens and goes into the
//! sealing key, so only a device that read the QR code can make a response
//! the new device will open. The seal is hybrid X25519 plus ML-KEM-768. A
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

fn info(
    uid: &str,
    device_id: &str,
    ek: &[u8],
    kem_ct: &[u8],
    x25519_pub: &[u8],
    kem_pub: &[u8],
) -> Result<Vec<u8>> {
    lp(&[
        b"fireplace/v2/link",
        uid.as_bytes(),
        device_id.as_bytes(),
        ek,
        kem_ct,
        x25519_pub,
        kem_pub,
    ])
}

/// Shortest and longest secret a QR code may carry, in bytes.
pub const LINK_SECRET_MIN: usize = 16;
pub const LINK_SECRET_MAX: usize = 64;

fn check_secret(secret: &[u8]) -> Result<()> {
    if secret.len() < LINK_SECRET_MIN || secret.len() > LINK_SECRET_MAX {
        return Err(Error::Invalid("link secret"));
    }
    Ok(())
}

/// The two shared secrets have fixed lengths, so the QR secret after them
/// needs no length prefix.
fn key(dh: &[u8], shared: &[u8], secret: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if !prim::contributory(dh) {
        return Err(Error::Crypto("Invalid device linking key."));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    let ikm = Zeroizing::new(concat(&[dh, shared, secret]));
    hkdf_sha256(&ikm, b"", info, &mut out[..])?;
    Ok(out)
}

/// `secret` is the random value read from the new device's QR code.
/// 32-byte ephemeral X25519 seed, 32 encapsulation coins, then a 12-byte nonce.
pub fn seal(
    identity: &AccountIdentity,
    uid: &str,
    device_id: &str,
    x25519_pub: &[u8],
    kem_pub: &[u8],
    secret: &[u8],
    rng: &mut Rng,
) -> Result<SealedIdentity> {
    check_secret(secret)?;
    if kem_pub.len() != MLKEM_EK || x25519_pub.len() != 32 {
        return Err(Error::Invalid("link key"));
    }
    let mut seed = rng.array::<32>()?;
    let ek = prim::x25519_public(&seed)?.to_vec();
    let dh = prim::x25519_shared(&seed, x25519_pub).map(Zeroizing::new);
    seed.zeroize();
    let dh = dh?;
    let coins = Zeroizing::new(rng.array::<32>()?);
    let (kem_ct, shared) = prim::mlkem_encapsulate(kem_pub, &coins[..])?;
    let shared = Zeroizing::new(shared);
    let info = info(uid, device_id, &ek, &kem_ct, x25519_pub, kem_pub)?;
    // The plaintext is every secret key of the account: wipe it when done.
    let plain = Zeroizing::new(identity.to_json().into_bytes());
    let nonce = rng.array::<12>()?;
    let sealing = key(&dh[..], &shared[..], secret, &info)?;
    let (ct, mac) = aead::seal(&sealing[..], &nonce, &info, &plain)
        .map_err(|_| Error::Crypto("Invalid device linking key."))?;
    Ok(SealedIdentity {
        ek,
        kem_ct,
        nonce: nonce.to_vec(),
        ct,
        mac: mac.to_vec(),
    })
}

/// `secret` is the random value this device put in its QR code. A response
/// sealed without it does not open.
pub fn open(
    sealed: &SealedIdentity,
    uid: &str,
    keys: &DeviceKeys,
    secret: &[u8],
) -> Result<AccountIdentity> {
    check_secret(secret)?;
    let opened = (|| {
        let dh = Zeroizing::new(prim::x25519_shared(&keys.x25519_seed, &sealed.ek)?);
        let shared = Zeroizing::new(prim::mlkem_decapsulate(&keys.kem_secret, &sealed.kem_ct)?);
        let info = info(
            uid,
            &keys.device_id,
            &sealed.ek,
            &sealed.kem_ct,
            &keys.x25519_pub,
            &keys.kem_pub,
        )?;
        let opening = key(&dh[..], &shared[..], secret, &info)?;
        let plain = Zeroizing::new(aead::open(
            &opening[..],
            &sealed.nonce,
            &info,
            &sealed.ct,
            &sealed.mac,
        )?);
        let text = core::str::from_utf8(&plain).map_err(|_| Error::Invalid("link"))?;
        AccountIdentity::from_json(text)
    })();
    opened.map_err(|_| Error::Crypto("Could not decrypt the transferred identity."))
}

use zeroize::{Zeroize, Zeroizing};
