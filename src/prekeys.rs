//! Signed and one-time prekeys. A prekey id is 9 random bytes of url-safe
//! base64 (12 characters, no padding to strip).

use crate::codec::{self, Json, b64_encode, b64url_encode, lp, obj_i64, obj_str, parse_json};
use crate::device::{DeviceBundle, b64_exact};
use crate::error::{Error, Result};
use crate::identity::AccountIdentity;
use crate::prim::{self, MLKEM_DK, MLKEM_EK};
use crate::rng::Rng;
use zeroize::Zeroize;

const CREATED_MAX: i64 = 8_640_000_000_000_000;

#[derive(Clone)]
pub struct PreKeyRecord {
    pub id: String,
    pub x25519_seed: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub kem_secret: Vec<u8>,
    pub kem_pub: Vec<u8>,
    pub created_at: i64,
}

impl Drop for PreKeyRecord {
    fn drop(&mut self) {
        self.x25519_seed.zeroize();
        self.kem_secret.zeroize();
    }
}

impl core::fmt::Debug for PreKeyRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PreKeyRecord({})", self.id)
    }
}

impl PreKeyRecord {
    /// 32-byte X25519 seed, 64-byte ML-KEM seed, then 9 id bytes.
    pub fn generate(rng: &mut Rng, now_ms: i64) -> Result<Self> {
        check_created(now_ms)?;
        let mut seed = rng.array::<32>()?;
        let public = prim::x25519_public(&seed)?.to_vec();
        let kem = prim::mlkem_generate(rng)?;
        let id = b64url_raw9(&rng.bytes(9)?);
        let record = Self {
            id,
            x25519_seed: seed.to_vec(),
            x25519_pub: public,
            kem_secret: kem.secret,
            kem_pub: kem.public,
            created_at: now_ms,
        };
        seed.zeroize();
        Ok(record)
    }

    pub fn to_json(&self) -> String {
        codec::to_json(&Json::object(vec![
            ("id".to_string(), Json::Str(self.id.clone())),
            (
                "x25519Seed".to_string(),
                Json::Str(b64_encode(&self.x25519_seed)),
            ),
            (
                "x25519Pub".to_string(),
                Json::Str(b64_encode(&self.x25519_pub)),
            ),
            (
                "kemSecret".to_string(),
                Json::Str(b64_encode(&self.kem_secret)),
            ),
            ("kemPub".to_string(), Json::Str(b64_encode(&self.kem_pub))),
            ("createdAt".to_string(), Json::Int(self.created_at)),
        ]))
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_fields(parse_json(text)?.as_object()?)
    }

    pub fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let id = obj_str(obj, "id").map_err(|_| Error::Invalid("id"))?;
        if id.is_empty() || id.len() > 32 {
            return Err(Error::Invalid("id"));
        }
        let created_at = obj_i64(obj, "createdAt").map_err(|_| Error::Invalid("createdAt"))?;
        check_created(created_at)?;
        Ok(Self {
            id: id.to_string(),
            x25519_seed: b64_exact(obj, "x25519Seed", 32)?,
            x25519_pub: b64_exact(obj, "x25519Pub", 32)?,
            kem_secret: b64_exact(obj, "kemSecret", MLKEM_DK)?,
            kem_pub: b64_exact(obj, "kemPub", MLKEM_EK)?,
            created_at,
        })
    }

    pub fn consistent(&self) -> bool {
        prim::x25519_matches(&self.x25519_seed, &self.x25519_pub)
            && prim::mlkem_matches(&self.kem_secret, &self.kem_pub)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreKeyKind {
    Signed,
    OneTime,
}

#[derive(Clone, Debug)]
pub struct PublishedPreKey {
    pub id: String,
    pub kind: PreKeyKind,
    pub x25519_pub: Vec<u8>,
    pub kem_pub: Vec<u8>,
    pub sig: Option<Vec<u8>>,
}

impl PublishedPreKey {
    pub fn to_json(&self) -> String {
        let mut pairs = vec![
            ("id".to_string(), Json::Str(self.id.clone())),
            (
                "kind".to_string(),
                Json::Str(
                    match self.kind {
                        PreKeyKind::Signed => "signed",
                        PreKeyKind::OneTime => "onetime",
                    }
                    .to_string(),
                ),
            ),
            (
                "x25519Pub".to_string(),
                Json::Str(b64_encode(&self.x25519_pub)),
            ),
            ("kemPub".to_string(), Json::Str(b64_encode(&self.kem_pub))),
        ];
        if let Some(sig) = &self.sig {
            pairs.push(("sig".to_string(), Json::Str(b64_encode(sig))));
        }
        codec::to_json(&Json::object(pairs))
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_fields(parse_json(text)?.as_object()?)
    }

    pub fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let id = obj_str(obj, "id").map_err(|_| Error::Invalid("id"))?;
        if id.is_empty() || id.len() > 32 {
            return Err(Error::Invalid("id"));
        }
        let kind = match obj_str(obj, "kind").map_err(|_| Error::Invalid("kind"))? {
            "signed" => PreKeyKind::Signed,
            "onetime" => PreKeyKind::OneTime,
            _ => return Err(Error::Invalid("kind")),
        };
        let x25519_pub =
            b64_exact(obj, "x25519Pub", 32).map_err(|_| Error::Invalid("bad key length"))?;
        let kem_pub =
            b64_exact(obj, "kemPub", MLKEM_EK).map_err(|_| Error::Invalid("bad key length"))?;
        let sig = match codec::obj_opt(obj, "sig") {
            None => None,
            Some(value) => Some(b64_decode_value(value)?),
        };
        if kind == PreKeyKind::Signed
            && (sig.is_none() || sig.as_ref().is_some_and(|s| s.len() > 8192))
        {
            return Err(Error::Invalid("missing signature"));
        }
        Ok(Self {
            id: id.to_string(),
            kind,
            x25519_pub,
            kem_pub,
            sig,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    pub device: DeviceBundle,
    pub signed: PublishedPreKey,
    pub one_time: Option<PublishedPreKey>,
}

impl PreKeyBundle {
    pub fn from_json(text: &str) -> Result<Self> {
        let obj = parse_json(text)?.as_object()?.to_vec();
        let device = match codec::obj_get(&obj, "device")? {
            Json::Obj(pairs) => DeviceBundle::from_fields(pairs)?,
            _ => return Err(Error::Invalid("device")),
        };
        let signed = match codec::obj_get(&obj, "signed")? {
            Json::Obj(pairs) => PublishedPreKey::from_fields(pairs)?,
            _ => return Err(Error::Invalid("signed")),
        };
        let one_time = match codec::obj_opt(&obj, "oneTime") {
            None => None,
            Some(Json::Obj(pairs)) => Some(PublishedPreKey::from_fields(pairs)?),
            Some(_) => return Err(Error::Invalid("oneTime")),
        };
        Ok(Self {
            device,
            signed,
            one_time,
        })
    }
}

pub fn signed_message(
    uid: &str,
    device_id: &str,
    id: &str,
    x25519_pub: &[u8],
    kem_pub: &[u8],
) -> Result<Vec<u8>> {
    lp(&[
        b"fireplace/v2/signed-prekey",
        uid.as_bytes(),
        device_id.as_bytes(),
        id.as_bytes(),
        x25519_pub,
        kem_pub,
    ])
}

pub fn sign(
    record: &PreKeyRecord,
    identity: &AccountIdentity,
    uid: &str,
    device_id: &str,
    rng: &mut Rng,
) -> Result<PublishedPreKey> {
    let message = signed_message(
        uid,
        device_id,
        &record.id,
        &record.x25519_pub,
        &record.kem_pub,
    )?;
    Ok(PublishedPreKey {
        id: record.id.clone(),
        kind: PreKeyKind::Signed,
        x25519_pub: record.x25519_pub.clone(),
        kem_pub: record.kem_pub.clone(),
        sig: Some(identity.sign(&message, rng)?),
    })
}

pub fn one_time(record: &PreKeyRecord) -> PublishedPreKey {
    PublishedPreKey {
        id: record.id.clone(),
        kind: PreKeyKind::OneTime,
        x25519_pub: record.x25519_pub.clone(),
        kem_pub: record.kem_pub.clone(),
        sig: None,
    }
}

pub fn verify_signed(device: &DeviceBundle, prekey: &PublishedPreKey) -> bool {
    let Some(sig) = &prekey.sig else {
        return false;
    };
    if prekey.kind != PreKeyKind::Signed {
        return false;
    }
    let Ok(message) = signed_message(
        &device.uid,
        &device.device_id,
        &prekey.id,
        &prekey.x25519_pub,
        &prekey.kem_pub,
    ) else {
        return false;
    };
    AccountIdentity::verify(&device.identity_pub, &message, sig)
}

fn check_created(created: i64) -> Result<()> {
    if !(0..=CREATED_MAX).contains(&created) {
        Err(Error::Invalid("createdAt"))
    } else {
        Ok(())
    }
}

/// Dart replaces `+` and `/` and does not strip `=`, but 9 bytes encode to
/// 12 characters with no padding.
fn b64url_raw9(bytes: &[u8]) -> String {
    debug_assert_eq!(bytes.len(), 9);
    b64url_encode(bytes)
}

fn b64_decode_value(value: &Json) -> Result<Vec<u8>> {
    let text = value.as_str().map_err(|_| Error::Invalid("sig"))?;
    codec::b64_decode(text).map_err(|_| Error::Invalid("sig"))
}
