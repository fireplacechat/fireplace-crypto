//! One device: an X25519 key, an ML-KEM-768 key, and a certificate from the
//! account identity. The device id is 16 random bytes as url-safe base64.

use crate::codec::{self, Json, b64_decode, b64_encode, b64url_encode, lp, obj_str, parse_json};
use crate::error::{Error, Result};
use crate::identity::AccountIdentity;
use crate::prim::{self, MLKEM_DK, MLKEM_EK};
use crate::rng::Rng;
use zeroize::Zeroize;

#[derive(Clone, Debug)]
pub struct DeviceBundle {
    pub uid: String,
    pub device_id: String,
    pub x25519_pub: Vec<u8>,
    pub kem_pub: Vec<u8>,
    pub identity_pub: Vec<u8>,
    pub cert: Vec<u8>,
}

impl DeviceBundle {
    pub fn cert_message(
        uid: &str,
        device_id: &str,
        x25519_pub: &[u8],
        kem_pub: &[u8],
    ) -> Result<Vec<u8>> {
        lp(&[
            b"fireplace/v1/device-cert",
            uid.as_bytes(),
            device_id.as_bytes(),
            x25519_pub,
            kem_pub,
        ])
    }

    pub fn verify_cert(&self) -> bool {
        let Ok(message) =
            Self::cert_message(&self.uid, &self.device_id, &self.x25519_pub, &self.kem_pub)
        else {
            return false;
        };
        AccountIdentity::verify(&self.identity_pub, &message, &self.cert)
    }

    pub fn to_json(&self) -> String {
        codec::to_json(&Json::object(vec![
            ("uid".to_string(), Json::Str(self.uid.clone())),
            ("deviceId".to_string(), Json::Str(self.device_id.clone())),
            (
                "x25519Pub".to_string(),
                Json::Str(b64_encode(&self.x25519_pub)),
            ),
            ("kemPub".to_string(), Json::Str(b64_encode(&self.kem_pub))),
            (
                "identityPub".to_string(),
                Json::Str(b64_encode(&self.identity_pub)),
            ),
            ("cert".to_string(), Json::Str(b64_encode(&self.cert))),
        ]))
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_fields(parse_json(text)?.as_object()?)
    }

    pub fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let uid = obj_str(obj, "uid")
            .map_err(|_| Error::Invalid("uid"))?
            .to_string();
        let device_id = obj_str(obj, "deviceId")
            .map_err(|_| Error::Invalid("deviceId"))?
            .to_string();
        if uid.is_empty() || device_id.is_empty() {
            return Err(Error::Invalid("device"));
        }
        Ok(Self {
            uid,
            device_id,
            x25519_pub: b64_exact(obj, "x25519Pub", 32)?,
            kem_pub: b64_exact(obj, "kemPub", MLKEM_EK)?,
            identity_pub: b64_any(obj, "identityPub")?,
            cert: b64_any(obj, "cert")?,
        })
    }
}

pub struct DeviceKeys {
    pub device_id: String,
    pub x25519_seed: Vec<u8>,
    pub x25519_pub: Vec<u8>,
    pub kem_pub: Vec<u8>,
    pub kem_secret: Vec<u8>,
}

impl Drop for DeviceKeys {
    fn drop(&mut self) {
        self.x25519_seed.zeroize();
        self.kem_secret.zeroize();
    }
}

impl core::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeviceKeys({})", self.device_id)
    }
}

impl Clone for DeviceKeys {
    fn clone(&self) -> Self {
        Self {
            device_id: self.device_id.clone(),
            x25519_seed: self.x25519_seed.clone(),
            x25519_pub: self.x25519_pub.clone(),
            kem_pub: self.kem_pub.clone(),
            kem_secret: self.kem_secret.clone(),
        }
    }
}

impl DeviceKeys {
    /// 32-byte X25519 seed, 64-byte ML-KEM seed, then 16 id bytes.
    pub fn generate(rng: &mut Rng) -> Result<Self> {
        let mut seed = rng.array::<32>()?;
        let public = prim::x25519_public(&seed)?.to_vec();
        let kem = prim::mlkem_generate(rng)?;
        let id = b64url_encode(&rng.bytes(16)?);
        let keys = Self {
            device_id: id,
            x25519_seed: seed.to_vec(),
            x25519_pub: public,
            kem_pub: kem.public,
            kem_secret: kem.secret,
        };
        seed.zeroize();
        Ok(keys)
    }

    pub fn certify(
        &self,
        identity: &AccountIdentity,
        uid: &str,
        rng: &mut Rng,
    ) -> Result<DeviceBundle> {
        let message =
            DeviceBundle::cert_message(uid, &self.device_id, &self.x25519_pub, &self.kem_pub)?;
        let cert = identity.sign(&message, rng)?;
        Ok(DeviceBundle {
            uid: uid.to_string(),
            device_id: self.device_id.clone(),
            x25519_pub: self.x25519_pub.clone(),
            kem_pub: self.kem_pub.clone(),
            identity_pub: identity.public_bytes()?,
            cert,
        })
    }

    pub fn to_json(&self) -> String {
        codec::to_json(&Json::object(vec![
            ("deviceId".to_string(), Json::Str(self.device_id.clone())),
            (
                "x25519Seed".to_string(),
                Json::Str(b64_encode(&self.x25519_seed)),
            ),
            (
                "x25519Pub".to_string(),
                Json::Str(b64_encode(&self.x25519_pub)),
            ),
            ("kemPub".to_string(), Json::Str(b64_encode(&self.kem_pub))),
            (
                "kemSecret".to_string(),
                Json::Str(b64_encode(&self.kem_secret)),
            ),
        ]))
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Self::from_fields(parse_json(text)?.as_object()?)
    }

    pub fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        let device_id = obj_str(obj, "deviceId").map_err(|_| Error::Invalid("deviceId"))?;
        if !valid_device_id(device_id) {
            return Err(Error::Invalid("deviceId"));
        }
        Ok(Self {
            device_id: device_id.to_string(),
            x25519_seed: b64_exact(obj, "x25519Seed", 32)?,
            x25519_pub: b64_exact(obj, "x25519Pub", 32)?,
            kem_pub: b64_exact(obj, "kemPub", MLKEM_EK)?,
            kem_secret: b64_exact(obj, "kemSecret", MLKEM_DK)?,
        })
    }

    pub fn consistent(&self) -> bool {
        prim::x25519_matches(&self.x25519_seed, &self.x25519_pub)
            && prim::mlkem_matches(&self.kem_secret, &self.kem_pub)
    }
}

pub fn valid_device_id(id: &str) -> bool {
    let len = id.len();
    (8..=64).contains(&len)
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub(crate) fn b64_exact(obj: &[(String, Json)], key: &'static str, len: usize) -> Result<Vec<u8>> {
    let text = obj_str(obj, key).map_err(|_| Error::Invalid(key))?;
    if text.len() > len * 2 {
        return Err(Error::Invalid(key));
    }
    let bytes = b64_decode(text).map_err(|_| Error::Invalid(key))?;
    if bytes.len() != len {
        return Err(Error::Invalid(key));
    }
    Ok(bytes)
}

pub(crate) fn b64_any(obj: &[(String, Json)], key: &'static str) -> Result<Vec<u8>> {
    let text = obj_str(obj, key).map_err(|_| Error::Invalid(key))?;
    b64_decode(text).map_err(|_| Error::Invalid(key))
}
