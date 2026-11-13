//! Account identity: Ed25519 and ML-DSA-65. A signature counts only when both
//! halves verify. The stored JSON is the Dart object, in that field order,
//! because the recovery backup encrypts `jsonEncode` of it.

use crate::codec::{Json, b64_decode, b64_encode, lp, obj_str, parse_json, to_json, unlp};
use crate::error::{Error, Result};
use crate::prim::{self, MLDSA_PK, MLDSA_SK};
use crate::rng::Rng;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct AccountIdentity {
    ed_seed: Vec<u8>,
    pub ed_pub: Vec<u8>,
    dsa_secret: Vec<u8>,
    pub dsa_pub: Vec<u8>,
}

impl Drop for AccountIdentity {
    fn drop(&mut self) {
        self.ed_seed.zeroize();
        self.dsa_secret.zeroize();
    }
}

impl core::fmt::Debug for AccountIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountIdentity")
    }
}

impl AccountIdentity {
    /// 32-byte Ed25519 seed, then a 32-byte ML-DSA seed.
    pub fn generate(rng: &mut Rng) -> Result<Self> {
        let mut ed_seed = rng.array::<32>()?;
        let ed_pub = prim::ed25519_public(&ed_seed)?.to_vec();
        let dsa = prim::mldsa_generate(rng)?;
        let identity = Self {
            ed_seed: ed_seed.to_vec(),
            ed_pub,
            dsa_secret: dsa.secret,
            dsa_pub: dsa.public,
        };
        ed_seed.zeroize();
        Ok(identity)
    }

    pub fn public_bytes(&self) -> Result<Vec<u8>> {
        lp(&[&self.ed_pub, &self.dsa_pub])
    }

    pub fn sign(&self, message: &[u8], rng: &mut Rng) -> Result<Vec<u8>> {
        let ed = prim::ed25519_sign(&self.ed_seed, message)?;
        let dsa = prim::mldsa_sign(&self.dsa_secret, message, rng)?;
        lp(&[&ed, &dsa])
    }

    /// False for any malformed input. Verification never errors.
    pub fn verify(public_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(public) = unlp(public_bytes) else {
            return false;
        };
        let Ok(signature) = unlp(signature) else {
            return false;
        };
        if public.len() != 2 || signature.len() != 2 {
            return false;
        }
        prim::ed25519_verify(&public[0], message, &signature[0])
            && prim::mldsa_verify(&public[1], message, &signature[1])
    }

    pub fn to_json(&self) -> String {
        to_json(&Json::object(vec![
            ("edSeed".to_string(), Json::Str(b64_encode(&self.ed_seed))),
            ("edPub".to_string(), Json::Str(b64_encode(&self.ed_pub))),
            (
                "dsaSecret".to_string(),
                Json::Str(b64_encode(&self.dsa_secret)),
            ),
            ("dsaPub".to_string(), Json::Str(b64_encode(&self.dsa_pub))),
        ]))
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let value = parse_json(text)?;
        let obj = value.as_object()?;
        Self::from_fields(obj)
    }

    pub fn from_fields(obj: &[(String, Json)]) -> Result<Self> {
        Ok(Self {
            ed_seed: field(obj, "edSeed", 32)?,
            ed_pub: field(obj, "edPub", 32)?,
            dsa_secret: field(obj, "dsaSecret", MLDSA_SK)?,
            dsa_pub: field(obj, "dsaPub", MLDSA_PK)?,
        })
    }

    /// Ed25519 public key matches the seed, and a fresh hybrid signature
    /// verifies. A malformed ML-DSA secret is "not consistent", not a panic.
    pub fn consistent(&self, rng: &mut Rng) -> Result<bool> {
        if !prim::ed25519_matches(&self.ed_seed, &self.ed_pub) {
            return Ok(false);
        }
        let probe = rng.bytes(16)?;
        let signature = match self.sign(&probe, rng) {
            Ok(signature) => signature,
            Err(Error::Invalid(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
        let public = self.public_bytes()?;
        Ok(Self::verify(&public, &probe, &signature))
    }
}

fn field(obj: &[(String, Json)], key: &'static str, len: usize) -> Result<Vec<u8>> {
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
