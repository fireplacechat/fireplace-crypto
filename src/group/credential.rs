//! The Fireplace credential inside an MLS BasicCredential: it binds a device's MLS
//! signature key to the account identity (Ed25519 + ML-DSA-65), so a group member
//! is the same person the app already knows and pins (decision 0014).

use openmls::prelude::{BasicCredential, Credential as MlsCredential};

use crate::codec::{Json, b64_encode, lp, u64_bytes, unlp};
use crate::{AccountIdentity, Error, Result, Rng};

const DOMAIN: &[u8] = b"fireplace-mls-credential-v1";
const MAX_ID: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub uid: String,
    pub device: String,
    pub cert_hash: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub generation: u64,
    pub identity: Vec<u8>,
    signature: Vec<u8>,
}

impl Credential {
    fn signed(
        uid: &str,
        device: &str,
        cert_hash: &[u8],
        signature_key: &[u8],
        generation: u64,
        identity: &[u8],
    ) -> Result<Vec<u8>> {
        let suite = u16::from(super::SUITE).to_be_bytes();
        lp(&[
            DOMAIN,
            uid.as_bytes(),
            device.as_bytes(),
            cert_hash,
            signature_key,
            &suite,
            &u64_bytes(generation),
            identity,
        ])
    }

    pub fn issue(
        identity: &AccountIdentity,
        uid: &str,
        device: &str,
        cert_hash: &[u8],
        signature_key: &[u8],
        generation: u64,
        rng: &mut Rng,
    ) -> Result<Self> {
        check_id(uid)?;
        check_id(device)?;
        if cert_hash.len() != 32 {
            return Err(Error::Invalid("certificate hash"));
        }
        let public = identity.public_bytes()?;
        let message = Self::signed(uid, device, cert_hash, signature_key, generation, &public)?;
        Ok(Self {
            uid: uid.into(),
            device: device.into(),
            cert_hash: cert_hash.to_vec(),
            signature_key: signature_key.to_vec(),
            generation,
            signature: identity.sign(&message, rng)?,
            identity: public,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        lp(&[
            DOMAIN,
            self.uid.as_bytes(),
            self.device.as_bytes(),
            &self.cert_hash,
            &self.signature_key,
            &u64_bytes(self.generation),
            &self.identity,
            &self.signature,
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let parts = unlp(bytes)?;
        if parts.len() != 8 || parts[0] != DOMAIN {
            return Err(Error::Invalid("credential"));
        }
        let text =
            |b: &Vec<u8>| String::from_utf8(b.clone()).map_err(|_| Error::Invalid("credential"));
        let generation = u64::from_be_bytes(
            parts[5]
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("credential"))?,
        );
        let credential = Self {
            uid: text(&parts[1])?,
            device: text(&parts[2])?,
            cert_hash: parts[3].clone(),
            signature_key: parts[4].clone(),
            generation,
            identity: parts[6].clone(),
            signature: parts[7].clone(),
        };
        check_id(&credential.uid)?;
        check_id(&credential.device)?;
        Ok(credential)
    }

    /// True when both account signatures cover this credential for this suite.
    pub fn verify(&self) -> bool {
        let Ok(message) = Self::signed(
            &self.uid,
            &self.device,
            &self.cert_hash,
            &self.signature_key,
            self.generation,
            &self.identity,
        ) else {
            return false;
        };
        AccountIdentity::verify(&self.identity, &message, &self.signature)
    }
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ID || id.contains(['/', ':']) {
        return Err(Error::Invalid("credential id"));
    }
    Ok(())
}

/// A group member whose Fireplace credential verified for its own leaf key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMember {
    pub leaf: u32,
    pub uid: String,
    pub device: String,
    pub identity: Vec<u8>,
    pub signature_key: Vec<u8>,
}

impl VerifiedMember {
    pub fn check(credential: &MlsCredential, signature_key: &[u8], leaf: u32) -> Result<Self> {
        let basic = BasicCredential::try_from(credential.clone())
            .map_err(|_| Error::Crypto("credential type"))?;
        let c = Credential::decode(basic.identity())?;
        // The credential must be for exactly the key this leaf signs with.
        if c.signature_key != signature_key || !c.verify() {
            return Err(Error::Crypto("credential"));
        }
        Ok(Self {
            leaf,
            uid: c.uid,
            device: c.device,
            identity: c.identity,
            signature_key: signature_key.to_vec(),
        })
    }

    pub fn same_leaf(&self, other: &Self) -> bool {
        self.leaf == other.leaf && self.signature_key == other.signature_key
    }

    pub fn to_json(&self) -> Json {
        Json::object(vec![
            ("leaf".into(), Json::Int(self.leaf as i64)),
            ("uid".into(), Json::Str(self.uid.clone())),
            ("device".into(), Json::Str(self.device.clone())),
            ("identity".into(), Json::Str(b64_encode(&self.identity))),
        ])
    }
}
