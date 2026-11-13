//! Classical and post-quantum primitives, shaped like the Dart calls.
//!
//! ML-KEM and ML-DSA stored secrets use the expanded FIPS encodings the app
//! already writes to disk. Those encodings are deprecated inside the crates
//! in favour of a short seed, but a seed is a different file format, so the
//! expanded form stays. `from_expanded` can panic on a malformed ML-DSA key;
//! that panic is caught here and reported as an invalid key.
//!
//! Randomness is drawn by us, in the same order the Dart code draws it once
//! the test seam is on: ML-KEM key generation is `d` then `z` (64 bytes),
//! encapsulation coins are 32 bytes, and a hedged ML-DSA signature draws 32
//! bytes of `rnd`. The context string is `fireplace/v1`.

use crate::error::{Error, Result};
use crate::rng::Rng;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65,
    Signature as DsaSignature, VerifyingKey as DsaVerifyingKey,
};
use ml_kem::kem::{Decapsulate, KeyExport};
#[allow(deprecated)] // expanded ML-KEM keys are the bytes Fireplace stores
use ml_kem::{
    B32, DecapsulationKey, EncapsulationKey, ExpandedKeyEncoding, MlKem768, Seed as KemSeed,
};
use rand_core::TryCryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[allow(dead_code)]
pub const X25519_LEN: usize = 32;
pub const MLKEM_EK: usize = 1184;
pub const MLKEM_DK: usize = 2400;
pub const MLKEM_CT: usize = 1088;
#[allow(dead_code)]
pub const ED25519_LEN: usize = 32;
#[allow(dead_code)]
pub const ED25519_SIG: usize = 64;
pub const MLDSA_PK: usize = 1952;
pub const MLDSA_SK: usize = 4032;
pub const MLDSA_SIG: usize = 3309;
const DSA_CTX: &[u8] = b"fireplace/v1";

fn array32(bytes: &[u8], what: &'static str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| Error::Invalid(what))
}

pub fn x25519_public(seed: &[u8]) -> Result<[u8; 32]> {
    let seed = array32(seed, "x25519 seed")?;
    let secret = StaticSecret::from(seed);
    Ok(PublicKey::from(&secret).to_bytes())
}

pub fn x25519_matches(seed: &[u8], public: &[u8]) -> bool {
    match (x25519_public(seed), array32(public, "x25519 pub")) {
        (Ok(got), Ok(want)) => crate::codec::bytes_equal(&got, &want),
        _ => false,
    }
}

/// Shared secret, including an all-zero result. Callers that must reject a
/// non-contributory output use [`x25519_dh`].
pub fn x25519_shared(seed: &[u8], remote_public: &[u8]) -> Result<[u8; 32]> {
    let seed = array32(seed, "x25519 seed")?;
    let remote = array32(remote_public, "x25519 pub")?;
    let secret = StaticSecret::from(seed);
    Ok(secret.diffie_hellman(&PublicKey::from(remote)).to_bytes())
}

/// Shared secret. Rejects a wrong length and an all-zero result. The all-zero
/// scan is the Dart check; `SharedSecret::was_contributory` is the same
/// condition, and the scan keeps the comparison identical.
pub fn x25519_dh(seed: &[u8], remote_public: &[u8]) -> Result<[u8; 32]> {
    let shared = x25519_shared(seed, remote_public)?;
    if !contributory(&shared) {
        return Err(Error::Crypto("invalid X25519 contribution"));
    }
    Ok(shared)
}

pub fn contributory(secret: &[u8]) -> bool {
    secret.len() == 32 && secret.iter().fold(0u8, |acc, byte| acc | byte) != 0
}

pub struct MlKemPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

/// Draw `d` then `z` and expand them to the stored 2400-byte secret.
pub fn mlkem_generate(rng: &mut Rng) -> Result<MlKemPair> {
    let mut seed = [0u8; 64];
    rng.fill(&mut seed)?;
    let pair = mlkem_from_seed(&seed);
    seed.zeroize();
    Ok(pair)
}

pub fn mlkem_from_seed(seed: &[u8; 64]) -> MlKemPair {
    let dk = DecapsulationKey::<MlKem768>::from_seed(KemSeed::from(*seed));
    let public = dk.encapsulation_key().to_bytes().to_vec();
    #[allow(deprecated)]
    let secret = dk.to_expanded_bytes().to_vec();
    MlKemPair { public, secret }
}

pub fn mlkem_matches(secret: &[u8], public: &[u8]) -> bool {
    secret.len() == MLKEM_DK
        && public.len() == MLKEM_EK
        && crate::codec::bytes_equal(&secret[1152..1152 + MLKEM_EK], public)
}

fn encapsulation_key(public: &[u8]) -> Result<EncapsulationKey<MlKem768>> {
    if public.len() != MLKEM_EK {
        return Err(Error::Invalid("kem pub"));
    }
    let bytes = ml_kem::kem::Key::<EncapsulationKey<MlKem768>>::try_from(public)
        .map_err(|_| Error::Invalid("kem pub"))?;
    EncapsulationKey::new(&bytes).map_err(|_| Error::Invalid("kem pub"))
}

fn decapsulation_key(secret: &[u8]) -> Result<DecapsulationKey<MlKem768>> {
    if secret.len() != MLKEM_DK {
        return Err(Error::Invalid("kem secret"));
    }
    let bytes = ml_kem::ExpandedDecapsulationKey::<MlKem768>::try_from(secret)
        .map_err(|_| Error::Invalid("kem secret"))?;
    #[allow(deprecated)]
    DecapsulationKey::<MlKem768>::from_expanded_bytes(&bytes)
        .map_err(|_| Error::Invalid("kem secret"))
}

/// Encapsulation coins are the 32-byte `m` Dart passes to `encapsulate`.
pub fn mlkem_encapsulate(public: &[u8], coins: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let ek = encapsulation_key(public)?;
    let coins = array32(coins, "kem coins")?;
    let (ct, shared) = ek.encapsulate_deterministic(&B32::from(coins));
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared.as_slice());
    Ok((ct.to_vec(), ss))
}

pub fn mlkem_decapsulate(secret: &[u8], ciphertext: &[u8]) -> Result<[u8; 32]> {
    if ciphertext.len() != MLKEM_CT {
        return Err(Error::Crypto("bad KEM ciphertext"));
    }
    let dk = decapsulation_key(secret).map_err(|_| Error::Crypto("bad KEM ciphertext"))?;
    let shared = dk
        .decapsulate_slice(ciphertext)
        .map_err(|_| Error::Crypto("bad KEM ciphertext"))?;
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared.as_slice());
    Ok(ss)
}

pub fn ed25519_public(seed: &[u8]) -> Result<[u8; 32]> {
    let seed = array32(seed, "ed25519 seed")?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

pub fn ed25519_matches(seed: &[u8], public: &[u8]) -> bool {
    match (ed25519_public(seed), array32(public, "ed25519 pub")) {
        (Ok(got), Ok(want)) => crate::codec::bytes_equal(&got, &want),
        _ => false,
    }
}

pub fn ed25519_sign(seed: &[u8], message: &[u8]) -> Result<[u8; 64]> {
    let seed = array32(seed, "ed25519 seed")?;
    Ok(SigningKey::from_bytes(&seed).sign(message).to_bytes())
}

pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public) = array32(public, "ed25519 pub") else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&public) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    verifying.verify(message, &signature).is_ok()
}

fn dsa_expanded(secret: &[u8]) -> Result<ExpandedSigningKey<MlDsa65>> {
    if secret.len() != MLDSA_SK {
        return Err(Error::Invalid("dsa secret"));
    }
    let encoded = ExpandedSigningKeyBytes::<MlDsa65>::try_from(secret)
        .map_err(|_| Error::Invalid("dsa secret"))?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[allow(deprecated)]
        ExpandedSigningKey::<MlDsa65>::from_expanded(&encoded)
    }))
    .map_err(|_| Error::Invalid("dsa secret"))
}

pub struct MlDsaPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

pub fn mldsa_generate(rng: &mut Rng) -> Result<MlDsaPair> {
    let mut xi = [0u8; 32];
    rng.fill(&mut xi)?;
    let pair = mldsa_from_seed(&xi);
    xi.zeroize();
    Ok(pair)
}

pub fn mldsa_from_seed(xi: &[u8; 32]) -> MlDsaPair {
    let seed = ml_dsa::Seed::from(*xi);
    let expanded = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
    let public = expanded.verifying_key().encode().to_vec();
    #[allow(deprecated)]
    let secret = expanded.to_expanded().to_vec();
    MlDsaPair { public, secret }
}

pub fn mldsa_sign(secret: &[u8], message: &[u8], rng: &mut Rng) -> Result<Vec<u8>> {
    let key = dsa_expanded(secret)?;
    // `sign_randomized` turns an RNG failure into its own opaque error.
    // `failed` is set by our stream or by `getrandom`, so the caller still
    // sees [`Error::Rng`] instead of a protocol error.
    let signature = key.sign_randomized(message, DSA_CTX, rng).map_err(|_| {
        if rng.failed() {
            Error::Rng
        } else {
            Error::Crypto("ml-dsa sign")
        }
    })?;
    Ok(signature.encode().to_vec())
}

pub fn mldsa_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public.len() != MLDSA_PK || signature.len() != MLDSA_SIG {
        return false;
    }
    let Ok(encoded_pk) = EncodedVerifyingKey::<MlDsa65>::try_from(public) else {
        return false;
    };
    let Ok(encoded_sig) = EncodedSignature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    let Some(signature) = DsaSignature::<MlDsa65>::decode(&encoded_sig) else {
        return false;
    };
    let verifying = DsaVerifyingKey::<MlDsa65>::decode(&encoded_pk);
    verifying.verify_with_context(message, DSA_CTX, &signature)
}

/// The `rand_core` bound is only here so a future caller can see that the
/// RNG handed to ML-DSA is the fallible one. The methods above take [`Rng`].
#[allow(dead_code)]
fn _rng_is_fallible<R: TryCryptoRng + ?Sized>() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_7748_x25519() {
        let scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let point = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let shared = x25519_dh(&scalar, &point).unwrap();
        assert_eq!(
            hex_encode(&shared),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    #[test]
    fn rfc_8032_ed25519_test_1() {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = ed25519_public(&seed).unwrap();
        assert_eq!(
            hex_encode(&public),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let signature = ed25519_sign(&seed, b"").unwrap();
        assert_eq!(
            hex_encode(&signature),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(ed25519_verify(&public, b"", &signature));
    }

    #[test]
    fn all_zero_x25519_is_not_contributory() {
        assert!(!contributory(&[0u8; 32]));
        assert!(contributory(&[1u8; 32]));
        assert!(!contributory(&[0u8; 31]));
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
